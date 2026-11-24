#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vanta::patterns {
using Address=std::uint64_t;
struct Range {Address address{};std::size_t size{};};
struct Pattern {std::vector<std::uint8_t> bytes;std::string mask;};
enum class ScanError {None,InvalidPattern,InvalidRange,InvalidOptions,UnreadableMemory,MatchLimit,Cancelled};
struct ScanOptions {
    std::size_t blockSize=65536,pageSize=4096,maxMatches=64;
    std::function<bool()> cancelled;
};
struct ScanResult {
    std::vector<Address> matches;
    bool complete=true;
    ScanError error=ScanError::None;
    std::size_t bytesRead{},unreadableBytes{},readCalls{};
};
inline const char* errorName(ScanError error) {
    switch(error) {
        case ScanError::None:return "none";
        case ScanError::InvalidPattern:return "invalid pattern";
        case ScanError::InvalidRange:return "invalid range";
        case ScanError::InvalidOptions:return "invalid scan options";
        case ScanError::UnreadableMemory:return "unreadable memory";
        case ScanError::MatchLimit:return "match limit reached";
        case ScanError::Cancelled:return "cancelled";
    }
    return "unknown scan failure";
}
inline bool validRange(Address address,std::size_t size) {
    return size>0 && size<=std::numeric_limits<Address>::max()-address;
}
inline bool validPattern(const Pattern& pattern) {
    return !pattern.bytes.empty() && pattern.bytes.size()<=65536 && pattern.bytes.size()==pattern.mask.size() &&
        std::all_of(pattern.mask.begin(),pattern.mask.end(),[](char c){return c=='x'||c=='?';});
}
inline std::optional<Address> uniqueAddress(const ScanResult& result) {
    if(!result.complete || result.matches.size()!=1 || result.error!=ScanError::None) return {};
    return result.matches.front();
}
// Unlike uniqueAddress, this explicitly permits one observed candidate when
// unreadable ranges prevent a uniqueness proof. Cancellation/limits still fail.
inline std::optional<Address> bestCandidateAddress(const ScanResult& result) {
    if(const auto unique=uniqueAddress(result))return unique;
    if(!result.complete && result.error==ScanError::UnreadableMemory && result.matches.size()==1)
        return result.matches.front();
    return {};
}
inline std::optional<Address> addSigned(Address value,std::int64_t delta) {
    if(delta>=0) {
        const auto amount=static_cast<Address>(delta);
        if(amount>std::numeric_limits<Address>::max()-value)return {};
        return value+amount;
    }
    const auto amount=static_cast<Address>(-(delta+1))+1;
    if(amount>value)return {};
    return value-amount;
}

namespace detail {
inline bool validOptions(const ScanOptions& options) {
    return options.blockSize>0 && options.blockSize<=262144 && options.pageSize>0 && options.pageSize<=65536 &&
        (options.pageSize&(options.pageSize-1))==0 && options.maxMatches>0 && options.maxMatches<=65536;
}
struct CompiledPattern {
    std::vector<std::pair<std::size_t,std::uint8_t>> fixed;
    std::size_t length{},anchor{};
    std::uint8_t anchorByte{};
    explicit CompiledPattern(const Pattern& pattern):length(pattern.bytes.size()) {
        for(std::size_t i=0;i<length;++i)if(pattern.mask[i]=='x')fixed.push_back({i,pattern.bytes[i]});
        if(!fixed.empty()) {anchor=fixed.front().first;anchorByte=fixed.front().second;}
    }
};
}

// Read is bool(Address address, void* destination, size_t bytes). It must return
// true only when every requested byte was copied. Failed buffers are never
// searched, even if a transport wrote partial bytes before returning false.
template<class Read> ScanResult scan(Read&& read,Address base,std::size_t size,const Pattern& pattern,
                                    const ScanOptions& options={}) {
    ScanResult result;
    const auto invalid=[&](ScanError error){result.complete=false;result.error=error;return result;};
    if(!validPattern(pattern))return invalid(ScanError::InvalidPattern);
    if(!validRange(base,size))return invalid(ScanError::InvalidRange);
    if(!detail::validOptions(options))return invalid(ScanError::InvalidOptions);
    if(pattern.bytes.size()>size)return result;
    const detail::CompiledPattern compiled(pattern);
    std::vector<std::uint8_t> block(options.blockSize),tail,window;
    tail.reserve(compiled.length-1);
    Address previousEnd=base;
    bool stopped{};
    const auto cancelled=[&] {
        if(!options.cancelled || !options.cancelled())return false;
        result.complete=false;result.error=ScanError::Cancelled;stopped=true;return true;
    };
    const auto consume=[&](Address address,const std::uint8_t* bytes,std::size_t count) {
        if(address!=previousEnd)tail.clear();
        const auto oldTail=tail.size();
        window.clear();window.reserve(oldTail+count);
        window.insert(window.end(),tail.begin(),tail.end());window.insert(window.end(),bytes,bytes+count);
        const Address start=address-static_cast<Address>(oldTail);
        const auto available=window.size();
        if(available>=compiled.length) {
            const auto last=available-compiled.length;
            std::size_t position{};
            while(position<=last) {
                if(!compiled.fixed.empty()) {
                    const auto anchorStart=window.data()+position+compiled.anchor;
                    const auto found=static_cast<const std::uint8_t*>(std::memchr(anchorStart,compiled.anchorByte,last-position+1));
                    if(!found)break;
                    position=static_cast<std::size_t>(found-window.data())-compiled.anchor;
                }
                bool matches=true;
                for(const auto& fixed:compiled.fixed)if(window[position+fixed.first]!=fixed.second){matches=false;break;}
                if(matches) {
                    result.matches.push_back(start+static_cast<Address>(position));
                    if(result.matches.size()>=options.maxMatches) {
                        result.complete=false;result.error=ScanError::MatchLimit;stopped=true;return;
                    }
                }
                ++position;
            }
        }
        const auto keep=std::min(compiled.length-1,window.size());
        tail.assign(window.end()-keep,window.end());
        previousEnd=address+static_cast<Address>(count);
    };
    std::size_t processed{};
    while(processed<size && !stopped) {
        if(cancelled())break;
        const auto count=std::min(options.blockSize,size-processed);
        const Address address=base+static_cast<Address>(processed);
        ++result.readCalls;
        if(read(address,block.data(),count)) {
            result.bytesRead+=count;consume(address,block.data(),count);
        } else {
            // A failed bulk read does not imply every page is unavailable.
            // Resume only with successfully read, contiguous page fragments.
            std::size_t pageOffset{};
            while(pageOffset<count && !stopped) {
                if(cancelled())break;
                const Address pageAddress=address+static_cast<Address>(pageOffset);
                const auto toBoundary=options.pageSize-static_cast<std::size_t>(pageAddress%options.pageSize);
                const auto pageCount=std::min(toBoundary,count-pageOffset);
                ++result.readCalls;
                if(read(pageAddress,block.data(),pageCount)) {
                    result.bytesRead+=pageCount;consume(pageAddress,block.data(),pageCount);
                } else {
                    tail.clear();previousEnd=pageAddress+static_cast<Address>(pageCount);
                    result.complete=false;result.unreadableBytes+=pageCount;
                    if(result.error==ScanError::None)result.error=ScanError::UnreadableMemory;
                }
                pageOffset+=pageCount;
            }
        }
        processed+=count;
    }
    return result;
}

// Independent executable ranges must not be stitched across non-code gaps.
// Overlapping ranges are coalesced so a single match never becomes a duplicate.
template<class Read> ScanResult scanRanges(Read&& read,std::vector<Range> ranges,const Pattern& pattern,
                                          const ScanOptions& options={}) {
    ScanResult combined;
    if(!validPattern(pattern)){combined.complete=false;combined.error=ScanError::InvalidPattern;return combined;}
    if(!detail::validOptions(options)){combined.complete=false;combined.error=ScanError::InvalidOptions;return combined;}
    for(const auto& range:ranges)if(!validRange(range.address,range.size)) {
        combined.complete=false;combined.error=ScanError::InvalidRange;return combined;
    }
    std::sort(ranges.begin(),ranges.end(),[](const Range& a,const Range& b){return a.address<b.address;});
    std::vector<Range> merged;
    for(const auto& range:ranges) {
        if(!merged.empty() && range.address<=merged.back().address+merged.back().size) {
            const auto end=std::max(merged.back().address+merged.back().size,range.address+range.size);
            if(end-merged.back().address>std::numeric_limits<std::size_t>::max()) {
                combined.complete=false;combined.error=ScanError::InvalidRange;return combined;
            }
            merged.back().size=static_cast<std::size_t>(end-merged.back().address);
        } else merged.push_back(range);
    }
    for(const auto& range:merged) {
        auto nextOptions=options;nextOptions.maxMatches=options.maxMatches-combined.matches.size();
        auto current=scan(read,range.address,range.size,pattern,nextOptions);
        combined.matches.insert(combined.matches.end(),current.matches.begin(),current.matches.end());
        combined.bytesRead+=current.bytesRead;combined.unreadableBytes+=current.unreadableBytes;combined.readCalls+=current.readCalls;
        combined.complete=combined.complete&&current.complete;
        if(current.error!=ScanError::None)combined.error=current.error;
        if(current.error==ScanError::MatchLimit || current.error==ScanError::Cancelled)break;
    }
    return combined;
}

template<class Read> std::optional<std::uint64_t> readUnsignedOperand(Read&& read,Address instruction,
    std::size_t operandOffset,std::size_t width=4) {
    if(width!=1 && width!=2 && width!=4 && width!=8)return {};
    if(operandOffset>std::numeric_limits<Address>::max()-instruction)return {};
    const auto address=instruction+static_cast<Address>(operandOffset);
    if(!validRange(address,width))return {};
    std::array<std::uint8_t,8> bytes{};
    if(!read(address,bytes.data(),width))return {};
    std::uint64_t value{};
    for(std::size_t i=0;i<width;++i)value|=std::uint64_t(bytes[i])<<(8*i);
    return value;
}
template<class Read> std::optional<Address> resolveRipRelative(Read&& read,Address instruction,
    std::size_t displacementOffset,std::size_t instructionSize) {
    if(instructionSize==0 || instructionSize>15 || displacementOffset>instructionSize ||
       instructionSize-displacementOffset<4 || !validRange(instruction,instructionSize))return {};
    const auto raw=readUnsignedOperand(read,instruction,displacementOffset,4);
    if(!raw)return {};
    const auto displacement=(*raw&0x80000000ULL)?static_cast<std::int64_t>(*raw)-0x100000000LL:static_cast<std::int64_t>(*raw);
    return addSigned(instruction+static_cast<Address>(instructionSize),displacement);
}

// Parse only PE headers and executable virtual ranges. All offsets below belong
// to the public PE/COFF format, not to any version-specific game structure.
template<class Read> std::optional<std::vector<Range>> executableSections(Read&& read,Address moduleBase,std::size_t moduleSize) {
    if(!validRange(moduleBase,moduleSize) || moduleSize<64)return {};
    std::array<std::uint8_t,64> dos{};
    if(!read(moduleBase,dos.data(),dos.size()) || dos[0]!='M' || dos[1]!='Z')return {};
    const auto u16=[](const std::uint8_t* p)->std::uint16_t{return static_cast<std::uint16_t>(std::uint16_t(p[0])|(std::uint16_t(p[1])<<8));};
    const auto u32=[](const std::uint8_t* p){return std::uint32_t(p[0])|(std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|(std::uint32_t(p[3])<<24);};
    const auto peOffset=u32(dos.data()+0x3C);
    if(peOffset>moduleSize || moduleSize-peOffset<24)return {};
    std::array<std::uint8_t,24> nt{};
    if(!read(moduleBase+peOffset,nt.data(),nt.size()) || u32(nt.data())!=0x4550 || u16(nt.data()+4)!=0x8664)return {};
    const auto count=u16(nt.data()+6),optionalSize=u16(nt.data()+20);
    if(!count || count>96 || optionalSize<64 || optionalSize>4096)return {};
    const auto optionalOffset=std::size_t(peOffset)+24;
    const auto tableOffset=optionalOffset+optionalSize;
    if(tableOffset>moduleSize || std::size_t(count)*40>moduleSize-tableOffset)return {};
    std::array<std::uint8_t,64> optional{};
    if(!read(moduleBase+optionalOffset,optional.data(),optional.size()) || u16(optional.data())!=0x20B)return {};
    const auto imageSize=u32(optional.data()+56);
    if(!imageSize || imageSize>moduleSize || tableOffset+std::size_t(count)*40>imageSize)return {};
    std::vector<std::uint8_t> table(std::size_t(count)*40);
    if(!read(moduleBase+tableOffset,table.data(),table.size()))return {};
    std::vector<Range> ranges;
    for(unsigned i=0;i<count;++i) {
        const auto section=table.data()+std::size_t(i)*40;
        if((u32(section+36)&0x20000000U)==0)continue;
        const auto rva=u32(section+12),virtualSize=u32(section+8),rawSize=u32(section+16);
        const auto size=virtualSize?virtualSize:rawSize;
        if(!size)continue;
        if(rva>=imageSize || size>imageSize-rva)return {};
        ranges.push_back({moduleBase+rva,static_cast<std::size_t>(size)});
    }
    if(ranges.empty())return {};
    return ranges;
}
} // namespace vanta::patterns
