#include "pattern_scan.hpp"
#include <iostream>

namespace {
using namespace vanta::patterns;
unsigned checks{},failures{};
void check(bool pass,const char* label) {++checks;if(!pass){++failures;std::cerr<<"FAIL: "<<label<<'\n';}}
struct Memory {
    Address base=0x1000;
    std::vector<std::uint8_t> data;
    std::vector<Range> gaps;
    std::vector<Range> reads;
    std::size_t maximumRead=std::numeric_limits<std::size_t>::max();
    bool fillFailed{};
    explicit Memory(std::size_t size):data(size,0xCC) {}
    bool readable(Address address,std::size_t size) const {
        if(address<base || address-base>data.size() || size>data.size()-static_cast<std::size_t>(address-base))return false;
        for(const auto& gap:gaps)if(address<gap.address+gap.size && gap.address<address+size)return false;
        return true;
    }
    bool read(Address address,void* destination,std::size_t size) {
        reads.push_back({address,size});
        if(size>maximumRead || !readable(address,size)) {
            if(fillFailed)std::memset(destination,0xAA,size);
            return false;
        }
        std::memcpy(destination,data.data()+static_cast<std::size_t>(address-base),size);return true;
    }
    void bytes(std::size_t offset,std::initializer_list<std::uint8_t> values) {
        std::copy(values.begin(),values.end(),data.begin()+offset);
    }
    void put(std::size_t offset,std::uint64_t value,unsigned width) {
        for(unsigned i=0;i<width;++i)data[offset+i]=static_cast<std::uint8_t>(value>>(8*i));
    }
};
ScanOptions small() {ScanOptions options;options.blockSize=16;options.pageSize=8;options.maxMatches=128;return options;}
ScanResult run(Memory& memory,const Pattern& pattern,const ScanOptions& options=small()) {
    return scan([&](Address address,void* destination,std::size_t size){return memory.read(address,destination,size);},memory.base,memory.data.size(),pattern,options);
}
Memory peFixture() {
    Memory memory(0x5000);std::fill(memory.data.begin(),memory.data.end(),std::uint8_t{0});
    memory.bytes(0,{'M','Z'});memory.put(0x3C,0x80,4);
    memory.put(0x80,0x4550,4);memory.put(0x84,0x8664,2);memory.put(0x86,2,2);memory.put(0x94,0xF0,2);
    memory.put(0x98,0x20B,2);memory.put(0x98+56,0x5000,4);
    memory.put(0x188+8,0x2000,4);memory.put(0x188+12,0x1000,4);memory.put(0x188+16,0x2000,4);memory.put(0x188+36,0x60000020,4);
    memory.put(0x1B0+8,0x1000,4);memory.put(0x1B0+12,0x3000,4);memory.put(0x1B0+16,0x1000,4);memory.put(0x1B0+36,0xC0000040,4);
    return memory;
}
}
int main() {
    using namespace vanta::patterns;
    const Pattern exact{{0x48,0x8B,0x05,0xA1},"xxxx"};
    {
        Memory memory(32);memory.bytes(1,{0x48,0x8B,0x05,0xA1});memory.gaps={{memory.base+8,8}};
        const auto partial=run(memory,exact);
        check(!uniqueAddress(partial) && bestCandidateAddress(partial)==memory.base+1,
              "one observed match remains explicitly unproven when another page is unreadable");
        memory.bytes(17,{0x48,0x8B,0x05,0xA1});
        check(!bestCandidateAddress(run(memory,exact)),"partial scan with two candidates remains ambiguous");
        for(const auto error:{ScanError::None,ScanError::InvalidPattern,ScanError::InvalidRange,ScanError::InvalidOptions,
                              ScanError::UnreadableMemory,ScanError::MatchLimit,ScanError::Cancelled}) {
            ScanResult result;result.matches={0x1234};result.error=error;
            for(const bool complete:{false,true}) {
                result.complete=complete;
                const bool allowed=(complete && error==ScanError::None) || (!complete && error==ScanError::UnreadableMemory);
                check(bestCandidateAddress(result).has_value()==allowed,"candidate policy does not accept cancellation, limits or invalid results");
                result.matches.clear();check(!bestCandidateAddress(result),"empty candidate set never supplies an address");
                result.matches={0x1234,0x5678};check(!bestCandidateAddress(result),"multiple candidates never supply an address");
                result.matches={0x1234};
            }
        }
    }
    {
        Memory memory(64);memory.bytes(15,{0x48,0x8B,0x05,0xA1});
        const auto result=run(memory,exact);
        check(result.complete && result.error==ScanError::None && uniqueAddress(result)==memory.base+15,"match spanning read blocks is found once");
        check(result.bytesRead==64,"complete coverage counted once");
        check(std::all_of(memory.reads.begin(),memory.reads.end(),[&](const Range& r){return r.address>=memory.base && r.address+r.size<=memory.base+memory.data.size();}),"all reads stay inside the supplied module");
        memory.maximumRead=8;memory.reads.clear();
        const auto fallback=run(memory,exact);
        check(fallback.complete && fallback.matches==result.matches,"failed bulk reads fall back to readable page fragments");
        check(fallback.readCalls>result.readCalls && fallback.bytesRead==64,"fallback reports calls without double-counting failed bytes");
    }
    {
        Memory memory(64);memory.base=0x1003;memory.maximumRead=8;memory.bytes(3,{0x48,0x8B,0x05,0xA1});
        check(uniqueAddress(run(memory,exact))==memory.base+3,"unaligned module and page boundary are handled");
        memory.bytes(37,{0x48,0x8B,0x11,0xA1});
        const auto wildcard=run(memory,{{0x48,0x8B,0,0xA1},"xx?x"});
        check(wildcard.matches==std::vector<Address>{memory.base+3,memory.base+37},"wildcards match only the requested positions");
        memory.bytes(53,{0x48,0,0x8B});
        check(uniqueAddress(run(memory,{{0x48,0,0x8B},"xxx"}))==memory.base+53,"embedded zero signature bytes are not treated as string terminators");
    }
    {
        Memory memory(131072);memory.maximumRead=4096;memory.bytes(4095,{0x48,0x8B,0x05,0xA1});memory.bytes(65535,{0x48,0x8B,0x05,0xA1});
        const auto result=run(memory,exact,ScanOptions{});
        check(result.complete && result.matches==std::vector<Address>{memory.base+4095,memory.base+65535},"real 4 KiB page and 64 KiB block boundaries survive fallback");
    }
    {
        Memory memory(32);memory.gaps={{memory.base+8,8}};memory.fillFailed=true;
        memory.bytes(1,{0x48,0x8B,0x05,0xA1});memory.bytes(17,{0x48,0x8B,0x05,0xA1});
        const auto result=run(memory,exact);
        check(!result.complete && result.error==ScanError::UnreadableMemory && result.unreadableBytes==8,"unreadable pages produce an explicit incomplete result");
        check(result.matches==std::vector<Address>{memory.base+1,memory.base+17},"readable matches before and after a gap survive");
        check(!uniqueAddress(result),"incomplete coverage cannot establish a unique address");
        check(run(memory,{{0xAA,0xAA},"xx"}).matches.empty(),"bytes written by a failed read are never searched");
        memory.bytes(6,{0x11,0x22});memory.bytes(16,{0x33,0x44});
        check(run(memory,{{0x11,0x22,0x33,0x44},"xxxx"}).matches.empty(),"separate readable pages are not stitched over a gap");
    }
    {
        Memory memory(5);std::fill(memory.data.begin(),memory.data.end(),std::uint8_t{0x41});
        const auto result=run(memory,{{0x41,0x41,0x41,0x41},"xxxx"});
        check(result.matches==std::vector<Address>{memory.base,memory.base+1},"overlapping occurrences remain distinct");
        check(!uniqueAddress(result),"multiple matches are ambiguous");
        auto options=small();options.maxMatches=1;
        const auto first=run(memory,{{0x41},"x"},options);
        check(first.matches==std::vector<Address>{memory.base} && !first.complete && first.error==ScanError::MatchLimit,"first-match stopping is explicit rather than a uniqueness claim");
        const auto any=run(memory,{{0,0,0},"???"});
        check(any.complete && any.matches.size()==3,"all-wildcard patterns retain literal mask semantics");
    }
    {
        Memory memory(32);
        for(const auto& pattern:std::vector<Pattern>{{{},""},{{1,2},"x"},{{1},"X"},{{1,2},"x "}}) {
            memory.reads.clear();const auto result=run(memory,pattern);
            check(!result.complete && result.error==ScanError::InvalidPattern && memory.reads.empty(),"invalid signatures fail before any memory read");
        }
        auto read=[&](Address address,void* output,std::size_t size){return memory.read(address,output,size);};
        check(scan(read,memory.base,0,exact).error==ScanError::InvalidRange,"empty range rejected");
        check(scan(read,std::numeric_limits<Address>::max()-2,4,exact).error==ScanError::InvalidRange,"address overflow rejected");
        memory.reads.clear();const auto shortRange=scan(read,memory.base,3,exact);
        check(shortRange.complete && shortRange.matches.empty() && memory.reads.empty(),"shorter range cannot contain the pattern");
        for(unsigned choice=0;choice<5;++choice) {
            auto options=small();
            if(choice==0)options.blockSize=0;else if(choice==1)options.pageSize=3;
            else if(choice==2)options.maxMatches=0;else if(choice==3)options.blockSize=262145;else options.maxMatches=65537;
            check(run(memory,exact,options).error==ScanError::InvalidOptions,"invalid resource bounds rejected");
        }
        auto options=small();options.cancelled=[&]{return memory.reads.size()>=2;};memory.reads.clear();
        const auto cancelled=run(memory,exact,options);
        check(cancelled.complete && cancelled.error==ScanError::None && cancelled.bytesRead==32,"a cancellation condition reached after the final read does not invalidate completed coverage");
        Memory longMemory(128);options.cancelled=[&]{return longMemory.reads.size()>=2;};
        const auto stopped=run(longMemory,exact,options);
        check(stopped.error==ScanError::Cancelled && !stopped.complete && stopped.readCalls==2,"cancellation stops scanning promptly between reads");
    }
    {
        Memory memory(48);memory.bytes(10,{0x48,0x8B,0x05,0xA1});
        auto read=[&](Address address,void* output,std::size_t size){return memory.read(address,output,size);};
        const auto merged=scanRanges(read,{{memory.base,16},{memory.base+8,16}},exact,small());
        check(merged.complete && merged.matches==std::vector<Address>{memory.base+10} && merged.bytesRead==24,"overlapping code ranges are coalesced before scanning");
        memory.bytes(7,{0x11});memory.bytes(16,{0x22});
        check(scanRanges(read,{{memory.base,8},{memory.base+16,8}},{{0x11,0x22},"xx"},small()).matches.empty(),"nonadjacent executable ranges cannot fabricate a cross-gap match");
        memory.bytes(8,{0x22});
        check(uniqueAddress(scanRanges(read,{{memory.base,8},{memory.base+8,8}},{{0x11,0x22},"xx"},small()))==memory.base+7,"adjacent executable ranges preserve boundary matches");
    }
    {
        Memory memory(128);memory.put(35,0x20,4);
        auto read=[&](Address address,void* output,std::size_t size){return memory.read(address,output,size);};
        check(resolveRipRelative(read,memory.base+32,3,7)==memory.base+32+7+0x20,"positive RIP displacement resolves against the end of the instruction");
        memory.put(35,0xFFFFFFE0,4);
        check(resolveRipRelative(read,memory.base+32,3,7)==memory.base+32+7-0x20,"negative RIP displacement is sign extended");
        check(!resolveRipRelative(read,memory.base+32,4,7) && !resolveRipRelative(read,memory.base+32,3,16),"operand must fit inside an x64 instruction");
        memory.gaps={{memory.base+35,4}};
        check(!resolveRipRelative(read,memory.base+32,3,7),"unreadable operand does not resolve to zero");
        check(!addSigned(1,-2) && !addSigned(std::numeric_limits<Address>::max(),1),"signed addition detects underflow and overflow");
        check(addSigned(0,0)==0,"a legitimate zero result is distinct from no result");
        check(!addSigned(0,std::numeric_limits<std::int64_t>::min()),"minimum signed displacement does not overflow during checking");
        memory.gaps.clear();memory.put(64,0xFEDCBA9876543210ULL,8);
        check(readUnsignedOperand(read,memory.base+60,4,1)==0x10 && readUnsignedOperand(read,memory.base+60,4,2)==0x3210 &&
              readUnsignedOperand(read,memory.base+60,4,4)==0x76543210 && readUnsignedOperand(read,memory.base+60,4,8)==0xFEDCBA9876543210ULL,
              "immediates and member displacements decode little endian at each supported width");
        check(!readUnsignedOperand(read,memory.base,0,3) && !readUnsignedOperand(read,std::numeric_limits<Address>::max()-1,4,4),"invalid operand widths and addresses fail");
    }
    {
        auto memory=peFixture();memory.bytes(0x1010,{0x48,0x8B,0x05,0xA1});memory.bytes(0x3010,{0x48,0x8B,0x05,0xA1});
        auto read=[&](Address address,void* output,std::size_t size){return memory.read(address,output,size);};
        const auto ranges=executableSections(read,memory.base,memory.data.size());
        check(ranges && ranges->size()==1 && ranges->front().address==memory.base+0x1000 && ranges->front().size==0x2000,"PE executable virtual section bounds decoded");
        check(ranges && uniqueAddress(scanRanges(read,*ranges,exact))==memory.base+0x1010,"executable-only scanning excludes a matching data section");
        memory.put(0x188+8,0,4);
        const auto rawSize=executableSections(read,memory.base,memory.data.size());
        check(rawSize && rawSize->front().size==0x2000,"zero virtual size uses bounded raw size");
        memory.put(0x188+12,0x5000,4);
        check(!executableSections(read,memory.base,memory.data.size()),"out-of-module executable section is rejected");
        memory=peFixture();memory.put(0x84,0x14C,2);
        check(!executableSections(read,memory.base,memory.data.size()),"wrong PE architecture rejected");
        memory=peFixture();memory.put(0x3C,0xFFFFFFF0,4);
        check(!executableSections(read,memory.base,memory.data.size()),"malformed PE header pointer rejected");
        memory=peFixture();memory.put(0x188+36,0x40000040,4);
        check(!executableSections(read,memory.base,memory.data.size()),"an image without executable sections cannot supply code signatures");
    }
    {
        // Differential tests vary pattern lengths beyond block size, wildcard
        // locations, module alignment and holes. The reference uses byte-level
        // availability and does not share the streaming implementation.
        std::uint32_t state=0x12345678;
        const auto random=[&]() {state=state*1664525U+1013904223U;return state;};
        for(unsigned iteration=0;iteration<500;++iteration) {
            Memory memory(128);memory.base+=iteration%7;for(auto& byte:memory.data)byte=static_cast<std::uint8_t>((random()>>24)&3);
            auto options=small();options.blockSize=std::array<std::size_t,4>{1,4,16,64}[iteration%4];options.pageSize=8;
            memory.maximumRead=iteration%3?8:65536;
            for(unsigned page=0;page<16;++page)if((random()&15)==0) {
                const Address address=(memory.base/8+page)*8;
                memory.gaps.push_back({address,8});
            }
            Pattern pattern;pattern.bytes.resize(1+random()%24);pattern.mask.resize(pattern.bytes.size());
            for(std::size_t i=0;i<pattern.bytes.size();++i){pattern.bytes[i]=static_cast<std::uint8_t>((random()>>24)&3);pattern.mask[i]=(random()&3)?'x':'?';}
            std::vector<Address> expected;
            for(std::size_t start=0;start+pattern.bytes.size()<=memory.data.size();++start) {
                if(!memory.readable(memory.base+start,pattern.bytes.size()))continue;
                bool match=true;for(std::size_t i=0;i<pattern.bytes.size();++i)if(pattern.mask[i]=='x' && pattern.bytes[i]!=memory.data[start+i]){match=false;break;}
                if(match)expected.push_back(memory.base+start);
            }
            const auto result=run(memory,pattern,options);
            check(result.matches==expected,"streaming scanner agrees with independent readable-byte reference");
        }
    }
    std::cout<<"pattern scanner: "<<checks<<" checks, "<<failures<<" failures; synthetic memory only\n";
    return failures?1:0;
}
