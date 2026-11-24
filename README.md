# Pattern Scan Lab // 不把未知伪装成确定

[![C++17 tests](https://github.com/dajiejie1/pattern-scan-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/dajiejie1/pattern-scan-lab/actions/workflows/tests.yml)

> 一个匹配，不一定代表唯一。读不到的内存，也不能假装不存在。

这是一个独立的 **C++17 二进制模式扫描实验**。它把部分读取、不可读页面、地址边界和结果完整性作为接口的一部分，而不是把问题藏在“找到地址”四个字后面。

## 它解决什么

| 场景 | 处理方式 |
| :--- | :--- |
| 模式包含通配符或 `0x00` | 按字节与掩码匹配，保留精确语义 |
| 大范围读取失败 | 回退到分页读取，并记录不可读区域 |
| 模式横跨块或页边界 | 保留必要重叠，不漏掉有效匹配 |
| 两段可读内存之间有空洞 | 不跨越空洞拼接出虚假匹配 |
| 某些区域无法读取 | 将结果标记为不完整，拒绝“唯一地址”结论 |
| PE64 映像 | 校验边界后提取可执行节范围 |

```text
完整读取 + 一个匹配       → uniqueAddress() 可以给出地址
读取不完整 + 一个匹配     → 只能得到已观察到的候选
跨越不可读区域的字节     → 永远不是一个匹配
```

## 验证记录

- **595 项检查，0 失败**：本地 MSVC 19.44 编译与 CTest 通过。
- **500 组差分测试**：随机生成合成内存、通配符、页对齐变化与不可读区域，再与独立的逐字节参考实现比较。
- GitHub Actions 在 Windows 和 Linux 上运行同一套测试。

## 编译

需要 CMake 3.20+ 与 C++17 编译器：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## 公开范围

仓库只包含通用扫描器和**完全合成的测试内存**。没有游戏偏移、专有签名、驱动或真实进程访问。完整项目保留在私有空间。本仓库可供阅读研究；未授予通用代码复用许可。
