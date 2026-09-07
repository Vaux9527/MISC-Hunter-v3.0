# MISC Hunter

> **MISC Hunter is a modular CTF MISC analysis toolkit designed to automate repetitive file-analysis, extraction, steganography detection, and recursive artifact analysis workflows.**
>
> MISC Hunter 是一个模块化的 CTF MISC 分析工具，用于自动化执行重复性的文件分析、数据提取、隐写检测和递归分析流程。

**版本: v3.0** · 核心纯 Python 标准库实现（零 pip 依赖），Kali Linux / Windows 均可运行
（可选 pycryptodome 增强对称解密，缺失自动降级）

---

## 定位

工具负责大量重复、机械、规则明确的工作；人负责最终推理、联想和判断。

```text
输入一个可疑文件
    ↓
自动识别文件类型 → 自动运行常见分析 → 发现异常特征
    ↓
自动调用对应插件 → 提取隐藏数据 → 新文件重新进入分析队列(递归)
    ↓
输出结果、日志、报告 —— 需要人类推理的部分清晰呈现给用户
```

**找到就给**（flag 自动报告），**找不到就把原料给人类**（候选文件/字符串/解码结果呈现到终端与报告），**分析不出来的明确列入"待人工分析"清单**，绝不悄悄消失。整不出来的如实报告推测与建议，不假装成功。

## 快速开始

无参数运行显示主页(大字标题 + 用法):

```bash
python hunter.py
```

```bash
python hunter.py <文件或目录> [更多...]
```

示例（仓库自带 CTF 样本）：

```bash
python hunter.py samples/snake.jpg     # 单文件
python hunter.py samples/              # 目录: 自动扫描其中所有文件
```

`snake.jpg` 是 JPEG + 尾部隐藏 ZIP 的拼接样本：类型识别 → ZIP 定位/切出/解压 →
Base64 检测解码 → 字符串提取，全程递归自动完成，最终把人类需要推理的提示呈现出来。

输出分三层：

```text
第1层: 逐轮详细流水(每个 finding, 含解码内容/提取列表)     ← 深挖用
第2层: 简要汇总(每个文件的关键结论 + FLAG + 待人工清单)    ← 一眼看懂
第3层: 提取链树(文件来龙去脉) + 开始/结束时间与耗时
```

完整输出示例:

```text
[开始] 2026-09-07 15:03:28
[分析] samples/snake.jpg
  [+] 该文件实际为JPEG
  ...
[分析] ...\key
  [+] 发现编码内容并解码(1层)
     解码第1层 [Base64]: What is Nicki Minaj's favorite song that refers to snakes?

====================================================
  分析完成 · 简要汇总
====================================================
  samples\snake.jpg  [JPEG]
    [!] 关键字: http
    [+] 提取 3 个: cipher, extracted_278260.zip, key
  ...
====================================================
  提取链
====================================================
  └── samples\snake.jpg
      ├── extracted_278260.zip
      ├── key [解码: What is Nicki Minaj's favorite song...]
      │   └── key.decoded.txt
      └── cipher [需密钥/人工]
====================================================
[结束] 2026-09-07 15:03:53 · 耗时 12.6 秒
[完成] 分析结束。终端上方是简要汇总, 完整结果在报告文件:
       E:\MISC_Hunter\output\report.txt
```

运行产物:

```text
output/
├── report.txt              # 汇总报告: 每文件分析 + 提取链树 + 待人工清单 + FLAG
└── extracted/              # 所有提取/生成的文件
    ├── *.zip / key / cipher        # 提取与解压产物
    ├── *.decoded.txt               # 解码明文
    ├── *.strings.txt               # 可打印字符串(供人类查看)
    ├── *.xor_candidates.txt        # XOR/LSB 爆破候选(供人类查看)
    └── *.fixed.png                 # PNG 宽高修复产物
```

report.txt 的**提取链**节展示文件来龙去脉:

```text
提取链(文件来龙去脉)
└── samples\snake.jpg
    ├── extracted_278260.zip
    ├── key [解码: What is Nicki Minaj's favorite song...]
    │   └── key.decoded.txt
    └── cipher [需密钥/人工]
```

## 插件清单 (v3.0, 按执行顺序)

| priority | 插件 | 功能 |
|---|---|---|
| 10 | `file_type.py` | 魔数识别: JPEG/PNG/GIF/PDF/ZIP/RAR/BMP |
| 12 | `metadata.py` | PNG tEXt/zTXt 注释、JPEG COM 注释、EXIF IFD0 文本标签(大小端自适应) |
| 15 | `png_analyzer.py` | PNG chunk 遍历、IHDR 解析、全 chunk CRC 校验(stored/calculated 可解释) |
| 16 | `png_fixer.py` | 宽高恢复: IDAT 解压长度反推真实高度, 重写 IHDR + CRC, 输出 fixed.png |
| 17 | `lsb_extractor.py` | LSB 隐写提取: PNG(5种滤波逆变换) / BMP(BGR, 双行序), 多模式全试 |
| 18 | `zsteg_scanner.py` | 外部工具 zsteg: PNG/BMP 隐写全模式(纯Python LSB的补充) |
| 19 | `steghide_scanner.py` | 外部工具 steghide: JPEG/BMP/WAV 隐写检测与空口令提取 |
| 20 | `zip_detector.py` | 定位嵌入式/独立 ZIP |
| 22 | `zip_crypto.py` | 伪加密检测修复(清GPBF位+CRC验证) / 真加密弱密码+数字爆破 |
| 25 | `binwalk.py` | 外部工具框架调用 binwalk(未安装自动降级提示) |
| 30 | `zip_extractor.py` | 按偏移切出 ZIP + 解压内部文件(防路径穿越), 依赖 20 先行 |
| 32 | `rar_extractor.py` | RAR 检测+提取: 独立/嵌入式(找Rar!偏移切段), 工具 7z/unrar/bsdtar |
| 35 | `f5_scanner.py` | 外部工具 f5extract: JPEG F5 频域隐写提取 |
| 40 | `decoder.py` | 自动检测 Base64 → 套娃解码 → 明文落盘进队列 |
| 50 | `strings_analyzer.py` | flag/ctf 模式 → 敏感关键字 → 全量字符串提取 |
| 55 | `caesar.py` | 凯撒/ROT 检测: flag 前缀精确还原轨 + 英文频率轨 |
| 60 | `xor_bruteforcer.py` | 单字节 XOR 爆破(256 key, 候选落盘) |
| 61 | `xor_multi.py` | 多字节 XOR 频率攻击(分列 + 英文频率打分), 失败发 DECRYPT_NEEDED |

## 架构

```text
hunter.py (CLI 入口)
    │  命令行接收目标 → 递归队列 → 终端呈现 → report.txt
    │  人机接力: 见 DECRYPT_NEEDED 时询问用户密钥
    ▼
core/plugin_loader.py (自动发现)
    │  扫描 plugins/ 目录 → 实例化所有 Plugin 子类 → 按 priority 排序
    ▼
Engine (项目经理: 不懂业务, 只负责流程)
    │  1. 创建 AnalysisContext(中央数据库)
    │  2. 创建 Logger
    │  3. 按 priority 顺序运行插件(异常隔离: 单插件崩溃不影响整体)
    ▼
Plugin (插件: 各干一件事)
    │  读 context.target → 分析 → 写 findings / extracted_files
    ▼
提取出的新文件 → 重新进入分析队列 → 递归直到没有新内容
```

### 核心对象

| 对象 | 职责 |
|---|---|
| `AnalysisContext` | 中央数据库: target / findings / extracted_files / logs |
| `Logger` | 日志: 时间戳 + 级别(INFO/WARNING/ERROR) |
| `Engine` | 流程控制 + 按 priority 排序 + **异常隔离**(try/except + continue) |
| `Plugin` | 基类: name / version / **priority**(执行顺序) / run(context) |

### 关键架构特性

**插件自动发现** — 扫描 `plugins/` 目录动态加载所有 Plugin 子类，按 `priority`
排序执行。新插件 = 新建文件 + 继承 Plugin + 声明 priority，hunter.py 永不用改。
依赖关系通过 priority 显式声明（如 ZipExtractor=30 依赖 ZipDetector=20 的 finding）。

**异常隔离** — 每个插件调用包在 `try/except Exception` 中：崩溃 → ERROR 日志(插件名+原因)
→ 跳过继续。用 `Exception` 而非 `BaseException`，保证 Ctrl+C 不被吞。

**文件接力通信** — 插件间不直接依赖：产物落盘 → 记入 `extracted_files` →
递归队列作为新 target 接力分析。来源(source/method/offset)记录在提取条目中供追溯。

**候选文件模式** — 爆破/隐写类插件把无法唯一判定的候选**全部落盘**（
`.xor_candidates.txt` / `.lsb_candidates.txt`），进队列由 strings 的 flag 精确匹配
做最终裁决，人类可查完整候选。判定统一为"像英文 **或** 含 flag{/ctf{ 结构"
(`plausible_plain`)——flag 内容可能是乱码，英文频率会漏，结构特征是精确的。

**人机接力** — 自动破解失败时插件发 `DECRYPT_NEEDED` finding（插件保持无 I/O），
hunter.py 在交互终端询问用户密钥 → 按**算法注册表**尝试解密 → 产物回队列继续递归。
非交互环境(isatty 检查)自动跳过不卡死。

**密钥解密框架**（`utils/decryptors.py`）— 人类提供密钥后自动尝试组合矩阵：

```
算法: XOR → Serpent → AES → DES → 3DES
模式: ECB / CBC(零IV) / CBC(IV前置)
key派生: 原样 / md5 / sha256 / 补零16·24·32 / 重复到16 / hex解析
```

命中即报告"用 Serpent-ECB(md5派生) 解开(尝试了N种组合)"；全部失败如实报告。
依赖策略: Serpent 为项目自带 vendor(`utils/vendor/pyserpent`, MIT, 纯Python零pip依赖)；
AES/DES/3DES 需 pycryptodome(可选, 缺失自动降级提示)。

**外部工具框架** — `utils/tools.py`：`find_tool`(shutil.which 检测) /
`run_tool`(subprocess, 超时保护, 列表传参防注入) / 工具缺失返回降级 finding 不崩溃。
binwalk/zsteg/steghide/F5/7z/unrar 插件共用此模板，执行与解析分离(解析器为可单测的纯函数)。
"有工具直接增强、没工具告知安装命令并降级"，不影响其他分析。

**递归护栏** — 递归队列带深度与总数双上限（默认 15 层 / 200 文件）：
畸形输入或产物自我增殖时强制停止并提示，防呆保险丝。

**提取链呈现** — 从提取记录(source→path)构建文件谱系树(每文件取首个来源防环)，
终端与报告同步展示"来龙去脉"，节点带结论标注(解码内容/需密钥/伪加密修复等)。

**主页与时间** — 无参数运行显示 figlet 大字主页(slant 字体, 字模内嵌零依赖)与用法；
分析输出开始/结束时间与总耗时。

**解码库** — `utils/decoders.py`：`try_b64/b32/b16/b85`(失败返回 None)、
`decode_chain`(套娃解码, 字符集窄先试防抢答, 双层防死循环)、`xor_decrypt`(人机接力用)、
`looks_like_text`/`plausible_plain`(文本判定)、`ENGLISH_FREQ`/`english_score`(频率分析)。
可读性检查在**原始字节**上做，避免 `errors="ignore"` 丢字节造成的假阳性。

## 独立工具

`tools/decoder_cli.py` — 早期独立开发的交互式解码工具箱(粘贴即用):
二进制/十进制/十六进制转 ASCII、Base16/32/64/85、URL/Unicode、自动递归解 Base 套娃、进制互转。
`python tools/decoder_cli.py` 直接运行。

`tools/caesar_cli.py` — 凯撒密码全 26 位爆破 CLI:
`python tools/caesar_cli.py "密文"` / `python tools/caesar_cli.py 文件路径` / 无参数交互粘贴。
常见英文单词智能评分(词表含 flag/ctf), 最可能明文 ★ 高亮, 一次显示全部结果。
评分逻辑与插件 `plugins/caesar.py` 同源。

## 目录结构

```text
MISC_Hunter/
├── core/            # context / engine / logger / plugin / plugin_loader(自动发现)
├── plugins/         # 分析插件 18 个(每个只解决一种问题, 声明 priority)
├── utils/           # paths(路径统一) / decoders(解码库) / tools(外部工具框架)
│                    # decryptors(密钥解密注册表) / vendor(自带Serpent, MIT)
├── tools/           # 独立 CLI 工具(decoder_cli / caesar_cli)
├── samples/         # 测试样本
├── tests/           # 流程验证脚本
├── output/          # 运行产物(不入库)
├── hunter.py        # 入口: figlet 主页 + 目录批量 + 递归队列(护栏) + 人机接力 + 汇总/提取链 + 报告
└── requirements.txt
```

## 设计原则

1. **模块化** — 一个插件只解决一种问题，插件间不直接依赖(文件接力)
2. **可失败** — 单插件崩溃不影响整体(异常隔离)；工具缺失降级提示
3. **可解释** — 每条 finding 带 code/message/severity；CRC mismatch 报 stored/calculated
4. **有结果才扩散** — 只有提取出真实文件才进入下一轮递归
5. **递归分析** — 提取文件自动回队列；工具产物文件不被产出型插件再爆破(终止保障)
6. **机械自动化，推理留人类** — 编码/提取/穷举自动化；密钥、算法线索留给人类(人机接力)
7. **不扔垃圾桶** — 自动判定不了的候选全部落盘呈现；报告列"待人工分析"清单
8. **诚实边界** — 解不开就如实报告(尝试数/推测/建议路径)，不为具体题目调参、不假装成功
9. **简单套路优先** — 简单机械的迭代/查找/爆破为主，纯 Python 干不了的交外部工具

## 版本路线

| 版本 | 主题 | 内容 |
|---|---|---|
| **1.0** ✅ | 能用的流水线 | CLI + 递归队列 + 报告 + 基础插件 + 插件自动发现/priority |
| **2.0** ✅ | 覆盖面 | PNG 专项(chunk/CRC/宽高恢复)、metadata(EXIF)、LSB(PNG/BMP)、XOR 单/多字节、凯撒、binwalk 工具框架、人机接力、统一判定 |
| **3.0** ✅ | 深度与接力 | 密钥解密框架(Serpent vendor + AES/DES 注册表)、ZIP 伪加密修复/弱密码爆破、RAR 独立+嵌入式提取、外部工具矩阵(zsteg/steghide/F5)、目录批量输入、递归护栏、报告提取链、figlet 主页 |
| **4.0** | AI 辅助层 | LLM 做总结/建议/解释 —— 确定性分析仍是核心 |

## 环境要求

- Python 3.8+
- 核心 Python 依赖: **零**（requirements.txt 说明见下）
- 可选: `pip install pycryptodome` → 密钥解密框架支持 AES/DES/3DES
  （Serpent 已 vendor 进项目无需安装；缺失时自动降级提示）

```bash
python hunter.py              # 主页(大字标题 + 用法)
python tools/decoder_cli.py   # 交互解码工具
python tools/caesar_cli.py    # 凯撒爆破工具
```

## 外部工具（可选, 按需安装）

部分插件调用 **Kali 系统命令**（不是 Python 包, 所以不进 requirements.txt）。
未安装时对应插件自动降级提示（如 `binwalk 未安装, 跳过该分析`），**不影响其他分析**；
装好后同一份代码自动生效, 无需任何配置。

| 工具 | 用途 | 安装 (Kali) | 插件 |
|---|---|---|---|
| binwalk | 深度扫描嵌入数据 | `sudo apt install binwalk` | binwalk.py |
| steghide | JPEG/BMP/WAV 隐写 | `sudo apt install steghide` | steghide_scanner.py |
| zsteg | PNG/BMP 隐写全模式 | `sudo gem install zsteg` | zsteg_scanner.py |
| F5 | JPEG 频域隐写 | 官网 jar + 全局命令 `f5extract` | f5_scanner.py |
| 7z / unrar / bsdtar | RAR 提取 | `sudo apt install p7zip-full` (Win10+ 自带 bsdtar) | rar_extractor.py |
| strings | 字符串提取(GNU) | `sudo apt install binutils`(Kali 自带) | (纯Python版已内置) |
| exiftool | 元数据(备用) | `sudo apt install libimage-exiftool-perl` | (metadata 已纯Python实现) |

检测工具是否可用:

```bash
python -c "from utils.tools import find_tool; print(find_tool('binwalk'))"
# 输出路径 = 已安装; None = 未安装
```
