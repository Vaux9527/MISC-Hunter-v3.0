'''
MISC HUNTER 入口

用法:
    python hunter.py <文件或目录> [更多...]

支持:
    - 直接传文件: python hunter.py samples/snake.jpg
    - 传目录(自动扫描目录下所有文件): python hunter.py samples/
    - 递归分析: 每轮产出的新文件自动重新进队列
    - 递归护栏: 深度上限 + 文件总数上限(防呆, 防止畸形输入跑爆)

流程:
    1. 命令行接收目标(文件/目录展开)
    2. 递归分析队列(带深度与总数护栏)
    3. 每轮 findings 打印到终端
    4. 全部结束后: 简要汇总 + output/report.txt(含提取链树)
'''

import os
import sys
from collections import defaultdict
from datetime import datetime

from core.engine import Engine
from core.plugin_loader import discover_plugins
from utils.decoders import xor_decrypt, looks_like_text
from utils.paths import OUTPUT_DIR, EXTRACT_DIR, ensure_dirs

# 插件自动发现: 扫描 plugins/ 目录, 按 priority 排序
# 新插件只需在 plugins/ 下新建文件继承 Plugin, 无需改这里
PLUGINS = discover_plugins()

# ========== 递归护栏(防呆) ==========
MAX_DEPTH = 15      # 提取链最大深度(超过即停, 防畸形输入死循环)
MAX_FILES = 200     # 单次任务最多分析的文件总数

# 终端输出统一 UTF-8 (Windows 控制台默认 GBK 会乱码)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

SEVERITY_MARK = {"INFO": "[+]", "WARNING": "[!]", "ERROR": "[x]"}


def print_findings(context):
    """终端呈现一轮分析的所有 findings(含找到的具体内容)"""
    for f in context.findings:
        mark = SEVERITY_MARK.get(f["severity"], "[?]")
        print(f"  {mark} {f['message']}")
        data = f.get("data") or {}

        # 各种 finding 的详细内容, 直接展示在终端
        if f["code"] == "FLAG_FOUND":
            print(f"     >>> FLAG: {data['flag']}")
        elif f["code"] == "DECODED":
            for i, layer in enumerate(data.get("layers", [])):
                text = layer["result"].strip()
                if len(text) > 200:
                    text = text[:200] + "..."
                print(f"     解码第{i+1}层 [{layer['decoder']}]: {text}")
        elif f["code"] == "STRINGS_EXTRACTED":
            for s in data.get("preview", []):
                print(f"     | {s}")
            if data.get("count", 0) > len(data.get("preview", [])):
                print(f"     | ... 共{data['count']}条, 完整内容见文件")


def _save_decrypted(target, context, analyzed, targets, depth, text, method):
    """解密成功的明文统一落盘进队列(depth: 当前递归深度, 产物深度+1)"""
    ensure_dirs()
    out_path = os.path.join(
        str(EXTRACT_DIR),
        os.path.basename(target) + ".decrypted.txt"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    context.extracted_files.append({
        "path": out_path,
        "source": target,
        "method": method,
        "offset": 0
    })
    print(f"  [+] 密钥有效! 解密结果已写入: {out_path}")
    if out_path not in analyzed:
        targets.append((out_path, depth + 1))


def _ask_for_key(target, context, analyzed, targets, depth):
    """
    人机接力: 询问用户是否有密钥, 有则尝试解密
    解密产物重新进队列继续分析(递归)

    尝试顺序:
        1. XOR(多字节, 纯标准库)
        2. 对称加密注册表: Serpent/AES/DES/3DES × ECB/CBC × key派生
           (utils/decryptors.py, Serpent 自带 vendor, AES/DES 需 pycryptodome)

    全部失败: 如实报告尝试数量, 不假装成功
    """
    try:
        key = input(f"  [?] 疑似加密数据: {os.path.basename(target)}\n"
                    "      如有密钥请输入(直接回车跳过): ").strip()
    except EOFError:
        return
    if not key:
        return

    with open(target, "rb") as f:
        data = f.read()

    # ---- 1. XOR ----
    decrypted = xor_decrypt(data, key.encode())
    if decrypted is not None and looks_like_text(decrypted, letter_th=0.75):
        _save_decrypted(target, context, analyzed, targets, depth,
                        decrypted.decode("utf-8", errors="replace"),
                        "MANUAL_KEY_XOR")
        return

    # ---- 2. 对称加密注册表 ----
    from utils import decryptors
    hit = decryptors.try_decrypt_all(key, data)
    if hit["ok"]:
        print(f"  [+] 解密命中: {hit['description']} "
              f"(尝试了{hit['attempts']}种组合)")
        _save_decrypted(target, context, analyzed, targets, depth,
                        hit["plaintext"].decode("utf-8", errors="replace"),
                        f"MANUAL_KEY_{hit['algorithm']}_{hit['mode']}")
        return

    # ---- 全部失败 ----
    hint = ""
    if not decryptors.HAVE_PYCRYPTODOME:
        hint = " (提示: AES/DES 需要 pip install pycryptodome)"
    print(f"  [x] 密钥未能解开数据(已尝试 XOR + {hit['attempts']}种对称组合)"
          f"{hint}: 密钥可能不对, 或算法不在注册表内")


def run_analysis(targets):
    """
    递归分析队列(带护栏), 返回所有轮次的 context 列表(供报告使用)
    targets: 初始文件路径列表(用户输入, 深度 0)
    队列元素: (path, depth); 提取产物深度 +1
    护栏: MAX_DEPTH 深度上限 / MAX_FILES 总文件数上限(防畸形输入跑爆)
    """
    queue = [(t, 0) for t in targets]
    analyzed = set()
    contexts = []
    total = 0

    while queue and total < MAX_FILES:
        target, depth = queue.pop()
        if target in analyzed:
            continue

        if depth > MAX_DEPTH:
            print(f"  [x] 已达递归深度上限({MAX_DEPTH}), 停止深入: {target}")
            continue

        analyzed.add(target)
        total += 1

        print(f"\n[分析] {target}")
        context = Engine(target, PLUGINS).run()
        contexts.append(context)
        print_findings(context)

        # ===== 人机接力: 插件发现疑似加密但破解失败, 询问用户密钥 =====
        needed = [f for f in context.findings if f["code"] == "DECRYPT_NEEDED"]
        if needed and sys.stdin.isatty():   # 仅交互终端询问(管道/自动化不卡死)
            _ask_for_key(target, context, analyzed, queue, depth)

        for file in context.extracted_files:
            path = file["path"]
            if path not in analyzed:
                print(f"  [+] 提取新文件: {path}")
                queue.append((path, depth + 1))

    if total >= MAX_FILES:
        print(f"  [x] 已达单次任务文件数上限({MAX_FILES}), 停止分析")

    return contexts


def _chain_annotation(path, contexts):
    """提取链节点的简短标注: 从该文件的分析结论里挑一条最值得看的"""
    for ctx in contexts:
        if ctx.target != path:
            continue
        for f in ctx.findings:
            d = f.get("data") or {}
            if f["code"] == "FLAG_FOUND":
                return " [flag!]"
            if f["code"] == "DECRYPT_NEEDED":
                return " [需密钥/人工]"
            if f["code"] == "DECODED":
                text = d["layers"][-1]["result"].strip()[:36]
                return f" [解码: {text}]"
            if f["code"] == "CAESAR_DECODED":
                return " [凯撒解出, 见文件]"
            if f["code"] in ("XOR_MULTI_FOUND", "XOR_CANDIDATES_FOUND",
                             "LSB_CANDIDATES_FOUND", "ZSTEG_FINDINGS"):
                return " [发现隐写/加密线索]"
            if f["code"] == "ZIP_FAKE_ENCRYPTED":
                return " [伪加密已修复]"
            if f["code"] == "ZIP_CRACKED":
                return " [密码已破解]"
        break
    return ""


def build_chain_tree(contexts):
    """
    从提取记录构建 父->子 树
    每个文件只取"第一个提取它的来源"(防多父/环, 链自然无环)
    根 = 被分析过但从未作为提取产物出现的文件(用户输入)
    """
    parent = {}
    for ctx in contexts:
        for e in ctx.extracted_files:
            if e["path"] not in parent:
                parent[e["path"]] = e["source"]

    children = defaultdict(list)
    for path, src in parent.items():
        children[src].append(path)

    analyzed_paths = set()
    for ctx in contexts:
        analyzed_paths.add(ctx.target)
        for e in ctx.extracted_files:
            analyzed_paths.add(e["path"])

    roots = sorted(p for p in analyzed_paths if p not in parent)
    return roots, children


def render_chain_tree(roots, children, contexts):
    """渲染提取链树(ASCII), 返回行列表"""
    lines = []
    paths = roots + [c for subs in children.values() for c in subs]

    def walk(node, prefix, is_last, depth, visited):
        if node in visited:
            return
        visited.add(node)
        marker = "└── " if is_last else "├── "
        label = os.path.basename(node)
        if depth == 0:
            label = os.path.relpath(node)  # 根显示相对路径
        lines.append(f"{prefix}{marker}{label}{_chain_annotation(node, contexts)}")
        subs = children.get(node, [])
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, sub in enumerate(subs):
            walk(sub, child_prefix, i == len(subs) - 1, depth + 1, visited)

    visited = set()
    for i, root in enumerate(roots):
        walk(root, "", i == len(roots) - 1, 0, visited)

    # 孤立的提取产物(父未被分析, 如跨任务残留)也补上
    orphan = [p for p in paths if p not in visited]
    for p in orphan:
        lines.append(f"└── {os.path.basename(p)}{_chain_annotation(p, contexts)}")
    return lines


def write_report(contexts):
    """把每轮分析的 findings/extracted 汇总成 output/report.txt"""
    ensure_dirs()
    lines = []
    lines.append("=" * 44)
    lines.append("MISC HUNTER REPORT")
    lines.append("=" * 44)
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    all_flags = []
    # 待人工分析清单: (目标, 原因)
    manual = []

    for ctx in contexts:
        lines.append("-" * 44)
        lines.append(f"目标: {ctx.target}")

        # 文件类型: 从 FileTypeDetector 的 finding 里找
        ftype = "未知"
        for f in ctx.findings:
            if f["code"] == "FILE_TYPE_DETECTED":
                ftype = f["data"].get("type", "未知")
        lines.append(f"文件类型: {ftype}")
        lines.append("")

        lines.append("Findings:")
        codes = []
        for f in ctx.findings:
            mark = SEVERITY_MARK.get(f["severity"], "[?]")
            lines.append(f"  {mark} [{f['code']}] {f['message']}")
            codes.append(f["code"])
            if f["code"] == "FLAG_FOUND":
                all_flags.append(f["data"]["flag"])
        lines.append("")

        if ctx.extracted_files:
            lines.append("Extracted:")
            for e in ctx.extracted_files:
                lines.append(f"  - {e['path']}")
            lines.append("")

        # 判定是否"待人工分析": 工具没搞定的要明确告诉人, 不能悄悄消失
        # 有 STRINGS_EXTRACTED 说明内容已提取呈现(有结论), 不算待人工
        has_extract = bool(ctx.extracted_files)
        has_flag = "FLAG_FOUND" in codes
        has_content = "STRINGS_EXTRACTED" in codes
        if "DECRYPT_NEEDED" in codes:
            manual.append((ctx.target, "疑似加密数据, 自动破解失败, 可提供密钥重试"))
        elif (("FILE_TYPE_UNKNOWN" in codes) and not has_extract
                and not has_flag and not has_content):
            manual.append((ctx.target, "未知文件类型, 无任何提取结果"))

    lines.append("=" * 44)
    lines.append("提取链(文件来龙去脉)")
    lines.append("=" * 44)
    roots, children = build_chain_tree(contexts)
    tree = render_chain_tree(roots, children, contexts)
    if tree:
        lines.extend(tree)
    else:
        lines.append("  (无提取)")
    lines.append("")

    lines.append("=" * 44)
    lines.append("待人工分析")
    lines.append("=" * 44)
    if manual:
        for t, reason in manual:
            lines.append(f"  - {t}")
            lines.append(f"      原因: {reason}")
    else:
        lines.append("  无(所有文件均已自动处理或有明确结论)")
    lines.append("")

    lines.append("=" * 44)
    lines.append("FLAG 汇总")
    lines.append("=" * 44)
    if all_flags:
        for flag in all_flags:
            lines.append(f"  flag: {flag}")
    else:
        lines.append("  未发现 flag")
    lines.append("")
    lines.append("=" * 44)

    report_path = OUTPUT_DIR / "report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return report_path


def print_summary(contexts):
    """终端最终摘要: 每个文件的关键结论(人话版, 不刷屏)
    详细流水见上方逐轮输出与 output/report.txt"""
    bar = "=" * 52
    print(f"\n{bar}")
    print("  分析完成 · 简要汇总")
    print(bar)

    all_flags = []
    manual = []

    for ctx in contexts:
        rel = os.path.relpath(ctx.target)

        ftype = "未知"
        for f in ctx.findings:
            if f["code"] == "FILE_TYPE_DETECTED":
                ftype = f["data"].get("type", "未知")

        # 收集该文件的关键结论(按出现顺序)
        lines_out = []
        for f in ctx.findings:
            d = f.get("data") or {}
            if f["code"] == "FLAG_FOUND":
                all_flags.append(d["flag"])
                lines_out.append(f"[+] FLAG: {d['flag']}")
            elif f["code"] == "DECODED":
                final = d["layers"][-1]["result"].strip()
                lines_out.append(f"[+] 解码({len(d['layers'])}层): {final[:110]}")
            elif f["code"] == "CAESAR_DECODED":
                lines_out.append(f"[+] {f['message'][:120]}")
            elif f["code"] == "KEYWORD_FOUND":
                lines_out.append(f"[!] 关键字: {', '.join(d.get('keywords', []))}")
            elif f["code"] == "STRINGS_EXTRACTED" and ftype == "未知" and d.get("preview"):
                # 只显示文本类文件的字符串内容(二进制里的噪音字符串无意义)
                lines_out.append(f"[+] 字符串: {d['preview'][0][:110]}")
            elif f["code"] == "DECRYPT_NEEDED":
                manual.append(rel)
                lines_out.append("[!] 疑似加密数据 — 需密钥/人工")

        # 提取产物(去重)
        if ctx.extracted_files:
            names = sorted({os.path.basename(e["path"]) for e in ctx.extracted_files})
            lines_out.append(f"[+] 提取 {len(names)} 个: {', '.join(names)}")

        if not lines_out:
            continue  # 纯噪音轮(全是 NOT_FOUND), 不显示

        print(f"\n  {rel}  [{ftype}]")
        for l in lines_out:
            print(f"    {l}")

    print(f"\n{bar}")
    if all_flags:
        uniq = list(dict.fromkeys(all_flags))
        print(f"  FLAG 汇总: {', '.join(uniq)}")
    else:
        print("  FLAG: 未发现")
    if manual:
        names = ", ".join(os.path.basename(m) for m in dict.fromkeys(manual))
        print(f"  待人工分析: {names}(需密钥/进一步分析)")
    print(bar)

    # ===== 提取链树(文件来龙去脉) =====
    roots, children = build_chain_tree(contexts)
    tree = render_chain_tree(roots, children, contexts)
    if tree:
        print(f"\n{bar}")
        print("  提取链")
        print(bar)
        for line in tree:
            print(f"  {line}")
        print(bar)


# figlet slant 字体字模(官方, 6行高) —— 用于主页大字标题
_FONT_HEIGHT = 6
_FONT = {
    'M': [
        '    __  ___',
        '   /  |/  /',
        '  / /|_/ / ',
        ' / /  / /  ',
        '/_/  /_/   ',
        '           ',
    ],
    'I': [
        '    ____',
        '   /  _/',
        '   / /  ',
        ' _/ /   ',
        '/___/   ',
        '        ',
    ],
    'S': [
        '   _____',
        '  / ___/',
        '  \\__ \\ ',
        ' ___/ / ',
        '/____/  ',
        '        ',
    ],
    'C': [
        '   ______',
        '  / ____/',
        ' / /     ',
        '/ /___   ',
        '\\____/   ',
        '         ',
    ],
    ' ': [
        '       ',
        '       ',
        '       ',
        '       ',
        '       ',
        '       ',
    ],
    'H': [
        '    __  __',
        '   / / / /',
        '  / /_/ / ',
        ' / __  /  ',
        '/_/ /_/   ',
        '          ',
    ],
    'U': [
        '   __  __',
        '  / / / /',
        ' / / / / ',
        '/ /_/ /  ',
        '\\____/   ',
        '         ',
    ],
    'N': [
        '    _   __',
        '   / | / /',
        '  /  |/ / ',
        ' / /|  /  ',
        '/_/ |_/   ',
        '          ',
    ],
    'T': [
        '  ______',
        ' /_  __/',
        '  / /   ',
        ' / /    ',
        '/_/     ',
        '        ',
    ],
    'E': [
        '    ______',
        '   / ____/',
        '  / __/   ',
        ' / /___   ',
        '/_____/   ',
        '          ',
    ],
    'R': [
        '    ____ ',
        '   / __ \\',
        '  / /_/ /',
        ' / _, _/ ',
        '/_/ |_|  ',
        '         ',
    ],
}


def figlet_line(text):
    """把文本渲染成 figlet 大字, 返回行列表"""
    first = _FONT.get(text[0].upper(), _FONT[" "])
    rows = [""] * len(first)
    for ch in text:
        glyph = _FONT.get(ch.upper(), _FONT[" "])
        for i in range(len(rows)):
            rows[i] += glyph[i]
    return rows



def print_banner():
    """无参数运行时的主页: figlet 艺术字标题 + 用法说明"""
    # Windows 启用 ANSI 颜色
    if os.name == "nt":
        os.system("")
    cyan = "\033[36m"
    reset = "\033[0m"

    print()
    for row in figlet_line("MISC HUNTER"):
        print(f"{cyan}{row}{reset}")
    print(f"{cyan}  CTF MISC ANALYSIS TOOLKIT · v3.0{reset}")
    print()
    print("用法:")
    print("  python hunter.py <文件或目录> [更多...]")
    print()
    print("示例:")
    print("  python hunter.py samples/snake.jpg    分析单个文件")
    print("  python hunter.py samples/             批量分析目录下所有文件")
    print()
    print("流程:")
    print("  识别文件类型 → 分析(元数据/PNG/LSB/ZIP/RAR/解码/隐写)")
    print("  → 提取隐藏内容 → 递归分析新文件 → 简要汇总 + 完整报告")
    print()
    print("报告:")
    print("  完整结果(逐文件细节/提取链/待人工清单/FLAG)写入 output/report.txt")
    print()
    print("独立工具:")
    print("  python tools/caesar_cli.py \"密文\"      凯撒全26位爆破")
    print("  python tools/decoder_cli.py            交互解码工具箱")
    print()
    print("提示: 外部工具(binwalk/zsteg/steghide/F5/7z)未安装时")
    print("      对应插件自动降级提示, 不影响其他分析")
    print()


def expand_inputs(args):
    """命令行参数展开: 文件直接用, 目录递归扫描其下所有文件"""
    files = []
    for arg in args:
        if os.path.isdir(arg):
            for root, _dirs, names in os.walk(arg):
                for name in sorted(names):
                    if name.startswith("."):
                        continue
                    files.append(os.path.join(root, name))
        else:
            files.append(arg)
    return files


def main():
    raw = sys.argv[1:]
    if not raw:
        print_banner()   # 无参数: 主页 + 用法
        return

    targets = expand_inputs(raw)
    if not targets:
        print("[!] 输入的目录下没有文件")
        return

    # 分析起止时间与耗时
    start = datetime.now()
    if len(targets) > 1:
        print(f"[*] 共 {len(targets)} 个目标文件")
    print(f"[开始] {start.strftime('%Y-%m-%d %H:%M:%S')}")

    ensure_dirs()
    contexts = run_analysis(targets)
    report_path = write_report(contexts)
    print_summary(contexts)

    end = datetime.now()
    cost = round((end - start).total_seconds(), 1)
    print(f"[结束] {end.strftime('%Y-%m-%d %H:%M:%S')} · 耗时 {cost} 秒")
    print(f"\n[完成] 分析结束。终端上方是简要汇总, "
          f"完整结果(逐文件细节/提取链/待人工清单/FLAG)在报告文件:")
    print(f"       {report_path}")


if __name__ == "__main__":
    main()
