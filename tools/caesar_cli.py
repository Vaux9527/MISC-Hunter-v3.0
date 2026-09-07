# -*- coding: utf-8 -*-
"""
Caesar Brute Force CLI — 凯撒密码全 26 位爆破工具

用法:
    python caesar_cli.py "密文"          # 直接传密文
    python caesar_cli.py cipher.txt      # 从文件读取(参数是存在的文件路径)
    python caesar_cli.py                 # 交互粘贴(空行结束)

特性:
    全 26 位移一次显示
    常见英文单词智能评分, 命中最高者 ★ 高亮(词表含 flag/ctf 等 CTF 词)
    支持大小写, 数字符号原样保留

独立自包含工具(零依赖, 可单独拷贝运行), 核心评分逻辑与
项目 plugins/caesar.py / utils/decoders.py 同源
"""

import os
import sys

# Windows 控制台: 启用 ANSI 颜色 + UTF-8 输出
if os.name == "nt":
    os.system("")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ANSI 颜色
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ───────────────────────── 常见英文单词词典(智能评分) ─────────────────────────
COMMON_WORDS = frozenset("""
    the be to of and a in that have i it for not on with he as you do at
    this but his by from they we say her she or an will my one all would
    there their what so up out if about who get which go me when make can
    like time no just him know take people into year your good some could
    them see other than then now look only come its over think also back
    after use two how our work first well way even new want because any
    these give day most us hello world is are was were been has had did
    does doing am being secret message password attack dawn meet flag ctf
    crypto cipher encrypt decrypt key shift
""".split())


def caesar_decrypt(ciphertext, shift):
    """凯撒解密: 密文字母右移 shift 位还原明文"""
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def score_text(text):
    """词命中评分: 命中常见单词数(去标点, 忽略大小写)"""
    words = text.lower().split()
    hits = 0
    for w in words:
        w = w.strip(".,!?;:'\"()[]{}<>-_")
        if w in COMMON_WORDS:
            hits += 1
    return hits


def read_input(args):
    """参数 -> 密文: 文件路径读文件 / 文本直接用 / 无参数交互输入"""
    if args:
        if os.path.isfile(args[0]):
            with open(args[0], "r", encoding="utf-8", errors="replace") as f:
                return f.read().strip()
        return " ".join(args).strip()

    print(f"{CYAN}粘贴密文, 输入完成后单独一行 END 并回车:{RESET}")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def print_banner():
    print(f"{CYAN}")
    print("╔══════════════════════════════════════════════╗")
    print("║        CAESAR  BRUTE  FORCE  v1.0            ║")
    print("║     全 26 位移爆破 · 常见词智能评分           ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{RESET}")


def main():
    cipher = read_input(sys.argv[1:])
    if not cipher:
        print(f"{YELLOW}[!] 未输入密文{RESET}")
        return

    print_banner()
    print(f"{DIM}密文({len(cipher)}字符): {cipher[:80]}{RESET}\n")

    results = []
    for shift in range(26):
        plain = caesar_decrypt(cipher, shift)
        results.append((shift, plain, score_text(plain)))

    best_score = max(r[2] for r in results)
    meaningful = best_score > 0

    print(f"{BOLD}{'位移':<8}{'评分':<6}明文{RESET}")
    print("-" * 72)
    for shift, plain, score in results:
        is_best = meaningful and score == best_score

        # 单行显示, 超长截断
        display = plain.replace("\n", "\\n")
        if len(display) > 76:
            display = display[:73] + "..."

        if is_best:
            mark = f"{GREEN}★  {RESET}"
        elif score > 0:
            mark = f"{YELLOW}   {RESET}"
        else:
            mark = "   "

        score_str = f"{score}" if score else "-"
        if is_best:
            line = f"{mark}Shift {shift:<3} {score_str:<5} {GREEN}{display}{RESET}"
        elif score > 0:
            line = f"{mark}Shift {shift:<3} {score_str:<5} {display}"
        else:
            line = f"{mark}Shift {shift:<3} -     {DIM}{display}{RESET}"
        print(line)

    print("-" * 72)
    if meaningful:
        print(f"{GREEN}★ 标记行为最可能明文(命中{best_score}个常见词){RESET}")
    else:
        print(f"{DIM}未检测到明显英文(评分全 0), 结果仅供参考, 请人工核对{RESET}")


if __name__ == "__main__":
    main()
