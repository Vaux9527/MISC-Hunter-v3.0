# -*- coding: utf-8 -*-
"""
凯撒密码全 26 位爆破工具
深色主题 GUI · 艺术字标题 · 智能高亮候选明文
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import string

# ───────────────────────── 常见英文单词词典（用于智能评分） ─────────────────────────
COMMON_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
    "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them", "see",
    "other", "than", "then", "now", "look", "only", "come", "its", "over",
    "think", "also", "back", "after", "use", "two", "how", "our", "work",
    "first", "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "hello", "world", "is", "are", "was", "were",
    "been", "has", "had", "did", "does", "doing", "am", "been", "being",
    "secret", "message", "password", "attack", "dawn", "meet", "at", "the",
    "flag", "ctf", "crypto", "cipher", "encrypt", "decrypt", "key", "shift",
}


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """对密文做指定位移的凯撒解密（shift 为正表示密文右移回明文）。"""
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def score_text(text: str) -> int:
    """简单英文评分：命中常见单词数 + 可打印字母比例。"""
    words = text.lower().translate(str.maketrans("", "", string.punctuation)).split()
    hits = sum(1 for w in words if w in COMMON_WORDS)
    return hits


# ───────────────────────── 艺术字标题（Canvas 阴影 + 渐变字） ─────────────────────────
class ArtTitle(tk.Canvas):
    """用 Canvas 绘制带阴影的大号艺术字标题。"""

    def __init__(self, master, text="CAESAR CRACKER", **kwargs):
        super().__init__(master, height=90, bg="#0d1117", highlightthickness=0, **kwargs)
        self.text = text
        self.bind("<Configure>", self._draw)

    def _draw(self, event=None):
        self.delete("all")
        w = self.winfo_width()
        # 阴影层
        self.create_text(
            w / 2 + 3, 48,
            text=self.text,
            font=("Consolas", 34, "bold"),
            fill="#000000",
        )
        # 主标题层（青绿色霓虹感）
        self.create_text(
            w / 2, 45,
            text=self.text,
            font=("Consolas", 34, "bold"),
            fill="#58e6c8",
        )
        # 副标题装饰线
        self.create_line(w / 2 - 160, 78, w / 2 + 160, 78, fill="#30363d", width=2)
        self.create_text(w / 2, 84, text="◆  BRUTE FORCE  ·  ALL 26 SHIFTS  ◆",
                         font=("Consolas", 9), fill="#8b949e")


# ───────────────────────── 主应用 ─────────────────────────
class CaesarCrackerApp:
    BG_DARK = "#0d1117"
    BG_PANEL = "#161b22"
    BG_INPUT = "#0d1117"
    FG_MAIN = "#c9d1d9"
    FG_DIM = "#8b949e"
    ACCENT = "#58e6c8"
    ACCENT_HOVER = "#7ff0d8"
    HIGHLIGHT = "#2ea043"
    WARN = "#f0883e"

    def __init__(self, root):
        self.root = root
        self.root.title("Caesar Cracker — 凯撒密码爆破")
        self.root.geometry("820x680")
        self.root.minsize(720, 560)
        self.root.configure(bg=self.BG_DARK)

        self._setup_style()
        self._build_ui()

    # ── 样式 ──
    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background=self.BG_DARK)
        style.configure("Panel.TFrame", background=self.BG_PANEL)

        style.configure(
            "Accent.TButton",
            background=self.ACCENT,
            foreground="#0d1117",
            font=("Consolas", 12, "bold"),
            padding=(20, 8),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", self.ACCENT_HOVER), ("pressed", "#3dd4b0")],
        )

        style.configure(
            "Ghost.TButton",
            background=self.BG_PANEL,
            foreground=self.FG_MAIN,
            font=("Consolas", 10),
            padding=(12, 6),
            borderwidth=1,
        )
        style.map("Ghost.TButton", background=[("active", "#21262d")])

    # ── 界面构建 ──
    def _build_ui(self):
        # 艺术字标题
        self.title_canvas = ArtTitle(self.root)
        self.title_canvas.pack(fill="x", padx=0, pady=(8, 4))

        # 输入面板
        input_frame = tk.Frame(self.root, bg=self.BG_PANEL, bd=1, relief="solid",
                                highlightbackground="#30363d", highlightthickness=1)
        input_frame.pack(fill="x", padx=20, pady=(4, 10))

        tk.Label(
            input_frame, text="📜  输入密文 (Ciphertext)",
            bg=self.BG_PANEL, fg=self.ACCENT,
            font=("Consolas", 11, "bold"),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self.cipher_entry = tk.Text(
            input_frame, height=3,
            bg=self.BG_INPUT, fg=self.FG_MAIN,
            insertbackground=self.ACCENT,
            font=("Consolas", 12),
            bd=0, relief="flat",
            highlightbackground="#30363d", highlightthickness=1,
            highlightcolor=self.ACCENT,
            wrap="word",
        )
        self.cipher_entry.pack(fill="x", padx=14, pady=(0, 12))
        self.cipher_entry.insert("1.0", "L fdph, L vdz, L frqtxhuhg.")  # 示例

        # 按钮行
        btn_row = tk.Frame(self.root, bg=self.BG_DARK)
        btn_row.pack(fill="x", padx=20, pady=(0, 10))

        self.crack_btn = ttk.Button(
            btn_row, text="▶  开始爆破  CRACK",
            style="Accent.TButton", command=self.on_crack,
        )
        self.crack_btn.pack(side="left")

        ttk.Button(btn_row, text="清空", style="Ghost.TButton",
                   command=self.on_clear).pack(side="left", padx=(10, 0))
        ttk.Button(btn_row, text="复制最佳结果", style="Ghost.TButton",
                   command=self.on_copy_best).pack(side="left", padx=(10, 0))

        # 状态标签
        self.status_var = tk.StringVar(value="就绪 · 等待输入密文")
        tk.Label(
            btn_row, textvariable=self.status_var,
            bg=self.BG_DARK, fg=self.FG_DIM,
            font=("Consolas", 9),
        ).pack(side="right")

        # 结果区
        result_frame = tk.Frame(self.root, bg=self.BG_PANEL, bd=1, relief="solid",
                                 highlightbackground="#30363d", highlightthickness=1)
        result_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        tk.Label(
            result_frame, text="🔓  爆破结果  (共 26 种位移  ·  绿色高亮 = 最可能明文)",
            bg=self.BG_PANEL, fg=self.ACCENT,
            font=("Consolas", 11, "bold"),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            bg=self.BG_INPUT, fg=self.FG_MAIN,
            font=("Consolas", 11),
            bd=0, relief="flat",
            highlightbackground="#30363d", highlightthickness=1,
            wrap="word",
            state="disabled",
            cursor="arrow",
        )
        self.result_text.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        # 标签样式
        self.result_text.tag_configure("header", foreground=self.FG_DIM,
                                        font=("Consolas", 10, "bold"))
        self.result_text.tag_configure("shift", foreground=self.WARN,
                                        font=("Consolas", 11, "bold"))
        self.result_text.tag_configure("normal", foreground=self.FG_MAIN)
        self.result_text.tag_configure("best", foreground=self.HIGHLIGHT,
                                        font=("Consolas", 11, "bold"),
                                        background="#13241a")
        self.result_text.tag_configure("candidate", foreground="#3fb950",
                                        background="#0f1d14")
        self.result_text.tag_configure("sep", foreground="#30363d")

        # 底部信息
        tk.Label(
            self.root,
            text="Caesar Cracker v1.0  ·  支持大小写 / 数字符号原样保留  ·  基于常见英文单词智能评分",
            bg=self.BG_DARK, fg="#484f58",
            font=("Consolas", 8),
        ).pack(side="bottom", pady=(0, 6))

        # 回车快捷键
        self.root.bind("<Control-Return>", lambda e: self.on_crack())

    # ── 核心逻辑 ──
    def on_crack(self):
        cipher = self.cipher_entry.get("1.0", "end").strip()
        if not cipher:
            messagebox.showwarning("提示", "请先输入密文！")
            return

        # 生成 26 种结果并评分
        results = []
        for shift in range(26):
            plain = caesar_decrypt(cipher, shift)
            score = score_text(plain)
            results.append((shift, plain, score))

        best_score = max(r[2] for r in results)
        # 找出所有候选（分数 >= 1 且 等于最高分 或 最高分>0时取最高分）
        has_meaningful = best_score > 0

        # 渲染
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")

        self.result_text.insert("end", "═" * 72 + "\n", "sep")
        self.result_text.insert("end", f"  密文长度: {len(cipher)} 字符  |  "
                                        f"最高评分: {best_score}  |  "
                                        f"{'检测到英文候选' if has_meaningful else '未检测到明显英文，仅供参考'}\n",
                                "header")
        self.result_text.insert("end", "═" * 72 + "\n\n", "sep")

        for shift, plain, score in results:
            # 位移标签
            self.result_text.insert("end", f"  [Shift {shift:2d}] ", "shift")

            # 内容样式
            if has_meaningful and score == best_score and score > 0:
                tag = "best"
                marker = " ★ 最可能"
            elif score >= 1:
                tag = "candidate"
                marker = f"  (score={score})"
            else:
                tag = "normal"
                marker = ""

            # 单行显示，超长截断提示
            display = plain if len(plain) <= 80 else plain[:77] + "..."
            self.result_text.insert("end", display, tag)
            if marker:
                self.result_text.insert("end", marker, tag)
            self.result_text.insert("end", "\n")

        self.result_text.insert("end", "\n" + "═" * 72 + "\n", "sep")
        self.result_text.insert("end", "  提示: 绿色 ★ 行命中最多常见英文单词，大概率为正确明文。\n",
                                "header")
        self.result_text.insert("end", "═" * 72 + "\n", "sep")

        self.result_text.config(state="disabled")

        # 状态
        if has_meaningful:
            best_shift = next(r[0] for r in results if r[2] == best_score)
            self.status_var.set(f"✓ 爆破完成 · 最佳位移 = {best_shift} (评分 {best_score})")
        else:
            self.status_var.set("✓ 爆破完成 · 未检测到明显英文，请人工核对")

        # 保存最佳结果供复制
        self._best_result = next((r[1] for r in results if r[2] == best_score), results[0][1])

    def on_clear(self):
        self.cipher_entry.delete("1.0", "end")
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.config(state="disabled")
        self.status_var.set("已清空 · 等待输入密文")
        self._best_result = ""

    def on_copy_best(self):
        if not getattr(self, "_best_result", ""):
            messagebox.showinfo("提示", "请先点击「开始爆破」生成结果。")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._best_result)
        self.status_var.set("✓ 最佳结果已复制到剪贴板")


def main():
    root = tk.Tk()
    # 尝试设置 DPI 感知（Windows）
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = CaesarCrackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
