'''
单字节 XOR 爆破器

原理: 密文的每个字节与同一个 key(0~255) 异或
    解密 = 加密(同一个运算): plain = cipher XOR key

爆破: 256 种 key 全试, 过滤出候选:
    判定 = 像英文文本 或 含 flag{/ctf{ 结构(plausible_plain)
    flag 内容可能是乱码, 纯英文频率会漏, flag 前缀是精确特征

候选处理(有用/无用分流):
    无用: 不过筛的结果直接丢弃, 不产生任何文件
    有用: 全部候选写入 xxx.xor_candidates.txt 进递归队列
          strings 插件自动接力: 候选含 flag{...} 自动报出;
          非flag候选(如人类提示句)由人工查看
    无候选: 返回 None(不是单字节XOR, 可能多字节/其他算法, 安静)

前置(防递归+防噪音):
    文件本身可打印占比 > 0.9 的文本文件不爆——文本 XOR 爆破
    只会产生一堆假候选(还曾导致候选文件被反复爆破无限递归)
    权衡: 文本 XOR "友好key" 产生的可打印密文会漏报(此类题少见)

1.0 限制: 仅单字节 key; 多字节 XOR(如字符串 key)见 xor_multi
'''

import os

from core.plugin import Plugin
from utils.decoders import plausible_plain
from utils.paths import EXTRACT_DIR, ensure_dirs


class XorBruteforcer(Plugin):
    name = "XOR Bruteforcer"
    version = "1.0"
    priority = 60   # 放最后: 它对每个文件都试 256 次, 不影响其他插件

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            cipher = f.read()

        if len(cipher) < 8:
            return None  # 太短没有统计意义, 不爆

        # 前置1: 工具产物文件不爆(它们进队列只为 strings/flag 接力,
        #   再爆破会产出假候选, 曾导致候选文件被反复爆破递归)
        if os.path.basename(target).endswith((
            ".xor_candidates.txt", ".xor_multi_candidates.txt",
            ".lsb_candidates.txt", ".decrypted.txt",
        )):
            return None

        # 前置2: 文本文件不爆(防噪音)
        printable = sum(1 for b in cipher if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(cipher) > 0.9:
            return None

        # ========== 256 种 key 全试 + 候选判定 ==========
        # 判定 = 像英文文本 OR 含 flag{/ctf{ 结构
        # (flag 内容可能是乱码/编码串, 纯英文频率法会漏掉)
        candidates = []
        for key in range(256):
            out = bytes(b ^ key for b in cipher)
            if not plausible_plain(out):
                continue
            candidates.append({"key": key, "text": self._to_text(out)})

        if not candidates:
            return None  # 没有候选: 不是单字节 XOR, 安静

        # ========== 候选落盘, 进队列(strings 接力) ==========
        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".xor_candidates.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# {target} 的单字节XOR爆破候选({len(candidates)}条)\n")
            for c in candidates:
                f.write(f"[key=0x{c['key']:02X}] {c['text']}\n")

        context.extracted_files.append({
            "path": out_path,
            "source": target,
            "method": "XOR_CANDIDATES",
            "offset": 0
        })

        best = candidates[0]["text"][:100]
        return {
            "code": "XOR_CANDIDATES_FOUND",
            "message": (
                f"单字节XOR爆破: {len(candidates)}个候选key, "
                f"已写入候选文件(首个: {best})"
            ),
            "severity": "WARNING",
            "data": {
                "candidate_count": len(candidates),
                "keys": [c["key"] for c in candidates],
                "path": out_path
            }
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _to_text(self, raw):
        """bytes -> 可读字符串(不可解码字节用 . 代替, 保持长度对齐)"""
        return "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in raw
        )
