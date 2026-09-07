'''
凯撒/ROT 检测插件

底层逻辑:
    凯撒只移位字母(A-Z/a-z), 空格和标点原样保留
    -> 密文试全部 26 种移位, 正确移位解出的文本字母频率最像英文
    -> 用英文频率表打分(english_score), 最高分移位即真实移位
    -> 移位 0 得分最高 = 本来就是明文, 不是凯撒加密, 安静退出

候选处理: 同 XOR/LSB 模式, 解出文本落盘进队列(strings 接力 flag)

1.0 说明:
    - 只处理"文本形态"文件(可打印占比高且字母密集), 二进制不试
    - 自动检测无需知道 ROT 几; ROT13 是凯撒的特例, 同样覆盖
'''

import os

from core.plugin import Plugin
from utils.decoders import (
    english_score, count_common_words, plausible_plain, has_flag_marker,
)
from utils.paths import EXTRACT_DIR, ensure_dirs


class CaesarDetector(Plugin):
    name = "Caesar Detector"
    version = "1.0"
    priority = 55

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        if not data:
            return None

        # 前置: 只分析文本形态(可打印占比高)
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(data) < 0.9:
            return None  # 不是文本, 凯撒无从谈起

        # ========== 轨1(确定性, 无需字母统计): flag 结构还原 ==========
        # 凯撒只移字母, flag{ 会被移位成别的字母, 正确移位必然还原它
        # flag 内容可能是乱码/hex(字母占比低), 频率法区分不了, 但前缀是精确特征
        # 从 shift=1 开始: shift=0 命中 = 明文自带 flag(那是 strings 的活, 不算凯撒)
        best_shift = None
        for shift in range(1, 26):
            if has_flag_marker(self._shift(data, shift)):
                best_shift = shift
                break

        # ========== 轨2(频率法): 无 flag 结构, 按英文频率打分 ==========
        if best_shift is None:
            # 频率法需要字母统计样本
            letters = sum(
                1 for b in data
                if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A
            )
            if letters / len(data) < 0.6:
                return None  # 字母太少, 频率法无意义

            # 凯撒保留空格, 英文句子必有空格结构;
            # 无空格 = 编码串(Base64/hex/连续字母), 频率法对它们会误报
            if data.count(0x20) / len(data) < 0.02:
                return None

            best_shift, best_score = 0, -1.0
            for shift in range(26):
                dec = self._shift(data, shift)
                # 组合评分: 英文频率 + 常见词命中加权
                # (词命中是确定性特征, 短文本比频率可靠;
                #  词表含 flag/ctf/secret 等 CTF 词)
                score = english_score(dec) + 5.0 * count_common_words(dec)
                if score > best_score:
                    best_shift, best_score = shift, score

            if best_shift == 0:
                return None  # 明文本身得分最高: 不是凯撒加密

        # 解出文本做最终验证(可读或含 flag 结构才报)
        plain = self._shift(data, best_shift)
        if not plausible_plain(plain, letter_th=0.7):
            return None

        # ========== 解出明文落盘, 进队列(strings 接力) ==========
        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".caesar_plain.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(plain.decode("utf-8", errors="replace"))

        context.extracted_files.append({
            "path": out_path,
            "source": target,
            "method": "CAESAR_DECODE",
            "offset": 0
        })

        preview = plain.decode("utf-8", errors="replace")[:100]
        # best_shift 是解密位移(对密文做 +best_shift 还原明文)
        # 加密时的 ROT 数 = 26 - best_shift (ROT13 自逆, 两者相等)
        rot_n = best_shift if best_shift == 13 else (26 - best_shift) % 26
        return {
            "code": "CAESAR_DECODED",
            "message": (
                f"发现凯撒加密(ROT{rot_n}), "
                f"解出: {preview}"
            ),
            "severity": "WARNING",
            "data": {
                "shift": best_shift,
                "rot": rot_n,
                "plain_path": out_path
            }
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _shift(self, data, shift):
        """凯撒移位: 只移字母, 其他字节原样保留"""
        out = bytearray()
        for b in data:
            if 0x41 <= b <= 0x5A:      # 大写
                out.append(0x41 + (b - 0x41 + shift) % 26)
            elif 0x61 <= b <= 0x7A:    # 小写
                out.append(0x61 + (b - 0x61 + shift) % 26)
            else:
                out.append(b)
        return bytes(out)
