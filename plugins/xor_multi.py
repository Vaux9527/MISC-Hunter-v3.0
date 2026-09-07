'''
多字节 XOR 爆破器

原理: key 是一串字节, 加密时循环使用: plain[i] XOR key[i % keylen]
    核心洞察: 密文按 key 长度分组后, 每一"列"都是单字节 XOR
    (位置 0,L,2L.. 全被 key[0] XOR, 位置 1,L+1.. 全被 key[1] XOR ...)
    -> 把"多字节问题"降回"已解决的单字节问题"

破解流程:
    1. 猜 key 长度 L (2~32)
    2. 把密文分 L 列: cols[i] = cipher[i::L]
    3. 每列做单字节频率分析: 试 256 个 key 字节,
       解出的字节流按英文字母频率表打分, 最高分者 = 该列 key 字节
    4. 拼出完整 key -> 全解 -> 三层文本筛子验证(looks_like_text)

诚实边界(数学限制):
    频率攻击需要统计样本, 密文太短(每列样本 < ~50字节)时
    最频假设不稳, 破解会失败 -> 安静返回, 不瞎报

候选处理: 同单字节模式, 候选明文落盘进队列(strings 接力)
'''

import os

from core.plugin import Plugin
from utils.decoders import plausible_plain, ENGLISH_FREQ
from utils.paths import EXTRACT_DIR, ensure_dirs

MIN_LEN = 64        # 短于它统计无效, 不爆
MAX_KEYLEN = 32     # 猜测的 key 长度上限
MAX_PRINTABLE = 0.9  # 密文可打印占比高于它 -> 不像密文, 不爆
SAMPLE_CAP = 200    # 每列最多取这么多字节做频率分析(样本足够即可, 防大文件卡顿)


class XorMultiBruteforcer(Plugin):
    name = "Multi-XOR Bruteforcer"
    version = "1.0"
    priority = 61

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            cipher = f.read()

        # 工具产物文件不分析(进队列只为 strings/flag 接力)
        if os.path.basename(target).endswith((
            ".xor_candidates.txt", ".xor_multi_candidates.txt",
            ".lsb_candidates.txt", ".decrypted.txt",
        )):
            return None

        # 已知格式的文件不是裸密文(JPEG/ZIP/PNG/BMP 等), 不需要问 key
        KNOWN_FORMATS = (
            b"PK\x03\x04", b"\xFF\xD8\xFF", b"\x89PNG\r\n\x1a\n",
            b"GIF8", b"%PDF", b"BM",
        )
        for magic in KNOWN_FORMATS:
            if cipher.startswith(magic):
                return None

        # 密文本身太"干净"就不爆(真密文通常是乱码)
        printable = sum(1 for b in cipher if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / len(cipher) > MAX_PRINTABLE:
            return None

        if len(cipher) < MIN_LEN:
            # 太短, 频率统计无效 -> 提示人类提供密钥(人机接力)
            return self._need_key_finding()

        # ========== 逐个长度尝试 ==========
        found = []
        for keylen in range(2, min(MAX_KEYLEN, len(cipher) // 4) + 1):
            key = self._guess_key(cipher, keylen)
            if key is None:
                continue
            plain = bytes(
                cipher[i] ^ key[i % keylen]
                for i in range(len(cipher))
            )
            # 候选判定: 像英文 或 含 flag{/ctf{ 结构(flag 内容可能非英文分布)
            # 追加大写占比闸门: 大写密集的乱码(XOR 后落在大写区)直接排除
            if not plausible_plain(plain, letter_th=0.75):
                continue
            upper = sum(1 for b in plain if 0x41 <= b <= 0x5A)
            if upper / len(plain) > 0.4:
                continue
            found.append({
                "keylen": keylen,
                "key": key,
                "plain": self._to_text(plain),
            })

        if not found:
            # 自动破解失败 -> 提示人类提供密钥
            return self._need_key_finding()

        # ========== 候选落盘, 进队列(strings 接力) ==========
        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".xor_multi_candidates.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# {target} 的多字节XOR爆破候选({len(found)}条)\n")
            for c in found:
                key_text = "".join(chr(k) if 32 <= k <= 126 else f"\\x{k:02x}" for k in c["key"])
                f.write(f"[keylen={c['keylen']} key={key_text!r}]\n")
                f.write(c["plain"] + "\n\n")

        context.extracted_files.append({
            "path": out_path,
            "source": target,
            "method": "XOR_MULTI_CANDIDATES",
            "offset": 0
        })

        best = found[0]
        keys_desc = "; ".join(
            f"L{c['keylen']}:'{''.join(chr(k) if 32 <= k <= 126 else '.' for k in c['key'])}'"
            for c in found
        )
        return {
            "code": "XOR_MULTI_FOUND",
            "message": (
                f"多字节XOR破解: {len(found)}个候选key ({keys_desc}), "
                f"明文已写入候选文件(完整明文见文件)"
            ),
            "severity": "WARNING",
            "data": {
                "candidate_count": len(found),
                "candidates": [
                    {"keylen": c["keylen"], "key": list(c["key"])}
                    for c in found
                ],
                "path": out_path
            }
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _need_key_finding(self):
        """
        "人机接力"信号: 疑似加密但自动破解失败(或太短无法统计)
        由 hunter.py 入口层看到此 finding 后询问用户是否有密钥
        (插件保持无 I/O, 交互是入口层的事)
        """
        return {
            "code": "DECRYPT_NEEDED",
            "message": "疑似加密数据(无文件格式/自动破解失败), 可提供密钥手动尝试解密",
            "severity": "INFO",
            "data": {}
        }

    def _guess_key(self, cipher, keylen):
        """
        对每列做单字节频率分析: 试全部 256 个 key 字节,
        解出的字节流按英文频率表打分, 最高分者即该列 key 字节
        (比"空格假设"稳: 文本规律/空格分布不均时最频假设会错)
        """
        key = []
        for col_start in range(keylen):
            col = cipher[col_start::keylen][:SAMPLE_CAP]
            if len(col) < 4:
                return None  # 该列样本太少, 此长度不可靠

            best_k, best_score = 0, -1.0
            for k in range(256):
                score = sum(
                    ENGLISH_FREQ.get(b ^ k, 0.0) for b in col
                )
                if score > best_score:
                    best_k, best_score = k, score
            key.append(best_k)
        return bytes(key)

    def _to_text(self, raw):
        return "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in raw
        )
