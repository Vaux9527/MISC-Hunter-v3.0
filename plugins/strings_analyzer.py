'''
字符串分析器

三层递进:
    层1: 检测 flag{...} / ctf{...} 模式(含大小写变体)  -> "找到就给"
    层2: 检测敏感关键字(http/KEY/password/token 等)     -> 可疑线索
    层3: 提取全部可打印字符串, 写入 .strings.txt 文件   -> "找不到就把原料给人类"

1.0 说明:
    - flag 模式只匹配闭合的 {...}, 被截断/分割的 flag 留给人类在层3原料里找
    - 层3的字符串文件不进 extracted_files(它是给人看的材料, 不是待分析产物)
'''

import os
import re

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs


class StringsAnalyzer(Plugin):
    name = "Strings Analyzer"
    version = "1.0"
    priority = 50

    # 层2: 敏感关键字(字节匹配, 命中任意一个即报告)
    keywords = (b"http", b"KEY", b"password", b"token")

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        # ========== 层1: flag / ctf 模式 ==========
        # [Ff][Ll][Aa][Gg] = 大小写混合的 flag, { 后到第一个 } 之间最多200字符
        flag_pattern = (
            rb'[Ff][Ll][Aa][Gg]\{[^}]{0,200}\}'
            rb'|[Cc][Tt][Ff]\{[^}]{0,200}\}'
        )
        hits = re.findall(flag_pattern, data)

        if hits:
            text = hits[0].decode("ascii", errors="ignore")
            return {
                "code": "FLAG_FOUND",
                "message": f"发现疑似flag: {text}",
                "severity": "INFO",
                "data": {
                    "flag": text,
                    "offset": data.find(hits[0])
                }
            }

        # ========== 层2: 敏感关键字 ==========
        keyword_hits = [kw.decode("ascii") for kw in self.keywords if kw in data]

        if keyword_hits:
            return {
                "code": "KEYWORD_FOUND",
                "message": f"发现敏感关键字: {', '.join(keyword_hits)}",
                "severity": "WARNING",
                "data": {
                    "keywords": keyword_hits
                }
            }

        # ========== 层3: 全量字符串提取, 写文件给人类 ==========
        # [\x20-\x7e] = 空格到~的可打印ASCII区间, 连续>=4个算一条
        strings = re.findall(rb'[\x20-\x7e]{4,}', data)

        if not strings:
            return {
                "code": "STRINGS_NONE",
                "message": "未发现任何可打印字符串",
                "severity": "INFO",
                "data": {}
            }

        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".strings.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            for s in strings:
                f.write(s.decode("ascii", errors="ignore") + "\n")

        # preview: 前10条内容, 供终端直接展示(长行截断到120字符)
        preview = [
            s.decode("ascii", errors="ignore")[:120] for s in strings[:10]
        ]

        return {
            "code": "STRINGS_EXTRACTED",
            "message": f"提取到{len(strings)}条字符串, 已写入 {out_path}",
            "severity": "INFO",
            "data": {
                "count": len(strings),
                "path": out_path,
                "preview": preview
            }
        }
