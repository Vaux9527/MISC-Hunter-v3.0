'''
在文件中自动寻找 Base64 编码内容并解码
解出第一层后继续尝试解开 Base 套娃, 每层结果都记录
1.0 说明:
    - 自动检测只认 Base64 特征(+/= 字符集独特, 误报少)
      Base32/16 字符集和普通文本重叠太多, 自动找候选会误报爆炸, 留给后续版本
    - 解码出的最终明文会落盘(output 下 .decoded.txt 文件)并进入提取队列,
      让后续插件(字符串分析等)能接力分析; 插件间靠文件通信, 不直接依赖 finding
'''

import os
import re

from core.plugin import Plugin
from utils.decoders import try_b64, decode_chain
from utils.paths import EXTRACT_DIR, ensure_dirs


class DecoderPlugin(Plugin):
    name = "Decoder"
    version = "1.0"
    priority = 40

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        # 找 Base64 候选: 连续字符 >= 16, 结尾可带 0~2 个 =
        candidates = re.findall(rb'[A-Za-z0-9+/]{16,}={0,2}', data)

        for cand in candidates:
            text = cand.decode("ascii", errors="ignore")
            offset = data.find(cand)

            # 第一层: 候选本身是 Base64
            first = try_b64(text)
            if first is None:
                continue

            # 后续层: 从明文继续尝试, 解开套娃
            layers = decode_chain(first)
            layers.insert(0, {"decoder": "Base64", "result": first})

            # 最终明文落盘, 进提取队列(插件间靠文件接力)
            final_text = layers[-1]["result"]
            ensure_dirs()
            out_path = os.path.join(
                str(EXTRACT_DIR),
                os.path.basename(target) + ".decoded.txt"
            )
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(final_text)
            context.extracted_files.append(
                {
                    "path": out_path,
                    "source": target,
                    "method": "DECODED_OUTPUT",
                    "offset": offset
                }
            )

            return {
                "code": "DECODED",
                "message": f"发现编码内容并解码({len(layers)}层)",
                "severity": "INFO",
                "data": {
                    "offset": offset,
                    "layers": layers
                }
            }

        return {
            "code": "DECODER_NOTHING",
            "message": "未发现可解码内容",
            "severity": "INFO",
            "data": {}
        }
