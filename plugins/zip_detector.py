"""
简单寻找文件中是否存在ZIP数据
目前仅检测 ZIP Local File Header
V1.0 仅探测第一次出现的位置
"""

from core.plugin import Plugin

class ZipDetector(Plugin):
    name = "ZIP Detector"
    version = "1.0"
    priority = 20

    def run(self, context):
        target = context.target

        with open(target, "rb") as file:
            data = file.read()

        offset = data.find(b"PK\x03\x04")

        if offset != -1:

            # 构造 finding
            if offset == 0:
                finding = {
                    "code": "ZIP_STANDALONE",
                    "message": "文件本身为ZIP",
                    "severity": "INFO",
                    "data": {
                        "offset": 0
                    }
                }
            else:
                finding = {
                    "code": "ZIP_EMBEDDED",
                    "message": "发现疑似嵌入式ZIP数据",
                    "severity": "WARNING",
                    "data": {
                        "offset": offset
                    }
                }

            return finding

        # 没找到
        fail_finding = {
            "code": "ZIP_NOT_FOUND",
            "message": "未发现ZIP文件特征",
            "severity": "INFO",
            "data": {}
        }

        return fail_finding