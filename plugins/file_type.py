'''
通过文件头部的魔数
初步判定文件实际到底是什么文件类型
'''

from core.plugin import Plugin

class FileTypeDetector(Plugin):
    name = "File Type Detector"
    version = "1.0"
    priority = 10

    def run(self, context):
        target = context.target

        magic_signatures = {
            b"\xFF\xD8\xFF": "JPEG",
            b"\x89PNG\r\n\x1a\n": "PNG",
            b"GIF8": "GIF",
            b"%PDF": "PDF",
            b"PK\x03\x04": "ZIP",
            b"Rar!\x1a\x07": "RAR",
            b"BM": "BMP",
        }

        with open(target, "rb") as file:
            data = file.read(8)

        for signature, file_type in magic_signatures.items():

            if data.startswith(signature):
                finding = {
                    "code" : 'FILE_TYPE_DETECTED',
                    "message" : f"该文件实际为{file_type}",
                    "severity": "INFO",
                    "data": {
                        "type": file_type,
                        "magic": signature
                    }
                }

                return finding

        fail_finding = {
            "code": "FILE_TYPE_UNKNOWN",
            "message": "无法通过文件魔数识别文件类型",
            "severity": "WARNING",
            "data": {
                "magic": data
            }
        }

        return fail_finding

        # 如果所有魔数都没匹配
        # 返回 FILE_TYPE_UNKNOWN  
