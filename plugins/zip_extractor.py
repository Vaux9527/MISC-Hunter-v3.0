'''
提取隐藏的 ZIP 数据
'''

import os
import zipfile

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR

class ZipExtractor(Plugin):
    name = "ZIP Extractor"
    version = "1.0"
    priority = 30  # 依赖 ZipDetector(20) 先产出 ZIP_EMBEDDED/STANDALONE finding

    def _unpack(self, zip_location_path, source, offset, context):
                 #解压
        with zipfile.ZipFile(zip_location_path) as z:
            for name in z.namelist():
                data = z.read(name)
                out_path = os.path.join(str(EXTRACT_DIR), name)
                with open(out_path,"wb") as f:
                    f.write(data)
                context.extracted_files.append(
                    {
                            "path" : out_path,
                            "source" : source,
                            "method" : "ZIP_UNPACK",
                            "offset" : offset
                    }
                )
       

    def run(self, context):

        target = context.target
        zip_location_path = None
        for finding in context.findings:
            if finding["code"] == "ZIP_EMBEDDED":
                offset = finding["data"]["offset"]
                filename = f"extracted_{offset}.zip"
                zip_location_path = os.path.join(str(EXTRACT_DIR), filename)
                # 从 ZIP 开始位置读取
                with open(target, "rb") as file:
                    file.seek(offset)
                    data = file.read()
                # 写入新的 ZIP 文件
                with open(zip_location_path, "wb") as file:
                    file.write(data)
                # 记录提取结果
                context.extracted_files.append(
                    {
                        "path": zip_location_path,
                        "source": target,
                        "method": "ZIP_OFFSET",
                        "offset": offset
                    }
                )

                self._unpack(zip_location_path,target,offset,context)

            elif finding["code"] == "ZIP_STANDALONE":
                offset = 0
                zip_location_path = target

                self._unpack(zip_location_path,target,offset,context)

        if zip_location_path is None:  
            return {
                "code": "ZIP_NOT_FOUND",
                "message": "没有找到可提取的ZIP数据",
                "severity": "INFO",
                "data": {}
            }    


        return {
            "code": "ZIP_EXTRACTED",
            "message": "ZIP数据提取成功",
            "severity": "INFO",
            "data": {
                "path": zip_location_path,
                "offset": offset
            }
        }
