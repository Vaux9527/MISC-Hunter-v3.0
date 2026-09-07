import os
import sys

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)

from core.engine import Engine
from plugins.file_type import FileTypeDetector
from plugins.zip_detector import ZipDetector
from plugins.zip_extractor import ZipExtractor


target = os.path.join(
    BASE_DIR,
    "samples",
    "snake.jpg"
)

plugins = [
    FileTypeDetector(),
    ZipDetector(),
    ZipExtractor()
]

engine = Engine(target, plugins)

context = engine.run()


print("========== 分析结果 ==========")

print("目标文件:")
print(context.target)

print("\n发现结果:")
for finding in context.findings:
    print(finding)

print("\n提取文件:")
for extracted_file in context.extracted_files:
    print(extracted_file)

print("\n分析日志:")
for log in context.logs:
    print(log)