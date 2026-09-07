"""
FileTypeDetector 测试

验证：
目标文件
    ↓
FileTypeDetector
    ↓
Engine
    ↓
Context
    ↓
Finding + Logger
"""

import os
import sys


# 获取项目根目录
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)


from core.engine import Engine
from plugins.file_type import FileTypeDetector


# 测试目标
target = os.path.join(
    BASE_DIR,
    "samples",
    "snake.jpg"
)


# 创建插件
plugin = FileTypeDetector()


# 创建 Engine
engine = Engine(target, [plugin])


# 执行分析
context = engine.run()


# 输出结果
print("========== 分析结果 ==========")

print("目标文件:")
print(context.target)

print("\n发现结果:")
for finding in context.findings:
    print(finding)

print("\n分析日志:")
for log in context.logs:
    print(log)