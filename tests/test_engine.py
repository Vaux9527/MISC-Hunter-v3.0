"""
Engine 测试

验证：
TestPlugin -> Engine -> Context -> Logger
这一整条基础流程是否正常。
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
from plugins.test_plugin import TestPlugin


# 创建测试插件
plugin = TestPlugin()


# 创建 Engine
engine = Engine(
    "snake.jpg",
    [plugin]
)


# 执行分析
context = engine.run()


# 输出最终结果
print("========== 分析结果 ==========")

print("目标文件:")
print(context.target)


print("\n发现结果:")

for finding in context.findings:
    print(finding)


print("\n分析日志:")

for log in context.logs:
    print(log)