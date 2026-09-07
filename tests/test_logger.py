import sys
import os


# 获取项目根目录
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(BASE_DIR)


from core.context import AnalysisContext
from core.logger import Logger



# 创建分析上下文
context = AnalysisContext("snake.jpg")


# 创建日志器
logger = Logger(context)



# 模拟 Engine 产生消息
logger.info(
    "开始分析文件"
)


# 模拟 Plugin 产生消息
logger.info(
    "发现JPEG文件结构"
)


# 模拟异常情况
logger.warning(
    "发现文件尾部存在额外数据"
)


# 模拟失败
logger.error(
    "ZIP提取失败"
)



print("当前日志:")
for log in context.logs:
    print(log)