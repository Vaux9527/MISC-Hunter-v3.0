import sys
import os


# 获取项目根目录
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# 加入Python模块搜索路径
sys.path.append(BASE_DIR)


from core.context import AnalysisContext



# 创建分析上下文
context = AnalysisContext("snake.jpg")


print("初始化:")
print("目标文件:", context.target)
print("发现:", context.findings)


# 模拟插件发现隐藏ZIP
context.add_finding(
    code="ZIP_FOUND",
    message="发现隐藏ZIP文件",
    data={
        "offset": 123456
    }
)
context.add_finding(
    code="EXIF_FOUND",
    message="发现EXIF元数据",
    data={
        "camera":"Canon"
    }
)

print("\n分析后:")
print(context.findings)