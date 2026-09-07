'''
输出路径统一管理

为什么要有这个文件:
    插件之前硬编码 os.path.join("output", ...) 是相对当前工作目录的
    如果从别的目录运行 hunter.py, 文件会写到错误的地方
    这里统一基于"项目根目录"计算路径, 从任何地方运行都正确

约定:
    output/              报告文件(report.txt)
    output/extracted/    所有提取/生成的中间文件

用法(插件里):
    from utils.paths import EXTRACT_DIR
    out = os.path.join(str(EXTRACT_DIR), filename)
'''

from pathlib import Path

# 项目根目录 = 本文件(utils/paths.py)的上两级
BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "output"          # 报告目录
EXTRACT_DIR = OUTPUT_DIR / "extracted"    # 提取产物目录


def ensure_dirs():
    """确保输出目录存在(不存在就创建)"""
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
