'''
engine不懂得任何业务
其将作为项目经理
只在乎和确定各项业务的流程
V1.0将只会负责：
    1,接收目标文件
    2,创建context
    3,创建logger
    4,依次运行插件
'''
from core.context import AnalysisContext
from core.logger import Logger

class Engine:
    def __init__(self,target,plugins):
        self.context = AnalysisContext(target)
        self.plugins = plugins
        self.target = target
        self.logger = Logger(self.context)

    def run(self):
        self.logger.info("开始分析")
        # 按插件 priority 排序执行: 数字小的先跑
        # (依赖其他插件产出的插件, 通过 priority 声明自己的顺序)
        ordered = sorted(self.plugins, key=lambda p: p.priority)
        for plugin in ordered:
            try:
                result = plugin.run(self.context)
            except Exception as e:
                #keyboardinterrupt作为用户手动停止，如果用baseexception，ctrl+c将无法退出
                self.logger.error(f"{plugin.name}运行失败，原因：{str(e)}")
                continue
            if result is not None:
                self.context.add_finding(
                    result["code"],
                    result["message"],
                    result["severity"],
                    result["data"]
                )
                self.logger.info(result["message"])
        self.logger.info("分析完成")

        return self.context
