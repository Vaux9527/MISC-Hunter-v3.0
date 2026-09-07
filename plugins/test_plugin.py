'''
测试用插件
无实际功能, 仅用于验证 Engine -> Plugin -> Context -> Logger 基础流程
'''

from core.plugin import Plugin

class TestPlugin(Plugin):

    name = "Test Plugin"
    version = "1.0"

    def run(self, context):
        return  {
            "code": "TEST_FOUND",
            "message": "测试插件成功运行",
            "severity": "INFO",
            "data": {
                "target": context.target
            }
        } #模拟返回了一个finding