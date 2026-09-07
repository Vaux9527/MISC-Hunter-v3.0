'''
各种Plugin的基类
用来全局规定插件的具体实现

priority: 插件执行顺序, 数字越小越先执行
    依赖其他插件产出的插件, 必须声明更大的 priority
    例: ZipExtractor 需要 ZipDetector 先产出 ZIP_EMBEDDED finding
        所以 ZipDetector=20 < ZipExtractor=30
    约定: 每级间隔 10, 给后续插件留插入空间
'''

class Plugin:

    name = "Base Plugin"
    version = "1.0"
    priority = 100   # 执行顺序: 小的先执行

    def run(self, context):
        raise NotImplementedError   #报警：未实现
