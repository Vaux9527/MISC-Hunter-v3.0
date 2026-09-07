'''
插件自动发现

扫描 plugins/ 目录下的所有模块, 找出继承 Plugin 的类并实例化
新插件只需在 plugins/ 下新建文件并继承 Plugin, 无需手动注册

约定:
    - 模块名以 test_ 开头的跳过(测试用插件不参与自动发现)
    - 同一个模块里多个 Plugin 子类都会被加载

Engine 会按各插件的 priority 属性排序执行
'''

import importlib
import pkgutil

import plugins
from core.plugin import Plugin


def discover_plugins():
    """返回按 priority 排序的插件实例列表"""
    found = []

    for mod_info in pkgutil.iter_modules(plugins.__path__):
        # 跳过测试模块
        if mod_info.name.startswith("test_"):
            continue

        # 动态导入模块
        module = importlib.import_module(f"plugins.{mod_info.name}")

        # 找出模块里所有 Plugin 子类(排除基类自身)
        for attr_name in dir(module):
            cls = getattr(module, attr_name)
            if (isinstance(cls, type)
                    and issubclass(cls, Plugin)
                    and cls is not Plugin):
                found.append(cls())

    # 按 priority 排序, 小的先执行
    found.sort(key=lambda p: p.priority)
    return found
