'''
外部 CTF 工具调用框架

为什么需要: binwalk/zsteg/F5/steghide 等是 Kali 命令行工具,
    纯 Python 无法替代(尤其 F5 需要 Java), 插件必须能调用它们

设计决策:
    - find_tool: 先检测工具是否存在(shutil.which), 不存在走降级
    - run_tool: 执行命令, 超时保护, 所有失败包成结构体不抛异常
    - tool_missing_finding: 工具缺失的统一降级 finding
    - 执行与解析分离: 本模块只负责"跑命令拿输出",
      输出解析由各插件自己写(各工具输出格式不同)

安全:
    - 参数用列表传参(subprocess.run([tool] + args)), 禁止字符串拼接
      路径含空格会崩, 字符串拼接还有命令注入风险
'''

import shutil
import subprocess


def find_tool(name):
    """检测工具是否可用; 返回可执行路径或 None"""
    return shutil.which(name)


def run_tool(tool, args, timeout=30):
    """
    执行外部工具

    args: 参数列表(不含工具名), 例如 ["samples/snake.jpg"]
    timeout: 超时秒数(外部工具可能在大文件上卡死)

    返回: {"ok": bool, "stdout": str, "stderr": str, "error": str|None}
    所有失败(超时/异常)都包成结构体, 不抛异常
    """
    try:
        result = subprocess.run(
            [tool] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "error": f"执行超时({timeout}秒)",
        }
    except Exception as e:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "error": str(e),
        }


def tool_missing_finding(tool, hint):
    """工具未安装时的统一降级 finding(可解释, 不崩溃)"""
    return {
        "code": "TOOL_MISSING",
        "message": f"外部工具 {tool} 未安装, 跳过该分析 ({hint})",
        "severity": "INFO",
        "data": {"tool": tool},
    }
