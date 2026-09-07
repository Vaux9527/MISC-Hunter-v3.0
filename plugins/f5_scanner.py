'''
F5 隐写扫描插件(外部工具, Java)

F5 是 JPEG 频域隐写算法, 纯 Python 无法实现, 调用官方工具:
    部署: 官方 f5-steganography jar, 配置全局命令 f5extract
    用法: f5extract <carrier.jpg> [password]
    提取内容输出到 stdout(文本消息)

流程:
    1. JPEG 门控
    2. find_tool("f5extract") -> 缺失降级(提示部署方式)
    3. 无密码尝试提取: 捕获 stdout
    4. stdout 是像消息的文本 -> 落盘进队列(strings 接力 flag)
       含 password/错误 -> 报告; 空 -> 安静

注意: 输出位置/命名因 F5 工具版本而异, 如你的 f5extract 输出
    为文件而非 stdout, 请调整本插件的捕获逻辑
'''

from core.plugin import Plugin
from utils.decoders import plausible_plain
from utils.paths import EXTRACT_DIR, ensure_dirs
from utils.tools import find_tool, run_tool, tool_missing_finding
import os

JPEG_SIG = b"\xFF\xD8\xFF"


class F5Scanner(Plugin):
    name = "F5 Scanner"
    version = "1.0"
    priority = 35

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            head = f.read(3)

        if not head.startswith(JPEG_SIG):
            return None  # 只处理 JPEG

        tool = find_tool("f5extract")
        if tool is None:
            return tool_missing_finding(
                "f5extract",
                "官方F5工具部署(Java jar)后配置全局命令 f5extract")

        # ========== 无密码尝试提取 ==========
        result = run_tool(tool, [target], timeout=20)
        content = (result["stdout"] or "").strip()

        if not result["ok"]:
            err = (result["stderr"] or content or result["error"] or "").lower()
            if "password" in err:
                return {
                    "code": "F5_NEED_PASSWORD",
                    "message": "F5隐写数据需要密码(尝试无密码提取失败)",
                    "severity": "WARNING",
                    "data": {}
                }
            return {
                "code": "F5_ERROR",
                "message": f"f5extract 执行失败: {err[:100]}",
                "severity": "WARNING",
                "data": {}
            }

        if not content:
            return None  # 无输出 = 无嵌入消息(或该图无F5), 安静

        # ========== stdout 像提取消息 -> 落盘进队列 ==========
        raw = content.encode("utf-8", errors="replace")
        if not plausible_plain(raw, letter_th=0.6):
            # 输出不是消息文本(可能是工具提示信息), 不报
            return None

        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".f5.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)

        context.extracted_files.append({
            "path": out_path,
            "source": target,
            "method": "F5_EXTRACT",
            "offset": 0
        })

        return {
            "code": "F5_MESSAGE",
            "message": f"F5提取到消息: {content[:80]}",
            "severity": "WARNING",
            "data": {"path": out_path}
        }
