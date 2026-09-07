'''
binwalk 深度扫描插件(外部工具)

binwalk 能发现纯 Python 签名表覆盖不到的嵌入数据
(固件/文件系统/多种压缩格式等), 是 MISC 分析的标准第一步

1.0 说明:
    - 只解析 binwalk 报告文本并报告发现(偏移+类型), 不自动提取
      自家 ZIP 提取已覆盖常见场景; binwalk -e 全量提取留后续版本
    - binwalk 未安装: 返回降级 finding(TOOL_MISSING), 不崩溃
    - 执行与解析分离: _parse_output 是纯函数, 可脱离 binwalk 单独测试
'''

from core.plugin import Plugin
from utils.tools import find_tool, run_tool, tool_missing_finding


class BinwalkScanner(Plugin):
    name = "Binwalk Scanner"
    version = "1.0"
    priority = 25

    def run(self, context):
        target = context.target

        # 1. 工具检测: 缺失走降级
        tool = find_tool("binwalk")
        if tool is None:
            return tool_missing_finding("binwalk", "Kali: sudo apt install binwalk")

        # 2. 执行
        result = run_tool(tool, [target])
        if not result["ok"]:
            return {
                "code": "BINWALK_ERROR",
                "message": f"binwalk 执行失败: {result['error'] or result['stderr'][:100]}",
                "severity": "WARNING",
                "data": {}
            }

        # 3. 解析报告
        entries = self._parse_output(result["stdout"])
        if not entries:
            return None  # 没有发现嵌入数据, 安静

        # 4. 报告: 偏移 > 0 的是嵌入数据(0 = 文件自身)
        embedded = [e for e in entries if e["offset"] > 0]
        if not embedded:
            return None

        preview = "; ".join(
            f"@{e['offset']}: {e['desc'][:40]}" for e in embedded[:5]
        )
        return {
            "code": "BINWALK_FINDINGS",
            "message": f"binwalk发现{len(embedded)}处嵌入数据: {preview}",
            "severity": "WARNING",
            "data": {
                "entries": embedded,
                "total_entries": len(entries)
            }
        }

    # ============================================================
    # 解析 binwalk 报告(纯函数, 可单独测试)
    # 真实输出格式:
    #   DECIMAL       HEXADECIMAL     DESCRIPTION
    #   ------------------------------------------------
    #   0             0x0             JPEG image data, ...
    #   278260        0x43EF4         Zip archive data, ...
    # ============================================================

    def _parse_output(self, text):
        entries = []
        for line in text.splitlines():
            line = line.strip()
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            offset_str, hex_str, desc = parts
            if not offset_str.isdigit():
                continue  # 跳过表头
            if not hex_str.startswith("0x"):
                continue
            entries.append({
                "offset": int(offset_str),
                "hex": hex_str,
                "desc": desc,
            })
        return entries
