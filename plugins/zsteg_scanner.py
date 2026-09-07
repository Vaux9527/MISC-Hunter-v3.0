'''
zsteg 隐写扫描插件(外部工具)

zsteg(Ruby) 检测 PNG/BMP 的多种隐写模式(位平面/通道/比特序全试),
作为纯 Python LSB 插件(lsb_extractor)的全模式补充。

流程(模板与 binwalk 一致):
    1. 格式门控: 只扫 PNG/BMP(避免对无关格式跑外部工具)
    2. find_tool -> 缺失降级 finding
    3. run_tool -> 解析输出(纯函数可单测)
    4. 发现 -> finding 报告

zsteg 输出行格式: "b1,r,lsb,xy :: text: \"flag{...}\"" 或 ":: file: ..."
'''

from core.plugin import Plugin
from utils.tools import find_tool, run_tool, tool_missing_finding

PNG_SIG = b"\x89PNG\r\n\x1a\n"
BMP_SIG = b"BM"


class ZstegScanner(Plugin):
    name = "Zsteg Scanner"
    version = "1.0"
    priority = 18

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            head = f.read(8)

        # 格式门控: 只扫 PNG/BMP
        if not (head.startswith(PNG_SIG) or head.startswith(BMP_SIG)):
            return None

        tool = find_tool("zsteg")
        if tool is None:
            return tool_missing_finding(
                "zsteg", "Kali: sudo gem install zsteg (需要 Ruby)")

        result = run_tool(tool, [target])
        if not result["ok"] and not result["stdout"]:
            return {
                "code": "ZSTEG_ERROR",
                "message": f"zsteg 执行失败: {(result['error'] or result['stderr'])[:100]}",
                "severity": "WARNING",
                "data": {}
            }

        findings = self._parse_output(result["stdout"])
        if not findings:
            return None  # 无发现, 安静

        preview = "; ".join(
            f"{f['mode']} -> {f['detail'][:60]}" for f in findings[:3]
        )
        return {
            "code": "ZSTEG_FINDINGS",
            "message": f"zsteg发现{len(findings)}处隐写数据: {preview}",
            "severity": "WARNING",
            "data": {"entries": findings}
        }

    # ============================================================
    # 解析 zsteg 输出(纯函数, 可脱离 zsteg 单测)
    # ============================================================

    def _parse_output(self, text):
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if " :: " not in line:
                continue
            mode, _, rest = line.partition(" :: ")
            # rest 形如: text: "flag{...}" / file: xxx / ...
            if ":" in rest:
                kind, _, content = rest.partition(":")
                content = content.strip().strip('"')
            else:
                kind, content = "", rest
            if content:
                entries.append({
                    "mode": mode.strip(),
                    "kind": kind.strip(),
                    "detail": content,
                })
        return entries
