'''
steghide 隐写扫描插件(外部工具)

steghide 支持 JPEG/BMP/WAV/AU 的隐写(嵌入与提取都需要口令)。

流程:
    1. 格式门控: JPEG/BMP/WAV
    2. find_tool -> 缺失降级
    3. steghide info: 检测是否有嵌入数据
       (输出含 "embedded data: yes/no")
    4. 有嵌入 -> 尝试空口令提取(-p "" 必须传, 防交互卡死)
       成功 -> 产物进队列; 失败 -> 报告"需口令"
    5. 无嵌入 -> 安静

注意: steghide 交互提示会卡死自动化, 所有命令必须带 -p 参数
'''

import os
import shutil
import tempfile

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs
from utils.tools import find_tool, run_tool, tool_missing_finding

JPEG_SIG = b"\xFF\xD8\xFF"
BMP_SIG = b"BM"
WAV_SIG = b"RIFF"


class SteghideScanner(Plugin):
    name = "Steghide Scanner"
    version = "1.0"
    priority = 19

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            head = f.read(8)

        # 格式门控
        if not (head.startswith(JPEG_SIG) or head.startswith(BMP_SIG)
                or head.startswith(WAV_SIG)):
            return None

        tool = find_tool("steghide")
        if tool is None:
            return tool_missing_finding(
                "steghide", "Kali: sudo apt install steghide")

        # ========== info: 检测嵌入 ==========
        info = run_tool(tool, ["info", target], timeout=15)
        out = (info["stdout"] or "").lower()
        if "embedded data: no" in out:
            return None  # 无嵌入, 安静
        if "embedded data: yes" not in out:
            # info 失败或输出异常(如非支持格式被门控漏过)
            if not info["ok"]:
                return {
                    "code": "STEGHIDE_ERROR",
                    "message": f"steghide info 失败: {(info['error'] or info['stderr'])[:80]}",
                    "severity": "WARNING",
                    "data": {}
                }
            return None

        # ========== 有嵌入: 尝试空口令提取 ==========
        workdir = tempfile.mkdtemp(prefix="hunter_steg_")
        try:
            out_file = os.path.join(workdir, "steg_out")
            # -p "" 空口令(必须传, 否则交互提示卡死); 提取失败会给提示
            result = run_tool(
                tool, ["extract", "-sf", target, "-xf", out_file, "-p", ""],
                timeout=20)
            err = (result["stderr"] or result["stdout"] or "").lower()

            if result["ok"] and os.path.exists(out_file):
                ensure_dirs()
                name = os.path.basename(target) + ".steg"
                out_path = os.path.join(str(EXTRACT_DIR), name)
                shutil.copy2(out_file, out_path)
                context.extracted_files.append({
                    "path": out_path,
                    "source": target,
                    "method": "STEGHIDE_EXTRACT",
                    "offset": 0
                })
                return {
                    "code": "STEGHIDE_EXTRACTED",
                    "message": "检测到steghide嵌入数据, 空口令提取成功",
                    "severity": "WARNING",
                    "data": {"path": out_path}
                }

            if "no file" in err or "could not extract" in err or not result["ok"]:
                return {
                    "code": "STEGHIDE_NEED_PASSWORD",
                    "message": "检测到steghide嵌入数据, 空口令提取失败, 需提供口令",
                    "severity": "WARNING",
                    "data": {}
                }
            return {
                "code": "STEGHIDE_EXTRACT_FAIL",
                "message": f"steghide 提取异常: {err[:100]}",
                "severity": "WARNING",
                "data": {}
            }
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
