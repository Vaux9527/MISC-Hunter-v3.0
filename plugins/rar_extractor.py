'''
RAR 检测与提取插件(外部工具)

现实约束: Python 标准库不支持 RAR(zipfile 只管 ZIP),
    纯 Python 无解 -> 调用系统工具(7z / unrar / bsdtar)

功能与 ZIP 链路对齐(拼接题同样覆盖):
    1. 检测: 全文件找第一个 Rar!\x1a\x07 -> 偏移
       偏移 > 0 = 嵌入式(藏在别的文件后, 如 JPEG+RAR)
       偏移 == 0 = 独立 RAR
    2. 嵌入式: 按偏移切出 RAR 段 -> 提取; 独立: 直接提取
    3. 产物复制进 extracted(队列接力)
    4. 失败: 错误含 password -> "加密需密码"; 否则报提取失败

1.0 边界(诚实):
    - RAR 无中央目录结构, 段边界切到文件尾(拼接题 RAR 在尾部是常态)
    - 加密 RAR 不做爆破(unrar 试密码极慢, 不划算), 报告需密码
'''

import os
import shutil
import tempfile

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs
from utils.tools import find_tool, run_tool

RAR_SIGNATURE = b"Rar!\x1a\x07"


class RarExtractor(Plugin):
    name = "RAR Extractor"
    version = "1.0"
    priority = 32   # ZIP 提取(30)之后: 容器提取

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        # ========== 1. 检测: 找第一个 RAR 签名 ==========
        offset = data.find(RAR_SIGNATURE)
        if offset == -1:
            return None  # 不是 RAR(独立或嵌入式都没有)

        # ========== 2. 找工具 ==========
        tool = (find_tool("7z") or find_tool("unrar")
                or find_tool("bsdtar") or find_tool("7za"))
        if tool is None:
            return {
                "code": "TOOL_MISSING",
                "message": "检测到RAR文件, 但未安装提取工具 "
                           "(Kali: sudo apt install p7zip-full)",
                "severity": "INFO",
                "data": {"tool": "7z/unrar/bsdtar"}
            }

        embedded = offset > 0

        # ========== 3. 准备 RAR 数据文件 ==========
        # 嵌入式: 按偏移切出 RAR 段(切到文件尾), 写临时文件供工具读取
        tmp_rar = None
        try:
            if embedded:
                fd, tmp_rar = tempfile.mkstemp(prefix="hunter_rar_", suffix=".rar")
                with os.fdopen(fd, "wb") as f:
                    f.write(data[offset:])
                rar_path = tmp_rar
            else:
                rar_path = target

            result = self._extract(tool, rar_path)
        finally:
            if tmp_rar and os.path.exists(tmp_rar):
                os.remove(tmp_rar)

        # ========== 4. 结果分派 ==========
        if result["code"] in ("RAR_NEED_PASSWORD", "RAR_EXTRACT_FAIL"):
            finding = dict(result)
            if embedded:
                finding["message"] = f"[嵌入式偏移{offset}] {finding['message']}"
            return finding

        if result["code"] == "RAR_EMPTY":
            return result

        # ========== 5. 产物进队列 ==========
        ensure_dirs()
        extracted = []
        for name in result["files"]:
            src = os.path.join(result["workdir"], name)
            out_path = os.path.join(str(EXTRACT_DIR), name)
            shutil.copy2(src, out_path)
            context.extracted_files.append({
                "path": out_path,
                "source": target,
                "method": "RAR_EXTRACT",
                "offset": offset
            })
            extracted.append(name)
        shutil.rmtree(result["workdir"], ignore_errors=True)

        code = "RAR_EMBEDDED" if embedded else "RAR_STANDALONE"
        message = (
            f"发现嵌入式RAR(偏移{offset})并提取成功: {len(extracted)}个文件进队列"
            if embedded else
            f"RAR提取成功: {len(extracted)}个文件进队列"
        )
        return {
            "code": code,
            "message": message,
            "severity": "INFO",
            "data": {"offset": offset, "files": extracted}
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _extract(self, tool, rar_path):
        """用工具把 rar_path 提取到临时目录; 返回结果字典"""
        workdir = tempfile.mkdtemp(prefix="hunter_rar_out_")
        tool_name = os.path.basename(tool)

        try:
            if "7z" in tool_name:
                result = run_tool(tool, ["x", "-y", f"-o{workdir}", rar_path])
            elif "unrar" in tool_name:
                result = run_tool(tool, ["x", "-y", rar_path, workdir + os.sep])
            else:  # bsdtar
                result = run_tool(tool, ["-xf", rar_path, "-C", workdir])

            if not result["ok"]:
                err = (result["stderr"] or result["stdout"]
                       or result["error"] or "").lower()
                shutil.rmtree(workdir, ignore_errors=True)
                if "password" in err or "encrypted" in err:
                    return {
                        "code": "RAR_NEED_PASSWORD",
                        "message": "RAR文件加密, 需密码解压(人工处理或提供密码)",
                        "severity": "WARNING",
                        "data": {}
                    }
                return {
                    "code": "RAR_EXTRACT_FAIL",
                    "message": f"RAR提取失败: {(result['error'] or result['stderr'])[:100]}",
                    "severity": "WARNING",
                    "data": {}
                }

            files = [
                n for n in os.listdir(workdir)
                if os.path.isfile(os.path.join(workdir, n))
            ]
            if not files:
                shutil.rmtree(workdir, ignore_errors=True)
                return {
                    "code": "RAR_EMPTY",
                    "message": "RAR提取完成但内部无文件",
                    "severity": "INFO",
                    "data": {}
                }
            return {"code": "OK", "files": files, "workdir": workdir}
        except Exception as e:
            shutil.rmtree(workdir, ignore_errors=True)
            return {
                "code": "RAR_EXTRACT_FAIL",
                "message": f"RAR提取异常: {str(e)[:100]}",
                "severity": "WARNING",
                "data": {}
            }
