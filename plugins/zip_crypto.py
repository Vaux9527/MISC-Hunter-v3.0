'''
ZIP 加密分析与爆破

CTF 高频两种场景:
    1. 伪加密: GPBF 加密标志位被设置, 但文件数据实际未加密
       清除标志位即可正常解压(CRC 校验会证实)
    2. 真加密: ZipCrypto 真加密, 用弱密码字典 + 数字爆破

流程:
    检测加密位 -> 伪加密修复(清位 + testzip CRC 验证)
    -> 修复文件进队列(extractor 接力解压)
    -> 真加密则爆破弱密码 -> 命中解压进队列
    -> 全失败: 诚实报告"需密码"(人工 unzip -P 或更强的字典)

1.0 范围: 弱密码字典 + 0000~9999 数字; 更强大的字典留后续版本
'''

import io
import os
import struct
import zipfile

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs

# CTF 常见弱密码(可自行扩展)
WEAK_PASSWORDS = [
    "flag", "ctf", "password", "123456", "1234", "admin", "root",
    "secret", "hunter", "misc", "zip", "0000", "1111", "888888",
    "qwerty", "abc123", "test", "hack", "letmein", "welcome",
    "challenge", "key", "love", "666666", "iloveyou", "000000",
    "123123", "1q2w3e4r", "flag123", "ctf123", "snake", "anaconda",
]


class ZipCryptoAnalyzer(Plugin):
    name = "ZIP Crypto Analyzer"
    version = "1.0"
    priority = 22

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        if not data.startswith(b"PK\x03\x04"):
            return None  # 不是 ZIP

        # ========== 1. 检测加密位 ==========
        if not self._has_encrypt_flag(data):
            return None  # 无加密, 安静

        # ========== 2. 伪加密修复(清位 + CRC 验证) ==========
        fixed = self._clear_encrypt_flags(data)
        if self._test_zip(io.BytesIO(fixed)) is None:
            ensure_dirs()
            fixed_path = os.path.join(
                str(EXTRACT_DIR),
                os.path.basename(target) + ".fixed.zip"
            )
            with open(fixed_path, "wb") as f:
                f.write(fixed)

            context.extracted_files.append({
                "path": fixed_path,
                "source": target,
                "method": "ZIP_FAKE_ENCRYPT_FIX",
                "offset": 0
            })

            return {
                "code": "ZIP_FAKE_ENCRYPTED",
                "message": "检测到ZIP伪加密(加密标志位已设置但数据未加密), "
                           "已清除标志位并修复输出",
                "severity": "WARNING",
                "data": {"fixed_path": fixed_path}
            }

        # ========== 3. 真加密爆破 ==========
        first_name = self._first_entry_name(data)
        if first_name is None:
            return None

        attempts = 0
        candidates = WEAK_PASSWORDS + [
            f"{i:04d}" for i in range(10000)
        ]
        for pwd in candidates:
            attempts += 1
            if self._try_password(data, first_name, pwd):
                # 命中: 解压全部内容
                return self._extract_all(
                    context, target, data, pwd, attempts
                )

        return {
            "code": "ZIP_NEED_PASSWORD",
            "message": (
                f"ZIP为真加密, 弱密码爆破失败(已尝试{attempts}个密码), "
                "需提供密码(建议人工 unzip -P 或扩展字典)"
            ),
            "severity": "WARNING",
            "data": {"attempts": attempts}
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _has_encrypt_flag(self, data):
        """扫描所有 Local Header(+6) 和 Central Directory(+8) 的加密位"""
        for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break
                flags = struct.unpack("<H", data[pos + flag_off:pos + flag_off + 2])[0]
                if flags & 0x1:  # bit0 = 加密
                    return True
                pos += 4
        return False

    def _clear_encrypt_flags(self, data):
        """复制 ZIP 字节, 清除所有条目的加密标志位"""
        out = bytearray(data)
        for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = 0
            while True:
                pos = out.find(sig, pos)
                if pos == -1:
                    break
                flags = struct.unpack("<H", out[pos + flag_off:pos + flag_off + 2])[0]
                out[pos + flag_off:pos + flag_off + 2] = struct.pack("<H", flags & ~0x1)
                pos += 4
        return bytes(out)

    def _test_zip(self, stream):
        """testzip(): 全部条目 CRC 校验通过返回 None, 否则返回坏文件名"""
        try:
            with zipfile.ZipFile(stream) as z:
                return z.testzip()
        except Exception as e:
            return str(e)

    def _first_entry_name(self, data):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
                return names[0] if names else None
        except Exception:
            return None

    def _try_password(self, data, name, pwd):
        """用候选密码读第一个条目, 无异常且数据非空 = 密码正确"""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.read(name, pwd=pwd.encode("utf-8"))
            return True
        except Exception:
            return False

    def _extract_all(self, context, target, data, pwd, attempts):
        """密码命中: 解压全部条目到 extracted 并进队列"""
        ensure_dirs()
        extracted = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                # 只取 basename(防路径穿越, 与 zip_extractor 同策略)
                out_path = os.path.join(str(EXTRACT_DIR), os.path.basename(name))
                content = z.read(name, pwd=pwd.encode("utf-8"))
                with open(out_path, "wb") as f:
                    f.write(content)
                context.extracted_files.append({
                    "path": out_path,
                    "source": target,
                    "method": "ZIP_CRACKED",
                    "offset": 0
                })
                extracted.append(os.path.basename(name))

        return {
            "code": "ZIP_CRACKED",
            "message": (
                f"ZIP密码爆破成功: 密码='{pwd}' (尝试{attempts}个), "
                f"已解压 {len(extracted)} 个文件"
            ),
            "severity": "WARNING",
            "data": {
                "password": pwd,
                "attempts": attempts,
                "files": extracted
            }
        }
