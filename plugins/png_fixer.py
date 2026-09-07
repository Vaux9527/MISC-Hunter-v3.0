'''
PNG 宽高修复器

原理: 不依赖 CRC, 靠"IDAT 解压长度"验证宽高
    IHDR 声称: 宽 W, 高 H, 通道数 ch(由颜色类型决定)
    每行真实字节数 = 1(行首filter) + W * ch
    解压 IDAT 得到 raw_len
    宽高没被改  -> raw_len == H * (1 + W*ch), 无事发生
    高度被改    -> 真实高度 H' = raw_len / (1 + W*ch) (能整除)
    除不尽      -> 宽度也被改了(1.0 不自动猜, 报异常给人类)

修复: 重写 IHDR 的高度 + 重算该 chunk 的 CRC -> 输出 xxx.fixed.png 进递归队列

1.0 限制:
    - 只处理非隔行 PNG(interlace=0)
    - 只自动恢复"宽度可信、高度被改"的主流场景
'''

import os
import struct
import zlib

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# 颜色类型 -> 每像素通道数
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


class PngFixer(Plugin):
    name = "PNG Fixer"
    version = "1.0"
    priority = 16

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        if not data.startswith(PNG_SIGNATURE):
            return None  # 非 PNG: 无事发生

        # ========== 解析 IHDR + 收集 IDAT ==========
        parsed = self._parse(data)
        if parsed is None:
            return {
                "code": "PNG_UNSUPPORTED",
                "message": "PNG结构异常或为隔行PNG, 无法自动修复宽高",
                "severity": "WARNING",
                "data": {}
            }

        width = parsed["width"]
        height = parsed["height"]
        row_bytes = 1 + width * parsed["channels"]

        # ========== 解压 IDAT, 验证长度 ==========
        try:
            raw = zlib.decompress(parsed["idat_data"])
        except zlib.error:
            return {
                "code": "PNG_IDAT_DAMAGED",
                "message": "IDAT数据无法解压(zlib流损坏或被截断)",
                "severity": "WARNING",
                "data": {}
            }

        raw_len = len(raw)
        expected = height * row_bytes

        if raw_len == expected:
            return None  # 宽高一致, 没毛病不出声

        # ========== 高度被改? 反推真实高度 ==========
        if raw_len % row_bytes == 0:
            real_height = raw_len // row_bytes
            if real_height == height:
                return None

            # 修复: 重写 IHDR 高度 + 重算 CRC
            ensure_dirs()
            fixed_path = os.path.join(
                str(EXTRACT_DIR),
                os.path.basename(target) + ".fixed.png"
            )
            self._write_fixed(data, parsed["ihdr_offset"], real_height, fixed_path)

            # 修复产物进队列(analyzer 会对修复版重新体检)
            context.extracted_files.append({
                "path": fixed_path,
                "source": target,
                "method": "PNG_HEIGHT_FIX",
                "offset": parsed["ihdr_offset"]
            })

            return {
                "code": "PNG_FIXED",
                "message": (
                    f"IHDR高度异常: 声称{height}, 实际应为{real_height} "
                    f"(IDAT解压长度推算), 已修复输出"
                ),
                "severity": "WARNING",
                "data": {
                    "claimed_height": height,
                    "real_height": real_height,
                    "width": width,
                    "fixed_path": fixed_path
                }
            }

        # ========== 除不尽: 宽度也改了, 不自动猜 ==========
        return {
            "code": "PNG_DIMENSION_ANOMALY",
            "message": (
                f"宽高异常: IDAT解压{raw_len}字节无法按当前宽{width}整除分行, "
                "宽度可能也被篡改, 需人工分析"
            ),
            "severity": "WARNING",
            "data": {
                "width": width,
                "claimed_height": height,
                "raw_len": raw_len,
                "row_bytes": row_bytes
            }
        }

    # ============================================================
    # 内部方法
    # ============================================================

    def _parse(self, data):
        """解析 PNG: 返回 IHDR 信息 + 拼接的 IDAT 数据; 异常返回 None"""
        offset = 8
        ihdr = None
        idat_parts = []

        while offset + 12 <= len(data):
            length, ctype = struct.unpack(">I4s", data[offset:offset + 8])
            start = offset + 8
            end = start + length

            if end + 4 > len(data):
                return None  # chunk 越界: 结构损坏

            chunk_data = data[start:end]

            if ctype == b"IHDR" and length >= 13:
                (w, h, bit_depth, color_type,
                 _comp, _filter, interlace) = struct.unpack(">IIBBBBB", chunk_data[:13])
                if interlace != 0:
                    return None  # 隔行 PNG, 1.0 不支持
                ihdr = {
                    "width": w,
                    "height": h,
                    "channels": CHANNELS.get(color_type),
                    "ihdr_offset": offset,
                }
                if ihdr["channels"] is None:
                    return None  # 未知颜色类型

            elif ctype == b"IDAT":
                idat_parts.append(chunk_data)

            offset = end + 4
            if ctype == b"IEND":
                break

        if ihdr is None or not idat_parts:
            return None

        ihdr["idat_data"] = b"".join(idat_parts)
        return ihdr

    def _write_fixed(self, data, ihdr_offset, real_height, fixed_path):
        """改写 IHDR 高度字段 + 重算 CRC, 写修复文件"""
        fixed = bytearray(data)
        data_off = ihdr_offset + 8          # chunk 头(长度+类型)在 ihdr_offset, 数据在 +8

        # 高度字段在 IHDR 数据的 [4:8]
        fixed[data_off + 4:data_off + 8] = struct.pack(">I", real_height)

        # 重算 CRC: crc32(b"IHDR" + 新的13字节数据)
        new_crc = zlib.crc32(
            b"IHDR" + bytes(fixed[data_off:data_off + 13])
        ) & 0xFFFFFFFF
        fixed[data_off + 13:data_off + 17] = struct.pack(">I", new_crc)

        with open(fixed_path, "wb") as f:
            f.write(bytes(fixed))
