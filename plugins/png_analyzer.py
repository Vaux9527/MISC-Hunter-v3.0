'''
PNG 结构分析器

解析 PNG 签名与所有 chunk:
    1. 验证 PNG 签名
    2. 遍历 chunk: 解析 长度/类型/数据/CRC
    3. 解析 IHDR: 宽高、位深、颜色类型
    4. 对每个 chunk 做 CRC 校验(zlib.crc32(类型+数据) vs 文件里的 CRC)

CRC mismatch 是宽高被篡改的经典信号(改宽高没同步改 CRC)
下节课的 png_fixer 将基于本插件的 finding 做宽高恢复
'''

import struct
import zlib

from core.plugin import Plugin

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# IHDR 颜色类型对照
COLOR_TYPES = {
    0: "灰度",
    2: "真彩RGB",
    3: "调色板",
    4: "灰度+Alpha",
    6: "真彩+Alpha",
}


class PngAnalyzer(Plugin):
    name = "PNG Analyzer"
    version = "1.0"
    priority = 15

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        # 签名检查: 不是 PNG 就安静返回, 不啰嗦
        if not data.startswith(PNG_SIGNATURE):
            return {
                "code": "PNG_NOT_PNG",
                "message": "非PNG文件(签名不匹配)",
                "severity": "INFO",
                "data": {}
            }

        # ========== 遍历 chunk ==========
        info = self._parse_chunks(data)

        # ========== 组装 finding ==========
        crc_errors = info["crc_errors"]
        ihdr = info["ihdr"]

        if crc_errors:
            # 有 CRC 异常: 报详细 mismatch, 提示宽高嫌疑
            detail = "; ".join(
                f"{e['chunk']}(偏移{e['offset']}) stored={e['stored']} "
                f"calculated={e['calculated']}"
                for e in crc_errors
            )
            message = (
                f"PNG {ihdr['width']}x{ihdr['height']}, "
                f"{len(crc_errors)}个chunk CRC异常: {detail}"
            )
            severity = "WARNING"
        else:
            message = (
                f"PNG结构正常: {ihdr['width']}x{ihdr['height']}, "
                f"{ihdr['color_desc']}, {info['chunk_count']}个chunk, CRC全部通过"
            )
            severity = "INFO"

        return {
            "code": "PNG_ANALYZED",
            "message": message,
            "severity": severity,
            "data": {
                "width": ihdr["width"],
                "height": ihdr["height"],
                "bit_depth": ihdr["bit_depth"],
                "color_type": ihdr["color_desc"],
                "chunk_count": info["chunk_count"],
                "crc_errors": crc_errors,
                "ihdr_suspect": any(e["chunk"] == "IHDR" for e in crc_errors)
            }
        }

    # ============================================================
    # 内部方法: 解析 chunk 结构, 返回汇总信息
    # ============================================================

    def _parse_chunks(self, data):
        """从第8字节开始遍历所有 chunk, 返回解析结果字典"""
        offset = 8
        chunk_count = 0
        crc_errors = []
        ihdr = {
            "width": 0, "height": 0,
            "bit_depth": 0, "color_desc": "未知"
        }

        while offset + 12 <= len(data):
            # chunk 头: 长度(4) + 类型(4)
            length, ctype = struct.unpack(">I4s", data[offset:offset + 8])
            ctype_str = ctype.decode("ascii", errors="replace")

            start = offset + 8
            end = start + length

            # 数据越界: 结构异常, 停止解析
            if end + 4 > len(data):
                crc_errors.append({
                    "chunk": f"{ctype_str}(数据越界)",
                    "offset": offset,
                    "stored": "?",
                    "calculated": "?"
                })
                break

            chunk_data = data[start:end]

            # CRC 校验: CRC32(类型 + 数据)
            stored_crc = struct.unpack(">I", data[end:end + 4])[0]
            calculated_crc = zlib.crc32(ctype + chunk_data) & 0xFFFFFFFF
            if stored_crc != calculated_crc:
                crc_errors.append({
                    "chunk": ctype_str,
                    "offset": offset,
                    "stored": f"0x{stored_crc:08X}",
                    "calculated": f"0x{calculated_crc:08X}"
                })

            chunk_count += 1

            # IHDR: 解析宽高等关键信息(数据固定13字节)
            if ctype == b"IHDR" and length >= 13:
                (w, h, bit_depth, color_type,
                 _comp, _filter, _interlace) = struct.unpack(">IIBBBBB", chunk_data[:13])
                ihdr = {
                    "width": w,
                    "height": h,
                    "bit_depth": bit_depth,
                    "color_desc": COLOR_TYPES.get(color_type, f"类型{color_type}")
                }

            offset = end + 4

            # IEND 是最后一个 chunk, 后面即使有垃圾也忽略
            if ctype == b"IEND":
                break

        return {
            "chunk_count": chunk_count,
            "crc_errors": crc_errors,
            "ihdr": ihdr
        }
