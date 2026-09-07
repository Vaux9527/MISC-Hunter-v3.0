'''
元数据提取器

从常见图片格式中提取文本类元数据(注释/描述等, CTF 常在此藏 flag):
    PNG:  tEXt(明文注释) / zTXt(zlib压缩注释) chunk
    JPEG: COM 段(注释) / APP1 EXIF 的 IFD0 文本标签
          (作者/厂商/软件/日期/描述/版权, 大小端自适应)

1.0 说明:
    - 文本按 Latin-1 解码并做可读性检查, 避免二进制垃圾误报
    - 非 PNG/JPEG 或无元数据: 安静返回 None(没毛病不出声)
'''

import struct
import zlib

from core.plugin import Plugin
from utils.decoders import is_printable

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xFF\xD8"


class MetadataExtractor(Plugin):
    name = "Metadata Extractor"
    version = "1.0"
    priority = 12

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        items = []

        if data.startswith(PNG_SIGNATURE):
            items = self._png_text_chunks(data)
        elif data.startswith(JPEG_SOI):
            items = self._jpeg_segments(data)
        else:
            return None  # 本插件只管 PNG/JPEG

        if not items:
            return None  # 没发现元数据, 不出声

        # 拼 message: 显示前几条内容
        preview = "; ".join(
            f"{it['kind']}: {it['text'][:80]}" for it in items[:3]
        )
        return {
            "code": "METADATA_FOUND",
            "message": f"发现{len(items)}条元数据: {preview}",
            "severity": "INFO",
            "data": {
                "items": items
            }
        }

    # ============================================================
    # PNG: tEXt / zTXt
    # ============================================================

    def _png_text_chunks(self, data):
        items = []
        offset = 8

        while offset + 12 <= len(data):
            length, ctype = struct.unpack(">I4s", data[offset:offset + 8])
            start = offset + 8
            end = start + length

            if end + 4 > len(data):
                break  # chunk 越界, 停止

            chunk_data = data[start:end]

            if ctype == b"tEXt":
                # 数据 = keyword \x00 text
                text = self._split_keyword_text(chunk_data)
                if text:
                    items.append({"kind": "PNG注释", **text})

            elif ctype == b"zTXt":
                # 数据 = keyword \x00 压缩方法(1字节) zlib压缩文本
                sep = chunk_data.find(b"\x00")
                if sep == -1:
                    continue
                keyword = chunk_data[:sep].decode("latin-1", errors="replace")
                try:
                    raw = zlib.decompress(chunk_data[sep + 2:])
                    content = raw.decode("latin-1", errors="replace")
                    if is_printable(content):
                        items.append({"kind": "PNG压缩注释", "keyword": keyword, "text": content})
                except zlib.error:
                    continue  # 压缩数据损坏, 跳过

            offset = end + 4
            if ctype == b"IEND":
                break

        return items

    def _split_keyword_text(self, chunk_data):
        """tEXt 数据: keyword \x00 text; 返回 dict 或 None"""
        sep = chunk_data.find(b"\x00")
        if sep == -1:
            return None
        keyword = chunk_data[:sep].decode("latin-1", errors="replace")
        content = chunk_data[sep + 1:].decode("latin-1", errors="replace")
        if not is_printable(content):
            return None  # 内容不可读, 不是文本注释
        return {"keyword": keyword, "text": content}

    # ============================================================
    # JPEG: 段遍历
    # ============================================================

    def _jpeg_segments(self, data):
        items = []
        i = 2  # 跳过 SOI(FF D8)

        while i + 4 <= len(data):
            if data[i] != 0xFF:
                break  # 结构异常

            marker = data[i + 1]

            # 无长度字段的段: RSTn/临时标记/SOI, 直接跳 2 字节
            if marker == 0xD8 or 0xD0 <= marker <= 0xD7 or marker == 0x01:
                i += 2
                continue

            if marker == 0xD9:  # EOI: 文件结束
                break

            seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
            payload = data[i + 4:i + 2 + seg_len]

            if marker == 0xFE:  # COM: 注释
                content = payload.decode("latin-1", errors="replace")
                if is_printable(content):
                    items.append({"kind": "JPEG注释", "keyword": "", "text": content})

            elif marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                # 解析 EXIF(TIFF 结构)里的 IFD0 文本标签
                exif_items = self._parse_exif(payload[6:])
                if exif_items:
                    items.extend(exif_items)
                else:
                    items.append({
                        "kind": "EXIF",
                        "keyword": "",
                        "text": f"APP1含EXIF元数据({len(payload)}字节)"
                    })

            if marker == 0xDA:  # SOS: 压缩数据开始, 段遍历到此结束
                break

            i += 2 + seg_len

        return items

    # ============================================================
    # EXIF: TIFF IFD0 解析
    # ============================================================

    # 常见 IFD0 文本标签
    EXIF_TAGS = {
        0x010E: "图像描述",
        0x010F: "厂商",
        0x0110: "型号",
        0x0131: "软件",
        0x0132: "日期时间",
        0x013B: "作者",
        0x8298: "版权",
    }
    # TIFF 类型 -> 单条数据字节数
    TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

    def _parse_exif(self, tiff):
        """解析 TIFF 的 IFD0 表, 返回文本标签列表(空表返回 [])"""
        if len(tiff) < 8:
            return []

        # 字节序: 'II' 小端 / 'MM' 大端
        order = "<" if tiff[:2] == b"II" else ">"
        if tiff[2:4] != b"\x2a\x00" and tiff[2:4] != b"\x00\x2a":
            return []  # 42 魔数不符, 不是合法 TIFF

        ifd_offset = struct.unpack(order + "I", tiff[4:8])[0]
        if ifd_offset + 2 > len(tiff):
            return []

        entry_count = struct.unpack(order + "H", tiff[ifd_offset:ifd_offset + 2])[0]
        items = []

        for i in range(entry_count):
            pos = ifd_offset + 2 + i * 12
            if pos + 12 > len(tiff):
                break
            tag, typ, count = struct.unpack(order + "HHI", tiff[pos:pos + 8])
            value_field = tiff[pos + 8:pos + 12]

            if tag not in self.EXIF_TAGS:
                continue  # 只要文本类常见标签
            if typ not in self.TIFF_TYPE_SIZE:
                continue

            data_len = self.TIFF_TYPE_SIZE[typ] * count

            if typ == 2:  # ASCII 字符串
                if data_len <= 4:
                    raw = value_field[:data_len]
                else:
                    off = struct.unpack(order + "I", value_field)[0]
                    if off + data_len > len(tiff):
                        continue
                    raw = tiff[off:off + data_len]
                text = raw.split(b"\x00")[0].decode("latin-1", errors="replace")
                if text and is_printable(text):
                    items.append({
                        "kind": "EXIF",
                        "keyword": self.EXIF_TAGS[tag],
                        "text": text
                    })

        return items
