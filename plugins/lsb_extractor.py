'''
LSB 隐写提取器

底层逻辑:
    像素颜色的最低位被隐写者替换成秘密 bit, 肉眼无差别
    提取 = 镜像操作: 读每个像素字节的特定位 -> 拼 bit 流 -> 8bit 一组还原字节

支持的容器格式:
    PNG: 非隔行, 位深8, 颜色类型 0(灰度)/2(RGB)/6(RGBA), 需逆滤波
    BMP: 24/32位 BI_RGB(无压缩), 像素 BGR 顺序, 小端结构
         高度为正(bottom-up)时文件行序与显示序相反, 两种顺序都试

多模式尝试(隐写变体很多, 全试):
    格式顺序 × 位平面: 0~3 × 比特序: 低位在前/高位在前
    分段: 真实隐写只占图片一部分, 提取出的字节流 = 可读文本 + 尾部噪声
          所以对字节流做"可打印分段"提取, 而不是整段判定

候选处理(同 XOR 爆破的模式):
    可读分段 -> 写入 xxx.lsb_candidates.txt 进递归队列
    -> strings 自动接力: flag{...} 自动报出; 人类可查完整候选
'''

import os
import struct
import zlib

from core.plugin import Plugin
from utils.paths import EXTRACT_DIR, ensure_dirs

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
BMP_SIGNATURE = b"BM"

# 颜色类型 -> 每像素通道数
CHANNELS = {0: 1, 2: 3, 6: 4}


class LsbExtractor(Plugin):
    name = "LSB Extractor"
    version = "1.0"
    priority = 17

    def run(self, context):
        target = context.target

        with open(target, "rb") as f:
            data = f.read()

        # ========== 按格式解析出像素字节流 ==========
        # streams: [(格式说明, 像素字节流), ...]
        streams = []

        if data.startswith(PNG_SIGNATURE):
            png = self._parse_png(data)
            if png is None:
                return None  # 隔行/非常规位深等: 不支持, 安静
            try:
                scanlines = zlib.decompress(png["idat"])
            except zlib.error:
                return None
            pixels = self._unfilter(
                scanlines, png["width"], png["height"], png["channels"]
            )
            streams.append(("PNG", pixels))

        elif data.startswith(BMP_SIGNATURE):
            bmp_streams = self._parse_bmp(data)
            if bmp_streams is None:
                return None  # 压缩/非常规 BMP: 不支持, 安静
            streams.extend(bmp_streams)

        else:
            return None  # 非 PNG/BMP

        # ========== 多模式提取 ==========
        segments = []  # 收集所有模式的可读分段
        for fmt, pixels in streams:
            for plane in range(4):          # 位平面 0~3
                for msb_first in (False, True):   # 两种比特序
                    stream = self._extract_bits(pixels, plane, msb_first)
                    for seg in self._readable_segments(stream):
                        segments.append({
                            "fmt": fmt,
                            "plane": plane,
                            "order": "MSB-first" if msb_first else "LSB-first",
                            "text": seg,
                        })

        if not segments:
            return None  # 任何模式都没提取到可读内容

        # ========== 候选去重后落盘, 进队列 ==========
        seen = set()
        unique = []
        for s in segments:
            if s["text"] not in seen:
                seen.add(s["text"])
                unique.append(s)

        ensure_dirs()
        out_path = os.path.join(
            str(EXTRACT_DIR),
            os.path.basename(target) + ".lsb_candidates.txt"
        )
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# {target} 的LSB提取候选({len(unique)}段)\n")
            for s in unique:
                f.write(
                    f"[{s['fmt']} 位平面{s['plane']} {s['order']}] "
                    f"{s['text']}\n"
                )

        context.extracted_files.append({
            "path": out_path,
            "source": target,
            "method": "LSB_CANDIDATES",
            "offset": 0
        })

        return {
            "code": "LSB_CANDIDATES_FOUND",
            "message": (
                f"LSB提取: 发现{len(unique)}段可读内容, "
                f"已写入候选文件(首段: {unique[0]['text'][:60]})"
            ),
            "severity": "WARNING",
            "data": {
                "segment_count": len(unique),
                "path": out_path
            }
        }

    # ============================================================
    # PNG 解析 + 逆滤波 (像素解码, 工程细节)
    # ============================================================

    def _parse_png(self, data):
        """解析 IHDR + 收集 IDAT; 非常规格式返回 None"""
        offset = 8
        info = {}
        idat_parts = []

        while offset + 12 <= len(data):
            length, ctype = struct.unpack(">I4s", data[offset:offset + 8])
            start = offset + 8
            end = start + length
            if end + 4 > len(data):
                return None
            chunk_data = data[start:end]

            if ctype == b"IHDR" and length >= 13:
                (w, h, bit_depth, color_type,
                 _comp, _filter, interlace) = struct.unpack(
                    ">IIBBBBB", chunk_data[:13])
                if interlace != 0 or bit_depth != 8:
                    return None  # 隔行/非8位深不支持
                if color_type not in CHANNELS:
                    return None  # 调色板等不支持
                info = {
                    "width": w, "height": h,
                    "channels": CHANNELS[color_type],
                }
            elif ctype == b"IDAT":
                idat_parts.append(chunk_data)

            offset = end + 4
            if ctype == b"IEND":
                break

        if not info or not idat_parts:
            return None
        info["idat"] = b"".join(idat_parts)
        return info

    def _parse_bmp(self, data):
        """
        解析 BMP(24/32位, BI_RGB 无压缩), 返回像素字节流列表:
            [("BMP-显示序", ...), ("BMP-存储序", ...)]
        高度为正(bottom-up)时文件行序与显示序相反, 两种都试
        (隐写者可能按任一顺序藏数据); 不支持压缩/非常规 BMP -> None
        """
        if len(data) < 54:
            return None

        off_bits = struct.unpack("<I", data[10:14])[0]   # 像素数据偏移
        width = struct.unpack("<i", data[18:22])[0]
        height = struct.unpack("<i", data[22:26])[0]
        bpp = struct.unpack("<H", data[28:30])[0]
        compression = struct.unpack("<I", data[30:34])[0]

        if width <= 0 or height == 0 or compression != 0:
            return None
        if bpp not in (24, 32):
            return None

        channels = bpp // 8
        # BMP 每行按 4 字节对齐
        stride = ((width * channels + 3) // 4) * 4
        pixel_bytes = data[off_bits:]
        row_bytes = width * channels

        rows = []
        for r in range(abs(height)):
            start = r * stride
            rows.append(pixel_bytes[start:start + row_bytes])

        # 显示顺序: height>0 = bottom-up, 文件第一行是图像最后一行 -> 反转行序
        display = b"".join(rows[::-1]) if height > 0 else b"".join(rows)
        storage = b"".join(rows)
        return [("BMP-显示序", display), ("BMP-存储序", storage)]

    def _unfilter(self, raw, width, height, channels):
        """
        逆滤波: PNG 每行 = 1个滤波字节 + 像素数据, 共5种滤波
        参考: 左(a) 上(b) 左上(c), 运算都在 mod 256 下
        """
        stride = width * channels
        out = bytearray()
        prev = [0] * stride
        pos = 0

        for _ in range(height):
            f = raw[pos]
            pos += 1
            line = list(raw[pos:pos + stride])
            pos += stride

            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0

                if f == 1:        # Sub: 左像素同通道
                    v = line[i] + a
                elif f == 2:      # Up: 上一行同通道
                    v = line[i] + b
                elif f == 3:      # Average: (左+上)/2
                    v = line[i] + (a + b) // 2
                elif f == 4:      # Paeth
                    v = line[i] + self._paeth(a, b, c)
                else:             # 0 None
                    v = line[i]

                v &= 0xFF
                line[i] = v
                out.append(v)

            prev = line

        return bytes(out)

    @staticmethod
    def _paeth(a, b, c):
        """Paeth 预测器"""
        p = a + b - c
        pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
        if pa <= pb and pa <= pc:
            return a
        if pb <= pc:
            return b
        return c

    # ============================================================
    # LSB 提取
    # ============================================================

    def _extract_bits(self, pixels, plane, msb_first):
        """取每个字节的第 plane 位, 拼成字节流"""
        bits = [(b >> plane) & 1 for b in pixels]
        # 去掉不满 8 的尾巴
        usable = len(bits) - (len(bits) % 8)
        out = bytearray()
        for i in range(0, usable, 8):
            group = bits[i:i + 8]
            if msb_first:
                val = 0
                for bit in group:
                    val = (val << 1) | bit
            else:
                val = 0
                for j, bit in enumerate(group):
                    val |= bit << j
            out.append(val)
        return bytes(out)

    def _readable_segments(self, stream):
        """把字节流切成可打印连续段(>=4), 返回文本段列表"""
        segs = []
        current = bytearray()
        for b in stream:
            if 32 <= b <= 126:
                current.append(b)
            else:
                if len(current) >= 4:
                    segs.append(current.decode("ascii", errors="replace"))
                current = bytearray()
        if len(current) >= 4:
            segs.append(current.decode("ascii", errors="replace"))
        return segs
