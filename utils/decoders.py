'''
MISC Hunter 解码库
从 useful_or_not/decoder.py 提取并改造:
    - 去掉菜单和交互, 保留纯解码逻辑
    - auto_base_decode 改为返回结构化的解码记录(插件需要逐层结果)
    - Base58/Base91 依赖第三方库, 1.0 暂不内置(装库后可参照 try_b85 补上)
'''

import base64
import re
import string


def is_printable(s, threshold=0.9):
    """判断字符串是否大部分可打印, 避免把乱码当解码结果"""
    if not s:
        return False
    count = sum(c in string.printable for c in s)
    return count / len(s) > threshold


def _clean(content):
    """去掉换行/空格/回车, 统一解码前的输入格式"""
    return content.replace("\n", "").replace(" ", "").replace("\r", "")


def looks_like_text(raw, printable_th=0.95, space_max=0.25, letter_th=0.8):
    """
    三层文本筛子(供 XOR 爆破类插件复用):
        第1筛: 可打印字节占比(滤掉乱码)
        第2筛: 空格率上限(只设上限: flag{...} 无空格不能误杀)
        第3筛: 字母占比(滤掉数字符号乱炖)
    """
    if not raw:
        return False

    n = len(raw)
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if printable / n < printable_th:
        return False

    if raw.count(0x20) / n > space_max:
        return False

    letters = sum(
        1 for b in raw
        if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A
    )
    if letters / n < letter_th:
        return False

    return True


def xor_decrypt(data, key):
    """
    多字节 XOR 解密: plain[i] = data[i] XOR key[i % len(key)]
    供"人机接力"接口使用(人类提供 key, 工具执行解密)
    """
    if not key:
        return None
    return bytes(
        data[i] ^ key[i % len(key)]
        for i in range(len(data))
    )


FLAG_PATTERN = re.compile(rb'[Ff][Ll][Aa][Gg]\{|[Cc][Tt][Ff]\{')


def has_flag_marker(raw):
    """
    确定性 flag 结构检测: 是否含 flag{ / ctf{ 前缀
    不依赖英文频率(flag 内容可能是乱码/编码串, 频率法会失效)
    """
    return bool(FLAG_PATTERN.search(raw))


def plausible_plain(raw, printable_th=0.95, letter_th=0.8):
    """
    统一候选判定: "像英文文本" 或 "含 flag 结构" 都算候选
    解决 flag{乱码} 场景(英文频率法对乱码 flag 失效的盲区)
    """
    if not raw:
        return False
    if has_flag_marker(raw):
        return True
    return looks_like_text(raw, printable_th=printable_th, letter_th=letter_th)


# 英文字母频率表(空格 + 大小写字母), 用于给"解出的字节流"打分
# 越像英文得分越高(凯撒/XOR 爆破共用)
ENGLISH_FREQ = {
    0x20: 0.180,
    ord('e'): 0.127, ord('t'): 0.091, ord('a'): 0.082, ord('o'): 0.075,
    ord('i'): 0.070, ord('n'): 0.067, ord('s'): 0.063, ord('h'): 0.061,
    ord('r'): 0.060, ord('d'): 0.043, ord('l'): 0.040, ord('c'): 0.028,
    ord('u'): 0.028, ord('m'): 0.024, ord('w'): 0.024, ord('f'): 0.022,
    ord('g'): 0.020, ord('y'): 0.020, ord('p'): 0.019, ord('b'): 0.015,
    ord('v'): 0.010, ord('k'): 0.008, ord('j'): 0.002, ord('x'): 0.002,
    ord('q'): 0.001, ord('z'): 0.001,
}
# 大写字母映射到对应小写的频率
for _c in range(ord('A'), ord('Z') + 1):
    ENGLISH_FREQ[_c] = ENGLISH_FREQ.get(_c + 0x20, 0.0)


def english_score(raw):
    """按英文频率表给字节流打分: 越像英文得分越高"""
    return sum(ENGLISH_FREQ.get(b, 0.0) for b in raw)


# 常见英文单词(词命中评分用, 从独立凯撒工具移植)
# 含 CTF 高频词(flag/ctf/secret/message...): 短文本下词命中比频率更可靠
COMMON_WORDS = frozenset("""
    the be to of and a in that have i it for not on with he as you do at
    this but his by from they we say her she or an will my one all would
    there their what so up out if about who get which go me when make can
    like time no just him know take people into year your good some could
    them see other than then now look only come its over think also back
    after use two how our work first well way even new want because any
    these give day most us hello world is are was were been has had did
    does doing am being secret message password attack dawn meet flag ctf
    crypto cipher encrypt decrypt key shift
""".split())


def count_common_words(raw):
    """
    统计字节流命中的常见英文单词数(忽略大小写与标点)
    词命中是"确定性"特征: 解出文本含 the/flag/secret 等词,
    比频率统计对短文本更可靠
    """
    text = "".join(
        chr(b) if 32 <= b <= 126 else " "
        for b in raw
    )
    words = text.lower().split()
    hits = 0
    for w in words:
        w = w.strip(".,!?;:'\"()[]{}<>-_")
        if w in COMMON_WORDS:
            hits += 1
    return hits


def _looks_readable(raw, threshold=0.9):
    """
    字节级可读性检查: 在"解码后的原始字节"上统计可打印占比
    达标 -> 返回解码文本; 不达标 -> 返回 None
    注意: 必须在原始字节上检查, 不能先 decode("utf-8", errors="ignore")
    再检查——ignore 会静默丢弃乱码字节, 让占比虚高, 造成假阳性
    """
    if not raw:
        return None
    count = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if count / len(raw) <= threshold:
        return None
    return raw.decode("utf-8", errors="replace")


def try_b64(content):
    """尝试 Base64 解码; 失败或结果不可读 -> 返回 None"""
    try:
        c = _clean(content)
        missing = 4 - len(c) % 4
        if missing != 4:
            c += "=" * missing
        return _looks_readable(base64.b64decode(c))
    except Exception:
        return None


def try_b32(content):
    """尝试 Base32 解码; 失败或结果不可读 -> 返回 None"""
    try:
        c = _clean(content).upper()
        missing = 8 - len(c) % 8
        if missing != 8:
            c += "=" * missing
        return _looks_readable(base64.b32decode(c))
    except Exception:
        return None


def try_b16(content):
    """尝试 Base16(hex) 解码; 失败或结果不可读 -> 返回 None"""
    try:
        c = _clean(content)
        return _looks_readable(base64.b16decode(c))
    except Exception:
        return None


def try_b85(content):
    """尝试 Base85 解码(先 a85 再 b85); 失败或结果不可读 -> 返回 None"""
    try:
        c = _clean(content)
        for fn in (base64.a85decode, base64.b85decode):
            try:
                readable = _looks_readable(fn(c))
                if readable is not None:
                    return readable
            except Exception:
                continue
        return None
    except Exception:
        return None


# 自动解码时按这个顺序尝试
# 顺序有讲究: 字符集越窄的越先试(hex 全在 base32/64 字符集内, 先解窄的)
_DECODERS = [
    ("Base16", try_b16),
    ("Base32", try_b32),
    ("Base64", try_b64),
    ("Base85", try_b85),
]


def decode_chain(content, max_layers=20):
    """
    递归解 Base 套娃
    从 content 开始, 逐层尝试所有解码器, 解到解不动为止
    返回: [{"decoder": "Base64", "result": "..."}, ...] 每层一条记录
    防死循环: 结果必须变化(res != current) + 最多 max_layers 层
    """
    layers = []
    current = content.strip()

    for _ in range(max_layers):
        for name, fn in _DECODERS:
            res = fn(current)
            if res and res != current:
                layers.append({"decoder": name, "result": res})
                current = res
                break
        else:
            # for 循环完整跑完没 break = 所有解码器都解不动了
            break

    return layers
