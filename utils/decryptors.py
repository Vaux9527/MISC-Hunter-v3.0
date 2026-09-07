'''
密钥解密框架

用途: 人机接力接口的"算法注册表"——人类提供密钥后,
     按 算法 × 模式 × key派生 的组合尝试解密, 解出可读文本即命中

组合矩阵:
    算法: XOR(单独, 见 utils.decoders.xor_decrypt)
          / Serpent / AES / DES / 3DES
    模式: ECB / CBC(零IV) / CBC(IV前置, Serpent v1.2 格式)
    key派生: 原样 / md5 / sha256 / 补零16/24/32 / 重复到16
            (输入为 hex 串时也按 hex 字节试)

依赖策略:
    Serpent: utils/vendor/pyserpent (MIT 自带, 零 pip 依赖)
    AES/DES/3DES: pycryptodome (可选——缺失自动跳过, 建议 pip install pycryptodome)

诚实原则: 全部组合试完仍解不出 -> 返回 None, 由调用方如实报告
    不会假装成功; 解不开不代表 key 错, 可能是算法/参数不在注册表内
'''

import hashlib

from utils.decoders import plausible_plain
from utils.vendor.pyserpent.serpent import (
    Serpent as SerpentECB,
    serpent_cbc_decrypt,
)

# pycryptodome 可选
try:
    from Crypto.Cipher import AES, DES, DES3
    HAVE_PYCRYPTODOME = True
except ImportError:
    HAVE_PYCRYPTODOME = False


def _key_variants(key_bytes):
    """key 派生矩阵: (派生名, key字节) 列表, 供各算法按长度要求选用"""
    v = [("原样", key_bytes)]

    if len(key_bytes) not in (16, 24, 32):
        v.append(("补零16", key_bytes.ljust(16, b"\x00")))
    if len(key_bytes) != 32:
        v.append(("补零32", key_bytes.ljust(32, b"\x00")))

    v.append(("md5", hashlib.md5(key_bytes).digest()))
    v.append(("sha256", hashlib.sha256(key_bytes).digest()))
    v.append(("sha256前16", hashlib.sha256(key_bytes).digest()[:16]))

    if len(key_bytes) <= 8:
        v.append(("重复到16", (key_bytes * 3)[:16]))

    return v


def parse_key_input(key_str):
    """用户输入的 key 可能是文本也可能是 hex; 返回候选 key 字节列表"""
    candidates = [key_str.encode("utf-8", errors="replace")]
    s = key_str.strip()
    if s and len(s) % 2 == 0:
        try:
            candidates.append(bytes.fromhex(s))
        except ValueError:
            pass
    return candidates


def _check(plain, result_holder):
    """解出后判定是否像明文; 命中则记录并返回 True"""
    if plain and plausible_plain(plain, letter_th=0.7):
        result_holder["hit"] = plain
        return True
    return False


def try_decrypt_all(key_str, data):
    """
    按注册表尝试所有组合

    返回: {"ok": True, "algorithm": ..., "mode": ..., "key_derivation": ...,
           "plaintext": bytes, "attempts": N}
          或 {"ok": False, "attempts": N}
    """
    result = {"attempts": 0}

    def attempt(label, plain):
        result["attempts"] += 1
        if _check(plain, result):
            # 从 label 反解描述: "Serpent-ECB(原样)" 形式
            result["hit_label"] = label
            return True
        return False

    for raw_key in parse_key_input(key_str):
        for deriv_name, key in _key_variants(raw_key):
            # ========== Serpent (vendor, 自带) ==========
            # ECB: key 长度须 4 的倍数且 <= 32
            if len(key) % 4 == 0 and len(key) <= 32:
                try:
                    if len(data) % 16 == 0:
                        plain = SerpentECB(key).decrypt(data)
                        if attempt(f"Serpent-ECB({deriv_name})", plain):
                            return _finalize(result, "Serpent", "ECB", deriv_name)
                except Exception:
                    pass

                # CBC 零IV: 前置 16 个零字节(旧版/v1.1 风格)
                try:
                    plain = serpent_cbc_decrypt(key, b"\x00" * 16 + data)
                    if attempt(f"Serpent-CBC零IV({deriv_name})", plain):
                        return _finalize(result, "Serpent", "CBC零IV", deriv_name)
                except Exception:
                    pass

                # CBC IV前置(v1.2 格式): 密文头部 16 字节即 IV
                if len(data) > 16:
                    try:
                        plain = serpent_cbc_decrypt(key, data)
                        if attempt(f"Serpent-CBC前置IV({deriv_name})", plain):
                            return _finalize(result, "Serpent", "CBC前置IV", deriv_name)
                    except Exception:
                        pass

            # ========== AES/DES/3DES (pycryptodome, 可选) ==========
            if HAVE_PYCRYPTODOME:
                for algo_name, algo_cls, block in (
                    ("AES", AES, 16), ("DES", DES, 8), ("3DES", DES3, 8),
                ):
                    # key 长度约束: AES 16/24/32, DES 8, 3DES 16/24
                    # (pycryptodome 的 key_size 可能是 int 或元组, 统一处理)
                    allowed_sizes = algo_cls.key_size
                    if isinstance(allowed_sizes, int):
                        allowed_sizes = (allowed_sizes,)
                    if len(key) not in allowed_sizes:
                        continue
                    try:
                        if len(data) % block == 0:
                            plain = algo_cls.new(key, algo_cls.MODE_ECB).decrypt(data)
                            if attempt(f"{algo_name}-ECB({deriv_name})", plain):
                                return _finalize(result, algo_name, "ECB", deriv_name)
                    except Exception:
                        pass
                    try:
                        if len(data) % block == 0:
                            plain = algo_cls.new(
                                key, algo_cls.MODE_CBC, iv=b"\x00" * block
                            ).decrypt(data)
                            if attempt(f"{algo_name}-CBC零IV({deriv_name})", plain):
                                return _finalize(result, algo_name, "CBC零IV", deriv_name)
                    except Exception:
                        pass

    return {"ok": False, "attempts": result["attempts"]}


def _finalize(result, algorithm, mode, deriv):
    return {
        "ok": True,
        "algorithm": algorithm,
        "mode": mode,
        "key_derivation": deriv,
        "plaintext": result["hit"],
        "attempts": result["attempts"],
        "description": f"{algorithm}-{mode}({deriv})",
    }
