import base64
import urllib.parse
import sys
import string

# 尝试导入可选Base库，没装不影响核心功能
try:
    import base58
    HAVE_BASE58 = True
except ImportError:
    HAVE_BASE58 = False
try:
    import base91
    HAVE_BASE91 = True
except ImportError:
    HAVE_BASE91 = False

def print_banner():
    print("="*50)
    print("🌟 CTF常用编码解码工具箱 🌟")
    print("支持自动处理空行、空格、换行，粘贴即用")
    print("="*50)
    print("👉 解码类：")
    print("1. 二进制转ASCII")
    print("2. 十进制转ASCII")
    print("3. 十六进制转ASCII")
    print("4. Base64解码")
    print("5. URL编码解码")
    print("6. Unicode转中文(\\uXXXX)")
    print("7. 自动递归解多层Base套娃")
    print("👉 编码/转换类：")
    print("8. ASCII转二/十/十六进制")
    print("9. 进制互转(2/8/10/16任意转)")
    print("0. 退出工具")
    print("="*50)

def get_input(prompt="请粘贴内容，粘贴完成后单独输入一行 END 并回车："):
    """获取用户多行输入，以END为结束标记，自动处理空行、空格"""
    print(f"\n{prompt}")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)

def is_printable(s):
    """判断字符串是否大部分是可打印字符，避免乱码"""
    if not s:
        return False
    print_count = sum(c in string.printable for c in s)
    return print_count / len(s) > 0.9

# ------------------------------ 解码函数 ------------------------------
def bin_to_ascii(content):
    """二进制转ASCII，自动处理空行、空格"""
    result = ""
    for line in content.split("\n"):
        binary = line.strip().replace(" ", "")
        if not binary:
            continue
        try:
            num = int(binary, 2)
            result += chr(num)
        except:
            print(f"[!] 无效二进制: {binary}，已跳过")
    return result

def dec_to_ascii(content):
    """十进制转ASCII，支持空格/换行/逗号分隔"""
    result = ""
    content = content.replace(" ", "\n").replace(",", "\n").replace(";", "\n")
    for line in content.split("\n"):
        dec = line.strip()
        if not dec:
            continue
        try:
            num = int(dec, 10)
            result += chr(num)
        except:
            print(f"[!] 无效十进制: {dec}，已跳过")
    return result

def hex_to_ascii(content):
    """十六进制转ASCII，自动去0x、空格"""
    result = ""
    content = content.replace(" ", "").replace("0x", "").replace("\n", "").replace("\r", "")
    for i in range(0, len(content), 2):
        hex_str = content[i:i+2]
        if not hex_str:
            continue
        try:
            num = int(hex_str, 16)
            result += chr(num)
        except:
            print(f"[!] 无效十六进制: {hex_str}，已跳过")
    return result

def try_b64(content):
    """尝试Base64解码"""
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "")
        missing_padding = 4 - len(c) % 4
        if missing_padding !=4:
            c += "="*missing_padding
        res = base64.b64decode(c).decode("utf-8", errors="ignore")
        return res if is_printable(res) else None
    except:
        return None

def try_b32(content):
    """尝试Base32解码"""
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "").upper()
        missing_padding = 8 - len(c) % 8
        if missing_padding !=8:
            c += "="*missing_padding
        res = base64.b32decode(c).decode("utf-8", errors="ignore")
        return res if is_printable(res) else None
    except:
        return None

def try_b16(content):
    """尝试Base16(hex)解码"""
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "")
        res = base64.b16decode(c).decode("utf-8", errors="ignore")
        return res if is_printable(res) else None
    except:
        return None

def try_b85(content):
    """尝试Base85解码"""
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "")
        try:
            res = base64.a85decode(c).decode("utf-8", errors="ignore")
            if is_printable(res):
                return res
        except:
            pass
        try:
            res = base64.b85decode(c).decode("utf-8", errors="ignore")
            if is_printable(res):
                return res
        except:
            return None
    except:
        return None

def try_b58(content):
    """尝试Base58解码（需要装base58库）"""
    if not HAVE_BASE58:
        return None
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "")
        res = base58.b58decode(c).decode("utf-8", errors="ignore")
        return res if is_printable(res) else None
    except:
        return None

def try_b91(content):
    """尝试Base91解码（需要装base91库）"""
    if not HAVE_BASE91:
        return None
    try:
        c = content.replace("\n", "").replace(" ", "").replace("\r", "")
        res = base91.decode(c).decode("utf-8", errors="ignore")
        return res if is_printable(res) else None
    except:
        return None

def auto_base_decode(content):
    """自动递归解多层Base套娃"""
    print("\n" + "="*30 + " 开始自动解码 " + "="*30)
    current = content.strip()
    layer = 1
    # 所有尝试的解码函数
    decoders = [try_b16, try_b32, try_b64, try_b85, try_b58, try_b91]
    decoder_names = ["Base16", "Base32", "Base64", "Base85", "Base58(需装库)", "Base91(需装库)"]
    while True:
        decoded = None
        used_decoder = ""
        for i, decoder in enumerate(decoders):
            res = decoder(current)
            if res and res != current:
                decoded = res
                used_decoder = decoder_names[i]
                break
        if not decoded:
            break
        print(f"[+] 第{layer}层 {used_decoder} 解码结果：")
        print(decoded)
        print("-"*70)
        current = decoded
        layer +=1
        if layer > 20: # 防止死循环，最多解20层
            print("[!] 已达最大解码层数，停止")
            break
    print("="*30 + " 最终结果 " + "="*30)
    return current

def b64_decode(content):
    res = try_b64(content)
    return res if res else "[!] Base64解码失败，请检查格式"

def url_decode(content):
    try:
        return urllib.parse.unquote(content, errors="ignore")
    except Exception as e:
        return f"[!] URL解码失败: {str(e)}"

def unicode_decode(content):
    try:
        return content.encode("utf-8").decode("unicode_escape", errors="ignore")
    except Exception as e:
        return f"[!] Unicode解码失败: {str(e)}"

# ------------------------------ 编码/转换函数 ------------------------------
def ascii_to_xxx():
    """ASCII转二/十/十六进制"""
    content = get_input("请输入要编码的明文，粘贴完输END回车：")
    print("\n请选择编码类型：")
    print("1. 转二进制（每行一个，无前导0，和题目格式一致）")
    print("2. 转二进制（8位标准，补前导0）")
    print("3. 转十进制（每行一个）")
    print("4. 转十六进制（连写，小写）")
    choice = input("输入选项：").strip()
    res = []
    for c in content:
        if c == "\n" or c == "\r":
            continue
        if choice == "1":
            res.append(bin(ord(c))[2:]) # 去掉0b前缀
        elif choice == "2":
            res.append(bin(ord(c))[2:].zfill(8)) # 补0到8位
        elif choice == "3":
            res.append(str(ord(c)))
        elif choice == "4":
            res.append(hex(ord(c))[2:].zfill(2)) # 转2位十六进制
        else:
            return "[!] 选项错误"
    return "\n".join(res)

def base_convert():
    """进制互转"""
    num_str = input("请输入要转换的数字：").strip().replace(" ", "")
    src_base = int(input("输入原进制(2/8/10/16)：").strip())
    dst_base = int(input("输入目标进制(2/8/10/16)：").strip())
    try:
        num = int(num_str, src_base)
        if dst_base == 2:
            res = bin(num)[2:]
        elif dst_base == 8:
            res = oct(num)[2:]
        elif dst_base == 10:
            res = str(num)
        elif dst_base == 16:
            res = hex(num)[2:]
        else:
            return "[!] 仅支持2/8/10/16进制"
        return f"转换结果：{res}"
    except Exception as e:
        return f"[!] 转换失败：{str(e)}"

if __name__ == "__main__":
    print_banner()
    if not HAVE_BASE58:
        print("[i] 提示：安装base58库(pip install base58)可支持Base58自动解码")
    if not HAVE_BASE91:
        print("[i] 提示：安装base91库(pip install base91)可支持Base91自动解码")
    while True:
        choice = input("\n请选择功能(输入数字): ").strip()
        if choice == "0":
            print("退出工具~")
            sys.exit(0)
        if choice in ["1","2","3","4","5","6","7"]:
            content = get_input()
        if choice == "1":
            res = bin_to_ascii(content)
        elif choice == "2":
            res = dec_to_ascii(content)
        elif choice == "3":
            res = hex_to_ascii(content)
        elif choice == "4":
            res = b64_decode(content)
        elif choice == "5":
            res = url_decode(content)
        elif choice == "6":
            res = unicode_decode(content)
        elif choice == "7":
            res = auto_base_decode(content)
        elif choice == "8":
            res = ascii_to_xxx()
        elif choice == "9":
            res = base_convert()
        else:
            print("[!] 请输入正确的选项数字！")
            continue
        print("\n" + "="*30 + " 结果 " + "="*30)
        print(res)
        print("="*72)