from typing import List

cipher_list = [0x30,0x37,0x39,0x32,0x35,0x37,0x35,0x32,0x34,0x32,0x30,0x37,
               0x65,0x34,0x35,0x32,0x34,0x32,0x34,0x32,0x30,0x37,0x35,0x37,
               0x37,0x37,0x32,0x36,0x35,0x37,0x36,0x37,0x37,0x37,0x35,0x36,
               0x62,0x37,0x61,0x36,0x32,0x35,0x38,0x34,0x32,0x34,0x63,0x36,
               0x32,0x32,0x34,0x32,0x32,0x36]

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def rol4_nibble(b: int) -> int:
    return ((b << 4) & 0xF0) | ((b >> 4) & 0x0F)

def ror_bits(data: bytes, n: int) -> bytes:
    """整体 bitstream 循环右移 n 位（逆向用）"""
    bit_len = len(data) * 8
    if bit_len == 0:
        return data
    n = n % bit_len
    val = int.from_bytes(data, "big")
    val = ((val >> n) | (val << (bit_len - n))) & ((1 << bit_len) - 1)
    return val.to_bytes(len(data), "big")

def decrypt_from_ascii_hex_bytes(ascii_hex_bytes: bytes) -> bytes:
    """
    输入: 一段由 ASCII hex 字符组成的 bytes（例如 b'0792...'）
    返回: 还原后的明文字节
    """
    # 1) 把 ASCII hex bytes -> 原始字节（因为最后encrypt 返回 data.hex()，所以外面是 ASCII hex）
    try:
        raw = bytes.fromhex(ascii_hex_bytes.decode('ascii'))
    except Exception as e:
        raise ValueError("输入不是有效的 ASCII-hex 字节串") from e

    # 2) 加密的最后一步是整体左移 32 bit (rol_bits(...,32))
    #    解密：整体右移 32 bit
    raw = ror_bits(raw, 32)

    # 3) 加密前一步是 reverse，解密也要 reverse
    raw = raw[::-1]

    # 4) 加密时对每字节做了 rol4_nibble（交换高低半字节），该操作自身可逆，直接再做一次
    raw = bytes([rol4_nibble(b) for b in raw])

    # 5) 加密时对每字节 xor 0x11，解密也再 xor 0x11
    raw = xor_bytes(raw, 0x11)

    return raw

if __name__ == "__main__":
    # 把你给的 list[int] 先变成 bytes（这一步代表 ASCII hex 字节流）
    ascii_hex_bytes = bytes(cipher_list)

    plain = decrypt_from_ascii_hex_bytes(ascii_hex_bytes)

    print("flag:", plain.decode('utf-8'))
# SYC{jtfgdsfda554_a54d8as53}
