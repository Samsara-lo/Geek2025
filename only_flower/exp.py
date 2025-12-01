# decrypt_onlyflower.py
CIPHER = [
    0x0A,0x84,0xC2,0x84,0x51,0x48,0x5F,0xF2,0x9E,0x8D,0xD0,0x84,0x75,0x67,0x73,0x8F,
    0xCA,0x57,0xD7,0xE6,0x14,0x6E,0x77,0xE2,0x29,0xFE,0xDF,0xCC
]
KEY = b"GEEK2025"

def ror8(v, n):
    n &= 7
    return ((v >> n) | ((v << (8 - n)) & 0xFF)) & 0xFF

def decrypt(cipher, key):
    klen = len(key)
    out = bytearray(len(cipher))
    for i, y in enumerate(cipher):
        k = key[i % klen]
        r = (y - (i & 0xFF)) & 0xFF
        x = ror8(r, k & 7)
        b = x ^ k
        out[i] = b
    return bytes(out)

if __name__ == "__main__":
    flag = decrypt(CIPHER, KEY)
    print(flag.decode('utf-8'))
# SYC{asdjjasdhjk12wk12ijkejk}