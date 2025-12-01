def b2nle(b, n): return [int.from_bytes(b[i:i+n], byteorder='little', signed=False) for i in range(0, len(b), n)]

def n2ble(na, n):
    b = bytearray()
    for a in na: b.extend(a.to_bytes(n, byteorder='little'))
    return b

key = bytearray.fromhex("102030405566778890ABBCCDDEEF0123")
dkey = b2nle(key, 4)
perm = bytearray.fromhex("1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
sbox = bytearray(256)
inv_sbox = bytearray(256)
enc = bytearray.fromhex("CA5A96FF084972393618138A14C00C78F87C49C7BEE891ED7FB002AD7774D434")
inp = bytearray(b"12345678901234567890123456789012")

def rol(b, shift):
    shift &= 31
    return ((b << shift) | (b >> (32-shift))) & 0xFFFFFFFF

def gen(sbox, inv_sbox, key):
    for i in range(256): sbox[i] = i
    t = 0
    for j in range(256):
        t = (t + key[j % 16] + sbox[j]) & 0xFF
        sbox[j], sbox[t] = sbox[t], sbox[j]
    for k in range(256): inv_sbox[sbox[k]] = k

def F(dm, dk, sbox):
    dm ^= dk
    bm = n2ble([dm], 4)
    for i in range(4): bm[i] = sbox[bm[i]]
    dm = b2nle(bm, 4)[0]
    return rol(dm, 5)

gen(sbox, inv_sbox, key)
for i in range(32): inp[i] ^= key[i%16]
for i in range(32): inp[i] = sbox[inp[i]]
inp = inp[-1:] + inp[:-1]
dinp = b2nle(inp, 4)[::-1]
for i in range(4):
    for j in range(6, -2, -2):
        dinp[j], dinp[j+1] = dinp[j+1] ^ F(dinp[j], dkey[i], sbox), dinp[j]
dinp = dinp[::-1]
res = n2ble(dinp, 4)
print(res.hex())

denc = b2nle(enc, 4)
denc = denc[::-1]
for i in range(3, -1, -1):
    for j in range(0, 8, 2):
        denc[j], denc[j+1] = denc[j+1], denc[j] ^ F(denc[j+1], dkey[i], sbox)
denc = denc[::-1]
benc = n2ble(denc, 4)
rec = benc[1:] + benc[:1]
for i in range(32): rec[i] = inv_sbox[rec[i]]
for i in range(32): rec[i] ^= key[i % 16]
print(rec)