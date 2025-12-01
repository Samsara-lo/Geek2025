// simple_cipher_fixed.c
// 一个简化的可逆加密算法（修正：支持 32-byte block）
// 教学用，不适合真实安全用途。

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK 32
#define ROUNDS 4

static void xor_key(uint8_t *b, const uint8_t *key, int n) {
    for (int i = 0; i < n; i++) b[i] ^= key[i % 16];
}

static uint32_t ROL32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}


static void gen_sbox(uint8_t s[256], uint8_t inv[256], const uint8_t *key) {
    for (int i = 0; i < 256; i++) s[i] = i;

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + s[i] + key[i % 16];
        uint8_t t = s[i];
        s[i] = s[j];
        s[j] = t;
    }

    for (int i = 0; i < 256; i++) inv[s[i]] = i;
}

static const uint8_t perm[BLOCK] = {
    31, 0, 1, 2, 3, 4, 5, 6,
     7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,
    23,24,25,26,27,28,29,30
};

static const uint8_t inv_perm[BLOCK] = {
     1, 2, 3, 4, 5, 6, 7, 8,
     9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,
    25,26,27,28,29,30,31, 0
};


static uint32_t F(uint32_t x, uint32_t k, const uint8_t sbox[256]) {
    x ^= k;
    uint8_t b0 = sbox[(x >>  0) & 0xFF];
    uint8_t b1 = sbox[(x >>  8) & 0xFF];
    uint8_t b2 = sbox[(x >> 16) & 0xFF];
    uint8_t b3 = sbox[(x >> 24) & 0xFF];
    uint32_t y = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return ROL32(y, 5);
}

static void encrypt_block(uint8_t b[BLOCK], const uint8_t *key,
                          const uint8_t sbox[256], const uint8_t inv_sbox[256])
{
    xor_key(b, key, BLOCK);

    for (int i = 0; i < BLOCK; i++) b[i] = sbox[b[i]];

    uint8_t tmp[BLOCK];
    for (int i = 0; i < BLOCK; i++) tmp[i] = b[perm[i]];
    memcpy(b, tmp, BLOCK);

    uint32_t W0 = 0, W1 = 0, W2 = 0, W3 = 0, X0 = 0, X1 = 0, X2 = 0, X3 = 0;
    memcpy(&W0, b + 0, 4);  memcpy(&W1, b + 4, 4);
    memcpy(&W2, b + 8, 4);  memcpy(&W3, b +12, 4);
    memcpy(&X0, b +16, 4);  memcpy(&X1, b +20, 4);
    memcpy(&X2, b +24, 4);  memcpy(&X3, b +28, 4);

    for (int r = 0; r < ROUNDS; r++) {
        uint32_t k = ((const uint32_t*)key)[r % 4];

        uint32_t t0 = W0 ^ F(W1, k, sbox); W0 = W1; W1 = t0;
        uint32_t t1 = W2 ^ F(W3, k, sbox); W2 = W3; W3 = t1;

        uint32_t t2 = X0 ^ F(X1, k, sbox); X0 = X1; X1 = t2;
        uint32_t t3 = X2 ^ F(X3, k, sbox); X2 = X3; X3 = t3;
    }

    memcpy(b + 0, &W0, 4); memcpy(b + 4, &W1, 4);
    memcpy(b + 8, &W2, 4); memcpy(b +12, &W3, 4);
    memcpy(b +16, &X0, 4); memcpy(b +20, &X1, 4);
    memcpy(b +24, &X2, 4); memcpy(b +28, &X3, 4);
}


static void decrypt_block(uint8_t b[BLOCK], const uint8_t *key,
                          const uint8_t sbox[256], const uint8_t inv_sbox[256])
{
    uint32_t W0 = 0, W1 = 0, W2 = 0, W3 = 0, X0 = 0, X1 = 0, X2 = 0, X3 = 0;
    memcpy(&W0, b + 0, 4);  memcpy(&W1, b + 4, 4);
    memcpy(&W2, b + 8, 4);  memcpy(&W3, b +12, 4);
    memcpy(&X0, b +16, 4);  memcpy(&X1, b +20, 4);
    memcpy(&X2, b +24, 4);  memcpy(&X3, b +28, 4);

    for (int r = ROUNDS - 1; r >= 0; r--) {
        uint32_t k = ((const uint32_t*)key)[r % 4];

        uint32_t t3 = X3 ^ F(X2, k, sbox); X3 = X2; X2 = t3;
        uint32_t t2 = X1 ^ F(X0, k, sbox); X1 = X0; X0 = t2;

        uint32_t t1 = W3 ^ F(W2, k, sbox); W3 = W2; W2 = t1;
        uint32_t t0 = W1 ^ F(W0, k, sbox); W1 = W0; W0 = t0;
    }

    memcpy(b + 0, &W0, 4); memcpy(b + 4, &W1, 4);
    memcpy(b + 8, &W2, 4); memcpy(b +12, &W3, 4);
    memcpy(b +16, &X0, 4); memcpy(b +20, &X1, 4);
    memcpy(b +24, &X2, 4); memcpy(b +28, &X3, 4);

    uint8_t tmp[BLOCK];
    for (int i = 0; i < BLOCK; i++) tmp[i] = b[inv_perm[i]];
    memcpy(b, tmp, BLOCK);

    for (int i = 0; i < BLOCK; i++) b[i] = inv_sbox[b[i]];

    xor_key(b, key, BLOCK);
}

int main() {
    uint8_t key[16] = {
        0x10,0x20,0x30,0x40,0x55,0x66,0x77,0x88,
        0x90,0xAB,0xBC,0xCD,0xDE,0xEF,0x01,0x23
    };

    uint8_t sbox[256], inv_sbox[256];
    gen_sbox(sbox, inv_sbox, key);

    static const uint8_t target_enc[BLOCK] = {
        0xCA,0x5A,0x96,0xFF,0x08,0x49,0x72,0x39,
        0x36,0x18,0x13,0x8A,0x14,0xC0,0x0C,0x78,
        0xF8,0x7C,0x49,0xC7,0xBE,0xE8,0x91,0xED,
        0x7F,0xB0,0x02,0xAD,0x77,0x74,0xD4,0x34
    };

    uint8_t input_buf[BLOCK + 4] = {0};
    printf("Input the flag (<= 32 chars): ");
    if (!fgets((char*)input_buf, sizeof(input_buf), stdin)) {
        printf("Input error.\n");
        return 1;
    }
    size_t len = strcspn((char*)input_buf, "\r\n");
    input_buf[len] = '\0';
    uint8_t *start = input_buf;
    if (len >= 3 && start[0] == 0xEF && start[1] == 0xBB && start[2] == 0xBF) {
        start += 3;
        len -= 3;
    }

    if (len == 0 || len > BLOCK) {
        printf("Try again?\n");
        return 0;
    }

    uint8_t block[BLOCK] = {0};
    memcpy(block, start, len);

    encrypt_block(block, key, sbox, inv_sbox);

    if (memcmp(block, target_enc, BLOCK) == 0) {
        printf("Congratulations!\n");
    } else {
        printf("Try again?\n");
    }

    return 0;
}
//SYC{Then_you_are_1mpressivse}