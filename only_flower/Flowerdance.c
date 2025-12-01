#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

static const char *KEY = "GEEK2025"; 

static const uint8_t CIPHER[] = {
    0x0A,0x84,0xC2,0x84,0x51,0x48,0x5F,0xF2,0x9E,0x8D,0xD0,0x84,0x75,0x67,0x73,0x8F,
    0xCA,0x57,0xD7,0xE6,0x14,0x6E,0x77,0xE2,0x29,0xFE,0xDF,0xCC
};
static const size_t CIPHER_LEN = sizeof(CIPHER);


static inline uint8_t rol8(uint8_t v, unsigned int n) {
    n &= 7;
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

void encrypt(const uint8_t *in, uint8_t *out, size_t len) {
    size_t klen = strlen(KEY);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = in[i];
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        uint8_t k = (uint8_t)KEY[i % klen];
        uint8_t x = b ^ k;
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        uint8_t r = rol8(x, k & 7);
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        uint8_t y = (uint8_t)((r + (uint8_t)(i & 0xFF)) & 0xFF);
        out[i] = y;
    }
}

int checkcheck(const char *s) {
    if (!s) return 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    size_t L = strlen(s);
    if (L < 4) return 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    if (s[0] != 'S' || s[1] != 'Y' || s[2] != 'C' || s[3] != '{') return 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    if (s[L-1] != '}') return 0;
    return 1;
}

void hint(void) {
    printf("\n[Flowerdance hint] \n");
    printf("Samsara: What is FLower?\n");
    printf("QYQS: see what junk code is.\n");
}

int main(void) {
    char buf[256];
    printf("Welcome to Flowerdance. Input your flag: ");
    
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );

    size_t L = strlen(buf);
    if (L > 0 && buf[L-1] == '\n') buf[--L] = 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );


    if (!checkcheck(buf)) {
        printf("Bad format..\n");
        hint();
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        return 0;
    }

    size_t inlen = strlen(buf);
    if (inlen != CIPHER_LEN) {
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        printf("Wrong length (expected %lu bytes including braces).\n", (unsigned long)CIPHER_LEN);
        hint();
        return 0;
    }

    uint8_t *tmp = (uint8_t*)malloc(inlen);
    if (!tmp) return 0;
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    
    encrypt((const uint8_t*)buf, tmp, inlen);
    __asm__ __volatile__ (
        ".byte 0xEB,0xFF,0xC0,0x48;"
    );
    if (memcmp(tmp, CIPHER, inlen) == 0) {
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        printf("Correct! Flowerdance!\n");
    } else {
        printf("Incorrect. Keep dancing.\n");
        __asm__ __volatile__ (
            ".byte 0xEB,0xFF,0xC0,0x48;"
        );
        hint();
    }

    free(tmp);
    return 0;
}
