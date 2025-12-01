#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include<Windows.h>
#include<string>
using namespace std;
#include <iostream>

static bool g_miao_encrypted = false;

typedef struct {
    uint8_t S[256];
    uint8_t i, j;
} CTX;

void init(CTX* ctx, const uint8_t* key, int keylen) {
    for (int i = 0; i < 256; i++) ctx->S[i] = (uint8_t)i;
    ctx->i = ctx->j = 0;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + ctx->S[i] + key[i % keylen]);
        uint8_t t = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = t;
    }
}

uint8_t getbyte(CTX* ctx) {
    ctx->i++;
    ctx->j += ctx->S[ctx->i];
    uint8_t t = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = t;
    return ctx->S[(uint8_t)(ctx->S[ctx->i] + ctx->S[ctx->j])];
}

void encode(CTX* ctx, uint8_t* data, int len) {
    for (int n = 0; n < len; n++) data[n] ^= getbyte(ctx);
}

uint8_t* ascii_to_hexbytes(const char* s, int* outlen) {
    int len = strlen(s);
    uint8_t* buf = (uint8_t*)malloc(len * 2 + 1);
    for (int i = 0; i < len; i++) {
        sprintf((char*)buf + 2 * i, "%02X", (unsigned char)s[i]);
    }
    *outlen = len * 2;
    buf[*outlen] = 0;
    return buf;
}

uint8_t* hexstr_to_bytes(const char* hex, int* outlen) {
    int len = strlen(hex);
    *outlen = len / 2;
    uint8_t* buf = (uint8_t*)malloc(*outlen);
    for (int i = 0; i < *outlen; i++) {
        char tmp[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        buf[i] = (uint8_t)strtol(tmp, NULL, 16);
    }
    return buf;
}

char* bytes_to_hexstr(const uint8_t* buf, int len) {
    char* s = (char*)malloc(len * 2 + 1);
    for (int i = 0; i < len; i++) sprintf(s + 2 * i, "%02x", buf[i]); // 用小写 %02x
    s[len * 2] = 0;
    return s;
}



#if defined(_MSC_VER)
  #define MIAO_CODE  __declspec(code_seg(".miao"))
  #pragma code_seg(".miao")
  #pragma comment(linker, "/SECTION:.miao,ERW")
#else
  #define MIAO_CODE  __attribute__((section(".miao"))) __attribute__((noinline))
#endif





static void miao_xor(uint8_t* p, SIZE_T n) {
    for (SIZE_T i = 0; i < n; ++i) p[i] ^= 3u;
}

static bool find_miao_section(uint8_t** outBase, SIZE_T* outSize) {
    uint8_t* base = (uint8_t*)GetModuleHandleA(NULL);
    if (!base) return false;

    auto dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto sec = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < n; ++i, ++sec) {
        char name[9] = {0};
        memcpy(name, sec->Name, 8);
        if (strncmp(name, ".miao", 8) == 0) {
            SIZE_T sz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            if (sz == 0) return false;
            *outBase = base + sec->VirtualAddress;
            *outSize = sz;
            return true;
        }
    }
    return false;
}

static bool miao_encrypt() {
    if (g_miao_encrypted) return true;
    uint8_t* va; SIZE_T sz;
    if (!find_miao_section(&va, &sz)) return false;
    DWORD old;
    if (!VirtualProtect(va, sz, PAGE_EXECUTE_READWRITE, &old)) return false;
    miao_xor(va, sz);
    FlushInstructionCache(GetCurrentProcess(), va, sz);
    VirtualProtect(va, sz, old, &old);
    g_miao_encrypted = true;
    return true;
}
static bool miao_decrypt() {
    if (!g_miao_encrypted) return true;
    uint8_t* va; SIZE_T sz;
    if (!find_miao_section(&va, &sz)) return false;
    DWORD old;
    if (!VirtualProtect(va, sz, PAGE_EXECUTE_READWRITE, &old)) return false;
    miao_xor(va, sz);
    FlushInstructionCache(GetCurrentProcess(), va, sz);
    VirtualProtect(va, sz, old, &old);
    g_miao_encrypted = false;
    return true;
}

MIAO_CODE
char* encodee(const uint8_t* buf, int len) {
    static const char base64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if (!out) return NULL;
    int j = 0;
    for (int i = 0; i < len; i += 3) {
        uint32_t v = buf[i] << 16;
        if (i + 1 < len) v |= buf[i + 1] << 8;
        if (i + 2 < len) v |= buf[i + 2];
        out[j++] = base64_table[(v >> 18) & 63];
        out[j++] = base64_table[(v >> 12) & 63];
        out[j++] = (i + 1 < len) ? base64_table[(v >> 6) & 63] : '=';
        out[j++] = (i + 2 < len) ? base64_table[v & 63] : '=';
    }
    out[j] = 0;
    return out;
}
#if defined(_MSC_VER)
  #pragma code_seg() 
#endif

void encodeeend()
{
 
}

typedef char* (*encodee_t)(const uint8_t*, int);



void xxor(uint8_t* source, SIZE_T dLen) {
    for (SIZE_T i = 0; i < dLen; i++) source[i] ^= 3;
}

void SMC(char* pBuf)
{
    const char* szSecName = ".miao";
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pBuf + pDosHeader->e_lfanew);

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return;


    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHeader);
    WORD nSec = pNtHeader->FileHeader.NumberOfSections;

    for (int i = 0; i < nSec; i++, pSec++) {
        if (strncmp((char*)pSec->Name, szSecName, strlen(szSecName)) == 0) {
            uint8_t* packStart = (uint8_t*)pBuf + pSec->VirtualAddress;
            SIZE_T pack_size = pSec->Misc.VirtualSize;
            if (pack_size == 0) pack_size = pSec->SizeOfRawData;
            if (pack_size == 0) return;
            printf("1");

            DWORD oldProtect;
            BOOL vp = VirtualProtect(packStart, pack_size, PAGE_EXECUTE_READWRITE, &oldProtect);
            printf("2");
            if (!vp) {
                printf("3");
                if (!VirtualProtect(packStart, pack_size, PAGE_READWRITE, &oldProtect)) {
                    printf("4");
                    return;
                }
            }
            printf("5");
            xxor(packStart, pack_size);

            VirtualProtect(packStart, pack_size, oldProtect, &oldProtect);
            printf("6");
            return;
        }
    }
}


void UnPack()
{
    char* hMod;
    hMod = (char*)GetModuleHandle(0);
    SMC(hMod);
}


static const char base58_table[] =
"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789";

char* enc0de(const uint8_t* data, int len) {
    int size = len * 138 / 100 + 2;
    int* digits = (int*)calloc(size, sizeof(int));
    int zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    for (int i = zeros; i < len; i++) {
        int carry = data[i];
        for (int j = size - 1; j >= 0; j--) {
            carry += 256 * digits[j];
            digits[j] = carry % 58;
            carry /= 58;
        }
    }

    int i = 0;
    while (i < size && digits[i] == 0) i++;
    int out_len = zeros + (size - i);
    char* out = (char*)malloc(out_len + 1);
    int p = 0;
    for (int k = 0; k < zeros; k++) out[p++] = base58_table[0];
    for (; i < size; i++) out[p++] = base58_table[digits[i]];
    out[p] = 0;
    free(digits);
    return out;
}

int main() {
    const char* cipher =
        "tHMoSoMX71sm62ARQ8aHF6i88nhkH9Ac2J7CrkQsQgXpiy6efoC8YVkzZu1tMyFxCLbbqvgXZHxtwK5TACVhPi1EE5mK6JG56wPNR4d2GmkELGfJHgtcAEH7";

    printf("Plz input your flag miao: ");
    char input[1024];
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\r\n")] = 0;

    int hexlen;
    uint8_t* hex_ascii = ascii_to_hexbytes(input, &hexlen);

    int binlen;
    uint8_t* bin = hexstr_to_bytes((char*)hex_ascii, &binlen);

    uint8_t key[1] = { 0x11 };
    CTX ctx;
    init(&ctx, key, 1);
    encode(&ctx, bin, binlen);

    char* en1 = bytes_to_hexstr(bin, binlen);

    miao_encrypt();
    char* en2 = encodee((uint8_t*)en1, strlen(en1));


    if (!en2) { puts("encodee returned NULL"); return 0; }
    // miao_encrypt();

    char* en3 = enc0de((uint8_t*)en2, strlen(en2));


    if (strcmp(en3, cipher) == 0) {
        printf("Correct!\n");
    }
    else {
        printf("Wrong!\n");
    }

    free(hex_ascii);
    free(bin);
    free(en1);
    free(en2);
    free(en3);
    return 0;
}
