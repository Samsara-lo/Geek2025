#include <stdio.h>
#include <string.h>
unsigned char sbox[256] = { 0 };

void swap(unsigned char* a, unsigned char* b)
{
	unsigned char tmp = *a;
	*a = *b;
	*b = tmp;
}

void init_sbox( unsigned char key[]) {
	for (unsigned int i = 0; i < 256; i++)//赋值
		sbox[i] = i;
	unsigned int keyLen = strlen((char*)key);
	unsigned char Ttable[256] = { 0 };
	for (int i = 0; i < 256; i++)
		Ttable[i] = key[i % keyLen];//根据初始化t表
	for (int j = 0, i = 0; i < 256; i++)
	{
		j = (j + sbox[i] + Ttable[i]) % 256;	//打乱s盒
		swap(&sbox[i], &sbox[j]);
	}
}
void RC4_enc(unsigned char data[], unsigned int dataLen, unsigned char key[])
{
    unsigned char i = 0, j = 0;

    init_sbox(key);

    for (unsigned h = 0; h < dataLen; h++) {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        swap(&sbox[i], &sbox[j]);
        unsigned char t = (sbox[i] + sbox[j]) % 256;
        unsigned char k = sbox[t];
        data[h] += k;
    }
}


void RC4_dec(unsigned char data[], unsigned int dataLen, unsigned char key[])
{
    unsigned char i = 0, j = 0;

    init_sbox(key);

    for (unsigned h = 0; h < dataLen; h++) {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        swap(&sbox[i], &sbox[j]);
        unsigned char t = (sbox[i] + sbox[j]) % 256;
        unsigned char k = sbox[t];
        data[h] -= k;
    }
}

 
int main()
{
    printf("I heard someone say that my question is too easy and can be solved entirely by AI.let's see how your algorithm recognition skills hold up.\n");
	printf("But I admit that confusing things is indeed fun.\n");
    unsigned char data[1000] =
        "SYC{Alright_I_sti1l_h0pe_th3t_you_solved_the_chall3nge_by_deobfuscating_them_Geek_is_just_the_first_step_of_your_CTF_journey_Im_glad_I_could_be_part_of_your_growth_Good_luck_for_y0u!}";

    unsigned char key[] = "Samsara";

    unsigned int len = strlen((char*)data);

    // 加密
    RC4_enc(data, len, key);

    printf("加密后的密文(hex):\n");
    for (unsigned i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");

    // 解密
    RC4_dec(data, len, key);

    printf("解密后的明文:\n%s\n", data);

    return 0;
}
// 加密后的密文(hex):
// b4cd6954bd67209df2c32414c21be96a44144e39c5c85b1175addebbfee46e65069a91fea068a486176c0acf1e67e30d6047136bd136f27758761e98f57f0a92b70aeaae467e6a184a594e71b2e1417a0b31bac6aacfce09bf2ef84d75ef14ed5f66446fdee27c108cb74e6bb2d4f691d784861ff865940b1428fbdd47f4c117423f1e3807bb3733120c1668e023127572d9717a88d0462888ad1e988f927e0e692937b1ffc5af6f4137650ed262118fa63e95f5809adc
// 解密后的明文:
// SYC{Alright_I_sti1l_h0pe_th3t_you_solved_the_chall3nge_by_deobfuscating_them_Geek_is_just_the_first_step_of_your_CTF_journey_Im_glad_I_could_be_part_of_your_growth_Good_luck_for_y0u!}