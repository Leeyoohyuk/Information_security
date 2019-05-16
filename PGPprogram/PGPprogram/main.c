#include "md5.h"
#include "rsa.h"
#include "sdes.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>

#define MD 5
#if MD == 5
#endif
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final
static void MDFile PROTO_LIST((char *));
static void MDString PROTO_LIST((char *));
static void MDPrint PROTO_LIST((unsigned char[16]));
void rsa(long int *p, long int *q, long int *n, long int *e, long int *d);
void gen_sdes_keys(int key[], int keys[][8]);

void main()
{
	FILE *origin = fopen("Test.txt", "rb"); // origin file
	FILE *hash; // hash
	FILE *sum_mac; // origin + mac
	FILE *sum_enc; // En(origin + mac)
	FILE *Etxt; // En(origin + mac) + session key enc = Etext
	FILE *sum_dec; // En(origin + mac)
	FILE *sum_mac2; // origin + mac
	FILE *Dtxt; // dec file = Dtext
	fseek(origin, 0, SEEK_END);
	int size = ftell(origin);
	fseek(origin, 0, SEEK_SET);
	long int key[10];
	long int skeyen[10];
	int enc_size;
	int keys[2][8];
	long int p1, q1, n1, e1, d1; // pra1, pua1
	long int p2, q2, n2, e2, d2; // prb2, pub2

	// ------------ 세션키1,2 생성, pua1,2, pub1,2 생성 ------------
	printf("\nGenerate First Public, Private\n");
	rsa(&p1, &q1, &n1, &e1, &d1);
	printf("\nGenerate Second Public, Private\n");
	rsa(&p2, &q2, &n2, &e2, &d2);
	printf("\nFirst RSA KEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p1, q1, n1, e1, d1);
	printf("\nSecond RSA KEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p2, q2, n2, e2, d2);
	printf("\nGenerate Session Key for DES (Random Generated)\n");
	gen_sdes_keys(key, keys);
	printf("\n");
	// ------------ 세션키1,2 생성, pua1,2, pub1,2 생성 ------------

	// ========================== 송신부 시작 ==========================
	
	// MD5 hash
	MDFile("Test.txt", size);
	fflush(stdin);

	// Hash read
	if ((hash = fopen("hash.txt", "rb")) == NULL)
		printf("%s can't be opened\n", "hash.txt");
	fseek(hash, 0, SEEK_END);
	int hash_size = ftell(hash);
	fseek(hash, 0, SEEK_SET);
	char *msg = malloc(sizeof(char)*hash_size);
	long int *m = malloc(sizeof(long int)*(hash_size));
	long int *en = malloc(sizeof(long int)*(hash_size));
	fread(msg, 1, hash_size, hash);
	fclose(hash);
	for (int i = 0; i < hash_size; i++)
	{
		m[i] = msg[i];
	}

	// Hash -> MAC
	printf("================================== PGP 시나리오 시작 ==================================");
	encrypt(n1, d1, hash_size, m, en);
	printf("\nHash -> MAC 생성 완료\n");

	// Attach MAC at origin text
	if ((sum_mac = fopen("Sending_MAC&origin.txt", "wb")) == NULL)
		printf("%s can't be opend\n", "Sending_MAC&origin.txt");
	else
	{
		char *buffer = malloc(sizeof(char)*size);
		fread(buffer, 1, size, origin);
		fwrite(en, 4, hash_size, sum_mac);
		fwrite(buffer, 1, size, sum_mac);
		printf("\n\"test.txt\" + MAC 결과 \"Sending_MAC&origin.txt\" 파일 생성 완료\n");
	}
	fclose(origin);
	fclose(sum_mac);

	// Byte 단위 encryption Session key 사용한 sdes
	int pt[8] = { 0 };
	int ct[8] = { 0 };
	if ((sum_mac = fopen("Sending_MAC&origin.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "Sending_MAC&origin.txt");
	else
	{
		sum_enc = fopen("Encrypted.txt", "wb");
		int bf;
		while (EOF != (bf = fgetc(sum_mac)))
		{
			for (int i = 7; i >= 0; i--)
			{
				pt[i] = bf % 2;
				bf = bf / 2;
			}
			en_de(pt, 0, keys, ct);
			int output = 0;
			for (int i = 7; i >= 0; i--)
			{
				if (ct[i] == 1)
					output += pow(2, (double)(7 - i));
			}
			char ch[1] = { output };
			fwrite(ch, 1, 1, sum_enc);
		}
		fclose(sum_enc);
		fclose(sum_mac);
		printf("\nByte 단위 암호화 결과 \"Encrypted.txt\" 생성 완료\n");
	}

	// Session key encryption
	encrypt(n2, e2, 10, key, skeyen);
	printf("\n10 Byte Session Key 암호화 완료\n");

	// Attach session key
	if ((sum_enc = fopen("Encrypted.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "Encrypted.txt");
	else {
		fseek(sum_enc, 0, SEEK_END);
		enc_size = ftell(sum_enc);
		fseek(sum_enc, 0, SEEK_SET);
		char *buffer = malloc(sizeof(char)*enc_size);
		fread(buffer, 1, enc_size, sum_enc);
		Etxt = fopen("EText.txt", "wb");
		char *buffer2 = malloc(sizeof(char) * 10);
		for (int i = 0; i < 10; i++)
			buffer2[i] = skeyen[i];
		fwrite(buffer2, 1, 10, Etxt);
		fwrite(buffer, 1, enc_size, Etxt);
		fclose(sum_enc);
		fclose(Etxt);
		printf("\n\"Encrypted.txt\" + 암호화된 Session Key 결과 \"Etext,txt\" 생성 완료\n");
	}
	printf("\n송신부 종료!!\n");
	// ========================== 송신부 종료 ==========================

	// ========================== 수신부 시작 ==========================
	printf("\n수신부 시작!!\n");
	// Detach session key
	if ((Etxt = fopen("Etext.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "Etext.txt");
	else {
		char *buffer = malloc(sizeof(char) * 10);
		fread(buffer, 1, 10, Etxt);
		for (int i = 0; i < 10; i++)
			skeyen[i] = buffer[i];
		char *buffer2 = malloc(sizeof(char)*enc_size);
		fread(buffer2, 1, enc_size, Etxt);
		sum_dec = fopen("En(Origin&MAC).txt", "wb");
		fwrite(buffer2, 1, enc_size, sum_dec);
		fclose(sum_dec);
		printf("\n\"Etext.txt\" 에서 암호화된 Session Key 부분 분리 후 \"En(Origin&MAC),txt\" 생성 완료\n");
	}

	// Session key decryption
	decrypt(n2, d2, 10, key, skeyen);
	printf("\n10 Byte Session Key 복호화 완료\n");

	// Total Decryption
	if ((sum_dec = fopen("En(Origin&MAC).txt", "rb")) == NULL)
		printf("%s can't be opend\n", "En(Origin&MAC).txt");
	else
	{
		sum_mac2 = fopen("Receiving_MAC&origin.txt", "wb");
		int bf;
		while (EOF != (bf = fgetc(sum_dec)))
		{
			for (int i = 7; i >= 0; i--)
			{
				ct[i] = bf % 2;
				bf = bf / 2;
			}
			en_de(ct, 1, keys, pt);
			int output = 0;
			for (int i = 7; i >= 0; i--)
			{
				if (pt[i] == 1)
					output += pow(2, (double)(7 - i));
			}
			char ch[1] = { output };
			fwrite(ch, 1, 1, sum_mac2);
		}
		fclose(sum_dec);
		fclose(sum_mac2);
		printf("\nByte 단위 복호화 결과 \"Receiving_MAC&origin.txt\" 생성 완료\n");
	}
	// Detach MAC from file
	if ((sum_mac2 = fopen("Receiving_MAC&origin.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "Receiving_MAC&origin.txt");
	else {
		char compare_string1[33], *string_pointer1;
		char compare_string2[33], *string_pointer2;
		string_pointer1 = &compare_string1[0];
		string_pointer2 = &compare_string2[0];

		long int *buffer = malloc(sizeof(long int)*(hash_size));
		fread(buffer, 4, hash_size, sum_mac2);
		printf("\n\"Receiving_MAC&origin.txt\" 에서 MAC분리 완료\n");
		decrypt(n1, e1, hash_size, m, buffer);
		printf("\nCompare MAC Decrtyption Result to Message Hash Result");
		printf("\nMAC Decryption Result (hash) : ");
		for (int i = 0; i < hash_size; i++)
		{
			string_pointer1 += sprintf(string_pointer1, "%c", m[i]);
			printf("%c", m[i]);
		}
		int temp = ftell(sum_mac2);
		fseek(sum_mac2, 0, SEEK_END);
		int read_size = ftell(sum_mac2) - temp;
		fseek(sum_mac2, temp, SEEK_SET);
		char *buffer2 = (char*)malloc(sizeof(char) * read_size);
		fread(buffer2, 1, read_size, sum_mac2);

		printf("\nMessage Hash Result : ");
		unsigned char digest[16];
		MDString(buffer2, read_size, digest);
		for (int i = 0; i < 16; i++)
		{
			string_pointer2 += sprintf(string_pointer2, "%02x", digest[i]);
		}
		int check = 1;
		for (int i = 0; i < 33; i++)
		{
			if (compare_string1[i] != compare_string2[i])
				check = 0;
		}

		if (check)
		{
			printf("\n비교 결과 정상 \"Dtext.txt\"를 생성합니다.\n");
			Dtxt = fopen("DText.txt", "wb");
			fwrite(buffer2, 1, size, Dtxt);
			fclose(Dtxt);
		}
		else
		{
			printf("\nError : 메세지 위-변조 발생 의심\n");
		}
		fclose(sum_mac2);
		printf("================================== PGP 시나리오 종료 ==================================\n");
	}
	system("pause");
	return;
}

// ================================================================================
/*
	Digests a file and prints the result.
 */
static void MDFile(filename, size)
char *filename;
int size;
{
	FILE *org; // input file
	FILE *hash; // output file
	MD5_CTX context;
	char *temp = (char*)malloc(sizeof(char)*size);
	unsigned char digest[16];
	hash = fopen("hash.txt", "wb");
	if ((org = fopen(filename, "rb")) == NULL)
		printf("%s can't be opened\n", filename);
	else
	{
		MDInit(&context);
		//		while (len = fread(buffer, 1, 1000, org))
		fread(temp, 1, size, org);
		MDUpdate(&context, temp, size);
		MDFinal(digest, &context);
		for (int i = 0; i < 16; i++)
			fprintf(hash, "%02x", digest[i]);
		fclose(org);
		fclose(hash);
		printf("\nMD%d (%s) = ", MD, filename);
		MDPrint(digest);
		printf("\n");
		free(temp);
	}
}

/* Digests a string and prints the result.
 */
static void MDString(string, size, temp)
char *string;
int size;
char temp[];
{
	MD5_CTX context;
	unsigned char digest[16];
	MDInit(&context);
	MDUpdate(&context, string, size);
	MDFinal(digest, &context);
	MDPrint(digest);
	memcpy(temp, digest, sizeof(digest));
	printf("\n");
}

static void MDPrint(digest)
unsigned char digest[16];
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		printf("%02x", digest[i]);
}

void rsa(long int *p, long int *q, long int *n, long int *e, long int *d)
{
	long int t, flag;

	do {
		printf("\nENTER FIRST PRIME NUMBER (Number must be bigger than 10)\n");
		scanf("%ld", p);
	} while (*p < 10);
	flag = prime(*p);

	if (flag == 0)
	{
		printf("\nWRONG INPUT\n");
		getch();
		exit(1);
	}

	do {
		printf("\nENTER ANOTHER PRIME NUMBER (Number must be bigger than 10)\n");
		scanf("%ld", q);
	} while (*q < 10);

	flag = prime(*q);
	if (flag == 0 || *p == *q)
	{
		printf("\nWRONG INPUT\n");
		getch();
		exit(1);
	}
	*n = (*p) * (*q);
	t = (*p - 1)*(*q - 1);
	ce(t, e, d, *p, *q);
}

void gen_sdes_keys(int key[], int keys[][8])
{
	srand(time(NULL));
	int i, keyip[10];
	int p10[] = { 3,5,2,7,4,10,1,9,8,6 }, p8[] = { 6,3,7,4,8,5,10,9 };
	for (i = 0; i < 10; i++)
		key[i] = rand() % 2;
	for (i = 0; i < 10; i++) // permutation p10
		keyip[i] = key[p10[i] - 1];
	left_shift(keyip, 1);	 // left shifting (array,no of bts)
	printf("\nkey1 :");
	for (i = 0; i < 8; i++) { 			//permuting p8 on key1
		keys[0][i] = keyip[p8[i] - 1];// key1 generated!!
		printf("%d", keys[0][i]);
	}
	left_shift(keyip, 2);// generating key2 . .
	printf("\nkey2 :");
	for (i = 0; i < 8; i++) {
		keys[1][i] = keyip[p8[i] - 1];// key2 generated!!
		printf("%d", keys[1][i]);
	}
}