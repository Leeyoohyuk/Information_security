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
static void MDPrint PROTO_LIST((unsigned char[16]));
void rsa(long int *p, long int *q, long int *n, long int *e, long int *d);
void gen_sdes_keys(int key[], int keys[][8]);

void main()
{
	FILE *origin = fopen("test.txt", "rb"); // origin file
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

	// ------------ 技记虐1,2 积己, pua1,2, pub1,2 积己 -----------
	printf("\nGenerate First Public, Private\n");
	rsa(&p1, &q1, &n1, &e1, &d1);
	printf("\nGenerate Second Public, Private\n");
	rsa(&p2, &q2, &n2, &e2, &d2);
	printf("\nFirst RSA KEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p1, q1, n1, e1, d1);
	printf("\nSecond RSA KEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p2, q2, n2, e2, d2);
	printf("\nGenerate Session Key1, 2 for DES (Random Generated)\n");
	gen_sdes_keys(key, keys);
	printf("\n");
	// ------------ 技记虐1,2 积己, pua1,2, pub1,2 积己 -----------

	// ========================== 价脚何 矫累 ==========================
	
	// MD5 hash
	MDFile("test.txt", size);
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
	encrypt(n1, d1, hash_size, m, en);

	// Attach MAC at origin text
	if ((sum_mac = fopen("Sending_MAC&origin.txt", "wb")) == NULL)
		printf("%s can't be opend\n", "Sending_MAC&origin.txt");
	else
	{
		char *buffer = malloc(sizeof(char)*size);
		fread(buffer, 1, size, origin);
		fwrite(en, 4, hash_size, sum_mac);
		fwrite(buffer, 1, size, sum_mac);
	}
	fclose(origin);
	fclose(sum_mac);

	// Byte 窜困 encryption Session key 荤侩茄 sdes
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
	}

	// Session key encryption
	encrypt(n2, e2, 10, key, skeyen);

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
	}
	// ========================== 价脚何 辆丰 ==========================

	// ========================== 荐脚何 矫累 ==========================

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
	}

	// Session key decryption
	decrypt(n2, d2, 10, key, skeyen);

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
	}
	// Detach MAC from file
	int Dsize = 0;
	if ((sum_mac2 = fopen("Receiving_MAC&origin.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "Receiving_MAC&origin.txt");
	else {
		Dtxt = fopen("DText.txt", "wb");
		long int *buffer = malloc(sizeof(long int)*(hash_size));
		fread(buffer, 4, hash_size, sum_mac2);
		decrypt(n1, e1, hash_size, m, buffer);
		printf("\nMAC Decryption Result (hash) : ");
		for (int i = 0; i < hash_size; i++)
		{
			printf("%c", m[i]);
		}
		printf("\n");
		char *buffer2 = malloc(sizeof(char)*size);
		Dsize = fread(buffer2, 1, size, sum_mac2);
		fwrite(buffer2, 1, size, Dtxt);
		fclose(sum_mac2);
		fclose(Dtxt);
	}
	Dtxt = fopen("DText.txt", "rb");
	MDFile("Dtext.txt", size);

	return;
}

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
		int len = fread(temp, 1, size, org);
		MDUpdate(&context, temp, len);
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

	printf("\nENTER FIRST PRIME NUMBER\n");
	scanf("%d", p);
	flag = prime(*p);
	if (flag == 0)
	{
		printf("\nWRONG INPUT\n");
		getch();
		exit(1);
	}
	printf("\nENTER ANOTHER PRIME NUMBER\n");
	scanf("%d", q);
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