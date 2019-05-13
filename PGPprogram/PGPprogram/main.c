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
void rsa();
void gen_sdes_keys(int keys[][8]);

void main()
{
	FILE *org = fopen("test.txt","rb"); // origin file
	FILE *hash; // hash file
	FILE *sum; // origin + hash mac file
	FILE *sum_enc; // origin + hash mac encryption
	FILE *Etxt;
	fseek(org, 0, SEEK_END);
	int size = ftell(org);
	fseek(org, 0, SEEK_SET);
	int key[10];
	int keys[2][8];
	long int p1, q1, n1, e1, d1; // pra1, pua1
	long int p2, q2, n2, e2, d2; // prb2, pub2
	 
	// ------------ 세션키1,2 생성, pua1,2, pub1,2 생성, 해싱 -------
	printf("\nGenerate First Public, Private");
	rsa(&p1, &q1, &n1, &e1, &d1);
	printf("\nGenerate Second Public, Private");
	rsa(&p2, &q2, &n2, &e2, &d2);
	//printf("\nKEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p1, q1, n1, e1, d1);
	//printf("\nKEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p2, q2, n2, e2, d2);
	// ------------ 세션키1,2 생성, pua1,2, pub1,2 생성, 해싱 -------
	printf("\nGenerate Session key1,2 for DES\n");
	gen_sdes_keys(key, keys);
	printf("\n");
	// MD5 hash
	MDFile("test.txt", size);
	fflush(stdin);
	// HASH read
	if ((hash = fopen("hash.txt", "rb")) == NULL)
		printf("%s can't be opened\n", "hash.txt");
	fseek(hash, 0, SEEK_END);
	int hash_size = ftell(hash);
	fseek(hash, 0, SEEK_SET);
	char *msg = malloc(sizeof(char)*hash_size);
	int *m = malloc(sizeof(int)*hash_size);
	int *en = malloc(sizeof(int)*(hash_size+1));
	fread(msg, 1, hash_size, hash);
	fclose(hash);
	for (int i = 0; i < hash_size; i++)
	{
		m[i] = msg[i];
	}
	// HASH -> MAC
	encrypt(n1, d1, hash_size, m, en);
	// Origin msg + MAC
	if ((org = fopen("test.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "test.txt");
	else
	{
		char *buffer = malloc(sizeof(char)*size);
		fread(buffer, 1, size, org);
		if ((sum = fopen("orgNmac.txt", "wb")) == NULL)
			printf("%s can't be opend\n", "orgNmac.txt");
		else
		{
			char *buffer2 = malloc(sizeof(char)*hash_size); 
			for (int i = 0; i < hash_size; i++)
				buffer2[i] = en[i];
			fwrite(buffer2, 1, hash_size, sum);
			fwrite(buffer, 1, size, sum);
		}
	}
	fclose(org);
	fclose(sum);
	// 전체 encrypting - - - byte 단위, 세션 키 사용한 sdes
	int pt[8] = { 0 };
	int ct[8] = { 0 };

	if ((sum = fopen("orgNmac.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "orgNmac.txt");
	else
	{
		sum_enc = fopen("orgNmacenc.txt", "wb");
		char bf;
		while (EOF != (bf = fgetc(sum)))
		{
			int input = bf;
			for (int i = 7; i >= 0; i--) {
				pt[i] = ( input & (1 << i)) != 0;
			}
			en_de(pt, 0, keys, ct); // 1 바이트 인코딩 sdes 사용
			int output = 0;
			for (int i = 7; i >= 0; i--)
			{
				if (ct[i] == 1)
					output += pow(2, (double)(7 - i));
			}
			char ch[1] = {output};
			fwrite(ch, 1, 1, sum_enc);
		}
		fclose(sum_enc);
	}
	// SESSION KEY ENCRYPTION
	int skeyen[11];
	encrypt(n2, e2, 10, key, skeyen);
	// SESSION KEY ATTATCH
	if ((sum_enc = fopen("orgNmacenc.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "orgNmac.txt");
	else {
		fseek(sum_enc, 0, SEEK_END);
		int enc_size = ftell(sum_enc);
		fseek(sum_enc, 0, SEEK_SET);
		char *buffer = malloc(sizeof(char)*enc_size);
		fread(buffer, 1, enc_size, sum_enc);
		Etxt = fopen("EText.txt", "wb");
		char *buffer2 = malloc(sizeof(char)*10);
		for (int i = 0; i < 10; i++)
			buffer2[i] = skeyen[i];
		fwrite(buffer2, 1, 10, Etxt);
		fwrite(buffer, 1, enc_size, Etxt);
		fclose(sum_enc);
		fclose(Etxt);
	}

	//decrypt(n1, e1, m, en); // mac -> 해시

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
	int len;
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
		for (int i = 0; i<16; i++)
			fprintf(hash, "%02x", digest[i]);
		fclose(org);
		fclose(hash);
		printf("MD%d (%s) = ", MD, filename);
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

/*
시나리오
rsa를 이용해 키를 생성해서 먼저 갖고 있음
세션키도 미리 갖고 있음
파일을 열고 md5이용해서 Hash값 생성
rsa pr a이용한 Hash -> mac 생성
org mes + mac 생성

compression 생략
// key main에서 받아오도록 설정해야함, key 양쪽 다 갖고있또록
rsa pu b이용한 
*/