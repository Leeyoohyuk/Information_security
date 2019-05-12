#include "md5.h"
#include "rsa.h"
#include "sdes.h"
#include <stdio.h>
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
	char msg[1000]; // 메세지
	long int m[1000], en[1000]; // int 형 메세지, 암호화 메세지
	// --------------------------------------------------------------
	int keys[2][8];
	long int p1, q1, n1, e1, d1; // pra1, pua1
	long int p2, q2, n2, e2, d2; // prb2, pub2
	// ------------ 세션키1,2 생성, pua1,2, pub1,2 생성, 해싱 -------
	printf("\nGenerate First Public, Private");
	rsa(&p1, &q1, &n1, &e1, &d1);
	//printf("\nGenerate Second Public, Private");
	//rsa(&p2, &q2, &n2, &e2, &d2);
	//printf("\nKEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p1, q1, n1, e1, d1);
	//printf("\nKEY P: %ld Q: %ld N: %ld E: %ld D: %ld\n", p2, q2, n2, e2, d2);
	//printf("\nGenerate Session key1,2 for DES\n");
	//gen_sdes_keys(keys);
	//printf("\n");
	// --------------------------------------------------------------
	MDFile("test.txt");
	fflush(stdin);
	FILE *hash; // hash file
	FILE *org; // origin file
	FILE *sum; // origin + hash mac file
	if ((hash = fopen("hash.txt", "rb")) == NULL)
		printf("%s can't be opened\n", "hash.txt");
	else
	{
		fgets(msg, sizeof(msg), hash);
	}
	fclose(hash);
	for (int i = 0; msg[i] != NULL; i++)
	{
		m[i] = msg[i];
	}
	encrypt(n1, d1, msg, m, en); // 해시 -> mac
	if ((org = fopen("test.txt", "rb")) == NULL)
		printf("%s can't be opend\n", "test.txt");
	else
	{
		char buffer[1000];
		fgets(buffer, sizeof(buffer), org);
		if ((sum = fopen("orgNmac.txt", "w")) == NULL)
			printf("%s can't be opend\n", "orgNmac.txt");
		else
		{
			char buffer2[1000];
			for (int i = 0; i < strlen(msg); i++)
				buffer2[i] = en[i];
			buffer2[strlen(msg)] = '\n';
			fwrite(buffer2, 1, strlen(msg)+1, sum);
			fputs(buffer, sum);
		}
	}
	fclose(org);
	fclose(sum);

	////encrypting - - - 
	//int pt[8] = { 0 };
	//int ct[8] = { 0 };
	//printf("enter plain text binary bits:");// 1바이트씩 읽어옴
	//for (int i = 0; i < 8; i++)
	//	scanf("%d", &pt[i]);
	//en_de(pt, 0, keys);
	//printf("\ncipher text :");
	//for (int i = 0; i < 8; i++)
	//	printf("%d", ct[i]);
	////decrypting - - -
	//en_de(ct, 1, keys);
	//printf("\nplain text (after decrypting):");
	//for (int i = 0; i < 8; i++)
	//	printf("%d", ct[i]);

	//decrypt(n1, e1, m, en); // mac -> 해시

	return;
}

/* 
	Digests a file and prints the result.
 */
static void MDFile(filename)
char *filename;
{
	FILE *org; // input file
	FILE *hash; // output file

	MD5_CTX context;
	int len;
	unsigned char buffer[1024], digest[16];

	hash = fopen("hash.txt", "w");
	if ((org = fopen(filename, "rb")) == NULL)
		printf("%s can't be opened\n", filename);
	else
	{
		MDInit(&context);
		while (len = fread(buffer, 1, 1024, org))
			MDUpdate(&context, buffer, len);
		MDFinal(digest, &context);
		for (int i = 0; i<16; i++)
			fprintf(hash, "%02x", digest[i]);
		fclose(org);
		fclose(hash);
		printf("MD%d (%s) = ", MD, filename);
		MDPrint(digest);
		printf("\n");
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

void gen_sdes_keys(int keys[][8])
{
	int key[10], i, keyip[10];
	int p10[] = { 3,5,2,7,4,10,1,9,8,6 }, p8[] = { 6,3,7,4,8,5,10,9 };
	printf("\nEnter key 10 digit:");
	for (i = 0; i < 10; i++)
		scanf("%d", &key[i]);
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