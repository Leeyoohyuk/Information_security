#include<stdio.h> 
#include<conio.h> 
#include<stdlib.h> 
#include<math.h>
#include<Windows.h>
#include<string.h> 
#include"rsa.h"

int prime(long int pr)
{
	int i;
	int j = sqrt(pr);
	for (i = 2; i <= j; i++)
	{
		if (pr%i == 0)
			return 0;
	}
	return 1;
}
void ce(long int t, long int *e, long int *d, long int p, long int q)
{
	int flag;
	for (int i = 2; i < t; i++)
	{
		if (t%i == 0)
			continue;
		flag = prime(i);
		if (flag == 1 && i != p && i != q)
		{
			*e = i;
			flag = cd(*e, t);
			if (flag > 0)
			{
				*d = flag;
				break;
			}
		}
	}
}
long int cd(long int x, long int t)
{
	long int k = 1;
	while (1)
	{
		k = k + t;
		if (k%x == 0)
			return(k / x);
	}
}

void encrypt(long int n, long int key, int size, long int m[], long int en[])
{
	long int pt, ct;
	long long k;
	int i = 0;
	while (i != size)
	{
		pt = m[i] - 96;
		k = 1;
		for (int j = 0; j < key; j++)
		{
			k = k * pt;
			k = k % n;
		}
		ct = k + 96;
		en[i] = ct;
		i++;
	}
}
void decrypt(long int n, long int key, int size, long int m[], long int en[])
{
	long int pt, ct;
	long long k;
	int i = 0;
	while (i != size)
	{
		ct = en[i] - 96;
		k = 1;
		for (int j = 0; j < key; j++)
		{
			k = k * ct;
			k = k % n;
		}
		pt = k + 96;
		m[i] = pt;
		i++;
	}
}