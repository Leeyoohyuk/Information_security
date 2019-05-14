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
	int j=sqrt(pr); 
	for(i=2;i<=j;i++) 
	{ 
		if(pr%i==0) 
		return 0; 
	}
	return 1; 
} 
void ce(long int t, long int *e, long int *d, long int p, long int q)
{
	int flag;
	for(int i=2;i<t;i++) 
	{ 
		if(t%i==0) 
			continue;
		flag=prime(i); 
		if(flag==1&&i!=p&&i!=q) 
		{ 
			*e=i;
			flag=cd(*e, t); 
			if(flag>0)
			{
				*d=flag;
				break;
			} 
		} 
	}
}
long int cd(long int x, long int t)
{ 
	long int k=1; 
	while(1) 
	{ 
		k=k+t; 
		if(k%x==0) 
			return(k/x); 
	} 
}

void encrypt(long int n, long int key, int size, int m[], int en[])
{
	long int pt,ct,k,len; 
	int i=0; 
	len=size; 
	while(i!=len) 
	{ 
		pt=m[i]-96; 
		k=1; 
		for(int j=0;j<key;j++) 
		{ 
			k=k*pt; 
			k=k%n; 
		} 
		ct=k+96; 
		en[i]=ct; 
		i++;
	} 
	en[i]=-1;
	printf("\nTHE ENCRYPTED MESSAGE IS\n"); 
	for(i=0;en[i]!=-1;i++) 
		printf("%c",en[i]);
} 
void decrypt(long int n, long int key, int m[], int en[])
{ 
	long int pt,ct,k; 
	int i=0;
	while(en[i]!=-1)
	{ 
		ct=en[i]-96;
		k=1; 
		for(int j=0;j<key;j++) 
		{ 
			k=k*ct; 
			k=k%n; 
		} 
		pt=k+96;
		m[i]=pt;
		i++;
	}
	m[i]=-1; 
	printf("\nTHE DECRYPTED MESSAGE IS\n"); 
	for(i=0;m[i]!=-1;i++) 
		printf("%c",m[i]);
}