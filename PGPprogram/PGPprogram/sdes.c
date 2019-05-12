//**************************************
// name: simplified des (sdes) [encryption &amp; decryption]
// description:to encrypt &amp; decrypt binary information
//
//
//
// inputs:binary input 8- bits
//ex: 1 0 0 0 1 0 1 1
//10 bit binary key
//ex: 0 0 0 0 0 1 1 0 1 1
//
// returns:none
//
//assumes:none
//
//side effects:none
//for details.
//**************************************

#include <stdio.h>
int l[4], r[4], tempct[8];
void sbox(int sip[],int p[],int sbno,int i)
{
	int sbox[2][4][4]={1,0,3,2,3,2,1,0,0,2,1,3,3,1,3,2,0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3};
	int rw,c,sop;
	rw = sip[3]+sip[0]*2;
	c = sip[2]+sip[1]*2;
	sop = sbox[sbno][rw][c]; //sop gives decimal value of s-box output
	for(;sop!=0;sop/=2)
		p[i--]=sop%2;
}

void cmp_fun(int round, int keys[][8])
{
	int ep[]={4,1,2,3,2,3,4,1},i,epd[8];
	int slip[4],srip[4];
	int p[4]={0},p4[]={2,4,3,1},np[4];
	for(i=0;i<8;i++) // e/p permutation
		epd[i]=r[ep[i]-1];
	for(i=0;i<8;i++)//performing xor with key
		if(i<4)
    		slip[i] = epd[i]^keys[round][i]; // using key _ 1=>0
		else
    		srip[i-4] = epd[i]^keys[round][i];
	sbox(slip,p,0,1);//calling sbox 1, 0->sbox 1
	sbox(srip,p,1,3);//calling sbox 1, 1->sbox 2
	for(i=0;i<4;i++) //p4 permutation
		np[i]=p[p4[i]-1];
	for(i=0;i<4;i++)
		l[i] = l[i]^np[i];
}

void left_shift(int keyip[],int nob)
{
	int t1,t2,i;
	while(nob>0)
	{
		t1=keyip[0],t2=keyip[5];
		for(i=0;i<9;i++)
			if(i<4)
        		keyip[i] =keyip[i+1];
			else if(i>4)
        		keyip[i] = keyip[i+1];
		keyip[4]=t1,keyip[9]=t2;
		nob--;
	}
}


void en_de(int pt[],int c, int keys[][8])
{
	int ip[]={2,6,3,1,4,8,5,7},ipi[]={4,1,3,5,7,2,8,6},t[8],i;
	for(i=0;i<8;i++)// performing permutation on input bits!!
		if(i<4)
			l[i]=pt[ip[i]-1];
		else
			r[i-4] = pt[ip[i]-1];
	cmp_fun(c, keys);//round 0+1 using key 0+1
	for(i=0;i<4;i++) //swapping left & right
		r[i]=l[i]+r[i],l[i]=r[i]-l[i],r[i]=r[i]-l[i];
	printf("\n\n");
	cmp_fun(!c, keys); // round 1+1 wid key1+1 wid swapped bits
	for(i=0;i<8;i++)
		if(i<4)	t[i]=l[i];
		else	t[i]=r[i-4];
	for(i=0;i<8;i++)
		tempct[i] = t[ipi[i]-1];
}