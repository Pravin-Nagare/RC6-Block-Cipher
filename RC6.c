#include <stdio.h>
#include<string.h>
   
#define w 32    /* word of 32 bits */
#define r 20    /* 20 rounds */
#define P32 0xB7E15163  
#define Q32 0x9E3779B9
#define bytes   4             /* word size*/
#define c       (b/4)   
#define lgw     5                           /* log2(w) and w is 32*/
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
 
unsigned int S[44], ct[33], pt[33];

typedef union input
{
        unsigned int integer;
        unsigned char byte[sizeof(unsigned int)];
}input;      
 
void rc6_key(unsigned char *K, int b)          //Function to generate key with 20 rounds
{
    int i, j, s, v;
    unsigned int L[c-1]; 
    unsigned int A, B;
 
    L[c - 1] = 0;
    for (i = b - 1; i >= 0; i--)
        L[i / bytes] = (L[i / bytes] << 8) + K[i];

    S[0] = P32;
    for (i = 1; i <= 2 * r + 3; i++)
        S[i] = S[i - 1] + Q32;
 
    A = B = i = j = 0;
    v = 44;
    if (c > v) 
	v = c;
    v *= 3;
 
    for (s = 1; s <= v; s++)
    {
        A = S[i] = ROTL(S[i] + A + B, 3);
        B = L[j] = ROTL(L[j] + A + B, A + B);
        i = (i + 1) % 44;
        j = (j + 1) % c;
    }
}

void output(unsigned int *txt, char op)                    // Output print in output.txt file
{
	input in;
        int i=0, j, start, end, temp;
	FILE *fp=fopen("output.txt","w+");
	char str[3];
 	if(op=='E')
  		fprintf(fp,"%s","ciphertext: ");
	else
  		fprintf(fp,"%s","plaintext: ");
	for(j=0;j<4;j++){
        in.integer=txt[j];
        for(i=0;i<sizeof(unsigned int)/2;i++)
        {
                start = i;
                end = (sizeof(unsigned int) - i - 1);
                temp = in.byte[start];
                in.byte[start] = in.byte[end];
                in.byte[end] = temp;
        }
        for(i=3;i>=0;i--)
                fprintf(fp,"%02x ",in.byte[i]);
	}
}
 
void rc6_encrypt(unsigned int *pt)              // Function to encrypt plain text
{
    unsigned int A, B, C, D, t, u, x,m;
    int i, j, b=16,k=0;
    char op='E';
    A = pt[0];
    B = pt[1];
    C = pt[2];
    D = pt[3];
    B += S[0];
    D += S[1];
    for (i = 2; i <= 2 * r; i += 2)
    {
        t = ROTL(B * (2 * B + 1), lgw);
        u = ROTL(D * (2 * D + 1), lgw);
        A = ROTL(A ^ t, u) + S[i];
        C = ROTL(C ^ u, t) + S[i + 1];
        x = A;
        A = B;
        B = C;
        C = D;
        D = x;
    }
    A += S[2 * r + 2];
    C += S[2 * r + 3];
    ct[0] = A;
    ct[1] = B;
    ct[2] = C;
    ct[3] = D;
    output(ct,op);
}

 
void rc6_decrypt(unsigned int *ct)               // Function to decrypt ciphertext
{
    unsigned int A, B, C, D, t, u, x;
    int i, j;
    char op='D';
    A = ct[0];
    B = ct[1];
    C = ct[2];
    D = ct[3];
    C -= S[2 * r + 3];
    A -= S[2 * r + 2];
    for (i = 2 * r; i >= 2; i -= 2)
    {
        x = D;
        D = C;
        C = B;
        B = A;
        A = x;
        u = ROTL(D * (2 * D + 1), lgw);
        t = ROTL(B * (2 * B + 1), lgw);
        C = ROTR(C - S[i + 1], t) ^ u;
        A = ROTR(A - S[i], u) ^ t;
    }
    D -= S[1];
    B -= S[0];
    pt[0] = A;
    pt[1] = B;
    pt[2] = C;
    pt[3] = D;  
    output(pt,op);
}
 
int main()                          //Driving function
{
	char type[20],tmp[20];
    	unsigned int pt1[32],k;
    	int keylen,i;
	unsigned char key[64],d1;
	FILE *fp=fopen("input.txt","r");
        fscanf(fp,"%s",type);
        fscanf(fp,"%s",tmp);
 	for(i=0;i<16;i++)
	{
	         fscanf(fp,"%x",&k);
		 pt[i]=k;
        }
         fscanf(fp,"%s",tmp);
                      
         i=0;      
         for(i=0;!feof(fp);i++)
         {
                 fscanf(fp,"%x",&k);
                 key[i]=k;
         }
	 keylen=i-1;
	 rc6_key(key, keylen);
	 pt1[3]=0;
 	 int b=16;
	 for(i=b-1;i>=0;i--)
	 {
		pt1[i/bytes]=(pt1[i/bytes]<<8)+pt[i];
 	 }
	if(strstr(type,"Encryption"))
		rc6_encrypt(pt1);
	else
		rc6_decrypt(pt1);
        return 0;
}
