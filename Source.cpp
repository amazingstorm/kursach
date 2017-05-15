#include <iostream>
#include "Defender.hpp"
#include "aes.hpp"

unsigned key_length = 128;
static const byte plaintext[4][aes::block_size] =
   {  
		{0x6c, 0x65, 0x74, 0x6d, 0x65, 0x31, 0x6e, 0x53, 0x59, 0x53, 0x74, 0x65, 0x6d, 0x21},//"letme1nSYStem!"
		{0x45, 0x6e, 0x74, 0x65, 0x72, 0x3a, 0x20}, //"Enter: "
		{0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64, 0x21},//"Accepted!"
		{0x57, 0x72, 0x6f, 0x6e, 0x67, 0x21}//"Wrong!"
    };

static byte encrypted[4][aes::block_size] =
{
	{0x36,0xde,0xb,0x58,0x9a,0x59,0xe4,0x7a,0xb0,0x95,0x8f,0xcd,0xbc,0x36,0x5d,0x10},//letme1nSYStem!
	{0xc3,0x1a,0x27,0xea,0xd5,0x22,0x88,0x80,0x38,0x36,0x65,0xb0,0x4e,0xd9,0x7,0xc8,},//Enter:
	{0x23,0x36,0xc6,0x27,0x3f,0xba,0x62,0x9a,0xa8,0x89,0x46,0xe0,0x64,0x92,0xc4,0x12},//Accepted!
	{0x68,0x73,0x92,0x92,0x4b,0xe1,0x1a,0xbb,0xe6,0x9a,0x32,0x6e,0x82,0x85,0x52,0x15} //Wrong!
};
 
   // Для "коротких" ключей используется начальная часть всего ключа.
static const byte key[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    // 192 бит
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    // 256 бит
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const byte ciphertext[3][aes::block_size] =
{
    //  для ключа 128 бит
    {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
     0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
    //  для ключа 192 бит
    {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
     0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91},
    //  для ключа 256 бит
    {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
     0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89}
};
 
aes     crypto;
byte    buf[crypto.block_size];

unsigned int CheckSum (int size, char* buf)
{
	unsigned int result = 0;
	for(int i = 0;i<size;i++)
	{
		result +=buf[i]&0xff;
	}
	return result;
}
bool SplitChecker( char* input, char* image, const byte** begin = 0, const byte** end = 0)
{
    if(begin && end)
    {
        __asm
        {
            mov eax, dword ptr [begin]  
            lea edx, _begin
            mov dword ptr [eax], edx          
            mov eax, dword ptr [end]  
            lea edx, _end
            mov dword ptr [eax], edx          
        }
        return;
    }
	char inp1[10], inp2[10], img1[10], img2[10];
	memcpy(inp1,input,7);//copy first 7 bytes
	memcpy(inp2,input+7,7);//copy second 7 bytes
	memcpy(img1,image,7);//copy first 7 bytes
	memcpy(img2,image+7,7);//copy second 7 bytes
	Int2DCheck();
	_begin:
	if(!memcmp(inp1,img1,7) && !memcmp(inp2,img2,7))//if equal
		return false;
	else return true;
	_end:;
}
int Check1 (int* first, int* second)
{
	int sum = rand();
	*first = sum;
	dbg5();
	*second = sum - 1000;
	return 1337;
}
char* right (char * input)
{
	int i = 2;
	//dbg3();
	crypto.decrypt(encrypted[0], buf);
	while (i < 100)
	{
		i--;
		i = i+2;
	}
	return (char*)buf;
}
void correct (char* input)
{
	dbg4();
	right(input);
}
void main()
{ 	
	const byte * begin;
	const byte * end;
	unsigned int sum = 0;
	SplitChecker(0,0,&begin,&end);
	/*check*/
	sum = CheckSum(48, (char *)begin);
	if (6469 != sum)
		exit(0);
	dbg();
	if( crypto.expand_key(key, key_length) != crypto.Ok )
	{
			return;
	}
	char * image = NULL;
	char input[20];
	int imgcheck, inputcheck; 
	int a;
	bool (*f)(char*,char*,const byte**, const byte**);
	f = SplitChecker;
	crypto.decrypt(encrypted[1], buf);
	printf("%s", buf);
	gets_s(input,20);
	/*check*/
	a = Check1 (&imgcheck, &inputcheck);
	if(imgcheck == inputcheck +1000)
	{
		image = right(input);
		//a = SplitChecker(image, input);
		/* Вызов SplitCheker по указателю*/
		a = f(image,input,0,0);
	}
	else if (imgcheck == rand()%357)
	{
		correct(input);
	}
	dbg1();
	if(a)
	{
		/* jz-jnz call*/
		if(1)
		{
			crypto.decrypt(encrypted[3], buf);
			printf("%s", buf);

		}
		else
		{
			crypto.decrypt(encrypted[3], buf);
			printf("%s", buf);
		}
		/* jz-jnz call*/

	}
		else{ 
			
			if(1)
			{
				crypto.decrypt(encrypted[2], buf);
				printf("%s", buf);
			}
			else
			{
				crypto.decrypt(encrypted[2], buf);
				printf("%s", buf);
			}

	}

}


	