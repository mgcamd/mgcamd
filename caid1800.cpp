#include "stdio.h"
#include <stdlib.h>
#include <string.h>
#include <iostream.h>

#include <mirdef.h>
#include <big.h>

#ifndef BYTE
  #define BYTE unsigned char
  #define INT int
  #define APIENTRY
#endif

// Global Variables

Miracl mir(150,16);
miracl* mip=&mir;

//Big E1,N1,E2,N2;	// EMM decrypt keys
//BYTE Verify[8];		// EMM verify key


unsigned char Nagra_SCODES[]={
	0xF7,0xE2,0x3C,0xBF,0x04,0x5B,0x9A,0xEC,0x9B,0x87,0x06,0x59,0xAD,0xF4,0xE0,0x0A,
    0x62,0x08,0x95,0x63,0x5F,0x36,0x49,0x95,0x38,0xD1,0x73,0xAE,0x91,0xAD,0x8E,0xF0,
    0x10,0x7F,0x55,0x1A,0xE7,0x92,0xF9,0x25,0x4E,0x11,0xC3,0xCC,0x3B,0xC8,0x2C,0x56,
    0xCF,0x93,0x66,0xDD,0xB4,0xE9,0x3A,0x70,0xA2,0x24,0xAD,0x37,0x48,0x1E,0xD1,0xAB,
    0x85,0xBB,0x88,0x4D,0x76,0x61,0x7D,0xDA,0xE9,0x42,0xB3,0x94,0x1F,0x8C,0x04,0x67,
    0xD0,0x66,0x4B,0xF8,0x2C,0xDF,0x12,0x35,0x07,0x39,0xEE,0x03,0xCA,0x40,0xB1,0xCE,
    0x7B,0xC8,0xF4,0x22,0xDC,0x06,0xA3,0x8D,0xB0,0xAB,0x2A,0x77,0x66,0x71,0x5F,0xB4,
    0x2E,0x55,0x11,0x8F,0x82,0xB9,0xCD,0x4A,0x59,0xF0,0xD7,0xEC,0xF5,0x2E,0x68,0x13,
    0xC4,0xB2,0x51,0x8F,0xBE,0xC5,0x2B,0x46,0x32,0x28,0x6C,0x33,0xDD,0x9E,0xD7,0xF0,
    0xF3,0x64,0xEA,0x59,0xC5,0x5B,0x90,0x2C,0x68,0x8D,0x0F,0x0A,0x06,0x31,0x69,0xC7,
    0x27,0xDD,0x2A,0xB6,0x52,0x08,0x4C,0x75,0x84,0x43,0xBF,0x60,0xEB,0xA4,0x81,0x9A,
    0x1D,0x01,0x90,0xEF,0x2E,0xB7,0xF9,0x12,0xD3,0x7E,0xC5,0x99,0x78,0x4B,0x16,0x6C,
    0xB2,0x18,0xFC,0xF5,0x1F,0xF3,0xCA,0x80,0x04,0xED,0x89,0xA6,0x61,0x2E,0x76,0x39,
    0x4D,0xF2,0x33,0xCF,0xF0,0x8C,0xA5,0x5A,0x97,0x5B,0xDE,0x71,0xAB,0xE7,0x08,0xA4,
    0xEB,0xA6,0x47,0x19,0x82,0x68,0x34,0xE7,0x5D,0x3B,0x7A,0xD0,0x38,0xD5,0xE1,0x0C,
    0x70,0xCD,0xAC,0x2A,0x49,0x12,0x5F,0xB4,0xAE,0x91,0x13,0x4F,0x95,0x7E,0xB6,0xD3
};
static BYTE Nagra_mirrorbits(BYTE b)
{
	int i;
	BYTE c=0;
	for(i=0;i<8;i++,b=b/2) c=2*c+b%2;
	return c;
}
static BYTE Nagra_BitOf7(const BYTE *b, int nb)
{
	return (b[6-(nb/8)]>>(nb%8))&1;
}
static void Nagra_PrepareKey(const BYTE *in_cardkey, BYTE *out_nagra_key)
{
	int i;
	for(i=0;i<8;i++)
		out_nagra_key[i]=2*Nagra_mirrorbits(in_cardkey[i]);
	// Compress Nagra_KEY
	out_nagra_key[0]|=out_nagra_key[1]>>7;
	out_nagra_key[1]<<=1;
	out_nagra_key[1]|=out_nagra_key[2]>>6;
	out_nagra_key[2]<<=2;
	out_nagra_key[2]|=out_nagra_key[3]>>5;
	out_nagra_key[3]<<=3;
	out_nagra_key[3]|=out_nagra_key[4]>>4;
	out_nagra_key[4]<<=4;
	out_nagra_key[4]|=out_nagra_key[5]>>3;
	out_nagra_key[5]<<=5;
	out_nagra_key[5]|=out_nagra_key[6]>>2;
	out_nagra_key[6]<<=6;
	out_nagra_key[6]|=out_nagra_key[7]>>1;
	out_nagra_key[7]=0;
}


static void Nagra_InitializeBuffer(BYTE *out_nagra_buffer)
{
	out_nagra_buffer[0]=0x0;  out_nagra_buffer[1]=0;
	out_nagra_buffer[2]=0x40; out_nagra_buffer[3]=0x01;
	out_nagra_buffer[4]=0x80; out_nagra_buffer[5]=0x02;
	out_nagra_buffer[6]=0xC0; out_nagra_buffer[7]=0x03;
	out_nagra_buffer[8]=0x0;
}
static void Nagra_PrepareKey2(const BYTE *in_nagra_key, BYTE *out_nagra_buffer)
{
	out_nagra_buffer[0]|=(Nagra_BitOf7(in_nagra_key,21)<<5)+(Nagra_BitOf7(in_nagra_key,49)<<4)+(Nagra_BitOf7(in_nagra_key,2)<<3) +(Nagra_BitOf7(in_nagra_key,36)<<2)+(Nagra_BitOf7(in_nagra_key,51)<<1)+Nagra_BitOf7(in_nagra_key,15);
	out_nagra_buffer[1]|=(Nagra_BitOf7(in_nagra_key,43)<<7)+(Nagra_BitOf7(in_nagra_key,23)<<6)+(Nagra_BitOf7(in_nagra_key,14)<<5)+(Nagra_BitOf7(in_nagra_key,8)<<4) +(Nagra_BitOf7(in_nagra_key,31)<<3)+(Nagra_BitOf7(in_nagra_key,35)<<2);
	out_nagra_buffer[2]|=(Nagra_BitOf7(in_nagra_key,0)<<5) +(Nagra_BitOf7(in_nagra_key,45)<<4)+(Nagra_BitOf7(in_nagra_key,28)<<3)+(Nagra_BitOf7(in_nagra_key,29)<<2)+(Nagra_BitOf7(in_nagra_key,37)<<1)+Nagra_BitOf7(in_nagra_key,9);
	out_nagra_buffer[3]|=(Nagra_BitOf7(in_nagra_key,42)<<7)+(Nagra_BitOf7(in_nagra_key,22)<<6)+(Nagra_BitOf7(in_nagra_key,30)<<5)+(Nagra_BitOf7(in_nagra_key,38)<<4)+(Nagra_BitOf7(in_nagra_key,7)<<3) +(Nagra_BitOf7(in_nagra_key,1)<<2);
	out_nagra_buffer[4]|=(Nagra_BitOf7(in_nagra_key,10)<<5)+(Nagra_BitOf7(in_nagra_key,39)<<4)+(Nagra_BitOf7(in_nagra_key,54)<<3)+(Nagra_BitOf7(in_nagra_key,41)<<2)+(Nagra_BitOf7(in_nagra_key,4)<<1) +Nagra_BitOf7(in_nagra_key,26);
	out_nagra_buffer[5]|=(Nagra_BitOf7(in_nagra_key,32)<<7)+(Nagra_BitOf7(in_nagra_key,27)<<6)+(Nagra_BitOf7(in_nagra_key,53)<<5)+(Nagra_BitOf7(in_nagra_key,11)<<4)+(Nagra_BitOf7(in_nagra_key,33)<<3)+(Nagra_BitOf7(in_nagra_key,48)<<2);
	out_nagra_buffer[6]|=(Nagra_BitOf7(in_nagra_key,24)<<5)+(Nagra_BitOf7(in_nagra_key,20)<<4)+(Nagra_BitOf7(in_nagra_key,3)<<3) +(Nagra_BitOf7(in_nagra_key,40)<<2)+(Nagra_BitOf7(in_nagra_key,25)<<1)+Nagra_BitOf7(in_nagra_key,5);
	out_nagra_buffer[7]|=(Nagra_BitOf7(in_nagra_key,34)<<7)+(Nagra_BitOf7(in_nagra_key,55)<<6)+(Nagra_BitOf7(in_nagra_key,6)<<5) +(Nagra_BitOf7(in_nagra_key,18)<<4)+(Nagra_BitOf7(in_nagra_key,19)<<3)+(Nagra_BitOf7(in_nagra_key,46)<<2);
	out_nagra_buffer[8]|=(Nagra_BitOf7(in_nagra_key,17)<<7)+(Nagra_BitOf7(in_nagra_key,12)<<6)+(Nagra_BitOf7(in_nagra_key,47)<<5)+(Nagra_BitOf7(in_nagra_key,13)<<4)+(Nagra_BitOf7(in_nagra_key,52)<<3)+(Nagra_BitOf7(in_nagra_key,16)<<2)+(Nagra_BitOf7(in_nagra_key,44)<<1)+Nagra_BitOf7(in_nagra_key,50);
}

static void Nagra_Permute_L(BYTE *b)
{
	int i;
	for(i=0;i<8;i++)
		b[i]=Nagra_mirrorbits(b[i]);
}
static void Nagra_Permute_R(const BYTE *in_nagra_key, BYTE *out_nagra_buffer)
{
	if(in_nagra_key[0]&1)
		out_nagra_buffer[7]|=(1<<6);
	if(in_nagra_key[0]&2)
		out_nagra_buffer[1]|=(1<<3);
	if(in_nagra_key[0]&4)
		out_nagra_buffer[2]|=(1<<5);
	if(in_nagra_key[0]&8)
		out_nagra_buffer[3]|=(1<<2);
	if(in_nagra_key[0]&16)
		out_nagra_buffer[0]|=(1<<3);
	if(in_nagra_key[0]&32)
		out_nagra_buffer[6]|=(1<<0);
	if(in_nagra_key[0]&64)
		out_nagra_buffer[7]|=(1<<5);
	if(in_nagra_key[0]&128)
		out_nagra_buffer[6]|=(1<<3);

	if(in_nagra_key[1]&1)
		out_nagra_buffer[8]|=(1<<5);
	if(in_nagra_key[1]&2)
		out_nagra_buffer[5]|=(1<<2);
	if(in_nagra_key[1]&4)
		out_nagra_buffer[0]|=(1<<4);
	if(in_nagra_key[1]&8)
		out_nagra_buffer[8]|=(1<<0);
	if(in_nagra_key[1]&16)
		out_nagra_buffer[0]|=(1<<1);
	if(in_nagra_key[1]&32)
		out_nagra_buffer[8]|=(1<<3);
	if(in_nagra_key[1]&64)
		out_nagra_buffer[5]|=(1<<5);
	if(in_nagra_key[1]&128)
		out_nagra_buffer[4]|=(1<<3);

	if(in_nagra_key[2]&1)
		out_nagra_buffer[4]|=(1<<4);
	if(in_nagra_key[2]&2)
		out_nagra_buffer[6]|=(1<<2);
	if(in_nagra_key[2]&4)
		out_nagra_buffer[4]|=(1<<2);
	if(in_nagra_key[2]&8)
		out_nagra_buffer[3]|=(1<<7);
	if(in_nagra_key[2]&16)
		out_nagra_buffer[1]|=(1<<7);
	if(in_nagra_key[2]&32)
		out_nagra_buffer[8]|=(1<<1);
	if(in_nagra_key[2]&64)
		out_nagra_buffer[2]|=(1<<4);
	if(in_nagra_key[2]&128)
		out_nagra_buffer[7]|=(1<<2);

	if(in_nagra_key[3]&1)
		out_nagra_buffer[4]|=(1<<1);
	if(in_nagra_key[3]&2)
		out_nagra_buffer[5]|=(1<<7);
	if(in_nagra_key[3]&4)
		out_nagra_buffer[5]|=(1<<3);
	if(in_nagra_key[3]&8)
		out_nagra_buffer[7]|=(1<<7);
	if(in_nagra_key[3]&16)
		out_nagra_buffer[1]|=(1<<2);
	if(in_nagra_key[3]&32)
		out_nagra_buffer[0]|=(1<<2);
	if(in_nagra_key[3]&64)
		out_nagra_buffer[2]|=(1<<1);
	if(in_nagra_key[3]&128)
		out_nagra_buffer[3]|=(1<<4);

	if(in_nagra_key[4]&1)
		out_nagra_buffer[1]|=(1<<6);
	if(in_nagra_key[4]&2)
		out_nagra_buffer[6]|=(1<<5);
	if(in_nagra_key[4]&4)
		out_nagra_buffer[6]|=(1<<1);
	if(in_nagra_key[4]&8)
		out_nagra_buffer[4]|=(1<<0);
	if(in_nagra_key[4]&16)
		out_nagra_buffer[5]|=(1<<6);
	if(in_nagra_key[4]&32)
		out_nagra_buffer[2]|=(1<<3);
	if(in_nagra_key[4]&64)
		out_nagra_buffer[2]|=(1<<2);
	if(in_nagra_key[4]&128)
		out_nagra_buffer[3]|=(1<<5);

	if(in_nagra_key[5]&1)
		out_nagra_buffer[0]|=(1<<0);
	if(in_nagra_key[5]&2)
		out_nagra_buffer[8]|=(1<<2);
	if(in_nagra_key[5]&4)
		out_nagra_buffer[8]|=(1<<7);
	if(in_nagra_key[5]&8)
		out_nagra_buffer[7]|=(1<<4);
	if(in_nagra_key[5]&16)
		out_nagra_buffer[7]|=(1<<3);
	if(in_nagra_key[5]&32)
		out_nagra_buffer[6]|=(1<<4);
	if(in_nagra_key[5]&64)
		out_nagra_buffer[0]|=(1<<5);
	if(in_nagra_key[5]&128)
		out_nagra_buffer[3]|=(1<<6);

	if(in_nagra_key[6]&1)
		out_nagra_buffer[3]|=(1<<3);
	if(in_nagra_key[6]&2)
		out_nagra_buffer[1]|=(1<<4);
	if(in_nagra_key[6]&4)
		out_nagra_buffer[2]|=(1<<0);
	if(in_nagra_key[6]&8)
		out_nagra_buffer[4]|=(1<<5);
	if(in_nagra_key[6]&16)
		out_nagra_buffer[5]|=(1<<4);
	if(in_nagra_key[6]&32)
		out_nagra_buffer[8]|=(1<<6);
	if(in_nagra_key[6]&64)
		out_nagra_buffer[8]|=(1<<4);
	if(in_nagra_key[6]&128)
		out_nagra_buffer[1]|=(1<<5);
}
static void Nagra_StripParity(const BYTE *in, BYTE *out)
{
	int i,b;
	for(i=0;i<8;i++)
	{
		out[i]=0;
		for(b=0;b<8;b++)
		{
			if( (in[b]>>(7-i))&1 )
				out[i]|=(1<<b);
		}
	}
}
static void Nagra_PrepareSBox(BYTE *parity, BYTE *data_buffer, BYTE *cmd4)
{
	BYTE TEMP;
	BYTE DATABYTE;
	cmd4[0]=0;
	cmd4[1]=0;
	cmd4[2]=0;
	cmd4[3]=0;

	// 0
	TEMP=(parity[7]*2)+(parity[1]>>7);
	DATABYTE=Nagra_SCODES[ (TEMP&0x3F)^data_buffer[0] ]; // SBox_R
	if(DATABYTE&1)
		cmd4[1]|=(1<<0);
	if(DATABYTE&2)
		cmd4[2]|=(1<<0);
	if(DATABYTE&4)
		cmd4[2]|=(1<<6);
	if(DATABYTE&8)
		cmd4[3]|=(1<<6);

	// 1
	TEMP=(parity[7]/2)+((parity[5]&1)<<7);
	DATABYTE=Nagra_SCODES[ (TEMP&0xFC)^data_buffer[1] ]; // SBox_L
	if(DATABYTE&16)
		cmd4[1]|=(1<<4);
	if(DATABYTE&32)
		cmd4[3]|=(1<<3);
	if(DATABYTE&64)
		cmd4[0]|=(1<<1);
	if(DATABYTE&128)
		cmd4[2]|=(1<<1);

	// 2
	TEMP=(parity[5]*2)+(parity[7]>>7);
	DATABYTE=Nagra_SCODES[ (TEMP&0x3F)^data_buffer[2] ]; // SBox_R
	if(DATABYTE&1)
		cmd4[2]|=(1<<7);
	if(DATABYTE&2)
		cmd4[1]|=(1<<7);
	if(DATABYTE&4)
		cmd4[3]|=(1<<5);
	if(DATABYTE&8)
		cmd4[0]|=(1<<5);

	// 3
	TEMP=(parity[5]/2)+((parity[3]&1)<<7);
	DATABYTE=Nagra_SCODES[ (TEMP&0xFC)^data_buffer[3] ]; // SBox_L
	if(DATABYTE&16)
		cmd4[3]|=(1<<1);
	if(DATABYTE&32)
		cmd4[2]|=(1<<3);
	if(DATABYTE&64)
		cmd4[1]|=(1<<1);
	if(DATABYTE&128)
		cmd4[0]|=(1<<0);

	// 4
	TEMP=(parity[3]*2)+(parity[5]>>7);
	DATABYTE=Nagra_SCODES[ (TEMP&0x3F)^data_buffer[4] ]; // SBox_R
	if(DATABYTE&1)
		cmd4[0]|=(1<<7);
	if(DATABYTE&2)
		cmd4[1]|=(1<<5);
	if(DATABYTE&4)
		cmd4[3]|=(1<<0);
	if(DATABYTE&8)
		cmd4[0]|=(1<<2);

	// 5
	TEMP=(parity[3]/2)+((parity[1]&1)<<7);
	DATABYTE=Nagra_SCODES[ (TEMP&0xFC)^data_buffer[5] ]; // SBox_L
	if(DATABYTE&16)
		cmd4[0]|=(1<<3);
	if(DATABYTE&32)
		cmd4[3]|=(1<<4);
	if(DATABYTE&64)
		cmd4[1]|=(1<<2);
	if(DATABYTE&128)
		cmd4[2]|=(1<<2);

	// 6
	TEMP=(parity[1]*2)+(parity[3]>>7);
	DATABYTE=Nagra_SCODES[ (TEMP&0x3F)^data_buffer[6] ]; // SBox_R
	if(DATABYTE&1)
		cmd4[3]|=(1<<7);
	if(DATABYTE&2)
		cmd4[1]|=(1<<3);
	if(DATABYTE&4)
		cmd4[2]|=(1<<5);
	if(DATABYTE&8)
		cmd4[0]|=(1<<6);

	// 7
	TEMP=(parity[1]/2)+((parity[7]&1)<<7);
	DATABYTE=Nagra_SCODES[ (TEMP&0xFC)^data_buffer[7] ]; // SBox_L
	if(DATABYTE&16)
		cmd4[0]|=(1<<4);
	if(DATABYTE&32)
		cmd4[3]|=(1<<2);
	if(DATABYTE&64)
		cmd4[1]|=(1<<6);
	if(DATABYTE&128)
		cmd4[2]|=(1<<4);

	//
	TEMP=parity[6];
	TEMP=TEMP^cmd4[0];
	parity[6]=parity[7];
	parity[7]=TEMP;


	TEMP=parity[4];
	TEMP=TEMP^cmd4[1];
	parity[4]=parity[5];
	parity[5]=TEMP;

	TEMP=parity[2];
	TEMP=TEMP^cmd4[2];
	parity[2]=parity[3];
	parity[3]=TEMP;

	TEMP=parity[0];
	TEMP=TEMP^cmd4[3];
	parity[0]=parity[1];
	parity[1]=TEMP;
}
// Nagra_DATA is FSR (Nagra_CMDBUFFER+0xD)
// Nagra_BUFFER is DATA_BUFFER
static void Nagra_CryptStep2(const BYTE *in_nagra_data, BYTE *out_nagra_buffer)
{
	if(in_nagra_data[0]&1)
		out_nagra_buffer[3]|=(1<<6);
	if(in_nagra_data[0]&2)
		out_nagra_buffer[3]|=(1<<2);
	if(in_nagra_data[0]&4)
		out_nagra_buffer[1]|=(1<<7);
	if(in_nagra_data[0]&8)
		out_nagra_buffer[2]|=(1<<0);
	if(in_nagra_data[0]&16)
		out_nagra_buffer[1]|=(1<<3);
	if(in_nagra_data[0]&32)
		out_nagra_buffer[2]|=(1<<3);

	if(in_nagra_data[1]&4)
		out_nagra_buffer[3]|=(1<<7);
	if(in_nagra_data[1]&8)
		out_nagra_buffer[3]|=(1<<4);
	if(in_nagra_data[1]&16)
		out_nagra_buffer[0]|=(1<<0);
	if(in_nagra_data[1]&32)
		out_nagra_buffer[0]|=(1<<5);
	if(in_nagra_data[1]&64)
		out_nagra_buffer[3]|=(1<<5);
	if(in_nagra_data[1]&128)
		out_nagra_buffer[8]|=(1<<0);

	if(in_nagra_data[2]&1)
		out_nagra_buffer[8]|=(1<<2);
	if(in_nagra_data[2]&2)
		out_nagra_buffer[8]|=(1<<1);
	if(in_nagra_data[2]&4)
		out_nagra_buffer[0]|=(1<<2);
	if(in_nagra_data[2]&8)
		out_nagra_buffer[1]|=(1<<2);
	if(in_nagra_data[2]&16)
		out_nagra_buffer[8]|=(1<<3);
	if(in_nagra_data[2]&32)
		out_nagra_buffer[3]|=(1<<3);

	if(in_nagra_data[3]&4)
		out_nagra_buffer[1]|=(1<<4);
	if(in_nagra_data[3]&8)
		out_nagra_buffer[1]|=(1<<5);
	if(in_nagra_data[3]&16)
		out_nagra_buffer[2]|=(1<<4);
	if(in_nagra_data[3]&32)
		out_nagra_buffer[2]|=(1<<1);
	if(in_nagra_data[3]&64)
		out_nagra_buffer[2]|=(1<<2);
	if(in_nagra_data[3]&128)
		out_nagra_buffer[0]|=(1<<4);

	if(in_nagra_data[4]&1)
		out_nagra_buffer[5]|=(1<<3);
	if(in_nagra_data[4]&2)
		out_nagra_buffer[5]|=(1<<4);
	if(in_nagra_data[4]&4)
		out_nagra_buffer[5]|=(1<<2);
	if(in_nagra_data[4]&8)
		out_nagra_buffer[7]|=(1<<5);
	if(in_nagra_data[4]&16)
		out_nagra_buffer[7]|=(1<<2);
	if(in_nagra_data[4]&32)
		out_nagra_buffer[8]|=(1<<7);

	if(in_nagra_data[5]&4)
		out_nagra_buffer[7]|=(1<<6);
	if(in_nagra_data[5]&8)
		out_nagra_buffer[6]|=(1<<2);
	if(in_nagra_data[5]&16)
		out_nagra_buffer[7]|=(1<<4);
	if(in_nagra_data[5]&32)
		out_nagra_buffer[6]|=(1<<0);
	if(in_nagra_data[5]&64)
		out_nagra_buffer[7]|=(1<<7);
	if(in_nagra_data[5]&128)
		out_nagra_buffer[4]|=(1<<4);

	if(in_nagra_data[6]&1)
		out_nagra_buffer[8]|=(1<<6);
	if(in_nagra_data[6]&2)
		out_nagra_buffer[5]|=(1<<7);
	if(in_nagra_data[6]&4)
		out_nagra_buffer[8]|=(1<<5);
	if(in_nagra_data[6]&8)
		out_nagra_buffer[4]|=(1<<5);
	if(in_nagra_data[6]&16)
		out_nagra_buffer[5]|=(1<<6);
	if(in_nagra_data[6]&32)
		out_nagra_buffer[4]|=(1<<1);

	if(in_nagra_data[7]&4)
		out_nagra_buffer[5]|=(1<<5);
	if(in_nagra_data[7]&8)
		out_nagra_buffer[4]|=(1<<0);
	if(in_nagra_data[7]&16)
		out_nagra_buffer[6]|=(1<<1);
	if(in_nagra_data[7]&32)
		out_nagra_buffer[8]|=(1<<4);
	if(in_nagra_data[7]&64)
		out_nagra_buffer[6]|=(1<<3);
	if(in_nagra_data[7]&128)
		out_nagra_buffer[4]|=(1<<2);
// in_nagra_data[8] was CMDLEN
	if(in_nagra_data[8]&1)
		out_nagra_buffer[2]|=(1<<5);
	if(in_nagra_data[8]&2)
		out_nagra_buffer[0]|=(1<<1);
	if(in_nagra_data[8]&4)
		out_nagra_buffer[1]|=(1<<6);
	if(in_nagra_data[8]&8)
		out_nagra_buffer[0]|=(1<<3);
	if(in_nagra_data[8]&16)
		out_nagra_buffer[6]|=(1<<4);
	if(in_nagra_data[8]&32)
		out_nagra_buffer[4]|=(1<<3);
	if(in_nagra_data[8]&64)
		out_nagra_buffer[7]|=(1<<3);
	if(in_nagra_data[8]&128)
		out_nagra_buffer[6]|=(1<<5);

}
// Nagra_DATA is FSR (Nagra_CMDBUFFER+0xD)
// Nagra_BUFFER is DATA_BUFFER
static void Nagra_DecryptStep2(const BYTE *in_nagra_data, BYTE *out_nagra_buffer)
{
	if(in_nagra_data[0]&1)
		out_nagra_buffer[1]|=(1<<4);
	if(in_nagra_data[0]&2)
		out_nagra_buffer[8]|=(1<<1);
	if(in_nagra_data[0]&4)
		out_nagra_buffer[2]|=(1<<2);
	if(in_nagra_data[0]&8)
		out_nagra_buffer[8]|=(1<<3);
	if(in_nagra_data[0]&16)
		out_nagra_buffer[3]|=(1<<7);
	if(in_nagra_data[0]&32)
		out_nagra_buffer[1]|=(1<<5);

	if(in_nagra_data[1]&4)
		out_nagra_buffer[2]|=(1<<3);
	if(in_nagra_data[1]&8)
		out_nagra_buffer[0]|=(1<<4);
	if(in_nagra_data[1]&16)
		out_nagra_buffer[3]|=(1<<2);
	if(in_nagra_data[1]&32)
		out_nagra_buffer[3]|=(1<<3);
	if(in_nagra_data[1]&64)
		out_nagra_buffer[8]|=(1<<2);
	if(in_nagra_data[1]&128)
		out_nagra_buffer[0]|=(1<<2);

	if(in_nagra_data[2]&1)
		out_nagra_buffer[0]|=(1<<3);
	if(in_nagra_data[2]&2)
		out_nagra_buffer[3]|=(1<<5);
	if(in_nagra_data[2]&4)
		out_nagra_buffer[3]|=(1<<6);
	if(in_nagra_data[2]&8)
		out_nagra_buffer[0]|=(1<<5);
	if(in_nagra_data[2]&16)
		out_nagra_buffer[3]|=(1<<4);
	if(in_nagra_data[2]&32)
		out_nagra_buffer[8]|=(1<<0);

	if(in_nagra_data[3]&4)
		out_nagra_buffer[0]|=(1<<1);
	if(in_nagra_data[3]&8)
		out_nagra_buffer[2]|=(1<<5);
	if(in_nagra_data[3]&16)
		out_nagra_buffer[1]|=(1<<3);
	if(in_nagra_data[3]&32)
		out_nagra_buffer[1]|=(1<<6);
	if(in_nagra_data[3]&64)
		out_nagra_buffer[0]|=(1<<0);
	if(in_nagra_data[3]&128)
		out_nagra_buffer[1]|=(1<<2);

	if(in_nagra_data[4]&1)
		out_nagra_buffer[7]|=(1<<3);
	if(in_nagra_data[4]&2)
		out_nagra_buffer[6]|=(1<<5);
	if(in_nagra_data[4]&4)
		out_nagra_buffer[7]|=(1<<7);
	if(in_nagra_data[4]&8)
		out_nagra_buffer[8]|=(1<<5);
	if(in_nagra_data[4]&16)
		out_nagra_buffer[5]|=(1<<7);
	if(in_nagra_data[4]&32)
		out_nagra_buffer[6]|=(1<<3);

	if(in_nagra_data[5]&4)
		out_nagra_buffer[4]|=(1<<2);
	if(in_nagra_data[5]&8)
		out_nagra_buffer[4]|=(1<<0);
	if(in_nagra_data[5]&16)
		out_nagra_buffer[4]|=(1<<1);
	if(in_nagra_data[5]&32)
		out_nagra_buffer[7]|=(1<<2);
	if(in_nagra_data[5]&64)
		out_nagra_buffer[6]|=(1<<4);
	if(in_nagra_data[5]&128)
		out_nagra_buffer[6]|=(1<<1);

	if(in_nagra_data[6]&1)
		out_nagra_buffer[5]|=(1<<5);
	if(in_nagra_data[6]&2)
		out_nagra_buffer[7]|=(1<<4);
	if(in_nagra_data[6]&4)
		out_nagra_buffer[5]|=(1<<3);
	if(in_nagra_data[6]&8)
		out_nagra_buffer[7]|=(1<<6);
	if(in_nagra_data[6]&16)
		out_nagra_buffer[8]|=(1<<4);
	if(in_nagra_data[6]&32)
		out_nagra_buffer[8]|=(1<<7);

	if(in_nagra_data[7]&4)
		out_nagra_buffer[4]|=(1<<4);
	if(in_nagra_data[7]&8)
		out_nagra_buffer[8]|=(1<<6);
	if(in_nagra_data[7]&16)
		out_nagra_buffer[5]|=(1<<4);
	if(in_nagra_data[7]&32)
		out_nagra_buffer[4]|=(1<<3);
	if(in_nagra_data[7]&64)
		out_nagra_buffer[5]|=(1<<2);
	if(in_nagra_data[7]&128)
		out_nagra_buffer[5]|=(1<<6);
// was Nagra_CMDLEN
	if(in_nagra_data[8]&1)
		out_nagra_buffer[1]|=(1<<7);
	if(in_nagra_data[8]&2)
		out_nagra_buffer[2]|=(1<<1);
	if(in_nagra_data[8]&4)
		out_nagra_buffer[2]|=(1<<0);
	if(in_nagra_data[8]&8)
		out_nagra_buffer[2]|=(1<<4);
	if(in_nagra_data[8]&16)
		out_nagra_buffer[7]|=(1<<5);
	if(in_nagra_data[8]&32)
		out_nagra_buffer[6]|=(1<<2);
	if(in_nagra_data[8]&64)
		out_nagra_buffer[6]|=(1<<0);
	if(in_nagra_data[8]&128)
		out_nagra_buffer[4]|=(1<<5);
}
static void Nagra_MoveBuffer(const BYTE *in_nagra_buffer, BYTE *out_nagra_data)
{
	int i;
	for(i=0;i<8;i++) out_nagra_data[i]=in_nagra_buffer[i];
	out_nagra_data[8]=in_nagra_buffer[8];
}
static void Nagra_PermutationDecrypt(BYTE *nagra_buffer, BYTE *nagra_data, BYTE *nagra_parity, BYTE *nagra_cmd4)
{
	int loop;
	for(loop=0;loop<6;loop++)
	{
		int i=0;
		Nagra_InitializeBuffer(nagra_buffer);
		Nagra_DecryptStep2(nagra_data,nagra_buffer);
		Nagra_PrepareSBox(nagra_parity,nagra_buffer,nagra_cmd4);
		Nagra_MoveBuffer(nagra_buffer, nagra_data);
		Nagra_InitializeBuffer(nagra_buffer);
		Nagra_DecryptStep2(nagra_data,nagra_buffer);
		Nagra_MoveBuffer(nagra_buffer,nagra_data);
	}
}
static void Nagra_PermutationCrypt(BYTE *nagra_buffer, BYTE *nagra_data, BYTE *nagra_parity, BYTE *nagra_cmd4)
{
	int loop;
	for(loop=0;loop<6;loop++)
	{
		int i=0;
		Nagra_InitializeBuffer(nagra_buffer);
		Nagra_CryptStep2(nagra_data,nagra_buffer);
		Nagra_PrepareSBox(nagra_parity,nagra_buffer,nagra_cmd4);
		Nagra_MoveBuffer(nagra_buffer,nagra_data);
		Nagra_InitializeBuffer(nagra_buffer);
		Nagra_CryptStep2(nagra_data,nagra_buffer);
		Nagra_MoveBuffer(nagra_buffer, nagra_data);
	}
}
// Nagra_DATA is FSR (Nagra_CMDBUFFER+0xD)
static void Nagra_Permutation2(const BYTE *in_nagra_dataparity, BYTE *in_out_data )
{
	int loop;
	in_out_data[8]=1;
	for(loop=0;loop<8;loop++)
	{
		in_out_data[loop]=0;
		if(in_nagra_dataparity[1]&in_out_data[8])
			in_out_data[loop]|=(1<<7);
		if(in_nagra_dataparity[0]&in_out_data[8])
			in_out_data[loop]|=(1<<6);
		if(in_nagra_dataparity[3]&in_out_data[8])
			in_out_data[loop]|=(1<<5);
		if(in_nagra_dataparity[2]&in_out_data[8])
			in_out_data[loop]|=(1<<4);
		if(in_nagra_dataparity[5]&in_out_data[8])
			in_out_data[loop]|=(1<<3);
		if(in_nagra_dataparity[4]&in_out_data[8])
			in_out_data[loop]|=(1<<2);
		if(in_nagra_dataparity[7]&in_out_data[8])
			in_out_data[loop]|=(1<<1);
		if(in_nagra_dataparity[6]&in_out_data[8])
			in_out_data[loop]|=(1<<0);
		in_out_data[8]<<=1;
	}
}

extern "C"
{
void Nagra_Decrypt(const BYTE *_data, const BYTE *_key, BYTE *_decrypted)
{
	BYTE data[9];
	BYTE dataparity[8];
	BYTE cardkey[8];
	BYTE nagrakey[8];
	BYTE nagrabuffer[9];
	BYTE nagracmd4[4];
	memcpy(data,_data,8); data[8]=0;
	memcpy(cardkey,_key,8);
// Nagra Algo
	Nagra_PrepareKey(cardkey,nagrakey);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_PrepareKey2(nagrakey,nagrabuffer);
	Nagra_Permute_L(data);
	Nagra_StripParity(data,dataparity);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
//	for(i=0;i<8;i++) Nagra_DATA[i]=Nagra_BUFFER[i];
//	Nagra_DATA[8]=Nagra_BUFFER[8];

	Nagra_PermutationDecrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_DecryptStep2(data,nagrabuffer);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_PermutationDecrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_DecryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_DecryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);

	Nagra_Permutation2(dataparity,data);
	Nagra_Permute_L(data);
// End Nagra Algo
	memcpy(_decrypted,data,8);
}

void Nagra_Crypt(const BYTE *_data, const BYTE *_key, BYTE *out)
{
	BYTE data[9];
	BYTE dataparity[8];
	BYTE cardkey[8];
	BYTE nagrakey[8];
	BYTE nagrabuffer[9];
	BYTE nagracmd4[4];
	memcpy(data,_data,8); data[8]=0;
	memcpy(cardkey,_key,8);
// Nagra Algo
	Nagra_PrepareKey(cardkey,nagrakey);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_Permute_R(nagrakey,nagrabuffer);
	Nagra_Permute_L(data);
	Nagra_StripParity(data,dataparity);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
//	for(i=0;i<8;i++) Nagra_DATA[i]=Nagra_BUFFER[i];
//	Nagra_DATA[8]=Nagra_BUFFER[8];

	Nagra_PermutationCrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_PermutationCrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);

	Nagra_Permutation2(dataparity,data);
	Nagra_Permute_L(data);
// End Nagra Algo
	memcpy(out,data,8);
}


void Nagra_KeyCrypt(const BYTE *_data, const BYTE *_key, BYTE *out)
{
	BYTE data[16];
	BYTE dataparity[16];
	BYTE cardkey[16];
	BYTE nagrakey[16];
	BYTE nagrabuffer[16];
	BYTE nagracmd4[8];
	int i;
	memcpy(data,_data,8); data[8]=0;
	memcpy(cardkey,_key,8);
// Nagra Algo
	//Nagra_PrepareKey(cardkey,nagrakey);
	for(i=0;i<7;i++)
		nagrakey[i]=cardkey[i];
	nagrakey[7]=0;
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_Permute_R(nagrakey,nagrabuffer);
	//Nagra_KPrepareKey(cardkey,nagrabuffer);
	Nagra_Permute_L(data);
	Nagra_StripParity(data,dataparity);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
//	for(i=0;i<8;i++) Nagra_DATA[i]=Nagra_BUFFER[i];
//	Nagra_DATA[8]=Nagra_BUFFER[8];

	Nagra_PermutationCrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_PermutationCrypt(nagrabuffer, data,dataparity,nagracmd4);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);
	Nagra_MoveBuffer(nagrabuffer,data);
	Nagra_InitializeBuffer(nagrabuffer);
	Nagra_CryptStep2(data,nagrabuffer);
	Nagra_PrepareSBox(dataparity,nagrabuffer,nagracmd4);

	Nagra_Permutation2(dataparity,data);
	Nagra_Permute_L(data);
// End Nagra Algo
	memcpy(out,data,8);
}


void APIENTRY Nagra_Hash(const BYTE *_data, BYTE *_hash, int rounds)
{
	BYTE cr[8];
	int j,i;

	for (j=0;j<rounds; j++) {
		Nagra_Crypt(_data+j*8,_hash,cr);
		for(i=0;i<8;i++) _hash[i]=cr[i]^_data[j*8+i];
	}
}

void APIENTRY Nagra_DecryptBlock(BYTE * decrypted, const BYTE * crypted, const BYTE * key, const int rounds)
{
	int i;

	for (i=0;i<rounds; i++) {
		Nagra_Decrypt(crypted+i*8,key,decrypted+i*8);
	}
}

void ArrayFromString(BYTE * _out, char * in_ascii, int bytes)
{
	int i;
	char strbyte[4];
	for (i=0; i<bytes; i++) {
		sscanf(in_ascii+2*i,"%2s", strbyte);
		_out[i]=strtoul(strbyte,0,16);
	}
}

void ArrayToString(char * string, BYTE * _data, int count)
{
	int j;
	char tstr[4];
	char stringy[256];

	strcpy(stringy, "");
	for (j=0;j<count;j++){
		sprintf(tstr, "%02X", _data[j]);
		strncat(stringy,tstr,2);
	}
	strcpy(string, stringy);
}


int APIENTRY Nagra_GetKeys(BYTE * _decodedEMM, BYTE * _provider, BYTE * _key0, BYTE * _key1)
{
	unsigned int i, tester, ROMaddress;		// returns:
	BYTE hash[16];							// 0 - Not recognised as a key update EMM
	BYTE block[64];							// 1 - Keys updated successfully
	FILE * pROM;							// 2 - Can't find the ROMx.bin for key update procedure
	char * pROMFileName=NULL;


	memcpy(block, _decodedEMM+3, 4);
	tester = 0;
	for (i=0; i<4; i++) {
		tester = tester << 8;
		tester+=block[i];
	}

	switch (tester) {
		case 0xf3cd6a0a:
			pROMFileName="ROM3.bin";
			break;
		case 0xf4cd6909:
			pROMFileName="ROM4.bin";
			break;
		case 0xf7cd584d:
			pROMFileName="ROM7.bin";
			break;
		case 0xfacd7ab7:
			pROMFileName="ROM10.bin";
			break;
		case 0xfbcd456f:
			pROMFileName="ROM11.bin";
			break;
	}

	if (pROMFileName==NULL) {return 0;}

	memcpy(_provider, _decodedEMM+42, 2);	//the ident for which the new keys are intended

	memcpy(block, _decodedEMM+7, 2);		//the address of the 4*8 block to look up in the ROM
	ROMaddress = (block[0]<<8) + block[1];

	pROM=fopen(pROMFileName, "rb");
        if (pROM==0) {
                char c[128];
                strcpy(c,"/video/");
                strcat(c,pROMFileName);
                pROM=fopen(c,"rb");
                if (pROM==0) {
                        strcpy(c,"/opt/lib/");
                        strcat(c,pROMFileName);
                        pROM=fopen(c,"rb");
                }
        }
	if (pROM==0) {
		memset(_key0, 0, 8);
		memset(_key1, 0, 8);
		return 2;
	}

	fseek(pROM, ROMaddress-0x4000, SEEK_SET); 	// hash 32 bytes from specified loaction in ROM
	for (i=0; i<32; i++) {block[i]=fgetc(pROM);}
	fclose(pROM);
	for (i=0; i<8; i++) {hash[i]=block[i];}
	Nagra_Hash(block, hash, 4);

	memcpy(block, _decodedEMM+46, 8);			// use the hash & E*DES to arrive at the new plainkeys
	Nagra_KeyCrypt(block, hash, _key0);

	memcpy(block, _decodedEMM+56, 8);
	Nagra_KeyCrypt(block, hash, _key1);

	return 1;
}


/*****************************************************************
   Reverse byte order of hex string
*****************************************************************/
void ReverseOrder(char *s)
{
 int c,l=strlen(s);
 char aux[1000];

 aux[0]=0;

 c=0;
 for (int i=l-2;i>=0;i-=2)
 {
  aux[c++]=s[i];
  aux[c++]=s[i+1];
 }

 aux[c]=0;

 strcpy(s,aux);
 return;
}

void memcpyflipped( char * out, char * in, int count)
{
	int i;
	for (i=0; i<count; i++) {
		out[i]=in[count-i];
	}
return;
}


/*****************************************************************
           Nagra Signature Check
*****************************************************************/

bool APIENTRY Nagra_SigCheck(BYTE * block, BYTE * Sig, BYTE * Vkey, int rounds)
{
BYTE hash[8];

memcpy(hash, Vkey, 8);
Nagra_Hash(block, hash, rounds);

return (0==memcmp(hash, Sig, 8));
}


/*****************************************************************
                 Decrypt EMM old/new method
*****************************************************************/
INT APIENTRY Nagra_DecryptEMM(BYTE * EMM, char * ASCII_VKey, char * ASCII_E1, char * ASCII_N1, char * ASCII_N2)
{
	BYTE  decodedEMM[64];
	BYTE * encodedEMM;
	BYTE * signature;
	BYTE * key_select;
	BYTE VKey[8];

	ArrayFromString(VKey, ASCII_VKey, 8);

	Big E1,N1,E2,N2;	// EMM decrypt keys

	key_select=EMM;
	signature=EMM+1;
	encodedEMM=EMM+9;
	
	mip->IOBASE=16;

	ReverseOrder(ASCII_E1);
	E1=ASCII_E1;
	ReverseOrder(ASCII_E1); // put it back as we found it

	ReverseOrder(ASCII_N1);
	N1=ASCII_N1;
	ReverseOrder(ASCII_N1);

	E2="03";

	ReverseOrder(ASCII_N2);
	N2=ASCII_N2;
	ReverseOrder(ASCII_N2);

	Big emm,round1result,round2result,sig;
	unsigned int tester;
	bool old=true;

	char ASCII_EMM[256];
	char ASCII_Sig[32];
	char ASCII_decodedEMM[256];
	int ks=key_select[0];
	unsigned long newsigH, newsigL;	// used for hash test code

	ArrayToString(ASCII_EMM, encodedEMM, 64);
	ReverseOrder(ASCII_EMM);
	emm=ASCII_EMM;	// initialise bignum

	ArrayToString(ASCII_Sig, signature, 8);	
	ReverseOrder(ASCII_Sig);
	sig=ASCII_Sig;	// initialise bignum

	powmod(emm.getbig(),E2.getbig(),N2.getbig(),round1result.getbig());
//	otstr(round1result.getbig(), ASCII_decodedEMM);
//	printf("%0128s\n", ASCII_decodedEMM);
	
	tester = round1result.getbig()->w[0x0F];	// modify round1result with the key_select bits 7-4
//	tester &= 0x3fffffff;
	ks = ks >> 6;								// lose the lower 4 nibble
	tester |= ks<<30;							// combine upper nibble with round1result
	round1result.getbig()->w[0x0F]=tester;

//	otstr(round1result.getbig(), ASCII_decodedEMM);
//	printf("%0128s\n", ASCII_decodedEMM);

	powmod(round1result.getbig(),E1.getbig(),N1.getbig(),round2result.getbig());

	otstr(round2result.getbig(), ASCII_decodedEMM);

	char tempst[129];
	sprintf(tempst, "%0128s", ASCII_decodedEMM);
	strcpy(ASCII_decodedEMM, tempst);

	ArrayFromString(decodedEMM, ASCII_decodedEMM, 64);

	if (Nagra_SigCheck(decodedEMM, signature, VKey, 8)) {
		memcpy(EMM+1, signature, 8);
		memcpy(EMM+9, decodedEMM, 64);	
		return(1);
	}
	// We might need to use intercambia firma method...
	newsigH=round1result.getbig()->w[0x01];			// Intercambia firma:
	newsigL=round1result.getbig()->w[0x00];			// Exchange signature for lower 64 bits after round 1 powmod()

	for (int i=0; i<4 ;i++) {									// build revised signature in reverse
		signature[i]=((0xff<<(i*8))&newsigL)>>(i*8);}		// byte order of result1 lower 64 bits
	for (int i=0; i<4 ; i++) {
		signature[4+i]=((0xff<<(i*8))&newsigH)>>(i*8);}

	round1result.getbig()->w[0x01]=sig.getbig()->w[0x01];	// use reverse order sig as N2 lower 64 bits
	round1result.getbig()->w[0x00]=sig.getbig()->w[0x00];	// this is the "intercambia firma" modification

	powmod(round1result.getbig(),E1.getbig(),N1.getbig(),round2result.getbig());

	otstr(round2result.getbig(), ASCII_decodedEMM);
	sprintf(tempst, "%0128s", ASCII_decodedEMM);
	strcpy(ASCII_decodedEMM, tempst);

	ArrayFromString(decodedEMM, ASCII_decodedEMM, 64);
	
	memcpy(EMM+1, signature, 8);
	memcpy(EMM+9, decodedEMM, 64);

	if (Nagra_SigCheck(EMM+9, EMM+1, VKey, 8)) {return(2);}

	return(0);

}

void APIENTRY Nagra_RSADecrypt(char * Data, char * KeySelect, char * ASCII_E1, char * ASCII_N1, char * ASCII_N2)
{

	Big E1,N1,E2,N2;	// EMM decrypt keys
	Big emm,round1result,round2result;

	mip->IOBASE=16;

	ReverseOrder(ASCII_E1);
	E1=ASCII_E1;
	ReverseOrder(ASCII_E1); // put it back as we found it

	ReverseOrder(ASCII_N1);
	N1=ASCII_N1;
	ReverseOrder(ASCII_N1);

	E2="03";

	ReverseOrder(ASCII_N2);
	N2=ASCII_N2;
	ReverseOrder(ASCII_N2);

	ReverseOrder(Data);
	emm=Data;	// initialise bignum

	unsigned int tester;
	int ks=strtoul(KeySelect, 0, 16);

	powmod(emm.getbig(),E2.getbig(),N2.getbig(),round1result.getbig());
	
	tester = round1result.getbig()->w[0x0F];	// modify round1result with the key_select bits 7-4
	ks = ks >> 4;								// lose the lower 4 nibble
	tester |= ks<<28;							// combine upper nibble with round1result
	round1result.getbig()->w[0x0F]=tester;

	powmod(round1result.getbig(),E1.getbig(),N1.getbig(),round2result.getbig());

	otstr(round2result.getbig(), Data);
	char tempst[129];
	sprintf(tempst, "%0128s", Data);
	strcpy(Data, tempst);

}

void Nagra_GetCW(const BYTE * decrypted, BYTE * evenCW, BYTE * oddCW, BYTE * type)
{
	switch (decrypted[0]) {
	case 0x10:
		memcpy(evenCW, decrypted+2, 8);
		memcpy(oddCW, decrypted+11, 8);
		type[0]=1;
		break;
	case 0x11:
		memcpy(evenCW, decrypted+2, 8);
		type[0]=2;
		break;
	case 0x12:
		memcpy(oddCW, decrypted+2, 8);
		type[0]=3;
		break;
	default:
		type[0]=0;
		break;
	}
}
}
