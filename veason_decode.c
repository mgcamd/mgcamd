/* 
decode.c - The EuroCrypt decryption algorithm, with
   modifications for VIACCESS


   DO NOT USE THIS SOFTWARE TO WATCH TV WITHOUT HAVING A LEGAL SUBSCRIPTION.
   IT IS EXPERIMENTAL FOR TESTING PURPOSES ONLY!

   Last updated: 2001-02-17
*/

/*
From John Mac Donalds document on Eurocrypt:
THE DECRYPTION SYSTEM

So far I've described how the key for a channel is obtained, how the two
encrypted words are obtained, and how the decrypted words are sent to the
DC. The next sections deal with the algorithm which is applied to the key
and an encrypted word to obtain a decrypted word.

The algorithm is based upon the Data Encryption Standard originally  created
for the secure transmission of military data. There is a very good scholarly
paper on this standard in a file called des-how-.txt by Matthew Fischer of
The University of Iowa on the Web and BBSs which is worth a read.

The Eurocrypt system has two flavours, Eurocrypt-M and Eurocrypt-S2 which
are currently used by TV channels. I'll describe M first, then S2.

In this section all numbers are decimal unless stated otherwise, not hex.

EUROCRYPT-M

The main steps in the process are:

	- key preparation
	
	- data word manipulation 
	
	- process iteration.

In other words, we perform some operations on the key, then manipulate the
data word, do some interaction between the two (based on exclusive ORing)
and repeat the process several times until we have the decrypted word. In
fact the process is performed (decimal) 16 times.

KEY PREPARATION

This is very straightforward. We have a 7 byte or 56 bit key which we split
into two 28 bit halves and we rotate each half 1 or 2 bits to the left
depending which of the 16 rounds we're on then put the two halves together. 
A single rotation left means that the first (most significant or left hand)
bit moves to the last (least significant or right hand) position and all the
other bits move one to the left.

The exact number of left rotations is determined by the table:

Round            1  2  3  4  5  6  7  8  9  10  11  12  13  14  15  16 No of
rotations 1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1

We then create a new 48 bit key by reordering 48 of the bits in the 56 bit
shifted key according to the pattern:

		       14 17 11 24  1  5
                             3 28 15
			6 21 10
		       23 19 12  4 26  8                           
		       16  7 27 20 13  2                           
		       41 52 31 37 47 55                           
		       30 40 51 45 33 48                           
		       44 49 39 56 34 53                           
 		       46 42 50 36 29 32     
		       
This means that the new 1st bit is the 14th old bit, new 2nd bit is old 17th
and so on with the new 48th bit being the old 32nd bit. The old bits 9, 18,
22, 25, 35, 38, 43, 54 are not used. This operation is called a Permutation
and the table is called Permuted Choice 2 or PC-2 in DES terminology.

Preparation of the key is now complete for a single round. Note that the net
result is that we have a new 48 bit key for use later on.

DATA WORD MANIPULATION

The encrypted data word is 8 bytes or 64 bits long. The first thing to do is
to split this into two halves each 32 bits long called L and R. Then we
build a new R called R1 of length 48 bits by using the pattern:

		       32  1  2  3  4  5
                       4 5 6 7 8 9 
			8 9 10 11 12 13
		       12 13 14 15 16 17                           
		       16 17 18 19 20 21                           
		       20 21 22 23 24 25                           
		       24 25 26 27 28 29                           
		       28 29 30 31 32  1

This means our R1 has its 1st bit as old R's last bit, its 2nd bit as old
R's 1st bit and so on with its last bit being the ols R's 1st bit. As you
can see, some of old R's bits are used more than once. The table is called
the Expansion or E-Table.

We now XOR this 48 bit R1 with the 48 bit key we prepared earlier, and we
split the result up into eight 6-bit blocks. Each of these blocks is used to
locate an entry in one of the eight tables below, called Substitution or
S-Boxes.


		       Substitution Box 1             
	       
		       14  4 13  1  2 15 11  8  3 10  6 12  5  9  0  7 0 15
			7 4 14 2 13 1 10 6 12 11 9 5 3 8 4 1 14 8 13 6 2 11
			15 12 9 7 3 10 5 0
		       15 12  8  2  4  9  1  7  5 11  3 14 10  0  6 13                                  
		       
		       Substitution Box 2
		       
		       15  1  8 14  6 11  3  4  9  7  2 13 12  0  5 10 3 13
			4 7 15 2 8 14 12 0 1 10 6 9 11 5 0 14 7 11 10 4 13 1
			5 8 12 6 9 3 2 15
		       13  8 10  1  3 15  4  2 11  6  7 12  0  5 14  9                                  
		       
		       Substitution Box 3
		       
		       10  0  9 14  6  3 15  5  1 13 12  7 11  4  2  8
		       13 7 0 9 3 4 6 10 2 8 5 14 12 11 15 1 13 6 4 9 8 15 3
		       0 11 1 2 12 5 10 14 7
			1 10 13  0  6  9  8  7  4 15 14  3 11  5  2 12                                  
			
		       Substitution Box 4

			7 13 14  3  0  6  9 10  1  2  8  5 11 12  4 15
		       13 8 11 5 6 15 0 3 4 7 2 12 1 10 14 9 10 6 9 0 12 11
		       7 13 15 1 3 14 5 2 8 4
			3 15  0  6 10  1 13  8  9  4  5 11 12  7  2 14                                  
			
		       Substitution Box 5

			2 12  4  1  7 10 11  6  8  5  3 15 13  0 14  9
		       14 11 2 12 4 7 13 1 5 0 15 10 3 9 8 6
			4  2  1 11 10 13  7  8 15  9 12  5  6  3  0 14
		       11 8 12 7 1 14 2 13 6 15 0 9 10 4 5 3
		       
		       Substitution Box 6

		       12  1 10 15  9  2  6  8  0 13  3  4 14  7  5 11
		       10 15 4 2 7 12 9 5 6 1 13 14 0 11 3 8
			9 14 15  5  2  8 12  3  7  0  4 10  1 13 11  6
			4 3 2 12 9 5 15 10 11 14 1 7 6 0 8 13
			
		       Substitution Box 7 
		       
			4 11  2 14 15  0  8 13  3 12  9  7  5 10  6  1
		       13 0 11 7 4 9 1 10 14 3 5 12 2 15 8 6
			1  4 11 13 12  3  7 14 10 15  6  8  0  5  9  2
			6 11 13 8 1 4 10 7 9 5 0 15 14 2 3 12
			
		       Substitution Box 8 
		       
		       13  2  8  4  6 15 11  1 10  9  3 14  5  0 12  7
			1 15 13 8 10 3 7 4 12 5 6 11 0 14 9 2 7 11 4 1 9 12
			14 2 0 6 10 13 15 3 5 8 2 1 14 7 4 10 8 13 15 12 9 0
			3 5 6 11

The entry in the S-Box is found by using the 1st and 6th bits of the 6 bit
block as the row (0, 1, 2, or 3) and the middle 4 bits as the column (0 -
15). Also, the 1st 6 bit block uses S-1, the 2nd S-2, and so on with the 8th
using S-8.

You will notice that each of the S-Box entries is between 0 and 15; we now
form a new R called R2 from each of the located S-Box entries in order,
giving us a new 32 bit R2.

The last operation is to create a (third and final) R called R3 from R2 by
using the following Permutation or P Table:

		       16  7 20 21                               29 12 28 17
			1 15 23 26                                5 18 31 10
			2 8 24 14
		       32 27  3  9                              
		       19 13 30  6                              
		       22 11  4 25

This means that the 1st bit of R3 is the 16th of R2, the 2nd is the 7th  and
so on, with the 32nd being the 25th bit of R2.

PROCESS ITERATION

The net result of the previous section was to split the encrypted word into
two halves, ignore the left-hand one L and eventually create a new right-
hand one R3.

Now we XOR L and R3 together, and we've finished a decryption round.

For the next round, we treat R3 as the left-hand half of a new data word and
the result of the XOR operation as the right-hand half and repeat the
process of key preparation (for that round) and data manipulation (of the
new data word). We do this 16 times and we end up with a last left-right
pair of 32 bits each.

Put these together and we have a decrypted 8 byte word. 

Continue the whole decryption process for the second encrypted word obtained
from the 88 instruction dialogue and then both can be sent to the DC via the
C0 instruction dialogue and the TV picture is unscrambled!

EUROCRYPT-S2

There are three variations on Eurocrypt-M which together form Eurocrypt-S2.

KEY PREPARATION

The key is split into a left and right pair as before. However, no left
shifting is performed prior to data word manipulation; the shifting is
performed after the manipulation and the shifts are to the right, not the
left.

DATA WORD MANIPULATION

Before performing the E-table operation, a new data word should be created
using the following permutation:

		       58 50 42 34 26 18 10  2                         60 52
		       44 36 28 20 12 4 62 54 46 38 30 22 14 6 64 56 48 40
		       32 24 16 8 57 49 41 33 25 17 9 1 59 51 43 35 27 19 11
		       3 61 53 45 37 29 21 13 5 63 55 47 39 31 23 15 7

This means that the new data word is 64 bits long, and its 1st bit is the
original word's 58th and so on. This is called the Initial Permutation or IP
and is performed once per 16 decryption rounds.

After the decryption is complete as per Eurocrypt-M (ie after 16 rounds),
the decrypted data word is permuted using the following table:

		       40  8 48 16 56 24 64 32                         39 7
		       47 15 55 23 63 31 38 6 46 14 54 22 62 30 37 5 45 13
		       53 21 61 29 36 4 44 12 52 20 60 28 35 3 43 11 51 19
		       59 27 34 2 42 10 50 18 58 26 33 1 41 9 49 17 57 25

This means that the final decrypted word is 64 bits long and its first bit
is the previous word's 40th and so on. This is called the Inverse Initial
Permutation or IP**-1.

THE CHECKSUM ALGORITHM

The Eurocrypt system includes a function whereby the card, official or
otherwise, can check that packets received from the decoder are not
corrupted and that any control word decryption and entitlement management is
done correctly. For example, the card needs to be sure that the new CANAL +
key is the intended one before it overwrites the old one. (The single PIC
cards don't do this but the twin PIC cards and COPs do). This function is
called the HASH function and this section describes how it works.

Any instruction packet from the DC which quotes the use of a key (most often
18 and 88 instructions) has at the end of the packet a ten byte string
consisting of

		f0 08 < 8 hex bytes >

This is the HASH parameter and it always starts with f0 08. It should not be
confused with the f0 instruction which is the 'process address' instruction.
The HASH function appears at the end of the decoder-->card traffic following
an instruction packet quoting the use of a key index. The 8 bytes following
the f0 08 are the HASH digits. When the card processes the decoder
instruction it applies the HASH algorithm to the data and checks that the
result it gets is the same as the HASH digits. If it is it completes the
instruction processing and sends the usual 90 00; otherwise it aborts the
instruction processing and sends 90 08 whereupon the decoder displays the
"HASH ERROR" message (Error 5).

I'll now describe how the HASH algorithm works.

It's based on an eight-byte buffer which is zeroised at the start of the
instruction processing (except for ca 18 01 and ca 18 02 instructions; in
these cases it's zeroised at the start of the preceding f0 instruction).

Bytes from the decoder-->card packet are loaded in order into the HASH
buffer by XORing each one with current occupant (usually initially zero). 
When eight bytes have been loaded, the HASH function is applied to them and
the result is stored in the HASH buffer, (overwriting not XORing). Further
packet bytes are buffered restarting at position 1 in the HASH buffer.

Loading further bytes from the packet continues in this way (XORing then
HASHing every eight bytes and overwriting) until all bytes in the packet
prior to f0 08 have been buffered. A final HASH of the HASH buffer contents
is then performed.

The result of the final HASH should equal the eight bytes following f0 08 in
the decoder-->card packet. If it does, fine; if not, "Hash Error".

So, what's the HASH function?

Its the same as the DES function (M or S) which is used for control word
decryption except that near the end of each DES round the first and second
bytes of the right-hand half of the eight byte word are swapped prior to
XORing the right-hand half with the left-hand half. The key used in this DES
variation is the key specified in the decoder instruction (usually the key
index is in the fourth byte of the instruction packet).

Now you can see why you get "Hash Error" if you don't have the right key,
because the HASH function will generate incorrect values in the HASH buffer
giving a mismatch with the HASH bytes following f0 08.

Just as a matter of interest, single PIC cards ignore the HASH function
because there aren't enough registers for the HASH buffer. The auto update
of CANAL + and Cine Cinemas is done by comparing the new key with the old
and overwriting if they're different. This is not really satisfactory but
works OK. The implementation in COP and twin PIC cards is much better,
relying on the HASH function to determine if the new key is the intended
one.


I hope you find this helpful. If you think you have any improvements or
errors to correct leave me a message where you found this file and I'll be
happy to update it.
*/


/*
From the newsgroup alt.tv.crypt:

NOTE
EuroDes uses a 7 byte key.
Viaccess uses an 8 byte key, if the last byte is zero,
then it is like Eurocrypt M.
If the last byte is not zero:

 Is this true???????

Viaccess is a modification of Eurocrypt M. In this mod the key has 8 bytes
when EC-M has only 7.
If the 8th byte is zero then Viaccess works exactly like EC-M.
If the 8th byte is nonzero then this will trigger several different small
mods.

One of these mods is in DES routine.
7 key bytes are used in des but the 8th byte is used in special core
function in every DES round.

This mod is done just before expansion E and it alters the 5th data byte
which is the first of the right-hand 4 data bytes to be used in the DES-
round.

Therefore it has affect in S-boxes 1, 2, 3 and 8.

The mod is done only with this byte for expansion E and the original byte
remains the same.

In this mod the 8th key byte is multiplied with the data byte for at get a
16 bit word.

Then the data byte is added to this word (upper 8 bit byte is incremented if
there was a carry with the lower byte).

Then the 8th key byte is added to the word on the same way.

Then the upper byte is subtracted from the lower byte.
If there was a carry in this subtract then result is incremented by 1.
Then this result byte is used instead of the original byte in expansion E.

All hash algorithms are working like in EC-M when this DES modification is
done.

CA 88 and CA 18 message processing:
If the 8th keybyte is nonzero then first 7 keybytes are rotated left by 2
bytes.
This means key(k1 k2 k3 k4 k5 k6 k7 k8) -> key(k3 k4 k5 k6 k7 k1 k2 k8)

If the 8th key byte is even then this is the last modification but if it is
odd then there is still one very complicated data modification.

First there is one constant which is 5Ah if the 8th key byte is odd and less
than 10h.
If the 8th byte is odd and bigger than 10h then this constant is A5h.

In the data modification is used hash result for the 8 bytes which are just
before the encrypted data.
If there are not enough bytes in these hash results then values 00 are used
in missing bytes.

These hash bytes are first ANDed with the constant and then XORed with the
encrypted data bytes.
Result bytes are then used as input data for DES.
Ofcourse DES is done with necessary mods.

After DES the result bytes are ready for CA C0 message or other use in
CA 18 messages.
*/

#include "veason_des.h"
#include "veason_decode.h"

#define DES_ITER 16

unsigned long F(unsigned long, unsigned char *);

const char bytebit[]={128,64,32,16,8,4,2,1,0};

unsigned char modkey;


void decode(unsigned char *in, const unsigned char *key8, char mode)
{
char i;
char j, k,l;
char t;
unsigned long R, L, C, D;
unsigned long R1, DD, CC;                              
unsigned char *key = (unsigned char*) key8;
unsigned char pin[8];
unsigned char K[8];

modkey = key8[7];

C =\
	(unsigned long) key[0] << 20
	^ (unsigned long) key[1] << 12
	^ (unsigned long) key[2] <<  4
	^ (unsigned long) (key[3] >> 4);
D =\
	(unsigned long) (key[3] & 0x0f) << 24
	^ (unsigned long) key[4] << 16
	^ (unsigned long) key[5] << 8
	^ (unsigned long) key[6];

if (mode == 2)  // Eurocrypt S2
	{
	for(i = 0; i < 8; i++) pin[i]=0;

	for(i = 0; i < 64; i++)
		{
		if(in[(IP[i] - 1) / 8] & bytebit[(IP[i] - 1) % 8] )
		pin[i / 8] |= bytebit[i % 8];
		}

	for(i = 0; i < 8; i++) in[i] = pin[i];
	}

L =\
	(unsigned long) in[0] << 24
	^ (unsigned long) in[1] << 16
	^ (unsigned long) in[2] << 8
 	^ (unsigned long) in[3];
R =\
	(unsigned long) in[4] << 24
	^ (unsigned long) in[5] << 16
	^ (unsigned long) in[6] << 8
	^ (unsigned long) in[7];

if(mode != 2)
	{
	for(i = 0; i < DES_ITER; i++)
		{
		/* Key schedule */
		for(j = 0; j < LS[i]; j++)
			{
			C = (C << 1 ^ C >> 27) & 0xfffffffL;
			D = (D << 1 ^ D >> 27) & 0xfffffffL;
			}

		for(j = 0, k = 0; j < 8; j++ )
			{
			K[j] = 0;
			for(t = 0; t < 6; t++, k++) 
				if( PC2[k] < 29 )
					K[j] |= (C >> 28 - PC2[k] & 1) << (5 - t);
				else
					K[j] |= (D >> 56 - PC2[k] & 1) << (5 - t);
			}

		/* One decryption round */
		R1 = L ^ F(R, K);
		L = R;
		R = R1;
		}
	} /* end if mode != 2 */
else
	{
	for(i = DES_ITER - 1; i >= 0;  i--)
		{
		CC = C;
		DD = D;
		/* Key schedule */
		for(l = 0; l <= i; l++)
			{
			for(j = 0; j < LS[l]; j++ )
				{
				CC = (CC << 1 ^ CC >> 27) & 0xfffffffL;
				DD = (DD << 1 ^ DD >> 27) & 0xfffffffL;
				}
			}
		for(j = 0, k = 0; j < 8; j++ )
			{
			K[j] = 0;
			for(t = 0; t < 6; t++, k++)
				{
				if( PC2[k] < 29)
					K[j] |= (CC >> 28 - PC2[k] & 1) << (5 - t);
				else
					K[j] |= (DD >> 56 - PC2[k] & 1) << (5 - t);
				}
			}

		/* One decryption round */
		R1 = L ^ F(R, K);
		L = R;
		R = R1;
		}
	} /* end else mode is 2 */

in[0] = R >> 24;
in[1] = R >> 16;
in[2] = R >> 8;
in[3] = R;
in[4] = L >> 24;
in[5] = L >> 16;
in[6] = L >> 8;
in[7] = L;

if (mode == 2)
	{
	for(i = 0; i < 8; i++) pin[i] = 0;

	for(i = 0; i < 64; i++)
		{
		if(in[(IP1[i] - 1) / 8] & bytebit[(IP1[i] - 1) % 8])
			pin[i / 8] |= bytebit[i % 8];
		}

	for(i = 0; i < 8; i++) in[i] = pin[i];
	} /* end if mode == 2 */

} /* end function decode */


unsigned long F(unsigned long R, unsigned char *K)
{
int i, k;
unsigned int ml;
unsigned long s = 0, result = 0;
unsigned char temp;
unsigned char key5;
unsigned int ax, ah, al, bx, bh, bl;

if(modkey != 0)
	{
	//Get the 5th data byte (included in R)
	key5 = (R >> 24) &0xff;

	//and apply the Viaccess mod to it:

	ml = (unsigned int) modkey * (unsigned int) key5;
	ml += (unsigned int) modkey;
	ml += (unsigned int) key5;

	/* start mod */
	bx = ml;		

	al = bx & 0xff;

	bh = (bx & 0xff00) >> 8;

	al &= 0xff;
	bh &= 0xff;

	al -= bh;
	if(al & 0x100) al++;

	al &= 0xff;

	key5 = al;

	/* end mod */
	
/*
	asm 
		{
		mov bx,ml
		mov al,bl
		sub al,bh
		jnc nocarry
		inc al
		};

	nocarry:
	asm
		{
		mov key5, al
		};
*/
	
	// and represent it as (long) again:
	R &= 0xffffffL;
	R |= (( (unsigned long) key5) << 24);
	} /* end if modkey not zero */ 

for(i = 0, k = 0; i < 8; i++)
	{
	int j;
	char v = 0;

	/* The expansion E */
	for(j = 0; j < 6; j++, k++) v |= (R >> 32 - E[k] & 1) << (5 - j);
	v ^= K[i];

	/* The S-boxes */
	s |= (unsigned long) S[i][v] << 28 - 4 * i;
	} /* end for i */

/* The permutation P */
for(i = 0; i < 32; i++) result |= (s >> 32 - P[i] & 1) << 31 - i;

return result;
} /* end function F */



//*************** HASH FUNCTION ******************************************

void hash(unsigned char *in, const unsigned char *key8, char mode)
{
char i;
char j, k,l;
char t;
unsigned char swap1, swap2;
unsigned long R, L, C, D,T;
unsigned long R1, DD, CC;
unsigned char *key = (unsigned char *) key8;
unsigned char pin[8];
unsigned char K[8];

modkey=key8[7];

C =\
	 (unsigned long) key[0] << 20
	^ (unsigned long) key[1] << 12
	^ (unsigned long) key[2] <<  4
	^ (unsigned long) (key[3] >> 4);
D =\
	(unsigned long) (key[3] & 0x0f) << 24
	^ (unsigned long) key[4] << 16
	^ (unsigned long) key[5] << 8
	^ (unsigned long) key[6];

if(mode == 2)  // Eurocrypt S2
	{
	for(i = 0; i < 8; i++) pin[i] = 0;

	for(i = 0; i < 64; i++)
		{
		if(in[(IP[i] - 1) / 8] & bytebit[(IP[i] - 1) % 8])
			pin[i / 8] |= bytebit[i % 8];
		}

	for (i = 0; i < 8; i++) in[i] = pin[i];
	} /* end if mode == 2 */

L =\
	(unsigned long) in[0] << 24
  ^ (unsigned long) in[1] << 16
  ^ (unsigned long) in[2] << 8
  ^ (unsigned long) in[3];
R =\
	(unsigned long) in[4] << 24
  ^ (unsigned long) in[5] << 16
  ^ (unsigned long) in[6] << 8
  ^ (unsigned long) in[7];

if(mode != 2)
	{
	for(i = 0; i < DES_ITER; i++)
		{
		/* Key schedule */
		for(j = 0; j < LS[i]; j++ )
			{
			C = (C << 1 ^ C >> 27) & 0xfffffffL;
			D = (D << 1 ^ D >> 27) & 0xfffffffL;
			}

		for(j = 0, k = 0; j < 8; j++ )
			{
			K[j] = 0;
			for(t = 0; t < 6; t++, k++)
				{
				if( PC2[k] < 29 )
					K[j] |= (C >> 28 - PC2[k] & 1) << (5 - t);
				else
					K[j] |= (D >> 56 - PC2[k] & 1) << (5 - t);
				}
			}

		/* One decryption round */
		T = F(R, K);

		swap1 = (T >> 24) & 0xffL;
		swap2 = (T >> 16) & 0xffL;

		T = (T & 0x0000ffffL) | 
			(( (unsigned long) swap1) << 16) |
			(( (unsigned long) swap2) << 24);

		R1 = L ^ T;
		L = R;
		R = R1;

/*
		R1 = L ^ F(R, K);
		L = R;
		R = R1;
*/

		}
	} /* end if mode != 2 */
else  /* mode == 2 */
	{
	for(i = DES_ITER - 1; i >= 0;  i--)
		{
		CC = C;
		DD = D;

		/* Key schedule */
		for(l = 0; l <= i; l++)
			{
			for(j = 0; j < LS[l]; j++ )
				{
				CC = (CC << 1 ^ CC >> 27) & 0xfffffffL;
				DD = (DD << 1 ^ DD >> 27) & 0xfffffffL;
				}
			}
		for(j = 0, k = 0; j < 8; j++ )
			{
			K[j] = 0;
			for(t = 0; t < 6; t++, k++)
				{
				if( PC2[k] < 29 )
					K[j] |= (CC >> 28 - PC2[k] & 1) << (5 - t);
				else
					K[j] |= (DD >> 56 - PC2[k] & 1) << (5 - t);
				}
			}

		/* One decryption round, Swap byte 1 + 2 prior to XOR R, L */
		R1 = L ^ F(R,K);
		L = R;
		R = R1;
		}
	} /* end else mode == 2 */

in[0] = R >> 24;
in[1] = R >> 16;
in[2] = R >> 8;
in[3] = R;
in[4] = L >> 24;
in[5] = L >> 16;
in[6] = L >> 8;
in[7] = L;

if(mode == 2)
	{
	for(i = 0; i < 8; i++) pin[i] = 0;

	for(i = 0; i < 64; i++)
		{
		if(in[(IP1[i] - 1) / 8] & bytebit[(IP1[i] - 1) % 8])
			pin[i / 8] |= bytebit[i % 8];
		}

	for(i = 0; i < 8; i++) in[i] = pin[i];
	} /* end if mode == 2 */
} /* end function hash */ 

