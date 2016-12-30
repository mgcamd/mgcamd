#include "viemu.h"
#include "viemu_proto.h"

#include "veason_decode.h"


/*
With thank you to those who do not want to be called the Russian maffia:

 Algorithm for Viaccess. Real version. 26. 02. 2001 (with fixes and
             additions). Copyright U D.S. 2001.
 
 Please do not call us as Russian Mafia! :))
 
Viaccess algoritm.
DES

Viaccess is a modification of Eurocrypt M. In this mod the key has
8 bytes when EC-M has only 7. If the 8th byte is zero then Viaccess
works exactly like EC-M. If the 8th byte is nonzero then this will
trigger several different small mods. One of these mods is in DES
routine. 7 key bytes are used in des but the 8th byte is used in
special core function in every DES round. This mod is done just
before expansion E and it alters the 5th data byte which is the
first of the right-hand 4 data bytes to be used in the DES-round.
Therefore it has affect in S-boxes 1,2,3 and 8. The mod is done
only with this byte for expansion E and the original byte remains
the same.
In this mod the 8th key byte is multiplied with the data byte for
at get a 16 bit word. Then the data byte is added to this word
(upper 8 bit byte is incremented if there was a carry with the
lower byte). Then the 8th key byte is added to the word on the same
way. Then the upper byte is subtracted from the lower byte. If
there was a carry in this subtract then result is incremented by 1.
Then this result byte is used instead of the original byte in
expansion E.

Caution there is a little mistake in John Macdonalds FAQ at the end
of each round the new L is build with the old R and not the old R3

Another modification in the DES routine is the permutation table
used after xoring the bytes of the expanded data with the modified
keys data the new permutation table is

32 15 4 9

25 24 20 1

5 31 11 18

13 2 27 22

6 16 12 30

28 19 7 21

3 29 26 14

10 23 8 17

Key

If the 8th keybyte is nonzero then first 7 keybytes are rotated
left by 2 bytes. This means key(k1 k2 k3 k4 k5 k6 k7 k8) -> key(k3
k4 k5 k6 k7 k1 k2 k8) These modified key is used in the DES routine
but in the hash routine we have to use the non modified key.

Hash

All hash algorithms are working like in EC-M when this DES
modification is done.

CA 88 and CA 18 message processing: 

If the 8th key byte is even then this is the last modification but
if it is odd then there is still one very complicated data
modification. First there is one constant which is 5Ah if the 8th
key byte is odd and his lower nibble is equal to zero. If the 8th
byte is odd his lower nibble is not equal to zero then this
constant is A5h.

Whe have to calculate the hash like in eurocrypt but the crypted
words included in the data field have to be processed with the k
constant to build the real crypted word.

There for the bytes of the sanded CW are first ANDed with the
constant and then XORed with the encrypted data bytes. Result bytes
are then stored in the real crypted word witch

is used as input data for DES. Ofcourse DES is done with necessary
mods. The non modified bytes of the CW are still used to continue
the hash processing. After DES the result bytes are ready for CA C0
message or other use in CA 18 messages.
 ______________________________________________________________

 Some new litle bug was found and fixed in algorithm by author D.S
 at 09.03.2001

a little bug in the viaccess algo in the key chapter actual version
If the 8th keybyte is nonzero then first 7 keybytes are rotated
left by 2 bytes.
This means key(k1 k2 k3 k4 k5 k6 k7 k8) -> key(k3 k4 k5 k6 k7 k1 k2 k8)
These modified key is used in the DES routine but in the hash routine we
have to use the non modified key.

corrected one
In the DES hash routine we have to use the key as is (k1 k2 k3 k4 k5 k6 k7
k8).
But in the DES decrypt routine we build a new key in whith the first 7
keybytes are rotated left by 2 bytes. This means key(k1 k2 k3 k4 k5 k6 k7
k8) -> key(k3 k4 k5 k6 k7 k1 k2 k8)

Regards
 ______________________________________________________________

New information about GCA added 10 july 2001

Explanation of a possible counter measure from ViaAccess
It is based on the geographical code area (GCA) and it has been used
in the past by Viasat. The smart card code was available only
on some cop card.

The GCA is a value of 4 bytes and could be specific to each card.
When sending an ECM, you could give the right to descramble only
to the card with a GCA of a specific value (or a set of value).
If needed, you could indicate that you don't care of the GCA value
using a FF FF FF FF value.
When it is received by a decoder, the commands exchanged with the
card will be :
a) CA AC A6 00 00 to check if the card has a GCA
b) CA F8 00 08 06 9F 04 FF FF FF FF
by this command the decoder explains to the card that
the GCA is not important.
c) CA 88 01 08 LEN data
Here it is a normal CA 88 but P1=01 and not 00
What is interesting is the hash used in the CA 88.
If you do b) followed into c) by a hash computed using
for example viaprog, you will get a hash error.
Why ? because the 9F 04 FF FF FF FF is used to give
an initial value to the hash buffer used for CA 88.
It works like for EMM and CA F0.
Consequently, today, with almost available smart card hex,
there is a problem because :
command a) answer 90 08 and not 90 00
command b) answer 6D 00 because F8 is unknown.
command c) doesn't use the good initial hash buffer.

Note by Panteltje:
In the ca f8 (Geographical Area Code 'nano') the thing should not reset.
That is one.
But the ca 88 01 x x x  (versus ca 88 00 as normal) requires a different hash.
The hash buffer is then initialized with zero,
but this time the data comes from that CGA instruction.

Also the KEY specified in that CGA instruction is the key to be used for that
initial hash (it also happens to be 0e for this case same the main key used,
but I think it does not have to be).

Then read ca f8 xx yy zz etc, starting hashing at xx for P3 bytes.
If hascount != zero then do the final hash, and set it to zero.

Then use this hashbuffer as start for the normal decoding.
------end note----


 ______________________________________________________________

Some new litle bug was found and fixed in algorithm by author D.S
at 10 july 2001

the Hrt key's allowed to discover a bug in the algo

here the current version
If the 8th key byte is even then this is the last modification but
if it is odd then there is still one very complicated data
modification. First there is one constant which is 5Ah if the 8th
key byte is odd and his lower nibble is equal to zero. If the 8th
byte is odd his lower nibble is not equal to zero then this
constant is A5h.

and corrected one

If the 8th key byte is even then this is the last modification but
if it is odd then there is still one very complicated data
modification. First there is one constant which is 5Ah if the 8th
key byte is odd and his higher nibble is equal to zero ((k8 & F0)=
=0). If the 8th byte is odd his higher nibble is not equal to zero
((k8 & F0)! =0) then this constant is A5h.
*/


int avrx_buffer[] =\
{
//0xCA, 0x88, 0x00, 0x08, 0x28
0xE2, 0x03,		0x2A, 0x56, 0x1F,
0xE4, 0x05,		0x00, 0x00, 0x00, 0x00, 0x00,
0xEA, 0x10,		0x42, 0xCD, 0x01, 0xB2, 0x02, 0x7B, 0x84, 0xEF,
				0x81, 0x53, 0xC6, 0x6F, 0xBE, 0x78, 0xB6, 0x38,
0xF0, 0x08,		0x51, 0x1E, 0xE5, 0xE0, 0x65, 0x88, 0xED, 0x44 
};

unsigned char vrx_key[]= {};
unsigned char vry_key[]= {};

unsigned char hashbuffer[8];
unsigned char hashkey[8];
unsigned char pH;


void init_hash(unsigned char *hk)
{
int i;

pH = 0;
memset(hashbuffer, 0, 8);
memcpy(hashkey, hk, 8);
} /* end function init_hash */


void hash_byte(unsigned char n)
{
hashbuffer[pH] ^= n;
pH++;
if(pH == 8)
	{
	hash(hashbuffer, hashkey, 0);
	pH = 0;
	}
} /* end function hash_byte */


unsigned char get_actual_byte()
{
return hashbuffer[pH];
} /* end function get_actual_byte */


int check_hash(unsigned char *signatur)
{
int i;

if(debug_flag)
	{
	fprintf(stdout, "check_hash(): using pH=%02x arg signatur=", pH);
	for(i = 0; i < 8; i++)
		{
		fprintf(stdout, "%02x ", signatur[i]);
		}
	fprintf(stdout, "\n");
	}

hash(hashbuffer, hashkey, 0);

if(debug_flag)
	{
	fprintf(stdout, "check_hash(): arg hashbuffer=");
	for(i = 0; i < 8; i++)
		{
		fprintf(stdout, "%02x ", hashbuffer[i]);
		}
	fprintf(stdout, "\n");
	}

if (memcmp(signatur, hashbuffer, 8) == 0) return 1;
else return 0;
} /* end function check_hash */


int decrypt(\
int addressed_channel_id[],\
int key_index,\
int rx_message[],\
int rx_message_length,\
int decoded_word_1[],\
int decoded_word_2[],\
int P1)
{
int msg_pos;
int sub_msg_len;
int sub_msg_type;
int date[10];
int date_len;
int encrypted_bytes[32];
int encrypted_bytes_len;
int checksum[32];
int checksum_len;
int xxx[32];
int xxx_len;
byte work_space[16];
char *ptr;
byte preceding_bytes[8];
int encrypted_bytes_start;
int preceding_bytes_start;
int checksum_bytes_start;
int pos;
int a, b, c, i, j;
int key[MAX_KEY_SIZE];
unsigned char work_key[MAX_KEY_SIZE];
unsigned char cga_work_key[MAX_KEY_SIZE];
unsigned char signatur[8];
unsigned char prepared_key[8];
unsigned char tmp;
int SignatureOk;
unsigned char k;
unsigned char des_data1[8], des_data2[8];

if(debug_flag)
	{
	fprintf(stdout,\
	"decrypt(): arg\n\
	addressed_channel_id=%02x %02x %02x\n\
	key_index=%02x\n\
	rx_message=%lu\n\
	rx_message_length=%02x\n\
	P1=%02x\n",\
	addressed_channel_id[0],\
	addressed_channel_id[1],\
	addressed_channel_id[2],\
	key_index,\
	rx_message,\
	rx_message_length,\
	P1);
	}

if(key_index >= 0)
	{
	/* get the key from channels.dat */
	if(! get_key(addressed_channel_id, key_index, key) ) return 0;
	}
else if(key_index == -1) 
	{
	for(i = 0; i < 8; i++)
		{
		key[i] = vrx_key[i];
		}
	}
else if(key_index == -2)
	{
	for(i = 0; i < 8; i++)
		{
		key[i] = vry_key[i];
		}
	}
else return 0;

if(debug_flag)
	{
	fprintf(stdout, "decrypt(): key=");
	for(i = 0; i < 8; i++)
		{
		fprintf(stdout, "%02x ", key[i]);
		}
	fprintf(stdout, "\n");
	}

/* copy key to work_key */
for(i = 0; i < MAX_KEY_SIZE; i++)
	{
	work_key[i] = (unsigned char) key[i];
	}

/* clear buffers */
memset(des_data1, 0, 8);
memset(des_data2, 0, 8);

/* extract the various fields */
date_len = 0;
encrypted_bytes_len = 0;
checksum_len = 0;
xxx_len = 0;
msg_pos = 0;
/* for all sub messages in rx_message */
while(1)
	{
	sub_msg_type = rx_message[msg_pos];
	/* get sub message length */
	sub_msg_len = rx_message[msg_pos + 1];
	if(debug_flag)
		{
		printf(\
"decrypt(): rx_message_length=%02x sub_msg_type=%02x sub_msg_len=%02x\n",\
		rx_message_length, sub_msg_type, sub_msg_len);
		}

	switch(sub_msg_type)
		{
		case 0xe2:	/* date what is the meaning of the 3rd byte? */
//			rx_message[msg_pos + 2 + 2] = 0x15;
			for(i = 0; i < sub_msg_len; i++)
				{				
				date[i] = rx_message[msg_pos + 2 + i];
				date_len = sub_msg_len;
				}
			break;
		case 0xe4:	/* no idea, seen on ARAB NET */
			for(i = 0; i < sub_msg_len; i++)
				{				
				xxx[i] = rx_message[msg_pos + 2 + i];
				xxx_len = sub_msg_len;
				}
			break;
		case 0xea:	/* encrypted bytes */
			for(i = 0; i < sub_msg_len; i++)
				{				
				encrypted_bytes[i] = rx_message[msg_pos + 2 + i];
				encrypted_bytes_len = sub_msg_len;
				}
			/* 
			remember start of encrypted bytes in rxbuffer
			to be able to do hash later. 
			*/
			encrypted_bytes_start = msg_pos + 2;
			break;
		case 0xf0:	/* checksum */
			for(i = 0; i < sub_msg_len; i++)
				{				
				checksum[i] = rx_message[msg_pos + 2 + i];
				checksum_len = sub_msg_len;
				}
			checksum_bytes_start = msg_pos + 2;
			break;
		default: /* unknown submessage type */
			for(i = 0; i < sub_msg_len; i++)
				{				
				xxx[i] = rx_message[msg_pos + 2 + i];
				xxx_len = sub_msg_len;
				}
			break;
		} /* switch sub_msg_type */

	/* move to next position */
	msg_pos += sub_msg_len + 2;
		
	/* test for end of rx_message */
	if(msg_pos >= rx_message_length) break;
	} /* end if sub message indicator */

if(debug_flag)
	{
	fprintf(stdout, "decrypt(): date=");
	for(i = 0; i < date_len; i++)
		{
		fprintf(stdout, "%02x ", date[i]);
		}

	if(! show_date(date) ) return 0;

	fprintf(stdout, "decrypt(): xxx=");
	for(i = 0; i < xxx_len; i++)
		{
		fprintf(stdout, "%02x ", xxx[i]);
		}
	fprintf(stdout, "\n");

	fprintf(stdout, "decrypt(): encrypted_bytes=\n\t\t\t");
	for(i = 0; i < encrypted_bytes_len; i++)
		{
		fprintf(stdout, "%02x ", encrypted_bytes[i]);
		if(i == 7) fprintf(stdout, " ");
		}
	fprintf(stdout, "\n");

	fprintf(stdout, "decrypt(): checksum=");
	for(i = 0; i < checksum_len; i++)
		{
		fprintf(stdout, "%02x ", checksum[i]);
		}
	fprintf(stdout, "\n");

	} /* end if debug_flag */

if(debug_flag)
	{
	printf("decrypt():\n\
	encrypted_bytes_start=%02x\n\
	checksum_bytes_start=%02x\n",\
	encrypted_bytes_start, checksum_bytes_start);
	}

#ifdef SA_SEARCH
	current_channel_shared_card_address[0] = 0;
	current_channel_shared_card_address[1] = 0;
	current_channel_shared_card_address[2] = 8;
#endif /* SA_SEARCH */

if(P1 == 0)
	{
	/* init hash (sets hashbuffer to all zeros) */
	init_hash(work_key);
	}
else if(P1 == 1)
	{
try_sa:
	/* get the key as indicated by ca f8 */

	if(cga_key >= 0)
		{
                if (debug_flag)
        	      	printf("ca 88 01 *****cga_key=%02x\n", cga_key);

		/* get the key from channels.dat */
		if(! get_key(addressed_channel_id, cga_key, key) ) return 0;
		}

	if(debug_flag)
		{
		fprintf(stdout, "decrypt(): cga key=");
		for(i = 0; i < 8; i++)
			{
			fprintf(stdout, "%02x ", key[i]);
			}
		fprintf(stdout, "\n");
		}

	/* copy key to cga_work_key */
	for(i = 0; i < MAX_KEY_SIZE; i++)
		{
		cga_work_key[i] = (unsigned char) key[i];
		}

	/* init hashkey to cga_work_key and set pH to zero */
	pH = 0;
//	memset(hashbuffer, 0, 8);
	memcpy(hashkey, cga_work_key, 8);

#ifndef SA_SEARCH
	/* get shared address for this channel */
//	if(! set_shared(addressed_channel_id) ) return 0;
#endif /* SA_SEARCH */

	if(debug_flag)
		{
		printf("sa=%02x %02x %02x\n",\
		current_channel_shared_card_address[0],\
		current_channel_shared_card_address[1],\
		current_channel_shared_card_address[2]);

		printf("decrypt(): using shared=");
		for(i = 0; i < 4; i ++)
			{
			printf("%02x ", current_channel_shared_card_address[i]);
			}
		printf("\n");
		}

	/* put the shared address in bytes 5-7 of the hash buffer */
	hashbuffer[0] = 0;
	hashbuffer[1] = 0;
	hashbuffer[2] = 0;
	hashbuffer[3] = 0;
	hashbuffer[4] = 0;
	hashbuffer[5] = 0; //current_channel_shared_card_address[0];
	hashbuffer[6] = 0; //current_channel_shared_card_address[1];
	hashbuffer[7] = 0; //current_channel_shared_card_address[2];

	/* report for debug */
	if(debug_flag)
		{
		printf("decrypt(): hashbuffer=");
	
		for(i = 0; i < 8; i++)
			{
			printf("%02x ", hashbuffer[i]);
			}
		printf("\n");
		} /* end if debug_flag */

	/* print the cga_buffer */
	if(debug_flag)
		{
		fprintf(stdout, "decrypt(): cga_buffer=");
		for(i = 0; i < cga_p3; i++)
			{
			fprintf(stdout, "%02x ", cga_buffer[i]);
			}
		fprintf(stdout, "\n");

		printf("decrypt(): cga_p3=%02x\n", cga_p3);
		}

	/* now hash cga_p3 bytes from cga_buffer */
	for(i = 0; i < cga_p3; i++)
		{
		hash_byte( (unsigned char) cga_buffer[i] );	
		}

	/* final hash */
	if(pH)
		{
		hash(hashbuffer, hashkey, 0);
		pH = 0;
		}

	if(debug_flag)
		{
		printf("decrypt(): after hash: hashbuffer=");

		for(i = 0; i < 8; i++)
			{
			printf("%02x ", hashbuffer[i]);
			}
		printf("\n");
		} /* end if debug_flag */

	/* now the value in the hash buffer is our start point */

	/* ????? select the normal key for hashing */
//	pH = 0;

	/* get the normal key */
	if(! get_key(addressed_channel_id, key_index, key) ) return 0;

	/* copy key to work_key */
	for(i = 0; i < MAX_KEY_SIZE; i++)
		{
		work_key[i] = (unsigned char) key[i];
		}

	/* copy work_key to hashkey */
	memcpy(hashkey, work_key, 8);

	} /* end if P1 == 1 */

/* copy checksum signature */
for(i = 0; i < 8; i++)
	{
	signatur[i] = (unsigned char) checksum[i];
	}

/* copy encrypted bytes */
for(i = 0; i < 8; i++)
	{
	des_data1[i] = (unsigned char) encrypted_bytes[i];
	des_data2[i] = (unsigned char) encrypted_bytes[i + 8];
	}

/* key preparation */ 
if(work_key[7] == 0) 
	{
	//8th key-byte = 0 then like Eurocrypt-M but with viaccess mods

	/* calculate hash */
	for(i = 0; i < encrypted_bytes_start + 16; i++)
		{
		hash_byte( (unsigned char) rx_message[i] );
		}

	/* copy key as is */
	for(i = 0; i < 8; i++)
		{
		prepared_key[i] = (unsigned char) work_key[i];
		}
	}
else /* key8 not zero */
	{
	/* rotate the key 2x left */
	prepared_key[0] = (unsigned char) work_key[2];
	prepared_key[1] = (unsigned char) work_key[3];
	prepared_key[2] = (unsigned char) work_key[4];
	prepared_key[3] = (unsigned char) work_key[5];
	prepared_key[4] = (unsigned char) work_key[6];
	prepared_key[5] = (unsigned char) work_key[0];
	prepared_key[6] = (unsigned char) work_key[1];
	prepared_key[7] = (unsigned char) work_key[7];

	/* test if key8 odd */
	if(work_key[7] & 1)
		{
		/* calculate hash */
		for(i = 0; i < encrypted_bytes_start; i++)
			{
			hash_byte( (unsigned char) rx_message[i] );
			}

		/* test if low nibble zero */
		if( (work_key[7] & 0x0f) == 0) k = 0x5a;
		else k = 0xa5;

		for(i = 0; i < 8; i++)
			{
			tmp = des_data1[i];

			des_data1[i] = (k & get_actual_byte() ) ^ tmp;

			hash_byte( tmp );
			}

		for(i = 0; i < 8; i++)
			{
			tmp = des_data2[i];

			des_data2[i] = (k & get_actual_byte() ) ^ tmp;

			hash_byte( tmp );
			}
		} /* end if key8 odd */
	else /* even key, not zero */
		{
		/* calculate hash */
		for(i = 0; i < encrypted_bytes_start + 16; i++)
			{
			hash_byte( (unsigned char) rx_message[i] );
			}
		} /* end if key8 even and not zero */
	} /* end else if key8 not zero */

if(debug_flag)
	{
	fprintf(stdout, "decrypt modified key=");
	for(i = 0; i < 8; i ++)
		{
		fprintf(stdout, "%02x ", prepared_key[i]);
		}
	fprintf(stdout, "\n");

	fprintf(stdout, "decrypt des_data1=");
	for(i = 0; i < 8; i ++)
		{
		fprintf(stdout, "%02x ", des_data1[i]);
		}
	fprintf(stdout, "\n");

	fprintf(stdout, "decrypt des_data2=");
	for(i = 0; i < 8; i ++)
		{
		fprintf(stdout, "%02x ", des_data2[i]);
		}
	fprintf(stdout, "\n");
	}

decode(des_data1, prepared_key, 0);

decode(des_data2, prepared_key, 0);

/* check_hash() also does the final hash (always why?) */
SignatureOk = check_hash(signatur);
if (SignatureOk == 1)
	{
        if (debug_flag)
        	printf("Hash OK!\n");

#ifdef SA_SEARCH
	exit(0);
#endif /* SA_SEARCH */
	}
else
	{
        if (debug_flag)
        	printf("Hash Wrong! WRONG KEY?\n");

#ifdef SA_SEARCH
	current_channel_shared_card_address[0] ++;
	if(current_channel_shared_card_address[0] == 256)
		{
		current_channel_shared_card_address[0] = 0;
		current_channel_shared_card_address[1] ++;
		if( current_channel_shared_card_address[1] == 256)
			{
			current_channel_shared_card_address[1] = 0;
			current_channel_shared_card_address[2] ++;
			}
		if(current_channel_shared_card_address[2] == 256) exit(1);
		}

	goto try_sa;
#endif /* SA_SEARCH */

	/*
	returning 0 here causes a jump to start = wait reset
	also sometimes the pic is correctly decoded if the hash
	is wrong (NTV HTB)
	*/

	return 0;
	}

/* copy result */
for(i = 0; i < 8; i++)
	{
	decoded_word_1[i] = (int) des_data1[i];
	decoded_word_2[i] = (int) des_data2[i];
	}

return 1;
} /* end function decrypt */


int veason_algo_test(int key)
{
int i, j;
int decoded_word_1[128];
int decoded_word_2[128];
int channel_id[3];

if(debug_flag)
	{
	fprintf(stdout, "veason_algo_test(): arg none\n");
	}

/*
decrypt(
int addressed_channel_id[],\
int key_index,\
int rx_message[],\
int rx_message_length,\
int decoded_word_1[],\
int decoded_word_2[]\
P1)
*/

channel_id[0] = 0x00;
channel_id[1] = 0x01;
channel_id[2] = 0x02;

decrypt(\
	channel_id, key, avrx_buffer, 0x28, decoded_word_1, decoded_word_2, 0);

/* display all */
printf("decoded words are:\n");
for(i = 0; i < 8; i++)
	{
	printf("%02x ", decoded_word_1[i]);
	}

printf(" ");
for(i = 0; i < 8; i++)
	{
	printf("%02x ", decoded_word_2[i]);
	}
printf("\n");

printf("should be:\n41 54 00 5F 00 44 44 F7  44 05 45 48 15 11 41 D9\n");

printf("Ready\n");

return 1;
} /* end function decrypt */


