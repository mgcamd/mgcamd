#ifndef _VIEMU_H_
#define _VIEMU_H_

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

#include <termcap.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <asm/io.h>
#include <getopt.h>

//#include "des.h"

typedef unsigned char byte;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int  u32;


int debug_flag;
char *home_dir;

char *key_file_name;
int unique_card_address[5];

int current_channel;
int current_channel_id[3];
int current_channel_shared_card_address[4];
char *current_channel_name;
int line_counter;
int cga_buffer[1024];
int cga_key;
int cga_p3;

#define READSIZE	65535
#define TEMP_SIZE	4096

#define MAX_KEY_SIZE			8
#define MAX_KEYS_PER_CHANNEL	160
#define MAX_CHANNELS			1000

#define VERSION "0.5.5"

#endif
