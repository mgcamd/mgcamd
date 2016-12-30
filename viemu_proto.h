#ifndef _VIEMU_PROTO_H_
#define _VIEMU_PROTO_H_

#include "viemu.h"

#include "viemu_proto.h"

extern char *get_channel_name(int channel_id[]);
extern int viaccess_algo(\
	byte key[], byte preceding_bytes[], byte work_space[]);
extern int show_date(int date[]);
extern int update_key(int addressed_channel_id[], int rx_message[],\
	int mk, int rx_message_length);
extern int process_address(\
	int addressed_channel_id[], int buffer[], int length);
extern int beep_n_times(int n, int delay);
extern int get_active_provider_id(char *channel_id_hex_string);

extern int set_port_parameters(int fd, int baudrate, char *device);
extern int get_reset(char *device, int *state);
extern int set_rts(char *device, int state);
extern int log(char *filename, char *text);
extern int to_decoder(char *hex_string);
extern int from_decoder(int *buffer, int length);
extern int send_ok();
extern int sened_error();

extern struct channel *lookup_channel(char *name);
extern struct channel *install_channel_at_end_of_list(char *name);
extern int delete_channel(char *name);
extern int delete_all_channels();
extern int load_channels();
extern int save_channels();
extern int clear_channel();
extern int increment_channel();
extern int set_channel(int channel);
extern int select_channel_zero();
extern char *get_channel_list(int *message_length);
extern int get_key(int receiver_channel_id[], int key_index, int key[]);

extern char *strsave(char *s);
extern int readline(FILE *file, char *contents);

extern int inverse_character(int value, int *result);
extern int inverse_message(char *message);

extern int decrypt(\
	int receiver_channel_id[],\
	int key_index,\
	int rx_message[],\
	int rx_message_length,\
	int decoded_word_1[],\
	int decoded_word_2[],\
	int P1);

extern rtsoff(int port);
extern rs232_rxstatus(int channel);
extern rs232_txstatus(int channel);
extern rs232_send(int channel, int txchar);
extern rs232_receive(int channel);
extern rs232_flush(int channel);
extern int rs232_init(\
	int chan, long baudrate, char parity, int stopbit, int wordlen);
extern int  rs232_putc(int chan, int c);
extern int  rs232_getc(int chan);
extern void rs232_prot(int chan, int prot);
extern int rs232_setbaudrate(int channel, long baudrate);

extern void EuroDes(\
	byte key1[], byte key2[], byte desMode, byte operatingMode,\
	byte data[]);

extern void ViaDes(byte key[], byte data[]);

#endif /* _VIEMU_PROTO_H_ */
