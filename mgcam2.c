#include <fcntl.h>
#include <ost/ca.h>
#include <ost/dmx.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include "viemu_proto.h"

extern void Nagra_Decrypt(const byte *_data, const byte *_key, byte *_decrypted);
extern int Nagra_SigCheck(byte * block, byte * Sig, byte * Vkey, int rounds);
extern void Nagra_RSADecrypt(char * Data, char * KeySelect, char * ASCII_E1, char * ASCII_N1, char * ASCII_N2);

/* modify this line if you prefer a different language */
#define PREFERRED_LANGUAGE "eng"

#define SECA_CA_SYSTEM      0x100
#define VIACCESS_CA_SYSTEM  0x500
#define IRDETO_CA_SYSTEM    0x600
#define BETA_CA_SYSTEM     0x1700
#define NAGRA_CA_SYSTEM    0x1800

#define FROMHEX(c) ((c)>='a' ? (c)-'a'+10 : ((c)>='A' ? (c)-'A'+10 : (c)-'0'))

struct ECMINFO
{
  struct ECMINFO *next;
  char *name;
  int system;
  int ecm_pid;
  int id;
};

struct KEYINFO
{
  struct KEYINFO *next;
  char type;
  int id;
  int keynr;
  long long key;
};

struct EMMKEYINFO
{
  struct EMMKEYINFO *next;
  char type;
  int id;
  char name[4];
  char *key;
};

struct ECMINFO *ecminfos = 0;
struct KEYINFO *keyinfos = 0;
struct EMMKEYINFO *emmkeyinfos = 0;

static int debug = 0;

static volatile int running = 0;
static volatile int stop = 0;

static unsigned long crc_table[256] =
{
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b,
  0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 0x4c11db70, 0x48d0c6c7,
  0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
  0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 0xbe2b5b58, 0xbaea46ef,
  0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb,
  0xceb42022, 0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077, 0x30476dc0,
  0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4,
  0x0808d07d, 0x0cc9cdca, 0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
  0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc,
  0xb6238b25, 0xb2e29692, 0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050,
  0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34,
  0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 0x4f040d56, 0x4bc510e1,
  0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
  0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 0xf12f560e, 0xf5ee4bb9,
  0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd,
  0xcda1f604, 0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6, 0x9ff77d71,
  0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2,
  0x470cdd2b, 0x43cdc09c, 0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
  0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a,
  0x2d15ebe3, 0x29d4f654, 0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676,
  0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662,
  0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
};

static unsigned long crc32 (char *data,int len)
{
  unsigned long crc = 0xffffffff;
  int i;

  for (i=0; i<len; i++)
    crc = (crc << 8) ^ crc_table[((crc >> 24) ^ *data++) & 0xff];
  return crc;
}

/**
 * Read the key file.
**/
static int GetCardInfos()
{
  FILE *f;
  char c[128];
  char type;
  int id,keynr;
  long long key;
  struct KEYINFO *k,*n;

  f = fopen("SoftCam.Key","r");
  if (f == 0)
    f = fopen("/video/SoftCam.Key","r");
  if (f == 0)
    f = fopen("/opt/lib/SoftCam.Key","r");
  if (f == 0)
  {
    perror("SoftCam.Key");
    return -1;    
  }

  k = keyinfos;
  while (k != 0)
  {
    n = k->next;
    free(k);
    k = n;
  }
  keyinfos = 0;


  while (fgets(c,sizeof(c),f))
  {
    type = 0;
    if (sscanf(c,"%c %x %x %llx",&type,&id,&keynr,&key) != 4)
      continue;

    k = malloc(sizeof(struct KEYINFO));
    if (k == 0)
      return -1;

    k->next = keyinfos;
    k->type = type;
    k->id = id;
    k->keynr = keynr;
    k->key = key;

    keyinfos = k;
  }

   fclose(f);
   return 0;
}

/**
 * Load the RSA keys needed for Nagra.
**/
static void Nagra_LoadEMM()
{
  FILE *f;
  static char c[1024];
  char type;
  int id;
  static char name[1024];
  static char key[1024];
  struct EMMKEYINFO *k;

  if (emmkeyinfos != 0)
    return;

  f = fopen("AutoRoll.Key","r");
  if (f == 0)
    f = fopen("/video/AutoRoll.Key","r");
  if (f == 0)
    f = fopen("/opt/lib/AutoRoll.Key","r");
  if (f == 0)
  {
    perror("AutoRoll.Key");
    return;    
  }

  while (fgets(c,sizeof(c),f))
  {
    type = 0;
    if (sscanf(c,"%c %x %s %s",&type,&id,name,key) != 4)
      continue;

    k = malloc(sizeof(struct EMMKEYINFO));
    if (k == 0)
      return;

    k->key = malloc(strlen(key)+1);
    if (k->key == 0)
      return;

    k->next = emmkeyinfos;
    k->type = type;
    k->id = id;
    strncpy(k->name,name,4);
    strcpy(k->key,key);

    emmkeyinfos = k;
  }

  fclose(f);
}

/**
 * Set a filter for a DVB stream
**/
static void SetFilt(int fd,int pid,int tnr)
{
  struct dmxSctFilterParams FilterParams;

  memset(&FilterParams.filter.filter,0,DMX_FILTER_SIZE);
  memset(&FilterParams.filter.mask,0,DMX_FILTER_SIZE);

  if (tnr >= 0)
  {
    FilterParams.filter.filter[0] = tnr;
    FilterParams.filter.mask[0] = 0xff;
  }
  FilterParams.timeout = 15000;
  FilterParams.flags = DMX_IMMEDIATE_START;
  FilterParams.pid = pid;

  if (ioctl(fd,DMX_SET_FILTER,&FilterParams) < 0)
    perror("DMX SET SECTION FILTER");
}

/**
 * Stop a PID filter.
**/
static void StopFilt(int fd)
{
  ioctl(fd,DMX_STOP);
}

/**
 * Set the video and audio pids.
 * This seems to cure problems with the audio decoding.
 * Also it allows us to automatically select the English 
 * audio channel if there is a choice.
 *
 * This will fail if another program (or the same program) has already
 * got a handle open that it has used to set the video or audio pid.
 * It will only work if any other tuning program in use follows the
 * strategy of opening a handle, setting the pids and then closing the
 * handle. This is turn will only work if the driver has been loaded with
 * the "pids_off" parameter set to 0. Still, it fixed the problem for me.
**/
static void SetPids(int fd,int vpid,int apid)
{
  struct dmxPesFilterParams pesFilterParams;
  dvb_pid_t pids[5];

  /* get the current PID settings */
  if (ioctl(fd,DMX_GET_PES_PIDS,&pids))
  {
    perror("GET PIDS");
    return;
  }

  /* fix the video PID if it is wrong */
  if (vpid!=0 && vpid!=(pids[1]&0x1fff))
  {
    int f = open("/dev/ost/demux",O_RDWR|O_NONBLOCK);

    printf("Setting vpid %x\n",vpid);

    pesFilterParams.pid = vpid;
    pesFilterParams.input = DMX_IN_FRONTEND;
    pesFilterParams.output = DMX_OUT_DECODER;
    pesFilterParams.pesType = DMX_PES_VIDEO;
    pesFilterParams.flags = DMX_IMMEDIATE_START;
    ioctl(f,DMX_SET_PES_FILTER,&pesFilterParams);

    close(f);
  }

  /* reset the audio PID even if it is already OK */
  /* this seems to help cure the "missing audio" bug */
  if (apid!=0 /* && apid!=(pids[0]&0x1fff)*/)
  {
    int f = open("/dev/ost/demux",O_RDWR|O_NONBLOCK);

    printf("Setting apid %x\n",apid);

    pesFilterParams.pid = apid;
    pesFilterParams.input = DMX_IN_FRONTEND;
    pesFilterParams.output = DMX_OUT_DECODER;
    pesFilterParams.pesType = DMX_PES_AUDIO;
    pesFilterParams.flags = DMX_IMMEDIATE_START;
    ioctl(f,DMX_SET_PES_FILTER,&pesFilterParams);

    close(f);
  }
}

/**
 * Read with timeout.
**/
static int read_t(int fd,byte *buffer,int length,int cks)
{
  /*
  struct pollfd u[1];

  u[0].fd = fd;
  u[0].events = POLLIN;

  if (poll(u,1,20000) <= 0)
  {
    printf("Timeout\n");
    return -1;
  }

  buffer[0] = 0;
  return read(fd,buffer+1,length-1)+1;
  */

  struct pollfd u[1];
  int retries;
  int n,l;

  for (retries=0;retries<100;retries++)
  {
    u[0].fd = fd;
    u[0].events = POLLIN;

    n = poll(u,1,20000);
    if (n < 0)
    {
      perror("poll error");
      return -1;
    }
    if (n == 0)
    {
      fprintf(stderr,"timeout\n");
      return -1;
    }

    buffer[0] = 0;

    n = read(fd,buffer+1,length-1);
    if (n < 0)
    {
      perror("read error");
      return -1;
    }

    if (cks && crc32(buffer+1,n) != 0)
    {
      fprintf(stderr,"crc error\n");
      continue;
    }

    break;
  }

  return n+1;
}

/**
 * Parse the PAT to get the PMT.
**/
static int ParsePAT(int fd,int program_number,int *pid)
{
  byte buffer[4096];
  int length,index;
  int n;

  *pid = 0;

  /* The PAT is supposed to fit in a 184 bytes packet */
  printf("Reading PAT ...\n");
  SetFilt(fd,0,0);
  do
  {
    n = read_t(fd,buffer,sizeof(buffer),1);
  }
  while (n>=2 && (buffer[0]!=0 || buffer[1]!=0));
  StopFilt(fd);

  if (n < 2)
    return -1;

  printf("Analyzing PAT ...\n");
  length = ((buffer[2] & 0x0F) << 8) | buffer[3];
  for (index=9; index<length-4 && index<184; index +=4)
  {
    int p = (buffer[index] << 8) | buffer[index+1];

    if (debug)
      printf("Found program number %d\n",p);

    if (program_number == p)
    {
      *pid = ((buffer[index+2] << 8) | buffer[index+3]) & 0x1FFF;
      break;
    }
  }

  if (*pid == 0)
  {
    printf ("Program number %d not in PAT\n", program_number);
    return -1;
  }

  printf("Program number: %d PMT pid: %x\n",program_number,*pid);
  return 0;
}

/**
 * Parse CA descriptor
**/
static void ParseCADescriptor (byte *data,int length)
{
  static char *seca_name = "Seca";
  static char *viaccess_name = "Viaccess";
  static char *nagra_name = "Nagra";
  static char *irdeto_name = "Irdeto";

  int ca_system;
  int j;

  struct ECMINFO *e;

  if (debug)
  {
    printf("ca_descr");
    for (j=0; j<length; j++) printf(" %02x",data[j]);
    printf("\n");
  }

  /* only test the upper 8 bits of the ca_system */
  ca_system = (data[0] << 8) /* | data[1]*/;

  switch (ca_system)
  {
    case SECA_CA_SYSTEM:
      for (j=2; j<length; j+=15)
      {
        e = malloc(sizeof(struct ECMINFO));
        if (e == 0)
          return;
        e->system = ca_system;
        e->name = seca_name;
        e->ecm_pid = ((data[j] & 0x1f) << 8) | data[j+1];
        e->id = (data[j+2] << 8) | data[j+3];
        e->next = ecminfos;
        ecminfos = e;
        printf("Found seca id %04x\n",e->id);
      }        
      break;
    case VIACCESS_CA_SYSTEM:
      j = 4;
      while (j < length)
      {
        if (data[j]==0x14)
        {
          e = malloc(sizeof(struct ECMINFO));
          if (e == 0)
            return;
          e->system = ca_system;
          e->name = viaccess_name;
          e->ecm_pid = ((data[2] & 0x1f) << 8) | data[3];
          e->id = (data[j+2] << 16) | (data[j+3] << 8) | (data[j+4] & 0xf0);
          e->next = ecminfos;
          ecminfos = e;
          printf("Found viaccess id %04x\n",e->id);
        }
        j += 2+data[j+1];
      }
      break;
    case IRDETO_CA_SYSTEM:
    case BETA_CA_SYSTEM:
      e = malloc(sizeof(struct ECMINFO));
      if (e == 0)
        return;
      e->system = ca_system;
      e->name = irdeto_name;
      e->ecm_pid = ((data[2] & 0x1f) << 8) | data[3];
      e->next = ecminfos;
      ecminfos = e;
      printf("Found irdeto\n");
      break;
    case NAGRA_CA_SYSTEM:
      e = malloc(sizeof(struct ECMINFO));
      if (e == 0)
        return;
      e->system = ca_system;
      e->name = nagra_name;
      e->ecm_pid = ((data[2] & 0x1f) << 8) | data[3];
      e->next = ecminfos;
      ecminfos = e;
      printf("Found nagra\n");
      break;
  }
}

/**
 * Parse PMT to get ECM PID
**/
static int ParsePMT(int fd,int program_number,int pmt_pid)
{
  byte buffer[4096];
  int length,info_len,data_len,index;
  int retries;
  int pid;
  int n,i;

  int vpid = 0;
  int apid = 0;
  int preferred_apid = 0;
  int pnr = -1;

  printf("Analyzing PMT (PID = %x)...\n", pmt_pid);
  SetFilt(fd,pmt_pid,2);

  for (retries=0; retries<100; retries++)
  {
    do
    {
      n = read_t(fd,buffer,sizeof(buffer),1);
    }
    while (n>=2 && (buffer[0]!=0 || buffer[1]!=0x02));
   
    length = ((buffer[2] & 0x0F) << 8) | buffer[3];
    if (length+4 > sizeof(buffer))
      n = -1;

    if (n < 2)
      break;

    pnr = (buffer[4]<<8) + buffer[5];
    if (pnr == program_number)
      break;
  }

  StopFilt(fd);

  if (pnr != program_number)
  {
    printf("Can't find PMT entry\n");
    return -1;
  }

  index = 11;
  info_len = ((buffer[index] & 0x0F) << 8) + buffer[index+1];
  index += 2;

  while (info_len > 0)
  {
    if (buffer[index] == 0x09)
      ParseCADescriptor(&buffer[index+2], buffer[index+1]);

    info_len -= 2+buffer[index+1];
    index += 2+buffer[index+1];
  }

  while (index < length-4)
  {
    pid = ((buffer[index+1] & 0x1f) << 8) + buffer[index+2];

    if (buffer[index]==2 && vpid==0)
      vpid = pid;    
    else
    if ((buffer[index]==3 || buffer[index]==4) && apid==0)
      apid = pid;    

    data_len = ((buffer[index+3] & 0x0F) << 8) + buffer[index+4];
    if (buffer[index]==0x02 || buffer[index]==0x03 || buffer[index]==0x04)
    {
      i = index+5;
      while (i < index+5+data_len)
      {
        switch (buffer[i])
        {
          case 0x0a:
            if (buffer[index]==3 || buffer[index]==4)
            {
              printf("Language = %.3s\n",&buffer[i+2]);
              if (memcmp(&buffer[i+2],PREFERRED_LANGUAGE,3)==0)
                preferred_apid = pid;
            }
            break;
          case 0x09:
            ParseCADescriptor(&buffer[i+2],buffer[i+1]);
            break;
        }
        i += 2 + buffer[i+1];
      }
    }
    index += 5 + data_len;
  }

  if (preferred_apid != 0)
    apid = preferred_apid;

  SetPids(fd,vpid,apid);

  return 0;
}

/**
 * Write the control words to the firmware
**/
static void write_control_words(int ca,byte *buffer,int index)
{
  static byte xor[8] = {0x55,0x55,0xaa,0xaa,0x99,0x99,0xbb,0xbb};
  ca_descr_t ca_descr;
  long long ecw,ocw;
  struct KEYINFO *k;
  byte *p;
  int i;

  for (i=0; i<16; i+=4)
    buffer[i+3] = buffer[i]+buffer[i+1]+buffer[i+2];

  if (debug)
  {
    ecw = ocw = 0;
    for (i=0; i<8; i++)
    {
      ecw= (ecw << 8) | buffer[i];
      ocw= (ocw << 8) | buffer[i+8];
    }
    printf("Even control word = %016llx\nOdd  control word = %016llx\n",ecw,ocw);
  }

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='X' || k->type=='x') && k->id==0 && k->keynr==0)
      break;

    k = k->next;
  }

  if (k != 0)
  {
    if (debug) printf("XOR ctrl word with  %016llx\n",k->key);

    p = (byte *)&k->key;
    for (i=0; i<8; i++)
    {
      buffer[i] ^= p[7-i];
      buffer[i+8] ^= p[7-i];
    }
  }

  if (ca < 0)
    return;

  ca_descr.index = index;
  ca_descr.parity = 0;
  for (i=0; i<8; i++)
    ca_descr.cw[i] = buffer[i];
  if (ioctl(ca,CA_SET_DESCR,&ca_descr) < 0)
    perror("CA_SET_DESCR");

  ca_descr.index = index;
  ca_descr.parity = 1;
  for (i=0; i<8; i++)
    ca_descr.cw[i] = buffer[i+8];
  if (ioctl(ca,CA_SET_DESCR,&ca_descr) < 0)
    perror("CA_SET_DESCR");
}

/**
 * Decode SECA using the provider we found in the PMT
 * Return 0 for success, -1 for error (missing key, bad signature etc)
**/
static int seca_decode(int ca,byte *source,int length,int id,int keynr)
{
  int param,extra;
  struct KEYINFO *k;
  byte signature[8];
  byte keys[16];
  byte *p;
  int i,j;

  byte *data = 0;

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='S' || k->type=='s') && k->id==id && k->keynr==keynr)
      break;

    k = k->next;
  }

  if (k == 0)
  {
    printf("No seca key found for id %04x keynr %02x\n",id,keynr);
    return -1;
  }

  if (debug) printf("Using key %c %04x %02x %016llx\n",k->type,k->id,k->keynr,k->key);

  p = (byte *)&k->key;
  for (i=0; i<8; i++)
    keys[i] = keys[i+8] = p[7-i];

  memset(signature,0,8);
  for (i=0; i<length-8; i+=8)
  {
    for (j=0; j<8 && i+j<length-8; j++)
      signature[j] ^= source[i+j];

    encrypt_seca(keys,signature);
  }

  i = 0;
  while (i<length)
  {
    param = source[i++];
    extra = (param >> 4) & 0x0f;
    switch (extra)
    {
      case 0x0d:
        extra = 0x10;
        break;
      case 0x0e:
        extra = 0x18;
        break;
      case 0x0f:
        extra = 0x20;
        break;
    }

    switch (param)
    {
      case 0xd1:
        data = &source[i];
        break;
      case 0x82:
        if (memcmp(&source[i],signature,8) != 0)
          return -1;
        break;
    }

    i += extra;
  }

  if (data == 0)
    return -1;

  decrypt_seca(&keys[0],&data[0]);
  decrypt_seca(&keys[0],&data[8]);
  write_control_words(ca,&data[0],0);
  return 0;
}

/**
 * Decode VIACCESS using the provider we found in the PMT
 * Return 0 for success, -1 for error (missing key, bad signature etc)
**/
static int viaccess_decode(int ca,byte *source,int length,int P1,int id,int keynr)
{
  int receiver_channel_id[3];
  int decoded_word[16];
  int rx_message[184];
  byte data[16];
  int i;

  receiver_channel_id[0] = id;

  for (i=0; i<length; i++)
    rx_message[i] = source[i];

  cga_key = keynr;
  if (decrypt(receiver_channel_id,keynr,rx_message,length,&decoded_word[0],&decoded_word[8],P1))
  {
    for (i=0; i<16; i++)
      data[i] = decoded_word[i];
    write_control_words(ca,&data[0],0);

    return 0;
  }

  return -1;
}

/**
 * The viaccess decrypt() method calls this to get the key.
 * We pass the channel id in the first entry in the array
 * instead of splitting it up into 3 bytes.
**/
int get_key(int receiver_channel_id[], int key_index, int key[])
{
  struct KEYINFO *k;
  byte *p;
  int i;

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='V' || k->type=='v') && k->id==receiver_channel_id[0] && k->keynr==key_index)
      break;

    k = k->next;
  }

  if (k == 0)
  {
    printf("No viaccess key found for id %06x keynr %02x\n",receiver_channel_id[0],key_index);
    return 0;
  }

  if (debug) printf("Using key %c %06x %02x %016llx\n",k->type,k->id,k->keynr,k->key);

  p = (byte *)&k->key;
  for (i=0; i<8; i++)
    key[i] = p[7-i];

  return 1;
}

/**
 * The viaccess decrypt() calls this too.
**/
int show_date(int date[])
{
  return 1;
}

/**
 * Decode IRDETO
 * Return 0 for success, -1 for error (missing key, bad signature etc)
**/
static int irdeto_decode(int ca,byte *source,int length,int id)
{
  int param,extra;
  byte sessionKey[8];
  struct KEYINFO *k;
  unsigned char *p;
  byte save[16];
  int keynr;
  int i,j;

  byte *data = 0;
  int date = -1;

  i = 6;
  while (i<length-5)
  {
    param = source[i++];
    extra = source[i++] & 0x3f;

    switch (param)
    {
      case 0x78:
        keynr = source[i];
        data = &source[i+2];
        break;
      case 0x00:
      case 0x40:
        date = (source[i]<<8) | source[i+1];
        break;
    }

    i += extra;

    /* look no further if we've got everything we need */
    /* (in case the Dutch Canal + sends more crap to confuse us) */
    if (data != 0 && date != -1)
      break;
  }

  if (data==0 || date==-1)
    return -1;

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='I' || k->type=='i') && k->id==id && k->keynr==keynr)
    {
      p = (byte *)&k->key;
      for (i=0; i<8; i++)
        sessionKey[i] = p[7-i];

      /* save the encrypted data */
      memcpy(save,data,16);

      sessionKeyCrypt(&data[0],sessionKey,date);
      sessionKeyCrypt(&data[8],sessionKey,date);
      if (signatureCheck(source,length-5,sessionKey,date,&source[length-5]))
      {
        if (debug) printf("Using key %c %02x %02x %016llx\n",k->type,k->id,k->keynr,k->key);
        write_control_words(ca,&data[0],0);
        return 0;
      }

      /* put back the encrypted data if it didn't work */
      memcpy(data,save,16);
    }

    k = k->next;
  }

  printf("No irdeto key found for id %02x keynr %02x\n",id,keynr);
  return -1;
}

static void WriteNagraTable(byte *to,byte *from,int off)
{
  if (off+16 <= 256)
    memcpy(to+off,from,16);
  else
  {
    int l = 256-off;
    memcpy(to+off,from,l);
    memcpy(to,from+16-l,16-l);
  }
}

/**
 * Decode NAGRA
 * Return 0 for success, -1 for error (missing key, bad signature etc)
**/
static int nagra_decode(int ca,byte *data,int len)
{
  static byte Nagra_MECMTable[256];

  byte decrypted[128];
  byte sessionKey[8];
  byte verifyKey[8];
  byte cws[16];
  struct KEYINFO *k;
  int block;
  byte *p;
  int i;
  
  int id = (data[0] & 0xFE) *256 + data[1];
  int keynr = (data[4] & 0x10) >> 4;
  byte *pvalidhash = data + 5;
  byte *pdata = pvalidhash + 8;
  int plen = len-5-8;
  int hasvkey = 0;

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='N' || k->type=='n') && k->id==id && k->keynr==0x80)
      break;

    k = k->next;
  }

  if (k != 0)
  {
    if (debug) printf("Using  verify key %c %04x %02x %016llx\n",k->type,k->id,k->keynr,k->key);

    p = (byte *)&k->key;
    for (i=0; i<8; i++)
      verifyKey[i] = p[7-i];

    hasvkey = 1;
  }

  k = keyinfos;
  while (k != 0)
  {
    if ((k->type=='N' || k->type=='n') && k->id==id && k->keynr==keynr)
      break;

    k = k->next;
  }

  if (k == 0)
  {
    printf("No nagra key found for id %04x keynr %02x\n",id,keynr);
    return -1;
  }

  if (debug) printf("Using decrypt key %c %04x %02x %016llx\n",k->type,k->id,k->keynr,k->key);

  p = (byte *)&k->key;
  for (i=0; i<8; i++)
    sessionKey[i] = p[7-i];

  for (block=0; block<plen/8; block++)
    Nagra_Decrypt(pdata+block*8,sessionKey,decrypted+block*8);

  if (decrypted[0]!=0x10 && decrypted[0]!=0x11 && decrypted[0]!=0x12)
    return -1;

  if (hasvkey && !Nagra_SigCheck(decrypted,pvalidhash,verifyKey,plen/8))
  {
    printf("Maybe bad verify key\n");
    return -1;
  }

  if (len>data[3]+4)
  {
    byte mecmdata[128];
    byte *pmecm = data+data[3]+4;
    int plenmecm = pmecm[1];
    int mecm_ok = 0;

    if (*pmecm==0x20)
    {
      char asciidata[128*2]="";
      unsigned short mecmprovid = pmecm[2]*256+pmecm[3];
      int tableoffset = pmecm[5];
      char keyselect[10];

      char *e1 = 0;
      char *n1 = 0;
      char *n2 = 0;
      char *v = 0;
      struct EMMKEYINFO *ek;

      ek = emmkeyinfos;
      while (ek != 0)
      {
        if ((ek->type=='N' || ek->type=='n') && ek->id==mecmprovid)
        {
          if (strcmp(ek->name,"E1") == 0)
            e1 = ek->key;
          if (strcmp(ek->name,"N1") == 0)
            n1 = ek->key;
          if (strcmp(ek->name,"N2") == 0)
            n2 = ek->key;
        }

        ek = ek->next;
      }

      if (e1==0 || n1==0 || n2==0)
      {
        printf("Nagra RSA key not found for id %04x\n",mecmprovid);
        return -1;
      }

      sprintf(keyselect,"%2X",pmecm[4]);
      for (i=0; i<plenmecm-4; i++)
        sprintf(asciidata+i*2,"%02X",pmecm[i+6]);

      Nagra_RSADecrypt(asciidata,keyselect,e1,n1,n2);

      for (i=0; i<plenmecm-4; i++)
        mecmdata[i] = FROMHEX(asciidata[i*2])*16+FROMHEX(asciidata[i*2+1]);
      if (mecmdata[0]==0x2F && mecmdata[1]==pmecm[2] && mecmdata[2]==pmecm[3])
      {
        WriteNagraTable(Nagra_MECMTable,mecmdata+4,mecmdata[3]*2);
        mecm_ok = 1;
      }
    }

    if (debug && !mecm_ok)
      printf("Error receiving MECM key\n");
  }

  if (decrypted[1] < 0x80)
  {
    for (i=0; i<8; i++)
      decrypted[i+2] ^= Nagra_MECMTable[decrypted[1]*2+i];
  }
  if (decrypted[10] < 0x80)
  {
    for (i=0; i<8; i++)
      decrypted[i+11] ^= Nagra_MECMTable[decrypted[10]*2+i];
  }

  memcpy(cws,decrypted+11,8);
  memcpy(cws+8,decrypted+2,8);
  write_control_words(ca,cws,0);
  return 0;
}

/**
 * Process a record we've read from the ECM PID
 * If we can't decode with this ECM, we will try a different one next time
**/
static int process(int ca,struct ECMINFO *ecm,byte *buffer)
{
  switch (ecm->system)
  {
    case SECA_CA_SYSTEM:
      return seca_decode(ca,&buffer[9],buffer[3]-5,ecm->id,buffer[8] & 0x0f);
    case VIACCESS_CA_SYSTEM:
      return viaccess_decode(ca,&buffer[10],buffer[3]-6,buffer[4],ecm->id,buffer[9] & 0x0f);
    case IRDETO_CA_SYSTEM:
    case BETA_CA_SYSTEM:
      return irdeto_decode(ca,&buffer[7],buffer[12]+6,buffer[9]);
    case NAGRA_CA_SYSTEM:
      return nagra_decode(ca,&buffer[6],buffer[5]);
  }

  return -1;
}

void ca_process(int ca,int fd,int program_number)
{
  struct ECMINFO *e;
  byte buffer[184];
  int decoded_ok;
  int ecm_is_ok;
  int pmt_pid;
  int parity;
  int n,i;

  running = 1;

  if (GetCardInfos())
    goto exit;

  Nagra_LoadEMM();

  sleep(1);

  ecminfos = 0;

  if (ParsePAT(fd,program_number,&pmt_pid))
    goto exit;

  if (ParsePMT(fd,program_number,pmt_pid))
    goto exit;

  if (ecminfos==0)
  {
    printf("No supported encryption system found\n");
    goto exit;
  }

  e = ecminfos;
  SetFilt(fd,e->ecm_pid,-1);

  if (debug)
    printf("Try system %s id %x ecm %x\n",e->name,e->id,e->ecm_pid);

  parity = 0xff;
  ecm_is_ok = 0;
  while (!stop)
  {
    decoded_ok = 1;

    n = read_t(fd,buffer,184,0);
    if ((n > 0) && (buffer[1] == 0x80 || buffer[1] == 0x81))
    {
      if (parity != (buffer[1] & 1))
      {
        parity = buffer[1] & 1;

        if (debug)
        {
          printf("ca_data ");
          for (i=0; i<n && i<buffer[3]+4; i++)
            printf(" %02x",buffer[i]);
          printf("\n");
          fflush(stdout);
        }

        if (process(ca,e,buffer))
        {
          printf("Missing or wrong key\n");
          decoded_ok = 0;
        }
        else
        {
          /* once we've found an ECM PID that works, we stick with it */
          if (!ecm_is_ok)
            printf("Correct key found\n");
          ecm_is_ok = 1;
        }
      }
    }
    else
      decoded_ok = 0;

    if (!decoded_ok)
    {
      /* re-read the keys, in case they have changed */
      GetCardInfos();

      /* if this ECM PID worked before, it must be OK, and the */
      /* broadcaster is just sending a bad message out of malice */
      if (!ecm_is_ok)
      {
        /* but if this ECM PID never worked, we've probably */
        /* got the wrong one, so let's try another */
        StopFilt(fd);
        e = e->next;

        /* when we've tried them all, go back and start again */
        /* in case one of them was OK but the broadcaster was */
        /* sending a fake message when we happened to try it */
        if (e == 0)            
        {
          e = ecminfos;
          sleep(1);
        }

        SetFilt(fd,e->ecm_pid,-1);
        if (debug)
          printf("Try system %s id %x ecm %x\n",e->name,e->id,e->ecm_pid);
      }
      parity = 0xff;
    }
  }

exit:
  StopFilt(fd);
  running = 0;
}

void ca_stop()
{
  struct ECMINFO *e,*n;

  if (running)
  {
    stop = 1;
    while (running)
      sleep(1);
  }
  stop = 0;

  e = ecminfos;
  while (e != 0)
  {
    n = e->next;
    free(e);
    e = n;
  }
  ecminfos = 0;
}

#ifdef WITH_MAIN

/**
 * Find the video pid for this program number.
**/
static int find_video_pid(int fd,int pmt_pid,int program_number)
{
  byte buffer[4096];
  int length,info_len,data_len,index;
  int retries;
  int pid;
  int n,i;

  int vpid = 0;
  int pnr = -1;

  printf("Analyzing PMT (PID = %x)...\n", pmt_pid);
  SetFilt(fd,pmt_pid,2);
  for (retries=0; retries<100; retries++)
  {
    do
    {
      n = read_t(fd,buffer,sizeof(buffer),0);
    }
    while (n>=2 && (buffer[0]!=0 || buffer[1]!=0x02));

    length = ((buffer[2] & 0x0F) << 8) | buffer[3];
    if (length+4 > sizeof(buffer))
      n = -1;

    if (n < 2)
      break;

    pnr = (buffer[4]<<8) + buffer[5];
    if (pnr == program_number)
      break;
  }

  StopFilt(fd);

  if (pnr != program_number)
  {
    printf("Can't find PMT entry\n");
    return -1;
  }

  index = 11;
  info_len = ((buffer[index] & 0x0F) << 8) + buffer[index+1];
  index += 2 + info_len;

  while (index < length-4)
  {
    pid = ((buffer[index+1] & 0x1f) << 8) + buffer[index+2];
    if (buffer[index]==2 && vpid==0)
      vpid = pid;    

    data_len = ((buffer[index+3] & 0x0F) << 8) + buffer[index+4];
    index += 5 + data_len;
  }

  return vpid;
}

/**
 * Discover the program number from the currently-tuned video pid.
**/
static int find_program_number(int fd,int vpid)
{
  byte buffer[4096];
  int length,index;
  int n;

  int prognr = -1;

  /* The PAT is supposed to fit in a 184 bytes packet */
  printf("Reading PAT ...\n");
  SetFilt(fd,0,0);
  do
  {
    n = read_t(fd,buffer,sizeof(buffer),1);
  }
  while (n>=2 && (buffer[0]!=0 || buffer[1]!=0));
  StopFilt(fd);

  if (n < 2)
    return -1;

  printf("Analyzing PAT ...\n");
  length = ((buffer[2] & 0x0F) << 8) | buffer[3];
  for (index=9; index<length-4 && index<184; index +=4)
  {
    int pnr = (buffer[index] << 8) | buffer[index+1];
    int pmt = ((buffer[index+2] << 8) | buffer[index+3]) & 0x1FFF;

    if (pnr != 0)
    {
      int pid = find_video_pid(fd,pmt,pnr);

      if (debug)
        printf("Found program number %d video pid %d\n",pnr,pid);

      if (pid == vpid)
      {
        prognr = pnr;
        break;
      }
    }
  }

  return prognr;
}

int main(int argc,char **argv)
{
  int fd,ca,program_number;

  debug = 1;

  if ((fd = open("/dev/ost/demux",O_RDWR|O_NONBLOCK)) < 0)
  {
    perror("DEMUX DEVICE");
    return -1;
  }

  if ((ca = open("/dev/ost/ca",O_RDWR|O_NONBLOCK)) < 0)
  {
    perror("CA DEVICE");
    return -1;
  }

  if (argc >= 2)
    program_number=atoi(argv[1]);
  else
  {
    dvb_pid_t pids[5];

    if (ioctl(fd,DMX_GET_PES_PIDS,&pids) < 0)
    {
      perror("Unable to read pids");
      return -1;
    }

    program_number = find_program_number(fd,pids[1] & 0x1fff);
  }

  ca_process(ca,fd,program_number);

  close(fd);
  close(ca);
  return 0;
}

/*

int main(int argc,char **argv)
{
  char c[1024];
  byte b[1024];
  FILE *f;
  int i,j;

  debug = 1;

  GetCardInfos();
  Nagra_LoadEMM();

  f = fopen("input","r");
  if (f == 0)
  {
    printf("No input file\n");
    return -1;
  }

  while (fgets(c,sizeof(c),f))
  {
    if (memcmp(c,"ca_data ",8) == 0)
    {
      i = 8;
      j = 0;

      while (c[i] != 0)
      {
        while (c[i]==' ')
          i++;

        b[j] = 0;
        while (c[i]>='0' && c[i]<='f')
        {
          b[j] = (b[j]<<4) | FROMHEX(c[i]);
          i++;
        }
        j++;
      }

      printf("ca_data ");
      for (i=0; i<j && i<b[3]+4; i++)
        printf(" %02x",b[i]);
      printf("\n");

      nagra_decode(-1,&b[6],b[5]);
    }
  }

  fclose(f);
  return 0;
}

*/

#endif
