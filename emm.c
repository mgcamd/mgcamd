#include <errno.h>
#include <fcntl.h>
#include <ost/ca.h>
#include <ost/dmx.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#define SECA_CA_SYSTEM      0x100
#define VIACCESS_CA_SYSTEM  0x500
#define IRDETO_CA_SYSTEM    0x600
#define BETA_CA_SYSTEM     0x1700
#define NAGRA_CA_SYSTEM    0x1800

#define SECTION  1
#define CHECKSUM 2
#define ONE_SHOT 4

#define FROMHEX(c) ((c)>='a' ? (c)-'a'+10 : ((c)>='A' ? (c)-'A'+10 : (c)-'0'))

typedef unsigned char byte;
typedef void (*HANDLER)(byte *,int);

struct READER
{
  struct READER *next;
  int flags;
  int filenr;
  HANDLER handler;
  byte *buffer;
  int bufsize;
};

struct KEYINFO
{
  struct KEYINFO *next;
  char type;
  int id;
  int keynr;
  long long key;
  char *string;
};

struct EMMKEYINFO
{
  struct EMMKEYINFO *next;
  char type;
  int id;
  char name[4];
  char *key;
};

static struct KEYINFO *keyinfos;
static struct EMMKEYINFO *emmkeyinfos;

static void add_reader(HANDLER handler,int bufsize,int flags,int pid,int tnr);
static void remove_reader(struct READER *reader);

extern int Nagra_DecryptEMM(byte *EMM,char *ASCII_VKey,char *ASCII_E1,char *ASCII_N1,char *ASCII_N2);

static struct READER *readers;

static int debug;

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

static void set_section_filter(int fd,int pid,int tnr)
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

static void set_pes_filter(int fd,int pid)
{
  struct dmxPesFilterParams FilterParams;

  FilterParams.input = DMX_IN_FRONTEND;
  FilterParams.output = DMX_OUT_TAP;
  FilterParams.pesType = DMX_PES_OTHER;
  FilterParams.pid = pid;
  FilterParams.flags = DMX_IMMEDIATE_START;

  if (ioctl(fd,DMX_SET_PES_FILTER,&FilterParams) < 0)
    perror("DMX SET PES FILTER");
}

static void read_data(struct READER *r)
{
  int offset = (r->flags & SECTION) ? 1 : 0;
  int n;

  r->buffer[0] = 0;

  n = read(r->filenr,r->buffer+offset,r->bufsize-offset);

  if (n < 0)
  {
    perror("read error");
    return;
  }

  if ((r->flags & CHECKSUM) && crc32(r->buffer+offset,n) != 0)
  {
    fprintf(stderr,"crc error\n");
    return;
  }

  r->handler(r->buffer,n+offset);

  if (r->flags & ONE_SHOT)
    remove_reader(r);
}

static void poll_loop()
{
  struct pollfd u[256];
  struct READER *r;
  int n;

  r = readers;
  n = 0;
  while (r != 0)
  {
    u[n].fd = r->filenr;
    u[n].events = POLLIN;
    u[n].revents = 0;
    n++;
    r = r->next;
  }      

  n = poll(u,n,20000);
  if (n < 0)
    perror("poll error");
  else
  if (n == 0)
    fprintf(stderr,"timeout\n");

  r = readers;
  n = 0;
  while (r != 0)
  {
    if (u[n].revents & POLLIN)
      read_data(r);
    n++;
    r = r->next;
  }
}

static int read_autoroll_key_file()
{
  FILE *f;
  static char c[1024];
  char type;
  int id;
  static char name[1024];
  static char key[1024];
  struct EMMKEYINFO *k;

  f = fopen("AutoRoll.Key","r");
  if (f == 0)
    f = fopen("/video/AutoRoll.Key","r");
  if (f == 0)
    f = fopen("/opt/lib/AutoRoll.Key","r");
  if (f == 0)
  {
    perror("AutoRoll.Key");
    return -1;    
  }

  while (fgets(c,sizeof(c),f))
  {
    type = 0;
    if (sscanf(c,"%c %x %s %s",&type,&id,name,key) != 4)
      continue;

    k = malloc(sizeof(struct EMMKEYINFO));
    if (k == 0)
      return -1;

    k->key = malloc(strlen(key)+1);
    if (k->key == 0)
      return -1;

    k->next = emmkeyinfos;
    k->type = type;
    k->id = id;
    strncpy(k->name,name,4);
    strcpy(k->key,key);

    emmkeyinfos = k;
  }

  fclose(f);
  return 0;
}

static int read_decrypt_key_file()
{
  FILE *f;
  static char c[1024];
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

  while (fgets(c,sizeof(c),f))
  {
    k = malloc(sizeof(struct KEYINFO));
    if (k == 0)
      return -1;

    k->string = malloc(strlen(c)+1);
    if (k->string == 0)
      return -1;

    strcpy(k->string,c);

    if (sscanf(c,"%c %x %x %llx",&type,&id,&keynr,&key) == 4)
    {
      k->type = type;
      k->id = id;
      k->keynr = keynr;
      k->key = key;
    }

    if (keyinfos == 0)
      keyinfos = k;
    else
    {
      n = keyinfos;
      while (n->next != 0)
        n = n->next;
      n->next = k;
    }
    k->next = 0;
  }

  fclose(f);
  return 0;
}

static void update_key_file(char type,int id,int keynr,byte *key)
{
  struct KEYINFO *info;
  long long k;
  byte *p;
  int i;

  p = (byte *)&k;
  for (i=0; i<8; i++)
    p[i] = key[7-i];

  printf("KEY %c %x %x %016llx\n",type,id,keynr,k);

  info = keyinfos;
  while (info != 0)
  {
    if (info->type==type && info->id==id && info->keynr==keynr)
    {
      /* Irdeto keys are not uniquely identified by id/keynr */
      /* so we append new Irdeto keys instead of over-writing */
      if (type!='I' || info->key==k)
      {
        info->key = k;
        return;
      }
    }
    info = info->next;
  }


  info = malloc(sizeof(struct KEYINFO));
  if (info == 0)
    return;

  info->type = type;
  info->id = id;
  info->keynr = keynr;
  info->key = k;
  info->next = keyinfos;
  keyinfos = info;
}

static void flush_key_file()
{
  struct KEYINFO *k;
  FILE *f;

  f = fopen("SoftCam.Key","w");

  k = keyinfos;
  while (k != 0)
  {
    switch (k->type)
    {
      case 'I':
      case 'i':
        fprintf(f,"%c %02X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
        break;

      case 'S':
      case 's':
        fprintf(f,"%c %04X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
        break;

      case 'V':
      case 'v':
        fprintf(f,"%c %06X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
        break;

      case 'N':
      case 'n':
        fprintf(f,"%c %04X %02X %016llX\n",k->type,k->id,k->keynr,k->key);
        break;

      default:
        fprintf(f,"%s",k->string);
        break;
    }

    k = k->next;
  }
  
  fclose(f);

  exit(0);
}

static void add_reader(HANDLER handler,int bufsize,int flags,int pid,int tnr)
{
  struct READER *r;
  int filenr;

  filenr = open("/dev/ost/demux",O_RDWR|O_NONBLOCK);
  if (filenr < 0)
  {
    perror("DEMUX DEVICE");
    return;
  }

  r = malloc(sizeof(struct READER));
  if (r == 0)
    return;

  r->buffer = malloc(bufsize);
  if (r->buffer == 0)
  {
    free(r);
    return;
  }

  r->flags = flags;
  r->filenr = filenr;
  r->handler = handler;
  r->bufsize = bufsize;

  r->next = readers;
  readers = r;

  if (flags & SECTION)
    set_section_filter(r->filenr,pid,tnr);
  else
    set_pes_filter(r->filenr,pid);
}

static void remove_reader(struct READER *r)
{
  ioctl(r->filenr,DMX_STOP);
  close(r->filenr);

  if (readers == r)
    readers = r->next;
  else
  {
    struct READER *r1 = readers;
    while (r1->next != r)
      r1 = r1->next;
    r1->next = r->next;
  }

  free(r->buffer);
//  free(r);
}

void ParseIrdetoEMM(byte *buffer,int length)
{
  int provider = -1;
  int provid = -1;
  int date = -1;
  byte pmk[8];

  struct EMMKEYINFO *k;
  int param,extra;
  int index;
  int nlen;
  int i;

  int keys_index = -1;
  int keys_length;

  if (debug)
  {
    printf("emm_data");
    for (i=0; i<length; i++) 
      printf(" %02x",buffer[i]); 
    printf("\n");
  }

  switch (buffer[4])
  {
    case 0x02:
      provid = (buffer[5]<<16) | (buffer[6]<<8);
      provider = 0x00;
      break;
    case 0x03:
      provid = (buffer[5]<<16) | (buffer[6]<<8) | buffer[7];
      provider = 0x00;
      break;
    case 0x0a:
      provid = (buffer[5]<<16) | (buffer[6]<<8);
      provider = 0x10;
      break;
    case 0x0b:
      provid = (buffer[5]<<16) | (buffer[6]<<8) | buffer[7];
      provider = 0x10;
      break;
  }

  if (provid < 0)
    return;

  k = emmkeyinfos;
  while (k != 0)
  {
    if ((k->type=='I' || k->type=='i') && k->id==provid && strcmp(k->name,"PMK")==0)
      break;
    k = k->next;
  }

  if (k == 0)
  {
    printf("Irdeto PMK not found for provid %06x\n",provid);
    return;
  }

  for (i=0; i<8; i++)
    pmk[i] = (FROMHEX(k->key[i*2]))<<4 | FROMHEX(k->key[i*2+1]);

  nlen = buffer[10];
  index = 11;

  i = 0;
  while (i<nlen-5)
  {
    param = buffer[index++] & 0x3f;
    extra = buffer[index++] & 0x3f;

    switch (param)
    {
      case 0x00:
        date = (buffer[index]<<8) | buffer[index+1];
        break;
      case 0x10:
        keys_index = index;
        keys_length = extra;
        for (i=0; i<extra; i+=9)
          sessionKeyCrypt(&buffer[index+i+1],&pmk[0],date);
        break;
      case 0x28:
        // change provider id
        break;
    }

    index += extra;
    i += 2+extra;
  }

  if (keys_index >= 0)
  {
    /* weird - is this right ? */
    buffer[5] = buffer[4];
    buffer[6] = provid>>16;
    buffer[7] = provid>>8;
    buffer[8] = provid;
    buffer[9] = 0;
    if (signatureCheck(&buffer[5],length-10,pmk,date,&buffer[index]))
    {
      for (i=0; i<keys_length; i+=9)
        update_key_file('I',provider,buffer[keys_index+i],&buffer[keys_index+i+1]);
    }
    else
      printf("duff signature\n");      

    flush_key_file();
  }
}

void ParseNagraEMM(byte *buffer,int length)
{
  char *e1 = 0;
  char *n1 = 0;
  char *n2 = 0;
  char *v = 0;
  struct EMMKEYINFO *k;
  int id;
  int i;

  byte ident[2];
  byte key0[8];
  byte key1[8];

  if (debug)
  {
    printf("emm_data");
    for (i=0; i<length; i++) 
      printf(" %02x",buffer[i]); 
    printf("\n");
  }

  id = (buffer[11]<<8) | buffer[12];

  k = emmkeyinfos;
  while (k != 0)
  {
    if ((k->type=='N' || k->type=='n') && k->id==id)
    {
      if (strcmp(k->name,"E1") == 0)
        e1 = k->key;
      if (strcmp(k->name,"N1") == 0)
        n1 = k->key;
      if (strcmp(k->name,"N2") == 0)
        n2 = k->key;
      if (strcmp(k->name,"V") == 0)
        v = k->key;
    }

    k = k->next;
  }

  if (v==0 || e1==0 || n1==0 || n2==0)
  {
    printf("Nagra keys not found for id %x\n",id);
    return;
  }

  if (Nagra_DecryptEMM(buffer+13,v,e1,n1,n2))
  {
    if (debug)
    {
      printf("decrypted");
      for (i=22; i<length; i++) 
        printf(" %02x",buffer[i]); 
      printf("\n");
    }
    switch (Nagra_GetKeys(buffer+22,ident, key0, key1))
    {
      case 1:
        printf("got keys for %04x\n",id);
        update_key_file('N',id,0,key0);
        update_key_file('N',id,1,key1);
        flush_key_file();
        break;
      case 2:
        printf("MISSING ROM FILE\n");
        break;
    }
  }
}

static void ParseCADescriptor(byte *data,int length)
{
  int ca_system;
  int emm_pid;
  int j;

  if (debug)
  {
    printf("ca_descr");
    for (j=0; j<length; j++) printf(" %02x",data[j]);
    printf("\n");
  }

  /* only test the upper 8 bits of the ca_system */
  ca_system = (data[0] << 8) /* | data[1]*/;
  emm_pid = ((data[2] & 0x1f) << 8) | data[3];

  switch (ca_system)
  {
    case SECA_CA_SYSTEM:
      printf("Found seca emm %x\n",emm_pid);
      // add_reader(ParseEMM,184,SECTION,emm_pid,-1);
      break;
    case VIACCESS_CA_SYSTEM:
      printf("Found viaccess emm %x\n",emm_pid);
      // add_reader(ParseEMM,184,SECTION,emm_pid,-1);
      break;
    case IRDETO_CA_SYSTEM:
    case BETA_CA_SYSTEM:
      printf("Found irdeto emm %x\n",emm_pid);
      add_reader(ParseIrdetoEMM,184,SECTION,emm_pid,0x82);
      break;
    case NAGRA_CA_SYSTEM:
      printf("Found nagra emm %x\n",emm_pid);
      add_reader(ParseNagraEMM,184,SECTION,emm_pid,0x82);
      break;
  }
}

void ParseCAT(byte *buffer,int length)
{
  int index;

  length = ((buffer[2] & 0x0F) << 8) + buffer[3];

  index = 9;
  while (length > 0)
  {
    if (buffer[index] == 0x09)
      ParseCADescriptor(&buffer[index+2], buffer[index+1]);

    length -= 2+buffer[index+1];
    index += 2+buffer[index+1];
  }
}

int main(int argc,char **argv)
{
  debug = 1;

  read_autoroll_key_file();
  read_decrypt_key_file();
  add_reader(ParseCAT,184,ONE_SHOT|SECTION,1,-1);

  while (readers != 0)
    poll_loop();
}

/*

int main(int argc,char **argv)
{
  char c[1024];
  byte b[512];
  FILE *f = fopen("input","r");
  int i;
  
  read_autoroll_key_file();
  read_decrypt_key_file();

  while (fgets(c,sizeof(c),f))
  {
    for (i=0; i<86; i++)
      b[i] = FROMHEX(c[i*3+1])*16+FROMHEX(c[i*3+2]);
    ParseNagraEMM(b,86);
  }

  fclose(f);
}

*/
