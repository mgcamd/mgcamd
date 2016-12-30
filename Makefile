CFLAGS = -DWITH_MAIN
CPPFLAGS = -I.

EMM = \
  big.o \
  caid1800.o \
  emm.o \
  irdeto.o

MGCAM = \
  big.o \
  caid1800.o \
  decrypt.o \
  irdeto.o \
  mgcam2.o \
  secaencrypt.o \
  veason_decode.o

MIRACL = \
  mralloc.o \
  mrarth0.o \
  mrarth1.o \
  mrarth2.o \
  mrarth3.o \
  mrcore.o \
  mrgcd.o \
  mrio1.o \
  mrio2.o \
  mrlucas.o \
  mrmonty.o \
  mrmuldv.o \
  mrpower.o \
  mrprime.o \
  mrrand.o \
  mrxgcd.o

all: emm mgcam

emm: $(EMM) $(MIRACL)
	g++ -o emm $(EMM) $(MIRACL)

mgcam: $(MGCAM) $(MIRACL)
	g++ -o mgcam $(MGCAM) $(MIRACL)
