CC	= gcc
LD	= $(CC)
OPT 	= -O2 -s
IPATH	= -I/home/wolf/miners/sgminer-builds/sgminer-lin64/include/
LPATH	= -L/home/wolf/miners/sgminer-builds/sgminer-lin64/lib
CFLAGS 	= -D_POSIX_SOURCE -D_GNU_SOURCE $(OPT) -std=c11 -pthread $(IPATH)
LDFLAGS	= -DPTW32_STATIC_LIB $(LPATH)
LIBS	= -ljansson -lOpenCL -pthread -ldl

PLAT	= X86
OBJX86	= crypto/aesb.o crypto/aesb-x86-impl.o crypto/oaes_lib.o
AESX86	= -maes
OBJARM	=
AESARM	= -march=armv8-a+crypto
OBJPLAT = $(OBJ$(PLAT))
AES	= $(AES$(PLAT))

OBJS	= $(OBJPLAT) crypto/c_blake256.o \
	crypto/c_groestl.o crypto/c_keccak.o crypto/c_jh.o crypto/c_skein.o \
	cryptonight.o log.o net.o minerutils.o gpu.o main.o

all: $(OBJS)
	$(LD) $(LDFLAGS) -o miner $(OBJS) $(LIBS)

cryptonight.o:	cryptonight.c
	$(CC) $(CFLAGS) $(AES)  -c -o $@ $?

clean:
	rm -f *.o crypto/*.o miner
