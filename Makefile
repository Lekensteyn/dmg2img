#CC = gcc
CFLAGS = -O2 -Wall
BIN_DIR = ${DESTDIR}/usr/bin

all: dmg2img vfdecrypt 

dmg2img: dmg2img.c dmg2img.h mntcmd.h gpt.h dmg2img.o base64.o adc.o 
	$(CC) -s -o dmg2img dmg2img.o base64.o adc.o -L. -lz -lbz2

dmg2img.o: dmg2img.c dmg2img.h
	$(CC) $(CFLAGS) -c dmg2img.c

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) -c base64.c

adc.o: adc.c adc.h
	$(CC) $(CFLAGS) -c adc.c

vfdecrypt: vfdecrypt.c
	$(CC) $(CFLAGS) -s -o vfdecrypt vfdecrypt.c -lcrypto

install: dmg2img vfdecrypt
	mkdir -p ${BIN_DIR}
	install -c -s -m 755 -o root -g root dmg2img vfdecrypt $(BIN_DIR)

clean:
	rm -f dmg2img vfdecrypt *~ *.o core
