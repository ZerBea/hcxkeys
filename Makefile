INSTALLDIR	= /usr/local/bin

CC	= gcc
CFLAGS	= -O3 -Wall -Wextra


all: build

build:
	$(CC) $(CFLAGS) -o wlangenpmk wlangenpmk.c -lcrypto
	$(CC) $(CFLAGS) -o wlangenpmkocl wlangenpmkocl.c -lcrypto -lOpenCL
	$(CC) $(CFLAGS) -o pwhash pwhash.c -lcrypto


install: build
	install -D -m 0755 wlangenpmk $(INSTALLDIR)/wlangenpmk
	install -D -m 0755 wlangenpmkocl $(INSTALLDIR)/wlangenpmkocl
	install -D -m 0755 pwhash $(INSTALLDIR)/pwhash
	rm -f wlangenpmk
	rm -f wlangenpmkocl
	rm -f pwhash
	rm -f *.o *~


clean:
	rm -f wlangenpmk
	rm -f wlangenpmkocl
	rm -f pwhash
	rm -f *.o *~


uninstall:
	rm -f $(INSTALLDIR)/wlangenpmk
	rm -f $(INSTALLDIR)/wlangenpmkocl
	rm -f $(INSTALLDIR)/pwhash
