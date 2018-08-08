INSTALLDIR	= /usr/local/bin

HOSTOS := $(shell uname -s)
CC	= gcc
CFLAGS	?= -O3 -Wall -Wextra
CFLAGS	+= -std=gnu99
INSTFLAGS = -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(HOSTOS), Darwin)
CFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
endif

all: build

build:
	$(CC) $(CFLAGS) -o wlangenpmk wlangenpmk.c -lcrypto
ifeq ($(HOSTOS), Darwin)
	$(CC) $(CFLAGS) -o wlangenpmkocl wlangenpmkocl.c -lcrypto -Wl,-framework,OpenCL -lm
else
	$(CC) $(CFLAGS) -o wlangenpmkocl wlangenpmkocl.c -lcrypto -lOpenCL
endif
	$(CC) $(CFLAGS) -o pwhash pwhash.c -lcrypto


install: build
	install $(INSTFLAGS) wlangenpmk $(INSTALLDIR)/wlangenpmk
	install $(INSTFLAGS) wlangenpmkocl $(INSTALLDIR)/wlangenpmkocl
	install $(INSTFLAGS) pwhash $(INSTALLDIR)/pwhash
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
