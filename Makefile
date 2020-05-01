PRODUCTION		:= 0
PRODUCTION_VERSION	:= 6.0.0
PRODUCTION_YEAR		:= 2020

ifeq ($(PRODUCTION),1)
VERSION_TAG		:= $(PRODUCTION_VERSION)
else
VERSION_TAG		:= $(shell git describe --tags || echo $(PRODUCTION_VERSION))
endif
VERSION_YEAR		:= $(shell echo $(PRODUCTION_YEAR))

PREFIX		?=/usr/local
INSTALLDIR	= $(DESTDIR)$(PREFIX)/bin

HOSTOS := $(shell uname -s)
CC	= gcc
CFLAGS	?= -O3 -Wall -Wextra
CFLAGS	+= -std=gnu99
DEFS	= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"
INSTFLAGS = -m 0755

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif

ifeq ($(HOSTOS), Darwin)
CFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
endif

all: build

build:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) -o wlangenpmk wlangenpmk.c -lcrypto $(LDFLAGS)
ifeq ($(HOSTOS), Darwin)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) -o wlangenpmkocl wlangenpmkocl.c -lcrypto -Wl,-framework,OpenCL -lm $(LDFLAGS)
else
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) -o wlangenpmkocl wlangenpmkocl.c -lcrypto -lOpenCL $(LDFLAGS)
endif
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEFS) -o pwhash pwhash.c -lcrypto $(LDFLAGS)


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
