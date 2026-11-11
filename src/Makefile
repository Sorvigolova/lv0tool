CC=gcc
STRIP=strip
CFLAGS=-O2 -Wall -std=gnu11
LDFLAGS=-static
LIBS=

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all clean install uninstall

all: lv0tool

lv0tool: main.o aes.o util.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@
	# $(STRIP) -s $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: lv0tool
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 lv0tool $(DESTDIR)$(BINDIR)/lv0tool

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lv0tool

clean:
	rm -f *.o lv0tool