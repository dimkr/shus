CC ?= cc
CFLAGS ?= -O2 -pipe
LDFLAGS ?= -s
DESTDIR ?=
BIN_DIR ?= /bin
SBIN_DIR ?= /sbin
MAN_DIR ?= /usr/share/man
DOC_DIR ?= /usr/share/doc
LOG_DIR ?= /var/log
USER ?= nobody

PACKAGE = shus
VERSION = 0.1
CFLAGS += -std=gnu99 -Wall -pedantic \
          -D_GNU_SOURCE \
          -DNDEBUG \
          -DPACKAGE=\"$(PACKAGE)\" \
          -DVERSION=\"$(VERSION)\" \
          -DUSER=\"$(USER)\" \
          -DLOG_PATH=\"$(LOG_DIR)/$(PACKAGE).log\"

INSTALL = install -v

SRCS = $(wildcard *.c)
OBJECTS = $(SRCS:.c=.o)
HEADERS = $(wildcard *.h)

PROGS = shusd shus-index

all: $(PROGS)

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)

shusd: shusd.o
	$(CC) -o $@ $^ $(LDFLAGS)

shus-index: shus-index.o
	$(CC) -o $@ $^ $(LDFLAGS)

install: all
	$(INSTALL) -D -m 755 shusd $(DESTDIR)/$(SBIN_DIR)/shusd
	$(INSTALL) -D -m 755 shus-index $(DESTDIR)/$(BIN_DIR)/shus-index
	$(INSTALL) -D -m 644 shusd.8 $(DESTDIR)/$(MAN_DIR)/man8/shusd.8
	$(INSTALL) -D -m 644 shus-index.1 $(DESTDIR)/$(MAN_DIR)/man1/shus-index.1
	$(INSTALL) -D -m 644 README $(DESTDIR)/$(DOC_DIR)/shus/README
	$(INSTALL) -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/shus/AUTHORS
	$(INSTALL) -m 644 UNLICENSE $(DESTDIR)/$(DOC_DIR)/shus/UNLICENSE

clean:
	rm -f $(PROGS) $(OBJECTS)