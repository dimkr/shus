CC ?= cc
CFLAGS ?= -O2 -pipe
LIBS ?= -lmagic
LDFLAGS ?= -Wl,-s
DESTDIR ?=
BIN_DIR ?= /bin
SBIN_DIR ?= /sbin
MAN_DIR ?= /usr/share/man
DOC_DIR ?= /usr/share/doc
LOG_DIR ?= /var/log
USER ?= nobody

CFLAGS += -std=gnu99 \
          -Wall \
          -pedantic \
          -pthread \
          -D_GNU_SOURCE \
          -DNDEBUG \
          -DUSER=\"$(USER)\"
LDFLAGS += -pthread
LIBS += -lrt

INSTALL = install -v

SRCS = $(wildcard *.c)
OBJECTS = $(SRCS:.c=.o)
HEADERS = $(wildcard *.h)

all: shusd

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)

shusd: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

install: all
	$(INSTALL) -D -m 755 shusd $(DESTDIR)/$(SBIN_DIR)/shusd
	$(INSTALL) -D -m 644 shusd.8 $(DESTDIR)/$(MAN_DIR)/man8/shusd.8
	$(INSTALL) -D -m 644 README $(DESTDIR)/$(DOC_DIR)/shus/README
	$(INSTALL) -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/shus/AUTHORS
	$(INSTALL) -m 644 COPYING $(DESTDIR)/$(DOC_DIR)/shus/UNLICENSE

clean:
	rm -f shusd $(OBJECTS)
