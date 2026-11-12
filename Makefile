CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
PREFIX ?= /usr/local

.PHONY: all test install clean

all: build/netless

build/netless: src/netless.c
	@mkdir -p build
	$(CC) $(CFLAGS) $< -o $@

test: build/netless
	python3 -m unittest discover -s tests -v

install: build/netless
	install -D -m 0755 build/netless $(DESTDIR)$(PREFIX)/bin/netless

clean:
	rm -rf build
