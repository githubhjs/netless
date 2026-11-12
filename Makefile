CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
PREFIX ?= /usr/local

.PHONY: all test install clean

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
PLATFORM_SRC := src/netless.c
else ifeq ($(UNAME_S),Darwin)
PLATFORM_SRC := src/netless_macos.c
LDLIBS := -lsandbox
CFLAGS += -Wno-deprecated-declarations
else ifeq ($(UNAME_S),OpenBSD)
PLATFORM_SRC := src/netless_openbsd.c
else
$(error Unsupported OS $(UNAME_S): network isolation backend not implemented)
endif

all: build/netless

build/netless: $(PLATFORM_SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

test: build/netless
	@if [ "$(UNAME_S)" = Linux ]; then python3 -m unittest discover -s tests -p 'test_netless.py' -v; \
	else python3 -m unittest discover -s tests -p 'test_portable.py' -v; fi

install: build/netless
	install -D -m 0755 build/netless $(DESTDIR)$(PREFIX)/bin/netless

clean:
	rm -rf build
