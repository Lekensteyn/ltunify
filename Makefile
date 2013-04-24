CFLAGS ?= -g -O2 -Wall -Werror -Wextra
BINDIR ?= $(HOME)

%: %.c
	$(CC) $(CFLAGS) -o $(OUTDIR)$@ $<

all: ltunify read-dev-usbmon

.PHONY: clean install-home
clean:
	rm -f ltunify read-dev-usbmon hidraw

install-home: ltunify
	install -m755 -D ltunify $(BINDIR)/ltunify
