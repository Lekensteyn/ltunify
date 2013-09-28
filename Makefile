CFLAGS ?= -g -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector --param ssp-buffer-size=4
# for install-home
BINDIR ?= $(HOME)/bin

# for install and uninstall
DESTDIR ?=
bindir ?= /usr/local/bin
udevrulesdir ?= /etc/udev/rules.d

udevrule = 42-logitech-unify-permissions.rules

PACKAGE_VERSION ?= $(shell git describe --dirty 2>/dev/null | sed s/^v//)
ifeq (PACKAGE_VERSION, "")
	LTUNIFY_DEFINES :=
else
	LTUNIFY_DEFINES := -DPACKAGE_VERSION=\"$(PACKAGE_VERSION)\"
endif

%: %.c
	$(CC) $(CFLAGS) -o $(OUTDIR)$@ $<

all: ltunify read-dev-usbmon

read-dev-usbmon: read-dev-usbmon.c hidraw.c

ltunify: ltunify.c hidpp20.c
	$(CC) $(CFLAGS) -o $(OUTDIR)$@ $< -lrt $(LTUNIFY_DEFINES)

.PHONY: all clean install-home install install-udevrule uninstall
clean:
	rm -f ltunify read-dev-usbmon hidraw

install-home: ltunify
	install -m755 -D ltunify $(BINDIR)/ltunify

# System-wide installation
install: ltunify install-udevrule
	install -m755 -D ltunify $(DESTDIR)$(bindir)/ltunify

install-udevrule: udev/$(udevrule)
	install -m644 -D udev/$(udevrule) $(DESTDIR)$(udevrulesdir)/$(udevrule)

uninstall:
	$(RM) $(DESTDIR)$(bindir)/ltunify $(DESTDIR)$(udevrulesdir)/$(udevrule)
