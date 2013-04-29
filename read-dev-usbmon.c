/*
 * Tool for reading usbmon messages and writing non-empty data to stdout.
 * Because of limitations of a single output stream, there is currently a hack
 * that directly includes hidraw.c.
 *
 * Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h> /* getenv */
#include <errno.h>
#include <sys/time.h> /* gettimeofday */
#include <time.h> /* localtime */

typedef uint16_t u16;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
#define SETUP_LEN 8

/* taken from Linux, Documentation/usb/usbmon.txt */
struct usbmon_packet {
	u64 id;                 /*  0: URB ID - from submission to callback */
	unsigned char type;     /*  8: Same as text; extensible. */
	unsigned char xfer_type; /*    ISO (0), Intr, Control, Bulk (3) */
	unsigned char epnum;    /*     Endpoint number and transfer direction */
	unsigned char devnum;   /*     Device address */
	u16 busnum;             /* 12: Bus number */
	char flag_setup;        /* 14: Same as text */
	char flag_data;         /* 15: Same as text; Binary zero is OK. */
	s64 ts_sec;             /* 16: gettimeofday */
	s32 ts_usec;            /* 24: gettimeofday */
	int status;             /* 28: */
	unsigned int length;    /* 32: Length of data (submitted or actual) */
	unsigned int len_cap;   /* 36: Delivered length */
	union {                 /* 40: */
		unsigned char setup[SETUP_LEN]; /* Only for Control S-type */
		struct iso_rec {                /* Only for ISO */
			int error_count;
			int numdesc;
		} iso;
	} s;
	int interval;           /* 48: Only for Interrupt and ISO */
	int start_frame;        /* 52: For ISO */
	unsigned int xfer_flags; /* 56: copy of URB's transfer_flags */
	unsigned int ndesc;     /* 60: Actual number of ISO descriptors */
};

struct mon_get_arg {
	struct usbmon_packet *hdr;
	void *data;
	size_t alloc;           /* Length of data (can be zero) */
};

#define MON_IOC_MAGIC		0x92
#define MON_IOCQ_URB_LEN	_IO(MON_IOC_MAGIC, 1)
#define MON_IOCX_GET		_IOW(MON_IOC_MAGIC, 6, struct mon_get_arg)

#define NO_MAIN
// HACK - otherwise there is no easy wat to tell whether a packet is read or
// written from the usbmon
#include "hidraw.c"
#undef NO_MAIN

void print_time(void) {
	struct timeval tval;
	struct tm *tm;

	if (gettimeofday(&tval, NULL)) {
		perror("gettimeofday");
		return;
	}
	tm = localtime(&tval.tv_sec);
	printf("%02d:%02d:%02d.%03ld ",
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		tval.tv_usec / 1000);
}

int main(int argc, char ** argv) {
	unsigned char data[1024];
	struct usbmon_packet hdr;
	struct mon_get_arg event;
	int fd, r;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s /dev/usbmonX\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		return 1;
	}

	memset(&hdr, 0, sizeof hdr);
	event.hdr = &hdr; // hopefully it is OK to use stack for this
	event.data = &data;
	event.alloc = sizeof data;

	//r = ioctl(fd, MON_IOCQ_URB_LEN);
	//printf("%i\n", r);
	for (;;) {
		memset(&data, 0xCC, sizeof data); // for debugging purposes
		r = ioctl(fd, MON_IOCX_GET, &event);
		if (r == -1 && errno == EINTR) {
			continue;
		}
		if (r < 0) {
			perror("ioctl");
			break;
		}

		// ignore non-data packets
		if (hdr.len_cap) {
			if (getenv("HEX")) {
				unsigned int i;
				printf("Type=%c\n", hdr.type);
				for (i=0; i<hdr.len_cap; i++) {
					printf("%02X%c", data[i],
						i + 1 == hdr.len_cap ? '\n' : ' ');
				}
			} else if (hdr.len_cap > sizeof (struct report)) {
				fprintf(stderr, "Discarding too large packet of length %u!\n", hdr.len_cap);
			} else {
				struct report *report = (struct report *)&data;
				if (hdr.len_cap < 3) {
					fprintf(stderr, "Short data len: %i\n", hdr.len_cap);
					continue;
				}
#define COLOR(c, cstr) "\033[" c "m" cstr "\033[m"
				print_time();
				if (hdr.type == 'C') {
					printf(COLOR("1;32", "Recv\t"));
				} else if (hdr.type == 'S') {
					printf(COLOR("1;31", "Send\t"));
				} else {
					printf(COLOR("1;35", "Type=%c\t") "\n", hdr.type);
				}
				process_msg(report, hdr.len_cap);
				fflush(NULL);
#if 0
				if (write(STDOUT_FILENO, &data, hdr.len_cap) < 0) {
					perror("write");
					break;
				}
#endif
			}
		}
	}

	close(fd);

	return 0;
}
