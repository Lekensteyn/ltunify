/*
 * Displays a more human-readable interpretation of the USB data payload
 * for Logitech Unifying Receiver.
 *
 * Example usage: read-dev-usbmon /dev/usbmon0 | hidraw
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
#include <stdio.h>
#include <unistd.h>
#include <string.h>

typedef unsigned char u8;

#define SHORT_MSG	0x10
#define SHORT_MSG_LEN	7
#define LONG_MSG	0x11
#define LONG_MSG_LEN	20

struct payload_short {
	u8 address;
	u8 value[3];
};
struct payload_long {
	u8 address;
	u8 str[16];
};
struct report {
	u8 report_id;
	u8 device_index;
	u8 sub_id;
	union {
		struct payload_long l;
		struct payload_short s;
	};
} __attribute__((__packed__));

static const char * report_types[0xFF] = {
	// 0x00 - 0x3F HID reports
	[0x01] = "KEYBOARD",
	[0x02] = "MOUSE",
	[0x03] = "CONSUMER_CONTROL",
	[0x04] = "SYSTEM_CONTROL",

	[0x08] = "MEDIA_CENTER",

	[0x0E] = "LEDS",

	// 0x40 - 0x7F enumerator notifications
	[0x40] = "NOTIF_DEVICE_UNPAIRED",
	[0x41] = "NOTIF_DEVICE_PAIRED",
	[0x42] = "NOTIF_CONNECTION_STATUS",
	[0x4A] = "NOTIF_RECV_LOCK_CHANGED",
	[0x4B] = "?NOTIF_PAIR_ACCEPTED",

	[0x7F] = "NOTIF_ERROR",

	// 0x80 - 0xFF enumerator commands; Register Access
	[0x80] = "SET_REG", // was CMD_SWITCH
	[0x81] = "GET_REG", // was CMD_GET_PAIRED_DEVICES
	[0x82] = "SET_LONG_REG",
	[0x83] = "GET_LONG_REG",
	[0x8F] = "_ERROR_MSG",
};

static const char * error_messages[0xFF] = {
	// error messages for type=8F (ERROR_MSG)
	[0x01] = "SUCCESS",
	[0x02] = "INVALID_SUBID",
	[0x03] = "INVALID_ADDRESS",
	[0x04] = "INVALID_VALUE",
	[0x05] = "CONNECT_FAIL",
	[0x06] = "TOO_MANY_DEVICES",
	[0x07] = "ALREADY_EXISTS",
	[0x08] = "BUSY",
	[0x09] = "UNKNOWN_DEVICE",
	[0x0a] = "RESOURCE_ERROR",
	[0x0b] = "REQUEST_UNAVAILABLE",
	[0x0c] = "INVALID_PARAM_VALUE",
	[0x0d] = "WRONG_PIN_CODE",
};

static const char * registers[0xFF] = {
	[0x00] = "ENABLED_NOTIFS",
	[0x01] = "KBD_HAND_DETECT?",
	[0x02] = "CONNECTION_STATE",
	[0x03] = "FN_KEY_SWAP?",
	[0x17] = "ILLUMINATION_INFO?",
	[0xb2] = "DEVICE_PAIRING",
	[0xb3] = "DEVICE_ACTIVITY",
	[0xb5] = "PAIRING_INFO",
	[0xf1] = "VERSION_INFO?", /* guessed */
};

const char * report_type_str(u8 type) {
	const char * str = report_types[type];
	return str ? str : "";
}
const char * device_type_str(u8 type) {
	switch (type) {
	case 0x01: return "DEV1";
	case 0x02: return "DEV2";
	case 0x03: return "DEV3";
	case 0x04: return "DEV4";
	case 0x05: return "DEV5";
	case 0x06: return "DEV6";
	case 0xFF: return "RECV";
	default: return "";
	}
}
const char *error_str(u8 er) {
	const char * str = error_messages[er];
	return str ? str : "";
}
const char *register_str(u8 reg) {
	const char * str = registers[reg];
	return str ? str : "";
}

void process_msg_payload(struct report *r, u8 data_len) {
	u8 pos, i;
	u8 * bytes = (u8 *) &r->s;

	switch (r->sub_id) {
	case 0x8F: // error
		// TODO: length check
		printf("SubID=%02X %s  ", bytes[0], report_type_str(bytes[0]));
		printf("reg=%02X %s  ", bytes[1], register_str(bytes[1]));
		printf("err=%02X %s  ", bytes[2], error_str(bytes[2]));
		pos = 4; // everything is processed
		break;
	case 0x80:
	case 0x81:
	case 0x82: /* long */
	case 0x83: /* long */
		printf("reg=%02X %s  ", bytes[0], register_str(bytes[0]));
		pos = 1;
		break;
	default:
		pos = 0; // nothing has been processed
		break;
	}

	if (pos < data_len) {
		printf("params=");
		//printf("params(len=%02X)=", data_len);
	}
	for (i = 0; pos < data_len; pos++, i++) {
		printf("%02X ", bytes[pos]);
		if (i % 4 == 3 && pos + 1 < data_len) {
			putchar(' ');
		}
	}
}

void process_msg(struct report *report, ssize_t size) {
	const char * report_type;

	switch (report->report_id) {
	case SHORT_MSG:
		report_type = "short";
		if (size != SHORT_MSG_LEN) {
			fprintf(stderr, "Invalid short msg len %zi\n", size);
			return;
		}
		break;
	case LONG_MSG:
		report_type = "long";
		if (size != LONG_MSG_LEN) {
			fprintf(stderr, "Invalid long msg len %zi\n", size);
			return;
		}
		break;
	default:
		report_type = "unkn";
		//fprintf(stderr, "Unknown report ID %02x, len=%zi\n", report->report_id, size);
		if (size < 3) {
			return;
		}
		break;
	}

	printf("report_id=%02X %-5s ", report->report_id, report_type);
	printf("device=%02X %-4s ", report->device_index,
			device_type_str(report->device_index));
	printf("type=%02X %-23s ", report->sub_id,
			report_type_str(report->sub_id));

	if (size > 3) {
		process_msg_payload(report, size - 3);
	}
	putchar('\n');
}

#ifndef NO_MAIN
int main(int argc, char ** argv) {
	int fd = STDIN_FILENO;
	ssize_t r;
	struct report report;

	if (argc >= 2 && (fd = open(argv[1], O_RDONLY)) < 0) {
		perror(argv[1]);
		return 1;
	}

	do {
		memset(&report, 0xCC, sizeof report); // for debugging purposes
		r = read(fd, &report, sizeof report);
		if (r > 0) {
			process_msg(&report, r);
		}
	} while (r >= 0);

	if (r < 0) {
		perror("read");
	}

	close(fd);

	return 0;
}
#endif /* ! NO_MAIN */
