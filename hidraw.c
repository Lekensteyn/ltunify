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
#include <stdbool.h>

typedef unsigned char u8;

#define SHORT_MSG	0x10
#define SHORT_MSG_LEN	7
#define DJ_SHORT	0x20
#define DJ_SHORT_LEN	15
#define DJ_LONG		0x21
#define DJ_LONG_LEN	32
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

/* types for HID++ report IDs 0x10 and 0x11 */
static const char * report_types[0x100] = {
	[0x00] = "_HIDPP20", // fake type
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
	[0xFF] = "_HIDPP20_ERROR_MSG",
};

/* types for DJ report IDS 0x20 and 0x21 */
static const char *dj_report_types[0x100] = {
	/* 0x00 - 0x3F: RF reports */
	[0x01] = "KEYBOARD",
	[0x02] = "MOUSE",
	[0x03] = "CONSUMER_CONTROL",
	[0x04] = "SYSTEM_CONTROL",
	[0x08] = "MEDIA_CENTER",
	[0x0E] = "KEYBOARD_LEDS",

	/* 0x40 - 0x7F: DJ notifications */
	[0x40] = "NOTIF_DEVICE_UNPAIRED",
	[0x41] = "NOTIF_DEVICE_PAIRED",
	[0x42] = "NOTIF_CONNECTION_STATUS",

	[0x7F] = "NOTIF_ERROR",

	/* 0x80 - 0xFF: DJ commands */
	[0x80] = "CMD_SWITCH_N_KEEPALIVE",
	[0x81] = "CMD_GET_PAIRED_DEVICES"
};

static const char * error_messages[0x100] = {
	// error messages for type=8F (ERROR_MSG)
	[0x00] = "SUCCESS",
	[0x01] = "INVALID_SUBID",
	[0x02] = "INVALID_ADDRESS",
	[0x03] = "INVALID_VALUE",
	[0x04] = "CONNECT_FAIL",
	[0x05] = "TOO_MANY_DEVICES",
	[0x06] = "ALREADY_EXISTS",
	[0x07] = "BUSY",
	[0x08] = "UNKNOWN_DEVICE",
	[0x09] = "RESOURCE_ERROR",
	[0x0A] = "REQUEST_UNAVAILABLE",
	[0x0B] = "INVALID_PARAM_VALUE",
	[0x0C] = "WRONG_PIN_CODE",
};

// I don't know the upper bound, perhaps 0x10 is enough
static const char * error_messages_hidpp20[0x100] = {
	[0x00] = "NoError",
	[0x01] = "Unknown",
	[0x02] = "InvalidArgument",
	[0x03] = "OutOfRange",
	[0x04] = "HWError",
	[0x05] = "Logitech internal",
	[0x06] = "INVALID_FEATURE_INDEX",
	[0x07] = "INVALID_FUNCTION_ID",
	[0x08] = "Busy",
	[0x09] = "Unsupported",
};

// everything with a '?' is guessed
static const char * registers[0x100] = {
	[0x00] = "ENABLED_NOTIFS",
	[0x01] = "KBD_HAND_DETECT?",
	[0x02] = "CONNECTION_STATE",
	[0x07] = "BATTERY?",
	[0x09] = "FN_KEY_SWAP?",
	[0x17] = "ILLUMINATION_INFO?",
	[0xb2] = "DEVICE_PAIRING",
	[0xb3] = "DEVICE_ACTIVITY",
	[0xb5] = "PAIRING_INFO",
	[0xf1] = "VERSION_INFO?",
};

bool report_type_is_hidpp(u8 report_id) {
	return report_id == SHORT_MSG || report_id == LONG_MSG;
}
bool report_type_is_dj(u8 report_id) {
	return report_id == DJ_SHORT || report_id == DJ_LONG;
}

const char * report_type_str(u8 report_id, u8 type) {
	const char *str = NULL;
	if (report_type_is_hidpp(report_id))
		str = report_types[type];
	else if (report_type_is_dj(report_id))
		str = dj_report_types[type];
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
const char *error_str_hidpp20(u8 er) {
	const char * str = error_messages_hidpp20[er];
	return str ? str : "";
}
const char *register_str(u8 reg) {
	const char * str = registers[reg];
	return str ? str : "";
}

void process_msg_payload(struct report *r, u8 data_len) {
	u8 pos, i;
	u8 * bytes = (u8 *) &r->s;

	pos = 0; // nothing has been processed

	if (report_type_is_hidpp(r->report_id))
	switch (r->sub_id) {
	case 0x00: // assume HID++ 2.0 request/response for feature IRoot
		if (data_len == 4 || data_len == 17) {
			printf("func=%X  ", bytes[0] >> 4);
			printf("swId=%X  ", bytes[0] & 0xF);
			pos = 1;
		}
		break;
	case 0xFF: // assume HID++ 2.0 error
		if (data_len == 17) {
			printf("feat=%X  ", bytes[0]);
			printf("func=%X  ", bytes[1] >> 4);
			printf("swId=%X  ", bytes[1] & 0xF);
			printf("err=%02X %s  ", bytes[2], error_str_hidpp20(bytes[2]));
			pos = 3;
		}
		break;
	case 0x8F: // error
		// TODO: length check
		printf("SubID=%02X %s  ", bytes[0], report_type_str(r->report_id, bytes[0]));
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
	case DJ_SHORT:
		report_type = "dj_s";
		if (size != DJ_SHORT_LEN) {
			fprintf(stderr, "Invalid DJ short msg len %zi\n", size);
			return;
		}
		break;
	case DJ_LONG:
		report_type = "dj_l";
		if (size != DJ_LONG_LEN) {
			fprintf(stderr, "Invalid DJ long msg len %zi\n", size);
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
			report_type_str(report->report_id, report->sub_id));

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
