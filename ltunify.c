/*
 * Pair, unpair or list information about wireless devices like keyboards and
 * mice that use the Logitech® Unifying receiver.
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
#include <errno.h>
#include <stdlib.h> /* strtoul */
#include <stdint.h> /* uint16_t */
#include <arpa/inet.h> /* ntohs, ntohl */
#include <glob.h> /* for /dev/hidrawX discovery */
#include <getopt.h> /* for getopt_long */
#include <poll.h>
#include <libgen.h> /* for basename, used during discovery */
#include <time.h> /* needs -lrt, for clock_gettime as timeout helper */
#include <stdarg.h>

#ifndef PACKAGE_VERSION
#	define PACKAGE_VERSION "0.3"
#endif

#define ARRAY_SIZE(a) (sizeof (a) / sizeof *(a))

// pass -D option to print very verbose details like protocol communication
static bool debug_enabled;
#define DPRINTF(...) if (debug_enabled) { fprintf(stderr, __VA_ARGS__); }

typedef unsigned char u8;

#define VID_LOGITECH		0x046d
#define PID_NANO_RECEIVER	0xc52f
#define PID_NANO_RECEIVER_2	0xc534

#define HEADER_SIZE		3
#define SHORT_MESSAGE           0x10
#define SHORT_MESSAGE_LEN       7
#define LONG_MESSAGE            0x11
#define LONG_MESSAGE_LEN        20

#define DEVICE_RECEIVER         0xFF

#define SUB_SET_REGISTER        0x80
#define SUB_GET_REGISTER        0x81
#define SUB_SET_LONG_REGISTER   0x82
#define SUB_GET_LONG_REGISTER   0x83
#define SUB_ERROR_MSG           0x8F

#define NOTIF_DEV_DISCONNECT	0x40 /* Device Disconnection */
#define NOTIF_DEV_CONNECT	0x41 /* Device Connection */
#define NOTIF_RECV_LOCK_CHANGE	0x4A /* Unifying Receiver Locking Change information */

#define REG_ENABLED_NOTIFS      0x00
#define REG_CONNECTION_STATE    0x02
/* Device Connection and Disconnection (Pairing) */
#define REG_DEVICE_PAIRING      0xB2
#define REG_DEVICE_ACTIVITY     0xB3
#define REG_PAIRING_INFO        0xB5
#define REG_VERSION_INFO	0xF1 /* undocumented */

// Used for: {GET,SET}_REGISTER_{REQ,RSP}, SET_LONG_REGISTER_RSP, GET_LONG_REGISTER_REQ
struct msg_short {
        u8 address;
        u8 value[3];
};
// Used for: SET_LONG_REGISTER_REQ, GET_LONG_REGISTER_RSP
struct msg_long {
        u8 address;
        u8 str[16];
};
// Used for: ERROR_MSG
struct msg_error {
        u8 sub_id;
        u8 address;
        u8 error_code;
        u8 padding; /* set to 0 */
};

// 0x00 Enable HID++ Notifications
struct msg_enable_notifs {
	u8 reporting_flags_devices; // bit 4 Battery status
	u8 reporting_flags_receiver; // bit 0 Wireless notifications, 3 Software Present
	u8 reporting_flags_receiver2; // (reserved)
};

// long receiver resp - 0xB5 Pairing information, 0x03 - "Receiver information"? (undocumented)
struct msg_receiver_info {
	u8 _dunno1; // always 0x03 for receiver?
	u8 serial_number[4];
	u8 _dunno2; // 06 - Max Device Capability? (not sure, but it is six)
	u8 _dunno3;
	u8 padding[8]; // 00 00 00 00  00 00 00 00 - ??
};

// 0xB5 Pairing information, 0x20..0x2F - Unifying Device pairing information
struct msg_dev_pair_info {
	u8 requested_field; // 0x20..0x25
	u8 dest_id;
	u8 report_interval; // ms
	u8 pid_msb;
	u8 pid_lsb;
	u8 _reserved1[2];
	u8 device_type;
	u8 _reserved2[6];
};
// 0xB5 Pairing information, 0x30..0x3F - Unifying Device extended pairing info
struct msg_dev_ext_pair_info {
	u8 requested_field; // 0x30..0x35
	u8 serial_number[4]; // index 0 is MSB
	u8 report_types[4]; // index 0 is MSB
	u8 usability_info; // bits 0..3 is location of power switch
};
// 0xB5 Pairing information, 0x40..0x4F - Unifying Device name
#define DEVICE_NAME_MAXLEN 14
struct msg_dev_name {
	u8 requested_field; // 0x40..0x45
	u8 length;
	char str[DEVICE_NAME_MAXLEN]; // UTF-8 encoding
};

struct notif_devcon {
#define DEVCON_PROT_UNIFYING	0x04
#define DEVCON_PROT_NANO_LITE	0x0a
	u8 prot_type; // bits 0..2 is protocol type (4 for unifying), 3..7 is reserved
#define DEVCON_DEV_TYPE_MASK	0x0f
// Link status: 0 is established (in range), 1 is not established (out of range)
#define DEVCON_LINK_STATUS_FLAG	0x40
	u8 device_info;
	// wireless product id:
	u8 pid_lsb;
	u8 pid_msb;
};

// Register 0x02 Connection State
struct val_reg_connection_state {
// 0x02 triggers a 0x41 notification for all known devices
#define CONSTATE_ACTION_LIST_DEVICES	0x02
	u8 action; // always 0 for read
	u8 connected_devices_count;
	u8 _undocumented2;
};

// Register 0xB2 Device Connection and Disconnection (Pairing)
struct val_reg_devpair {
#define DEVPAIR_KEEP_LOCK	0
#define DEVPAIR_OPEN_LOCK	1
#define DEVPAIR_CLOSE_LOCK	2
#define DEVPAIR_DISCONNECT	3
	u8 action;
	u8 device_number; // same as device index from 0x41 notif
	u8 open_lock_timeout; // timeout in seconds, 0 = default (30s)
};

// Register 0xF1 Version Info (undocumented)
struct val_reg_version {
// v1.v2.xxx
#define VERSION_FIRMWARE	1
// x.x.v1v2
#define VERSION_FW_BUILD	2
// value 3 is invalid for receiver, but returns 00 07 for keyboard
// BL.v1.v2
#define VERSION_BOOTLOADER	4
	u8 select_field;
	u8 v1;
	u8 v2;
};

struct hidpp_message {
        u8 report_id;
        u8 device_index;
        u8 sub_id;
        union {
                struct msg_short msg_short;
                struct msg_long msg_long;
                struct msg_error msg_error;
        };
};

struct hidpp_version {
	u8 major;
	u8 minor;
};

struct version {
	u8 fw_major;
	u8 fw_minor;
	uint16_t fw_build;
	u8 bl_major;
	u8 bl_minor;
};

#define DEVICES_MAX	6u
struct device {
	bool device_present; // whether the device is paired
	bool device_available; // whether the device is connected
	u8 device_type;
	uint16_t wireless_pid;
	char name[DEVICE_NAME_MAXLEN + 1]; // include NUL byte
	uint32_t serial_number;
	u8 power_switch_location;
	struct hidpp_version hidpp_version;
	struct version version;
};
struct device devices[DEVICES_MAX];

struct receiver_info {
	uint32_t serial_number;
	struct version version;
};

struct receiver_info receiver;

// error messages for type=8F (ERROR_MSG)
static const char * error_messages[0x100] = {
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

static const char * device_type[0x10] = {
	[0x00] = "Unknown",
	[0x01] = "Keyboard",
	[0x02] = "Mouse",
	[0x03] = "Numpad",
	[0x04] = "Presenter",
	// 0x05..0x07 Reserved for future
	[0x08] = "Trackball",
	[0x09] = "Touchpad",
	// 0x0A..0x0F Reserved
};

const char *device_type_str(u8 type) {
	if (type > 0x0F) {
		return "(invalid)";
	}
	if (device_type[type]) {
		return device_type[type];
	}
	return "(reserved)";
}

// returns device type index or -1 if the string is invalid
int device_type_from_str(const char *str) {
	unsigned i;

	// skip "Unknown" type
	for (i = 1; i < ARRAY_SIZE(device_type); i++) {
		if (device_type[i] && !strcasecmp(device_type[i], str)) {
			return i;
		}
	}

	return -1;
}
static void print_device_types(void) {
	unsigned i;

	// skip "Unknown" type
	for (i = 1; i < ARRAY_SIZE(device_type); i++) {
		if (device_type[i]) {
			fprintf(stderr, " %s", device_type[i]);
		}
	}
	putchar('\n');
}

static void dump_msg(struct hidpp_message *msg, size_t payload_size, const char *tag) {
	size_t i;

	if (!debug_enabled) {
		return;
	}

	// HACK: do not mess with stderr colors
	fflush(NULL);
	printf("\033[34m");
	printf("%s: ", tag);
	for (i=0; i<payload_size; i++) {
		printf("%02x%c", ((char *) msg)[i] & 0xFF,
				i + 1 == payload_size ? '\n' : ' ');
	}
	printf("\033[m");
	fflush(NULL);
}

static long long unsigned get_timestamp_ms(void) {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}

#include <execinfo.h>
static ssize_t do_read(int fd, struct hidpp_message *msg, u8 expected_report_id, int timeout) {
	ssize_t r;
	size_t payload_size = LONG_MESSAGE_LEN;
	long long unsigned begin_ms, end_ms;

	if (expected_report_id == SHORT_MESSAGE) {
		payload_size = SHORT_MESSAGE_LEN;
	}

	begin_ms = get_timestamp_ms();

	while (timeout > 0) {
		struct pollfd pollfd;
		pollfd.fd = fd;
		pollfd.events = POLLIN;

		r = poll(&pollfd, 1, timeout);
		if (r < 0) {
			perror("poll");
			return 0;
		} else if (r == 0) {
			DPRINTF("poll timeout reached!\n");
			// timeout
			return 0;
		}

		memset(msg, 0, payload_size);
		r = read(fd, msg, payload_size);
		if (r < 0) {
			perror("read");
			return 0;
		} else if (r > 0) {
			dump_msg(msg, r, "rd");
			if (msg->report_id == expected_report_id) {
				return r;
			} else if (expected_report_id == 0 &&
				(msg->report_id == SHORT_MESSAGE ||
				msg->report_id == LONG_MESSAGE)) {
				/* HACK: ping response for HID++ 2.0 is a LONG
				 * message, but for HID++ 1.0 it is a SHORT one. */
				return r;
			} else {
				DPRINTF("Skipping unexpected report ID %#x (want %#x)\n",
					msg->report_id, expected_report_id);
			}
		}

		/* unexpected message, try again with updated timeout */
		end_ms = get_timestamp_ms();
		timeout -= end_ms - begin_ms;
		begin_ms = end_ms;
	}

	/* timeout expired, no report found unfortunately */
	return 0;
}
static ssize_t do_write(int fd, struct hidpp_message *msg) {
	ssize_t r, payload_size = SHORT_MESSAGE_LEN;

	if (msg->report_id == LONG_MESSAGE) {
		payload_size = LONG_MESSAGE_LEN;
	}

	dump_msg(msg, payload_size, "wr");
	r = write(fd, msg, payload_size);
	if (r < 0) {
		perror("write");
	}

	return payload_size == r ? payload_size : 0;
}

const char *get_report_id_str(u8 report_type) {
	switch (report_type) {
	case SHORT_MESSAGE:
		return "short";
	case LONG_MESSAGE:
		return "long";
	default:
		return "unkn";
	}
}

bool process_notif_dev_connect(struct hidpp_message *msg, u8 *device_index,
	bool *is_new_device) {
	u8 dev_idx = msg->device_index;
	struct notif_devcon *dcon = (struct notif_devcon *) &msg->msg_short;
	struct device *dev;
	if (msg->sub_id != NOTIF_DEV_CONNECT) {
		fprintf(stderr, "Invalid msg type %#0x, expected dev conn notif\n",
			msg->sub_id);
		return false;
	}
	if (msg->report_id != SHORT_MESSAGE) {
		fprintf(stderr, "Dev conn notif is expected to be short, got "
			"%#04x instead\n", msg->report_id);
		return false;
	}
	if (dcon->prot_type != DEVCON_PROT_UNIFYING &&
	    dcon->prot_type != DEVCON_PROT_NANO_LITE) {
		fprintf(stderr, "Unknown protocol %#04x in devcon notif\n",
			dcon->prot_type);
		return false;
	}
	if (dev_idx < 1 || dev_idx > DEVICES_MAX) {
		fprintf(stderr, "Disallowed device index %#04x\n", dev_idx);
		return false;
	}

	dev = &devices[dev_idx - 1];
	if (device_index) *device_index = dev_idx;
	if (is_new_device) *is_new_device = !dev->device_present;

	memset(dev, 0, sizeof *dev);
	dev->device_type = dcon->device_info & DEVCON_DEV_TYPE_MASK;
	dev->wireless_pid = (dcon->pid_msb << 8) | dcon->pid_lsb;
	dev->device_present = true;
	dev->device_available = !(dcon->device_info & DEVCON_LINK_STATUS_FLAG);
	return true;
}

// use for reading registers and skipping notifications from return
static bool do_read_skippy(int fd, struct hidpp_message *msg,
	u8 exp_report_id, u8 exp_sub_id) {
	for (;;) {
		if (!do_read(fd, msg, exp_report_id, 2000)) {
			return false;
		}
		if (msg->report_id == exp_report_id && msg->sub_id == exp_sub_id) {
			return true;
		}

		/* ignore non-HID++ reports (e.g. DJ reports) */
		if (msg->report_id != SHORT_MESSAGE && msg->report_id != LONG_MESSAGE) {
			continue;
		}

		// guess: 0xFF is error message in HID++ 2.0?
		if (msg->report_id == LONG_MESSAGE && msg->sub_id == 0xFF) {
			if (debug_enabled) {
				fprintf(stderr, "HID++ 2.0 error %#04x\n",
					msg->msg_long.str[2]);
			}
			return false;
		}
		if (msg->report_id == SHORT_MESSAGE && msg->sub_id == SUB_ERROR_MSG
			&& msg->msg_error.sub_id == exp_sub_id) {
			struct msg_error *error = &msg->msg_error;
			// TODO: consider address (register)?
			u8 error_code = error->error_code;
			const char *err_str = error_messages[error_code];
			if (debug_enabled) {
				fprintf(stderr, "Received error for subid=%#04x,"
					" reg=%#04x: %#04x (%s)\n", error->sub_id,
					error->address, error_code, err_str);
			}
			return false;
		}
		if (msg->sub_id == NOTIF_DEV_CONNECT) {
			process_notif_dev_connect(msg, NULL, NULL);
			continue;
		} else if (msg->sub_id == NOTIF_DEV_DISCONNECT) {
			u8 device_index = msg->device_index;
			u8 disconnect_type = *(u8 *) &msg->msg_short;
			if (device_index < 1 || device_index > DEVICES_MAX) {
				fprintf(stderr, "Invalid device index %#04x\n", device_index);
			} else if (disconnect_type & 0x02) {
				memset(&devices[device_index - 1], 0, sizeof *devices);
			} else {
				fprintf(stderr, "Unexpected disconnection type %#04x\n", disconnect_type);
			}
		} else if (msg->sub_id == NOTIF_RECV_LOCK_CHANGE) {
			if (msg->report_id != SHORT_MESSAGE || msg->device_index != DEVICE_RECEIVER) {
				fprintf(stderr, "Received invalid Unifying Receiver Locking Change notification (0x4A)\n");
				continue;
			}
			// TODO: this can be used to make an application aware
			// that pairing is (not) possible (anymore)
			if (debug_enabled) {
				fprintf(stderr, "Receiver lock state is now %s\n",
					(*(u8 *)&msg->msg_short) & 1 ? "open" : "closed");
			}
		}
		if (debug_enabled &&
			(msg->report_id != exp_report_id || msg->sub_id != exp_sub_id)) {
			fprintf(stderr, "Expected %s msg %#02x, got %s msg %#02x\n",
				get_report_id_str(exp_report_id), exp_sub_id,
				get_report_id_str(msg->report_id), msg->sub_id);
		}
		// let's try reading another message...
	}
	return true;
}

// TODO: separate files
#include "hidpp20.c"

static bool set_register(int fd, u8 device_index, u8 address,
	u8 *params, struct hidpp_message *res, bool is_long_req) {
	u8 exp_sub_id;
        struct hidpp_message msg;

        msg.device_index = device_index;
	if (is_long_req) {
		msg.report_id = LONG_MESSAGE;
		exp_sub_id = SUB_SET_LONG_REGISTER;
		msg.msg_long.address = address;
		memcpy(&msg.msg_long.str, params, sizeof msg.msg_long.str);
	} else {
		msg.report_id = SHORT_MESSAGE;
		exp_sub_id = SUB_SET_REGISTER;
		msg.msg_short.address = address;
		memcpy(&msg.msg_short.value, params, sizeof msg.msg_short.value);
	}
	msg.sub_id = exp_sub_id;

        if (!do_write(fd, &msg)) {
                return false;
        }

        msg.report_id = SHORT_MESSAGE;
        if (!do_read_skippy(fd, &msg, SHORT_MESSAGE, exp_sub_id)) {
                return false;
        }
        memcpy(res, &msg, sizeof msg);
        return true;
}

bool set_short_register(int fd, u8 device_index, u8 address, u8 *params, struct hidpp_message *res) {
        return set_register(fd, device_index, address, params, res, false);
}
bool set_long_register(int fd, u8 device_index, u8 address, u8 *params, struct hidpp_message *res) {
	return set_register(fd, device_index, address, params, res, true);
}

static bool get_register(int fd, u8 device_index, u8 address,
	struct hidpp_message *out, u8 *params, bool is_long_resp) {
	u8 exp_report_id, exp_sub_id;
        struct hidpp_message msg;

	exp_report_id = is_long_resp ? LONG_MESSAGE : SHORT_MESSAGE;
	exp_sub_id = is_long_resp ? SUB_GET_LONG_REGISTER : SUB_GET_REGISTER;

        msg.report_id = SHORT_MESSAGE;
        msg.device_index = device_index;
        msg.sub_id = exp_sub_id;
        memset(msg.msg_short.value, 0, sizeof msg.msg_short.value);
	msg.msg_short.address = address;
	if (params) {
		memcpy(&msg.msg_short.value, params, sizeof msg.msg_short.value);
	}

        if (!do_write(fd, &msg)) {
                return false;
        }

        if (!do_read_skippy(fd, &msg, exp_report_id, exp_sub_id)) {
                return false;
	}
        memcpy(out, &msg, sizeof msg);
        return true;
}

bool get_short_register(int fd, u8 device_index, u8 address, u8 *params, struct hidpp_message *out) {
	return get_register(fd, device_index, address, out, params, false);
}
bool get_long_register(int fd, u8 device_index, u8 address, u8 *params, struct hidpp_message *out) {
	return get_register(fd, device_index, address, out, params, true);
}

bool get_info(int fd, struct hidpp_message *msg) {
        if (!get_long_register(fd, DEVICE_RECEIVER, REG_DEVICE_ACTIVITY, NULL, msg)) {
                return false;
        }
        return true;
}

// begin directly-usable functions
bool get_notifications(int fd, u8 device_index, struct msg_enable_notifs *params) {
	struct hidpp_message msg;
        if (!get_short_register(fd, device_index, REG_ENABLED_NOTIFS, NULL, &msg)) {
                return false;
        }
	memcpy((u8 *) params, &msg.msg_short.value, sizeof *params);
        return true;
}
bool set_notifications(int fd, u8 device_index, struct msg_enable_notifs *params) {
	struct hidpp_message msg;
        if (!set_short_register(fd, device_index, REG_ENABLED_NOTIFS, (u8 *) params, &msg)) {
                return false;
        }
        return true;
}
bool get_and_print_notifications(int fd, u8 device_index, struct msg_enable_notifs *notifsp) {
	putchar('\n');
	if (get_notifications(fd, device_index, notifsp)) {
		u8 flags = notifsp->reporting_flags_receiver;
		printf("Reporting Flags (Receiver) = %02x\n", flags & 0xFF);
		printf("Wireless notifications     = %s\n", flags & 1 ? "yes" : "no");
		printf("Software Present           = %s\n", flags & 4 ? "yes" : "no");
		return true;
	} else {
		fprintf(stderr, "Failed to get HID++ Notification status\n");
		return false;
	}
}

bool get_connected_devices(int fd, u8 *devices_count) {
	struct hidpp_message msg;
	struct val_reg_connection_state *cval;
	if (!get_short_register(fd, DEVICE_RECEIVER, REG_CONNECTION_STATE, NULL, &msg)) {
		return false;
	}
	cval = (struct val_reg_connection_state *) msg.msg_short.value;
	*devices_count = cval->connected_devices_count;
	return true;
}

bool pair_start(int fd, u8 timeout) {
	struct hidpp_message msg;
	struct val_reg_devpair cmd;
	cmd.action = DEVPAIR_OPEN_LOCK;
	// device_index is 1..6 for a specific device, 0x53 is seen for "any
	// device".  Not sure if this is a special value or randomly chosen
	cmd.device_number = 0;
	cmd.open_lock_timeout = timeout;
	if (!set_short_register(fd, DEVICE_RECEIVER, REG_DEVICE_PAIRING, (u8 *) &cmd, &msg)) {
		return false;
	}
	return true;
}

bool pair_cancel(int fd) {
	struct hidpp_message msg;
	struct val_reg_devpair cmd;
	cmd.action = DEVPAIR_CLOSE_LOCK;
	// see discussion at pair_start, why did logitech use 0x53? Confusion?
	cmd.device_number = 0;
	// timeout applies to open lock, not sure why I saw 0x94 (148 sec)
	cmd.open_lock_timeout = 0;
	if (!set_short_register(fd, DEVICE_RECEIVER, REG_DEVICE_PAIRING, (u8 *) &cmd, &msg)) {
		return false;
	}
	return true;
}

bool device_unpair(int fd, u8 device_index) {
	struct hidpp_message msg;
	struct val_reg_devpair cmd;
	cmd.action = DEVPAIR_DISCONNECT;
	cmd.device_number = device_index;
	cmd.open_lock_timeout = 0;
	if (!set_short_register(fd, DEVICE_RECEIVER, REG_DEVICE_PAIRING, (u8 *) &cmd, &msg)) {
		return false;
	}
	return true;
}

void perform_pair(int fd, u8 timeout) {
	struct hidpp_message msg;
	if (timeout == 0) {
		timeout = 30;
	}
	if (!pair_start(fd, timeout)) {
		fprintf(stderr, "Failed to send pair request\n");
		return;
	}
	puts("Please turn your wireless device off and on to start pairing.");
	// WARNING: mess ahead. I knew it would become messy before writing it.
	for (;;) {
		if (!do_read(fd, &msg, SHORT_MESSAGE, timeout * 1000 + 2000)) {
			fprintf(stderr, "Failed to read short message\n");
			break;
		}
		if (msg.sub_id == NOTIF_RECV_LOCK_CHANGE) {
			u8 *bytes = (u8 *) &msg.msg_short;
			if (msg.report_id != SHORT_MESSAGE || msg.device_index != DEVICE_RECEIVER) {
				fprintf(stderr, "Received invalid Unifying Receiver Locking Change notification (0x4A)\n");
				continue;
			}
			if (bytes[0] & 1) { // locking open
				continue;
			} else { // locking closed
				const char *result;
				switch (bytes[1]) {
				case 0x00:
					result = "Success";
					break;
				case 0x01:
					result = "Timeout";
					break;
				default:
					result = "Failure";
				}
				printf("Pairing result: %s (%i)\n", result, bytes[1]);
				break;
			}
		} else if (msg.sub_id == NOTIF_DEV_CONNECT) {
			u8 device_index;
			bool is_new_dev;
			if (!process_notif_dev_connect(&msg, &device_index, &is_new_dev)) {
				// error message is already emitted
				continue;
			}

			if (device_index < 1 || device_index > DEVICES_MAX) {
				fprintf(stderr, "Invalid device index %#04x\n", device_index);
			} else if (is_new_dev) {
				u8 device_type = devices[device_index - 1].device_type;
				printf("Found new device, id=%#04x %s\n",
					device_index,
					device_type_str(device_type));
				break;
			} else {
				printf("Ignoring existent device id=%#04x\n", device_index);
			}
		}
	}
	// end of mess
	if (!pair_cancel(fd)) {
		fprintf(stderr, "Failed to cancel pair visibility\n");
	}
}
void perform_unpair(int fd, u8 device_index) {
	struct device *dev = &devices[device_index - 1];
	u8 dev_device_type = dev->device_type; // will be overwritten, therefore store it
	if (!dev->device_present) {
		printf("Device %#04x does not appear to be paired\n", device_index);
		return;
	}
	if (device_unpair(fd, device_index)) {
		if (!dev->device_present) {
			printf("Device %#04x %s successfully unpaired\n", device_index,
				device_type_str(dev_device_type));
		} else {
			fprintf(stderr, "Unpairing of %#04x possibly failed\n", device_index);
		}
	} else {
		fprintf(stderr, "Failed to send unpair %#04x request\n", device_index);
	}
}

// triggers a notification that updates the list of paired devices
bool get_all_devices(int fd) {
	struct hidpp_message msg;
	struct val_reg_connection_state cval;
	memset(&cval, 0, sizeof cval);
	cval.action = CONSTATE_ACTION_LIST_DEVICES;
	if (!set_short_register(fd, DEVICE_RECEIVER, REG_CONNECTION_STATE, (u8 *) &cval, &msg)) {
		return false;
	}
	return true;
}
bool get_receiver_info(int fd, struct receiver_info *rinfo) {
	struct hidpp_message msg;
	u8 params[3] = {0};

	params[0] = 0x03; // undocumented
	if (get_long_register(fd, DEVICE_RECEIVER, REG_PAIRING_INFO, params, &msg)) {
		struct msg_receiver_info *info = (struct msg_receiver_info *) &msg.msg_long.str;
		uint32_t serial_number;

		memcpy(&serial_number, &info->serial_number, sizeof(serial_number));
		rinfo->serial_number = ntohl(serial_number);
		return true;
	}
	return false;
}
bool get_device_pair_info(int fd, u8 device_index) {
	struct device *dev = &devices[device_index - 1];
	struct hidpp_message msg;
	u8 params[3] = {0};

	params[0] = 0x20 | (device_index - 1); // 0x20..0x2F Unifying Device pairing info
	if (get_long_register(fd, DEVICE_RECEIVER, REG_PAIRING_INFO, params, &msg)) {
		struct msg_dev_pair_info *info = (struct msg_dev_pair_info *) &msg.msg_long.str;

		dev->wireless_pid = (info->pid_msb << 8) | info->pid_lsb;
		dev->device_type = info->device_type;
		return true;
	}
	return false;
}
bool get_device_ext_pair_info(int fd, u8 device_index) {
	struct device *dev = &devices[device_index - 1];
	struct hidpp_message msg;
	u8 params[3] = {0};

	params[0] = 0x30 | (device_index - 1); // 0x30..0x3F Unifying Device extended pairing info
	if (get_long_register(fd, DEVICE_RECEIVER, REG_PAIRING_INFO, params, &msg)) {
		struct msg_dev_ext_pair_info *info;
		uint32_t serial_number;

		info = (struct msg_dev_ext_pair_info *) &msg.msg_long.str;
		memcpy(&serial_number, &info->serial_number, sizeof(serial_number));
		dev->serial_number = ntohl(serial_number);
		dev->power_switch_location = info->usability_info & 0x0F;
		return true;
	}
	return false;
}
bool get_device_name(int fd, u8 device_index) {
	struct device *dev = &devices[device_index - 1];
	struct hidpp_message msg;
	u8 params[3] = {0};

	params[0] = 0x40 | (device_index - 1); // 0x40..0x4F Unifying Device Name
	if (get_long_register(fd, DEVICE_RECEIVER, REG_PAIRING_INFO, params, &msg)) {
		struct msg_dev_name *name = (struct msg_dev_name *) &msg.msg_long.str;
		if (name->length > DEVICE_NAME_MAXLEN) {
			fprintf(stderr, "Invalid name length %#04x for idx=%i\n", name->length, device_index);
			return false;
		}

		memcpy(&dev->name, name->str, name->length);
		dev->name[name->length] = 0;
		return true;
	}
	return false;
}

bool get_hidpp_version(int fd, u8 device_index, struct hidpp_version *version) {
	struct hidpp_message msg;
	struct msg_short *payload = &msg.msg_short;
	u8 softwareId = 0x04; // value 1..15 - random choice for 0x4
	u8 ping_data = 0x00; // can be any value

	msg.report_id = SHORT_MESSAGE;
	msg.device_index = device_index;
	msg.sub_id = 0x00; // Root feature index

	memset(payload->value, 0, sizeof payload->value);
	payload->address = 0x10 | softwareId;
	payload->value[2] = ping_data;
	if (!do_write(fd, &msg)) {
		return false;
	}
	for (;;) {
		if (!do_read(fd, &msg, 0, 3000)) {
			if (debug_enabled) {
				fprintf(stderr, "Failed to read HID++ version, device does not respond!\n");
			}
			return false;
		}
		if (msg.sub_id == 0x8F) {
			struct msg_error *error = (struct msg_error *) &msg.msg_error;
			if (error->sub_id == 0x00 && error->address == (0x10 | softwareId)) {
				// if error is ERR_INVALID_SUBID (0x01), then HID++ 1.0
				if (error->error_code == 0x01) {
					version->major = 1;
					version->minor = 0;
					return true;
				} else if (debug_enabled) {
					const char *err_str = error_messages[error->error_code];
					fprintf(stderr, "Failed to retrieve version: %#04x (%s)\n",
						error->error_code, err_str);
				}
				// fatal error - is device connected?
				return false;
			}
			// ignore other errors
		}
		if (msg.sub_id == 0x00 && (payload->address & 0xF) == softwareId &&
			payload->value[2] == ping_data) {
			break; // I think we got a version
		} else if (debug_enabled) {
			fprintf(stderr, "Ignoring sub_id=%02x\n", msg.sub_id);
		}
		// ignore other messages
	}

	version->major = payload->value[0];
	version->minor = payload->value[1];
	return true;
}

// device_index can also be 0xFF for receiver
bool get_device_version(int fd, u8 device_index, u8 version_type, struct val_reg_version *ver) {
	struct hidpp_message msg;
	// TODO: not 100% reliable for wireless devices, it may return MSG_ERR
	// (err=SUCCESS, wtf). Perhaps we need to send another msg type=00
	// (whatever the undocumented params are).

	memset(ver, 0, sizeof *ver);
	ver->select_field = version_type;
	if (get_short_register(fd, device_index, REG_VERSION_INFO, (u8 *) ver, &msg)) {
		memcpy(ver, msg.msg_short.value, sizeof *ver);
		return true;
	}
	return false;
}

bool get_device_versions(int fd, u8 device_index, struct version *version) {
	struct val_reg_version ver;

	memset(version, 0, sizeof *version);

	if (get_device_version(fd, device_index, VERSION_FIRMWARE, &ver)) {
		version->fw_major = ver.v1;
		version->fw_minor = ver.v2;
	} else {
		// assume that other versions will fail too
		return false;
	}
	if (get_device_version(fd, device_index, VERSION_FW_BUILD, &ver)) {
		version->fw_build = (ver.v1 << 8) | ver.v2;
	}
	//if (get_device_version(fd, device_index, 3, &ver)) puts("No idea what this is useful for");
	if (get_device_version(fd, device_index, VERSION_BOOTLOADER, &ver)) {
		version->bl_major = ver.v1;
		version->bl_minor = ver.v2;
	}
	return true;
}

// device index is 1..6
void gather_device_info(int fd, u8 device_index) {
	if (get_device_pair_info(fd, device_index)) {
		struct device *dev = &devices[device_index - 1];

		dev->device_present = true;

		get_hidpp_version(fd, device_index, &dev->hidpp_version);
		get_device_ext_pair_info(fd, device_index);
		get_device_name(fd, device_index);
		if (dev->hidpp_version.major == 1 && dev->hidpp_version.minor == 0) {
			if (get_device_versions(fd, device_index, &dev->version)) {
				dev->device_available = true;
			}
		} else {
			// TODO: hid++20 support
		}
	} else {
		// retrieve some information from notifier
		get_all_devices(fd);
	}
}

void print_versions(struct version *ver) {
	// versions are shown as hex. Probably a mistake given that the length
	// is 3 which can fit 255 instead of FF (and 65535 instead of FF)
	printf("Firmware version: %03x.%03x.%05x\n",
			ver->fw_major, ver->fw_minor, ver->fw_build);
	printf("Bootloader version: BL.%03x.%03x\n",
			ver->bl_major, ver->bl_minor);
}

void get_and_print_recv_info(int fd) {
	if (get_receiver_info(fd, &receiver)) {
		printf("Serial number: %08X\n", receiver.serial_number);
	}
	if (get_device_versions(fd, DEVICE_RECEIVER, &receiver.version)) {
		print_versions(&receiver.version);
	}
}

void print_detailed_device(u8 device_index) {
	struct device *dev = &devices[device_index - 1];

	if (!dev->device_present) {
		printf("Device %i is not paired\n", device_index);
		return;
	}

	if (dev->hidpp_version.major) {
		printf("HID++ version: %i.%i\n", dev->hidpp_version.major, dev->hidpp_version.minor);
	} else {
		puts("HID++ version: unknown");
	}
	printf("Device index %i\n", device_index);
	printf("%s\n", device_type_str(dev->device_type));
	printf("Name: %s\n", dev->name);
	printf("Wireless Product ID: %04X\n", dev->wireless_pid);
	printf("Serial number: %08X\n", dev->serial_number);
	if (dev->device_available) {
		print_versions(&dev->version);
	} else {
		puts("Device was unavailable, version information not available.");
	}
}
void get_device_names(int fd) {
	u8 i;

	for (i=0; i<DEVICES_MAX; i++) {
		struct device *dev = &devices[i];
		if (!dev->device_present) {
			continue;
		}

		if (!get_device_name(fd, i + 1)) {
			fprintf(stderr, "Failed to read device name for idx=%i\n", i + 1);
		}
	}
}

static void print_version(void) {
	fprintf(stderr,
"Logitech Unifying tool version " PACKAGE_VERSION "\n"
"Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>\n");
}

void print_all_devices(void) {
	unsigned i;
	puts("Connected devices:");
	for (i=0; i<DEVICES_MAX; i++) {
		struct device *dev = &devices[i];
		if (!dev->device_present) {
			continue;
		}

		printf("idx=%i\t%s\t%s\n", i + 1,
			device_type_str(dev->device_type), dev->name);
	}
}

static void print_usage(const char *program_name) {
	fprintf(stderr, "Usage: %s [options] cmd [cmd options]\n",
		program_name);
	print_version();
	fprintf(stderr,
"\n"
"Generic options:\n"
"  -d, --device path Bypass detection, specify custom hidraw device.\n"
"  -D                Print debugging information\n"
"  -h, --help        Show this help message\n"
"\n"
"Commands:\n"
"  list            - show all paired devices\n"
"  pair [timeout]  - Try to pair within \"timeout\" seconds (1 to 255,\n"
"                    default 0 which is an alias for 30s)\n"
"  unpair idx      - Unpair device\n"
"  info idx        - Show more detailed information for a device\n"
"  receiver-info   - Show information about the receiver\n"
"In the above lines, \"idx\" refers to the device number shown in the\n"
" first column of the list command (between 1 and 6). Alternatively, you\n"
" can use the following names (case-insensitive):\n");
	print_device_types();
}

static bool is_numeric_device_index(const char *str) {
	char *end;
	unsigned long device_index = strtoul(str, &end, 0);

	// if a number was found, there must be no other characters thereafter
	return !*end &&
		device_index >= 1 && device_index <= DEVICES_MAX;
}

// Return number of commands and command arguments, -1 on error. If the program
// should not run (--help), then 0 is returned and args is NULL.
static int validate_args(int argc, char **argv, char ***argsp, char **hidraw_path) {
	int args_count;
	char *cmd;
	int opt;
	char **args;
	struct option longopts[] = {
		{ "device",     1, NULL, 'd' },
		{ "help",       0, NULL, 'h' },
		{ "version",	0, NULL, 'V' },
		{ 0, 0, 0, 0 },
	};

	*argsp = NULL;

	while ((opt = getopt_long(argc, argv, "+Dd:hV", longopts, NULL)) != -1) {
		switch (opt) {
		case 'D':
			debug_enabled = true;
			break;
		case 'd':
			*hidraw_path = optarg;
			break;
		case 'V':
			print_version();
			return 0;
		case 'h':
			print_usage(*argv);
			return 0;
		default:
			return -1;
		}
	}

	if (optind >= argc) {
		// missing command
		print_usage(*argv);
		return -1;
	}
	*argsp = args = &argv[optind];
	args_count = argc - optind - 1;

	cmd = args[0];
	if (!strcmp(cmd, "list") || !strcmp(cmd, "receiver-info")) {
		/* nothing to check */
	} else if (!strcmp(cmd, "pair")) {
		if (args_count >= 1) {
			char *end;
			unsigned long int n;
			n = strtoul(args[1], &end, 0);
			if (*end != '\0' || n > 0xFF) {
				fprintf(stderr, "Timeout must be a number between 0 and 255\n");
				return -1;
			}
		}
	} else if (!strcmp(cmd, "unpair") || !strcmp(cmd, "info")) {
		if (args_count < 1) {
			fprintf(stderr, "%s requires a device index\n", cmd);
			return -1;
		}
		if (!is_numeric_device_index(args[1]) &&
			device_type_from_str(args[1]) == -1) {
			fprintf(stderr, "Invalid device type, must be a numeric index or:\n");
			print_device_types();
			return -1;
		}
	} else {
		fprintf(stderr, "Unrecognized command: %s\n", cmd);
		return -1;
	}
	return args_count;
}

#ifdef __GNUC__
static FILE *fopen_format(const char *format, ...)
__attribute__((format(printf, 1, 2)));
#endif

static FILE *fopen_format(const char *format, ...) {
	char buf[1024];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buf, sizeof buf, format, ap);
	va_end(ap);
	return fopen(buf, "r");
}

#define RECEIVER_NAME "logitech-djreceiver"
int open_hidraw(void) {
	int fd = -1;
	glob_t matches;
	char hiddev_name[32] = {0};

	if (!glob("/sys/class/hidraw/hidraw*/device/driver", 0, NULL, &matches)) {
		size_t i;
		char buf[1024];
		for (i = 0; i < matches.gl_pathc; i++) {
			ssize_t r;
			char *name = matches.gl_pathv[i];
			const char *last_comp;
			char *dev_name;
			FILE *fp;
			uint32_t vid = 0, pid = 0;

			r = readlink(name, buf, (sizeof buf) - 1);
			if (r < 0) {
				perror(name);
				continue;
			}

			buf[r] = 0; /* readlink does not NUL-terminate */
			last_comp = basename(buf);

			/* retrieve 'hidrawX' name */
			dev_name = name + sizeof "/sys/class/hidraw";
			*(strchr(dev_name, '/')) = 0;

			// Assume that the first match is the receiver. Devices bound to the
			// same receiver may have the same modalias.
			if ((fp = fopen_format("/sys/class/hidraw/%s/device/modalias", dev_name))) {
				int m = fscanf(fp, "hid:b%*04Xg%*04Xv%08Xp%08X", &vid, &pid);
				if (m != 2) {
					pid = 0;
				}
				fclose(fp);
			}
			if (vid != VID_LOGITECH) {
				continue;
			}

			if (!strcmp(last_comp, RECEIVER_NAME)) {
				/* Logitech receiver c52b and c532 - pass.
				 *
				 * Logitech Nano receiver c534 however has
				 * multiple hidraw devices, but the first one is
				 * only used for keyboard events and should be
				 * ignored. The second one is for the mouse, and
				 * that interface has a vendor-specific HID page
				 * for HID++.
				 * Parsing .../device/report_descriptor is much
				 * more complicated, so stick with knowledge
				 * about device-specific interfaces for now.
				 */
				if (pid == PID_NANO_RECEIVER_2) {
					int iface = -1;
					if ((fp = fopen_format("/sys/class/hidraw/%s/device/../bInterfaceNumber", dev_name))) {
						fscanf(fp, "%02x", &iface);
						fclose(fp);
					}
					if (iface == 0) {
						/* Skip first interface. */
						continue;
					}
				}
			} else if (!strcmp(last_comp, "hid-generic")) {
				/* need to test for older nano receiver c52f */
				if (pid != PID_NANO_RECEIVER) {
					continue;
				}
			} else { /* unknown driver */
				continue;
			}

			snprintf(hiddev_name, sizeof hiddev_name, "/dev/%s", dev_name);
			fd = open(hiddev_name, O_RDWR);
			if (fd < 0) {
				perror(hiddev_name);
			} else {
				break;
			}
		}
	}

	if (fd < 0) {
		if (*hiddev_name) {
			fprintf(stderr, "Logitech Unifying Receiver device is not accessible.\n"
				"Try running this program as root or enable read/write permissions\n"
				"for %s\n", hiddev_name);
		} else {
			fprintf(stderr, "No Logitech Unifying Receiver device found\n");
			if (access("/sys/class/hidraw", R_OK)) {
				fputs("The kernel must have CONFIG_HIDRAW enabled.\n",
					stderr);
			}
			if (access("/sys/module/hid_logitech_dj", F_OK)) {
				fprintf(stderr, "Driver is not loaded, try:"
						"   sudo modprobe hid-logitech-dj\n");
			}
		}
	}
	globfree(&matches);

	return fd;
}

// returns device index starting at 1 or 0 on failure
static u8 find_device_index_for_type(int fd, const char *str, bool *fetched_devices) {
	char *end;
	u8 device_index;

	device_index = strtoul(str, &end, 0);
	if (*end == '\0') {
		return device_index;
	}

	if (get_all_devices(fd)) {
		u8 i;
		int device_type_n;

		device_type_n = device_type_from_str(str);
		if (fetched_devices) {
			*fetched_devices = true;
		}

		for (i = 0; i < DEVICES_MAX; i++) {
			if (devices[i].device_type == device_type_n) {
				return i + 1;
			}
		}
	} else {
		fprintf(stderr, "Unable to request a list of paired devices");
	}
	return 0;
}

int main(int argc, char **argv) {
        int fd;
	struct msg_enable_notifs notifs;
	char *cmd, **args;
	int args_count;
	char *hidraw_path = NULL;
	bool disable_notifs = false;

	args_count = validate_args(argc, argv, &args, &hidraw_path);
        if (args_count < 0) {
		return 1;
	} else if (args == NULL) {
		return 0;
	}
	cmd = args[0];

	if (hidraw_path) {
		fd = open(hidraw_path, O_RDWR);
		if (fd < 0) {
			perror(hidraw_path);
		}
	} else {
		fd = open_hidraw();
	}
        if (fd < 0) {
                return 1;
        }

	if (debug_enabled) {
		if (!get_and_print_notifications(fd, DEVICE_RECEIVER, &notifs)) {
			goto end_close;
		}
	} else {
		if (!get_notifications(fd, DEVICE_RECEIVER, &notifs)) {
			fprintf(stderr, "Failed to retrieve notification state\n");
			goto end_close;
		}
	}

	if (!notifs.reporting_flags_receiver) {
		disable_notifs = true;
		notifs.reporting_flags_receiver |= 1;
		if (set_notifications(fd, DEVICE_RECEIVER, &notifs)) {
			if (debug_enabled) {
				puts("Successfully enabled notifications");
			}
		} else {
			fprintf(stderr, "Failed to set HID++ Notification status\n");
		}
	}

	if (!strcmp(cmd, "pair")) {
		u8 timeout = 0;
		if (args_count >= 1) {
			timeout = (u8) strtoul(args[1], NULL, 0);
		}
		perform_pair(fd, timeout);
	} else if (!strcmp(cmd, "unpair")) {
		bool fetched_devices = false;
		u8 device_index;
		device_index = find_device_index_for_type(fd, args[1], &fetched_devices);
		if (!fetched_devices && !get_all_devices(fd)) {
			fprintf(stderr, "Unable to request a list of paired devices\n");
		}
		if (device_index) {
			perform_unpair(fd, device_index);
		} else {
			fprintf(stderr, "Device %s not found\n", args[1]);
		}
	} else if (!strcmp(cmd, "list")) {
		u8 device_count;
		if (get_connected_devices(fd, &device_count)) {
			printf("Devices count: %i\n", device_count);
		} else {
			fprintf(stderr, "Failed to get connected devices count\n");
		}

		if (get_all_devices(fd)) {
			get_device_names(fd);
			print_all_devices();
		} else {
			fprintf(stderr, "Unable to request a list of paired devices\n");
		}
	} else if (!strcmp(cmd, "info")) {
		u8 device_index;

		device_index = find_device_index_for_type(fd, args[1], NULL);
		if (device_index) {
			struct device *dev = &devices[device_index - 1];
			gather_device_info(fd, device_index);
			print_detailed_device(device_index);
			if (dev->hidpp_version.major == 2 && dev->hidpp_version.minor == 0) {
				// TODO: separate fetch/print
				hidpp20_print_features(fd, device_index);
			}
		} else {
			fprintf(stderr, "Device %s not found\n", args[1]);
		}
	} else if (!strcmp(cmd, "receiver-info")) {
		get_and_print_recv_info(fd);
	} else {
		fprintf(stderr, "Unhandled command: %s\n", cmd);
	}

	if (disable_notifs) {
		notifs.reporting_flags_receiver &= ~1;
		if (set_notifications(fd, DEVICE_RECEIVER, &notifs)) {
			if (debug_enabled) {
				puts("Successfully disabled notifications");
			}
		} else {
			fprintf(stderr, "Failed to set HID++ Notification status\n");
		}
	}

	if (debug_enabled) {
		get_and_print_notifications(fd, DEVICE_RECEIVER, &notifs);
	}

end_close:
        close(fd);

        return 0;
}
