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
#include <signal.h>
#include <stdlib.h> /* strtoul */
#include <stdint.h> /* uint16_t */
#include <arpa/inet.h> /* ntohs, ntohl */

// Set DEBUG envvar to enable printing extra verbose details
static bool debug_enabled;

typedef unsigned char u8;

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
	u8 reporting_flags_receiver; // bit 0 Wireless noitifcations, 3 Software Present
	u8 reporting_flags_receiver2; // (reserved)
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
	struct version version;
};
struct device devices[DEVICES_MAX];

// error messages for type=8F (ERROR_MSG)
static const char * error_messages[0xFF] = {
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

static const char * device_type[0x0F] = {
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

static ssize_t do_io(int fd, struct hidpp_message *msg, bool is_write) {
        ssize_t r;
        size_t payload_size = SHORT_MESSAGE_LEN;

        if (msg->report_id == LONG_MESSAGE) {
                payload_size = LONG_MESSAGE_LEN;
        }

	if (is_write) {
		dump_msg(msg, payload_size, "wr");
		r = write(fd, msg, payload_size);
	} else {
		r = read(fd, msg, payload_size);
		if (r >= 0) {
			int saved_errno = errno;
			dump_msg(msg, r, "rd");
			errno = saved_errno;
		}
	}
        if ((size_t) r == payload_size
		|| (msg->report_id == SUB_ERROR_MSG && r == SHORT_MESSAGE_LEN)) {
		return payload_size;
	}

	if (r < 0) {
		perror(is_write ? "write" : "read");
	}
	return 0;
}
static ssize_t do_read(int fd, struct hidpp_message *msg) {
	return do_io(fd, msg, false);
}
static ssize_t do_write(int fd, struct hidpp_message *msg) {
	return do_io(fd, msg, true);
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
		fprintf(stderr, "Dev conn notif is exoected to be short, got "
			"%#04x instead\n", msg->report_id);
		return false;
	}
	if (dcon->prot_type != DEVCON_PROT_UNIFYING) {
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

	memset(&devices[dev_idx], 0, sizeof devices[dev_idx]);
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
		msg->report_id = exp_report_id;
		if (!do_read(fd, msg)) {
			return false;
		}
		if (msg->report_id == exp_report_id && msg->sub_id == exp_sub_id) {
			return true;
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

static bool set_register(int fd, u8 device_index, u8 address,
	u8 *params, struct hidpp_message *res, bool is_long_req) {
	u8 exp_sub_id;
        struct hidpp_message msg;

        msg.device_index = device_index;
	if (is_long_req) {
		msg.report_id = LONG_MESSAGE;
		exp_sub_id = SUB_SET_LONG_REGISTER;
		msg.msg_long.address = address;
		memcpy(&msg.msg_long.str, params, LONG_MESSAGE_LEN - HEADER_SIZE);
	} else {
		msg.report_id = SHORT_MESSAGE;
		exp_sub_id = SUB_SET_REGISTER;
		msg.msg_short.address = address;
		memcpy(&msg.msg_short.value, params, SHORT_MESSAGE_LEN - HEADER_SIZE);
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
		memcpy(&msg.msg_short.value, params, SHORT_MESSAGE_LEN - HEADER_SIZE);
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
	if (!pair_start(fd, timeout)) {
		fprintf(stderr, "Failed to send pair request\n");
		return;
	}
	// WARNING: mess ahead. I knew it would become messy before writing it.
	for (;;) {
		msg.report_id = SHORT_MESSAGE;
		if (!do_read(fd, &msg)) {
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
	if (!dev->device_present) {
		printf("Device %#04x does not appear to be paired\n", device_index);
		return;
	}
	if (device_unpair(fd, device_index)) {
		if (!dev->device_present) {
			printf("Device %#04x succesfully unpaired\n", device_index);
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
		uint32_t *serial_numberp;

		info = (struct msg_dev_ext_pair_info *) &msg.msg_long.str;
		serial_numberp = (uint32_t *) &info->serial_number;

		dev->serial_number = ntohl(*serial_numberp);
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

// device_index can also be 0xFF for receiver
bool get_device_version(int fd, u8 device_index, u8 version_type, struct val_reg_version *ver) {
	struct hidpp_message msg;
	// TODO: not 100% reliable for wireless devices, it may return MSG_ERR
	// (err=SUCCESS, wtf). Perhaps we need to send another msg type=00
	// (whatever the undocumened params are).

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

		get_device_ext_pair_info(fd, device_index);
		get_device_name(fd, device_index);
		if (get_device_versions(fd, device_index, &dev->version)) {
			dev->device_available = true;
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

void get_and_print_recv_fw(int fd) {
	struct version version;

	if (get_device_versions(fd, DEVICE_RECEIVER, &version)) {
		print_versions(&version);
		putchar('\n');
	}
}

void print_detailed_device(u8 device_index) {
	struct device *dev = &devices[device_index - 1];

	if (!dev->device_present) {
		printf("Device %i is not paired\n", device_index);
		return;
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

// begin signal functions
static bool stopping;
static void sig_handler(int signum) {
	if (signum != SIGINT) {
		return;
	}
	fprintf(stderr, "Caught SIGINT, shutting down\n");
	stopping = true;
}
static void install_sighandlers(void) {
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = sig_handler;
	sigaction(SIGINT, &sa, NULL);
}
// end signal functions

static void print_usage(const char *program_name) {
	fprintf(stderr, "Usage: %s /dev/hidrawX cmd [cmd options]\n"
"Logitech Unifying tool\n"
"Copyright (C) 2013 Peter Wu <lekensteyn@gmail.com>\n"
"\n"
"Commands:\n"
"  list            - show all paired devices\n"
"  pair [timeout]  - Try to pair within \"timeout\" seconds (1 to 255,\n"
"                    default 0 which is an alias for 30s)\n"
"  unpair idx      - Unpair device\n"
"  info idx        - Show more detailled information for a device\n"
"In the above lines, \"idx\" refers to the device number shown in the\n"
" first column of the list command (between 1 and 6).\n"
	, program_name);
}

static bool validate_args(int argc, char **argv) {
	char *cmd;

	if (argc < 3) {
		return false;
	}

	cmd = argv[2];
	if (!strcmp(cmd, "list")) {
		return true;
	} else if (!strcmp(cmd, "pair")) {
		// timeout is optional, do not check
		return true;
	} else if (!strcmp(cmd, "unpair") || !strcmp(cmd, "info")) {
		u8 device_index;
		if (argc < 4) {
			return false;
		}
		device_index = (u8) strtoul(argv[3], NULL, 0);
		if (device_index < 1 || device_index > DEVICES_MAX) {
			fprintf(stderr, "Device index must be between 1 and 6.\n");
			return false;
		}
		return true;
	}

	// unrecognized command
	return false;
}

int main(int argc, char **argv) {
        int fd;
	struct msg_enable_notifs notifs;
	char *cmd;

	debug_enabled = !!getenv("DEBUG");

        if (!validate_args(argc, argv)) {
		print_usage(*argv);
		return 1;
        }
	cmd = argv[2];

        fd = open(argv[1], O_RDWR);
        if (fd < 0) {
                perror(argv[1]);
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

	install_sighandlers();

	notifs.reporting_flags_receiver |= 1;
	if (set_notifications(fd, DEVICE_RECEIVER, &notifs)) {
		if (debug_enabled) {
			puts("Succesfully enabled notifications");
		}
	} else {
		fprintf(stderr, "Failed to set HID++ Notification status\n");
	}

	if (!strcmp(cmd, "pair")) {
		u8 timeout = 0;
		if (argc >= 4) {
			timeout = (u8) strtoul(argv[3], NULL, 0);
		}
		perform_pair(fd, timeout);
	} else if (!strcmp(cmd, "unpair")) {
		u8 device_index;
		device_index = (u8) strtoul(argv[3], NULL, 0);
		if (!get_all_devices(fd)) {
			fprintf(stderr, "Unable to request a list of paired devices\n");
		}
		perform_unpair(fd, device_index);
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

		get_and_print_recv_fw(fd);

		device_index = (u8) strtoul(argv[3], NULL, 0);
		gather_device_info(fd, device_index);
		print_detailed_device(device_index);
	} else {
		print_usage(*argv);
		goto end_notifs;
	}

#if 0
        struct hidpp_message msg;
        while (!stopping && get_info(fd, &msg)) {
                u8 *resp = msg.msg_long.str;
                unsigned i;
		// activity counter for each device
                for (i=0; i<DEVICES_MAX; i++) {
                        printf("%2x%c", resp[i], i == 5 ? '\n' : ' ');
                }
                usleep(100000);
		getchar();
        }
#endif

end_notifs:
	notifs.reporting_flags_receiver &= ~1;
	if (set_notifications(fd, DEVICE_RECEIVER, &notifs)) {
		if (debug_enabled) {
			puts("Succesfully disabled notifications");
		}
	} else {
		fprintf(stderr, "Failed to set HID++ Notification status\n");
	}

	if (debug_enabled) {
		get_and_print_notifications(fd, DEVICE_RECEIVER, &notifs);
	}

end_close:
        close(fd);

        return 0;
}
