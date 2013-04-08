#!/usr/bin/gawk -f
# Formats the output of usbmon, assuming Logitech Unifying Receiver protocol
# Usage: sudo cat /sys/kernel/debug/usb/usbmon/5u | usbmon.awk
# (on older gawk versions, use gawk --re-interval -f usbmon.awk)
#
# Author: Peter Wu <lekensteyn@gmail.com>
# Date: 2013-04-04

BEGIN {
	OFS="   ";
# Taken from Linux source, drivers/hid/hid-logitech-dj.h
# Catgegories are taken from patent description of US8386651
# 0x00 - 0x3F HID reports
types["01"] = "KEYBOARD";
types["02"] = "MOUSE";
types["03"] = "CONSUMER_CONTROL";
types["04"] = "SYSTEM_CONTROL";

types["08"] = "MEDIA_CENTER";

types["0E"] = "LEDS";

# 0x40 - 0x7F enumerator notifications
types["40"] = "NOTIF_DEVICE_UNPAIRED";
types["41"] = "NOTIF_DEVICE_PAIRED";
types["42"] = "NOTIF_CONNECTION_STATUS";
types["4A"] = "NOTIF_RECV_LOCK_CHANGED"; # 0100 0000 = ready for connections, 0010 0000 = new connections disabled
types["4B"] = "?NOTIF_PAIR_ACCEPTED"; # 0100 0000

types["7F"] = "NOTIF_ERROR";

# 0x80 - 0xFF enumerator commands; Register Access
types["80"] = "SET_REG"; # CMD_SWITCH
types["81"] = "GET_REG"; # CMD_GET_PAIRED_DEVICES
types["82"] = "SET_LONG_REG";
types["83"] = "GET_LONG_REG";
types["8F"] = "_ERROR_MSG";
# Align type name
maxlen=0;
for (i in types) {
	if (maxlen < length(types[i])) {
		maxlen = length(types[i]);
	}
}

# error messages for type=8F (ERROR_MSG)
errmsgs["01"] = "SUCCESS";
errmsgs["02"] = "INVALID_SUBID";
errmsgs["03"] = "INVALID_ADDRESS";
errmsgs["04"] = "INVALID_VALUE";
errmsgs["05"] = "CONNECT_FAIL";
errmsgs["06"] = "TOO_MANY_DEVICES";
errmsgs["07"] = "ALREADY_EXISTS";
errmsgs["08"] = "BUSY";
errmsgs["09"] = "UNKNOWN_DEVICE";
errmsgs["0a"] = "RESOURCE_ERROR";
errmsgs["0b"] = "REQUEST_UNAVAILABLE";
errmsgs["0c"] = "INVALID_PARAM_VALUE";
errmsgs["0d"] = "WRONG_PIN_CODE";

regs["00"] = "ENABLED_NOTIFS";
regs["02"] = "CONNECTION_STATE";
regs["b2"] = "DEVICE_PAIRING";
regs["b3"] = "DEVICE_ACTIVITY";
regs["b5"] = "PAIRING_INFO";
} # end of BEGIN
function colorize(col, s) {
	return "\033[" col "m" s "\033[m";
}
# global color
function c(s) {
	return colorize(color, s);
}
function endPoint(ep) {
	if (ep == "0") return "output";
	if (ep == "1") return " input";
	if (ep == "2") return colorize("1;33", "enumIf");
	# if (ep == "3") return "   ???"; # seen in the output of usbmon
	return sprintf("%6s", "ep" ep);
}
function dev(hex) {
	if (hex == "ff") {
		return "RECV";
	}
	if (int(hex) >= 1 && int(hex) <= 6) {
		return "DEV" int(hex)
	}
	return "    ";
}
function typeStr(hex) {
	return sprintf("%-" maxlen "s", types[toupper(hex)]);
}
function payload(type, p) {
	v1 = substr(p, 1, 2);
	if (type == "8f") { # error
		er=substr(p, 5, 2);
		reg=substr(p, 3, 2);
		parms = "SubID=" v1
		parms = parms ", Reg=" c(reg) " " regs[reg];
		parms = parms ", er=" c(er);
		parms = parms " " errmsgs[er];
	} else if (type == "80" || type == "81" || type == "82" || type == "83") {
		parms = "reg=" c(v1) " " regs[v1];
		parms = parms " parms=" c(substr(p, 3));
	} else {
		parms = "parms=" c(p);
	}
	return parms;
}

{
	if (match($0, /.*?:[0-9]+:[0-9]{3,}:([0-9]+) .*? = (..)(..)(..)(..) (.*)/, a)) {
		# length 85 is ok for most, but not when starting logitech program
		if (length($0) > 100) {
			print $0;
			$0 = "";
		}
		printf("%-100s", $0);
		color = "1;32";
		# sending data instead of receiving data
		if ($0 ~ " s ") color = "1;31";

		print	" " endPoint(a[1]),
			"report_id=" c(a[2]),
			"dev_idx=" c(a[3]) " " dev(a[3]),
			"type=" c(a[4]) " " typeStr(a[4]),
			payload(a[4], a[5] a[6]);
	} else {
		 print colorize("1;30", $0);
	}
	fflush();
}
