#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SHORT_MESSAGE           0x10
#define LONG_MESSAGE            0x11

struct hidpp2_message {
	u8 report_id;
	u8 device_index;
	u8 feature_index;
#define HIDPP_SET_FUNC(msg, func) ((msg)->func_swId |= ((func) << 4))
	u8 func_swId;
	u8 params[16]; // 3 or 16 params
} __attribute__((__packed__));

struct feature {
	uint16_t featureId;
#define FEAT_TYPE_MASK          0xe0
#define FEAT_TYPE_OBSOLETE      0x80
#define FEAT_TYPE_SWHIDDEN      0x40
#define FEAT_TYPE_RSVD_INTERNAL 0x20
	u8 featureType;
};

#define SOFTWARE_ID 0x04 /* getRandom() -- guaranteed to be random. */

#define FEATURE_INDEX_IROOT 0x00

#define FID_IFEATURESET 0x0001
static
const char *
get_feature_name(uint16_t featureId) {
	/* With '?' prefix are taken from SetPointP/KEMUI.xml */
	switch (featureId) {
	case 0x0000: return "Root";
	case 0x0001: return "FeatureSet";
	case 0x0002: return "FeatureInfo";
	case 0x0003: return "DeviceFwVersion";
	case 0x0005: return "DeviceName";
	case 0x0006: return "DeviceGroups";
	case 0x00C0: return "Dfucontrol";           /* Firmware Update */
	case 0x1000: return "BatteryStatus";
	case 0x1900: return "?SoundNotif";          /* Sound Notification */
	case 0x1920: return "?AudioControls";       /* Audio Controls */
	case 0x1940: return "?VOIP";                /* Internet Telephony */
	case 0x1960: return "?VideoCalling";
	case 0x1980: return "?Backlighting";
	case 0x1981: return "Backlight";
	case 0x1B00: return "ReprogControls";
	case 0x1B01: return "ReprogControlsV2";
	case 0x1B03: return "ReprogControlsV3";
	case 0x1D4B: return "WirelessDeviceStatus"; /* Wireless Update */
	case 0x2000: return "?MouseFeature";        /* Pointing Device Feature */
	case 0x2001: return "LeftRightSwap";
	case 0x2100: return "VerticalScrolling";
	case 0x2120: return "HiResScrolling";
	case 0x2200: return "MousePointer";
	case 0x2510: return "?ProfileMgmt";         /* Profile Management */
	case 0x4000: return "?KeyboardFeature";
	case 0x40A0: return "FnInversion";
	case 0x40A2: return "NewFnInversion";
	case 0x4100: return "Encryption";
	case 0x4301: return "SolarDashboard";
	case 0x4400: return "?DisplayFeature";
	case 0x4520: return "KeyboardLayout";       /* Inactive key */
	case 0x5500: return "?SliderControls";
	case 0x6000: return "?TouchpadFeature";
	case 0x6010: return "TouchpadFwItems";      /* Basic Touchpad settings */
	case 0x6011: return "TouchpadSwItems";      /* Enhanced Touchpad settings */
	case 0x6012: return "TouchpadWin8FwItems";
	case 0x6020: return "?TouchpadTapSelect";   /* Tap to select */
	case 0x6030: return "?DisablePointerAccel"; /* Disable pointer acceleration */
	case 0x6100: return "TouchpadRawXy";
	case 0x6110: return "TouchmouseRawPoints";
	case 0x6120: return "Touchmouse6120";
	case 0x6300: return "?HandwritingRecog";    /* Handwriting recognition" */
	default: return "unknown";
	}
}

/**
 * Initialize common values of a HID++ 2.0 message: report_id, device_index and
 * software ID. Remaining fields: feature_index, func, params.
 */
#define INIT_HIDPP_SHORT(msg, dev_index) \
	memset((msg), 0, sizeof *(msg)); \
	(msg)->report_id = SHORT_MESSAGE; \
	(msg)->device_index = dev_index; \
	(msg)->func_swId = SOFTWARE_ID

static
bool
do_hidpp2_request(int fd, struct hidpp2_message *msg) {
	struct hidpp_message *hid10_message = (struct hidpp_message *) msg;

        if (!do_write(fd, hid10_message)) {
                return false;
        }

	// use do_read_skippy in case there are interleaving notifications
	// sub id is feature index in HID++ 2.0
	if (!do_read_skippy(fd, hid10_message, 0x11, hid10_message->sub_id)) {
		puts("WTF");
		return false;
	}

	return true;
}

// Returns feature index for featureId
static
u8
get_feature(int fd, u8 device_index, uint16_t featureId) {
	struct hidpp2_message msg;
	INIT_HIDPP_SHORT(&msg, device_index);
	msg.feature_index = FEATURE_INDEX_IROOT;
	HIDPP_SET_FUNC(&msg, 0); // GetFeature(featureId)
	msg.params[0] = featureId >> 8;
	msg.params[1] = featureId & 0xFF;
	if (!do_hidpp2_request(fd, &msg)) {
		return 0;
	}
	return msg.params[0];
}

// Returns number of features or 0 on error.
static
u8
get_feature_count(int fd, u8 device_index, u8 ifeatIndex) {
	struct hidpp2_message msg;
	INIT_HIDPP_SHORT(&msg, device_index);
	// XXX: is this variable? Can't it be hard-coded to 0x01?
	msg.feature_index = ifeatIndex;
	HIDPP_SET_FUNC(&msg, 0); // GetCount()
	if (!do_hidpp2_request(fd, &msg)) {
		fprintf(stderr, "Failed to request features count\n");
		return 0;
	}
	return msg.params[0];
}

// Get featureId and type for a given featureIndex.
static
bool
get_featureId(int fd, u8 device_index, u8 ifeatIndex, u8 featureIndex, struct feature *feat) {
	struct hidpp2_message msg;
	INIT_HIDPP_SHORT(&msg, device_index);
	// XXX: is this variable? Can't it be hard-coded to 0x01?
	msg.feature_index = ifeatIndex;
	HIDPP_SET_FUNC(&msg, 1); // GetFeatureId(featureIndex)
	msg.params[0] = featureIndex;
	if (!do_hidpp2_request(fd, &msg)) {
		return false;
	}
	feat->featureId = (msg.params[0] << 8) | msg.params[1];
	feat->featureType = msg.params[2];
	return true;
}

void
hidpp20_print_features(int fd, u8 device_index) {
	u8 i, count, ifeatIndex;

	ifeatIndex = get_feature(fd, device_index, FID_IFEATURESET);
	if (!ifeatIndex) {
		fprintf(stderr, "Failed to get feature information\n");
		return;
	}
	count = get_feature_count(fd, device_index, ifeatIndex);

	printf("Total number of HID++ 2.0 features: %i\n", count);
	for (i = 0; i <= count; i++) {
		struct feature feat;
		if (get_featureId(fd, device_index, ifeatIndex, i, &feat)) {
			printf(" %2i: [%04X] %c%c%c %s\n", i, feat.featureId,
				feat.featureType & FEAT_TYPE_OBSOLETE ? 'O' : ' ',
				feat.featureType & FEAT_TYPE_SWHIDDEN ? 'H' : ' ',
				feat.featureType & FEAT_TYPE_RSVD_INTERNAL ? 'I' : ' ',
				get_feature_name(feat.featureId));
			if (feat.featureType & ~FEAT_TYPE_MASK) {
				printf("Warning: unrecognized feature flags: %#04x\n",
					feat.featureType & ~FEAT_TYPE_MASK);
			}
		} else {
			fprintf(stderr, "Failed to get feature, is device connected?\n");
		}
	}
	puts("(O = obsolete feature; H = SW hidden feature;\n"
		" I = reserved for internal use)");
}
