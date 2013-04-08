Logitech documents

2200_mousepointer.pdf, 4301_k750_solarkeyboard_lightandbattery.pdf,
6100_touchpadraw.pdf, 6110_touchmouseraw.pdf,
logitech_hidpp10_specification_for_Unifying_Receivers.pdf have been created
from .doc(x) files using LibreOffice.
logitech_hidpp_2.0_specification_draft_2012-06-04.pdf was already a PDF, so no
conversion was necessary.

The contents of the aforementioned files are (C) Logitech.
Retrieved from https://drive.google.com/?tab=mo&pli=1&authuser=0#folders/0BxbRzx7vEV7eWmgwazJ3NUFfQ28
(found at http://code.google.com/p/chromium/issues/detail?id=175572)

usbmon.awk was a RE attempt before I found the spec, it helped me understand
the packets when the specification was not available.

You will find the HID++ 1.0 spec the most interesting, I hope to produce a
pairing program soon.


Debuggers
usbmon.awk - initial debugging tool used for tapping usbmon from debugfs
hidraw.c   - successor of usbmon.awk that can parse packets of usb payload.
read-dev-usbmon.c - Reads data from /dev/usbmonX and show interpreted data in a
  more human-readable way.

Note: as a quick-n-dirty hack, I included hidraw.c at some point into the
read-dev-usbmon program. Otherwise, I had no way to show the difference between
a send or receive packet without adding to the same stdout stream. If I included
it in the stderr pipe, then it would be interleaved with stdout in an
unpredictable manner. This means that hidraw.c is currently unusable, it does
not process data correctly.

Usage of USB debugger:
1. Use `lsusb -d 046d:c52b` to determine the bus number. If the output is "Bus
   001 ..", your usb monitor device is at /dev/usbmon1.
2. sudo chgrp $USER /dev/usbmon1
3. sudo chmod g+r /dev/usbmon1
4. ./read-dev-usbmon /dev/usbmon1
5. Profit!

~ Peter Wu <lekensteyn@gmail.com>
