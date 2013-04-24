Logitech Unifying tool for Linux

See also the article on <https://lekensteyn.nl/logitech-unifying.html>

Logitech documents

I have learned a bit from the kernel source code hid-logitech-dj, but the
"official" Logitech specification (HID++ 1.0) was much more useful. These
documents can be found on <https://lekensteyn.nl/files/logitech/>.


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


Pairing tool (ltunify)
ltunify allows you to pair new devices, unpair existing devices or view
information for those devices. Run `ltunify --help` for available options.

Usage of the pairing tool is pretty straight-forward. Example session:

    $ ./ltunify list
    /dev/hidraw0: Permission denied
    Logitech Unifying Receiver device is not accessible.
    Try running this program as root or enable read/write permissions
    for /dev/hidraw0
    $ sudo chgrp $USER /dev/hidraw0 && sudo chmod g+rw /dev/hidraw0 
    $ ./ltunify list
    Devices count: 1
    Connected devices:
    idx=1   Mouse   M525
    $ ./ltunify info 1
    Device index 1
    Mouse
    Name: M525
    Wireless Product ID: 4013
    Serial number: DAFA335E
    Device was unavailable, version information not available.
    $ ./ltunify unpair 1
    Device 0x01 Mouse successfully unpaired
    $ ./ltunify list
    Devices count: 0
    Connected devices:
    $ ./ltunify pair
    Please turn your wireless device off and on to start pairing.
    Found new device, id=0x01 Mouse
    $ ./ltunify list
    Devices count: 1
    Connected devices:
    idx=1   Mouse   M525


~ Peter Wu <lekensteyn@gmail.com>
