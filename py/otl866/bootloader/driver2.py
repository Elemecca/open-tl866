from collections import namedtuple
import struct
import time
import usb.core
import usb.util


USB_VENDOR = 0xa466
USB_PRODUCT = 0x0a53

def list_devices():
    devices = list()

    devices.extend([
        UsbDevice(d)
        for d in usb.core.find(
            idVendor=USB_VENDOR,
            idProduct=USB_PRODUCT,
            find_all=True,
        )
    ])

    return devices


class UsbDevice():
    def __init__(self, device):
        self.device = device

    def open(self):
        pass

    def close(self):
        usb.util.dispose_resources(self.device)

    def reopen(self):
        self.close()

        dev = None
        stop_time = time.time() + 5  # timeout = 5s
        while dev is None and time.time() < stop_time:
            time.sleep(0.100)  # interval = 100ms
            dev = usb.core.find(
                port_numbers=self.device.port_numbers,
                custom_match=lambda d: d.address != self.device.address
            )

        if dev is None:
            raise RuntimeError("device did not reconnect after reset")

        if dev.idVendor != USB_VENDOR or dev.idProduct != USB_PRODUCT:
            raise RuntimeError("wrong device reconnected after reset")

        self.device = dev

    def read_cmd(self, size):
        return self.device.read(usb.util.ENDPOINT_IN | 1, size)

    def write_cmd(self, buf):
        if len(buf) <= 64:
            self.device.write(1, buf)
        elif len(buf) == 72:
            self.device.write(1, buf[:8])
            self.device.write(2, buf[8:])
        else:
            raise ValueError("writes >72 bytes not yet supported")


MODEL_TL866II = 0x05

class Bootloader2Driver():
    REPORT_FORMAT = struct.Struct('< xBxx BBBx 8s 20s 4x B')
    Report = namedtuple('Report', [
        'status',
        'firmware_version_minor',
        'firmware_version_major',
        'model',
        'device_code',
        'serial_number',
        'hardware_version',
    ])

    def __init__(self, device):
        self.device = device
        self.device.open()

    def reset(self):
        self.device.write_cmd(struct.pack('< B 3x I', 0x3D, 0xA578B986))
        self.device.write_cmd(struct.pack('< B 7x', 0x3F))
        self.device.reopen()

    def report(self):
        self.device.write_cmd(struct.pack('< B 7x', 0x00))
        buf = bytes(self.device.read_cmd(self.REPORT_FORMAT.size))
        return self.Report._make(self.REPORT_FORMAT.unpack(buf))
