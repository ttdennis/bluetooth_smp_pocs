import struct
import binascii
import sys

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# SMP Command Opcodes
SMP_PAIRING_CONFIRM_COMMAND = 0x03
SMP_RANDOM_COMMAND = 0x04
SMP_PUBKEY_COMMAND = 0x0c

PACKET_HEADER_LEN = 24
ACL_HEADER_LEN = 4

LINKTYPE_HCI_UART = b"\x03\xea"
LINKTYPE_UNENCAPSULATED_HCI = b"\x03\xe9"
PACKET_FLAG_OUTGOING_ACL = 0
PACKET_FLAG_INCOMING_ACL = 1

class SMPDecoder:
    def __init__(self, pk_a, pk_b, confirm_values, random_values):
        self.pk_a = pk_a
        self.pk_b = pk_b
        self.confirm_values = confirm_values
        self.random_values = random_values
        self.passkey = None

        self._check_values()

    def _check_values(self):
        print(f"[*] Found {len(self.confirm_values)} confirm values and {len(self.random_values)} random values")
        if len(self.confirm_values) != 20 or len(self.random_values) != 20:
            print("[!] Something is wrong with the confirm and random values, should be 20 each.")
            sys.exit(1)

        if not self.pk_a or not self.pk_b:
            print("[!] Need both pk_a and pk_b")
            sys.exit(1)

    # the f4 function from the Bluetooth specification "LE Secure Connections Confirm Value Generation Function f4"
    def f4(self, u, v, x, z):
        c = CMAC.new(x, ciphermod=AES)
        c.update(u + v + z)
        return c.digest()

    def get_bit(self,pk_a, pk_b, N_a, val):
        bit_0 = self.f4(pk_a, pk_b, N_a, bytearray([0x80]))
        if val == bit_0:
            return 0

        bit_1 = self.f4(pk_a, pk_b, N_a, bytearray([0x81]))
        if val != bit_1:
            print("[!] SMP Confirm value matches with neither 0 nor 1.")
            print(f"\tExpected {binascii.hexlify(val)}")
            print(f"\tWith Bit = 0: {binascii.hexlify(bit_0)}")
            print(f"\tWith Bit = 1: {binascii.hexlify(bit_1)}")
            sys.exit(1)
        else:
            return 1

    def decode(self):
        passkey = 0
        for i, val in enumerate(self.confirm_values):
            bit = self.get_bit(self.pk_a, self.pk_b, self.random_values[i], self.confirm_values[i])
            passkey += bit << i

        return passkey

class BTSnoopSMPParser:
    def __init__(self, data):
        self.pk_a = None
        self.pk_b = None
        self.confirm_values = []
        self.random_values = []
        self.packet_header_offset = 0

        self.data = data

        self._parse_linktype()

    def _parse_linktype(self):
        linktype = self.data[0xe:0x10]
        if linktype == LINKTYPE_HCI_UART:
            print("[*] Linktype: HCI_UART")
            self.packet_header_offset = 1
        elif linktype == LINKTYPE_UNENCAPSULATED_HCI:
            print("[*] Linktype: UNENCAPSULATED_HCI")
            self.packet_header_offset = 0
        else:
            print("[!] Unknown linktype")

    def extract_acl_packets(self, packet_flag_filter):
        acl_packets = []
        data = self.data[16:]
        while True:
            orig_len = struct.unpack(">i", data[:4])[0]
            packet_flags = struct.unpack(">i", data[8:12])[0]

            # ACL in and ACL out
            if packet_flags == packet_flag_filter:
                acl_packets.append(data[PACKET_HEADER_LEN+self.packet_header_offset:orig_len+PACKET_HEADER_LEN])

            offset = orig_len + PACKET_HEADER_LEN
            if offset < len(data):
                data = data[offset:]
            else:
                break

        return acl_packets

    def extract_l2cap_packets(self, acl_packets):
        l2cap_packets = []
        reassembly_buffer = b""

        for acl_packet in acl_packets:
            (handle, acl_len, l2len, cid) = struct.unpack("hhhh", acl_packet[:8])

            if handle >> 8 == 0x10:
                reassembly_buffer += acl_packet[ACL_HEADER_LEN:]
                l2len = struct.unpack("h", reassembly_buffer[:2])[0]
                if l2len == len(reassembly_buffer) - 4:
                    l2cap_packets.append(reassembly_buffer)
            elif acl_len < l2len + 4:
                reassembly_buffer = acl_packet[ACL_HEADER_LEN:]
            else:
                l2cap_packets.append(acl_packet[ACL_HEADER_LEN:])

        return l2cap_packets

    def _parse_incoming_pubkey(self, l2cap):
        # from the incoming L2CAP packets we only need the remote device's pubkey
        for l2cap_packet in l2cap:
            (l2len, cid) = struct.unpack("hh", l2cap_packet[:4])
            if cid == 0x06:
                if l2cap_packet[4] == SMP_PUBKEY_COMMAND:
                    print("[*] Found incoming SMP Public Key Command")
                    (pk_x, pk_y) = struct.unpack("32s32s", l2cap_packet[5:])
                    print("\tPK_x: ", binascii.hexlify(pk_x[::-1]))
                    print("\tPK_y: ", binascii.hexlify(pk_y[::-1]))
                    self.pk_b = pk_x[::-1]

    def _parse_outgoing_smp(self, l2cap):
        # from the outgoing L2CAP packets we need the device's pubkey, the confirm values as well as the random values
        for l2cap_packet in l2cap:
            (l2len, cid) = struct.unpack("hh", l2cap_packet[:4])
            if cid == 0x06:
                cmd = l2cap_packet[4]
                if cmd == SMP_PUBKEY_COMMAND:
                    print("[*] Found outgoing SMP Public Key Command")
                    (pk_x, pk_y) = struct.unpack("32s32s", l2cap_packet[5:])
                    print(f"\tPK_x: {binascii.hexlify(pk_x[::-1])}")
                    print(f"\tPK_y: {binascii.hexlify(pk_y[::-1])}")
                    self.pk_a = pk_x[::-1]
                elif cmd == SMP_PAIRING_CONFIRM_COMMAND:
                    (val,) = struct.unpack("16s", l2cap_packet[5:])
                    self.confirm_values.append(val[::-1])
                    print(f"[*] Found outgoing SMP Pairing Confirm Command ({binascii.hexlify(val[::-1])})")
                elif cmd == SMP_RANDOM_COMMAND:
                    (val,) = struct.unpack("<16s", l2cap_packet[5:])
                    self.random_values.append(val[::-1])
                    print(f"[*] Found outgoing SMP Random Command {binascii.hexlify(val[::-1])}")

    def parse(self):
        acl_in = self.extract_acl_packets(PACKET_FLAG_INCOMING_ACL)
        acl_out = self.extract_acl_packets(PACKET_FLAG_OUTGOING_ACL)
        l2cap_in = self.extract_l2cap_packets(acl_in)
        l2cap_out = self.extract_l2cap_packets(acl_out)

        self._parse_incoming_pubkey(l2cap_in)
        self._parse_outgoing_smp(l2cap_out)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} [BTSNOOP filename]")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        btsnoop = f.read()

    bts = BTSnoopSMPParser(btsnoop)
    bts.parse()

    decoder = SMPDecoder(bts.pk_a, bts.pk_b, bts.confirm_values, bts.random_values)
    pk = decoder.decode()

    print(f"[*] Got passkey {pk}")

if __name__ == "__main__":
    main()
