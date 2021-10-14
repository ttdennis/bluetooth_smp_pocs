import binascii
import struct

import logging

from internalblue.utils.packing import p16


class L2CAPManager:
    def __init__(self, btconn, mtu=0x30):
        self.connection = btconn
        self._setup_logging()
        self.connection.registerACLHandler(self._receptionHandler)

        # cidHandlers is a map from CID -> function array
        self.cidHandlers = {}
        self.handlers = []
        self.mtu = mtu

    def _setup_logging(self):
        self.log = logging.getLogger("l2cap")
        self.log.setLevel(logging.INFO)
        if not self.log.hasHandlers():
            fmt = logging.Formatter("\x1b[36m[L2CAP]\x1b[0m %(message)s")
            handler = logging.StreamHandler()
            handler.setFormatter(fmt)
            self.log.addHandler(handler)
            self.log.propagate = False

    def sendData(self, data, cid):
        self.log.debug(f"Sent L2CAP data to channel: {cid}, data: {binascii.hexlify(data)}")
        self.connection.sendACL(p16(len(data)) + p16(cid) + data)

    def registerHandler(self, handler):
        self.handlers.append(handler)
        self.log.debug("Registered L2CAP handler")

    def registerCIDHandler(self, handler, cid):
        if cid not in self.cidHandlers:
            self.cidHandlers[cid] = []

        self.cidHandlers[cid].append(handler)
        self.log.debug(f"Registered L2CAP handler for CID {cid}")

    def _receptionHandler(self, data):
        if len(data) > 5:
            l2cap_data = data[5:]
        else:
            self.log.debug(f"Received invalid L2CAP data at L2CAP handler: {binascii.hexlify(data)}")
            return

        if data[2] == 0x20 or data[2] == 0x00:
            l2cap_len = struct.unpack_from("h", l2cap_data)[0]
            if l2cap_len == len(l2cap_data)-4:
                self._handleL2CAP(l2cap_data)
            else:
                self.reassembly_buffer = l2cap_data
        elif data[2] == 0x10:
            self.reassembly_buffer += l2cap_data
            l2cap_len = struct.unpack_from("h", self.reassembly_buffer)[0]

            # if all data was received we can process the L2CAP message
            if l2cap_len == len(self.reassembly_buffer) - 4:
                self._handleL2CAP(self.reassembly_buffer)
        else:
            self.log.error(f"Unhandled ACL Fragmentation byte: {data[2]}")

    def _handleL2CAP(self, l2cap_data):
        # prioritize specific CID handlers
        (length, cid) = struct.unpack_from("hh", l2cap_data)
        self.log.debug(f"Received L2CAP data for cid: {cid}, {binascii.hexlify(l2cap_data)}")
        if cid in self.cidHandlers:
            for handler in self.cidHandlers[cid]:
                handler(l2cap_data[4:], self)

        for handler in self.handlers:
            handler(l2cap_data[4:], self)


class L2CAPSignalChannel:
    def __init__(self, chanman):
        self.chanman = chanman
        self.chanman.registerCIDHandler(0x01, self._receptionHandler)

    def sendCFrameRaw(self, code, identifier, length, data):
        self.chanman.sendData(code + identifier + length + data)

    def sendCFrame(self, code, identifier, data):
        data_len = len(data) / 2
        self.sendCFrameRaw(code, identifier, p16(data_len), data)

    def _receptionHandler(self, data):
        pass
