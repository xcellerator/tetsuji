#!/usr/bin/python3

import socket

from hexdump import hexdump, dump
from enum import Enum
from collections import OrderedDict

import logger

import pkm
import crystal

# The states that the Mobile Adapter GB can be in
class TransferState(Enum):
    Waiting     = 0  # Waiting for the first byte of the preamble (0x99).
    Preamble    = 1  # Expecting the second byte of the preamble (0x66).
    PacketStart = 2  # Expecting the packet start.
    Packet01    = 3  # Expecting packet offset 0x01 (unused?)
    Packet02    = 4  # Expecting packet offset 0x02 (unused?)
    PacketLen   = 5  # Expecting the packet length.
    PacketBody  = 6  # Expecting the packet body.
    Checksum1   = 7  # Expecting the first byte of the checksum.
    Checksum2   = 8  # Expecting the second byte of the checksum.
    DeviceID    = 9  # Expecting the device ID.
    StatusByte  = 10 # Expecting the status byte (0x00 for sender, 0x80 ^ packetID for receiver)

# Main class for the communication
class MobileAdapterGB:
    def __init__(self):
        # BGB Connection
        self.ip = '127.0.0.1'
        self.port = 8765
        self.sock = None

        # Link Cable
        self.recv_count = 0
        self.sent_count = 0
        self.ticks_count = 0
        self.frames_count = 0

        # Mobile Adapter GB
        self.state = TransferState.Waiting
        self.is_sender = False
        self.packet_data = {'id': 0, 'size': 0, 'data': [], 'checksum': 0}
        self.line_busy = False
        self.ma_port = 0
        self.http_ready = True
        self.pop_begun = False
        self.response_text = bytearray()

        # POP
        try:
            with open('email.txt','rb') as f:
                self.email = f.read()
        except FileNotFoundError:
            logger.log.critical('File email.txt not found!')

        # HTTP
        try:
            with open('index.html','rb') as f:
                self.http_ex = f.read()
        except FileNotFoundError:
            logger.log.critical('File index.html not found!')

        # Store the various responses to each path (the domain cannot be changed)
        self.http_text = bytearray()
        self.http_responses = {}

        # XXX
        self.http_responses[b'GET /cgb/download?name=/01/CGB-BXTJ/POKESTA/menu.cgb HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': b'FINDMEFINDME' }

        # Mobile Trainer Homepage, loaded from index.html
        self.http_responses[b'GET /01/CGB-B9AJ/index.html HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': self.http_ex }

        # Used by Pokemon Crystal to send Pokemon away to be traded
        self.http_responses[b'GET /cgb/download?name=/01/CGB-BXTJ/exchange/index.txt HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': (
                b'http://gameboy.datacenter.ne.jp/cgb/upload?name=/01/CGB-BXTJ/exchange/10upload.cgi\r\n'
                b'http://gameboy.datacetner.ne.jp/cgb/upload?name=/01/CGB-BXTJ/exchange/cancel.cgi\r\n'
                )}

        # During upload, we have to return a 401. Later there's another request to this path with the Gb-Auth-ID
        # header set which is handled separately further down
        self.http_responses[b'GET /cgb/upload?name=/01/CGB-BXTJ/exchange/10upload.cgi HTTP/1.0'] = {
            'response': b'HTTP/1.0 401 Unauthorized',
            'headers': {'Gb-Auth-ID': b'HAIL GIOVANNI'},
            'content': b'' }

        # Just reply 200 to this request - part of the upload process for trading Pokemon
        self.http_responses[b'POST /cgb/upload?name=/01/CGB-BXTJ/exchange/10upload.cgi HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': b'' }

        # If something goes wrong we will get a POST to this path
        self.http_responses[b'POST /cgb/upload?name=/01/CGB-BXTJ/exchange/cancel.cgi HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': b'' }

        # XXX
        self.http_responses[b'GET /cgb/download?name=/01/CGB-BXTJ/tamago/index.txt HTTP/1.0'] = {
            'response': b'HTTP/1.0 200 OK',
            'headers': {},
            'content': (
                b'http://gameboy.datacenter.ne.jp/cgb/download?name=/01/CGB-BXTJ/tamago/tamagoXX.pkm\r\n'
                b'0ccc170a2e1447ad5eb778518ccca147b0a3bfffd1eae3d6f0a2ffff\r\n'
                )}

        # Odd Eggs
        odd_eggs = []
        # Pichu
        odd_eggs.append( bytes.fromhex( 'AC 00 54 CC 92 00 00 08 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 1E 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 11 00 09 00 06 00 0B 00 08 00 08'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'AC 00 54 CC 92 00 00 01 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 1E 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 11 00 09 00 07 00 0C 00 09 00 09'
                                        '8F 9D 09 50 50 50') )
        # Cleffa
        odd_eggs.append( bytes.fromhex( 'AD 00 01 CC 92 00 00 10 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 23 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 14 00 07 00 07 00 06 00 09 00 0A'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'AD 00 01 CC 92 00 00 03 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 23 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 14 00 07 00 08 00 07 00 0A 00 0B'
                                        '8F 9D 09 50 50 50') )
        # Igglypugg
        odd_eggs.append( bytes.fromhex( 'AE 00 2F CC 92 00 00 10 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 0F 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 18 00 08 00 06 00 06 00 09 00 07'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'AE 00 2F CC 92 00 00 03 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 0F 14 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 18 00 08 00 07 00 07 00 0A 00 08'
                                        '8F 9D 09 50 50 50') )
        # Smoochum
        odd_eggs.append( bytes.fromhex( 'EE 00 01 7A 92 00 00 0E 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 23 1E 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 08 00 06 00 0B 00 0D 00 0B'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'EE 00 01 7A 92 00 00 02 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 23 1E 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 08 00 07 00 0C 00 0E 00 0C'
                                        '8F 9D 09 50 50 50') )
        # Magby
        odd_eggs.append( bytes.fromhex( 'F0 00 34 92 00 00 00 0A 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 19 0A 00 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 0C 00 08 00 0D 00 0C 00 0A'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'F0 00 34 92 00 00 00 02 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 19 0A 00 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 0C 00 09 00 0E 00 0D 00 0B'
                                        '8F 9D 09 50 50 50') )
        # Elekid
        odd_eggs.append( bytes.fromhex( 'EF 00 62 2B 92 00 00 0C 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 1E 1E 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 0B 00 08 00 0E 00 0B 00 0A'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'EF 00 62 2B 92 00 00 02 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 1E 1E 0A 00 14 00 00 00 05'
                                        '00 00 00 00 00 13 00 0B 00 09 00 0F 00 0C 00 0B'
                                        '8F 9D 09 50 50 50') )
        # Tyrogue
        odd_eggs.append( bytes.fromhex( 'EC 00 21 92 00 00 00 0A 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 00 00 23 0A 00 00 14 00 00 00 05'
                                        '00 00 00 00 00 12 00 08 00 08 00 08 00 08 00 08'
                                        '8F 9D 09 50 50 50') )
        # XXX ???
        odd_eggs.append( bytes.fromhex( 'EC 00 21 92 00 00 00 01 00 00 7D 00 00 00 00 00'
                                        '00 00 00 00 00 2A AA 23 0A 00 00 14 00 00 00 05'
                                        '00 00 00 00 00 12 00 08 00 09 00 09 00 09 00 09'
                                        '8F 9D 09 50 50 50') )

        # XXX
        for egg in odd_eggs:
            new_url = 'GET /cgb/download?name=/01/CGB-BXTJ/tamago/tamago%02x.pkm HTTP/1.0' % odd_eggs.index(egg)
            self.http_responses[new_url.encode()] = { 'response': b'HTTP/1.0 200 OK',
                                                 'headers': {},
                                                 'content': egg }

        return

    # Where the business happens
    def main(self):
        self.connect()
        while True:
            try:
                recv = self.sock.recv( 1024 )
                self.on_recv_cb(recv)
            except KeyboardInterrupt:
                exit()
        return

    # Connect locally to the BGB link cable listener
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect( (self.ip, self.port) )
        except ConnectionRefusedError:
            logger.log.critical(f'Cannot connect to port {self.port}. Is BGB listening?')
        return

    # Hardcoded status indicates we're ready
    def status(self):
        status = [0x6a, 0, 0, 0, 0, 0, 0, 0]
        self.ticks_count += 1
        self.frames_count += 8
        status[2] = self.ticks_count % 256
        status[3] = (self.ticks_count // 256) % 256
        status[5] = self.frames_count % 256
        status[6] = (self.frames_count // 256) % 256
        status[7] = (self.frames_count // 256 // 256) % 256
        return bytes(status)

    # Callback everytime we receive a packet
    def on_recv_cb(self, pkt):
        resp = None

        # Sometimes (on error?) we get an empty packet
        if len(pkt) == 0:
            return

        # Link Cable Response
        if pkt[0] == 0x01:
            logger.log.debug(f'[<] {dump(pkt)}')
            self.send_pkt(pkt)
            self.send_pkt(b'\x6c\x03\x00\x00\x00\x00\x00\x00')

        elif pkt[0] == 0x6c:
            logger.log.debug(f'[<] {dump(pkt)}')
            self.send_pkt(b'\x6c\x01\x00\x00\x00\x00\x00\x00')
            self.send_pkt(self.status())

        elif pkt[0] == 0x65:
            logger.log.debug(f'[<] {dump(pkt)}')
            pass

        elif pkt[0] == 0x6a:
            self.send_pkt(self.status(), log=False)

        elif pkt[0] == 0x68 or pkt[0] == 0x69:
            logger.log.debug(f'[<] {dump(pkt)}')
            # Mobile Adapter Packet
            self.recv_count += 1
            self.sent_count += 1
            resp = list(pkt)
            resp[1] = self.mobile_adapter_byte(resp[1])
            self.send_pkt(bytes(resp))
            self.send_pkt(self.status())

        else:
            logger.log.warning(f'UNHANDLED: {dump(pkt)}')

        return

    # Send the packet off to the GameBoy
    def send_pkt(self, pkt, log=True):
        if log == True:
            logger.log.debug(f'[>] {dump(pkt)}')
        self.sock.send(pkt)
        return

    # Deal with the data byte of each Mobile Adapter GB packet
    def mobile_adapter_byte(self, b):
        # We are sending
        if self.is_sender:
            # Waiting -> Preamble
            if self.state == TransferState.Waiting:
                self.update_state(TransferState.Preamble)
                return 0x99

            # Preamble -> PacketStart
            elif self.state == TransferState.Preamble:
                self.update_state(TransferState.PacketStart)
                return 0x66

            # PacketStart -> Packet01
            elif self.state == TransferState.PacketStart:
                self.update_state(TransferState.Packet01)
                return self.packet_data['id']

            # Packet01 -> Packet02
            elif self.state == TransferState.Packet01:
                self.update_state(TransferState.Packet02)
                return 0x00

            # Packet02 -> PacketLen
            elif self.state == TransferState.Packet02:
                self.update_state(TransferState.PacketLen)
                return 0x00

            # PacketLen -> PacketBody
            # PacketLen -> Checksum1
            elif self.state == TransferState.PacketLen:
                if self.packet_data['size'] > 0:
                    self.update_state(TransferState.PacketBody)
                else:
                    self.update_state(TransferState.Checksum1)
                return self.packet_data['size']

            # PacketBody -> Checksum1
            elif self.state == TransferState.PacketBody:
                self.packet_data['size'] -= 1
                if self.packet_data['size'] == 0:
                    self.update_state(TransferState.Checksum1)
                return self.packet_data['data'][-1 - self.packet_data['size']]

            # Checksum1 -> Checksum2
            elif self.state == TransferState.Checksum1:
                self.update_state(TransferState.Checksum2)
                return self.packet_data['checksum'] >> 8

            # Checksum2 -> DeviceID
            elif self.state == TransferState.Checksum2:
                self.update_state(TransferState.DeviceID)
                return self.packet_data['checksum'] & 0xff

            # DeviceID -> StatusByte
            elif self.state == TransferState.DeviceID:
                self.update_state(TransferState.StatusByte)
                """
                ID:  e800 / 9000
                0x88: 0x1 / 0xfe
                0x89: 0x2 / 0xfd
                0x8a: 0x3 / 0xfc 
                0x8b: 0x4 / 0xfb
                0x8c: 0x5 / 0xfa
                0x8d: 0x6 / 0xf9
                0x8e: 0x7 / 0xf8
                0x8f: 0x8 / 0xf7
                """
                return 0x88

            # StatusByte -> Waiting
            elif self.state == TransferState.StatusByte:
                self.update_state(TransferState.Waiting)
                self.is_sender = False
                return 0x00

        # We are receiving
        else:
            # Waiting -> Preamble
            if self.state == TransferState.Waiting:
                if b == 0x99:
                    self.update_state(TransferState.Preamble)
                    # Reset Packet
                    self.packet_data = {'id': 0, 'data': bytearray(), 'checksum': 0}

            # Preamble -> PacketStart
            # Preamble -> Waiting
            elif self.state == TransferState.Preamble:
                if b == 0x66:
                    self.update_state(TransferState.PacketStart)
                else:
                    self.update_state(TransferState.Waiting)
                    return 0xf1

            # PacketStart -> Packet01
            elif self.state == TransferState.PacketStart:
                self.packet_data['id'] = b
                self.update_state(TransferState.Packet01)

            # Packet01 -> Packet02
            elif self.state == TransferState.Packet01:
                self.update_state(TransferState.Packet02)

            # Packet02 -> PacketLen
            elif self.state == TransferState.Packet02:
                self.update_state(TransferState.PacketLen)

            # PacketLen -> PacketBody
            # PacketLen -> Checksum1
            elif self.state == TransferState.PacketLen:
                self.packet_data['size'] = b
                if self.packet_data['size'] > 0:
                    self.update_state(TransferState.PacketBody)
                else:
                    self.update_state(TransferState.Checksum1)

            # PacketBody -> Checksum1
            elif self.state == TransferState.PacketBody:
                self.packet_data['data'].append(b)
                self.packet_data['size'] -= 1
                if self.packet_data['size'] == 0:
                    self.update_state(TransferState.Checksum1)

            # Checksum1 -> Checksum2
            elif self.state == TransferState.Checksum1:
                self.packet_data['checksum'] = b << 8
                self.update_state(TransferState.Checksum2)

            # Checksum2 -> DeviceID
            elif self.state == TransferState.Checksum2:
                self.packet_data['checksum'] += b
                self.update_state(TransferState.DeviceID)

            # DeviceID -> StatusByte
            elif self.state == TransferState.DeviceID:
                self.update_state(TransferState.StatusByte)

            # StatusByte -> Waiting
            elif self.state == TransferState.StatusByte:
                self.update_state(TransferState.Waiting)
                self.is_sender = True
                return self.mobile_adapter_response()

        return 0x4b

    # Decide how to respond, parsing the full message as received
    def mobile_adapter_response(self):
        ret = 0x80 ^ self.packet_data['id']

        # 0x10: BEGIN SESSION
        if self.packet_data['id'] == 0x10:
            logger.log.info(f'0x10: Opening Session ({self.packet_data["data"].decode()})')
            self.ma_port = 0
            # Respond with the same data

        # 0x11: END SESSION
        elif self.packet_data['id'] == 0x11:
            logger.log.info(f'0x11: Closing Session')
            self.ma_port = 0
            self.line_busy = False
            # Respond with the same data

        # 0x12: DIAL TELEPHONE
        elif self.packet_data['id'] == 0x12:
            logger.log.info(f'0x12: Dialling {self.packet_data["data"][1:].decode()}')
            # Respond with empty body
            self.packet_data['data'] = bytearray()
            self.line_busy = True

        # 0x13: HANG UP
        elif self.packet_data['id'] == 0x13:
            logger.log.info(f'0x13: Hanging Up')
            self.line_busy = False
            # Empty out anything left in response_text
            self.response_text = bytearray()
            # Respond with same data

        # 0x14: WAITING FOR CALL
        elif self.packet_data['id'] == 0x14:
            logger.log.info(f'0x13: Waiting for Call')
            # Respond with same data

        # 0x15: TRANSFER DATA
        elif self.packet_data['id'] == 0x15:
            # POP
            if self.ma_port == 110:
                if len(self.packet_data['data']) <= 1:
                    logger.log.debug(f'0x15: No POP Traffic Received')
                else:
                    logger.log.info(f'0x15: POP Recv: {self.packet_data["data"][1:-2].decode()}')

                self.packet_data['id'] = 0x95 # 0x80 ^ 0x15
                self.packet_data['data'] = bytearray(b'\x00') + self.pop_response()
                if len(self.packet_data['data']) <= 1:
                    logger.log.debug(f'0x95: No POP Traffic To Send')
                else:
                    logger.log.info(f'0x95: POP Send: {self.packet_data["data"][1:-2].decode()}')

            # HTTP
            elif self.ma_port == 80:
                if len(self.packet_data['data']) <= 1:
                    logger.log.debug(f'0x15: No HTTP Traffic Received')
                else:
                    if self.packet_data['data'][-4:] == b'\r\n\r\n':
                        logger.log.info(f'0x15: HTTP Recv: {self.http_text.decode()}')

                if self.http_ready or len(self.response_text) > 0:
                    self.packet_data['id'] = 0x95
                    self.packet_data['data'] = bytearray(b'\x00') + self.http_response()
                    if len(self.packet_data['data']) <= 1:
                        logger.log.debug(f'0x95: No HTTP Traffic To Send')
                    else:
                        logger.log.info(f'0x95: HTTP Send: {len(self.packet_data["data"])} bytes')

                else:
                    self.packet_data['id'] = 0x9f
                    self.packet_data['data'] = bytearray(b'\x00')
                    logger.log.info('0x95: HTTP Server Closed Connection')

            # Pokemon Crystal Battle
            elif self.ma_port == 0:
                self.packet_data = crystal.battle(self.packet_data).reply

            else:
                logger.log.warning(f'0x15: Unknown Protocol on port {self.ma_port}')
                logger.log.warning(f'Echoing data and hoping for the best!')

        # 0x17: TELEPHONE STATUS
        elif self.packet_data['id'] == 0x17:
            logger.log.info(f'0x17: Check Telephone Line')
            if self.line_busy:
                logger.log.info(f'0x17: Line Busy')
                # Setting the third byte to 0xf0 indicates that we're using the unlimited battle adapter
                self.packet_data['data'] = bytearray(b'\x05\x4d\xf0')
            else:
                logger.log.info(f'0x17: Line Free')
                # Setting the third byte to 0xf0 indicates that we're using the unlimited battle adapter
                self.packet_data['data'] = bytearray(b'\x00\x4d\xf0')

        # 0x19: READ CONFIGURATION DATA
        elif self.packet_data['id'] == 0x19:
            self.read_config()
            offset = self.packet_data['data'][0]
            length = self.packet_data['data'][1]
            logger.log.info(f'0x19: Read Config: {length} bytes @ {offset}')
            hexdump( self.config[offset: offset + length] )
            self.packet_data['data'] = bytearray([offset]) + self.config[ offset: offset + length ]

        # 0x1a: WRITE CONFIGURATION DATA
        elif self.packet_data['id'] == 0x1a:
            offset = self.packet_data['data'][0]
            length = len(self.packet_data['data']) - 1
            logger.log.info(f'0x1a: Write Config: {length} bytes @ {offset}')
            hexdump( self.packet_data['data'][1:] )
            self.config[offset: offset+length] = self.packet_data['data'][1:]
            self.write_config()
            # Send empty response
            self.packet_data['data'] = bytearray()

        # 0x21: ISP LOGIN
        elif self.packet_data['id'] == 0x21:
            logger.log.info(f'0x21: Log in to DION')
            # Send empty response to signal success (lol)
            self.packet_data['data'] = bytearray(b'\x00')

        # 0x22: ISP LOGOUT
        elif self.packet_data['id'] == 0x22:
            logger.log.info(f'0x22: Log out of DION')
            self.ma_port = 0
            # Respond with the same packet

        # 0x23: OPEN TCP CONNECTION
        elif self.packet_data['id'] == 0x23:
            self.ma_port = (self.packet_data['data'][4] << 8) + self.packet_data['data'][5]
            ip_string = f'{self.packet_data["data"][0]}.{self.packet_data["data"][1]}.{self.packet_data["data"][2]}.{self.packet_data["data"][3]}'
            logger.log.info(f'0x23: Open TCP Connection to {ip_string}:{self.ma_port}')
            # Respond with success
            self.packet_data['id'] = 0xa3
            self.packet_data['data'] = bytearray(b'\xff')
            self.http_ready = True
            self.pop_begun = False

        # 0x24: CLOSE TCP CONNECTION
        elif self.packet_data['id'] == 0x24:
            logger.log.info(f'0x24: Close TCP Connection')
            self.ma_port = 0
            self.response_text = bytearray()
            # Respond with the same packet

        # 0x28: DNS QUERY
        elif self.packet_data['id'] == 0x28:
            logger.log.info(f'0x28: DNS Query for {self.packet_data["data"].decode()}')
            self.packet_data['data'] = bytearray(b'\x13\x37\x13\x37\x00')

        # Hopefully we never hit this, but if we do, something interesting is probably going on
        else:
            logger.log.warning(f'UNKNOWN COMMAND: {hex(self.packet_data["id"])}')

        self.packet_data['size'] = len(self.packet_data['data'])

        checksum = self.packet_data['id'] + self.packet_data['size']
        for byte in self.packet_data['data']:
            checksum += byte
        self.packet_data['checksum'] = checksum

        return ret

    # Build a valid POP3 response
    def pop_response(self):
        pop_text = bytearray()
        if len(self.response_text) == 0:
            if len(self.packet_data['data']) > 1:
                pop_text = self.packet_data['data'][1:]

            if pop_text.find(b'STAT') == 0 or pop_text.find(b'LIST 1') == 0:
                self.response_text += f'+OK 1 {len(self.email)}\r\n'.encode()

            elif pop_text.find(b'LIST ') == 0:
                self.response_text += b'-ERR\r\n'

            elif pop_text.find(b'LIST') == 0:
                self.response_text += f'+OK\r\n1 {len(self.email)}\r\n.\r\n'.encode()

            # Email headers only
            elif pop_text.find(b'TOP 1 0') == 0:
                self.response_text += b'+OK\r\n' + self.email.split(b'\r\n\r\n')[0] + b'\r\n\r\n.\r\n'

            elif pop_text.find(b'RETR 1') == 0:
                self.response_text += b'+OK\r\n' + self.email + b'\r\n.\r\n'

            # Reply +OK at the start of any session or to any other command
            elif len(pop_text) > 0 or not self.pop_begun:
                self.pop_begun = True
                self.response_text += b'+OK\r\n'

            # Something went wrong?
            else:
                logger.log.error('Got unhandled POP Command: {pop_text}')
                self.response_text += b'-ERR\r\n'

        bytes_to_send = min(254, len(self.response_text))
        text_to_send = self.response_text[:bytes_to_send]
        self.response_text = self.response_text[bytes_to_send:]
        return text_to_send

    # Build a valid HTTP response
    def http_response(self):
        if len(self.response_text) == 0:
            if len(self.packet_data['data']) > 1:
                self.http_text += self.packet_data['data'][1:]

            http_data = self.parse_http(self.http_text)

            if 'request' in http_data:
                # If this is a POST, is it done or is there more data?
                if http_data['request'].find(b'POST') == 0:
                    if 'Content-Length' in http_data['headers']:
                        content_length = int(http_data['headers']['Content-Length'])
                        # Request is done?
                        if len(http_data['content']) >= content_length:
                            self.http_ready = False

                # This is a GET, so we're definitely done
                else:
                    self.http_ready = False

                if not self.http_ready:
                    # Clear self.http_text before next request
                    self.http_text = bytearray()

                    response = self.http_responses.get( bytes(http_data['request']) )

                    if http_data['request'] == b'GET /cgb/upload?name=/01/CGB-BXTJ/exchange/10upload.cgi HTTP/1.0':
                        if 'Gb-Auth-ID' in http_data['headers']:
                            response = { 'response': b'HTTP/1.0 200 OK',
                                         'headers': {'Gb-Auth-ID': b'HAIL GIOVANNI'},
                                         'content':b'\r\n' }

                    # If we hit here, we got asked for something we don't know how to reply to. The game will probably
                    # error out, so go try to implement what it asked for ;)
                    if response is None:
                        logger.log.warning(f'No response known for {http_data["request"].decode()}')
                        self.response_text = b'HTTP/1.0 404 Not Found\r\n\r\n'
                    else:
                        self.response_text = response['response'] + b'\r\n'
                        for header, value in response['headers'].items():
                            self.response_text += header.encode() + b': ' + value + b'\r\n'
                            
                        self.response_text += b'\r\n' + response['content']

        # Can only send 254 bytes at a time
        bytes_to_send = min(254, len(self.response_text))
        text_to_send = self.response_text[:bytes_to_send]
        self.response_text = self.response_text[bytes_to_send:]
        return text_to_send

    # Parse the incoming HTTP request
    def parse_http(self, recv):
        http_data = {}

        # Is this a complete request?
        if b'\r\n' in recv:
            http_data['request'] = recv.split(b'\r\n')[0]

            http_data['headers'] = {}

            # Deal with headers
            if recv.find(b'\r\n') < recv.find(b'\r\n\r\n'):
                headers = recv[ recv.find(b'\r\n') + 2 : recv.find(b'\r\n\r\n') ]
                headers = headers.split(b'\r\n')
                for header in headers:
                    header = header.split(b': ')
                    http_data['headers'][header[0].decode()] = header[1]

            http_data['content'] = recv[ recv.find(b'\r\n\r\n') + 4: ]

            # Assume we have a Pokemon request so print it nicely
            if http_data['request'].find(b'POST') == 0 and len(http_data['content']) > 0:
                hexdump(http_data['content'])
                from pprint import pprint
                pprint( pkm.parse_pokemon_request( http_data['content'] ).data )

        return http_data

    # Update the current transfer state
    def update_state(self, new_state):
        logger.log.debug(f'State Update: [{self.state}] --> [{new_state}]')
        self.state = new_state
        return

    # Load the config file
    def read_config(self):
        try:
            with open('config.bin','rb') as f:
                self.config = bytearray(f.read())
        except FileNotFoundError:
            with open('config.bin','wb') as f:
                self.config = b'\x00' * 192
                f.write(self.config)
        return

    # Write out the config file it's changed
    def write_config(self):
        with open('config.bin','wb') as f:
            f.write(self.config)
        return

# Parse the configuration file
class parse_config:
    def __init__(self, fname):
        try:
            with open(fname, 'rb') as f:
                self.config = f.read()
        except FileNotFoundError:
            logger.log.critical(f'Error: {fname} not found!')

        if len(self.config) != 192:
            logger.log.critical(f'Error: config data not 192 bytes, have {len(self.config)}')

        self.parse()
        return

    def parse(self):
        self.data = OrderedDict()

        self.data['magic'] = self.config[0x0:0x0+2]
        self.data['reg'] = self.config[0x2:0x2+2]
        self.data['dns1'] = self.parse_ip( self.config[0x4:0x4+4] )
        self.data['dns2'] = self.parse_ip( self.config[0x8:0x8+4] )
        self.data['login'] = self.config[0xc:0xc+32]
        self.data['email'] = self.config[0x2c:0x2c+30]
        self.data['smtp'] = self.config[0x4a:0x4a+20]
        self.data['pop'] = self.config[0x5e:0x5e+24]
        self.data['conf1'] = self.config[0x76:0x76+24]
        self.data['conf2'] = self.config[0x8e:0x8e+24]
        self.data['conf3'] = self.config[0xa6:0xa6+24]
        self.data['checksum'] = self.config[0xbe:0xbe+2]

        if self.data['reg'] == b'\x01\x00':
            self.data['reg'] = 'NOT REGISTERED'
        elif self.data['reg'] == b'\x81\x00':
            self.data['reg'] = 'REGISTERED'

        self.data['login'] = self.data['login'].rstrip(b'\x00').decode()
        self.data['email'] = self.data['email'].rstrip(b'\x00').decode()
        self.data['smtp'] = self.data['smtp'].rstrip(b'\x00').decode()
        self.data['pop'] = self.data['pop'].rstrip(b'\x00').decode()

        self.data['conf1'] = self.parse_config_data( self.data['conf1'] )
        self.data['conf2'] = self.parse_config_data( self.data['conf2'] )
        self.data['conf3'] = self.parse_config_data( self.data['conf3'] )

        sum = 0
        for i in range(190):
            sum += self.config[i]
        sum = int.to_bytes(sum, 2, 'big')

        if sum != self.data['checksum']:
            logger.log.error(f'Checksum incorrect! Got {self.data["checksum"]}, should be {sum}')

        return

    # Render IP address as a string
    def parse_ip(self, b):
        return f'{b[0]}.{b[1]}.{b[2]}.{b[3]}'

    # Parse the data part of the configuration file
    def parse_config_data(self, b):
        tel = bytearray()
        for i in b[:8]:
            b1 = i >> 4
            if b1 == 0xf:
                break
            tel += int.to_bytes(b1 + 0x30, 1, 'big')
            b2 = i & 0xf
            if b2 == 0xf:
                break
            tel += int.to_bytes(b2 + 0x30, 1, 'big')
        for i in range(len(tel)):
            if tel[i] == 0x3a:
                tel[i] = ord('#')

        return {'tel': tel.decode(), 'svc': b[8:].rstrip(b'\x00').decode()}

    def print(self):
        logger.log.info('Configuration Data:')
        logger.log.info(f'Registration State: {self.data["reg"]}')
        logger.log.info(f'Primary DNS:   {self.data["dns1"]}')
        logger.log.info(f'Secondary DNS: {self.data["dns2"]}')
        logger.log.info(f'Login: {self.data["login"]}')
        logger.log.info(f'Email: {self.data["email"]}')
        logger.log.info(f'SMTP:  {self.data["smtp"]}')
        logger.log.info(f'POP:   {self.data["pop"]}')

        logger.log.info(f'Slot 1: {self.data["conf1"]["svc"]}: {self.data["conf1"]["tel"]}')
        logger.log.info(f'Slot 2: {self.data["conf2"]["svc"]}: {self.data["conf2"]["tel"]}')
        logger.log.info(f'Slot 3: {self.data["conf3"]["svc"]}: {self.data["conf3"]["tel"]}')
        return

if __name__ == "__main__":
    #logger.log.setLevel(logger.logging.DEBUG)
    obj = MobileAdapterGB()
    obj.main()
