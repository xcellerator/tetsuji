#!/usr/bin/env python3

from hexdump import hexdump

import logger

from pkm_list import pkms
from pkm_list import moves

# Class to called
class battle:
    def __init__(self, packet_data):
        # If nothing else, we just echo back the packet without modifying it
        self.reply = packet_data

        # Try to parse and handle
        if self.is_keepalive(packet_data):
            return
        self.parse(packet_data)
        self.handle()
        self.reply = self.update()
        return

    # If packet_data is just 0xff, then it's a keepalive
    def is_keepalive(self, packet_data):
        if packet_data['data'] == b'\xff':
            return True
        return False

    # Have to rebuild packet_data from pkt (incl checksum!)
    # packet_data has ['id'] and ['data']
    # ['data'] is FF + cmd + data + checksum
    def update(self):
        update = self.reply
        update['data']  = b''
        update['data'] += b'\xff'
        update['data'] += int.to_bytes(self.pkt['cmd'], 1, 'big')
        update['data'] += self.pkt['data']
        update['data'] += self.calc_checksum( self.pkt['data'] )
        return update

    # Compute Checksum
    def calc_checksum(self, blob):
        sum = 0
        for i in blob:
            sum += i
        sum = sum % (2**16)
        return int.to_bytes(sum, 2, 'little')

    # Parse the Packet into cmd/data/checksum
    def parse(self, packet_data):
        self.pkt = {}
        if packet_data['data'][0] != 0xff:
            logger.log.warning(f'Battle: Not a battle packet!')
        if 'data' in packet_data:
            self.pkt['cmd'] = packet_data['data'][1]
            self.pkt['data'] = bytearray(packet_data['data'][2:-2])
            self.pkt['checksum'] = packet_data['data'][-2:]
            self.checksum(self.pkt)
        return

    # Verify the Checksum
    def checksum(self, pkt):
        sum = 0
        for i in pkt['data']:
            sum += i
        sum = int.to_bytes(sum, 2, 'little')
        if sum == pkt['checksum']:
            return True
        logger.log.warning('Battle: checksum doesn\'t match!')
        return False

    # Payload - Print '3' to the screen
    print_me  = b''
    # Executed from Address $CA4F
    print_me += bytes.fromhex('F0 44')      # ld a, (FF00+44)   ; LY
    print_me += bytes.fromhex('FE 90')      # cp a, $90         ; past vblank
    print_me += bytes.fromhex('38 FA')      # jr c, $CA4F       ; wait

    print_me += bytes.fromhex('AF')         # xor a
    print_me += bytes.fromhex('E0 40')      # ld (FF00+40), a   ; reset LCDC

    print_me += bytes.fromhex('21 00 98')   # ld hl, $9800      ; top-left
    print_me += bytes.fromhex('06 F9')      # ld b, $F9
    print_me += bytes.fromhex('70')         # ld (hl), b

    print_me += bytes.fromhex('3E B8')      # ld a, $B8         ; index $38 of bg palette data, with auto-increment
    print_me += bytes.fromhex('E0 68')      # ld (FF00+68), a   ; BGPI
    print_me += bytes.fromhex('AF')         # xor a
    print_me += bytes.fromhex('E0 69')      # ld (FF00+69), a   ; black bg (BGPD)
    print_me += bytes.fromhex('E0 69')      # ld (FF00+69), a   ; black bg (BGPD)

    print_me += bytes.fromhex('AF')         # xor a
    print_me += bytes.fromhex('E0 42')      # ld (FF00+42), a   ; scroll LY
    print_me += bytes.fromhex('E0 43')      # ld (FF00+43), a   ; scroll LX
    print_me += bytes.fromhex('3E 81')      # ld a, %10000001
    print_me += bytes.fromhex('E0 40')      # ld (FF00+40), a   ; lcd on
    print_me += bytes.fromhex('18 FE')      # jr $CA70          ; inf loop

    # Handle the Battle Packets as they arrive
    def handle(self):
        logger.log.warning(f'Battle: Packet Received ({self.pkt["cmd"]} bytes)')
        # Initial "limit_crystal" packet, reply with same
        if self.pkt['cmd'] == 0x15:
            hexdump( self.pkt['data'] )
            return

        # Random Bytes Each Time
        elif self.pkt['cmd'] == 0x0d:
            hexdump( self.pkt['data'] )
            return

        # Konnichiwa String (seems unused)
        elif self.pkt['cmd'] == 0x4d:
            hexdump( self.pkt['data'] )
            return

        # Blobs of save data. One from 0x600 (seems unused) and party save data from 0x281a
        elif self.pkt['cmd'] == 0x53:
            # First few bytes of the Pokemon Party blob is the Player Name, overwrite with string parsing bug
            #self.pkt['data'][0:0+8] = bytes.fromhex('3F4F 1508 1880 0058')
            self.pkt['data'][0:0+3] = bytes.fromhex('3F0000')
            hexdump( self.pkt['data'] )
            return

        # Always nulls
        elif self.pkt['cmd'] == 0x0f:
            hexdump( self.pkt['data'] )
            return

        # Final packet of the Pokemon Party Data
        elif self.pkt['cmd'] == 0x3b:
            # Packet from index 13 onwards survives the final 0x09-type packet, so that's where the payload goes
            self.pkt['data'][13:13+len(self.print_me)] = self.print_me
            hexdump( self.pkt['data'] )
            return

        # First three bytes indicate which Pokemon from the Party are being battled with
        elif self.pkt['cmd'] == 0x09:
            hexdump( self.pkt['data'] )
            return

        # Tetsuji Packet: Use a move or swap out a Pokemon
        elif self.pkt['cmd'] == 0x0c:
            hexdump( self.pkt['data'] )
            return

        # Catch unhandled packet
        else:
            logger.log.error(f'Battle: Unhandled command ({self.pkt["cmd"]})')
            hexdump( self.pkt['data'] )
            return
        return
