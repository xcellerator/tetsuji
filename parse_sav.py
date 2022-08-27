#!/usr/bin/env python3

import sys

from hexdump import hexdump, dump
from pprint import pprint

import pkm
import logger

party_offset = 0x281a
pkm_size = 48

obj = pkm.parse_pokemon_request

if len(sys.argv) != 2:
    logger.log.critical(f'Usage: {sys.argv[0]} <pkm.sav>')

try:
    with open(sys.argv[1], 'rb') as f:
        save = f.read()
except FileNotFoundError as e:
    logger.log.critical(f'Error: {e}')


logger.log.info(f'Filesize: {len(save)}')
party_count = save[party_offset]
logger.log.info(f'Pokemon in party: {party_count}')
logger.log.info(f'Species: {dump(save[party_offset + 1:party_offset+1+party_count])}')

for i in range(party_count):
    start = party_offset + 1 + party_count + 1 + (i * pkm_size)
    end = start + pkm_size
    print(f'{hex(start)} - {hex(end)}')
    pkm_struct = save[start+1:end+1]
    parsed = obj.parse_pokemon( obj,  pkm_struct )
    parsed['pkm'] = hex( parsed['pkm'] )
    hexdump( pkm_struct )
    pprint(parsed)
    print()

print(f'OT Names   | Nicknames')
for i in range(party_count):
    start = 1 + party_offset + 1 + 5 + 1 + (6 * pkm_size) + (i * 12)
    end = start + 12
    print(f'{save[start:end-7].hex()} | {save[start+6:end-1].hex()}')
