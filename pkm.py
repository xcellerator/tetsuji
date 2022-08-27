#!/usr/bin/python3

from hexdump import hexdump, dump
from collections import OrderedDict

import logger

class parse_pokemon_request:
    def __init__(self, blob):
        if len(blob) != 143:
            logger.log.error(f'Invalid Pokemon Request Size: {len(blob)}, should be 143')
            self.data = {}
            return
        self.blob = blob
        self.parse()
        return

    def parse(self):
        self.data = OrderedDict()
        
        self.data['email'] = self.blob[0: self.blob.find(b'\x00')].decode()
        self.data['trainer_id'] = self.blob[0x1e:0x1e+2]
        self.data['secret_id'] = self.blob[0x20:0x20+2]
        self.data['offer_gender'] = self.blob[0x22]
        self.data['offer_species'] = self.blob[0x23]
        self.data['request_gender'] = self.blob[0x24]
        self.data['request_species'] = self.blob[0x25]
        self.data['trainer_name'] = self.blob[0x26:0x26+5]
        self.data['pokemon_struct'] = self.blob[0x2b:0x2b+48]
        self.data['pokemon_ot_name'] = self.blob[0x5b:0x5b+5]
        self.data['pokemon_nickname'] = self.blob[0x60:0x60+5]
        self.data['mail_data'] = OrderedDict()
        self.data['mail_data']['message'] = self.blob[0x65:0x65+33]
        self.data['mail_data']['sender_name'] = self.blob[0x86:0x86+5]
        self.data['mail_data']['sender_trainer_id'] = self.blob[0x8b:0x8b+2]
        self.data['mail_data']['pokemon_species'] = self.blob[0x8d]
        self.data['mail_data']['item_index'] = self.blob[0x8e]

        self.data['offer_gender'] = self.gender_nice( self.data['offer_gender'] )
        self.data['request_gender'] = self.gender_nice( self.data['request_gender'] )

        self.data['pokemon_struct'] = self.parse_pokemon( self.data['pokemon_struct'] )
        return

    def gender_nice(self, gender):
        if gender == 0x0:
            return 'UNKNOWN'
        elif gender == 0x1:
            return 'MALE'
        elif gender == 0x2:
            return 'FEMALE'
        elif gender == 0x3:
            return 'EITHER'
        else:
            return 'ERROR'

    def parse_pokemon(self, pkm):
        data = OrderedDict()
        i = 0

        data['pkm'] = pkm[i]
        i += 1

        data['item'] = pkm[i]
        i += 1

        data['move1'] = pkm[i]
        i += 1

        data['move2'] = pkm[i]
        i += 1

        data['move3'] = pkm[i]
        i += 1

        data['move4'] = pkm[i]
        i += 1

        data['ot_id'] = pkm[i:i+2]
        i += 2

        data['exp'] = pkm[i:i+3]
        i += 3

        data['hp_ev'] = pkm[i:i+2]
        i += 2

        data['att_ev'] = pkm[i:i+2]
        i += 2

        data['def_ev'] = pkm[i:i+2]
        i += 2

        data['spd_ev'] = pkm[i:i+2]
        i += 2

        data['spc_ev'] = pkm[i:i+2]
        i += 2

        data['iv'] = pkm[i:i+2]
        i += 2

        data['pp1'] = pkm[i]
        i += 1

        data['pp2'] = pkm[i]
        i += 1

        data['pp3'] = pkm[i]
        i += 1

        data['pp4'] = pkm[i]
        i += 1

        data['frndshp'] = pkm[i] # Also remaining egg cycles
        i += 1

        data['pokerus'] = pkm[i]
        i += 1

        data['caught'] = pkm[i:i+2]
        i += 2

        data['level'] = pkm[i]
        i += 1

        data['status'] = pkm[i]
        i += 1

        # 1 byte unused
        i += 1

        data['curr_hp'] = pkm[i:i+2]
        i += 2

        data['max_hp'] = pkm[i:i+2]
        i += 2

        data['att'] = pkm[i:i+2]
        i += 2

        data['def'] = pkm[i:i+2]
        i += 2
        
        data['spd'] = pkm[i:i+2]
        i += 2

        data['sp_att'] = pkm[i:i+2]
        i += 2

        data['sp_def'] = pkm[i:i+2]
        i += 2
        return data
