'''
Simple password manager.
'''

import datetime
import json
import logging
import sys
import os
import uuid

from .encryptedfile import EncryptedFile

LOG = logging.getLogger()


class KnioPass(EncryptedFile):
    def save(self):
        data = json.dumps(self.data, sort_keys=True, indent=2)
        self.save_file(data.encode('utf-8'))

    def load(self):
        data = self.load_file()
        self.data = json.loads(data)

    def add(self, name, **data):
        entry = {
            'uuid': str(uuid.uuid4()),
            'data': {
                'time': datetime.datetime.utcnow().isoformat(),
                'name': name,
                **data
            },
            'history': []
        }
        self.data[entry['uuid']] = entry
        self.modified = True

    def edit(self, uuid, **new_data):
        entry = self.data[uuid]
        entry['history'].append(entry['data'])
        entry['data'] = {
            'time': datetime.datetime.utcnow().isoformat(),
            **new_data
        }
        self.modified = True

    @staticmethod
    def generate_password(sets=None, first_set=None, length=16):
        all_chars = ''.join(sets)
        if not first_set:
            first_set = ''.join(sets)
        char_to_set = {}
        for s in sets:
            for c in s:
                char_to_set[c] = s
        for i in range(10000):
            password = []
            while len(password) < length:
                chrs = map(chr, os.urandom(32))
                password += [c for c in chrs if c in all_chars]
            password = password[:length]
            s = {char_to_set[c] for c in password}
            if sets != s:
                continue
            if password[0] not in first_set:
                continue
            return ''.join(password)
        raise Exception('Impossible requirements')
