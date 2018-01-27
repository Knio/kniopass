import argparse
import getpass
import json
import logging
import os
import string

import cryptography.hazmat
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.kdf.pbkdf2
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.padding

BACKEND = cryptography.hazmat.backends.default_backend()
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger()

class ExitException(Exception): pass

class PasswordStore(object):
    DATA_MAGIC = b'kniopass'
    KEY_SALT = b'kniopass890123456'
    KEY_ITERATIONS = (1 << 19)
    KEY_LENGTH = 32 * 8
    ALGORITHMS = [
        (32, cryptography.hazmat.primitives.ciphers.algorithms.AES),
        (32, cryptography.hazmat.primitives.ciphers.algorithms.Camellia),
        (16, cryptography.hazmat.primitives.ciphers.algorithms.CAST5),
        (16, cryptography.hazmat.primitives.ciphers.algorithms.SEED),
    ]
    def __init__(self, filename, password):
        self.filename = filename
        self.key = self.compute_key(password)
        self.data = None
        self.modified = False

    @classmethod
    def compute_key(cls, password):
        keygen = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            backend=BACKEND,
            algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            length=cls.KEY_LENGTH,
            salt=cls.KEY_SALT,
            iterations=cls.KEY_ITERATIONS
        )
        return keygen.derive(password.encode('utf-8'))

    @classmethod
    def decrypt_data(cls, key, data):
        key_offset = sum(i[0] for i in cls.ALGORITHMS)
        nonce = data[:cls.KEY_LENGTH]
        data = data[cls.KEY_LENGTH:]
        for key_size, alg in reversed(cls.ALGORITHMS):
            key_offset -= key_size
            k = key[key_offset : key_offset + key_size]
            a = alg(k)
            n = nonce[key_offset : key_offset + a.block_size // 8]
            p = cryptography.hazmat.primitives.padding.PKCS7(a.block_size).unpadder()
            cipher = cryptography.hazmat.primitives.ciphers.Cipher(
                a,
                cryptography.hazmat.primitives.ciphers.modes.CBC(n),
                backend=BACKEND
            )
            decryptor = cipher.decryptor()
            data = decryptor.update(data) + decryptor.finalize()
            data = p.update(data) + p.finalize()
        return data

    @classmethod
    def encrypt_data(cls, key, data):
        key_offset = 0
        nonce = os.urandom(cls.KEY_LENGTH)
        for key_size, alg in cls.ALGORITHMS:
            k = key[key_offset : key_offset + key_size]
            a = alg(k)
            n = nonce[key_offset : key_offset + a.block_size // 8]
            key_offset += key_size
            p = cryptography.hazmat.primitives.padding.PKCS7(a.block_size).padder()
            data = p.update(data) + p.finalize()
            cipher = cryptography.hazmat.primitives.ciphers.Cipher(
                a,
                cryptography.hazmat.primitives.ciphers.modes.CBC(n),
                backend=BACKEND
            )
            encryptor = cipher.encryptor()
            data = encryptor.update(data) + encryptor.finalize()
        return nonce + data

    def load_file(self):
        LOG.info('Loading %s', self.filename)
        data = open(self.filename, 'rb').read()
        data = self.decrypt_data(self.key, data)
        if not data[0:8] == self.DATA_MAGIC:
            raise Exception('Wrong password')
        data = data[8:].decode('utf-8')
        self.data = json.loads(data)

    def save_file(self):
        data = json.dumps(self.data, sort_keys=True, indent=2)
        data = self.DATA_MAGIC + data.encode('utf-8')
        data = self.encrypt_data(self.key, data)
        LOG.info('Saving to %s', self.filename)
        open(self.filename, 'wb').write(data)
        self.modified = False

    @staticmethod
    def generate_password(sets=None, length=16):
        first_chr = string.ascii_lowercase + string.ascii_uppercase
        sets = {
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            '!@#$%^&*' # '()_+-=<>,.{}[]\|?/~`"\'',
        }
        all_chars = ''.join(sets)
        char_to_set = {}
        for s in sets:
            for c in s:
                char_to_set[c] = s
        while True:
            password = []
            while len(password) < length:
                chrs = map(chr, os.urandom(32))
                password += [c for c in chrs if c in all_chars]
            password = password[:length]
            s = {char_to_set[c] for c in password}
            if sets != s:
                continue
            if password[0] not in first_chr:
                continue
            return ''.join(password)

    def command_password(self):
        print(self.generate_password())

    def command_dump(self):
        print(json.dumps(self.data, sort_keys=True, indent=2))

    def command_add(self, name):
        entry = {
            'name': name,
            'password': self.generate_password(),
        }
        self.data.append(entry)
        self.modified = True

    def command_save(self):
        self.save_file()

    def command_exit(self):
        if self.modified:
            self.save_file()
        raise ExitException()

    @staticmethod
    def show_entry(entry):
        for k, v in sorted(entry.items()):
            print('{}: {}'.format(k, v))

    def command_show(self, search):
        matches = []
        exact_matches = []
        for entry in self.data:
            s = search
            match = entry['name']
            if match == search:
                exact_matches.append(entry)
            while s:
                n = match.find(s[0])
                if n == -1:
                    break
                s = s[1:]
                match = match[n:]
            if s:
                continue
            matches.append(entry)

        if len(exact_matches) == 1:
            self.show_entry(exact_matches[0])
            return

        if len(exact_matches) > 1:
            print('Multiple Entries found:')
            print()
            for entry in exact_matches:
                self.show_entry(entry)
                print()
            return

        if len(matches) == 0:
            print('No matching entries.')
            return

        if len(matches) == 1:
            self.show_entry(matches[0])
            return

        print('Found multiple matches:')
        for entry in matches:
            print('   ' + entry['name'])

    def repl(self):
        while True:
            try:
                prompt = '{}> '.format(os.path.basename(self.filename))
                command = input(prompt).strip().split()
                if not command:
                    continue
                c, args = command[0], command[1:]
                m = getattr(self, 'command_{}'.format(c), None)
                if not m:
                    print('Invalid command')
                    continue
                m(*args)
            except ExitException:
                break
            except KeyboardInterrupt:
                self.save_file()
                break
            except Exception as e:
                LOG.exception(e)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file')
    parser.add_argument('--create')
    args = parser.parse_args()

    if args.create:
        if os.path.isfile(args.create):
            raise Exception('File already exists. Refusing to overwrite')
        password = getpass.getpass('Password for {}: '.format(args.create))
        pw = PasswordStore(filename=args.create, password=password)
        pw.data = []
        pw.save_file()
        LOG.info('Created new empty password store %s', args.create)
        return

    if args.file:
        if not os.path.isfile(args.file):
            raise Exception('File does not exist')
        password = getpass.getpass('Password for {}: '.format(args.file))
        pw = PasswordStore(filename=args.file, password=password)
        pw.load_file()
        pw.repl()

if __name__ == '__main__':
    main()
