'''
CLI to KnioPass
'''

import collections
import functools
import getpass
import json
import time
import os
import string
import sys

import colorama
try:
    import tty
    import termios
except ImportError:
    tty = None
try:
    import msvcrt
except ImportError:
    msvcrt = None

from .kniopass import KnioPass

colorama.init()


def color(style, text):
    return style + text + colorama.Style.RESET_ALL

bold = functools.partial(color, colorama.Style.BRIGHT + colorama.Fore.YELLOW)
norm = functools.partial(color, colorama.Style.NORMAL)
hide = functools.partial(color, colorama.Fore.YELLOW + colorama.Back.YELLOW)
yellow = functools.partial(color, colorama.Fore.YELLOW)


def get_choice(prompt, choices, default=None):
    while True:
        print('{} [{}]: '.format(prompt, '/'.join(choices)), end='', flush=True)

        if msvcrt:
            c = msvcrt.getch().decode('utf-8')
            print()
        else:
            orig_settings = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin)
            c = sys.stdin.read(1)[0]
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, orig_settings)

        if c in choices:
            return c

        if default is not None:
            return default


class ExitException(Exception):
    pass


class KnioPassCLI(KnioPass):
    DEFAULT_FIELDS = ('url', 'username', 'email')

    @classmethod
    def password_picker(cls):
        sets = [
            ('l', 'lowercase', string.ascii_lowercase),
            ('u', 'uppercase', string.ascii_uppercase),
            ('d', 'digits', string.digits),
            ('b', 'basic symbols', '!@#$%^&*'),
            ('e', 'extra symbols', '()_+-=<>,.{}[]\|?/~`"\''),
        ]
        sets_enabled = {
            'lowercase', 'uppercase', 'digits', 'basic symbols'
        }
        first_alpha = True
        length = 16

        def generate():
            s = {v for c, k, v in sets if k in sets_enabled}
            f = string.ascii_lowercase + string.ascii_uppercase if first_alpha else None
            try:
                return cls.generate_password(s, f, length)
            except:
                print('Could not generate password with those requirements')
                return ''

        help_text = (
            '\n[y] accept password             Toggle options:\n'
            '[enter] regenerate              [a] start with letter\n'
            '[m] manually enter password     [l] lowercase letters\n'
            '[+] longer                      [u] uppercase letters\n'
            '[-] shorter                     [d] digits\n'
            '[h] this help text              [b] basic symbols\n'
            '                                [e] extra symbols\n'
        )

        pw = generate()
        while True:
            print('\nPassword: {}'.format(bold(pw)))
            command = get_choice('Accept password?', 'ym+-aludbeh', default='').lower()
            if command == 'y':
                return pw
            if command == 'm':
                pw = getpass.getpass('Enter password:')
                continue
            if command == 'a':
                first_alpha = not first_alpha
            if command == '+':
                length += 1
            if command == '-':
                length -= 1
            if command == 'h':
                print(help_text)
            if command == 'l':
                sets_enabled.symmetric_difference_update({'lowercase'})
            if command == 'u':
                sets_enabled.symmetric_difference_update({'upper'})
            if command == 'b':
                print('bbbb')
                sets_enabled.symmetric_difference_update({'basic symbols'})
            if command == 'e':
                sets_enabled.symmetric_difference_update({'extra symbols'})
            pw = generate()

    def fuzzy_find(self, search):
        matches = []
        exact_matches = []
        for entry in self.data.values():
            s = search
            match = entry['data']['name']
            if match == search:
                exact_matches.append(entry)
            while s:
                for n, c in enumerate(match):
                    if s[0] == c: break
                    if s[0].islower() and s[0] == c.lower(): break
                else:
                    break
                s = s[1:]
                match = match[n:]
            if s:
                continue
            matches.append(entry)
        return matches, exact_matches

    def command_password(self):
        print(self.generate_password())

    def command_dump(self):
        print(json.dumps(self.data, sort_keys=True, indent=2))

    def command_add(self, name):
        existing = [e for e in self.data.values() if e['data'].get('name') == name]
        if existing:
            print('An entry with name {} already exists.'.format(bold(name)))
            c = get_choice('Are you sure you want to add a new one?', 'yN', default='N')
            if c != 'y':
                return
        print('Adding new entry {}'.format(bold(name)))

        data = {}
        c = get_choice('Password?', 'Yn', default='Y').lower()
        if c != 'n':
            data['password'] = self.password_picker()

        for item in self.DEFAULT_FIELDS:
            v = input('Add {}?: '.format(item))
            if v:
                data[item] = v

        c = get_choice('Add notes?', 'yN', default='N')
        if c == 'y':
            lines = []
            print("('.' or ^D to end)")
            while True:
                line = input()
                if line == '.': break
                if line == '\x04': break
                lines.append(line)
            data['notes'] = '\n'.join(lines)

        while True:
            c = get_choice('Add other fields?', 'yN', default='N')
            if c == 'y':
                k = input('Field name: ')
                v = input('Field value: ')
                data[k] = v
                continue
            break

        self.add(name, **data)
        self.save()

    def command_save(self):
        self.save()

    def command_exit(self):
        raise ExitException()

    @classmethod
    def show_entry(cls, entry):
        data = dict(entry['data'])
        print('\n      name: {}'.format(bold(data['name'])))
        pw = data.pop('password', None)
        if pw:
            print('  password: {}'.format(hide(pw)))
        items = []
        for n in cls.DEFAULT_FIELDS:
            if n in data:
                items.append((n, data.pop(n)))
        notes = data.pop('notes', None)
        items += sorted(data.items())
        for k, v in items:
            if k in ('name', 'password'): continue
            print('{:>10s}: {}'.format(k, yellow(v)))
        if notes:
            print('     notes:')
            print(yellow(notes))
        print()

    def command_show(self, search):
        matches, exact_matches = self.fuzzy_find(search)
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
            print('   ' + yellow(entry['data']['name']))

    def command_list(self):
        fmt = '{name:20s} {username:20s} {url:30s} {email:20s} {notes}'
        fields = (
            'name',
            'username'
        )
        print(fmt.format_map({
            'name':     bold('name'),
            'username': bold('username'),
            'email':    bold('email'),
            'url':      bold('url'),
            'notes':    bold('notes'),
        }))
        name_sort = lambda x: x['data'].get('name')
        for entry in sorted(self.data.values(), key=name_sort):
            data = collections.defaultdict(str)
            data.update({k:norm(v) for k, v in entry['data'].items()})
            print(fmt.format_map(data))

    def command_copy(self, search):
        try:
            import win32clipboard as w
            import win32con
        except ImportError:
            print('Copy not supported')
            return

        def set_cb(text):
            w.OpenClipboard()
            try:
                last = w.GetClipboardData(win32con.CF_UNICODETEXT)
            except TypeError:
                last = b'\0\0'
            w.EmptyClipboard()
            w.SetClipboardText(text, win32con.CF_TEXT)
            w.SetClipboardText(text, win32con.CF_UNICODETEXT)
            w.CloseClipboard()
            return last

        def copy(entry):
            last = set_cb(entry['data']['password'])
            print('Copied password for {}'.format(bold(entry['data']['name'])))
            print('Clearing in 10 seconds...')
            try:
                time.sleep(10)
            except KeyboardInterrupt:
                pass
            set_cb(u'')

        matches, exact_matches = self.fuzzy_find(search)

        if len(exact_matches) > 1:
            print('Multiple Entries found, cannot copy')
            return

        if len(exact_matches) == 1:
            copy(exact_matches[0])
            return

        if len(matches) > 1:
            print('Multiple Entries found, cannot copy')
            self.command_show(search)
            return

        if len(matches) == 1:
            copy(matches[0])
            return

        print('No matching entries.')


    def command_edit(self, search):
        matches, exact_matches = self.fuzzy_find(search)

        if len(exact_matches) > 1:
            print('Multiple Entries found, cannot edit')
            return
        elif len(exact_matches) == 1:
            entry = exact_matches[0]
        else:
            if len(matches) > 1:
                print('Multiple Entries found, cannot edit')
                self.command_show(search)
                return
            if len(matches) != 1:
                print('No matching entries.')
                return
            entry = matches[0]

        new_data = dict(entry['data'])
        new_data.pop('time', None)
        edited = False
        for field in sorted(new_data.keys()):
            if field in {'time'}:
                continue
            c = get_choice('Edit {}?'.format(bold(field)), 'yN', default='N')
            if c != 'y':
                continue
            print('Current value for {}: {}'.format(
                bold(field),
                yellow(new_data[field])))
            if field == 'password':
                new_value = self.password_picker()
            else:
                new_value = input('New value for {}: '.format(field))
            if new_data[field] != new_value:
                new_data[field] = new_value
                edited = True

        if edited:
            self.edit(entry['uuid'], **new_data)
            self.save()
        else:
            print('Nothing edited!')


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
            except (ExitException, KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                import traceback
                traceback.print_exc()

        print('\nExiting')
