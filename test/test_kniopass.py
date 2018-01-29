import kniopass

SALT = b'abcdefgh12345678'
PASSWORD = 'hunter42'

def test_compute_key():
    key = kniopass.KnioPass.compute_key(SALT, PASSWORD)
    assert key == (
        b'\xd4;t\x9fre\xac\x1a\xe8{\xfd\xf6\xe4\xa7\x14\x92x\xa9\x07?\xde6\xa1&'
        b'\xbfl\xcdQ\x93G\xca\xaf\xe4qw\xfd\xf0\xa3\x8e\xab?\x9a\x98\x8fQ\xf0\xcc\x92'
        b'i\xdc\x16\x8a\xeb\nE\x1b\xebKX\xaff\x82\xb7lHB\xeb\x83\x0b\xd7\x1a\x08'
        b'\x12c=+\x1e\xe8(Z\xc26\xd0\xe0\xb3\xb2J\xe0\xe6\xaf\x08\x8f\x1b\x17\x96\xfa'
    )

def test_encrypt_data():
    key = kniopass.KnioPass.compute_key(SALT, PASSWORD)
    data = b'foobar asdasd kasdkljasdkl asjdkl asjdkla sjdl'
    ct = kniopass.KnioPass.encrypt_data(key, data)
    pt = kniopass.KnioPass.decrypt_data(key, ct)
    assert data == pt

def test_password():
    password = kniopass.KnioPass.generate_password({'a', 'b'}, 'a')
    print(password)
    assert password.startswith('a')
    assert 'b' in password
