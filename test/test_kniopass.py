import kniopass

PASSWORD = 'hunter42'

def test_compute_key():
    key = kniopass.KnioPass.compute_key(PASSWORD)
    assert key == (
        b'\x08\xcb\xcc\xc2\x18 \x8f\xca\xe4\xf0\xabx+\x94\xb9\x16.\x14H\x16'
        b"\xba\xf5<\xc9\x7f\xbf\xaelA>!\x9a\x1c\xf6H\x85ty\x87N\xd5'u\\\xda\xfbL\xe1"
        b'\x80|\x0e\xbb\xa8\xe2\x9a\xdd\xb0\x07\xc4\xd66\x97\x04U\x0e\xe0\x9c\xba'
        b'\xf8}\xf1\x8a\xe9{\xee\x9em\n\xf8l\xff\xc6\x97\x15\x01\xe9\x9c@[\x9fMN'
        b'Fj\x1a\xfa'
    )

def test_encrypt_data():
    key = kniopass.KnioPass.compute_key(PASSWORD)
    data = b'foobar asdasd kasdkljasdkl asjdkl asjdkla sjdl'
    ct = kniopass.KnioPass.encrypt_data(key, data)
    pt = kniopass.KnioPass.decrypt_data(key, ct)
    assert data == pt

def test_password():
    password = kniopass.KnioPass.generate_password({'a', 'b'}, 'a')
    print(password)
    assert password.startswith('a')
    assert 'b' in password
