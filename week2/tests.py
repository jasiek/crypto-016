import pytest
from Crypto import Random
from Crypto.Random import random as rand
from week2 import *

random = Random.new()

def test_hex2bin():
    assert(hex2bin('00') == b'\x00')
    assert(hex2bin('01') == b'\x01')

def test_bin2hex():
    assert(bin2hex(b'\x00') == '00')
    assert(bin2hex(b'\x01') == '01')

def test_xor():
    assert(xor(b'\x00', b'\x01') == b'\x01')
    assert(xor(b'\xff', b'\x01') == b'\xfe')
    assert(xor(b'\x00\x00', b'\x01\x02') == b'\x01\x02')

def test_pad_pkcs5():
    for i in range(16):
        assert(pad_pkcs5(b'z' * i) == b'z' * i + chr(16 - i) * (16 - i))
    assert(pad_pkcs5(b'z' * 16) == b'z' * 16 + chr(16) * 16)

def test_pad_unpad_pkcs5():
    for _ in xrange(1000):
        length = rand.randint(0, 1000)
        random_string = random.read(length)
        assert(unpad_pkcs5(pad_pkcs5(random_string)) == random_string)

def test_split_into_chunks():
    for _ in xrange(1000):
        whole_size = rand.randint(100, 10000)
        chunk_size = rand.randint(1, 100)
        random_string = random.read(whole_size)
        chunks = split_into_chunks(random_string, chunk_size)
        for c in chunks:
            if c == chunks[-1]:
                assert(len(c) <= chunk_size)
            else:
                assert(len(c) == chunk_size)

def test_encrypt_decrypt_cbc():
    for _ in xrange(1000):
        length = rand.randint(1, 1000)
        key = bin2hex(random.read(16))
        plaintext = bin2hex(random.read(length))

        assert(cbc_decrypt(cbc_encrypt(plaintext, key), key) == plaintext)

def test_encrypt_decrypt_ctr():
    for _ in xrange(1000):
        length = rand.randint(1, 1000)
        key = bin2hex(random.read(16))
        plaintext = bin2hex(random.read(length))

        ciphertext = ctr_encrypt(plaintext, key)
        decrypted = ctr_decrypt(ciphertext, key)
        assert(len(decrypted) == len(plaintext))
        assert(decrypted == plaintext)

def test_increment():
    a = '\x00' * 16
    b = increment(a)
    assert(b == '\x00' * 15 + '\x01')

    a = '\xff' * 16
    b = increment(a)
    assert(b == '\x00' * 16)
