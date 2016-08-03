import pytest
from week2 import *

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
    for i in range(256):
        string = b'z' * i
        assert(unpad_pkcs5(pad_pkcs5(string)) == string)
