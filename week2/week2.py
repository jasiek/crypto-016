from Crypto.Cipher import AES
from Crypto import Random
import bitstring

import pdb

def hex2bin(hexstring):
    return bitstring.Bits(hex=hexstring).bytes

def bin2hex(binstring):
    return bitstring.Bits(bytes=binstring).hex

def xor(binstring1, binstring2):
    def xorbyte(a, b):
        return a ^ b
    return b''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(binstring1, binstring2)])
        

def pad_pkcs5(binstring):
    to_pad = 16 - len(binstring) % 16
    padding = chr(to_pad) * to_pad
    return binstring + padding

def unpad_pkcs5(binstring):
    if len(binstring) == 0:
        return binstring
    else:
        last_block = binstring[-AES.block_size:]
        to_pad = ord(last_block[-1])
        padding = chr(to_pad) * to_pad
        if last_block[AES.block_size - to_pad:] == padding:
            return binstring[0:-to_pad]
        else:
            return binstring

def split_into_chunks(binstring, size):
    chunks = []
    while len(binstring) > 0:
        chunks.append(binstring[0:size])
        binstring = binstring[size:]
    return chunks
        
def cbc_encrypt(plaintext_h, key_h):
    iv_b = Random.new().read(AES.block_size)
    plaintext_b = hex2bin(plaintext_h)
    key_b = hex2bin(key_h)
    padded_plaintext_b = pad_pkcs5(plaintext_b)
    cipher = AES.new(key_b, AES.MODE_ECB)

    def step(to_xor, inchunk):
        xored = xor(inchunk, to_xor)
        encrypted = cipher.encrypt(xored)
        return (encrypted, encrypted)
    
    output = [iv_b]
    to_xor = iv_b
    for inchunk in split_into_chunks(padded_plaintext_b, AES.block_size):
        to_xor, outchunk = step(to_xor, inchunk)
        output.append(outchunk)

    return bin2hex(b''.join(output))
    
def cbc_decrypt(ciphertext_h, key_h):
    ciphertext_b = hex2bin(ciphertext_h)
    key_b = hex2bin(key_h)
    chunks = split_into_chunks(ciphertext_b, AES.block_size)
    iv_b = chunks.pop(0)
    cipher = AES.new(key_b, AES.MODE_ECB)

    def step(to_xor, inchunk):
        unxored = cipher.decrypt(inchunk)
        outchunk = xor(unxored, to_xor)
        return (inchunk, outchunk)

    output = []
    to_xor = iv_b
    for inchunk in chunks:
        to_xor, outchunk = step(to_xor, inchunk)
        output.append(outchunk)
    
    return bin2hex(unpad_pkcs5(b''.join(output)))


def increment(ctr):
    ctr_b = bitstring.Bits(bytes=ctr)
    i = (ctr_b.uint + 1) % 2 ** (AES.block_size * 8)
    return bitstring.Bits(uint=i, length=AES.block_size * 8).bytes

def ctr_encrypt(plaintext_h, key_h):
    nonce = Random.new().read(AES.block_size / 2)
    counter = b'\x00' * (AES.block_size / 2)

    plaintext_b = hex2bin(plaintext_h)
    padded_plaintext_b = pad_pkcs5(plaintext_b)
    key_b = hex2bin(key_h)
    cipher = AES.new(key_b, AES.MODE_ECB)

    def step(nonce_and_counter, chunk):
        encrypted = cipher.encrypt(nonce_and_counter)
        return (increment(nonce_and_counter), xor(chunk, encrypted))

    nonce_and_counter = nonce + counter
    output = [nonce_and_counter]
    for inchunk in split_into_chunks(padded_plaintext_b, AES.block_size):
        nonce_and_counter, encrypted = step(nonce_and_counter, inchunk)
        output.append(encrypted)

    return bin2hex(b''.join(output))

def ctr_decrypt(ciphertext_h, key_h):
    ciphertext_b = hex2bin(ciphertext_h)
    key_b = hex2bin(key_h)
    chunks = split_into_chunks(ciphertext_b, AES.block_size)
    nonce_and_counter = chunks.pop(0)
    cipher = AES.new(key_b, AES.MODE_ECB)

    def step(nonce_and_counter, chunk):
        decrypted = xor(cipher.encrypt(nonce_and_counter), chunk)
        return (increment(nonce_and_counter), decrypted)

    output = []
    for inchunk in chunks:
        nonce_and_counter, outchunk = step(nonce_and_counter, inchunk)
        output.append(outchunk)
        
    return bin2hex(unpad_pkcs5(b''.join(output)))
    
    

print hex2bin(cbc_decrypt('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81', '140b41b22a29beb4061bda66b6747e14'))
print hex2bin(cbc_decrypt('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253', '140b41b22a29beb4061bda66b6747e14'))
print hex2bin(ctr_decrypt('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329', '36f18357be4dbd77f050515c73fcf9f2'))
print hex2bin(ctr_decrypt('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451', '36f18357be4dbd77f050515c73fcf9f2'))
