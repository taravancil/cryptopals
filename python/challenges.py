#!/usr/bin/python3

"""Solutions to the Matasano crypto challenges (cryptopals.com)."""
import base64
from _crypto import _crypto, blocks
from Crypto.Cipher import AES
from itertools import zip_longest
import utils

CHALLENGES = {}
def challenge(n):
    """Wrapper for challenges."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            print('--------------')
            print('Challenge %d' % n)
            print('--------------')
            f(*args, **kwargs)
        CHALLENGES[n] = wrapper
        return wrapper
    return decorator

def expect(actual, expected):
    """Compare actual to expected and print feedback."""
    if actual != expected:
        print(u'\u2718 Failed')
        print('Got:\n{}'.format(actual))
        print('Expected:\n{}'.format(expected))
        return

    print(u'\u2713 Success!')
    print(actual)

@challenge(1)
def chal1():
    """Convert a hex string to base64."""
    IN = '49276d206b696c6c696e6720796f757220627261696e206c696b6' \
         '5206120706f69736f6e6f7573206d757368726f6f6d'

    OUT = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    expect(utils.hex_to_base64(IN), OUT)

@challenge(2)
def chal2():
    """XOR two equal-length buffers."""
    IN1 = '1c0111001f010100061a024b53535009181c'
    IN2 = '686974207468652062756c6c277320657965'
    OUT = '746865206b696420646f6e277420706c6179'

    b1 = utils.hex_to_bytes(IN1)
    b2 = utils.hex_to_bytes(IN2)

    result = _crypto.xor(b1, b2)

    # The expected output is hex-encoded
    expect(utils.bytes_to_hex(result), OUT)

@challenge(3)
def chal3():
    """The input has been XORed against a single character. Find the
    key, decrypt the message.
    """
    IN = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a' \
         '393b3736'
    OUT = b'cOOKING\x00mc\x07S\x00LIKE\x00A\x00POUND\x00OF\x00BACON'
    ciphertext = utils.hex_to_bytes(IN)

    # I forgot how I figured this out in my Golang implementation, but
    # it turns out there are a bunch of null bytes in the
    # plaintext. A NULL byte in binary is 000000 so when you XOR it
    # with any byte, you get the byte. So in this case, because the
    # NULL byte occurs most frequently in the plaintext, in the
    # ciphertext the key is the most common byte. TODO how in the heck
    # do I figure this out with frequency analysis and without advance
    # knowledge of the fact that there are a bunch of NULL bytes?
    key = utils.get_popular_byte(ciphertext)
    plaintext = _crypto.xor_single_byte_key(ciphertext, key)

    expect(plaintext.decode('utf-8'), OUT.decode('utf-8'))

@challenge(4)
def chal4():
    """
    One of the 60-character strings in input/4.txt has been
    encrypted with single-character XOR. Find it and decrypt it.
    """
    f = open('input/4.txt')
    # TODO Fenimore's suggestion about using an uppercase key
    OUT = b'nOW\x00THAT\x00THE\x00PARTY\x00IS\x00JUMPING*'
    best_score = 0
    result = ''

    for line in f:
        ciphertext = utils.hex_to_bytes(line.strip())

        # Assume the most popular byte in the ciphertext is the key
        key = utils.get_popular_byte(ciphertext)

        # Try the key
        plaintext_bytes = _crypto.xor_single_byte_key(ciphertext, key)

        score = utils.english_score(str(plaintext_bytes))

        # The decrypted string that looks most like English is most
        # likely the one we're looking for
        if score > best_score:
            best_score = score
            result = plaintext_bytes

    expect(result.decode('utf-8'), OUT.decode('utf-8'))

@challenge(5)
def chal5():
    """Encrypt the input under the key 'ICE' using repeating-key XOR."""
    IN = "Burning 'em, if you ain't quick and nimble\nI go crazy" \
         " when I hear a cymbal"
    OUT = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622' \
          '6324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c69' \
          '2b20283165286326302e27282f'
    KEY = 'ICE'

    ciphertext = _crypto.xor_repeating_key(bytes(IN, 'utf-8'),
                                          bytes(KEY, 'utf-8'))
    result = utils.bytes_to_hex(ciphertext)

    expect(result, OUT)

@challenge(6)
def chal6():
    """
    The text in input/6.txt has been base64 encoded after being
    encrypted with repeating-key XOR. Decrypt it.
    """
    f = open('input/6.txt')
    ciphertext = utils.base64_to_bytes(f.read())

    best_english_score = 0
    result = ''

    keysizes = utils.find_possible_keysizes(ciphertext, 3, 2, 40)
    for keysize in keysizes:
        key = [0] * keysize

        # Split the ciphertext into blocks of length keysize
        blocks = [ciphertext[i:i+keysize] for i in range(0,
    len(ciphertext), keysize)]

        # Transpose the blocks
        transposed = [bytes(t) for t in zip_longest(*blocks,
        fillvalue=0)]

        # Treat each block as if it's been encrypted with a
        # repeating-key XOR
        for i in range(0, len(transposed)-1):
            key[i] = utils.get_popular_byte(transposed[i])

        plaintext = _crypto.xor_repeating_key(ciphertext, bytes(key))
        english_score = utils.english_score(plaintext.decode('utf-8'))

        if english_score > best_english_score:
            result = plaintext.decode('utf-8')

@challenge(7)
def chal7():
    """
    The text in input/7.txt has been encrypted with AES-128 in ECB
    mode under the key YELLOW SUBMARINE and base64-encoded. Decrypt
    it.
    """
    KEY = 'YELLOW SUBMARINE'
    INPUT = open('input/7.txt').read()
    OUTPUT = open('output/7.txt').read()

    ciphertext = base64.b64decode(INPUT)
    cipher = AES.new(KEY, AES.MODE_ECB)

    # Why the heck does each line in the plaintext have extra
    # whitespace at the end?
    plaintext = utils.strip_unprintable(cipher.decrypt(ciphertext).decode('utf-8'))
    lines = plaintext.split('\n')
    result = ''
    for line in lines:
        result += line.rstrip(' ') + '\n'

    expect(result, OUTPUT)

@challenge(8)
def chal8():
    """
    One of the lines in input/8.txt is encrypted with AES in ECB
    mode. Detect it.
    """
    INPUT = open('input/8.txt').read()

    result = -1

    for (i, line) in enumerate(INPUT.split('\n')):
        # if the line has a repeated block, it's probably encrypted
        # in ECB mode
        if blocks.has_repeated_block(bytes(line, 'utf-8'), 16):
            result = i

    expect(result, 132)

@challenge(9)
def chal9():
    """Implement PKCS#7 padding"""
    INPUT = b'YELLOW SUBMARINE'
    OUTPUT = b'YELLOW SUBMARINE\x04\x04\x04\x04'

    expect(blocks.pad(INPUT, 20), OUTPUT)

if __name__ == '__main__':
    for n in CHALLENGES.keys():
        CHALLENGES[n]()
