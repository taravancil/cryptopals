#!/usr/bin/python3

"""Solutions to the Matasano crypto challenges (cryptopals.com)."""
from crypto import crypto, utils

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

    result = crypto.xor(b1, b2)
    print(result)

    # The expected output is hex-encoded
    expect(utils.bytes_to_hex(result), OUT)

if __name__ == '__main__':
    for n in CHALLENGES.keys():
        CHALLENGES[n]()
