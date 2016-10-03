#!/usr/bin/python

"""Solutions to the Matasano crypto challenges (cryptopals.com)."""
from crypto import utils

CHALLENGES = {}
def challenge(n):
    """Wrapper for challenges."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            print '--------------'
            print 'Challenge %d' % n
            print '--------------'
            f(*args, **kwargs)
        CHALLENGES[n] = wrapper
        return wrapper
    return decorator

def expect(actual, expected):
    """Compare actual to expected and print feedback."""
    if actual != expected:
        print u'\u2718 Failed'
        print 'Got:\n{}'.format(actual)
        print 'Expected:\n{}'.format(expected)
        return

    print u'\u2713 Success!'
    print actual

@challenge(1)
def chal1():
    """Convert a hex string to base64."""
    IN = '49276d206b696c6c696e6720796f757220627261696e206c696b6' \
         '5206120706f69736f6e6f7573206d757368726f6f6d'

    OUT = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    expect(utils.hex_to_base64(IN), OUT)

if __name__ == '__main__':
    for n in CHALLENGES.keys():
        CHALLENGES[n]()
