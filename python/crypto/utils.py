#!/usr/bin/python3
"""Utilities and wrappers for encoding and decoding."""

import codecs

def hex_to_base64(hexstr):
    """Convert the given string to base64."""

    decoded = codecs.decode(hexstr, 'hex')

    # Strip the trailing newline from codecs
    return codecs.encode(decoded, 'base64').decode('utf-8').strip()

def hex_to_bytes(hexstr):
    """Convert the given string to a bytes object."""
    decoded = codecs.decode(hexstr, 'hex')
    return str_to_bytes(decoded)

def bytes_to_hex(_bytes):
    """Convert the given bytes object to a hex string."""
    return _bytes.hex()

def str_to_bytes(s):
    return bytes(s)

def get_popular_byte(_bytes):
    """
    Return the most popular byte in a bytes object. O(n) time when k
    <= n. O(k) space.
    space.
    """

    # Max value is 255, k = max + 1
    k = 256

    # Create a lookup array of length k to track the count of
    # each byte. Bytes will be looked up by their index.
    lookup = [0] * k

    # O(n)
    for b in _bytes:
        lookup[b] += 1

    max_count = 0
    result = 0

    # Iterate through the lookup array. O(k) == O(256)
    for i in range(0, k):
        if lookup[i] > max_count:
            max_count = lookup[i]
            result = i

    return result
