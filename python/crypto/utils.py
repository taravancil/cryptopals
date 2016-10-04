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
