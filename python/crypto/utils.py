#!/usr/bin/python3
"""Utilities and wrappers for encoding and decoding."""

import codecs

def hex_to_base64(hexstr):
    """Convert the given string to base64."""
    decoded = codecs.decode(hexstr, 'hex')
    return codecs.encode(decoded, encoding='base64')

def hex_to_bytes(hexstr):
    """Convert the given string to a bytes object."""
    decoded = codecs.decode(hexstr, 'hex')
    return str_to_bytes(decoded)

def str_to_bytes(s):
    return bytes(s)
