#!/usr/bin/python

"""Utilities and wrappers for encoding and decoding."""
def hex_to_base64(hexstr):
    """Convert the given string to base64."""
    return hexstr.decode('hex').encode('base64').strip() # strip newline
