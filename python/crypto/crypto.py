#!/usr/bin/python3

def xor(b1, b2):
    """Return the result of XORing two equal-length bytes objects."""

    if len(b1) != len(b2):
        raise Exception('bytes objects must have the same length')

    result = []
    for i in range(0, len(b1)):
        result.append(b1[i] ^ b2[i])

    return bytes(result)

def xor_repeating_key(_bytes, key):
    """
    Return the result of XORing a bytes object with a single-byte
    key.
    """
    # Get mutable bytearray
    _bytes = bytearray(_bytes)

    for i in range(0, len(_bytes)):
        tmp = _bytes[i]
        _bytes[i] = tmp ^ key

    return _bytes
