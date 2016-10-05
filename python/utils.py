#!/usr/bin/python3
"""Utilities and wrappers for encoding and decoding."""

import codecs
import math

# Frequencies distribution of the most common 11 letters in the
# English language
ENGLISH_FREQUENCIES = {
    'E': .1202,
    'T': .0910,
    'A': .0812,
    'O': .0768,
    'I': .0731,
    'N': .0695,
    'S': .0628,
    'R': .0602,
    'H': .0592,
    'D': .0432,
    'L': .0398,
}

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

def base64_to_bytes(base64str):
    """Decode the given base64-encoded string and return a bytes object."""
    _bytes = bytes(base64str, 'utf-8')
    return codecs.encode(_bytes, 'base64')

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

def english_score(string):
    """
    Return a score that indicates the likelihood that a given
    string is written in English. Higher score indicates highers
    likelihood.
    """
    # frequencies = {}
    string = string.upper()
    total_chars = len(string)
    score = 0

    # Count the occurrences of each letter in the input strin
    for char in ENGLISH_FREQUENCIES:
        count = string.count(char)
        char_score = count/total_chars
        # frequencies[char] = char_score

        # Calculate how similar the calculated distribution is to the
        # distribution in ENGLISH_FREQUENCIES. The smaller the
        # distance, the higher the score.
        score += math.sqrt(char_score * ENGLISH_FREQUENCIES[char])

    return score

def hamming_distance(bytes1, bytes2):
    """Return the Hamming distance of two bytes objects."""
    if len(bytes1) != len(bytes2):
        raise Exception("Input strings must be the same length")

    distance = 0

    for i in range(0, len(bytes1)):
        # Hamming distance indicates the difference between two
        # inputs. When we XOR corresponding bits, a 1 indicates that
        # the corresponding bits are not equal. We can count the
        # number of mismatched bits in a byte by calculating the
        # Hamming weight (basically the number of 1s in a byte) of the
        # result of XORing bytes1[i] with bytes2[i]
        distance += hamming_weight(bytes1[i] ^ bytes2[i])

    return distance

def hamming_weight(x):
    """
    Return the Hamming weight of a given byte.

    Constants are from https://wikipedia.org/wiki/Hamming_weight.
    """
    m1 = 0x5555555555555555
    m2 = 0x3333333333333333
    m4 = 0x0f0f0f0f0f0f0f0f
    h01 = 0x0101010101010101

    x -= (x >> 1) & m1
    x = (x & m2) + ((x >> 2) & m2)
    x = (x + (x >> 4)) & m4
    return (x * h01) >> 56
