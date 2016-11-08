#!/usr/bin/python3
"""Utilities and wrappers for encoding and decoding."""

import codecs
import itertools
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

def remove_unprintable_ascii(string):
    return ''.join(c for c in string if ord(c) >= 32)

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

def find_possible_keysizes(ciphertext, n, min_keysize, max_keysize):
    """
    Return a list of n possible keysizes in range(min_keysize,
    max_keysize + 1).

    For each keysize in range(min_keysize, max_keysize + 1), take the
    first 4 keysize blocks, find the Hamming distance between each
    possible pair of blocks, and normalize the Hamming distance.

    The n keysizes with the smallest normalized Hamming distance are
    the candidates.
    """
    # Check the inputs' length requirements
    if n == 0 or len(ciphertext) == 0:
        return []

    if min_keysize >= max_keysize:
        raise Exception("max_keysize must be greater than min_keysize")

    if max_keysize * 4 > len(ciphertext):
        raise Exception(
            "The ciphertext is not long enough to analyze")

    # Initialize a dictionary of minimum normalized Hamming distances to a
    # large number
    min_dists = {0: 1000, 1: 1001, 3: 1002}

    for size in range(min_keysize, max_keysize + 1):
        # Get a list of the first 4 blocks of length size
        blocks = [ciphertext[i:i + size] for i in range(0, size*4, size)]

        # Get a list of all 2-block combinations in blocks
        block_combos = itertools.combinations(blocks, 2)

        # Calculate the Hamming distance for each 2-block combination
        dists_sum = 0
        for pair in block_combos:
            dists_sum += hamming_distance(pair[0], pair[1])

        # Get the normalized distance; 6 = number of combinations; 
        normalized_dist = dists_sum / 6 / size

        # The key of the highest value in min_dists
        max_key = max(min_dists, key=min_dists.get)

        # If dist is smaller than the max value in min_dists, remove
        # the old max and add dist to the object
        if normalized_dist < min_dists[max_key]:
            del min_dists[max_key]
            min_dists[size] = normalized_dist

    return min_dists.keys()
