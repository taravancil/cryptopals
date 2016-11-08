def has_repeated_block(_bytes, blocksize):
    blocks = split_into_blocks(_bytes, blocksize)
    tmp = set()

    for block in blocks:
        if block not in tmp:
            tmp.add(block)
        else:
            return True

    return False

def split_into_blocks(_bytes, blocksize):
    return [_bytes[i:i+blocksize] for i in range(0, len(_bytes))]

def pad(_bytes, blocksize):
    while len(_bytes) % blocksize != 0:
        _bytes += b'\x04'

    return _bytes
