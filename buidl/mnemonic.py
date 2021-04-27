from os import path
from secrets import randbits
from time import time

from buidl.helper import int_to_big_endian, sha256


def secure_mnemonic(num_bits=256, extra_entropy=0):
    """
    Generates a mnemonic phrase using num_bits of entropy
    extra_entropy is optional and should not be saved as it is NOT SUFFICIENT to recover your mnemonic.
    extra_entropy exists only to prevent 100% reliance on your random number generator.
    """
    if num_bits not in (128, 160, 192, 224, 256):
        raise ValueError(f"Invalid num_bits: {num_bits}")
    if type(extra_entropy) is not int:
        raise TypeError(f"extra_entropy must be an int: {extra_entropy}")
    if extra_entropy < 0:
        raise ValueError(f"extra_entropy cannot be negative: {extra_entropy}")

    # if we have more than 128 bits, just mask everything but the last 128 bits
    if len(bin(extra_entropy)) > num_bits + 2:
        extra_entropy &= (1 << num_bits) - 1

    # For added paranoia, xor current epoch to extra_entropy
    # Would use time.time_ns() but that requires python3.7
    extra_entropy ^= int(time() * 1_000_000)

    # xor some random bits with the extra_entropy that was passed in
    preseed = randbits(num_bits) ^ extra_entropy
    # convert the number to big-endian
    s = int_to_big_endian(preseed, num_bits // 8)
    # 1 extra bit for checksum is needed per 32 bits
    checksum_bits_needed = num_bits // 32
    # the checksum is the sha256's first n bits. At most this is 8
    checksum = sha256(s)[0] >> (8 - checksum_bits_needed)
    # we concatenate the checksum to the preseed
    total = (preseed << checksum_bits_needed) | checksum
    # now we get the mnemonic passphrase
    mnemonic = []

    # now group into groups of 11 bits
    for _ in range((num_bits + checksum_bits_needed) // 11):
        # grab the last 11 bits
        current = total & ((1 << 11) - 1)
        # insert the correct word at the front
        mnemonic.insert(0, get_bip39_word(current))
        # shift by 11 bits so we can move to the next set
        total >>= 11
    # return the mnemonic phrase by putting spaces between
    return " ".join(mnemonic)


BIP39_WORDS = []
BIP39_LOOKUP = {}


def all_bip39_words():
    # lazy load
    if not BIP39_WORDS:
        __init__()
    for word in BIP39_WORDS:
        yield word


def normalize_bip39_word(word):
    """Return the full word not the partial"""
    # lazy load
    if not BIP39_WORDS:
        __init__()
    return BIP39_WORDS[BIP39_LOOKUP[word]]


def get_bip39_index(word):
    if not BIP39_WORDS:
        __init__()
    return BIP39_LOOKUP[word]


def get_bip39_word(index):
    """Get the word at a particular index"""
    # lazy load
    if not BIP39_WORDS:
        __init__()
    return BIP39_WORDS[index]


def __init__():
    # load word from file and make a lookup table
    word_file = path.join(path.dirname(__file__), "bip39_words.txt")
    global BIP39_WORDS, BIP39_LOOKUP
    with open(word_file, "r") as f:
        BIP39_WORDS = f.read().split()
    for i, word in enumerate(BIP39_WORDS):
        # add the word's index in the hash BIP39_LOOKUP
        BIP39_LOOKUP[word] = i
        # if the word is more than 4 characters, also keep
        #  a lookup of just the first 4 characters
        if len(word) > 4:
            BIP39_LOOKUP[word[:4]] = i
