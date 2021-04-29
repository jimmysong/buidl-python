from os import path
from secrets import randbits
from time import time

from buidl.helper import big_endian_to_int, int_to_big_endian, sha256


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

    # if we have more bits than needed, mask so we get what we need
    if len(bin(extra_entropy)) > num_bits + 2:
        extra_entropy &= (1 << num_bits) - 1

    # For added paranoia, xor current epoch to extra_entropy
    # Would use time.time_ns() but that requires python3.7
    extra_entropy ^= int(time() * 1_000_000)

    # xor some random bits with the extra_entropy that was passed in
    preseed = randbits(num_bits) ^ extra_entropy
    # convert the number to big-endian
    s = int_to_big_endian(preseed, num_bits // 8)
    # convert to mnemonic
    mnemonic = bytes_to_mnemonic(s, num_bits)
    # sanity check
    if mnemonic_to_bytes(mnemonic) != s:
        raise RuntimeError('Generated mnemonic does not correspond to random bits')
    return mnemonic


def mnemonic_to_bytes(mnemonic):
    '''returns a byte representation of the mnemonic'''
    all_bits = 0
    words = mnemonic.split()
    num_words = len(words)
    for word in words:
        all_bits <<= 11
        all_bits += BIP39.index(word)
    num_checksum_bits = num_words // 3
    checksum = all_bits & ((1 << num_checksum_bits) - 1)
    all_bits >>= num_checksum_bits
    num_bytes = (num_words * 11 - num_checksum_bits) // 8
    s = int_to_big_endian(all_bits, num_bytes)
    computed_checksum = sha256(s)[0] >> (8 - num_checksum_bits)
    if checksum != computed_checksum:
        raise ValueError('Checksum is wrong')
    return s


def bytes_to_mnemonic(b, num_bits):
    '''returns a mnemonic given a byte representation'''
    preseed = big_endian_to_int(b)
    # 1 extra bit for checksum is needed per 32 bits
    num_checksum_bits = num_bits // 32
    # the checksum is the sha256's first n bits. At most this is 8
    checksum = sha256(b)[0] >> (8 - num_checksum_bits)
    # we concatenate the checksum to the preseed
    all_bits = (preseed << num_checksum_bits) | checksum
    # now we get the mnemonic passphrase
    mnemonic = []
    # now group into groups of 11 bits
    for _ in range((num_bits + num_checksum_bits) // 11):
        # grab the last 11 bits
        current = all_bits & ((1 << 11) - 1)
        # insert the correct word at the front
        mnemonic.insert(0, BIP39.word(current))
        # shift by 11 bits so we can move to the next set
        all_bits >>= 11
    # return the mnemonic phrase by putting spaces between
    return " ".join(mnemonic)


class WordList:

    @classmethod
    def _load(cls):
        word_file = path.join(path.dirname(__file__), cls.filename)
        with open(word_file, "r") as f:
            cls.words = f.read().split()
        cls.lookup = {}
        for i, word in enumerate(cls.words):
            # add the word's index in the dict lookup
            cls.lookup[word] = i
            # if the word is more than 4 characters, also keep
            #  a lookup of just the first 4 characters
            if len(word) > 4:
                cls.lookup[word[:4]] = i

    @classmethod
    def index(cls, word):
        return cls.lookup[word]

    @classmethod
    def normalize(cls, word):
        return cls.words[cls.lookup[word]]

    @classmethod
    def word(cls, index):
        return cls.words[index]


class BIP39(WordList):
    filename = 'bip39_words.txt'


BIP39._load()
