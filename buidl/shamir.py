import hmac

from hashlib import pbkdf2_hmac
from os import path
from secrets import randbits

from buidl.helper import big_endian_to_int, int_to_big_endian
from buidl.mnemonic import WordList, bytes_to_mnemonic, mnemonic_to_bytes


def rs1024_polymod(values):
    GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]
    chk = 1
    for v in values:
        b = (chk >> 20)
        chk = (chk & 0xfffff) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def rs1024_verify_checksum(cs, data):
    return rs1024_polymod([x for x in cs] + data) == 1


def rs1024_create_checksum(cs, data):
    values = [x for x in cs] + data
    polymod = rs1024_polymod(values + [0,0,0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]


class Share:

    def __init__(self, share_bit_length, id, exponent, group_index, group_threshold, group_count, member_index, member_threshold, value):
        self.share_bit_length = share_bit_length
        self.id = id
        self.exponent = exponent
        self.group_index = group_index
        self.group_threshold = group_threshold
        self.group_count = group_count
        self.member_index = member_index
        self.member_threshold = member_threshold
        self.value = value
        self.bytes = int_to_big_endian(value, share_bit_length // 8)

    def __repr__(self):
        return f'id: {self.id}\nexponent: {self.exponent}\ngi: {self.group_index}\ngroup: {self.group_threshold} of {self.group_count}\nmi: {self.member_index}\nmt: {self.member_threshold}\nshare: {self.value}'

    @classmethod
    def parse(cls, mnemonic):
        # convert mnemonic into bits
        words = mnemonic.split()
        indices = [SLIP39.index(word) for word in words]
        if not rs1024_verify_checksum(b'shamir', indices):
            raise ValueError('Invalid Checksum')
        id = (indices[0] << 5) | (indices[1] >> 5)
        exponent = indices[1] & 31
        group_index = indices[2] >> 6
        group_threshold = ((indices[2] >> 2) & 15) + 1
        group_count = (((indices[2] & 3) << 2) | (indices[3] >> 8)) + 1
        member_index = (indices[3] << 4) & 15
        member_threshold = (indices[3] & 15) + 1
        value = 0
        for index in indices[4:-3]:
            value = (value << 10) | index
        share_bit_length = (len(indices) - 7) * 10 // 16 * 16
        if value >> share_bit_length != 0:
            raise SyntaxError('Share not 0-padded properly')
        return cls(share_bit_length, id, exponent, group_index, group_threshold, group_count, member_index, member_threshold, value)

    def mnemonic(self):
        all_bits = (self.id << 5) | self.exponent
        all_bits <<= 4
        all_bits |= self.group_index
        all_bits <<= 4
        all_bits |= self.group_threshold - 1
        all_bits <<= 4
        all_bits |= self.group_count - 1
        all_bits <<= 4
        all_bits |= self.member_index
        all_bits <<= 4
        all_bits |= self.member_threshold - 1
        padding = 10 - self.share_bit_length % 10
        all_bits <<= padding + self.share_bit_length
        all_bits |= self.value
        num_words = 4 + (padding + self.share_bit_length) // 10
        indices = [(all_bits >> 10 * (num_words - i - 1)) & 1023 for i in range(num_words)]
        checksum = rs1024_create_checksum(b'shamir', indices)
        return ' '.join([SLIP39.word(index) for index in indices + checksum])


class ShareSet:
    exp = [1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246]
    log2 = [0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7]

    def __init__(self, shares):
        self.shares = shares
        if len(shares) > 1:
            # check that the identifiers are the same
            ids = {s.id for s in shares}
            if len(ids) != 1:
                raise TypeError('Shares are from different secrets')
            # check that the exponents are the same
            exponents = {s.exponent for s in shares}
            if len(exponents) != 1:
                raise TypeError('Shares should have the same exponent')
            # check that the k-of-n is the same
            k = {s.group_threshold for s in shares}
            if len(k) != 1:
                raise ValueError('K of K-of-N should be the same')
            n = {s.group_count for s in shares}
            if len(k) != 1:
                raise ValueError('N of K-of-N should be the same')
            # check that the share lengths are the same
            lengths = {s.share_bit_length for s in shares}
            if len(lengths) != 1:
                raise ValueError('all shares should have the same length')
            # check that the x coordinates unique
            xs = {s.group_index for s in shares}
            if len(xs) != len(shares):
                raise ValueError('Share indices should be unique')
        self.id = shares[0].id
        self.salt = b'shamir' + int_to_big_endian(self.id, 2)
        self.exponent = shares[0].exponent
        self.group_threshold = shares[0].group_threshold
        self.group_count = shares[0].group_count
        self.share_bit_length = shares[0].share_bit_length

    def decrypt(self, encrypted, passphrase=b''):
        if len(encrypted) % 2:
            raise ValueError('encrypted data should be an even number of bytes')
        else:
            half = len(encrypted) // 2
        l = encrypted[:half]
        r = encrypted[half:]
        for i in (b'\x03', b'\x02',b'\x01',b'\x00'):
            f = pbkdf2_hmac(
                'sha256',
                i + passphrase,
                self.salt + r,
                2500 << self.exponent, # 10000 << self.exponent // 4
                dklen=half,
            )
            l, r = r, bytes(x ^ y for x, y in zip(l, f))
        return r + l

    @classmethod
    def encrypt(cls, payload, id, exponent, passphrase=b''):
        if len(payload) % 2:
            raise ValueError('payload should be an even number of bytes')
        else:
            half = len(payload) // 2
        l = payload[:half]
        r = payload[half:]
        salt = b'shamir' + int_to_big_endian(id, 2)
        for i in (b'\x00', b'\x01',b'\x02',b'\x03'):
            f = pbkdf2_hmac(
                'sha256',
                i + passphrase,
                salt + r,
                2500 << exponent, # 10000 << exponent // 4
                dklen=half,
            )
            l, r = r, bytes(x ^ y for x, y in zip(l, f))
        return r + l

    def encrypt_set(self, payload, passphrase=b''):
        return self.encrypt(payload, self.id, self.exponent, passphrase)

    @classmethod
    def interpolate(cls, x, share_data):
        '''Gets the y value at a particular x'''
        # we're using the lagrange formula
        # https://github.com/satoshilabs/slips/blob/master/slip-0039/lagrange.png
        # the numerator of the multiplication part is what we're pre-computing
        # (x - x_i) 0<=i<=m where x_i is each x in the share
        # we don't store this, but the log of this
        # and exponentiate later
        log_product = sum(cls.log2[share_x ^ x] for share_x, _ in share_data)
        # the y value that we want is stored in result
        result = bytes(len(share_data[0][1]))
        for share_x, share_bytes in share_data:
            # we have to subtract the current x - x_i since
            # the formula is for j where j != i
            log_numerator = log_product - cls.log2[share_x ^ x]
            # the denominator we can just sum because we cheated and made
            # log(0) = 0 which will happen when i = j
            log_denominator = sum(cls.log2[share_x ^ other_x] for other_x, _ in share_data)
            log = (log_numerator - log_denominator) % 255
            result = bytes(
                c ^ (
                    cls.exp[(cls.log2[y] + log) % 255] if y > 0 else 0
                ) for y, c in zip(share_bytes, result))
        return result

    @classmethod
    def digest(self, random, shared_secret):
        return hmac.new(random, shared_secret, 'sha256').digest()[:4]

    def recover(self, passphrase=b''):
        if self.group_threshold == 1:
            return self.decrypt(self.shares[0].bytes, passphrase)
        share_data = [(share.group_index, share.bytes) for share in self.shares]
        shared_secret = self.interpolate(255, share_data)
        digest_share = self.interpolate(254, share_data)
        digest = digest_share[:4]
        random = digest_share[4:]
        if digest != self.digest(random, shared_secret):
            raise ValueError('Digest does not match secret')
        return self.decrypt(shared_secret, passphrase)

    @classmethod
    def split_secret(cls, secret, k, n):
        '''Split secret into k-of-n shares'''
        if k > n:
            raise ValueError('K is too big, K <= N')
        num_bytes = len(secret)
        if num_bytes not in (16, 32):
            raise ValueError('secret should be 128 bits or 256 bits')
        if k == 1:
            return [(0, secret)]
        else:
            random = bytes(randbits(8) for _ in range(num_bytes - 4))
            digest = cls.digest(random, secret)
            digest_share = digest + random
            share_data = [(i, bytes(randbits(8) for _ in range(num_bytes))) for i in range(k-2)]
            more_data = share_data.copy()
            share_data.append((254, digest_share))
            share_data.append((255, secret))
            for i in range(k-2, n):
                more_data.append((i, cls.interpolate(i, share_data)))
        return more_data

    @classmethod
    def generate_shares(cls, mnemonic, k, n, passphrase=b'', exponent=0):
        '''Takes a BIP39 mnemonic along with k, n, passphrase and exponent.
        Returns a list of SLIP39 mnemonics, any k of of which, along with the passphrase, recover the secret'''
        # convert mnemonic to a shared secret
        secret = mnemonic_to_bytes(mnemonic)
        num_bits = len(secret) * 8
        if num_bits not in (128, 256):
            raise ValueError('mnemonic must be 12 or 24 words')
        # generate id
        id = randbits(15)
        # encrypt secret with passphrase
        encrypted = cls.encrypt(secret, id, exponent, passphrase)
        # split encrypted payload and create shares
        shares = []
        data = cls.split_secret(encrypted, k, n)
        group_count = len(data)
        for group_index, share_bytes in data:
            shares.append(Share(num_bits, id, exponent, group_index, k, n, 0, 1, big_endian_to_int(share_bytes)).mnemonic())
        return shares

    @classmethod
    def recover_mnemonic(cls, share_mnemonics, passphrase=b''):
        '''Recovers the BIP39 mnemonic from a bunch of SLIP39 mnemonics'''
        shares = [Share.parse(m) for m in share_mnemonics]
        share_set = ShareSet(shares)
        secret = share_set.recover(passphrase)
        return bytes_to_mnemonic(secret, share_set.share_bit_length)


class SLIP39(WordList):
    filename = 'slip39_words.txt'


SLIP39._load()
