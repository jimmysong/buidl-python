from unittest import TestCase

from buidl.helper import int_to_big_endian
from buidl.mnemonic import secure_mnemonic
from buidl.shamir import Share, ShareSet


class ShamirTest(TestCase):

    def test_share_errors(self):
        mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
        with self.assertRaises(ValueError):
            share = Share.parse(mnemonic)

        mnemonic = "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
        with self.assertRaises(SyntaxError):
            share = Share.parse(mnemonic)

    def test_share(self):
        mnemonic = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
        share = Share.parse(mnemonic)
        self.assertEqual(share.mnemonic(), mnemonic)
        expected = 'bb54aac4b89dc868ba37d9cc21b2cece'
        share_set = ShareSet([share])
        self.assertEqual(share_set.recover(b'TREZOR').hex(), expected)
        self.assertEqual(share_set.encrypt_set(bytes.fromhex(expected), b'TREZOR'), share.bytes)
        mnemonic = "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
        expected = '989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92'
        share = Share.parse(mnemonic)
        self.assertEqual(share.mnemonic(), mnemonic)
        share_set = ShareSet([share])
        self.assertEqual(share_set.recover(b'TREZOR').hex(), expected)
        self.assertEqual(share_set.encrypt_set(bytes.fromhex(expected), b'TREZOR'), share.bytes)


    def test_recover(self):
        shares = [

            Share.parse("eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"),
            Share.parse("eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market"),
        ]
        share_set = ShareSet(shares)
        expected = '7c3397a292a5941682d7a4ae2d898d11'
        self.assertEqual(share_set.recover(b'TREZOR').hex(), expected)
        shares = [
            Share.parse("wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"),
            Share.parse("wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs"),
        ]
        share_set = ShareSet(shares)
        expected = "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b"
        self.assertEqual(share_set.recover(b'TREZOR').hex(), expected)

    def test_split(self):
        secret = bytes.fromhex('7c3397a292a5941682d7a4ae2d898d11')
        for k, n in ((2,3),(3,5),(5,5),(9,9),(13,15)):
            share_data = ShareSet.split_secret(secret, k, n)
            self.assertEqual(secret, ShareSet.interpolate(255, share_data[:k]))

    def test_generate(self):
        # bip39 mnemonic
        for num_bits in (128, 256):
            mnemonic = secure_mnemonic(num_bits)
            passphrase = b'buidltest'
            for k, n in ((2,3),(3,5),(5,5),(9,9),(13,15),(2,8)):
                shares = ShareSet.generate_shares(mnemonic, k, n, passphrase=passphrase, exponent=2)
                self.assertEqual(ShareSet.recover_mnemonic(shares[:k], passphrase), mnemonic)
