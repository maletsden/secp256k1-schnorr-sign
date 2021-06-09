import unittest
import sys

sys.path.append("../secp256k1")

from secp256k1.Secp256k1 import Secp256k1
from secp256k1.Secp256k1Types import PrivateKey, PublicKey


class Secp256k1TestCase(unittest.TestCase):
    def test_getPublicKey(self):
        private_key: PrivateKey = PrivateKey(0x0000000000000000000000000000000000000000000000000000000000000001)
        public_key: PublicKey = Secp256k1.getPublicKey(private_key)

        expected_public_key: PublicKey = PublicKey(Secp256k1.G)

        self.assertEqual(public_key, expected_public_key, "Public key is wrong")

        print("Test1. PublicKey successfully generated.")


if __name__ == '__main__':
    unittest.main()
