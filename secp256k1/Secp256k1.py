import hashlib
from typing import Final
import random

from Secp256k1Types import PrivateKey, PublicKey, Point, Signature, SignatureData


class Secp256k1:
    """
    Equation: y**2 = x**3 + 7
    """

    p: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    G: Final[Point] = Point(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    )

    @staticmethod
    def getPublicKey(private_key: PrivateKey) -> PublicKey:
        point: Point = Secp256k1.pointMultiply(Secp256k1.G, private_key)
        return PublicKey(point)

    @staticmethod
    def pointMultiply(p: Point, k: PrivateKey) -> Point:
        p2: Point = Point(None, None)
        for i in range(256):
            if (k >> i) & 1:
                p2 = Secp256k1.pointAdd(p2, p)
            p = Secp256k1.pointAdd(p, p)

        return p2

    @staticmethod
    def pointAdd(p1: Point, p2: Point) -> Point:
        # corner cases
        if p1.isNone():
            return p2

        if p2.isNone():
            return p1

        # check symmetry
        if p1.x == p2.x and p1.y != p2.y:
            return Point(None, None)

        # if the same point - find tangent to a curve
        if p1 == p2:
            s: int = (3 * p1.x * p1.x * pow(p1.y << 1, Secp256k1.p - 2, Secp256k1.p)) % Secp256k1.p
        else:
            s: int = ((p2.y - p1.y) * pow(p2.x - p1.x, Secp256k1.p - 2, Secp256k1.p)) % Secp256k1.p

        x3: int = (s * s - p1.x - p2.x) % Secp256k1.p
        y3: int = (s * (p1.x - x3) - p1.y) % Secp256k1.p

        return Point(x3, y3)

    @staticmethod
    def sha256(b: bytes) -> int:
        return int.from_bytes(hashlib.sha256(b).digest(), byteorder="big")

    @staticmethod
    def getChallenge(p: PublicKey, r: PublicKey, m: str) -> int:
        return Secp256k1.sha256(p.toBytes() + r.toBytes() + bytes(m, 'utf-8'))

    @staticmethod
    def jacobi(x: int) -> int:
        return pow(x, (Secp256k1.p - 1) >> 1, Secp256k1.p)

    @staticmethod
    def signMessage(msg: str, private_key: PrivateKey) -> SignatureData:
        nonce: PrivateKey = PrivateKey(random.getrandbits(256))
        pubic_nonce: PublicKey = Secp256k1.getPublicKey(nonce)

        pubic_key: PublicKey = Secp256k1.getPublicKey(private_key)

        e: int = Secp256k1.sha256(
            pubic_nonce.toBytes() + pubic_key.toBytes() + bytes(msg, "utf-8")
        )

        signature: Signature = Signature((nonce + e * private_key) % Secp256k1.n)

        return SignatureData(
            signature=signature,
            public_key=pubic_key,
            public_nonce=pubic_nonce
        )

    @staticmethod
    def isOnCurve(point: Point) -> bool:
        return (pow(point.y, 2, Secp256k1.p) - pow(point.x, 3, Secp256k1.p)) % Secp256k1.p == 7

    @staticmethod
    def verifySignature(msg: str, signature_data: SignatureData) -> bool:
        signature: Signature = signature_data['signature']
        public_key: PublicKey = signature_data['public_key']
        public_nonce: PublicKey = signature_data['public_nonce']

        if not Secp256k1.isOnCurve(public_key):
            return False

        if public_nonce.x >= Secp256k1.p or signature >= Secp256k1.n:
            return False

        e: int = Secp256k1.sha256(
            public_nonce.toBytes() + public_key.toBytes() + bytes(msg, "utf-8")
        )

        sg: PublicKey = Secp256k1.getPublicKey(PrivateKey(signature))

        check: Point = Secp256k1.pointAdd(
            public_nonce,
            Secp256k1.pointMultiply(public_key, PrivateKey(e))
        )

        return sg == check
