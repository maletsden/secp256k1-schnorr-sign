from typing import Final

from Secp256k1Types import PrivateKey, PublicKey, Point


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
                p2 = Secp256k1.point_add(p2, p)
            p = Secp256k1.point_add(p, p)

        return p2

    @staticmethod
    def point_add(p1: Point, p2: Point) -> Point:
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


