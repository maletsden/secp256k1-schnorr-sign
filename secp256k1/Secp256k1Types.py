from __future__ import annotations

from typing import NewType, NamedTuple, Union, TypedDict


class PointNTuple(NamedTuple):
    x: Union[int, None]
    y: Union[int, None]


class Point(PointNTuple):
    def isNone(self) -> bool:
        return self.x is None or self.y is None

    def toBytes(self) -> bytes:
        return self.x.to_bytes(32, byteorder="big") + self.y.to_bytes(32, byteorder="big")


PrivateKey = NewType('PrivateKey', int)
PublicKey = NewType('PublicKey', Point)
Signature = NewType('Signature', int)


class SignatureData(TypedDict):
    signature: Signature
    public_nonce: PublicKey
    public_key: PublicKey

