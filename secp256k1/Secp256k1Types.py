from typing import NewType, NamedTuple, Union


class PointNTuple(NamedTuple):
    x: Union[int, None]
    y: Union[int, None]


class Point(PointNTuple):
    def isNone(self) -> bool:
        return self.x is None or self.y is None


PrivateKey = NewType('PrivateKey', int)
PublicKey = NewType('PublicKey', Point)
