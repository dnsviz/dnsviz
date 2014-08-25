import socket

class IPAddr(str):
    def __new__(cls, string):
        if ':' in string:
            af = socket.AF_INET6
        else:
            af = socket.AF_INET
        ipaddr_bytes = socket.inet_pton(af, string)
        obj = super(IPAddr, cls).__new__(cls, socket.inet_ntop(af, ipaddr_bytes))
        obj._ipaddr_bytes = ipaddr_bytes
        return obj

    def __lt__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) < 0

    def __le__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) <= 0

    def __eq__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) == 0

    def __ne__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) != 0

    def __gt__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) > 0

    def __ge__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        return cmp(self, other) >= 0

    def __cmp__(self, other):
        if self.__class__ != other.__class__:
            raise TypeError('Cannot compare IPAddr to non-IPAddr!')
        if len(self._ipaddr_bytes) < len(other._ipaddr_bytes):
            return -1
        elif len(self._ipaddr_bytes) > len(other._ipaddr_bytes):
            return 1
        else:
            return cmp(self._ipaddr_bytes, other._ipaddr_bytes)

    def __hash__(self):
        return hash(self._ipaddr_bytes)
