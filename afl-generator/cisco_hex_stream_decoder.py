import binascii
from scapy.all import *
import cisco_dissector

hexstream = binascii.unhexlify(
    '90e2ba18fc2e001d9ccacb1b08004500004400b540004006a3fa0a0164020a011e01af12f37a833318dabaef3ea75018100065690000650004000001020f0000000000000000000000000000000001000000')
pkt = Ether(hexstream)
pkt.show()