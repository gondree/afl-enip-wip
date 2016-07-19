import logging
import sys

from cip import CIP, CIP_Path
import plc

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

# Connect to PLC
client = plc.PLCClient('192.168.1.10')
if not client.connected:
    sys.exit(1)
print("Established session {}".format(client.session_id))

if not client.forward_open():
    sys.exit(1)

# Send a CIP ReadTag request
cippkt = CIP(service=0x4c, path=CIP_Path.make_str("HMI_LIT101"))
client.send_unit_cip(cippkt)

# Receive the response and show it
resppkt = client.recv_enippkt()
resppkt[CIP].show()

# Close the connection
client.forward_close()