#!/usr/bin/env python2
from scapy.all import *

# Wireshark uses #define directives and static const value_string data structure for encapsulation commands

class LEShortLenField(FieldLenField):
    """A len field in a 2-byte integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        FieldLenField.__init__(self, name, default, fmt="<H",
                                         count_of=count_of, length_of=length_of)
class LEXIntField(LEIntField):
    """A LEIntField with hexadecimal representation"""

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class LEXShortField(LEShortField):
    """A LEShortField with hexadecimal representation"""

    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class LEXShortEnumField(LEShortEnumField):
    """A ByteEnumField with hexadecimal representation"""

    def __init__(self, name, default, enum):
        LEShortEnumField.__init__(self, name, default, enum)

    def i2repr(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return lhex(self.i2h(pkt, x))

class ENIP_TCP_EncapsulationCommand(Packet):
    """Command field of Encapsulation Packet using TCP"""
#TODO test parsing to handle "Reserved" Encapsulation command fields
    name = "ENIP TCP"
    fields_desc = [
        LEXShortEnumField("Command", None, {             # LE short (2 bytes); Command values taken from dict
            0x0000: "NOP (0x0000)", # TCP only
            # 0x0001: "Reserved for legacy (0x0001 through 0x0003",
            0x0004: "List Services (0x0004)",                    # UDP or TCP
            0x0063: "List Identity (0x0063)",                    # UDP or TCP
            0x0064: "List Interfaces (0x0064)",                  # UDP or TCP
            0x0065: "Register Session (0x0065)",                 # TCP only
            0x0066: "UnRegister Session (0x0066)",               # TCP only
            0x006F: "Send RR Data (0x006F)",                     # TCP only
            0x0070: "Send Unit Data (0x0070)",                   # TCP only
            0x0072: "Indicate Status (0x0072)",                  # TCP only
            0x0073: "Cancel (0x0073)",                           # TCP only
        }),
        LEShortField("Length", None),                   # LE short (2 bytes)
        LEXIntField("Session_Handle", 0),                # LE unsigned int (4 bytes)
#TODO test parsing to handle "Reserved" Status fields
        LEIntEnumField("Status", 0, {                   # LE unsinged int (4 bytes); Status values taken from dict
            0x0000: "Success",
            0x0001: "The sender issued an invalid or unsupported encapsulation command.",
            0x0002: "Insufficient memory resources in the receiver to handle the command.",
            0x0003: "Poorly formed or incorrect data in the data portion of the encapsulation message.",
            0x0064: "An originator used an invalid session handle when sending an encapsulation message to the target.",
            0x0065: "The target received a message of invalid length.",
            0x0069: "Unsupported encapsulation protocol revision.",
        }),
        LongField("Sender_Context", 0),               # LE unsigned long long (8 bytes)
        LEIntField("Options", 0),                       # LE unsigned int (4 bytes)
    ]

    def extract_padding(self, p):
        return p[:self.Length], p[self.Length:]

    def post_build(self, p, pay):
        if self.Length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

# need to determine whether AB supports additional UDP encapsulation commands
# Wireshark dissector supports all commands
# Vol 2 EtherNet/IP spec-- valid UDP: ListServices and ListIdentity only
class ENIP_UDP_EncapsulationCommand(Packet):
    """Command field of Encapsulation Packet UDP"""
    name = "ENIP UDP"
    fields_desc = [
        # LEXShortEnumField("Command", None, {
        LEXShortEnumField("Command", None, {
            0x0004: "List Services (0x0004)",
            0x0063: "List Identity (0x0063)",
        }),
        # LEShortField("Length", None),
        LEShortField("Length", None),
        LEXIntField("Session_Handle", 0),
        LEIntEnumField("Status", 0, {
            0x0000: "Success",
            0x0001: "The sender issued an invalid or unsupported encapsulation command.",
            0x0002: "Insufficient memory resources in the receiver to handle the command.",
            0x0003: "Poorly formed or incorrect data in the data portion of the encapsulation message.",
            0x0064: "An originator used an invalid session handle when sending an encapsulation message to the target.",
            0x0065: "The target received a message of invalid length.",
            0x0069: "Unsupported encapsulation protocol revision.",
        }),
        LELongField("Sender_Context", 0),               # LE unsigned long long (8 bytes)
        LEIntField("Options", 0),                       # LE unsigned int (4 bytes)
    ]

    def extract_padding(self, p):
        return p[:self.Length], p[self.Length:]

    def post_build(self, p, pay):
        if self.Length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay

class ENIP_NOP(Packet):
    """NOP command specific data portion
    Encapsulation Packet:
    Command = 0x00
    Length = data portion (0 to 65511)
    Session Handle ignored
    Status = 0
    Sender Context ignored
    Options = 0"""
    name = "NOP"
    fields_desc = [LELongField("Unused_Data",0)]

class ENIP_ListServices_Data (Packet):
    name = "List Services Data"
    fields_desc = [
        LEShortField("Item_Length", None),
        LEShortField("Encapsulation_Version", 1),
#TODO test parsing for "Reserved" Capability_Flags fields
        LEShortEnumField("Capability_Flags", None, {
            0x0020: "Supports CIP via TCP",
            0x0100: "Supports CIP Class 0 or 1 UDP connections",
        }),
        StrField("Name_of_Service", None, fmt="16s")         # Name field shall allow up to a 16-byte NULL-terminated string
    ]

class ENIP_ListServices(Packet):
    """ENIP_ListServices Reply command specific data portion
    Encapsulation Packet:
    Command = 0x04
    Length = length of data portion
    Session Handle = ignored
    Status = 0
    Sender Context = preserved from ListServices Request
    Options = 0"""
    name = "List Services"
    fields_desc = [
        LEShortLenField("Item_Count", None, count_of="Items"),
        LEShortEnumField("Type_Code", 0x0100, {0x0100: "List Services Response (0x0100)"}),
        PacketListField("Items", [], ENIP_ListServices_Data, count_from=lambda p: p.Item_Count)
    ]

class ENIP_ListIdentity_Reply(Packet):
    """ListIdentity Reply command specific data portion
    Encapsulation packet:
    Command = 0x63
    Length = 0
    Session Handle ignored
    Status = 0
    Sender Context = 0
    Options = 0"""
    name = "List Identity Reply"
    fields_desc = [
        SignedIntField("sin_family", 0),            # big-endian
        ShortField("sin_port", 0),                  # big-endian
        LongField("sin_addr", 0),                   # big-endian
        ShortField("sin_zero", 0),                  # big-endian
        LEShortField("Vendor_ID", 0),
        LEShortField("Device_Type", 0),
        LEShortField("Product_Code", 0),
        LEShortField("Revision", 0),
        LEShortField("Status", 0),                  #TODO veryify WORD data type
        LELongField("Serial_Number", 0),
        StrField("Product_Name", None),             #TODO verify SHORT_STRING data type
        LEShortField("State", 0)
    ]

class ENIP_ListInterfaces(Packet):
    """ENIP_ListInterfaces Reply command specific data portion
    Encapsulation packet:
    Command = 0x64
    Length = 0
    Session Handle ignored
    Status = 0
    Sender Context = 0
    Options = 0"""
    name = "List Interfaces"
    # fields_desc = [
    #     LELongField("Item_Data", None)
    # ]

class ENIP_RegisterSession(Packet):
    """ENIP_RegisterSession command specific data portion
    Encapsulation Packet:
    Command = 0x65
    Length = 4 bytes
    Session Handle = 0          # for Reply, Session Handle returned by target
    Status = 0
    Sender Context = Any sender context         # for Reply, Sender context preserved from Request
    Options = 0"""
    name = "Register Session"
    fields_desc = [
        LEShortField("Protocol_Version", 1),  # Requested protocol version shall be set to 1
#TODO test parsing for "Reserved" Options_Flag fields
        LEShortField("Options_Flag", None)      # Session options shall be set to 0
    ]

class ENIP_SendRRData(Packet):
#     """ENIP_SendRRData command specific data portion
#     Encapsulation Packet:
#     Command = 0x6F
#     Length = length of data portion
#     Session Handle = any sender context       # for Reply, handle preserved from Request
#     Status = 0
#     Sender Context = preserved from ListServices Request
#     Options = 0"""
    name = "Send RR Data"
    fields_desc = [
        LEIntField("Interface_Handle", 0),
        LEShortField("Timeout", 0)
    ]

class ENIP_SendUnitData(Packet):
#     """ENIP_SendUnitData command specific data portion
#     Encapsulation Packet:
#     Command = 0x70
#     Length = length of data portion
#     Session Handle = handle returned by Register Session
#     Status = 0
#     Sender Context = any sender context
#     Options = 0"""
    name = "Send Unit Data"
    fields_desc = [
        LEIntField("Interface_Handle", 0),
        LEShortField("Timeout", 0)
    ]

class ENIP_CPF_Item(Packet):
    """data portion of message, contains 2-byte item count followed by array of address/data items"""
    name = "Common Packet Format Item"
    fields_desc = [
    #TODO test parsing for "Reserved" Item fields
        LEShortEnumField("Address_Data_Item", None, {
    # TODO determine type of commented address items (e.g. address or data)
            0x0000: "Null (0x0000)",                             # item type = address; used for UCMM message
            0x000C: "List Identity Response (0x000C)",           # item type = data
            0x00A1: "Connection-Based (0x00A1)",                 # item type = address
            0x0100: "List Services Response",                    # field defined in Encapuslation header and name "Communications"
            0x8002: "Sequenced Address Item",                    # item type = address
            0x00B1: "Connected Transport Packet (0x00B1)",       # item type = data
            0x00B2: "Unconnected Message (0x00B2)",              # item type = data
            0x8000: "Sockaddr Info (0x8000)",                    # item type = data; originator-to-target
            0x8001: "Sockaddr Info (0x8001)",                    # item type = data; target-to-originator
        }),
        ConditionalField(LEShortField("Address_Length", None), lambda pkt: pkt.Address_Data_Item == 0x0000 or pkt.Address_Data_Item == 0x00A1
                                                                        or pkt.Address_Data_Item == 0x8002),
        ConditionalField(LEXIntField("Connection_Identifier", None), lambda pkt: pkt.Address_Data_Item == 0x00A1),
        ConditionalField(LEShortField("Data_Length", None), lambda pkt: pkt.Address_Data_Item == 0x000C or pkt.Address_Data_Item == 0x00B1 or
                         pkt.Address_Data_Item == 0x00B2), # length in bytes of Item data field

        ConditionalField(LEXShortField("Sequence_Number", None), lambda pkt: pkt.Address_Data_Item == 0x8002 or pkt.Address_Data_Item == 0x00B1),
        # Vol 2 EtherNet/IP Chapter 3 and observed in Wireshark Dissector for 0x00B1
        # The sequence number shall be maintained per connection. Each time an Ethernet device sends a CIP class 1 packet, it shall increment the sequence number for that connection.
        # If the receiving Ethernet device receives a packet whose sequence number is less than the previously received packet, the packet with the smaller sequence number shall be discarded.
        # Duplicate packets shall be accepted and given to the transport layer.
        ConditionalField(LEShortField("Length", None), lambda pkt: pkt.Address_Data_Item == 0x8000 or pkt.Address_Data_Item == 0x8001),
        # LEShortField("Address_Data_Item_Length", None),

        ConditionalField(LEIntField("sin_family", None), lambda pkt: pkt.Address_Data_Item == 0x8000 or pkt.Address_Data_Item == 0x8001),
        ConditionalField(LEIntField("sin_port", None), lambda pkt: pkt.Address_Data_Item == 0x8000 or pkt.Address_Data_Item == 0x8001),
        ConditionalField(LELongField("sin_addr", None), lambda pkt: pkt.Address_Data_Item == 0x8000 or pkt.Address_Data_Item == 0x8001),
        ConditionalField(LEShortField("sin_zero", None), lambda pkt: pkt.Address_Data_Item == 0x8000 or pkt.Address_Data_Item == 0x8001)
    ]

    def extract_padding(self, p):
        return "", p
    # def extract_padding(self, p):
    #     return p[:self.Data_Length], p[self.Data_Length:]
    #
    # def post_build(self, p, pay):
    #     if self.Length is None and pay:
    #         l = len(pay)
    #         p = p[:8] + struct.pack("<H", l) + p[10:]
    #     return p + pay

class ENIP_CommonPacketFormat(Packet):
    """data portion of message, contains 2-byte item count followed by array of address/data items"""
    fields_desc = [
        LEShortLenField("Item_Count", None, count_of="Items"),
        PacketListField("Items", [], ENIP_CPF_Item, count_from=lambda p: p.Item_Count)
    ]


bind_layers(TCP, ENIP_TCP_EncapsulationCommand, dport=44818)    # bind_layers to link layers
bind_layers(TCP, ENIP_TCP_EncapsulationCommand, sport=44818)
bind_layers(UDP, ENIP_UDP_EncapsulationCommand, dport=44818)
bind_layers(UDP, ENIP_UDP_EncapsulationCommand, sport=44818)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_NOP, Command=0x0000)
bind_layers(ENIP_UDP_EncapsulationCommand, ENIP_NOP, Command=0x0000)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_ListServices, Command=0x0004)
# bind_layers(ENIP_UDP_EncapsulationCommand, ENIP_ListServices, Command=0x0004)
# bind_layers(ENIP_ListServices, ENIP_ListServices_Data, Type_Code=0x0100)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_ListIdentity_Reply, Command=0x0063)
bind_layers(ENIP_UDP_EncapsulationCommand, ENIP_ListIdentity_Reply, Command=0x0063)
bind_layers(ENIP_ListIdentity_Reply, ENIP_CommonPacketFormat)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_ListInterfaces, Command=0x0064)
bind_layers(ENIP_ListInterfaces, ENIP_CommonPacketFormat)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_RegisterSession, Command=0x0065)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_SendRRData, Command=0x006F)
bind_layers(ENIP_SendRRData, ENIP_CommonPacketFormat)

bind_layers(ENIP_TCP_EncapsulationCommand, ENIP_SendUnitData, Command=0x0070)
bind_layers(ENIP_SendUnitData, ENIP_CommonPacketFormat)



# Test dissector
if __name__ == '__main__':

    # pkt = Ether(src='00:1d:9c:ca:cb:1b', dst='90:e2:ba:18:fc:2e')     # No. 18 Frame SC-GoOnline-TurnKnob-160304.pcapng
    # pkt /= IP(src='10.1.100.2', dst='10.1.30.1')
    # pkt /= TCP(sport=44818, dport=62330)
    # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0004, Session_Handle=00000000)
    # pkt /= ENIP_ListServices(Items=[ENIP_ListServices_Data(Item_Length=20, Capability_Flags=0x0020, Name_of_Service="Communications\0\0")])
    # test = str(pkt)
    # pkt = Ether(test)
    #
    # wrpcap("temp.pcap",pkt)     # builds pcap
    #
    # pkt.show()

    # assert pkt[ENIP_TCP_EncapsulationCommand].Command == 0x0004
    # assert pkt[ENIP_TCP_EncapsulationCommand].Session_Handle == 0
    # assert pkt[ENIP_TCP_EncapsulationCommand].Status == 0
    # assert pkt[ENIP_TCP_EncapsulationCommand].Length == 26
    # assert pkt[ENIP_ListServices].Type_Code == 0x0100
    # assert pkt[ENIP_ListServices_Data].Capability_Flags == 0x0020
    # assert pkt[ENIP_ListServices_Data].Name_of_Service == "Communications"

    # Packet to test PLC

    # pkt = Ether(dst='ff:ff:ff:ff:ff:ff')     # ENIP UDP ListIdentity Packet
    #
    # pkt /= IP(src="192.168.0.62", dst='255.255.255.255')
    #
    # pkt /= UDP(sport=51604, dport=44818)
    #
    #
    # pkt /= ENIP_UDP_EncapsulationCommand(Command=77)
    #
    # sendp(pkt)
    #
    # wrpcap("temp.pcap",pkt)     # builds pcap
    #
    # pkt.show()

    pkt = IP(dst="192.168.0.59",)
    pkt /= TCP(dport=44818)
    pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0004)

    #sendp(pkt)

    # mystream.send(pkt)
    # wrpcap("temp.pcap",pkt)     # builds pcap

    pkt.show()

