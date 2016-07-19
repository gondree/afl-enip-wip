from scapy.all import *
import binascii
from cisco_enip_dissector import *
from cisco_cip_dissector import *
from optparse import OptionParser
import socket

def fuzzer(packetList):
    for pkt in packetList:

        sendp(pkt)

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(pkt)

def enip_tcp(numofpackets, plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes EtherNet/IP TCP Command Field
    """

    plcPort = int(plc_port)

    #socket.create_connection((plc_addr, plcPort))

    packetList = list()
    i = 0
    while i < numofpackets:

        socket.create_connection((plc_addr, plcPort))

        enipTCPencapCommand = ENIP_TCP_EncapsulationCommand()
        enipTCPencapCommand.Command = random.randint(0, 65535)
        enipTCPencapCommand.Length = 0
        enipTCPencapCommand.Session_Handle = 0
        enipTCPencapCommand.Status = 0
        enipTCPencapCommand.Sender_Context = 0
        enipTCPencapCommand.Options = 0

        packetList.append(Ether(dst='00:1d:9c:a1:28:4c') / IP(src="192.168.0.62", dst=plc_addr) / TCP(dport=plcPort) / enipTCPencapCommand)
        #packetList.append(enipTCPencapCommand)

        i = i + 1

    return packetList

def enip_udp(numofpackets):
    """
    Fuzzes EtherNet/IP UDP Command Field
    """
    packetList = list()
    i = 0
    while i < numofpackets:
        enipUDPencapCommand = ENIP_UDP_EncapsulationCommand()
        enipUDPencapCommand.Command = random.randint(0, 65535)
        enipUDPencapCommand.Length = 0
        enipUDPencapCommand.Session_Handle = 0
        enipUDPencapCommand.Status = 0
        enipUDPencapCommand.Sender_Context = 0
        enipUDPencapCommand.Options = 0

        packetList.append(Ether(dst='ff:ff:ff:ff:ff:ff') / IP(src="192.168.0.62", dst='255.255.255.255') /
                          UDP(sport=51604, dport=44818) / enipUDPencapCommand)

        i = i + 1

    return packetList

def cip_multiservicepacket(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP Common Service Multiple Service Packet
    """

    #TODO make this pretty: For fuzzing

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))
    # open an EtherNet/IP session
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle

    numofpackets = 10
    i = 0
    while i < numofpackets:
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=session_id)
        enippkt /= ENIP_SendUnitData()
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=enip_connid),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=10, Sequence_Number=sequence)])
        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0A, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
                                                                                     CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
        enippkt /= CIP_Multiple_Service_Packet(Number_of_Services=random.randint(0, 65535))
        # enippkt /= fuzz(CIP_Multiple_Service_Packet())

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))

        pktbytes = sock.recv(4096)
        reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
        session_id = reply_pkt.Session_Handle

        i = i + 1

    print i

# def recv_enippkt(self):
#         """Receive an ENIP packet from the TCP socket"""
#         if self.sock is None:
#             return
#         pktbytes = self.sock.recv(2000)
#         pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
#         return pkt

def cip_nop(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP NOP
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle
    sender_cntxt= reply_pkt.Sender_Context

    # Create CM Packet
    #
    # cmpkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
    # cmpkt /= ENIP_SendRRData(Timeout=20)
    # cmpkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=46)])
    #
    # cmpkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
    #                                                                          CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    # cmpkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0x9B, O_T_Network_Connection_ID=0x80000002,
    #     T_O_Network_Connection_ID=0x80FE0001, Connection_Serial_Number=0x0002, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x05600AF3,
    #     Connection_Timeout_Multiplier=0x02, Reserved=0x000200, O_T_RPI=0x001312D0, O_T_Network_Connection_Parameters=0x4312, T_O_RPI=0x001312D0, T_O_Network_Connection_Parameters=0x4312,
    #     Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
    #     Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
    #            CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
    #
    # sock.send(str(cmpkt))
    #
    # pktbytes3 = sock.recv(4096)
    # reply_pkt = ENIP_CPF_Item(pktbytes3)
    # enip_connid = reply_pkt.Connection_Identifier
    sequence += 1

    numofpackets = 255
    i = 0
    while i < numofpackets:

        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
        enippkt /= ENIP_SendRRData()

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=2)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17)

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x78609D9F),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=6, Sequence_Number=sequence)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Request_Path_Size=1, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=random.randint(0, 255))])

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=4)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Request_Path_Size=1, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02)])

        #
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=6)])
        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=i),
                                                                                     CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])


        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=6)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=random.randint(0,255)),
        #                                                                              CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x78609D9F),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=8, Sequence_Number=sequence)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
        #                                                                              CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])



        # enippkt = ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=session_id, Sender_Context=sender_cntxt)
        # enippkt /= ENIP_SendUnitData()

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=2)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17)

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x78609D9F),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=6, Sequence_Number=sequence)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Request_Path_Size=1, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=random.randint(0, 255))])

        # enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x78609D9F),
        #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=6, Sequence_Number=sequence)])
        # enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Request_Path_Size=1, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02)])



        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet
        time.sleep(1)
        # print "sent"
        # pktbytes = sock.recv(4096)
        # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
        # session_id = reply_pkt.Session_Handle
        # print i
        i = i + 1
        print i

    print i

def cip_get_attribute_list(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP Get Attribute List
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle
    sender_cntxt= reply_pkt.Sender_Context
    # reply_pkt = ENIP_CPF_Item(pktbytes)
    # enip_connid = reply_pkt.Connection_Identifier

    numofpackets = 1000000
    i = 0
    while i < numofpackets:
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=session_id)
        enippkt /= ENIP_SendUnitData()
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000, Address_Length=0, Connection_Identifier=enip_connid),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=20, Sequence_Number=sequence)])
        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x03, Request_Path_Size=3, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x6B),
                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x1, Sixteen_bit_Instance=sequence)])
        enippkt /= CIP_Get_Attribute_List_Request(Attributes=[1,2])

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet
        # time.sleep(1)

        pktbytes = sock.recv(0)
        reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
        session_id = reply_pkt.Session_Handle

        i = i + 1

    print i

def cip_read_tag_service(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP Read Tag Service
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle
    sender_cntxt= reply_pkt.Sender_Context
    # reply_pkt = ENIP_CPF_Item(pktbytes)
    # enip_connid = reply_pkt.Connection_Identifier

    numofpackets = 1000000
    i = 0
    while i < numofpackets:
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=session_id)
        enippkt /= ENIP_SendUnitData()
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000, Address_Length=0, Connection_Identifier=enip_connid),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=10, Sequence_Number=sequence)])
        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4C, Request_Path_Size=3, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x6B),
                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x1, Sixteen_bit_Instance=0xF68F)])
        enippkt /= CIP_Read_Tag_Service_Request(Number_of_elements=1)

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet
        time.sleep(1)

        # pktbytes = sock.recv(0)
        # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
        # session_id = reply_pkt.Session_Handle

        i = i + 1

    print i

# def recv_enippkt(self):
#         """Receive an ENIP packet from the TCP socket"""
#         if self.sock is None:
#             return
#         pktbytes = self.sock.recv(2000)
#         pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
#         return pkt

def cip_get_attribute_single(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP Get Attribute Single
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle
    sender_cntxt= reply_pkt.Sender_Context

    # Create CM Packet
    #
    cmpkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
    cmpkt /= ENIP_SendRRData(Timeout=20)
    cmpkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=46)])

    cmpkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
                                                                             CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    cmpkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0x9B, O_T_Network_Connection_ID=0x80000002,
        T_O_Network_Connection_ID=0x80FE0001, Connection_Serial_Number=0x0002, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x05600AF3,
        Connection_Timeout_Multiplier=0x02, Reserved=0x000200, O_T_RPI=0x001312D0, O_T_Network_Connection_Parameters=0x4312, T_O_RPI=0x001312D0, T_O_Network_Connection_Parameters=0x4312,
        Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
        Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

    sock.send(str(cmpkt))

    numofpackets = 1000000
    i = 0
    while i < numofpackets:
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=session_id)
        enippkt /= ENIP_SendUnitData()
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x78609D9F),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=10, Sequence_Number=sequence)])
        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0E, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x04),
                                                                                      CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        enippkt /= CIP_Get_Attribute_Single_Request(Attribute_Identifier=0x03)

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet

        pktbytes = sock.recv(4096)
        reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
        session_id = reply_pkt.Session_Handle

        i = i + 1

    print i

def cip_cm_forward_open(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP CM Forward Open
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet

    # open an EtherNet/IP session                                                # comment out to build packet
    # session_id = 0
    enip_connid = 0
    sender_cntxt = 0
    sequence = 1

    #FIXME this was part of observed "handshake"; this probably can be removed
    # listservicespkt = ENIP_TCP_EncapsulationCommand() / ENIP_ListServices()
    # sock.send(str(listservicespkt))
    # pktbytes = sock.recv(4096)
    #
    # listinterfacespkt = ENIP_TCP_EncapsulationCommand() / ENIP_ListInterfaces()
    # sock.send(str(listinterfacespkt))
    # pktbytes = sock.recv(4096)

    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    # srcport = reply_pkt.dst
    session_id = reply_pkt.Session_Handle
    sender_cntxt = reply_pkt.Sender_Context

    # send Execute PCCC Service request
    #FIXME this may not be needed

    # servicepkt = Ether(src='08:00:27:EC:11:8C', dst='00:1D:9C:A1:28:4C')
    # servicepkt /= IP(src='192.168.0.62', dst='192.168.0.59')
    # servicepkt /= TCP(src=srcport, dport=44818)
    servicepkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
    servicepkt /= ENIP_SendRRData(Timeout=20)
    servicepkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=18)])
    servicepkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4B, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x67),
                                                                           CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    # servicepkt /= CIP_Execute_PCCC_Service(Object_Specific_Data='\x07\x4D\x00\xF3\x0A\x60\x05\x06\x00\x70\x03\x03')
    servicepkt /= Raw(load="\x07\x4D\x00\xF3\x0A\x60\x05\x06\x00\x70\x03\x03")

    pktdump = PcapWriter("temp2.pcap", append=True, sync=True) # writes packets to pcap
    pktdump.write(servicepkt)

    sock.send(str(servicepkt))


    pktbytes2 = sock.recv(4096)

    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes2)
    session_id = reply_pkt.Session_Handle
    sender_cntxt = reply_pkt.Sender_Context

    numofpackets = 1000000
    i = 0
    while i < numofpackets:

        # enippkt = Ether(src='08:00:27:EC:11:8C', dst='00:1D:9C:A1:28:4C')
        # enippkt /= IP(src='192.168.0.62', dst='192.168.0.59')
        # enippkt /= TCP(src=srcport, dport=44818)
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
        enippkt /= ENIP_SendRRData(Timeout=20)
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=46)])

        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
                                                                                  CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        enippkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0x9B, O_T_Network_Connection_ID=0x80000002,
        T_O_Network_Connection_ID=0x80FE0001, Connection_Serial_Number=0x0002, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x05600AF3,
        Connection_Timeout_Multiplier=0x02, Reserved=0x000200, O_T_RPI=0x001312D0, O_T_Network_Connection_Parameters=0x4312, T_O_RPI=0x001312D0, T_O_Network_Connection_Parameters=0x4312,
        Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
        Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet

        # pktbytes3 = sock.recv(4096)
        # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes3)
        # session_id = reply_pkt.Session_Handle
        # sender_cntxt = reply_pkt.Sender_Context

        i = i + 1

    print i

def cip_cm_forward_close(plc_addr="192.168.0.59", plc_port="44818"):
    """
    Fuzzes CIP CM Forward Close
    """

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet

    # open an EtherNet/IP session                                                # comment out to build packet
    # session_id = 0
    enip_connid = 0
    sender_cntxt = 0
    sequence = 1

    # listservicespkt = ENIP_TCP_EncapsulationCommand() / ENIP_ListServices()
    # sock.send(str(listservicespkt))
    # pktbytes = sock.recv(4096)
    #
    # listinterfacespkt = ENIP_TCP_EncapsulationCommand() / ENIP_ListInterfaces()
    # sock.send(str(listinterfacespkt))
    # pktbytes = sock.recv(4096)

    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    # srcport = reply_pkt.dst
    session_id = reply_pkt.Session_Handle
    sender_cntxt = reply_pkt.Sender_Context

    # send Execute PCCC Service request
    #FIXME this may not be needed

    # servicepkt = Ether(src='08:00:27:EC:11:8C', dst='00:1D:9C:A1:28:4C')
    # servicepkt /= IP(src='192.168.0.62', dst='192.168.0.59')
    # servicepkt /= TCP(src=srcport, dport=44818)
    # servicepkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
    # servicepkt /= ENIP_SendRRData(Timeout=20)
    # servicepkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=18)])
    # servicepkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4B, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x67),
    #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    # # servicepkt /= CIP_Execute_PCCC_Service(Object_Specific_Data='\x07\x4D\x00\xF3\x0A\x60\x05\x06\x00\x70\x03\x03')
    # servicepkt /= Raw(load="\x07\x4D\x00\xF3\x0A\x60\x05\x06\x00\x70\x03\x03")
    #
    # pktdump = PcapWriter("temp2.pcap", append=True, sync=True) # writes packets to pcap
    # pktdump.write(servicepkt)
    #
    # sock.send(str(servicepkt))


    # pktbytes2 = sock.recv(4096)

    # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes2)
    # session_id = reply_pkt.Session_Handle
    # sender_cntxt = reply_pkt.Sender_Context

    numofpackets = 1000000
    i = 0
    while i < numofpackets:

        # enippkt = Ether(src='08:00:27:EC:11:8C', dst='00:1D:9C:A1:28:4C')
        # enippkt /= IP(src='192.168.0.62', dst='192.168.0.59')
        # enippkt /= TCP(src=srcport, dport=44818)
        enippkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
        enippkt /= ENIP_SendRRData(Timeout=20)
        enippkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=22)])

        enippkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4E, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
                                                                                  CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        enippkt /= CIP_CM_Forward_Close_Service_Request(Tick_Time=0x7, Time_out_ticks=0x9B, Connection_Serial_Number=0x0003, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

        sequence += 1

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(enippkt)

        sock.send(str(enippkt))           #comment out to build packet

        # pktbytes3 = sock.recv(4096)
        # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes3)
        # session_id = reply_pkt.Session_Handle
        # sender_cntxt = reply_pkt.Sender_Context

        i = i + 1

    print i

def pccc_execute_service_request(plc_addr="192.168.0.59", plc_port="44818"):

    # Fuzzes Allen Bradley PCCC Execute Service

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    enip_connid = 0
    sequence = 1
    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(4096)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle
    sender_cntxt= reply_pkt.Sender_Context

    # Create CM Packet
    #
    cmpkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
    cmpkt /= ENIP_SendRRData(Timeout=20)
    cmpkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=46)])

    cmpkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
                                                                             CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    cmpkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0x9B, O_T_Network_Connection_ID=0x80000002,
        T_O_Network_Connection_ID=0x80FE0001, Connection_Serial_Number=0x0002, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x05600AF3,
        Connection_Timeout_Multiplier=0x02, Reserved=0x000200, O_T_RPI=0x001312D0, O_T_Network_Connection_Parameters=0x4312, T_O_RPI=0x001312D0, T_O_Network_Connection_Parameters=0x4312,
        Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
        Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

    sock.send(str(cmpkt))

    numofpackets = 1000000
    i = 0
    while i < numofpackets:

        sequence += 1

            # send PCCC Service Packet
        servicepkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=sender_cntxt)
        servicepkt /= ENIP_SendRRData(Timeout=20)
        servicepkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x9F9D0B6F),
                                              ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=31, Sequence_Number=sequence)])
        servicepkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4B, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x67),
                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        servicepkt /= CIP_Execute_PCCC_Service_Request(Length_of_Requestor_ID=7, CIP_Vendor_ID_of_Requestor=0x4D, CIP_Serial_Number=90180339, CMD=0xB, Status=0, Transaction_Word=1, Function=0)
        servicepkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0E, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                                                      CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        servicepkt /= CIP_Get_Attribute_Single_Request(Attribute_Identifier=0x01)

        pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
        pktdump.write(servicepkt)

        sock.send(str(servicepkt))           #comment out to build packet

        # pktbytes3 = sock.recv(4096)
        # reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes3)
        # session_id = reply_pkt.Session_Handle
        # sender_cntxt = reply_pkt.Sender_Context

        i = i + 1

    print i


if __name__ == '__main__':

    print "\n\nFuzzer. To fuzz: python cisco_fuzzer.py --FRAME UDP_Command --COUNT 1000\n\n"

    parser = OptionParser()
    parser.add_option("--FRAME", dest="frametype")
    # parser.add_option("--ETHER", dest="etherdest")
    # parser.add_option("--LHOST", dest="sourceIP")
    # parser.add_option("--RHOST", dest="destIP")
    # parser.add_option("--LPORT", dest="localPort")
    # parser.add_option("--RPORT", dest="remotePort")
    parser.add_option("--COUNT", dest="pkts", type="int")

    (options, args) = parser.parse_args()
    if options.frametype == "UDP_Command":
        packets = enip_udp(options.pkts)
    elif options.frametype == "TCP_Command":
        packets = enip_tcp(options.pkts)
    elif options.frametype == "CIP_Multiple_Service_Pkt":
        packets = cip_multiservicepacket()
    elif options.frametype == "CIP_NOP":
        packets = cip_nop()
    elif options.frametype == "CIP_Get_Attribute_List":
        packets = cip_get_attribute_list()
    elif options.frametype == "CIP_Get_Attribute_Single":
        packets = cip_get_attribute_single()
    elif options.frametype == "CIP_CM_Forward_Open":
        packets = cip_cm_forward_open()
    elif options.frametype == "CIP_CM_Forward_Close":
        packets = cip_cm_forward_close()
    elif options.frametype == "CIP_Read_Tag_Service":
        packets = cip_read_tag_service()
    elif options.frametype == "PCCC_Execute_Service":
        packets = pccc_execute_service_request()
    else:
        print "frametype not found."
        sys.exit()
    # print "Number of packets sent:\t", len(packets), "\n"

    # fuzzer(get_ENIP_UDP_EncapuslationCommand(0x00, 0xFF))
    # fuzzer(packets)