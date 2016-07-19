from scapy.all import *
import binascii
from cisco_enip_dissector import *
from cisco_cip_dissector import *
from optparse import OptionParser
import socket

def send_enip(plc_addr="10.0.2.15", plc_port="44818"):

    plcPort = int(plc_port)

    sock = socket.create_connection((plc_addr, plcPort))                       # comment out to build packet
    # open an EtherNet/IP session                                                # comment out to build packet
    session_id = 0
    sequence = 0
    conn_id = 0

    sessionpkt = ENIP_TCP_EncapsulationCommand() / ENIP_RegisterSession()
    sock.send(str(sessionpkt))

    pktbytes = sock.recv(2000)
    reply_pkt = ENIP_TCP_EncapsulationCommand(pktbytes)
    session_id = reply_pkt.Session_Handle

    # Create CM Packet
    #
    cmpkt = ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=session_id, Sender_Context=0)
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

    pktbytes2 = sock.recv(2000)
    reply = ENIP_TCP_EncapsulationCommand(pktbytes2)
    reply.show()
send_enip()
