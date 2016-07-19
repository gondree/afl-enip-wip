#!/usr/bin/env python2
from scapy.all import *
from cisco_enip_dissector import *
import dictionary
import pprint # for debugging

#TODO EIP-CIP V2 ODVA Chapter 4: Object model contains no additions to CIP object model that are ENIP specific
#TODO Implement EIP-CIP V2 ODVA Chapter 5: Object Library

class XBitEnumField(BitEnumField):
    """A BitEnumField with hexadecimal representation"""

    def __init__(self, name, default, size, enum):
        BitEnumField.__init__(self, name, default, size, enum)

    def i2repr_one(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return lhex(x)

class XByteEnumField(ByteEnumField):
    """A ByteEnumField with hexadecimal representation"""

    def __init__(self, name, default, enum):
        ByteEnumField.__init__(self, name, default, enum)

    def i2repr(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return lhex(self.i2h(pkt, x))

class LEIntLenField(FieldLenField):
    """A len field in a unsigned integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        FieldLenField.__init__(self, name, default, fmt="<B", count_of=count_of, length_of=length_of)

class CIP_Request_Path(Packet):
    """ A common use of CIP segments is to specify relationships among different objects. A value used to specify such a
    relationship is referred to as a path. A path attribute consists of multiple segments, and typically references the
    class, instance, and attribute of another object.

    A CIP segment is a stream of encoded items used to reference, describe, and/or configure a specific CIP entity.
    CIP V1 ODVA Appendix C: Data Management

    Logical segment - logical reference information (such as class/instance/attribute IDs)
    CIP V1 ODVA Appendix C: Data Management

    Port segment - used for routing from subnet to another CIP V1 ODVA Appendix C: Data Management

    CIP_Request_Path_Instance
    At minimum, every EtherNet/IP device shall implement instance number one of each of the following objects:
    Identity Object (0x01)
    Message Router Object (0x02)
    Connection Manager Object (0x06)
    TCP/IP Interface Object (OxF5)
    *Ethernet Link Object (0xF6) -- if an Ethernet medium is used


    """
#TODO bind with CIP_Logical_Segment
    name = "CIP Request Path"
    fields_desc = [
        BitEnumField("Path_Segment_Type", None, 3, {
            0x0: "Port Segment",
            0x1: "Logical Segment",
            0x2: "Network Segment",
            0x3: "Symbolic Segment",
            0x4: "Data Segment",
            0x5: "Data Type (constructed)",
            0x6: "Data Type (elementary)",
            0x7: "Reserved for future use",
        }),
        ConditionalField(BitEnumField("Logical_Segment_Type", None, 3, {
            0x0: "Class ID",
            0x1: "Instance ID",
            0x2: "Member ID",
            0x3: "Connection Point",
            0x4: "Attribute ID",
            0x5: "Special",
            0x6: "Service ID",
            0x7: "Reserved for future use",
        }), lambda pkt:pkt.getfieldval("Path_Segment_Type") == 0x1),
        ConditionalField(BitEnumField("Logical_Segment_Format", None, 2, {
            0x0: "8-bit logical address",
            0x1: "16-bit logical address",
            0x2: "32-bit logical address",
            0x3: "Reserved for future use",
        }), lambda pkt:pkt.getfieldval("Path_Segment_Type") == 0x1),
        ConditionalField(XByteEnumField("Class", None, {                   #CIP V1, Chapter 5, Object Specification in the CIP Object Library, size taken from Wireshark
            0x01: "Identity Object",
            0x02: "Message Router",
            0x03: "DeviceNet Object",
            0x04: "Assembly Object",
            0x05: "Connection Object",
            0x06: "Connection Manager Object",
            0x07: "Register Object",
            0x08: "Discrete Input Point Object",
            0x09: "Discrete Output Point Object",
            0x0A: "Analog Input Point Object",
            0x0B: "Analog Output Point Object",
            0x0E: "Presence Sensing Object",
            0x0F: "Parameter Object",
            0x10: "Parameter Group Object",
            0x12: "Group Object",
            0x1D: "Discrete Input Group Object",
            0x1E: "Discrete Output Group Object",
            0x1F: "Discrete Group Object",
            0x20: "Analog Input Group Object",
            0x21: "Analog Output Group Object",
            0x22: "Analog Group Object",
            0x23: "Position Sensor Object",
            0x24: "Position Controller Supervisor Object",
            0x25: "Position Controller Object",
            0x26: "Block Sequencer Object",
            0x27: "Command Block Object",
            0x28: "Motor Data Object",
            0x29: "Control Supervisor Object",
            0x2A: "AC/DC Drive Object",
            0x2B: "Acknowledge Handler Object",
            0x2C: "Overload Object",
            0x2D: "Softstart Object",
            0x2E: "Selection Object",
            0x30: "S-Device Supervisor Object",
            0x31: "S-Analog Sensor Object",
            0x32: "S-Analog Actuator Object",
            0x33: "S-Single Stage Controller Object",
            0x34: "S-Gas Calibration Object",
            0x35: "Trip Point Object",
            0x37: "File Object",
            0x38: "S-Partial Pressure Object",
            0x39: "Safety Supervisor Object",
            0x3A: "Safety Validator Object",
            0x3B: "Safety Discrete Output Point Object",
            0x3C: "Safety Discrete Output Group Object",
            0x3D: "Safety Discrete Input Point Object",
            0x3E: "Safety Discrete Input Group Object",
            0x3F: "Safety Dual Channel Output Object",
            0x40: "S-Sensor Calibration Object",
            0x41: "Event Log Object",
            0x42: "Motion Axis Object",
            0x43: "Time Sync Object",
            0x44: "Modbus Object",
            # 0x45: "Originator Connection List Object",     #Not in spec, but in Wireshark epan_dissectors_packet-cip.c
            # 0x46: "Modbus Serial Link Object",
            # 0x47: "Device Level Ring (DLR) Object",
            # 0x48: "QoS Object",
            # 0x49: "Safety Analog Input Point Object",
            # 0x4A: "Safety Analog Input Group Object",
            # 0x4B: "Safety Dual Channel Analog Input Object",
            # 0x4C: "Sercos III Link Object",
            # 0x4D: "Target Connection List Object",
            # 0x4E: "Base Energy Object",
            # 0x4F: "Electrical Energy Object",
            # 0x50: "Non-Electrical Energy Object",
            # 0x51: "Base Switch Object",
            # 0x52: "SNMP Object",
            # 0x53: "Power Management Object",
            # 0x54: "RSTP Bridge Object",
            # 0x55: "RSTP Port Object",
            0xF0: "ControlNet Object",
            0xF1: "ControlNet Keeper Object",
            0xF2: "ControlNet Scheduling Object",
            0xF3: "Connection Configuration Object",
            0xF4: "Port Object",
            0xF5: "TCP/IP Interface Object",          #Specific to EtherNet/IP EIP-CIP V2 ODVA Chapter 5: Object Library
            0xF6: "EtherNet Link Object",             #Specific to EtherNet/IP EIP-CIP V2 ODVA Chapter 5: Object Library
            0xF7: "CompoNet Object",
            0xF8: "CompoNet Repeater Object",
        }),
                         lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x0 and
                                     pkt.getfieldval("Logical_Segment_Format") == 0x0),
        ConditionalField(XByteField("Padded_EPath_with_Sixteen_bit_Class", 0), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x0 and
                                                                                     pkt.getfieldval("Logical_Segment_Format")  == 0x1),
        ConditionalField(LEXShortField("Sixteen_bit_Class", None), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x0 and
                                                                          pkt.getfieldval("Logical_Segment_Format")  == 0x1),
        ConditionalField(X3BytesField("Thirty_two_bit_Class", None), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x0 and
                                                                         pkt.getfieldval("Logical_Segment_Format")  == 0x2), #FIXME this should be little endian
        ConditionalField(XByteField("Eight_bit_Instance", None), lambda pkt:pkt.getfieldval("Logical_Segment_Type") == 0x1 and
                                                                            pkt.getfieldval("Logical_Segment_Format") == 0x0),
        ConditionalField(XByteField("Padded_EPath_with_Sixteen_bit_Instance", 0), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x1 and
                                                                                     pkt.getfieldval("Logical_Segment_Format")  == 0x1),
        ConditionalField(LEXShortField("Sixteen_bit_Instance", None), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x1 and
                                                                          pkt.getfieldval("Logical_Segment_Format")  == 0x1),
        ConditionalField(X3BytesField("Thirty_two_bit_Instance", None), lambda pkt: pkt.getfieldval("Logical_Segment_Type") == 0x1 and
                                                                         pkt.getfieldval("Logical_Segment_Format")  == 0x2), #FIXME this should be little endian
        ConditionalField(BitEnumField("Extended_Link_Address_Size", None, 1, {0: "=1 byte", 1: ">1 byte"}),
                         lambda pkt:pkt.getfieldval("Path_Segment_Type") == 0x0),
        ConditionalField(BitEnumField("Port_Identifier", None, 4, {
            0x0: "Reserved",
            0x1: "1"                  #back-plane port
        }),
                         lambda pkt:pkt.getfieldval("Path_Segment_Type") == 0x0),

        # "Optional Extended Port Identifier" If the Port Identifier is 15, then a 16-bit field, called the Extended Port
        #  Identifier, shall be the next part of the Port Segment (following the optional Link Address Size if present)
        ConditionalField(XByteField("Link_Address", None), lambda pkt:pkt.getfieldval("Path_Segment_Type") == 0x0)  # If the Link Address is greater than one byte it shall be padded so that the
        # length of the entire port segment is an even number of bytes. The pad byte shall be set to zero and shall not
        # be included in the Link Address Size.
    ]

    def extract_padding(self, p):
        return "", p

#FIXME what is CIP_CM_Unconnected_Send
# class CIP_CM_Unconnected_Send(Packet):
#     #TODO bind with CIP_Request_Path and CIP_Service
#     Message Request Size
#     Message Request
#         CIP
#             Service
#     ]

class CIP_Common_Service(Packet):
    """CIP Common Services: Explicit Messaging -- Volume 1 CIP Spec, Appendix A

    CIP defines a standard data format for delivering data to and from the Message Router object. This data format is
    used in various places within CIP including the Unconnected Send service of the Connection Manager object and the
    UCMM data structures of most of the CIP networks. EIP
    """

    name = "Common_Industrial_Protocol"
    fields_desc = [
        BitEnumField("Request_Response", None, 1, {0: "Request", 1: "Response"}),
        XBitEnumField("Common_Service", 0, 7, {
            0x01: "Get_Attributes_All",
            0x02: "Set_Attributes_All_Request",
            0x03: "Get_Attribute_List",
            0x04: "Set_Attribute_List",
            0x05: "Reset",
            0x06: "Start",
            0x07: "Stop",
            0x08: "Create",
            0x09: "Delete",
            0x0A: "Multiple_Service_Packet",
            0x0D: "Apply_Attributes",
            0x0E: "Get_Attribture_Single",
            0x10: "Set_Attribute_Single",
            0x11: "Find_Next_Object_Instance",
            0x15: "Restore",
            0x16: "Save",
            0x17: "NOP",
            0x18: "Get_Member",
            0x19: "Set_Member",
            0x1A: "Insert_Member",
            0x1B: "Remove_Member",
            0x1C: "GroupSync",

            # Connection Manager Services
            0x4E: "Connection_Manager_Forward_Close",

            0x4B: "Execute_PCCC_Service",   #FIXME need to verify
            0x4C: "Read_Tag_Service",

            0x52: "Connection_Manager_Unconnected_Send",
            0x54: "Connection_Manager_Forward_Open",
            0x56: "Connection_Manager_Get_Connection_Data",
            0x57: "Connection_Manager_Search_Connection_Data",
            0x5A: "Connection_Manager_Get_Connection_Owner",
            0x5B: "Connection_Manager_Large_Forward_Open",
        }),

        # Common Services header

        ConditionalField(LEIntLenField("Request_Path_Size", None, count_of="Words"),
                        lambda pkt:pkt.getfieldval("Request_Response") == 0),
        ConditionalField(PacketListField("Words", [], CIP_Request_Path, length_from=lambda p: p.Request_Path_Size*2),
                        lambda pkt:pkt.getfieldval("Request_Response") == 0),
        ConditionalField(ByteField("Reserved", 0),                  #Reserved shall be zero
                        lambda pkt:pkt.getfieldval("Request_Response") == 1),
        ConditionalField(ByteEnumField("General_Status", None, dictionary.STATUS_DICT),       #General Status code may be present in an Error Response message
                        lambda pkt:pkt.getfieldval("Request_Response") == 1),
        ConditionalField(ByteField("Size_of_Additional_Status", 0),
                        lambda pkt:pkt.getfieldval("Request_Response") == 1),
        # ConditionalField(LEShortField("Additional_Status", 0),
        #                 lambda pkt:pkt.getfieldval("Request_Response") == 1),
    ]

class CIP_CM_Forward_Open_Request(Packet):
    """The Forward Open Service (Service Code = 54hex) and Large_Forward_Open service (Service Code = 5Bhex) are used to
    establish a Connection with a Target Device1. These services result in local connection establishment on each link
    along the path.
    CIP ODVA V1 Chapter 3.5
    """
    #TODO bind with CIP_CM_Forward_Open_Request
    name = "CIP CM Forward Open Request"
    fields_desc = [
        BitField("Reserved", 000, 3),
        BitEnumField("Priority", 0, 1, {0: "Normal", 1: "Reserved"}), #The Reserved and Priority fields shall be set to
        # zero (0). The tick time shall be used in conjunction with the Time-out_ticks parameter value to determine the
        # total time out value.
        BitEnumField("Tick_Time", None, 4, {
            0x0: "1",
            0x1: "2",
            0x2: "4",
            0x3: "8",
            0x4: "16",
            0x5: "32",
            0x6: "64",
            0x7: "128",
            0x8: "256",
            0x9: "512",
            0xA: "1024",
            0xB: "2048",
            0xC: "4096",
            0xD: "8192",
            0xE: "16,384",
            0xF: "32,768",
        }),
        ByteField("Time_out_ticks", None),
        LEXIntField("O_T_Network_Connection_ID", None), #The Network Connection ID shall be link specific and shall not
        # be related to the connection serial number, which is connection specific and the same over all the links. The
        # fields of the Network Connection ID shall be used to set the screening mechanism for the specified link. The
        # Network Connection ID is either a CIP Produced Connection ID or CIP Consumed Connection ID.
        LEXIntField("T_O_Network_Connection_ID", None),
        LEXShortField("Connection_Serial_Number", None),
        LEShortEnumField("Originator_Vendor_ID", None, dictionary.VENDOR_DICT),         #Dictionary of Originator Vendor ID
        LEIntField("Originator_Serial_Number", None),
        ByteField("Connection_Timeout_Multiplier", None),
        X3BytesField("Reserved", 0x000000),
        LEIntField("O_T_RPI", None),
        LEXShortField("O_T_Network_Connection_Parameters", None),
        LEIntField("T_O_RPI", None),
        LEXShortField("T_O_Network_Connection_Parameters", None),
        BitEnumField("Transport_Type_Trigger_Direction", None, 1, {0: "Client", 1: "Server"}),
        BitEnumField("Transport_Type_Trigger_Production_Trigger", None, 3, {
            0x0: "Cyclic",
            0x1: "Change-Of-State",
            0x2: "Application Object",
            # 3-7 Reserved for CIP
        }),
        BitEnumField("Transport_Type_Trigger_Transport_Class", None, 4, {
            0x0: "Class 0",
            0x1: "Class 1",
            0x2: "Class 2",
            0x3: "Class 3",
            # 7-F Reserved
        }),
        LEIntLenField("Connection_Path_Size", None, count_of="Words"),
        PacketListField("Words", [], CIP_Request_Path, count_from=lambda p: p.Connection_Path_Size)
    ]

    def extract_padding(self, p):
        return "", p

class CIP_CM_Large_Forward_Open_Request(Packet):
    """The Large_Forward_Open service differs from the Forward_Open service only in the maximum size
    connection that can be established.
    CIP ODVA V1 Chapter 3.5
    """
    #TODO bind with CIP_CM_Forward_Open_Request
    name = "CIP CM Large Forward Open Request"
    fields_desc = [
        BitField("Reserved", 000, 3),
        BitEnumField("Priority", 0, 1, {0: "Normal", 1: "Reserved"}), #The Reserved and Priority fields shall be set to
        # zero (0). The tick time shall be used in conjunction with the Time-out_ticks parameter value to determine the
        # total time out value.
        BitEnumField("Tick_Time", None, 4, {
            0x0: "1",
            0x1: "2",
            0x2: "4",
            0x3: "8",
            0x4: "16",
            0x5: "32",
            0x6: "64",
            0x7: "128",
            0x8: "256",
            0x9: "512",
            0xA: "1024",
            0xB: "2048",
            0xC: "4096",
            0xD: "8192",
            0xE: "16,384",
            0xF: "32,768",
        }),
        ByteField("Time_out_ticks", None),
        LEXIntField("O_T_Network_Connection_ID", None), #The Network Connection ID shall be link specific and shall not
        # be related to the connection serial number, which is connection specific and the same over all the links. The
        # fields of the Network Connection ID shall be used to set the screening mechanism for the specified link. The
        # Network Connection ID is either a CIP Produced Connection ID or CIP Consumed Connection ID.
        LEXIntField("T_O_Network_Connection_ID", None),
        LEXShortField("Connection_Serial_Number", None),
        LEShortEnumField("Originator_Vendor_ID", None, dictionary.VENDOR_DICT),         #Dictionary of Originator Vendor ID
        LEIntField("Originator_Serial_Number", None),
        ByteField("Connection_Timeout_Multiplier", None),
        X3BytesField("Reserved", None),
        LEXIntField("O_T_RPI", None),
        LEXIntField("O_T_Network_Connection_Parameters", None),
        LEXIntField("T_O_RPI", None),
        LEXIntField("T_O_Network_Connection_Parameters", None),
        BitEnumField("Transport_Type_Trigger_Direction", None, 1, {0: "Client", 1: "Server"}),
        BitEnumField("Transport_Type_Trigger_Production_Trigger)", None, 3, {
            0x0: "Cyclic",
            0x1: "Change-Of-State",
            0x2: "Application Object",
            # 3-7 Reserved for CIP
        }),
        BitEnumField("Transport_Type_Trigger_Transport_Class", None, 4, {
            0x0: "Class 0",
            0x1: "Class 1",
            0x2: "Class 2",
            0x3: "Class 3",
            # 7-F Reserved
        }),
        LEIntLenField("Connection_Path_Size", None, count_of="Words"),
        PacketListField("Words", [], CIP_Request_Path, count_from=lambda p: p.Connection_Path_Size)
    ]

    def extract_padding(self, p):
        return "", p

class CIP_CM_Foward_Open_Response(Packet):
    name = "CIP CM Forward Open Response"
    fields_desc = [
        LEXIntField("O_T_Network_Connection_ID", None),
        LEXIntField("T_O_Network_Connection_ID", None),
        LEXShortField("Connection_Serial_Number", None),
        LEShortEnumField("Originator_Vendor_ID", None, dictionary.VENDOR_DICT),
        LEXIntField("Originator_Serial_Number", None),
        LEXIntField("O_T_API", None), # Actual packet rate, originator to target. A router shall use the lesser of this
        # value and the T->O API for the expected_packet_rate of the connection.
        LEXIntField("T_O_API", None), #Actual packet rate, target to originator. A router shall use the lesser of this
        # value and the O->T API for the expected_packet_rate of the connection.
        ByteField("Application_Reply_Size", None),
        ByteField("Reserved", None)
    ]

class CIP_CM_Forward_Close_Service_Request(Packet):
    """
    The Forward_Close Service (Service Code = 4Ehex) is used to close a connection with a Target Device (and all other
    nodes in the connection path). The Forward_Close request shall remove a connection from all the nodes participating
    in the original connection. The Forward_Close shall be sent between Connection Managers as specified in the connection_path.
    The Forward_Close request shall cause all resources in all nodes participating in the connection to be deallocated,
    including connection IDs, bandwidth, and internal memory buffers.
    CIP ODVA V1 Chapter 3.5
    """
    name = "CIP CM Forward Close Service Request"
    fields_desc = [
        BitField("Reserved", 000, 3),
        BitEnumField("Priority", 0, 1, {0: "Normal", 1: "Reserved"}), #The Reserved and Priority fields shall be set to
        # zero (0). The tick time shall be used in conjunction with the Time-out_ticks parameter value to determine the
        # total time out value.
        BitEnumField("Tick_Time", None, 4, {
            0x0: "1",
            0x1: "2",
            0x2: "4",
            0x3: "8",
            0x4: "16",
            0x5: "32",
            0x6: "64",
            0x7: "128",
            0x8: "256",
            0x9: "512",
            0xA: "1024",
            0xB: "2048",
            0xC: "4096",
            0xD: "8192",
            0xE: "16,384",
            0xF: "32,768",
        }),
        ByteField("Time_out_ticks", None),
        LEXShortField("Connection_Serial_Number", None),
        LEShortEnumField("Originator_Vendor_ID", None, dictionary.VENDOR_DICT),
        LEXIntField("Originator_Serial_Number", None),
        LEIntLenField("Connection_Path_Size", None, count_of="Words"),
        ByteField("Reserved", None),
        PacketListField("Words", [], CIP_Request_Path, count_from=lambda p: p.Connection_Path_Size)
    ]

    def extract_padding(self, p):
        return "", p

class CIP_CM_Forward_Close_Response(Packet):
    name = "CIP CM Forward Close Response"
    fields_desc = [
        LEXShortField("Connection_Serial_Number", None),
        LEShortEnumField("Originator_Vendor_ID", None, dictionary.VENDOR_DICT),
        LEXIntField("Originator_Serial_Number", None),
        ByteField("Application_Reply_Size", None),
        ByteField("Reserved", None)
    ]

class CIP_Get_Attribute_List_Request(Packet):
    """ Volume 1 CIP Spec, Appendix A
    The Get_Attribute_List service shall return the contents of the selected gettable attributes of the specified object class or instance.
    """
    name = "CIP Get Attribute List Request"
    fields_desc = [
        LEShortLenField("Attribute_Count", None, count_of="Attributes"),
        FieldListField("Attributes", [], LEShortField("", 0), count_from=lambda pkt: pkt.Attribute_Count)
    ]

    def extract_padding(self, p):
        return "", p

class CIP_CM_Unconnected_Send_Request(Packet):
    """
    The Unconnected_Send service shall allow an application to send a message to a device without first setting up a
    connection. The Unconnected_Send service shall use the Connection Manager object in each intermediate node to forward
    the message and to remember the return path. The UCMM of each link shall be used to forward the request from Connection
    Manager to Connection Manager just as it is for the Forward_Open service; however, no connection shall be built. The
    Unconnected_Send service shall be sent to the local Connection Manager and shall be sent between intermediate nodes.
    When an intermediate node removes the last port segment, the message shall be formatted as a UCMM message and sent to
    the port and link address of the last segment.
    CIP ODVA V1 Chpater 3.5
    """
    name = "CIP CM Unconnected Send Request"
    fields_desc = [
        BitField("Reserved", 000, 3),
        BitEnumField("Priority", 0, 1, {0: "Normal", 1: "Reserved"}),
        BitEnumField("Tick_Time", None, 4, {
            0x0: "1",
            0x1: "2",
            0x2: "4",
            0x3: "8",
            0x4: "16",
            0x5: "32",
            0x6: "64",
            0x7: "128",
            0x8: "256",
            0x9: "512",
            0xA: "1024",
            0xB: "2048",
            0xC: "4096",
            0xD: "8192",
            0xE: "16,384",
            0xF: "32,768",
        }),
        ByteField("Time_out_ticks", None),
        LEShortField("Message_Request_Size", None),
        CIP_Common_Service,
        # ConditionalField(ByteField("Pad", 0), lambda pkt:pkt.getfieldval("Message_Request_Size") % 2 != 0),

        # TODO add support for Unconnected Send other Common_Service?
        # Unconnected Send Get Attribute List
        ConditionalField(LEShortLenField("Attribute_Count", None, count_of="Attributes"), lambda pkt:pkt.getfieldval("Common_Service") == 0x03),
        ConditionalField(FieldListField("Attributes", [], LEShortField("", 0), count_from=lambda pkt: pkt.Attribute_Count), lambda pkt:pkt.getfieldval("Common_Service") == 0x03),

        LEIntLenField("Route_Path_Size", None, count_of="Route_Path"),
        ByteField("Reserved", None),
        PacketListField("Route_Path", [], CIP_Request_Path, count_from=lambda p: p.Route_Path_Size)
    ]

    def extract_padding(self, p):
        return "", p

class CIP_CM_Unconnected_Send_Response(Packet):
    name = "CIP CM Unconnected Send Response"
    fields_desc = [
        ByteField("Reply_Service", None),
        ByteField("Reserved", 0),
        ByteField("General_Status", None),  # This value shall be zero (0) for successful transactions
        ByteField("Reserved", 0),
    ]

#FIXME taken from scy-phy
class Multiple_Service_Packet(PacketListField):
    """The list of packets in a CIP MultipleServicePacket message"""

    def getfield(self, pkt, remain):
        lst = []
        pkt_count = pkt.Number_of_Services
        cur_offset = 2 + 2 * pkt_count
        shift = pkt.Service_Offsets[0] - cur_offset
        if shift > 0:
            # There is some padding between the CIP MSP header and the first packet
            lst.append(conf.raw_layer(load=remain[:shift]))
            remain = remain[shift:]
        cur_offset += shift
        for off in pkt.Service_Offsets[1:]:
            # Decode packet remain[:off - cur_offset]
            try:
                p = self.m2i(pkt, remain[:off - cur_offset])
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain[:off - cur_offset])
            remain = remain[off - cur_offset:]
            lst.append(p)
            cur_offset = off

        if remain:
            # Last packet contains all the remaining data
            try:
                p = self.m2i(pkt, remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
            lst.append(p)
        return "", lst

class CIP_Multiple_Service_Packet(Packet):
    """
    Performs a set of services as an autonomous sequence.
    CIP ODVA V1 Appendix A
    """
    name = "CIP Multiple Service Packet"
    fields_desc = [
        LEShortLenField("Number_of_Services", None, count_of="Service_Packets"),
        FieldListField("Service_Offsets", [], LEShortField("", 0),
                                 count_from=lambda pkt: pkt.Number_of_Services),
        Multiple_Service_Packet("Service_Packets", [], CIP_Common_Service)
    ]

    def do_build(self):
        """Build the packet by concatenating packets and building the offsets list"""
        # Build the sub packets
        subpkts = [str(pkt) for pkt in self.Service_Packets]
        # Build the offset lists
        current_offset = 2 + 2 * len(subpkts)
        Service_Offsets = []
        for p in subpkts:
            Service_Offsets.append(struct.pack("<H", current_offset))
            current_offset += len(p)
        return struct.pack("<H", len(subpkts)) + "".join(Service_Offsets) + "".join(subpkts)


        # This is for fuzzing
    #
    # name = "CIP Multiple Service Packet"
    # fields_desc = [
    #     LEShortField("Number_of_Services", 0),       #changed for fuzzing
    #     LEShortField("Service_Offsets", 0),
    #     Multiple_Service_Packet("Service_Packets", [], CIP_Common_Service)
    # ]

#FIXME unused?
# class CIP_Connection_Manager(Packet):
#     """ The Connection Manager Class allocates and manages the internal resources associated with both I/O and Explicit
#     Messaging Connections.
#     CIP ODVA V1 Chapter 3
#     """
#     #TODO bind with CIP_Request_Path_Class
#     name = "CIP Connection Manager"
#     fields_desc = [
#         BitEnumField("Request_Response", None, 1, {0:"Request", 1:"Response"}),
#         BitEnumField("Service", 0, 7, {
#             0x4E: "Forward_Close",
#             0x52: "Unconnected_Send",
#             0x54: "Forward_Open",
#             0x56: "Get_Connection_Data",
#             0x57: "Search_Connection_Data",
#             0x5A: "Get_Connection_Owner",
#             0x5B: "Large_Forward_Open",
#         }),
#         ConditionalField(PacketField("Request", CIP_CM_Forward_Open_Request(), CIP_CM_Forward_Open_Request),
#                         lambda pkt:pkt.getfieldval("Service") == 0x4E)
#     ]

#TODO determine if used
class CIP_UCMM_Message(Packet):
    """Unconnected Message Manager (UCMM) establishes Explicit Messaging and I/0 connections; target application
    object is the Message Router object (Class Code 2).
    request -- EIP-CIP ODVA V2 Chapter 3"""
    name = "CIP UCMM Message"

# class CIP_Message_Router_Response(Packet):
# #TODO verify field sizes
#     name = "CIP Message Router Response"
#     fields_desc = [
#         LEIntField("Reserved", 0),                  #Reserved shall be zero
#         LEIntEnumField("General_Status", 0, dictionary.STATUS_DICT),       #General Status code may be present in an Error Response message
#         LEIntField("Size_of_Additional_Status", 0),
#         LEShortField("Additional_Status", 0),
#     ]

#FIXME "Attribute Data" is Object/Class specific, this will affect packets following a packet with "Attribute Status" value "Success" (0x00)
class CIP_Attributes(Packet):
    fields_desc = [
        LEShortField("Attribute_Identifier", None),
        LEShortEnumField("Attribute_Status", None, dictionary.STATUS_DICT),
        ConditionalField(LEXShortField("Open_Requests", None), lambda pkt:pkt.getfieldval("Attribute_Identifier") == 0x01),
        ConditionalField(LEXShortField("Attribute_Data", None), lambda pkt:pkt.getfieldval("Attribute_Status") == 0x0), #FIXME we assume that the data size for status Success is a short
        # StrField("Attribute_Data", "")
    ]

    def extract_padding(self, p):
        return "", p

class CIP_Get_Attribute_List_Response(Packet):
    name = "CIP Get Attribute List Response"
    fields_desc = [
        # LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        # LEShortField("Attribute_Identifier", None),
        # LEShortEnumField("Attribute_Status", None, dictionary.STATUS_DICT),
        # ConditionalField(LEShortField("Open_Requests", None), lambda pkt:pkt.getfieldval("Attribute_Identifier") == 0x01),
        # StrField("Attribute_Data", "")

        LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        PacketListField("", [], CIP_Attributes, count_from=lambda p: p.Attribute_Count)

        # LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        # FieldListField("Attribute_Identifier", [], LEShortField("", 0), count_from=lambda pkt: pkt.Attribute_Count),
        # LEShortEnumField("Attribute_Status", None, dictionary.STATUS_DICT),
        # ConditionalField(LEShortField("Open_Requests", None), lambda pkt:pkt.getfieldval("Attribute_Identifier") == 0x01),
        # StrField("Attribute_Data", "")
    ]

    def extract_padding(self, p):
        return "", p

class CIP_Set_Attribute_List_Request(Packet):
    """ Volume 1 CIP Spec, Appendix A
    The Set_Attribute_List service shall set the contents of selected attributes of the specified object class or instance.
    """
    name = "CIP Set Attribute List Request"
    fields_desc = [
        LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        FieldListField("Attribute_Identifier", [], LEShortField("", 0), count_from=lambda pkt: pkt.Attribute_Count),
        StrField("Attribute_Data", "")
    ]

    def extract_padding(self, p):
        return "", p

class CIP_Get_Attribute_Single_Request(Packet):
    """ Volume 1 CIP Spec, Appendix A
    Returns the contents of the specified attribute.
    """
    name = "CIP Get Attribute Single Request"
    fields_desc = [
        LEShortField("Attribute_Identifier", None),
    ]

    def extract_padding(self, p):
        return "", p

class CIP_Get_Attribute_Single_Response(Packet):
    name = "CIP Get Attribute Single Response"
    fields_desc = [
    StrField("Attribute_Data", "")
    ]

class CIP_Set_Attribute_List_Response(Packet):
    name = "CIP Set Attribute List Response"
    fields_desc = [
        # LEShortField("Attribute_Count", None),
        # LEShortField("Attribute_Identifier", None),
        # LEShortEnumField("Attribute_Status", None, dictionary.STATUS_DICT),
        # StrField("Attribute_Data", "")
        # LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        # FieldListField("Attribute_Identifier", [], LEShortField("", 0), count_from=lambda pkt: pkt.Attribute_Count),
        # LEShortEnumField("Attribute_Status", None, dictionary.STATUS_DICT),
        # StrField("Attribute_Data", "")
        LEShortLenField("Attribute_Count", None, count_of="Attribute_Identifier"),
        PacketListField("", [], CIP_Attributes, count_from=lambda p: p.Attribute_Count)
    ]

class CIP_Execute_PCCC_Service_Request(Packet):
#FIXME This may be device specific
    name = "CIP Execute PCCC Service Request"
    fields_desc = [
        # StrField("Object_Specific_Data", ""),
        ByteField("Length_of_Requestor_ID", None),
        LEShortEnumField("CIP_Vendor_ID_of_Requestor", None, dictionary.VENDOR_DICT),
        LEIntField("CIP_Serial_Number", None),
        ConditionalField(ByteField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0x8),
        ConditionalField(LEShortField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0x9),
        ConditionalField(LEIntField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0xA),
        XByteEnumField("CMD", None, {
            0x0B: "Unconnected_PCCC_Command_Request",       # Found in Delivery of CIP Over RA Serial DF1 Links
            0x0A: "Connected_PCCC_Command_Request",
            0x0F: "0x0F",
            0x06: "0x06",
            0x01: "Unprotected_Read",           #FIXME these do not have a Function Field
            0x08: "Unprotected_Write",          #FIXME these do not have a Function Field
        }),
        ByteField("Status", 0),
        LEShortField("Transaction_Word", None),
        XByteEnumField("Function", None, {
            0x82: "Close_File",
            0x03: "Diagnostic_Status",
            0x41: "Disable_Forces",
            0x52: "Download_Completed",
            0x00: "Echo",
            0x57: "Initialize_Memory",
            0x81: "Open_File",
            0xA7: "Protected_Typed_File_Read",
            0xAF: "Protected_Typed_File_Write",
            0xA2: "Protected_Typed_Logical_Read_Three_Address_Fields",
            0xAA: "Protected_Typed_Logical_Write_Three_Address_Fields",
            0x01: "Read_Diagnostic_Counters",
            0x07: "Reset_Diagnostic_Counters",
            0x09: "Read_Link_Parameters",
            0x3A: "Set_CPU_Mode",
            0x0A: "Set_Link_Parameters"
        }),
        # StrField("PCCC_CMD_FNC_Specific_Data"),      # Max size is 244
        ConditionalField(XByteField("Extra", None), lambda pkt: pkt.getfieldval("Function") == 0x0),
        ConditionalField(PacketField("CIP_Service", "", CIP_Common_Service), lambda pkt: pkt.getfieldval("Function") == 0x0),
        # ConditionalField(CIP_Common_Service, lambda pkt: pkt.getfieldval("Function") == 0x0),
        ConditionalField(ByteField("Byte_Size", None), lambda pkt: pkt.getfieldval("CMD") == 0x0F and pkt.getfieldval("Function") == 0xA2),
        ConditionalField(ByteField("File_No", None), lambda pkt: pkt.getfieldval("CMD") == 0x0F and pkt.getfieldval("Function") == 0xA2),
        ConditionalField(ByteField("File_Type", None), lambda pkt: pkt.getfieldval("CMD") == 0x0F and pkt.getfieldval("Function") == 0xA2),
        ConditionalField(ByteField("Element_No", None), lambda pkt: pkt.getfieldval("CMD") == 0x0F and pkt.getfieldval("Function") == 0xA2),
        ConditionalField(ByteField("Sub_Element_No", None), lambda pkt: pkt.getfieldval("CMD") == 0x0F and pkt.getfieldval("Function") == 0xA2),
        # LEShortField("Address", None),
        # ByteField("Size", None),
        # StrField("Data", None),
        # LEShortField("Connection_ID", None),
        # LEShortField("Transport_Header", None),
    ]

    def extract_padding(self, p):
        return "", p

class CIP_Execute_PCCC_Service_Response(Packet):
#FIXME formatting may not be correct
    name = "CIP Execute PCCC Service Response"
    fields_desc = [
        # StrField("Object_Specific_Data", ""),
        ByteField("Length_of_Requestor_ID", None),
        LEShortEnumField("CIP_Vendor_ID_of_Requestor", None, dictionary.VENDOR_DICT),
        LEIntField("CIP_Serial_Number", None),
        ConditionalField(ByteField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0x8),
        ConditionalField(LEShortField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0x9),
        ConditionalField(LEIntField("Other", None), lambda pkt: pkt.getfieldval("Length_of_Requestor_ID") == 0xA),
        XByteField("CMD", None),
        ByteField("STS", 0),
        LEShortField("Transaction_Word", None),
        XByteField("Function", None),
        # StrField("PCCC_CMD_FNC_Specific_Data")      # Max size is 244
        ConditionalField(XByteField("Extra", None), lambda pkt: pkt.getfieldval ("Status") == 0xF0),
        # LEShortField("Connection_ID", None),
        # LEShortField("Transport_Header", None),
        PacketField("CIP_Service", None, CIP_Common_Service)
    ]

class CIP_Read_Tag_Service_Request(Packet):
#FIXME Need to verify; not found in spec
    name = "CIP Read Tag Service Request"
    fields_desc = [
        LEShortField("Number_of_elements", None),
    ]

class CIP_Create_Request(Packet):
    name = "CIP Create Request"
    fields_desc = [
        StrField("Object_Specific_Data", "")
    ]

class CIP_Create_Response(Packet):
    name = "CIP Create Response"
    fields_desc = [
    LEShortField("Instance_ID", None),
    StrField("Object_Specific_Data", "")
    ]

# class CIP_Get_Attributes_All_Request(Packet):
#     name = "Get Attributes All Request"

class CIP_Get_Attributes_All_Response(Packet):
    name = "CIP Get Attributes All Response Packet"
    fields_desc = [
    StrField("Attribute_Data", "")
    ]

#FIXME need to add support for different CIP_Request_Path_Segments
#TODO build CIP, ENIP


bind_layers(ENIP_CommonPacketFormat, CIP_Common_Service)

bind_layers(CIP_Common_Service, CIP_Get_Attribute_List_Request, Request_Response=0, Common_Service=0x03)
bind_layers(CIP_Common_Service, CIP_Get_Attribute_List_Response, Request_Response=1, Common_Service=0x03)

bind_layers(CIP_Common_Service, CIP_Set_Attribute_List_Request, Request_Response=0, Common_Service=0x04)
bind_layers(CIP_Common_Service, CIP_Set_Attribute_List_Response, Request_Response=1, Common_Service=0x04)

bind_layers(CIP_Common_Service, CIP_Create_Request, Request_Response=0, Common_Service=0x08)
bind_layers(CIP_Common_Service, CIP_Create_Response, Request_Response=1, Common_Service=0x08)

# bind_layers(CIP_Common_Service, CIP_Get_Attributes_All_Request, Request_Response=0, Common_Service=0x01)
bind_layers(CIP_Common_Service, CIP_Get_Attributes_All_Response, Request_Response=1, Common_Service=0x01)

bind_layers(CIP_Common_Service, CIP_Multiple_Service_Packet, Request_Response=0, Common_Service=0x0A)
bind_layers(CIP_Common_Service, CIP_Multiple_Service_Packet, Request_Response=1, Common_Service=0x0A)


bind_layers(CIP_Common_Service, CIP_CM_Forward_Open_Request, Request_Response=0, Common_Service=0x54)
bind_layers(CIP_Common_Service, CIP_CM_Foward_Open_Response, Request_Response=1, Common_Service=0x54)

bind_layers(CIP_Common_Service, CIP_CM_Forward_Close_Service_Request, Request_Response=0, Common_Service=0x4E)
bind_layers(CIP_Common_Service, CIP_CM_Forward_Close_Response, Request_Response=1, Common_Service=0x4E)

bind_layers(CIP_Common_Service, CIP_CM_Unconnected_Send_Request, Request_Response=0, Common_Service=0x52)

bind_layers(CIP_Common_Service, CIP_Get_Attribute_Single_Request, Request_Response=0, Common_Service=0x0E)
bind_layers(CIP_Common_Service, CIP_Get_Attribute_Single_Response, Request_Response=1, Common_Service=0x0E)

bind_layers(CIP_Common_Service, CIP_Execute_PCCC_Service_Request, Request_Response=0, Common_Service=0x4B)
bind_layers(CIP_Common_Service, CIP_Execute_PCCC_Service_Response, Request_Response=1, Common_Service=0x4B)

bind_layers(CIP_Common_Service, CIP_Read_Tag_Service_Request, Request_Response=0, Common_Service=0x4B)


#TODO bind_layers for CIP Request Path Segments


# Test dissector
if __name__ == '__main__':

# CM Forward Open for fuzzer

        # pkt = Ether(src='08:00:27:EC:11:8C', dst='00:1D:9C:A1:28:4C')
        # pkt /= IP(src='192.168.0.62', dst='192.168.0.59')
        # pkt /= TCP(sport=44818, dport=62330)
        # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F)
        # pkt /= ENIP_SendRRData(Timeout=20)
        # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2)])
        # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4B, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
        #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        # pkt /= CIP_Execute_PCCC_Service(Object_Specific_Data='\x07\x4D\x00\xF3\x0A\x60\x05\x06\x00\x70\x03\x03')

        # pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
        # pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
        # pkt /= TCP(sport=62330, dport=44818)
        # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F)
        #
        # pkt /= ENIP_SendRRData(Timeout=20)
        # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=46)])
        #
        # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
        #                                                                       CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
        # pkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0xF9, O_T_Network_Connection_ID=0x80000002,
        # T_O_Network_Connection_ID=0x80FE0001, Connection_Serial_Number=0x0002, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x05600AF3,
        # Connection_Timeout_Multiplier=0, Reserved=0x000200, O_T_RPI=0x001312D0, O_T_Network_Connection_Parameters=0x4312, T_O_RPI=0x001312D0, T_O_Network_Connection_Parameters=0x4312,
        # Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
        # Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
        #        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

        # test = str(pkt)
        # pkt = Ether(test)
        #
        # wrpcap("temp.pcap",pkt) # This builds pcap
        #
        # pkt.show()

# No. 46 Frame SC-GoOnline-TurnKnob-160304.pcapng Connection Manager Forward Open Request Packet
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100, Sender_Context=0x5C290F0058E0E209)
#
#     pkt /= ENIP_SendRRData(Timeout=32)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=48)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)])
#     pkt /= CIP_CM_Forward_Open_Request(Tick_Time=0x7, Time_out_ticks=0xF9, O_T_Network_Connection_ID=0x800001B7,
#     T_O_Network_Connection_ID=0x80FE01B6, Connection_Serial_Number=0x01B7, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x3D974B99,
#     Connection_Timeout_Multiplier=0, O_T_RPI=0x007A1200, O_T_Network_Connection_Parameters=0x43F4, T_O_RPI=0x007A1200, T_O_Network_Connection_Parameters=0x43F4,
#     Transport_Type_Trigger_Direction=1, Transport_Type_Trigger_Production_Trigger=0x2, Transport_Type_Trigger_Transport_Class=3,
#     Words=[CIP_Request_Path(Path_Segment_Type=0x0, Extended_Link_Address_Size=0, Port_Identifier=0x1, Link_Address=0x0),
#            CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
#            CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()

# No. 48 Frame SC-GoOnline-TurnKnob-160304.pcapng Get Attribute List Request Packet
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
#
#     pkt /= ENIP_SendUnitData(Timeout=1)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x002B0301),
#                                           ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=14, Sequence_Number=0x0001)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)])
#     pkt /= CIP_Get_Attribute_List_Request(Attributes=[10,12])
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()


# No. 49 Frame SC-GoOnline-TurnKnob-160304.pcapng Get Attribute List Response Packet
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
#
#     pkt /= ENIP_SendUnitData(Timeout=1)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x80FE01B6),
#                                           ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=24, Sequence_Number=0x0001)])
#
#     pkt /= CIP_Common_Service(Request_Response=1, Common_Service=0x03)
#
#     pkt /= CIP_Get_Attribute_List_Response(Attribute_Count=2, Attribute_Identifier=10, Attribute_Data="\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x87\xa0\x00\x00")
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()

# No. 56 Frame SC-GoOnline-TurnKnob-160304.pcapng Forward Close Request Packet
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100, Sender_Context=0x5C290F0058E0E209)
#
#     pkt /= ENIP_SendRRData(Timeout=32)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=48)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x54, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)])
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100, Sender_Context=0x5C290F0058E0E209)
#
#     pkt /= ENIP_SendRRData(Timeout=32)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=48)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4E, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
#     pkt /= CIP_CM_Forward_Close_Service_Request(Tick_Time=0x7, Time_out_ticks=0xF9, Connection_Serial_Number=0x01B7, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x3D974B99,
#     Reserved=0x0, Words=[CIP_Request_Path(Path_Segment_Type=0x0, Extended_Link_Address_Size=0, Port_Identifier=0x1, Link_Address=0x0),
#                          CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
#                          CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
#
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()

# No. 57 Frame SC-GoOnline-TurnKnob-160304.pcapng Forward Close Response Packet
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100, Sender_Context=0x5C290F0058E0E209)
#
#     pkt /= ENIP_SendRRData(Timeout=32)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=14)])
#
#     pkt /= CIP_Common_Service(Request_Response=1, Common_Service=0x4E)
#     pkt /= CIP_CM_Forward_Close_Response(Connection_Serial_Number=0x01B7, Originator_Vendor_ID=0x004D, Originator_Serial_Number= 0x3D974B99,
#     Application_Reply_Size=0, Reserved=0x0)
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()

# No. 24 Frame SC-GoOnline-TurnKnob-160304.pcapng Connection Manager Unconnected Send: Get Attribute All
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100, Sender_Context=0x5C290F0058E0E209)
#
#     pkt /= ENIP_SendRRData(Timeout=32)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x0000), ENIP_CPF_Item(Address_Data_Item=0x00B2, Data_Length=20)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x52, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x06),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
#     pkt /= CIP_CM_Unconnected_Send_Request(Tick_Time=0x7, Time_out_ticks=0xF9, Message_Request_Size=6, Request_Response=0, Common_Service=0x01,
#                                            Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
#                                                   CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)],
#                                            Route_Path=[CIP_Request_Path(Path_Segment_Type=0x0, Extended_Link_Address_Size=0, Port_Identifier=0x1, Link_Address=0)])
#
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()

# Fuzzing Multiple Service Packet using fuzzer
#     pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
#     pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
#     pkt /= TCP(sport=62330, dport=44818)
#     pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
#
#     pkt /= ENIP_SendUnitData(Timeout=1)
#     pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x002B0701),
#                                           ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=10, Sequence_Number=0x0010)])
#
#     pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0A, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
#                                                                               CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
#     pkt /= CIP_Multiple_Service_Packet(Number_of_Services=random.randint(0, 65535))
#
#     test = str(pkt)
#     pkt = Ether(test)
#
#     wrpcap("temp.pcap",pkt) # This builds pcap
#
#     pkt.show()


# Used for building pcap with Dissector

    # pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
    # pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
    # pkt /= TCP(sport=62330, dport=44818)
    # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
    #
    # pkt /= ENIP_SendUnitData(Timeout=1)
    # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x002B0701),
    #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=22, Sequence_Number=0x0010)])
    #
    # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0A, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
    #                                                                           CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
    # pkt /= CIP_Multiple_Service_Packet(Service_Packets=[CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
    #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
    #                                                     CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
    #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10]),

                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10]),
                                                        #
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10]),
                                                        #
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10]),
                                                        #
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10]),
                                                        #
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x64),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[1,2,6]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[5]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x0)]) / CIP_Get_Attribute_List_Request(Attributes=[11]),
                                                        # CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x69),
                                                        #                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[4,10])

    #                                                     ])
    #
    # test = str(pkt)
    # pkt = Ether(test)
    #
    # wrpcap("temp.pcap",pkt) # This builds pcap
    #
    # pkt.show()

# # Used for building pcap with fuzzer
#

    # pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
    # pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
    # pkt /= TCP(sport=62330, dport=44818)
    # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
    #
    # pkt /= ENIP_SendUnitData(Timeout=1)
    # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x002B0701),
    #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=22, Sequence_Number=0x0010)])
    #
    # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0A, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
    #                                                                           CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
    # pkt /= CIP_Multiple_Service_Packet(Number_of_Services=[1], Service_Offsets=[4], Service_Packets=[CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
    #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8])])
    #
    # pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
    # pktdump.write(pkt)
    # pkt.show()

    # pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
    # pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
    # pkt /= TCP(sport=62330, dport=44818)
    # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
    #
    # pkt /= ENIP_SendUnitData(Timeout=1)
    # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x002B0701),
    #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=38, Sequence_Number=0x0010)])
    #
    # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0A, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
    #                                                                           CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])
    # pkt /= CIP_Multiple_Service_Packet(Number_of_Services=[2], Service_Offsets=[6,16], Service_Packets=[CIP_Common_Service(Request_Response=0, Common_Service=0x03, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x8E),
    #                                                                        CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)]) / CIP_Get_Attribute_List_Request(Attributes=[8])])
    #
    # pktdump = PcapWriter("temp.pcap", append=True, sync=True) # writes packets to pcap
    # pktdump.write(pkt)
    # pkt.show()

#NOP Packet
    # pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
    # pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
    # pkt /= TCP(sport=62330, dport=44818)
    # pkt /= ENIP_TCP_EncapsulationCommand(Command=0x0070, Session_Handle=0x0F020100)
    #
    # pkt /= ENIP_SendUnitData(Timeout=1)
    # pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x80FE01B6),
    #                                       ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=24, Sequence_Number=0x0001)])
    #
    # pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x17, Request_Path_Size=random.randint(0, 255), Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x02),
    #                                                                                  CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x1)])

    #
    # test = str(pkt)
    # pkt = Ether(test)
    #
    # wrpcap("temp.pcap",pkt) # This builds pcap
    #
    # pkt.show()

    pkt = Ether(src='90:e2:ba:18:fc:2e', dst='00:1d:9c:ca:cb:1b')
    pkt /= IP(src='10.1.30.1', dst='10.1.100.2')
    pkt /= TCP(sport=62330, dport=44818)
    pkt /= ENIP_TCP_EncapsulationCommand(Command=0x006F, Session_Handle=0x0F020100)

    pkt /= ENIP_SendRRData(Timeout=1)
    pkt /= ENIP_CommonPacketFormat(Items=[ENIP_CPF_Item(Address_Data_Item=0x00A1, Address_Length=4, Connection_Identifier=0x9F9D0B6F),
                                   ENIP_CPF_Item(Address_Data_Item=0x00B1, Data_Length=31)])
    pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x4B, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x67),
                                                                    CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    pkt /= CIP_Execute_PCCC_Service_Request(Length_of_Requestor_ID=7, CIP_Vendor_ID_of_Requestor=0x4D, CIP_Serial_Number=90180339, CMD=0xB, Status=0, Transaction_Word=1, Function=0, Extra=0)
    pkt /= CIP_Common_Service(Request_Response=0, Common_Service=0x0E, Words=[CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x0, Logical_Segment_Format=0x0, Class=0x01),
                                                                           CIP_Request_Path(Path_Segment_Type=0x1, Logical_Segment_Type=0x1, Logical_Segment_Format=0x0, Eight_bit_Instance=0x01)])
    pkt /= CIP_Get_Attribute_Single_Request(Attribute_Identifier=0x01)

    test = str(pkt)
    pkt = Ether(test)

    wrpcap("temp2.pcap",pkt) # This builds pcap

    pkt.show()