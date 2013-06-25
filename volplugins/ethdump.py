# Volatility
# Copyright (c) 2010, 2011, 2012 Jamaal Speights <jamaal.speights@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.taskmods as taskmods
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.win32 as win32
import volatility.scan as scan
import binascii 
import re 
import struct
import socket
import os 

# Update this section to follow the style guide 
# Style guide http://code.google.com/p/volatility/wiki/StyleGuide
from dpkt.pcap import *
from dpkt.ethernet import *
from dpkt.ip import *
from dpkt.tcp import *
from dpkt.pcap import *
from pcap import *

try:
    import dpkt 
    has_dpkt = True
except ImportError:
    has_dpkt = False


class EthDump(common.AbstractWindowsCommand):
        """Finds Valid Ethernet Packets in Memory and saves them to a PCAP File"""
        def __init__(self, config, *args, **kwargs):
            common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
            config.add_option('DUMP-DIR', short_option = 'D', default = None,
                              cache_invalidator = False,
                              help = 'Directory in which to dump executable files')


        #computes the packets ip checksum to find valid ethernet frames 
        def ip_checksum(self, data):
            x = 0 
            y = 0 
            for i in range(0, len(data) - 1, 2):
                y = binascii.hexlify(data[i:i+2])
                x+=int(y, 0x10)
            checksum =  hex(x)[2:]
            carry_byte = checksum[0]
            rbytes= checksum[1:] #remainder_bytes
            checksum = int(rbytes, 0x10)+int(carry_byte, 0x10)
            return (~checksum & 0xFFFF)   #verified bytes 

        def calculate(self):
            if not has_dpkt:
                debug.error("Install dpkt http://code.google.com/p/dpkt/")
            
            #ipvxh will eventually be upated to include all types and will be a list 
            self.ipvxh = binascii.unhexlify("080045")

            self.protoTable = {
                            0x3E : "CFTP CFTP ", 
                            0x3D : "Any host internal protocol ", 
                            0x28 : "IL IL Transport Protocol ", 
                            0x29 : "IPv6 6in4 (encapsulation) RFC 2473, RFC 3056", 
                            0x3A : "IPv6-ICMP ICMP for IPv6 RFC 4443, RFC 4884", 
                            0x3C : "IPv6-Opts Destination Options for IPv6 RFC 2460", 
                            0x3B : "IPv6-NoNxt No Next Header for IPv6 RFC 2460", 
                            0x22 : "3PC Third Party Connect Protocol ", 
                            0x39 : "SKIP Simple Key-Management for Internet Protocol RFC 2356", 
                            0x20 : "MERIT-INP MERIT Internodal Protocol ", 
                            0x21 : "DCCP Datagram Congestion Control Protocol RFC 4340", 
                            0x26 : "IDPR-CMTP IDPR Control Message Transport Protocol ", 
                            0x27 : "TP++ TP++ Transport Protocol ", 
                            0x24 : "XTP Xpress Transport Protocol ", 
                            0x25 : "DDP Datagram Delivery Protocol ", 
                            0xFF : "Reserved.", 
                            0x35 : "SWIPE SwIPe IP with Encryption", 
                            0x34 : "I-NLSP Integrated Net Layer Security Protocol TUBA", 
                            0x37 : "MOBILE IP Mobility (Min Encap) RFC 2004", 
                            0x36 : "NARP NBMA Address Resolution Protocol RFC 1735", 
                            0x31 : "BNA BNA ", 
                            0x30 : "MHRP Mobile Host Routing Protocol ", 
                            0x33 : "AH Authentication Header RFC 4302", 
                            0x32 : "ESP Encapsulating Security Payload RFC 4303", 
                            0x2B : "IPv6-Route Routing Header for IPv6 RFC 2460", 
                            0x2C : "IPv6-Frag Fragment Header for IPv6 RFC 2460", 
                            0x2A : "SDRP Source Demand Routing Protocol RFC 1940", 
                            0x2F : "GRE Generic Routing Encapsulation RFC 2784, RFC 2890", 
                            0x38 : "TLSP Transport Layer Security Protocol (using Kryptonet key management) ", 
                            0x2D : "IDRP Inter-Domain Routing Protocol ", 
                            0x2E : "RSVP Resource Reservation Protocol RFC 2205", 
                            0x40 : "SAT-EXPAK SATNET and Backroom EXPAK ", 
                            0x41 : "KRYPTOLAN Kryptolan ", 
                            0x42 : "RVD MIT Remote Virtual Disk Protocol ", 
                            0x43 : "IPPC Internet Pluribus Packet Core ", 
                            0x44 : "Any distributed file system ", 
                            0x45 : "SAT-MON SATNET Monitoring ", 
                            0x46 : "VISA VISA Protocol ", 
                            0x47 : "IPCV Internet Packet Core Utility ", 
                            0x48 : "CPNX Computer Protocol Network Executive ", 
                            0x49 : "CPHB Computer Protocol Heart Beat ", 
                            0x8D-0xFC : "UNASSIGNED", 
                            0x5C : "MTP Multicast Transport Protocol ", 
                            0x5B : "LARP Locus Address Resolution Protocol ", 
                            0x5A : "Sprite-RPC Sprite RPC Protocol ", 
                            0x5F : "MICP Mobile Internetworking Control Protocol ", 
                            0x5E : "IPIP IP-within-IP Encapsulation Protocol RFC 2003", 
                            0x5D : "AX.25 AX.25 ", 
                            0x53 : "VINES VINES ", 
                            0x52 : "SECURE-VMTP Secure Versatile Message Transaction Protocol RFC 1045", 
                            0x51 : "VMTP Versatile Message Transaction Protocol RFC 1045", 
                            0x3F : "Any local network ", 
                            0x57 : "TCF TCF ", 
                            0x56 : "DGP Dissimilar Gateway Protocol ", 
                            0x55 : "NSFNET-IGP NSFNET-IGP ", 
                            0x54 : "IPTM Internet Protocol Traffic Manager ", 
                            0x59 : "OSPF Open Shortest Path First RFC 1583", 
                            0x58 : "EIGRP EIGRP ", 
                            0x4A : "WSN Wang Span Network ", 
                            0x4B : "PVP Packet Video Protocol ", 
                            0x4C : "BR-SAT-MON Backroom SATNET Monitoring ", 
                            0x4D : "SUN-ND SUN ND PROTOCOL-Temporary ", 
                            0x4E : "WB-MON WIDEBAND Monitoring ", 
                            0x4F : "WB-EXPAK WIDEBAND EXPAK ", 
                            0x50 : "ISO-IP International Organization for Standardization Internet Protocol ", 
                            0x23 : "IDPR Inter-Domain Policy Routing Protocol RFC 1479", 
                            0x68 : "ARIS IBM's ARIS (Aggregate Route IP Switching) Protocol ", 
                            0x69 : "SCPS SCPS (Space Communications Protocol Standards) SCPS-TP[1]", 
                            0x66 : "PNNI PNNI over IP ", 
                            0x67 : "PIM Protocol Independent Multicast ", 
                            0x64 : "GMTP GMTP ", 
                            0x65 : "IFMP Ipsilon Flow Management Protocol ", 
                            0x62 : "ENCAP Encapsulation Header RFC 1241", 
                            0x63 : "Any private encryption scheme ", 
                            0x60 : "SCC-SP Semaphore Communications Sec. Pro ", 
                            0x61 : "ETHERIP Ethernet-within-IP Encapsulation RFC 3378", 
                            0x7A : "SM SM ", 
                            0x7C : "IS-IS over IPv4 ", 
                            0x7B : "PTP Performance Transparency Protocol ", 
                            0x7E : "CRTP Combat Radio Transport Protocol ", 
                            0x7D : "FIRE ", 
                            0x7F : "CRUDP Combat Radio User Datagram ", 
                            0x79 : "SMP Simple Message Protocol ", 
                            0x78 : "UTI UTI ", 
                            0x71 : "PGM PGM Reliable Transport Protocol RFC 3208", 
                            0x70 : "VRRP Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned) VRRP:RFC 3768", 
                            0x73 : "L2TP Layer Two Tunneling Protocol Version 3 RFC 3931", 
                            0x72 : "Any 0-hop protocol ", 
                            0x75 : "IATP Interactive Agent Transfer Protocol ", 
                            0x74 : "DDX D-II Data Exchange (DDX) ", 
                            0x77 : "SRP SpectraLink Radio Protocol ", 
                            0x76 : "STP Schedule Transfer Protocol ", 
                            0x6F : "IPX-in-IP IPX in IP ", 
                            0x6D : "SNP Sitara Networks Protocol ", 
                            0x6E : "Compaq-Peer Compaq Peer Protocol ", 
                            0x6B : "A/N Active Networks ", 
                            0x6C : "IPComp IP Payload Compression Protocol RFC 3173", 
                            0x6A : "QNX QNX ", 
                            0x1F : "MFE-NSP MFE Network Services Protocol ", 
                            0x1E : "NETBLT Bulk Data Transfer Protocol RFC 998", 
                            0x1D : "ISO-TP4 ISO Transport Protocol Class 4 RFC 905", 
                            0x1C : "IRTP Internet Reliable Transaction Protocol RFC 938", 
                            0x1B : "RDP Reliable Datagram Protocol RFC 908", 
                            0x1A : "LEAF-2 Leaf-2 ", 
                            0x08 : "EGP Exterior Gateway Protocol RFC 888", 
                            0x09 : "IGP Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP)) ", 
                            0x04 : "IPv4 IPv4 (encapsulation) RFC 791", 
                            0x05 : "ST Internet Stream Protocol RFC 1190, RFC 1819", 
                            0x06 : "TCP Transmission Control Protocol RFC 793", 
                            0x07 : "CBT Core-based trees RFC 2189", 
                            0x00 : "HOPOPT IPv6 Hop-by-Hop Option RFC 2460", 
                            0x01 : "ICMP Internet Control Message Protocol RFC 792", 
                            0x02 : "IGMP Internet Group Management Protocol RFC 1112", 
                            0x03 : "GGP Gateway-to-Gateway Protocol RFC 823", 
                            0x84 : "SCTP Stream Control Transmission Protocol ", 
                            0x85 : "FC Fibre Channel ", 
                            0x86 : "RSVP-E2E-IGNORE RFC 3175", 
                            0x87 : "Mobility Header RFC 3775", 
                            0x80 : "SSCOPMCE ", 
                            0x81 : "IPLT ", 
                            0x82 : "SPS Secure Packet Shield ", 
                            0x83 : "PIPE Private IP Encapsulation within IP Expired I-D draft-petri-mobileip-pipe-00.txt", 
                            0x88 : "UDP Lite RFC 3828", 
                            0x89 : "MPLS-in-IP RFC 4023", 
                            0x8A : "manet MANET Protocols RFC 5498", 
                            0x8B : "HIP Host Identity Protocol RFC 5201", 
                            0x8C : "Shim6 Site Multihoming by IPv6 Intermediation RFC 5533", 
                            0xFD-0xFE : "Use for experimentation and testing RFC 3692", 
                            0x0D : "ARGUS ARGUS ", 
                            0x0E : "EMCON EMCON ", 
                            0x0F : "XNET Cross Net Debugger IEN 158", 
                            0x0A : "BBN-RCC-MON BBN RCC Monitoring ", 
                            0x0B : "NVP-II Network Voice Protocol RFC 741", 
                            0x0C : "PUP Xerox PUP ", 
                            0x19 : "LEAF-1 Leaf-1 ", 
                            0x18 : "TRUNK-2 Trunk-2 ", 
                            0x17 : "TRUNK-1 Trunk-1 ", 
                            0x16 : "XNS-IDP XEROX NS IDP ", 
                            0x15 : "PRM Packet Radio Measurement ", 
                            0x14 : "HMP Host Monitoring Protocol RFC 869", 
                            0x13 : "DCN-MEAS DCN Measurement Subsystems ", 
                            0x12 : "MUX Multiplexing IEN 90", 
                            0x11 : "UDP User Datagram Protocol RFC 768", 
                            0x10 : "CHAOS Chaos ",
            }            
            kernel_space = utils.load_as(self._config)
            
            
                
            #this entire section needs to be moved to render
            if self._config.DUMP_DIR == None:
                debug.error("Please specify a dump directory (--dump-dir)")
            if not os.path.isdir(self._config.DUMP_DIR):
                debug.error(self._config.DUMP_DIR + " is not a directory")

            apath = os.path.abspath(self._config.DUMP_DIR)
            pcapfile = os.path.join(apath, 'out.pcap')
            pcapfile = open(pcapfile, 'wb')
            outstr = "saving pcap to: " + pcapfile.name

            #render_text 
            #self.outfd.write(outstr)
    
            pcw = dpkt.pcap.Writer(pcapfile)
            addr_space = utils.load_as(self._config, astype = 'physical')
            
            offsetlist = [] 

            for (offset, length) in addr_space.get_available_addresses():
                data = addr_space.read(offset, length)
                
                offsets = [m.start() for m in re.finditer(self.ipvxh, str(data))]
                if offsets:
                    for h in offsets:
                        self.ptype = int(binascii.hexlify(data[h+11]), 0x10)
                        if self.ptype in self.protoTable:
                            header_offset = h-12
                            #verify checksum 
                            checksum = data[header_offset+14:header_offset+34]
                            checksum = self.ip_checksum(checksum)
                            if checksum == 0:
                                offsetlist.append(int(h))
                                #print "Packet",  self.protoTable[ptype]                            
                                # packet size 
                                tsize = binascii.hexlify(data[header_offset+0x10:header_offset+0x12])
                                tsize = int(tsize, 0x10)
                                
                                #ip header 
                                ipHeader = data[header_offset:header_offset+12]
                                
                                #ip data 
                                ipPacket = data[h:h+tsize]
                                
                                #let our powers combine 
                                memPacket = ipHeader + ipPacket
                                
                                #create ethernet frame from mem using dpkt 
                                eth = dpkt.ethernet.Ethernet(memPacket)
                                pcw.writepkt(eth)
            return outstr, offsetlist 

        def render_text(self, outfd, data):
            if self._config.DUMP_DIR == None:
                debug.error("Please specify a dump directory (--dump-dir)")
            if not os.path.isdir(self._config.DUMP_DIR):
                debug.error(self._config.DUMP_DIR + " is not a directory")
        
            self.table_header(outfd, [("Offset", "[addrpad]")])
        
            for process in data[1]:
                self.table_row(outfd, process)
            #update using outfd
            print data[0]
