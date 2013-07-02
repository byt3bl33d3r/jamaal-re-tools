# Volatility
# Copyright (c) 2010, 2011, 2012, 2013 Jamaal Speights <jamaal.speights@gmail.com>
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


import struct
import os 
import volatility.commands as commands
import volatility.utils as utils
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug
from binascii import hexlify
from binascii import unhexlify

try:
    import dpkt 
    from dpkt import pcap 
    from dpkt.pcap import Writer 
    has_dpkt = True
except ImportError:
    has_dpkt = False

global counterA 
global counterB 
counterA = 0 
counterB = 0
        
class PacketType(object):
    """PacketType Class returns Ethernet and Protocol types by get_ethtype and get_prototye methods"""
    protocols = {
                            0x00: ['HOPOPT', 0],
                            0x01: ['ICMP', 0],
                            0x02: ['IGMP', 0],
                            0x03: ['GGP', 0],
                            0x04: ['IPv4', 0],
                            0x05: ['ST', 0],
                            0x06: ['TCP', 0],
                            0x07: ['CBT', 0],
                            0x08: ['EGP', 0],
                            0x09: ['IGP', 0],
                            0x0A: ['BBN-RCC-MON', 0],
                            0x0B: ['NVP-II', 0],
                            0x0C: ['PUP', 0],
                            0x0D: ['ARGUS', 0],
                            0x0E: ['EMCON', 0],
                            0x0F: ['XNET', 0],
                            0x10: ['CHAOS', 0],
                            0x11: ['UDP', 0],
                            0x12: ['MUX', 0],
                            0x13: ['DCN-MEAS', 0],
                            0x14: ['HMP', 0],
                            0x15: ['PRM', 0],
                            0x16: ['XNS-IDP', 0],
                            0x17: ['TRUNK-1', 0],
                            0x18: ['TRUNK-2', 0],
                            0x19: ['LEAF-1', 0],
                            0x1A: ['LEAF-2', 0],
                            0x1B: ['RDP', 0],
                            0x1C: ['IRTP', 0],
                            0x1D: ['ISO-TP4', 0],
                            0x1E: ['NETBLT', 0],
                            0x1F: ['MFE-NSP', 0],
                            0x20: ['MERIT-INP', 0],
                            0x21: ['DCCP', 0],
                            0x22: ['3PC', 0],
                            0x23: ['IDPR', 0],
                            0x24: ['XTP', 0],
                            0x25: ['DDP', 0],
                            0x26: ['IDPR-CMTP', 0],
                            0x27: ['TP++', 0],
                            0x28: ['IL', 0],
                            0x29: ['IPv6', 0],
                            0x2A: ['SDRP', 0],
                            0x2B: ['IPv6-Route', 0],
                            0x2C: ['IPv6-Frag', 0],
                            0x2D: ['IDRP', 0],
                            0x2E: ['RSVP', 0],
                            0x2F: ['GRE', 0],
                            0x30: ['MHRP', 0],
                            0x31: ['BNA', 0],
                            0x32: ['ESP', 0],
                            0x33: ['AH', 0],
                            0x34: ['I-NLSP', 0],
                            0x35: ['SWIPE', 0],
                            0x36: ['NARP', 0],
                            0x37: ['MOBILE', 0],
                            0x38: ['TLSP', 0],
                            0x39: ['SKIP', 0],
                            0x3A: ['IPv6-ICMP', 0],
                            0x3B: ['IPv6-NoNxt', 0],
                            0x3C: ['IPv6-Opts', 0],
                            0x3D: ['Any host internal protocol', 0],
                            0x3E: ['CFTP', 0],
                            0x3F: ['Any local network', 0],
                            0x40: ['SAT-EXPAK', 0],
                            0x41: ['KRYPTOLAN', 0],
                            0x42: ['RVD MIT', 0],
                            0x43: ['IPPC', 0],
                            0x44: ['Any distributed file system ', 0],
                            0x45: ['SAT-MON SATNET', 0],
                            0x46: ['VISA', 0],
                            0x47: ['IPCV', 0],
                            0x48: ['CPNX', 0],
                            0x49: ['CPHB', 0],
                            0x4A: ['WSN', 0],
                            0x4B: ['PVP', 0],
                            0x4C: ['BR-SAT-MON', 0],
                            0x4D: ['SUN-ND', 0],
                            0x4E: ['WB-MON', 0],
                            0x4F: ['WB-EXPAK', 0],
                            0x50: ['ISO-IP', 0],
                            0x51: ['VMTP', 0],
                            0x52: ['SECURE-VMTP', 0],
                            0x53: ['VINES', 0],
                            0x54: ['TTP', 0],
                            0x54: ['IPTM', 0],
                            0x55: ['NSFNET-IGP', 0],
                            0x56: ['DGP', 0],
                            0x57: ['TCF', 0],
                            0x58: ['EIGRP', 0],
                            0x59: ['OSPF', 0],
                            0x5A: ['Sprite-RPC', 0],
                            0x5B: ['LARP', 0],
                            0x5C: ['MTP Multicast Transport Protocol', 0],
                            0x5D: ['AX.25', 0],
                            0x5E: ['IPIP', 0],
                            0x5F: ['MICP', 0],
                            0x60: ['SCC-SP', 0],
                            0x61: ['ETHERIP', 0],
                            0x62: ['ENCAP', 0],
                            0x63: ['Any private encryption scheme', 0],
                            0x64: ['GMTP', 0],
                            0x65: ['IFMP', 0],
                            0x66: ['PNNI', 0],
                            0x67: ['PIM', 0],
                            0x68: ['ARIS', 0],
                            0x69: ['SCPS', 0],
                            0x6A: ['QNX', 0],
                            0x6B: ['A/N', 0],
                            0x6C: ['IPComp', 0],
                            0x6D: ['SNP', 0],
                            0x6E: ['Compaq-Peer', 0],
                            0x6F: ['IPX-in-IP', 0],
                            0x70: ['VRRP', 0],
                            0x71: ['PGM', 0],
                            0x72: ['Any 0-hop protocol', 0],
                            0x73: ['L2TP', 0],
                            0x74: ['DDX', 0],
                            0x75: ['IATP', 0],
                            0x76: ['STP', 0],
                            0x77: ['SRP', 0],
                            0x78: ['UTI', 0],
                            0x79: ['SMP', 0],
                            0x7A: ['SM', 0],
                            0x7B: ['PTP', 0],
                            0x7C: ['IS-IS over IPv4', 0],
                            0x7D: ['FIRE', 0],
                            0x7E: ['CRTP', 0],
                            0x7F: ['CRUDP', 0],
                            0x80: ['SSCOPMCE', 0],
                            0x81: ['IPLT', 0],
                            0x82: ['SPS', 0],
                            0x83: ['PIPE', 0],
                            0x84: ['SCTP', 0],
                            0x85: ['FC', 0],
                            0x86: ['RSVP-E2E-IGNORE', 0],
                            0x87: ['Mobility Header', 0],
                            0x88: ['UDP Lite', 0],
                            0x89: ['MPLS-in-IP', 0],
                            0x8A: ['manet', 0],
                            0x8B: ['HIP', 0],
                            0x8C: ['Shim6', 0],
                            0xFE: ['Unknown', 0],
    }
                        
    ethertypes = {
                            0x0800: ['IPv4', 0, None],
                            0x0806: ['ARP', 0, None],
                            0x0842: ['Wake-on-LAN', 0, None],
                            0x22F3: ['IETF TRILL Protocol', 0, None],
                            0x6003: ['DECnet Phase IV', 0, None],
                            0x8035: ['Reverse ARP', 0, None],
                            0x809B: ['AppleTalk', 0, None],
                            0x80F3: ['AppleTalk ARP', 0, None],
                            0x8100: ['VLAN-tagged', 0, None],
                            0x8137: ['IPX', 0, None],
                            0x8138: ['IPX', 0, None],
                            0x8204: ['QNX Qnet', 0, None],
                            0x86DD: ['IPv6', 0, None],
                            0x8808: ['Ethernet flow control', 0, None],
                            0x8809: ['Slow Protocols (IEEE 802.3)', 0, None],
                            0x8819: ['CobraNet', 0, None],
                            0x8847: ['MPLS unicast', 0, None],
                            0x8848: ['MPLS multicast', 0, None],
                            0x8863: ['PPPoE Discovery Stage', 0, None],
                            0x8864: ['PPPoE Session Stage', 0, None],
                            0x8870: ['Jumbo Frames', 0, None],
                            0x887B: ['HomePlug 1.0 MME', 0, None],
                            0x888E: ['IEEE 802.1X', 0, None],
                            0x8892: ['PROFINET Protocol', 0, None],
                            0x889A: ['SCSI over Ethernet', 0, None],
                            0x88A2: ['ATA over Ethernet', 0, None],
                            0x88A4: ['EtherCAT', 0, None],
                            0x88A8: ['802.1ad & IEEE 802.1aq', 0, None],
                            0x88AB: ['Ethernet Powerlink', 0, None],
                            0x88CC: ['LLDP', 0, None],
                            0x88CD: ['SERCOS', 0, None],
                            0x88E1: ['HomePlug AV MME', 0, None],
                            0x88E3: ['Media Redundancy Protocol (IEC62439-2)', 0, None],
                            0x88E5: ['MAC security (IEEE 802.1AE)', 0, None],
                            0x88F7: ['Precision Time Protocol (IEEE 1588)', 0, None],
                            0x8902: ['IEEE 802.1ag', 0, None],
                            0x8906: ['FCoE', 0, None],
                            0x8914: ['FCoE Initialization Protocol', 0, None],
                            0x8915: ['RDMA over Converged Ethernet (RoCE)', 0, None],
                            0x9000: ['Ethernet Configuration Testing Protocol', 0, None],
                            0x9100: ['Q-in-Q', 0, None],
                            0xCAFE: ['Veritas Low Latency Transport (LLT)', 0, None],
                            #0x0000: ['Unknown', 0, None],
        }                       
        
    
    def get_ethtype(self, lookup):
        # ! There has to be a better way.  
        #unpack binary data 
        ethstr = struct.unpack('>h',lookup)[0]
        #convert it to 0x0800 format 
        ethstr =  "{0:#0{1}x}".format(ethstr,6)
        #look up string as int 
        etype = self.ethertypes.get(int(ethstr, 0x10), "Unkown")[0]
        return etype,ethstr
        
    def get_prototye(self, lookup):
        ptype = "Unknown"
        ptype = self.protocols.get(lookup, "UnKnown")
        return ptype                        
    
class EthScanVTypes(obj.ProfileModification):
    """ EthScanVTypes packet structure """
    
    # //!!  This isn't required
    #conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):        
        
        ethVtype = {
        'ethFrame': [ 0x0, {
            'ethDst' : [ 0x0, ['array', 6,  ['unsigned char']]],
            'ethSrc': [ 0x6, ['array', 6,  ['unsigned char']]],
            'ethType': [ 0x0c, ['unsigned short']],
            'ipVer': [0x0e, ['unsigned char']], 
            'ipCheckSum': [ 0x0e, ['array', 20,  ['unsigned char']]],            
            'ipDSF': [0xf, ['unsigned char']], 
            'ipTotalLen': [0x10, ['unsigned short']], 
            'ipIDENT': [0x12, ['unsigned short']], 
            'ipFLAG': [0x14, ['unsigned char']],
            'ipOffSet': [0x14, ['unsigned short']],         # // ipOffSet = ipFLAG offset + size of 2 bytes
            'ipTTL': [0x16, ['unsigned char']],  
            'ipProtoType': [0x17, ['unsigned char']],  
            'ipChecksum': [0x18, ['unsigned short']],  
            'ipSource': [0x1a, ['IpAddress']],  
            'ipDest': [0x1e, ['IpAddress']],  
             'ipSrcPort' : [0x22, ['unsigned short']],  
             'ipDstPort' : [0x24, ['unsigned short']],  
                            }], 
        }
        profile.vtypes.update(ethVtype)

class FindEthFrame(scan.ScannerCheck):
    """ ScannerCheck to verify the IPv4 protocol, standard header length and protocol """

    def ip_checksum(self, data):
        x = 0 
        y = 0 
        for i in range(0, len(data) - 1, 2):
            y = hexlify(data[i:i+2])
            x+=int(y, 0x10)
        checksum =  hex(x)[2:]
        carry_byte = checksum[0]
        rbytes= checksum[1:] #remainder_bytes
        checksum = int(rbytes, 0x10)+int(carry_byte, 0x10)
        return (~checksum & 0xFFFF)   #verified bytes       


    # // Finds valid packets 
    def check(self, offset):
        
        global counterA 
        global counterB 
        
        eth = obj.Object('ethFrame', vm = self.address_space, offset = offset)
        
        # // IPv4 Check   
        # // Checks the IP version becase the Ethernet type is used in the skip() function below 
        # // 4 = IPv4, 5 is (5 * 20).  The 5 in the combined  to produce the number 0x45 
        # // Note the 5 in 0x45 is not constant.  0x4 is so we check just for 0x4 
        if eth.ipVer >= 0x40 and eth.ipVer <= 0x49:
            counterA += 1
            checksum = ""
            
            # // build the checksum string ipCheckSum is currently an Array 
            for cs in eth.ipCheckSum:
                checksum += chr(cs)
        # // checksum() is used to compute if a packet is vaild based upon the packets header 
        # // The checksum will return 0 if it is a valid packet                 
            checksum = self.ip_checksum(checksum)
            if checksum == 0:
                return eth
            
        # //IPv6 Check 
        #  print "DEBUG",  hex(int(eth.ethType))
        #  //!! UNITY! - convert eth.ethType from long to int with int(eth.ethType)
        #  if int(eth.ethType) == 0x86dd: 
        #  print "DEBUG IPV6"
    
    #// Skip bytes based upon ethertypes from the PacketType Class 
    def skip(self, data, offset):
        try:
            # !this goes through all the ethertypes and searchers for the return key header in the ethertypes dictionary 
            # !probably a cleanerly way of doing this
            for ethHeader in PacketType.ethertypes.keys():
                nstep = struct.pack('>H', ethHeader)
                nextval = data.index(nstep, offset + 1)
                return (nextval-len(nstep)-0xC) - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset            
            
class EthScanner(scan.BaseScanner):
    checks = [('FindEthFrame', {})]

class EthScan(commands.Command):
    """Scans for TCP/UDP packet fragments in memory"""
    
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump executable files')
        config.add_option('SAVE-PCAP', short_option = 'P', default = None,
                          cache_invalidator = False,
                          help = 'Create a pcap file from recovered packets of given name: "Example: -p out.pcap" (requires dpkt)')
        config.add_option("SAVE-RAW", short_option = 'r', default = False, action = 'store_true',
                        help = 'Create binary files of each pcap found in memory based off the packet counter: ')
                        
    def calculate(self):       

        # // sum what redundant method for checking what options have been set easily 
        oplist = ["dump_dir","save_pcap", "save_raw", "ass_cap"]
        dumpDir = 0
        for opkeys in self._config.opts.keys():
            if opkeys in oplist:
                dumpDir = 1 
            else:
                pass  

        # // Check to make sure our dumpdir is real and set 
        # // Check to make sure we have dpkt installed 
        if dumpDir:
            if self._config.DUMP_DIR == None:
                debug.error("Please specify a dump directory (--dump-dir)")
            if not os.path.isdir(self._config.DUMP_DIR):
                debug.error(self._config.DUMP_DIR + " is not a directory")

            if self._config.SAVE_PCAP != None:
                ## Just grab the AS and scan it using our scanner
                if not has_dpkt:
                    debug.error("Install dpkt http://code.google.com/p/dpkt/")

        address_space = utils.load_as(self._config, astype = 'physical')

        for offset in EthScanner().scan(address_space):
            objct = obj.Object('ethFrame', vm = address_space, offset = offset)
            yield  objct

    def render_text(self, outfd, data):
        
        # // dump directory check 
        if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")
            
        # // Set pcap file name
        if self._config.DUMP_DIR and os.path.isdir(self._config.DUMP_DIR) and self._config.SAVE_PCAP:
            pcapfile = self._config.SAVE_PCAP
            if pcapfile[-3:].lower() != "cap":
                pcapfile = pcapfile + ".pcap"
            pcapfile = open(os.path.join(self._config.DUMP_DIR, pcapfile), 'wb')
            pcw = dpkt.pcap.Writer(pcapfile)
                
        counter = 0
        for objct in data:
            source = objct.ipSource.v()
            dest = objct.ipDest.v()
            srcport = str(objct.ipSrcPort.v())
            destport = str(objct.ipDstPort.v())

            #// Packet Size 
            #/ ! ? What is the best way to flip endies from an int 
            #/ ! ? The best solution I found was to conver the int into a hex string 
            #/ ! ? 1) '%04x'% int(objct.ipTotalLen.v())
            #/ ! ? Converts from 0x4e00L to 4e00(str)  
            #/ ! ? 2) struct.unpack("<H",unhexlify(plen)) 
            #/ ! ? Converts raw data as 0x4e <type 'int'>
            #/ ! ? 0x4e00L converts to 0x004e 
            psize = '%04x'% int(objct.ipTotalLen.v())
            psize = struct.unpack("<H",unhexlify(psize))[0]
            pdata = objct.obj_vm.read(objct.ipVer.obj_offset, psize)
            
            # // 0xE the size of 
            # // DST MAC ADDR + SRC MAC ADDR + PACKET TYPE (0x0800 for example)
            # // The IP header starts at 0xE offset which is normally 0x45 (Version + header length) 
            pheader = objct.obj_vm.read(objct.ethDst.obj_offset, 0xe)
            
            #Mac Addr 
            macdst =  objct.obj_vm.read(objct.ethDst.obj_offset, objct.ethSrc.size())       
            macsrc =  objct.obj_vm.read(objct.ethSrc.obj_offset, objct.ethSrc.size())    

            # // Packet ID  (0x800 for example)
            etype = objct.obj_vm.read(objct.ethType.obj_offset, objct.ethType.size())
            
            # // Convert Mac Address by unpacking into fmt string 
            macsrc = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("6B",macsrc)
            macdst = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("6B",macdst)
            
            # // ProtoType Number [17 (0x11) = UDP, 0x6 = TCP] for example
            proto = objct.ipProtoType.v()
                        
            # // Packet Types Class instance to lookup either Ethernet Frame Type or Protocol Type 
            # // Methods: get_prototye(int value) | returns Protocol string description 
            # // Methods: get_ethtype(int value) | returns Frame Type string description 
            ptypes =  PacketType()
            
            # // Gets Protocol String 
            protoStr = ptypes.get_prototye(proto)[0]
            # // Get Ethernet Frame Name and Numeric representation
            ethname,ethnum = ptypes.get_ethtype(etype)
            
            # // create a full packet 
            fullpacket = pheader+pdata

            # // Text Output 
            outfd.write(ethname + " (" + ethnum + ") " + "\n")
            outfd.write("Protocol "+ protoStr + " " + "("+str(proto)+")" + "\n")
            outfd.write("Src: " + source +":" + srcport + " (" +macsrc+"), " + "Dst: " + dest +":" + destport + " (" +macdst+")" +"\n""")            
            outfd.write("Data " + "(" + str(len(pheader+pdata)) + " Bytes" +")" + "\n" )
            
            for offset, hextext, chars in utils.Hexdump(fullpacket):
                outfd.write("{0:#010x}  {1:<48}  {2}\n".format(offset, hextext, ''.join(chars)))
                
            # // Build and save to the pcap file 
            if self._config.SAVE_PCAP:
                eth = dpkt.ethernet.Ethernet(fullpacket)
                pcw.writepkt(eth)

            # // Raw Packets saved to --dump-dir 
            # //Format is PACKET NUM __ visual reminded __ IPSRC __ IP SRCPORT __ DST __IP DESTPORT __ PROTOCOL . BIN  
            # // Example: 0__pktnum__SRC_210.146.64.4_20480__DST_81.131.67.131_42762__TCP.bin
            if self._config.SAVE_RAW:
                filename =  str(counter) + "__pktnum" + "__SRC_" + source +"_" + srcport  +"__DST_" + dest +"_" + destport + "__" + protoStr + ".bin"
                fh = open(os.path.join(self._config.DUMP_DIR, filename), 'wb')
                fh.write(fullpacket)
                fh.close()
                
            outfd.write("\n")
            counter += 1
            
        outfd.write("Packets Found: " + str(counter) + "\n")
        if self._config.SAVE_PCAP:
            pcw.close()
        
