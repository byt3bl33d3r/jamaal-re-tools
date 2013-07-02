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
import volatility.commands as commands
import volatility.utils as utils
import volatility.scan as scan
import volatility.obj as obj
from binascii import hexlify
from binascii import unhexlify
try:
    import dpkt 
    has_dpkt = True
except ImportError:
    has_dpkt = False


class EthScanVTypes(obj.ProfileModification):
    """Apply structures for IE history parsing"""
    
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):        
        
        ethVtype = {
        'ethFrame': [ 0x0, {
            'ethDst' : [ 0x0, ['array', 6,  ['unsigned char']]],
            'ethSrc': [ 0x6, ['array', 6,  ['unsigned char']]],
            'ethType': [ 0x0c, ['unsigned short']],
            'ethVer': [0x0e, ['unsigned char']], 
            'ipCheckSum': [ 0x0e, ['array', 20,  ['unsigned char']]],            
            'ethDSF': [0xf, ['unsigned char']], 
            'ethTotalLen': [0x10, ['unsigned short']], 
            'ethID': [0x12, ['unsigned short']], 
            'ethFLAG': [0x14, ['unsigned char']],
            'ethOffSet': [0x14, ['unsigned short']],         # // ethOffSet = ethFLAG offset + size of 2 bytes
            'ethTTL': [0x16, ['unsigned char']],  
            'ethProto': [0x17, ['unsigned char']],  
            'ethChecksum': [0x18, ['unsigned short']],  
            'ipSource': [0x1a, ['IpAddress']],  
            'ipDest': [0x1e, ['IpAddress']],  
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

    def check(self, offset):
        eth = obj.Object('ethFrame', vm = self.address_space, offset = offset)
        ethVerStr = '%02x' %  eth.ethVer
        
        if ethVerStr[0] == "4":
            checksum = ""
            for cs in eth.ipCheckSum:
                checksum += chr(cs)
            checksum = self.ip_checksum(checksum)
            if checksum == 0:
                return eth
                
                
    def skip(self, data, offset):
        try:
            nstep = unhexlify("0800") #will be list 
            nextval = data.index(nstep, offset + 1)
            return (nextval-len(nstep)-0xC) - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset            
            
class EthScanner(scan.BaseScanner):
    checks = [('FindEthFrame', {})]

class EthScan(commands.Command):
    """Scans for TCP/UDP packet fragments in memory"""

    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(self._config, astype = 'physical')

        for offset in EthScanner().scan(address_space):
            objct = obj.Object('ethFrame', vm = address_space, offset = offset)
            yield objct,  objct.ipSource.v(), objct.ipDest.v(),  objct.ethTotalLen.v()

    def render_text(self, outfd, data):
        counter = 0
        for objct,  source, dest,  plen in data:

            psize = struct.unpack("<H",unhexlify(hex(int(plen))[2:]))[0]
            pdata = objct.obj_vm.read(objct.ethVer.obj_offset, psize)
            pheader = objct.obj_vm.read(objct.ethSrc.obj_offset, 0xe)
            macsrc =  objct.obj_vm.read(objct.ethSrc.obj_offset, objct.ethSrc.size())    
            macdst =  objct.obj_vm.read(objct.ethDst.obj_offset, objct.ethSrc.size())            
        
            macsrc = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",macsrc)
            macdst = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",macdst)
            proto = objct.ethProto.v()
            protoStr = "Unknown"
            if proto == 6:
                protoStr = "TCP"
            elif proto == 17:
                protoStr = "UDP"

            outfd.write("Src: " + source +" (" +macsrc+"), " + "Dst: " + dest +"(" +macdst+")" +"\n""")            
            outfd.write("Protocol "+ protoStr + " " + str(proto) + "\n" + "Data " + "(" + str(len(pheader+pdata)) + " Bytes" +")" + "\n" )
            for offset, hextext, chars in utils.Hexdump(pheader+pdata):
                outfd.write("{0:#010x}  {1:<48}  {2}\n".format(offset, hextext, ''.join(chars)))
            outfd.write("\n")
            counter += 1
        outfd.write("Total count: " + str(counter) + "\n")
        
