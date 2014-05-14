#This will print zlib compressed data in pcaps regardless of the location in the data area of the packet.   
from libtsron import Tsron 
import sys
import binascii
import zlib 
import string 

offset = 0
zlibheader = "789c"
header = "__libtsron_packet__"
start = 0
zlibstart = 0
zlib_nextoffset = 0 

if __name__ == "__main__":
    try:
        srcpcap = sys.argv[1]
    except IndexError:
	print "python pzcapzlib.py file.pcap "
        sys.exit(2)

tvar = {'typestream': 'TCP', 'header': header, 'srcpcap': srcpcap, 'streamnum': 0, 'display': False, 'outdir': None}
streamObj=Tsron(**tvar)
x = streamObj.TCP()

while offset != -1:
        offset = x.find(header, start)        
        znext = offset + 1
        next_offset = x.find(header, znext)
        start = next_offset

        if offset != -1:
            hexPacket = binascii.b2a_hex(x[offset:next_offset])  #turns data into hex
            hexData = hexPacket.find(zlibheader,0)
            if hexData != -1:
                try:
                    compressed_data = hexPacket[hexData:]
                    try:
                        compressed_data = binascii.unhexlify(compressed_data)
                    except:
                        pass
                    decompressed_data = zlib.decompress(compressed_data)
                    print "\ndecompressed zlib data-> ", decompressed_data
                    dd_printable = filter(lambda x: x in string.printable, decompressed_data)
                    print "***Printable data->", dd_printable
                except zlib.error:
                    pass
