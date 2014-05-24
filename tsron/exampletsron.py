
from libtsron import Tsron 
import sys
import binascii
import zlib 
import string 


header = "__libtsron_packet__"

if __name__ == "__main__":
    try:
        srcpcap = sys.argv[1]
    except IndexError:
	print "python exampletsron.py file.pcap "
        sys.exit(2)


# // targs 
targs = {
'typestream': 'TCP', 
'header': header, 
'srcpcap': srcpcap, 
'streamnum': 0, 
'display': False, 
'outdir': None,
'connheader': False
}

streamObj=Tsron(**tvar)
x = streamObj.TCP()

print x 
