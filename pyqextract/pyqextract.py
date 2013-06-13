# pyqextract.py 
# Symantec quarantine file decoder
# jamaal.speights@gmail.com
# Symantec xor's quarantine executables with 0xA5, while the symantec header is xor'ed with
# 0x5a.  Symantec also adds ODB (OL' DIRTY BYTES) to the executable offsetting the IAT,
# code and data segments.
# pyqextract.py fixes all this
# uncomment out the print header statement to view the header
# v0.1 

import sys
import os
import binascii
from binascii import *


def main(argv):

    if len(argv)==3:
        try:
            fh = argv[1]
            outh = argv[2]
            dheader ="5A5A5A5A5A5A5A5A72"
            dfooter="A6A5A5A5A7A5A5A5"  
            mzheader = "4D5A900003000000"
            odbA= "F6FFEFFFFF"  #ol dirty bytes
            odbB = "F6ABFFFFFF" 
            header = "" 
            binstr = ""
            infile = open(fh,'rb').read()
            infile = hexlify(infile).upper()
            header = infile[infile.find(dheader):(infile.find(dfooter))]
            footer = infile[(infile.find(dfooter)):]
            
            for i in xrange(0, len(header), 2):
                header += "%02x" % (0x5a ^ int(header[i:i+2],0x10))
            #print unhexlify(header)
                
            for i in xrange(0, len(footer), 2):
                binstr += "%02x" % (0xA5 ^ int(footer[i:i+2],0x10))

            header = header.upper()
            binstr = binstr.upper()
            binstr =  binstr[binstr.find(mzheader):]
            binstr = binstr.replace(odbA,"")
            binstr = binstr.replace(odbB,"")
            binstr = unhexlify(binstr)
            if binstr:
                f = open(outh,'wb')
                f.write(binstr)
                f.close()
                print "done..."
        except Exception,e:
            print "failed: ",str(e)


    else:
        print "Usage: python %s 578D3452A.VBN outifle.exe"  % (argv[0])
        
if __name__ == "__main__":
    main(sys.argv)
    
