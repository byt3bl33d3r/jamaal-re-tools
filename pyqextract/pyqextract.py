# jsqextract.py 
# Symantec quarantine file decoder
# jamaal.speights@gmail.com
# Symantec xor's quarantine executables with 0xA5, while the symantec header is xor'ed with
# 0x5a.  Symantec also adds ODB (OL' DIRTY BYTES) to the executable offsetting the IAT,
# code and data segments.
# jsqextract.py fixes all this
# uncomment out the print header statement to view the header
# version 0.2 

import sys
import os
import binascii
from binascii import *


def main(argv):

    if len(argv)==3:
        try:
            fh = argv[1]
            outh = argv[2]
            dheader = unhexlify("5A5A5A5A5A5A5A5A72")
            dfooter= unhexlify("A6A5A5A5A7A5A5A5")
            mzheader = unhexlify("4D5A900003000000")
            odbA= unhexlify("F6FFEFFFFF")  # // Ol Dirty Bytes
            odbB = unhexlify("F6ABFFFFFF") # // Ol Dirty Bytes
            header = "" 
            binstr = header
            
            infile = open(fh,'rb').read()
            header = infile[infile.find(dheader):infile.find(dfooter)]
            footer = infile[(infile.find(dfooter)):]

            for i in range(len(header)):
                header += chr(0x5a ^ ord(header[i]))

            for i in range(len(footer)):
                binstr += chr(0xA5 ^ ord(footer[i]))

            binstr =  binstr[binstr.find(mzheader):]
            binstr = binstr.replace(odbA,"")
            binstr = binstr.replace(odbB,"")
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
    
