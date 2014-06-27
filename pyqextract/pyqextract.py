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
            doffset = unhexlify("03000000020000")  # // data offset starts with 03000000020000 followed by [00 00] size 
            dheader = unhexlify("5A5A5A5A5A5A5A5A72")
            dfooter= unhexlify("A6A5A5A5A7A5A5A5")
            fileheader = unhexlify("03000000020000")
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

            # // Technical we could find the true data lenght at 0x7 bytes to 0x9 [0000]
            # // However I am unsure if this will work on all VBN files 
            # // So we search for the header instead 03000000020000[0000] plus 2 bytes [0000] 
            # // [0000] is the offset to the start of the quarantined file in bytes
            # // [00d4] for example is 0xd4 bytes to the offset plus 0x28 from the start of the file
            # // 0x28 appears to be a static header size
            # // Because doffset "03000000020000" is 0x7 bytes in size, we do doffset + 0x21 to give us the 0x28 offset            
            # // so 0x28 + 0xd4 will give us the offset of the file to decode
            offsetval =  binstr[binstr.rindex(doffset)+7:binstr.rindex(doffset)+9]
            offsetlen = int(hexlify(offsetval),0x10)
            binstr = binstr[binstr.index(doffset)+len(doffset)+0x21+offsetlen:]
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
        print "\nUsage: python %s 578D3452A.VBN outifle"  % (argv[0])
        print "Example: python %s 578D3452A.VBN malware.exe"  % (argv[0])
        print "\t python %s 578D34534.VBN inbox.pst\n"  % (argv[0])
        
if __name__ == "__main__":
    main(sys.argv)
    
