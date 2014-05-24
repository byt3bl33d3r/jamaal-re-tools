# Copyright (C) 2014 Jamaal Speights 
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from libtsron import Tsron 
import sys


header = "__libtsron_packet__"

if __name__ == "__main__":
    try:
        srcpcap = sys.argv[1]
    except IndexError:
	print "python exampletsron.py file.pcap "
        sys.exit(2)


# // targs 
targs = {
'typestream': 'TCP',     # // TCP, UDP or GRE 
'header': header,            # // delimit each packet with a user defined header  
'srcpcap': srcpcap, 	 # // File name of pcap 
'streamnum': 0,          # // 0 stream means all streams
'display': False,        # // Display stream stats 
'outdir': None,          # // output directory to write streams, if not, return streams to variable 
'connheader': False      # // Include connection flow information as apart of the header 
}

streamObj=Tsron(**targs) # // create instance of Tsron 
x = streamObj.TCP()      # // return TCP stream from PCAP to var x 

print x  # // print the raw ordered TCP data :D 

