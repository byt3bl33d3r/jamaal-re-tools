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

import volatility.plugins.vadinfo as vadinfo
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.win32 as win32
import volatility.obj as obj

ProtectionDict={
    0: 'NOACCESS',
    1: 'READONLY',
    2: 'EXECUTE',
    3: 'EXECUTE_READ',
    4: 'READWRITE',
    5: 'WRITECOPY',
    6: 'EXECUTE_READWRITE',
    7: 'EXECUTE_WRITECOPY',
    8: 'NOACCESS',
    9: 'NOCACHE | READONLY',
    10:'NOCACHE | EXECUTE',
    11:'NOCACHE | EXECUTE_READ',
    12:'NOCACHE | READWRITE',
    13:'NOCACHE | WRITECOPY',
    14:'NOCACHE | EXECUTE_READWRITE',
    15:'NOCACHE | EXECUTE_WRITECOPY',
    16:'NOACCESS',
    17:'GUARD | READONLY',
    18:'GUARD | EXECUTE',
    19:'GUARD | EXECUTE_READ',
    20:'GUARD | READWRITE',
    21:'GUARD | WRITECOPY',
    22:'GUARD | EXECUTE_READWRITE',
    23:'GUARD | EXECUTE_WRITECOPY',
    24:'NOACCESS',
    25:'WRITECOMBINE | READONLY',
    26:'WRITECOMBINE | EXECUTE',
    27:'WRITECOMBINE | EXECUTE_READ',
    28:'WRITECOMBINE | READWRITE',
    29:'WRITECOMBINE | WRITECOPY',
    30:'WRITECOMBINE | EXECUTE_READWRITE',
    31:'WRITECOMBINE | EXECUTE_WRITECOPY',
    }

parentImageDict = {}
class VADImm(vadinfo.VADInfo):
    """VADInfo rendered using Immunity Debugger layout"""
    def render_text(self, outfd, data):
        for task in data:
            imagename = ""
            outfd.write("*" * 72 + "\n")
            outfd.write("Process: {0}, Pid: {1}\n".format(task.ImageFileName, task.UniqueProcessId))
            
            task_space = task.get_process_address_space()
            if task_space == None:
                result = "Error: Cannot acquire process AS"
            elif task.Peb == None:
                result = "Error: PEB at {0:#x} is paged".format(task.m('Peb'))
            elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
                result = "Error: ImageBaseAddress at {0:#x} is paged".format(task.Peb.ImageBaseAddress)
            else:
                base = task.Peb.ImageBaseAddress
                try:
                    dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = base,
                                    vm = task_space)
                    nt_header = dos_header.get_nt_header()

                    hbase = hex(base).replace("L", "")                    
                    isize = nt_header.OptionalHeader.SizeOfImage
                    tsize = hex(base+ nt_header.OptionalHeader.SizeOfImage).replace("L", "")
                    outfd.write("Image Base: " + hbase + "\nImagize Size: " +  str(isize) + "\nImage Total size: " + tsize +"\n")   
                    outfd.write("\nSections: \n")
                    for sec in nt_header.get_sections(True):
                        secname = str(sec.Name) 
                        secaddr = hex(sec.VirtualAddress + base)
                        outfd.write("\t" + secname + " " +  secaddr + "\n")
                    outfd.write("\n")

                except:
                    pass 

            self.table_header(outfd,
                  [
                   ("Current", "[addrpad]"), 
                   ("-->", "2"),
                   ("Parent", "[addrpad]"), 
                   ("|", "1"),                   
                   ("StartAddr", "[addrpad]"),
                   ("|", "1"),
                   ("Size", "[addrpad]"),       
                   ("|", "1"),
                   ("EndAddr", "[addrpad]"),      
                   ("|", "1"),  
                   ("Owner",  "14"), 
                   ("|", "1"),                                   
                   ("MapType", "8"), 
                   ("|", "1"),                                    
                   ("Commit", "5"), 
                   ("|", "1"),
                   ("Access", "17"),
                   ("|", "1"),                                   
                   ("Filename", "")
                   ])       
                   
            for vad in task.VadRoot.traverse():
                levels = {}

                imagename = ""
                filename = ""
                try:
                    file_obj = vad.ControlArea.FilePointer
                    if file_obj:
                        filename = file_obj.FileName or "Pagefile-backed section"
                        if str(filename) != "Pagefile-backed section":
                            imagename = str(filename).rsplit("\\",1)[-1]
                            parentImageDict[vad.obj_offset] = imagename


                except AttributeError:
                    pass
                mapType = commit = accessStr = ""
                commit = vad.u.VadFlags.CommitCharge if vad.u.VadFlags.CommitCharge < 0x7FFFFFFFFFFFF else -1
                mapType = "Private" if vad.u.VadFlags.PrivateMemory > 0 else "Mapped"
                accessStr = ProtectionDict.get(int(vad.u.VadFlags.Protection))
                if "EXECUTE" in accessStr:
                    mapType = "Image"
        
                pvad = 0
                cvad = 0
                pvad = vad.Parent.obj_offset
                cvad = vad.obj_offset

                if not imagename:
                    imagename = parentImageDict.get(vad.Parent.obj_offset, "")

                self.table_row(outfd, 
                                      cvad, 
                                      "-->", 
                                      pvad, 
                                      "|",                                       
                                      vad.Start,
                                      "|",
                                      vad.Length, 
                                      "|", 
                                      vad.End, 
                                        "|", 
                                      imagename, 
                                        "|", 
                                      mapType, 
                                      "|", 
                                      commit, 
                                      "|",            
                                      accessStr, 
                                      "|",            
                                      filename
                )
                mpi = vad.Parent.obj_offset
