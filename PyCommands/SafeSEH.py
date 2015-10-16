#!/usr/bin/env python
"""
CopyLeft.
"""
import immlib
import getopt
import immutils
import struct
imm = immlib.Debugger()
def main(args):#show all modules safeSEH status.
    def addModtoSEHWindow(mod, window, isSafeSEH):
        if isSafeSEH:
            window.add(0, [mod.getName(), 'safeSEH']);
        else:
            window.add(0, [mod.getName(), 'No SafeSEH']);
    allModules = imm.getAllModules();
    SEHWindow = imm.createTable('SafeSEH',['Module','SafeSEH']);
    for mod in allModules:
        mzbase = mod.getBaseAddress();
        peoffset = struct.unpack('<L', imm.readMemory(mzbase+0x3c,4))[0];
        pebase = mzbase + peoffset;
        dllflag = struct.unpack('<H', imm.readMemory(pebase+0x5e,2))[0];
        numberofentries = struct.unpack('<L', imm.readMemory(pebase+0x74,4))[0];
        if numberofentries > 10: #why?
            sectionaddr,sectionsize = struct.unpack('<LL', imm.readMemory(pebase+0x78+8*10, 8));
            sectionaddr += mzbase;
            sectionsize_2 = struct.unpack('<L', imm.readMemory(sectionaddr, 4))[0];
            condition = (sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==sectionsize_2));
            #insert table to result
            addModtoSEHWindow(mod, SEHWindow, condition);