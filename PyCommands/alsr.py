#!/usr/bin/env python
"""
CopyLeft.
"""
import immlib
import getopt
import immutils
import struct
imm = immlib.Debugger()
def main(args):
    imm = immlib.Debugger()
    ALSRwindow = imm.createTable('ALSR',['Module','ALSR']);
    allModules = imm.getAllModules();
    for mod in allModules:
        mzbase = mod.getBaseAddress();
        peoffset = struct.unpack('<L', imm.readMemory(mzbase+0x3c,4))[0];
        pebase = mzbase + peoffset;
        ALSRflag = struct.unpack('<H', imm.readMemory(pebase+0x5e,2))[0];
        if ALSRflag & 0x0040 == 0:
            ALSRresult = 'No';
        else:
            ALSRresult = 'Yes';
        ALSRwindow.add(0, [mod.getName(), ALSRresult]);