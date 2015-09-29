# -*- coding: utf-8 -*-  
from pydbg import *
from pydbg.defines import *

import struct
import random

def printf_randomizer(dbg):
    parameter_addr = dbg.context.Esp + 0x8;
    counter = dbg.read_process_memory(parameter_addr, 4);
    counter = struct.unpack("L",counter)[0];
    print "Counter:%d" % int(counter);
    random_counter = random.randint(1,100);
    random_counter = struct.pack("L", random_counter)[0];
    dbg.write_process_memory(parameter_addr, random_counter);
    return DBG_CONTINUE;

dbg = pydbg();
pid = int(raw_input("PID:"));
dbg.attach(pid);
printf_address = dbg.func_resolve("msvcrt", "printf");
dbg.bp_set (printf_address, description="printf_address", handler=printf_randomizer);
dbg.run();
