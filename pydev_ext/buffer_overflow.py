from ctypes import *
msvcrt = cdll.msvcrt
kernel32 = cdll.kernel32

print("PID:%d" % kernel32.GetCurrentProcessId());
raw_input("press any key to continue:");
buffer = c_char_p("AAAAA");
overflow = "A"*100;
msvcrt.strcpy(buffer, overflow);
