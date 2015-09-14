import time
from ctypes import *
msvcrt = cdll.msvcrt
count  = 0;
while True:
    msvcrt.printf("loop:%d\r\n", count);
    time.sleep(2);
    count = count + 1;