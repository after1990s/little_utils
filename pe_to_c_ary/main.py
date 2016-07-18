from ctypes import *
import sys
kernel32 = windll.kernel32
user32 = windll.user32
def main():
    if len(sys.argv) != 3:
        print """
            usage: exe2code.py exefile tofile
        """

    f = open(sys.argv[1], mode="rb")
    r = open(sys.argv[2], mode="w")

    r.write(str([hex(ord(v)) for v in list(f.read())]).replace('[','{').replace(']','}'));

    f.close();
    r.close();
if __name__ == '__main__':
    main()