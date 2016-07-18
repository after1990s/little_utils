import pefile
import os
import sys


def calc(file_name, physical_addr):
    pe_load_file = pefile.PE(file_name)
    pe_load_file.parse_data_directories()
    #find physical_addr in which section
    for i in pe_load_file.sections:
        if (physical_addr >= i.PointerToRawData and
            physical_addr <= i.PointerToRawData +i.SizeOfRawData):
            return physical_addr - i.PointerToRawData + i.VirtualAddress
    raise Exception("Bad Para.");

def main():
    if len(sys.argv) != 3:
        print ("pe_physical covert pe file physical address to RVA\nusage:\n pe_physical exe_file physical_addr")
        return
    if sys.argv[2][:2] != "0x":
        print ("physical_addr must be a hex format, like \"0x4000\"")
        return
    target_addr = int(sys.argv[2], 0)
    try:
        target_file_stat = os.stat(sys.argv[1]);
        if (target_file_stat.st_size < target_addr):
            print ("physical_addr too big to file " + sys.argv[1] + ".")
            return
    except WindowsError:
        print ("can't open file "+sys.argv[1]+".")
        return
    print("RVA: " + str(hex(calc(sys.argv[1], target_addr))));
if __name__=="__main__":
    main()