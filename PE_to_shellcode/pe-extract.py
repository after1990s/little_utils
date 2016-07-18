# -*- coding: utf-8 -*-  
#给定一个exe文件，将其转为可以执行的shellcode。处理了重定位表、导入表和data和rdata段。
#exe不能包含自定义的区块信息。
#exe编译时不能开启SEH。
#exe编译时需要使用以下选项： /sdl- /O1 /Ob1 /Oi /Os /GL /GS- /Gy
#exe链接时需要使用以下选项： /MAP /INCREMENTAL:NO /OPT:REF /OPT:ICF /function_order: order.txt
#由于处理导入表和平台相关，需要在哪个平台上运行shellcode，就需要在哪个平台上运行该脚本。
#shellcode加载器需要调用loadlibrary来加载需要的dll Getprocaddress 来加载需要的api
#注意,xp到win7中，psapi.dll的几个函数移入了kernel32.dll，可能会导致shellcode运行异常。
#该shellcode会包含0x00。
import pefile
import sys
from ctypes import *
from _debugger_defines import *
from pefile import section_characteristics
from pydbg.pdx import kernel32
#调试用，检查sections_list的内容是否正确
def check_sections_list(sections, sections_list):
    for i in sections:
        assert (sections[i]['data'][1] == \
                sections_list[sections[i]['offset']+1]);
def fix_shellcode_single_block(shellcode_dict):
    all_op = set(range(1,255));
    bytes = set([ord(c) for c in shellcode_dict]);
    missing_bytes = [b for b in all_op if b not in bytes];
    if len(missing_bytes)== 0:
        return NULL;
    #print missing_bytes;
    
    return shellcode_dict;
#给定一个Virtual Address，判断其是否在对应的section内。地址都是未加IMAGE_BASE的值
def is_va_in_section(va, section_start, section_size):
    return (va >= section_start) and va <= (section_start+section_size) and section_size > 0;

#如果dst_rva在 给定的section中，就在reloc_addr_offset增加一项。下标为shellcode中的地址，值为地址指向的数据在新的section_list中的偏移量。
def try_add_offset_to_reloc_item_addr(reloc_addr_offset, dst_rva, section_rva_begin, section_rva_size,reloc_item_value, new_offset):
    for key in reloc_addr_offset:
        if key == reloc_item_value:
            return True;
    if is_va_in_section(dst_rva, section_rva_begin, section_rva_size):
        #计算出rva对于section开始的长度，然后加上section的新偏移值。
        reloc_addr_offset[reloc_item_value] = dst_rva - section_rva_begin + new_offset;
        return True
    return False;
def load_section_contents(pe_load_file, all_sections, section, section_name):
    if section.Name.find(section_name) == 0:
        data = pe_load_file.get_data(section.VirtualAddress, section.Misc_VirtualSize);
        all_sections[section_name] = {'vastart': section.VirtualAddress,
                                      'size': section.Misc_VirtualSize,
                                      'data': data};
        print "%s_start: 0x%.8x, %s_size: 0x%.4x" % (section_name, section.VirtualAddress,section_name, section.Misc_VirtualSize);

#section_list包括了所有段的数据。
#sectins包括了段数据，段长度，段数据在section_list的起始位置。
def load_pe_sections(pe_load_file):
    base_address = pe_load_file.OPTIONAL_HEADER.ImageBase;

    sections = {};
    for section in pe_load_file.sections:
        load_section_contents(pe_load_file, sections, section, '.text');
        load_section_contents(pe_load_file, sections, section, '.rdata');
        load_section_contents(pe_load_file, sections, section, '.data');
        load_section_contents(pe_load_file, sections, section, '.idata');
        load_section_contents(pe_load_file, sections, section, '.bss');
        load_section_contents(pe_load_file, sections, section, '.crt');
        load_section_contents(pe_load_file, sections, section, '.tls');    
        load_section_contents(pe_load_file, sections, section, '.rsrc');
    sections_list = [];#记录所有除.text外的section的数据
    next_begin_offset = 0;
    
    #section_list先加入.text的信息。
    sections['.text']['offset'] = next_begin_offset;
    for byte in sections['.text']['data']:
        sections_list.append(byte);
        next_begin_offset = next_begin_offset + 1;
    
    for i in sections:
        if i=='.text':
            continue;
        sections[i]['offset'] = next_begin_offset;
        for byte in sections[i]['data']:
            sections_list.append(byte);
            next_begin_offset += 1;
    check_sections_list(sections, sections_list);
    return (sections, sections_list);                    

def calc_reloc_entry_offset_in_sections_list(entry, sections):
    rva = entry.rva;
    for i in sections:
        section_begin = sections[i]['vastart'];
        section_end = sections[i]['vastart']+sections[i]['size'];
        if (rva >= section_begin and rva <= section_end):
            return rva - section_begin + sections[i]['offset'];
    assert(false);

#将所有seciton的内容集中到sections_list,保存每个section在section_list的开始位置。
#sections保存了各个section的信息。
#仅处理了这些段：text,rdata,data,idata,bss,crt,tls,
#返回值(shellcode, reloc_item, reloc_point_to_item, sections_list, reloc_addr_offset)
#.text段的数据保存在shellcode内。
def reloc_process(pe_load_file,sections, sections_list):
    #process reloc 
    
    shellcode_start = sections['.text']['vastart'];
    shellcode_end = shellcode_start + sections['.text']['size'];
    reloc_item = [];#记录了一个reloc项相对于shellcode起始位置的偏移
    reloc_addr_offset = {};#offset from item to the begins of section(.rdata);        
    reloc_text_addr_offset = {}; #text段的reloc信息需要单独处理，因为shellcode中text段在最前面。
    #把每项reloc段的数据在每个section中都尝试处理一次
    for relocs in pe_load_file.DIRECTORY_ENTRY_BASERELOC:
        
        for entry in relocs.entries:
            #unused reloc info.
            if entry.type == 0: #RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                continue;
            #don't process x64 code.
            if entry.type == 10: # RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                continue;
            #if (entry.base_rva < shellcode_start or entry.base_rva > shellcode_end):
            #    print "jump reloc info not in the .text section: 0x%.8x" % entry.base_rva;
            #    continue;
                
            reloc_item_value = pe_load_file.get_dword_at_rva(entry.rva);
            reloc_item_rva = reloc_item_value - pe_load_file.OPTIONAL_HEADER.ImageBase;#reloc项相对IMAGEBASE的偏移            
            reloc_processed = False;
            for i in sections:
                #if i=='.text':
                #    if try_add_offset_to_reloc_item_addr(reloc_addr_offset, 
                #                  reloc_item_rva,
                #                  sections[i]['vastart'], 
                #                  sections[i]['size'],
                #                  reloc_item_value, 
                #                  0):
                #        reloc_processed = True;
                #        break;#该项reloc处理成功
                #continue;
                if try_add_offset_to_reloc_item_addr(reloc_addr_offset, 
                                                  reloc_item_rva,
                                                  sections[i]['vastart'], 
                                                  sections[i]['size'],
                                                  reloc_item_value, 
                                                  sections[i]['offset']):
                    #找到了就在reloc_item中增加该项的记录
                    #print ("reloc entry rva :0x%.8x") % entry.rva;
                    reloc_item_offset_from_shellcode = calc_reloc_entry_offset_in_sections_list(entry, sections);#记录了一个reloc项相对于sections_list开始的偏移
                    #检查reloc_item_value和section_list中的是否一致
                    if  reloc_item_value!= string_to_dword(\
                                           sections_list[reloc_item_offset_from_shellcode:reloc_item_offset_from_shellcode+4]):
                        assert (false);
                    reloc_item.append(reloc_item_offset_from_shellcode);
                    reloc_processed = True;
                    break;#该项reloc处理成功
            if not reloc_processed:#对于在.text段及其之前的reloc信息，需要手动操作。
                #获得数据值
                #reloc_rva = pe_load_file.get_dword_at_rva(entry.rva);
                #reloc_point_to_value = pe_load_file.get_dword_at_rva(reloc_rva);
                #数据存于sections_list尾部,记录偏移
                #value_offset = len (sections_list);
                #sections_list.append(dword_to_bytes(reloc_point_to_value));
                #reloc_addr_offset[reloc_rva] = 偏移 \
                #reloc_addr_offset[reloc_rva] = value_offset;
                #将偏移添加到reloc_item项       
                #reloc_item.append(reloc_rva);
                print "reloc process failed, address 0x%.8x value :0x%.8x" % (entry.rva,reloc_item_value);
                
    shellcode = [];    
    for byte in sections['.text']['data']:
        shellcode.append(byte);    
    
  
 
    return (shellcode, reloc_item,  sections_list, reloc_addr_offset);

def write_dword_to_section_list(va, value, sections, section_list):
    for sec in sections:
        if is_va_in_section(va, sections[sec]['vastart'], sections[sec]['size']):
            off_to_sec_begin = va - sections[sec]['vastart'];
            dst_offset = off_to_sec_begin + sections[sec]['offset'];
            section_list[dst_offset:dst_offset+4] = [chr(b) for b in dword_to_bytes(value)];
            
            return;
#将import table的IAT值替换为正确值。这个IAT值和系统平台相关，因此需要在哪个平台运行shellcode，该脚本也需要在哪个平台上运行。
def import_table_process(pe_load_file, sections, section_list):
    print "process import function."
    kernel32 = windll.kernel32;
    try:
        for import_dll_item in pe_load_file.DIRECTORY_ENTRY_IMPORT:
            dll_module = kernel32.LoadLibraryA(import_dll_item.dll);
            for import_fun_item in import_dll_item.imports:
                fun_addr = kernel32.GetProcAddress(dll_module, import_fun_item.name);
                iat_va = import_fun_item.address - pe_load_file.OPTIONAL_HEADER.ImageBase;
                write_dword_to_section_list(iat_va, fun_addr, sections, section_list)
                #print "funcname: %.25s addr: 0x%.8x dll: %.10s"% (import_fun_item.name, fun_addr, import_dll_item.dll);
                #print "GetProcAddress(Hmod, \"%s\");" % import_fun_item.name;
            print "LoadLibrary(\"%s\");" % import_dll_item.dll;
            print ""
    except AttributeError:
        print "No import table."

    
#sections:所有section的数据和长度。
#sections_list:section的byte集合。包括了.text的代码段。
#reloc_addr_offset,每个reloc项。下标是shellcode中的值，值是sections_list的偏移量。
def add_loader_to_shellcode_v2(sections,reloc_items, sections_list, reloc_addr_offset):
   
    if reloc_items==0:
        return sections_list;
    loader_size = 21;
    # The format of the new shellcode is:
    #       call    here
    #   here:
    #       ...
    #   shellcode_start:
    #       <shellcode>         (contains offsets to strX (offset are from "here" label))
    #       <sction_rdata>
    #       <section_data>...   (contains all sections data)
    #   relocs:
    #       off1|off2|...       (offsets to relocations (offset are from "here" label))
    #       str1|str2|...
    #
    reloc_start_offset = dword_to_bytes(loader_size + len(sections_list));
    reloc_size = dword_to_bytes(len(reloc_items));
    code = [
        0xE8, 0x00, 0x00, 0x00, 0x00,               #   CALL here
                                                    # here:
        0x5E,                                       #   POP ESI
        0x8B, 0xFE,                                 #   MOV EDI, ESI
        0x81, 0xC6, reloc_start_offset[0], reloc_start_offset[1], reloc_start_offset[2], reloc_start_offset[3],         #   ADD ESI, shellcode_start + len(shellcode) - here
        0xB9, reloc_size[0], reloc_size[1], reloc_size[2], reloc_size[3],               #   MOV ECX, len(relocs)
        0xFC,                                       #   CLD
                                                    # again:
        0xAD,                                       #   LODSD
        0x01, 0x3C, 0x07,                           #   ADD [EDI+EAX], EDI
        0xE2, 0xFA                                  #   LOOP again
                                                    # shellcode_start:
    ];
    
    offset_from_begin_to_sections = loader_size + sections['.text']['size'];
    shellcode = sections_list;
    
    final_part = [dword_to_string(reloc + loader_size) for reloc in reloc_items];
    final_part = final_part;
    addr_to_offset = {};
    byte_shellcode = [ord(c) for c in shellcode];
    try:
        for off in reloc_items:
            addr = bytes_to_dword(byte_shellcode[off:off+4]);
            rdda = reloc_addr_offset[addr];
            byte_shellcode[off:off+4] = dword_to_bytes(rdda + loader_size);
    except KeyError:
        print ("key error 0x%.8x ") % addr;
        
    r_shellcode = ''.join([chr(b) for b in (code+byte_shellcode)]) + ''.join(final_part);

    return r_shellcode;
def print_reloc_info(pe_load_file):  
    for relocs in pe_load_file.DIRECTORY_ENTRY_BASERELOC:
        for entry in relocs.entries:
            if entry.type == 0:
                continue;
            reloc_val = pe_load_file.get_dword_at_rva(entry.rva);
            reloc_val_to_ptr = pe_load_file.get_data(reloc_val - pe_load_file.OPTIONAL_HEADER.ImageBase, 4);
            print "entry reloc: RVA:0x%.8x, length: %d, type:%.2d, value: 0x%.8x, value_pointer %s"\
                    % (entry.rva, 4, entry.type, reloc_val, reloc_val_to_ptr);       
def main(pe_name, output_name):
    pe_load_file = pefile.PE(pe_name);
    pe_load_file.parse_data_directories();
    print_exe_info(pe_load_file);
    print_reloc_info(pe_load_file);
    
    (sections, sections_list)=load_pe_sections(pe_load_file)
    import_table_process(pe_load_file, sections, sections_list);
    (shellcode, reloc_item, sections_list, reloc_addr_offset) = \
        reloc_process(pe_load_file, sections, sections_list);
    r_shellcode = add_loader_to_shellcode_v2(sections,reloc_item,sections_list, reloc_addr_offset);
    #print [ord(c) for c in r_shellcode];
    f = open(output_name, 'wb');
    f.write(r_shellcode);
    
def get_cstring(data, offset):
    '''
    Extracts a C string (i.e. null-terminated string) from data starting from offset.
    '''
   
    pos = data.find('\0', offset)
    if pos == -1:
        return None
    return data[offset:pos+1]
 
     
def dword_to_bytes(value):
    return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff]   
def dword_to_string(dword):
    return ''.join([chr(x) for x in dword_to_bytes(dword)])
def print_exe_info(pe_load_file):
    print pe_load_file.dump_info();
def dword_to_bytes(value):
    return [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff]
def bytes_to_dword(bytes):
    return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) | \
           ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24)
def string_to_dword(str):
    bytes = [ord(c) for c in str];
    return (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) | \
           ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24)
if __name__=='__main__':
    #main("e:\\shellcode_framework.exe","e:\\shellcode.bin");
    #main("e:\\Server in VS.exe","e:\\shellcode.bin");
    main("e:\\shellcode_test_gui.exe","e:\\shellcode.bin");
    