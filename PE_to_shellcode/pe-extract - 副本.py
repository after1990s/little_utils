# -*- coding: utf-8 -*-  
import pefile
import sys
from pefile import section_characteristics
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
    if is_va_in_section(dst_rva, section_rva_begin, section_rva_size):
        #计算出rva对于section开始的长度，然后加上section的新偏移值。
        reloc_addr_offset[reloc_item_value] = dst_rva - section_rva_begin + new_offset;
        return True
    return False;
def load_section_contents(pe_load_file, all_sections, section, section_name):
    if section.Name.find(section_name) != -1:
        data = pe_load_file.get_data(section.VirtualAddress, section.Misc_VirtualSize);
        all_sections[section_name] = {'start': section.VirtualAddress,
                                      'size': section.Misc_VirtualSize,
                                      'data': data};
        print "%s_start: 0x%.8x, %s_size: 0x%.4x" % (section_name, section.VirtualAddress,section_name, section.Misc_VirtualSize);
                                      

#将所有seciton的内容集中到sections_list,保存每个section在section_list的开始位置。
#sections保存了各个section的信息。
#仅处理了这些段：rdata,data,idata,bss,crt,tls,text.
#返回值：(shellcode, => .text段的所有内容。
#        reloc_item, 
#        reloc_point_to_item,
#        sections_list,
#        reloc_addr_offset)
def reloc_process(pe_load_file):
    #process reloc 
    base_address = pe_load_file.OPTIONAL_HEADER.ImageBase;
    reloc_item = [];#item includes relative addr, 4 byte size .
    reloc_point_to_item = {};#reloc pointer to itme.
    sections = {};
    for section in pe_load_file.sections:
        load_section_contents(pe_load_file, sections, section, '.rdata');
        load_section_contents(pe_load_file, sections, section, '.data');
        load_section_contents(pe_load_file, sections, section, '.idata');
        load_section_contents(pe_load_file, sections, section, '.bss');
        load_section_contents(pe_load_file, sections, section, '.crt');
        load_section_contents(pe_load_file, sections, section, '.tls');
        load_section_contents(pe_load_file, sections, section, '.text');
        
    sections_list = [];#记录所有section的数据
    next_begin_offset = 0;
    for i in sections:
        if i=='.text':
            continue;
        for byte in sections[i]['data']:
            sections_list.append(byte);
        sections[i]['offset'] = next_begin_offset;
        next_begin_offset += sections[i]['size'];
    
    shellcode_start = sections['.text']['start'];
    reloc_addr_offset = {};#offset from item to the begins of  section(.rdata);        
    #reloc
    for relocs in pe_load_file.DIRECTORY_ENTRY_BASERELOC:
        for entry in relocs.entries:
            #unused reloc info.
            if entry.type == 0: #RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                continue;
            #don't process x64 code.
            if entry.type == 10: # RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                continue;
            reloc_item_offset_from_shellcode = entry.rva - shellcode_start;#记录了一个reloc项相对于shellcode开始的偏移
            reloc_item.append(reloc_item_offset_from_shellcode);
            reloc_item_value = pe_load_file.get_dword_at_rva(entry.rva);
            reloc_item_rva = reloc_item_value - pe_load_file.OPTIONAL_HEADER.ImageBase;#reloc项相对IMAGEBASE的偏移
            
            for i in sections:
                if try_add_offset_to_reloc_item_addr(reloc_addr_offset, 
                                                  reloc_item_rva,
                                                  sections[i]['start'], 
                                                  sections[i]['size'],
                                                  reloc_item_value, 
                                                  sections[i]['offset']):
                    break;
            #这里假设.data段一定在rdata段后面。
        #   3 if reloc_item_rva - data_start >= 0:
         #   int_value = pe_load_file.get_data(reloc_item_rva, 4);
          #      reloc_point_to_item[reloc_item_addr] = int_value;
           # elif reloc_item_rva - rdata_start >= 0:
            #    string_value = pe_load_file.get_data(reloc_item_rva, rdata_size);
             #   str = get_cstring(string_value, 0);
                #reloc_point_to_item[reloc_item_addr] = str;
    shellcode = [];
    for byte in sections['.text']['data']:
        shellcode.append(byte);    
    
  
    print(reloc_point_to_item);  
    return (shellcode, reloc_item, reloc_point_to_item, sections_list, reloc_addr_offset);
    print reloc_item; 

def add_loader_to_shellcode(shellcode, reloc_items, addr_to_strings):
    if reloc_items==0:
        return shellcode;
    loader_size = 21;
    # The format of the new shellcode is:
    #       call    here
    #   here:
    #       ...
    #   shellcode_start:
    #       <shellcode>         (contains offsets to strX (offset are from "here" label))
    #   relocs:
    #       off1|off2|...       (offsets to relocations (offset are from "here" label))
    #       str1|str2|...
    #
    reloc_start_offset = dword_to_bytes(loader_size + len(shellcode));
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
    
    offset_from_begin_to_string = loader_size+ len(shellcode)+ len(reloc_items)*4;
    final_part = [dword_to_string(reloc + loader_size) for reloc in reloc_items];
    addr_to_offset = {};
    #将提取出来的str每一项都加到shellcode尾部，记录其 地址-偏移量 序对的值
    for addr in addr_to_strings.keys():
        string = addr_to_strings[addr];
        final_part.append(string);
        addr_to_offset[addr] = offset_from_begin_to_string
        offset_from_begin_to_string += len(string);
        
    byte_shellcode = [ord(c) for c in shellcode];

    for off in reloc_items:
        addr = bytes_to_dword(byte_shellcode[off:off+4]);
        byte_shellcode[off:off+4] = dword_to_bytes(addr_to_offset[addr]);
    r_shellcode = ''.join([chr(b) for b in (code+byte_shellcode)]) + ''.join(final_part);

    return r_shellcode;
     
#shellcode:未处理的shellcode,reloc_itmes:reloc项目相对于shellcode的偏移。
#sections_list:section的byte集合。
#reloc_addr_offset,每个reloc项。下标是shellcode中的值，值是sections_list的偏移量。
def add_loader_to_shellcode_v2(shellcode,reloc_items, sections_list, reloc_addr_offset):
    if reloc_items==0:
        return shellcode;
    loader_size = 21;
    # The format of the new shellcode is:
    #       call    here
    #   here:
    #       ...
    #   shellcode_start:
    #       <shellcode>         (contains offsets to strX (offset are from "here" label))
    #   relocs:
    #       off1|off2|...       (offsets to relocations (offset are from "here" label))
    #       str1|str2|...
    #
    reloc_start_offset = dword_to_bytes(loader_size + len(shellcode));
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
    
    offset_from_begin_to_sections = loader_size+ len(shellcode)+ len(reloc_items)*4;
    final_part = [dword_to_string(reloc + loader_size) for reloc in reloc_items];
    final_part = final_part+sections_list;
    addr_to_offset = {};
    byte_shellcode = [ord(c) for c in shellcode];
    
    for off in reloc_items:
        addr = bytes_to_dword(byte_shellcode[off:off+4]);
        byte_shellcode[off:off+4] = dword_to_bytes(reloc_addr_offset[addr] + offset_from_begin_to_sections);
    r_shellcode = ''.join([chr(b) for b in (code+byte_shellcode)]) + ''.join(final_part);

    return r_shellcode;
         
def main(pe_name):
    pe_load_file = pefile.PE(pe_name);
    pe_load_file.parse_data_directories();
    print_exe_info(pe_load_file);
#    for entry in pe_load_file.DIRECTORY_ENTRY_IMPORT:
#        print entry.dll;
#        for imp in entry.imports:
#            print '\t', hex(imp.address), imp.name
#    print "entry point:", hex(pe_load_file.OPTIONAL_HEADER.AddressOfEntryPoint);
    for relocs in pe_load_file.DIRECTORY_ENTRY_BASERELOC:
        for entry in relocs.entries:
            if entry.type == 0:
                continue;
            reloc_val = pe_load_file.get_dword_at_rva(entry.rva);
            reloc_val_to_ptr = pe_load_file.get_data(reloc_val - pe_load_file.OPTIONAL_HEADER.ImageBase, 4);
            print "entry reloc: RVA:0x%.8x, length: %d, type:%.2d, value: 0x%.8x, value_pointer %s" % (entry.rva, 4, entry.type, reloc_val, reloc_val_to_ptr);
    
    (shellcode, reloc_item, reloc_point_to_item,sections_list, reloc_addr_offset) = reloc_process(pe_load_file);
    r_shellcode = add_loader_to_shellcode_v2(shellcode,reloc_item,sections_list, reloc_addr_offset);
    print [ord(c) for c in r_shellcode];
def get_cstring(data, offset):#TODO:did not handle unicode .
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
if __name__=='__main__':
    main("E:\\Project\\s.exe");
