import sys
import os
import struct
import leb128
from exception import UnknownMagic, UnsupportBindOpcode
from macho import MACH_O_CPU_TYPE
from fat_header import FatHeader
from mach_header import *
from objc import *

class MachOAnalyzer:
    def __init__(self, file, cpu_type=MACH_O_CPU_TYPE.ARM64):
        self.__fd = file

        try:
            self.__fat_header = FatHeader(self.__fd)

            print 'FAT Mach-O detected'
            fat_arch = self.__fat_header.get_arch(cpu_type)
            if fat_arch == None:
                print 'No arch for', cpu_type, ' in FAT Header'
                fat_arch = self.__fat_header.get_arch()
                print 'Using the first avaiable arch:', fat_arch.get_cpu_type() 
            self.__mh_offset = fat_arch.get_file_offset()
        except UnknownMagic:
            print 'Mach-O detected'
            self.__mh_offset = 0

        self.__mach_header = MachHeader(self.__fd, self.__mh_offset)

        if True == self.__mach_header.is_big_endian():
            self.__endian_str = '>'
        else:
            self.__endian_str = '<'
            
        if True == self.__mach_header.is_64bit_cpu():
            self.__is_64bit_cpu = True
        else:
            self.__is_64bit_cpu = False

        self.__segments = self.__build_segments()

        self.__dylibs = self.__build_load_dylib()

        dyld_info = self.get_dyld_info()

        #pass1: build the import table
        if dyld_info.bind_size != 0:
            #print 'bind pass1'
            self.__build_bind_info(dyld_info.bind_off, dyld_info.bind_size, self.__bind_pass1)

        if dyld_info.weak_bind_size != 0:
            #print 'weak bind pass1'
            self.__build_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, self.__bind_pass1)

        if dyld_info.lazy_bind_size != 0:
            #print 'lazy bind pass1'
            self.__build_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, self.__bind_pass1)

        #build virtual section from the import table
        #TODO revise the data structure for addend
        self.__virtual_section = self.__build_virtual_section()

        #pass2: bind address to virtual section
        if dyld_info.bind_size != 0:
            #print 'bind pass2'
            self.__build_bind_info(dyld_info.bind_off, dyld_info.bind_size, self.__bind_pass2)

        if dyld_info.weak_bind_size != 0:
            #print 'weak bind pass2'
            self.__build_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, self.__bind_pass2)

        if dyld_info.lazy_bind_size != 0:
            #print 'lazy bind pass2'
            self.__build_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, self.__bind_pass2)

        self.__objc2_cls_stack = []
        self.__resloved_objc2_cls_list = []

        self.__objc_classlist = self.__build_objc2_clslist()
        self.__objc_nlclslist = self.__build_objc2_nlclslist()

    '''
    struct segment_command
    {
        unsigned long type;
        unsigned long len;
        char segment_name[16];
        unsigned long vmaddr;
        unsigned long vmsize;
        unsigned long fileoff;
        unsigned long filesize;
        unsigned long maxprot;
        unsigned long initprot;
        unsigned long nsects;
        unsigned long flags;
    }
    
    struct segment_command_64
    {
        unsigned long type;
        unsigned long len;
        char segment_name[16];
        unsigned long long vmaddr;
        unsigned long long vmsize;
        unsigned long long fileoff;
        unsigned long long filesize;
        unsigned long maxprot;
        unsigned long initprot;
        unsigned long nsects;
        unsigned long flags;
    }

    struct section
    {
        char section_name[16];
        char segment_name[16];
        unsigned long addr;
        unsigned long size;
        unsigned long offset;
        unsigned long alignment;
        unsigned long reloff;
        unsigned long nreloc
        unsigned long flags;
        unsigned long reserved1;
        unsigned long reserved2;
    }
    
    struct section_64
    {
        char section_name[16];
        char segment_name[16];
        unsigned long long addr;
        unsigned long long size;
        unsigned long offset;
        unsigned long alignment;
        unsigned long reloff;
        unsigned long nreloc
        unsigned long flags;
        unsigned long reserved1;
        unsigned long reserved2;
        unsigned long reserved3;
    }
    '''
    #Build Segment and section list in memory
    def __build_segments(self):
        n_lcmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + self.__mach_header.get_hdr_len())

        segments = []
        for i in range(n_lcmds):
            type, len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            if self.__is_64bit_cpu == True and MACH_O_LOAD_COMMAND_TYPE(type) == MACH_O_LOAD_COMMAND_TYPE.SEGMENT_64:
                name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags = \
                    struct.unpack(self.__endian_str + '16sQQQQLLLL', self.__fd.read(64))
                name = name.strip('\x00')
                segment = Segment(name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags)
                segments.append(segment)
                
                for j in range(nsects):
                    sec_name, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3 = \
                        struct.unpack(self.__endian_str + '16s16sQQLLLLLLLL', self.__fd.read(80))
                    sec_name = sec_name.strip('\x00')
                    section = Section(sec_name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3)
                    segment.append_section(section)
                    
            elif self.__is_64bit_cpu == False and MACH_O_LOAD_COMMAND_TYPE(type) == MACH_O_LOAD_COMMAND_TYPE.SEGMENT:
                name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags = \
                    struct.unpack(self.__endian_str + '16sLLLLLLLL', self.__fd.read(48))
                name = name.strip('\x00')
                segment = Segment(name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags)
                segments.append(segment)

                for j in range(nsects):
                    sec_name, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2 = \
                        struct.unpack(self.__endian_str + '16s16sLLLLLLLLL', self.__fd.read(68))
                    sec_name = sec_name.strip('\x00')
                    section = Section(sec_name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2)
                    segment.append_section(section)
            else:
                self.__fd.seek(len - 8, os.SEEK_CUR)

        for segment in segments:
            for section in segment.sections:
                self.__fd.seek(self.__mh_offset + section.offset)
                section.buf_data(self.__fd.read(section.vmsize))
                
        return segments
                
    '''
    struct load_dylib
    {
        unsigned long type;
        unsigned long len;
        unsigned long name_off;
        unsigned long timestamp;
        unsigned long current_ver;
        unsigned long compat_ver;
        char lib_name[];
    }
    '''
    #Build dylib name list from LC_LOAD_DYLIB
    def __build_load_dylib(self):
        #skip mach header to load commands
        offset = self.__mach_header.get_hdr_len()
        n_cmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + offset)

        dylibs = []
        dylib_cmd_count = 0
        for i in range(n_cmds):
            type, lc_len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            if (MACH_O_LOAD_COMMAND_TYPE(type) == MACH_O_LOAD_COMMAND_TYPE.LOAD_DYLIB) or \
                (MACH_O_LOAD_COMMAND_TYPE(type) == MACH_O_LOAD_COMMAND_TYPE.WEAK_DYLIB):
                off, ts, cur_ver, compat_ver = struct.unpack(self.__endian_str + 'LLLL', self.__fd.read(16))

                c_str = ''
                while True:
                    c = self.__fd.read(1)
                    if ord(c) == 0:
                        break
                    c_str = c_str + c

                self.__fd.seek(lc_len - 8 - 16 - len(c_str) - 1, os.SEEK_CUR)
                
                dylib = DYLib(ts, cur_ver, compat_ver, c_str)
                dylibs.append(dylib)
            else:
                self.__fd.seek(lc_len - 8, os.SEEK_CUR)
        return dylibs

    def get_dylib(self, lib_idx):
        return self.__dylibs[lib_idx]
        pass

    '''
    struct dyld_info
    {
        unsigned long type;
        unsigned long len;
        unsigned long rebase_off;
        unsigned long rebase_size;
        unsigned long bind_off;
        unsigned long bind_size;
        unsigned long week_bind_off;
        unsigned long week_bind_size;
        unsigned long lazy_bind_off;
        unsigned long lazy_bind_size;
        unsigned long export_off;
        unsigned long export_size;
    }
    '''
    #Search for segment LOAD_COMMAND_DYLD_INFO and return its fields
    def get_dyld_info(self):
        offset = self.__mach_header.get_hdr_len()
        n_cmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + offset)

        rebase_off = 0
        rebase_size = 0
        bind_off = 0
        bind_size = 0
        weak_bind_off = 0
        weak_bind_size = 0
        lazy_bind_off = 0
        lazy_bind_size = 0
        export_off = 0
        export_size = 0
        for i in range(n_cmds):
            type, len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))

            if MACH_O_LOAD_COMMAND_TYPE(type) == MACH_O_LOAD_COMMAND_TYPE.DYLD_INFO:
                rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size \
                    = struct.unpack(self.__endian_str + 'LLLLLLLLLL', self.__fd.read(40))
                break
            else:
                self.__fd.seek(len - 8, os.SEEK_CUR)
        
        dyld_info = DYLDInfo(rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size)
        return dyld_info

    #Load binding information and build up a binding table which is a list of vmaddr to imported symbol mapping
    #This is a simple implementation
    #Many Object-C data structure are fixed up based on binding information. The binding table must be loaded before analyzing and dumping Object-C data.
    def __build_bind_info(self, bind_off, bind_size, bind_function):
        self.__fd.seek(self.__mh_offset + bind_off)
        bind_data = self.__fd.read(bind_size)
        library = None
        bind_item = []
        bind_list = []

        i = 0
        #Deal with bind command without set dylib ordinal
        lib_ordinal = 1
        value = None
        len = None
        symbol = None
        type = None
        addend = 0
        seg_idx = None
        seg_off = None
        addr = None
        count = None
        skip = None
        while i < bind_size:
            byte = bind_data[i]
            opcode = ord(byte) & DYLD_INFO_BIND_OPCODE.OPCODE_MASK.value
            opcode = DYLD_INFO_BIND_OPCODE(opcode)
            imm = ord(byte) & DYLD_INFO_BIND_OPCODE.IMMEDIATE_MASK.value

            debug_str = '[0x{:x}] 0x{:x}:'.format(i, ord(byte))
            i = i + 1
            if opcode == DYLD_INFO_BIND_OPCODE.DONE:

                debug_str = debug_str + 'bind done'
                #print debug_str

                return
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_ORDINAL_IMM:
                lib_ordinal = imm
                
                debug_str = debug_str + 'set library oridinal imm: {:d}'.format(lib_ordinal)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_ORDINAL_ULEB:
                value, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                lib_ordinal = value
                i = i + len
                
                debug_str = debug_str + 'set library oridinal uleb: 0x{:x}'.format(lib_ordinal)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_SPECIAL_IMM:
                #Have no idea about how to handle negative or zero library ordinal
                #So print and raise an exception here
                if imm != 0:
                    lib_ordinal = imm | DYLD_INFO_BIND_OPCODE.OPCODE_MASK
                else:
                    lib_ordinal = imm

                debug_str = debug_str + 'set library oridinal special imm: 0x{:x}'.format(lib_ordinal)
                #print debug_str
                raise UnsupportBindOpcode(byte)
                    
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbol = ''
                while ord(bind_data[i]) != 0:
                    symbol = symbol + bind_data[i]
                    i = i + 1
                i = i + 1

                debug_str = debug_str + 'set symbol imm: 0x{:x}, {:s}'.format(imm, symbol)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_TYPE_IMM:
                type = imm

                debug_str = debug_str + 'set type imm: 0x{:x}'.format(type)
                #print debug_str

                if DYLD_INFO_BIND_TYPE(type) != DYLD_INFO_BIND_TYPE.POINTER:
                    raise UnsupportBindOpcode(byte)
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_ADDEND_SLEB:
                #TODO: Add support for non zero addend
                #The virtual section data structure need to be revised
                addend, len = leb128.decode_sleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                debug_str = debug_str + 'set addend sleb: 0x{:x}'.format(addend)
                #print debug_str

                #raise UnsupportBindOpcode(byte)
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_SEGMENT_AND_OFFSET_ULEB:
                seg_idx = imm
                seg_off, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                debug_str = debug_str + 'set segment: {:d} and offset 0x{:x}'.format(seg_idx, seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.ADD_ADDR_ULEB:
                addr, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len
                #it's actually signed long long
                if addr & 0x8000000000000000:
                    addr = -((addr - 1) ^ 0xFFFFFFFFFFFFFFFF)
                seg_off = seg_off + addr

                debug_str = debug_str + 'add addr uleb: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + 8
                else:
                    seg_off = seg_off + 4

                debug_str = debug_str + 'do bind, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ADD_ADDR_ULEB:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + 8
                else:
                    seg_off = seg_off + 4
                
                addr, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                if addr & 0x8000000000000000:
                    addr = -((addr - 1) ^ 0xFFFFFFFFFFFFFFFF)
                i = i + len
                seg_off = seg_off + addr

                debug_str = debug_str + 'do bind add addr uleb, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ADD_ADDR_IMM_SCALED:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + (imm + 1)* 8
                else:
                    seg_off = seg_off + (imm + 1) * 4

                debug_str = debug_str + 'do bind add addr imm scaled, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len
                skip, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                for j in range(count):
                    bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                    if self.__is_64bit_cpu == True:
                        seg_off = seg_off + skip + 8
                    else:
                        seg_off = seg_off + skip + 4

                debug_str = debug_str + 'do bind ulbe times ({:d}) skipping uleb ({:d}), offset is now: 0x{:x}'.format(count, skip, seg_off)
                #print debug_str
            else:
                raise UnsupportBindOpcode(byte)
        #bind commands without end
        print 'bind commands without end'
        return

    #Search for segment  LOAD_COMMAND_SEGMENT or LOAD_COMMAND_SEGMENT64 with segment index
    #Generally __ZEROPAGE is indexed by 0, __TEXT by 1, __DATA by 2 and __LINKEDIT by 3
    def get_segment(self, seg_idx):
        return self.__segments[seg_idx]
    
    def get_section_by_addr(self, seg_idx, seg_off):
        size = 0
        for section in self.__segments[seg_idx].sections:
            size = size + section.vmsize
            if seg_off < size:
                return section

    def __bind_pass1(self, seg_idx, seg_off, type, lib_ordinal, addend, symbol):
        dylib = self.get_dylib(lib_ordinal - 1)
        dylib.append_symbol(symbol)
        
    def __bind_pass2(self, seg_idx, seg_off, type, lib_ordinal, addend, symbol):
        segment = self.get_segment(seg_idx)
        section = self.get_section_by_addr(seg_idx, seg_off)
        symbol_addr = self.get_virtual_map_addr(symbol)

        position = seg_off - (section.vmaddr - segment.vmaddr)
        if self.__is_64bit_cpu == True:
            length = 8
            addr_str = struct.pack(self.__endian_str + 'Q', symbol_addr)
        else:
            length = 4
            addr_str = struct.pack(self.__endian_str + 'L', symbol_addr)

        #TODO: addend
        data = section.data[0 : position] + addr_str + section.data[position + length:]
        section.data = data
        #print '0x{:X} binding to 0x{:X}:{:s}+{:d}'.format(segment.vmaddr + seg_off, symbol_addr, symbol, addend)

    def dump_import_table(self):
        for dylib in self.__dylibs:
            print dylib.name
            for symbol in dylib.symbols:
                print '    ', symbol

    def __build_virtual_section(self):
        segment = self.__segments[-1]
        addr = segment.vmaddr + segment.vmsize

        vsec = []
        for dylib in self.__dylibs:
            for symbol in dylib.symbols:
                vmap = VirtualMap(addr, symbol)
                vsec.append(vmap)
                if self.__is_64bit_cpu == True:
                    addr = addr + 8
                else:
                    addr = addr + 4
        return vsec

    def is_virtual_section_addr(self, addr):
        return addr >= self.__virtual_section[0].addr
        
    def get_virtual_map_addr(self, symbol):
        for vmap in self.__virtual_section:
            if symbol == vmap.symbol:
                return vmap.addr

    def get_virtual_map_symbol(self, addr):
        if self.is_virtual_section_addr(addr):
            if self.__is_64bit_cpu == True:
                idx = (addr - self.__virtual_section[0].addr) / 8
            else:
                idx = (addr - self.__virtual_section[0].addr) / 4
            return self.__virtual_section[idx].symbol
        return None
        

    def dump_virtual_section(self):
        for vmap in self.__virtual_section:
            print '0x{:X}:{:s}'.format(vmap.addr, vmap.symbol)
    
    #Search a section with segment name and section name
    def get_section_by_name(self, seg_name, sec_name):
        for segment in self.__segments:
            if seg_name == segment.name:
                for section in segment.sections:
                    if sec_name == section.name:
                        return section
        return None

    def get_objc2_ivar_layout(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_classname')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        ivar_layout = ord(section.data[position])
        return ivar_layout
        
    def get_objc2_cls_name(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_classname')
        assert vmaddr < (section.vmaddr + section.vmsize)
        
        position = vmaddr - section.vmaddr
        c_str = ''
        
        while True:
            c = section.data[position]
            position = position + 1
            if ord(c) == 0:
                break
            c_str = c_str + c
        return c_str
    
    def get_objc2_method_name(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_methname')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        i = 0
        c_str = ''
        while True:
            c = section.data[position]
            position = position + 1
            if ord(c) == 0:
                break
            c_str = c_str + c
        return c_str

    def get_objc2_method_type(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_methtype')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        i = 0
        c_str = ''
        while True:
            c = section.data[position]
            position = position + 1
            if ord(c) == 0:
                break
            c_str = c_str + c
        return c_str

    '''
    struct objc2_meth
    {
        vmaddr sel_ptr;
        vmaddr type_ptr;
        vmaddr imp_ptr;
    }
    struct objc2_meth_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_meth first;
    }
    '''
    def get_objc2_methods(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position: position + 8:])
        position = position + 8

        method_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                sel_ptr, type_ptr, imp_ptr = struct.unpack(self.__endian_str + 'QQQ', section.data[position: position + entry_size:])
            else:
                sel_ptr, type_ptr, imp_ptr = struct.unpack(self.__endian_str + 'LLL', section.data[position: position + entry_size:])
            position = position + entry_size
            
            meth_name = self.get_objc2_method_name(sel_ptr)
            meth_type = self.get_objc2_method_type(type_ptr)
            imp_addr = '0x{:X}'.format(imp_ptr)
            
            objc2_meth = ObjC2Method(meth_name, meth_type, imp_addr)
            method_list.append(objc2_meth)

        return method_list

    def get_objc2_protocols(self, vmaddr):
        pass

    def get_objc2_ivar_offset(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_ivar')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        offset, = struct.unpack(self.__endian_str + 'L', section.data[position: position + 4])
        return offset
        
    '''
    struct objc2_ivar
    {
        vmaddr offset_ptr;
        vmaddr name_ptr;
        vmaddr type_ptr;
        unsigned long alignment;
        unsigned long size;
    }
    struct objc2_ivar_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_ivar first;
    }
    ''' 
    def get_objc2_ivars(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position : position + 8])
        position = position + 8

        ivar_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                offset_ptr, name_ptr, type_ptr, alignment, size = struct.unpack(self.__endian_str + 'QQQLL', section.data[position : position + entry_size])
            else:
                offset_ptr, name_ptr, type_ptr, alignment, size = struct.unpack(self.__endian_str + 'LLLLL', section.data[position : position + entry_size])
            position = position + entry_size

            offset = self.get_objc2_ivar_offset(offset_ptr)
            meth_name = self.get_objc2_method_name(name_ptr)
            meth_type = self.get_objc2_method_type(type_ptr)

            objc2_ivar = ObjC2IVar(offset, meth_name, meth_type, alignment, size)
            
            ivar_list.append(objc2_ivar)

        return ivar_list

    def get_cstring(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__cstring')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        c_str = ''
        while True:
            c = section.data[position]
            position = position + 1
            if ord(c) == 0:
                break
            c_str = c_str + c
        return c_str
    
    '''
    struct objc2_property
    {
        vmaddr name_ptr;
        vmaddr attr_ptr;
    };

    struct objc2_prop_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_prop first;
    };
    '''
    def get_objc2_properties(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position : position + 8])
        position = position + 8

        prop_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                name_ptr, attr_ptr = struct.unpack(self.__endian_str + 'QQ', section.data[position : position + entry_size])
            else:
                name_ptr, attr_ptr = struct.unpack(self.__endian_str + 'LL', section.data[position : position + entry_size])
            position = position + entry_size

            name = self.get_cstring(name_ptr)
            attr = self.get_cstring(attr_ptr)
            objc2_property = ObjC2Property(name, attr)

            prop_list.append(objc2_property)
            
        return prop_list
        
    '''
    struct objc2_class_ro {
        uint32_t flags;
        uint32_t instanceStart;
        uint32_t instanceSize;
        uint32_t reserved; // *** this field does not exist in the 32-bit version ***
        vmaddr ivar_layout_ptr;
        vmaddr cls_name_ptr;
        vmaddr base_methods_ptr;
        vmaddr base_protocols_ptr;
        vmaddr ivars_ptr;
        vmaddr weak_ivar_layout_ptr;
        vmaddr base_properties_ptr;
    };
    '''
    def __build_objc2_cls_ro(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        flags, inst_start, inst_size = struct.unpack(self.__endian_str + 'LLL', section.data[position : position + 12])
        position = position + 12
        
        if self.__is_64bit_cpu == True:
            reserved, ivar_layout_ptr, cls_name_ptr, base_methods_ptr, base_protocols_ptr, ivars_ptr, weak_ivar_layout_ptr, base_properties_ptr = \
                struct.unpack(self.__endian_str + 'LQQQQQQQ', section.data[position : position + 60])
        else:
            ivar_layout_ptr, cls_name_ptr, base_methods_ptr, base_protocols_ptr, ivars_ptr, weak_ivar_layout_ptr, base_properties_ptr = \
                struct.unpack(self.__endian_str + 'LLLLLLL', section.data[position : position + 28])
            reserved = None
        

        if ivar_layout_ptr != 0:
            ivar_layout = self.get_objc2_ivar_layout(ivar_layout_ptr)
        else:
            ivar_layout = None

        if cls_name_ptr != 0:
            cls_name = self.get_objc2_cls_name(cls_name_ptr)
        else:
            cls_name = None

        if base_methods_ptr != 0:
            methods = self.get_objc2_methods(base_methods_ptr)
        else:
            methods = None

        if base_protocols_ptr != 0:
            self.get_objc2_protocols(base_protocols_ptr)

        if ivars_ptr != 0:
            ivars = self.get_objc2_ivars(ivars_ptr)
        else:
            ivars = None

        if weak_ivar_layout_ptr != 0:
            weak_ivar_layout = self.get_objc2_ivar_layout(weak_ivar_layout_ptr)
        else:
            weak_ivar_layout = None

        if base_properties_ptr != 0:
            properties = self.get_objc2_properties(base_properties_ptr)
        else:
            properties = None

        return ObjC2ClassRO(flags, inst_start, inst_size, ivar_layout, cls_name, methods, ivars, weak_ivar_layout, properties, reserved)
    
    '''
    struct objc2_class {
        vmaddr isa_ptr;
        vmaddr superclass_ptr;
        vmaddr cache_ptr;
        vmaddr vtable_ptr;
        vmaddr data_ptr; //objc2_class_ro
    }
    
    '''
    def __build_objc2_cls(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_data')
        assert vmaddr < (section.vmaddr + section.vmsize)

        if vmaddr in self.__objc2_cls_stack:
            return None
        else:
            self.__objc2_cls_stack.append(vmaddr)
        
        position = vmaddr - section.vmaddr
        if self.__is_64bit_cpu == True:
            isa_ptr, superclass_ptr, cache_ptr, vtable_ptr, data_ptr = \
                struct.unpack(self.__endian_str + 'QQQQQ', section.data[position : position + 40])
        else:
            isa_ptr, superclass_ptr, cache_ptr, vtable_ptr, data_ptr = \
                struct.unpack(self.__endian_str + 'LLLLL', section.data[position : position + 20])

        objc2_cls_ro = self.__build_objc2_cls_ro(data_ptr)
        objc2_class = ObjC2Class(vmaddr, objc2_cls_ro)
        self.__resloved_objc2_cls_list.append(objc2_class)

        isa = None
        if self.is_virtual_section_addr(isa_ptr):
            isa_name = self.get_virtual_map_symbol(isa_ptr)
        elif isa_ptr != 0:
            isa = self.__build_objc2_cls(isa_ptr)
            if isa == None:
                for resloved_cls in self.__resloved_objc2_cls_list:
                    if isa_ptr == resloved_cls.vmaddr:
                        isa_name = resloved_cls.name
                        break
            else:
                isa_name = isa.name
        else:
            isa_name = '{:d}'.format(isa_ptr)

        objc2_class.isa = isa
        objc2_class.isa_name = isa_name

        superclass = None
        if self.is_virtual_section_addr(superclass_ptr):
            superclass_name = self.get_virtual_map_symbol(superclass_ptr)
        elif superclass_ptr != 0:
            superclass = self.__build_objc2_cls(superclass_ptr)
            if superclass == None:
                for resloved_cls in self.__resloved_objc2_cls_list:
                    if superclass_ptr == resloved_cls.vmaddr:
                        superclass_name = resloved_cls.name
                        break
            else:
                superclass_name = superclass.name
        else:
            superclass_name = '{:d}'.format(superclass_ptr)

        objc2_class.superclass = superclass
        objc2_class.superclass_name = superclass_name
                
        if self.is_virtual_section_addr(cache_ptr):
            cache_name = self.get_virtual_map_symbol(cache_ptr)
        else:
            cache_name = '{:d}'.format(cache_ptr)
        objc2_class.cache_name = cache_name

        if self.is_virtual_section_addr(vtable_ptr):
            vtable_name = self.get_virtual_map_symbol(vtable_ptr)
        else:
            vtable_name = '{:d}'.format(vtable_ptr)
        objc2_class.vtable_name = vtable_name

        self.__objc2_cls_stack.pop()
        return objc2_class
        
    def __build_objc2_clslist(self):
        section = self.get_section_by_name('__DATA', '__objc_classlist')

        if self.__is_64bit_cpu == True:
            n_cls = section.vmsize / 8
        else:
            n_cls = section.vmsize / 4

        cls_list = []
        position = 0
        for i in range(n_cls):
            if self.__is_64bit_cpu == True:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + 8 :])
                position = position + 8
            else:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'L', section.data[position : position + 4 :])
                position = position + 4
            objc2_cls = self.__build_objc2_cls(objc2_cls_ptr)
            cls_list.append(objc2_cls)

        return cls_list

    def __build_objc2_nlclslist(self):
        section = self.get_section_by_name('__DATA', '__objc_nlclslist')

        if self.__is_64bit_cpu == True:
            n_cls = section.vmsize / 8
        else:
            n_cls = section.vmsize / 4

        cls_list = []
        position = 0
        for i in range(n_cls):
            if self.__is_64bit_cpu == True:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + 8 :])
                position = position + 8
            else:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'L', section.data[position : position + 4 :])
                position = position + 4
            objc2_cls = self.__build_objc2_cls(objc2_cls_ptr)
            cls_list.append(objc2_cls)

        return cls_list

    def __build_objc2_protolist(self):
        section = self.get_section_by_name('__DATA', '__objc_protolist')
        if self.__is_64bit_cpu == True:
            n_proto = section.vmsize / 8
        else:
            n_proto = section.vmsize / 4

        proto_list = []
        #TODO

    def dump_objc_classlist(self):
        for objc_class in self.__objc_classlist:
            objc_class.dump()

    def dump_objc_nlclslist(self):
        for objc_class in self.__objc_nlclslist:
            objc_class.dump()

    def dump_section_objc_selrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_selrefs')

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize/ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            method_name = self.get_objc2_method_name(ref)
            print '0x{:X}: __objc_methname(\'{:s}\')'.format(address, method_name)
            address = address + ref_size

    def get_objc_class_ref(self, vmaddr):
        for objc_class in self.__objc_classlist:
            if vmaddr == objc_class.vmaddr:
                return objc_class
        
        for objc_class in self.__objc_nlclslist:
            if vmaddr == objc_class.vmaddr:
                return objc_class

        return None
        
    def dump_section_objc_classrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_classrefs')

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize/ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            if self.is_virtual_section_addr(ref):
                class_name = self.get_virtual_map_symbol(ref)
            else:
                objc_class = self.get_objc_class_ref(ref)
                class_name = objc_class.name
            print '0x{:X}: {:s}'.format(address, class_name)
            address = address + ref_size

    def dump_section_objc_superrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_superrefs')

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize/ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            if self.is_virtual_section_addr(ref):
                class_name = self.get_virtual_map_symbol(ref)
            else:
                objc_class = self.get_objc_class_ref(ref)
                class_name = objc_class.name
            print '0x{:X}: {:s}'.format(address, class_name)
            address = address + ref_size

    def dump_section_objc_ivar(self):
        section = self.get_section_by_name('__DATA', '__objc_ivar')

        ivar_size = 4
            
        nivar = section.vmsize/ivar_size

        address = section.vmaddr
        for i in range(nivar):
            position = address - section.vmaddr
            ivar, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ivar_size])

            print '0x{:X}: 0x{:X}'.format(address, ivar)
            address = address + ivar_size

    '''
    struct __NSConstantStringImpl
    {
        vmaddr isa;
        unsigned long flags;
        vmaddr str;
        unsigned long length;
    }
    
    struct __NSConstantStringImpl64
    {
        vmaddr isa;
        unsigned long long flags;
        vmaddr str;
        unsigned long long length;
    }
    '''
    def dump_section_cfstring(self):
        section = self.get_section_by_name('__DATA', '__cfstring')

        if self.__is_64bit_cpu == True:
            cfstring_size = 32
        else:
            cfstring_size = 16
            
        ncfstring = section.vmsize/cfstring_size

        address = section.vmaddr
        for i in range(ncfstring):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                isa, flags, str, length = struct.unpack(self.__endian_str + 'QQQQ', section.data[position : position + cfstring_size])
            else:
                isa, flags, str, length = struct.unpack(self.__endian_str + 'LLLL', section.data[position : position + cfstring_size])

            if self.is_virtual_section_addr(isa):
                isa_name = self.get_virtual_map_symbol(isa)
            else:
                isa_name = '0x:{:X}'.format(isa)

            c_str = self.get_cstring(str)

            print '0x{:X}: __CFString<{:s}, 0x{:X}, \'{:s}\', {:d}>'.format(address, isa_name, flags, c_str, length)
            address = address + cfstring_size

def main():
    from optparse import OptionParser

    parser = OptionParser(usage='usage: %prog [options] file', version='%prog 0.01')
    
    parser.add_option('-a', '--arch', action='store', dest='arch', \
        type='choice', choices=['arm', 'aarch64', 'i386', 'x86_64'], default='aarch64', help='specify an arch to dump, aarch64 is specified by default, applicable only for FAT Mach-O file')

    parser.add_option('-l', '--all', action='store_true', dest='dump_all', default=False, help='dump all')
    parser.add_option('-c', '--classlist', action='store_true', dest='dump_clslist', default=False, help='dump section __objc_classlist')
    parser.add_option('-n', '--nlclslist', action='store_true', dest='dump_nlclslist', default=False, help='dump section __objc_nlclslist')
    parser.add_option('-s', '--selrefs', action='store_true', dest='dump_selrefs', default=False, help='dump section __objc_selrefs')
    parser.add_option('-r', '--classrefs', action='store_true', dest='dump_classrefs', default=False, help='dump section __objc_classrefs')
    parser.add_option('-u', '--superrefs', action='store_true', dest='dump_superrefs', default=False, help='dump section __objc_superrefs')
    parser.add_option('-i', '--ivar', action='store_true', dest='dump_ivar', default=False, help='dump section __objc_ivar')
    parser.add_option('-f', '--cfstring', action='store_true', dest='dump_cfstring', default=False, help='dump section __cfstring')
    parser.add_option('-m', '--import_table', action='store_true', dest='dump_import_table', default=False, help='dump all imported symbols')
    parser.add_option('-v', '--virtual_section', action='store_true', dest='dump_vsection', default=False, help='dump virtual section for dynamic binding')
    
    options, args = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit(0)
    
    file = args[0]

    arch = None
    if options.arch == 'aarch64':
        arch = MACH_O_CPU_TYPE.ARM64
    elif options.arch == 'arm':
        arch = MACH_O_CPU_TYPE.ARM
    elif options.arch == 'i386':
        arch = MACH_O_CPU_TYPE.I386
    elif options.arch == 'x86_64':
        arch = MACH_O_CPU_TYPE.X86_64
    else:
        print 'Unknown arch selected, fallback to aarch64'
        arch = MACH_O_CPU_TYPE.ARM64

    if options.dump_all == True:
        options.dump_clslist = True
        options.dump_nlclslist = True
        options.dump_selrefs = True
        options.dump_classrefs = True
        options.dump_superrefs = True
        options.dump_ivar = True
        options.dump_cfstring = True
        options.dump_import_table = True
        options.dump_vsection = True
    
    fd = open(file, 'rb')
    try:
        mach_o_anylyzer = MachOAnalyzer(fd, arch)
    except UnknownMagic as e:
        print 'Unknow magic:' + e.value
        fd.close()
        sys.exit(0)

    if options.dump_clslist:
        print '--------------__objc_classlist--------------'
        mach_o_anylyzer.dump_objc_classlist()

    if options.dump_nlclslist:
        print '--------------__objc_nlclslist--------------'
        mach_o_anylyzer.dump_objc_nlclslist()

    if options.dump_selrefs:
        print '---------------__objc_selrefs---------------'
        mach_o_anylyzer.dump_section_objc_selrefs()

    if options.dump_classrefs:
        print '--------------__objc_classrefs--------------'
        mach_o_anylyzer.dump_section_objc_classrefs()

    if options.dump_superrefs:
        print '--------------__objc_superrefs--------------'
        mach_o_anylyzer.dump_section_objc_superrefs()

    if options.dump_ivar:
        print '----------------__objc_ivar-----------------'
        mach_o_anylyzer.dump_section_objc_ivar()

    if options.dump_cfstring:
        print '-----------------__cfstring-----------------'
        mach_o_anylyzer.dump_section_cfstring()

    if options.dump_import_table:
        print '----------------import_table----------------'
        mach_o_anylyzer.dump_import_table()

    if options.dump_vsection:
        print '---------------virtual_section--------------'
        mach_o_anylyzer.dump_virtual_section()

    fd.close()

if __name__ == '__main__':
    main()
