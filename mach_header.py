import os
import struct
from enum import Enum

class MACH_O_LOAD_COMMAND_TYPE(Enum):
    SEGMENT = 0x1           #File segment to be mapped.
    SYMTAB = 0x2            #Link-edit stab symbol table info (obsolete).
    SYMSEG = 0x3            #Link-edit gdb symbol table info.
    THREAD = 0x4            #Thread.
    UNIXTHREAD = 0x5        #UNIX thread (includes a stack).
    LOADFVMLIB = 0x6        #Load a fixed VM shared library.
    IDFVMLIB = 0x7          #Fixed VM shared library id.
    IDENT = 0x8             #Object identification information (obsolete).
    FVMFILE = 0x9           #Fixed VM file inclusion.
    PREPAGE = 0xa           #Prepage command (internal use).
    DYSYMTAB = 0xb          #Dynamic link-edit symbol table info.
    LOAD_DYLIB = 0xc        #Load a dynamically linked shared library.
    ID_DYLIB = 0xd          #Dynamically linked shared lib identification.
    LOAD_DYLINKER = 0xe     #Load a dynamic linker.
    ID_DYLINKER = 0xf       #Dynamic linker identification.
    PREBOUND_DYLIB = 0x10   #Modules prebound for a dynamically.
    ROUTINES = 0x11         #Image routines.
    SUB_FRAMEWORK = 0x12    #Sub framework.
    SUB_UMBRELLA = 0x13     #Sub umbrella.
    SUB_CLIENT = 0x14       #Sub client.
    SUB_LIBRARY = 0x15      #Sub library.
    TWOLEVEL_HINTS = 0x16   #Two-level namespace lookup hints.
    PREBIND_CKSUM = 0x17    #Prebind checksum.
    #Load a dynamically linked shared library that is allowed to be missing (weak).
    WEAK_DYLIB = 0x18
    SEGMENT_64 = 0x19       #64-bit segment of this file to be mapped.
    ROUTINES_64 = 0x1a      #Address of the dyld init routine in a dylib.
    UUID = 0x1b             #128-bit UUID of the executable.
    RPATH = 0x8000001c            #Run path addiions.
    CODE_SIGNATURE = 0x1d   #Local of code signature.
    SEGMENT_SPLIT_INFO = 0x1e   #Local of info to split seg.
    REEXPORT_DYLIB = 0x1f   #Load and re-export lib.
    LAZY_LOAD_DYLIB = 0x20  #Delay load of lib until use.
    ENCRYPTION_INFO = 0x21  #Encrypted segment info.
    DYLD_INFO = 0x80000022        #Compressed dyld information.
    LOAD_UPWARD_DYLIB = 0x23    #Load upward dylib.
    VERSION_MIN_MACOSX = 0x24   #Minimal MacOSX version.
    VERSION_MIN_IPHONEOS = 0x25 #Minimal IOS version.
    FUNCTION_STARTS = 0x26      #Compressed table of func start.
    DYLD_ENVIRONMENT = 0x27     #Env variable string for dyld.
    MAIN = 0x80000028                 #Entry point.
    DATA_IN_CODE = 0x29         #Table of non-instructions.
    SOURCE_VERSION = 0x2a       #Source version.
    DYLIB_CODE_SIGN_DRS = 0x2b  #DRs from dylibs.
    ENCRYPTION_INFO_64 = 0x2c   #Encrypted 64 bit seg info.
    LINKER_OPTIONS = 0x2d       #Linker options.
    LINKER_OPTIMIZATION_HINT = 0x2e #Optimization hints.
    VERSION_MIN_WATCHOS = 0x30  #Minimal WatchOS version.

class MACH_O_SECTION_TYPE(Enum):
    #/* Regular section.  */
    REGULAR = 0x0

    #/* Zero fill on demand section.  */
    ZEROFILL = 0x1

    #/* Section with only literal C strings.  */
    CSTRING_LITERALS = 0x2

    #/* Section with only 4 byte literals.  */
    FOUR_BYTE_LITERALS = 0x3

    #/* Section with only 8 byte literals.  */
    EIGHT_BYTE_LITERALS = 0x4

    #/* Section with only pointers to literals.  */
    LITERAL_POINTERS = 0x5

    '''
    For the two types of symbol pointers sections and the symbol stubs
    section they have indirect symbol table entries.  For each of the
    entries in the section the indirect symbol table entries, in
    corresponding order in the indirect symbol table, start at the index
    stored in the reserved1 field of the section structure.  Since the
    indirect symbol table entries correspond to the entries in the
    section the number of indirect symbol table entries is inferred from
    the size of the section divided by the size of the entries in the
    section.  For symbol pointers sections the size of the entries in
    the section is 4 bytes and for symbol stubs sections the byte size
    of the stubs is stored in the reserved2 field of the section
    structure.
    '''

    #/* Section with only non-lazy symbol pointers.  */
    NON_LAZY_SYMBOL_POINTERS = 0x6

    #/* Section with only lazy symbol pointers.  */
    LAZY_SYMBOL_POINTERS = 0x7

    #/* Section with only symbol stubs, byte size of stub in the reserved2 field.  */
    SYMBOL_STUBS = 0x8

    #/* Section with only function pointers for initialization.  */
    MOD_INIT_FUNC_POINTERS = 0x9

    #/* Section with only function pointers for termination.  */
    MOD_FINI_FUNC_POINTERS = 0xa

    #/* Section contains symbols that are coalesced by the linkers.  */
    COALESCED = 0xb

    #/* Zero fill on demand section (possibly larger than 4 GB).  */
    GB_ZEROFILL = 0xc

    #/* Section with only pairs of function pointers for interposing.  */
    INTERPOSING = 0xd

    #/* Section with only 16 byte literals.  */
    SIXTEEN_BYTE_LITERALS = 0xe

    #/* Section contains DTrace Object Format.  */
    DTRACE_DOF = 0xf

    #/* Section with only lazy symbol pointers to lazy loaded dylibs.  */
    LAZY_DYLIB_SYMBOL_POINTERS = 0x10

class DYLD_INFO_BIND_OPCODE(Enum):
    #Constants for dyld info bind.
    OPCODE_MASK = 0xf0
    IMMEDIATE_MASK = 0x0f
    
    #The bind opcodes
    DONE = 0x00
    SET_DYLIB_ORDINAL_IMM = 0x10
    SET_DYLIB_ORDINAL_ULEB = 0x20
    SET_DYLIB_SPECIAL_IMM = 0x30
    SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    SET_TYPE_IMM = 0x50
    SET_ADDEND_SLEB = 0x60
    SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    ADD_ADDR_ULEB = 0x80
    DO_BIND = 0x90
    DO_BIND_ADD_ADDR_ULEB = 0xa0
    DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0
    DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0

class DYLD_INFO_BIND_TYPE(Enum):
    #The bind types.
    POINTER = 1
    TEXT_ABSOLUTE32 = 2
    TEXT_PCREL32 = 3

class MachHeader:
    '''
    #define MH_MAGIC 0xfeedface
    #define MH_CIGAM 0xcefaedfe
    struct mach_header
    {
        unsigned long magic;      /* Magic number.  */
        unsigned long cputype;    /* CPU that this object is for.  */
        unsigned long cpusubtype; /* CPU subtype.  */
        unsigned long filetype;   /* Type of file.  */
        unsigned long ncmds;      /* Number of load commands.  */
        unsigned long sizeofcmds; /* Total size of load commands.  */
        unsigned long flags;      /* Flags for special featues.  */
    };
    
    #define MH_MAGIC_64 0xfeedfacf
    #define MH_CIGAM_64 0xcffaedfe
    struct mach_header_64
    {
        unsigned long magic;      /* Magic number.  */
        unsigned long cputype;    /* CPU that this object is for.  */
        unsigned long cpusubtype; /* CPU subtype.  */
        unsigned long filetype;   /* Type of file.  */
        unsigned long ncmds;      /* Number of load commands.  */
        unsigned long sizeofcmds; /* Total size of load commands.  */
        unsigned long flags;      /* Flags for special featues.  */
        unsigned long reserved;   /* Reserved.  Duh.  */
    };
    '''
    def __init__(self, mach_o_file, file_offset):
        __MH_MAGIC = '\xfe\xed\xfa\xce'
        __MH_CIGAM = '\xce\xfa\xed\xfe'
        __MH_MAGIC_64 = '\xfe\xed\xfa\xcf'
        __MH_CIGAM_64 = '\xcf\xfa\xed\xfe'
        
        mach_o_file.seek(file_offset)

        magic = mach_o_file.read(4)
        
        if magic == __MH_MAGIC or magic == __MH_CIGAM:
            self.__big_endian = (magic == __MH_MAGIC)
            self.__64bit_cpu = False
            self.__hdr_len = 28
        elif magic == __MH_MAGIC_64 or magic == __MH_CIGAM_64:
            self.__big_endian = (magic == __MH_MAGIC_64)
            self.__64bit_cpu = True
            self.__hdr_len = 32
        else:
            raise UnknownMagic(magic)
            
        if self.__big_endian == True:
            endian_str = '>'
        else:
            endian_str = '<'

        #skip cuptype, cpusubtype and filetype
        mach_o_file.seek(12, os.SEEK_CUR)
        self.__number_cmds, = struct.unpack(endian_str + 'L', mach_o_file.read(4))

    def is_big_endian(self):
        return self.__big_endian
    def is_64bit_cpu(self):
        return self.__64bit_cpu
    def get_hdr_len(self):
        return self.__hdr_len
    def get_number_cmds(self):
        return self.__number_cmds

class Segment:
    def __init__(self, name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.offset = offset
        self.filesize = filesize
        self.maxprot = maxprot
        self.initprot = initprot
        self.nsects = nsects
        self.flags = flags
        self.sections = []

    def append_section(self, section):
            self.sections.append(section)
        
class Section:
    def __init__(self, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3=None):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.offset = offset
        self.alignment = alignment
        self.reloff = reloff
        self.nreloc = nreloc
        self.flags = flags
        self.reserved1 = reserved1
        self.reserved2 = reserved2
        self.reserved3 = reserved3
        self.data = None
        
    def buf_data(self, data):
        self.data = data

class DYLib:
    def __init__(self, timestamp, current_ver, compat_ver, name):
        self.timestamp = timestamp
        self.current_ver = current_ver
        self.compat_ver = compat_ver
        self.name = name
        self.symbols = []
        
    def append_symbol(self, symbol):
        if symbol not in self.symbols:
            self.symbols.append(symbol)
    
class DYLDInfo:
    def __init__(self, rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size):
        self.rebase_off = rebase_off
        self.rebase_size = rebase_size
        self.bind_off = bind_off
        self.bind_size = bind_size
        self.weak_bind_off = weak_bind_off
        self.weak_bind_size = weak_bind_size
        self.lazy_bind_off = lazy_bind_off
        self.lazy_bind_size = lazy_bind_size
        self.export_off = export_off
        self.export_size = export_size

class VirtualMap:
    def __init__(self, addr, symbol):
        self.addr = addr
        self.symbol = symbol

