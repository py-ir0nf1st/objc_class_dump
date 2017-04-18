import struct
from exception import UnknownMagic
from macho import MACH_O_CPU_TYPE

'''
#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca

struct fat_header {
    unsigned long   magic;      /* FAT_MAGIC */
    unsigned long   nfat_arch;  /* number of structs that follow */
};

struct fat_arch {
    cpu_type_t  cputype;    /* cpu specifier (int) */
    cpu_subtype_t   cpusubtype; /* machine specifier (int) */
    unsigned long   offset;     /* file offset to this object file */
    unsigned long   size;       /* size of this object file */
    unsigned long   align;      /* alignment as a power of 2 */
};
'''

class FatArch:
    def __init__(self, cpu_type, file_offset, size, alignment):
        self.__cpu_type = cpu_type
        self.__file_offset = file_offset
        self.__size = size
        self.__alignment = alignment
    def get_cpu_type(self):
        return self.__cpu_type
    def get_file_offset(self):
        return self.__file_offset
        
class FatHeader:
    def __init__(self, mach_o_file):        
        __FAT_MAGIC = '\xca\xfe\xba\xbe'
        __FAT_CIGAM = '\xbe\xba\xfe\xca'

        #Assuming Fat Header always resides at the beginning of the file
        mach_o_file.seek(0)
        
        magic = mach_o_file.read(4)
        
        if magic == __FAT_MAGIC:
            big_endian = True
        elif magic == __FAT_CIGAM:
            big_endian = False
        else:
            raise UnknownMagic(magic)
            
        if  big_endian == True:
            endian_str = '>'
        else:
            endian_str = '<'
        number_fat_arch, = struct.unpack(endian_str + 'L', mach_o_file.read(4))
        
        fat_arch_list = []
        for i in range(number_fat_arch):
            cpu_type, cpu_subtype, file_offset, size, alignment = struct.unpack(endian_str + 'LLLLL', mach_o_file.read(20))
            fat_arch_list.append(FatArch(MACH_O_CPU_TYPE(cpu_type), file_offset, size, alignment))
        self.__arch_tuple = tuple(fat_arch_list)
        
    def get_arch_tuple(self):
        return self.__arch_tuple
        
    def get_arch(self, cpu_type=None):
        if(cpu_type == None):
            return self.__arch_tuple[0]
        for arch in self.__arch_tuple:
            if cpu_type == arch.get_cpu_type():
                return arch
        return None

