from enum import Enum

class MACH_O_CPU_TYPE(Enum):
    MACH_O_CPU_IS64BIT = 0x1000000
    VAX = 1
    MC680x0 = 6
    I386 = 7
    MIPS = 8
    MC98000 = 10
    HPPA = 11
    ARM = 12
    MC88000 = 13
    SPARC = 14
    I860 = 15
    ALPHA = 16
    POWERPC = 18
    POWERPC_64 = (POWERPC | MACH_O_CPU_IS64BIT)
    X86_64 = (I386 | MACH_O_CPU_IS64BIT)
    ARM64 = (ARM | MACH_O_CPU_IS64BIT)

class MACH_O_CPU_SUBTYPE(Enum):
    #i386
    X86_ALL = 3
    #arm
    ARM_ALL = 0
    MACH_O_CPU_SUBTYPE_ARM_V4T = 5
    ARM_V6 = 6
    ARM_V5TEJ = 7
    ARM_XSCALE = 8
    ARM_V7 = 9
    #arm64
    ARM64_ALL = 0
    ARM64_V8 = 1

