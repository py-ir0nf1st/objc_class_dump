# objc_class_dump
A object-c class dumper written in Python

The famous object-c class-dump(https://github.com/nygard/class-dump) is not very handy when doing some assembler language level IOS application ananlysis.

So I developed an objc_class_dump with Python from scrath.

This tool not only dumps the hierarchy of all object-c classes but also dumps raw information of some other sections.

This tool was developed with Python 2.7 and tested with Mach-O file with arm and aarch64 architecture.

How it works:

1. Detects Fat Mach-O header magic

2. Detects Mach-O Header magic

3. Loads all sections into memory

4. Build an import table based on LC_LOAD_DYLIB and DYLD_INFO

5. Build an virtual section for all imported symbols

6. Bind to imported symbols based on DYLD_INFO

7. Build hierarchy of object-c class list and non-lazy class list

How to use:
python objc_class_dump.py [options] <mach-o-file>

# TODO:
---
> dump __objc_protolist
> Documentation

