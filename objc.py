class ObjC2Method:
    def __init__(self, meth_name, meth_type, imp_addr):
        self.name = meth_name
        self.type = meth_type
        self.imp = imp_addr

class ObjC2IVar:
    def __init__(self, offset, meth_name, meth_type, alignment, size):
        self.offset = offset
        self.name = meth_name
        self.type = meth_type
        self.alignment = alignment
        self.size = size

class ObjC2Property:
    def __init__(self, name, attr):
        self.name = name
        self.attr = attr
    
class ObjC2Class:
    def __init__(self, vmaddr,  class_data):
        self.vmaddr = vmaddr

        self.isa = None
        self.isa_name = None
        self.superclass = None
        self.superclass_name = None
        self.cache_name = None
        self.vtable_name = None
        self.class_data = class_data
        if (class_data.flags & 1) == 0:
            self.name = '_OBJC_CLASS_$_' + class_data.cls_name
        else:
            self.name = '_OBJC_METACLASS_$_' + class_data.cls_name
            
    def dump(self):        
        print '0x{:X}:{:s} __objc2_class<{:s}, {:s}, {:s}, {:s}, {:s}>'.format(\
            self.vmaddr, self.name, \
            self.isa_name, self.superclass_name, self.cache_name, self.vtable_name, self.class_data.name)
        self.class_data.dump()

        if self.isa != None:
            self.isa.dump()

        if self.superclass != None:
            self.superclass.dump()

class ObjC2ClassRO:
    def __init__(self, flags, inst_start, inst_size, ivar_layout, cls_name, methods, ivars, weak_ivar_layout, properties, reserved=0):
        self.flags = flags
        self.inst_start = inst_start
        self.inst_size = inst_size
        if ivar_layout == None:
            self.ivar_layout = 0
        else:
            self.ivar_layout = ivar_layout
            
        self.cls_name = cls_name
        if (flags & 1) == 0:
            self.name = self.cls_name + '_$classData'
        else:
            self.name = self.cls_name + '_$metaData'
        self.methods = methods
        self.ivars = ivars
        if weak_ivar_layout == None:
            self.weak_ivar_layout = 0
        else:
            self.weak_ivar_layout = weak_ivar_layout
        self.properties = properties
        self.reserved = reserved
        
    def dump_method(self, method):
        #meth_name, meth_type, '0x{:x}'.format(imp_ptr)
        ident = '    '
        print ident, ident, ident, '__objc2_meth<\'{:s}\', \'{:s}\', {:s}>'.format(method.name, method.type, method.imp)

    def dump_ivar(self, ivar):
        #offset, meth_name, meth_type, alignment, size
        ident = '    '
        print ident, ident, ident, '__objc2_ivar<0x{:X}, \'{:s}\', \'{:s}\', {:d}, {:d}>'.format(ivar.offset, ivar.name, ivar.type, ivar.alignment, ivar.size)

    def dump_property(self, property):
        #prop_name, prop_attr
        ident = '    '
        print ident, ident, ident, '__objc2_prop<\'{:s}\', \'{:s}\'>'.format(property.name, property.attr)
        
    def dump(self):
        ident = '    '
        print ident, '{:s}:'.format(self.name)

        print ident, ident, 'flags:0x{:X}, instance_start:0x{:X}, instance_size:0x{:X}, ivar_layout:0x{:X}, weak_ivar_layout:0x{:X}'.format(\
            self.flags, self.inst_start, self.inst_size, self.ivar_layout, self.weak_ivar_layout)

        if self.methods != None:
            print ident, ident, 'method list:'
            for method in self.methods:
                self.dump_method(method)
        else:
            print ident, ident, 'empty method list'

        if self.ivars != None:
            print ident, ident, 'ivar list:'
            for ivar in self.ivars:
                self.dump_ivar(ivar)
        else:
            print ident, ident, 'empty ivar list'

        if self.properties != None:
            print ident, ident, 'property list:'
            for property in self.properties:
                self.dump_property(property)
        else:
            print ident, ident, 'empty property list'

