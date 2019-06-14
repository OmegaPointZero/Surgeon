import bin as binr
import io

class bcolors:
    HEADER = '\033[97m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'    


bs = binr.bin2str
lstr = lambda string: bcolors.HEADER + "|" + "{:<86}".format(string) + bcolors.HEADER + "|"
# reads bytes until null terminator, returns the string
def iterateUntilNull(offset,binary):
    name = []
    o = offset
    finished = False    
    while finished == False:
        b = binary[o]
        if hex(ord(b)) != "0x0":
            name.append(b)
            o = o+1
        elif hex(ord(b)) == "0x0":
            finished = True
            return "".join(name)

#Get the name of this section header
def getSectionHeaderName(sections,sh):
    for section in sections:
        name_off = int(section['sh_name'],16)
        name = iterateUntilNull(name_off,sh)
        section['name'] = name

    return sections

# Get all the section headers from the table
def parseSectionHeaderTable(path, offset, arch, endian, entNum, entSize, nameIndex, sh):

    f = io.open(path,'rb')
    
    if sh:
        print bcolors.FAIL + "\nSECTION HEADER TABLE\n" + bcolors.HEADER
        print "Should be %s%s%s entries of %s%s%s bytes." % (bcolors.WARNING,int(entNum,16), bcolors.HEADER, bcolors.WARNING, int(entSize,16), bcolors.HEADER)
        print "Table: Looking up section header table at %s0x%s%s" % (bcolors.OKBLUE,offset ,bcolors.HEADER)

    # nameIndex is the index of the .shstrtab
    nI = int(nameIndex,16)
    sections = []

    for y in range(0,int(entNum,16)):
        # sf = index * entry size
        sf = int(y)*int(str(entSize),16)
        # Offset of the start of section header table
        tf = int(str(offset),16) 
        # section offset = table offset + (number of entries * size of entries)
        soffset = tf + sf
        section = parseSectionHeaders(f, soffset, arch, endian, entNum, entSize, nameIndex, sh)
        sections.append(section)
        if y == nI:
            # this is the .shstrtab section, need to get the contents of this section
            f.close()
            f = io.open(path,'rb')
            f.seek(int(section['sh_offset'],16))
            shstrtab = f.read(int(section['sh_size'],16))
            # Function that iterates through all sections[], gets name from shstrtab
            named = getSectionHeaderName(sections, shstrtab)
            return named


def parseSectionHeaders(elfFile, offset, arch, endian, entNum, entSize, nameIndex, sh):

    def parseFlags(flg):
    
        flags = int(flg)

        flagStr = ""

        pfl = lambda flags, mask, code, string: string+code if flags & mask else string+" "

        # First bit for write

        flagStr = pfl(flags, 0b1, "W", flagStr)
        flagStr = pfl(flags, 0b10, "A", flagStr)
        flagStr = pfl(flags, 0b100, "X", flagStr)
        flagStr = pfl(flags, 0x10, "M", flagStr)
        flagStr = pfl(flags, 0x20, "S", flagStr)
        flagStr = pfl(flags, 0x40, "I", flagStr)
        flagStr = pfl(flags, 0x80, "L", flagStr)
        

        return flagStr            

    def getSHType(byte):
        sh_types = {
            0: "SHT_NULL",
            1: "SHT_PROGBITS",
            2: "SHT_SYMTAB",
            3: "SHT_STRTAB",
            4: "SHT_RELA",
            5: "SHT_HASH",
            6: "SHT_DYNAMIC",
            7: "SHT_NOTE",
            8: "SHT_NOBITS",
            9: "SHT_REL",
            10: "SHT_LIB",
            11: "SHT_DYNSYM",
            14: "SHT_INT_ARRAY",
            15: "SHT_FINI_ARRAY",
            16: "SHT_PREINIT_ARRAY",
            17: "SHT_GROUP",
            18: "SHY_SYMTAB_SHNDX",
            19: "SHT_NUM",
            1610612736: "SHT_LOOS"
        }
        return sh_types.get(byte,"Unknown")
        
    elfFile.seek(0)
    elfFile.seek(offset)
    s = elfFile.read(int(entSize,16))

    bsr = lambda x, y : bs(s[x:y], endian)

    sh_name = bsr(0,4)
    t = bsr(4,8)
    sh_type = getSHType(int(t,16))
    if arch=="64-bit":
        sh_flags = bsr(8,16)
        sh_addr = bsr(16,24)
        sh_offset = bsr(24,32)
        sh_size = bsr(32,40)
        sh_link = bsr(40,44)
        sh_info = bsr(44,48)
        sh_addralign = bsr(48,56)
        sh_entsize = bsr(56,64)
    elif arch=="32-bit":
        sh_flags = bsr(8,12)
        sh_addr = bsr(12,16)
        sh_offset = bsr(16,20)
        sh_size = bsr(20,24)
        sh_link = bsr(24,28)
        sh_info = bsr(28,32)
        sh_addralign = bsr(32,36)
        sh_entsize = bsr(36,40)
        
    parsed_flags = parseFlags(sh_flags)

    if not sh_name:
        sh_name = "error"

    obj = {
        'parsed_flags' : parsed_flags,
        'sh_name' : sh_name,
        'sh_type' : t,
        'type' : sh_type,
        'sh_flags' : sh_flags,
        'sh_addr' : sh_addr,
        'sh_offset' : sh_offset,
        'sh_size' : sh_size,
        'sh_link' : sh_link,
        'sh_info' : sh_info,
        'sh_addralign' : sh_addralign,
        'sh_entsize' : sh_entsize,
        'soffset' : offset
    }

    return obj



def parseELFHeader(elfFile, fh):
    f = io.open(elfFile,'rb')

    bsr = lambda x, y : bs(h[x:y], endian)

    h = f.read(64)
    magic = h[0:4]

    if hex(ord(h[4]))=="0x1":
        arch = "32-bit"
    elif hex(ord(h[4]))=="0x2":
        arch = "64-bit"
    else:
        arch = "unknown"

    if hex(ord(h[5]))=="0x1":
        endian = "Little"
    elif hex(ord(h[5]))=="0x2":
        endian = "Big"
    else: 
        endian = "unknown"

    # h[6] is always 1 for ELF original version

    def getABI(byte):
        byte = ord(byte)
        abi = {
            0 : "System V (Default Unix Application Binary Interface)",
            1 : "HP-UX",
            2 : "NetBSD",
            3 : "Linux",
            4 : "GNU Hurd",
            6 : "Solaris",
            7 : "AIX",
            8 : "IRIX",
            9 : "FreeBSD",
            10: "Tru64",
            11: "Novell Modesto",
            12: "OpenBSD",
            13: "OpenVMS",
            14: "NonStop Kernel",
            15: "AROS",
            16: "Fenix OS",
            17: "CloudABI"
        }
        return abi.get(byte, "Unknown")

    abi = getABI(h[7])
    abi_vers = ord(h[8])
    if abi_vers == 0 :
        abi_vers = "Unknown"

    # h[9-15] are e_ident[EI_PAD], unused padding

    def getFileType(byte):
        Byte = int(hex(ord(byte)),16)
        types = {
            int(0x00) : "ET_NONE",
            int(0x01) : "ET_REL",
            int(0x02) : "ET_EXEC",
            int(0x03) : "ET_DYN",
            int(0x04) : "ET_CORE",
        }
        return types.get(Byte, "UNKNOWN")

    fileType = getFileType(h[16])

    def getArch(byte):
        archs = {
            "0x0" : "Unspecified",
            "0x2" : "SPARC",
            "0x3" : "x86",
            "0x8" : "MIPS",
            "0x14" : "PowerPC",
            "0x16" : "S390",
            "0x28" : "ARM",
            "0x2a" : "SuperH",
            "0x32" : "IA-64",
            "0x3e" : "x86_64",
            "0Xb7" : "AArch64",
            "0xf3" : "RISC-V"
        }
        err = "Unknown: " + hex(ord(byte))
        return archs.get(hex(ord(byte)), err)

    iarch = getArch(h[18])
    
    # e_version (h[20]) = 1 for elf, takes up 4 bytes

    if arch=="64-bit":
        entry = bsr(24,32)
        pht = bsr(32,40) # program header table
        sht = bsr(40,48) # section header table
        e_flags = bsr(48,52)
        e_ehsize = bsr(52,54)
        e_phentsize = bsr(54,56)
        e_phnum = bsr(56,58)
        e_shentsize = bsr(58,60)
        e_shnum = bsr(60,62)
        e_shstrndx = bsr(62,64)
    elif arch=="32-bit":
        entry = bsr(24,28)
        pht = bsr(28,32)
        sht = bsr(32,36)
        e_flags = bsr(36,40)
        e_ehsize = bsr(40,42)
        e_phentsize = bsr(42,44)
        e_phnum = bsr(44,46)
        e_shentsize = bsr(46,48)
        e_shnum = bsr(48,50)
        e_shstrndx = bsr(50,52)



    if fh:
        print bcolors.HEADER + "+--------------------------------------------------------------------------------------+"
        print "\n\t"+bcolors.FAIL+"EXECUTABLE FILE HEADERS\n"+bcolors.HEADER
        print "\tFormat: \033[93mELF (Executable and Linkable Format)\033[97m"
        print "\tArchitecture: \033[93m%s\033[97m " % arch
        print "\tEndian: \033[93m%s\033[97m " % endian
        print "\tABI: \033[93m%s\033[97m, Version: \033[93m%s\033[97m " % (abi, abi_vers)
        print "\tFile Type: \033[93m%s\033[97m " % fileType
        print "\tInstruction set architecture: \033[93m%s\033[97m " % iarch
        print "\tEntry Point: \033[96m0x%s\033[97m" % entry
        print "\tStart of Program Header Table: \033[96m0x%s\033[97m" % pht
        print "\tStart of Section Header Table: \033[96m0x%s\033[97m" % sht
        print "\te_flags: \033[96m0x%s\033[97m" % e_flags
        print "\tHeader size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (e_ehsize, int(e_ehsize, 16))
        print "\tProgram Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (e_phentsize, int(e_phentsize, 16))
        print "\tNumber of entries in Program Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (e_phnum, int(e_phnum, 16))
        print "\tSection Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (e_shentsize, int(e_shentsize,16))
        print "\tNumber of entries in Section Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (e_shnum, int(e_shnum, 16))
        print "\tIndex of Section Table Header entry containing section names: \033[96m0x%s\033[97m " % e_shstrndx
        print bcolors.HEADER + "\n+--------------------------------------------------------------------------------------+" + bcolors.ENDC

    obj = {
        'format': 'ELF',
        'magic': magic,
        'arch': arch,
        'endian': endian,
        'abi': abi,
        'fileType': fileType,
        'iarch': iarch,
        'entry': entry,
        'pht': pht,
        'sht': sht,
        'e_flags': e_flags,
        'e_ehsize': e_ehsize,
        'e_phentsize': e_phentsize,
        'e_phnum': e_phnum,
        'e_shentsize': e_shentsize,
        'e_shnum': e_shnum,
        'e_shstrndx': e_shstrndx
    }

    return obj
