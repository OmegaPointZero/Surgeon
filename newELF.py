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

class ELF:
    def __init__(self, file_object):
        self.file_object = file_object
        self.magic_bytes = ''
        self.endian = ''
        self.arch_bits = ''
        self.architecture = ''
        self.ABI = '' # Application Binary Interface
        self.ABI_version = ''
        self.ELF_file_type = ''
        self.instruction_arch = ''
        self.entry_point = ''
        self.program_header_table = '' # program header table
        self.section_header_table = '' # section header table
        self.e_flags = ''
        self.e_ehsize = ''
        self.e_phentsize = '' # program header table size
        self.e_phnum = ''     # program header table len(entries)
        self.e_shentsize = ''      # section header table size
        self.e_shnum = ''          # section header table len(entries)
        self.e_shstrndx =  ''     #
        self.file_object.seek(0)
        self.divisor = bcolors.HEADER + "\n+" + "-" * 86 + "+" + bcolors.ENDC


    def parseFileHeader(self):
        bsr = lambda x, y : bs(header[x:y], self.endian)
        self.file_object.seek(0)
        header = self.file_object.read(64)
        self.magic_bytes = header[0:4]

        if hex(header[4])=="0x1":
            self.arch_bits = "32-bit"
        elif hex(header[4])=="0x2":
            self.arch_bits = "64-bit"
        else:
            self.arch_bits = "unknown"

        if hex(header[5])=="0x1":
            self.endian = "Little"
        elif hex(header[5])=="0x2":
            self.endian = "Big"
        else: 
            self.endian = "unknown"

        # get the ABI (Application Binary Interface)
        # h[6] is always 1 for ELF original version
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
        self.ABI = abi.get(header[7], "Unknown")
        abi_vers = header[8]
        if abi_vers == 0 :
            abi_vers = "Unknown"
        self.ABI_version = abi_vers

        # h[9-15] are e_ident[EI_PAD], unused padding
        e_ident_types = {
                int(0x00) : "ET_NONE",
                int(0x01) : "ET_REL",
                int(0x02) : "ET_EXEC",
                int(0x03) : "ET_DYN",
                int(0x04) : "ET_CORE",
            }
        self.ELF_file_type = e_ident_types.get(hex(header[16]),16)

        # Instruction Set Architecture (ISA)
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
        self.instruction_arch = archs.get(hex(header[18]), "Unknown")

        
        # e_version (h[20]) = 1 for elf, takes up 4 bytes
        if self.arch_bits == "64-bit":
            self.entry_point = bsr(24,32)
            self.program_header_table = bsr(32,40) # program header table
            self.section_header_table = bsr(40,48) # section header table
            self.e_flags = bsr(48,52)
            self.e_ehsize = bsr(52,54)
            self.e_phentsize = bsr(54,56)
            self.e_phnum = bsr(56,58)
            self.e_shentsize = bsr(58,60)
            self.e_shnum = bsr(60,62)
            self.e_shstrndx = bsr(62,64)
        elif self.arch_bits == "32-bit":
            self.entry_point = bsr(24,28)
            self.program_header_table = bsr(28,32)
            self.section_header_table = bsr(32,36)
            self.e_flags = bsr(36,40)
            self.e_ehsize = bsr(40,42)
            self.e_phentsize = bsr(42,44)
            self.e_phnum = bsr(44,46)
            self.e_shentsize = bsr(46,48)
            self.e_shnum = bsr(48,50)
            self.e_shstrndx = bsr(50,52)

        obj = {
            'format': 'ELF',
            'magic': self.magic_bytes,
            'arch': self.arch_bits,
            'endian': self.endian,
            'abi': self.ABI,
            'fileType': self.ELF_file_type,
            'iarch': self.instruction_arch,
            'entry': self.entry_point,
            'pht': self.program_header_table,
            'sht': self.section_header_table,
            'e_flags': self.e_flags,
            'e_ehsize': self.e_ehsize,
            'e_phentsize': self.e_phentsize,
            'e_phnum': self.e_phnum,
            'e_shentsize': self.e_shentsize,
            'e_shnum': self.e_shnum,
            'e_shstrndx': self.e_shstrndx
        }

        return obj

    def parseSectionHeaders(self, offset, arch, endian, entNum, entSize, nameIndex, sh):
        def parseFlags(flg):        
            flags = int(flg)
            flagStr = ""
            #parseFlags lambda function
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

        self.file_object.seek(0)
        self.file_object.seek(offset)
        s = self.file_object.read(int(entSize,16))
    
        # binary to string lambda
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

    # reads bytes until null terminator, returns the string
    def iterateUntilNull(self,offset,binary):
        binary = bytearray(binary)
        name = []
        o = offset
        finished = False    
        while finished == False:
            b = str(binary[o])
            if hex(int(b)) != "0x0":
                name.append(b)
                o = o+1
            elif hex(int(b)) == "0x0":
                finished = True
                return "".join(name)

    #Get the name of this section header
    def getSectionHeaderName(self,sections,sh):
        for section in sections:
            name_off = int(section['sh_name'],16)
            name = self.iterateUntilNull(name_off,sh)
            section['name'] = name

        return sections


    # Get all the section headers from the table
    def parseSectionHeaderTable(self, display):
        # path, offset, arch, endian,  entNum,     entSize,  nameIndex, sh
        #          sht, arch, endian, e_shnum, e_shentsize, e_shstrndx, sh
        #f = io.open(path,'rb')
        
        # if displaying the section headers:
        if display:
            print(bcolors.FAIL + "\n\tSECTION HEADER TABLE\n" + bcolors.HEADER)
            print("\tShould be %s%s%s entries of %s%s%s bytes." % 
              (bcolors.WARNING,int(self.e_shnum,16), bcolors.HEADER, bcolors.WARNING, 
              int(self.e_shentsize,16), bcolors.HEADER))
            print("\tTable: Looking up section header table at %s0x%s%s\n" % 
                (bcolors.OKBLUE,self.section_header_table, bcolors.HEADER))
        # nameIndex is the index of the .shstrtab
        nameIndex = int(self.e_shstrndx,16)
        sections = []

        for y in range(0,int(self.e_shnum,16)):
            # sf = index * entry size
            sf = int(y)*int(str(self.e_shentsize),16)
            # Offset of the start of section header table
            tf = int(str(self.section_header_table),16) 
            # section offset = table offset + (number of entries * size of entries)
            section_offset = tf + sf

            # section = parseSectionHeaders(f, section_offset, arch, endian,
            #                                entNum, entSize, nameIndex, sh)
            section = self.parseSectionHeaders(section_offset,self.arch_bits, 
                                               self.endian, self.e_shnum,
                                               self.e_shentsize, self.e_shstrndx,
                                               display)
            sections.append(section)
            if y == nameIndex:
                # this is the .shstrtab section, need to get the contents of this section
                self.file_object.seek(0)
                self.file_object.seek(int(section['sh_offset'],16))
                shstrtab = self.file_object.read(int(section['sh_size'],16))
                # Function that iterates through all sections[], gets name from shstrtab
                return self.getSectionHeaderName(sections, shstrtab)


    def print_file_headers(self):   
        print(self.divisor)
        print("\n\t"+bcolors.FAIL+"EXECUTABLE FILE HEADERS\n"+bcolors.HEADER)
        print("\tFormat: \033[93mELF (Executable and Linkable Format)\033[97m")
        print("\tArchitecture: \033[93m%s\033[97m " % self.arch_bits)
        print("\tEndian: \033[93m%s\033[97m " % self.endian)
        print("\tABI: \033[93m%s\033[97m, Version: \033[93m%s\033[97m " % (self.ABI, self.ABI_version))
        print("\tFile Type: \033[93m%s\033[97m " % self.ELF_file_type)
        print("\tInstruction set architecture: \033[93m%s\033[97m " % self.instruction_arch)
        print("\tEntry Point: \033[96m0x%s\033[97m" % self.entry_point)
        print("\tStart of Program Header Table: \033[96m0x%s\033[97m" % self.program_header_table)
        print("\tStart of Section Header Table: \033[96m0x%s\033[97m" % self.section_header_table)
        print("\te_flags: \033[96m0x%s\033[97m" % self.e_flags)
        print("\tHeader size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_ehsize, int(self.e_ehsize,16)))
        print("\tProgram Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_phentsize, int(self.e_phentsize,16)))
        print("\tNumber of entries in Program Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (self.e_phnum, int(self.e_phnum, 16)))
        print("\tSection Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_shentsize, int(self.e_shentsize,16)))
        print("\tNumber of entries in Section Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (self.e_shnum, int(self.e_shnum, 16)))
        print("\tIndex of Section Table Header entry containing section names: \033[96m0x%s\033[97m " % self.e_shstrndx)
        print(self.divisor)

    def printSectionsOverView(self):
        sections = ''
        print(bcolors.FAIL +  "\nSection Headers: " + bcolors.HEADER)
        print(self.divisor)
        print("%s| %s[Number] %s%s %s%s %s%s %s%s%s |" % (bcolors.HEADER, bcolors.FAIL, bcolors.HEADER, "{:<18}".format('Name'),bcolors.OKGREEN, "{:<18}".format('Type'), bcolors.LB, "{:<18}".format('Addr'), bcolors.OKBLUE,"{:<18}".format('Offset'),bcolors.HEADER ))
        print("%s|          %s%s %s%s %sFlags              %sAlignment          |" % (bcolors.HEADER,bcolors.PR,"{:<18}".format('Size'),bcolors.WARNING, "{:<18}".format('EntSize'), bcolors.FAIL, bcolors.HEADER ))
        print(self.divisor)
        for x in range(0,len(sections)):
            section = sections[x]
            y = hex(x)
            if len(y) < 4:
                y = "0x0" + y[-1]
            string1 = "%s|%s [ %s] %s%s %s%s %s%s %s%s %s|" % (bcolors.HEADER,bcolors.FAIL, "{:<5}".format(y), bcolors.HEADER, "{:<18}".format(section['name']), bcolors.OKGREEN, "{:<18}".format(section['type']), bcolors.LB, "{:<18}".format(section['sh_addr']), bcolors.OKBLUE, "{:<18}".format(section['sh_offset']), bcolors.HEADER )
            string2 = "%s|%s          %s %s%s %s%s %s%s |" % (bcolors.HEADER,bcolors.PR,"{:<18}".format(section['sh_size']), bcolors.WARNING, "{:<18}".format(section['sh_entsize']), bcolors.FAIL, "{:<18}".format(section['parsed_flags']), bcolors.HEADER, "{:<18}".format(section['sh_addralign']))
            print(string1)
            print(string2)
            print(divisor)
