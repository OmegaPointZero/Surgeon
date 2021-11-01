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



    def print_file_headers(self):   
        print(bcolors.HEADER + "+--------------------------------------------------------------------------------------+")
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
        print("\tHeader size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_ehsize, self.e_ehsize))
        print("\tProgram Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_phentsize, self.e_phentsize))
        print("\tNumber of entries in Program Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (self.e_phnum, self.e_phnum))
        print("\tSection Header Table entry size: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (self.e_shentsize, self.e_shentsize))
        print("\tNumber of entries in Section Header Table: \033[96m0x%s\033[97m (\033[94m%s entries\033[97m)" % (self.e_shnum, self.e_shnum))
        print("\tIndex of Section Table Header entry containing section names: \033[96m0x%s\033[97m " % self.e_shstrndx)
        print(bcolors.HEADER + "\n+--------------------------------------------------------------------------------------+" + bcolors.ENDC)
