import bin as binr
import io

bs = binr.bin2str
lstr = lambda string: bcolors.HEADER + "|" + "{:<86}".format(string) + bcolors.HEADER + "|"
bsr = lambda x, y : bs(s[x:y], endian)

class bcolors:
    HEADER = '\033[97m'
    LB = '\033[96m'
    PR = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    TEST = '\033[89m'
    ENDC = '\033[0m'    

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

def parseSectionHeaders(path, offset, endian, entNum, entSize, sh):

    f = io.open(path, 'rb')
    f.seek(offset)
    s = f.read(entSize)

    bstr = lambda x, y : bs(s[x:y],endian)
    sh_name = iterateUntilNull(0,s)
    sh_vsize = bstr(8,12)
    sh_vaddr = bstr(12,16)
    sh_size = bstr(16,20)
    sh_dataPointer = bstr(20,24)
    sh_relocPointer = bstr(24,28)
    sh_linePointer = bstr(28,32)
    sh_relocNums = bstr(32,34)
    sh_numLinenums = bstr(34,36)
    sh_characteristics = bstr(36,40)

    def parseFlags(flags):

        flagStr = ""
        pfl = lambda flags, mask, code, string: string+code if flags & mask else string+" "
        flagStr = pfl(flags, 0x80000000, "W", flagStr)
        flagStr = pfl(flags, 0x40000000, "R", flagStr)
        flagStr = pfl(flags, 0x20000000, "X", flagStr)
        return flagStr

    obj = {
        'parsed_flags' : parseFlags(int(sh_characteristics,16)),
        'sh_name' : sh_name,
        'sh_vsize' : sh_vsize,
        'sh_addr' : sh_vaddr,
        'sh_dataPointer' : sh_dataPointer,
        'sh_size' : sh_size,
        'sh_relocPointer' : sh_relocPointer,
        'sh_linePointer' : sh_linePointer,
        'sh_relocNums' : sh_relocNums,
        'sh_characteristics' : sh_characteristics
    }

    return obj


def parsePESectionsHeaderTable(path, offset, endian, entNum, entSize, sh):

    if sh:
        print bcolors.FAIL + "\nSECTION HEADER TABLE\n" + bcolors.HEADER
        print "Should be %s%s%s entries of %s%s%s bytes." % (bcolors.WARNING,entNum, bcolors.HEADER, bcolors.WARNING, entSize, bcolors.HEADER)
        print "Table: Looking up section header table at %s%s%s" % (bcolors.OKBLUE,str(hex(offset)) ,bcolors.HEADER)

    sections = []

    f = io.open(path, 'rb') 
    for y in range(0,int(entNum)): 
        # sf = index * entry size 
        sf = int(y)*int(entSize) 
        # section offset = table offset + (number of entries * size of entries) 
        soffset = offset + sf 
        section = parseSectionHeaders(path, soffset, endian, entNum, entSize, sh) 
        sections.append(section) 
    return sections

def parsePEHeader(peFile,fh):

    # PE Files are always assumed to be little-endian
    endian = "Little"

    f = io.open(peFile, 'rb')
    f.seek(0x3c)
    start = f.read(4) # Get out of DOS header and find PE Header
    starting_offset = bs(start[0:4], endian)
    f.close()
    f = io.open(peFile, 'rb')
    f.seek(int(starting_offset,16))
    coff = f.read(0x18)    

    def getMachineType(byte):
        b1 = hex(ord(byte[0]))[2:4]
        b2 = hex(ord(byte[1]))[2:4]
        b = (b2 + b1).lower()
        types = {
            "014c" : "Intel 386",
            "8664" : "x64",
            "0162" : "MIPS R3000",
            "0168" : "MIPS R10000",
            "0169" : "MIPS Little Endian WCI v2",
            "0183" : "Old Alpha AXP",
            "0184" : "Alpha AXP",
            "01a2" : "Hitachi SH3",
            "01a3" : "Hitachi SH3 DSP",
            "01a6" : "Hitachi SH4",
            "01a8" : "Hitachi SH5",
            "01c0" : "ARM Little Endian",
            "01c2" : "Thumb",
            "01c4" : "ARMv7",
            "01d3" : "Matsushita AM33",
            "01f0" : "PowerPC Little Endian",
            "01f1" : "PowerPC with Floating Point Support",
            "0200" : "Intel IA64",
            "0266" : "MIPS16",
            "0268" : "Motorola 68000 Series",
            "0284" : "Alpha AXP 64-bit",
            "0366" : "MIPS with FPU",
            "0466" : "MIPS16 with FPU",
            "0ebc" : "EFI Byte Code",
            "9041" : "Mitsubishi M32R Little Endian",
            "aa64" : "ARM64 Little Endian",
            "c0ee" : "clr pure MSIL"
        }
        return types.get(b, "Unknown/ERROR")

    numSec = int(bs(coff[6:8], endian),16)
    timestamp = int(bs(coff[8:12], endian),16)
    optHeaderSize = bs(coff[20:22], endian)

    if fh:
        print bcolors.HEADER + "+--------------------------------------------------------------------------------------+"
        print "\n\t"+bcolors.FAIL+"EXECUTABLE FILE HEADERS\n"+bcolors.HEADER
        print "\tFormat: \033[93mPE (Portable Executable)\033[97m"
        print "\tArchitecture: \033[93m%s\033[97m " % getMachineType(coff[4:6])
        print "\tEndian: \033[93m%s\033[97m " % endian
        print "\tNumber of sections: \033[93m%s\033[97m " % numSec
        print "\tUnix Timestamp: \033[93m%s\033[97m" % timestamp
        print "\tStart of COFF Header Table: \033[96m0x%s\033[97m" % starting_offset
        print "\tSize of optional header: \033[96m0x%s\033[97m (\033[94m%s bytes\033[97m)" % (optHeaderSize, int(optHeaderSize,16))
        print bcolors.HEADER + "\n+--------------------------------------------------------------------------------------+" + bcolors.ENDC

    sht = int(starting_offset,16) + int(optHeaderSize,16) + 0x18
    obj = {
        'endian' : endian,
        'sht' : sht,
        'e_shnum' : numSec,
        'e_shentsize' : 40,
    }

    return obj
