def binArr(binary):
    arr = []
    bytes = len(binary)
    for b in binary:
        if len(hex(ord(b))) < 4:
            b = hex(ord(b))
            b = "0x0" + b[-1]
            arr.append(b)
        else:
            arr.append(hex(ord(b)))
    return arr

def bin2str(binary, endian):
    bArr = binArr(binary)
    # Array to hold bytes processed
    hArr = []
    if endian=="Big":
        for e in bArr:
            e = e[2:]
            hArr.append(e)
    elif endian == "Little":
        # put into array until it's len 4, reverse, join, put in hArr
        eArr = []
        for e in bArr:
            e = e[2:]
            if len(eArr) == 4:
                hArr = eArr[::-1] + hArr
                eArr = []
                eArr.append(e)
            else:
                eArr.append(e)
        hArr = eArr[::-1] + hArr
    # Last one not happening in loop for some reason
    return "".join(hArr)
