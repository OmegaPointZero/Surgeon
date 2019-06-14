# Surgeon
An ELF/PE binary file backdooring toolkit, that finds codecaves, injects shellcode and modifies section permissions.

# Usage

`python surgeon.py` will prompt the user for the absolute path to the binary being analyzed. The default behavior is to set the -A, -d and -s flags on the binary.

To tell Surgeon that you're looking to enumerate code cave information from the binary, or only want specific information about it, these are the following flags:

`  -f, --file FILE_PATH  Location of file to search for code cave in (absolute
                        path)`
                        
`  -d, --file-headers    Show File Headers`
  
`  -s, --section-headers
                        Show enumerated section headers`
                        
`  -S, --search SEARCH   Section to search for code cave inside of`
  
`  -X                    Search all executable sections`
  
  `-A                    Search all sections`
  
  `-l, --length LENGTH   Number of bytes that constitutes a cave (default 64)`
  
  `-b, --byte BYTE       Byte to be searching for.`
  

  To tell Surgeon to inject shellcode, the following options need to be used. BE CAREFUL! This will overwrite WHATEVER OFFSET YOU TELL IT TO.


`  -t, --target-offset TARGET
                        Target offset to inject shellcode`
                        
`  -j INJECTION_FILE     A file of raw bytes to inject`
  
`  -J INJECTION_STRING   A string of raw bytes to inject supplied like \xef\xeb`


