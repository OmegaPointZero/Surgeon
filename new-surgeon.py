import re
#import elf 
from newELF import ELF
import bin as binr
import argparse
#import pe
import sys 
"""
bs = binr.bin2str
elfh = elf.parseELFHeader
elfs = elf.parseSectionHeaderTable
peh = pe.parsePEHeader
pes = pe.parsePESectionsHeaderTable
"""


class bcolors:
  def __init__(self):
    self.HEADER = '\033[97m'
    self.LB = '\033[96m'
    self.PR = '\033[95m'
    self.OKBLUE = '\033[94m'
    self.OKGREEN = '\033[92m'
    self.WARNING = '\033[93m'
    self.FAIL = '\033[91m'
    self.TEST = '\033[89m'
    self.ENDC = '\033[0m'    


class Surgeon:
  def __init__(self):
    self.file_type = ''
    self.target_file = ''
    self.file_object = None
    self.show_headers_flag = True
    self.fileOperator = None
  
  def setTargetFile(self, filename):
    self.target_file = filename
    return self.target_file

  def getTargetFile(self):
    return self.target_file

  def getFileType(self, target_file):
    self.file_object = open(target_file, 'rb')
    f = bytes(self.file_object.read(4))
    if f == b'\x7FELF':
      self.file_type = 'ELF'
      self.fileOperator = ELF(self.file_object)
    elif f[0:2] == b"\x4d\x5a":
      self.file_type = "PE"
      '''
      self.fileOperator = PE()
      '''
    return self.file_type


if __name__ == '__main__':

  args = sys.argv
  parser = argparse.ArgumentParser(description='Parse and modify executables, find codecaves, and create backdoors')
  # File we're working with

  parser.add_argument('-f, --file', action='store', default="", dest='file_path', help='Location of file to search for code cave in (absolute path)')
  '''
  # Options for if we're searching for code caves
  parser.add_argument('-d, --file-headers', action='store_true', dest='fh', help='Show File Headers')
  parser.add_argument('-s, --section-headers', action='store_true', dest='sh', help='Show enumerated section headers')
  parser.add_argument('-S, --search', action='store', dest='search', help='Section to search for code cave inside of')
  parser.add_argument('-X', action='store_true', dest='allEx', help='Search all executable sections')
  parser.add_argument('-A', action='store_true', dest='allSec', help='Search all sections')
  parser.add_argument('-l, --length', action='store', default='64', dest='length', help='Number of bytes that constitutes a cave (default 64)')
  parser.add_argument('-b, --byte', action='store', default='0x00', dest='byte', help='Byte to be searching for.')

  # Options for injecting shellcode
  parser.add_argument('-t, --target-offset', action='store', dest='target', help='Target offset to inject shellcode')
  parser.add_argument('-j', action='store', dest='injection_file', help='A file of raw bytes to inject')
  parser.add_argument('-J', action='store', dest='injection_string', help='A string of raw bytes to inject supplied like \\xef\\xeb')
  parser.add_argument('-P', action='store_true', dest='permissions', help='Include this flag to have caveman verify shellcode fits in the code cave, and modifies permissions of the section to allow for code execution')
  parser.add_argument('-E', action='store_true', dest='autoentry', help='Changes entry point of the executable to the target offset')
  parser.add_argument('-e', action='store', dest='epoints', help='Changes entry point of the executable to a custom defined offset')
  # set results
  '''
  results = parser.parse_args()

  # First, make sure we have a target file to operate on 
  if results.file_path == '':
      path = input("Input path to the file to look for code caves in\n> ")
  else: 
    path = results.file_path 

  # Instantiate our Surgeon and give it the file
  S = Surgeon()
  S.target_file = path
  # Get the file type from the target file
  fileType = S.getFileType(S.target_file)
  # Parse the file Headers
  S.fileOperator.parseFileHeader()
  if(S.show_headers_flag == True):
    S.fileOperator.print_file_headers()


