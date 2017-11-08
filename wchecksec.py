import argparse
import os
import pefile
import glob
import itertools
import json

from termcolor import colored

class PESecurityFlags():
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)

    def nx(self):
        return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0

    def aslr(self):
        return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x040 != 0

    def safeseh(self):
        return (self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].VirtualAddress != 0) \
            and (self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size != 0)
    
    def cfg(self):
        return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000 != 0

def mglob(path, *exts):
    return itertools.chain.from_iterable(
        glob.iglob("%s/**/*.%s" % (path, ext), recursive=True) for ext in exts
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='Directory to scan')
    args = parser.parse_args()

    files = mglob(args.path, "dll", "exe")

    for path in files:
        flags = PESecurityFlags(path)

        print("%s %s %s %s %s" % (
            colored("NX", ["red", "green"][flags.nx()]),
            colored("ASLR", ["red", "green"][flags.aslr()]),
            colored("SAFESEH", ["red", "green"][flags.safeseh()]),
            colored("CFG", ["red", "green"][flags.cfg()]),
            path
        ))

