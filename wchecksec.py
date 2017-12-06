import argparse
import os
import pefile
import glob
import itertools
import json

from termcolor import colored

class PESecurityFlags():
    def __init__(self, path):
        try:
            self.pe = pefile.PE(path, fast_load=True)
        except pefile.PEFormatError:
            self.pe = None
        self.path = path

    def print(self, color=False):
        if color:
            if self.pe is not None:
                print("%s %s %s %s %s" % (
                        colored("NX", ["red", "green"][flags.nx()]),
                        colored("ASLR", ["red", "green"][flags.aslr()]),
                        colored("SAFESEH", ["red", "green"][flags.safeseh()]),
                        colored("CFG", ["red", "green"][flags.cfg()]),
                        self.path
                    ))
            else:
                print("%s %s %s %s %s" % (
                    colored("NX", "magenta"),
                    colored("ASLR", "magenta"),
                    colored("SAFESEH", "magenta"),
                    colored("CFG", "magenta"),
                    self.path
                ))
        else:
            if self.pe is not None:
                print("%s;%s;%s;%s;%s" % (
                    self.path,
                    ["N", "Y"][flags.nx()],
                    ["N", "Y"][flags.aslr()],
                    ["N", "Y"][flags.safeseh()],
                    ["N", "Y"][flags.cfg()]
                ))
            else:
                print("%s;N/A;N/A;N/A;N/A" % (self.path))

    def nx(self):
        if self.pe is not None:
            return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0
        return None

    def aslr(self):
        if self.pe is not None:
            return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0
        return None

    def safeseh(self):
        if self.pe is not None:
            return (self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].VirtualAddress != 0) \
                and (self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size != 0)
        return None

    def cfg(self):
        if self.pe is not None:
            return self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000 != 0
        return None

def mglob(path, *exts):
    return itertools.chain.from_iterable(
        glob.iglob("%s/**/*.%s" % (path, ext), recursive=True) for ext in exts
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--text', help='Enable text mode', action='store_const', const=True)
    parser.add_argument('path', help='Directory to scan', type=str)
    args = parser.parse_args()

    files = mglob(args.path, "dll", "exe")

    if args.text:
        print("PATH;NX;ASLR;SAFESEH;CFG")

    for path in files:
        flags = PESecurityFlags(path)
        flags.print(color=(not args.text))
