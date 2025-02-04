#!/usr/bin/env python3
# (c) flatz
# converted to python3 by stoykow

import string
import sys, os, struct
import argparse
import shutil
import distutils.dir_util
import math

from hexdump import hexdump
from pprint import pprint

#
# #
# # #
# # # # downgrade elf
# # #
# #
#

def align_up(x, alignment):
    return (x + (alignment - 1)) & ~(alignment - 1)

def align_down(x, alignment):
    return x & ~(alignment - 1)

def is_intervals_overlap(p1, p2):
    return p1[0] <= p2[1] and p1[1] <= p2[0]

def check_file_magic(f, expected_magic):
    old_offset = f.tell()
    try:
        magic = f.read(len(expected_magic))
    except:
        return False
    finally:
        f.seek(old_offset)
    return (magic == expected_magic)

def check_sdk_version(sdk_version):
    if len(sdk_version) != 10:
        return False
    parts = sdk_version.split('.', 2)
    if len(parts) != 3:
        return False
    try:
        lengths = [2, 3, 3]
        for i, n in enumerate(parts):
            if len(n) != lengths[i]:
                return False
            _ = int(n, 10)
    except:
        return False
    return True

# SDK version have 001 in "patch" field
def parse_sdk_version(sdk_version):
    major = sdk_version >> 24
    minor = (sdk_version >> 12) & 0xFFF
    patch = sdk_version & 0xFFF
    return major, minor, patch

def stringify_sdk_version(major, minor, patch):
    return '{0:02x}.{1:03x}.{2:03x}'.format(major, minor, patch)

def unstringify_sdk_version(sdk_version):
    # e.g. "05.050.001" => (5, 50, 1) in hex
    major, minor, patch = map(lambda x: int(x, 16), sdk_version.split('.', 2))
    return major, minor, patch

def build_sdk_version(major, minor, patch):
    return ((major & 0xFF) << 24) | ((minor & 0xFFF) << 12) | (patch & 0xFFF)

# Tag for SCE string table size
DT_SCE_JMPREL       = 0x61000029
DT_SCE_PLTRELSZ     = 0x6100002D
DT_SCE_RELASZ       = 0x61000031
DT_SCE_SYMTAB       = 0x61000039
DT_SCE_SYMENT       = 0x6100003B
DT_SCE_HASHSZ       = 0x6100003D
DT_SCE_SYMTABSZ     = 0x6100003F

ENUM_RELA_TYPES = dict(
    R_AMD64_NONE        = 0x00000000,
    R_AMD64_64          = 0x00000001,
    R_AMD64_PC32        = 0x00000002,
    R_AMD64_GOT32       = 0x00000003,
    R_AMD64_PLT32       = 0x00000004,
    R_AMD64_COPY        = 0x00000005,
    R_AMD64_GLOB_DAT    = 0x00000006,
    R_AMD64_JUMP_SLOT   = 0x00000007,
    R_AMD64_RELATIVE    = 0x00000008,
    R_AMD64_GOTPCREL    = 0x00000009,
    R_AMD64_32          = 0x0000000A,
    R_AMD64_32S         = 0x0000000B,
    R_AMD64_16          = 0x0000000C,
    R_AMD64_PC16        = 0x0000000D,
    R_AMD64_8           = 0x0000000E,
    R_AMD64_PC8         = 0x0000000F,
    R_AMD64_DTPMOD64    = 0x00000010,
    R_AMD64_DTPOFF64    = 0x00000011,
    R_AMD64_TPOFF64     = 0x00000012,
    R_AMD64_TLSGD       = 0x00000013,
    R_AMD64_TLSLD       = 0x00000014,
    R_AMD64_DTPOFF32    = 0x00000015,
    R_AMD64_GOTTPOFF    = 0x00000016,
    R_AMD64_TPOFF32     = 0x00000017,
    R_AMD64_PC64        = 0x00000018,
    R_AMD64_GOTOFF64    = 0x00000019,
    R_AMD64_GOTPC32     = 0x0000001A,
)

ENUM_SYMTAB_BINDS = dict(
     STB_LOCAL          = 0x00000000,
     STB_GLOBAL         = 0x00000001,
     STB_WEAK           = 0x00000002,
)

ENUM_SYMTAB_TYPES = dict(
    STT_NOTYPE          = 0x00000000,
    STT_OBJECT          = 0x00000001,
    STT_FUNC            = 0x00000002,
    STT_SECTION         = 0x00000003,
    STT_FILE            = 0x00000004,
    STT_COMMON          = 0x00000005,
    STT_TLS             = 0x00000006,
)

class ElfProgramHeader(object):
    FMT = '<2I6Q'

    PT_NULL = 0x0
    PT_LOAD = 0x1
    PT_DYNAMIC = 0x2
    PT_INTERP = 0x3
    PT_TLS = 0x7
    PT_SCE_DYNLIBDATA = 0x61000000
    PT_SCE_PROCPARAM = 0x61000001
    PT_SCE_MODULE_PARAM = 0x61000002
    PT_SCE_RELRO = 0x61000010
    PT_SCE_COMMENT = 0x6FFFFF00
    PT_SCE_VERSION = 0x6FFFFF01
    PT_GNU_EH_FRAME = 0x6474E550

    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4
    PF_RX = PF_R | PF_X
    PF_RW = PF_R | PF_W

    def __init__(self):
        self.type = None
        self.offset = None
        self.vaddr = None
        self.paddr = None
        self.file_size = None
        self.mem_size = None
        self.flags = None
        self.align = None

    def load(self, f):
        data = f.read(struct.calcsize(ElfProgramHeader.FMT))
        if len(data) != struct.calcsize(ElfProgramHeader.FMT):
            return False
        (self.type, self.flags, self.offset, self.vaddr, self.paddr,
         self.file_size, self.mem_size, self.align) = struct.unpack(ElfProgramHeader.FMT, data)
        return True

    def save(self, f):
        data = struct.pack(
            ElfProgramHeader.FMT,
            self.type,
            self.flags,
            self.offset,
            self.vaddr,
            self.paddr,
            self.file_size,
            self.mem_size,
            self.align
        )
        if not args.dry_run:
            f.write(data)
        return True

class ElfSectionHeader(object):
    FMT = '<2I4Q2I2Q'

    def __init__(self, fmt):
        self.name = None
        self.type = None
        self.flags = None
        self.addr = None
        self.offset = None
        self.size = None
        self.link = None
        self.info = None
        self.align = None
        self.entry_size = None

    def load(self, f):
        data = f.read(struct.calcsize(ElfProgramHeader.FMT))
        if len(data) != struct.calcsize(ElfProgramHeader.FMT):
            return False
        (self.name, self.type, self.flags, self.addr, self.offset,
         self.size, self.link, self.info, self.align,
         self.entry_size) = struct.unpack(ElfProgramHeader.FMT, data)
        return True

    def save(self, f):
        data = struct.pack(
            ElfProgramHeader.FMT,
            self.name,
            self.type,
            self.flags,
            self.addr,
            self.offset,
            self.size,
            self.link,
            self.info,
            self.align,
            self.entry_size
        )
        if not args.dry_run:
            f.write(data)
        return True

class ElfFile(object):
    # Must be bytes in Python 3
    MAGIC = b'\x7FELF'

    FMT = '<4s5B6xB2HI3QI6H'

    CLASS_NONE = 0
    CLASS_64 = 2

    DATA_NONE = 0
    DATA_LSB = 1

    VERSION_CURRENT = 1

    MACHINE_X86_64 = 0x3E

    TYPE_EXEC = 0x2
    TYPE_SCE_EXEC = 0xFE00
    TYPE_SCE_EXEC_ASLR = 0xFE10
    TYPE_SCE_DYNAMIC = 0xFE18

    def __init__(self):
        self.magic = None
        self.cls = None
        self.encoding = None
        self.version = None
        self.os_abi = None
        self.abi_version = None
        self.nident_size = None
        self.type = None
        self.machine = None
        self.version = None
        self.entry = None
        self.phdr_offset = None
        self.shdr_offset = None
        self.flags = None
        self.ehdr_size = None
        self.phdr_size = None
        self.phdr_count = None
        self.shdr_size = None
        self.shdr_count = None
        self.shdr_strtable_idx = None

        self.phdrs = None
        self.shdrs = None

    def check(self, f):
        old_offset = f.tell()
        try:
            result = check_file_magic(f, ElfFile.MAGIC)
        except:
            return False
        finally:
            f.seek(old_offset)
        return result

    def load(self, f):
        data = f.read(struct.calcsize(ElfFile.FMT))
        if len(data) != struct.calcsize(ElfFile.FMT):
            print('error: unable to read header')
            return False

        (self.magic, self.cls, self.encoding, self.legacy_version,
         self.os_abi, self.abi_version, self.nident_size,
         self.type, self.machine, self.version,
         self.entry, self.phdr_offset, self.shdr_offset,
         self.flags, self.ehdr_size, self.phdr_size,
         self.phdr_count, self.shdr_size, self.shdr_count,
         self.shdr_strtable_idx) = struct.unpack(ElfFile.FMT, data)

        if self.magic != ElfFile.MAGIC:
            # self.magic is bytes, so can't do {0:08X} directly
            print('error: invalid magic: {!r}'.format(self.magic))
            return False
        if self.encoding != ElfFile.DATA_LSB:
            print('error: unsupported encoding: 0x{0:02X}'.format(self.encoding))
            return False
        if self.legacy_version != ElfFile.VERSION_CURRENT:
            raise Exception('Unsupported version: 0x{0:x}'.format(self.version))
        if self.cls != ElfFile.CLASS_64:
            print('error: unsupported class: 0x{0:02X}'.format(self.cls))
            return False
        if self.type not in [ElfFile.TYPE_SCE_EXEC, ElfFile.TYPE_SCE_EXEC_ASLR, ElfFile.TYPE_SCE_DYNAMIC]:
            print('error: unsupported type: 0x{0:04X}'.format(self.type))
            return False
        if self.machine != ElfFile.MACHINE_X86_64:
            print('error: unexpected machine: 0x{0:X}'.format(self.machine))
            return False
        if self.ehdr_size != struct.calcsize(ElfFile.FMT):
            print('error: invalid elf header size: 0x{0:X}'.format(self.ehdr_size))
            return False
        if self.phdr_size > 0 and self.phdr_size != struct.calcsize(ElfProgramHeader.FMT):
            print('error: invalid program header size: 0x{0:X}'.format(self.phdr_size))
            return False
        if self.shdr_size > 0 and self.shdr_size != struct.calcsize(ElfSectionHeader.FMT):
            print('error: invalid section header size: 0x{0:X}'.format(self.shdr_size))
            return False

        self.phdrs = []
        for i in range(self.phdr_count):
            phdr = ElfProgramHeader()
            f.seek(self.phdr_offset + i * self.phdr_size)
            if not phdr.load(f):
                print('error: unable to load program header #{0}'.format(i))
                return False
            self.phdrs.append(phdr)

        self.shdrs = []
        # if self.shdr_size > 0:
        #     for i in range(self.shdr_count):
        #         shdr = ElfSectionHeader()
        #         f.seek(self.shdr_offset + i * self.shdr_size)
        #         if not shdr.load(f):
        #             print('error: unable to load section header #{0}'.format(i))
        #             return False
        #         self.shdrs.append(shdr)

        return True

    def save_hdr(self, f):
        data = struct.pack(
            ElfFile.FMT,
            self.magic, self.cls, self.encoding,
            self.legacy_version, self.os_abi, self.abi_version,
            self.nident_size, self.type, self.machine,
            self.version, self.entry, self.phdr_offset,
            self.shdr_offset, self.flags, self.ehdr_size,
            self.phdr_size, self.phdr_count, self.shdr_size,
            self.shdr_count, self.shdr_strtable_idx
        )
        if len(data) != struct.calcsize(ElfFile.FMT):
            print('error: unable to save header')
            return False

        if not args.dry_run:
            f.write(data)

        for i, phdr in enumerate(self.phdrs):
            f.seek(self.phdr_offset + i * self.phdr_size)
            if not phdr.save(f):
                print('error: unable to save program header #{0}'.format(i))
                return False

        for i, shdr in enumerate(self.shdrs):
            f.seek(self.shdr_offset + i * self.shdr_size)
            if not shdr.save(f):
                print('error: unable to save section header #{0}'.format(i))
                return False

        return True

    def get_phdr_by_type(self, ttype):
        for i, phdr in enumerate(self.phdrs):
            if phdr.type == ttype:
                return phdr
        return None

class MyParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.stderr.write('\nerror: {0}\n'.format(message))
        sys.exit(2)

def CheckHexText(source, length, add_0x):  # returns the hex text
    source_hex = str(hex(source)[2:])
    source_hex_length = len(source_hex)
    source_hex_index = None
    source_hex_cell = None

    for source_hex_index in range(source_hex_length):
        source_hex_cell = source_hex[source_hex_index]
        if (source_hex_cell not in string.hexdigits):
            source_hex = source_hex[:source_hex_index]
            break

    result = str(source_hex.zfill(length))
    if add_0x is True:
        result = "0x" + result
    return result

def add_replacement(old_value, new_value, struct_fmt):
    replacement_old_value_bytes = struct.pack(struct_fmt, old_value)
    replacement_new_value_bytes = struct.pack(struct_fmt, new_value)
    replacement_value_size = struct.calcsize(struct_fmt)
    replacement_min_segments_index = 0
    return [
        old_value,
        replacement_old_value_bytes,
        new_value,
        replacement_new_value_bytes,
        replacement_value_size,
        replacement_min_segments_index
    ]

def remove_replacements_duplicates(replacements):
    if not replacements:
        return []
    current_result = []
    replacements_old_value_list = []
    for replacement in replacements:
        replacement_old_value = replacement[0]
        if replacement_old_value not in replacements_old_value_list:
            current_result.append(replacement)
            replacements_old_value_list.append(replacement_old_value)
    return current_result

def print_patch_memhole_references_help():
    print("patch memhole references options:")
    print(
        "00x:\t0 - don't patch memory hole segments bytes"
        + "\n\t1 - patch memory hole segments bytes"
        + "\n0x0:\t0 - don't patch memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0"
        + "\n\t1 - patch memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0"
        + "\nx00:\t0 - don't patch memory hole segments bytes with addresses that aren't a multiple of 8"
        + "\n\t1 - patch memory hole segments bytes with addresses that aren't a multiple of 8"
    )

Debug = False

parser = MyParser(description='elf downgrader tool')

if not Debug:
    parser.add_argument('--input', required=False, type=str, help='old file')
    parser.add_argument('--output', required=False, default="", type=str, help='new file')
    parser.add_argument('--dry-run', required=False, default=False, action='store_true', help='if inserted then nothing will be written to the output file')
    parser.add_argument('--verbose', required=False, default=False, action='store_true', help='detailed printing')
    parser.add_argument('--overwrite', required=False, default=False, action='store_true')
    parser.add_argument('--sdk-version', required=False, default="0", type=str,
                        help='wanted sdk version, leave empty/0 for no patching (e.g. 05.050.001)')
    parser.add_argument('--add-modded-to-output', required=False, default=False, action='store_true',
                        help='if true then adds _modded to the output file name')
    parser.add_argument('--patch-memhole', required=False, default="1", type=str,
                        help="0 - don't patch, 1 - extend the memory size, 2 - move subsequent segments")
    parser.add_argument('--patch-memhole-references', required=False, default="001", type=str,
                        help="use --patch-memhole-references-help to see usage")
    parser.add_argument('--patch-memhole-references-help', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-program-headers', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-dynamic-section', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-relocation-section', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-symbol-table', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-elf-header', required=False, default=False, action='store_true')

    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(1)
else:
    # Debug defaults
    parser.add_argument('--input', required=False, default="C:/somefolder/somefile.elf", type=str)
    parser.add_argument('--output', required=False, default="", type=str)
    parser.add_argument('--dry-run', required=False, default=False, action='store_true')
    parser.add_argument('--verbose', required=False, default=False, action='store_true')
    parser.add_argument('--overwrite', required=False, default=False, action='store_true')
    parser.add_argument('--sdk-version', required=False, default="0", type=str)
    parser.add_argument('--add-modded-to-output', required=False, default=False, action='store_true')
    parser.add_argument('--patch-memhole', required=False, default="1", type=str)
    parser.add_argument('--patch-memhole-references', required=False, default="001", type=str)
    parser.add_argument('--patch-memhole-references-help', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-program-headers', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-dynamic-section', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-relocation-section', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-symbol-table', required=False, default=False, action='store_true')
    parser.add_argument('--not-patch-elf-header', required=False, default=False, action='store_true')

args = parser.parse_args()

if args.patch_memhole_references_help:
    print_patch_memhole_references_help()
    sys.exit(1)

input_file_path = os.path.abspath(args.input).replace('\\','/')
if not os.path.isfile(input_file_path):
    parser.error('invalid input file: {0}'.format(input_file_path))

input_folder_path = os.path.dirname(input_file_path).replace('\\','/')
if input_folder_path.endswith('/'):
    input_folder_path = input_folder_path[:-1]

if args.output == "":
    input_file_name = os.path.basename(input_file_path)
    input_file_name_length = len(input_file_name)
    input_file_name_splitted = input_file_name.split(".")
    input_file_name_splitted_amount = len(input_file_name_splitted)
    input_file_name_extension = input_file_name_splitted[input_file_name_splitted_amount - 1]
    input_file_name_extension_length = len(input_file_name_extension)
    input_file_name_without_extension = input_file_name[:input_file_name_length - input_file_name_extension_length - 1]

    output_file_name_without_extension = input_file_name_without_extension
    if args.add_modded_to_output:
        output_file_name_without_extension += "_modded"
    output_file_name = output_file_name_without_extension + '.' + input_file_name_extension

    if args.overwrite:
        output_folder_path = input_folder_path + "/backup"
        output_file_path = output_folder_path + "/" + output_file_name
    else:
        output_folder_path = input_folder_path
        if not args.add_modded_to_output:
            output_folder_path += "/output"
        output_file_path = output_folder_path + "/" + output_file_name
else:
    output_file_path = os.path.abspath(args.output).replace('\\','/')
    output_folder_path = os.path.dirname(output_file_path).replace('\\','/')

if not args.dry_run:
    distutils.dir_util.mkpath(output_folder_path)

if os.path.exists(output_file_path) and not os.path.isfile(output_file_path):
    parser.error('invalid output file: {0}'.format(output_file_path))

if not args.dry_run:
    shutil.copyfile(input_file_path, output_file_path)

if args.overwrite:
    output_file_path = input_file_path

if args.dry_run:
    output_file_path_fixed = input_file_path
else:
    output_file_path_fixed = output_file_path

print(
    "Input:" + ' ' + input_file_path + "\n"
    + "Output:" + ' ' + output_file_path + "\n"
    + "Dry Run:" + ' ' + ("True" if args.dry_run else "False") + "\n"
    + "Verbose:" + ' ' + ("True" if args.verbose else "False") + "\n"
    + "Overwrite:" + ' ' + ("True" if args.overwrite else "False") + "\n"
    + "Sdk Version:" + ' ' + ("Not Patching" if args.sdk_version == "0" else args.sdk_version) + "\n"
    + "Add _modded to Output:" + ' ' + ("True" if args.add_modded_to_output else "False") + "\n"
    + "Patch Memory Hole:" + ' ' + args.patch_memhole + "\n"
    + "Patch Memory Hole References:" + ' ' + args.patch_memhole_references + "\n"
    + "Patch Memory Hole References Help:" + ' ' + ("True" if args.patch_memhole_references_help else "False") + "\n"
    + "Patch Program Headers:" + ' ' + ("False" if args.not_patch_program_headers else "True") + "\n"
    + "Patch Dynamic Section:" + ' ' + ("False" if args.not_patch_dynamic_section else "True") + "\n"
    + "Patch Relocation Section:" + ' ' + ("False" if args.not_patch_relocation_section else "True") + "\n"
    + "Patch Symbol Table:" + ' ' + ("False" if args.not_patch_symbol_table else "True") + "\n"
    + "Patch Elf Header:" + ' ' + ("False" if args.not_patch_elf_header else "True")
)

print("")
print('processing elf file: {0}'.format(output_file_path))

with open(output_file_path_fixed, 'rb+') as f:
    elf = ElfFile()

    Headers = None
    Fields = None
    FieldsIndex = None

    AddressesLength = 8  #16
    MemorySizeLength = 8 #16
    SymbolsSizeLength = 4
    SymbolsLength = 8
    TagsLength = 8
    TypesLength = 8
    ValuesLength = 8  #16
    
    struct_fmt = None
    struct_size = None

    method_found = False
    error_found = False
    has_changes = False
    selfutil_detected = False

    if not elf.check(f):
        print('error: invalid elf file format')
        sys.exit(1)

    if not elf.load(f):
        print('error: unable to load elf file')
        sys.exit(1)

    #
    # Patching proc/module param structure.
    #

    if elf.type in [ElfFile.TYPE_SCE_EXEC, ElfFile.TYPE_SCE_EXEC_ASLR]:
        needed_type = ElfProgramHeader.PT_SCE_PROCPARAM
        param_magic = b'ORBI'
        print("")
        print('executable file detected')
    elif elf.type == ElfFile.TYPE_SCE_DYNAMIC:
        needed_type = ElfProgramHeader.PT_SCE_MODULE_PARAM
        param_magic = b'\xBF\xF4\x13\x3C'
        print("")
        print('module file detected')
    else:
        print('error: unsupported elf type')
        sys.exit(1)

    if args.sdk_version == "0":
        new_sdk_version = 0
    else:
        major, minor, patch = unstringify_sdk_version(args.sdk_version)
        new_sdk_version = build_sdk_version(major, minor, patch)
        new_sdk_version_str = stringify_sdk_version(major, minor, patch)
        print('wanted sdk version: {0}'.format(new_sdk_version_str))

        print("")
        print('searching for {0} param segment'.format(
            'proc' if needed_type == ElfProgramHeader.PT_SCE_PROCPARAM else 'module'
        ))

        phdr = elf.get_phdr_by_type(needed_type)
        if phdr is not None:
            print('found param segment, parsing param structure')
            struct_fmt = '<I'
            f.seek(phdr.offset)
            data = f.read(phdr.file_size)
            if len(data) != phdr.file_size:
                print('error: insufficient data read')
                sys.exit(1)

            param_size, = struct.unpack(struct_fmt, data[0x0:0x4])
            if param_size < 0x14:
                print('error: param structure is too small')
                sys.exit(1)
            data = data[:param_size]
            if data[0x8:0xC] != param_magic:
                print('error: unexpected param structure format')
                sys.exit(1)

            old_sdk_version, = struct.unpack(struct_fmt, data[0x10:0x14])
            maj, mn, pt = parse_sdk_version(old_sdk_version)
            old_sdk_version_str = stringify_sdk_version(maj, mn, pt)
            print('sdk version: {0}'.format(old_sdk_version_str))

            if old_sdk_version > new_sdk_version:
                print("")
                print('patching param structure')
                if not args.dry_run:
                    f.seek(phdr.offset + 0x10)
                    f.write(struct.pack(struct_fmt, new_sdk_version))
                print('patched param structure')
            print('parsed param structure')
        else:
            print('warning: param segment not found (elf from old sdk?)')

    #
    # Removing memory holes in PHDRs.
    # Prevents error on old kernel versions: uncountigous RELRO and DATA segments
    #

    if new_sdk_version < 0x06000000:  # less than 6.00 fw
        segments = []
        segments_length = None
        segments_index = 1
        segments_indexA = None
        segments_indexB = None
        segment = None
        previous_segment = None
        next_segment = None

        dynamicPH = None
        dynlibDataPH = None

        DynamicTableEntriesAmount = None
        DynamicTableEntriesIndex = None
        DynamicTable_addr = None
        
        RelaTableSize = 0
        RelaTableEntriesAmount = None
        RelaTableEntriesIndex = None
        RelaTable_addr = None
        
        SymTableSize = 0
        SymTableEntriesAmount = None
        SymTableEntriesIndex = None
        SymTable_addr = None

        FirstSegment_VirtualAddress = None
        SegmentBeforeMemHole_VirtualAddress = None
        SegmentAfterMemHole_Unmapped_VirtualAddress = None
        SegmentAfterMemHole_Mapped_VirtualAddress = None
        SegmentAfterMemHole_FileSize = None
        SegmentAfterMemHole_MemorySize = None
        
        paddr_mem_size = None
        paddr_file_size = None
        paddr_start = None
        paddr_end = None
        paddr_diff = None
        
        vaddr_mem_size = None
        vaddr_file_size = None
        vaddr_start = None
        vaddr_end = None
        vaddr_diff = None

        old_mem_size = None
        new_mem_size = None

        old_paddr = None
        old_vaddr = None
        new_paddr = None
        new_vaddr = None
        mem_size_aligned = None

        faddr = None
        old_struct_data = None
        old_struct_unpacked = None
        new_struct_data_list = None
        new_struct_data = None
        new_struct_unpacked = None

        d_tag = None
        old_d_val = None
        new_d_val = None

        d_val_replacements = None
        d_val_replacements_use = True

        old_r_addr = None
        r_info = None
        r_sym = None
        old_r_addend = None
        new_r_addr = None
        new_r_addend = None

        r_addr_replacements = None
        r_addr_replacements_use = True
        r_addend_replacements = None
        r_addend_replacements_use = True

        r_type = None

        st_name = None
        st_info = None
        st_other = None
        st_shndx = None
        old_st_value = None
        st_size = None
        new_st_value = None

        st_value_replacements = None
        st_value_replacements_use = True
        
        st_type = None
        st_bind = None

        patch_memhole_references_value = int(args.patch_memhole_references, 2)
        patch_memhole_references_enable = ((patch_memhole_references_value & int("001", 2)) > 0)
        patch_memhole_references_patch_rest_bytes_not_zeroes = ((patch_memhole_references_value & int("010", 2)) > 0)
        patch_memhole_references_patch_not_8_multiply = ((patch_memhole_references_value & int("100", 2)) > 0)

        safe_min_bytes_size = None
        safe_min_bytes_amount = None
        safe_min_bytes_estimated_amount = None
        safe_max_bytes_size = None
        safe_max_bytes_amount = None
        safe_max_bytes_estimated_amount = None
        
        replacements = None
        replacements_amount = None
        replacements_min_value = None
        replacements_max_value = None
        replacement = None

        replacement_old_value = None
        replacement_old_value_bytes = None
        replacement_new_value = None
        replacement_new_value_bytes = None
        replacement_value_size = None

        old_replacement_min_segments_index = None
        new_replacement_min_segments_index = None

        SegmentsIndex = 0
        current_value = None
        current_value_size_index = None
        bytes_estimated_index = None
        bytes_index = None

        # Collect candidate segments
        for phdrs_index, phdr in enumerate(elf.phdrs):
            if phdr.type not in [ElfProgramHeader.PT_LOAD, ElfProgramHeader.PT_SCE_RELRO]:
                continue
            if phdr.type == ElfProgramHeader.PT_LOAD and phdr.flags == ElfProgramHeader.PF_RX:
                # skipping text segment
                continue
            segments.append(phdr)

        # Then add any duplicates referencing same paddr/vaddr
        method_found = False
        for phdrs_index, phdr in enumerate(elf.phdrs):
            for s in segments:
                if s == phdr:
                    method_found = True
                    break
            if method_found:
                method_found = False
            else:
                for s in segments:
                    if s.paddr == phdr.paddr:
                        method_found = True
                        break
                if not method_found:
                    for s in segments:
                        if s.vaddr == phdr.vaddr:
                            method_found = True
                            break
                if method_found:
                    method_found = False
                    segments.append(phdr)

        segments_length = len(segments)
        # sort
        segments.sort(key=lambda x: (x.vaddr, -(x.vaddr + x.mem_size)))

        # remove fully overlapping segments
        segments_index = 1
        while segments_index < segments_length:
            segment = segments[segments_index]
            previous_segment = segments[segments_index - 1]
            if (segment.vaddr >= previous_segment.vaddr and
                (segment.vaddr + segment.mem_size <= previous_segment.vaddr + previous_segment.mem_size) and
                segment.type == previous_segment.type):
                segments = segments[:segments_index] + segments[segments_index + 1:]
                segments_length -= 1
            else:
                segments_index += 1

        # If we need patch for "2", find dynamicPH / dynlibDataPH
        if ((not args.not_patch_dynamic_section or not args.not_patch_relocation_section or not args.not_patch_symbol_table)
            and args.patch_memhole == "2"):
            for phdrs_index, phdr in enumerate(elf.phdrs):
                if phdr.type == ElfProgramHeader.PT_DYNAMIC:
                    dynamicPH = phdr
                elif phdr.type == ElfProgramHeader.PT_SCE_DYNLIBDATA:
                    dynlibDataPH = phdr
            if dynamicPH is None:
                print("An error occurred, as the ELF is not a valid OELF!")
                sys.exit(1)

            struct_fmt = '<QQ'
            struct_size = struct.calcsize(struct_fmt)
            DynamicTableEntriesAmount = int(dynamicPH.mem_size / struct_size)
            DynamicTable_addr = dynamicPH.offset
            RelaTable_addr = dynlibDataPH.offset
            SymTable_addr  = dynlibDataPH.offset

        FirstSegment_VirtualAddress = elf.phdrs[0].vaddr

        # If patch_memhole == 2, find RelaTable & SymTable size
        if ((not args.not_patch_relocation_section or not args.not_patch_symbol_table) and args.patch_memhole == "2"):
            for DynamicTableEntriesIndex in range(DynamicTableEntriesAmount):
                struct_fmt = '<QQ'
                struct_size = struct.calcsize(struct_fmt)
                f.seek(dynamicPH.offset + (DynamicTableEntriesIndex * struct_size))
                d_tag, d_val = struct.unpack(struct_fmt, f.read(struct_size))
                if d_tag == DT_SCE_JMPREL:
                    RelaTable_addr += d_val
                elif d_tag == DT_SCE_PLTRELSZ:
                    RelaTableSize += d_val
                elif d_tag == DT_SCE_RELASZ:
                    RelaTableSize += d_val
                elif d_tag == DT_SCE_SYMTAB:
                    SymTable_addr += d_val
                elif d_tag == DT_SCE_SYMTABSZ:
                    SymTableSize += d_val

            # Rela table
            struct_fmt = '<QLLq'
            struct_size = struct.calcsize(struct_fmt)
            RelaTableEntriesAmount = int(RelaTableSize / struct_size)

            # Sym table
            struct_fmt = '<IBBHQQ'
            struct_size = struct.calcsize(struct_fmt)
            SymTableEntriesAmount = int(SymTableSize / struct_size)

        # Now look for actual memholes
        if segments_length > 1:
            for segments_indexA in range(0, segments_length - 1):
                segment = segments[segments_indexA]
                next_segment = segments[segments_indexA + 1]
                mem_size_aligned = align_up(segment.mem_size, 0x4000)
                if (segment.vaddr + mem_size_aligned) < next_segment.vaddr:
                    print("")
                    print(
                        "found a memhole between:"
                        + ' ' + CheckHexText(segment.vaddr + mem_size_aligned, AddressesLength, True)
                        + ' ' + '-' + ' ' + CheckHexText(next_segment.vaddr, AddressesLength, True)
                        + ' ' + "(not including the last address)"
                    )
                    old_mem_size = segment.mem_size
                    old_paddr = next_segment.paddr
                    old_vaddr = next_segment.vaddr
                    paddr_mem_size = next_segment.mem_size
                    vaddr_mem_size = next_segment.mem_size
                    paddr_file_size = next_segment.file_size
                    vaddr_file_size = next_segment.file_size
                    paddr_start = old_paddr
                    vaddr_start = old_vaddr

                    if args.not_patch_program_headers or args.patch_memhole == "0":
                        new_mem_size = old_mem_size
                        new_paddr = old_paddr
                        new_vaddr = old_vaddr
                        paddr_end = paddr_start + paddr_mem_size - 1
                        vaddr_end = vaddr_start + vaddr_mem_size - 1
                        paddr_diff = old_paddr - new_paddr
                        vaddr_diff = old_vaddr - new_vaddr
                    else:
                        print("")
                        print("patching program headers")
                        if args.patch_memhole == "1":
                            new_mem_size = old_vaddr - segment.vaddr
                        elif args.patch_memhole == "2":
                            new_mem_size = mem_size_aligned

                        if args.patch_memhole == "1":
                            new_paddr = old_paddr
                            new_vaddr = old_vaddr
                        elif args.patch_memhole == "2":
                            new_paddr = segment.paddr + new_mem_size
                            new_vaddr = segment.vaddr + new_mem_size

                        segment.mem_size = new_mem_size
                        paddr_diff = old_paddr - new_paddr
                        vaddr_diff = old_vaddr - new_vaddr

                        if args.patch_memhole == "2":
                            next_segment.paddr = new_paddr
                            next_segment.vaddr = new_vaddr
                            if segments_length > segments_indexA + 2:
                                for segments_indexB in range(segments_indexA + 2, segments_length):
                                    if old_paddr == segments[segments_indexB].paddr:
                                        method_found = True
                                        segments[segments_indexB].paddr = new_paddr
                                    if old_vaddr == segments[segments_indexB].vaddr:
                                        method_found = True
                                        segments[segments_indexB].vaddr = new_vaddr
                                    if segments[segments_indexB].mem_size > paddr_mem_size:
                                        method_found = True
                                        paddr_mem_size = segments[segments_indexB].mem_size
                                    if segments[segments_indexB].mem_size > vaddr_mem_size:
                                        method_found = True
                                        vaddr_mem_size = segments[segments_indexB].mem_size
                                    if segments[segments_indexB].file_size > paddr_file_size:
                                        method_found = True
                                        paddr_file_size = segments[segments_indexB].file_size
                                    if segments[segments_indexB].file_size > vaddr_file_size:
                                        method_found = True
                                        vaddr_file_size = segments[segments_indexB].file_size
                                    if method_found:
                                        method_found = False
                                    else:
                                        break
                            paddr_end = paddr_start + paddr_mem_size - 1
                            vaddr_end = vaddr_start + vaddr_mem_size - 1

                            for phdrs_index, phdrx in enumerate(elf.phdrs):
                                if (phdrx.paddr > old_paddr or phdrx.vaddr > old_vaddr):
                                    if phdrx.paddr > old_paddr:
                                        phdrx.paddr -= paddr_diff
                                    if phdrx.vaddr > old_vaddr:
                                        phdrx.vaddr -= vaddr_diff
                                    if (phdrx.paddr + phdrx.mem_size - 1) > paddr_end:
                                        paddr_end = phdrx.paddr + phdrx.mem_size - 1
                                    if (phdrx.vaddr + phdrx.mem_size - 1) > vaddr_end:
                                        vaddr_end = phdrx.vaddr + phdrx.mem_size - 1
                        else:
                            paddr_end = paddr_start + paddr_mem_size - 1
                            vaddr_end = vaddr_start + vaddr_mem_size - 1

                        if args.verbose:
                            Headers = ["Old Memory Size", "New Memory Size", "Old Address", "New Address"]
                            Fields = []
                            Fields.append(Headers[0] + ':' + ' ' + CheckHexText(old_mem_size, MemorySizeLength, True))
                            Fields.append(Headers[1] + ':' + ' ' + CheckHexText(new_mem_size, MemorySizeLength, True))
                            Fields.append(Headers[2] + ':' + ' ' + CheckHexText(old_paddr, AddressesLength, True))
                            Fields.append(Headers[3] + ':' + ' ' + CheckHexText(new_paddr, AddressesLength, True))
                            print('\t'.join(Fields))

                        print("")
                        print("patched program headers")

                    SegmentBeforeMemHole_VirtualAddress = segment.vaddr
                    SegmentAfterMemHole_Unmapped_VirtualAddress = old_vaddr
                    SegmentAfterMemHole_Mapped_VirtualAddress = new_vaddr
                    SegmentAfterMemHole_FileSize = vaddr_file_size
                    SegmentAfterMemHole_MemorySize = vaddr_mem_size

                    # dynamic section patch if patch_memhole == "2"
                    if not args.not_patch_dynamic_section and args.patch_memhole == "2":
                        print("")
                        print("patching dynamic section")
                        if DynamicTableEntriesAmount == 0:
                            print("couldn't find the dynamic section")
                        else:
                            print("Found dynamic section, entries: " + str(DynamicTableEntriesAmount))
                            struct_fmt = '<QQ'
                            struct_size = struct.calcsize(struct_fmt)
                            for DynamicTableEntriesIndex in range(DynamicTableEntriesAmount):
                                faddr = DynamicTable_addr + (DynamicTableEntriesIndex * struct_size)
                                f.seek(faddr)
                                old_struct_data = f.read(struct_size)
                                old_struct_unpacked = struct.unpack(struct_fmt, old_struct_data)
                                d_tag, old_d_val = old_struct_unpacked
                                new_d_val = old_d_val
                                # patch if inside memhole
                                if (d_tag not in [DT_SCE_JMPREL, DT_SCE_PLTRELSZ, DT_SCE_RELASZ, DT_SCE_SYMTAB]):
                                    if new_d_val >= vaddr_start and new_d_val <= vaddr_end:
                                        new_d_val -= vaddr_diff
                                        if d_val_replacements is None:
                                            d_val_replacements = []
                                        d_val_replacements.append(add_replacement(old_d_val, new_d_val, '<Q'))
                                        new_struct_data = struct.pack(struct_fmt, d_tag, new_d_val)
                                        if not args.dry_run:
                                            f.seek(faddr)
                                            f.write(new_struct_data)
                                        if args.verbose:
                                            Headers = ["Entry", "Tag", "Old Value", "New Value"]
                                            Fields = []
                                            Fields.append(Headers[0] + ':' + ' ' + str(DynamicTableEntriesIndex + 1))
                                            Fields.append(Headers[2] + ':' + ' ' + CheckHexText(old_d_val, ValuesLength, True))
                                            Fields.append(Headers[3] + ':' + ' ' + CheckHexText(new_d_val, ValuesLength, True))
                                            print('\t'.join(Fields))
                            print("")
                            print("patched dynamic section")

                    # relocation section patch if patch_memhole == "2"
                    if not args.not_patch_relocation_section and args.patch_memhole == "2":
                        print("")
                        print("patching relocation section")
                        if RelaTableEntriesAmount == 0:
                            print("couldn't find the relocation section")
                        else:
                            print("Found relocation section, entries: " + str(RelaTableEntriesAmount))
                            struct_fmt = '<QLLq'
                            struct_size = struct.calcsize(struct_fmt)
                            for RelaTableEntriesIndex in range(RelaTableEntriesAmount):
                                faddr = RelaTable_addr + (RelaTableEntriesIndex * struct_size)
                                f.seek(faddr)
                                old_struct_data = f.read(struct_size)
                                (old_r_addr, r_info, r_sym, old_r_addend) = struct.unpack(struct_fmt, old_struct_data)
                                new_r_addr = old_r_addr
                                new_r_addend = old_r_addend
                                # patch addresses inside memhole
                                if new_r_addr >= vaddr_start and new_r_addr <= vaddr_end:
                                    if r_addr_replacements is None:
                                        r_addr_replacements = []
                                    diff_repl = add_replacement(old_r_addr, new_r_addr - vaddr_diff, '<Q')
                                    r_addr_replacements.append(diff_repl)
                                    new_r_addr -= vaddr_diff
                                    if args.verbose:
                                        Headers = ["Entry", "Type", "Old Address", "New Address", "Old Addend", "New Addend", "Symbol"]
                                        Fields = []
                                        Fields.append(Headers[0] + ':' + ' ' + str(RelaTableEntriesIndex + 1))
                                        Fields.append(Headers[2] + ':' + ' ' + CheckHexText(old_r_addr, AddressesLength, True))
                                        Fields.append(Headers[3] + ':' + ' ' + CheckHexText(new_r_addr, AddressesLength, True))
                                        print('\t'.join(Fields))
                                if new_r_addend >= vaddr_start and new_r_addend <= vaddr_end:
                                    if r_addend_replacements is None:
                                        r_addend_replacements = []
                                    diff_repl = add_replacement(old_r_addend, new_r_addend - vaddr_diff, '<q')
                                    r_addend_replacements.append(diff_repl)
                                    new_r_addend -= vaddr_diff
                                    if args.verbose:
                                        Headers = ["Entry", "Type", "Old Address", "New Address", "Old Addend", "New Addend", "Symbol"]
                                        Fields = []
                                        Fields.append(Headers[0] + ':' + ' ' + str(RelaTableEntriesIndex + 1))
                                        Fields.append(Headers[4] + ':' + ' ' + CheckHexText(old_r_addend, AddressesLength, True))
                                        Fields.append(Headers[5] + ':' + ' ' + CheckHexText(new_r_addend, AddressesLength, True))
                                        print('\t'.join(Fields))
                                # write if changed
                                if (new_r_addr != old_r_addr) or (new_r_addend != old_r_addend):
                                    new_struct_data = struct.pack(struct_fmt, new_r_addr, r_info, r_sym, new_r_addend)
                                    if not args.dry_run:
                                        f.seek(faddr)
                                        f.write(new_struct_data)
                            print("")
                            print("patched relocation section")

                    # symbol table patch if patch_memhole == "2"
                    if not args.not_patch_symbol_table and args.patch_memhole == "2":
                        print("")
                        print("patching symbol table")
                        if SymTableEntriesAmount == 0:
                            print("couldn't find the symbol table")
                        else:
                            print("Found symbol table, entries: " + str(SymTableEntriesAmount))
                            struct_fmt = '<IBBHQQ'
                            struct_size = struct.calcsize(struct_fmt)
                            for SymTableEntriesIndex in range(SymTableEntriesAmount):
                                faddr = SymTable_addr + (SymTableEntriesIndex * struct_size)
                                f.seek(faddr)
                                old_struct_data = f.read(struct_size)
                                (st_name, st_info, st_other, st_shndx, old_st_value, st_size) = struct.unpack(struct_fmt, old_struct_data)
                                new_st_value = old_st_value
                                # if st_value is in hole, fix
                                if new_st_value >= vaddr_start and new_st_value <= vaddr_end:
                                    if st_value_replacements is None:
                                        st_value_replacements = []
                                    st_value_replacements.append(add_replacement(old_st_value, new_st_value - vaddr_diff, '<Q'))
                                    new_st_value -= vaddr_diff
                                    new_struct_data = struct.pack(struct_fmt, st_name, st_info, st_other, st_shndx, new_st_value, st_size)
                                    if not args.dry_run:
                                        f.seek(faddr)
                                        f.write(new_struct_data)
                                    if args.verbose:
                                        Headers = ["Entry","Type","Bind","Ndx","Name","Old Value","New Value","Size","Info","Other"]
                                        Fields = []
                                        Fields.append(Headers[0] + ':' + ' ' + str(SymTableEntriesIndex + 1))
                                        Fields.append(Headers[5] + ':' + ' ' + CheckHexText(old_st_value, AddressesLength, True))
                                        Fields.append(Headers[6] + ':' + ' ' + CheckHexText(new_st_value, AddressesLength, True))
                                        Fields.append(Headers[7] + ':' + ' ' + CheckHexText(st_size, SymbolsSizeLength, True))
                                        print('\t'.join(Fields))
                            print("")
                            print("patched symbol table")

                    # memory hole references patch if patch_memhole_references_enable and patch_memhole == "2"
                    if patch_memhole_references_enable and args.patch_memhole == "2":
                        print("")
                        print("patching memory hole references between the segment before the memory hole to the segment after the memory hole and its file size")
                        struct_size = SegmentAfterMemHole_Mapped_VirtualAddress + SegmentAfterMemHole_FileSize - SegmentBeforeMemHole_VirtualAddress
                        replacements = (
                            (st_value_replacements if st_value_replacements and st_value_replacements_use else [])
                            + (r_addend_replacements if r_addend_replacements and r_addend_replacements_use else [])
                            + (d_val_replacements if d_val_replacements and d_val_replacements_use else [])
                            + (r_addr_replacements if r_addr_replacements and r_addr_replacements_use else [])
                        )
                        replacements = remove_replacements_duplicates(replacements)
                        if replacements:
                            replacements_amount = len(replacements)
                        else:
                            replacements_amount = 0
                        print("Found memory hole references section, entries: " + str(struct_size))
                        if replacements_amount > 0:
                            faddr = segment.offset
                            f.seek(faddr)
                            old_struct_data = f.read(struct_size)
                            new_struct_data_list = []
                            safe_min_bytes_size = int(SegmentAfterMemHole_Unmapped_VirtualAddress)
                            safe_min_bytes_amount = int(math.ceil(math.log(safe_min_bytes_size, 256)))
                            safe_min_bytes_estimated_amount = int(2**(math.ceil(math.log(safe_min_bytes_amount, 2))))

                            safe_max_bytes_size = int(SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1)
                            safe_max_bytes_amount = int(math.ceil(math.log(safe_max_bytes_size, 256)))
                            safe_max_bytes_estimated_amount = int(2**(math.ceil(math.log(safe_max_bytes_amount, 2))))

                            replacements_min_value = SegmentAfterMemHole_Unmapped_VirtualAddress
                            replacements_max_value = SegmentAfterMemHole_Unmapped_VirtualAddress + SegmentAfterMemHole_MemorySize - 1

                            SegmentsIndex = 0
                            while SegmentsIndex <= struct_size - 1:
                                current_value = 0
                                current_value_size_index = 0
                                bytes_estimated_index = safe_min_bytes_estimated_amount
                                method_found = False

                                while bytes_estimated_index <= safe_max_bytes_estimated_amount:
                                    if SegmentsIndex <= struct_size - bytes_estimated_index:
                                        current_value_size = bytes_estimated_index
                                        current_value = 0
                                        current_value_size_index = 0
                                        while current_value_size_index < current_value_size:
                                            # in Python 3, old_struct_data[...] is int
                                            current_value += (int(pow(256, current_value_size_index))
                                                              * old_struct_data[SegmentsIndex + current_value_size_index])
                                            current_value_size_index += 1
                                        if (current_value >= replacements_min_value and
                                            current_value <= replacements_max_value):
                                            # We found a potential replacement
                                            for replacement in replacements:
                                                replacement_old_value = replacement[0]
                                                replacement_old_value_bytes = replacement[1]
                                                replacement_new_value = replacement[2]
                                                replacement_new_value_bytes = replacement[3]
                                                replacement_value_size = replacement[4]
                                                old_replacement_min_segments_index = replacement[5]
                                                new_replacement_min_segments_index = old_replacement_min_segments_index

                                                # Check if the current segment index >= old repl index
                                                if SegmentsIndex >= old_replacement_min_segments_index:
                                                    if current_value_size <= replacement_value_size:
                                                        # check match of partial bytes
                                                        error_found = False
                                                        for bytes_index in range(current_value_size):
                                                            if old_struct_data[SegmentsIndex + bytes_index] != replacement_old_value_bytes[bytes_index]:
                                                                error_found = True
                                                                break
                                                        if not error_found:
                                                            # check trailing
                                                            for bytes_index in range(current_value_size, replacement_value_size):
                                                                if replacement_old_value_bytes[bytes_index] != 0:
                                                                    error_found = True
                                                                    break
                                                            if not error_found:
                                                                new_replacement_min_segments_index = SegmentsIndex + current_value_size

                                                if new_replacement_min_segments_index != old_replacement_min_segments_index:
                                                    # we might attempt a bigger replacement
                                                    if SegmentsIndex <= struct_size - replacement_value_size:
                                                        for bytes_index in range(current_value_size, replacement_value_size):
                                                            if old_struct_data[SegmentsIndex + bytes_index] != 0:
                                                                error_found = True
                                                                break
                                                    else:
                                                        error_found = True

                                                    if error_found:
                                                        error_found = False
                                                        if patch_memhole_references_patch_rest_bytes_not_zeroes:
                                                            method_found = True
                                                            print("Patching memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0")
                                                        else:
                                                            print("Skipped patch for memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0")
                                                    else:
                                                        method_found = True

                                                    if method_found:
                                                        method_found = False
                                                        if ((SegmentsIndex + SegmentBeforeMemHole_VirtualAddress) % 8) != 0:
                                                            error_found = True
                                                        if error_found:
                                                            if patch_memhole_references_patch_not_8_multiply:
                                                                method_found = True
                                                                print("Patching memory hole segments bytes with an address that isn't a multiple of 8")
                                                            else:
                                                                print("Skipped patch for memory hole segments bytes with an address that isn't a multiple of 8")
                                                        else:
                                                            method_found = True

                                                    if method_found:
                                                        replacement[5] = new_replacement_min_segments_index
                                                        for bytes_index in range(current_value_size):
                                                            new_struct_data_list.append(replacement_new_value_bytes[bytes_index])
                                                        if args.verbose:
                                                            Headers = ["Entry","Address","Old Value","New Value","Section"]
                                                            if d_val_replacements and replacement in d_val_replacements:
                                                                Section = "dynamic values"
                                                            elif r_addr_replacements and replacement in r_addr_replacements:
                                                                Section = "relocation addresses"
                                                            elif r_addend_replacements and replacement in r_addend_replacements:
                                                                Section = "relocation addends"
                                                            else:
                                                                Section = "symbol values"
                                                            Fields = []
                                                            Fields.append(Headers[0] + ':' + ' ' + str(SegmentsIndex + 1))
                                                            Fields.append(Headers[1] + ':' + ' ' + CheckHexText(SegmentsIndex + SegmentBeforeMemHole_VirtualAddress, AddressesLength, True))
                                                            Fields.append(Headers[2] + ':' + ' ' + CheckHexText(replacement_old_value, AddressesLength, True))
                                                            Fields.append(Headers[3] + ':' + ' ' + CheckHexText(replacement_new_value, AddressesLength, True))
                                                            Fields.append(Headers[4] + ':' + ' ' + Section)
                                                            print('\t'.join(Fields))
                                                    else:
                                                        Headers = ["Entry","Address","Value","Section"]
                                                        if d_val_replacements and replacement in d_val_replacements:
                                                            Section = "dynamic values"
                                                        elif r_addr_replacements and replacement in r_addr_replacements:
                                                            Section = "relocation addresses"
                                                        elif r_addend_replacements and replacement in r_addend_replacements:
                                                            Section = "relocation addends"
                                                        else:
                                                            Section = "symbol values"
                                                        Fields = []
                                                        Fields.append(Headers[0] + ':' + ' ' + str(SegmentsIndex + 1))
                                                        Fields.append(Headers[1] + ':' + ' ' + CheckHexText(SegmentsIndex + SegmentBeforeMemHole_VirtualAddress, AddressesLength, True))
                                                        Fields.append(Headers[2] + ':' + ' ' + CheckHexText(replacement_old_value, AddressesLength, True))
                                                        if len(Section) > 0:
                                                            Fields.append(Headers[3] + ':' + ' ' + Section)
                                                        print('(' + '\t'.join(Fields) + ')')

                                                    if method_found:
                                                        SegmentsIndex += current_value_size
                                                        break
                                            if method_found:
                                                break
                                    else:
                                        break
                                    bytes_estimated_index += 1
                                if method_found:
                                    method_found = False
                                else:
                                    # default: keep old byte
                                    new_struct_data_list.append(old_struct_data[SegmentsIndex])
                                    SegmentsIndex += 1

                            new_struct_data = bytes(new_struct_data_list)
                            if not args.dry_run:
                                f.seek(faddr)
                                f.write(new_struct_data)

                        print("")
                        print("patched memory hole references")

                    print("")
                    print("First Segment Virtual Address:" + ' ' + CheckHexText(FirstSegment_VirtualAddress, AddressesLength, True))
                    print("")
                    print("Segment Before Memory Hole Virtual Address:" + ' ' + CheckHexText(SegmentBeforeMemHole_VirtualAddress, AddressesLength, True))
                    print("")
                    print("Segment After Memory Hole Unmapped Virtual Address:" + ' ' + CheckHexText(SegmentAfterMemHole_Unmapped_VirtualAddress, AddressesLength, True))
                    print("Segment After Memory Hole Mapped Virtual Address:" + ' ' + CheckHexText(SegmentAfterMemHole_Mapped_VirtualAddress, AddressesLength, True))
                    print("Segment After Memory Hole Memory Size:" + ' ' + CheckHexText(SegmentAfterMemHole_MemorySize, MemorySizeLength, True))

    #
    # Patching version information in version segment.
    #
    print("")
    print('searching for version segment')

    phdr = elf.get_phdr_by_type(ElfProgramHeader.PT_SCE_VERSION)
    if phdr is not None:
        print('found version segment, parsing library list')
        f.seek(phdr.offset)
        data = f.read(phdr.file_size)
        if len(data) != phdr.file_size:
            print('error: insufficient data read')
            sys.exit(1)

        method_found = False
        # In Python 3, iterating `data` yields ints
        for bval in data:
            if bval != 0:
                method_found = True
                break

        if not method_found:
            selfutil_detected = True
            print("detected the use of selfutil, consider using unfself or selfutil patched (also can't patch the sdk version in the version segment in such a case)")
        else:
            print("detected the use of selfutil patched or unfself")
            if new_sdk_version > 0:
                if phdr.file_size > 0:
                    offset = 0
                    while offset < phdr.file_size:
                        length = data[offset]
                        offset += 1
                        if offset + length > phdr.file_size:
                            break
                        name_slice = data[offset:offset+length]
                        # name, old_sdk_version => split on b':'
                        # first ensure there's a colon
                        colon_pos = name_slice.find(b':')
                        if colon_pos < 0:
                            offset += length
                            continue
                        old_sdk_part = name_slice[colon_pos+1:]
                        name_part = name_slice[:colon_pos]
                        # The original code did:
                        #   name, old_sdk_version = name.split(':',1)
                        #   if len(old_sdk_version) != struct_size => error
                        struct_fmt = 'I'
                        struct_size = struct.calcsize(struct_fmt)
                        if len(old_sdk_part) != struct_size:
                            print('error: unexpected library list entry format')
                            sys.exit(1)
                        # switch to big-endian
                        struct_fmt = '>I'
                        (old_sdk_val,) = struct.unpack(struct_fmt, old_sdk_part)
                        om, on, op = parse_sdk_version(old_sdk_val)
                        old_sdk_str = stringify_sdk_version(om, on, op)
                        if args.verbose:
                            # decode name as ascii
                            try:
                                nm_str = name_part.decode('ascii', 'ignore')
                            except:
                                nm_str = repr(name_part)
                            print('{0} (sdk version: {1})'.format(nm_str, old_sdk_str))

                        if old_sdk_val > new_sdk_version:
                            has_changes = True
                            new_sdk_bytes = struct.pack(struct_fmt, new_sdk_version)
                            new_entry = name_part + b':' + new_sdk_bytes
                            # rebuild data
                            startpos = offset
                            # offset-1 = the place we wrote 'length'
                            # but the Py2 code did data[:offset] + name + ':' + struct.pack(...) + data[offset+length:]
                            # which means the chunk from offset-length => offset was name
                            # The old code effectively replaced the "name" region
                            # Let's do similarly:
                            data = data[:offset] + new_entry + data[offset+length:]
                        offset += length

                    if has_changes:
                        has_changes = False
                        print("")
                        print('patching sdk versions in library list')
                        if not args.dry_run:
                            f.seek(phdr.offset)
                            f.write(data)
                        print('patched sdk versions in library list')

        print('parsed library list')
    else:
        print('version segment not found')

    if not args.not_patch_elf_header:
        #
        # Patching section headers.
        #
        print("")
        print('patching elf header')
        # Prevents error in orbis-bin:
        #   Section header offset (XXX) exceeds file size (YYY).
        elf.shdr_offset = 0
        elf.shdr_count = 0
        print('patched elf header')

    f.seek(0)
    if not elf.save_hdr(f):
        print('error: unable to save elf file')
        sys.exit(1)

    print("")
    print('finished patching:' + ' ' + output_file_path)
