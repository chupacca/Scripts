# GEF PYTHON FILE THAT WAS MODIFIED TO WORK FOR GDB ON WINDOWS
# 
# -*- coding: utf-8 -*-
#
#
#######################################################################################
# GEF-Legacy
#  - Multi-Architecture GDB Enhanced Features for Exploiters & Reverse-Engineers
#
# by  @_hugsy_
#######################################################################################
#
# GEF is a kick-ass set of commands for X86, ARM, MIPS, PowerPC and SPARC to
# make GDB cool again for exploit dev. It is aimed to be used mostly by exploit
# devs and reversers, to provides additional features to GDB using the Python
# API to assist during the process of dynamic analysis.
#
# GEF-Legacy is the Python2 only version of the original GEF, which officially stopped
# supporting by default Python2 when it became EOL (01/01/2020). GEF-Legacy doesn't
# offer all the broad set of features that original GEF as only the command Python2
# compatible can be found. In addition, as of 01/01/2020, no new feature is integrated
# to this code base, although functional bugs are still being taken care of. Please
# report them if you discover any.
#
# GEF-Legacy has full support for both Python2 and works on
#   * x86-32 & x86-64
#   * arm v5,v6,v7
#   * aarch64 (armv8)
#   * mips & mips64
#   * powerpc & powerpc64
#   * sparc & sparc64(v9)
#
# Requires GDB 7.x compiled with Python2
#
# To start: in gdb, type `source /path/to/gef.py`
#
#######################################################################################
#
# gef is distributed under the MIT License (MIT)
# Copyright (c) 2013-2019 crazy rabbidz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#


from __future__ import print_function, division, absolute_import

import abc
import binascii
import codecs
import collections
import ctypes
import functools
import getopt
import hashlib
import imp
import inspect
import itertools
import os
import platform
import re
import shutil
import site
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
import traceback



from HTMLParser import HTMLParser #pylint: disable=import-error
from cStringIO import StringIO #pylint: disable=import-error
from urllib import urlopen #pylint: disable=no-name-in-module
import ConfigParser as configparser #pylint: disable=import-error
import xmlrpclib #pylint: disable=import-error

# Compat Py2/3 hacks
def range(*args):
   """
   Replace range() builtin with an iterator version.
   """
   if len(args) < 1:
       raise TypeError()
   start, end, step = 0, args[0], 1
   if len(args) == 2: start, end = args
   if len(args) == 3: start, end, step = args
   for n in itertools.count(start=start, step=step):
       if (step>0 and n >= end) or (step<0 and n<=end): break
       yield n

FileNotFoundError = IOError #pylint: disable=redefined-builtin
ConnectionRefusedError = socket.error #pylint: disable=redefined-builtin

LEFT_ARROW = "<-"
RIGHT_ARROW = "->"
DOWN_ARROW = "\\->"
HORIZONTAL_LINE = "-"
VERTICAL_LINE = "|"
CROSS = "x"
TICK = "v"
GEF_PROMPT = "gef> "
GEF_PROMPT_ON = "\001\033[1;32m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)
GEF_PROMPT_OFF = "\001\033[1;31m\002{0:s}\001\033[0m\002".format(GEF_PROMPT)


def http_get(url):
    """Basic HTTP wrapper for GET request. Return the body of the page if HTTP code is OK,
    otherwise return None."""
    try:
        http = urlopen(url)
        if http.getcode() != 200:
            return None
        return http.read()
    except Exception:
        return None


def update_gef(argv):
    """Try to update `gef` to the latest version pushed on GitHub. Return 0 on success,
    1 on failure. """
    gef_local = os.path.realpath(argv[0])
    hash_gef_local = hashlib.sha512(open(gef_local, "rb").read()).digest()
    gef_remote = "https://raw.githubusercontent.com/hugsy/gef-legacy/master/gef.py"
    gef_remote_data = http_get(gef_remote)
    if gef_remote_data is None:
        print("[-] Failed to get remote gef")
        return 1

    hash_gef_remote = hashlib.sha512(gef_remote_data).digest()
    if hash_gef_local == hash_gef_remote:
        print("[-] No update")
    else:
        with open(gef_local, "wb") as f:
            f.write(gef_remote_data)
        print("[+] Updated")
    return 0


try:
    import gdb
except ImportError:
    # if out of gdb, the only action allowed is to update gef.py
    if len(sys.argv)==2 and sys.argv[1]=="--update":
        sys.exit(update_gef(sys.argv))
    print("[-] gef cannot run as standalone")
    sys.exit(0)

__gef__                                = None
__commands__                           = []
__functions__                          = []
__aliases__                            = []
__config__                             = {}
__watches__                            = {}
__infos_files__                        = []
__gef_convenience_vars_index__         = 0
__context_messages__                   = []
__heap_allocated_list__                = []
__heap_freed_list__                    = []
__heap_uaf_watchpoints__               = []
__pie_breakpoints__                    = {}
__pie_counter__                        = 1
__gef_remote__                         = None
__gef_qemu_mode__                      = False
__gef_default_main_arena__             = "main_arena"
__gef_int_stream_buffer__              = None

DEFAULT_PAGE_ALIGN_SHIFT               = 12
DEFAULT_PAGE_SIZE                      = 1 << DEFAULT_PAGE_ALIGN_SHIFT
GEF_RC                                 = os.path.join(os.getenv("HOME"), ".gef.rc")
GEF_TEMP_DIR                           = os.path.join(tempfile.gettempdir(), "gef")
GEF_MAX_STRING_LENGTH                  = 50

GDB_MIN_VERSION                         = (7, 7)
GDB_VERSION_MAJOR, GDB_VERSION_MINOR    = [int(_) for _ in re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()]
GDB_VERSION                             = (GDB_VERSION_MAJOR, GDB_VERSION_MINOR)

current_elf  = None
current_arch = None

highlight_table = {}
ANSI_SPLIT_RE = "(\033\[[\d;]*m)"


def lru_cache(maxsize = 128):
    """Port of the Python3 LRU cache mechanism provided by itertools."""
    class GefLruCache(object):
        """Local LRU cache for Python2."""
        def __init__(self, input_func, max_size):
            self._input_func        = input_func
            self._max_size          = max_size
            self._caches_dict       = {}
            self._caches_info       = {}
            return

        def cache_info(self, caller=None):
            """Return a string with statistics of cache usage."""
            if caller not in self._caches_dict:
                return ""
            hits = self._caches_info[caller]["hits"]
            missed = self._caches_info[caller]["missed"]
            cursz = len(self._caches_dict[caller])
            return "CacheInfo(hits={}, misses={}, maxsize={}, currsize={})".format(hits, missed, self._max_size, cursz)

        def cache_clear(self, caller=None):
            """Clear a cache."""
            if caller in self._caches_dict:
                self._caches_dict[caller] = collections.OrderedDict()
            return

        def __get__(self, obj, objtype):
            """Cache getter."""
            return_func = functools.partial(self._cache_wrapper, obj)
            return_func.cache_clear = functools.partial(self.cache_clear, obj)
            return functools.wraps(self._input_func)(return_func)

        def __call__(self, *args, **kwargs):
            """Invoking the wrapped function, by attempting to get its value from cache if existing."""
            return self._cache_wrapper(None, *args, **kwargs)

        __call__.cache_clear = cache_clear
        __call__.cache_info  = cache_info

        def _cache_wrapper(self, caller, *args, **kwargs):
            """Defines the caching mechanism."""
            kwargs_key = "".join(map(lambda x : str(x) + str(type(kwargs[x])) + str(kwargs[x]), sorted(kwargs)))
            key = "".join(map(lambda x : str(type(x)) + str(x) , args)) + kwargs_key
            if caller not in self._caches_dict:
                self._caches_dict[caller] = collections.OrderedDict()
                self._caches_info[caller] = {"hits":0, "missed":0}

            cur_caller_cache_dict = self._caches_dict[caller]
            if key in cur_caller_cache_dict:
                self._caches_info[caller]["hits"] += 1
                return cur_caller_cache_dict[key]

            self._caches_info[caller]["missed"] += 1
            if self._max_size is not None:
                if len(cur_caller_cache_dict) >= self._max_size:
                    cur_caller_cache_dict.popitem(False)

            cur_caller_cache_dict[key] = self._input_func(caller, *args, **kwargs) if caller != None else self._input_func(*args, **kwargs)
            return cur_caller_cache_dict[key]

    return lambda input_func: functools.wraps(input_func)(GefLruCache(input_func, maxsize))


def reset_all_caches():
    """Free all caches. If an object is cached, it will have a callable attribute `cache_clear`
    which will be invoked to purge the function cache."""

    for mod in dir(sys.modules["__main__"]):
        obj = getattr(sys.modules["__main__"], mod)
        if hasattr(obj, "cache_clear"):
            obj.cache_clear()
    return


def highlight_text(text):
    """
    Highlight text using highlight_table { match -> color } settings.

    If RegEx is enabled it will create a match group around all items in the
    highlight_table and wrap the specified color in the highlight_table
    around those matches.

    If RegEx is disabled, split by ANSI codes and 'colorify' each match found
    within the specified string.
    """
    if not highlight_table:
        return text

    if get_gef_setting("highlight.regex"):
        for match, color in highlight_table.items():
            text = re.sub("(" + match + ")", Color.colorify("\\1", color), text)
        return text

    ansiSplit = re.split(ANSI_SPLIT_RE, text)

    for match, color in highlight_table.items():
        for index, val in enumerate(ansiSplit):
            found = val.find(match)
            if found > -1:
                ansiSplit[index] = val.replace(match, Color.colorify(match, color))
                break
        text = "".join(ansiSplit)
        ansiSplit = re.split(ANSI_SPLIT_RE, text)

    return "".join(ansiSplit)


def gef_print(x="", *args, **kwargs):
    """Wrapper around print(), using string buffering feature."""
    x = highlight_text(x)
    if __gef_int_stream_buffer__ and not is_debug():
        return __gef_int_stream_buffer__.write(x + kwargs.get("end", "\n"))
    return print(x, *args, **kwargs)


def bufferize(f):
    """Store the content to be printed for a function in memory, and flush it on function exit."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        global __gef_int_stream_buffer__

        if __gef_int_stream_buffer__:
            return f(*args, **kwargs)

        __gef_int_stream_buffer__ = StringIO()
        try:
            rv = f(*args, **kwargs)
        finally:
            sys.stdout.write(__gef_int_stream_buffer__.getvalue())
            sys.stdout.flush()
            __gef_int_stream_buffer__ = None
        return rv

    return wrapper


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg):       return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg):     return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg):      return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg):    return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg):      return Color.colorify(msg, "gray")
    @staticmethod
    def pinkify(msg):      return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg):      return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg):      return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg):  return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg): return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg):     return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text, attrs):
        """Color text according to the given attributes."""
        if get_gef_setting("gef.disable_color") is True: return text

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg :   msg.append(colors["highlight_off"])
        if colors["underline"] in msg :   msg.append(colors["underline_off"])
        if colors["blink"] in msg :       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)


class Address:
    """GEF representation of memory addresses."""
    def __init__(self, *args, **kwargs):
        self.value = kwargs.get("value", 0)
        self.section = kwargs.get("section", None)
        self.info = kwargs.get("info", None)
        self.valid = kwargs.get("valid", True)
        return

    def __str__(self):
        value = format_address(self.value)
        code_color = get_gef_setting("theme.address_code")
        stack_color = get_gef_setting("theme.address_stack")
        heap_color = get_gef_setting("theme.address_heap")
        if self.is_in_text_segment():
            return Color.colorify(value, code_color)
        if self.is_in_heap_segment():
            return Color.colorify(value, heap_color)
        if self.is_in_stack_segment():
            return Color.colorify(value, stack_color)
        return value

    def is_in_text_segment(self):
        return (hasattr(self.info, "name") and ".text" in self.info.name) or \
            (hasattr(self.section, "path") and get_filepath() == self.section.path and self.section.is_executable())

    def is_in_stack_segment(self):
        return hasattr(self.section, "path") and "[stack]" == self.section.path

    def is_in_heap_segment(self):
        return hasattr(self.section, "path") and "[heap]" == self.section.path

    def dereference(self):
        addr = align_address(long(self.value))
        derefed = dereference(addr)
        return None if derefed is None else long(derefed)


class Permission:
    """GEF representation of Linux permission."""
    NONE      = 0
    READ      = 1
    WRITE     = 2
    EXECUTE   = 4
    ALL       = READ | WRITE | EXECUTE

    def __init__(self, **kwargs):
        self.value = kwargs.get("value", 0)
        return

    def __or__(self, value):
        return self.value | value

    def __and__(self, value):
        return self.value & value

    def __xor__(self, value):
        return self.value ^ value

    def __eq__(self, value):
        return self.value == value

    def __ne__(self, value):
        return self.value != value

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    @staticmethod
    def from_info_sections(*args):
        perm = Permission()
        for arg in args:
            if "READONLY" in arg:
                perm.value += Permission.READ
            if "DATA" in arg:
                perm.value += Permission.WRITE
            if "CODE" in arg:
                perm.value += Permission.EXECUTE
        return perm

    @staticmethod
    def from_process_maps(perm_str):
        perm = Permission()
        if perm_str[0] == "r":
            perm.value += Permission.READ
        if perm_str[1] == "w":
            perm.value += Permission.WRITE
        if perm_str[2] == "x":
            perm.value += Permission.EXECUTE
        return perm


class Section:
    """GEF representation of process memory sections."""

    def __init__(self, *args, **kwargs):
        self.page_start = kwargs.get("page_start")
        self.page_end = kwargs.get("page_end")
        self.offset = kwargs.get("offset")
        self.permission = kwargs.get("permission")
        self.inode = kwargs.get("inode")
        self.path = kwargs.get("path")
        return

    def is_readable(self):
        return self.permission.value and self.permission.value&Permission.READ

    def is_writable(self):
        return self.permission.value and self.permission.value&Permission.WRITE

    def is_executable(self):
        return self.permission.value and self.permission.value&Permission.EXECUTE

    @property
    def size(self):
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start

    @property
    def realpath(self):
        # when in a `gef-remote` session, realpath returns the path to the binary on the local disk, not remote
        return self.path if __gef_remote__ is None else "/tmp/gef/{:d}/{:s}".format(__gef_remote__, self.path)


Zone = collections.namedtuple("Zone", ["name", "zone_start", "zone_end", "filename"])


class Elf:
    """Basic ELF parsing.
    Ref:
    - http://www.skyfree.org/linux/references/ELF_Format.pdf
    - http://refspecs.freestandards.org/elf/elfspec_ppc.pdf
    - http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
    """
    LITTLE_ENDIAN     = 1
    BIG_ENDIAN        = 2

    ELF_32_BITS       = 0x01
    ELF_64_BITS       = 0x02

    X86_64            = 0x3e
    X86_32            = 0x03

    ET_EXEC           = 2
    ET_DYN            = 3
    ET_CORE           = 4


    e_magic           = b"\x7fELF"
    e_class           = ELF_32_BITS
    e_endianness      = LITTLE_ENDIAN
    e_eiversion       = None
    e_osabi           = None
    e_abiversion      = None
    e_pad             = None
    e_type            = ET_EXEC
    e_machine         = X86_32
    e_version         = None
    e_entry           = 0x00
    e_phoff           = None
    e_shoff           = None
    e_flags           = None
    e_ehsize          = None
    e_phentsize       = None
    e_phnum           = None
    e_shentsize       = None
    e_shnum           = None
    e_shstrndx        = None



    def __init__(self, elf="", minimalist=False):
        """
        Instantiate an ELF object. The default behavior is to create the object by parsing the ELF file.
        But in some cases (QEMU-stub), we may just want a simple minimal object with default values."""
        if minimalist:
            return

        if not os.access(elf, os.R_OK):
            err("'{0}' not found/readable".format(elf))
            err("Failed to get file debug information, most of gef features will not work")
            return

        with open(elf, "rb") as fd:
            # off 0x0
            self.e_magic, self.e_class, self.e_endianness, self.e_eiversion = struct.unpack(">IBBB", fd.read(7))

            # adjust endianness in bin reading
            endian = "<" if self.e_endianness == Elf.LITTLE_ENDIAN else ">"

            # off 0x7
            self.e_osabi, self.e_abiversion = struct.unpack("{}BB".format(endian), fd.read(2))
            # off 0x9
            self.e_pad = fd.read(7)
            # off 0x10
            self.e_type, self.e_machine, self.e_version = struct.unpack("{}HHI".format(endian), fd.read(8))
            # off 0x18
            if self.e_class == Elf.ELF_64_BITS:
                # if arch 64bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}QQQ".format(endian), fd.read(24))
            else:
                # else arch 32bits
                self.e_entry, self.e_phoff, self.e_shoff = struct.unpack("{}III".format(endian), fd.read(12))

            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum = struct.unpack("{}HHHH".format(endian), fd.read(8))
            self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack("{}HHH".format(endian), fd.read(6))
        return


class Instruction:
    """GEF representation of a CPU instruction."""
    def __init__(self, address, location, mnemo, operands):
        self.address, self.location, self.mnemonic, self.operands = address, location, mnemo, operands
        return

    def __str__(self):
        return "{:#10x} {:16} {:6} {:s}".format(self.address,
                                                self.location,
                                                self.mnemonic,
                                                ", ".join(self.operands))

    def is_valid(self):
        return "(bad)" not in self.mnemonic

@lru_cache()
def search_for_main_arena():
    global __gef_default_main_arena__
    malloc_hook_addr = to_unsigned_long(gdb.parse_and_eval("(void *)&__malloc_hook"))

    if is_x86():
        addr = align_address_to_size(malloc_hook_addr + current_arch.ptrsize, 0x20)
    elif is_arch(Elf.AARCH64) or is_arch(Elf.ARM):
        addr = malloc_hook_addr - current_arch.ptrsize*2 - MallocStateStruct("*0").struct_size
    else:
        raise OSError("Cannot find main_arena for {}".format(current_arch.arch))

    __gef_default_main_arena__ = "*0x{:x}".format(addr)
    return addr

class MallocStateStruct(object):
    """GEF representation of malloc_state from https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L1658"""
    def __init__(self, addr):
        try:
            self.__addr = to_unsigned_long(gdb.parse_and_eval("&{}".format(addr)))
        except gdb.error:
            self.__addr = search_for_main_arena()

        self.num_fastbins = 10
        self.num_bins = 254

        self.int_size = cached_lookup_type("int").sizeof
        self.size_t = cached_lookup_type("size_t")
        if not self.size_t:
            ptr_type = "unsigned long" if current_arch.ptrsize == 8 else "unsigned int"
            self.size_t = cached_lookup_type(ptr_type)

        if get_libc_version() >= (2, 26):
            self.fastbin_offset = align_address_to_size(self.int_size*3, 8)
        else:
            self.fastbin_offset = self.int_size*2
        return

    # struct offsets
    @property
    def addr(self):
        return self.__addr
    @property
    def fastbins_addr(self):
        return self.__addr + self.fastbin_offset
    @property
    def top_addr(self):
        return self.fastbins_addr + self.num_fastbins*current_arch.ptrsize
    @property
    def last_remainder_addr(self):
        return self.top_addr + current_arch.ptrsize
    @property
    def bins_addr(self):
        return self.last_remainder_addr + current_arch.ptrsize
    @property
    def next_addr(self):
        return self.bins_addr + self.num_bins*current_arch.ptrsize + self.int_size*4
    @property
    def next_free_addr(self):
        return self.next_addr + current_arch.ptrsize
    @property
    def system_mem_addr(self):
        return self.next_free_addr + current_arch.ptrsize*2
    @property
    def struct_size(self):
        return self.system_mem_addr + current_arch.ptrsize*2 - self.__addr

    # struct members
    @property
    def fastbinsY(self):
        return self.get_size_t_array(self.fastbins_addr, self.num_fastbins)
    @property
    def top(self):
        return self.get_size_t_pointer(self.top_addr)
    @property
    def last_remainder(self):
        return self.get_size_t_pointer(self.last_remainder_addr)
    @property
    def bins(self):
        return self.get_size_t_array(self.bins_addr, self.num_bins)
    @property
    def next(self):
        return self.get_size_t_pointer(self.next_addr)
    @property
    def next_free(self):
        return self.get_size_t_pointer(self.next_free_addr)
    @property
    def system_mem(self):
        return self.get_size_t(self.system_mem_addr)

    # helper methods
    def get_size_t(self, addr):
        return dereference(addr).cast(self.size_t)

    def get_size_t_pointer(self, addr):
        size_t_pointer = self.size_t.pointer()
        return dereference(addr).cast(size_t_pointer)

    def get_size_t_array(self, addr, length):
        size_t_array = self.size_t.array(length)
        return dereference(addr).cast(size_t_array)

    def __getitem__(self, item):
        return getattr(self, item)


class GlibcArena:
    """Glibc arena class
    Ref: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1671 """
    TCACHE_MAX_BINS = 0x40

    def __init__(self, addr, name=None):
        self.__name = name or __gef_default_main_arena__
        try:
            arena = gdb.parse_and_eval(addr)
            malloc_state_t = cached_lookup_type("struct malloc_state")
            self.__arena = arena.cast(malloc_state_t)
            self.__addr = long(arena.address)
        except:
            self.__arena = MallocStateStruct(addr)
            self.__addr = self.__arena.addr
        return

    def __getitem__(self, item):
        return self.__arena[item]

    def __getattr__(self, item):
        return self.__arena[item]

    def __int__(self):
        return self.__addr

    def tcachebin(self, i):
        """Return head chunk in tcache[i]."""
        heap_base = HeapBaseFunction.heap_base()
        addr = dereference(heap_base + 2*current_arch.ptrsize + self.TCACHE_MAX_BINS + i*current_arch.ptrsize)
        if not addr:
            return None
        return GlibcChunk(long(addr))

    def fastbin(self, i):
        """Return head chunk in fastbinsY[i]."""
        addr = dereference_as_long(self.fastbinsY[i])
        if addr == 0:
            return None
        return GlibcChunk(addr + 2 * current_arch.ptrsize)

    def bin(self, i):
        idx = i * 2
        fd = dereference_as_long(self.bins[idx])
        bw = dereference_as_long(self.bins[idx + 1])
        return fd, bw

    def get_next(self):
        addr_next = dereference_as_long(self.next)
        arena_main = GlibcArena(self.__name)
        if addr_next == arena_main.__addr:
            return None
        return GlibcArena("*{:#x} ".format(addr_next))

    def __str__(self):
        top             = dereference_as_long(self.top)
        last_remainder  = dereference_as_long(self.last_remainder)
        n               = dereference_as_long(self.next)
        nfree           = dereference_as_long(self.next_free)
        sysmem          = long(self.system_mem)
        fmt = "Arena (base={:#x}, top={:#x}, last_remainder={:#x}, next={:#x}, next_free={:#x}, system_mem={:#x})"
        return fmt.format(self.__addr, top, last_remainder, n, nfree, sysmem)


class GlibcChunk:
    """Glibc chunk class.
    Ref:  https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/."""

    def __init__(self, addr, from_base=False):
        self.ptrsize = current_arch.ptrsize
        if from_base:
            self.chunk_base_address = addr
            self.address = addr + 2 * self.ptrsize
        else:
            self.chunk_base_address = long(addr - 2 * self.ptrsize)
            self.address = addr

        self.size_addr  = int(self.address - self.ptrsize)
        self.prev_size_addr = self.chunk_base_address
        return

    def get_chunk_size(self):
        return read_int_from_memory(self.size_addr) & (~0x07)

    @property
    def size(self):
        return self.get_chunk_size()

    def get_usable_size(self):
        # https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L4537
        cursz = self.get_chunk_size()
        if cursz == 0: return cursz
        if self.has_m_bit(): return cursz - 2 * self.ptrsize
        return cursz - self.ptrsize

    @property
    def usable_size(self):
        return self.get_usable_size()

    def get_prev_chunk_size(self):
        return read_int_from_memory(self.prev_size_addr)

    def get_next_chunk(self):
        addr = self.address + self.get_chunk_size()
        return GlibcChunk(addr)

    # if free-ed functions
    def get_fwd_ptr(self):
        return read_int_from_memory(self.address)

    @property
    def fwd(self):
        return self.get_fwd_ptr()

    fd = fwd # for compat

    def get_bkw_ptr(self):
        return read_int_from_memory(self.address + self.ptrsize)

    @property
    def bck(self):
        return self.get_bkw_ptr()

    bk = bck # for compat
    # endif free-ed functions

    def has_p_bit(self):
        return read_int_from_memory(self.size_addr) & 0x01

    def has_m_bit(self):
        return read_int_from_memory(self.size_addr) & 0x02

    def has_n_bit(self):
        return read_int_from_memory(self.size_addr) & 0x04

    def is_used(self):
        """Check if the current block is used by:
        - checking the M bit is true
        - or checking that next chunk PREV_INUSE flag is true """
        if self.has_m_bit():
            return True

        next_chunk = self.get_next_chunk()
        return True if next_chunk.has_p_bit() else False

    def str_chunk_size_flag(self):
        msg = []
        msg.append("PREV_INUSE flag: {}".format(Color.greenify("On") if self.has_p_bit() else Color.redify("Off")))
        msg.append("IS_MMAPPED flag: {}".format(Color.greenify("On") if self.has_m_bit() else Color.redify("Off")))
        msg.append("NON_MAIN_ARENA flag: {}".format(Color.greenify("On") if self.has_n_bit() else Color.redify("Off")))
        return "\n".join(msg)

    def _str_sizes(self):
        msg = []
        failed = False

        try:
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.get_chunk_size()))
            msg.append("Usable size: {0:d} ({0:#x})".format(self.get_usable_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Chunk size: Cannot read at {:#x} (corrupted?)".format(self.size_addr))

        try:
            msg.append("Previous chunk size: {0:d} ({0:#x})".format(self.get_prev_chunk_size()))
            failed = True
        except gdb.MemoryError:
            msg.append("Previous chunk size: Cannot read at {:#x} (corrupted?)".format(self.chunk_base_address))

        if failed:
            msg.append(self.str_chunk_size_flag())

        return "\n".join(msg)

    def _str_pointers(self):
        fwd = self.address
        bkw = self.address + self.ptrsize

        msg = []
        try:
            msg.append("Forward pointer: {0:#x}".format(self.get_fwd_ptr()))
        except gdb.MemoryError:
            msg.append("Forward pointer: {0:#x} (corrupted?)".format(fwd))

        try:
            msg.append("Backward pointer: {0:#x}".format(self.get_bkw_ptr()))
        except gdb.MemoryError:
            msg.append("Backward pointer: {0:#x} (corrupted?)".format(bkw))

        return "\n".join(msg)

    def str_as_alloced(self):
        return self._str_sizes()

    def str_as_freed(self):
        return "{}\n\n{}".format(self._str_sizes(), self._str_pointers())

    def flags_as_string(self):
        flags = []
        if self.has_p_bit():
            flags.append(Color.colorify("PREV_INUSE", "red bold"))
        if self.has_m_bit():
            flags.append(Color.colorify("IS_MMAPPED", "red bold"))
        if self.has_n_bit():
            flags.append(Color.colorify("NON_MAIN_ARENA", "red bold"))
        return "|".join(flags)

    def __str__(self):
        msg = "{:s}(addr={:#x}, size={:#x}, flags={:s})".format(Color.colorify("Chunk", "yellow bold underline"),
                                                                long(self.address),
                                                                self.get_chunk_size(),
                                                                self.flags_as_string())
        return msg

    def psprint(self):
        msg = []
        msg.append(str(self))
        if self.is_used():
            msg.append(self.str_as_alloced())
        else:
            msg.append(self.str_as_freed())

        return "\n".join(msg) + "\n"


@lru_cache()
def get_libc_version():
    sections = get_process_maps()
    try:
        for section in sections:
            if "libc-" in section.path:
                libc_version = tuple(int(_) for _ in
                                     re.search(r"libc-(\d+)\.(\d+)\.so", section.path).groups())
                break
        else:
            libc_version = 0, 0
    except AttributeError:
        libc_version = 0, 0
    return libc_version


@lru_cache()
def get_main_arena():
    try:
        return GlibcArena(__gef_default_main_arena__)
    except Exception as e:
        err("Failed to get the main arena, heap commands may not work properly: {}".format(e))
        return None


def titlify(text, color=None, msg_color=None):
    """Print a centered title."""
    cols = get_terminal_size()[1]
    nb = (cols - len(text) - 2)//2
    if color is None:
        color = __config__.get("theme.default_title_line")[0]
    if msg_color is None:
        msg_color = __config__.get("theme.default_title_message")[0]

    msg = []
    msg.append(Color.colorify("{} ".format(HORIZONTAL_LINE * nb), color))
    msg.append(Color.colorify(text, msg_color))
    msg.append(Color.colorify(" {}".format(HORIZONTAL_LINE * nb), color))
    return "".join(msg)


def err(msg):   return gef_print("{} {}".format(Color.colorify("[!]", "bold red"), msg))
def warn(msg):  return gef_print("{} {}".format(Color.colorify("[*]", "bold yellow"), msg))
def ok(msg):    return gef_print("{} {}".format(Color.colorify("[+]", "bold green"), msg))
def info(msg):  return gef_print("{} {}".format(Color.colorify("[+]", "bold blue"), msg))


def push_context_message(level, message):
    """Push the message to be displayed the next time the context is invoked."""
    global __context_messages__
    if level not in ("error", "warn", "ok", "info"):
        err("Invalid level '{}', discarding message".format(level))
        return
    __context_messages__.append((level, message))
    return


def show_last_exception():
    """Display the last Python exception."""

    def _show_code_line(fname, idx):
        fname = os.path.expanduser(os.path.expandvars(fname))
        __data = open(fname, "r").read().splitlines()
        return __data[idx-1] if idx < len(__data) else ""

    gef_print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()

    gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
    gef_print("{}: {}".format(Color.colorify(exc_type.__name__, "bold underline red"), exc_value))
    gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))

    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        filename, lineno, method, code = fs

        if not code or not code.strip():
            code = _show_code_line(filename, lineno)

        gef_print("""{} File "{}", line {:d}, in {}()""".format(DOWN_ARROW, Color.yellowify(filename),
                                                                lineno, Color.greenify(method)))
        gef_print("   {}    {}".format(RIGHT_ARROW, code))

    gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
    gdb.execute("show commands")
    gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
    gef_print("* GDB: {}".format(gdb.VERSION))
    gef_print("* Python: {:d}.{:d}.{:d} - {:s}".format(sys.version_info.major, sys.version_info.minor,
                                                       sys.version_info.micro, sys.version_info.releaselevel))
    gef_print("* OS: {:s} - {:s} ({:s}) on {:s}".format(platform.system(), platform.release(),
                                                        platform.architecture()[0],
                                                        " ".join(platform.dist()))) #pylint: disable=deprecated-method
    gef_print(HORIZONTAL_LINE*80)
    gef_print("")
    return


def gef_pystring(x):
    """Python 2 & 3 compatibility function for strings handling."""
    res = x
    substs = [("\n","\\n"), ("\r","\\r"), ("\t","\\t"), ("\v","\\v"), ("\b","\\b"), ]
    for x,y in substs: res = res.replace(x,y)
    return res


@lru_cache()
def which(program):
    """Locate a command on the filesystem."""
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath = os.path.split(program)[0]
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    raise FileNotFoundError("Missing file `{:s}`".format(program))


def style_byte(b, color=True):
    style = {
        "nonprintable": "yellow",
        "printable": "white",
        "00": "gray",
        "0a": "blue",
        "ff": "green",
    }
    sbyte = "{:02x}".format(b)
    if not color or get_gef_setting("highlight.regex"):
        return sbyte

    if sbyte in style:
        st = style[sbyte]
    elif chr(b) in (string.ascii_letters + string.digits + string.punctuation + " "):
        st = style.get("printable")
    else:
        st = style.get("nonprintable")
    if st:
        sbyte = Color.colorify(sbyte, st)
    return sbyte


def hexdump(source, length=0x10, separator=".", show_raw=False, base=0x00):
    """Return the hexdump of `src` argument.
    @param source *MUST* be of type bytes or bytearray
    @param length is the length of items per line
    @param separator is the default character to use if one byte is not printable
    @param show_raw if True, do not add the line nor the text translation
    @param base is the start address of the block being hexdump
    @return a string with the hexdump"""
    result = []
    align = get_memory_alignment()*2+2 if is_alive() else 18

    for i in range(0, len(source), length):
        chunk = bytearray(source[i:i + length])
        hexa = " ".join([style_byte(b, color=not show_raw) for b in chunk])


        if show_raw:
            result.append(hexa)
            continue

        text = "".join([chr(b) if 0x20 <= b < 0x7F else separator for b in chunk])
        sym = gdb_get_location_from_symbol(base+i)
        sym = "<{:s}+{:04x}>".format(*sym) if sym else ""

        result.append("{addr:#0{aw}x} {sym}    {data:<{dw}}    {text}".format(aw=align,
                                                                              addr=base+i,
                                                                              sym=sym,
                                                                              dw=3*length,
                                                                              data=hexa,
                                                                              text=text))
    return "\n".join(result)


def is_debug():
    """Check if debug mode is enabled."""
    return get_gef_setting("gef.debug") is True

context_hidden = False
def hide_context():
    global context_hidden
    context_hidden = True
def unhide_context():
    global context_hidden
    context_hidden = False

def enable_redirect_output(to_file="/dev/null"):
    """Redirect all GDB output to `to_file` parameter. By default, `to_file` redirects to `/dev/null`."""
    gdb.execute("set logging overwrite")
    gdb.execute("set logging file {:s}".format(to_file))
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")
    return


def disable_redirect_output():
    """Disable the output redirection, if any."""
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")
    return


@lru_cache()
def get_gef_setting(name):
    """Read global gef settings.
    Return None if not found. A valid config setting can never return None,
    but False, 0 or ""."""
    global __config__
    setting = __config__.get(name, None)
    if not setting:
        return None
    return setting[0]


def set_gef_setting(name, value, _type=None, _desc=None):
    """Set global gef settings.
    Raise ValueError if `name` doesn't exist and `type` and `desc`
    are not provided."""
    global __config__

    if name not in __config__:
        # create new setting
        if _type is None or _desc is None:
            raise ValueError("Setting '{}' is undefined, need to provide type and description".format(name))
        __config__[name] = [_type(value), _type, _desc]
        return

    # set existing setting
    func = __config__[name][1]
    __config__[name][0] = func(value)
    reset_all_caches()
    return


def gef_makedirs(path, mode=0o755):
    """Recursive mkdir() creation. If successful, return the absolute path of the directory created."""
    abspath = os.path.realpath(path)
    if os.path.isdir(abspath):
        return abspath

    try:
        os.makedirs(path, mode=mode)
    except os.error:
        pass
    return abspath


@lru_cache()
def gdb_lookup_symbol(sym):
    """Fetch the proper symbol or None if not defined."""
    try:
        return gdb.decode_line(sym)[1]
    except gdb.error:
        return None


@lru_cache(maxsize=512)
def gdb_get_location_from_symbol(address):
    """Retrieve the location of the `address` argument from the symbol table.
    Return a tuple with the name and offset if found, None otherwise."""
    # this is horrible, ugly hack and shitty perf...
    # find a *clean* way to get gdb.Location from an address
    name = None
    sym = gdb.execute("info symbol {:#x}".format(address), to_string=True)
    if sym.startswith("No symbol matches"):
        return None

    i = sym.find(" in section ")
    sym = sym[:i].split()
    name, offset = sym[0], 0
    if len(sym) == 3 and sym[2].isdigit():
        offset = int(sym[2])
    return name, offset


def gdb_disassemble(start_pc, **kwargs):
    """Disassemble instructions from `start_pc` (Integer). Accepts the following named parameters:
    - `end_pc` (Integer) only instructions whose start address fall in the interval from start_pc to end_pc are returned.
    - `count` (Integer) list at most this many disassembled instructions
    If `end_pc` and `count` are not provided, the function will behave as if `count=1`.
    Return an iterator of Instruction objects
    """
    frame = gdb.selected_frame()
    arch = frame.architecture()

    for insn in arch.disassemble(start_pc, **kwargs):
        address = insn["addr"]
        asm = insn["asm"].rstrip().split(None, 1)
        if len(asm) > 1:
            mnemo, operands = asm
            operands = operands.split(",")
        else:
            mnemo, operands = asm[0], []

        loc = gdb_get_location_from_symbol(address)
        location = "<{}+{}>".format(*loc) if loc else ""

        yield Instruction(address, location, mnemo, operands)


def gdb_get_nth_previous_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction before `addr`."""
    # fixed-length ABI
    if current_arch.instruction_length:
        return addr - n*current_arch.instruction_length

    # variable-length ABI
    cur_insn_addr = gef_current_instruction(addr).address

    # we try to find a good set of previous instructions by "guessing" disassembling backwards
    # the 15 comes from the longest instruction valid size
    for i in range(15*n, 0, -1):
        try:
            insns = list(gdb_disassemble(addr-i, end_pc=cur_insn_addr, count=n+1))
        except gdb.MemoryError:
            # this is because we can hit an unmapped page trying to read backward
            break

        # 1. check that the disassembled instructions list size is correct
        if len(insns)!=n+1: # we expect the current instruction plus the n before it
            continue

        # 2. check all instructions are valid
        for insn in insns:
            if not insn.is_valid():
                continue

        # 3. if cur_insn is at the end of the set
        if insns[-1].address==cur_insn_addr:
            return insns[0].address

    return None


def gdb_get_nth_next_instruction_address(addr, n):
    """Return the address (Integer) of the `n`-th instruction after `addr`."""
    # fixed-length ABI
    if current_arch.instruction_length:
        return addr + n*current_arch.instruction_length

    # variable-length ABI
    insn = list(gdb_disassemble(addr, count=n))[-1]
    return insn.address


def gef_instruction_n(addr, n):
    """Return the `n`-th instruction after `addr` as an Instruction object."""
    return list(gdb_disassemble(addr, count=n+1))[n]


def gef_get_instruction_at(addr):
    """Return the full Instruction found at the specified address."""
    insn = next(gef_disassemble(addr, 1))
    return insn


def gef_current_instruction(addr):
    """Return the current instruction as an Instruction object."""
    return gef_instruction_n(addr, 0)


def gef_next_instruction(addr):
    """Return the next instruction as an Instruction object."""
    return gef_instruction_n(addr, 1)


def gef_disassemble(addr, nb_insn, nb_prev=0):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`.
    Return an iterator of Instruction objects."""
    count = nb_insn + 1 if nb_insn & 1 else nb_insn

    if nb_prev:
        start_addr = gdb_get_nth_previous_instruction_address(addr, nb_prev)
        if start_addr:
            for insn in gdb_disassemble(start_addr, count=nb_prev):
                if insn.address == addr: break
                yield insn

    for insn in gdb_disassemble(addr, count=count):
        yield insn


def capstone_disassemble(location, nb_insn, **kwargs):
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before
    `addr` using the Capstone-Engine disassembler, if available.
    Return an iterator of Instruction objects."""

    def cs_insn_to_gef_insn(cs_insn):
        sym_info = gdb_get_location_from_symbol(cs_insn.address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        ops = [] + cs_insn.op_str.split(", ")
        return Instruction(cs_insn.address, loc, cs_insn.mnemonic, ops)

    capstone    = sys.modules["capstone"]
    arch, mode  = get_capstone_arch(arch=kwargs.get("arch", None), mode=kwargs.get("mode", None), endian=kwargs.get("endian", None))
    cs          = capstone.Cs(arch, mode)
    cs.detail   = True

    page_start  = align_address_to_page(location)
    offset      = location - page_start
    pc          = current_arch.pc

    skip       = int(kwargs.get("skip", 0))
    nb_prev    = int(kwargs.get("nb_prev", 0))
    if nb_prev > 0:
        location = gdb_get_nth_previous_instruction_address(pc, nb_prev)
        nb_insn += nb_prev

    code = kwargs.get("code", read_memory(location, gef_getpagesize() - offset - 1))
    code = bytes(code)

    for insn in cs.disasm(code, location):
        if skip:
            skip -= 1
            continue
        nb_insn -= 1
        yield cs_insn_to_gef_insn(insn)
        if nb_insn==0:
            break
    return


def gef_execute_external(command, as_list=False, *args, **kwargs):
    """Execute an external command and return the result."""
    res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=kwargs.get("shell", False))
    return [gef_pystring(_) for _ in res.splitlines()] if as_list else gef_pystring(res)


def gef_execute_gdb_script(commands):
    """Execute the parameter `source` as GDB command. This is done by writing `commands` to
    a temporary file, which is then executed via GDB `source` command. The tempfile is then deleted."""
    fd, fname = tempfile.mkstemp(suffix=".gdb", prefix="gef_")
    with os.fdopen(fd, "w") as f:
        f.write(commands)
        f.flush()
    if os.access(fname, os.R_OK):
        gdb.execute("source {:s}".format(fname))
        os.unlink(fname)
    return




@lru_cache()
def get_arch():
    """Return the binary's architecture."""
    if is_alive():
        arch = gdb.selected_frame().architecture()
        return arch.name()

    arch_str = gdb.execute("show architecture", to_string=True).strip()
    if "The target architecture is set automatically (currently " in arch_str:
        # architecture can be auto detected
        arch_str = arch_str.split("(currently ", 1)[1]
        arch_str = arch_str.split(")", 1)[0]
    elif "The target architecture is assumed to be " in arch_str:
        # architecture can be assumed
        arch_str = arch_str.replace("The target architecture is assumed to be ", "")
    else:
        # unknown, we throw an exception to be safe
        raise RuntimeError("Unknown architecture: {}".format(arch_str))
    return arch_str


@lru_cache()
def get_endian():
    """Return the binary endianness."""
    if is_alive():
        return get_elf_headers().e_endianness
    if gdb.execute("show endian", to_string=True).strip().split()[7] == "little" :
        return Elf.LITTLE_ENDIAN
    raise EnvironmentError("Invalid endianess")


def is_big_endian():     return get_endian() == Elf.BIG_ENDIAN
def is_little_endian():  return not is_big_endian()


def flags_to_human(reg_value, value_table):
    """Return a human readable string showing the flag states."""
    flags = []
    for i in value_table:
        flag_str = Color.boldify(value_table[i].upper()) if reg_value & (1<<i) else value_table[i].lower()
        flags.append(flag_str)
    return "[{}]".format(" ".join(flags))


class Architecture(object):
    """Generic metaclass for the architecture supported by GEF."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def all_registers(self):                       pass
    @abc.abstractproperty
    def instruction_length(self):                  pass
    @abc.abstractproperty
    def nop_insn(self):                            pass
    @abc.abstractproperty
    def return_register(self):                     pass
    @abc.abstractproperty
    def flag_register(self):                       pass
    @abc.abstractproperty
    def flags_table(self):                         pass
    @abc.abstractproperty
    def function_parameters(self):                 pass
    @abc.abstractmethod
    def flag_register_to_human(self, val=None):    pass
    @abc.abstractmethod
    def is_call(self, insn):                       pass
    @abc.abstractmethod
    def is_ret(self, insn):                        pass
    @abc.abstractmethod
    def is_conditional_branch(self, insn):         pass
    @abc.abstractmethod
    def is_branch_taken(self, insn):               pass
    @abc.abstractmethod
    def get_ra(self, insn, frame):                 pass

    special_registers = []

    @property
    def pc(self):
        return get_register("$pc")

    @property
    def sp(self):
        return get_register("$sp")

    @property
    def fp(self):
        return get_register("$fp")

    @property
    def ptrsize(self):
        return get_memory_alignment()

    def get_ith_parameter(self, i, in_func=True):
        """Retrieves the correct parameter used for the current function call."""
        reg = self.function_parameters[i]
        val = get_register(reg)
        key = reg
        return key, val




class X86(Architecture):
    arch = "X86"
    mode = "32"

    nop_insn = b"\x90"
    flag_register = "$eflags"
    special_registers = ["$cs", "$ss", "$ds", "$es", "$fs", "$gs", ]
    gpr_registers = ["$eax", "$ebx", "$ecx", "$edx", "$esp", "$ebp", "$esi", "$edi", "$eip", ]
    all_registers = gpr_registers + [ flag_register, ] + special_registers
    instruction_length = None
    return_register = "$eax"
    function_parameters = ["$esp", ]
    flags_table = {
        6: "zero",
        0: "carry",
        2: "parity",
        4: "adjust",
        7: "sign",
        8: "trap",
        9: "interrupt",
        10: "direction",
        11: "overflow",
        16: "resume",
        17: "virtualx86",
        21: "identification",
    }
    syscall_register = "$eax"
    syscall_instructions = ["sysenter", "int 0x80"]

    def flag_register_to_human(self, val=None):
        reg = self.flag_register
        if not val:
            val = get_register(reg)
        return flags_to_human(val, self.flags_table)

    def is_call(self, insn):
        mnemo = insn.mnemonic
        call_mnemos = {"call", "callq"}
        return mnemo in call_mnemos

    def is_ret(self, insn):
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        branch_mnemos = {
            "ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
            "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
            "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
            "jo", "jp", "jpe", "js"
        }
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
        flags = dict((self.flags_table[k], k) for k in self.flags_table)
        val = get_register(self.flag_register)

        taken, reason = False, ""

        if mnemo in ("ja", "jnbe"):
            taken, reason = not val&(1<<flags["carry"]) and not val&(1<<flags["zero"]), "!C && !Z"
        elif mnemo in ("jae", "jnb", "jnc"):
            taken, reason = not val&(1<<flags["carry"]), "!C"
        elif mnemo in ("jb", "jc", "jnae"):
            taken, reason = val&(1<<flags["carry"]), "C"
        elif mnemo in ("jbe", "jna"):
            taken, reason = val&(1<<flags["carry"]) or val&(1<<flags["zero"]), "C || Z"
        elif mnemo in ("jcxz", "jecxz", "jrcxz"):
            cx = get_register("$rcx") if self.mode == 64 else get_register("$ecx")
            taken, reason = cx == 0, "!$CX"
        elif mnemo in ("je", "jz"):
            taken, reason = val&(1<<flags["zero"]), "Z"
        elif mnemo in ("jne", "jnz"):
            taken, reason = not val&(1<<flags["zero"]), "!Z"
        elif mnemo in ("jg", "jnle"):
            taken, reason = not val&(1<<flags["zero"]) and bool(val&(1<<flags["overflow"])) == bool(val&(1<<flags["sign"])), "!Z && S==O"
        elif mnemo in ("jge", "jnl"):
            taken, reason = bool(val&(1<<flags["sign"])) == bool(val&(1<<flags["overflow"])), "S==O"
        elif mnemo in ("jl", "jnge"):
            taken, reason = val&(1<<flags["overflow"]) != val&(1<<flags["sign"]), "S!=O"
        elif mnemo in ("jle", "jng"):
            taken, reason = val&(1<<flags["zero"]) or bool(val&(1<<flags["overflow"])) != bool(val&(1<<flags["sign"])), "Z || S!=O"
        elif mnemo in ("jo",):
            taken, reason = val&(1<<flags["overflow"]), "O"
        elif mnemo in ("jno",):
            taken, reason = not val&(1<<flags["overflow"]), "!O"
        elif mnemo in ("jpe", "jp"):
            taken, reason = val&(1<<flags["parity"]), "P"
        elif mnemo in ("jnp", "jpo"):
            taken, reason = not val&(1<<flags["parity"]), "!P"
        elif mnemo in ("js",):
            taken, reason = val&(1<<flags["sign"]), "S"
        elif mnemo in ("jns",):
            taken, reason = not val&(1<<flags["sign"]), "!S"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        if self.is_ret(insn):
            ra = to_unsigned_long(dereference(current_arch.sp))
        if frame.older():
            ra = frame.older().pc()

        return ra

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 125
        insns = [
            "pushad",
            "mov eax, {:d}".format(_NR_mprotect),
            "mov ebx, {:d}".format(addr),
            "mov ecx, {:d}".format(size),
            "mov edx, {:d}".format(perm),
            "int 0x80",
            "popad",]
        return "; ".join(insns)

    def get_ith_parameter(self, i, in_func=True):
        if in_func:
            i += 1 # Account for RA being at the top of the stack
        sp = current_arch.sp
        sz =  current_arch.ptrsize
        loc = sp + (i * sz)
        val = read_int_from_memory(loc)
        key = "[sp + {:#x}]".format(i * sz)
        return key, val


class X86_64(X86):
    arch = "X86"
    mode = "64"

    gpr_registers = [
        "$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi", "$rdi", "$rip",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", ]
    all_registers = gpr_registers + [ X86.flag_register, ] + X86.special_registers
    return_register = "$rax"
    function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    syscall_register = "$rax"
    syscall_instructions = ["syscall"]
    # We don't want to inherit x86's stack based param getter
    get_ith_parameter = Architecture.get_ith_parameter

    @classmethod
    def mprotect_asm(cls, addr, size, perm):
        _NR_mprotect = 10
        insns = ["push rax", "push rdi", "push rsi", "push rdx",
                 "mov rax, {:d}".format(_NR_mprotect),
                 "mov rdi, {:d}".format(addr),
                 "mov rsi, {:d}".format(size),
                 "mov rdx, {:d}".format(perm),
                 "syscall",
                 "pop rdx", "pop rsi", "pop rdi", "pop rax"]
        return "; ".join(insns)




def write_memory(address, buffer, length=0x10):
    """Write `buffer` at address `address`."""
    return gdb.selected_inferior().write_memory(address, buffer, length)


def read_memory(addr, length=0x10):
    """Return a `length` long byte array with the copy of the process memory at `addr`."""
    print(hex(addr), hex(length))
    return gdb.selected_inferior().read_memory(addr, length)



def read_int_from_memory(addr):
    """Return an integer read from memory."""
    sz = current_arch.ptrsize
    mem = read_memory(addr, sz)
    fmt = "{}{}".format(endian_str(), "I" if sz==4 else "Q")
    return struct.unpack(fmt, mem)[0]


def read_cstring_from_memory(address, max_length=GEF_MAX_STRING_LENGTH, encoding=None):
    """Return a C-string read from memory."""

    if not encoding:
        encoding = "ascii"

    char_ptr = cached_lookup_type("char").pointer()

    length = min(address|(DEFAULT_PAGE_SIZE-1), max_length+1)
    try:
        res = gdb.Value(address).cast(char_ptr).string(encoding=encoding, length=length).strip()
    except gdb.error:
        res = bytes(read_memory(address, length)).decode("utf-8")

    res = res.split("\x00", 1)[0]
    ustr = res.replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")
    if max_length and len(res) > max_length:
        return "{}[...]".format(ustr[:max_length])

    return ustr


def read_ascii_string(address):
    """Read an ASCII string from memory"""
    cstr = read_cstring_from_memory(address)
    if isinstance(cstr, unicode) and cstr and all([x in string.printable for x in cstr]):
        return cstr
    return None


def is_ascii_string(address):
    """Helper function to determine if the buffer pointed by `address` is an ASCII string (in GDB)"""
    try:
        return read_ascii_string(address) is not None
    except Exception:
        return False


def is_alive():
    """Check if GDB is running."""
    try:
        return gdb.selected_inferior().pid > 0
    except Exception:
        return False
    return False


def only_if_gdb_running(f):
    """Decorator wrapper to check if GDB is running."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")
    return wrapper


def only_if_gdb_target_local(f):
    """Decorator wrapper to check if GDB is running locally (target not remote)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_remote_debug():
            return f(*args, **kwargs)
        else:
            warn("This command cannot work for remote sessions.")
    return wrapper


def experimental_feature(f):
    """Decorator to add a warning when a feature is experimental."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        warn("This feature is under development, expect bugs and unstability...")
        return f(*args, **kwargs)
    return wrapper


def only_if_gdb_version_higher_than(required_gdb_version):
    """Decorator to check whether current GDB version requirements."""
    def wrapper(f):
        def inner_f(*args, **kwargs):
            if GDB_VERSION >= required_gdb_version:
                f(*args, **kwargs)
            else:
                reason = "GDB >= {} for this command".format(required_gdb_version)
                raise EnvironmentError(reason)
        return inner_f
    return wrapper


def use_stdtype():
    if   is_elf32(): return "uint32_t"
    elif is_elf64(): return "uint64_t"
    return "uint16_t"


def use_default_type():
    if   is_elf32(): return "unsigned int"
    elif is_elf64(): return "unsigned long"
    return "unsigned short"


def use_golang_type():
    if   is_elf32(): return "uint32"
    elif is_elf64(): return "uint64"
    return "uint16"


def to_unsigned_long(v):
    """Cast a gdb.Value to unsigned long."""
    mask = (1 << 64) - 1
    return int(v.cast(gdb.Value(mask).type)) & mask


def get_register(regname):
    """Return a register's value."""
    try:
        value = gdb.parse_and_eval(regname)
        return to_unsigned_long(value) if value.type.code == gdb.TYPE_CODE_INT else long(value)
    except gdb.error:
        value = gdb.selected_frame().read_register(regname)
        return long(value)


def get_path_from_info_proc():
    for x in gdb.execute("info proc", to_string=True).splitlines():
        if x.startswith("exe = "):
            return x.split(" = ")[1].replace("'", "")
    return None


@lru_cache()
def get_os():
    """Return the current OS."""
    return platform.system().lower()


@lru_cache()
def get_pid():
    """Return the PID of the debuggee process."""
    return gdb.selected_inferior().pid


@lru_cache()
def get_filepath():
    """Return the local absolute path of the file currently debugged."""
    filename = gdb.current_progspace().filename

    if is_remote_debug():
        # if no filename specified, try downloading target from /proc
        if filename is None:
            pid = get_pid()
            if pid > 0:
                return download_file("/proc/{:d}/exe".format(pid), use_cache=True)
            return None

        # if target is remote file, download
        elif filename.startswith("target:"):
            fname = filename[len("target:"):]
            return download_file(fname, use_cache=True, local_name=fname)

        elif __gef_remote__ is not None:
            return "/tmp/gef/{:d}/{:s}".format(__gef_remote__, get_path_from_info_proc())
        return filename
    else:
        if filename is not None:
            return filename
        # inferior probably did not have name, extract cmdline from info proc
        return get_path_from_info_proc()


@lru_cache()
def get_filename():
    """Return the full filename of the file currently debugged."""
    return os.path.basename(get_filepath())


def download_file(target, use_cache=False, local_name=None):
    """Download filename `target` inside the mirror tree inside the GEF_TEMP_DIR.
    The tree architecture must be GEF_TEMP_DIR/gef/<local_pid>/<remote_filepath>.
    This allow a "chroot-like" tree format."""

    try:
        local_root = os.path.sep.join([GEF_TEMP_DIR, str(get_pid())])
        if local_name is None:
            local_path = os.path.sep.join([local_root, os.path.dirname(target)])
            local_name = os.path.sep.join([local_path, os.path.basename(target)])
        else:
            local_path = os.path.sep.join([local_root, os.path.dirname(local_name)])
            local_name = os.path.sep.join([local_path, os.path.basename(local_name)])

        if use_cache and os.access(local_name, os.R_OK):
            return local_name

        gef_makedirs(local_path)
        gdb.execute("remote get {0:s} {1:s}".format(target, local_name))

    except gdb.error:
        # gdb-stub compat
        with open(local_name, "w") as f:
            if is_elf32():
                f.write("00000000-ffffffff rwxp 00000000 00:00 0                    {}\n".format(get_filepath()))
            else:
                f.write("0000000000000000-ffffffffffffffff rwxp 00000000 00:00 0                    {}\n".format(get_filepath()))

    except Exception as e:
        err("download_file() failed: {}".format(str(e)))
        local_name = None
    return local_name


def open_file(path, use_cache=False):
    """Attempt to open the given file, if remote debugging is active, download
    it first to the mirror in /tmp/."""
    if is_remote_debug():
        lpath = download_file(path, use_cache)
        if not lpath:
            raise IOError("cannot open remote path {:s}".format(path))
        path = lpath

    return open(path, "r")


def get_function_length(sym):
    """Attempt to get the length of the raw bytes of a function."""
    dis = gdb.execute("disassemble {:s}".format(sym), to_string=True).splitlines()
    start_addr = int(dis[1].split()[0], 16)
    end_addr = int(dis[-2].split()[0], 16)
    return end_addr - start_addr


def get_process_maps_linux(proc_map_file):
    """Parse the Linux process `/proc/pid/maps` file."""
    for line in open_file(proc_map_file, use_cache=False):
        line = line.strip()
        addr, perm, off, _, rest = line.split(" ", 4)
        rest = rest.split(" ", 1)
        if len(rest) == 1:
            inode = rest[0]
            pathname = ""
        else:
            inode = rest[0]
            pathname = rest[1].lstrip()

        addr_start, addr_end = list(map(lambda x: long(x, 16), addr.split("-")))
        off = long(off, 16)
        perm = Permission.from_process_maps(perm)

        yield Section(page_start=addr_start,
                      page_end=addr_end,
                      offset=off,
                      permission=perm,
                      inode=inode,
                      path=pathname)
    return


@lru_cache()
def get_process_maps():
    """Parse the `/proc/pid/maps` file."""

    sections = []
    try:
        pid = get_pid()
        fpath = "/proc/{:d}/maps".format(pid)
        sections = get_process_maps_linux(fpath)
        return list(sections)

    except FileNotFoundError as e:
        warn("Failed to read /proc/<PID>/maps, using GDB sections info: {}".format(e))
        return list(get_info_sections())


@lru_cache()
def get_info_sections():
    """Retrieve the debuggee sections."""
    stream = StringIO(gdb.execute("maintenance info sections", to_string=True))

    for line in stream:
        if not line:
            break

        try:
            parts = [x.strip() for x in line.split()]
            addr_start, addr_end = [long(x, 16) for x in parts[1].split("->")]
            off = long(parts[3][:-1], 16)
            path = parts[4]
            inode = ""
            perm = Permission.from_info_sections(parts[5:])

            yield Section(page_start=addr_start,
                          page_end=addr_end,
                          offset=off,
                          permission=perm,
                          inode=inode,
                          path=path)

        except IndexError:
            continue
        except ValueError:
            continue

    return


@lru_cache()
def get_info_files():
    """Retrieve all the files loaded by debuggee."""
    lines = gdb.execute("info files", to_string=True).splitlines()

    if len(lines) < len(__infos_files__):
        return __infos_files__

    for line in lines:
        line = line.strip()

        if not line:
            break

        if not line.startswith("0x"):
            continue

        blobs = [x.strip() for x in line.split(" ")]
        addr_start = long(blobs[0], 16)
        addr_end = long(blobs[2], 16)
        section_name = blobs[4]

        if len(blobs) == 7:
            filename = blobs[6]
        else:
            filename = get_filepath()

        info = Zone(section_name, addr_start, addr_end, filename)

        __infos_files__.append(info)

    return __infos_files__


def process_lookup_address(address):
    """Look up for an address in memory.
    Return an Address object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    if is_x86() :
        if is_in_x86_kernel(address):
            return None

    for sect in get_process_maps():
        if sect.page_start <= address < sect.page_end:
            return sect

    return None


def process_lookup_path(name, perm=Permission.ALL):
    """Look up for a path in the process memory mapping.
    Return a Section object if found, None otherwise."""
    if not is_alive():
        err("Process is not running")
        return None

    for sect in get_process_maps():
        if name in sect.path and sect.permission.value & perm:
            return sect

    return None

def file_lookup_name_path(name, path):
    """Look up a file by name and path.
    Return a Zone object if found, None otherwise."""
    for xfile in get_info_files():
        if path == xfile.filename and name == xfile.name:
            return xfile
    return None

def file_lookup_address(address):
    """Look up for a file by its address.
    Return a Zone object if found, None otherwise."""
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


def lookup_address(address):
    """Try to find the address in the process address space.
    Return an Address object, with validity flag set based on success."""
    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return Address(value=address, valid=False)
    return Address(value=address, section=sect, info=info)


def xor(data, key):
    """Return `data` xor-ed with `key`."""
    key = key.lstrip("0x")
    key = binascii.unhexlify(key)
    return b"".join([chr(ord(x) ^ ord(y)) for x, y in zip(data, itertools.cycle(key))])


def is_hex(pattern):
    """Return whether provided string is a hexadecimal value."""
    if not pattern.startswith("0x") and not pattern.startswith("0X"):
        return False
    return len(pattern)%2==0 and all(c in string.hexdigits for c in pattern[2:])


def ida_synchronize_handler(event):
    gdb.execute("ida-interact sync", from_tty=True)
    return


def continue_handler(event):
    """GDB event handler for new object continue cases."""
    return


def hook_stop_handler(event):
    """GDB event handler for stop cases."""
    reset_all_caches()
    gdb.execute("context")
    return


def new_objfile_handler(event):
    """GDB event handler for new object file cases."""
    reset_all_caches()
    set_arch()
    return


def exit_handler(event):
    """GDB event handler for exit cases."""
    global __gef_remote__, __gef_qemu_mode__

    reset_all_caches()
    __gef_qemu_mode__ = False
    if __gef_remote__ and get_gef_setting("gef-remote.clean_on_exit") is True:
        shutil.rmtree("/tmp/gef/{:d}".format(__gef_remote__))
        __gef_remote__ = None
    return


def get_terminal_size():
    """Return the current terminal size."""
    if is_debug():
        return 600, 100

    try:
        cmd = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
        tty_rows, tty_columns = int(cmd[0]), int(cmd[1])
        return tty_rows, tty_columns

    except OSError:
        return 600, 100


def get_generic_arch(module, prefix, arch, mode, big_endian, to_string=False):
    """
    Retrieves architecture and mode from the arguments for use for the holy
    {cap,key}stone/unicorn trinity.
    """
    if to_string:
        arch = "{:s}.{:s}_ARCH_{:s}".format(module.__name__, prefix, arch)
        if mode:
            mode = "{:s}.{:s}_MODE_{:s}".format(module.__name__, prefix, str(mode))
        else:
            mode = ""
        if is_big_endian():
            mode += " + {:s}.{:s}_MODE_BIG_ENDIAN".format(module.__name__, prefix)
        else:
            mode += " + {:s}.{:s}_MODE_LITTLE_ENDIAN".format(module.__name__, prefix)

    else:
        arch = getattr(module, "{:s}_ARCH_{:s}".format(prefix, arch))
        if mode:
            mode = getattr(module, "{:s}_MODE_{:s}".format(prefix, mode))
        else:
            mode = 0
        if big_endian:
            mode |= getattr(module, "{:s}_MODE_BIG_ENDIAN".format(prefix))
        else:
            mode |= getattr(module, "{:s}_MODE_LITTLE_ENDIAN".format(prefix))

    return arch, mode


def get_generic_running_arch(module, prefix, to_string=False):
    """
    Retrieves architecture and mode from the current context.
    """

    if not is_alive():
        return None, None

    if current_arch is not None:
        arch, mode = current_arch.arch, current_arch.mode
    else:
        raise OSError("Emulation not supported for your OS")

    return get_generic_arch(module, prefix, arch, mode, is_big_endian(), to_string)




@lru_cache()
def get_elf_headers(filename=None):
    """Return an Elf object with info from `filename`. If not provided, will return
    the currently debugged file."""
    if filename is None:
        filename = get_filepath()

    if filename.startswith("target:"):
        warn("Your file is remote, you should try using `gef-remote` instead")
        return

    return Elf(filename)


@lru_cache()
def is_elf64(filename=None):
    """Checks if `filename` is an ELF64."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_class == Elf.ELF_64_BITS


@lru_cache()
def is_elf32(filename=None):
    """Checks if `filename` is an ELF32."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_class == Elf.ELF_32_BITS

@lru_cache()
def is_x86_64(filename=None):
    """Checks if `filename` is an x86-64 ELF."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_machine == Elf.X86_64


@lru_cache()
def is_x86_32(filename=None):
    """Checks if `filename` is an x86-32 ELF."""
    elf = current_elf or get_elf_headers(filename)
    return elf.e_machine == Elf.X86_32

@lru_cache()
def is_x86(filename=None):
    return is_x86_32(filename) or is_x86_64(filename)


@lru_cache()
def is_arch(arch):
    elf = current_elf or get_elf_headers()
    return elf.e_machine == arch


def set_arch(arch=None, default=None):
    """Sets the current architecture.
    If an arch is explicitly specified, use that one, otherwise try to parse it
    out of the ELF header. If that fails, and default is specified, select and
    set that arch.
    Return the selected arch, or raise an OSError.
    """
    arches = {

        "X86": X86, Elf.X86_32: X86,
        "X86_64": X86_64, Elf.X86_64: X86_64,
  
    }
    global current_arch, current_elf

    if arch:
        try:
            current_arch = arches[arch.upper()]()
            return current_arch
        except KeyError:
            raise OSError("Specified arch {:s} is not supported".format(arch.upper()))

    current_elf = current_elf or get_elf_headers()
    try:
        current_arch = arches[current_elf.e_machine]()
    except KeyError:
        if default:
            try:
                current_arch = arches[default.upper()]()
            except KeyError:
                raise OSError("CPU not supported, neither is default {:s}".format(default.upper()))
        else:
            #commenting this out so you don't see this
            #raise OSError("CPU type is currently not supported: {:s}".format(get_arch()))
            pass
    return current_arch


@lru_cache()
def cached_lookup_type(_type):
    try:
        return gdb.lookup_type(_type).strip_typedefs()
    except RuntimeError:
        return None


@lru_cache()
def get_memory_alignment(in_bits=False):
    """Try to determine the size of a pointer on this system.
    First, try to parse it out of the ELF header.
    Next, use the size of `size_t`.
    Finally, try the size of $pc.
    If `in_bits` is set to True, the result is returned in bits, otherwise in
    bytes."""
    if is_elf32():
        return 4 if not in_bits else 32
    elif is_elf64():
        return 8 if not in_bits else 64

    res = cached_lookup_type("size_t")
    if res is not None:
        return res.sizeof if not in_bits else res.sizeof * 8

    try:
        return gdb.parse_and_eval("$pc").type.sizeof
    except:
        pass
    raise EnvironmentError("GEF is running under an unsupported mode")


def clear_screen(tty=""):
    """Clear the screen."""
    if not tty:
        gdb.execute("shell clear")
        return

    with open(tty, "w") as f:
        f.write("\x1b[H\x1b[J")
    return


def format_address(addr):
    """Format the address according to its size."""
    memalign_size = get_memory_alignment()
    addr = align_address(addr)

    if memalign_size == 4:
        return "0x{:08x}".format(addr)

    return "0x{:016x}".format(addr)


def format_address_spaces(addr, left=True):
    """Format the address according to its size, but with spaces instead of zeroes."""
    width = get_memory_alignment() * 2 + 2
    addr = align_address(addr)

    if not left:
        return "0x{:x}".format(addr).rjust(width)

    return "0x{:x}".format(addr).ljust(width)


def align_address(address):
    """Align the provided address to the process's native length."""
    if get_memory_alignment() == 4:
        return address & 0xFFFFFFFF

    return address & 0xFFFFFFFFFFFFFFFF

def align_address_to_size(address, align):
    """Align the address to the given size."""
    return address + ((align - (address % align)) % align)

def align_address_to_page(address):
    """Align the address to a page."""
    a = align_address(address) >> DEFAULT_PAGE_ALIGN_SHIFT
    return a << DEFAULT_PAGE_ALIGN_SHIFT


def parse_address(address):
    """Parse an address and return it as an Integer."""
    if is_hex(address):
        return long(address, 16)
    return to_unsigned_long(gdb.parse_and_eval(address))


def is_in_x86_kernel(address):
    address = align_address(address)
    memalign = get_memory_alignment(in_bits=True) - 1
    return (address >> memalign) == 0xF


@lru_cache()
def endian_str():
    elf = current_elf or get_elf_headers()
    return "<" if elf.e_endianness == Elf.LITTLE_ENDIAN else ">"


@lru_cache()
def is_remote_debug():
    """"Return True is the current debugging session is running through GDB remote session."""
    return __gef_remote__ is not None or "remote" in gdb.execute("maintenance print target-stack", to_string=True)


def de_bruijn(alphabet, n):
    """De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib)."""
    k = len(alphabet)
    a = [0] * k * n
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c
    return db(1,1)


def generate_cyclic_pattern(length):
    """Create a `length` byte bytearray of a de Bruijn cyclic pattern."""
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    cycle = get_memory_alignment()
    res = bytearray()

    for i, c in enumerate(de_bruijn(charset, cycle)):
        if i == length:
            break
        res.append(c)

    return res


def safe_parse_and_eval(value):
    """GEF wrapper for gdb.parse_and_eval(): this function returns None instead of raising
    gdb.error if the eval failed."""
    try:
        return gdb.parse_and_eval(value)
    except gdb.error:
        return None




def gef_convenience(value):
    """Defines a new convenience value."""
    global __gef_convenience_vars_index__
    var_name = "$_gef{:d}".format(__gef_convenience_vars_index__)
    __gef_convenience_vars_index__ += 1
    gdb.execute("""set {:s} = "{:s}" """.format(var_name, value))
    return var_name


def parse_string_range(s):
    """Parses an address range (e.g. 0x400000-0x401000)"""
    addrs = s.split("-")
    return map(lambda x: int(x, 16), addrs)


@lru_cache()
def gef_get_auxiliary_values():
    """Retrieves the auxiliary values of the current execution. Returns None if not running, or a dict()
    of values."""
    if not is_alive():
        return None

    res = {}
    for line in gdb.execute("info auxv", to_string=True).splitlines():
        tmp = line.split()
        _type = tmp[1]
        if _type in ("AT_PLATFORM", "AT_EXECFN"):
            idx = line[:-1].rfind('"') - 1
            tmp = line[:idx].split()

        res[_type] = int(tmp[-1], base=0)
    return res


def gef_read_canary():
    """Read the canary of a running process using Auxiliary Vector. Return a tuple of (canary, location)
    if found, None otherwise."""
    auxval = gef_get_auxiliary_values()
    if not auxval:
        return None

    canary_location = auxval["AT_RANDOM"]
    canary = read_int_from_memory(canary_location)
    canary &= ~0xff
    return canary, canary_location


def gef_get_pie_breakpoint(num):
    global __pie_breakpoints__
    return __pie_breakpoints__[num]


@lru_cache()
def gef_getpagesize():
    """Get the page size from auxiliary values."""
    auxval = gef_get_auxiliary_values()
    if not auxval:
        return DEFAULT_PAGE_SIZE
    return auxval["AT_PAGESZ"]


def only_if_events_supported(event_type):
    """Checks if GDB supports events without crashing."""
    def wrap(f):
        def wrapped_f(*args, **kwargs):
            if getattr(gdb, "events") and getattr(gdb.events, event_type):
                return f(*args, **kwargs)
            warn("GDB events cannot be set")
        return wrapped_f
    return wrap


#
# Event hooking
#

@only_if_events_supported("cont")
def gef_on_continue_hook(func): return gdb.events.cont.connect(func)
@only_if_events_supported("cont")
def gef_on_continue_unhook(func): return gdb.events.cont.disconnect(func)

@only_if_events_supported("stop")
def gef_on_stop_hook(func): return gdb.events.stop.connect(func)
@only_if_events_supported("stop")
def gef_on_stop_unhook(func): return gdb.events.stop.disconnect(func)

@only_if_events_supported("exited")
def gef_on_exit_hook(func): return gdb.events.exited.connect(func)
@only_if_events_supported("exited")
def gef_on_exit_unhook(func): return gdb.events.exited.disconnect(func)

@only_if_events_supported("new_objfile")
def gef_on_new_hook(func): return gdb.events.new_objfile.connect(func)
@only_if_events_supported("new_objfile")
def gef_on_new_unhook(func): return gdb.events.new_objfile.disconnect(func)


#
# Virtual breakpoints
#

class PieVirtualBreakpoint(object):
    """PIE virtual breakpoint (not real breakpoint)."""
    def __init__(self, set_func, vbp_num, addr):
        # set_func(base): given a base address return a
        # set breakpoint gdb command string
        self.set_func = set_func
        self.vbp_num = vbp_num
        # breakpoint num, 0 represents not instantiated yet
        self.bp_num = 0
        self.bp_addr = 0
        # this address might be a symbol, just to know where to break
        if isinstance(addr, int):
            self.addr = hex(addr)
        else:
            self.addr = addr

    def instantiate(self, base):
        if self.bp_num:
            self.destroy()

        try:
            res = gdb.execute(self.set_func(base), to_string=True)
        except gdb.error as e:
            err(e)
            return

        if "Breakpoint" not in res:
            err(res)
            return
        res_list = res.split()
        # Breakpoint (no) at (addr)
        self.bp_num = res_list[1]
        self.bp_addr = res_list[3]

    def destroy(self):
        if not self.bp_num:
            err("Destroy PIE breakpoint not even set")
            return
        gdb.execute("delete {}".format(self.bp_num))
        self.bp_num = 0

#
# Breakpoints
#

class FormatStringBreakpoint(gdb.Breakpoint):
    """Inspect stack for format string."""
    def __init__(self, spec, num_args):
        super(FormatStringBreakpoint, self).__init__(spec, type=gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        msg = []
        ptr, addr = current_arch.get_ith_parameter(self.num_args)
        addr = lookup_address(addr)

        if not addr.valid:
            return False

        if addr.section.permission.value & Permission.WRITE:
            content = read_cstring_from_memory(addr.value)
            name = addr.info.name if addr.info else addr.section.path
            msg.append(Color.colorify("Format string helper", "yellow bold"))
            msg.append("Possible insecure format string: {:s}('{:s}' {:s} {:#x}: '{:s}')".format(self.location, ptr, RIGHT_ARROW, addr.value, content))
            msg.append("Reason: Call to '{:s}()' with format string argument in position "
                       "#{:d} is in page {:#x} ({:s}) that has write permission".format(self.location, self.num_args, addr.section.page_start, name))
            push_context_message("warn", "\n".join(msg))
            return True

        return False


class StubBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.)."""

    def __init__(self, func, retval):
        super(StubBreakpoint, self).__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.retval = retval

        m = "All calls to '{:s}' will be skipped".format(self.func)
        if self.retval is not None:
            m += " (with return value set to {:#x})".format(self.retval)
        info(m)
        return

    def stop(self):
        m = "Ignoring call to '{:s}' ".format(self.func)
        m+= "(setting return value to {:#x})".format(self.retval)
        gdb.execute("return (unsigned int){:#x}".format(self.retval))
        ok(m)
        return False


class ChangePermissionBreakpoint(gdb.Breakpoint):
    """When hit, this temporary breakpoint will restore the original code, and position
    $pc correctly."""

    def __init__(self, loc, code, pc):
        super(ChangePermissionBreakpoint, self).__init__(loc, gdb.BP_BREAKPOINT, internal=False)
        self.original_code = code
        self.original_pc = pc
        return

    def stop(self):
        info("Restoring original context")
        write_memory(self.original_pc, self.original_code, len(self.original_code))
        info("Restoring $pc")
        gdb.execute("set $pc = {:#x}".format(self.original_pc))
        return True


class TraceMallocBreakpoint(gdb.Breakpoint):
    """Track allocations done with malloc() or calloc()."""

    def __init__(self, name):
        super(TraceMallocBreakpoint, self).__init__(name, gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        return

    def stop(self):
        _, size = current_arch.get_ith_parameter(0)
        self.retbp = TraceMallocRetBreakpoint(size, self.name)
        return False



class TraceMallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of malloc()."""

    def __init__(self, size, name):
        super(TraceMallocRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.size = size
        self.name = name
        self.silent = True
        return


    def stop(self):
        global __heap_uaf_watchpoints__, __heap_freed_list__, __heap_allocated_list__

        if self.return_value:
            loc = long(self.return_value)
        else:
            loc = to_unsigned_long(gdb.parse_and_eval(current_arch.return_register))

        size = self.size
        ok("{} - {}({})={:#x}".format(Color.colorify("Heap-Analysis", "yellow bold"), self.name, size, loc))
        check_heap_overlap = get_gef_setting("heap-analysis-helper.check_heap_overlap")

        # pop from free-ed list if it was in it
        if __heap_freed_list__:
            idx = 0
            for item in __heap_freed_list__:
                addr = item[0]
                if addr==loc:
                    __heap_freed_list__.remove(item)
                    continue
                idx+=1

        # pop from uaf watchlist
        if __heap_uaf_watchpoints__:
            idx = 0
            for wp in __heap_uaf_watchpoints__:
                wp_addr = wp.address
                if loc <= wp_addr < loc+size:
                    __heap_uaf_watchpoints__.remove(wp)
                    wp.enabled = False
                    continue
                idx+=1

        item = (loc, size)

        if check_heap_overlap:
            # seek all the currently allocated chunks, read their effective size and check for overlap
            msg = []
            align = get_memory_alignment()
            for chunk_addr, _ in __heap_allocated_list__:
                current_chunk = GlibcChunk(chunk_addr)
                current_chunk_size = current_chunk.get_chunk_size()

                if chunk_addr <= loc < chunk_addr + current_chunk_size:
                    offset = loc - chunk_addr - 2*align
                    if offset < 0: continue # false positive, discard

                    msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                    msg.append("Possible heap overlap detected")
                    msg.append("Reason {} new allocated chunk {:#x} (of size {:d}) overlaps in-used chunk {:#x} (of size {:#x})".format(RIGHT_ARROW, loc, size, chunk_addr, current_chunk_size))
                    msg.append("Writing {0:d} bytes from {1:#x} will reach chunk {2:#x}".format(offset, chunk_addr, loc))
                    msg.append("Payload example for chunk {1:#x} (to overwrite {0:#x} headers):".format(loc, chunk_addr))
                    msg.append("  data = 'A'*{0:d} + 'B'*{1:d} + 'C'*{1:d}".format(offset, align))
                    push_context_message("warn", "\n".join(msg))
                    return True

        # add it to alloc-ed list
        __heap_allocated_list__.append(item)
        return False


class TraceReallocBreakpoint(gdb.Breakpoint):
    """Track re-allocations done with realloc()."""

    def __init__(self):
        super(TraceReallocBreakpoint, self).__init__("__libc_realloc", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self):
        _, ptr = current_arch.get_ith_parameter(0)
        _, size = current_arch.get_ith_parameter(1)
        self.retbp = TraceReallocRetBreakpoint(ptr, size)
        return False


class TraceReallocRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to retrieve the return value of realloc()."""

    def __init__(self, ptr, size):
        super(TraceReallocRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.ptr = ptr
        self.size = size
        self.silent = True
        return

    def stop(self):
        global __heap_uaf_watchpoints__, __heap_freed_list__, __heap_allocated_list__

        if self.return_value:
            newloc = long(self.return_value)
        else:
            newloc = to_unsigned_long(gdb.parse_and_eval(current_arch.return_register))

        if newloc != self:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", "yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify("{:#x}".format(newloc), "green"),))
        else:
            ok("{} - realloc({:#x}, {})={}".format(Color.colorify("Heap-Analysis", "yellow bold"),
                                                   self.ptr, self.size,
                                                   Color.colorify("{:#x}".format(newloc), "red"),))

        item = (newloc, self.size)

        try:
            # check if item was in alloc-ed list
            idx = [x for x,y in __heap_allocated_list__].index(self.ptr)
            # if so pop it out
            item = __heap_allocated_list__.pop(idx)
        except ValueError:
            if is_debug():
                warn("Chunk {:#x} was not in tracking list".format(self.ptr))
        finally:
            # add new item to alloc-ed list
            __heap_allocated_list__.append(item)

        return False


class TraceFreeBreakpoint(gdb.Breakpoint):
    """Track calls to free() and attempts to detect inconsistencies."""

    def __init__(self):
        super(TraceFreeBreakpoint, self).__init__("__libc_free", gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        return

    def stop(self):
        _, addr = current_arch.get_ith_parameter(0)
        msg = []
        check_free_null = get_gef_setting("heap-analysis-helper.check_free_null")
        check_double_free = get_gef_setting("heap-analysis-helper.check_double_free")
        check_weird_free = get_gef_setting("heap-analysis-helper.check_weird_free")
        check_uaf = get_gef_setting("heap-analysis-helper.check_uaf")

        ok("{} - free({:#x})".format(Color.colorify("Heap-Analysis", "yellow bold"), addr))
        if addr==0:
            if check_free_null:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append("Attempting to free(NULL) at {:#x}".format(current_arch.pc))
                msg.append("Reason: if NULL page is allocatable, this can lead to code execution.")
                push_context_message("warn", "\n".join(msg))
                return True
            return False


        if addr in [x for (x,y) in __heap_freed_list__]:
            if check_double_free:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append("Double-free detected {} free({:#x}) is called at {:#x} but is already in the free-ed list".format(RIGHT_ARROW, addr, current_arch.pc))
                msg.append("Execution will likely crash...")
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # if here, no error
        # 1. move alloc-ed item to free list
        try:
            # pop from alloc-ed list
            idx = [x for x,y in __heap_allocated_list__].index(addr)
            item = __heap_allocated_list__.pop(idx)

        except ValueError:
            if check_weird_free:
                msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
                msg.append("Heap inconsistency detected:")
                msg.append("Attempting to free an unknown value: {:#x}".format(addr))
                push_context_message("warn", "\n".join(msg))
                return True
            return False

        # 2. add it to free-ed list
        __heap_freed_list__.append(item)

        self.retbp = None
        if check_uaf:
            # 3. (opt.) add a watchpoint on pointer
            self.retbp = TraceFreeRetBreakpoint(addr)
        return False


class TraceFreeRetBreakpoint(gdb.FinishBreakpoint):
    """Internal temporary breakpoint to track free()d values."""

    def __init__(self, addr):
        super(TraceFreeRetBreakpoint, self).__init__(gdb.newest_frame(), internal=True)
        self.silent = True
        self.addr = addr
        return

    def stop(self):
        wp = UafWatchpoint(self.addr)
        __heap_uaf_watchpoints__.append(wp)
        ok("{} - watching {:#x}".format(Color.colorify("Heap-Analysis", "yellow bold"), self.addr))
        return False


class UafWatchpoint(gdb.Breakpoint):
    """Custom watchpoints set TraceFreeBreakpoint() to monitor free()d pointers being used."""

    def __init__(self, addr):
        super(UafWatchpoint, self).__init__("*{:#x}".format(addr), gdb.BP_WATCHPOINT, internal=True)
        self.address = addr
        self.silent = True
        self.enabled = True
        return

    def stop(self):
        """If this method is triggered, we likely have a UaF. Break the execution and report it."""
        frame = gdb.selected_frame()
        if frame.name() in ("_int_malloc", "malloc_consolidate", "__libc_calloc"):
            # ignore when the watchpoint is raised by malloc() - due to reuse
            return False

        # software watchpoints stop after the next statement (see
        # https://sourceware.org/gdb/onlinedocs/gdb/Set-Watchpoints.html)
        pc = gdb_get_nth_previous_instruction_address(current_arch.pc, 2)
        insn = gef_current_instruction(pc)
        msg = []
        msg.append(Color.colorify("Heap-Analysis", "yellow bold"))
        msg.append("Possible Use-after-Free in '{:s}': pointer {:#x} was freed, but is attempted to be used at {:#x}"
                   .format(get_filepath(), self.address, pc))
        msg.append("{:#x}   {:s} {:s}".format(insn.address, insn.mnemonic, Color.yellowify(", ".join(insn.operands))))
        push_context_message("warn", "\n".join(msg))
        return True


class EntryBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint used internally to stop execution at the most convenient entry point."""

    def __init__(self, location):
        super(EntryBreakBreakpoint, self).__init__(location, gdb.BP_BREAKPOINT, internal=True, temporary=True)
        self.silent = True
        return

    def stop(self):
        return True


class NamedBreakpoint(gdb.Breakpoint):
    """Breakpoint which shows a specified name, when hit."""

    def __init__(self, location, name):
        super(NamedBreakpoint, self).__init__(spec=location, type=gdb.BP_BREAKPOINT, internal=False, temporary=False)
        self.name = name
        self.loc = location

        return

    def stop(self):
        push_context_message("info", "Hit breakpoint {} ({})".format(self.loc, Color.colorify(self.name, "red bold")))
        return True


#
# Commands
#

def register_external_command(obj):
    """Registering function for new GEF (sub-)command to GDB."""
    global __commands__, __gef__
    cls = obj.__class__
    __commands__.append(cls)
    __gef__.load(initial=False)
    __gef__.doc.add_command_to_doc((cls._cmdline_, cls, None))
    __gef__.doc.refresh()
    return cls


def register_command(cls):
    """Decorator for registering new GEF (sub-)command to GDB."""
    global __commands__
    __commands__.append(cls)
    return cls


def register_priority_command(cls):
    """Decorator for registering new command with priority, meaning that it must
    loaded before the other generic commands."""
    global __commands__
    __commands__.insert(0, cls)
    return cls

def register_function(cls):
    """Decorator for registering a new convenience function to GDB."""
    global __functions__
    __functions__.append(cls)
    return cls

class GenericCommand(gdb.Command):
    """This is an abstract class for invoking commands, should not be instantiated."""
    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, **kwargs):
        self.pre_load()
        syntax = Color.yellowify("\nSyntax: ") + self._syntax_
        example = Color.yellowify("\nExample: ") + self._example_ if self._example_ else ""
        self.__doc__ = self.__doc__.replace(" "*4, "") + syntax + example
        self.repeat = False
        self.repeat_count = 0
        self.__last_command = None
        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)
        complete_type = kwargs.setdefault("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.setdefault("prefix", False)
        super(GenericCommand, self).__init__(self._cmdline_, command_type, complete_type, prefix)
        self.post_load()
        return

    def invoke(self, args, from_tty):
        try:
            argv = gdb.string_to_argv(args)
            self.__set_repeat_count(argv, from_tty)
            bufferize(self.do_invoke)(argv)
        except Exception as e:
            # Note: since we are intercepting cleaning exceptions here, commands preferably should avoid
            # catching generic Exception, but rather specific ones. This is allows a much cleaner use.
            if is_debug():
                show_last_exception()
            else:
                err("Command '{:s}' failed to execute properly, reason: {:s}".format(self._cmdline_, str(e)))
        return

    def usage(self):
        err("Syntax\n{}".format(self._syntax_))
        return

    @abc.abstractproperty
    def _cmdline_(self): pass

    @abc.abstractproperty
    def _syntax_(self): pass

    @abc.abstractproperty
    def _example_(self): return ""

    @abc.abstractmethod
    def do_invoke(self, argv): pass

    def pre_load(self): pass

    def post_load(self): pass

    def __get_setting_name(self, name):
        def __sanitize_class_name(clsname):
            if " " not in clsname:
                return clsname
            return "-".join(clsname.split())

        class_name = __sanitize_class_name(self.__class__._cmdline_)
        return "{:s}.{:s}".format(class_name, name)

    @property
    def settings(self):
        """Return the list of settings for this command."""
        return [ x.split(".", 1)[1] for x in __config__
                 if x.startswith("{:s}.".format(self._cmdline_)) ]

    def get_setting(self, name):
        key = self.__get_setting_name(name)
        setting = __config__[key]
        return setting[1](setting[0])

    def has_setting(self, name):
        key = self.__get_setting_name(name)
        return key in __config__

    def add_setting(self, name, value, description=""):
        key = self.__get_setting_name(name)
        __config__[key] = [value, type(value), description]
        return

    def del_setting(self, name):
        key = self.__get_setting_name(name)
        del __config__[key]
        return

    def __set_repeat_count(self, argv, from_tty):
        if not from_tty:
            self.repeat = False
            self.repeat_count = 0
            return

        command = gdb.execute("show commands", to_string=True).strip().split("\n")[-1]
        self.repeat = self.__last_command == command
        self.repeat_count = self.repeat_count + 1 if self.repeat else 0
        self.__last_command = command
        return


# Copy/paste this template for new command
# @register_command
# class TemplateCommand(GenericCommand):
# """TemplateCommand: description here will be seen in the help menu for the command."""
#     _cmdline_ = "template-fake"
#     _syntax_  = "{:s}".format(_cmdline_)
#     _aliases_ = ["tpl-fk",]
#     def __init__(self):
#        super(TemplateCommand, self).__init__(complete=gdb.COMPLETE_FILENAME)
#         return
#     def do_invoke(self, argv):
#         return

@register_command
class PrintFormatCommand(GenericCommand):
    """Print bytes format in high level languages."""

    _cmdline_ = "print-format"
    _syntax_  = "{:s} [-f FORMAT] [-b BITSIZE] [-l LENGTH] [-c] [-h] LOCATION".format(_cmdline_)
    _aliases_ = ["pf",]
    _example_ = "{0:s} -f py -b 8 -l 256 $rsp".format(_cmdline_)

    bitformat = {8: "<B", 16: "<H", 32: "<I", 64: "<Q"}
    c_type = {8: "char", 16: "short", 32: "int", 64: "long long"}
    asm_type = {8: "db", 16: "dw", 32: "dd", 64: "dq"}

    def __init__(self):
        super(PrintFormatCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def usage(self):
        h = self._syntax_
        h += "\n\t-f FORMAT specifies the output format for programming language, avaliable value is py, c, js, asm (default py).\n"
        h += "\t-b BITSIZE sepecifies size of bit, avaliable values is 8, 16, 32, 64 (default is 8).\n"
        h += "\t-l LENGTH specifies length of array (default is 256).\n"
        h += "\t-c The result of data will copied to clipboard\n"
        h += "\tLOCATION specifies where the address of bytes is stored."
        info(h)
        return

    def clip(self, data):
        if sys.platform == "linux":
            xclip = which("xclip")
            prog = [xclip, "-selection", "clipboard", "-i"] # For linux
        elif sys.platform == "darwin":
            pbcopy = which("pbcopy")
            prog = [pbcopy] # For OSX
        else:
            warn("Can't copy to clipboard, platform not supported")
            return False

        try:
            p = subprocess.Popen(prog, stdin=subprocess.PIPE)
        except Exception:
            warn("Can't copy to clipboard, Something went wrong while copying")
            return False

        p.stdin.write(data)
        p.stdin.close()
        p.wait()
        return True

    @only_if_gdb_running
    def do_invoke(self, argv):
        """Default value for print-format command."""
        lang = "py"
        length = 256
        bitlen = 8
        copy_to_clipboard = False
        supported_formats = ["py", "c", "js", "asm"]

        opts, args = getopt.getopt(argv, "f:l:b:ch")
        for o,a in opts:
            if   o == "-f": lang = a
            elif o == "-l": length = long(gdb.parse_and_eval(a))
            elif o == "-b": bitlen = long(a)
            elif o == "-c": copy_to_clipboard = True
            elif o == "-h":
                self.usage()
                return

        if not args:
            err("No address specified")
            return

        start_addr = long(gdb.parse_and_eval(args[0]))

        if bitlen not in [8, 16, 32, 64]:
            err("Size of bit must be in 8, 16, 32, or 64")
            return

        if lang not in supported_formats:
            err("Language must be : {}".format(str(supported_formats)))
            return

        size = long(bitlen / 8)
        end_addr = start_addr+length*size
        bf = self.bitformat[bitlen]
        data = []
        out = ""

        for address in range(start_addr, end_addr, size):
            value = struct.unpack(bf, read_memory(address, size))[0]
            data += [value]
        sdata = ", ".join(map(hex, data))

        if lang == "py":
            out = "buf = [{}]".format(sdata)
        elif lang == "c":
            out =  "unsigned {0} buf[{1}] = {{{2}}};".format(self.c_type[bitlen], length, sdata)
        elif lang == "js":
            out =  "var buf = [{}]".format(sdata)
        elif lang == "asm":
            out += "buf {0} {1}".format(self.asm_type[bitlen], sdata)

        if copy_to_clipboard:
            if self.clip(bytes(out, "utf-8")):
                info("Copied to clipboard")
            else:
                warn("There's a problem while copying")

        print(out)
        return


@register_command
class PieCommand(GenericCommand):
    """PIE breakpoint support."""

    _cmdline_ = "pie"
    _syntax_  = "{:s} (breakpoint|info|delete|run|attach|remote)".format(_cmdline_)

    def __init__(self):
        super(PieCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        if not argv:
            self.usage()
        return


@register_command
class PieBreakpointCommand(GenericCommand):
    """Set a PIE breakpoint."""

    _cmdline_ = "pie breakpoint"
    _syntax_  = "{:s} BREAKPOINT".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_counter__, __pie_breakpoints__
        if len(argv) < 1:
            self.usage()
            return
        bp_expr = " ".join(argv)
        tmp_bp_expr = bp_expr

        if bp_expr[0] == "*":
            addr = long(gdb.parse_and_eval(bp_expr[1:]))
        else:
            addr = long(gdb.parse_and_eval("&{}".format(bp_expr))) # get address of symbol or function name

        self.set_pie_breakpoint(lambda base: "b *{}".format(base + addr), addr)

        # When the process is already on, set real breakpoints immediately
        if is_alive():
            vmmap = get_process_maps()
            base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
            for bp_ins in __pie_breakpoints__.values():
                bp_ins.instantiate(base_address)


    @staticmethod
    def set_pie_breakpoint(set_func, addr):
        global __pie_counter__, __pie_breakpoints__
        __pie_breakpoints__[__pie_counter__] = PieVirtualBreakpoint(set_func, __pie_counter__, addr)
        __pie_counter__ += 1


@register_command
class PieInfoCommand(GenericCommand):
    """Display breakpoint info."""

    _cmdline_ = "pie info"
    _syntax_  = "{:s} BREAKPOINT".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_breakpoints__
        if len(argv) < 1:
            # No breakpoint info needed
            bps = [__pie_breakpoints__[x] for x in __pie_breakpoints__]
        else:
            try:
                bps = [__pie_breakpoints__[int(x)] for x in argv]
            except ValueError:
                err("Please give me breakpoint number")
                return
        lines = []
        lines.append("VNum\tNum\tAddr")
        lines += [
            "{}\t{}\t{}".format(x.vbp_num, x.bp_num if x.bp_num else "N/A", x.addr) for x in bps
        ]
        gef_print("\n".join(lines))


@register_command
class PieDeleteCommand(GenericCommand):
    """Delete a PIE breakpoint."""

    _cmdline_ = "pie delete"
    _syntax_  = "{:s} [BREAKPOINT]".format(_cmdline_)

    def do_invoke(self, argv):
        global __pie_breakpoints__
        if len(argv) < 1:
            # no arg, delete all
            to_delete = [__pie_breakpoints__[x] for x in __pie_breakpoints__]
            self.delete_bp(to_delete)
        try:
            self.delete_bp([__pie_breakpoints__[int(x)] for x in argv])
        except ValueError:
            err("Please input PIE virtual breakpoint number to delete")

    @staticmethod
    def delete_bp(breakpoints):
        global __pie_breakpoints__
        for bp in breakpoints:
            # delete current real breakpoints if exists
            if bp.bp_num:
                gdb.execute("delete {}".format(bp.bp_num))
            # delete virtual breakpoints
            del __pie_breakpoints__[bp.vbp_num]


@register_command
class PieRunCommand(GenericCommand):
    """Run process with PIE breakpoint support."""

    _cmdline_ = "pie run"
    _syntax_  = _cmdline_

    def do_invoke(self, argv):
        global __pie_breakpoints__
        fpath = get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn("The file '{}' is not executable.".format(fpath))
            return

        if is_alive():
            warn("gdb is already running. Restart process.")

        # get base address
        gdb.execute("set stop-on-solib-events 1")
        hide_context()
        gdb.execute("run {}".format(" ".join(argv)))
        unhide_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        info("base address {}".format(hex(base_address)))

        # modify all breakpoints
        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)

        try:
            gdb.execute("continue")
        except gdb.error as e:
            err(e)
            gdb.execute("kill")


@register_command
class PieAttachCommand(GenericCommand):
    """Do attach with PIE breakpoint support."""

    _cmdline_ = "pie attach"
    _syntax_  = "{:s} PID".format(_cmdline_)

    def do_invoke(self, argv):
        try:
            gdb.execute("attach {}".format(" ".join(argv)), to_string=True)
        except gdb.error as e:
            err(e)
            return
        # after attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]

        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")


@register_command
class PieRemoteCommand(GenericCommand):
    """Attach to a remote connection with PIE breakpoint support."""

    _cmdline_ = "pie remote"
    _syntax_  = "{:s} REMOTE".format(_cmdline_)

    def do_invoke(self, argv):
        try:
            gdb.execute("gef-remote {}".format(" ".join(argv)))
        except gdb.error as e:
            err(e)
            return
        # after remote attach, we are stopped so that we can
        # get base address to modify our breakpoint
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.realpath == get_filepath()][0]

        for bp_ins in __pie_breakpoints__.values():
            bp_ins.instantiate(base_address)
        gdb.execute("context")


@register_command
class SmartEvalCommand(GenericCommand):
    """SmartEval: Smart eval (vague approach to mimic WinDBG `?`)."""
    _cmdline_ = "$"
    _syntax_  = "{0:s} EXPR\n{0:s} ADDRESS1 ADDRESS2".format(_cmdline_)
    _example_ = "\n{0:s} $pc+1\n{0:s} 0x00007ffff7a10000 0x00007ffff7bce000".format(_cmdline_)

    def do_invoke(self, argv):
        argc = len(argv)
        if argc==1:
            self.evaluate(argv)
            return

        if argc==2:
            self.distance(argv)
        return

    def evaluate(self, expr):
        def show_as_int(i):
            off = current_arch.ptrsize*8
            def comp2_x(x): return "{:x}".format((x + (1 << off)) % (1 << off))
            def comp2_b(x): return "{:b}".format((x + (1 << off)) % (1 << off))

            try:
                s_i = comp2_x(res)
                s_i = s_i.rjust(len(s_i)+1, "0") if len(s_i)%2 else s_i
                gef_print("{:d}".format(i))
                gef_print("0x" + comp2_x(res))
                gef_print("0b" + comp2_b(res))
                gef_print("{}".format(binascii.unhexlify(s_i)))
                gef_print("{}".format(binascii.unhexlify(s_i)[::-1]))
            except:
                pass
            return

        parsed_expr = []
        for xp in expr:
            try:
                xp = gdb.parse_and_eval(xp)
                xp = int(xp)
                parsed_expr.append("{:d}".format(xp))
            except gdb.error:
                parsed_expr.append(str(xp))

        try:
            res = eval(" ".join(parsed_expr))
            if type(res) is int:
                show_as_int(res)
            else:
                gef_print("{}".format(res))
        except SyntaxError:
            gef_print(" ".join(parsed_expr))
        return

    def distance(self, args):
        try:
            x = int(args[0], 16) if is_hex(args[0]) else int(args[0])
            y = int(args[1], 16) if is_hex(args[1]) else int(args[1])
            gef_print("{}".format(abs(x-y)))
        except ValueError:
            warn("Distance requires 2 numbers: {} 0 0xffff".format(self._cmdline_))
        return


@register_command
class CanaryCommand(GenericCommand):
    """Shows the canary value of the current process. Apply the techique detailed in
    https://www.elttam.com.au/blog/playing-with-canaries/ to show the canary."""

    _cmdline_ = "canary"
    _syntax_  = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.dont_repeat()

        has_canary = checksec(get_filepath())["Canary"]
        if not has_canary:
            warn("This binary was not compiled with SSP.")
            return

        res = gef_read_canary()
        if not res:
            err("Failed to get the canary")
            return

        canary, location = res
        info("Found AT_RANDOM at {:#x}, reading {} bytes".format(location, current_arch.ptrsize))
        info("The canary of process {} is {:#x}".format(get_pid(), canary))
        return


@register_command
class ProcessStatusCommand(GenericCommand):
    """Extends the info given by GDB `info proc`, by giving an exhaustive description of the
    process status (file descriptors, ancestor, descendants, etc.). """

    _cmdline_ = "process-status"
    _syntax_  = _cmdline_
    _aliases_ = ["status", ]

    def __init__(self):
        super(ProcessStatusCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        return

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv):
        self.show_info_proc()
        self.show_ancestor()
        self.show_descendants()
        self.show_fds()
        self.show_connections()
        return

    def get_state_of(self, pid):
        res = {}
        for line in open("/proc/{}/status".format(pid), "r"):
            key, value = line.split(":", 1)
            res[key.strip()] = value.strip()
        return res

    def get_cmdline_of(self, pid):
        return open("/proc/{}/cmdline".format(pid), "r").read().replace("\x00", "\x20").strip()

    def get_process_path_of(self, pid):
        return os.readlink("/proc/{}/exe".format(pid))

    def get_children_pids(self, pid):
        ps = which("ps")
        cmd = [ps, "-o", "pid", "--ppid","{}".format(pid), "--noheaders"]
        try:
            return [int(x) for x in gef_execute_external(cmd, as_list=True)]
        except Exception:
            return []

    def show_info_proc(self):
        info("Process Information")
        pid = get_pid()
        cmdline = self.get_cmdline_of(pid)
        gef_print("\tPID {} {}".format(RIGHT_ARROW, pid))
        gef_print("\tExecutable {} {}".format(RIGHT_ARROW, self.get_process_path_of(pid)))
        gef_print("\tCommand line {} '{}'".format(RIGHT_ARROW, cmdline))
        return

    def show_ancestor(self):
        info("Parent Process Information")
        ppid = int(self.get_state_of(get_pid())["PPid"])
        state = self.get_state_of(ppid)
        cmdline = self.get_cmdline_of(ppid)
        gef_print("\tParent PID {} {}".format(RIGHT_ARROW, state["Pid"]))
        gef_print("\tCommand line {} '{}'".format(RIGHT_ARROW, cmdline))
        return

    def show_descendants(self):
        info("Children Process Information")
        children = self.get_children_pids(get_pid())
        if not children:
            gef_print("\tNo child process")
            return

        for child_pid in children:
            state = self.get_state_of(child_pid)
            pid = state["Pid"]
            gef_print("\tPID {} {} (Name: '{}', CmdLine: '{}')".format(RIGHT_ARROW,
                                                                       pid,
                                                                       self.get_process_path_of(pid),
                                                                       self.get_cmdline_of(pid)))
            return

    def show_fds(self):
        pid = get_pid()
        path = "/proc/{:d}/fd".format(pid)

        info("File Descriptors:")
        items = os.listdir(path)
        if not items:
            gef_print("\tNo FD opened")
            return

        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath):
                gef_print("\t{:s} {:s} {:s}".format (fullpath, RIGHT_ARROW, os.readlink(fullpath)))
        return

    def list_sockets(self, pid):
        sockets = []
        path = "/proc/{:d}/fd".format(pid)
        items = os.listdir(path)
        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath) and os.readlink(fullpath).startswith("socket:"):
                p = os.readlink(fullpath).replace("socket:", "")[1:-1]
                sockets.append(int(p))
        return sockets

    def parse_ip_port(self, addr):
        ip, port = addr.split(":")
        return socket.inet_ntoa(struct.pack("<I", int(ip, 16))), int(port, 16)

    def show_connections(self):
        # https://github.com/torvalds/linux/blob/v4.7/include/net/tcp_states.h#L16
        tcp_states_str = {
            0x01: "TCP_ESTABLISHED",
            0x02: "TCP_SYN_SENT",
            0x03: "TCP_SYN_RECV",
            0x04: "TCP_FIN_WAIT1",
            0x05: "TCP_FIN_WAIT2",
            0x06: "TCP_TIME_WAIT",
            0x07: "TCP_CLOSE",
            0x08: "TCP_CLOSE_WAIT",
            0x09: "TCP_LAST_ACK",
            0x0a: "TCP_LISTEN",
            0x0b: "TCP_CLOSING",
            0x0c: "TCP_NEW_SYN_RECV",
        }

        udp_states_str = {
            0x07: "UDP_LISTEN",
        }

        info("Network Connections")
        pid = get_pid()
        sockets = self.list_sockets(pid)
        if not sockets:
            gef_print("\tNo open connections")
            return

        entries = {}
        entries["TCP"] = [x.split() for x in open("/proc/{:d}/net/tcp".format(pid), "r").readlines()[1:]]
        entries["UDP"]= [x.split() for x in open("/proc/{:d}/net/udp".format(pid), "r").readlines()[1:]]

        for proto in entries:
            for entry in entries[proto]:
                local, remote, state = entry[1:4]
                inode = int(entry[9])
                if inode in sockets:
                    local = self.parse_ip_port(local)
                    remote = self.parse_ip_port(remote)
                    state = int(state, 16)
                    state_str = tcp_states_str[state] if proto=="TCP" else udp_states_str[state]

                    gef_print("\t{}:{} {} {}:{} ({})".format(local[0], local[1],
                                                             RIGHT_ARROW,
                                                             remote[0], remote[1],
                                                             state_str))
        return


@register_priority_command
class GefThemeCommand(GenericCommand):
    """Customize GEF appearance."""
    _cmdline_ = "theme"
    _syntax_  = "{:s} [KEY [VALUE]]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefThemeCommand, self).__init__(GefThemeCommand._cmdline_)
        self.add_setting("context_title_line", "gray", "Color of the borders in context window")
        self.add_setting("context_title_message", "cyan", "Color of the title in context window")
        self.add_setting("default_title_line", "gray", "Default color of borders")
        self.add_setting("default_title_message", "cyan", "Default color of title")
        self.add_setting("table_heading", "blue", "Color of the column headings to tables (e.g. vmmap)")
        self.add_setting("disassemble_current_instruction", "green", "Color to use to highlight the current $pc when disassembling")
        self.add_setting("dereference_string", "yellow", "Color of dereferenced string")
        self.add_setting("dereference_code", "gray", "Color of dereferenced code")
        self.add_setting("dereference_base_address", "cyan", "Color of dereferenced address")
        self.add_setting("dereference_register_value", "bold blue" , "Color of dereferenced register")
        self.add_setting("registers_register_name", "blue", "Color of the register name in the register window")
        self.add_setting("registers_value_changed", "bold red", "Color of the changed register in the register window")
        self.add_setting("address_stack", "pink", "Color to use when a stack address is found")
        self.add_setting("address_heap", "green", "Color to use when a heap address is found")
        self.add_setting("address_code", "red", "Color to use when a code address is found")
        self.add_setting("source_current_line", "green", "Color to use for the current code line in the source window")
        return

    def do_invoke(self, args):
        self.dont_repeat()
        argc = len(args)

        if argc==0:
            for setting in sorted(self.settings):
                value = self.get_setting(setting)
                value = Color.colorify(value, value)
                gef_print("{:40s}: {:s}".format(setting, value))
            return

        setting = args[0]
        if not self.has_setting(setting):
            err("Invalid key")
            return

        if argc==1:
            value = self.get_setting(setting)
            value = Color.colorify(value, value)
            gef_print("{:40s}: {:s}".format(setting, value))
            return

        val = [x for x in args[1:] if x in Color.colors]
        self.add_setting(setting, " ".join(val))
        return





























































































########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################





#HEAP METHOD ##############################################################################

#THIS WORKS ON WINDOWS
@register_command
class HeapAnalysisCommand(GenericCommand):
    """Heap vulnerability analysis helper: this command aims to track dynamic heap allocation
    done through malloc()/free() to provide some insights on possible heap vulnerabilities. The
    following vulnerabilities are checked:
    - NULL free
    - Use-after-Free
    - Double Free
    - Heap overlap"""
    _cmdline_ = "heap-analysis-helper"
    _syntax_ = _cmdline_

    def __init__(self, *args, **kwargs):
        super(HeapAnalysisCommand, self).__init__(complete=gdb.COMPLETE_NONE)
        self.add_setting("check_free_null", False, "Break execution when a free(NULL) is encountered")
        self.add_setting("check_double_free", True, "Break execution when a double free is encountered")
        self.add_setting("check_weird_free", True, "Break execution when free() is called against a non-tracked pointer")
        self.add_setting("check_uaf", True, "Break execution when a possible Use-after-Free condition is found")
        self.add_setting("check_heap_overlap", True, "Break execution when a possible overlap in allocation is found")

        self.bp_malloc, self.bp_calloc, self.bp_free, self.bp_realloc = None, None, None, None
        return

    @only_if_gdb_running
    @experimental_feature
    def do_invoke(self, argv):
        if not argv:
            self.setup()
            return

        if argv[0]=="show":
            self.dump_tracked_allocations()
        return

    def setup(self):
        ok("Tracking malloc() & calloc()")
        self.bp_malloc = TraceMallocBreakpoint("__libc_malloc")
        self.bp_calloc = TraceMallocBreakpoint("__libc_calloc")
        ok("Tracking free()")
        self.bp_free = TraceFreeBreakpoint()
        ok("Tracking realloc()")
        self.bp_realloc = TraceReallocBreakpoint()

        ok("Disabling hardware watchpoints (this may increase the latency)")
        gdb.execute("set can-use-hw-watchpoints 0")

        info("Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.")
        warn("{}: The heap analysis slows down the execution noticeably.".format(
            Color.colorify("Note", "bold underline yellow")))


        # when inferior quits, we need to clean everything for a next execution
        gef_on_exit_hook(self.clean)
        return

    def dump_tracked_allocations(self):
        global __heap_allocated_list__, __heap_freed_list__, __heap_uaf_watchpoints__

        if __heap_allocated_list__:
            ok("Tracked as in-use chunks:")
            for addr, sz in __heap_allocated_list__: gef_print("{} malloc({:d}) = {:#x}".format(CROSS, sz, addr))
        else:
            ok("No malloc() chunk tracked")

        if __heap_freed_list__:
            ok("Tracked as free-ed chunks:")
            for addr, sz in __heap_freed_list__: gef_print("{}  free({:d}) = {:#x}".format(TICK, sz, addr))
        else:
            ok("No free() chunk tracked")
        return

    def clean(self, event):
        global __heap_allocated_list__, __heap_freed_list__, __heap_uaf_watchpoints__

        ok("{} - Cleaning up".format(Color.colorify("Heap-Analysis", "yellow bold"),))
        for bp in [self.bp_malloc, self.bp_calloc, self.bp_free, self.bp_realloc]:
            if hasattr(bp, "retbp") and bp.retbp:
                bp.retbp.delete()
            bp.delete()

        for wp in __heap_uaf_watchpoints__:
            wp.delete()

        __heap_allocated_list__ = []
        __heap_freed_list__ = []
        __heap_uaf_watchpoints__ = []

        ok("{} - Re-enabling hardware watchpoints".format(Color.colorify("Heap-Analysis", "yellow bold"),))
        gdb.execute("set can-use-hw-watchpoints 1")

        gef_on_exit_unhook(self.clean)
        return



#THIS WORKS ON WINDOWS
@register_command
class ScanSectionCommand(GenericCommand):
    """Search for addresses that are located in a memory mapping (haystack) that belonging
    to another (needle)."""

    _cmdline_ = "scan"
    _syntax_  = "{:s} HAYSTACK NEEDLE".format(_cmdline_)
    _aliases_ = ["lookup",]
    _example_ = "\n{0:s} stack libc".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 2:
            self.usage()
            return

        haystack = argv[0]
        needle = argv[1]

        info("Searching for addresses in '{:s}' that point to '{:s}'"
             .format(Color.yellowify(haystack), Color.yellowify(needle)))

        if haystack == "binary":
            haystack = get_filepath()

        if needle == "binary":
            needle = get_filepath()

        needle_sections = []
        haystack_sections = []

        if "0x" in haystack:
            start, end = parse_string_range(haystack)
            haystack_sections.append((start, end, ""))

        if "0x" in needle:
            start, end = parse_string_range(needle)
            needle_sections.append((start, end))

        for sect in get_process_maps():
            if haystack in sect.path:
                haystack_sections.append((sect.page_start, sect.page_end, os.path.basename(sect.path)))
            if needle in sect.path:
                needle_sections.append((sect.page_start, sect.page_end))

        #step = current_arch.ptrsize
        fmt = "{}{}".format(endian_str(), "I" if step==4 else "Q")

        for hstart, hend, hname in haystack_sections:
            try:
                mem = read_memory(hstart, hend - hstart)
            except gdb.MemoryError:
                continue

            for i in range(0, len(mem), step):
                target = struct.unpack(fmt, mem[i:i+step])[0]
                for nstart, nend in needle_sections:
                    if target >= nstart and target < nend:
                        deref = DereferenceCommand.pprint_dereferenced(hstart, long(i / step))
                        if hname != "":
                            name = Color.colorify(hname, "yellow")
                            gef_print("{:s}: {:s}".format(name, deref))
                        else:
                            gef_print(" {:s}".format(deref))

        return


#THIS WORKS ON WINDOWS
@register_command
class SearchPatternCommand(GenericCommand):
    """SearchPatternCommand: search a pattern in memory. If given an hex value (starting with 0x)
    the command will also try to look for upwards cross-references to this address."""

    _cmdline_ = "search-pattern"
    _syntax_  = "{:s} PATTERN [small|big] [section]".format(_cmdline_)
    _aliases_ = ["grep", "xref"]
    _example_ = "\n{0:s} AAAAAAAA\n{0:s} 0x555555554000 little stack\n{0:s}AAAA 0x600000-0x601000".format(_cmdline_)

    def print_section(self, section):
        title = "In "
        if section.path:
            title += "'{}'".format(Color.blueify(section.path) )

        title += "({:#x}-{:#x})".format(section.page_start, section.page_end)
        title += ", permission={}".format(section.permission)
        ok(title)
        return

    def print_loc(self, loc):
        gef_print("""  {:#x} - {:#x} {}  "{}" """.format(loc[0], loc[1], RIGHT_ARROW, Color.pinkify(loc[2]),))
        return

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search a pattern within a range defined by arguments."""
        step = 0x400 * 0x1000
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            mem = read_memory(chunk_addr, chunk_size)

            for match in re.finditer(pattern, mem):
                start = chunk_addr + match.start()
                if is_ascii_string(start):
                    ustr = read_ascii_string(start)
                    end = start + len(ustr)
                else :
                    ustr = gef_pystring(pattern)+"[...]"
                    end = start + len(pattern)
                locations.append((start, end, ustr))

            del mem

        return locations

    def search_pattern(self, pattern, section_name):
        """Search a pattern within the whole userland memory."""
        for section in get_process_maps():
            if not section.permission & Permission.READ: continue
            if section.path == "[vvar]": continue
            if not section_name in section.path: continue

            start = section.page_start
            end   = section.page_end - 1
            old_section = None

            for loc in self.search_pattern_by_address(pattern, start, end):
                addr_loc_start = lookup_address(loc[0])
                if addr_loc_start and addr_loc_start.section:
                    if old_section != addr_loc_start.section:
                        self.print_section(addr_loc_start.section)
                        old_section = addr_loc_start.section

                self.print_loc(loc)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 1:
            self.usage()
            return

        pattern = argv[0]
        endian = get_endian()

        if argc >= 2:
            if argv[1].lower() == "big": endian = Elf.BIG_ENDIAN
            elif argv[1].lower() == "small": endian = Elf.LITTLE_ENDIAN

        if is_hex(pattern):
            if endian == Elf.BIG_ENDIAN:
                pattern = "".join(["\\x"+pattern[i:i+2] for i in range(2, len(pattern), 2)])
            else:
                pattern = "".join(["\\x"+pattern[i:i+2] for i in range(len(pattern) - 2, 0, -2)])

        if argc == 3:
            info("Searching '{:s}' in {:s}".format(Color.yellowify(pattern), argv[2]))

            if "0x" in argv[2]:
                start, end = parse_string_range(argv[2])

                loc = lookup_address(start)
                if loc.valid:
                    self.print_section(loc.section)

                for loc in self.search_pattern_by_address(pattern, start, end):
                    self.print_loc(loc)
            else:
                section_name = argv[2]
                if section_name == "binary":
                    section_name = get_filepath()

                self.search_pattern(pattern, section_name)
        else:
            info("Searching '{:s}' in memory".format(Color.yellowify(pattern)))
            self.search_pattern(pattern, "")
        return




#THIS WORKS IN THE WINDOWS
@register_command
class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it. The command will test for
    well-known symbols for entry points, such as `main`, `_main`, `__libc_start_main`, etc. defined by
    the setting `entrypoint_symbols`."""

    _cmdline_ = "entry-break"
    _syntax_  = _cmdline_
    _aliases_ = ["start",]

    def __init__(self, *args, **kwargs):
        super(EntryPointBreakCommand, self).__init__()
        self.add_setting("entrypoint_symbols", "main _main __libc_start_main __uClibc_main start _start", "Possible symbols for entry points")
        return

    def do_invoke(self, argv):
        fpath = get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn("The file '{}' is not executable.".format(fpath))
            return

        if is_alive() and not __gef_qemu_mode__:
            warn("gdb is already running")
            return

        bp = None
        entrypoints = self.get_setting("entrypoint_symbols").split()

        for sym in entrypoints:
            try:
                value = gdb.parse_and_eval(sym)
                info("Breaking at '{:s}'".format(str(value)))
                bp = EntryBreakBreakpoint(sym)
                gdb.execute("run {}".format(" ".join(argv)))
                return

            except gdb.error as gdb_error:
                if 'The "remote" target does not support "run".' in str(gdb_error):
                    # this case can happen when doing remote debugging
                    gdb.execute("continue")
                    return
                continue

        # if here, clear the breakpoint if any set
        if bp:
            bp.delete()

        # break at entry point
        elf = get_elf_headers()
        if elf is None:
            return

        if self.is_pie(fpath):
            self.set_init_tbreak_pie(elf.e_entry, argv)
            gdb.execute("continue")
            return

        self.set_init_tbreak(elf.e_entry)
        gdb.execute("run {}".format(" ".join(argv)))
        return

    def set_init_tbreak(self, addr):
        info("Breaking at entry-point: {:#x}".format(addr))
        bp = EntryBreakBreakpoint("*{:#x}".format(addr))
        return bp

    def set_init_tbreak_pie(self, addr, argv):
        warn("PIC binary detected, retrieving text base address")
        gdb.execute("set stop-on-solib-events 1")
        hide_context()
        gdb.execute("run {}".format(" ".join(argv)))
        unhide_context()
        gdb.execute("set stop-on-solib-events 0")
        vmmap = get_process_maps()
        base_address = [x.page_start for x in vmmap if x.path == get_filepath()][0]
        return self.set_init_tbreak(base_address + addr)

    def is_pie(self, fpath):
        return checksec(fpath)["PIE"]


#THIS WORKS IN THE WINDOWS
@register_command
class HexdumpCommand(GenericCommand):
    """Display SIZE lines of hexdump from the memory location pointed by ADDRESS. """

    _cmdline_ = "hexdump"
    _syntax_  = "{:s} [qword|dword|word|byte] [ADDRESS] [[L][SIZE]] [REVERSE]".format(_cmdline_)
    _example_ = "{:s} byte $rsp L16 REVERSE".format(_cmdline_)

    def __init__(self):
        super(HexdumpCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("always_show_ascii", False, "If true, hexdump will always display the ASCII dump")
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        fmt = "byte"
        target = "$sp"
        valid_formats = ["byte", "word", "dword", "qword"]
        read_len = None
        reverse = False

        for arg in argv:
            arg = arg.lower()
            is_format_given = False
            for valid_format in valid_formats:
                if valid_format.startswith(arg):
                    fmt = valid_format
                    is_format_given = True
                    break
            if is_format_given:
                continue
            if arg.startswith("l"):
                arg = arg[1:]
            try:
                read_len = long(arg, 0)
                continue
            except ValueError:
                pass

            if "reverse".startswith(arg):
                reverse = True
                continue
            target = arg

        start_addr = to_unsigned_long(gdb.parse_and_eval(target))
        read_from = align_address(start_addr)
        if not read_len:
            read_len = 0x40 if fmt=="byte" else 0x10

        if fmt == "byte":
            read_from += self.repeat_count * read_len
            mem = read_memory(read_from, read_len)
            lines = hexdump(mem, base=read_from).splitlines()
        else:
            lines = self._hexdump(read_from, read_len, fmt, self.repeat_count * read_len)

        if reverse:
            lines.reverse()

        gef_print("\n".join(lines))
        return


    def _hexdump(self, start_addr, length, arrange_as, offset=0):
        elf = get_elf_headers()
        if elf is None:
            return
        endianness = endian_str()

        base_address_color = get_gef_setting("theme.dereference_base_address")
        show_ascii = self.get_setting("always_show_ascii")

        formats = {
            "qword": ("Q", 8),
            "dword": ("I", 4),
            "word": ("H", 2),
        }

        r, l = formats[arrange_as]
        fmt_str = "{{base}}{v}+{{offset:#06x}}   {{sym}}{{val:#0{prec}x}}   {{text}}".format(v=VERTICAL_LINE, prec=l*2+2)
        fmt_pack = endianness + r
        lines = []

        i = 0
        text = ""
        while i < length:
            cur_addr = start_addr + (i + offset) * l
            sym = gdb_get_location_from_symbol(cur_addr)
            sym = "<{:s}+{:04x}> ".format(*sym) if sym else ""
            mem = read_memory(cur_addr, l)
            val = struct.unpack(fmt_pack, mem)[0]
            if show_ascii:
                text = "".join([chr(b) if 0x20 <= b < 0x7F else "." for b in mem])
            lines.append(fmt_str.format(base=Color.colorify(format_address(cur_addr), base_address_color),
                                        offset=(i + offset) * l, sym=sym, val=val, text=text))
            i += 1

        return lines

#THIS WORKS ON WINDOWS
@register_command
class PatchCommand(GenericCommand):
    """Write specified values to the specified address."""

    _cmdline_ = "patch"
    _syntax_  = ("{0:s} (qword|dword|word|byte) LOCATION VALUES\n"
                 "{0:s} string LOCATION \"double-escaped string\"".format(_cmdline_))
    SUPPORTED_SIZES = {
        "qword": (8, "Q"),
        "dword": (4, "L"),
        "word": (2, "H"),
        "byte": (1, "B"),
    }

    def __init__(self):
        super(PatchCommand, self).__init__(complete=gdb.COMPLETE_LOCATION, prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc < 3:
            self.usage()
            return

        fmt, location, values = argv[0].lower(), argv[1], argv[2:]
        if fmt not in self.SUPPORTED_SIZES:
            self.usage()
            return

        addr = align_address(long(gdb.parse_and_eval(location)))
        size, fcode = self.SUPPORTED_SIZES[fmt]

        d = "<" if is_little_endian() else ">"
        for value in values:
            value = parse_address(value) & ((1 << size * 8) - 1)
            vstr = struct.pack(d + fcode, value)
            write_memory(addr, vstr, length=size)
            addr += size

        return

#THIS WORKS ON WINDOWS
@register_command
class PatchStringCommand(GenericCommand):
    """Write specified string to the specified memory location pointed by ADDRESS."""

    _cmdline_ = "patch string"
    _syntax_  = "{:s} ADDRESS \"double backslash-escaped string\"".format(_cmdline_)
    _example_ = "{:s} $sp \"GEFROCKS\"".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc != 2:
            self.usage()
            return

        location, s = argv[0:2]
        addr = align_address(long(gdb.parse_and_eval(location)))

        try:
            s = codecs.escape_decode(s)[0]
        except binascii.Error:
            gef_print("Could not decode '\\xXX' encoded string \"{}\"".format(s))
            return

        write_memory(addr, s, len(s))
        return


#THIS WORKS ON WINDOWS
@register_command
class ASLRCommand(GenericCommand):
    """View/modify the ASLR setting of GDB. By default, GDB will disable ASLR when it starts the process. (i.e. not
    attached). This command allows to change that setting."""

    _cmdline_ = "aslr"
    _syntax_  = "{:s} (on|off)".format(_cmdline_)

    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True)
            i = ret.find("virtual address space is ")
            if i < 0:
                return

            msg = "ASLR is currently "
            if ret[i + 25:].strip() == "on.":
                msg += Color.redify("disabled")
            else:
                msg += Color.greenify("enabled")

            gef_print(msg)
            return

        elif argc == 1:
            if argv[0] == "on":
                info("Enabling ASLR")
                gdb.execute("set disable-randomization off")
                return
            elif argv[0] == "off":
                info("Disabling ASLR")
                gdb.execute("set disable-randomization on")
                return

            warn("Invalid command")

        self.usage()
        return


#THIS WORKS ON WINDOWS
@register_command
class VMMapCommand(GenericCommand):
    """Display a comprehensive layout of the virtual memory mapping. If a filter argument, GEF will
    filter out the mapping whose pathname do not match that filter."""

    _cmdline_ = "vmmap"
    _syntax_  = "{:s} [FILTER]".format(_cmdline_)
    _example_ = "{:s} libc".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        vmmap = get_process_maps()
        if not vmmap:
            err("No address mapping information found")
            return

        if not get_gef_setting("gef.disable_color"):
            self.show_legend()

        color = get_gef_setting("theme.table_heading")

        headers = ["Start", "End", "Offset", "Perm", "Path"]
        gef_print(Color.colorify("{:<{w}s}{:<{w}s}{:<{w}s}{:<4s} {:s}".format(*headers, w=get_memory_alignment()*2+3), color))

        for entry in vmmap:
            if argv and not argv[0] in entry.path:
                continue

            self.print_entry(entry)
        return

    def print_entry(self, entry):
        line_color = ""
        if entry.path == "[stack]":
            line_color = get_gef_setting("theme.address_stack")
        elif entry.path == "[heap]":
            line_color = get_gef_setting("theme.address_heap")
        elif entry.permission.value & Permission.READ and entry.permission.value & Permission.EXECUTE:
            line_color = get_gef_setting("theme.address_code")

        l = []
        l.append(Color.colorify(format_address(entry.page_start), line_color))
        l.append(Color.colorify(format_address(entry.page_end), line_color))
        l.append(Color.colorify(format_address(entry.offset), line_color))

        if entry.permission.value == (Permission.READ|Permission.WRITE|Permission.EXECUTE):
            l.append(Color.colorify(str(entry.permission), "underline " + line_color))
        else:
            l.append(Color.colorify(str(entry.permission), line_color))

        l.append(Color.colorify(entry.path, line_color))
        line = " ".join(l)

        gef_print(line)
        return

    def show_legend(self):
        code_addr_color = get_gef_setting("theme.address_code")
        stack_addr_color = get_gef_setting("theme.address_stack")
        heap_addr_color = get_gef_setting("theme.address_heap")

        gef_print("[ Legend:  {} | {} | {} ]".format(Color.colorify("Code", code_addr_color),
                                                     Color.colorify("Heap", heap_addr_color),
                                                     Color.colorify("Stack", stack_addr_color)
        ))
        return


#THIS WORKS ON WINDOWS
@register_command
class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary. This command extends the GDB command
    `info files`, by retrieving more information from extra sources, and providing a better
    display. If an argument FILE is given, the output will grep information related to only that file.
    If an argument name is also given, the output will grep to the name within FILE."""

    _cmdline_ = "xfiles"
    _syntax_  = "{:s} [FILE [NAME]]".format(_cmdline_)
    _example_ = "\n{0:s} libc\n{0:s} libc IO_vtables".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        color = get_gef_setting("theme.table_heading")
        headers = ["Start", "End", "Name", "File"]
        gef_print(Color.colorify("{:<{w}s}{:<{w}s}{:<21s} {:s}".format(*headers, w=get_memory_alignment()*2+3), color))

        filter_by_file = argv[0] if argv and argv[0] else None
        filter_by_name = argv[1] if len(argv) > 1 and argv[1] else None

        for xfile in get_info_files():
            if filter_by_file:
                if filter_by_file not in xfile.filename:
                    continue
                if filter_by_name and filter_by_name not in xfile.name:
                    continue

            l = []
            l.append(format_address(xfile.zone_start))
            l.append(format_address(xfile.zone_end))
            l.append("{:<21s}".format(xfile.name))
            l.append(xfile.filename)
            gef_print(" ".join(l))
        return



#THIS WORKS ON WINDOWS
@register_command
class PatternCommand(GenericCommand):
    """This command will create or search a De Bruijn cyclic pattern to facilitate
    determining the offset in memory. The algorithm used is the same as the one
    used by pwntools, and can therefore be used in conjunction."""

    _cmdline_ = "pattern"
    _syntax_  = "{:s} (create|search) ARGS".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(PatternCommand, self).__init__(prefix=True)
        self.add_setting("length", 1024, "Initial length of a cyclic buffer to generate")
        return

    def do_invoke(self, argv):
        self.usage()
        return

#THIS WORKS ON WINDOWS
@register_command
class PatternCreateCommand(GenericCommand):
    """Generate a de Bruijn cyclic pattern. It will generate a pattern long of SIZE,
    incrementally varying of one byte at each generation. The length of each block is
    equal to sizeof(void*).
    Note: This algorithm is the same than the one used by pwntools library."""

    _cmdline_ = "pattern create"
    _syntax_  = "{:s} [SIZE]".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) == 1:
            if not argv[0].isdigit():
                err("Invalid size")
                return
            set_gef_setting("pattern.length", long(argv[0]))
        elif len(argv) > 1:
            err("Invalid syntax")
            return

        size = get_gef_setting("pattern.length")
        info("Generating a pattern of {:d} bytes".format(size))
        pattern_str = gef_pystring(generate_cyclic_pattern(size))
        gef_print(pattern_str)
        ok("Saved as '{:s}'".format(gef_convenience(pattern_str)))
        return

#THIS WORKS ON WINDOWS
@register_command
class PatternSearchCommand(GenericCommand):
    """Search for the cyclic de Bruijn pattern generated by the `pattern create` command. The
    PATTERN argument can be a GDB symbol (such as a register name) or an hexadecimal value."""

    _cmdline_ = "pattern search"
    _syntax_  = "{:s} PATTERN [SIZE]".format(_cmdline_)
    _example_ = "\n{0:s} $pc\n{0:s} 0x61616164\n{0:s} aaab".format(_cmdline_)
    _aliases_ = ["pattern offset",]

    @only_if_gdb_running
    def do_invoke(self, argv):
        argc = len(argv)
        if argc not in (1, 2):
            self.usage()
            return

        if argc==2:
            if not argv[1].isdigit():
                err("Invalid size")
                return
            size = long(argv[1])
        else:
            size = get_gef_setting("pattern.length")

        pattern = argv[0]
        info("Searching '{:s}'".format(pattern))
        self.search(pattern, size)
        return

    def search(self, pattern, size):
        pattern_be, pattern_le = None, None

        # 1. check if it's a symbol (like "$sp" or "0x1337")
        symbol = safe_parse_and_eval(pattern)
        if symbol:
            addr = long(symbol)
            dereferenced_value = dereference(addr)
            # 1-bis. try to dereference
            if dereferenced_value:
                addr = long(dereferenced_value)

            if current_arch.ptrsize == 4:
                pattern_be = struct.pack(">I", addr)
                pattern_le = struct.pack("<I", addr)
            else:
                pattern_be = struct.pack(">Q", addr)
                pattern_le = struct.pack("<Q", addr)

        else:
            # 2. assume it's a plain string
            pattern_be = pattern
            pattern_le = pattern[::-1]


        cyclic_pattern = generate_cyclic_pattern(size)
        found = False
        off = cyclic_pattern.find(pattern_le)
        if off >= 0:
            ok("Found at offset {:d} (little-endian search) {:s}".format(off, Color.colorify("likely", "bold red") if is_little_endian() else ""))
            found = True

        off = cyclic_pattern.find(pattern_be)
        if off >= 0:
            ok("Found at offset {:d} (big-endian search) {:s}".format(off, Color.colorify("likely", "bold green") if is_big_endian() else ""))
            found = True

        if not found:
            err("Pattern '{}' not found".format(pattern))
        return



#THIS WORKS ON WINDOWS
@register_command
class ShellcodeCommand(GenericCommand):
    """ShellcodeCommand uses @JonathanSalwan simple-yet-awesome shellcode API to
    download shellcodes."""

    _cmdline_ = "shellcode"
    _syntax_  = "{:s} (search|get)".format(_cmdline_)

    def __init__(self):
        super(ShellcodeCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        err("Missing sub-command (search|get)")
        self.usage()
        return


#THIS WORKS ON WINDOWS
@register_command
class ShellcodeSearchCommand(GenericCommand):
    """Search pattern in shell-storm's shellcode database."""

    _cmdline_ = "shellcode search"
    _syntax_  = "{:s} PATTERN1 PATTERN2".format(_cmdline_)
    _aliases_ = ["sc-search",]

    api_base = "http://shell-storm.org"
    search_url = "{}/api/?s=".format(api_base)


    def do_invoke(self, argv):
        if not argv:
            err("Missing pattern to search")
            self.usage()
            return

        self.search_shellcode(argv)
        return


    def search_shellcode(self, search_options):
        # API : http://shell-storm.org/shellcode/
        args = "*".join(search_options)

        res = http_get(self.search_url + args)
        if res is None:
            err("Could not query search page")
            return

        ret = gef_pystring(res)

        # format: [author, OS/arch, cmd, id, link]
        lines = ret.split("\\n")
        refs = [line.split("::::") for line in lines]

        if refs:
            info("Showing matching shellcodes")
            info("\t".join(["Id", "Platform", "Description"]))
            for ref in refs:
                try:
                    _, arch, cmd, sid, _ = ref
                    gef_print("\t".join([sid, arch, cmd]))
                except ValueError:
                    continue

            info("Use `shellcode get <id>` to fetch shellcode")
        return



#THIS WORKS ON WINDOWS


########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################



#MIGHT WORK ON WINDOWS
@register_command
class PCustomCommand(GenericCommand):
    """Dump user defined structure.
    This command attempts to reproduce WinDBG awesome `dt` command for GDB and allows
    to apply structures (from symbols or custom) directly to an address.
    Custom structures can be defined in pure Python using ctypes, and should be stored
    in a specific directory, whose path must be stored in the `pcustom.struct_path`
    configuration setting."""

    _cmdline_ = "pcustom"
    _syntax_  = "{:s} [-l] [StructA [0xADDRESS] [-e]]".format(_cmdline_)

    def __init__(self):
        super(PCustomCommand, self).__init__(complete=gdb.COMPLETE_SYMBOL)
        self.add_setting("struct_path", os.path.join(GEF_TEMP_DIR, "structs"),
                         "Path to store/load the structure ctypes files")
        return

    def do_invoke(self, argv):
        argc = len(argv)
        if argc == 0:
            self.usage()
            return

        if argv[0] == "-l":
            self.list_custom_structures()
            return

        modname, structname = argv[0].split(":", 1) if ":" in argv[0] else (argv[0], argv[0])
        structname = structname.split(".", 1)[0] if "." in structname else structname

        if argc == 1:
            self.dump_structure(modname, structname)
            return

        if argv[1] == "-e":
            self.create_or_edit_structure(modname, structname)
            return

        if not is_alive():
            return

        try:
            address = long(gdb.parse_and_eval(argv[1]))
        except gdb.error:
            err("Failed to parse '{:s}'".format(argv[1]))
            return

        self.apply_structure_to_address(modname, structname, address)
        return


    def get_struct_path(self):
        path = os.path.expanduser(self.get_setting("struct_path"))
        path = os.path.realpath(path)
        return path if os.path.isdir(path) else None


    def pcustom_filepath(self, x):
        p = self.get_struct_path()
        if not p: return None
        return os.path.join(p, "{}.py".format(x))


    def is_valid_struct(self, x):
        p = self.pcustom_filepath(x)
        return os.access(p, os.R_OK) if p else None


    def dump_structure(self, mod_name, struct_name):
        # If it's a builtin or defined in the ELF use gdb's `ptype`
        try:
            gdb.execute("ptype struct {:s}".format(struct_name))
            return
        except gdb.error:
            pass

        self.dump_custom_structure(mod_name, struct_name)
        return


    def dump_custom_structure(self, mod_name, struct_name):
        if not self.is_valid_struct(mod_name):
            err("Invalid structure name '{:s}'".format(struct_name))
            return

        _class, _struct = self.get_structure_class(mod_name, struct_name)

        for _name, _type in _struct._fields_:
            _size = ctypes.sizeof(_type)
            gef_print("+{:04x} {:s} {:s} ({:#x})".format(getattr(_class, _name).offset, _name, _type.__name__, _size))
        return


    def deserialize(self, struct, data):
        length = min(len(data), ctypes.sizeof(struct))
        ctypes.memmove(ctypes.addressof(struct), data, length)
        return


    def get_module(self, modname):
        _fullname = self.pcustom_filepath(modname)
        return imp.load_source(modname, _fullname)


    def get_structure_class(self, modname, classname):
        _mod = self.get_module(modname)
        _class = getattr(_mod, classname)
        return _class, _class()

    def list_all_structs(self, modname):
        _mod = self.get_module(modname)
        _invalid = set(["BigEndianStructure", "LittleEndianStructure", "Structure"])
        _structs = set([x for x in dir(_mod) \
                         if inspect.isclass(getattr(_mod, x)) \
                         and issubclass(getattr(_mod, x), ctypes.Structure)])
        return _structs - _invalid


    def apply_structure_to_address(self, mod_name, struct_name, addr, depth=0):
        if not self.is_valid_struct(mod_name):
            err("Invalid structure name '{:s}'".format(struct_name))
            return

        try:
            _class, _struct = self.get_structure_class(mod_name, struct_name)
            data = read_memory(addr, ctypes.sizeof(_struct))
        except gdb.MemoryError:
            err("{}Cannot reach memory {:#x}".format(" "*depth, addr))
            return

        self.deserialize(_struct, data)

        _regsize = get_memory_alignment()

        for field in _struct._fields_:
            _name, _type = field
            _value = getattr(_struct, _name)
            _offset = getattr(_class, _name).offset

            if    (_regsize == 4 and _type is ctypes.c_uint32) \
               or (_regsize == 8 and _type is ctypes.c_uint64) \
               or (_regsize == ctypes.sizeof(ctypes.c_void_p) and _type is ctypes.c_void_p):
                # try to dereference pointers
                _value = RIGHT_ARROW.join(DereferenceCommand.dereference_from(_value))

            line = []
            line += "  "*depth
            line += ("{:#x}+0x{:04x} {} : ".format(addr, _offset, _name)).ljust(40)
            line += "{} ({})".format(_value, _type.__name__)
            parsed_value = self.get_ctypes_value(_struct, _name, _value)
            if parsed_value:
                line += " {} {}".format(RIGHT_ARROW, parsed_value)
            gef_print("".join(line))

            if issubclass(_type, ctypes.Structure):
                self.apply_structure_to_address(mod_name, _type.__name__, addr + _offset, depth + 1)
        return


    def get_ctypes_value(self, struct, item, value):
        if not hasattr(struct, "_values_"): return ""
        values_list = getattr(struct, "_values_")
        default = ""
        for name, values in values_list:
            if name != item: continue
            if callable(values):
                return values(value)
            try:
                for val, desc in values:
                    if value == val: return desc
                    if val is None: default = desc
            except:
                err("Error while trying to obtain values from _values_[\"{}\"]".format(name))

        return default


    def create_or_edit_structure(self, mod_name, struct_name):
        path = self.get_struct_path()
        if path is None:
            err("Invalid struct path")
            return

        fullname = self.pcustom_filepath(mod_name)
        if not self.is_valid_struct(mod_name):
            info("Creating '{:s}' from template".format(fullname))
            with open(fullname, "w") as f:
                f.write(self.get_template(struct_name))
                f.flush()
        else:
            info("Editing '{:s}'".format(fullname))

        cmd = os.getenv("EDITOR").split() if os.getenv("EDITOR") else ["nano",]
        cmd.append(fullname)
        retcode = subprocess.call(cmd)
        return retcode


    def get_template(self, structname):
        d = [
            "from ctypes import *\n\n",
            "class ", structname, "(Structure):\n",
            "    _fields_ = []\n"
        ]
        return "".join(d)


    def list_custom_structures(self):
        path = self.get_struct_path()
        if path is None:
            err("Cannot open '{0}': check directory and/or `gef config {0}` "
                "setting, currently: '{1}'".format("pcustom.struct_path", self.get_setting("struct_path")))
            return

        info("Listing custom structures from '{:s}'".format(path))
        for filen in os.listdir(path):
            name, ext = os.path.splitext(filen)
            if ext != ".py": continue
            _modz = self.list_all_structs(name)
            ok("{:s} {:s} ({:s})".format(RIGHT_ARROW, name, ", ".join(_modz)))
        return

#MIGHT WORK, BUT MAY BE UNNECESSARY
@register_command
class ChangeFdCommand(GenericCommand):
    """ChangeFdCommand: redirect file descriptor during runtime."""

    _cmdline_ = "hijack-fd"
    _syntax_  = "{:s} FD_NUM NEW_OUTPUT".format(_cmdline_)
    _example_ = "{:s} 2 /tmp/stderr_output.txt".format(_cmdline_)

    @only_if_gdb_running
    @only_if_gdb_target_local
    def do_invoke(self, argv):
        if len(argv)!=2:
            self.usage()
            return

        if not os.access("/proc/{:d}/fd/{:s}".format(get_pid(), argv[0]), os.R_OK):
            self.usage()
            return

        old_fd = int(argv[0])
        new_output = argv[1]

        if ":" in new_output:
            address = socket.gethostbyname(new_output.split(":")[0])
            port = int(new_output.split(":")[1])

            AF_INET = 2
            SOCK_STREAM = 1
            res = gdb.execute("""call (int)socket({}, {}, 0)""".format(AF_INET, SOCK_STREAM), to_string=True)
            new_fd = self.get_fd_from_result(res)

            # fill in memory with sockaddr_in struct contents
            # we will do this in the stack, since connect() wants a pointer to a struct
            vmmap = get_process_maps()
            stack_addr = [entry.page_start for entry in vmmap if entry.path == "[stack]"][0]
            original_contents = read_memory(stack_addr, 8)

            write_memory(stack_addr, "\x02\x00", 2)
            write_memory(stack_addr + 0x2, struct.pack("<H", socket.htons(port)), 2)
            write_memory(stack_addr + 0x4, socket.inet_aton(address), 4)

            info("Trying to connect to {}".format(new_output))
            res = gdb.execute("""call (int)connect({}, {}, {})""".format(new_fd, stack_addr, 16), to_string=True)

            # recover stack state
            write_memory(stack_addr, original_contents, 8)

            res = self.get_fd_from_result(res)
            if res == -1:
                err("Failed to connect to {}:{}".format(address, port))
                return

            info("Connected to {}".format(new_output))
        else:
            res = gdb.execute("""call (int)open("{:s}", 66, 0666)""".format(new_output), to_string=True)
            new_fd = self.get_fd_from_result(res)

        info("Opened '{:s}' as fd #{:d}".format(new_output, new_fd))
        gdb.execute("""call (int)dup2({:d}, {:d})""".format(new_fd, old_fd), to_string=True)
        info("Duplicated fd #{:d}{:s}#{:d}".format(new_fd, RIGHT_ARROW, old_fd))
        gdb.execute("""call (int)close({:d})""".format(new_fd), to_string=True)
        info("Closed extra fd #{:d}".format(new_fd))
        ok("Success")
        return

    def get_fd_from_result(self, res):
        # Output example: $1 = 3
        res = int(res.split()[2], 0)
        res = gdb.execute("""p/d {}""".format(res), to_string=True)
        res = int(res.split()[2], 0)
        return res

#I THINK THIS WORKS ON WINDOWS
@register_command
class IdaInteractCommand(GenericCommand):
    """IDA Interact: set of commands to interact with IDA via a XML RPC service
    deployed via the IDA script `ida_gef.py`. It should be noted that this command
    can also be used to interact with Binary Ninja (using the script `binja_gef.py`)
    using the same interface."""

    _cmdline_ = "ida-interact"
    _syntax_  = "{:s} METHOD [ARGS]".format(_cmdline_)
    _aliases_ = ["binaryninja-interact", "bn", "binja"]
    _example_ = "\n{0:s} Jump $pc\n{0:s} SetColor $pc ff00ff".format(_cmdline_)

    def __init__(self):
        super(IdaInteractCommand, self).__init__(prefix=False)
        host, port = "127.0.0.1", 1337
        self.add_setting("host", host, "IP address to use connect to IDA/Binary Ninja script")
        self.add_setting("port", port, "Port to use connect to IDA/Binary Ninja script")
        self.add_setting("sync_cursor", False, "Enable real-time $pc synchronisation")

        self.sock = None
        self.version = ("", "")
        self.old_bps = set()
        return

    def is_target_alive(self, host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, port))
            s.close()
        except socket.error:
            return False
        return True

    def connect(self, host=None, port=None):
        """Connect to the XML-RPC service."""
        host = host or self.get_setting("host")
        port = port or self.get_setting("port")

        try:
            sock = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(host, port))
            gef_on_stop_hook(ida_synchronize_handler)
            gef_on_continue_hook(ida_synchronize_handler)
            self.version = sock.version()
        except ConnectionRefusedError:
            err("Failed to connect to '{:s}:{:d}'".format(host, port))
            sock = None
        self.sock = sock
        return

    def disconnect(self):
        gef_on_stop_unhook(ida_synchronize_handler)
        gef_on_continue_unhook(ida_synchronize_handler)
        self.sock = None
        return

    def do_invoke(self, argv):
        def parsed_arglist(arglist):
            args = []
            for arg in arglist:
                try:
                    # try to solve the argument using gdb
                    argval = gdb.parse_and_eval(arg)
                    argval.fetch_lazy()
                    # check if value is addressable
                    argval = long(argval) if argval.address is None else long(argval.address)
                    # if the bin is PIE, we need to substract the base address
                    is_pie = checksec(get_filepath())["PIE"]
                    if is_pie and main_base_address <= argval < main_end_address:
                        argval -= main_base_address
                    args.append("{:#x}".format(argval,))
                except Exception:
                    # if gdb can't parse the value, let ida deal with it
                    args.append(arg)
            return args

        if self.sock is None:
            # trying to reconnect
            self.connect()
            if self.sock is None:
                self.disconnect()
                return

        if len(argv) == 0 or argv[0] in ("-h", "--help"):
            method_name = argv[1] if len(argv)>1 else None
            self.usage(method_name)
            return

        method_name = argv[0].lower()
        if method_name == "version":
            self.version = self.sock.version()
            info("Enhancing {:s} with {:s} (v.{:s})".format(Color.greenify("gef"),
                                                            Color.redify(self.version[0]),
                                                            Color.yellowify(self.version[1])))
            return

        if not is_alive():
            main_base_address = main_end_address = 0
        else:
            vmmap = get_process_maps()
            main_base_address = min([x.page_start for x in vmmap if x.realpath == get_filepath()])
            main_end_address = max([x.page_end for x in vmmap if x.realpath == get_filepath()])

        try:
            if method_name == "sync":
                self.synchronize()
            else:
                method = getattr(self.sock, method_name)
                if len(argv) > 1:
                    args = parsed_arglist(argv[1:])
                    res = method(*args)
                else:
                    res = method()

                if method_name == "importstruct":
                    self.import_structures(res)
                else:
                    gef_print(str(res))

            if self.get_setting("sync_cursor") is True:
                jump = getattr(self.sock, "Jump")
                jump(hex(current_arch.pc-main_base_address),)

        except socket.error:
            self.disconnect()
        return


    def synchronize(self):
        """Submit all active breakpoint addresses to IDA/BN."""
        pc = current_arch.pc
        vmmap = get_process_maps()
        base_address = min([x.page_start for x in vmmap if x.path == get_filepath()])
        end_address = max([x.page_end for x in vmmap if x.path == get_filepath()])
        if not (base_address <= pc < end_address):
            # do not sync in library
            return

        breakpoints = gdb.breakpoints() or []
        gdb_bps = set()
        for bp in breakpoints:
            if bp.enabled and not bp.temporary:
                if bp.location[0]=="*": # if it's an address i.e. location starts with "*"
                    addr = long(gdb.parse_and_eval(bp.location[1:]))
                else: # it is a symbol
                    addr = long(gdb.parse_and_eval(bp.location).address)
                if not (base_address <= addr < end_address):
                    continue
                gdb_bps.add(addr-base_address)

        added = gdb_bps - self.old_bps
        removed = self.old_bps - gdb_bps
        self.old_bps = gdb_bps

        try:
            # it is possible that the server was stopped between now and the last sync
            rc = self.sock.Sync("{:#x}".format(pc-base_address), list(added), list(removed))
        except ConnectionRefusedError:
            self.disconnect()
            return

        ida_added, ida_removed = rc

        # add new bp from IDA
        for new_bp in ida_added:
            location = base_address+new_bp
            gdb.Breakpoint("*{:#x}".format(location), type=gdb.BP_BREAKPOINT)
            self.old_bps.add(location)

        # and remove the old ones
        breakpoints = gdb.breakpoints() or []
        for bp in breakpoints:
            if bp.enabled and not bp.temporary:
                if bp.location[0]=="*": # if it's an address i.e. location starts with "*"
                    addr = long(gdb.parse_and_eval(bp.location[1:]))
                else: # it is a symbol
                    addr = long(gdb.parse_and_eval(bp.location).address)

                if not (base_address <= addr < end_address):
                    continue

                if (addr-base_address) in ida_removed:
                    if (addr-base_address) in self.old_bps:
                        self.old_bps.remove((addr-base_address))
                    bp.delete()
        return


    def usage(self, meth=None):
        if self.sock is None:
            return

        if meth is not None:
            gef_print(titlify(meth))
            gef_print(self.sock.system.methodHelp(meth))
            return

        info("Listing available methods and syntax examples: ")
        for m in self.sock.system.listMethods():
            if m.startswith("system."): continue
            gef_print(titlify(m))
            gef_print(self.sock.system.methodHelp(m))
        return


    def import_structures(self, structs):
        if self.version[0] != "IDA Pro":
            return

        path = get_gef_setting("pcustom.struct_path")
        if path is None:
            return

        if not os.path.isdir(path):
            gef_makedirs(path)

        for struct_name in structs:
            fullpath = os.path.join(path, "{}.py".format(struct_name))
            with open(fullpath, "w") as f:
                f.write("from ctypes import *\n\n")
                f.write("class ")
                f.write(struct_name)
                f.write("(Structure):\n")
                f.write("    _fields_ = [\n")
                for _, name, size in structs[struct_name]:
                    name = bytes(name, encoding="utf-8")
                    if   size == 1: csize = "c_uint8"
                    elif size == 2: csize = "c_uint16"
                    elif size == 4: csize = "c_uint32"
                    elif size == 8: csize = "c_uint64"
                    else:           csize = "c_byte * {}".format(size)
                    m = '        (\"{}\", {}),\n'.format(name, csize)
                    f.write(m)
                f.write("]\n")
        ok("Success, {:d} structure{:s} imported".format(len(structs),
                                                         "s" if len(structs)>1 else ""))
        return




#THIS MIGHT WORK ON WINDOWS
@register_command
class SyscallArgsCommand(GenericCommand):
    """Gets the syscall name and arguments based on the register values in the current state."""
    _cmdline_ = "syscall-args"
    _syntax_ = _cmdline_

    def __init__(self):
        super(SyscallArgsCommand, self).__init__()
        self.add_setting("path", os.path.join(GEF_TEMP_DIR, "syscall-tables"),
                         "Path to store/load the syscall tables files")
        return

    def do_invoke(self, argv):
        color = get_gef_setting("theme.table_heading")

        path = self.get_settings_path()
        if path is None:
            err("Cannot open '{0}': check directory and/or `gef config {0}` setting, "
                "currently: '{1}'".format("syscall-args.path", self.get_setting("path")))
            return

        arch = current_arch.__class__.__name__
        syscall_table = self.get_syscall_table(arch)

        reg_value = get_register(current_arch.syscall_register)
        if reg_value not in syscall_table:
            warn("There is no system call for {:#x}".format(reg_value))
            return
        syscall_entry = syscall_table[reg_value]

        values = []
        for param in syscall_entry.params:
            values.append(get_register(param.reg))

        parameters = [s.param for s in syscall_entry.params]
        registers = [s.reg for s in syscall_entry.params]

        info("Detected syscall {}".format(Color.colorify(syscall_entry.name, color)))
        gef_print("    {}({})".format(syscall_entry.name, ", ".join(parameters)))

        headers = ["Parameter", "Register", "Value"]
        param_names = [re.split(r" |\*", p)[-1] for p in parameters]
        info(Color.colorify("{:<28} {:<28} {}".format(*headers), color))
        for name, register, value in zip(param_names, registers, values):
            line = "    {:<15} {:<15} 0x{:x}".format(name, register, value)

            addrs = DereferenceCommand.dereference_from(value)

            if len(addrs) > 1:
                sep = " {:s} ".format(RIGHT_ARROW)
                line += sep
                line += sep.join(addrs[1:])

            gef_print(line)

        return

    def get_filepath(self, x):
        p = self.get_settings_path()
        if not p: return None
        return os.path.join(p, "{}.py".format(x))

    def get_module(self, modname):
        _fullname = self.get_filepath(modname)
        return imp.load_source(modname, _fullname)

    def get_syscall_table(self, modname):
        _mod = self.get_module(modname)
        return getattr(_mod, "syscall_table")

    def get_settings_path(self):
        path = os.path.expanduser(self.get_setting("path"))
        path = os.path.realpath(path)
        return path if os.path.isdir(path) else None



#THIS MIGHT WORK ON WINDOWS
@register_command
class HighlightCommand(GenericCommand):
    """
    This command highlights user defined text matches which modifies GEF output universally.
    """
    _cmdline_ = "highlight"
    _syntax_ = "{} (add|remove|list|clear)".format(_cmdline_)
    _aliases_ = ["hl"]

    def __init__(self):
        super(HighlightCommand, self).__init__(prefix=True)
        self.add_setting("regex", False, "Enable regex highlighting")

    def do_invoke(self, argv):
        return self.usage()

#THIS MIGHT WORK ON WINDOWS
@register_command
class HighlightListCommand(GenericCommand):
    """Show the current highlight table with matches to colors."""
    _cmdline_ = "highlight list"
    _aliases_ = ["highlight ls", "hll"]
    _syntax_ = _cmdline_

    def print_highlight_table(self):
        if not highlight_table:
            return err("no matches found")

        left_pad = max(map(len, highlight_table.keys()))
        for match, color in sorted(highlight_table.items()):
            print("{} | {}".format(Color.colorify(match.ljust(left_pad), color),
                                   Color.colorify(color, color)))
        return

    def do_invoke(self, argv):
        return self.print_highlight_table()

#THIS MIGHT WORK ON WINDOWS
@register_command
class HighlightClearCommand(GenericCommand):
    """Clear the highlight table, remove all matches."""
    _cmdline_ = "highlight clear"
    _aliases_ = ["hlc"]
    _syntax_ = _cmdline_

    def do_invoke(self, argv):
        return highlight_table.clear()

#THIS MIGHT WORK ON WINDOWS
@register_command
class HighlightAddCommand(GenericCommand):
    """Add a match to the highlight table."""
    _cmdline_ = "highlight add"
    _syntax_ = "{} MATCH COLOR".format(_cmdline_)
    _aliases_ = ["highlight set", "hla"]
    _example_ = "{} 41414141 yellow".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) < 2:
            return self.usage()

        match, color = argv
        highlight_table[match] = color
        return

#THIS MIGHT WORK ON WINDOWS
@register_command
class HighlightRemoveCommand(GenericCommand):
    """Remove a match in the highlight table."""
    _cmdline_ = "highlight remove"
    _syntax_ = "{} MATCH".format(_cmdline_)
    _aliases_ = [
        "highlight delete",
        "highlight del",
        "highlight unset",
        "highlight rm",
        "hlr"
    ]
    _example_ = "{} remove 41414141".format(_cmdline_)

    def do_invoke(self, argv):
        if not argv:
            return self.usage()

        highlight_table.pop(argv[0], None)
        return


#I THINK THIS WORKS ON WINDOWS
@register_command
class ShellcodeGetCommand(GenericCommand):
    """Download shellcode from shell-storm's shellcode database."""

    _cmdline_ = "shellcode get"
    _syntax_  = "{:s} SHELLCODE_ID".format(_cmdline_)
    _aliases_ = ["sc-get",]

    api_base = "http://shell-storm.org"
    get_url = "{}/shellcode/files/shellcode-{{:d}}.php".format(api_base)

    def do_invoke(self, argv):
        if len(argv) != 1:
            err("Missing ID to download")
            self.usage()
            return

        if not argv[0].isdigit():
            err("ID is not a number")
            self.usage()
            return

        self.get_shellcode(long(argv[0]))
        return

    def get_shellcode(self, sid):
        res = http_get(self.get_url.format(sid))
        if res is None:
            err("Failed to fetch shellcode #{:d}".format(sid))
            return

        ret  = gef_pystring(res)

        info("Downloading shellcode id={:d}".format(sid))
        fd, fname = tempfile.mkstemp(suffix=".txt", prefix="sc-", text=True, dir="/tmp")
        data = ret.split("\\n")[7:-11]
        buf = "\n".join(data)
        buf = HTMLParser().unescape(buf)
        os.write(fd, buf)
        os.close(fd)
        info("Shellcode written to '{:s}'".format(fname))
        return


#I THINK THIS WORKS ON WINDOWS
@register_command
class ProcessListingCommand(GenericCommand):
    """List and filter process. If a PATTERN is given as argument, results shown will be grepped
    by this pattern."""

    _cmdline_ = "process-search"
    _syntax_  = "{:s} [PATTERN]".format(_cmdline_)
    _aliases_ = ["ps",]
    _example_ = "{:s} gdb".format(_cmdline_)

    def __init__(self):
        super(ProcessListingCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("ps_command", "/bin/ps auxww", "`ps` command to get process information")
        return

    def do_invoke(self, argv):
        do_attach = False
        smart_scan = False

        opts, args = getopt.getopt(argv, "as")
        for o, _ in opts:
            if o == "-a": do_attach  = True
            if o == "-s": smart_scan = True

        pattern = re.compile("^.*$") if not args else re.compile(args[0])

        for process in self.get_processes():
            pid = int(process["pid"])
            command = process["command"]

            if not re.search(pattern, command):
                continue

            if smart_scan:
                if command.startswith("[") and command.endswith("]"): continue
                if command.startswith("socat "): continue
                if command.startswith("grep "): continue
                if command.startswith("gdb "): continue

            if args and do_attach:
                ok("Attaching to process='{:s}' pid={:d}".format(process["command"], pid))
                gdb.execute("attach {:d}".format(pid))
                return None

            line = [process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command")]
            gef_print("\t\t".join(line))

        return None


    def get_processes(self):
        output = gef_execute_external(self.get_setting("ps_command").split(), True)
        names = [x.lower().replace("%", "") for x in output[0].split()]

        for line in output[1:]:
            fields = line.split()
            t = {}

            for i, name in enumerate(names):
                if i == len(names) - 1:
                    t[name] = " ".join(fields[i:])
                else:
                    t[name] = fields[i]

            yield t

        return


#I THINK THIS WORKS ON WINDOWS
@register_command
class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data. This command is here for debugging and test purposes, GEF
    handles properly the cache reset under "normal" scenario."""

    _cmdline_ = "reset-cache"
    _syntax_  = _cmdline_

    def do_invoke(self, argv):
        reset_all_caches()
        return



#I THINK THIS WILL WORK ON WINDOWS
@register_command
class XorMemoryCommand(GenericCommand):
    """XOR a block of memory. The command allows to simply display the result, or patch it
    runtime at runtime."""

    _cmdline_ = "xor-memory"
    _syntax_  = "{:s} (display|patch) ADDRESS SIZE KEY".format(_cmdline_)

    def __init__(self):
        super(XorMemoryCommand, self).__init__(prefix=True)
        return

    def do_invoke(self, argv):
        self.usage()
        return

#I THINK THIS WILL WORK ON WINDOWS
@register_command
class XorMemoryDisplayCommand(GenericCommand):
    """Display a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory display"
    _syntax_  = "{:s} ADDRESS SIZE KEY".format(_cmdline_)
    _example_ = "{:s} $sp 16 41414141".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = long(gdb.parse_and_eval(argv[0]))
        length = long(argv[1], 0)
        key = argv[2]
        block = read_memory(address, length)
        info("Displaying XOR-ing {:#x}-{:#x} with {:s}".format(address, address + len(block), repr(key)))

        gef_print(titlify("Original block"))
        gef_print(hexdump(block, base=address))

        gef_print(titlify("XOR-ed block"))
        gef_print(hexdump(xor(block, key), base=address))
        return


#I THINK THIS WILL WORK ON WINDOWS
@register_command
class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory pointed by ADDRESS by xor-ing each byte with KEY. The key must be
    provided in hexadecimal format."""

    _cmdline_ = "xor-memory patch"
    _syntax_  = "{:s} ADDRESS SIZE KEY".format(_cmdline_)
    _example_ = "{:s} $sp 16 41414141".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        if len(argv) != 3:
            self.usage()
            return

        address = parse_address(argv[0])
        length = long(argv[1], 0)
        key = argv[2]
        block = read_memory(address, length)
        info("Patching XOR-ing {:#x}-{:#x} with '{:s}'".format(address, address + len(block), key))
        xored_block = xor(block, key)
        write_memory(address, xored_block, length)
        return


#THIS MIGHT WORK ON WINDOWS
@register_command
class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper: this command will set up specific breakpoints
    at well-known dangerous functions (printf, snprintf, etc.), and check if the pointer
    holding the format string is writable, and therefore susceptible to format string
    attacks if an attacker can control its content."""
    _cmdline_ = "format-string-helper"
    _syntax_ = _cmdline_
    _aliases_ = ["fmtstr-helper",]

    def do_invoke(self, argv):
        dangerous_functions = {
            "printf": 0,
            "sprintf": 1,
            "fprintf": 1,
            "snprintf": 2,
            "vsnprintf": 2,
        }

        enable_redirect_output("/dev/null")

        for func_name, num_arg in dangerous_functions.items():
            FormatStringBreakpoint(func_name, num_arg)

        disable_redirect_output()
        ok("Enabled {:d} FormatStringBreakpoint".format(len(dangerous_functions)))
        return


#I THINK THIS WORKS ON WINDOWS


#######################################################################################
# IT MIGHT WORK, BUT IT MAY NOT BE THE MOST USEFUL ON WINDOWS #########################
#######################################################################################

@register_command
class GlibcHeapCommand(GenericCommand):
    """Base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _syntax_  = "{:s} (chunk|chunks|bins|arenas)".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapCommand, self).__init__(prefix=True)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        self.usage()
        return


@register_command
class GlibcHeapSetArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap set-arena"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)
    _example_ = "{:s} 0x001337001337".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapSetArenaCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        global __gef_default_main_arena__

        if not argv:
            ok("Current main_arena set to: '{}'".format(__gef_default_main_arena__))
            return

        new_arena = safe_parse_and_eval(argv[0])
        if new_arena is None:
            err("Invalid location")
            return

        if argv[0].startswith("0x"):
            new_arena = Address(value=to_unsigned_long(new_arena))
            if new_arena is None or not new_arena.valid:
                err("Invalid location")
                return

            __gef_default_main_arena__ = "*{:s}".format(format_address(new_arena.value))
        else:
            __gef_default_main_arena__ = argv[0]
        return

@register_command
class GlibcHeapArenaCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap arenas"
    _syntax_  = _cmdline_

    @only_if_gdb_running
    def do_invoke(self, argv):
        try:
            arena = GlibcArena(__gef_default_main_arena__)
        except gdb.error:
            err("Could not find Glibc main arena")
            return

        while True:
            gef_print("{}".format(str(arena)))
            arena = arena.get_next()
            if arena is None:
                break
        return

@register_command
class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk.
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _cmdline_ = "heap chunk"
    _syntax_  = "{:s} LOCATION".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunkCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if not argv:
            err("Missing chunk address")
            self.usage()
            return

        if get_main_arena() is None:
            return

        addr = to_unsigned_long(gdb.parse_and_eval(argv[0]))
        chunk = GlibcChunk(addr)
        gef_print(chunk.psprint())
        return

@register_command
class GlibcHeapChunksCommand(GenericCommand):
    """Display information all chunks from main_arena heap. If a location is passed,
    it must correspond to the base address of the first chunk."""

    _cmdline_ = "heap chunks"
    _syntax_  = "{0} [LOCATION]".format(_cmdline_)
    _example_ = "\n{0}\n{0} 0x555555775000".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapChunksCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("peek_nb_byte", 16, "Hexdump N first byte(s) inside the chunk data (0 to disable)")
        return

    @only_if_gdb_running
    def do_invoke(self, argv):

        if not argv:
            heap_section = [x for x in get_process_maps() if x.path == "[heap]"]
            if not heap_section:
                err("No heap section")
                return

            heap_section = heap_section[0].page_start
        else:
            heap_section = int(argv[0], 0)


        arena = get_main_arena()
        if arena is None:
            err("No valid arena")
            return

        nb = self.get_setting("peek_nb_byte")
        current_chunk = GlibcChunk(heap_section, from_base=True)
        while True:

            if current_chunk.chunk_base_address == arena.top:
                gef_print("{} {} {}".format(str(current_chunk), LEFT_ARROW, Color.greenify("top chunk")))
                break

            if current_chunk.chunk_base_address > arena.top:
                break

            if current_chunk.size == 0:
                # EOF
                break

            line = str(current_chunk)
            if nb:
                line += "\n    [" + hexdump(read_memory(current_chunk.address, nb), nb, base=current_chunk.address)  + "]"
            gef_print(line)

            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break

            next_chunk_addr = Address(value=next_chunk.address)
            if not next_chunk_addr.valid:
                # corrupted
                break


            current_chunk = next_chunk
        return

@register_command
class GlibcHeapBinsCommand(GenericCommand):
    """Display information on the bins on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _bin_types_ = ["tcache", "fast", "unsorted", "small", "large"]
    _cmdline_ = "heap bins"
    _syntax_ = "{:s} [{:s}]".format(_cmdline_, "|".join(_bin_types_))

    def __init__(self):
        super(GlibcHeapBinsCommand, self).__init__(prefix=True, complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if not argv:
            for bin_t in GlibcHeapBinsCommand._bin_types_:
                gdb.execute("heap bins {:s}".format(bin_t))
            return

        bin_t = argv[0]
        if bin_t not in GlibcHeapBinsCommand._bin_types_:
            self.usage()
            return

        gdb.execute("heap bins {}".format(bin_t))
        return

    @staticmethod
    def pprint_bin(arena_addr, index, _type=""):
        arena = GlibcArena(arena_addr)
        fw, bk = arena.bin(index)

        if bk==0x00 and fw==0x00:
            warn("Invalid backward and forward bin pointers(fw==bk==NULL)")
            return -1

        nb_chunk = 0
        head = GlibcChunk(bk, from_base=True).fwd
        if fw == head:
            return nb_chunk

        ok("{}bins[{:d}]: fw={:#x}, bk={:#x}".format(_type, index, fw, bk))

        m = []
        while fw != head:
            chunk = GlibcChunk(fw, from_base=True)
            m.append("{:s}  {:s}".format(RIGHT_ARROW, str(chunk)))
            fw = chunk.fwd
            nb_chunk += 1

        if m:
            gef_print("  ".join(m))
        return nb_chunk


@register_command
class GlibcHeapTcachebinsCommand(GenericCommand):
    """Display information on the Tcachebins on an arena (default: main_arena).
    See https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc."""

    _cmdline_ = "heap bins tcache"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapTcachebinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        # Determine if we are using libc with tcache built in (2.26+)
        if get_libc_version() < (2, 26):
            info("No Tcache in this version of libc")
            return

        arena = GlibcArena("*{:s}".format(argv[0])) if len(argv) == 1 else get_main_arena()

        if arena is None:
            err("Invalid Glibc arena")
            return

        # Get tcache_perthread_struct for this arena
        addr = HeapBaseFunction.heap_base() + 0x10

        gef_print(titlify("Tcachebins for arena {:#x}".format(int(arena))))
        for i in range(GlibcArena.TCACHE_MAX_BINS):
            count = ord(read_memory(addr + i, 1))
            chunk = arena.tcachebin(i)
            chunks = set()
            m = []

            # Only print the entry if there are valid chunks. Don't trust count
            while True:
                if chunk is None:
                    break

                try:
                    m.append("{:s} {:s} ".format(LEFT_ARROW, str(chunk)))
                    if chunk.address in chunks:
                        m.append("{:s} [loop detected]".format(RIGHT_ARROW))
                        break

                    chunks.add(chunk.address)

                    next_chunk = chunk.get_fwd_ptr()
                    if next_chunk == 0:
                        break

                    chunk = GlibcChunk(next_chunk)
                except gdb.MemoryError:
                    m.append("{:s} [Corrupted chunk at {:#x}]".format(LEFT_ARROW, chunk.address))
                    break
            if m:
                gef_print("Tcachebins[idx={:d}, size={:#x}] count={:d} ".format(i, (i+1)*(current_arch.ptrsize)*2, count), end="")
                gef_print("".join(m))
        return



@register_command
class GlibcHeapFastbinsYCommand(GenericCommand):
    """Display information on the fastbinsY on an arena (default: main_arena).
    See https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1123."""

    _cmdline_ = "heap bins fast"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapFastbinsYCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        def fastbin_index(sz):
            return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

        SIZE_SZ = current_arch.ptrsize
        MAX_FAST_SIZE = (80 * SIZE_SZ // 4)
        NFASTBINS = fastbin_index(MAX_FAST_SIZE) - 1

        arena = GlibcArena("*{:s}".format(argv[0])) if len(argv) == 1 else get_main_arena()

        if arena is None:
            err("Invalid Glibc arena")
            return

        gef_print(titlify("Fastbins for arena {:#x}".format(int(arena))))
        for i in range(NFASTBINS):
            gef_print("Fastbins[idx={:d}, size={:#x}] ".format(i, (i+1)*SIZE_SZ*2), end="")
            chunk = arena.fastbin(i)
            chunks = set()

            while True:
                if chunk is None:
                    gef_print("0x00", end="")
                    break

                try:
                    gef_print("{:s} {:s} ".format(LEFT_ARROW, str(chunk)), end="")
                    if chunk.address in chunks:
                        gef_print("{:s} [loop detected]".format(RIGHT_ARROW), end="")
                        break

                    if fastbin_index(chunk.get_chunk_size()) != i:
                        gef_print("[incorrect fastbin_index] ", end="")

                    chunks.add(chunk.address)

                    next_chunk = chunk.get_fwd_ptr()
                    if next_chunk == 0:
                        break

                    chunk = GlibcChunk(next_chunk, from_base=True)
                except gdb.MemoryError:
                    gef_print("{:s} [Corrupted chunk at {:#x}]".format(LEFT_ARROW, chunk.address), end="")
                    break
            gef_print()
        return

@register_command
class GlibcHeapUnsortedBinsCommand(GenericCommand):
    """Display information on the Unsorted Bins of an arena (default: main_arena).
    See: https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1689."""

    _cmdline_ = "heap bins unsorted"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapUnsortedBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else __gef_default_main_arena__
        gef_print(titlify("Unsorted Bin for arena '{:s}'".format(arena_addr)))
        nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, 0, "unsorted_")
        if nb_chunk >= 0:
            info("Found {:d} chunks in unsorted bin.".format(nb_chunk))
        return

@register_command
class GlibcHeapSmallBinsCommand(GenericCommand):
    """Convenience command for viewing small bins."""

    _cmdline_ = "heap bins small"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapSmallBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else __gef_default_main_arena__
        gef_print(titlify("Small Bins for arena '{:s}'".format(arena_addr)))
        bins = {}
        for i in range(1, 63):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, i, "small_")
            if nb_chunk < 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info("Found {:d} chunks in {:d} small non-empty bins.".format(sum(bins.values()), len(bins)))
        return

@register_command
class GlibcHeapLargeBinsCommand(GenericCommand):
    """Convenience command for viewing large bins."""

    _cmdline_ = "heap bins large"
    _syntax_  = "{:s} [ARENA_ADDRESS]".format(_cmdline_)

    def __init__(self):
        super(GlibcHeapLargeBinsCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        if get_main_arena() is None:
            err("Invalid Glibc arena")
            return

        arena_addr = "*{:s}".format(argv[0]) if len(argv) == 1 else __gef_default_main_arena__
        gef_print(titlify("Large Bins for arena '{:s}'".format(arena_addr)))
        bins = {}
        for i in range(63, 126):
            nb_chunk = GlibcHeapBinsCommand.pprint_bin(arena_addr, i, "large_")
            if nb_chunk <= 0:
                break
            if nb_chunk > 0:
                bins[i] = nb_chunk
        info("Found {:d} chunks in {:d} large non-empty bins.".format(sum(bins.values()), len(bins)))
        return


#I THINK THIS WORKS ON WINDOWS
@register_command
class RemoteCommand(GenericCommand):
    """gef wrapper for the `target remote` command. This command will automatically
    download the target binary in the local temporary directory (defaut /tmp) and then
    source it. Additionally, it will fetch all the /proc/PID/maps and loads all its
    information."""

    _cmdline_ = "gef-remote"
    _syntax_  = "{:s} [OPTIONS] TARGET".format(_cmdline_)
    _example_  = "\n{0:s} -p 6789 localhost:1234\n{0:s} -q localhost:4444 # when using qemu-user".format(_cmdline_)

    def __init__(self):
        super(RemoteCommand, self).__init__(prefix=False)
        self.handler_connected = False
        self.add_setting("clean_on_exit", False, "Clean the temporary data downloaded when the session exits.")
        return

    def do_invoke(self, argv):
        global __gef_remote__

        if __gef_remote__ is not None:
            err("You already are in remote session. Close it first before opening a new one...")
            return

        target = None
        rpid = -1
        update_solib = False
        self.download_all_libs = False
        download_lib = None
        is_extended_remote = False
        qemu_gdb_mode = False
        opts, args = getopt.getopt(argv, "p:UD:qAEh")
        for o,a in opts:
            if   o == "-U":   update_solib = True
            elif o == "-D":   download_lib = a
            elif o == "-A":   self.download_all_libs = True
            elif o == "-E":   is_extended_remote = True
            elif o == "-p":   rpid = int(a)
            elif o == "-q":   qemu_gdb_mode = True
            elif o == "-h":
                self.help()
                return

        if not args or ":" not in args[0]:
            err("A target (HOST:PORT) must always be provided.")
            return

        if qemu_gdb_mode:
            # compat layer for qemu-user
            self.prepare_qemu_stub(args[0])
            return

        # lazily install handler on first use
        if not self.handler_connected:
            gef_on_new_hook(self.new_objfile_handler)
            self.handler_connected = True

        target = args[0]

        if self.connect_target(target, is_extended_remote) is False:
            return

        # if extended-remote, need to attach
        if is_extended_remote:
            ok("Attaching to {:d}".format(rpid))
            hide_context()
            gdb.execute("attach {:d}".format(rpid))
            unhide_context()
        else:
            rpid = get_pid()
            ok("Targeting PID={:d}".format(rpid))

        self.add_setting("target", target, "Remote target to connect to")
        self.setup_remote_environment(rpid, update_solib)

        if not is_remote_debug():
            err("Failed to establish remote target environment.")
            return

        if self.download_all_libs is True:
            vmmap = get_process_maps()
            success = 0
            for sect in vmmap:
                if sect.path.startswith("/"):
                    _file = download_file(sect.path)
                    if _file is None:
                        err("Failed to download {:s}".format(sect.path))
                    else:
                        success += 1

            ok("Downloaded {:d} files".format(success))

        elif download_lib is not None:
            _file = download_file(download_lib)
            if _file is None:
                err("Failed to download remote file")
                return

            ok("Download success: {:s} {:s} {:s}".format(download_lib, RIGHT_ARROW, _file))

        if update_solib:
            self.refresh_shared_library_path()

        set_arch()
        __gef_remote__ = rpid
        return

    def new_objfile_handler(self, event):
        """Hook that handles new_objfile events, will update remote environment accordingly."""
        if not is_remote_debug():
            return

        if self.download_all_libs and event.new_objfile.filename.startswith("target:"):
            lib = event.new_objfile.filename[len("target:"):]
            llib = download_file(lib, use_cache=True)
            if llib:
                ok("Download success: {:s} {:s} {:s}".format(lib, RIGHT_ARROW, llib))
        return


    def setup_remote_environment(self, pid, update_solib=False):
        """Clone the remote environment locally in the temporary directory.
        The command will duplicate the entries in the /proc/<pid> locally and then
        source those information into the current gdb context to allow gef to use
        all the extra commands as it was local debugging."""
        gdb.execute("reset-cache")

        infos = {}
        for i in ("maps", "environ", "cmdline",):
            infos[i] = self.load_from_remote_proc(pid, i)
            if infos[i] is None:
                err("Failed to load memory map of '{:s}'".format(i))
                return

        exepath = get_path_from_info_proc()
        infos["exe"] = download_file("/proc/{:d}/exe".format(pid), use_cache=False, local_name=exepath)
        if not os.access(infos["exe"], os.R_OK):
            err("Source binary is not readable")
            return

        directory  = os.path.sep.join([GEF_TEMP_DIR, str(get_pid())])
        # gdb.execute("file {:s}".format(infos["exe"]))
        self.add_setting("root", directory, "Path to store the remote data")
        ok("Remote information loaded to temporary path '{:s}'".format(directory))
        return


    def connect_target(self, target, is_extended_remote):
        """Connect to remote target and get symbols. To prevent `gef` from requesting information
        not fetched just yet, we disable the context disable when connection was successful."""
        hide_context()
        try:
            cmd = "target {} {}".format("extended-remote" if is_extended_remote else "remote", target)
            gdb.execute(cmd)
            ok("Connected to '{}'".format(target))
            ret = True
        except Exception as e:
            err("Failed to connect to {:s}: {:s}".format(target, str(e)))
            ret = False
        unhide_context()
        return ret


    def load_from_remote_proc(self, pid, info):
        """Download one item from /proc/pid."""
        remote_name = "/proc/{:d}/{:s}".format(pid, info)
        return download_file(remote_name, use_cache=False)


    def refresh_shared_library_path(self):
        dirs = [r for r, d, f in os.walk(self.get_setting("root"))]
        path = ":".join(dirs)
        gdb.execute("set solib-search-path {:s}".format(path,))
        return


    def help(self):
        h = self._syntax_
        h += "\n\t   TARGET (mandatory) specifies the host:port, serial port or tty to connect to.\n"
        h += "\t-U will update gdb `solib-search-path` attribute to include the files downloaded from server (default: False).\n"
        h += "\t-A will download *ALL* the remote shared libraries and store them in the new environment. " \
             "This command can take a few minutes to complete (default: False).\n"
        h += "\t-D LIB will download the remote library called LIB.\n"
        h += "\t-E Use 'extended-remote' to connect to the target.\n"
        h += "\t-p PID (mandatory if -E is used) specifies PID of the debugged process on gdbserver's end.\n"
        h += "\t-q Uses this option when connecting to a Qemu GDBserver.\n"
        info(h)
        return


    def prepare_qemu_stub(self, target):
        global current_arch, current_elf, __gef_qemu_mode__

        reset_all_caches()
        arch = get_arch()
        current_elf  = Elf(minimalist=True)
        if arch.startswith("i386:intel"):
            current_elf.e_machine = Elf.X86_32
            current_arch = X86()
        elif arch.startswith("i386:x86-64"):
            current_elf.e_machine = Elf.X86_64
            current_elf.e_class = Elf.ELF_64_BITS
            current_arch = X86_64()
        else:
            raise RuntimeError("unsupported architecture: {}".format(arch))

        ok("Setting QEMU-stub for '{}' (memory mapping may be wrong)".format(current_arch.arch))
        gdb.execute("target remote {}".format(target))
        __gef_qemu_mode__ = True
        return


# I THINK THIS WORKS ON WINDOWS


########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################





####################################################################################
#DEREFEREMCE STUFF

#I WANT THIS TO WORK ON WINDOWS
@register_command
class DereferenceCommand(GenericCommand):
    """Dereference recursively from an address and display information. This acts like WinDBG `dps`
    command."""

    _cmdline_ = "dereference"
    _syntax_  = "{:s} [LOCATION] [l[NB]]".format(_cmdline_)
    _aliases_ = ["telescope", ]
    _example_ = "{:s} $sp l20".format(_cmdline_)

    def __init__(self):
        super(DereferenceCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_recursion", 7, "Maximum level of pointer recursion")
        return

    @staticmethod
    def pprint_dereferenced(addr, off):
        base_address_color = get_gef_setting("theme.dereference_base_address")
        registers_color = get_gef_setting("theme.dereference_register_value")

        regs = [(k, get_register(k)) for k in current_arch.all_registers]

        sep = " {:s} ".format(RIGHT_ARROW)
        memalign = current_arch.ptrsize

        offset = off * memalign
        current_address = align_address(addr + offset)
        addrs = DereferenceCommand.dereference_from(current_address)
        l  = ""
        addr_l = format_address(long(addrs[0], 16))
        l += "{:s}{:s}+{:#06x}: {:{ma}s}".format(Color.colorify(addr_l, base_address_color),
                                                 VERTICAL_LINE, offset,
                                                 sep.join(addrs[1:]), ma=(memalign*2 + 2))

        register_hints = []

        for regname, regvalue in regs:
            if current_address == regvalue:
                register_hints.append(regname)

        if register_hints:
            m = "\t{:s}{:s}".format(LEFT_ARROW, ", ".join(list(register_hints)))
            l += Color.colorify(m, registers_color)

        offset += memalign
        return l


    @only_if_gdb_running
    def do_invoke(self, argv):
        target = "$sp"
        nb = 10

        for arg in argv:
            if arg.isdigit():
                nb = int(arg)
            elif arg[0] in ("l", "L") and arg[1:].isdigit():
                nb = int(arg[1:])
            else:
                target = arg

        addr = safe_parse_and_eval(target)
        if addr is None:
            err("Invalid address")
            return

        addr = long(addr)
        if process_lookup_address(addr) is None:
            err("Unmapped address")
            return

        if get_gef_setting("context.grow_stack_down") is True:
            from_insnum = nb * (self.repeat_count + 1) - 1
            to_insnum = self.repeat_count * nb - 1
            insnum_step = -1
        else:
            from_insnum = 0 + self.repeat_count * nb
            to_insnum = nb * (self.repeat_count + 1)
            insnum_step = 1

        start_address = align_address(addr)

        for i in range(from_insnum, to_insnum, insnum_step):
            gef_print(DereferenceCommand.pprint_dereferenced(start_address, i))

        return


    @staticmethod
    def dereference_from(addr):
        if not is_alive():
            return [format_address(addr),]

        code_color = get_gef_setting("theme.dereference_code")
        string_color = get_gef_setting("theme.dereference_string")
        max_recursion = get_gef_setting("dereference.max_recursion") or 10
        addr = lookup_address(align_address(long(addr)))
        msg = [format_address(addr.value),]
        seen_addrs = set()

        while addr.section and max_recursion:
            if addr.value in seen_addrs:
                msg.append("[loop detected]")
                break
            seen_addrs.add(addr.value)

            max_recursion -= 1

            # Is this value a pointer or a value?
            # -- If it's a pointer, dereference
            deref = addr.dereference()
            if deref is None:
                # if here, dereferencing addr has triggered a MemoryError, no need to go further
                msg.append(str(addr))
                break

            new_addr = lookup_address(deref)
            if new_addr.valid:
                addr = new_addr
                msg.append(str(addr))
                continue

            # -- Otherwise try to parse the value
            if addr.section:
                if addr.section.is_executable() and addr.is_in_text_segment() and not is_ascii_string(addr.value):
                    insn = gef_current_instruction(addr.value)
                    insn_str = "{} {} {}".format(insn.location, insn.mnemonic, ", ".join(insn.operands))
                    msg.append(Color.colorify(insn_str, code_color))
                    break

                elif addr.section.permission.value & Permission.READ:
                    if is_ascii_string(addr.value):
                        s = read_cstring_from_memory(addr.value)
                        if len(s) < get_memory_alignment():
                            txt = '{:s} ("{:s}"?)'.format(format_address(deref), Color.colorify(s, string_color))
                        elif len(s) > 50:
                            txt = Color.colorify('"{:s}[...]"'.format(s[:50]), string_color)
                        else:
                            txt = Color.colorify('"{:s}"'.format(s), string_color)

                        msg.append(txt)
                        break

            # if not able to parse cleanly, simply display and break
            val = "{:#0{ma}x}".format(long(deref & 0xFFFFFFFFFFFFFFFF), ma=(current_arch.ptrsize * 2 + 2))
            msg.append(val)
            break

        return msg


def dereference(addr):
    """GEF wrapper for gdb dereference function."""
    try:
        ulong_t = cached_lookup_type(use_stdtype()) or \
                  cached_lookup_type(use_default_type()) or \
                  cached_lookup_type(use_golang_type())
        unsigned_long_type = ulong_t.pointer()
        res = gdb.Value(addr).cast(unsigned_long_type).dereference()
        # GDB does lazy fetch by default so we need to force access to the value
        res.fetch_lazy()
        return res
    except gdb.MemoryError:
        pass
    return None


def dereference_as_long(addr):
    derefed = dereference(addr)
    return long(derefed.address) if derefed is not None else 0



####################################################################################

#I WANT THIS TO WORK ON WINDOWS
#registers
@register_command
class DetailRegistersCommand(GenericCommand):
    """Display full details on one, many or all registers value from current architecture."""

    _cmdline_ = "registers"
    _syntax_  = "{:s} [[Register1][Register2] ... [RegisterN]]".format(_cmdline_)
    _example_ = "\n{0:s}\n{0:s} $eax $eip $esp".format(_cmdline_)

    @only_if_gdb_running
    def do_invoke(self, argv):
        unchanged_color = get_gef_setting("theme.registers_register_name")
        changed_color = get_gef_setting("theme.registers_value_changed")
        string_color = get_gef_setting("theme.dereference_string")

        if argv:
            regs = [reg for reg in current_arch.all_registers if reg in argv]
            if not regs:
                warn("No matching registers found")
        else:
            regs = current_arch.all_registers


        memsize = current_arch.ptrsize
        endian = endian_str()
        charset = string.printable
        widest = max(map(len, current_arch.all_registers))
        special_line = ""

        for regname in regs:
            reg = gdb.parse_and_eval(regname)
            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue

            padreg = regname.ljust(widest, " ")

            if str(reg) == "<unavailable>":
                line = "{}: ".format(Color.colorify(padreg, unchanged_color))
                line += Color.colorify("no value", "yellow underline")
                gef_print(line)
                continue

            value = align_address(long(reg))
            old_value = ContextCommand.old_registers.get(regname, 0)
            if value == old_value:
                color = unchanged_color
            else:
                color = changed_color

            # Special (e.g. segment) registers go on their own line
            if regname in current_arch.special_registers:
                special_line += "{}: ".format(Color.colorify(regname, color))
                special_line += "0x{:04x} ".format(get_register(regname))
                continue

            line = "{}: ".format(Color.colorify(padreg, color))

            if regname == current_arch.flag_register:
                line += current_arch.flag_register_to_human()
                gef_print(line)
                continue

            addr = lookup_address(align_address(long(value)))
            if addr.valid:
                line += str(addr)
            else:
                line += format_address_spaces(value)
            addrs = DereferenceCommand.dereference_from(value)

            if len(addrs) > 1:
                sep = " {:s} ".format(RIGHT_ARROW)
                line += sep
                line += sep.join(addrs[1:])

            # check to see if reg value is ascii
            try:
                fmt = "{}{}".format(endian, "I" if memsize==4 else "Q")
                last_addr = int(addrs[-1],16)
                val = gef_pystring(struct.pack(fmt, last_addr))
                if all([_ in charset for _ in val]):
                    line += ' ("{:s}"?)'.format(Color.colorify(val, string_color))
            except ValueError:
                pass

            gef_print(line)

        if special_line:
            gef_print(special_line)
        return


#I WANT THIS TO WORK ON WINDOWS
@register_command
class SolveKernelSymbolCommand(GenericCommand):
    """Solve kernel symbols from kallsyms table."""

    _cmdline_ = "ksymaddr"
    _syntax_  = "{:s} SymbolToSearch".format(_cmdline_)
    _example_ = "{:s} prepare_creds".format(_cmdline_)

    def do_invoke(self, argv):
        if len(argv) != 1:
            self.usage()
            return

        found = False
        sym = argv[0]
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                try:
                    symaddr, symtype, symname = line.strip().split(" ", 3)
                    symaddr = long(symaddr, 16)
                    if symname == sym:
                        ok("Found matching symbol for '{:s}' at {:#x} (type={:s})".format(sym, symaddr, symtype))
                        found = True
                    if sym in symname:
                        warn("Found partial match for '{:s}' at {:#x} (type={:s}): {:s}".format(sym, symaddr, symtype, symname))
                        found = True
                except ValueError:
                    pass

        if not found:
            err("No match for '{:s}'".format(sym))
        return




#I WANT THIS TO WORK ON WINDOWS
@register_command
class CapstoneDisassembleCommand(GenericCommand):
    """Use capstone disassembly framework to disassemble code."""

    _cmdline_ = "capstone-disassemble"
    _syntax_  = "{:s} [LOCATION] [[length=LENGTH] [option=VALUE]] ".format(_cmdline_)
    _aliases_ = ["cs-dis",]
    _example_ = "{:s} $pc length=50".format(_cmdline_)

    def pre_load(self):
        try:
            __import__("capstone")
        except ImportError:
            msg = "Missing `capstone` package for Python2. Install with `pip2 install capstone`."
            raise ImportWarning(msg)
        return

    def __init__(self):
        super(CapstoneDisassembleCommand, self).__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @only_if_gdb_running
    def do_invoke(self, argv):
        location = None

        kwargs = {}
        for arg in argv:
            if "=" in arg:
                key, value = arg.split("=", 1)
                kwargs[key] = value

            elif location is None:
                location = parse_address(arg)

        location = location or current_arch.pc
        length = int(kwargs.get("length", get_gef_setting("context.nb_lines_code")))

        for insn in capstone_disassemble(location, length, skip=length*self.repeat_count, **kwargs):
            text_insn = str(insn)
            msg = ""

            if insn.address == current_arch.pc:
                msg = Color.colorify("{}   {}".format(RIGHT_ARROW, text_insn), "bold red")
                reason = self.capstone_analyze_pc(insn, length)[0]
                if reason:
                    gef_print(msg)
                    gef_print(reason)
                    break
            else:
                msg = "{} {}".format(" "*5, text_insn)

            gef_print(msg)
        return

    def capstone_analyze_pc(self, insn, nb_insn):
        if current_arch.is_conditional_branch(insn):
            is_taken, reason = current_arch.is_branch_taken(insn)
            if is_taken:
                reason = "[Reason: {:s}]".format(reason) if reason else ""
                msg = Color.colorify("\tTAKEN {:s}".format(reason), "bold green")
            else:
                reason = "[Reason: !({:s})]".format(reason) if reason else ""
                msg = Color.colorify("\tNOT taken {:s}".format(reason), "bold red")
            return (is_taken, msg)

        if current_arch.is_call(insn):
            target_address = int(insn.operands[-1].split()[0], 16)
            msg = []
            for i, new_insn in enumerate(capstone_disassemble(target_address, nb_insn)):
                msg.append("   {}  {}".format (DOWN_ARROW if i==0 else " ", str(new_insn)))
            return (True, "\n".join(msg))

        return (False, "")




#I WANT THIS TO WORK ON WINDOWS



########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################




















































####################################################################################
# OTHER STUFF ######################################################################
####################################################################################



@lru_cache()
def get_section_base_address(name):
    section = process_lookup_path(name)
    if section:
        return section.page_start

    return None

@lru_cache()
def get_zone_base_address(name):
    zone = file_lookup_name_path(name, get_filepath())
    if zone:
        return zone.zone_start

    return None

class GenericFunction(gdb.Function):
    """This is an abstract class for invoking convenience functions, should not be instantiated."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def _function_(self): pass
    @property
    def _syntax_(self):
        return "${}([offset])".format(self._function_)

    def __init__ (self):
        super(GenericFunction, self).__init__(self._function_)

    def invoke(self, *args):
        if not is_alive():
            raise gdb.GdbError("No debugging session active")
        return long(self.do_invoke(args))

    def arg_to_long(self, args, index, default=0):
        try:
            addr = args[index]
            return long(addr) if addr.address is None else long(addr.address)
        except IndexError:
            return default

    @abc.abstractmethod
    def do_invoke(self, args): pass


##################################################################################
# PROCESS COMPONENTS #############################################################
##################################################################################

@register_function
class StackOffsetFunction(GenericFunction):
    """Return the current stack base address plus an optional offset."""
    _function_ = "_stack"

    def do_invoke(self, args):
        return self.arg_to_long(args, 0) + get_section_base_address("[stack]")

@register_function
class HeapBaseFunction(GenericFunction):
    """Return the current heap base address plus an optional offset."""
    _function_ = "_heap"

    def do_invoke(self, args):
        base = HeapBaseFunction.heap_base()
        if not base:
            raise gdb.GdbError("Heap not found")

        return self.arg_to_long(args, 0) + base

    @staticmethod
    def heap_base():
        try:
            base = long(gdb.parse_and_eval("mp_->sbrk_base"))
            if base != 0:
                return base
        except gdb.error:
            pass
        return get_section_base_address("[heap]")

@register_function
class PieBaseFunction(GenericFunction):
    """Return the current pie base address plus an optional offset."""
    _function_ = "_pie"

    def do_invoke(self, args):
        return self.arg_to_long(args, 0) + get_section_base_address(get_filepath())

@register_function
class BssBaseFunction(GenericFunction):
    """Return the current bss base address plus the given offset."""
    _function_ = "_bss"

    def do_invoke(self, args):
        return self.arg_to_long(args, 0) + get_zone_base_address(".bss")

@register_function
class GotBaseFunction(GenericFunction):
    """Return the current bss base address plus the given offset."""
    _function_ = "_got"

    def do_invoke(self, args):
        return self.arg_to_long(args, 0) + get_zone_base_address(".got")

@register_command
class GefFunctionsCommand(GenericCommand):
    """List the convenience functions provided by GEF."""
    _cmdline_ = "functions"
    _syntax_ = _cmdline_

    def __init__(self):
        super(GefFunctionsCommand, self).__init__()
        self.docs = []
        self.setup()
        return

    def setup(self):
        global __gef__
        for function in __gef__.loaded_functions:
            self.add_function_to_doc(function)
        self.__doc__ = "\n".join(sorted(self.docs))
        return

    def add_function_to_doc(self, function):
        """Add function to documentation."""
        doc = getattr(function, "__doc__", "").lstrip()
        doc = "\n                         ".join(doc.split("\n"))
        syntax = getattr(function, "_syntax_", "").lstrip()
        msg = "{syntax:<25s} -- {help:s}".format(syntax=syntax, help=Color.greenify(doc))
        self.docs.append(msg)
        return

    def do_invoke(self, argv):
        self.dont_repeat()
        gef_print(titlify("GEF - Convenience Functions"))
        gef_print("These functions can be used as arguments to other "
                  "commands to dynamically calculate values, eg: {:s}\n"
                  .format(Color.colorify("deref $_heap(0x20)", "yellow")))
        gef_print(self.__doc__)
        return


######################################################################################
#GEF COMMAND STUFF ###################################################################
######################################################################################


class GefCommand(gdb.Command):
    """GEF main command: view all new commands by typing `gef`."""

    _cmdline_ = "gef"
    _syntax_  = "{:s} (missing|config|save|restore|set|run)".format(_cmdline_)

    def __init__(self):
        super(GefCommand, self).__init__(GefCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT,
                                         gdb.COMPLETE_NONE,
                                         True)
        set_gef_setting("gef.follow_child", True, bool, "Automatically set GDB to follow child when forking")
        set_gef_setting("gef.readline_compat", False, bool, "Workaround for readline SOH/ETX issue (SEGV)")
        set_gef_setting("gef.debug", False, bool, "Enable debug mode for gef")
        set_gef_setting("gef.autosave_breakpoints_file", "", str, "Automatically save and restore breakpoints")
        set_gef_setting("gef.extra_plugins_dir", "", str, "Autoload additional GEF commands from external directory")
        set_gef_setting("gef.disable_color", False, bool, "Disable all colors in GEF")
        self.loaded_commands = []
        self.loaded_functions = []
        self.missing_commands = {}
        return

    def setup(self):
        self.load(initial=True)
        # loading GEF sub-commands
        self.doc = GefHelpCommand(self.loaded_commands)
        self.cfg = GefConfigCommand(self.loaded_command_names)
        GefSaveCommand()
        GefRestoreCommand()
        GefMissingCommand()
        GefSetCommand()
        GefRunCommand()

        # load the saved settings
        gdb.execute("gef restore")

        # restore the autosave/autoreload breakpoints policy (if any)
        self.__reload_auto_breakpoints()

        # load plugins from `extra_plugins_dir`
        if self.__load_extra_plugins() > 0:
            # if here, at least one extra plugin was loaded, so we need to restore
            # the settings once more
            gdb.execute("gef restore quiet")

        return


    def __reload_auto_breakpoints(self):
        bkp_fname = __config__.get("gef.autosave_breakpoints_file", None)
        bkp_fname = bkp_fname[0] if bkp_fname else None
        if bkp_fname:
            # restore if existing
            if os.access(bkp_fname, os.R_OK):
                gdb.execute("source {:s}".format(bkp_fname))

            # add hook for autosave breakpoints on quit command
            source = [
                "define hook-quit",
                " save breakpoints {:s}".format(bkp_fname),
                "end"
            ]
            gef_execute_gdb_script("\n".join(source) + "\n")
        return


    def __load_extra_plugins(self):
        nb_added = -1
        try:
            nb_inital = len(self.loaded_commands)
            directories = get_gef_setting("gef.extra_plugins_dir")
            if directories:
                for directory in directories.split(";"):
                    directory = os.path.realpath(os.path.expanduser(directory))
                    if os.path.isdir(directory):
                        sys.path.append(directory)
                        for fname in os.listdir(directory):
                            if not fname.endswith(".py"): continue
                            fpath = "{:s}/{:s}".format(directory, fname)
                            if os.path.isfile(fpath):
                                gdb.execute("source {:s}".format(fpath))
            nb_added = len(self.loaded_commands) - nb_inital
            if nb_added > 0:
                ok("{:s} extra commands added from '{:s}'".format(Color.colorify(nb_added, "bold green"),
                                                                  Color.colorify(directory, "bold blue")))
        except gdb.error as e:
            err("failed: {}".format(str(e)))
        return nb_added


    @property
    def loaded_command_names(self):
        return [x[0] for x in self.loaded_commands]


    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("gef help")
        return


    def load(self, initial=False):
        """Load all the commands and functions defined by GEF into GDB."""
        nb_missing = 0
        self.commands = [(x._cmdline_, x) for x in __commands__]

        # load all of the functions
        for function_class_name in __functions__:
            self.loaded_functions.append(function_class_name())

        def is_loaded(x):
            return any(filter(lambda u: x == u[0], self.loaded_commands))

        for cmd, class_name in self.commands:
            if is_loaded(cmd):
                continue

            try:
                self.loaded_commands.append((cmd, class_name, class_name()))

                if hasattr(class_name, "_aliases_"):
                    aliases = getattr(class_name, "_aliases_")
                    for alias in aliases:
                        GefAlias(alias, cmd)

            except Exception as reason:
                self.missing_commands[cmd] = reason
                nb_missing += 1

        # sort by command name
        self.loaded_commands = sorted(self.loaded_commands, key=lambda x: x[1]._cmdline_)

        if initial:
            gef_print("{:s} for {:s} ready, type `{:s}' to start, `{:s}' to configure"
                      .format(Color.greenify("GEF"), get_os(),
                              Color.colorify("gef","underline yellow"),
                              Color.colorify("gef config", "underline pink")))

            ver = "{:d}.{:d}".format(sys.version_info.major, sys.version_info.minor)
            nb_cmds = len(self.loaded_commands)
            gef_print("{:s} commands loaded for GDB {:s} using Python engine {:s}"
                      .format(Color.colorify(nb_cmds, "bold green"),
                              Color.colorify(gdb.VERSION, "bold yellow"),
                              Color.colorify(ver, "bold red")))

            if nb_missing:
                warn("{:s} command{} could not be loaded, run `{:s}` to know why."
                          .format(Color.colorify(nb_missing, "bold red"),
                                  "s" if nb_missing > 1 else "",
                                  Color.colorify("gef missing", "underline pink")))
        return


class GefHelpCommand(gdb.Command):
    """GEF help sub-command."""
    _cmdline_ = "gef help"
    _syntax_  = _cmdline_

    def __init__(self, commands, *args, **kwargs):
        super(GefHelpCommand, self).__init__(GefHelpCommand._cmdline_,
                                             gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE,
                                             False)
        self.docs = []
        self.generate_help(commands)
        self.refresh()
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gef_print(titlify("GEF - GDB Enhanced Features"))
        gef_print(self.__doc__)
        return

    def generate_help(self, commands):
        """Generate builtin commands documentation."""
        for command in commands:
            self.add_command_to_doc(command)
        return

    def add_command_to_doc(self, command):
        """Add command to GEF documentation."""
        cmd, class_name, _  = command
        if " " in cmd:
            # do not print subcommands in gef help
            return
        doc = getattr(class_name, "__doc__", "").lstrip()
        doc = "\n                         ".join(doc.split("\n"))
        aliases = " (alias: {:s})".format(", ".join(class_name._aliases_)) if hasattr(class_name, "_aliases_") else ""
        msg = "{cmd:<25s} -- {help:s}{aliases:s}".format(cmd=cmd, help=Color.greenify(doc), aliases=aliases)
        self.docs.append(msg)
        return

    def refresh(self):
        """Refresh the documentation."""
        self.__doc__ = "\n".join(sorted(self.docs))
        return


class GefConfigCommand(gdb.Command):
    """GEF configuration sub-command
    This command will help set/view GEF settingsfor the current debugging session.
    It is possible to make those changes permanent by running `gef save` (refer
    to this command help), and/or restore previously saved settings by running
    `gef restore` (refer help).
    """
    _cmdline_ = "gef config"
    _syntax_  = "{:s} [setting_name] [setting_value]".format(_cmdline_)

    def __init__(self, loaded_commands, *args, **kwargs):
        super(GefConfigCommand, self).__init__(GefConfigCommand._cmdline_, gdb.COMMAND_NONE, prefix=False)
        self.loaded_commands = loaded_commands
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        argv = gdb.string_to_argv(args)
        argc = len(argv)

        if not (0 <= argc <= 2):
            err("Invalid number of arguments")
            return

        if argc == 0:
            gef_print(titlify("GEF configuration settings"))
            self.print_settings()
            return

        if argc == 1:
            prefix = argv[0]
            names = list(filter(lambda x: x.startswith(prefix), __config__.keys()))
            if names:
                if len(names)==1:
                    gef_print(titlify("GEF configuration setting: {:s}".format(names[0])))
                    self.print_setting(names[0], verbose=True)
                else:
                    gef_print(titlify("GEF configuration settings matching '{:s}'".format(argv[0])))
                    for name in names: self.print_setting(name)
            return

        self.set_setting(argc, argv)
        return

    def print_setting(self, plugin_name, verbose=False):
        res = __config__.get(plugin_name)
        string_color = get_gef_setting("theme.dereference_string")
        misc_color = get_gef_setting("theme.dereference_base_address")

        if not res:
            return

        _value, _type, _desc = res
        _setting = Color.colorify(plugin_name, "green")
        _type = _type.__name__
        if _type == "str":
            _value = '"{:s}"'.format(Color.colorify(_value, string_color))
        else:
            _value = Color.colorify(_value, misc_color)

        gef_print("{:s} ({:s}) = {:s}".format(_setting, _type, _value))

        if verbose:
            gef_print(Color.colorify("\nDescription:", "bold underline"))
            gef_print("\t{:s}".format(_desc))
        return

    def print_settings(self):
        for x in sorted(__config__):
            self.print_setting(x)
        return

    def set_setting(self, argc, argv):
        global __gef__
        if "." not in argv[0]:
            err("Invalid command format")
            return

        loaded_commands = [ x[0] for x in __gef__.loaded_commands ] + ["gef"]
        plugin_name = argv[0].split(".", 1)[0]
        if plugin_name not in loaded_commands:
            err("Unknown plugin '{:s}'".format(plugin_name))
            return

        _type = __config__.get(argv[0], [None, None, None])[1]
        if _type is None:
            err("Failed to get '{:s}' config setting".format(argv[0],))
            return

        try:
            if _type == bool:
                _newval = True if argv[1].upper() in ("TRUE", "T", "1") else False
            else:
                _newval = _type(argv[1])

        except Exception:
            err("{} expects type '{}'".format(argv[0], _type.__name__))
            return

        reset_all_caches()
        __config__[argv[0]][0] = _newval
        return

    def complete(self, text, word):
        settings = sorted(__config__)

        if text=="":
            # no prefix: example: `gef config TAB`
            return [s for s in settings if word in s]

        if "." not in text:
            # if looking for possible prefix
            return [s for s in settings if s.startswith(text.strip())]

        # finally, look for possible values for given prefix
        return [s.split(".", 1)[1] for s in settings if s.startswith(text.strip())]


class GefSaveCommand(gdb.Command):
    """GEF save sub-command.
    Saves the current configuration of GEF to disk (by default in file '~/.gef.rc')."""
    _cmdline_ = "gef save"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefSaveCommand, self).__init__(GefSaveCommand._cmdline_, gdb.COMMAND_SUPPORT,
                                             gdb.COMPLETE_NONE, False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        cfg = configparser.RawConfigParser()
        old_sect = None

        # save the configuration
        for key in sorted(__config__):
            sect, optname = key.split(".", 1)
            value = __config__.get(key, None)
            value = value[0] if value else None

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        # save the aliases
        cfg.add_section("aliases")
        for alias in __aliases__:
            cfg.set("aliases", alias._alias, alias._command)

        with open(GEF_RC, "w") as fd:
            cfg.write(fd)

        ok("Configuration saved to '{:s}'".format(GEF_RC))
        return


class GefRestoreCommand(gdb.Command):
    """GEF restore sub-command.
    Loads settings from file '~/.gef.rc' and apply them to the configuration of GEF."""
    _cmdline_ = "gef restore"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefRestoreCommand, self).__init__(GefRestoreCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if not os.access(GEF_RC, os.R_OK):
            return

        quiet = args.lower() == "quiet"
        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        for section in cfg.sections():
            if section == "aliases":
                # load the aliases
                for key in cfg.options(section):
                    GefAlias(key, cfg.get(section, key))
                continue

            # load the other options
            for optname in cfg.options(section):
                try:
                    key = "{:s}.{:s}".format(section, optname)
                    _type = __config__.get(key)[1]
                    new_value = cfg.get(section, optname)
                    if _type == bool:
                        new_value = True if new_value == "True" else False
                    else:
                        new_value = _type(new_value)
                    __config__[key][0] = new_value
                except Exception:
                    pass

        if not quiet:
            ok("Configuration from '{:s}' restored".format(Color.colorify(GEF_RC, "bold blue")))
        return


class GefMissingCommand(gdb.Command):
    """GEF missing sub-command
    Display the GEF commands that could not be loaded, along with the reason of why
    they could not be loaded.
    """
    _cmdline_ = "gef missing"
    _syntax_  = _cmdline_

    def __init__(self, *args, **kwargs):
        super(GefMissingCommand, self).__init__(GefMissingCommand._cmdline_,
                                                gdb.COMMAND_SUPPORT,
                                                gdb.COMPLETE_NONE,
                                                False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        missing_commands = __gef__.missing_commands.keys()
        if not missing_commands:
            ok("No missing command")
            return

        for missing_command in missing_commands:
            reason = __gef__.missing_commands[missing_command]
            warn("Command `{}` is missing, reason {} {}".format(missing_command, RIGHT_ARROW, reason))
        return


class GefSetCommand(gdb.Command):
    """Override GDB set commands with the context from GEF.
    """
    _cmdline_ = "gef set"
    _syntax_  = "{:s} [GDB_SET_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefSetCommand, self).__init__(GefSetCommand._cmdline_,
                                            gdb.COMMAND_SUPPORT,
                                            gdb.COMPLETE_SYMBOL,
                                            False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        args = args.split()
        cmd = ["set", args[0],]
        for p in args[1:]:
            if p.startswith("$_gef"):
                c = gdb.parse_and_eval(p)
                cmd.append(c.string())
            else:
                cmd.append(p)

        gdb.execute(" ".join(cmd))
        return


class GefRunCommand(gdb.Command):
    """Override GDB run commands with the context from GEF.
    Simple wrapper for GDB run command to use arguments set from `gef set args`. """
    _cmdline_ = "gef run"
    _syntax_  = "{:s} [GDB_RUN_ARGUMENTS]".format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super(GefRunCommand, self).__init__(GefRunCommand._cmdline_,
                                            gdb.COMMAND_SUPPORT,
                                            gdb.COMPLETE_FILENAME,
                                            False)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        if is_alive():
            gdb.execute("continue")
            return

        argv = args.split()
        gdb.execute("gef set args {:s}".format(" ".join(argv)))
        gdb.execute("run")
        return


class GefAlias(gdb.Command):
    """Simple aliasing wrapper because GDB doesn't do what it should.
    """
    def __init__(self, alias, command, completer_class=gdb.COMPLETE_NONE, command_class=gdb.COMMAND_NONE):
        p = command.split()
        if not p:
            return

        if list(filter(lambda x: x._alias == alias, __aliases__)):
            return

        self._command = command
        self._alias = alias
        c = command.split()[0]
        r = self.lookup_command(c)
        self.__doc__ = "Alias for '{}'".format(Color.greenify(command))
        if r is not None:
            _instance = r[2]
            self.__doc__ += ": {}".format(_instance.__doc__)

            if hasattr(_instance,  "complete"):
                self.complete = _instance.complete

        super(GefAlias, self).__init__(alias, command_class, completer_class=completer_class)
        __aliases__.append(self)
        return

    def invoke(self, args, from_tty):
        gdb.execute("{} {}".format(self._command, args), from_tty=from_tty)
        return

    def lookup_command(self, cmd):
        global __gef__
        for _name, _class, _instance in __gef__.loaded_commands:
            if cmd == _name:
                return _name, _class, _instance

        return None


class GefAliases(gdb.Command):
    """List all custom aliases."""
    def __init__(self):
        super(GefAliases, self).__init__("aliases", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()
        ok("Aliases defined:")
        for _alias in __aliases__:
            gef_print("{:30s} {} {}".format(_alias._alias, RIGHT_ARROW, _alias._command))
        return


class GefTmuxSetup(gdb.Command):
    """Setup a confortable tmux debugging environment."""
    def __init__(self):
        super(GefTmuxSetup, self).__init__("tmux-setup", gdb.COMMAND_NONE, gdb.COMPLETE_NONE)
        GefAlias("screen-setup", "tmux-setup")
        return

    def invoke(self, args, from_tty):
        self.dont_repeat()

        tmux = os.getenv("TMUX")
        if tmux:
            self.tmux_setup()
            return

        screen = os.getenv("TERM")
        if screen is not None and screen == "screen":
            self.screen_setup()
            return

        warn("Not in a tmux/screen session")
        return


    def tmux_setup(self):
        """Prepare the tmux environment by vertically splitting the current pane, and
        forcing the context to be redirected there."""
        tmux = which("tmux")
        ok("tmux session found, splitting window...")
        old_ptses = set(os.listdir("/dev/pts"))
        gdb.execute("! {} split-window -h 'clear ; cat'".format(tmux))
        gdb.execute("! {} select-pane -L".format(tmux))
        new_ptses = set(os.listdir("/dev/pts"))
        pty = list(new_ptses - old_ptses)[0]
        pty = "/dev/pts/{}".format(pty)
        ok("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("gef config context.redirect {}".format(pty))
        ok("Done!")
        return


    def screen_setup(self):
        """Hackish equivalent of the tmux_setup() function for screen."""
        screen = which("screen")
        sty = os.getenv("STY")
        ok("screen session found, splitting window...")
        fd_script, script_path = tempfile.mkstemp()
        fd_tty, tty_path = tempfile.mkstemp()
        os.close(fd_tty)

        with os.fdopen(fd_script, "w") as f:
            f.write("startup_message off\n")
            f.write("split -v\n")
            f.write("focus right\n")
            f.write("screen /bin/bash -c 'tty > {}; clear; cat'\n".format(tty_path))
            f.write("focus left\n")

        gdb.execute("""! {} -r {} -m -d -X source {}""".format(screen, sty, script_path))
        # artificial delay to make sure `tty_path` is populated
        time.sleep(0.25)
        with open(tty_path, "r") as f:
            pty = f.read().strip()
        ok("Setting `context.redirect` to '{}'...".format(pty))
        gdb.execute("gef config context.redirect {}".format(pty))
        ok("Done!")
        os.unlink(script_path)
        os.unlink(tty_path)
        return


def __gef_prompt__(current_prompt):
    """GEF custom prompt function."""
    if get_gef_setting("gef.readline_compat") is True: return GEF_PROMPT
    if get_gef_setting("gef.disable_color") is True: return GEF_PROMPT
    if is_alive(): return GEF_PROMPT_ON
    return GEF_PROMPT_OFF


######################################################################################
#MAIN ################################################################################
######################################################################################


if __name__  == "__main__":

    if GDB_VERSION < GDB_MIN_VERSION:
        err("You're using an old version of GDB. GEF will not work correctly. "
            "Consider updating to GDB {} or higher.".format(".".join(map(str, GDB_MIN_VERSION))))

    else:
        try:
            pyenv = which("pyenv")
            PYENV_ROOT = gef_pystring(subprocess.check_output([pyenv, "root"]).strip())
            PYENV_VERSION = gef_pystring(subprocess.check_output([pyenv, "version-name"]).strip())
            site_packages_dir = os.path.join(PYENV_ROOT, "versions", PYENV_VERSION, "lib",
                                             "python{}".format(PYENV_VERSION[:3]), "site-packages")
            site.addsitedir(site_packages_dir)
        except FileNotFoundError:
            pass

        # setup prompt
        gdb.prompt_hook = __gef_prompt__

        # setup config
        gdb.execute("set confirm off")
        gdb.execute("set verbose off")
        gdb.execute("set pagination off")
        gdb.execute("set step-mode on")
        gdb.execute("set print elements 0")

        # gdb history
        gdb.execute("set history save on")
        gdb.execute("set history filename ~/.gdb_history")

        # gdb input and output bases
        gdb.execute("set output-radix 0x10")

        # pretty print
        gdb.execute("set print pretty on")

        try:
            # this will raise a gdb.error unless we're on x86
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            # we can safely ignore this
            pass

        # SIGALRM will simply display a message, but gdb won't forward the signal to the process
        gdb.execute("handle SIGALRM print nopass")

        # saving GDB indexes in GEF tempdir
        gef_makedirs(GEF_TEMP_DIR)
        gdb.execute("save gdb-index {}".format(GEF_TEMP_DIR))

        # load GEF
        __gef__ = GefCommand()
        __gef__.setup()

        # gdb events configuration
        gef_on_continue_hook(continue_handler)
        gef_on_stop_hook(hook_stop_handler)
        gef_on_new_hook(new_objfile_handler)
        gef_on_exit_hook(exit_handler)

        if gdb.current_progspace().filename is not None:
            # if here, we are sourcing gef from a gdb session already attached
            # we must force a call to the new_objfile handler (see issue #278)
            new_objfile_handler(None)

        GefAliases()
        GefTmuxSetup()
