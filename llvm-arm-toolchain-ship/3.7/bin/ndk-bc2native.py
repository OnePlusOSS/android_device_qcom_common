#!/usr/bin/python

r'''
 Copyright (C) 2013 The Android Open Source Project

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
'''

import sys, os, argparse, subprocess, types
import tempfile, struct, shutil

VERBOSE = False
KEEP = False
NDK = ''
SYSROOT = ''
HOST_TAG = ''
LLVM_VERSION = '3.4'
PLATFORM = None
ABI = None
LD = None
BITCODE = None
OUTPUT = None

TRANSLATE_CMD = None
LLC_CMD = None
LD_CMD = None
AS_CMD = None
USE_GAS = False

# bitcode wrapper
SHARED = True
SONAME = None
DEPEND_LIBS = []
LDFLAGS = None

def log(string):
    global VERBOSE
    if VERBOSE:
        print(string)

def error(string, errcode=1):
    print('ERROR: %s' % (string))
    exit(errcode)

def find_program(program, extra_paths = []):
    ''' extra_paths are searched before PATH '''
    PATHS = extra_paths+os.environ['PATH'].split(os.pathsep)
    exts = ['']
    if sys.platform.startswith('win'):
        exts += ['.exe', '.bat', '.cmd']
    for path in PATHS:
        if os.path.isdir(path):
            for ext in exts:
                full = path + os.sep + program + ext
                if os.path.isfile(full):
                    return True, full
    return False, None

# Return the llvm bin path for the host os.
def llvm_bin_path(ndk, host_tag, llvm_ver):
    return ndk+'/toolchains/llvm-'+llvm_ver+'/prebuilt/'+host_tag+'/bin'

# Return the sysroot for arch.
def sysroot_for_arch(arch):
    global NDK, SYSROOT, PLATFORM
    sysroot = NDK+'/platforms/'+PLATFORM+'/arch-'+arch
    if os.path.exists(sysroot):
        return sysroot
    elif os.path.exists(SYSROOT):
        return SYSROOT
    else:
        error('sysroot not found: %s' % (sysroot))
    return ''

# Return the arch name for abi
def get_arch_for_abi(abi):
    if abi == 'armeabi' or abi == 'armeabi-v7a':
        return 'arm'
    elif abi == 'x86':
        return 'x86'
    elif abi == 'mips':
        return 'mips'
    error('Unspported abi: %s' % (abi))
    return ''

# Get default llvm triple for abi.
def get_default_triple_for_abi(abi):
    if abi == 'armeabi':
        return 'armv5te-none-linux-androideabi'
    elif abi == 'armeabi-v7a':
        return 'thumbv7-none-linux-androideabi'
    elif abi == 'x86':
        return 'i686-none-linux-android'
    elif abi == 'mips':
        return 'mipsel-none-linux-androideabi'
    error('Unspported abi: %s' % (abi))
    return ''

def get_default_emulation_for_arch(arch):
    if arch == 'arm':
        return 'armelf_linux_eabi'
    elif arch == 'x86':
        return 'elf_i386'
    elif arch == 'mips':
        return 'elf32ltsmip'
    return ''

def gcc_toolchain_for_arch(arch):
    if arch == 'arm':
        return NDK+'/toolchains/arm-linux-androideabi-4.6/prebuilt/'+HOST_TAG
    elif arch == 'x86':
        return NDK+'/toolchains/x86-4.6/prebuilt/'+HOST_TAG
    elif arch == 'mips':
        return NDK+'/toolchains/mipsel-linux-android-4.6/prebuilt/'+HOST_TAG
    return ''

def get_ld_name_for_arch(arch, ld_suffix):
    if arch == 'arm':
        return 'arm-linux-androideabi-ld.'+ld_suffix
    elif arch == 'x86':
        return 'i686-linux-android-ld.'+ld_suffix
    elif arch == 'mips':
        if ld_suffix == 'gold':
            error('ld.gold is not supported for mips!')
        else:
            return 'mipsel-linux-android-ld.'+ld_suffix
    return ''

def get_as_name_for_arch(arch):
    if arch == 'arm':
        return 'arm-linux-androideabi-as'
    elif arch == 'x86':
        return 'i686-linux-android-as'
    elif arch == 'mips':
        return 'mipsel-linux-android-as'
    return ''

def handle_args():
    global BITCODE, OUTPUT
    global PLATFORM, LLVM_VERSION, ABI, NDK, SYSROOT, LD
    global VERBOSE, KEEP, USE_GAS

    parser = argparse.ArgumentParser(description='''Transform bitcode to binary tool''')

    parser.add_argument( '--file',
                         nargs=2,
                         required=True,
                         action='append',
                         metavar=('input_bitcode', 'output_file'),
                         help='Specify input bitcode and output filename')

    parser.add_argument( '--platform',
                         help='Specify API level for target binary',
                         default='android-9',
                         dest='platform')

    parser.add_argument( '--ndk-dir',
                         help='Specify the ndk directory',
                         dest='ndk_dir')

    parser.add_argument( '--sysroot',
                         help='Specify where is the sysroot (for standalone usage)',
                         dest='sysroot')

    parser.add_argument( '--abi',
                         help='Specify ABI for target binary',
                         default='armeabi',
                         choices=['armeabi', 'armeabi-v7a', 'x86', 'mips'])

    parser.add_argument( '--use-ld',
                         help='Select linker (mcld, bfd, gold) for linking binaries',
                         default='mcld',
                         choices=['mcld','bfd','gold'])

    parser.add_argument( '-v', '--verbose',
                         help='Enable verbose mode',
                         action='store_true',
                         dest='verbose')

    parser.add_argument( '--keep',
                         help='Keep the temporary files',
                         action='store_true',
                         dest='keep')

    parser.add_argument( '--use-gas',
                         help='Use GNU as to generate object files',
                         action='store_true',
                         dest='use_gas')

    args = parser.parse_args()
    # TODO: Support multiple input
    BITCODE = args.file[0][0]
    OUTPUT = args.file[0][1]

    if os.path.isfile(BITCODE) != True:
        error('Input bitcode %s not found!' % (BITCODE))

    VERBOSE = args.verbose
    KEEP = args.keep
    PLATFORM = args.platform
    ABI = args.abi
    LD = args.use_ld
    USE_GAS = args.use_gas

    if args.ndk_dir != None and args.sysroot != None:
        error('Either --ndk-dir or --sysroot can only exist one!')
    if args.ndk_dir == None and args.sysroot == None:
        error('Either --ndk-dir or --sysroot must exist one!')
    if args.ndk_dir != None:
        NDK = args.ndk_dir
        log('Android NDK installation path: %s' % (NDK))
    else:
        SYSROOT = args.sysroot
        log('Android NDK sysroot path: %s' % (SYSROOT))

def locate_tools():
    global HOST_TAG, NDK, LLVM_VERSION, ABI, LD
    global TRANSLATE_CMD, LLC_CMD, LD_CMD, AS_CMD

    pwd = os.path.abspath(os.path.dirname(sys.argv[0]))
    # pwd is in /path/HOST_TAG/bin: the 1st split drops "bin", the 2nd split keeps HOST_TAG
    HOST_TAG = os.path.split(os.path.split(pwd)[0])[1]

    llvm_bin = llvm_bin_path(NDK, HOST_TAG, LLVM_VERSION)
    arch = get_arch_for_abi(ABI)
    gcc_bin = gcc_toolchain_for_arch(arch) + '/bin/'

    (found_translate, TRANSLATE_CMD) = find_program('ndk-translate', [pwd, llvm_bin])
    if found_translate != True:
        error('Cannot find ndk-translate')

    (found_llc,  LLC_CMD)  = find_program('llc', [pwd, llvm_bin])
    if found_llc != True:
        error('Cannot find llc')

    ld_name = get_ld_name_for_arch(arch, LD)
    (found_ld, LD_CMD) = find_program(ld_name, [pwd, gcc_bin])
    if found_ld != True:
        error('Cannot find %s' %(ld_name))

    as_name = get_as_name_for_arch(arch)
    (found_as, AS_CMD) = find_program(as_name, [pwd, gcc_bin])
    if found_as != True:
        error('Cannot find %s' %(as_name))

def parse_bitcode_type(data):
    type = struct.unpack('<i',data)[0]
    if type != 1:
        return False
    return True

'''
  The bitcode wrapper definition:

  struct AndroidBitcodeWrapper {
    uint32_t Magic;
    uint32_t Version;
    uint32_t BitcodeOffset;
    uint32_t BitcodeSize;
    uint32_t HeaderVersion;
    uint32_t TargetAPI;
    uint32_t PNaClVersion;
    uint16_t CompilerVersionTag;
    uint16_t CompilerVersionLen;
    uint32_t CompilerVersion;
    uint16_t OptimizationLevelTag;
    uint16_t OptimizationLevelLen;
    uint32_t OptimizationLevel;
  };

'''
def read_bitcode_wrapper(bitcode):
    global SHARED, SONAME, DEPEND_LIBS, LDFLAGS
    global OUTPUT
    f = open(bitcode, 'rb')
    fixed_field = struct.unpack('<iiiiiii',f.read(4*7))
    magic_number = fixed_field[0]
    if hex(magic_number) != '0xb17c0de':
        error("Invalid bitcode file!")
    offset = fixed_field[2]
    offset -= 4*7
    while offset > 0:
        tag,length = struct.unpack('<hh',f.read(4))
        length = (length+3) & ~3
        data = f.read(length)
        if hex(tag) == '0x5001':
            SHARED = parse_bitcode_type(data)
        elif hex(tag) == '0x5002':
            LDFLAGS = str(data).rstrip('\0')
        offset -= (length+4)

def get_runtime_name(libname):
    return {
        'gabi++_static': 'libgabi++_static.a',
        'gabi++_shared': 'libgabi++_shared.so',
        }.get(libname, '')

# Return the full path of specific compiler runtime
def get_compiler_runtime(libname):
    global NDK, SYSROOT, ABI
    if SYSROOT:
         return SYSROOT + '/usr/lib/' + libname
    else:
        arch = get_arch_for_abi(ABI)
        sysroot = sysroot_for_arch(arch)
        return {
            'libportable.wrap': NDK+'/sources/android/libportable/libs/'+ABI+'/libportable.wrap',
            'libportable.a': NDK+'/sources/android/libportable/libs/'+ABI+'/libportable.a',
            'libcompiler_rt_static.a': NDK+'/sources/android/compiler-rt/libs/'+ABI+'/libcompiler_rt_static.a',
            'libgabi++_shared.so': NDK+'/sources/cxx-stl/gabi++/libs/'+ABI+'/libgabi++_shared.so',
            'libgabi++_static.a': NDK+'/sources/cxx-stl/gabi++/libs/'+ABI+'/libgabi++_static.a',
            'libgccunwind.a': NDK+'/sources/android/gccunwind/libs/'+ABI+'/libgccunwind.a',
            }.get(libname, sysroot+'/usr/lib/'+libname)

#  Remove '-o outputfile' from ldflags, we already know the name of output file.
def process_ldflags(ldflags):
    orig_ldflags = ldflags.split()
    output_ldflags = []
    save = True
    for option in orig_ldflags:
        if option == '-o':
            save = False
        elif option[0:2] == '-l':
            # Convert the runtime path
            runtime_name = get_runtime_name(option[2:])
            runtime_path = get_compiler_runtime(runtime_name)
            if os.path.isfile(runtime_path):
                output_ldflags += [runtime_path]
            else:
                output_ldflags += [option]
        else:
            if save == True:
                output_ldflags += [option]
            save = True
    return output_ldflags

def run_cmd(args):
    log(' '.join(args))
    ret = 0
    try:
        text = subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        ret = e.returncode
        text = e.output
    return ret, text

def do_translate(bitcode, output):
    global TRANSLATE_CMD
    global ABI

    arch = get_arch_for_abi(ABI)
    args = [TRANSLATE_CMD]
    args += ['-arch='+arch]
    args += ['-o']
    args += [output]
    args += [bitcode]

    return run_cmd(args)

def do_as(asm, relocatable):
    global AS_CMD
    global ABI

    args = [AS_CMD]
    if ABI == 'armeabi':
        args += ['-mfloat-abi=soft']
        args += ['-march=armv5te']
    elif ABI == 'armeabi-v7a':
        args += ['-mfloat-abi=soft']
        args += ['-march=armv7-a']
        args += ['-mfpu=vfpv3-d16']

    args += ['--noexecstack']
    args += ['-o']
    args += [relocatable]
    args += [asm]

    return run_cmd(args)

def get_llc_flags_for_abi(abi):
    extra_args = []
    if abi == 'x86':
        extra_args += ['-disable-fp-elim']
        # Translated from -mstackrealign which is default in gcc
        extra_args += ['-force-align-stack']
        # Not all Android x86 devices have these features
        extra_args += ['-mattr="-ssse3,-sse41,-sse42,-sse4a,-popcnt"']
    elif abi == 'armeabi' or abi == 'armeabi-v7a':
        extra_args += ['-arm-enable-ehabi']
        extra_args += ['-arm-enable-ehabi-descriptors']
    return extra_args

def do_llc(bitcode, output):
    global LLC_CMD
    global ABI

    triple = get_default_triple_for_abi(ABI)
    args = [LLC_CMD]
    args += ['-mtriple='+triple]

    if (ABI == 'armeabi' or ABI == 'armeabi-v7a') and USE_GAS:
        args += ['-filetype=asm']
    else:
        args += ['-filetype=obj']

    args += ['-relocation-model=pic']
    args += ['-code-model=small']
    args += ['-use-init-array']
    args += ['-mc-relax-all']
    if ABI == 'armeabi' or ABI == 'armeabi-v7a':
        args += ['-float-abi=soft']
    args += get_llc_flags_for_abi(ABI)
    args += ['-O2']
    args += [bitcode]
    args += ['-o']
    args += [output]
    ret,text = run_cmd(args)

    if (ABI == 'armeabi' or ABI == 'armeabi-v7a') and USE_GAS:
        o_file = tempfile.NamedTemporaryFile(delete=False)
        ret,text = do_as(output, o_file.name)
        if ret != 0:
            error('Exit status: %d, %s' %(ret, text))
        o_file.close()
        os.rename(o_file.name,output)

    return ret,text

def do_ld(relocatable, output):
    global LD_CMD
    global ABI, PLATFORM
    global SHARED, SONAME, DEPEND_LIBS, LDFLAGS

    arch = get_arch_for_abi(ABI)
    sysroot = sysroot_for_arch(arch)

    args = [LD_CMD]
    args += ['--sysroot='+sysroot]
    args += ['-m']
    args += [get_default_emulation_for_arch(arch)]
    args += ['-Bsymbolic']
    args += ['--eh-frame-hdr']
    args += ['-dynamic-linker']
    args += ['/system/bin/linker']
    args += ['-X']

    if SHARED:
        args += [get_compiler_runtime('crtbegin_so.o')]
    else:
        args += [get_compiler_runtime('crtbegin_dynamic.o')]
    args += [relocatable]
    args += process_ldflags(LDFLAGS)

    args += ['@' + get_compiler_runtime('libportable.wrap')]
    args += [get_compiler_runtime('libportable.a')]
    args += [get_compiler_runtime('libcompiler_rt_static.a')]
    args += [get_compiler_runtime('libgccunwind.a')]
    args += ['-ldl']

    if SHARED:
        args += [get_compiler_runtime('crtend_so.o')]
    else:
        args += [get_compiler_runtime('crtend_android.o')]

    args += ['-o']
    args += [output]

    return run_cmd(args)

def do_compilation():
    global PLATFORM
    global BITCODE, OUTPUT
    global ABI, ARCH
    global VERBOSE, KEEP

    read_bitcode_wrapper(BITCODE)

    bc_file = tempfile.NamedTemporaryFile(delete=False)
    ret,text = do_translate(BITCODE, bc_file.name)
    if ret != 0:
        error('Exit status: %d, %s' %(ret, text))

    o_file = tempfile.NamedTemporaryFile(delete=False)
    ret,text = do_llc(bc_file.name, o_file.name)
    if ret != 0:
        error('Exit status: %d, %s' %(ret, text))

    ret,text = do_ld(o_file.name,OUTPUT)
    if ret != 0:
        error('Exit status: %d, %s' %(ret, text))

    bc_file.close()
    o_file.close()

    # clean up temporary files
    if KEEP == False:
        os.unlink(bc_file.name)
        os.unlink(o_file.name)
    return 0

def main():
    handle_args()
    locate_tools()
    do_compilation()

if __name__ == '__main__':
    main()
