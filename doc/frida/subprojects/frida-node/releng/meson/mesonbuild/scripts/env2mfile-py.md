Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its function, its relevance to reverse engineering, its use of low-level concepts, its logical flow, potential errors, and how a user might arrive at executing it.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly read through the code, looking for keywords and patterns that give clues about its purpose. I see imports like `os`, `subprocess`, `shlex`, `typing`, and names like `MachineInfo`, `compiler`, `linker`, `cross compilation`, `native compilation`, `dpkg-architecture`, environment variables (`CPPFLAGS`, `CFLAGS`, `LDFLAGS`), and output file handling. These strongly suggest a script for generating configuration files, likely related to building software for different target architectures. The presence of `frida` in the file path confirms its connection to the Frida dynamic instrumentation tool.

**2. Identifying the Core Functionality:**

The core functionality appears to be generating "meson" configuration files. Meson is a build system, so this script is creating files that tell Meson how to build software. The arguments (`--cross`, `--native`, `--debarch`, `--gccsuffix`, `-o`, etc.) clearly point towards configuring builds for different architectures and environments. The `MachineInfo` class acts as a data structure to hold information about the target machine.

**3. Relating to Reverse Engineering:**

Now, the crucial step: how does this connect to reverse engineering? Frida is a dynamic instrumentation toolkit used *heavily* in reverse engineering. It allows you to inject JavaScript into running processes to inspect and modify their behavior. The ability to build Frida itself for different target architectures (e.g., an Android device, an embedded Linux system) is essential for using Frida in reverse engineering those targets. Cross-compilation is a *key* technique here.

**Example Generation (Reverse Engineering):**  I think about scenarios where you'd need to build Frida for a different architecture. Imagine you're reversing an Android application. You need to get Frida onto your Android device. This script, when run with the correct cross-compilation flags, would generate the configuration needed to build the Frida agent that runs *on* the Android device.

**4. Identifying Low-Level and Kernel/Framework Connections:**

The script interacts with the underlying operating system through:

* **Environment Variables:** `CPPFLAGS`, `CFLAGS`, `LDFLAGS` are fundamental to the compilation process in Unix-like systems.
* **System Calls (indirectly):**  `subprocess.check_output` executes external commands like `dpkg-architecture`.
* **File System Operations:** `os.path.exists`, `os.path.join`, `open`, `os.replace`.
* **Executable Path:** `os.get_exec_path()` and `shutil.which()` are used to locate executables.

The Debian-specific parts (`dpkg-architecture`) and the mentioning of "kernel" in the command-line arguments hint at the ability to target specific operating systems and even kernel versions during cross-compilation. While the script itself doesn't directly interact with kernel code, the *output* it generates will be used in the build process to create software that *does* interact with the kernel.

**Example Generation (Low-Level):** I consider how cross-compilation works. You need to tell the compiler and linker about the target architecture's libraries, system calls, and ABI (Application Binary Interface). The environment variables and the configuration file this script creates help achieve that.

**5. Logical Inference and Examples:**

I look for conditional logic and data transformations. The `detect_cross_debianlike` function parses the output of `dpkg-architecture`. The `deb_cpu_family_map` and `deb_cpu_map` perform mappings between Debian architecture names and more generic CPU names. The `write_machine_file` function formats the output into a specific structure.

**Hypothetical Input and Output:**  I imagine running the script to cross-compile for ARM Linux. I'd expect the output file to contain compiler paths, linker paths, and architecture-specific flags.

**6. User Errors:**

What are common mistakes a user might make?

* **Incorrect Environment Variables:** Not setting `CPPFLAGS`, `CFLAGS`, etc., correctly for the target architecture.
* **Missing Dependencies:**  Not having the cross-compilation toolchain installed.
* **Typos in Arguments:**  Misspelling command-line options like `--debarch`.
* **Conflicting Options:**  Using both `--cross` and `--native`.

**Example Generation (User Errors):** I think about scenarios where a user might be new to cross-compilation and might not understand the required environment setup.

**7. Tracing User Actions:**

How does a user get to running this script?

* **Setting up the Frida build environment:** This likely involves cloning the Frida repository.
* **Navigating to the script's directory:** `frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/`.
* **Executing the script with `python`:**  `python env2mfile.py`.
* **Providing command-line arguments:**  For example, `--cross --debarch=armhf -o armhf.ini`.
* **Potentially being guided by Frida's build documentation:** The documentation would tell users how to generate these configuration files.

**8. Refinement and Organization:**

Finally, I organize my thoughts into the requested categories, providing clear explanations and concrete examples for each point. I ensure that the language is accurate and avoids jargon where possible (or explains it when necessary). I also review the prompt to make sure I haven't missed any specific requirements. For instance, the prompt asks about "debugging clues." The user action section addresses that by outlining the steps to reach the script, which is essential for debugging build issues.
This Python script, `env2mfile.py`, is part of the Meson build system and its primary function is to **generate a Meson machine file** based on environment variables and command-line arguments. These machine files are crucial for configuring Meson to build software for a specific target architecture, which can be the host system (native build) or a different system (cross-compilation).

Here's a breakdown of its functionalities:

**1. Detecting Build Environment:**

* **Parsing Environment Variables:** The script reads various environment variables like `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, and compiler-specific environment variables (e.g., `CC_FOR_BUILD`, `CXX`). These variables typically hold compiler flags, include paths, and linker flags necessary for building software.
* **Locating Compilers and Binaries:** It attempts to locate compilers (like `gcc`, `g++`) and other essential build tools (like `ar`, `strip`, `objcopy`, `ld`, `cmake`, `pkg-config`) either by directly using the paths specified in environment variables or by searching the system's `PATH`.
* **Debian Architecture Detection:** If the `--debarch` argument is provided (especially set to `auto`), it uses the `dpkg-architecture` command (specific to Debian-based systems) to determine the target architecture's details (CPU, OS, endianness, etc.).

**2. Generating Meson Machine Files:**

* **Structuring Output:** The script creates a text file (specified by the `-o` argument) in the Meson machine file format. This format is essentially a structured INI-like file with sections like `[binaries]`, `[built-in options]`, `[properties]`, `[host_machine]`, and `[cmake]`.
* **Populating Sections:**
    * **`[binaries]`:** Lists the paths to the detected compilers and build tools.
    * **`[built-in options]`:**  Includes compiler and linker flags extracted from environment variables, organized by language (C, C++, Objective-C, etc.).
    * **`[properties]`:** Stores system-specific properties like `pkg_config_libdir` and `sys_root`.
    * **`[host_machine]`:** Defines the target architecture's properties like CPU, CPU family, endianness, system, subsystem, and kernel. This is particularly important for cross-compilation.
    * **`[cmake]`:** If CMake is found, it includes settings for CMake, such as the C and C++ compiler paths and system information.
* **Handling Cross-Compilation:** When the `--cross` argument is used, the script attempts to gather information about the target system. This can be done via `dpkg-architecture` (for Debian-like systems) or by explicitly providing the target system details using arguments like `--system`, `--cpu`, `--endian`, etc.
* **Handling Native Compilation:** When the `--native` argument is used, it assumes the build is for the host system and primarily relies on the environment variables set for the current build environment.

**Relation to Reverse Engineering:**

This script is directly relevant to reverse engineering because **Frida itself needs to be built for the target system you intend to instrument.**

* **Cross-compiling Frida for Android/iOS/Embedded Devices:** When reverse engineering mobile applications or embedded systems, you often need to run Frida on the target device. This requires building the Frida agent (the part that runs on the target) specifically for that device's architecture (e.g., ARM, ARM64). `env2mfile.py` is crucial for generating the Meson machine file that tells Meson how to cross-compile Frida for those target architectures.
    * **Example:** Imagine you want to reverse engineer an Android application running on an ARM64 device. You would need to cross-compile the Frida agent for ARM64 Android. You might run `env2mfile.py` with arguments like `--cross --system=android --cpu=arm64 --endian=little -o android_arm64.ini`, after setting up your cross-compilation toolchain environment variables. This would generate `android_arm64.ini`, which you would then use with Meson to build Frida.

**Binary 底层, Linux, Android 内核及框架知识:**

The script touches upon these areas:

* **Binary 底层 (Binary Low-Level):**
    * **Compiler and Linker Flags:** The environment variables the script parses (`CFLAGS`, `LDFLAGS`, etc.) directly influence how the compiler translates source code into machine code and how the linker combines object files into executables or libraries. These flags can control optimization levels, instruction set architecture, and linking behavior, all of which are fundamental to the binary's structure and execution.
    * **Target Architecture (CPU, Endianness):**  The script handles specifying the target CPU architecture (`--cpu`) and endianness (`--endian`). These are crucial binary-level details as they determine the instruction set the compiled code will use and how multi-byte data is arranged in memory.
* **Linux:**
    * **`dpkg-architecture`:**  The script uses this Debian/Ubuntu specific command to gather information about the target system. This command itself understands the conventions of Debian package management and system architecture definitions on Linux.
    * **Environment Variables:** The reliance on environment variables like `PATH`, `CPPFLAGS`, `LDFLAGS` is a standard practice in Linux build systems.
    * **Executable Paths:** The script's attempts to locate executables using `os.get_exec_path()` reflects how Linux systems manage and find executable files.
* **Android Kernel and Framework (Indirectly):**
    * **Cross-compilation for Android:** When cross-compiling for Android, the generated machine file will define the toolchain and architecture that are compatible with the Android kernel and its userspace framework. While the script itself doesn't directly interact with the Android kernel code, the output it produces is essential for building software (like Frida) that *will* interact with the Android system.
    * **System and CPU specification:**  Using arguments like `--system=android` and `--cpu=arm64` implies an understanding of the target platform's operating system and processor architecture.

**逻辑推理 (Logical Inference):**

The script performs logical inferences based on the provided arguments and environment:

* **Assumption:** If `--debarch` is `auto`, it assumes the `dpkg-architecture` command will provide accurate information about the target system if run in the correct environment.
    * **Hypothetical Input:** User runs the script in a cross-compilation environment on a Debian system with `CPPFLAGS_FOR_BUILD`, `CC_FOR_BUILD`, etc., set for an ARM target, and uses `--cross --debarch=auto -o arm_target.ini`.
    * **Hypothetical Output:** The `arm_target.ini` file will contain compiler paths and flags specific to the ARM target, as detected by `dpkg-architecture`.
* **Conditional Compiler Detection:** The `add_compiler_if_missing` function checks if a compiler for a specific language is already defined. If not, it tries to locate common compiler names.
    * **Hypothetical Input:**  Environment variables don't explicitly define the C++ compiler, but `g++` is on the system's `PATH`.
    * **Hypothetical Output:** The generated machine file's `[binaries]` section will include the path to `g++`.
* **Cross vs. Native:** The script enforces the logical constraint that you can only specify either `--cross` or `--native`, not both, as a build cannot be simultaneously cross and native.

**用户或编程常见的使用错误 (Common User/Programming Errors):**

* **Incorrect or Missing Environment Variables:**
    * **Example:**  User wants to cross-compile for ARM but forgets to set the `PATH` to include the ARM cross-compiler toolchain binaries (e.g., `arm-linux-gnueabihf-gcc`). The script might then fail to locate the compiler or use the host system's compiler, leading to build errors.
* **Mismatched Arguments and Environment:**
    * **Example:** User provides `--cpu=arm` but their environment variables (`CPPFLAGS`, `LDFLAGS`) are set up for an x86 target. This inconsistency will lead to a machine file that doesn't accurately reflect the intended target.
* **Specifying Both `--cross` and `--native`:**
    * **Example:** User mistakenly runs `python env2mfile.py --cross --native -o my_config.ini`. The script will exit with an error message: "You can only specify either --cross or --native, not both."
* **Typos in Arguments:**
    * **Example:** User types `--cros` instead of `--cross`. The script won't recognize the argument and might behave unexpectedly or fail.
* **Forgetting to Install Cross-Compilation Toolchain:**
    * **Example:** User tries to cross-compile for Android but hasn't installed the Android NDK or a suitable cross-compilation toolchain. The script might not find the necessary compilers and tools.

**用户操作是如何一步步的到达这里 (User Steps to Reach This Point):**

As a debugging clue, here's how a user might end up running this script:

1. **Trying to build Frida for a non-host architecture:** The user wants to use Frida on a device with a different architecture than their development machine (e.g., an Android phone, an IoT device).
2. **Consulting Frida's documentation or build instructions:** Frida's documentation will guide users on how to build for different targets, likely mentioning the need to generate a Meson machine file for the target architecture.
3. **Navigating to the relevant directory:** The documentation or build scripts would instruct the user to go to the `frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/` directory within the Frida source code.
4. **Identifying `env2mfile.py`:** The user sees this script and understands (or is instructed) that it's responsible for generating the machine file.
5. **Setting up the necessary environment variables:**  Based on the target architecture, the user would need to set environment variables like `PATH` to include the cross-compilation toolchain, and potentially `CPPFLAGS`, `CFLAGS`, `LDFLAGS` to provide specific compilation flags for the target.
6. **Executing the script with appropriate arguments:** The user would run the script from the command line, providing arguments like `--cross`, `--debarch` (if on Debian), `--system`, `--cpu`, `--endian`, and `-o` to specify the output file name. For example:
   ```bash
   python env2mfile.py --cross --debarch=armhf -o frida_armhf.ini
   ```
   or for a more generic cross-compilation:
   ```bash
   python env2mfile.py --cross --system=linux --cpu=arm --endian=little -o frida_arm.ini
   ```
7. **Using the generated machine file with Meson:** After generating the machine file, the user would then use it with Meson to configure the Frida build:
   ```bash
   meson builddir --cross-file frida_armhf.ini
   ```
   or
   ```bash
   meson builddir --cross-file frida_arm.ini
   ```
8. **Proceeding with the build:** Finally, the user would run the actual build command:
   ```bash
   ninja -C builddir
   ```

By understanding these steps, developers can effectively troubleshoot issues related to building Frida for different architectures and understand the role of `env2mfile.py` in that process.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 The Meson development team

from __future__ import annotations

import sys, os, subprocess, shutil
import shlex
import typing as T

from .. import envconfig
from .. import mlog
from ..compilers import compilers
from ..compilers.detect import defaults as compiler_names

if T.TYPE_CHECKING:
    import argparse

def has_for_build() -> bool:
    for cenv in envconfig.ENV_VAR_COMPILER_MAP.values():
        if os.environ.get(cenv + '_FOR_BUILD'):
            return True
    return False

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: 'argparse.ArgumentParser') -> None:
    parser.add_argument('--debarch', default=None,
                        help='The dpkg architecture to generate.')
    parser.add_argument('--gccsuffix', default="",
                        help='A particular gcc version suffix if necessary.')
    parser.add_argument('-o', required=True, dest='outfile',
                        help='The output file.')
    parser.add_argument('--cross', default=False, action='store_true',
                        help='Generate a cross compilation file.')
    parser.add_argument('--native', default=False, action='store_true',
                        help='Generate a native compilation file.')
    parser.add_argument('--system', default=None,
                        help='Define system for cross compilation.')
    parser.add_argument('--subsystem', default=None,
                        help='Define subsystem for cross compilation.')
    parser.add_argument('--kernel', default=None,
                        help='Define kernel for cross compilation.')
    parser.add_argument('--cpu', default=None,
                        help='Define cpu for cross compilation.')
    parser.add_argument('--cpu-family', default=None,
                        help='Define cpu family for cross compilation.')
    parser.add_argument('--endian', default='little', choices=['big', 'little'],
                        help='Define endianness for cross compilation.')

class MachineInfo:
    def __init__(self) -> None:
        self.compilers: T.Dict[str, T.List[str]] = {}
        self.binaries: T.Dict[str, T.List[str]] = {}
        self.properties: T.Dict[str, T.Union[str, T.List[str]]] = {}
        self.compile_args: T.Dict[str, T.List[str]] = {}
        self.link_args: T.Dict[str, T.List[str]] = {}
        self.cmake: T.Dict[str, T.Union[str, T.List[str]]] = {}

        self.system: T.Optional[str] = None
        self.subsystem: T.Optional[str] = None
        self.kernel: T.Optional[str] = None
        self.cpu: T.Optional[str] = None
        self.cpu_family: T.Optional[str] = None
        self.endian: T.Optional[str] = None

#parser = argparse.ArgumentParser(description='''Generate cross compilation definition file for the Meson build system.
#
#If you do not specify the --arch argument, Meson assumes that running
#plain 'dpkg-architecture' will return correct information for the
#host system.
#
#This script must be run in an environment where CPPFLAGS et al are set to the
#same values used in the actual compilation.
#'''
#)

def locate_path(program: str) -> T.List[str]:
    if os.path.isabs(program):
        return [program]
    for d in os.get_exec_path():
        f = os.path.join(d, program)
        if os.access(f, os.X_OK):
            return [f]
    raise ValueError("%s not found on $PATH" % program)

def write_args_line(ofile: T.TextIO, name: str, args: T.Union[str, T.List[str]]) -> None:
    if len(args) == 0:
        return
    if isinstance(args, str):
        ostr = name + "= '" + args + "'\n"
    else:
        ostr = name + ' = ['
        ostr += ', '.join("'" + i + "'" for i in args)
        ostr += ']\n'
    ofile.write(ostr)

def get_args_from_envvars(infos: MachineInfo) -> None:
    cppflags = shlex.split(os.environ.get('CPPFLAGS', ''))
    cflags = shlex.split(os.environ.get('CFLAGS', ''))
    cxxflags = shlex.split(os.environ.get('CXXFLAGS', ''))
    objcflags = shlex.split(os.environ.get('OBJCFLAGS', ''))
    objcxxflags = shlex.split(os.environ.get('OBJCXXFLAGS', ''))
    ldflags = shlex.split(os.environ.get('LDFLAGS', ''))

    c_args = cppflags + cflags
    cpp_args = cppflags + cxxflags
    c_link_args = cflags + ldflags
    cpp_link_args = cxxflags + ldflags

    objc_args = cppflags + objcflags
    objcpp_args = cppflags + objcxxflags
    objc_link_args = objcflags + ldflags
    objcpp_link_args = objcxxflags + ldflags

    if c_args:
        infos.compile_args['c'] = c_args
    if c_link_args:
        infos.link_args['c'] = c_link_args
    if cpp_args:
        infos.compile_args['cpp'] = cpp_args
    if cpp_link_args:
        infos.link_args['cpp'] = cpp_link_args
    if objc_args:
        infos.compile_args['objc'] = objc_args
    if objc_link_args:
        infos.link_args['objc'] = objc_link_args
    if objcpp_args:
        infos.compile_args['objcpp'] = objcpp_args
    if objcpp_link_args:
        infos.link_args['objcpp'] = objcpp_link_args

deb_cpu_family_map = {
    'mips64el': 'mips64',
    'i686': 'x86',
    'powerpc64le': 'ppc64',
}

deb_cpu_map = {
    'armhf': 'arm7hlf',
    'mips64el': 'mips64',
    'powerpc64le': 'ppc64',
}

def deb_detect_cmake(infos: MachineInfo, data: T.Dict[str, str]) -> None:
    system_name_map = {'linux': 'Linux', 'kfreebsd': 'kFreeBSD', 'hurd': 'GNU'}
    system_processor_map = {'arm': 'armv7l', 'mips64el': 'mips64', 'powerpc64le': 'ppc64le'}

    infos.cmake["CMAKE_C_COMPILER"] = infos.compilers['c']
    try:
        infos.cmake["CMAKE_CXX_COMPILER"] = infos.compilers['cpp']
    except KeyError:
        pass
    infos.cmake["CMAKE_SYSTEM_NAME"] = system_name_map[data['DEB_HOST_ARCH_OS']]
    infos.cmake["CMAKE_SYSTEM_PROCESSOR"] = system_processor_map.get(data['DEB_HOST_GNU_CPU'],
                                                                     data['DEB_HOST_GNU_CPU'])

def deb_compiler_lookup(infos: MachineInfo, compilerstems: T.List[T.Tuple[str, str]], host_arch: str, gccsuffix: str) -> None:
    for langname, stem in compilerstems:
        compilername = f'{host_arch}-{stem}{gccsuffix}'
        try:
            p = locate_path(compilername)
            infos.compilers[langname] = p
        except ValueError:
            pass

def detect_cross_debianlike(options: T.Any) -> MachineInfo:
    if options.debarch == 'auto':
        cmd = ['dpkg-architecture']
    else:
        cmd = ['dpkg-architecture', '-a' + options.debarch]
    output = subprocess.check_output(cmd, universal_newlines=True,
                                     stderr=subprocess.DEVNULL)
    data = {}
    for line in output.split('\n'):
        line = line.strip()
        if line == '':
            continue
        k, v = line.split('=', 1)
        data[k] = v
    host_arch = data['DEB_HOST_GNU_TYPE']
    host_os = data['DEB_HOST_ARCH_OS']
    host_subsystem = host_os
    host_kernel = 'linux'
    host_cpu_family = deb_cpu_family_map.get(data['DEB_HOST_GNU_CPU'],
                                             data['DEB_HOST_GNU_CPU'])
    host_cpu = deb_cpu_map.get(data['DEB_HOST_ARCH'],
                               data['DEB_HOST_ARCH'])
    host_endian = data['DEB_HOST_ARCH_ENDIAN']

    compilerstems = [('c', 'gcc'),
                     ('cpp', 'g++'),
                     ('objc', 'gobjc'),
                     ('objcpp', 'gobjc++')]
    infos = MachineInfo()
    deb_compiler_lookup(infos, compilerstems, host_arch, options.gccsuffix)
    if len(infos.compilers) == 0:
        print('Warning: no compilers were detected.')
    infos.binaries['ar'] = locate_path("%s-ar" % host_arch)
    infos.binaries['strip'] = locate_path("%s-strip" % host_arch)
    infos.binaries['objcopy'] = locate_path("%s-objcopy" % host_arch)
    infos.binaries['ld'] = locate_path("%s-ld" % host_arch)
    try:
        infos.binaries['cmake'] = locate_path("cmake")
        deb_detect_cmake(infos, data)
    except ValueError:
        pass
    try:
        infos.binaries['pkg-config'] = locate_path("%s-pkg-config" % host_arch)
    except ValueError:
        pass # pkg-config is optional
    try:
        infos.binaries['cups-config'] = locate_path("cups-config")
    except ValueError:
        pass
    infos.system = host_os
    infos.subsystem = host_subsystem
    infos.kernel = host_kernel
    infos.cpu_family = host_cpu_family
    infos.cpu = host_cpu
    infos.endian = host_endian

    get_args_from_envvars(infos)
    return infos

def write_machine_file(infos: MachineInfo, ofilename: str, write_system_info: bool) -> None:
    tmpfilename = ofilename + '~'
    with open(tmpfilename, 'w', encoding='utf-8') as ofile:
        ofile.write('[binaries]\n')
        ofile.write('# Compilers\n')
        for langname in sorted(infos.compilers.keys()):
            compiler = infos.compilers[langname]
            write_args_line(ofile, langname, compiler)
        ofile.write('\n')

        ofile.write('# Other binaries\n')
        for exename in sorted(infos.binaries.keys()):
            exe = infos.binaries[exename]
            write_args_line(ofile, exename, exe)
        ofile.write('\n')

        ofile.write('[built-in options]\n')
        all_langs = list(set(infos.compile_args.keys()).union(set(infos.link_args.keys())))
        all_langs.sort()
        for lang in all_langs:
            if lang in infos.compile_args:
                write_args_line(ofile, lang + '_args', infos.compile_args[lang])
            if lang in infos.link_args:
                write_args_line(ofile, lang + '_link_args', infos.link_args[lang])
        ofile.write('\n')

        ofile.write('[properties]\n')
        for k, v in infos.properties.items():
            write_args_line(ofile, k, v)
        ofile.write('\n')

        if infos.cmake:
            ofile.write('[cmake]\n\n')
            for k, v in infos.cmake.items():
                write_args_line(ofile, k, v)
            ofile.write('\n')

        if write_system_info:
            ofile.write('[host_machine]\n')
            ofile.write(f"cpu = '{infos.cpu}'\n")
            ofile.write(f"cpu_family = '{infos.cpu_family}'\n")
            ofile.write(f"endian = '{infos.endian}'\n")
            ofile.write(f"system = '{infos.system}'\n")
            if infos.subsystem:
                ofile.write(f"subsystem = '{infos.subsystem}'\n")
            if infos.kernel:
                ofile.write(f"kernel = '{infos.kernel}'\n")

    os.replace(tmpfilename, ofilename)

def detect_language_args_from_envvars(langname: str, envvar_suffix: str = '') -> T.Tuple[T.List[str], T.List[str]]:
    compile_args = []
    if langname in compilers.CFLAGS_MAPPING:
        compile_args = shlex.split(os.environ.get(compilers.CFLAGS_MAPPING[langname] + envvar_suffix, ''))
    if langname in compilers.LANGUAGES_USING_CPPFLAGS:
        cppflags = tuple(shlex.split(os.environ.get('CPPFLAGS' + envvar_suffix, '')))
        lang_compile_args = list(cppflags) + compile_args
    else:
        lang_compile_args = compile_args
    lang_link_args = []
    if langname in compilers.LANGUAGES_USING_LDFLAGS:
        lang_link_args += shlex.split(os.environ.get('LDFLAGS' + envvar_suffix, ''))
    lang_link_args += compile_args
    return (lang_compile_args, lang_link_args)

def detect_compilers_from_envvars(envvar_suffix: str = '') -> MachineInfo:
    infos = MachineInfo()
    for langname, envvarname in envconfig.ENV_VAR_COMPILER_MAP.items():
        compilerstr = os.environ.get(envvarname + envvar_suffix)
        if not compilerstr:
            continue
        if os.path.exists(compilerstr):
            compiler = [compilerstr]
        else:
            compiler = shlex.split(compilerstr)
        infos.compilers[langname] = compiler
        lang_compile_args, lang_link_args = detect_language_args_from_envvars(langname, envvar_suffix)
        if lang_compile_args:
            infos.compile_args[langname] = lang_compile_args
        if lang_link_args:
            infos.link_args[langname] = lang_link_args
    return infos

def detect_binaries_from_envvars(infos: MachineInfo, envvar_suffix: str = '') -> None:
    for binname, envvar_base in envconfig.ENV_VAR_TOOL_MAP.items():
        envvar = envvar_base + envvar_suffix
        binstr = os.environ.get(envvar)
        if binstr:
            infos.binaries[binname] = shlex.split(binstr)

def detect_properties_from_envvars(infos: MachineInfo, envvar_suffix: str = '') -> None:
    var = os.environ.get('PKG_CONFIG_LIBDIR' + envvar_suffix)
    if var is not None:
        infos.properties['pkg_config_libdir'] = var
    var = os.environ.get('PKG_CONFIG_SYSROOT_DIR' + envvar_suffix)
    if var is not None:
        infos.properties['sys_root'] = var

def detect_cross_system(infos: MachineInfo, options: T.Any) -> None:
    for optname in ('system', 'subsystem', 'kernel', 'cpu', 'cpu_family', 'endian'):
        v = getattr(options, optname)
        if not v:
            mlog.error(f'Cross property "{optname}" missing, set it with --{optname.replace("_", "-")}.')
            sys.exit(1)
        setattr(infos, optname, v)

def detect_cross_env(options: T.Any) -> MachineInfo:
    if options.debarch:
        print('Detecting cross environment via dpkg-reconfigure.')
        infos = detect_cross_debianlike(options)
    else:
        print('Detecting cross environment via environment variables.')
        infos = detect_compilers_from_envvars()
        detect_cross_system(infos, options)
    detect_binaries_from_envvars(infos)
    detect_properties_from_envvars(infos)
    return infos

def add_compiler_if_missing(infos: MachineInfo, langname: str, exe_names: T.List[str]) -> None:
    if langname in infos.compilers:
        return
    for exe_name in exe_names:
        lookup = shutil.which(exe_name)
        if not lookup:
            continue
        compflags, linkflags = detect_language_args_from_envvars(langname)
        infos.compilers[langname] = [lookup]
        if compflags:
            infos.compile_args[langname] = compflags
        if linkflags:
            infos.link_args[langname] = linkflags
        return

def detect_missing_native_compilers(infos: MachineInfo) -> None:
    # T.Any per-platform special detection should go here.
    for langname, exes in compiler_names.items():
        if langname not in envconfig.ENV_VAR_COMPILER_MAP:
            continue
        add_compiler_if_missing(infos, langname, exes)

def detect_missing_native_binaries(infos: MachineInfo) -> None:
    # T.Any per-platform special detection should go here.
    for toolname in sorted(envconfig.ENV_VAR_TOOL_MAP.keys()):
        if toolname in infos.binaries:
            continue
        exe = shutil.which(toolname)
        if exe:
            infos.binaries[toolname] = [exe]

def detect_native_env(options: T.Any) -> MachineInfo:
    use_for_build = has_for_build()
    if use_for_build:
        mlog.log('Using FOR_BUILD envvars for detection')
        esuffix = '_FOR_BUILD'
    else:
        mlog.log('Using regular envvars for detection.')
        esuffix = ''
    infos = detect_compilers_from_envvars(esuffix)
    detect_missing_native_compilers(infos)
    detect_binaries_from_envvars(infos, esuffix)
    detect_missing_native_binaries(infos)
    detect_properties_from_envvars(infos, esuffix)
    return infos

def run(options: T.Any) -> None:
    if options.cross and options.native:
        sys.exit('You can only specify either --cross or --native, not both.')
    if not options.cross and not options.native:
        sys.exit('You must specify --cross or --native.')
    mlog.notice('This functionality is experimental and subject to change.')
    detect_cross = options.cross
    if detect_cross:
        infos = detect_cross_env(options)
        write_system_info = True
    else:
        infos = detect_native_env(options)
        write_system_info = False
    write_machine_file(infos, options.outfile, write_system_info)

"""

```