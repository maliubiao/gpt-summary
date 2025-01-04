Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - What is the Goal?**

The first lines of the script and the command-line arguments give a strong clue: it generates a cross-compilation definition file for the Meson build system. The filename `env2mfile.py` further suggests it's converting environment variables into a Meson file format. The presence of `--cross` and `--native` flags solidifies the idea that it handles both native and cross-compilation scenarios.

**2. Deconstructing the Functionality - Top-Down Approach**

I'll start by examining the main `run` function, as it orchestrates the script's execution.

*   **`run(options)`:**
    *   Checks for mutual exclusivity of `--cross` and `--native`.
    *   Requires either `--cross` or `--native`.
    *   Prints a warning about experimental status.
    *   Calls either `detect_cross_env` or `detect_native_env` based on the flags.
    *   Calls `write_machine_file` to output the result.

*   **`detect_cross_env(options)`:**
    *   If `--debarch` is provided (likely related to Debian/Ubuntu cross-compilation), it calls `detect_cross_debianlike`.
    *   Otherwise, it calls `detect_compilers_from_envvars` and `detect_cross_system`.
    *   It then calls `detect_binaries_from_envvars` and `detect_properties_from_envvars`.

*   **`detect_native_env(options)`:**
    *   Checks for `_FOR_BUILD` environment variables (indicating a "for build" host).
    *   Calls `detect_compilers_from_envvars`, `detect_missing_native_compilers`, `detect_binaries_from_envvars`, `detect_missing_native_binaries`, and `detect_properties_from_envvars`.

*   **`write_machine_file(infos, ofilename, write_system_info)`:**
    *   Writes the collected information (compilers, binaries, arguments, properties, etc.) into a file in Meson's specific format.

**3. Diving Deeper - Examining Key Functions and Concepts**

Now I'll look at individual functions and data structures that perform specific tasks:

*   **`MachineInfo` class:** This is a crucial data structure holding all the information about the target machine (compilers, binaries, flags, etc.). It's the central repository of the detected environment.

*   **`detect_compilers_from_envvars`:** This function is essential for understanding how the script interacts with environment variables. It iterates through predefined environment variables (like `CC`, `CXX`, etc.) and attempts to locate the corresponding compilers.

*   **`detect_cross_debianlike`:** This function uses `dpkg-architecture`, a Debian/Ubuntu specific tool, to gather cross-compilation information. This indicates OS-specific handling.

*   **`locate_path`:** A utility function to find executable programs in the system's `PATH`.

*   **`shlex.split`:**  Used to parse space-separated arguments from environment variables.

**4. Connecting to Reverse Engineering Concepts**

At this point, I'll consider how the script relates to reverse engineering:

*   **Cross-compilation:**  Crucial for reverse engineering on platforms different from the development machine (e.g., analyzing Android binaries on a Linux desktop).
*   **Environment variables:** Understanding how build systems use environment variables is helpful in replicating build environments for analysis.
*   **Binary tools:** The script deals with tools like `ar`, `strip`, `objcopy`, `ld`, which are commonly used in reverse engineering for examining and manipulating binaries.

**5. Identifying Binary/OS/Kernel/Framework Relationships**

*   **Binary Level:** The script directly deals with finding and using binary executables (compilers, linkers, archivers, etc.).
*   **Linux:** The `dpkg-architecture` dependency in `detect_cross_debianlike` explicitly links to Linux (specifically Debian/Ubuntu). The use of `$PATH` is also a Linux/Unix concept.
*   **Android:** While not explicitly mentioned, the context of Frida strongly suggests that this script is used in its build process, which often involves cross-compiling for Android. The concepts of cross-compilation and dealing with specific architectures are fundamental to Android reverse engineering.
*   **Kernel/Framework:**  The `--system`, `--subsystem`, and `--kernel` arguments in `add_arguments` hint at the ability to specify target operating system details, which can include kernel information. For Android, the "subsystem" could relate to the Android runtime environment.

**6. Logical Reasoning and Examples**

*   **Assumption:** The user has set environment variables correctly for their target platform.
*   **Input (example):**
    *   `CC_FOR_ARM=arm-linux-gnueabihf-gcc`
    *   `CXX_FOR_ARM=arm-linux-gnueabihf-g++`
    *   Command-line: `python env2mfile.py --cross --cpu arm --cpu-family arm --system linux --endian little -o arm.meson`
*   **Output (partial `arm.meson`):**
    ```meson
    [binaries]
    c = ['arm-linux-gnueabihf-gcc']
    cpp = ['arm-linux-gnueabihf-g++']

    [host_machine]
    cpu = 'arm'
    cpu_family = 'arm'
    endian = 'little'
    system = 'linux'
    ```

**7. Common User Errors**

*   **Incorrect or missing environment variables:** If `CC_FOR_ARM` isn't set, the script won't find the ARM compiler.
*   **Specifying both `--cross` and `--native`:** The script explicitly prevents this.
*   **Not specifying `--cross` or `--native`:** The script requires one of these.
*   **Typos in command-line arguments:** `--cpu-famly` instead of `--cpu-family`.

**8. Debugging Lineage**

The user arrives at this script by wanting to build Frida for a target platform. The typical steps would be:

1. Clone the Frida repository.
2. Configure the build environment for the target (setting environment variables).
3. Run Meson to configure the build. Meson, in turn, might execute this `env2mfile.py` script to generate the target environment configuration file based on the provided flags and environment variables.

This step-by-step analysis covers the key aspects of the script, providing a comprehensive understanding of its functionality and its relationship to reverse engineering, system-level concepts, and potential user errors.
This Python script, `env2mfile.py`, is a utility designed to generate Meson build system configuration files based on environment variables and command-line arguments. These configuration files define the build environment, especially for cross-compilation scenarios. Here's a breakdown of its functionality:

**Functionality:**

1. **Detects Compiler and Binary Paths:** It searches for compiler and other essential binary tool paths (like `ar`, `strip`, `objcopy`, `ld`) based on environment variables (e.g., `CC`, `CXX`, `AR`, etc.) and the system's `PATH`. It can distinguish between native and cross-compilation tools based on suffixes like `_FOR_BUILD`.
2. **Extracts Compiler and Linker Flags:** It retrieves compiler-specific and linker-specific flags from environment variables like `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, `CPPFLAGS`, etc.
3. **Generates Meson Machine Files:**  It outputs a text file in Meson's configuration file format (`.meson`) containing sections for:
    *   `[binaries]`:  Specifies the paths to compilers and other build tools.
    *   `[built-in options]`: Defines compiler and linker flags for different languages.
    *   `[properties]`:  Stores miscellaneous build properties (e.g., `pkg_config_libdir`, `sys_root`).
    *   `[cmake]`:  Potentially includes CMake-related configuration if CMake is detected.
    *   `[host_machine]`: (For cross-compilation) Describes the target machine's architecture (CPU, CPU family, endianness, system, kernel, subsystem).
4. **Supports Cross-Compilation:**  It's primarily designed for creating cross-compilation setup files. It takes arguments like `--cross`, `--system`, `--cpu`, `--endian`, etc., to define the target architecture. It can also leverage `dpkg-architecture` on Debian-like systems to automatically detect cross-compilation settings.
5. **Supports Native Compilation:** It can also generate configuration files for native builds, detecting compilers and flags from the standard environment variables.
6. **Handles "For Build" Environments:** It recognizes environment variables with the suffix `_FOR_BUILD`, which are used when building tools that will run on the host system during the main target build (e.g., a code generator).
7. **Provides CMake Integration (Limited):** It attempts to detect the `cmake` executable and can include basic CMake configuration in the output file.

**Relationship to Reverse Engineering:**

This script is directly relevant to reverse engineering, especially when dealing with compiled code for different architectures or operating systems. Here's how:

*   **Setting up Cross-Compilation Environments:** Reverse engineers often need to build tools and libraries for the target platform they are analyzing. For example, if you're reverse engineering an Android application (running on ARM architecture), you might need to compile Frida's core components for ARM on your x86 development machine. This script helps automate the creation of the necessary Meson configuration file for this cross-compilation process.
*   **Example:** Let's say you want to build Frida for an Android device with an ARM64 architecture. You might set environment variables like:
    ```bash
    export CC_FOR_ARM64=aarch64-linux-gnu-gcc
    export CXX_FOR_ARM64=aarch64-linux-gnu-g++
    export AR_FOR_ARM64=aarch64-linux-gnu-ar
    # ... other necessary variables ...
    ```
    Then, running the script with the `--cross` flag and architecture-specific arguments would generate a `meson` file that tells the build system to use these specific ARM64 toolchains.
*   **Replicating Build Environments:**  Understanding the compiler flags and toolchain used to build a target application is crucial for accurate analysis. This script helps in capturing those settings, which can be useful for reproducing the build environment for further analysis or manipulation of the target binary.

**Binary Bottom, Linux, Android Kernel and Framework Knowledge:**

This script interacts with several low-level concepts:

*   **Binary Bottom:** It directly deals with executables (compilers, linkers, archivers) which operate on binary files. It needs to locate these binaries and understand how to invoke them.
*   **Linux:**
    *   **Environment Variables:** The script heavily relies on environment variables, a fundamental concept in Linux and other Unix-like systems for configuring processes.
    *   **`PATH` Environment Variable:**  It uses `os.get_exec_path()` to search for executables in the directories listed in the `PATH` environment variable.
    *   **`dpkg-architecture`:**  The script uses the `dpkg-architecture` command, specific to Debian-based Linux distributions, to retrieve information about the target architecture for cross-compilation.
    *   **Shell Commands:** It uses `subprocess.check_output` to execute external commands like `dpkg-architecture`.
*   **Android Kernel and Framework (Indirectly):** While the script itself doesn't directly interact with the Android kernel or framework code, its purpose is to facilitate building tools (like Frida) that *do* interact with them. When cross-compiling for Android:
    *   The `--system`, `--kernel`, `--cpu`, `--cpu-family`, and `--endian` arguments are crucial for specifying the target Android platform's architecture, which is directly related to the kernel it runs on (typically Linux-based).
    *   The environment variables used (e.g., pointing to ARM compilers) are specific to the Android target architecture.
    *   The generated `meson` file will configure the build process to produce binaries compatible with the Android environment.

**Logical Reasoning with Assumptions, Input, and Output:**

**Assumption:** The user has correctly installed the necessary cross-compilation toolchain (e.g., `aarch64-linux-gnu-gcc`).

**Input:**

```bash
export CC_FOR_ARM=arm-linux-gnueabihf-gcc
export CXX_FOR_ARM=arm-linux-gnueabihf-g++
python frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/env2mfile.py \
    -o my_arm_config.meson --cross --system linux --cpu arm --endian little
```

**Output (`my_arm_config.meson`):**

```meson
[binaries]
c = ['arm-linux-gnueabihf-gcc']
cpp = ['arm-linux-gnueabihf-g++']

[built-in options]

[properties]

[host_machine]
cpu = 'arm'
cpu_family = 'armv7l'  # Might be inferred or need explicit setting
endian = 'little'
system = 'linux'
```

**User or Programming Common Usage Errors:**

1. **Incorrect Environment Variables:**
    *   **Mistyping:** `CC_FOR_AMR` instead of `CC_FOR_ARM`.
    *   **Not Setting:** Forgetting to `export CC_FOR_ARM` before running the script.
    *   **Pointing to Wrong Binaries:** The environment variable points to an invalid or incorrect compiler executable.
2. **Conflicting or Missing Command-Line Arguments:**
    *   **Specifying both `--cross` and `--native`:** The script explicitly prevents this.
    *   **Forgetting required arguments for cross-compilation:** Running with `--cross` but not providing `--system` or `--cpu`. The script will likely error out or produce an incomplete configuration.
3. **Running in the Wrong Environment:** Running the script without the necessary cross-compilation toolchain installed or without the correct environment variables set.
4. **File Permissions:** Not having execute permissions on the compiler binaries specified in the environment variables.

**User Operation Steps to Reach This Script (Debugging Lineage):**

1. **Decide to Build Frida for a Different Architecture:** A developer or reverse engineer wants to use Frida on a device with a different architecture than their development machine (e.g., building Frida for an Android ARM device from an x86 Linux machine).
2. **Consult Frida's Build Instructions:** They would consult Frida's documentation, which would guide them to use the Meson build system.
3. **Understand Cross-Compilation Requirements:** The documentation or general knowledge of cross-compilation would indicate the need for a cross-compiler toolchain and a way to configure Meson for the target architecture.
4. **Identify `env2mfile.py`:** The build instructions might explicitly mention running `env2mfile.py` or the user might find it within the Frida build scripts as part of the cross-compilation setup process.
5. **Set Environment Variables:** Based on the target architecture, the user would set appropriate environment variables pointing to the cross-compilation toolchain (e.g., `CC_FOR_ARM`, `CXX_FOR_ARM`).
6. **Execute `env2mfile.py`:** The user would then run the `env2mfile.py` script, providing the necessary command-line arguments (like `--cross`, `--system`, `--cpu`, `-o output_file.meson`) to generate the Meson configuration file.
7. **Use the Generated File with Meson:** Finally, the user would use the generated `.meson` file when configuring the Frida build with Meson (e.g., `meson setup builddir --cross-file my_arm_config.meson`).

In essence, `env2mfile.py` is a crucial helper script in Frida's build system (and potentially other Meson-based projects) that simplifies the often complex task of setting up cross-compilation environments by leveraging environment variables and providing a structured way to define the target platform's characteristics for the build system.

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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