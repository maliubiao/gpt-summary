Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the script's name: `env2mfile.py`. The comments mention generating "cross compilation definition file for the Meson build system". This immediately tells us the script's main goal is to create a file that Meson can use to understand how to compile code for a different target architecture (cross-compilation). The `env2mfile` name suggests it takes information from environment variables.

**2. Identifying Key Functionalities by Section/Function Analysis:**

Next, we systematically go through the code, function by function, and identify what each part does.

* **Imports:**  Look at the imported modules (`sys`, `os`, `subprocess`, `shutil`, `shlex`, `typing`). These give clues about the script's operations: interacting with the system (environment, paths, processes), file manipulation, and command-line argument parsing (`shlex`). The `typing` module indicates type hinting for better code readability and maintainability.

* **`has_for_build()`:** This function checks for environment variables with a `_FOR_BUILD` suffix. This hints at a mechanism to differentiate between the build host and the target environment.

* **`add_arguments()`:** This is clearly related to command-line argument parsing using `argparse`. It defines the possible options users can pass to the script (like `--debarch`, `--gccsuffix`, `-o`, `--cross`, `--native`, etc.).

* **`MachineInfo` Class:**  This class acts as a data structure to hold information about the target machine. The attributes (`compilers`, `binaries`, `properties`, `compile_args`, `link_args`, `cmake`, `system`, `subsystem`, etc.) directly relate to what a build system needs to know for compilation.

* **`locate_path()`:** This function searches for an executable in the system's `PATH`. This is crucial for finding compilers and other build tools.

* **`write_args_line()`:**  This helper function formats and writes key-value pairs to the output file, which is the Meson definition file.

* **`get_args_from_envvars()`:** This function extracts compiler flags and linker flags from standard environment variables (`CPPFLAGS`, `CFLAGS`, `LDFLAGS`, etc.). This reinforces the idea that the script uses the environment to gather information.

* **`deb_*` Functions (`deb_detect_cmake`, `deb_compiler_lookup`, `detect_cross_debianlike()`):** The `deb` prefix strongly suggests these functions are specific to Debian-like systems and how they handle cross-compilation (using `dpkg-architecture`).

* **`detect_cross_system()`:** This function deals with the command-line options related to specifying cross-compilation target properties like system, CPU, endianness, etc.

* **`detect_cross_env()`:** This function orchestrates the detection of cross-compilation settings, potentially using Debian-specific tools or generic environment variables.

* **`detect_language_args_from_envvars()`:**  This function seems to extract language-specific compiler and linker arguments based on environment variables.

* **`detect_compilers_from_envvars()`, `detect_binaries_from_envvars()`, `detect_properties_from_envvars()`:** These functions are responsible for populating the `MachineInfo` object by looking for specific environment variables related to compilers, binaries (like `ar`, `strip`), and other properties (like `pkg-config` paths).

* **`detect_missing_native_compilers()`, `detect_missing_native_binaries()`:** These functions appear to fill in the gaps for native compilation by searching for common compiler and binary names using `shutil.which()`.

* **`detect_native_env()`:** This function handles the detection of settings for native compilation (compiling for the same architecture as the build machine). It utilizes the `_FOR_BUILD` suffixed environment variables if `has_for_build()` returns `True`.

* **`run()`:** This is the main entry point of the script. It parses command-line arguments and calls the appropriate detection functions (`detect_cross_env` or `detect_native_env`) and the writing function (`write_machine_file`).

**3. Identifying Connections to Reverse Engineering, Binaries, Kernels, etc.:**

As we go through the functions, we look for keywords and concepts related to the prompt:

* **Reverse Engineering:** The script itself isn't a reverse engineering tool. However, the *output* it generates (the Meson cross-compilation file) is crucial for *building* tools that *could* be used for reverse engineering on a target platform (like Frida itself). Cross-compilation allows developers to build software for architectures different from their development machine, which is a common scenario in reverse engineering embedded devices or mobile platforms.

* **Binary Underpinnings:** The script directly deals with finding compilers and linkers (`gcc`, `g++`, `ld`). It also handles tools like `ar` (archiver), `strip` (removes symbols from binaries), and `objcopy` (copies and translates object files). These are fundamental tools in the binary world.

* **Linux/Android Kernel & Framework:**  The script has specific logic for Debian-like systems (`dpkg-architecture`). While not directly manipulating the kernel, understanding target operating systems (like Linux) and their conventions is essential for cross-compilation. The `system`, `subsystem`, and `kernel` options in the `MachineInfo` class and command-line arguments indicate awareness of these concepts. For Android, while not explicitly mentioned in detail, the concept of cross-compiling Frida for Android devices is the underlying motivation for this kind of tool.

**4. Logical Reasoning and Examples:**

Once we understand the functionality, we can start forming hypotheses about inputs and outputs:

* **Hypothesis:** If the user provides `--cross` and sets environment variables like `CC_FOR_BUILD=arm-linux-gnueabihf-gcc`, the script should detect the cross-compiler and include it in the output file.

* **Example:** If the script is run with `--cross --system linux --cpu arm`, it will generate a Meson file with `[host_machine]` containing `cpu = 'arm'` and `system = 'linux'`.

**5. User Errors and Debugging:**

Consider common user mistakes:

* **Error:** Forgetting to set essential environment variables when doing a cross-compilation. The script might issue warnings or fail to detect compilers.
* **Error:**  Specifying contradictory options like both `--cross` and `--native`. The script explicitly checks for this.

To understand how a user reaches this script, consider the typical Frida development workflow:

1. **Setting up a build environment:**  A developer wanting to cross-compile Frida for an Android device might follow instructions involving setting up a cross-compilation toolchain.
2. **Using Meson:** Frida uses Meson as its build system. When configuring the build for a target architecture, Meson needs a machine definition file.
3. **Running `env2mfile.py`:**  This script is likely part of Frida's build process to automatically generate that machine definition file based on the current environment (especially for cross-compilation scenarios). The user might not directly run this script, but it's invoked by the build system.

By following these steps, we can effectively analyze the script, understand its purpose, and relate it to the broader context of Frida, reverse engineering, and system-level programming. The key is to be systematic, read the code carefully, and connect the individual pieces to the overall goal.
This Python script, `env2mfile.py`, is designed to generate a Meson machine file based on environment variables. Meson uses these machine files to configure build settings, especially for cross-compilation. Let's break down its functionalities and connections:

**Core Functionalities:**

1. **Detecting Build Environment Settings:** The script's primary function is to inspect environment variables to gather information about the build environment. This includes:
    * **Compiler Paths:** It looks for environment variables like `CC`, `CXX`, `OBJC`, `OBJCXX` (potentially with `_FOR_BUILD` suffixes) to find the paths to different language compilers (C, C++, Objective-C, Objective-C++).
    * **Compiler Flags:** It reads `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `OBJCFLAGS`, `OBJCXXFLAGS` to collect preprocessor and compiler flags.
    * **Linker Flags:** It reads `LDFLAGS` to get linker flags.
    * **Other Binary Paths:** It searches for paths to tools like `ar`, `strip`, `objcopy`, `ld`, `cmake`, `pkg-config`, and `cups-config` based on naming conventions or environment variables.
    * **System Properties:** It can detect system-related information like architecture, operating system, CPU, and endianness, especially when the `--cross` option is used.
    * **CMake Settings:** If CMake is detected, it tries to determine relevant CMake variables.

2. **Generating Meson Machine Files:**  Based on the detected environment variables and command-line arguments, the script creates a Meson machine file. This file is structured into sections like `[binaries]`, `[built-in options]`, `[properties]`, `[cmake]`, and `[host_machine]`. It populates these sections with the detected compiler paths, flags, and system properties in a format that Meson can understand.

3. **Supporting Cross-Compilation:** The script explicitly supports generating machine files for cross-compilation scenarios using the `--cross` flag. It leverages Debian-specific tools like `dpkg-architecture` (if `--debarch` is used) or relies on users providing system information via command-line arguments (`--system`, `--cpu`, etc.).

4. **Supporting Native Compilation:** It also supports generating machine files for native compilation (compiling for the same architecture as the host) using the `--native` flag.

5. **Handling `_FOR_BUILD` Suffixes:** The script recognizes environment variables with a `_FOR_BUILD` suffix. This is a convention often used in cross-compilation setups where you have separate toolchains for the build host and the target environment.

**Relationship to Reverse Engineering:**

This script plays a crucial role in the development workflow of Frida, which is a dynamic instrumentation toolkit heavily used in reverse engineering. Here's how:

* **Building Frida for Target Devices:** When reverse engineering, you often need to run Frida on a different device or architecture than your development machine (e.g., an Android phone, an embedded Linux device). `env2mfile.py` helps generate the necessary Meson machine file to cross-compile the Frida agent for that target device. The environment variables would be set up to point to the cross-compilation toolchain for the target architecture.

   **Example:**  Imagine you want to reverse engineer an Android application. You would need to build the Frida gadget (the component that runs on the Android device). To do this, you might set environment variables like:
   ```bash
   export CC_FOR_BUILD=arm-linux-androideabi-gcc
   export CXX_FOR_BUILD=arm-linux-androideabi-g++
   export AR_FOR_BUILD=arm-linux-androideabi-ar
   # ... and so on for other tools
   ```
   Then, running `env2mfile.py --cross --system android --cpu arm -o android_arm.meson` would generate a `android_arm.meson` file containing the paths to the Android cross-compilation tools. Meson would then use this file to compile Frida for the Android ARM architecture.

**Involvement of Binary Underpinnings, Linux, Android Kernel & Framework:**

The script interacts with several low-level concepts:

* **Binary Toolchain:** The core of cross-compilation involves using a specific toolchain (compilers, linkers, assemblers, etc.) that can generate binaries for the target architecture. `env2mfile.py` directly deals with locating these binary tools through environment variables.
* **Linux Kernel (and Android Kernel, which is based on Linux):** When cross-compiling for Linux or Android, the script needs to be aware of the target operating system. The `--system` and `--kernel` options allow specifying these. While the script doesn't directly interact with the kernel source code, it's configuring the build process to create binaries that will eventually run on that kernel.
* **Android Framework:**  While not explicitly mentioned in the code, the concept of cross-compiling for Android inherently involves understanding aspects of the Android framework. The compiler flags and linker settings might need to be adjusted to link against Android-specific libraries or to adhere to Android's ABI (Application Binary Interface).
* **Endianness:** The `--endian` option allows specifying the byte order (big-endian or little-endian) of the target architecture. This is a fundamental binary-level detail that affects how data is interpreted.
* **CPU Architecture:** Options like `--cpu` and `--cpu-family` allow specifying the target CPU architecture (e.g., arm, x86, mips). This dictates the instruction set the compiler will generate.
* **System Libraries and Tooling:** The script's detection of tools like `ar`, `strip`, `objcopy`, and `pkg-config` reflects the need for these standard binary utilities during the build process.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

```bash
export CC=/usr/bin/gcc
export CXX=/usr/bin/g++
export CFLAGS="-O2 -Wall"
export LDFLAGS="-lm -pthread"
```

**Command:**

```bash
python env2mfile.py --native -o native.meson
```

**Hypothetical Output (`native.meson`):**

```meson
[binaries]
# Compilers
c = ['/usr/bin/gcc']
cpp = ['/usr/bin/g++']

# Other binaries
ar = ['/usr/bin/ar']  # Assuming 'ar' is in /usr/bin
strip = ['/usr/bin/strip'] # Assuming 'strip' is in /usr/bin
objcopy = ['/usr/bin/objcopy'] # Assuming 'objcopy' is in /usr/bin
ld = ['/usr/bin/ld'] # Assuming 'ld' is in /usr/bin

[built-in options]
c_args = ['-O2', '-Wall']
c_link_args = ['-O2', '-Wall', '-lm', '-pthread']
cpp_args = ['-O2', '-Wall']
cpp_link_args = ['-O2', '-Wall', '-lm', '-pthread']

[properties]
```

**Explanation of Output:**

* The `[binaries]` section lists the detected C and C++ compilers. It also attempts to find other common binary tools.
* The `[built-in options]` section includes the compiler and linker flags extracted from the environment variables.
* The `[properties]` section is empty in this example as no specific properties were set in the environment.
* The `[host_machine]` section would not be present because `--native` was used.

**User or Programming Common Usage Errors:**

1. **Missing Environment Variables for Cross-Compilation:** A common mistake is trying to cross-compile without setting the appropriate environment variables for the target toolchain.

   **Example:** Running `python env2mfile.py --cross --system android --cpu arm -o android.meson` without setting `CC_FOR_BUILD`, `CXX_FOR_BUILD`, etc., would result in the script not finding the necessary compilers, leading to an incomplete or incorrect `android.meson` file. Meson would likely fail later during the build process.

2. **Conflicting Options:** Specifying both `--cross` and `--native` is an error that the script explicitly catches and reports.

3. **Incorrect `--debarch` Value:** If using `--debarch` for Debian-based cross-compilation, providing an incorrect or misspelled architecture string would lead to `dpkg-architecture` failing, and the script would not be able to detect the cross-compilation settings correctly.

4. **Overriding System Defaults Unintentionally:** Setting global environment variables might unintentionally affect the generated machine file when the user intends to build for the host system. It's often better to set environment variables specifically for the cross-compilation build process.

**User Operation Steps to Reach This Script (Debugging Context):**

Typically, a user wouldn't directly invoke `env2mfile.py` in isolation. It's usually part of a larger build system like Meson. Here's a common scenario when debugging a Frida build issue:

1. **User Attempts to Build Frida:** The user starts the process of building Frida for a specific target (e.g., an Android device) using Meson. This usually involves commands like:
   ```bash
   meson setup build-android -Dtarget=android -Darch=arm64
   ```
   or a similar command that configures the build.

2. **Meson Needs a Machine File:** Meson, during the `setup` phase, needs a machine file to understand the target environment. If a suitable machine file doesn't exist or needs to be generated, Meson (or the Frida build scripts) might internally call `env2mfile.py`.

3. **Environment Variables are Relevant:** The environment variables set in the user's shell at this point are crucial. If the user is cross-compiling, they should have set variables like `CC_FOR_BUILD`, `CXX_FOR_BUILD`, etc.

4. **Debugging a Build Failure:** If the Frida build fails, especially during the configuration or compilation stages, a developer might investigate the generated machine file (`build-android/meson-info/native-file.ini` for native builds or a target-specific file for cross-compilation).

5. **Considering `env2mfile.py`:** If the machine file seems incorrect (e.g., wrong compiler paths), the developer might suspect that `env2mfile.py` didn't correctly detect the environment variables.

6. **Reproducing and Testing:** The developer might then try to reproduce the issue by manually running `env2mfile.py` with specific options and environment variables to see if it generates the expected output. This helps isolate whether the problem lies within `env2mfile.py`'s logic or elsewhere in the build system.

In essence, `env2mfile.py` acts as a bridge between the user's environment and the Meson build system, especially in cross-compilation scenarios for tools like Frida. Understanding its function is crucial when troubleshooting build issues related to target architectures and toolchains.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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