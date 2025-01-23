Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Request:**

The core request is to analyze a Python script named `env2mfile.py` from the Frida project, focusing on its functionality, relationship to reverse engineering, low-level details, logical inferences, potential user errors, and debugging context.

**2. Initial Skim and Keyword Spotting:**

The first step is to quickly skim the code, looking for keywords and patterns that hint at its purpose. I see:

* `mesonbuild`: This immediately suggests integration with the Meson build system.
* `cross compilation`, `native compilation`: These are prominent command-line arguments and concepts in the code.
* `compilers`, `binaries`, `properties`: These seem to be the main categories of information the script deals with.
* `dpkg-architecture`:  A Debian-specific tool, indicating support for Debian-like systems.
* `CPPFLAGS`, `CFLAGS`, `LDFLAGS`: Standard environment variables for build processes.
* `shlex.split`, `os.environ`, `subprocess.check_output`:  Interactions with the system environment and external commands.
* `write_machine_file`:  The output is a file, likely a configuration file for Meson.

From this initial scan, I can hypothesize that the script generates Meson configuration files, possibly for cross-compilation, by inspecting environment variables and system tools.

**3. Function-by-Function Analysis:**

Next, I'd go through the code function by function, trying to understand the purpose of each.

* **`has_for_build()`:** Checks for the existence of `*_FOR_BUILD` environment variables, suggesting a mechanism for separate build configurations.
* **`add_arguments()`:** Defines command-line arguments using `argparse`. This confirms the script is meant to be run from the command line.
* **`MachineInfo` class:**  A data structure to hold information about the build environment (compilers, binaries, etc.).
* **`locate_path()`:**  Finds executable files in the system's PATH.
* **`write_args_line()`:**  Formats key-value pairs for the output file.
* **`get_args_from_envvars()`:** Extracts compiler flags from standard environment variables.
* **`deb_cpu_family_map`, `deb_cpu_map`:**  Mappings related to Debian architecture names.
* **`deb_detect_cmake()`:**  Specifically handles CMake configuration for Debian-like systems.
* **`deb_compiler_lookup()`:** Locates Debian-style cross-compilers.
* **`detect_cross_debianlike()`:** Detects cross-compilation settings using `dpkg-architecture`.
* **`write_machine_file()`:** Writes the collected information to the output file in a specific format.
* **`detect_language_args_from_envvars()`:**  More fine-grained extraction of compiler and linker flags, potentially with suffixes.
* **`detect_compilers_from_envvars()`:** Detects compilers based on environment variables.
* **`detect_binaries_from_envvars()`:** Detects other build tools from environment variables.
* **`detect_properties_from_envvars()`:** Detects properties like `pkg-config` paths.
* **`detect_cross_system()`:** Handles cross-compilation properties provided as command-line arguments.
* **`detect_cross_env()`:**  Orchestrates cross-compilation detection.
* **`add_compiler_if_missing()`:**  Attempts to find compilers if they weren't detected via environment variables.
* **`detect_missing_native_compilers()`:**  Looks for standard compiler names.
* **`detect_missing_native_binaries()`:** Looks for standard binary names.
* **`detect_native_env()`:**  Detects native compilation environment.
* **`run()`:** The main function, coordinating the detection and writing process based on command-line arguments.

**3.1. Identifying Core Functionality:**

By analyzing the functions, I can now confidently state the core functionality:  This script generates Meson machine files that describe the build environment (compilers, linkers, etc.), primarily for cross-compilation but also for native compilation. It gathers this information from environment variables, command-line arguments, and system tools.

**4. Connecting to Reverse Engineering:**

This requires thinking about how cross-compilation and build environments relate to reverse engineering.

* **Cross-compilation:**  Crucial for targeting embedded devices or architectures different from the host machine, which is common in reverse engineering of firmware or mobile apps (like Android).
* **Frida's context:** Knowing Frida is a dynamic instrumentation toolkit reinforces the idea of targeting various platforms. This script helps set up the build environment for Frida on those targets.
* **Environment variables:** Understanding how build tools are configured is essential for replicating build environments or modifying the build process during reverse engineering.

**5. Identifying Low-Level and System Knowledge:**

This involves pinpointing aspects related to operating systems and system internals:

* **Linux commands:** `dpkg-architecture`, `gcc`, `g++`, `ar`, `strip`, `objcopy`, `ld`, `cmake`, `pkg-config`, `cups-config`.
* **Environment variables:** `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, and the `*_FOR_BUILD` variants.
* **File system interaction:**  `os.path.exists`, `os.access`, `shutil.which`.
* **Process execution:** `subprocess.check_output`.
* **Debian packaging:** The use of `dpkg-architecture` and Debian-specific naming conventions.
* **Cross-compilation concepts:** Targeting different architectures, the need for specific toolchains.

**6. Logical Inferences and Examples:**

Here, I need to think about how the script processes information and what the output would look like.

* **Input:**  Presence or absence of specific environment variables, command-line arguments like `--cross`, `--debarch`, compiler paths in the PATH.
* **Output:** A Meson machine file (`.ini`-like format) containing sections for `[binaries]`, `[built-in options]`, `[properties]`, `[cmake]`, and potentially `[host_machine]`. The values would be the detected paths to tools and compiler flags. I would construct a simple example based on common scenarios.

**7. Identifying User Errors:**

Think about how a user might misuse the script or encounter problems.

* **Missing dependencies:** Not having the required cross-compilation toolchain installed.
* **Incorrect environment variables:** Setting environment variables incorrectly or inconsistently.
* **Conflicting options:** Using `--cross` and `--native` simultaneously.
* **Misunderstanding the purpose:** Trying to use this script for something other than generating Meson machine files.

**8. Debugging Context:**

Imagine how a developer would arrive at this script during debugging.

* **Build failures:** If the Meson build fails due to incorrect compiler or linker settings, a developer might investigate how the machine file is generated.
* **Cross-compilation issues:** Problems when building for a target architecture would lead to examining the cross-compilation configuration.
* **Frida-specific build problems:**  If building Frida fails for a specific platform, this script is a likely point of investigation.
* **Tracing the build process:** Following the Meson build system's logic might lead back to this script as a key component in environment detection.

**9. Structuring the Answer:**

Finally, organize the information into the requested categories: functionality, relationship to reverse engineering, low-level details, logical inferences, user errors, and debugging context, providing concrete examples for each. Use clear and concise language. Ensure the explanation flows logically and addresses all parts of the prompt. Use formatting like bullet points and code blocks to improve readability.
This Python script, `env2mfile.py`, is a utility within the Frida project's build system (using Meson) responsible for **generating Meson machine files**. These files define the build environment, particularly when cross-compiling or when specific environment variables dictate the toolchain.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Detecting Build Tools:** The script probes the environment for the locations of compilers (like GCC, Clang), linkers, and other essential build tools (like `ar`, `strip`, `objcopy`, `cmake`, `pkg-config`). It looks for these tools based on standard naming conventions and environment variables.
2. **Capturing Compiler and Linker Flags:** It extracts compiler flags (e.g., `-I`, `-D`) and linker flags (e.g., `-L`, `-l`) from environment variables like `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS`, `OBJCFLAGS`, and `OBJCXXFLAGS`.
3. **Generating Meson Machine Files:**  It writes the detected information into a text file adhering to Meson's machine file format. This file contains sections defining the paths to binaries, default compiler and linker arguments, and other system properties.
4. **Handling Cross-Compilation:** The script has specific logic to handle cross-compilation scenarios. It can use `dpkg-architecture` (on Debian-based systems) to automatically determine target architecture details or rely on explicit command-line arguments (`--system`, `--cpu`, `--endian`, etc.) and environment variables (suffixed with `_FOR_BUILD`).
5. **Handling Native Compilation:**  It can also generate machine files for native builds, using the environment variables directly.
6. **CMake Integration:** It attempts to detect CMake and, if found, includes CMake-related settings in the generated machine file.
7. **`FOR_BUILD` Environment Variables:** It supports a convention where environment variables suffixed with `_FOR_BUILD` are used when building tools that will be used during the actual build process (the "host" of the build process, when cross-compiling).

**Relationship to Reverse Engineering:**

This script is directly relevant to reverse engineering, especially in the context of Frida:

* **Targeting Different Architectures:** Frida is often used to instrument applications running on different architectures (e.g., ARM on mobile devices, x86 on desktops). `env2mfile.py` is crucial for setting up the cross-compilation environment to build Frida itself for these target architectures. For example, if you're reverse engineering an Android application, you'll need to build the Frida gadget (the agent injected into the target process) for the ARM architecture of the Android device. This script helps generate the necessary Meson configuration.
* **Reproducible Builds:** In reverse engineering, it's important to have reproducible build environments. This script helps capture the exact compiler and linker settings used, which can be vital for recreating a build environment for analysis or modification.
* **Building Frida Gadgets/Stubs:**  Frida often involves building small pieces of code (gadgets or stubs) that are injected into target processes. This script helps ensure these components are built with the correct toolchain for the target environment.

**Example (Cross-Compilation for Android ARM64):**

Let's say you want to build Frida for an Android ARM64 device. You might perform the following steps leading to the execution of `env2mfile.py`:

1. **Set up a cross-compilation toolchain:** You would install an ARM64 cross-compiler (e.g., `aarch64-linux-gnu-gcc`, `aarch64-linux-gnu-g++`).
2. **Define environment variables:** You'd set environment variables pointing to your cross-compiler and related tools:
   ```bash
   export CC_FOR_BUILD=/usr/bin/gcc
   export CXX_FOR_BUILD=/usr/bin/g++
   export AR_FOR_BUILD=/usr/bin/ar
   export STRIP_FOR_BUILD=/usr/bin/strip

   export CC=/path/to/aarch64-linux-gnu-gcc
   export CXX=/path/to/aarch64-linux-gnu-g++
   export AR=/path/to/aarch64-linux-gnu-ar
   export STRIP=/path/to/aarch64-linux-gnu-strip
   export CPPFLAGS="-I/path/to/your/target/sysroot/usr/include"
   export LDFLAGS="-L/path/to/your/target/sysroot/usr/lib"
   ```
3. **Configure Meson:** You would run Meson with the `--cross-file` option, potentially creating a file manually or relying on `env2mfile.py` to generate one.
4. **Frida's Build System Invokes `env2mfile.py`:**  When Meson is configured, it might internally call `env2mfile.py` with the `--cross` flag (or detect a cross-compilation scenario). The script would then:
   - Detect the `CC` and `CXX` environment variables and their corresponding paths.
   - Extract `CPPFLAGS` and `LDFLAGS`.
   - Based on your system (if Debian-like), it might use `dpkg-architecture` to infer target architecture details.
   - Write this information to a Meson machine file (e.g., `meson-cross.txt`).

The generated `meson-cross.txt` file would look something like this:

```ini
[binaries]
c = '/path/to/aarch64-linux-gnu-gcc'
cpp = '/path/to/aarch64-linux-gnu-g++'
ar = '/path/to/aarch64-linux-gnu-ar'
strip = '/path/to/aarch64-linux-gnu-strip'

[built-in options]
c_args = ['-I/path/to/your/target/sysroot/usr/include']
c_link_args = ['-L/path/to/your/target/sysroot/usr/lib']
cpp_args = ['-I/path/to/your/target/sysroot/usr/include']
cpp_link_args = ['-L/path/to/your/target/sysroot/usr/lib']

[host_machine]
cpu = 'aarch64'
cpu_family = 'aarch64'
endian = 'little'
system = 'linux'
```

**Binary Underpinnings, Linux, Android Kernel/Framework Knowledge:**

* **Binary Toolchain:** The script directly deals with the paths to binary executables like compilers, linkers, and utilities (`ar`, `strip`). These are the fundamental tools for transforming source code into executable binaries.
* **Linux Commands:**  The script uses commands like `dpkg-architecture` (specific to Debian-based Linux distributions) to gather information about the system's architecture. It also relies on the standard location of executables within the Linux filesystem (accessed via `os.get_exec_path()` and `shutil.which`).
* **Environment Variables:**  The script heavily relies on environment variables, which are a core mechanism in Linux (and other Unix-like systems) for configuring processes and their behavior. Understanding the meaning and usage of `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, etc., is crucial when working with this script.
* **Cross-Compilation Concepts:** The script embodies the fundamental concepts of cross-compilation, where the build process occurs on one architecture (the host) to produce binaries for a different architecture (the target). This requires understanding how to specify the target architecture, use appropriate toolchains, and provide necessary system libraries or headers for the target. While the script itself doesn't delve into the specifics of the Android kernel or framework, it's a necessary step in building Frida for Android, which interacts deeply with these components at runtime.

**Logical Inference (Hypothetical Input and Output):**

**Hypothetical Input (Command-line):**

```bash
python env2mfile.py --cross --system linux --cpu arm --endian little -o my_cross_config.ini
```

**Hypothetical Environment Variables:**

```bash
export CC=/opt/arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc
export CXX=/opt/arm-linux-gnueabi/bin/arm-linux-gnueabi-g++
```

**Hypothetical Output (`my_cross_config.ini`):**

```ini
[binaries]
c = '/opt/arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc'
cpp = '/opt/arm-linux-gnueabi/bin/arm-linux-gnueabi-g++'

[built-in options]

[properties]

[host_machine]
cpu = 'arm'
cpu_family = 'arm'
endian = 'little'
system = 'linux'
```

**User/Programming Errors:**

1. **Missing Toolchain:** A common error is not having the necessary cross-compilation toolchain installed or not having the environment variables correctly pointing to it. For example, if `CC` is not set or points to a native compiler when cross-compiling, the generated machine file will be incorrect.
   ```bash
   # Incorrect - using native gcc for a cross-compile
   export CC=/usr/bin/gcc
   python env2mfile.py --cross --system linux --cpu arm ...
   ```
   The resulting `my_cross_config.ini` would incorrectly point to the native GCC.

2. **Incorrect Environment Variables:** Setting `CPPFLAGS` or `LDFLAGS` incorrectly can lead to build failures. For instance, if the paths to the target system's header files in `CPPFLAGS` are wrong, the compiler won't find necessary headers.

3. **Conflicting Options:** Specifying both `--cross` and `--native` is an error that the script explicitly checks for and exits.

4. **Typos in Command-line Arguments:**  Typing the target system or CPU incorrectly in the command-line arguments will lead to an incorrect `[host_machine]` section in the output file.

**User Operation and Debugging:**

Here's how a user might reach this script and how it can be a point of debugging:

1. **Starting a Frida Build:** A developer wants to build Frida for a specific target platform (e.g., an embedded Linux device).
2. **Configuring the Build System:** They use Meson to configure the build, potentially providing a cross-compilation file or relying on automatic detection.
3. **Meson Invokes `env2mfile.py`:** If Meson detects a cross-compilation scenario or if the user explicitly requests the generation of a machine file, Meson will execute `env2mfile.py`. This execution might be part of the `meson configure` step.
4. **Build Errors Occur:**  During the subsequent build process (e.g., `meson compile`), the build might fail with errors indicating that the wrong compiler or linker is being used, or that include files or libraries are missing.
5. **Investigating the Machine File:** The developer would then examine the generated Meson machine file (the output of `env2mfile.py`) to see if the paths to the compilers and other tools are correct, and if the compiler/linker flags are appropriate for the target architecture.
6. **Checking Environment Variables:** If the machine file is incorrect, the next step is to check the environment variables that were in effect when `env2mfile.py` was run. This involves verifying that `CC`, `CXX`, `CPPFLAGS`, `LDFLAGS`, etc., are set correctly.
7. **Debugging `env2mfile.py` (Less Common):** In more complex scenarios, or if there's suspicion that the script itself is not behaving as expected, a developer might step through the `env2mfile.py` script with a debugger to understand how it's detecting the build environment and why it's producing a particular output. This might involve setting breakpoints and inspecting variables within the script.

In essence, `env2mfile.py` is a foundational piece of the Frida build system, ensuring that the build process uses the correct tools and settings for the intended target architecture. When build problems arise, especially in cross-compilation scenarios, this script and its output are often key areas for investigation.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```