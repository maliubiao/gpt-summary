Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Goal:** The immediate giveaway is the filename `env2mfile.py` and the command-line arguments it accepts (`--cross`, `--native`, `-o`). This strongly suggests it's converting environment variables into a Meson configuration file. The docstring confirms this, stating it generates "cross compilation definition file for the Meson build system."

2. **Dissecting the Functionality (Top-Down):**

   * **Entry Point (`run` function):**  This is usually a good starting point. It handles command-line arguments, checks for conflicts (`--cross` and `--native`), and calls either `detect_cross_env` or `detect_native_env` based on the arguments. Finally, it calls `write_machine_file`.

   * **Environment Detection (`detect_cross_env`, `detect_native_env`):**  These are the core logic.
      * `detect_cross_env`:  Handles cross-compilation. It differentiates between Debian-like systems (using `dpkg-architecture`) and other systems (relying more on environment variables). It calls functions like `detect_cross_debianlike`, `detect_compilers_from_envvars`, `detect_binaries_from_envvars`, and `detect_properties_from_envvars`. The `detect_cross_system` function ensures required cross-compilation properties are provided.
      * `detect_native_env`:  Handles native compilation. It checks for `_FOR_BUILD` suffixes in environment variables (indicating a "for build" context) and then calls similar detection functions. It also has special logic to detect missing compilers and binaries using `shutil.which`.

   * **Data Storage (`MachineInfo` class):** This class acts as a container to store all the detected information: compilers, binaries, properties, and system information. This is a common pattern for organizing data.

   * **Writing the Output (`write_machine_file`):**  This function takes the `MachineInfo` object and writes its contents into a Meson-compatible file format (INI-like syntax). It iterates through the dictionaries in `MachineInfo` and formats the output accordingly.

   * **Helper Functions:** Functions like `locate_path`, `write_args_line`, `get_args_from_envvars`, `deb_compiler_lookup`, `detect_language_args_from_envvars`, `add_compiler_if_missing`, etc., handle specific tasks like finding executables, formatting output, extracting arguments from environment variables, and detecting compilers.

3. **Identifying Key Concepts and Connections:**

   * **Cross-compilation:**  The script's primary purpose. The `--cross` flag, the handling of Debian architectures, and the need to specify target system properties are all indicators.
   * **Native compilation:** Handled by the `--native` flag. The script still relies on environment variables but might use system-level detection of compilers and tools.
   * **Environment variables:**  Crucial for specifying compiler paths, flags, and other build-related information. The script heavily parses these.
   * **Meson build system:** The output format directly targets Meson, making this script an auxiliary tool for Meson.
   * **Debian packaging:** The `dpkg-architecture` command and the handling of Debian-specific variables suggest an integration with Debian's cross-compilation toolchain.

4. **Relating to Reverse Engineering, Binary Bottom, Kernels, and Frameworks:**

   * **Reverse Engineering:** Frida is a dynamic instrumentation toolkit *used* in reverse engineering. This script itself isn't directly performing reverse engineering, but it facilitates setting up the build environment necessary to *build* Frida. A correctly built Frida is essential for reverse engineering tasks.
   * **Binary Bottom/Low-Level:** The script deals with compilers (which produce binaries), linkers, and tools like `strip` and `objcopy`. Cross-compilation often involves understanding target architectures and their binary formats.
   * **Linux/Android Kernels and Frameworks:**  Cross-compiling for Android or specific Linux distributions requires knowing the target system's kernel and framework. The `--system`, `--kernel`, and `--subsystem` options are directly related to this. The Debian-specific logic also ties into Linux distribution conventions.

5. **Logical Reasoning and Examples:**  Consider how the script processes information. If `--cross` is given, it *infers* that a cross-compilation setup is needed and then tries to gather relevant information. The Debian logic *assumes* that `dpkg-architecture` provides accurate information. The examples provided in the initial prompt illustrate how these assumptions and processing steps work.

6. **User Errors and Debugging:** Think about what could go wrong. Incorrect or missing environment variables, typos in command-line arguments, or assuming the script will magically find compilers if they aren't in the PATH are common errors. The script provides some basic error messages, but understanding the underlying assumptions is crucial for debugging. The "User Steps" section in the initial prompt highlights how a user might arrive at this script.

7. **Structuring the Answer:**  Organize the information logically, starting with a high-level overview and then drilling down into specific details. Use headings and bullet points to improve readability. Provide concrete examples to illustrate the points. Address all the specific questions in the prompt.

By following this kind of structured analysis, you can effectively understand the functionality and purpose of even complex code. It's a process of asking "what," "why," and "how" repeatedly and connecting the pieces together.
这个Python脚本 `env2mfile.py` 的主要功能是**生成用于 Meson 构建系统的交叉编译定义文件或本地编译定义文件**。它通过读取环境变量来获取编译器、工具链和其他构建相关的信息，并将这些信息格式化后写入一个 Meson 可以识别的配置文件。

以下是该脚本功能的详细列表，以及与逆向、二进制底层、Linux/Android 内核及框架知识的关联，以及逻辑推理、常见错误和调试线索：

**功能列表:**

1. **解析命令行参数:** 接受诸如 `--debarch`（Debian 架构）、`--gccsuffix`（GCC 版本后缀）、`-o`（输出文件路径）、`--cross`（生成交叉编译文件）、`--native`（生成本地编译文件）、以及定义目标系统架构（`--system`, `--subsystem`, `--kernel`, `--cpu`, `--cpu-family`, `--endian`）等参数。

2. **检测编译器:**  根据环境变量（如 `CC`, `CXX`, `OBJC`, `OBJCXX` 等）或通过查找系统路径来定位 C、C++、Objective-C、Objective-C++ 等编译器。对于交叉编译，它会尝试查找带有架构前缀的编译器（例如 `arm-linux-gnueabi-gcc`）。

3. **检测其他二进制工具:**  类似地，根据环境变量（如 `AR`, `STRIP`, `OBJCOPY`, `LD` 等）或系统路径查找 `ar`（归档工具）、`strip`（去除符号信息工具）、`objcopy`（目标文件复制工具）、`ld`（链接器）等二进制工具。

4. **读取编译和链接参数:** 从环境变量 `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `OBJCFLAGS`, `OBJCXXFLAGS`, `LDFLAGS` 中读取编译和链接所需的标志和选项。

5. **生成 Meson 配置文件:** 将检测到的编译器、二进制工具、编译和链接参数以及目标系统信息写入指定的输出文件。这个文件遵循 Meson 的特定格式，用于指导 Meson 构建系统如何进行编译和链接。

6. **处理 Debian 架构信息:** 如果指定了 `--debarch` 参数，脚本会调用 `dpkg-architecture` 命令来获取 Debian 系统的架构信息，并据此推断编译器和工具链的名称。

7. **处理 CMake 信息:** 如果找到了 `cmake` 命令，会将 CMake 相关的配置信息写入配置文件。

8. **区分交叉编译和本地编译:** 根据 `--cross` 和 `--native` 参数来决定生成哪种类型的配置文件，并采取相应的检测策略。

**与逆向方法的关联及举例:**

* **交叉编译 Frida Server 到目标设备:**  Frida 经常被用于逆向 Android 或嵌入式设备上的应用程序。为了在目标设备上运行 Frida Server，通常需要将其交叉编译到目标设备的架构。这个脚本可以生成用于交叉编译 Frida Server 的 Meson 配置文件。

   **举例:** 假设你要为 ARM 架构的 Android 设备交叉编译 Frida Server。你需要设置相应的环境变量，然后运行 `env2mfile.py`：
   ```bash
   export CC=/opt/toolchains/arm-linux-gnueabi-gcc
   export CXX=/opt/toolchains/arm-linux-gnueabi-g++
   export AR=/opt/toolchains/arm-linux-gnueabi-ar
   export STRIP=/opt/toolchains/arm-linux-gnueabi-strip
   # ... 其他环境变量
   python env2mfile.py --cross --system android --cpu arm --endian little -o arm_android.meson
   ```
   生成的 `arm_android.meson` 文件将被 Meson 用于配置针对 ARM Android 设备的编译过程。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

* **目标架构和指令集:**  交叉编译需要明确指定目标设备的 CPU 架构（例如 ARM, x86, MIPS）和指令集。脚本中的 `--cpu` 参数和 `dpkg-architecture` 命令的输出与这些信息直接相关。理解目标架构的特性对于成功构建能够在目标设备上运行的二进制文件至关重要。

* **链接器和标准库:** 交叉编译需要使用目标平台的链接器和标准库。脚本通过检测带有架构前缀的 `ld` 命令来识别目标链接器。环境变量中设置的 `LDFLAGS` 可以指定链接器选项和库路径。

* **系统调用约定和 ABI:**  不同的操作系统和架构有不同的系统调用约定和应用程序二进制接口 (ABI)。交叉编译工具链需要与目标系统的 ABI 兼容。脚本中生成的配置文件会影响编译器和链接器的行为，以确保生成的二进制文件符合目标系统的 ABI。

* **Android NDK:**  在为 Android 交叉编译时，通常会使用 Android NDK (Native Development Kit)。NDK 提供了交叉编译工具链和 Android 特定的头文件和库。脚本在为 Android 生成配置文件时，需要指向 NDK 提供的工具链。

   **举例:**  当使用 `--system android` 时，脚本实际上是在指示 Meson 配置一个针对 Android 系统的构建环境。这会影响 Meson 在构建过程中如何处理依赖项和链接库。

**逻辑推理及假设输入与输出:**

* **假设输入:**
    * 命令行参数: `--cross --debarch=armhf -o cross_armhf.meson`
    * 系统环境变量中 `dpkg-architecture -a armhf` 的输出包含 `DEB_HOST_GNU_TYPE=arm-linux-gnueabihf`，并且系统中存在 `arm-linux-gnueabihf-gcc`。
* **逻辑推理:** 脚本会执行 `dpkg-architecture -a armhf` 获取目标架构信息，然后根据 `DEB_HOST_GNU_TYPE` 推断交叉编译工具链的名称，并在系统路径中查找 `arm-linux-gnueabihf-gcc` 等编译器。
* **预期输出:**  `cross_armhf.meson` 文件中会包含类似以下的配置：
    ```meson
    [binaries]
    c = ['arm-linux-gnueabihf-gcc']
    cpp = ['arm-linux-gnueabihf-g++']
    ar = ['arm-linux-gnueabihf-ar']
    strip = ['arm-linux-gnueabihf-strip']
    # ... 其他二进制工具
    [host_machine]
    cpu = 'arm7hlf'
    # ... 其他架构信息
    ```

**涉及用户或编程常见的使用错误及举例:**

* **错误的工具链路径:** 用户可能设置了错误的 `CC` 或 `CXX` 环境变量，指向了不兼容目标架构的编译器。

   **举例:** 用户尝试为 ARM 架构编译，但 `CC` 环境变量指向了 x86 的 GCC 编译器。运行脚本后，生成的配置文件将包含错误的编译器路径，导致后续的 Meson 构建失败。

* **缺少必要的交叉编译工具链:** 用户可能没有安装目标架构的交叉编译工具链。

   **举例:** 用户在没有安装 `arm-linux-gnueabi-gcc` 的情况下运行针对 ARM 的交叉编译命令，脚本会因为找不到编译器而发出警告，生成的配置文件可能不完整或者为空。

* **环境变量设置不完整:**  用户可能只设置了部分环境变量，例如只设置了 `CC` 而没有设置 `AR` 或 `STRIP`。

   **举例:**  如果 `AR` 环境变量没有设置，脚本可能无法找到归档工具，导致生成的配置文件中缺少 `ar` 的配置，这可能会在构建过程中导致链接错误。

* **交叉编译参数设置错误:** 用户可能错误地指定了 `--system`, `--cpu`, 或 `--endian` 等参数，与实际目标设备不符。

   **举例:**  用户为大端序 (big-endian) 的设备编译，但错误地设置了 `--endian=little`，生成的配置文件将指示编译器生成小端序的代码，导致程序在目标设备上无法正确运行。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 开发或构建:** 用户可能正在尝试构建 Frida 的一部分，例如 Frida Server，以便在特定的目标设备上使用。

2. **查阅 Frida 构建文档:**  Frida 的构建文档通常会指导用户如何为不同的平台配置构建环境。文档可能会提到使用 Meson 构建系统，并可能建议使用 `env2mfile.py` 这样的脚本来生成初始的配置文件。

3. **尝试配置交叉编译环境:**  当目标设备与主机架构不同时，用户需要配置交叉编译环境。这通常涉及到安装交叉编译工具链并设置相应的环境变量。

4. **运行 `env2mfile.py`:** 用户根据文档的指示，或者通过查看 Frida 的构建脚本，了解到可以使用 `env2mfile.py` 来自动生成 Meson 配置文件。他们会根据自己的目标平台需求，使用不同的命令行参数运行该脚本。

5. **遇到构建错误:** 如果生成的配置文件不正确，或者环境变量设置有误，后续的 Meson 构建过程可能会失败。

6. **检查 Meson 配置文件:** 用户可能会打开生成的 `.meson` 文件，查看其中的编译器路径、链接器选项等是否正确。

7. **检查环境变量:** 用户会检查自己设置的环境变量，例如 `CC`, `CXX`, `PATH` 等，确保指向正确的交叉编译工具链。

8. **调试 `env2mfile.py` 的输出:** 如果怀疑 `env2mfile.py` 生成了错误的配置，用户可能会重新运行脚本，并仔细观察其输出，或者添加一些调试信息到脚本中，以了解脚本是如何检测编译器和工具的。

9. **参考 `env2mfile.py` 源代码:**  为了更深入地理解脚本的行为，用户可能会查看 `env2mfile.py` 的源代码，了解其如何解析命令行参数、查找环境变量、以及生成配置文件的逻辑。

总而言之，`env2mfile.py` 是 Frida 构建过程中的一个实用工具，它简化了 Meson 交叉编译配置文件的生成。理解其功能和工作原理，以及相关的底层知识，对于成功构建 Frida 并将其应用于逆向工程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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