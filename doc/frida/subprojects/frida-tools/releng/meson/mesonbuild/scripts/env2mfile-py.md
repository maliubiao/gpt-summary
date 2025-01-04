Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding and Goal Identification:**

The first step is to read the initial comments and the overall structure of the code. The docstring clearly states: "Generate cross compilation definition file for the Meson build system."  This immediately tells us the primary function: creating configuration files for cross-compilation within the Meson build system.

**2. Deconstructing the Functionality - Top-Down Approach:**

I'd start by looking at the `run` function, as it's the entry point and orchestrates the main logic. I see it handles the `--cross` and `--native` flags, deciding whether to generate a cross-compilation or native compilation file. This leads to investigating `detect_cross_env` and `detect_native_env`.

**3. Analyzing `detect_cross_env`:**

* **`options.debarch` check:** This suggests handling Debian-like systems specifically. The call to `detect_cross_debianlike` confirms this.
* **`detect_cross_debianlike` deep dive:**  I see it uses `dpkg-architecture` to gather information about the target architecture. This is a key piece of information related to cross-compilation for Debian-based systems. I'd note the usage of `subprocess` and the parsing of the output. The mapping of Debian architecture names to more generic terms is also interesting.
* **Environment variable detection:** If `options.debarch` isn't set, it falls back to detecting compilers and system information from environment variables. This points to a more generic cross-compilation setup. The call to `detect_cross_system` confirms that command-line arguments are used to specify missing system details.
* **Binary and property detection:**  `detect_binaries_from_envvars` and `detect_properties_from_envvars` indicate that the script also gathers information about tools (like `ar`, `strip`) and properties (like `pkg-config` paths) from environment variables.

**4. Analyzing `detect_native_env`:**

* **`has_for_build()`:** This function checks for `*_FOR_BUILD` environment variables, hinting at a mechanism to differentiate between the host build environment and the target build environment even for native builds (perhaps for building tools that will be used in the build process).
* **Environment variable detection (with suffix):** Similar to cross-compilation, it detects compilers, binaries, and properties from environment variables, but with an optional `_FOR_BUILD` suffix.
* **Missing compiler/binary detection:** `detect_missing_native_compilers` and `detect_missing_native_binaries` attempt to find compilers and binaries using `shutil.which`. This acts as a fallback when environment variables aren't set.

**5. Understanding the Output - `write_machine_file`:**

This function is crucial for understanding the *output* of the script. It writes a Meson machine file in a specific format (`[binaries]`, `[built-in options]`, `[properties]`, `[host_machine]`). This confirms the script's purpose of generating configuration files.

**6. Identifying Key Concepts:**

During the analysis, I'd be noting keywords and concepts related to:

* **Cross-compilation:** The core functionality.
* **Meson build system:** The target user of these configuration files.
* **Environment variables:** A primary source of information.
* **Debian packaging:**  The special handling of Debian architectures.
* **Compiler detection:**  Finding the right compilers for the target platform.
* **Binary detection:**  Locating tools like archivers, linkers, etc.
* **System properties:** Information about the target operating system, CPU architecture, etc.

**7. Relating to Reverse Engineering (Instruction 2):**

At this point, I'd consider how the information collected by this script is relevant to reverse engineering. Cross-compilation is often used to build tools that will run on a different architecture than the development machine. These tools could be used for debugging, analysis, or manipulation of software on the target platform. Frida itself is a dynamic instrumentation toolkit, so the connection to reverse engineering is quite direct.

**8. Identifying Low-Level/Kernel Aspects (Instruction 3):**

The script deals with concepts like:

* **CPU architecture (`cpu`, `cpu_family`):**  Fundamental to how code is executed.
* **Endianness (`endian`):**  Byte order, a crucial low-level detail.
* **System and kernel information:**  Operating system and kernel specifics.
* **Compiler and linker flags:** These directly influence the generated binary.

**9. Logical Reasoning and Examples (Instruction 4):**

I'd think about simple scenarios:

* **Cross-compiling for ARM on a Linux x86 machine:**  Input would involve setting environment variables for the ARM compiler toolchain or using the `--debarch` option for an ARM Debian target. The output would be a Meson machine file specifying the ARM compiler, linker, and architecture details.
* **Native compilation:** Input could be just running the script with `--native`. The output would list the detected native compilers and tools.

**10. User Errors (Instruction 5):**

I'd consider common mistakes:

* **Incorrect environment variables:** Setting the wrong paths to compilers or other tools.
* **Missing dependencies:** Not having the required cross-compilation toolchain installed.
* **Conflicting options:** Trying to use both `--cross` and `--native`.

**11. User Steps to Reach the Script (Instruction 6):**

Finally, I'd trace back the steps a user would take:

1. **Decide to cross-compile or generate a native build configuration using Meson.**
2. **Realize they need a machine definition file.**
3. **Find or be directed to the `env2mfile.py` script.**
4. **Run the script with appropriate command-line arguments (`--cross` or `--native`) and potentially other options like `--debarch`.**

By following this structured thought process, I can systematically analyze the code and address all the points raised in the prompt. The key is to understand the core purpose of the script and then delve into the details of how it achieves that purpose, while also connecting it to the broader context of reverse engineering and low-level system knowledge.
这个Python脚本 `env2mfile.py` 的主要功能是**为 Meson 构建系统生成交叉编译或本地编译的定义文件**。它通过扫描环境变量以及使用 `dpkg-architecture` (在 Debian-like 系统上) 来检测编译器、工具以及目标系统的属性，并将这些信息写入一个 Meson 可以理解的 `.ini` 格式的配置文件。

以下是其更详细的功能列表：

**主要功能：**

1. **生成 Meson 机器文件：**  这是脚本的核心功能。它创建一个文件，用于告知 Meson 如何针对特定的目标平台（无论是与当前主机相同还是不同）进行构建。

2. **检测交叉编译环境：**
   - **基于 `dpkg-architecture` (Debian-like 系统)：**  如果提供了 `--debarch` 参数，脚本会调用 `dpkg-architecture` 命令来获取目标 Debian 架构的信息（例如，目标 CPU 架构、操作系统、ABI 等）。
   - **基于环境变量：**  如果未指定 `--debarch` 或在非 Debian 系统上，脚本会查找特定的环境变量（例如 `CC`, `CXX`, `AR`, `CFLAGS`, `LDFLAGS` 等）来确定交叉编译工具链的位置和编译/链接选项。
   - **通过命令行参数显式指定：** 允许用户通过 `--system`, `--subsystem`, `--kernel`, `--cpu`, `--cpu-family`, `--endian` 等参数显式指定目标系统的属性。

3. **检测本地编译环境：**
   - **基于环境变量：**  查找标准的环境变量（例如 `CC`, `CXX` 等）来确定本地编译器。
   - **检测缺失的编译器和二进制工具：** 如果在环境变量中找不到，脚本会尝试在系统的 PATH 中查找常见的编译器（如 `gcc`, `g++`）和二进制工具（如 `ar`, `strip`）。
   - **使用 `_FOR_BUILD` 后缀的环境变量：** 支持使用带有 `_FOR_BUILD` 后缀的环境变量，用于区分构建主机上的工具和目标构建所使用的工具。

4. **收集编译器和链接器信息：**
   - 检测 C, C++, Objective-C, Objective-C++ 等语言的编译器路径。
   - 从环境变量中提取编译和链接选项（例如，`CFLAGS`, `CXXFLAGS`, `LDFLAGS`）。

5. **收集其他二进制工具信息：**
   - 检测 `ar` (归档工具), `strip` (去除符号信息工具), `objcopy` (对象文件复制工具), `ld` (链接器) 等二进制工具的路径。
   - 尝试检测 `cmake` 和 `pkg-config` 的路径。

6. **收集目标系统属性：**
   - 目标操作系统 (`system`)
   - 子系统 (`subsystem`)
   - 内核 (`kernel`)
   - CPU 架构 (`cpu`)
   - CPU 家族 (`cpu_family`)
   - 字节序 (`endian`)

7. **生成 CMake 相关信息：**
   - 如果检测到 `cmake`，会尝试生成一些 CMake 相关的变量，例如 `CMAKE_C_COMPILER`, `CMAKE_CXX_COMPILER`, `CMAKE_SYSTEM_NAME`, `CMAKE_SYSTEM_PROCESSOR`。

**与逆向的方法的关系：**

这个脚本与逆向工程有密切关系，因为它主要用于配置**交叉编译环境**。在逆向工程中，经常需要将工具或代码编译到目标设备上运行，而目标设备的架构可能与开发机器不同（例如，在 x86 开发机上为 ARM Android 设备编译 Frida Agent）。

**举例说明：**

假设你想在你的 x86 Linux 机器上为一台 ARM Android 设备编译 Frida。你需要一个 ARM 交叉编译工具链。你可以设置相应的环境变量，然后运行 `env2mfile.py` 来生成 Meson 的配置文件。

```bash
export CC=/opt/toolchains/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc
export CXX=/opt/toolchains/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-g++
export AR=/opt/toolchains/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-ar
export STRIP=/opt/toolchains/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-strip
# ... 其他可能需要的环境变量

python env2mfile.py --cross --system=linux --kernel=android --cpu=arm --endian=little -o arm_android.ini
```

这个命令会生成一个名为 `arm_android.ini` 的文件，其中包含了为 ARM Android 平台构建所需的编译器和工具信息。Meson 在构建时会读取这个文件，从而使用正确的交叉编译工具链。

**涉及二进制底层，Linux, Android 内核及框架的知识：**

1. **二进制底层知识：**
   - **CPU 架构 (`--cpu`, `--cpu-family`) 和字节序 (`--endian`)：** 这些参数直接关系到目标平台 CPU 的指令集和数据存储方式。逆向工程师需要理解目标平台的这些底层细节，才能正确分析和修改二进制代码。
   - **编译器和链接器 (`CC`, `CXX`, `LD`)：**  脚本需要知道交叉编译工具链中这些工具的位置。这些工具负责将源代码转换为目标平台可执行的二进制代码。
   - **`ar`, `strip`, `objcopy` 等工具：** 这些是处理二进制文件的工具，在构建过程中用于创建库文件、去除调试信息、复制对象文件等。

2. **Linux 内核知识：**
   - **`--system=linux` 和 `--kernel=android`：**  指定目标操作系统是 Linux，并且是 Android 内核。这会影响 Meson 在构建过程中的某些决策，例如查找特定的库或头文件。

3. **Android 框架知识：**
   - 虽然脚本本身不直接涉及 Android 框架的细节，但它生成的配置文件用于构建在 Android 上运行的软件（比如 Frida Agent）。理解 Android 的框架对于逆向在 Android 上运行的应用程序至关重要。

**逻辑推理，假设输入与输出：**

**假设输入：**

```bash
export CC=/usr/bin/gcc
export CXX=/usr/bin/g++
python env2mfile.py --native -o native.ini
```

**预期输出 (简化版 `native.ini`):**

```ini
[binaries]
# Compilers
c = ['/usr/bin/gcc']
cpp = ['/usr/bin/g++']

# Other binaries
ar = ['/usr/bin/ar']
strip = ['/usr/bin/strip']
# ... 其他检测到的二进制工具

[built-in options]
```

**假设输入 (交叉编译)：**

```bash
export CC=/opt/cross/arm-linux-gnueabihf-gcc
export CXX=/opt/cross/arm-linux-gnueabihf-g++
python env2mfile.py --cross --system=linux --cpu=arm -o arm.ini
```

**预期输出 (简化版 `arm.ini`):**

```ini
[binaries]
# Compilers
c = ['/opt/cross/arm-linux-gnueabihf-gcc']
cpp = ['/opt/cross/arm-linux-gnueabihf-g++']

# Other binaries
ar = ['/opt/cross/arm-linux-gnueabihf-ar']
strip = ['/opt/cross/arm-linux-gnueabihf-strip']
# ... 其他检测到的二进制工具

[built-in options]

[host_machine]
cpu = 'arm'
system = 'linux'
```

**用户或编程常见的使用错误：**

1. **未设置必要的环境变量：**  如果用户忘记设置 `CC` 或 `CXX` 等环境变量，脚本可能无法找到编译器，导致生成的配置文件不完整或错误。
   ```bash
   # 忘记设置 CC 环境变量
   export CXX=/usr/bin/g++
   python env2mfile.py --native -o native.ini
   ```
   脚本可能会警告找不到 C 编译器。

2. **交叉编译时参数不完整：**  用户可能只指定了 `--cross`，但没有提供目标系统的其他信息，如 `--system` 或 `--cpu`。
   ```bash
   python env2mfile.py --cross -o cross.ini
   ```
   脚本会报错，提示缺少必要的交叉编译属性。

3. **本地编译和交叉编译参数混用：**  用户可能同时指定了 `--cross` 和 `--native`，这会导致冲突。
   ```bash
   python env2mfile.py --cross --native -o out.ini
   ```
   脚本会明确指出只能选择一个模式。

4. **`--debarch` 参数与当前环境不符：**  如果用户在非 Debian 系统上使用了 `--debarch` 参数，或者指定的架构与实际环境不符，可能会导致错误或生成不正确的配置文件。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要使用 Meson 构建 Frida 或其他项目。**
2. **构建目标平台与当前开发机器不同，需要进行交叉编译。**
3. **用户了解到 Meson 需要一个机器定义文件来配置交叉编译环境。**
4. **用户可能在 Meson 的文档中或者其他地方找到了 `env2mfile.py` 这个脚本。**
5. **用户意识到需要根据自己的交叉编译工具链和目标平台设置相应的环境变量。**
6. **用户根据目标平台的架构和操作系统，选择使用 `--cross` 或 `--native` 参数运行 `env2mfile.py`。**
7. **如果目标是 Debian-like 系统，并且用户知道目标架构的 `dpkg` 名称，可能会使用 `--debarch` 参数。**
8. **用户指定输出文件的路径和名称 (`-o` 参数)。**
9. **运行脚本后，检查生成的 `.ini` 文件，确认其中包含了正确的编译器、工具和目标系统信息。**

**作为调试线索，如果用户报告构建失败，可以检查以下几点：**

* **用户运行 `env2mfile.py` 时设置的环境变量是否正确，是否指向了正确的交叉编译工具链。**
* **用户提供的命令行参数是否与目标平台匹配（例如，`--system`, `--cpu` 等）。**
* **如果使用了 `--debarch`，目标系统是否真的是 Debian-like，并且指定的架构是否正确。**
* **生成的 `.ini` 文件中编译器和工具的路径是否正确。**
* **是否存在权限问题，导致脚本无法访问环境变量或执行外部命令（如 `dpkg-architecture`）。**

总而言之，`env2mfile.py` 是 Frida 项目中一个关键的辅助工具，它简化了为 Meson 构建系统配置编译环境的过程，尤其是对于需要进行交叉编译的场景，这在逆向工程和嵌入式开发中非常常见。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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