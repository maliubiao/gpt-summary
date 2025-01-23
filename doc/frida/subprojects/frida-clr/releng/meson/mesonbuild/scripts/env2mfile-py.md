Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the overall structure. The filename `env2mfile.py` and the comment "Generate cross compilation definition file for the Meson build system" immediately suggest its primary function: converting environment variables into a Meson machine file. The `frida` path indicates this is specific to the Frida project's build system.

**2. Identifying Key Functionalities (Decomposition):**

Next, I scanned the code for major functions and their roles:

* **`has_for_build()`:** Checks for `*_FOR_BUILD` environment variables, hinting at a distinction between host and target environments.
* **`add_arguments()`:**  Uses `argparse` to define command-line options, providing insight into what the script configures (architecture, compilers, output file, cross/native compilation).
* **`MachineInfo` class:**  A data structure to hold information about the target machine (compilers, binaries, properties, etc.). This is central to the script's purpose.
* **`locate_path()`:**  A utility function to find executable paths, crucial for identifying compilers and tools.
* **`write_args_line()`:**  Formats output lines for the Meson machine file.
* **`get_args_from_envvars()`:** Extracts compiler flags and linker flags from environment variables like `CPPFLAGS`, `CFLAGS`, `LDFLAGS`.
* **`deb_detect_cmake()`, `deb_compiler_lookup()`, `detect_cross_debianlike()`:**  Specific logic for detecting cross-compilation environments on Debian-like systems using `dpkg-architecture`. This is a significant part of the cross-compilation handling.
* **`write_machine_file()`:**  Writes the collected information to the output file in the Meson format.
* **`detect_language_args_from_envvars()`, `detect_compilers_from_envvars()`, `detect_binaries_from_envvars()`, `detect_properties_from_envvars()`:** Functions to systematically detect compilers, binaries, and properties based on environment variables. The optional `envvar_suffix` parameter suggests handling both native and cross-compilation environments.
* **`detect_cross_system()`:** Handles explicit cross-compilation target specifications via command-line arguments.
* **`detect_cross_env()`:** Orchestrates the detection of cross-compilation settings, potentially using Debian tools or generic environment variables.
* **`add_compiler_if_missing()`, `detect_missing_native_compilers()`, `detect_missing_native_binaries()`:** Logic to automatically find common compilers and tools if not explicitly specified.
* **`detect_native_env()`:**  Detects the native compilation environment, potentially using `*_FOR_BUILD` variables.
* **`run()`:** The main entry point, orchestrating the entire process based on command-line arguments.

**3. Identifying Connections to Reverse Engineering:**

With the core functionalities in mind, I looked for aspects relevant to reverse engineering:

* **Cross-compilation:**  This is a big clue. Reverse engineers often need to analyze software for different architectures than their development machine. Setting up a proper cross-compilation environment is key.
* **Compiler and linker flags:**  The script processes `CFLAGS`, `CXXFLAGS`, `LDFLAGS`. These flags significantly impact the generated binary. Reverse engineers need to understand how these flags affect things like optimizations, debugging symbols, and linking behavior.
* **Target architecture:** The script handles specifying target OS, CPU, and endianness. These are fundamental to understanding the binary's structure and behavior.
* **Binary tools:** The script deals with `ar`, `strip`, `objcopy`, `ld`. Reverse engineers use these tools for tasks like examining archives, removing symbols, and manipulating object files.

**4. Identifying Connections to Binary/Kernel/Framework Knowledge:**

* **Low-level details:** The focus on architecture, endianness, and compiler/linker flags directly relates to binary structure and execution.
* **Linux and Android:** The mention of `dpkg-architecture` (Debian/Ubuntu), and the Frida context itself (often used for Android and other platforms) indicates relevance to these systems. Kernel knowledge is implicit in understanding how binaries interact with the OS. "Framework" could refer to user-space frameworks on Android, which Frida can interact with.

**5. Logical Reasoning (Input/Output Examples):**

Here, I considered how the script would behave with different inputs:

* **Simple native build:**  If no cross-compilation flags are given, the script would try to find the native compiler (e.g., `gcc`) and generate a machine file reflecting the host system.
* **Cross-compilation for ARM:**  Providing `--cross --system linux --cpu arm` would trigger the cross-compilation logic, looking for ARM compilers and setting the target architecture in the output file.
* **Using `*_FOR_BUILD` variables:** Setting environment variables like `CC_FOR_BUILD` and running the script without `--cross` would use those variables to configure a "for build" environment, potentially used when building tools that run on the host but produce output for the target.

**6. Common User Errors:**

I considered what mistakes users might make:

* **Missing compiler:** Not having the specified cross-compiler in the `PATH`.
* **Incorrect architecture:** Specifying an architecture that doesn't match the installed cross-toolchain.
* **Conflicting options:** Using both `--cross` and `--native`.
* **Incorrect environment variables:**  Having `CFLAGS` set for the host system when intending to cross-compile.

**7. Debugging Clues (How to Reach the Code):**

I thought about the steps a developer or user would take to end up executing this script:

* **Building Frida:** This is the primary context. The script is part of Frida's build system.
* **Configuring the build:**  Meson is used for building. The user would run `meson` to configure the build, and Meson would internally call this script based on the project's configuration (likely when setting up cross-compilation).
* **Troubleshooting build issues:** If there are problems with cross-compilation, a developer might need to examine the generated machine file or the script's execution to understand why the build is failing.

**8. Iteration and Refinement:**

Throughout this process, I would reread sections of the code, refine my understanding, and correct any initial assumptions. For example, initially, I might have overlooked the importance of the `*_FOR_BUILD` variables, but noticing them in several functions would lead me to investigate their purpose more closely.

By systematically addressing these points, I could build a comprehensive understanding of the script's functionality and its relevance to different areas.
这个Python脚本 `env2mfile.py` 的主要功能是为 Frida 动态 instrumentation 工具的 Meson 构建系统生成交叉编译定义文件或本地编译定义文件。它通过读取环境变量和命令行参数来收集关于目标机器或本地构建环境的信息，并将这些信息写入一个 Meson 可以理解的格式的文件中。

以下是它的详细功能点：

**1. 生成 Meson 构建系统使用的机器定义文件:**

   - 脚本的核心目标是将关于编译器、工具链、目标架构等信息转化为 Meson 构建系统可以解析的格式。这些文件通常被命名为 `*.ini` 或 `*.txt`，包含 `[binaries]`, `[built-in options]`, `[properties]`, `[host_machine]` 等节，定义了构建过程中使用的工具和配置。

**2. 支持交叉编译和本地编译:**

   - 通过命令行参数 `--cross` 和 `--native`，脚本可以生成用于交叉编译（在一种架构上构建用于另一种架构的软件）或本地编译的文件。

**3. 从环境变量中获取构建信息:**

   - 脚本会读取诸如 `CC`, `CXX`, `AR`, `STRIP`, `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS` 等环境变量，这些变量通常包含了编译器路径、编译选项和链接选项等关键信息。这使得用户可以通过设置环境变量来控制构建过程。

**4. 支持 Debian-like 系统的交叉编译配置:**

   - 对于 Debian 或 Ubuntu 等系统，脚本可以使用 `dpkg-architecture` 命令来自动检测目标架构的配置信息（通过 `--debarch` 参数）。这大大简化了在这些系统上进行交叉编译的配置过程。

**5. 允许用户显式指定目标系统信息:**

   - 通过命令行参数 `--system`, `--subsystem`, `--kernel`, `--cpu`, `--cpu-family`, `--endian`，用户可以显式地指定目标系统的操作系统、子系统、内核、CPU 架构、CPU 家族和字节序等信息。这在无法通过环境变量或 `dpkg-architecture` 自动检测时非常有用。

**6. 检测和配置编译器和二进制工具:**

   - 脚本会尝试在系统的 `PATH` 环境变量中查找指定的编译器（如 gcc, g++）和二进制工具（如 ar, strip, objcopy, ld）。对于交叉编译，它会查找带有目标架构前缀的工具（例如 `arm-linux-gnueabi-gcc`）。

**7. 处理编译器和链接器参数:**

   - 脚本会将从环境变量中获取的 `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `LDFLAGS` 等参数添加到生成的 Meson 配置文件中，以便在构建过程中传递给编译器和链接器。

**8. 生成 CMake 工具链文件所需的变量:**

   - 脚本可以检测系统中是否存在 CMake，并生成一些与 CMake 工具链文件相关的变量，例如 `CMAKE_C_COMPILER`, `CMAKE_CXX_COMPILER`, `CMAKE_SYSTEM_NAME`, `CMAKE_SYSTEM_PROCESSOR`。

**9. 支持 "for build" 环境:**

   - 脚本检查以 `_FOR_BUILD` 结尾的环境变量（例如 `CC_FOR_BUILD`），这通常用于构建在构建主机上运行的工具，这些工具会生成用于目标平台的代码或文件。

**与逆向方法的关系及举例说明:**

这个脚本与逆向工程有密切关系，特别是当需要在与开发机器不同的目标平台上进行逆向分析时。

**举例说明:**

- **交叉编译 Frida Server 到 Android 设备:**  一个逆向工程师可能需要在 x86 开发机上编译 Frida Server 以运行在 ARM 架构的 Android 设备上。这时，可以使用这个脚本生成一个用于 Android ARM 架构的 Meson 交叉编译定义文件。
    - **用户操作:**
        1. 安装 Android NDK (Native Development Kit)，其中包含了交叉编译工具链。
        2. 设置相关的环境变量，例如指向 NDK 中 ARM 工具链的路径：
           ```bash
           export PATH="/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
           export CC="armv7a-linux-androideabi-clang"
           export CXX="armv7a-linux-androideabi-clang++"
           export AR="arm-linux-androideabi-ar"
           export STRIP="arm-linux-androideabi-strip"
           # ... 其他必要的环境变量
           ```
        3. 运行 `env2mfile.py` 脚本，指定输出文件和 `--cross` 参数：
           ```bash
           python frida/subprojects/frida-clr/releng/meson/mesonbuild/scripts/env2mfile.py --cross -o android_arm.ini
           ```
        4. 脚本会读取上述环境变量，生成 `android_arm.ini` 文件，其中包含了用于交叉编译到 Android ARM 平台的编译器和工具链信息。
        5. 在配置 Meson 构建时，指定这个生成的定义文件：
           ```bash
           meson setup build --cross-file android_arm.ini
           ```
    - **逆向意义:** 逆向工程师可以使用编译好的 Frida Server 来动态分析 Android 应用程序的行为，例如 hook 函数、查看内存等。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

脚本的处理过程和生成的文件涉及到以下底层知识：

**举例说明:**

- **二进制底层:**
    - **字节序 (Endianness):** 脚本允许通过 `--endian` 参数指定目标平台的字节序（大端或小端），这直接影响到二进制数据的解析和处理。不同的 CPU 架构可能有不同的默认字节序。
    - **目标架构 (CPU, CPU Family):**  脚本需要知道目标 CPU 的架构（例如 ARM, x86, MIPS）和 CPU 家族（例如 armv7, arm64），以便选择正确的编译器和生成相应的机器码。
- **Linux:**
    - **环境变量:** 脚本大量依赖 Linux 系统的环境变量来获取构建信息，这是 Linux 系统中配置程序行为的常用方法。
    - **`dpkg-architecture`:**  脚本在 Debian-like 系统上使用 `dpkg-architecture` 命令，这是一个 Debian 包管理系统提供的工具，用于获取关于系统架构的信息。
- **Android 内核及框架:**
    - **交叉编译到 Android:**  正如上面的逆向例子，为了让 Frida Server 运行在 Android 设备上，需要使用 Android NDK 提供的交叉编译工具链。脚本需要能够正确识别和配置这些工具链。
    - **Android NDK 工具链前缀:**  Android NDK 的工具链通常带有特定的前缀，例如 `arm-linux-androideabi-` 或 `aarch64-linux-android-`。脚本需要能够处理这些前缀来找到正确的工具。

**逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，例如根据环境变量的存在与否来判断是否需要设置某些配置。

**假设输入与输出:**

**假设输入 1 (本地编译):**

- 命令行参数: `--native -o native.ini`
- 环境变量:
    ```bash
    export CC="/usr/bin/gcc"
    export CXX="/usr/bin/g++"
    export CFLAGS="-O2 -Wall"
    ```

**输出 1 (native.ini):**

```ini
[binaries]
# Compilers
c = ['/usr/bin/gcc']
cpp = ['/usr/bin/g++']

# Other binaries

[built-in options]
c_args = ['-O2', '-Wall']
cpp_args = ['-O2', '-Wall']

[properties]

[host_machine]
cpu = 'your_host_cpu'  # 实际值会根据你的主机 CPU 而定
cpu_family = 'your_host_cpu_family' # 实际值会根据你的主机 CPU 而定
endian = 'little'  # 或 'big'
system = 'linux'  # 或其他操作系统
```

**假设输入 2 (交叉编译到 ARM Linux):**

- 命令行参数: `--cross --system linux --cpu arm --endian little -o arm_linux.ini`
- 环境变量:
    ```bash
    export CC="arm-linux-gnueabi-gcc"
    export CXX="arm-linux-gnueabi-g++"
    export AR="arm-linux-gnueabi-ar"
    ```

**输出 2 (arm_linux.ini):**

```ini
[binaries]
# Compilers
c = ['arm-linux-gnueabi-gcc']
cpp = ['arm-linux-gnueabi-g++']

# Other binaries
ar = ['arm-linux-gnueabi-ar']

[built-in options]

[properties]

[host_machine]
cpu = 'arm'
cpu_family = 'arm'
endian = 'little'
system = 'linux'
```

**涉及用户或编程常见的使用错误及举例说明:**

- **环境变量设置错误:** 用户可能设置了错误的编译器路径或编译选项，导致构建失败。
    - **例子:** 用户将 `CC` 环境变量设置为一个不存在的路径，或者设置了与目标平台不兼容的编译选项。
- **缺少必要的交叉编译工具链:**  进行交叉编译时，用户可能没有安装目标平台的交叉编译工具链。
    - **例子:** 尝试交叉编译到 ARM，但没有安装 `arm-linux-gnueabi-gcc` 等工具。
- **命令行参数使用错误:** 用户可能错误地使用了 `--cross` 和 `--native` 参数，或者忘记指定输出文件。
    - **例子:** 同时指定了 `--cross` 和 `--native`，或者没有使用 `-o` 参数指定输出文件名。
- **与 Meson 构建系统的配置不匹配:** 生成的定义文件可能与 Meson 项目的 `meson.build` 文件中的配置不匹配，导致构建错误。
    - **例子:**  定义文件中指定的编译器版本与 `meson.build` 中要求的版本不一致。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 项目的开发者或贡献者:**  在开发 Frida 的过程中，可能需要修改或调试其构建系统，包括交叉编译的配置。他们可能会查看这个脚本的源代码以了解其工作原理。
2. **尝试为特定平台编译 Frida 的用户:**  用户可能希望在非标准的平台上构建 Frida，或者遇到自动检测配置失败的情况。他们可能需要手动创建或修改 Meson 的机器定义文件。
3. **Frida 的构建流程:**  当用户运行 Meson 配置 Frida 的构建环境时 (`meson setup build`)，Meson 内部可能会调用这个脚本来生成或更新机器定义文件。如果构建过程中出现与编译器或工具链相关的问题，开发者可能会检查这个脚本的输出来排查问题。
4. **查看 Frida 的构建脚本:** Frida 的构建脚本（通常是 `meson.build` 或其他相关的 Python 脚本）可能会调用或依赖于这个 `env2mfile.py` 脚本。为了理解构建过程，开发者可能会查看这些脚本的源代码。
5. **调试构建错误:**  如果 Frida 的构建过程失败，错误信息可能会指向与编译器或工具链配置相关的问题。开发者可能会追踪错误信息，最终定位到这个脚本，以查看生成的机器定义文件是否正确，或者脚本本身是否有错误。

总而言之，`env2mfile.py` 是 Frida 构建系统中一个关键的组件，负责收集和组织构建环境的信息，以便 Meson 可以正确地配置编译过程，特别是对于需要交叉编译的场景。理解这个脚本的功能对于 Frida 的开发者和需要在不同平台上构建 Frida 的用户来说非常重要。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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