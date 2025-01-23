Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to read the initial comments and docstrings. They clearly state the purpose: generating cross-compilation definition files for the Meson build system. This immediately tells us it's about configuring the build process for different target architectures.

**2. Identifying Key Components:**

Next, I scan the code for major building blocks. I notice:

* **Argument Parsing (`argparse`):**  The `add_arguments` function indicates command-line options are used to control the script's behavior. This is a standard pattern for command-line tools.
* **`MachineInfo` Class:** This class acts as a data structure to hold information about the target machine (compilers, binaries, properties, etc.). This is central to the script's purpose.
* **Environment Variable Handling:**  The script heavily relies on environment variables (e.g., `CPPFLAGS`, `CC`, `AR`). Functions like `get_args_from_envvars`, `detect_compilers_from_envvars`, etc., are key.
* **Debian/dpkg Specific Logic:**  The presence of functions like `detect_cross_debianlike`, `deb_compiler_lookup`, and the handling of `debarch` suggest special handling for Debian-based systems.
* **File I/O:** The `write_machine_file` function is responsible for writing the output configuration file.
* **Compiler/Binary Detection:** Functions like `locate_path`, `shutil.which`, and the checks within `detect_missing_native_compilers` and `detect_missing_native_binaries` deal with finding necessary tools.
* **Cross vs. Native Modes:** The `--cross` and `--native` flags and the conditional logic in `run` highlight the script's ability to generate configurations for either cross-compilation or native builds.

**3. Analyzing Functionality:**

Now I go through the functions, understanding what each does:

* **`has_for_build()`:** Checks for `*_FOR_BUILD` environment variables, suggesting a mechanism for isolating build environments.
* **`add_arguments()`:**  Defines the command-line interface.
* **`MachineInfo`:**  A simple data container.
* **`locate_path()`:**  Finds executables in the system's PATH. Crucial for locating compilers and tools.
* **`write_args_line()`:** Formats output for the configuration file.
* **`get_args_from_envvars()`:** Extracts compiler flags and linker flags from common environment variables.
* **`deb_detect_cmake()`:**  Populates CMake-related settings for Debian cross-compilation.
* **`deb_compiler_lookup()`:**  Searches for cross-compilers with Debian-style naming conventions.
* **`detect_cross_debianlike()`:**  Gathers cross-compilation information using `dpkg-architecture`.
* **`write_machine_file()`:**  Writes the `MachineInfo` to a file in Meson's configuration format.
* **`detect_language_args_from_envvars()`:**  Handles language-specific compiler and linker flag environment variables.
* **`detect_compilers_from_envvars()`:**  Identifies compilers based on environment variables.
* **`detect_binaries_from_envvars()`:** Identifies other build tools (ar, strip, etc.) based on environment variables.
* **`detect_properties_from_envvars()`:**  Detects properties like `pkg_config_libdir`.
* **`detect_cross_system()`:**  Handles command-line arguments for specifying cross-compilation target details.
* **`detect_cross_env()`:** Orchestrates cross-compilation detection, handling both Debian and generic environment variable approaches.
* **`add_compiler_if_missing()`:**  Attempts to find native compilers if they weren't explicitly set.
* **`detect_missing_native_compilers()`:**  Detects standard native compilers.
* **`detect_missing_native_binaries()`:** Detects standard native build tools.
* **`detect_native_env()`:**  Detects the native build environment.
* **`run()`:**  The main function, coordinating the detection and file writing based on command-line arguments.

**4. Connecting to Reverse Engineering, Binary, Kernel, etc.:**

At this stage, I look for connections to the specific prompts:

* **Reverse Engineering:** The script's core function – setting up cross-compilation – is often used in reverse engineering to build tools for target devices or architectures. The ability to specify target CPU, endianness, etc., is crucial here.
* **Binary/Low-Level:** The script deals with compilers, linkers, and other binary tools. The generated configuration files will directly influence how binaries are built. Understanding compiler flags and linker options is essential for low-level work.
* **Linux/Android Kernel/Framework:**  Cross-compilation is fundamental to building software for embedded systems like Android. The script's handling of `system`, `kernel`, and CPU architecture directly relates to targeting these platforms. The Debian-specific logic is also relevant as many embedded Linux distributions are Debian-based.

**5. Constructing Examples and Scenarios:**

Now I start creating concrete examples:

* **Logic/Input-Output:**  Think about simple cases like setting `CC` and `CXX` environment variables.
* **Usage Errors:** Consider common mistakes users might make, like specifying both `--cross` and `--native`.
* **Debugging:** Trace how a user might end up running this script as part of setting up a build environment.

**6. Refining and Organizing:**

Finally, I organize the information into the requested categories, ensuring clarity and providing specific examples for each point. I double-check that I've addressed all parts of the original prompt. I try to use precise language and connect the script's functionality to the underlying concepts (e.g., explaining *why* cross-compilation is important for reverse engineering).

This iterative process of understanding the code, identifying key components, analyzing functionality, making connections, and constructing examples leads to a comprehensive and well-structured explanation.
这个Python脚本 `env2mfile.py` 的主要功能是**为 Meson 构建系统生成交叉编译定义文件或本地编译定义文件**。它通过检测当前环境中的环境变量以及命令行参数来收集关于编译器、链接器和其他构建工具的信息，并将这些信息写入一个 Meson 可以理解的配置文件。

让我们更详细地分解其功能，并联系到你提到的各个方面：

**1. 功能列表:**

* **生成交叉编译配置文件:**  当使用 `--cross` 选项时，脚本会尝试检测目标架构的编译器、链接器等信息，并生成一个描述目标系统的 `.ini` 格式的 Meson 配置文件。
* **生成本地编译配置文件:** 当使用 `--native` 选项时，脚本会检测本地系统的编译器、链接器等信息，并生成一个描述本地系统的 Meson 配置文件。
* **从环境变量中检测编译器和构建工具:**  脚本会检查一系列预定义的环境变量（例如 `CC`, `CXX`, `AR`, `STRIP` 等）来确定使用的编译器和构建工具的路径。这使得用户可以通过设置环境变量来指定特定的工具链。
* **支持 Debian-like 系统的交叉编译配置检测:**  当指定 `--debarch` 选项时，脚本会利用 `dpkg-architecture` 命令来获取 Debian 架构的信息，并根据这些信息查找相应的交叉编译工具。
* **允许用户通过命令行指定目标系统属性:**  通过 `--system`, `--subsystem`, `--kernel`, `--cpu`, `--cpu-family`, `--endian` 等选项，用户可以显式地指定交叉编译目标系统的各种属性。
* **处理编译器和链接器参数:**  脚本会读取 `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `OBJCFLAGS`, `OBJCXXFLAGS`, `LDFLAGS` 等环境变量，并将这些参数写入配置文件，以便 Meson 在构建时使用。
* **支持 CMake 集成:**  脚本会尝试检测 `cmake` 工具，并在配置文件中生成 CMake 相关的配置项。
* **检测 `pkg-config` 和 `cups-config` 等工具:**  脚本会尝试查找 `pkg-config` 和 `cups-config` 等工具，并将它们添加到配置文件中。
* **处理 `*_FOR_BUILD` 后缀的环境变量:**  脚本支持使用带有 `_FOR_BUILD` 后缀的环境变量，这允许在构建过程中区分宿主机和目标机的工具链。
* **生成 `.ini` 格式的输出文件:**  最终生成的文件是 `.ini` 格式的，包含了 `[binaries]`, `[built-in options]`, `[properties]`, `[cmake]`, `[host_machine]` 等 секции，Meson 可以解析这些 секции来配置构建过程。

**2. 与逆向方法的关系及举例说明:**

该脚本与逆向工程密切相关，因为它为交叉编译提供了配置支持。在逆向工程中，我们经常需要在宿主机上编译针对目标设备的工具或库。

* **示例:** 假设你要逆向一个运行在 ARM Linux 上的固件。你需要使用一个针对 ARM 架构的交叉编译工具链。你可以设置以下环境变量，然后运行 `env2mfile.py` 来生成一个 Meson 配置文件：

   ```bash
   export AR=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-ar
   export AS=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-as
   export CC=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc
   export CXX=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-g++
   export LD=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-ld
   export STRIP=/opt/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-strip
   export CPPFLAGS="-I/opt/arm-linux-gnueabihf/include"
   export LDFLAGS="-L/opt/arm-linux-gnueabihf/lib"

   python env2mfile.py --cross -o arm-linux.ini --system linux --cpu arm --endian little
   ```

   这个命令会生成一个名为 `arm-linux.ini` 的文件，其中包含了指向你的 ARM 交叉编译工具链的路径和相关的编译/链接选项。然后，你可以在你的 Meson 项目中使用这个配置文件来构建针对 ARM Linux 的二进制文件。这些二进制文件可能是你为了逆向分析目标固件而构建的辅助工具，例如自定义的调试器 agent 或分析脚本。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:** 脚本处理的是编译器、链接器等构建工具，这些工具直接操作二进制文件。它需要知道如何查找这些工具（通过 `PATH` 环境变量），以及如何将编译和链接参数传递给它们。
    * **示例:** 脚本中的 `locate_path` 函数就直接涉及到在文件系统中查找可执行二进制文件的操作。生成的配置文件中关于 `ar`, `strip`, `objcopy` 等二进制工具的配置，也直接影响最终二进制文件的生成。
* **Linux:** 脚本对 Debian-like 系统的特殊处理（通过 `dpkg-architecture`）是 Linux 特有的。此外，很多构建工具（如 `gcc`, `g++`, `ar` 等）在 Linux 系统中非常常见。
    * **示例:**  `detect_cross_debianlike` 函数利用 `dpkg-architecture` 命令获取 Debian 系统的架构信息，这与 Linux 的包管理系统紧密相关。
* **Android 内核及框架:**  虽然脚本本身没有直接针对 Android 的特定代码，但它可以被用于为 Android 构建软件。Android 基于 Linux 内核，其用户空间程序通常需要交叉编译。
    * **示例:**  如果你想使用 Frida 来 hook Android 应用程序，你需要在你的开发机器上构建 Frida 的 Gadget 或 Agent。这通常需要针对 Android 架构（例如 `arm64-v8a`, `armeabi-v7a`）进行交叉编译。你可以使用此脚本生成相应的 Meson 交叉编译配置文件，指定 `--system android` 和 `--cpu` 为相应的架构。

**4. 逻辑推理及假设输入与输出:**

* **假设输入:** 用户设置了以下环境变量：
  ```bash
  export CC=/usr/bin/gcc
  export CXX=/usr/bin/g++
  export CFLAGS="-Wall -O2"
  ```
  并执行了命令：
  ```bash
  python env2mfile.py --native -o native.ini
  ```
* **逻辑推理:** 脚本会检测到 `CC` 和 `CXX` 环境变量指向的编译器，以及 `CFLAGS` 中定义的编译选项。由于使用了 `--native`，它会生成一个本地编译配置文件。
* **预期输出 (native.ini 的部分内容):**
  ```ini
  [binaries]
  c = ['/usr/bin/gcc']
  cpp = ['/usr/bin/g++']

  [built-in options]
  c_args = ['-Wall', '-O2']
  cpp_args = ['-Wall', '-O2']
  ```

**5. 涉及用户或编程常见的使用错误及举例说明:**

* **错误地同时指定 `--cross` 和 `--native`:**  脚本会检查这种情况并报错退出，因为一个配置文件要么是用于交叉编译，要么是用于本地编译，不能同时是两者。
    * **示例:** 如果用户运行 `python env2mfile.py --cross --native -o config.ini`，脚本会输出错误信息并终止。
* **缺少必要的交叉编译环境变量:**  如果用户使用 `--cross` 但没有设置必要的交叉编译工具链环境变量（例如 `CC`, `AR` 等），脚本可能无法正确检测到编译器，或者生成的配置文件可能不完整。
    * **示例:** 如果用户只设置了 `CC` 但没有设置 `AR`，运行 `python env2mfile.py --cross -o cross.ini` 后，`cross.ini` 文件中可能缺少 `ar` 的配置。
* **拼写错误的命令行参数:**  如果用户输入了错误的命令行参数（例如 `--cros` 而不是 `--cross`），`argparse` 模块会报错并显示帮助信息。
* **输出文件路径错误或权限问题:**  如果用户指定的输出文件路径不存在或没有写入权限，脚本在尝试写入文件时会报错。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户会按照以下步骤使用这个脚本，这也可以作为调试问题的线索：

1. **了解 Meson 构建系统:** 用户需要知道 Meson 使用特定的配置文件来定义构建环境。
2. **需要进行交叉编译或本地编译:** 用户可能正在为一个嵌入式设备构建软件（交叉编译）或者需要为一个项目配置本地构建环境。
3. **查找或创建 Meson 配置文件:** 用户可能需要创建一个新的 Meson 配置文件，或者需要更新现有的配置文件。
4. **发现 `env2mfile.py` 脚本:** 用户可能通过 Meson 的文档、示例或者其他资源了解到这个脚本可以辅助生成配置文件。
5. **设置必要的环境变量:** 用户根据自己的需求设置相关的环境变量，例如指定编译器路径、编译选项等。如果是交叉编译，需要设置交叉编译工具链的环境变量。
6. **执行 `env2mfile.py` 脚本:** 用户使用带有相应选项的命令来运行脚本，例如指定输出文件名、是否进行交叉编译等。
7. **检查生成的配置文件:** 用户查看生成的 `.ini` 文件，确认其中包含了预期的编译器、工具和选项。
8. **在 Meson 项目中使用配置文件:** 用户将生成的配置文件路径传递给 Meson 的配置命令，例如 `meson setup builddir --cross-file config.ini`。

**调试线索:**

* **检查环境变量:** 如果生成的配置文件不正确，首先要检查环境变量是否设置正确，特别是编译器和工具的路径。
* **检查命令行参数:** 确认运行脚本时使用的命令行参数是否正确，例如 `--cross` 或 `--native`，以及输出文件名等。
* **查看脚本输出:** 脚本在运行时可能会打印一些信息，例如检测到的编译器和工具，这些信息可以帮助判断问题所在。
* **手动创建或修改配置文件进行对比:** 可以尝试手动创建一个简单的 Meson 配置文件，与脚本生成的配置文件进行对比，找出差异。
* **查阅 Meson 文档:** 参考 Meson 的官方文档，了解配置文件的格式和选项，以及交叉编译的配置方法。

总而言之，`env2mfile.py` 是一个非常有用的工具，可以帮助用户快速生成 Meson 构建系统所需的配置文件，尤其是在需要进行交叉编译时，可以大大简化配置过程。理解其工作原理和使用方法，对于使用 Frida 进行动态Instrumentation 以及其他涉及交叉编译的场景都非常有帮助。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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