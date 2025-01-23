Response:
The user wants to understand the functionality of the Python script `env2mfile.py` which is part of the Frida dynamic instrumentation tool. I need to break down the script's purpose, identify its connections to reverse engineering, low-level aspects, and logical reasoning, and address potential user errors and debugging.

Here's a plan:

1. **Overall Functionality:** Describe the script's primary goal, which is to generate Meson build system definition files based on environment variables.

2. **Reverse Engineering Relevance:** Analyze how this script aids reverse engineering by setting up cross-compilation environments needed for targeting different architectures often encountered in reverse engineering targets. Provide examples.

3. **Low-Level/Kernel/Framework Knowledge:** Identify the script's interactions with low-level concepts like CPU architecture, endianness, and how it leverages environment variables related to toolchains for different platforms (Linux, Android).

4. **Logical Reasoning:**  Examine the conditional logic within the script (e.g., detecting cross vs. native compilation) and construct hypothetical input scenarios and their expected outputs (the generated Meson file).

5. **Common User Errors:** Pinpoint potential mistakes users might make when invoking the script and provide illustrative examples.

6. **Debugging Steps:** Explain how a user might arrive at running this script as part of a larger Frida debugging workflow.

Let's execute this plan step-by-step.
这个Python脚本 `env2mfile.py` 的主要功能是**根据当前的环境变量生成用于 Meson 构建系统的编译定义文件（通常是`.ini`格式的 machine file）。** 这些定义文件描述了目标平台的编译器、链接器和其他构建工具的位置以及相关的编译和链接参数。Meson 使用这些文件来配置构建过程，特别是进行交叉编译时。

下面是根据你的要求对脚本功能及其相关方面的详细说明：

**1. 功能列举：**

* **检测并提取编译器信息:**  脚本会检查特定的环境变量 (例如 `CC`, `CXX`, `AR`, `STRIP` 等)  以及根据 Debian 架构信息 (如果指定了 `--debarch`) 来定位 C, C++, Objective-C 等编程语言的编译器。
* **提取编译和链接参数:**  它会读取 `CPPFLAGS`, `CFLAGS`, `CXXFLAGS`, `OBJCFLAGS`, `OBJCXXFLAGS`, `LDFLAGS` 等环境变量，并将它们分解为编译和链接器的参数。
* **生成 Meson 格式的配置文件:**  脚本会将提取到的编译器路径、编译/链接参数以及目标平台的架构信息 (CPU, CPU 族, 字节序, 系统类型等)  写入到一个 `.ini` 格式的文件中，供 Meson 构建系统使用。
* **支持交叉编译和本地编译配置:**  通过 `--cross` 和 `--native` 参数，脚本可以生成用于交叉编译或本地编译的配置文件。
* **支持 Debian 架构配置:**  使用 `--debarch` 参数，可以利用 `dpkg-architecture` 命令来获取 Debian/Ubuntu 系统下的目标架构信息，方便生成交叉编译配置。
* **处理特定后缀的编译器:**  通过 `--gccsuffix` 参数，可以指定特定的 GCC 版本后缀，例如 `gcc-7`，以便在环境中存在多个 GCC 版本时选择正确的编译器。
* **检测 CMake 信息:** 脚本会尝试检测 `cmake` 命令，并提取一些 CMake 相关的配置信息。
* **检测 `pkg-config` 信息:** 脚本会尝试检测 `pkg-config` 命令，并提取库文件路径等信息。

**2. 与逆向方法的关系及举例说明：**

`env2mfile.py` 与逆向工程密切相关，尤其是在需要对目标平台（例如嵌入式设备、移动设备）进行代码注入、Hook 或者进行动态分析时。由于目标平台的架构可能与开发主机不同，因此需要进行**交叉编译**。

**举例说明：**

假设你想使用 Frida 对一个运行在 ARM 架构 Android 设备上的 Native 程序进行逆向分析。

1. **目标平台信息:** 你需要知道目标 Android 设备的 CPU 架构 (例如 `arm64-v8a`, `armeabi-v7a`)。
2. **交叉编译工具链:**  你需要安装一个针对该 ARM 架构的交叉编译工具链 (例如 `aarch64-linux-gnu-gcc`, `arm-linux-gnueabihf-g++`)。
3. **设置环境变量:** 你需要设置相关的环境变量，指向你的交叉编译工具链。例如：
   ```bash
   export CC=/path/to/aarch64-linux-gnu-gcc
   export CXX=/path/to/aarch64-linux-gnu-g++
   export AR=/path/to/aarch64-linux-gnu-ar
   export STRIP=/path/to/aarch64-linux-gnu-strip
   # ... 其他编译和链接参数 ...
   ```
4. **运行 `env2mfile.py`:**  你可以使用 `--cross` 参数来生成交叉编译配置文件：
   ```bash
   python frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/env2mfile.py \
       --cross \
       --system linux \
       --cpu aarch64 \
       --endian little \
       -o my_android_arm64.ini
   ```
   或者，如果你的环境已经配置好了 Debian 交叉编译环境，可以使用 `--debarch`：
   ```bash
   python frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/env2mfile.py \
       --cross \
       --debarch arm64 \
       -o my_android_arm64.ini
   ```
5. **Meson 构建:**  生成的 `my_android_arm64.ini` 文件将被 Meson 构建系统用于配置针对 ARM64 Android 平台的 Frida Gum 库的编译过程。这样，你就可以基于交叉编译的 Frida Gum 库来开发针对目标 Android 设备的 Frida 脚本或工具。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    * **CPU 架构 (`--cpu`, `--cpu-family`):**  脚本需要知道目标设备的 CPU 架构 (例如 ARM, x86, MIPS) 和 CPU 族 (例如 Cortex-A53, Intel Core i7)，这直接影响了指令集的选择和代码的生成。
    * **字节序 (`--endian`):**  不同的 CPU 架构可能使用大端 (big-endian) 或小端 (little-endian) 字节序来存储多字节数据。交叉编译时必须指定正确的字节序，否则会导致数据解析错误。
    * **编译和链接参数 (`CPPFLAGS`, `CFLAGS`, `LDFLAGS`):** 这些环境变量包含了与底层二进制代码生成和链接相关的选项，例如优化级别、ABI 兼容性、库文件路径等。

* **Linux:**
    * **系统类型 (`--system linux`):**  脚本需要知道目标操作系统是 Linux，以便设置正确的系统调用约定和库文件路径。
    * **工具链命名规范 (`host_arch-gcc`):**  在 Linux 交叉编译环境中，编译器和其他工具通常会带有目标架构的前缀，例如 `arm-linux-gnueabihf-gcc`。脚本会根据 `--debarch` 或环境变量来推断这些工具的名称。
    * **`dpkg-architecture`:**  对于 Debian/Ubuntu 系统，`dpkg-architecture` 命令可以提供关于主机或目标架构的详细信息，脚本利用这个命令来简化交叉编译配置。

* **Android 内核及框架:**
    * **Subsystem (`--subsystem`):**  虽然脚本中提供了 `--subsystem` 参数，但在 Android 的上下文中，通常 `system` 就足够了。但某些特定的嵌入式 Linux 系统可能会使用 `subsystem` 来更精细地划分。
    * **目标 ABI:**  Android 定义了应用二进制接口 (ABI)，例如 `armeabi-v7a`, `arm64-v8a`。虽然脚本本身不直接处理 ABI 的细节，但用户需要确保所设置的交叉编译工具链和相关的环境变量与目标 Android 设备的 ABI 兼容。

**举例说明：**

假设你正在为运行在 Android (基于 Linux 内核) 上的 ARM64 设备交叉编译 Frida Gadget。

* 你需要设置 `--cpu aarch64` 和 `--system linux`。
* 如果你使用 Debian 交叉编译环境，你可以使用 `--debarch arm64`，脚本会自动处理一些细节。
* 环境变量 `CC` 需要指向你的 ARM64 交叉编译器的路径，例如 `aarch64-linux-android-clang`。
* 你可能需要在 `CFLAGS` 中添加与 Android 平台相关的编译选项，例如 `-march=armv8-a`, `-mfpu=neon`, `-mfloat-abi=hard`。
* `LDFLAGS` 可能需要指定 Android 系统库的路径。

**4. 逻辑推理及假设输入与输出：**

脚本的主要逻辑是根据用户提供的参数和环境变量来推断目标平台的构建配置。

**假设输入：**

* **场景 1 (本地编译):**
    * 运行命令： `python env2mfile.py --native -o native.ini`
    * 环境变量： `CC=gcc`, `CXX=g++` (假设系统中存在 `gcc` 和 `g++` 命令)
* **场景 2 (交叉编译 - Debian 架构):**
    * 运行命令： `python env2mfile.py --cross --debarch armhf -o cross_armhf.ini`
    * 环境变量： 无特定要求，依赖于 Debian 交叉编译环境的配置。
* **场景 3 (交叉编译 - 手动指定):**
    * 运行命令： `python env2mfile.py --cross --system linux --cpu arm --endian little -o cross_arm_manual.ini`
    * 环境变量： `CC=arm-linux-gnueabihf-gcc`, `CXX=arm-linux-gnueabihf-g++`

**预期输出：**

* **场景 1 (`native.ini`):**
   ```ini
   [binaries]
   # Compilers
   c = ['gcc']
   cpp = ['g++']

   # Other binaries

   [built-in options]

   [properties]

   [host_machine]
   # (根据本地系统信息)
   ```
* **场景 2 (`cross_armhf.ini`):**
   ```ini
   [binaries]
   # Compilers
   c = ['arm-linux-gnueabihf-gcc']
   cpp = ['arm-linux-gnueabihf-g++']
   # ... 其他交叉编译工具 ...

   [built-in options]

   [properties]

   [host_machine]
   cpu = 'arm'
   cpu_family = 'armv7l'
   endian = 'little'
   system = 'linux'
   ```
* **场景 3 (`cross_arm_manual.ini`):**
   ```ini
   [binaries]
   # Compilers
   c = ['arm-linux-gnueabihf-gcc']
   cpp = ['arm-linux-gnueabihf-g++']

   # Other binaries

   [built-in options]

   [properties]

   [host_machine]
   cpu = 'arm'
   cpu_family = 'armv7l' # 可能会根据工具链推断
   endian = 'little'
   system = 'linux'
   ```

**5. 涉及用户或者编程常见的使用错误及举例说明：**

* **忘记指定 `--cross` 或 `--native`:**
   ```bash
   python env2mfile.py -o myconfig.ini  # 错误：缺少模式指定
   ```
   错误信息会提示用户必须指定 `--cross` 或 `--native`。
* **交叉编译时缺少必要的环境变量或参数:**
   ```bash
   python env2mfile.py --cross -o cross.ini # 错误：缺少系统、CPU等信息
   ```
   错误信息会提示缺少交叉编译所需的属性，例如 "Cross property \"system\" missing"。
* **指定了不存在的 Debian 架构:**
   ```bash
   python env2mfile.py --cross --debarch invalid_arch -o cross.ini
   ```
   这会导致 `dpkg-architecture` 命令执行失败，从而导致脚本出错。
* **环境变量与实际工具链不匹配:**
   ```bash
   export CC=/usr/bin/gcc  # 本地 GCC
   python env2mfile.py --cross --debarch armhf -o cross.ini
   ```
   虽然脚本会尝试根据 `--debarch` 查找交叉编译工具，但如果环境变量 `CC` 指向本地编译器，可能会导致混淆或构建错误。用户应该确保环境变量与预期的交叉编译环境一致。
* **拼写错误的参数名:**
   ```bash
   python env2mfile.py --corss ... # 错误：参数名拼写错误
   ```
   `argparse` 模块会抛出错误，提示未知的参数。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户在尝试使用 Frida 对非本地平台进行逆向工程时会接触到这个脚本。以下是一个可能的调试过程：

1. **目标:** 用户想在他们的开发机器上构建 Frida Gum 库，以便在目标设备上使用 (例如，注入到 Android 进程)。
2. **发现需要交叉编译:** 用户了解到目标设备的架构与开发机器不同，需要进行交叉编译。
3. **了解 Meson 构建系统:** Frida 使用 Meson 作为其构建系统，用户需要了解 Meson 的基本用法。
4. **寻找交叉编译配置:** 用户查阅 Frida 的文档或 Meson 的文档，了解到需要提供一个 machine file 来配置交叉编译环境。
5. **定位 `env2mfile.py`:** 用户可能会在 Frida 的源代码仓库中找到 `env2mfile.py` 这个脚本，它看起来像是用来生成 machine file 的工具。
6. **尝试运行 `env2mfile.py`:** 用户尝试运行该脚本，但可能会遇到各种错误，例如忘记指定 `--cross` 或缺少交叉编译所需的参数。
7. **阅读脚本帮助:** 用户通过运行 `python env2mfile.py --help` 来查看脚本的参数说明。
8. **配置交叉编译环境:** 用户根据目标平台的架构安装交叉编译工具链，并设置相关的环境变量 (例如 `CC`, `CXX`, `AR` 等)。
9. **使用 `--cross` 和相关参数:** 用户使用 `--cross` 参数，并根据目标平台的架构信息 (例如 `--system linux`, `--cpu arm`, `--endian little`) 运行脚本。如果使用 Debian 交叉编译环境，可能会使用 `--debarch` 参数。
10. **生成 machine file:** 脚本成功运行后，会生成一个 `.ini` 格式的 machine file。
11. **使用 Meson 构建:** 用户在 Frida Gum 的项目目录下使用 Meson，并指定生成的 machine file 进行配置和构建：
    ```bash
    meson setup builddir --cross-file my_cross_config.ini
    meson compile -C builddir
    ```
12. **调试构建错误:** 如果构建过程中出现错误，用户可能会回头检查生成的 machine file 是否正确，环境变量是否配置正确，或者交叉编译工具链是否工作正常。他们可能会修改环境变量或重新运行 `env2mfile.py` 来生成新的配置文件。

总而言之，`env2mfile.py` 是 Frida 构建过程中一个关键的辅助工具，它简化了为不同目标平台配置编译环境的过程，尤其在进行交叉编译以支持逆向工程场景时非常有用。理解其功能和使用方法对于成功构建和使用 Frida 进行动态分析至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/env2mfile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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