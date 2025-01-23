Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The core request is to analyze a Python file (`toolchain.py`) and explain its functionalities, especially in the context of reverse engineering, low-level interactions, and potential user errors. The request emphasizes providing concrete examples.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the code to get a general idea of its purpose. Keywords like "CMake," "toolchain," "compiler," "machine," "build_dir," etc., immediately suggest that this code is related to configuring the build process, specifically for projects using CMake. The file path (`frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/toolchain.py`) confirms this, indicating it's part of the Frida project and deals with generating CMake toolchain files within the Meson build system.

**3. Identifying Key Classes and Methods:**

Next, I'd identify the main class, `CMakeToolchain`, and its key methods. This involves looking for `class` definitions and `def` statements within the class. Important methods jump out:

* `__init__`:  The constructor, responsible for initializing the object's state. This tells me what information is required to create a `CMakeToolchain` object.
* `write`:  Suggests writing data to a file. The file name `CMakeMesonToolchainFile.cmake` is significant.
* `get_cmake_args`: Hints at generating arguments to be passed to CMake.
* `generate`:  Likely responsible for creating the content of the toolchain file.
* `generate_cache`:  Deals with generating CMake cache information.
* `get_defaults`:  Suggests setting up default values for CMake variables.
* `update_cmake_compiler_state`: Seems to be about determining compiler information.

**4. Analyzing Functionality Based on Method Names and Code:**

Now, I'd analyze each key method in more detail, looking at the code within them:

* **`__init__`:** I'd note the parameters it takes (CMakeExecutor, Environment, MachineChoice, etc.) and how it initializes instance variables. The calculation of `self.toolchain_file` and `self.cmcache_file` is important. The logic around `self.skip_check` based on `CMakeSkipCompilerTest` also stands out.
* **`write`:** This clearly writes the output of `generate()` and `generate_cache()` to files. This is the core action of the class.
* **`get_cmake_args`:**  It constructs a list of arguments, including the path to the generated toolchain file. This confirms the purpose of the `write` method.
* **`generate`:** This is where the toolchain file content is built. It includes handling preloaded files, setting compiler information (conditionally based on `skip_check`), adding variables from the Meson configuration, and including user-provided toolchain files. The code iterating through `self.variables` and the conditional inclusion of the user file are key parts.
* **`generate_cache`:**  This generates content for the CMake cache file based on `self.cmakestate.cmake_cache`.
* **`get_defaults`:** This method populates the `defaults` dictionary. The logic for mapping Meson system names to `CMAKE_SYSTEM_NAME`, setting `CMAKE_SIZEOF_VOID_P`, `CMAKE_SYSROOT`, and handling compiler executables is crucial. The distinction between cross-compilation and native builds is also important.
* **`update_cmake_compiler_state`:** This method involves creating a temporary CMake project, running CMake to gather compiler information, and then parsing the output. This is more complex and warrants careful examination. The use of `CMakeTraceParser` is a key detail.

**5. Connecting to the Prompts:**

With a solid understanding of the code's functionality, I would now address the specific prompts:

* **Functionality Listing:**  This is a direct summary of the analysis done in step 4.
* **Reverse Engineering Relevance:** I'd consider how the generated toolchain file would affect a reverse engineer. Specifically, the compiler flags and target architecture are critical for understanding the compiled binary. The example provided about architecture mismatches is a good illustration.
* **Binary/Low-Level/Kernel/Framework Knowledge:**  The code directly interacts with these concepts by setting variables like `CMAKE_SYSTEM_NAME`, `CMAKE_SYSTEM_PROCESSOR`, `CMAKE_SIZEOF_VOID_P`, and `CMAKE_SYSROOT`. The example about cross-compilation highlights the importance of this.
* **Logical Reasoning (Input/Output):** This requires thinking about the inputs to the `CMakeToolchain` class and the output it produces (the toolchain file). The example provided gives a concrete scenario.
* **User Errors:**  I'd consider common mistakes users might make when configuring their Meson build that could lead to problems in the CMake build. Incorrect compiler paths, mismatched architectures, and issues with custom toolchain files are good examples.
* **User Operation Trace:**  This requires understanding the broader context of how this code is used within the Frida build process. Starting with the `meson` command and following the execution flow into the CMake subproject is essential.

**6. Refinement and Examples:**

Finally, I would refine the explanations and ensure that the examples are clear, concise, and relevant. The goal is to make the technical details understandable to someone with a reasonable understanding of build systems and software development.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the code directly interacts with the kernel. **Correction:** The code *configures* the build process for targets that might run on specific kernels (like Android), but it doesn't directly make system calls or load kernel modules.
* **Initial thought:** Focus only on the `generate()` method. **Correction:**  All the methods work together to create the final toolchain file, so a holistic view is necessary.
* **Initial thought:**  Assume the user perfectly understands CMake and Meson. **Correction:**  Explain concepts like toolchain files and cross-compilation briefly to make the explanation accessible to a broader audience.

By following this structured approach, systematically analyzing the code, and connecting it to the specific prompts, I can generate a comprehensive and accurate explanation of the `toolchain.py` file.
这是一个名为 `toolchain.py` 的 Python 源代码文件，位于 Frida 动态插桩工具的构建系统相关目录中。它的主要功能是为使用 Meson 构建系统来构建基于 CMake 的子项目或依赖项时，生成 CMake 工具链文件。

以下是该文件的详细功能列表和相关说明：

**主要功能：生成 CMake 工具链文件**

* **目的:**  当 Meson 构建系统需要构建一个依赖于 CMake 的项目时，CMake 需要知道目标平台的编译器、链接器和其他构建工具的位置和配置。`toolchain.py` 的核心作用就是根据 Meson 的配置信息，生成一个 CMake 可以理解的工具链文件 (`CMakeMesonToolchainFile.cmake`)。
* **工作流程:**
    1. **初始化 (`__init__`)**: 接收 Meson 提供的构建环境信息，包括目标机器架构、编译器配置、构建目录等。
    2. **收集配置信息**: 从 Meson 的环境中获取编译器信息、系统名称、处理器架构等。
    3. **生成工具链文件 (`generate`)**:  根据收集到的信息，生成 CMake 工具链文件的内容。这包括：
        * 设置编译器路径 (例如 CMAKE_C_COMPILER, CMAKE_CXX_COMPILER)。
        * 设置目标系统信息 (例如 CMAKE_SYSTEM_NAME, CMAKE_SYSTEM_PROCESSOR)。
        * 设置其他必要的 CMake 变量 (例如 CMAKE_SYSROOT, CMAKE_SIZEOF_VOID_P)。
        * 包含用户自定义的 CMake 工具链文件 (如果指定)。
    4. **生成 CMake 缓存文件片段 (`generate_cache`)**:  在某些情况下（跳过编译器测试时），生成 CMake 缓存文件的部分内容，用于预设一些变量。
    5. **写入文件 (`write`)**: 将生成的工具链文件和缓存文件片段写入到构建目录中。
    6. **提供 CMake 参数 (`get_cmake_args`)**:  生成传递给 CMake 的命令行参数，指定使用的工具链文件。

**与逆向方法的关系及举例说明：**

* **目标架构指定:**  通过设置 `CMAKE_SYSTEM_NAME` 和 `CMAKE_SYSTEM_PROCESSOR`，工具链文件会告诉 CMake 编译的目标架构（例如 Android ARM64）。这对于逆向工程师来说非常重要，因为他们需要了解目标二进制文件的架构，才能使用相应的工具进行分析和调试。
    * **举例:** 如果 Frida 需要在 Android ARM64 设备上运行，Meson 会配置目标机器为 `android` 和 `aarch64`。`toolchain.py` 会生成包含 `set(CMAKE_SYSTEM_NAME Android)` 和 `set(CMAKE_SYSTEM_PROCESSOR aarch64)` 的工具链文件。CMake 使用这些信息来配置编译器以生成 ARM64 代码。逆向工程师在分析 Frida 在 Android 上的组件时，就需要知道这是 ARM64 的二进制文件。
* **编译器路径:** 工具链文件会指定使用的编译器路径。逆向工程师可能需要了解编译器的版本和特性，以便更好地理解代码的编译方式和可能的漏洞。
    * **举例:** 工具链文件可能包含 `set(CMAKE_C_COMPILER /path/to/arm64-linux-android-clang)`。逆向工程师通过这个路径可以知道 Frida 使用的是 Clang 编译器，并且是针对 Android ARM64 平台的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **目标操作系统 (`CMAKE_SYSTEM_NAME`)**:  代码中维护了一个从 Meson 系统名称到 CMake 系统名称的映射 (`SYSTEM_MAP`)，例如 'android' 映射到 'Android'，'linux' 映射到 'Linux'。这反映了对不同操作系统的底层知识，因为不同的操作系统有不同的系统调用接口、库和二进制格式。
    * **举例:** 当 Meson 配置目标为 Android 时，`CMAKE_SYSTEM_NAME` 会被设置为 'Android'。CMake 会根据这个信息来选择合适的平台相关的配置和库。这对于 Frida 来说至关重要，因为它需要在 Android 系统上进行进程注入、内存操作等底层操作。
* **目标处理器架构 (`CMAKE_SYSTEM_PROCESSOR`)**:  代码会设置 `CMAKE_SYSTEM_PROCESSOR` 来指定目标处理器的架构，例如 'aarch64' (ARM64)。这直接关系到生成的二进制文件的指令集和ABI（应用程序二进制接口）。
    * **举例:** 在构建 Frida 的 Android 版本时，如果目标设备是 ARM64，`CMAKE_SYSTEM_PROCESSOR` 将被设置为 'aarch64'。这意味着生成的 Frida 组件（例如 frida-server）将包含 ARM64 指令，只能在支持 ARM64 指令集的设备上运行。
* **`CMAKE_SIZEOF_VOID_P`**:  代码根据目标机器是 64 位还是 32 位来设置 `CMAKE_SIZEOF_VOID_P`。这影响指针的大小，是二进制底层编程的关键概念。
    * **举例:**  如果目标是 64 位 Android，`CMAKE_SIZEOF_VOID_P` 将被设置为 '8'。这意味着指针占用 8 个字节。这对于理解内存布局、函数调用约定等底层细节至关重要。
* **`CMAKE_SYSROOT`**:  代码允许设置 `CMAKE_SYSROOT`，这指定了交叉编译时使用的目标系统的根目录。这对于访问目标系统的头文件和库非常重要。
    * **举例:** 在为 Android 构建 Frida 时，可能需要设置 `CMAKE_SYSROOT` 指向 Android SDK 中的 sysroot 目录，以便 CMake 能够找到 Android 系统的头文件和库。这与 Android 框架的知识相关。
* **编译器可执行文件路径**: 代码会设置 `CMAKE_<LANG>_COMPILER` 变量，指向 C 和 C++ 编译器。对于 Android 来说，这通常是 Android NDK 提供的交叉编译器。
    * **举例:** `set(CMAKE_C_COMPILER /opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang)`。这表明 Frida 的 Android 组件是由 Android NDK 提供的 Clang 编译器编译的。

**逻辑推理、假设输入与输出：**

假设 Meson 配置了以下信息：

* `env.machines[for_machine].system = 'android'`
* `env.machines[for_machine].cpu_family = 'aarch64'`
* `env.machines[for_machine].is_64_bit = True`
* `env.properties[for_machine].cmake_defaults = True` (使用默认值)
* `env.coredata.compilers[for_machine] = {'c': <Compiler object for arm64-linux-android-clang>, 'cpp': <Compiler object for arm64-linux-android-clang++>}`

**假设输入:** 上述 Meson 配置信息。

**输出 (`generate()` 方法的输出片段):**

```cmake
######################################
###  AUTOMATICALLY GENERATED FILE  ###
######################################

# This file was generated from the configuration in the
# relevant meson machine file. See the meson documentation
# https://mesonbuild.com/Machine-files.html for more information

if(DEFINED MESON_PRELOAD_FILE)
    include("${MESON_PRELOAD_FILE}")
endif()

# Variables from meson
set(CMAKE_SYSTEM_NAME "Android")
set(CMAKE_SYSTEM_PROCESSOR "aarch64")
set(CMAKE_SIZEOF_VOID_P "8")
set(CMAKE_C_COMPILER "/path/to/arm64-linux-android-clang")
set(CMAKE_CXX_COMPILER "/path/to/arm64-linux-android-clang++")

```

**涉及用户或者编程常见的使用错误及举例说明：**

* **错误的编译器路径:** 用户可能在 Meson 的配置中指定了错误的编译器路径，导致 `toolchain.py` 生成的 CMake 工具链文件指向不存在的编译器。
    * **举例:** 用户在 `meson_options.txt` 或命令行中设置了错误的 C 编译器路径：`c_args = ['/usr/bin/gcc']` (但实际上目标平台需要交叉编译器)。这会导致 CMake 构建失败，因为找不到指定的编译器。
* **目标架构不匹配:** 用户可能在 Meson 中指定了与实际目标设备架构不匹配的架构。
    * **举例:** 用户尝试在 x86_64 的机器上构建 Android ARM 版本的 Frida，但没有正确配置 Meson 的目标机器信息。这会导致生成的工具链文件中的 `CMAKE_SYSTEM_PROCESSOR` 设置错误，CMake 将尝试使用本地的 x86_64 编译器进行编译，导致错误。
* **缺少必要的依赖:** 如果用户没有安装目标平台所需的交叉编译工具链 (例如 Android NDK)，即使 Meson 配置正确，`toolchain.py` 也只能生成指向本地编译器的工具链文件（如果本地有 GCC/Clang）。这会导致构建出的二进制文件无法在目标平台上运行。
* **自定义工具链文件错误:** 如果用户指定了自定义的 CMake 工具链文件，但该文件存在语法错误或配置不当，可能会导致 CMake 构建失败。
    * **举例:** 用户通过 `cmake_toolchain_file` 选项指定了一个自定义的工具链文件，但该文件中 `set(CMAKE_SYSTEM_NAME)` 的值与 Meson 的配置不一致，可能会导致冲突。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户配置 Meson 构建:** 用户执行 `meson setup builddir` 命令，Meson 会读取 `meson.build` 和 `meson_options.txt` 等配置文件，确定构建目标、编译器选项等。
2. **Meson 处理 CMake 子项目/依赖:**  `meson.build` 文件中可能包含了 `cmake` 项目的声明 (例如 `declare_dependency('my_cmake_project')`)。当 Meson 处理到这些 CMake 项目时，需要为其生成构建配置。
3. **调用 CMake 集成模块:** Meson 内部会调用相关的 CMake 集成模块来处理 CMake 项目。
4. **创建 `CMakeToolchain` 实例:** 在 CMake 集成模块中，会创建 `toolchain.py` 中定义的 `CMakeToolchain` 类的实例，并将当前 Meson 的构建环境信息传递给它。
5. **`CMakeToolchain` 生成工具链文件:**  `CMakeToolchain` 实例的 `write()` 方法被调用，根据 Meson 的配置生成 `CMakeMesonToolchainFile.cmake` 文件。
6. **CMake 使用工具链文件:** 当 Meson 随后调用 CMake 来构建子项目时，会将生成的工具链文件路径作为 `-DCMAKE_TOOLCHAIN_FILE` 参数传递给 CMake。CMake 会读取这个文件，根据其中的配置来选择编译器和构建工具。

**调试线索:**

* **查看生成的工具链文件:**  如果 CMake 构建出现问题，可以首先检查生成的 `CMakeMesonToolchainFile.cmake` 文件内容，查看编译器路径、目标架构等设置是否正确。
* **检查 Meson 的配置:**  确认 Meson 的配置文件 (例如 `meson_options.txt`) 中关于编译器、目标架构等选项的设置是否符合预期。
* **查看 Meson 的输出:**  Meson 在配置和构建过程中会输出一些信息，可以从中找到关于 CMake 集成和工具链生成的线索。
* **使用 Meson 的调试功能:** Meson 提供了一些调试功能，例如可以查看内部变量的值，有助于理解 Meson 是如何配置 CMake 工具链的。

总而言之，`frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/toolchain.py` 文件在 Frida 的构建过程中扮演着关键角色，它负责将 Meson 的高级构建配置转换为 CMake 可以理解的工具链文件，从而确保基于 CMake 的子项目能够正确地构建针对目标平台的二进制文件。理解这个文件的功能有助于理解 Frida 的构建流程，并在遇到与 CMake 构建相关的问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/toolchain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

from pathlib import Path
from .traceparser import CMakeTraceParser
from ..envconfig import CMakeSkipCompilerTest
from .common import language_map, cmake_get_generator_args
from .. import mlog

import shutil
import typing as T
from enum import Enum
from textwrap import dedent

if T.TYPE_CHECKING:
    from .executor import CMakeExecutor
    from ..environment import Environment
    from ..compilers import Compiler
    from ..mesonlib import MachineChoice

class CMakeExecScope(Enum):
    SUBPROJECT = 'subproject'
    DEPENDENCY = 'dependency'

class CMakeToolchain:
    def __init__(self, cmakebin: 'CMakeExecutor', env: 'Environment', for_machine: MachineChoice, exec_scope: CMakeExecScope, build_dir: Path, preload_file: T.Optional[Path] = None) -> None:
        self.env = env
        self.cmakebin = cmakebin
        self.for_machine = for_machine
        self.exec_scope = exec_scope
        self.preload_file = preload_file
        self.build_dir = build_dir
        self.build_dir = self.build_dir.resolve()
        self.toolchain_file = build_dir / 'CMakeMesonToolchainFile.cmake'
        self.cmcache_file = build_dir / 'CMakeCache.txt'
        self.minfo = self.env.machines[self.for_machine]
        self.properties = self.env.properties[self.for_machine]
        self.compilers = self.env.coredata.compilers[self.for_machine]
        self.cmakevars = self.env.cmakevars[self.for_machine]
        self.cmakestate = self.env.coredata.cmake_cache[self.for_machine]

        self.variables = self.get_defaults()
        self.variables.update(self.cmakevars.get_variables())

        # Determine whether CMake the compiler test should be skipped
        skip_status = self.properties.get_cmake_skip_compiler_test()
        self.skip_check = skip_status == CMakeSkipCompilerTest.ALWAYS
        if skip_status == CMakeSkipCompilerTest.DEP_ONLY and self.exec_scope == CMakeExecScope.DEPENDENCY:
            self.skip_check = True
        if not self.properties.get_cmake_defaults():
            self.skip_check = False

        assert self.toolchain_file.is_absolute()

    def write(self) -> Path:
        if not self.toolchain_file.parent.exists():
            self.toolchain_file.parent.mkdir(parents=True)
        self.toolchain_file.write_text(self.generate(), encoding='utf-8')
        self.cmcache_file.write_text(self.generate_cache(), encoding='utf-8')
        mlog.cmd_ci_include(self.toolchain_file.as_posix())
        return self.toolchain_file

    def get_cmake_args(self) -> T.List[str]:
        args = ['-DCMAKE_TOOLCHAIN_FILE=' + self.toolchain_file.as_posix()]
        if self.preload_file is not None:
            args += ['-DMESON_PRELOAD_FILE=' + self.preload_file.as_posix()]
        return args

    @staticmethod
    def _print_vars(vars: T.Dict[str, T.List[str]]) -> str:
        res = ''
        for key, value in vars.items():
            res += 'set(' + key
            for i in value:
                res += f' "{i}"'
            res += ')\n'
        return res

    def generate(self) -> str:
        res = dedent('''\
            ######################################
            ###  AUTOMATICALLY GENERATED FILE  ###
            ######################################

            # This file was generated from the configuration in the
            # relevant meson machine file. See the meson documentation
            # https://mesonbuild.com/Machine-files.html for more information

            if(DEFINED MESON_PRELOAD_FILE)
                include("${MESON_PRELOAD_FILE}")
            endif()

        ''')

        # Escape all \ in the values
        for key, value in self.variables.items():
            self.variables[key] = [x.replace('\\', '/') for x in value]

        # Set compiler
        if self.skip_check:
            self.update_cmake_compiler_state()
            res += '# CMake compiler state variables\n'
            for lang, vars in self.cmakestate:
                res += f'# -- Variables for language {lang}\n'
                res += self._print_vars(vars)
                res += '\n'
            res += '\n'

        # Set variables from the current machine config
        res += '# Variables from meson\n'
        res += self._print_vars(self.variables)
        res += '\n'

        # Add the user provided toolchain file
        user_file = self.properties.get_cmake_toolchain_file()
        if user_file is not None:
            res += dedent('''
                # Load the CMake toolchain file specified by the user
                include("{}")

            '''.format(user_file.as_posix()))

        return res

    def generate_cache(self) -> str:
        if not self.skip_check:
            return ''

        res = ''
        for name, v in self.cmakestate.cmake_cache.items():
            res += f'{name}:{v.type}={";".join(v.value)}\n'
        return res

    def get_defaults(self) -> T.Dict[str, T.List[str]]:
        defaults: T.Dict[str, T.List[str]] = {}

        # Do nothing if the user does not want automatic defaults
        if not self.properties.get_cmake_defaults():
            return defaults

        # Best effort to map the meson system name to CMAKE_SYSTEM_NAME, which
        # is not trivial since CMake lacks a list of all supported
        # CMAKE_SYSTEM_NAME values.
        SYSTEM_MAP: T.Dict[str, str] = {
            'android': 'Android',
            'linux': 'Linux',
            'windows': 'Windows',
            'freebsd': 'FreeBSD',
            'darwin': 'Darwin',
        }

        # Only set these in a cross build. Otherwise CMake will trip up in native
        # builds and thing they are cross (which causes TRY_RUN() to break)
        if self.env.is_cross_build(when_building_for=self.for_machine):
            defaults['CMAKE_SYSTEM_NAME'] = [SYSTEM_MAP.get(self.minfo.system, self.minfo.system)]
            defaults['CMAKE_SYSTEM_PROCESSOR'] = [self.minfo.cpu_family]

        defaults['CMAKE_SIZEOF_VOID_P'] = ['8' if self.minfo.is_64_bit else '4']

        sys_root = self.properties.get_sys_root()
        if sys_root:
            defaults['CMAKE_SYSROOT'] = [sys_root]

        def make_abs(exe: str) -> str:
            if Path(exe).is_absolute():
                return exe

            p = shutil.which(exe)
            if p is None:
                return exe
            return p

        # Set the compiler variables
        for lang, comp_obj in self.compilers.items():
            prefix = 'CMAKE_{}_'.format(language_map.get(lang, lang.upper()))

            exe_list = comp_obj.get_exelist()
            if not exe_list:
                continue

            if len(exe_list) >= 2 and not self.is_cmdline_option(comp_obj, exe_list[1]):
                defaults[prefix + 'COMPILER_LAUNCHER'] = [make_abs(exe_list[0])]
                exe_list = exe_list[1:]

            exe_list[0] = make_abs(exe_list[0])
            defaults[prefix + 'COMPILER'] = exe_list
            if comp_obj.get_id() == 'clang-cl':
                defaults['CMAKE_LINKER'] = comp_obj.get_linker_exelist()

        return defaults

    @staticmethod
    def is_cmdline_option(compiler: 'Compiler', arg: str) -> bool:
        if compiler.get_argument_syntax() == 'msvc':
            return arg.startswith('/')
        else:
            return arg.startswith('-')

    def update_cmake_compiler_state(self) -> None:
        # Check if all variables are already cached
        if self.cmakestate.languages.issuperset(self.compilers.keys()):
            return

        # Generate the CMakeLists.txt
        mlog.debug('CMake Toolchain: Calling CMake once to generate the compiler state')
        languages = list(self.compilers.keys())
        lang_ids = [language_map.get(x, x.upper()) for x in languages]
        cmake_content = dedent(f'''
            cmake_minimum_required(VERSION 3.7)
            project(CompInfo {' '.join(lang_ids)})
        ''')

        build_dir = Path(self.env.scratch_dir) / '__CMake_compiler_info__'
        build_dir.mkdir(parents=True, exist_ok=True)
        cmake_file = build_dir / 'CMakeLists.txt'
        cmake_file.write_text(cmake_content, encoding='utf-8')

        # Generate the temporary toolchain file
        temp_toolchain_file = build_dir / 'CMakeMesonTempToolchainFile.cmake'
        temp_toolchain_file.write_text(CMakeToolchain._print_vars(self.variables), encoding='utf-8')

        # Configure
        trace = CMakeTraceParser(self.cmakebin.version(), build_dir, self.env)
        self.cmakebin.set_exec_mode(print_cmout=False, always_capture_stderr=trace.requires_stderr())
        cmake_args = []
        cmake_args += trace.trace_args()
        cmake_args += cmake_get_generator_args(self.env)
        cmake_args += [f'-DCMAKE_TOOLCHAIN_FILE={temp_toolchain_file.as_posix()}', '.']
        rc, _, raw_trace = self.cmakebin.call(cmake_args, build_dir=build_dir, disable_cache=True)

        if rc != 0:
            mlog.warning('CMake Toolchain: Failed to determine CMake compilers state')
            return

        # Parse output
        trace.parse(raw_trace)
        self.cmakestate.cmake_cache = {**trace.cache}

        vars_by_file = {k.name: v for (k, v) in trace.vars_by_file.items()}

        for lang in languages:
            lang_cmake = language_map.get(lang, lang.upper())
            file_name = f'CMake{lang_cmake}Compiler.cmake'
            vars = vars_by_file.setdefault(file_name, {})
            vars[f'CMAKE_{lang_cmake}_COMPILER_FORCED'] = ['1']
            self.cmakestate.update(lang, vars)
```