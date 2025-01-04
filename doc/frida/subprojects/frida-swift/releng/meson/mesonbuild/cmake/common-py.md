Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `common.py` file within the context of Frida, a dynamic instrumentation tool. The request asks for a breakdown of its features, its relationship to reverse engineering, its interaction with low-level systems, any logical inferences, common user errors, and how a user might reach this code.

**2. Initial Scan and High-Level Overview:**

The first step is to quickly scan the code to identify key structures and patterns. I notice:

* **Imports:** `mesonlib`, `pathlib`, `typing`. This immediately suggests an interaction with the Meson build system and file system operations. The `typing` module indicates the use of type hints for better code clarity and static analysis.
* **Dictionaries:** `language_map`, `backend_generator_map`. These look like mappings used for configuration or translation between different systems (programming languages and build system backends).
* **Lists:** `blacklist_cmake_defs`. This strongly hints at a filtering or restriction mechanism, likely related to CMake definitions.
* **Functions:** Several functions like `cmake_is_debug`, `cmake_get_generator_args`, `cmake_defines_to_args`, `check_cmake_args`. The prefix "cmake_" suggests an interaction with CMake.
* **Classes:** `CMakeException`, `CMakeBuildFile`, `CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`, `SingleTargetOptions`, `TargetOptions`. The naming convention clearly points to representing CMake project structures and build configurations.

From this initial scan, the core purpose seems to be processing and managing information related to CMake projects within the Meson build environment.

**3. Deep Dive into Key Sections:**

Now, let's examine each section more closely:

* **Mappings:** The `language_map` and `backend_generator_map` are straightforward. They translate Meson's internal representations to CMake's.
* **Blacklist:**  The `blacklist_cmake_defs` is critical. It indicates that certain CMake definitions are intentionally ignored by this code, likely due to conflicts or incompatibility with Meson's approach to cross-compilation.
* **`cmake_is_debug`:** This function determines if the build is a debug build by checking Meson's build options, particularly `b_vscrt` (Visual Studio C Runtime) and `debug`.
* **Exceptions:** `CMakeException` is a custom exception class for handling CMake-related errors.
* **`CMakeBuildFile`:** This simple class represents a CMake build file.
* **Flag Handling (`_flags_to_list`):** This function parses a raw string of command-line flags into a list, handling quoting and escaping. This is a common task when dealing with build systems.
* **Argument Generation (`cmake_get_generator_args`, `cmake_defines_to_args`):** These functions convert Meson's internal representation of build settings (like the backend and defined variables) into command-line arguments suitable for CMake. The `cmake_defines_to_args` function also applies the blacklist.
* **Argument Checking (`check_cmake_args`):**  This function reinforces the blacklist by warning users if they try to set forbidden CMake definitions directly.
* **CMake Structure Classes (`CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`):** These classes represent the hierarchical structure of a CMake project as extracted from CMake's output (likely a JSON or similar format). They store information about include paths, source files, compiler flags, linker settings, and targets. The `log()` methods suggest a debugging or informational purpose.
* **Options Management (`SingleTargetOptions`, `TargetOptions`):** These classes provide a way to manage and override build options (compiler flags, linker flags, install status) at both a global and per-target level. This allows for fine-grained control over the build process.

**4. Connecting to Reverse Engineering and Low-Level Details:**

Now, let's link the code's functionality to reverse engineering and low-level aspects:

* **Dynamic Instrumentation (Frida):** The code belongs to Frida, a dynamic instrumentation tool. This means its ultimate goal is to modify the behavior of running programs. CMake is used to build Frida itself and potentially libraries that Frida injects.
* **Binary/Native Code:** CMake builds native code. The compiler and linker flags managed by this code directly influence the generated binary.
* **Operating Systems (Linux, Android):**  Frida works across multiple platforms, including Linux and Android. The build system needs to handle platform-specific compiler/linker settings and libraries. The `cmake_is_debug` function and the handling of Visual Studio CRT options suggest cross-platform considerations.
* **Kernel and Framework Knowledge:**  While this specific code doesn't directly interact with the kernel, the build process it manages produces the Frida agent, which *does* interact with the kernel to perform instrumentation. Understanding how libraries are linked and how code is compiled is crucial for ensuring Frida can function correctly.

**5. Logical Inferences and Examples:**

Consider the `cmake_defines_to_args` function. The logic is: iterate through definitions, check against the blacklist, format the definition into a CMake command-line argument.

* **Hypothetical Input:** `raw = [{'MY_FLAG': True, 'ANOTHER_FLAG': 'value', 'CMAKE_TOOLCHAIN_FILE': '/path/to/toolchain'}]`
* **Output:** `['-DMY_FLAG=ON', '-DANOTHER_FLAG=value']`  (The `CMAKE_TOOLCHAIN_FILE` is skipped due to the blacklist.)

**6. User Errors:**

The `check_cmake_args` function explicitly warns about setting blacklisted CMake definitions. This is a common user error when trying to adapt existing CMake build configurations to Meson.

* **Example:** A user might try to pass `-DCMAKE_TOOLCHAIN_FILE=/some/path` directly to Meson, expecting it to be passed through to CMake. This code prevents that and provides a warning.

**7. User Journey and Debugging:**

How does a user end up "here"?

1. **User wants to build Frida:** They clone the Frida repository.
2. **Frida uses Meson:** The build process is managed by Meson.
3. **Frida has subprojects (like `frida-swift`):** This subproject might use CMake for part of its build.
4. **Meson interacts with CMake:** When building the `frida-swift` subproject, Meson needs to configure and invoke CMake.
5. **`common.py` comes into play:** This file provides utility functions for interacting with CMake, such as generating command-line arguments, parsing CMake output, and managing build options.
6. **Debugging Scenario:**  If the build fails or behaves unexpectedly, a developer might need to examine the generated CMake arguments or the parsed CMake project structure. They might look at the logging done by the `log()` methods in the CMake structure classes.

**8. Iteration and Refinement:**

As I go through this process, I might revisit earlier assumptions or interpretations. For example, initially, I might not have fully grasped the purpose of the `TargetOptions` class. Upon closer inspection, it becomes clear that it's for managing build options at different scopes.

By following these steps, I can systematically analyze the code and address all the requirements of the prompt, providing a comprehensive understanding of the `common.py` file.
好的，我们来详细分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/common.py` 这个文件。

**文件功能概述**

这个 Python 文件是 Frida 项目中，用于与 CMake 构建系统集成的工具模块。它的主要功能是：

1. **定义语言和构建后端映射:**  维护了编程语言名称（如 'c', 'cpp', 'swift'）到 CMake 识别的名称（如 'C', 'CXX', 'Swift'）的映射，以及 Meson 支持的构建后端（如 'ninja', 'xcode'）到 CMake 生成器名称的映射。
2. **管理 CMake 定义黑名单:**  定义了一个黑名单 `blacklist_cmake_defs`，列出了不希望通过 Meson 传递给 CMake 的特定定义。这通常是因为这些定义与 Meson 的内部工作方式冲突，或者 Meson 有自己的处理方式。
3. **判断是否为 Debug 构建:**  提供了一个函数 `cmake_is_debug`，用于判断当前的 Meson 构建配置是否为 Debug 模式。它会检查 Meson 的 `buildtype` 和 `b_vscrt` (Visual Studio C Runtime) 选项。
4. **定义 CMake 相关的异常:**  定义了一个自定义异常类 `CMakeException`，用于处理与 CMake 集成相关的错误。
5. **表示 CMake 构建文件:**  定义了一个类 `CMakeBuildFile`，用于表示 CMake 构建文件的相关信息，如文件路径、是否是 CMake 文件以及是否是临时文件。
6. **处理命令行参数:**  提供函数 `_flags_to_list` 将原始的命令行字符串转换为字符串列表，处理转义和引号。
7. **生成 CMake 生成器参数:**  提供函数 `cmake_get_generator_args`，根据 Meson 的后端选项生成传递给 CMake 的生成器参数（例如 `-G Ninja`）。
8. **转换 Meson 定义为 CMake 参数:**  提供函数 `cmake_defines_to_args`，将 Meson 的定义（字典列表）转换为 CMake 的命令行参数（例如 `-DMyVar=Value`）。此函数会检查黑名单。
9. **检查 CMake 参数:**  提供函数 `check_cmake_args`，用于检查用户提供的 CMake 参数是否包含黑名单中的定义，并发出警告。
10. **表示 CMake 的结构:**  定义了多个类 (`CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`)，用于解析和表示 CMake 生成的构建信息（通常是 JSON 格式），包括头文件路径、源文件分组、目标文件信息、项目信息和配置信息。
11. **管理目标构建选项:** 定义了 `SingleTargetOptions` 和 `TargetOptions` 类，用于管理针对特定目标或全局的编译选项、链接选项和安装设置。

**与逆向方法的关系及举例说明**

这个文件本身不是直接进行逆向操作的工具，但它是 Frida 工具链的一部分，而 Frida 是一个强大的动态 instrumentation 框架，广泛用于逆向工程。

* **构建 Frida 组件:** 该文件参与构建 Frida 的一些组件，特别是那些可能依赖 CMake 构建的子项目 (例如 `frida-swift`)。逆向工程师可能需要重新编译 Frida 或其组件，以包含自定义的 instrumentation 代码或调试符号。
* **理解目标程序的构建过程:**  逆向工程师有时需要了解目标程序的构建方式，以便更好地进行分析和 hook。这个文件可以帮助理解 Frida 如何与使用 CMake 的项目进行交互，以及如何传递编译和链接选项。
* **修改编译选项以利于逆向:**  逆向工程师可能需要修改编译选项来添加调试符号、禁用优化或添加特定的宏定义，以便更容易地进行动态分析。`TargetOptions` 类提供的功能可以用于在 Frida 的构建过程中修改这些选项。

**举例说明:**

假设逆向工程师想要为使用 Swift 编写的 Android 应用编写 Frida 脚本。`frida-swift` 子项目负责处理 Swift 相关的 instrumentation。为了调试 `frida-swift` 本身，或者为了让它在特定的 Android 环境下工作，逆向工程师可能需要：

1. **修改 CMake 定义:** 通过 Meson 的配置选项，间接地影响传递给 CMake 的定义，例如指定特定的 SDK 路径。
2. **添加编译选项:**  使用 `TargetOptions` 类为 `frida-swift` 目标添加 `-g` 编译选项以包含调试符号。这可以通过修改 Frida 的构建脚本或配置文件来实现，最终会调用到这个 `common.py` 文件中的相关逻辑。
3. **查看 CMake 生成的构建信息:**  通过 Frida 的调试输出来查看 `CMakeProject` 等类解析出的 CMake 构建信息，了解 `frida-swift` 的依赖和编译方式。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

这个文件本身处理的是构建过程，但其产物以及它所支持的 Frida 工具，都与二进制底层、Linux 和 Android 有着密切关系。

* **二进制底层:** CMake 构建过程最终生成的是二进制文件（例如共享库 `.so` 文件）。这个文件涉及到编译、链接等底层操作，需要了解目标平台的 ABI (Application Binary Interface)。
* **Linux:** Frida 在 Linux 平台上有广泛的应用。这个文件中的一些逻辑，例如处理共享库的链接、编译选项等，都与 Linux 平台的特性相关。例如，链接器标志 (`linkFlags`) 可能包含 `-Wl,-rpath` 这样的 Linux 特有的选项。
* **Android 内核及框架:**  Frida 广泛用于 Android 逆向。`frida-swift` 子项目需要能够与 Android 的 Dalvik/ART 虚拟机以及底层的 Native 代码进行交互。CMake 的配置需要考虑 Android NDK 的使用，以及针对不同 Android 架构（如 ARM, ARM64）的编译设置。
* **共享库加载:**  `linkLibraries` 字段会列出链接时需要的共享库，这涉及到操作系统如何加载和解析共享库的知识。

**举例说明:**

1. **`language_map` 中的 'swift' -> 'Swift':**  这体现了对 Swift 语言及其在底层编译过程中的表示的理解。
2. **`backend_generator_map` 中的 'ninja':** Ninja 是一个快速的小型构建系统，常用于 Linux 和 Android 开发，因为它能更好地利用多核处理器。
3. **`blacklist_cmake_defs` 中的 `CMAKE_TOOLCHAIN_FILE`:**  `CMAKE_TOOLCHAIN_FILE` 用于指定交叉编译的工具链。Meson 通常有自己的方式来处理交叉编译，所以它会阻止用户直接通过 CMake 设置工具链文件，以避免冲突。这体现了对交叉编译和构建系统之间协作的理解。
4. **`CMakeTarget` 中的 `artifacts` 和 `linkLibraries`:**  这些字段涉及到最终生成的二进制文件（例如 `.so` 文件）以及它所依赖的其他共享库，这直接关联到操作系统如何加载和执行程序。

**逻辑推理及假设输入与输出**

在 `cmake_defines_to_args` 函数中存在逻辑推理：

* **假设输入:** `raw = [{'MY_FLAG': True, 'ANOTHER_FLAG': 'value', 'CMAKE_TOOLCHAIN_FILE': '/path/to/toolchain'}]`
* **逻辑:** 遍历 `raw` 中的每个字典项，如果键不在 `blacklist_cmake_defs` 中，则根据值的类型将其转换为 CMake 的 `-D` 参数。
* **输出:** `['-DMY_FLAG=ON', '-DANOTHER_FLAG=value']`

**涉及用户或编程常见的使用错误及举例说明**

1. **尝试设置黑名单中的 CMake 定义:** 用户可能会尝试通过 Meson 的 `cmake_args` 选项设置 `CMAKE_TOOLCHAIN_FILE`，例如：`meson setup build -Dcmake_args="-DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk/toolchain.cmake"`。`check_cmake_args` 函数会捕获这种情况并发出警告，提示用户应该使用 Meson 提供的交叉编译机制。

   **错误信息:**
   ```
   WARNING: Setting -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk/toolchain.cmake is not supported. See the meson docs for cross compilation support:
     - URL: https://mesonbuild.com/CMake-module.html#cross-compilation
     --> Ignoring this option
   ```

2. **为 CMake 定义传递不支持的数据类型:**  `cmake_defines_to_args` 函数会检查定义的值类型。如果用户尝试传递一个列表或字典作为 CMake 定义的值，会抛出异常。

   **假设用户尝试:** `meson setup build -Dmy_list='["a", "b"]'`
   这最终会导致 `cmake_defines_to_args` 接收到 `{'my_list': ['a', 'b']}`。

   **预期异常:** `MesonException: Type "list" of "my_list" is not supported as for a CMake define value`

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户尝试构建 Frida 或其子项目:** 用户首先会执行 `git clone` 克隆 Frida 的仓库，然后进入 Frida 的根目录。
2. **执行 Meson 配置:** 用户会执行 `meson setup build` 命令来配置构建环境。
3. **Meson 处理 `meson.build` 文件:** Meson 会解析项目根目录下的 `meson.build` 文件，该文件描述了项目的构建规则。
4. **遇到需要构建 CMake 子项目的情况:** 如果 `meson.build` 文件中包含了对使用 CMake 的子项目的构建指令（例如 `frida-swift`），Meson 会调用相应的逻辑来处理 CMake 项目。
5. **Meson 调用 CMake 集成模块:**  Meson 的 CMake 集成模块会被激活，这个模块负责生成 CMakeLists.txt 文件（如果需要）、调用 CMake 并解析 CMake 的输出。
6. **`common.py` 中的函数被调用:** 在这个过程中，`common.py` 文件中的函数会被调用：
   * `cmake_is_debug` 可能用于确定构建类型。
   * `cmake_get_generator_args` 用于生成 CMake 的生成器参数。
   * `cmake_defines_to_args` 用于将 Meson 的选项转换为 CMake 的定义。
   * `check_cmake_args` 用于检查用户提供的 CMake 参数。
   * 当 CMake 执行完成后，其生成的构建信息（例如 targets.json 文件）会被解析，并使用 `CMakeProject`、`CMakeTarget` 等类来表示。
7. **调试线索:** 如果构建过程中出现与 CMake 相关的错误，或者需要理解 Frida 如何与 CMake 项目交互，开发者可能会查看这个 `common.py` 文件中的代码，了解 Meson 如何处理 CMake 的配置和参数传递。例如，如果传递给 CMake 的参数不正确，开发者可能会查看 `cmake_defines_to_args` 和 `check_cmake_args` 函数的逻辑。如果解析 CMake 输出时出现问题，可能会查看 `CMakeProject` 等类的定义和解析过程。

总而言之，`frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/common.py` 文件是 Frida 构建系统中关键的一部分，它负责处理与 CMake 构建系统的集成，确保 Frida 能够构建包含 CMake 子模块的项目。理解这个文件有助于理解 Frida 的构建过程，并在遇到与 CMake 相关的问题时提供调试线索。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

from __future__ import annotations

from ..mesonlib import MesonException, OptionKey
from .. import mlog
from pathlib import Path
import typing as T

if T.TYPE_CHECKING:
    from ..environment import Environment
    from ..interpreterbase import TYPE_var

language_map = {
    'c': 'C',
    'cpp': 'CXX',
    'cuda': 'CUDA',
    'objc': 'OBJC',
    'objcpp': 'OBJCXX',
    'cs': 'CSharp',
    'java': 'Java',
    'fortran': 'Fortran',
    'swift': 'Swift',
}

backend_generator_map = {
    'ninja': 'Ninja',
    'xcode': 'Xcode',
    'vs2010': 'Visual Studio 10 2010',
    'vs2012': 'Visual Studio 11 2012',
    'vs2013': 'Visual Studio 12 2013',
    'vs2015': 'Visual Studio 14 2015',
    'vs2017': 'Visual Studio 15 2017',
    'vs2019': 'Visual Studio 16 2019',
    'vs2022': 'Visual Studio 17 2022',
}

blacklist_cmake_defs = [
    'CMAKE_TOOLCHAIN_FILE',
    'CMAKE_PROJECT_INCLUDE',
    'MESON_PRELOAD_FILE',
    'MESON_PS_CMAKE_CURRENT_BINARY_DIR',
    'MESON_PS_CMAKE_CURRENT_SOURCE_DIR',
    'MESON_PS_DELAYED_CALLS',
    'MESON_PS_LOADED',
    'MESON_FIND_ROOT_PATH',
    'MESON_CMAKE_SYSROOT',
    'MESON_PATHS_LIST',
    'MESON_CMAKE_ROOT',
]

def cmake_is_debug(env: 'Environment') -> bool:
    if OptionKey('b_vscrt') in env.coredata.options:
        is_debug = env.coredata.get_option(OptionKey('buildtype')) == 'debug'
        if env.coredata.options[OptionKey('b_vscrt')].value in {'mdd', 'mtd'}:
            is_debug = True
        return is_debug
    else:
        # Don't directly assign to is_debug to make mypy happy
        debug_opt = env.coredata.get_option(OptionKey('debug'))
        assert isinstance(debug_opt, bool)
        return debug_opt

class CMakeException(MesonException):
    pass

class CMakeBuildFile:
    def __init__(self, file: Path, is_cmake: bool, is_temp: bool) -> None:
        self.file = file
        self.is_cmake = is_cmake
        self.is_temp = is_temp

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.file}; cmake={self.is_cmake}; temp={self.is_temp}>'

def _flags_to_list(raw: str) -> T.List[str]:
    # Convert a raw commandline string into a list of strings
    res = []
    curr = ''
    escape = False
    in_string = False
    for i in raw:
        if escape:
            # If the current char is not a quote, the '\' is probably important
            if i not in ['"', "'"]:
                curr += '\\'
            curr += i
            escape = False
        elif i == '\\':
            escape = True
        elif i in {'"', "'"}:
            in_string = not in_string
        elif i in {' ', '\n'}:
            if in_string:
                curr += i
            else:
                res += [curr]
                curr = ''
        else:
            curr += i
    res += [curr]
    res = [r for r in res if len(r) > 0]
    return res

def cmake_get_generator_args(env: 'Environment') -> T.List[str]:
    backend_name = env.coredata.get_option(OptionKey('backend'))
    assert isinstance(backend_name, str)
    assert backend_name in backend_generator_map
    return ['-G', backend_generator_map[backend_name]]

def cmake_defines_to_args(raw: T.List[T.Dict[str, TYPE_var]], permissive: bool = False) -> T.List[str]:
    res: T.List[str] = []

    for i in raw:
        for key, val in i.items():
            if key in blacklist_cmake_defs:
                mlog.warning('Setting', mlog.bold(key), 'is not supported. See the meson docs for cross compilation support:')
                mlog.warning('  - URL: https://mesonbuild.com/CMake-module.html#cross-compilation')
                mlog.warning('  --> Ignoring this option')
                continue
            if isinstance(val, (str, int, float)):
                res += [f'-D{key}={val}']
            elif isinstance(val, bool):
                val_str = 'ON' if val else 'OFF'
                res += [f'-D{key}={val_str}']
            else:
                raise MesonException('Type "{}" of "{}" is not supported as for a CMake define value'.format(type(val).__name__, key))

    return res

# TODO: this function will become obsolete once the `cmake_args` kwarg is dropped
def check_cmake_args(args: T.List[str]) -> T.List[str]:
    res: T.List[str] = []
    dis = ['-D' + x for x in blacklist_cmake_defs]
    assert dis  # Ensure that dis is not empty.
    for i in args:
        if any(i.startswith(x) for x in dis):
            mlog.warning('Setting', mlog.bold(i), 'is not supported. See the meson docs for cross compilation support:')
            mlog.warning('  - URL: https://mesonbuild.com/CMake-module.html#cross-compilation')
            mlog.warning('  --> Ignoring this option')
            continue
        res += [i]
    return res

class CMakeInclude:
    def __init__(self, path: Path, isSystem: bool = False):
        self.path = path
        self.isSystem = isSystem

    def __repr__(self) -> str:
        return f'<CMakeInclude: {self.path} -- isSystem = {self.isSystem}>'

class CMakeFileGroup:
    def __init__(self, data: T.Dict[str, T.Any]) -> None:
        self.defines: str = data.get('defines', '')
        self.flags = _flags_to_list(data.get('compileFlags', ''))
        self.is_generated: bool = data.get('isGenerated', False)
        self.language: str = data.get('language', 'C')
        self.sources = [Path(x) for x in data.get('sources', [])]

        # Fix the include directories
        self.includes: T.List[CMakeInclude] = []
        for i in data.get('includePath', []):
            if isinstance(i, dict) and 'path' in i:
                isSystem = i.get('isSystem', False)
                assert isinstance(isSystem, bool)
                assert isinstance(i['path'], str)
                self.includes += [CMakeInclude(Path(i['path']), isSystem)]
            elif isinstance(i, str):
                self.includes += [CMakeInclude(Path(i))]

    def log(self) -> None:
        mlog.log('flags        =', mlog.bold(', '.join(self.flags)))
        mlog.log('defines      =', mlog.bold(', '.join(self.defines)))
        mlog.log('includes     =', mlog.bold(', '.join([str(x) for x in self.includes])))
        mlog.log('is_generated =', mlog.bold('true' if self.is_generated else 'false'))
        mlog.log('language     =', mlog.bold(self.language))
        mlog.log('sources:')
        for i in self.sources:
            with mlog.nested():
                mlog.log(i.as_posix())

class CMakeTarget:
    def __init__(self, data: T.Dict[str, T.Any]) -> None:
        self.artifacts = [Path(x) for x in data.get('artifacts', [])]
        self.src_dir = Path(data.get('sourceDirectory', ''))
        self.build_dir = Path(data.get('buildDirectory', ''))
        self.name: str = data.get('name', '')
        self.full_name: str = data.get('fullName', '')
        self.install: bool = data.get('hasInstallRule', False)
        self.install_paths = [Path(x) for x in set(data.get('installPaths', []))]
        self.link_lang: str = data.get('linkerLanguage', '')
        self.link_libraries = _flags_to_list(data.get('linkLibraries', ''))
        self.link_flags = _flags_to_list(data.get('linkFlags', ''))
        self.link_lang_flags = _flags_to_list(data.get('linkLanguageFlags', ''))
        # self.link_path = Path(data.get('linkPath', ''))
        self.type: str = data.get('type', 'EXECUTABLE')
        # self.is_generator_provided: bool = data.get('isGeneratorProvided', False)
        self.files: T.List[CMakeFileGroup] = []

        for i in data.get('fileGroups', []):
            self.files += [CMakeFileGroup(i)]

    def log(self) -> None:
        mlog.log('artifacts             =', mlog.bold(', '.join([x.as_posix() for x in self.artifacts])))
        mlog.log('src_dir               =', mlog.bold(self.src_dir.as_posix()))
        mlog.log('build_dir             =', mlog.bold(self.build_dir.as_posix()))
        mlog.log('name                  =', mlog.bold(self.name))
        mlog.log('full_name             =', mlog.bold(self.full_name))
        mlog.log('install               =', mlog.bold('true' if self.install else 'false'))
        mlog.log('install_paths         =', mlog.bold(', '.join([x.as_posix() for x in self.install_paths])))
        mlog.log('link_lang             =', mlog.bold(self.link_lang))
        mlog.log('link_libraries        =', mlog.bold(', '.join(self.link_libraries)))
        mlog.log('link_flags            =', mlog.bold(', '.join(self.link_flags)))
        mlog.log('link_lang_flags       =', mlog.bold(', '.join(self.link_lang_flags)))
        # mlog.log('link_path             =', mlog.bold(self.link_path))
        mlog.log('type                  =', mlog.bold(self.type))
        # mlog.log('is_generator_provided =', mlog.bold('true' if self.is_generator_provided else 'false'))
        for idx, i in enumerate(self.files):
            mlog.log(f'Files {idx}:')
            with mlog.nested():
                i.log()

class CMakeProject:
    def __init__(self, data: T.Dict[str, T.Any]) -> None:
        self.src_dir = Path(data.get('sourceDirectory', ''))
        self.build_dir = Path(data.get('buildDirectory', ''))
        self.name: str = data.get('name', '')
        self.targets: T.List[CMakeTarget] = []

        for i in data.get('targets', []):
            self.targets += [CMakeTarget(i)]

    def log(self) -> None:
        mlog.log('src_dir   =', mlog.bold(self.src_dir.as_posix()))
        mlog.log('build_dir =', mlog.bold(self.build_dir.as_posix()))
        mlog.log('name      =', mlog.bold(self.name))
        for idx, i in enumerate(self.targets):
            mlog.log(f'Target {idx}:')
            with mlog.nested():
                i.log()

class CMakeConfiguration:
    def __init__(self, data: T.Dict[str, T.Any]) -> None:
        self.name: str = data.get('name', '')
        self.projects: T.List[CMakeProject] = []
        for i in data.get('projects', []):
            self.projects += [CMakeProject(i)]

    def log(self) -> None:
        mlog.log('name =', mlog.bold(self.name))
        for idx, i in enumerate(self.projects):
            mlog.log(f'Project {idx}:')
            with mlog.nested():
                i.log()

class SingleTargetOptions:
    def __init__(self) -> None:
        self.opts: T.Dict[str, str] = {}
        self.lang_args: T.Dict[str, T.List[str]] = {}
        self.link_args: T.List[str] = []
        self.install = 'preserve'

    def set_opt(self, opt: str, val: str) -> None:
        self.opts[opt] = val

    def append_args(self, lang: str, args: T.List[str]) -> None:
        if lang not in self.lang_args:
            self.lang_args[lang] = []
        self.lang_args[lang] += args

    def append_link_args(self, args: T.List[str]) -> None:
        self.link_args += args

    def set_install(self, install: bool) -> None:
        self.install = 'true' if install else 'false'

    def get_override_options(self, initial: T.List[str]) -> T.List[str]:
        res: T.List[str] = []
        for i in initial:
            opt = i[:i.find('=')]
            if opt not in self.opts:
                res += [i]
        res += [f'{k}={v}' for k, v in self.opts.items()]
        return res

    def get_compile_args(self, lang: str, initial: T.List[str]) -> T.List[str]:
        if lang in self.lang_args:
            return initial + self.lang_args[lang]
        return initial

    def get_link_args(self, initial: T.List[str]) -> T.List[str]:
        return initial + self.link_args

    def get_install(self, initial: bool) -> bool:
        return {'preserve': initial, 'true': True, 'false': False}[self.install]

class TargetOptions:
    def __init__(self) -> None:
        self.global_options = SingleTargetOptions()
        self.target_options: T.Dict[str, SingleTargetOptions] = {}

    def __getitem__(self, tgt: str) -> SingleTargetOptions:
        if tgt not in self.target_options:
            self.target_options[tgt] = SingleTargetOptions()
        return self.target_options[tgt]

    def get_override_options(self, tgt: str, initial: T.List[str]) -> T.List[str]:
        initial = self.global_options.get_override_options(initial)
        if tgt in self.target_options:
            initial = self.target_options[tgt].get_override_options(initial)
        return initial

    def get_compile_args(self, tgt: str, lang: str, initial: T.List[str]) -> T.List[str]:
        initial = self.global_options.get_compile_args(lang, initial)
        if tgt in self.target_options:
            initial = self.target_options[tgt].get_compile_args(lang, initial)
        return initial

    def get_link_args(self, tgt: str, initial: T.List[str]) -> T.List[str]:
        initial = self.global_options.get_link_args(initial)
        if tgt in self.target_options:
            initial = self.target_options[tgt].get_link_args(initial)
        return initial

    def get_install(self, tgt: str, initial: bool) -> bool:
        initial = self.global_options.get_install(initial)
        if tgt in self.target_options:
            initial = self.target_options[tgt].get_install(initial)
        return initial

"""

```