Response:
My thinking process to analyze the Python code and answer the prompt goes through these stages:

1. **Understand the Goal:** The primary goal is to understand the functionality of the `common.py` file within the Frida project, particularly its relation to reverse engineering, low-level details, and potential user errors. The prompt also asks for examples and debugging context.

2. **High-Level Overview (Skimming):** I'll quickly read through the code, paying attention to class names, function names, and imported modules. This gives me a general idea of the file's purpose. I see terms like `CMake`, `Environment`, `Target`, `Project`, `Options`, and the file path mentions `frida-clr` and `meson`. This suggests interaction with the CMake build system, likely related to building Frida's .NET/CLR components.

3. **Identify Key Data Structures and Classes:**  I focus on the defined classes:
    * `CMakeException`: A custom exception.
    * `CMakeBuildFile`: Represents a CMake build file.
    * `CMakeInclude`: Represents an include directory for CMake.
    * `CMakeFileGroup`: Groups source files with associated compiler flags and defines.
    * `CMakeTarget`: Represents a build target (executable, library).
    * `CMakeProject`: Represents a CMake project.
    * `CMakeConfiguration`:  Represents a CMake build configuration.
    * `SingleTargetOptions`, `TargetOptions`: Structures for managing build options.

4. **Analyze Key Functions:** I examine the purpose of the functions:
    * `cmake_is_debug()`: Determines if the build is a debug build.
    * `_flags_to_list()`: Parses a command-line string of flags into a list.
    * `cmake_get_generator_args()`:  Gets CMake generator arguments based on the build system backend (Ninja, Xcode, Visual Studio).
    * `cmake_defines_to_args()`: Converts CMake definitions (key-value pairs) into command-line arguments. Crucially, it has a blacklist of unsupported definitions.
    * `check_cmake_args()`: Checks for blacklisted arguments in a list of CMake arguments.
    * The `log()` methods within the CMake classes:  Used for debugging output.
    * The methods in `SingleTargetOptions` and `TargetOptions`:  For managing and overriding build options.

5. **Connect to Reverse Engineering (Instruction 2):** I consider how this code relates to reverse engineering. Frida is a dynamic instrumentation tool. Building Frida, especially components that interact with the CLR, is a prerequisite for using it to reverse engineer .NET applications. The code helps configure and build these components. The ability to customize build options (through `TargetOptions`) could be useful for building specific debugging or instrumentation configurations.

6. **Identify Low-Level/Kernel/Framework Aspects (Instruction 3):** I look for indicators of interaction with the operating system or lower levels:
    * **Build System Integration (CMake):** CMake itself deals with generating platform-specific build files, inherently interacting with the OS.
    * **Compiler Flags and Defines:**  The code manipulates compiler flags (`-D`, `-I`, etc.) which directly affect how the compiler builds the binary. These flags can be crucial for targeting specific architectures or enabling/disabling features.
    * **Linker Flags and Libraries:**  The code handles linker flags and libraries, which are essential for creating executables and libraries that can run on the target platform.
    * **Blacklisted CMake Definitions:** The blacklist (`blacklist_cmake_defs`) includes definitions like `CMAKE_TOOLCHAIN_FILE` and `MESON_CMAKE_SYSROOT`, which are vital for cross-compilation. Cross-compilation is frequently used when targeting embedded systems like Android.
    * **Language Support:** The `language_map` indicates support for languages like C, C++, C#, and Java, all of which have different levels of interaction with the underlying OS.

7. **Logical Inference and Assumptions (Instruction 4):** I think about the inputs and outputs of functions, making reasonable assumptions:
    * `cmake_is_debug()`:  Input is the `Environment` object. Output is a boolean indicating debug mode. Assumption: The `Environment` object correctly reflects the user's build settings.
    * `_flags_to_list()`: Input is a string of flags. Output is a list of individual flags. Assumption: Flags are separated by spaces, and quotes are handled correctly.
    * `cmake_defines_to_args()`: Input is a list of dictionaries representing CMake definitions. Output is a list of `-D` arguments. Assumption: The dictionary values are of supported types.

8. **User Errors (Instruction 5):** I consider common mistakes users might make:
    * **Using Blacklisted CMake Definitions:** The code explicitly warns against this. Users might try to set these definitions directly, thinking they have control over cross-compilation settings.
    * **Incorrectly Formatted Flag Strings:**  The `_flags_to_list()` function attempts to parse flag strings, and incorrect quoting or spacing could lead to errors.
    * **Providing Unsupported Data Types for CMake Defines:** The `cmake_defines_to_args()` function checks for supported types. Users might try to pass complex objects, causing an exception.

9. **User Steps to Reach the Code (Instruction 6):** I reconstruct how a user's actions could lead to this code being executed:
    * A user wants to build Frida, specifically the .NET/CLR bridge (`frida-clr`).
    * They use the Meson build system.
    * Meson needs to configure the build for CMake-based subprojects.
    * The `common.py` file contains utility functions used during this CMake configuration phase within the Meson build process.
    * The user might be setting build options through Meson's command-line arguments (e.g., setting debug mode, specifying a backend, providing CMake definitions).
    * Meson will then call functions in `common.py` to translate these options into CMake-compatible arguments.

10. **Structure and Refine the Answer:** I organize my findings based on the prompt's questions, providing clear explanations and examples. I use the identified keywords and concepts from the code to illustrate my points. I make sure to explicitly address each part of the prompt.

This step-by-step approach allows me to systematically analyze the code, understand its purpose within the larger Frida project, and relate it to the specific areas mentioned in the prompt. It also helps me generate concrete examples and scenarios.
好的，我们来详细分析一下 `frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/common.py` 这个文件。

**文件功能概述**

这个 Python 文件是 Frida 项目中用于处理 CMake 子项目构建配置的工具模块。它的主要功能是：

1. **定义了与 CMake 相关的常量和映射:**
   - `language_map`:  将 Meson 使用的语言名称映射到 CMake 使用的语言名称（例如，'c' 映射到 'C'）。
   - `backend_generator_map`: 将 Meson 的构建后端（如 'ninja', 'xcode'）映射到相应的 CMake 生成器名称。
   - `blacklist_cmake_defs`:  列出了不应直接传递给 CMake 的 CMake 定义，通常与 Meson 的交叉编译处理有关。

2. **提供了获取和转换 CMake 参数的函数:**
   - `cmake_is_debug(env)`:  根据 Meson 的构建配置判断是否是 Debug 构建。
   - `cmake_get_generator_args(env)`:  根据 Meson 的后端配置生成 CMake 的 `-G` 参数。
   - `cmake_defines_to_args(raw, permissive=False)`: 将 Python 字典形式的 CMake 定义转换为 CMake 命令行参数（`-Dkey=value`）。它会检查黑名单中的定义。
   - `check_cmake_args(args)`: 检查给定的 CMake 参数列表中是否包含黑名单中的定义。
   - `_flags_to_list(raw)`:  将原始的命令行字符串形式的编译或链接标志解析为 Python 列表。

3. **定义了用于表示 CMake 项目结构的数据类:**
   - `CMakeException`:  自定义的 CMake 异常类。
   - `CMakeBuildFile`:  表示 CMake 构建生成的文件。
   - `CMakeInclude`:  表示 CMake 的包含目录。
   - `CMakeFileGroup`:  表示一组具有相同编译选项的源文件。
   - `CMakeTarget`:  表示一个 CMake 构建目标（例如，可执行文件或库）。
   - `CMakeProject`:  表示一个 CMake 项目。
   - `CMakeConfiguration`: 表示一个 CMake 构建配置。

4. **提供了用于管理目标构建选项的类:**
   - `SingleTargetOptions`:  用于存储单个目标的特定选项（例如，特定的编译参数、链接参数、是否安装）。
   - `TargetOptions`:  用于管理全局和特定目标的构建选项。

**与逆向方法的关系及举例说明**

Frida 本身就是一个动态插桩工具，广泛用于逆向工程。这个 `common.py` 文件虽然不是直接进行插桩的代码，但它参与了 Frida 中基于 CMake 的子项目（`frida-clr`，即 Frida 的 .NET/CLR 支持）的构建过程。构建过程是逆向工程的基础，因为你需要能够编译和运行目标代码才能进行分析和修改。

**举例说明:**

* **定制构建:** 逆向工程师可能需要以特定的配置构建 `frida-clr`，例如启用特定的调试符号，或者禁用某些优化以方便调试。`TargetOptions` 类允许在构建过程中覆盖默认的编译和链接选项。逆向工程师可以通过 Meson 的配置系统，间接地影响到这里定义的选项，从而实现定制构建。

* **理解构建过程:**  理解 `common.py` 中定义的数据结构（如 `CMakeTarget`, `CMakeFileGroup`）可以帮助逆向工程师了解 `frida-clr` 的模块组成、依赖关系以及编译方式。这对于分析 Frida 如何与 .NET CLR 运行时交互非常有帮助。

* **分析构建错误:** 如果在构建 `frida-clr` 时出现错误，了解这个文件中处理 CMake 参数的逻辑可以帮助逆向工程师分析错误原因。例如，如果某个特定的 CMake 定义与 Meson 的配置冲突，`blacklist_cmake_defs` 和相关的警告信息可以提供线索。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

虽然这个文件本身是高级的 Python 代码，但它处理的构建配置直接影响到最终生成的二进制文件的特性以及在不同平台上的运行方式。

**举例说明:**

* **编译器标志 (Compiler Flags):** `CMakeFileGroup` 类中存储了编译标志 (`flags`)。这些标志会直接传递给底层的 C++ 编译器（例如 GCC, Clang, MSVC）。不同的编译器标志会影响代码的优化程度、生成的指令集、调试信息的包含与否等，这些都是二进制底层的关键属性。例如，`-m32` 或 `-m64` 标志会影响生成 32 位还是 64 位的二进制代码。

* **链接器标志 (Linker Flags):** `CMakeTarget` 类中存储了链接器标志 (`link_flags`) 和链接库 (`link_libraries`)。链接器负责将编译后的目标文件组合成最终的可执行文件或库。链接器标志会影响内存布局、依赖库的查找路径等。例如，在 Android 上，链接器可能需要指定特定的系统库路径。

* **交叉编译 (Cross-compilation):** `blacklist_cmake_defs` 中包含 `CMAKE_TOOLCHAIN_FILE` 和 `MESON_CMAKE_SYSROOT` 等定义。这些是进行交叉编译的关键配置，即在一个平台上构建在另一个平台上运行的代码。Frida 需要支持多种平台（包括 Linux 和 Android），因此理解如何配置交叉编译环境非常重要。

* **目标平台 (Target Platform):**  `backend_generator_map` 映射了不同的构建后端。例如，当目标平台是 Android 时，可能需要使用特定的 CMake 工具链和生成器。

* **动态链接库 (Shared Libraries):** Frida 作为一个动态插桩工具，自身也可能以动态链接库的形式存在。`CMakeTarget` 的 `type` 属性可以区分构建的是可执行文件还是库。链接过程会决定 Frida 的哪些符号是导出的，以及它如何与其他库进行交互。

**逻辑推理、假设输入与输出**

让我们以 `cmake_defines_to_args` 函数为例进行逻辑推理：

**假设输入:**

```python
raw = [
    {"ENABLE_FEATURE_A": True},
    {"LIBRARY_PATH": "/opt/mylibs"},
    {"VERSION": "1.2.3"},
    {"DISABLE_FEATURE_B": False},
    {"UNSUPPORTED_DEFINE": [1, 2, 3]}  # 假设不支持列表类型的定义
]
env_options = {'backend': 'ninja'} # 假设 Meson 配置的后端是 Ninja
```

**执行 `cmake_defines_to_args(raw)` 后的输出:**

```python
['-DENABLE_FEATURE_A=ON', '-DLIBRARY_PATH=/opt/mylibs', '-DVERSION=1.2.3', '-DDISABLE_FEATURE_B=OFF']
```

**推理过程:**

1. 函数遍历 `raw` 列表中的每个字典。
2. 对于每个键值对，它检查键是否在 `blacklist_cmake_defs` 中。假设上面的例子中没有黑名单中的键。
3. 它检查值的类型：
   - 如果是 `bool`，则转换为 "ON" 或 "OFF"。
   - 如果是 `str`, `int`, 或 `float`，则直接使用其字符串表示。
   - 如果是其他类型（例如列表 `[1, 2, 3]`），则会抛出 `MesonException` (代码中有类型检查 `isinstance(val, (str, int, float, bool))`，不满足条件会抛出异常)。
4. 它将合法的键值对转换为 `-Dkey=value` 形式的字符串。
5. 最终返回所有转换后的字符串列表。

**涉及用户或编程常见的使用错误及举例说明**

* **使用黑名单中的 CMake 定义:** 用户可能尝试通过 Meson 的配置系统直接设置 `CMAKE_TOOLCHAIN_FILE` 等被 `blacklist_cmake_defs` 列出的定义。`cmake_defines_to_args` 或 `check_cmake_args` 函数会发出警告，提示用户不要这样做，并建议查阅 Meson 的文档以了解正确的交叉编译方式。

   **用户操作:** 在 Meson 的 `meson_options.txt` 文件中或通过命令行选项设置了 `-Dcmake_toolchain_file=/path/to/toolchain.cmake`。

   **结果:**  构建过程中会显示类似以下的警告：
   ```
   WARNING: Setting CMAKE_TOOLCHAIN_FILE is not supported. See the meson docs for cross compilation support:
   WARNING:   - URL: https://mesonbuild.com/CMake-module.html#cross-compilation
   WARNING:   --> Ignoring this option
   ```

* **传递不支持类型的 CMake 定义值:** 用户可能尝试将列表、字典等复杂数据类型作为 CMake 定义的值传递。

   **用户操作:**  在 Meson 的配置中设置了类似 `my_config = {'option1': 'value', 'option2': [1, 2]}`，并尝试将其作为 CMake 定义传递。

   **结果:** `cmake_defines_to_args` 函数会抛出 `MesonException`，指出不支持的类型。

* **错误格式的编译/链接标志字符串:** 用户可能手动设置编译或链接标志，但字符串格式不正确，导致 `_flags_to_list` 解析出错。

   **用户操作:**  尝试通过某种方式设置编译标志，例如 `"-I/path with space" -DMY_DEFINE`，其中路径包含空格但没有正确引用。

   **结果:**  虽然 `_flags_to_list` 会尽力解析，但在某些复杂情况下可能会得到不期望的结果，导致构建错误或运行时问题。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户想要构建 Frida 的 .NET/CLR 支持 (`frida-clr`) 并遇到了问题。以下是可能的操作步骤，最终导致需要查看 `common.py` 文件：

1. **配置构建环境:** 用户安装了 Frida 的构建依赖，包括 Meson 和 Ninja (或其他构建后端)。

2. **配置 Frida 源码:** 用户下载了 Frida 的源代码，并进入了 Frida 的根目录。

3. **配置构建选项:** 用户可能通过以下方式配置构建选项：
   - **编辑 `meson_options.txt`:** 修改 Meson 的选项配置文件。
   - **使用 `meson setup` 命令的选项:** 例如，`meson setup build --backend=ninja -Doption=value`。这些选项可能包括影响 CMake 子项目的配置。

4. **执行构建命令:** 用户运行 `meson compile -C build` 或 `ninja -C build` 来开始构建过程。

5. **构建系统处理 CMake 子项目:** 当 Meson 处理到 `frida-clr` 子项目时，它会使用 CMake 进行构建。Meson 会调用 `frida/subprojects/frida-clr/meson.build` 中定义的逻辑。

6. **`common.py` 的作用:** 在处理 CMake 子项目时，Meson 会使用 `common.py` 中的函数来：
   - 获取 CMake 生成器参数 (`cmake_get_generator_args`)。
   - 将 Meson 的构建选项转换为 CMake 的定义 (`cmake_defines_to_args`)。
   - 检查用户提供的 CMake 参数 (`check_cmake_args`)。

7. **遇到构建错误:**  如果用户配置了不兼容的选项，或者 CMake 子项目的构建脚本存在问题，构建过程可能会失败。

8. **调试过程:** 为了理解构建失败的原因，用户可能会：
   - **查看构建日志:**  构建日志中可能会包含 `common.py` 发出的警告信息，例如关于黑名单定义的警告。
   - **查看 Meson 的源码:**  为了理解 Meson 如何处理 CMake 子项目，用户可能会查看 `frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/common.py` 这个文件，了解它如何转换和传递 CMake 参数。
   - **使用调试工具:**  如果熟悉 Python 调试，用户甚至可以设置断点来跟踪 `common.py` 中函数的执行过程，查看具体的参数传递和逻辑。

总而言之，`common.py` 是 Frida 构建系统中处理 CMake 子项目配置的关键模块。理解它的功能有助于理解 Frida 的构建过程，排查构建错误，以及进行定制化构建以满足逆向工程的需求。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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