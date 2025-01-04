Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its function, relate it to reverse engineering, identify low-level details, spot logical inferences, highlight potential user errors, and trace the user journey to this code.

**1. Initial Skim and Purpose Identification:**

The first step is a quick read-through to get a general sense of what the code does. Keywords like "cmake," "meson," "build," "target," "flags," "defines," and "options" stand out. The file path `frida/subprojects/frida-core/releng/meson/mesonbuild/cmake/common.py` is a huge clue. It suggests this code helps bridge the gap between the Meson build system and CMake projects within the Frida project. Specifically, it seems to handle information extraction and manipulation related to CMake projects for use by Meson.

**2. Function-by-Function Analysis:**

Next, a more detailed examination of each function and class is necessary:

*   **`language_map` and `backend_generator_map`:** These are simple mappings. Recognize them as configuration data for translating between Meson's and CMake's terminology.
*   **`blacklist_cmake_defs`:**  This immediately signals a filtering or security mechanism. The comments about cross-compilation hints at potential conflicts or complexities when Meson tries to directly pass these definitions to CMake.
*   **`cmake_is_debug`:**  This is crucial for build processes. It determines if a debug build should be performed, considering both the general `debug` option and the Visual Studio CRT library setting. This is relevant to reverse engineering because debug builds often contain more information (symbols, less optimization) useful for analysis.
*   **`CMakeException`:** A standard custom exception for this module.
*   **`CMakeBuildFile`:**  A simple data structure to represent a CMake build file, whether it's a regular or temporary file.
*   **`_flags_to_list`:**  This is a utility function to parse command-line style flags. Pay attention to the handling of quotes and escape characters – common pitfalls in command-line parsing.
*   **`cmake_get_generator_args`:**  Translates Meson's backend choice to CMake's generator argument. Important for how CMake generates its build files.
*   **`cmake_defines_to_args`:**  Converts Python dictionaries of definitions into CMake command-line arguments. The blacklist is checked here. The handling of different value types (string, int, bool) is important.
*   **`check_cmake_args`:**  Another filtering function for command-line arguments, specifically checking the blacklist. This and `cmake_defines_to_args` have overlapping concerns, suggesting a possible refactoring opportunity.
*   **`CMakeInclude`:** Represents an include directory with a flag for whether it's a system include.
*   **`CMakeFileGroup`:**  Groups source files and associated compilation settings (flags, defines, includes, language). This is a core concept in build systems.
*   **`CMakeTarget`:** Represents a build target (executable, library) with its artifacts, source directories, build directories, linking information, and file groups. This is a central entity in any build system.
*   **`CMakeProject`:**  A collection of CMake targets.
*   **`CMakeConfiguration`:**  A top-level structure holding CMake projects.
*   **`SingleTargetOptions` and `TargetOptions`:** These classes handle overriding or customizing build options for individual targets or globally. This allows fine-grained control over the build process.

**3. Connecting to Reverse Engineering:**

During the function analysis, consider how each part relates to reverse engineering. For instance:

*   Debug builds (`cmake_is_debug`) are crucial for easier reverse engineering.
*   Understanding build flags and defines (`CMakeFileGroup`, `cmake_defines_to_args`) helps in understanding how the target was compiled and potential security mitigations.
*   Knowing the linked libraries (`CMakeTarget`) is essential for identifying dependencies and potential attack surfaces.
*   The generated artifacts (`CMakeTarget`) are the targets of reverse engineering efforts.

**4. Identifying Low-Level Details:**

Look for code that interacts with the operating system or compiler:

*   File paths (`pathlib.Path`) indicate interaction with the file system.
*   Compilation flags and linker flags directly influence the compiler and linker behavior.
*   The concept of include paths is fundamental to compilation.

**5. Spotting Logical Inferences:**

Identify any conditional logic or transformations:

*   The `cmake_is_debug` function makes a decision based on multiple options.
*   The argument parsing in `_flags_to_list` and `cmake_defines_to_args` involves logical checks.
*   The `TargetOptions` classes manage option overrides based on target names.

**6. Thinking about User Errors:**

Consider how a user might misuse the functionality or encounter errors:

*   Providing incorrect paths.
*   Using unsupported CMake definitions (the blacklist).
*   Having issues with the command-line flag parsing (especially with quotes and escapes).
*   Misconfiguring build options.

**7. Tracing the User Journey:**

Imagine the steps a developer takes to reach this code:

1. They are working on the Frida project.
2. They are dealing with a component that uses CMake as its build system.
3. Meson is the overall build system for Frida.
4. Meson needs to interact with the CMake project.
5. Meson uses this `common.py` module to parse and understand the CMake project's structure and settings.

This involves the user running Meson commands to configure and build Frida, and Meson internally invoking this code to process the CMake parts.

**8. Structuring the Output:**

Finally, organize the findings into the requested categories:

*   **Functionality:** Provide a high-level overview and then detail the purpose of each class and function.
*   **Relationship to Reverse Engineering:**  Connect specific code elements to reverse engineering concepts.
*   **Binary/Kernel/Framework Knowledge:** Highlight interactions with the underlying system and build process.
*   **Logical Inference:** Explain the reasoning within the code with examples.
*   **User Errors:** Provide concrete examples of common mistakes.
*   **User Journey:** Describe the steps leading to the execution of this code.

By following this systematic approach, you can thoroughly analyze the provided Python code and extract the relevant information requested in the prompt.
这是一个名为 `common.py` 的 Python 源代码文件，它位于 Frida 项目的 `frida-core` 子项目的构建系统目录中。该文件似乎是为了帮助 Meson 构建系统处理和理解 CMake 项目的结构和配置信息。

以下是该文件的功能列表，以及它与逆向方法、二进制底层、Linux/Android 内核及框架知识的关联，逻辑推理，用户错误，以及用户操作如何到达这里的调试线索：

**功能列表:**

1. **语言映射 (`language_map`)**: 定义了 CMake 中使用的语言名称（例如 "C", "CXX"）与 Meson 中使用的语言名称的映射。
2. **后端生成器映射 (`backend_generator_map`)**:  定义了 Meson 构建后端（如 Ninja, Xcode）与 CMake 生成器名称的映射。这允许 Meson 在使用 CMake 构建子项目时，指定合适的 CMake 生成器。
3. **CMake 定义黑名单 (`blacklist_cmake_defs`)**:  维护一个 CMake 定义的黑名单。这些定义通常由 Meson 管理或控制，不应直接由 CMake 项目设置。这有助于避免构建系统之间的冲突。
4. **判断是否为调试构建 (`cmake_is_debug`)**:  根据 Meson 的构建选项判断当前是否为调试构建。它会考虑 `buildtype` 和 `b_vscrt` (Visual Studio C/C++ 运行时库) 等选项。
5. **自定义 CMake 异常 (`CMakeException`)**:  定义了一个继承自 `MesonException` 的自定义异常类，用于表示与 CMake 相关的错误。
6. **表示 CMake 构建文件 (`CMakeBuildFile`)**:  定义了一个类来表示一个 CMake 构建文件，包含文件路径、是否为 CMake 文件以及是否为临时文件等信息。
7. **将原始标志字符串转换为列表 (`_flags_to_list`)**:  一个实用函数，用于将包含空格分隔的命令行标志的字符串转换为字符串列表，并处理转义字符和引号。
8. **获取 CMake 生成器参数 (`cmake_get_generator_args`)**:  根据 Meson 的后端选项，返回相应的 CMake 生成器参数（例如 `'-G', 'Ninja'`）。
9. **将 CMake 定义转换为命令行参数 (`cmake_defines_to_args`)**:  将 Python 字典格式的 CMake 定义转换为 CMake 命令行参数，例如 `['-DMyKey=MyValue']`。它还会检查黑名单中的定义。
10. **检查 CMake 参数 (`check_cmake_args`)**:  检查给定的 CMake 参数列表，并警告并忽略黑名单中的定义。
11. **表示 CMake 包含目录 (`CMakeInclude`)**:  定义一个类来表示 CMake 的包含目录，包括路径和是否为系统包含目录。
12. **表示 CMake 文件组 (`CMakeFileGroup`)**:  定义一个类来表示 CMake 中的文件组，包含编译定义、编译标志、是否为生成文件、编程语言以及源文件和包含目录列表。
13. **记录 CMake 文件组信息 (`CMakeFileGroup.log`)**:  一个用于记录 `CMakeFileGroup` 详细信息的函数，方便调试。
14. **表示 CMake 目标 (`CMakeTarget`)**:  定义一个类来表示 CMake 构建目标（例如，可执行文件或库），包含构建产物、源目录、构建目录、名称、安装信息、链接库、链接标志、链接器语言以及包含的文件组。
15. **记录 CMake 目标信息 (`CMakeTarget.log`)**:  一个用于记录 `CMakeTarget` 详细信息的函数。
16. **表示 CMake 项目 (`CMakeProject`)**:  定义一个类来表示 CMake 项目，包含源目录、构建目录、项目名称和包含的目标列表。
17. **记录 CMake 项目信息 (`CMakeProject.log`)**:  一个用于记录 `CMakeProject` 详细信息的函数。
18. **表示 CMake 配置 (`CMakeConfiguration`)**:  定义一个类来表示 CMake 构建配置，包含配置名称和包含的项目列表。
19. **记录 CMake 配置信息 (`CMakeConfiguration.log`)**:  一个用于记录 `CMakeConfiguration` 详细信息的函数。
20. **单个目标的选项 (`SingleTargetOptions`)**:  定义一个类来存储单个 CMake 目标的选项，例如编译定义、编译参数、链接参数和安装选项。
21. **设置/追加单个目标选项的方法 (`set_opt`, `append_args`, `append_link_args`, `set_install`)**:  提供修改 `SingleTargetOptions` 对象的方法。
22. **获取覆盖选项 (`get_override_options`)**:  获取需要覆盖的选项列表。
23. **获取编译参数 (`get_compile_args`)**:  获取特定语言的编译参数。
24. **获取链接参数 (`get_link_args`)**:  获取链接参数。
25. **获取安装选项 (`get_install`)**:  获取安装选项。
26. **目标选项 (`TargetOptions`)**:  定义一个类来管理全局和特定目标的构建选项。
27. **获取特定目标的选项 (`__getitem__`)**:  允许通过目标名称访问特定目标的选项。
28. **获取特定目标的覆盖选项、编译参数、链接参数和安装选项 (`get_override_options`, `get_compile_args`, `get_link_args`, `get_install`)**:  提供访问特定目标或全局选项的方法。

**与逆向方法的关系及举例说明:**

*   **理解构建过程**:  逆向工程的一个重要方面是理解目标软件是如何构建的。这个文件揭示了 Frida 项目中如何使用 Meson 来集成和处理 CMake 构建的子项目。通过分析这个文件，逆向工程师可以了解 Frida 的哪些部分是使用 CMake 构建的，以及构建过程中可能使用的编译和链接选项。例如，`CMakeFileGroup` 类中的 `flags` 和 `defines` 字段可以告诉逆向工程师在编译特定源文件时使用了哪些编译标志和宏定义。这对于理解代码的行为和潜在的安全漏洞至关重要。
*   **查找编译标志和宏定义**:  逆向工程师可以利用这些信息来重现构建环境，或者在静态分析或动态调试时考虑这些标志和定义的影响。例如，如果某个目标使用了 `-DDEBUG` 编译标志，逆向工程师可以推断该目标可能包含额外的调试信息或不同的执行路径。
*   **识别链接库**:  `CMakeTarget` 类中的 `link_libraries` 字段列出了目标链接的库。逆向工程师可以根据这些信息来识别目标依赖的外部库，并进一步分析这些库的功能和潜在漏洞。
*   **分析安装路径**: `CMakeTarget` 类中的 `install_paths` 可以帮助逆向工程师了解构建产物最终安装到系统上的哪些位置，这对于理解软件的部署结构很有用。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明:**

*   **编译和链接标志 (`CMakeFileGroup.flags`, `CMakeTarget.link_flags`)**: 这些标志直接传递给编译器和链接器，影响最终生成的二进制文件的结构和行为。例如，`-fPIC` 标志用于生成位置无关代码，这对于共享库是必需的。在 Android 上，理解这些标志对于分析 Native 代码的执行和内存布局至关重要。
*   **链接库 (`CMakeTarget.link_libraries`)**:  这些库通常是编译好的二进制文件 (`.so` 在 Linux/Android 上)，包含了可执行代码和数据。理解链接过程以及不同类型的库（静态库、共享库）对于逆向分析至关重要。例如，Frida 可能会链接到 glibc 等系统库，或者自己的一些内部库。
*   **包含目录 (`CMakeFileGroup.includes`)**:  指定了编译器搜索头文件的路径。了解这些路径有助于理解代码的依赖关系和使用的系统或第三方 API。在 Android 开发中，可能会涉及到 Android NDK 提供的头文件。
*   **目标类型 (`CMakeTarget.type`)**:  区分了可执行文件 (`EXECUTABLE`) 和库 (`SHARED_LIBRARY`, `STATIC_LIBRARY`) 等不同类型的构建产物。这直接关系到二进制文件的格式和加载方式。
*   **系统包含目录 (`CMakeInclude.isSystem`)**:  区分了用户提供的包含目录和系统默认的包含目录，这有助于理解代码使用了哪些系统级别的 API。

**逻辑推理及假设输入与输出:**

*   **`cmake_is_debug(env)`**:
    *   **假设输入**: `env.coredata.options` 中 `buildtype` 为 `'debug'`， `b_vscrt` 不存在。
    *   **输出**: `True`
    *   **假设输入**: `env.coredata.options` 中 `buildtype` 为 `'release'`， `b_vscrt` 的值为 `'mdd'`。
    *   **输出**: `True` (因为 `b_vscrt` 设置为调试运行时)
    *   **假设输入**: `env.coredata.options` 中 `buildtype` 为 `'release'`， `b_vscrt` 不存在， `debug` 选项为 `False`。
    *   **输出**: `False`

*   **`cmake_defines_to_args(raw)`**:
    *   **假设输入**: `raw = [{'MY_DEFINE': 'value'}, {'ANOTHER_DEFINE': 123}, {'BOOL_DEFINE': True}]`
    *   **输出**: `['-DMY_DEFINE=value', '-DANOTHER_DEFINE=123', '-DBOOL_DEFINE=ON']`
    *   **假设输入**: `raw = [{'CMAKE_TOOLCHAIN_FILE': '/path/to/toolchain'}]` (黑名单中的定义)
    *   **输出**: `[]` (同时会发出警告信息)

*   **`_flags_to_list(raw)`**:
    *   **假设输入**: `raw = "-Wall -O2 \"-DDEFINE_WITH_SPACE=value with space\" 'another flag'"`
    *   **输出**: `['-Wall', '-O2', '-DDEFINE_WITH_SPACE=value with space', 'another flag']`

**涉及用户或者编程常见的使用错误及举例说明:**

*   **在 CMake 定义中使用不支持的类型**: `cmake_defines_to_args` 函数会检查值的类型。如果用户尝试使用不支持的类型（例如列表或字典）作为 CMake 定义的值，则会抛出 `MesonException`。
    *   **错误示例**:  在 Meson 的配置中，尝试传递 `cmake_defines: {'MY_LIST': [1, 2, 3]}`。
*   **尝试设置黑名单中的 CMake 定义**:  如果用户尝试通过 Meson 的 `cmake_options` 或其他方式设置 `blacklist_cmake_defs` 中列出的 CMake 定义，构建系统会发出警告并忽略这些设置。这可能会导致用户期望的配置没有生效。
    *   **错误示例**:  在 Meson 的配置中设置 `cmake_options: ['-DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain']`。
*   **命令行标志解析错误**:  在 `_flags_to_list` 函数中，如果用户提供的原始标志字符串中的引号或转义字符使用不当，可能会导致标志被错误地解析。
    *   **错误示例**:  一个本意是 `-DNAME="value"` 的标志，如果写成 `-DNAME=\"value` 可能会被错误解析。
*   **假设 CMake 项目的结构**:  该代码假设 Meson 可以通过 CMake 的某种机制（例如 `cmake` 命令的输出或生成的文件）来获取项目的结构信息。如果 CMake 项目的结构不符合预期，或者 Meson 解析信息的方式有误，可能会导致解析错误或构建失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida 或其包含 CMake 子模块的部分**: 用户通常会执行类似 `meson setup build` 和 `meson compile -C build` 这样的命令来配置和构建 Frida 项目。
2. **Meson 处理构建配置**: 当 Meson 遇到需要构建的 CMake 子项目时，它会解析 `meson.build` 文件中与该子项目相关的指令。
3. **调用 CMake 构建系统**: Meson 会调用 CMake 来配置和生成该子项目的构建文件。
4. **Meson 解析 CMake 信息**:  为了更好地集成 CMake 子项目，Meson 需要了解 CMake 项目的结构、目标、编译选项等信息。`common.py` 中的代码很可能在这一步被使用。Meson 可能会执行 CMake 命令来获取 JSON 格式的构建信息，然后使用 `CMakeConfiguration`、`CMakeProject`、`CMakeTarget` 等类来解析这些信息。
5. **处理构建选项和定义**:  用户可能在 Meson 的配置中指定了需要传递给 CMake 项目的选项和定义。`cmake_defines_to_args` 和 `check_cmake_args` 等函数会被用来处理这些选项，并确保它们符合 Meson 的要求。
6. **生成最终的构建命令**: Meson 最终会根据解析到的 CMake 信息和用户提供的选项，生成用于编译和链接 CMake 子项目的命令。

**调试线索**:

*   如果在构建过程中出现与 CMake 相关的错误，可以检查 Meson 的构建日志，查看是否输出了与 `common.py` 中警告信息相关的日志，例如关于黑名单 CMake 定义的警告。
*   可以使用 Meson 提供的调试工具或环境变量来查看 Meson 在处理 CMake 子项目时的详细操作，例如传递给 CMake 的参数。
*   如果怀疑是由于 Meson 解析 CMake 信息有误导致的问题，可以尝试手动运行 CMake 命令来生成构建信息，并将结果与 Meson 的行为进行对比。
*   检查 `meson.build` 文件中与 CMake 子项目相关的配置，确保配置正确，并且没有尝试设置黑名单中的 CMake 定义。

总而言之，`common.py` 文件是 Frida 项目中 Meson 构建系统与 CMake 构建系统之间的一个重要桥梁，它负责解析、转换和管理 CMake 项目的元数据和构建选项，以便 Meson 能够有效地构建包含 CMake 子模块的 Frida 项目。理解这个文件的功能对于理解 Frida 的构建过程和排查相关的构建问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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