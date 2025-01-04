Response:
The user wants a detailed analysis of the provided Python code, which is part of the Frida dynamic instrumentation tool and deals with CMake integration within the Meson build system. I need to break down the functionality of the code, relating it to reverse engineering, low-level concepts, and potential user errors.

Here's a plan:

1. **Core Functionality:** Identify the main purpose of the `common.py` file. It seems to be handling the interaction between Meson and CMake, specifically for projects that use CMake as a subproject within a Meson build.

2. **Key Classes and Functions:**
    - `language_map`, `backend_generator_map`, `blacklist_cmake_defs`: These are simple data structures defining mappings and blacklisted CMake definitions.
    - `cmake_is_debug`:  Determine if the build is a debug build.
    - `CMakeException`: Custom exception for CMake-related errors.
    - `CMakeBuildFile`: Represents a CMake build file.
    - `_flags_to_list`: Parses a command-line string into a list of flags.
    - `cmake_get_generator_args`:  Gets the CMake generator arguments based on the Meson backend.
    - `cmake_defines_to_args`: Converts a dictionary of definitions into CMake `-D` arguments.
    - `check_cmake_args`:  Filters out blacklisted CMake arguments.
    - `CMakeInclude`: Represents an include directory for CMake.
    - `CMakeFileGroup`:  Groups source files with their compile flags, defines, and includes.
    - `CMakeTarget`: Represents a CMake target (executable, library).
    - `CMakeProject`: Represents a CMake project.
    - `CMakeConfiguration`: Represents a CMake configuration.
    - `SingleTargetOptions`, `TargetOptions`:  Allow overriding CMake options and arguments for specific targets.

3. **Reverse Engineering Relevance:** How does this code assist or relate to reverse engineering? Frida is a dynamic instrumentation tool used heavily in reverse engineering. This code helps integrate external CMake-based components into Frida's build process. These components might be libraries or tools used for hooking, code injection, or other reverse engineering tasks.

4. **Low-Level Concepts:** Identify parts of the code that interact with or are related to:
    - Binary format: CMake builds executables and libraries.
    - Linux/Android kernel/framework: Frida often targets these platforms. CMake handles platform-specific build configurations.
    - Compilation and linking:  The code deals with compiler flags, linker flags, and libraries.

5. **Logical Reasoning:** Look for conditional logic and data transformations. Explain the input and output of certain functions.

6. **User/Programming Errors:** Identify potential mistakes a user or developer might make when interacting with this code or the Meson/CMake integration.

7. **User Journey (Debugging Clue):**  Describe the steps a user might take that would lead to this specific file being involved in the debugging process. This usually involves a build failure or unexpected behavior related to the CMake subproject.

**Detailed Breakdown (Self-Correction/Refinement):**

- **Reverse Engineering:** Initially, I might just say "Frida is used for RE."  I need to be more specific: the *CMake components* built using this code *within Frida's build* could be RE tools.
- **Low-Level:**  Don't just mention the terms. Give concrete examples from the code: `link_libraries`, `link_flags`, the handling of different languages (`C`, `CXX`).
- **User Journey:** The user is likely trying to build Frida and encountering problems with a CMake dependency. The error message or build logs might point to Meson's CMake integration.
这个Python源代码文件 `common.py` 是 Frida 动态 instrumentation 工具中，用于处理 CMake 构建系统集成的一个模块。它的主要功能是帮助 Meson 构建系统与 CMake 项目进行交互，特别是在 Frida 作为 Meson 项目构建时，需要包含一些基于 CMake 的子项目时。

以下是其功能点的详细列举和说明：

**功能列举:**

1. **定义语言映射:** `language_map` 字典定义了不同编程语言在 Meson 和 CMake 中的对应关系，例如 `'c'` 对应 `'C'`， `'cpp'` 对应 `'CXX'` 等。
2. **定义后端生成器映射:** `backend_generator_map` 字典定义了 Meson 的构建后端（如 Ninja, Xcode, Visual Studio）与 CMake 生成器的对应关系。这允许 Meson 指示 CMake 使用特定的生成器来生成构建文件。
3. **定义 CMake 禁止使用的变量:** `blacklist_cmake_defs` 列表列出了一系列不应该由 Meson 直接传递给 CMake 的变量。这些变量通常由 Meson 自己管理，或者在跨平台构建中需要特殊处理。
4. **判断是否为 Debug 构建:** `cmake_is_debug(env)` 函数根据 Meson 的构建选项判断当前是否为 Debug 构建。它会检查 `buildtype` 和 `b_vscrt`（Visual Studio 运行时库）等选项。
5. **定义 CMake 异常:** `CMakeException` 类是自定义的异常类型，用于表示 CMake 相关的错误。
6. **表示 CMake 构建文件:** `CMakeBuildFile` 类用于表示一个 CMake 构建文件，包含文件路径、是否为 CMake 原生文件以及是否为临时文件等信息。
7. **将命令行字符串转换为列表:** `_flags_to_list(raw)` 函数将一个包含命令行参数的字符串分割成一个字符串列表，考虑到转义字符和引号的处理。
8. **获取 CMake 生成器参数:** `cmake_get_generator_args(env)` 函数根据 Meson 的后端设置，生成传递给 CMake 的 `-G` 参数，指定 CMake 使用哪个生成器。
9. **将定义转换为 CMake 参数:** `cmake_defines_to_args(raw, permissive=False)` 函数将 Python 字典形式的定义转换为 CMake 的 `-D` 参数字符串列表。它会检查是否使用了黑名单中的变量，并对不同类型的变量值进行相应的格式化。
10. **检查 CMake 参数:** `check_cmake_args(args)` 函数检查用户提供的 CMake 参数，如果包含黑名单中的变量，则发出警告并忽略。
11. **表示 CMake 包含目录:** `CMakeInclude` 类表示一个 CMake 的包含目录，包括路径和是否为系统包含目录的信息。
12. **表示 CMake 文件组:** `CMakeFileGroup` 类表示 CMake 中一组源文件及其相关的编译选项，包括宏定义、编译标志、包含目录、是否为生成文件以及编程语言等信息。它还提供了 `log()` 方法用于输出详细信息。
13. **表示 CMake 目标:** `CMakeTarget` 类表示一个 CMake 构建目标（例如可执行文件或库），包含其生成产物、源目录、构建目录、名称、是否安装、安装路径、链接语言、链接库、链接标志以及包含的文件组等信息。它也提供了 `log()` 方法用于输出详细信息。
14. **表示 CMake 项目:** `CMakeProject` 类表示一个 CMake 项目，包含源目录、构建目录、项目名称以及包含的目标列表。它同样提供了 `log()` 方法用于输出详细信息。
15. **表示 CMake 配置:** `CMakeConfiguration` 类表示一个 CMake 构建配置，包含配置名称以及包含的项目列表。它也提供了 `log()` 方法用于输出详细信息。
16. **处理单个目标的选项:** `SingleTargetOptions` 类用于存储和管理单个 CMake 目标的选项，包括自定义选项、特定语言的编译参数、链接参数以及安装行为。
17. **处理所有目标的选项:** `TargetOptions` 类用于存储和管理所有 CMake 目标的选项，包括全局选项和特定目标的选项，并提供方法来合并和获取最终的选项和参数。

**与逆向方法的关联及举例说明:**

Frida 本身就是一个强大的动态 instrumentation 工具，广泛应用于逆向工程。这个 `common.py` 文件虽然不直接执行逆向操作，但它使得在 Frida 的构建过程中可以集成一些基于 CMake 的组件，这些组件可能正是用于辅助逆向的工具或库。

**举例说明:**

假设 Frida 需要集成一个用 C++ 编写的、使用 CMake 构建的库，这个库提供了一些底层的内存操作或代码解析功能，这些功能在 Frida 进行 hook 或代码注入时非常有用。`common.py` 的功能就能帮助 Meson 正确地找到并构建这个 CMake 子项目，将其编译成 Frida 可以使用的动态链接库。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件虽然是 Python 代码，但它处理的是构建过程，最终会影响到生成的二进制文件和在目标平台上的运行。

**举例说明:**

* **二进制底层:** `CMakeTarget` 类中的 `artifacts` 属性记录了 CMake 构建生成的二进制文件（例如 `.so` 或 `.dylib` 文件）。编译和链接选项（如 `link_libraries`, `link_flags`）直接影响这些二进制文件的结构和依赖关系。例如，链接器标志可能指定了特定的 section 布局或符号处理方式。
* **Linux/Android 内核:**  当 Frida 需要在 Linux 或 Android 上运行时，CMake 构建过程需要针对这些平台进行配置。`cmake_is_debug` 函数判断是否为 debug 构建，这会影响编译器优化级别和是否包含调试符号，这些对于在内核中调试 Frida 的行为至关重要。
* **Android 框架:** 如果 Frida 需要与 Android 的 framework 进行交互，可能需要编译一些 JNI 桥接代码。`language_map` 中定义了 `java` 的映射，表明 CMake 构建也可能涉及到 Java 代码的编译。CMake 目标可能需要链接到 Android SDK 中的特定库。

**逻辑推理及假设输入与输出:**

`cmake_defines_to_args` 函数包含一定的逻辑推理，它根据输入字典中值的类型来决定如何生成 CMake 的 `-D` 参数。

**假设输入:**
```python
raw_defines = [{'MY_FLAG': True, 'MY_INT': 123, 'MY_STRING': 'hello'}]
```

**输出:**
```python
['-DMY_FLAG=ON', '-DMY_INT=123', '-DMY_STRING=hello']
```

**逻辑:**
- 如果值是布尔类型，则转换为 `'ON'` 或 `'OFF'`。
- 如果值是字符串、整数或浮点数，则直接使用其字符串表示。
- 如果值是其他类型，则会抛出 `MesonException`。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **使用黑名单中的 CMake 变量:** 用户可能尝试通过 `cmake_args` 或其他方式设置 `blacklist_cmake_defs` 中列出的变量，例如 `CMAKE_TOOLCHAIN_FILE`。这可能导致构建失败或产生不可预测的行为，因为 Meson 有自己的处理跨平台构建的方式。`check_cmake_args` 函数会检测到这种情况并发出警告。
   ```python
   # 错误示例：直接设置 CMAKE_TOOLCHAIN_FILE
   ['-DCMAKE_TOOLCHAIN_FILE=/path/to/my/toolchain.cmake']
   ```
   Meson 会警告用户不应该这样做，因为它期望用户通过 Meson 提供的跨平台构建机制来指定 toolchain 文件。

2. **在 `cmake_defines_to_args` 中传递不支持的数据类型:** 用户可能尝试将列表、字典等复杂数据类型作为 CMake 的定义值传递，这会被函数拒绝。
   ```python
   # 错误示例：传递列表作为定义值
   raw_defines = [{'MY_LIST': [1, 2, 3]}]
   cmake_defines_to_args(raw_defines) # 会抛出 MesonException
   ```
   错误信息会提示用户指定的类型不被支持。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当用户在构建 Frida 时，如果 Frida 的构建配置（`meson.build` 文件）中包含了使用 `cmake.subproject()` 函数引入的 CMake 子项目，那么 Meson 会在构建过程中调用 CMake 来构建这个子项目。

**步骤:**

1. **用户执行构建命令:** 用户在 Frida 源代码目录下执行 Meson 的构建命令，例如 `meson setup build` 或 `ninja -C build`。
2. **Meson 解析构建文件:** Meson 解析 `meson.build` 文件，发现了 `cmake.subproject()` 调用。
3. **Meson 与 CMake 交互:** Meson 需要配置 CMake 子项目。为了实现这一点，Meson 会生成一些临时的 CMake 文件或者调用 CMake 的 API。
4. **`common.py` 的参与:** 在这个过程中，`common.py` 中定义的函数会被调用，用于生成传递给 CMake 的参数（例如使用 `cmake_get_generator_args` 获取生成器参数，使用 `cmake_defines_to_args` 转换定义的宏）。
5. **构建失败或异常:** 如果 CMake 子项目的构建过程中出现错误，例如找不到依赖、编译失败等，或者用户配置了不正确的 CMake 选项，那么在调试过程中，开发者可能会查看 Meson 的构建日志。如果日志中涉及到 CMake 的调用和参数，就可能会追溯到 `common.py` 这个文件，因为它负责生成和处理与 CMake 相关的配置信息。

例如，如果构建日志中显示传递给 CMake 的 `-D` 参数不正确，或者使用了黑名单中的变量导致 CMake 行为异常，开发者就会查看 `cmake_defines_to_args` 和 `check_cmake_args` 的实现，以理解 Meson 是如何处理 CMake 定义的。如果涉及到 CMake 生成器的选择问题，则会查看 `cmake_get_generator_args` 的逻辑。

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/common.py` 这个文件是 Frida 构建系统中 Meson 与 CMake 桥梁的关键部分，它负责处理两者之间的信息转换和参数传递，确保 CMake 子项目能够被正确地集成到 Frida 的构建流程中。理解这个文件的功能对于调试 Frida 构建过程中与 CMake 相关的错误至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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