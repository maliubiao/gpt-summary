Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding: The Big Picture**

The filename `frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/common.py` immediately tells us a few things:

* **Frida:** It's part of the Frida project, a dynamic instrumentation toolkit.
* **frida-node:** It's related to the Node.js bindings for Frida.
* **releng:**  Likely part of the release engineering or build process.
* **meson:** The build system being used is Meson.
* **cmake:** This file interacts with CMake, another build system.
* **common.py:**  Suggests it contains shared functionality related to CMake integration within the Meson build.

Therefore, the core purpose is likely to manage the interaction between Frida's Node.js build process (using Meson) and external libraries or components built with CMake.

**2. Deconstructing the Code: Identifying Key Components and Their Functions**

I would then go through the code block by block, focusing on understanding the purpose of each class, function, and data structure.

* **`language_map`, `backend_generator_map`:** These are simple mappings. `language_map` translates Meson language names to CMake names. `backend_generator_map` does the same for build system backends (Ninja, Xcode, Visual Studio). This is about compatibility and translation between the two systems.

* **`blacklist_cmake_defs`:** This list is crucial. It identifies CMake definitions that are *not* supported when using Meson's CMake integration. This points to potential conflicts or differences in how Meson handles cross-compilation and other settings.

* **`cmake_is_debug(env)`:** This function determines if the current build is a debug build. It checks Meson's `buildtype` and `b_vscrt` options (related to Visual Studio runtimes). This indicates a need to configure CMake builds differently for debug vs. release.

* **`CMakeException`:** A custom exception class for CMake-related errors within the Meson build. Good practice for error handling.

* **`CMakeBuildFile`:** A simple data structure to represent a CMake build file, storing its path and whether it's a CMakeLists.txt or a temporary file.

* **`_flags_to_list(raw)`:** This is a utility function to parse a command-line string of flags into a list of individual flag strings, handling quoting and escaping. Essential for dealing with compiler and linker flags.

* **`cmake_get_generator_args(env)`:**  Determines the appropriate CMake generator argument based on the Meson backend being used. This tells CMake what kind of build files to generate (e.g., Ninja build.ninja, Xcode project).

* **`cmake_defines_to_args(raw, permissive=False)`:** Converts a list of Python dictionaries (representing CMake definitions) into a list of CMake command-line arguments (`-Dkey=value`). It also checks against the `blacklist_cmake_defs`. This is a key function for passing configuration information to CMake.

* **`check_cmake_args(args)`:**  Another function to filter out blacklisted CMake arguments. Likely a precursor to the more comprehensive `cmake_defines_to_args`. The comment suggests it might become obsolete.

* **`CMakeInclude`:** Represents an include directory path, indicating whether it's a system include.

* **`CMakeFileGroup`:**  Represents a group of source files with associated compiler flags, defines, and include paths. This corresponds to how CMake organizes source files. The `log()` method is for debugging output.

* **`CMakeTarget`:** Represents a CMake target (e.g., an executable or a library). It holds information about artifacts, source/build directories, link libraries, link flags, and the `CMakeFileGroup`s it contains. The `log()` method is again for debugging.

* **`CMakeProject`:**  Represents a CMake project, containing multiple `CMakeTarget`s. Includes source and build directories.

* **`CMakeConfiguration`:** Represents a CMake build configuration (e.g., Debug, Release), containing multiple `CMakeProject`s.

* **`SingleTargetOptions`, `TargetOptions`:** These classes provide a way to manage options (compiler flags, linker flags, install status) that can be applied globally or to specific CMake targets. This allows for fine-grained control over the CMake build process.

**3. Connecting to the Request: Answering the Specific Questions**

Once I have a good understanding of the code, I can systematically address the questions in the prompt:

* **Functionality:**  Summarize the purpose of each component as described above.

* **Relationship to Reverse Engineering:** Focus on how the code interacts with the build process of potentially reverse-engineered targets. The ability to set compiler/linker flags, define symbols, and manage include paths is crucial for building Frida gadgets or agents that interact with specific applications or libraries. The example with setting library paths directly illustrates this.

* **Binary/Kernel/Framework Knowledge:** Point out areas where the code touches upon these concepts. The compiler/linker flags, understanding the differences between debug and release builds, and the management of include paths all relate to the underlying compilation and linking process. Mention the OS-specific nature of some flags and library paths.

* **Logical Inference:** Look for conditional logic and how inputs affect outputs. The `cmake_is_debug` function is a good example, where the input `env.coredata.options` determines the boolean output. The `cmake_defines_to_args` function takes dictionaries and produces command-line arguments.

* **User/Programming Errors:** Identify potential mistakes users could make, such as trying to use blacklisted CMake definitions or providing incorrect data types for definitions.

* **User Operations Leading Here:**  Trace the execution path backward. A user would likely be trying to build Frida's Node.js bindings, which involves using Meson and potentially interacting with CMake-based dependencies. The need for this file arises when Meson delegates part of the build process to CMake.

**4. Structuring the Answer:**

Finally, organize the findings in a clear and structured way, using headings and bullet points as in the example answer you provided. This makes the information easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly *executes* CMake. **Correction:**  It primarily *prepares* information and arguments for CMake. Meson will then invoke the CMake executable.
* **Overlooking details:**  Initially, I might gloss over the `SingleTargetOptions` and `TargetOptions` classes. **Refinement:**  Realize their importance in providing flexible configuration management for CMake targets.
* **Ambiguity:** Some variable names might be unclear initially. **Refinement:**  Infer their purpose from the context and how they are used. For instance, understanding that `env` refers to the Meson environment.

By following this structured thought process, combining code analysis with domain knowledge (Frida, build systems), and focusing on the questions asked, it's possible to generate a comprehensive and accurate explanation of the code's functionality and its relevance to reverse engineering and related concepts.
这个 Python 源代码文件 `common.py` 是 Frida 动态Instrumentation 工具中，负责处理与 CMake 构建系统集成的模块的一部分。它定义了一些数据结构和函数，用于在 Meson 构建系统中使用 CMake 项目或与 CMake 产生的构建信息进行交互。

以下是该文件的功能列表，并根据你的要求进行了详细说明：

**1. 定义语言和构建后端映射:**

* **`language_map`:**  将 Meson 使用的编程语言名称（如 'c', 'cpp'）映射到 CMake 使用的名称 ('C', 'CXX')。这在 Meson 需要将语言信息传递给 CMake 时进行转换。
* **`backend_generator_map`:** 将 Meson 的构建后端名称（如 'ninja', 'xcode'）映射到 CMake 的生成器名称 ('Ninja', 'Xcode')。当 Meson 调用 CMake 时，需要指定生成器以告诉 CMake 生成哪种类型的构建文件。

**2. 定义 CMake 禁止使用的定义:**

* **`blacklist_cmake_defs`:**  列出了一组 CMake 定义（例如 `CMAKE_TOOLCHAIN_FILE`），这些定义在使用 Meson 进行构建时是不允许直接设置的。这通常是因为 Meson 有自己的方式来处理这些设置（例如交叉编译的工具链文件），直接使用 CMake 的定义可能会导致冲突或不一致。

**3. 判断是否是 Debug 构建:**

* **`cmake_is_debug(env)`:**  根据 Meson 的构建选项判断当前是否是 Debug 构建。它会检查 `buildtype` 和 `b_vscrt`（Visual Studio 运行时库）选项。这对于在 CMake 构建中设置正确的编译标志和链接选项非常重要。

**4. 定义 CMake 相关的异常:**

* **`CMakeException`:**  定义了一个继承自 `MesonException` 的自定义异常类，用于在处理 CMake 相关操作时抛出特定的错误。

**5. 表示 CMake 构建文件的类:**

* **`CMakeBuildFile`:**  一个简单的数据类，用于表示一个 CMake 构建文件，包含文件路径、是否是 CMakeLists.txt 文件以及是否是临时文件。

**6. 将原始命令行字符串转换为列表:**

* **`_flags_to_list(raw)`:**  这是一个内部辅助函数，用于将包含空格分隔的命令行选项的字符串转换为字符串列表。它还处理转义字符和引号，以正确解析包含空格的选项值。

**7. 获取 CMake 生成器参数:**

* **`cmake_get_generator_args(env)`:**  根据 Meson 的构建后端选项，返回传递给 CMake 的生成器参数（例如 `['-G', 'Ninja']`）。

**8. 将 CMake 定义转换为命令行参数:**

* **`cmake_defines_to_args(raw, permissive=False)`:**  将一个包含 CMake 定义的字典列表转换为 CMake 的命令行参数形式 (`-Dkey=value`)。它会检查定义的键是否在 `blacklist_cmake_defs` 中，如果是则发出警告。对于布尔值，会转换为 'ON' 或 'OFF'。

   **与逆向的方法的关系举例:**

   假设你需要使用 Frida hook 一个使用了特定库的 Android 应用。这个库可能需要通过 CMake 构建，并且在构建时需要定义一个特定的宏 `MY_CUSTOM_DEFINE` 来启用某些功能。你可以在 Meson 的构建配置中，通过 `cmake_options` 传递这个定义：

   ```python
   cmake_options = {
       'MY_CUSTOM_DEFINE': '1'
   }
   ```

   `cmake_defines_to_args` 函数会将这个字典转换为 `['-DMY_CUSTOM_DEFINE=1']`，然后传递给 CMake，从而影响库的构建方式，最终影响 Frida hook 的行为。

**9. 检查 CMake 参数 (可能已过时):**

* **`check_cmake_args(args)`:**  类似于 `cmake_defines_to_args`，用于检查给定的 CMake 参数列表是否包含黑名单中的定义。注释表明这个函数未来可能会被废弃。

**10. 表示 CMake 包含目录的类:**

* **`CMakeInclude`:**  一个数据类，表示一个 CMake 的包含目录，包含路径和是否是系统包含目录的标志。

**11. 表示 CMake 文件组的类:**

* **`CMakeFileGroup`:**  表示 CMake 中的一个文件组，通常包含一组源文件以及与之相关的编译选项、宏定义和包含目录。

   **涉及到二进制底层、Linux、Android 内核及框架的知识举例:**

   假设一个 Frida 组件需要编译一些 C 代码，这些代码使用了 Linux 内核的头文件，例如 `linux/kernel.h`。在 `CMakeFileGroup` 中，`includes` 列表可能会包含指向内核头文件目录的 `CMakeInclude` 对象，并且 `isSystem` 标志可能为 `True`。

   如果这个 Frida 组件需要在 Android 上运行，并且需要访问 Android Framework 的头文件（例如 `android/log.h`），那么 `CMakeFileGroup` 的 `includes` 中也会包含指向 Android SDK 或 NDK 中相关头文件目录的 `CMakeInclude` 对象。

   `flags` 字段可能包含针对特定架构或操作系统的编译标志，例如 `-marm` 或 `-D_GNU_SOURCE`。

   **假设输入与输出 (逻辑推理):**

   假设 `CMakeFileGroup` 的 `data` 输入如下：

   ```python
   data = {
       'compileFlags': '-Wall -O2',
       'defines': 'DEBUG_ENABLED',
       'includePath': [
           '/usr/include',
           {'path': '/opt/my_lib/include', 'isSystem': False}
       ],
       'language': 'C++',
       'sources': ['src/myfile.cpp', 'src/another.cpp']
   }
   ```

   `CMakeFileGroup(data)` 初始化后，其属性将为：

   * `flags`: `['-Wall', '-O2']`
   * `defines`: `DEBUG_ENABLED`
   * `includes`: `[CMakeInclude(path=Path('/usr/include'), isSystem=True), CMakeInclude(path=Path('/opt/my_lib/include'), isSystem=False)]`
   * `language`: `C++`
   * `sources`: `[Path('src/myfile.cpp'), Path('src/another.cpp')]`

**12. 表示 CMake 目标的类:**

* **`CMakeTarget`:**  表示 CMake 构建系统中的一个目标（例如可执行文件、库）。它包含目标的工件路径、源目录、构建目录、名称、安装规则、链接库、链接标志等信息。

   **涉及到二进制底层、Linux、Android 内核及框架的知识举例:**

   `link_libraries` 列表可能包含需要链接的共享库的名称，例如 `['pthread', 'ssl']`。这些库可能与操作系统底层功能或特定的框架有关。

   `link_flags` 可能包含链接器标志，例如 `-Wl,-rpath,/opt/my_lib/lib`，用于指定运行时库的搜索路径。这直接涉及到二进制文件的加载和执行过程。

**13. 表示 CMake 项目的类:**

* **`CMakeProject`:**  表示一个 CMake 项目，包含多个 CMake 目标。

**14. 表示 CMake 配置的类:**

* **`CMakeConfiguration`:**  表示一个 CMake 构建配置（例如 Debug 或 Release），包含多个 CMake 项目。

**15. 用于管理目标选项的类:**

* **`SingleTargetOptions`:**  用于存储单个 CMake 目标的自定义选项，包括编译选项、链接选项和安装状态。
* **`TargetOptions`:**  用于管理所有 CMake 目标的选项，可以设置全局选项或针对特定目标的选项。

   **用户或编程常见的使用错误举例:**

   用户可能会尝试通过 `TargetOptions` 设置一个在 `blacklist_cmake_defs` 中的 CMake 定义，例如 `CMAKE_TOOLCHAIN_FILE`。虽然代码中会发出警告，但如果用户不注意，可能会导致构建配置与 Meson 的预期不一致，引发构建错误或运行时问题。

   例如，用户可能尝试这样设置：

   ```python
   target_options = TargetOptions()
   target_options.global_options.set_opt('CMAKE_TOOLCHAIN_FILE', '/path/to/my/toolchain.cmake')
   ```

   这将触发警告，因为 `CMAKE_TOOLCHAIN_FILE` 是被禁止的。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida 的 Node.js 绑定：** 用户通常会执行类似 `npm install frida` 或使用 `meson` 命令来构建 Frida 的 Node.js 模块。

2. **Meson 构建系统介入：** Frida 的 Node.js 绑定使用了 Meson 作为构建系统。Meson 会读取项目中的 `meson.build` 文件来了解构建配置。

3. **集成 CMake 子项目：** 在 `meson.build` 文件中，可能声明了需要集成一个或多个基于 CMake 的子项目或依赖项。

4. **Meson 调用 CMake：** 当 Meson 处理到需要构建 CMake 项目的部分时，它会调用 CMake 工具。

5. **`common.py` 中的代码被调用：** 在调用 CMake 之前，Meson 需要准备 CMake 的参数和配置。`common.py` 中的函数，例如 `cmake_get_generator_args` 和 `cmake_defines_to_args`，会被 Meson 调用，以便根据 Meson 的配置生成正确的 CMake 命令行参数。

6. **读取和解析 CMake 构建信息：**  在某些情况下，Meson 可能需要读取 CMake 生成的构建信息（例如，用于查找库或头文件）。这时，`CMakeProject`、`CMakeTarget` 等类会被用来解析这些信息。

**调试线索：**

如果你在 Frida 的 Node.js 绑定构建过程中遇到与 CMake 相关的问题，例如：

* **CMake 配置错误：**  可能是因为传递给 CMake 的定义或选项不正确。你可以检查 `common.py` 中的黑名单，确认你没有尝试设置被禁止的选项。
* **链接错误：**  可能是因为 CMake 构建的目标没有正确地链接到 Frida 的 Node.js 绑定。你可以查看 `CMakeTarget` 中的 `link_libraries` 和 `link_flags`，确认链接设置是否正确。
* **编译错误：**  可能是因为 CMake 构建的目标的编译选项不正确。你可以查看 `CMakeFileGroup` 中的 `flags` 和 `includes`，确认编译标志和包含目录是否正确设置。

通过理解 `common.py` 中定义的类和函数的功能，你可以更好地理解 Frida 的 Node.js 绑定是如何与 CMake 构建系统集成的，从而更有效地进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```