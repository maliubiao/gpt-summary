Response:
The user wants a summary of the functionalities of the provided Python code, which is a module for interpreting CMake projects within the Frida dynamic instrumentation tool.

Here's a breakdown of the thinking process to generate the answer:

1. **Identify the Core Functionality:** The code is named `interpreter.py` and resides within a CMake-related directory (`frida/subprojects/frida-python/releng/meson/mesonbuild/cmake`). This strongly suggests its primary function is to interpret CMake project files.

2. **Analyze Class Structure:** The code defines several classes: `OutputTargetMap`, `ConverterTarget`, and `ConverterCustomTarget`. These classes likely represent the internal data structures used to represent CMake targets (both regular and custom).

3. **Examine Key Methods:**  Focus on the methods within these classes to understand how they process CMake information:
    * `OutputTargetMap`:  Methods like `add`, `target`, `executable`, `artifact`, `generated` indicate its role in managing and retrieving target information based on names and artifacts.
    * `ConverterTarget`: The `__init__` method likely parses CMake target information. `postprocess` suggests further refinement and adjustments of the target data. Methods like `process_object_libs`, `process_inter_target_dependencies`, and `cleanup_dependencies` hint at how target dependencies are handled. The `meson_func` method is a strong indicator of converting CMake target types to Meson equivalents.
    * `ConverterCustomTarget`: Similar to `ConverterTarget`, `__init__` and `postprocess` are key. The `get_ref` method indicates how custom target outputs are referenced.

4. **Look for Interactions with Other Systems:** The code imports from `..mesonlib`, `..coredata`, `..compilers`, `..programs`. This implies the interpreter interacts with the Meson build system's internal data structures and utilities.

5. **Identify Connections to Reverse Engineering:** The code is part of Frida, a reverse engineering tool. Look for hints of how the CMake interpretation relates to this:
    * The handling of shared libraries (`MODULE_LIBRARY`, `SHARED_LIBRARY`) and executables is relevant to reverse engineering targets.
    * The processing of include directories and link libraries is crucial for building and understanding the dependencies of binaries.

6. **Infer Binary/Kernel/Framework Interactions:**
    * The handling of different library types (static, shared) and executables directly involves binary concepts.
    * The mention of Linux and Android kernels and frameworks is not explicit in this code snippet. However, Frida *targets* these systems, so the *output* of this interpreter is likely used in building instrumentation for those environments. The code itself might not directly manipulate kernel structures, but it sets up the build process.

7. **Consider Logic and Assumptions:** Analyze how the code transforms CMake data. For example, how are CMake target names translated to Meson names? How are dependencies resolved?

8. **Identify Potential User Errors:** Look for areas where incorrect CMake configurations could lead to problems during interpretation. Warnings about missing targets or non-existent paths are good indicators.

9. **Trace User Actions (Debugging Clue):**  Think about the steps a user would take to trigger this code. They would likely be using Frida's tooling to instrument a target, and that process would involve interpreting the CMake build system of the target.

10. **Synthesize the Information:** Group the findings into logical categories to answer the user's questions systematically.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focus solely on the direct code manipulations.
* **Correction:**  Realize the need to connect the code's function to the broader context of Frida and reverse engineering.
* **Initial thought:**  List every single method and attribute.
* **Correction:**  Focus on the *key* functionalities and how they contribute to the overall goal.
* **Initial thought:**  Assume direct manipulation of kernel structures within this code.
* **Correction:**  Recognize that this code primarily *interprets* build information, and the actual kernel interaction happens at a later stage in Frida's operation. The connection is indirect.

By following this process, iteratively refining the understanding of the code's purpose and context, a comprehensive summary can be generated, addressing all aspects of the user's request.
好的，我们来分析一下 `frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/interpreter.py` 这个文件的功能。从代码结构和内容来看，这个 Python 模块的主要作用是将 CMake 项目的信息转换为 Meson 构建系统可以理解的数据结构。

**该文件的主要功能归纳如下：**

1. **CMake 项目信息解析：** 该模块读取并解析 CMake 构建系统生成的信息，例如目标（targets）、源文件、编译选项、链接库、依赖关系等。
2. **CMake 目标（Target）转换：**  将 CMake 定义的各种目标类型（例如：静态库、共享库、可执行文件、对象库、接口库、自定义目标）转换为 Meson 中对应的目标类型。
3. **依赖关系处理：** 分析 CMake 项目中目标之间的依赖关系，并将其转换为 Meson 可以理解的依赖关系。
4. **编译和链接选项处理：**  提取和处理 CMake 项目中定义的编译选项和链接选项，并进行一些过滤和转换，例如移除不必要的或可能引起冲突的选项。
5. **头文件和源文件管理：**  识别和管理 CMake 项目中的头文件和源文件，并处理包含目录。
6. **自定义命令处理：**  处理 CMake 中定义的自定义命令，并将其转换为 Meson 的自定义目标（Custom Target）。
7. **路径处理：**  处理 CMake 项目中各种路径，使其相对于 Meson 的构建目录和源码目录。
8. **与 Meson 集成：**  将解析和转换后的 CMake 项目信息提供给 Meson 构建系统，以便 Meson 可以根据这些信息生成最终的构建系统。

**与逆向方法的关系以及举例说明：**

这个模块的功能与逆向工程有密切关系，因为它允许 Frida 这个动态插桩工具利用目标应用程序的 CMake 构建信息来构建插桩代码。

**举例说明：**

假设你要使用 Frida 对一个使用 CMake 构建的 Android 原生库 (`.so` 文件) 进行插桩。

1. **CMake 信息的获取：**  Frida 会分析该原生库的 CMakeLists.txt 文件以及 CMake 生成的构建信息（例如：CMake File API 的输出）。
2. **目标识别：** `interpreter.py` 模块会识别出该原生库是一个 `SHARED_LIBRARY` 类型的 CMake 目标。
3. **源文件和头文件识别：**  模块会找到该库的所有源文件 (`.c`, `.cpp` 等) 和头文件 (`.h`)。
4. **编译选项提取：** 模块会提取出编译该库时使用的编译选项，例如 `-DDEBUG`、`-O2`、`-I/path/to/include` 等。
5. **依赖关系分析：**  如果该库依赖于其他 CMake 目标（例如：静态库），`interpreter.py` 会分析这些依赖关系。
6. **链接库提取：**  模块会提取出链接该库时需要的其他库。
7. **Meson 转换：** `interpreter.py` 将这些信息转换为 Meson 可以理解的格式，例如创建一个 Meson 的 `shared_library()` 目标，并设置相应的源文件、头文件路径、编译选项、链接库等。
8. **Frida 插桩构建：**  Frida 基于这些信息，可以构建能够与目标原生库交互的插桩代码。例如，它可以根据头文件信息生成函数签名，以便进行函数 hook。

**涉及到二进制底层、Linux、Android 内核及框架的知识的举例说明：**

虽然 `interpreter.py` 本身是用 Python 编写的，并不直接操作二进制底层或内核，但它处理的信息与这些底层概念密切相关。

**举例说明：**

* **二进制底层：**
    * `target_type_map` 变量将 CMake 的 `SHARED_LIBRARY` 映射到 Meson 的 `shared_library`。共享库是二进制文件的一种形式，理解其结构（例如：导出符号、重定位信息）对于逆向和插桩至关重要。
    * 模块处理链接库 (`link_libraries`)，这些链接库通常是编译后的二进制文件 (`.so` 或 `.a` 文件)。
    * 过滤链接标志 (`blacklist_link_flags`) 中包含了如 `/machine:x64`、`/machine:arm` 这样的架构相关的标志，这涉及到目标二进制文件的架构。

* **Linux/Android 内核及框架：**
    * 在 Android 环境下，被插桩的目标可能使用了 Android 框架的库。`interpreter.py` 需要正确解析这些库的依赖关系。例如，一个使用了 `libbinder.so` 的库，其依赖关系需要被正确识别。
    * 模块处理的链接库可能包含与 Linux 系统调用或 Android 特定 API 相关的库。

**逻辑推理的假设输入与输出：**

假设输入一个简单的 CMake 目标定义：

```cmake
add_library(mylib SHARED
    src/mylib.c
    include/mylib.h
)

target_include_directories(mylib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
```

**假设输入：**  CMake 对 `mylib` 目标的描述信息，包括源文件路径、头文件路径、目标类型等。

**预期输出（部分）：**

* `ConverterTarget` 对象，其 `name` 属性为 `mylib`。
* `ConverterTarget` 对象的 `type` 属性为 `SHARED_LIBRARY`。
* `ConverterTarget` 对象的 `sources` 属性包含 `Path('src/mylib.c')`。
* `ConverterTarget` 对象的 `includes` 属性包含 `Path('include')` (相对路径，可能需要进一步处理)。

**涉及用户或编程常见的使用错误及举例说明：**

1. **CMake 配置错误：** 如果 CMakeLists.txt 文件配置错误，例如头文件路径或源文件路径不正确，`interpreter.py` 可能会无法正确解析，导致后续的 Frida 构建失败。
   * **例子：**  CMakeLists.txt 中头文件路径写错 `target_include_directories(mylib PUBLIC include_typo)`，`interpreter.py` 可能会找不到头文件，导致 Frida 无法生成正确的插桩代码。

2. **不支持的 CMake 特性：**  某些高级或特定的 CMake 特性可能 `interpreter.py` 尚未支持。
   * **例子：**  使用了比较新的 CMake 命令或语法，而 `interpreter.py` 的代码没有及时更新来解析这些新特性，可能会导致解析错误。

3. **依赖关系解析错误：**  复杂的 CMake 依赖关系可能导致 `interpreter.py` 解析错误，尤其是当依赖关系涉及到自定义命令生成的文件。
   * **例子：**  一个目标依赖于另一个自定义目标生成的头文件，如果 `interpreter.py` 没有正确识别自定义目标的输出，就可能无法建立正确的依赖关系。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **用户使用 Frida 插桩工具，指定一个目标应用程序或库。**
2. **Frida 需要了解目标程序的构建信息，特别是当目标是原生代码时。**
3. **如果目标程序使用 CMake 构建，Frida 会尝试利用 CMake 生成的构建信息（通过 CMake File API 或其他方式）。**
4. **Frida 内部的构建系统会调用 `frida-python` 相关的代码。**
5. **`frida-python` 的 releng 目录下的 Meson 构建系统被触发。**
6. **`mesonbuild/cmake/interpreter.py` 模块被加载，用于解析 CMake 提供的信息。**
7. **如果解析过程中出现错误，例如找不到目标或依赖，或者遇到不支持的 CMake 特性，用户可能会看到相关的错误信息。** 这些错误信息可以作为调试线索，帮助用户检查 CMake 配置或 Frida 的版本。

**功能归纳（第 1 部分）：**

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/interpreter.py` 的主要功能是作为 Frida 的一个桥梁，负责将 CMake 构建系统的项目信息翻译成 Meson 构建系统可以理解的形式。这使得 Frida 能够利用目标应用程序的 CMake 构建信息来辅助进行动态插桩和逆向分析。它处理了 CMake 项目的结构、目标、依赖、编译选项、链接选项等关键信息，并进行必要的转换和过滤，以便 Meson 可以基于这些信息进行构建。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

# This class contains the basic functionality needed to run any interpreter
# or an interpreter-based tool.
from __future__ import annotations

from functools import lru_cache
from os import environ
from pathlib import Path
import re
import typing as T

from .common import CMakeException, CMakeTarget, language_map, cmake_get_generator_args, check_cmake_args
from .fileapi import CMakeFileAPI
from .executor import CMakeExecutor
from .toolchain import CMakeToolchain, CMakeExecScope
from .traceparser import CMakeTraceParser
from .tracetargets import resolve_cmake_trace_targets
from .. import mlog, mesonlib
from ..mesonlib import MachineChoice, OrderedSet, path_is_in_root, relative_to_if_possible, OptionKey
from ..mesondata import DataFile
from ..compilers.compilers import assembler_suffixes, lang_suffixes, header_suffixes, obj_suffixes, lib_suffixes, is_header
from ..programs import ExternalProgram
from ..coredata import FORBIDDEN_TARGET_NAMES
from ..mparser import (
    Token,
    BaseNode,
    CodeBlockNode,
    FunctionNode,
    ArrayNode,
    ArgumentNode,
    AssignmentNode,
    BooleanNode,
    StringNode,
    IdNode,
    IndexNode,
    MethodNode,
    NumberNode,
    SymbolNode,
)


if T.TYPE_CHECKING:
    from .common import CMakeConfiguration, TargetOptions
    from .traceparser import CMakeGeneratorTarget
    from .._typing import ImmutableListProtocol
    from ..backend.backends import Backend
    from ..environment import Environment

    TYPE_mixed = T.Union[str, int, bool, Path, BaseNode]
    TYPE_mixed_list = T.Union[TYPE_mixed, T.Sequence[TYPE_mixed]]
    TYPE_mixed_kwargs = T.Dict[str, TYPE_mixed_list]

# Disable all warnings automatically enabled with --trace and friends
# See https://cmake.org/cmake/help/latest/variable/CMAKE_POLICY_WARNING_CMPNNNN.html
disable_policy_warnings = [
    'CMP0025',
    'CMP0047',
    'CMP0056',
    'CMP0060',
    'CMP0065',
    'CMP0066',
    'CMP0067',
    'CMP0082',
    'CMP0089',
    'CMP0102',
]

target_type_map = {
    'STATIC_LIBRARY': 'static_library',
    'MODULE_LIBRARY': 'shared_module',
    'SHARED_LIBRARY': 'shared_library',
    'EXECUTABLE': 'executable',
    'OBJECT_LIBRARY': 'static_library',
    'INTERFACE_LIBRARY': 'header_only'
}

skip_targets = ['UTILITY']

blacklist_compiler_flags = [
    '-Wall', '-Wextra', '-Weverything', '-Werror', '-Wpedantic', '-pedantic', '-w',
    '/W1', '/W2', '/W3', '/W4', '/Wall', '/WX', '/w',
    '/O1', '/O2', '/Ob', '/Od', '/Og', '/Oi', '/Os', '/Ot', '/Ox', '/Oy', '/Ob0',
    '/RTC1', '/RTCc', '/RTCs', '/RTCu',
    '/Z7', '/Zi', '/ZI',
]

blacklist_link_flags = [
    '/machine:x64', '/machine:x86', '/machine:arm', '/machine:ebc',
    '/debug', '/debug:fastlink', '/debug:full', '/debug:none',
    '/incremental',
]

blacklist_clang_cl_link_flags = ['/GR', '/EHsc', '/MDd', '/Zi', '/RTC1']

blacklist_link_libs = [
    'kernel32.lib',
    'user32.lib',
    'gdi32.lib',
    'winspool.lib',
    'shell32.lib',
    'ole32.lib',
    'oleaut32.lib',
    'uuid.lib',
    'comdlg32.lib',
    'advapi32.lib'
]

transfer_dependencies_from = ['header_only']

_cmake_name_regex = re.compile(r'[^_a-zA-Z0-9]')
def _sanitize_cmake_name(name: str) -> str:
    name = _cmake_name_regex.sub('_', name)
    if name in FORBIDDEN_TARGET_NAMES or name.startswith('meson'):
        name = 'cm_' + name
    return name

class OutputTargetMap:
    rm_so_version = re.compile(r'(\.[0-9]+)+$')

    def __init__(self, build_dir: Path):
        self.tgt_map: T.Dict[str, T.Union['ConverterTarget', 'ConverterCustomTarget']] = {}
        self.build_dir = build_dir

    def add(self, tgt: T.Union['ConverterTarget', 'ConverterCustomTarget']) -> None:
        def assign_keys(keys: T.List[str]) -> None:
            for i in [x for x in keys if x]:
                self.tgt_map[i] = tgt
        keys = [self._target_key(tgt.cmake_name)]
        if isinstance(tgt, ConverterTarget):
            keys += [tgt.full_name]
            keys += [self._rel_artifact_key(x) for x in tgt.artifacts]
            keys += [self._base_artifact_key(x) for x in tgt.artifacts]
        if isinstance(tgt, ConverterCustomTarget):
            keys += [self._rel_generated_file_key(x) for x in tgt.original_outputs]
            keys += [self._base_generated_file_key(x) for x in tgt.original_outputs]
        assign_keys(keys)

    def _return_first_valid_key(self, keys: T.List[str]) -> T.Optional[T.Union['ConverterTarget', 'ConverterCustomTarget']]:
        for i in keys:
            if i and i in self.tgt_map:
                return self.tgt_map[i]
        return None

    def target(self, name: str) -> T.Optional[T.Union['ConverterTarget', 'ConverterCustomTarget']]:
        return self._return_first_valid_key([self._target_key(name)])

    def executable(self, name: str) -> T.Optional['ConverterTarget']:
        tgt = self.target(name)
        if tgt is None or not isinstance(tgt, ConverterTarget):
            return None
        if tgt.meson_func() != 'executable':
            return None
        return tgt

    def artifact(self, name: str) -> T.Optional[T.Union['ConverterTarget', 'ConverterCustomTarget']]:
        keys = []
        candidates = [name, OutputTargetMap.rm_so_version.sub('', name)]
        for i in lib_suffixes:
            if not name.endswith('.' + i):
                continue
            new_name = name[:-len(i) - 1]
            new_name = OutputTargetMap.rm_so_version.sub('', new_name)
            candidates += [f'{new_name}.{i}']
        for i in candidates:
            keys += [self._rel_artifact_key(Path(i)), Path(i).name, self._base_artifact_key(Path(i))]
        return self._return_first_valid_key(keys)

    def generated(self, name: Path) -> T.Optional['ConverterCustomTarget']:
        res = self._return_first_valid_key([self._rel_generated_file_key(name), self._base_generated_file_key(name)])
        assert res is None or isinstance(res, ConverterCustomTarget)
        return res

    # Utility functions to generate local keys
    def _rel_path(self, fname: Path) -> T.Optional[Path]:
        try:
            return fname.resolve().relative_to(self.build_dir)
        except ValueError:
            pass
        return None

    def _target_key(self, tgt_name: str) -> str:
        return f'__tgt_{tgt_name}__'

    def _rel_generated_file_key(self, fname: Path) -> T.Optional[str]:
        path = self._rel_path(fname)
        return f'__relgen_{path.as_posix()}__' if path else None

    def _base_generated_file_key(self, fname: Path) -> str:
        return f'__gen_{fname.name}__'

    def _rel_artifact_key(self, fname: Path) -> T.Optional[str]:
        path = self._rel_path(fname)
        return f'__relart_{path.as_posix()}__' if path else None

    def _base_artifact_key(self, fname: Path) -> str:
        return f'__art_{fname.name}__'

class ConverterTarget:
    def __init__(self, target: CMakeTarget, env: 'Environment', for_machine: MachineChoice) -> None:
        self.env = env
        self.for_machine = for_machine
        self.artifacts = target.artifacts
        self.src_dir = target.src_dir
        self.build_dir = target.build_dir
        self.name = target.name
        self.cmake_name = target.name
        self.full_name = target.full_name
        self.type = target.type
        self.install = target.install
        self.install_dir: T.Optional[Path] = None
        self.link_libraries = target.link_libraries
        self.link_flags = target.link_flags + target.link_lang_flags
        self.depends_raw: T.List[str] = []
        self.depends: T.List[T.Union[ConverterTarget, ConverterCustomTarget]] = []

        if target.install_paths:
            self.install_dir = target.install_paths[0]

        self.languages: T.Set[str] = set()
        self.sources: T.List[Path] = []
        self.generated: T.List[Path] = []
        self.generated_ctgt: T.List[CustomTargetReference] = []
        self.includes: T.List[Path] = []
        self.sys_includes: T.List[Path] = []
        self.link_with: T.List[T.Union[ConverterTarget, ConverterCustomTarget]] = []
        self.object_libs: T.List[ConverterTarget] = []
        self.compile_opts: T.Dict[str, T.List[str]] = {}
        self.public_compile_opts: T.List[str] = []
        self.pie = False

        # Project default override options (c_std, cpp_std, etc.)
        self.override_options: T.List[str] = []

        # Convert the target name to a valid meson target name
        self.name = _sanitize_cmake_name(self.name)

        self.generated_raw: T.List[Path] = []

        for i in target.files:
            languages: T.Set[str] = set()
            src_suffixes: T.Set[str] = set()

            # Insert suffixes
            for j in i.sources:
                if not j.suffix:
                    continue
                src_suffixes.add(j.suffix[1:])

            # Determine the meson language(s)
            # Extract the default language from the explicit CMake field
            lang_cmake_to_meson = {val.lower(): key for key, val in language_map.items()}
            languages.add(lang_cmake_to_meson.get(i.language.lower(), 'c'))

            # Determine missing languages from the source suffixes
            for sfx in src_suffixes:
                for key, val in lang_suffixes.items():
                    if sfx in val:
                        languages.add(key)
                        break

            # Register the new languages and initialize the compile opts array
            for lang in languages:
                self.languages.add(lang)
                if lang not in self.compile_opts:
                    self.compile_opts[lang] = []

            # Add arguments, but avoid duplicates
            args = i.flags
            args += [f'-D{x}' for x in i.defines]
            for lang in languages:
                self.compile_opts[lang] += [x for x in args if x not in self.compile_opts[lang]]

            # Handle include directories
            self.includes += [x.path for x in i.includes if x.path not in self.includes and not x.isSystem]
            self.sys_includes += [x.path for x in i.includes if x.path not in self.sys_includes and x.isSystem]

            # Add sources to the right array
            if i.is_generated:
                self.generated_raw += i.sources
            else:
                self.sources += i.sources

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.name}>'

    std_regex = re.compile(r'([-]{1,2}std=|/std:v?|[-]{1,2}std:)(.*)')

    def postprocess(self, output_target_map: OutputTargetMap, root_src_dir: Path, subdir: Path, install_prefix: Path, trace: CMakeTraceParser) -> None:
        # Detect setting the C and C++ standard and do additional compiler args manipulation
        for i in ['c', 'cpp']:
            if i not in self.compile_opts:
                continue

            temp: T.List[str] = []
            for j in self.compile_opts[i]:
                m = ConverterTarget.std_regex.match(j)
                ctgt = output_target_map.generated(Path(j))
                if m:
                    std = m.group(2)
                    supported = self._all_lang_stds(i)
                    if std not in supported:
                        mlog.warning(
                            'Unknown {0}_std "{1}" -> Ignoring. Try setting the project-'
                            'level {0}_std if build errors occur. Known '
                            '{0}_stds are: {2}'.format(i, std, ' '.join(supported)),
                            once=True
                        )
                        continue
                    self.override_options += [f'{i}_std={std}']
                elif j in {'-fPIC', '-fpic', '-fPIE', '-fpie'}:
                    self.pie = True
                elif isinstance(ctgt, ConverterCustomTarget):
                    # Sometimes projects pass generated source files as compiler
                    # flags. Add these as generated sources to ensure that the
                    # corresponding custom target is run.2
                    self.generated_raw += [Path(j)]
                    temp += [j]
                elif j in blacklist_compiler_flags:
                    pass
                else:
                    temp += [j]

            self.compile_opts[i] = temp

        # Make sure to force enable -fPIC for OBJECT libraries
        if self.type.upper() == 'OBJECT_LIBRARY':
            self.pie = True

        # Use the CMake trace, if required
        tgt = trace.targets.get(self.cmake_name)
        if tgt:
            self.depends_raw = trace.targets[self.cmake_name].depends

            rtgt = resolve_cmake_trace_targets(self.cmake_name, trace, self.env)
            self.includes += [Path(x) for x in rtgt.include_directories]
            self.link_flags += rtgt.link_flags
            self.public_compile_opts += rtgt.public_compile_opts
            self.link_libraries += rtgt.libraries

        elif self.type.upper() not in ['EXECUTABLE', 'OBJECT_LIBRARY']:
            mlog.warning('CMake: Target', mlog.bold(self.cmake_name), 'not found in CMake trace. This can lead to build errors')

        temp = []
        for i in self.link_libraries:
            # Let meson handle this arcane magic
            if ',-rpath,' in i:
                continue
            if not Path(i).is_absolute():
                link_with = output_target_map.artifact(i)
                if link_with:
                    self.link_with += [link_with]
                    continue

            temp += [i]
        self.link_libraries = temp

        # Filter out files that are not supported by the language
        supported = list(assembler_suffixes) + list(header_suffixes) + list(obj_suffixes)
        for i in self.languages:
            supported += list(lang_suffixes[i])
        supported = [f'.{x}' for x in supported]
        self.sources = [x for x in self.sources if any(x.name.endswith(y) for y in supported)]
        # Don't filter unsupported files from generated_raw because they
        # can be GENERATED dependencies for other targets.
        # See: https://github.com/mesonbuild/meson/issues/11607
        # However, the dummy CMake rule files for Visual Studio still
        # need to be filtered out. They don't exist (because the project was
        # not generated at this time) but the fileapi will still
        # report them on Windows.
        # See: https://stackoverflow.com/a/41816323
        self.generated_raw = [x for x in self.generated_raw if not x.name.endswith('.rule')]

        # Make paths relative
        def rel_path(x: Path, is_header: bool, is_generated: bool) -> T.Optional[Path]:
            if not x.is_absolute():
                x = self.src_dir / x
            x = x.resolve()
            assert x.is_absolute()
            if not x.exists() and not any(x.name.endswith(y) for y in obj_suffixes) and not is_generated:
                if path_is_in_root(x, Path(self.env.get_build_dir()), resolve=True):
                    x.mkdir(parents=True, exist_ok=True)
                    return x.relative_to(Path(self.env.get_build_dir()) / subdir)
                else:
                    mlog.warning('CMake: path', mlog.bold(x.as_posix()), 'does not exist.')
                    mlog.warning(' --> Ignoring. This can lead to build errors.')
                    return None
            if x in trace.explicit_headers:
                return None
            if (
                    path_is_in_root(x, Path(self.env.get_source_dir()))
                    and not (
                        path_is_in_root(x, root_src_dir) or
                        path_is_in_root(x, Path(self.env.get_build_dir()))
                    )
                    ):
                mlog.warning('CMake: path', mlog.bold(x.as_posix()), 'is inside the root project but', mlog.bold('not'), 'inside the subproject.')
                mlog.warning(' --> Ignoring. This can lead to build errors.')
                return None
            if path_is_in_root(x, Path(self.env.get_build_dir())) and is_header:
                return x.relative_to(Path(self.env.get_build_dir()) / subdir)
            if path_is_in_root(x, root_src_dir):
                return x.relative_to(root_src_dir)
            return x

        build_dir_rel = self.build_dir.relative_to(Path(self.env.get_build_dir()) / subdir)
        self.generated_raw = [rel_path(x, False, True) for x in self.generated_raw]
        self.includes = list(OrderedSet([rel_path(x, True, False) for x in OrderedSet(self.includes)] + [build_dir_rel]))
        self.sys_includes = list(OrderedSet([rel_path(x, True, False) for x in OrderedSet(self.sys_includes)]))
        self.sources = [rel_path(x, False, False) for x in self.sources]

        # Resolve custom targets
        for gen_file in self.generated_raw:
            ctgt = output_target_map.generated(gen_file)
            if ctgt:
                assert isinstance(ctgt, ConverterCustomTarget)
                ref = ctgt.get_ref(gen_file)
                assert isinstance(ref, CustomTargetReference) and ref.valid()
                self.generated_ctgt += [ref]
            elif gen_file is not None:
                self.generated += [gen_file]

        # Remove delete entries
        self.includes = [x for x in self.includes if x is not None]
        self.sys_includes = [x for x in self.sys_includes if x is not None]
        self.sources = [x for x in self.sources if x is not None]

        # Make sure '.' is always in the include directories
        if Path('.') not in self.includes:
            self.includes += [Path('.')]

        # make install dir relative to the install prefix
        if self.install_dir and self.install_dir.is_absolute():
            if path_is_in_root(self.install_dir, install_prefix):
                self.install_dir = self.install_dir.relative_to(install_prefix)

        # Remove blacklisted options and libs
        def check_flag(flag: str) -> bool:
            if flag.lower() in blacklist_link_flags or flag in blacklist_compiler_flags + blacklist_clang_cl_link_flags:
                return False
            if flag.startswith('/D'):
                return False
            return True

        self.link_libraries = [x for x in self.link_libraries if x.lower() not in blacklist_link_libs]
        self.link_flags = [x for x in self.link_flags if check_flag(x)]

        # Handle OSX frameworks
        def handle_frameworks(flags: T.List[str]) -> T.List[str]:
            res: T.List[str] = []
            for i in flags:
                p = Path(i)
                if not p.exists() or not p.name.endswith('.framework'):
                    res += [i]
                    continue
                res += ['-framework', p.stem]
            return res

        self.link_libraries = handle_frameworks(self.link_libraries)
        self.link_flags = handle_frameworks(self.link_flags)

        # Handle explicit CMake add_dependency() calls
        for i in self.depends_raw:
            dep_tgt = output_target_map.target(i)
            if dep_tgt:
                self.depends.append(dep_tgt)

    def process_object_libs(self, obj_target_list: T.List['ConverterTarget'], linker_workaround: bool) -> None:
        # Try to detect the object library(s) from the generated input sources
        temp = [x for x in self.generated if any(x.name.endswith('.' + y) for y in obj_suffixes)]
        stem = [x.stem for x in temp]
        exts = self._all_source_suffixes()
        # Temp now stores the source filenames of the object files
        for i in obj_target_list:
            source_files = [x.name for x in i.sources + i.generated]
            for j in stem:
                # On some platforms (specifically looking at you Windows with vs20xy backend) CMake does
                # not produce object files with the format `foo.cpp.obj`, instead it skipps the language
                # suffix and just produces object files like `foo.obj`. Thus we have to do our best to
                # undo this step and guess the correct language suffix of the object file. This is done
                # by trying all language suffixes meson knows and checking if one of them fits.
                candidates = [j]
                if not any(j.endswith('.' + x) for x in exts):
                    mlog.warning('Object files do not contain source file extensions, thus falling back to guessing them.', once=True)
                    candidates += [f'{j}.{x}' for x in exts]
                if any(x in source_files for x in candidates):
                    if linker_workaround:
                        self._append_objlib_sources(i)
                    else:
                        self.includes += i.includes
                        self.includes = list(OrderedSet(self.includes))
                        self.object_libs += [i]
                    break

        # Filter out object files from the sources
        self.generated = [x for x in self.generated if not any(x.name.endswith('.' + y) for y in obj_suffixes)]

    def _append_objlib_sources(self, tgt: 'ConverterTarget') -> None:
        self.includes += tgt.includes
        self.sources += tgt.sources
        self.generated += tgt.generated
        self.generated_ctgt += tgt.generated_ctgt
        self.includes = list(OrderedSet(self.includes))
        self.sources = list(OrderedSet(self.sources))
        self.generated = list(OrderedSet(self.generated))
        self.generated_ctgt = list(OrderedSet(self.generated_ctgt))

        # Inherit compiler arguments since they may be required for building
        for lang, opts in tgt.compile_opts.items():
            if lang not in self.compile_opts:
                self.compile_opts[lang] = []
            self.compile_opts[lang] += [x for x in opts if x not in self.compile_opts[lang]]

    @lru_cache(maxsize=None)
    def _all_source_suffixes(self) -> 'ImmutableListProtocol[str]':
        suffixes: T.List[str] = []
        for exts in lang_suffixes.values():
            suffixes.extend(exts)
        return suffixes

    @lru_cache(maxsize=None)
    def _all_lang_stds(self, lang: str) -> 'ImmutableListProtocol[str]':
        try:
            res = self.env.coredata.options[OptionKey('std', machine=MachineChoice.BUILD, lang=lang)].choices
        except KeyError:
            return []

        # TODO: Get rid of this once we have proper typing for options
        assert isinstance(res, list)
        for i in res:
            assert isinstance(i, str)

        return res

    def process_inter_target_dependencies(self) -> None:
        # Move the dependencies from all transfer_dependencies_from to the target
        to_process = list(self.depends)
        processed = []
        new_deps = []
        for i in to_process:
            processed += [i]
            if isinstance(i, ConverterTarget) and i.meson_func() in transfer_dependencies_from:
                to_process += [x for x in i.depends if x not in processed]
            else:
                new_deps += [i]
        self.depends = list(OrderedSet(new_deps))

    def cleanup_dependencies(self) -> None:
        # Clear the dependencies from targets that where moved from
        if self.meson_func() in transfer_dependencies_from:
            self.depends = []

    def meson_func(self) -> str:
        return target_type_map.get(self.type.upper())

    def log(self) -> None:
        mlog.log('Target', mlog.bold(self.name), f'({self.cmake_name})')
        mlog.log('  -- artifacts:      ', mlog.bold(str(self.artifacts)))
        mlog.log('  -- full_name:      ', mlog.bold(self.full_name))
        mlog.log('  -- type:           ', mlog.bold(self.type))
        mlog.log('  -- install:        ', mlog.bold('true' if self.install else 'false'))
        mlog.log('  -- install_dir:    ', mlog.bold(self.install_dir.as_posix() if self.install_dir else ''))
        mlog.log('  -- link_libraries: ', mlog.bold(str(self.link_libraries)))
        mlog.log('  -- link_with:      ', mlog.bold(str(self.link_with)))
        mlog.log('  -- object_libs:    ', mlog.bold(str(self.object_libs)))
        mlog.log('  -- link_flags:     ', mlog.bold(str(self.link_flags)))
        mlog.log('  -- languages:      ', mlog.bold(str(self.languages)))
        mlog.log('  -- includes:       ', mlog.bold(str(self.includes)))
        mlog.log('  -- sys_includes:   ', mlog.bold(str(self.sys_includes)))
        mlog.log('  -- sources:        ', mlog.bold(str(self.sources)))
        mlog.log('  -- generated:      ', mlog.bold(str(self.generated)))
        mlog.log('  -- generated_ctgt: ', mlog.bold(str(self.generated_ctgt)))
        mlog.log('  -- pie:            ', mlog.bold('true' if self.pie else 'false'))
        mlog.log('  -- override_opts:  ', mlog.bold(str(self.override_options)))
        mlog.log('  -- depends:        ', mlog.bold(str(self.depends)))
        mlog.log('  -- options:')
        for key, val in self.compile_opts.items():
            mlog.log('    -', key, '=', mlog.bold(str(val)))

class CustomTargetReference:
    def __init__(self, ctgt: 'ConverterCustomTarget', index: int) -> None:
        self.ctgt = ctgt
        self.index = index

    def __repr__(self) -> str:
        if self.valid():
            return '<{}: {} [{}]>'.format(self.__class__.__name__, self.ctgt.name, self.ctgt.outputs[self.index])
        else:
            return f'<{self.__class__.__name__}: INVALID REFERENCE>'

    def valid(self) -> bool:
        return self.ctgt is not None and self.index >= 0

    def filename(self) -> str:
        return self.ctgt.outputs[self.index]

class ConverterCustomTarget:
    tgt_counter = 0
    out_counter = 0

    def __init__(self, target: CMakeGeneratorTarget, env: 'Environment', for_machine: MachineChoice) -> None:
        assert target.current_bin_dir is not None
        assert target.current_src_dir is not None
        self.name = target.name
        if not self.name:
            self.name = f'custom_tgt_{ConverterCustomTarget.tgt_counter}'
            ConverterCustomTarget.tgt_counter += 1
        self.cmake_name = str(self.name)
        self.original_outputs = list(target.outputs)
        self.outputs = [x.name for x in self.original_outputs]
        self.conflict_map: T.Dict[str, str] = {}
        self.command: T.List[T.List[T.Union[str, ConverterTarget]]] = []
        self.working_dir = target.working_dir
        self.depends_raw = target.depends
        self.inputs: T.List[T.Union[str, CustomTargetReference]] = []
        self.depends: T.List[T.Union[ConverterTarget, ConverterCustomTarget]] = []
        self.current_bin_dir = target.current_bin_dir
        self.current_src_dir = target.current_src_dir
        self.env = env
        self.for_machine = for_machine
        self._raw_target = target

        # Convert the target name to a valid meson target name
        self.name = _sanitize_cmake_name(self.name)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.name} {self.outputs}>'

    def postprocess(self, output_target_map: OutputTargetMap, root_src_dir: Path, all_outputs: T.List[str], trace: CMakeTraceParser) -> None:
        # Default the working directory to ${CMAKE_CURRENT_BINARY_DIR}
        if self.working_dir is None:
            self.working_dir = self.current_bin_dir

        # relative paths in the working directory are always relative
        # to ${CMAKE_CURRENT_BINARY_DIR}
        if not self.working_dir.is_absolute():
            self.working_dir = self.current_bin_dir / self.working_dir

        # Modify the original outputs if they are relative. Again,
        # relative paths are relative to ${CMAKE_CURRENT_BINARY_DIR}
        def ensure_absolute(x: Path) -> Path:
            if x.is_absolute():
                return x
            else:
                return self.current_bin_dir / x
        self.original_outputs = [ensure_absolute(x) for x in self.original_outputs]

        # Ensure that there is no duplicate output in the project so
        # that meson can handle cases where the same filename is
        # generated in multiple directories
        temp_outputs: T.List[str] = []
        for i in self.outputs:
            if i in all_outputs:
                old = str(i)
                i = f'c{ConverterCustomTarget.out_counter}_{i}'
                ConverterCustomTarget.out_counter += 1
                self.conflict_map[old] = i
            all_outputs += [i]
            temp_outputs += [i]
        self.outputs = temp_outputs

        # Check if the command is a build target
        commands: T.List[T.List[T.Union[str, ConverterTarget]]] = []
        for curr_cmd in self._raw_target.command:
            assert isinstance(curr_cmd, list)
            assert curr_cmd[0] != '', "An empty string is not a valid executable"
            cmd: T.List[T.Union[str, ConverterTarget]] = []

            for j in curr_cmd:
                if not j:
                    continue
                target = output_target_map.executable(j)
                if target:
                    # When cross compiling, binaries have to be executed with an exe_wrapper (for instance wine for mingw-w64)
                    if self.env.exe_wrapper is not None and self.env.properties[self.for_machine].get_cmake_use_exe_wrapper():
                        assert isinstance(self.env.exe_wrapper, ExternalProgram)
                        cmd += self.env.exe_wrapper.get_command()
                    cmd += [target]
                    continue
                elif j in trace.targets:
                    trace_tgt = trace.targets[j]
                    if trace_tgt.type == 'EXECUTABLE' and 'IMPORTED_LOCATION' in trace_tgt.properties:
                        cmd += trace_tgt.properties['IMPORTED_LOCATION']
                        continue
                    mlog.debug(f'CMake: Found invalid CMake target "{j}" --> ignoring \n{trace_tgt}')

                # Fallthrough on error
                cmd += [j]

            commands += [cmd]
        self.command = commands

        # If the custom target does not declare any output, create a dummy
        # one that can be used as dependency.
        if not self.outputs:
            self.outputs = [self.name + '.h']

        # Check dependencies and input files
        for i in self.depends_raw:
            if not i:
                continue
            raw = Path(i)
            art = output_target_map.artifact(i)
            tgt = output_target_map.target(i)
            gen = output_target_map.generated(raw)

            rel_to_root = None
            try:
                rel_to_root = raw.relative_to(root_src_dir)
            except ValueError:
                rel_to_root = None

            # First check for existing files. Only then check for existing
            # targets, etc. This reduces the chance of misdetecting input files
            # as outputs from other targets.
            # See https://github.com/mesonbuild/meson/issues/6632
            if not raw.is_absolute() and (self.current_src_dir / raw).is_file():
                self.inputs += [(self.current_src_dir / raw).relative_to(root_src_dir).as_posix()]
            elif raw.is_absolute() and raw.exists() and rel_to_root is not None:
                self.inputs += [rel_to_root.as_posix()]
            elif art:
                self.depends += [art]
            elif tgt:
                self.depends += [tgt]
            elif gen:
                ctgt_ref = gen.get_ref(raw)
                assert ctgt_ref is not None
                self.inputs += [ctgt_ref]

    def process_inter_target_dependencies(self) -> None:
        # Move the dependencies from all transfer_dependencies_from to the target
        to_process = list(self.depends)
        processed = []
        new_deps = []
        for i in to_process:
            processed += [i]
            if isinstance(i, ConverterTarget) and i.meson_func() in transfer_dependencies_from:
                to_process += [x for x in i.depends if x not in processed]
            else:
                new_deps += [i]
        self.depends = list(OrderedSet(new_deps))

    def get_ref(self, fname: Path) -> T.Optional[CustomTargetReference]:
        name = fname.name
        try:
            if name in self.conflict_map:
                name = self.conflict_map[name]
            idx = self.outputs.index(name)
            return CustomTargetReference(self, idx)
        except ValueError:
            return None

    def log(self) -> None:
        mlog.log('Custom Target', mlog.bold(self.name), f'({self.cmake_name})')
        mlog.log('  -- command:      ', mlog.bold(str(self.command)))
        mlog.log('  -- outputs:      ', mlog.bold(str(self.outputs)))
        mlog.log('  -- conflict_map: ', 
"""


```