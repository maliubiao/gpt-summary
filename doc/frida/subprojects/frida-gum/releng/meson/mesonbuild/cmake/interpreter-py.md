Response:
The user wants a summary of the functionality of the Python code provided. I need to go through the code and identify its main responsibilities and how it achieves them. The request also asks for specific connections to reverse engineering, low-level details, logical reasoning, common user errors, and debugging scenarios.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file `interpreter.py` within the `frida-gum` project suggests it's responsible for interpreting or processing some form of input. The presence of "CMake" in the file path and imports like `CMakeFileAPI`, `CMakeExecutor`, and `CMakeToolchain` strongly indicate that this code handles CMake project information. It seems to be converting CMake project definitions into a format understandable by the Meson build system.

2. **Break Down Functionality by Class/Major Sections:**

    * **`OutputTargetMap`:** This class manages a mapping of CMake target names and output artifacts to Meson's internal representation of targets. It acts as a lookup table to find the Meson equivalent of a given CMake target or output.

    * **`ConverterTarget`:** This class is central to the conversion process. It takes a `CMakeTarget` object (representing a CMake target like a library or executable) and transforms it into a structure suitable for Meson. This involves extracting information like sources, includes, link libraries, compiler flags, etc., and converting them to Meson's conventions.

    * **`CustomTargetReference`:** This is a simple helper class used to represent a reference to an output of a custom target.

    * **`ConverterCustomTarget`:**  This class handles CMake custom commands or targets. It parses the commands, inputs, and outputs of these custom actions and translates them into Meson's `custom_target` construct.

3. **Identify Key Actions within Each Class:**

    * **`OutputTargetMap`:** Adding targets, looking up targets by various keys (name, artifact), handling shared library versioning in lookups.

    * **`ConverterTarget`:**  Initialization with CMake target data, parsing source files and languages, handling include directories, processing compiler and linker flags, resolving dependencies (including those specified in CMake trace files), handling object libraries, making paths relative, managing install directories. A key aspect is the `postprocess` method which does much of the detailed conversion and cleanup.

    * **`ConverterCustomTarget`:** Initialization with custom target data, parsing commands, handling working directories, managing outputs (including conflict resolution), identifying inputs and dependencies. The `postprocess` method here also handles crucial steps.

4. **Connect to Specific Requirements of the Prompt:**

    * **Reverse Engineering:** The entire process is inherently related to reverse engineering. The code is taking the output of the CMake build system's introspection (via the File API and optionally a trace) and trying to understand the build structure. This is a form of reverse engineering the build process itself. *Example:* Analyzing the `link_libraries` to understand the dependencies between components.

    * **Binary/Low-Level:** The code deals with compiler and linker flags (`compile_opts`, `link_flags`), which directly influence the generation of binary code. It also handles different types of libraries (`static_library`, `shared_library`, `object_library`). *Example:* The handling of `-fPIC` for position-independent code, which is essential for shared libraries.

    * **Linux/Android Kernel/Framework:** While the code itself isn't directly interacting with the kernel, it's processing information *about* software that might interact with the kernel or frameworks. The handling of shared libraries and executables is fundamental to these environments.

    * **Logical Reasoning:** The code makes decisions based on the properties of CMake targets. For instance, the logic in `process_object_libs` attempts to identify object libraries based on their output filenames and source files. *Example:* If a generated file has an `.obj` extension, it's likely an object file.

    * **User/Programming Errors:** The code includes warnings for unknown language standards or missing CMake trace information, suggesting potential user configuration errors. The output conflict resolution in `ConverterCustomTarget` addresses a common scenario where users might inadvertently generate files with the same name in different custom commands.

    * **Debugging:** The code logs information about the converted targets, which can be valuable for debugging issues during the conversion process. The tracing of CMake dependencies is another debugging aid. The warning messages also act as debugging hints.

    * **User Operation Flow:**  A user would typically interact with this code indirectly by using a build system (like Meson) that uses this `interpreter.py` to process a CMake-based subproject. The steps would involve configuring Meson, which then triggers the CMake introspection and the execution of this Python code to translate the CMake project.

5. **Structure the Summary:** Organize the identified functionalities into logical groups, reflecting the main classes and their roles. Ensure to address each point from the prompt with specific examples.

6. **Review and Refine:** Read through the summary to ensure accuracy, clarity, and completeness. Check that all parts of the prompt have been addressed adequately. For instance, initially, I might forget to explicitly mention the handling of installation paths, so a review helps catch such omissions.

By following these steps, I can construct a comprehensive and accurate summary of the `interpreter.py` file, addressing all the specific points raised in the user's request.
这是 frida 动态插桩工具中负责解析 CMake 构建系统信息的 Python 模块。它的主要功能是将 CMake 项目的元数据（通过 CMake 的 File API 和可选的 trace 功能获取）转换为 frida 构建系统（Meson）能够理解的格式。

以下是它的主要功能归纳：

**核心功能：CMake 项目信息解析与转换**

1. **读取和解析 CMake 元数据:**  该模块利用 `CMakeFileAPI` 和 `CMakeTraceParser` 从 CMake 构建系统中提取目标 (targets)、源文件、包含目录、链接库、编译选项、链接选项、自定义命令等信息。

2. **将 CMake 目标映射到 Meson 概念:** 它将 CMake 中的各种目标类型 (例如 `STATIC_LIBRARY`, `SHARED_LIBRARY`, `EXECUTABLE`, `CUSTOM_COMMAND`) 映射到 Meson 中对应的概念 (例如 `static_library`, `shared_library`, `executable`, `custom_target`)。

3. **处理依赖关系:**  解析 CMake 中声明的依赖关系 (通过 `add_dependencies`) 以及通过 CMake trace 功能获取的更详细的依赖信息，并在 Meson 的目标中正确表示这些依赖关系。

4. **转换编译和链接选项:**  提取 CMake 中设置的编译和链接选项，并将其转换为 Meson 可以理解的格式。它还会过滤掉一些与 Meson 不兼容或由 Meson 自身管理的选项（例如，优化级别、调试信息、某些警告选项）。

5. **处理包含目录:**  提取 CMake 中指定的包含目录，并将其添加到 Meson 目标的包含路径中。

6. **处理链接库:**  解析 CMake 中指定的链接库，并将其转换为 Meson 中的链接依赖。它会尝试识别项目内部的库，并将它们转换为对其他 Meson 目标的依赖。对于外部库，它会直接使用库名称。

7. **处理自定义命令/目标:**  将 CMake 中的 `add_custom_command` 和 `add_custom_target` 转换为 Meson 中的 `custom_target`。它会解析命令、输入和输出文件，以及工作目录等信息。

8. **处理安装信息:**  如果 CMake 目标声明了安装规则，则会提取安装目录等信息，并在 Meson 中表示。

9. **处理生成的文件:**  识别 CMake 构建过程中生成的文件，并将其添加到 Meson 目标的源文件或依赖中。对于通过自定义命令生成的文件，会创建相应的 `custom_target`。

10. **解决命名冲突:**  在转换自定义目标时，如果检测到输出文件名冲突，会进行重命名以避免 Meson 构建系统中的问题。

**与逆向方法的关系举例:**

* **理解目标结构:** 在逆向一个基于 CMake 构建的项目时，理解其目标结构（哪些库依赖于哪些其他库，哪些可执行文件使用了哪些库）至关重要。这个模块的功能就是从 CMake 的描述中提取出这种结构信息，为后续的 frida 插桩提供基础。例如，如果需要对某个共享库进行插桩，就需要知道这个库依赖于哪些其他库，以便在 frida 中正确加载和处理这些依赖。
* **分析编译选项:**  逆向工程师可能需要了解目标编译时使用的特定选项，例如是否开启了符号信息、是否使用了特定的优化级别等。这个模块可以提取这些信息，帮助逆向工程师更好地理解目标二进制文件的特性。
* **理解自定义构建步骤:** CMake 中经常会使用自定义命令来执行特定的构建任务，例如代码生成、资源处理等。这个模块可以解析这些自定义命令，帮助逆向工程师理解构建过程中的非标准步骤，这对于理解最终的二进制文件如何生成可能非常重要。

**涉及到二进制底层，Linux, Android 内核及框架的知识举例:**

* **处理共享库 (SHARED_LIBRARY):**  理解共享库的加载和链接机制是底层知识。该模块需要正确识别 CMake 中定义的共享库，并将其转换为 Meson 中的 `shared_library`，这涉及到理解动态链接的概念和不同平台上的共享库命名约定（例如 Linux 上的 `.so` 文件）。
* **处理可执行文件 (EXECUTABLE):** 类似地，理解可执行文件的生成和加载过程也需要底层知识。该模块需要能够识别 CMake 中的可执行文件，并将其转换为 Meson 中的 `executable`。
* **处理链接选项 (link_flags):** 链接选项直接影响最终生成的可执行文件和库的二进制结构。例如，链接选项可以指定链接器脚本、库的搜索路径等。该模块需要解析这些选项，虽然它会过滤掉一些选项，但理解这些选项的含义对于理解构建过程仍然重要。
* **处理位置无关代码 (PIC/PIE):** 对于共享库和某些可执行文件，需要生成位置无关的代码。该模块会检测 CMake 中是否设置了相关的编译选项 (`-fPIC`, `-fPIE`)，这涉及到操作系统中内存管理和地址空间布局的知识。
* **处理 Android 框架 (可能间接涉及):** 虽然代码本身不直接操作 Android 内核或框架，但如果 frida 需要插桩 Android 平台上的软件，那么被插桩的目标很可能是基于 Android 框架构建的。这个模块需要能够正确解析这些项目的 CMake 构建信息。例如，Android NDK 开发通常使用 CMake。

**逻辑推理举例:**

* **假设输入:**  CMake 元数据中定义了一个名为 `mylib` 的静态库，它包含 `a.c` 和 `b.c` 两个源文件，并且依赖于另一个名为 `utils` 的共享库。
* **输出:**  该模块会创建一个名为 `mylib` 的 Meson 目标，类型为 `static_library`，包含源文件 `a.c` 和 `b.c`（相对于源目录的路径），并且声明了对名为 `utils` 的 Meson 目标的依赖。

* **假设输入:** CMake 元数据中定义了一个自定义命令，用于生成 `config.h` 文件，该命令的输入是 `config.in`，执行的命令是 `process_config.sh config.in config.h`。
* **输出:** 该模块会创建一个名为（例如）`custom_tgt_0` 的 Meson `custom_target`，其命令为 `['process_config.sh', 'config.in', 'config.h']`，输入为 `config.in`（相对于源目录的路径），输出为 `config.h`（相对于构建目录的路径）。

**用户或编程常见的使用错误举例:**

* **CMake 配置错误:** 如果 CMakeLists.txt 文件中存在语法错误或者逻辑错误，导致 CMake 无法正确生成元数据，那么这个模块可能无法正确解析信息，从而导致 Meson 构建失败。例如，如果 `target_link_libraries` 中指定了一个不存在的库。
* **CMake 版本兼容性问题:**  不同版本的 CMake 生成的元数据格式可能存在差异。如果 frida 使用的这个模块没有考虑到某些 CMake 版本的变化，可能会导致解析错误。
* **自定义命令输出未声明:** 如果 CMake 中的自定义命令生成了文件，但没有在 `OUTPUT` 参数中显式声明，那么这个模块可能无法正确识别这些生成的文件，导致依赖关系不完整。
* **路径问题:**  CMake 中使用的路径可以是相对路径或绝对路径。用户在配置 CMake 时可能会出现路径错误，导致这个模块解析路径时出现问题。例如，包含目录或链接库的路径错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试使用 frida 插桩一个基于 CMake 构建的项目。**
2. **frida 的构建系统 (Meson) 需要理解目标项目的构建信息，以便正确地进行插桩。**
3. **如果目标项目使用 CMake，Meson 会调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/cmake.py` 模块来处理 CMake 项目。**
4. **`cmake.py` 模块会利用 CMake 的 File API (通过运行 `cmake -E server`) 来获取项目的元数据信息。**
5. **`cmake.py` 模块可能会选择使用 CMake 的 trace 功能来获取更详细的依赖关系信息 (如果用户启用了相关选项)。**
6. **`cmake.py` 模块会调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py` 这个模块，将从 CMake 获取的元数据转换为 Meson 可以理解的数据结构。**

当用户遇到与 CMake 项目插桩相关的问题时，例如链接错误、找不到头文件等，就可以沿着这个步骤回溯，检查每个环节是否正常工作。例如：

* **检查 CMakeLists.txt 文件是否存在错误。**
* **检查 CMake 是否成功生成了元数据信息。**
* **检查 `interpreter.py` 模块是否正确解析了 CMake 的元数据信息，例如，检查链接库、包含目录是否被正确识别。**
* **如果使用了 CMake trace，检查 trace 信息是否完整和正确。**

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py` 是 frida 集成 CMake 构建系统的关键组件，它负责将 CMake 的项目描述翻译成 Meson 的项目描述，从而使得 frida 能够理解并处理基于 CMake 构建的目标项目。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```