Response:
The user wants a summary of the Python code provided, specifically focusing on its functionality within the context of the Frida dynamic instrumentation tool. I need to identify the core responsibilities of this `interpreter.py` file and highlight aspects relevant to reverse engineering, binary/kernel interactions, logical reasoning, common user errors, and debugging.

Here's a breakdown of the thought process:

1. **Identify the Purpose:** The file is located within the Frida project's CMake build system (`frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/interpreter.py`). The name "interpreter" strongly suggests its role is to process and translate CMake build instructions into a format understandable by the Meson build system, which Frida uses.

2. **Core Functionality - CMake Interpretation:** The primary function is to parse CMake files and extract information about build targets (libraries, executables, custom commands), dependencies, compiler flags, linker settings, and other build-related configurations. It acts as a bridge between CMake's declarative build language and Meson's.

3. **Reverse Engineering Relevance:**
    * **Target Information:** Extracting target names, types (static/shared libraries, executables), and dependencies is crucial for understanding the structure of the software being analyzed or instrumented. This helps in identifying entry points, important libraries, and relationships between components.
    * **Build Settings:**  Compiler and linker flags can reveal optimization levels, debugging symbols, and other settings that impact how the binary behaves and how easily it can be reversed.
    * **Custom Commands:**  `ConverterCustomTarget` handles arbitrary commands. These can be used for code generation, data processing, or other build steps that are vital to understanding the final binary. Reverse engineers often need to understand these steps to fully grasp the build process.

4. **Binary/Kernel/Framework Relevance:**
    * **Target Types:**  Recognizing shared libraries (`MODULE_LIBRARY`, `SHARED_LIBRARY`) is important as Frida often injects into these. Executables are the entry point of processes.
    * **Linker Libraries:** The `link_libraries` and `link_flags` are directly related to how the final binary is linked and what system libraries it depends on (e.g., `kernel32.lib` on Windows). Understanding these dependencies is critical for analyzing interactions with the operating system.
    * **Compiler Flags:** Flags like `-fPIC` (Position Independent Code) are essential for shared libraries on Linux and influence how memory is managed at runtime.

5. **Logical Reasoning:**
    * **Dependency Resolution:** The code attempts to resolve dependencies between CMake targets and map them to Meson targets. This involves matching target names and output files.
    * **Standard Detection:** The code tries to identify the C/C++ standard being used based on compiler flags. This involves pattern matching and mapping to known standards.
    * **Blacklisting:** The code uses blacklists for compiler and linker flags. This suggests a reasoning process to filter out flags that are not relevant or might interfere with Frida's build process.

6. **User/Programming Errors:**
    * **Incorrect CMake:**  If the CMake files are malformed or contain errors, the interpreter might fail to parse them correctly, leading to build failures.
    * **Missing Dependencies:**  If a CMake project relies on external libraries or targets that are not properly defined or found, the interpreter might not be able to resolve the dependencies.
    * **Conflicting Output Names:** The code handles potential conflicts in output filenames from custom targets, suggesting this is a possible user error scenario.

7. **Debugging Clues:**
    * **Logging:** The code uses `mlog` for logging, indicating points where information is being outputted. This can be valuable for debugging the interpretation process.
    * **Error Handling:** The presence of `CMakeException` suggests that the interpreter handles errors during CMake parsing.
    * **Tracing:** The interaction with `CMakeTraceParser` implies that the tool can use CMake's tracing functionality for more detailed information, which would be useful for debugging complex build scenarios.

8. **Step-by-Step User Action:** To reach this code, a user would typically:
    * Be working with a project (like Frida) that uses CMake as part of its build process.
    * Be using Meson as the primary build system.
    * Meson's CMake integration would be invoked when processing the Frida project, leading to the execution of this `interpreter.py` file to parse the CMake build definitions.

9. **Overall Function Summary:**  The file acts as a translator, converting CMake project definitions into a format suitable for Meson. It extracts crucial build information, handles dependencies, and adapts CMake concepts to Meson's framework. This is a critical step in building projects that use CMake as a subproject within a larger Meson-based build system.

By following this thought process, I can systematically analyze the code and extract the requested information, focusing on the key functionalities and their relevance to the specified domains.
This Python code file, `interpreter.py`, is a crucial component of Frida's build system. It acts as a **CMake interpreter** within the Meson build environment. Its primary function is to **parse and understand CMake build definitions** and **translate them into a format that Meson can understand and use to build the Frida components**.

Here's a breakdown of its key functionalities:

**Core Functionality: CMake Interpretation and Translation**

1. **Parsing CMake Data:** This script reads and interprets the output of CMake's File API. This API provides structured information about the CMake project, including targets (libraries, executables), source files, dependencies, compiler flags, linker settings, and custom commands.

2. **Representing CMake Targets:** It defines Python classes like `ConverterTarget` and `ConverterCustomTarget` to represent the different types of targets defined in the CMake project. These classes store the extracted information in a structured way.

3. **Mapping CMake Concepts to Meson:** The script translates CMake-specific concepts (like target types, dependencies, and flags) into their Meson equivalents. For example, it maps CMake target types like `STATIC_LIBRARY` to Meson's `static_library`.

4. **Handling Dependencies:** It identifies and manages dependencies between CMake targets, ensuring that targets are built in the correct order. This includes both regular library dependencies and dependencies on custom commands.

5. **Processing Compiler and Linker Flags:** It extracts compiler and linker flags from the CMake data, filtering out irrelevant or problematic flags (e.g., excessive warnings, debugging flags) using blacklists.

6. **Managing Include Directories:** It extracts and manages include directories required for compiling the source code.

7. **Handling Custom Commands:** It processes custom commands defined in the CMake project, representing them as `ConverterCustomTarget` objects.

8. **Generating Meson-compatible Data:** The extracted and translated information is then used by Meson to generate the actual build instructions.

**Relevance to Reverse Engineering (with examples):**

* **Understanding Project Structure:** By parsing CMake's target definitions, this script reveals the organization of the Frida codebase. You can see which libraries and executables are being built and their relationships. For example, if you are trying to understand how Frida's Swift bridge is built, this script would show you the targets related to `frida-swift` and their dependencies on other Frida components.

* **Identifying Key Libraries and Executables:**  The `ConverterTarget` objects represent the different binaries being built. Reverse engineers can use this information to pinpoint the core libraries and executables they need to focus on for analysis. For instance, you might see targets for the Frida server or specific instrumentation libraries.

* **Analyzing Build Settings:** The extracted compiler and linker flags provide insights into how the binaries are being compiled. This can reveal optimization levels (impacting performance and potentially obfuscation), debugging symbols (making reverse engineering easier), and security features. For example, you might see flags related to ASLR or stack canaries.

* **Understanding Custom Build Steps:** `ConverterCustomTarget` objects represent custom commands. Reverse engineers can analyze these to understand any code generation or pre-processing steps that might be happening before the main compilation. This could involve generating Swift interface files from C headers, for example.

**Relevance to Binary Bottom, Linux, Android Kernel & Framework (with examples):**

* **Target Types:** The script identifies different target types like `SHARED_LIBRARY` (common on Linux and Android) and `EXECUTABLE`. This indicates which parts of Frida are loaded dynamically versus run as standalone processes.

* **Linker Libraries:** The `link_libraries` information shows the system libraries and other external dependencies required by the Frida components. On Linux and Android, this might include libraries like `libc`, `libdl`, or Android-specific framework libraries.

* **Compiler Flags:** Flags like `-fPIC` are crucial for building shared libraries on Linux and Android, enabling them to be loaded at arbitrary memory addresses. The script handles these flags.

* **Understanding Build Paths:** The script deals with file paths within the build system. This is relevant to understanding where intermediate and final binaries are located on Linux and Android systems.

**Logical Reasoning (with examples):**

* **Dependency Resolution:** The script makes decisions about how to link targets based on the dependencies defined in CMake. For example, if a CMake target `A` depends on target `B`, the script will ensure that `B` is built before `A` and that the necessary linking information is passed.
    * **Hypothetical Input:** CMake defines target `frida-agent` that depends on `frida-core`.
    * **Output:** The script will create a `ConverterTarget` for `frida-agent` with a dependency on the `ConverterTarget` for `frida-core`. Meson will then build `frida-core` before `frida-agent`.

* **Filtering Flags:** The script uses blacklists to filter out certain compiler and linker flags. This involves a logical decision to ignore flags that are deemed irrelevant or potentially problematic for the Meson build.
    * **Hypothetical Input:** CMake defines compiler flags including `-Wall` and `-Werror`.
    * **Output:** The script will likely filter out `-Wall` and `-Werror` because these are general warning flags that Meson might handle differently or that could cause issues in the Meson build environment.

* **Mapping Target Types:** The `target_type_map` demonstrates a logical mapping from CMake target type strings to Meson's target type strings.

**User or Programming Common Usage Errors (with examples):**

* **Incorrect CMake Configuration:** If the CMake files have syntax errors or illogical dependencies, this script might fail to parse them correctly, leading to build errors. Meson would then report errors originating from this script or the CMake parsing process.

* **Missing Dependencies:** If the CMake project depends on external libraries that are not available in the build environment, the script might not be able to resolve these dependencies, resulting in linking errors during the Meson build.

* **Conflicting Output Names in Custom Commands:** The script includes logic to handle potential conflicts in output filenames generated by custom commands (`ConverterCustomTarget`). If two custom commands try to generate files with the same name, this could cause issues. The script attempts to resolve this by renaming outputs.

**User Operation to Reach This Code (Debugging Clues):**

A user would typically not interact with this file directly. However, if a build error occurs during the Meson build of Frida, and the error messages point to issues related to CMake integration, a developer might investigate this file.

Here's a typical scenario:

1. **User tries to build Frida:** The user executes a Meson build command (e.g., `meson setup build`, `ninja -C build`).
2. **Meson encounters a CMake subproject:** During the build process, Meson detects that Frida uses CMake for some of its components (like the Swift bridge).
3. **Meson invokes the CMake interpreter:** Meson executes the `interpreter.py` script to parse the CMake project information.
4. **Error occurs in CMake parsing/translation:** If there's an issue in the CMake files or in the translation logic within `interpreter.py`, an error might occur.
5. **Error messages point to this script:** The error messages from Meson or Ninja might include stack traces or mentions of files within the `mesonbuild/cmake` directory, leading a developer to investigate `interpreter.py`.
6. **Debugging steps:** A developer might then examine the CMake files, the `interpreter.py` code, and the Meson build logs to understand the root cause of the error. They might add logging statements within `interpreter.py` to see how the CMake data is being parsed and translated.

**Summary of Functionality (for Part 1):**

The `interpreter.py` file is the **bridge between CMake and Meson** in the Frida build system. It **parses CMake project definitions**, **extracts relevant build information**, **translates CMake concepts into Meson equivalents**, and **manages dependencies**. This allows Meson to understand and build the CMake-based components of Frida. It plays a crucial role in ensuring a successful and consistent build process.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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