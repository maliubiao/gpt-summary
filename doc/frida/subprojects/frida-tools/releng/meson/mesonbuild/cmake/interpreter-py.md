Response:
The user wants a breakdown of the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The code is specifically located in `frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/interpreter.py`. I need to analyze the code and explain:

1. **General Functionality:** What does this Python file do? What are its main components and their roles?
2. **Relationship to Reverse Engineering:** How does this code, which seems to handle CMake projects, tie into reverse engineering, which is Frida's domain?
3. **Low-Level/Kernel/Framework Interaction:** Does this code interact with the operating system's low-level components, Linux/Android kernels, or frameworks?
4. **Logical Reasoning:** Are there any parts of the code that perform logical deductions or inferences? If so, I need to provide an example with hypothetical input and output.
5. **Common User/Programming Errors:** What mistakes could a user or developer make when using or interacting with this code?
6. **User Path to This Code:** How does a user's action eventually lead to this specific Python file being executed? This requires understanding the overall workflow.
7. **Summary of Functionality:** A concise summary of the file's purpose.

**Plan:**

1. **High-Level Overview:** Start by understanding the role of this file within the broader context of Frida and its interaction with CMake. It likely translates CMake project information into something Meson can understand.
2. **Key Classes Analysis:** Examine the main classes (`ConverterTarget`, `ConverterCustomTarget`, `OutputTargetMap`) and their methods to understand their responsibilities in the translation process.
3. **Reverse Engineering Connection:** Identify how the translation of build systems (like CMake) facilitates Frida's ability to interact with and instrument binaries.
4. **Low-Level Interactions:** Look for clues suggesting interaction with operating system features or kernel concepts, though this file might be more focused on build system translation rather than direct low-level interaction.
5. **Logical Inference:** Analyze code sections where decisions are made based on input data, such as identifying target types or processing compiler flags.
6. **Error Scenarios:** Consider situations where the CMake project is malformed, or where there's a mismatch between the CMake configuration and what Frida expects.
7. **User Workflow:** Think about the steps a user would take to instrument a program built with CMake using Frida. This will trace back to the execution of this file.
8. **Synthesize and Organize:**  Structure the explanation according to the user's prompt, providing examples where requested.
This Python file, located within the Frida project, is responsible for **interpreting CMake project information and converting it into a format that Meson, the build system Frida uses, can understand.**  Essentially, it acts as a bridge between CMake and Meson, allowing Frida tools to work with projects that use CMake as their build system.

Here's a breakdown of its functionalities:

**1. Parsing and Interpreting CMake Project Structure:**

* **Reading CMake's File API:** The code utilizes `CMakeFileAPI` to interact with CMake's file system API. This allows it to query information about the CMake project's structure, targets, dependencies, source files, compiler flags, and more.
* **Extracting Target Information:** It identifies different types of CMake targets (executables, static libraries, shared libraries, etc.) and extracts their relevant properties. The `ConverterTarget` and `ConverterCustomTarget` classes are central to this, representing the Meson-equivalent of CMake targets.
* **Handling Dependencies:** It analyzes the dependencies between CMake targets, both explicit and implicit, and translates them into Meson's dependency model.
* **Processing Compiler and Linker Flags:** The code extracts compiler and linker flags specified in the CMake project and prepares them for use by Meson. It also includes logic to filter out potentially problematic or redundant flags (e.g., `-Wall`, `/W4`).
* **Identifying Source Files and Include Directories:** It determines the source files and include directories associated with each target.

**2. Converting CMake Constructs to Meson Equivalents:**

* **Mapping CMake Target Types:** The `target_type_map` dictionary translates CMake target types (e.g., `STATIC_LIBRARY`) to their corresponding Meson function names (e.g., `static_library`).
* **Creating Meson Target Representations:** The `ConverterTarget` and `ConverterCustomTarget` classes encapsulate the information extracted from CMake targets and transform it into a structure that aligns with Meson's target definition.
* **Handling Custom Commands:** The `ConverterCustomTarget` class specifically deals with CMake's `add_custom_command` and `add_custom_target`, converting them into Meson's `custom_target` construct.
* **Managing Output Paths:** It handles the output paths of generated files and artifacts, potentially resolving conflicts by renaming files if necessary.

**3. Optimization and Filtering:**

* **Blacklisting Compiler/Linker Flags and Libraries:** The code maintains lists of blacklisted compiler flags, linker flags, and libraries that are often redundant or can cause issues in a Meson build. This helps to produce cleaner and more reliable Meson build definitions.
* **Filtering Supported Source Files:** It filters source files based on their extensions to ensure that only files supported by the detected programming languages are included.

**Relationship to Reverse Engineering (with examples):**

This file is crucial for reverse engineering because it allows Frida tools to operate on binaries built using CMake. Here's how:

* **Instrumenting CMake-built Applications:**  Reverse engineers often want to instrument applications built with standard build systems like CMake. This file makes it possible for Frida to understand the structure of such projects, locate the target executable, and inject instrumentation code.
    * **Example:** A reverse engineer wants to use Frida to trace function calls in a closed-source Android application built with CMake. This `interpreter.py` file would be involved in parsing the Android.mk (which can be used with CMake) or CMakeLists.txt, identifying the main executable, and then Frida can attach to that process.
* **Analyzing Libraries and Frameworks:** Many libraries and frameworks are built using CMake. Understanding their build structure allows Frida to hook into specific functions or analyze their internal workings.
    * **Example:** A researcher wants to analyze a specific shared library on Linux that was built with CMake. Frida, through this file, can identify the library's location and dependencies, making it easier to hook functions within that library.
* **Working with Cross-Platform Projects:** CMake is often used for cross-platform development. This file helps Frida to understand how targets are built for different architectures and operating systems, facilitating cross-platform reverse engineering efforts.
    * **Example:** A security analyst is investigating a piece of malware that has components for both Windows and Linux, built using CMake. This file helps Frida to understand the build process for each platform, allowing the analyst to use Frida on both the Windows and Linux binaries.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge (with examples):**

While this specific Python file primarily deals with build system interpretation, it indirectly interacts with lower-level concepts:

* **Binary Artifacts:** The code deals with the output of the build process – executables, shared libraries, static libraries – which are binary files. It needs to know the file extensions associated with these binary types (`.so`, `.dll`, `.exe`, `.a`, `.lib`).
    * **Example:** The code identifies a CMake target as an `EXECUTABLE`. This implies the build process will produce a platform-specific executable binary, which Frida will later interact with at the binary level.
* **Shared Libraries (`.so`, `.dll`):** The handling of `MODULE_LIBRARY` and `SHARED_LIBRARY` targets is directly related to the concept of shared libraries in operating systems. The code needs to understand how these libraries are linked and loaded.
    * **Example:** The code extracts the `link_libraries` for a shared library target. This list contains the names of other libraries that this library depends on at runtime, a fundamental concept in operating system binary loading.
* **Linux/Android Specifics (Indirectly):** While the code itself isn't deeply involved in kernel specifics, it processes build information that is platform-dependent. The compiler and linker flags, and the resulting binary formats, differ between Linux and Android (and other operating systems).
    * **Example:** On Android, shared libraries might have different extensions or naming conventions compared to Linux. This file needs to handle these variations to correctly identify and process the build outputs. Furthermore, the logic to handle `exe_wrapper` for cross-compilation hints at the need to execute binaries built for a different target architecture, common in Android development.
* **Frameworks (Indirectly):** The code handles the linking of frameworks, which are collections of libraries and resources often used in higher-level development on macOS and iOS.
    * **Example:** The code handles OSX frameworks by converting framework paths to `-framework <name>` linker flags. This demonstrates awareness of platform-specific linking mechanisms.

**Logical Reasoning (with hypothetical input/output):**

The code performs logical reasoning when interpreting CMake data. Here's an example:

**Hypothetical Input (Snippet from CMake File API data for a target):**

```json
{
  "name": "mylib",
  "type": "SHARED_LIBRARY",
  "files": [
    {
      "language": "CXX",
      "sources": ["src/mylib.cpp", "include/mylib.h"],
      "flags": ["-O2"],
      "defines": ["DEBUG"]
    }
  ],
  "linkLibraries": ["dependency1", "dependency2.so"]
}
```

**Processing Logic in `interpreter.py`:**

1. The code identifies the `type` as `SHARED_LIBRARY`.
2. It maps `SHARED_LIBRARY` to the Meson function `shared_library`.
3. It extracts the source files: `src/mylib.cpp` and `include/mylib.h`.
4. It identifies the language as `CXX`.
5. It extracts the compiler flags: `-O2` and defines: `DEBUG`.
6. It extracts the link libraries: `dependency1` and `dependency2.so`.
7. It checks if `dependency1` corresponds to another CMake target and `dependency2.so` is a pre-built library.

**Hypothetical Output (Internal representation in `ConverterTarget`):**

```python
ConverterTarget(
    name='mylib',
    cmake_name='mylib',
    type='SHARED_LIBRARY',
    languages={'cpp'},
    sources=[Path('src/mylib.cpp')],
    includes=[Path('include')],  # Assuming 'include' is relative to the source directory
    compile_opts={'cpp': ['-O2', '-DDEBUG']},
    link_libraries=['dependency2.so'],
    link_with=[<ConverterTarget: dependency1>] # Assuming dependency1 is another CMake target
)
```

**Explanation:** The code reasons about the input data to create a structured representation of the CMake target in a way that Meson can understand. It maps CMake concepts to Meson equivalents, separates source files from headers, and identifies dependencies.

**Common User or Programming Usage Errors (with examples):**

Users typically don't interact with this file directly. However, errors in the CMake project definition can lead to issues processed by this file:

* **Missing Dependencies:** If a CMake project specifies a dependency that doesn't exist or isn't properly defined, this file might not be able to resolve it, leading to build errors in Meson.
    * **Example:** A CMakeLists.txt has `target_link_libraries(my_executable non_existent_lib)`, and `non_existent_lib` is not a valid target or library. This file would encounter an issue trying to find `non_existent_lib`.
* **Incorrectly Specified Include Paths:**  If include paths are wrong in the CMake project, the code might not identify the necessary header files.
    * **Example:** `include_directories(../wrong_path)` in CMakeLists.txt. The code would process this incorrect path, potentially leading to compilation errors later.
* **Conflicting Output File Names:** If two custom commands in the CMake project attempt to generate files with the same name in the same output directory, this file will detect the conflict and rename one of the outputs to avoid issues in Meson.
    * **Example:** Two `add_custom_command` calls both try to create `output.txt` in the build directory. The `conflict_map` in `ConverterCustomTarget` handles this.
* **Unsupported CMake Features:** If the CMake project uses features that this interpreter doesn't fully understand or support, it might lead to incorrect translations or build failures.
    * **Example:** A very complex or highly customized CMake function might not have a direct Meson equivalent that this code knows how to generate.

**User Operation Steps to Reach This Code (as a debugging clue):**

A user would typically indirectly trigger the execution of this file by trying to build or interact with a CMake-based project using Frida tools that leverage Meson for the build process. Here's a possible sequence:

1. **User has a target application/library built with CMake.** This is the starting point.
2. **User uses a Frida tool that needs to understand the build structure.** This could be a tool that prepares the target for instrumentation, analyzes its dependencies, or needs to rebuild parts of the project.
3. **The Frida tool, internally, uses Meson to manage the build process.** This is a key assumption for this specific file to be involved.
4. **Meson, when encountering a CMake subproject or when explicitly instructed to handle a CMake project, calls the CMake interpreter.** This happens during Meson's configuration or dependency resolution phase.
5. **This `interpreter.py` file is executed to parse the CMake project information.** Meson provides the necessary paths and configuration to this script.
6. **The script reads the CMake project using the File API and builds an internal representation of the targets and dependencies.**
7. **Meson then uses this information to generate its own build files and proceed with the build process or instrumentation.**

**Summary of Functionality:**

In essence, `interpreter.py` acts as a **CMake-to-Meson translator** within the Frida build system. It takes information about a CMake project, parses its structure and build rules, and converts it into a format that Meson can understand and use for building, analyzing, or instrumenting the target. This enables Frida tools to seamlessly work with projects that use CMake as their native build system.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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