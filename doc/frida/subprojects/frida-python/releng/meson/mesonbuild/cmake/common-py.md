Response:
Let's break down the request and the Python code to construct a comprehensive answer.

**1. Understanding the Goal:**

The request asks for an analysis of the `common.py` file within the Frida project. The focus is on understanding its functionality, relating it to reverse engineering, exploring its connections to low-level concepts, identifying logical reasoning, highlighting potential user errors, and tracing how a user might end up interacting with this code.

**2. Initial Code Review - Identifying Key Areas:**

My first pass at the code reveals several important sections:

* **Language and Backend Mappings:**  `language_map` and `backend_generator_map` translate Meson's language and backend names to CMake's conventions.
* **Blacklisted CMake Definitions:** `blacklist_cmake_defs` prevents users from directly setting certain CMake variables, likely due to conflicts or better ways Meson handles these settings.
* **Debug Determination:** The `cmake_is_debug` function figures out if a debug build is requested, considering different Meson settings.
* **CMake Data Structures:**  Classes like `CMakeBuildFile`, `CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, and `CMakeConfiguration` represent the structure of a CMake project. This suggests the file's purpose is to *parse and represent* CMake project information.
* **Argument Conversion:** Functions like `cmake_get_generator_args` and `cmake_defines_to_args` convert Meson's internal representations into CMake command-line arguments.
* **String-to-List Conversion:** The `_flags_to_list` function parses command-line flag strings into lists.
* **Target-Specific Options:** The `SingleTargetOptions` and `TargetOptions` classes allow for customizing build settings (compile flags, link flags, install status) for individual CMake targets.

**3. Connecting to Reverse Engineering:**

The prompt specifically asks about the relationship to reverse engineering. Frida is a dynamic instrumentation toolkit, heavily used in reverse engineering. The presence of CMake integration suggests that Frida might need to interact with projects that use CMake for their build system. This interaction could be for:

* **Building Frida itself:**  Frida might use CMake as part of its own build process.
* **Interacting with target applications:**  Frida might need to understand the build structure of the application being instrumented, especially if it involves native components built with CMake.

**4. Exploring Low-Level Concepts:**

The code touches upon several low-level concepts:

* **Binary Compilation:** The functions dealing with flags, defines, and link libraries directly relate to the compilation and linking stages of creating binary executables.
* **Operating Systems (Linux/Android):** While not explicitly manipulating kernel code, the interaction with build systems and the resulting binaries is fundamental to how software runs on these platforms. The mention of cross-compilation hints at supporting building for different architectures (like those used in Android).
* **Build Systems (CMake):** The entire file is about interacting with CMake, a build system generator. Understanding how build systems work is crucial for controlling the compilation process.
* **Debugging:** The `cmake_is_debug` function directly relates to configuring debug builds.

**5. Identifying Logical Reasoning:**

The code contains logical reasoning, particularly in:

* **`cmake_is_debug`:**  It makes decisions based on the values of different Meson options (`b_vscrt`, `buildtype`, `debug`). The logic handles different scenarios for determining if a debug build is requested.
* **`cmake_defines_to_args` and `check_cmake_args`:** These functions filter out blacklisted CMake definitions, implying a reasoned decision to prevent users from setting them directly.
* **The `TargetOptions` classes:** These classes implement a hierarchy of options, allowing for global defaults and target-specific overrides.

**6. Spotting Potential User Errors:**

The blacklisting of CMake definitions directly points to potential user errors. Users might try to set these variables directly, which Meson prevents.

**7. Tracing User Interaction (Debugging Clues):**

To understand how a user might reach this code, consider the following scenarios when using Frida and its Python bindings:

* **Building Frida from source:** If a user is building Frida from source, and Frida uses CMake for some of its components (or for building extensions/plugins), the Meson build system would internally use this `common.py` file to translate Meson's build instructions into CMake commands.
* **Using Frida with targets built with CMake:** If a user is using Frida to instrument an application that itself uses CMake, Frida might need to parse the target's CMake project information to understand its structure and dependencies. This could happen if Frida offers features to inject code or hook functions within the target application, and needs to understand the target's build artifacts.
* **Developing Meson build definitions for Frida components:** Developers working on Frida or its extensions might directly interact with Meson build files. When Meson encounters a `cmake` dependency or interacts with a CMake project, it would use this code.

**8. Structuring the Answer:**

Finally, I need to organize the identified points into a clear and structured answer, addressing each part of the original request. This involves writing clear explanations, providing concrete examples where applicable, and connecting the code to the broader context of Frida and reverse engineering. The use of headings, bullet points, and code snippets will improve readability.
This Python code file, `common.py`, located within the Frida project's build system (using Meson), serves as a utility module to bridge the gap between Meson's build definitions and CMake's build system. Its primary function is to facilitate the integration of CMake-based projects or components within a larger Frida build managed by Meson.

Let's break down its functionalities with examples relating to reverse engineering, low-level concepts, and potential user errors:

**1. Mapping Languages and Build System Backends:**

* **Functionality:**  The `language_map` dictionary translates common programming language names (as understood by Meson) to their corresponding CMake language identifiers. Similarly, `backend_generator_map` maps Meson's build system backend choices (like Ninja or Xcode) to the appropriate CMake generator names.
* **Relationship to Reverse Engineering:** While not directly a reverse engineering *method*, this mapping is crucial for building reverse engineering tools or analyzing applications that might be built using different languages and build systems. For instance, Frida itself might need to compile components written in C, C++, or other languages, and understanding how these languages are handled by CMake is necessary.
* **Binary/Low-Level/Kernel/Framework Knowledge:**  This relates to the fundamental process of compiling code into machine-executable binaries. CMake, and by extension this mapping, deals with the low-level details of how source code is transformed into object files and then linked into executables or libraries. The choice of language directly impacts the compiler and linker used, which are core tools for working with binaries.
* **Logical Reasoning:**
    * **Assumption:** Meson needs to interact with CMake projects.
    * **Input:** A Meson build definition specifying a component written in "cpp" and a backend of "ninja".
    * **Output:** The code will use `language_map['cpp']` to get "CXX" and `backend_generator_map['ninja']` to get "Ninja", which are then used in CMake commands.

**2. Blacklisting CMake Definitions:**

* **Functionality:** The `blacklist_cmake_defs` list contains CMake variables that this module explicitly prevents users from setting directly. This is likely done to ensure consistency and prevent conflicts with how Meson manages the build process.
* **Relationship to Reverse Engineering:**  When analyzing a target application, you might encounter CMake build files. Understanding which variables are controlled by the higher-level build system (Meson in this case) is important to avoid making assumptions or trying to manipulate those variables directly.
* **Binary/Low-Level/Kernel/Framework Knowledge:** Some of these blacklisted variables, like `CMAKE_TOOLCHAIN_FILE` and `MESON_CMAKE_SYSROOT`, are critical for cross-compilation. Cross-compilation is frequently used in reverse engineering, especially when targeting embedded systems or different architectures (like Android). Preventing direct manipulation ensures that Meson's cross-compilation setup is used correctly.
* **Logical Reasoning:**
    * **Assumption:** Letting users directly set certain CMake variables can lead to build errors or inconsistencies when Meson is managing the overall build.
    * **Input:** A Meson build file attempts to set `CMAKE_TOOLCHAIN_FILE` within a `cmake` block.
    * **Output:** The code will detect this and issue a warning, ignoring the user's attempt to set the variable directly.

**3. Determining Debug Build Status:**

* **Functionality:** The `cmake_is_debug` function determines whether a debug build is being requested. It considers Meson's `buildtype` option and the `b_vscrt` option (related to Visual Studio runtime linking).
* **Relationship to Reverse Engineering:** Debug builds are essential for reverse engineering as they often contain symbolic information, making it easier to understand the code's structure and function. Frida itself and the applications it instruments are often built in debug mode during development and analysis.
* **Binary/Low-Level/Kernel/Framework Knowledge:** The concept of debug vs. release builds is fundamental in software development. Debug builds are typically compiled with optimizations disabled and debugging symbols included, which affects the generated binary's size and performance but greatly aids in debugging.
* **Logical Reasoning:**
    * **Assumption:** The debug status in the CMake subproject should align with Meson's overall debug settings.
    * **Input:** Meson's `buildtype` option is set to "debug".
    * **Output:** `cmake_is_debug(env)` will return `True`.

**4. Representing CMake Build Files and Project Structure:**

* **Functionality:** The classes `CMakeBuildFile`, `CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, and `CMakeConfiguration` are data structures designed to represent the various components and organization of a CMake project. They parse and store information extracted from CMake's output or build descriptions.
* **Relationship to Reverse Engineering:** When interacting with a target application built with CMake, Frida might need to understand the target's build structure – where source files are, include paths, linked libraries, etc. These classes provide a way to represent this information programmatically. For example, knowing the include paths (`CMakeInclude`) is crucial when Frida tries to inject code or hook functions, as it needs to understand the target's headers. Knowing the linked libraries (`CMakeTarget.link_libraries`) can help understand dependencies and potential attack surfaces.
* **Binary/Low-Level/Kernel/Framework Knowledge:** These classes reflect the core concepts of how software projects are organized and built. They represent the source code, the compilation process (flags, defines, includes), and the linking process that combines compiled units into final binaries.
* **Logical Reasoning:**
    * **Assumption:**  Information about the CMake project needs to be structured for easier programmatic access within Meson.
    * **Input:**  Data parsed from CMake's output describing a library target with specific source files, include directories, and compiler flags.
    * **Output:** A `CMakeTarget` object will be created, populated with the relevant `CMakeFileGroup` containing the source files, `CMakeInclude` objects for the include directories, and the compiler flags.

**5. Converting Meson Settings to CMake Arguments:**

* **Functionality:** Functions like `cmake_get_generator_args` and `cmake_defines_to_args` translate Meson's configuration settings into the command-line arguments expected by CMake.
* **Relationship to Reverse Engineering:** When building Frida or components that interface with CMake-based projects, it's necessary to translate the build instructions from Meson's format to CMake's format. For example, if Frida needs to build a plugin that uses a CMake library, Meson will use these functions to tell CMake how to build it.
* **Binary/Low-Level/Kernel/Framework Knowledge:** This involves understanding the command-line interfaces of build tools like CMake and how different options affect the compilation and linking process. Compiler flags, defines, and linker settings directly impact the generated binary.
* **Logical Reasoning:**
    * **Assumption:**  CMake needs specific command-line arguments to configure and generate the build system.
    * **Input:** Meson is configured to use the "ninja" backend.
    * **Output:** `cmake_get_generator_args(env)` will return `['-G', 'Ninja']`.

**6. Handling Compile and Link Flags:**

* **Functionality:** The `_flags_to_list` function parses a string of command-line flags into a list of individual flag strings. The `CMakeFileGroup` and `CMakeTarget` classes store these flags.
* **Relationship to Reverse Engineering:** Compiler and linker flags significantly influence the generated binary. Reverse engineers often need to understand the compilation process to identify potential vulnerabilities or understand how specific features were implemented. For example, flags related to security features (like stack canaries) or optimization levels can be crucial information.
* **Binary/Low-Level/Kernel/Framework Knowledge:**  This directly relates to the command-line options of compilers (like GCC or Clang) and linkers. Understanding these flags requires knowledge of low-level concepts like memory layout, optimization techniques, and linking procedures.
* **Logical Reasoning:**
    * **Assumption:**  CMake provides compile and link flags as strings, and they need to be parsed into a more usable list format.
    * **Input:** A CMake output contains `"compileFlags": "-Wall -O2 -DDEBUG"`.
    * **Output:** `_flags_to_list("-Wall -O2 -DDEBUG")` will return `['', '-Wall', '-O2', '-DDEBUG']`. (Note: The initial empty string might be a minor artifact and could be handled differently).

**7. Overriding Target-Specific Options:**

* **Functionality:** The `SingleTargetOptions` and `TargetOptions` classes allow for setting and managing build options (like compile flags, link flags, and install status) that are specific to individual CMake targets.
* **Relationship to Reverse Engineering:**  Complex projects might have different build requirements for different components. This functionality allows for fine-grained control over how individual libraries or executables are built within a larger CMake project, which can be important when analyzing specific parts of a target application.
* **Binary/Low-Level/Kernel/Framework Knowledge:** This relates to the ability to customize the build process for different parts of a software project, potentially using different compiler settings or linking against different libraries.
* **Logical Reasoning:**
    * **Assumption:**  Different CMake targets might require different build configurations.
    * **Input:** A Meson build file specifies additional compile flags for a specific CMake library target.
    * **Output:** The `TargetOptions` will store these flags, and when generating CMake commands for that specific target, these overridden flags will be included.

**Potential User Errors and Debugging:**

* **Setting Blacklisted CMake Definitions:** If a user tries to set a variable in `blacklist_cmake_defs` within their Meson build file when integrating a CMake project, the `check_cmake_args` function will issue a warning, and the setting will be ignored. This could lead to unexpected build behavior if the user relies on that specific variable being set. The warning message guides the user to the Meson documentation for cross-compilation, suggesting they should use Meson's mechanisms instead.

    * **User Action:** In a `meson.build` file:
      ```python
      cmake_dep = cmake.subproject('my_cmake_project', cmake_options={'CMAKE_TOOLCHAIN_FILE': '/path/to/my/toolchain.cmake'})
      ```
    * **How it reaches `common.py`:** Meson's CMake integration logic calls `check_cmake_args` in `common.py` to validate the provided `cmake_options`.
    * **Output/Debugging Clue:** The user will see a warning message in the Meson build output: "Setting CMAKE_TOOLCHAIN_FILE is not supported..."

* **Incorrect Language or Backend Mapping:** If the `language_map` or `backend_generator_map` is incomplete or incorrect, Meson might generate invalid CMake commands, leading to build errors. This is less likely for users to directly cause but is a potential area for developer error in Frida's build system.

* **Incorrectly Specifying CMake Options:** Users might provide CMake options with incorrect syntax or types. The `cmake_defines_to_args` function performs some basic type checking, and if an unsupported type is encountered, it will raise a `MesonException`.

    * **User Action:** In a `meson.build` file:
      ```python
      cmake_dep = cmake.subproject('my_cmake_project', cmake_options={'MY_FLAG': [1, 2, 3]}) # List is not supported
      ```
    * **How it reaches `common.py`:** Similar to the previous point, Meson's CMake integration calls `cmake_defines_to_args`.
    * **Output/Debugging Clue:** The Meson build will fail with an error message like: "Type "list" of "MY_FLAG" is not supported as for a CMake define value".

**In summary, `common.py` is a crucial utility within Frida's build system for seamlessly integrating CMake projects. It handles the translation between Meson's and CMake's concepts, manages build settings, and provides structured representations of CMake project information. This integration is indirectly relevant to reverse engineering by enabling the building of Frida itself and its interaction with target applications that might be built using CMake.**

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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