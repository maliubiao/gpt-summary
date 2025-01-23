Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The initial request asks for an analysis of the `common.py` file within the Frida project, specifically focusing on its functions, relevance to reverse engineering, interaction with low-level concepts, logical reasoning, potential user errors, and how a user might end up here (debugging context).

2. **High-Level Overview:**  The first step is to skim the code to get a general understanding. Keywords like "CMake," "options," "targets," "files," and "flags" immediately stand out. The file seems heavily involved with processing and translating CMake project information for use within the Meson build system.

3. **Function-by-Function Analysis (Core Functionality):**  The next step is to go through each class and function, figuring out its purpose.

    * **`language_map`, `backend_generator_map`, `blacklist_cmake_defs`:** These are data structures. `language_map` and `backend_generator_map` are simple mappings. `blacklist_cmake_defs` is important – it suggests filtering or restrictions on CMake definitions. *Initial thought: This might be security-related or to prevent conflicts with Meson's own settings.*

    * **`cmake_is_debug`:**  This function clearly determines if a debug build is being requested. It checks the `buildtype` and `b_vscrt` options. *Connection to low-level: Debug builds often disable optimizations and include debug symbols, important for reverse engineering.*

    * **`CMakeException`, `CMakeBuildFile`:**  Standard exception and a simple data class for CMake build files. Not much to elaborate on here.

    * **`_flags_to_list`:** This is a utility function for parsing command-line style flag strings. The logic for handling quotes and escapes is a key detail. *Potential user error: Incorrectly quoting or escaping flags in CMake definitions.*

    * **`cmake_get_generator_args`:**  Translates Meson's backend choice to CMake's generator argument. *Relates to build systems, a fundamental aspect of software development.*

    * **`cmake_defines_to_args`:** Converts a dictionary of definitions into CMake command-line arguments (`-Dkey=value`). The blacklist check is reinforced here. *Connection to reverse engineering: CMake definitions can control build behavior, including enabling/disabling features that might be of interest during analysis.*

    * **`check_cmake_args`:** Similar to `cmake_defines_to_args` but for a list of arguments directly. The blacklist check is present again.

    * **`CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`:** These classes represent the structure of a CMake project as extracted and used by Meson. They store information about include paths, source files, compile flags, link libraries, targets, and projects. *Crucial for understanding how Meson integrates with CMake.*

    * **`SingleTargetOptions`, `TargetOptions`:** These classes handle overriding or customizing build options for individual targets or globally. This allows fine-grained control over the build process.

4. **Identifying Connections to Reverse Engineering:** After understanding the individual components, look for specific connections to reverse engineering.

    * **Debug Builds:** The `cmake_is_debug` function highlights the importance of debug symbols.
    * **Build System Information:**  Knowing how a target is built (compile flags, link libraries, etc.) is crucial for understanding its structure and dependencies, which is vital for reverse engineering. The `CMakeTarget` and `CMakeFileGroup` classes are central here.
    * **Conditional Compilation:** CMake definitions can control which code is compiled, impacting the final binary. The `cmake_defines_to_args` function and the blacklist are relevant.

5. **Identifying Connections to Low-Level Concepts:**

    * **Binary:**  The entire process of building software from source code to a binary is inherently low-level. The output of CMake and Meson are executable binaries or libraries.
    * **Linux and Android:** While not explicitly mentioned in the code, the presence of build system logic and the types of options handled (compiler flags, linker settings) are common across Linux and Android development. Frida itself heavily interacts with these platforms.
    * **Kernel and Framework:** Frida's purpose is dynamic instrumentation, which often involves interacting with the operating system kernel and application frameworks. The build process prepares the tools for this interaction.

6. **Logical Reasoning (Hypothetical Inputs and Outputs):** Choose a simple function and imagine how it would behave. For example, take `_flags_to_list`:

    * **Input:** `"-DFOO=bar -DBAZ='quoted value'"`
    * **Expected Output:** `["-DFOO=bar", "-DBAZ='quoted value'"]`

    This helps solidify understanding and identify potential edge cases.

7. **User Errors:** Think about how a user might misuse the functionality:

    * **Incorrect Flag Syntax:**  As mentioned with `_flags_to_list`.
    * **Using Blacklisted CMake Definitions:** The code explicitly warns against this.
    * **Misunderstanding Option Overrides:**  The `TargetOptions` class can be complex; users might not understand the order of precedence.

8. **Debugging Context (How to Arrive Here):** Consider the scenarios that would lead a developer to examine this file:

    * **Build Issues:** If the build fails when using CMake subprojects, this file could be a point of investigation.
    * **Unexpected CMake Behavior:** If CMake options aren't being applied as expected.
    * **Understanding Meson's CMake Integration:**  A developer might want to understand how Meson handles CMake projects internally.
    * **Contributing to Frida/Meson:** A developer might need to modify this code.

9. **Structure and Refine:** Organize the findings into the requested categories (functionality, reverse engineering, low-level, logic, errors, debugging). Use examples to illustrate the points. Ensure the language is clear and concise.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  The blacklist might be purely about avoiding conflicts. *Refinement:*  Consider the security implications of allowing arbitrary CMake definitions.
* **Focus too much on individual functions:** *Refinement:* Ensure the analysis also captures the bigger picture of how the functions work together to process CMake projects.
* **Not enough concrete examples:** *Refinement:* Add specific examples for reverse engineering connections, logical reasoning, and user errors.

By following these steps, combining code analysis with domain knowledge (build systems, reverse engineering, low-level systems), and engaging in some "what if" scenarios, a comprehensive and accurate analysis of the code can be generated.
This Python code file, `common.py`, is part of the Frida dynamic instrumentation toolkit's build system, specifically focusing on the interaction with CMake projects when they are included as subprojects within a larger Meson build. Its primary function is to **parse and represent information from CMake projects in a way that Meson can understand and utilize**.

Here's a breakdown of its functionalities:

**1. Mapping and Configuration:**

* **`language_map`:**  Defines a mapping between common programming language extensions (like 'c', 'cpp') and their corresponding CMake language identifiers ('C', 'CXX'). This is crucial for telling CMake which compiler and toolchain to use for different source files.
* **`backend_generator_map`:** Maps Meson's build system backends (like 'ninja', 'xcode') to the corresponding CMake generator names ('Ninja', 'Xcode'). This allows Meson to instruct CMake on how to generate the actual build files.
* **`blacklist_cmake_defs`:**  A list of CMake definitions that this code explicitly disallows setting. This is likely done to prevent conflicts with Meson's own build system management or to enforce certain build practices.
* **`cmake_is_debug(env)`:**  Determines if a debug build is being requested based on Meson's build options (`buildtype` and `b_vscrt`). This information can be passed to CMake to configure debug vs. release builds of the CMake subproject.

**2. Data Structures for Representing CMake Information:**

The file defines several classes to model the structure of a CMake project:

* **`CMakeException`:** A custom exception class for errors specific to CMake processing within Meson.
* **`CMakeBuildFile`:** Represents a CMake build file (either a `CMakeLists.txt` or a temporary one generated by Meson).
* **`CMakeInclude`:** Represents an include directory path, specifying whether it's a system include path.
* **`CMakeFileGroup`:**  Groups source files with associated compiler flags, defines, and include paths for a specific part of a CMake target.
* **`CMakeTarget`:** Represents a CMake build target (like an executable or library), containing information about its artifacts (output files), source and build directories, link libraries, link flags, and associated file groups.
* **`CMakeProject`:** Represents a CMake project, containing a collection of CMake targets.
* **`CMakeConfiguration`:** Represents a CMake build configuration (like "Debug" or "Release"), containing a collection of CMake projects.
* **`SingleTargetOptions`:**  Holds options specific to a single CMake target for overriding default behavior (e.g., specific compile flags, link arguments, install status).
* **`TargetOptions`:** Manages both global and per-target override options for CMake subprojects.

**3. Utility Functions for CMake Interaction:**

* **`_flags_to_list(raw)`:**  Parses a raw string of command-line flags into a list of individual flag strings, handling quoting and escaping.
* **`cmake_get_generator_args(env)`:**  Retrieves the appropriate CMake generator argument based on Meson's selected backend.
* **`cmake_defines_to_args(raw, permissive=False)`:** Converts a list of dictionaries representing CMake definitions into a list of command-line arguments (`-Dkey=value`). It also checks against the `blacklist_cmake_defs`.
* **`check_cmake_args(args)`:**  Checks a list of arbitrary CMake arguments against the `blacklist_cmake_defs` to prevent disallowed options.

**Relationship to Reverse Engineering:**

This code, while part of the *build process*, has indirect but important connections to reverse engineering when using Frida:

* **Understanding Build Configuration:** Reverse engineers often need to understand how a target application or library was built. This file helps bridge the gap between Meson's build system and the underlying CMake configuration of a subproject. By examining the parsed `CMakeTarget` and `CMakeFileGroup` information, one can infer:
    * **Compiler Flags and Defines:**  These can reveal optimizations applied, debugging symbols included (or stripped), and conditional compilation settings, all crucial for understanding the binary's behavior. For example, compiler flags like `-fno-omit-frame-pointer` make stack tracing easier during reverse engineering. Defines might enable or disable specific features that are relevant to the analysis.
    * **Link Libraries:** Knowing the libraries a target depends on is fundamental for understanding its functionality and identifying potential attack surfaces. The `link_libraries` attribute in `CMakeTarget` provides this information.
    * **Include Paths:** While less directly relevant to the final binary, knowing the include paths can be helpful when examining the source code or decompiling the binary, as it gives context to the symbols and structures being used.
* **Reproducing Builds:**  Understanding how Meson interacts with CMake allows for potentially reproducing the build environment of a target application. This can be valuable for creating a controlled environment for analysis and debugging.
* **Targeting Specific Build Configurations:** Frida might interact differently with debug vs. release builds. The `cmake_is_debug` function highlights the awareness of these configurations within the build process. Reverse engineers often prefer debugging symbols present in debug builds.

**Example of Reverse Engineering Relevance:**

Imagine a Frida script targeting a closed-source Android application that uses a native library built with CMake. If this library exhibits unexpected behavior, a reverse engineer might:

1. **Examine the Frida build system:** They might look at how the native library is included as a subproject. This would lead them to files like `common.py`.
2. **Inspect the parsed CMake information:** They could potentially access the parsed `CMakeTarget` data for the native library to see the compiler flags used.
3. **Identify a flag like `-DENABLE_FEATURE_X`:** This define might indicate a specific feature is enabled. The reverse engineer could then focus their analysis on the code paths related to this feature.
4. **Look at `link_libraries`:** They might find dependencies on cryptography libraries, giving them a clue about the security mechanisms in place.

**Relationship to Binary Bottom, Linux, Android Kernel & Framework:**

* **Binary Bottom:**  The entire process of building software using CMake and Meson ultimately results in binary files (executables, shared libraries). This code is a step in that process, ensuring that CMake projects contribute correctly to the final binaries.
* **Linux:**  Meson and CMake are commonly used build systems on Linux. The handling of compiler flags, linkers, and library paths within this code is directly relevant to Linux development practices.
* **Android Kernel & Framework:** While the code itself doesn't directly interact with the Android kernel, it's part of the build process for tools (like Frida itself or native libraries it might inject) that *do* interact with the Android framework and potentially the kernel. For example, when building Frida for Android, this code helps manage the build of native components that will run on the Android system. The handling of cross-compilation scenarios (though partially blacklisted here) is relevant for targeting Android.

**Example of Linux/Android Relevance:**

When building a Frida gadget for Android, the `cmake_get_generator_args` function might be used to instruct CMake to use the "Ninja" generator, which is a fast build system often preferred for Android development. The handling of compiler flags like `-march=armv7-a` or `-mthumb` (not explicitly in this code, but illustrative of the kinds of things handled in the broader build system) would be crucial for targeting the correct Android architecture.

**Logical Reasoning (Hypothetical Input & Output):**

Let's take the `_flags_to_list` function:

**Hypothetical Input:** `raw = '-DFOO="bar baz" -DVAR=value -DOPT=\'single quoted\'`

**Expected Output:** `['\-DFOO="bar baz"', '-DVAR=value', '-DOPT=\'single quoted\'']`

**Explanation:** The function correctly splits the raw string into individual flags, preserving the quotes around values that contain spaces.

Let's take `cmake_defines_to_args`:

**Hypothetical Input:** `raw = [{'MY_DEFINE': 'hello'}, {'DEBUG_MODE': True}, {'COUNT': 123}]`

**Expected Output:** `['-DMY_DEFINE=hello', '-DDEBUG_MODE=ON', '-DCOUNT=123']`

**Explanation:** The function correctly converts dictionary-based definitions into CMake command-line arguments with appropriate formatting for strings, booleans, and integers.

**User or Programming Common Usage Errors:**

* **Using Blacklisted CMake Definitions:**  A user might try to pass a CMake definition that's in the `blacklist_cmake_defs` list, such as `CMAKE_TOOLCHAIN_FILE`. This code will issue a warning and ignore the option.
    * **Example:** In a `meson.build` file, when using the `cmake.subproject()` function, a user might try to pass `cmake_options: ['-DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain.cmake']`. Meson would warn and skip this.
* **Incorrectly Quoting Flags:** When providing raw flag strings, users might make mistakes in quoting or escaping special characters, which would lead to `_flags_to_list` parsing them incorrectly.
    * **Example:** If a user intends to pass a flag like `-DMyVar="value with space"` but writes `-DMyVar=value with space`, the parser will likely split it into multiple arguments.
* **Type Errors in CMake Defines:** If a user provides a value with an unsupported type for a CMake define (e.g., a list or a complex object), the `cmake_defines_to_args` function will raise a `MesonException`.
    * **Example:**  `cmake_options: [{'MY_LIST': [1, 2, 3]}]` would cause an error.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **User wants to include a CMake project as a subproject in their Frida build.** This is done using the `cmake.subproject()` function in a `meson.build` file.
2. **The CMake subproject requires specific definitions or flags to be set.** The user attempts to pass these through the `cmake_options` argument of `cmake.subproject()`.
3. **The Meson build process starts.**  Meson needs to translate these CMake options into a format that CMake understands.
4. **Meson's CMake integration code is invoked.** This includes the `frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/common.py` file.
5. **The `cmake_defines_to_args` function is called.** This function receives the user-provided CMake options.
6. **The function checks for blacklisted definitions.** If the user has provided a blacklisted definition, a warning is logged.
7. **The function converts the valid definitions into command-line arguments.**
8. **(If there's an error):** The user might encounter a build error related to the CMake subproject. To debug, they might:
    * **Examine the Meson build log:** They would see warnings about blacklisted options or error messages if there were type issues.
    * **Step through the Meson build system's code (less common for typical users):**  A developer contributing to Frida or Meson might need to trace the execution and would end up examining `common.py` to understand how CMake options are being processed.
    * **Experiment with different ways of passing CMake options:** They might try different quoting styles or data types for the definitions, leading them to understand the limitations and requirements enforced by this code.

In essence, this `common.py` file plays a crucial role in the seamless integration of CMake subprojects within the broader Frida build system managed by Meson. It handles the translation and validation of CMake-specific information, ensuring consistency and preventing potential conflicts. While not directly involved in the dynamic instrumentation process itself, it's a foundational component for building Frida and its extensions, which are essential for reverse engineering and security analysis.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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