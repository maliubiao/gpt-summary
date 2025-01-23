Response:
Let's break down the thought process to analyze this Python code and answer the request.

**1. Understanding the Request:**

The core request is to analyze the `common.py` file within the Frida project, focusing on its functionality and how it relates to reverse engineering, low-level concepts, and potential user errors. The decomposed questions provide specific angles to explore.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd do a quick skim of the code to grasp its main purpose. Keywords like `cmake`, `options`, `flags`, `targets`, `projects`, and the function names like `cmake_get_generator_args`, `cmake_defines_to_args` strongly suggest this file is responsible for handling interactions with CMake within the Meson build system. It seems to be parsing and manipulating CMake project information and converting Meson options into CMake arguments.

**3. Deeper Dive into Functionality (Iterating through the code):**

Now, I'd go through the code section by section:

* **Imports:**  Note the standard library imports (`pathlib`, `typing`) and the Meson-specific imports (`mesonlib`, `mlog`, `environment`, `interpreterbase`). This confirms it's a Meson module interacting with CMake.
* **`language_map` and `backend_generator_map`:** These are simple dictionaries mapping Meson language and backend names to CMake equivalents. This points to the file's role in translating between the two build systems.
* **`blacklist_cmake_defs`:** This list of disallowed CMake definitions is crucial. It suggests the file is enforcing certain restrictions, likely due to Meson's own cross-compilation handling.
* **`cmake_is_debug`:**  This function determines if a debug build is being requested, considering both the general `debug` option and the Visual Studio runtime library option (`b_vscrt`). This shows interaction with Meson's build configuration.
* **`CMakeException`:** A custom exception class, indicating error handling within this module.
* **`CMakeBuildFile`:** A simple data class representing a CMake build file.
* **`_flags_to_list`:** This function is interesting. It parses a raw command-line string into a list of arguments, handling quotes and escapes. This is directly relevant to how compilers and linkers receive arguments.
* **`cmake_get_generator_args`:** This function translates the Meson backend option into the corresponding CMake generator argument.
* **`cmake_defines_to_args`:** This is a key function. It converts Meson definitions (likely from `meson.build` files) into CMake `-D` arguments. It also enforces the blacklist. The type checking is also important.
* **`check_cmake_args`:**  Another function for filtering CMake arguments against the blacklist. The comment "TODO: this function will become obsolete" is a useful observation.
* **`CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`:** These classes represent the structure of a CMake project as parsed from a CMake file (likely a JSON output from CMake itself). The `log` methods suggest these classes are used for debugging or informational purposes. The data they hold (sources, includes, defines, flags, artifacts, etc.) is fundamental to how software is built.
* **`SingleTargetOptions` and `TargetOptions`:** These classes appear to manage overrides and customizations for CMake options and arguments, either globally or for specific targets. This indicates a mechanism for fine-tuning the CMake build process.

**4. Connecting to the Specific Questions:**

Now, systematically address each part of the request:

* **Functionality:**  Summarize the main tasks:  CMake interaction within Meson, argument translation, project information parsing, option management.
* **Relationship to Reverse Engineering:**  Consider the *output* of the build process. This file helps generate the build system that produces the binaries. Reverse engineers work with these binaries. The flags, defines, and libraries used during compilation (handled by this code) directly affect the resulting binary and are crucial information for reverse engineering. Provide concrete examples of how compiler flags can affect reverse engineering (e.g., stripping symbols).
* **Binary/Low-Level, Linux/Android Kernel/Framework:**  Think about what kind of information this code manipulates that is relevant to these areas. Compiler flags (`-D`, `-I`, etc.) are directly related to how code is compiled into machine code. Linker flags control how libraries are combined. The handling of different languages (C, C++, etc.) is relevant to the underlying compiled code. The concept of "targets" maps to executables, libraries, etc., which are fundamental binary concepts. While the code itself *doesn't* directly touch the kernel, the build process it configures *does* produce code that runs on those systems.
* **Logical Inference (Hypothetical Input/Output):** Focus on key functions like `cmake_defines_to_args`. Provide a simple example of a Meson dictionary and how it would be translated into CMake arguments, demonstrating the logic.
* **User/Programming Errors:**  Look at the blacklist and the warning messages. Users might try to set disallowed CMake definitions. Incorrectly formatted input strings to `_flags_to_list` (though the code is robust) could be a source of issues. Misunderstanding how Meson options map to CMake could also lead to unexpected behavior.
* **User Operations and Debugging:**  Think about the typical workflow of a developer using Frida and Meson. They would configure their build using `meson configure`, then build with `meson compile`. The `common.py` file is involved during the *configuration* phase, when Meson sets up the CMake project. Explain how a user might end up needing to look at this file (e.g., if they're having issues with CMake integration).

**5. Structuring the Answer:**

Organize the findings clearly, using headings and bullet points to address each part of the request. Provide code snippets and concrete examples to illustrate the points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly executes CMake commands.
* **Correction:** Closer inspection reveals it's primarily *generating the arguments* for CMake, not executing it directly. Meson will handle the actual execution.
* **Initial thought:** Focus heavily on the low-level binary manipulation aspects *within* the Python code.
* **Correction:**  The Python code itself is higher-level. The connection to the binary is through the *CMake configuration* it generates, which then drives the compiler and linker. Shift the focus accordingly.
* **Make sure to answer *all* parts of the decomposed question.** Don't just focus on the most obvious aspects.

By following this structured approach, combining code analysis with an understanding of the broader build process and the user context, you can generate a comprehensive and accurate answer to the request.
This Python code file, `common.py`, located within the Frida project's build system, serves as a utility module to facilitate the interaction between the Meson build system and CMake. It provides functions and classes to manage CMake-specific configurations, arguments, and project information within the Meson environment.

Here's a breakdown of its functionalities:

**1. Mapping and Translation:**

* **`language_map`:**  Maps Meson's language identifiers (like 'c', 'cpp') to their corresponding CMake language identifiers ('C', 'CXX'). This is crucial for ensuring that when Meson interacts with CMake, it uses the correct language names understood by CMake.
* **`backend_generator_map`:** Maps Meson's backend choices (like 'ninja', 'xcode') to the corresponding CMake generator names ('Ninja', 'Xcode'). This is essential for instructing CMake on how to generate the actual build files for the chosen build system.

**2. Blacklisting CMake Definitions:**

* **`blacklist_cmake_defs`:** Defines a list of CMake definitions that are explicitly disallowed from being set directly through Meson's CMake integration. This is likely done to maintain control over certain aspects of the build process and avoid conflicts with Meson's own configuration management, especially regarding cross-compilation.

**3. Determining Debug Build:**

* **`cmake_is_debug(env)`:**  A function that determines whether a debug build is being requested. It checks Meson's build options, specifically looking at the `buildtype` and the Visual Studio runtime library setting (`b_vscrt`). This function helps to translate Meson's debug/release concept into the appropriate CMake configuration.

**4. Handling CMake Build Files:**

* **`CMakeBuildFile` class:** A simple data class to represent a CMake build file, storing its path and whether it's a CMakeLists.txt or a temporary file.

**5. Parsing Command-Line Flags:**

* **`_flags_to_list(raw)`:**  This function takes a raw string of command-line flags and converts it into a list of individual flag strings, correctly handling quotes and escaped characters. This is essential for parsing compiler and linker flags.

**6. Generating CMake Generator Arguments:**

* **`cmake_get_generator_args(env)`:**  Retrieves the selected backend from Meson's environment and returns the corresponding CMake generator argument (e.g., `['-G', 'Ninja']`).

**7. Converting Meson Definitions to CMake Arguments:**

* **`cmake_defines_to_args(raw, permissive=False)`:** This is a key function. It takes a list of dictionaries, where each dictionary represents a Meson definition (key-value pair), and converts them into a list of CMake `-D` arguments (e.g., `['-DMyOption=value']`). It also enforces the `blacklist_cmake_defs`. This allows users to pass configuration options defined in their `meson.build` file down to the CMake project.

**8. Checking CMake Arguments (and Blacklisting):**

* **`check_cmake_args(args)`:**  This function takes a list of CMake arguments and filters out any arguments that start with the blacklisted definitions. This provides an additional layer of protection against using disallowed CMake definitions.

**9. Representing CMake Project Structure:**

The file defines several classes to model the structure of a CMake project as reported by CMake's file API:

* **`CMakeInclude`:** Represents an include directory with its path and whether it's a system include.
* **`CMakeFileGroup`:** Represents a group of source files with associated compiler flags, defines, and include directories.
* **`CMakeTarget`:** Represents a CMake target (e.g., an executable or library) with its artifacts, source and build directories, name, install rules, link libraries, link flags, and file groups.
* **`CMakeProject`:** Represents a CMake project containing multiple targets.
* **`CMakeConfiguration`:** Represents a CMake configuration (e.g., Debug or Release) containing multiple projects.

These classes are used to parse and store information about the CMake project, allowing Meson to understand its structure and build settings.

**10. Managing Target-Specific Options:**

* **`SingleTargetOptions`:**  Stores options, language-specific arguments, and linker arguments that can be applied to a single target.
* **`TargetOptions`:**  Manages both global options and target-specific options, allowing for fine-grained control over the CMake build process.

**Relationship to Reverse Engineering:**

This file plays a crucial role in setting up the build environment for software, and the build environment directly influences the resulting binaries that reverse engineers analyze. Here's how it relates:

* **Compiler and Linker Flags:** The `_flags_to_list`, `CMakeFileGroup`, and `CMakeTarget` classes handle compiler and linker flags. These flags significantly impact the generated code. For instance:
    * **`-g` (debug symbols):** If the debug flag is enabled (via `cmake_is_debug`), and this propagates through the CMake configuration, the compiled binaries will contain debugging symbols, making reverse engineering easier.
    * **`-O0`, `-O1`, `-O2`, `-O3` (optimization levels):** Different optimization levels will produce binaries with varying degrees of code transformations, impacting performance and the complexity of reverse engineering. Higher optimization levels can make the code harder to follow.
    * **`-fPIC` (Position Independent Code):** This flag is often necessary for shared libraries and affects how addresses are resolved at runtime. Understanding whether a library is PIC or not is crucial for dynamic analysis.
    * **Linker flags (`-l`, `-L`):** These flags specify which libraries to link against and where to find them. Knowing the linked libraries is essential for understanding the dependencies and functionality of a binary. A reverse engineer might use this information to identify common libraries and known vulnerabilities.
* **Preprocessor Definitions:** The `cmake_defines_to_args` function handles preprocessor definitions. These definitions can conditionally compile code, enable/disable features, or embed configuration information into the binary. Reverse engineers need to be aware of these definitions to understand the different code paths and functionalities.
    * **Example:**  A definition like `DEBUG_MODE` might enable extra logging or checks in a debug build. A reverse engineer analyzing a release build might not see this code.
* **Include Paths:** The `CMakeInclude` class manages include paths. While not directly affecting the binary code, knowing the include paths can help reverse engineers understand the source code structure and the origin of different functions and data structures.

**Example:**

Let's say a Frida developer wants to build the QML module in debug mode for Linux.

1. **User Operation:** The developer runs the Meson configuration command, specifying a debug build: `meson setup _build -Dbuildtype=debug`
2. **Meson Processing:** Meson reads the `meson.build` files for the `frida-qml` subproject.
3. **CMake Integration:** The `frida-qml` subproject likely uses the `cmake` module in Meson to integrate with an underlying CMake project.
4. **`common.py` Involvement:**  When Meson configures the CMake project, the functions in `common.py` are used:
    * `cmake_is_debug` would return `True` because `buildtype` is 'debug'.
    * `cmake_get_generator_args` would determine the CMake generator based on the chosen backend (e.g., `['-G', 'Ninja']`).
    * `cmake_defines_to_args` would translate Meson definitions into CMake `-D` arguments, potentially including a definition to indicate a debug build to the CMake project.
    * Compiler flags and include paths specified in the CMake project would be parsed and represented by the `CMakeFileGroup` and `CMakeInclude` classes.
5. **CMake Configuration:** Meson would then invoke CMake with the generated arguments. CMake, knowing it's a debug build, would typically add the `-g` flag to the compiler commands.
6. **Result:** The compiled binaries would contain debug symbols, which a reverse engineer could later use with tools like gdb or a disassembler to step through the code, examine variables, and understand the program's execution flow.

**Binary/Bottom Layer, Linux, Android Kernel & Framework Knowledge:**

This file touches upon these areas indirectly by managing the build process that produces binaries for these platforms:

* **Binary Bottom Layer:** The core purpose is to configure the compilation and linking process that transforms source code into executable binaries. The flags, definitions, and libraries managed by this file dictate the structure and content of these binaries.
* **Linux:**  The support for the 'ninja' backend is a strong indicator of Linux compatibility, as Ninja is a common build system on Linux. The generated CMake configuration will produce Makefiles or Ninja build files suitable for Linux.
* **Android Kernel & Framework:** Frida is heavily used for dynamic instrumentation on Android. While this specific file doesn't directly interact with the Android kernel, it's part of the build process that creates Frida components that *do* interact with the Android framework and potentially the kernel. The CMake configuration might need to handle Android-specific toolchains, system libraries, and build requirements. For example, it might need to link against Android's `libc` or other framework libraries.

**Logical Inference (Hypothetical Input & Output):**

Let's consider the `cmake_defines_to_args` function:

**Hypothetical Input:**

```python
raw_defines = [
    {"ENABLE_FEATURE_X": True},
    {"API_KEY": "your_secret_key"},
    {"BUFFER_SIZE": 1024}
]
```

**Hypothetical Output:**

```python
['-DENABLE_FEATURE_X=ON', '-DAPI_KEY=your_secret_key', '-DBUFFER_SIZE=1024']
```

**Explanation:**

The function iterates through the dictionary list. Boolean values are converted to "ON" or "OFF", while strings and integers are passed directly. This demonstrates the logic of converting Meson's definition format into CMake's command-line argument format.

**User or Programming Common Usage Errors:**

* **Trying to set blacklisted CMake definitions:**  A user might try to directly set a CMake definition that is in the `blacklist_cmake_defs` list, either through the `cmake_options` argument in their `meson.build` file or through command-line arguments passed to Meson.
    * **Example:**  If a user tries to set `CMAKE_TOOLCHAIN_FILE` directly, Meson will issue a warning and ignore the option because it's blacklisted.
* **Incorrectly formatted flags string:** If a developer provides a poorly formatted string of compiler or linker flags, the `_flags_to_list` function might not parse it correctly, leading to unexpected build errors or behavior. While the function tries to handle quotes, incorrect escaping or mismatched quotes could cause issues.
* **Misunderstanding Meson's CMake integration:** Users might misunderstand how Meson translates its own build concepts to CMake. For instance, they might expect a Meson option to directly map to a specific CMake variable without considering the translation logic in this file.
* **Providing unsupported data types for CMake defines:** The `cmake_defines_to_args` function checks the data type of the values in the definitions. If a user provides a complex data structure like a list or dictionary as a CMake define value, it will raise a `MesonException`.

**User Operations Leading Here (Debugging Scenario):**

A user might end up looking at this file as a debugging step if they encounter issues with the CMake integration in their Frida build:

1. **Problem:** The user observes unexpected behavior in the built Frida modules or encounters CMake-related build errors.
2. **Hypothesis:** The issue might be related to how Meson is configuring the underlying CMake project.
3. **Investigation:** The user might start by examining the Meson build log to see the CMake commands being executed.
4. **Source Code Examination:**  To understand how those commands are generated, they might delve into the Meson source code responsible for CMake integration. Following the call stack, they could find themselves in `frida/subprojects/frida-qml/releng/meson/mesonbuild/cmake/common.py`.
5. **Analyzing the Code:** The user would then analyze the functions in this file, such as `cmake_defines_to_args` or `cmake_get_generator_args`, to understand how Meson options are translated into CMake arguments and identify potential discrepancies or errors in the configuration process. They might also inspect the `blacklist_cmake_defs` to see if a setting they are trying to use is being blocked by Meson.

In summary, `common.py` is a vital utility module within Frida's build system that bridges the gap between Meson and CMake. It handles the translation of build configurations, manages CMake project information, and plays a crucial role in setting up the build environment that ultimately produces the Frida binaries used for dynamic instrumentation and reverse engineering. Understanding its functionality is essential for developers working with Frida's build system and can be helpful for debugging CMake-related issues.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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