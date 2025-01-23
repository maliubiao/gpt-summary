Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Understanding the Goal:**

The prompt asks for an analysis of the provided Python code, specifically focusing on its functionality, relevance to reverse engineering, interaction with low-level systems, logical inferences, potential user errors, and debugging context. The key is to extract meaningful information from the code itself and relate it to the larger context of Frida and dynamic instrumentation.

**2. Initial Code Scan and High-Level Purpose:**

My first step is always a quick skim to understand the overall structure and purpose. I see imports like `pathlib`, `typing`, and comments indicating this code interacts with Meson, a build system. The presence of classes like `CMakeBuildFile`, `CMakeTarget`, and `CMakeProject` strongly suggests this code is involved in processing information related to CMake projects. The `frida/releng` path in the file name suggests it's part of Frida's release engineering or build process.

**3. Deeper Dive into Functionality:**

I then go through each section of the code, noting down the purpose of key elements:

* **`language_map` and `backend_generator_map`:** These are simple mappings, likely used for translating between Meson's internal representations and CMake's conventions.
* **`blacklist_cmake_defs`:** This is a crucial list. It indicates CMake definitions that this code explicitly *ignores*. This is a strong indicator of where Meson's control over the build process is asserted, and potentially where conflicts could arise if users try to manipulate these settings directly in CMake.
* **`cmake_is_debug`:** This function determines if a debug build is being configured. The logic involving `b_vscrt` suggests it's handling Visual Studio runtime library settings, relevant for Windows development.
* **`CMakeException` and `CMakeBuildFile`:** These are basic data structures and custom exceptions for managing CMake-related files.
* **`_flags_to_list`:**  This is a utility function to parse command-line flag strings, handling quoting and escaping. This is essential for dealing with compiler and linker flags.
* **`cmake_get_generator_args`:** This translates Meson's backend selection (e.g., "ninja") into the corresponding CMake generator argument (e.g., "-GNinja").
* **`cmake_defines_to_args`:**  This function converts a list of key-value pairs (likely representing CMake definitions) into CMake command-line arguments (-Dkey=value). The check against `blacklist_cmake_defs` is important here.
* **`check_cmake_args`:**  This is similar to `cmake_defines_to_args` but operates on a list of existing arguments, again filtering based on the blacklist. The comment "// TODO: this function will become obsolete once the `cmake_args` kwarg is dropped" is a valuable insight into potential future code changes.
* **`CMakeInclude`, `CMakeFileGroup`, `CMakeTarget`, `CMakeProject`, `CMakeConfiguration`:** These classes represent the structure of a CMake project, mirroring the information typically found in CMake's internal representation or generated files. They parse and store details about source files, include paths, compiler flags, linker settings, and target dependencies. The `log()` methods are clearly for debugging purposes.
* **`SingleTargetOptions` and `TargetOptions`:** These classes handle overriding and managing CMake options on a per-target basis. This suggests a mechanism for fine-grained control over the build process for individual libraries or executables within a larger CMake project.

**4. Connecting to Reverse Engineering:**

Now, I start linking the code's functionality to the concept of reverse engineering.

* **Dynamic Instrumentation (Frida Context):** I know Frida is a dynamic instrumentation tool. This code is part of Frida's build system. Therefore, this code is indirectly involved in setting up the environment where Frida itself is built. Understanding how Frida is built is a prerequisite for understanding how it works and how to potentially reverse engineer it or its targets.
* **CMake and Build Processes:** Reverse engineers often encounter projects built with CMake. Understanding how CMake projects are structured and configured is a valuable skill. This code provides insights into how a build system like Meson interacts with CMake, which can be helpful for reverse engineers analyzing CMake-based targets.
* **Compiler and Linker Flags:** The code deals extensively with compiler and linker flags. These flags directly influence the generated binary. Reverse engineers need to understand these flags to interpret the behavior of the compiled code, identify optimizations, and understand linking dependencies.

**5. Identifying Low-Level System Interactions:**

The code has several connections to low-level systems:

* **Operating System (Linux, Android):**  The handling of compiler and linker flags is OS-specific. The presence of build system logic inherently ties into how software is compiled and linked on different platforms. While this specific code doesn't directly interact with the Linux or Android kernel, it's part of the build process that *creates* software that will run on those kernels.
* **Binary Structure:**  Linker flags directly influence the structure of the generated binary (e.g., shared libraries, executables, symbol tables). This code, by manipulating these flags, indirectly influences the binary's layout.
* **Visual Studio Runtime (Windows):** The `cmake_is_debug` function specifically checks `b_vscrt`, which is related to the Visual Studio C/C++ runtime library. This is a clear indicator of Windows-specific considerations in the build process.

**6. Logical Inferences and Assumptions:**

I look for conditional logic and how data is transformed.

* **`cmake_is_debug`:** The logic infers the debug status based on the `buildtype` option and the `b_vscrt` setting. The assumptions are that these options are set correctly in the Meson configuration.
* **`cmake_defines_to_args`:** This function assumes that the values in the input dictionary are of supported types (string, int, float, bool). If a different type is encountered, it raises an exception.
* **Class Structures:** The class structure (`CMakeProject`, `CMakeTarget`, `CMakeFileGroup`) infers a hierarchical relationship between these elements, reflecting the structure of a CMake project.

**7. Potential User Errors:**

I think about how a user might misuse this functionality.

* **Blacklisted CMake Definitions:**  Trying to set CMake definitions in `blacklist_cmake_defs` will be ignored, potentially leading to unexpected build behavior. Users might be confused if their manually specified CMake settings are not being applied.
* **Incorrect Data Types:** Providing values of incorrect types to `cmake_defines_to_args` will cause an error.
* **Misunderstanding Meson's Abstraction:** Users familiar with CMake might try to directly manipulate CMake settings that Meson intends to manage, leading to conflicts and unexpected results.

**8. Debugging Context and User Steps:**

I consider how a developer would end up looking at this code.

* **Build Issues:**  A developer might investigate this code if they encounter problems building Frida or a project that uses Frida's build system. For example, if CMake options are not being applied as expected, they might trace the execution to this file.
* **Customizing Frida's Build:**  Someone wanting to modify Frida's build process or add custom CMake options might examine this code to understand how Meson interacts with CMake.
* **Understanding Error Messages:**  If errors related to CMake configuration or option handling occur during the build, the stack trace might lead a developer to this code.

To reconstruct the steps:

1. **User wants to build Frida:**  They would typically follow Frida's build instructions, which likely involve using `meson` to configure the build.
2. **Meson interacts with CMake:** If the project or its dependencies use CMake, Meson will invoke CMake.
3. **This code is involved in generating CMake arguments:** The `common.py` file is part of Meson's CMake integration. When Meson needs to configure CMake, it uses functions in this file to generate the appropriate arguments.
4. **Debugging a CMake-related build issue:** If something goes wrong during the CMake configuration, the error messages or debugging tools might point to this file as the source of the problem. The developer might then open this file to understand how Meson is handling CMake options.

**9. Structuring the Answer:**

Finally, I organize the collected information into a coherent answer, addressing each point of the prompt with relevant details and examples. I use clear headings and bullet points for readability. I also make sure to explain the terms and concepts in a way that is understandable to someone who might not be intimately familiar with Meson or CMake.
This Python code file, `common.py`, located within the Frida project's build system (using Meson), provides a set of utility functions and classes for managing and interacting with CMake projects as part of the larger Frida build process. Let's break down its functionalities and address the specific points raised:

**Functionalities:**

1. **Mapping Languages and Backends:**
   - `language_map`:  Provides a mapping between common programming language identifiers (like 'c', 'cpp') and their corresponding CMake language names ('C', 'CXX'). This is used when configuring CMake to handle different language sources.
   - `backend_generator_map`: Maps Meson's build backend names (like 'ninja', 'xcode') to the corresponding CMake generator names ('Ninja', 'Xcode'). This allows Meson to instruct CMake to use the desired build system generator.

2. **Blacklisting CMake Definitions:**
   - `blacklist_cmake_defs`: Defines a list of CMake definitions that this code explicitly prevents from being set directly. This suggests that Meson wants to maintain control over these specific settings, likely related to cross-compilation, toolchain management, and internal Meson configurations.

3. **Determining Debug Build Status:**
   - `cmake_is_debug(env)`:  A function to determine if a debug build is being configured. It checks Meson's `buildtype` option and the `b_vscrt` option (related to Visual Studio runtime libraries) to accurately identify debug builds, especially in Windows environments.

4. **Handling CMake Exceptions:**
   - `CMakeException`: A custom exception class derived from `MesonException`, used to signal errors specifically within the CMake interaction logic.

5. **Representing CMake Build Files:**
   - `CMakeBuildFile` class: A simple data class to represent a CMake build file, storing its path and whether it's a regular CMake file or a temporary one.

6. **Parsing Command-Line Flags:**
   - `_flags_to_list(raw)`: A utility function to parse a raw string of command-line flags into a list of individual flag strings, handling quoting and escaping. This is crucial for processing compiler and linker flags.

7. **Generating CMake Generator Arguments:**
   - `cmake_get_generator_args(env)`:  Takes the Meson environment as input and returns the appropriate CMake generator argument (e.g., `['-G', 'Ninja']`) based on the selected Meson backend.

8. **Converting Definitions to CMake Arguments:**
   - `cmake_defines_to_args(raw, permissive=False)`: Converts a list of dictionaries (where each dictionary represents a set of CMake definitions) into a list of CMake command-line arguments (e.g., `['-DMyVar=value']`). It also checks against the `blacklist_cmake_defs` and issues warnings for unsupported definitions.

9. **Checking and Filtering CMake Arguments:**
   - `check_cmake_args(args)`:  Filters a list of existing CMake arguments, removing any arguments that attempt to set blacklisted definitions. This acts as a safeguard against users trying to override Meson's controlled settings.

10. **Representing CMake Project Structure:**
    - `CMakeInclude`: Represents an include directory path, indicating whether it's a system include directory.
    - `CMakeFileGroup`:  Represents a group of source files within a CMake target, along with their associated compiler flags, defines, and include paths.
    - `CMakeTarget`: Represents a CMake target (like an executable or library), storing information about its artifacts, source and build directories, name, link libraries, link flags, and associated file groups.
    - `CMakeProject`: Represents a CMake project, containing a list of CMake targets.
    - `CMakeConfiguration`: Represents a CMake build configuration (e.g., Debug, Release), containing a list of CMake projects. These classes are used to parse and represent the structure of a CMake project, likely obtained from CMake's file system or internal data structures.

11. **Managing Target-Specific Options:**
    - `SingleTargetOptions`:  Stores options specific to a single CMake target, such as compiler arguments, linker arguments, and install status overrides.
    - `TargetOptions`: Manages a collection of `SingleTargetOptions`, allowing for global options that apply to all targets and target-specific overrides. This provides a mechanism to customize the CMake build process on a granular level.

**Relationship to Reverse Engineering:**

This code, while part of the *build* process of Frida, has indirect relevance to reverse engineering:

* **Understanding Frida's Build:** To effectively reverse engineer Frida itself, understanding how it's built is crucial. This code reveals how Frida integrates with CMake, a common build system used for native projects. Knowing the compiler and linker flags used during Frida's build (which this code helps manage) can provide insights into its internal workings and optimizations.
* **Analyzing Target Binaries:** Frida is used to instrument and analyze other processes. When targeting a process built with CMake, understanding CMake's structure and configuration (as reflected in this code) can aid in understanding the target's layout, dependencies, and build process. This knowledge can be helpful when hooking functions, analyzing memory, and understanding the target's architecture.
* **Dynamic Analysis and Build Systems:**  Reverse engineers often need to rebuild parts of a target application or create custom instrumentation. Knowing how the target was originally built (potentially using CMake) and understanding the tools and flags involved is essential for replicating the build environment and avoiding inconsistencies.

**Example of Relationship to Reverse Engineering:**

Imagine you are reverse engineering a closed-source Android application that you suspect uses native libraries built with CMake. If you were to use Frida to hook into functions within those libraries, understanding how those libraries were linked (e.g., static vs. shared, specific linker flags) could be crucial. This `common.py` file, by managing CMake's linker settings, provides insights into the linking process that ultimately shapes the binary you're analyzing with Frida. For example, knowing if `-fvisibility=hidden` was used (a common compiler flag managed through CMake) could inform your approach to symbol resolution during dynamic analysis.

**Binary Underlying, Linux, Android Kernel & Framework Knowledge:**

* **Compiler and Linker Flags:** The code directly deals with compiler flags (in `CMakeFileGroup.flags`) and linker flags (in `CMakeTarget.link_flags`). These flags directly impact the generated binary's structure, optimizations, and linking behavior. For example, flags like `-O2` (optimization level), `-fPIC` (position-independent code for shared libraries), `-Wall` (enable all warnings), and `-ldl` (link against the dynamic linker library) are common examples that directly relate to the underlying binary and how it interacts with the operating system.
* **Linux/Android Shared Libraries:** The concept of linking libraries (`CMakeTarget.link_libraries`) is fundamental to how software works on Linux and Android. Understanding which libraries a target depends on and how they are linked (static or dynamic) is crucial for reverse engineering.
* **Android Framework (Indirect):** While this code doesn't directly interact with the Android framework, Frida is heavily used on Android. The build process managed by this code ultimately produces the Frida tools that can then interact with the Android framework for dynamic analysis.
* **Sysroot (Implicit):** The `blacklist_cmake_defs` includes `MESON_CMAKE_SYSROOT`. The sysroot is a crucial concept in cross-compilation, indicating the root directory of the target system's libraries and headers. By blacklisting this, Meson likely manages the sysroot internally to ensure consistent cross-compilation for different target platforms (including Android).

**Example involving Binary Underlying, Linux, Android:**

Let's say Frida is being built for an Android target. Meson will use this `common.py` code to configure CMake. The `cmake_defines_to_args` function might add definitions like `-DANDROID_ABI=arm64-v8a` or `-DANDROID_PLATFORM=android-29`. These definitions directly influence how the C/C++ compiler and linker behave, ensuring that the generated Frida binaries are compatible with the Android ABI and API level. The linker flags managed here would ensure that Frida can dynamically link against necessary Android system libraries when it runs on the target device.

**Logical Inference (Hypothetical Input & Output):**

**Hypothetical Input:**

Let's assume the `env.coredata.options` in `cmake_is_debug(env)` has:
```python
{
    OptionKey('buildtype'): 'release',
    OptionKey('b_vscrt'): OptionValue('mtd')
}
```

**Logical Inference:**

The `cmake_is_debug` function would execute as follows:

1. `OptionKey('b_vscrt') in env.coredata.options` evaluates to `True`.
2. `is_debug = env.coredata.get_option(OptionKey('buildtype')) == 'debug'` evaluates to `False` (because `buildtype` is 'release').
3. `env.coredata.options[OptionKey('b_vscrt')].value in {'mdd', 'mtd'}` evaluates to `True` (because `b_vscrt` is 'mtd').
4. Therefore, `is_debug` is set to `True`.
5. The function returns `True`.

**Output:**

The function `cmake_is_debug` would return `True`, indicating a debug build despite the `buildtype` being 'release'. This highlights how the `b_vscrt` option can override the default `buildtype` for determining debug status, particularly relevant for Visual Studio projects where different runtime library configurations imply debug or release.

**User or Programming Common Usage Errors:**

1. **Trying to set blacklisted CMake definitions:** A user might try to pass a custom CMake argument like `-DCMAKE_TOOLCHAIN_FILE=/path/to/my/toolchain.cmake` when configuring the Frida build. The `check_cmake_args` function would detect this and issue a warning, effectively ignoring the user's attempt to set the toolchain file directly, as Meson intends to manage this aspect. This can lead to confusion if the user expects their custom toolchain to be used.

2. **Providing incorrect data types to `cmake_defines_to_args`:**  If a user (or a part of the Meson build system) attempts to pass a non-string, non-integer, non-float, non-boolean value as a CMake definition, the `cmake_defines_to_args` function will raise a `MesonException`. For example:
   ```python
   cmake_defines_to_args([{'MY_LIST': [1, 2, 3]}])  # This would cause an error
   ```
   The error message would inform the user about the unsupported data type, guiding them to provide valid CMake definition values.

**User Operation to Reach This Code (Debugging Clues):**

A user might end up examining this code in the following scenarios, typically as part of debugging a Frida build issue:

1. **Compilation Errors Related to CMake:** If the Frida build process fails during the CMake configuration or generation stage, the error messages might point to issues with CMake arguments or definitions. The user or a Frida developer might then investigate how Meson is generating these arguments by looking at files like `common.py`.

2. **Unexpected Build Behavior with Custom CMake Options:** If a user attempts to pass custom CMake options (using Meson's mechanisms) and these options don't seem to be taking effect, they might delve into this code to understand how Meson handles and potentially filters CMake arguments. The `blacklist_cmake_defs` and `check_cmake_args` functions would be points of interest.

3. **Debugging Cross-Compilation Issues:** Frida supports cross-compilation for various target platforms (like Android). If there are problems with the cross-compilation setup, such as incorrect toolchain selection or sysroot configuration, developers might examine how Meson interacts with CMake to manage these aspects, leading them to this file. The blacklisting of `CMAKE_TOOLCHAIN_FILE` is a strong indicator of Meson's role in managing the toolchain.

4. **Understanding Frida's Internal Build System:**  A developer contributing to Frida or deeply investigating its build system might explore this code to understand how Meson integrates with CMake and how the build process is structured.

**Steps to reach this code as a debugging line:**

1. **User attempts to build Frida:** They run the Meson configuration command (e.g., `meson setup build`).
2. **Meson configures the build system:**  Meson analyzes the project's `meson.build` files and determines that CMake needs to be involved (either for Frida itself or its dependencies).
3. **Meson invokes CMake:** Meson calls the CMake executable, passing a set of arguments to configure the CMake project.
4. **Error occurs during CMake configuration:**  CMake might fail due to missing dependencies, incorrect arguments, or other issues. The error message from CMake might be visible in the console output.
5. **User investigates Meson's CMake interaction:** To understand *why* CMake failed, the user or developer might look into Meson's source code to see how it generates the CMake arguments. They might trace the execution flow and find that `frida/releng/meson/mesonbuild/cmake/common.py` is responsible for generating and managing these arguments.
6. **Examining `common.py`:** The user would then open this file to understand the functions like `cmake_defines_to_args`, `cmake_get_generator_args`, and the blacklisting logic to identify potential causes of the CMake configuration failure.

In essence, this `common.py` file acts as a bridge between Meson's build system and CMake, providing the necessary utilities to manage CMake projects within the broader Frida build process. Understanding its functionality is crucial for anyone working with Frida's build system or debugging related issues.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/cmake/common.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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