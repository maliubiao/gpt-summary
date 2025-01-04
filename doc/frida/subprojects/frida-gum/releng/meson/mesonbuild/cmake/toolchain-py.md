Response:
Let's break down the thought process to analyze this Python code and generate the comprehensive explanation.

**1. Initial Understanding - What is the Core Purpose?**

The first thing I notice is the file path `frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/toolchain.py`. Keywords here are "frida," "cmake," and "toolchain."  This immediately suggests that the code is responsible for generating CMake toolchain files for the Frida project. Frida is a dynamic instrumentation toolkit, and CMake is a build system generator. A toolchain file in CMake specifies the compilers, linkers, and other tools to use for building software. So, the core purpose is to bridge the Meson build system (which Frida uses) and CMake for subprojects or dependencies.

**2. Decomposition by Class and Method:**

The code is well-structured with a `CMakeToolchain` class. I'll go through the class and its methods to understand the workflow:

*   `__init__`: This is the constructor. It takes various arguments related to the build environment (environment, machine architecture, build directory, etc.) and initializes the state of the `CMakeToolchain` object. It also determines whether compiler tests should be skipped.

*   `write()`: This method generates the actual CMake toolchain file content and writes it to disk. It also writes a CMake cache file.

*   `get_cmake_args()`: This method returns a list of CMake arguments, including the path to the generated toolchain file.

*   `_print_vars()`: A utility method for formatting CMake variable settings.

*   `generate()`: This is where the main logic for generating the toolchain file content resides. It includes setting compiler paths, system information, and potentially including a user-provided toolchain file.

*   `generate_cache()`:  Generates content for the CMake cache file, primarily when compiler tests are skipped.

*   `get_defaults()`:  Determines default CMake variable values based on the target platform and compiler information. This includes mapping Meson system names to CMake system names and setting compiler executables.

*   `is_cmdline_option()`: A helper to determine if a string is a command-line option for a given compiler.

*   `update_cmake_compiler_state()`:  This is a more complex method. It runs CMake in a temporary directory to gather information about the available compilers and their properties. This is essential when skipping compiler tests.

**3. Identifying Key Functionalities and their Relevance:**

As I go through the methods, I'll note down the key functionalities:

*   **Toolchain File Generation:**  The core purpose. Involves setting compiler paths, target system information, and custom user settings.

*   **Compiler Handling:**  Extracting compiler executables, setting appropriate CMake variables (e.g., `CMAKE_C_COMPILER`).

*   **Cross-Compilation Support:**  The logic for setting `CMAKE_SYSTEM_NAME` and `CMAKE_SYSTEM_PROCESSOR` is crucial for cross-compilation scenarios.

*   **Skipping Compiler Tests:**  The `skip_check` logic and the `update_cmake_compiler_state()` method deal with optimizing the build process by potentially skipping expensive compiler tests.

*   **User Customization:**  The ability to include a user-provided CMake toolchain file allows for further customization.

**4. Connecting to Reverse Engineering Concepts:**

Now, I start thinking about how these functionalities relate to reverse engineering:

*   **Target Environment Setup:** Reverse engineers often need to build tools or libraries for specific target architectures (e.g., Android, embedded Linux). This toolchain file generation directly facilitates that by configuring CMake for the correct target.

*   **Compiler Manipulation:**  Knowing how the code sets compiler paths can be relevant if a reverse engineer wants to use a specific compiler version or a custom compiler toolchain.

*   **Understanding Build Processes:**  Reverse engineers often encounter software built with CMake. Understanding how toolchain files work helps in comprehending the build process and potential build-time configurations.

*   **Dynamic Instrumentation Context:** Given that this code is within Frida, the connection to dynamic instrumentation is direct. Frida injects code into running processes. To build Frida or extensions for specific target platforms, the correct toolchain setup is essential.

**5. Identifying Binary/OS/Kernel Aspects:**

Next, I look for code parts that touch upon lower-level concepts:

*   **`CMAKE_SYSTEM_NAME` and `CMAKE_SYSTEM_PROCESSOR`:** These directly relate to the target operating system and CPU architecture.

*   **`CMAKE_SYSROOT`:** This is fundamental for cross-compilation, pointing to the root directory of the target system's libraries and headers.

*   **Compiler Executables:**  The code deals with locating and specifying compiler executables, which are binary files.

*   **Android Context:** The `SYSTEM_MAP` includes "android," indicating specific handling for Android targets.

**6. Logical Reasoning and Examples:**

I consider the logical flow and construct examples:

*   **Skipping Compiler Tests:**  If `CMakeSkipCompilerTest.ALWAYS` is set, the code will proactively gather compiler information to avoid running tests later. The example shows the conditional output based on this setting.

*   **User Toolchain Inclusion:**  If a user provides a custom toolchain, it's included at the end. The example demonstrates how this layering works.

**7. User Errors and Debugging:**

I think about common mistakes:

*   **Incorrect Paths:**  Specifying wrong paths for compilers or user toolchain files is a likely error.

*   **Mismatched Architectures:** Trying to build for the wrong architecture.

*   **Missing Dependencies:** If the target system's SDK isn't properly configured, the build will fail.

Then, I trace back how a user might reach this code:

*   A user initiates a Meson build for a Frida component.
*   Meson detects a CMake subproject or dependency.
*   Meson calls this `toolchain.py` script to generate the necessary CMake configuration.

**8. Refinement and Organization:**

Finally, I organize the information logically, using headings and bullet points to create a clear and comprehensive explanation, ensuring all aspects of the prompt are addressed. I review the generated text to ensure accuracy and clarity. I make sure the examples are concrete and illustrative.

This iterative process of understanding the core purpose, breaking down the code, identifying key functionalities, connecting to relevant concepts, and constructing examples allows for a thorough and informative analysis.
This Python code file, `toolchain.py`, is part of the Frida dynamic instrumentation toolkit's build system, specifically within the Meson build system's integration with CMake. Its primary function is to **generate CMake toolchain files**.

Here's a breakdown of its functionalities:

**Core Functionality: Generating CMake Toolchain Files**

The main purpose of this code is to create files that inform CMake about the compilers, linkers, and other build tools it should use when building a CMake-based subproject or dependency within a larger Meson project. This is crucial for cross-compilation or when specific build environments are required.

**Key Features and Functionalities:**

1. **Initialization (`__init__`)**:
    *   Receives information about the build environment, including the CMake executor (`cmakebin`), the overall Meson environment (`env`), the target machine architecture (`for_machine`), the execution scope (whether it's for a subproject or a dependency), the build directory (`build_dir`), and an optional preload file.
    *   Stores this information as attributes.
    *   Constructs the paths for the generated toolchain file (`CMakeMesonToolchainFile.cmake`) and the CMake cache file (`CMakeCache.txt`).
    *   Retrieves machine-specific configurations (like system information, properties, compiler details, CMake variables, and cached CMake state) from the Meson environment.
    *   Initializes a dictionary `variables` with default CMake variable settings.
    *   Determines whether to skip CMake's compiler tests based on user configuration.

2. **Writing Toolchain and Cache Files (`write`)**:
    *   Creates the directory for the toolchain file if it doesn't exist.
    *   Calls the `generate()` method to create the content of the toolchain file.
    *   Writes the generated content to `CMakeMesonToolchainFile.cmake`.
    *   Calls the `generate_cache()` method to create the content of the CMake cache file.
    *   Writes the generated cache content to `CMakeCache.txt`.
    *   Logs the path of the generated toolchain file.

3. **Generating CMake Arguments (`get_cmake_args`)**:
    *   Returns a list of CMake command-line arguments.
    *   Crucially, includes the `-DCMAKE_TOOLCHAIN_FILE=` argument, pointing CMake to the generated toolchain file.
    *   Optionally includes `-DMESON_PRELOAD_FILE=` if a preload file is specified.

4. **Generating Toolchain File Content (`generate`)**:
    *   Starts with a header indicating it's an automatically generated file.
    *   Includes the content of a preload file if specified.
    *   **Handles Skipping Compiler Checks**: If configured to skip compiler checks, it includes pre-existing CMake compiler state variables in the toolchain file to avoid CMake running its own compiler checks.
    *   **Sets Meson-Defined Variables**: Includes CMake variable settings derived from the Meson machine configuration (e.g., target architecture, compiler paths).
    *   **Includes User-Provided Toolchain File**: If the user has specified a custom CMake toolchain file, it includes that file using CMake's `include()` command, allowing users to further customize the build environment.

5. **Generating Cache File Content (`generate_cache`)**:
    *   Only generates content if compiler checks are skipped.
    *   Iterates through the cached CMake variables and writes them to the file in the format `name:type=value`.

6. **Getting Default CMake Variables (`get_defaults`)**:
    *   Determines default values for various CMake variables.
    *   **Cross-Compilation Handling**: Specifically sets `CMAKE_SYSTEM_NAME` and `CMAKE_SYSTEM_PROCESSOR` when cross-compiling, mapping Meson's system names to CMake's conventions.
    *   Sets `CMAKE_SIZEOF_VOID_P` based on the target architecture's bitness.
    *   Sets `CMAKE_SYSROOT` if specified in the Meson properties, which is vital for cross-compilation.
    *   **Compiler Path Handling**: Sets CMake compiler variables (e.g., `CMAKE_C_COMPILER`, `CMAKE_CXX_COMPILER`) based on the compilers configured in the Meson environment. It handles compiler launchers and distinguishes between the compiler executable and potential wrapper scripts.

7. **Checking for Command-Line Options (`is_cmdline_option`)**:
    *   A utility method to determine if a given string is likely a command-line option for a compiler based on its syntax (e.g., `-` for GCC/Clang, `/` for MSVC).

8. **Updating CMake Compiler State (`update_cmake_compiler_state`)**:
    *   This is a more involved process for when CMake compiler checks are skipped.
    *   It checks if compiler information for all languages is already cached.
    *   If not, it generates a minimal `CMakeLists.txt` file.
    *   It then runs CMake in a temporary directory **once** with the generated temporary toolchain file to get CMake to probe the compilers and determine their properties.
    *   It uses a `CMakeTraceParser` to parse the output of this CMake run and extract the relevant compiler information and cached variables.
    *   Finally, it updates the internal CMake cache state with the gathered information.

**Relationship to Reverse Engineering:**

This code is directly relevant to reverse engineering in several ways:

*   **Target Environment Setup**: Reverse engineers often need to build tools or libraries to run on specific target platforms (e.g., Android, embedded Linux). This script ensures that when a Frida module or extension has a CMake dependency, it's built for the correct target architecture and operating system. By configuring the toolchain, it ensures that the compiled code is compatible with the intended target environment.

*   **Cross-Compilation**: Reverse engineers frequently work with embedded systems or mobile platforms that have different architectures than their development machines. This script is essential for setting up cross-compilation environments, where code is compiled on one machine but intended to run on another with a different architecture.

*   **Understanding Build Processes**: When analyzing software, understanding the build process is crucial. This script reveals how Frida integrates with CMake, how toolchain files are used, and how compiler settings are configured. This knowledge can be valuable when reverse engineering software built with similar tools.

*   **Dynamic Instrumentation on Specific Platforms**: Frida is a dynamic instrumentation toolkit. To use Frida on different platforms (like Android), the Frida components themselves need to be built for those platforms. This script is a key part of ensuring that the CMake-based parts of Frida are built correctly for the target platform where instrumentation will occur.

**Examples Connecting to Reverse Engineering:**

*   **Scenario: Building a Frida gadget for an ARM Android device.**
    *   Meson, when building Frida for Android, will use this `toolchain.py` script.
    *   The script will set `CMAKE_SYSTEM_NAME` to "Android" and `CMAKE_SYSTEM_PROCESSOR` to "arm" (or "aarch64").
    *   It will also set the paths to the Android NDK's compilers (like `aarch64-linux-android-clang`).
    *   This ensures that any CMake-based parts of the Frida gadget are compiled with the correct cross-compilation toolchain for ARM Android.

*   **Scenario: Reverse engineering a library on a custom embedded Linux system.**
    *   If the library uses CMake for its build system, and you're building tools to interact with this library, you might need to understand how its toolchain is configured.
    *   This script demonstrates the principles of how a toolchain file ties together the target system information and the compiler paths.

**Binary, Linux, Android Kernel & Framework Knowledge:**

*   **Binary Level**: The script directly deals with the paths to compiler executables and linkers, which are binary files. The `CMAKE_SIZEOF_VOID_P` setting is a low-level detail related to the memory architecture (32-bit vs. 64-bit).

*   **Linux**: The `SYSTEM_MAP` dictionary includes "linux," indicating specific handling for Linux targets. The concept of a sysroot (`CMAKE_SYSROOT`) is fundamental in Linux cross-compilation.

*   **Android Kernel & Framework**:
    *   The "android" entry in `SYSTEM_MAP` signifies Android-specific configuration.
    *   When building for Android, this script would interact with the Android NDK (Native Development Kit), which provides the toolchain (compilers, linkers, headers, libraries) for building native code for Android. The paths to these NDK tools are set through this script.
    *   The `CMAKE_SYSTEM_NAME` being set to "Android" is crucial for CMake to understand it's targeting the Android environment.

**Logical Reasoning with Hypothetical Input/Output:**

**Hypothetical Input:**

*   `env.is_cross_build(when_building_for=self.for_machine)` is `True`.
*   `self.minfo.system` is "linux".
*   `self.minfo.cpu_family` is "arm".
*   The Meson environment has configured the C compiler to be `/opt/my_arm_toolchain/bin/arm-linux-gnueabihf-gcc`.

**Logical Output (within the `get_defaults` method):**

```python
defaults = {
    'CMAKE_SYSTEM_NAME': ['Linux'],
    'CMAKE_SYSTEM_PROCESSOR': ['arm'],
    'CMAKE_SIZEOF_VOID_P': ['4'],  # Assuming 32-bit ARM
    'CMAKE_C_COMPILER': ['/opt/my_arm_toolchain/bin/arm-linux-gnueabihf-gcc'],
    # ... other potential defaults
}
```

**Explanation:**

The `get_defaults` method, recognizing a cross-compilation scenario for Linux on ARM, would set `CMAKE_SYSTEM_NAME` and `CMAKE_SYSTEM_PROCESSOR` accordingly. It would also extract the C compiler path from the Meson environment and set the `CMAKE_C_COMPILER` variable. The `CMAKE_SIZEOF_VOID_P` would be set based on the assumed bitness of the ARM target.

**Common User/Programming Errors and Examples:**

1. **Incorrect Compiler Paths:**
    *   **Error:**  The user has misconfigured the Meson environment, and the compiler paths are wrong (e.g., pointing to a non-existent executable).
    *   **Result:** CMake will fail to find the compiler when it tries to build the project, leading to build errors.
    *   **Example:**  `self.compilers['c'].get_exelist()` returns `['/opt/wrong_path/gcc']`, which doesn't exist. The generated toolchain file will contain `set(CMAKE_C_COMPILER "/opt/wrong_path/gcc")`, causing CMake to fail.

2. **Mismatched Architectures:**
    *   **Error:** The user is trying to build a CMake subproject for an architecture that is not compatible with the configured compilers.
    *   **Result:** Compilation errors due to incompatible object files or libraries.
    *   **Example:**  Building for a 64-bit target but the toolchain points to 32-bit compilers, or vice versa.

3. **Missing Sysroot (for cross-compilation):**
    *   **Error:** When cross-compiling, the `CMAKE_SYSROOT` is not set or is pointing to an incorrect location.
    *   **Result:** CMake will not be able to find the target system's headers and libraries, leading to compilation and linking errors.
    *   **Example:** The user forgets to configure the `sys_root` property in the Meson machine file. The generated toolchain file will not have the `CMAKE_SYSROOT` variable set, causing build failures.

**User Operations Leading to This Code (Debugging Clues):**

1. **User Initiates a Meson Build:** The user runs a `meson build` command (or a similar command that triggers the Meson build process).

2. **Meson Detects a CMake Subproject or Dependency:** During the configuration phase, Meson encounters a `subproject()` or `dependency()` call in the `meson.build` file that refers to a CMake-based project.

3. **Meson Needs to Configure CMake:** Meson recognizes that it needs to invoke CMake to build this subproject or dependency.

4. **Toolchain File Generation:** Before calling CMake, Meson needs to generate a suitable toolchain file. This is where this `toolchain.py` script is executed.

5. **Script Execution:** Meson instantiates the `CMakeToolchain` class, passing in the relevant environment information.

6. **Toolchain File Creation:** The `write()` method of the `CMakeToolchain` instance is called, which in turn calls `generate()` to create the toolchain file content and writes it to disk.

7. **CMake Invocation:** Meson then calls the CMake executable, passing the path to the generated toolchain file using the `-DCMAKE_TOOLCHAIN_FILE` argument (obtained from `get_cmake_args()`).

**Debugging Scenario:**

If a user is encountering build errors within a CMake subproject in their Frida setup, and the errors suggest problems with compiler paths or target architecture, a developer would investigate the generated `CMakeMesonToolchainFile.cmake`. They would then look at this `toolchain.py` script to understand how that file is being generated and identify potential issues in the configuration logic or the input data being provided to the script. Examining the Meson log output related to CMake execution would also be crucial.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/cmake/toolchain.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

from pathlib import Path
from .traceparser import CMakeTraceParser
from ..envconfig import CMakeSkipCompilerTest
from .common import language_map, cmake_get_generator_args
from .. import mlog

import shutil
import typing as T
from enum import Enum
from textwrap import dedent

if T.TYPE_CHECKING:
    from .executor import CMakeExecutor
    from ..environment import Environment
    from ..compilers import Compiler
    from ..mesonlib import MachineChoice

class CMakeExecScope(Enum):
    SUBPROJECT = 'subproject'
    DEPENDENCY = 'dependency'

class CMakeToolchain:
    def __init__(self, cmakebin: 'CMakeExecutor', env: 'Environment', for_machine: MachineChoice, exec_scope: CMakeExecScope, build_dir: Path, preload_file: T.Optional[Path] = None) -> None:
        self.env = env
        self.cmakebin = cmakebin
        self.for_machine = for_machine
        self.exec_scope = exec_scope
        self.preload_file = preload_file
        self.build_dir = build_dir
        self.build_dir = self.build_dir.resolve()
        self.toolchain_file = build_dir / 'CMakeMesonToolchainFile.cmake'
        self.cmcache_file = build_dir / 'CMakeCache.txt'
        self.minfo = self.env.machines[self.for_machine]
        self.properties = self.env.properties[self.for_machine]
        self.compilers = self.env.coredata.compilers[self.for_machine]
        self.cmakevars = self.env.cmakevars[self.for_machine]
        self.cmakestate = self.env.coredata.cmake_cache[self.for_machine]

        self.variables = self.get_defaults()
        self.variables.update(self.cmakevars.get_variables())

        # Determine whether CMake the compiler test should be skipped
        skip_status = self.properties.get_cmake_skip_compiler_test()
        self.skip_check = skip_status == CMakeSkipCompilerTest.ALWAYS
        if skip_status == CMakeSkipCompilerTest.DEP_ONLY and self.exec_scope == CMakeExecScope.DEPENDENCY:
            self.skip_check = True
        if not self.properties.get_cmake_defaults():
            self.skip_check = False

        assert self.toolchain_file.is_absolute()

    def write(self) -> Path:
        if not self.toolchain_file.parent.exists():
            self.toolchain_file.parent.mkdir(parents=True)
        self.toolchain_file.write_text(self.generate(), encoding='utf-8')
        self.cmcache_file.write_text(self.generate_cache(), encoding='utf-8')
        mlog.cmd_ci_include(self.toolchain_file.as_posix())
        return self.toolchain_file

    def get_cmake_args(self) -> T.List[str]:
        args = ['-DCMAKE_TOOLCHAIN_FILE=' + self.toolchain_file.as_posix()]
        if self.preload_file is not None:
            args += ['-DMESON_PRELOAD_FILE=' + self.preload_file.as_posix()]
        return args

    @staticmethod
    def _print_vars(vars: T.Dict[str, T.List[str]]) -> str:
        res = ''
        for key, value in vars.items():
            res += 'set(' + key
            for i in value:
                res += f' "{i}"'
            res += ')\n'
        return res

    def generate(self) -> str:
        res = dedent('''\
            ######################################
            ###  AUTOMATICALLY GENERATED FILE  ###
            ######################################

            # This file was generated from the configuration in the
            # relevant meson machine file. See the meson documentation
            # https://mesonbuild.com/Machine-files.html for more information

            if(DEFINED MESON_PRELOAD_FILE)
                include("${MESON_PRELOAD_FILE}")
            endif()

        ''')

        # Escape all \ in the values
        for key, value in self.variables.items():
            self.variables[key] = [x.replace('\\', '/') for x in value]

        # Set compiler
        if self.skip_check:
            self.update_cmake_compiler_state()
            res += '# CMake compiler state variables\n'
            for lang, vars in self.cmakestate:
                res += f'# -- Variables for language {lang}\n'
                res += self._print_vars(vars)
                res += '\n'
            res += '\n'

        # Set variables from the current machine config
        res += '# Variables from meson\n'
        res += self._print_vars(self.variables)
        res += '\n'

        # Add the user provided toolchain file
        user_file = self.properties.get_cmake_toolchain_file()
        if user_file is not None:
            res += dedent('''
                # Load the CMake toolchain file specified by the user
                include("{}")

            '''.format(user_file.as_posix()))

        return res

    def generate_cache(self) -> str:
        if not self.skip_check:
            return ''

        res = ''
        for name, v in self.cmakestate.cmake_cache.items():
            res += f'{name}:{v.type}={";".join(v.value)}\n'
        return res

    def get_defaults(self) -> T.Dict[str, T.List[str]]:
        defaults: T.Dict[str, T.List[str]] = {}

        # Do nothing if the user does not want automatic defaults
        if not self.properties.get_cmake_defaults():
            return defaults

        # Best effort to map the meson system name to CMAKE_SYSTEM_NAME, which
        # is not trivial since CMake lacks a list of all supported
        # CMAKE_SYSTEM_NAME values.
        SYSTEM_MAP: T.Dict[str, str] = {
            'android': 'Android',
            'linux': 'Linux',
            'windows': 'Windows',
            'freebsd': 'FreeBSD',
            'darwin': 'Darwin',
        }

        # Only set these in a cross build. Otherwise CMake will trip up in native
        # builds and thing they are cross (which causes TRY_RUN() to break)
        if self.env.is_cross_build(when_building_for=self.for_machine):
            defaults['CMAKE_SYSTEM_NAME'] = [SYSTEM_MAP.get(self.minfo.system, self.minfo.system)]
            defaults['CMAKE_SYSTEM_PROCESSOR'] = [self.minfo.cpu_family]

        defaults['CMAKE_SIZEOF_VOID_P'] = ['8' if self.minfo.is_64_bit else '4']

        sys_root = self.properties.get_sys_root()
        if sys_root:
            defaults['CMAKE_SYSROOT'] = [sys_root]

        def make_abs(exe: str) -> str:
            if Path(exe).is_absolute():
                return exe

            p = shutil.which(exe)
            if p is None:
                return exe
            return p

        # Set the compiler variables
        for lang, comp_obj in self.compilers.items():
            prefix = 'CMAKE_{}_'.format(language_map.get(lang, lang.upper()))

            exe_list = comp_obj.get_exelist()
            if not exe_list:
                continue

            if len(exe_list) >= 2 and not self.is_cmdline_option(comp_obj, exe_list[1]):
                defaults[prefix + 'COMPILER_LAUNCHER'] = [make_abs(exe_list[0])]
                exe_list = exe_list[1:]

            exe_list[0] = make_abs(exe_list[0])
            defaults[prefix + 'COMPILER'] = exe_list
            if comp_obj.get_id() == 'clang-cl':
                defaults['CMAKE_LINKER'] = comp_obj.get_linker_exelist()

        return defaults

    @staticmethod
    def is_cmdline_option(compiler: 'Compiler', arg: str) -> bool:
        if compiler.get_argument_syntax() == 'msvc':
            return arg.startswith('/')
        else:
            return arg.startswith('-')

    def update_cmake_compiler_state(self) -> None:
        # Check if all variables are already cached
        if self.cmakestate.languages.issuperset(self.compilers.keys()):
            return

        # Generate the CMakeLists.txt
        mlog.debug('CMake Toolchain: Calling CMake once to generate the compiler state')
        languages = list(self.compilers.keys())
        lang_ids = [language_map.get(x, x.upper()) for x in languages]
        cmake_content = dedent(f'''
            cmake_minimum_required(VERSION 3.7)
            project(CompInfo {' '.join(lang_ids)})
        ''')

        build_dir = Path(self.env.scratch_dir) / '__CMake_compiler_info__'
        build_dir.mkdir(parents=True, exist_ok=True)
        cmake_file = build_dir / 'CMakeLists.txt'
        cmake_file.write_text(cmake_content, encoding='utf-8')

        # Generate the temporary toolchain file
        temp_toolchain_file = build_dir / 'CMakeMesonTempToolchainFile.cmake'
        temp_toolchain_file.write_text(CMakeToolchain._print_vars(self.variables), encoding='utf-8')

        # Configure
        trace = CMakeTraceParser(self.cmakebin.version(), build_dir, self.env)
        self.cmakebin.set_exec_mode(print_cmout=False, always_capture_stderr=trace.requires_stderr())
        cmake_args = []
        cmake_args += trace.trace_args()
        cmake_args += cmake_get_generator_args(self.env)
        cmake_args += [f'-DCMAKE_TOOLCHAIN_FILE={temp_toolchain_file.as_posix()}', '.']
        rc, _, raw_trace = self.cmakebin.call(cmake_args, build_dir=build_dir, disable_cache=True)

        if rc != 0:
            mlog.warning('CMake Toolchain: Failed to determine CMake compilers state')
            return

        # Parse output
        trace.parse(raw_trace)
        self.cmakestate.cmake_cache = {**trace.cache}

        vars_by_file = {k.name: v for (k, v) in trace.vars_by_file.items()}

        for lang in languages:
            lang_cmake = language_map.get(lang, lang.upper())
            file_name = f'CMake{lang_cmake}Compiler.cmake'
            vars = vars_by_file.setdefault(file_name, {})
            vars[f'CMAKE_{lang_cmake}_COMPILER_FORCED'] = ['1']
            self.cmakestate.update(lang, vars)

"""

```