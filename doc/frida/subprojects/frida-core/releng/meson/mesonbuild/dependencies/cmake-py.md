Response:
Let's break down the thought process for analyzing this Python code for the Frida dynamic instrumentation tool.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `cmake.py` file, particularly its relation to reverse engineering, low-level details (Linux, Android kernels), logical reasoning, common user errors, and how a user might reach this code.

**2. Initial Code Scan and High-Level Understanding:**

* **Imports:** The imports immediately give clues about the file's purpose. `mesonlib`, `cmake`, `pathlib`, `os`, `shutil`, `textwrap`, `typing` all point towards a build system integration (Meson) dealing with CMake projects. `importlib.resources` suggests accessing embedded files.
* **Class `CMakeDependency`:** This is the core of the file. The name itself strongly suggests it's about handling dependencies that are managed by CMake.
* **Methods:**  A quick scan of the methods reveals actions like `_get_cmake_info`, `_preliminary_find_check`, `_detect_dep`, `_call_cmake`, `get_variable`. These suggest steps involved in finding, configuring, and interacting with CMake-based dependencies.

**3. Deeper Dive into Key Methods:**

* **`__init__`:** This is the constructor. It sets up the environment, finds the CMake executable, and initiates the dependency detection process. The logic around `language_list` hints at handling different programming languages supported by CMake.
* **`_get_cmake_info`:**  This method is crucial for understanding how the script gathers information about the CMake installation on the system. It tries different CMake generators, runs CMake with a special "trace" file, and parses the output to extract paths, architectures, etc.
* **`_preliminary_find_check`:**  This is an optimization to quickly check if a CMake dependency is likely to exist before running the full CMake configuration. It searches in common locations based on the dependency name.
* **`_detect_dep`:** This is the heart of the dependency resolution. It runs CMake's `find_package` functionality, parsing the output (especially the trace output) to determine if the dependency was found, its version, include directories, libraries, etc. The logic for handling CMake "modules" (targets) is significant here.
* **`_call_cmake`:**  This is a helper function to actually execute the CMake command with specific arguments and a CMakeLists.txt file.
* **`get_variable`:** This method allows retrieval of CMake variables defined during the dependency detection process.

**4. Connecting to Reverse Engineering:**

* **Dynamic Instrumentation (Frida Context):** Recognizing that this code is *part* of Frida is key. Frida injects into running processes. CMake is used to build native components that Frida might rely on. Thus, understanding how Frida's build process handles CMake dependencies is relevant to understanding Frida's overall architecture and potential extension points.
* **Native Libraries:**  CMake is often used to build native libraries (C, C++). These libraries are precisely what Frida might interact with and instrument within a target process.
* **Symbols and Debugging:** While not explicitly in *this* file, the process of finding and linking against libraries is fundamental to reverse engineering and debugging. Frida needs to know where these libraries are and how to interact with their functions.

**5. Identifying Low-Level Aspects:**

* **Linux/Android:** The code contains checks for operating systems (`is_windows()`, `machine.is_darwin()`), environment variables (`os.environ`), and path separators (`os.pathsep`). The search paths (`/lib`, `/usr/lib`, etc.) are common in Linux/Unix environments. The mention of Android isn't explicit in the code, but Frida's support for Android implies this dependency management might be used when building Frida's Android components.
* **Kernel/Framework:**  The code itself doesn't directly interact with the kernel. However, the *libraries* built by CMake (which this script helps find) might interact with the kernel or Android framework. For example, a Frida gadget library might use Android NDK APIs.
* **Binary:** The output of the CMake process is the creation of compiled binaries (shared libraries, executables). This script is a step in the process of building those binaries.

**6. Logical Reasoning and Assumptions:**

* **Input:**  The script takes a dependency name, environment information, and optional keyword arguments. A key input is the `CMakeLists.txt` file (even if a temporary one is generated).
* **Output:** The primary output is a `CMakeDependency` object containing information about the found dependency (or an indication that it wasn't found). This includes include paths, library paths, and compile/link arguments.
* **Assumptions:** The script assumes CMake is installed and accessible in the system's PATH. It also assumes the target CMake project follows standard conventions for `find_package`.

**7. Identifying User Errors:**

* **Incorrect Dependency Name:** Misspelling the dependency name or using the wrong capitalization.
* **Missing CMake or Development Packages:** The underlying problem might be that CMake isn't installed, or the development headers/libraries for the dependency are missing.
* **Incorrect CMake Arguments:** Providing wrong or incompatible `cmake_args`.
* **Conflicting Dependencies:** Having multiple versions of the same dependency installed.
* **Missing `CMakeLists.txt` or Misconfigured Project:** If the target CMake project is malformed, `find_package` will fail.

**8. Tracing User Operations:**

The steps to reach this code are part of the Frida build process using Meson:

1. **User initiates a build:**  The user runs a command like `meson build` or `ninja`.
2. **Meson analyzes the `meson.build` file:** Meson reads the project's build definition.
3. **Dependency declaration:** The `meson.build` file likely contains a `dependency()` call specifying a CMake-based dependency.
4. **Meson calls the `CMakeDependencyFactory`:** Meson recognizes the dependency type as "cmake" and uses the factory to create a `CMakeDependency` object.
5. **The `CMakeDependency` constructor is called:** This is where the `cmake.py` code starts executing.

**Self-Correction/Refinement during Analysis:**

* **Initial thought:** Focus heavily on the reverse engineering aspects *within* this file.
* **Correction:** Realize that this file is about *building* the tools used for reverse engineering (Frida). Its connection to reverse engineering is indirect but foundational.
* **Initial thought:** Treat the code as isolated.
* **Correction:** Understand that this code is a *module* within the larger Meson build system and Frida project. Its behavior is influenced by the Meson environment and the target CMake project.
* **Initial thought:** Overlook the significance of the CMake trace output.
* **Correction:** Recognize that the trace output is crucial for extracting information about the dependency.

By following this detailed process of code examination, import analysis, method understanding, contextualization within Frida, and considering potential user errors, we can arrive at a comprehensive explanation of the `cmake.py` file's functionality.
This Python code file, `cmake.py`, is a crucial part of Frida's build system, specifically responsible for handling dependencies that are managed by CMake. Let's break down its functionalities:

**Core Functionality: Managing CMake Dependencies**

The primary purpose of this file is to allow the Meson build system (which Frida uses) to find and integrate dependencies that are built using CMake. It essentially acts as a bridge between Meson and CMake.

**Key Functionalities Explained:**

1. **Finding the CMake Executable:**
   - It uses the `CMakeExecutor` class to locate the CMake executable on the system. This is essential for interacting with CMake projects.
   - It handles cases where CMake is not found and raises an error if the dependency is required.

2. **Gathering CMake System Information:**
   - The `_get_cmake_info` method is responsible for extracting fundamental information about the CMake installation, such as:
     - Module search paths (where CMake looks for `Find<Package>.cmake` files).
     - The CMake root directory.
     - Supported architectures.
     - Common library search paths (like `lib`, `lib64`, `share`).
   - It achieves this by running CMake with a special "trace" file and parsing the output. This allows it to understand the system configuration from CMake's perspective.
   - It tries different CMake "generators" (like Ninja, Makefiles, Visual Studio) to ensure compatibility across various systems.

3. **Preliminary Dependency Check:**
   - The `_preliminary_find_check` method performs a quick, heuristic-based check to see if a dependency is likely to exist before running the full CMake `find_package` process.
   - It searches in common locations like module paths, library directories, and environment variables. This can speed up the build process by avoiding unnecessary CMake runs.

4. **Detecting Dependencies with CMake (`_detect_dep`):**
   - This is the core of the dependency detection logic. It uses CMake's `--find-package` mode to locate the specified dependency.
   - It generates a temporary `CMakeLists.txt` file that instructs CMake to find the package.
   - It parses the CMake trace output (stderr) to extract information about the found package, such as:
     - Whether the package was found (`PACKAGE_FOUND`).
     - The package version (`PACKAGE_VERSION`).
     - Include directories (`PACKAGE_INCLUDE_DIRS`).
     - Compiler definitions (`PACKAGE_DEFINITIONS`).
     - Libraries to link against (`PACKAGE_LIBRARIES`).
     - CMake "targets" (modern way of defining libraries and their properties).
   - It handles both "module mode" (using `find_package(ModuleName)`) and "config mode" (looking for `<Package>Config.cmake` files).
   - It attempts to automatically detect CMake targets if none are explicitly provided.
   - It maps the found information to Meson's dependency representation (compile arguments, link arguments).

5. **Handling CMake Modules (Targets):**
   - The code heavily emphasizes the use of CMake "imported targets." This is a more robust way of managing dependencies compared to relying solely on variables like `PACKAGE_LIBRARIES`.
   - It resolves CMake targets to their actual library files, include directories, and compile options.

6. **Managing Build Directories:**
   - It creates separate build directories for each CMake dependency under the `cmake_root_dir` to avoid conflicts.

7. **Customizing CMake Behavior:**
   - It allows users to pass custom CMake arguments (`cmake_args`) through the Meson dependency declaration.
   - It provides hooks for subclasses to customize module and component list mapping (`_map_module_list`, `_map_component_list`).

8. **Retrieving CMake Variables:**
   - The `get_variable` method allows retrieving the values of CMake variables defined during the dependency detection process.

**Relationship to Reverse Engineering:**

This code is indirectly related to reverse engineering. Frida is a powerful tool used extensively for dynamic instrumentation and reverse engineering. This `cmake.py` file plays a vital role in **building** Frida itself.

**Example:**

Imagine Frida needs to link against a native library (written in C/C++) that uses CMake for its build system, like `libuv`.

- When Meson processes Frida's `meson.build` file, it might encounter a declaration like:
  ```python
  libuv_dep = dependency('libuv', method='cmake')
  ```
- This will trigger the `CMakeDependencyFactory` and eventually create a `CMakeDependency` object.
- The `cmake.py` code will then:
  - Try to find the CMake executable.
  - Run CMake's `find_package(libuv)` or look for `libuvConfig.cmake`.
  - If found, it will parse the output to get the include directories and library files for `libuv`.
  - Meson will then use this information to correctly compile and link Frida against `libuv`.

**Binary Underlying, Linux, Android Kernel & Framework:**

- **Binary Underlying:** CMake's primary output is binary files (libraries, executables). This script is involved in the process of ensuring Frida can link against these binary dependencies.
- **Linux:** The code contains platform-specific logic (e.g., checking environment variables like `PATH` which are common in Linux/Unix systems). It also searches for libraries in typical Linux locations (`/lib`, `/usr/lib`).
- **Android Kernel & Framework:** While not explicitly dealing with the *kernel*, Frida often targets Android applications. These applications use the Android framework. If a Frida component depends on a library built with CMake that interacts with the Android framework (e.g., through the NDK), this script would be responsible for finding that library during Frida's build process. The script's ability to handle different architectures is also relevant for Android, which uses various CPU architectures (ARM, x86).

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

- Dependency name: `zlib`
- `CMakeLists.txt` of `zlib` is in `/path/to/zlib`
- User has set `CMAKE_PREFIX_PATH` environment variable to `/path/to/zlib/install`

**Logical Reasoning Flow:**

1. `_preliminary_find_check` might find `FindZLIB.cmake` or `zlibConfig.cmake` in the standard module paths or under `/path/to/zlib/install/lib/cmake/zlib`.
2. `_detect_dep` will run CMake in a temporary build directory with a `CMakeLists.txt` containing `find_package(zlib)`.
3. CMake will search for `zlib` based on its module paths and `CMAKE_PREFIX_PATH`.
4. If found, CMake will set variables like `ZLIB_INCLUDE_DIR` and `ZLIB_LIBRARIES`.
5. The `CMakeTraceParser` will extract these variables from the CMake output.

**Hypothetical Output:**

- `self.is_found` will be `True`.
- `self.compile_args` might contain `-I/path/to/zlib/install/include`.
- `self.link_args` might contain `/path/to/zlib/install/lib/libz.so` (or `.a` on some systems).

**User or Programming Common Usage Errors:**

1. **Incorrect Dependency Name:**
   - **Example:**  `dependency('zlib2', method='cmake')` when the actual CMake package name is `zlib`.
   - **Error:** CMake will fail to find the package, and the build will likely fail with an error like "CMake: invalid module zlib2 for ...".

2. **Missing CMake or Development Packages:**
   - **Example:** The user doesn't have the `zlib-dev` (or equivalent) package installed on their system.
   - **Error:** CMake will find the base `zlib` library but might be missing header files, leading to compilation errors later in the Frida build process. Or, `find_package` itself might fail.

3. **Incorrect `cmake_args`:**
   - **Example:** Passing a CMake argument that conflicts with Frida's build setup.
   - **Error:** This can lead to various CMake configuration or build errors that are hard to diagnose without understanding CMake well.

4. **Conflicting Dependencies:**
   - **Example:**  The user has multiple versions of a library installed, and CMake picks the wrong one.
   - **Error:**  This can lead to linking errors or runtime issues if the interfaces of the libraries are incompatible.

**User Operation Steps to Reach This Code (Debugging Scenario):**

Let's say a user is trying to build Frida from source and encounters an error related to a missing CMake dependency, like `glib-2.0`.

1. **User runs `meson setup build` or `ninja -C build`:** This initiates the build process.
2. **Meson processes the `meson.build` files:** It reads the build instructions, including dependency declarations.
3. **Meson encounters a `dependency('glib-2.0', method='cmake')`:**  This signals that the `cmake.py` module needs to be invoked.
4. **The `CMakeDependencyFactory` creates a `CMakeDependency` object:** The `__init__` method of `CMakeDependency` is executed.
5. **`_preliminary_find_check` and `_detect_dep` are called:** The code attempts to find the `glib-2.0` CMake package.
6. **If `glib-2.0` is not found:**
   - CMake will output errors in the trace.
   - The `CMakeTraceParser` will not find the necessary information.
   - `self.is_found` will be `False`.
   - Meson will report an error indicating that the dependency `glib-2.0` was not found.

**Debugging Clue:**  The error message reported by Meson will often point to the specific dependency that failed to be found via CMake. The user might then need to:

- Install the necessary development packages for `glib-2.0` (e.g., `libglib2.0-dev` on Debian/Ubuntu).
- Ensure that the `glib-2.0` CMake configuration files are in a location where CMake can find them (standard module paths or paths specified in `CMAKE_PREFIX_PATH`).
- If the dependency is in a non-standard location, the user might need to provide additional `cmake_args` to the `dependency()` call in the `meson.build` file to guide CMake.

In essence, this `cmake.py` file is a foundational piece of Frida's build process, allowing it to seamlessly integrate with the vast ecosystem of libraries built using CMake. Understanding its functionality is crucial for anyone contributing to Frida or troubleshooting build issues related to CMake dependencies.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2021 The Meson development team

from __future__ import annotations

from .base import ExternalDependency, DependencyException, DependencyTypeName
from ..mesonlib import is_windows, MesonException, PerMachine, stringlistify, extract_as_list
from ..cmake import CMakeExecutor, CMakeTraceParser, CMakeException, CMakeToolchain, CMakeExecScope, check_cmake_args, resolve_cmake_trace_targets, cmake_is_debug
from .. import mlog
import importlib.resources
from pathlib import Path
import functools
import re
import os
import shutil
import textwrap
import typing as T

if T.TYPE_CHECKING:
    from ..cmake import CMakeTarget
    from ..environment import Environment
    from ..envconfig import MachineInfo
    from ..interpreter.type_checking import PkgConfigDefineType

class CMakeInfo(T.NamedTuple):
    module_paths: T.List[str]
    cmake_root: str
    archs: T.List[str]
    common_paths: T.List[str]

class CMakeDependency(ExternalDependency):
    # The class's copy of the CMake path. Avoids having to search for it
    # multiple times in the same Meson invocation.
    class_cmakeinfo: PerMachine[T.Optional[CMakeInfo]] = PerMachine(None, None)
    # Version string for the minimum CMake version
    class_cmake_version = '>=3.4'
    # CMake generators to try (empty for no generator)
    class_cmake_generators = ['', 'Ninja', 'Unix Makefiles', 'Visual Studio 10 2010']
    class_working_generator: T.Optional[str] = None

    def _gen_exception(self, msg: str) -> DependencyException:
        return DependencyException(f'Dependency {self.name} not found: {msg}')

    def _main_cmake_file(self) -> str:
        return 'CMakeLists.txt'

    def _extra_cmake_opts(self) -> T.List[str]:
        return []

    def _map_module_list(self, modules: T.List[T.Tuple[str, bool]], components: T.List[T.Tuple[str, bool]]) -> T.List[T.Tuple[str, bool]]:
        # Map the input module list to something else
        # This function will only be executed AFTER the initial CMake
        # interpreter pass has completed. Thus variables defined in the
        # CMakeLists.txt can be accessed here.
        #
        # Both the modules and components inputs contain the original lists.
        return modules

    def _map_component_list(self, modules: T.List[T.Tuple[str, bool]], components: T.List[T.Tuple[str, bool]]) -> T.List[T.Tuple[str, bool]]:
        # Map the input components list to something else. This
        # function will be executed BEFORE the initial CMake interpreter
        # pass. Thus variables from the CMakeLists.txt can NOT be accessed.
        #
        # Both the modules and components inputs contain the original lists.
        return components

    def _original_module_name(self, module: str) -> str:
        # Reverse the module mapping done by _map_module_list for
        # one module
        return module

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None, force_use_global_compilers: bool = False) -> None:
        # Gather a list of all languages to support
        self.language_list: T.List[str] = []
        if language is None or force_use_global_compilers:
            compilers = None
            if kwargs.get('native', False):
                compilers = environment.coredata.compilers.build
            else:
                compilers = environment.coredata.compilers.host

            candidates = ['c', 'cpp', 'fortran', 'objc', 'objcxx']
            self.language_list += [x for x in candidates if x in compilers]
        else:
            self.language_list += [language]

        # Add additional languages if required
        if 'fortran' in self.language_list:
            self.language_list += ['c']

        # Ensure that the list is unique
        self.language_list = list(set(self.language_list))

        super().__init__(DependencyTypeName('cmake'), environment, kwargs, language=language)
        self.name = name
        self.is_libtool = False

        # Where all CMake "build dirs" are located
        self.cmake_root_dir = environment.scratch_dir

        # T.List of successfully found modules
        self.found_modules: T.List[str] = []

        # Store a copy of the CMake path on the object itself so it is
        # stored in the pickled coredata and recovered.
        #
        # TODO further evaluate always using MachineChoice.BUILD
        self.cmakebin = CMakeExecutor(environment, CMakeDependency.class_cmake_version, self.for_machine, silent=self.silent)
        if not self.cmakebin.found():
            msg = f'CMake binary for machine {self.for_machine} not found. Giving up.'
            if self.required:
                raise DependencyException(msg)
            mlog.debug(msg)
            return

        # Setup the trace parser
        self.traceparser = CMakeTraceParser(self.cmakebin.version(), self._get_build_dir(), self.env)

        cm_args = stringlistify(extract_as_list(kwargs, 'cmake_args'))
        cm_args = check_cmake_args(cm_args)
        if CMakeDependency.class_cmakeinfo[self.for_machine] is None:
            CMakeDependency.class_cmakeinfo[self.for_machine] = self._get_cmake_info(cm_args)
        cmakeinfo = CMakeDependency.class_cmakeinfo[self.for_machine]
        if cmakeinfo is None:
            raise self._gen_exception('Unable to obtain CMake system information')
        self.cmakeinfo = cmakeinfo

        package_version = kwargs.get('cmake_package_version', '')
        if not isinstance(package_version, str):
            raise DependencyException('Keyword "cmake_package_version" must be a string.')
        components = [(x, True) for x in stringlistify(extract_as_list(kwargs, 'components'))]
        modules = [(x, True) for x in stringlistify(extract_as_list(kwargs, 'modules'))]
        modules += [(x, False) for x in stringlistify(extract_as_list(kwargs, 'optional_modules'))]
        cm_path = stringlistify(extract_as_list(kwargs, 'cmake_module_path'))
        cm_path = [x if os.path.isabs(x) else os.path.join(environment.get_source_dir(), x) for x in cm_path]
        if cm_path:
            cm_args.append('-DCMAKE_MODULE_PATH=' + ';'.join(cm_path))
        if not self._preliminary_find_check(name, cm_path, self.cmakebin.get_cmake_prefix_paths(), environment.machines[self.for_machine]):
            mlog.debug('Preliminary CMake check failed. Aborting.')
            return
        self._detect_dep(name, package_version, modules, components, cm_args)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} {self.name}: {self.is_found} {self.version_reqs}>'

    def _get_cmake_info(self, cm_args: T.List[str]) -> T.Optional[CMakeInfo]:
        mlog.debug("Extracting basic cmake information")

        # Try different CMake generators since specifying no generator may fail
        # in cygwin for some reason
        gen_list = []
        # First try the last working generator
        if CMakeDependency.class_working_generator is not None:
            gen_list += [CMakeDependency.class_working_generator]
        gen_list += CMakeDependency.class_cmake_generators

        temp_parser = CMakeTraceParser(self.cmakebin.version(), self._get_build_dir(), self.env)
        toolchain = CMakeToolchain(self.cmakebin, self.env, self.for_machine, CMakeExecScope.DEPENDENCY, self._get_build_dir())
        toolchain.write()

        for i in gen_list:
            mlog.debug('Try CMake generator: {}'.format(i if len(i) > 0 else 'auto'))

            # Prepare options
            cmake_opts = temp_parser.trace_args() + toolchain.get_cmake_args() + ['.']
            cmake_opts += cm_args
            if len(i) > 0:
                cmake_opts = ['-G', i] + cmake_opts

            # Run CMake
            ret1, out1, err1 = self._call_cmake(cmake_opts, 'CMakePathInfo.txt')

            # Current generator was successful
            if ret1 == 0:
                CMakeDependency.class_working_generator = i
                break

            mlog.debug(f'CMake failed to gather system information for generator {i} with error code {ret1}')
            mlog.debug(f'OUT:\n{out1}\n\n\nERR:\n{err1}\n\n')

        # Check if any generator succeeded
        if ret1 != 0:
            return None

        try:
            temp_parser.parse(err1)
        except MesonException:
            return None

        def process_paths(l: T.List[str]) -> T.Set[str]:
            if is_windows():
                # Cannot split on ':' on Windows because its in the drive letter
                tmp = [x.split(os.pathsep) for x in l]
            else:
                # https://github.com/mesonbuild/meson/issues/7294
                tmp = [re.split(r':|;', x) for x in l]
            flattened = [x for sublist in tmp for x in sublist]
            return set(flattened)

        # Extract the variables and sanity check them
        root_paths_set = process_paths(temp_parser.get_cmake_var('MESON_FIND_ROOT_PATH'))
        root_paths_set.update(process_paths(temp_parser.get_cmake_var('MESON_CMAKE_SYSROOT')))
        root_paths = sorted(root_paths_set)
        root_paths = [x for x in root_paths if os.path.isdir(x)]
        module_paths_set = process_paths(temp_parser.get_cmake_var('MESON_PATHS_LIST'))
        rooted_paths: T.List[str] = []
        for j in [Path(x) for x in root_paths]:
            for p in [Path(x) for x in module_paths_set]:
                rooted_paths.append(str(j / p.relative_to(p.anchor)))
        module_paths = sorted(module_paths_set.union(rooted_paths))
        module_paths = [x for x in module_paths if os.path.isdir(x)]
        archs = temp_parser.get_cmake_var('MESON_ARCH_LIST')

        common_paths = ['lib', 'lib32', 'lib64', 'libx32', 'share', '']
        for i in archs:
            common_paths += [os.path.join('lib', i)]

        res = CMakeInfo(
            module_paths=module_paths,
            cmake_root=temp_parser.get_cmake_var('MESON_CMAKE_ROOT')[0],
            archs=archs,
            common_paths=common_paths,
        )

        mlog.debug(f'  -- Module search paths:    {res.module_paths}')
        mlog.debug(f'  -- CMake root:             {res.cmake_root}')
        mlog.debug(f'  -- CMake architectures:    {res.archs}')
        mlog.debug(f'  -- CMake lib search paths: {res.common_paths}')

        return res

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _cached_listdir(path: str) -> T.Tuple[T.Tuple[str, str], ...]:
        try:
            return tuple((x, str(x).lower()) for x in os.listdir(path))
        except OSError:
            return tuple()

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _cached_isdir(path: str) -> bool:
        try:
            return os.path.isdir(path)
        except OSError:
            return False

    def _preliminary_find_check(self, name: str, module_path: T.List[str], prefix_path: T.List[str], machine: 'MachineInfo') -> bool:
        lname = str(name).lower()

        # Checks <path>, <path>/cmake, <path>/CMake
        def find_module(path: str) -> bool:
            for i in [path, os.path.join(path, 'cmake'), os.path.join(path, 'CMake')]:
                if not self._cached_isdir(i):
                    continue

                # Check the directory case insensitive
                content = self._cached_listdir(i)
                candidates = ['Find{}.cmake', '{}Config.cmake', '{}-config.cmake']
                candidates = [x.format(name).lower() for x in candidates]
                if any(x[1] in candidates for x in content):
                    return True
            return False

        # Search in <path>/(lib/<arch>|lib*|share) for cmake files
        def search_lib_dirs(path: str) -> bool:
            for i in [os.path.join(path, x) for x in self.cmakeinfo.common_paths]:
                if not self._cached_isdir(i):
                    continue

                # Check <path>/(lib/<arch>|lib*|share)/cmake/<name>*/
                cm_dir = os.path.join(i, 'cmake')
                if self._cached_isdir(cm_dir):
                    content = self._cached_listdir(cm_dir)
                    content = tuple(x for x in content if x[1].startswith(lname))
                    for k in content:
                        if find_module(os.path.join(cm_dir, k[0])):
                            return True

                # <path>/(lib/<arch>|lib*|share)/<name>*/
                # <path>/(lib/<arch>|lib*|share)/<name>*/(cmake|CMake)/
                content = self._cached_listdir(i)
                content = tuple(x for x in content if x[1].startswith(lname))
                for k in content:
                    if find_module(os.path.join(i, k[0])):
                        return True

            return False

        # Check the user provided and system module paths
        for i in module_path + [os.path.join(self.cmakeinfo.cmake_root, 'Modules')]:
            if find_module(i):
                return True

        # Check the user provided prefix paths
        for i in prefix_path:
            if search_lib_dirs(i):
                return True

        # Check PATH
        system_env: T.List[str] = []
        for i in os.environ.get('PATH', '').split(os.pathsep):
            if i.endswith('/bin') or i.endswith('\\bin'):
                i = i[:-4]
            if i.endswith('/sbin') or i.endswith('\\sbin'):
                i = i[:-5]
            system_env += [i]

        # Check the system paths
        for i in self.cmakeinfo.module_paths + system_env:
            if find_module(i):
                return True

            if search_lib_dirs(i):
                return True

            content = self._cached_listdir(i)
            content = tuple(x for x in content if x[1].startswith(lname))
            for k in content:
                if search_lib_dirs(os.path.join(i, k[0])):
                    return True

            # Mac framework support
            if machine.is_darwin():
                for j in [f'{lname}.framework', f'{lname}.app']:
                    for k in content:
                        if k[1] != j:
                            continue
                        if find_module(os.path.join(i, k[0], 'Resources')) or find_module(os.path.join(i, k[0], 'Version')):
                            return True

        # Check the environment path
        env_path = os.environ.get(f'{name}_DIR')
        if env_path and find_module(env_path):
            return True

        # Check the Linux CMake registry
        linux_reg = Path.home() / '.cmake' / 'packages'
        for p in [linux_reg / name, linux_reg / lname]:
            if p.exists():
                return True

        return False

    def _detect_dep(self, name: str, package_version: str, modules: T.List[T.Tuple[str, bool]], components: T.List[T.Tuple[str, bool]], args: T.List[str]) -> None:
        # Detect a dependency with CMake using the '--find-package' mode
        # and the trace output (stderr)
        #
        # When the trace output is enabled CMake prints all functions with
        # parameters to stderr as they are executed. Since CMake 3.4.0
        # variables ("${VAR}") are also replaced in the trace output.
        mlog.debug('\nDetermining dependency {!r} with CMake executable '
                   '{!r}'.format(name, self.cmakebin.executable_path()))

        # Try different CMake generators since specifying no generator may fail
        # in cygwin for some reason
        gen_list = []
        # First try the last working generator
        if CMakeDependency.class_working_generator is not None:
            gen_list += [CMakeDependency.class_working_generator]
        gen_list += CMakeDependency.class_cmake_generators

        # Map the components
        comp_mapped = self._map_component_list(modules, components)
        toolchain = CMakeToolchain(self.cmakebin, self.env, self.for_machine, CMakeExecScope.DEPENDENCY, self._get_build_dir())
        toolchain.write()

        for i in gen_list:
            mlog.debug('Try CMake generator: {}'.format(i if len(i) > 0 else 'auto'))

            # Prepare options
            cmake_opts = []
            cmake_opts += [f'-DNAME={name}']
            cmake_opts += ['-DARCHS={}'.format(';'.join(self.cmakeinfo.archs))]
            cmake_opts += [f'-DVERSION={package_version}']
            cmake_opts += ['-DCOMPS={}'.format(';'.join([x[0] for x in comp_mapped]))]
            cmake_opts += ['-DSTATIC={}'.format('ON' if self.static else 'OFF')]
            cmake_opts += args
            cmake_opts += self.traceparser.trace_args()
            cmake_opts += toolchain.get_cmake_args()
            cmake_opts += self._extra_cmake_opts()
            cmake_opts += ['.']
            if len(i) > 0:
                cmake_opts = ['-G', i] + cmake_opts

            # Run CMake
            ret1, out1, err1 = self._call_cmake(cmake_opts, self._main_cmake_file())

            # Current generator was successful
            if ret1 == 0:
                CMakeDependency.class_working_generator = i
                break

            mlog.debug(f'CMake failed for generator {i} and package {name} with error code {ret1}')
            mlog.debug(f'OUT:\n{out1}\n\n\nERR:\n{err1}\n\n')

        # Check if any generator succeeded
        if ret1 != 0:
            return

        try:
            self.traceparser.parse(err1)
        except CMakeException as e:
            e2 = self._gen_exception(str(e))
            if self.required:
                raise
            else:
                self.compile_args = []
                self.link_args = []
                self.is_found = False
                self.reason = e2
                return

        # Whether the package is found or not is always stored in PACKAGE_FOUND
        self.is_found = self.traceparser.var_to_bool('PACKAGE_FOUND')
        if not self.is_found:
            return

        # Try to detect the version
        vers_raw = self.traceparser.get_cmake_var('PACKAGE_VERSION')

        if len(vers_raw) > 0:
            self.version = vers_raw[0]
            self.version.strip('"\' ')

        # Post-process module list. Used in derived classes to modify the
        # module list (append prepend a string, etc.).
        modules = self._map_module_list(modules, components)
        autodetected_module_list = False

        # Try guessing a CMake target if none is provided
        if len(modules) == 0:
            for i in self.traceparser.targets:
                tg = i.lower()
                lname = name.lower()
                if f'{lname}::{lname}' == tg or lname == tg.replace('::', ''):
                    mlog.debug(f'Guessed CMake target \'{i}\'')
                    modules = [(i, True)]
                    autodetected_module_list = True
                    break

        # Failed to guess a target --> try the old-style method
        if len(modules) == 0:
            # Warn when there might be matching imported targets but no automatic match was used
            partial_modules: T.List[CMakeTarget] = []
            for k, v in self.traceparser.targets.items():
                tg = k.lower()
                lname = name.lower()
                if tg.startswith(f'{lname}::'):
                    partial_modules += [v]
            if partial_modules:
                mlog.warning(textwrap.dedent(f'''\
                    Could not find and exact match for the CMake dependency {name}.

                    However, Meson found the following partial matches:

                        {[x.name for x in partial_modules]}

                    Using imported is recommended, since this approach is less error prone
                    and better supported by Meson. Consider explicitly specifying one of
                    these in the dependency call with:

                        dependency('{name}', modules: ['{name}::<name>', ...])

                    Meson will now continue to use the old-style {name}_LIBRARIES CMake
                    variables to extract the dependency information since no explicit
                    target is currently specified.

                '''))
                mlog.debug('More info for the partial match targets:')
                for tgt in partial_modules:
                    mlog.debug(tgt)

            incDirs = [x for x in self.traceparser.get_cmake_var('PACKAGE_INCLUDE_DIRS') if x]
            defs = [x for x in self.traceparser.get_cmake_var('PACKAGE_DEFINITIONS') if x]
            libs_raw = [x for x in self.traceparser.get_cmake_var('PACKAGE_LIBRARIES') if x]

            # CMake has a "fun" API, where certain keywords describing
            # configurations can be in the *_LIBRARIES variables. See:
            # - https://github.com/mesonbuild/meson/issues/9197
            # - https://gitlab.freedesktop.org/libnice/libnice/-/issues/140
            # - https://cmake.org/cmake/help/latest/command/target_link_libraries.html#overview  (the last point in the section)
            libs: T.List[str] = []
            cfg_matches = True
            is_debug = cmake_is_debug(self.env)
            cm_tag_map = {'debug': is_debug, 'optimized': not is_debug, 'general': True}
            for i in libs_raw:
                if i.lower() in cm_tag_map:
                    cfg_matches = cm_tag_map[i.lower()]
                    continue
                if cfg_matches:
                    libs += [i]
                # According to the CMake docs, a keyword only works for the
                # directly the following item and all items without a keyword
                # are implicitly `general`
                cfg_matches = True

            # Try to use old style variables if no module is specified
            if len(libs) > 0:
                self.compile_args = [f'-I{x}' for x in incDirs] + defs
                self.link_args = []
                for j in libs:
                    rtgt = resolve_cmake_trace_targets(j, self.traceparser, self.env, clib_compiler=self.clib_compiler)
                    self.link_args += rtgt.libraries
                    self.compile_args += [f'-I{x}' for x in rtgt.include_directories]
                    self.compile_args += rtgt.public_compile_opts
                mlog.debug(f'using old-style CMake variables for dependency {name}')
                mlog.debug(f'Include Dirs:         {incDirs}')
                mlog.debug(f'Compiler Definitions: {defs}')
                mlog.debug(f'Libraries:            {libs}')
                return

            # Even the old-style approach failed. Nothing else we can do here
            self.is_found = False
            raise self._gen_exception('CMake: failed to guess a CMake target for {}.\n'
                                      'Try to explicitly specify one or more targets with the "modules" property.\n'
                                      'Valid targets are:\n{}'.format(name, list(self.traceparser.targets.keys())))

        # Set dependencies with CMake targets
        # recognise arguments we should pass directly to the linker
        incDirs = []
        compileOptions = []
        libraries = []

        for i, required in modules:
            if i not in self.traceparser.targets:
                if not required:
                    mlog.warning('CMake: T.Optional module', mlog.bold(self._original_module_name(i)), 'for', mlog.bold(name), 'was not found')
                    continue
                raise self._gen_exception('CMake: invalid module {} for {}.\n'
                                          'Try to explicitly specify one or more targets with the "modules" property.\n'
                                          'Valid targets are:\n{}'.format(self._original_module_name(i), name, list(self.traceparser.targets.keys())))

            if not autodetected_module_list:
                self.found_modules += [i]

            rtgt = resolve_cmake_trace_targets(i, self.traceparser, self.env,
                                               clib_compiler=self.clib_compiler,
                                               not_found_warning=lambda x:
                                                   mlog.warning('CMake: Dependency', mlog.bold(x), 'for', mlog.bold(name), 'was not found')
                                               )
            incDirs += rtgt.include_directories
            compileOptions += rtgt.public_compile_opts
            libraries += rtgt.libraries + rtgt.link_flags

        # Make sure all elements in the lists are unique and sorted
        incDirs = sorted(set(incDirs))
        compileOptions = sorted(set(compileOptions))
        libraries = sorted(set(libraries))

        mlog.debug(f'Include Dirs:         {incDirs}')
        mlog.debug(f'Compiler Options:     {compileOptions}')
        mlog.debug(f'Libraries:            {libraries}')

        self.compile_args = compileOptions + [f'-I{x}' for x in incDirs]
        self.link_args = libraries

    def _get_build_dir(self) -> Path:
        build_dir = Path(self.cmake_root_dir) / f'cmake_{self.name}'
        build_dir.mkdir(parents=True, exist_ok=True)
        return build_dir

    def _setup_cmake_dir(self, cmake_file: str) -> Path:
        # Setup the CMake build environment and return the "build" directory
        build_dir = self._get_build_dir()

        # Remove old CMake cache so we can try out multiple generators
        cmake_cache = build_dir / 'CMakeCache.txt'
        cmake_files = build_dir / 'CMakeFiles'
        if cmake_cache.exists():
            cmake_cache.unlink()
        shutil.rmtree(cmake_files.as_posix(), ignore_errors=True)

        # Insert language parameters into the CMakeLists.txt and write new CMakeLists.txt
        cmake_txt = importlib.resources.read_text('mesonbuild.dependencies.data', cmake_file, encoding = 'utf-8')

        # In general, some Fortran CMake find_package() also require C language enabled,
        # even if nothing from C is directly used. An easy Fortran example that fails
        # without C language is
        #   find_package(Threads)
        # To make this general to
        # any other language that might need this, we use a list for all
        # languages and expand in the cmake Project(... LANGUAGES ...) statement.
        from ..cmake import language_map
        cmake_language = [language_map[x] for x in self.language_list if x in language_map]
        if not cmake_language:
            cmake_language += ['NONE']

        cmake_txt = textwrap.dedent("""
            cmake_minimum_required(VERSION ${{CMAKE_VERSION}})
            project(MesonTemp LANGUAGES {})
        """).format(' '.join(cmake_language)) + cmake_txt

        cm_file = build_dir / 'CMakeLists.txt'
        cm_file.write_text(cmake_txt, encoding='utf-8')
        mlog.cmd_ci_include(cm_file.absolute().as_posix())

        return build_dir

    def _call_cmake(self,
                    args: T.List[str],
                    cmake_file: str,
                    env: T.Optional[T.Dict[str, str]] = None) -> T.Tuple[int, T.Optional[str], T.Optional[str]]:
        build_dir = self._setup_cmake_dir(cmake_file)
        return self.cmakebin.call(args, build_dir, env=env)

    @staticmethod
    def log_tried() -> str:
        return 'cmake'

    def log_details(self) -> str:
        modules = [self._original_module_name(x) for x in self.found_modules]
        modules = sorted(set(modules))
        if modules:
            return 'modules: ' + ', '.join(modules)
        return ''

    def get_variable(self, *, cmake: T.Optional[str] = None, pkgconfig: T.Optional[str] = None,
                     configtool: T.Optional[str] = None, internal: T.Optional[str] = None,
                     default_value: T.Optional[str] = None,
                     pkgconfig_define: PkgConfigDefineType = None) -> str:
        if cmake and self.traceparser is not None:
            try:
                v = self.traceparser.vars[cmake]
            except KeyError:
                pass
            else:
                # CMake does NOT have a list datatype. We have no idea whether
                # anything is a string or a string-separated-by-; Internally,
                # we treat them as the latter and represent everything as a
                # list, because it is convenient when we are mostly handling
                # imported targets, which have various properties that are
                # actually lists.
                #
                # As a result we need to convert them back to strings when grabbing
                # raw variables the user requested.
                return ';'.join(v)
        if default_value is not None:
            return default_value
        raise DependencyException(f'Could not get cmake variable and no default provided for {self!r}')


class CMakeDependencyFactory:

    def __init__(self, name: T.Optional[str] = None, modules: T.Optional[T.List[str]] = None):
        self.name = name
        self.modules = modules

    def __call__(self, name: str, env: Environment, kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None, force_use_global_compilers: bool = False) -> CMakeDependency:
        if self.modules:
            kwargs['modules'] = self.modules
        return CMakeDependency(self.name or name, env, kwargs, language, force_use_global_compilers)

    @staticmethod
    def log_tried() -> str:
        return CMakeDependency.log_tried()
```