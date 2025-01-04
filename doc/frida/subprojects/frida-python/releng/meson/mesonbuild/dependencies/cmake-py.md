Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The core request is to understand the functionality of a specific Python file within the Frida project related to CMake dependencies and how it connects to reverse engineering, low-level details, and common user errors.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick skim of the code, looking for recognizable keywords and patterns. This helps establish the overall purpose. Keywords like `CMakeDependency`, `find_package`, `CMakeLists.txt`, `modules`, `components`, `cmake_args`, and `traceparser` immediately suggest this file deals with finding and handling CMake-based dependencies. The presence of `ExternalDependency` hints at integration with a larger build system (Meson in this case).

**3. Dissecting the Class Structure (`CMakeDependency`):**

The core of the functionality lies within the `CMakeDependency` class. We need to analyze its methods:

* **`__init__`:** This is the constructor. It initializes the dependency object, finds the CMake executable, and performs an initial check for the dependency. The use of `CMakeExecutor` and `CMakeTraceParser` is important.
* **`_get_cmake_info`:** This method extracts system information from CMake, like module paths and architectures. This is crucial for finding the correct dependency files. The attempt to try different CMake generators is also significant.
* **`_preliminary_find_check`:**  This function tries to quickly locate the dependency by searching common paths and checking for specific files. It's an optimization to avoid full CMake runs if possible.
* **`_detect_dep`:** This is the heart of the dependency detection logic. It uses CMake's `--find-package` functionality and parses the output to extract information about the dependency (include directories, libraries, etc.). The handling of "modules" (CMake targets) and the fallback to older variable-based detection are key details.
* **`_get_build_dir` and `_setup_cmake_dir`:** These methods manage temporary build directories for running CMake commands. This isolates the dependency detection process.
* **`_call_cmake`:**  This method executes the CMake commands.
* **`get_variable`:**  This allows retrieving CMake variables associated with the dependency.
* **Other helper methods:** `_main_cmake_file`, `_extra_cmake_opts`, `_map_module_list`, `_map_component_list`, `_original_module_name` suggest customization points for specific dependency types.

**4. Connecting to Reverse Engineering:**

The key link here is how external libraries are used in reverse engineering tools like Frida.

* **Frida's Need for Libraries:** Frida interacts with target processes, often requiring libraries for instrumentation, hooking, and other tasks. These libraries might be built using CMake.
* **Dynamic Instrumentation:** The mention of "dynamic instrumentation tool" in the initial description reinforces this. Frida injects into running processes, and the libraries it uses need to be located and linked correctly.
* **Example:**  Consider a scenario where Frida needs to use a custom hooking library built with CMake. This `cmake.py` script would be responsible for finding that library's build artifacts.

**5. Identifying Low-Level, Kernel, and Framework Connections:**

* **Binary Bottom Layer:** CMake deals with linking, which directly involves binary files (libraries, executables). The script's output includes library paths and linker flags, which are essential for binary manipulation.
* **Linux and Android Kernels/Frameworks:** Frida often targets these platforms. The code explicitly checks for platform-specific behavior (like Mac frameworks) and uses environment variables and standard directory structures common in Linux/Android development. The `_get_cmake_info` method gathers information relevant to the target system's architecture and library paths.
* **Example:** When targeting an Android app, Frida might need to link against system libraries or framework components. This script ensures that CMake finds the correct versions for the target architecture.

**6. Analyzing Logic and Potential Inputs/Outputs:**

The `_detect_dep` method embodies the core logic.

* **Input:** Dependency name, version requirements, lists of modules/components, and CMake arguments.
* **Process:** The script executes CMake with specific flags to find the package. It parses the output to determine if the package was found and to extract relevant build information.
* **Output:**  Boolean indicating if the dependency was found, version information, compiler flags, and linker flags.

**7. Spotting Potential User Errors:**

* **Incorrect Dependency Name:**  Typing the dependency name wrong in the Meson build file will lead to CMake failing to find the package.
* **Missing CMake Configuration:** If the dependency isn't properly set up with a `CMakeLists.txt` file, this script won't be able to find it.
* **Incorrect Module/Component Names:**  Specifying the wrong module or component names will cause CMake to fail during the `find_package` call.
* **Conflicting CMake Arguments:** Providing conflicting arguments through `cmake_args` can lead to unexpected behavior or failures.
* **Incorrectly Set Environment Variables:**  If environment variables like `PATH` or dependency-specific variables are not set correctly, CMake might not be able to locate the dependency.

**8. Tracing User Operations:**

To understand how a user ends up using this file, we need to consider the build process.

* **Meson Build System:** Frida uses Meson as its build system.
* **`dependency()` Function:**  In a `meson.build` file, the user would call the `dependency()` function to declare a dependency.
* **`type: 'cmake'`:**  To use the functionality of `cmake.py`, the user would specify the dependency type as `'cmake'`.
* **Keyword Arguments:** The user can provide various keyword arguments (like `modules`, `components`, `cmake_args`) that are then passed to the `CMakeDependency` constructor.
* **Meson Invocation:**  When the user runs `meson compile`, Meson processes the `meson.build` file and, for CMake dependencies, instantiates the `CMakeDependency` class, leading to the execution of the code in `cmake.py`.

**9. Iterative Refinement:**

After the initial analysis, it's good to revisit the code to catch any missed details or refine the explanations. For instance, noticing the `_map_module_list` and `_map_component_list` methods suggests the possibility of customizing how modules and components are handled, which could be relevant for certain types of CMake packages.

This systematic approach, combining code reading, keyword analysis, understanding the surrounding context (Frida and Meson), and considering potential use cases and errors, allows for a comprehensive understanding of the Python file's functionality.
This Python code file, `cmake.py`, is a core component of Frida's build system (which uses Meson) for handling dependencies that are managed using CMake. It defines how Frida's build process interacts with external libraries and components that provide their build definitions as CMake projects.

Here's a breakdown of its functionality:

**Core Functionality: Managing CMake Dependencies**

The primary goal of this file is to find and configure dependencies that use the CMake build system. It provides a `CMakeDependency` class that encapsulates the logic for locating CMake packages and extracting necessary information (include paths, libraries, compiler flags) to link them into the Frida build.

**Key Features and Functionality:**

1. **Finding CMake:** It locates the CMake executable (`cmake`). It tries different generators (Ninja, Makefiles, Visual Studio) to ensure compatibility across different systems.

2. **Extracting CMake System Information:** The `_get_cmake_info` method runs a basic CMake command to gather information about the system's CMake setup, including module paths, architecture information, and common library directories. This helps in locating dependency files.

3. **Preliminary Dependency Check:** The `_preliminary_find_check` method performs a quick search for CMake module files (e.g., `Find<Package>.cmake`, `<Package>Config.cmake`) in common locations before running a full CMake configuration. This is an optimization to speed up the build process.

4. **Dependency Detection using `find_package`:** The `_detect_dep` method is the core of the dependency finding logic. It creates a temporary CMake project and uses the `find_package()` command to locate the specified dependency. It parses the output of CMake (specifically the trace output) to determine if the package was found and to extract variables defined by the package's CMake configuration.

5. **Handling CMake Modules and Components:** It supports specifying specific modules or components of a CMake package to link against. This allows for finer-grained control over the dependencies.

6. **Extracting Build Information:** It extracts essential build information from the CMake output, such as include directories (`PACKAGE_INCLUDE_DIRS`), preprocessor definitions (`PACKAGE_DEFINITIONS`), and libraries to link (`PACKAGE_LIBRARIES`). It also handles modern CMake targets.

7. **Mapping Modules and Components:** The `_map_module_list` and `_map_component_list` methods provide hooks for modifying the list of modules and components before and after the initial CMake pass. This can be used for custom logic based on the dependency's CMake configuration.

8. **Handling Different CMake Generators:** It attempts to use different CMake generators to ensure compatibility across various platforms and development environments.

9. **Caching and Optimization:** It uses caching (`@functools.lru_cache`) to optimize file system operations like `listdir` and `isdir`, which can improve build performance.

10. **Error Handling:** It includes error handling to gracefully manage situations where dependencies are not found or CMake configuration fails.

**Relationship to Reverse Engineering:**

This file is crucial for Frida's reverse engineering capabilities because Frida often depends on external libraries for various functionalities like:

* **Code Injection and Hooking:**  Libraries that provide low-level system interaction APIs might be built with CMake.
* **Instrumentation Frameworks:** External frameworks that Frida integrates with might use CMake for their build process.
* **Communication and Networking:** Libraries for network communication or inter-process communication might be CMake-based.
* **Specific Target Libraries:**  When targeting specific applications or systems, Frida might need to link against libraries that are part of that target and built with CMake.

**Example:**

Imagine Frida needs to integrate with a hypothetical library called `CoolHookLib` that provides advanced hooking capabilities and is built using CMake.

* In Frida's `meson.build` file, a developer would declare this dependency like:
  ```meson
  coolhooklib_dep = dependency('CoolHookLib', type : 'cmake')
  ```
* When Meson processes this, it will instantiate the `CMakeDependency` class from `cmake.py`.
* `cmake.py` will use the CMake executable to try and find `CoolHookLib`. It might look for a `FindCoolHookLib.cmake` module or a `CoolHookLibConfig.cmake` file.
* If found, CMake will execute the necessary commands defined in `CoolHookLib`'s CMake files.
* `cmake.py` will parse the output to find include paths (where `CoolHookLib`'s header files are located) and the library file itself (e.g., `libCoolHookLib.so` on Linux).
* This information (include paths and library paths) will then be passed to the compiler and linker when building Frida, allowing Frida to use the functionality provided by `CoolHookLib`.

**Binary Bottom Layer, Linux, Android Kernel & Framework Knowledge:**

This code inherently deals with these concepts:

* **Binary Bottom Layer:** CMake's primary function is to generate build files that compile and link binary executables and libraries. This code interacts with the output of CMake, specifically looking for binary library files (`.so`, `.dylib`, `.dll`). The `resolve_cmake_trace_targets` function likely deals with extracting information about compiled targets.
* **Linux and Android:** The code includes platform-specific considerations:
    * **Path Separators:**  It uses `os.pathsep` for path manipulation, which is different on Windows and Linux/Android.
    * **Library Search Paths:** It understands common Linux library directories like `lib`, `lib64`, `share`.
    * **Environment Variables:** It checks environment variables like `PATH` and dependency-specific variables (e.g., `<dependency_name>_DIR`) that are common in Linux/Android development.
    * **Mac Frameworks:** It has specific logic for handling macOS frameworks (`.framework`).
* **Kernel and Framework Knowledge (Indirect):** While this code doesn't directly interact with the kernel or framework code, it facilitates the inclusion of libraries that *do*. When Frida needs to hook into system calls or interact with Android framework components, it often relies on external libraries that are built with CMake, and this file manages that integration.

**Logic and Reasoning (Hypothetical Input & Output):**

**Assumption:** Frida needs to depend on a library called `MyUtils` built with CMake. `MyUtils`'s `CMakeLists.txt` defines an include directory `include` and creates a shared library `libmyutils.so`.

**Hypothetical Input (within Frida's `meson.build`):**

```meson
myutils_dep = dependency('MyUtils', type : 'cmake')
```

**Reasoning within `cmake.py`:**

1. The `CMakeDependency` class is instantiated with the name "MyUtils".
2. `_preliminary_find_check` might search for `FindMyUtils.cmake` or `MyUtilsConfig.cmake` in standard locations.
3. `_detect_dep` will create a temporary CMake project and run `find_package(MyUtils)`.
4. CMake will execute `MyUtils`'s CMake files. Let's assume `MyUtilsConfig.cmake` sets variables like:
   ```cmake
   set(MyUtils_INCLUDE_DIRS "/path/to/myutils/include")
   set(MyUtils_LIBRARIES "/path/to/myutils/libmyutils.so")
   ```
5. `cmake.py`'s `CMakeTraceParser` will parse the CMake output and extract these variables.

**Hypothetical Output (within Frida's build system):**

The `myutils_dep` object will have the following properties set:

* `is_found`: `True`
* `compile_args`: `['-I/path/to/myutils/include']`
* `link_args`: `['/path/to/myutils/libmyutils.so']`

These arguments will then be used by Meson to compile Frida and link it against `libmyutils.so`.

**User or Programming Common Usage Errors:**

1. **Incorrect Dependency Name:** If the user types `dependency('MyUtilz', type : 'cmake')` (typo in the name), CMake will likely fail to find the package, and the build will fail with an error message indicating the dependency wasn't found.

2. **Missing or Incorrect CMake Files:** If the `MyUtils` library doesn't have a proper `CMakeLists.txt` or its configuration files (`FindMyUtils.cmake` or `MyUtilsConfig.cmake`) are missing or incorrectly set up, CMake will fail during the `find_package` step, and the build will fail.

3. **Incorrect `modules` Specification:** If the CMake package has multiple targets, and the user wants to link against a specific one, they might use the `modules` keyword. Specifying an incorrect module name would lead to an error. For example, if `MyUtils` had targets `MyUtilsCore` and `MyUtilsGUI`, and the user used `dependency('MyUtils', type : 'cmake', modules : ['MyUtilsBase'])`, the build would fail if `MyUtilsBase` doesn't exist.

4. **Missing CMake as a Dependency:** If the system doesn't have CMake installed or it's not in the `PATH`, the initial check for the CMake executable will fail, resulting in an error.

**User Operations Leading to This Code (Debugging Clues):**

1. **User modifies Frida's `meson.build`:** A developer adds or modifies a dependency declaration with `type : 'cmake'`.
2. **User runs `meson setup` or `meson compile`:**  Meson starts processing the build definition.
3. **Meson encounters a CMake dependency:**  It identifies a `dependency()` call with `type : 'cmake'`.
4. **Meson instantiates `CMakeDependency`:**  Meson imports and uses the `CMakeDependency` class from `frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/cmake.py`.
5. **The `__init__` method is called:** This starts the process of finding the CMake executable and gathering system information.
6. **`_detect_dep` is called:** This attempts to find the specific CMake package using `find_package`.
7. **If debugging is enabled or the build fails:** Meson might print verbose output that includes CMake command-line arguments, output from CMake, and error messages, potentially leading the developer to examine the logic within `cmake.py` to understand why a dependency is not being found or configured correctly.

By understanding the flow and logic within this `cmake.py` file, developers working on Frida or integrating with CMake-based libraries can effectively troubleshoot dependency issues and ensure the build process works correctly.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```