Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The core request is to understand the functionality of the `cmake.py` file within the Frida project and how it relates to reverse engineering, low-level concepts, and potential user errors.

2. **Initial Skim for High-Level Purpose:**  Reading the initial comments and class names (`CMakeDependency`, `CMakeExecutor`, `CMakeTraceParser`) immediately suggests this file deals with integrating CMake projects or dependencies within the Meson build system. The "frida" path suggests this integration is crucial for building or utilizing components of the Frida dynamic instrumentation tool.

3. **Identify Key Classes and Their Roles:**

    * **`CMakeDependency`:**  The central class. It represents a CMake dependency within the Meson build. It handles finding the dependency, extracting information (include paths, libraries, etc.), and providing it to Meson.
    * **`CMakeInfo`:**  A simple data structure to hold information about the CMake installation itself (module paths, root, architectures). This helps the dependency finding process.
    * **`CMakeExecutor`:**  Responsible for actually running CMake commands. It abstracts away the details of invoking the CMake executable.
    * **`CMakeTraceParser`:**  Parses the output of CMake when tracing is enabled. This is how the script extracts information about the found package (variables, targets).
    * **`CMakeToolchain`:**  Manages the generation and writing of CMake toolchain files, which are important for cross-compilation scenarios.
    * **`CMakeDependencyFactory`:** A factory class for creating `CMakeDependency` objects. This is a common design pattern for simplifying object creation.

4. **Analyze `CMakeDependency.__init__`:** This is the entry point for creating a CMake dependency. Key actions here include:
    * Determining supported languages.
    * Finding the CMake executable using `CMakeExecutor`.
    * Setting up the `CMakeTraceParser`.
    * Calling `_get_cmake_info` to gather basic CMake environment details.
    * Performing a preliminary check with `_preliminary_find_check` to quickly determine if the dependency *might* exist before a full CMake run.
    * Calling the core logic `_detect_dep` to actually find and extract dependency information.

5. **Deep Dive into Key Methods:**

    * **`_get_cmake_info`:** This is crucial for understanding how the script learns about the system's CMake setup. It tries different CMake generators to get a working configuration and then parses the output to find module paths, architectures, etc. The use of `CMakeTraceParser` is important here.
    * **`_preliminary_find_check`:** This is an optimization. It looks for common CMake files (`Find*.cmake`, `*Config.cmake`) in various locations to avoid a potentially slow full CMake run if the dependency is obviously missing. This involves checking environment variables and standard locations.
    * **`_detect_dep`:**  The heart of the dependency detection. It runs CMake in "find-package" mode with tracing enabled. The output is parsed by `CMakeTraceParser` to extract variables like `PACKAGE_FOUND`, `PACKAGE_VERSION`, and target information. It handles cases where modules (targets) are explicitly specified or need to be guessed. It also has fallback logic to parse older-style CMake variable conventions if targets aren't found.
    * **`_call_cmake`:** A utility method to execute CMake with specified arguments and in the correct build directory.
    * **`get_variable`:** Allows retrieving CMake variables found during the dependency detection process.

6. **Connect to the Prompts:** Now, systematically address each part of the request:

    * **Functionality:** Summarize the core purpose and the roles of the main classes and methods.
    * **Reverse Engineering:** Think about how CMake is used in reverse engineering contexts. Frida itself is a reverse engineering tool, and it likely depends on other libraries built with CMake. The ability to find these dependencies is crucial. Consider examples like finding a specific hooking library.
    * **Binary/Low-Level/Kernel/Framework:** Consider where CMake interacts with these areas. CMake generates build files that compile low-level code. It deals with target architectures, which are very relevant to binary code. Think about cross-compilation for Android (kernel, framework). The toolchain handling becomes relevant here.
    * **Logical Inference (Assumptions and Outputs):**  Pick a simple scenario (e.g., finding a library named "MyLib"). Walk through the potential steps and what the script would try, making reasonable assumptions about the project structure and CMake files. Show what the input (dependency name) and possible outputs (found/not found, include paths, libraries) would be.
    * **User Errors:** Consider common mistakes users might make when specifying CMake dependencies in Meson. Incorrect module names, missing CMake files, wrong paths are all possibilities.
    * **User Operation/Debugging:**  Trace the steps a user might take to end up in this code. They would be building a Frida component that depends on a CMake project. When Meson tries to resolve this dependency, it will invoke this code. Explain how enabling debug logs can help understand the process.

7. **Refine and Structure:** Organize the findings logically, using clear headings and bullet points. Provide concrete examples to illustrate the concepts. Ensure the language is clear and avoids jargon where possible, or explains it when necessary. Double-check that all parts of the original request are covered. For example, ensure you've explained the purpose of the different `_map_*_list` functions even though they have default implementations.

8. **Self-Correction/Review:**  Reread the analysis. Does it make sense? Is it accurate?  Are there any missing pieces or areas where the explanation could be clearer?  For example, initially, I might have focused too much on the technical details of CMake and missed the broader context of Frida's usage. Reviewing helps to catch these omissions. Also, ensure the examples provided directly relate to the point being made.

By following this structured approach, we can thoroughly analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The key is to start with a high-level understanding and then gradually dive deeper into the details, always keeping the original questions in mind.
This Python code file, `cmake.py`, is part of the Meson build system's functionality for handling dependencies that are built using CMake. Meson is used by the Frida project to manage its build process. Specifically, this file defines how Meson interacts with CMake to find and incorporate external libraries or components that have their own CMake-based build system.

Let's break down its functionality:

**Core Functionality: Handling CMake Dependencies**

The primary function of this file is to define the `CMakeDependency` class, which represents an external dependency managed by CMake. It allows Meson to find, configure, and link against these CMake-based dependencies.

Here's a breakdown of the key actions:

1. **Finding the CMake Executable:** The code first ensures that the CMake executable is available on the system. It uses the `CMakeExecutor` class to find it and check its version.

2. **Gathering CMake System Information:**  The `_get_cmake_info` method attempts to get basic information about the CMake installation, such as module search paths, the CMake root directory, and supported architectures. This is done by running a temporary CMake project.

3. **Preliminary Dependency Check:** The `_preliminary_find_check` method performs a quick check to see if the dependency *might* exist by looking for common CMake configuration files (`Find<Name>.cmake`, `<Name>Config.cmake`) in various standard and user-specified locations. This is an optimization to avoid running the full CMake dependency detection if it's likely to fail.

4. **Detecting the Dependency (`_detect_dep`):** This is the core of the dependency detection process. It uses CMake's "find-package" functionality with tracing enabled. This involves:
   - Creating a temporary CMake project (`CMakeLists.txt`) that attempts to find the specified dependency.
   - Running CMake with specific arguments (including trace flags) and potential CMake generators.
   - Parsing the trace output (stderr) using `CMakeTraceParser` to extract information about whether the package was found, its version, include directories, compile definitions, and target libraries.

5. **Mapping Modules and Components:** The `_map_module_list` and `_map_component_list` methods provide hooks for modifying the lists of modules and components being searched for. These are executed before and after the initial CMake pass, respectively, allowing for dynamic adjustments based on information gathered from the CMake project.

6. **Resolving CMake Targets:** If the dependency is found, the code attempts to identify specific CMake *targets* within the dependency. CMake targets represent buildable units (libraries, executables, etc.). This is the preferred method for integrating CMake dependencies. If no explicit targets are given, it tries to guess based on naming conventions.

7. **Extracting Dependency Information:**  Once targets are identified, the code uses `resolve_cmake_trace_targets` to extract relevant information for Meson, such as include directories, compile options, and libraries to link against.

8. **Providing Information to Meson:** The `CMakeDependency` object stores the extracted information (include paths, libraries, etc.) and makes it available to Meson so it can be used during the main build process.

**Relationship to Reverse Engineering:**

This file is directly relevant to reverse engineering, especially in the context of Frida, which is a dynamic instrumentation toolkit used for reverse engineering, debugging, and security research.

* **Frida's Dependencies:** Frida itself likely depends on various external libraries (e.g., for networking, scripting language support, core utilities) that might be built using CMake. This file ensures that Meson can correctly find and integrate these dependencies.
* **Targeting Software with CMake Dependencies:** When using Frida to instrument target software, the target itself might have been built using CMake and rely on other CMake-managed libraries. Understanding how Meson handles CMake dependencies is crucial if you need to build custom Frida modules or extensions that interact with such targets or their dependencies.

**Example:** Imagine Frida depends on a library called "MyHookingLib" built with CMake. The `CMakeDependency` class would be used as follows:

```python
# In a Meson build definition file (meson.build) for Frida:
my_hooking_lib = dependency('MyHookingLib', type : 'cmake')
```

The `cmake.py` code would then:

1. Try to find the CMake executable.
2. Create a temporary `CMakeLists.txt` that tries to `find_package(MyHookingLib)`.
3. Run CMake and parse the output to determine if `MyHookingLib` is found, its version, and the necessary linking information.
4. Make the include paths and libraries of `MyHookingLib` available to the Frida build process.

**Involvement of Binary底层, Linux, Android Kernel and Framework Knowledge:**

* **Binary 底层 (Binary Low-Level):**  CMake is often used to build libraries and tools that operate at a low level, interacting directly with hardware or system calls. The `CMakeDependency` class is responsible for ensuring that the correct libraries (binary files) are linked into the final Frida binaries.
* **Linux:** CMake is a popular build system on Linux, and Frida heavily supports Linux. The code handles standard Linux directory structures and environment variables (like `PATH`) when searching for CMake modules and packages.
* **Android Kernel and Framework:** While not explicitly mentioned in this file, CMake is increasingly used in Android development, including for native components and sometimes even parts of the Android framework. If Frida needs to interact with or depend on such components when running on Android, this `cmake.py` file would be involved in finding and linking against those CMake-built parts. The `_get_cmake_info` and `_preliminary_find_check` methods implicitly handle platform-specific path conventions. The `CMakeToolchain` class (imported but not heavily used in this snippet) would be more directly involved in cross-compilation scenarios for Android.

**Logical Inference (Hypothetical Input and Output):**

**Hypothetical Input:**

```python
# In meson.build:
my_utils = dependency('MyUtils', type : 'cmake', modules: ['MyCore'])
```

* **Dependency Name:** "MyUtils"
* **Dependency Type:** "cmake"
* **Modules:** ["MyCore"] (This suggests we are looking for a specific CMake target named "MyCore" within the "MyUtils" package).

**Possible Output (Assuming "MyUtils" is found and "MyCore" exists):**

* **`self.is_found`:** `True`
* **`self.version`:** (The version string of "MyUtils" if available in its CMake configuration)
* **`self.compile_args`:** A list of compiler flags, including `-I/path/to/MyUtils/include` (where the header files for "MyCore" are located).
* **`self.link_args`:** A list of linker flags, including `-lMyCore` (or the full path to the "MyCore" library binary).
* **`self.found_modules`:** `['MyCore']`

**Possible Output (Assuming "MyUtils" is found but "MyCore" does not exist):**

* **`self.is_found`:** `True` (because the package itself was found)
* **A `DependencyException`** would be raised during the target resolution in `_detect_dep`, indicating that the module "MyCore" could not be found.

**Possible Output (Assuming "MyUtils" is not found):**

* **`self.is_found`:** `False`
* A message would be logged indicating that the dependency "MyUtils" was not found.

**User or Programming Common Usage Errors:**

1. **Incorrect Dependency Name:**  If the user specifies the wrong name for the CMake package (e.g., `dependency('MyUtil', type : 'cmake')` when the actual package is "MyUtils"), the `_detect_dep` method will likely fail to find the package, and `self.is_found` will be `False`.

2. **Incorrect Module Names:**  Specifying a non-existent module name in the `modules` list (as in the logical inference example where "MyCore" might not exist) will lead to a `DependencyException`.

3. **Missing or Incorrectly Configured CMake Installation:** If CMake is not installed or not in the system's `PATH`, the initial check for the CMake executable in `CMakeExecutor` will fail, and a `DependencyException` will be raised early on.

4. **CMake Configuration Issues in the Dependency:** If the external CMake project has errors in its `CMakeLists.txt` that prevent `find_package` from working correctly, Meson will be unable to find the dependency. The error messages from CMake might be visible in Meson's output, providing clues.

5. **Incorrect `cmake_args`:**  Passing incorrect or conflicting arguments via the `cmake_args` keyword argument could lead to CMake configuration failures.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **User is Building Frida or a Frida Component:** The user is attempting to build Frida from source or a custom Frida module that declares a dependency on a CMake-based library in its `meson.build` file.

2. **Meson Processes the `meson.build` File:** Meson reads the `meson.build` file and encounters a `dependency()` call with `type: 'cmake'`.

3. **Meson Calls the `CMakeDependencyFactory`:** Based on the `type`, Meson instantiates a `CMakeDependencyFactory` for CMake dependencies.

4. **The Factory Creates a `CMakeDependency` Object:** The factory's `__call__` method creates an instance of the `CMakeDependency` class in `cmake.py`.

5. **`CMakeDependency.__init__` is Executed:** This is where the process of finding and configuring the CMake dependency begins.

6. **Potential Debugging Points:**

   - **Check CMake Installation:**  The user might get an error early on if CMake is not found. They should ensure CMake is installed and in their `PATH`.
   - **Examine Meson Output:** Meson will print debug messages (if the verbosity is high enough) showing the CMake commands being executed and the output. This can help identify if `find_package` is failing or if there are errors in the dependency's CMake files.
   - **Inspect Temporary CMake Files:** Meson creates temporary `CMakeLists.txt` files in the build directory. The user can inspect these to see how Meson is trying to find the dependency.
   - **Use CMake Directly:** The user can try running `cmake` manually in a separate build directory targeting the external dependency's source to verify if the dependency can be found and configured independently of Meson.

By understanding these steps and the functionality of `cmake.py`, developers working with Frida or other Meson-based projects can troubleshoot issues related to CMake dependencies effectively.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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