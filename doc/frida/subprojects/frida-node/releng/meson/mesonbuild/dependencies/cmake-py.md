Response:
Let's break down the thought process for analyzing this Python code for the Frida instrumentation tool.

**1. Understanding the Goal:**

The request asks for a breakdown of the `cmake.py` file's functionality within the Frida project. Key areas of interest are its relation to reverse engineering, low-level concepts (kernel, binaries), logical reasoning, common user errors, and how a user might trigger this code.

**2. Initial Code Scan and High-Level Interpretation:**

The first step is a quick skim of the code to identify its primary purpose. Keywords like "CMake," "dependency," "find_package," "module," "target," and the overall structure of a class dealing with external dependencies strongly suggest this code is responsible for finding and integrating CMake-based dependencies into the Frida build process.

**3. Identifying Core Functionality:**

Now, let's analyze the key methods and attributes:

* **`CMakeDependency` Class:** This is the central class. It encapsulates the logic for handling CMake dependencies.
* **`__init__`:**  Initialization logic, including setting up language support, finding the CMake executable, and initializing the trace parser.
* **`_get_cmake_info`:**  Crucial for extracting system information from CMake (paths, architectures, etc.). This involves running CMake in a controlled way.
* **`_preliminary_find_check`:** A quick check to see if the dependency *might* exist before a full CMake run. This saves time.
* **`_detect_dep`:** The heart of the dependency detection process. It uses CMake's `--find-package` mode and parses the trace output to extract information about the dependency (libraries, include directories, etc.).
* **`_get_build_dir` and `_setup_cmake_dir`:**  Manage temporary build directories for running CMake commands.
* **`_call_cmake`:**  Executes the CMake command with specific arguments.
* **`get_variable`:**  Allows fetching specific CMake variables.

**4. Connecting to Reverse Engineering:**

The key connection here is how external libraries are used in reverse engineering tools like Frida. Frida needs to link against and use the functionalities of other software components. CMake is a common way these components are built and packaged. Therefore, this `cmake.py` script is *essential* for Frida to incorporate these external pieces. Examples include:

* **Linking against a crypto library:** If Frida needs cryptographic functions, it might depend on a library built with CMake (like OpenSSL).
* **Using a specific data format library:** Libraries for handling specific file formats or protocols could be CMake-based dependencies.

**5. Identifying Low-Level and System Interactions:**

* **Binary Dependencies:**  The entire purpose is to find and link *binary* libraries (`.so`, `.dll`, `.dylib`).
* **Linux/Android Kernel/Framework:** While this specific script doesn't directly interact with the *kernel*, it's part of a *build system* for a tool (Frida) that *does* interact with these low-level components. Frida might depend on libraries that themselves have kernel or framework dependencies. The script needs to handle different target architectures and operating systems (as seen in the generator handling and path manipulation).
* **File System Operations:**  The code extensively uses `os` and `pathlib` for creating directories, checking file existence, and listing directory contents. This is a fundamental interaction with the operating system.
* **Process Execution:** The `_call_cmake` method uses `self.cmakebin.call` to execute external CMake processes, a core operating system interaction.

**6. Analyzing Logical Reasoning:**

The script exhibits logical reasoning in several places:

* **Generator Selection:** The code tries different CMake generators (`Ninja`, `Makefiles`, Visual Studio) to ensure compatibility across different systems. It remembers the last working generator to optimize future attempts. This is a decision-making process based on prior experience.
* **Dependency Resolution Logic:** The `_detect_dep` function implements a multi-step process to find the dependency, trying different approaches (modules, old-style variables). It makes decisions based on the output of CMake commands and the presence of specific files.
* **Path Searching:** The `_preliminary_find_check` and `_get_cmake_info` methods implement complex logic for searching through various potential locations for CMake modules and configuration files. This involves pattern matching and conditional checks.

**7. Considering Common User Errors:**

* **Incorrect `cmake_args`:** Users might provide invalid or conflicting arguments to CMake.
* **Missing Dependencies:** The script handles cases where the dependency isn't found, but the user might still have installation problems.
* **Incorrect `modules` or `components`:** Specifying the wrong module or component names is a common mistake. The script provides warnings and errors in such cases.
* **Environment Issues:** Problems with the user's PATH or other environment variables can prevent CMake from being found.

**8. Tracing User Actions:**

To reach this code, a user is typically:

1. **Configuring a Frida build:** This usually involves running a Meson command (e.g., `meson setup build`).
2. **The Meson build system encounters a dependency declared in a `meson.build` file.** This dependency is specified as a CMake dependency.
3. **Meson invokes the appropriate dependency handling logic, which leads to the instantiation of a `CMakeDependency` object.**
4. **The methods within `cmake.py` are then executed to locate and configure the dependency.**

**9. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each point raised in the original request with specific examples from the code. Use clear headings and bullet points for readability. Explain the concepts in a way that is accessible even to someone who isn't deeply familiar with CMake or Frida internals. Prioritize the most important aspects and provide concrete examples where possible.
This Python code file, `cmake.py`, is a crucial component of the Frida dynamic instrumentation tool's build system, specifically when dealing with external dependencies that are managed by CMake. Let's break down its functionality:

**Core Functionality: Managing CMake Dependencies**

The primary goal of this file is to provide a way for the Meson build system (which Frida uses) to find and integrate external libraries or components that utilize CMake as their build system. It essentially acts as a bridge between Meson and CMake.

Here's a breakdown of its key functions:

* **Finding the CMake Executable:** It ensures that the CMake executable is available on the system. It searches for it and stores its path.
* **Extracting CMake System Information:** It runs CMake in a special mode to gather information about the system's CMake setup, including module paths, architecture lists, and common library search paths. This is essential for correctly locating dependencies.
* **Searching for CMake Packages:**  It implements a sophisticated search strategy to locate CMake packages (libraries or components). This involves looking in standard CMake module paths, user-provided paths, and probing common library directories. It handles various naming conventions (e.g., `Find<Name>.cmake`, `<Name>Config.cmake`).
* **Detecting Dependencies using `find_package`:** The core of its functionality lies in using CMake's `find_package` command to locate the desired dependency. It executes CMake with specific arguments to trigger the search and captures the output.
* **Parsing CMake Trace Output:**  It leverages CMake's trace functionality to understand how `find_package` resolved the dependency. It parses the standard error output of CMake to extract information about found modules, include directories, compiler definitions, and libraries.
* **Handling Different CMake Generators:** It attempts to work with various CMake generators (like Ninja, Makefiles, Visual Studio) to ensure compatibility across different platforms and build environments.
* **Mapping Modules and Components:** It provides hooks (`_map_module_list`, `_map_component_list`) to potentially modify the list of modules or components requested from the CMake package. This allows for customization based on the specific dependency.
* **Providing Dependency Information to Meson:** Once a dependency is found, it extracts relevant information (include paths, link libraries, compiler flags) and makes it available to the Meson build system, allowing Frida to link against and use the external library.
* **Handling Optional Dependencies:** It supports the concept of optional modules within a CMake package.
* **Caching Information:** It uses caching (e.g., `_cached_listdir`, `_cached_isdir`) to optimize file system lookups, improving build performance.

**Relation to Reverse Engineering**

This file plays a crucial role in enabling Frida to interact with external libraries that might be used in reverse engineering scenarios. Here's an example:

* **Scenario:** Frida needs to interact with a library that handles a specific binary file format (e.g., a library for parsing ELF files). This library is built using CMake.
* **How `cmake.py` helps:**
    1. Frida's build system (Meson) will declare a dependency on this ELF parsing library.
    2. Meson will use the `CMakeDependency` class defined in `cmake.py` to find this library.
    3. `cmake.py` will search for the library's CMake configuration files (e.g., `FindElf.cmake` or `elf-config.cmake`).
    4. It will execute CMake's `find_package(Elf)` command internally.
    5. If found, `cmake.py` will parse the CMake output to determine the include directories needed to compile code that uses the ELF parsing library and the library files that need to be linked.
    6. Meson will then use this information to correctly compile and link Frida, allowing Frida's code to utilize the ELF parsing library's functions for reverse engineering tasks (e.g., analyzing executable structure).

**In essence, `cmake.py` makes it possible for Frida to leverage the functionality of other software components built with CMake, extending Frida's capabilities for reverse engineering.**

**Involvement of Binary Underlying, Linux, Android Kernel & Framework Knowledge**

While `cmake.py` doesn't directly interact with the kernel, it deals with concepts deeply intertwined with binary formats and system-level aspects:

* **Binary Libraries:** The entire purpose is to find and link against compiled binary libraries (e.g., `.so` on Linux, `.dll` on Windows, `.dylib` on macOS).
* **Platform Differences:** The code implicitly handles platform differences by trying different CMake generators and considering platform-specific library paths. The handling of Windows paths (not splitting on `:`) is a clear example.
* **Architecture Awareness:**  It extracts and uses architecture information (`MESON_ARCH_LIST`) from CMake to locate the correct version of libraries for the target architecture (e.g., x86, ARM). This is crucial for cross-compilation scenarios, which are common in embedded systems and Android development.
* **Library Search Paths:** The logic for searching for CMake packages involves understanding common library directory structures on Linux (e.g., `/usr/lib`, `/usr/local/lib`, directories under `/lib`, `/share`).
* **Android Context (Implicit):** While not explicitly stated in the code, Frida is heavily used in Android reverse engineering. The ability to handle CMake dependencies is essential for integrating with Android-specific libraries or components that might be built with CMake (e.g., certain native libraries). The handling of architecture and library paths is relevant to the Android environment.
* **System Environment Variables:** It uses environment variables like `PATH` and `<DependencyName>_DIR` to locate dependencies, reflecting an understanding of how operating systems locate executables and libraries.

**Logical Reasoning with Assumptions and Outputs**

Let's consider the `_preliminary_find_check` function as an example of logical reasoning:

* **Assumption (Input):** The user is trying to find a dependency named "MyLib".
* **Logic:**
    1. Check if a directory named "MyLib" or "mylib" exists in the provided `module_path`.
    2. Check if a directory named "cmake" or "CMake" exists inside those "MyLib" directories and contains files like `FindMyLib.cmake`, `MyLibConfig.cmake`, or `mylib-config.cmake` (case-insensitive).
    3. Check common library directories (like `lib`, `lib64`, `share`) within the `prefix_path` for directories named "MyLib" or "mylib" containing CMake configuration files.
    4. Check system-wide module paths and the `PATH` environment variable.
    5. Consider macOS framework structures (`MyLib.framework`).
    6. Check for environment variables like `MyLib_DIR`.
    7. Check the Linux CMake package registry (`~/.cmake/packages/MyLib`).
* **Output:** `True` if a potential CMake package for "MyLib" is found based on these heuristics, `False` otherwise.

**This preliminary check tries to quickly determine if the dependency *might* exist before performing a full CMake run, optimizing the process.**

**Common User or Programming Errors**

* **Incorrect `cmake_args`:** Users might provide invalid or conflicting CMake arguments in the `meson.build` file.
    * **Example:**  Specifying a wrong generator or trying to set a variable that's not understood by the dependency's CMakeLists.txt. This could lead to CMake failing during the `_call_cmake` step, and the parsing might fail.
* **Missing CMake Configuration Files:** If the dependency is present but its CMake configuration files (`Find<Name>.cmake` or `<Name>Config.cmake`) are missing or not in the expected locations, the `_preliminary_find_check` and the subsequent `find_package` call will fail.
    * **Example:** The user has installed the library's binaries but hasn't installed the development headers and CMake configuration files.
* **Incorrect `modules` or `components` names:**  When specifying the `modules` or `components` keyword in the `dependency()` call in `meson.build`, typos or incorrect names will lead to CMake not finding the specified targets, and the `traceparser.targets` lookup will fail in `_detect_dep`.
    * **Example:** The user intends to link against the `foo` target but mistakenly specifies `fooo`.
* **Environment Issues:** Problems with the user's `PATH` environment variable can prevent the script from finding the CMake executable itself.
    * **Example:** CMake is installed, but its directory is not in the system's `PATH`.
* **Permissions Issues:**  The script needs permissions to create temporary build directories and execute CMake. Lack of permissions will lead to errors.

**User Operation Flow to Reach This Code (Debugging Context)**

1. **User Configures Frida Build:** The user runs a Meson command to configure the Frida build (e.g., `meson setup build`).
2. **Meson Parses `meson.build`:** Meson reads the `meson.build` files in the Frida project.
3. **Dependency Declaration:**  One of the `meson.build` files contains a declaration for an external dependency that is identified as a CMake dependency. This might look something like:
   ```python
   dependency('MyLib', type='cmake', modules: ['target1', 'target2'])
   ```
4. **Meson Invokes `CMakeDependency`:** Meson recognizes the `type='cmake'` and instantiates the `CMakeDependency` class from `cmake.py`.
5. **Initialization (`__init__`)**: The `__init__` method starts the process:
   - It finds the CMake executable.
   - It extracts basic CMake system information using `_get_cmake_info`.
   - It performs the preliminary check using `_preliminary_find_check`.
6. **Dependency Detection (`_detect_dep`)**: If the preliminary check passes, the `_detect_dep` method is called:
   - It sets up a temporary CMake build directory.
   - It writes a temporary `CMakeLists.txt` file.
   - It executes CMake using `_call_cmake` with the `--find-package` option and tracing enabled.
7. **Trace Parsing:** The `CMakeTraceParser` parses the stderr output of the CMake execution.
8. **Information Extraction:** The script extracts include directories, libraries, and compiler flags from the parsed trace output.
9. **Meson Integration:** This information is then returned to Meson, allowing it to compile and link Frida correctly.

**As a debugging line, if a user is encountering issues with a CMake dependency in Frida, they might:**

* **Examine the Meson log:** Look for errors or warnings related to CMake execution or dependency resolution.
* **Set `MESON_LOG` environment variable:**  Run Meson with increased logging to see the specific CMake commands being executed and their output.
* **Manually run CMake commands:**  Try to reproduce the CMake commands that Meson is executing in the temporary build directory to isolate the problem.
* **Inspect the temporary `CMakeLists.txt`:** Check the content of the generated `CMakeLists.txt` file to ensure it's correctly configured.

Understanding this file is crucial for anyone wanting to debug issues related to external CMake dependencies in Frida or for those looking to add new CMake-based dependencies to the project.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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