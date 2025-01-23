Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Initial Understanding & Goal Setting:**

The first step is to recognize that this is a Python file named `cmake.py` within a larger project (`frida`, specifically the `frida-swift` subproject). The file deals with CMake dependencies within the Meson build system. The request asks for the file's functionality, its relation to reverse engineering, its use of low-level/kernel knowledge, logical reasoning, potential user errors, and how a user might arrive at this code during debugging.

**2. Core Functionality Identification (Top-Down Approach):**

I start by looking at the main class, `CMakeDependency`. Its name strongly suggests its primary purpose: handling CMake dependencies within Meson. I then scan the methods of this class, focusing on the most significant ones:

* `__init__`:  This is the constructor. It initializes the `CMakeDependency` object, including searching for the CMake executable, setting up the trace parser, and performing an initial dependency detection.
* `_detect_dep`: This method seems crucial for actually finding the dependency using CMake. The name "detect dependency" is a strong indicator.
* `_get_cmake_info`:  This function is clearly responsible for gathering information about the CMake installation itself (paths, architecture, etc.). This is fundamental to any CMake interaction.
* `_preliminary_find_check`:  This suggests an initial, faster check before the full dependency detection.
* `_get_build_dir` and `_setup_cmake_dir`: These handle the creation and setup of temporary build directories where CMake commands are executed.
* `_call_cmake`:  This is the workhorse – actually executing CMake with specified arguments.
* `get_variable`: This method allows retrieving CMake variables, providing a way to access information discovered during the dependency search.

**3. Relation to Reverse Engineering:**

Now, I consider how this code might be relevant to reverse engineering, given Frida's purpose as a dynamic instrumentation tool.

* **Instrumenting Software Built with CMake:**  The most direct connection is that Frida might need to instrument software built using CMake. This code facilitates finding and linking against libraries and headers of such software.
* **Dependency Analysis:**  Reverse engineers often need to understand the dependencies of a target application. This code plays a part in resolving those dependencies.
* **Modifying Build Processes (Less Direct):** While not the primary function, if a reverse engineer needs to modify the build process of a target, understanding how Frida interacts with CMake can be helpful.

**4. Low-Level/Kernel/Android Aspects:**

I look for clues related to system-level concepts:

* **Operating System Specifics:** The code uses `is_windows()` and mentions Cygwin and Darwin (macOS), indicating awareness of platform differences.
* **Architecture Awareness:**  The `cmakeinfo.archs` and the handling of library paths (`lib`, `lib64`, etc.) point to handling different architectures.
* **File System Interaction:**  Extensive use of `os.path` and `pathlib` indicates interaction with the file system, which is fundamental to low-level operations.
* **Environment Variables:**  The code accesses environment variables like `PATH` and `[name]_DIR`, reflecting interaction with the operating system environment.
* **CMake Generators:**  The concept of CMake generators (Ninja, Makefiles, Visual Studio) is related to the underlying build process and how executables are created.

**5. Logical Reasoning and Assumptions:**

Here, I focus on how the code makes decisions and the assumptions it operates under.

* **Trying Different CMake Generators:** The code iterates through a list of generators, indicating a strategy to handle potentially different CMake environments. The assumption is that one of the listed generators will work.
* **Preliminary Check:** The `_preliminary_find_check` suggests an optimization to avoid running the full CMake process if the dependency is likely not present. The assumption is that simple file system checks can provide a good initial filter.
* **CMake Variable Interpretation:** The code parses CMake output and interprets variables like `PACKAGE_FOUND`, `PACKAGE_VERSION`, `PACKAGE_INCLUDE_DIRS`, etc. It assumes these variables are set by the CMake find modules or config files.
* **Target Guessing:** The logic to guess CMake targets (`if f'{lname}::{lname}' == tg or lname == tg.replace('::', '')`) is a heuristic based on common CMake naming conventions.

**6. User Errors:**

I consider what mistakes a user might make when using this code or when it encounters problems.

* **Incorrect `cmake_args`:**  Providing invalid or conflicting CMake arguments.
* **Missing CMake:**  Not having CMake installed or accessible in the `PATH`.
* **Incorrect Module Names:**  Specifying the wrong CMake module names in the `modules` argument.
* **Environment Variables Not Set:**  Relying on environment variables like `[name]_DIR` that are not set.
* **Version Mismatches:**  The code checks for a minimum CMake version, and using an older version could cause issues.

**7. Debugging and User Journey:**

Finally, I think about how a user might end up looking at this specific code during debugging.

* **Dependency Resolution Failures:** If Meson fails to find a CMake dependency, the user might investigate the CMake-related parts of the Meson output or even step into the Meson source code.
* **Build Errors Related to Missing Libraries/Headers:** If the build fails due to missing dependencies, the user might trace the dependency resolution process back to this code.
* **Investigating Custom CMake Modules:** If a user has custom CMake modules and Meson isn't finding them, they might examine how Meson searches for CMake modules.
* **Contributing to Frida:** A developer contributing to Frida might need to understand how Frida handles its own CMake dependencies or dependencies of the software it's instrumenting.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  "This just finds CMake dependencies."  **Correction:** It's not just *finding*, but also *configuring* and *extracting information* about them.
* **Initial thought:**  "The reverse engineering link is weak." **Correction:** While not directly a reverse engineering *tool*, it's essential for Frida to function correctly with software built using CMake, which is often the target of reverse engineering efforts.
* **Focusing too much on individual lines:**  **Correction:**  Shift focus to the overall purpose and interactions between methods to understand the high-level functionality.

By following this structured approach, I could systematically analyze the code and generate a comprehensive and informative explanation covering the various aspects requested in the prompt.
This Python code file, `cmake.py`, is part of the Frida dynamic instrumentation toolkit and is responsible for handling dependencies that are managed by the CMake build system. Let's break down its functionality and address your specific points.

**Core Functionality:**

The primary goal of this code is to allow Meson (the build system Frida uses) to find and use external libraries or components that are built and managed using CMake. It achieves this by:

1. **Locating CMake:** It first ensures that the CMake executable is available on the system.
2. **Gathering CMake System Information:** It extracts crucial information about the CMake installation, such as module search paths, CMake root directory, supported architectures, and common library paths. This is done by running CMake in a special "information gathering" mode.
3. **Finding CMake Packages:**  It attempts to locate the requested dependency by leveraging CMake's `find_package()` mechanism. It essentially simulates a CMake build to see if the dependency can be found.
4. **Extracting Dependency Information:** If the dependency is found, it parses the output of the CMake run to extract relevant information, such as:
    * **Include Directories:** Paths to header files needed for compilation.
    * **Library Files:** Paths to the compiled library files (.so, .a, .lib, .dylib).
    * **Compiler Definitions:** Preprocessor definitions required for compilation.
    * **Linker Flags:** Special flags needed for linking against the library.
    * **CMake Targets:**  Modern CMake uses "imported targets" to represent dependencies. This code attempts to identify and use these targets.
5. **Providing Dependency Information to Meson:**  It then exposes this extracted information (include directories, libraries, compiler flags, etc.) to Meson, allowing Meson to correctly link and compile against the CMake-managed dependency.

**Relationship to Reverse Engineering:**

This code is directly relevant to reverse engineering when the software being analyzed or instrumented by Frida has dependencies managed by CMake.

* **Example:** Imagine you are reverse-engineering a closed-source application built with CMake that uses the `libuv` library. If Frida needs to interact with this application (e.g., by injecting code or hooking functions within `libuv`), Meson needs to know how to find `libuv`. This `cmake.py` code would be responsible for:
    1. Running CMake's `find_package(libuv)` (or a similar mechanism).
    2. Discovering the location of `libuv`'s header files (e.g., `/usr/include/uv.h`).
    3. Discovering the location of the `libuv` library file (e.g., `/usr/lib/libuv.so`).
    4. Providing this information to Meson so that Frida's build process can correctly link against `libuv`.

**In this scenario, without `cmake.py`, Frida might fail to build or might not be able to interact correctly with the target application because it wouldn't know where the necessary dependencies are located.**

**Binary 底层, Linux, Android Kernel & Framework Knowledge:**

This code touches upon several low-level and operating system concepts:

* **Binary Layout and Linking:** The code deals with identifying and locating binary library files (`.so`, `.a`, `.lib`, `.dylib`). This is fundamental to how programs are built and linked. It understands the difference between static and shared libraries.
* **File System Paths:** It heavily relies on understanding file system paths and conventions for locating header files and libraries (e.g., `/usr/include`, `/usr/lib`, `/opt/local/include`, etc.).
* **Operating System Differences:** The code explicitly handles differences between Windows and other systems (primarily Linux/macOS) in how paths are handled and how CMake is invoked.
* **Architecture Awareness:** The code extracts and utilizes information about system architectures (e.g., x86, x86_64, ARM) to locate architecture-specific libraries. It looks for paths like `lib/x86_64`, `lib64`, etc.
* **Environment Variables:** It uses environment variables like `PATH` and dependency-specific variables (e.g., `LIBFOO_DIR`) to help locate dependencies.
* **CMake Generators (Ninja, Makefiles, Visual Studio):**  It understands that CMake can generate build files for different tools, and it attempts to work with various generators.
* **Linux CMake Registry:** It checks the Linux-specific CMake package registry (`~/.cmake/packages`) for dependency information.
* **Android (Implicit):** While not explicitly mentioning the Android kernel, the concepts of shared libraries (`.so`) and architecture-specific libraries are directly relevant to Android development and reverse engineering. Frida often targets Android, and the ability to handle CMake dependencies is crucial for interacting with Android applications and libraries built with CMake.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

* **`name` (Dependency Name):** "zlib"
* **`environment`:**  A Meson `Environment` object representing a Linux x86_64 build.
* **`kwargs`:** `{'modules': ['ZLIB::ZLIB']}` (specifying a CMake imported target).

**Logical Reasoning Flow:**

1. The `CMakeDependency` object is initialized.
2. CMake executable is located.
3. CMake system information is gathered for the target machine.
4. The `_detect_dep` method is called.
5. CMake is invoked in a temporary build directory with arguments to find the "zlib" package and specifically the "ZLIB::ZLIB" target.
6. CMake's output (especially stderr, which contains the trace) is parsed by `CMakeTraceParser`.
7. The parser identifies that the "ZLIB::ZLIB" target exists and extracts its properties (include directories, library paths, compiler flags).

**Hypothetical Output:**

* **`self.is_found`:** `True`
* **`self.version`:**  (The version of zlib found on the system, e.g., "1.2.11")
* **`self.compile_args`:** `['-I/usr/include']` (assuming zlib headers are in `/usr/include`)
* **`self.link_args`:** `['-L/usr/lib/x86_64-linux-gnu', '-lz']` (assuming zlib library is `/usr/lib/x86_64-linux-gnu/libz.so`)
* **`self.found_modules`:** `['ZLIB::ZLIB']`

**User or Programming Common Usage Errors:**

* **Incorrect Dependency Name:**  Specifying the wrong name for the dependency (e.g., `"zlib"` instead of `"ZLIB"` if CMake expects the latter). This would lead to `find_package()` failing.
* **Missing CMake:** Not having CMake installed or in the system's `PATH`. The `CMakeExecutor` would fail to find the executable.
* **Incorrect `cmake_args`:**  Providing invalid or conflicting CMake arguments in the `kwargs`. This could cause the CMake run to fail or behave unexpectedly.
* **Specifying Non-Existent Modules:** Providing a `modules` list with CMake target names that don't actually exist in the dependency's CMake configuration.
* **Environment Variables Not Set:** If the CMake package relies on environment variables (e.g., `ZLIB_DIR`) to be set, and they are not, the dependency might not be found.
* **Conflicting CMake Generators:**  If the user's system has issues with certain CMake generators, the code might fail when trying different generators.
* **Case Sensitivity Issues:** CMake can be case-sensitive in some situations. Incorrectly cased module or package names could lead to failures.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **User attempts to build a Frida module or project that depends on a library managed by CMake.**  This build is using Meson.
2. **Meson encounters a `dependency()` call in the `meson.build` file that specifies a CMake dependency.** For example:
   ```python
   libfoo_dep = dependency('libfoo', type='cmake')
   ```
3. **Meson's dependency resolution logic identifies that the dependency type is 'cmake'.**
4. **Meson then instantiates the `CMakeDependency` class from this `cmake.py` file.**
5. **If the dependency is not found, or if there are issues extracting the necessary information, Meson might report an error.** For example:
   ```
   Dependency libfoo found via CMake but could not extract necessary information.
   ```
6. **To debug this, the user might:**
   * **Examine the Meson build log:** The log might show the CMake commands being executed and their output (stdout and stderr).
   * **Set `MESON_LOG` environment variable:** This can provide more detailed debugging information from Meson, including the steps taken during dependency resolution.
   * **Step through the Meson source code:** A developer familiar with Meson might set breakpoints in `cmake.py` to understand how the dependency is being located and processed. They would look at the values of variables like `cmake_opts`, `ret1`, `out1`, `err1`, and the contents of `self.traceparser.vars` and `self.traceparser.targets`.
   * **Manually run the CMake commands:** The user might copy the CMake commands from the Meson log and run them manually in a terminal to isolate the issue.
   * **Inspect the target library's CMake files:** The user might need to examine the `CMakeLists.txt` and any Find modules (`FindLibfoo.cmake`) associated with the dependency to understand how it is supposed to be found.

By following these steps, a user trying to understand why a CMake dependency is not being found or is causing build errors in their Frida project would likely end up examining the logic within this `cmake.py` file.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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