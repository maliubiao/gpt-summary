Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Initial Understanding of the Code's Purpose:**

The first clue is the file path: `frida/releng/meson/mesonbuild/dependencies/cmake.py`. This immediately suggests that this code is part of the Frida project and is related to handling CMake dependencies within the Meson build system. The comments at the top reinforce this.

**2. Identifying Key Classes and Their Roles:**

Skimming the code, I see several important classes:

* `CMakeInfo`:  A simple data structure (named tuple) to hold information about the CMake environment.
* `CMakeDependency`: The core class. It inherits from `ExternalDependency`, which hints at its purpose: representing and managing external dependencies resolved through CMake.
* `CMakeDependencyFactory`:  A factory class to create `CMakeDependency` instances, potentially with some pre-set configurations.

**3. Analyzing `CMakeDependency` Methods - The Heart of the Logic:**

I start examining the methods within `CMakeDependency`, as this is where the main functionality resides. I look for verbs and keywords to understand what each method does:

* `__init__`:  Initialization - setting up language support, finding the CMake executable, and performing initial checks. The use of `CMakeExecutor` is a key detail.
* `_get_cmake_info`:  Extracting information about the CMake installation (module paths, root, architectures) by running CMake in a special way. This involves trying different generators.
* `_preliminary_find_check`: A quick check to see if the dependency *might* be found by looking for common CMake module/config file patterns in various locations. This is an optimization to avoid running the full CMake dependency resolution if it's unlikely to succeed.
* `_detect_dep`: The main method for finding the dependency. It uses CMake's `--find-package` mode and parses the trace output to extract information like include directories, libraries, and compiler definitions. This is where the core "reverse engineering" of CMake's output happens.
* `_get_build_dir`, `_setup_cmake_dir`, `_call_cmake`:  Methods for managing a temporary build directory for running CMake commands. This separation of concerns is typical.
* `get_variable`:  Allows retrieving CMake variables related to the found dependency.

**4. Connecting to Reverse Engineering:**

I think about how CMake is used in the context of dependencies. Often, libraries are built with CMake, and to use them in another project (like Frida), you need to find the necessary headers, libraries, and compiler flags. CMake provides "Find Modules" and "Config Packages" to help with this. `CMakeDependency` essentially automates this "finding" process, which is crucial for integrating with external components – a common task in reverse engineering (when you need to use existing libraries or frameworks).

**5. Identifying Interactions with the Binary Level, Linux, Android Kernel/Framework:**

I look for keywords and concepts related to these areas:

* **Binary Level:**  The very act of linking libraries is a binary-level operation. The code deals with extracting library paths and link arguments, which directly affect the final executable's binary structure.
* **Linux:**  File path separators (`os.pathsep`), environment variable handling (`os.environ`), and the mention of the Linux CMake registry (`~/.cmake/packages`) point to Linux-specific considerations.
* **Android Kernel/Framework:**  While the code itself doesn't explicitly mention Android kernel details, the broader context of Frida as a dynamic instrumentation tool makes this connection clear. Frida is heavily used on Android. The code's ability to handle dependencies is essential for Frida to interact with Android system libraries. The handling of different architectures (`self.cmakeinfo.archs`) is also relevant, as Android has various architectures (ARM, ARM64, etc.). The `native` keyword argument in `__init__` and the concept of host vs. build machine further support this.

**6. Logical Reasoning (Hypothetical Input/Output):**

I consider a simple scenario:

* **Input:** A Meson project declares a dependency on a library named "Foo" using the `cmake` dependency type.
* **Internal Processing:** `CMakeDependency` will run CMake's `find_package(Foo)` command. It will parse the output to find the location of "Foo"'s headers (include directories) and libraries.
* **Output:**  The `CMakeDependency` object will store this information in `self.compile_args` (for include paths) and `self.link_args` (for library paths). Meson will then use this information to compile and link the Frida components.

**7. Common Usage Errors:**

I think about potential problems users might encounter:

* **Incorrect `modules`:**  Specifying the wrong CMake target name is a likely issue. The code even has warnings about this.
* **Missing CMake:**  If CMake is not installed or not in the system's PATH, the dependency resolution will fail.
* **CMake configuration issues:** The external CMake project might not be properly configured to be found by `find_package`.

**8. Tracing User Operations (Debugging Clues):**

I imagine the user workflow:

1. **Edit `meson.build`:** The user adds a dependency like `dependency('Foo', type : 'cmake')`.
2. **Run `meson setup builddir`:** Meson starts the build process.
3. **Meson encounters the CMake dependency:**  It creates a `CMakeDependency` object.
4. **`CMakeDependency` runs CMake:**  It creates temporary build directories and calls the CMake executable.
5. **Errors occur:** If CMake fails, Meson will report an error. Looking at the debug output (`mlog.debug`) would reveal the specific CMake commands being run and their output, pointing to the source of the problem.

**9. Structuring the Explanation:**

Finally, I organize my findings into logical sections (Functionality, Relation to Reverse Engineering, Binary/Kernel Aspects, Logical Reasoning, User Errors, Debugging Clues), using clear language and examples to illustrate the points. I also use the code snippets to ground the explanation. The use of bullet points and code formatting improves readability.

This iterative process of reading the code, identifying key components, understanding their interactions, and relating them to the broader context of Frida and CMake allows for a comprehensive and informative explanation.
This Python code file, `cmake.py`, is part of the Frida dynamic instrumentation toolkit and specifically deals with handling dependencies that are managed using the CMake build system. Let's break down its functionality:

**Core Functionality: Integrating CMake Dependencies into Meson Builds**

The primary purpose of this code is to allow Frida (or projects using Meson) to declare and resolve dependencies that are built and managed using CMake. It acts as a bridge between the Meson build system and the CMake ecosystem.

Here's a breakdown of its key functionalities:

1. **Finding the CMake Executable:** It searches for the CMake executable on the system. This is crucial for invoking CMake to inspect dependencies.
2. **Extracting CMake System Information:** It runs CMake in a special mode to gather information about the CMake installation itself, such as module search paths, the CMake root directory, and supported architectures. This helps in locating dependency files later.
3. **Detecting CMake Dependencies (`_detect_dep`):** This is the core of the dependency resolution process. It uses CMake's `--find-package` mechanism to locate a specific dependency. It parses the standard error output of CMake (using `CMakeTraceParser`) to extract information about the dependency, such as:
    * Whether the package was found (`PACKAGE_FOUND`).
    * The version of the package (`PACKAGE_VERSION`).
    * Include directories (`PACKAGE_INCLUDE_DIRS`).
    * Compiler definitions (`PACKAGE_DEFINITIONS`).
    * Libraries to link against (`PACKAGE_LIBRARIES`).
    * CMake Targets: It can also identify and use imported CMake targets, which is the recommended way to handle CMake dependencies.
4. **Mapping Modules and Components:** It provides hooks (`_map_module_list`, `_map_component_list`) to potentially transform or filter the requested modules or components of a CMake dependency based on information available during the CMake processing.
5. **Providing Dependency Information to Meson:** Once the CMake dependency is detected, the `CMakeDependency` class stores the relevant information (include paths, link arguments, compiler flags) which Meson then uses to compile and link the project that depends on it.
6. **Handling Different CMake Generators:** It attempts to use different CMake generators (like Ninja, Makefiles, Visual Studio) to improve compatibility across different platforms.
7. **Caching and Optimization:** It uses caching (e.g., `_cached_listdir`, `_cached_isdir`) to avoid redundant file system operations, speeding up the dependency detection process.
8. **Handling Optional Dependencies:** It supports optional CMake modules, allowing the build to proceed even if a particular module is not found.
9. **Retrieving CMake Variables:**  The `get_variable` method allows retrieving specific CMake variables associated with a found dependency.

**Relationship to Reverse Engineering:**

This code is directly relevant to reverse engineering in several ways:

* **Interacting with Libraries Built with CMake:** Many libraries and frameworks that are targets for reverse engineering (or that need to be integrated with reverse engineering tools like Frida) are built using CMake. This code provides a mechanism to seamlessly integrate these libraries into the Frida build process.
* **Dynamic Instrumentation and Dependency Injection:** Frida works by injecting code into running processes. Often, you need to interact with specific libraries within that process. This code ensures that the necessary dependencies of Frida (or Frida gadgets) are correctly linked, allowing for interaction with those target libraries.
* **Example:** Imagine you are developing a Frida script to analyze an application that uses the Qt framework. Qt is often built with CMake. Using this `cmake.py` module, you can declare Qt as a dependency in Frida's build system. Meson will then use CMake to locate the Qt libraries and headers, ensuring that Frida can be built with the necessary Qt components. This allows your Frida script to interact with Qt objects and functions within the target application.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This code interacts with these low-level aspects in the following ways:

* **Binary Bottom:**
    * **Linking Libraries:** The core function is to find and provide the necessary libraries (`.so`, `.dll`, `.a`, `.lib`) for linking. Linking is a fundamental binary-level operation that combines compiled code into an executable or shared library.
    * **Compiler Flags:** It extracts compiler flags (like include paths `-I`) that tell the compiler where to find header files. Header files define the interfaces at the binary level.
* **Linux:**
    * **File System Paths:** It extensively uses file system paths (`os.path`, `pathlib`) and path separators (`os.pathsep`), which are operating system-specific. The code considers common Linux directory structures for finding libraries (e.g., `/lib`, `/usr/lib`).
    * **Environment Variables:** It interacts with environment variables like `PATH` to locate CMake and potentially dependency files.
    * **Linux CMake Registry:**  It checks the Linux-specific CMake package registry (`~/.cmake/packages`) for dependency information.
* **Android Kernel & Framework:**
    * **Cross-Compilation:** While not explicitly in this code, the underlying Meson build system (and Frida) frequently deals with cross-compilation for Android. CMake is commonly used in Android development, particularly for native components. This module enables managing CMake dependencies when building Frida for Android.
    * **Architecture Handling:** The code extracts and uses architecture information (`self.cmakeinfo.archs`) which is crucial for dealing with different Android architectures (ARM, ARM64, etc.).
    * **System Libraries:** When instrumenting Android processes, you often interact with Android framework libraries. This module helps manage dependencies on those native components if they are built with CMake.

**Logical Reasoning (Hypothetical Input and Output):**

Let's say you have a CMake-based library called "MyLib" with a CMakeLists.txt that defines a target called `mylib`. In your Frida `meson.build` file, you declare:

```python
mylib_dep = dependency('MyLib', type : 'cmake', modules : ['mylib'])
```

**Hypothetical Input to `_detect_dep` (internal function):**

* `name`: "MyLib"
* `modules`: `[('mylib', True)]`
* `components`: `[]`
* `args`:  Potentially empty or containing user-provided `cmake_args`.

**Hypothetical Output from `_detect_dep`:**

Assuming CMake finds "MyLib", the `CMakeTraceParser` will extract information. The `CMakeDependency` object will have attributes set like:

* `self.is_found`: `True`
* `self.version`: (The version of MyLib if defined in its CMakeLists.txt)
* `self.compile_args`: A list of strings like `['-I/path/to/MyLib/include']`
* `self.link_args`: A list of strings like `['-L/path/to/MyLib/lib', '-lmylib']`
* `self.found_modules`: `['mylib']`

If "MyLib" is not found, `self.is_found` would be `False`, and an exception would be raised if the dependency is required.

**Common User Errors:**

Users might encounter the following errors when using CMake dependencies:

1. **Incorrect Module Name:** Specifying the wrong module name in the `modules` list. For example, if the CMake target is actually called `MyLibStatic`, using `modules : ['mylib']` will fail. The code tries to guess the target, but explicit specification is safer.
    * **Example:** `dependency('MyLib', type : 'cmake', modules : ['wrong_module_name'])` will likely result in an error like "CMake: invalid module wrong_module_name for MyLib."
2. **Missing CMake:** If CMake is not installed or not in the system's `PATH`, the dependency will not be found.
    * **Example:** Running `meson setup build` without CMake installed will result in an error like "CMake binary for machine host not found."
3. **Dependency Not Found by CMake:** The CMake `find_package` command might fail to locate the dependency because it's not installed in a standard location or because its CMake configuration files are not properly set up.
    * **Example:** If "MyLib" is not installed, the CMake output parsed by `CMakeTraceParser` will not have `PACKAGE_FOUND` set to `True`, and the dependency will fail.
4. **Incorrect `cmake_args`:** Providing incorrect or conflicting arguments in the `cmake_args` keyword can lead to CMake failing to configure or find the package.
    * **Example:**  Passing an incorrect `-DCMAKE_PREFIX_PATH` might prevent CMake from finding the dependency.
5. **Case Sensitivity:** CMake can be case-sensitive in some scenarios (though the code attempts to handle case-insensitivity). Using the wrong case for module names might cause issues.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User Edits `meson.build`:** The user adds a dependency to their Frida module or project using the `dependency()` function with `type : 'cmake'`.
   ```python
   my_external_lib = dependency('MyExternalLib', type : 'cmake', modules : ['the_target'])
   ```
2. **User Runs `meson setup builddir`:** This command initiates the Meson build system.
3. **Meson Processes Dependencies:** Meson reads the `meson.build` file and encounters the CMake dependency.
4. **`CMakeDependencyFactory` is Called:** The `CMakeDependencyFactory` class (defined at the end of the file) is used to create an instance of `CMakeDependency`.
5. **`CMakeDependency.__init__` is Executed:**  The constructor initializes the dependency object, finds the CMake executable, and sets up the trace parser.
6. **`CMakeDependency._detect_dep` is Called:** This is the core function that attempts to find the CMake dependency. It sets up a temporary build directory, writes a minimal `CMakeLists.txt` file, and runs CMake with the `--find-package` option and trace output enabled.
7. **CMake Execution and Parsing:** CMake runs, and its standard error output is captured and parsed by the `CMakeTraceParser`.
8. **Dependency Information is Stored:** The parsed information (include paths, link arguments, etc.) is stored in the `CMakeDependency` object.
9. **Meson Uses the Dependency:** Meson uses the information from the `CMakeDependency` object to compile and link the parts of the Frida module or project that depend on "MyExternalLib."

**As a debugging clue:** If a CMake dependency is failing, you might:

* **Check Meson's output:** Meson will usually print detailed information about the CMake commands it's running and any errors that occur. Look for lines involving `cmake` in the output.
* **Enable verbose output:** Meson has options for verbose output (e.g., `-v` or `-vv`) which can provide more details about the dependency resolution process.
* **Inspect the temporary build directory:** The `_get_build_dir` method creates a temporary directory where CMake is executed. Examining the `CMakeLists.txt` and the CMake output files in this directory can provide insights into what's going wrong.
* **Manually run CMake:** You could try to manually run the CMake command that Meson is executing (you can find this in the verbose output) in the temporary build directory to isolate the CMake-specific issues.

In summary, this `cmake.py` file is a crucial component for integrating CMake-based dependencies into Frida projects built with Meson, bridging the gap between these two build systems and enabling the use of a wide range of external libraries in Frida's dynamic instrumentation capabilities.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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