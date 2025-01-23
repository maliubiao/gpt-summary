Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Core Purpose:** The very first lines tell us this is about `cmake.py` within the `frida` project, specifically for dependency handling in the Meson build system. This immediately sets the context. Frida is for dynamic instrumentation, and Meson is a build system. This file bridges them for CMake-based dependencies.

2. **Identify Key Classes and Their Roles:** Scan the code for class definitions. The main ones are `CMakeInfo`, `CMakeDependency`, and `CMakeDependencyFactory`.

    * **`CMakeInfo`:**  Looks like a data structure holding important CMake system information (module paths, root, architectures). This is likely gathered once and reused.
    * **`CMakeDependency`:**  This is the central class. It inherits from `ExternalDependency`, indicating it's about managing external dependencies. Its methods clearly deal with finding, configuring, and extracting information from CMake packages.
    * **`CMakeDependencyFactory`:** A factory class to create `CMakeDependency` objects, potentially with pre-configured settings.

3. **Analyze `CMakeDependency`'s Methods - Function by Function:** Go through the methods of the `CMakeDependency` class. Focus on what each method does and its potential relevance to the questions:

    * `_gen_exception`: Simple helper for creating dependency exceptions.
    * `_main_cmake_file`, `_extra_cmake_opts`: Customizable points for specific dependencies (looks like default CMake file).
    * `_map_module_list`, `_map_component_list`, `_original_module_name`:  Mechanisms to map or transform module/component names. This suggests a level of abstraction or compatibility handling.
    * `__init__`:  The constructor is crucial. Note the gathering of language information, initialization of the `CMakeExecutor`, `CMakeTraceParser`, and the calls to `_get_cmake_info` and `_detect_dep`. This is where the core dependency detection logic starts.
    * `_get_cmake_info`: This method is key for understanding how CMake's system information is extracted. It involves running CMake with different generators and parsing the output. The use of `CMakeTraceParser` is significant.
    * `_cached_listdir`, `_cached_isdir`:  Caching file system operations for efficiency - a common performance optimization.
    * `_preliminary_find_check`: A fast initial check for CMake module files before the more involved `find_package`. This is important for performance.
    * `_detect_dep`: The heart of the dependency detection. It involves running `cmake` with `--find-package`, parsing the trace output, and extracting information like version, include directories, libraries, and compiler flags. The handling of CMake targets and the fallback to old-style variable extraction are important details.
    * `_get_build_dir`, `_setup_cmake_dir`: Setting up the temporary build environment for CMake execution. The manipulation of `CMakeLists.txt` is interesting.
    * `_call_cmake`:  Actually executing the `cmake` command.
    * `log_tried`, `log_details`: Methods for logging information about the dependency resolution process.
    * `get_variable`: Allows retrieving CMake variables, crucial for accessing information exposed by the dependency's CMake configuration.

4. **Connect to the Questions:** Now, with an understanding of the code's structure and functionality, address each part of the prompt:

    * **Functionality:**  Summarize the key actions of the code: finding CMake, gathering system info, running `find_package`, parsing output, extracting details.
    * **Reverse Engineering:** Look for actions directly aiding reverse engineering. Frida's purpose is dynamic instrumentation, so think about *how* this file helps. The ability to find and link against libraries used by target processes is critical. Consider examples like finding a specific version of OpenSSL.
    * **Binary/Low-Level/Kernel/Framework:**  Identify aspects touching these areas. Linking involves binaries. Linux/Android are mentioned in the code (platform checks). The toolchain setup implicitly deals with compilers. Kernel knowledge is less direct here but the resulting linked libraries can interact with the kernel.
    * **Logical Reasoning:** Look for conditional logic and decisions. The choice of CMake generators, the fallback to old-style variables, and the handling of optional modules are examples. Formulate input/output scenarios. Example: providing an incorrect module name.
    * **User/Programming Errors:**  Consider common mistakes users might make when specifying dependencies. Incorrect module names, missing CMake packages, version mismatches are good examples.
    * **User Operation to Reach Here:**  Trace back the steps a user would take to trigger this code. It starts with defining a dependency in a Meson build file that relies on a CMake package.

5. **Refine and Organize:**  Structure the answer clearly, using headings and bullet points. Provide specific code snippets or examples where appropriate. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. Double-check that all parts of the prompt have been addressed. For example, initially, I might have missed the nuance of the `_map_module_list` and `_map_component_list` methods, but reviewing the code would highlight their presence and purpose. Similarly, the caching mechanisms might be a detail easily overlooked on a first pass.

6. **Self-Correction/Review:** After drafting the answer, reread the prompt and the answer to ensure alignment. Are there any ambiguities?  Have all constraints been met?  Is the explanation clear and easy to understand?  For example, I might initially focus too much on the CMake specifics and forget to explicitly link it back to Frida's purpose. A review would catch this.
这个Python源代码文件 `cmake.py` 是 Frida 动态 Instrumentation 工具中用于处理基于 CMake 的外部依赖项的模块。它的主要功能是让 Meson 构建系统能够找到、配置和链接使用 CMake 构建的库。

下面我们来详细列举它的功能，并根据你的要求进行举例说明：

**主要功能:**

1. **查找 CMake 可执行文件:**  代码会查找系统中可用的 CMake 可执行文件，并确定其版本。
2. **获取 CMake 系统信息:** 它会尝试运行 CMake 来获取目标系统的基本信息，例如模块搜索路径、CMake 根目录、支持的架构等。这通过尝试不同的 CMake 生成器来实现，以提高兼容性。
3. **初步查找依赖项:** 在进行更复杂的 CMake 操作之前，它会先进行初步的查找，检查用户提供的模块路径、系统模块路径以及预定义的路径中是否存在与目标依赖项相关的 CMake 模块文件（例如 `Find<Name>.cmake` 或 `<Name>Config.cmake`）。
4. **使用 CMake 的 `find_package` 功能查找依赖项:**  这是核心功能。它会创建一个临时的 CMake 项目，并使用 CMake 的 `find_package` 命令来查找指定的依赖项。它会尝试不同的 CMake 生成器，并捕获 CMake 的输出和错误信息。
5. **解析 CMake 的跟踪输出:**  为了获取依赖项的详细信息，代码使用了 `CMakeTraceParser` 来解析 CMake 在运行 `find_package` 时生成的跟踪输出（stderr）。这个跟踪输出包含了 CMake 执行的函数调用和变量值。
6. **提取依赖项信息:** 从解析的跟踪输出中，它会提取关键的依赖项信息，例如：
    * 依赖项是否找到 (`PACKAGE_FOUND`)
    * 依赖项的版本 (`PACKAGE_VERSION`)
    * 头文件路径 (`PACKAGE_INCLUDE_DIRS`)
    * 预处理器定义 (`PACKAGE_DEFINITIONS`)
    * 库文件 (`PACKAGE_LIBRARIES`)
    * CMake 目标 (targets)
7. **处理 CMake 模块和组件:** 它允许指定要查找的 CMake 模块和组件，并提供映射和转换这些模块和组件名称的机制。
8. **生成编译和链接参数:** 根据提取到的依赖项信息，它会生成相应的编译参数（例如 `-I<include_path>` 和预处理器定义）和链接参数（例如库文件）。
9. **处理不同的 CMake 生成器:** 为了提高兼容性，它会尝试使用不同的 CMake 生成器（例如 Ninja, Unix Makefiles, Visual Studio），并记录成功工作的生成器。
10. **处理静态和共享库:**  它会根据构建配置（静态或共享）来调整查找依赖项的方式。
11. **提供获取 CMake 变量的功能:** 允许用户获取在 CMake 查找过程中设置的 CMake 变量的值。

**与逆向方法的关系及举例说明:**

这个文件直接支持 Frida 的逆向工程能力，因为它负责找到目标进程可能依赖的库。

* **例子:** 假设 Frida 需要 hook 一个使用了 OpenSSL 库的进程。`cmake.py` 会负责在系统中找到 OpenSSL 的开发包（包含头文件和库文件）。这样，Frida 的 C/C++ 代码才能正确地包含 OpenSSL 的头文件并链接到 OpenSSL 库，从而实现对 OpenSSL 相关功能的 hook。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **二进制底层:**  `cmake.py` 最终目的是找到二进制库文件 (`.so` on Linux/Android, `.dylib` on macOS, `.dll` on Windows) 并将其链接到 Frida 的组件中。这涉及到操作系统加载器如何处理二进制文件以及链接器的作用。
* **Linux/Android:**
    * **库文件路径:** 代码中硬编码了一些常见的 Linux/Android 库文件搜索路径（例如 `lib`, `lib64`, `share`），以及根据架构动态生成的路径（例如 `lib/arm64-v8a`）。
    * **CMake 注册表:** 代码会检查 Linux 的 CMake 注册表（`~/.cmake/packages`）以查找已安装的 CMake 包。
    * **环境变量 `PATH`:** 代码会检查环境变量 `PATH`，因为某些 CMake 包可能将其可执行文件放在 `PATH` 环境变量包含的目录下。
* **Android 框架:** 虽然这个文件本身不直接操作 Android 内核或框架的 API，但它找到的库文件可能会是 Android 框架的一部分。例如，如果 Frida 需要 hook Android 的某个系统服务，它可能需要找到并链接到 Android 的 framework 库。
* **架构 (Architecture):** 代码会尝试获取目标系统的架构信息，并将其传递给 CMake，以便 CMake 能够找到对应架构的库文件。例如，在 Android 上，可能会有 `arm`, `arm64`, `x86`, `x86_64` 等不同的架构。

**逻辑推理及假设输入与输出:**

假设输入：

* **依赖项名称:** "zlib"
* **Meson 构建配置:**  目标平台为 Linux x86_64
* **系统中已安装 zlib 的开发包，其 CMake 配置文件位于 `/usr/lib/cmake/ZLIB`**

逻辑推理过程：

1. `CMakeDependency` 初始化，接收依赖项名称 "zlib"。
2. 执行初步查找，可能会在 `/usr/lib/cmake/ZLIB` 中找到 `ZLIBConfig.cmake`。
3. 如果初步查找成功，则跳过后续步骤；否则，会创建一个临时的 CMake 项目。
4. 运行 CMake 的 `find_package(zlib)` 命令。
5. `CMakeTraceParser` 解析 CMake 的跟踪输出。
6. 从跟踪输出中提取到 `ZLIB_INCLUDE_DIR` 为 `/usr/include`，`ZLIB_LIBRARY` 为 `/usr/lib/x86_64-linux-gnu/libz.so`。

假设输出：

* `self.is_found` 为 `True`
* `self.version` 可能从 `zlibConfig.cmake` 中提取到，例如 "1.2.11"
* `self.compile_args` 包含 `"-I/usr/include"`
* `self.link_args` 包含 `"/usr/lib/x86_64-linux-gnu/libz.so"`

**用户或编程常见的使用错误及举例说明:**

* **错误指定模块名称:** 用户在 `meson.build` 文件中指定了错误的 CMake 模块名称。

   ```python
   # 错误的模块名称 "ZLib" (大小写敏感)
   zlib_dep = dependency('zlib', modules: ['ZLib'], method: 'cmake')
   ```

   **结果:** CMake 无法找到名为 "ZLib" 的模块，导致构建失败。错误信息可能会提示找不到指定的模块，并列出可用的模块。

* **缺少 CMake 依赖项:** 目标系统上没有安装所需的 CMake 依赖项的开发包。

   ```python
   # 假设系统上没有安装 libcurl 的开发包
   curl_dep = dependency('libcurl', method: 'cmake')
   ```

   **结果:** CMake 的 `find_package(libcurl)` 命令会失败，`self.is_found` 为 `False`，构建过程会报错，提示找不到 libcurl。

* **CMake 包配置不正确:**  即使安装了依赖项，其 CMake 配置文件可能存在问题，例如变量未定义或路径不正确。

   **结果:** `CMakeTraceParser` 解析跟踪输出时可能会遇到错误，或者提取到的信息不完整或错误，导致后续的编译或链接失败。

* **指定的 CMake 版本过低:**  代码中设置了最低 CMake 版本要求 (`class_cmake_version = '>=3.4'`)，如果系统上的 CMake 版本低于此要求，将会报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本或 Frida 组件的代码。**
2. **用户使用 Meson 构建系统来编译 Frida 或其组件。** 这涉及到在 `meson.build` 文件中定义依赖项。
3. **在 `meson.build` 文件中，用户使用 `dependency()` 函数声明一个基于 CMake 的外部依赖项，并指定 `method: 'cmake'`。** 例如：

   ```python
   my_lib_dep = dependency('mylib', method: 'cmake')
   ```

4. **Meson 构建系统在处理依赖项时，会识别出 `method: 'cmake'`，并调用 `frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/cmake.py` 文件中的 `CMakeDependency` 类来处理这个依赖项。**
5. **`CMakeDependency` 类会执行上述的查找、配置和提取信息的过程。**
6. **如果构建过程中遇到与 CMake 依赖项相关的问题，例如找不到依赖项或链接错误，开发者可能会检查 Meson 的构建日志，其中会包含 `cmake.py` 执行的详细信息，例如尝试的 CMake 命令、跟踪输出等。** 这可以帮助开发者诊断问题，例如确认依赖项是否安装、CMake 配置是否正确等。
7. **开发者还可以通过设置 Meson 的调试级别来获取更详细的输出，以便了解 `cmake.py` 的具体执行过程。**

总而言之，`frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/cmake.py` 文件是 Frida 构建系统中一个至关重要的组件，它使得 Frida 能够方便地使用和链接基于 CMake 构建的第三方库，从而扩展 Frida 的功能和支持更广泛的目标环境。理解这个文件的功能对于调试 Frida 构建过程中的依赖项问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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