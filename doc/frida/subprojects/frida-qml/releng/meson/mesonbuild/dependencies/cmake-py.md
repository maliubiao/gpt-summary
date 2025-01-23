Response:
Let's break down the thought process for analyzing this Python code for the `CMakeDependency` class within the Frida project.

**1. Initial Understanding & Purpose:**

The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/dependencies/cmake.py` immediately tells us this is part of Frida, specifically related to its QML integration, and focuses on dependency management within the Meson build system. The filename `cmake.py` strongly suggests this code is responsible for finding and integrating CMake-based dependencies.

**2. High-Level Functionality (Skimming the Code):**

A quick skim reveals keywords and concepts like:

* `ExternalDependency`, `DependencyException`:  This is about managing external libraries that the Frida QML component relies on.
* `CMakeExecutor`, `CMakeTraceParser`, `CMakeToolchain`: These indicate interactions with the CMake build system itself.
* `find_package`, `modules`, `components`:  These are common CMake terms for finding libraries.
* `compile_args`, `link_args`: This points to extracting necessary compiler and linker flags.
* `_detect_dep`, `_get_cmake_info`:  These look like the core logic for finding and extracting information about CMake dependencies.

**3. Detailed Analysis - Function by Function (and Key Attributes):**

Now, let's go through the code more methodically, focusing on the requested aspects:

* **`__init__`:**  This is the constructor. It initializes the `CMakeDependency` object, sets up language support, finds the CMake executable, and importantly calls `_detect_dep` which is a key function.

* **`_detect_dep`:** This seems to be the heart of the dependency detection. It uses CMake's trace functionality to parse the output of `find_package`, extracts version information, compiler flags, and linker flags. It also handles module/target selection.

* **`_get_cmake_info`:**  This function is crucial for gathering basic information about the CMake environment itself (module paths, architecture, etc.). It uses CMake to probe the system.

* **`_preliminary_find_check`:** This appears to be an optimization – a quick, less resource-intensive check to see if a CMake package is likely to exist before running the full `find_package`. It checks common installation locations.

* **Other helper functions:**  `_main_cmake_file`, `_extra_cmake_opts`, `_map_module_list`, `_map_component_list`, `_original_module_name`, `_get_build_dir`, `_setup_cmake_dir`, `_call_cmake`, `get_variable`. These support the core detection logic.

* **Class Attributes:** `class_cmakeinfo`, `class_cmake_version`, `class_cmake_generators`, `class_working_generator`. These represent shared state or configuration for CMake dependency handling.

**4. Connecting to the Request's Specific Points:**

Now, let's explicitly address each point in the request:

* **Functionality:**  Summarize the purpose of each key function and the overall goal of the class.

* **Reverse Engineering:**  Focus on how the code helps when reverse engineering. The ability to find libraries (`find_package`), extract compiler/linker flags, and work with specific CMake targets (`modules`) are directly relevant. Provide concrete examples like hooking into a function from a CMake-managed library.

* **Binary/Kernel/Framework:** Look for areas where the code interacts with low-level concepts. The handling of architectures (`self.cmakeinfo.archs`), the potential need to find libraries in system paths, and the interaction with the underlying operating system (Linux, Android via the broader Frida context) are relevant. Mention how CMake helps abstract away platform differences.

* **Logical Reasoning:** Examine sections where assumptions are made or different possibilities are explored. The generator selection logic in `_get_cmake_info` and `_detect_dep`, the guessing of CMake targets when not explicitly provided, and the fallback to older CMake variable methods demonstrate logical reasoning. Construct hypothetical scenarios with inputs and expected outcomes (success/failure, which generator is chosen).

* **User/Programming Errors:** Identify common mistakes a user or developer might make when interacting with this code or the underlying CMake system. Incorrect module names, missing dependencies, or problems with CMake configuration are good examples. Explain how these errors might manifest.

* **Debugging Lineage:**  Think about how a user's actions in Frida could lead to this code being executed. The process of building Frida, particularly the QML component, and the need to find external libraries are key steps. Trace the execution flow conceptually.

**5. Structuring the Answer:**

Organize the findings into clear sections based on the request's points. Use headings and bullet points for readability. Provide code snippets where necessary to illustrate specific functionalities. Be precise in the terminology.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Perhaps this code directly executes reverse engineering tools. **Correction:** Realized it's more about *finding the necessary libraries and tools* for reverse engineering tasks that Frida performs.
* **Initial thought:** Focus only on the Python code. **Correction:**  Recognized the need to explain the underlying CMake concepts to fully understand the Python code's purpose.
* **Initial thought:** Provide overly technical details of CMake internals. **Correction:**  Focused on the aspects of CMake that are directly relevant to the Python code's function within Frida.

By following this structured approach, combining high-level understanding with detailed code analysis, and explicitly addressing each point of the request, a comprehensive and accurate explanation can be generated.
这个Python源代码文件 `cmake.py` 是 Frida 动态 Instrumentation 工具中，用于处理 **CMake 构建的外部依赖** 的一个关键组件。 它的主要功能是允许 Frida 的构建系统 (Meson) 查找、配置和集成基于 CMake 构建的第三方库。

以下是该文件的详细功能列表，并结合了逆向、底层、内核、用户错误和调试线索的说明：

**核心功能:**

1. **查找 CMake 可执行文件:**  `CMakeExecutor` 类用于查找系统中可用的 CMake 可执行文件，并检查其版本是否满足最低要求 (`class_cmake_version = '>=3.4'`)。

2. **获取 CMake 系统信息:** `_get_cmake_info` 函数通过运行 CMake 并解析其输出来获取关于目标系统的关键信息，例如模块搜索路径 (`module_paths`)、CMake 根目录 (`cmake_root`)、支持的架构 (`archs`) 以及常见的库搜索路径 (`common_paths`)。

3. **预先检查依赖是否存在:** `_preliminary_find_check` 函数在执行完整的 CMake `find_package` 之前，进行快速的文件系统检查，以确定依赖项是否存在于常见的安装位置。这可以提高构建效率。

4. **使用 `find_package` 检测依赖:** `_detect_dep` 函数是核心的依赖检测逻辑。它通过生成一个临时的 `CMakeLists.txt` 文件，并使用 CMake 的 `find_package` 命令来查找指定的依赖项。它会尝试不同的 CMake 生成器 (`class_cmake_generators`)，并解析 CMake 的跟踪输出 (`CMakeTraceParser`) 来获取依赖项的信息。

5. **解析 CMake 输出:** `CMakeTraceParser` 类用于解析 CMake 的跟踪输出，提取关键信息，例如依赖项是否找到 (`PACKAGE_FOUND`)、版本号 (`PACKAGE_VERSION`)、包含目录 (`PACKAGE_INCLUDE_DIRS`)、预处理器定义 (`PACKAGE_DEFINITIONS`) 以及库文件 (`PACKAGE_LIBRARIES`)。

6. **处理 CMake 模块和组件:** 代码支持指定要查找的 CMake 模块 (`modules`) 和组件 (`components`)。 `_map_module_list` 和 `_map_component_list` 允许在查找过程中对模块和组件列表进行自定义映射。

7. **处理 CMake 目标 (Targets):**  代码能够识别和使用 CMake 的 "导入目标" (Imported Targets)。如果用户指定了模块，代码会尝试在 CMake 的跟踪输出中查找匹配的目标，并从中提取编译和链接所需的参数。

8. **提取编译和链接参数:**  根据 CMake 的输出来提取依赖项的包含目录 (`compile_args`) 和链接库 (`link_args`)。

9. **处理静态和动态链接:**  通过 `self.static` 属性来区分静态和动态链接。

10. **缓存 CMake 信息:**  `class_cmakeinfo` 使用 `PerMachine` 存储每个机器的 CMake 信息，避免在同一次 Meson 构建中多次搜索 CMake。

11. **处理用户提供的 CMake 参数:**  允许用户通过 `cmake_args` 关键字参数传递额外的 CMake 参数。

**与逆向方法的关联及举例:**

* **查找逆向工具依赖的库:** 许多逆向工程工具依赖于特定的库，例如 Capstone (反汇编引擎)、Keystone (汇编引擎) 或 Zydis (另一个反汇编引擎)。这个脚本可以用来查找这些库，并将它们的头文件和库文件包含到 Frida 的构建过程中。

   **举例:**  假设 Frida 需要依赖 Capstone。用户可能会在 `meson.build` 文件中声明依赖项：
   ```python
   capstone_dep = dependency('capstone', method='cmake')
   ```
   `cmake.py` 会尝试在系统中找到 Capstone 的 CMake 配置，并提取其头文件路径和库文件路径，以便 Frida 可以链接到 Capstone。

* **集成自定义的逆向分析库:**  如果开发者编写了自己的基于 CMake 构建的逆向分析库，他们可以使用这个脚本将其集成到 Frida 的插件或扩展中。

   **举例:**  一个开发者创建了一个名为 "MyReverseLib" 的 CMake 项目，提供了一些自定义的反汇编或代码分析功能。他们可以通过在 Frida 的构建脚本中声明依赖来使用 `cmake.py` 集成这个库。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **架构感知 (`self.cmakeinfo.archs`):**  CMake 可以处理多架构构建。该脚本会获取目标系统的架构信息，以便 CMake 能够找到对应架构的库文件。这对于在不同架构的 Android 设备上运行 Frida 非常重要。

   **举例:**  在为 ARM64 Android 设备构建 Frida 时，`cmake.py` 会获取 `arm64` 作为架构信息，CMake 会尝试找到为 ARM64 编译的依赖库。

* **库搜索路径 (`self.cmakeinfo.common_paths`, 系统环境变量 `PATH`):**  脚本会搜索常见的库安装路径 (如 `/lib`, `/usr/lib`) 和系统环境变量 `PATH` 中指定的路径，以找到依赖的库文件。这与操作系统的加载器如何查找动态链接库有关。

* **处理不同操作系统 (`is_windows()`):** 代码中存在对 Windows 平台的特殊处理，例如路径分隔符的处理。这表明了对不同操作系统构建环境的考虑。

* **查找 Framework (macOS):**  在 macOS 上，代码会尝试查找 `.framework` 和 `.app` 目录，这是 macOS 特有的库和应用程序打包方式。这体现了对 macOS 平台特性的了解。

**逻辑推理及假设输入与输出:**

* **假设输入:**  用户在 Frida 的 `meson.build` 文件中声明了一个依赖项 `dependency('mylib', method='cmake', modules: ['MyLibTarget'])`。
* **逻辑推理:**
    1. `cmake.py` 会被调用来处理这个依赖项。
    2. 它会查找 CMake 可执行文件。
    3. 它会生成一个临时的 `CMakeLists.txt` 文件，其中包含 `find_package(mylib REQUIRED)`。
    4. 它会运行 CMake，并解析其跟踪输出。
    5. 它会在跟踪输出中查找名为 `MyLibTarget` 的 CMake 目标。
    6. 如果找到 `MyLibTarget`，它会提取该目标的包含目录和链接库。
* **假设输出:**  如果 `MyLibTarget` 存在，`cmake.py` 会成功找到依赖项，并返回其包含目录和链接库，以便 Meson 可以将其添加到 Frida 的编译和链接命令中。如果找不到，则会抛出 `DependencyException`。

**用户或编程常见的使用错误及举例:**

* **错误的模块名称:** 用户可能在 `modules` 中指定了错误的 CMake 目标名称。

   **举例:**  如果实际的 CMake 目标名为 `MyLib::Target`，但用户指定了 `modules: ['MyLibTarget']`，则 `cmake.py` 将无法找到该目标，并会抛出错误，提示用户有效的目标名称。

* **依赖项未安装或不在搜索路径中:**  用户尝试依赖一个尚未安装或者安装路径不在 CMake 默认搜索路径或用户提供的 `cmake_module_path` 中的库。

   **举例:**  如果用户依赖 `libfoo`，但 `libfoo` 没有安装，或者它的 CMake 配置文件没有放在标准位置，CMake 的 `find_package` 将会失败，导致 `cmake.py` 找不到依赖项。

* **CMake 版本过低:**  如果用户的系统中安装的 CMake 版本低于 `class_cmake_version` 指定的最低版本，`CMakeExecutor` 会报错。

* **传递错误的 `cmake_args`:** 用户可能传递了不兼容或错误的 CMake 参数，导致 CMake 配置失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 的开发者或用户想要构建 Frida 或其一个组件 (例如 frida-qml)。**
2. **Frida 的构建系统 Meson 开始解析 `meson.build` 文件。**
3. **在 `meson.build` 文件中，可能声明了一个或多个使用 CMake 构建的外部依赖项，通过 `dependency(..., method='cmake', ...)` 的方式声明。**
4. **当 Meson 处理到这样的依赖项时，它会调用 `cmake.py` 中定义的 `CMakeDependency` 类或其工厂类 (`CMakeDependencyFactory`)。**
5. **`CMakeDependency.__init__` 方法会被调用，初始化依赖项对象，并开始查找 CMake 可执行文件。**
6. **`_detect_dep` 方法会被调用，开始执行 CMake 的依赖查找过程。**
7. **在这个过程中，会涉及到 `CMakeExecutor` 执行 CMake 命令，`CMakeTraceParser` 解析 CMake 的输出。**

**作为调试线索:**

* 如果构建过程中出现与 CMake 依赖相关的错误，可以检查 Meson 的构建日志，查看 `cmake.py` 产生的调试信息 (例如 "Determining dependency...", "Try CMake generator...", CMake 的输出)。
* 检查 `meson.build` 文件中关于该依赖项的声明是否正确，例如模块名称、组件名称、额外的 CMake 参数等。
* 检查系统中是否安装了所需的 CMake 版本。
* 尝试手动运行 CMake 的 `find_package` 命令，看看是否能够找到依赖项，以便隔离问题。
* 可以临时修改 `cmake.py` 文件，添加更多的调试输出，以便更详细地了解 CMake 的执行过程和输出结果。

总而言之，`cmake.py` 是 Frida 构建系统中一个至关重要的组件，它负责桥接 Meson 和 CMake，使得 Frida 能够轻松地集成基于 CMake 构建的外部库，这对于扩展 Frida 的功能和支持更广泛的逆向工程任务至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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