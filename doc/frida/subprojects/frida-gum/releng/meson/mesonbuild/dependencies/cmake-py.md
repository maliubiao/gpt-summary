Response:
Let's break down the thought process to analyze the Python code and answer the user's request.

**1. Understanding the Core Purpose:**

The first step is to recognize the file path: `frida/subprojects/frida-gum/releng/meson/mesonbuild/dependencies/cmake.py`. This immediately tells us:

* **Frida:**  This is part of the Frida dynamic instrumentation toolkit. This is a crucial context.
* **Subprojects/frida-gum:**  Suggests this is a sub-component dealing with Frida's "gum" library (likely the instrumentation engine).
* **Releng/meson:**  Indicates this is part of the release engineering process, using the Meson build system.
* **Mesonbuild/dependencies:**  This pinpoints the core functionality: handling external dependencies within the Meson build.
* **cmake.py:** This tells us the specific dependency being handled is CMake.

Therefore, the primary function of this code is to allow the Meson build system to find and integrate libraries or other components that are managed by CMake.

**2. Deconstructing the Code - High-Level Sections:**

Next, we scan the code for key structural elements:

* **Imports:**  `from ...`, `import ...`. This reveals the dependencies of this module. We see imports related to Meson's internal structures (`base.py`, `mesonlib.py`, `cmake.py`), standard Python libraries (`pathlib`, `functools`, `re`, `os`, `shutil`, `textwrap`, `typing`), and potentially Frida-specific resources (`importlib.resources`).
* **Class Definition: `CMakeDependency`:** This is the main class doing the work. We note its inheritance from `ExternalDependency`, confirming its role in handling external components.
* **Methods within `CMakeDependency`:**  We read the method names and docstrings (where present) to understand their purpose. Important methods include:
    * `__init__`:  Initialization, taking dependency name, environment, and keyword arguments.
    * `_gen_exception`: Creating dependency-related exceptions.
    * `_main_cmake_file`:  Specifying the CMakeLists.txt template.
    * `_extra_cmake_opts`:  Allowing customization of CMake arguments.
    * `_map_module_list`, `_map_component_list`, `_original_module_name`:  Methods for mapping and translating module names.
    * `_get_cmake_info`:  Crucial for extracting CMake system information.
    * `_preliminary_find_check`:  A quick check to see if the dependency might exist.
    * `_detect_dep`:  The core logic for finding and extracting dependency information using CMake.
    * `_get_build_dir`, `_setup_cmake_dir`, `_call_cmake`:  Managing the temporary CMake build environment.
    * `log_tried`, `log_details`:  Logging information about the dependency search.
    * `get_variable`:  Retrieving CMake variables.
* **Class Definition: `CMakeDependencyFactory`:** A factory class to simplify the creation of `CMakeDependency` instances.

**3. Connecting to User's Questions (Iterative Process):**

Now, we systematically address each of the user's questions, drawing upon our understanding of the code:

* **Functionality:** We summarize the core purpose – finding and integrating CMake-based dependencies within a Meson build. We then list the key steps involved in this process, drawing directly from the methods within `CMakeDependency`.

* **Relationship to Reverse Engineering:**  This is where the Frida context becomes crucial. Since Frida is a dynamic instrumentation tool used *for* reverse engineering, the ability to integrate external CMake-based components expands Frida's capabilities. We need concrete examples. Imagine a Frida module that relies on a library built with CMake for advanced analysis or hooking. This module would be a *dependency* of Frida.

* **Binary/Low-Level, Linux/Android Kernel/Framework:**  We look for clues in the code that touch upon these areas:
    * **CMake:** CMake itself is often used to build low-level libraries and tools.
    * **Platform-Specific Logic:**  The code checks for Windows (`is_windows()`) and Darwin (`machine.is_darwin()`), indicating awareness of platform differences.
    * **Architecture:** The `cmakeinfo.archs` variable suggests handling of different architectures, relevant to binary compatibility.
    * **Search Paths:** The code manipulates library search paths, essential for finding shared libraries at runtime.
    * **Environment Variables:** The code interacts with environment variables like `PATH` and `*_DIR`, which are fundamental in operating systems.

* **Logical Reasoning (Assumptions and Outputs):**  Here, we focus on the `_detect_dep` method. We need to think about the inputs (dependency name, version, modules, components, CMake arguments) and how CMake's output (trace log) is parsed to extract the desired information (include directories, link libraries, etc.). We construct a plausible scenario and trace the expected flow.

* **Common Usage Errors:** We consider how users might misuse the dependency declaration in their Meson build files:
    * Incorrect dependency name.
    * Incorrect module names.
    * Missing CMake requirement (`>=3.4`).
    * Incorrect paths.

* **User Operation to Reach the Code:**  We reconstruct the steps a developer would take when building a Frida component that depends on a CMake project. This involves editing Meson build files and running the Meson command.

**4. Refinement and Structuring:**

Finally, we organize the answers logically, use clear and concise language, and provide code snippets where relevant. We ensure that the explanation flows well and is easy for someone familiar with build systems and reverse engineering concepts to understand. We also need to make sure the explanation is detailed enough to be useful but not overly technical or dense. The goal is to bridge the gap between the raw code and its practical application in the Frida ecosystem.

**(Self-Correction Example during the process):**  Initially, I might have focused too much on the low-level details of CMake itself. However, the request emphasizes the *context* of Frida. So, I would then re-emphasize how this code enables Frida to incorporate external components, making it more powerful for reverse engineering tasks. Similarly, if I initially missed the platform-specific checks, I would go back and add those details as they are relevant to binary compatibility and system-level interactions.
这个Python源代码文件 `cmake.py` 是 Frida 动态 instrumentation 工具中用于处理 **CMake 构建的外部依赖** 的一个模块。它的主要功能是允许 Meson 构建系统（Frida 使用 Meson）找到并集成那些使用 CMake 进行构建的第三方库或组件。

以下是该文件的功能列表及其与逆向、底层、内核/框架知识、逻辑推理和常见错误的关联：

**主要功能：**

1. **查找 CMake 可执行文件:**  `CMakeExecutor` 类用于定位系统中的 CMake 可执行文件，并检查其版本是否满足最低要求 (>=3.4)。
2. **提取 CMake 系统信息:** `_get_cmake_info` 方法尝试运行 CMake 来获取目标系统的基本信息，例如模块搜索路径、CMake 根目录和支持的架构。这通过尝试不同的 CMake 生成器来实现。
3. **预先检查依赖是否存在:** `_preliminary_find_check` 方法在执行完整的 CMake 查找之前，通过搜索常见的模块和配置文件位置，快速检查依赖项是否可能存在。
4. **使用 CMake 查找依赖:** `_detect_dep` 方法是核心功能，它使用 CMake 的 `--find-package` 模式，并通过解析 CMake 的 trace 输出（stderr）来获取依赖项的信息，例如包含目录、库文件和编译选项。
5. **处理模块和组件:**  允许指定要查找的 CMake 模块和组件，并提供映射函数 (`_map_module_list`, `_map_component_list`) 以根据 CMakeLists.txt 中的定义进行转换。
6. **处理不同的 CMake 生成器:**  尝试不同的 CMake 生成器（例如 Ninja, Unix Makefiles, Visual Studio），以提高在不同环境下的兼容性。
7. **处理静态/动态链接:**  根据 `static` 参数设置 CMake 查找静态或动态库。
8. **获取 CMake 变量:** `get_variable` 方法允许从 CMake 的 trace 输出中检索特定的 CMake 变量。
9. **管理 CMake 构建目录:**  创建和管理用于执行 CMake 命令的临时构建目录。
10. **提供日志信息:**  提供 `log_tried` 和 `log_details` 方法，用于记录依赖查找过程中的信息。

**与逆向的方法的关系及举例说明：**

* **集成逆向工具依赖的库:** Frida 作为一个逆向工具，可能依赖于其他使用 CMake 构建的库来实现特定的功能，例如反汇编引擎、符号解析库或者协议解析库。
    * **举例:** 假设 Frida 需要集成一个名为 "Capstone" 的反汇编库，Capstone 使用 CMake 构建。`cmake.py` 的功能就是帮助 Frida 的构建系统找到 Capstone，并获取其头文件路径和库文件路径，以便 Frida 可以链接和使用 Capstone 提供的反汇编功能。在 Frida 的 `meson.build` 文件中，可能会有类似 `dependency('capstone', method: 'cmake')` 的声明，Meson 会调用 `cmake.py` 来处理这个依赖。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **架构感知:**  代码中涉及到架构列表 (`self.cmakeinfo.archs`)，说明它需要处理不同架构下的依赖关系，这对于 Frida 这样的跨平台工具来说非常重要，尤其是在处理 Android 这种多架构平台时。
    * **举例:**  在 Android 上，Frida 可能需要为 ARM、ARM64、x86 等不同架构编译不同的组件。`cmake.py` 可以根据目标架构的不同，指导 CMake 查找对应架构的依赖库。
* **库文件路径:** 代码中处理了各种常见的库文件路径（例如 `lib`, `lib64`, `share`），这与 Linux 和 Android 系统中库文件的组织方式有关。
* **环境变量:** 代码中使用了环境变量 `PATH` 和 `*_DIR` 来查找依赖项，这反映了操作系统中查找可执行文件和库的常见方式。
* **CMake 模块路径:**  代码中使用了 `CMAKE_MODULE_PATH` 变量，允许用户指定额外的 CMake 模块搜索路径，这在处理一些非标准安装的库时非常有用。
* **系统根路径:** 代码中考虑了系统根路径 (`MESON_FIND_ROOT_PATH`, `MESON_CMAKE_SYSROOT`)，这在交叉编译或者处理 SDK 时非常重要，例如在为 Android 平台编译 Frida 组件时。

**逻辑推理及假设输入与输出：**

* **假设输入:**
    * 依赖项名称: "libuv"
    * 目标平台: Linux x86_64
    * libuv 已安装在 `/usr/local` 目录下，CMake 配置文件位于 `/usr/local/lib/cmake/libuv`。
* **逻辑推理过程:**
    1. `_preliminary_find_check` 方法会搜索常见的路径，包括 `/usr/local/lib/cmake/libuv`，如果找到 `libuvConfig.cmake` 或 `Findlibuv.cmake`，则认为依赖可能存在。
    2. `_detect_dep` 方法会调用 CMake 的 `find_package(libuv)` 命令。
    3. CMake 会根据 `CMAKE_MODULE_PATH` 和默认的搜索路径查找 `Findlibuv.cmake` 或 `libuvConfig.cmake`。
    4. 假设找到了 `libuvConfig.cmake`，CMake 会执行该文件，设置相关的变量，例如 `libuv_INCLUDE_DIRS` 和 `libuv_LIBRARIES`。
    5. `cmake.py` 通过解析 CMake 的 trace 输出，提取这些变量的值。
* **预期输出:**
    * `self.is_found` 为 `True`。
    * `self.compile_args` 包含 `-I/usr/local/include` (假设 libuv 的头文件在 `/usr/local/include`)。
    * `self.link_args` 包含 `-luv` 或 `/usr/local/lib/libuv.so` (取决于 libuv 的配置)。

**涉及用户或编程常见的使用错误及举例说明：**

* **依赖名称拼写错误:** 用户在 `meson.build` 文件中声明依赖时，可能会拼错依赖项的名称。
    * **举例:** `dependency('libuvv', method: 'cmake')`，正确的名称是 "libuv"。这会导致 `cmake.py` 无法找到对应的 CMake 模块或配置文件。
* **缺少 CMake 环境:**  如果目标系统没有安装 CMake，或者 CMake 不在 PATH 环境变量中，`CMakeExecutor` 将无法找到 CMake 可执行文件，导致构建失败。
* **CMake 版本过低:**  代码要求 CMake 版本至少为 3.4。如果用户系统中的 CMake 版本低于此要求，将会报错。
* **CMake 配置文件缺失或不正确:** 如果依赖项的 CMake 配置文件（例如 `XXXConfig.cmake`）缺失或配置不正确，CMake 的 `find_package` 命令可能会失败，导致 `cmake.py` 无法找到依赖。
* **未提供必要的 CMake 参数:** 有些依赖项可能需要特定的 CMake 参数才能正确找到。用户需要在 `meson.build` 文件中通过 `cmake_args` 参数提供这些参数。
    * **举例:** 某个库可能需要指定 `BUILD_SHARED_LIBS=OFF` 才能找到静态库版本。用户需要在 `meson.build` 中添加 `cmake_args: ['-DBUILD_SHARED_LIBS=OFF']`。
* **模块名称错误:**  如果用户通过 `modules` 参数指定了错误的 CMake target 名称，`cmake.py` 将无法找到对应的 target。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida 或其某个组件:** 用户在 Frida 的源代码目录下执行 `meson setup build` 或 `ninja -C build` 命令来构建 Frida。
2. **Meson 解析构建文件:** Meson 会读取 `meson.build` 文件，其中包括对外部依赖项的声明，例如 `dependency('some_cmake_lib', method: 'cmake')`。
3. **Meson 调用相应的依赖处理模块:** 当 Meson 遇到 `method: 'cmake'` 时，它会加载并调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/dependencies/cmake.py` 模块来处理该依赖。
4. **`CMakeDependency` 类被实例化:**  `dependency()` 函数会创建一个 `CMakeDependency` 类的实例，传入依赖项的名称、环境信息和相关的关键字参数。
5. **`__init__` 方法执行:**  `CMakeDependency` 的 `__init__` 方法会被调用，它会执行以下操作：
    * 初始化各种属性。
    * 使用 `CMakeExecutor` 查找 CMake 可执行文件。
    * 如果需要，调用 `_get_cmake_info` 获取 CMake 系统信息。
    * 调用 `_preliminary_find_check` 进行初步检查。
    * 调用核心方法 `_detect_dep` 来查找依赖项。
6. **`_detect_dep` 方法执行 CMake 命令并解析输出:**  `_detect_dep` 方法会创建一个临时的 CMake 构建目录，生成一个临时的 `CMakeLists.txt` 文件，并使用 `self.cmakebin.call()` 执行 CMake 命令，其中包含 `--find-package` 和 trace 参数。
7. **`CMakeTraceParser` 解析 CMake 输出:**  CMake 的 stderr 输出会被 `CMakeTraceParser` 解析，从中提取依赖项的信息，例如包含目录、库文件和定义的宏。
8. **依赖信息被存储在 `CMakeDependency` 对象中:** 解析出的信息会被存储在 `CMakeDependency` 对象的属性中，例如 `self.compile_args` 和 `self.link_args`。
9. **Meson 将依赖信息传递给编译器和链接器:**  Meson 会将 `CMakeDependency` 对象中获取的编译和链接参数传递给底层的编译器和链接器，以完成 Frida 的构建。

如果在构建过程中出现与 CMake 依赖相关的问题，例如找不到依赖项或链接错误，开发者可以：

* **检查 `meson-log.txt`:** Meson 的日志文件会记录依赖查找的详细过程，包括 `cmake.py` 执行的 CMake 命令及其输出，这可以作为调试的线索。
* **设置 `MESON_DEBUG` 环境变量:**  设置 `MESON_DEBUG=1` 可以获取更详细的 Meson 调试信息。
* **手动执行 CMake 命令:**  可以尝试手动执行 `cmake.py` 中生成的 CMake 命令，以便更直接地观察 CMake 的行为和输出。
* **检查 CMake 配置文件:**  确认依赖项的 CMake 配置文件是否正确安装和配置。
* **检查环境变量:** 确认相关的环境变量（例如 `PATH`, `CMAKE_PREFIX_PATH`）是否设置正确。

总而言之，`cmake.py` 是 Frida 构建系统中一个关键的组成部分，它桥接了 Meson 和 CMake，使得 Frida 能够方便地利用使用 CMake 构建的第三方库，从而扩展其功能并支持更广泛的逆向场景。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/dependencies/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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