Response:
Let's break down the request and the provided Python code. The goal is to understand the functionality of `dev.py` within the context of Frida, specifically how it relates to reverse engineering, binary analysis, and system-level interactions.

**Mental Sandbox Simulation:**

1. **Understanding the Core Purpose:** The file lives under `frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/`. The name "dependencies" strongly suggests it's involved in finding and managing external libraries required to build Frida. The `dev.py` name might indicate dependencies used during development or less common ones.

2. **Scanning for Key Functionality:** I'll look for keywords and patterns:
    * **Dependency Detection:**  Functions or classes that search for libraries (`find_library`, `detect`, `PkgConfigDependency`, `CMakeDependency`, `SystemDependency`).
    * **Compiler Interaction:** Mentions of compilers (`clib_compiler`, `get_llvm_tool_names`).
    * **System Specifics:** References to operating systems (`is_windows`, `is_darwin`, `is_linux`, `is_freebsd`, `is_android`), paths (`/usr/src/gtest`), and kernel/framework concepts (JNI).
    * **Version Handling:**  Functions like `version_compare`, `search_version`.
    * **Configuration Tools:**  References to `llvm-config`.
    * **Packaging Systems:** `PkgConfigDependency`.

3. **Mapping to Reverse Engineering Concepts:** How do these functionalities connect to reverse engineering?
    * **External Libraries:** Frida likely relies on libraries for low-level operations (like interacting with the operating system or debugging APIs). These dependencies need to be found and linked.
    * **Binary Manipulation:** While this specific file doesn't directly manipulate binaries, it sets up the build environment where that manipulation will happen. Dependencies like LLVM (with its compiler infrastructure) are crucial for binary analysis and instrumentation.
    * **System Interaction:**  Frida's core purpose is to interact with running processes. Dependencies related to specific OS functionalities (like JNI for Java processes on Android) are essential.

4. **Considering Specific Examples (Instruction #2 & #3):**
    * **Reverse Engineering:**  GTest and GMock are for testing. While not direct reverse engineering tools, they ensure the *correctness* of Frida's reverse engineering capabilities. LLVM is a powerful toolchain often used in reverse engineering for disassembly, decompilation, and instrumentation.
    * **Binary/Kernel/Framework:** JNI directly relates to the Android framework and allows interaction with Java code at a lower level. The code handling shared library suffixes (`.so`, `.dylib`, `.dll`) is fundamental to how binaries are loaded and linked in different operating systems.

5. **Logical Reasoning (Instruction #4):** I'll focus on classes that perform actions based on input. The `LLVMDependencyConfigTool` and `LLVMDependencyCMake` classes seem to take a list of modules as input and determine the necessary compile and link arguments. I can try to construct a simple scenario.

6. **User Errors (Instruction #5):**  Dependency management is a common source of build problems. Incorrectly installed dependencies, missing dependencies, or wrong versions are likely issues.

7. **Debugging Steps (Instruction #6):**  How does a user end up in this code? It's part of the build process. A user would be running a command (like `meson build`) that triggers Meson to configure the build. If a dependency is not found or configured correctly, the Meson build system would interact with these dependency detection scripts.

**Pre-computation/Pre-analysis (Mental Notes):**

* **Meson's Role:** Remember that this code is within the Meson build system. Meson automates the process of finding libraries and setting up the compilation environment.
* **Dependency Types:**  Distinguish between system dependencies (found on the system), CMake dependencies (found using CMake's infrastructure), and PkgConfig dependencies (found using `.pc` files).
* **Frida's Architecture:** Keep in mind that Frida is a dynamic instrumentation toolkit. Its dependencies will likely include libraries that allow it to inject code and intercept function calls in running processes.

**Confidence Check:**

* Does the code handle dependency detection? Yes.
* Are there connections to reverse engineering? Yes (indirectly through testing and LLVM).
* Are there connections to binary/kernel/framework? Yes (JNI, shared library handling).
* Can I create logical reasoning examples? Yes (with LLVM module selection).
* Can I identify potential user errors? Yes (dependency issues).
* Can I trace the user's path to this code? Yes (through the build process).

Strategizing complete. I will now generate the response based on these insights.
这个 `dev.py` 文件是 Frida 动态 instrumentation 工具构建系统中，使用 Meson 构建系统时，用于处理**开发依赖**的一个模块。它定义了一些用于查找和配置特定开发库的类和方法。

以下是它的功能列表，并结合逆向、二进制底层、Linux/Android 内核及框架知识进行举例说明：

**1. 定义了多种依赖查找和配置的类:**

* **`SystemDependency` 的子类 (例如 `GTestDependencySystem`, `GMockDependencySystem`, `ZlibSystemDependency`, `JNISystemDependency`):**  用于在系统中查找预装的库。
    * **逆向相关举例:**  `GTestDependencySystem` 和 `GMockDependencySystem` 用于查找 Google Test 和 Google Mock 库，这两个库常用于编写单元测试，确保 Frida 内部组件的正确性，间接支持 Frida 的逆向功能。逆向工程师可能会使用 Frida 自身的测试套件来验证 Frida 功能。
    * **二进制底层/Linux/Android 内核及框架知识举例:** `ZlibSystemDependency` 用于查找 `zlib` 库，该库用于数据压缩。在逆向分析过程中，可能会遇到压缩过的数据，Frida 需要 `zlib` 来解压这些数据进行检查。这涉及到操作系统提供的压缩库。
    * **JNISystemDependency** 用于查找 Java Native Interface (JNI) 相关的库。在逆向 Android 应用时，经常需要与 Java 层进行交互，JNI 是桥梁。这个类会查找 JDK 中的 `jvm` 和 `jawt` 库，它们是 JNI 的核心组件。这直接关系到 Android 框架 (基于 Java) 和底层的 JVM 运行时环境。

* **`PkgConfigDependency` 的子类 (例如 `GTestDependencyPC`, `GMockDependencyPC`, `ValgrindDependency`):** 用于通过 `pkg-config` 工具查找库。
    * **逆向相关举例:**  `ValgrindDependency` 用于查找 Valgrind 工具。Valgrind 是一套用于内存调试、内存泄漏检测以及性能分析的工具集，在 Frida 开发中用于检测潜在的内存问题，保证 Frida 的稳定性和安全性，这对最终的逆向分析工作至关重要。

* **`CMakeDependency` 的子类 (`LLVMDependencyCMake`):** 用于通过 CMake 的 `find_package` 机制查找库。
    * **逆向相关举例:**  `LLVMDependencyCMake` 用于查找 LLVM 库。LLVM 是一个编译器基础设施项目，包含 Clang 编译器等。在 Frida 的开发中，LLVM 被用于编译和处理底层代码，例如生成中间表示 (IR) 或进行代码优化。逆向工程师可能利用 Frida 与目标进程的 LLVM 基础设施进行交互。
    * **二进制底层知识举例:** LLVM 能够理解和操作二进制代码的底层结构，例如指令集。Frida 使用 LLVM 可以在运行时生成和修改目标进程的代码。

* **`ConfigToolDependency` 的子类 (`LLVMDependencyConfigTool`):**  用于通过特定的配置工具 (例如 `llvm-config`) 查找和获取库的编译和链接信息。
    * **逆向相关举例:**  `LLVMDependencyConfigTool` 同样用于查找 LLVM，但它使用 `llvm-config` 工具。`llvm-config` 可以提供 LLVM 库的头文件路径、链接库路径等信息，这对于编译依赖 LLVM 的代码至关重要。

* **`DependencyFactory`:** 用于注册和管理不同类型的依赖。

**2. 辅助函数:**

* **`get_shared_library_suffix`:**  根据目标操作系统确定共享库的后缀名 (`.so`, `.dylib`, `.dll`)。
    * **二进制底层/Linux/Android 内核及框架知识举例:** 不同的操作系统使用不同的共享库格式。这个函数体现了对操作系统底层加载和链接机制的理解。在逆向过程中，理解这些后缀名对于查找和加载目标进程的库文件至关重要。

**3. 逻辑推理举例:**

* **`LLVMDependencyConfigTool` 的 `check_components` 方法:**
    * **假设输入:** `modules = ["Core", "ExecutionEngine"]`, `provided_modules = ["Core", "ExecutionEngine", "MC"]`
    * **输出:** `self.required_modules` 将包含 `"Core"` 和 `"ExecutionEngine"`。`self.module_details` 将包含 `"Core"`, `"ExecutionEngine"`, `"MC(missing but optional)"` (如果 "MC" 是可选的).
    * **解释:** 此方法检查所需的 LLVM 模块是否已安装。如果所需的模块不存在，则会设置 `self.is_found` 为 `False`，并且如果 `self.required` 为 `True`，则会抛出异常。

* **`LLVMDependencyCMake` 的 `_extra_cmake_opts` 方法:**
    * **假设输入:** `self.llvm_modules = ["Core"]`, `self.llvm_opt_modules = ["Support"]`, `self.name = "llvm"`, `self.static = False`
    * **输出:** `['-DLLVM_MESON_REQUIRED_MODULES=Core', '-DLLVM_MESON_OPTIONAL_MODULES=Support', '-DLLVM_MESON_PACKAGE_NAMES=llvm', '-DLLVM_MESON_VERSIONS=', '-DLLVM_MESON_DYLIB=ON']`
    * **解释:** 此方法生成传递给 CMake 的额外选项，指定所需的和可选的 LLVM 模块，以及是否进行动态链接。

**4. 用户或编程常见的使用错误举例:**

* **缺少依赖:** 用户在构建 Frida 时，如果系统中没有安装必要的开发库 (例如，没有安装 gtest 的开发包)，Meson 会尝试查找这些依赖，但最终会失败，导致构建错误。
    * **错误信息示例:**  类似于 "Could not find dependency gtest" 或 "Program 'llvm-config' not found"。
* **错误的依赖版本:**  Frida 可能依赖特定版本的库。如果用户安装的版本不兼容，可能会导致编译错误或运行时错误。
    * **错误信息示例:**  `JNISystemDependency` 中，如果检测到的 JDK 版本与要求的版本不符，会输出错误信息。
* **配置问题:**  对于使用 `pkg-config` 的依赖，如果 `.pc` 文件配置不正确，或者 `PKG_CONFIG_PATH` 环境变量没有设置正确，Meson 可能无法找到库。
* **没有设置 JAVA_HOME 环境变量 (针对 JNI 依赖):** `JNISystemDependency` 中提到，如果无法自动发现 `JAVA_HOME`，可能会导致构建失败。

**5. 用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:**  用户通常会执行类似 `meson setup build` 或 `ninja -C build` 的命令来构建 Frida。
2. **Meson 配置阶段:**  Meson 首先会读取 `meson.build` 文件，该文件描述了项目的构建过程和依赖关系。
3. **查找依赖:**  当 Meson 遇到需要外部库的组件时 (例如，Frida Core)，它会根据 `meson.build` 中声明的依赖项，调用相应的依赖查找机制。
4. **进入 `dev.py`:**  对于声明为 "development" 依赖的库，Meson 可能会调用 `frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/dev.py` 中定义的类和方法来查找这些库。
5. **依赖查找过程:**  例如，如果需要查找 gtest，Meson 会尝试使用 `pkg-config` (如果配置了) 或者通过 `GTestDependencySystem` 来在系统中搜索。`dev.py` 中的代码会检查预定义的路径、调用编译器命令来查找库文件和头文件。
6. **配置结果:**  如果依赖找到，`dev.py` 中的代码会提取库的编译参数 (头文件路径、宏定义) 和链接参数 (库文件路径)。这些信息会被 Meson 用于生成编译命令。
7. **失败情况:** 如果依赖查找失败，`dev.py` 中的代码会将 `is_found` 标记为 `False`，并且 Meson 会报告错误，提示用户缺少依赖。

**作为调试线索，理解 `dev.py` 的功能可以帮助我们：**

* **定位构建失败原因:**  如果构建失败并提示缺少依赖，我们可以查看 `dev.py` 中对应依赖的查找逻辑，了解 Meson 是如何尝试找到该库的，从而判断是库未安装、版本不正确还是配置问题。
* **排查依赖查找错误:**  如果怀疑 Meson 没有正确找到某个库，可以检查 `dev.py` 中该库的查找路径和方法是否正确。
* **理解 Frida 的依赖关系:**  通过查看 `dev.py`，可以了解 Frida 的构建依赖了哪些开发库，以及这些库在 Frida 中的作用。

总而言之，`dev.py` 是 Frida 构建系统中负责管理开发依赖的关键模块，它封装了多种查找和配置依赖库的策略，并与逆向分析、二进制底层、操作系统特性等多个方面都有着密切的联系。理解它的功能有助于我们更好地构建、调试和理解 Frida。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2019 The Meson development team

from __future__ import annotations

import glob
import os
import re
import pathlib
import shutil
import subprocess
import typing as T
import functools

from mesonbuild.interpreterbase.decorators import FeatureDeprecated

from .. import mesonlib, mlog
from ..environment import get_llvm_tool_names
from ..mesonlib import version_compare, version_compare_many, search_version, stringlistify, extract_as_list
from .base import DependencyException, DependencyMethods, detect_compiler, strip_system_includedirs, strip_system_libdirs, SystemDependency, ExternalDependency, DependencyTypeName
from .cmake import CMakeDependency
from .configtool import ConfigToolDependency
from .detect import packages
from .factory import DependencyFactory
from .misc import threads_factory
from .pkgconfig import PkgConfigDependency

if T.TYPE_CHECKING:
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..mesonlib import MachineChoice
    from typing_extensions import TypedDict

    class JNISystemDependencyKW(TypedDict):
        modules: T.List[str]
        # FIXME: When dependency() moves to typed Kwargs, this should inherit
        # from its TypedDict type.
        version: T.Optional[str]


def get_shared_library_suffix(environment: 'Environment', for_machine: MachineChoice) -> str:
    """This is only guaranteed to work for languages that compile to machine
    code, not for languages like C# that use a bytecode and always end in .dll
    """
    m = environment.machines[for_machine]
    if m.is_windows():
        return '.dll'
    elif m.is_darwin():
        return '.dylib'
    return '.so'


class GTestDependencySystem(SystemDependency):
    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__(name, environment, kwargs, language='cpp')
        self.main = kwargs.get('main', False)
        self.src_dirs = ['/usr/src/gtest/src', '/usr/src/googletest/googletest/src']
        if not self._add_sub_dependency(threads_factory(environment, self.for_machine, {})):
            self.is_found = False
            return
        self.detect()

    def detect(self) -> None:
        gtest_detect = self.clib_compiler.find_library("gtest", self.env, [])
        gtest_main_detect = self.clib_compiler.find_library("gtest_main", self.env, [])
        if gtest_detect and (not self.main or gtest_main_detect):
            self.is_found = True
            self.compile_args = []
            self.link_args = gtest_detect
            if self.main:
                self.link_args += gtest_main_detect
            self.sources = []
            self.prebuilt = True
        elif self.detect_srcdir():
            self.is_found = True
            self.compile_args = ['-I' + d for d in self.src_include_dirs]
            self.link_args = []
            if self.main:
                self.sources = [self.all_src, self.main_src]
            else:
                self.sources = [self.all_src]
            self.prebuilt = False
        else:
            self.is_found = False

    def detect_srcdir(self) -> bool:
        for s in self.src_dirs:
            if os.path.exists(s):
                self.src_dir = s
                self.all_src = mesonlib.File.from_absolute_file(
                    os.path.join(self.src_dir, 'gtest-all.cc'))
                self.main_src = mesonlib.File.from_absolute_file(
                    os.path.join(self.src_dir, 'gtest_main.cc'))
                self.src_include_dirs = [os.path.normpath(os.path.join(self.src_dir, '..')),
                                         os.path.normpath(os.path.join(self.src_dir, '../include')),
                                         ]
                return True
        return False

    def log_info(self) -> str:
        if self.prebuilt:
            return 'prebuilt'
        else:
            return 'building self'


class GTestDependencyPC(PkgConfigDependency):

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        assert name == 'gtest'
        if kwargs.get('main'):
            name = 'gtest_main'
        super().__init__(name, environment, kwargs)


class GMockDependencySystem(SystemDependency):
    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__(name, environment, kwargs, language='cpp')
        self.main = kwargs.get('main', False)
        if not self._add_sub_dependency(threads_factory(environment, self.for_machine, {})):
            self.is_found = False
            return

        # If we are getting main() from GMock, we definitely
        # want to avoid linking in main() from GTest
        gtest_kwargs = kwargs.copy()
        if self.main:
            gtest_kwargs['main'] = False

        # GMock without GTest is pretty much useless
        # this also mimics the structure given in WrapDB,
        # where GMock always pulls in GTest
        found = self._add_sub_dependency(gtest_factory(environment, self.for_machine, gtest_kwargs))
        if not found:
            self.is_found = False
            return

        # GMock may be a library or just source.
        # Work with both.
        gmock_detect = self.clib_compiler.find_library("gmock", self.env, [])
        gmock_main_detect = self.clib_compiler.find_library("gmock_main", self.env, [])
        if gmock_detect and (not self.main or gmock_main_detect):
            self.is_found = True
            self.link_args += gmock_detect
            if self.main:
                self.link_args += gmock_main_detect
            self.prebuilt = True
            return

        for d in ['/usr/src/googletest/googlemock/src', '/usr/src/gmock/src', '/usr/src/gmock']:
            if os.path.exists(d):
                self.is_found = True
                # Yes, we need both because there are multiple
                # versions of gmock that do different things.
                d2 = os.path.normpath(os.path.join(d, '..'))
                self.compile_args += ['-I' + d, '-I' + d2, '-I' + os.path.join(d2, 'include')]
                all_src = mesonlib.File.from_absolute_file(os.path.join(d, 'gmock-all.cc'))
                main_src = mesonlib.File.from_absolute_file(os.path.join(d, 'gmock_main.cc'))
                if self.main:
                    self.sources += [all_src, main_src]
                else:
                    self.sources += [all_src]
                self.prebuilt = False
                return

        self.is_found = False

    def log_info(self) -> str:
        if self.prebuilt:
            return 'prebuilt'
        else:
            return 'building self'


class GMockDependencyPC(PkgConfigDependency):

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        assert name == 'gmock'
        if kwargs.get('main'):
            name = 'gmock_main'
        super().__init__(name, environment, kwargs)


class LLVMDependencyConfigTool(ConfigToolDependency):
    """
    LLVM uses a special tool, llvm-config, which has arguments for getting
    c args, cxx args, and ldargs as well as version.
    """
    tool_name = 'llvm-config'
    __cpp_blacklist = {'-DNDEBUG'}

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        self.tools = get_llvm_tool_names('llvm-config')

        # Fedora starting with Fedora 30 adds a suffix of the number
        # of bits in the isa that llvm targets, for example, on x86_64
        # and aarch64 the name will be llvm-config-64, on x86 and arm
        # it will be llvm-config-32.
        if environment.machines[self.get_for_machine_from_kwargs(kwargs)].is_64_bit:
            self.tools.append('llvm-config-64')
        else:
            self.tools.append('llvm-config-32')

        # It's necessary for LLVM <= 3.8 to use the C++ linker. For 3.9 and 4.0
        # the C linker works fine if only using the C API.
        super().__init__(name, environment, kwargs, language='cpp')
        self.provided_modules: T.List[str] = []
        self.required_modules: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()
        self.module_details:   T.List[str] = []
        if not self.is_found:
            return

        self.provided_modules = self.get_config_value(['--components'], 'modules')
        modules = stringlistify(extract_as_list(kwargs, 'modules'))
        self.check_components(modules)
        opt_modules = stringlistify(extract_as_list(kwargs, 'optional_modules'))
        self.check_components(opt_modules, required=False)

        cargs = mesonlib.OrderedSet(self.get_config_value(['--cppflags'], 'compile_args'))
        self.compile_args = list(cargs.difference(self.__cpp_blacklist))
        self.compile_args = strip_system_includedirs(environment, self.for_machine, self.compile_args)

        if version_compare(self.version, '>= 3.9'):
            self._set_new_link_args(environment)
        else:
            self._set_old_link_args()
        self.link_args = strip_system_libdirs(environment, self.for_machine, self.link_args)
        self.link_args = self.__fix_bogus_link_args(self.link_args)
        if not self._add_sub_dependency(threads_factory(environment, self.for_machine, {})):
            self.is_found = False
            return

    def __fix_bogus_link_args(self, args: T.List[str]) -> T.List[str]:
        """This function attempts to fix bogus link arguments that llvm-config
        generates.

        Currently it works around the following:
            - FreeBSD: when statically linking -l/usr/lib/libexecinfo.so will
              be generated, strip the -l in cases like this.
            - Windows: We may get -LIBPATH:... which is later interpreted as
              "-L IBPATH:...", if we're using an msvc like compilers convert
              that to "/LIBPATH", otherwise to "-L ..."
        """

        new_args = []
        for arg in args:
            if arg.startswith('-l') and arg.endswith('.so'):
                new_args.append(arg.lstrip('-l'))
            elif arg.startswith('-LIBPATH:'):
                cpp = self.env.coredata.compilers[self.for_machine]['cpp']
                new_args.extend(cpp.get_linker_search_args(arg.lstrip('-LIBPATH:')))
            else:
                new_args.append(arg)
        return new_args

    def __check_libfiles(self, shared: bool) -> None:
        """Use llvm-config's --libfiles to check if libraries exist."""
        mode = '--link-shared' if shared else '--link-static'

        # Set self.required to true to force an exception in get_config_value
        # if the returncode != 0
        restore = self.required
        self.required = True

        try:
            # It doesn't matter what the stage is, the caller needs to catch
            # the exception anyway.
            self.link_args = self.get_config_value(['--libfiles', mode], '')
        finally:
            self.required = restore

    def _set_new_link_args(self, environment: 'Environment') -> None:
        """How to set linker args for LLVM versions >= 3.9"""
        try:
            mode = self.get_config_value(['--shared-mode'], 'link_args')[0]
        except IndexError:
            mlog.debug('llvm-config --shared-mode returned an error')
            self.is_found = False
            return

        if not self.static and mode == 'static':
            # If llvm is configured with LLVM_BUILD_LLVM_DYLIB but not with
            # LLVM_LINK_LLVM_DYLIB and not LLVM_BUILD_SHARED_LIBS (which
            # upstream doesn't recommend using), then llvm-config will lie to
            # you about how to do shared-linking. It wants to link to a a bunch
            # of individual shared libs (which don't exist because llvm wasn't
            # built with LLVM_BUILD_SHARED_LIBS.
            #
            # Therefore, we'll try to get the libfiles, if the return code is 0
            # or we get an empty list, then we'll try to build a working
            # configuration by hand.
            try:
                self.__check_libfiles(True)
            except DependencyException:
                lib_ext = get_shared_library_suffix(environment, self.for_machine)
                libdir = self.get_config_value(['--libdir'], 'link_args')[0]
                # Sort for reproducibility
                matches = sorted(glob.iglob(os.path.join(libdir, f'libLLVM*{lib_ext}')))
                if not matches:
                    if self.required:
                        raise
                    self.is_found = False
                    return

                self.link_args = self.get_config_value(['--ldflags'], 'link_args')
                libname = os.path.basename(matches[0]).rstrip(lib_ext).lstrip('lib')
                self.link_args.append(f'-l{libname}')
                return
        elif self.static and mode == 'shared':
            # If, however LLVM_BUILD_SHARED_LIBS is true # (*cough* gentoo *cough*)
            # then this is correct. Building with LLVM_BUILD_SHARED_LIBS has a side
            # effect, it stops the generation of static archives. Therefore we need
            # to check for that and error out on static if this is the case
            try:
                self.__check_libfiles(False)
            except DependencyException:
                if self.required:
                    raise
                self.is_found = False
                return

        link_args = ['--link-static', '--system-libs'] if self.static else ['--link-shared']
        self.link_args = self.get_config_value(
            ['--libs', '--ldflags'] + link_args + list(self.required_modules),
            'link_args')

    def _set_old_link_args(self) -> None:
        """Setting linker args for older versions of llvm.

        Old versions of LLVM bring an extra level of insanity with them.
        llvm-config will provide the correct arguments for static linking, but
        not for shared-linking, we have to figure those out ourselves, because
        of course we do.
        """
        if self.static:
            self.link_args = self.get_config_value(
                ['--libs', '--ldflags', '--system-libs'] + list(self.required_modules),
                'link_args')
        else:
            # llvm-config will provide arguments for static linking, so we get
            # to figure out for ourselves what to link with. We'll do that by
            # checking in the directory provided by --libdir for a library
            # called libLLVM-<ver>.(so|dylib|dll)
            libdir = self.get_config_value(['--libdir'], 'link_args')[0]

            expected_name = f'libLLVM-{self.version}'
            re_name = re.compile(fr'{expected_name}.(so|dll|dylib)$')

            for file_ in os.listdir(libdir):
                if re_name.match(file_):
                    self.link_args = [f'-L{libdir}',
                                      '-l{}'.format(os.path.splitext(file_.lstrip('lib'))[0])]
                    break
            else:
                raise DependencyException(
                    'Could not find a dynamically linkable library for LLVM.')

    def check_components(self, modules: T.List[str], required: bool = True) -> None:
        """Check for llvm components (modules in meson terms).

        The required option is whether the module is required, not whether LLVM
        is required.
        """
        for mod in sorted(set(modules)):
            status = ''

            if mod not in self.provided_modules:
                if required:
                    self.is_found = False
                    if self.required:
                        raise DependencyException(
                            f'Could not find required LLVM Component: {mod}')
                    status = '(missing)'
                else:
                    status = '(missing but optional)'
            else:
                self.required_modules.add(mod)

            self.module_details.append(mod + status)

    def log_details(self) -> str:
        if self.module_details:
            return 'modules: ' + ', '.join(self.module_details)
        return ''

class LLVMDependencyCMake(CMakeDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        self.llvm_modules = stringlistify(extract_as_list(kwargs, 'modules'))
        self.llvm_opt_modules = stringlistify(extract_as_list(kwargs, 'optional_modules'))

        compilers = None
        if kwargs.get('native', False):
            compilers = env.coredata.compilers.build
        else:
            compilers = env.coredata.compilers.host
        if not compilers or not all(x in compilers for x in ('c', 'cpp')):
            # Initialize basic variables
            ExternalDependency.__init__(self, DependencyTypeName('cmake'), env, kwargs)

            # Initialize CMake specific variables
            self.found_modules: T.List[str] = []
            self.name = name

            # Warn and return
            mlog.warning('The LLVM dependency was not found via CMake since both a C and C++ compiler are required.')
            return

        super().__init__(name, env, kwargs, language='cpp', force_use_global_compilers=True)

        if not self.cmakebin.found():
            return

        if not self.is_found:
            return

        # CMake will return not found due to not defined LLVM_DYLIB_COMPONENTS
        if not self.static and version_compare(self.version, '< 7.0') and self.llvm_modules:
            mlog.warning('Before version 7.0 cmake does not export modules for dynamic linking, cannot check required modules')
            return

        # Extract extra include directories and definitions
        inc_dirs = self.traceparser.get_cmake_var('PACKAGE_INCLUDE_DIRS')
        defs = self.traceparser.get_cmake_var('PACKAGE_DEFINITIONS')
        # LLVM explicitly uses space-separated variables rather than semicolon lists
        if len(defs) == 1:
            defs = defs[0].split(' ')
        temp = ['-I' + x for x in inc_dirs] + defs
        self.compile_args += [x for x in temp if x not in self.compile_args]
        self.compile_args = strip_system_includedirs(env, self.for_machine, self.compile_args)
        if not self._add_sub_dependency(threads_factory(env, self.for_machine, {})):
            self.is_found = False
            return

    def _main_cmake_file(self) -> str:
        # Use a custom CMakeLists.txt for LLVM
        return 'CMakeListsLLVM.txt'

    # Check version in CMake to return exact version as config tool (latest allowed)
    # It is safe to add .0 to latest argument, it will discarded if we use search_version
    def llvm_cmake_versions(self) -> T.List[str]:

        def ver_from_suf(req: str) -> str:
            return search_version(req.strip('-')+'.0')

        def version_sorter(a: str, b: str) -> int:
            if version_compare(a, "="+b):
                return 0
            if version_compare(a, "<"+b):
                return 1
            return -1

        llvm_requested_versions = [ver_from_suf(x) for x in get_llvm_tool_names('') if version_compare(ver_from_suf(x), '>=0')]
        if self.version_reqs:
            llvm_requested_versions = [ver_from_suf(x) for x in get_llvm_tool_names('') if version_compare_many(ver_from_suf(x), self.version_reqs)]
        # CMake sorting before 3.18 is incorrect, sort it here instead
        return sorted(llvm_requested_versions, key=functools.cmp_to_key(version_sorter))

    # Split required and optional modules to distinguish it in CMake
    def _extra_cmake_opts(self) -> T.List[str]:
        return ['-DLLVM_MESON_REQUIRED_MODULES={}'.format(';'.join(self.llvm_modules)),
                '-DLLVM_MESON_OPTIONAL_MODULES={}'.format(';'.join(self.llvm_opt_modules)),
                '-DLLVM_MESON_PACKAGE_NAMES={}'.format(';'.join(get_llvm_tool_names(self.name))),
                '-DLLVM_MESON_VERSIONS={}'.format(';'.join(self.llvm_cmake_versions())),
                '-DLLVM_MESON_DYLIB={}'.format('OFF' if self.static else 'ON')]

    def _map_module_list(self, modules: T.List[T.Tuple[str, bool]], components: T.List[T.Tuple[str, bool]]) -> T.List[T.Tuple[str, bool]]:
        res = []
        for mod, required in modules:
            cm_targets = self.traceparser.get_cmake_var(f'MESON_LLVM_TARGETS_{mod}')
            if not cm_targets:
                if required:
                    raise self._gen_exception(f'LLVM module {mod} was not found')
                else:
                    mlog.warning('Optional LLVM module', mlog.bold(mod), 'was not found', fatal=False)
                    continue
            for i in cm_targets:
                res += [(i, required)]
        return res

    def _original_module_name(self, module: str) -> str:
        orig_name = self.traceparser.get_cmake_var(f'MESON_TARGET_TO_LLVM_{module}')
        if orig_name:
            return orig_name[0]
        return module


class ValgrindDependency(PkgConfigDependency):
    '''
    Consumers of Valgrind usually only need the compile args and do not want to
    link to its (static) libraries.
    '''
    def __init__(self, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__('valgrind', env, kwargs)

    def get_link_args(self, language: T.Optional[str] = None, raw: bool = False) -> T.List[str]:
        return []

packages['valgrind'] = ValgrindDependency


class ZlibSystemDependency(SystemDependency):

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        from ..compilers.c import AppleClangCCompiler
        from ..compilers.cpp import AppleClangCPPCompiler

        m = self.env.machines[self.for_machine]

        # I'm not sure this is entirely correct. What if we're cross compiling
        # from something to macOS?
        if ((m.is_darwin() and isinstance(self.clib_compiler, (AppleClangCCompiler, AppleClangCPPCompiler))) or
                m.is_freebsd() or m.is_dragonflybsd() or m.is_android()):
            # No need to set includes,
            # on macos xcode/clang will do that for us.
            # on freebsd zlib.h is in /usr/include

            self.is_found = True
            self.link_args = ['-lz']
        else:
            if self.clib_compiler.get_argument_syntax() == 'msvc':
                libs = ['zlib1', 'zlib']
            else:
                libs = ['z']
            for lib in libs:
                l = self.clib_compiler.find_library(lib, environment, [], self.libtype)
                h = self.clib_compiler.has_header('zlib.h', '', environment, dependencies=[self])
                if l and h[0]:
                    self.is_found = True
                    self.link_args = l
                    break
            else:
                return

        v, _ = self.clib_compiler.get_define('ZLIB_VERSION', '#include <zlib.h>', self.env, [], [self])
        self.version = v.strip('"')


class JNISystemDependency(SystemDependency):
    def __init__(self, environment: 'Environment', kwargs: JNISystemDependencyKW):
        super().__init__('jni', environment, T.cast('T.Dict[str, T.Any]', kwargs))

        self.feature_since = ('0.62.0', '')

        m = self.env.machines[self.for_machine]

        if 'java' not in environment.coredata.compilers[self.for_machine]:
            detect_compiler(self.name, environment, self.for_machine, 'java')
        self.javac = environment.coredata.compilers[self.for_machine]['java']
        self.version = self.javac.version

        modules: T.List[str] = mesonlib.listify(kwargs.get('modules', []))
        for module in modules:
            if module not in {'jvm', 'awt'}:
                msg = f'Unknown JNI module ({module})'
                if self.required:
                    mlog.error(msg)
                else:
                    mlog.debug(msg)
                self.is_found = False
                return

        if 'version' in kwargs and not version_compare(self.version, kwargs['version']):
            mlog.error(f'Incorrect JDK version found ({self.version}), wanted {kwargs["version"]}')
            self.is_found = False
            return

        self.java_home = environment.properties[self.for_machine].get_java_home()
        if not self.java_home:
            self.java_home = pathlib.Path(shutil.which(self.javac.exelist[0])).resolve().parents[1]
            if m.is_darwin():
                problem_java_prefix = pathlib.Path('/System/Library/Frameworks/JavaVM.framework/Versions')
                if problem_java_prefix in self.java_home.parents:
                    res = subprocess.run(['/usr/libexec/java_home', '--failfast', '--arch', m.cpu_family],
                                         stdout=subprocess.PIPE)
                    if res.returncode != 0:
                        msg = 'JAVA_HOME could not be discovered on the system. Please set it explicitly.'
                        if self.required:
                            mlog.error(msg)
                        else:
                            mlog.debug(msg)
                        self.is_found = False
                        return
                    self.java_home = pathlib.Path(res.stdout.decode().strip())

        platform_include_dir = self.__machine_info_to_platform_include_dir(m)
        if platform_include_dir is None:
            mlog.error("Could not find a JDK platform include directory for your OS, please open an issue or provide a pull request.")
            self.is_found = False
            return

        java_home_include = self.java_home / 'include'
        self.compile_args.append(f'-I{java_home_include}')
        self.compile_args.append(f'-I{java_home_include / platform_include_dir}')

        if modules:
            if m.is_windows():
                java_home_lib = self.java_home / 'lib'
                java_home_lib_server = java_home_lib
            else:
                if version_compare(self.version, '<= 1.8.0'):
                    java_home_lib = self.java_home / 'jre' / 'lib' / self.__cpu_translate(m.cpu_family)
                else:
                    java_home_lib = self.java_home / 'lib'

                java_home_lib_server = java_home_lib / 'server'

            if 'jvm' in modules:
                jvm = self.clib_compiler.find_library('jvm', environment, extra_dirs=[str(java_home_lib_server)])
                if jvm is None:
                    mlog.debug('jvm library not found.')
                    self.is_found = False
                else:
                    self.link_args.extend(jvm)
            if 'awt' in modules:
                jawt = self.clib_compiler.find_library('jawt', environment, extra_dirs=[str(java_home_lib)])
                if jawt is None:
                    mlog.debug('jawt library not found.')
                    self.is_found = False
                else:
                    self.link_args.extend(jawt)

        self.is_found = True

    @staticmethod
    def __cpu_translate(cpu: str) -> str:
        '''
        The JDK and Meson have a disagreement here, so translate it over. In the event more
        translation needs to be done, add to following dict.
        '''
        java_cpus = {
            'x86_64': 'amd64',
        }

        return java_cpus.get(cpu, cpu)

    @staticmethod
    def __machine_info_to_platform_include_dir(m: 'MachineInfo') -> T.Optional[str]:
        '''Translates the machine information to the platform-dependent include directory

        When inspecting a JDK release tarball or $JAVA_HOME, inside the `include/` directory is a
        platform-dependent directory that must be on the target's include path in addition to the
        parent `include/` directory.
        '''
        if m.is_linux():
            return 'linux'
        elif m.is_windows():
            return 'win32'
        elif m.is_darwin():
            return 'darwin'
        elif m.is_sunos():
            return 'solaris'
        elif m.is_freebsd():
            return 'freebsd'
        elif m.is_netbsd():
            return 'netbsd'
        elif m.is_openbsd():
            return 'openbsd'
        elif m.is_dragonflybsd():
            return 'dragonfly'

        return None

packages['jni'] = JNISystemDependency


class JDKSystemDependency(JNISystemDependency):
    def __init__(self, environment: 'Environment', kwargs: JNISystemDependencyKW):
        super().__init__(environment, kwargs)

        self.feature_since = ('0.59.0', '')
        self.featurechecks.append(FeatureDeprecated(
            'jdk system dependency',
            '0.62.0',
            'Use the jni system dependency instead'
        ))

packages['jdk'] = JDKSystemDependency


packages['llvm'] = llvm_factory = DependencyFactory(
    'LLVM',
    [DependencyMethods.CMAKE, DependencyMethods.CONFIG_TOOL],
    cmake_class=LLVMDependencyCMake,
    configtool_class=LLVMDependencyConfigTool,
)

packages['gtest'] = gtest_factory = DependencyFactory(
    'gtest',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM],
    pkgconfig_class=GTestDependencyPC,
    system_class=GTestDependencySystem,
)

packages['gmock'] = gmock_factory = DependencyFactory(
    'gmock',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM],
    pkgconfig_class=GMockDependencyPC,
    system_class=GMockDependencySystem,
)

packages['zlib'] = zlib_factory = DependencyFactory(
    'zlib',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CMAKE, DependencyMethods.SYSTEM],
    cmake_name='ZLIB',
    system_class=ZlibSystemDependency,
)

"""

```