Response:
The user wants to understand the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool's build system. I need to analyze the code and identify its purpose, especially concerning reverse engineering, binary manipulation, and interaction with operating system kernels and frameworks. I also need to provide examples of logical reasoning, potential user errors, and how a user might reach this code during debugging.

**Plan:**

1. **Overall Functionality:** Determine the high-level goal of this `dev.py` file within the Frida build process. It seems to be defining dependencies for the build system.
2. **Reverse Engineering Relevance:** Identify if any of the defined dependencies or the logic within the file are directly related to reverse engineering tasks. Frida itself is a reverse engineering tool, so its build system likely touches on related concepts.
3. **Binary/Kernel/Framework Relevance:** Look for code that interacts with binary files, operating system functionalities (Linux, Android kernel/framework), or low-level system libraries.
4. **Logical Reasoning:**  Pinpoint any conditional logic or decision-making processes within the code and create hypothetical input/output examples.
5. **User Errors:** Consider common mistakes a user might make that could lead to issues related to these dependencies.
6. **Debugging Scenario:**  Describe a realistic sequence of user actions that could lead a developer or user to examine this specific file during a debugging session.
这个Python源代码文件 `dev.py` 的主要功能是定义和检测 Frida 工具构建过程中所依赖的各种开发库（dependencies）。它使用 Meson 构建系统的 API 来查找和配置这些依赖项，以便在编译和链接 Frida 的不同组件时能够正确地使用它们。

以下是更详细的功能列表和相关说明：

**1. 定义依赖项类型：**

*   文件中定义了多种依赖项的类，这些类继承自基类 `SystemDependency` 或 `ExternalDependency`：
    *   `GTestDependencySystem`, `GTestDependencyPC`: 定义 Google Test 单元测试框架的依赖。
    *   `GMockDependencySystem`, `GMockDependencyPC`: 定义 Google Mock 模拟框架的依赖。
    *   `LLVMDependencyConfigTool`, `LLVMDependencyCMake`: 定义 LLVM 编译器基础设施的依赖，支持使用 `llvm-config` 工具或 CMake 进行查找。
    *   `ValgrindDependency`: 定义 Valgrind 内存调试工具的依赖。
    *   `ZlibSystemDependency`: 定义 Zlib 压缩库的依赖。
    *   `JNISystemDependency`, `JDKSystemDependency`: 定义 Java Native Interface (JNI) 和 Java Development Kit (JDK) 的依赖。

**2. 依赖项查找和配置：**

*   每个依赖项类都实现了特定的逻辑来查找系统上是否已安装该库，以及如何获取其编译和链接所需的参数（例如头文件路径、库文件路径、编译选项、链接选项）。
*   它尝试多种查找方法，例如：
    *   查找预编译的库文件（`.so`, `.dylib`, `.dll`）。
    *   查找库的开发包（包含头文件和静态/动态库）。
    *   使用 `pkg-config` 工具（`*.pc` 文件）。
    *   使用特定于库的工具，如 `llvm-config`。
    *   使用 CMake 的 `find_package` 功能。
    *   在预定义的系统路径中查找源文件（例如 GTest, GMock）。
*   根据查找结果，它会设置依赖项对象的属性，如 `is_found`（是否找到），`compile_args`（编译参数），`link_args`（链接参数），`sources`（源代码文件，用于内部构建的情况）。

**3. 与逆向方法的关联和举例：**

*   **GTest 和 GMock：** 这两个框架常用于编写 Frida 自身的单元测试。逆向工程师在开发 Frida 的新特性或修复 bug 时，会使用这些测试来验证代码的正确性。
    *   **举例：**  假设逆向工程师修改了 Frida 处理 JavaScript 代码的模块。他们可能会编写一个使用 GTest 的测试用例，来断言新的处理逻辑对于特定的输入能够产生预期的结果。
*   **LLVM：** Frida 的某些组件（特别是和即时编译相关的部分）可能会依赖 LLVM。LLVM 提供了强大的代码生成和优化功能，这在动态 instrumentation 中非常有用。
    *   **举例：** 如果 Frida 需要在运行时动态生成机器码来 hook 某个函数，它可能会使用 LLVM 的 API 来实现这个功能。该文件会确保构建时能够找到 LLVM 的开发库。
*   **Valgrind：** 用于检测 Frida 代码中的内存泄漏和其他内存相关的错误。逆向工程师可以使用 Valgrind 来确保 Frida 自身的稳定性和可靠性。
    *   **举例：** 在开发 Frida 的 native 模块时，如果怀疑存在内存泄漏，可以使用 Valgrind 运行 Frida 的测试，并分析 Valgrind 的输出报告。
*   **JNI/JDK：**  Frida 可以在 Java 虚拟机中运行，或者与 Java 代码进行交互。因此，对 JNI 和 JDK 的依赖是必要的。
    *   **举例：**  Frida 可以注入到 Android 应用的 Dalvik/ART 虚拟机中，或者允许从 Java 代码中调用 Frida 的功能。这需要 JNI 来连接 native 代码和 Java 代码。

**4. 涉及二进制底层、Linux、Android 内核及框架的知识和举例：**

*   **查找共享库后缀：** 函数 `get_shared_library_suffix` 根据目标操作系统（Windows, macOS, Linux）返回共享库文件的后缀名（`.dll`, `.dylib`, `.so`）。这涉及到不同操作系统下二进制文件的格式和命名约定。
*   **查找库文件：**  代码中多次使用编译器对象的方法（如 `clib_compiler.find_library`）来查找库文件。这需要知道库文件在不同操作系统和发行版中的常见位置。
*   **处理系统包含目录和库目录：** 函数 `strip_system_includedirs` 和 `strip_system_libdirs` 用于去除编译器默认的系统包含目录和库目录，以避免不必要的依赖或冲突。这需要了解编译器的搜索路径机制。
*   **LLVM 的模块化：**  LLVM 被组织成多个模块，代码中会检查所需的 LLVM 模块是否存在。这反映了 LLVM 复杂的架构。
    *   **举例：**  如果 Frida 的某个功能需要 LLVM 的 JIT 编译功能，那么在构建时就需要找到 `LLVMCodeGen` 或相关的模块。
*   **Android 特殊处理：** 在 `ZlibSystemDependency` 和 `JNISystemDependency` 中，可以看到对 Android 系统的特殊处理。这表明 Frida 需要考虑 Android 平台的特殊性。
    *   **举例：** 在 Android 上，Zlib 库通常是系统库，不需要额外链接。JNI 的头文件路径也与标准 Linux 系统不同。
*   **JNI 中 CPU 架构的转换：** `JNISystemDependency.__cpu_translate` 函数用于将 Meson 使用的 CPU 架构名称转换为 JDK 使用的名称。这反映了不同工具链对架构命名的差异。

**5. 逻辑推理的假设输入与输出：**

*   **GTest 依赖查找：**
    *   **假设输入：** 用户机器上安装了 GTest 的开发包，头文件在 `/usr/include/gtest`，库文件是 `/usr/lib/libgtest.so` 和 `/usr/lib/libgtest_main.so`。
    *   **输出：** `GTestDependencySystem` 对象的 `is_found` 属性为 `True`，`compile_args` 可能包含 `-I/usr/include/gtest`，如果 `main=True`，则 `link_args` 将包含 `['-lgtest', '-lgtest_main']`。
*   **LLVM 依赖查找（使用 `llvm-config`）：**
    *   **假设输入：** 用户机器上安装了 LLVM，并且 `llvm-config` 命令可用。运行 `llvm-config --version` 返回 `14.0.0`，运行 `llvm-config --libs Core` 返回 `-lLLVMCore`。
    *   **输出：** `LLVMDependencyConfigTool` 对象的 `is_found` 属性为 `True`，`version` 属性为 `14.0.0`，如果指定了 `modules=['Core']`，则 `link_args` 将包含 `-lLLVMCore`。
*   **JNI 依赖查找：**
    *   **假设输入：** 用户机器上安装了 JDK，`JAVA_HOME` 环境变量已设置正确，例如 `/usr/lib/jvm/java-11-openjdk-amd64`。
    *   **输出：** `JNISystemDependency` 对象的 `is_found` 属性为 `True`，`compile_args` 将包含类似 `-I/usr/lib/jvm/java-11-openjdk-amd64/include` 和 `-I/usr/lib/jvm/java-11-openjdk-amd64/include/linux` 的路径。如果 `modules=['jvm']`，则 `link_args` 可能会包含 `-ljvm`（具体路径取决于操作系统）。

**6. 用户或编程常见的使用错误和举例：**

*   **缺少依赖库：** 用户在构建 Frida 时，如果缺少某个必要的依赖库（例如没有安装 LLVM 的开发包），构建过程会失败。
    *   **举例：** 如果用户没有安装 `libgtest-dev`，尝试构建 Frida 时，`GTestDependencySystem` 会找不到 GTest，导致构建失败并提示缺少依赖。
*   **错误的依赖库版本：** Frida 可能需要特定版本的依赖库。如果用户安装的版本不兼容，可能会导致编译错误或运行时错误。
    *   **举例：** 如果 Frida 需要 LLVM 10 或更高版本，但用户只安装了 LLVM 9，`LLVMDependencyConfigTool` 可能会检测到版本不匹配并报错。
*   **环境变量未设置或设置错误：** 某些依赖库的查找可能依赖于特定的环境变量，例如 `JAVA_HOME`。如果这些变量未设置或设置错误，会导致依赖项查找失败。
    *   **举例：** 如果 `JAVA_HOME` 没有指向正确的 JDK 安装目录，`JNISystemDependency` 可能无法找到 JNI 的头文件和库文件。
*   **指定了不存在的模块：** 对于像 LLVM 和 JNI 这样的模块化库，如果用户在 Meson 的构建选项中指定了不存在的模块，会导致构建失败。
    *   **举例：** 如果用户在构建 Frida 时指定 LLVM 依赖的模块为 `NonExistentModule`，`LLVMDependencyConfigTool` 或 `LLVMDependencyCMake` 会检测到该模块不存在并报错。
*   **编译选项冲突：** 用户可能在 Meson 的构建选项中设置了与依赖库要求不一致的编译选项。
    *   **举例：** 如果用户强制使用静态链接，但 LLVM 没有以静态方式构建，`LLVMDependencyConfigTool` 可能会因为找不到静态库而失败。

**7. 用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida：** 用户从 Frida 的 Git 仓库克隆了源代码，并尝试使用 Meson 构建系统编译 Frida。通常的命令是 `meson setup build` 和 `ninja -C build`。
2. **构建失败并出现关于依赖项的错误：** 在构建过程中，Meson 会执行 `dev.py` 文件来查找和配置依赖项。如果某个依赖项找不到或配置错误，构建过程会失败并显示相关的错误信息。
3. **用户查看构建日志：** 用户会查看 Meson 或 Ninja 的构建日志，以了解构建失败的具体原因。日志中可能会包含关于哪个依赖项查找失败，以及相关的错误信息（例如找不到头文件、库文件）。
4. **用户怀疑是依赖项配置问题：** 根据错误信息，用户可能会怀疑是依赖项的配置出现了问题，例如 Meson 没有正确找到某个库。
5. **用户查看 `meson.build` 文件：** 用户可能会查看 Frida 仓库根目录下的 `meson.build` 文件，了解 Frida 声明了哪些依赖项。
6. **用户定位到 `dev.py` 文件：**  在 `meson.build` 文件中，会看到如何使用 `dependency()` 函数来声明依赖项。通过查看 Meson 的源代码或文档，用户可能会了解到 `dependency()` 函数的实现会调用 `frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/dev.py` 中的代码来处理这些依赖项。
7. **用户查看 `dev.py` 的源代码：** 为了深入了解依赖项的查找和配置过程，用户可能会打开 `frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/dev.py` 文件，查看具体的实现逻辑，例如 `GTestDependencySystem.__init__` 或 `LLVMDependencyConfigTool.detect` 等函数，来理解依赖项是如何被检测和配置的。
8. **用户尝试修改或调试 `dev.py`：**  在某些情况下，为了解决依赖项问题，用户可能会尝试修改 `dev.py` 文件中的代码，例如添加额外的搜索路径、修改查找逻辑等。这通常是高级用户或 Frida 的开发者才会进行的操作。他们可能会添加 `print()` 语句来调试变量的值，或者修改条件判断来绕过某些检测。

总而言之，`dev.py` 文件是 Frida 构建系统的关键组成部分，负责处理各种开发依赖项的查找、配置和管理，确保 Frida 能够成功编译和链接。它涉及到操作系统、编译器、链接器以及各种开发库的底层知识，对于理解 Frida 的构建过程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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