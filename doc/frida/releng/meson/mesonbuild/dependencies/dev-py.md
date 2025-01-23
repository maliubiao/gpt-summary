Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Core Purpose:** The filename and the initial comments (`frida/releng/meson/mesonbuild/dependencies/dev.py`, "fridaDynamic instrumentation tool", "SPDX-License-Identifier: Apache-2.0", "Copyright 2013-2019 The Meson development team") immediately suggest this file is part of the Meson build system and handles external dependencies for the Frida project. The `dev.py` likely indicates "development" dependencies, though that's a slight misnomer as it handles common system dependencies.

2. **Identify Key Classes:**  A quick scan reveals several important classes inheriting from `SystemDependency`, `PkgConfigDependency`, `CMakeDependency`, and `ConfigToolDependency`. This strongly indicates that the file is responsible for finding and configuring different types of system libraries or packages that Frida might depend on. The names of these classes (e.g., `GTestDependencySystem`, `LLVMDependencyConfigTool`) give clues about the specific dependencies they handle.

3. **Analyze Individual Dependency Classes:** For each dependency class, focus on:
    * **Initialization (`__init__`)**: What are the input parameters (e.g., `name`, `environment`, `kwargs`)? What initial setup is performed? Are there checks for sub-dependencies?
    * **Detection Logic (`detect` or similar methods):** How does the class attempt to find the dependency on the system? Does it look for libraries, headers, or use tools like `pkg-config` or `llvm-config`?
    * **Configuration:** What information is extracted (compile flags, link flags, source files)? How is this information stored (e.g., in `self.compile_args`, `self.link_args`)?
    * **Logging (`log_info`, `log_details`):**  What information does the class provide for debugging?

4. **Look for Patterns:** Notice how several classes follow a similar structure:
    * They inherit from a base dependency class.
    * They often have both a `System` and a `PC` (PkgConfig) variant.
    * They might use different methods (system search, pkg-config, CMake, config-tool) to find the same dependency.

5. **Connect to Reverse Engineering:** Consider how the listed dependencies are relevant to reverse engineering. Think about the tasks involved in reverse engineering and which tools or libraries would be helpful. For example:
    * **GTest/GMock:** Used for testing, relevant for *testing* reverse engineering tools or analyzing software that uses these frameworks.
    * **LLVM:** A compiler infrastructure, crucial for tools that perform static analysis, code instrumentation, or recompilation.
    * **Valgrind:** A memory debugging tool, important for ensuring the correctness of reverse engineering tools.
    * **Zlib:** A compression library, frequently encountered when dealing with packed or compressed binaries.
    * **JNI/JDK:** Necessary for interacting with Java code, a common target for reverse engineering.

6. **Identify Potential User Errors:**  Think about what could go wrong when using these dependency definitions. Common issues include:
    * Missing dependencies.
    * Incorrect versions of dependencies.
    * Incorrect environment configuration (e.g., `JAVA_HOME` not set).
    * Conflicts between different ways of finding a dependency (e.g., system vs. pkg-config).

7. **Trace User Actions:** Imagine a developer trying to build a project using Meson and these dependency definitions. What steps would they take that would eventually lead to this code being executed? This helps understand the debugging context.

8. **Infer Logic and Assumptions:**  Analyze conditional statements and loops. What are the assumptions made by the code? For example, the LLVM dependency code makes assumptions about the behavior of `llvm-config` for different LLVM versions. Think about edge cases and potential issues arising from these assumptions.

9. **Consider Binary/Kernel Aspects:** Some dependencies, like LLVM and JNI, have direct connections to binary formats and operating system interactions. Explain how these dependencies relate to these lower-level aspects.

10. **Structure the Answer:** Organize the findings into logical sections based on the prompt's questions. Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just lists dependencies."  **Correction:**  It doesn't just list them; it *defines how to find and configure* them.
* **Overlooking Details:** Initially, I might have skipped over the version comparison logic in the `JNISystemDependency`. **Refinement:** Realize the importance of version compatibility and include it in the analysis.
* **Focusing too much on individual lines:**  Step back and understand the overall flow and purpose of each class and the file as a whole.
* **Not making explicit connections:**  Initially, I might have just listed the functions of each dependency without explicitly linking them to reverse engineering or lower-level concepts. **Refinement:**  Ensure these connections are clearly stated.

By following this iterative process of exploration, analysis, and refinement, you can build a comprehensive understanding of the code's functionality and its relevance to the broader context.
这个文件 `frida/releng/meson/mesonbuild/dependencies/dev.py` 是 Frida 项目中 Meson 构建系统用于处理**开发依赖**的一个关键文件。它定义了如何查找和配置 Frida 构建所需的各种外部库和工具。

**功能列表:**

1. **定义和检测系统依赖:**  这个文件包含了多个类的定义，每个类负责处理一个特定的系统依赖项，例如 `gtest`, `gmock`, `llvm`, `valgrind`, `zlib`, `jni` (Java Native Interface), `jdk` (Java Development Kit)。这些类都继承自 `SystemDependency` 或其子类。
2. **多种依赖查找方法:**  对于同一个依赖项，可能定义了多种查找方法，例如通过 `pkg-config`, `cmake`, 或者直接在系统路径中查找库文件和头文件。这提高了在不同操作系统和环境下的兼容性。
3. **配置编译和链接参数:**  一旦找到依赖项，这些类会提取出编译所需的头文件路径 (`compile_args`) 和链接所需的库文件路径和参数 (`link_args`)。
4. **处理不同版本的依赖:**  部分依赖项的类会根据已安装的版本执行不同的查找和配置策略，例如 `LLVMDependencyConfigTool` 会根据 LLVM 的版本使用不同的链接参数设置。
5. **处理依赖项的子依赖:**  某些依赖项可能需要先找到其他的依赖项才能正常工作。例如，`GTestDependencySystem` 和 `GMockDependencySystem` 都依赖于 `threads`。
6. **处理可选模块:**  对于某些依赖项（如 LLVM 和 JNI），可以指定需要哪些可选的模块。
7. **提供友好的日志信息:**  每个依赖项的类都提供了 `log_info` 和 `log_details` 方法，用于在构建过程中输出关于依赖项状态的有用信息。
8. **处理静态和动态链接:**  对于一些库（如 LLVM），可以指定是静态链接还是动态链接。
9. **处理特定平台的差异:**  代码中包含针对不同操作系统（如 Linux, macOS, Windows）的特殊处理逻辑，例如查找 JNI 库的路径。
10. **定义依赖查找工厂:**  使用了 `DependencyFactory` 来统一管理不同依赖项的查找方法。

**与逆向方法的关系及举例说明:**

Frida 本身就是一个动态插桩工具，广泛应用于逆向工程。这个文件定义的依赖项很多都直接或间接地与逆向方法相关：

* **LLVM (Low-Level Virtual Machine):**  LLVM 是一个强大的编译器基础设施，Frida 的某些组件可能使用 LLVM 来进行代码生成、优化或者进行二进制分析。
    * **举例:** Frida 可以使用 LLVM 的反汇编库 (如 Capstone，虽然这里没直接列出，但 LLVM 的功能类似) 来将目标进程的机器码反汇编成可读的汇编指令，方便逆向工程师分析程序的行为。
* **GTest/GMock (Google Test/Google Mock):**  虽然是测试框架，但用于测试 Frida 本身的功能，确保插桩和 hook 等核心功能的正确性。逆向工程师在开发自己的 Frida 脚本或扩展时，也可以使用这些框架进行单元测试。
    * **举例:**  Frida 的开发者可能会使用 GTest 来编写测试用例，验证当 Frida hook 某个函数后，该函数的行为是否如预期被修改。
* **Valgrind:**  一个内存调试和性能分析工具。Frida 的开发过程中可以使用 Valgrind 来检测内存泄漏、非法内存访问等问题，保证 Frida 本身的稳定性和可靠性。
    * **举例:**  在开发新的 Frida 功能时，开发者可能会使用 Valgrind 来运行 Frida，观察是否存在内存泄漏，尤其是在处理目标进程内存时。
* **Zlib:**  一个通用的数据压缩库。Frida 可能使用 zlib 来压缩传输的数据，或者处理目标进程中压缩的数据。
    * **举例:**  Frida 可以将收集到的目标进程的内存快照进行压缩后传输到控制端，以减少网络带宽消耗。
* **JNI/JDK:**  用于和 Java 代码进行交互。在逆向 Android (使用 Java) 应用时，Frida 经常需要通过 JNI 与 Dalvik/ART 虚拟机交互。
    * **举例:**  当逆向一个 Android 应用时，Frida 需要找到 `libjvm.so` (JVM 库) 或其他 JNI 相关的库，才能 hook Java 方法或者读取 Java 对象的属性。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个文件在处理依赖项时，涉及到很多底层知识：

* **二进制底层:**
    * **库文件后缀:**  `get_shared_library_suffix` 函数根据目标机器的操作系统判断共享库的后缀名 (`.so`, `.dylib`, `.dll`)，这是与二进制文件格式直接相关的知识。
    * **链接参数:**  代码中处理 `-l` 参数来指定需要链接的库，以及 `-L` 参数来指定库的搜索路径，这些都是链接器 (linker) 的基本概念。
    * **头文件包含路径:**  代码中处理 `-I` 参数来指定头文件的搜索路径，这是编译器 (compiler) 的基本概念。
* **Linux:**
    * **标准库路径:**  代码中硬编码了一些 Linux 系统上常见的库文件路径，例如 `/usr/lib`, `/usr/local/lib` 等。
    * **pkg-config:**  使用了 `PkgConfigDependency` 来查找依赖项，`pkg-config` 是 Linux 系统上常用的管理库依赖的工具。
    * **`/usr/src` 路径:**  `GTestDependencySystem` 中查找 GTest 源代码的路径 `/usr/src/gtest/src` 和 `/usr/src/googletest/googletest/src` 是 Linux 系统上源码安装库的常见位置。
* **Android 内核及框架:**
    * **JNI 依赖:**  `JNISystemDependency` 类专门处理 JNI 相关的依赖，这是在 Android 上进行本地代码开发和逆向的重要组成部分。
    * **`java_home` 的查找:**  代码中尝试查找 `java_home` 环境变量或通过 `which javac` 命令来定位 JDK 的安装路径，这对于与 Android 虚拟机交互至关重要。
    * **特定平台的 JNI 头文件路径:**  `__machine_info_to_platform_include_dir` 函数根据操作系统类型选择正确的 JNI 头文件路径（例如 `linux`, `win32`, `darwin`），这反映了不同平台 JNI 实现的差异。
    * **JDK 版本差异:**  `JNISystemDependency` 中针对不同的 JDK 版本（例如 1.8.0 之前和之后）查找 JNI 库的路径有所不同，这体现了对 Android 平台 Java 版本演进的理解。

**逻辑推理，假设输入与输出:**

以 `GTestDependencySystem` 为例：

* **假设输入:**  `environment` 对象包含关于目标机器和编译器信息，`kwargs` 可能包含 `{'main': True}` 表示需要链接 `gtest_main` 库。
* **逻辑推理:**
    1. 首先尝试查找预编译的 `libgtest.so` 和 `libgtest_main.so` 库文件。
    2. 如果找不到预编译的库，则检查是否存在 GTest 的源代码目录 `/usr/src/gtest/src` 或 `/usr/src/googletest/googletest/src`。
    3. 如果找到源代码目录，则设置编译参数 (`-I`) 和源代码文件路径。
    4. 如果 `kwargs` 中 `main` 为 `True`，则需要链接 `gtest_main`，无论是预编译还是从源码构建。
* **可能的输出:**
    * **找到预编译库:** `self.is_found = True`, `self.compile_args = []`, `self.link_args = ['-lgtest', '-lgtest_main']`
    * **找到源代码:** `self.is_found = True`, `self.compile_args = ['-I/usr/src/googletest/googletest/include']`, `self.sources = [mesonlib.File(...gtest-all.cc), mesonlib.File(...gtest_main.cc)]`, `self.link_args = []`
    * **未找到:** `self.is_found = False`

**用户或编程常见的使用错误及举例说明:**

* **依赖项未安装:**  如果用户没有安装所需的依赖项，Meson 构建会失败。
    * **举例:**  如果用户尝试构建 Frida，但没有安装 LLVM，Meson 在处理 `llvm` 依赖时会找不到 `llvm-config` 工具，导致构建失败，并可能提示类似 "Could not find LLVM dependency" 的错误。
* **依赖项版本不兼容:**  某些 Frida 版本可能依赖特定版本的库。
    * **举例:**  如果 Frida 需要 LLVM 7.0 或更高版本，但用户安装的是 LLVM 6.0，`LLVMDependencyConfigTool` 在检查版本时会发现不匹配，导致构建失败。
* **环境变量未设置:**  某些依赖项的查找可能依赖于特定的环境变量。
    * **举例:**  `JNISystemDependency` 依赖 `JAVA_HOME` 环境变量来定位 JDK 的安装路径。如果用户没有设置 `JAVA_HOME`，或者设置的路径不正确，Meson 将无法找到 JNI 相关的头文件和库文件。
* **编译选项冲突:**  用户在配置 Meson 时可能会设置与依赖项要求冲突的选项。
    * **举例:**  如果用户强制使用静态链接，但某个依赖项（例如 LLVM 在某些配置下）只能动态链接，则构建可能会失败。
* **指定了错误的模块名称:**  在使用 `modules` 参数指定可选模块时，如果拼写错误或者指定了不存在的模块，会导致构建失败或警告。
    * **举例:**  在使用 LLVM 依赖时，如果用户错误地指定了 `modules=['clanggg']`（正确的可能是 `clang`），`LLVMDependencyConfigTool` 会报告找不到该模块。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:**  用户通常会执行类似 `meson build` 或 `ninja` 命令来启动 Frida 的构建过程。
2. **Meson 解析 `meson.build` 文件:**  Meson 会读取项目根目录下的 `meson.build` 文件，该文件描述了项目的构建配置和依赖关系。
3. **遇到 `dependency()` 函数:**  在 `meson.build` 文件中，可能会有类似 `llvm_dep = dependency('llvm', modules: ['clang'])` 的语句，声明了对 LLVM 的依赖。
4. **调用 `Dependency()` 工厂:**  Meson 的依赖管理机制会根据依赖项的名称（例如 'llvm'）调用相应的 `DependencyFactory`。
5. **`DependencyFactory` 选择查找方法:**  `llvm_factory` 定义了查找 LLVM 的方法，优先尝试 CMake，然后是 `llvm-config` 工具。
6. **执行 `LLVMDependencyCMake` 或 `LLVMDependencyConfigTool` 的 `__init__` 方法:**  根据选择的查找方法，会实例化相应的依赖类。
7. **执行 `detect` 方法 (或 `_extra_cmake_opts` 等方法):**  依赖类会执行具体的查找和配置逻辑，例如运行 `llvm-config --version --cflags --ldflags ...` 命令或者执行 CMake 命令。
8. **如果查找失败或配置不正确:**  相关的依赖类会将 `self.is_found` 设置为 `False`，并可能抛出异常或输出警告信息。
9. **调试线索:**  如果构建过程中出现与依赖项相关的问题，用户可以检查以下内容：
    * **Meson 的输出信息:**  Meson 会打印出关于依赖项查找和配置的详细信息，包括是否找到、使用的查找方法、提取的编译和链接参数等。
    * **`meson.build` 文件:**  检查 `dependency()` 函数的参数是否正确，例如依赖项名称、版本要求、模块列表等。
    * **系统环境变量:**  检查与依赖项相关的环境变量是否设置正确，例如 `JAVA_HOME`。
    * **依赖项的安装:**  确认所需的依赖项已经正确安装在系统中，并且版本符合要求。
    * **构建日志:**  查看详细的构建日志，可以找到执行的命令和输出，进一步定位问题。

总而言之，`frida/releng/meson/mesonbuild/dependencies/dev.py` 是 Frida 项目构建系统的核心组成部分，负责处理各种开发依赖项的查找、配置和管理，这对于保证 Frida 能够在不同的平台上顺利构建至关重要，并且其中涉及到的很多技术和知识点都与逆向工程密切相关。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```