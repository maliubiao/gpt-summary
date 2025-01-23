Response:
Let's break down the thought process to analyze this Python code and answer the prompt's questions.

**1. Understanding the Core Purpose:**

The first step is to recognize the file's location (`frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/dev.py`) and the surrounding context (Frida, Meson). This immediately suggests it's part of Frida's build system, specifically handling external dependencies within the Python component. The filename `dev.py` might indicate it handles dependencies for development or system-level components.

**2. Initial Scan for Key Concepts:**

I'd scan the code for keywords and patterns related to the prompt:

* **Functionality:**  Look for class definitions, function definitions, and what they seem to be doing (e.g., `detect`, `find_library`, `get_config_value`). The numerous `Dependency` classes stand out as the core functionality.
* **Reverse Engineering:** Search for terms like "disassemble," "breakpoint," "memory," or any mention of binary manipulation. The presence of `frida` in the path hints at relevance, but the immediate code itself might be focused on dependency management.
* **Binary/Low-Level:** Look for interactions with the operating system, file system operations (`os.path.exists`, `glob`), and compiler/linker flags (`compile_args`, `link_args`).
* **Linux/Android Kernel/Framework:**  Examine specific paths (`/usr/src/gtest`, `/System/Library/Frameworks/JavaVM.framework`), and look for OS-specific checks (`m.is_linux()`, `m.is_android()`). The `JNISystemDependency` clearly relates to Java.
* **Logic/Inference:** Pay attention to conditional statements (`if`, `elif`, `else`), loops (`for`), and how different dependencies are handled. Look for patterns in how dependency information is collected and used.
* **User Errors:** Consider scenarios where configuration is wrong or dependencies are missing. Look for error messages (`mlog.error`, `DependencyException`).
* **User Journey/Debugging:** Think about how a developer might interact with Frida's build process. How does Meson discover these dependencies? What happens if a dependency isn't found?

**3. Detailed Analysis of Key Sections:**

* **Dependency Classes:** Focus on the structure of the `SystemDependency`, `ExternalDependency`, `PkgConfigDependency`, `CMakeDependency`, and custom dependency classes like `GTestDependencySystem`, `GMockDependencySystem`, `LLVMDependencyConfigTool`, `JNISystemDependency`, and `ZlibSystemDependency`. Understand their inheritance relationships and how they override or extend base class behavior.
* **Detection Mechanisms:**  Analyze the `detect()` methods and how they try to find dependencies (e.g., looking for libraries, headers, using `pkg-config`, or `llvm-config`).
* **Configuration Tool Integration:** Understand how `ConfigToolDependency` is used for `llvm-config`. Note how it fetches compiler flags, linker flags, and version information.
* **CMake Integration:**  Analyze the `CMakeDependency` class, particularly how it constructs CMake commands and parses the output to extract dependency information. The custom `CMakeListsLLVM.txt` for LLVM is significant.
* **System-Specific Logic:** Pay close attention to the conditional logic within classes like `ZlibSystemDependency` and `JNISystemDependency` that handle platform differences (macOS, Linux, Windows).
* **Error Handling:** Identify how missing dependencies or version mismatches are handled (e.g., setting `is_found = False`, raising `DependencyException`).

**4. Answering the Specific Questions (Iterative Refinement):**

* **Functionality:**  Based on the analysis, list the core functionalities: dependency detection, providing compiler/linker flags, handling different dependency sources (system, pkg-config, CMake, config tools), and managing versions.

* **Relevance to Reverse Engineering:**  Initially, the direct connection isn't obvious within *this specific file*. However, since it's part of Frida, and Frida is used for dynamic instrumentation (a key technique in reverse engineering), the *dependencies* managed by this file are likely used by Frida's core components that *do* perform reverse engineering tasks. This requires a bit of domain knowledge about Frida.

* **Binary/Low-Level:**  Identify the mechanisms for interacting with the underlying system: finding libraries, headers, manipulating compiler/linker arguments, and handling OS-specific differences in library naming and locations.

* **Linux/Android Kernel/Framework:** Pinpoint the code sections that explicitly deal with Linux (`/usr/src`), Android, and the Java framework (`JNISystemDependency`).

* **Logic/Inference:** Analyze the conditional logic in dependency detection. For example, the `GTestDependencySystem` tries to find pre-built libraries first, and if that fails, it looks for source code. The `LLVMDependencyConfigTool` has complex logic based on the LLVM version. Think of simple input scenarios (e.g., `gtest` dependency requested) and how the code would try to locate it.

* **User Errors:**  Consider common mistakes: requesting a specific version that's not installed, missing required "modules" for LLVM or JNI, or having an incorrectly configured environment.

* **User Journey/Debugging:**  Trace the likely steps: a user runs Meson to build Frida, Meson encounters a dependency declaration, and then this code is invoked to find and configure that dependency. If something goes wrong (dependency not found), Meson will report an error, possibly pointing to issues handled by this code.

**5. Refinement and Organization:**

After the initial analysis, review the answers for clarity, accuracy, and completeness. Organize the information logically, using examples where appropriate. For instance, when discussing user errors, give concrete examples of incorrect dependency declarations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file seems very focused on dependency management, not direct reverse engineering."
* **Correction:** "While the *code itself* doesn't perform reverse engineering, it manages the dependencies *used by* Frida's reverse engineering components. Therefore, it's indirectly related."
* **Initial thought:** "Just list the classes and their immediate functions."
* **Refinement:** "Explain the *purpose* of these classes in the context of dependency management. Connect the code to the broader goal of building Frida."

By following this iterative process of scanning, analyzing, and refining, one can systematically understand the functionality of complex code like this and answer the specific questions in the prompt.
这个文件 `dev.py` 是 Frida 动态 instrumentation 工具构建系统的一部分，它使用 Meson 构建系统来管理项目依赖。这个文件的主要职责是定义和检测各种开发和系统依赖项，这些依赖项是构建 Frida Python 绑定所必需的。

以下是 `dev.py` 文件的功能列表以及与逆向、二进制底层、Linux/Android 内核及框架知识的关联，以及逻辑推理、用户错误和调试线索的说明：

**功能列表:**

1. **定义依赖项类:**  定义了各种依赖项的类，这些类继承自 `SystemDependency`、`ExternalDependency`、`PkgConfigDependency`、`CMakeDependency` 和 `ConfigToolDependency` 等基类。这些类封装了特定依赖项的检测和配置逻辑。
2. **系统依赖项检测:**  实现了检测系统上已安装的特定库和工具的功能，例如 `gtest`、`gmock`、`llvm`、`valgrind`、`zlib` 和 `jni` (Java Native Interface)。
3. **多种检测方法:**  针对不同的依赖项，使用了多种检测方法，包括：
    * **查找库文件:** 使用编译器的 `find_library` 方法查找预编译的库文件。
    * **查找头文件:** 使用编译器的 `has_header` 方法查找头文件。
    * **pkg-config:** 使用 `pkg-config` 工具获取库的编译和链接参数。
    * **llvm-config:** 使用 `llvm-config` 工具获取 LLVM 的编译和链接参数。
    * **CMake:** 使用 CMake 来查找和配置依赖项，特别是对于 LLVM。
    * **源码构建:** 对于某些依赖项（如 `gtest` 和 `gmock`），如果找不到预编译的版本，则可以从源码构建。
4. **配置编译和链接参数:**  为每个检测到的依赖项设置 `compile_args` (编译参数) 和 `link_args` (链接参数)，以便在编译和链接 Frida Python 绑定时使用。
5. **处理可选依赖项:**  允许指定可选的依赖项，并在找不到时不会导致构建失败，例如 LLVM 的可选模块。
6. **处理不同操作系统:**  针对不同的操作系统（如 Linux、macOS、Windows）提供不同的检测和配置逻辑，例如查找库文件的路径和名称可能不同。
7. **版本控制:**  可以指定依赖项的版本要求，并在找到的版本不符合要求时报错。
8. **子依赖项管理:**  某些依赖项可能依赖于其他依赖项，例如 `GMockDependencySystem` 依赖于 `GTestDependencySystem` 和 `threads_factory`。
9. **日志记录:**  使用 `mlog` 模块记录依赖项检测的详细信息，用于调试。
10. **提供工厂函数:**  使用 `DependencyFactory` 创建依赖项的实例。

**与逆向方法的关联:**

这个文件本身并不直接实现逆向方法，但它配置了 Frida Python 绑定所需的依赖项，而 Frida 本身是一个强大的动态 instrumentation 工具，广泛用于软件逆向工程。

* **LLVM:**  Frida 的某些组件可能使用 LLVM 进行代码生成或分析，LLVM 是一个编译器基础设施项目，在逆向工程中常用于反汇编和中间表示分析。
* **GTest/GMock:** 这些是 C++ 的测试框架，用于测试 Frida 的 C++ 代码，确保 Frida 的核心功能在被 Python 绑定使用时是正确的。逆向工程师可能需要了解 Frida 的内部工作原理，因此了解其测试框架也有帮助。

**与二进制底层、Linux/Android 内核及框架的知识的关联:**

这个文件在多个方面涉及到二进制底层、Linux/Android 内核及框架的知识：

* **共享库后缀:** `get_shared_library_suffix` 函数根据目标机器的操作系统确定共享库的后缀（`.so`、`.dylib`、`.dll`），这直接涉及到不同操作系统下二进制文件的格式。
* **查找库文件:**  `find_library` 操作需要在文件系统中查找特定的二进制文件（共享库），这需要了解库文件的命名约定和搜索路径。
* **编译和链接参数:**  `compile_args` 和 `link_args` 直接传递给编译器和链接器，这些参数会影响最终生成的二进制文件的结构和依赖关系。例如，`-I` 用于指定头文件搜索路径，`-L` 用于指定库文件搜索路径，`-l` 用于指定要链接的库。
* **Linux 特有路径:**  `GTestDependencySystem` 中使用了 `/usr/src/gtest/src` 等 Linux 系统中常见的源码路径。
* **Android 特有逻辑:** `ZlibSystemDependency` 中包含了针对 Android 平台的特殊处理。
* **JNI (Java Native Interface):** `JNISystemDependency` 用于检测和配置 JNI，这涉及到 Java 虚拟机 (JVM) 的底层接口，允许 C/C++ 代码与 Java 代码交互。在 Android 上，Frida 经常用于 instrumentation Android 应用程序，而这些应用程序通常使用 Java 或 Kotlin 编写，并通过 Dalvik/ART 虚拟机运行。理解 JNI 是在 Android 上进行逆向分析的关键。
* **查找 `java_home`:** `JNISystemDependency` 需要确定 Java 开发工具包 (JDK) 的安装路径，这涉及到对操作系统文件系统结构的理解。
* **CPU 架构:** `JNISystemDependency.__cpu_translate` 函数处理 JDK 和 Meson 中 CPU 架构名称的差异，这与二进制兼容性有关。
* **平台特定的包含目录:** `JNISystemDependency.__machine_info_to_platform_include_dir` 函数根据操作系统确定 JNI 头文件的路径，这些头文件包含了与特定平台相关的 JNI 函数声明。

**逻辑推理的举例说明:**

* **假设输入:** 用户在 Linux 系统上构建 Frida Python 绑定，并且系统中没有安装预编译的 `gtest` 库。
* **代码逻辑:** `GTestDependencySystem` 的 `detect` 方法首先尝试使用 `clib_compiler.find_library("gtest", ...)` 查找预编译的库，如果找不到，则会进入 `detect_srcdir` 方法，检查 `/usr/src/gtest/src` 或 `/usr/src/googletest/googletest/src` 等目录是否存在 `gtest` 的源代码。
* **假设输出:** 如果找到源代码，`is_found` 被设置为 `True`，`compile_args` 被设置为包含头文件路径，`link_args` 为空，`sources` 被设置为 `gtest-all.cc` 等源文件，`prebuilt` 为 `False`。Meson 构建系统会指示编译器编译这些源文件来构建 `gtest`。

**涉及用户或编程常见的使用错误，举例说明:**

1. **缺失依赖项:** 如果用户尝试构建 Frida Python 绑定，但系统中缺少某个必需的依赖项（例如，没有安装 LLVM 或 pkg-config），则相应的依赖项检测类会设置 `is_found` 为 `False`，导致 Meson 构建失败并显示错误消息。
    * **用户操作:**  运行 `meson setup build` 或 `ninja` 命令。
    * **错误:** Meson 报告找不到依赖项，例如 "Could not find dependency LLVM"。

2. **版本不匹配:** 用户可能安装了某个依赖项，但版本不符合 Frida 的要求。
    * **用户操作:**  系统上安装了 LLVM 10，但 Frida 需要 LLVM 7 或更高版本，但某些特性可能只在特定版本中可用。
    * **代码逻辑:** 像 `LLVMDependencyConfigTool` 这样的类会使用 `version_compare` 函数来检查版本，如果版本不匹配，可能会设置 `is_found` 为 `False` 或发出警告。
    * **错误:**  可能在配置阶段或编译阶段出现错误，指出版本不兼容。

3. **错误的依赖项配置:** 用户可能手动配置了某些环境变量或使用了不正确的 Meson 选项，导致依赖项检测失败或使用了错误的库。
    * **用户操作:**  错误设置了 `PKG_CONFIG_PATH` 环境变量，导致 `PkgConfigDependency` 找不到正确的 `.pc` 文件。
    * **代码逻辑:**  依赖项检测类依赖于系统环境和 Meson 的配置。错误的配置可能会导致检测逻辑失败。

4. **在不支持的平台上构建:**  某些依赖项或其检测方法可能只在特定的操作系统上有效。
    * **用户操作:**  尝试在某个非常规的操作系统上构建 Frida，而该操作系统没有针对特定依赖项的检测逻辑。
    * **代码逻辑:**  依赖项检测类中的操作系统检查 (`m.is_linux()`, `m.is_darwin()`, 等) 会导致某些代码分支不被执行。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当用户尝试构建 Frida Python 绑定时，Meson 构建系统会执行以下步骤，最终会执行到 `dev.py` 中的代码：

1. **运行 Meson 配置:** 用户在项目根目录下运行 `meson setup <build_directory>` 命令。
2. **读取 `meson.build` 文件:** Meson 解析项目根目录下的 `meson.build` 文件，该文件描述了项目的构建结构和依赖关系。
3. **处理依赖项声明:**  `meson.build` 文件中可能包含 `dependency()` 函数调用，用于声明项目所需的外部依赖项，例如 `dependency('gtest')` 或 `dependency('llvm', modules: ['Core', 'Analysis'])`。
4. **调用依赖项工厂:**  Meson 根据依赖项的名称查找对应的 `DependencyFactory` 实例（例如，`packages['gtest']` 或 `packages['llvm']`）。
5. **实例化依赖项对象:**  `DependencyFactory` 根据配置的检测方法（`DependencyMethods.PKGCONFIG`, `DependencyMethods.SYSTEM`, `DependencyMethods.CMAKE` 等）尝试实例化相应的依赖项类（例如，`GTestDependencyPC`, `GTestDependencySystem`, `LLVMDependencyCMake`, `LLVMDependencyConfigTool`）。这些类在 `dev.py` 中定义。
6. **执行检测逻辑:**  实例化的依赖项对象的 `__init__` 方法和 `detect` 方法会被调用，执行在 `dev.py` 中定义的依赖项检测逻辑，例如查找库文件、头文件、运行 `pkg-config` 或 `llvm-config` 命令。
7. **收集编译和链接参数:**  如果依赖项被成功检测到，其 `compile_args` 和 `link_args` 属性会被设置。
8. **Meson 构建图:**  Meson 将所有依赖项的信息添加到构建图中，用于后续的编译和链接过程。
9. **运行构建命令:** 用户运行 `ninja` 或 `meson compile` 命令来执行实际的编译和链接操作。
10. **使用依赖项信息:**  在编译和链接 Frida Python 绑定时，Meson 会使用之前收集到的依赖项的编译和链接参数，确保编译器和链接器能够找到所需的库和头文件。

**作为调试线索:**

当构建过程中出现依赖项相关的问题时，了解上述步骤可以帮助用户进行调试：

* **查看 Meson 日志:** Meson 会生成详细的日志，其中包含了依赖项检测的输出。查看日志可以了解哪些依赖项被找到，哪些没有找到，以及检测过程中执行的命令和输出。
* **检查 `dev.py` 代码:** 如果怀疑是特定的依赖项检测逻辑有问题，可以直接查看 `dev.py` 中对应依赖项类的代码，了解其检测方法和逻辑。
* **手动执行检测命令:**  可以尝试手动执行 `dev.py` 中使用的检测命令（例如 `pkg-config --cflags gtest` 或 `llvm-config --libs`)，以验证这些命令是否按预期工作。
* **检查系统环境:**  确认相关的环境变量（例如 `PKG_CONFIG_PATH`, `JAVA_HOME`) 是否已正确设置。
* **隔离问题:**  如果构建失败，可以尝试单独测试某个依赖项的检测，以确定问题的具体来源。

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/dev.py` 是 Frida Python 绑定构建过程中的一个关键文件，它负责定义和检测各种构建依赖项，并提供了必要的编译和链接信息。理解这个文件的功能和逻辑对于理解 Frida 的构建过程以及解决构建问题至关重要，特别是对于那些涉及到逆向工程、二进制底层和操作系统特性的依赖项。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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