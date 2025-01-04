Response:
Let's break down the thought process for analyzing this Python code and addressing the user's request.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the provided Python code snippet. The code is identified as part of the Frida dynamic instrumentation tool and specifically deals with dependency management within the Meson build system. The user also wants to know its relevance to reverse engineering, low-level details, logic, potential errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick scan for recognizable keywords and patterns. This helps establish the general purpose of the code. Keywords like `Dependency`, `PkgConfigDependency`, `CMakeDependency`, `SystemDependency`, `find_library`, `has_header`, `compile_args`, `link_args`,  `version_compare`, and names like `gtest`, `gmock`, `llvm`, `zlib`, and `jni` immediately jump out. These suggest that the code is about finding and configuring external libraries required for the Frida build.

**3. Deconstructing the Code by Class:**

A natural way to understand the code's structure is to examine each class definition.

* **`get_shared_library_suffix`:** This is a utility function, not a dependency. It's straightforward: determine the shared library extension based on the operating system.

* **`GTestDependencySystem`, `GTestDependencyPC`:** These deal with the Google Test framework. The "System" version tries to find it as a system library or build it from source. The "PC" version uses `pkg-config`.

* **`GMockDependencySystem`, `GMockDependencyPC`:** Similar to GTest, but for Google Mock. It also has logic to handle the dependency on GTest.

* **`LLVMDependencyConfigTool`, `LLVMDependencyCMake`:** These are more complex and handle the LLVM compiler infrastructure. They use both `llvm-config` (a tool provided by LLVM) and CMake to find and configure LLVM.

* **`ValgrindDependency`:**  Deals with the Valgrind memory debugging tool, primarily focusing on compiler flags.

* **`ZlibSystemDependency`:**  Manages the zlib compression library, with platform-specific logic.

* **`JNISystemDependency`, `JDKSystemDependency`:**  Handle the Java Native Interface (JNI) and Java Development Kit (JDK) dependencies.

* **`DependencyFactory`:** This is a helper class for registering and selecting dependency implementations.

**4. Identifying Core Functionality:**

After examining the classes, the core functionality becomes clear:

* **Dependency Detection:** The code aims to locate required external libraries (like GTest, GMock, LLVM, zlib, JDK/JNI) on the system.
* **Configuration:**  Once a dependency is found, the code extracts necessary compiler flags (include paths, defines) and linker flags (library paths, library names).
* **Multiple Detection Methods:**  It employs different methods for finding dependencies: system libraries, `pkg-config`, CMake, and specific configuration tools (`llvm-config`).
* **Version Handling:**  It includes logic for checking dependency versions.
* **Platform Awareness:**  The code has platform-specific logic (e.g., for macOS, Windows, Linux) in how it finds libraries and determines compiler/linker flags.
* **Source Building:**  For some dependencies (like GTest and GMock), it can build them from source if pre-built versions aren't found.

**5. Connecting to Reverse Engineering:**

This requires thinking about how Frida is used in reverse engineering. Frida *instruments* processes, meaning it injects code into running applications to observe and modify their behavior. This requires:

* **Compilation:** Frida itself needs to be compiled. The dependencies managed by this code are crucial for that compilation.
* **Low-Level Interaction:**  Frida often interacts with system APIs and libraries. Libraries like LLVM (for its compiler infrastructure) and zlib (potentially for data handling) are relevant.
* **Platform Support:** Frida needs to run on various platforms, so handling platform-specific dependencies is vital.

**6. Identifying Low-Level/Kernel/Framework Connections:**

This involves recognizing libraries and concepts related to operating systems and low-level programming:

* **Shared Libraries (.so, .dll, .dylib):** The code explicitly deals with finding these, which are fundamental to how programs are loaded and linked in operating systems.
* **System Libraries:** The concept of system dependencies inherently involves interacting with the operating system's library management.
* **Kernel (Indirectly):** While this code doesn't directly interact with the kernel, dependencies like zlib might be used by kernel modules or system-level components. JNI directly bridges managed Java code with native (potentially kernel-interacting) code.
* **Android Framework (Indirectly):** The inclusion of JNI is a strong indicator of potential Android support, as JNI is heavily used in the Android framework.

**7. Logical Inference (Hypothetical Input/Output):**

This involves choosing a specific dependency and tracing its logic. For example, for `GTestDependencySystem`:

* **Input (Hypothetical):** Meson build system needs the `gtest` dependency, and the `main` option is set to `True`.
* **Process:** The code first checks for pre-built libraries (`libgtest.so`, `libgtest_main.so`). If not found, it looks for source directories (`/usr/src/gtest/src`, etc.). If source is found, it determines include paths and source files.
* **Output (Hypothetical):** If pre-built libraries are found, `self.is_found` is `True`, and `self.link_args` will contain the library names. If built from source, `self.is_found` is `True`, `self.compile_args` has include paths, and `self.sources` lists the source files.

**8. Common Usage Errors:**

This requires thinking about what could go wrong when a user is trying to build software with dependencies:

* **Missing Dependencies:** The most common error. The required library or tool isn't installed.
* **Incorrect Versions:** The installed version of a dependency doesn't match the required version.
* **Incorrect Environment:**  Environment variables (like `JAVA_HOME`) might be set incorrectly.
* **Conflicting Dependencies:** Different libraries might conflict with each other.

**9. Tracing User Actions (Debugging Clues):**

This involves thinking about how a user's actions in the build process lead to this code being executed:

* **`meson` command:** The user runs the `meson` command to configure the build.
* **`dependency()` function:**  The `meson.build` file likely contains calls to the `dependency()` function, specifying the required libraries (e.g., `dependency('gtest')`, `dependency('llvm', modules: ['Core', 'Analysis'])`).
* **Dependency Resolution:** Meson then uses the `DependencyFactory` and the specific dependency classes in this Python file to try and find the dependencies.
* **Error Messages:** If a dependency isn't found, Meson will report an error, potentially providing clues about why (e.g., "Could not find gtest").

**10. Structuring the Answer:**

Finally, the information needs to be organized logically and clearly, using headings and bullet points to improve readability. The examples should be concrete and illustrative. The explanation should flow from general concepts to specific details.

This step-by-step process of analyzing the code, connecting it to the broader context of Frida and reverse engineering, and considering potential user interactions is crucial for generating a comprehensive and helpful answer.
这个 Python 源代码文件 `dev.py` 是 Frida 动态 instrumentation工具的构建系统 Meson 的一部分，负责处理项目构建过程中开发依赖项的管理和查找。它定义了一系列用于检测和配置各种开发库（如 GTest, GMock, LLVM, Zlib, JNI 等）的类和方法。

以下是其主要功能和与逆向方法、二进制底层、Linux/Android 内核及框架知识的关系：

**1. 依赖项检测与配置:**

*   **目的:**  该文件的核心功能是自动化地在构建环境中查找并配置项目所需的各种开发依赖库。这些库通常在编译、链接阶段被使用。
*   **方法:**  它尝试多种方法来定位依赖项，包括：
    *   **系统路径查找 (`SystemDependency`):**  直接在标准系统路径下查找库文件或头文件。
    *   **Pkg-config (`PkgConfigDependency`):**  使用 `pkg-config` 工具来获取库的编译和链接参数。
    *   **CMake (`CMakeDependency`):**  利用 CMake 的 `find_package` 功能来查找库，并解析 CMake 导出的配置信息。
    *   **配置工具 (`ConfigToolDependency`):**  使用特定于库的配置工具（如 LLVM 的 `llvm-config`）来获取编译和链接参数。
*   **功能细化:**  针对不同的库，它有特定的检测逻辑，例如：
    *   **GTest/GMock:**  既能查找预编译的库，也能检测源代码路径并配置为从源代码构建。
    *   **LLVM:**  能处理不同版本的 LLVM，并能根据用户指定的模块进行查找。
    *   **Zlib:**  根据操作系统平台选择不同的查找策略。
    *   **JNI/JDK:**  查找 Java Development Kit，并能根据指定的模块（如 `jvm`, `awt`）查找相应的库。

**与逆向方法的关联及举例:**

*   **GTest/GMock:**  Frida 本身以及使用 Frida 的项目经常会编写单元测试。GTest 和 GMock 是 C++ 中流行的测试框架。因此，Frida 的构建过程需要能够找到这些测试框架以便进行测试。
    *   **举例:**  Frida 的开发者在编写新的核心功能后，可能会使用 GTest 编写单元测试来验证其正确性。Meson 构建系统通过 `dev.py` 找到 GTest，然后将 GTest 的头文件路径添加到编译器的包含路径中，并将 GTest 的库文件添加到链接器的库路径中，以便编译和链接测试代码。
*   **LLVM:**  LLVM 是一个强大的编译器基础设施，Frida 的一些组件（例如，用于代码生成或优化的部分）可能会使用 LLVM 的库。
    *   **举例:**  如果 Frida 的某个模块需要动态生成机器码，它可能会使用 LLVM 的 API。`dev.py` 中关于 `LLVMDependency` 的代码负责找到 LLVM 的头文件和库文件，确保 Frida 在编译时能够使用 LLVM 提供的功能。
*   **JNI:** Frida 提供了 Java 绑定，允许在 Java 环境中使用 Frida。这需要 JNI 来连接 Java 代码和 Frida 的原生代码。
    *   **举例:**  一个使用 Frida 的 Android 逆向工具可能会用 Java 编写界面，并使用 Frida 的 JNI 绑定来注入和控制 Android 进程。`dev.py` 中关于 `JNISystemDependency` 的代码负责找到 JDK，并获取编译和链接 JNI 代码所需的头文件和库文件。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例:**

*   **共享库后缀 (`get_shared_library_suffix`):**  该函数根据目标操作系统确定共享库文件的后缀名 (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows)。这是操作系统加载和链接二进制文件的基础知识。
    *   **举例:**  在链接 Frida 的组件时，链接器需要知道库文件的正确名称。`get_shared_library_suffix` 确保在不同的操作系统上使用正确的库文件后缀。
*   **查找库文件 (`find_library`):**  `SystemDependency` 类使用编译器提供的 `find_library` 方法在系统路径下查找库文件。这涉及到操作系统库加载路径的知识。
    *   **举例:**  在 Linux 上，编译器可能会搜索 `/lib`, `/usr/lib`, `/usr/local/lib` 等标准路径来查找 GTest 的库文件 `libgtest.so`。
*   **头文件路径 (`-I` 参数):**  代码中会设置编译器的头文件包含路径，以便编译器能够找到依赖库的头文件。这对于使用库的 API 是必要的。
    *   **举例:**  在找到 GTest 的头文件后，`dev.py` 可能会将类似 `-I/usr/include/gtest` 的参数添加到编译命令中。
*   **链接参数 (`-l`, `-L` 参数):**  代码会设置链接器的链接参数，指定要链接的库以及库文件所在的目录。
    *   **举例:**  找到 GTest 的库文件后，`dev.py` 可能会添加 `-lgtest` (链接 `libgtest.so`) 和 `-L/usr/lib` (如果库文件在 `/usr/lib` 中) 到链接命令中。
*   **JNI 和 Android:** `JNISystemDependency` 类需要查找 JDK，这与 Java 虚拟机在不同操作系统上的安装和路径有关。对于 Android，JNI 是连接 Java 层和 Native 层的关键技术。
    *   **举例:**  在 Android 上构建使用 Frida Java 绑定的代码时，`dev.py` 需要找到 Android SDK 中的 JDK，并配置 JNI 相关的编译和链接参数，以便生成能与 Android 运行时环境交互的 Native 代码。

**逻辑推理及假设输入与输出:**

以 `GTestDependencySystem` 为例：

*   **假设输入:**
    *   构建系统需要 `gtest` 依赖。
    *   `kwargs` 中 `main` 参数为 `True` (表示需要 `gtest_main` 库)。
    *   系统上没有预编译的 `libgtest.so` 和 `libgtest_main.so`。
    *   系统在 `/usr/src/gtest/src` 存在 GTest 的源代码。
*   **逻辑推理:**
    1. 检测到 `main` 为 `True`。
    2. 尝试查找预编译的 `libgtest.so` 和 `libgtest_main.so`，失败。
    3. 检测到源代码路径 `/usr/src/gtest/src` 存在。
    4. 设置 `self.is_found` 为 `True`。
    5. 设置编译参数 `self.compile_args`，包含 GTest 源代码的头文件路径。
    6. 设置链接参数 `self.link_args` 为空，因为将从源代码构建。
    7. 设置源文件 `self.sources`，包含 `gtest-all.cc` 和 `gtest_main.cc`。
    8. 设置 `self.prebuilt` 为 `False`。
*   **假设输出:**
    *   `self.is_found` 为 `True`。
    *   `self.compile_args` 包含类似 `['-I/usr/src/gtest/include', '-I/usr/src/gtest']` 的路径。
    *   `self.link_args` 为 `[]`。
    *   `self.sources` 包含 GTest 的源文件对象。
    *   `self.prebuilt` 为 `False`。

**用户或编程常见的使用错误及举例:**

*   **依赖库未安装:**  用户在构建 Frida 时，如果系统中缺少某些必要的开发库（例如，没有安装 GTest 的开发包），`dev.py` 可能会找不到这些库，导致构建失败。
    *   **举例:**  用户在 Linux 上构建 Frida，但没有安装 `libgtest-dev` 包。`GTestDependencySystem` 无法找到 `libgtest.so` 和头文件，最终 `self.is_found` 为 `False`，Meson 会报告找不到 GTest 的错误。
*   **依赖库版本不兼容:**  用户安装了旧版本或不兼容版本的依赖库，可能导致编译或链接错误。
    *   **举例:**  Frida 的某个版本可能需要特定版本的 LLVM。如果用户安装的 LLVM 版本过低，`LLVMDependencyConfigTool` 的版本比较逻辑 (`version_compare`) 可能会检测到版本不匹配，导致构建失败。
*   **环境变量未设置或设置错误:**  某些依赖库的查找可能依赖于特定的环境变量。如果用户没有正确设置这些环境变量，`dev.py` 可能无法找到依赖库。
    *   **举例:**  `JNISystemDependency` 可能会依赖 `JAVA_HOME` 环境变量来定位 JDK 的安装路径。如果用户没有设置 `JAVA_HOME` 或设置的路径不正确，`dev.py` 将无法找到 JDK，导致与 Java 相关的组件构建失败。
*   **指定了错误的依赖模块:**  对于像 LLVM 这样的库，用户可能需要在 `meson.build` 文件中指定所需的模块。如果指定了不存在的模块，`LLVMDependencyConfigTool` 的 `check_components` 方法会检测到并报错。
    *   **举例:**  用户在 `meson.build` 中指定 `dependency('llvm', modules: ['NonExistentModule'])`，`check_components` 发现 `NonExistentModule` 不存在于 LLVM 提供的模块列表中，会设置 `self.is_found` 为 `False` 并抛出异常。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户执行 `meson setup build` 或 `meson` 命令:** 这是启动 Meson 构建系统的第一步，Meson 会读取项目根目录下的 `meson.build` 文件。
2. **`meson.build` 文件中声明了依赖项:**  `meson.build` 文件中会使用 `dependency()` 函数来声明项目所需的外部依赖项，例如 `dependency('gtest')`, `dependency('llvm', modules: ['Core'])`, `dependency('jni')` 等。
3. **Meson 解析 `meson.build` 文件:** Meson 会解析 `meson.build` 文件，并识别出声明的依赖项。
4. **Meson 调用相应的依赖查找逻辑:**  对于每个声明的依赖项，Meson 会根据依赖项的名称查找对应的处理类。对于像 `gtest`, `llvm`, `jni` 这样的依赖项，Meson 会调用 `frida/subprojects/frida-qml/releng/meson/mesonbuild/dependencies/dev.py` 文件中定义的相应类（例如 `GTestDependencySystem`, `LLVMDependencyConfigTool`, `JNISystemDependency`）。
5. **`dev.py` 中的类执行依赖查找:**  这些类会根据自身的逻辑（例如，查找系统路径、调用 `pkg-config`、执行 `llvm-config` 等）来尝试找到依赖项。
6. **依赖查找结果返回给 Meson:**  `dev.py` 中的类会将依赖查找的结果（是否找到、编译参数、链接参数等）返回给 Meson。
7. **Meson 根据依赖查找结果生成构建文件:**  Meson 根据依赖查找的结果以及其他构建配置信息，生成底层的构建文件（例如，Makefile 或 Ninja build 文件）。

**作为调试线索:**

当用户在构建 Frida 时遇到依赖问题时，了解 `dev.py` 的工作原理可以帮助定位问题：

*   **构建失败信息:**  查看 Meson 的构建失败信息，通常会指示哪个依赖项没有找到或配置错误。
*   **检查 `dev.py` 中的查找逻辑:**  根据失败信息中的依赖项名称，可以查看 `dev.py` 中对应依赖类的查找逻辑，例如，检查它搜索的路径、调用的命令以及预期的输出。
*   **验证系统环境:**  检查系统中是否安装了所需的依赖库及其开发包，版本是否符合要求，相关的环境变量是否设置正确。
*   **手动执行查找命令:**  可以尝试手动执行 `dev.py` 中使用的查找命令（例如，`pkg-config --cflags gtest`, `llvm-config --cxxflags`)，查看输出结果，判断是否能正确找到依赖项。
*   **修改 `dev.py` (临时调试):**  在调试阶段，可以临时修改 `dev.py` 中的打印语句或查找路径，以便更详细地了解依赖查找的过程。但这不建议作为长期解决方案。

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/dependencies/dev.py` 是 Frida 构建系统的核心组件，负责自动化地管理和查找各种开发依赖项，这对于确保 Frida 能够在不同的平台上正确编译和链接至关重要。理解其功能和实现细节对于调试 Frida 的构建问题非常有帮助，尤其是在涉及到与操作系统底层、内核、框架交互的依赖项时。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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