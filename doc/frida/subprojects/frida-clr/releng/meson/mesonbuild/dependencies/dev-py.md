Response:
Let's break down the request and the provided Python code to understand how to generate the desired explanation.

**1. Understanding the Goal:**

The request asks for an analysis of a Python file (`dev.py`) within the Frida project. The analysis needs to cover several aspects:

* **Functionality:** What does the code do?
* **Relevance to Reverse Engineering:** How does it relate to the techniques used in reverse engineering?
* **Low-Level Details:** Does it interact with the binary level, Linux/Android kernel/frameworks?
* **Logic and Inference:** Are there conditional statements or logical deductions?  Provide examples.
* **Common Usage Errors:** What mistakes could developers make when using this code?
* **User Journey:** How does a user's interaction lead to this specific code being executed?

**2. Initial Code Examination:**

The code defines various dependency-related classes and functions. It's part of Meson's build system and focuses on finding and configuring external libraries or components needed for a build. Key observations:

* **Dependency Management:**  The core purpose is managing dependencies like `gtest`, `gmock`, `llvm`, `zlib`, and `jni`.
* **Multiple Detection Methods:** For each dependency, it tries different ways to find it: system-wide libraries, `pkg-config`, CMake, or even building from source.
* **Build System Integration:** It's tightly integrated with Meson, using Meson's classes and functions.
* **Cross-Compilation Awareness:**  The code considers different target machines (Windows, macOS, Linux, etc.) and CPU architectures.
* **Compiler Interaction:** It interacts with compilers (C, C++, Java) to find libraries, headers, and compiler/linker flags.

**3. Addressing the Specific Questions:**

* **Functionality:**  The primary function is to provide a structured way for Meson to find and configure dependencies needed for building Frida or related projects. Each dependency class (`GTestDependencySystem`, `LLVMDependencyConfigTool`, etc.) implements logic to locate and extract necessary information (include paths, library paths, link arguments) for a specific dependency.

* **Reverse Engineering Relevance:** This is where the connection to Frida becomes important. Frida is a dynamic instrumentation toolkit used *extensively* in reverse engineering. While this specific *build* code doesn't directly perform reverse engineering, it sets up the environment necessary to *build* Frida. The dependencies it manages (like LLVM) are crucial for Frida's internal workings, which *are* used for reverse engineering.

* **Binary/Kernel/Frameworks:** The `jni` dependency directly interacts with the Java Virtual Machine. Finding the JVM, its libraries (`jvm.dll`, `libjvm.so`), and header files (`jni.h`) involves understanding the underlying operating system's structure for Java installations. While it doesn't directly manipulate the kernel, finding system libraries on Linux and Android involves knowledge of standard locations (`/usr/lib`, `/system/lib`, etc.).

* **Logic and Inference:**  The code is full of conditional logic:
    * Checking for the existence of files and directories (`os.path.exists`).
    * Comparing versions (`version_compare`).
    * Using `if/elif/else` to choose different dependency detection methods.
    * Example:  For `GTestDependencySystem`, it first tries to find pre-built libraries (`find_library`), and if that fails, it looks for source code.

* **Common Usage Errors:** Users interacting with Meson (Frida developers) might make mistakes in their `meson.build` files when declaring dependencies:
    * Incorrect dependency names.
    * Specifying wrong versions.
    * Forgetting to install necessary dependency packages on their system.
    * Misconfiguring environment variables (like `JAVA_HOME`).

* **User Journey:**  A developer wanting to build Frida would:
    1. Clone the Frida repository.
    2. Run `meson setup build` (or similar Meson command).
    3. Meson would parse the `meson.build` files.
    4. When it encounters a `dependency()` call for, say, `gtest`, it would delegate to the appropriate dependency factory (`gtest_factory`).
    5. The factory would try the registered methods (PkgConfig, System).
    6. The code in `dev.py` (like `GTestDependencyPC` or `GTestDependencySystem`) would be executed to find the GTest dependency.

**4. Structuring the Explanation:**

Organize the explanation into clear sections corresponding to the prompt's questions. Use examples where appropriate. Highlight the connections to reverse engineering and low-level details when they exist.

**5. Refining the Explanation (Self-Correction):**

* **Initial thought:** Focus solely on the direct actions of the code.
* **Correction:**  Recognize the broader context of Frida and reverse engineering. While the code itself isn't performing reverse engineering, it's *essential* for building the tools that do.
* **Initial thought:**  List every single function and class.
* **Correction:** Focus on the main functionalities and provide representative examples of different dependency types. Don't need to explain every single line of code.
* **Initial thought:**  Assume advanced knowledge of Meson.
* **Correction:** Provide some context about Meson's role as a build system.

By following this thought process, systematically analyzing the code, and focusing on the specific requirements of the prompt, we can construct a comprehensive and informative explanation.
This Python file, `dev.py`, is a crucial part of Frida's build system, specifically within the Meson build environment. Its primary function is to **define how Frida finds and integrates its dependencies**. It acts as a central registry and logic hub for locating various external libraries and components required to build Frida.

Here's a breakdown of its functionalities:

**1. Dependency Detection and Configuration:**

* **Defines Dependency Classes:**  It contains classes like `GTestDependencySystem`, `LLVMDependencyConfigTool`, `JNISystemDependency`, etc. Each class is responsible for detecting and configuring a specific dependency (e.g., Google Test, LLVM, Java Development Kit).
* **Multiple Detection Methods:** For each dependency, it often defines multiple ways to find it (e.g., using `pkg-config`, searching system paths, using CMake, or even building from source). This makes the build process more robust across different operating systems and configurations.
* **Provides Dependency Information:** Once a dependency is found, these classes extract crucial information like include paths, library paths, compiler flags, and linker flags. This information is then used by Meson to correctly compile and link Frida.
* **Handles Optional Dependencies:**  The code also manages optional dependencies, meaning the build can proceed even if certain libraries are not found (though some features might be disabled).
* **Version Handling:**  It includes logic to check for specific versions of dependencies and handle compatibility issues.

**2. Abstraction and Organization:**

* **Centralized Dependency Management:** This file centralizes the logic for finding dependencies, making the overall build system cleaner and easier to maintain.
* **Factory Pattern:** The use of `DependencyFactory` allows for a structured way to register and retrieve dependency classes based on the detection methods available.
* **Consistent Interface:**  The base class `SystemDependency` and its subclasses provide a consistent interface for Meson to interact with different types of dependencies.

**3. Platform Awareness:**

* **Operating System Specific Logic:**  The code often contains conditional logic based on the target operating system (e.g., Windows, macOS, Linux, Android). This is necessary because dependency locations and naming conventions vary across platforms.
* **Architecture Awareness:**  In some cases, like with LLVM, it considers the target architecture (32-bit or 64-bit) to locate the correct tools.

**Relationship to Reverse Engineering:**

This file is indirectly related to reverse engineering by ensuring that Frida, a powerful reverse engineering tool, can be built correctly. The dependencies it manages are essential for Frida's functionality:

* **LLVM:** Frida uses LLVM's compiler infrastructure for its instrumentation engine (DynamoRIO is an alternative). LLVM allows Frida to analyze and modify the target process's code at runtime. Finding and configuring LLVM correctly is crucial.
    * **Example:**  The `LLVMDependencyConfigTool` class uses `llvm-config` to get the necessary compiler and linker flags for building against LLVM. This ensures that Frida's core components can interact with LLVM's libraries.
* **Google Test (gtest) and Google Mock (gmock):** These are testing frameworks used to write and run unit tests for Frida's code. While not directly used in the end-user's reverse engineering process, they are vital for development and ensuring the stability of Frida.
    * **Example:**  The `GTestDependencySystem` class might look for pre-built gtest libraries or build it from source if necessary. If found, it provides the include paths and link arguments so that Frida's tests can be compiled and linked against gtest.
* **Java Development Kit (JDK/JNI):** Frida has capabilities to interact with Java applications on Android. The `JNISystemDependency` class handles finding the JDK and its Native Interface (JNI) libraries.
    * **Example:** When instrumenting an Android app, Frida needs to interact with the Dalvik/ART runtime, which is based on Java. This dependency ensures that Frida can compile and link against the necessary JNI headers and libraries to communicate with the Java environment.

**Binary 底层 (Binary Low-Level):**

While the Python code itself doesn't directly manipulate bits and bytes, it facilitates the building of components that do:

* **Compiler and Linker Flags:** The extracted information (compile args, link args) is directly passed to the C/C++ compiler and linker. These tools operate at the binary level, generating machine code and linking it together.
    * **Example:** The `LLVMDependencyConfigTool` retrieves flags like `-I/path/to/llvm/include` (include directory) and `-L/path/to/llvm/lib -lLLVM` (library path and library name). These flags tell the compiler and linker where to find the LLVM headers and libraries, which are binary files.
* **Shared Libraries (.so, .dylib, .dll):** The code deals with finding and linking against shared libraries. These are binary files containing compiled code that can be loaded at runtime.
    * **Example:** The `get_shared_library_suffix` function determines the appropriate file extension for shared libraries based on the operating system. This is a fundamental concept in binary execution.

**Linux, Android 内核及框架 (Linux, Android Kernel and Framework):**

* **System Library Paths:** The code searches standard system paths for libraries, which is relevant to both Linux and Android.
    * **Example:**  The `GTestDependencySystem` looks in `/usr/src/gtest/src` and `/usr/src/googletest/googletest/src`, which are common locations for development headers on Linux.
* **Android Specific Logic:** The `JNISystemDependency` has specific logic for finding the JDK on Android, which involves understanding the Android file system structure.
    * **Example:** The code might need to check environment variables or specific locations within the Android SDK to locate the necessary Java components.
* **Java Native Interface (JNI):**  The `JNISystemDependency` directly deals with JNI, which is the mechanism for native code (like Frida's core) to interact with the Java Virtual Machine used in Android's framework.

**逻辑推理 (Logical Reasoning):**

The code is full of logical reasoning, primarily in the form of conditional checks and decisions:

* **Dependency Existence:**  `if os.path.exists(s):` checks if a directory exists before attempting to use it.
    * **假设输入:** `s` is "/usr/lib/libgtest.so"
    * **输出:** If the file exists, the code proceeds to use it; otherwise, it might try another method to find gtest.
* **Version Comparison:** `if version_compare(self.version, '>= 3.9'):` compares the version of a dependency to make decisions about how to configure it.
    * **假设输入:** `self.version` is "3.8", the comparison string is ">= 3.9"
    * **输出:** The condition is false, and the code might execute a different block of instructions designed for older versions.
* **Operating System Checks:** `if m.is_windows():` branches the logic based on the target operating system.
    * **假设输入:** The target machine `m` is a Windows machine.
    * **输出:** The code within the `if` block, which handles Windows-specific dependency locations and conventions, will be executed.
* **Module Existence (LLVM):** The `LLVMDependencyConfigTool` checks if required LLVM modules are present.
    * **假设输入:** `kwargs['modules']` contains `['core', 'bitwriter']`, and the output of `llvm-config --components` includes both "core" and "bitwriter".
    * **输出:** The dependency is considered found, and these modules will be linked against.

**用户或编程常见的使用错误 (Common User or Programming Errors):**

* **Missing Dependencies:** Users might encounter errors if the required dependencies are not installed on their system.
    * **Example:** If a user tries to build Frida without LLVM installed, the `LLVMDependencyConfigTool` will likely fail to find `llvm-config`, leading to a build error. Meson will typically report that the dependency "llvm" was not found.
    * **Debugging Clue:** The error message from Meson would indicate a missing dependency. Users would need to install the corresponding development packages (e.g., `llvm-dev` on Debian/Ubuntu).
* **Incorrect Dependency Versions:**  Specifying an incorrect version requirement in the `meson.build` file can lead to build failures.
    * **Example:** If `meson.build` requires `llvm >= 9.0`, but the system has LLVM 8.0 installed, the version comparison logic in `LLVMDependencyConfigTool` will likely fail.
    * **Debugging Clue:**  Meson might report a version mismatch error for the "llvm" dependency. Users would need to either update their LLVM installation or adjust the version requirement in `meson.build`.
* **Misconfigured Environment Variables (e.g., `JAVA_HOME`):** For dependencies like the JDK, environment variables play a crucial role.
    * **Example:** If the `JAVA_HOME` environment variable is not set or points to an invalid Java installation, the `JNISystemDependency` might fail to locate the necessary Java headers and libraries.
    * **Debugging Clue:** Meson might report that the "jni" dependency was not found or that it couldn't locate the JDK. Users would need to correctly configure the `JAVA_HOME` environment variable.
* **Conflicting Dependencies:**  In rare cases, different dependencies might conflict with each other. While this file tries to manage dependencies, complex scenarios can arise.
    * **Example:**  Two libraries might provide the same symbols, leading to linker errors.
    * **Debugging Clue:** Linker errors during the build process would be a sign of potential conflicts.

**用户操作如何一步步的到达这里 (How User Operations Lead Here):**

The execution of this `dev.py` file is triggered as part of the Meson build process. Here's a typical sequence:

1. **User Obtains Frida Source Code:** The user downloads or clones the Frida repository.
2. **User Navigates to the Frida Directory:** The user opens a terminal and changes the directory to the root of the Frida source code.
3. **User Initiates Meson Configuration:** The user runs a command like `meson setup builddir` (where `builddir` is the name of the build directory).
4. **Meson Parses `meson.build` Files:** Meson reads and parses the `meson.build` files in the Frida project. These files describe the project's structure, source files, and dependencies.
5. **Dependency Declaration:** When Meson encounters a `dependency('name')` call in a `meson.build` file (e.g., `dependency('llvm')`), it needs to find and configure that dependency.
6. **Dependency Factory Lookup:** Meson uses the `DependencyFactory` (defined in this `dev.py` file) to find the appropriate dependency class for the given name. For example, `dependency('llvm')` would lead to the `llvm_factory`.
7. **Dependency Detection Methods:** The factory then iterates through the registered detection methods for that dependency (e.g., CMake, Config Tool for LLVM).
8. **Execution of Dependency Class Logic:**  The corresponding dependency class (e.g., `LLVMDependencyCMake` or `LLVMDependencyConfigTool`) defined in `dev.py` is instantiated and its `__init__` method is executed. This is where the logic for finding the dependency on the user's system is implemented.
9. **Dependency Information Retrieval:** The dependency class attempts to locate the dependency using its defined methods (e.g., running `llvm-config`, using `pkg-config`, or searching for CMake configuration files).
10. **Providing Information to Meson:**  If the dependency is found, the dependency class provides Meson with the necessary include paths, library paths, compiler flags, and linker flags.
11. **Meson Uses Dependency Information:** Meson uses this information to generate the final build system files (e.g., Makefiles or Ninja files).
12. **User Initiates Compilation:** The user then runs a command like `meson compile -C builddir` or `ninja -C builddir` to start the actual compilation process. The compiler and linker use the information gathered by the dependency classes in `dev.py`.

In essence, this `dev.py` file is executed during the *configuration* phase of the Meson build process, well before the actual compilation of Frida's source code begins. It's a foundational step that ensures all the necessary building blocks are in place.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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