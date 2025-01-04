Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request is to understand the *functionality* of the provided Python file (`dev.py`) within the context of the Frida dynamic instrumentation tool. Specifically, it asks for connections to reverse engineering, low-level details, logic, potential errors, and how a user might reach this code.

2. **Initial Scan for Clues:**  Read through the code, looking for keywords, class names, function names, and comments that provide hints about its purpose. Some immediate observations:
    * Lots of `Dependency` classes (e.g., `GTestDependencySystem`, `LLVMDependencyConfigTool`). This strongly suggests the file deals with managing external library dependencies.
    * Mentions of `mesonbuild`, `environment`, `compiler`, `link_args`, `compile_args`. This confirms it's part of the Meson build system and focuses on building software.
    * Specific library names like `gtest`, `gmock`, `llvm`, `valgrind`, `zlib`, `jni`, `jdk`. These are the specific dependencies being handled.
    * References to operating systems (`windows`, `darwin`, `linux`, `freebsd`, `android`). This indicates platform-specific handling of dependencies.
    * Use of `pkgconfig`, `cmake`, and system libraries as sources for dependencies.

3. **Identify Core Functionality:** Based on the clues, the primary function of this file is to define how the Meson build system finds and integrates various development dependencies (libraries, frameworks) needed by Frida. It defines strategies for locating these dependencies using different methods.

4. **Categorize Functionality by Dependency:** It's helpful to go through each dependency class and summarize its individual responsibilities:
    * **GTest/GMock:**  Looks for Google Test and Google Mock libraries. Tries both pre-built libraries and building from source. Handles variations with and without `main()`.
    * **LLVM:**  Uses `llvm-config` and CMake to find LLVM. Handles different LLVM versions and optional components/modules. Deals with both static and shared linking complexities. This is a *major* dependency for Frida.
    * **Valgrind:** Primarily focuses on providing compile arguments for Valgrind (a memory debugging tool), not necessarily linking.
    * **Zlib:**  Standard zlib library. Handles platform differences in how zlib is found.
    * **JNI/JDK:**  Deals with finding the Java Native Interface and Java Development Kit. Handles platform-specific paths and library names.

5. **Connect to Reverse Engineering:** Now, explicitly address the prompt's requirements:
    * **Reverse Engineering:** Think about how these dependencies are *used* in a reverse engineering context. Frida *itself* is a reverse engineering tool. Therefore, these dependencies are essential for *building* Frida. LLVM is a key component because Frida's core uses compiler technologies for code instrumentation. GTest/GMock are used for testing. Valgrind might be used for internal memory checks during Frida development.
    * **Binary/Low-Level:** Consider which dependencies interact directly with the underlying system:
        * LLVM:  Works directly with compiler infrastructure, which generates and manipulates machine code.
        * JNI: Bridges between Java and native code (C/C++), a common pattern in Android where Frida is heavily used.
        * Zlib: Used for compression, potentially relevant for handling packed or compressed data.
        * System Libraries (general):  The entire concept of linking to system libraries touches on how executables are built and interact with the OS kernel.
    * **Linux/Android Kernel/Framework:** Focus on the platform-specific logic:
        * Path handling (`/usr/src/gtest`, `/System/Library/Frameworks/JavaVM.framework`).
        * The JNI section explicitly handles Android (and other OSes) in finding Java components.
        * The `get_shared_library_suffix` function is very OS-specific.

6. **Logical Reasoning (Hypothetical Input/Output):** Choose a specific scenario and trace the code's behavior. A good example is the LLVM dependency:
    * **Input:** Meson is configured to build Frida, and the `dependency('llvm')` call is encountered.
    * **Reasoning:** The code will try `llvm-config` first, then CMake. It will check for specified modules. If `llvm-config` succeeds, it will parse the output for compile and link flags. If CMake is used, it will execute CMake with a custom script.
    * **Output:**  The `LLVMDependency` object will contain the necessary compile and link arguments for LLVM, allowing the Frida build to proceed. If LLVM isn't found, an error will be raised.

7. **User/Programming Errors:**  Think about common mistakes when working with dependencies:
    * Not having the dependency installed.
    * Incorrect version of the dependency.
    * Specifying incorrect module names for LLVM.
    * Issues with environment variables like `JAVA_HOME`.

8. **User Operations Leading to This Code:** Imagine a user building Frida:
    * **Step 1:** Download the Frida source code.
    * **Step 2:** Run the Meson configuration command (e.g., `meson setup build`).
    * **Step 3:** Meson reads the `meson.build` file, which will contain `dependency()` calls for libraries like LLVM, GTest, etc.
    * **Step 4:**  Meson's dependency resolution mechanism will call the appropriate factory functions (like `llvm_factory`) defined in `dev.py`.
    * **Step 5:** The code in `dev.py` executes to find and configure the dependencies.

9. **Structure and Refine:** Organize the findings logically, using headings and bullet points. Ensure the explanations are clear and concise. Review the generated answer against the original prompt to make sure all requirements are addressed. Add examples where appropriate to illustrate the concepts. For instance, showing the `llvm-config` command or a CMake option clarifies how those tools are used.

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:**  "This file just finds libraries."
* **Correction:** "It does more than just find them. It also determines how to *use* them, including compile flags, link flags, and handling different versions and configurations."
* **Refinement:** Emphasize the different *strategies* for finding dependencies (pkg-config, CMake, system detection) and the logic involved in choosing the right approach. Highlight the version checking and module handling within the LLVM dependency.

By following this systematic approach, combining code reading with knowledge of build systems and the specific tools involved, you can effectively analyze and explain the functionality of this kind of dependency management code.
This Python file, `dev.py`, located within the Frida project's build system, is responsible for **defining and detecting various development dependencies** required to build Frida. It uses the Meson build system's dependency handling framework.

Here's a breakdown of its functionalities:

**Core Functionality: Dependency Management**

* **Defining Dependency Classes:** The file defines multiple classes, each representing a specific external dependency (e.g., `GTestDependencySystem`, `LLVMDependencyConfigTool`, `ZlibSystemDependency`). These classes encapsulate the logic for finding and configuring that particular dependency.
* **Detection Strategies:** Each dependency class implements methods to detect the dependency on the system using different strategies:
    * **System Libraries:**  Searching standard system library paths (e.g., using compiler's `find_library` method).
    * **Pkg-config:**  Using `.pc` files to get compile and link flags.
    * **CMake:**  Using CMake's `find_package` functionality.
    * **Configuration Tools:**  Using specific tools provided by the dependency itself (e.g., `llvm-config` for LLVM).
    * **Source Code Detection:**  Looking for source code directories (e.g., for GTest/GMock).
* **Providing Build Information:** Once a dependency is detected, the classes provide information to Meson about how to use it, including:
    * **Include Paths (`compile_args`):** Directories containing header files.
    * **Link Libraries (`link_args`):** Libraries to link against.
    * **Source Files (`sources`):** Source files to compile (if building from source).
    * **Version Information (`version`):** The version of the detected dependency.
    * **Whether it's Prebuilt (`prebuilt`):** Indicates if a system library is used or if it needs to be built from source.
* **Dependency Factories:**  The `DependencyFactory` class is used to create instances of dependency objects based on the specified methods (e.g., try Pkg-config first, then System detection).
* **Handling Optional Modules:** For dependencies like LLVM and JNI, it allows specifying required and optional modules.

**Relationship to Reverse Engineering**

This file is directly related to reverse engineering because Frida itself is a dynamic instrumentation toolkit heavily used for reverse engineering. The dependencies managed by this file are crucial for building Frida:

* **LLVM:**  A cornerstone dependency. Frida uses LLVM's compiler infrastructure for code manipulation and instrumentation. Without a correctly configured LLVM dependency, Frida cannot be built.
    * **Example:**  When Frida instruments a function, it might use LLVM to parse the function's assembly, insert instrumentation code (like probes), and then reassemble the modified code. This relies on LLVM's libraries and headers.
* **GTest/GMock:** These are testing frameworks used for unit testing Frida's own code. While not directly used *during* runtime instrumentation, they are essential for ensuring the correctness and stability of Frida's core components.
    * **Example:** Frida developers write unit tests using GTest to verify that a specific instrumentation function behaves as expected under various conditions.
* **Zlib:**  A compression library, potentially used for compressing data exchanged between the Frida client and the target process or within Frida's internal mechanisms.
    * **Example:**  If Frida needs to transfer a large amount of data from the target process, it might use zlib to compress it for efficiency.
* **JNI/JDK:** Necessary when building Frida components that interact with Java or Android environments. Frida is widely used on Android for reverse engineering.
    * **Example:** Frida can hook into Java methods on Android. This requires the JNI to bridge the gap between Frida's native code and the Java Virtual Machine.

**Involvement of Binary, Linux, Android Kernel & Framework Knowledge**

The code demonstrates knowledge of these low-level aspects:

* **Binary:**
    * **Shared Library Suffixes:** The `get_shared_library_suffix` function knows the standard suffixes for shared libraries on different operating systems (`.so`, `.dylib`, `.dll`).
    * **Linking:** The code manipulates link arguments (`-l`, `-L`) which are fundamental to the binary linking process.
    * **Library Finding:**  The `find_library` method interacts with the operating system's mechanisms for locating shared libraries.
* **Linux:**
    * **Standard Library Paths:** The code checks for libraries in common Linux locations like `/usr/lib`, `/usr/local/lib`.
    * **File System Structure:** It checks for source code in directories like `/usr/src/gtest/src`.
* **Android Kernel & Framework:**
    * **JNI:** The `JNISystemDependency` class explicitly handles the Java Native Interface, which is crucial for interacting with Android's Java framework.
    * **Java Home Detection:**  It attempts to locate the `JAVA_HOME` environment variable and uses platform-specific paths within the JDK.
    * **CPU Architecture Handling:** The `__cpu_translate` method in `JNISystemDependency` addresses discrepancies in CPU architecture naming between Meson and the JDK.
* **Operating System Differences:** The code uses conditional logic based on `m.is_windows()`, `m.is_darwin()`, etc., to handle platform-specific library naming conventions and locations.

**Logical Reasoning (Hypothetical Input & Output)**

Let's take the `LLVMDependencyConfigTool` as an example:

**Hypothetical Input:**

* Meson is configuring the build for Frida.
* The system has LLVM installed, and `llvm-config` is in the system's PATH.
* The `meson.build` file has a `dependency('llvm', modules: ['Core', 'Analysis'])` call.

**Logical Reasoning:**

1. The `LLVMDependencyConfigTool` constructor is called.
2. It attempts to find `llvm-config` (and potentially `llvm-config-64` or `llvm-config-32` based on the architecture).
3. If found, it executes `llvm-config --version` to get the LLVM version.
4. It executes `llvm-config --cppflags` to get compile arguments.
5. It executes `llvm-config --components` to get the available LLVM components.
6. It checks if the requested modules ('Core', 'Analysis') are in the available components.
7. It executes `llvm-config --libs --ldflags --link-shared Core Analysis` (or similar commands depending on the version and static/shared linking requirements) to get link arguments.

**Hypothetical Output:**

* `self.is_found` would be `True`.
* `self.version` would be set to the output of `llvm-config --version`.
* `self.compile_args` would be a list of compiler flags (e.g., `-I/usr/lib/llvm/include`).
* `self.link_args` would be a list of linker flags and libraries (e.g., `-L/usr/lib/llvm -lLLVMCore -lLLVMAnalysis`).
* `self.module_details` would indicate the status of the requested modules (e.g., `['Core', 'Analysis']`).

**User or Programming Common Usage Errors**

* **Dependency Not Installed:**  The most common error is that the required dependency (e.g., LLVM, GTest) is not installed on the system or is not in the expected location. Meson will fail to find the dependency, and the build will fail.
    * **Example:** If a user tries to build Frida without LLVM installed, the `LLVMDependencyConfigTool` or `LLVMDependencyCMake` will fail to find LLVM, and Meson will report an error like "Dependency 'llvm' not found".
* **Incorrect Dependency Version:**  Some dependencies might have minimum version requirements. If an older version is installed, the build might fail or exhibit unexpected behavior.
    * **Example:** If Frida requires LLVM 9 or higher, and the user has LLVM 8 installed, the version check in `LLVMDependencyConfigTool` might fail, leading to a build error.
* **Missing Development Packages:** Often, the *runtime* libraries of a dependency are installed, but the *development* packages (containing header files and static libraries) are missing. This will cause the dependency detection to fail.
    * **Example:**  A user might have the `zlib` runtime library installed but not the `zlib-dev` or `zlib-devel` package (depending on the distribution), which contains `zlib.h`. The `ZlibSystemDependency` would then fail to find the necessary header file.
* **Incorrect Module Names (LLVM):** When specifying LLVM modules, using incorrect or misspelled module names will cause the `check_components` method in `LLVMDependencyConfigTool` to report missing modules.
    * **Example:** If a user specifies `modules: ['Foobar']` for the LLVM dependency, and 'Foobar' is not a valid LLVM module, the build will likely fail.
* **Incorrect `JAVA_HOME` (JNI/JDK):** If the `JAVA_HOME` environment variable is not set correctly or points to an invalid JDK installation, the `JNISystemDependency` will fail to locate the necessary Java components.
    * **Example:** On macOS, if `JAVA_HOME` points to a system Java installation that doesn't contain the required development headers, the JNI dependency detection might fail.

**User Operations Leading to This Code (Debugging Clues)**

A user would typically reach this code indirectly through the Meson build process. Here's a step-by-step scenario:

1. **Download Frida Source:** The user clones or downloads the Frida source code repository.
2. **Run Meson Setup:** The user executes the Meson configuration command, typically from the root of the Frida source directory: `meson setup build`.
3. **Meson Reads `meson.build`:** Meson parses the `meson.build` file, which contains `dependency()` calls for various libraries (e.g., `dependency('llvm')`, `dependency('gtest')`).
4. **Dependency Resolution:** For each `dependency()` call, Meson needs to find the corresponding dependency. It looks for a file named `dependencies/dev.py` (relative to the `meson.build` file or a standard location).
5. **Dependency Factory Invocation:** Inside `dev.py`, the appropriate `DependencyFactory` (e.g., `llvm_factory`, `gtest_factory`) is invoked based on the dependency name.
6. **Dependency Class Instantiation:** The factory then instantiates the dependency class specified in its `methods` list (e.g., `LLVMDependencyConfigTool`, `GTestDependencySystem`).
7. **Detection Logic Execution:** The constructor and detection methods of the dependency class are executed to find the dependency on the system.

**As a debugging clue, if a user encounters an error related to a missing or misconfigured dependency during the Meson setup phase, the issue likely lies within the corresponding dependency class defined in `dev.py`.**  For example, if Meson reports "Dependency 'llvm' not found", the developer or user would investigate the `LLVMDependencyConfigTool` and `LLVMDependencyCMake` classes in `dev.py` to understand how LLVM detection is attempted and where it might be failing. They might check if the expected executables (`llvm-config`) or CMake files are present and accessible.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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