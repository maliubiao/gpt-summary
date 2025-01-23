Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understanding the Goal:** The primary goal is to analyze a Python file (`dev.py`) within the Frida project and describe its functionalities, especially concerning reverse engineering, low-level aspects (kernel, etc.), logical reasoning, common user errors, and how a user might end up interacting with this code.

2. **Initial Scan and Keyword Spotting:**  I started by quickly reading through the code, looking for keywords and patterns that could indicate its purpose. Keywords like `Dependency`, `SystemDependency`, `PkgConfigDependency`, `CMakeDependency`, `llvm-config`, `gtest`, `gmock`, `zlib`, `jni`, and `jdk` immediately jumped out. These suggest the file is about managing external library dependencies.

3. **Identifying Core Functionality - Dependency Management:**  The presence of various dependency classes (`GTestDependencySystem`, `GMockDependencyPC`, `LLVMDependencyConfigTool`, etc.) and the `DependencyFactory` strongly indicate that this file is responsible for detecting and configuring external libraries required by the Frida build process.

4. **Categorizing Dependencies:** I noticed different ways dependencies are handled:
    * **System Dependencies:**  These check for libraries already installed on the system (e.g., `GTestDependencySystem`, `ZlibSystemDependency`, `JNISystemDependency`).
    * **Pkg-config Dependencies:**  These utilize `.pc` files to get information about libraries (e.g., `GTestDependencyPC`, `GMockDependencyPC`, `ValgrindDependency`).
    * **CMake Dependencies:**  These use CMake's `find_package` mechanism (e.g., `LLVMDependencyCMake`).
    * **Config Tool Dependencies:**  These rely on specific tools provided by the library (e.g., `LLVMDependencyConfigTool` using `llvm-config`).

5. **Relating to Reverse Engineering:** I considered how these dependencies might be used in a dynamic instrumentation tool like Frida.
    * **LLVM:**  Crucial for compiler infrastructure, likely used by Frida's Gum engine for code generation or manipulation. This directly connects to reverse engineering tasks like code injection and instrumentation.
    * **GTest/GMock:** Testing frameworks used for developing and verifying Frida's functionality, indirectly related to reverse engineering but vital for its correctness.
    * **Zlib:** A common compression library. Frida might use it for compressing data during communication or when dealing with packed executables.
    * **JNI/JDK:**  Essential for interacting with Java code on Android, a primary target for Frida. This is a *very strong* link to reverse engineering Android applications.
    * **Valgrind:** A memory debugging and profiling tool. While not a direct Frida dependency *at runtime*, it might be used during Frida's development or for analyzing the behavior of instrumented processes.

6. **Identifying Low-Level/Kernel Connections:** I focused on dependencies interacting directly with the operating system or requiring specific system knowledge:
    * **System Dependencies in General:**  By their nature, these interact with the OS to locate libraries.
    * **JNI/JDK:**  Involves understanding the Java runtime environment, which has platform-specific implementations and interacts closely with the OS. Specifically, finding `jvm.so` (or equivalent) is a low-level operation.
    * **LLVM:**  Can be used to generate machine code, directly interacting with the CPU architecture.

7. **Looking for Logical Reasoning/Assumptions:** I scanned for conditional logic and assumptions within the code:
    * **Version Comparisons:**  The extensive use of `version_compare` functions highlights logic based on the version of the dependency.
    * **Platform Checks:**  `m.is_windows()`, `m.is_darwin()`, etc., show platform-specific logic in how dependencies are located and configured.
    * **Module Handling (LLVM, JNI):** The code checks for specific modules or components of dependencies.

8. **Considering User Errors:** I thought about what could go wrong from a user's perspective:
    * **Missing Dependencies:** The most common issue – the required libraries aren't installed.
    * **Incorrect Versions:**  The dependency versions don't match Frida's requirements.
    * **Misconfigured Environments:**  `JAVA_HOME` not set correctly is a prime example.
    * **Build System Issues:** Problems with `pkg-config` or CMake.

9. **Tracing User Interaction (Debugging Clues):** I imagined a user trying to build Frida:
    * Running the build command (likely using `meson`).
    * Meson would execute this `dev.py` script to find dependencies.
    * If a dependency isn't found, Meson would report an error, often pointing to the missing package. This file contains the logic that *determines* what's missing.

10. **Structuring the Answer:** Finally, I organized the information into clear categories based on the prompt's requirements:
    * Core Functionality
    * Relationship to Reverse Engineering (with examples)
    * Binary/Low-Level/Kernel Aspects (with examples)
    * Logical Reasoning (with input/output assumptions)
    * User Errors (with examples)
    * User Journey (debugging context)

Throughout this process, I reread sections of the code as needed to clarify details and ensure accuracy. The iterative approach of scanning, identifying patterns, and then deep-diving into specific parts was key to understanding the file's overall purpose and its relevance to Frida's function.
This Python file, `dev.py`, located within the Frida project's build system, plays a crucial role in **managing external dependencies** required to build Frida. It defines how the Meson build system should locate and configure various development libraries on different operating systems.

Here's a breakdown of its functionalities:

**1. Dependency Detection and Configuration:**

* **Defines Dependency Classes:** The file defines several classes that represent specific external dependencies, such as `GTestDependencySystem`, `GMockDependencyPC`, `LLVMDependencyConfigTool`, `LLVMDependencyCMake`, `ValgrindDependency`, `ZlibSystemDependency`, `JNISystemDependency`, and `JDKSystemDependency`.
* **Detection Strategies:** Each dependency class implements different strategies to find the corresponding library on the system. These strategies include:
    * **System-level detection:** Looking for libraries in standard system paths (e.g., `/usr/lib`, `/usr/include`) using compiler tools.
    * **Pkg-config:** Utilizing `.pc` files to retrieve compile and link flags.
    * **CMake:** Employing CMake's `find_package` mechanism or custom CMake scripts.
    * **Config tools:** Using specific tools provided by the dependency (e.g., `llvm-config` for LLVM).
* **Configuration Retrieval:** Once a dependency is found, the classes extract necessary information, such as:
    * **Compile arguments:** Include paths (`-I`).
    * **Link arguments:** Library paths (`-L`, `-l`).
    * **Sources:** Source files needed for building (for dependencies that can be built from source).
    * **Version:** The version of the detected library.
* **Dependency Factories:** The `DependencyFactory` class helps in registering different methods (Pkgconfig, System, CMake) for detecting a single dependency. This allows Meson to try multiple approaches to find a library.

**2. Relationship to Reverse Engineering (with Examples):**

This file is indirectly related to the core reverse engineering functionalities of Frida but is essential for building the tool itself. The dependencies it manages are often used in reverse engineering workflows:

* **LLVM:** This is a major dependency. LLVM is a compiler infrastructure. Frida's **Gum engine**, which is responsible for dynamic instrumentation (injecting code, hooking functions), likely uses LLVM for just-in-time (JIT) compilation of instrumentation code or for manipulating the target process's code.
    * **Example:** When Frida injects a JavaScript snippet to hook a function, the Gum engine might use LLVM to generate the machine code for the hook and detour.
* **GTest/GMock:** These are C++ testing frameworks. While not directly involved in reverse engineering the target application, they are crucial for **testing Frida's own code**. Robust testing ensures the reliability of Frida's instrumentation capabilities.
    * **Example:**  Developers might write GTest cases to verify that Frida correctly hooks functions in different scenarios or that memory is handled properly during instrumentation.
* **Zlib:** This is a compression library. Frida might use it for compressing data during communication between the Frida client and the target process, especially when transferring large amounts of data.
    * **Example:** If you are dumping a large chunk of memory from a process using Frida, the data might be compressed using zlib before being sent back to the client.
* **JNI (Java Native Interface):** This dependency is vital for Frida's ability to interact with **Android applications**. JNI allows native code (like parts of Frida) to interact with Java code.
    * **Example:** Frida uses JNI to attach to a Dalvik/ART VM in an Android process, enumerate classes and methods, and hook Java functions.
* **JDK (Java Development Kit):**  Similar to JNI, the JDK dependency is primarily for interacting with Java environments.

**3. Binary Underlying, Linux, Android Kernel & Framework Knowledge (with Examples):**

The file demonstrates knowledge of these areas through how it detects and configures dependencies:

* **Binary Underlying:**
    * **Shared Library Suffixes:** The `get_shared_library_suffix` function knows the standard suffixes for shared libraries on different platforms (`.dll` on Windows, `.dylib` on macOS, `.so` on Linux).
    * **Library Linking:**  The code uses compiler flags like `-l` and `-L` to specify libraries to link against, demonstrating an understanding of the linking process.
    * **Compiler-Specific Arguments:** The code sometimes adjusts detection logic based on the compiler in use (e.g., handling MSVC library names for Zlib).
* **Linux:**
    * **Standard Library Paths:** It checks common Linux library paths like `/usr/lib` and include paths like `/usr/include`.
    * **Pkg-config:**  The reliance on Pkg-config is a common practice on Linux systems for managing library dependencies.
* **Android Kernel & Framework:**
    * **JNI Detection:** The `JNISystemDependency` class specifically looks for the `jvm` and `jawt` libraries, which are core components of the Java Runtime Environment on Android.
    * **`java_home` Discovery:** The code attempts to locate the `JAVA_HOME` environment variable or uses heuristics specific to macOS to find the JDK installation, crucial for interacting with Android's Java framework.
    * **CPU Architecture Translation:** The `__cpu_translate` method in `JNISystemDependency` handles discrepancies between how Meson and the JDK name CPU architectures (e.g., `x86_64` vs. `amd64`).

**4. Logical Reasoning (with Assumptions, Input & Output):**

The file contains logical reasoning in its dependency detection logic:

* **Assumption:** If a specific library (e.g., `gtest`) is required and not found through system detection, try using Pkg-config.
* **Input (Hypothetical):**  The Meson build system is run on a Linux system where the `libgtest.so` library is installed in `/usr/lib`, but the `gtest.pc` file is missing.
* **Output:** The `GTestDependencySystem` class would find the library using `self.clib_compiler.find_library("gtest", self.env, [])` and set `self.is_found = True`, populating `self.link_args`. The `GTestDependencyPC` class would likely fail to find the dependency.

* **Assumption:** For LLVM, if `llvm-config` is available, it provides the most reliable way to get compile and link flags. If not, try CMake.
* **Input (Hypothetical):** Meson is building Frida on a system where LLVM is installed, and the `llvm-config` tool is in the system's PATH.
* **Output:** The `LLVMDependencyConfigTool` class would be used. It would execute `llvm-config --cppflags`, `llvm-config --libs`, etc., to retrieve the necessary compiler and linker flags.

**5. User or Programming Common Usage Errors (with Examples):**

* **Missing Dependencies:** The most common error is when a required dependency is not installed on the system.
    * **Example:** If a user tries to build Frida without having LLVM installed, Meson will report an error indicating that the LLVM dependency could not be found. The error message might originate from within the LLVM dependency detection logic in this file.
* **Incorrect Dependency Versions:**  Sometimes, the installed version of a library is too old or too new for Frida.
    * **Example:** If Frida requires a specific version of Zlib and the user has an older version installed, the `ZlibSystemDependency` class might detect the library but the build might fail later due to API incompatibilities. The `version_compare` functions in this file are used to check for version compatibility.
* **Misconfigured Environment:** Some dependencies rely on environment variables.
    * **Example:**  If the `JAVA_HOME` environment variable is not set correctly on a system where the user is building Frida with Java bindings, the `JNISystemDependency` class might fail to locate the JDK, leading to a build error.
* **Problems with Pkg-config or CMake:** If these tools are not installed or configured correctly, dependency detection can fail.
    * **Example:** If Pkg-config is not in the system's PATH, the `GTestDependencyPC` class will not be able to find the `gtest.pc` file, even if the library is installed.

**6. User Operation to Reach This File (Debugging Clues):**

A user would indirectly interact with this file during the Frida build process:

1. **Clone the Frida repository:**  A user starts by cloning the Frida source code from GitHub.
2. **Install build dependencies:** The user would typically follow the documentation to install the base build requirements (like Python, Meson, Ninja).
3. **Run Meson:** The user executes the Meson command to configure the build. For example: `meson setup build`.
4. **Meson executes build scripts:** During the configuration phase, Meson will execute the `meson.build` files and other Python scripts within the project, including `frida/subprojects/frida-gum/releng/meson/mesonbuild/dependencies/dev.py`.
5. **Dependency detection:** This `dev.py` file is invoked by Meson to find and configure the external dependencies.
6. **Error reporting (if any):** If a dependency is not found or configured correctly, Meson will generate an error message. These error messages often provide clues about which dependency is missing or causing problems. The logic within the dependency classes in this file determines whether a dependency is considered "found" or not.

**As a debugging clue:** If a user encounters an error during the Meson configuration phase related to a missing dependency (e.g., "Could not find dependency LLVM"), the developer might start investigating the corresponding dependency class in `dev.py` (`LLVMDependencyConfigTool` or `LLVMDependencyCMake`) to understand how Meson is trying to find that dependency and where the detection might be failing. They might add logging statements within these classes to gain more insight into the detection process on the user's system.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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