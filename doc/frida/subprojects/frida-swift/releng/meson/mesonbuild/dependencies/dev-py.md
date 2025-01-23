Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Understanding the Goal:**

The request asks for a functional breakdown of a Python file within the Frida project, specifically focusing on its relevance to reverse engineering, low-level details, and potential user errors, with a focus on debugging.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "Dependency," "SystemDependency," "PkgConfigDependency," "CMakeDependency," and specific library names (gtest, gmock, llvm, zlib, jni) immediately suggest that this file deals with managing external library dependencies within the Meson build system. The `dev.py` in the path hints that these are likely development dependencies.

**3. Identifying Core Functionality Areas:**

As I read through, I start grouping related code blocks into functional areas:

* **Dependency Base Classes:**  `SystemDependency`, `ExternalDependency`, `PkgConfigDependency`, `CMakeDependency`, `ConfigToolDependency`. These establish the fundamental ways dependencies are handled.
* **Specific Dependency Implementations:** `GTestDependencySystem`, `GTestDependencyPC`, `GMockDependencySystem`, `GMockDependencyPC`, `LLVMDependencyConfigTool`, `LLVMDependencyCMake`, `ValgrindDependency`, `ZlibSystemDependency`, `JNISystemDependency`, `JDKSystemDependency`. Each of these manages a particular dependency.
* **Dependency Factory:** `DependencyFactory`. This is a design pattern for creating dependency objects.
* **Helper Functions:** `get_shared_library_suffix`. This provides a utility function.
* **Import Statements:** These indicate external modules used by the file (e.g., `os`, `glob`, `subprocess`).

**4. Analyzing Each Functional Area for Requested Details:**

Now, I go deeper into each area, specifically looking for information relevant to the prompt's requirements:

* **Reverse Engineering:**
    * **LLVM:**  Stands out immediately. LLVM is heavily used in reverse engineering tools and frameworks (like Frida itself) for compiler infrastructure and code analysis. I note how this code finds and configures LLVM.
    * **GTest/GMock:**  Unit testing frameworks, important for development and ensuring correctness, which *can* be relevant in reverse engineering when analyzing or extending tools.
    * **Valgrind:** A memory debugging and profiling tool, frequently used in reverse engineering to understand program behavior and find vulnerabilities.
    * **Shared Libraries:** The function to get shared library suffixes is directly relevant to understanding how dynamic libraries work, a key concept in reverse engineering.

* **Binary/Low-Level, Linux/Android Kernel/Framework:**
    * **Shared Libraries:** Again, the shared library suffix function.
    * **`.so` suffix:**  Directly links to Linux shared libraries.
    * **Library Finding:** The `find_library` methods of the compiler objects directly interact with the system's library paths, a low-level OS concept.
    * **Include Paths:** Managing include paths (`-I`) is fundamental to compilation and understanding how code interacts with system headers.
    * **Kernel/Framework Specifics (Android):**  The `ZlibSystemDependency` and `JNISystemDependency` have Android-specific logic, indicating awareness of the Android environment. The JNI dependency deals with the Java Native Interface, crucial for Android's framework.

* **Logical Reasoning (Assumptions/Inputs/Outputs):**
    * For the `DependencyFactory`, the input is a name and a list of dependency methods. The output is an appropriate dependency object based on which method succeeds.
    * For specific dependency classes (like `LLVMDependencyConfigTool`), the input is the dependency name, environment, and keyword arguments (like `modules`). The output is a configured dependency object with compile and link arguments, or a "not found" status. I try to think of scenarios where the logic within these classes would branch (e.g., different LLVM versions).

* **User/Programming Errors:**
    * **Missing Dependencies:** The entire file is about dependencies. A common error is not having the required libraries installed.
    * **Incorrect Versions:** The version checking in `LLVMDependencyConfigTool` and `JNISystemDependency` highlights potential version mismatch errors.
    * **Incorrect Configuration:** Passing wrong arguments to dependency calls (e.g., wrong module names for LLVM).
    * **Environmental Issues:**  `JAVA_HOME` not being set correctly for the JNI dependency.

* **User Operations to Reach This Code (Debugging Clues):**
    * The user is using the Meson build system.
    * They are trying to build a project that depends on Frida (given the file path).
    * The build process is in the dependency resolution stage.
    * Meson is attempting to find and configure the development dependencies (due to `dev.py`).
    * Errors encountered during this stage would likely involve messages related to "dependency not found," version mismatches, or problems with specific dependency tools (like `llvm-config`).

**5. Structuring the Explanation:**

Finally, I organize the gathered information into a clear and structured explanation, using headings and bullet points to improve readability. I try to connect the technical details back to the prompt's specific points about reverse engineering, low-level concepts, etc. I include code snippets where helpful for illustrating a point.

**Self-Correction/Refinement:**

During the process, I might realize I missed something or misunderstood a piece of code. For instance, I might initially overlook the significance of the `DependencyFactory` and then go back and add an explanation of its role. Or, I might refine my examples of user errors to be more concrete and relatable. I also double-check that I've addressed all aspects of the original prompt.
This Python file, `dev.py`, within the Frida project, is responsible for **defining and detecting development dependencies** required to build Frida's Swift bindings. It leverages the Meson build system's dependency management features.

Here's a breakdown of its functionalities:

**1. Defining Dependency Types:**

* **System Dependencies:**  It defines classes for detecting dependencies available on the system, like `GTestDependencySystem`, `GMockDependencySystem`, `ZlibSystemDependency`, `JNISystemDependency`. These classes attempt to locate the libraries and their associated header files in standard system locations.
* **Package Config Dependencies:** It uses `PkgConfigDependency` for dependencies that provide `.pc` files, like `GTestDependencyPC`, `GMockDependencyPC`, and `ValgrindDependency`. `pkg-config` is a standard tool for retrieving compile and link flags for libraries.
* **CMake Dependencies:** It utilizes `CMakeDependency` for dependencies that provide CMake configuration files, specifically for LLVM (`LLVMDependencyCMake`). This allows leveraging existing CMake build configurations.
* **Config Tool Dependencies:** It introduces `ConfigToolDependency` as a base for dependencies that have their own configuration tools, like LLVM's `llvm-config` (`LLVMDependencyConfigTool`).
* **Dependency Factory:** The `DependencyFactory` class acts as a factory pattern to create the appropriate dependency object based on the available detection methods (e.g., try pkg-config first, then system detection).

**2. Detecting Specific Dependencies:**

The file contains logic to find and configure the following development dependencies:

* **Google Test (gtest):**  Used for unit testing the Frida Swift bindings. It attempts to find pre-built libraries or build from source if necessary.
* **Google Mock (gmock):**  A mocking framework often used with gtest for more complex testing scenarios. Similar detection logic to gtest.
* **LLVM:** A crucial dependency as it provides the compiler infrastructure necessary for working with Swift's intermediate representation (IR) and performing code generation tasks. It supports detection via both `llvm-config` and CMake.
* **Valgrind:** A memory debugging and profiling tool. It's primarily used to get compile arguments (for annotations) rather than linking.
* **Zlib:** A compression library, potentially used for various tasks within the build process.
* **Java/JDK (jni/jdk):** Required for interacting with Java code from Swift, especially on Android. It needs to locate the Java Development Kit (JDK).

**3. Handling Different Operating Systems and Architectures:**

The code includes platform-specific logic, for example:

* **Shared Library Suffix:** The `get_shared_library_suffix` function determines the correct suffix for shared libraries (`.so`, `.dylib`, `.dll`) based on the target operating system.
* **macOS-specific checks:** In `ZlibSystemDependency` and `JNISystemDependency`, there are checks and assumptions specific to macOS (e.g., system include paths, finding `JAVA_HOME`).
* **Windows-specific checks:** The `ZlibSystemDependency` checks for different zlib library names on Windows.
* **Android-specific checks:**  The `ZlibSystemDependency` and `JNISystemDependency` have specific considerations for Android.
* **CPU architecture considerations:**  The `LLVMDependencyConfigTool` considers the CPU architecture (32-bit or 64-bit) when looking for `llvm-config`. The `JNISystemDependency` translates CPU architecture names between Meson and Java conventions.

**4. Version Handling:**

Some dependency classes, like `LLVMDependencyConfigTool` and `JNISystemDependency`, have logic to check the version of the found dependency against required versions.

**Relationship to Reverse Engineering:**

This file, while part of the build system, has significant ties to reverse engineering concepts due to the nature of the dependencies it manages:

* **LLVM:**  LLVM is a foundational technology in many reverse engineering tools and frameworks. Frida itself uses LLVM for code instrumentation and analysis. Detecting and correctly configuring LLVM is essential for Frida's functionality, which is heavily used in dynamic reverse engineering. **Example:** When Frida instruments a process, it often involves manipulating the process's memory and code. LLVM's compiler infrastructure is used to generate or modify code snippets that are injected into the target process. This file ensures the correct LLVM libraries and headers are available for this process.
* **Valgrind:** Valgrind is a powerful tool for detecting memory errors and understanding program behavior, which are common tasks in reverse engineering. While this file only uses it for compile arguments, the fact that it's included highlights its relevance to the development process of a tool like Frida, which often interacts with low-level memory operations. **Example:** During the development of Frida's Swift bindings, Valgrind could be used to detect memory leaks or other memory corruption issues that might arise from the interaction between Swift and native code.
* **Shared Libraries:** The concept of shared libraries (`.so`, `.dylib`, `.dll`) is fundamental to understanding how software is structured and how different components interact at runtime. Reverse engineers frequently analyze shared libraries to understand their functionality and identify potential vulnerabilities. This file deals with finding and linking against these shared libraries. **Example:** When Frida attaches to a process, it often injects its own agent as a shared library. Understanding how these libraries are loaded and how dependencies are resolved is crucial for Frida's operation.

**Involvement of Binary 底层, Linux, Android内核及框架知识:**

* **Binary/底层:** The file deals with linking against binary libraries (`.so`, `.dylib`, `.dll`) and providing include paths for header files. This directly involves understanding the binary interface of libraries and how compilers and linkers work at a low level.
* **Linux:** The `.so` suffix and the search paths for libraries (`/usr/lib`, `/usr/local/lib`) are specific to Linux-like systems. The handling of `JAVA_HOME` and library locations in `JNISystemDependency` also considers typical Linux layouts.
* **Android:** The `JNISystemDependency` has explicit logic for handling the JDK on Android. This involves understanding the structure of the Android SDK and where the necessary Java libraries are located within the Android framework. The `ZlibSystemDependency` also has an Android-specific case. **Example:** On Android, Frida often needs to interact with the Dalvik/ART runtime. The JNI dependency ensures that Frida can compile code that uses the Java Native Interface to bridge between native code (like Frida's core) and the Java framework on Android.
* **Kernel (Indirect):** While this file doesn't directly interact with the kernel, the dependencies it manages (especially LLVM) are used by Frida to perform actions that can have kernel-level implications, such as code injection and memory manipulation.

**Logical Reasoning (Assumptions and Input/Output):**

Let's take the `GTestDependencySystem` as an example:

* **Assumption:** The GTest library or its source code is present in one of the defined `src_dirs` or is available as a pre-built library.
* **Input (Hypothetical):**
    * `environment`:  A Meson `Environment` object containing information about the build setup, compilers, etc.
    * `kwargs`: An empty dictionary `{}` in this basic case.
* **Output (Possible):**
    * **Scenario 1: Pre-built GTest found:** `self.is_found` is `True`, `self.compile_args` is an empty list, `self.link_args` contains the paths to `libgtest.so` (and `libgtest_main.so` if `main=True` was in `kwargs`), `self.sources` is empty, `self.prebuilt` is `True`.
    * **Scenario 2: GTest source directory found:** `self.is_found` is `True`, `self.compile_args` contains `-I` flags pointing to the GTest include directories, `self.link_args` is empty, `self.sources` contains the `gtest-all.cc` (and `gtest_main.cc` if `main=True`), `self.prebuilt` is `False`.
    * **Scenario 3: GTest not found:** `self.is_found` is `False`.

**User or Programming Common Usage Errors:**

* **Missing Dependencies:** The most common error is not having the required development dependencies installed on the system. For example, if LLVM is not installed, the build will likely fail with an error message indicating that `llvm-config` or CMake couldn't find LLVM.
* **Incorrect Versions:**  If a specific version of a dependency is required but a different version is installed, the build might fail or exhibit unexpected behavior. The version checks in the code aim to mitigate this, but users might still encounter issues. **Example:**  If Frida requires LLVM version 10 or higher, but the user has version 9 installed, the `LLVMDependencyConfigTool` might fail to find a suitable LLVM installation.
* **Incorrect Environment Configuration:**  Some dependencies rely on environment variables. For example, if `JAVA_HOME` is not set correctly, the `JNISystemDependency` will fail to find the JDK.
* **Typos in Dependency Names or Options:** When configuring the Meson build, users might make typos in the names of dependencies or their options (e.g., misspelling "gtest" or providing an incorrect module name for LLVM).
* **Conflicting Dependencies:** In some rare cases, different dependencies might conflict with each other, leading to build errors.

**User Operations to Reach This Code (Debugging Clues):**

A user would interact with this code during the **dependency resolution phase** of the Meson build process. Here's a step-by-step scenario leading to the execution of this code:

1. **User clones the Frida repository:**  This gets the source code, including this `dev.py` file.
2. **User attempts to build Frida's Swift bindings:** This typically involves running commands like `meson setup build --backend=ninja` followed by `ninja` from the root of the Frida repository.
3. **Meson starts the setup process:** It reads the `meson.build` files, which define the project structure and dependencies.
4. **Meson encounters a dependency declaration:**  In the `meson.build` files related to the Swift bindings, there will be calls to the `dependency()` function, specifying the development dependencies like "gtest," "gmock," "llvm," "zlib," and "jni" (or "jdk").
5. **Meson calls the appropriate dependency factory:** For each dependency, Meson will use the registered `DependencyFactory` (e.g., `llvm_factory` for "llvm").
6. **The factory tries different detection methods:** The factory will iterate through the listed methods (e.g., `PKGCONFIG`, `SYSTEM` for gtest).
7. **For `SYSTEM` method, the corresponding class in `dev.py` is instantiated:** If the system detection method is chosen, classes like `GTestDependencySystem`, `LLVMDependencySystem`, etc., from `dev.py` are created.
8. **The `detect()` method of the dependency class is executed:** This method contains the logic to find the dependency on the system (e.g., searching for libraries, headers, or configuration tools).
9. **If the dependency is found:** The dependency object is configured with compile and link arguments.
10. **If the dependency is not found:** Meson will issue an error message indicating the missing dependency.

**Debugging Clues:**

* **Meson output:** Look for error messages from Meson that specifically mention missing dependencies (e.g., "Dependency gtest found: NO").
* **`meson-log.txt`:** This file contains a more detailed log of the Meson build process, including the attempts to find dependencies and any errors encountered. Examining this log can provide valuable information about why a dependency was not found.
* **Environment variables:** Check if necessary environment variables like `JAVA_HOME` or paths to LLVM installations are correctly set.
* **Installed packages:** Verify that the required development packages (e.g., `libgtest-dev`, `llvm`, `openjdk`) are installed on the system using the system's package manager.
* **Typos in `meson.build`:** Double-check the dependency names and options in the `meson.build` files.

In summary, `dev.py` plays a crucial role in ensuring that the necessary development tools and libraries are available for building Frida's Swift bindings. Its logic involves platform-specific considerations, version handling, and multiple strategies for detecting dependencies, making it a central piece of the build system with strong ties to reverse engineering concepts and low-level system knowledge.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/dependencies/dev.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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