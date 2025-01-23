Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Understanding the Goal:**

The request asks for a comprehensive explanation of the provided Python code, focusing on its functionality and relevance to reverse engineering, low-level aspects, and potential user errors, while also outlining how a user might trigger this code.

**2. Initial Skim and High-Level Understanding:**

A quick read-through reveals the file's purpose: detecting and managing external dependencies for the Frida project using the Meson build system. Keywords like "Dependency," "PKGCONFIG," "CMAKE," and names of common libraries (netcdf, dl, OpenMP, etc.) immediately stand out. The `frida` directory in the path also reinforces the connection to the Frida dynamic instrumentation tool.

**3. Core Functionality Identification:**

The primary function is clearly dependency management. The code defines various ways to find and incorporate external libraries needed by Frida during its build process. This involves:

* **Dependency Factories:**  The `@factory_methods` decorator and `DependencyFactory` class indicate a pattern for creating dependency objects based on different detection methods.
* **Detection Methods:** The code implements checks using `pkg-config`, CMake, built-in compiler features, and direct system library searches.
* **Specific Dependency Handlers:**  Classes like `NetcdfFactory`, `DlBuiltinDependency`, `OpenMPDependency`, etc., handle the specifics of detecting individual libraries. They check for headers, libraries, and sometimes use configuration tools.
* **Dependency Properties:**  The dependency objects store information like include paths, library paths, and version numbers.

**4. Connecting to Reverse Engineering:**

This requires thinking about *why* Frida needs these dependencies.

* **`dl` (Dynamic Linking):**  Crucial for Frida's core functionality of injecting into and interacting with running processes. Reverse engineering often involves understanding how programs load and use libraries.
* **`netcdf`:** While not directly related to *core* reverse engineering tasks,  it might be used for analyzing data formats or scientific applications that Frida instruments.
* **`OpenMP` (Parallel Processing):** If the target application uses multi-threading via OpenMP, Frida's ability to intercept and analyze these threads could be valuable.
* **`pcap` (Packet Capture):**  Essential for network-related reverse engineering, allowing Frida to intercept and inspect network traffic.
* **`openssl`, `libgcrypt`, `gpgme`:** Cryptography is a frequent area of interest in reverse engineering. These dependencies suggest Frida might interact with or analyze cryptographic functions.
* **`curses`:** Less common in modern applications, but might appear in older or terminal-based software.
* **`shaderc`:** Relevant when reverse engineering graphics applications or games that use shaders.

**5. Identifying Low-Level, Kernel, and Framework Connections:**

* **Binary/Low-Level:** The use of `dlopen` and library linking directly deals with how executables and shared libraries are loaded and interact at the binary level.
* **Linux/Android Kernel:** `dlopen` is a fundamental Linux system call. On Android, similar mechanisms exist in the Android runtime (ART). The `pcap` dependency relates directly to network interfaces managed by the kernel.
* **Android Framework:** While this specific file doesn't have explicit Android framework code, the `frida` context implies that the build process using these dependencies will eventually result in Frida components that *do* interact with the Android framework (e.g., hooking system services).

**6. Logical Reasoning and Input/Output Examples:**

For each dependency handler, consider:

* **Input:** The user's `meson.build` file might request a specific dependency (e.g., `dependency('openssl')`). The build environment and compiler settings are also implicit inputs.
* **Processing:** The code checks for the dependency using the configured methods.
* **Output:**  A `Dependency` object is created, indicating success or failure, along with relevant compile and link arguments.

Examples:

* **`DlBuiltinDependency`:** If the compiler has `dlopen`, it's found. Output: `is_found = True`.
* **`OpenMPDependency`:** If the compiler defines `_OPENMP`, it tries to map the value to a version. Output: `version = '5.1'`, `is_found = True`, along with compiler/linker flags.
* **`CursesSystemDependency`:** It tries different library names and header files. Output: If `ncursesw` and `ncursesw/ncurses.h` are found, `is_found = True`, `link_args` set to the path of `ncursesw`.

**7. Common User/Programming Errors:**

Think about what could go wrong from a user's perspective:

* **Missing Dependencies:** The most common error is not having the required libraries installed on the system. Meson will fail to find them.
* **Incorrect Configuration:**  Users might specify incorrect dependency names or versions in their `meson.build` files.
* **Conflicting Dependencies:**  Different libraries might have conflicting symbols or ABI (Application Binary Interface) incompatibilities.
* **Cross-Compilation Issues:**  Finding dependencies for a target architecture different from the build machine can be complex.
* **Static vs. Shared Linking:**  Users might request static linking when only shared libraries are available, or vice versa.

**8. Tracing User Operations:**

The journey starts with the user:

1. **Writes `meson.build`:** The user defines their project's dependencies using `dependency('name')`.
2. **Runs `meson setup builddir`:** Meson reads the `meson.build` file and starts the dependency resolution process.
3. **Meson calls dependency factories:** For each dependency, Meson iterates through the registered factories (like the ones in this file).
4. **Detection methods are executed:**  The factory methods (e.g., checking for `pkg-config` files, running CMake, or compiling test code) are invoked.
5. **This `misc.py` file is involved:** When a dependency like `openssl`, `pcap`, etc., is requested, the corresponding factory function in `misc.py` is called.
6. **Dependency object is created:**  A `Dependency` object is returned, containing information about whether the dependency was found and how to use it.
7. **Build proceeds (or fails):**  If all dependencies are found, the build continues. Otherwise, Meson reports an error.

**9. Structuring the Explanation:**

Organize the information logically:

* Start with a general overview of the file's purpose.
* Explain the core concepts like dependency factories and detection methods.
* Detail the functionality of individual dependency handlers, highlighting their relevance to reverse engineering and low-level aspects.
* Provide concrete examples of logical reasoning (input/output).
* Discuss common user errors.
* Describe the user's path to triggering this code.

**10. Refinement and Clarity:**

Review the explanation for clarity, accuracy, and completeness. Use precise terminology and avoid jargon where possible. Ensure the examples are easy to understand. For instance,  initially, I might have just said "it checks for dependencies," but refining it to describe *how* it checks (pkg-config, CMake, etc.) makes it much more informative. Similarly, instead of just listing dependencies related to reverse engineering, explaining *why* they are relevant strengthens the answer.
This Python code file, `misc.py`, located within the `frida-tools` project, plays a crucial role in **detecting and managing various external dependencies** required to build the Frida dynamic instrumentation toolkit. It's a part of the Meson build system integration for Frida.

Here's a breakdown of its functionalities:

**1. Dependency Detection Logic:**

* **Defines Dependency Factories:** The file sets up "factories" (using the `@factory_methods` decorator and `DependencyFactory` class) for various external libraries. These factories encapsulate different methods for finding a specific dependency on the system.
* **Implements Specific Dependency Handlers:**  It contains classes (e.g., `NetcdfFactory`, `DlBuiltinDependency`, `OpenMPDependency`) that implement the logic for finding specific libraries. This logic involves:
    * **Checking for `pkg-config` files:**  A standard way to get compile and link flags for libraries.
    * **Using CMake's `find_package`:**  Leveraging CMake's ability to locate dependencies.
    * **Checking for headers:** Verifying the presence of necessary header files.
    * **Searching for libraries:** Attempting to find the library files themselves.
    * **Using configuration tools:** Executing tools like `pcap-config` or `cups-config` to retrieve necessary flags.
    * **Built-in checks:**  For some fundamental dependencies, it checks directly for compiler features (e.g., `dlopen`).
* **Supports Multiple Detection Methods:** For many dependencies, it tries multiple methods (e.g., `PKGCONFIG` then `CMAKE` then `SYSTEM`) to increase the chances of finding the library.

**2. Dependency Information Storage:**

* When a dependency is found, the corresponding handler class creates a `Dependency` object (or a subclass like `BuiltinDependency`, `SystemDependency`, `CMakeDependency`, etc.).
* These objects store important information about the dependency, such as:
    * **Include directories:** Paths to header files.
    * **Library directories:** Paths to library files.
    * **Link arguments:** Flags needed to link against the library.
    * **Compile arguments:** Flags needed to compile code that uses the library.
    * **Version:** The version of the found library.
    * **Whether the dependency was found (`is_found`).**

**3. Handling Variations and Platform Differences:**

* **Language Support:** Some dependency factories (like `netcdf_factory`) are aware of the programming language being used (C, C++, Fortran) and adjust the search accordingly.
* **Platform-Specific Checks:**  Code like in `BlocksDependency` checks if the system is Darwin (macOS) and handles blocks language extensions differently.
* **Compiler-Specific Logic:**  The `OpenMPDependency` class has specific handling for different compilers (like NAG Fortran and PGI) that might not define the standard `_OPENMP` macro.

**Relationship to Reverse Engineering:**

This file directly relates to reverse engineering because the libraries it helps find are often crucial for Frida's core functionality and for instrumenting various types of applications. Here are some examples:

* **`dl` (Dynamic Linking):**  This dependency is fundamental. Frida relies heavily on dynamic linking to inject its agent into target processes. The `dlopen` function (checked by `DlBuiltinDependency` and `DlSystemDependency`) is the core function for loading shared libraries at runtime in Linux and Android. Reverse engineers need to understand how dynamic linking works to analyze how applications load and use libraries. Frida's ability to intercept calls to functions in dynamically linked libraries is a cornerstone of its power.

    * **Example:** When Frida attaches to a process, it uses `dlopen` (or its platform equivalent) to load its agent library into the target process's memory space. Understanding how `dlopen` works, what arguments it takes, and what it returns is essential for reverse engineering Frida's injection mechanism.

* **`pcap` (Packet Capture):**  If Frida needs to intercept and analyze network traffic generated by an application (common in mobile app reverse engineering or analyzing network protocols), the `pcap` library is essential. Reverse engineers use tools like Wireshark (which also uses `libpcap`) to examine network packets. Frida can leverage `libpcap` to dynamically intercept and modify network communication.

    * **Example:** A reverse engineer might use Frida with `pcap` to intercept the HTTPS traffic of a mobile application to understand the API calls it makes to a server. They could then analyze the captured packets or even modify them to test for vulnerabilities.

* **`openssl`, `libcrypto`, `libssl`:**  These dependencies are for handling secure communication (SSL/TLS) and cryptography. Many applications use these libraries. Frida needs them to potentially interact with encrypted communication or to analyze cryptographic implementations within an application.

    * **Example:**  A reverse engineer might use Frida to hook functions within `libssl` during an HTTPS handshake to extract encryption keys or to analyze how an application implements certificate pinning.

**Relationship to Binary Underpinnings, Linux, Android Kernel/Framework:**

* **Binary Level:** The detection of libraries and linking directly relates to the binary structure of executables and shared libraries (e.g., ELF format on Linux, Mach-O on macOS, PE on Windows). The link arguments determine how the different binary pieces are combined.
* **Linux Kernel:**  Dependencies like `dl` and `pcap` have direct ties to the Linux kernel. `dlopen` is a system call that interacts with the kernel's dynamic loader. `pcap` interacts with network interfaces managed by the kernel.
* **Android Kernel:**  On Android, similar concepts apply, though the specific implementations might differ. The Android runtime (ART) handles dynamic linking.
* **Android Framework:** While this specific file doesn't directly interact with the Android framework, the libraries it helps find (like `openssl`) are used extensively within the Android framework. Frida, once built, can then be used to interact with the Android framework.

**Logical Reasoning with Hypothetical Input/Output:**

Let's consider the `OpenMPDependency`:

* **Hypothetical Input:** The build system is using GCC, and the compiler is invoked with the `-fopenmp` flag.
* **Processing:**
    * `self.clib_compiler.get_define('_OPENMP', ...)` is called. Because `-fopenmp` is used, the GCC preprocessor will define `_OPENMP`.
    * The value of `_OPENMP` is retrieved (e.g., "201511").
    * The code looks up this value in the `VERSIONS` dictionary, finding '4.5'.
    * It checks for the `omp.h` header.
    * It adds the appropriate OpenMP compiler and linker flags.
* **Hypothetical Output:**
    * `self.is_found` will be `True`.
    * `self.version` will be '4.5'.
    * `self.compile_args` will contain compiler flags like `-fopenmp`.
    * `self.link_args` will contain linker flags like `-fopenmp`.

**Common User or Programming Errors:**

* **Missing Dependencies:** The most common error is that the user's system doesn't have the required libraries installed (e.g., `libpcap-dev` on Debian/Ubuntu). Meson will fail to find the dependency and the build will fail.

    * **Example:** If a user tries to build Frida on a fresh Ubuntu system without installing `libpcap-dev`, the `pcap_factory` will likely fail to find the `pcap-config` tool or the `pcap.h` header, resulting in a build error.

* **Incorrectly Configured Paths:** If the libraries are installed in non-standard locations, Meson might not find them. Users might need to set environment variables (like `PKG_CONFIG_PATH` for `pkg-config`) to help Meson locate the dependencies.

    * **Example:** If a user manually compiled and installed `openssl` to `/opt/openssl`, but didn't configure `PKG_CONFIG_PATH` or other relevant environment variables, Meson might not find it even though it's present on the system.

* **Version Mismatches:** Sometimes a project requires a specific version of a dependency. If the system has an older or newer version, the build might fail, or runtime issues might occur. While this file has some version checking (e.g., in `CursesSystemDependency`), it primarily focuses on *finding* the dependency.

* **Static vs. Shared Linking Issues:** If the build is configured to link statically against a library, but only shared libraries are available (or vice versa), the dependency detection might fail or lead to linker errors. The `shaderc_factory` demonstrates handling of static vs. shared preferences.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **User Clones the Frida Repository:** The user obtains the Frida source code, including the `frida-tools` subdirectory.
2. **User Navigates to the `frida-tools` Directory:** The user opens a terminal and goes into the `frida-tools` directory.
3. **User Initiates the Build Process:** The user typically runs commands like:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install meson ninja
   meson setup build
   cd build
   ninja
   ```
4. **Meson Executes:** During the `meson setup build` phase, Meson reads the `meson.build` files in the project.
5. **Dependency Declaration in `meson.build`:** The `meson.build` files will contain declarations like `dependency('pcap')`, `dependency('openssl')`, etc.
6. **Meson Calls Dependency Factories:** When Meson encounters a `dependency()` call, it looks up the corresponding dependency factory. For the dependencies handled in `misc.py`, the functions decorated with `@factory_methods` will be called.
7. **Code in `misc.py` is Executed:**  The logic within the relevant dependency factory (e.g., `pcap_factory` for `dependency('pcap')`) in `misc.py` is executed to attempt to find the dependency on the system.
8. **Error or Success:** If the dependency is found, the build process continues. If not, Meson will report an error, and the user might need to investigate why the dependency wasn't found.

Therefore, a user encountering issues with finding specific dependencies during the Frida build process will likely be indirectly interacting with the code in `misc.py`. Debugging efforts might involve checking if the necessary libraries are installed, if environment variables are set correctly, and potentially looking at Meson's output to see which dependency checks are failing.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/dependencies/misc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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

# This file contains the detection logic for miscellaneous external dependencies.
from __future__ import annotations

import functools
import re
import typing as T

from .. import mesonlib
from .. import mlog
from .base import DependencyException, DependencyMethods
from .base import BuiltinDependency, SystemDependency
from .cmake import CMakeDependency, CMakeDependencyFactory
from .configtool import ConfigToolDependency
from .detect import packages
from .factory import DependencyFactory, factory_methods
from .pkgconfig import PkgConfigDependency

if T.TYPE_CHECKING:
    from ..environment import Environment
    from .factory import DependencyGenerator


@factory_methods({DependencyMethods.PKGCONFIG, DependencyMethods.CMAKE})
def netcdf_factory(env: 'Environment',
                   for_machine: 'mesonlib.MachineChoice',
                   kwargs: T.Dict[str, T.Any],
                   methods: T.List[DependencyMethods]) -> T.List['DependencyGenerator']:
    language = kwargs.get('language', 'c')
    if language not in ('c', 'cpp', 'fortran'):
        raise DependencyException(f'Language {language} is not supported with NetCDF.')

    candidates: T.List['DependencyGenerator'] = []

    if DependencyMethods.PKGCONFIG in methods:
        if language == 'fortran':
            pkg = 'netcdf-fortran'
        else:
            pkg = 'netcdf'

        candidates.append(functools.partial(PkgConfigDependency, pkg, env, kwargs, language=language))

    if DependencyMethods.CMAKE in methods:
        candidates.append(functools.partial(CMakeDependency, 'NetCDF', env, kwargs, language=language))

    return candidates

packages['netcdf'] = netcdf_factory


class DlBuiltinDependency(BuiltinDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.62.0', "consider checking for `dlopen` with and without `find_library('dl')`")

        if self.clib_compiler.has_function('dlopen', '#include <dlfcn.h>', env)[0]:
            self.is_found = True


class DlSystemDependency(SystemDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.62.0', "consider checking for `dlopen` with and without `find_library('dl')`")

        h = self.clib_compiler.has_header('dlfcn.h', '', env)
        self.link_args = self.clib_compiler.find_library('dl', env, [], self.libtype)

        if h[0] and self.link_args:
            self.is_found = True


class OpenMPDependency(SystemDependency):
    # Map date of specification release (which is the macro value) to a version.
    VERSIONS = {
        '202111': '5.2',
        '202011': '5.1',
        '201811': '5.0',
        '201611': '5.0-revision1',  # This is supported by ICC 19.x
        '201511': '4.5',
        '201307': '4.0',
        '201107': '3.1',
        '200805': '3.0',
        '200505': '2.5',
        '200203': '2.0',
        '199810': '1.0',
    }

    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        language = kwargs.get('language')
        super().__init__('openmp', environment, kwargs, language=language)
        self.is_found = False
        if self.clib_compiler.get_id() == 'nagfor':
            # No macro defined for OpenMP, but OpenMP 3.1 is supported.
            self.version = '3.1'
            self.is_found = True
            self.compile_args = self.link_args = self.clib_compiler.openmp_flags()
            return
        if self.clib_compiler.get_id() == 'pgi':
            # through at least PGI 19.4, there is no macro defined for OpenMP, but OpenMP 3.1 is supported.
            self.version = '3.1'
            self.is_found = True
            self.compile_args = self.link_args = self.clib_compiler.openmp_flags()
            return

        try:
            openmp_date = self.clib_compiler.get_define(
                '_OPENMP', '', self.env, self.clib_compiler.openmp_flags(), [self], disable_cache=True)[0]
        except mesonlib.EnvironmentException as e:
            mlog.debug('OpenMP support not available in the compiler')
            mlog.debug(e)
            openmp_date = None

        if openmp_date:
            try:
                self.version = self.VERSIONS[openmp_date]
            except KeyError:
                mlog.debug(f'Could not find an OpenMP version matching {openmp_date}')
                if openmp_date == '_OPENMP':
                    mlog.debug('This can be caused by flags such as gcc\'s `-fdirectives-only`, which affect preprocessor behavior.')
                return

            if self.clib_compiler.get_id() == 'clang-cl':
                # this is necessary for clang-cl, see https://github.com/mesonbuild/meson/issues/5298
                clangcl_openmp_link_args = self.clib_compiler.find_library("libomp", self.env, [])
                if not clangcl_openmp_link_args:
                    mlog.log(mlog.yellow('WARNING:'), 'OpenMP found but libomp for clang-cl missing.')
                    return
                self.link_args.extend(clangcl_openmp_link_args)

            # Flang has omp_lib.h
            header_names = ('omp.h', 'omp_lib.h')
            for name in header_names:
                if self.clib_compiler.has_header(name, '', self.env, dependencies=[self], disable_cache=True)[0]:
                    self.is_found = True
                    self.compile_args.extend(self.clib_compiler.openmp_flags())
                    self.link_args.extend(self.clib_compiler.openmp_link_flags())
                    break
            if not self.is_found:
                mlog.log(mlog.yellow('WARNING:'), 'OpenMP found but omp.h missing.')

packages['openmp'] = OpenMPDependency


class ThreadDependency(SystemDependency):
    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__(name, environment, kwargs)
        self.is_found = True
        # Happens if you are using a language with threads
        # concept without C, such as plain Cuda.
        if not self.clib_compiler:
            self.compile_args = []
            self.link_args = []
        else:
            self.compile_args = self.clib_compiler.thread_flags(environment)
            self.link_args = self.clib_compiler.thread_link_flags(environment)


class BlocksDependency(SystemDependency):
    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__('blocks', environment, kwargs)
        self.name = 'blocks'
        self.is_found = False

        if self.env.machines[self.for_machine].is_darwin():
            self.compile_args = []
            self.link_args = []
        else:
            self.compile_args = ['-fblocks']
            self.link_args = ['-lBlocksRuntime']

            if not self.clib_compiler.has_header('Block.h', '', environment, disable_cache=True) or \
               not self.clib_compiler.find_library('BlocksRuntime', environment, []):
                mlog.log(mlog.red('ERROR:'), 'BlocksRuntime not found.')
                return

        source = '''
            int main(int argc, char **argv)
            {
                int (^callback)(void) = ^ int (void) { return 0; };
                return callback();
            }'''

        with self.clib_compiler.compile(source, extra_args=self.compile_args + self.link_args) as p:
            if p.returncode != 0:
                mlog.log(mlog.red('ERROR:'), 'Compiler does not support blocks extension.')
                return

            self.is_found = True

packages['blocks'] = BlocksDependency


class PcapDependencyConfigTool(ConfigToolDependency):

    tools = ['pcap-config']
    tool_name = 'pcap-config'

    # version 1.10.2 added error checking for invalid arguments
    # version 1.10.3 will hopefully add actual support for --version
    skip_version = '--help'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')
        if self.version is None:
            # older pcap-config versions don't support this
            self.version = self.get_pcap_lib_version()

    def get_pcap_lib_version(self) -> T.Optional[str]:
        # Since we seem to need to run a program to discover the pcap version,
        # we can't do that when cross-compiling
        # FIXME: this should be handled if we have an exe_wrapper
        if not self.env.machines.matches_build_machine(self.for_machine):
            return None

        v = self.clib_compiler.get_return_value('pcap_lib_version', 'string',
                                                '#include <pcap.h>', self.env, [], [self])
        v = re.sub(r'libpcap version ', '', str(v))
        v = re.sub(r' -- Apple version.*$', '', v)
        return v


class CupsDependencyConfigTool(ConfigToolDependency):

    tools = ['cups-config']
    tool_name = 'cups-config'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--ldflags', '--libs'], 'link_args')


class LibWmfDependencyConfigTool(ConfigToolDependency):

    tools = ['libwmf-config']
    tool_name = 'libwmf-config'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')


class LibGCryptDependencyConfigTool(ConfigToolDependency):

    tools = ['libgcrypt-config']
    tool_name = 'libgcrypt-config'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')
        self.version = self.get_config_value(['--version'], 'version')[0]


class GpgmeDependencyConfigTool(ConfigToolDependency):

    tools = ['gpgme-config']
    tool_name = 'gpg-config'

    def __init__(self, name: str, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')
        self.version = self.get_config_value(['--version'], 'version')[0]


class ShadercDependency(SystemDependency):

    def __init__(self, environment: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__('shaderc', environment, kwargs)

        static_lib = 'shaderc_combined'
        shared_lib = 'shaderc_shared'

        libs = [shared_lib, static_lib]
        if self.static:
            libs.reverse()

        cc = self.get_compiler()

        for lib in libs:
            self.link_args = cc.find_library(lib, environment, [])
            if self.link_args is not None:
                self.is_found = True

                if self.static and lib != static_lib:
                    mlog.warning(f'Static library {static_lib!r} not found for dependency '
                                 f'{self.name!r}, may not be statically linked')

                break


class CursesConfigToolDependency(ConfigToolDependency):

    """Use the curses config tools."""

    tool = 'curses-config'
    # ncurses5.4-config is for macOS Catalina
    tools = ['ncursesw6-config', 'ncursesw5-config', 'ncurses6-config', 'ncurses5-config', 'ncurses5.4-config']

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any], language: T.Optional[str] = None):
        super().__init__(name, env, kwargs, language)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')
        self.link_args = self.get_config_value(['--libs'], 'link_args')


class CursesSystemDependency(SystemDependency):

    """Curses dependency the hard way.

    This replaces hand rolled find_library() and has_header() calls. We
    provide this for portability reasons, there are a large number of curses
    implementations, and the differences between them can be very annoying.
    """

    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)

        candidates = [
            ('pdcurses', ['pdcurses/curses.h']),
            ('ncursesw',  ['ncursesw/ncurses.h', 'ncurses.h']),
            ('ncurses',  ['ncurses/ncurses.h', 'ncurses/curses.h', 'ncurses.h']),
            ('curses',  ['curses.h']),
        ]

        # Not sure how else to elegantly break out of both loops
        for lib, headers in candidates:
            l = self.clib_compiler.find_library(lib, env, [])
            if l:
                for header in headers:
                    h = self.clib_compiler.has_header(header, '', env)
                    if h[0]:
                        self.is_found = True
                        self.link_args = l
                        # Not sure how to find version for non-ncurses curses
                        # implementations. The one in illumos/OpenIndiana
                        # doesn't seem to have a version defined in the header.
                        if lib.startswith('ncurses'):
                            v, _ = self.clib_compiler.get_define('NCURSES_VERSION', f'#include <{header}>', env, [], [self])
                            self.version = v.strip('"')
                        if lib.startswith('pdcurses'):
                            v_major, _ = self.clib_compiler.get_define('PDC_VER_MAJOR', f'#include <{header}>', env, [], [self])
                            v_minor, _ = self.clib_compiler.get_define('PDC_VER_MINOR', f'#include <{header}>', env, [], [self])
                            self.version = f'{v_major}.{v_minor}'

                        # Check the version if possible, emit a warning if we can't
                        req = kwargs.get('version')
                        if req:
                            if self.version:
                                self.is_found = mesonlib.version_compare(self.version, req)
                            else:
                                mlog.warning('Cannot determine version of curses to compare against.')

                        if self.is_found:
                            mlog.debug('Curses library:', l)
                            mlog.debug('Curses header:', header)
                            break
            if self.is_found:
                break


class IconvBuiltinDependency(BuiltinDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.60.0', "consider checking for `iconv_open` with and without `find_library('iconv')`")
        code = '''#include <iconv.h>\n\nint main() {\n    iconv_open("","");\n}''' # [ignore encoding] this is C, not python, Mr. Lint

        if self.clib_compiler.links(code, env)[0]:
            self.is_found = True


class IconvSystemDependency(SystemDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.60.0', "consider checking for `iconv_open` with and without find_library('iconv')")

        h = self.clib_compiler.has_header('iconv.h', '', env)
        self.link_args = self.clib_compiler.find_library('iconv', env, [], self.libtype)

        if h[0] and self.link_args:
            self.is_found = True


class IntlBuiltinDependency(BuiltinDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.59.0', "consider checking for `ngettext` with and without `find_library('intl')`")
        code = '''#include <libintl.h>\n\nint main() {\n    gettext("Hello world");\n}'''

        if self.clib_compiler.links(code, env)[0]:
            self.is_found = True


class IntlSystemDependency(SystemDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)
        self.feature_since = ('0.59.0', "consider checking for `ngettext` with and without `find_library('intl')`")

        h = self.clib_compiler.has_header('libintl.h', '', env)
        self.link_args = self.clib_compiler.find_library('intl', env, [], self.libtype)

        if h[0] and self.link_args:
            self.is_found = True

            if self.static:
                if not self._add_sub_dependency(iconv_factory(env, self.for_machine, {'static': True})):
                    self.is_found = False
                    return


class OpensslSystemDependency(SystemDependency):
    def __init__(self, name: str, env: 'Environment', kwargs: T.Dict[str, T.Any]):
        super().__init__(name, env, kwargs)

        dependency_kwargs = {
            'method': 'system',
            'static': self.static,
        }
        if not self.clib_compiler.has_header('openssl/ssl.h', '', env)[0]:
            return

        # openssl >= 3 only
        self.version = self.clib_compiler.get_define('OPENSSL_VERSION_STR', '#include <openssl/opensslv.h>', env, [], [self])[0]
        # openssl < 3 only
        if not self.version:
            version_hex = self.clib_compiler.get_define('OPENSSL_VERSION_NUMBER', '#include <openssl/opensslv.h>', env, [], [self])[0]
            if not version_hex:
                return
            version_hex = version_hex.rstrip('L')
            version_ints = [((int(version_hex.rstrip('L'), 16) >> 4 + i) & 0xFF) for i in (24, 16, 8, 0)]
            # since this is openssl, the format is 1.2.3a in four parts
            self.version = '.'.join(str(i) for i in version_ints[:3]) + chr(ord('a') + version_ints[3] - 1)

        if name == 'openssl':
            if self._add_sub_dependency(libssl_factory(env, self.for_machine, dependency_kwargs)) and \
                    self._add_sub_dependency(libcrypto_factory(env, self.for_machine, dependency_kwargs)):
                self.is_found = True
            return
        else:
            self.link_args = self.clib_compiler.find_library(name.lstrip('lib'), env, [], self.libtype)
            if not self.link_args:
                return

        if not self.static:
            self.is_found = True
        else:
            if name == 'libssl':
                if self._add_sub_dependency(libcrypto_factory(env, self.for_machine, dependency_kwargs)):
                    self.is_found = True
            elif name == 'libcrypto':
                use_threads = self.clib_compiler.has_header_symbol('openssl/opensslconf.h', 'OPENSSL_THREADS', '', env, dependencies=[self])[0]
                if not use_threads or self._add_sub_dependency(threads_factory(env, self.for_machine, {})):
                    self.is_found = True
                # only relevant on platforms where it is distributed with the libc, in which case it always succeeds
                sublib = self.clib_compiler.find_library('dl', env, [], self.libtype)
                if sublib:
                    self.link_args.extend(sublib)


@factory_methods({DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL, DependencyMethods.SYSTEM})
def curses_factory(env: 'Environment',
                   for_machine: 'mesonlib.MachineChoice',
                   kwargs: T.Dict[str, T.Any],
                   methods: T.List[DependencyMethods]) -> T.List['DependencyGenerator']:
    candidates: T.List['DependencyGenerator'] = []

    if DependencyMethods.PKGCONFIG in methods:
        pkgconfig_files = ['pdcurses', 'ncursesw', 'ncurses', 'curses']
        for pkg in pkgconfig_files:
            candidates.append(functools.partial(PkgConfigDependency, pkg, env, kwargs))

    # There are path handling problems with these methods on msys, and they
    # don't apply to windows otherwise (cygwin is handled separately from
    # windows)
    if not env.machines[for_machine].is_windows():
        if DependencyMethods.CONFIG_TOOL in methods:
            candidates.append(functools.partial(CursesConfigToolDependency, 'curses', env, kwargs))

        if DependencyMethods.SYSTEM in methods:
            candidates.append(functools.partial(CursesSystemDependency, 'curses', env, kwargs))

    return candidates
packages['curses'] = curses_factory


@factory_methods({DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM})
def shaderc_factory(env: 'Environment',
                    for_machine: 'mesonlib.MachineChoice',
                    kwargs: T.Dict[str, T.Any],
                    methods: T.List[DependencyMethods]) -> T.List['DependencyGenerator']:
    """Custom DependencyFactory for ShaderC.

    ShaderC's odd you get three different libraries from the same build
    thing are just easier to represent as a separate function than
    twisting DependencyFactory even more.
    """
    candidates: T.List['DependencyGenerator'] = []

    if DependencyMethods.PKGCONFIG in methods:
        # ShaderC packages their shared and static libs together
        # and provides different pkg-config files for each one. We
        # smooth over this difference by handling the static
        # keyword before handing off to the pkg-config handler.
        shared_libs = ['shaderc']
        static_libs = ['shaderc_combined', 'shaderc_static']

        if kwargs.get('static', env.coredata.get_option(mesonlib.OptionKey('prefer_static'))):
            c = [functools.partial(PkgConfigDependency, name, env, kwargs)
                 for name in static_libs + shared_libs]
        else:
            c = [functools.partial(PkgConfigDependency, name, env, kwargs)
                 for name in shared_libs + static_libs]
        candidates.extend(c)

    if DependencyMethods.SYSTEM in methods:
        candidates.append(functools.partial(ShadercDependency, env, kwargs))

    return candidates
packages['shaderc'] = shaderc_factory


packages['cups'] = cups_factory = DependencyFactory(
    'cups',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL, DependencyMethods.EXTRAFRAMEWORK, DependencyMethods.CMAKE],
    configtool_class=CupsDependencyConfigTool,
    cmake_name='Cups',
)

packages['dl'] = dl_factory = DependencyFactory(
    'dl',
    [DependencyMethods.BUILTIN, DependencyMethods.SYSTEM],
    builtin_class=DlBuiltinDependency,
    system_class=DlSystemDependency,
)

packages['gpgme'] = gpgme_factory = DependencyFactory(
    'gpgme',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    configtool_class=GpgmeDependencyConfigTool,
)

packages['libgcrypt'] = libgcrypt_factory = DependencyFactory(
    'libgcrypt',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    configtool_class=LibGCryptDependencyConfigTool,
)

packages['libwmf'] = libwmf_factory = DependencyFactory(
    'libwmf',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    configtool_class=LibWmfDependencyConfigTool,
)

packages['pcap'] = pcap_factory = DependencyFactory(
    'pcap',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    configtool_class=PcapDependencyConfigTool,
    pkgconfig_name='libpcap',
)

packages['threads'] = threads_factory = DependencyFactory(
    'threads',
    [DependencyMethods.SYSTEM, DependencyMethods.CMAKE],
    cmake_name='Threads',
    system_class=ThreadDependency,
)

packages['iconv'] = iconv_factory = DependencyFactory(
    'iconv',
    [DependencyMethods.BUILTIN, DependencyMethods.SYSTEM],
    builtin_class=IconvBuiltinDependency,
    system_class=IconvSystemDependency,
)

packages['intl'] = intl_factory = DependencyFactory(
    'intl',
    [DependencyMethods.BUILTIN, DependencyMethods.SYSTEM],
    builtin_class=IntlBuiltinDependency,
    system_class=IntlSystemDependency,
)

packages['openssl'] = openssl_factory = DependencyFactory(
    'openssl',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM, DependencyMethods.CMAKE],
    system_class=OpensslSystemDependency,
    cmake_class=CMakeDependencyFactory('OpenSSL', modules=['OpenSSL::Crypto', 'OpenSSL::SSL']),
)

packages['libcrypto'] = libcrypto_factory = DependencyFactory(
    'libcrypto',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM, DependencyMethods.CMAKE],
    system_class=OpensslSystemDependency,
    cmake_class=CMakeDependencyFactory('OpenSSL', modules=['OpenSSL::Crypto']),
)

packages['libssl'] = libssl_factory = DependencyFactory(
    'libssl',
    [DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM, DependencyMethods.CMAKE],
    system_class=OpensslSystemDependency,
    cmake_class=CMakeDependencyFactory('OpenSSL', modules=['OpenSSL::SSL']),
)
```