Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Understanding the Goal:**

The core request is to analyze a Python file (`misc.py`) within the Frida project and describe its functionality, especially concerning reverse engineering, low-level details, and potential usage errors, along with how a user might end up interacting with this code.

**2. Initial Code Scan (High-Level):**

The first step is to get a general idea of what the code does. I look for keywords and patterns:

* **`# SPDX-License-Identifier: Apache-2.0` and `Copyright`:**  Standard license and copyright information. Indicates it's likely part of a larger open-source project.
* **`from __future__ import annotations` and `import typing as T`:** Modern Python type hinting is used. This helps with understanding the intended types of variables and function arguments.
* **`from .. ... import ...`:**  Imports from other modules within the `mesonbuild` project. This tells me this file is part of a larger build system.
* **Decorators like `@factory_methods`:** This immediately signals a pattern for creating dependency objects using different methods (like `pkgconfig`, `cmake`).
* **Class definitions like `DlBuiltinDependency`, `OpenMPDependency`, etc.:** These look like representations of external dependencies that the build system needs to find.
* **Dictionaries like `packages['netcdf'] = netcdf_factory`:**  This seems to be a central registry or mapping of dependency names to their factory functions.
* **References to system libraries and tools (e.g., `dlopen`, `dlfcn.h`, `libdl`, `OpenMP`, `pcap-config`, `cups-config`):** This confirms the file deals with external system dependencies.
* **Methods like `has_function`, `has_header`, `find_library`, `get_define`, `links`:** These are typical functions a build system uses to probe the system for the presence of libraries and headers.

**3. Deeper Dive into Key Sections:**

Now, I start examining specific parts of the code based on the keywords and patterns identified:

* **Dependency Factories (`netcdf_factory`, `curses_factory`, `shaderc_factory`):**  I pay close attention to how these functions work. They take an environment, machine info, keyword arguments, and a list of dependency methods. They return a list of *generators* (using `functools.partial`), which suggests a deferred or prioritized approach to finding dependencies. The use of `PkgConfigDependency` and `CMakeDependency` hints at different ways of locating dependencies.

* **Individual Dependency Classes (`DlBuiltinDependency`, `OpenMPDependency`, etc.):**  I analyze what each class does:
    * **Base Classes:**  I note the inheritance from `BuiltinDependency` and `SystemDependency`. This suggests a common interface for representing dependencies.
    * **`__init__` methods:** I look for the core logic of how each dependency is detected. This often involves checking for headers, libraries, or compiler features.
    * **`is_found`:** A common attribute indicating whether the dependency was found.
    * **`compile_args` and `link_args`:**  These are crucial for telling the compiler and linker how to use the dependency.
    * **Version Detection:**  I notice different strategies for version detection (e.g., macros for OpenMP, config tools for pcap, checking header defines for curses).

* **The `packages` Dictionary:** I see how the factory functions are registered for specific dependency names.

**4. Connecting to the Request's Specific Points:**

Now, I explicitly address the questions in the prompt:

* **Functionality:** I synthesize the information gathered into a concise summary of the file's purpose – detecting and providing information about miscellaneous system dependencies.

* **Relationship to Reverse Engineering:**  I think about *why* Frida would need these dependencies. `dl` is a prime example for dynamic loading, which is fundamental to Frida's instrumentation. Other dependencies like `openssl` might be used for secure communication within Frida.

* **Binary/Kernel/Framework Knowledge:** I identify the dependencies that clearly relate to these areas:
    * `dl`: Directly interacts with the dynamic linker.
    * `OpenMP`, `threads`: Relate to multi-threading and concurrency.
    * `pcap`: For packet capture, often used in network analysis and security (relevant to reverse engineering network protocols).
    * `curses`: For terminal UI, less directly related but a common tool.

* **Logical Inference (Hypothetical Inputs/Outputs):**  For the dependency factories, I consider:
    * **Input:**  The dependency name (`netcdf`), the desired methods (`pkgconfig`), and maybe some specific version requirements.
    * **Output:** A list of dependency objects (or generators for them), each representing a potential way to satisfy the dependency.

* **Common Usage Errors:** I consider what could go wrong when a user tries to build a project using these dependencies:
    * Missing dependencies (the most common case).
    * Incorrectly configured build environments.
    * Version mismatches.
    * Problems with static vs. shared linking.

* **User Operation as Debugging Clue:** I think about the steps a user takes that would lead to this code being executed:
    1. Configuring the build system (e.g., using Meson).
    2. Meson trying to find the required dependencies.
    3. This `misc.py` file being called as part of the dependency detection process.

**5. Structuring the Explanation:**

Finally, I organize the information into a clear and readable format using headings and bullet points, as demonstrated in the example answer. I ensure that the explanations are specific and provide concrete examples where possible. I also make sure to connect the technical details back to the user's perspective and the context of the Frida project.

**Self-Correction/Refinement During the Process:**

* Initially, I might just list the dependencies. Then, I realize I need to explain *how* they are detected and *why* they are relevant to Frida.
* I might focus too much on the technical details of the Meson build system. I then need to step back and explain it in a way that's understandable even without deep Meson knowledge.
* I might miss some of the connections to reverse engineering. I then revisit the list of dependencies and consider their broader implications in security and analysis.

By following this systematic approach, I can effectively analyze the code and generate a comprehensive and informative explanation that addresses all aspects of the request.
This Python code file, `misc.py`, located within the Frida project's build system (using Meson), is responsible for **detecting and configuring various miscellaneous external dependencies** required to build Frida's Node.js bindings.

Here's a breakdown of its functionalities:

**1. Dependency Detection Logic:**

* **Defines "Dependency Factories":** The core of the file revolves around functions decorated with `@factory_methods`. These functions (like `netcdf_factory`, `curses_factory`, `shaderc_factory`) are responsible for creating lists of potential ways to find a specific dependency. They consider different methods like:
    * **PkgConfig:**  A standard way to retrieve compile and link flags for libraries.
    * **CMake:** Another popular build system that can provide dependency information.
    * **System:** Directly searching for headers and libraries on the system.
    * **ConfigTool:**  Using specific command-line tools (like `pcap-config`, `cups-config`) provided by the dependency itself.
    * **Builtin:**  Checking for the presence of specific functions or language features (like `dlopen` or `gettext`).
* **Implements "Dependency Classes":** The file defines several classes (inheriting from `BuiltinDependency`, `SystemDependency`, `ConfigToolDependency`, `CMakeDependency`) that represent individual dependencies. Each class encapsulates the logic to detect and retrieve the necessary compiler flags, linker flags, and version information for that specific dependency.
* **Registers Dependencies:** The `packages` dictionary maps dependency names (e.g., 'netcdf', 'dl', 'openmp') to their corresponding factory functions or dependency classes. This acts as a central registry for dependency management.

**2. Relationship to Reverse Engineering:**

Several dependencies handled in this file have direct or indirect relevance to reverse engineering techniques:

* **`dl` (Dynamic Linking):** This dependency is crucial for Frida's core functionality. Frida operates by injecting code into running processes. The `dl` library (specifically `dlopen`) is the standard way in Linux and other Unix-like systems to dynamically load shared libraries (like Frida's agent) into a process at runtime.
    * **Example:** Frida uses `dlopen` to load its agent library into the target process's memory space. This agent then performs the instrumentation tasks. The `DlBuiltinDependency` and `DlSystemDependency` classes ensure that the build system can find the necessary headers (`dlfcn.h`) and the `dl` library itself.
* **`pcap` (Packet Capture):** While not directly involved in code injection, `pcap` is a fundamental library for network analysis. Reverse engineers often analyze network traffic to understand application behavior or identify vulnerabilities. Frida itself might use `pcap` for certain network-related instrumentation or analysis tasks (though not explicitly shown in this file).
    * **Example:** A reverse engineer might use Frida to intercept network calls made by an application and then use `pcap` (or a tool that uses `pcap`) to analyze the captured packets for sensitive information or communication protocols. The `PcapDependencyConfigTool` class helps find the `pcap-config` tool to get the correct compiler and linker flags for libpcap.
* **`openssl` (Cryptography):**  Reverse engineers frequently encounter encryption and cryptographic functions in applications. Having `openssl` as a dependency suggests that Frida or its components might use it for secure communication, handling encrypted data, or interacting with applications that utilize TLS/SSL.
    * **Example:**  If Frida communicates with a remote server, it might use `openssl` to establish a secure connection. Reverse engineers might use Frida to intercept cryptographic operations and understand how an application handles sensitive data. The `OpensslSystemDependency` and associated factory functions ensure the `openssl` library (and potentially its sub-libraries `libssl` and `libcrypto`) are available during the build.

**3. Relationship to Binary Underlying, Linux, Android Kernel & Framework:**

* **`dl`:**  As mentioned before, `dl` directly interacts with the operating system's dynamic linker, a core component of the Linux and Android systems. It's a low-level interface for managing shared libraries.
* **`threads` (POSIX Threads):**  Multi-threading is a fundamental concept in modern operating systems. Frida and the applications it instruments often use threads. This dependency ensures that the necessary compiler and linker flags for thread support are included.
    * **Example:** Frida's agent might use multiple threads to handle different instrumentation tasks concurrently. The `ThreadDependency` class uses compiler-specific flags to enable thread support.
* **`blocks` (Blocks Language Extension):** This dependency is specific to Apple's platforms (macOS, iOS). Blocks are a language-level feature for creating closures. While less common in general Linux/Android kernel development, it might be relevant for Frida's interaction with iOS applications.
* **Kernel (Indirectly):** While not directly interacting with the kernel in this file, dependencies like `dl` and `threads` are essential for user-space applications to interact with kernel services and manage resources. Frida, by injecting code, ultimately operates within the context of the target process, which interacts with the kernel.
* **Android Framework (Indirectly):**  Some of the dependencies could be relevant for instrumenting Android applications that use native libraries or interact with lower-level system components. For example, `openssl` is used extensively in Android.

**4. Logical Inference (Hypothetical Input and Output):**

Let's consider the `netcdf_factory` as an example:

* **Hypothetical Input:**
    * `env`: An `Environment` object representing the build environment.
    * `for_machine`:  Specifies the target architecture (e.g., Linux x86_64).
    * `kwargs`: `{'language': 'cpp'}`  (Indicates the project uses C++).
    * `methods`: `[DependencyMethods.PKGCONFIG, DependencyMethods.CMAKE]` (The build system will try PkgConfig first, then CMake).

* **Logical Output:**
    A list containing two `partial` objects (which are callable):
    1. `functools.partial(PkgConfigDependency, 'netcdf', env, kwargs, language='cpp')`
    2. `functools.partial(CMakeDependency, 'NetCDF', env, kwargs, language='cpp')`

    This means the build system will first try to find the `netcdf` dependency using PkgConfig (looking for a `netcdf.pc` file). If that fails, it will then try to find it using CMake (searching for a `NetCDF` CMake package).

**5. User or Programming Common Usage Errors:**

* **Missing Dependencies:** The most common error is when a required dependency is not installed on the system.
    * **Example:** If a user tries to build Frida without `libssl-dev` (or the equivalent package on their system), the `openssl` dependency check will fail, and the build will likely break. The error message might indicate that the `openssl/ssl.h` header file could not be found.
* **Incorrectly Configured Build Environment:** If environment variables like `PKG_CONFIG_PATH` or `CMAKE_PREFIX_PATH` are not set up correctly, the build system might fail to find dependencies even if they are installed.
    * **Example:** If `PKG_CONFIG_PATH` doesn't include the directory where `netcdf.pc` is located, the PkgConfig check for `netcdf` will fail.
* **Version Mismatches:** Sometimes, a dependency is installed, but the version is too old or too new for Frida's requirements. This might lead to compilation or linking errors.
    * **Example:** If Frida requires a specific version of `openssl` and the user has an older version installed, the build might fail due to missing functions or incompatible APIs.
* **Static vs. Shared Linking Issues:** The `static` keyword in `kwargs` influences whether the build system prefers static or shared libraries. If a static library is requested but not available, the build might fail or fall back to a shared library (potentially causing deployment issues).
    * **Example:** If `kwargs.get('static')` is True for `shaderc`, but only the shared library is available, the build system might issue a warning or fail to link statically.

**6. User Operations Leading to This Code:**

A user typically doesn't interact with this specific Python file directly. Instead, their actions during the Frida build process will trigger its execution:

1. **Cloning the Frida Repository:** The user downloads the Frida source code, which includes this file.
2. **Installing Build Dependencies:**  The user usually follows instructions to install the necessary build tools (like Meson, Python, compilers) and general dependencies. However, they might miss some specific "miscellaneous" dependencies.
3. **Configuring the Build with Meson:** The user runs the `meson` command in the build directory, specifying the source directory and build options.
    * **At this point, Meson starts analyzing the `meson.build` files and their dependencies.**
4. **Meson Executes Dependency Detection Logic:** When Meson encounters a dependency like `dependency('openssl')` in the `meson.build` files, it looks up the corresponding factory function in the `packages` dictionary within this `misc.py` file.
5. **Factory Functions are Called:** The relevant factory function (e.g., `openssl_factory`) is executed with information about the build environment and target machine.
6. **Dependency Classes are Instantiated:** The factory function creates instances of the appropriate dependency classes (e.g., `OpensslSystemDependency`).
7. **Detection Methods are Attempted:** The methods within the dependency class (like checking for headers, libraries, or running config tools) are executed to find the dependency.
8. **Compiler and Linker Flags are Collected:** If a dependency is found, the necessary compiler and linker flags are stored.
9. **Meson Generates Build Files:** Based on the detected dependencies and other configuration, Meson generates the final build files (like Makefiles or Ninja files).
10. **User Builds the Project:** The user runs a build command (like `ninja`) which uses the generated build files to compile and link Frida.

**Debugging Clue:**

If the build fails with an error related to a missing or incorrect version of a dependency handled in `misc.py`, this file becomes a crucial point for investigation. A developer might:

* **Examine the `packages` dictionary:** To see how the failing dependency is being detected.
* **Inspect the corresponding dependency class:** To understand the specific checks being performed (e.g., which headers are being looked for, which config tools are being executed).
* **Run the config tools manually:** If a `ConfigToolDependency` is involved, the developer might run the tool (e.g., `pcap-config --libs`) directly to see if it's working correctly and providing the expected output.
* **Check environment variables:** To ensure that paths to dependencies are correctly set.

In essence, `misc.py` is a vital part of Frida's build system, ensuring that all the necessary external libraries are found and configured correctly, including those with specific relevance to reverse engineering and low-level system interactions. Understanding its logic is crucial for troubleshooting build issues related to these dependencies.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/misc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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