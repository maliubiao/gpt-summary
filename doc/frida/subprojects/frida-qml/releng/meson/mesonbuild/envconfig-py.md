Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `envconfig.py` file within the Frida project and explain its relevance to reverse engineering, low-level concepts, and potential user errors.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick read-through to identify key data structures, classes, and important variables. Keywords like "configuration files," "native," "cross file," "environment variables," "compiler," "linker," "CPU," "system," and "binary" stand out. These give a high-level understanding of the file's purpose.

**3. Deconstructing the Classes:**

Next, focus on the individual classes (`Properties`, `MachineInfo`, `BinaryTable`, `CMakeVariables`). For each class:

* **Purpose:** What is the main responsibility of this class?  The docstrings and variable names provide clues.
* **Attributes:** What data does this class hold?  Note the types and potential values.
* **Methods:** What actions can be performed with this class? Analyze the input and output of each method.

**Example Breakdown (MachineInfo):**

* **Purpose:** Represents information about the target machine.
* **Attributes:** `system`, `cpu_family`, `cpu`, `endian`, `kernel`, `subsystem`. These directly relate to system architecture. The `is_64_bit` attribute is a calculated property.
* **Methods:** `from_literal` (parsing), `is_windows`, `is_linux`, etc. (OS detection), `get_exe_suffix`, `get_object_suffix` (binary naming conventions).

**4. Identifying Relationships and Data Flow:**

Consider how the classes interact. For example:

* `Properties` seems to load data from configuration files.
* `MachineInfo` likely receives information from these configurations or system detection.
* `BinaryTable` manages paths to compilers and tools.
* `CMakeVariables` handles CMake-specific configuration.

The docstring at the beginning of the file explicitly states that these classes hold "inputs" to the configuration process, contrasting them with `coredata` which holds "outputs."

**5. Connecting to Reverse Engineering:**

Now, link the functionalities to reverse engineering concepts:

* **Target Environment:** `MachineInfo` is crucial for understanding the architecture of the system being targeted for reverse engineering. Knowing the OS, CPU, and endianness is fundamental.
* **Tools:** `BinaryTable` manages the paths to tools like `objdump`, `readelf`, `strip`, debuggers (implicitly through compiler flags), which are essential for reverse engineering.
* **Compilation Process:** Understanding how the target was built (compiler, linker, flags) is helpful. While this file doesn't *execute* the build, it *configures* it, which is relevant.

**6. Connecting to Low-Level Concepts:**

Identify aspects related to operating systems, kernels, and hardware:

* **Operating System Detection:** `MachineInfo` has methods like `is_linux()`, `is_windows()`, etc., which directly relate to OS identification.
* **CPU Architecture:** `cpu_family`, `cpu`, `is_64_bit` in `MachineInfo` deal with CPU details.
* **Endianness:** The `endian` attribute in `MachineInfo` is a fundamental low-level concept.
* **Binary Formats:** `get_exe_suffix`, `get_object_suffix` relate to how executables and object files are named on different platforms.

**7. Logical Inference and Examples:**

Think about how the code might be used and potential scenarios:

* **Cross-Compilation:** The existence of "native" and "cross files" suggests support for building for different target architectures.
* **Conditional Logic:**  The `if` statements in methods like `get_exe_suffix` show how the build process adapts to different platforms.
* **Default Values:** Notice how some methods have default values or fallbacks if certain configuration options are missing.

**8. Identifying Potential User Errors:**

Consider how a user interacting with the build system might cause errors related to this file:

* **Incorrect Configuration Files:**  Supplying a `meson.build` file that references incorrect tool names or has incompatible settings.
* **Environment Variables:**  Not setting necessary environment variables (like `CC`, `CXX`) or setting them incorrectly.
* **Cross-Compilation Issues:**  Providing an invalid or incomplete cross-compilation configuration.

**9. Tracing User Operations:**

Think about the typical workflow when using Frida and how it leads to this configuration file being used:

* **Frida Installation:**  Likely involves a build process.
* **Targeting a Process:**  Frida needs to understand the architecture of the target process.
* **Customizing the Build:** Users might provide configuration files to tailor the Frida build.

**10. Structuring the Explanation:**

Organize the findings into logical sections:

* **Overview:** Briefly describe the file's purpose.
* **Functionality Breakdown:** Detail each class and its methods.
* **Relevance to Reverse Engineering:** Provide concrete examples.
* **Low-Level Concepts:** Explain the connections.
* **Logical Inference:** Offer possible scenarios.
* **User Errors:** Illustrate common mistakes.
* **User Operations:** Trace the path to this file.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file just loads environment variables."  **Correction:**  It loads from configuration files and *also* provides a structure for accessing environment variables.
* **Initial thought:** "The examples are too abstract." **Correction:**  Provide more specific examples related to Frida's use cases (e.g., targeting an Android app).
* **Initial thought:** "The connection to the kernel is weak." **Correction:** Emphasize how target architecture information is crucial for Frida's core functionality of interacting with processes at a low level, including potentially hooking into kernel functions (though this file doesn't directly do that).

By following these steps, systematically analyzing the code, and connecting it to the broader context of Frida and reverse engineering, a comprehensive and accurate explanation can be generated.
This Python file, `envconfig.py`, part of the Frida dynamic instrumentation toolkit's build system (using Meson), primarily serves to **define and manage configuration settings related to the build environment**. It acts as a central repository for information about the host and target machines, compilers, linkers, and other build tools.

Here's a breakdown of its functionalities:

**1. Data Structures for Configuration:**

* **`known_cpu_families`, `CPU_FAMILIES_64_BIT`:**  Defines lists of known CPU architectures. This is crucial for understanding the target platform during cross-compilation.
* **`ENV_VAR_COMPILER_MAP`, `ENV_VAR_TOOL_MAP`, `ENV_VAR_PROG_MAP`:**  These dictionaries map logical names for compilers (like 'c', 'cpp') and tools (like 'ar', 'objdump') to their corresponding environment variable names (like 'CC', 'CXX', 'AR'). This allows the build system to locate these tools based on the user's environment.
* **`DEPRECATED_ENV_PROG_MAP`:** Maps deprecated environment variable names to their newer counterparts for backward compatibility.
* **`CMakeSkipCompilerTest` (Enum):** Defines options for skipping compiler tests when using CMake as a subproject.
* **`Properties` (Class):**  Represents properties loaded from configuration files (like native and cross-compilation files). It handles settings like standard libraries, root directories, and CMake-specific options.
* **`MachineInfo` (Class):**  Stores information about a specific machine (host or target), including its operating system, CPU family, CPU architecture, and endianness. This is vital for cross-compilation scenarios.
* **`BinaryTable` (Class):**  Holds the paths to various binary executables (compilers, linkers, tools) used during the build process. It can detect compiler caches like `ccache` and `sccache`.
* **`CMakeVariables` (Class):** Stores CMake variables defined in configuration files.

**2. Abstraction of Configuration Sources:**

The file aims to abstract away the details of where configuration information comes from. It can load settings from:

* **Environment Variables:** Directly uses environment variables defined in the user's shell.
* **Meson Configuration Files:**  Parses native and cross-compilation files (likely in `.ini` format or a similar structure) to get target-specific settings.

**3. Helpers for Accessing Configuration:**

The classes provide methods to access the stored configuration data in a structured way, for example:

* `Properties.get_stdlib(language)`:  Gets the standard library for a given language.
* `MachineInfo.is_windows()`, `MachineInfo.is_linux()`: Checks the operating system.
* `BinaryTable.lookup_entry(name)`:  Finds the path to a specific binary.

**Relationship to Reverse Engineering:**

This file is directly relevant to reverse engineering in several ways, especially when Frida is used in cross-compilation scenarios (e.g., developing Frida gadgets or tools that will run on Android or other embedded systems):

* **Target Architecture Awareness:** The `MachineInfo` class is crucial for understanding the architecture of the target system being reverse engineered. Knowing the CPU family, endianness, and operating system is fundamental when analyzing binaries. Frida needs this information to build components that are compatible with the target.
    * **Example:** When attaching Frida to an Android application, Frida needs to be built for the ARM or x86 architecture of the Android device. The `MachineInfo` for the target Android system will guide the build process.
* **Toolchain Definition:**  The `BinaryTable` class manages the paths to compilers, linkers, and other tools. For cross-compilation, you'll need a specific toolchain targeting the architecture you're reverse engineering. This file helps configure which toolchain Frida will use.
    * **Example:** To build a Frida gadget for an ARM-based Android device, the `BinaryTable` will contain the paths to the ARM cross-compiler (e.g., `arm-linux-gnueabihf-gcc`) and linker.
* **Platform-Specific Settings:** The `Properties` class handles platform-specific settings that might be necessary for the build. This can include things like the location of standard libraries or SDKs for the target platform.
    * **Example:** When targeting iOS, you might need to specify the path to the iOS SDK.

**Examples of Connection to Binary 底层, Linux, Android Kernel & Framework:**

* **Binary 底层 (Binary Low-Level):**
    * **Endianness:** The `MachineInfo.endian` attribute directly reflects the byte order of the target architecture. This is critical when dealing with binary data during reverse engineering. Frida needs to know if the target is little-endian or big-endian to correctly interpret memory and data structures.
    * **Executable and Object File Formats:** The `MachineInfo.get_exe_suffix()` and `get_object_suffix()` methods are aware of platform-specific file extensions (`.exe` on Windows, `.o` on Linux). This is directly related to binary file formats.
* **Linux Kernel:**
    * **System Identification:** `MachineInfo.is_linux()` identifies if the target system is Linux-based. This influences build flags and library dependencies.
    * **Kernel Version (Potentially):** Although not explicitly present in the provided code snippet, the `MachineInfo` class could be extended to include kernel version information, which is relevant for understanding kernel-level functionalities and vulnerabilities.
* **Android Kernel & Framework:**
    * **Android as a System:** `MachineInfo.is_android()` specifically identifies Android as the target operating system.
    * **CPU Architectures:** The `known_cpu_families` list includes architectures common on Android devices like 'arm' and 'aarch64'. Frida needs to be compiled for the correct Android CPU architecture.
    * **Cross-Compilation:** Building Frida components for Android requires a cross-compilation setup. This file is central to configuring that setup, specifying the Android NDK (Native Development Kit) paths, compiler flags, etc.

**Logical Inference with Hypothetical Input and Output:**

Let's consider how the `BinaryTable.lookup_entry()` method might work:

**Hypothetical Input:**

* `name`: "objdump"

**Scenario 1: Environment Variable is Set**

* **Assume:** The user has the environment variable `OBJDUMP` set to `/opt/my_toolchains/binutils/objdump`.
* **Output:**  The method would likely return `['/opt/my_toolchains/binutils/objdump']`.

**Scenario 2: Entry in Configuration File**

* **Assume:** The `BinaryTable` was initialized with a `binaries` dictionary containing `{"objdump": ["/usr/bin/gobjdump"]}` from a configuration file.
* **Output:** The method would return `['/usr/bin/gobjdump']`.

**Scenario 3: Neither Environment Variable nor Configuration**

* **Assume:** The `OBJDUMP` environment variable is not set, and no entry for "objdump" exists in the loaded configuration.
* **Output:** The method would return `None`.

**Common User Errors and Examples:**

* **Incorrect Environment Variables:**
    * **Error:** User tries to build Frida for Android but hasn't set the `ANDROID_NDK_HOME` environment variable, which might be used by other parts of the build system based on configurations loaded by this file.
    * **Consequence:** The build process might fail because it cannot find the necessary Android development tools.
* **Mismatched Cross-Compilation Configuration:**
    * **Error:** The user provides a cross-compilation file that specifies the wrong CPU architecture for the target device. For example, trying to build for `arm` when the target is `aarch64`.
    * **Consequence:** The compiled Frida components will be incompatible with the target device and won't work.
* **Missing Dependencies:**
    * **Error:** The build system relies on certain tools being available in the system's PATH (or explicitly configured). If a tool like `pkg-config` is missing, the build might fail.
    * **Consequence:** The build will report an error indicating that the required tool is not found.

**User Operations Leading to This File:**

1. **Installing Frida from Source:** A user wants to build Frida from its source code.
2. **Running the Meson Configuration Step:** The user executes a command like `meson setup build`.
3. **Meson Reads Configuration Files:** During the `meson setup` phase, Meson parses `meson.build` files and potentially native (`meson.native`) and cross-compilation files (`meson.<target>.cross`).
4. **`envconfig.py` is Executed (Indirectly):**  Meson, during its configuration process, uses modules like `envconfig.py` to load and manage the configuration settings from these files and the environment. It uses the classes and functions defined in `envconfig.py` to represent and access this information.
5. **Accessing Tool Paths:** When the build system needs to find a compiler (e.g., for compiling the Frida agent), it might use `BinaryTable.lookup_entry('c')`. This function, guided by the data in `envconfig.py`, will check environment variables and configuration files for the path to the C compiler.
6. **Determining Target Architecture:** If it's a cross-compilation build, Meson will use the `MachineInfo` class, populated from the cross-compilation file, to understand the target's CPU, OS, and other properties.

**In summary, `envconfig.py` is a foundational part of Frida's build system, responsible for centralizing and managing configuration information. It plays a crucial role in ensuring that Frida can be built correctly for various target platforms, which is essential for its use in dynamic instrumentation and reverse engineering.**

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/envconfig.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2016 The Meson development team

from __future__ import annotations

from dataclasses import dataclass
import subprocess
import typing as T
from enum import Enum

from . import mesonlib
from .mesonlib import EnvironmentException, HoldableObject
from . import mlog
from pathlib import Path


# These classes contains all the data pulled from configuration files (native
# and cross file currently), and also assists with the reading environment
# variables.
#
# At this time there isn't an ironclad difference between this and other sources
# of state like `coredata`. But one rough guide is much what is in `coredata` is
# the *output* of the configuration process: the final decisions after tests.
# This, on the other hand has *inputs*. The config files are parsed, but
# otherwise minimally transformed. When more complex fallbacks (environment
# detection) exist, they are defined elsewhere as functions that construct
# instances of these classes.


known_cpu_families = (
    'aarch64',
    'alpha',
    'arc',
    'arm',
    'avr',
    'c2000',
    'c6000',
    'csky',
    'dspic',
    'e2k',
    'ft32',
    'ia64',
    'loongarch64',
    'm68k',
    'microblaze',
    'mips',
    'mips64',
    'msp430',
    'parisc',
    'pic24',
    'ppc',
    'ppc64',
    'riscv32',
    'riscv64',
    'rl78',
    'rx',
    's390',
    's390x',
    'sh4',
    'sparc',
    'sparc64',
    'sw_64',
    'wasm32',
    'wasm64',
    'x86',
    'x86_64',
)

# It would feel more natural to call this "64_BIT_CPU_FAMILIES", but
# python identifiers cannot start with numbers
CPU_FAMILIES_64_BIT = [
    'aarch64',
    'alpha',
    'ia64',
    'loongarch64',
    'mips64',
    'ppc64',
    'riscv64',
    's390x',
    'sparc64',
    'sw_64',
    'wasm64',
    'x86_64',
]

# Map from language identifiers to environment variables.
ENV_VAR_COMPILER_MAP: T.Mapping[str, str] = {
    # Compilers
    'c': 'CC',
    'cpp': 'CXX',
    'cs': 'CSC',
    'cython': 'CYTHON',
    'd': 'DC',
    'fortran': 'FC',
    'objc': 'OBJC',
    'objcpp': 'OBJCXX',
    'rust': 'RUSTC',
    'vala': 'VALAC',
    'nasm': 'NASM',

    # Linkers
    'c_ld': 'CC_LD',
    'cpp_ld': 'CXX_LD',
    'd_ld': 'DC_LD',
    'fortran_ld': 'FC_LD',
    'objc_ld': 'OBJC_LD',
    'objcpp_ld': 'OBJCXX_LD',
    'rust_ld': 'RUSTC_LD',
}

# Map from utility names to environment variables.
ENV_VAR_TOOL_MAP: T.Mapping[str, str] = {
    # Binutils
    'ar': 'AR',
    'as': 'AS',
    'ld': 'LD',
    'nm': 'NM',
    'objcopy': 'OBJCOPY',
    'objdump': 'OBJDUMP',
    'ranlib': 'RANLIB',
    'readelf': 'READELF',
    'size': 'SIZE',
    'strings': 'STRINGS',
    'strip': 'STRIP',
    'windres': 'WINDRES',

    # Other tools
    'cmake': 'CMAKE',
    'qmake': 'QMAKE',
    'pkg-config': 'PKG_CONFIG',
    'make': 'MAKE',
    'vapigen': 'VAPIGEN',
    'llvm-config': 'LLVM_CONFIG',
}

ENV_VAR_PROG_MAP = {**ENV_VAR_COMPILER_MAP, **ENV_VAR_TOOL_MAP}

# Deprecated environment variables mapped from the new variable to the old one
# Deprecated in 0.54.0
DEPRECATED_ENV_PROG_MAP: T.Mapping[str, str] = {
    'd_ld': 'D_LD',
    'fortran_ld': 'F_LD',
    'rust_ld': 'RUST_LD',
    'objcpp_ld': 'OBJCPP_LD',
}

class CMakeSkipCompilerTest(Enum):
    ALWAYS = 'always'
    NEVER = 'never'
    DEP_ONLY = 'dep_only'

class Properties:
    def __init__(
            self,
            properties: T.Optional[T.Dict[str, T.Optional[T.Union[str, bool, int, T.List[str]]]]] = None,
    ):
        self.properties = properties or {}

    def has_stdlib(self, language: str) -> bool:
        return language + '_stdlib' in self.properties

    # Some of get_stdlib, get_root, get_sys_root are wider than is actually
    # true, but without heterogeneous dict annotations it's not practical to
    # narrow them
    def get_stdlib(self, language: str) -> T.Union[str, T.List[str]]:
        stdlib = self.properties[language + '_stdlib']
        if isinstance(stdlib, str):
            return stdlib
        assert isinstance(stdlib, list)
        for i in stdlib:
            assert isinstance(i, str)
        return stdlib

    def get_root(self) -> T.Optional[str]:
        root = self.properties.get('root', None)
        assert root is None or isinstance(root, str)
        return root

    def get_sys_root(self) -> T.Optional[str]:
        sys_root = self.properties.get('sys_root', None)
        assert sys_root is None or isinstance(sys_root, str)
        return sys_root

    def get_pkg_config_libdir(self) -> T.Optional[T.List[str]]:
        p = self.properties.get('pkg_config_libdir', None)
        if p is None:
            return p
        res = mesonlib.listify(p)
        for i in res:
            assert isinstance(i, str)
        return res

    def get_cmake_defaults(self) -> bool:
        if 'cmake_defaults' not in self.properties:
            return True
        res = self.properties['cmake_defaults']
        assert isinstance(res, bool)
        return res

    def get_cmake_toolchain_file(self) -> T.Optional[Path]:
        if 'cmake_toolchain_file' not in self.properties:
            return None
        raw = self.properties['cmake_toolchain_file']
        assert isinstance(raw, str)
        cmake_toolchain_file = Path(raw)
        if not cmake_toolchain_file.is_absolute():
            raise EnvironmentException(f'cmake_toolchain_file ({raw}) is not absolute')
        return cmake_toolchain_file

    def get_cmake_skip_compiler_test(self) -> CMakeSkipCompilerTest:
        if 'cmake_skip_compiler_test' not in self.properties:
            return CMakeSkipCompilerTest.DEP_ONLY
        raw = self.properties['cmake_skip_compiler_test']
        assert isinstance(raw, str)
        try:
            return CMakeSkipCompilerTest(raw)
        except ValueError:
            raise EnvironmentException(
                '"{}" is not a valid value for cmake_skip_compiler_test. Supported values are {}'
                .format(raw, [e.value for e in CMakeSkipCompilerTest]))

    def get_cmake_use_exe_wrapper(self) -> bool:
        if 'cmake_use_exe_wrapper' not in self.properties:
            return True
        res = self.properties['cmake_use_exe_wrapper']
        assert isinstance(res, bool)
        return res

    def get_java_home(self) -> T.Optional[Path]:
        value = T.cast('T.Optional[str]', self.properties.get('java_home'))
        return Path(value) if value else None

    def get_bindgen_clang_args(self) -> T.List[str]:
        value = mesonlib.listify(self.properties.get('bindgen_clang_arguments', []))
        if not all(isinstance(v, str) for v in value):
            raise EnvironmentException('bindgen_clang_arguments must be a string or an array of strings')
        return T.cast('T.List[str]', value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, type(self)):
            return self.properties == other.properties
        return NotImplemented

    # TODO consider removing so Properties is less freeform
    def __getitem__(self, key: str) -> T.Optional[T.Union[str, bool, int, T.List[str]]]:
        return self.properties[key]

    # TODO consider removing so Properties is less freeform
    def __contains__(self, item: T.Union[str, bool, int, T.List[str]]) -> bool:
        return item in self.properties

    # TODO consider removing, for same reasons as above
    def get(self, key: str, default: T.Optional[T.Union[str, bool, int, T.List[str]]] = None) -> T.Optional[T.Union[str, bool, int, T.List[str]]]:
        return self.properties.get(key, default)

@dataclass(unsafe_hash=True)
class MachineInfo(HoldableObject):
    system: str
    cpu_family: str
    cpu: str
    endian: str
    kernel: T.Optional[str]
    subsystem: T.Optional[str]

    def __post_init__(self) -> None:
        self.is_64_bit: bool = self.cpu_family in CPU_FAMILIES_64_BIT

    def __repr__(self) -> str:
        return f'<MachineInfo: {self.system} {self.cpu_family} ({self.cpu})>'

    @classmethod
    def from_literal(cls, literal: T.Dict[str, str]) -> 'MachineInfo':
        minimum_literal = {'cpu', 'cpu_family', 'endian', 'system'}
        if set(literal) < minimum_literal:
            raise EnvironmentException(
                f'Machine info is currently {literal}\n' +
                'but is missing {}.'.format(minimum_literal - set(literal)))

        cpu_family = literal['cpu_family']
        if cpu_family not in known_cpu_families:
            mlog.warning(f'Unknown CPU family {cpu_family}, please report this at https://github.com/mesonbuild/meson/issues/new')

        endian = literal['endian']
        if endian not in ('little', 'big'):
            mlog.warning(f'Unknown endian {endian}')

        system = literal['system']
        kernel = literal.get('kernel', None)
        subsystem = literal.get('subsystem', None)

        return cls(system, cpu_family, literal['cpu'], endian, kernel, subsystem)

    def is_windows(self) -> bool:
        """
        Machine is windows?
        """
        return self.system == 'windows'

    def is_cygwin(self) -> bool:
        """
        Machine is cygwin?
        """
        return self.system == 'cygwin'

    def is_linux(self) -> bool:
        """
        Machine is linux?
        """
        return self.system == 'linux'

    def is_darwin(self) -> bool:
        """
        Machine is Darwin (iOS/tvOS/OS X)?
        """
        return self.system in {'darwin', 'ios', 'tvos'}

    def is_android(self) -> bool:
        """
        Machine is Android?
        """
        return self.system == 'android'

    def is_haiku(self) -> bool:
        """
        Machine is Haiku?
        """
        return self.system == 'haiku'

    def is_netbsd(self) -> bool:
        """
        Machine is NetBSD?
        """
        return self.system == 'netbsd'

    def is_openbsd(self) -> bool:
        """
        Machine is OpenBSD?
        """
        return self.system == 'openbsd'

    def is_dragonflybsd(self) -> bool:
        """Machine is DragonflyBSD?"""
        return self.system == 'dragonfly'

    def is_freebsd(self) -> bool:
        """Machine is FreeBSD?"""
        return self.system == 'freebsd'

    def is_sunos(self) -> bool:
        """Machine is illumos or Solaris?"""
        return self.system == 'sunos'

    def is_hurd(self) -> bool:
        """
        Machine is GNU/Hurd?
        """
        return self.system == 'gnu'

    def is_aix(self) -> bool:
        """
        Machine is aix?
        """
        return self.system == 'aix'

    def is_irix(self) -> bool:
        """Machine is IRIX?"""
        return self.system.startswith('irix')

    # Various prefixes and suffixes for import libraries, shared libraries,
    # static libraries, and executables.
    # Versioning is added to these names in the backends as-needed.
    def get_exe_suffix(self) -> str:
        if self.is_windows() or self.is_cygwin():
            return 'exe'
        else:
            return ''

    def get_object_suffix(self) -> str:
        if self.is_windows():
            return 'obj'
        else:
            return 'o'

    def libdir_layout_is_win(self) -> bool:
        return self.is_windows() or self.is_cygwin()

class BinaryTable:

    def __init__(
            self,
            binaries: T.Optional[T.Dict[str, T.Union[str, T.List[str]]]] = None,
    ):
        self.binaries: T.Dict[str, T.List[str]] = {}
        if binaries:
            for name, command in binaries.items():
                if not isinstance(command, (list, str)):
                    raise mesonlib.MesonException(
                        f'Invalid type {command!r} for entry {name!r} in cross file')
                self.binaries[name] = mesonlib.listify(command)
            if 'pkgconfig' in self.binaries:
                if 'pkg-config' not in self.binaries:
                    mlog.deprecation('"pkgconfig" entry is deprecated and should be replaced by "pkg-config"', fatal=False)
                    self.binaries['pkg-config'] = self.binaries['pkgconfig']
                elif self.binaries['pkgconfig'] != self.binaries['pkg-config']:
                    raise mesonlib.MesonException('Mismatched pkgconfig and pkg-config binaries in the machine file.')
                else:
                    # Both are defined with the same value, this is allowed
                    # for backward compatibility.
                    # FIXME: We should still print deprecation warning if the
                    # project targets Meson >= 1.3.0, but we have no way to know
                    # that here.
                    pass
                del self.binaries['pkgconfig']

    @staticmethod
    def detect_ccache() -> T.List[str]:
        try:
            subprocess.check_call(['ccache', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError):
            return []
        return ['ccache']

    @staticmethod
    def detect_sccache() -> T.List[str]:
        try:
            subprocess.check_call(['sccache', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError):
            return []
        return ['sccache']

    @staticmethod
    def detect_compiler_cache() -> T.List[str]:
        # Sccache is "newer" so it is assumed that people would prefer it by default.
        cache = BinaryTable.detect_sccache()
        if cache:
            return cache
        return BinaryTable.detect_ccache()

    @classmethod
    def parse_entry(cls, entry: T.Union[str, T.List[str]]) -> T.Tuple[T.List[str], T.List[str]]:
        compiler = mesonlib.stringlistify(entry)
        # Ensure ccache exists and remove it if it doesn't
        if compiler[0] == 'ccache':
            compiler = compiler[1:]
            ccache = cls.detect_ccache()
        elif compiler[0] == 'sccache':
            compiler = compiler[1:]
            ccache = cls.detect_sccache()
        else:
            ccache = []
        # Return value has to be a list of compiler 'choices'
        return compiler, ccache

    def lookup_entry(self, name: str) -> T.Optional[T.List[str]]:
        """Lookup binary in cross/native file and fallback to environment.

        Returns command with args as list if found, Returns `None` if nothing is
        found.
        """
        command = self.binaries.get(name)
        if not command:
            return None
        elif not command[0].strip():
            return None
        return command

class CMakeVariables:
    def __init__(self, variables: T.Optional[T.Dict[str, T.Any]] = None) -> None:
        variables = variables or {}
        self.variables: T.Dict[str, T.List[str]] = {}

        for key, value in variables.items():
            value = mesonlib.listify(value)
            for i in value:
                if not isinstance(i, str):
                    raise EnvironmentException(f"Value '{i}' of CMake variable '{key}' defined in a machine file is a {type(i).__name__} and not a str")
            self.variables[key] = value

    def get_variables(self) -> T.Dict[str, T.List[str]]:
        return self.variables
```