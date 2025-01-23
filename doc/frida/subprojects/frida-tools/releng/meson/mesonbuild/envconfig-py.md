Response:
The user wants to understand the functionality of the `envconfig.py` file in the Frida project. I need to break down the code and explain its purpose, especially in relation to reverse engineering, low-level concepts, and potential user errors.

Here's a plan:

1. **General Functionality:** Describe the file's role in managing environment configurations for the Meson build system.
2. **Reverse Engineering Relevance:** Identify parts of the code (like compiler/linker settings) that are relevant to reverse engineering processes.
3. **Low-Level Concepts:** Point out the connection to binary formats, operating systems (Linux, Android), and potentially kernel/framework interactions.
4. **Logical Inference:** Analyze how the code might process inputs and produce outputs based on its structure (though this file is primarily about data structures, not complex logic).
5. **User Errors:**  Highlight common mistakes users might make when providing configuration data.
6. **User Journey:** Explain the steps a user might take that would lead to this code being executed, particularly in a debugging scenario.
这个 `envconfig.py` 文件是 Frida 项目中用于处理构建环境配置的关键部分。它主要为 Meson 构建系统提供了一种结构化的方式来管理编译器、链接器和其他构建工具的信息。以下是其各项功能的详细说明：

**1. 功能列举：**

*   **定义和管理已知 CPU 架构:** `known_cpu_families` 和 `CPU_FAMILIES_64_BIT` 定义了 Meson 构建系统支持的 CPU 架构列表，并区分了 64 位架构。
*   **映射环境变量到编译器和工具:** `ENV_VAR_COMPILER_MAP` 和 `ENV_VAR_TOOL_MAP`  将编程语言和工具的标识符映射到相应的环境变量。例如，'c' 映射到 'CC' (C 编译器)，'ld' 映射到 'LD' (链接器)。这使得构建系统能够从环境变量中读取编译器和工具的路径。
*   **处理废弃的环境变量:** `DEPRECATED_ENV_PROG_MAP` 记录了旧版本的环境变量名，以便在过渡期间提供兼容性。
*   **CMake 配置选项:** `CMakeSkipCompilerTest` 枚举定义了控制 CMake 编译器测试行为的选项。
*   **解析和存储构建属性:** `Properties` 类用于存储和访问从配置文件中读取的各种构建属性，例如标准库位置 (`stdlib`)，根目录 (`root`)，系统根目录 (`sys_root`)，以及与 CMake 相关的配置。
*   **表示目标机器信息:** `MachineInfo` 数据类用于存储目标构建机器的体系结构信息，包括操作系统、CPU 家族、CPU 类型、字节序等。
*   **管理二进制工具路径:** `BinaryTable` 类用于存储和查找构建过程中使用的各种二进制工具的路径。它可以从配置文件中读取，并提供检测常见工具（如 ccache 和 sccache）的功能。
*   **存储 CMake 变量:** `CMakeVariables` 类用于存储在构建过程中传递给 CMake 的变量。

**2. 与逆向方法的关联及举例说明：**

这个文件直接关系到逆向工程过程中的**编译和构建**环节。在进行逆向分析时，我们经常需要重新编译目标程序或其组件，以便进行调试、插桩或者修改。`envconfig.py` 文件中定义的信息直接影响着编译过程使用的编译器、链接器及其选项。

*   **编译器选择:** 如果逆向工程师想要使用特定版本的编译器或带有特定补丁的编译器来构建目标，他们可以通过设置相应的环境变量（例如 `CC`，`CXX`）来影响构建过程。`envconfig.py` 中的映射确保了 Meson 构建系统能够识别这些环境变量。
    *   **举例:** 假设逆向工程师想要使用 clang 而不是 gcc 来编译一个 C 程序，他们可以在执行 Meson 构建命令之前设置环境变量 `export CC=/usr/bin/clang`。Meson 在读取配置时会通过 `ENV_VAR_COMPILER_MAP` 找到 `CC` 对应的编译器，并使用 clang 进行编译。
*   **链接器配置:**  类似的，链接器的选择和配置对于逆向工程也很重要，因为它决定了最终可执行文件的结构和依赖关系。
    *   **举例:** 如果逆向工程师需要使用特定的链接器来排除某些链接错误或尝试特定的链接技术，他们可以设置 `CC_LD` 或 `CXX_LD` 环境变量。
*   **工具链路径:**  逆向工程中可能需要使用特定的工具链（包含编译器、链接器和其他工具），`envconfig.py` 通过环境变量映射，允许用户指定这些工具链的路径。
    *   **举例:** 对于 Android 逆向，可能需要使用 Android NDK 提供的工具链。可以通过设置环境变量如 `CC` 指向 NDK 中的 clang 路径，`AR` 指向 NDK 中的 ar 路径等来实现。

**3. 涉及的二进制底层，Linux, Android 内核及框架的知识及举例说明：**

*   **二进制底层:** 文件中定义的 CPU 架构（如 'x86', 'arm', 'aarch64'）直接关联到二进制文件的指令集架构。不同的架构需要不同的编译器和链接器配置，以及不同的指令编码。
    *   **举例:**  在为 ARM 架构的 Android 设备编译 Frida 组件时，Meson 会根据目标架构选择相应的编译器和链接器。`MachineInfo` 类中存储的 `cpu_family` 信息会被用来判断目标是 32 位 ARM 还是 64 位 ARM (AArch64)，从而选择正确的工具链。
*   **Linux 和 Android 内核:**  尽管 `envconfig.py` 本身不直接操作内核，但它所管理的构建过程会生成在 Linux 和 Android 内核上运行的二进制文件。`MachineInfo` 类中的 `system` 字段（例如 'linux', 'android') 指示了目标操作系统，这会影响到一些默认的编译和链接选项。
    *   **举例:** 在为 Android 构建时，可能需要链接特定的 Android 系统库，或者使用与 Android 系统调用约定兼容的编译器选项。这些信息可能在 Meson 的其他部分或者构建脚本中根据 `system` 字段进行处理。
*   **Android 框架:**  在 Frida 的上下文中，`envconfig.py` 间接地影响着 Frida agent 的构建，这些 agent 会运行在 Android 应用程序的进程空间中，并与 Android 框架进行交互。
    *   **举例:**  Frida agent 的构建可能需要链接 Android Runtime (ART) 的库，或者使用特定的头文件。这些依赖关系和路径配置会受到构建环境配置的影响，而 `envconfig.py` 是配置的入口之一。

**4. 逻辑推理的假设输入与输出：**

尽管 `envconfig.py` 主要定义数据结构，但我们可以设想一些基于其内容的逻辑推理：

*   **假设输入:**  一个 Meson 的配置文件 (meson.options) 或跨平台定义文件 (meson.build) 中指定了目标架构为 `aarch64`。
*   **输出:**  在构建过程中，`MachineInfo` 类的实例的 `is_64_bit` 属性会被设置为 `True`，因为 `'aarch64'` 存在于 `CPU_FAMILIES_64_BIT` 列表中。这会影响后续的构建步骤，例如选择 64 位的库和工具。
*   **假设输入:** 用户设置了环境变量 `CC=/opt/my_custom_gcc`。
*   **输出:**  当 Meson 构建系统查找 C 编译器时，通过 `ENV_VAR_COMPILER_MAP`，它会读取到环境变量 `CC` 的值 `/opt/my_custom_gcc`，并将其作为 C 编译器的路径。
*   **假设输入:**  在跨平台定义文件中， `binaries` 部分定义了 `pkgconfig: ['/usr/local/bin/pkg-config']`。
*   **输出:** `BinaryTable` 类在解析时会将 `self.binaries['pkg-config']` 设置为 `['/usr/local/bin/pkg-config']`。后续构建过程中需要使用 `pkg-config` 时，会使用这个指定的路径。

**5. 用户或编程常见的使用错误及举例说明：**

*   **环境变量设置错误:** 用户可能设置了错误的环境变量名或者路径。
    *   **举例:** 用户可能错误地将 C++ 编译器的环境变量设置为 `CPP` 而不是 `CXX`。Meson 构建系统可能无法找到 C++ 编译器，导致构建失败。
*   **配置文件格式错误:**  如果用户手动编辑了 Meson 的 native 或 cross 文件，可能会引入格式错误。
    *   **举例:** 在配置文件的 `binaries` 部分，用户可能将工具的路径写成了字符串而不是列表，例如 `ar: /usr/bin/ar` 而不是 `ar: ['/usr/bin/ar']`，这会导致 `BinaryTable` 解析时抛出 `mesonlib.MesonException`。
*   **CMake 配置错误:**  用户可能为 CMake 相关的属性提供了无效的值。
    *   **举例:**  用户在 native 或 cross 文件中设置了 `cmake_skip_compiler_test: "maybe"`，而 `CMakeSkipCompilerTest` 枚举中没有 "maybe" 这个值，这会导致在获取该属性时抛出 `EnvironmentException`。
*   **指定不存在的工具路径:** 用户可能在配置文件或环境变量中指定了不存在的工具路径。
    *   **举例:** 用户设置了 `CC=/path/to/nonexistent/gcc`，构建过程在尝试执行该编译器时会失败，并可能抛出 "command not found" 类似的错误。

**6. 用户操作如何一步步的到达这里，作为调试线索：**

通常情况下，用户不会直接编辑 `envconfig.py` 文件。用户与这个文件的交互是通过 Meson 构建系统进行的。以下是一些可能导致相关代码执行的场景：

1. **配置构建环境:** 用户执行 `meson setup builddir` 命令来配置构建环境。Meson 会读取 `meson.build` 文件以及可选的 native 或 cross 文件。这些文件中的配置信息会被解析并存储在 `Properties` 和 `BinaryTable` 等类的实例中，这个过程会涉及到 `envconfig.py` 中的代码。
2. **指定 native 或 cross 文件:** 用户在 `meson setup` 命令中使用 `--native-file` 或 `--cross-file` 参数指定了 native 或 cross 文件。Meson 会解析这些文件，并将其中定义的编译器、工具和目标机器信息加载到 `envconfig.py` 定义的数据结构中。
3. **设置环境变量:**  用户在执行 `meson setup` 或 `meson compile` 之前设置了环境变量（例如 `CC`, `CXX`, `PKG_CONFIG_PATH`）。Meson 在初始化构建环境时会读取这些环境变量，`envconfig.py` 中的映射关系定义了哪些环境变量会被读取，以及它们对应于哪些构建工具。
4. **调试构建问题:** 当构建过程中出现编译器或链接器相关的错误时，开发者可能会检查 Meson 的配置信息，以确定 Meson 使用了哪个编译器、链接器以及相关的选项。这可能涉及到查看 Meson 生成的构建日志或使用 Meson 的 introspection 功能，从而间接地涉及到 `envconfig.py` 中定义的数据。
5. **Frida 的构建过程:** 作为 Frida 项目的一部分，当开发者尝试构建 Frida 的组件（例如 frida-core 或 frida-tools）时，Meson 会被调用，并会执行 `envconfig.py` 中的代码来初始化构建环境。
6. **修改构建脚本或配置文件:**  开发者可能会修改 `meson.build`、meson options 文件或者 native/cross 文件，以更改编译选项、指定特定的工具路径或目标架构。这些修改会导致 Meson 重新解析配置，并执行 `envconfig.py` 中的相关代码。

作为调试线索，如果用户在构建 Frida 或其他使用 Meson 的项目时遇到与编译器、链接器或工具链相关的错误，他们应该检查以下几点：

*   **环境变量是否正确设置:** 检查相关的环境变量（例如 `CC`, `CXX`, `AR`, `PKG_CONFIG_PATH`) 是否指向正确的工具路径。
*   **native 或 cross 文件配置是否正确:** 如果使用了 native 或 cross 文件，检查其中的语法和配置是否正确，特别是 `binaries` 和 `properties` 部分。
*   **Meson 的配置缓存:**  尝试清除 Meson 的构建缓存 (`meson --wipe builddir`) 并重新配置，以排除旧的配置信息造成的影响。
*   **查看 Meson 的构建日志:**  详细的构建日志可以提供关于编译器和链接器调用的具体信息，帮助定位问题。

总之，`envconfig.py` 虽然不直接被用户操作，但它是 Meson 构建系统解析和管理构建环境配置的核心部分，用户通过配置 Meson 的相关文件和环境变量来间接地影响其行为。理解这个文件的功能有助于理解基于 Meson 的项目的构建过程，并能更好地排查构建错误。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/envconfig.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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