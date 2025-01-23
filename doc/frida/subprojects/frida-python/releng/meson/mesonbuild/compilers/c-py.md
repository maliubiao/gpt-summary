Response:
The user wants a functional overview of the provided Python code, which is part of the Meson build system and specifically deals with C compilers. I need to analyze the code and identify its core responsibilities and how it interacts with other parts of the system.

Here's a breakdown of the thought process:

1. **Identify the core class:** The primary class is `CCompiler`, and most other classes inherit from it or mix it in. This suggests that `CCompiler` defines the fundamental behavior for handling C compilation.

2. **Understand the purpose of the file:** The file is located within `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py`. This indicates it's part of Frida's build process using Meson and is specifically concerned with managing C compilers. It's responsible for abstracting away the differences between various C compilers.

3. **Analyze the `CCompiler` class:**
    * It inherits from `CLikeCompiler` and `Compiler`, suggesting it handles C-like languages and provides general compiler functionalities.
    * The `__init__` method initializes the compiler with paths, version, target machine, and cross-compilation status.
    * `get_no_stdinc_args` likely provides arguments to exclude standard include directories.
    * `sanity_check` performs a basic compilation test.
    * `has_header_symbol` checks if a specific symbol is defined within a header file. This is crucial for feature detection.
    * `get_options` retrieves configurable compiler options, including the C standard.
    * `attribute_check_func` validates function attributes.

4. **Examine the mixin classes:**  Several mixin classes like `GnuCompiler`, `ClangCompiler`, `MSVCCompiler`, etc., are used. These represent different compiler families and provide specific logic for their command-line arguments and behavior. This is a key design pattern for handling compiler variations.

5. **Identify compiler-specific subclasses:** Classes like `ClangCCompiler`, `GnuCCompiler`, `VisualStudioCCompiler`, etc., represent concrete C compiler implementations. They inherit from `CCompiler` and the appropriate mixin to provide compiler-specific details.

6. **Look for compiler option handling:** The `get_options`, `get_option_compile_args`, and `get_option_link_args` methods within the compiler subclasses are responsible for managing compiler flags based on user-defined options like the C standard.

7. **Consider the broader context:** This file is part of Meson, a build system. It interacts with other Meson modules to generate build commands. The compiler information is used during the configuration and compilation phases of the build process.

8. **Address the specific questions in the prompt:**
    * **Functionality:** Summarize the core responsibilities identified above.
    * **Relation to reverse engineering:**  Consider how the ability to check for header symbols and compile code snippets could be used in reverse engineering scenarios (e.g., checking for the presence of specific functions or data structures).
    * **Binary/kernel knowledge:** Identify aspects that touch upon low-level details, such as handling different architectures (cross-compilation), standard libraries, and compiler flags that affect code generation.
    * **Logical reasoning:**  Look for conditional logic within the code (e.g., setting standard based on compiler version).
    * **User errors:** Identify potential misconfigurations or incorrect usage of compiler options.
    * **User journey:**  Trace the steps a user might take to interact with this code (configuring build options in a `meson.build` file).

9. **Structure the answer:** Organize the findings into logical sections addressing each point raised in the prompt.

By following these steps, I can generate a comprehensive overview of the file's functionality and its relevance to the topics mentioned in the prompt.
这是文件 `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py` 的源代码，它属于 Frida 动态 instrumentation 工具的构建系统，并且专注于处理 C 语言编译器。以下是该文件的功能归纳：

**核心功能：C 语言编译器抽象与管理**

该文件的主要目的是为 Meson 构建系统提供一个统一的接口来处理各种不同的 C 语言编译器。它定义了一个 `CCompiler` 类，并为各种常见的 C 编译器（如 GCC、Clang、MSVC 等）提供了具体的子类实现。

**具体功能点：**

1. **编译器信息封装：**
   - 封装了 C 编译器的可执行路径 (`exelist`)、版本号 (`version`)、目标机器架构 (`for_machine`)、是否为交叉编译 (`is_cross`) 等基本信息。
   - 允许获取编译器的完整版本信息 (`full_version`)。

2. **编译选项管理：**
   - 定义了获取和设置编译器选项的方法，例如 C 语言标准 (`-std`)。
   - 针对不同的编译器，提供了获取特定选项的编译参数 (`get_option_compile_args`) 和链接参数 (`get_option_link_args`) 的方法。
   - 管理了通用的警告级别选项 (`warn_args`)，并为不同的编译器提供了预设的警告级别。

3. **标准库链接管理：**
   - 对于 Windows 平台，提供了管理需要链接的标准库 (`winlibs`) 的机制。

4. **头文件处理：**
   - 提供了获取 `-nostdinc` 参数的方法 (`get_no_stdinc_args`)，用于排除标准头文件目录。
   - 实现了预编译头文件 (PCH) 的使用方法 (`get_pch_use_args`)。
   - 提供了添加包含目录的参数 (`get_include_args`)。

5. **代码检查与测试：**
   - 实现了基本的代码编译检查 (`sanity_check`)，用于验证编译器是否可用。
   - 提供了检查头文件中是否定义了特定符号 (`has_header_symbol`) 的功能。

6. **特性检测抽象：**
   - 通过 `attribute_check_func` 方法，可以检查编译器是否支持特定的函数属性。

7. **平台和编译器特定处理：**
   - 使用 Mixin 类（如 `CLikeCompiler`, `GnuCompiler`, `ClangCompiler`, `MSVCCompiler` 等）来共享不同编译器家族的通用行为和选项处理逻辑。
   - 针对不同的编译器（例如 Apple Clang 和标准 Clang），处理了版本差异导致的标准支持不同。
   - 为交叉编译场景提供了支持，例如 `EmscriptenCCompiler`。

**与逆向方法的潜在关系举例：**

- **检查目标平台特性：** 在逆向分析特定二进制文件时，可能需要了解其编译时使用的 C 标准或特定编译器特性。可以通过 Meson 构建系统配置不同的编译器和标准，然后使用 `has_header_symbol` 等方法来模拟编译环境，从而推断目标二进制的编译环境。例如，可以尝试检查某个特定的宏是否在某个头文件中被定义，以此判断目标二进制是否使用了某个特定的库版本或编译器特性。

  **举例说明：** 假设逆向一个 Linux 下的 ELF 文件，怀疑它使用了 glibc 的某个特定版本。可以通过 Meson 配置 GCC 编译器，并使用 `has_header_symbol` 检查 glibc 版本相关的宏（例如 `_GNU_SOURCE` 或特定的 `__GLIBC_MINOR__` 版本宏）是否被定义。

- **构建测试用例：**  在进行动态分析时，可能需要编写一些小的 C 代码片段来测试目标程序的行为。Meson 可以用来构建这些测试用例，并确保它们使用与目标程序相似的编译选项和环境。

**涉及到的二进制底层、Linux、Android 内核及框架的知识举例：**

- **目标机器架构 (`for_machine`) 和交叉编译 (`is_cross`):** 这些参数直接关联到目标二进制文件的架构（例如 ARM、x86）和操作系统。在 Frida 的场景下，逆向分析 Android 应用通常涉及到 ARM 架构，并且需要进行交叉编译。Meson 通过这些信息来选择合适的编译器和链接器。

- **标准库链接 (`winlibs`):** 在 Windows 平台下，链接正确的标准库（例如 `kernel32.lib`, `user32.lib`）对于生成可执行文件至关重要。这涉及到操作系统底层的 API 调用和链接机制。

- **头文件路径和标准库包含 (`get_no_stdinc_args`, `get_include_args`):**  编译器需要知道在哪里查找头文件。不同的操作系统和编译器有不同的默认头文件路径。在构建针对 Android 平台的 Frida 组件时，需要配置正确的 Android NDK 头文件路径。

- **预编译头文件 (PCH):**  PCH 是一种优化编译速度的技术，它涉及到将常用的头文件预先编译成二进制文件。这涉及到编译器底层的编译流程和文件管理。

**逻辑推理举例（假设输入与输出）：**

**假设输入：**

- 使用 Clang 编译器。
- 设置 C 标准为 `c11`。

**输出（`get_option_compile_args` 方法的返回值）：**

- 对于 `ClangCCompiler`，输出可能是 `['-std=c11']`。
- 对于 `VisualStudioCCompiler` (MSVC)，输出可能是 `['/std:c11']`。

**解释：**  `get_option_compile_args` 方法会根据当前使用的编译器类型和用户设置的 C 标准，生成相应的编译器命令行参数。不同的编译器使用不同的语法来指定 C 标准。

**涉及用户或编程常见的使用错误举例：**

- **指定了编译器不支持的 C 标准：** 用户可能在 `meson.build` 文件中设置了一个当前编译器版本不支持的 C 标准，例如在使用较旧版本的 GCC 时尝试设置 `c23` 标准。Meson 会尝试将此选项传递给编译器，导致编译错误。

  **用户操作步骤：**
  1. 在 `meson.build` 文件中设置 `c_std = 'c23'`。
  2. 使用旧版本的 GCC 运行 `meson setup builddir` 和 `ninja`。
  3. 编译器会报错，提示不支持 `c23` 标准。

- **Windows 下链接缺失必要的标准库：** 在 Windows 平台下开发时，如果 `meson.build` 文件中没有指定需要链接的某些标准库（例如使用了 `windows.h` 但没有链接 `user32.lib`），链接器会报错。

  **用户操作步骤：**
  1. 编写包含 `windows.h` 并调用 User32 API 的 C 代码。
  2. 在 `meson.build` 文件中没有添加 `winlibs = ['user32']`。
  3. 运行 `meson setup builddir` 和 `ninja`。
  4. 链接器会报错，提示找不到相关的 API 函数。

**用户操作是如何一步步地到达这里，作为调试线索：**

1. **用户配置构建：** 用户在项目的根目录下创建一个 `meson.build` 文件，其中会指定项目使用的语言（包括 C），以及可能的 C 标准和其他编译选项。
2. **运行 `meson setup`：** 用户在命令行中运行 `meson setup <build_directory>`，Meson 会读取 `meson.build` 文件，并根据配置信息开始探测系统中的编译器。
3. **Meson 选择 C 编译器：** Meson 会根据用户的配置和系统环境，选择合适的 C 编译器。这个选择过程可能会涉及到查找环境变量、PATH 路径等。
4. **加载 C 编译器模块：** 当 Meson 确定使用 C 编译器进行构建时，它会加载 `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py` 文件中的相关编译器类（例如 `GnuCCompiler` 或 `ClangCCompiler`）。
5. **实例化编译器对象：** Meson 会根据找到的编译器信息（路径、版本等）实例化相应的编译器对象。
6. **处理用户选项：** Meson 会读取 `meson.build` 文件中关于 C 语言的选项（例如 `c_std`），并将这些选项传递给编译器对象的相应方法（例如 `get_option_compile_args`）。
7. **生成构建命令：**  编译器对象的方法会根据用户选项生成实际的编译器命令行参数，这些参数会被 Meson 用于生成最终的构建命令。
8. **执行构建命令：**  用户运行 `ninja` 或其他构建工具时，Meson 会执行生成的包含编译器参数的命令，从而调用 C 编译器进行代码编译。

**调试线索：** 如果在编译 C 代码时遇到问题，例如编译器报错说不识别某个标准，或者链接器报错说找不到某个库，那么查看 `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py` 文件中对应编译器的实现，可以帮助理解 Meson 是如何处理 C 编译器选项的，以及可能存在的问题。例如，可以查看 `get_option_compile_args` 方法是如何将用户设置的 C 标准转换为编译器命令行参数的，或者查看 `get_option_link_args` 方法是如何处理 Windows 下的标准库链接的。

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py` 文件在 Frida 的构建过程中扮演着关键的角色，它负责抽象和管理 C 语言编译器，使得 Meson 能够以一种统一的方式处理不同的 C 编译器，并根据用户配置生成正确的编译和链接命令。 这对于确保 Frida 能够在不同的平台和环境下正确构建至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/c.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2020 The Meson development team

from __future__ import annotations

import os.path
import typing as T

from .. import coredata
from .. import mlog
from ..mesonlib import MesonException, version_compare, OptionKey
from .c_function_attributes import C_FUNC_ATTRIBUTES
from .mixins.clike import CLikeCompiler
from .mixins.ccrx import CcrxCompiler
from .mixins.xc16 import Xc16Compiler
from .mixins.compcert import CompCertCompiler
from .mixins.ti import TICompiler
from .mixins.arm import ArmCompiler, ArmclangCompiler
from .mixins.visualstudio import MSVCCompiler, ClangClCompiler
from .mixins.gnu import GnuCompiler
from .mixins.gnu import gnu_common_warning_args, gnu_c_warning_args
from .mixins.intel import IntelGnuLikeCompiler, IntelVisualStudioLikeCompiler
from .mixins.clang import ClangCompiler
from .mixins.elbrus import ElbrusCompiler
from .mixins.pgi import PGICompiler
from .mixins.emscripten import EmscriptenMixin
from .mixins.metrowerks import MetrowerksCompiler
from .mixins.metrowerks import mwccarm_instruction_set_args, mwcceppc_instruction_set_args
from .compilers import (
    gnu_winlibs,
    msvc_winlibs,
    Compiler,
)

if T.TYPE_CHECKING:
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..dependencies import Dependency
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    from .compilers import CompileCheckMode

    CompilerMixinBase = Compiler
else:
    CompilerMixinBase = object

_ALL_STDS = ['c89', 'c9x', 'c90', 'c99', 'c1x', 'c11', 'c17', 'c18', 'c2x', 'c23']
_ALL_STDS += [f'gnu{std[1:]}' for std in _ALL_STDS]
_ALL_STDS += ['iso9899:1990', 'iso9899:199409', 'iso9899:1999', 'iso9899:2011', 'iso9899:2017', 'iso9899:2018']


class CCompiler(CLikeCompiler, Compiler):
    def attribute_check_func(self, name: str) -> str:
        try:
            return C_FUNC_ATTRIBUTES[name]
        except KeyError:
            raise MesonException(f'Unknown function attribute "{name}"')

    language = 'c'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        # If a child ObjC or CPP class has already set it, don't set it ourselves
        Compiler.__init__(self, ccache, exelist, version, for_machine, info,
                          is_cross=is_cross, full_version=full_version, linker=linker)
        CLikeCompiler.__init__(self)

    def get_no_stdinc_args(self) -> T.List[str]:
        return ['-nostdinc']

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        code = 'int main(void) { int class=0; return class; }\n'
        return self._sanity_check_impl(work_dir, environment, 'sanitycheckc.c', code)

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        fargs = {'prefix': prefix, 'header': hname, 'symbol': symbol}
        t = '''{prefix}
        #include <{header}>
        int main(void) {{
            /* If it's not defined as a macro, try to use as a symbol */
            #ifndef {symbol}
                {symbol};
            #endif
            return 0;
        }}'''
        return self.compiles(t.format(**fargs), env, extra_args=extra_args,
                             dependencies=dependencies)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts.update({
            key: coredata.UserStdOption('C', _ALL_STDS),
        })
        return opts


class _ClangCStds(CompilerMixinBase):

    """Mixin class for clang based compilers for setting C standards.

    This is used by both ClangCCompiler and ClangClCompiler, as they share
    the same versions
    """

    _C17_VERSION = '>=6.0.0'
    _C18_VERSION = '>=8.0.0'
    _C2X_VERSION = '>=9.0.0'
    _C23_VERSION = '>=18.0.0'

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        stds = ['c89', 'c99', 'c11']
        # https://releases.llvm.org/6.0.0/tools/clang/docs/ReleaseNotes.html
        # https://en.wikipedia.org/wiki/Xcode#Latest_versions
        if version_compare(self.version, self._C17_VERSION):
            stds += ['c17']
        if version_compare(self.version, self._C18_VERSION):
            stds += ['c18']
        if version_compare(self.version, self._C2X_VERSION):
            stds += ['c2x']
        if version_compare(self.version, self._C23_VERSION):
            stds += ['c23']
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(stds, gnu=True)
        return opts


class ClangCCompiler(_ClangCStds, ClangCompiler, CCompiler):

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross, info, linker=linker, full_version=full_version)
        ClangCompiler.__init__(self, defines)
        default_warn_args = ['-Wall', '-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': ['-Weverything']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        if self.info.is_windows() or self.info.is_cygwin():
            self.update_options(
                opts,
                self.create_option(coredata.UserArrayOption,
                                   OptionKey('winlibs', machine=self.for_machine, lang=self.language),
                                   'Standard Win libraries to link against',
                                   gnu_winlibs),
            )
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', machine=self.for_machine, lang=self.language)]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        if self.info.is_windows() or self.info.is_cygwin():
            # without a typedict mypy can't understand this.
            libs = options[OptionKey('winlibs', machine=self.for_machine, lang=self.language)].value.copy()
            assert isinstance(libs, list)
            for l in libs:
                assert isinstance(l, str)
            return libs
        return []


class ArmLtdClangCCompiler(ClangCCompiler):

    id = 'armltdclang'


class AppleClangCCompiler(ClangCCompiler):

    """Handle the differences between Apple Clang and Vanilla Clang.

    Right now this just handles the differences between the versions that new
    C standards were added.
    """

    _C17_VERSION = '>=10.0.0'
    _C18_VERSION = '>=11.0.0'
    _C2X_VERSION = '>=11.0.0'


class EmscriptenCCompiler(EmscriptenMixin, ClangCCompiler):

    id = 'emscripten'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        if not is_cross:
            raise MesonException('Emscripten compiler can only be used for cross compilation.')
        if not version_compare(version, '>=1.39.19'):
            raise MesonException('Meson requires Emscripten >= 1.39.19')
        ClangCCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                                info, linker=linker,
                                defines=defines, full_version=full_version)


class ArmclangCCompiler(ArmclangCompiler, CCompiler):
    '''
    Keil armclang
    '''

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        ArmclangCompiler.__init__(self)
        default_warn_args = ['-Wall', '-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': ['-Weverything']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c90', 'c99', 'c11'], gnu=True)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', machine=self.for_machine, lang=self.language)]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []


class GnuCCompiler(GnuCompiler, CCompiler):

    _C18_VERSION = '>=8.0.0'
    _C2X_VERSION = '>=9.0.0'
    _C23_VERSION = '>=14.0.0'
    _INVALID_PCH_VERSION = ">=3.4.0"

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross, info, linker=linker, full_version=full_version)
        GnuCompiler.__init__(self, defines)
        default_warn_args = ['-Wall']
        if version_compare(self.version, self._INVALID_PCH_VERSION):
            default_warn_args += ['-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': (default_warn_args + ['-Wextra', '-Wpedantic'] +
                                         self.supported_warn_args(gnu_common_warning_args) +
                                         self.supported_warn_args(gnu_c_warning_args))}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        stds = ['c89', 'c99', 'c11']
        if version_compare(self.version, self._C18_VERSION):
            stds += ['c17', 'c18']
        if version_compare(self.version, self._C2X_VERSION):
            stds += ['c2x']
        if version_compare(self.version, self._C23_VERSION):
            stds += ['c23']
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(stds, gnu=True)
        if self.info.is_windows() or self.info.is_cygwin():
            self.update_options(
                opts,
                self.create_option(coredata.UserArrayOption,
                                   key.evolve('winlibs'),
                                   'Standard Win libraries to link against',
                                   gnu_winlibs),
            )
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', lang=self.language, machine=self.for_machine)]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        if self.info.is_windows() or self.info.is_cygwin():
            # without a typeddict mypy can't figure this out
            libs: T.List[str] = options[OptionKey('winlibs', lang=self.language, machine=self.for_machine)].value.copy()
            assert isinstance(libs, list)
            for l in libs:
                assert isinstance(l, str)
            return libs
        return []

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        return ['-fpch-preprocess', '-include', os.path.basename(header)]


class PGICCompiler(PGICompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        PGICompiler.__init__(self)


class NvidiaHPC_CCompiler(PGICompiler, CCompiler):

    id = 'nvidia_hpc'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        PGICompiler.__init__(self)


class ElbrusCCompiler(ElbrusCompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        ElbrusCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        stds = ['c89', 'c9x', 'c99', 'gnu89', 'gnu9x', 'gnu99']
        stds += ['iso9899:1990', 'iso9899:199409', 'iso9899:1999']
        if version_compare(self.version, '>=1.20.00'):
            stds += ['c11', 'gnu11']
        if version_compare(self.version, '>=1.21.00') and version_compare(self.version, '<1.22.00'):
            stds += ['c90', 'c1x', 'gnu90', 'gnu1x', 'iso9899:2011']
        if version_compare(self.version, '>=1.23.00'):
            stds += ['c90', 'c1x', 'gnu90', 'gnu1x', 'iso9899:2011']
        if version_compare(self.version, '>=1.26.00'):
            stds += ['c17', 'c18', 'iso9899:2017', 'iso9899:2018', 'gnu17', 'gnu18']
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(stds)
        return opts

    # Elbrus C compiler does not have lchmod, but there is only linker warning, not compiler error.
    # So we should explicitly fail at this case.
    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        if funcname == 'lchmod':
            return False, False
        else:
            return super().has_function(funcname, prefix, env,
                                        extra_args=extra_args,
                                        dependencies=dependencies)


class IntelCCompiler(IntelGnuLikeCompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        IntelGnuLikeCompiler.__init__(self)
        self.lang_header = 'c-header'
        default_warn_args = ['-Wall', '-w3']
        self.warn_args = {'0': [],
                          '1': default_warn_args + ['-diag-disable:remark'],
                          '2': default_warn_args + ['-Wextra', '-diag-disable:remark'],
                          '3': default_warn_args + ['-Wextra', '-diag-disable:remark'],
                          'everything': default_warn_args + ['-Wextra']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        stds = ['c89', 'c99']
        if version_compare(self.version, '>=16.0.0'):
            stds += ['c11']
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(stds, gnu=True)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', machine=self.for_machine, lang=self.language)]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args


class IntelLLVMCCompiler(ClangCCompiler):

    id = 'intel-llvm'


class VisualStudioLikeCCompilerMixin(CompilerMixinBase):

    """Shared methods that apply to MSVC-like C compilers."""

    def get_options(self) -> MutableKeyedOptionDictType:
        return self.update_options(
            super().get_options(),
            self.create_option(
                coredata.UserArrayOption,
                OptionKey('winlibs', machine=self.for_machine, lang=self.language),
                'Windows libs to link against.',
                msvc_winlibs,
            ),
        )

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        # need a TypeDict to make this work
        key = OptionKey('winlibs', machine=self.for_machine, lang=self.language)
        libs = options[key].value.copy()
        assert isinstance(libs, list)
        for l in libs:
            assert isinstance(l, str)
        return libs


class VisualStudioCCompiler(MSVCCompiler, VisualStudioLikeCCompilerMixin, CCompiler):

    _C11_VERSION = '>=19.28'
    _C17_VERSION = '>=19.28'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo', target: str,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker,
                           full_version=full_version)
        MSVCCompiler.__init__(self, target)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        stds = ['c89', 'c99']
        if version_compare(self.version, self._C11_VERSION):
            stds += ['c11']
        if version_compare(self.version, self._C17_VERSION):
            stds += ['c17', 'c18']
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(stds, gnu=True, gnu_deprecated=True)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', machine=self.for_machine, lang=self.language)]
        # As of MVSC 16.8, /std:c11 and /std:c17 are the only valid C standard options.
        if std.value in {'c11'}:
            args.append('/std:c11')
        elif std.value in {'c17', 'c18'}:
            args.append('/std:c17')
        return args


class ClangClCCompiler(_ClangCStds, ClangClCompiler, VisualStudioLikeCCompilerMixin, CCompiler):
    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo', target: str,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, [], exelist, version, for_machine, is_cross,
                           info, linker=linker,
                           full_version=full_version)
        ClangClCompiler.__init__(self, target)

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key].value
        if std != "none":
            return [f'/clang:-std={std}']
        return []


class IntelClCCompiler(IntelVisualStudioLikeCompiler, VisualStudioLikeCCompilerMixin, CCompiler):

    """Intel "ICL" compiler abstraction."""

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo', target: str,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, [], exelist, version, for_machine, is_cross,
                           info, linker=linker,
                           full_version=full_version)
        IntelVisualStudioLikeCompiler.__init__(self, target)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99', 'c11'])
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value == 'c89':
            mlog.log("ICL doesn't explicitly implement c89, setting the standard to 'none', which is close.", once=True)
        elif std.value != 'none':
            args.append('/Qstd:' + std.value)
        return args


class IntelLLVMClCCompiler(IntelClCCompiler):

    id = 'intel-llvm-cl'


class ArmCCompiler(ArmCompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker,
                           full_version=full_version)
        ArmCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99', 'c11'])
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('--' + std.value)
        return args


class CcrxCCompiler(CcrxCompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        CcrxCompiler.__init__(self)

    # Override CCompiler.get_always_args
    def get_always_args(self) -> T.List[str]:
        return ['-nologo']

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99'])
        return opts

    def get_no_stdinc_args(self) -> T.List[str]:
        return []

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value == 'c89':
            args.append('-lang=c')
        elif std.value == 'c99':
            args.append('-lang=c99')
        return args

    def get_compile_only_args(self) -> T.List[str]:
        return []

    def get_no_optimization_args(self) -> T.List[str]:
        return ['-optimize=0']

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'-output=obj={target}']

    def get_werror_args(self) -> T.List[str]:
        return ['-change_message=error']

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if path == '':
            path = '.'
        return ['-include=' + path]


class Xc16CCompiler(Xc16Compiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        Xc16Compiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99'], gnu=True)
        return opts

    def get_no_stdinc_args(self) -> T.List[str]:
        return []

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('-ansi')
            args.append('-std=' + std.value)
        return args

    def get_compile_only_args(self) -> T.List[str]:
        return []

    def get_no_optimization_args(self) -> T.List[str]:
        return ['-O0']

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'-o{target}']

    def get_werror_args(self) -> T.List[str]:
        return ['-change_message=error']

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if path == '':
            path = '.'
        return ['-I' + path]

class CompCertCCompiler(CompCertCompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        CompCertCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99'])
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []

    def get_no_optimization_args(self) -> T.List[str]:
        return ['-O0']

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'-o{target}']

    def get_werror_args(self) -> T.List[str]:
        return ['-Werror']

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if path == '':
            path = '.'
        return ['-I' + path]

class TICCompiler(TICompiler, CCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        TICompiler.__init__(self)

    # Override CCompiler.get_always_args
    def get_always_args(self) -> T.List[str]:
        return []

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        std_opt = opts[OptionKey('std', machine=self.for_machine, lang=self.language)]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c89', 'c99', 'c11'])
        return opts

    def get_no_stdinc_args(self) -> T.List[str]:
        return []

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('--' + std.value)
        return args

class C2000CCompiler(TICCompiler):
    # Required for backwards compat with projects created before ti-cgt support existed
    id = 'c2000'

class C6000CCompiler(TICCompiler):
    id = 'c6000'

class MetrowerksCCompilerARM(MetrowerksCompiler, CCompiler):
    id = 'mwccarm'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                           info, linker=linker, full_version=full_version)
        MetrowerksCompiler.__init__(self)

    def get_instruction_set_args(self, instruction_set: str) -> T.Optional[T.List[str]]:
        return mwccarm_instruction_set_args.get(instruction_set, None)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CCompiler.get_options(self)
        c_stds = ['c99']
        opts[OptionKey('std', machine=self.for_machine, lang=self.language)].choices = ['none'] + c_stds
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args = []
        std = options[OptionKey('std', machine=self.for_machine, lang=self.language)]
        if std.value != 'none':
            args.append('-lang')
            args.append(std.value)
        return args

class MetrowerksCCompilerEmbeddedPowerPC(Metrower
```