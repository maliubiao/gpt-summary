Response:
The user wants a summary of the functionality of the provided Python code. I need to analyze the code and identify its key responsibilities and features. The code defines a `CCompiler` class and several subclasses, which suggests it's about managing and abstracting different C compilers within a build system (likely Meson).

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The central element is the `CCompiler` class. It inherits from `CLikeCompiler` and `Compiler`, indicating it handles C-specific compilation while adhering to a broader compiler interface.

2. **Subclass Analysis:** The code defines many subclasses like `ClangCCompiler`, `GnuCCompiler`, `MSVCCCompiler`, etc. This strongly suggests that the code is designed to support various C compilers. Each subclass likely has specific configurations or behaviors tailored to that particular compiler.

3. **Mixin Classes:** Notice the use of mixin classes like `CLikeCompiler`, `ArmCompiler`, `VisualStudioLikeCCompilerMixin`. These provide shared functionalities to multiple compiler classes, promoting code reuse and organization.

4. **Key Functionalities within `CCompiler`:**
    * `attribute_check_func`: This seems to validate or retrieve information about C function attributes.
    * `language`: Explicitly sets the language to 'c'.
    * `__init__`:  Standard constructor, likely setting up core compiler attributes.
    * `get_no_stdinc_args`: Returns arguments to exclude standard include directories.
    * `sanity_check`: Performs a basic compilation test.
    * `has_header_symbol`: Checks if a header file defines a specific symbol. This is crucial for feature detection.
    * `get_options`: Defines configurable options for the C compiler, such as the C standard.

5. **Compiler-Specific Logic:** The subclasses appear to override or extend functionalities from the base `CCompiler` and mixins. This is where compiler-specific flags, standard versions, and library linking details are likely handled. For example, `GnuCCompiler` has logic for different C standard versions and Windows library linking.

6. **Standard Handling:**  The code extensively deals with C standards (c89, c99, c11, etc.). It seems to manage which standards are supported by different compilers and how to specify them.

7. **Warning Levels:**  Several compilers define `warn_args`, suggesting the code handles different warning levels during compilation.

8. **Cross-Compilation:** The `is_cross` parameter in the constructors hints at support for cross-compilation scenarios.

9. **Dependency Management:** The `dependencies` parameter in `has_header_symbol` suggests the integration with a dependency management system.

10. **Configuration Options:** The `get_options` methods and the use of `coredata.UserStdOption` indicate that users can configure the C compiler through options.

11. **Platform Specifics:**  Conditional logic based on `self.info.is_windows()` or `self.info.is_cygwin()` suggests handling platform-specific compiler behavior (e.g., linking against Windows libraries).

12. **Precompiled Headers (PCH):** The `get_pch_use_args` method in `GnuCCompiler` indicates support for precompiled headers.

13. **Output and Error Handling:** Methods like `get_output_args` and `get_werror_args` control the output file naming and treat warnings as errors.

14. **Include Paths:** The `get_include_args` method manages how include directories are passed to the compiler.

15. **No Optimization:**  Methods like `get_no_optimization_args` allow disabling optimizations for debugging or specific build scenarios.

16. **Sanity Checks and Feature Detection:** The `sanity_check` and `has_header_symbol` functions are key for ensuring the compiler works and has the required features.

17. **Logical Inferences:** For example, the existence of `_C17_VERSION`, `_C18_VERSION`, etc., within the Clang compilers suggests that the code is aware of the compiler version and enables C standards based on that.

By piecing these observations together, the core functionality of the code emerges as providing a structured and extensible way to interact with different C compilers within a build system. It handles compiler selection, configuration (standards, warnings, libraries), feature detection, and compilation process abstraction.
好的，让我们来归纳一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/c.py` 这个文件的功能。

**核心功能归纳：**

这个 Python 源代码文件定义了 Meson 构建系统中用于处理 C 语言编译器的相关类和方法。其主要功能是：

1. **C 语言编译器的抽象和统一接口：** 它定义了一个基类 `CCompiler`，并针对不同的 C 编译器（如 GCC, Clang, MSVC, Intel Compiler 等）创建了相应的子类。这提供了一个统一的接口来操作各种 C 编译器，屏蔽了它们之间的差异。

2. **编译器配置管理：**  它负责管理和配置 C 编译器的各种选项，例如：
    * **C 语言标准：** 支持多种 C 语言标准 (c89, c99, c11, c17, c18, c2x, c23 等)，并根据不同编译器的版本提供可用的标准选项。
    * **警告级别：**  定义了不同警告级别的编译参数。
    * **包含目录：**  管理包含头文件的路径。
    * **链接库：**  管理需要链接的库文件，特别是针对 Windows 平台的标准库。
    * **优化选项：**  提供禁用优化的选项。
    * **预编译头文件 (PCH)：**  支持预编译头文件的使用。

3. **编译器特性检测：**  它提供了一些方法来检测编译器的特性和功能，例如：
    * **`sanity_check`:**  执行一个简单的编译测试，以确保编译器可以正常工作。
    * **`has_header_symbol`:**  检查头文件中是否定义了特定的符号。
    * **`has_function`:** 检查是否存在某个函数。

4. **平台和架构特定处理：**  代码中包含了一些针对特定平台（如 Windows, Cygwin）和架构的处理逻辑。

5. **编译和链接参数生成：**  根据配置选项和目标平台，生成传递给编译器的命令行参数。

**与逆向方法的关联及举例说明：**

* **二进制代码生成和分析的基础：** C 语言是许多底层软件和操作系统内核的开发语言，逆向工程经常需要分析用 C 语言编写的二进制代码。理解编译器如何将 C 代码转换为机器码，以及编译器选项如何影响最终的二进制文件，对于逆向分析至关重要。
    * **举例：**  逆向分析一个 Android native 库时，了解它是由哪个版本的 GCC 或 Clang 编译的，以及使用了哪些优化选项（例如 `-O2`, `-Os`），可以帮助理解代码的结构和行为。优化可能会导致代码指令的重排、内联等，使得逆向分析更具挑战性。

* **符号信息和调试信息：** 编译器选项可以控制是否生成符号信息和调试信息。这些信息对于逆向工程中的动态调试和符号解析非常有用。
    * **举例：**  在 Frida 中 hook 一个函数时，如果目标程序没有符号信息，可能需要手动定位函数地址。了解编译器是否使用了 strip 命令移除了符号信息，或者是否生成了 DWARF 调试信息，可以指导逆向工程师采取不同的策略。

* **调用约定和ABI：** 不同的编译器和平台可能使用不同的调用约定 (calling convention) 和应用程序二进制接口 (ABI)。理解这些差异对于跨平台或跨编译器逆向分析非常重要。
    * **举例：**  在分析 Linux 内核模块时，需要了解内核使用的 GCC 版本和编译选项，因为内核有特定的调用约定和 ABI。如果逆向分析工具与目标环境的编译器设置不匹配，可能会导致函数调用栈解析错误。

**涉及到的二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层知识：**
    * **目标文件格式 (如 ELF, PE, Mach-O)：**  编译器生成的中间目标文件和最终的可执行文件遵循特定的二进制格式。理解这些格式对于分析代码段、数据段、重定位信息等至关重要。
        * **举例：**  Meson 需要知道目标平台的二进制格式，以便正确地链接目标文件。例如，在 Android 上，通常使用 ELF 格式。
    * **指令集架构 (ISA)：** 不同的处理器架构（如 ARM, x86）有不同的指令集。编译器负责将 C 代码转换为目标架构的机器指令。
        * **举例：**  Frida 需要支持多种架构的进程注入和代码执行，因此 Meson 构建系统需要能够为不同的目标架构选择合适的 C 编译器和编译选项。

* **Linux 内核知识：**
    * **内核模块编译：**  Linux 内核模块通常使用 GCC 编译，并且有一些特定的编译选项和头文件路径。
        * **举例：**  如果 Frida 需要注入到内核模块中，它可能需要模拟内核模块的编译环境，包括使用相同的编译器和编译选项。
    * **系统调用接口：** C 语言编写的程序通过系统调用与内核交互。理解系统调用的机制对于逆向分析用户空间程序与内核的交互至关重要。
        * **举例：**  Frida 可以 hook 系统调用，监控程序与内核的交互。了解 Linux 内核的系统调用约定对于实现这些 hook 功能非常重要。

* **Android 内核及框架知识：**
    * **Android NDK 编译：**  Android 的 native 代码通常使用 Android NDK (Native Development Kit) 提供的工具链编译，其中包含了 Clang 或 GCC 编译器。
        * **举例：**  Frida 自身是用 C/C++ 编写的，其 Android 部分的构建就依赖于 Android NDK 提供的编译器。这个文件中的 `ClangCCompiler` 等类就与 NDK 的编译过程密切相关。
    * **Android 系统库：**  Android 系统库是用 C/C++ 编写的，逆向分析 Android 应用的 native 代码时经常需要分析这些库。
        * **举例：**  在 hook Android 系统服务时，了解这些服务是由哪个编译器编译的，可以帮助理解其内部结构和工作原理。

**逻辑推理及假设输入与输出：**

* **假设输入：** 用户在 Meson 构建文件中指定使用 Clang 编译器，并要求编译一个使用了 C11 标准的代码文件 `my_code.c`。
* **逻辑推理：**  `ClangCCompiler` 类会被实例化。`get_option_compile_args` 方法会被调用，根据用户指定的 C11 标准，该方法会返回 `['-std=c11']` 这个编译参数。
* **输出：** Meson 构建系统最终会调用 Clang 编译器，并带上 `-std=c11` 这个参数来编译 `my_code.c`。

* **假设输入：** 用户在 Meson 构建文件中指定使用 GCC 编译器，并要求检查是否存在头文件 `<pthread.h>` 中定义的符号 `pthread_create`。
* **逻辑推理：** `GnuCCompiler` 类会被实例化。`has_header_symbol` 方法会被调用，它会生成一段临时的 C 代码，包含 `#include <pthread.h>` 并尝试使用 `pthread_create`。然后调用 GCC 编译器编译这段代码。
* **输出：** 如果编译成功（表示 `pthread_create` 存在），`has_header_symbol` 返回 `(True, True)`；如果编译失败，则返回 `(False, False)` 或其他指示编译失败原因的元组。

**涉及用户或编程常见的使用错误及举例说明：**

* **指定的 C 标准不被编译器支持：** 用户在 Meson 中指定了一个 C 标准，但当前使用的编译器版本不支持该标准。
    * **举例：**  使用旧版本的 GCC 尝试编译时指定 `-std=c23`，`GnuCCompiler` 类会检查编译器版本，如果版本低于支持 C23 的最低版本，则不会在 `get_options` 中将 `c23` 列为有效选项。Meson 会报错，提示用户指定的 C 标准无效。

* **链接 Windows 标准库时拼写错误：**  在使用 MSVC 或 Clang-cl 编译器时，用户在 Meson 中指定链接 Windows 标准库时，库名拼写错误。
    * **举例：** 用户在 `winlibs` 选项中输入了 `user32.libb` 而不是 `user32.lib`，`VisualStudioCCompiler` 或 `ClangClCCompiler` 在 `get_option_link_args` 中会直接将错误的库名传递给链接器，导致链接失败，并产生链接器错误。

* **交叉编译时未正确配置目标平台：** 在进行交叉编译时，用户可能没有正确配置目标平台的工具链或环境变量。
    * **举例：**  在使用 Emscripten 编译器进行 WebAssembly 交叉编译时，如果用户没有正确安装和配置 Emscripten SDK，`EmscriptenCCompiler` 的初始化过程中会抛出异常，因为找不到 Emscripten 的编译器工具。

**说明用户操作是如何一步步到达这里，作为调试线索：**

1. **用户编写 Meson 构建文件 `meson.build`：**  用户在构建文件中使用 `project()` 函数定义项目，并使用 `executable()` 或 `library()` 函数定义构建目标，指定使用 C 语言，并可能设置了特定的编译器选项（例如 C 标准）。
2. **用户运行 `meson setup builddir` 命令：**  Meson 工具开始解析 `meson.build` 文件，并根据用户指定的编译器（或者 Meson 自动检测到的编译器）实例化相应的编译器类。对于 C 语言，会实例化 `CCompiler` 的子类，例如 `GnuCCompiler` 或 `ClangCCompiler`。
3. **Meson 调用编译器类的方法：**
    * 为了获取编译器的版本信息，可能会调用编译器的可执行文件并解析其输出。
    * 为了获取编译器支持的 C 标准，会调用 `get_options()` 方法。
    * 在配置构建目标时，会调用 `get_option_compile_args()` 和 `get_option_link_args()` 方法来生成编译和链接参数。
    * 在执行编译测试或特性检测时，会调用 `sanity_check()` 或 `has_header_symbol()` 方法。
4. **如果出现编译错误或配置问题：** 用户可能会查看 Meson 的输出日志，其中会包含调用的编译器命令和产生的错误信息。通过查看这些信息，结合 `c.py` 文件中各个方法的功能，可以推断出问题可能出现在哪个环节。
    * **例如：** 如果日志中显示的编译器命令缺少 `-std=c11` 参数，可能是因为 `get_option_compile_args()` 方法的逻辑有问题，或者用户指定的编译器版本不支持 C11 标准。
    * **例如：** 如果链接错误提示找不到某个库，可能是 `get_option_link_args()` 方法没有正确生成链接参数，或者用户在 `winlibs` 中指定了错误的库名。

**总结 `c.py` 的功能：**

总而言之，`frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/c.py` 文件的核心功能是**作为 Meson 构建系统中 C 语言编译器的抽象层和配置管理器**。它定义了处理各种 C 编译器的通用接口和特定逻辑，负责管理编译器选项、检测编译器特性，并生成用于编译和链接的命令行参数，为 Frida 项目的 C 代码构建提供基础支持。 这使得 Meson 能够以统一的方式处理不同的 C 编译器，提高了构建系统的灵活性和可移植性。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/c.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
"""


```