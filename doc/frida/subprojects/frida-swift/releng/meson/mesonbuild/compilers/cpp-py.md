Response:
The user wants a summary of the Python code provided. I need to identify the main functionalities of this `cpp.py` file within the context of the Frida dynamic instrumentation tool.

The file defines the `CPPCompiler` class and several subclasses for different C++ compilers (like GCC, Clang, MSVC). It seems to be part of Meson's build system, specifically handling C++ compilation settings.

Here's a breakdown of the likely functionalities:

1. **Abstraction of C++ Compilers:**  The code provides a base class (`CPPCompiler`) and specific implementations for various C++ compilers. This allows Meson to work with different compilers in a consistent way.
2. **Compiler Option Handling:** It manages compiler-specific options like standard library versions (`-std`), exception handling (`-fno-exceptions`, `/EHsc`), and RTTI (`-fno-rtti`, `/GR-`).
3. **Standard Library Detection:**  The `_StdCPPLibMixin` suggests it can detect the C++ standard library being used (libstdc++ or libc++).
4. **Sanity Checks:** The `sanity_check` method indicates the ability to perform basic tests to ensure the compiler is working.
5. **Feature Detection:** Methods like `has_header_symbol` are used to check for the presence of specific symbols in headers, a common task in build systems.
6. **Warning Level Management:**  Different warning levels are defined and mapped to compiler flags (e.g., `-Wall`, `-Wextra`).
7. **Cross-Compilation Support:** The inclusion of `is_cross` in the `__init__` methods indicates support for building for different target architectures.
8. **Integration with Meson:** The code uses Meson's internal structures like `coredata`, `mlog`, `Environment`, and `OptionKey`.

Now, let's consider the specific questions:

* **Relationship to reverse engineering:** While the code itself isn't directly involved in reverse engineering, the *output* of the compilation process is what's often reverse-engineered. The ability to control compiler flags (like disabling optimizations or including debug symbols, though not explicitly shown here) can be relevant.
* **Binary/OS knowledge:** The handling of platform-specific options (like Windows libraries) and the need to detect standard libraries are tied to the underlying operating system and binary formats.
* **Logic/reasoning:** The `_find_best_cpp_std` function exemplifies logical reasoning by trying different `-std` flags to find the one supported by the compiler.
* **User errors:**  Incorrectly specifying compiler options or standard library versions could lead to build failures.
* **User operation to reach here:**  A user would interact with Meson's build configuration (e.g., `meson_options.txt` or command-line arguments) to set C++ compiler options, which would eventually be processed by this code.
这是 frida 动态 instrumentation 工具中负责处理 C++ 编译器相关的源代码文件。它定义了 `CPPCompiler` 基类以及针对各种具体 C++ 编译器的子类（例如 ClangCPPCompiler、GnuCPPCompiler、MSVCCompiler 等）。该文件的主要功能是为 Meson 构建系统提供一个统一的接口来管理和调用不同的 C++ 编译器，并处理与 C++ 语言相关的编译选项和特性。

**以下是该文件的功能归纳：**

1. **C++ 编译器抽象和统一接口:**
   - 定义了 `CPPCompiler` 基类，作为所有 C++ 编译器的抽象。
   - 针对不同的 C++ 编译器（如 GCC、Clang、MSVC、Intel 等）提供了具体的子类实现，封装了各自编译器的特性和调用方式。
   - 使得 Meson 构建系统能够以统一的方式处理不同的 C++ 编译器，隐藏了底层编译器的差异。

2. **C++ 编译选项管理:**
   - 负责处理各种 C++ 特有的编译选项，例如：
     - **C++ 标准:**  通过 `-std` 参数指定 C++ 标准版本（如 c++11, c++14, c++17 等），并能根据编译器版本选择合适的标准。
     - **异常处理:** 管理 C++ 异常处理的选项（如 `-fno-exceptions`, `/EHsc` 等）。
     - **RTTI (运行时类型识别):**  控制 RTTI 的启用与禁用（如 `-fno-rtti`, `/GR-`）。
     - **STL 调试模式:**  管理标准模板库的调试选项（如 `-D_GLIBCXX_DEBUG=1`）。
     - **警告级别:**  定义不同级别的警告选项，并映射到具体的编译器参数（如 `-Wall`, `-Wextra`）。
     - **Windows 库:**  管理 Windows 平台需要链接的标准库。

3. **C++ 标准库处理:**
   - 提供了 `_StdCPPLibMixin`，用于检测和处理 C++ 标准库 (libc++ 或 libstdc++) 的链接。
   - 能够自动添加正确的标准库链接参数。

4. **编译器特性检测:**
   - 实现了 `has_header_symbol` 方法，用于检查头文件中是否存在特定的符号，这对于条件编译和特性检测非常重要。
   - 实现了 `sanity_check` 方法，用于执行基本的编译器健全性检查。
   - 提供了 `attribute_check_func` 方法，用于检查函数属性是否被编译器支持。

5. **跨平台和交叉编译支持:**
   - 通过 `for_machine` 和 `is_cross` 参数，支持针对不同目标平台的交叉编译。
   - 针对不同的操作系统（如 Windows, Linux）和编译器，提供相应的默认库和选项。

6. **与 Meson 构建系统的集成:**
   - 该文件是 Meson 构建系统的一部分，使用了 Meson 提供的 API 和数据结构，例如 `coredata`、`mlog`、`Environment`、`OptionKey` 等。
   - 通过 `get_options` 方法，将 C++ 相关的编译选项暴露给 Meson 的配置系统。

**与逆向的方法的关系举例说明：**

* **控制异常处理:** 逆向工程师有时需要了解程序如何处理异常。通过 Meson 配置，用户可以选择不同的异常处理选项 (`eh`)，这会影响最终生成的可执行文件的行为。例如，如果禁用异常处理 (`'none'`)，逆向分析时可能需要关注其他的错误处理机制。
* **控制 RTTI:**  RTTI 包含了类的类型信息，这对于逆向分析多态和继承结构很有帮助。通过 Meson 配置，可以启用或禁用 RTTI。禁用 RTTI (`rtti=False`) 会使逆向分析类结构变得更加困难，因为类型信息会被移除。
* **选择 C++ 标准:** 不同的 C++ 标准引入了不同的语言特性。逆向工程师可能需要了解目标程序是用哪个 C++ 标准编译的，以便更好地理解其代码结构和行为。Meson 允许用户指定 C++ 标准 (`std`)，这会影响编译器使用的语言版本和特性。
* **调试符号:** 虽然该文件没有直接涉及调试符号，但作为编译器配置的一部分，Meson 最终会调用编译器来生成包含或不包含调试符号的可执行文件。调试符号对于逆向工程至关重要，因为它们提供了函数名、变量名和源代码行号等信息。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明：**

* **Windows 库 (`winlibs`):**  `gnu_winlibs` 和 `msvc_winlibs` 变量包含了 Windows 平台上常见的需要链接的库，例如 `kernel32`, `user32`, `ws2_32` 等。这些库是 Windows API 的核心组成部分，涉及到操作系统底层的调用和功能。在 Frida 用于 hook Windows 平台上的进程时，理解这些库的作用至关重要。
* **标准库链接 (`_StdCPPLibMixin`):**  在 Linux 和 Android 等平台上，C++ 程序通常依赖于 `libstdc++` (GCC) 或 `libc++` (Clang) 标准库。这个文件能够检测并正确链接这些标准库，这涉及到对不同 Linux 发行版和 Android 平台的库搜索路径和命名约定的理解。Frida 本身也需要与目标进程的 C++ 标准库兼容。
* **异常处理机制:**  不同的编译器和操作系统有不同的异常处理实现方式。例如，GCC 使用 Itanium C++ ABI，而 MSVC 有自己的 SEH 机制。`eh` 选项的选择会影响生成的二进制文件的异常处理结构，这与底层的操作系统异常处理机制紧密相关。理解这些机制对于在 Frida 中进行异常相关的 hook 和分析非常重要。
* **架构相关的编译选项:** 虽然在这个代码片段中没有显式展示，但 `for_machine` 参数表明 Meson 和这个编译器模块能够处理不同架构（如 x86, ARM）的编译。这涉及到对不同 CPU 架构的指令集、调用约定和 ABI 的理解，这些知识在逆向 Android (通常是 ARM 架构) 上的 native 代码时至关重要。

**逻辑推理的假设输入与输出举例：**

* **假设输入:** 用户在 Meson 配置中指定 `std = 'c++14'`，并且使用的编译器是 Clang 版本 10.0.0。
* **逻辑推理:**  `_find_best_cpp_std` 函数会被调用。由于 Clang 10.0.0 支持 `-std=c++14`，因此会直接返回 `'-std=c++14'`。
* **输出:**  最终传递给 Clang 编译器的编译参数中会包含 `'-std=c++14'`。

* **假设输入:** 用户在 Meson 配置中指定 `std = 'c++17'`，并且使用的编译器是旧版本的 GCC，可能不支持 `-std=c++17`。
* **逻辑推理:** `_find_best_cpp_std` 函数会被调用。由于 GCC 不支持 `c++17`，它可能会尝试回退到更早的版本，例如 `c++1z`。如果 `c++1z` 也不支持，则会抛出一个 `MesonException`。
* **输出:** 如果找到支持的版本，例如 `c++1z`，则输出 `'-std=c++1z'`。否则，会抛出构建错误。

**涉及用户或者编程常见的使用错误举例说明：**

* **指定了编译器不支持的 C++ 标准:** 用户在 Meson 配置中指定了一个当前使用的编译器版本不支持的 C++ 标准（例如，使用旧版本的 GCC 指定 `std = 'c++20'`）。这会导致 Meson 尝试传递一个无效的 `-std` 参数给编译器，最终导致编译失败，并可能在 Meson 的日志中看到相关的错误信息。
* **错误的异常处理选项:** 用户可能错误地为非 MSVC 编译器设置了 `'s'` 或 `'c'` 异常处理选项。该代码会发出警告，提示用户这些选项不受支持，并建议使用 `'default'`。
* **链接了不兼容的 Windows 库:**  用户可能在 `winlibs` 中添加了不适用于当前构建环境的 Windows 库，这会导致链接错误。
* **在交叉编译时使用了主机平台的库:** 用户可能在交叉编译时尝试链接主机系统上的库，而不是目标平台的库，这会导致链接失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户创建或修改了 `meson.build` 文件:**  在 `meson.build` 文件中，用户通过 `project()` 函数指定了项目名称和使用的编程语言，其中可能包括 `'cpp'`。
2. **用户可能创建或修改了 `meson_options.txt` 文件:**  在这个文件中，用户可以设置各种构建选项，包括 C++ 编译器的相关选项，例如 `cpp_std`，`cpp_eh`，`cpp_rtti` 等。或者，用户也可以通过命令行参数传递这些选项给 Meson。
3. **用户运行 `meson setup builddir` 命令:**  Meson 会读取 `meson.build` 和 `meson_options.txt` 文件，并根据用户的配置生成构建系统。在这个过程中，Meson 会检测系统中可用的 C++ 编译器。
4. **Meson 初始化 C++ 编译器对象:**  根据检测到的 C++ 编译器类型，Meson 会创建 `cpp.py` 文件中对应的编译器类实例（例如 `ClangCPPCompiler`, `GnuCPPCompiler`）。
5. **Meson 处理编译选项:**  当 Meson 需要编译 C++ 代码时，它会调用编译器对象的 `get_option_compile_args` 和 `get_option_link_args` 等方法，这些方法会根据用户设置的选项和编译器的特性，生成传递给编译器的具体参数。
6. **如果出现编译错误:**  用户可能会查看 Meson 的构建日志，其中会包含编译器调用的命令和输出信息。如果错误与 C++ 编译选项有关，调试时可以回到 `meson_options.txt` 文件或命令行参数，检查 C++ 相关的选项是否设置正确。也可以检查 `cpp.py` 文件中对应编译器的选项处理逻辑，看是否有 bug 或者配置错误。

总而言之，`frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/cpp.py` 文件的核心功能是 **抽象和管理 C++ 编译器的配置和调用，以便 Meson 构建系统能够跨平台、灵活地处理 C++ 项目的构建过程。** 它负责将用户在高层次配置中指定的 C++ 选项转换为底层编译器能够理解的命令行参数，并处理不同编译器之间的差异。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/cpp.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2017 The Meson development team

from __future__ import annotations

import copy
import functools
import os.path
import typing as T

from .. import coredata
from .. import mlog
from ..mesonlib import MesonException, version_compare, OptionKey

from .compilers import (
    gnu_winlibs,
    msvc_winlibs,
    Compiler,
    CompileCheckMode,
)
from .c_function_attributes import CXX_FUNC_ATTRIBUTES, C_FUNC_ATTRIBUTES
from .mixins.clike import CLikeCompiler
from .mixins.ccrx import CcrxCompiler
from .mixins.ti import TICompiler
from .mixins.arm import ArmCompiler, ArmclangCompiler
from .mixins.visualstudio import MSVCCompiler, ClangClCompiler
from .mixins.gnu import GnuCompiler, gnu_common_warning_args, gnu_cpp_warning_args
from .mixins.intel import IntelGnuLikeCompiler, IntelVisualStudioLikeCompiler
from .mixins.clang import ClangCompiler
from .mixins.elbrus import ElbrusCompiler
from .mixins.pgi import PGICompiler
from .mixins.emscripten import EmscriptenMixin
from .mixins.metrowerks import MetrowerksCompiler
from .mixins.metrowerks import mwccarm_instruction_set_args, mwcceppc_instruction_set_args

if T.TYPE_CHECKING:
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..dependencies import Dependency
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    CompilerMixinBase = CLikeCompiler
else:
    CompilerMixinBase = object

_ALL_STDS = ['c++98', 'c++0x', 'c++03', 'c++1y', 'c++1z', 'c++11', 'c++14', 'c++17', 'c++2a', 'c++20', 'c++23', 'c++26']
_ALL_STDS += [f'gnu{std[1:]}' for std in _ALL_STDS]
_ALL_STDS += ['vc++11', 'vc++14', 'vc++17', 'vc++20', 'vc++latest', 'c++latest']


def non_msvc_eh_options(eh: str, args: T.List[str]) -> None:
    if eh == 'none':
        args.append('-fno-exceptions')
    elif eh in {'s', 'c'}:
        mlog.warning(f'non-MSVC compilers do not support {eh} exception handling. '
                     'You may want to set eh to \'default\'.', fatal=False)

class CPPCompiler(CLikeCompiler, Compiler):
    def attribute_check_func(self, name: str) -> str:
        try:
            return CXX_FUNC_ATTRIBUTES.get(name, C_FUNC_ATTRIBUTES[name])
        except KeyError:
            raise MesonException(f'Unknown function attribute "{name}"')

    language = 'cpp'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        # If a child ObjCPP class has already set it, don't set it ourselves
        Compiler.__init__(self, ccache, exelist, version, for_machine, info,
                          is_cross=is_cross, linker=linker,
                          full_version=full_version)
        CLikeCompiler.__init__(self)

    @classmethod
    def get_display_language(cls) -> str:
        return 'C++'

    def get_no_stdinc_args(self) -> T.List[str]:
        return ['-nostdinc++']

    def get_no_stdlib_link_args(self) -> T.List[str]:
        return ['-nostdlib++']

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        code = 'class breakCCompiler;int main(void) { return 0; }\n'
        return self._sanity_check_impl(work_dir, environment, 'sanitycheckcpp.cc', code)

    def get_compiler_check_args(self, mode: CompileCheckMode) -> T.List[str]:
        # -fpermissive allows non-conforming code to compile which is necessary
        # for many C++ checks. Particularly, the has_header_symbol check is
        # too strict without this and always fails.
        return super().get_compiler_check_args(mode) + ['-fpermissive']

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        # Check if it's a C-like symbol
        found, cached = super().has_header_symbol(hname, symbol, prefix, env,
                                                  extra_args=extra_args,
                                                  dependencies=dependencies)
        if found:
            return True, cached
        # Check if it's a class or a template
        if extra_args is None:
            extra_args = []
        t = f'''{prefix}
        #include <{hname}>
        using {symbol};
        int main(void) {{ return 0; }}'''
        return self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)

    def _test_cpp_std_arg(self, cpp_std_value: str) -> bool:
        # Test whether the compiler understands a -std=XY argument
        assert cpp_std_value.startswith('-std=')

        # This test does not use has_multi_arguments() for two reasons:
        # 1. has_multi_arguments() requires an env argument, which the compiler
        #    object does not have at this point.
        # 2. even if it did have an env object, that might contain another more
        #    recent -std= argument, which might lead to a cascaded failure.
        CPP_TEST = 'int i = static_cast<int>(0);'
        with self.compile(CPP_TEST, extra_args=[cpp_std_value], mode=CompileCheckMode.COMPILE) as p:
            if p.returncode == 0:
                mlog.debug(f'Compiler accepts {cpp_std_value}:', 'YES')
                return True
            else:
                mlog.debug(f'Compiler accepts {cpp_std_value}:', 'NO')
                return False

    @functools.lru_cache()
    def _find_best_cpp_std(self, cpp_std: str) -> str:
        # The initial version mapping approach to make falling back
        # from '-std=c++14' to '-std=c++1y' was too brittle. For instance,
        # Apple's Clang uses a different versioning scheme to upstream LLVM,
        # making the whole detection logic awfully brittle. Instead, let's
        # just see if feeding GCC or Clang our '-std=' setting works, and
        # if not, try the fallback argument.
        CPP_FALLBACKS = {
            'c++11': 'c++0x',
            'gnu++11': 'gnu++0x',
            'c++14': 'c++1y',
            'gnu++14': 'gnu++1y',
            'c++17': 'c++1z',
            'gnu++17': 'gnu++1z',
            'c++20': 'c++2a',
            'gnu++20': 'gnu++2a',
            'c++23': 'c++2b',
            'gnu++23': 'gnu++2b',
            'c++26': 'c++2c',
            'gnu++26': 'gnu++2c',
        }

        # Currently, remapping is only supported for Clang, Elbrus and GCC
        assert self.id in frozenset(['clang', 'lcc', 'gcc', 'emscripten', 'armltdclang', 'intel-llvm'])

        if cpp_std not in CPP_FALLBACKS:
            # 'c++03' and 'c++98' don't have fallback types
            return '-std=' + cpp_std

        for i in (cpp_std, CPP_FALLBACKS[cpp_std]):
            cpp_std_value = '-std=' + i
            if self._test_cpp_std_arg(cpp_std_value):
                return cpp_std_value

        raise MesonException(f'C++ Compiler does not support -std={cpp_std}')

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = super().get_options()
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts.update({
            key: coredata.UserStdOption('C++', _ALL_STDS),
        })
        return opts


class _StdCPPLibMixin(CompilerMixinBase):

    """Detect whether to use libc++ or libstdc++."""

    @functools.lru_cache(None)
    def language_stdlib_only_link_flags(self, env: Environment) -> T.List[str]:
        """Detect the C++ stdlib and default search dirs

        As an optimization, this method will cache the value, to avoid building the same values over and over

        :param env: An Environment object
        :raises MesonException: If a stdlib cannot be determined
        """

        # We need to apply the search prefix here, as these link arguments may
        # be passed to a different compiler with a different set of default
        # search paths, such as when using Clang for C/C++ and gfortran for
        # fortran.
        search_dirs = [f'-L{d}' for d in self.get_compiler_dirs(env, 'libraries')]

        machine = env.machines[self.for_machine]
        assert machine is not None, 'for mypy'

        # https://stackoverflow.com/a/31658120
        header = 'version' if self.has_header('<version>', '', env) else 'ciso646'
        is_libcxx = self.has_header_symbol(header, '_LIBCPP_VERSION', '', env)[0]
        lib = 'c++' if is_libcxx else 'stdc++'

        if self.find_library(lib, env, []) is not None:
            return search_dirs + [f'-l{lib}']

        # TODO: maybe a bug exception?
        raise MesonException('Could not detect either libc++ or libstdc++ as your C++ stdlib implementation.')


class ClangCPPCompiler(_StdCPPLibMixin, ClangCompiler, CPPCompiler):

    _CPP23_VERSION = '>=12.0.0'
    _CPP26_VERSION = '>=17.0.0'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        ClangCompiler.__init__(self, defines)
        default_warn_args = ['-Wall', '-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': ['-Weverything']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CPPCompiler.get_options(self)
        key = OptionKey('key', machine=self.for_machine, lang=self.language)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('rtti'),
                               'Enable RTTI',
                               True),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('debugstl'),
                               'STL debug mode',
                               False),
        )
        cppstd_choices = [
            'c++98', 'c++03', 'c++11', 'c++14', 'c++17', 'c++1z', 'c++2a', 'c++20',
        ]
        if version_compare(self.version, self._CPP23_VERSION):
            cppstd_choices.append('c++23')
        if version_compare(self.version, self._CPP26_VERSION):
            cppstd_choices.append('c++26')
        std_opt = opts[key.evolve('std')]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(cppstd_choices, gnu=True)
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
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append(self._find_best_cpp_std(std.value))

        non_msvc_eh_options(options[key.evolve('eh')].value, args)

        if options[key.evolve('debugstl')].value:
            args.append('-D_GLIBCXX_DEBUG=1')

            # We can't do _LIBCPP_DEBUG because it's unreliable unless libc++ was built with it too:
            # https://discourse.llvm.org/t/building-a-program-with-d-libcpp-debug-1-against-a-libc-that-is-not-itself-built-with-that-define/59176/3
            # Note that unlike _GLIBCXX_DEBUG, _MODE_DEBUG doesn't break ABI. It's just slow.
            if version_compare(self.version, '>=18'):
                args.append('-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG')

        if not options[key.evolve('rtti')].value:
            args.append('-fno-rtti')

        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        if self.info.is_windows() or self.info.is_cygwin():
            # without a typedict mypy can't understand this.
            key = OptionKey('winlibs', machine=self.for_machine, lang=self.language)
            libs = options[key].value.copy()
            assert isinstance(libs, list)
            for l in libs:
                assert isinstance(l, str)
            return libs
        return []

    def get_assert_args(self, disable: bool) -> T.List[str]:
        args: T.List[str] = []
        if disable:
            return ['-DNDEBUG']

        # Clang supports both libstdc++ and libc++
        args.append('-D_GLIBCXX_ASSERTIONS=1')
        if version_compare(self.version, '>=18'):
            args.append('-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE')
        elif version_compare(self.version, '>=15'):
            args.append('-D_LIBCPP_ENABLE_ASSERTIONS=1')

        return args


class ArmLtdClangCPPCompiler(ClangCPPCompiler):

    id = 'armltdclang'


class AppleClangCPPCompiler(ClangCPPCompiler):

    _CPP23_VERSION = '>=13.0.0'
    # TODO: We don't know which XCode version will include LLVM 17 yet, so
    # use something absurd.
    _CPP26_VERSION = '>=99.0.0'


class EmscriptenCPPCompiler(EmscriptenMixin, ClangCPPCompiler):

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
        ClangCPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                                  info, linker=linker,
                                  defines=defines, full_version=full_version)

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append(self._find_best_cpp_std(std.value))
        return args


class ArmclangCPPCompiler(ArmclangCompiler, CPPCompiler):
    '''
    Keil armclang
    '''

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        ArmclangCompiler.__init__(self)
        default_warn_args = ['-Wall', '-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': ['-Weverything']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CPPCompiler.get_options(self)
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
        )
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(['c++98', 'c++03', 'c++11', 'c++14', 'c++17'], gnu=True)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('-std=' + std.value)

        non_msvc_eh_options(options[key.evolve('eh')].value, args)

        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []


class GnuCPPCompiler(_StdCPPLibMixin, GnuCompiler, CPPCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        GnuCompiler.__init__(self, defines)
        default_warn_args = ['-Wall', '-Winvalid-pch']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic'],
                          'everything': (default_warn_args + ['-Wextra', '-Wpedantic'] +
                                         self.supported_warn_args(gnu_common_warning_args) +
                                         self.supported_warn_args(gnu_cpp_warning_args))}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts = CPPCompiler.get_options(self)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('rtti'),
                               'Enable RTTI',
                               True),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('debugstl'),
                               'STL debug mode',
                               False),
        )
        cppstd_choices = [
            'c++98', 'c++03', 'c++11', 'c++14', 'c++17', 'c++1z',
            'c++2a', 'c++20',
        ]
        if version_compare(self.version, '>=11.0.0'):
            cppstd_choices.append('c++23')
        if version_compare(self.version, '>=14.0.0'):
            cppstd_choices.append('c++26')
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(cppstd_choices, gnu=True)
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
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append(self._find_best_cpp_std(std.value))

        non_msvc_eh_options(options[key.evolve('eh')].value, args)

        if not options[key.evolve('rtti')].value:
            args.append('-fno-rtti')

        if options[key.evolve('debugstl')].value:
            args.append('-D_GLIBCXX_DEBUG=1')
        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        if self.info.is_windows() or self.info.is_cygwin():
            # without a typedict mypy can't understand this.
            key = OptionKey('winlibs', machine=self.for_machine, lang=self.language)
            libs = options[key].value.copy()
            assert isinstance(libs, list)
            for l in libs:
                assert isinstance(l, str)
            return libs
        return []

    def get_assert_args(self, disable: bool) -> T.List[str]:
        if disable:
            return ['-DNDEBUG']

        # XXX: This needs updating if/when GCC starts to support libc++.
        # It currently only does so via an experimental configure arg.
        return ['-D_GLIBCXX_ASSERTIONS=1']

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        return ['-fpch-preprocess', '-include', os.path.basename(header)]


class PGICPPCompiler(PGICompiler, CPPCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        PGICompiler.__init__(self)


class NvidiaHPC_CPPCompiler(PGICompiler, CPPCompiler):

    id = 'nvidia_hpc'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        PGICompiler.__init__(self)


class ElbrusCPPCompiler(ElbrusCompiler, CPPCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 defines: T.Optional[T.Dict[str, str]] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        ElbrusCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CPPCompiler.get_options(self)

        cpp_stds = ['c++98']
        if version_compare(self.version, '>=1.20.00'):
            cpp_stds += ['c++03', 'c++0x', 'c++11']
        if version_compare(self.version, '>=1.21.00') and version_compare(self.version, '<1.22.00'):
            cpp_stds += ['c++14', 'c++1y']
        if version_compare(self.version, '>=1.22.00'):
            cpp_stds += ['c++14']
        if version_compare(self.version, '>=1.23.00'):
            cpp_stds += ['c++1y']
        if version_compare(self.version, '>=1.24.00'):
            cpp_stds += ['c++1z', 'c++17']
        if version_compare(self.version, '>=1.25.00'):
            cpp_stds += ['c++2a']
        if version_compare(self.version, '>=1.26.00'):
            cpp_stds += ['c++20']

        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('debugstl'),
                               'STL debug mode',
                               False),
        )
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(cpp_stds, gnu=True)
        return opts

    # Elbrus C++ compiler does not have lchmod, but there is only linker warning, not compiler error.
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

    # Elbrus C++ compiler does not support RTTI, so don't check for it.
    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append(self._find_best_cpp_std(std.value))

        non_msvc_eh_options(options[key.evolve('eh')].value, args)

        if options[key.evolve('debugstl')].value:
            args.append('-D_GLIBCXX_DEBUG=1')
        return args


class IntelCPPCompiler(IntelGnuLikeCompiler, CPPCompiler):
    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        CPPCompiler.__init__(self, ccache, exelist, version, for_machine, is_cross,
                             info, linker=linker, full_version=full_version)
        IntelGnuLikeCompiler.__init__(self)
        self.lang_header = 'c++-header'
        default_warn_args = ['-Wall', '-w3', '-Wpch-messages']
        self.warn_args = {'0': [],
                          '1': default_warn_args + ['-diag-disable:remark'],
                          '2': default_warn_args + ['-Wextra', '-diag-disable:remark'],
                          '3': default_warn_args + ['-Wextra', '-diag-disable:remark'],
                          'everything': default_warn_args + ['-Wextra']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = CPPCompiler.get_options(self)
        # Every Unix compiler under the sun seems to accept -std=c++03,
        # with the exception of ICC. Instead of preventing the user from
        # globally requesting C++03, we transparently remap it to C++98
        c_stds = ['c++98', 'c++03']
        g_stds = ['gnu++98', 'gnu++03']
        if version_compare(self.version, '>=15.0.0'):
            c_stds += ['c++11', 'c++14']
            g_stds += ['gnu++11']
        if version_compare(self.version, '>=16.0.0'):
            c_stds += ['c++17']
        if version_compare(self.version, '>=17.0.0'):
            g_stds += ['gnu++14']
        if version_compare(self.version, '>=19.1.0'):
            c_stds += ['c++2a']
            g_stds += ['gnu++2a']

        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('rtti'),
                               'Enable RTTI',
                               True),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('debugstl'),
                               'STL debug mode',
                               False),
        )
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(c_stds + g_stds)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            remap_cpp03 = {
                'c++03': 'c++98',
                'gnu++03': 'gnu++98'
            }
            args.append('-std=' + remap_cpp03.get(std.value, std.value))
        if options[key.evolve('eh')].value == 'none':
            args.append('-fno-exceptions')
        if not options[key.evolve('rtti')].value:
            args.append('-fno-rtti')
        if options[key.evolve('debugstl')].value:
            args.append('-D_GLIBCXX_DEBUG=1')
        return args

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []


class IntelLLVMCPPCompiler(ClangCPPCompiler):

    id = 'intel-llvm'


class VisualStudioLikeCPPCompilerMixin(CompilerMixinBase):

    """Mixin for C++ specific method overrides in MSVC-like compilers."""

    VC_VERSION_MAP = {
        'none': (True, None),
        'vc++11': (True, 11),
        'vc++14': (True, 14),
        'vc++17': (True, 17),
        'vc++20': (True, 20),
        'vc++latest': (True, "latest"),
        'c++11': (False, 11),
        'c++14': (False, 14),
        'c++17': (False, 17),
        'c++20': (False, 20),
        'c++latest': (False, "latest"),
    }

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        # need a typeddict for this
        key = OptionKey('winlibs', machine=self.for_machine, lang=self.language)
        return T.cast('T.List[str]', options[key].value[:])

    def _get_options_impl(self, opts: 'MutableKeyedOptionDictType', cpp_stds: T.List[str]) -> 'MutableKeyedOptionDictType':
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        self.update_options(
            opts,
            self.create_option(coredata.UserComboOption,
                               key.evolve('eh'),
                               'C++ exception handling type.',
                               ['none', 'default', 'a', 's', 'sc'],
                               'default'),
            self.create_option(coredata.UserBooleanOption,
                               key.evolve('rtti'),
                               'Enable RTTI',
                               True),
            self.create_option(coredata.UserArrayOption,
                               key.evolve('winlibs'),
                               'Windows libs to link against.',
                               msvc_winlibs),
        )
        std_opt = opts[key]
        assert isinstance(std_opt, coredata.UserStdOption), 'for mypy'
        std_opt.set_versions(cpp_stds)
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)

        eh = options[key.evolve('eh')]
        if eh.value == 'default':
            args.append('/EHsc')
        elif eh.value == 'none':
            args.append('/EHs-c-')
        else:
            args.append('/EH' + eh.value)

        if not options[key.evolve('rtti')].value:
            args.append('/GR-')

        permissive, ver = self.VC_VERSION_MAP[
"""


```