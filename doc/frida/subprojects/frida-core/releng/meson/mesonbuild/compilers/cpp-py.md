Response:
The user wants a summary of the functionalities of the provided Python code. I need to analyze the code to understand its purpose and key features. The code seems to define different C++ compiler classes for use within the Meson build system. It handles compiler-specific flags, standard library linking, and various options related to C++ development.

Here's a breakdown of the thinking process:

1. **Identify the Core Purpose:** The filename and the initial comments clearly indicate this file is part of the Frida project and deals with C++ compiler definitions within the Meson build system. This suggests the primary goal is to provide a way for Meson to interact with different C++ compilers.

2. **Analyze Class Structure:**  The code defines a base class `CPPCompiler` and then a hierarchy of derived classes, each representing a specific C++ compiler (e.g., `ClangCPPCompiler`, `GnuCPPCompiler`, `MSVCCompiler`). This pattern suggests a strategy to handle compiler-specific behavior.

3. **Examine Key Methods:**  Focus on the important methods within the classes:
    * `__init__`:  Initialization logic, often setting up compiler paths and versions.
    * `sanity_check`:  A basic test to verify the compiler is working.
    * `get_options`:  Defines the configurable options for each compiler (e.g., C++ standard, exception handling, RTTI).
    * `get_option_compile_args`:  Translates user-defined options into compiler-specific command-line arguments for compilation.
    * `get_option_link_args`: Translates user-defined options into compiler-specific command-line arguments for linking.
    * `has_header_symbol`: Checks if a header file contains a specific symbol.
    * `_find_best_cpp_std`:  Handles the selection of the appropriate `-std` flag.
    * `language_stdlib_only_link_flags`:  Determines the correct C++ standard library to link against.
    * `get_assert_args`:  Handles arguments related to enabling or disabling assertions.

4. **Identify Mixins:** The use of mixin classes (e.g., `CLikeCompiler`, `GnuCompiler`, `MSVCCompiler`) indicates a strategy for sharing common functionalities across different compiler types. This helps avoid code duplication.

5. **Infer Functionalities from Methods:** Based on the methods, I can deduce the core functionalities:
    * **Compiler Abstraction:** Provides a unified interface for interacting with different C++ compilers.
    * **Option Handling:**  Allows users to configure compiler behavior through Meson's option system.
    * **Standard Compliance:**  Manages the `-std` flag for different C++ standards.
    * **Library Linking:**  Handles the linking of standard C++ libraries (libstdc++, libc++).
    * **Feature Detection:**  Provides mechanisms to check for the presence of headers and symbols.
    * **Warning Level Configuration:** Supports different warning levels.
    * **Exception Handling Configuration:** Allows users to control exception handling.
    * **RTTI Control:**  Enables or disables Run-Time Type Information.
    * **Debugging Support:**  Includes options for STL debugging.

6. **Consider the Context (Frida):** Although the provided code is about compiler definitions, knowing it's part of Frida is important. Frida is a dynamic instrumentation toolkit. This implies that the way these compilers are used within Frida will be related to compiling code that gets injected or interacts with running processes.

7. **Formulate the Summary:**  Based on the analysis, I can now summarize the key functions. I need to focus on the high-level purpose and the main features offered by the code.

8. **Refine the Summary:** Ensure the summary is concise, clear, and accurately reflects the code's purpose. Use terminology appropriate for software development and build systems.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cpp.py` 文件的第一部分，它主要定义了 **Meson 构建系统中用于处理 C++ 编译器的各种类和方法**。 这些类和方法旨在抽象不同 C++ 编译器的差异，并为 Meson 提供一个统一的接口来执行 C++ 代码的编译和链接。

**以下是其主要功能的归纳：**

1. **C++ 编译器类的定义:**  文件中定义了 `CPPCompiler` 基类，以及一系列继承自 `CPPCompiler` 或其他 mixin 类的子类，例如 `ClangCPPCompiler`, `GnuCPPCompiler`, `MSVCCompiler` 等。每个子类代表一个特定的 C++ 编译器（例如 Clang, GCC, MSVC）。

2. **编译器属性和配置:**  这些类包含了特定编译器的信息，例如编译器名称 (`id`)，支持的警告选项 (`warn_args`)，以及用于编译和链接的默认参数。

3. **编译器选项管理:**  通过 `get_options` 方法，每个编译器类都定义了用户可以配置的选项，例如 C++ 标准 (`std`)、异常处理 (`eh`)、RTTI (Run-Time Type Information) (`rtti`)、STL 调试模式 (`debugstl`) 等。Meson 将使用这些信息来生成构建系统的配置选项。

4. **编译参数生成:**  `get_option_compile_args` 方法根据用户选择的选项，生成特定编译器所需的命令行编译参数。例如，根据 `std` 选项的值，会生成 `-std=c++17` 或类似参数。

5. **链接参数生成:**  `get_option_link_args` 方法根据用户选择的选项，生成特定编译器所需的命令行链接参数。例如，对于 Windows 平台，可以指定需要链接的 Windows 库。

6. **头文件和符号检查:**  `has_header_symbol` 方法用于检查特定的头文件中是否存在某个符号。这对于在编译时确定某些库或特性的可用性非常有用。

7. **标准库处理:**  `_StdCPPLibMixin` 混合类及其 `language_stdlib_only_link_flags` 方法用于检测应该链接哪个 C++ 标准库（例如 `libstdc++` 或 `libc++`），并生成相应的链接参数。

8. **Sanity Check (完整性检查):** `sanity_check` 方法用于执行一个简单的编译测试，以确保编译器可以正常工作。

9. **预编译头文件 (PCH) 支持:** `get_pch_use_args` 方法定义了使用预编译头文件的编译参数。

10. **断言处理:** `get_assert_args` 方法用于生成启用或禁用断言的编译参数。

11. **C++ 标准支持:**  代码中定义了 `_ALL_STDS` 列表，包含了所有支持的 C++ 标准。  `_find_best_cpp_std` 方法用于找到编译器支持的最佳 C++ 标准版本。

**与逆向方法的关系 (推测):**

虽然这个文件本身没有直接实现逆向操作，但它是 Frida 项目的一部分，而 Frida 是一种动态 instrumentation 工具，广泛用于逆向工程。 这个文件所定义的编译器配置和抽象，对于 Frida 构建其核心组件（`frida-core`）至关重要。

* **构建注入代码:**  Frida 经常需要编译一些小的 C++ 代码片段，然后注入到目标进程中执行。 这个文件中的编译器定义确保了 Frida 可以使用合适的编译器和编译选项来构建这些注入代码。 例如，可能需要使用特定的 C++ 标准或禁用某些特性以保证兼容性。
* **构建 Frida 自身:** `frida-core` 本身是用 C++ 编写的。 这个文件定义了如何使用不同的 C++ 编译器来构建 Frida 的核心库。

**涉及的二进制底层、Linux、Android 内核及框架知识 (推测):**

* **二进制底层:**  编译器的工作是将高级 C++ 代码转换为机器码，这涉及到对目标 CPU 架构的深入理解。 这个文件通过编译器抽象，隐藏了这些底层的细节，但编译器的选择和配置会直接影响最终生成的二进制代码。
* **Linux:**  许多编译器类（例如 `GnuCPPCompiler`, `ClangCPPCompiler`）的特定参数和行为与 Linux 平台密切相关。例如，链接标准库的方式在 Linux 上与 Windows 上有所不同。
* **Android 内核及框架:** 虽然代码本身没有直接涉及 Android 内核，但由于 Frida 经常用于 Android 平台的逆向，因此用于构建 Frida 的编译器可能需要支持 Android NDK (Native Development Kit) 提供的工具链，并了解 Android 平台的 ABI (Application Binary Interface)。

**逻辑推理示例 (假设输入与输出):**

假设用户在 Meson 构建文件中设置了以下选项：

```meson
cpp_std = 'c++17'
cpp_eh = 'none'
```

并且当前正在使用 `GnuCPPCompiler`。

**输入:** `options` 对象包含 `{'std': 'c++17', 'eh': 'none'}`。

**逻辑推理 (在 `GnuCPPCompiler.get_option_compile_args` 中):**

1. `std.value` 是 `'c++17'`，不等于 `'none'`。
2. 调用 `self._find_best_cpp_std('c++17')`，假设 GCC 支持 `c++17`，则返回 `'-std=c++17'`。
3. `options[key.evolve('eh')].value` 是 `'none'`。
4. 调用 `non_msvc_eh_options('none', args)`，将 `'-fno-exceptions'` 添加到 `args` 列表中。

**输出:** `args` 列表为 `['-std=c++17', '-fno-exceptions']`。

**用户或编程常见的使用错误 (举例说明):**

* **指定了编译器不支持的 C++ 标准:**  如果用户指定了 `cpp_std = 'c++2x'`，但使用的编译器版本较旧，不支持该标准，Meson 会抛出错误，因为 `_find_best_cpp_std` 无法找到合适的参数。
* **C++ 标准和链接库不匹配:**  例如，如果代码使用了 C++11 的特性，但链接了为旧版本 C++ 编译的库，可能会导致链接错误或运行时问题。Meson 尝试通过 `language_stdlib_only_link_flags` 来缓解这个问题，但用户仍然可能手动指定不兼容的链接选项。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户执行 `meson setup builddir` 命令:** Meson 开始读取构建定义文件 (`meson.build`)。
2. **Meson 检测到 C++ 项目:** 构建定义中可能包含 `project('myproject', 'cpp')`。
3. **Meson 确定使用的 C++ 编译器:**  这可以通过环境变量、命令行参数或 Meson 的自动检测机制来完成。
4. **Meson 加载相应的编译器模块:**  根据确定的编译器，Meson 会加载 `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cpp.py` 文件，并实例化相应的编译器类（例如 `GnuCPPCompiler`）。
5. **Meson 处理用户定义的选项:**  如果在 `meson.build` 或命令行中定义了 C++ 相关的选项（例如 `cpp_std`），Meson 会将这些选项传递给编译器对象的 `get_option_compile_args` 和 `get_option_link_args` 方法。
6. **在编译或链接阶段:** Meson 使用 `get_option_compile_args` 和 `get_option_link_args` 返回的参数来调用实际的 C++ 编译器。

总而言之，这个文件的核心功能是为 Meson 提供了一个灵活且可扩展的框架来管理各种 C++ 编译器的配置和使用，使其能够跨平台地构建 C++ 项目。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/cpp.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
```