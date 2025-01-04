Response:
The user wants a summary of the functionality of the provided Python code.
This Python code defines classes for different C++ compilers used within the Frida dynamic instrumentation tool, as indicated by the file path `frida/releng/meson/mesonbuild/compilers/cpp.py`.

To summarize the functionality, I need to identify:
1. The core purpose of the file.
2. The main classes defined and their roles.
3. The common functionalities implemented by these classes.
4. Any connections to reverse engineering, low-level aspects, or common user errors.

Based on the code, this file seems to be part of the build system (Meson) configuration for Frida, specifically handling C++ compilation.

Here's a breakdown of the code's components:

- **Imports:** Standard Python libraries and Meson-specific modules related to core data, logging, compiler definitions, and compiler mixins.
- **Constants:** `_ALL_STDS` defines a list of supported C++ standard versions.
- **Helper Functions:** `non_msvc_eh_options` handles exception handling flags for non-MSVC compilers.
- **Base Class: `CPPCompiler`:** This class serves as a base for all C++ compiler implementations. It inherits from `CLikeCompiler` and `Compiler`. It provides common functionalities like:
    - Determining the display language.
    - Getting arguments to exclude standard include paths and libraries.
    - Performing sanity checks.
    - Getting compiler check arguments (with `-fpermissive`).
    - Checking for header symbols (with special handling for C++).
    - Testing and finding the best C++ standard argument.
    - Defining compiler-specific options (like C++ standard).
- **Mixin Classes:**  Classes like `_StdCPPLibMixin` provide reusable functionality (e.g., detecting the C++ standard library).
- **Concrete Compiler Classes:** Classes like `ClangCPPCompiler`, `GnuCPPCompiler`, `MSVCCompiler`, etc., inherit from `CPPCompiler` and specific mixins. Each class represents a particular C++ compiler and implements compiler-specific logic, including:
    - Setting default warning arguments.
    - Defining compiler-specific options (like exception handling, RTTI, debug STL).
    - Getting compiler and linker arguments based on selected options.
    - Handling assertions.

The file's primary function is to abstract the differences between various C++ compilers, allowing the build system to use a consistent interface for compiling C++ code regardless of the underlying compiler.

Connections to reverse engineering and low-level aspects will be explored in the subsequent parts of the prompt. Common user errors might involve selecting unsupported compiler options or standard versions.

The user's operation to reach this code would typically involve the build system (Meson) processing the project's build definition, detecting the C++ compiler, and then instantiating the corresponding compiler class from this file. This happens during the configuration phase of the build process.
好的，让我们来归纳一下 `frida/releng/meson/mesonbuild/compilers/cpp.py` 这个文件的功能。

**核心功能:**

这个 Python 源代码文件定义了 Frida 项目中用于处理 C++ 代码编译的各种编译器类的实现。它的主要目的是：

1. **抽象化不同的 C++ 编译器:**  针对不同的 C++ 编译器（例如 GCC, Clang, MSVC, Intel 等），提供了各自的类实现，封装了它们在命令行参数、选项处理等方面的差异。这使得构建系统（Meson）可以使用统一的接口来处理 C++ 代码的编译，而无需关心具体使用的编译器。

2. **定义和管理编译选项:**  每个编译器类都定义了其支持的编译选项，例如 C++ 标准版本 (`-std`)、异常处理 (`-fexceptions` 或 `/EHsc`)、RTTI (Run-Time Type Information) 的启用/禁用、STL 调试模式等。这些选项可以通过 Meson 的配置系统进行设置。

3. **生成编译器和链接器参数:**  根据用户的配置和选择的编译器，这些类负责生成传递给实际编译器和链接器的命令行参数。例如，根据选择的 C++ 标准版本，会生成 `-std=c++17` 这样的参数。

4. **提供编译器能力检测:**  文件中定义了一些方法来检测编译器的能力，例如 `has_header_symbol` 用于检查头文件中是否存在特定的符号。

5. **处理平台特定的库:**  对于某些编译器（如 Clang 和 GCC 在 Windows 上），会处理需要链接的标准 Windows 库 (`winlibs`)。

**更细致的功能点:**

* **支持多种 C++ 标准:** 通过 `_ALL_STDS` 定义了支持的 C++ 标准版本列表，并允许用户通过 `std` 选项进行选择。
* **异常处理选项:**  通过 `eh` 选项支持不同的 C++ 异常处理方式。
* **RTTI 控制:** 允许用户通过 `rtti` 选项启用或禁用 RTTI。
* **STL 调试模式:**  提供了 `debugstl` 选项来启用 STL 的调试模式 (例如 GCC 的 `_GLIBCXX_DEBUG` 或 Clang 的 `_LIBCPP_HARDENING_MODE`)。
* **断言控制:**  提供了 `get_assert_args` 方法来生成启用或禁用断言的编译器参数 (`-DNDEBUG` 或 `_GLIBCXX_ASSERTIONS=1` 等)。
* **预编译头文件支持:** `get_pch_use_args` 方法用于生成使用预编译头文件的编译器参数。
* **针对特定编译器的优化和调整:**  每个编译器类都可能包含针对其特性的代码，例如 Intel 编译器会将 `c++03` 映射到 `c++98`。
* **处理跨平台编译:** 考虑了跨平台编译的情况，例如 Emscripten 编译器只能用于交叉编译。

**与逆向方法的潜在关系 (虽然在这个文件中不直接体现，但编译器的行为会影响逆向):**

* **编译器优化:**  编译器在编译代码时会进行各种优化，这些优化可能会使逆向分析更加困难。例如，内联函数、循环展开、指令重排等都可能改变代码的结构，使得反汇编后的代码与源代码差异较大。
* **符号信息:** 编译器可以选择生成调试符号信息（例如 DWARF 或 PDB），这些信息对于逆向工程非常有用，因为它提供了函数名、变量名、类型信息等。Meson 的配置可能会影响是否生成这些符号。
* **异常处理机制:** 不同的编译器和平台实现异常处理的方式可能不同，理解这些机制对于逆向分析程序的异常处理流程至关重要。
* **RTTI:** 如果启用了 RTTI，会在二进制文件中生成额外的元数据，用于支持动态类型转换等特性。逆向工程师可以利用这些信息来理解对象的继承关系和多态行为。
* **安全特性:**  一些编译器支持安全特性，例如堆栈保护、地址空间布局随机化（ASLR）兼容等。这些特性旨在提高程序的安全性，但也可能增加逆向分析的难度。

**涉及二进制底层、Linux、Android 内核及框架的知识 (在这个文件中部分体现):**

* **二进制底层:** 这个文件与二进制底层有间接关系，因为它负责配置将源代码转换为机器码的过程。编译器生成的指令、数据布局、链接方式等都直接影响最终的二进制文件。
* **Linux 内核:**  在 Linux 平台上编译 C++ 代码时，需要链接到 C 标准库 (`libc`) 和 C++ 标准库 (`libstdc++` 或 `libc++`)，这些库与 Linux 内核紧密相关。例如，系统调用是通过这些库的封装来完成的。
* **Android 内核及框架:**  在为 Android 平台编译代码时，可能需要链接到 Android 特定的库，例如 `libandroid`。  这个文件中的编译器配置会影响最终生成的 Android 可执行文件或共享库的兼容性和行为。 例如，选择不同的 C++ 标准库实现 (libc++ 是 Android 官方推荐的) 会影响程序的运行环境。

**逻辑推理示例 (假设输入与输出):**

假设用户在 `meson.build` 文件中配置了使用 Clang 编译器，并且指定了 C++17 标准：

**假设输入:**

* 使用的编译器: Clang
* C++ 标准: `c++17`

**逻辑推理过程 (在 `ClangCPPCompiler` 类中):**

1. `get_option_compile_args` 方法被调用。
2. 从配置中获取 `std` 选项的值为 `c++17`。
3. 调用 `_find_best_cpp_std('c++17')`。
4. `_test_cpp_std_arg('-std=c++17')` 被调用，Clang 能够识别 `-std=c++17`。
5. `_find_best_cpp_std` 返回 `'-std=c++17'`。
6. `get_option_compile_args` 将 `'-std=c++17'` 添加到编译参数列表中。

**输出 (部分):**

* 传递给 Clang 编译器的参数列表中会包含 `'-std=c++17'`。

**用户或编程常见的使用错误举例:**

1. **指定编译器不支持的 C++ 标准:**  用户可能在 `meson.build` 中指定了一个编译器不支持的 C++ 标准版本。例如，对于一个旧版本的 GCC，指定 `c++23` 可能会导致构建失败。Meson 会尝试检测并给出错误提示，但有时可能需要用户查阅编译器文档。

   ```python
   # meson.build
   project('myproject', 'cpp',
       default_options: [
           'cpp_std=c++23'  # 如果当前 GCC 版本过低，可能不支持 c++23
       ]
   )
   ```

2. **错误配置异常处理选项:**  用户可能错误地配置了异常处理选项，例如在非 MSVC 编译器上使用了 `eh: 's'` 或 `'c'`，这会导致警告，因为这些选项不被支持。

   ```python
   # meson_options.txt
   cpp_eh = combo('', ['none', 'default', 'a', 's', 'sc'], value: 's') # 在 GCC/Clang 上使用 's' 可能不是预期行为
   ```

3. **链接错误的库:**  在 Windows 上，用户可能在 `winlibs` 选项中指定了不存在或不需要的库，导致链接失败。

   ```python
   # meson.build
   cpp_options = ['-DENABLE_FEATURE']
   if host_machine.system() == 'windows':
       cpp_winlibs = ['user32', 'gdi32', 'nonexistentlib'] # 'nonexistentlib' 会导致链接错误
   executable('myprogram', 'main.cpp', cpp_options: cpp_options, cpp_winlibs: cpp_winlibs)
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户执行 `meson setup builddir`:**  这是 Meson 构建过程的开始，Meson 会读取 `meson.build` 文件。
2. **Meson 解析 `meson.build` 并确定项目语言为 C++:**  Meson 会识别 `project('myproject', 'cpp', ...)`  声明。
3. **Meson 探测系统中的 C++ 编译器:**  Meson 会根据系统环境变量和预定义的查找路径，找到可用的 C++ 编译器（例如 g++, clang++, cl.exe）。
4. **Meson 加载对应的编译器模块:**  根据探测到的编译器，Meson 会加载 `frida/releng/meson/mesonbuild/compilers/cpp.py` 文件，并实例化相应的编译器类（例如 `GnuCPPCompiler`, `ClangCPPCompiler` 或 `MSVCCompiler`）。
5. **Meson 处理编译选项:**  Meson 会读取 `meson_options.txt` 或 `meson.build` 中定义的 C++ 编译选项。
6. **调用编译器类的方法生成编译和链接命令:**  Meson 会调用编译器类的方法（例如 `get_option_compile_args`, `get_option_link_args`）来生成实际的编译和链接命令。
7. **如果出现编译错误，用户可能会查看详细的构建日志:**  构建日志中会包含 Meson 生成的编译器命令，用户可以从中分析传递给编译器的参数，并可能回溯到 `cpp.py` 文件中生成这些参数的逻辑。
8. **在调试构建系统问题时，开发者可能会直接查看 `cpp.py` 的源代码:**  为了理解 Meson 如何处理 C++ 编译，开发者可能会查看这个文件，了解不同编译器类的实现细节和选项处理方式。

**总结一下它的功能:**

`frida/releng/meson/mesonbuild/compilers/cpp.py` 文件的核心功能是为 Frida 项目在 Meson 构建系统中处理 C++ 代码编译提供了一套抽象和实现。它通过定义各种编译器类来封装不同 C++ 编译器的特性，管理编译选项，并生成相应的编译器和链接器参数，使得 Frida 的构建过程能够跨平台和编译器。 这为 Frida 动态插桩工具的构建奠定了基础。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/compilers/cpp.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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