Response:
The user is asking for a summary of the functionality of the Python code provided. The code defines several classes related to C++ compilers within the Meson build system. I need to identify the core purpose of this file and the roles of the various classes.

Here's a breakdown of the thinking process:

1. **Identify the main goal:** The filename `cpp.py` within the `mesonbuild/compilers` directory strongly suggests that this file is responsible for defining and handling C++ compilers within the Meson build system.

2. **Analyze the imports:** The imports reveal the file's dependencies and provide clues about its functionality. It imports from:
    * `..coredata`: Likely for accessing and defining build system options.
    * `..mlog`:  Probably for logging messages during the build process.
    * `..mesonlib`:  General utility functions used by Meson.
    * `.compilers`:  Base classes for compilers within Meson.
    * `.c_function_attributes`:  Definitions related to function attributes.
    * `.mixins.*`:  These imports suggest a mixin pattern is used to add specific functionalities to the compiler classes. The mixins indicate features like:
        * Generic C-like compiler behavior (`CLikeCompiler`)
        * Specific compiler families (GNU, Clang, MSVC, Intel, etc.)
        * Target architectures (ARM)
        * Emscripten support
        * Handling of specific compiler features (RTTI, exception handling).

3. **Examine the `CPPCompiler` class:** This class seems to be the central class for representing a generic C++ compiler. Key functionalities include:
    * `attribute_check_func`:  Checking function attributes.
    * `sanity_check`:  Performing a basic compilation test.
    * `get_compiler_check_args`:  Getting arguments for compiler feature checks.
    * `has_header_symbol`:  Checking for the existence of a symbol in a header file.
    * `_test_cpp_std_arg` and `_find_best_cpp_std`:  Handling C++ standard versions.
    * `get_options`:  Defining configurable options for the compiler.

4. **Analyze the subclasses of `CPPCompiler`:**  The numerous subclasses (e.g., `ClangCPPCompiler`, `GnuCPPCompiler`, `MSVCCompiler`) indicate support for different C++ compiler implementations. Each subclass likely customizes the behavior of the base `CPPCompiler` to match the specific characteristics of that compiler.

5. **Identify the role of the mixins:** The mixins provide reusable blocks of functionality that are shared across multiple compiler classes. For example, `_StdCPPLibMixin` handles the detection of the C++ standard library.

6. **Consider the provided context:** The file path "frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/cpp.py" indicates this code is part of the Frida dynamic instrumentation tool. This means the compiler configurations defined here are used to build components of Frida.

7. **Formulate the summary:** Based on the above analysis, the core function of this file is to define the C++ compiler interface and provide implementations for various C++ compilers within the Meson build system, specifically tailored for the Frida project. It handles compiler options, standard versions, feature checks, and architecture-specific configurations through a combination of base classes and mixins.

8. **Review and refine:**  Ensure the summary is concise and accurately reflects the main purpose and key features of the code. Highlight the role of inheritance and mixins in organizing the compiler definitions.
这是 Frida 动态 instrumentation 工具中 Meson 构建系统关于 C++ 编译器的源代码文件。它的主要功能是**定义和管理各种 C++ 编译器的配置和行为**，以便 Meson 构建系统能够正确地使用这些编译器来编译 Frida 的 C++ 代码。

以下是该文件的功能归纳：

1. **定义 C++ 编译器的抽象基类 (`CPPCompiler`)**:  该基类提供了 C++ 编译器通用的接口和方法，例如：
    * **语言标识**:  将语言标识为 'cpp'。
    * **包含路径控制**: 提供获取 `-nostdinc++` 和 `-nostdlib++` 参数的方法。
    * **Sanity 检查**:  定义一个基本的编译测试来验证编译器是否可用。
    * **编译器检查参数**: 提供获取用于检查编译器特性的参数的方法（例如，添加 `-fpermissive` 以允许非严格的代码编译）。
    * **头文件符号检查**:  提供检查头文件中是否存在特定符号的方法，同时考虑 C 和 C++ 符号的差异。
    * **C++ 标准处理**:  提供测试编译器是否支持特定 C++ 标准版本以及找到最佳兼容标准的方法。
    * **通用编译选项**: 提供获取通用编译选项的方法（虽然这里主要是继承自 `CLikeCompiler`）。

2. **定义和实现各种具体的 C++ 编译器类**:  通过继承 `CPPCompiler` 和不同的 Mixin 类，该文件为多种 C++ 编译器提供了具体的实现，包括：
    * **Clang (`ClangCPPCompiler`, `AppleClangCPPCompiler`, `ArmLtdClangCPPCompiler`, `EmscriptenCPPCompiler`, `IntelLLVMCPPCompiler`)**:  针对 Clang 编译器的特定选项和行为进行配置，例如异常处理 (`-fno-exceptions`)、RTTI (`-fno-rtti`)、调试 STL (`-D_GLIBCXX_DEBUG`) 等。
    * **GNU GCC (`GnuCPPCompiler`)**: 针对 GCC 编译器的特定选项和行为进行配置，例如各种警告级别 (`-Wall`, `-Wextra`, `-Wpedantic`)。
    * **ARM Compiler (`ArmclangCPPCompiler`)**:  针对 ARM 编译器的配置。
    * **PGI Compiler (`PGICPPCompiler`, `NvidiaHPC_CPPCompiler`)**:  针对 PGI 编译器的配置。
    * **Elbrus Compiler (`ElbrusCPPCompiler`)**:  针对 Elbrus 编译器的配置，并处理其特定的限制（例如不支持 RTTI，缺少 `lchmod` 函数）。
    * **Intel Compiler (`IntelCPPCompiler`)**:  针对 Intel 编译器的配置，并处理其对 C++ 标准版本的特殊处理。
    * **Visual Studio (`MSVCCompiler`, `ClangClCompiler`, 通过 `VisualStudioLikeCPPCompilerMixin` 实现）**: 针对 MSVC 编译器的配置，包括异常处理选项 (`/EHsc`, `/EHs-c-`)、RTTI (`/GR-`) 以及链接 Windows 库。

3. **使用 Mixin 类来共享通用功能**:  Mixin 类 (例如 `CLikeCompiler`, `GnuCompiler`, `ClangCompiler`, `MSVCCompiler`, `_StdCPPLibMixin`) 用于将通用的编译器功能模块化，并让多个编译器类可以复用这些功能，减少代码重复。例如，`_StdCPPLibMixin` 用于检测应该使用 `libc++` 还是 `libstdc++` 标准库。

4. **处理编译器特定的选项和参数**:  每个具体的编译器类都定义了如何处理特定的编译器选项，例如：
    * **C++ 标准**:  通过 `-std=` 参数设置 C++ 标准版本。
    * **异常处理**:  通过不同的命令行参数控制异常处理的开启和类型。
    * **RTTI (运行时类型识别)**:  控制 RTTI 的启用或禁用。
    * **警告级别**:  设置不同的警告级别以提高代码质量。
    * **链接库**:  指定需要链接的库。
    * **断言**:  控制断言的启用和禁用。

5. **提供获取编译和链接参数的方法**:  每个编译器类都实现了 `get_option_compile_args` 和 `get_option_link_args` 方法，根据用户配置的选项返回相应的编译器和链接器参数。

**与逆向方法的关系：**

该文件本身不直接涉及逆向的具体操作，但它是 Frida 工具构建过程中的一部分。Frida 作为一个动态 instrumentation 工具，其核心功能是 **在运行时修改目标进程的行为**。为了实现这一点，Frida 需要编译和链接 C++ 代码，这些代码将被注入到目标进程中执行。

**举例说明：**

* **注入代码的编译**: 当你使用 Frida 编写 JavaScript 代码来 hook 目标进程的某个函数时，Frida 可能会需要编译一些 C++ 代码来实现更底层的操作或性能优化。这个 `cpp.py` 文件就定义了用于编译这些 C++ 代码的编译器配置。
* **定制化编译选项**: 逆向工程师可能需要使用特定的编译器选项来编译 Frida 的组件，例如，禁用某些优化以方便调试注入的代码，或者启用特定的安全特性。这个文件提供的选项配置机制使得用户可以通过 Meson 构建系统来定制这些编译选项。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层**:  C++ 编译器最终生成的是机器码，这是与二进制底层直接相关的。该文件通过配置编译器，影响着最终生成的二进制代码的特性，例如代码布局、指令选择等。
* **Linux**:  许多编译器类（如 `GnuCPPCompiler`，`ClangCPPCompiler`）在 Linux 系统上广泛使用。该文件需要处理 Linux 系统上编译器特有的选项和行为。例如，关于标准库的链接 (`-lstdc++` 或 `-lc++`) 在 Linux 上尤为重要。
* **Android 内核及框架**: Frida 常常被用于 Android 平台的逆向分析。该文件中的某些编译器类（尤其是 Clang 和 GCC 的变种）也常用于编译 Android 系统组件。了解 Android 平台的编译环境有助于理解该文件中的一些配置。
* **共享库**:  Frida 的很多功能是通过动态链接库 (shared libraries) 实现的。该文件中的链接器配置（通过 `get_option_link_args` 等方法）决定了如何将这些库链接到 Frida 的可执行文件中。

**逻辑推理的假设输入与输出：**

假设用户通过 Meson 的配置文件设置了以下选项：

* `cpp_std`: 'c++17'
* `cpp_eh`: 'none' (禁用异常处理)
* 正在使用 GCC 编译器。

**输入:**  上述用户配置信息，以及当前的目标平台信息。

**输出:**  `GnuCPPCompiler` 类的 `get_option_compile_args` 方法将会返回包含以下参数的列表：

```python
['-std=gnu++17', '-fno-exceptions']
```

**解释:**

* `'-std=gnu++17'`:  因为用户选择了 `c++17` 标准，而使用的是 GCC 编译器，所以会映射到 `gnu++17`。
* `'-fno-exceptions'`: 因为用户选择了禁用异常处理。

**涉及用户或编程常见的使用错误：**

* **指定了编译器不支持的 C++ 标准**: 用户可能会在 Meson 配置文件中指定一个当前使用的编译器版本不支持的 C++ 标准。例如，使用旧版本的 GCC 并尝试指定 `c++23`。该文件中的 `_test_cpp_std_arg` 和 `_find_best_cpp_std` 方法会尝试检测并回退到支持的标准，但如果完全不支持，则会抛出异常。
* **不匹配的异常处理选项**:  在混合编译 C++ 代码时，不同模块可能使用不同的异常处理设置。如果设置不当，可能会导致链接错误或运行时崩溃。该文件提供了控制异常处理选项的机制，但用户需要理解这些选项的含义以及如何正确配置。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户配置 Meson**: 用户在 Frida 项目的根目录下或者构建目录中，通过 `meson_options.txt` 文件或者命令行参数配置了 C++ 相关的选项，例如 `cpp_std`，`cpp_eh` 等。
2. **运行 Meson**: 用户执行 `meson build` 命令来配置构建系统。
3. **Meson 加载编译器信息**: Meson 在配置阶段会检测系统中可用的 C++ 编译器，并根据编译器的 ID（例如 'gcc', 'clang', 'msvc'）加载对应的编译器类，比如这里的 `cpp.py` 文件中的 `GnuCPPCompiler` 或 `ClangCPPCompiler`。
4. **Meson 读取用户配置**: Meson 会读取用户在 `meson_options.txt` 或命令行中设置的选项。
5. **调用编译器类的方法**:  当 Meson 需要获取编译或链接参数时，会调用相应的编译器类的方法，例如 `get_option_compile_args` 或 `get_option_link_args`，并将用户配置的选项作为参数传递进去。
6. **生成构建文件**: 编译器类的方法根据用户配置生成实际的编译器和链接器命令行参数，这些参数会被写入到 Ninja 或其他构建系统中使用的构建文件中。

**总结一下它的功能：**

该 Python 源代码文件是 Frida 项目中 Meson 构建系统关于 C++ 编译器的核心配置文件。它定义了各种 C++ 编译器的抽象接口和具体实现，负责处理编译器特定的选项和参数，并提供获取编译和链接参数的方法。它的主要目标是确保 Frida 的 C++ 代码能够使用正确的编译器和配置进行编译，为 Frida 的动态 instrumentation 功能提供基础支持。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/cpp.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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