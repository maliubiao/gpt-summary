Response:
The user wants a summary of the functionality of the Python code provided. I need to analyze the code and identify its main purpose and key features.

Here's a breakdown of my thought process to summarize the code:

1. **Identify the Core Class:** The central class is `CPPCompiler`. This immediately suggests the code is about handling C++ compilation.

2. **Inheritance Structure:**  Note the inheritance from `CLikeCompiler` and `Compiler`. This indicates the `CPPCompiler` class builds upon general compilation functionalities and those specific to C-like languages. The various mixin classes (like `GnuCompiler`, `ClangCompiler`, `MSVCCompiler`, etc.) signify that this code handles different C++ compiler implementations.

3. **Key Methods:** Examine the important methods within the `CPPCompiler` class and the mixins:
    * `__init__`: Initializes the compiler object, taking arguments like compiler path, version, target machine, and cross-compilation status.
    * `sanity_check`: Performs a basic compilation test to ensure the compiler works.
    * `get_compiler_check_args`: Returns compiler arguments used for checking compiler features.
    * `has_header_symbol`: Checks if a header file defines a specific symbol. The logic here handles both C-style and C++-style symbols.
    * `_test_cpp_std_arg` and `_find_best_cpp_std`:  Deal with handling different C++ standard versions and finding the best supported version.
    * `get_options`: Defines configurable options for the compiler (like C++ standard, exception handling, RTTI).
    * `get_option_compile_args`: Returns compiler arguments based on the selected options.
    * `get_option_link_args`: Returns linker arguments based on the selected options.
    * `get_assert_args`: Returns arguments related to enabling or disabling assertions.
    * Methods in mixins like `language_stdlib_only_link_flags`: Handle platform-specific or compiler-specific details (like detecting the C++ standard library).

4. **Compiler-Specific Logic:** The presence of classes like `ClangCPPCompiler`, `GnuCPPCompiler`, `MSVCCPPCompiler` (implicit in the mixins), and `IntelCPPCompiler` highlights that the code handles nuances and specific arguments for different C++ compiler families.

5. **Configuration and Options:** The code uses the `coredata` module and `OptionKey` to manage compiler options. This suggests a configuration system that allows users to customize compiler behavior.

6. **Error Handling:** The code includes checks and raises `MesonException` in cases of unsupported features or errors (e.g., unsupported standard, Emscripten not being used for cross-compilation).

7. **Logging:** The use of `mlog` suggests that the code provides some level of logging or debugging output.

8. **Relationship to Meson:** The file path `frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/cpp.py` strongly indicates that this code is part of the Meson build system and is responsible for handling C++ compilation within that context.

9. **High-Level Summary Construction:** Based on the above points, I can formulate a summary that captures the key functionalities:
    * It's a Meson module for handling C++ compilation.
    * It supports various C++ compilers (GCC, Clang, MSVC, etc.).
    * It manages compiler options like C++ standard, exception handling, and RTTI.
    * It performs basic checks to ensure the compiler is working correctly.
    * It handles compiler-specific arguments and behaviors.
    * It helps in detecting the C++ standard library.

10. **Refinement:** Review the summary to ensure it's clear, concise, and covers the most important aspects of the code. Avoid overly technical jargon where possible.

By following these steps, I can effectively analyze the code and generate a meaningful summary of its functions.
```python
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
### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/cpp.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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