Response:
The user wants a summary of the functionalities of the provided Python code. I need to go through the code and identify the key features and their purpose. The code defines classes related to static and dynamic linkers used in the Frida build system, which leverages Meson.

Here's a breakdown of the thinking process to summarize the code's functionalities:

1. **Identify the Core Purpose:** The file `linkers.py` within the Frida/Meson context deals with defining how linking is performed for both static and dynamic libraries/executables. This involves interacting with the actual linker tools.

2. **Recognize Key Abstractions:** The code uses abstract base classes (`StaticLinker`, `DynamicLinker`) and mixins (`PosixDynamicLinkerMixin`, `GnuLikeDynamicLinkerMixin`). This suggests the code is designed to be extensible and handle different linker implementations.

3. **Analyze `StaticLinker` Class:**
    * It provides a base interface for static linkers.
    * Methods like `get_exelist`, `get_output_args`, `get_std_link_args` suggest handling basic linker commands and options.
    * `can_linker_accept_rsp` and `rsp_file_syntax` indicate support for response files, especially on Windows.
    * Methods like `get_coverage_link_args`, `get_optimization_link_args`, and `thread_link_flags` show support for various linking options.

4. **Analyze `DynamicLinker` Class:**
    * It provides a base interface for dynamic linkers, inheriting from `abc.ABCMeta`.
    * Abstract properties like `id` indicate that each specific dynamic linker will have a unique identifier.
    * Methods like `get_output_args`, `get_std_shared_lib_args`, `get_search_args` are crucial for dynamic linking.
    * Methods related to optimization (`get_optimization_link_args`), debug information (`get_debugfile_name`, `get_debugfile_args`), and linking behavior (`get_asneeded_args`, `get_link_whole_for`) point to advanced linker features.
    * The `build_rpath_args` method is essential for setting up runtime library paths.

5. **Analyze Mixin Classes:**
    * `PosixDynamicLinkerMixin`: Provides common functionality for POSIX-like linkers (like basic output and search path arguments).
    * `GnuLikeDynamicLinkerMixin`: Offers features common to GNU-like linkers (like PIE, as-needed linking, LTO, sanitizers, RPATH handling).

6. **Analyze Concrete Linker Implementations:** The code then defines specific linker implementations by inheriting from the base classes and mixins. Examples include:
    * `VisualStudioLinker`, `IntelVisualStudioLinker`: For Microsoft Visual Studio.
    * `ArLinker`, `AppleArLinker`, `ArmarLinker`: For `ar` (archiver) utilities.
    * `DLinker`, `CcrxLinker`, `Xc16Linker`, etc.: For other specific toolchains.
    * `AppleDynamicLinker`, `LLVMLD64DynamicLinker`: For Apple's linkers.
    * `GnuDynamicLinker`, `GnuGoldDynamicLinker`, `GnuBFDDynamicLinker`, `MoldDynamicLinker`: For GNU linkers.
    * `LLVMDynamicLinker`: For LLVM's `lld`.
    * `WASMDynamicLinker`: For WebAssembly linking.
    * `CcrxDynamicLinker`: For Renesas CCrx.

7. **Identify Utility Functions:** The `prepare_rpaths`, `order_rpaths`, and `evaluate_rpath` functions are utility methods specifically for handling RPATHs (runtime library paths).

8. **Summarize Functionalities based on the Analysis:**  Now, based on the identified classes and methods, I can create a concise summary of the file's functionalities. This involves grouping related features together.

9. **Focus on the "Part 1" Request:**  The prompt specifies "This is the first part..." so the summary should focus on the general architecture and the base classes and their immediate functions, setting the stage for more specific linker implementations in the subsequent part (presumably).

By following these steps, I can generate an accurate and comprehensive summary of the code's functionalities as requested by the user.
这是 `frida/releng/meson/mesonbuild/linkers/linkers.py` 文件的第一部分，它定义了 Frida 构建系统中用于处理静态和动态链接器的抽象基类和一些具体实现。 它的主要功能是提供一个统一的接口，用于与各种不同的链接器进行交互，而无需关心它们的具体命令行语法和行为差异。

以下是该文件的功能归纳：

**核心功能：定义静态和动态链接器的抽象接口和基类**

1. **`StaticLinker` 类:**
    *   定义了静态链接器的通用接口。
    *   包含了获取可执行文件路径 (`get_exelist`)、构建基本链接参数 (`get_base_link_args`)、获取标准链接参数 (`get_std_link_args`)、优化链接参数 (`get_optimization_link_args`)、输出参数 (`get_output_args`)、覆盖率链接参数 (`get_coverage_link_args`)、rpath 参数 (`build_rpath_args`)、线程链接标志 (`thread_link_flags`)、OpenMP 标志 (`openmp_flags`)、选项链接参数 (`get_option_link_args`)、调试文件名称和参数 (`get_link_debugfile_name`, `get_link_debugfile_args`)、以及始终传递的参数 (`get_always_args`, `get_linker_always_args`) 等方法。
    *   还包含了处理响应文件 (`can_linker_accept_rsp`, `rsp_file_syntax`) 和转换命令行参数 (`unix_args_to_native`, `native_args_to_unix`) 的方法。

2. **`DynamicLinker` 类 (抽象基类):**
    *   定义了动态链接器的通用接口。
    *   包含了获取 ID (`id`)、获取可执行文件路径 (`get_exelist`)、获取版本字符串 (`get_version_string`)、处理响应文件 (`get_accepts_rsp`, `rsp_file_syntax`)、获取始终传递的参数 (`get_always_args`)、库前缀 (`get_lib_prefix`)、选项参数 (`get_option_args`)、是否支持多参数 (`has_multi_arguments`)、调试文件名称和参数 (`get_debugfile_name`, `get_debugfile_args`)、优化链接参数 (`get_optimization_link_args`)、标准共享库和模块参数 (`get_std_shared_lib_args`, `get_std_shared_module_args`)、PIE 参数 (`get_pie_args`)、LTO 参数 (`get_lto_args`)、ThinLTO 缓存参数 (`get_thinlto_cache_args`)、Sanitizer 参数 (`sanitizer_args`)、按需链接参数 (`get_asneeded_args`)、链接整个库的参数 (`get_link_whole_for`)、允许未定义符号的参数 (`get_allow_undefined_args`)、输出参数 (`get_output_args`)、覆盖率参数 (`get_coverage_args`)、搜索路径参数 (`get_search_args`)、导出动态符号参数 (`export_dynamic_args`)、导入库参数 (`import_library_args`)、线程标志 (`thread_flags`)、禁止未定义符号的参数 (`no_undefined_args`)、将警告视为错误的参数 (`fatal_warnings`)、header padding 参数 (`headerpad_args`)、Windows 子系统参数 (`get_win_subsystem_args`)、Bitcode 参数 (`bitcode_args`)、rpath 参数 (`build_rpath_args`)、soname 参数 (`get_soname_args`)、归档库的名称 (`get_archive_name`) 以及归档共享库的命令 (`get_command_to_archive_shlib`) 等抽象方法或具有默认实现的方法。

**具体链接器实现 (部分):**

*   **`VisualStudioLikeLinker`:**  一个为 Visual Studio 风格的链接器提供基础功能的类。
*   **`VisualStudioLinker`:**  代表 Microsoft 的 `lib` 静态链接器。
*   **`IntelVisualStudioLinker`:** 代表 Intel 的 `xilib` 静态链接器。
*   **`ArLinker`:** 代表 `ar` 归档工具。
*   **`AppleArLinker`:**  代表 Apple 平台的 `ar` 归档工具。
*   **`ArmarLinker`:** 代表 ARM 平台的 `ar` 归档工具。
*   **`DLinker`:**  代表 D 语言的链接器。
*   **`CcrxLinker`:** 代表 Renesas CC-RX 编译器的链接器。
*   **`Xc16Linker`:** 代表 Microchip XC16 编译器的链接器。
*   **`CompCertLinker`:** 代表 CompCert 编译器的链接器。
*   **`TILinker`:** 代表 Texas Instruments 编译器的链接器。
*   **`C2000Linker`, `C6000Linker`:**  `TILinker` 的特定变体。
*   **`AIXArLinker`:** 代表 AIX 平台的 `ar` 归档工具。
*   **`MetrowerksStaticLinker`, `MetrowerksStaticLinkerARM`, `MetrowerksStaticLinkerEmbeddedPowerPC`:** 代表 Metrowerks 编译器的静态链接器。

**实用函数:**

*   **`prepare_rpaths`:**  处理和转换 rpath 路径，使其相对于构建目录，以提高构建的可重现性。
*   **`order_rpaths`:**  对 rpath 路径进行排序，以便构建目录内的路径优先。
*   **`evaluate_rpath`:**  计算单个 rpath 的最终值。

**总结来说，该文件的核心目标是为 Frida 的构建系统提供一个灵活且可扩展的链接器管理框架。它通过定义抽象接口和提供具体实现来支持多种不同的链接器，并处理它们之间的差异，从而简化了构建过程。**

由于这是第一部分，它主要集中在定义基础结构和一些静态链接器的实现。可以推测第二部分会包含更多动态链接器的具体实现。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/linkers/linkers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright 2012-2022 The Meson development team

from __future__ import annotations

import abc
import os
import typing as T
import re

from .base import ArLikeLinker, RSPFileSyntax
from .. import mesonlib
from ..mesonlib import EnvironmentException, MesonException
from ..arglist import CompilerArgs

if T.TYPE_CHECKING:
    from ..coredata import KeyedOptionDictType
    from ..environment import Environment
    from ..mesonlib import MachineChoice


class StaticLinker:

    id: str

    def __init__(self, exelist: T.List[str]):
        self.exelist = exelist

    def compiler_args(self, args: T.Optional[T.Iterable[str]] = None) -> CompilerArgs:
        return CompilerArgs(self, args)

    def can_linker_accept_rsp(self) -> bool:
        """
        Determines whether the linker can accept arguments using the @rsp syntax.
        """
        return mesonlib.is_windows()

    def get_base_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        """Like compilers.get_base_link_args, but for the static linker."""
        return []

    def get_exelist(self) -> T.List[str]:
        return self.exelist.copy()

    def get_std_link_args(self, env: 'Environment', is_thin: bool) -> T.List[str]:
        return []

    def get_optimization_link_args(self, optimization_level: str) -> T.List[str]:
        return []

    def get_output_args(self, target: str) -> T.List[str]:
        return []

    def get_coverage_link_args(self) -> T.List[str]:
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

    def thread_link_flags(self, env: 'Environment') -> T.List[str]:
        return []

    def openmp_flags(self) -> T.List[str]:
        return []

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []

    @classmethod
    def unix_args_to_native(cls, args: T.List[str]) -> T.List[str]:
        return args[:]

    @classmethod
    def native_args_to_unix(cls, args: T.List[str]) -> T.List[str]:
        return args[:]

    def get_link_debugfile_name(self, targetfile: str) -> T.Optional[str]:
        return None

    def get_link_debugfile_args(self, targetfile: str) -> T.List[str]:
        # Static libraries do not have PDB files
        return []

    def get_always_args(self) -> T.List[str]:
        return []

    def get_linker_always_args(self) -> T.List[str]:
        return []

    def rsp_file_syntax(self) -> RSPFileSyntax:
        """The format of the RSP file that this compiler supports.

        If `self.can_linker_accept_rsp()` returns True, then this needs to
        be implemented
        """
        assert not self.can_linker_accept_rsp(), f'{self.id} linker accepts RSP, but doesn\' provide a supported format, this is a bug'
        raise EnvironmentException(f'{self.id} does not implement rsp format, this shouldn\'t be called')


class DynamicLinker(metaclass=abc.ABCMeta):

    """Base class for dynamic linkers."""

    _OPTIMIZATION_ARGS: T.Dict[str, T.List[str]] = {
        'plain': [],
        '0': [],
        'g': [],
        '1': [],
        '2': [],
        '3': [],
        's': [],
    }

    @abc.abstractproperty
    def id(self) -> str:
        pass

    def _apply_prefix(self, arg: T.Union[str, T.List[str]]) -> T.List[str]:
        args = [arg] if isinstance(arg, str) else arg
        if self.prefix_arg is None:
            return args
        elif isinstance(self.prefix_arg, str):
            return [self.prefix_arg + arg for arg in args]
        ret: T.List[str] = []
        for arg in args:
            ret += self.prefix_arg + [arg]
        return ret

    def __init__(self, exelist: T.List[str],
                 for_machine: mesonlib.MachineChoice, prefix_arg: T.Union[str, T.List[str]],
                 always_args: T.List[str], *, version: str = 'unknown version'):
        self.exelist = exelist
        self.for_machine = for_machine
        self.version = version
        self.prefix_arg = prefix_arg
        self.always_args = always_args
        self.machine: T.Optional[str] = None

    def __repr__(self) -> str:
        return '<{}: v{} `{}`>'.format(type(self).__name__, self.version, ' '.join(self.exelist))

    def get_id(self) -> str:
        return self.id

    def get_version_string(self) -> str:
        return f'({self.id} {self.version})'

    def get_exelist(self) -> T.List[str]:
        return self.exelist.copy()

    def get_accepts_rsp(self) -> bool:
        # rsp files are only used when building on Windows because we want to
        # avoid issues with quoting and max argument length
        return mesonlib.is_windows()

    def rsp_file_syntax(self) -> RSPFileSyntax:
        """The format of the RSP file that this compiler supports.

        If `self.can_linker_accept_rsp()` returns True, then this needs to
        be implemented
        """
        return RSPFileSyntax.GCC

    def get_always_args(self) -> T.List[str]:
        return self.always_args.copy()

    def get_lib_prefix(self) -> str:
        return ''

    # XXX: is use_ldflags a compiler or a linker attribute?

    def get_option_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        raise EnvironmentException(f'Language {self.id} does not support has_multi_link_arguments.')

    def get_debugfile_name(self, targetfile: str) -> T.Optional[str]:
        '''Name of debug file written out (see below)'''
        return None

    def get_debugfile_args(self, targetfile: str) -> T.List[str]:
        """Some compilers (MSVC) write debug into a separate file.

        This method takes the target object path and returns a list of
        commands to append to the linker invocation to control where that
        file is written.
        """
        return []

    def get_optimization_link_args(self, optimization_level: str) -> T.List[str]:
        # We can override these in children by just overriding the
        # _OPTIMIZATION_ARGS value.
        return mesonlib.listify([self._apply_prefix(a) for a in self._OPTIMIZATION_ARGS[optimization_level]])

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_std_shared_module_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return self.get_std_shared_lib_args()

    def get_pie_args(self) -> T.List[str]:
        # TODO: this really needs to take a boolean and return the args to
        # disable pie, otherwise it only acts to enable pie if pie *isn't* the
        # default.
        raise EnvironmentException(f'Linker {self.id} does not support position-independent executable')

    def get_lto_args(self) -> T.List[str]:
        return []

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return []

    def sanitizer_args(self, value: str) -> T.List[str]:
        return []

    def get_asneeded_args(self) -> T.List[str]:
        return []

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        raise EnvironmentException(
            f'Linker {self.id} does not support link_whole')

    def get_allow_undefined_args(self) -> T.List[str]:
        raise EnvironmentException(
            f'Linker {self.id} does not support allow undefined')

    @abc.abstractmethod
    def get_output_args(self, outputname: str) -> T.List[str]:
        pass

    def get_coverage_args(self) -> T.List[str]:
        raise EnvironmentException(f"Linker {self.id} doesn't implement coverage data generation.")

    @abc.abstractmethod
    def get_search_args(self, dirname: str) -> T.List[str]:
        pass

    def export_dynamic_args(self, env: 'Environment') -> T.List[str]:
        return []

    def import_library_args(self, implibname: str) -> T.List[str]:
        """The name of the outputted import library.

        This implementation is used only on Windows by compilers that use GNU ld
        """
        return []

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        return []

    def no_undefined_args(self) -> T.List[str]:
        """Arguments to error if there are any undefined symbols at link time.

        This is the inverse of get_allow_undefined_args().

        TODO: A future cleanup might merge this and
              get_allow_undefined_args() into a single method taking a
              boolean
        """
        return []

    def fatal_warnings(self) -> T.List[str]:
        """Arguments to make all warnings errors."""
        return []

    def headerpad_args(self) -> T.List[str]:
        # Only used by the Apple linker
        return []

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        # Only used if supported by the dynamic linker and
        # only when targeting Windows
        return []

    def bitcode_args(self) -> T.List[str]:
        raise MesonException('This linker does not support bitcode bundles')

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def get_archive_name(self, filename: str) -> str:
        #Only used by AIX.
        return str()

    def get_command_to_archive_shlib(self) -> T.List[str]:
        #Only used by AIX.
        return []


if T.TYPE_CHECKING:
    StaticLinkerBase = StaticLinker
    DynamicLinkerBase = DynamicLinker
else:
    StaticLinkerBase = DynamicLinkerBase = object


class VisualStudioLikeLinker(StaticLinkerBase):
    always_args = ['/NOLOGO']

    def __init__(self, machine: str):
        self.machine = machine

    def get_always_args(self) -> T.List[str]:
        return self.always_args.copy()

    def get_linker_always_args(self) -> T.List[str]:
        return self.always_args.copy()

    def get_output_args(self, target: str) -> T.List[str]:
        args: T.List[str] = []
        if self.machine:
            args += ['/MACHINE:' + self.machine]
        args += ['/OUT:' + target]
        return args

    @classmethod
    def unix_args_to_native(cls, args: T.List[str]) -> T.List[str]:
        from ..compilers.c import VisualStudioCCompiler
        return VisualStudioCCompiler.unix_args_to_native(args)

    @classmethod
    def native_args_to_unix(cls, args: T.List[str]) -> T.List[str]:
        from ..compilers.c import VisualStudioCCompiler
        return VisualStudioCCompiler.native_args_to_unix(args)

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.MSVC


class VisualStudioLinker(VisualStudioLikeLinker, StaticLinker):

    """Microsoft's lib static linker."""

    id = 'lib'

    def __init__(self, exelist: T.List[str], machine: str):
        StaticLinker.__init__(self, exelist)
        VisualStudioLikeLinker.__init__(self, machine)


class IntelVisualStudioLinker(VisualStudioLikeLinker, StaticLinker):

    """Intel's xilib static linker."""

    id = 'xilib'

    def __init__(self, exelist: T.List[str], machine: str):
        StaticLinker.__init__(self, exelist)
        VisualStudioLikeLinker.__init__(self, machine)


class ArLinker(ArLikeLinker, StaticLinker):
    id = 'ar'

    def __init__(self, for_machine: mesonlib.MachineChoice, exelist: T.List[str]):
        super().__init__(exelist)
        stdo = mesonlib.Popen_safe(self.exelist + ['-h'])[1]
        # Enable deterministic builds if they are available.
        stdargs = 'csr'
        thinargs = ''
        if '[D]' in stdo:
            stdargs += 'D'
        if '[T]' in stdo:
            thinargs = 'T'
        self.std_args = [stdargs]
        self.std_thin_args = [stdargs + thinargs]
        self.can_rsp = '@<' in stdo
        self.for_machine = for_machine

    def can_linker_accept_rsp(self) -> bool:
        return self.can_rsp

    def get_std_link_args(self, env: 'Environment', is_thin: bool) -> T.List[str]:
        # Thin archives are a GNU extension not supported by the system linkers
        # on Mac OS X, Solaris, or illumos, so don't build them on those OSes.
        # OS X ld rejects with: "file built for unknown-unsupported file format"
        # illumos/Solaris ld rejects with: "unknown file type"
        if is_thin and not env.machines[self.for_machine].is_darwin() \
          and not env.machines[self.for_machine].is_sunos():
            return self.std_thin_args
        else:
            return self.std_args


class AppleArLinker(ArLinker):

    # mostly this is used to determine that we need to call ranlib

    id = 'applear'


class ArmarLinker(ArLikeLinker, StaticLinker):
    id = 'armar'


class DLinker(StaticLinker):
    def __init__(self, exelist: T.List[str], arch: str, *, rsp_syntax: RSPFileSyntax = RSPFileSyntax.GCC):
        super().__init__(exelist)
        self.id = exelist[0]
        self.arch = arch
        self.__rsp_syntax = rsp_syntax

    def get_std_link_args(self, env: 'Environment', is_thin: bool) -> T.List[str]:
        return ['-lib']

    def get_output_args(self, target: str) -> T.List[str]:
        return ['-of=' + target]

    def get_linker_always_args(self) -> T.List[str]:
        if mesonlib.is_windows():
            if self.arch == 'x86_64':
                return ['-m64']
            elif self.arch == 'x86_mscoff' and self.id == 'dmd':
                return ['-m32mscoff']
            return ['-m32']
        return []

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return self.__rsp_syntax


class CcrxLinker(StaticLinker):

    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'rlink'

    def can_linker_accept_rsp(self) -> bool:
        return False

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'-output={target}']

    def get_linker_always_args(self) -> T.List[str]:
        return ['-nologo', '-form=library']


class Xc16Linker(StaticLinker):

    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'xc16-ar'

    def can_linker_accept_rsp(self) -> bool:
        return False

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'{target}']

    def get_linker_always_args(self) -> T.List[str]:
        return ['rcs']

class CompCertLinker(StaticLinker):

    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'ccomp'

    def can_linker_accept_rsp(self) -> bool:
        return False

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'-o{target}']


class TILinker(StaticLinker):

    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'ti-ar'

    def can_linker_accept_rsp(self) -> bool:
        return False

    def get_output_args(self, target: str) -> T.List[str]:
        return [f'{target}']

    def get_linker_always_args(self) -> T.List[str]:
        return ['-r']


class C2000Linker(TILinker):
    # Required for backwards compat with projects created before ti-cgt support existed
    id = 'ar2000'

class C6000Linker(TILinker):
    id = 'ar6000'


class AIXArLinker(ArLikeLinker, StaticLinker):
    id = 'aixar'
    std_args = ['-csr', '-Xany']


class MetrowerksStaticLinker(StaticLinker):

    def can_linker_accept_rsp(self) -> bool:
        return True

    def get_linker_always_args(self) -> T.List[str]:
        return ['-library']

    def get_output_args(self, target: str) -> T.List[str]:
        return ['-o', target]

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.GCC


class MetrowerksStaticLinkerARM(MetrowerksStaticLinker):
    id = 'mwldarm'


class MetrowerksStaticLinkerEmbeddedPowerPC(MetrowerksStaticLinker):
    id = 'mwldeppc'

def prepare_rpaths(raw_rpaths: T.Tuple[str, ...], build_dir: str, from_dir: str) -> T.List[str]:
    # The rpaths we write must be relative if they point to the build dir,
    # because otherwise they have different length depending on the build
    # directory. This breaks reproducible builds.
    internal_format_rpaths = [evaluate_rpath(p, build_dir, from_dir) for p in raw_rpaths]
    ordered_rpaths = order_rpaths(internal_format_rpaths)
    return ordered_rpaths


def order_rpaths(rpath_list: T.List[str]) -> T.List[str]:
    # We want rpaths that point inside our build dir to always override
    # those pointing to other places in the file system. This is so built
    # binaries prefer our libraries to the ones that may lie somewhere
    # in the file system, such as /lib/x86_64-linux-gnu.
    #
    # The correct thing to do here would be C++'s std::stable_partition.
    # Python standard library does not have it, so replicate it with
    # sort, which is guaranteed to be stable.
    return sorted(rpath_list, key=os.path.isabs)


def evaluate_rpath(p: str, build_dir: str, from_dir: str) -> str:
    if p == from_dir:
        return '' # relpath errors out in this case
    elif os.path.isabs(p):
        return p # These can be outside of build dir.
    else:
        return os.path.relpath(os.path.join(build_dir, p), os.path.join(build_dir, from_dir))


class PosixDynamicLinkerMixin(DynamicLinkerBase):

    """Mixin class for POSIX-ish linkers.

    This is obviously a pretty small subset of the linker interface, but
    enough dynamic linkers that meson supports are POSIX-like but not
    GNU-like that it makes sense to split this out.
    """

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_std_shared_lib_args(self) -> T.List[str]:
        return ['-shared']

    def get_search_args(self, dirname: str) -> T.List[str]:
        return ['-L' + dirname]


class GnuLikeDynamicLinkerMixin(DynamicLinkerBase):

    """Mixin class for dynamic linkers that provides gnu-like interface.

    This acts as a base for the GNU linkers (bfd and gold), LLVM's lld, and
    other linkers like GNU-ld.
    """

    if T.TYPE_CHECKING:
        for_machine = MachineChoice.HOST
        def _apply_prefix(self, arg: T.Union[str, T.List[str]]) -> T.List[str]: ...

    _OPTIMIZATION_ARGS: T.Dict[str, T.List[str]] = {
        'plain': [],
        '0': [],
        'g': [],
        '1': [],
        '2': [],
        '3': ['-O1'],
        's': [],
    }

    _SUBSYSTEMS: T.Dict[str, str] = {
        "native": "1",
        "windows": "windows",
        "console": "console",
        "posix": "7",
        "efi_application": "10",
        "efi_boot_service_driver": "11",
        "efi_runtime_driver": "12",
        "efi_rom": "13",
        "boot_application": "16",
    }

    def get_pie_args(self) -> T.List[str]:
        return ['-pie']

    def get_asneeded_args(self) -> T.List[str]:
        return self._apply_prefix('--as-needed')

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if not args:
            return args
        return self._apply_prefix('--whole-archive') + args + self._apply_prefix('--no-whole-archive')

    def get_allow_undefined_args(self) -> T.List[str]:
        return self._apply_prefix('--allow-shlib-undefined')

    def get_lto_args(self) -> T.List[str]:
        return ['-flto']

    def sanitizer_args(self, value: str) -> T.List[str]:
        if value == 'none':
            return []
        return ['-fsanitize=' + value]

    def get_coverage_args(self) -> T.List[str]:
        return ['--coverage']

    def export_dynamic_args(self, env: 'Environment') -> T.List[str]:
        m = env.machines[self.for_machine]
        if m.is_windows() or m.is_cygwin():
            return self._apply_prefix('--export-all-symbols')
        return self._apply_prefix('-export-dynamic')

    def import_library_args(self, implibname: str) -> T.List[str]:
        return self._apply_prefix('--out-implib=' + implibname)

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        if env.machines[self.for_machine].is_haiku():
            return []
        return ['-pthread']

    def no_undefined_args(self) -> T.List[str]:
        return self._apply_prefix('--no-undefined')

    def fatal_warnings(self) -> T.List[str]:
        return self._apply_prefix('--fatal-warnings')

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        m = env.machines[self.for_machine]
        if m.is_windows() or m.is_cygwin():
            # For PE/COFF the soname argument has no effect
            return []
        sostr = '' if soversion is None else '.' + soversion
        return self._apply_prefix(f'-soname,{prefix}{shlib_name}.{suffix}{sostr}')

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        m = env.machines[self.for_machine]
        if m.is_windows() or m.is_cygwin():
            return ([], set())
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        args: T.List[str] = []
        origin_placeholder = '$ORIGIN'
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        # Need to deduplicate rpaths, as macOS's install_name_tool
        # is *very* allergic to duplicate -delete_rpath arguments
        # when calling depfixer on installation.
        all_paths = mesonlib.OrderedSet([os.path.join(origin_placeholder, p) for p in processed_rpaths])
        rpath_dirs_to_remove: T.Set[bytes] = set()
        for p in all_paths:
            rpath_dirs_to_remove.add(p.encode('utf8'))
        # Build_rpath is used as-is (it is usually absolute).
        if build_rpath != '':
            all_paths.add(build_rpath)
            for p in build_rpath.split(':'):
                rpath_dirs_to_remove.add(p.encode('utf8'))

        # TODO: should this actually be "for (dragonfly|open)bsd"?
        if mesonlib.is_dragonflybsd() or mesonlib.is_openbsd():
            # This argument instructs the compiler to record the value of
            # ORIGIN in the .dynamic section of the elf. On Linux this is done
            # by default, but is not on dragonfly/openbsd for some reason. Without this
            # $ORIGIN in the runtime path will be undefined and any binaries
            # linked against local libraries will fail to resolve them.
            args.extend(self._apply_prefix('-z,origin'))

        # In order to avoid relinking for RPATH removal, the binary needs to contain just
        # enough space in the ELF header to hold the final installation RPATH.
        paths = ':'.join(all_paths)
        if len(paths) < len(install_rpath):
            padding = 'X' * (len(install_rpath) - len(paths))
            if not paths:
                paths = padding
            else:
                paths = paths + ':' + padding
        args.extend(self._apply_prefix('-rpath,' + paths))

        # TODO: should this actually be "for solaris/sunos"?
        if mesonlib.is_sunos():
            return (args, rpath_dirs_to_remove)

        # Rpaths to use while linking must be absolute. These are not
        # written to the binary. Needed only with GNU ld:
        # https://sourceware.org/bugzilla/show_bug.cgi?id=16936
        # Not needed on Windows or other platforms that don't use RPATH
        # https://github.com/mesonbuild/meson/issues/1897
        #
        # In addition, this linker option tends to be quite long and some
        # compilers have trouble dealing with it. That's why we will include
        # one option per folder, like this:
        #
        #   -Wl,-rpath-link,/path/to/folder1 -Wl,-rpath,/path/to/folder2 ...
        #
        # ...instead of just one single looooong option, like this:
        #
        #   -Wl,-rpath-link,/path/to/folder1:/path/to/folder2:...
        for p in rpath_paths:
            args.extend(self._apply_prefix('-rpath-link,' + os.path.join(build_dir, p)))

        return (args, rpath_dirs_to_remove)

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        # MinGW only directly supports a couple of the possible
        # PE application types. The raw integer works as an argument
        # as well, and is always accepted, so we manually map the
        # other types here. List of all types:
        # https://github.com/wine-mirror/wine/blob/3ded60bd1654dc689d24a23305f4a93acce3a6f2/include/winnt.h#L2492-L2507
        versionsuffix = None
        if ',' in value:
            value, versionsuffix = value.split(',', 1)
        newvalue = self._SUBSYSTEMS.get(value)
        if newvalue is not None:
            if versionsuffix is not None:
                newvalue += f':{versionsuffix}'
            args = [f'--subsystem,{newvalue}']
        else:
            raise mesonlib.MesonBugException(f'win_subsystem: {value!r} not handled in MinGW linker. This should not be possible.')

        return self._apply_prefix(args)


class AppleDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Apple's ld implementation."""

    id = 'ld64'

    def get_asneeded_args(self) -> T.List[str]:
        return self._apply_prefix('-dead_strip_dylibs')

    def get_allow_undefined_args(self) -> T.List[str]:
        return self._apply_prefix('-undefined,dynamic_lookup')

    def get_std_shared_module_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return ['-bundle'] + self._apply_prefix('-undefined,dynamic_lookup')

    def get_pie_args(self) -> T.List[str]:
        return []

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        result: T.List[str] = []
        for a in args:
            result.extend(self._apply_prefix('-force_load'))
            result.append(a)
        return result

    def get_coverage_args(self) -> T.List[str]:
        return ['--coverage']

    def sanitizer_args(self, value: str) -> T.List[str]:
        if value == 'none':
            return []
        return ['-fsanitize=' + value]

    def no_undefined_args(self) -> T.List[str]:
        # We used to emit -undefined,error, but starting with Xcode 15 /
        # Sonoma, doing so triggers "ld: warning: -undefined error is
        # deprecated". Given that "-undefined error" is documented to be the
        # linker's default behaviour, this warning seems ill advised. However,
        # it does create a lot of noise.  As "-undefined error" is the default
        # behaviour, the least bad way to deal with this seems to be to just
        # not emit anything here. Of course that only works as long as nothing
        # else injects -undefined dynamic_lookup, or such. Complain to Apple.
        return []

    def headerpad_args(self) -> T.List[str]:
        return self._apply_prefix('-headerpad_max_install_names')

    def bitcode_args(self) -> T.List[str]:
        return self._apply_prefix('-bitcode_bundle')

    def fatal_warnings(self) -> T.List[str]:
        return self._apply_prefix('-fatal_warnings')

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        install_name = ['@rpath/', prefix, shlib_name]
        if soversion is not None:
            install_name.append('.' + soversion)
        install_name.append('.dylib')
        args = ['-install_name', ''.join(install_name)]
        if darwin_versions:
            args.extend(['-compatibility_version', darwin_versions[0],
                         '-current_version', darwin_versions[1]])
        return args

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        args: T.List[str] = []
        # @loader_path is the equivalent of $ORIGIN on macOS
        # https://stackoverflow.com/q/26280738
        origin_placeholder = '@loader_path'
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        all_paths = mesonlib.OrderedSet([os.path.join(origin_placeholder, p) for p in processed_rpaths])
        if build_rpath != '':
            all_paths.add(build_rpath)
        for rp in all_paths:
            args.extend(self._apply_prefix('-rpath,' + rp))

        return (args, set())

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ["-Wl,-cache_path_lto," + path]


class LLVMLD64DynamicLinker(AppleDynamicLinker):

    id = 'ld64.lld'


class GnuDynamicLinker(GnuLikeDynamicLinkerMixin, PosixDynamicLinkerMixin, DynamicLinker):

    """Representation of GNU ld.bfd and ld.gold."""

    def get_accepts_rsp(self) -> bool:
        return True


class GnuGoldDynamicLinker(GnuDynamicLinker):

    id = 'ld.gold'

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ['-Wl,-plugin-opt,cache-dir=' + path]


class GnuBFDDynamicLinker(GnuDynamicLinker):

    id = 'ld.bfd'


class MoldDynamicLinker(GnuDynamicLinker):

    id = 'ld.mold'

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ['-Wl,--thinlto-cache-dir=' + path]


class LLVMDynamicLinker(GnuLikeDynamicLinkerMixin, PosixDynamicLinkerMixin, DynamicLinker):

    """Representation of LLVM's ld.lld linker.

    This is only the gnu-like linker, not the apple like or link.exe like
    linkers.
    """

    id = 'ld.lld'

    def __init__(self, exelist: T.List[str],
                 for_machine: mesonlib.MachineChoice, prefix_arg: T.Union[str, T.List[str]],
                 always_args: T.List[str], *, version: str = 'unknown version'):
        super().__init__(exelist, for_machine, prefix_arg, always_args, version=version)

        # Some targets don't seem to support this argument (windows, wasm, ...)
        _, _, e = mesonlib.Popen_safe(self.exelist + always_args + self._apply_prefix('--allow-shlib-undefined'))
        # Versions < 9 do not have a quoted argument
        self.has_allow_shlib_undefined = ('unknown argument: --allow-shlib-undefined' not in e) and ("unknown argument: '--allow-shlib-undefined'" not in e)

    def get_allow_undefined_args(self) -> T.List[str]:
        if self.has_allow_shlib_undefined:
            return self._apply_prefix('--allow-shlib-undefined')
        return []

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ['-Wl,--thinlto-cache-dir=' + path]

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        # lld does not support a numeric subsystem value
        version = None
        if ',' in value:
            value, version = value.split(',', 1)
        if value in self._SUBSYSTEMS:
            if version is not None:
                value += f':{version}'
            return self._apply_prefix([f'--subsystem,{value}'])
        else:
            raise mesonlib.MesonBugException(f'win_subsystem: {value} not handled in lld linker. This should not be possible.')


class WASMDynamicLinker(GnuLikeDynamicLinkerMixin, PosixDynamicLinkerMixin, DynamicLinker):

    """Emscripten's wasm-ld."""

    id = 'ld.wasm'

    def get_allow_undefined_args(self) -> T.List[str]:
        return ['-sERROR_ON_UNDEFINED_SYMBOLS=0']

    def no_undefined_args(self) -> T.List[str]:
        return ['-sERROR_ON_UNDEFINED_SYMBOLS=1']

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        raise MesonException(f'{self.id} does not support shared libraries.')

    def get_asneeded_args(self) -> T.List[str]:
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())


class CcrxDynamicLinker(DynamicLinker):

    """Linker for Renesas CCrx compiler."""

    id = 'rlink'

    def __init__(self, for_machine: mesonlib.Mac
```