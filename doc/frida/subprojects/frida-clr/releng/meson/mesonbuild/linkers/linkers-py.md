Response:
The user wants a summary of the functionality of the provided Python code, which defines classes for static and dynamic linkers used within the Frida dynamic instrumentation tool's build system (Meson).

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file is located within the `frida/subprojects/frida-clr/releng/meson/mesonbuild/linkers/` directory, suggesting it deals with linkers within the Meson build system for Frida's CLR (Common Language Runtime) component. The filename `linkers.py` reinforces this.

2. **Categorize the Classes:**  Scan the file for class definitions. Notice the presence of `StaticLinker` and `DynamicLinker` as base classes, along with several concrete implementations like `VisualStudioLinker`, `ArLinker`, `GnuDynamicLinker`, etc. This suggests a hierarchy for different linker types.

3. **Analyze `StaticLinker`:**  Go through the methods of the `StaticLinker` class. Key functionalities include:
    * Managing the execution command (`exelist`).
    * Handling compiler arguments.
    * Determining if response files are supported.
    * Getting base, standard, and optimization link arguments.
    * Defining output arguments.
    * Handling coverage and rpath arguments.
    * Setting thread and OpenMP link flags.
    * Providing options for debug files.
    * Defining always-present linker arguments.
    * Handling response file syntax.

4. **Analyze `DynamicLinker`:**  Examine the methods of the `DynamicLinker` class. It has many overlapping functionalities with `StaticLinker`, but with a focus on dynamic linking:
    *  Similar argument handling (optimization, standard, output).
    *  Specific methods for shared libraries and modules.
    *  Handling Position Independent Executables (PIE).
    *  Link-Time Optimization (LTO).
    *  Sanitizer arguments.
    *  `as-needed` linking.
    *  `link_whole` and `allow_undefined` options.
    *  Coverage arguments.
    *  Search paths for libraries.
    *  Exporting dynamic symbols.
    *  Import libraries.
    *  Thread flags.
    *  Handling undefined symbols.
    *  Fatal warnings.
    *  Windows subsystem settings.
    *  Bitcode arguments.
    *  Soname handling.
    *  Archiving shared libraries (AIX specific).

5. **Identify Concrete Linker Implementations:** Notice the various subclasses of `StaticLinker` (e.g., `VisualStudioLinker`, `ArLinker`, `DLinker`) and `DynamicLinker` (e.g., `AppleDynamicLinker`, `GnuDynamicLinker`, `LLVMDynamicLinker`). These represent specific linker tools and their particular command-line options.

6. **Focus on Shared Functionality:**  Recognize that both base classes provide mechanisms for managing linker executables, constructing argument lists, and handling platform-specific options.

7. **Infer Context (Frida and Meson):**  The file path and the `frida` prefix clearly indicate this is part of Frida. The presence of `mesonbuild` in the path signifies integration with the Meson build system.

8. **Synthesize the Summary:** Combine the observations into a concise summary:
    *  The file defines classes for static and dynamic linkers.
    *  It provides an abstraction layer over different linker tools.
    *  Key functionalities include managing linker executables, generating command-line arguments for linking, and handling platform-specific options.
    *  It supports various linker features like optimization, debugging, coverage, and RPATH.
    *  It includes concrete implementations for common linkers (GNU ld, LLVM lld, Apple's ld, MSVC's link).

9. **Refine and Organize:** Ensure the summary is clear, well-structured, and uses appropriate terminology. Emphasize the core purpose and the key abstractions. Group similar functionalities together.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/linkers/linkers.py` 文件的第一部分，主要定义了用于处理静态链接和动态链接的基类和一些具体的链接器类。其核心功能是为 Meson 构建系统提供一个抽象层，使得 Meson 可以与各种不同的链接器进行交互，而无需了解每个链接器的具体命令行参数和行为。

**主要功能归纳:**

1. **定义链接器基类:**
   - **`StaticLinker`:**  定义了静态链接器的通用接口，包含获取执行命令、构建参数、处理输出、设置调试信息等方法。
   - **`DynamicLinker`:** 定义了动态链接器的通用接口，与 `StaticLinker` 类似，但侧重于动态链接相关的特性，如共享库、模块、rpath 等。

2. **提供链接器抽象:**
   - 通过基类和子类的方式，将不同链接器的差异性封装起来，使得 Meson 可以使用统一的接口来操作不同的链接器，例如 GNU ld、LLVM lld、Apple ld、MSVC link 等。

3. **管理链接器执行命令:**
   - 每个链接器类都维护了其可执行文件的路径列表 (`exelist`)。

4. **构建链接参数:**
   - 提供了多种方法来生成链接器的命令行参数，例如：
     - 基本链接参数 (`get_base_link_args`)
     - 标准链接参数 (`get_std_link_args`)
     - 优化级别参数 (`get_optimization_link_args`)
     - 输出文件参数 (`get_output_args`)
     - 覆盖率参数 (`get_coverage_link_args`)
     - RPATH 参数 (`build_rpath_args`)
     - 线程相关参数 (`thread_link_flags`)
     - OpenMP 相关参数 (`openmp_flags`)
     - 用户自定义选项参数 (`get_option_link_args`)
     - 调试信息参数 (`get_link_debugfile_args`, `get_debugfile_args`)
     - 始终使用的参数 (`get_always_args`, `get_linker_always_args`)
     - 共享库相关参数 (`get_std_shared_lib_args`, `get_std_shared_module_args`)
     - PIE (`get_pie_args`)
     - LTO (`get_lto_args`)
     - Sanitizer (`sanitizer_args`)
     - `as-needed` (`get_asneeded_args`)
     - `link_whole` (`get_link_whole_for`)
     - `allow_undefined` (`get_allow_undefined_args`)
     - 搜索路径 (`get_search_args`)
     - 导出动态符号 (`export_dynamic_args`)
     - 导入库 (`import_library_args`)
     - soname (`get_soname_args`)

5. **处理平台差异:**
   - 针对不同的操作系统和链接器，提供了特定的子类和方法来处理平台差异，例如 `VisualStudioLinker`、`ArLinker`、`AppleDynamicLinker`、`GnuDynamicLinker` 等。

6. **支持响应文件:**
   - 提供了判断链接器是否支持响应文件 (`can_linker_accept_rsp`) 以及获取响应文件语法 (`rsp_file_syntax`) 的方法，用于处理大量链接参数的情况。

7. **提供参数转换工具:**
   - 提供了 Unix 风格参数和 native 风格参数之间的转换方法 (`unix_args_to_native`, `native_args_to_unix`)，主要用于 Visual Studio 链接器。

**与逆向方法的关联及举例说明:**

- **生成包含调试信息的二进制文件:**  `get_link_debugfile_name` 和 `get_link_debugfile_args` 方法用于控制链接器生成调试信息文件（例如，Windows 上的 PDB 文件，或者 ELF 文件中的 DWARF 信息）。逆向工程师通常需要这些调试信息来辅助分析二进制代码，例如查看符号信息、函数调用栈等。
    - **举例:**  假设输入 `targetfile` 是 "my_executable"，对于支持生成独立调试文件的链接器，`get_link_debugfile_args` 可能会返回 `["/DEBUG:FULL", "/PDB:my_executable.pdb"]` (MSVC) 或 `["-Wl,--build-id"]` (GNU ld)，指示链接器生成包含完整调试信息的 "my_executable.pdb" 或在 ELF 文件中添加 build-id。

- **控制链接器的行为以避免 strip 操作:** 某些链接器选项可以影响最终生成的可执行文件是否包含符号信息。逆向分析通常依赖于符号信息。
    - **举例:** 某些链接器可能默认会 strip 掉符号信息以减小文件大小。通过链接器选项，例如不使用 `-s` 优化级别，可以保留符号信息。虽然这段代码没有直接控制 strip 操作，但它通过 `get_optimization_link_args` 影响了传递给链接器的优化级别，从而间接影响是否 strip。

- **设置 RPATH (Run-Time Search Path) 用于动态库加载:** `build_rpath_args` 方法用于设置可执行文件运行时搜索动态库的路径。逆向工程师在分析程序加载动态库的过程时，RPATH 信息非常重要。
    - **举例:**  如果构建时指定了 `rpath_paths = ["$ORIGIN/lib"]`，`build_rpath_args` 可能会生成类似 `-Wl,-rpath,'$ORIGIN/lib'` 的参数，指示操作系统在运行时首先在可执行文件所在目录的 `lib` 子目录下查找动态库。

**涉及二进制底层、Linux、Android 内核及框架的知识的举例说明:**

- **RPATH 和动态库加载 (Linux):**  `build_rpath_args` 方法的处理涉及到 Linux 系统中动态链接器如何查找和加载共享库的机制。`$ORIGIN` 占位符是一个与平台相关的概念，在 Linux 上表示可执行文件或共享库所在的目录。
    - **举例:** 在 Linux 上，`build_rpath_args` 方法会生成 `-Wl,-rpath` 参数，这是 GNU ld 链接器用于设置 RPATH 的选项。了解 Linux 动态链接的机制对于理解这段代码如何工作至关重要。

- **共享库的 soname (Linux):** `get_soname_args` 方法用于设置共享库的 soname (Shared Object Name)，这是 Linux 系统中用于版本控制和动态链接的重要概念。
    - **举例:** 在 Linux 上，`get_soname_args` 可能会生成 `-Wl,-soname,libmylib.so.1` 这样的参数，指定生成的共享库的 soname 为 `libmylib.so.1`。

- **Windows 子系统 (Windows):**  `get_win_subsystem_args` 方法用于设置 Windows 可执行文件的子系统类型（例如，控制台程序、Windows 应用程序等）。
    - **举例:** 在 Windows 上，如果需要生成一个图形界面的应用程序，`get_win_subsystem_args` 可能会返回 `['/SUBSYSTEM:WINDOWS']`。

**逻辑推理及假设输入与输出:**

- **假设输入:**
    - 链接器是 GNU ld。
    - 目标文件名是 "my_executable"。
    - 没有指定额外的 RPATH。
- **输出 (在 `GnuDynamicLinker` 的 `get_output_args` 方法中):**
    - `get_output_args("my_executable")` 可能会返回 `['-o', 'my_executable']`。

- **假设输入:**
    - 链接器是 Visual Studio Linker。
    - 目标文件名是 "my_library.lib"。
    - 目标机器架构是 "x64"。
- **输出 (在 `VisualStudioLinker` 的 `get_output_args` 方法中):**
    - `get_output_args("my_library.lib")` 可能会返回 `['/MACHINE:x64', '/OUT:my_library.lib']`。

**涉及用户或编程常见的使用错误及举例说明:**

- **错误地指定了不存在的优化级别:**  `get_optimization_link_args` 方法依赖于 `_OPTIMIZATION_ARGS` 字典。如果用户在 Meson 构建文件中指定了一个 `optimization_level`，但该级别在字典中不存在，则可能会导致错误或者使用默认的优化级别。
    - **举例:** 如果用户设置 `optimization : 'super_high'`，但 `DynamicLinker._OPTIMIZATION_ARGS` 中没有 'super_high' 键，则 `get_optimization_link_args('super_high')` 可能会抛出 KeyError 异常。

- **在不支持 RPATH 的平台上尝试设置 RPATH:**  某些平台（如 Windows）不使用 RPATH。如果用户尝试在这些平台上设置 RPATH，`build_rpath_args` 方法可能会返回空列表，或者链接器本身可能会忽略这些参数，但用户可能会误以为 RPATH 已经设置成功。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户执行 `meson setup build` 或 `ninja` 命令:**  这是触发 Meson 构建过程的起点。
2. **Meson 读取 `meson.build` 文件:**  Meson 解析项目根目录下的 `meson.build` 文件，该文件描述了构建目标、依赖关系和构建选项。
3. **Meson 配置链接器:**  根据 `meson.build` 文件中指定的语言和平台，Meson 会选择合适的链接器。这个选择过程可能会涉及到查找系统中的链接器可执行文件。
4. **Meson 调用链接器模块:** 当需要执行链接操作时，Meson 会加载 `frida/subprojects/frida-clr/releng/meson/mesonbuild/linkers/linkers.py` 模块。
5. **Meson 创建链接器对象:**  根据选择的链接器类型，Meson 会创建 `StaticLinker` 或 `DynamicLinker` 的具体子类的实例，例如 `GnuDynamicLinker` 或 `VisualStudioLinker`。
6. **Meson 调用链接器对象的方法:**  在链接过程中，Meson 会调用链接器对象的各种方法来生成链接命令，例如 `get_output_args` 获取输出文件参数，`get_std_link_args` 获取标准链接参数，`build_rpath_args` 获取 RPATH 参数等。
7. **用户配置构建选项:**  用户可以通过 `meson configure` 命令设置构建选项，例如优化级别 (`optimization`)、是否生成调试信息 (`buildtype`) 等。这些选项会影响 Meson 调用链接器对象的方法时传递的参数，从而影响最终生成的链接命令。
8. **`frida-clr` 特定的构建逻辑:**  由于这个文件位于 `frida-clr` 的子项目中，`frida-clr` 的构建逻辑可能会对链接器的选择和参数配置产生特定的影响。

**总结:**

`frida/subprojects/frida-clr/releng/meson/mesonbuild/linkers/linkers.py` 的第一部分主要定义了用于抽象静态链接和动态链接过程的基类和一些具体的链接器实现。它为 Meson 提供了一个灵活的方式来与不同的链接器交互，管理链接器的执行命令，并根据不同的平台和构建选项生成相应的链接参数。这对于构建 Frida 这样的跨平台工具至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/linkers/linkers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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