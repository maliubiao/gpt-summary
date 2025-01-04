Response:
My thinking process to answer the request about the `linkers.py` file goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Python code, specifically focusing on its relationship to reverse engineering, binary/kernel knowledge, logical reasoning, potential user errors, and debugging context. It's also explicitly stated that this is part 1 of a 2-part request and asks for a functional summary specifically for this part.

2. **Initial Scan and High-Level Purpose:**  I first skim the code to get a general idea of what it does. Keywords like "Linker," "StaticLinker," "DynamicLinker," and methods like `get_output_args`, `get_search_args`, `build_rpath_args` strongly suggest that this code is responsible for managing the linking process of software compilation. It defines interfaces and implementations for different linkers.

3. **Identify Key Classes:** I notice the presence of abstract base classes (`StaticLinker`, `DynamicLinker`) and concrete implementations (e.g., `VisualStudioLinker`, `ArLinker`, `GnuDynamicLinker`, `AppleDynamicLinker`). This hierarchical structure implies a design pattern where common linking functionalities are defined in the base classes, and specific linker behaviors are implemented in the derived classes.

4. **Analyze Base Class Functionality (StaticLinker):** I examine the methods within the `StaticLinker` class. These methods seem to define the core operations a static linker performs:
    * Executable management (`__init__`, `get_exelist`)
    * Argument handling (`compiler_args`, `get_base_link_args`, `get_std_link_args`, `get_optimization_link_args`, `get_output_args`, `get_coverage_link_args`, `thread_link_flags`, `openmp_flags`, `get_option_link_args`, `unix_args_to_native`, `native_args_to_unix`, `get_always_args`, `get_linker_always_args`)
    * Debugging information (`get_link_debugfile_name`, `get_link_debugfile_args`)
    * Response file handling (`can_linker_accept_rsp`, `rsp_file_syntax`)
    * RPATH handling (`build_rpath_args`)

5. **Analyze Base Class Functionality (DynamicLinker):** I repeat the process for the `DynamicLinker` class, noting similarities and differences:
    *  Similarities in executable and argument handling.
    *  Introduction of concepts specific to dynamic linking (e.g., `get_std_shared_lib_args`, `get_std_shared_module_args`, `get_pie_args`, `get_lto_args`, `sanitizer_args`, `get_asneeded_args`, `get_link_whole_for`, `get_allow_undefined_args`, `export_dynamic_args`, `import_library_args`, `thread_flags`, `no_undefined_args`, `fatal_warnings`, `headerpad_args`, `get_win_subsystem_args`, `bitcode_args`, `get_soname_args`).
    * Abstract methods that concrete implementations must provide (e.g., `get_output_args`, `get_search_args`).

6. **Examine Concrete Implementations:** I briefly look at some of the concrete linker implementations (e.g., `VisualStudioLinker`, `ArLinker`, `GnuDynamicLinker`, `AppleDynamicLinker`). This helps understand how the abstract methods are specialized for different linker tools. I notice the use of mixin classes (`PosixDynamicLinkerMixin`, `GnuLikeDynamicLinkerMixin`) to share common behavior among groups of linkers.

7. **Connect to the Request's Specific Points:** Now I go back to the request's specific questions and relate them to the code:

    * **Reverse Engineering:** I consider how linking relates to reverse engineering. The linker combines compiled object files and libraries into an executable. Understanding linker flags and how libraries are linked is crucial for reverse engineers analyzing the structure and dependencies of a binary. The `build_rpath_args` method, for instance, directly deals with how the operating system finds shared libraries at runtime, which is a key aspect of reverse engineering shared libraries.

    * **Binary/Kernel/OS Knowledge:**  The code interacts heavily with OS-specific concepts like RPATHs (Linux), install names (macOS), import libraries (Windows), and the differences between static and dynamic linking. Methods like `get_pie_args` (Position Independent Executables), `get_win_subsystem_args` (Windows executable types), and handling of different archive formats (`ArLinker`) demonstrate this connection.

    * **Logical Reasoning:** The code contains conditional logic based on the operating system, linker type, and build options. The `order_rpaths` and `evaluate_rpath` functions demonstrate a logical process for managing library search paths. The use of mixins also involves logical grouping of related functionalities.

    * **User Errors:**  I consider potential mistakes a user might make that would lead to this code being executed. Incorrectly specifying library paths, conflicting linker flags, or choosing the wrong linker for the target platform are examples. The code itself doesn't *directly* handle user errors, but it *implements* the logic that would be affected by those errors.

    * **Debugging:** I think about how a developer would end up looking at this code. They might be debugging linking errors, investigating why a particular library isn't being found, or adding support for a new linker.

8. **Formulate the Summary:** Based on the analysis, I structure the summary to address each part of the request. I start with the core functionality (managing linking), then address the specific points about reverse engineering, binary/kernel knowledge, logic, user errors, and debugging context, providing examples where relevant. Since this is part 1, I focus on summarizing the *functionality* of the code without diving too deeply into specific use cases that might be covered in part 2.

9. **Refine and Review:** I review the summary for clarity, accuracy, and completeness, ensuring it directly answers the prompt. I double-check that the examples are relevant and easy to understand.

This systematic approach allows me to break down the complex code into manageable parts and extract the key information needed to answer the detailed request effectively.
好的，让我们来分析一下 `frida/subprojects/frida-qml/releng/meson/mesonbuild/linkers/linkers.py` 这个文件的功能。

**功能归纳:**

这个 Python 文件定义了 Meson 构建系统中用于处理链接（linking）过程的各种类和方法。它的核心功能是提供一个抽象层，允许 Meson 与不同类型的链接器（linker）进行交互，而无需关心底层链接器的具体命令和语法差异。 这部分代码主要关注静态链接器 (`StaticLinker`) 和动态链接器 (`DynamicLinker`) 的抽象基类及其一些具体的实现类。

更具体地说，它的功能包括：

1. **定义链接器的抽象接口:**
   - `StaticLinker` 类定义了静态链接器的通用接口，例如获取执行命令、链接参数、输出参数、调试信息参数等。
   - `DynamicLinker` 类定义了动态链接器的通用接口，涵盖了共享库、模块、符号导出、rpath 设置等更丰富的动态链接特性。

2. **实现特定链接器的类:**
   - 针对不同的链接器（例如 GNU ld, LLVM lld, Apple ld, Visual Studio link.exe, ar 等）提供了具体的类实现，例如 `GnuDynamicLinker`, `AppleDynamicLinker`, `VisualStudioLinker`, `ArLinker` 等。
   - 这些具体的类继承自抽象基类，并根据特定链接器的语法和行为实现了抽象方法，例如如何指定输出文件名、添加库搜索路径、设置 rpath 等。

3. **处理链接参数和选项:**
   - 提供了方法来获取不同类型的链接参数，例如优化级别、调试信息、覆盖率、线程支持等。
   - 针对不同的平台和链接器，提供了参数转换的功能，例如 `unix_args_to_native` 和 `native_args_to_unix`。

4. **处理 Response 文件 (RSP):**
   - 提供了处理链接器 response 文件的功能，允许将大量的链接参数写入文件中，避免命令行长度限制的问题。
   - `can_linker_accept_rsp()` 方法判断链接器是否支持 response 文件，`rsp_file_syntax()` 方法定义了 response 文件的语法格式。

5. **处理 RPATH (Run-Time Path):**
   - 提供了 `build_rpath_args` 方法来生成用于设置 RPATH 的链接器参数，这对于动态链接库的查找至关重要。
   - 包含 `prepare_rpaths`, `order_rpaths`, `evaluate_rpath` 等辅助函数来处理和优化 RPATH 的设置。

**与逆向方法的关联及举例说明:**

链接过程是生成可执行文件和动态链接库的关键步骤，理解链接过程对于逆向工程至关重要。这个文件中的功能与逆向方法有以下关联：

* **理解依赖关系:** 逆向工程师需要了解目标程序依赖哪些动态链接库。`build_rpath_args` 方法生成的参数决定了程序运行时如何查找这些库。分析这些参数可以帮助逆向工程师理解程序的依赖关系和加载机制。例如，如果逆向分析一个 Linux 程序，查看其 `.dynamic` 节中的 `RPATH` 或 `RUNPATH` 可以了解程序期望从哪些目录加载共享库，这与 `build_rpath_args` 的输出有关。

* **分析符号和导出:** 动态链接器负责处理符号的解析和导出。了解链接器的行为可以帮助逆向工程师理解程序中的函数和变量是如何被链接和调用的。例如，`export_dynamic_args` 方法与将符号导出到动态符号表有关，逆向工程师可以使用工具（如 `readelf -s`) 查看动态符号表，了解程序导出了哪些函数。

* **调试符号:** `get_link_debugfile_args` 方法与生成调试符号文件（如 PDB 文件或 DWARF 信息）有关。逆向工程师通常依赖这些调试符号来辅助分析程序。了解链接器如何处理调试信息可以帮助理解调试符号的生成和使用。

* **理解加壳和混淆:** 一些加壳和混淆技术会修改程序的链接结构或导入导出表。理解正常的链接过程有助于逆向工程师识别这些异常。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件涉及到了以下二进制底层、Linux、Android 内核及框架的知识：

* **二进制格式 (ELF, PE, Mach-O):**  不同的操作系统使用不同的可执行文件格式。链接器的行为会受到这些格式的影响。例如，RPATH 是 ELF 格式的概念，而在 macOS 上对应的是 install name。

* **动态链接和共享库 (.so, .dll, .dylib):** 动态链接是现代操作系统中常用的技术，允许程序在运行时加载库。这个文件中的 `DynamicLinker` 类及其子类就是用来处理动态链接的。

* **RPATH 和库搜索路径:** 在 Linux 等系统中，RPATH 是一种指定程序运行时动态链接库搜索路径的机制。`build_rpath_args` 方法就是用来生成设置 RPATH 的链接器参数。在 Android 中，`dlopen` 等函数也会受到库搜索路径的影响。

* **符号表:** 链接器负责处理符号的解析，符号表记录了程序中的函数和变量的地址和信息。理解符号表对于逆向分析至关重要。

* **Position Independent Executable (PIE):** `get_pie_args` 方法与生成 PIE 可执行文件有关。PIE 是一种安全机制，可以使程序在内存中的加载地址随机化，增加攻击难度。这在 Linux 和 Android 等系统中被广泛使用。

* **Windows Subsystem:** `get_win_subsystem_args` 方法用于指定 Windows 可执行文件的子系统（例如控制台程序、GUI 程序）。这涉及到 Windows PE 文件的头信息。

**逻辑推理及假设输入与输出:**

这个文件中的逻辑推理主要体现在：

* **条件判断:**  根据不同的操作系统、链接器类型和构建选项，选择不同的链接器参数。例如，`get_asneeded_args` 方法在不同的链接器中返回的参数可能不同。

* **参数转换:** `unix_args_to_native` 和 `native_args_to_unix` 方法用于在 Unix 风格的参数和特定平台的原生参数之间进行转换。

* **RPATH 处理:** `prepare_rpaths`, `order_rpaths`, `evaluate_rpath` 这些函数包含对 RPATH 路径进行处理和优化的逻辑，例如将相对路径转换为内部格式、排序 RPATH 路径等。

**假设输入与输出 (以 `build_rpath_args` 为例):**

**假设输入:**

* `env`:  包含目标机器信息的 `Environment` 对象，假设目标是 Linux x86_64。
* `build_dir`:  构建目录的路径，例如 `/home/user/project/build`。
* `from_dir`:  当前源文件的目录，例如 `/home/user/project/src`。
* `rpath_paths`:  一个包含需要添加到 RPATH 的相对路径的元组，例如 `('lib', '../otherlib')`。
* `build_rpath`:  一个额外的构建时 RPATH 字符串，例如 `/opt/custom/lib`。
* `install_rpath`:  一个安装时 RPATH 字符串，例如 `$ORIGIN/../lib`。

**逻辑推理:**

1. `prepare_rpaths` 将相对路径转换为相对于构建目录的路径，例如 `lib` 转换为 `lib`，`../otherlib` 转换为 `../otherlib`。
2. `order_rpaths` 对 RPATH 路径进行排序，通常将绝对路径放在前面。
3. `build_rpath_args` 根据目标平台 (Linux) 和链接器类型 (假设是 GNU ld) 生成相应的链接器参数。

**预期输出:**

* 一个包含链接器参数的列表，例如 `['-Wl,-rpath,$ORIGIN/lib:$ORIGIN/../otherlib:/opt/custom/lib', '-Wl,-rpath-link,/home/user/project/build/lib', '-Wl,-rpath-link,/home/user/project/build/../otherlib']`。
* 一个包含需要从 RPATH 中移除的目录的集合 (用于安装时处理)。

**涉及用户或编程常见的使用错误及举例说明:**

虽然这个文件本身是 Meson 的内部实现，但用户或程序员在使用 Meson 构建系统时可能会犯以下错误，这些错误最终会影响到这里代码的执行：

* **错误的库路径配置:** 用户可能在 `meson.build` 文件中指定了错误的库搜索路径 (`link_with` 或 `dependencies`)，导致链接器无法找到所需的库。这会导致链接过程失败，最终会调用到这个文件中的链接器相关逻辑进行处理，并可能抛出链接错误。

* **链接器参数冲突:** 用户可能通过 `link_args` 手动添加了与 Meson 默认行为冲突的链接器参数。例如，手动指定了一个与 Meson 生成的 RPATH 参数冲突的值，可能导致程序运行时找不到库。

* **平台相关的配置错误:**  用户可能在跨平台构建时，没有正确处理平台特定的链接器参数或库依赖，导致在特定平台上链接失败。

* **误解 RPATH 的工作方式:** 用户可能不理解 RPATH 的工作原理，导致配置的 RPATH 不正确，程序运行时找不到动态链接库。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户执行 `meson compile` 或 `ninja` 命令进行编译时，Meson 会经历以下步骤，最终可能会执行到 `linkers.py` 中的代码：

1. **解析 `meson.build` 文件:** Meson 首先会解析项目中的 `meson.build` 文件，读取项目的构建配置信息，包括依赖项、源文件、目标类型等。

2. **确定链接器:** Meson 会根据项目配置和当前环境（操作系统、编译器等）自动选择合适的链接器。这个选择过程可能涉及到查找系统中的链接器可执行文件。

3. **生成链接命令:** 当需要链接生成可执行文件或共享库时，Meson 会调用 `linkers.py` 中的相应链接器类的方法，生成特定于该链接器的链接命令。这包括设置输出文件名、添加库搜索路径、指定需要链接的库文件、设置 RPATH 等。

4. **执行链接命令:** Meson 或 Ninja (如果使用 Ninja 构建后端) 会执行生成的链接命令。

**调试线索:**

* **链接错误信息:** 如果编译过程中出现链接错误，例如 "cannot find -lxxx" 或 "undefined reference to 'yyy'"，这表明链接器在执行 `linkers.py` 生成的命令时遇到了问题。

* **查看生成的链接命令:**  Meson 通常会提供选项（例如使用 `-v` 或查看构建日志）来查看实际执行的链接命令。分析这些命令可以帮助理解 Meson 是如何调用链接器的，以及哪些参数被传递给了链接器。

* **断点调试 Meson 代码:** 对于 Meson 开发人员或需要深入了解构建过程的用户，可以使用 Python 调试器在 `linkers.py` 中设置断点，查看链接器对象的属性和方法的调用过程，从而理解链接命令是如何生成的。

**总结它的功能 (针对第 1 部分):**

`linkers.py` 文件的核心功能是为 Meson 构建系统提供一个抽象的、平台无关的方式来与各种静态和动态链接器进行交互。它定义了链接器的通用接口和针对特定链接器的实现，负责生成正确的链接命令，处理链接参数、库搜索路径、RPATH 设置等关键的链接过程。这部分代码主要关注链接器的抽象基类和一部分具体的实现类，为 Meson 的链接功能奠定了基础。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/linkers/linkers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
"""


```