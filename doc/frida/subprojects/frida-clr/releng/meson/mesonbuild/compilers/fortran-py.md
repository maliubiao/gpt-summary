Response:
Let's break down the thought process for analyzing this Python code and generating the detailed explanation.

1. **Understand the Core Task:** The initial request is to analyze a specific Python file within the Frida project, focusing on its functionality, relationship to reverse engineering, low-level details, logical inferences, common errors, and debugging context.

2. **Initial Code Scan and Purpose Identification:**  The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "Compiler," "Fortran," "sanity_check," "optimization_args," "debug_args," and the various compiler-specific classes immediately indicate that this file defines how Meson, the build system, interacts with different Fortran compilers. It's about abstracting away the specifics of each Fortran compiler for the build process.

3. **Functionality Breakdown:**  Go through each class and method, noting its purpose. Focus on the key actions a compiler needs to perform:
    * Compilation (sanity check, argument handling)
    * Linking (finding libraries, link arguments)
    * Preprocessing
    * Module handling (incdir, outdir, module names)
    * Optimization and debugging
    * Standard selection
    * Dependency generation

4. **Connecting to Reverse Engineering:** This requires some higher-level thinking. How does compiling Fortran code relate to reverse engineering?
    * **Target Analysis:** Fortran might be used in the target application being reversed. Understanding how it's compiled can be helpful.
    * **Instrumentation:**  Frida is an *instrumentation* tool. While this file itself doesn't *do* instrumentation, it's part of the build process for Frida's components. If Frida needs to interact with Fortran code in a target, this code is relevant. Think broadly about the ecosystem.
    * **Compiler-Specific Behavior:**  Reverse engineers sometimes need to understand compiler-specific optimizations or code generation quirks. Knowing how Meson configures the compiler provides context.

5. **Identifying Low-Level/Kernel/Framework Aspects:**  Look for features that interact with the underlying system:
    * **Binary Execution:** The `exelist` represents the compiler's executable.
    * **Linking:** Finding libraries (`find_library`), linker prefixes (`LINKER_PREFIX`), and standard library linking flags directly relate to the binary's structure and dependencies.
    * **File System Interaction:**  Module output directories, include directories, and sanity checks all involve file system operations.
    * **Compiler Options:** Many compiler options directly influence the generated binary code (optimization, debugging).
    * **Platform Differences:** The code explicitly handles different operating systems (through `for_machine`).

6. **Logical Inference (Hypothetical Inputs and Outputs):** Choose a few key methods and imagine how they would behave with specific inputs.
    * **`module_name_to_filename`:**  Test with simple and submodule names for different compilers.
    * **`get_module_outdir_args`:**  See how the output directory is specified for different compilers.
    * **`get_optimization_args`:**  Show the flags for different optimization levels.

7. **Common Usage Errors:** Think about how a user of Meson (the build system that uses this code) might make mistakes related to Fortran compilation:
    * Incorrect standard specification.
    * Missing libraries (leading to linking errors).
    * Issues with module paths.
    * Problems with compiler availability.

8. **Debugging Context (Path to This Code):** Trace the steps a developer might take to end up looking at this specific file:
    * A build failure related to Fortran.
    * Investigating Meson's compiler handling.
    * Contributing to Meson and working on Fortran support.

9. **Structure and Refine:** Organize the information logically using headings and bullet points. Ensure clarity and conciseness. Use code snippets to illustrate points.

10. **Review and Iterate:** Read through the explanation, checking for accuracy, completeness, and clarity. Could anything be explained better? Are there any missing connections?  For instance, initially, the connection to reverse engineering might be weak. Revisiting it to emphasize the *build process* for potentially reversed Fortran applications strengthens the link.

**Self-Correction Example During the Process:**

* **Initial thought:**  This file is purely about compilation and has nothing to do with *runtime* reverse engineering.
* **Correction:**  While it's about compilation, understanding *how* the code is compiled is valuable for reverse engineering. Furthermore, Frida itself might need to compile components, and this code would be part of that process if Fortran is involved. Focus on the *build process* aspect.

By following this structured thinking process, covering different angles (functionality, reverse engineering, low-level details, usage, debugging), and iterating on the explanations, a comprehensive and accurate answer can be generated.
这是 Frida 动态插桩工具中用于处理 Fortran 语言编译器的源代码文件。它的主要功能是为 Meson 构建系统提供一个统一的接口来与各种不同的 Fortran 编译器进行交互。

以下是其功能的详细列表和相关的举例说明：

**1. 定义和抽象 Fortran 编译器的通用行为:**

*   **功能:**  定义了一个 `FortranCompiler` 基类，它继承自 `CLikeCompiler` 和 `Compiler`。这个基类包含了所有 Fortran 编译器通用的属性和方法，例如语言类型 (`language = 'fortran'`)，以及一些默认的行为。
*   **逆向方法关系:** 在逆向工程中，了解目标程序是用何种编译器编译的至关重要。这个文件抽象了 Fortran 编译器的通用特性，可以帮助 Frida 更统一地处理使用 Fortran 编写的目标程序，无论其具体编译器是什么。
*   **二进制底层:**  编译器是连接高级语言和机器码的桥梁。这个文件处理的是编译器层面的抽象，间接影响最终生成的二进制代码的结构、调用约定和调试信息。

**2. 实现特定 Fortran 编译器的支持:**

*   **功能:** 针对不同的 Fortran 编译器 (例如 GNU Fortran, Intel Fortran, PGI Fortran 等)，定义了各自的子类 (如 `GnuFortranCompiler`, `IntelFortranCompiler` 等)。每个子类都根据特定编译器的语法和行为，重写或实现基类的方法。
*   **逆向方法关系:** 不同的 Fortran 编译器在代码生成、优化和调试信息格式上可能存在差异。了解目标程序使用的具体编译器，并利用 Frida 与相应编译器的交互能力，可以更精确地进行插桩和分析。例如，不同编译器生成的符号表格式可能不同，Frida 需要知道如何解析这些符号。
*   **二进制底层:** 不同的 Fortran 编译器可能使用不同的 ABI (Application Binary Interface)，这会影响函数调用、数据布局等方面。这个文件通过适配不同的编译器，确保 Frida 能正确地与这些二进制代码进行交互。

**3. 处理编译器参数和选项:**

*   **功能:**  包含了处理各种编译器参数的方法，例如获取优化参数 (`get_optimization_args`)、调试参数 (`get_debug_args`)、预处理参数 (`get_preprocess_only_args`)、模块路径参数 (`get_module_incdir_args`, `get_module_outdir_args`) 等。
*   **逆向方法关系:**  在逆向工程中，有时需要了解目标程序在编译时使用了哪些特定的编译器选项。例如，是否开启了优化，是否包含了调试信息。Frida 可以利用这些信息来更好地理解程序的行为。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 调用 `compiler.get_optimization_args('2')`，其中 `compiler` 是 `GnuFortranCompiler` 的实例。
    *   **输出:**  `['-Wall', '-Wextra']` (根据 `GnuFortranCompiler` 的定义)。
*   **用户常见使用错误:** 用户可能在 Meson 的配置文件中指定了错误的编译器选项，导致编译失败。例如，指定了某个编译器不支持的 Fortran 标准版本。

**4. 处理模块 (Modules) 的编译和链接:**

*   **功能:**  提供了处理 Fortran 模块的方法，例如将模块名转换为文件名 (`module_name_to_filename`)，获取模块输出目录参数 (`get_module_outdir_args`)。
*   **逆向方法关系:** Fortran 的模块化特性允许将代码组织成独立的单元。了解模块的编译和链接方式，可以帮助逆向工程师理解代码的结构和依赖关系。
*   **二进制底层:** Fortran 模块的编译会生成特定的文件 (.mod, .smod 等)，这些文件包含了模块的接口信息。链接器需要这些信息来正确地链接使用该模块的代码。

**5. 进行基本的编译器健康检查:**

*   **功能:**  提供了 `sanity_check` 方法，用于检查 Fortran 编译器是否能够正常工作。
*   **用户操作到达此处的调试线索:** 如果 Meson 在配置构建环境时，检测到 Fortran 编译器存在问题，就会调用这个方法进行检查。用户可能会看到类似 "Fortran compiler sanity check failed" 的错误信息。

**6. 查找库文件:**

*   **功能:**  提供了 `find_library` 方法，用于在指定的路径中查找 Fortran 库文件。
*   **逆向方法关系:**  目标程序可能依赖于一些 Fortran 库。Frida 可以利用这个功能来查找这些库，以便进行更深入的分析。
*   **用户常见使用错误:** 用户可能忘记安装目标程序依赖的 Fortran 库，导致链接失败。

**7. 检查编译器对特定参数的支持:**

*   **功能:**  提供了 `has_multi_arguments` 和 `has_multi_link_arguments` 方法，用于检查编译器是否支持传递多个参数或链接参数。

**8. 处理 Fortran 语言标准:**

*   **功能:**  提供了获取和设置 Fortran 语言标准的方法 (`get_options`, `get_option_compile_args`)。
*   **逆向方法关系:**  不同的 Fortran 语言标准 (例如 F95, F2003, F2008) 具有不同的语法和特性。了解目标程序使用的 Fortran 标准，可以帮助逆向工程师更好地理解代码。
*   **用户常见使用错误:** 用户可能在 Meson 配置文件中指定了目标编译器不支持的 Fortran 标准，导致编译错误。

**9. 获取依赖关系生成参数:**

*   **功能:**  提供了 `get_dependency_gen_args` 方法，用于获取生成依赖关系文件的编译器参数。

**10. 处理 OpenMP 并行化:**

*   **功能:**  一些编译器子类 (如 `SunFortranCompiler`, `PathScaleFortranCompiler`, `NAGFortranCompiler`) 提供了 `openmp_flags` 方法，用于获取 OpenMP 编译所需的标志。
*   **逆向方法关系:**  如果目标程序使用了 OpenMP 进行并行化，了解其编译方式可以帮助逆向工程师理解程序的并发行为。

**与逆向方法的关系举例说明:**

假设你想使用 Frida 分析一个用 GNU Fortran 编译的程序，并且该程序使用了 Fortran 模块。

1. Frida 在启动时，会通过 Meson 构建系统检测到目标程序需要 Fortran 编译器。
2. Meson 会加载 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/fortran.py` 文件。
3. 根据系统中安装的 Fortran 编译器，Meson 会实例化 `GnuFortranCompiler` 类。
4. 当你尝试对程序中的某个函数进行插桩时，Frida 可能需要确定该函数是否定义在某个 Fortran 模块中。
5. Frida 可能会调用 `GnuFortranCompiler` 的 `module_name_to_filename` 方法，传入模块名，以确定包含该模块定义的文件名。
6. Frida 还需要知道如何链接 Fortran 标准库，这会涉及到 `GnuFortranCompiler` 的 `language_stdlib_only_link_flags` 方法。

**涉及到二进制底层、Linux、Android 内核及框架的知识的举例说明:**

*   **二进制底层:**  `FortranCompiler` 类中的方法，如 `get_module_outdir_args`，会影响编译过程中生成的二进制文件的结构。例如，模块信息的存储方式会影响链接器的行为。
*   **Linux:**  在 Linux 系统上，不同的 Fortran 编译器 (如 gfortran) 通常会安装在特定的路径下。Meson 需要能够找到这些编译器，这涉及到对 Linux 文件系统和环境变量的理解。
*   **Android 内核及框架:** 虽然 Fortran 在 Android 应用开发中不常见，但如果某些底层库或工具链使用了 Fortran，Frida 仍然需要能够处理。这个文件提供的编译器抽象可以帮助 Frida 在 Android 环境下也能正常工作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试使用 Frida 插桩一个用 Fortran 编写的目标程序。**
2. **Frida 内部的构建系统 (通常是 Meson) 需要配置 Fortran 编译环境。**
3. **Meson 会查找系统中可用的 Fortran 编译器。**
4. **Meson 根据找到的编译器类型，加载 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/fortran.py` 文件中相应的编译器类 (例如 `GnuFortranCompiler`)。**
5. **如果配置过程中出现问题 (例如找不到编译器，或者编译器版本不支持)，用户可能会在错误信息中看到与 Fortran 编译相关的提示。**
6. **为了调试这个问题，开发者可能会查看 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/fortran.py` 文件，了解 Frida 是如何处理 Fortran 编译器的，以及可能出错的地方。**

总而言之，`fortran.py` 文件在 Frida 项目中扮演着关键的角色，它使得 Frida 能够理解和利用各种 Fortran 编译器，从而支持对使用 Fortran 编写的目标程序进行动态插桩和分析。它通过抽象和适配不同的编译器，简化了 Frida 的内部实现，并提高了其跨平台和跨编译器的兼容性。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2017 The Meson development team

from __future__ import annotations

import typing as T
import os

from .. import coredata
from .compilers import (
    clike_debug_args,
    Compiler,
    CompileCheckMode,
)
from .mixins.clike import CLikeCompiler
from .mixins.gnu import GnuCompiler,  gnu_optimization_args
from .mixins.intel import IntelGnuLikeCompiler, IntelVisualStudioLikeCompiler
from .mixins.clang import ClangCompiler
from .mixins.elbrus import ElbrusCompiler
from .mixins.pgi import PGICompiler

from mesonbuild.mesonlib import (
    version_compare, MesonException,
    LibType, OptionKey,
)

if T.TYPE_CHECKING:
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..dependencies import Dependency
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice


class FortranCompiler(CLikeCompiler, Compiler):

    language = 'fortran'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        Compiler.__init__(self, [], exelist, version, for_machine, info,
                          is_cross=is_cross, full_version=full_version, linker=linker)
        CLikeCompiler.__init__(self)

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise MesonException('Fortran does not have "has_function" capability.\n'
                             'It is better to test if a Fortran capability is working like:\n\n'
                             "meson.get_compiler('fortran').links('block; end block; end program')\n\n"
                             'that example is to see if the compiler has Fortran 2008 Block element.')

    def _get_basic_compiler_args(self, env: 'Environment', mode: CompileCheckMode) -> T.Tuple[T.List[str], T.List[str]]:
        cargs = env.coredata.get_external_args(self.for_machine, self.language)
        largs = env.coredata.get_external_link_args(self.for_machine, self.language)
        return cargs, largs

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        source_name = 'sanitycheckf.f90'
        code = 'program main; print *, "Fortran compilation is working."; end program\n'
        return self._sanity_check_impl(work_dir, environment, source_name, code)

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return gnu_optimization_args[optimization_level]

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        return clike_debug_args[is_debug]

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-cpp'] + super().get_preprocess_only_args()

    def get_module_incdir_args(self) -> T.Tuple[str, ...]:
        return ('-I', )

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-module', path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I' or i[:2] == '-L':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))

        return parameter_list

    def module_name_to_filename(self, module_name: str) -> str:
        if '_' in module_name:  # submodule
            s = module_name.lower()
            if self.id in {'gcc', 'intel', 'intel-cl'}:
                filename = s.replace('_', '@') + '.smod'
            elif self.id in {'pgi', 'flang'}:
                filename = s.replace('_', '-') + '.mod'
            else:
                filename = s + '.mod'
        else:  # module
            filename = module_name.lower() + '.mod'

        return filename

    def find_library(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                     libtype: LibType = LibType.PREFER_SHARED, lib_prefix_warning: bool = True) -> T.Optional[T.List[str]]:
        code = 'stop; end program'
        return self._find_library_impl(libname, env, extra_dirs, code, libtype, lib_prefix_warning)

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_arguments(args, env, 'stop; end program')

    def has_multi_link_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_link_arguments(args, env, 'stop; end program')

    def get_options(self) -> 'MutableKeyedOptionDictType':
        return self.update_options(
            super().get_options(),
            self.create_option(coredata.UserComboOption,
                               OptionKey('std', machine=self.for_machine, lang=self.language),
                               'Fortran language standard to use',
                               ['none'],
                               'none'),
        )


class GnuFortranCompiler(GnuCompiler, FortranCompiler):

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 defines: T.Optional[T.Dict[str, str]] = None,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        GnuCompiler.__init__(self, defines)
        default_warn_args = ['-Wall']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic', '-fimplicit-none'],
                          'everything': default_warn_args + ['-Wextra', '-Wpedantic', '-fimplicit-none']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        fortran_stds = ['legacy', 'f95', 'f2003']
        if version_compare(self.version, '>=4.4.0'):
            fortran_stds += ['f2008']
        if version_compare(self.version, '>=8.0.0'):
            fortran_stds += ['f2018']
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none'] + fortran_stds
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        # Disabled until this is fixed:
        # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=62162
        # return ['-cpp', '-MD', '-MQ', outtarget]
        return []

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-J' + path]

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # We need to apply the search prefix here, as these link arguments may
        # be passed to a different compiler with a different set of default
        # search paths, such as when using Clang for C/C++ and gfortran for
        # fortran,
        search_dirs: T.List[str] = []
        for d in self.get_compiler_dirs(env, 'libraries'):
            search_dirs.append(f'-L{d}')
        return search_dirs + ['-lgfortran', '-lm']

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:
        '''
        Derived from mixins/clike.py:has_header, but without C-style usage of
        __has_include which breaks with GCC-Fortran 10:
        https://github.com/mesonbuild/meson/issues/7017
        '''
        code = f'{prefix}\n#include <{hname}>'
        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies, mode=CompileCheckMode.PREPROCESS, disable_cache=disable_cache)


class ElbrusFortranCompiler(ElbrusCompiler, FortranCompiler):
    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 defines: T.Optional[T.Dict[str, str]] = None,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine, is_cross,
                                 info, linker=linker, full_version=full_version)
        ElbrusCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        fortran_stds = ['f95', 'f2003', 'f2008', 'gnu', 'legacy', 'f2008ts']
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none'] + fortran_stds
        return opts

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-J' + path]


class G95FortranCompiler(FortranCompiler):

    LINKER_PREFIX = '-Wl,'
    id = 'g95'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-Wall']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-pedantic'],
                          'everything': default_warn_args + ['-Wextra', '-pedantic']}

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-fmod=' + path]


class SunFortranCompiler(FortranCompiler):

    LINKER_PREFIX = '-Wl,'
    id = 'sun'

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-fpp']

    def get_always_args(self) -> T.List[str]:
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        return []

    def get_module_incdir_args(self) -> T.Tuple[str, ...]:
        return ('-M', )

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-moddir=' + path]

    def openmp_flags(self) -> T.List[str]:
        return ['-xopenmp']


class IntelFortranCompiler(IntelGnuLikeCompiler, FortranCompiler):

    file_suffixes = ('f90', 'f', 'for', 'ftn', 'fpp', )
    id = 'intel'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        # FIXME: Add support for OS X and Windows in detect_fortran_compiler so
        # we are sent the type of compiler
        IntelGnuLikeCompiler.__init__(self)
        default_warn_args = ['-warn', 'general', '-warn', 'truncated_source']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-warn', 'unused'],
                          '3': ['-warn', 'all'],
                          'everything': ['-warn', 'all']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none', 'legacy', 'f95', 'f2003', 'f2008', 'f2018']
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        stds = {'legacy': 'none', 'f95': 'f95', 'f2003': 'f03', 'f2008': 'f08', 'f2018': 'f18'}
        if std.value != 'none':
            args.append('-stand=' + stds[std.value])
        return args

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-cpp', '-EP']

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # TODO: needs default search path added
        return ['-lifcore', '-limf']

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-gen-dep=' + outtarget, '-gen-depformat=make']


class IntelLLVMFortranCompiler(IntelFortranCompiler):

    id = 'intel-llvm'


class IntelClFortranCompiler(IntelVisualStudioLikeCompiler, FortranCompiler):

    file_suffixes = ('f90', 'f', 'for', 'ftn', 'fpp', )
    always_args = ['/nologo']

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo', target: str,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        IntelVisualStudioLikeCompiler.__init__(self, target)

        default_warn_args = ['/warn:general', '/warn:truncated_source']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['/warn:unused'],
                          '3': ['/warn:all'],
                          'everything': ['/warn:all']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none', 'legacy', 'f95', 'f2003', 'f2008', 'f2018']
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        stds = {'legacy': 'none', 'f95': 'f95', 'f2003': 'f03', 'f2008': 'f08', 'f2018': 'f18'}
        if std.value != 'none':
            args.append('/stand:' + stds[std.value])
        return args

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['/module:' + path]


class IntelLLVMClFortranCompiler(IntelClFortranCompiler):

    id = 'intel-llvm-cl'

class PathScaleFortranCompiler(FortranCompiler):

    id = 'pathscale'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-fullwarn']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def openmp_flags(self) -> T.List[str]:
        return ['-mp']


class PGIFortranCompiler(PGICompiler, FortranCompiler):

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        PGICompiler.__init__(self)

        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args + ['-Mdclchk'],
                          'everything': default_warn_args + ['-Mdclchk']}

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # TODO: needs default search path added
        return ['-lpgf90rtl', '-lpgf90', '-lpgf90_rpm1', '-lpgf902',
                '-lpgf90rtl', '-lpgftnrtl', '-lrt']


class NvidiaHPC_FortranCompiler(PGICompiler, FortranCompiler):

    id = 'nvidia_hpc'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        PGICompiler.__init__(self)

        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args + ['-Mdclchk'],
                          'everything': default_warn_args + ['-Mdclchk']}


class FlangFortranCompiler(ClangCompiler, FortranCompiler):

    id = 'flang'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        ClangCompiler.__init__(self, {})
        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # We need to apply the search prefix here, as these link arguments may
        # be passed to a different compiler with a different set of default
        # search paths, such as when using Clang for C/C++ and gfortran for
        # fortran,
        # XXX: Untested....
        search_dirs: T.List[str] = []
        for d in self.get_compiler_dirs(env, 'libraries'):
            search_dirs.append(f'-L{d}')
        return search_dirs + ['-lflang', '-lpgmath']

class ArmLtdFlangFortranCompiler(FlangFortranCompiler):

    id = 'armltdflang'

class Open64FortranCompiler(FortranCompiler):

    id = 'open64'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-fullwarn']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def openmp_flags(self) -> T.List[str]:
        return ['-mp']


class NAGFortranCompiler(FortranCompiler):

    id = 'nagfor'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        # Warnings are on by default; -w disables (by category):
        self.warn_args = {
            '0': ['-w=all'],
            '1': [],
            '2': [],
            '3': [],
            'everything': [],
        }

    def get_always_args(self) -> T.List[str]:
        return self.get_nagfor_quiet(self.version)

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-mdir', path]

    @staticmethod
    def get_nagfor_quiet(version: str) -> T.List[str]:
        return ['-quiet'] if version_compare(version, '>=7100') else []

    def get_pic_args(self) -> T.List[str]:
        return ['-PIC']

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-fpp']

    def get_std_exe_link_args(self) -> T.List[str]:
        return self.get_always_args()

    def openmp_flags(self) -> T.List[str]:
        return ['-openmp']
```