Response:
Let's break down the thought process for analyzing the provided Python code.

**1. Understanding the Request:**

The core request is to analyze a specific Python file (`fortran.py`) within the Frida project, focusing on its functionality, relationship to reverse engineering, interaction with low-level systems (kernel, etc.), logical reasoning, potential user errors, and debugging context.

**2. Initial Code Scan and Purpose Identification:**

The first step is to quickly read through the code, identifying key classes, functions, and imports. The filename itself suggests this file deals with Fortran compilers. The imports from `mesonbuild` strongly indicate this is part of the Meson build system. The class `FortranCompiler` and its subclasses confirm this. The primary purpose of this file is to define how Meson interacts with different Fortran compilers (GNU Fortran, Intel Fortran, etc.). It encapsulates compiler-specific logic.

**3. Functionality Breakdown (Instruction 1):**

Go through each class and significant method, summarizing its purpose. For `FortranCompiler`:
    * `__init__`: Basic initialization, inheriting from `Compiler` and `CLikeCompiler`.
    * `has_function`: Explicitly states Fortran doesn't have this in the C sense. Suggests alternatives.
    * `_get_basic_compiler_args`: Retrieves compiler and linker flags from Meson's configuration.
    * `sanity_check`: Compiles a simple Fortran program to verify the compiler works.
    * `get_optimization_args`, `get_debug_args`, `get_preprocess_only_args`: Return compiler-specific flags for these operations.
    * `get_module_incdir_args`, `get_module_outdir_args`:  Handle Fortran module compilation.
    * `compute_parameters_with_absolute_paths`:  Makes include/library paths absolute.
    * `module_name_to_filename`:  Converts Fortran module names to filenames.
    * `find_library`: Locates Fortran libraries.
    * `has_multi_arguments`, `has_multi_link_arguments`: Checks if the compiler supports multiple arguments.
    * `get_options`: Defines compiler-specific options (like Fortran standard).

Then, analyze the subclasses, noting their inheritance and any overridden or new methods. Focus on what makes each compiler class distinct (e.g., GNU Fortran's `-std` options, Intel's module handling, etc.).

**4. Relationship to Reverse Engineering (Instruction 2):**

Think about how a build system and compilers relate to the final executable that a reverse engineer might analyze. Compilers generate the binary code. Understanding compiler flags (optimization, debugging symbols) is crucial for reverse engineering.

* **Optimization:**  `get_optimization_args` directly impacts the difficulty of reverse engineering. Higher optimization makes code harder to follow.
* **Debugging Symbols:** `get_debug_args` controls the inclusion of debugging information, which is vital for dynamic analysis during reverse engineering.
* **Code Structure:** Fortran modules and their handling (in `get_module_outdir_args` and `module_name_to_filename`) affect the organization of the compiled code, which a reverse engineer needs to understand.
* **Standard Library Linking:** `language_stdlib_only_link_flags` shows how standard Fortran libraries are linked, which are common components a reverse engineer will encounter.

**5. Low-Level, Kernel, and Framework Knowledge (Instruction 3):**

Consider where the compiler interacts with the underlying system.

* **Binary Generation:** Compilers are the primary tools for creating binary executables.
* **Operating System/Kernel Interaction:**  While this code doesn't directly touch kernel code, the *output* of the compiler (the binary) will interact with the OS kernel for execution, memory management, etc. The linker, which this code interacts with, is crucial for resolving dependencies against system libraries.
* **Android Connection (Indirect):**  While this specific file isn't Android-specific, Frida *does* target Android. The build system (Meson) ensures that the Fortran code, if used in a Frida component, is compiled correctly for the target Android environment. Cross-compilation (indicated by `is_cross`) is relevant here.

**6. Logical Reasoning (Instruction 4):**

Look for conditional logic or methods that transform input.

* **`module_name_to_filename`:**  This method clearly transforms a module name based on compiler ID. Provide examples of input and output for different compilers.
* **`get_option_compile_args`:** This method maps the "std" option to compiler-specific flags. Show how different standard choices result in different compiler arguments.

**7. User/Programming Errors (Instruction 5):**

Think about common mistakes when using a build system or working with compilers.

* **Incorrect Standard:**  Specifying an unsupported Fortran standard via the "std" option.
* **Missing Libraries:**  Failing to provide necessary library paths or names, leading to linking errors. The `find_library` method is relevant here, as it tries to locate libraries.
* **Incorrect Compiler Choice:**  Forcing the use of a specific compiler that isn't installed or doesn't support the required features.

**8. User Operation and Debugging (Instruction 6):**

Trace back how a user might end up interacting with this code.

* **Meson Configuration:** The user runs `meson setup` or `meson configure`. Meson needs to determine the Fortran compiler.
* **Compiler Detection:** Meson executes the Fortran compiler to get its version and identify its type (GNU, Intel, etc.).
* **Compiler Class Instantiation:** Based on the detected compiler, Meson instantiates the appropriate class from this file (e.g., `GnuFortranCompiler`).
* **Build Process:** During compilation, Meson uses the methods in these classes to generate the correct compiler commands.
* **Debugging Scenario:** If compilation fails, a developer might inspect the generated build files or the Meson log. Knowing that the logic for handling Fortran compilers resides in this file helps pinpoint the source of the issue.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Focus heavily on reverse engineering tools.
* **Correction:**  Shift focus to *how* the compiler affects the *output* that is reverse engineered. The code itself is build system logic, not a reverse engineering tool.
* **Initial thought:**  Assume direct kernel interaction.
* **Correction:** Recognize that the interaction is indirect – the compiler produces binaries that interact with the kernel. The focus here is on the compiler's role in *preparing* that binary.
* **Ensure examples are concrete:**  Instead of just saying "optimization flags," give examples like `-O2` or `-O3`.

By following this structured approach, combining code reading with contextual knowledge (of build systems, compilers, and reverse engineering concepts), we can arrive at a comprehensive analysis like the example provided in the initial prompt.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/fortran.py` 这个文件。

**文件功能概述**

这个 Python 文件是 Frida 项目中 Meson 构建系统的一部分，专门用于处理 Fortran 语言的编译。它的主要功能是：

1. **定义了 Fortran 编译器的抽象基类 `FortranCompiler`:**  这个类包含了所有 Fortran 编译器通用的行为和属性。
2. **实现了针对不同 Fortran 编译器的具体子类:**  例如 `GnuFortranCompiler` (GNU gfortran), `IntelFortranCompiler` (Intel ifort/ifx), `ClangCompiler` (Flang) 等。每个子类都根据特定编译器的特性实现了编译、链接、选项处理等方法。
3. **提供了获取编译器参数的方法:**  例如获取优化级别参数 (`get_optimization_args`)、调试信息参数 (`get_debug_args`)、预处理参数 (`get_preprocess_only_args`) 等。
4. **处理 Fortran 模块的编译:**  定义了如何指定模块包含目录 (`get_module_incdir_args`) 和输出目录 (`get_module_outdir_args`)，以及如何将模块名称转换为文件名 (`module_name_to_filename`)。
5. **实现了基本的编译器功能检查:**  例如 `sanity_check` 用于验证编译器是否能够正常工作，`has_function` (虽然 Fortran 不适用，但提供了替代方案)。
6. **管理编译器特定的选项:**  例如通过 `get_options` 方法定义了不同编译器支持的 Fortran 标准 (`-std`)。
7. **处理链接库:** 提供了 `find_library` 方法来查找 Fortran 库。

**与逆向方法的关系及举例说明**

这个文件本身并不是一个逆向工具，但它直接参与了生成被逆向的二进制文件的过程。理解编译器的行为对于逆向分析至关重要。

* **优化选项的影响:**  `get_optimization_args` 方法控制编译器应用的优化级别。高优化级别 (例如 `-O2`, `-O3`) 会导致代码结构复杂化，例如函数内联、循环展开、指令重排等，这使得逆向分析变得更加困难。
    * **举例:**  假设 Frida 使用 gfortran 编译，设置了优化级别为 `3`。`GnuFortranCompiler` 的 `get_optimization_args('3')` 可能会返回 `['-O3']`。逆向工程师在分析由此编译出的二进制文件时，会发现代码结构高度优化，难以直接对应到源代码。
* **调试符号的包含:** `get_debug_args` 方法控制是否生成调试符号。包含调试符号 (例如 `-g`) 会在二进制文件中留下符号表和行号信息，极大地帮助逆向工程师进行调试和理解代码。
    * **举例:** 如果 Frida 编译时设置了调试模式，`GnuFortranCompiler` 的 `get_debug_args(True)` 可能会返回 `['-g']`。逆向工程师可以使用 GDB 或其他调试器加载这个二进制文件，并能够设置断点、查看变量值等。
* **模块化编译:** Fortran 的模块化特性影响了编译单元和链接方式。`get_module_outdir_args` 和 `module_name_to_filename` 决定了模块文件的生成和查找方式。逆向工程师需要理解这种模块化结构才能正确分析程序的不同部分。
    * **举例:**  如果一个 Fortran 程序使用了名为 `my_module` 的模块，gfortran 可能会生成名为 `my_module.mod` 或 `my@module.smod` 的文件（取决于编译器版本）。逆向工程师需要知道这些模块文件可能包含重要的类型信息和接口定义。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

这个文件虽然是构建系统的一部分，但其最终目的是生成在特定平台上运行的二进制代码，因此涉及到一些底层知识：

* **二进制文件的生成:**  编译器将 Fortran 源代码转换为机器码，生成可执行文件或库文件。这个过程涉及到目标平台的指令集架构 (例如 x86, ARM)。
* **链接过程:**  编译器需要调用链接器将编译生成的对象文件和库文件链接在一起。`language_stdlib_only_link_flags` 方法提供了链接标准库所需的参数。在 Linux 和 Android 上，这通常涉及到链接 `libc` (C 标准库) 以及 Fortran 特有的运行时库 (例如 `libgfortran`)。
    * **举例 (Linux):** `GnuFortranCompiler` 的 `language_stdlib_only_link_flags` 方法可能会返回 `['-L<搜索路径>', '-lgfortran', '-lm']`。这意味着链接器需要搜索指定的路径，并链接 `libgfortran.so` (Fortran 运行时库) 和 `libm.so` (数学库)。
    * **举例 (Android):**  虽然这个文件本身没有直接的 Android 特有代码，但 Meson 构建系统会根据目标平台（Android）配置编译器和链接器，确保生成的二进制文件能在 Android 上运行。这可能涉及到使用 Android NDK 提供的编译器和链接器，以及链接 Android 特有的库。
* **操作系统接口:**  最终生成的二进制文件会通过系统调用与操作系统内核进行交互，例如进行文件操作、网络通信、内存管理等。编译器需要确保生成的代码能够正确地调用这些系统调用。
* **框架知识 (间接):**  Frida 是一个动态插桩框架，它允许在运行时修改进程的行为。这个 Fortran 编译器配置文件是 Frida 构建过程的一部分，确保了 Frida 的 Fortran 组件能够被正确编译。这间接涉及到 Frida 框架的构建和运行机制。

**逻辑推理及假设输入与输出**

许多方法都包含逻辑推理，例如根据编译器 ID 选择不同的参数或文件名后缀。

* **`module_name_to_filename` 方法:**
    * **假设输入:**  模块名 "my_module"，编译器 ID "gcc"
    * **输出:** "my_module.mod"
    * **假设输入:**  模块名 "sub_mod"，编译器 ID "intel"
    * **输出:** "sub@mod.smod"
    * **假设输入:**  模块名 "another_sub_module"，编译器 ID "pgi"
    * **输出:** "another-sub-module.mod"

* **`get_option_compile_args` 方法 (针对 `GnuFortranCompiler`):**
    * **假设输入:**  `options` 字典中 `std` 的值为 "f2008"
    * **输出:** `['-std=f2008']`
    * **假设输入:**  `options` 字典中 `std` 的值为 "none"
    * **输出:** `[]`

**用户或编程常见的使用错误及举例说明**

* **指定了不支持的 Fortran 标准:** 用户可能在 Meson 的配置文件中指定了某个 Fortran 编译器不支持的标准。
    * **举例:**  用户在使用较旧版本的 gfortran 时，设置了 `fortran_std: 'f2018'`。`GnuFortranCompiler` 的 `get_options` 方法会限制 `std` 的选项，如果用户指定的标准不在列表中，Meson 会报错。
* **模块依赖问题:**  如果 Fortran 代码中使用了模块，但编译时没有正确设置模块的包含路径，会导致编译错误。
    * **举例:** 用户在 `meson.build` 文件中定义了一个 Fortran目标，依赖于另一个模块，但没有使用 `include_directories` 或其他方式告知编译器模块文件的位置。编译器会找不到模块定义文件 (`.mod` 或 `.smod`)。
* **链接库错误:**  如果程序依赖于外部 Fortran 库，但没有正确指定库的路径或名称，会导致链接错误。
    * **举例:** 用户在 `meson.build` 中使用了 `link_with` 参数链接一个自定义的 Fortran 库，但库文件不在标准的库搜索路径中，也没有通过 `link_args` 添加库的路径。链接器会报错找不到该库。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户尝试构建 Frida:** 用户通常会从 Frida 的源代码仓库克隆代码，并尝试使用 Meson 构建系统进行构建。
   ```bash
   git clone https://github.com/frida/frida.git
   cd frida
   mkdir build
   cd build
   meson setup ..
   meson compile
   ```
2. **Meson 执行配置:** 当用户运行 `meson setup ..` 时，Meson 会检测系统环境，包括已安装的编译器。
3. **Fortran 编译器检测:** Meson 会尝试找到系统中的 Fortran 编译器 (例如 gfortran, ifort)。它可能会执行编译器命令 (例如 `gfortran --version`) 来获取版本信息和识别编译器类型。
4. **加载 Fortran 编译器模块:**  Meson 根据检测到的 Fortran 编译器的类型，加载 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/fortran.py` 文件，并实例化相应的编译器类 (例如 `GnuFortranCompiler`)。
5. **处理构建指令:**  当 `meson compile` 运行后，Meson 会读取 `meson.build` 文件中的构建指令，如果涉及到 Fortran 代码的编译，Meson 会调用 `fortran.py` 中相应编译器类的方法来生成编译命令。
6. **编译 Fortran 代码:**  例如，如果 `meson.build` 中定义了一个 Fortran 可执行文件或库，Meson 会调用 `GnuFortranCompiler.compile()` 或类似的方法，该方法会使用 `get_option_compile_args`、`get_debug_args` 等方法获取编译参数，并执行实际的 Fortran 编译器命令。
7. **链接 Fortran 代码:**  类似地，链接 Fortran 代码时，Meson 会调用 `language_stdlib_only_link_flags` 等方法获取链接参数，并执行链接器命令。

**作为调试线索:**

如果 Frida 的 Fortran 组件在构建过程中出现问题，例如编译错误或链接错误，开发者可以：

* **查看 Meson 的日志:** Meson 会记录详细的构建过程，包括执行的编译器命令。开发者可以查看日志，了解具体的编译参数和错误信息。
* **检查 `meson_options.txt` 或 `meson.build` 文件:**  查看是否配置了不兼容的 Fortran 选项或错误的依赖关系。
* **断点调试 `fortran.py`:**  如果怀疑是 Meson 对 Fortran 编译器的处理有问题，开发者可以在 `fortran.py` 文件中添加断点，例如在 `get_option_compile_args` 或 `language_stdlib_only_link_flags` 方法中，来检查 Meson 生成的编译器参数是否正确。
* **手动执行编译器命令:**  从 Meson 的日志中复制编译器命令，然后在命令行中手动执行，以便更精细地调试编译过程。

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/fortran.py` 文件是 Frida 项目构建系统的核心组成部分，负责处理 Fortran 代码的编译和链接。理解其功能和实现细节对于理解 Frida 的构建过程以及调试相关的构建问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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