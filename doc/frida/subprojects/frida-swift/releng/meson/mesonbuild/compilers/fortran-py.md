Response:
Let's break down the thought process for analyzing the Python code and generating the response.

**1. Understanding the Goal:**

The primary goal is to analyze a Python file (`fortran.py`) within the Frida project and describe its functionalities, relate them to reverse engineering (if applicable), discuss any low-level/kernel/framework aspects, identify logical reasoning, and pinpoint potential user errors. Crucially, the request also asks for how a user might end up interacting with this code (debugging context).

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the imports and class definitions. This immediately reveals:

* **`frida` context:** The file path itself indicates it's part of the Frida project, specifically related to Swift and its build system (Meson).
* **Compiler-related:** The imports (`compilers`, `mixins`) and the class names (`FortranCompiler`, `GnuFortranCompiler`, etc.) strongly suggest this file defines how the Meson build system handles Fortran compilation.
* **Inheritance:**  Notice the inheritance patterns: `GnuFortranCompiler` inherits from both `GnuCompiler` and `FortranCompiler`. This suggests a hierarchical structure for defining different Fortran compiler implementations.
* **Configuration:**  The presence of `get_options` and handling of compiler flags (`-std`, `-Wall`, etc.) indicates configuration and customization capabilities.

**3. Dissecting the `FortranCompiler` Base Class:**

This is the core class. Analyze its methods one by one:

* **`__init__`:** Standard constructor, noting it initializes both `Compiler` and `CLikeCompiler` bases.
* **`has_function`:**  The explicit exception thrown here is important. It tells us Fortran compilation testing uses a different approach than C/C++. This is a key functional detail.
* **`_get_basic_compiler_args`:**  Retrieves compiler and linker flags from the Meson configuration.
* **`sanity_check`:**  Verifies the Fortran compiler is working by compiling a simple program. This is a build system fundamental.
* **`get_optimization_args` and `get_debug_args`:**  Standard compiler flags for optimization and debugging.
* **`get_preprocess_only_args`:**  Compiler flag for pre-processing.
* **`get_module_incdir_args` and `get_module_outdir_args`:**  Handle Fortran module paths, a specific feature of the language.
* **`compute_parameters_with_absolute_paths`:**  Ensures paths are correct during the build process.
* **`module_name_to_filename`:**  Translates Fortran module names to their corresponding file names, with compiler-specific variations.
* **`find_library`:**  A standard compiler task, searching for libraries.
* **`has_multi_arguments` and `has_multi_link_arguments`:** Checks if the compiler supports multiple arguments.
* **`get_options`:** Defines the configurable options for the Fortran compiler (like the Fortran standard).

**4. Analyzing Subclasses (e.g., `GnuFortranCompiler`):**

Focus on how these subclasses *extend* or *override* the base class:

* **Specific compiler flags:**  Each subclass often has unique flags (`-J` for GNU, `-fmod` for G95).
* **Standard support:**  The `get_options` method is frequently overridden to list supported Fortran standards for that specific compiler.
* **Library linking:**  Methods like `language_stdlib_only_link_flags` specify the standard libraries to link against.
* **Conditional logic:** Notice the use of `version_compare` to enable features based on the compiler version.

**5. Connecting to Reverse Engineering:**

This is where we need to bridge the gap between the code and reverse engineering principles.

* **Dynamic Instrumentation:** The file path hints at Frida. Frida is a dynamic instrumentation tool. Fortran might be used in applications targeted for instrumentation.
* **Compiler knowledge:** Understanding compiler flags and how they affect the generated code is crucial for reverse engineering. For example, knowing how debug symbols are generated helps with debugging. Optimization flags can make reverse engineering harder.
* **Library dependencies:** Identifying linked libraries is a core part of understanding an application's functionality.

**6. Identifying Low-Level/Kernel/Framework Aspects:**

* **Binary Code Generation:**  Compilers are fundamental to creating executable binaries.
* **Linking:**  Linking involves resolving symbols and creating the final executable.
* **Operating System Differences:**  Compiler flags and library names can differ across Linux, Android, and other platforms. While this specific code doesn't *directly* interact with the kernel, the *output* of the compiler (the binary) will.
* **Framework Dependencies:** While not explicitly in the *code*, the *purpose* of compiling Fortran code is often to create applications that *use* system libraries and frameworks.

**7. Logical Reasoning (Hypothetical Input/Output):**

Think about how different inputs to the configuration options or build process would affect the compiler commands generated.

* **Example:**  If the user selects `-std=f95`, the `get_option_compile_args` method in `GnuFortranCompiler` will add `-std=f95` to the compiler command.

**8. Identifying User Errors:**

Consider common mistakes users make when setting up build systems or compiling code:

* **Incorrect compiler installation:** If the Fortran compiler isn't installed or configured correctly, the sanity check will fail.
* **Invalid standard selection:** Choosing a Fortran standard not supported by the compiler will lead to errors.
* **Missing libraries:** If a required library isn't found, the linking stage will fail.
* **Incorrect path settings:**  Problems with include or library paths.

**9. Tracing User Interaction (Debugging Context):**

Imagine a developer using Frida to build a project that includes Fortran code. Think about the steps involved:

* **Setting up the build environment:** Installing Meson, the Fortran compiler, etc.
* **Running Meson:** Meson will detect the Fortran compiler. This is where the code in this file gets invoked.
* **Configuration:** The user might specify compiler options (like the Fortran standard) through Meson's configuration.
* **Compilation:** Meson will use the functions in this file to generate the correct compiler commands.
* **Debugging:** If there are build errors, the developer might need to inspect the generated commands or the Meson log files.

**10. Structuring the Response:**

Organize the findings into logical sections based on the prompt's requirements. Use clear headings and bullet points for readability. Provide concrete examples where possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This is just about compiling Fortran."
* **Correction:** "No, it's about how *Meson* handles Fortran compilation, which is part of the *build process* for a larger project (like one that Frida might target)."
* **Initial thought:** "Reverse engineering isn't directly mentioned."
* **Correction:** "While not explicitly in the code, the *purpose* of compilation is to create binaries that are often the target of reverse engineering. Understanding compiler behavior is a key skill for reverse engineers."

By following these steps, systematically analyzing the code, and connecting the technical details to the broader context of build systems, compilers, and reverse engineering, we can generate a comprehensive and accurate response.
这个文件 `fortran.py` 是 Frida 动态 instrumentation 工具中 Meson 构建系统用于处理 Fortran 语言编译器的模块。它的主要功能是定义和管理各种 Fortran 编译器的行为和特性，以便 Meson 能够正确地配置和使用它们来构建项目。

以下是其功能的详细列表：

**1. 定义 Fortran 编译器的抽象基类 `FortranCompiler`:**

*   **提供 Fortran 语言的基础支持:**  声明了 `language = 'fortran'`，表明处理的是 Fortran 语言。
*   **初始化编译器信息:**  `__init__` 方法接收可执行文件路径、版本号、目标机器信息等，用于初始化编译器的基本属性。
*   **禁止 `has_function` 能力:** Fortran 不像 C/C++ 那样方便地测试函数是否存在，因此该方法抛出异常，并建议使用 `links` 方法来测试编译器能力。
*   **获取基本的编译和链接参数:** `_get_basic_compiler_args` 方法用于获取从 Meson 配置中读取的通用编译和链接参数。
*   **实现 Sanity Check:** `sanity_check` 方法编译一个简单的 Fortran 程序来验证编译器是否正常工作。
*   **获取优化和调试参数:**  `get_optimization_args` 和 `get_debug_args` 方法分别返回不同优化级别和调试模式下的编译器参数。
*   **获取预处理参数:** `get_preprocess_only_args` 返回只进行预处理的编译器参数。
*   **处理模块 (Module) 路径:** `get_module_incdir_args` 和 `get_module_outdir_args`  用于指定 Fortran 模块的包含和输出路径。
*   **计算绝对路径:** `compute_parameters_with_absolute_paths` 将相对路径转换为绝对路径。
*   **模块名到文件名转换:** `module_name_to_filename`  根据编译器类型将 Fortran 模块名转换为对应的文件名（例如，`.mod`, `.smod`）。
*   **查找库文件:** `find_library` 方法用于查找指定的 Fortran 库。
*   **检查是否支持多参数:** `has_multi_arguments` 和 `has_multi_link_arguments` 用于检查编译器是否支持一次传递多个参数。
*   **获取编译器选项:** `get_options` 方法返回可配置的编译器选项，例如 Fortran 标准。

**2. 定义各种具体 Fortran 编译器的子类:**

*   **`GnuFortranCompiler` (gfortran):**  GNU Fortran 编译器的实现，继承自 `GnuCompiler` 和 `FortranCompiler`，提供了特定于 gfortran 的警告选项、标准支持等。
*   **`ElbrusFortranCompiler`:** Elbrus 编译器的实现。
*   **`G95FortranCompiler`:** G95 编译器的实现。
*   **`SunFortranCompiler`:** Sun Studio Fortran 编译器的实现。
*   **`IntelFortranCompiler` (ifort):** Intel Fortran 编译器的实现，继承自 `IntelGnuLikeCompiler` 和 `FortranCompiler`。
*   **`IntelLLVMFortranCompiler`:** 基于 LLVM 的 Intel Fortran 编译器的实现。
*   **`IntelClFortranCompiler` (ifort on Windows):**  使用 Visual Studio 风格命令行参数的 Intel Fortran 编译器的实现，继承自 `IntelVisualStudioLikeCompiler`。
*   **`IntelLLVMClFortranCompiler`:** 基于 LLVM 的使用 Visual Studio 风格命令行参数的 Intel Fortran 编译器。
*   **`PathScaleFortranCompiler`:** PathScale 编译器的实现。
*   **`PGIFortranCompiler` (pgfortran):** PGI (现 NVIDIA HPC SDK) Fortran 编译器的实现，继承自 `PGICompiler`。
*   **`NvidiaHPC_FortranCompiler`:** NVIDIA HPC SDK Fortran 编译器的实现。
*   **`FlangFortranCompiler`:** LLVM Flang 编译器的实现，继承自 `ClangCompiler`。
*   **`ArmLtdFlangFortranCompiler`:** Arm 提供的 Flang 编译器的实现。
*   **`Open64FortranCompiler`:** Open64 编译器的实现。
*   **`NAGFortranCompiler` (nagfor):** NAG Fortran 编译器的实现。

这些子类根据特定编译器的特性，重写或扩展了基类的方法，例如定义不同的警告级别、支持的 Fortran 标准、模块路径参数等。

**与逆向方法的关系：**

这个文件本身并不直接涉及逆向工程的具体操作，但它对于理解和操作基于 Fortran 构建的软件至关重要。在逆向工程中，了解目标软件是如何编译和链接的，可以帮助逆向工程师：

*   **理解代码结构:** Fortran 的模块化特性会影响代码的组织方式。`module_name_to_filename` 等方法揭示了模块和文件之间的对应关系。
*   **识别编译器特性:** 不同的编译器对代码的解释和优化不同，了解目标软件使用的编译器及其版本，可以帮助理解其行为。例如，某些编译器有特定的内联或优化策略。
*   **分析符号信息:** 调试参数 (`get_debug_args`) 的设置会影响生成的调试信息，这对于逆向工程中的符号分析至关重要。
*   **理解库依赖:** `find_library` 和 `language_stdlib_only_link_flags`  揭示了软件依赖的 Fortran 运行时库，这有助于分析软件的外部依赖。

**举例说明：**

假设一个逆向工程师正在分析一个使用 gfortran 编译的程序。通过理解 `GnuFortranCompiler` 类的实现，他们可以知道：

*   **假设输入:**  目标程序使用了 Fortran 2008 标准。
*   **逻辑推理:** Meson 会调用 `GnuFortranCompiler` 的 `get_option_compile_args` 方法，并将 `-std=f2008` 添加到编译命令中。
*   **逆向意义:** 逆向工程师在分析二进制代码时，如果发现程序使用了 Fortran 2008 的特性（例如 `block` 结构），就可以推断出编译时可能使用了 `-std=f2008` 参数，从而更好地理解代码的意图。

**涉及到二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层:** 这个文件最终目的是生成可以被编译器使用的命令行参数，这些参数直接影响生成的二进制代码的结构、性能和调试信息。例如，优化参数会改变指令的生成方式。
*   **Linux/Android:** 虽然代码本身是平台无关的 Python，但它处理的 Fortran 编译器通常是特定于操作系统的。例如，gfortran 是 Linux 上的常见 Fortran 编译器。在 Android 上，可以使用 NDK 中的 Fortran 编译器。
*   **内核及框架:**  该文件生成的编译器配置会影响程序链接的库。Fortran 程序可能依赖于特定的数学库、并行计算库等，这些库可能与操作系统内核或特定框架有关。例如，OpenMP 相关的编译选项会影响程序如何利用多核处理器。

**举例说明：**

*   **二进制底层:**  `get_optimization_args` 方法根据优化级别返回不同的编译器参数，例如 `-O2` 或 `-O3`。这些参数会直接影响生成的机器码的效率和大小。
*   **Linux:** `GnuFortranCompiler` 的 `language_stdlib_only_link_flags` 方法会添加 `-lgfortran` 和 `-lm` 等链接参数，这些是 Linux 系统上 gfortran 运行时库和数学库的名称。
*   **Android:**  如果 Frida 被用于 Android 平台上，Meson 会检测 Android NDK 中提供的 Fortran 编译器，并使用相应的配置。

**逻辑推理的例子：**

*   **假设输入:** 用户在 `meson_options.txt` 中设置了 `fortran_std` 选项为 `f95`。
*   **逻辑推理:**  当 Meson 配置项目时，会调用 `GnuFortranCompiler` 的 `get_option_compile_args` 方法，该方法会读取 `fortran_std` 的值，并生成编译器参数 `-std=f95`。
*   **输出:**  最终传递给 gfortran 编译器的命令会包含 `-std=f95`。

**涉及用户或编程常见的使用错误：**

*   **编译器未安装或路径错误:** 如果用户没有安装 Fortran 编译器或 Meson 无法找到编译器可执行文件，`sanity_check` 方法将会失败，导致构建过程终止。
*   **选择了不支持的 Fortran 标准:** 用户可能在 Meson 的配置中选择了编译器不支持的 Fortran 标准（例如，gfortran 低版本选择了 `f2018`）。这会导致编译器报错。
    *   **举例说明:**  用户在 `meson_options.txt` 中设置 `fortran_std = f2018`，但使用的 gfortran 版本低于 8.0.0，`GnuFortranCompiler` 的 `get_option_compile_args` 会生成 `-std=f2018`，但 gfortran 会报错，提示不支持该标准。
*   **链接库错误:**  用户可能依赖了某些 Fortran 库，但没有正确配置库的搜索路径或链接参数。
    *   **举例说明:** 用户使用了需要链接 BLAS 库的 Fortran 代码，但没有在 Meson 配置中指定 BLAS 库的路径，链接器将无法找到该库，导致链接失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试使用 Frida 构建一个包含 Fortran 代码的项目。** 该项目使用了 Meson 作为构建系统。
2. **Meson 开始配置构建环境。** 在配置过程中，Meson 会检测系统中可用的 Fortran 编译器。
3. **Meson 调用相应的 Fortran 编译器类进行初始化。** 例如，如果检测到 gfortran，就会创建 `GnuFortranCompiler` 的实例。
4. **Meson 获取编译器的信息。**  例如，通过运行 `gfortran --version` 获取版本号。
5. **Meson 读取用户的配置选项。** 例如，从 `meson_options.txt` 或命令行参数中读取 `fortran_std` 的值。
6. **Meson 调用编译器类的方法生成编译和链接参数。** 例如，调用 `get_option_compile_args` 获取标准相关的参数，调用 `get_module_outdir_args` 获取模块输出路径。
7. **Meson 使用生成的参数调用 Fortran 编译器进行编译。**
8. **如果编译或链接过程中出现错误，用户可能会检查 Meson 的日志文件。** 日志文件中会包含 Meson 调用的编译器命令，以及编译器的输出信息。
9. **作为调试线索，用户可能会查看 `frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/fortran.py` 文件，**  以了解 Meson 是如何处理 Fortran 编译器的，以及哪些编译器参数被传递给了编译器。
10. **用户可以检查该文件中特定编译器子类的实现，** 例如 `GnuFortranCompiler`，来理解 Meson 是如何处理 gfortran 特有的选项和行为的。

总之，`fortran.py` 文件是 Frida 构建系统中处理 Fortran 编译器的核心组件，它定义了各种 Fortran 编译器的行为，并为 Meson 提供了必要的接口来配置和使用这些编译器构建项目。理解这个文件对于调试 Fortran 相关的构建问题，以及进行与 Fortran 软件相关的逆向工程都有一定的帮助。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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