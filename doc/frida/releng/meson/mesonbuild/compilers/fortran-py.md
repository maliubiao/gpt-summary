Response:
Let's break down the thought process for analyzing this Python code and addressing the prompt's specific requirements.

**1. Understanding the Goal:**

The core request is to analyze the given Python code, which is a part of the Meson build system related to Fortran compiler handling. The analysis should focus on its functionality, its relevance to reverse engineering, its interaction with low-level concepts (kernels, frameworks), its logical reasoning, potential user errors, and how a user might reach this code.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of what it does. Keywords like `Compiler`, `FortranCompiler`, `GnuFortranCompiler`, and compiler-specific names (Intel, PGI, Flang, etc.) immediately suggest that this code is about managing different Fortran compilers within the Meson build system. The presence of methods like `sanity_check`, `get_optimization_args`, `get_debug_args`, `find_library`, `has_header`, and `links` confirms this.

**3. Deconstructing Functionality - Method by Method:**

A more detailed analysis involves examining each method within the `FortranCompiler` class and its subclasses. The key is to understand *what* each method does. For example:

* `__init__`:  Initializes the compiler object, storing the executable path, version, target machine, etc.
* `has_function`: Explicitly states that Fortran doesn't have this capability in the same way C does. It suggests an alternative approach using `links`.
* `_get_basic_compiler_args`: Retrieves default compiler and linker flags.
* `sanity_check`:  Performs a basic compilation test to verify the compiler is working.
* `get_optimization_args`, `get_debug_args`:  Return compiler flags for optimization and debugging.
* `get_preprocess_only_args`:  Returns flags for preprocessing only.
* `get_module_incdir_args`, `get_module_outdir_args`: Handle Fortran module paths.
* `compute_parameters_with_absolute_paths`:  Ensures paths are absolute, important for build systems.
* `module_name_to_filename`: Converts Fortran module names to filenames.
* `find_library`:  Searches for libraries.
* `has_multi_arguments`, `has_multi_link_arguments`: Checks for compiler support for multiple arguments.
* `get_options`: Defines configurable options for the Fortran compiler.

For subclasses like `GnuFortranCompiler`, `IntelFortranCompiler`, etc., we look for specific behavior or overrides related to those compilers (e.g., standard flags, module output, library linking).

**4. Identifying Connections to Reverse Engineering:**

This requires thinking about how compiler behavior relates to understanding compiled code. Key areas to consider:

* **Optimization:** How optimization flags (`-O1`, `-O2`, etc.) affect the resulting binary and the difficulty of reverse engineering.
* **Debugging Symbols:** How debug flags (`-g`) include debugging information that is crucial for reverse engineering.
* **Preprocessing:** Understanding preprocessing directives is sometimes necessary when analyzing obfuscated or complex code.
* **Linking:** Knowing how libraries are linked helps in understanding dependencies and potential vulnerabilities.
* **Standard Library Linking:**  Understanding the default libraries linked (like `libgfortran`) is important for analyzing function calls and dependencies.

**5. Identifying Connections to Low-Level Concepts:**

This involves recognizing elements related to the operating system, kernel, and frameworks:

* **Binary Executables:** Compilers produce binary executables. The code manages the tools that create these binaries.
* **Linux/Android Kernels (Indirectly):**  While the code doesn't directly interact with the kernel, the *output* of the compiler (the compiled binary) will run on these kernels. The compiler needs to produce code compatible with the target OS.
* **Frameworks (Indirectly):**  Similar to the kernel, the compiler needs to produce code that can interact with system frameworks and libraries.
* **Dynamic Linking:** The `DynamicLinker` parameter hints at the management of dynamically linked libraries.

**6. Logical Reasoning and Examples:**

For methods that involve logic, try to create simple "if-then" scenarios:

* **`module_name_to_filename`:** If the module name is `my_module`, the output for GCC would be `my_module.mod`. If it's `sub_module_of_mine`, it becomes `sub@module@of@mine.smod`.
* **`compute_parameters_with_absolute_paths`:** If the input is `['-I../include', '-L/lib']` and the build directory is `/home/user/build`, the output for the `-I` flag would be `'-I/home/user/build/../include'`.

**7. User Errors:**

Think about common mistakes users might make when interacting with a build system:

* **Incorrect Standard:**  Specifying an unsupported Fortran standard.
* **Missing Libraries:** Trying to link against a library that doesn't exist or isn't in the search path.
* **Incorrect Flags:** Using compiler flags that are not supported or have unintended consequences.

**8. Tracing User Operations (Debugging Clues):**

Consider how a user might end up triggering this specific code:

* **Running Meson:** The user would execute the `meson` command to configure their build.
* **Project Configuration:** The `meson.build` file would specify Fortran as a language.
* **Compiler Detection:** Meson would attempt to find a Fortran compiler on the system.
* **Compiler Class Instantiation:**  Based on the detected compiler (gfortran, ifort, etc.), the corresponding class (e.g., `GnuFortranCompiler`) would be instantiated.
* **Compilation/Linking:** When source files need to be compiled or linked, methods from these compiler classes would be called.
* **Option Handling:** If the user sets specific Fortran compiler options, the `get_options` and `get_option_compile_args` methods would be involved.

**9. Structuring the Output:**

Finally, organize the findings according to the prompt's requirements:

* **Functionality:** Describe what the code does in general and then detail the purpose of specific methods.
* **Reverse Engineering:** Explain the connections between compiler behavior and reverse engineering challenges/techniques. Provide concrete examples.
* **Low-Level Concepts:** Explain how the code relates to binary code, operating systems, kernels, and frameworks. Provide examples.
* **Logical Reasoning:** Present clear "if-then" examples illustrating the logic within certain methods.
* **User Errors:** Give specific examples of common user mistakes and how this code might be involved.
* **User Operations (Debugging):** Outline the steps a user takes that would lead to this code being executed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus too much on the specifics of each compiler. **Correction:**  Need to balance compiler-specific details with the broader functionality of the `FortranCompiler` base class.
* **Initial thought:** Overlook the connection to reverse engineering. **Correction:** Explicitly think about how compiler options influence the compiled binary and the reverse engineering process.
* **Initial thought:**  Not enough concrete examples. **Correction:** For logical reasoning and user errors, provide specific input and output scenarios.

By following these steps, systematically analyzing the code, and considering the specific requirements of the prompt, a comprehensive and accurate response can be generated.
好的，让我们来详细分析一下 `frida/releng/meson/mesonbuild/compilers/fortran.py` 这个文件。

**文件功能概述**

这个 Python 文件是 Frida 动态 instrumentation 工具的构建系统 Meson 中用于处理 Fortran 编译器的模块。它的主要功能是：

1. **抽象和管理不同的 Fortran 编译器:**  定义了一个 `FortranCompiler` 基类，并为各种具体的 Fortran 编译器（如 GNU Fortran, Intel Fortran, PGI Fortran 等）提供了子类。这使得 Meson 能够以统一的方式处理不同编译器的特定行为和选项。

2. **提供编译、链接和相关操作的接口:**  定义了用于执行常见编译器操作的方法，例如：
   - `sanity_check`: 检查编译器是否可以正常工作。
   - `compile`: 编译 Fortran 源代码。
   - `link`: 链接目标文件生成可执行文件或库。
   - `get_optimization_args`, `get_debug_args`: 获取优化和调试相关的编译器参数。
   - `get_preprocess_only_args`: 获取仅进行预处理的编译器参数。
   - `get_module_incdir_args`, `get_module_outdir_args`:  处理 Fortran 模块的包含路径和输出路径。
   - `find_library`: 查找指定的库文件。
   - `has_function`: （虽然 Fortran 不适用，但这里提到了替代方案）。
   - `has_header`: 检查是否存在指定的头文件。
   - `has_multi_arguments`, `has_multi_link_arguments`: 检查编译器是否支持一次接受多个参数或链接参数。
   - `get_options`: 定义了用户可以配置的编译器选项。

3. **处理不同 Fortran 编译器的特性和差异:**  不同的 Fortran 编译器有不同的命令行选项、模块处理方式、标准支持等等。这个文件中的子类针对特定编译器进行了定制，以处理这些差异。例如，GNU Fortran 使用 `-J` 来指定模块输出目录，而 Intel Fortran 使用 `-module`。

**与逆向方法的关系及举例说明**

这个文件本身并不直接执行逆向操作，但它所管理的 Fortran 编译器在逆向工程中扮演着重要的角色：

* **编译目标程序:** 逆向工程师经常需要编译他们正在分析的目标程序，以便进行调试、修改或理解其行为。这个文件定义了如何使用 Fortran 编译器来完成这个任务。

* **理解编译选项的影响:**  编译器选项会显著影响生成的可执行文件的结构和行为。例如：
    - **优化级别 (`-O0`, `-O1`, `-O2`, `-O3`):**  较高的优化级别会使代码更难阅读和理解，因为编译器会进行各种转换，例如内联函数、循环展开、指令重排等。逆向工程师可能需要了解不同优化级别的影响，以便选择合适的编译选项进行分析，或者在分析被高度优化的代码时意识到这些转换的存在。
    - **调试信息 (`-g`):**  包含调试信息的编译可以生成包含符号表、行号信息等的数据，这对于使用调试器（如 GDB）进行逆向分析至关重要。这个文件中的 `get_debug_args` 方法就定义了如何启用调试信息的生成。
    - **代码生成选项 (`-fPIC`):**  生成位置无关代码对于创建共享库是必要的。理解这些选项对于分析共享库的加载和链接过程很重要。
    - **标准选择 (`-std=f95`, `-std=f2003`):** 不同的 Fortran 标准会影响语言特性和编译器的行为。逆向工程师可能需要了解目标程序是用哪个标准编译的，以便更好地理解其代码。

**举例说明:**

假设逆向工程师想要分析一个用 Fortran 编写的科学计算程序。他们可能需要：

1. **使用与目标程序相同的 Fortran 编译器进行编译:** 为了最大程度地复现目标程序的行为，最好使用相同的编译器版本和选项进行编译。这个文件确保 Meson 能够正确地调用相应的 Fortran 编译器。
2. **禁用优化进行调试:**  为了更容易地单步执行和理解代码，逆向工程师可能会使用 `-O0` 选项禁用优化。Meson 可以通过其构建配置来传递这些选项，而这个文件定义了如何将这些高级配置转换为特定编译器的命令行参数。
3. **生成包含调试信息的版本:**  使用 `-g` 选项编译程序，以便使用 GDB 等调试器进行分析。`get_debug_args` 方法提供了实现此目的的参数。
4. **分析模块依赖:**  理解 Fortran 模块的依赖关系对于理解程序的结构很重要。这个文件中的 `get_module_incdir_args` 和 `get_module_outdir_args` 方法处理了模块的查找和生成，这在逆向分析中可能需要关注。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

虽然这个 Python 文件本身是在构建系统层面运作，但它所处理的 Fortran 编译器直接生成在底层操作系统上运行的二进制代码。因此，它间接地涉及到以下概念：

* **二进制底层:**
    - **指令集架构 (ISA):**  不同的 Fortran 编译器会针对不同的目标架构（例如 x86, ARM）生成机器码。Meson 需要知道目标架构（通过 `for_machine` 参数传递），以便选择合适的编译器和链接器。
    - **调用约定 (Calling Conventions):**  Fortran 编译器遵循特定的调用约定，以便函数之间正确地传递参数和返回值。逆向工程师在分析汇编代码时需要了解这些约定。
    - **内存布局:** 编译器决定了程序在内存中的布局，包括代码段、数据段、栈和堆的位置。

* **Linux/Android 内核:**
    - **系统调用:**  编译后的 Fortran 程序会通过系统调用与操作系统内核进行交互，例如读写文件、网络通信等。逆向分析可能需要跟踪这些系统调用来理解程序的行为。
    - **进程和线程管理:**  Fortran 程序作为操作系统中的进程运行。理解进程和线程的管理对于分析并发程序很重要。
    - **动态链接:**  Fortran 程序通常会依赖于动态链接库。这个文件中的 `find_library` 方法涉及到查找和链接这些库。

* **Android 框架 (间接):**
    - 如果 Frida 被用于 instrument Android 上的 Fortran 代码，那么这个文件所管理的编译器生成的代码最终会在 Android 运行时环境（如 ART）中执行。理解 Android 框架的某些方面，例如权限模型、组件生命周期等，可能对逆向分析有帮助。

**举例说明:**

* **交叉编译:** 如果 Frida 需要在 Android 上 instrument 运行在 ARM 架构上的 Fortran 代码，那么 Meson 需要使用能够生成 ARM 代码的 Fortran 交叉编译器。这个文件中的 `is_cross` 参数会指示 Meson 正在进行交叉编译。
* **动态链接库依赖:**  一个 Fortran 程序可能依赖于 `libgfortran` (GNU Fortran 运行时库)。这个文件中的 `language_stdlib_only_link_flags` 方法定义了链接这些标准库所需的参数。在逆向分析时，需要关注这些依赖库，因为它们包含了程序运行时所需的关键函数。
* **系统调用跟踪:** 使用 Frida 动态地 instrument 一个编译后的 Fortran 程序，可以拦截其系统调用，例如 `open`, `read`, `write` 等，从而了解程序与操作系统底层的交互。

**逻辑推理及假设输入与输出**

文件中的一些方法包含逻辑推理，例如：

* **`module_name_to_filename`:**  根据编译器 ID 和模块名称来推断模块文件的名称。
    - **假设输入:** `module_name = "my_module"`, `self.id = "gcc"`
    - **输出:** `"mymodule.mod"`
    - **假设输入:** `module_name = "sub_module_of_mine"`, `self.id = "intel"`
    - **输出:** `"sub@module@of@mine.smod"`

* **`compute_parameters_with_absolute_paths`:**  如果参数以 `-I` 或 `-L` 开头，则将其后面的路径转换为绝对路径。
    - **假设输入:** `parameter_list = ["-I../include", "-L/usr/lib"]`, `build_dir = "/home/user/project/build"`
    - **输出:** `["-I/home/user/project/build/../include", "-L/usr/lib"]` (注意：对于已经绝对的路径，不会修改)

* **`get_option_compile_args` (以 `GnuFortranCompiler` 为例):**  根据用户选择的标准选项生成相应的编译器参数。
    - **假设输入:** `options = {"std": "f2008"}`
    - **输出:** `["-std=f2008"]`
    - **假设输入:** `options = {"std": "none"}`
    - **输出:** `[]`

**用户或编程常见的使用错误及举例说明**

* **指定了编译器不支持的 Fortran 标准:**
    - **例子:** 用户在 Meson 的配置文件中设置了 `fortran_std = 'f202x'`，但使用的 gfortran 版本较旧，不支持 Fortran 202x 标准。
    - **结果:**  Meson 可能会报错，或者编译器会发出警告或错误，导致构建失败。

* **尝试使用 `has_function` 方法:**
    - **例子:** 用户在 `meson.build` 文件中尝试使用 `meson.get_compiler('fortran').has_function('my_fortran_function')`。
    - **结果:**  会抛出 `MesonException`，因为 Fortran 不像 C 那样直接支持 `has_function` 这样的特性检查。错误信息会引导用户使用 `links` 方法进行能力测试。

* **模块依赖问题:**
    - **例子:**  一个 Fortran 项目包含多个模块，但模块的包含路径没有正确配置。
    - **结果:**  编译器可能找不到所需的模块文件，导致编译错误。这个文件中的 `get_module_incdir_args` 和 `get_module_outdir_args` 方法的配置不正确会加剧这个问题。

* **链接库错误:**
    - **例子:**  用户尝试链接一个不存在的库，或者库的路径没有正确指定。
    - **结果:**  链接器会报错。这个文件中的 `find_library` 方法用于查找库，但如果库根本不存在或路径错误，则会返回 `None`。

**用户操作是如何一步步的到达这里，作为调试线索**

当用户使用 Frida 时，如果目标进程中包含了 Fortran 代码，并且 Frida 的构建系统需要处理 Fortran 代码的编译和链接，那么就会涉及到这个文件。以下是一个可能的步骤：

1. **用户下载或更新 Frida:**  用户通过 pip 或其他方式安装或更新 Frida。
2. **Frida 构建系统运行:**  当 Frida 需要构建其自身的一部分（例如，在某些情况下可能需要编译一些桥接代码或者辅助工具）时，会运行 Meson 构建系统。
3. **Meson 配置阶段:**  Meson 会读取 `meson.build` 文件，检测系统上可用的编译器。如果检测到 Fortran 编译器，就会创建这个文件中定义的 `FortranCompiler` 或其子类的实例。
4. **用户项目配置 (如果 Frida 作为依赖):** 如果用户自己的项目使用了 Frida，并且他们的项目包含了 Fortran 代码，那么当他们的项目使用 Meson 构建时，也会涉及到这个文件。
5. **编译 Fortran 代码:**  当需要编译 Fortran 源代码时，Meson 会调用 `FortranCompiler` 类中定义的方法，例如 `compile`。这些方法会使用在这个文件中配置的编译器参数。
6. **链接 Fortran 代码:**  当需要链接 Fortran 目标文件时，Meson 会调用 `FortranCompiler` 类中的链接相关方法，例如 `link`。
7. **查找 Fortran 库:** 如果需要链接 Fortran 库，Meson 会调用 `find_library` 方法来查找库文件。
8. **处理编译器选项:** 用户可以通过 Meson 的配置选项来影响 Fortran 编译器的行为。`get_options` 方法定义了哪些选项是可配置的，而 `get_option_compile_args` 等方法会将这些选项转换为具体的编译器命令行参数.

**作为调试线索:**

当 Frida 在处理包含 Fortran 代码的目标时遇到构建问题，可以从以下几个方面入手进行调试，并可能涉及到这个文件：

* **检查使用的 Fortran 编译器:**  查看 Meson 的构建日志，确认使用了哪个 Fortran 编译器（例如 gfortran, ifort）。这个文件中的不同子类对应不同的编译器。
* **查看编译器参数:**  Meson 的构建日志通常会显示传递给编译器的完整命令行。对比这个文件中的方法（如 `get_optimization_args`, `get_debug_args` 等）生成的参数，可以了解构建系统是如何配置编译器的。
* **检查模块和库的查找路径:**  如果出现模块或库找不到的错误，需要检查相关的包含路径和库路径是否正确配置。这个文件中的 `get_module_incdir_args`, `get_module_outdir_args`, 和 `find_library` 方法与此相关。
* **确认 Fortran 标准:**  如果出现与语言标准相关的编译错误，需要确认 Meson 的配置和使用的编译器是否支持所需的 Fortran 标准。`get_options` 方法定义了标准选项。
* **逐步执行 Meson 代码 (如果需要深入分析):**  可以使用 Python 调试器（如 pdb）逐步执行 Meson 的代码，查看 `FortranCompiler` 类的方法是如何被调用的，以及编译器参数是如何生成的。

总而言之，`frida/releng/meson/mesonbuild/compilers/fortran.py` 文件是 Frida 构建系统中处理 Fortran 编译器的核心组件，它抽象了不同编译器的差异，提供了编译和链接的接口，并且间接地影响着最终生成的可执行文件的结构和行为，这对于理解 Frida 如何处理 Fortran 代码以及在遇到问题时进行调试都非常重要。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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