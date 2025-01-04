Response:
The user wants to understand the functionality of a specific Python file within the Frida project. This file seems to define compiler-specific configurations for the Metrowerks compiler family when using the Meson build system.

Here's a breakdown of the thought process to address the user's request:

1. **Understand the Core Function:** The file `metrowerks.py` in `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/mixins` clearly deals with compiler settings. The "mixins" part suggests it's a reusable component to add Metrowerks-specific behavior to a more generic compiler class in Meson. The `SPDX-License-Identifier` and `Copyright` lines confirm it's part of an open-source project.

2. **Identify Key Data Structures:** The file defines several dictionaries (`mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, etc.). These dictionaries map human-readable names (like 'v4', 'generic', '0', 'true') to compiler-specific command-line arguments (like `'-proc', 'v4'`, `'-O0'`, `'-g'`). This is the core mechanism for translating abstract build settings into concrete compiler instructions.

3. **Analyze the `MetrowerksCompiler` Class:** This class inherits from `Compiler` (or a mock for type checking). It defines methods that correspond to common compiler operations:
    * `__init__`:  Initialization, checks for cross-compilation.
    * `depfile_for_object`:  Handles dependency file naming.
    * `get_always_args`, `get_compiler_check_args`, etc.: These methods return lists of compiler flags based on different build options (debugging, optimization, include paths, etc.).

4. **Connect to Reverse Engineering:**  Think about how compiler settings relate to reverse engineering.
    * **Instruction Sets:** The `*_instruction_set_args` dictionaries are crucial. Reverse engineers need to understand the target CPU architecture. Being able to specify the instruction set during compilation is directly relevant to analyzing the resulting binary.
    * **Optimization:**  Optimization levels (`-O0`, `-O1`, etc.) significantly impact the final binary. Optimized code can be harder to reverse engineer due to inlining, register allocation, and other transformations. Debug symbols (`-g`) are also a key factor.
    * **Cross-Compilation:** Frida is often used for dynamic instrumentation on targets different from the host. This file explicitly enforces cross-compilation, which is central to the reverse engineering workflow in such scenarios.

5. **Relate to Binary/Kernel/Framework:**
    * **Instruction Sets (again):** Directly related to the CPU's binary instruction format.
    * **`-proc` flag:** This flag directly targets specific processor architectures, which is low-level binary knowledge.
    * **Cross-compilation:** Necessitates understanding target architectures (potentially Linux, Android, or other embedded systems).
    * **`-nostdinc`, `-nostdlib`:** These flags relate to linking against standard libraries, which are part of the operating system framework (including the kernel).

6. **Consider Logic and Assumptions:** The methods in the `MetrowerksCompiler` class perform logical mapping. For instance, when `is_debug` is `True`, `get_debug_args` returns `['-g']`. This is a simple but important logical step. Think about the inputs (boolean debug flag, optimization level string) and the output (list of compiler arguments).

7. **Identify Potential User Errors:**  Look for constraints or common misunderstandings.
    * **Cross-compilation requirement:** Users might try to use this compiler for native builds, which the code explicitly prevents.
    * **Incorrect instruction set:** Users might choose an instruction set that doesn't match their target hardware.

8. **Trace the User's Path (Debugging):**  Imagine how a developer might end up looking at this file.
    * They might be using Frida and encountering issues with the Metrowerks compiler.
    * They could be working on the Frida build system itself, perhaps adding support for a new compiler or debugging existing support.
    * They might be investigating the Meson build system and how it handles different compilers.

9. **Structure the Answer:** Organize the information clearly, addressing each part of the user's request (functionality, reverse engineering relevance, binary/kernel/framework links, logic, user errors, debugging). Use examples to illustrate the points. Start with a high-level summary and then go into more detail.

By following these steps, we can provide a comprehensive and informative answer to the user's query, explaining the file's purpose and its connections to various technical domains.
这是 Frida 动态 instrumentation 工具中一个名为 `metrowerks.py` 的源代码文件，它位于 `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/mixins` 目录下。这个文件的主要功能是为 Meson 构建系统提供对 **Metrowerks/Freescale Embedded C/C++ 编译器家族** 的特定支持。

让我们分解一下它的功能，并根据你的要求进行说明：

**功能列举:**

1. **定义 Metrowerks 编译器的特定命令行参数:**
   - 该文件定义了多个字典，例如 `mwccarm_instruction_set_args`，`mwcceppc_instruction_set_args`，`mwcc_optimization_args`，`mwcc_debug_args`。
   - 这些字典将抽象的概念（如 ARM 指令集名称 'v4t'，优化级别 '0'，调试开关 True/False）映射到 Metrowerks 编译器实际需要的命令行参数（例如 `['-proc', 'v4t']`，`['-O0']`，`['-g']`）。
   - 这样 Meson 构建系统就可以根据用户配置或内部逻辑选择正确的编译器参数。

2. **提供 `MetrowerksCompiler` 类:**
   - 这个类继承自 Meson 的 `Compiler` 类（或者在类型检查时使用一个模拟），并针对 Metrowerks 编译器进行了定制。
   - 它定义了诸如获取编译、链接、调试、优化等不同阶段所需的编译器参数的方法。
   - 例如，`get_compile_only_args` 返回 `['-c']`，表示只进行编译不链接。`get_debug_args` 根据是否启用调试返回 `['-g']` 或 `[]`。
   - 它还处理了依赖文件生成、预编译头文件 (PCH) 等特定于编译器的任务。

3. **处理平台和架构特定的设置:**
   - 通过 `mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 等字典，该文件能够根据目标架构（ARM, PowerPC 等）和具体的处理器型号生成相应的编译器参数（使用 `-proc` 标志）。

4. **限制为交叉编译:**
   -  `__init__` 方法中检查 `self.is_cross`，如果不是交叉编译，则抛出 `EnvironmentException`。这表明 Frida 对 Metrowerks 编译器的支持主要用于交叉编译场景。

5. **处理 Unix 风格的参数到 Metrowerks 原生参数的转换:**
   - `_unix_args_to_native` 方法尝试将一些通用的 Unix 风格的编译器参数（如 `-D`, `-I`, `-L`）转换为 Metrowerks 编译器能够理解的格式。不过，它目前忽略了 `-Wl,-rpath=` 和 `--print-search-dirs` 等链接器相关的参数，以及库路径 `-L`。

6. **计算绝对路径:**
   - `compute_parameters_with_absolute_paths` 方法用于将包含相对路径的参数（主要是 include 路径 `-I`）转换为绝对路径，确保编译器能够正确找到头文件。

**与逆向方法的关系及举例说明:**

该文件与逆向工程密切相关，因为 Frida 本身就是一个动态 instrumentation 工具，常用于逆向分析、安全研究和漏洞挖掘。Metrowerks 编译器常用于嵌入式系统开发，而嵌入式系统是逆向工程的重要目标。

* **指定目标架构 (Instruction Set):** 逆向工程师在分析二进制文件时，首先需要了解目标处理器的架构和指令集。`mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 允许开发者在编译 Frida Agent 或要注入的目标程序时，精确指定目标处理器的指令集。
   * **例子:** 如果你要在运行于 ARMv7 架构的嵌入式设备上使用 Frida，那么在构建 Frida Agent 时，Meson 构建系统可能会使用 `['-proc', 'v5te']` 或类似的参数，这直接影响了生成的二进制代码，而逆向工程师就需要基于 ARMv5TE 指令集来分析。

* **控制优化级别:** 编译器的优化级别会显著影响生成二进制代码的结构和可读性。
   * **例子:** 使用 `-O0` (对应 `mwcc_optimization_args['0']`) 编译的代码通常更容易阅读和调试，因为它保留了更多的源代码结构。逆向工程师在初步分析时可能会倾向于分析未优化的版本。相反，分析被 `-O2` 或 `-O4,p` 优化的代码则更具挑战性，因为编译器可能会进行函数内联、循环展开等优化，使得代码逻辑更复杂。

* **包含/排除调试信息:** 调试信息对于逆向分析非常有用，因为它包含了符号信息、行号等，可以帮助将二进制代码与源代码关联起来。
   * **例子:** 如果在编译时设置了调试标志 (`-g`, 对应 `mwcc_debug_args[True]`)，生成的二进制文件中会包含调试符号，这使得使用 GDB 等调试器进行动态分析更加容易。逆向工程师可以通过分析这些符号信息来理解程序的结构和功能。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **二进制底层:** `mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 中列出的各种处理器架构名称（如 'v4t', 'arm920t', 'e500'）直接对应于不同的 CPU 架构和二进制指令集。选择正确的指令集对于在目标设备上正确执行代码至关重要。
   * **例子:**  选择 'arm7tdmi' 会导致编译器生成针对 ARM7TDMI 架构的二进制代码，该代码只能在该架构或兼容架构的处理器上运行。理解这些架构的特点和指令集是二进制逆向的基础。

* **交叉编译:**  该文件强制使用交叉编译 (`if not self.is_cross:`)，这在嵌入式开发和 Frida 使用场景中非常常见。交叉编译意味着在一个平台上（例如 x86 Linux）编译出可以在另一个平台（例如 ARM Android 设备）上运行的代码。这需要对目标平台的体系结构、ABI (Application Binary Interface) 有深入的了解。
   * **例子:** 在 x86 Linux 上使用 Metrowerks 编译器为 ARM Android 内核模块编译代码就需要指定 ARM 架构和相应的 ABI。

* **标准库 (`-nostdlib`, `-nostdinc`):**  `get_no_stdlib_link_args` 和 `get_no_stdinc_args` 方法返回的参数 (`-nostdlib`, `-nostdinc`) 用于指示编译器在链接和包含头文件时不要使用标准库。这在构建嵌入式系统或内核级别的代码时很常见，因为这些环境可能不提供完整的标准库，或者需要使用定制的库。
   * **例子:**  开发 Android 内核模块或驱动程序时，通常需要使用 Android 特定的 API 和头文件，而不是标准的 C 库。在这种情况下，使用 `-nostdlib` 和 `-nostdinc` 可以避免链接或包含错误的库。

**逻辑推理及假设输入与输出:**

该文件中的逻辑主要是基于条件判断和字典映射。

* **假设输入:**  Meson 构建系统在处理一个需要使用 Metrowerks 编译器的项目，并且设置了以下选项：
    * 目标架构: 'arm926ej'
    * 优化级别: '2'
    * 启用调试: True
* **输出:**
    * `get_optimization_args('2')` 将返回 `['-O2']`。
    * `get_debug_args(True)` 将返回 `['-g']`。
    * 如果调用一个使用架构信息的方法，例如在编译一个 C 文件时，可能会生成包含 `['-proc', 'arm926ej']` 的命令行参数。

**用户或编程常见的使用错误及举例说明:**

1. **尝试在非交叉编译场景下使用 Metrowerks 编译器:**  正如代码中所示，`__init__` 方法会检查 `self.is_cross`。如果用户尝试在本地编译（例如在运行 Metrowerks 编译器的同一台机器上编译），Meson 会抛出一个异常，因为该文件明确声明只支持交叉编译。

   * **错误场景:** 用户在一个没有配置交叉编译环境的 Meson 项目中，尝试选择 Metrowerks 作为 C 或 C++ 编译器。
   * **报错信息 (可能):** `EnvironmentException: mwcc supports only cross-compilation.`

2. **指定了错误的指令集名称:**  用户可能会在 Meson 的配置文件中或通过命令行参数指定一个 `mwcc_instruction_set` 选项，但提供的名称不在 `mwccarm_instruction_set_args` 或其他指令集字典中。

   * **错误场景:** 用户尝试指定一个不存在的 ARM 处理器型号，例如 'arm999z'。
   * **后果:** Meson 构建系统可能无法生成正确的编译器参数，或者 Metrowerks 编译器自身会因为无法识别的 `-proc` 参数而报错。

3. **混淆了不同 Metrowerks 编译器的指令集选项:**  该文件区分了 `mwccarm_` 和 `mwcceppc_` 等不同编译器的指令集选项。用户可能会错误地为 ARM 编译器指定了 PowerPC 的指令集名称，反之亦然。

   * **错误场景:** 用户在使用 `mwccarm` 编译器时，错误地设置了 `instruction_set` 为 'gekko' (PowerPC 架构的处理器)。
   * **后果:** 编译器会收到不兼容的 `-proc` 参数，导致编译失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

一个开发者可能因为以下原因查看或修改这个文件：

1. **配置 Frida 的构建系统:** 当开发者尝试为特定的嵌入式平台构建 Frida 时，Meson 构建系统会根据配置选择相应的编译器。如果目标平台使用了 Metrowerks 编译器，Meson 就会加载 `metrowerks.py` 来获取编译器相关的设置。

2. **调试 Frida 的编译过程:** 如果在构建 Frida 时遇到与 Metrowerks 编译器相关的错误，开发者可能会查看这个文件来理解 Meson 是如何生成编译器命令的，以及检查是否存在错误的配置或参数。

3. **添加对新的 Metrowerks 编译器的支持:** 如果 Frida 需要支持一个尚未支持的 Metrowerks 编译器版本或新的目标架构，开发者可能需要修改这个文件，添加新的指令集选项或调整现有的逻辑。

4. **理解 Meson 构建系统的工作原理:**  开发者可能正在学习 Meson 构建系统，并希望了解它如何处理不同的编译器。查看 `metrowerks.py` 可以帮助理解 Meson 的编译器 mixin 机制。

5. **排查与 Frida Agent 编译相关的问题:** 如果为目标设备编译 Frida Agent 时出现问题，而该设备使用了 Metrowerks 编译器，开发者可能会查看此文件以确保编译参数正确。

**调试线索示例:**

假设用户在为某个嵌入式 Linux 设备构建 Frida Agent 时遇到了编译错误，错误信息指示编译器无法识别 `-proc` 参数。作为调试线索，用户可以：

1. **检查 Meson 的配置:** 确认在 Meson 的配置文件中是否正确指定了 Metrowerks 编译器的路径，以及是否设置了正确的 `instruction_set` 选项。
2. **查看 Meson 生成的编译命令:**  Meson 通常会输出执行的编译命令。用户可以检查这些命令中 `-proc` 参数的值是否正确，以及是否与 `metrowerks.py` 中定义的指令集名称一致。
3. **对比目标设备的 CPU 架构:**  确认 Meson 配置中的 `instruction_set` 与目标设备的实际 CPU 架构匹配。
4. **检查 `metrowerks.py` 文件:** 查看 `mwccarm_instruction_set_args` 或其他相关字典，确认所使用的指令集名称是否存在，以及对应的编译器参数是否正确。

总而言之，`metrowerks.py` 文件是 Frida 项目中连接 Meson 构建系统和 Metrowerks 编译器家族的关键桥梁，它通过提供编译器特定的配置信息，使得 Frida 能够正确地使用这些编译器进行交叉编译，这对于在各种嵌入式平台上部署 Frida 及其 Agent 至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2019 The Meson development team

from __future__ import annotations

"""Representations specific to the Metrowerks/Freescale Embedded C/C++ compiler family."""

import os
import typing as T

from ...mesonlib import EnvironmentException, OptionKey

if T.TYPE_CHECKING:
    from ...envconfig import MachineInfo
    from ...compilers.compilers import Compiler, CompileCheckMode
else:
    # This is a bit clever, for mypy we pretend that these mixins descend from
    # Compiler, so we get all of the methods and attributes defined for us, but
    # for runtime we make them descend from object (which all classes normally
    # do). This gives up DRYer type checking, with no runtime impact
    Compiler = object

mwccarm_instruction_set_args: T.Dict[str, T.List[str]] = {
    'generic': ['-proc', 'generic'],
    'v4': ['-proc', 'v4'],
    'v4t': ['-proc', 'v4t'],
    'v5t': ['-proc', 'v5t'],
    'v5te': ['-proc', 'v5te'],
    'v6': ['-proc', 'v6'],
    'arm7tdmi': ['-proc', 'arm7tdmi'],
    'arm710t': ['-proc', 'arm710t'],
    'arm720t': ['-proc', 'arm720t'],
    'arm740t': ['-proc', 'arm740t'],
    'arm7ej': ['-proc', 'arm7ej'],
    'arm9tdmi': ['-proc', 'arm9tdmi'],
    'arm920t': ['-proc', 'arm920t'],
    'arm922t': ['-proc', 'arm922t'],
    'arm940t': ['-proc', 'arm940t'],
    'arm9ej': ['-proc', 'arm9ej'],
    'arm926ej': ['-proc', 'arm926ej'],
    'arm946e': ['-proc', 'arm946e'],
    'arm966e': ['-proc', 'arm966e'],
    'arm1020e': ['-proc', 'arm1020e'],
    'arm1022e': ['-proc', 'arm1022e'],
    'arm1026ej': ['-proc', 'arm1026ej'],
    'dbmx1': ['-proc', 'dbmx1'],
    'dbmxl': ['-proc', 'dbmxl'],
    'XScale': ['-proc', 'XScale'],
    'pxa255': ['-proc', 'pxa255'],
    'pxa261': ['-proc', 'pxa261'],
    'pxa262': ['-proc', 'pxa262'],
    'pxa263': ['-proc', 'pxa263']
}

mwcceppc_instruction_set_args: T.Dict[str, T.List[str]] = {
    'generic': ['-proc', 'generic'],
    '401': ['-proc', '401'],
    '403': ['-proc', '403'],
    '505': ['-proc', '505'],
    '509': ['-proc', '509'],
    '555': ['-proc', '555'],
    '601': ['-proc', '601'],
    '602': ['-proc', '602'],
    '603': ['-proc', '603'],
    '603e': ['-proc', '603e'],
    '604': ['-proc', '604'],
    '604e': ['-proc', '604e'],
    '740': ['-proc', '740'],
    '750': ['-proc', '750'],
    '801': ['-proc', '801'],
    '821': ['-proc', '821'],
    '823': ['-proc', '823'],
    '850': ['-proc', '850'],
    '860': ['-proc', '860'],
    '7400': ['-proc', '7400'],
    '7450': ['-proc', '7450'],
    '8240': ['-proc', '8240'],
    '8260': ['-proc', '8260'],
    'e500': ['-proc', 'e500'],
    'gekko': ['-proc', 'gekko'],
}

mwasmarm_instruction_set_args: T.Dict[str, T.List[str]] = {
    'arm4': ['-proc', 'arm4'],
    'arm4t': ['-proc', 'arm4t'],
    'arm4xm': ['-proc', 'arm4xm'],
    'arm4txm': ['-proc', 'arm4txm'],
    'arm5': ['-proc', 'arm5'],
    'arm5T': ['-proc', 'arm5T'],
    'arm5xM': ['-proc', 'arm5xM'],
    'arm5TxM': ['-proc', 'arm5TxM'],
    'arm5TE': ['-proc', 'arm5TE'],
    'arm5TExP': ['-proc', 'arm5TExP'],
    'arm6': ['-proc', 'arm6'],
    'xscale': ['-proc', 'xscale']
}

mwasmeppc_instruction_set_args: T.Dict[str, T.List[str]] = {
    '401': ['-proc', '401'],
    '403': ['-proc', '403'],
    '505': ['-proc', '505'],
    '509': ['-proc', '509'],
    '555': ['-proc', '555'],
    '56X': ['-proc', '56X'],
    '601': ['-proc', '601'],
    '602': ['-proc', '602'],
    '603': ['-proc', '603'],
    '603e': ['-proc', '603e'],
    '604': ['-proc', '604'],
    '604e': ['-proc', '604e'],
    '740': ['-proc', '740'],
    '74X': ['-proc', '74X'],
    '750': ['-proc', '750'],
    '75X': ['-proc', '75X'],
    '801': ['-proc', '801'],
    '821': ['-proc', '821'],
    '823': ['-proc', '823'],
    '850': ['-proc', '850'],
    '85X': ['-proc', '85X'],
    '860': ['-proc', '860'],
    '86X': ['-proc', '86X'],
    '87X': ['-proc', '87X'],
    '88X': ['-proc', '88X'],
    '5100': ['-proc', '5100'],
    '5200': ['-proc', '5200'],
    '7400': ['-proc', '7400'],
    '744X': ['-proc', '744X'],
    '7450': ['-proc', '7450'],
    '745X': ['-proc', '745X'],
    '82XX': ['-proc', '82XX'],
    '8240': ['-proc', '8240'],
    '824X': ['-proc', '824X'],
    '8260': ['-proc', '8260'],
    '827X': ['-proc', '827X'],
    '8280': ['-proc', '8280'],
    'e300': ['-proc', 'e300'],
    'e300c2': ['-proc', 'e300c2'],
    'e300c3': ['-proc', 'e300c3'],
    'e300c4': ['-proc', 'e300c4'],
    'e600': ['-proc', 'e600'],
    '85xx': ['-proc', '85xx'],
    'e500': ['-proc', 'e500'],
    'e500v2': ['-proc', 'e500v2'],
    'Zen': ['-proc', 'Zen'],
    '5565': ['-proc', '5565'],
    '5674': ['-proc', '5674'],
    'gekko': ['-proc', 'gekko'],
    'generic': ['-proc', 'generic'],
}

mwcc_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': ['-O0'],
    'g': ['-Op'],
    '1': ['-O1'],
    '2': ['-O2'],
    '3': ['-O4,p'],
    's': ['-Os']
}

mwcc_debug_args: T.Dict[bool, T.List[str]] = {
    False: [],
    True: ['-g']
}


class MetrowerksCompiler(Compiler):
    id = 'mwcc'

    # These compilers can actually invoke the linker, but they choke on
    # linker-specific flags. So it's best to invoke the linker directly
    INVOKES_LINKER = False

    def __init__(self) -> None:
        if not self.is_cross:
            raise EnvironmentException(f'{id} supports only cross-compilation.')

        self.base_options = {
            OptionKey(o) for o in ['b_pch', 'b_ndebug']}

        default_warn_args: T.List[str] = []
        self.warn_args: T.Dict[str, T.List[str]] = {
            '0': ['-w', 'off'],
            '1': default_warn_args,
            '2': default_warn_args + ['-w', 'most'],
            '3': default_warn_args + ['-w', 'all'],
            'everything': default_warn_args + ['-w', 'full']}

    def depfile_for_object(self, objfile: str) -> T.Optional[str]:
        # Earlier versions of these compilers do not support specifying
        # a custom name for a depfile, and can only generate '<input_file>.d'
        return os.path.splitext(objfile)[0] + '.' + self.get_depfile_suffix()

    def get_always_args(self) -> T.List[str]:
        return ['-gccinc']

    def get_compiler_check_args(self, mode: CompileCheckMode) -> T.List[str]:
        return []

    def get_compile_only_args(self) -> T.List[str]:
        return ['-c']

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        return mwcc_debug_args[is_debug]

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        # Check comment in depfile_for_object()
        return ['-gccdep', '-MD']

    def get_depfile_suffix(self) -> str:
        return 'd'

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if not path:
            path = '.'
        return ['-I' + path]

    def get_no_optimization_args(self) -> T.List[str]:
        return ['-opt', 'off']

    def get_no_stdinc_args(self) -> T.List[str]:
        return ['-nostdinc']

    def get_no_stdlib_link_args(self) -> T.List[str]:
        return ['-nostdlib']

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return mwcc_optimization_args[optimization_level]

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_pic_args(self) -> T.List[str]:
        return ['-pic']

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-E']

    def get_preprocess_to_file_args(self) -> T.List[str]:
        return ['-P']

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        return ['-prefix', self.get_pch_name(header)]

    def get_pch_name(self, name: str) -> str:
        return os.path.basename(name) + '.' + self.get_pch_suffix()

    def get_pch_suffix(self) -> str:
        return 'mch'

    def get_warn_args(self, level: str) -> T.List[str]:
        return self.warn_args[level]

    def get_werror_args(self) -> T.List[str]:
        return ['-w', 'error']

    @classmethod
    def _unix_args_to_native(cls, args: T.List[str], info: MachineInfo) -> T.List[str]:
        result: T.List[str] = []
        for i in args:
            if i.startswith('-D'):
                i = '-D' + i[2:]
            if i.startswith('-I'):
                i = '-I' + i[2:]
            if i.startswith('-Wl,-rpath='):
                continue
            elif i == '--print-search-dirs':
                continue
            elif i.startswith('-L'):
                continue
            result.append(i)
        return result

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str], build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I':
                parameter_list[idx] = i[:9] + os.path.normpath(os.path.join(build_dir, i[9:]))

        return parameter_list

"""

```