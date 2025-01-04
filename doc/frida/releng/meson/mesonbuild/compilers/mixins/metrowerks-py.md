Response:
Let's break down the thought process for analyzing the provided Python code snippet.

**1. Understanding the Core Task:**

The primary goal is to analyze a Python file (`metrowerks.py`) that's part of the Frida dynamic instrumentation tool's build system (using Meson). The focus is on understanding its *functionality* and relating it to various technical areas like reverse engineering, low-level details, and potential user errors.

**2. Initial Code Scan and Interpretation:**

* **Imports:**  Notice imports like `os`, `typing`, and elements from `mesonbuild`. This immediately suggests a build-system-related file dealing with compilation. The `T.TYPE_CHECKING` block hints at type hinting for static analysis.
* **Class Definition:** The `MetrowerksCompiler` class is central. The docstring mentioning "Metrowerks/Freescale Embedded C/C++ compiler family" is a key piece of information. This tells us it's about supporting specific compilers, likely used in embedded systems.
* **Data Structures (Dictionaries):**  The code defines several dictionaries (`mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, etc.). These map symbolic names (like 'v4', 'generic') to lists of compiler flags (like `['-proc', 'v4']`). This strongly indicates the file's purpose is to configure the compiler based on target architecture and other settings.
* **Method Definitions:**  The `MetrowerksCompiler` class has methods like `get_always_args`, `get_compile_only_args`, `get_debug_args`, `get_include_args`, `get_optimization_args`, etc. These method names clearly suggest they are responsible for generating specific sets of compiler arguments based on build settings.
* **`INVOKES_LINKER = False`:** This is important. It states that this specific compiler wrapper *doesn't* directly invoke the linker. This implies a separate linking step might be needed.
* **`is_cross` Check:** The `__init__` method checks `self.is_cross`. This confirms it's primarily designed for cross-compilation (building for a different architecture than the host).
* **`_unix_args_to_native`:** This method suggests a conversion or filtering of arguments, likely when transitioning from a Unix-like build environment to the target's environment.

**3. Connecting to the Prompt's Requirements:**

Now, systematically address each part of the prompt:

* **Functionality:**  Summarize the observations from step 2. Focus on the core purpose: providing compiler-specific configurations for Metrowerks compilers within the Meson build system.

* **Relationship to Reverse Engineering:**  Consider how compiler flags impact the generated binary. Flags controlling optimization, debug symbols, and target architecture are directly relevant to reverse engineering. Explain *how* these flags make reverse engineering easier or harder.

* **Binary Bottom, Linux, Android Kernel/Framework:**  Think about where these compilers are typically used. Embedded systems are a strong connection. Relate the target architectures (ARM, PowerPC) to embedded Linux, Android (though less direct for these specific older architectures), and the concept of cross-compilation in these contexts. Mention the impact of instruction set selection.

* **Logic Inference (Hypothetical Input/Output):**  Choose a specific scenario. For example, enabling debugging. Show how the `get_debug_args` method maps the boolean `True` to the `-g` flag. Similarly, show the mapping for optimization levels.

* **User/Programming Errors:**  Consider how the user interacts with the build system (Meson). What mistakes could they make that would involve this code? Incorrect architecture selection, using optimization levels incorrectly, or misunderstandings about cross-compilation are good examples.

* **User Operation Steps (Debugging Clues):**  Outline the typical Meson workflow that would lead to this code being executed. This involves configuring the build environment, selecting the compiler, and running the build process.

**4. Structuring the Answer:**

Organize the information clearly, using headings and bullet points. Provide specific code examples where relevant. Explain technical terms like "cross-compilation" and "instruction set architecture" if the target audience isn't assumed to be experts.

**5. Refinement and Accuracy:**

Review the generated answer for correctness and completeness. Ensure the examples are accurate and the explanations are clear and concise. For instance, initially, I might have overemphasized Android, but upon closer examination, the listed architectures are older, making embedded Linux a more direct fit. I would then adjust the answer accordingly. Also, ensure the explanation of how the dictionaries work and how the methods use them is clear.

This iterative process of code analysis, connecting to the prompt, and structuring the answer leads to the comprehensive explanation provided in the initial example.
这个Python文件 `metrowerks.py` 是 Frida 动态 instrumentation 工具中用于处理 Metrowerks/Freescale 嵌入式 C/C++ 编译器系列的模块。它的主要功能是为 Meson 构建系统提供特定于这些编译器的配置和命令行参数生成逻辑。

以下是它的功能列表：

**核心功能：**

1. **定义编译器标识符:**  声明 `id = 'mwcc'`，用于在 Meson 构建系统中唯一标识 Metrowerks 编译器。
2. **指定不直接调用链接器:** 设置 `INVOKES_LINKER = False`，表明此编译器模块不负责直接调用链接器，而是由 Meson 统一处理链接过程。
3. **限制为交叉编译:**  在 `__init__` 方法中检查 `self.is_cross`，如果不是交叉编译，则抛出异常，说明此模块仅用于交叉编译场景。
4. **管理编译器选项:**  定义了 `base_options`，列出了与此编译器相关的基本构建选项（如预编译头 `b_pch` 和发布模式 `b_ndebug`）。
5. **处理警告选项:**  定义了不同警告级别的命令行参数 (`warn_args`)，允许用户控制编译器的警告行为。
6. **生成依赖文件路径:**  `depfile_for_object` 方法根据目标文件路径生成依赖文件（`.d` 文件）的路径。
7. **提供常用编译参数:**  `get_always_args` 返回一些始终需要的编译参数，例如 `-gccinc`。
8. **处理编译器检查参数:** `get_compiler_check_args` 返回用于检查编译器是否正常工作的参数。
9. **生成仅编译参数:** `get_compile_only_args` 返回 `-c` 参数，指示编译器只进行编译而不进行链接。
10. **处理调试信息参数:** `get_debug_args` 根据是否启用调试返回 `-g` 参数。
11. **生成依赖关系生成参数:** `get_dependency_gen_args` 返回生成依赖文件的参数，如 `-gccdep` 和 `-MD`。
12. **获取依赖文件后缀:** `get_depfile_suffix` 返回依赖文件的默认后缀 `d`。
13. **生成包含目录参数:** `get_include_args` 生成包含目录的 `-I` 参数。
14. **生成禁用优化参数:** `get_no_optimization_args` 返回禁用优化的参数 `-opt off`。
15. **生成禁用标准包含目录参数:** `get_no_stdinc_args` 返回 `-nostdinc` 参数。
16. **生成禁用标准库链接参数:** `get_no_stdlib_link_args` 返回 `-nostdlib` 参数。
17. **生成优化级别参数:** `get_optimization_args` 根据不同的优化级别返回相应的参数（如 `-O0`, `-O1`, `-O2`, `-O4,p`, `-Os`）。
18. **生成输出文件参数:** `get_output_args` 生成指定输出文件名的 `-o` 参数。
19. **生成位置无关代码参数:** `get_pic_args` 返回生成位置无关代码的 `-pic` 参数。
20. **生成预处理参数:** `get_preprocess_only_args` 返回仅进行预处理的 `-E` 参数。
21. **生成预处理到文件参数:** `get_preprocess_to_file_args` 返回将预处理结果输出到文件的 `-P` 参数。
22. **生成使用预编译头参数:** `get_pch_use_args` 返回使用预编译头的参数，如 `-prefix <pch_name>`。
23. **生成预编译头文件名:** `get_pch_name` 根据头文件名生成预编译头文件名。
24. **获取预编译头文件后缀:** `get_pch_suffix` 返回预编译头文件的默认后缀 `mch`。
25. **生成警告级别参数:** `get_warn_args` 根据不同的警告级别返回相应的参数。
26. **生成将警告视为错误参数:** `get_werror_args` 返回将警告视为错误的 `-w error` 参数。
27. **转换 Unix 参数为原生格式:** `_unix_args_to_native` 方法用于将 Unix 风格的命令行参数转换为 Metrowerks 编译器能够理解的格式，并移除一些不兼容的参数。
28. **计算绝对路径参数:** `compute_parameters_with_absolute_paths` 方法用于将相对路径的包含目录参数转换为绝对路径。
29. **定义指令集参数:**  定义了多个字典 (`mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, `mwasmarm_instruction_set_args`, `mwasmeppc_instruction_set_args`)，用于指定针对不同 ARM 和 PowerPC 架构的指令集参数，例如 `-proc v4`, `-proc arm7tdmi` 等。

**与逆向方法的关系及举例说明：**

该文件直接影响着目标二进制文件的编译方式，而编译方式对逆向分析有着重要的影响。

* **调试信息 (`get_debug_args`):**  如果启用了调试信息 (例如，通过 Meson 设置 `buildtype=debug`)，`get_debug_args` 会返回 `['-g']`，告诉编译器在生成的目标文件中包含调试符号。这些符号包含了函数名、变量名、源代码行号等信息，极大地简化了逆向工程师使用 GDB 或其他调试器进行分析的过程。反之，如果编译时没有包含调试信息，逆向分析将更加困难，需要花费更多精力来理解代码逻辑。

* **优化级别 (`get_optimization_args`):**  不同的优化级别会显著改变生成代码的结构和执行效率。
    * **`-O0` (无优化):** 生成的代码更接近源代码，指令顺序与源代码逻辑对应，方便逆向分析。
    * **`-O2`, `-O3` (高优化):** 编译器会进行各种代码优化，例如指令重排、内联函数、循环展开等，使得生成的目标代码更加高效，但同时也增加了逆向分析的难度，因为代码结构与源代码差异较大。逆向工程师需要理解编译器的优化策略才能更好地理解代码。

* **位置无关代码 (`get_pic_args`):**  在某些情况下，例如编译共享库时，需要生成位置无关代码。`get_pic_args` 返回 `['-pic']` 参数。位置无关代码可以在内存中的任意地址加载和执行，这对于理解动态链接和加载过程至关重要。逆向分析共享库时，需要理解 PIC 的实现机制（例如，使用 GOT 和 PLT）。

* **指令集架构 (`mwccarm_instruction_set_args` 等):**  选择不同的目标架构和指令集会生成不同的机器码。逆向工程师必须了解目标架构的指令集才能正确反汇编和理解代码。例如，如果目标是 ARMv7 架构，则需要使用支持 ARMv7 指令集的反汇编器。

**二进制底层、Linux、Android 内核及框架的知识举例说明：**

虽然此文件本身是 Meson 构建系统的一部分，但它处理的编译器是常用于嵌入式开发的 Metrowerks 编译器，这与二进制底层、Linux 和 Android 内核及框架有一定的关联：

* **二进制底层:**  该文件最终目的是生成编译器的命令行参数，这些参数直接控制着二进制文件的生成过程。例如，通过指定指令集架构，编译器会生成相应的机器码，这属于二进制底层的范畴。理解这些参数有助于理解最终二进制文件的结构和行为。

* **Linux 内核:** Metrowerks 编译器常用于嵌入式 Linux 系统的开发。该文件中定义的指令集参数 (`mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`)  对应着不同的处理器架构，而这些架构广泛应用于各种嵌入式 Linux 设备中。例如，在编译 Linux 内核模块或驱动程序时，可能会使用到这些编译器。

* **Android 内核 (早期版本或特定领域):**  虽然 Android 主要使用 GCC/Clang，但在一些早期的 Android 版本或者特定的嵌入式 Android 设备中，也可能使用 Metrowerks 编译器。 该文件支持的 ARM 架构也正是 Android 设备广泛使用的架构。理解针对这些架构的编译选项，有助于分析 Android 底层组件。

**逻辑推理（假设输入与输出）：**

假设用户在 Meson 构建配置文件中设置了以下选项：

```meson
project('myproject', 'c')
c_compiler = meson.get_compiler('c')

if c_compiler.get_id() == 'mwcc':
  add_global_arguments('-DDEBUG_ENABLED', language : 'c')
  add_global_link_arguments('-lmy_custom_lib', language : 'c')
  set_options('b_ndebug=true', 'optimization=2')
```

当 Meson 构建系统处理编译步骤时，`metrowerks.py` 中的相关方法会被调用。

* **输入:** `is_debug = False` (因为 `b_ndebug=true`)
* **输出:** `get_debug_args(False)` 返回 `[]` (空列表，不添加调试信息)

* **输入:** `optimization_level = '2'`
* **输出:** `get_optimization_args('2')` 返回 `['-O2']`

* **输入:** 用户需要编译一个名为 `source.c` 的文件。
* **输出:** `get_output_args('output/source.o')` 返回 `['-o', 'output/source.o']` (假设构建系统指定了输出路径)

**用户或编程常见的使用错误及举例说明：**

1. **在非交叉编译环境下使用:**  `MetrowerksCompiler` 的 `__init__` 方法会检查 `self.is_cross`。如果用户在本地主机上尝试使用 Metrowerks 编译器进行构建，Meson 会调用此模块，导致 `__init__` 抛出 `EnvironmentException`，提示用户该编译器仅支持交叉编译。

   ```
   meson.build:
   project('myproject', 'c')
   cc = meson.find_compiler('c')  # 如果本地默认 C 编译器是 mwcc 就会出错

   # 错误信息类似：
   # meson.build:2:0: ERROR: mwcc supports only cross-compilation.
   ```

2. **指定了不兼容的指令集:** 用户可能在 Meson 的交叉编译配置文件中指定了一个 Metrowerks 编译器不支持的指令集。虽然 `metrowerks.py` 定义了一些常见的指令集，但如果用户输入的指令集名称不在这些字典中，Meson 构建过程可能会出错，或者生成的命令行参数不正确。

   ```meson
   # 交叉编译配置文件 (e.g., my_cross_file.ini):
   [binaries]
   c = '/path/to/mwcc'

   [properties]
   c_args = ['-proc', 'invalid_instruction_set'] # 错误的指令集
   ```

   在这种情况下，Meson 可能会将 `-proc invalid_instruction_set` 传递给编译器，导致编译器报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户安装了 Frida 和 Meson:**  首先，用户需要安装 Frida 动态 instrumentation 工具和 Meson 构建系统。
2. **Frida 的构建系统使用 Meson:** Frida 的构建系统使用 Meson 来管理编译过程。
3. **配置构建环境:** 用户在 Frida 源代码目录下，使用 `meson setup build` 命令配置构建环境。
4. **选择 Metrowerks 编译器:**  用户可能在配置构建环境时，通过命令行参数或者 Meson 配置文件指定了使用 Metrowerks 编译器进行编译。例如：
   ```bash
   meson setup build -Dc_compiler=/path/to/mwcc
   ```
5. **Meson 调用编译器模块:** 当 Meson 执行编译步骤时，它会根据选择的编译器 (这里是 Metrowerks) 加载对应的编译器模块，即 `frida/releng/meson/mesonbuild/compilers/mixins/metrowerks.py`。
6. **执行模块中的方法:** Meson 会调用该模块中定义的方法 (如 `get_compile_only_args`, `get_debug_args` 等) 来生成特定于 Metrowerks 编译器的命令行参数。
7. **生成构建命令:** Meson 使用这些参数构建最终的编译器调用命令。
8. **执行编译命令:** Meson 执行生成的编译命令，从而使用 Metrowerks 编译器编译 Frida 的相关组件。

**作为调试线索:**

如果用户在构建 Frida 时遇到与 Metrowerks 编译器相关的问题（例如，编译错误，链接错误，或者生成的二进制文件行为异常），查看 `metrowerks.py` 文件的代码可以帮助理解 Meson 是如何配置和调用 Metrowerks 编译器的。

* **检查编译器路径:** 确认 Meson 是否找到了正确的 Metrowerks 编译器路径。
* **查看生成的命令行参数:** 通过 Meson 的 verbose 输出或者构建日志，查看实际传递给 Metrowerks 编译器的命令行参数，对照 `metrowerks.py` 中的逻辑，判断参数是否正确生成。
* **分析指令集配置:** 如果涉及到特定的硬件平台，检查指令集参数的配置是否正确。
* **理解优化和调试选项:**  确定是否启用了调试信息，以及优化级别是否符合预期。

总而言之，`metrowerks.py` 是 Frida 构建系统中使用 Meson 来支持 Metrowerks 编译器的关键组成部分，它定义了该编译器的特性和命令行参数生成规则，对最终生成的二进制文件的特性有着直接的影响，也为理解和调试 Frida 的构建过程提供了线索。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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