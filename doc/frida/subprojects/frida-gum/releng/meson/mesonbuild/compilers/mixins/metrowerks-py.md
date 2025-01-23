Response:
Let's break down the thought process for analyzing the `metrowerks.py` file.

1. **Understanding the Context:** The file path `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/metrowerks.py` immediately tells us this is part of the Frida project, specifically within the build system (Meson) for a component called `frida-gum`. The "mixins" directory suggests this file provides reusable functionalities for a specific compiler family. The name "metrowerks" points to a specific compiler suite.

2. **Initial Code Scan:** A quick glance reveals:
    * **License and Copyright:** Standard header information.
    * **Imports:** `os`, `typing`, and elements from the Meson build system (`mesonlib`, `envconfig`, `compilers`).
    * **Type Hinting:** Extensive use of `typing` indicates a focus on code clarity and maintainability.
    * **Data Structures:** Several dictionaries (`mwccarm_instruction_set_args`, etc.) mapping symbolic names to compiler flags. This immediately suggests the file is concerned with configuring compiler behavior based on target architecture and optimization levels.
    * **A Class:**  `MetrowerksCompiler` inheriting from `Compiler`. This confirms its role as a compiler-specific configuration within the Meson build system.
    * **Methods:**  Various methods like `get_always_args`, `get_debug_args`, `get_include_args`, etc. These strongly suggest the class is responsible for generating the correct command-line arguments for the Metrowerks compiler.

3. **Deconstructing the Functionality (Step-by-Step):**

    * **Instruction Set Handling:** The dictionaries like `mwccarm_instruction_set_args` are clearly mapping architecture names (e.g., 'v4', 'arm7tdmi') to the corresponding `-proc` compiler flag. This is fundamental for cross-compilation, as Frida often targets embedded systems with specific processor architectures.

    * **Optimization and Debugging:**  `mwcc_optimization_args` and `mwcc_debug_args` handle optimization levels (`-O0`, `-O1`, etc.) and debug symbol generation (`-g`). These are standard compiler features.

    * **Compiler Class (`MetrowerksCompiler`):**
        * `id = 'mwcc'`:  Identifies the compiler.
        * `INVOKES_LINKER = False`:  Important for build system behavior, indicating the linker needs to be invoked separately.
        * `__init__`:  Checks for cross-compilation, which aligns with Frida's target use cases.
        * `base_options`: Lists Meson's build options this compiler interacts with.
        * `warn_args`:  Handles different warning levels.
        * `depfile_for_object`:  Deals with dependency file generation, crucial for incremental builds.
        * `get_*_args` methods:  These are the core of the class. Each method returns a list of compiler flags for a specific purpose (includes, debug, optimization, output, etc.). The logic is mostly straightforward mapping to Metrowerks compiler flags.
        * `_unix_args_to_native`:  This is interesting. It seems to be filtering out flags that are specific to Unix-like linkers, reinforcing the `INVOKES_LINKER = False` point. This is crucial for cross-compilation where the host and target systems might differ.
        * `compute_parameters_with_absolute_paths`: Handles the conversion of relative include paths to absolute paths, necessary for the compiler to find the correct headers.

4. **Connecting to Reverse Engineering and Low-Level Concepts:**

    * **Instruction Sets:**  Directly related to reverse engineering. Understanding the target architecture's instruction set (ARM, PowerPC in this case) is vital for analyzing compiled code. Frida often manipulates code at this level.
    * **Cross-Compilation:**  A cornerstone of embedded system development and reverse engineering of such systems. Frida targets a wide range of platforms.
    * **Compiler Flags:**  Knowing how compiler flags influence the generated binary (optimization, debugging symbols) is essential for reverse engineers. It affects the ease of analysis.
    * **Dependency Generation:** While less directly related to *analyzing* a binary, understanding how build systems work and track dependencies can be helpful in larger reverse engineering projects involving rebuilding parts of a system.

5. **Logic, Assumptions, and Error Scenarios:**  The logic is mostly conditional mapping. Assumptions include the presence of the Metrowerks compiler and the correctness of the flag mappings. Potential user errors involve:
    * Incorrectly specifying the target architecture.
    * Not setting up the cross-compilation environment correctly.
    * Using Meson options incompatible with this compiler.

6. **Tracing User Actions:** Starting with wanting to use Frida on a target compiled with Metrowerks, a user would configure the Meson build system, specifying the compiler family. Meson would then load this `metrowerks.py` file to generate the correct build commands.

7. **Refining and Structuring the Answer:**  Organize the findings into clear sections (Functionality, Relationship to Reverse Engineering, etc.) with bullet points and examples. Use the provided code snippets to illustrate the explanations. Focus on the "why" behind the code.

By following this methodical approach, we can thoroughly understand the purpose and functionality of the `metrowerks.py` file within the Frida project. The key is to read the code carefully, understand the context, and connect the code elements to broader concepts in software development and reverse engineering.
这个文件 `metrowerks.py` 是 Frida 动态 instrumentation 工具中，用于支持 **Metrowerks/Freescale Embedded C/C++ 编译器系列** 的一个混入 (mixin) 模块。它定义了如何将 Meson 构建系统的抽象指令转换为 Metrowerks 编译器能够理解的命令行参数。

以下是它的主要功能：

**1. 定义特定于 Metrowerks 编译器的命令行参数：**

   - **指令集架构 (`-proc` 标志):**  它定义了针对不同 ARM 和 PowerPC 架构的 `-proc` 编译器标志，例如 `v4`, `arm7tdmi`, `e500` 等。这些标志指示编译器生成特定于目标处理器的代码。
     - `mwccarm_instruction_set_args`: 针对 ARM 架构。
     - `mwcceppc_instruction_set_args`: 针对 PowerPC 架构。
     - `mwasmarm_instruction_set_args`: 针对 ARM 架构（可能是 CodeWarrior for ARM）。
     - `mwasmeppc_instruction_set_args`: 针对 PowerPC 架构（可能是 CodeWarrior for PowerPC）。
   - **优化级别 (`-O` 标志):**  定义了不同优化级别的编译器标志，例如 `-O0`, `-O1`, `-O2`, `-O4,p`, `-Os`。
     - `mwcc_optimization_args`:  将 Meson 的优化级别映射到 Metrowerks 的标志。
   - **调试信息 (`-g` 标志):** 定义了是否生成调试信息的编译器标志。
     - `mwcc_debug_args`:  将 Meson 的调试设置映射到 Metrowerks 的标志。
   - **其他编译器选项:**  还包含了一些通用的编译器选项，例如包含路径 (`-I`), 输出文件名 (`-o`), 预处理 (`-E`, `-P`),  依赖关系生成 (`-gccdep`, `-MD`) 等。

**2. 提供一个 `MetrowerksCompiler` 类，继承自 `Compiler` 基类：**

   - **`id = 'mwcc'`:**  标识这个混入模块对应的是 Metrowerks 编译器。
   - **`INVOKES_LINKER = False`:**  明确指出 Metrowerks 编译器通常不直接调用链接器，需要单独调用。这对于构建系统的流程控制很重要。
   - **`__init__`:**  初始化方法，强制要求使用交叉编译，因为 Metrowerks 编译器通常用于嵌入式开发。
   - **`get_always_args`:**  返回始终需要添加的编译器参数，例如 `-gccinc`。
   - **`get_compiler_check_args`:**  返回用于检查编译器是否可用的参数。
   - **`get_compile_only_args`:**  返回只编译不链接的参数 (`-c`).
   - **`get_debug_args`:**  根据调试模式返回相应的调试参数。
   - **`get_dependency_gen_args`:** 返回生成依赖文件的参数。
   - **`get_depfile_suffix`:** 返回依赖文件的后缀名 (`.d`).
   - **`get_include_args`:**  返回添加包含路径的参数 (`-I`).
   - **`get_no_optimization_args`:** 返回禁用优化的参数 (`-opt off`).
   - **`get_no_stdinc_args`:** 返回不包含标准头文件路径的参数 (`-nostdinc`).
   - **`get_no_stdlib_link_args`:** 返回不链接标准库的参数 (`-nostdlib`).
   - **`get_optimization_args`:** 根据优化级别返回相应的优化参数。
   - **`get_output_args`:** 返回指定输出文件名的参数 (`-o`).
   - **`get_pic_args`:** 返回生成位置无关代码的参数 (`-pic`).
   - **`get_preprocess_only_args`:** 返回只进行预处理的参数 (`-E`).
   - **`get_preprocess_to_file_args`:** 返回预处理到文件的参数 (`-P`).
   - **`get_pch_use_args`:** 返回使用预编译头的参数 (`-prefix`).
   - **`get_pch_name`:** 返回预编译头的名称。
   - **`get_pch_suffix`:** 返回预编译头的后缀名 (`.mch`).
   - **`get_warn_args`:** 根据警告级别返回相应的警告参数。
   - **`get_werror_args`:** 返回将警告视为错误的参数 (`-w error`).
   - **`_unix_args_to_native`:**  一个静态方法，用于将 Unix 风格的参数转换为 Metrowerks 编译器能够理解的格式。这在交叉编译环境中处理不同平台的约定非常重要。
   - **`compute_parameters_with_absolute_paths`:**  将相对路径的包含路径转换为绝对路径。

**与逆向方法的关系及举例说明：**

这个文件本身并不直接参与逆向分析过程，但它 **影响着目标二进制文件的生成方式**，从而间接地影响逆向分析的难度和方法。

* **指令集架构:**  通过指定不同的 `-proc` 参数，编译器会生成不同的机器码指令。逆向工程师需要了解目标架构的指令集（例如 ARMv7, ARMv8, PowerPC 等）才能正确反汇编和理解代码。Frida 可以通过 hook 函数来观察运行时行为，而了解目标架构的指令集有助于理解 hook 的原理以及可能的副作用。
    * **举例:** 如果目标设备使用的是基于 ARMv5TE 的处理器，那么构建系统会使用 `'-proc', 'v5te'` 参数编译代码。逆向工程师在分析该设备上的 Frida 模块时，需要具备 ARMv5TE 指令集的知识。

* **优化级别:**  不同的优化级别会导致编译器进行不同的代码转换和优化，例如内联函数、循环展开、寄存器分配等。这会使得反汇编后的代码与源代码的结构差异较大，增加逆向分析的复杂度。
    * **举例:** 如果使用 `-O0` 编译，生成的代码通常更接近源代码，更容易理解。如果使用 `-O2` 或 `-O4,p` 编译，编译器会进行更积极的优化，例如可能会将多个简单的操作合并成一个复杂的指令，使得静态分析更加困难。Frida 在运行时可以绕过一些优化带来的混淆，例如通过 hook 函数的入口点来获取原始的参数。

* **调试信息:**  `-g` 参数会生成调试符号，包含变量名、函数名、源代码行号等信息。这些信息对于动态调试器（如 GDB）非常有用，可以帮助逆向工程师理解程序的运行状态。Frida 本身就是一个动态分析工具，它依赖于目标进程的某些结构和信息，而调试信息的存在可以简化 Frida 的开发和使用。
    * **举例:** 如果编译时没有使用 `-g`，那么反汇编出的函数和变量名可能是编译器生成的符号，可读性很差。如果使用了 `-g`，逆向工程师可以通过调试器看到原始的函数和变量名，更容易理解代码的功能。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层:**
    * **指令集架构:** 文件中定义的各种 `-proc` 参数直接对应了不同的处理器架构，这是二进制执行的基础。理解这些架构的特性对于理解 Frida 如何在这些平台上工作至关重要。
    * **编译选项对二进制布局的影响:** 优化级别和是否生成调试信息会直接影响最终生成的可执行文件的结构、代码段、数据段以及符号表等。Frida 需要能够解析和操作这些二进制结构。
    * **位置无关代码 (`-pic`):** 在某些平台上（例如 Linux），为了支持动态链接库的加载，需要生成位置无关代码。这个选项会影响代码的生成方式，确保代码可以在内存的任意位置执行。

* **Linux/Android 内核及框架:**
    * **交叉编译:** Frida 通常需要交叉编译以在目标设备上运行，而 Metrowerks 编译器常用于嵌入式开发，这与 Linux 和 Android 设备的开发场景相关。
    * **动态链接:**  `INVOKES_LINKER = False` 暗示了链接过程可能由其他的工具链或构建系统处理，这涉及到 Linux 和 Android 系统中动态链接库的加载和链接机制。
    * **系统调用:** Frida 的很多功能最终会涉及到系统调用，例如内存操作、进程管理等。理解目标系统的系统调用约定有助于理解 Frida 的底层实现。
    * **Android 框架:**  在 Android 平台上使用 Frida 时，可能需要与 Android 的运行时环境 (ART/Dalvik) 和框架进行交互。了解 Android 的构建系统和编译过程有助于理解 Frida 如何被注入到 Android 进程中。

**逻辑推理、假设输入与输出：**

这个文件主要进行的是 **映射** 和 **参数生成**，逻辑推理相对简单。

* **假设输入:** Meson 构建系统接收到要使用 Metrowerks 编译器编译针对 ARMv7 架构，并开启一级优化的 C++ 代码。
* **逻辑推理:**
    1. Meson 会识别出编译器类型为 `mwcc`。
    2. 它会调用 `MetrowerksCompiler` 类的相应方法。
    3. 根据架构 `armv7` (可能需要根据 Meson 的规范映射到 `mwccarm_instruction_set_args` 中的某个键，例如 `v5te` 或 `arm7tdmi`)，会从 `mwccarm_instruction_set_args` 中查找到 `'-proc', 'v5te'` (假设映射到此)。
    4. 根据优化级别 `1`，会从 `mwcc_optimization_args` 中查找到 `'-O1'`。
    5. 其他参数（例如包含路径、源文件等）也会通过相应的方法生成。
* **输出:**  最终会生成类似这样的编译器命令行：
   ```bash
   <path_to_mwcc> -proc v5te -O1 -c <source_file.cpp> -o <output_file.o> -I<include_path> ...
   ```

**涉及用户或者编程常见的使用错误及举例说明：**

* **不正确的指令集架构选择:** 用户可能选择了与目标硬件不匹配的指令集架构，导致编译出的代码无法在目标设备上运行。
    * **举例:** 用户错误地将目标架构设置为 `v4`，但实际硬件是 ARMv7，导致编译出的代码无法在该硬件上正确执行。
* **交叉编译环境未配置正确:** `__init__` 方法强制要求交叉编译，如果用户没有正确配置交叉编译工具链和环境变量，会导致构建失败。
    * **举例:** 用户尝试在本地 x86 环境下编译 ARM 代码，但没有设置指向 Metrowerks ARM 编译器的路径，会导致 Meson 找不到编译器而报错。
* **使用了不支持的 Meson 选项:**  Metrowerks 编译器可能不支持某些通用的编译器选项，如果用户在 `meson.build` 文件中使用了这些选项，可能会导致构建失败或产生未知的行为。
    * **举例:** 用户可能尝试使用 `-march=` 选项来指定架构，但这可能与 Metrowerks 的 `-proc` 选项冲突。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要在 Frida 中使用 Metrowerks 编译器编译一些代码。** 这可能是 Frida 自身的一部分，也可能是用户编写的需要用特定编译器编译的 Frida 模块。
2. **用户配置了 Meson 构建系统，** 在 `meson.build` 文件中指定了使用 `mwcc` 作为 C 或 C++ 编译器。这可以通过设置 `project()` 函数的 `default_c_compiler` 或 `default_cpp_compiler` 参数来实现。
   ```python
   project('my_frida_module', 'cpp',
           version : '0.1',
           default_options : [ 'cpp_std=c++11' ],
           default_cpp_compiler : 'mwcc')
   ```
3. **用户运行 Meson 配置命令，** 例如 `meson setup builddir`。
4. **Meson 在处理构建配置时，** 会根据 `default_cpp_compiler` 的设置，加载与 `mwcc` 相关的编译器定义。
5. **由于 `mwcc` 被识别为 Metrowerks 编译器，** Meson 会加载 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/metrowerks.py` 这个文件。
6. **当需要编译 C/C++ 代码时，** Meson 会调用 `MetrowerksCompiler` 类中的方法，根据用户的构建选项（例如优化级别、调试模式、目标架构等）和源代码文件信息，生成传递给 Metrowerks 编译器的命令行参数。
7. **如果构建过程中出现错误，** 并且怀疑是编译器参数的问题，开发者可能会查看 Meson 生成的构建日志，其中会包含实际执行的编译器命令。通过分析这些命令，结合 `metrowerks.py` 文件的内容，可以推断出 Meson 是如何将抽象的构建意图转化为具体的编译器指令的，从而定位问题所在。例如，如果发现使用了错误的 `-proc` 参数，开发者可以检查 `meson.build` 文件中是否正确指定了目标架构，或者检查 `metrowerks.py` 中指令集架构的映射是否正确。

总而言之，`metrowerks.py` 是 Frida 构建系统中一个关键的组成部分，它桥接了 Meson 的抽象构建描述和 Metrowerks 编译器的具体命令行参数，确保了 Frida 可以在使用 Metrowerks 编译器编译的目标平台上正确构建。理解这个文件的功能对于调试 Frida 构建过程以及理解 Frida 如何与底层硬件和操作系统交互非常有帮助。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```