Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Core Purpose:**

The first step is to recognize the context. The filename `metrowerks.py` within a `compilers/mixins` directory strongly suggests this code is related to compiler integration within a larger build system. The `fridaDynamic instrumentation tool` mention confirms it's used by Frida. The copyright notice for "The Meson development team" points to the Meson build system. Therefore, the primary function is likely to provide Metrowerks compiler-specific behavior within Meson.

**2. Identifying Key Data Structures:**

Next, examine the top-level data structures. The dictionaries `mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, etc., clearly map symbolic names (like 'v4', '401', 'arm4') to compiler command-line arguments (`['-proc', 'v4']`). This immediately signals that the code handles different target architectures and processor configurations for the Metrowerks compiler. The dictionaries `mwcc_optimization_args` and `mwcc_debug_args` show how optimization and debugging levels are translated to compiler flags.

**3. Analyzing the `MetrowerksCompiler` Class:**

The core logic resides in the `MetrowerksCompiler` class. Focus on its methods and attributes:

* **`id = 'mwcc'`**:  A unique identifier for this compiler.
* **`INVOKES_LINKER = False`**: A crucial piece of information indicating that Metrowerks compiler doesn't handle linking well in this context, so a separate linker invocation is preferred.
* **`__init__`**: Initializes the object, crucially checking if it's a cross-compilation scenario. This gives a strong hint that Frida using this is likely targeting embedded systems.
* **`base_options`**: Defines Meson's build options that this compiler cares about.
* **`warn_args`**:  Maps warning levels to compiler flags.
* **Methods like `depfile_for_object`, `get_always_args`, `get_compile_only_args`, etc.**: These methods follow a common pattern. They take some input (e.g., output filename, debug flag) and return the appropriate compiler command-line arguments. This pattern is typical of build system integrations where compiler flags need to be generated dynamically. Pay attention to specific flags like `-gccinc`, `-c`, `-g`, `-MD`, `-I`, `-o`, `-pic`, `-E`, `-P`, `-prefix`, `-w`.
* **`_unix_args_to_native`**: This method suggests a translation or filtering of command-line arguments, potentially because the build system might use a Unix-style argument representation internally, which needs to be adapted for the native Metrowerks compiler. The filtering of `-Wl,-rpath=`, `--print-search-dirs`, and `-L` indicates linker-specific flags are being removed, reinforcing the `INVOKES_LINKER = False` attribute.
* **`compute_parameters_with_absolute_paths`**: This is about handling include paths, ensuring they are absolute by prepending the build directory.

**4. Connecting to Frida and Reverse Engineering:**

Now, consider how this code relates to Frida. Frida is used for dynamic instrumentation. This Metrowerks compiler integration enables Frida to build components that run *inside* the target process being instrumented.

* **Cross-Compilation:** The `is_cross` check in `__init__` is key. Frida often targets embedded devices (like those running on ARM or PowerPC architectures), which necessitates cross-compilation.
* **Target Architectures:** The instruction set argument dictionaries directly map to specific CPU architectures. This is vital for Frida to build code that runs correctly on the target device.
* **Position Independent Code (`-pic`)**:  This is frequently used when building shared libraries or code that needs to be loaded at arbitrary memory addresses, which is common in dynamic instrumentation scenarios.
* **Debugging (`-g`)**:  While not always used in release builds, debug symbols are crucial for Frida's instrumentation capabilities, allowing inspection and modification of code at runtime.

**5. Inferring User Actions and Debugging:**

Consider how a user would end up needing this code. They would likely be:

1. **Configuring a Frida build:** This involves specifying the target architecture and compiler.
2. **Using Meson:**  Meson is the build system, so the user interacts with Meson commands to configure and build Frida.
3. **Targeting an embedded system:** The use of Metrowerks strongly suggests an embedded target.

Debugging scenarios arise when the build fails. The stack trace pointing to this file would indicate a problem with the Metrowerks compiler integration.

**6. Formulating Examples and Explanations:**

Based on the analysis, construct concrete examples and explanations for each requested point:

* **Reverse Engineering:** Focus on how target architecture selection impacts the compiled code, enabling Frida to interact with the target's instructions.
* **Binary/Kernel/Framework:** Explain the low-level nature of the instruction set arguments and how cross-compilation builds code for a different architecture.
* **Logic and Assumptions:**  Provide a simple example of how optimization level changes the compiler flags.
* **User Errors:**  Highlight the cross-compilation requirement as a potential pitfall.
* **Debugging:**  Describe the steps leading to encountering this file during a build error.

**7. Refining the Language:**

Ensure the language is clear, concise, and addresses each aspect of the prompt directly. Use technical terms accurately and explain their significance in the context of Frida and reverse engineering. Structure the answer logically with headings for better readability.

By following this thought process, we can systematically analyze the code and generate a comprehensive and accurate response.
这个文件 `metrowerks.py` 是 Frida 动态 instrumentation 工具中，用于集成 Metrowerks/Freescale 嵌入式 C/C++ 编译器系列的模块。它定义了如何使用这些特定的编译器来编译 Frida 的组件。  本质上，它是一个 Meson 构建系统（Frida 使用的构建系统）的插件，用于处理 Metrowerks 编译器的特定语法和选项。

以下是它的主要功能：

**1. 定义 Metrowerks 编译器的标识:**

*   `id = 'mwcc'`：  明确了这个模块处理的是名为 'mwcc' 的编译器家族。

**2. 指示不处理链接:**

*   `INVOKES_LINKER = False`：说明这个编译器配置主要负责编译源代码生成目标文件（.o 等），而不是最终的链接步骤。链接通常由 Meson 或另一个工具来处理。

**3. 强制交叉编译:**

*   在 `__init__` 方法中，如果不是交叉编译，则会抛出 `EnvironmentException`。这表明 Frida 使用 Metrowerks 编译器时，通常针对的是目标架构与构建主机不同的场景，即交叉编译。

**4. 管理编译器选项:**

*   **指令集选项:**  定义了不同 ARM 和 PowerPC 架构的指令集选项 (`mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, `mwasmarm_instruction_set_args`, `mwasmeppc_instruction_set_args`)。例如，将字符串 'v4t' 映射到 `['-proc', 'v4t']` 编译器参数。
*   **优化级别选项:**  定义了不同优化级别的编译器参数 (`mwcc_optimization_args`)，如 '-O0'，'-O1' 等。
*   **调试选项:**  定义了是否启用调试信息的编译器参数 (`mwcc_debug_args`)，即 `-g`。
*   **警告选项:**  定义了不同警告级别的编译器参数 (`warn_args`)。

**5. 生成构建所需的编译器命令行参数:**

*   提供了各种方法来生成特定的编译器参数，例如：
    *   `get_always_args()`:  返回始终需要的参数，如 `['-gccinc']`。
    *   `get_compile_only_args()`: 返回只编译不链接的参数 `['-c']`。
    *   `get_debug_args(is_debug)`: 根据是否启用调试返回相应的参数。
    *   `get_dependency_gen_args(outtarget, outfile)`: 返回生成依赖文件（用于增量编译）的参数 `['-gccdep', '-MD']`。
    *   `get_include_args(path, is_system)`: 返回包含头文件路径的参数 `['-I' + path]`。
    *   `get_optimization_args(optimization_level)`: 返回指定优化级别的参数。
    *   `get_output_args(outputname)`: 返回指定输出文件名的参数 `['-o', outputname]`。
    *   `get_pic_args()`: 返回生成位置无关代码的参数 `['-pic']`，这对于共享库非常重要。
    *   `get_preprocess_only_args()`: 返回只预处理的参数 `['-E']`。
    *   `get_pch_use_args(pch_dir, header)`: 返回使用预编译头文件的参数。
    *   `get_warn_args(level)`: 返回指定警告级别的参数。
    *   `get_werror_args()`: 返回将警告视为错误的参数 `['-w', 'error']`。

**6. 处理平台特定的参数转换:**

*   `_unix_args_to_native(cls, args, info)`:  这个方法用于将类似 Unix 的命令行参数转换为 Metrowerks 编译器能够理解的格式。它会过滤掉一些链接器相关的参数（因为 `INVOKES_LINKER` 是 False），并调整一些参数的格式，例如将 `-D` 和 `-I` 前缀保持不变。

**7. 处理绝对路径:**

*   `compute_parameters_with_absolute_paths(self, parameter_list: T.List[str], build_dir: str)`:  这个方法确保包含路径（以 `-I` 开头的参数）是绝对路径，通过将构建目录添加到相对路径前。

**与逆向方法的关联及举例说明:**

这个文件本身不直接执行逆向操作，但它是构建 Frida 组件的关键部分，而 Frida 正是一个强大的动态逆向工具。

*   **目标架构选择:**  逆向工程常常需要针对特定的目标架构（例如 ARM、PowerPC）。`mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 等字典允许 Frida 构建系统根据目标设备的 CPU 架构选择正确的 Metrowerks 编译器选项。例如，如果逆向目标是一个基于 ARMv7 的嵌入式设备，Frida 构建时可能会选择 'armv7' 对应的指令集参数，最终传递给 Metrowerks 编译器类似于 `mwcc -proc armv7 ...`。这确保了生成的 Frida 代码能在目标设备上正确执行。

*   **位置无关代码 (PIC):**  当 Frida 需要注入到目标进程时，生成的代码通常需要是位置无关的。`get_pic_args()` 返回 `['-pic']` 选项，确保 Metrowerks 编译器生成可以加载到任意内存地址的代码。这对于动态注入和代码插桩至关重要。

*   **调试符号:**  在逆向分析过程中，调试符号非常有用。`get_debug_args(True)` 返回 `['-g']` 选项，指示 Metrowerks 编译器在生成的目标文件中包含调试信息。这样，逆向工程师可以使用 GDB 或其他调试器来分析 Frida 在目标进程中的行为。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

*   **二进制底层:**  `mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 字典直接对应于不同的 CPU 指令集架构。例如，'arm7tdmi'、'arm920t' 是特定的 ARM 处理器架构，而 '401'、'603e' 是 PowerPC 处理器架构。选择正确的指令集确保编译器生成的目标代码能够在该特定架构的 CPU 上执行。这直接涉及到二进制指令的编码和处理器的执行方式。

*   **交叉编译:**  Metrowerks 编译器常用于嵌入式开发，这通常意味着交叉编译。Frida 需要在开发主机上编译出能在目标设备上运行的代码。这个文件强制进行交叉编译，说明 Frida 使用 Metrowerks 时，目标平台很可能不是运行构建过程的平台。这与嵌入式 Linux 或 Android 设备的开发场景密切相关。

*   **位置无关代码 (-pic):**  在 Linux 和 Android 等操作系统中，共享库（.so 文件）通常需要是位置无关的，才能在不同的内存地址加载而不会发生冲突。`get_pic_args()` 方法生成的 `-pic` 参数确保了编译出的 Frida 组件可以作为共享库加载到目标进程中，这是动态 instrumentation 的基础。

**逻辑推理及假设输入与输出:**

假设用户在配置 Frida 构建时，指定使用 Metrowerks ARM 编译器，并设置了优化级别为 '2'，启用了调试信息。

*   **假设输入:**
    *   编译器类型: Metrowerks ARM
    *   优化级别: '2'
    *   调试: True

*   **逻辑推理:**
    1. Meson 构建系统会识别出需要使用 `metrowerks.py` 模块。
    2. 调用 `get_optimization_args('2')`，返回 `['-O2']`。
    3. 调用 `get_debug_args(True)`，返回 `['-g']`。
    4. 最终，Metrowerks 编译器会被调用时，命令行参数中会包含 `-O2` 和 `-g`。

*   **假设输出 (部分编译器命令行):**
    ```
    mwcc <其他参数> -O2 -g <源文件> -o <目标文件>
    ```

**涉及用户或编程常见的使用错误及举例说明:**

*   **尝试在非交叉编译环境下使用 Metrowerks 编译器:**  由于 `__init__` 方法中检查了 `self.is_cross`，如果用户在配置 Frida 构建时，错误地设置了目标平台与构建平台相同，或者 Meson 没有正确检测到是交叉编译环境，将会导致 `EnvironmentException` 异常抛出，提示用户 Metrowerks 编译器只能用于交叉编译。

    **用户操作步骤导致错误:**
    1. 用户在配置 Frida 构建时，没有正确设置目标平台参数。
    2. Meson 执行配置阶段，调用 `MetrowerksCompiler` 的 `__init__` 方法。
    3. `self.is_cross` 为 False (错误地认为不是交叉编译)。
    4. 抛出 `EnvironmentException('mwcc supports only cross-compilation.')`。

*   **缺少 Metrowerks 编译器环境:**  如果用户指定使用 Metrowerks 编译器，但系统环境变量中没有配置正确的编译器路径，Meson 在尝试执行编译器时会失败。虽然这个文件本身不直接处理这种情况，但它是使用 Metrowerks 编译器的前提。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当 Frida 的构建过程中出现与 Metrowerks 编译器相关的错误时，开发者或用户可能会查看这个文件以了解问题根源。以下是一种可能的操作路径：

1. **用户尝试构建 Frida:**  用户执行类似 `meson setup build --default-library=shared -Dfrida_target_backend=qml ...` 的命令来配置 Frida 的构建。
2. **配置选择 Metrowerks 编译器:**  在配置过程中，用户可能通过 Meson 的配置选项（例如，设置 C 或 C++ 编译器为 Metrowerks 编译器的路径），或者 Meson 自动检测到 Metrowerks 编译器可用并选择使用。
3. **构建过程出错:**  在 `meson compile -C build` 构建阶段，如果涉及到使用 Metrowerks 编译器编译某些组件，并且遇到了错误（例如，编译器选项不正确，找不到头文件等），构建过程会失败并显示错误信息。
4. **查看构建日志:**  用户会查看构建日志，其中可能包含调用 Metrowerks 编译器的完整命令。
5. **识别涉及 Metrowerks 的构建步骤:**  通过日志，用户可以确定是哪个构建步骤使用了 Metrowerks 编译器。
6. **查找 Metrowerks 编译器集成代码:**  由于 Frida 使用 Meson 构建系统，用户可能会查找与 Metrowerks 编译器集成相关的代码。根据目录结构，他们会找到 `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/mixins/metrowerks.py` 这个文件。
7. **分析 `metrowerks.py`:**  用户会查看这个文件，了解 Frida 如何配置和调用 Metrowerks 编译器，例如检查指令集选项、优化级别、包含路径等，以找出构建失败的原因。他们可能会检查 `get_*_args` 方法，看生成的编译器参数是否正确。
8. **调试和修复:**  根据分析，用户可能会修改构建配置，更新 Metrowerks 编译器的路径，或者修改 `metrowerks.py` 文件（如果他们认为默认的配置有错误），然后重新尝试构建。

总而言之，`metrowerks.py` 文件是 Frida 构建系统中处理特定嵌入式编译器的关键模块，它通过定义编译器选项和参数，使得 Frida 能够在各种嵌入式平台上进行构建，从而支持对这些平台进行动态 instrumentation 和逆向分析。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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