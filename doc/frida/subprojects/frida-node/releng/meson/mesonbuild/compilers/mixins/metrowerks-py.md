Response:
Let's break down the thought process for analyzing the provided Python code.

**1. Understanding the Request:**

The request asks for a functional breakdown of the Python code, specifically focusing on its relevance to reverse engineering, low-level details (kernels, frameworks), logical reasoning, common usage errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and Identification of Key Components:**

The first step is to quickly read through the code, identifying the main elements:

* **License and Copyright:** Standard preamble, indicating the code's open-source nature.
* **Imports:**  `os`, `typing`, `EnvironmentException`, `OptionKey`, `MachineInfo`, `Compiler`, `CompileCheckMode`. These imports hint at the code's purpose within a larger build system. `typing` strongly suggests this code deals with types and compiler configurations.
* **Instruction Set Dictionaries:** `mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, `mwasmarm_instruction_set_args`, `mwasmeppc_instruction_set_args`. These dictionaries map architecture names to compiler flags. This is a strong indicator of compiler-specific configurations.
* **Optimization and Debug Dictionaries:** `mwcc_optimization_args`, `mwcc_debug_args`. These map optimization levels and debug settings to compiler flags. Another sign of compiler configuration.
* **`MetrowerksCompiler` Class:**  This is the core of the code. It inherits from `Compiler` (or pretends to for type checking) and defines various methods. The `id = 'mwcc'` confirms this class is specific to the Metrowerks compiler.
* **Methods within `MetrowerksCompiler`:**  These methods have names that are highly suggestive of compiler functionality: `depfile_for_object`, `get_always_args`, `get_compiler_check_args`, `get_compile_only_args`, `get_debug_args`, `get_dependency_gen_args`, etc. This confirms the code's role in generating compiler commands.
* **`_unix_args_to_native` Method:**  This method deals with converting Unix-style command-line arguments to a "native" format, implying cross-compilation.
* **`compute_parameters_with_absolute_paths` Method:** This method manipulates paths, suggesting it ensures correct path resolution during the build process.

**3. High-Level Functionality Deduction:**

Based on the identified components, the primary function of this code is to provide a **Mix-in** (as indicated by the file path) for the **Meson build system** to support the **Metrowerks compiler**. This mix-in defines how Meson should interact with the Metrowerks compiler, specifying the correct command-line flags for various build configurations (architecture, optimization, debugging, etc.).

**4. Connecting to Reverse Engineering:**

* **Instruction Set Selection:** The dictionaries mapping architecture names to flags are directly relevant. Reverse engineers often need to understand the target architecture and its specific instruction set. This code shows *how* a build system targets specific architectures.
* **Optimization Levels:**  Knowing the optimization level used to build a binary is crucial for reverse engineering. Highly optimized code can be more difficult to analyze. This code reveals the compiler flags used for different optimization levels.
* **Debugging Information:** The `-g` flag enables debugging symbols. Reverse engineers rely on these symbols (if present) for easier analysis. This code manages the inclusion of this flag.

**5. Connecting to Low-Level Details (Kernel, Framework):**

* **Cross-Compilation:** The `is_cross` check and the `_unix_args_to_native` method point to cross-compilation scenarios, where you build code for a different target platform than the one you're building on. This is very common in embedded systems and mobile development (like Android), where you might build on a Linux machine for an ARM-based Android device.
* **Architecture-Specific Flags:** The numerous instruction set options highlight the need to target specific CPU architectures, common in embedded and kernel development.
* **No Standard Libraries:** The `get_no_stdlib_link_args` method is relevant to environments where standard libraries might not be available or desired (e.g., bootloaders, very minimal embedded systems).

**6. Logical Reasoning (Hypothetical Input/Output):**

* **Scenario:** A user wants to compile code for an ARM Cortex-M4 processor with maximum optimization and debugging enabled.
* **Input (within Meson):**  The user would likely configure their Meson build with options like `buildtype=debugoptimized`, `cpu_family=arm`, `cpu=cortex-m4` (or similar, depending on how Meson handles these).
* **Output (from this code):** The `get_optimization_args` method would return `['-O4,p']` (assuming '3' maps to the highest optimization), and `get_debug_args` would return `['-g']`. The `get_always_args` would likely return `['-gccinc']`. The `mwccarm_instruction_set_args` dictionary would be used to select the appropriate `-proc` flag (though "cortex-m4" isn't explicitly there, a close match or a generic ARM option would be chosen).

**7. Common Usage Errors:**

* **Incorrect Architecture:** Specifying the wrong CPU architecture in the Meson configuration would lead to incorrect compiler flags being used, potentially resulting in non-functional or poorly performing code. Meson would likely pass this incorrect information down, and this Python code would generate flags based on that incorrect input.
* **Missing Compiler:** If the Metrowerks compiler isn't installed or correctly configured in the system's PATH, Meson wouldn't be able to find and execute it. This Python code assumes the compiler exists. The error would likely occur *before* this Python code is heavily involved, during Meson's initial setup.
* **Conflicting Options:** Users might try to combine conflicting optimization or debugging options, though Meson usually has mechanisms to prevent this. However, it's conceivable that a complex configuration could lead to unexpected flag combinations.

**8. User Interaction and Debugging Clues:**

* **User Action:** A user would typically interact with Meson through the command line (`meson setup builddir`, `ninja`) or through a higher-level build system that uses Meson.
* **Reaching this code:**  When Meson detects that the project requires the Metrowerks compiler (likely based on a `project()` declaration in the `meson.build` file), it will load this `metrowerks.py` file to understand how to use that compiler.
* **Debugging:** If a build fails with the Metrowerks compiler, a developer might need to examine the exact compiler commands being generated by Meson. This could involve looking at Meson's log output or using verbose build options. Understanding this `metrowerks.py` file helps decipher how those commands are constructed. Specifically, knowing how the instruction set, optimization, and debug settings are translated into flags is crucial for debugging.

By following these steps, we can systematically analyze the code and address all aspects of the request. The process involves understanding the code's purpose, identifying key relationships (e.g., architecture to flags), and then making connections to the broader context of reverse engineering, low-level development, and the user's interaction with the build system.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/metrowerks.py` 这个文件。

**文件功能概述：**

这个 Python 文件是 Frida 项目中用于集成 Metrowerks/Freescale 嵌入式 C/C++ 编译器系列的 Meson 构建系统 mixin。它的主要功能是：

1. **定义特定于 Metrowerks 编译器的命令行参数：**  它为不同的编译选项（如目标架构、优化级别、调试信息等）定义了 Metrowerks 编译器所需的特定命令行参数。
2. **处理交叉编译：**  它特别针对交叉编译场景，因为 Metrowerks 编译器通常用于嵌入式开发，即在主机上编译运行在目标设备上的代码。
3. **与 Meson 构建系统集成：**  作为 Meson 的 mixin，它扩展了 Meson 对 Metrowerks 编译器的支持，使得 Meson 能够正确地调用和配置该编译器。

**与逆向方法的关系及举例说明：**

这个文件本身不是一个直接的逆向工具，但它描述了如何使用 Metrowerks 编译器构建软件。了解构建过程和编译器选项对于逆向分析至关重要。

* **目标架构了解：**  `mwccarm_instruction_set_args`、`mwcceppc_instruction_set_args` 等字典定义了支持的 ARM 和 PowerPC 架构。逆向工程师需要知道目标设备的 CPU 架构，才能理解其指令集和执行方式。例如，如果逆向一个运行在 Freescale i.MX 系列处理器上的固件，而该处理器使用 ARMv7 架构，那么在 `mwccarm_instruction_set_args` 中找到对应的选项（如 `arm7tdmi` 或更高级的）可以帮助理解编译时可能使用的指令集特性。
* **优化级别分析：** `mwcc_optimization_args` 定义了不同的优化级别 (`-O0`, `-O1`, `-O2` 等)。了解编译时使用的优化级别有助于逆向工程师理解代码结构。例如，如果代码使用了 `-O2` 或更高的优化级别，那么函数可能会被内联，循环可能会被展开，导致代码结构与源代码差异较大，增加了逆向的难度。
* **调试信息存在性：** `mwcc_debug_args` 定义了是否包含调试信息的选项 (`-g`)。如果目标二进制文件在编译时包含了调试信息，逆向工程师可以使用 GDB 等调试器进行更方便的分析，例如设置断点、查看变量值等。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明：**

虽然这个文件本身不直接操作二进制或内核，但它与这些领域密切相关：

* **目标架构和指令集 (二进制底层)：**  文件中定义的各种 ARM 和 PowerPC 架构（例如 `arm7tdmi`, `e500`）直接对应于底层的 CPU 指令集。了解这些指令集是逆向二进制代码的基础。例如，知道目标是 `arm7tdmi`，逆向工程师就能预期看到 Thumb 或 ARM 指令，并使用相应的工具进行反汇编和分析。
* **交叉编译 (Linux/Android)：**  Frida 经常用于动态分析 Android 应用和系统服务。这个文件支持 Metrowerks 编译器的交叉编译，意味着可以使用 Linux 主机上的 Metrowerks 编译器为 Android 设备上的特定架构（通常是 ARM）编译代码。
* **编译器标志对 ABI 的影响：**  某些编译器标志可能会影响应用程序二进制接口 (ABI)，这决定了函数调用约定、数据布局等。虽然这个文件没有显式地展示 ABI 相关的标志，但了解编译器选项有助于理解目标二进制文件可能遵循的 ABI 约定，这对于逆向分析和与目标系统交互至关重要。

**逻辑推理、假设输入与输出：**

假设 Meson 构建系统在配置 Frida 的 Node.js 绑定时，检测到需要使用 Metrowerks 编译器，并且目标架构是 ARMv5TE。

* **假设输入：**  Meson 配置中指定了使用 Metrowerks 编译器，并且目标机器信息 (MachineInfo) 指明了 CPU 架构为 "armv5te"。
* **逻辑推理：**
    1. Meson 会加载 `metrowerks.py` 这个 mixin。
    2. 当需要生成编译 ARM 代码的命令行参数时，Meson 会调用 `mwccarm_instruction_set_args` 字典。
    3. Meson 会查找与 "armv5te" 最匹配的键。
* **假设输出：** `mwccarm_instruction_set_args['v5te']` 将被选中，输出为 `['-proc', 'v5te']`。这个参数会被添加到 Metrowerks 编译器的命令行中，指示编译器生成 ARMv5TE 架构的代码。

**涉及用户或编程常见的使用错误及举例说明：**

* **指定错误的架构：**  用户在配置 Meson 时，如果错误地指定了目标架构，例如，目标设备是 ARMv7，但用户指定了 "armv4"，那么 Meson 会使用 `mwccarm_instruction_set_args['v4']`，导致生成的代码可能无法在目标设备上正确运行。
* **编译器未正确配置：** 如果用户的系统上没有安装 Metrowerks 编译器，或者编译器路径没有正确配置，Meson 将无法找到编译器，导致构建失败。错误信息可能指示找不到 `mwcc` 命令。
* **使用了不支持的编译器选项：** 用户可能尝试在 Meson 中使用一些 Metrowerks 编译器特有的选项，但这些选项没有在这个 mixin 中定义。这可能会导致 Meson 无法识别这些选项，或者将它们传递给编译器时出错。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户尝试构建 Frida 的 Node.js 绑定：** 用户通常会克隆 Frida 的仓库，然后进入 `frida/frida-node` 目录，并尝试使用 Meson 进行构建，例如执行 `meson setup build --backend=ninja` 或类似的命令。
2. **Meson 解析构建配置：** Meson 会读取 `meson.build` 文件，其中会指定构建目标、依赖项和使用的编译器。如果 `meson.build` 文件中指定了需要使用 Metrowerks 编译器（这通常通过条件判断或环境变量来实现，例如针对特定的嵌入式平台），Meson 会开始处理与该编译器相关的配置。
3. **加载编译器 Mixin：** Meson 会根据识别到的编译器类型（Metrowerks）查找并加载对应的 mixin 文件，也就是 `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/metrowerks.py`。
4. **配置编译器参数：** Meson 会调用这个 mixin 中定义的方法，例如 `get_always_args`、`get_optimization_args`、`get_debug_args` 等，来获取构建过程中需要传递给 Metrowerks 编译器的命令行参数。这些参数的生成取决于 Meson 的配置选项、目标平台信息以及这个 mixin 中定义的映射关系。
5. **生成构建文件：** Meson 会根据获取到的编译器参数和构建配置，生成实际的构建文件（例如 Ninja 的 `build.ninja` 文件）。
6. **执行构建命令：** 用户执行 `ninja` 命令后，Ninja 会读取生成的构建文件，并调用 Metrowerks 编译器，并将之前生成的命令行参数传递给编译器。

**作为调试线索：**

* **构建失败信息：** 如果构建失败，错误信息可能会指示 Metrowerks 编译器返回了非零的退出码，或者找不到编译器。这可以引导开发者检查 Metrowerks 编译器是否正确安装和配置。
* **Meson 日志：** Meson 在执行过程中会输出详细的日志信息，包括它调用的编译器命令及其参数。查看 Meson 的日志可以帮助开发者确认是否使用了正确的编译器 mixin，以及生成的编译器参数是否符合预期。例如，可以检查 `-proc` 参数是否与目标架构匹配，`-O` 参数是否指定了期望的优化级别，`-g` 参数是否存在等。
* **检查 `metrowerks.py` 文件内容：** 如果怀疑是编译器 mixin 的配置问题导致构建失败，开发者可以直接查看 `metrowerks.py` 文件的内容，检查其中定义的架构映射、优化级别映射等是否正确。
* **环境变量和 Meson 配置：**  检查构建过程中使用的环境变量和 Meson 的配置选项，确保它们与目标平台和编译器要求一致。例如，可能需要设置特定的环境变量来指定 Metrowerks 编译器的路径。

总而言之，`metrowerks.py` 这个文件虽然不是直接的逆向工具，但它描述了 Frida 项目如何使用 Metrowerks 编译器构建代码，理解它的功能和配置对于逆向基于 Metrowerks 编译器构建的固件或软件至关重要，并且在调试 Frida 的构建过程时也是一个重要的线索。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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