Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Context:**

The very first line provides crucial context: "这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件". This tells us:

* **Location:**  Deep within the Frida project structure. This suggests it's a lower-level component.
* **Frida:** The overarching project. Knowing Frida's purpose (dynamic instrumentation) gives a strong hint about the file's role.
* **Purpose (implicit):** Since it's in `mesonbuild/compilers/mixins`, it likely deals with compiler integration within the Meson build system.
* **Specific Compiler:** `metrowerks.py` indicates this file is specifically for handling the Metrowerks/Freescale Embedded C/C++ compiler family.

**2. Deciphering the Code Structure and Key Elements:**

* **Imports:**  The `import` statements reveal dependencies:
    * `os`: For operating system interactions (likely path manipulation).
    * `typing`: For type hinting, aiding in code readability and maintainability.
    * `...mesonlib`:  Indicates interaction with the Meson build system's internal libraries. `EnvironmentException` and `OptionKey` are hints about error handling and configuration.
    * `...compilers.compilers`:  Shows it's interacting with Meson's generic compiler infrastructure. The clever `if T.TYPE_CHECKING` block distinguishes between type-checking and runtime behavior.

* **Data Structures (Dictionaries):**  The code defines several dictionaries like `mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, etc. These immediately stand out as mapping compiler options to specific argument lists. The names of the dictionaries (`instruction_set_args`, `optimization_args`, `debug_args`) are quite self-explanatory. The keys within these dictionaries are likely the *user-facing* options, and the values are the *compiler-specific flags*.

* **The `MetrowerksCompiler` Class:**  This is the core of the file. The inheritance from `Compiler` (or `object` at runtime) confirms its role in Meson's compiler abstraction.

* **Methods of `MetrowerksCompiler`:**  The methods generally follow a pattern of `get_` followed by a specific compiler feature (e.g., `get_debug_args`, `get_include_args`, `get_optimization_args`). This suggests the class is responsible for translating generic build system requests into Metrowerks compiler commands. Methods like `depfile_for_object`, `get_dependency_gen_args`, and `get_pch_*` relate to dependency tracking and precompiled headers, common compiler functionalities.

* **`_unix_args_to_native`:** This method hints at cross-compilation and the need to potentially adapt command-line arguments for the target platform.

* **`compute_parameters_with_absolute_paths`:**  This strongly suggests handling include paths and ensuring they are absolute, which is important for reliable builds.

**3. Connecting the Dots to Frida and Reverse Engineering:**

* **Dynamic Instrumentation:** Knowing Frida's purpose, we can infer that this compiler mixin is used when Frida targets embedded systems or platforms where the Metrowerks compiler is prevalent. These are often targets for reverse engineering.
* **Compiler Flags and Target Architecture:** The dictionaries containing instruction set arguments are highly relevant to reverse engineering. Choosing the correct instruction set is crucial when disassembling and analyzing code from a target device. This mixin allows Meson to configure the compiler to produce binaries for specific ARM or PowerPC architectures commonly found in embedded systems.

**4. Considering Binary, Kernel, and Framework Aspects:**

* **Binary Level:** The entire purpose of a compiler is to generate binary code. This file directly influences how that binary code is created (instruction sets, optimization levels, debugging symbols).
* **Embedded Systems:** The mention of ARM and PowerPC architectures, along with the Metrowerks compiler itself, strongly points towards embedded systems development, which often involves interacting closely with hardware and potentially the operating system kernel. While this specific file doesn't *directly* interact with the kernel, it's part of the toolchain used to *build* software that *will* interact with the kernel.
* **Android (Less Direct):** While not explicitly mentioned, ARM architectures are common in Android. It's possible this mixin could be used in scenarios where Frida is used to instrument processes on Android running on older or specific hardware where the Metrowerks compiler might have been used historically (less likely for modern Android).

**5. Logical Reasoning, Assumptions, and Input/Output:**

* **Assumptions:**  We assume that Meson will call the appropriate `get_` methods based on user-defined build options (e.g., setting a specific architecture or optimization level).
* **Input:** User-defined options in a `meson.build` file (e.g., specifying a target architecture like `'arm7tdmi'`).
* **Processing:** Meson, using this mixin, would look up the corresponding flags in the dictionaries (e.g., `mwccarm_instruction_set_args['arm7tdmi']` would return `['-proc', 'arm7tdmi']`).
* **Output:** The generated compiler command line would include these specific flags.

**6. User Errors and Debugging:**

* **Incorrect Architecture:** A common error would be specifying an incorrect or unsupported architecture. Meson might catch this if the key doesn't exist in the dictionary, or the compiler itself might fail.
* **Missing Compiler:**  The user needs to have the Metrowerks compiler installed and accessible in their environment.

**7. Tracing User Operations (Debugging Clues):**

To get to this file during debugging, a user would likely be:

1. **Using Frida:**  They are trying to use Frida for dynamic instrumentation.
2. **Building Frida or a Frida component:** They are using Meson as the build system.
3. **Targeting an embedded platform:**  They have configured Meson to use the Metrowerks compiler. This might be done by setting environment variables or specifying a compiler in the Meson configuration.
4. **Encountering a compiler-related issue:**  The build might be failing, or the generated code might not be behaving as expected.
5. **Inspecting the build process:** They might be looking at the Meson logs or stepping through the Meson build scripts to understand how the compiler is being invoked. This would lead them to the compiler mixins and eventually to `metrowerks.py`.

This detailed thought process combines code analysis, understanding the context of the Frida project, and considering the potential use cases and error scenarios. It moves from high-level understanding to specific code details and then back to the broader implications for reverse engineering and system-level development.
这个文件 `metrowerks.py` 是 Frida 动态 instrumentation 工具中，用于集成 Metrowerks/Freescale 嵌入式 C/C++ 编译器系列的 Meson 构建系统的 mixin (混合类)。它的主要功能是**为 Meson 构建系统提供关于如何使用 Metrowerks 编译器的特定信息和方法**。

以下是它的详细功能列表，并结合你提出的几个方面进行说明：

**核心功能：**

1. **定义编译器标识:**  `id = 'mwcc'`  声明了该 mixin 针对的是 'mwcc' 编译器（Metrowerks C/C++ Compiler）。

2. **声明不支持链接器调用:** `INVOKES_LINKER = False` 表明这个 mixin 建议不要直接使用 Metrowerks 编译器进行链接，通常会使用专门的链接器。

3. **配置基本构建选项:** `base_options = {OptionKey(o) for o in ['b_pch', 'b_ndebug']}`  指定了该编译器支持的 Meson 基本构建选项，例如预编译头 (`b_pch`) 和非调试构建 (`b_ndebug`)。

4. **配置警告级别:**  `warn_args` 字典定义了不同警告级别对应的编译器参数，例如关闭警告、显示所有警告等。

5. **生成依赖文件:** `depfile_for_object` 方法定义了如何根据目标文件名称生成依赖文件名称，这对于增量编译至关重要。

6. **提供常用编译参数:**  定义了各种场景下需要传递给编译器的参数，例如：
    * `get_always_args`:  始终传递的参数，例如 `-gccinc`。
    * `get_compile_only_args`:  仅编译的参数，例如 `-c`。
    * `get_debug_args`:  调试模式下的参数，例如 `-g`。
    * `get_dependency_gen_args`:  生成依赖文件的参数，例如 `'-gccdep', '-MD'`。
    * `get_include_args`:  包含头文件目录的参数，例如 `-I/path/to/headers`。
    * `get_no_optimization_args`:  关闭优化的参数，例如 `-opt off`。
    * `get_optimization_args`:  不同优化级别的参数，例如 `-O0`, `-O1`, `-O2` 等。
    * `get_output_args`:  指定输出文件名的参数，例如 `-o output.o`。
    * `get_pic_args`:  生成位置无关代码 (PIC) 的参数，例如 `-pic`。
    * `get_preprocess_only_args`:  仅预处理的参数，例如 `-E`。
    * `get_pch_use_args`:  使用预编译头的参数，例如 `-prefix myheader.h.mch`。
    * `get_warn_args`:  根据警告级别获取参数。
    * `get_werror_args`:  将警告视为错误的参数，例如 `'-w', 'error'`。

7. **处理交叉编译:**  `__init__` 方法中检查 `is_cross` 属性，确保该 mixin 仅在交叉编译场景下使用。

8. **转换参数:** `_unix_args_to_native` 方法尝试将 Unix 风格的参数转换为 Metrowerks 编译器能够理解的格式，尽管它目前主要是在过滤某些链接器相关的参数。

9. **处理绝对路径:** `compute_parameters_with_absolute_paths` 方法用于确保 include 目录的路径是绝对路径。

**与逆向方法的关系及举例：**

* **目标架构指定:**  `mwccarm_instruction_set_args`, `mwcceppc_instruction_set_args`, `mwasmarm_instruction_set_args`, `mwasmeppc_instruction_set_args` 这些字典允许指定目标处理器的架构和指令集。在逆向工程中，了解目标设备的 CPU 架构至关重要。
    * **举例:**  如果逆向工程师知道目标设备使用 ARMv7-A 架构，他们可能会在 Frida 的构建配置中设置相应的指令集，Meson 构建系统会通过 `mwccarm_instruction_set_args['v6']` (假设 'v6' 代表 ARMv7-A) 获取编译器参数 `['-proc', 'v6']`，确保编译出的 Frida 组件能在目标架构上运行。

* **编译选项控制:**  通过 `mwcc_optimization_args` 和 `mwcc_debug_args` 可以控制编译器的优化级别和调试信息的生成。
    * **举例:**  为了方便调试和分析目标程序，逆向工程师可能会选择较低的优化级别 (`'0'`)，Meson 会传递 `-O0` 参数给编译器，减少代码混淆，方便单步调试。反之，为了更接近最终发布版本的性能特征，可能会选择较高的优化级别。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

* **目标架构指令集:**  `mwccarm_instruction_set_args` 和 `mwcceppc_instruction_set_args` 等字典中定义的各种架构名称（如 'arm7tdmi', 'e500'）直接对应了底层的 CPU 指令集架构。理解这些架构对于理解反汇编代码至关重要。
* **交叉编译环境:**  这个 mixin 的存在本身就暗示了 Frida 在某些场景下需要进行交叉编译，即在一个平台上编译出在另一个平台（通常是嵌入式设备或移动设备）上运行的代码。这涉及到对目标平台的 ABI (Application Binary Interface) 和系统调用的理解。
* **Android 的可能关联 (间接):** 虽然 Metrowerks 编译器主要用于嵌入式系统，但早期的 Android 设备可能也使用了类似的工具链。Frida 可以用于在 Android 系统上进行动态 instrumentation，理解目标 Android 设备的架构和编译方式有助于更好地使用 Frida。
* **位置无关代码 (PIC):** `get_pic_args` 方法返回 `['-pic']` 参数。PIC 对于在动态链接库 (如 Android 的 `.so` 文件) 中加载代码至关重要，因为它允许代码在内存中的任意位置加载而无需修改。

**逻辑推理及假设输入与输出：**

* **假设输入:** 用户在 Meson 构建配置中指定使用 'mwcc' 编译器，并设置了优化级别为 '2'。
* **逻辑推理:** Meson 构建系统会识别出使用了 `MetrowerksCompiler` 这个 mixin，然后调用 `get_optimization_args('2')` 方法。
* **输出:**  `get_optimization_args('2')` 方法会返回 `['-O2']`。这个参数会被添加到传递给 Metrowerks 编译器的命令行中。

* **假设输入:** 用户需要为 ARMv5TE 架构编译。
* **逻辑推理:** Meson 构建系统会调用相应的代码，从 `mwccarm_instruction_set_args` 字典中查找键 'v5te'。
* **输出:**  `mwccarm_instruction_set_args['v5te']` 会返回 `['-proc', 'v5te']`。

**涉及用户或编程常见的使用错误及举例：**

* **指定不存在的架构:** 如果用户在构建配置中指定了一个 `mwccarm_instruction_set_args` 字典中不存在的架构名称（例如，拼写错误或者目标编译器不支持的架构），Meson 构建系统可能会抛出错误，因为它无法找到对应的编译器参数。
    * **举例:** 用户错误地将架构设置为 'armv8'，但 `mwccarm_instruction_set_args` 中没有 'armv8' 这个键，会导致构建失败。

* **交叉编译环境未配置:**  如果用户尝试使用这个 mixin 进行编译，但没有正确配置交叉编译环境（例如，没有安装 Metrowerks 编译器或将其路径添加到环境变量），Meson 会因为找不到编译器而报错。

* **与其他编译器选项冲突:** 用户可能错误地使用了与 Metrowerks 编译器选项冲突的 Meson 构建选项，导致编译器报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要在目标嵌入式设备上使用 Frida。**
2. **目标设备的编译器是 Metrowerks/Freescale 的某个版本。**
3. **用户开始构建 Frida，并指定使用 'mwcc' 编译器。**  这通常会在 Meson 的构建配置文件 (meson.build 或命令行参数) 中完成。
4. **Meson 构建系统会根据指定的编译器，加载相应的编译器 mixin，也就是 `metrowerks.py`。**
5. **在构建过程中，Meson 需要知道如何调用 Metrowerks 编译器，以及传递哪些参数。**  这时，`metrowerks.py` 中定义的各种 `get_` 方法会被调用，例如：
    * 获取包含目录：`get_include_args`
    * 设置优化级别：`get_optimization_args`
    * 指定目标架构：通过查找 `mwccarm_instruction_set_args` 等字典。
6. **如果构建过程中出现与编译器相关的错误，用户可能会查看 Meson 的构建日志。**  日志中会显示 Meson 构建系统生成的编译器命令行。
7. **为了理解为什么某个特定的编译器参数被添加到命令行中，或者为什么构建失败，用户可能会追溯到 Meson 的源代码，最终找到负责处理 Metrowerks 编译器的 `metrowerks.py` 文件。**
8. **用户可能会阅读这个文件的代码，理解各种字典和方法的作用，从而找到构建问题的根源。**  例如，他们可能会发现自己指定的架构名称在 `mwccarm_instruction_set_args` 中不存在。
9. **或者，如果编译器报错，用户可能会查看传递给编译器的参数，并对照 `metrowerks.py` 中的定义，来判断 Meson 是否正确地生成了这些参数。**

总而言之，`metrowerks.py` 是 Frida 使用 Meson 构建系统来支持 Metrowerks 编译器的关键组件，它封装了与该编译器交互的特定逻辑和参数，使得 Frida 可以在基于 Metrowerks 编译器的嵌入式平台上进行构建和部署，这对于针对这些平台的逆向工程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/mixins/metrowerks.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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