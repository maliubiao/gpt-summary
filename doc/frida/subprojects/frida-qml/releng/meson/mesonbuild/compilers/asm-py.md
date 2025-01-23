Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `asm.py` file within the Frida project and relate it to reverse engineering, low-level details, and potential user errors, all while explaining how a user might reach this code.

**2. Initial Skim and Identification of Key Classes:**

A quick scan reveals several classes inheriting from `Compiler`: `NasmCompiler`, `YasmCompiler`, `MasmCompiler`, `MasmARMCompiler`, `MetrowerksAsmCompiler`, `MetrowerksAsmCompilerARM`, and `MetrowerksAsmCompilerEmbeddedPowerPC`. The presence of multiple compiler classes suggests this file deals with different assembly language compilers.

**3. Focusing on the Base Class: `Compiler`:**

The `Compiler` class (imported but not fully defined in this snippet) is clearly the foundation. The derived classes are specializations for specific assemblers. This immediately suggests the file's primary function is to provide a standardized interface for interacting with various assembly compilers within the Meson build system.

**4. Analyzing Individual Compiler Classes:**

For each compiler class, I'd look for the following:

* **`language` and `id`:** These attributes clearly identify the assembly language and the compiler's internal name within Meson.
* **`get_always_args`:**  These are arguments always passed to the assembler. Looking at the logic in `NasmCompiler`'s `get_always_args` (handling Windows, macOS, and Linux ELF formats) reveals the connection to different operating system conventions and the generation of platform-specific assembly.
* **`get_output_args`:** This tells us how to specify the output file name for the compiled assembly.
* **`get_optimization_args` and `get_debug_args`:**  These methods control optimization and debugging flags, crucial for both performance tuning and reverse engineering. The differences between compilers (e.g., Yasm not supporting Nasm's optimization flags) are important.
* **`get_include_args`:**  This shows how to specify include directories for assembly source files.
* **`sanity_check`:** This method validates if the compiler is compatible with the target CPU architecture, highlighting the low-level hardware considerations.
* **`get_pic_args`:**  This relates to Position Independent Code, a concept important for shared libraries and security.
* **`get_crt_link_args` (especially for `NasmCompiler` and its mention of `_WinMain`):**  This connects to the C runtime library and the entry points of executable files, which is very relevant to understanding binary structure.
* **`get_dependency_gen_args`:**  This focuses on dependency tracking during the build process.
* **Methods related to MSVC-specific compilers (`MasmCompiler`, `MasmARMCompiler`):**  The `/nologo`, `/WX`, `/Fo`, and `/Zi` flags are standard MSVC assembler options.

**5. Identifying Relationships to Reverse Engineering:**

As I analyzed the compiler-specific methods, connections to reverse engineering became apparent:

* **Debugging flags (`get_debug_args`):** Essential for attaching debuggers and understanding program flow.
* **Optimization levels (`get_optimization_args`):**  Understanding if and how code is optimized helps when analyzing disassembled code.
* **Platform-specific arguments (`get_always_args`):**  Knowing the target platform is fundamental for reverse engineering.
* **C Runtime Library linking (`get_crt_link_args`):** Understanding how the C runtime is linked is crucial for analyzing function calls and standard library usage in reverse engineering.

**6. Identifying Relationships to Binary/Low-Level Concepts:**

* **CPU Architecture checks (`sanity_check`):**  Directly relates to instruction sets and register usage.
* **Platform-specific assembly formats (ELF, Mach-O, Win64 in `get_always_args`):** Fundamental knowledge for anyone working with binaries.
* **Position Independent Code (`get_pic_args`):** A core concept in shared library design and security.
* **Object file formats (`get_output_args`):** Understanding the structure of `.o` or `.obj` files.
* **Instruction sets (Metrowerks compilers' `get_instruction_set_args`):**  Specific to certain processor families.

**7. Identifying Potential User Errors:**

* **Incorrectly specifying include paths (`get_include_args`, `compute_parameters_with_absolute_paths`):** Leading to compilation failures.
* **Choosing an incompatible assembler for the target architecture (`sanity_check`):** Resulting in build errors.
* **Misunderstanding optimization levels:** Potentially hindering debugging.
* **Issues with C runtime library linking (`get_crt_link_args`):**  Causing linker errors.

**8. Tracing User Actions (Debugging Scenario):**

To illustrate how a user ends up here, I constructed a plausible debugging scenario:

* **Frida development:** A developer is working on Frida, which uses assembly for low-level instrumentation.
* **Meson build system:** Frida uses Meson for its build process.
* **Assembly compilation issues:** The developer encounters errors during the assembly compilation phase.
* **Investigating the build process:** The developer starts examining Meson's internal logic, potentially looking at the compiler setup.
* **Navigating the source code:** Following the Meson source code, they would eventually find the `asm.py` file, which is responsible for handling assembly compilation.

**9. Structuring the Answer:**

Finally, I organized the information into logical sections (Functionality, Relationship to Reverse Engineering, Binary/Low-Level Aspects, Logic and Assumptions, Common User Errors, and Debugging Scenario) to provide a comprehensive and easy-to-understand answer. Using examples and concrete scenarios helps to illustrate the abstract concepts. The use of bullet points enhances readability.
这是 Frida 动态 instrumentation 工具中用于处理汇编语言编译的源代码文件 `asm.py`。它定义了 Meson 构建系统中用于不同汇编编译器的接口和行为。

**功能列举:**

1. **定义汇编编译器类:**  该文件定义了多个类，每个类代表一个特定的汇编编译器，例如 `NasmCompiler` (NASM), `YasmCompiler` (Yasm), `MasmCompiler` (Microsoft Macro Assembler), `MasmARMCompiler` (ARM 版 MASM), 以及一些 Metrowerks 的汇编编译器。

2. **提供编译器通用接口:** 这些类都继承自 `Compiler` 基类（虽然在这个文件中没有完整定义，但在 `compilers` 目录下应该有），并实现了一组通用的方法，用于处理汇编代码的编译过程。

3. **处理特定编译器的命令行参数:**  每个编译器类都根据其自身的特点，实现了生成特定命令行参数的方法，例如：
    * `get_always_args()`: 返回编译器总是需要的参数。
    * `get_output_args()`: 返回指定输出文件名的参数。
    * `get_optimization_args()`: 返回指定优化级别的参数。
    * `get_debug_args()`: 返回指定是否生成调试信息的参数。
    * `get_include_args()`: 返回指定头文件搜索路径的参数。
    * `get_pic_args()`: 返回生成位置无关代码的参数。
    * `get_werror_args()`: 返回将警告视为错误的参数。

4. **处理平台特定的参数:**  `NasmCompiler` 的 `get_always_args()` 方法会根据目标操作系统 (Windows, macOS, Linux) 和 CPU 架构 (32 位或 64 位) 生成不同的预定义宏和输出格式参数。

5. **处理 C 运行时库 (CRT) 链接:** `NasmCompiler` 和 `MasmCompiler` 包含了处理与 C 运行时库链接的方法 `get_crt_link_args()`，这在将纯汇编代码链接成可执行文件或动态链接库时是必要的。

6. **执行编译器的环境检查:**  `sanity_check()` 方法用于检查当前环境是否满足编译器的要求，例如检查 CPU 架构是否受支持。

7. **处理依赖关系:** `get_dependency_gen_args()` 方法用于生成依赖关系文件，以便在源文件更改时重新编译。

8. **支持不同的汇编语法:** 通过定义不同的编译器类，支持不同的汇编语法，例如 NASM 语法、Yasm 语法和 MASM 语法。

**与逆向方法的关系及举例说明:**

该文件直接服务于 Frida 的构建过程，而 Frida 本身是一个强大的动态 instrumentation 工具，常用于逆向工程。因此，这个文件在幕后为逆向工作提供了基础支持。

* **编译包含调试信息的汇编代码:**  逆向工程师经常需要分析包含调试信息的程序，以便使用调试器进行单步执行和查看变量。`get_debug_args()` 方法允许 Meson 构建系统指示汇编器生成调试信息 (例如，DWARF 格式)。
    * **假设输入:** `is_debug = True`
    * **NasmCompiler 输出 (非 Windows):** `['-g', '-F', 'dwarf']`，这些参数指示 NASM 生成 DWARF 调试信息。
    * **逆向应用:**  使用 GDB 或 LLDB 等调试器可以加载由这些参数编译出的目标文件，并进行源码级别的调试。

* **编译特定架构的代码:**  逆向工程师可能需要分析针对特定 CPU 架构 (例如 ARM) 编译的代码。 `MasmARMCompiler` 类确保在 ARM 平台上使用正确的 MASM 编译器，并传递相应的参数。
    * **假设 Frida 构建目标为 ARM 架构。**
    * **Meson 会选择 `MasmARMCompiler`。**
    * **`get_always_args()` 可能包含 `-nologo`。**
    * **逆向应用:** 这保证了 Frida 的 ARM 版本组件能够被正确编译，逆向工程师可以在 ARM 设备上使用 Frida 进行分析。

* **理解平台相关的汇编差异:** `NasmCompiler` 的 `get_always_args()` 方法展示了不同平台汇编代码的常见约定。例如，在 Windows 上定义 `WIN32` 或 `WIN64` 宏，在 macOS 上定义 `MACHO` 宏，在 Linux 上定义 `ELF` 宏。
    * **假设目标平台是 Windows x64。**
    * **`NasmCompiler.get_always_args()` 返回 `['-f', 'win64', '-DWIN64', '-D__x86_64__']`。**
    * **逆向应用:** 逆向工程师在分析 Windows 程序的汇编代码时，会经常看到 `WIN64` 相关的条件编译指令或 API 调用。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层 - 对象文件格式:**  `get_output_args()` 方法指定了汇编器生成的对象文件的格式和名称。理解对象文件的结构 (例如 ELF 或 COFF) 对于逆向工程至关重要。
    * **NasmCompiler 的 `get_output_args(outputname='output.o')` 返回 `['-o', 'output.o']`。** 这意味着 NASM 会生成一个名为 `output.o` 的对象文件。

* **Linux - ELF 格式:** `NasmCompiler` 在 Linux 平台上默认使用 ELF 格式 (`-f elf32` 或 `-f elf64`)，这是 Linux 可执行文件和共享库的标准格式。
    * **假设在 Linux x86 上编译汇编代码。**
    * **`NasmCompiler.get_always_args()` 会包含 `['-f', 'elf32', '-DELF']`。**
    * **内核/框架应用:** Frida 在 Linux 上运行时，其注入目标进程的代码通常会以 ELF 格式存在。理解 ELF 结构有助于分析 Frida 的注入机制。

* **位置无关代码 (PIC):** 虽然在这个文件中 `get_pic_args()` 对于 NASM 返回空列表，但在其他编译器 (可能在基类或未展示的子类中) 可能会返回相关的参数。PIC 对于创建共享库至关重要，Android 框架大量使用共享库。
    * **假设某个汇编编译器的 `get_pic_args()` 返回 `['-fPIC']`。**
    * **内核/框架应用:** Frida 可能会使用 PIC 来编译其注入到 Android 应用程序中的代码，以便代码可以加载到任意内存地址。

* **C 运行时库 (CRT) 链接:** `NasmCompiler` 的 `get_crt_link_args()` 方法针对 Windows 平台处理 CRT 链接。理解 CRT 的作用以及不同 CRT 变体 (MD, MT, MDd, MTd) 的区别对于理解 Windows 程序的运行机制至关重要。
    * **假设 `b_vscrt` Meson 选项设置为 `md`。**
    * **`NasmCompiler.get_crt_link_args('md', 'release')` 返回 `['/DEFAULTLIB:ucrt.lib', '/DEFAULTLIB:vcruntime.lib', '/DEFAULTLIB:msvcrt.lib']`。**
    * **内核/框架应用:**  Frida 在 Windows 上运行时，可能需要与目标进程的 CRT 交互，理解这些链接选项有助于分析 Frida 与目标进程的交互方式。

**逻辑推理及假设输入与输出:**

* **`NasmCompiler.get_always_args()` 的逻辑:**
    * **假设输入:** `self.info.is_windows() = True`, `self.info.is_64_bit = True`
    * **输出:** `['-f', 'win64', '-DWIN64', '-D__x86_64__']` (选择 Windows 64 位格式，并定义相应的宏)
    * **假设输入:** `self.info.is_windows() = False`, `self.info.is_darwin() = True`
    * **输出:** `['-f', 'macho64', '-DMACHO', '-D__x86_64__']` (选择 macOS 64 位格式，并定义相应的宏)
    * **假设输入:** `self.info.is_windows() = False`, `self.info.is_darwin() = False`, `self.info.is_64_bit = False`
    * **输出:** `['-f', 'elf32', '-DELF']` (选择 Linux 32 位格式，并定义相应的宏)

* **`NasmCompiler.get_debug_args()` 的逻辑:**
    * **假设输入:** `is_debug = True`, `self.info.is_windows() = True`
    * **输出:** `[]` (在 Windows 上，NASM 的调试信息处理可能由链接器或其他工具负责，此处返回空列表)
    * **假设输入:** `is_debug = True`, `self.info.is_windows() = False`
    * **输出:** `['-g', '-F', 'dwarf']` (在非 Windows 平台上，使用 `-g` 生成调试信息，`-F dwarf` 指定 DWARF 格式)
    * **假设输入:** `is_debug = False`
    * **输出:** `[]` (不生成调试信息)

**涉及用户或编程常见的使用错误及举例说明:**

* **错误的包含路径:** 用户可能在编写 Frida 脚本或扩展时，依赖了某些头文件，但 Meson 构建系统无法找到这些文件。
    * **错误场景:** 用户在汇编代码中使用了 `include 'my_header.inc'`，但 `my_header.inc` 文件不在默认的搜索路径中，也没有通过 Meson 的 `include_directories` 功能添加。
    * **如何到达这里:** Meson 构建系统会调用相应的编译器，`get_include_args()` 方法会被用来构建包含路径参数。如果用户没有正确配置包含路径，汇编器会报错，导致构建失败。
    * **调试线索:** 编译器输出会显示找不到 `my_header.inc` 文件的错误信息。开发者需要检查 Meson 的构建配置和汇编源代码中的包含路径。

* **为错误的架构编译汇编代码:** 用户可能在配置 Meson 构建时，选择了与当前主机架构不符的目标架构。
    * **错误场景:** 用户在 x86_64 机器上尝试构建 ARM 版本的 Frida 组件，但相关的汇编代码没有针对 ARM 架构编写。
    * **如何到达这里:** Meson 会根据用户配置选择相应的编译器类，例如 `MasmARMCompiler`。`sanity_check()` 方法可能会捕获到架构不匹配的问题，但如果 `sanity_check()` 没有严格检查或者汇编代码本身存在架构兼容性问题，则会传递给汇编器。
    * **调试线索:** 汇编器会输出指令集错误的错误信息，例如 "无效的指令" 等。开发者需要检查 Meson 的构建配置和目标架构设置。

* **链接时缺少必要的 CRT 库 (Windows):**  在 Windows 上，如果使用纯汇编代码创建可执行文件或 DLL，需要正确链接 C 运行时库。
    * **错误场景:**  用户编写了一个纯汇编的 Windows DLL，但 Meson 构建配置中没有正确设置 `b_vscrt` 选项。
    * **如何到达这里:**  Meson 会调用链接器，但由于缺少必要的 CRT 库，链接器会报错，提示找不到 `_WinMain` 或 `_DllMainCRTStartup` 等入口点。 `get_crt_link_args()` 方法的目的是为了避免这类错误。
    * **调试线索:** 链接器会输出找不到入口点的错误信息。开发者需要检查 Meson 的 `b_vscrt` 选项设置。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设一个 Frida 开发者正在为一个新的平台或架构添加汇编语言支持，或者在调试现有的汇编代码编译过程：

1. **配置 Meson 构建系统:** 开发者会修改 Frida 项目根目录下的 `meson.build` 文件，或者在命令行中使用 `meson setup` 命令来配置构建系统。这可能涉及到指定目标平台、编译器选项等。

2. **Meson 处理构建配置:** 当开发者运行 `ninja` 命令开始构建时，Meson 会读取 `meson.build` 文件，解析构建依赖关系和编译规则。

3. **遇到汇编源文件:** 当 Meson 处理到需要编译汇编源文件 (`.asm`, `.s`) 时，它会查找相应的汇编编译器。

4. **选择合适的编译器类:**  Meson 的内部逻辑会根据配置的目标平台和可用的编译器，选择 `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/asm.py` 文件中定义的相应编译器类，例如 `NasmCompiler` 或 `MasmARMCompiler`。

5. **调用编译器类的方法:** Meson 会调用所选编译器类的各种方法，例如 `get_always_args()`, `get_output_args()`, `get_debug_args()` 等，来生成编译命令。

6. **执行汇编器:** Meson 使用生成的命令调用实际的汇编器 (例如 `nasm`, `yasm`, `ml`)。

7. **编译出错 (调试场景):** 如果汇编编译过程中出现错误 (例如找不到头文件、指令错误等)，开发者可能会需要深入了解 Meson 是如何调用汇编器的。

8. **查看 Meson 日志或内部代码:** 开发者可能会查看 Ninja 的构建日志，或者直接查看 Meson 的源代码来理解构建过程。

9. **定位到 `asm.py`:**  通过跟踪 Meson 的代码执行流程，开发者可能会发现涉及到汇编编译的部分是由 `asm.py` 文件中的类处理的。

10. **分析编译器参数:** 开发者可能会仔细分析 `asm.py` 中各个方法的实现，以确定传递给汇编器的命令行参数是否正确。例如，检查 `get_include_args()` 返回的包含路径是否包含了所需的目录。

11. **修改代码或配置:** 根据分析结果，开发者可能会修改 `asm.py` 文件 (如果需要添加新的编译器支持或修改现有编译器的行为)，或者修改 Meson 的构建配置文件来修复编译错误。

总之，`asm.py` 文件是 Frida 构建系统中处理汇编语言编译的关键组件。理解其功能和实现细节对于 Frida 的开发者和希望深入了解 Frida 构建过程的逆向工程师都非常有帮助。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/asm.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
from __future__ import annotations

import os
import typing as T

from ..mesonlib import EnvironmentException, OptionKey, get_meson_command
from .compilers import Compiler
from .mixins.metrowerks import MetrowerksCompiler, mwasmarm_instruction_set_args, mwasmeppc_instruction_set_args

if T.TYPE_CHECKING:
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    from ..envconfig import MachineInfo

nasm_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': ['-O0'],
    'g': ['-O0'],
    '1': ['-O1'],
    '2': ['-Ox'],
    '3': ['-Ox'],
    's': ['-Ox'],
}


class NasmCompiler(Compiler):
    language = 'nasm'
    id = 'nasm'

    # https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features
    crt_args: T.Dict[str, T.List[str]] = {
        'none': [],
        'md': ['/DEFAULTLIB:ucrt.lib', '/DEFAULTLIB:vcruntime.lib', '/DEFAULTLIB:msvcrt.lib'],
        'mdd': ['/DEFAULTLIB:ucrtd.lib', '/DEFAULTLIB:vcruntimed.lib', '/DEFAULTLIB:msvcrtd.lib'],
        'mt': ['/DEFAULTLIB:libucrt.lib', '/DEFAULTLIB:libvcruntime.lib', '/DEFAULTLIB:libcmt.lib'],
        'mtd': ['/DEFAULTLIB:libucrtd.lib', '/DEFAULTLIB:libvcruntimed.lib', '/DEFAULTLIB:libcmtd.lib'],
    }

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str,
                 for_machine: 'MachineChoice', info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None, is_cross: bool = False):
        super().__init__(ccache, exelist, version, for_machine, info, linker, full_version, is_cross)
        if 'link' in self.linker.id:
            self.base_options.add(OptionKey('b_vscrt'))

    def needs_static_linker(self) -> bool:
        return True

    def get_always_args(self) -> T.List[str]:
        cpu = '64' if self.info.is_64_bit else '32'
        if self.info.is_windows() or self.info.is_cygwin():
            plat = 'win'
            define = f'WIN{cpu}'
        elif self.info.is_darwin():
            plat = 'macho'
            define = 'MACHO'
        else:
            plat = 'elf'
            define = 'ELF'
        args = ['-f', f'{plat}{cpu}', f'-D{define}']
        if self.info.is_64_bit:
            args.append('-D__x86_64__')
        return args

    def get_werror_args(self) -> T.List[str]:
        return ['-Werror']

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def unix_args_to_native(self, args: T.List[str]) -> T.List[str]:
        outargs: T.List[str] = []
        for arg in args:
            if arg == '-pthread':
                continue
            outargs.append(arg)
        return outargs

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return nasm_optimization_args[optimization_level]

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        if is_debug:
            if self.info.is_windows():
                return []
            return ['-g', '-F', 'dwarf']
        return []

    def get_depfile_suffix(self) -> str:
        return 'd'

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-MD', outfile, '-MQ', outtarget]

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        if self.info.cpu_family not in {'x86', 'x86_64'}:
            raise EnvironmentException(f'ASM compiler {self.id!r} does not support {self.info.cpu_family} CPU family')

    def get_pic_args(self) -> T.List[str]:
        return []

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if not path:
            path = '.'
        return ['-I' + path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))
        return parameter_list

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    # Linking ASM-only objects into an executable or DLL
    # require this, otherwise it'll fail to find
    # _WinMain or _DllMainCRTStartup.
    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        if not self.info.is_windows():
            return []
        return self.crt_args[self.get_crt_val(crt_val, buildtype)]

class YasmCompiler(NasmCompiler):
    id = 'yasm'

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        # Yasm is incompatible with Nasm optimization flags.
        return []

    def get_exelist(self, ccache: bool = True) -> T.List[str]:
        # Wrap yasm executable with an internal script that will write depfile.
        exelist = super().get_exelist(ccache)
        return get_meson_command() + ['--internal', 'yasm'] + exelist

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        if is_debug:
            if self.info.is_windows():
                return ['-g', 'null']
            return ['-g', 'dwarf2']
        return []

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['--depfile', outfile]

# https://learn.microsoft.com/en-us/cpp/assembler/masm/ml-and-ml64-command-line-reference
class MasmCompiler(Compiler):
    language = 'masm'
    id = 'ml'

    def get_compile_only_args(self) -> T.List[str]:
        return ['/c']

    def get_argument_syntax(self) -> str:
        return 'msvc'

    def needs_static_linker(self) -> bool:
        return True

    def get_always_args(self) -> T.List[str]:
        return ['/nologo']

    def get_werror_args(self) -> T.List[str]:
        return ['/WX']

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['/Fo', outputname]

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return []

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        if is_debug:
            return ['/Zi']
        return []

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        if self.info.cpu_family not in {'x86', 'x86_64'}:
            raise EnvironmentException(f'ASM compiler {self.id!r} does not support {self.info.cpu_family} CPU family')

    def get_pic_args(self) -> T.List[str]:
        return []

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if not path:
            path = '.'
        return ['-I' + path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I' or i[:2] == '/I':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))
        return parameter_list

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    def depfile_for_object(self, objfile: str) -> T.Optional[str]:
        return None


# https://learn.microsoft.com/en-us/cpp/assembler/arm/arm-assembler-command-line-reference
class MasmARMCompiler(Compiler):
    language = 'masm'
    id = 'armasm'

    def get_argument_syntax(self) -> str:
        return 'msvc'

    def needs_static_linker(self) -> bool:
        return True

    def get_always_args(self) -> T.List[str]:
        return ['-nologo']

    def get_werror_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return []

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        if is_debug:
            return ['-g']
        return []

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        if self.info.cpu_family not in {'arm', 'aarch64'}:
            raise EnvironmentException(f'ASM compiler {self.id!r} does not support {self.info.cpu_family} CPU family')

    def get_pic_args(self) -> T.List[str]:
        return []

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if not path:
            path = '.'
        return ['-i' + path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))
        return parameter_list

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    def get_dependency_compile_args(self, dep: 'Dependency') -> T.List[str]:
        return [arg for arg in super().get_dependency_compile_args(dep) if not arg.startswith("-D")]

    def depfile_for_object(self, objfile: str) -> T.Optional[str]:
        return None


class MetrowerksAsmCompiler(MetrowerksCompiler, Compiler):
    language = 'nasm'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str,
                 for_machine: 'MachineChoice', info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None, is_cross: bool = False):
        Compiler.__init__(self, ccache, exelist, version, for_machine, info, linker, full_version, is_cross)
        MetrowerksCompiler.__init__(self)

        self.warn_args: T.Dict[str, T.List[str]] = {
            '0': [],
            '1': [],
            '2': [],
            '3': [],
            'everything': []}
        self.can_compile_suffixes.add('s')

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        return []

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return []

    def get_pic_args(self) -> T.List[str]:
        return []

    def needs_static_linker(self) -> bool:
        return True


class MetrowerksAsmCompilerARM(MetrowerksAsmCompiler):
    id = 'mwasmarm'

    def get_instruction_set_args(self, instruction_set: str) -> T.Optional[T.List[str]]:
        return mwasmarm_instruction_set_args.get(instruction_set, None)

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        if self.info.cpu_family not in {'arm'}:
            raise EnvironmentException(f'ASM compiler {self.id!r} does not support {self.info.cpu_family} CPU family')


class MetrowerksAsmCompilerEmbeddedPowerPC(MetrowerksAsmCompiler):
    id = 'mwasmeppc'

    def get_instruction_set_args(self, instruction_set: str) -> T.Optional[T.List[str]]:
        return mwasmeppc_instruction_set_args.get(instruction_set, None)

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        if self.info.cpu_family not in {'ppc'}:
            raise EnvironmentException(f'ASM compiler {self.id!r} does not support {self.info.cpu_family} CPU family')
```