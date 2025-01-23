Response:
Let's break down the thought process for analyzing the provided Python code and generating the response.

**1. Understanding the Goal:**

The request asks for a functional description of the Python code, specifically looking for connections to reverse engineering, low-level details (binary, OS kernels, frameworks), logical reasoning (with examples), common user errors, and debugging hints. The target audience is someone familiar with Frida and potentially interested in its internals.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly skim the code and identify its primary purpose. The file name (`asm.py`) and the imports (`compilers.Compiler`, `mixins.metrowerks`) immediately suggest that this code defines classes representing Assembly language compilers within the Frida build system (Meson). The presence of specific compiler names like `NasmCompiler`, `YasmCompiler`, `MasmCompiler`, and `MasmARMCompiler` confirms this.

**3. Analyzing Each Class Individually:**

The next step is to examine each class and its methods to understand its specific role.

* **Base `Compiler` Class (Implicit):** The code inherits from a `Compiler` class (defined elsewhere). This suggests a common interface and shared functionality for all compilers.

* **`NasmCompiler`:** This class seems to represent the NASM assembler. Key methods like `get_always_args`, `get_output_args`, `get_optimization_args`, `get_debug_args`, `get_include_args` are clearly related to compiler command-line options. The `sanity_check` method checks for supported CPU architectures. The `get_crt_link_args` method is interesting because it deals with linking against C Runtime Libraries on Windows.

* **`YasmCompiler`:** This class inherits from `NasmCompiler` and overrides some methods, indicating it's a variant of NASM with slightly different behaviors (e.g., different optimization flags, dependency file generation). The `get_exelist` method is notable for wrapping the Yasm executable with a Meson internal script.

* **`MasmCompiler`:**  This represents the Microsoft Macro Assembler (ML.exe). It has its own set of methods for arguments, debugging, etc., reflecting the differences in command-line syntax compared to NASM/YASM.

* **`MasmARMCompiler`:**  Similar to `MasmCompiler`, but specifically for ARM architecture.

* **`MetrowerksAsmCompiler` and its subclasses:** These classes represent assemblers from Metrowerks, a company known for embedded development tools. They have their own specific methods and architecture checks.

**4. Identifying Functionalities and Relating to the Request:**

As each class and method is understood, the next step is to connect them to the specific requirements of the prompt:

* **Functionality:** List out the key actions performed by the code: defining compiler classes, managing command-line arguments, handling optimizations, debugging symbols, include paths, dependency generation, and architecture-specific settings.

* **Reverse Engineering:**  Focus on aspects relevant to understanding compiled code. Assembly language is the direct output of compilation, making these compilers essential for reverse engineering. Highlight the role of debug symbols (`-g`, `/Zi`) and how they help in debugging disassembled code. Mention the architecture-specific nature and the importance of selecting the correct assembler.

* **Binary/Low-Level:**  Emphasize the direct connection to assembly language and machine code. Explain how the compiler translates assembly into binary. Mention CPU architectures (x86, ARM, PPC) and how the compiler needs to be aware of them. Briefly touch on linking and the role of CRT libraries.

* **Linux/Android Kernel/Framework:**  While the code itself doesn't directly interact with the kernel, it's part of the toolchain used to build software that *does*. Explain that Frida uses these compilers to instrument processes, which can include system libraries and frameworks on Linux and Android.

* **Logical Reasoning:** Look for conditional logic within the code. The `if` statements in `get_always_args` (choosing platform-specific flags) and `get_debug_args` are good examples. Construct simple input/output scenarios based on these conditions.

* **User Errors:** Think about common mistakes a developer might make when configuring the build system. Incorrect compiler selection, wrong architecture settings, and missing dependencies are likely candidates.

* **Debugging Clues:** Trace how a user's actions (e.g., running a Meson command) lead to this code being executed. Explain the role of Meson in selecting the appropriate compiler based on the project configuration and target platform.

**5. Structuring the Response:**

Organize the findings into clear sections corresponding to the prompt's requirements. Use headings and bullet points to improve readability. Provide concrete examples whenever possible.

**6. Refining and Expanding:**

Review the initial draft and look for areas to add more detail or clarity. For instance, explicitly mentioning the connection between assembly instructions and machine code, or expanding on the purpose of CRT libraries. Ensure the language is accessible to someone with some technical background but not necessarily an expert in compiler construction.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the technical details of each compiler flag.
* **Correction:** Realize the prompt asks for broader implications, especially regarding reverse engineering and low-level concepts. Shift the focus accordingly.

* **Initial thought:**  Describe each method in isolation.
* **Correction:** Emphasize the *relationships* between methods and how they contribute to the overall compilation process.

* **Initial thought:**  Assume the reader has deep knowledge of Meson.
* **Correction:** Provide a brief explanation of Meson's role to make the "debugging clues" section more understandable.

By following these steps, the comprehensive and informative answer presented in the initial example can be generated. The key is to systematically analyze the code, connect its components to the prompt's requirements, and present the information in a clear and organized manner.
这是一个名为 `asm.py` 的 Python 源代码文件，位于 Frida 动态 Instrumentation 工具的构建系统 Meson 的子项目 `frida-clr` 中。该文件定义了用于处理汇编语言（Assembly Language）编译的编译器类。

以下是该文件的功能及其与逆向、二进制底层、Linux/Android 内核/框架知识、逻辑推理、用户错误和调试线索的关系：

**功能列举:**

1. **定义汇编编译器类:** 该文件定义了多个 Python 类，每个类代表一个特定的汇编编译器，例如 `NasmCompiler` (NASM), `YasmCompiler` (YASM), `MasmCompiler` (Microsoft MASM), `MasmARMCompiler` (Microsoft ARMASM) 和 Metrowerks 的汇编编译器。

2. **封装编译器调用:** 这些类封装了调用底层汇编编译器的具体命令和参数。它们提供了一种抽象层，使得 Frida 的构建系统可以使用不同的汇编编译器，而无需在代码的其他部分处理每个编译器的特定语法。

3. **处理编译器选项:**  每个编译器类都定义了如何处理各种编译选项，例如：
    * **优化级别 (`get_optimization_args`)**:  将 Meson 的通用优化级别映射到特定汇编器的命令行参数。
    * **调试信息 (`get_debug_args`)**:  控制是否生成调试符号以及生成哪种格式的调试符号。
    * **包含路径 (`get_include_args`)**:  指定头文件的搜索路径。
    * **输出文件 (`get_output_args`)**:  指定输出目标文件的名称。
    * **错误处理 (`get_werror_args`)**:  将警告视为错误。
    * **预处理器定义 (`get_always_args`)**:  定义在汇编编译过程中使用的预处理器宏。
    * **位置无关代码 (`get_pic_args`)**:  生成可以在内存中任意位置加载的代码。
    * **C 运行时库链接 (`get_crt_link_args`)**:  处理与 C 运行时库的链接，这在 Windows 平台上尤其重要。
    * **依赖文件生成 (`get_dependency_gen_args`)**:  生成描述源文件依赖关系的文件，用于增量构建。

4. **平台特定处理:**  代码会根据目标平台（Windows, macOS, Linux）和 CPU 架构（x86, x86_64, ARM, AArch64）选择合适的编译器选项和参数。

5. **Sanity Check (完整性检查):**  `sanity_check` 方法用于验证当前使用的汇编编译器是否支持目标 CPU 架构。

**与逆向方法的关联及举例说明:**

* **理解底层代码:** 汇编语言是计算机指令的直接表示。逆向工程师经常需要阅读和理解汇编代码，以便分析程序的行为、查找漏洞或理解程序的内部机制。`asm.py` 中定义的编译器用于将程序员编写的汇编代码转换为机器码，这是逆向分析的起点。
    * **举例:** 当逆向一个没有源代码的二进制程序时，首先需要将其反汇编得到汇编代码。了解不同的汇编语法（例如 NASM 和 MASM 的语法差异）以及编译器生成的汇编代码风格对于准确理解程序至关重要。`asm.py` 中为不同汇编器定义了不同的类，反映了这些差异。

* **动态 Instrumentation (Frida 的核心功能):** Frida 允许在运行时修改进程的内存和行为。这通常涉及到注入自定义的代码，而这些代码有时是用汇编语言编写的，以实现更底层的操作或优化性能。`asm.py` 中的编译器用于编译这些用于注入的汇编代码。
    * **举例:**  假设你想在某个函数的入口处插入一段代码来记录其参数。你可以用汇编语言编写这段插入代码，然后 Frida 会使用 `asm.py` 中定义的编译器将其编译成机器码，并注入到目标进程中。

* **理解操作系统和架构特性:** 汇编代码通常会直接操作 CPU 寄存器、内存地址等底层资源。了解目标操作系统和 CPU 架构的特性对于编写和理解汇编代码至关重要。`asm.py` 中针对不同平台和架构设置不同的编译器参数，体现了这种架构感知。
    * **举例:** 在 Windows 上，汇编代码可能需要遵循特定的调用约定，并与 C 运行时库进行交互。`NasmCompiler` 的 `get_crt_link_args` 方法就处理了与 Windows C 运行时库链接相关的参数。

**涉及二进制底层、Linux, Android 内核及框架的知识及举例说明:**

* **二进制格式:** 汇编编译器生成的输出是二进制文件（目标文件，`.o` 或 `.obj`），其中包含了可以直接由计算机执行的机器码。`asm.py` 的核心功能就是生成这种二进制代码。
    * **举例:**  `get_output_args` 方法指定了输出二进制文件的名称。

* **CPU 架构 (`sanity_check`, `get_always_args`):** 代码会根据目标 CPU 架构（例如 x86, ARM）选择合适的汇编器，并设置相应的指令集和平台相关的定义。这与 Linux 和 Android 内核运行在不同的 CPU 架构上直接相关。
    * **举例:**  `NasmCompiler` 的 `get_always_args` 方法会根据目标平台和 CPU 位数定义预处理器宏（例如 `WIN32`, `WIN64`, `ELF`, `MACHO`），这些宏可以在汇编代码中使用，以便根据不同的环境进行编译。

* **位置无关代码 (PIC, `get_pic_args`):**  在共享库（.so 文件，在 Linux 和 Android 上广泛使用）中，代码通常需要是位置无关的，这意味着它可以加载到内存的任何地址而无需修改。`get_pic_args` 方法用于添加生成 PIC 的编译器选项。
    * **举例:**  当 Frida 需要在目标进程中注入共享库时，这些库必须是 PIC 的。`asm.py` 中的相关设置确保了使用汇编编写的共享库组件能够正确生成。

* **C 运行时库 (CRT, `get_crt_link_args`):**  在许多情况下，汇编代码需要与用 C 或 C++ 编写的代码进行交互，这需要链接到 C 运行时库。在 Windows 上尤其如此。
    * **举例:** `NasmCompiler` 的 `get_crt_link_args` 方法根据配置选择不同的 CRT 库（例如 `msvcrt.lib`, `libcmt.lib`），这对于确保汇编代码与 C/C++ 代码的兼容性至关重要。

**逻辑推理及假设输入与输出:**

* **假设输入:** Meson 构建系统配置为使用 NASM 编译器，目标平台是 64 位的 Linux 系统，构建类型为 Debug。
* **输出 (`NasmCompiler` 的相关方法):**
    * `get_always_args()`: `['-f', 'elf64', '-DELF', '-D__x86_64__']` (根据平台和架构确定)
    * `get_debug_args(True)`: `['-g', '-F', 'dwarf']` (启用调试信息，生成 DWARF 格式的调试符号)
    * `get_optimization_args('g')`: `['-O0']` (Debug 构建通常使用最低优化级别)

* **假设输入:** Meson 构建系统配置为使用 MASM 编译器，目标平台是 32 位的 Windows 系统，构建类型为 Release。
* **输出 (`MasmCompiler` 的相关方法):**
    * `get_always_args()`: `['/nologo']`
    * `get_debug_args(False)`: `[]` (Release 构建通常不包含调试信息)
    * `get_optimization_args('2')`: `[]` (MASM 编译器的类中 `get_optimization_args` 返回空列表，可能意味着 MASM 的优化控制方式不同或由链接器处理)

**涉及用户或者编程常见的使用错误及举例说明:**

* **选择错误的汇编器:** 用户可能在 Meson 的配置文件中指定了错误的汇编器，导致编译失败或生成不正确的代码。
    * **举例:**  在 ARM 架构上尝试使用 `NasmCompiler` 编译代码，这会导致错误，因为 NASM 主要用于 x86 架构。`sanity_check` 方法旨在捕获这类错误。

* **缺少必要的依赖或工具:** 如果系统中没有安装指定的汇编器（例如 NASM, YASM），Meson 构建过程将会失败。
    * **举例:** 如果用户尝试构建 Frida 并且没有安装 NASM，当 Meson 尝试使用 `NasmCompiler` 时会找不到 `nasm` 命令。

* **汇编代码语法错误:** 虽然 `asm.py` 主要处理编译器选项，但如果用户编写的汇编代码本身存在语法错误，编译器会报错。
    * **举例:**  汇编代码中使用了错误的指令助记符或操作数，NASM 或 MASM 会在编译时报告错误。

* **未正确配置包含路径:** 如果汇编代码依赖于其他头文件，但未在构建系统中正确配置包含路径，编译器将无法找到这些文件。
    * **举例:**  如果汇编代码中使用了 `include` 指令引用了一个不在默认搜索路径下的头文件，并且没有通过 `-I` 参数指定该头文件的路径，编译将会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:** 用户在他们的开发环境中执行用于构建 Frida 的命令，通常是基于 Meson 的命令，例如 `meson setup build` 或 `ninja`。

2. **Meson 解析构建配置:** Meson 读取项目根目录下的 `meson.build` 文件以及可能的子项目配置文件，包括 `frida/meson.build` 和 `frida/subprojects/frida-clr/meson.build`。

3. **识别汇编源文件:** 在构建配置中，会指定需要编译的源文件，其中可能包括扩展名为 `.asm` 或 `.s` 的汇编源文件。

4. **Meson 选择合适的汇编编译器:** 根据构建配置中的语言设置（例如 `language('nasm')`）和目标平台，Meson 会选择对应的汇编编译器类，例如 `NasmCompiler` 或 `MasmCompiler`。这部分逻辑在 Meson 的其他模块中实现，但最终会实例化 `asm.py` 中定义的类。

5. **调用汇编编译器:** Meson 使用选定的编译器类的方法来生成实际的汇编器调用命令。例如，对于一个名为 `my_assembly.asm` 的文件，如果使用 NASM，可能会调用类似 `nasm -f elf64 -o my_assembly.o my_assembly.asm` 的命令。`asm.py` 中的 `get_always_args`, `get_output_args` 等方法会被调用以构建这个命令。

6. **执行汇编命令:** Meson 最终会执行构造好的汇编命令，调用底层的汇编器程序（如 `nasm`, `ml64`）。

**作为调试线索:**

* **构建失败:** 如果构建过程中涉及到汇编文件的编译，并且构建失败，查看构建日志中与汇编器相关的错误信息是首要步骤。这些错误信息可能指示汇编代码的语法错误、编译器配置问题或缺少依赖。

* **编译器选择错误:** 如果怀疑 Meson 选择了错误的汇编器，可以检查 Meson 的配置输出，确认所选的汇编器是否符合预期。

* **链接错误:** 如果汇编代码需要与 C/C++ 代码链接，并且出现链接错误，可能需要检查 `get_crt_link_args` 生成的链接器参数是否正确，以及相关的库文件是否存在。

* **调试信息缺失或不正确:** 如果在调试过程中发现汇编代码的调试信息不完整或不正确，可能需要检查 `get_debug_args` 方法的实现，确保生成了正确的调试符号选项。

总而言之，`frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/asm.py` 文件在 Frida 的构建过程中扮演着关键角色，它抽象了不同汇编编译器的调用细节，使得构建系统能够灵活地处理汇编语言的编译，这对于 Frida 动态 instrumentation 功能的实现至关重要，并且与逆向工程、底层系统知识紧密相关。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/asm.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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