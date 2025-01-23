Response:
Let's break down the thought process for analyzing this Python code and answering the user's questions.

**1. Understanding the Goal:**

The user wants to understand the functionality of this Python file (`asm.py`) within the Frida project. They're particularly interested in its relation to reverse engineering, low-level details (kernel, etc.), logical reasoning within the code, common user errors, and how a user might end up using this code (debugging context).

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to identify its primary purpose. Keywords like `Compiler`, `nasm`, `yasm`, `masm`, `armasm`, `MetrowerksAsmCompiler`, and methods like `get_always_args`, `get_output_args`, `get_optimization_args`, `get_debug_args`, `sanity_check` immediately suggest that this file defines classes responsible for interacting with different assembly language compilers. It's part of a build system (likely Meson, given the file path) to compile assembly source code.

**3. Deeper Dive into Each Compiler Class:**

The next step is to analyze each class individually:

* **`NasmCompiler`:**  This seems like a core assembler class, defining common arguments and behaviors. Notice the platform-specific logic (`info.is_windows()`, `info.is_darwin()`, etc.) and the definition of optimization levels. The `crt_args` dictionary for Windows stands out as related to linking with the C runtime library.
* **`YasmCompiler`:** This class inherits from `NasmCompiler` and overrides some methods, indicating it's a variant or alternative assembler with slight differences in command-line arguments (e.g., dependency generation). The `get_meson_command()` call is specific to the Meson build system.
* **`MasmCompiler`:** This appears to be the Microsoft Macro Assembler. Its methods and arguments align with typical `ml.exe` command-line options.
* **`MasmARMCompiler`:**  Similar to `MasmCompiler`, but specifically for ARM architecture.
* **`MetrowerksAsmCompiler`, `MetrowerksAsmCompilerARM`, `MetrowerksAsmCompilerEmbeddedPowerPC`:** These handle the Metrowerks (now NXP) CodeWarrior assembler, focusing on specific architectures (ARM, PowerPC). The `get_instruction_set_args` method is specific to these compilers.

**4. Connecting to User Questions:**

Now, systematically address each of the user's requests:

* **Functionality:** Summarize the core purpose: defining compiler classes for assembly language within the Meson build system. Mention the specific assemblers supported.

* **Relationship to Reverse Engineering:** This requires some inference. Assembly language is fundamental to reverse engineering. Compiling assembly code is often part of building tools used for reverse engineering (e.g., Frida itself might use assembly). Specifically mention:
    * Analyzing compiled code (the *output* of these compilers).
    * Potentially writing custom assembly snippets for instrumentation (Frida's use case).
    * Understanding processor architecture (which is reflected in the compiler choices).

* **Binary/Low-Level/Kernel/Framework:** Identify elements that touch on these areas:
    * **Architecture-specific options:** The `if self.info.is_64_bit` block, platform-specific defines (`WIN64`, `MACHO`, `ELF`), and the different ARM/x86 compiler classes.
    * **Linking with C Runtime:** The `crt_args` in `NasmCompiler` directly relates to how compiled assembly interacts with standard libraries. This is a low-level concern.
    * **`get_pic_args()`:**  Position-Independent Code is crucial for shared libraries and often relevant in kernel-level development or dynamic instrumentation.
    * **Metrowerks compilers:**  These are historically used in embedded systems, often closer to hardware and sometimes involving kernel or driver development.

* **Logical Reasoning (Assumptions & Outputs):** Look for conditional logic and how inputs influence outputs. Examples:
    * Optimization levels (`nasm_optimization_args`). Input: '0', Output: `['-O0']`.
    * Debugging (`get_debug_args`). Input: `True` and Windows, Output: `[]`. Input: `True` and Linux, Output: `['-g', '-F', 'dwarf']`.
    * Platform-specific arguments in `get_always_args`.

* **User/Programming Errors:** Think about common mistakes when dealing with compilers:
    * Incorrect compiler choice for the target architecture.
    * Wrong optimization level leading to performance issues or debugging difficulties.
    * Missing or incorrect include paths.
    * Issues with linking, especially related to the C runtime on Windows (the `crt_args` hint at this).

* **User Path to This Code (Debugging Context):**  Imagine a scenario where this code gets executed. This usually happens when a build system like Meson is used:
    * The user initiates a build process (`meson build`, `ninja`).
    * The build process needs to compile assembly code.
    * Meson consults this `asm.py` file to determine the correct compiler and arguments based on the project's configuration and the target platform.
    * If there are compilation errors or if someone is developing the build system itself, they might need to inspect this file.

**5. Structuring the Answer:**

Finally, organize the information clearly, using headings and bullet points to address each of the user's questions. Provide concrete code examples where relevant to illustrate the points. Use clear and concise language, avoiding overly technical jargon where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file *directly* interacts with the operating system to execute assemblers.
* **Correction:** Realized it's part of a *build system* (Meson), so its primary role is *configuration* and *argument generation*, not direct execution. The build system then uses this information to run the actual compiler commands.
* **Initial thought:** Focus heavily on Frida's specific use cases.
* **Refinement:** While the file is *in* the Frida project, the code itself is more general-purpose for compiling assembly. Broaden the scope to include general assembly compilation within a build system context, and then connect it back to Frida's possible usage.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The key is to break down the problem, analyze the code systematically, and then relate the code's features back to the user's specific questions.
好的，让我们来分析一下 `frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/asm.py` 这个文件的功能。

**文件功能概览**

这个 Python 文件定义了 Frida 项目中用于处理汇编语言编译器的相关类。它属于 Meson 构建系统的一部分，专门负责管理如何调用不同的汇编器（assembler）以及传递哪些命令行参数来编译汇编源代码文件。

**具体功能分解**

1. **定义抽象基类和具体编译器类:**
   - 文件中定义了 `Compiler` 基类（虽然没有直接在当前文件中看到，但从导入 `from .compilers import Compiler` 可以推断），以及多个继承自 `Compiler` 的具体汇编器类，如 `NasmCompiler`, `YasmCompiler`, `MasmCompiler`, `MasmARMCompiler`, `MetrowerksAsmCompiler` 等。
   - 每个具体的编译器类都针对特定的汇编器，并包含了该汇编器特有的命令行参数和行为。

2. **管理汇编器的通用参数:**
   - 每个编译器类都定义了一些方法来获取通用的编译参数，例如：
     - `get_always_args()`:  获取始终需要传递的参数（例如，指定输出格式、定义宏等）。
     - `get_output_args(outputname)`: 获取指定输出文件名的参数。
     - `get_werror_args()`: 获取将警告视为错误的参数。
     - `get_optimization_args(optimization_level)`: 获取优化级别的参数。
     - `get_debug_args(is_debug)`: 获取调试信息的参数。
     - `get_include_args(path, is_system)`: 获取包含头文件路径的参数。
     - `get_pic_args()`: 获取生成位置无关代码 (PIC) 的参数。

3. **处理特定汇编器的差异:**
   - 不同的汇编器有不同的语法和命令行选项。这个文件通过不同的编译器类来处理这些差异。例如：
     - `NasmCompiler` 和 `YasmCompiler` 在优化参数、调试参数和依赖生成方面有所不同。
     - `MasmCompiler` 和 `MasmARMCompiler` 是 Microsoft 的汇编器，它们的参数语法和选项与其他汇编器不同。
     - `MetrowerksAsmCompiler` 系列用于 Metrowerks CodeWarrior 工具链。

4. **平台相关的配置:**
   - 代码中会根据目标操作系统（Windows, macOS, Linux 等）和 CPU 架构 (x86, x86_64, ARM 等) 生成不同的编译参数。例如，在 `NasmCompiler.get_always_args()` 中，会根据平台设置输出格式 (`-f`) 和预定义宏 (`-D`)。

5. **与 C 运行时库 (CRT) 的集成 (Windows):**
   - `NasmCompiler` 和 `MasmCompiler` 中有处理 Windows 平台下 C 运行时库链接的逻辑 (`crt_args` 和 `get_crt_link_args`)。这是因为即使是纯汇编代码，在 Windows 上也可能需要与 CRT 库链接才能正确运行。

6. **依赖关系生成:**
   - 部分编译器类（如 `NasmCompiler` 和 `YasmCompiler`) 实现了生成依赖关系文件的功能 (`get_dependency_gen_args`)，用于构建系统跟踪文件依赖，实现增量编译。

7. **Sanity Check (环境检查):**
   - 每个编译器类都有 `sanity_check` 方法，用于检查当前环境是否满足编译器的运行条件，例如，检查 CPU 架构是否受支持。

**与逆向方法的关联及举例说明**

汇编语言是逆向工程的基础。这个文件在 Frida 项目中负责编译汇编代码，这些汇编代码可能被用于：

* **动态插桩代码的编写:** Frida 的核心功能是在运行时修改目标进程的指令。这通常涉及到编写少量的汇编代码来插入到目标进程中。例如，你可能需要编写汇编代码来：
    - **Hook 函数:**  修改目标函数的入口地址，跳转到你自定义的汇编代码。
    - **读取/修改内存:** 直接操作目标进程的内存。
    - **调用目标进程的函数:** 手动设置函数参数并执行调用。
    - **实现自定义的指令逻辑:**  在目标进程中注入特定的行为。

   **举例说明:** 假设你想在 Android 平台的某个 Native 函数入口处打印一条日志。你可能会编写类似以下的 NASM 汇编代码：

   ```assembly
   ; 假设目标函数的参数在寄存器 r0, r1 中

   push {r0-r3, lr}  ; 保存寄存器状态
   ldr r0, =log_tag_ptr  ; 加载日志标签字符串的地址
   ldr r1, =log_message_ptr ; 加载日志消息字符串的地址
   bl  __android_log_print  ; 调用 __android_log_print 函数
   pop {r0-r3, pc}   ; 恢复寄存器状态并返回

   .data
   log_tag_ptr: .asciz "MyFridaHook"
   log_message_ptr: .asciz "Function entry point reached!"
   ```

   Frida 的构建系统会使用 `asm.py` 中定义的 `NasmCompiler` (或其他合适的编译器) 来编译这段汇编代码，生成目标代码，然后 Frida 才能将这段代码注入到目标进程中执行。

* **理解底层执行流程:** 逆向工程师经常需要阅读和理解汇编代码来分析程序的行为。这个文件定义了如何将人类可读的汇编代码转换成机器可以执行的二进制代码，理解编译过程有助于理解最终程序的执行方式。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明**

* **二进制底层:**  汇编语言直接对应于机器指令，因此这个文件处理的是将文本形式的汇编代码转换为二进制机器码的过程。不同的 CPU 架构（如 x86, ARM）有不同的指令集和二进制编码方式，`asm.py` 中的不同编译器类就对应于不同的指令集。

* **Linux/Android 内核:**
    - **系统调用:** 在 Linux 和 Android 中，与内核交互通常通过系统调用完成。汇编代码可以直接执行系统调用指令（例如，x86-64 的 `syscall` 指令，ARM 的 `svc` 指令）。Frida 可能会使用汇编代码来执行一些底层的操作，例如，修改进程的内存映射。
    - **ABI (Application Binary Interface):**  不同的操作系统和架构有不同的 ABI 规定了函数调用约定（参数如何传递、返回值如何获取等）。`asm.py` 中的一些平台相关的参数设置可能与 ABI 相关。例如，在 ARM 架构中，函数参数通常通过寄存器 `r0`-`r3` 传递。

* **Android 框架:**
    - **Native 代码:** Android 框架的底层很多部分是由 C/C++ 编写的，并编译成 Native 代码。逆向分析 Android 应用时，经常需要分析这些 Native 库的汇编代码。
    - **ART/Dalvik 虚拟机:** 尽管 Android 应用主要使用 Java 代码，但 ART/Dalvik 虚拟机本身是用 C/C++ 编写的。理解虚拟机的底层实现也可能需要分析汇编代码。

   **举例说明:**  在 `NasmCompiler.get_always_args()` 中，对于 Linux 平台，会设置 `-f elf32` 或 `-f elf64`，这指定了生成 ELF (Executable and Linkable Format) 格式的目标文件，这是 Linux 系统上可执行文件和共享库的标准格式。对于 Android，最终的 `.so` 库也是 ELF 格式。

**逻辑推理的假设输入与输出**

让我们以 `NasmCompiler.get_debug_args()` 方法为例进行逻辑推理：

**假设输入:**

* `is_debug = True`
* 运行平台为 Linux (或非 Windows 平台)

**逻辑推理:**

`get_debug_args()` 方法会判断 `is_debug` 的值。如果为 `True`，则进一步判断运行平台是否为 Windows。如果不是 Windows，则返回 `['-g', '-F', 'dwarf']`。

**输出:**

`['-g', '-F', 'dwarf']`

**解释:**

* `-g`:  是 GCC/Clang 等编译器中用于生成调试信息的选项。
* `-F dwarf`: 指定生成 DWARF 格式的调试信息。DWARF 是一种广泛使用的调试信息格式，用于在调试器中进行源码级别的调试。

**假设输入:**

* `is_debug = True`
* 运行平台为 Windows

**逻辑推理:**

`get_debug_args()` 方法会判断 `is_debug` 的值。如果为 `True`，则进一步判断运行平台是否为 Windows。如果为 Windows，则返回 `[]`。

**输出:**

`[]`

**解释:**

在 Windows 上，NASM 生成调试信息的方式可能与 GCC/Clang 不同，或者调试信息的处理方式有所差异，因此对于 Windows 平台，该方法选择不添加额外的调试参数，可能依赖于链接器或其他工具来处理调试信息。

**用户或编程常见的使用错误及举例说明**

* **选择了错误的汇编器:** 用户在配置 Frida 的构建环境时，可能会错误地指定了汇编器。例如，在需要 NASM 的情况下指定了 YASM，或者在需要 MASM 的情况下尝试使用 NASM 的语法。这会导致编译错误。

   **举例说明:** 如果一个汇编源文件使用了 MASM 特有的指令或语法，而 Frida 构建系统配置为使用 NASM 编译，那么 NASM 编译器会报错，提示无法识别的指令。

* **未安装或未配置汇编器:**  如果系统中没有安装指定的汇编器，或者汇编器的路径没有正确配置在环境变量中，构建系统将无法找到汇编器，导致编译失败。

   **举例说明:**  如果用户尝试构建使用了 NASM 汇编代码的 Frida 组件，但系统中没有安装 NASM，Meson 构建系统会报错，提示找不到 NASM 可执行文件。

* **使用了错误的命令行参数:**  直接调用汇编器时，用户可能会传递错误的命令行参数，例如，指定了不兼容的输出格式或优化级别。

   **举例说明:**  用户可能错误地使用了 NASM 的 `-Ox` (最大优化) 参数，但某些特定的汇编代码可能在最高优化级别下编译不正确或行为异常。

* **平台不兼容的汇编代码:**  编写的汇编代码可能只适用于特定的 CPU 架构或操作系统。如果在错误的平台上尝试编译，会导致汇编器报错。

   **举例说明:**  编写了针对 x86-64 的汇编代码，但在 ARM 架构的 Android 设备上尝试编译，汇编器会报告指令无效。

**用户操作是如何一步步的到达这里，作为调试线索**

通常情况下，用户不会直接与 `asm.py` 这个文件交互。这个文件是 Frida 构建系统的一部分，在后台默默地工作。用户操作到达这里的路径通常是这样的：

1. **用户尝试构建 Frida 或其组件:** 用户执行类似 `meson build` 或 `ninja` 这样的命令来构建 Frida 项目。

2. **构建系统解析构建配置:** Meson 构建系统会读取 `meson.build` 文件以及相关的配置文件，确定需要编译哪些源代码文件，包括汇编源文件。

3. **构建系统确定使用哪个汇编器:**  根据项目配置和当前平台，Meson 会决定使用哪个汇编器（例如，NASM, YASM, MASM）。这个决定可能会受到用户在 `meson_options.txt` 或命令行中设置的选项的影响。

4. **构建系统查找对应的编译器类:** Meson 会在 `asm.py` 文件中查找与所选汇编器对应的编译器类（例如，如果选择 NASM，则会使用 `NasmCompiler` 类）。

5. **构建系统调用编译器类的方法生成命令行参数:**  Meson 会调用编译器类中定义的方法（例如，`get_always_args()`, `get_output_args()`, `get_optimization_args()` 等）来生成编译汇编代码所需的完整命令行参数。

6. **构建系统执行汇编器:**  Meson 使用生成的命令行参数调用实际的汇编器可执行文件来编译汇编源代码。

**作为调试线索:**

当构建过程中出现与汇编代码编译相关的错误时，开发者或高级用户可能会需要查看 `asm.py` 文件来排查问题：

* **检查编译器选择逻辑:** 确认 Meson 是否选择了正确的汇编器。
* **检查生成的命令行参数:**  查看 `asm.py` 中对应编译器类的代码，了解构建系统是如何生成传递给汇编器的参数的。这有助于发现参数错误或遗漏。
* **理解平台相关的配置:**  分析代码中针对不同平台的处理逻辑，确认是否与当前构建环境匹配。
* **查看 `sanity_check` 方法:**  如果构建失败，可能是由于环境不满足编译器的要求，可以查看 `sanity_check` 方法的实现来了解具体的检查内容。

总而言之，`asm.py` 文件在 Frida 的构建流程中扮演着关键的角色，它抽象了不同汇编器的差异，并根据平台和配置生成正确的编译命令，使得 Frida 的构建过程能够顺利进行。理解这个文件的功能有助于理解 Frida 的构建过程以及排查与汇编代码编译相关的问题。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/asm.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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