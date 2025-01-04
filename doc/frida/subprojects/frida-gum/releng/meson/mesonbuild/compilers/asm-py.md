Response:
Let's break down the thought process for analyzing this Python code for the Frida instrumentation tool.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this specific Python file (`asm.py`) within the larger Frida project. This involves identifying what it *does*, how it interacts with the system, and potential implications for reverse engineering and low-level operations.

**2. Initial Code Scan (Keywords and Structure):**

The first step is to quickly scan the code for key terms and structural elements:

* **`class` definitions:**  `NasmCompiler`, `YasmCompiler`, `MasmCompiler`, `MasmARMCompiler`, `MetrowerksAsmCompiler`, `MetrowerksAsmCompilerARM`, `MetrowerksAsmCompilerEmbeddedPowerPC`. This immediately suggests the file deals with different assembly compilers.
* **Inheritance:**  Notice that `YasmCompiler` inherits from `NasmCompiler`, and the `Metrowerks` compilers have a common base. This hints at shared functionality and specialization.
* **Method names:**  `get_always_args`, `get_output_args`, `get_optimization_args`, `get_debug_args`, `get_pic_args`, `get_include_args`, `sanity_check`, `get_crt_compile_args`, `get_crt_link_args`, `get_dependency_gen_args`. These clearly indicate the file's role in configuring and invoking assembly compilers.
* **Attributes:** `language`, `id`, `crt_args`, `warn_args`. These provide metadata and specific configuration settings for each compiler.
* **Imports:** `os`, `typing`, `mesonlib`. This suggests interaction with the operating system and the Meson build system.

**3. Deconstructing Each Compiler Class:**

Now, let's examine each compiler class individually, focusing on the methods and attributes:

* **Base Class (`Compiler`):** While not explicitly defined in this snippet, the inheritance from `Compiler` implies a common interface and set of expected behaviors for all compilers within the Meson build system. The methods in the derived classes likely override or extend this base functionality.

* **`NasmCompiler` and `YasmCompiler`:** These are for the NASM and Yasm assemblers (common x86 assemblers). The methods configure command-line arguments for different scenarios (optimization, debugging, output, includes, etc.). The presence of `get_dependency_gen_args` is a key indicator of build system integration for tracking dependencies.

* **`MasmCompiler` and `MasmARMCompiler`:**  These target the Microsoft Macro Assembler (MASM) for x86 and ARM architectures, respectively. The methods and arguments are specific to the MASM command-line syntax (e.g., `/Fo`, `/Zi`).

* **`MetrowerksAsmCompiler` and its variants:** These handle the Metrowerks (now NXP) CodeWarrior assembler, often used in embedded systems. They have specific methods for instruction set selection.

**4. Identifying Key Functionalities and Their Relevance:**

Based on the class analysis, we can list the functionalities:

* **Abstraction over Assembly Compilers:** The file provides a consistent interface to interact with various assembly compilers (NASM, Yasm, MASM, Metrowerks).
* **Command-line Argument Generation:**  It generates the correct command-line arguments for each assembler based on the desired build settings (optimization, debugging, output paths, include directories, etc.).
* **Platform Awareness:**  It handles platform-specific arguments (Windows vs. Linux/macOS) and CPU architectures (x86, ARM).
* **Dependency Tracking:** Some compilers support dependency file generation, which is crucial for incremental builds.
* **Sanity Checks:** It ensures the chosen compiler is compatible with the target CPU architecture.
* **CRT Linking:** For Windows, it manages linking against the C runtime library (CRT).

**5. Connecting to Reverse Engineering, Binary, Kernel, and Framework Concepts:**

Now, let's connect these functionalities to the areas mentioned in the prompt:

* **Reverse Engineering:**  Understanding how assembly code is compiled is fundamental to reverse engineering. This file shows the *tools* used to create the low-level code that Frida manipulates. The debugging flags (`-g`, `/Zi`) are directly relevant for reverse engineering with debuggers.
* **Binary Underlying:** Assembly code *is* the binary underlying. This file deals with the process of generating that binary from assembly source. The different output formats (`elf`, `macho`, `win`) are key binary formats.
* **Linux/Android Kernel and Framework:** While the *file itself* doesn't directly manipulate the kernel, the *output* of these compilers (assembly code) can be used to interact with kernel-level functionalities or framework components. Frida's ability to inject code relies on understanding these low-level details. The platform-specific arguments (`-f elf`, `-f macho`) are relevant here.
* **Logic and Assumptions:**  The code makes assumptions about the availability of the compilers on the system. It also uses dictionaries to map optimization levels to specific compiler flags, demonstrating a form of rule-based logic.

**6. Illustrative Examples (Input/Output, User Errors):**

* **Input/Output:**  Imagine a user wants to compile an assembly file `my_code.asm` for a 64-bit Linux system with debugging enabled. Meson would use `NasmCompiler`, call `get_always_args` (resulting in `['-f', 'elf64', '-DELF', '-D__x86_64__']`), `get_debug_args` (resulting in `['-g', '-F', 'dwarf']`), and `get_output_args` (resulting in `['-o', 'my_code.o']`), combining them with the input file to form the final compiler command.
* **User Errors:** A common error is not having the required assembler (e.g., NASM) installed. Meson would likely throw an error during the configuration stage. Another error could be specifying incorrect or unsupported compiler flags.

**7. Tracing User Operations:**

The user interaction to reach this code would involve:

1. **Setting up a Frida development environment:** This includes installing Frida and its dependencies, including Meson.
2. **Configuring the build using Meson:** The user runs `meson setup builddir`. Meson reads the `meson.build` files, which specify the build targets and dependencies.
3. **Meson identifying assembly source files:** If the project includes `.asm` files, Meson will identify them.
4. **Meson selecting the appropriate assembler:** Based on the project configuration and detected system tools, Meson will select the relevant `*Compiler` class from `asm.py`.
5. **Meson invoking the assembler:**  During the compilation phase (`meson compile -C builddir`), Meson uses the methods in the `asm.py` classes to generate the command-line arguments and execute the assembler.

**8. Refinement and Organization:**

Finally, organize the findings into a clear and structured answer, addressing each part of the prompt. Use examples to illustrate the concepts and connect them to the relevant areas. This iterative process of scanning, analyzing, connecting, and illustrating is key to understanding complex code.
This Python code defines several classes that represent different assembly language compilers used by the Frida dynamic instrumentation toolkit. Its primary function is to **abstract away the specifics of each assembler and provide a consistent way for Frida's build system (Meson) to invoke them with the correct command-line arguments.**

Here's a breakdown of its functionalities and connections to various concepts:

**1. Abstraction of Assembly Compilers:**

* **Functionality:** The code defines classes like `NasmCompiler`, `YasmCompiler`, `MasmCompiler`, and others, each representing a specific assembly compiler (NASM, Yasm, Microsoft Macro Assembler, etc.).
* **Reverse Engineering Relevance:**  Different reverse engineering tasks might involve analyzing code compiled with different assemblers. This code helps Frida's build process handle these variations seamlessly. For example, if Frida needs to compile a small assembly snippet for injection on a Windows target, it would use the `MasmCompiler`. On a Linux target, it might use `NasmCompiler`.
* **Binary Underlying:** Assembly code is the most direct representation of machine code. This file is crucial for taking human-readable assembly and turning it into executable binary form that Frida can interact with.

**2. Generation of Compiler Command-Line Arguments:**

* **Functionality:** Each compiler class has methods like `get_always_args`, `get_output_args`, `get_optimization_args`, `get_debug_args`, `get_include_args`, etc. These methods dynamically construct the command-line arguments required to invoke the respective assembler with the desired settings.
* **Example (NasmCompiler):**
    * `get_always_args`: Determines platform-specific arguments (e.g., `-f elf64` for Linux 64-bit, `-f win64` for Windows 64-bit) and defines (e.g., `ELF`, `WIN64`).
    * `get_optimization_args`: Maps optimization levels (like '0', '1', '2') to NASM's optimization flags (e.g., `['-O0']`, `['-O1']`, `['-Ox']`).
    * `get_debug_args`: Adds debugging flags (e.g., `['-g', '-F', 'dwarf']` for Linux/macOS).
* **Reverse Engineering Relevance:** When reverse engineering, understanding how code was compiled (with or without debug symbols, optimization levels) can be crucial. This code demonstrates how Frida's build system manages these settings for its own internal assembly components.
* **Binary Underlying:** The command-line arguments directly influence how the assembly code is translated into binary. For example, debug flags tell the assembler to include extra information for debuggers. Optimization flags tell it to generate more efficient (but potentially harder to reverse) code.
* **Linux/Android Kernel & Framework:**  The `-f elf` argument for NASM is a direct indication of generating an ELF (Executable and Linkable Format) binary, which is the standard format for Linux and Android. When Frida needs to inject code into a running process (which could be part of the Android framework), it needs to produce code in a compatible binary format.

**3. Handling Platform Differences:**

* **Functionality:** The code checks the target operating system (`self.info.is_windows()`, `self.info.is_darwin()`, etc.) and CPU architecture (`self.info.is_64_bit`) to generate appropriate arguments.
* **Example (NasmCompiler):** The `get_always_args` method sets platform-specific output format flags (`win`, `macho`, `elf`) and defines.
* **Reverse Engineering Relevance:**  Code compiled for different operating systems and architectures will have different calling conventions, system libraries, and binary formats. This code ensures that Frida's assembly components are compiled correctly for the target environment.
* **Linux/Android Kernel & Framework:** The code explicitly handles differences between Windows, macOS, and generic ELF-based systems (like Linux and Android). This is vital for Frida to work cross-platform. For instance, linking against system libraries on Windows (`/DEFAULTLIB:ucrt.lib`) is different from Linux.

**4. Dependency Generation:**

* **Functionality:** Methods like `get_dependency_gen_args` (in `NasmCompiler` and `YasmCompiler`) specify how to generate dependency files. These files tell the build system which source files are dependent on which header files, allowing for faster incremental builds.
* **Binary Underlying:** While not directly related to the binary content, dependency tracking is crucial for the build process that *creates* the binary.

**5. Sanity Checks:**

* **Functionality:** The `sanity_check` method verifies that the selected assembler is compatible with the target CPU architecture.
* **Example (NasmCompiler):** It raises an error if NASM is selected for a non-x86 architecture.
* **Reverse Engineering Relevance:** Trying to compile assembly code for the wrong architecture will result in errors. These checks prevent such issues in Frida's build process.

**6. Handling C Runtime Library (CRT) Linking (Windows):**

* **Functionality:** The `NasmCompiler` has `crt_args` which defines linker flags to include the appropriate C runtime library on Windows (e.g., `md`, `mdd`, `mt`, `mtd`). The `get_crt_link_args` method uses this.
* **Reverse Engineering Relevance:** When injecting code, understanding how it interacts with the underlying system libraries (like the CRT) is important. This code shows how Frida manages these dependencies during its build.
* **Binary Underlying:**  The CRT provides essential functions for C/C++ programs. Linking against it correctly is necessary for code to run on Windows.

**7. Metrowerks Compiler Support:**

* **Functionality:**  The code includes classes for Metrowerks assemblers, which are often used in embedded systems.
* **Reverse Engineering Relevance:** Frida can be used to instrument embedded devices. Supporting these specialized assemblers is necessary for those scenarios.

**Logic Reasoning and Assumptions:**

* **Assumption:** The code assumes that the necessary assembler executables (nasm, yasm, ml, etc.) are present in the system's PATH.
* **Assumption:** It assumes a standard command-line interface for the assemblers.
* **Input (for `NasmCompiler.get_optimization_args`):**  If the input `optimization_level` is `'2'`, the output will be `['-Ox']`.
* **Input (for `NasmCompiler.get_always_args` on a 64-bit Linux system):** The output will be `['-f', 'elf64', '-DELF', '-D__x86_64__']`.

**User/Programming Errors:**

* **Incorrect Assembler Path:** If the assembler executable is not in the PATH, Meson will fail to invoke it, leading to a build error.
* **Unsupported Compiler Flags:** If Frida's build system tries to use a compiler flag that is not supported by the specific assembler version, the compilation will fail.
* **Mismatched Architecture:** Trying to compile assembly for a different architecture than the target (e.g., compiling x86 assembly for an ARM target) will be caught by the `sanity_check` or by the assembler itself, resulting in an error.
* **Incorrectly Specifying Optimization Levels:** While the code provides mappings, if a user were to directly interact with the build system configuration and provide an invalid optimization level, it might not be handled gracefully (though Meson typically enforces valid options).

**User Operation to Reach This Code (Debugging Scenario):**

1. **Developer is working on Frida itself:** A developer might be adding support for a new assembly feature or fixing a bug related to how assembly code is compiled.
2. **Meson build process is initiated:** The developer runs `meson compile` or a similar command.
3. **Meson encounters assembly source files:** The build system detects `.asm` files that need to be compiled.
4. **Meson loads the `asm.py` module:** To handle the assembly compilation, Meson imports the `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/asm.py` file.
5. **Meson instantiates the appropriate compiler class:** Based on the detected assembler on the system (e.g., `nasm`), Meson creates an instance of `NasmCompiler`.
6. **Meson calls methods on the compiler object:** Meson calls methods like `get_always_args`, `get_output_args`, etc., to construct the command-line for the assembler.
7. **Problem occurs during compilation:**  If the generated command-line is incorrect or the assembler fails, the developer might start debugging.
8. **Developer examines the `asm.py` code:** To understand how the command-line arguments are being generated, the developer would examine the logic within the `asm.py` file, potentially setting breakpoints or adding print statements to see the values of variables and the generated arguments.

In summary, this `asm.py` file is a crucial part of Frida's build system, responsible for managing the complexities of different assembly compilers and ensuring that Frida's internal assembly components are built correctly for various target platforms and architectures. It bridges the gap between high-level build system instructions and low-level assembly compilation.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/asm.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```