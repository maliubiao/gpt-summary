Response:
Let's break down the thought process for analyzing this Python code for the Frida project.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `asm.py` file within the Frida project, specifically its role in handling assembly language compilation. The prompt also asks to connect this to reverse engineering, low-level concepts, and potential user errors.

**2. Initial Code Scan and Structure Recognition:**

First, a quick scan of the code reveals several classes inheriting from `Compiler`. This immediately suggests that this file defines different assembly language compilers that Frida can use. The class names themselves (`NasmCompiler`, `YasmCompiler`, `MasmCompiler`, `MasmARMCompiler`, `MetrowerksAsmCompiler`, etc.) point to specific assembler tools.

**3. Analyzing Each Compiler Class:**

The next step is to examine each compiler class individually, looking for key methods and attributes that define its behavior.

* **`language` and `id`:** These attributes clearly identify the assembly language and the internal identifier used by Frida.
* **`__init__`:** The constructor mostly calls the parent class constructor. The `NasmCompiler` constructor has a specific check for the linker type, hinting at a dependency.
* **`get_always_args`:** This method provides default arguments passed to the assembler. Notice the logic for determining the platform (Windows, macOS, Linux) and architecture (32-bit or 64-bit) for `NasmCompiler`. This is a crucial function for setting up the assembler correctly.
* **`get_output_args`:** This defines how to specify the output file name.
* **`get_optimization_args`:** This relates to compiler optimization levels. Notice that different assemblers have different (or no) optimization flags.
* **`get_debug_args`:**  This handles debugging information. Different assemblers use different flags for this.
* **`get_include_args`:**  This specifies how to include header files or other assembly source files.
* **`sanity_check`:** This method enforces platform compatibility for each assembler.
* **`needs_static_linker`:** Indicates if a static linker is required. This is relevant for linking assembly output into final executables or libraries.
* **`get_crt_link_args`:**  Specifically for Windows, this adds necessary libraries for linking with the C Runtime Library (CRT). This is a lower-level detail.
* **`get_dependency_gen_args` / `get_depfile_suffix`:** Handles dependency tracking, allowing the build system to recompile only when necessary. The mechanisms differ between assemblers.
* **`get_pic_args`:**  Handles Position Independent Code (PIC), crucial for shared libraries. Note that most assemblers here return an empty list, suggesting they might rely on linker flags for PIC.
* **`compute_parameters_with_absolute_paths`:**  Deals with path manipulation, ensuring correct handling of include paths.

**4. Identifying Common Themes and Differences:**

After examining the individual classes, it's important to note the commonalities and differences:

* **Commonality:**  All classes inherit from `Compiler` and implement core methods like `get_always_args`, `get_output_args`, etc.
* **Differences:** The specific arguments and flags used for each assembler vary significantly, reflecting the syntax and features of the underlying tools (nasm, yasm, masm, etc.).

**5. Connecting to Reverse Engineering:**

The connection to reverse engineering is made through the fact that assembly language is the fundamental language of executables. Frida, as a dynamic instrumentation tool, often needs to interact with code at the assembly level. Being able to compile assembly code within Frida's build system allows for tasks like:

* **Code Injection:**  Dynamically generating and injecting small snippets of assembly code into a running process.
* **Hooking:**  Replacing existing assembly instructions with custom code.
* **Instrumentation:**  Inserting assembly instructions to monitor or modify program behavior.

**6. Identifying Low-Level Concepts:**

Several aspects of the code relate to low-level concepts:

* **CPU Architectures:** The code explicitly checks for CPU families (x86, x86_64, ARM, PPC) and sets appropriate flags.
* **Operating Systems:**  Platform-specific logic is present (Windows, macOS, Linux) in `get_always_args` and `get_crt_link_args`.
* **Object File Formats:**  The `-f` flag in `NasmCompiler` (elf, macho, win) specifies the output object file format.
* **Linking:** The interaction with the linker (through `needs_static_linker` and `get_crt_link_args`) is a fundamental low-level process.
* **Calling Conventions (Implicit):** While not explicitly coded, the CRT link arguments for Windows relate to the standard calling conventions and entry points.
* **Position Independent Code (PIC):**  The `get_pic_args` method is directly related to generating shared libraries that can be loaded at arbitrary memory addresses.

**7. Considering User Errors:**

Potential user errors can arise from:

* **Incorrectly Specifying the Assembler:** Choosing an assembler that doesn't support the target architecture.
* **Providing Invalid Assembler Flags:**  Passing arguments that are not recognized by the selected assembler.
* **Incorrect Include Paths:**  Failing to specify the correct paths to included assembly files.
* **Mismatched CRT Settings (Windows):** If the linker CRT settings don't match the compiled assembly, linking errors can occur.

**8. Tracing User Interaction (Debugging Clue):**

To reach this code, a user would typically:

1. **Be working within the Frida project's development environment.**
2. **Be in a situation where assembly code needs to be compiled as part of the build process.** This could be:
    * Building a Frida gadget that includes assembly code.
    * Building a test case that involves assembly.
    * Building part of Frida's core components that might use assembly for performance or low-level access.
3. **The Meson build system would be invoked.** Meson would analyze the build configuration and identify assembly files that need compilation.
4. **Meson would select an appropriate assembler based on the project's configuration and the available tools.**
5. **The corresponding compiler class in `asm.py` would be instantiated.**
6. **Meson would call methods on this compiler instance (like `get_always_args`, `get_output_args`, etc.) to generate the command-line arguments for the assembler.**
7. **The assembler would be executed.**

**9. Refining and Structuring the Answer:**

Finally, the information gathered from the above steps needs to be organized and presented clearly, addressing each point of the prompt with specific examples from the code. This involves summarizing the functionality, explaining the connections to reverse engineering and low-level concepts, providing hypothetical input/output for logical reasoning, illustrating user errors, and outlining the user's path to this code.
This Python code defines various assembly language compilers for the Frida dynamic instrumentation toolkit within the Meson build system. Let's break down its functionalities and connections.

**Core Functionality:**

This file defines classes for several assembly compilers, specifically:

* **`NasmCompiler`:**  For the NASM assembler (Netwide Assembler). This is a very popular assembler, especially on Linux.
* **`YasmCompiler`:** For the Yasm assembler, which is a reimplementation of NASM with some extensions.
* **`MasmCompiler`:** For the Microsoft Macro Assembler (MASM), commonly used on Windows.
* **`MasmARMCompiler`:**  Specifically for the ARM version of the Microsoft Macro Assembler.
* **`MetrowerksAsmCompiler` and its variants (`MetrowerksAsmCompilerARM`, `MetrowerksAsmCompilerEmbeddedPowerPC`):** For the Metrowerks (now NXP) CodeWarrior assembler, often used in embedded systems development.

Each of these classes inherits from a base `Compiler` class (likely defined elsewhere in the Frida/Meson build system) and implements methods specific to that assembler. These methods handle:

* **Setting compiler flags:**  Defining arguments for optimization levels, debugging information, output file names, include paths, etc.
* **Platform-specific arguments:**  Handling differences between Windows, macOS, and Linux.
* **Dependency generation:**  Creating files that track dependencies so the build system knows when to recompile.
* **Sanity checks:**  Verifying that the assembler is compatible with the target CPU architecture.
* **Linking with the C Runtime Library (CRT):**  Especially relevant on Windows, ensuring proper linking of assembly code with standard C libraries.

**Relationship to Reverse Engineering:**

Assembly language is the fundamental language of computer processors. Reverse engineering often involves analyzing and understanding compiled code at the assembly level. This `asm.py` file is crucial for reverse engineering within the Frida context because:

* **Frida can inject and execute custom assembly code:**  Researchers might want to inject small snippets of assembly to hook functions, modify behavior, or gather information. This file provides the tools to compile that assembly code within the Frida build process.
* **Understanding Frida's internals:**  Parts of Frida itself might be written in assembly for performance or low-level access. This file defines how those parts are built.
* **Targeting specific architectures:**  The different compiler classes allow Frida to work with applications compiled for various architectures (x86, ARM, PowerPC), which is essential for comprehensive reverse engineering.

**Example:**

Imagine you are reverse engineering a Windows application and want to hook a specific function. You might write a small assembly routine (using MASM syntax) to:

1. Save the registers.
2. Call your custom C function.
3. Restore the registers.
4. Jump back to the original function.

Frida would use the `MasmCompiler` class defined in this file to compile your assembly code into machine code that can then be injected into the target process. The `get_output_args`, `get_debug_args`, and other methods would be used to construct the appropriate command-line call to the MASM assembler.

**Involvement of Binary Underpinnings, Linux, Android Kernel/Framework:**

This code directly interacts with binary and system-level concepts:

* **CPU Architectures:** The `sanity_check` methods in each compiler class verify the target CPU family (x86, ARM, PPC). The `get_always_args` method in `NasmCompiler` sets flags based on whether the target is 32-bit or 64-bit.
* **Operating System Differences:** The `get_always_args` method in `NasmCompiler` distinguishes between Windows (`win`), macOS (`macho`), and Linux (`elf`) to set platform-specific assembler directives (like output format). The `get_crt_link_args` in `NasmCompiler` and `MasmCompiler` is specifically for handling the C Runtime Library linkage on Windows.
* **Object File Formats:** The `-f` flag in `NasmCompiler` (e.g., `-f elf64`, `-f macho64`, `-f win64`) specifies the binary object file format that the assembler should produce, directly related to how the operating system loads and links code.
* **Position Independent Code (PIC):** The `get_pic_args` method (though it often returns an empty list here, suggesting reliance on linker flags for PIC) is crucial for creating shared libraries or code that can be loaded at any memory address, a fundamental concept in operating systems.
* **Linking:** The `needs_static_linker` method indicates whether a static linker is required after assembling the code. The `get_crt_link_args` methods directly deal with the linking stage, particularly on Windows.
* **Kernel/Framework (Indirect):** While this code doesn't directly interact with the Linux or Android kernel code, it's essential for building Frida, which *does* interact with these kernels. Frida uses assembly for low-level operations and system calls, especially when interacting with the kernel. On Android, this could involve interacting with the ART runtime or native libraries.

**Example:**

The `NasmCompiler`'s `get_always_args` method demonstrates platform awareness:

```python
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
```

This logic ensures that NASM is invoked with the correct output format (`-f`) and preprocessor definitions (`-D`) based on the target operating system and architecture. This is crucial for generating compatible object files.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `NasmCompiler` and the `get_optimization_args` method:

**Hypothetical Input:** `optimization_level = '2'`

**Logical Reasoning:** The `nasm_optimization_args` dictionary maps optimization levels to NASM flags. Level '2' corresponds to `['-Ox']`.

**Output:** `['-Ox']`

**Hypothetical Input:** `is_debug = True` for the `NasmCompiler` on a Linux system.

**Logical Reasoning:** The `get_debug_args` method checks if debugging is enabled and if the platform is Windows. Since it's Linux, it returns `['-g', '-F', 'dwarf']`, which are standard GCC/Clang style debug flags for generating DWARF debugging information.

**Output:** `['-g', '-F', 'dwarf']`

**Common Usage Errors:**

* **Incorrectly specifying the assembler:**  If the Meson build configuration is set to use NASM, but the assembly code uses MASM syntax, the `NasmCompiler` will be invoked, and the MASM-specific syntax will cause assembly errors.
* **Missing include paths:** If the assembly code includes other files using directives like `include 'myfile.inc'`, but the `-I` flags (handled by `get_include_args`) are not correctly set, the assembler will fail to find those files.
* **Platform mismatch:** Trying to compile assembly code intended for one architecture (e.g., x86) for a different architecture (e.g., ARM) will lead to errors during assembly or linking. The `sanity_check` methods are designed to catch some of these mismatches early.
* **Incorrect CRT settings on Windows:** If you are linking assembly code on Windows and the `b_vscrt` Meson option is not set correctly, the `get_crt_link_args` might not include the necessary libraries, leading to linker errors about missing entry points like `_WinMain` or `_DllMainCRTStartup`.

**Example of a User Error:**

A user might write an assembly file `my_assembly.asm` intended for Windows with MASM syntax but the Meson build system is configured to use NASM. When Meson tries to compile `my_assembly.asm`, the `NasmCompiler` will be used, and the NASM assembler will likely produce errors because it doesn't understand MASM-specific directives.

**User Operations Leading to This Code (Debugging Clue):**

1. **A developer is working on the Frida project itself or a project that extends Frida.**
2. **The project's build system uses Meson.**
3. **The project needs to compile assembly language source files.** This could be:
    * Part of Frida's core components.
    * A Frida gadget that includes performance-critical assembly code.
    * Test cases written in assembly.
4. **Meson encounters assembly files (e.g., `.asm`, `.s`) during the build process.**
5. **Meson identifies the appropriate assembler to use based on the project's configuration and the available tools on the system.** This selection might be automatic or configured by the developer.
6. **Meson instantiates the corresponding compiler class from `frida/releng/meson/mesonbuild/compilers/asm.py` (e.g., `NasmCompiler`, `MasmCompiler`).**
7. **Meson calls methods on this compiler object (like `get_always_args`, `get_output_args`, `get_optimization_args`, etc.) to generate the command-line arguments for the assembler.**
8. **Meson executes the assembler with the generated arguments to compile the assembly source file into an object file.**

If a developer is debugging an issue with assembly compilation within the Frida build process, they might find themselves examining this `asm.py` file to understand how the assembler is being invoked and what flags are being used. They might also modify this file to add custom flags or troubleshoot issues with a specific assembler.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/compilers/asm.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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