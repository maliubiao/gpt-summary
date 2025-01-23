Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Request:**

The request asks for an analysis of a specific Python file (`gnu.py`) within the Frida project. The analysis should cover:

* **Functionality:** What does the code do?
* **Relationship to Reversing:** How does it connect to the broader concept of reverse engineering?
* **Low-Level Details:**  Connections to binary, Linux, Android (kernel/framework).
* **Logical Inference:** Examples of input/output behavior.
* **Common Usage Errors:**  Mistakes users might make.
* **Debugging Context:**  How a user might end up at this specific file during debugging.

**2. Initial Code Scan (High-Level):**

* **Imports:**  The imports (`abc`, `functools`, `os`, `multiprocessing`, `pathlib`, `re`, `subprocess`, `typing`) immediately suggest this code deals with system interactions (OS, subprocesses), function manipulation, and type hinting (indicating a focus on code correctness and maintainability). The `mesonlib` import points to integration with the Meson build system.
* **Class Definition:** The core of the file is the `GnuLikeCompiler` and `GnuCompiler` classes. The name "Compiler" strongly suggests this code is involved in the compilation process. The "GnuLike" suffix indicates that these classes handle compilers that follow the GNU command-line conventions (like GCC, Clang).
* **Data Structures:**  The code defines several dictionaries (`clike_debug_args`, `gnu_optimization_args`, etc.). These dictionaries map abstract concepts (like debug mode, optimization level, warning levels) to specific compiler flags (strings like `-g`, `-O2`, `-Wall`). This is a key pattern for how build systems manage compiler options.
* **Function Decorators:** The use of `@functools.lru_cache` suggests performance optimization by caching the results of certain function calls. This hints that these functions might be called repeatedly with the same arguments.
* **Abstract Base Class (ABC):** The `GnuLikeCompiler` uses `abc.ABCMeta` and `@abc.abstractmethod`, indicating that it defines a common interface for different GNU-like compilers, and specific implementations must provide certain methods.

**3. Deeper Dive - Focusing on Key Areas:**

* **Compiler Flags:** The numerous dictionaries defining compiler flags are central. The comments explaining the source of these flags (GCC documentation) and the exclusion of certain flags provide valuable context. The structure allows Meson to select appropriate flags based on user settings and compiler capabilities.
* **Include Paths:** The `gnulike_default_include_dirs` function demonstrates how the code interacts with the compiler to discover default system include paths. This involves running the compiler with specific flags (`-x{lang}`, `-E`, `-v`, `-`) and parsing the output.
* **Abstraction and Inheritance:** The relationship between `GnuLikeCompiler` and `GnuCompiler` is important. `GnuLikeCompiler` provides the general logic for GNU-like compilers, while `GnuCompiler` specializes it for GCC. This promotes code reuse and maintainability.
* **Build System Integration:** The references to `mesonlib`, `OptionKey`, and the interaction with `Environment` objects clearly tie this code to the Meson build system. The code is responsible for translating Meson's build configurations into compiler-specific command-line arguments.

**4. Connecting to Reversing, Low-Level Details, etc.:**

* **Reversing:**  The compiler directly impacts the final executable or library that reverse engineers analyze. The compiler flags selected by this code determine things like debug symbols (`-g`), optimization levels (`-O`), and symbol visibility (`-fvisibility`). Understanding these flags is crucial for reverse engineering.
* **Low-Level:** The compiler flags directly manipulate how the compiler translates source code into machine code. Flags like `-mmx`, `-msse`, `-mavx` control the use of specific CPU instructions. The handling of shared libraries and prelinking also touches on low-level linking concepts.
* **Linux/Android:** Many of the compiler flags and the concept of shared libraries are fundamental to Linux and Android development. The code doesn't directly interact with the kernel or framework *within this file*, but it's a crucial part of the toolchain used to build software for those platforms.

**5. Generating Examples and Scenarios:**

* **Logical Inference:**  Consider how the `get_optimization_args` function works. If the input is `'2'`, the output is `['-O2']`. This is a straightforward mapping.
* **Usage Errors:** Think about incorrect or missing compiler versions, trying to use a linker that's not supported, or providing incorrect file paths.
* **Debugging:**  Imagine a user is getting a compilation error related to missing symbols. They might investigate the linker flags and end up tracing the code back to how Meson generates those flags, potentially leading them to this `gnu.py` file.

**6. Structuring the Output:**

Organize the findings according to the points raised in the request: functionality, relationship to reversing, low-level details, logical inference, usage errors, and debugging context. Use clear language and provide specific examples where possible.

**Self-Correction/Refinement:**

* **Initial thought:** Focus solely on the compiler flag dictionaries.
* **Correction:** Realize the broader context of the Meson build system and the interaction with the compiler via subprocesses is equally important.
* **Initial thought:**  Assume direct kernel interaction.
* **Correction:**  Recognize that the code operates at the build tool level, influencing the *output* that interacts with the kernel, rather than directly manipulating the kernel itself.
* **Initial thought:** List all possible compiler flags.
* **Correction:** Focus on the *purpose* and examples of the flags, rather than an exhaustive list.

By following these steps, the detailed and informative analysis provided in the initial example can be constructed. The process involves understanding the code's purpose, identifying key elements, connecting them to the broader context, and providing concrete examples and explanations.
This Python code file, `gnu.py`, is part of the Frida dynamic instrumentation toolkit and is specifically responsible for handling compilers that follow the GNU command-line interface, such as GCC and Clang. It provides a set of mixin classes (`GnuLikeCompiler`, `GnuCompiler`) that encapsulate common logic and settings for these compilers within the Meson build system used by Frida.

Here's a breakdown of its functionalities:

**1. Abstraction of GNU-like Compilers:**

* **Provides a common interface:** It defines abstract classes (`GnuLikeCompiler`) that specify the methods and attributes expected from GNU-like compilers. This allows Frida's build system to interact with different compilers (GCC, Clang) in a uniform way.
* **Manages compiler flags:**  It stores and manages various compiler flags related to debugging (`-g`), optimization (`-O0`, `-O2`), instruction sets (`-msse`, `-mavx`), symbol visibility (`-fvisibility`), warnings (`-Wall`, `-Werror`), and other aspects of compilation. These flags are stored in dictionaries, mapping abstract concepts to their corresponding command-line arguments.
* **Handles language-specific settings:** It differentiates between C, C++, Objective-C, and Objective-C++ by providing language-specific warning flags and handling language-specific compiler behavior.

**2. Interaction with the Build System (Meson):**

* **Integrates with Meson options:** It recognizes and uses Meson's build options (e.g., `b_debug`, `b_lto`, `b_pgo`, `b_coverage`) to determine which compiler flags to enable.
* **Provides methods for generating command-line arguments:** It offers methods like `get_pic_args`, `get_optimization_args`, `get_debug_args`, `get_warn_args`, etc., which take abstract settings and translate them into concrete compiler command-line arguments.
* **Handles include directories:** It provides functionality to retrieve default include directories used by the compiler and to generate the `-I` and `-isystem` flags for including custom directories.
* **Supports precompiled headers (PCH):** It defines the suffix for precompiled header files (`.gch`).
* **Manages linker flags:** It provides a way to add linker-specific options using the `-Wl,` prefix.

**3. Feature Detection and Support:**

* **Checks compiler version:** It uses `mesonlib.version_compare` to conditionally apply compiler flags based on the version of the compiler being used. This is crucial because different compiler versions support different features and flags.
* **Detects supported warning flags:** It provides logic to determine which warning flags are supported by the specific compiler version.
* **Handles OpenMP support:** It provides flags for enabling OpenMP parallel processing (`-fopenmp`).
* **Supports Link-Time Optimization (LTO):** It provides flags for enabling LTO (`-flto`).
* **Supports Profile-Guided Optimization (PGO):** It provides flags for generating and using profiling data (`-fprofile-generate`, `-fprofile-use`).
* **Supports code coverage analysis:** It provides flags for enabling code coverage instrumentation (`--coverage`).
* **Handles sanitizers:** It provides flags for enabling compiler sanitizers like AddressSanitizer (`-fsanitize=address`).

**Relationship to Reverse Engineering:**

This code directly impacts the process of reverse engineering by influencing the characteristics of the compiled binaries:

* **Debug Symbols:** The `-g` flag, managed by this code, includes debugging information in the compiled binary. This information is invaluable for reverse engineers using debuggers like GDB to step through the code, inspect variables, and understand the program's execution flow. Without debug symbols, reverse engineering becomes significantly more challenging.
    * **Example:** If a reverse engineer is trying to understand a function's logic, having debug symbols allows them to see the original variable names, function names, and even the source code line corresponding to the current instruction. This drastically speeds up the analysis process.
* **Optimization Level:** The `-O` flags (e.g., `-O0`, `-O2`, `-O3`) control the level of optimization applied by the compiler. Higher optimization levels can make the code harder to reverse engineer because the compiler might reorder instructions, inline functions, and eliminate dead code.
    * **Example:** At `-O0`, the compiled code often closely resembles the source code, making it easier to follow. At `-O3`, the code can be heavily transformed, making it difficult to map back to the original source. Reverse engineers often prefer to analyze unoptimized binaries first.
* **Symbol Visibility:** The `-fvisibility` flags control which symbols (functions, variables) are visible outside the compiled unit (e.g., in a shared library). When reverse engineering, understanding the exported symbols of a library is a crucial first step.
    * **Example:** If a function is compiled with `-fvisibility=hidden`, it won't be directly accessible from outside the library, making it harder to discover and interact with.
* **Sanitizers:** While primarily used for development, if a binary is accidentally compiled with sanitizers enabled, it can provide insights during reverse engineering by identifying potential memory safety issues or undefined behavior.
    * **Example:** If an AddressSanitizer is active, and the program crashes due to a memory access error, it can point the reverse engineer to a specific area of the code where vulnerabilities might exist.

**Binary Bottom, Linux, Android Kernel and Framework Knowledge:**

This code interacts with the binary level through the compiler flags it generates:

* **Instruction Sets:** Flags like `-mmx`, `-msse`, `-mavx` directly instruct the compiler to use specific CPU instructions. Understanding these instructions is fundamental to low-level binary analysis. Reverse engineers often need to understand the assembly code generated by these instructions.
    * **Example:**  Seeing an `AVX2` instruction in disassembled code tells a reverse engineer that the code is likely leveraging advanced vector processing capabilities of the CPU.
* **Position Independent Code (PIC) and Position Independent Executable (PIE):** The `-fPIC` and `-fPIE` flags are crucial for creating shared libraries and executables that can be loaded at arbitrary memory addresses. This is a core concept in Linux and Android security.
    * **Example:** On Android, most libraries and executables are compiled with `-fPIE` for security reasons (to mitigate address space layout randomization (ASLR) bypasses).
* **Linker Behavior:** The `-Wl,` prefix allows passing flags directly to the linker. Linker flags control how different object files and libraries are combined into the final binary. Understanding linker scripts and flags is important for analyzing complex binaries.
    * **Example:** Linker flags can be used to specify the order in which libraries are linked, which can be relevant for resolving symbol dependencies during reverse engineering.
* **Linux/Android Specifics:** The code checks for the operating system to apply platform-specific defaults or handle differences in compiler behavior (e.g., handling of PIC on different platforms). The concepts of shared libraries (`.so` files on Linux/Android) and their dynamic linking are central to how Frida operates and how targets are instrumented.
* **Kernel/Framework (Indirectly):** While this code doesn't directly interact with the Linux or Android kernel, it's part of the toolchain used to build applications and libraries that run on these platforms. The compiler flags it manages ultimately affect how the compiled code interacts with the kernel and the Android framework.

**Logical Inference (Hypothetical Examples):**

* **Assumption:** The user has set the Meson option `b_debug` to `true`.
    * **Input:** `is_debug=True` passed to the `get_debug_args` method.
    * **Output:** The method returns `['-g']`, instructing the compiler to include debug symbols.
* **Assumption:** The user has set the Meson option `optimization` to `'2'`.
    * **Input:** `optimization_level='2'` passed to the `get_optimization_args` method.
    * **Output:** The method returns `['-O2']`, instructing the compiler to apply optimization level 2.
* **Assumption:** The compiler version is GCC 7.1.
    * **Input:** The `supported_warn_args` method is called with the defined warning flags dictionaries.
    * **Output:** The method will return a list of warning flags that are supported by GCC 7.1 and earlier, combining flags from different version groups in the dictionaries.

**User or Programming Common Usage Errors:**

* **Incorrect Compiler Path:** If the user has not correctly configured the path to their GCC or Clang compiler, Meson will fail to execute the compiler, and this code might be indirectly involved in the error reporting or debugging process.
* **Typos in Meson Options:** If a user makes a typo in a Meson option (e.g., `b_deubg` instead of `b_debug`), the intended compiler flags might not be applied, leading to unexpected behavior or difficulty in debugging.
* **Using Unsupported Linker:** If the user tries to force the use of a linker that is not supported by this code (e.g., a custom linker not in the `{'gold', 'bfd', 'lld'}` set), the `use_linker_args` method will raise a `mesonlib.MesonException`.
* **Mixing Compiler Flags:** While Meson generally handles this, users directly passing custom compiler flags might inadvertently provide flags that conflict with those managed by this code, potentially leading to build errors or unexpected behavior.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **The User Wants to Debug a Frida Gadget on Android:**  They are trying to instrument an Android application using Frida.
2. **Frida Uses Meson to Build the Gadget:** The Frida build process relies on the Meson build system to compile the Frida gadget (the shared library injected into the target process).
3. **Meson Needs to Determine Compiler Flags:** During the build process, Meson needs to figure out the correct compiler flags to use for the target platform (Android).
4. **Meson Selects the Appropriate Compiler Class:** Based on the detected compiler (likely `aarch64-linux-android-clang` or similar), Meson will instantiate the relevant compiler class, which might involve using the `GnuLikeCompiler` or a subclass for Clang (which inherits from `GnuLikeCompiler`).
5. **A Compilation Error Occurs:** Let's say the user encounters a compilation error related to missing debug symbols or incorrect optimization levels.
6. **The User Starts Investigating the Build Process:** They might look at the Meson log files or try to understand the exact compiler commands being executed.
7. **Tracing Back to Compiler Flag Generation:**  The user might see compiler commands in the logs and try to understand where those flags are coming from. They might then examine the Meson build files or the Frida build scripts.
8. **Finding the `gnu.py` File:**  Through their investigation, they might realize that the compiler flag generation logic resides within the `frida/releng/meson/mesonbuild/compilers/mixins/gnu.py` file.
9. **Debugging the Python Code:**  The user might then start examining this Python code to understand how the specific compiler flags causing the issue are being generated. They might use print statements or a Python debugger to trace the execution flow and see how Meson options and compiler versions influence the generated flags.

In essence, this file is a crucial component of Frida's build system, responsible for translating high-level build settings into low-level compiler instructions. Understanding its functionality is important for developers contributing to Frida or for advanced users troubleshooting build issues.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2022 The meson development team

from __future__ import annotations

"""Provides mixins for GNU compilers and GNU-like compilers."""

import abc
import functools
import os
import multiprocessing
import pathlib
import re
import subprocess
import typing as T

from ... import mesonlib
from ... import mlog
from ...mesonlib import OptionKey
from mesonbuild.compilers.compilers import CompileCheckMode

if T.TYPE_CHECKING:
    from ..._typing import ImmutableListProtocol
    from ...environment import Environment
    from ..compilers import Compiler
else:
    # This is a bit clever, for mypy we pretend that these mixins descend from
    # Compiler, so we get all of the methods and attributes defined for us, but
    # for runtime we make them descend from object (which all classes normally
    # do). This gives up DRYer type checking, with no runtime impact
    Compiler = object

# XXX: prevent circular references.
# FIXME: this really is a posix interface not a c-like interface
clike_debug_args: T.Dict[bool, T.List[str]] = {
    False: [],
    True: ['-g'],
}

gnu_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': ['-O0'],
    'g': ['-Og'],
    '1': ['-O1'],
    '2': ['-O2'],
    '3': ['-O3'],
    's': ['-Os'],
}

gnulike_instruction_set_args: T.Dict[str, T.List[str]] = {
    'mmx': ['-mmmx'],
    'sse': ['-msse'],
    'sse2': ['-msse2'],
    'sse3': ['-msse3'],
    'ssse3': ['-mssse3'],
    'sse41': ['-msse4.1'],
    'sse42': ['-msse4.2'],
    'avx': ['-mavx'],
    'avx2': ['-mavx2'],
    'neon': ['-mfpu=neon'],
}

gnu_symbol_visibility_args: T.Dict[str, T.List[str]] = {
    '': [],
    'default': ['-fvisibility=default'],
    'internal': ['-fvisibility=internal'],
    'hidden': ['-fvisibility=hidden'],
    'protected': ['-fvisibility=protected'],
    'inlineshidden': ['-fvisibility=hidden', '-fvisibility-inlines-hidden'],
}

gnu_color_args: T.Dict[str, T.List[str]] = {
    'auto': ['-fdiagnostics-color=auto'],
    'always': ['-fdiagnostics-color=always'],
    'never': ['-fdiagnostics-color=never'],
}

# Warnings collected from the GCC source and documentation.  This is an
# objective set of all the warnings flags that apply to general projects: the
# only ones omitted are those that require a project-specific value, or are
# related to non-standard or legacy language support.  This behaves roughly
# like -Weverything in clang.  Warnings implied by -Wall, -Wextra, or
# higher-level warnings already enabled here are not included in these lists to
# keep them as short as possible.  History goes back to GCC 3.0.0, everything
# earlier is considered historical and listed under version 0.0.0.

# GCC warnings for all C-family languages
# Omitted non-general warnings:
#   -Wabi=
#   -Waggregate-return
#   -Walloc-size-larger-than=BYTES
#   -Walloca-larger-than=BYTES
#   -Wframe-larger-than=BYTES
#   -Wlarger-than=BYTES
#   -Wstack-usage=BYTES
#   -Wsystem-headers
#   -Wtrampolines
#   -Wvla-larger-than=BYTES
#
# Omitted warnings enabled elsewhere in meson:
#   -Winvalid-pch (GCC 3.4.0)
gnu_common_warning_args: T.Dict[str, T.List[str]] = {
    "0.0.0": [
        "-Wcast-qual",
        "-Wconversion",
        "-Wfloat-equal",
        "-Wformat=2",
        "-Winline",
        "-Wmissing-declarations",
        "-Wredundant-decls",
        "-Wshadow",
        "-Wundef",
        "-Wuninitialized",
        "-Wwrite-strings",
    ],
    "3.0.0": [
        "-Wdisabled-optimization",
        "-Wpacked",
        "-Wpadded",
    ],
    "3.3.0": [
        "-Wmultichar",
        "-Wswitch-default",
        "-Wswitch-enum",
        "-Wunused-macros",
    ],
    "4.0.0": [
        "-Wmissing-include-dirs",
    ],
    "4.1.0": [
        "-Wunsafe-loop-optimizations",
        "-Wstack-protector",
    ],
    "4.2.0": [
        "-Wstrict-overflow=5",
    ],
    "4.3.0": [
        "-Warray-bounds=2",
        "-Wlogical-op",
        "-Wstrict-aliasing=3",
        "-Wvla",
    ],
    "4.6.0": [
        "-Wdouble-promotion",
        "-Wsuggest-attribute=const",
        "-Wsuggest-attribute=noreturn",
        "-Wsuggest-attribute=pure",
        "-Wtrampolines",
    ],
    "4.7.0": [
        "-Wvector-operation-performance",
    ],
    "4.8.0": [
        "-Wsuggest-attribute=format",
    ],
    "4.9.0": [
        "-Wdate-time",
    ],
    "5.1.0": [
        "-Wformat-signedness",
        "-Wnormalized=nfc",
    ],
    "6.1.0": [
        "-Wduplicated-cond",
        "-Wnull-dereference",
        "-Wshift-negative-value",
        "-Wshift-overflow=2",
        "-Wunused-const-variable=2",
    ],
    "7.1.0": [
        "-Walloca",
        "-Walloc-zero",
        "-Wformat-overflow=2",
        "-Wformat-truncation=2",
        "-Wstringop-overflow=3",
    ],
    "7.2.0": [
        "-Wduplicated-branches",
    ],
    "8.1.0": [
        "-Wcast-align=strict",
        "-Wsuggest-attribute=cold",
        "-Wsuggest-attribute=malloc",
    ],
    "9.1.0": [
        "-Wattribute-alias=2",
    ],
    "10.1.0": [
        "-Wanalyzer-too-complex",
        "-Warith-conversion",
    ],
    "12.1.0": [
        "-Wbidi-chars=ucn",
        "-Wopenacc-parallelism",
        "-Wtrivial-auto-var-init",
    ],
}

# GCC warnings for C
# Omitted non-general or legacy warnings:
#   -Wc11-c2x-compat
#   -Wc90-c99-compat
#   -Wc99-c11-compat
#   -Wdeclaration-after-statement
#   -Wtraditional
#   -Wtraditional-conversion
gnu_c_warning_args: T.Dict[str, T.List[str]] = {
    "0.0.0": [
        "-Wbad-function-cast",
        "-Wmissing-prototypes",
        "-Wnested-externs",
        "-Wstrict-prototypes",
    ],
    "3.4.0": [
        "-Wold-style-definition",
        "-Winit-self",
    ],
    "4.1.0": [
        "-Wc++-compat",
    ],
    "4.5.0": [
        "-Wunsuffixed-float-constants",
    ],
}

# GCC warnings for C++
# Omitted non-general or legacy warnings:
#   -Wc++0x-compat
#   -Wc++1z-compat
#   -Wc++2a-compat
#   -Wctad-maybe-unsupported
#   -Wnamespaces
#   -Wtemplates
gnu_cpp_warning_args: T.Dict[str, T.List[str]] = {
    "0.0.0": [
        "-Wctor-dtor-privacy",
        "-Weffc++",
        "-Wnon-virtual-dtor",
        "-Wold-style-cast",
        "-Woverloaded-virtual",
        "-Wsign-promo",
    ],
    "4.0.1": [
        "-Wstrict-null-sentinel",
    ],
    "4.6.0": [
        "-Wnoexcept",
    ],
    "4.7.0": [
        "-Wzero-as-null-pointer-constant",
    ],
    "4.8.0": [
        "-Wabi-tag",
        "-Wuseless-cast",
    ],
    "4.9.0": [
        "-Wconditionally-supported",
    ],
    "5.1.0": [
        "-Wsuggest-final-methods",
        "-Wsuggest-final-types",
        "-Wsuggest-override",
    ],
    "6.1.0": [
        "-Wmultiple-inheritance",
        "-Wplacement-new=2",
        "-Wvirtual-inheritance",
    ],
    "7.1.0": [
        "-Waligned-new=all",
        "-Wnoexcept-type",
        "-Wregister",
    ],
    "8.1.0": [
        "-Wcatch-value=3",
        "-Wextra-semi",
    ],
    "9.1.0": [
        "-Wdeprecated-copy-dtor",
        "-Wredundant-move",
    ],
    "10.1.0": [
        "-Wcomma-subscript",
        "-Wmismatched-tags",
        "-Wredundant-tags",
        "-Wvolatile",
    ],
    "11.1.0": [
        "-Wdeprecated-enum-enum-conversion",
        "-Wdeprecated-enum-float-conversion",
        "-Winvalid-imported-macros",
    ],
}

# GCC warnings for Objective C and Objective C++
# Omitted non-general or legacy warnings:
#   -Wtraditional
#   -Wtraditional-conversion
gnu_objc_warning_args: T.Dict[str, T.List[str]] = {
    "0.0.0": [
        "-Wselector",
    ],
    "3.3": [
        "-Wundeclared-selector",
    ],
    "4.1.0": [
        "-Wassign-intercept",
        "-Wstrict-selector-match",
    ],
}

_LANG_MAP = {
    'c': 'c',
    'cpp': 'c++',
    'objc': 'objective-c',
    'objcpp': 'objective-c++'
}

@functools.lru_cache(maxsize=None)
def gnulike_default_include_dirs(compiler: T.Tuple[str, ...], lang: str) -> 'ImmutableListProtocol[str]':
    if lang not in _LANG_MAP:
        return []
    lang = _LANG_MAP[lang]
    env = os.environ.copy()
    env["LC_ALL"] = 'C'
    cmd = list(compiler) + [f'-x{lang}', '-E', '-v', '-']
    _, stdout, _ = mesonlib.Popen_safe(cmd, stderr=subprocess.STDOUT, env=env)
    parse_state = 0
    paths: T.List[str] = []
    for line in stdout.split('\n'):
        line = line.strip(' \n\r\t')
        if parse_state == 0:
            if line == '#include "..." search starts here:':
                parse_state = 1
        elif parse_state == 1:
            if line == '#include <...> search starts here:':
                parse_state = 2
            else:
                paths.append(line)
        elif parse_state == 2:
            if line == 'End of search list.':
                break
            else:
                paths.append(line)
    if not paths:
        mlog.warning('No include directory found parsing "{cmd}" output'.format(cmd=" ".join(cmd)))
    # Append a normalized copy of paths to make path lookup easier
    paths += [os.path.normpath(x) for x in paths]
    return paths


class GnuLikeCompiler(Compiler, metaclass=abc.ABCMeta):
    """
    GnuLikeCompiler is a common interface to all compilers implementing
    the GNU-style commandline interface. This includes GCC, Clang
    and ICC. Certain functionality between them is different and requires
    that the actual concrete subclass define their own implementation.
    """

    LINKER_PREFIX = '-Wl,'

    def __init__(self) -> None:
        self.base_options = {
            OptionKey(o) for o in ['b_pch', 'b_lto', 'b_pgo', 'b_coverage',
                                   'b_ndebug', 'b_staticpic', 'b_pie']}
        if not (self.info.is_windows() or self.info.is_cygwin() or self.info.is_openbsd()):
            self.base_options.add(OptionKey('b_lundef'))
        if not self.info.is_windows() or self.info.is_cygwin():
            self.base_options.add(OptionKey('b_asneeded'))
        if not self.info.is_hurd():
            self.base_options.add(OptionKey('b_sanitize'))
        # All GCC-like backends can do assembly
        self.can_compile_suffixes.add('s')
        self.can_compile_suffixes.add('sx')

    def get_pic_args(self) -> T.List[str]:
        if self.info.is_windows() or self.info.is_cygwin() or self.info.is_darwin():
            return [] # On Window and OS X, pic is always on.
        return ['-fPIC']

    def get_pie_args(self) -> T.List[str]:
        return ['-fPIE']

    @abc.abstractmethod
    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        pass

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        return clike_debug_args[is_debug]

    @abc.abstractmethod
    def get_pch_suffix(self) -> str:
        pass

    def split_shlib_to_parts(self, fname: str) -> T.Tuple[str, str]:
        return os.path.dirname(fname), fname

    def get_instruction_set_args(self, instruction_set: str) -> T.Optional[T.List[str]]:
        return gnulike_instruction_set_args.get(instruction_set, None)

    def get_default_include_dirs(self) -> T.List[str]:
        return gnulike_default_include_dirs(tuple(self.get_exelist(ccache=False)), self.language).copy()

    @abc.abstractmethod
    def openmp_flags(self) -> T.List[str]:
        pass

    def gnu_symbol_visibility_args(self, vistype: str) -> T.List[str]:
        if vistype == 'inlineshidden' and self.language not in {'cpp', 'objcpp'}:
            vistype = 'hidden'
        return gnu_symbol_visibility_args[vistype]

    def gen_vs_module_defs_args(self, defsfile: str) -> T.List[str]:
        if not isinstance(defsfile, str):
            raise RuntimeError('Module definitions file should be str')
        # On Windows targets, .def files may be specified on the linker command
        # line like an object file.
        if self.info.is_windows() or self.info.is_cygwin():
            return [defsfile]
        # For other targets, discard the .def file.
        return []

    def get_argument_syntax(self) -> str:
        return 'gcc'

    def get_profile_generate_args(self) -> T.List[str]:
        return ['-fprofile-generate']

    def get_profile_use_args(self) -> T.List[str]:
        return ['-fprofile-use']

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str], build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I' or i[:2] == '-L':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))

        return parameter_list

    @functools.lru_cache()
    def _get_search_dirs(self, env: 'Environment') -> str:
        extra_args = ['--print-search-dirs']
        with self._build_wrapper('', env, extra_args=extra_args,
                                 dependencies=None, mode=CompileCheckMode.COMPILE,
                                 want_output=True) as p:
            return p.stdout

    def _split_fetch_real_dirs(self, pathstr: str) -> T.List[str]:
        # We need to use the path separator used by the compiler for printing
        # lists of paths ("gcc --print-search-dirs"). By default
        # we assume it uses the platform native separator.
        pathsep = os.pathsep

        # clang uses ':' instead of ';' on Windows https://reviews.llvm.org/D61121
        # so we need to repair things like 'C:\foo:C:\bar'
        if pathsep == ';':
            pathstr = re.sub(r':([^/\\])', r';\1', pathstr)

        # pathlib treats empty paths as '.', so filter those out
        paths = [p for p in pathstr.split(pathsep) if p]

        result: T.List[str] = []
        for p in paths:
            # GCC returns paths like this:
            # /usr/lib/gcc/x86_64-linux-gnu/8/../../../../x86_64-linux-gnu/lib
            # It would make sense to normalize them to get rid of the .. parts
            # Sadly when you are on a merged /usr fs it also kills these:
            # /lib/x86_64-linux-gnu
            # since /lib is a symlink to /usr/lib. This would mean
            # paths under /lib would be considered not a "system path",
            # which is wrong and breaks things. Store everything, just to be sure.
            pobj = pathlib.Path(p)
            unresolved = pobj.as_posix()
            if pobj.exists():
                if unresolved not in result:
                    result.append(unresolved)
                try:
                    resolved = pathlib.Path(p).resolve().as_posix()
                    if resolved not in result:
                        result.append(resolved)
                except FileNotFoundError:
                    pass
        return result

    def get_compiler_dirs(self, env: 'Environment', name: str) -> T.List[str]:
        '''
        Get dirs from the compiler, either `libraries:` or `programs:`
        '''
        stdo = self._get_search_dirs(env)
        for line in stdo.split('\n'):
            if line.startswith(name + ':'):
                return self._split_fetch_real_dirs(line.split('=', 1)[1])
        return []

    def get_lto_compile_args(self, *, threads: int = 0, mode: str = 'default') -> T.List[str]:
        # This provides a base for many compilers, GCC and Clang override this
        # for their specific arguments
        return ['-flto']

    def sanitizer_compile_args(self, value: str) -> T.List[str]:
        if value == 'none':
            return []
        args = ['-fsanitize=' + value]
        if 'address' in value:  # for -fsanitize=address,undefined
            args.append('-fno-omit-frame-pointer')
        return args

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-MD', '-MQ', outtarget, '-MF', outfile]

    def get_compile_only_args(self) -> T.List[str]:
        return ['-c']

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if not path:
            path = '.'
        if is_system:
            return ['-isystem' + path]
        return ['-I' + path]

    @classmethod
    def use_linker_args(cls, linker: str, version: str) -> T.List[str]:
        if linker not in {'gold', 'bfd', 'lld'}:
            raise mesonlib.MesonException(
                f'Unsupported linker, only bfd, gold, and lld are supported, not {linker}.')
        return [f'-fuse-ld={linker}']

    def get_coverage_args(self) -> T.List[str]:
        return ['--coverage']

    def get_preprocess_to_file_args(self) -> T.List[str]:
        # We want to allow preprocessing files with any extension, such as
        # foo.c.in. In that case we need to tell GCC/CLANG to treat them as
        # assembly file.
        lang = _LANG_MAP.get(self.language, 'assembler-with-cpp')
        return self.get_preprocess_only_args() + [f'-x{lang}']


class GnuCompiler(GnuLikeCompiler):
    """
    GnuCompiler represents an actual GCC in its many incarnations.
    Compilers imitating GCC (Clang/Intel) should use the GnuLikeCompiler ABC.
    """
    id = 'gcc'

    def __init__(self, defines: T.Optional[T.Dict[str, str]]):
        super().__init__()
        self.defines = defines or {}
        self.base_options.update({OptionKey('b_colorout'), OptionKey('b_lto_threads')})

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        if mesonlib.version_compare(self.version, '>=4.9.0'):
            return gnu_color_args[colortype][:]
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        # Mypy doesn't understand cooperative inheritance
        args = super().get_warn_args(level)
        if mesonlib.version_compare(self.version, '<4.8.0') and '-Wpedantic' in args:
            # -Wpedantic was added in 4.8.0
            # https://gcc.gnu.org/gcc-4.8/changes.html
            args[args.index('-Wpedantic')] = '-pedantic'
        return args

    def supported_warn_args(self, warn_args_by_version: T.Dict[str, T.List[str]]) -> T.List[str]:
        result: T.List[str] = []
        for version, warn_args in warn_args_by_version.items():
            if mesonlib.version_compare(self.version, '>=' + version):
                result += warn_args
        return result

    def has_builtin_define(self, define: str) -> bool:
        return define in self.defines

    def get_builtin_define(self, define: str) -> T.Optional[str]:
        if define in self.defines:
            return self.defines[define]
        return None

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return gnu_optimization_args[optimization_level]

    def get_pch_suffix(self) -> str:
        return 'gch'

    def openmp_flags(self) -> T.List[str]:
        return ['-fopenmp']

    def has_arguments(self, args: T.List[str], env: 'Environment', code: str,
                      mode: CompileCheckMode) -> T.Tuple[bool, bool]:
        # For some compiler command line arguments, the GNU compilers will
        # emit a warning on stderr indicating that an option is valid for a
        # another language, but still complete with exit_success
        with self._build_wrapper(code, env, args, None, mode) as p:
            result = p.returncode == 0
            if self.language in {'cpp', 'objcpp'} and 'is valid for C/ObjC' in p.stderr:
                result = False
            if self.language in {'c', 'objc'} and 'is valid for C++/ObjC++' in p.stderr:
                result = False
        return result, p.cached

    def get_has_func_attribute_extra_args(self, name: str) -> T.List[str]:
        # GCC only warns about unknown or ignored attributes, so force an
        # error.
        return ['-Werror=attributes']

    def get_prelink_args(self, prelink_name: str, obj_list: T.List[str]) -> T.List[str]:
        return ['-r', '-o', prelink_name] + obj_list

    def get_lto_compile_args(self, *, threads: int = 0, mode: str = 'default') -> T.List[str]:
        if threads == 0:
            if mesonlib.version_compare(self.version, '>= 10.0'):
                return ['-flto=auto']
            # This matches clang's behavior of using the number of cpus
            return [f'-flto={multiprocessing.cpu_count()}']
        elif threads > 0:
            return [f'-flto={threads}']
        return super().get_lto_compile_args(threads=threads)

    @classmethod
    def use_linker_args(cls, linker: str, version: str) -> T.List[str]:
        if linker == 'mold' and mesonlib.version_compare(version, '>=12.0.1'):
            return ['-fuse-ld=mold']
        return super().use_linker_args(linker, version)

    def get_profile_use_args(self) -> T.List[str]:
        return super().get_profile_use_args() + ['-fprofile-correction']
```