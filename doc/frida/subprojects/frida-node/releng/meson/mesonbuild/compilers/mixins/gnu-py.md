Response:
The user wants to understand the functionality of the Python code provided, which is a mixin class for GNU-like compilers in the Frida dynamic instrumentation tool. I need to analyze the code and explain its purpose and how it relates to reverse engineering, binary manipulation, and system-level programming concepts like Linux and Android kernels.

Here's a breakdown of the requested information:

1. **Functionality:** Describe what the code does.
2. **Relation to Reverse Engineering:** Provide examples if the code aids in reverse engineering.
3. **Binary/Kernel/Framework Relation:** Explain if the code interacts with low-level binary, Linux/Android kernels, or frameworks and provide examples.
4. **Logical Reasoning (Input/Output):** If the code performs logical operations, create hypothetical inputs and outputs.
5. **Common User Errors:** Identify potential mistakes users might make when interacting with or configuring this code.
6. **User Path to This Code (Debugging):** Explain how a user's actions might lead to this specific file being relevant during debugging.

Let's go through each point:

**1. Functionality:**

The code defines a mixin class `GnuLikeCompiler` and its subclass `GnuCompiler`. These classes provide common functionalities for compilers that follow the GNU command-line interface, such as GCC and Clang. This includes handling compiler flags for:

*   Optimization levels (-O0, -O1, -O2, -O3, -Os, -Og)
*   Debugging information (-g)
*   Instruction set extensions (-mmx, -msse, -mavx, -mfpu=neon)
*   Symbol visibility (-fvisibility)
*   Warning levels (-Wall, -Wextra, specific warnings)
*   Position Independent Code (-fPIC, -fPIE)
*   Link-Time Optimization (-flto)
*   Code coverage (--coverage)
*   Preprocessor output (-E)
*   Include directories (-I, -isystem)
*   Linker selection (-fuse-ld)
*   Profiling (-fprofile-generate, -fprofile-use)
*   Sanitizers (-fsanitize)

The code also includes logic to:

*   Determine default include directories by running the compiler.
*   Manage precompiled headers.
*   Handle module definition files (.def).
*   Adjust arguments for different operating systems (Windows, macOS, Linux).

**2. Relation to Reverse Engineering:**

Frida is a dynamic instrumentation toolkit often used for reverse engineering. This code plays a role in setting up the build environment for Frida's components that might need to be compiled. Here are some examples:

*   **Debugging Symbols:** The `-g` flag, handled by `get_debug_args`, is crucial for generating debugging symbols. These symbols are essential for reverse engineers using debuggers (like GDB or LLDB) to understand the program's execution flow, variable values, and function calls. Frida uses these symbols to hook into functions and inspect program state.
*   **Optimization Levels:** Reverse engineers might want to compile Frida with no optimizations (`-O0`) to make the code easier to follow during debugging. Conversely, they might want to analyze optimized code to understand the techniques used. This mixin allows configuring the optimization level.
*   **Instruction Set Extensions:** Understanding which instruction set extensions are used can be relevant in reverse engineering, especially when analyzing performance-critical code or when dealing with specific hardware features. This code helps manage compiler flags related to instruction sets.
*   **Symbol Visibility:** The `-fvisibility` flag controls which symbols are exported from a shared library. Reverse engineers often need to understand the exported interface of libraries they are interacting with.
*   **Sanitizers:**  Compiling with sanitizers like AddressSanitizer (`-fsanitize=address`) can help detect memory corruption bugs, which can be important in understanding vulnerabilities during reverse engineering.

**3. Binary/Kernel/Framework Relation:**

This code directly deals with compiler flags, which instruct the compiler on how to generate binary code. Here's how it relates to binary, Linux/Android kernels, and frameworks:

*   **Binary Level:** Compiler flags directly influence the generated machine code. Flags like `-march`, `-mtune`, and the instruction set extensions flags control the specific CPU instructions used. Optimization flags determine how the code is structured for performance.
*   **Linux Kernel:** While this Python code doesn't directly interact with the Linux kernel code, the compiled Frida tools will run on Linux and might interact with kernel APIs or data structures. The choice of compiler flags can affect the compatibility and performance of Frida on different Linux kernel versions. For example, compiling with specific kernel header paths using `-isystem` ensures compatibility.
*   **Android Kernel/Framework:** Similar to Linux, Frida runs on Android. The `get_default_include_dirs` function helps locate necessary headers for compiling against the Android NDK, which provides access to Android's system libraries and potentially kernel interfaces. Flags like `-fPIE` (Position Independent Executable) are important for security on Android. The `neon` instruction set argument is specific to ARM architectures, common in Android devices.
*   **Shared Libraries:** Flags related to symbol visibility are critical when building shared libraries (like Frida's agent). These flags determine what symbols are accessible from other libraries or the main executable.

**4. Logical Reasoning (Input/Output):**

Consider the `gnu_optimization_args` dictionary:

*   **Input:** `'2'` (string representing optimization level)
*   **Output:** `['-O2']` (list containing the corresponding compiler flag)

Another example is `get_debug_args`:

*   **Input:** `True` (boolean indicating debug build)
*   **Output:** `['-g']` (list containing the debug flag)

For `get_instruction_set_args`:

*   **Input:** `'avx2'`
*   **Output:** `['-mavx2']`

*   **Input:** `'xyz'` (an unsupported instruction set)
*   **Output:** `None`

**5. Common User Errors:**

*   **Incorrect Compiler Selection:** If a user attempts to use a non-GNU-like compiler without appropriate configuration, the assumptions made by this mixin might be invalid, leading to build errors.
*   **Mismatched Optimization Levels:** Specifying conflicting optimization levels or flags manually might lead to unexpected behavior or build failures.
*   **Incorrect Warning Level Configuration:** Users might misunderstand the impact of different warning flags, leading to noisy builds or missed potential issues. For example, enabling `-Werror` without understanding the implications can suddenly break the build on warnings that were previously tolerated.
*   **Typos in Instruction Set Names:**  Providing an incorrect instruction set name (e.g., `'avx3'`) would result in the `get_instruction_set_args` returning `None`, and the compiler might not be invoked with the intended flag.
*   **Path Issues with Include Directories:** If the default include directories are not correctly detected or if users manually specify incorrect include paths, the compiler won't find necessary header files.

**6. User Path to This Code (Debugging):**

A user might encounter this code during debugging in the following scenarios:

1. **Build System Issues:** If the Frida build process fails due to incorrect compiler flags or configurations, developers might need to inspect the Meson build scripts. This file is part of the Meson setup for Frida's Node.js bindings. They might look at the generated `compile_commands.json` or the Meson log to see the exact compiler commands being used and trace back the origin of the flags to files like this one.

2. **Investigating Compiler Flag Behavior:** If a user observes unexpected behavior in the compiled Frida binaries, such as performance issues or crashes, they might suspect the compiler flags. They might then delve into the Meson build files to understand how these flags are being set. For instance, if they suspect LTO is causing issues, they might look at how `b_lto` is handled.

3. **Adding Custom Compiler Flags:**  If a user wants to add specific compiler flags for debugging or experimentation, they might need to understand how Meson and Frida's build system handle compiler options. This file shows how common flags are managed, providing a template for adding custom ones.

4. **Debugging Frida's Node.js Bindings:**  Since the file path indicates it's part of the Frida Node.js binding build process, issues specific to compiling the native Node.js addon might lead developers to investigate this file. For example, problems with header file inclusion or linking could lead them here.

5. **Porting Frida to a New Platform:** When porting Frida to a new operating system or architecture, developers might need to adjust the compiler flags. They would then examine files like this to see how existing flags are handled and how to add new platform-specific ones.

In essence, whenever there's a problem related to how Frida's native components are being compiled using a GNU-like compiler, this file becomes a potential point of investigation within the Frida build system.

This Python file, located at `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/gnu.py`, is a part of Frida's build system, which uses Meson as its build tool. Specifically, this file defines a **mixin class** called `GnuLikeCompiler` and a concrete class `GnuCompiler`. These classes provide functionalities and configurations for compilers that behave like the GNU Compiler Collection (GCC), including Clang and other compatible compilers.

Here's a breakdown of its functionality and how it relates to your points:

**Functionality:**

1. **Provides common compiler arguments:** The file defines dictionaries (like `clike_debug_args`, `gnu_optimization_args`, `gnulike_instruction_set_args`, `gnu_symbol_visibility_args`, `gnu_color_args`, and various warning flag dictionaries) that map abstract concepts (like debug mode, optimization level, instruction set) to specific command-line arguments used by GNU-like compilers.
2. **Abstract interface for GNU-like compilers:** The `GnuLikeCompiler` class serves as an abstract base class, defining methods that all GNU-like compilers should implement or inherit. This promotes code reuse and a consistent way to interact with different compilers.
3. **Concrete implementation for GCC:** The `GnuCompiler` class provides a specific implementation for the GCC compiler, inheriting from `GnuLikeCompiler`. It might have GCC-specific behavior or arguments.
4. **Handles compiler options:** The code includes methods to generate compiler arguments based on user-defined options (like debug mode, optimization level, LTO, PGO, coverage). These options are typically configured in Meson's build definition files (`meson.build`).
5. **Manages include directories:** The `gnulike_default_include_dirs` function and the `get_default_include_dirs` method are responsible for determining the default include paths used by the compiler.
6. **Supports various compiler features:** It includes support for precompiled headers (PCH), Link-Time Optimization (LTO), Profile-Guided Optimization (PGO), code coverage, and sanitizers.
7. **Handles platform differences:** The code considers differences between operating systems (Windows, macOS, Linux) when determining compiler arguments (e.g., PIC behavior).

**Relation to Reverse Engineering:**

This file directly contributes to the build process of Frida, a powerful tool for dynamic instrumentation and often used in reverse engineering. Here's how:

*   **Debugging Symbols:** The `get_debug_args` method generates the `-g` flag, which is essential for including debugging symbols in the compiled Frida binaries. These symbols are crucial for reverse engineers who want to attach debuggers (like GDB or LLDB) to Frida and understand its internal workings.
    *   **Example:** When a reverse engineer wants to step through Frida's code to understand how it hooks into a target process, they need debugging symbols. This file ensures that the `-g` flag is passed to the compiler when building Frida in debug mode.
*   **Optimization Levels:** The `get_optimization_args` method allows configuring the optimization level. Reverse engineers might prefer to compile Frida with no optimizations (`-O0`) to make the code easier to follow during debugging.
    *   **Example:** If a reverse engineer is trying to understand a specific algorithm within Frida, compiling with `-O0` will prevent the compiler from reordering or optimizing away code, making the source code more directly correspond to the executed instructions.
*   **Instruction Set Extensions:** The `get_instruction_set_args` method handles flags for enabling specific CPU instruction set extensions (like SSE, AVX). This can be relevant for reverse engineers analyzing performance-critical parts of Frida or when dealing with specific hardware features.
    *   **Example:** If a reverse engineer suspects Frida is using specific SIMD instructions, knowing the compiler flags used to enable them can help in understanding the generated assembly code.
*   **Sanitizers:** The `sanitizer_compile_args` method adds flags for memory error detection tools like AddressSanitizer (`-fsanitize=address`). These tools are valuable for finding bugs in Frida itself, which is crucial for a reliable reverse engineering tool.
    *   **Example:** If Frida has a memory corruption bug, compiling it with AddressSanitizer can help identify the exact location and cause of the error.

**Relation to Binary Underlying, Linux, Android Kernel & Framework:**

This file operates at the level of compiler configuration, which directly influences the generated binary code and its interaction with the underlying system.

*   **Binary Underlying:** The compiler flags managed by this file directly affect the machine code generated by the compiler. Optimization flags determine how instructions are arranged and whether certain optimizations are applied. Instruction set extensions determine which CPU instructions can be used.
    *   **Example:** The `-fPIC` and `-fPIE` flags, handled indirectly through build options, are crucial for creating position-independent code, which is often required for shared libraries and for security features on modern operating systems.
*   **Linux Kernel:** While this file doesn't directly interact with the Linux kernel source code, the compiler arguments it generates are essential for building software that runs on Linux. The `get_default_include_dirs` function helps locate necessary header files for system libraries.
    *   **Example:** When compiling Frida components that interact with Linux system calls, the compiler needs to find the relevant header files (e.g., from `/usr/include/`) which this file helps configure.
*   **Android Kernel & Framework:** Similar to Linux, when building Frida components for Android, this file helps configure the compiler to target the Android environment. The `neon` instruction set argument is specific to ARM architectures commonly used in Android devices.
    *   **Example:** Compiling Frida for Android might involve using the Android NDK, and this file helps configure the compiler to find the necessary headers and libraries provided by the NDK.
*   **Shared Libraries:** Flags related to symbol visibility (`-fvisibility`) are important for building shared libraries like Frida's agent. These flags control which symbols are exported and accessible from other parts of the system.

**Logical Reasoning (Hypothetical Input & Output):**

*   **Assumption:** The user wants to build Frida in debug mode.
    *   **Input:**  The Meson build option `buildtype` is set to `debug`.
    *   **Output:** The `get_debug_args(True)` method will be called, returning `['-g']`. This flag will be added to the compiler command line, ensuring debugging symbols are included in the output binary.
*   **Assumption:** The user wants to optimize Frida for performance using the `-O2` optimization level.
    *   **Input:** The Meson build option `optimization` is set to `2`.
    *   **Output:** The `get_optimization_args('2')` method will be called, returning `['-O2']`. This flag will be added to the compiler command line, instructing the compiler to perform level 2 optimizations.
*   **Assumption:** The user's system has AVX2 support, and they want to enable it during compilation.
    *   **Input:** The Meson build option (or an explicitly passed compiler argument) requests the `avx2` instruction set.
    *   **Output:** The `get_instruction_set_args('avx2')` method will be called, returning `['-mavx2']`. This flag will be added to the compiler command line, allowing the compiler to utilize AVX2 instructions.

**User or Programming Common Usage Errors:**

*   **Incorrectly specifying optimization levels:** A user might try to set conflicting optimization flags manually in addition to what Meson configures, leading to unpredictable compiler behavior.
    *   **Example:** Setting `optimization = '0'` in Meson and then manually adding `-O3` to the compiler flags.
*   **Typographical errors in instruction set names:**  Users might mistype instruction set names, causing the compiler to ignore them or issue warnings.
    *   **Example:**  Trying to enable `'avx_2'` instead of `'avx2'`.
*   **Misunderstanding warning flags:** Users might enable too many warnings without understanding their implications, leading to noisy builds or even build failures if warnings are treated as errors.
    *   **Example:** Enabling `-Werror` along with a broad set of warnings without reviewing the existing codebase for potential violations.
*   **Issues with include paths:**  If the system's include paths are not correctly configured or if the user provides incorrect custom include paths, the compiler might fail to find necessary header files.
    *   **Example:**  Forgetting to install necessary development packages, causing header files to be missing.

**User Operation Steps to Reach Here (Debugging):**

A user, likely a developer or someone building Frida from source, might end up investigating this file in several scenarios:

1. **Build Errors Related to Compiler Flags:** If the Frida build fails with compiler errors related to specific flags (e.g., "unrecognized command-line option"), they might trace back where those flags are being generated. By examining the Meson build log or the generated `compile_commands.json` file, they can identify that the problematic flag originates from this `gnu.py` file.
2. **Investigating Optimization or Performance Issues:** If Frida is built and running but exhibits unexpected performance, a developer might suspect the compiler optimization settings. They might then look at this file to see how optimization levels are configured and how to potentially change them.
3. **Debugging Frida Itself:** When debugging Frida's native components (as opposed to the JavaScript API), developers might need to rebuild Frida with debugging symbols enabled. They might then check this file to confirm that the `-g` flag is being correctly applied in debug builds.
4. **Adding or Modifying Compiler Flags:** If a developer needs to add a specific compiler flag for a particular use case (e.g., enabling a specific warning or feature), they might need to understand how this file structures the compiler arguments and potentially modify it or a related Meson build file.
5. **Porting Frida to a New Platform:** When porting Frida to a new operating system or architecture, developers might need to adjust the compiler flags. They would likely examine this file to understand how existing flags are handled and where to introduce platform-specific logic.

In essence, anyone working on the build process of Frida or debugging issues related to how Frida is compiled using a GNU-like compiler might find themselves examining this `gnu.py` file to understand and potentially modify the compiler configurations.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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