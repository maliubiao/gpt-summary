Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Initial Understanding of the Request:**

The user wants to understand the functionality of a specific Python file within the Frida project. Key aspects they are interested in are:

* **Functionality:** What does this code do?
* **Relevance to Reverse Engineering:** How might it be used in reverse engineering contexts?
* **Binary/Kernel/Framework Interaction:** Does it touch low-level aspects of the system?
* **Logical Inference:** Are there any clear input/output relationships?
* **Common User Errors:**  Are there pitfalls for developers using this?
* **Debugging Context:** How does someone even *end up* looking at this file?

**2. High-Level Code Overview:**

The first step is to read through the code and get a general idea of its purpose. Keywords and structure immediately suggest:

* **`# SPDX-License-Identifier: Apache-2.0` and `Copyright`:** Standard open-source licensing information.
* **`from __future__ import annotations`:**  Type hinting is used, suggesting a focus on code clarity and maintainability.
* **Imports:**  The imports provide clues about what the code interacts with:
    * `abc`: Abstract base classes – indicates the use of interfaces and polymorphism.
    * `functools`:  `lru_cache` is used for memoization (optimization).
    * `os`, `pathlib`, `subprocess`: Interaction with the operating system and running external commands.
    * `re`: Regular expressions for text processing.
    * `typing as T`:  Extensive use of type hints.
    * `...`:  Relative imports suggest this file is part of a larger project (`frida-clr`, `meson`).
    * `mesonlib`, `mlog`: Likely utility functions and logging within the Meson build system.
    * `mesonbuild.compilers.compilers`:  This is a crucial import, indicating the file is involved in the compilation process.
* **Class Definitions:** `GnuLikeCompiler` and `GnuCompiler`. The names strongly suggest they deal with GNU-style compilers (like GCC and Clang). The use of `metaclass=abc.ABCMeta` reinforces the idea of abstract classes and interfaces.
* **Dictionaries of Flags:**  `clike_debug_args`, `gnu_optimization_args`, etc. These dictionaries map high-level concepts (e.g., optimization levels, debug flags) to compiler-specific command-line arguments.
* **`gnulike_default_include_dirs` function:**  This function runs the compiler with specific flags to extract the default include paths.

**3. Dissecting Key Functionality and Relating to User Queries:**

Now, go through the code section by section, connecting the functionality to the user's questions:

* **Purpose:** The mixins (`GnuLikeCompiler`) and the concrete class (`GnuCompiler`) provide a way for the Meson build system to interact with GNU-like compilers in a consistent manner. They abstract away compiler-specific command-line syntax for common tasks.
* **Reverse Engineering:** This requires some inference. Frida is a dynamic instrumentation tool, often used for reverse engineering. Compiler settings directly impact the generated binary. Things like debug symbols (`-g`), optimization levels (`-O`), and symbol visibility (`-fvisibility`) are all relevant in a reverse engineering context.
* **Binary/Kernel/Framework:** The code itself doesn't directly interact with the kernel or Android framework. However, the *purpose* of compilers is to generate binary code. The flags controlled by this code (like instruction set extensions `-msse`, `-mavx`) directly affect the generated machine code. The default include directories might point to system headers, which are part of the OS and frameworks.
* **Logical Inference:**  The dictionaries of flags clearly show input-output relationships. For example, the input `'2'` to `gnu_optimization_args` results in the output `['-O2']`. The `gnulike_default_include_dirs` function takes a compiler executable as input and outputs a list of include directories.
* **Common User Errors:** The code handles some error scenarios (like unsupported linker names). However, the main potential for user error lies in *configuration* at a higher level in the Meson build system. For example, specifying an invalid optimization level or warning level. The code itself is more about *mapping* valid inputs to compiler flags.
* **Debugging Context:** The file path `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/gnu.py` itself provides a strong clue. Someone debugging the Frida build process, particularly issues related to the Common Language Runtime (CLR) or compiler interactions, might need to examine this file. Compiler errors or unexpected behavior during the build would be reasons to delve into these compiler mixins.

**4. Structuring the Answer:**

Organize the findings into the categories requested by the user:

* **Functionality:**  Provide a concise summary of the code's role in the build process.
* **Reverse Engineering:** Give concrete examples of how compiler settings controlled by this code impact reverse engineering.
* **Binary/Kernel/Framework:** Explain the indirect relationship through the generated binary and system headers.
* **Logical Inference:** Present clear input/output examples.
* **Common User Errors:** Focus on the Meson configuration level rather than errors *within* the Python code itself.
* **Debugging Context:** Describe the steps a user might take to arrive at this file, emphasizing the build process and potential compiler-related issues.

**5. Refining and Expanding:**

* **Clarity:** Use clear and concise language. Avoid jargon where possible, or explain it.
* **Examples:** Provide concrete examples to illustrate the concepts. For instance, showing the mapping of optimization levels to flags.
* **Specificity:**  Reference specific parts of the code (like the dictionaries and the `gnulike_default_include_dirs` function).
* **Frida Context:** Since the user mentioned Frida, connect the functionality back to the purpose of Frida as a dynamic instrumentation tool.

By following this structured thought process, you can effectively analyze the code and provide a comprehensive and helpful answer to the user's request. The key is to break down the code, understand its individual components, and then synthesize that knowledge to address the specific questions posed.
This Python code file, `gnu.py`, located within the Frida dynamic instrumentation tool's build system (Meson), defines **mixins** for handling **GNU-like compilers**. These mixins provide reusable functionalities and common configurations for compilers like GCC, Clang, and ICC within the Meson build environment.

Here's a breakdown of its functionalities:

**1. Defining Compiler Options and Flags:**

* **Standardized Argument Mapping:** It defines dictionaries that map high-level concepts (like debug levels, optimization levels, CPU instruction sets, symbol visibility, and warning levels) to the corresponding command-line flags used by GNU-like compilers.
    * **Example:** `gnu_optimization_args` maps optimization levels ('0', '1', '2', '3', 's') to their respective compiler flags (`-O0`, `-O1`, etc.).
* **Conditional Flags:** It handles compiler-specific behavior and platform differences when applying certain flags. For instance, PIC (Position Independent Code) is handled differently on Windows and macOS.
* **Warning Management:** It provides a comprehensive list of warning flags supported by GCC across different versions, allowing the build system to enable specific warnings based on the compiler's capabilities.

**2. Abstract Base Class (`GnuLikeCompiler`):**

* **Interface Definition:**  It defines an abstract base class `GnuLikeCompiler` that outlines the common interface and methods expected from GNU-like compilers. This promotes code reusability and ensures consistency in how Meson interacts with different compilers in this family.
* **Common Methods:**  This class includes methods for:
    * Getting PIC and PIE (Position Independent Executable) flags.
    * Retrieving optimization and debug flags.
    * Determining the suffix for precompiled headers (PCH).
    * Splitting shared library names.
    * Handling instruction set arguments (like SSE, AVX).
    * Getting default include directories.
    * Managing OpenMP flags.
    * Controlling symbol visibility.
    * Handling module definition files (like `.def` on Windows).
    * Generating profiling and coverage flags.
    * Managing Link-Time Optimization (LTO) flags.
    * Setting up sanitizers (like AddressSanitizer).
    * Generating dependency information.
    * Handling include paths.
    * Specifying the linker to use.

**3. Concrete Compiler Class (`GnuCompiler`):**

* **GCC-Specific Implementation:** It defines a concrete class `GnuCompiler` that inherits from `GnuLikeCompiler` and provides specific implementations for GCC. This includes handling GCC-specific features and flags.
* **Built-in Define Handling:** It can check and retrieve built-in preprocessor defines for GCC.
* **Version-Specific Behavior:** It adjusts its behavior based on the GCC version, using features available in specific versions and potentially working around older limitations.

**Relationship to Reverse Engineering:**

This code directly relates to reverse engineering in several ways:

* **Controlling Binary Characteristics:** The compiler flags managed by this code directly influence the characteristics of the generated binary, which is the target of reverse engineering.
    * **Example:** Setting the debug level (`-g`) includes debugging symbols in the binary, making it easier to analyze with debuggers like GDB or LLDB. Conversely, building with `-O3` (highest optimization) can make reverse engineering harder due to code transformations and inlining.
    * **Example:** The `-fvisibility` flag controls the visibility of symbols in shared libraries. Setting it to `hidden` makes it harder to dynamically link to or hook functions in the library during runtime analysis.
    * **Example:** Instruction set extensions (like SSE or AVX) determine the specific machine instructions used, which a reverse engineer needs to understand when analyzing assembly code.
* **Reproducible Builds:** By standardizing the compiler flags, this code contributes to creating reproducible builds. This is important for reverse engineers who want to analyze a specific version of a software and ensure they are looking at the exact same binary.
* **Understanding Build Configuration:**  Knowing how the target was built (compiler, flags) can provide valuable context for reverse engineering. For instance, knowing if LTO was enabled can explain why function calls might be inlined across compilation units.

**Examples relating to Reverse Engineering:**

* **Scenario:** A reverse engineer wants to analyze a Frida gadget library (a shared library loaded by Frida). If this library was built using the `gnu.py` mixins, the flags set here would directly impact the library's structure and behavior.
* **Debugging:** If the reverse engineer needs to debug the gadget library, they would want it to be built with debugging symbols (`-g`). Meson, using this code, would ensure the correct flags are passed to the compiler if the `debug` build type is selected.
* **Performance Analysis:**  If the reverse engineer is investigating performance issues, they might be interested in knowing the optimization level used during compilation. This code manages those settings.
* **Security Analysis:**  Reverse engineers performing security audits might look for the presence or absence of certain compiler flags, like stack canaries (`-fstack-protector-strong`), which are managed by other parts of the Meson build system but are related to the compiler's capabilities handled here.

**Involvement of Binary底层, Linux, Android内核及框架的知识:**

This code directly interacts with and leverages knowledge of:

* **Binary 底层 (Low-Level Binary):**
    * **Compiler Flags and their Binary Output:** The core function is mapping high-level build options to specific compiler flags that directly control the generated machine code. Understanding how `-O2` differs from `-O0` at the binary level is crucial.
    * **Instruction Set Extensions:**  Options like `-msse4.2` directly tell the compiler to use specific CPU instructions, impacting the binary's instruction stream.
    * **Symbol Visibility:** The `-fvisibility` flag controls how symbols are exported in shared libraries, which is a fundamental concept in dynamic linking at the binary level.
    * **Position Independent Code (PIC) and Position Independent Executables (PIE):** These are crucial for security and dynamic loading on modern systems, and the code handles the platform-specific flags for them.
* **Linux:**
    * **GNU Toolchain:**  It's specifically designed for GNU-like compilers commonly used on Linux (GCC, Clang).
    * **Shared Library Conventions:** Concepts like symbol visibility and PIC/PIE are essential for how shared libraries work on Linux.
    * **Default Include Paths:** The code retrieves default include directories, which are system-specific on Linux.
* **Android Kernel and Framework (Indirectly):**
    * **Android NDK:** While this specific file might not directly interact with Android specifics, Frida is often used on Android. The underlying compilation process for Android libraries and executables would use similar compiler flags and concepts.
    * **System Libraries:** The default include paths might include headers from the Android framework or the underlying Linux kernel, although this code itself doesn't parse those headers.

**Logical Inference with Hypothetical Input and Output:**

**Hypothetical Input:**

* **User sets the Meson option `optimization` to `'2'`.**
* **The target language is C++ (`'cpp'`).**
* **The compiler is GCC, version `9.3.0`.**

**Logical Output (Based on the code):**

* The `get_optimization_args('2')` method in `GnuCompiler` would return `['-O2']`.
* When compiling the C++ source files, Meson would pass the `-O2` flag to the GCC compiler.
* If the user also set `debug` to `true`, the `get_debug_args(True)` method would return `['-g']`, and `-g` would also be passed to the compiler.
* If the user configured a specific instruction set like `'avx2'`, `get_instruction_set_args('avx2')` would return `['-mavx2']`, and this flag would be included in the compilation command.

**Hypothetical Input (for warning levels):**

* **User sets the Meson option `werror` to `true`.** (This is handled elsewhere in Meson but influences the warning flags)
* **User sets the Meson option `warning_level` to `'3'`.**

**Logical Output (Based on the code and GCC version):**

* The `get_warn_args('3')` method (inherited from a base class not fully shown here) would likely return a collection of warning flags, including `-Wall`, `-Wextra`, and potentially more specific warnings enabled at level 3.
* Because `werror` is true, the `-Werror` flag would also be added to the compilation command, turning warnings into errors.

**User or Programming Common Usage Errors and Examples:**

* **Incorrectly Specifying Instruction Set:**
    * **Error:** A user might specify an instruction set (`'sse5'`) that is not supported by the target CPU or the compiler.
    * **Result:** The `get_instruction_set_args` method would return `None`, and the build system might either ignore the invalid option or raise an error (depending on how Meson handles `None` returns). If the build system passes `None` or an empty list to the compiler, the compiler might ignore it, or in some cases, produce an error.
* **Using Incompatible Warning Levels with Compiler Version:**
    * **Error:** A user might set `warning_level` to a high value that includes warnings not supported by an older version of GCC.
    * **Result:** The `supported_warn_args` method would filter out the unsupported warnings, preventing build errors but potentially missing some desired checks.
* **Misunderstanding Symbol Visibility:**
    * **Error:** A developer might set symbol visibility to `hidden` when they intend for the library to export certain symbols for external use.
    * **Result:**  Linking errors would occur when other parts of the program try to use the hidden symbols. This is a logical error in the build configuration, and this code correctly translates the `hidden` setting to the compiler flag.
* **Typos in Option Names:**
    * **Error:**  A user might misspell a Meson option name (e.g., `optimizaton` instead of `optimization`).
    * **Result:** Meson would likely ignore the misspelled option, and the compiler would use its default settings. This isn't an error *in* this code, but a common user error in the build system configuration.

**How User Operations Lead to This Code (Debugging Clues):**

1. **User Starts a Build:** The user initiates the build process using Meson (e.g., `meson setup builddir` followed by `ninja -C builddir`).
2. **Meson Configuration:** Meson reads the `meson.build` file, which specifies the build targets, dependencies, and compiler options.
3. **Compiler Selection:** Meson determines the appropriate compiler to use (e.g., GCC if it's available and configured).
4. **Target Compilation:** When Meson needs to compile a source file (e.g., a `.c` or `.cpp` file), it needs to determine the correct compiler flags.
5. **Compiler Mixin Lookup:** Meson looks up the appropriate compiler mixin for the selected compiler. In this case, for GCC, it would use the `GnuCompiler` class defined in `gnu.py`.
6. **Flag Generation:**  Meson calls methods on the `GnuCompiler` instance (or its parent `GnuLikeCompiler`) to get the necessary compiler flags based on the user-defined options and the target language.
    * **Example:** If the user set `optimization = '2'`, Meson would call `compiler.get_optimization_args('2')`.
    * **Example:** If the build is a debug build, Meson would call `compiler.get_debug_args(True)`.
7. **Compiler Invocation:** Meson constructs the full compiler command line, including the generated flags, and executes the compiler process.

**Debugging Scenario:**

A developer might end up looking at `gnu.py` in these situations:

* **Unexpected Compiler Flags:** If the compiler is being invoked with flags the developer didn't expect, they might trace back through Meson's code to see how the flags are generated. This would lead them to the compiler mixins.
* **Compiler Errors:** If the compiler throws an error due to a specific flag, the developer might investigate which part of Meson's code is responsible for adding that flag.
* **Feature Request/Bug Fix:**  If a developer wants to add support for a new compiler flag or fix a bug related to how compiler flags are handled, they would likely need to modify the code in files like `gnu.py`.
* **Understanding Frida's Build System:**  Someone curious about how Frida is built and the compiler settings used might explore the Meson build files, including the compiler mixins.

In summary, `gnu.py` is a crucial part of Frida's build system, responsible for abstracting and managing the complexities of GNU-like compilers, ensuring consistent and configurable builds, which directly impacts the characteristics of the generated binaries and is therefore relevant to reverse engineering efforts.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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