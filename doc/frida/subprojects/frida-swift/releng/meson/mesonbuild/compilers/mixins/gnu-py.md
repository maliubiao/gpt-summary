Response:
The user wants to understand the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The file `gnu.py` defines mixin classes for compilers that behave like the GNU compiler collection (GCC). I need to analyze the code and explain its purpose, highlighting aspects related to reverse engineering, low-level details, and potential user errors.

Here's a breakdown of the request and how to address each part:

1. **Functionality:**  I'll go through the code section by section, describing the purpose of each class, method, and data structure. The core functionality revolves around providing reusable components for compiler implementations within Frida.

2. **Relation to Reverse Engineering:** I need to connect the compiler options and flags defined in this file to common reverse engineering tasks. This might involve understanding how certain flags affect the generated binary and how that impacts reverse engineering efforts.

3. **Binary/Low-Level, Linux/Android Kernel/Framework:**  The compiler options directly influence the generated binary code. I need to explain how certain flags affect aspects like memory layout, optimizations, and debugging information, and how these relate to the underlying operating system (Linux, Android).

4. **Logical Reasoning (Input/Output):**  For methods that perform transformations or decisions based on input, I'll create simple examples to illustrate the flow.

5. **User/Programming Errors:** I'll identify common mistakes users might make when configuring or using the compiler options exposed through this code.

6. **User Operation to Reach the File (Debugging Clue):** I need to think about the context in which this code is used within Frida. What actions would a developer or user take that might lead to the execution of this specific file?  This will likely involve Frida's build system (Meson) and the selection of a GNU-like compiler.
这个Python源代码文件 `gnu.py` 是 Frida 动态 instrumentation 工具中负责处理类 GNU 编译器的模块。它定义了一些 mixin 类，这些类提供了针对 GCC (GNU Compiler Collection) 及其类似编译器的通用功能和配置。这些 mixin 可以被其他更具体的编译器类继承，以减少代码重复并提供一致的编译器处理方式。

以下是该文件的主要功能：

**1. 定义通用的编译器选项和参数:**

*   **调试信息 (`clike_debug_args`)**:  定义了用于生成调试信息的编译器参数，例如 `-g`。
*   **优化级别 (`gnu_optimization_args`)**:  定义了不同优化级别的编译器参数，例如 `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-Og`。
*   **指令集 (`gnulike_instruction_set_args`)**: 定义了指定目标 CPU 指令集的编译器参数，例如 `-mmx`, `-msse`, `-mavx`, `-mfpu=neon`。
*   **符号可见性 (`gnu_symbol_visibility_args`)**: 定义了控制符号可见性的编译器参数，例如 `-fvisibility=default`, `-fvisibility=hidden`。
*   **错误/警告颜色 (`gnu_color_args`)**: 定义了控制编译器错误/警告输出颜色的参数，例如 `-fdiagnostics-color=auto`。
*   **各种警告 (`gnu_common_warning_args`, `gnu_c_warning_args`, `gnu_cpp_warning_args`, `gnu_objc_warning_args`)**:  详细列出了不同版本的 GCC 支持的各种警告标志，用于提高代码质量。

**2. 提供 Mixin 类 (`GnuLikeCompiler`, `GnuCompiler`)**:

*   **`GnuLikeCompiler`**:  这是一个抽象基类，定义了类 GNU 编译器的通用接口。它包含了处理位置无关代码 (PIC)、可执行文件位置无关 (PIE)、优化、调试、预编译头文件 (PCH)、指令集、符号可见性、模块定义文件、代码剖析 (Profiling)、链接器参数、代码覆盖率等功能的通用方法。
*   **`GnuCompiler`**:  继承自 `GnuLikeCompiler`，代表实际的 GCC 编译器。它实现了特定于 GCC 的功能，例如获取内置宏定义、处理警告、链接时优化 (LTO) 等。

**3. 获取默认的包含目录 (`gnulike_default_include_dirs`)**:

*   该函数通过调用编译器自身并解析其输出来获取默认的头文件搜索路径。

**与逆向方法的关系及举例说明:**

该文件中的编译器选项和参数与逆向工程密切相关：

*   **调试信息 (`-g`)**: 在编译时包含调试符号，使得逆向工程师可以使用调试器 (如 GDB, LLDB) 来单步执行代码、查看变量值、设置断点等，从而理解程序的执行流程和内部状态。
*   **优化级别 (`-O0`, `-O1`, `-O2`, `-O3`)**:  不同的优化级别会显著影响生成的可执行文件的结构和执行效率。
    *   `-O0` (无优化) 生成的代码更接近源代码，更易于理解和调试，但性能较差。逆向分析未优化的代码通常更容易，因为代码结构更直观。
    *   `-O2` 或 `-O3` (高优化) 生成的代码经过了各种转换和优化，例如内联函数、循环展开、死代码消除等，代码结构可能与源代码相差很大，这使得逆向分析更加困难。逆向工程师需要理解编译器的优化策略才能有效地分析这些代码。
*   **指令集 (`-msse`, `-mavx`)**:  了解目标程序的指令集可以帮助逆向工程师理解程序可能利用的硬件特性和性能优化。例如，如果使用了 AVX 指令，逆向工程师需要了解这些指令的功能才能正确分析相关的代码段。
*   **符号可见性 (`-fvisibility=hidden`)**:  将符号设置为隐藏可以阻止动态链接器在其他模块中查找这些符号，这可以提高安全性并减少符号冲突。但在逆向工程中，隐藏符号会使得静态分析和动态分析更加困难，因为逆向工程师可能无法直接访问或引用这些符号。
*   **位置无关代码 (`-fPIC`) 和可执行文件位置无关 (`-fPIE`)**:  这些选项影响代码的加载地址。
    *   `-fPIC` 用于生成共享库，使得库可以在内存中的任意地址加载，这在逆向分析共享库时需要考虑。
    *   `-fPIE` 用于生成可执行文件，增加了地址空间布局随机化 (ASLR) 的有效性，使得每次运行时代码的加载地址都不同，增加了攻击难度，也使得基于静态地址的逆向分析更加复杂。
*   **代码覆盖率 (`--coverage`)**:  虽然这个选项主要用于测试，但在逆向工程中，通过代码覆盖率工具可以了解程序执行了哪些代码路径，有助于理解程序的行为。

**涉及到二进制底层，Linux, Android内核及框架的知识的举例说明:**

*   **二进制底层**:  编译器选项直接影响生成的二进制代码的指令序列、内存布局、以及与操作系统交互的方式。例如，指令集选项决定了使用的 CPU 指令，优化选项会改变指令的排列和数量。
*   **Linux 内核**:
    *   **`-fPIE`**: 与 Linux 内核的地址空间布局随机化 (ASLR) 功能配合使用，提高了系统的安全性。内核在加载程序时会将代码段、数据段、堆栈等随机放置在内存中。
    *   **符号可见性**:  影响动态链接器 (`ld-linux.so`) 的行为。Linux 内核负责加载和链接动态库，符号可见性决定了哪些符号可以被其他库访问。
*   **Android 内核及框架**: Android 基于 Linux 内核，因此许多概念是相同的。
    *   **`-fPIC`**:  在 Android 中，几乎所有的共享库都需要使用 `-fPIC` 编译。
    *   **`-mfpu=neon`**:  指定使用 ARM 架构的 NEON SIMD 指令集，这在 Android 平台上进行多媒体处理和性能优化时非常常见。Android 框架层可能会利用这些优化过的库。

**逻辑推理的假设输入与输出举例:**

*   **函数 `get_optimization_args(optimization_level)` (在 `GnuCompiler` 中):**
    *   **假设输入**: `optimization_level = '2'`
    *   **预期输出**: `['-O2']`
    *   **逻辑**:  根据提供的优化级别字符串，从 `gnu_optimization_args` 字典中查找对应的编译器参数。
*   **函数 `gnu_symbol_visibility_args(vistype)` (在 `GnuLikeCompiler` 中):**
    *   **假设输入**: `vistype = 'hidden'`
    *   **预期输出**: `['-fvisibility=hidden']`
    *   **逻辑**:  根据提供的符号可见性类型字符串，从 `gnu_symbol_visibility_args` 字典中查找对应的编译器参数。
    *   **假设输入**: `vistype = 'inlineshidden'`, `self.language = 'c'`
    *   **预期输出**: `['-fvisibility=hidden']`
    *   **逻辑**:  如果 `vistype` 是 `inlineshidden` 且当前语言不是 C++ 或 Objective-C++，则降级为 `hidden`，因为 `-fvisibility-inlines-hidden` 只对 C++ 类语言有效。

**涉及用户或编程常见的使用错误及举例说明:**

*   **指定不支持的优化级别**:  用户可能会在构建配置中指定一个无效的优化级别字符串（例如 `'4'`）。程序可能会抛出异常或者使用默认的优化级别，具体取决于如何处理字典查找失败的情况。
*   **为不支持的语言指定特定的警告标志**:  用户可能会尝试为 C 代码启用只有 C++ 才有的警告标志。编译器通常会忽略这些无效的标志，但可能会产生警告信息。
*   **混淆大小写或拼写错误的指令集名称**:  用户可能错误地输入指令集名称，例如将 `'sse41'` 写成 `'sse4.1'`。`get_instruction_set_args` 函数会返回 `None`，调用者需要处理这种情况。
*   **在不适用的平台上使用特定的编译器选项**: 例如，尝试在 Windows 上使用 `-fPIC`。虽然该代码会返回空列表，但用户可能不理解为什么他们的设置没有生效。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置 Frida 构建**:  用户通常会使用 Meson 构建系统来配置和编译 Frida。他们可能会修改 `meson_options.txt` 文件或在命令行中使用 `-D` 参数来设置编译选项，例如指定编译器类型 (`-Ddefault_library=shared`) 或启用 LTO (`-Db_lto=true`)。
2. **Meson 执行**: 当用户运行 `meson build` 或 `ninja` 命令时，Meson 会解析构建配置，并根据目标平台和编译器类型选择相应的编译器后端。
3. **选择 GNU 类编译器**: 如果用户使用的编译器是 GCC、Clang 或者其他类 GNU 的编译器，Meson 会加载对应的编译器模块。
4. **Frida Swift 集成**:  Frida 包含对 Swift 代码的支持。当构建过程中涉及到 Swift 代码时，Frida Swift 子项目会被激活。
5. **编译器 Mixin 应用**:  在处理 Swift 代码的编译过程中，Frida Swift 的构建系统可能会需要配置底层的 C/C++ 编译器（因为 Swift 通常与 C/C++ 代码进行互操作）。这时，会使用到 `frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/mixins/gnu.py` 中定义的 mixin 类来设置编译器的选项和参数。
6. **调用 Mixin 方法**:  例如，如果启用了 LTO，Meson 会调用 `GnuCompiler` 或其父类 `GnuLikeCompiler` 的 `get_lto_compile_args` 方法来获取 LTO 相关的编译器参数。
7. **调试线索**:  如果用户在编译过程中遇到与编译器选项相关的问题（例如，链接错误，性能问题），他们可能会查看 Meson 的构建日志，其中会包含实际使用的编译器命令。通过分析这些命令，可以追溯到哪些 mixin 类和方法被调用，从而定位到 `gnu.py` 这个文件，并检查其中定义的编译器选项是否正确。

总而言之，`gnu.py` 文件在 Frida 的构建系统中扮演着重要的角色，它为类 GNU 编译器提供了一组通用的配置和功能，使得 Frida 能够灵活地支持不同的编译器，并根据用户的配置生成具有特定属性的可执行文件和库。理解这个文件的功能对于调试 Frida 的构建过程以及理解 Frida 如何与底层的编译工具交互至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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