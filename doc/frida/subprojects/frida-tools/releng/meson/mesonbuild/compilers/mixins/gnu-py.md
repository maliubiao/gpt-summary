Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding - What is this file?**

The first line `这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件` gives us the crucial context. This is a source code file for the Frida dynamic instrumentation tool. It's located within the Meson build system's compiler mixins, specifically for GNU-like compilers. This immediately suggests that the file deals with how Frida's build process interacts with compilers like GCC and Clang.

**2. High-Level Structure and Imports:**

Skimming the imports (`abc`, `functools`, `os`, `multiprocessing`, `pathlib`, `re`, `subprocess`, `typing`, etc.) reveals the file's purpose. It's using standard Python libraries for abstract base classes, caching, operating system interactions, concurrency, path manipulation, regular expressions, running external commands, type hinting, and interacting with the Meson build system (`mesonlib`, `mlog`).

**3. Key Data Structures (Dictionaries):**

The code defines several dictionaries like `clike_debug_args`, `gnu_optimization_args`, `gnulike_instruction_set_args`, `gnu_symbol_visibility_args`, `gnu_color_args`, and various `gnu_*_warning_args`. These dictionaries map high-level concepts (like debug levels, optimization levels, instruction sets, symbol visibility, compiler color output, and various warnings) to lists of command-line arguments used by GNU-like compilers. This is a strong indicator that the file is about generating compiler flags.

**4. Core Classes - `GnuLikeCompiler` and `GnuCompiler`:**

The presence of the abstract base class `GnuLikeCompiler` and its concrete implementation `GnuCompiler` is significant. This signals an object-oriented design. `GnuLikeCompiler` likely defines a common interface for interacting with compilers that follow the GNU command-line conventions, while `GnuCompiler` specifically handles the GCC family of compilers.

**5. Method Analysis (Focusing on Key Methods):**

Now, let's look at some of the more important methods within these classes:

* **`get_pic_args`, `get_pie_args`:** These methods likely control the generation of Position Independent Code (PIC) and Position Independent Executable (PIE) flags, which are important for shared libraries and security.

* **`get_optimization_args`, `get_debug_args`:** These directly map to the dictionaries we saw earlier, responsible for generating optimization and debugging flags.

* **`get_instruction_set_args`:**  This relates to compiler flags for enabling specific CPU instruction sets (like SSE, AVX).

* **`gnu_symbol_visibility_args`:** This controls the visibility of symbols in shared libraries, impacting linking and dynamic loading.

* **`get_warn_args`, `supported_warn_args`:** These are crucial for handling compiler warnings, allowing the build system to control the level of strictness.

* **`get_lto_compile_args`:**  Deals with Link Time Optimization (LTO), a technique to optimize across compilation units.

* **`sanitizer_compile_args`:** This method enables compiler-based sanitizers (like AddressSanitizer, UndefinedBehaviorSanitizer) for finding memory errors and undefined behavior.

* **`get_coverage_args`:**  Handles flags for generating code coverage information.

* **`use_linker_args`:**  Allows specifying which linker (like gold, lld) should be used.

**6. Connections to Reverse Engineering, Binary, Linux/Android:**

As we analyze these methods, we can start to connect them to the requested concepts:

* **Reverse Engineering:** Understanding how binaries are built (optimization levels, symbol visibility, debugging information) is essential for reverse engineering. For example, stripped binaries (built without debug symbols) are harder to reverse. Knowing about PIC/PIE helps understand how shared libraries are loaded.

* **Binary/Low-Level:**  The instruction set arguments, optimization flags, and LTO directly affect the generated machine code. Sanitizers operate at a low level to detect memory errors.

* **Linux/Android:**  PIC/PIE are crucial for shared libraries in Linux and Android. The handling of include paths and linker arguments is specific to these platforms. The mention of `/lib` and `/usr/lib` in `_split_fetch_real_dirs` directly points to Linux filesystem conventions.

**7. Logic and Assumptions:**

* **Assumptions:** The code assumes the presence of GNU-like compilers (GCC, Clang). It assumes a standard command-line interface for these compilers.
* **Logic:** The code uses dictionaries and conditional logic (based on compiler version) to map high-level build settings to specific compiler flags. It uses external commands to query the compiler's default include paths and search directories.

**8. User Errors and Debugging:**

* **User Errors:** Specifying an unsupported linker in `use_linker_args` is a potential user error. Incorrectly configuring warning levels could also be considered a user error.
* **Debugging:** The code itself is part of the build system, so if there's an issue with how compiler flags are being generated, developers might need to examine this code. The `mlog.warning` message in `gnulike_default_include_dirs` shows a basic debugging mechanism.

**9. Tracing User Actions:**

To reach this code, a user would be interacting with Frida's build system (likely using Meson). They might be setting build options related to:

* Debugging (e.g., `-Dbuildtype=debug`)
* Optimization (e.g., `-Doptimization=2`)
* Link Time Optimization (e.g., `-Db_lto=true`)
* Code coverage (e.g., `-Db_coverage=true`)
* Sanitizers (e.g., `-Db_sanitize=address`)
* Selecting a specific linker (through Meson options).

Meson would then process these options and call the relevant methods in this `gnu.py` file to generate the appropriate compiler and linker flags.

**Self-Correction/Refinement During Analysis:**

* Initially, I might just see a lot of dictionaries and assume it's simply about generating flags. But by examining the *names* of the keys and values in the dictionaries and the method names, the connection to specific compiler features (PIC, PIE, LTO, sanitizers) becomes clear.
*  Seeing the `_split_fetch_real_dirs` method and realizing the complexities of resolving compiler search paths (especially with the `/lib` vs. `/usr/lib` symlink issue) adds a layer of depth to the understanding. It's not just about blindly adding flags; it involves understanding the compiler's environment.
* Recognizing the abstract base class and the concrete implementation is crucial for understanding the code's structure and how it handles different but related compilers.

By following these steps, we can systematically analyze the code and arrive at a comprehensive understanding of its functionality and its relevance to the concepts mentioned in the prompt.
这个Python源代码文件 `gnu.py` 是 Frida 动态 Instrumentation 工具构建系统中，用于处理 GNU 风格编译器（例如 GCC 和 Clang）的 Mixin 类。Mixin 是一种代码复用技术，允许将特定的功能添加到多个不相关的类中。

**主要功能:**

1. **提供 GNU 风格编译器的通用接口:** 该文件定义了 `GnuLikeCompiler` 抽象基类，以及其具体实现 `GnuCompiler` 类。这些类封装了与 GNU 风格编译器交互的常见方法，例如：
    * 获取编译、链接所需的命令行参数（例如优化级别、调试信息、预编译头文件、LTO、PGO、代码覆盖率等）。
    * 处理不同的警告级别和特定警告选项。
    * 设置符号可见性。
    * 支持 OpenMP 并行编程。
    * 处理模块定义文件。
    * 获取编译器的默认包含目录。
    * 支持不同的链接器（gold, bfd, lld, mold）。
    * 支持代码清理器 (Sanitizer)。

2. **管理编译器选项和参数:** 文件中定义了多个字典，用于存储不同编译器选项及其对应的命令行参数。例如：
    * `clike_debug_args`:  控制是否生成调试信息的参数 (`-g`)。
    * `gnu_optimization_args`:  不同优化级别的参数 (`-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-Og`)。
    * `gnulike_instruction_set_args`:  指定 CPU 指令集扩展的参数 (`-mmx`, `-msse`, `-mavx` 等)。
    * `gnu_symbol_visibility_args`:  控制符号可见性的参数 (`-fvisibility=default`, `-fvisibility=hidden` 等)。
    * `gnu_color_args`: 控制编译器输出颜色信息的参数。
    * `gnu_common_warning_args`, `gnu_c_warning_args`, `gnu_cpp_warning_args`, `gnu_objc_warning_args`:  各种详细的警告选项，根据 GCC 版本进行组织。

3. **处理特定于 GCC 的功能:** `GnuCompiler` 类继承自 `GnuLikeCompiler`，并实现了特定于 GCC 的行为，例如：
    * 获取内置宏定义。
    * 处理 `-Wpedantic` 选项在不同 GCC 版本中的差异。
    *  处理 LTO 相关的线程数参数。
    *  处理 `-fprofile-correction` 参数用于 PGO。

**与逆向方法的关系及举例说明:**

该文件直接影响着 Frida 工具本身以及被 Frida 注入的进程的编译方式，因此与逆向分析息息相关：

* **调试信息 (`-g`):**  `clike_debug_args` 字典控制是否在编译时生成调试符号。逆向工程师经常依赖调试符号（例如 DWARF 信息）来理解程序的执行流程、变量值等。如果 Frida 或目标进程编译时没有添加 `-g`，逆向分析的难度会大大增加，无法使用 GDB 或 LLDB 等调试器进行源码级别的调试。
    * **例子:** 如果 Frida 构建时使用了 `-Db_ndebug=false` (默认值)，则 `get_debug_args(True)` 会返回 `['-g']`，Frida 相关的二进制文件会包含调试信息，方便开发和调试 Frida 本身。

* **优化级别 (`-O0`, `-O1`, `-O2`, `-O3`):** `gnu_optimization_args` 字典定义了不同优化级别对应的参数。较高的优化级别会导致编译器进行代码转换和优化，使得逆向分析更加困难。例如，编译器可能会内联函数、重排代码、删除未使用的变量等，使得反编译出的代码与源代码差异较大。
    * **例子:**  如果 Frida 构建时使用了默认的 release 构建（`-Db_ndebug=true`），可能会采用 `-O2` 或 `-O3` 优化，使得 Frida 的核心代码更难以被逆向分析，从而提高其安全性。

* **符号可见性 (`-fvisibility=hidden` 等):** `gnu_symbol_visibility_args` 字典控制着动态库中符号的可见性。将符号设置为隐藏 (hidden) 可以防止这些符号在库外部被直接访问，这在一定程度上可以提高安全性，但也增加了逆向分析的难度，因为逆向工程师可能无法直接调用或 hook 这些隐藏的函数。
    * **例子:** Frida 自身的一些内部函数可能会使用 `-fvisibility=hidden` 进行编译，防止被其他模块意外调用或 hook。

* **链接时优化 (LTO, `-flto`):** `get_lto_compile_args` 方法处理 LTO 相关的编译参数。LTO 是一种跨越多个编译单元的优化技术，它可以使得最终生成的可执行文件或动态库更小、更快，但也使得逆向分析更加困难，因为优化器可能会跨文件进行代码转换。
    * **例子:** 如果 Frida 构建时启用了 LTO (`-Db_lto=true`)，链接器会进行更深入的优化，这会使得 Frida 的最终二进制文件更难被静态分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **CPU 指令集扩展 (`-msse`, `-mavx` 等):** `gnulike_instruction_set_args` 字典允许指定使用特定的 CPU 指令集扩展。这些指令集直接操作硬件，理解它们对于逆向分析底层代码和性能优化至关重要。在 Android 平台上，不同的设备可能支持不同的指令集，Frida 可以利用这些指令集来提高效率。
    * **例子:**  如果 Frida 运行在支持 AVX 指令集的 Android 设备上，并且构建时指定了 `-mavx`，Frida 的某些计算密集型操作可能会利用 AVX 指令来加速。

* **位置无关代码 (PIC, `-fPIC`) 和位置无关可执行文件 (PIE, `-fPIE`):**  `get_pic_args` 和 `get_pie_args` 方法分别生成 PIC 和 PIE 相关的编译参数。PIC 对于构建共享库至关重要，因为它允许库在内存中的任意位置加载。PIE 是一种安全特性，可以防止某些类型的攻击，例如地址空间布局随机化 (ASLR) 的绕过。在 Linux 和 Android 系统中，共享库和可执行文件通常都需要以 PIC 或 PIE 的方式编译。
    * **例子:** Frida 作为一个动态库，必须使用 `-fPIC` 编译，才能被目标进程加载。Android 系统通常也要求可执行文件使用 `-fPIE` 编译。

* **链接器脚本 (`-Wl,` 前缀):**  `LINKER_PREFIX` 常量定义了传递给链接器的参数前缀。链接器脚本控制着最终二进制文件的内存布局。理解链接器脚本对于理解程序的加载过程和内存结构非常重要，尤其是在分析复杂的系统软件或内核模块时。
    * **例子:** Frida 可能会通过链接器参数指定其依赖的库，或者调整内存段的属性。

* **默认包含目录 (`gnulike_default_include_dirs`):**  该函数用于获取编译器的默认包含目录。这涉及到对编译器输出的解析，需要了解不同编译器的输出格式。在 Linux 和 Android 系统中，系统头文件通常位于 `/usr/include`, `/usr/local/include` 等目录。理解这些目录结构对于分析依赖系统库的程序至关重要。
    * **例子:** Frida 在编译时需要包含 Android NDK 提供的头文件，例如 `<jni.h>`，这些头文件位于 NDK 的特定目录下。

* **代码覆盖率 (`--coverage`):** `get_coverage_args` 方法生成用于代码覆盖率分析的参数。代码覆盖率工具可以帮助逆向工程师了解程序执行了哪些代码路径，这对于理解程序的行为和发现潜在的漏洞非常有帮助。
    * **例子:**  Frida 的开发者可以使用代码覆盖率工具来测试 Frida 的功能，确保其覆盖了各种可能的执行路径。

* **Sanitizer (`-fsanitize=`):** `sanitizer_compile_args` 方法生成用于启用各种代码清理器的参数，例如 AddressSanitizer (ASan) 用于检测内存错误，UndefinedBehaviorSanitizer (UBSan) 用于检测未定义行为。这些工具在开发和调试阶段非常有用，可以帮助发现潜在的错误，但也可能影响程序的性能。在逆向分析中，了解目标程序是否使用了 Sanitizer 可以帮助理解其内部机制和潜在的漏洞。
    * **例子:**  Frida 的开发者可以使用 ASan 或 UBSan 来构建 Frida，以检测 Frida 自身是否存在内存错误或未定义行为。

**逻辑推理及假设输入与输出:**

假设用户在构建 Frida 时设置了以下 Meson 选项：

* `-Dbuildtype=debug`
* `-Doptimization=1`
* `-Db_lto=false`
* `-Dinstruction_set=sse41`

当 Meson 调用 `gnu.py` 中的相关方法时，可以推断出以下输入和输出：

* **输入到 `get_debug_args`:** `is_debug=True`
* **`get_debug_args` 的输出:** `['-g']`

* **输入到 `get_optimization_args`:** `optimization_level='1'`
* **`get_optimization_args` 的输出:** `['-O1']`

* **输入到 `get_lto_compile_args`:**  (没有明确的输入参数，取决于 Meson 的配置)
* **`get_lto_compile_args` 的输出:** `[]` (因为 `b_lto` 为 `false`)

* **输入到 `get_instruction_set_args`:** `instruction_set='sse41'`
* **`get_instruction_set_args` 的输出:** `['-msse4.1']`

**涉及用户或编程常见的使用错误及举例说明:**

* **指定不支持的链接器:** 用户可能会在 Meson 配置中指定一个 GNU 风格编译器不支持的链接器。
    * **例子:**  如果用户尝试使用 `-Dld=mold` 但当前的 GCC 版本过低，不支持 mold 链接器，`GnuCompiler.use_linker_args` 方法会抛出 `mesonlib.MesonException`，提示用户不支持该链接器。

* **错误地配置警告级别:** 用户可能设置了过高或过低的警告级别，导致编译过程中出现大量无意义的警告，或者忽略了重要的潜在问题。
    * **例子:** 用户可能设置 `-Dwarning_level=everything`，导致编译器输出大量冗余的警告信息，影响开发效率。或者，用户可能设置 `-Dwarning_level=0`，忽略了本应注意的警告，导致潜在的 bug 被忽略。

* **在不支持的语言中使用特定选项:**  某些编译器选项可能只适用于特定的编程语言。
    * **例子:**  用户可能在 C 代码中使用了 C++ 特有的警告选项，例如 `-Weffc++`，这可能会被编译器忽略或者产生错误。`GnuCompiler.has_arguments` 方法在检查编译器是否支持某个参数时，会考虑到语言的差异。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置构建选项:**  用户在 Frida 项目的根目录下运行 Meson 命令，并指定各种构建选项，例如：
   ```bash
   meson setup build -Dbuildtype=debug -Doptimization=2
   ```

2. **Meson 解析构建选项:** Meson 工具会解析用户提供的构建选项，并将这些选项存储在内部的数据结构中。

3. **Meson 选择合适的编译器:** Meson 会根据用户的环境和配置，选择合适的 C/C++ 编译器 (例如 GCC 或 Clang)。

4. **Meson 初始化编译器对象:**  Meson 会创建与所选编译器对应的编译器对象，例如 `GnuCompiler` 或 `ClangCCompiler`。对于 GNU 风格的编译器，会实例化 `GnuCompiler` 对象。

5. **Meson 调用 Mixin 中的方法:** 在生成实际的编译命令时，Meson 会调用 `gnu.py` 中 `GnuCompiler` 或 `GnuLikeCompiler` 类的方法，根据之前解析的构建选项，生成相应的编译器参数。
   * 例如，如果 `-Dbuildtype=debug` 被设置，Meson 可能会调用 `GnuCompiler.get_debug_args(True)` 来获取调试相关的编译参数。
   * 如果 `-Doptimization=2` 被设置，Meson 可能会调用 `GnuCompiler.get_optimization_args('2')` 来获取优化相关的编译参数。

6. **生成编译命令:**  Meson 将从 Mixin 中获取的参数与其他必要的参数（例如源文件、包含目录、库文件）组合起来，生成最终的编译器命令。

7. **执行编译命令:** Meson 执行生成的编译器命令，完成代码的编译过程。

**调试线索:**

当遇到与编译相关的错误时，可以按照以下步骤进行调试：

1. **查看 Meson 的配置输出:**  Meson 在 `setup` 阶段会输出当前的构建配置，包括选择的编译器和各种选项的值。检查这些输出可以确认 Meson 是否正确解析了用户的构建选项。

2. **查看详细的编译命令:**  在 Meson 构建过程中，可以使用 `-v` 或 `--verbose` 选项来查看详细的编译命令。这些命令会显示实际传递给编译器的参数，可以帮助定位问题。

3. **检查 `gnu.py` 中的逻辑:**  如果怀疑编译器参数生成有问题，可以查看 `gnu.py` 中相关方法的实现，例如 `get_debug_args`、`get_optimization_args` 等，确认其逻辑是否符合预期，以及是否正确处理了特定的构建选项。

4. **使用断点或日志输出:**  可以在 `gnu.py` 中添加断点或日志输出，来跟踪代码的执行流程，查看特定变量的值，帮助理解参数是如何生成的。

通过以上分析，可以看出 `gnu.py` 文件在 Frida 的构建系统中扮演着重要的角色，它负责封装 GNU 风格编译器的特性，并根据用户的构建配置生成相应的编译和链接参数，这直接影响着最终生成的可执行文件和动态库的特性，也与逆向分析的方法和难度息息相关。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/mixins/gnu.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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