Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for a functional breakdown of the `clike.py` file within the Frida project, specifically looking for connections to reverse engineering, low-level/kernel concepts, logic, potential user errors, and how a user might end up interacting with this code. It's crucial to recognize this isn't about reverse-engineering *this specific file*, but understanding how its functionality *relates to* reverse engineering.

2. **Initial Skim and High-Level Purpose:**  The docstring at the beginning is a great starting point. It clearly states the file's purpose: providing mixin classes for C and C++ compilers within the Meson build system. The "avoid diamond inheritance" comment points to a design pattern focus.

3. **Identify Key Classes and Their Roles:**  The file defines two primary classes: `CLikeCompilerArgs` and `CLikeCompiler`.

    * **`CLikeCompilerArgs`:**  The name suggests it deals with arguments passed to the compiler. A quick scan of its methods (`to_native`, `_cached_realpath`, `__repr__`) confirms this. `to_native` looks important as it seems to convert arguments to a form the actual compiler understands. The comments about `--start-group`/`--end-group` and removing system includes are hints about linking and compilation optimizations.

    * **`CLikeCompiler`:**  This class seems to be the core of the functionality. It inherits from `Compiler` (though the typing is a bit tricky with the `if TYPE_CHECKING` block). The methods here are more numerous and hint at various compiler functionalities:  getting arguments, setting flags, performing checks (header, symbol, sanity), computing sizes/alignments, getting defines, etc.

4. **Connect to Reverse Engineering (Keyword Spotting and Reasoning):**  Now, the targeted analysis begins. Look for terms or functionalities that overlap with reverse engineering concepts:

    * **Linking (`-l`, `-L`, `--start-group`, `--end-group`, `DynamicLinkerMixin`):** Linking is essential in reverse engineering, especially when dealing with shared libraries (`.so`, `.dylib`, `.dll`). Understanding how these libraries are linked and their dependencies is vital. The code dealing with `--start-group` and `--end-group` is specifically about handling circular dependencies, which can be a real issue when reverse-engineering complex applications.
    * **Includes (`-I`, `-isystem`):**  Knowing the include paths is important for understanding the code's structure and dependencies. Reverse engineers often need to examine header files to understand data structures and function signatures.
    * **Preprocessor (`-E`, `-P`, `get_define`):** The preprocessor's role in macro expansion and conditional compilation is something reverse engineers need to be aware of to fully understand the code. `get_define` directly retrieves macro definitions.
    * **Sizes and Alignments (`sizeof`, `alignment`):** When analyzing binary data, understanding the size and alignment of data structures is crucial for interpreting the raw bytes.
    * **Sanity Checks (`sanity_check`):** While not directly reverse engineering, the concept of running a simple test program to ensure the toolchain is working correctly is analogous to some debugging steps a reverse engineer might take.
    * **Cross-compilation (`is_cross`):**  Reverse engineering often involves analyzing binaries compiled for different architectures (e.g., ARM on Android). The code's handling of cross-compilation is relevant.
    * **Kernel/OS interaction (implicit):** While not explicitly stating kernel calls, the concepts of linking shared libraries, finding headers, and understanding data layout are all fundamental to how programs interact with the underlying OS and kernel.

5. **Illustrate with Examples:** Once connections are identified, provide concrete examples:

    * **Linking:** Explain how `--start-group` helps resolve circular dependencies between static libraries, a common scenario when reverse engineering a program with many internal libraries.
    * **Includes:** Show how knowing the include paths can help find the definition of a function used in the target binary.
    * **`sizeof`:**  Demonstrate how the `sizeof` functionality helps determine the size of a struct, which is vital for analyzing memory layouts in reverse engineering.

6. **Identify Low-Level/Kernel/Android Aspects:**  Focus on parts of the code that directly or indirectly relate to these areas:

    * **Binary Format (`.so`, `.a`, ELF headers):** The code explicitly deals with different binary formats and checks ELF headers.
    * **Library Paths (`get_library_dirs`):**  This function interacts with the system's library search paths, crucial for dynamic linking in Linux and Android.
    * **Dynamic Linking (`GnuLikeDynamicLinkerMixin`):** The presence of this mixin points to the handling of dynamic linking, a core OS concept.
    * **Android (Implicit):** While no explicit Android code is present *in this file*, the fact that this is part of Frida, a tool heavily used for Android reverse engineering, makes many of the functionalities (linking, include paths, etc.) relevant to Android.

7. **Look for Logical Reasoning (Hypothetical Inputs and Outputs):**  Consider the functions and how they transform input:

    * **`to_native`:** If the input is `['-I/usr/include', '-L/usr/lib', '-lmylib']`, the output would be the same list, potentially with `--start-group` and `--end-group` added depending on the libraries.
    * **`get_define`:** If the input is a macro name `DEBUG` and the code has `#define DEBUG 1`, the output would be `"1"`. If `DEBUG` is not defined, the output would be `None`.
    * **`sizeof`:** If the input is `int`, the output would be `4` (on a 32-bit or 64-bit system).

8. **Identify Potential User Errors:** Think about how a developer using this as part of Meson might make mistakes:

    * **Incorrect Include Paths:** Specifying a wrong include path could lead to compilation errors.
    * **Incorrect Library Names:**  Typing the library name incorrectly would cause linking failures.
    * **Conflicting Flags:** Providing conflicting compiler or linker flags could lead to unexpected behavior or errors.

9. **Trace User Interaction (Debugging Perspective):** Imagine how a user might end up triggering this code:

    * A developer builds a Frida gadget or extension using Meson.
    * Meson invokes the compiler (via the `CLikeCompiler` class).
    * Meson needs to determine compiler capabilities (e.g., `has_header`).
    * Meson needs to compile source code, passing arguments handled by `CLikeCompilerArgs`.

10. **Summarize Functionality:** Finally, condense the detailed analysis into a concise summary of the file's purpose and main responsibilities.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file seems to be about compiling C/C++ code."  **Refinement:**  It's more specifically about *managing the compiler interaction* within the Meson build system, providing a consistent interface across different compilers.
* **Initial thought:** "The reverse engineering connection is weak." **Refinement:** By focusing on the *underlying concepts* (linking, includes, data layout) that are essential for both compilation and reverse engineering, the connection becomes clear.
* **Initial thought:** "The `if TYPE_CHECKING` block is confusing." **Refinement:** Understand that this is a Python typing mechanism to provide type hints during development without affecting runtime behavior. It's a common pattern in larger Python projects.

By following this systematic approach, combining code examination with an understanding of the broader context of compilation and reverse engineering, one can effectively analyze and explain the functionality of this code.
好的，我们来分析一下 `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/mixins/clike.py` 这个文件的功能。

**功能归纳：**

这个 Python 文件定义了两个 Mixin 类：`CLikeCompilerArgs` 和 `CLikeCompiler`。这些 Mixin 类旨在被 C 和 C++ 编译器类继承，以共享一些通用的功能和逻辑，避免代码重复和解决复杂的继承问题（菱形继承）。

**`CLikeCompilerArgs` 的功能：**

* **处理编译器参数：**  这个类继承自 `arglist.CompilerArgs`，主要负责处理和格式化传递给 C/C++ 编译器的命令行参数。
* **添加和移除特定前缀的参数：**  定义了 `prepend_prefixes` 和 `dedup2_prefixes`，用于管理带有特定前缀的参数，如 `-I`（包含路径）和 `-L`（库路径）。
* **处理重复的库链接参数：**  定义了 `dedup1_prefixes` 和 `dedup1_suffixes`，用于识别和处理重复的库链接参数（例如 `-lxxx.so`），以及一些常见的链接器参数（如 `-c`, `-S` 等）。
* **处理静态库循环依赖：**  在 `to_native` 方法中，针对 GNU 风格的链接器（如 `ld.bfd`, `ld.gold`），会检测库文件（`.so`, `.a`）是否存在，并根据需要添加 `-Wl,--start-group` 和 `-Wl,--end-group` 参数来解决静态库之间的循环依赖问题。
* **移除默认的系统包含路径：**  `to_native` 方法会获取编译器的默认包含路径，并移除通过 `-isystem` 添加的、与默认路径相同的包含路径，以避免重复和潜在的构建问题。
* **转换为原生命令行格式：**  `to_native` 方法最终调用编译器的 `unix_args_to_native` 方法，将处理过的参数转换为特定平台和编译器的原生命令行格式。
* **缓存文件真实路径：** 使用 `@functools.lru_cache` 装饰器缓存 `_cached_realpath` 方法的结果，避免重复计算文件真实路径。

**`CLikeCompiler` 的功能：**

* **提供 C/C++ 编译器的通用功能：**  这个类继承自 `Compiler`，为 C 和 C++ 编译器提供了许多共享的方法，用于执行常见的编译任务。
* **管理编译后缀：**  初始化时将 `.h` 添加到 `can_compile_suffixes`，表示可以处理头文件。
* **创建 `CLikeCompilerArgs` 实例：**  `compiler_args` 方法用于创建与当前编译器关联的 `CLikeCompilerArgs` 实例。
* **判断是否需要静态链接器：**  `needs_static_linker` 返回 `True`，表明在编译静态库时需要静态链接器。
* **获取常用编译参数：**  提供了获取各种常用编译参数的方法，例如：
    * `get_always_args`: 始终启用的参数（如大文件支持）。
    * `get_no_stdinc_args`: 禁用标准包含路径的参数。
    * `get_no_stdlib_link_args`: 禁用标准库链接的参数。
    * `get_warn_args`: 获取不同警告级别的参数。
    * `get_depfile_suffix`: 获取依赖文件后缀。
    * `get_preprocess_only_args`: 预处理的参数。
    * `get_compile_only_args`: 编译的参数。
    * `get_no_optimization_args`: 禁用优化的参数。
    * `get_output_args`: 指定输出文件名的参数。
    * `get_werror_args`: 将警告视为错误的参数。
    * `get_include_args`: 添加包含路径的参数。
* **获取编译器相关的目录：**  `get_compiler_dirs` 用于获取编译器相关的目录（例如库目录或程序目录）。
* **缓存库和程序目录：**  使用 `@functools.lru_cache` 装饰器缓存 `_get_library_dirs` 和 `_get_program_dirs` 的结果，提高性能。`get_library_dirs` 还会根据 ELF 类别（32 位或 64 位）过滤库目录。
* **获取 PIC 参数：**  `get_pic_args` 用于获取生成位置无关代码的参数（`-fPIC`）。
* **处理预编译头文件（PCH）：**  `get_pch_use_args` 和 `get_pch_name` 用于处理预编译头文件。
* **获取默认包含路径：**  `get_default_include_dirs` 返回编译器的默认包含路径。
* **生成动态链接导出符号的参数：**  `gen_export_dynamic_link_args` 调用链接器的 `export_dynamic_args` 方法。
* **生成导入库的参数：**  `gen_import_library_args` 调用链接器的 `import_library_args` 方法。
* **执行编译器 Sanity Check：**  `_sanity_check_impl` 和 `sanity_check` 方法用于执行编译器的基本功能测试，确保编译器可以正常编译和链接简单的程序。
* **检查头文件是否存在：**  `check_header` 和 `has_header` 方法用于检查指定的头文件是否存在。`has_header` 还会利用 `__has_include` 特性进行更可靠的检查。
* **检查头文件是否包含特定符号：**  `has_header_symbol` 方法用于检查头文件是否定义了特定的符号。
* **构建完整的编译器调用参数：**  `_get_basic_compiler_args` 和 `build_wrapper_args` 方法用于构建传递给编译器的完整参数列表，包括用户指定的参数、依赖项的参数以及基本的编译/链接参数。
* **编译并获取表达式的值（用于交叉编译）：**  `_compile_int` 用于在交叉编译环境下测试编译特定表达式的代码是否成功。`cross_compute_int` 利用二分查找在交叉编译环境下计算表达式的整数值。
* **编译并运行代码获取表达式的值：**  `compute_int` 方法编译并运行一段代码，通过标准输出获取表达式的整数值。
* **获取类型的大小：**  `cross_sizeof` 和 `sizeof` 方法用于获取指定类型的大小（字节数）。在交叉编译环境下，使用编译测试和二分查找来确定大小。
* **获取类型的对齐方式：**  `cross_alignment` 和 `alignment` 方法用于获取指定类型的内存对齐方式。在交叉编译环境下，通过编译包含该类型的结构体并计算偏移量来确定对齐方式。
* **获取宏定义的值：**  `get_define` 方法通过预处理代码来获取指定宏定义的值。
* **获取函数返回值：**  `get_return_value` 方法编译并运行代码，获取指定函数的返回值（支持字符串和整数类型）。
* **尝试查找没有原型声明的函数：** `_no_prototype_templ`  提供了一个模板，用于尝试在没有原型声明的情况下查找函数。

**与逆向方法的关联及举例说明：**

* **链接参数处理 (`CLikeCompilerArgs`)：** 在逆向工程中，了解目标程序链接了哪些库是非常重要的。`CLikeCompilerArgs` 中处理 `-l` 和 `-L` 参数的逻辑，以及处理静态库循环依赖的机制，可以帮助逆向工程师理解程序的依赖关系。例如，如果一个 Android Native Library (.so) 依赖于另一个静态库，`CLikeCompilerArgs` 可能会添加 `-Wl,--start-group` 和 `-Wl,--end-group`，这提示逆向工程师需要关注这些静态库。
* **包含路径处理 (`CLikeCompilerArgs`)：**  编译时使用的包含路径决定了编译器如何找到头文件。在逆向分析时，如果需要理解某个函数或数据结构的定义，就需要知道其头文件所在的路径。`CLikeCompilerArgs` 中对 `-I` 和 `-isystem` 的处理，反映了构建过程中的头文件查找机制，这可以为逆向工程师提供线索。
* **预处理 (`CLikeCompiler`, `get_define`)：**  C/C++ 代码中经常使用宏定义进行条件编译或定义常量。逆向工程师需要理解这些宏定义才能完整理解代码的逻辑。`CLikeCompiler` 的 `get_define` 方法可以获取宏定义的值，这与逆向分析中静态分析工具解析宏定义的功能类似。例如，如果想知道某个编译选项是否启用，可以通过 `get_define` 获取对应的宏定义值。
* **类型大小和对齐 (`CLikeCompiler`, `sizeof`, `alignment`)：** 在逆向工程中，理解数据结构的大小和内存布局至关重要。`CLikeCompiler` 提供的 `sizeof` 和 `alignment` 方法可以获取类型的大小和对齐方式，这与逆向分析中分析结构体内存布局的需求直接相关。例如，在分析一个二进制文件格式时，需要知道各个字段的大小和偏移量，`sizeof` 和 `alignment` 的结果可以提供关键信息。
* **交叉编译 (`CLikeCompiler`, 带有 `cross_` 前缀的方法)：** Frida 经常用于动态插桩运行在不同架构上的程序，例如 Android (ARM)。`CLikeCompiler` 中处理交叉编译的逻辑，以及 `cross_sizeof` 和 `cross_alignment` 等方法，体现了 Frida 构建过程需要处理不同目标架构的需求。在逆向 Android Native Library 时，了解目标架构的类型大小和对齐方式是必不可少的。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明：**

* **二进制文件格式 (`CLikeCompilerArgs`)：**  `CLikeCompilerArgs` 中对 `.so` 和 `.a` 文件的处理，以及对 ELF 头的简单检查，涉及到 Linux 和 Android 系统中动态链接库和静态库的二进制文件格式知识。
* **动态链接 (`CLikeCompilerArgs`, `CLikeCompiler`)：**  `CLikeCompilerArgs` 中处理 `-l` 和 `-L` 参数，以及添加 `-Wl,--start-group` 和 `-Wl,--end-group` 的逻辑，与 Linux 和 Android 系统中的动态链接机制密切相关。`CLikeCompiler` 中调用链接器的方法也体现了对动态链接过程的理解。
* **系统调用和库 (`CLikeCompiler`, Sanity Check)：** `CLikeCompiler` 的 `sanity_check` 方法会编译并运行一个简单的程序，这涉及到操作系统加载和执行二进制文件的过程，以及程序可能调用的基本系统调用或 C 标准库函数。
* **Android NDK 编译环境 (隐式)：** 虽然这个文件本身没有直接涉及 Android 特定的代码，但作为 Frida 项目的一部分，它所处理的编译过程很可能涉及到 Android NDK（Native Development Kit），即用于编译 Android 原生代码的工具链。

**逻辑推理的假设输入与输出举例：**

* **`CLikeCompilerArgs.to_native`:**
    * **假设输入:** `['-I/usr/include', '-L/usr/lib', '-lmylib1', '-lmylib2.so', '/path/to/libmylib3.a']`
    * **可能输出:** `['-I/usr/include', '-L/usr/lib', '-Wl,--start-group', '-lmylib1', '-lmylib2.so', '/path/to/libmylib3.a', '-Wl,--end-group']` (假设检测到需要分组链接)。
* **`CLikeCompiler.get_define`:**
    * **假设输入:** `dname="DEBUG"`, 代码片段包含 `#define DEBUG 1`
    * **输出:** `("1", False)` (假设未缓存)。
* **`CLikeCompiler.sizeof`:**
    * **假设输入:** `typename="int"`
    * **可能输出:** `(4, True)` (在 32 位或 64 位系统上，假设结果已缓存)。

**涉及用户或者编程常见的使用错误举例：**

* **`CLikeCompilerArgs`:**
    * 用户在构建脚本中指定了错误的库名称 (`-lmylib`)，导致链接失败。
    * 用户指定了不存在的包含路径 (`-I/non/existent/path`)，导致编译错误。
    * 用户在链接静态库时，没有正确处理循环依赖，可能需要 Meson 自动添加 `-Wl,--start-group` 和 `-Wl,--end-group`，如果 Meson 的逻辑出现问题，可能导致链接错误。
* **`CLikeCompiler`:**
    * 用户在进行交叉编译时，没有配置正确的交叉编译工具链，导致 `sanity_check` 失败。
    * 用户在使用 `check_header` 或 `has_header` 检查头文件时，头文件路径未添加到包含路径中，导致检查结果错误。
    * 用户在使用 `get_define` 获取宏定义时，宏定义不存在或在预处理过程中被取消定义，导致获取到的值为 `None` 或引发异常。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida Gadget 或 Instrumentation 代码。** 这通常涉及编写 C/C++ 代码，并使用 Meson 作为构建系统。
2. **Meson 读取 `meson.build` 文件。**  用户的 `meson.build` 文件中会指定源代码、依赖项和其他构建选项。
3. **Meson 检测到需要编译 C/C++ 代码。** 根据 `meson.build` 中的 `project()` 和 `executable()`/`shared_library()` 等声明，Meson 会确定需要使用 C 或 C++ 编译器。
4. **Meson 初始化相应的编译器对象。**  Meson 会根据检测到的编译器类型（例如 GCC, Clang, MSVC）创建对应的编译器对象，这些对象很可能会继承自 `CLikeCompiler` 或其子类。
5. **在编译或链接阶段，Meson 调用 `CLikeCompilerArgs` 来处理编译器参数。**  例如，当需要添加包含路径或链接库时，Meson 会使用 `CLikeCompilerArgs` 的方法来格式化和管理这些参数。
6. **Meson 调用 `CLikeCompiler` 的方法来执行编译任务。**  例如，当需要检查头文件是否存在时，Meson 会调用 `has_header` 方法。当需要获取宏定义的值时，Meson 会调用 `get_define` 方法。
7. **如果构建过程中出现错误（例如找不到头文件或链接失败），用户可能会查看 Meson 的构建日志。**  日志中会显示传递给编译器的具体命令行参数，这些参数正是由 `CLikeCompilerArgs` 处理过的。
8. **如果需要调试编译器行为或 Meson 的构建过程，开发者可能会深入到 Meson 的源代码中，例如 `clike.py`，来理解参数处理或编译检查的实现细节。**  查看 `to_native` 方法可以了解参数是如何被转换成原生命令行格式的。查看 `sanity_check` 方法可以了解 Meson 如何测试编译器的基本功能。

**这是第1部分，共2部分，请归纳一下它的功能：**

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件的主要功能是：

**为 Meson 构建系统中 C 和 C++ 编译器提供通用的、可重用的功能，包括处理编译器参数、执行基本的编译任务（如 sanity check、头文件检查、获取宏定义等），并处理与平台和架构相关的细节（如静态库循环依赖、交叉编译）。它通过 Mixin 类的设计模式，避免了代码重复，并为更具体的 C 和 C++ 编译器类提供了基础框架。**

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2023 The Meson development team

from __future__ import annotations


"""Mixin classes to be shared between C and C++ compilers.

Without this we'll end up with awful diamond inheritance problems. The goal
of this is to have mixin's, which are classes that are designed *not* to be
standalone, they only work through inheritance.
"""

import collections
import functools
import glob
import itertools
import os
import re
import subprocess
import copy
import typing as T
from pathlib import Path

from ... import arglist
from ... import mesonlib
from ... import mlog
from ...linkers.linkers import GnuLikeDynamicLinkerMixin, SolarisDynamicLinker, CompCertDynamicLinker
from ...mesonlib import LibType, OptionKey
from .. import compilers
from ..compilers import CompileCheckMode
from .visualstudio import VisualStudioLikeCompiler

if T.TYPE_CHECKING:
    from ...dependencies import Dependency
    from ..._typing import ImmutableListProtocol
    from ...environment import Environment
    from ...compilers.compilers import Compiler
else:
    # This is a bit clever, for mypy we pretend that these mixins descend from
    # Compiler, so we get all of the methods and attributes defined for us, but
    # for runtime we make them descend from object (which all classes normally
    # do). This gives up DRYer type checking, with no runtime impact
    Compiler = object

GROUP_FLAGS = re.compile(r'''^(?!-Wl,) .*\.so (?:\.[0-9]+)? (?:\.[0-9]+)? (?:\.[0-9]+)?$ |
                             ^(?:-Wl,)?-l |
                             \.a$''', re.X)

class CLikeCompilerArgs(arglist.CompilerArgs):
    prepend_prefixes = ('-I', '-L')
    dedup2_prefixes = ('-I', '-isystem', '-L', '-D', '-U')

    # NOTE: not thorough. A list of potential corner cases can be found in
    # https://github.com/mesonbuild/meson/pull/4593#pullrequestreview-182016038
    dedup1_prefixes = ('-l', '-Wl,-l', '-Wl,--export-dynamic')
    dedup1_suffixes = ('.lib', '.dll', '.so', '.dylib', '.a')
    dedup1_args = ('-c', '-S', '-E', '-pipe', '-pthread')

    def to_native(self, copy: bool = False) -> T.List[str]:
        # This seems to be allowed, but could never work?
        assert isinstance(self.compiler, compilers.Compiler), 'How did you get here'

        # Check if we need to add --start/end-group for circular dependencies
        # between static libraries, and for recursively searching for symbols
        # needed by static libraries that are provided by object files or
        # shared libraries.
        self.flush_pre_post()
        if copy:
            new = self.copy()
        else:
            new = self
        # This covers all ld.bfd, ld.gold, ld.gold, and xild on Linux, which
        # all act like (or are) gnu ld
        # TODO: this could probably be added to the DynamicLinker instead
        if isinstance(self.compiler.linker, (GnuLikeDynamicLinkerMixin, SolarisDynamicLinker, CompCertDynamicLinker)):
            group_start = -1
            group_end = -1
            for i, each in enumerate(new):
                if not GROUP_FLAGS.search(each):
                    continue
                group_end = i
                if group_start < 0:
                    # First occurrence of a library
                    group_start = i
            # Only add groups if there are multiple libraries.
            if group_end > group_start >= 0:
                # Last occurrence of a library
                new.insert(group_end + 1, '-Wl,--end-group')
                new.insert(group_start, '-Wl,--start-group')
        # Remove system/default include paths added with -isystem
        default_dirs = self.compiler.get_default_include_dirs()
        if default_dirs:
            real_default_dirs = [self._cached_realpath(i) for i in default_dirs]
            bad_idx_list: T.List[int] = []
            for i, each in enumerate(new):
                if not each.startswith('-isystem'):
                    continue

                # Remove the -isystem and the path if the path is a default path
                if (each == '-isystem' and
                        i < (len(new) - 1) and
                        self._cached_realpath(new[i + 1]) in real_default_dirs):
                    bad_idx_list += [i, i + 1]
                elif each.startswith('-isystem=') and self._cached_realpath(each[9:]) in real_default_dirs:
                    bad_idx_list += [i]
                elif self._cached_realpath(each[8:]) in real_default_dirs:
                    bad_idx_list += [i]
            for i in reversed(bad_idx_list):
                new.pop(i)
        return self.compiler.unix_args_to_native(new._container)

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _cached_realpath(arg: str) -> str:
        return os.path.realpath(arg)

    def __repr__(self) -> str:
        self.flush_pre_post()
        return f'CLikeCompilerArgs({self.compiler!r}, {self._container!r})'


class CLikeCompiler(Compiler):

    """Shared bits for the C and CPP Compilers."""

    if T.TYPE_CHECKING:
        warn_args: T.Dict[str, T.List[str]] = {}

    # TODO: Replace this manual cache with functools.lru_cache
    find_library_cache: T.Dict[T.Tuple[T.Tuple[str, ...], str, T.Tuple[str, ...], str, LibType], T.Optional[T.List[str]]] = {}
    find_framework_cache: T.Dict[T.Tuple[T.Tuple[str, ...], str, T.Tuple[str, ...], bool], T.Optional[T.List[str]]] = {}
    internal_libs = arglist.UNIXY_COMPILER_INTERNAL_LIBS

    def __init__(self) -> None:
        # If a child ObjC or CPP class has already set it, don't set it ourselves
        self.can_compile_suffixes.add('h')
        # Lazy initialized in get_preprocessor()
        self.preprocessor: T.Optional[Compiler] = None

    def compiler_args(self, args: T.Optional[T.Iterable[str]] = None) -> CLikeCompilerArgs:
        # This is correct, mypy just doesn't understand co-operative inheritance
        return CLikeCompilerArgs(self, args)

    def needs_static_linker(self) -> bool:
        return True # When compiling static libraries, so yes.

    def get_always_args(self) -> T.List[str]:
        '''
        Args that are always-on for all C compilers other than MSVC
        '''
        return self.get_largefile_args()

    def get_no_stdinc_args(self) -> T.List[str]:
        return ['-nostdinc']

    def get_no_stdlib_link_args(self) -> T.List[str]:
        return ['-nostdlib']

    def get_warn_args(self, level: str) -> T.List[str]:
        # TODO: this should be an enum
        return self.warn_args[level]

    def get_depfile_suffix(self) -> str:
        return 'd'

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-E', '-P']

    def get_compile_only_args(self) -> T.List[str]:
        return ['-c']

    def get_no_optimization_args(self) -> T.List[str]:
        return ['-O0']

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_werror_args(self) -> T.List[str]:
        return ['-Werror']

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        if path == '':
            path = '.'
        if is_system:
            return ['-isystem', path]
        return ['-I' + path]

    def get_compiler_dirs(self, env: 'Environment', name: str) -> T.List[str]:
        '''
        Get dirs from the compiler, either `libraries:` or `programs:`
        '''
        return []

    @functools.lru_cache()
    def _get_library_dirs(self, env: 'Environment',
                          elf_class: T.Optional[int] = None) -> 'ImmutableListProtocol[str]':
        # TODO: replace elf_class with enum
        dirs = self.get_compiler_dirs(env, 'libraries')
        if elf_class is None or elf_class == 0:
            return dirs

        # if we do have an elf class for 32-bit or 64-bit, we want to check that
        # the directory in question contains libraries of the appropriate class. Since
        # system directories aren't mixed, we only need to check one file for each
        # directory and go by that. If we can't check the file for some reason, assume
        # the compiler knows what it's doing, and accept the directory anyway.
        retval: T.List[str] = []
        for d in dirs:
            files = [f for f in os.listdir(d) if f.endswith('.so') and os.path.isfile(os.path.join(d, f))]
            # if no files, accept directory and move on
            if not files:
                retval.append(d)
                continue

            for f in files:
                file_to_check = os.path.join(d, f)
                try:
                    with open(file_to_check, 'rb') as fd:
                        header = fd.read(5)
                        # if file is not an ELF file, it's weird, but accept dir
                        # if it is elf, and the class matches, accept dir
                        if header[1:4] != b'ELF' or int(header[4]) == elf_class:
                            retval.append(d)
                        # at this point, it's an ELF file which doesn't match the
                        # appropriate elf_class, so skip this one
                    # stop scanning after the first successful read
                    break
                except OSError:
                    # Skip the file if we can't read it
                    pass

        return retval

    def get_library_dirs(self, env: 'Environment',
                         elf_class: T.Optional[int] = None) -> T.List[str]:
        """Wrap the lru_cache so that we return a new copy and don't allow
        mutation of the cached value.
        """
        return self._get_library_dirs(env, elf_class).copy()

    @functools.lru_cache()
    def _get_program_dirs(self, env: 'Environment') -> 'ImmutableListProtocol[str]':
        '''
        Programs used by the compiler. Also where toolchain DLLs such as
        libstdc++-6.dll are found with MinGW.
        '''
        return self.get_compiler_dirs(env, 'programs')

    def get_program_dirs(self, env: 'Environment') -> T.List[str]:
        return self._get_program_dirs(env).copy()

    def get_pic_args(self) -> T.List[str]:
        return ['-fPIC']

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        return ['-include', os.path.basename(header)]

    def get_pch_name(self, name: str) -> str:
        return os.path.basename(name) + '.' + self.get_pch_suffix()

    def get_default_include_dirs(self) -> T.List[str]:
        return []

    def gen_export_dynamic_link_args(self, env: 'Environment') -> T.List[str]:
        return self.linker.export_dynamic_args(env)

    def gen_import_library_args(self, implibname: str) -> T.List[str]:
        return self.linker.import_library_args(implibname)

    def _sanity_check_impl(self, work_dir: str, environment: 'Environment',
                           sname: str, code: str) -> None:
        mlog.debug('Sanity testing ' + self.get_display_language() + ' compiler:', mesonlib.join_args(self.exelist))
        mlog.debug(f'Is cross compiler: {self.is_cross!s}.')

        source_name = os.path.join(work_dir, sname)
        binname = sname.rsplit('.', 1)[0]
        mode = CompileCheckMode.LINK
        if self.is_cross:
            binname += '_cross'
            if environment.need_exe_wrapper(self.for_machine) and not environment.has_exe_wrapper():
                # Linking cross built C/C++ apps is painful. You can't really
                # tell if you should use -nostdlib or not and for example
                # on OSX the compiler binary is the same but you need
                # a ton of compiler flags to differentiate between
                # arm and x86_64. So just compile.
                mode = CompileCheckMode.COMPILE
        cargs, largs = self._get_basic_compiler_args(environment, mode)
        extra_flags = cargs + self.linker_to_compiler_args(largs)

        # Is a valid executable output for all toolchains and platforms
        binname += '.exe'
        # Write binary check source
        binary_name = os.path.join(work_dir, binname)
        with open(source_name, 'w', encoding='utf-8') as ofile:
            ofile.write(code)
        # Compile sanity check
        # NOTE: extra_flags must be added at the end. On MSVC, it might contain a '/link' argument
        # after which all further arguments will be passed directly to the linker
        cmdlist = self.exelist + [sname] + self.get_output_args(binname) + extra_flags
        pc, stdo, stde = mesonlib.Popen_safe(cmdlist, cwd=work_dir)
        mlog.debug('Sanity check compiler command line:', mesonlib.join_args(cmdlist))
        mlog.debug('Sanity check compile stdout:')
        mlog.debug(stdo)
        mlog.debug('-----\nSanity check compile stderr:')
        mlog.debug(stde)
        mlog.debug('-----')
        if pc.returncode != 0:
            raise mesonlib.EnvironmentException(f'Compiler {self.name_string()} cannot compile programs.')
        # Run sanity check
        if environment.need_exe_wrapper(self.for_machine):
            if not environment.has_exe_wrapper():
                # Can't check if the binaries run so we have to assume they do
                return
            cmdlist = environment.exe_wrapper.get_command() + [binary_name]
        else:
            cmdlist = [binary_name]
        mlog.debug('Running test binary command: ', mesonlib.join_args(cmdlist))
        try:
            # fortran code writes to stdout
            pe = subprocess.run(cmdlist, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            raise mesonlib.EnvironmentException(f'Could not invoke sanity test executable: {e!s}.')
        if pe.returncode != 0:
            raise mesonlib.EnvironmentException(f'Executables created by {self.language} compiler {self.name_string()} are not runnable.')

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        code = 'int main(void) { int class=0; return class; }\n'
        return self._sanity_check_impl(work_dir, environment, 'sanitycheckc.c', code)

    def check_header(self, hname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        code = f'''{prefix}
        #include <{hname}>\n'''
        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies)

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:
        code = f'''{prefix}
        #ifdef __has_include
         #if !__has_include("{hname}")
          #error "Header '{hname}' could not be found"
         #endif
        #else
         #include <{hname}>
        #endif\n'''
        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies, mode=CompileCheckMode.PREPROCESS, disable_cache=disable_cache)

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        t = f'''{prefix}
        #include <{hname}>
        int main(void) {{
            /* If it's not defined as a macro, try to use as a symbol */
            #ifndef {symbol}
                {symbol};
            #endif
            return 0;
        }}\n'''
        return self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)

    def _get_basic_compiler_args(self, env: 'Environment', mode: CompileCheckMode) -> T.Tuple[T.List[str], T.List[str]]:
        cargs: T.List[str] = []
        largs: T.List[str] = []
        if mode is CompileCheckMode.LINK:
            # Sometimes we need to manually select the CRT to use with MSVC.
            # One example is when trying to do a compiler check that involves
            # linking with static libraries since MSVC won't select a CRT for
            # us in that case and will error out asking us to pick one.
            try:
                crt_val = env.coredata.options[OptionKey('b_vscrt')].value
                buildtype = env.coredata.options[OptionKey('buildtype')].value
                cargs += self.get_crt_compile_args(crt_val, buildtype)
            except (KeyError, AttributeError):
                pass

        # Add CFLAGS/CXXFLAGS/OBJCFLAGS/OBJCXXFLAGS and CPPFLAGS from the env
        sys_args = env.coredata.get_external_args(self.for_machine, self.language)
        if isinstance(sys_args, str):
            sys_args = [sys_args]
        # Apparently it is a thing to inject linker flags both
        # via CFLAGS _and_ LDFLAGS, even though the former are
        # also used during linking. These flags can break
        # argument checks. Thanks, Autotools.
        cleaned_sys_args = self.remove_linkerlike_args(sys_args)
        cargs += cleaned_sys_args

        if mode is CompileCheckMode.LINK:
            ld_value = env.lookup_binary_entry(self.for_machine, self.language + '_ld')
            if ld_value is not None:
                largs += self.use_linker_args(ld_value[0], self.version)

            # Add LDFLAGS from the env
            sys_ld_args = env.coredata.get_external_link_args(self.for_machine, self.language)
            # CFLAGS and CXXFLAGS go to both linking and compiling, but we want them
            # to only appear on the command line once. Remove dupes.
            largs += [x for x in sys_ld_args if x not in sys_args]

        cargs += self.get_compiler_args_for_mode(mode)
        return cargs, largs

    def build_wrapper_args(self, env: 'Environment',
                           extra_args: T.Union[None, arglist.CompilerArgs, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                           dependencies: T.Optional[T.List['Dependency']],
                           mode: CompileCheckMode = CompileCheckMode.COMPILE) -> arglist.CompilerArgs:
        # TODO: the caller should handle the listing of these arguments
        if extra_args is None:
            extra_args = []
        else:
            # TODO: we want to do this in the caller
            extra_args = mesonlib.listify(extra_args)
        extra_args = mesonlib.listify([e(mode.value) if callable(e) else e for e in extra_args])

        if dependencies is None:
            dependencies = []
        elif not isinstance(dependencies, collections.abc.Iterable):
            # TODO: we want to ensure the front end does the listifing here
            dependencies = [dependencies]
        # Collect compiler arguments
        cargs: arglist.CompilerArgs = self.compiler_args()
        largs: T.List[str] = []
        for d in dependencies:
            # Add compile flags needed by dependencies
            cargs += d.get_compile_args()
            system_incdir = d.get_include_type() == 'system'
            for i in d.get_include_dirs():
                for idir in i.to_string_list(env.get_source_dir(), env.get_build_dir()):
                    cargs.extend(self.get_include_args(idir, system_incdir))
            if mode is CompileCheckMode.LINK:
                # Add link flags needed to find dependencies
                largs += d.get_link_args()

        ca, la = self._get_basic_compiler_args(env, mode)
        cargs += ca
        largs += la

        cargs += self.get_compiler_check_args(mode)

        # on MSVC compiler and linker flags must be separated by the "/link" argument
        # at this point, the '/link' argument may already be part of extra_args, otherwise, it is added here
        if self.linker_to_compiler_args([]) == ['/link'] and largs != [] and '/link' not in extra_args:
            extra_args += ['/link']

        args = cargs + extra_args + largs
        return args

    def _compile_int(self, expression: str, prefix: str, env: 'Environment',
                     extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                     dependencies: T.Optional[T.List['Dependency']]) -> bool:
        t = f'''{prefix}
        #include <stddef.h>
        int main(void) {{ static int a[1-2*!({expression})]; a[0]=0; return 0; }}\n'''
        return self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)[0]

    def cross_compute_int(self, expression: str, low: T.Optional[int], high: T.Optional[int],
                          guess: T.Optional[int], prefix: str, env: 'Environment',
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> int:
        # Try user's guess first
        if isinstance(guess, int):
            if self._compile_int(f'{expression} == {guess}', prefix, env, extra_args, dependencies):
                return guess

        # If no bounds are given, compute them in the limit of int32
        maxint = 0x7fffffff
        minint = -0x80000000
        if not isinstance(low, int) or not isinstance(high, int):
            if self._compile_int(f'{expression} >= 0', prefix, env, extra_args, dependencies):
                low = cur = 0
                while self._compile_int(f'{expression} > {cur}', prefix, env, extra_args, dependencies):
                    low = cur + 1
                    if low > maxint:
                        raise mesonlib.EnvironmentException('Cross-compile check overflowed')
                    cur = min(cur * 2 + 1, maxint)
                high = cur
            else:
                high = cur = -1
                while self._compile_int(f'{expression} < {cur}', prefix, env, extra_args, dependencies):
                    high = cur - 1
                    if high < minint:
                        raise mesonlib.EnvironmentException('Cross-compile check overflowed')
                    cur = max(cur * 2, minint)
                low = cur
        else:
            # Sanity check limits given by user
            if high < low:
                raise mesonlib.EnvironmentException('high limit smaller than low limit')
            condition = f'{expression} <= {high} && {expression} >= {low}'
            if not self._compile_int(condition, prefix, env, extra_args, dependencies):
                raise mesonlib.EnvironmentException('Value out of given range')

        # Binary search
        while low != high:
            cur = low + int((high - low) / 2)
            if self._compile_int(f'{expression} <= {cur}', prefix, env, extra_args, dependencies):
                high = cur
            else:
                low = cur + 1

        return low

    def compute_int(self, expression: str, low: T.Optional[int], high: T.Optional[int],
                    guess: T.Optional[int], prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                    dependencies: T.Optional[T.List['Dependency']] = None) -> int:
        if extra_args is None:
            extra_args = []
        if self.is_cross:
            return self.cross_compute_int(expression, low, high, guess, prefix, env, extra_args, dependencies)
        t = f'''{prefix}
        #include<stddef.h>
        #include<stdio.h>
        int main(void) {{
            printf("%ld\\n", (long)({expression}));
            return 0;
        }}'''
        res = self.run(t, env, extra_args=extra_args,
                       dependencies=dependencies)
        if not res.compiled:
            return -1
        if res.returncode != 0:
            raise mesonlib.EnvironmentException('Could not run compute_int test binary.')
        return int(res.stdout)

    def cross_sizeof(self, typename: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> int:
        if extra_args is None:
            extra_args = []
        t = f'''{prefix}
        #include <stddef.h>
        int main(void) {{
            {typename} something;
            return 0;
        }}\n'''
        if not self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)[0]:
            return -1
        return self.cross_compute_int(f'sizeof({typename})', None, None, None, prefix, env, extra_args, dependencies)

    def sizeof(self, typename: str, prefix: str, env: 'Environment', *,
               extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
               dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        if extra_args is None:
            extra_args = []
        if self.is_cross:
            r = self.cross_sizeof(typename, prefix, env, extra_args=extra_args,
                                  dependencies=dependencies)
            return r, False
        t = f'''{prefix}
        #include<stddef.h>
        #include<stdio.h>
        int main(void) {{
            printf("%ld\\n", (long)(sizeof({typename})));
            return 0;
        }}'''
        res = self.cached_run(t, env, extra_args=extra_args,
                              dependencies=dependencies)
        if not res.compiled:
            return -1, False
        if res.returncode != 0:
            raise mesonlib.EnvironmentException('Could not run sizeof test binary.')
        return int(res.stdout), res.cached

    def cross_alignment(self, typename: str, prefix: str, env: 'Environment', *,
                        extra_args: T.Optional[T.List[str]] = None,
                        dependencies: T.Optional[T.List['Dependency']] = None) -> int:
        if extra_args is None:
            extra_args = []
        t = f'''{prefix}
        #include <stddef.h>
        int main(void) {{
            {typename} something;
            return 0;
        }}\n'''
        if not self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)[0]:
            return -1
        t = f'''{prefix}
        #include <stddef.h>
        struct tmp {{
            char c;
            {typename} target;
        }};'''
        return self.cross_compute_int('offsetof(struct tmp, target)', None, None, None, t, env, extra_args, dependencies)

    def alignment(self, typename: str, prefix: str, env: 'Environment', *,
                  extra_args: T.Optional[T.List[str]] = None,
                  dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        if extra_args is None:
            extra_args = []
        if self.is_cross:
            r = self.cross_alignment(typename, prefix, env, extra_args=extra_args,
                                     dependencies=dependencies)
            return r, False
        t = f'''{prefix}
        #include <stdio.h>
        #include <stddef.h>
        struct tmp {{
            char c;
            {typename} target;
        }};
        int main(void) {{
            printf("%d", (int)offsetof(struct tmp, target));
            return 0;
        }}'''
        res = self.cached_run(t, env, extra_args=extra_args,
                              dependencies=dependencies)
        if not res.compiled:
            raise mesonlib.EnvironmentException('Could not compile alignment test.')
        if res.returncode != 0:
            raise mesonlib.EnvironmentException('Could not run alignment test binary.')
        align = int(res.stdout)
        if align == 0:
            raise mesonlib.EnvironmentException(f'Could not determine alignment of {typename}. Sorry. You might want to file a bug.')
        return align, res.cached

    def get_define(self, dname: str, prefix: str, env: 'Environment',
                   extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                   dependencies: T.Optional[T.List['Dependency']],
                   disable_cache: bool = False) -> T.Tuple[str, bool]:
        delim_start = '"MESON_GET_DEFINE_DELIMITER_START"\n'
        delim_end = '\n"MESON_GET_DEFINE_DELIMITER_END"'
        sentinel_undef = '"MESON_GET_DEFINE_UNDEFINED_SENTINEL"'
        code = f'''
        {prefix}
        #ifndef {dname}
        # define {dname} {sentinel_undef}
        #endif
        {delim_start}{dname}{delim_end}'''
        args = self.build_wrapper_args(env, extra_args, dependencies,
                                       mode=CompileCheckMode.PREPROCESS).to_native()
        func = functools.partial(self.cached_compile, code, env.coredata, extra_args=args, mode=CompileCheckMode.PREPROCESS)
        if disable_cache:
            func = functools.partial(self.compile, code, extra_args=args, mode=CompileCheckMode.PREPROCESS)
        with func() as p:
            cached = p.cached
            if p.returncode != 0:
                raise mesonlib.EnvironmentException(f'Could not get define {dname!r}')

        # Get the preprocessed value between the delimiters
        star_idx = p.stdout.find(delim_start)
        end_idx = p.stdout.rfind(delim_end)
        if (star_idx == -1) or (end_idx == -1) or (star_idx == end_idx):
            raise mesonlib.MesonBugException('Delimiters not found in preprocessor output.')
        define_value = p.stdout[star_idx + len(delim_start):end_idx]

        if define_value == sentinel_undef:
            define_value = None
        else:
            # Merge string literals
            define_value = self._concatenate_string_literals(define_value).strip()

        return define_value, cached

    def get_return_value(self, fname: str, rtype: str, prefix: str,
                         env: 'Environment', extra_args: T.Optional[T.List[str]],
                         dependencies: T.Optional[T.List['Dependency']]) -> T.Union[str, int]:
        # TODO: rtype should be an enum.
        # TODO: maybe we can use overload to tell mypy when this will return int vs str?
        if rtype == 'string':
            fmt = '%s'
            cast = '(char*)'
        elif rtype == 'int':
            fmt = '%lli'
            cast = '(long long int)'
        else:
            raise AssertionError(f'BUG: Unknown return type {rtype!r}')
        code = f'''{prefix}
        #include <stdio.h>
        int main(void) {{
            printf ("{fmt}", {cast} {fname}());
            return 0;
        }}'''
        res = self.run(code, env, extra_args=extra_args, dependencies=dependencies)
        if not res.compiled:
            raise mesonlib.EnvironmentException(f'Could not get return value of {fname}()')
        if rtype == 'string':
            return res.stdout
        elif rtype == 'int':
            try:
                return int(res.stdout.strip())
            except ValueError:
                raise mesonlib.EnvironmentException(f'Return value of {fname}() is not an int')
        assert False, 'Unreachable'

    @staticmethod
    def _no_prototype_templ() -> T.Tuple[str, str]:
        """
        Try to find the function without a prototype from a header by defining
        our own dummy prototype and trying to link with the C library (and
        whatever else the compiler links in by default). This is very similar
        to the check performed by Autoconf for AC_CHECK_FUNCS.
        """
        # Define the symbol to something else since it is defined by the
        # includes or defines listed by the user or by the compiler. This may
        # include, for instance _GNU_SOURCE which must be defined before
        # limits.h, which includes features.h
        # Then, undef the symbol to get rid of it completely.
        head = '''
        #define {func} meson_disable_define_of_{func}
        {prefix}
        #include <limits.h>
        #undef {func}
        '''
        # Override any GCC internal prototype and declare our own definition for
        # the symbol. Use char because that's unlikely to be an actual return
        # value for a function which ensures that we override the definition.
        head += '''
        #ifdef __cplusplus
        extern "C"
        #endif
        char {func} (void);
        '''
        # The actual function call
        main = '''
        int main(void) {{
          return {func} ();
```