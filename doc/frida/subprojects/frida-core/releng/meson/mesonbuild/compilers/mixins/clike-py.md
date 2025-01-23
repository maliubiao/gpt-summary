Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding: Context and Purpose**

The first thing I notice is the file path: `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/mixins/clike.py`. This immediately tells me:

* **Project:** Frida (a dynamic instrumentation toolkit).
* **Subproject:** Frida Core (likely the core functionality).
* **Build System:** Meson (a build system like CMake or Make).
* **Location:** Within the Meson configuration, specifically related to compilers.
* **Type:** "mixins," suggesting reusable code for C-like compilers.
* **Language:** Python.

The docstring reinforces this, stating it provides shared functionality for C and C++ compilers within Meson to avoid complex inheritance.

**2. Core Functionality Identification (Keywords and Patterns)**

I start scanning the code for keywords and patterns that reveal the core responsibilities:

* **Class `CLikeCompilerArgs`:**  This deals with compiler arguments. I see methods like `to_native`, `prepend_prefixes`, `dedup_prefixes`. This suggests it's responsible for formatting and manipulating compiler command-line arguments. The `GROUP_FLAGS` regular expression hints at handling library grouping for linking.
* **Class `CLikeCompiler`:** This is the main mixin class. I look for methods that indicate its functionality:
    * `compiler_args`: Creates an instance of `CLikeCompilerArgs`.
    * `needs_static_linker`:  Indicates if a static linker is required.
    * `get_always_args`, `get_no_stdinc_args`, etc.:  Methods that return lists of compiler flags, categorized by their purpose (warnings, include paths, optimization).
    * `get_include_args`, `get_library_dirs`, `get_program_dirs`: Methods for finding include directories, library directories, and program directories. This links to dependency management and finding tools.
    * `sanity_check`: A crucial method for verifying the compiler is working correctly.
    * `check_header`, `has_header`, `has_header_symbol`: Methods for checking the existence of headers and symbols within them – vital for feature detection.
    * `compiles`, `run`: Methods that actually invoke the compiler.
    * `compute_int`, `sizeof`, `alignment`, `get_define`: More complex checks that involve compiling and running code to determine values, sizes, and alignments. These are classic build system checks for platform differences.
    * `gen_export_dynamic_link_args`, `gen_import_library_args`: Methods related to dynamic linking.

**3. Relationship to Reverse Engineering**

I actively look for connections to reverse engineering concepts:

* **Dynamic Instrumentation (Frida's Purpose):**  The code's origin within Frida is the biggest clue. Compiler settings and checks directly impact how code is built, which is crucial for Frida to interact with target processes.
* **Binary Level:**  Methods like `sizeof` and `alignment` directly deal with the binary layout of data structures, fundamental to understanding how programs work at a low level.
* **Linking:** The handling of library paths (`get_library_dirs`), linker flags (`-l`, `-Wl`), and dynamic linking (`gen_export_dynamic_link_args`) are key to understanding how executables are assembled, which is important for reverse engineering.
* **System Calls/APIs:** Header checks (`has_header`) are about ensuring necessary system APIs are available. Understanding system calls is a large part of reverse engineering.
* **Architecture Differences:** The handling of 32-bit and 64-bit libraries (`elf_class`) shows an awareness of different architectures, a vital consideration in reverse engineering.

**4. Kernel/Framework Connections**

I consider how compiler settings interact with the OS:

* **Linux/Android Kernel:** Header files often come directly from the kernel or system libraries. Checks for these headers relate to kernel functionality.
* **Android Framework:** While not explicitly mentioned in the code, the general concepts of compilation and linking apply to Android framework components. The ability to check for specific symbols or features could be used when building Frida components that interact with the framework.

**5. Logical Reasoning and Examples**

I look for methods that perform checks and try to imagine input and output:

* **`compute_int`:**  If the input `expression` is "1 + 1", the output should be 2. The code handles cross-compilation, which adds complexity.
* **`sizeof`:** If `typename` is "int", the output on a 32-bit system would likely be 4, and on a 64-bit system, still likely 4 (but `long` might be 8).
* **`alignment`:** The alignment of a struct depends on its members. The example provided in the prompt is a good illustration.

**6. Common Usage Errors**

I think about how developers might misuse these functions:

* **Incorrect `prefix`:** If the `prefix` in header checks doesn't include necessary definitions, the check might fail incorrectly.
* **Wrong `extra_args`:**  Providing incorrect or missing compiler flags can lead to compilation errors.
* **Misunderstanding Cross-Compilation:**  Cross-compilation introduces many complexities, and users might not correctly configure the environment or compiler flags.

**7. Debugging Scenario**

I imagine how a developer might end up looking at this code:

* **Build Failure:** A common scenario is a build failure related to compiler errors or missing dependencies.
* **Feature Detection Issues:** If a build system check for a header or symbol fails unexpectedly, a developer might trace the execution to these mixin classes.
* **Cross-Compilation Problems:**  Debugging cross-compilation setups often involves examining the compiler flags and environment, leading developers to this code.

**8. Summarization**

Finally, I condense my understanding into a concise summary of the class's purpose and key functionalities.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on individual methods.**  I then realize the importance of understanding the overall *flow* and the relationships between methods.
* **I might miss a subtle connection.** For instance, the `GROUP_FLAGS` regex initially seemed like just a detail, but recognizing its connection to handling circular dependencies during linking is important.
* **I constantly revisit the context (Frida and Meson) to ensure my analysis is relevant.** I ask myself, "How does this help Frida build software?"

By following this systematic approach, combining code analysis with domain knowledge and reasoning, I can effectively understand and explain the functionality of this code snippet.
这是 frida 动态 instrumentation 工具中一个名为 `clike.py` 的 Python 源代码文件，位于 `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/mixins/` 目录下。从路径和文件名来看，它很明显是 Meson 构建系统中用于 C 语言及其衍生语言（如 C++、Objective-C 等）编译器的混合类 (mixin)。

**它的主要功能是提供 C-like 编译器通用的功能和逻辑，避免在 C 和 C++ 等编译器的类中重复编写相同的代码。** 这些功能涵盖了编译过程中的多个方面，包括参数处理、依赖查找、编译器检查、以及与操作系统底层交互等。

下面我们详细列举一下它的功能，并结合逆向、底层、内核、用户错误和调试线索进行说明：

**核心功能归纳：**

1. **编译器参数处理 (`CLikeCompilerArgs` 类):**
   - **功能:**  封装和处理 C-like 编译器的命令行参数。包括添加前缀、去重等操作。
   - **逆向关系:** 逆向工程师经常需要分析编译器生成的命令行，理解编译选项如何影响最终的二进制文件。这个类处理的参数直接影响着目标程序的编译方式，例如包含哪些头文件、链接哪些库、是否启用优化等。
   - **二进制底层:**  编译器参数直接控制着生成目标文件的过程，例如指定目标架构、代码优化级别、调试信息等，这些都与二进制文件的结构和行为息息相关。
   - **Linux/Android 内核及框架:**  例如 `-I` 参数指定头文件搜索路径，可能涉及到 Linux 或 Android 系统提供的标准库头文件。`-L` 参数指定库文件搜索路径，可能涉及到系统库或 Android Framework 的库。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  `CLikeCompilerArgs` 对象包含 `['-I/usr/include', '-L/usr/lib', '-lsqlite3', '-O2']`
     - **输出 (调用 `to_native()`):** 根据具体的编译器和平台，可能会添加 `-Wl,--start-group` 和 `-Wl,--end-group` 来处理静态库的循环依赖，并移除默认的系统 include 路径，最终输出适合该编译器的原生命令行参数列表。
   - **用户/编程常见错误:**  用户可能错误地指定了重复的 include 或 library 路径，或者使用了不兼容的编译器选项。这个类可以帮助 Meson 在构建时进行一定的规范化和检查。

2. **共享的编译器功能 (`CLikeCompiler` 类):**
   - **功能:** 提供 C 和 C++ 等编译器通用的方法，例如获取默认参数、处理警告、获取依赖文件后缀、执行编译和链接操作等。
   - **逆向关系:**  理解编译器的工作原理是逆向的基础。这个类中的方法，如 `get_output_args`（指定输出文件名）、`get_compile_only_args`（只编译不链接），直接关联到逆向分析时需要关注的目标文件的生成过程。
   - **二进制底层:**  例如 `get_pic_args` 返回生成位置无关代码的参数，这对于创建共享库至关重要，而共享库在动态链接中扮演核心角色。
   - **Linux/Android 内核及框架:**  `get_library_dirs` 方法用于获取库文件搜索路径，这会涉及到 Linux 的标准库路径（如 `/lib`, `/usr/lib`）或者 Android 系统库的路径。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 调用 `get_include_args('/opt/my_lib/include', is_system=False)`
     - **输出:** `['-I/opt/my_lib/include']`
     - **假设输入:** 调用 `get_werror_args()`
     - **输出:** `['-Werror']` (将所有警告视为错误)
   - **用户/编程常见错误:** 用户可能忘记包含必要的头文件路径，导致编译错误。Meson 利用这些方法来构建正确的编译器命令，减少此类错误。

3. **编译器的健全性检查 (`sanity_check` 方法):**
   - **功能:**  通过编译和运行一个简单的 C 程序来验证编译器是否正常工作。
   - **逆向关系:**  如果编译器本身有问题，那么所有基于此编译器的逆向分析工具或操作都可能面临风险。确保编译器的可靠性是至关重要的。
   - **二进制底层:**  这个检查确保编译器能够生成可执行的二进制代码。
   - **Linux/Android 内核及框架:**  验证编译器能否与目标平台的标准库正确链接。
   - **用户操作到达这里的方式 (调试线索):**
     1. 用户运行 Meson 配置命令 (`meson setup builddir`).
     2. Meson 会检测系统中的 C/C++ 编译器。
     3. 为了确保编译器可用，Meson 内部会调用 `sanity_check` 方法。
     4. 如果 `sanity_check` 失败，Meson 会报错，提示编译器不可用，并提供相关的 stdout 和 stderr 信息，作为调试线索。

4. **头文件和符号检查 (`check_header`, `has_header`, `has_header_symbol` 方法):**
   - **功能:**  检查指定的头文件是否存在，或者头文件中是否定义了某个符号。
   - **逆向关系:**  逆向分析时，了解目标程序依赖哪些头文件和符号是重要的信息。这些方法可以帮助判断某个功能或 API 是否在目标环境中可用。
   - **Linux/Android 内核及框架:**  例如，检查 `<pthread.h>` 是否存在，可以确定系统是否支持 POSIX 线程。检查 Android NDK 的特定头文件，可以了解目标是否支持某些 Android 特有的功能。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 调用 `has_header('stdio.h', '', env)`
     - **输出:** `(True, False)`  (假设 `stdio.h` 存在且未从缓存获取)
     - **假设输入:** 调用 `has_header_symbol('unistd.h', 'fork', '', env)`
     - **输出:** `(True, True)` (假设 `fork` 函数在 `unistd.h` 中定义)
   - **用户操作到达这里的方式 (调试线索):**
     1. Meson 构建脚本中使用了 `meson.get_compiler('c').has_header('...')` 或类似的方法。
     2. 在配置阶段，Meson 会调用这些方法进行特性检测。
     3. 如果头文件或符号检查失败，可能会导致依赖项查找失败或编译选项设置不正确，从而导致后续构建错误。Meson 的日志会包含这些检查的结果，作为调试线索。

5. **编译和运行代码片段 (`compiles`, `run` 方法):**
   - **功能:**  编译一段给定的 C/C++ 代码片段，并可以选择运行它。这通常用于更复杂的特性检测或获取编译器的行为信息。
   - **逆向关系:**  逆向工程师有时需要编写小的测试程序来验证对目标程序行为的理解，或者测试特定的编译器特性。
   - **用户操作到达这里的方式 (调试线索):**
     1. Meson 构建脚本中使用了 `meson.get_compiler('c').compiles('...')` 或 `meson.get_compiler('c').run('...')`。
     2. 这些方法用于进行更深入的特性检测，例如检查特定的语言特性是否支持，或者获取编译器的输出信息。
     3. 如果编译或运行失败，Meson 会提供编译器的输出和错误信息，帮助开发者定位问题。

6. **计算类型大小和对齐 (`sizeof`, `alignment` 方法):**
   - **功能:**  通过编译和运行代码来获取特定数据类型的大小和内存对齐方式。
   - **逆向关系:**  理解数据类型的布局对于逆向工程至关重要，尤其是在分析二进制数据结构和进行内存操作时。不同平台和编译器可能对类型的布局有所不同。
   - **二进制底层:**  直接关联到数据在内存中的表示方式。
   - **Linux/Android 内核及框架:**  类型的大小和对齐可能受到目标平台架构的影响。
   - **用户操作到达这里的方式 (调试线索):**
     1. Meson 构建脚本中使用了 `meson.get_compiler('c').sizeof('int')` 或 `meson.get_compiler('c').alignment('struct MyStruct')`。
     2. 这些信息用于调整数据结构或进行平台相关的优化。
     3. 如果获取的大小或对齐值与预期不符，可能表明编译器配置或目标平台存在问题。

7. **获取宏定义的值 (`get_define` 方法):**
   - **功能:**  通过预处理一段代码来获取某个宏定义的值。
   - **逆向关系:**  宏定义在 C/C++ 代码中广泛使用，理解宏的值对于理解代码的行为至关重要。
   - **用户操作到达这里的方式 (调试线索):**
     1. Meson 构建脚本中使用了 `meson.get_compiler('c').get_define('MY_MACRO', '...')`。
     2. 这用于获取编译时定义的配置信息。

8. **获取函数返回值 (`get_return_value` 方法):**
   - **功能:**  编译并运行一个调用特定函数的代码片段，获取该函数的返回值。
   - **逆向关系:**  在某些情况下，可能需要通过编译和运行代码来动态获取某些函数的返回值，以辅助逆向分析。

**涉及到的二进制底层知识:**

- **目标文件格式:**  编译器生成的目标文件的结构，例如 ELF (Linux) 或 Mach-O (macOS)。
- **链接过程:**  将多个目标文件和库文件合并成可执行文件的过程。
- **内存布局:**  数据在内存中的存储方式，包括大小端、对齐等。
- **指令集架构:**  编译器需要根据目标平台的指令集架构生成相应的机器码。

**涉及到的 Linux/Android 内核及框架知识:**

- **系统调用:**  编译器需要能够链接到提供系统调用接口的库。
- **标准 C 库 (libc):**  包含了许多常用的函数，编译器需要能够找到并链接它。
- **Android NDK/SDK:**  在构建 Android 应用时，需要使用 Android 特定的头文件和库。
- **动态链接器:**  负责在程序运行时加载共享库。

**涉及到的逻辑推理:**

- 例如在 `compute_int` 方法中，通过多次编译和比较来推断出一个整型表达式的值，即使在交叉编译环境下也能工作。

**涉及到的用户或编程常见的使用错误:**

- **路径配置错误:**  用户可能没有正确设置 include 或 library 的搜索路径。
- **编译器选择错误:**  用户可能选择了不适合目标平台的编译器。
- **依赖项缺失:**  用户可能缺少构建所需的库文件或头文件。
- **编译选项冲突:**  用户可能使用了相互冲突的编译器选项。

**总结 `clike.py` 的功能:**

`clike.py` 文件在 frida 的构建系统中扮演着关键角色，它为 C 和 C++ 等语言的编译器提供了通用的构建和检测功能。 这些功能包括处理编译器参数、执行健全性检查、检测头文件和符号、编译和运行代码片段、获取类型信息以及宏定义等。 这使得 Meson 能够灵活地支持各种 C-like 编译器，并能根据目标平台的特性进行正确的构建配置。  这些功能与逆向工程紧密相关，因为它们直接影响着最终生成的可执行文件和库的特性和结构，而这些都是逆向分析的对象。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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