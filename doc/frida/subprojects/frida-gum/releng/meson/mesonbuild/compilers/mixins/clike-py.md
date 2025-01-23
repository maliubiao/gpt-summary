Response:
The user wants to understand the functionality of the Python code provided, which is part of the Frida dynamic instrumentation tool. This code specifically resides in the `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py` file and defines mixin classes for C-like compilers within the Meson build system.

Here's a plan to address the request:

1. **Identify the core functionality:** Focus on the purpose of the `CLikeCompilerArgs` and `CLikeCompiler` classes and their methods.
2. **Explain the relationship to reverse engineering:**  Connect the functionalities to common tasks in reverse engineering, such as analyzing binaries, understanding code structures, and manipulating execution flow.
3. **Highlight interactions with low-level concepts:**  Point out aspects related to binary formats, operating system kernels (Linux, Android), and frameworks.
4. **Provide examples of logical reasoning:**  Illustrate how the code might handle different inputs and the expected outputs.
5. **Demonstrate potential user errors:** Show common mistakes a user could make when interacting with these functionalities.
6. **Explain the debugging context:** Describe how a user might end up in this part of the code during a debugging session.
7. **Summarize the overall function:** Concisely recap the main purpose of the code.

**Detailed Breakdown:**

* **`CLikeCompilerArgs`:** This class deals with managing compiler arguments. It handles things like:
    * Prepending prefixes to certain arguments (`-I`, `-L`).
    * Deduplicating arguments to avoid redundancy.
    * Adding linker groups for circular dependencies.
    * Removing default include paths.
    * Converting arguments to native compiler format.

* **`CLikeCompiler`:** This class provides a base for C-like compilers, offering common functionalities like:
    * Handling compiler arguments.
    * Checking for the need for a static linker.
    * Providing common compiler flags for warnings, optimizations, includes, etc.
    * Performing sanity checks to ensure the compiler is working correctly.
    * Checking for the presence of headers and symbols.
    * Computing the size and alignment of data types.
    * Retrieving the value of preprocessor defines.
    * Getting the return value of functions.

**Connecting to Reverse Engineering:**

Many of these functions are crucial for tasks performed during reverse engineering, as they allow interaction with the target binary's compilation environment.

**Low-Level Concepts:**

The code interacts with binary formats (like ELF), operating system concepts (like include paths and library directories), and build system details.

**Logical Reasoning Examples:**

Consider the `dedup1_prefixes` and `dedup1_suffixes`. If the input arguments contain `-lfoo.so` and later `-Wl,-lfoo`, the deduplication logic would remove the redundant entry.

**User Errors:**

A user might incorrectly specify include paths or library names, leading to compilation failures that this code might help diagnose.

**Debugging Context:**

A developer working on Frida might step into this code while debugging issues related to compiler flag generation, dependency resolution, or cross-compilation.
好的，让我们来分析一下 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件的功能。

**文件功能归纳：**

这个 Python 文件定义了一组混入类 (mixin classes)，旨在为 C 和 C++ 编译器提供共享的功能。这些混入类主要处理与编译过程相关的通用任务，例如：

1. **管理编译器参数 (`CLikeCompilerArgs`)：**
   -  定义了如何处理和格式化传递给编译器的参数，例如添加前缀（`-I`, `-L`）、去重（重复的 include 路径、库链接等）、以及添加链接器分组（`-Wl,--start-group`, `-Wl,--end-group`）来解决静态库之间的循环依赖问题。
   -  能够将内部表示的参数列表转换为特定编译器的原生命令行格式。
   -  提供了移除系统默认 include 路径的功能。

2. **提供 C-like 编译器的通用能力 (`CLikeCompiler`)：**
   -  维护了编译器支持的文件后缀列表 (`can_compile_suffixes`)。
   -  提供了获取预处理器对象的方法 (`get_preprocessor`)。
   -  封装了创建编译器参数对象的方法 (`compiler_args`)。
   -  定义了是否需要静态链接器的判断 (`needs_static_linker`)。
   -  提供了获取常用编译器参数的方法，例如：
     -  始终启用的参数 (`get_always_args`)
     -  禁用标准 include 路径的参数 (`get_no_stdinc_args`)
     -  禁用标准库链接的参数 (`get_no_stdlib_link_args`)
     -  不同警告级别的参数 (`get_warn_args`)
     -  生成依赖文件后缀 (`get_depfile_suffix`)
     -  预处理和编译的参数 (`get_preprocess_only_args`, `get_compile_only_args`)
     -  禁用优化的参数 (`get_no_optimization_args`)
     -  指定输出文件名的参数 (`get_output_args`)
     -  将警告视为错误的参数 (`get_werror_args`)
     -  添加 include 路径的参数 (`get_include_args`)
     -  获取库文件和程序文件的目录 (`get_compiler_dirs`, `get_library_dirs`, `get_program_dirs`)
     -  生成位置无关代码的参数 (`get_pic_args`)
     -  使用预编译头的参数 (`get_pch_use_args`, `get_pch_name`)
     -  获取默认 include 目录 (`get_default_include_dirs`)
     -  生成导出动态符号的链接参数 (`gen_export_dynamic_link_args`)
     -  生成导入库的链接参数 (`gen_import_library_args`)
   -  实现了编译器可用性的基本检查 (`sanity_check`)，通过编译和运行一个简单的程序来验证编译器是否正常工作。
   -  提供了检查头文件是否存在 (`check_header`, `has_header`) 以及头文件中是否存在特定符号 (`has_header_symbol`) 的功能。
   -  提供了在交叉编译环境下计算表达式的值 (`cross_compute_int`) 和获取类型大小 (`cross_sizeof`) 以及对齐方式 (`cross_alignment`) 的能力。
   -  提供了在本地编译环境下计算表达式的值 (`compute_int`) 和获取类型大小 (`sizeof`) 以及对齐方式 (`alignment`) 的能力。
   -  提供了获取预处理器宏定义值的功能 (`get_define`)。
   -  提供了获取函数返回值的功能 (`get_return_value`)。

**与逆向方法的关系：**

这个文件中的功能与逆向工程有密切关系，主要体现在以下几个方面：

1. **理解目标软件的编译环境：** 逆向工程师常常需要理解目标软件是如何被编译的，使用了哪些编译器选项、包含了哪些头文件、链接了哪些库。`CLikeCompiler` 类提供的功能，例如检查头文件、获取宏定义、检查编译器的基础功能，可以帮助逆向工程师重建或理解目标软件的编译环境。

   **举例说明：**  假设逆向一个 Linux 下的共享库，逆向工程师可能想知道编译该库时是否定义了某个特定的宏，例如 `_DEBUG`。`get_define` 方法可以模拟编译过程，提取出该宏的值，从而帮助理解库的行为是否与调试版本有关。

2. **模拟编译过程进行静态分析：** 逆向分析不仅仅是分析已经编译好的二进制代码，有时也需要对源代码进行静态分析。`CLikeCompiler` 提供的检查头文件、符号存在性的功能，可以帮助逆向工具理解代码结构和依赖关系，即使没有完整的编译环境。

   **举例说明：**  逆向工程师在分析一个二进制文件时，发现它调用了一个来自某个头文件的函数。可以使用 `has_header` 和 `has_header_symbol` 来验证是否真的包含了那个头文件以及函数是否在头文件中声明，从而推断代码的意图。

3. **辅助动态分析：** Frida 本身是一个动态插桩工具，而这个文件是 Frida 内部的一部分。在动态分析过程中，可能需要在目标进程中注入代码或修改内存。理解目标进程的编译环境（例如数据结构的大小和对齐方式）对于正确地操作内存至关重要。

   **举例说明：**  在 Frida 脚本中，逆向工程师可能需要读取或修改目标进程中某个结构体的成员。`sizeof` 和 `alignment` 方法可以帮助确定该结构体成员在内存中的偏移量，从而实现精确的内存操作。

**涉及到的二进制底层、Linux、Android 内核及框架的知识：**

1. **二进制底层知识：**
   - **ELF 文件格式：** 代码中涉及到检查 `.so` 文件，这与 Linux 下共享库的 ELF 文件格式有关。
   - **链接器分组：**  `-Wl,--start-group` 和 `-Wl,--end-group` 是链接器选项，用于解决静态库之间的循环依赖，这是二进制链接过程中的一个底层概念。
   - **预编译头 (PCH)：**  `get_pch_use_args` 和 `get_pch_name` 涉及到预编译头的处理，这是一种提高编译速度的优化技术，在二进制构建过程中很重要。

2. **Linux 内核及框架知识：**
   - **系统 include 路径：** 代码中移除了系统默认的 include 路径，这与 Linux 系统中头文件的查找机制有关。
   - **共享库 (`.so`)：** 代码中多次提到 `.so` 文件，这是 Linux 下动态链接库的常见格式。
   - **动态链接器：** 代码中与 `GnuLikeDynamicLinkerMixin` 和 `SolarisDynamicLinker` 等链接器类进行交互，涉及到 Linux 下动态链接的机制。

3. **Android 内核及框架知识：** 虽然代码没有直接提到 Android 特有的概念，但作为 Frida 的一部分，它所提供的编译器信息提取能力同样适用于 Android 平台的逆向分析。Android 应用程序和库的编译也遵循类似的 C/C++ 编译流程。

**逻辑推理举例：**

**假设输入：**

* `compiler`: 一个 GCC 编译器的实例。
* `args`: 一个包含字符串 `'-I/usr/include'` 和 `'-I/usr/include'` 的列表。

**输出 (在 `CLikeCompilerArgs.to_native` 中)：**

由于 `dedup2_prefixes` 包含 `'-I'`，重复的 `'-I/usr/include'` 将会被去重，最终 `new._container` 中只会包含一个 `'-I/usr/include'`。

**用户或编程常见的使用错误：**

1. **错误的 include 路径：** 用户在配置编译环境时，可能会提供错误的 include 路径，导致头文件找不到。`get_include_args` 可以帮助诊断这类问题，但如果用户提供的路径根本不存在，编译器仍然会报错。

   **举例：** 用户可能错误地将 `/opt/my_library/inc` 作为 include 路径，但实际上头文件在 `/opt/my_library/include` 下。

2. **库依赖缺失或顺序错误：**  在链接阶段，如果依赖的库文件缺失或者链接顺序不正确，会导致链接失败。`CLikeCompilerArgs` 中添加链接器分组的功能可以缓解静态库循环依赖的问题，但并不能解决所有库依赖问题。

   **举例：**  一个程序依赖 `libfoo.a` 和 `libbar.a`，但用户只链接了 `libfoo.a`，或者链接顺序错误，先链接了依赖其他库的库。

**用户操作如何一步步到达这里，作为调试线索：**

假设一个 Frida 开发者正在开发一个基于 Frida-gum 的工具，需要编译一些 C 代码注入到目标进程中。

1. **用户编写 Frida 脚本和 C 代码。**
2. **Frida 脚本调用 Frida-gum 的 API 来编译 C 代码。**
3. **Frida-gum 内部使用 Meson 构建系统来处理编译过程。**
4. **Meson 根据配置选择合适的编译器（例如 GCC）。**
5. **Meson 在处理编译器参数时，会创建 `CLikeCompilerArgs` 对象。**
6. **在生成最终的编译器命令行时，可能会调用 `CLikeCompilerArgs.to_native()` 方法。**
7. **如果在编译过程中出现链接错误，例如提示找不到某个库，开发者可能会开始调试 Meson 的构建过程。**
8. **开发者可能会在 `CLikeCompilerArgs.to_native()` 方法中设置断点，查看生成的命令行参数是否正确，例如是否包含了需要的库路径和库文件。**
9. **如果问题涉及到循环依赖，开发者可能会检查是否正确添加了链接器分组。**

**总结一下它的功能：**

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件定义了 Meson 构建系统中用于处理 C 和 C++ 编译器的基础功能。它负责管理和生成传递给编译器的参数，并提供了一系列检查编译器环境和能力的方法。这些功能对于确保 Frida-gum 能够正确地编译和链接代码至关重要。对于逆向工程师而言，理解这些功能有助于理解目标软件的编译过程，并辅助进行静态和动态分析。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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