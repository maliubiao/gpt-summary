Response:
The user wants a summary of the functionality of the Python code in `frida/releng/meson/mesonbuild/compilers/mixins/clike.py`. I need to identify the main purposes of this code, focusing on:

1. **Core Functionality**: What does this Python module do?
2. **Relationship to Reverse Engineering**: Does any of its functionality directly or indirectly aid in reverse engineering?
3. **Binary/Kernel/Framework Interaction**: Does it interact with low-level binary concepts, Linux/Android kernels, or frameworks?
4. **Logical Inference**: Does it perform any logical deductions or evaluations?
5. **Common User Errors**: Are there any ways a user could misuse the features of this code?
6. **User Path to This Code**: How might a user's actions lead to this code being executed?
7. **Overall Summary**: A concise overview of the module's role.

**Breakdown of the Code:**

* **Imports**:  Standard Python libraries (os, re, subprocess, etc.) and modules from the Meson build system (`arglist`, `mesonlib`, `linkers`, `compilers`). This suggests it's part of the build process for C/C++-like languages.
* **Mixin Classes**: The code defines mixin classes, designed to be inherited by other classes. This indicates a pattern for sharing functionality across different compiler types.
* **`CLikeCompilerArgs`**:  Deals with compiler arguments, including handling prefixes, deduplication, and converting to native command-line arguments. It seems involved in managing the flags passed to the compiler.
* **`CLikeCompiler`**: Contains methods for common C/C++ compiler operations:
    * **Compilation**: `compiler_args`, `needs_static_linker`, `get_always_args`, `get_no_stdinc_args`, etc. -  Managing compiler flags and settings.
    * **Dependency Handling**:  Potentially involved in how libraries and headers are located and linked.
    * **Sanity Checks**:  `sanity_check` - Verifying the compiler is working correctly.
    * **Feature Detection**: `check_header`, `has_header`, `has_header_symbol` -  Determining if certain headers or symbols exist.
    * **Type Information**: `sizeof`, `alignment` - Getting the size and alignment of data types.
    * **Macro Expansion**: `get_define` - Retrieving the value of preprocessor macros.
    * **Function Calls**: `get_return_value` - Executing simple programs to get function return values.
    * **Cross-Compilation**: Includes logic for handling cross-compilation scenarios.

**Thinking about the questions:**

* **Reverse Engineering**: Feature detection (header/symbol checks) could be indirectly relevant for understanding the target environment during reverse engineering. Accessing macro definitions could also provide insights.
* **Binary/Kernel/Framework**:  The code interacts with the compiler and linker, which directly operate on binary files. The logic for finding libraries and handling system include paths touches upon OS-level concepts.
* **Logical Inference**: The `cross_compute_int` function uses binary search via compilation checks to infer integer values, which is a form of logical deduction.
* **User Errors**: Incorrect paths, missing dependencies, or misconfigured compiler settings could lead to issues.
* **User Path**: A user building a project that includes C/C++ code with Meson would trigger this code. Feature checks or dependency resolution during the configuration stage would likely lead to its execution.

**Drafting the summary:**

This file defines mixin classes that provide common functionality for C-like compilers within the Frida's Meson build system. It handles compiler argument construction, dependency management, and performs various checks related to the compiler's capabilities and the target environment.
这是Frida动态 instrumentation tool的源代码文件 `frida/releng/meson/mesonbuild/compilers/mixins/clike.py` 的一部分。这个文件的主要功能是定义了一组 **mixin 类**，用于在 C 和 C++ 编译器之间共享通用功能。这些 mixin 类不是独立的，而是通过继承被其他编译器类使用，以避免复杂的菱形继承问题。

以下是该文件功能的详细归纳：

**核心功能：**

1. **编译器参数处理 (`CLikeCompilerArgs`)：**
   - 负责处理和构建传递给 C/C++ 编译器的命令行参数。
   - 提供了添加、删除和整理参数的方法，例如：
     - `prepend_prefixes`:  指定需要添加前缀的参数 (如 `-I`, `-L`)。
     - `dedup2_prefixes`:  指定需要去重的参数前缀 (如 `-I`, `-isystem`, `-L`, `-D`, `-U`)。
     - `dedup1_prefixes`/`dedup1_suffixes`/`dedup1_args`:  用于更复杂的参数去重逻辑，处理例如库文件 (`-l`) 和特定编译选项。
   - `to_native()` 方法将内部的参数表示转换为编译器可执行的本地命令行格式。
   - 实现了针对 GNU-like 链接器 (`GnuLikeDynamicLinkerMixin`) 的特殊处理，在静态库循环依赖的情况下添加 `-Wl,--start-group` 和 `-Wl,--end-group` 参数。
   - 可以移除通过 `-isystem` 添加的默认系统包含路径。

2. **C-like 编译器通用功能 (`CLikeCompiler`)：**
   - 提供了一系列方法，用于执行与 C/C++ 编译相关的通用操作。
   - **编译控制：**
     - `get_always_args()`: 获取所有 C 编译器都需要的默认参数。
     - `get_no_stdinc_args()`/`get_no_stdlib_link_args()`: 获取排除标准库的参数。
     - `get_warn_args()`: 获取不同警告级别的参数。
     - `get_depfile_suffix()`: 获取依赖文件后缀名。
     - `get_preprocess_only_args()`/`get_compile_only_args()`: 获取预处理或编译的参数。
     - `get_no_optimization_args()`: 获取禁用优化的参数。
     - `get_output_args()`: 获取指定输出文件名的参数。
     - `get_werror_args()`: 获取将警告视为错误的参数。
     - `get_include_args()`: 获取添加包含路径的参数 (`-I` 或 `-isystem`)。
     - `get_pic_args()`: 获取生成位置无关代码的参数 (`-fPIC`)。
     - `get_pch_use_args()`/`get_pch_name()`: 获取预编译头文件的相关参数。
   - **库和链接：**
     - `needs_static_linker()`: 指示是否需要静态链接器。
     - `get_library_dirs()`/`get_program_dirs()`: 获取库文件和程序文件的搜索路径。
     - `gen_export_dynamic_link_args()`/`gen_import_library_args()`:  生成导出动态符号和导入库的链接参数。
   - **编译器检查和探测：**
     - `sanity_check()`: 执行基本的编译器健全性检查，确保编译器可以编译和运行简单的程序。
     - `check_header()`/`has_header()`/`has_header_symbol()`:  检查头文件是否存在，或者头文件中是否定义了特定的符号。
     - `compute_int()`/`cross_compute_int()`:  通过编译和运行代码来计算表达式的整数值，支持交叉编译。
     - `sizeof()`/`cross_sizeof()`:  获取数据类型的大小，支持交叉编译。
     - `alignment()`/`cross_alignment()`: 获取数据类型的内存对齐方式，支持交叉编译。
     - `get_define()`: 获取宏定义的值。
     - `get_return_value()`:  编译并运行代码以获取函数的返回值。
   - **参数构建和管理：**
     - `compiler_args()`: 创建 `CLikeCompilerArgs` 实例。
     - `build_wrapper_args()`: 构建包含所有必要编译参数的列表，包括依赖项的参数。
   - **内部缓存：** 使用 `functools.lru_cache` 缓存 `find_library_cache` 和 `find_framework_cache`，避免重复查找库文件和框架。

**与逆向方法的关系：**

这个文件本身不是直接用于逆向的工具，但它提供的编译器功能和检查机制在逆向工程中有间接的应用：

* **环境探测：** `check_header`, `has_header`, `has_header_symbol`, `get_define` 等方法可以用来探测目标系统或库的特性，例如是否存在特定的头文件、宏定义或函数。这对于理解目标环境非常重要，尤其是在进行动态分析或编写与目标程序交互的代码时。
    * **举例：** 在逆向一个 Linux 应用程序时，可以使用 `has_header("sys/socket.h", "")` 来检查是否存在 socket 相关的头文件，从而判断程序是否使用了网络功能。
* **数据结构分析：** `sizeof` 和 `alignment` 方法可以帮助了解目标程序中使用的数据结构的大小和内存布局。这对于理解程序的数据组织方式和进行内存分析很有用。
    * **举例：**  可以使用 `sizeof("struct sockaddr_in", "")` 来获取 socket 地址结构体的大小，这在分析网络通信协议时非常重要。
* **理解编译选项的影响：**  通过分析 `CLikeCompilerArgs` 如何处理编译器参数，可以理解不同的编译选项如何影响最终生成的可执行文件。这对于理解目标程序的构建过程和潜在的安全漏洞很有帮助。

**涉及到的二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层：** 编译器的核心任务是将源代码转换为机器码（二进制指令）。这个文件中的功能，例如处理链接器参数、生成位置无关代码 (`-fPIC`)，都直接关系到二进制文件的生成和加载。
* **Linux：** 很多默认的编译器行为和参数（如 `-l`, `-I`, 动态链接库的查找路径）都与 Linux 系统约定有关。例如，`get_library_dirs` 方法需要知道在 Linux 系统中常见的库文件路径。
* **Android 内核及框架：** 虽然代码本身没有直接提到 Android，但如果 Frida 用于 instrument Android 应用程序，那么这个文件所提供的编译器功能就需要能够处理 Android NDK 编译环境的特性，例如交叉编译到 ARM 架构，以及处理 Android 特有的系统库和框架。
* **动态链接：** 代码中对动态链接器的处理（例如 `GnuLikeDynamicLinkerMixin`）以及生成导出/导入动态符号的参数，都涉及到动态链接的底层机制。

**逻辑推理举例：**

* **假设输入：** `cross_compute_int("sizeof(int) * 2", None, None, 4, "", env)`，其中 `env` 是一个交叉编译环境，并且我们猜测 `sizeof(int)` 是 4。
* **输出：**  如果编译器可以成功编译并执行测试代码，并且测试结果表明 `sizeof(int) * 2` 的值确实是 8，那么 `cross_compute_int` 将返回 8。这个过程中，它可能会先尝试用户提供的猜测值 4，如果验证失败，则会通过一系列编译检查进行二分查找，最终推断出正确的结果。

**涉及用户或者编程常见的使用错误举例：**

* **错误的包含路径：** 用户在配置编译环境时，如果设置了错误的包含路径，可能会导致 `check_header` 或 `has_header` 误判头文件不存在。
    * **举例：**  用户在设置头文件搜索路径时，将 `-I/usr/local/include` 错误地写成 `-Iusr/local/include`，会导致编译器找不到本应存在的头文件。
* **依赖项缺失：**  如果用户尝试编译依赖于某个库的代码，但该库的开发文件（头文件和静态/动态库）没有安装或路径未正确配置，则编译过程会失败，相关的编译器检查也会出错。
    * **举例：**  如果代码中使用了 `openssl/ssl.h`，但系统上没有安装 `libssl-dev` 或类似的开发包，`has_header("openssl/ssl.h", "")` 将返回 `False`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试使用 Frida instrument 一个 C/C++ 编写的目标程序。**
2. **Frida 的内部机制（基于 Meson 构建系统）需要确定目标程序的编译环境和特性。**
3. **在 Meson 构建过程中，会调用相应的编译器类来处理 C/C++ 代码的编译任务。**
4. **为了实现通用的编译器处理逻辑，Meson 使用了 mixin 类，`CLikeCompiler` 就是其中之一。**
5. **当需要执行一些通用的 C/C++ 编译器操作，例如检查头文件是否存在 (`check_header`)，或者获取数据类型的大小 (`sizeof`) 时，就会调用 `frida/releng/meson/mesonbuild/compilers/mixins/clike.py` 中定义的方法。**
6. **例如，如果 Frida 需要确定目标程序是否链接了某个特定的库，它可能会通过编译一个简单的测试程序并检查链接结果来实现，这会涉及到 `CLikeCompilerArgs` 构建链接器参数。**

**归纳一下它的功能：**

总而言之，`frida/releng/meson/mesonbuild/compilers/mixins/clike.py` 提供了 Frida 的 Meson 构建系统中 C 和 C++ 编译器通用的功能抽象和实现，包括编译器参数处理、常用编译操作、环境探测和类型信息获取等，为 Frida 能够正确地编译和 instrument 目标程序提供了基础支持。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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