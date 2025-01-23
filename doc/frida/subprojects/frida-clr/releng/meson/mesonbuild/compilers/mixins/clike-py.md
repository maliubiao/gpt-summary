Response:
The user wants to understand the functionality of the Python code provided. This code seems to be a part of the `frida` dynamic instrumentation tool, specifically related to handling C-like language compilation within the `meson` build system.

Here's a breakdown of how to address the user's request:

1. **Identify Core Functionality:**  The code defines mixin classes (`CLikeCompilerArgs`, `CLikeCompiler`) for C and C++ compilers within the Meson build system. These mixins provide common functionalities for tasks like argument handling, compilation, linking, and checking for features (headers, symbols, sizes, alignments).

2. **Relate to Reverse Engineering:**  Dynamic instrumentation tools like Frida are often used in reverse engineering. The ability to compile and run code snippets on the target system is crucial for tasks like:
    * **Probing Memory:** Compiling small programs to read or write memory at specific addresses.
    * **Function Hooking:**  Potentially using compiled code to modify function behavior.
    * **Data Structure Discovery:**  Using `sizeof` and alignment checks to understand the layout of data structures in the target process.

3. **Connect to Binary, Linux/Android Kernel/Framework:** The code interacts with low-level aspects:
    * **Binary Level:** It deals with compilation and linking, which ultimately produces binary executables or libraries. Concepts like ELF headers (demonstrated in `_get_library_dirs`) are relevant.
    * **Linux/Android Kernel/Framework:** The code includes logic for handling shared libraries (`.so`), dynamic linking (`-l`, `-Wl`), and standard library includes, all fundamental to Linux and Android development. The `get_default_include_dirs()` and `get_library_dirs()` methods are indicative of this.

4. **Identify Logical Reasoning:** Several methods involve logical checks and assumptions:
    * **Sanity Check:** Assumes that if a simple program compiles and runs, the compiler is generally functional.
    * **Header/Symbol Checks:** Assumes that if the compiler doesn't report an error when including a header or referencing a symbol, the header exists or the symbol is defined.
    * **`compute_int` and `cross_compute_int`:** Use binary search to determine the value of an expression based on compilation success or failure.

5. **Consider User/Programming Errors:**  The code implicitly handles potential errors:
    * **Incorrect Paths:**  The `get_include_args` handles empty paths.
    * **Compiler Issues:** The `sanity_check` explicitly raises an exception if the compiler fails.
    * **Invalid Input for `compute_int`:**  The code checks for `high < low`.

6. **Trace User Actions (Debugging):** To reach this code, a Frida user would likely be:
    * **Developing a Frida script:** This script might involve inspecting or modifying the behavior of a target application.
    * **Using Frida's API to interact with the target:** This interaction could trigger the need to compile small code snippets on the target.
    * **The Meson build system would be involved in building Frida itself.** When building Frida, this code would be used to determine the capabilities of the compiler on the build system.

7. **Summarize Functionality:** Concisely describe the purpose of the code based on the above points.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus too much on specific function implementations.
* **Correction:**  Shift focus to the broader purpose and how the different parts contribute to that purpose. Emphasize the "mixin" nature and the shared functionalities.
* **Initial thought:**  Overlook the connection to the `meson` build system.
* **Correction:**  Explicitly mention the role of `meson` and how this code integrates with it for compiler handling.
* **Initial thought:**  Not clearly distinguish between compile-time (Frida build) and runtime (Frida script execution on a target) scenarios.
* **Correction:** Clarify that this code is primarily used during the build process of Frida itself, to test the capabilities of the compiler. The reverse engineering examples are potential uses of *Frida* that are enabled by the underlying compilation capabilities.
这是 `frida` 动态instrumentation 工具中 `frida-clr` 子项目关于 C 语言系列（C/C++）编译器的 `meson` 构建系统的一部分代码。它定义了一些用于处理 C 风格编译器的混合类（mixin classes），目的是在 C 和 C++ 编译器之间共享通用功能，避免复杂的继承关系。

**功能归纳:**

1. **编译器参数处理 (`CLikeCompilerArgs`):**
   - 定义了用于处理命令行编译器参数的类，继承自 `arglist.CompilerArgs`。
   - 包含了添加前缀、去重等处理逻辑，例如 `-I`（包含目录）、`-L`（库目录）、`-l`（链接库）。
   - 针对静态库循环依赖问题，实现了自动添加 `-Wl,--start-group` 和 `-Wl,--end-group` 参数的逻辑，这在链接静态库时非常重要。
   - 提供了去除系统默认包含路径的功能，避免在编译时引入不必要的系统头文件。
   - `to_native()` 方法将内部的参数列表转换为编译器可以识别的原生格式。

2. **C 风格编译器通用功能 (`CLikeCompiler`):**
   - 定义了 C 和 C++ 编译器共享的通用方法，继承自 `compilers.Compiler`。
   - 维护了可以编译的文件后缀列表 (`can_compile_suffixes`)，默认包含 `.h` 头文件。
   - 提供了创建编译器参数对象的方法 (`compiler_args`)。
   - 声明了需要静态链接器 (`needs_static_linker`)，因为编译静态库需要。
   - 定义了获取常用编译器参数的方法，例如：
     - `get_always_args()`: 始终启用的参数，例如处理大文件的参数。
     - `get_no_stdinc_args()`: 禁用标准库包含路径的参数 (`-nostdinc`)。
     - `get_no_stdlib_link_args()`: 禁用标准库链接的参数 (`-nostdlib`)。
     - `get_warn_args()`: 获取不同警告级别的参数。
     - `get_depfile_suffix()`: 获取依赖文件后缀 (`d`)。
     - `get_preprocess_only_args()`: 预处理的参数 (`-E`, `-P`)。
     - `get_compile_only_args()`: 仅编译的参数 (`-c`)。
     - `get_no_optimization_args()`: 禁用优化的参数 (`-O0`)。
     - `get_output_args()`: 指定输出文件名的参数 (`-o`)。
     - `get_werror_args()`: 将警告视为错误的参数 (`-Werror`)。
     - `get_include_args()`: 生成包含目录参数 (`-I`, `-isystem`)。
     - `get_pic_args()`: 生成位置无关代码的参数 (`-fPIC`)。
     - `get_pch_use_args()`: 使用预编译头的参数 (`-include`)。
     - `get_pch_name()`: 获取预编译头的文件名。
     - `get_default_include_dirs()`: 获取默认的包含目录。
     - `gen_export_dynamic_link_args()`: 生成导出动态链接符号的参数。
     - `gen_import_library_args()`: 生成导入库的参数。
   - 提供了获取编译器库目录 (`get_library_dirs`) 和程序目录 (`get_program_dirs`) 的方法，并使用 `lru_cache` 进行缓存。
   - 实现了编译器基本功能检查 (`sanity_check`)，通过编译并运行一个简单的程序来验证编译器是否正常工作。
   - 提供了检查头文件是否存在 (`check_header`, `has_header`) 和头文件是否包含特定符号 (`has_header_symbol`) 的方法。
   - `_get_basic_compiler_args()` 方法获取基本的编译和链接参数，包括从环境变量中读取的参数。
   - `build_wrapper_args()` 方法根据依赖关系构建完整的编译器参数列表。
   - 提供了跨平台计算整型表达式 (`cross_compute_int`) 和本地计算整型表达式 (`compute_int`) 的方法，用于在构建时确定一些常量值。
   - 提供了获取类型大小 (`sizeof`) 和对齐方式 (`alignment`) 的方法。
   - 提供了获取宏定义值 (`get_define`) 的方法，通过预处理获取宏的值。
   - 提供了获取函数返回值 (`get_return_value`) 的方法，用于在构建时获取一些函数的返回值。
   - 提供了检查函数是否存在但没有原型声明的方法 (`_no_prototype_templ`)。

**与逆向方法的关系及举例说明:**

这些功能与逆向工程密切相关，因为动态 instrumentation 工具如 `frida` 经常需要在目标进程中注入代码或探测其状态。编译功能是实现这些目标的基础。

* **动态代码生成和注入:**  `frida` 可能会在运行时生成一些 C/C++ 代码片段，例如用于 hook 函数或读取内存，然后需要将这些代码编译成目标进程可以执行的形式。这个文件中的功能就负责处理编译参数的生成和执行编译过程。
* **探测内存布局和数据结构:** `sizeof` 和 `alignment` 方法在逆向工程中非常有用。通过在目标环境中编译包含特定数据结构的简单程序，可以确定这些数据结构的大小和成员对齐方式。例如，假设你想知道目标进程中一个名为 `MyStruct` 的结构体的大小：
  ```python
  # 假设在 Frida 脚本中可以访问编译器对象
  size, cached = compiler.sizeof("MyStruct", "", env)
  print(f"MyStruct 的大小为: {size} 字节")
  ```
* **检查目标环境的特性:** `check_header` 和 `has_header_symbol` 可以用来探测目标环境中是否存在特定的头文件或符号。例如，你可以检查目标进程的 libc 版本是否支持某个特定的函数：
  ```python
  has_symbol, _ = compiler.has_header_symbol("stdio.h", "printf_chk", "", env)
  if has_symbol:
      print("目标环境支持 printf_chk 函数")
  else:
      print("目标环境不支持 printf_chk 函数")
  ```
* **动态调用目标进程的函数:**  虽然这个文件本身不直接处理函数调用，但编译能力是动态调用目标进程函数的前提。你需要能够编译包装代码来调用目标函数。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **链接器参数 (`-l`, `-Wl`):**  代码中处理链接库的参数直接涉及到二进制文件的链接过程。`-l` 指定要链接的库，`-Wl` 将参数传递给链接器。
    * **静态库分组 (`-Wl,--start-group`, `-Wl,--end-group`):**  这部分代码是为了解决静态库之间的循环依赖问题，是链接器层面的概念。
    * **位置无关代码 (`-fPIC`):**  在构建共享库或进行动态代码注入时，需要生成位置无关的代码，以便加载到内存的任意位置。
    * **ELF 文件格式:**  `_get_library_dirs` 方法中检查库文件的 ELF 头信息，判断库文件的架构 (32位或64位)。
* **Linux:**
    * **共享库后缀 (`.so`):** 代码中硬编码了共享库的后缀 `.so`。
    * **动态链接器:** 代码中涉及到 `GnuLikeDynamicLinkerMixin` 和 `SolarisDynamicLinker`，这些都是 Linux 和 Solaris 系统上的动态链接器。
    * **标准库包含路径:** `get_no_stdinc_args` 和去除默认包含路径的功能与 Linux 系统中标准库的组织方式有关。
* **Android 内核及框架:**
    * 尽管代码本身没有明确提到 Android，但动态 instrumentation 技术广泛应用于 Android 逆向和安全分析。`frida` 也支持 Android 平台。因此，这里的功能可以用于在 Android 环境中编译和运行代码片段，例如用于 hook Android framework 的函数。
    * Android 系统也使用 Linux 内核，因此上述关于 Linux 的知识也适用。

**逻辑推理及假设输入与输出:**

* **静态库分组逻辑:**
    * **假设输入:**  一个包含多个静态库依赖的链接命令，例如 `liba.a libb.a libc.a`，其中 `liba` 依赖 `libb`，`libb` 依赖 `libc`，`libc` 又可能依赖 `liba`。
    * **逻辑:** 代码会遍历链接参数，找到所有的 `.a` 文件（静态库），然后在第一个静态库前添加 `-Wl,--start-group`，在最后一个静态库后添加 `-Wl,--end-group`。
    * **输出:** 修改后的链接命令类似 `-Wl,--start-group liba.a libb.a libc.a -Wl,--end-group`。
* **去除默认包含路径逻辑:**
    * **假设输入:**  编译器参数列表包含 `-isystem /usr/include`，而 `/usr/include` 是编译器的默认包含路径。
    * **逻辑:** 代码会获取编译器的默认包含路径，然后遍历参数列表，如果发现 `-isystem` 后面的路径是默认路径，则将其移除。
    * **输出:**  参数列表中的 `-isystem /usr/include` 被移除。

**涉及用户或编程常见的使用错误及举例说明:**

* **未正确设置包含路径或库路径:** 用户在编写 Frida 脚本时，如果需要编译依赖外部库的代码，但没有正确设置包含路径 (`-I`) 或库路径 (`-L`)，会导致编译失败。这个文件中的代码虽然不直接处理用户的输入，但它生成的编译器参数是用户配置的基础。
* **循环依赖的静态库链接问题:**  用户可能遇到静态库之间的循环依赖导致链接错误。这个文件中的自动添加分组参数的逻辑可以缓解这个问题，但用户仍然需要确保库的依赖关系是合理的。
* **交叉编译环境配置错误:**  在进行交叉编译时，如果用户配置的编译器路径或 sysroot 不正确，`sanity_check` 等功能会失败，提示用户环境配置有问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户安装或构建 Frida:**  当用户安装 Frida 或从源代码构建 Frida 时，`meson` 构建系统会执行。
2. **Meson 配置编译器:**  在配置阶段，`meson` 会检测系统中的 C 和 C++ 编译器，并使用此文件中的代码来生成编译和链接命令，执行编译器的基本功能检查 (`sanity_check`)，并获取编译器的默认设置和特性。
3. **Frida 脚本开发（间接影响）:**  虽然用户编写 Frida 脚本不会直接触发这个文件中的代码，但这个文件确保了 Frida 能够找到并正确使用系统中的编译器。当 Frida 脚本需要动态编译代码时，之前配置好的编译器信息会被使用。
4. **Frida CLR 子项目构建:**  如果用户正在使用或构建 `frida-clr` 子项目，那么 `meson` 会处理 `frida-clr` 的构建，这个文件中的代码就会被用于处理 C 语言相关的编译任务。
5. **调试 Frida 构建过程:**  如果 Frida 的构建过程出现与编译器相关的问题，开发者可能会查看 `meson` 的构建日志，其中会包含由这个文件生成的编译器命令，从而定位问题。

**总结:**

`frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件的主要功能是为 `frida` 项目中处理 C 和 C++ 编译器的部分提供通用的构建逻辑。它负责生成和处理编译器参数，进行编译器的基础功能检查，并提供了一些用于探测目标环境特性的方法。这些功能对于 `frida` 动态代码生成、内存探测以及与目标进程交互等核心能力至关重要。该代码深入到二进制链接、操作系统特性以及编译原理等底层知识。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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