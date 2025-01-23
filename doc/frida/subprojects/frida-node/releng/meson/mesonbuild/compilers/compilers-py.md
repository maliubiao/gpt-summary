Response:
The user wants a summary of the functionality of the provided Python code, which is part of the Frida dynamic instrumentation tool. The code defines a `Compiler` class and related helper functions and data structures for managing different compilers Meson can use.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The file is named `compilers.py` and resides within a directory related to build systems (`meson`). The comments at the beginning explicitly state that it contains data files for compilers known to Meson. This immediately suggests the central theme is managing and interacting with compilers.

2. **Analyze top-level definitions:** Look at the global variables and top-level functions.
    * `header_suffixes`, `obj_suffixes`, `lib_suffixes`, `lang_suffixes`, `all_languages`, etc.: These define sets and mappings related to file types and programming languages. This points to functionality for identifying and classifying source code, object files, and libraries.
    * `is_header`, `is_source`, `is_assembly`, `is_object`, `is_library`, `is_known_suffix`: These functions perform checks on file names to determine their type based on their suffixes. This confirms the file classification aspect.
    * `CompileCheckMode`: This enum suggests different stages of compilation that the system can handle.
    * `gnu_winlibs`, `msvc_winlibs`, `clike_optimization_args`, `clike_debug_args`, `MSCRT_VALS`: These are data structures containing compiler-specific or general compilation flags and settings. This indicates functionality for configuring the compilation process.
    * `BaseOption`, `BASE_OPTIONS`, `base_options`, `option_enabled`, `get_option_value`, `are_asserts_disabled`, `get_base_compile_args`, `get_base_link_args`: These are related to build options and how they are translated into compiler arguments. This confirms the compilation configuration aspect.
    * `CrossNoRunException`, `RunResult`, `CompileResult`: These classes define the results of executing code and compilation. This points to functionality for running and checking compilation results.
    * `Compiler` class: This is the most significant part. Its methods (even without going into detail yet) clearly relate to compiler operations: `can_compile`, `get_id`, `get_version_string`, `get_language`, `get_output_args`, `get_linker_output_args`, `check_header`, `has_header`, `run`, `sizeof`, `alignment`, `has_function`, `find_library`, `get_library_naming`, `has_multi_arguments`, `has_multi_link_arguments`.

3. **Focus on the `Compiler` class:**  This class is the core abstraction. Its methods represent different compiler actions.
    * **Information Retrieval:** Methods like `get_id`, `get_version_string`, `get_language`, `get_default_suffix` provide information about the compiler.
    * **Compilation and Linking:**  Methods like `get_output_args`, `get_linker_output_args`, `get_always_args`, `get_linker_always_args` deal with constructing command-line arguments for compilation and linking.
    * **Feature Detection:**  Methods like `check_header`, `has_header`, `has_header_symbol`, `has_function`, `sizeof`, `alignment`, `has_members`, `has_type`, `get_define`, `compute_int` are about probing the compiler and target environment for specific features and properties.
    * **Execution:** The `run` and `cached_run` methods handle the execution of compiled code.
    * **Library Handling:** `find_library`, `get_library_naming`, `gen_import_library_args` relate to managing libraries during the linking process.
    * **Option Handling:** `create_option`, `update_options`, `get_options`, `get_option_compile_args`, `get_option_link_args` manage compiler-specific and general build options.
    * **Argument Conversion:** `unix_args_to_native`, `native_args_to_unix` suggest handling differences in argument formats between different systems.

4. **Categorize the functionality:** Based on the analysis, group the functionalities into logical categories. Good categories would be:
    * Compiler Information
    * Compilation and Linking Argument Generation
    * Feature and Property Detection
    * Code Execution
    * Library Management
    * Option Handling
    * Argument Conversion

5. **Summarize each category:** Briefly describe what each category of functionality does. Use clear and concise language.

6. **Review and refine:**  Read through the summary to ensure accuracy, completeness, and clarity. Make sure the language is appropriate and avoid jargon where possible. For instance, initially I might have just listed all the methods, but grouping them by purpose makes the summary much more understandable. Also, emphasizing that this is about *managing* and *abstracting* interaction with compilers is important.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py` 这个文件的功能。

**文件核心功能归纳:**

这个 Python 文件定义了 Meson 构建系统用于处理各种编程语言编译器的抽象和数据结构。 它的主要功能是：

1. **编译器信息存储和管理:**  它包含了 Meson 已知的各种编译器的信息，例如支持的语言、文件后缀、以及用于编译和链接的命令行参数。这使得 Meson 能够识别不同的编译器并以正确的方式调用它们。
2. **文件类型识别:** 它定义了各种文件后缀名（如 `.c`, `.cpp`, `.h`, `.so`, `.dll` 等）以及用于判断文件类型（头文件、源文件、目标文件、库文件等）的函数。
3. **编译和链接参数生成:** 它定义了用于生成编译器和链接器命令行参数的逻辑，包括：
    *  通用的编译选项 (如优化级别、调试信息、代码静态检查等)。
    *  链接选项 (如库文件路径、链接时优化等)。
    *  特定于不同编译器的参数。
4. **编译环境检查:** 它提供了一些方法来检查编译环境的特性，例如：
    *  检查头文件是否存在或可用。
    *  检查头文件中是否存在特定的符号。
    *  检查函数是否存在。
    *  获取类型或成员的大小和对齐方式。
    *  检查编译器是否支持特定的编译或链接参数。
5. **代码执行:** 它包含运行编译后的代码的逻辑，用于测试编译结果或获取运行时的信息。
6. **构建选项管理:** 它定义了与编译相关的构建选项，并提供了启用或禁用这些选项的方法。
7. **跨平台处理:**  它考虑了不同操作系统（如 Windows）下库文件的命名约定和链接方式。

**与逆向方法的关联及举例说明:**

这个文件本身不是直接进行逆向操作的工具，但它为像 Frida 这样的动态插桩工具的构建过程提供了基础，而 Frida 是一个重要的逆向工具。

* **二进制文件分析基础:**  理解目标文件的结构（例如，通过识别 `.o` 或 `.obj` 文件）是逆向工程的第一步。这个文件中的 `obj_suffixes` 可以帮助识别目标文件。
* **动态库/共享对象处理:** 逆向工程经常需要处理动态链接库 (`.so`, `.dll`, `.dylib`)。`lib_suffixes` 变量定义了这些文件类型。
* **符号查找和函数调用:**  逆向分析常常需要定位和理解二进制代码中的函数。这个文件中的 `has_function` 方法模拟了构建系统如何检查链接时是否存在特定的函数符号。这反映了链接器在最终生成可执行文件时所做的操作。
* **编译器特性理解:** 不同的编译器可能生成不同的机器码或有不同的行为。理解目标程序是用哪个编译器编译的，以及编译时使用了哪些选项，对于逆向分析至关重要。这个文件记录了各种编译器的特性和默认行为。
* **运行时环境模拟:**  `run` 方法展示了构建系统如何执行编译后的代码。在某些逆向场景中，需要在一个受控的环境中执行目标程序来观察其行为，这与这里的代码有相似之处。

**例举说明:** 假设 Frida 需要检测目标进程中是否存在某个特定的库（例如 `libssl`）。Meson 构建系统可以使用 `find_library` 方法来查找这个库，而 `lib_suffixes` 变量会告诉 `find_library` 要查找哪些文件后缀。 这与逆向工程师在分析目标进程时，需要识别其加载的动态库是类似的。

**涉及二进制底层、Linux、Android 内核及框架知识的举例说明:**

* **二进制底层:**
    * **目标文件格式:** `obj_suffixes` 对应的是不同操作系统下的目标文件格式，例如 Linux 的 `.o` 和 Windows 的 `.obj`。理解这些格式是进行底层分析的基础。
    * **共享库/动态库:** `lib_suffixes` 中列出的 `.so` (Linux), `.dll` (Windows), `.dylib` (macOS) 是操作系统加载和链接二进制代码的核心概念。
    * **链接器行为:** 文件中关于链接器参数 (例如 `b_lundef`, `b_asneeded`) 的处理反映了链接器在解析符号引用和生成最终二进制文件时的行为。
* **Linux 内核:**
    * **共享对象 (`.so`) 的加载和链接:**  Linux 内核负责加载和链接共享对象到进程的地址空间。这个文件对 `.so` 文件的处理体现了对这一过程的理解。
    * **位置无关代码 (PIC/PIE):**  `b_staticpic` 和 `b_pie` 选项涉及到生成位置无关的代码，这在共享库和现代 Linux 发行版的可执行文件中是很重要的安全特性。
* **Android 框架:** 虽然这个文件本身不直接涉及 Android 框架的细节，但理解 Android 系统中使用的共享库 (通常也是 `.so` 文件) 以及编译过程，有助于理解 Frida 如何在 Android 环境中工作。Frida 需要编译一些组件以注入到 Android 进程中，而这个文件中的编译器信息对于构建这些组件至关重要。

**逻辑推理的假设输入与输出:**

假设有一个名为 `test.c` 的 C 语言源文件。

**假设输入:**

* 文件名: `test.c`
* 编译器语言: `c`
* 目标平台: Linux

**逻辑推理过程:**

1. **`is_source('test.c')`:** 根据 `lang_suffixes` 的定义，`.c` 是 `c` 语言的后缀，所以输出为 `True`。
2. **选择 C 编译器:** Meson 会根据语言选择合适的编译器。
3. **`get_output_args('output')` (对于 C 编译器):** C 编译器会将输入文件编译成目标文件，然后链接成可执行文件。输出参数会包含 `-o output`，指示输出文件的名称。
4. **如果启用了 LTO (链接时优化):**  `get_lto_link_args()` 方法会根据 `b_lto_mode` 的设置，添加相应的链接器参数，例如 `-flto=thin`。

**假设输出:**

* `is_source('test.c')` 输出: `True`
* `get_output_args('output')` 输出 (例如): `['-o', 'output']`
* `get_lto_link_args()` 输出 (如果 `b_lto_mode` 为 'thin'): `['-flto=thin']`

**用户或编程常见的使用错误举例说明:**

* **文件后缀名错误:** 如果用户将 C++ 源文件命名为 `file.c`，`is_source('file.c')` 会返回 `True`，但如果编译器被强制认为是 C 编译器，可能会导致编译错误，因为 C 编译器可能无法理解 C++ 的语法。
* **链接库文件时路径错误:**  用户可能在 `meson.build` 文件中指定了错误的库文件路径。虽然 `find_library` 可能会找到该文件，但如果该文件不是一个有效的库文件，或者它的依赖项不满足，链接过程仍然会失败。这个文件中的逻辑并不能完全避免这种错误，但它提供了一种机制来查找潜在的库文件。
* **构建选项冲突:** 用户可能同时启用了不兼容的构建选项，例如同时启用 `-O3` 和某些调试选项。这个文件定义了各种构建选项，但 Meson 需要在更高的层次上处理这些选项之间的冲突。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户运行 `meson setup builddir` 或 `ninja` 命令:**  当用户启动 Meson 构建过程时，Meson 首先会读取 `meson.build` 文件，了解项目的构建需求。
2. **Meson 解析 `meson.build` 文件:** Meson 会分析 `meson.build` 文件中定义的源文件、依赖项、构建选项等信息。
3. **Meson 识别编译器:**  Meson 会根据项目中使用的编程语言，调用相应的编译器检测逻辑（在 `detect.py` 中），并根据系统环境选择合适的编译器。
4. **加载编译器信息:**  一旦确定了使用的编译器，Meson 就会加载 `compilers.py` 中该编译器的相关信息。
5. **生成编译和链接命令:**  在编译或链接源文件时，Meson 会调用 `compilers.py` 中定义的各种方法（例如 `get_output_args`, `get_always_args`, `get_option_compile_args`）来生成实际的编译器和链接器命令行。
6. **执行编译和链接命令:** Meson 使用生成的命令调用编译器和链接器。

**作为调试线索:** 如果构建过程中出现与编译器或链接器相关的错误，例如找不到编译器、链接时出现符号未定义等，开发者可以检查：

* **`meson_log.txt` 文件:**  Meson 会将详细的构建日志记录到 `meson_log.txt` 文件中，包括实际执行的编译器和链接器命令。检查这些命令可以帮助理解 Meson 是如何调用编译器的，以及传递了哪些参数。
* **`meson.build` 文件:**  检查 `meson.build` 文件中是否正确指定了源文件、依赖项和构建选项。
* **编译器路径和环境变量:**  确保系统中安装了所需的编译器，并且相关的环境变量设置正确。
* **`compilers.py` 文件 (高级调试):**  在极少数情况下，如果怀疑 Meson 对特定编译器的处理有问题，可以检查 `compilers.py` 文件中该编译器的定义，查看其默认参数和行为是否符合预期。

希望以上分析能够帮助你理解 `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py` 文件的功能。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright 2012-2022 The Meson development team
# Copyright © 2023 Intel Corporation

from __future__ import annotations

import abc
import contextlib, os.path, re
import enum
import itertools
import typing as T
from dataclasses import dataclass
from functools import lru_cache

from .. import coredata
from .. import mlog
from .. import mesonlib
from ..mesonlib import (
    HoldableObject,
    EnvironmentException, MesonException,
    Popen_safe_logged, LibType, TemporaryDirectoryWinProof, OptionKey,
)

from ..arglist import CompilerArgs

if T.TYPE_CHECKING:
    from ..build import BuildTarget, DFeatures
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers import RSPFileSyntax
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice
    from ..dependencies import Dependency

    CompilerType = T.TypeVar('CompilerType', bound='Compiler')
    _T = T.TypeVar('_T')
    UserOptionType = T.TypeVar('UserOptionType', bound=coredata.UserOption)

"""This file contains the data files of all compilers Meson knows
about. To support a new compiler, add its information below.
Also add corresponding autodetection code in detect.py."""

header_suffixes = {'h', 'hh', 'hpp', 'hxx', 'H', 'ipp', 'moc', 'vapi', 'di'}
obj_suffixes = {'o', 'obj', 'res'}
# To the emscripten compiler, .js files are libraries
lib_suffixes = {'a', 'lib', 'dll', 'dll.a', 'dylib', 'so', 'js'}
# Mapping of language to suffixes of files that should always be in that language
# This means we can't include .h headers here since they could be C, C++, ObjC, etc.
# First suffix is the language's default.
lang_suffixes = {
    'c': ('c',),
    'cpp': ('cpp', 'cc', 'cxx', 'c++', 'hh', 'hpp', 'ipp', 'hxx', 'ino', 'ixx', 'C', 'H'),
    'cuda': ('cu',),
    # f90, f95, f03, f08 are for free-form fortran ('f90' recommended)
    # f, for, ftn, fpp are for fixed-form fortran ('f' or 'for' recommended)
    'fortran': ('f90', 'f95', 'f03', 'f08', 'f', 'for', 'ftn', 'fpp'),
    'd': ('d', 'di'),
    'objc': ('m',),
    'objcpp': ('mm',),
    'rust': ('rs',),
    'vala': ('vala', 'vapi', 'gs'),
    'cs': ('cs',),
    'swift': ('swift',),
    'java': ('java',),
    'cython': ('pyx', ),
    'nasm': ('asm',),
    'masm': ('masm',),
}
all_languages = lang_suffixes.keys()
c_cpp_suffixes = {'h'}
cpp_suffixes = set(lang_suffixes['cpp']) | c_cpp_suffixes
c_suffixes = set(lang_suffixes['c']) | c_cpp_suffixes
assembler_suffixes = {'s', 'S', 'sx', 'asm', 'masm'}
llvm_ir_suffixes = {'ll'}
all_suffixes = set(itertools.chain(*lang_suffixes.values(), assembler_suffixes, llvm_ir_suffixes, c_cpp_suffixes))
source_suffixes = all_suffixes - header_suffixes
# List of languages that by default consume and output libraries following the
# C ABI; these can generally be used interchangeably
# This must be sorted, see sort_clink().
clib_langs = ('objcpp', 'cpp', 'objc', 'c', 'nasm', 'fortran')
# List of languages that can be linked with C code directly by the linker
# used in build.py:process_compilers() and build.py:get_dynamic_linker()
# This must be sorted, see sort_clink().
clink_langs = ('d', 'cuda') + clib_langs

SUFFIX_TO_LANG = dict(itertools.chain(*(
    [(suffix, lang) for suffix in v] for lang, v in lang_suffixes.items())))

# Languages that should use LDFLAGS arguments when linking.
LANGUAGES_USING_LDFLAGS = {'objcpp', 'cpp', 'objc', 'c', 'fortran', 'd', 'cuda'}
# Languages that should use CPPFLAGS arguments when linking.
LANGUAGES_USING_CPPFLAGS = {'c', 'cpp', 'objc', 'objcpp'}
soregex = re.compile(r'.*\.so(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?$')

# Environment variables that each lang uses.
CFLAGS_MAPPING: T.Mapping[str, str] = {
    'c': 'CFLAGS',
    'cpp': 'CXXFLAGS',
    'cuda': 'CUFLAGS',
    'objc': 'OBJCFLAGS',
    'objcpp': 'OBJCXXFLAGS',
    'fortran': 'FFLAGS',
    'd': 'DFLAGS',
    'vala': 'VALAFLAGS',
    'rust': 'RUSTFLAGS',
    'cython': 'CYTHONFLAGS',
    'cs': 'CSFLAGS', # This one might not be standard.
}

# All these are only for C-linkable languages; see `clink_langs` above.

def sort_clink(lang: str) -> int:
    '''
    Sorting function to sort the list of languages according to
    reversed(compilers.clink_langs) and append the unknown langs in the end.
    The purpose is to prefer C over C++ for files that can be compiled by
    both such as assembly, C, etc. Also applies to ObjC, ObjC++, etc.
    '''
    if lang not in clink_langs:
        return 1
    return -clink_langs.index(lang)

def is_header(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in header_suffixes

def is_source_suffix(suffix: str) -> bool:
    return suffix in source_suffixes

def is_source(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1].lower()
    return is_source_suffix(suffix)

def is_assembly(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in assembler_suffixes

def is_llvm_ir(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]
    return suffix in llvm_ir_suffixes

@lru_cache(maxsize=None)
def cached_by_name(fname: 'mesonlib.FileOrString') -> bool:
    suffix = fname.split('.')[-1]
    return suffix in obj_suffixes

def is_object(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    return cached_by_name(fname)

def is_library(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname

    if soregex.match(fname):
        return True

    suffix = fname.split('.')[-1]
    return suffix in lib_suffixes

def is_known_suffix(fname: 'mesonlib.FileOrString') -> bool:
    if isinstance(fname, mesonlib.File):
        fname = fname.fname
    suffix = fname.split('.')[-1]

    return suffix in all_suffixes


class CompileCheckMode(enum.Enum):

    PREPROCESS = 'preprocess'
    COMPILE = 'compile'
    LINK = 'link'


gnu_winlibs = ['-lkernel32', '-luser32', '-lgdi32', '-lwinspool', '-lshell32',
               '-lole32', '-loleaut32', '-luuid', '-lcomdlg32', '-ladvapi32']

msvc_winlibs = ['kernel32.lib', 'user32.lib', 'gdi32.lib',
                'winspool.lib', 'shell32.lib', 'ole32.lib', 'oleaut32.lib',
                'uuid.lib', 'comdlg32.lib', 'advapi32.lib']

clike_optimization_args: T.Dict[str, T.List[str]] = {
    'plain': [],
    '0': [],
    'g': [],
    '1': ['-O1'],
    '2': ['-O2'],
    '3': ['-O3'],
    's': ['-Os'],
}

clike_debug_args: T.Dict[bool, T.List[str]] = {
    False: [],
    True: ['-g']
}


MSCRT_VALS = ['none', 'md', 'mdd', 'mt', 'mtd']

@dataclass
class BaseOption(T.Generic[coredata._T, coredata._U]):
    opt_type: T.Type[coredata._U]
    description: str
    default: T.Any = None
    choices: T.Any = None

    def init_option(self, name: OptionKey) -> coredata._U:
        keywords = {'value': self.default}
        if self.choices:
            keywords['choices'] = self.choices
        return self.opt_type(name.name, self.description, **keywords)

BASE_OPTIONS: T.Mapping[OptionKey, BaseOption] = {
    OptionKey('b_pch'): BaseOption(coredata.UserBooleanOption, 'Use precompiled headers', True),
    OptionKey('b_lto'): BaseOption(coredata.UserBooleanOption, 'Use link time optimization', False),
    OptionKey('b_lto_threads'): BaseOption(coredata.UserIntegerOption, 'Use multiple threads for Link Time Optimization', (None, None, 0)),
    OptionKey('b_lto_mode'): BaseOption(coredata.UserComboOption, 'Select between different LTO modes.', 'default',
                                        choices=['default', 'thin']),
    OptionKey('b_thinlto_cache'): BaseOption(coredata.UserBooleanOption, 'Use LLVM ThinLTO caching for faster incremental builds', False),
    OptionKey('b_thinlto_cache_dir'): BaseOption(coredata.UserStringOption, 'Directory to store ThinLTO cache objects', ''),
    OptionKey('b_sanitize'): BaseOption(coredata.UserComboOption, 'Code sanitizer to use', 'none',
                                        choices=['none', 'address', 'thread', 'undefined', 'memory', 'leak', 'address,undefined']),
    OptionKey('b_lundef'): BaseOption(coredata.UserBooleanOption, 'Use -Wl,--no-undefined when linking', True),
    OptionKey('b_asneeded'): BaseOption(coredata.UserBooleanOption, 'Use -Wl,--as-needed when linking', True),
    OptionKey('b_pgo'): BaseOption(coredata.UserComboOption, 'Use profile guided optimization', 'off',
                                   choices=['off', 'generate', 'use']),
    OptionKey('b_coverage'): BaseOption(coredata.UserBooleanOption, 'Enable coverage tracking.', False),
    OptionKey('b_colorout'): BaseOption(coredata.UserComboOption, 'Use colored output', 'always',
                                        choices=['auto', 'always', 'never']),
    OptionKey('b_ndebug'): BaseOption(coredata.UserComboOption, 'Disable asserts', 'false', choices=['true', 'false', 'if-release']),
    OptionKey('b_staticpic'): BaseOption(coredata.UserBooleanOption, 'Build static libraries as position independent', True),
    OptionKey('b_pie'): BaseOption(coredata.UserBooleanOption, 'Build executables as position independent', False),
    OptionKey('b_bitcode'): BaseOption(coredata.UserBooleanOption, 'Generate and embed bitcode (only macOS/iOS/tvOS)', False),
    OptionKey('b_vscrt'): BaseOption(coredata.UserComboOption, 'VS run-time library type to use.', 'from_buildtype',
                                     choices=MSCRT_VALS + ['from_buildtype', 'static_from_buildtype']),
}

base_options: KeyedOptionDictType = {key: base_opt.init_option(key) for key, base_opt in BASE_OPTIONS.items()}

def option_enabled(boptions: T.Set[OptionKey], options: 'KeyedOptionDictType',
                   option: OptionKey) -> bool:
    try:
        if option not in boptions:
            return False
        ret = options[option].value
        assert isinstance(ret, bool), 'must return bool'  # could also be str
        return ret
    except KeyError:
        return False


def get_option_value(options: 'KeyedOptionDictType', opt: OptionKey, fallback: '_T') -> '_T':
    """Get the value of an option, or the fallback value."""
    try:
        v: '_T' = options[opt].value
    except KeyError:
        return fallback

    assert isinstance(v, type(fallback)), f'Should have {type(fallback)!r} but was {type(v)!r}'
    # Mypy doesn't understand that the above assert ensures that v is type _T
    return v


def are_asserts_disabled(options: KeyedOptionDictType) -> bool:
    """Should debug assertions be disabled

    :param options: OptionDictionary
    :return: whether to disable assertions or not
    """
    return (options[OptionKey('b_ndebug')].value == 'true' or
            (options[OptionKey('b_ndebug')].value == 'if-release' and
             options[OptionKey('buildtype')].value in {'release', 'plain'}))


def get_base_compile_args(options: 'KeyedOptionDictType', compiler: 'Compiler') -> T.List[str]:
    args: T.List[str] = []
    try:
        if options[OptionKey('b_lto')].value:
            args.extend(compiler.get_lto_compile_args(
                threads=get_option_value(options, OptionKey('b_lto_threads'), 0),
                mode=get_option_value(options, OptionKey('b_lto_mode'), 'default')))
    except KeyError:
        pass
    try:
        args += compiler.get_colorout_args(options[OptionKey('b_colorout')].value)
    except KeyError:
        pass
    try:
        args += compiler.sanitizer_compile_args(options[OptionKey('b_sanitize')].value)
    except KeyError:
        pass
    try:
        pgo_val = options[OptionKey('b_pgo')].value
        if pgo_val == 'generate':
            args.extend(compiler.get_profile_generate_args())
        elif pgo_val == 'use':
            args.extend(compiler.get_profile_use_args())
    except KeyError:
        pass
    try:
        if options[OptionKey('b_coverage')].value:
            args += compiler.get_coverage_args()
    except KeyError:
        pass
    try:
        args += compiler.get_assert_args(are_asserts_disabled(options))
    except KeyError:
        pass
    # This does not need a try...except
    if option_enabled(compiler.base_options, options, OptionKey('b_bitcode')):
        args.append('-fembed-bitcode')
    try:
        crt_val = options[OptionKey('b_vscrt')].value
        buildtype = options[OptionKey('buildtype')].value
        try:
            args += compiler.get_crt_compile_args(crt_val, buildtype)
        except AttributeError:
            pass
    except KeyError:
        pass
    return args

def get_base_link_args(options: 'KeyedOptionDictType', linker: 'Compiler',
                       is_shared_module: bool, build_dir: str) -> T.List[str]:
    args: T.List[str] = []
    try:
        if options[OptionKey('b_lto')].value:
            if options[OptionKey('werror')].value:
                args.extend(linker.get_werror_args())

            thinlto_cache_dir = None
            if get_option_value(options, OptionKey('b_thinlto_cache'), False):
                thinlto_cache_dir = get_option_value(options, OptionKey('b_thinlto_cache_dir'), '')
                if thinlto_cache_dir == '':
                    thinlto_cache_dir = os.path.join(build_dir, 'meson-private', 'thinlto-cache')
            args.extend(linker.get_lto_link_args(
                threads=get_option_value(options, OptionKey('b_lto_threads'), 0),
                mode=get_option_value(options, OptionKey('b_lto_mode'), 'default'),
                thinlto_cache_dir=thinlto_cache_dir))
    except KeyError:
        pass
    try:
        args += linker.sanitizer_link_args(options[OptionKey('b_sanitize')].value)
    except KeyError:
        pass
    try:
        pgo_val = options[OptionKey('b_pgo')].value
        if pgo_val == 'generate':
            args.extend(linker.get_profile_generate_args())
        elif pgo_val == 'use':
            args.extend(linker.get_profile_use_args())
    except KeyError:
        pass
    try:
        if options[OptionKey('b_coverage')].value:
            args += linker.get_coverage_link_args()
    except KeyError:
        pass

    as_needed = option_enabled(linker.base_options, options, OptionKey('b_asneeded'))
    bitcode = option_enabled(linker.base_options, options, OptionKey('b_bitcode'))
    # Shared modules cannot be built with bitcode_bundle because
    # -bitcode_bundle is incompatible with -undefined and -bundle
    if bitcode and not is_shared_module:
        args.extend(linker.bitcode_args())
    elif as_needed:
        # -Wl,-dead_strip_dylibs is incompatible with bitcode
        args.extend(linker.get_asneeded_args())

    # Apple's ld (the only one that supports bitcode) does not like -undefined
    # arguments or -headerpad_max_install_names when bitcode is enabled
    if not bitcode:
        args.extend(linker.headerpad_args())
        if (not is_shared_module and
                option_enabled(linker.base_options, options, OptionKey('b_lundef'))):
            args.extend(linker.no_undefined_link_args())
        else:
            args.extend(linker.get_allow_undefined_link_args())

    try:
        crt_val = options[OptionKey('b_vscrt')].value
        buildtype = options[OptionKey('buildtype')].value
        try:
            args += linker.get_crt_link_args(crt_val, buildtype)
        except AttributeError:
            pass
    except KeyError:
        pass
    return args


class CrossNoRunException(MesonException):
    pass

class RunResult(HoldableObject):
    def __init__(self, compiled: bool, returncode: int = 999,
                 stdout: str = 'UNDEFINED', stderr: str = 'UNDEFINED',
                 cached: bool = False):
        self.compiled = compiled
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.cached = cached


class CompileResult(HoldableObject):

    """The result of Compiler.compiles (and friends)."""

    def __init__(self, stdo: T.Optional[str] = None, stde: T.Optional[str] = None,
                 command: T.Optional[T.List[str]] = None,
                 returncode: int = 999,
                 input_name: T.Optional[str] = None,
                 output_name: T.Optional[str] = None,
                 cached: bool = False):
        self.stdout = stdo
        self.stderr = stde
        self.input_name = input_name
        self.output_name = output_name
        self.command = command or []
        self.cached = cached
        self.returncode = returncode


class Compiler(HoldableObject, metaclass=abc.ABCMeta):
    # Libraries to ignore in find_library() since they are provided by the
    # compiler or the C library. Currently only used for MSVC.
    ignore_libs: T.List[str] = []
    # Libraries that are internal compiler implementations, and must not be
    # manually searched.
    internal_libs: T.List[str] = []

    LINKER_PREFIX: T.Union[None, str, T.List[str]] = None
    INVOKES_LINKER = True

    language: str
    id: str
    warn_args: T.Dict[str, T.List[str]]
    mode = 'COMPILER'

    def __init__(self, ccache: T.List[str], exelist: T.List[str], version: str,
                 for_machine: MachineChoice, info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None, is_cross: bool = False):
        self.exelist = ccache + exelist
        self.exelist_no_ccache = exelist
        # In case it's been overridden by a child class already
        if not hasattr(self, 'file_suffixes'):
            self.file_suffixes = lang_suffixes[self.language]
        if not hasattr(self, 'can_compile_suffixes'):
            self.can_compile_suffixes: T.Set[str] = set(self.file_suffixes)
        self.default_suffix = self.file_suffixes[0]
        self.version = version
        self.full_version = full_version
        self.for_machine = for_machine
        self.base_options: T.Set[OptionKey] = set()
        self.linker = linker
        self.info = info
        self.is_cross = is_cross
        self.modes: T.List[Compiler] = []

    def __repr__(self) -> str:
        repr_str = "<{0}: v{1} `{2}`>"
        return repr_str.format(self.__class__.__name__, self.version,
                               ' '.join(self.exelist))

    @lru_cache(maxsize=None)
    def can_compile(self, src: 'mesonlib.FileOrString') -> bool:
        if isinstance(src, mesonlib.File):
            src = src.fname
        suffix = os.path.splitext(src)[1]
        if suffix != '.C':
            suffix = suffix.lower()
        return bool(suffix) and suffix[1:] in self.can_compile_suffixes

    def get_id(self) -> str:
        return self.id

    def get_modes(self) -> T.List[Compiler]:
        return self.modes

    def get_linker_id(self) -> str:
        # There is not guarantee that we have a dynamic linker instance, as
        # some languages don't have separate linkers and compilers. In those
        # cases return the compiler id
        try:
            return self.linker.id
        except AttributeError:
            return self.id

    def get_version_string(self) -> str:
        details = [self.id, self.version]
        if self.full_version:
            details += ['"%s"' % (self.full_version)]
        return '(%s)' % (' '.join(details))

    def get_language(self) -> str:
        return self.language

    @classmethod
    def get_display_language(cls) -> str:
        return cls.language.capitalize()

    def get_default_suffix(self) -> str:
        return self.default_suffix

    def get_define(self, dname: str, prefix: str, env: 'Environment',
                   extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                   dependencies: T.List['Dependency'],
                   disable_cache: bool = False) -> T.Tuple[str, bool]:
        raise EnvironmentException('%s does not support get_define ' % self.get_id())

    def compute_int(self, expression: str, low: T.Optional[int], high: T.Optional[int],
                    guess: T.Optional[int], prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                    dependencies: T.Optional[T.List['Dependency']]) -> int:
        raise EnvironmentException('%s does not support compute_int ' % self.get_id())

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        raise EnvironmentException('%s does not support compute_parameters_with_absolute_paths ' % self.get_id())

    def has_members(self, typename: str, membernames: T.List[str],
                    prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                    dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('%s does not support has_member(s) ' % self.get_id())

    def has_type(self, typename: str, prefix: str, env: 'Environment',
                 extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]], *,
                 dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('%s does not support has_type ' % self.get_id())

    def symbols_have_underscore_prefix(self, env: 'Environment') -> bool:
        raise EnvironmentException('%s does not support symbols_have_underscore_prefix ' % self.get_id())

    def get_exelist(self, ccache: bool = True) -> T.List[str]:
        return self.exelist.copy() if ccache else self.exelist_no_ccache.copy()

    def get_linker_exelist(self) -> T.List[str]:
        return self.linker.get_exelist() if self.linker else self.get_exelist()

    @abc.abstractmethod
    def get_output_args(self, outputname: str) -> T.List[str]:
        pass

    def get_linker_output_args(self, outputname: str) -> T.List[str]:
        return self.linker.get_output_args(outputname)

    def get_linker_search_args(self, dirname: str) -> T.List[str]:
        return self.linker.get_search_args(dirname)

    def get_builtin_define(self, define: str) -> T.Optional[str]:
        raise EnvironmentException('%s does not support get_builtin_define.' % self.id)

    def has_builtin_define(self, define: str) -> bool:
        raise EnvironmentException('%s does not support has_builtin_define.' % self.id)

    def get_always_args(self) -> T.List[str]:
        return []

    def can_linker_accept_rsp(self) -> bool:
        """
        Determines whether the linker can accept arguments using the @rsp syntax.
        """
        return self.linker.get_accepts_rsp()

    def get_linker_always_args(self) -> T.List[str]:
        return self.linker.get_always_args()

    def get_linker_lib_prefix(self) -> str:
        return self.linker.get_lib_prefix()

    def gen_import_library_args(self, implibname: str) -> T.List[str]:
        """
        Used only on Windows for libraries that need an import library.
        This currently means C, C++, Fortran.
        """
        return []

    def create_option(self, option_type: T.Type[UserOptionType], option_key: OptionKey, *args: T.Any, **kwargs: T.Any) -> T.Tuple[OptionKey, UserOptionType]:
        return option_key, option_type(f'{self.language}_{option_key.name}', *args, **kwargs)

    @staticmethod
    def update_options(options: MutableKeyedOptionDictType, *args: T.Tuple[OptionKey, UserOptionType]) -> MutableKeyedOptionDictType:
        options.update(args)
        return options

    def get_options(self) -> 'MutableKeyedOptionDictType':
        return {}

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return []

    def get_option_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return self.linker.get_option_args(options)

    def check_header(self, hname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        """Check that header is usable.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support header checks.' % self.get_display_language())

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:
        """Check that header is exists.

        This check will return true if the file exists, even if it contains:

        ```c
        # error "You thought you could use this, LOLZ!"
        ```

        Use check_header if your header only works in some cases.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support header checks.' % self.get_display_language())

    def has_header_symbol(self, hname: str, symbol: str, prefix: str,
                          env: 'Environment', *,
                          extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                          dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise EnvironmentException('Language %s does not support header symbol checks.' % self.get_display_language())

    def run(self, code: 'mesonlib.FileOrString', env: 'Environment',
            extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None,
            dependencies: T.Optional[T.List['Dependency']] = None,
            run_env: T.Optional[T.Dict[str, str]] = None,
            run_cwd: T.Optional[str] = None) -> RunResult:
        need_exe_wrapper = env.need_exe_wrapper(self.for_machine)
        if need_exe_wrapper and not env.has_exe_wrapper():
            raise CrossNoRunException('Can not run test applications in this cross environment.')
        with self._build_wrapper(code, env, extra_args, dependencies, mode=CompileCheckMode.LINK, want_output=True) as p:
            if p.returncode != 0:
                mlog.debug(f'Could not compile test file {p.input_name}: {p.returncode}\n')
                return RunResult(False)
            if need_exe_wrapper:
                cmdlist = env.exe_wrapper.get_command() + [p.output_name]
            else:
                cmdlist = [p.output_name]
            try:
                pe, so, se = mesonlib.Popen_safe(cmdlist, env=run_env, cwd=run_cwd)
            except Exception as e:
                mlog.debug(f'Could not run: {cmdlist} (error: {e})\n')
                return RunResult(False)

        mlog.debug('Program stdout:\n')
        mlog.debug(so)
        mlog.debug('Program stderr:\n')
        mlog.debug(se)
        return RunResult(True, pe.returncode, so, se)

    # Caching run() in general seems too risky (no way to know what the program
    # depends on), but some callers know more about the programs they intend to
    # run.
    # For now we just accept code as a string, as that's what internal callers
    # need anyway. If we wanted to accept files, the cache key would need to
    # include mtime.
    def cached_run(self, code: str, env: 'Environment', *,
                   extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]], None] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None) -> RunResult:
        run_check_cache = env.coredata.run_check_cache
        args = self.build_wrapper_args(env, extra_args, dependencies, CompileCheckMode('link'))
        key = (code, tuple(args))
        if key in run_check_cache:
            p = run_check_cache[key]
            p.cached = True
            mlog.debug('Using cached run result:')
            mlog.debug('Code:\n', code)
            mlog.debug('Args:\n', extra_args)
            mlog.debug('Cached run returncode:\n', p.returncode)
            mlog.debug('Cached run stdout:\n', p.stdout)
            mlog.debug('Cached run stderr:\n', p.stderr)
        else:
            p = self.run(code, env, extra_args=extra_args, dependencies=dependencies)
            run_check_cache[key] = p
        return p

    def sizeof(self, typename: str, prefix: str, env: 'Environment', *,
               extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
               dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        raise EnvironmentException('Language %s does not support sizeof checks.' % self.get_display_language())

    def alignment(self, typename: str, prefix: str, env: 'Environment', *,
                  extra_args: T.Optional[T.List[str]] = None,
                  dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[int, bool]:
        raise EnvironmentException('Language %s does not support alignment checks.' % self.get_display_language())

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        """See if a function exists.

        Returns a two item tuple of bools. The first bool is whether the
        check succeeded, the second is whether the result was cached (True)
        or run fresh (False).
        """
        raise EnvironmentException('Language %s does not support function checks.' % self.get_display_language())

    @classmethod
    def _unix_args_to_native(cls, args: T.List[str], info: MachineInfo) -> T.List[str]:
        "Always returns a copy that can be independently mutated"
        return args.copy()

    def unix_args_to_native(self, args: T.List[str]) -> T.List[str]:
        return self._unix_args_to_native(args, self.info)

    @classmethod
    def native_args_to_unix(cls, args: T.List[str]) -> T.List[str]:
        "Always returns a copy that can be independently mutated"
        return args.copy()

    def find_library(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                     libtype: LibType = LibType.PREFER_SHARED, lib_prefix_warning: bool = True) -> T.Optional[T.List[str]]:
        raise EnvironmentException(f'Language {self.get_display_language()} does not support library finding.')

    def get_library_naming(self, env: 'Environment', libtype: LibType,
                           strict: bool = False) -> T.Optional[T.Tuple[str, ...]]:
        raise EnvironmentException(
            'Language {} does not support get_library_naming.'.format(
                self.get_display_language()))

    def get_program_dirs(self, env: 'Environment') -> T.List[str]:
        return []

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        """Checks if the compiler has all of the arguments.

        :returns:
            A tuple of (bool, bool). The first value is whether the check
            succeeded, and the second is whether it was retrieved from a cache
        """
        raise EnvironmentException(
            'Language {} does not support has_multi_arguments.'.format(
                self.get_display_language()))

    def has_multi_link_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        """Checks if the linker has all of the arguments.

        :returns:
            A tuple of (bool, bool). The first value is whether the check
            succeeded, and the second is whether it was retrieved from a cache
        """
        return self.linker.has_multi_arguments(args, env)

    def _get_compile_output(self, dirname: str, mode: CompileCheckMode) -> str:
        assert mode != CompileCheckMode.PREPROCESS, 'In pre-processor mode, the output is sent to stdout and discarded'
        # Exten
```