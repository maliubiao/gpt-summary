Response:
The user wants a summary of the functionality of the provided Python code. The code defines classes and functions related to compilers within the Frida dynamic instrumentation tool's build system (using Meson).

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The initial comment clearly states this file contains data about compilers known to Meson and handles compiler autodetection. This immediately sets the context.

2. **Analyze Top-Level Structures:** Notice the imports, especially from `..coredata`, `..mlog`, `..mesonlib`, and `..arglist`. This indicates the code interacts with Meson's core data structures, logging, utility functions, and argument handling.

3. **Examine Key Data Structures:**  The `header_suffixes`, `obj_suffixes`, `lib_suffixes`, and `lang_suffixes` dictionaries are fundamental. These define file types and their association with programming languages. Note the importance of `clink_langs` for C ABI compatibility and linking.

4. **Investigate Key Functions:** Functions like `is_header`, `is_source`, `is_library` are crucial for classifying files. The `sort_clink` function's purpose is important for understanding language preference during linking.

5. **Understand Core Classes:** The `Compiler` class is central. Analyze its methods:
    * **Initialization (`__init__`)**: Stores compiler executable paths, version, target machine, etc.
    * **`can_compile`**: Determines if a compiler can process a given source file.
    * **`get_exelist`, `get_linker_exelist`**:  Retrieving the compiler/linker command.
    * **`get_output_args`, `get_linker_output_args`**: Getting arguments for specifying output file names.
    * **`check_header`, `has_header`, `has_header_symbol`**: Performing checks related to header files and symbols.
    * **`run`, `cached_run`**: Compiling and running code snippets, with caching.
    * **`sizeof`, `alignment`, `has_function`**:  Compiler feature checks.
    * **`find_library`**: Locating libraries.
    * **`get_options`, `get_option_compile_args`, `get_option_link_args`**: Handling compiler-specific options.
    * **Methods related to LTO, sanitizers, PGO, coverage**: These indicate the file's role in managing advanced build features.

6. **Examine Supporting Classes:**  The `RunResult` and `CompileResult` classes represent the outcome of compilation and execution, respectively. The `BaseOption` and `BASE_OPTIONS` structures are used to define and manage Meson build options.

7. **Identify Relationships:**  The code establishes relationships between file suffixes and languages, and between compilers and linkers. The `clink_langs` variable is key to the interaction between different languages at the linking stage.

8. **Infer Functionality from Method Names:** Even without deep diving into the implementation, method names like `get_lto_compile_args`, `sanitizer_link_args`, `get_profile_generate_args` clearly suggest the features being managed.

9. **Synthesize the Summary:** Based on the above analysis, organize the functionalities into logical groups:
    * **File Type Handling:**  Identifying source, header, object, and library files.
    * **Compiler Representation:** The `Compiler` class and its attributes.
    * **Compilation and Linking Process:** Methods for getting command-line arguments, checking headers and symbols, running code snippets.
    * **Build Options Management:** Handling of common build options like LTO, sanitizers, PGO.
    * **Cross-Compilation Support:**  Mention of `CrossNoRunException`.
    * **Library Handling:** Finding and naming libraries.

10. **Refine the Summary:** Ensure the language is clear, concise, and accurately reflects the code's purpose. Use terms from the code itself where appropriate (e.g., "clink_langs", "LTO").

By following these steps, we can systematically analyze the code and produce a comprehensive summary of its functionality. The focus is on understanding the overall purpose, key data structures, and the responsibilities of the main classes and functions.
这是文件 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/compilers.py` 的源代码，它属于 Frida 动态 instrumentation 工具的构建系统，使用了 Meson 构建工具。该文件主要负责**定义和管理各种编程语言的编译器信息及其相关操作**。

以下是该文件的功能归纳：

**核心功能：编译器信息管理**

1. **定义已知语言的源文件、头文件、库文件和目标文件后缀名：**
   - 使用 `header_suffixes`, `obj_suffixes`, `lib_suffixes`, `lang_suffixes` 等变量定义了各种编程语言常见的文件后缀名。
   - 这使得 Meson 能够识别不同类型的源文件，并将其分配给正确的编译器处理。

2. **提供判断文件类型的功能：**
   - 提供了 `is_header`, `is_source`, `is_library`, `is_object` 等函数，用于判断给定文件名是否为头文件、源文件、库文件或目标文件。

3. **定义了可与 C 代码互操作的语言列表 (`clink_langs`)：**
   - 用于在链接阶段确定语言之间的兼容性，特别是对于可以被 C 编译器和 C++ 编译器都编译的文件。

4. **定义了与编译器相关的环境变量映射 (`CFLAGS_MAPPING`)：**
   - 将编程语言与通常用于设置编译选项的环境变量关联起来，例如 C 使用 `CFLAGS`，C++ 使用 `CXXFLAGS`。

5. **定义了通用的编译和链接选项 (`BASE_OPTIONS`)：**
   - 包含了一些常用的构建选项，如是否使用预编译头文件 (`b_pch`)，是否启用链接时优化 (`b_lto`)，代码静态分析 (`b_sanitize`) 等。

6. **定义了 `Compiler` 抽象基类：**
   - 作为所有编译器类的基类，定义了编译器对象应该具备的通用属性和方法，例如：
     - 编译器可执行文件路径 (`exelist`)
     - 编译器版本 (`version`)
     - 支持的编程语言 (`language`)
     - 获取编译和链接参数的方法 (`get_output_args`, `get_linker_output_args`)
     - 执行编译检查的方法 (`check_header`, `has_header`, `run`)
     - 获取内置宏定义的方法 (`get_builtin_define`)
     - 处理编译和链接选项的方法 (`get_options`, `get_option_compile_args`, `get_option_link_args`)

7. **定义了编译和运行结果的类 (`CompileResult`, `RunResult`)：**
   - 用于存储编译和运行测试代码的结果，包括标准输出、标准错误、返回码等信息。

**与逆向方法的关联：**

虽然这个文件本身不直接包含逆向工程的技术细节，但它为 Frida 这样的动态 instrumentation 工具的构建提供了基础。Frida 的核心功能是运行时代码注入和修改，这与编译和链接过程密切相关。

* **例子：编译用于注入的代码:** 当开发者编写 Frida 脚本或 Gadget 代码（通常是 C/C++）时，这个文件定义的编译器信息会被 Meson 用来正确地编译这些代码。例如，确定使用哪个编译器、传递哪些编译选项、以及如何链接生成的库。
* **例子：处理目标二进制文件:** Frida 需要能够处理不同平台上编译的二进制文件。这个文件定义的编译器信息有助于理解目标二进制文件的编译方式，从而更好地进行代码注入和 hook 操作。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层:**
    - 文件后缀名（如 `.o`, `.so`, `.dll`）直接关联到编译和链接产生的二进制文件格式。
    - 链接时优化 (`b_lto`) 直接影响最终生成二进制文件的结构和性能。
    - 代码静态分析 (`b_sanitize`) 可以检测潜在的二进制安全问题。
* **Linux:**
    - 共享库后缀名 `.so` 是 Linux 平台上的动态链接库。
    - 链接参数（如 `-Wl,--as-needed`）是 Linux 链接器的特定选项。
* **Android 内核及框架:**
    - 虽然代码本身没有直接提及 Android，但 Frida 广泛应用于 Android 逆向和分析。这个文件定义的编译器信息对于编译 Frida 在 Android 上运行的组件（如 Frida Server）至关重要。
    - 理解 Android 平台上使用的编译器（通常是 Clang）及其选项，对于正确构建 Frida 至关重要。

**逻辑推理示例：**

**假设输入:** Meson 遇到一个名为 `my_hook.cc` 的文件。

**处理过程中的逻辑推理:**

1. Meson 调用 `is_source('my_hook.cc')`。
2. `is_source` 函数提取文件后缀 `.cc`。
3. `SUFFIX_TO_LANG` 字典中存在 `.cc` 到 `cpp` 的映射。
4. 因此，`is_source` 返回 `True`，Meson 确定这是一个 C++ 源文件。
5. Meson 会根据 `lang_suffixes['cpp']` 找到 C++ 编译器的默认后缀名。
6. 后续 Meson 会使用与 `cpp` 语言关联的 `Compiler` 对象来处理 `my_hook.cc` 文件。

**用户或编程常见的使用错误：**

* **错误的文件后缀名:** 如果用户不小心将 C++ 源文件命名为 `my_hook.c`，Meson 可能会将其误认为 C 源文件，并使用 C 编译器进行编译，这可能导致编译错误或链接问题。
* **缺少必要的编译器:** 如果系统中没有安装与项目使用的编程语言对应的编译器，Meson 会报错。例如，如果项目包含 C++ 代码但没有安装 g++ 或 Clang。
* **错误的编译选项:** 用户可能在 `meson_options.txt` 或命令行中设置了不适用于特定编译器的选项，这可能会导致编译失败。例如，某些 GCC 特有的选项可能不适用于 Clang。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户执行 `meson setup build` 或 `ninja` 命令：** 这是 Meson 构建过程的入口点。
2. **Meson 解析 `meson.build` 文件：**  `meson.build` 文件描述了项目的构建规则，包括使用的源文件、依赖库等。
3. **Meson 识别源文件类型：** 当 Meson 遇到源文件时，会调用 `is_source` 等函数来判断文件类型。
4. **Meson 查找对应的编译器：** 根据源文件类型，Meson 会查找并实例化相应的 `Compiler` 对象（例如，如果识别为 C++ 文件，则会实例化一个 C++ 编译器对象）。
5. **Meson 调用 `Compiler` 对象的方法：**  例如，调用 `get_output_args` 获取输出文件名的参数，调用 `compile` 方法执行编译操作。
6. **如果编译或链接过程中出现错误：** 开发者可能会检查 Meson 的日志输出，查看使用的编译器命令和选项，从而追踪问题到具体的编译器设置。这个 `compilers.py` 文件中定义的编译器信息就是 Meson 如何理解和操作编译器的关键。

**功能归纳 (第 1 部分):**

该文件的核心功能是**作为 Meson 构建系统的一部分，集中管理各种编程语言的编译器信息**。它定义了文件类型与语言的关联，提供了判断文件类型的功能，定义了可互操作的语言列表，以及通用的编译和链接选项。最重要的是，它定义了 `Compiler` 抽象基类，为不同编程语言的编译器实现提供了统一的接口，使得 Meson 能够正确地识别、配置和调用编译器来构建项目。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
"""


```