Response:
The user wants a summary of the functionalities of the Python code provided.
The code defines the `Compiler` class and related functionalities for handling different compilers within the Meson build system.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file is named `compilers.py` and resides within a directory structure related to compilers in the Frida project's Meson build setup. This immediately suggests its primary function is to represent and manage compiler information.

2. **Examine Class Definitions:**  The code defines several classes: `BaseOption`, `RunResult`, `CompileResult`, and `Compiler`. Focus on `Compiler` as it appears to be the central entity.

3. **Analyze `Compiler` Class Attributes:** Go through the `__init__` method and other class-level attributes to understand the data it holds. Key attributes include `exelist` (compiler executable), `version`, `language`, `id`, `linker`, and various dictionaries for arguments.

4. **Analyze `Compiler` Class Methods:**  Categorize the methods based on their apparent function. Look for verbs and keywords in the method names. Some prominent categories emerge:
    * **Compilation:**  Methods related to compiling source code (e.g., `can_compile`, `get_output_args`).
    * **Linking:** Methods related to the linking process (e.g., `get_linker_exelist`, `get_linker_output_args`).
    * **Feature Checks:** Methods for probing compiler capabilities (e.g., `check_header`, `has_function`, `sizeof`).
    * **Option Handling:** Methods for managing compiler options (e.g., `create_option`, `get_options`, `get_option_compile_args`).
    * **Execution:** Methods for running compiled code (e.g., `run`, `cached_run`).
    * **Argument Manipulation:** Methods for modifying compiler arguments (e.g., `unix_args_to_native`).
    * **Library Handling:** Methods for finding and managing libraries (e.g., `find_library`).

5. **Identify Helper Functions and Data Structures:** Notice functions outside the `Compiler` class, like `is_header`, `is_source`, and data structures like `lang_suffixes`, `CFLAGS_MAPPING`, `BASE_OPTIONS`. These provide supporting information and utilities.

6. **Look for Connections to Reverse Engineering (as requested by the user):** Consider how the compiler interactions might relate to reverse engineering. For example, the ability to check for header files, symbols, and function existence could be used in reverse engineering scenarios to understand the target's API or internal structure.

7. **Look for Connections to Low-Level Details:**  Identify aspects related to binary operations, operating systems (Linux, Android), and kernel/framework interactions. The presence of linker-related methods, handling of shared libraries, and checks for system headers are relevant here.

8. **Consider Logic and Assumptions:** Note methods that perform conditional checks or make assumptions about the compiler's behavior. The `cached_run` method explicitly manages a cache based on input code and arguments.

9. **Identify Potential User Errors:** Think about common mistakes users might make when interacting with these compiler functionalities. For example, providing an incorrect header name or expecting a cross-compilation setup to run native executables directly.

10. **Trace User Actions (Debugging Clues):** Imagine how a user's build process would lead to the execution of this code. The Meson build system would invoke these classes and methods to configure the compilation and linking steps based on the project's configuration.

11. **Structure the Summary:** Organize the findings into logical sections based on the identified categories. Start with a high-level overview and then delve into specific functionalities. Address each point raised in the user's prompt.

12. **Refine and Clarify:** Review the summary for clarity, accuracy, and completeness. Ensure the language is precise and avoids jargon where possible. Add examples where they enhance understanding.

By following this process, we can systematically analyze the code and generate a comprehensive summary that addresses the user's specific questions. The key is to break down the code into its constituent parts and understand the purpose of each component and how they interact.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/compilers.py` 文件，它是 Frida 动态 instrumentation 工具中用于处理编译器的源代码文件。该文件在 Meson 构建系统中扮演着核心角色，负责定义和管理各种编译器的信息和操作。

**它的主要功能可以归纳为以下几点：**

1. **定义编译器通用接口 (`Compiler` 类):**
   - 提供了一个抽象基类 `Compiler`，作为所有具体编译器类的蓝图。
   - 定义了编译器共有的属性（如可执行文件路径 `exelist`、版本号 `version`、支持的语言 `language`、编译器 ID `id` 等）和方法。
   - 抽象方法需要子类实现，以处理特定编译器的行为，例如获取输出参数、编译代码、链接库等。

2. **存储和管理编译器相关信息:**
   - 定义了各种常量和数据结构，如 `header_suffixes` (头文件后缀)、`lang_suffixes` (语言对应的文件后缀)、`CFLAGS_MAPPING` (环境变量映射) 等，用于标识和区分不同类型的文件和编译器。
   - 包含了与编译相关的选项定义 (`BASE_OPTIONS`)，例如是否使用预编译头、LTO（链接时优化）、代码清理器等。

3. **提供编译器操作的通用方法:**
   - 提供了许多辅助函数，用于执行常见的编译器操作，例如：
     - `is_header`, `is_source`, `is_object`, `is_library`:  判断文件类型。
     - `get_base_compile_args`, `get_base_link_args`:  获取通用的编译和链接参数。
     - `option_enabled`:  检查特定选项是否启用。
     - `are_asserts_disabled`:  判断断言是否被禁用。
     - `sort_clink`:  对支持 C 链接的语言进行排序。

4. **支持编译器的特性检测:**
   - 提供了方法来检测编译器的各种特性，例如：
     - `check_header`, `has_header`:  检查头文件是否存在和可用。
     - `has_header_symbol`:  检查头文件中是否存在特定符号。
     - `has_function`:  检查是否存在特定函数。
     - `sizeof`, `alignment`:  获取数据类型的大小和对齐方式。
     - `has_members`, `has_type`: 检查结构体或类是否包含特定成员或类型。
     - `get_define`:  获取宏定义的值。
     - `compute_int`:  计算表达式的值。
     - `has_multi_arguments`, `has_multi_link_arguments`: 检查编译器或链接器是否支持多个参数。

5. **处理编译和链接过程:**
   - `run`, `cached_run`:  提供编译和运行代码片段的功能，用于特性检测。
   - 封装了调用编译器的过程，并处理输出和错误信息。

**与逆向方法的关系及举例说明:**

这个文件本身不是直接执行逆向操作的工具，但它为 Frida 这样的动态 instrumentation 工具提供了构建基础。逆向工程师可以使用 Frida 来分析和修改目标进程的运行时行为。这个文件定义了如何与不同语言的编译器进行交互，以便构建 Frida 自身以及可能需要编译的目标代码或钩子代码。

**举例说明：**

假设逆向工程师想要编写一个 Frida 脚本，该脚本需要在目标进程中注入一些 C 代码来实现特定的 hook 功能。

1. **Frida 使用 Meson 构建:** Frida 本身是用 Meson 构建的，因此这个 `compilers.py` 文件在 Frida 的构建过程中会被使用，用来确定 C 编译器（例如 GCC 或 Clang）的路径、版本以及支持的编译选项。
2. **动态代码编译 (可能):**  虽然不常见，但在某些高级场景下，Frida 可能会在运行时编译一些小的代码片段并注入到目标进程。  `compilers.py` 中定义的方法（例如 `run` 或内部的编译逻辑）会被用来调用目标系统上的 C 编译器来完成这个任务。
3. **特性检测用于适配:**  在构建 Frida 模块或脚本时，可能需要检测目标环境的编译器特性。例如，需要确定目标系统是否支持某个特定的 C 标准或编译器扩展。 `compilers.py` 中提供的 `check_header`、`has_function` 等方法可以用于实现这种检测。

**涉及到二进制底层，Linux, Android内核及框架的知识及举例说明:**

这个文件在很大程度上抽象了底层的编译细节，但它所处理的任务与这些概念紧密相关。

1. **二进制底层:** 编译器的最终输出是二进制代码。这个文件定义了如何调用编译器，生成目标文件 (`.o` 或 `.obj`) 和可执行文件或库文件 (`.so`, `.dll`, `.a`)。这些都是二进制层面的产物。
2. **Linux 和 Android 内核:**
   - **链接器 (`linker` 属性):**  文件中涉及到链接器的操作（例如 `get_linker_exelist`, `get_linker_output_args`）。链接器是操作系统的一部分，负责将编译后的目标文件组合成最终的可执行文件或库。在 Linux 和 Android 上，链接器的工作方式和参数有所不同。
   - **共享库 (`.so`):**  Frida 经常需要注入共享库到目标进程中。`compilers.py` 中的信息（例如 `lib_suffixes`）用于识别共享库文件。
   - **头文件路径:** 编译器需要知道系统头文件的路径（例如 Linux 内核头文件或 Android SDK 头文件）。虽然这个文件本身不直接管理头文件路径，但它所调用的编译器会使用这些信息。
3. **Android 框架:**  如果 Frida 用于 instrument Android 应用，那么编译过程可能涉及到 Android SDK 中的头文件和库。`compilers.py` 的功能是确保能够使用正确的编译器选项来处理这些依赖。

**举例说明：**

- **检测 Android NDK 的编译器:** 当 Frida 需要在 Android 上工作时，Meson 会使用 `compilers.py` 中的逻辑来检测 Android NDK (Native Development Kit) 中提供的交叉编译器。
- **生成 Android 共享库:** Frida 注入到 Android 进程的代码通常会被编译成 `.so` 文件。这个文件中的编译器配置会影响 `.so` 文件的生成，例如指定架构 (ARM, ARM64, x86) 和链接到 Android 系统库。

**逻辑推理及假设输入与输出:**

文件中存在一些逻辑推理，主要体现在特性检测和选项处理上。

**示例：`are_asserts_disabled` 函数**

- **假设输入:** 一个包含构建选项的字典 `options`。
- **逻辑:**
    - 如果 `options['b_ndebug'].value` 是 `'true'`，则断言被禁用。
    - 否则，如果 `options['b_ndebug'].value` 是 `'if-release'` 并且 `options['buildtype'].value` 是 `'release'` 或 `'plain'`，则断言也被禁用。
- **输出:** 一个布尔值，指示断言是否应该被禁用。

**示例：`cached_run` 函数**

- **假设输入:**  一段代码字符串 `code`，一个 `Environment` 对象 `env`，以及可选的编译参数 `extra_args` 和依赖项 `dependencies`。
- **逻辑:**
    - 构建编译和链接的参数 `args`。
    - 检查缓存 `run_check_cache` 中是否存在与 `(code, tuple(args))` 相同的键。
    - 如果存在，则返回缓存的结果，并将 `cached` 标记为 `True`。
    - 如果不存在，则调用 `self.run` 编译并运行代码，并将结果存入缓存。
- **输出:** 一个 `RunResult` 对象，包含运行结果（编译是否成功，返回码，标准输出，标准错误），以及是否使用了缓存的标记。

**用户或编程常见的使用错误及举例说明:**

虽然用户不直接与这个文件交互，但编程错误或配置错误可能导致这个文件中的代码执行出错。

**举例说明：**

- **配置了错误的编译器路径:** 如果 Meson 配置中指定的编译器路径不正确，当 `compilers.py` 尝试执行编译器时会失败。
- **提供了不支持的编译选项:** 用户在 `meson.build` 文件中指定的编译选项可能不被当前使用的编译器支持，这会导致编译器调用失败。`compilers.py` 中虽然定义了一些通用选项，但具体的编译器实现可能会有差异。
- **交叉编译环境配置错误:**  在交叉编译场景下，例如为 Android 构建 Frida 模块，如果交叉编译工具链配置不正确，`compilers.py` 可能会使用错误的编译器或链接器，导致构建失败。

**用户操作如何一步步的到达这里，作为调试线索:**

当用户执行 Meson 构建命令（例如 `meson setup builddir` 或 `ninja`) 时，以下步骤可能涉及到这个文件：

1. **Meson 解析 `meson.build` 文件:** Meson 首先会读取项目根目录下的 `meson.build` 文件以及其他相关的 `meson.build` 文件。
2. **探测编译器:**  Meson 会根据项目配置和系统环境，使用 `detect.py` (与 `compilers.py` 在同一目录下) 来探测可用的编译器。`compilers.py` 中定义的 `Compiler` 类和相关信息会被用来表示探测到的编译器。
3. **配置构建环境:** Meson 会根据探测到的编译器和用户指定的选项，创建构建环境。这包括设置编译器的路径、版本、默认参数等信息，这些信息很大程度上来自 `compilers.py`。
4. **处理编译目标:** 当 Meson 处理需要编译的目标（例如可执行文件、库）时，会使用 `compilers.py` 中定义的方法来生成编译命令。例如，根据文件后缀选择合适的编译器，调用 `get_output_args` 获取输出参数，调用 `get_option_compile_args` 获取用户指定的编译选项。
5. **执行编译命令:** Meson 或 Ninja (如果使用 Ninja backend) 会执行生成的编译命令。如果编译过程中出现错误，错误信息可能与 `compilers.py` 中定义的编译器执行逻辑有关。

**作为调试线索：**

- **编译器未找到:** 如果 Meson 报错说找不到编译器，可能是 `detect.py` 探测失败，或者 `compilers.py` 中没有正确配置该编译器的信息。
- **编译选项错误:** 如果编译器报错说某个选项不被支持，可能是 `meson.build` 中使用了错误的选项，或者 `compilers.py` 中没有正确处理该选项。
- **链接错误:** 如果链接器报错，可能是 `compilers.py` 中链接器相关的配置或参数生成有误。

**归纳一下它的功能（第 1 部分）：**

总的来说，`frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/compilers.py` 文件的主要功能是：

- **作为 Meson 构建系统中处理编译器的核心模块。**
- **定义了编译器对象的通用接口和数据结构，用于描述各种编译器的属性和行为。**
- **提供了用于执行常见编译器操作（编译、链接、特性检测）的通用方法。**
- **抽象了底层的编译细节，使得 Meson 可以以统一的方式处理不同的编译器。**
- **为 Frida 的构建过程提供了必要的编译器信息和操作支持。**

这个文件是构建过程的关键组成部分，确保了 Frida 能够使用正确的编译器选项，并能够检测目标环境的特性，从而成功构建和运行。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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