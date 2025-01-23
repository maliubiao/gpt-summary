Response:
The user is asking for a breakdown of the functionality of a Python file related to compiler management within the Frida dynamic instrumentation tool. They specifically want to know about its connections to reverse engineering, low-level binary interaction, Linux/Android kernel/framework details, logical inference, potential user errors, and how a user might reach this code during debugging.

Here's a plan to address this:

1. **High-Level Overview:** Briefly explain the file's core purpose: managing and providing information about different compilers used by the build system.

2. **Functional Breakdown:**  List the key functionalities, drawing directly from the code's structure and content. This includes:
    * Defining file suffixes for different languages.
    * Storing compiler options and their defaults.
    * Providing methods for checking compiler capabilities (compiling, linking, header existence, etc.).
    * Handling compiler arguments for various features (optimization, debugging, sanitizers).
    *  Providing mechanisms for running compiled code.

3. **Reverse Engineering Relevance:**  Identify how compiler configurations impact the binaries Frida interacts with during reverse engineering. Focus on aspects like:
    * Debug symbols (-g flag).
    * Optimization levels (-O flags).
    * Position-Independent Code (-fPIE, -fPIC).
    * Link-Time Optimization (-flto).
    * Sanitizers (e.g., AddressSanitizer).

4. **Binary/OS/Kernel/Framework Connections:** Explain how the compiler settings relate to the low-level aspects of the target environment:
    * Linking (shared libraries, static libraries).
    * Position-Independent Executables (PIE) for security.
    * System libraries (kernel32.lib on Windows).
    * Impact on binary structure and execution.

5. **Logical Inference (Hypothetical Inputs/Outputs):** Provide examples of how the code might behave given certain inputs. Focus on functions that make decisions, like `is_source()`, `can_compile()`, and the option handling functions.

6. **User Errors:**  Point out potential mistakes a user could make that might lead them to investigate this file, such as:
    * Incorrectly setting build options (e.g., LTO, sanitizers).
    * Issues with cross-compilation.
    * Problems with finding libraries.

7. **Debugging Scenario:** Outline a step-by-step process a user might follow that would lead them to this file during debugging. This will connect the abstract code to a concrete user experience.

8. **Summary of Functionality:**  Reiterate the main functions of the file in a concise summary.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the specifics of each compiler. The prompt asks for *the file's* functionality, so a higher-level view is more appropriate.
* Ensure the reverse engineering examples are clear and directly linked to how Frida operates.
* Double-check the code for specific features mentioned in the prompt (e.g., LTO, sanitizers).
* Frame the user error section in terms of debugging scenarios.

By following this plan and incorporating these refinements, I should be able to provide a comprehensive and accurate answer to the user's request.
This Python file, `compilers.py`, within the Frida project's build system (Meson), plays a crucial role in **managing and abstracting the complexities of different compilers** used to build the various components of Frida. It acts as a central repository for information and logic related to how different language compilers (C, C++, Rust, etc.) are invoked and how their options are handled.

Here's a breakdown of its key functionalities:

**1. Defining Language-Specific File Handling:**

* **File Suffix Mappings:** It defines dictionaries like `lang_suffixes`, `header_suffixes`, `obj_suffixes`, and `lib_suffixes` to categorize file extensions based on the programming language they belong to (e.g., `.c` for C, `.cpp` for C++). This is fundamental for the build system to understand how to process different types of source files.
* **Identifying File Types:**  Functions like `is_header`, `is_source`, `is_assembly`, `is_object`, and `is_library` use these suffix mappings to quickly determine the type of a given file.

**2. Managing Compiler Options and Arguments:**

* **Base Compiler Options:** It defines a set of common, build-related options (`BASE_OPTIONS`) like enabling LTO (Link Time Optimization), sanitizers (for detecting memory errors), PGO (Profile-Guided Optimization), and debugging features. These options are common across many compilers.
* **Mapping Options to Compiler Flags:**  It provides functions like `get_base_compile_args` and `get_base_link_args` that translate these abstract build options into specific compiler command-line flags (e.g., `-flto` for LTO in GCC/Clang). This abstracts away the differences in how these options are expressed by different compilers.
* **Language-Specific Flag Mappings:**  Dictionaries like `CFLAGS_MAPPING` store environment variable names commonly used for setting compiler flags for different languages.
* **Optimization and Debugging Arguments:** Dictionaries like `clike_optimization_args` and `clike_debug_args` provide mappings for common optimization levels (`-O1`, `-O2`, etc.) and debug flag (`-g`).

**3. Abstracting Compiler Invocation:**

* **Compiler Class:** The `Compiler` class serves as a base class for representing different compilers. It stores information like the compiler's executable path (`exelist`), version, supported languages, and provides abstract methods for common compiler operations.
* **Concrete Compiler Implementations (Not in this file):**  While this file defines the base `Compiler` class, the actual implementations for specific compilers (like GCC, Clang, MSVC) would reside in other files (likely within the same directory or a sibling directory).
* **Methods for Compiler Checks:** The `Compiler` class defines methods for checking various compiler capabilities, such as:
    * `can_compile`: Checks if the compiler can compile a given source file based on its suffix.
    * `check_header`, `has_header`, `has_header_symbol`:  Methods for probing the availability of header files and symbols within them.
    * `has_function`: Checks if a specific function is available during linking.
    * `run`: Compiles and runs a small piece of code to test certain features.
    * `sizeof`, `alignment`:  Determines the size and memory alignment of data types.
    * `has_multi_arguments`, `has_multi_link_arguments`: Checks if the compiler or linker supports a list of given arguments.

**4. Handling Linking:**

* **Linker Abstraction:** The `Compiler` class has a `linker` attribute, which is an instance of a `DynamicLinker` (defined in other files). This allows the file to abstract linker-specific operations.
* **Linker Argument Generation:**  Methods like `get_linker_output_args`, `get_linker_search_args`, `get_asneeded_args`, and `no_undefined_link_args` generate linker-specific command-line arguments.
* **LTO Handling:**  The file includes logic for handling Link Time Optimization (LTO), including arguments for compile and link stages, and options for ThinLTO caching.

**5. Supporting Cross-Compilation:**

* **`is_cross` Flag:** The `Compiler` class includes an `is_cross` flag to indicate if the compiler is being used for cross-compilation (building for a different target architecture).
* **`CrossNoRunException`:**  This exception is raised when trying to run executables during cross-compilation if an appropriate execution wrapper is not configured.

**Relation to Reverse Engineering:**

This file directly relates to reverse engineering because the choices made during the build process (controlled by the options and compiler settings managed here) significantly impact the characteristics of the final binary that a reverse engineer will analyze. For example:

* **Debug Symbols:**  The `b_ndebug` option and the `clike_debug_args` influence whether debug symbols are included in the binary. Reverse engineers rely heavily on debug symbols to understand the code's structure and execution flow.
* **Optimization Levels:** The various `-O` flags managed here determine how aggressively the compiler optimizes the code. Higher optimization levels can make the code harder to follow during reverse engineering due to inlining, register allocation, and other transformations.
* **Link-Time Optimization (LTO):** LTO can further complicate reverse engineering as it allows the compiler to perform optimizations across multiple object files, potentially changing function boundaries and code layout.
* **Position Independent Code (PIC/PIE):** The `b_staticpic` and `b_pie` options control whether libraries and executables are built as position-independent. This is important for security features like Address Space Layout Randomization (ASLR), which can affect how a reverse engineer approaches dynamic analysis.
* **Sanitizers:** While primarily for development, if a binary is built with sanitizers enabled (e.g., AddressSanitizer), it can introduce extra runtime checks that might be visible during reverse engineering.

**Example:** If a reverse engineer encounters a stripped binary (no debug symbols) that has been heavily optimized (e.g., with `-O3`), they might suspect that the `b_ndebug` option was set to `true` or `if-release` and a high optimization level was chosen, potentially due to the settings managed by this `compilers.py` file.

**Relation to Binary Underpinnings, Linux, Android Kernel/Framework:**

* **Linking Process:** The file's handling of linker arguments is directly related to the binary linking process on Linux and Android. Concepts like shared libraries (`.so`), static libraries (`.a`), and the search paths for libraries are managed here.
* **Position Independent Executables (PIE):** The `b_pie` option directly controls the generation of PIE executables, a security feature common in modern Linux and Android systems to mitigate certain types of exploits.
* **System Libraries:** The lists `gnu_winlibs` and `msvc_winlibs` contain the names of essential system libraries on Windows (like `kernel32.lib`). While these are Windows-specific, the concept applies to Linux and Android where linking against `libc`, `libm`, and other system libraries is fundamental.
* **Compiler Flags and ABIs:** The compiler flags managed by this file influence the Application Binary Interface (ABI) of the generated code, which dictates how different parts of the system (including the kernel and framework) interact with the compiled binary. For instance, flags related to calling conventions or structure layout are relevant here.

**Example:** On Android, if a Frida gadget (a small piece of code injected into a running process) is not compiled with the correct PIC flags (managed through `b_staticpic` if it's a static library), it might fail to load or execute correctly within the Android runtime environment.

**Logical Inference Examples:**

Let's consider the `is_source(fname)` function:

* **Hypothetical Input:** `fname = "my_code.cpp"`
* **Logic:** The function splits the filename by '.', gets the last part ("cpp"), converts it to lowercase, and checks if "cpp" is present in the `source_suffixes` set.
* **Output:** `True` (because "cpp" is in `lang_suffixes['cpp']` and thus in `source_suffixes`).

Consider the `option_enabled(boptions, options, option)` function:

* **Hypothetical Input:**
    * `boptions = {OptionKey('b_lto')}`
    * `options = {OptionKey('b_lto'): coredata.UserBooleanOption('b_lto', '...', value=True)}`
    * `option = OptionKey('b_lto')`
* **Logic:** The function checks if the `option` is in `boptions`. If it is, it retrieves the value of that option from the `options` dictionary and returns it.
* **Output:** `True`

**User Errors and Debugging:**

A user might end up investigating this file in various debugging scenarios:

1. **Build Failures Related to Compiler Options:** If the build process fails with cryptic compiler errors, a developer might suspect an issue with the compiler flags being generated. They might trace back the option settings in their Meson build definition to the logic in `compilers.py` that translates those options into flags.
2. **Unexpected Binary Behavior:** If a built Frida component behaves unexpectedly, especially related to performance or memory issues, a developer might investigate whether incorrect optimization levels or missing sanitizers were used during the build. This would lead them to examine the option handling in this file.
3. **Cross-Compilation Problems:** When setting up a cross-compilation environment, issues with finding the correct compilers or setting up the appropriate flags are common. Debugging these problems might involve inspecting how `compilers.py` selects and configures the compilers.
4. **Linker Errors:** Problems during the linking phase, such as missing symbols or unresolved dependencies, might prompt a developer to look at how the linker arguments are generated in this file.
5. **Feature Detection Issues:** If Frida's build system fails to correctly detect the presence of certain features (e.g., a specific header file or function), a developer might investigate the `check_header`, `has_header`, and `has_function` methods in this file to understand how these checks are performed.

**How User Actions Lead Here (Debugging Clues):**

Imagine a user is trying to build Frida with Link Time Optimization enabled.

1. **User Action:** The user sets the Meson option `-Db_lto=true` when configuring the build.
2. **Meson Processing:** Meson reads this option.
3. **`compilers.py` Involvement:** When the build system needs to compile or link code, it will instantiate the appropriate `Compiler` object.
4. **Option Application:** Functions like `get_base_compile_args` and `get_base_link_args` in `compilers.py` will be called. These functions check the value of the `b_lto` option (which was set by the user) and, if `True`, will add the relevant LTO flags (like `-flto`) to the compiler or linker command.
5. **Debugging Scenario:** If the linking stage fails with an LTO-related error, the user might start debugging by examining the generated linker command. They might then trace back to the `get_base_link_args` function in `compilers.py` to understand how the LTO flag was added and whether the logic is correct for their specific compiler. They might also inspect the `BASE_OPTIONS` definition to confirm the expected behavior of the `b_lto` option.

**Summary of Functionality:**

In essence, `compilers.py` in Frida's build system serves as a central point for:

* **Abstracting away the details of different compilers.**
* **Defining and managing common build options.**
* **Translating these options into compiler-specific command-line flags.**
* **Providing mechanisms for checking compiler capabilities.**
* **Facilitating the linking process.**
* **Supporting cross-compilation scenarios.**

This abstraction simplifies the build process and makes it more portable across different platforms and compiler toolchains. It also provides a structured way to manage the various flags and options that influence the characteristics of the final Frida binaries.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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