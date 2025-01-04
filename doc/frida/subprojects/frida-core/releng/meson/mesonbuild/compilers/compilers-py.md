Response:
The user wants a summary of the functionality of the Python code provided. I need to identify the key aspects of this file, focusing on its role in the Frida dynamic instrumentation tool. The request also asks for specific examples related to reverse engineering, low-level operations (Linux/Android kernel/framework), logical reasoning (with input/output examples), common user errors, and debugging context.

Here's a breakdown of the file's purpose and features:

1. **Compiler Definitions:** The core function is to define and manage information about different compilers used for various programming languages (C, C++, Rust, etc.).

2. **File Type Recognition:** The code defines sets of file suffixes for headers, objects, libraries, and source files, along with functions to check if a given file belongs to these categories.

3. **Compilation and Linking Options:**  It manages various compiler and linker flags related to optimization, debugging, link-time optimization (LTO), sanitizers, profile-guided optimization (PGO), code coverage, and position-independent code (PIC/PIE).

4. **Cross-Compilation Support:** It includes mechanisms for handling cross-compilation scenarios, including the concept of an "execution wrapper."

5. **Compile and Run Checks:** The code provides functions to compile and run small code snippets to test compiler capabilities, header availability, function existence, data type sizes and alignments, and other environment characteristics. It also includes caching for these checks to speed up subsequent builds.

6. **Environment Variable Handling:** It maps programming languages to their corresponding environment variables for compiler flags (CFLAGS, CXXFLAGS, etc.).

7. **Option Management:** The code defines a system for managing build options and their default values.

Now, let's address the specific requirements of the prompt:

*   **Reverse Engineering:**  Frida hooks into running processes. Knowing the compiler and linker options used to build those processes can be crucial for understanding their layout, debugging symbols, and security mitigations.

*   **Binary/Low-Level, Linux/Android Kernel/Framework:** The compiler options related to PIC/PIE are directly relevant to how executables and shared libraries are loaded into memory, which is fundamental to operating system kernels and frameworks like Android's.

*   **Logical Reasoning (Input/Output):** The `cached_run` function demonstrates a logical flow where the input is source code and compiler arguments, and the output is the execution result (return code, stdout, stderr).

*   **User/Programming Errors:**  Incorrectly specifying compiler or linker options can lead to build failures. For example, forgetting to include a necessary library path can cause linking errors.

*   **Debugging Context:** This file is part of the Meson build system, which Frida uses. Understanding this file helps debug build issues or when adding support for new compilers.

I will now formulate the summary based on these observations.
This Python code file, located within the Frida project's build system (Meson), serves as a central repository for defining and managing information about various compilers used in the build process. Its primary function is to abstract away the specifics of different compilers (like GCC, Clang, MSVC) and provide a consistent interface for the build system to interact with them.

Here's a breakdown of its functionalities:

1. **Compiler Definition and Attributes:** It defines classes and data structures to represent different compilers. This includes storing information like the compiler's executable path, version, supported languages, and unique identifier.

2. **File Type Recognition:** It defines sets of file suffixes for various file types (headers, source files, object files, libraries) associated with different programming languages. This allows the build system to correctly identify the type of a given file.

3. **Compilation and Linking Option Management:** The code manages compiler and linker flags related to various build features such as:
    *   **Optimization levels:**  Mapping user-friendly optimization levels (like "0", "1", "2", "3", "s") to specific compiler flags (e.g., `-O1`, `-O2`, `-Os`).
    *   **Debugging information:**  Mapping debug settings to compiler flags (e.g., `-g`).
    *   **Link-Time Optimization (LTO):**  Managing flags for enabling and configuring LTO.
    *   **Code sanitizers:**  Handling flags for enabling sanitizers like AddressSanitizer, ThreadSanitizer, etc.
    *   **Profile-Guided Optimization (PGO):**  Managing flags for generating and using PGO profiles.
    *   **Code coverage:**  Handling flags for enabling code coverage instrumentation.
    *   **Position Independent Code (PIC/PIE):**  Managing flags for building position-independent code for shared libraries and executables.
    *   **Run-time library selection (MSVC):**  Handling options for selecting the appropriate Visual Studio run-time library.

4. **Compile and Run Checks:**  The code provides functions (`check_header`, `has_header`, `has_function`, `run`, `cached_run`, etc.) to perform compile-time checks. These checks compile and sometimes execute small code snippets to determine the availability of headers, functions, data types, and other environment characteristics. The `cached_run` function specifically implements caching for these checks.

5. **Cross-Compilation Support:** The code includes considerations for cross-compilation, where the build machine and target machine are different. It introduces the concept of an "execution wrapper" for running test executables on the target machine.

6. **Environment Variable Mapping:** It maps programming languages to their corresponding environment variables used for passing compiler flags (e.g., 'c' to 'CFLAGS', 'cpp' to 'CXXFLAGS').

7. **Option Handling:**  It defines a system for managing build options (`BaseOption`) with descriptions, default values, and allowed choices. These options are then used to generate compiler-specific command-line arguments.

**Relation to Reverse Engineering (with examples):**

This file is indirectly related to reverse engineering by defining the tools and options used to create the binaries that are later targeted for analysis and instrumentation by Frida.

*   **Compiler and Linker Flags:** The specific compiler and linker flags used during the build process can significantly impact the final binary. For example, if a binary is built with debugging symbols (`-g`), reverse engineers can use debuggers more effectively. Conversely, if a binary is stripped of symbols, reverse engineering becomes more challenging. Understanding which flags are used (as defined in this file) can give insights into the binary's characteristics.
*   **Position Independent Code (PIC/PIE):** Whether a shared library or executable is built with PIC/PIE affects its memory layout and how it's loaded by the operating system. Reverse engineers need to be aware of these properties when analyzing code. The `b_staticpic` and `b_pie` options in this file control this.
*   **Link-Time Optimization (LTO):** LTO can significantly change the structure of the final binary by performing optimizations across multiple compilation units. This can make reverse engineering more complex as function boundaries might be less clear. The `b_lto` option controls LTO.
*   **Sanitizers:** While primarily for development, if a binary is built with sanitizers enabled (even accidentally), the sanitizer's runtime checks can be observed during reverse engineering, potentially revealing information about memory management or threading issues. The `b_sanitize` option manages these.

**Binary 底层, Linux, Android Kernel & Framework (with examples):**

This file directly interacts with binary-level concerns and build processes on Linux and Android:

*   **Object File and Library Suffixes:** The `obj_suffixes` and `lib_suffixes` lists define the common extensions for object files (`.o`, `.obj`) and libraries (`.so`, `.a`, `.dll`), which are fundamental binary artifacts in Linux and Android development.
*   **Shared Libraries (.so):** The `soregex` (shared object regular expression) specifically targets `.so` files, which are the standard for dynamic libraries on Linux and Android.
*   **Position Independent Code (PIC):**  The `b_staticpic` and `b_pie` options are crucial for building shared libraries and executables that can be loaded at arbitrary memory addresses, a requirement for modern operating systems like Linux and Android for security and memory management. This is particularly relevant for Android framework components.
*   **Linker Flags:** Many linker flags controlled in this file (like `-Wl,--as-needed`, `-Wl,--no-undefined`) directly influence how the final binary is linked and how dependencies are resolved, which are core concepts in Linux and Android system programming.
*   **Kernel Modules:** While not explicitly targeted, the principles of compiling and linking with specific flags are similar for kernel modules, and the underlying tools and concepts are the same.

**Logical Reasoning (with examples):**

The code employs logical reasoning for tasks like determining file types and applying appropriate compiler flags.

*   **Input:** A filename `my_source.cpp`.
*   **Reasoning:** The code checks if the filename ends with a suffix listed in `lang_suffixes['cpp']`. Since `.cpp` is present, it concludes this is a C++ source file.
*   **Output:** The build system knows to use the C++ compiler for this file.

*   **Input:** The build option `b_optimize` is set to `2`.
*   **Reasoning:** The code looks up the value `2` in the `clike_optimization_args` dictionary.
*   **Output:** The compiler will be invoked with the `-O2` flag.

**User or Programming Common Usage Errors (with examples):**

This file helps prevent certain user errors by providing a structured way to manage compiler options. However, errors can still occur:

*   **Incorrect Option Values:** If a user provides an invalid value for a build option (e.g., an incorrect sanitizer name for `b_sanitize`), the build system might fail or behave unexpectedly. The `choices` attribute in `BaseOption` helps limit these errors.
*   **Missing Dependencies:** While this file doesn't directly handle dependencies, incorrect compiler or linker settings can lead to errors where the linker cannot find required libraries. This could stem from missing library paths that a user needs to provide.
*   **Cross-Compilation Misconfiguration:** In cross-compilation scenarios, if the correct compiler for the target architecture isn't selected or the execution wrapper isn't configured properly, the build or test execution will fail.

**User Operation to Reach This Code (Debugging Clue):**

A user interacting with Frida indirectly triggers the execution of this code. Here's a likely sequence:

1. **User Configures Build:** The user interacts with Frida's build system (likely through a `meson_options.txt` file or command-line arguments passed to Meson) to set various build options (e.g., enabling LTO, selecting a sanitizer, setting the build type).
2. **Meson Invokes:** When the user runs the Meson configuration step (e.g., `meson setup build`), Meson reads the build definition (`meson.build` files) and the user's options.
3. **Compiler Detection:** Meson needs to determine which compilers are available on the system. The `detect.py` file mentioned in the docstring (which is a sibling to this file in the actual source) is used for this.
4. **Compiler Information Loading:** The information defined in `compilers.py` is loaded by Meson to understand the capabilities and flags of the detected compilers.
5. **Target Compilation:** When Meson compiles a target (e.g., a Frida gadget or server component), it uses the information in `compilers.py` to construct the correct compiler commands with the appropriate flags based on the user's selected options and the target's language.
6. **Debugging Scenario:** If a build error occurs related to compiler flags or linking, a developer might need to examine `compilers.py` to understand how a particular option is translated into compiler arguments or to add support for a new compiler.

**Summary of Functionalities:**

In summary, the `compilers.py` file in Frida's build system serves as a **centralized configuration and management point for compiler-related information**. It defines the attributes of different compilers, manages compilation and linking options, provides mechanisms for compile-time checks, supports cross-compilation, and maps languages to their corresponding environment variables. This abstraction allows the Meson build system to work consistently across different compilers and operating systems.

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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