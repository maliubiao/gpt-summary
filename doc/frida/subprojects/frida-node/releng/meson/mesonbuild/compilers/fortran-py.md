Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze a specific Python file (`fortran.py`) within the Frida project and explain its functionality, its relationship to reverse engineering, its reliance on low-level concepts, its logical inferences, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for keywords and patterns that give clues about its purpose. Some immediately stand out:

* **`FortranCompiler`:**  This is the central class, so the file is definitely about handling Fortran compilers.
* **`Compiler` (inheritance):** Indicates this is part of a larger compilation system.
* **`GnuCompiler`, `IntelCompiler`, `ClangCompiler`, etc.:**  These suggest support for various specific Fortran compiler implementations.
* **`exelist`, `version`, `is_cross`, `linker`:** These are common attributes of a compiler object, dealing with the compiler executable, version, cross-compilation, and the linker.
* **`get_options`, `get_compile_args`, `get_link_args`:** These are standard methods for configuring and invoking compilers.
* **`sanity_check`:**  A common method to ensure the compiler is working correctly.
* **`module_name_to_filename`, `get_module_outdir_args`:** These point to Fortran's module system.
* **`has_function`, `has_header`:**  Methods for checking compiler capabilities.
* **`warn_args`, `optimization_args`, `debug_args`:**  Configuration for compiler behavior.
* **`SPDX-License-Identifier`, `Copyright`:** Standard licensing information.

**3. Deeper Dive and Function-by-Function Analysis:**

Next, go through the main `FortranCompiler` class and its methods, trying to understand the purpose of each one.

* **`__init__`:**  Standard constructor, initializes compiler attributes.
* **`has_function`:**  Explicitly states Fortran doesn't have this and suggests using `links` instead. This is a key piece of information.
* **`_get_basic_compiler_args`:**  Retrieves compiler and linker arguments from environment settings.
* **`sanity_check`:**  Performs a basic compilation test.
* **`get_optimization_args`, `get_debug_args`, `get_preprocess_only_args`:**  Return compiler-specific flags for these tasks.
* **`get_module_incdir_args`, `get_module_outdir_args`:** Handle Fortran module paths.
* **`compute_parameters_with_absolute_paths`:** Makes paths absolute.
* **`module_name_to_filename`:**  Converts Fortran module names to filenames (with specific variations for different compilers).
* **`find_library`:**  Searches for libraries.
* **`has_multi_arguments`, `has_multi_link_arguments`:** Checks if the compiler supports multiple arguments/linker flags.
* **`get_options`:** Returns available compiler options.

**4. Analyzing Subclasses:**

Then, look at the subclasses like `GnuFortranCompiler`, `IntelFortranCompiler`, etc. Notice how they:

* **Inherit from `FortranCompiler` and a mixin:**  This indicates they extend the base functionality and inherit common behaviors.
* **Override methods:**  They customize behavior for their specific compiler (e.g., different ways to specify the Fortran standard, module output directory, library linking).
* **Define `warn_args`:**  Specify warning levels and corresponding compiler flags.

**5. Connecting to Reverse Engineering:**

Now, start connecting the dots to the prompt's specific questions. For reverse engineering:

* **Interception:** The code *itself* isn't directly intercepting functions like Frida. However, the *tools it helps build* (by configuring the compiler) can be used for reverse engineering. Think about how compiled Fortran code might interact with a target process.
* **Code Modification:**  Similarly, this code doesn't modify binaries directly, but the compiler configurations it manages are crucial for *building* tools that *can* modify or analyze binaries.
* **Understanding Binaries:** The handling of different Fortran standards and compiler flags is relevant because the *resulting binary* will behave differently based on these settings. A reverse engineer needs to understand how these flags influence the compiled output.

**6. Connecting to Low-Level Concepts:**

Think about what's happening under the hood:

* **Binary Generation:** Compilers translate high-level code to machine code. This file configures *how* that translation happens.
* **Linking:** The linker combines compiled object files and libraries. This file deals with linker flags.
* **Operating System Interaction:** The compiler interacts with the OS to execute commands and find libraries.
* **Kernel/Framework (less direct):** While not directly interacting with the kernel/framework, the compiled Fortran code *can* interact with them. This file is a step removed but essential for creating that interaction.

**7. Logical Inferences and Examples:**

Consider how the code makes decisions:

* **Compiler Identification:**  The different subclasses are chosen based on the detected Fortran compiler.
* **Option Handling:**  The `get_options` and `get_option_compile_args` methods implement logic for mapping user-defined options to compiler flags.
* **Version Checking:**  Some features are enabled based on the compiler version (e.g., supported Fortran standards in `GnuFortranCompiler`).

Construct simple input/output examples to illustrate these inferences.

**8. Identifying User Errors:**

Think about common mistakes users might make:

* **Incorrect Compiler Installation/Path:** Meson relies on finding the compiler executable.
* **Using Unsupported Flags:** Users might try to use compiler flags not supported by the specific Fortran compiler being used.
* **Incorrectly Specifying Dependencies/Libraries:**  Linking errors are common.
* **Standard Mismatches:** Trying to use language features not supported by the selected standard.

**9. Tracing User Interaction:**

Consider how a user would end up involving this code:

* **Meson Build System:** Users interact with Meson to configure and build projects.
* **`meson.build` Files:** These files define the project structure, including the use of the Fortran compiler.
* **Compiler Selection:** Meson automatically detects the Fortran compiler, leading to the instantiation of one of the `FortranCompiler` subclasses.
* **Configuration Options:** Users might set options that influence the compiler flags generated by this code.

**10. Structuring the Answer:**

Finally, organize the information into clear sections, addressing each part of the prompt systematically. Use bullet points, code examples, and clear explanations. Start with a high-level overview and then delve into specifics. Use the keywords identified earlier to guide the structure. Iterate and refine the explanation for clarity and completeness. For instance, when discussing reverse engineering, be precise about the *indirect* relationship.

By following these steps, we can thoroughly analyze the provided Python code and provide a comprehensive answer to the prompt.
This Python file, `fortran.py`, located within the Frida project's build system (Meson), defines how the Meson build system interacts with **Fortran compilers**. It provides an abstraction layer that allows Meson to work with various Fortran compilers (like gfortran, Intel Fortran, etc.) in a consistent way.

Here's a breakdown of its functionality:

**1. Compiler Abstraction:**

* **Defines Base Class (`FortranCompiler`):** This class provides a common interface for all Fortran compilers. It includes methods for:
    * **Initialization:**  Storing the compiler's executable path, version, target machine, and whether it's a cross-compilation setup.
    * **Sanity Check:** Verifying if the compiler is working correctly by attempting to compile a simple Fortran program.
    * **Getting Compiler Arguments:** Retrieving command-line arguments for various tasks like optimization, debugging, preprocessing, including module directories, and specifying module output directories.
    * **Finding Libraries:** Locating Fortran libraries.
    * **Checking Compiler Capabilities:** Determining if the compiler supports specific arguments or link arguments.
    * **Handling Fortran Modules:**  Converting module names to filenames and specifying output directories for compiled modules.
    * **Getting Language Standard Options:** Providing options for selecting the Fortran language standard (e.g., f95, f2003).

* **Defines Specific Compiler Subclasses:**  It includes subclasses for various Fortran compilers, inheriting from `FortranCompiler` and potentially from mixin classes (like `GnuCompiler`, `IntelGnuLikeCompiler`, `ClangCompiler`, etc.). These subclasses customize the behavior for each specific compiler, adapting to their command-line syntax and specific features. Examples include:
    * `GnuFortranCompiler` (gfortran)
    * `IntelFortranCompiler`
    * `ClangFortranCompiler` (Flang)
    * `PGIFortranCompiler`
    * And others like `SunFortranCompiler`, `NAGFortranCompiler`, etc.

**2. Interaction with Meson Build System:**

* This file is part of the Meson build system. Meson uses these classes to understand how to invoke the Fortran compiler, pass arguments, and manage the compilation process when a project uses Fortran.
* When Meson encounters Fortran source files in a project, it uses the logic in this file to determine the appropriate compiler commands.

**3. Handling Compiler-Specific Syntax and Features:**

* The subclasses tailor the compiler arguments and behavior based on the specific Fortran compiler being used. For example:
    * The way to specify the output directory for compiled Fortran modules (`.mod` files) varies between compilers (e.g., `-module` for some, `-J` for others).
    * Warning levels and their corresponding compiler flags are defined specifically for each compiler.
    * The syntax for preprocessing (`-cpp` or `-fpp`) can differ.

**Relationship to Reverse Engineering:**

While this file itself doesn't directly perform reverse engineering, it plays a crucial role in **building tools** that *can* be used for reverse engineering when those tools involve Fortran code. Here's how:

* **Building Instrumentation Tools:** Frida is a dynamic instrumentation toolkit. If you're building a Frida gadget or agent that includes Fortran code (perhaps for performance-critical parts or interacting with existing Fortran libraries in the target process), this `fortran.py` file would be involved in compiling that Fortran code.
* **Analyzing Fortran Binaries:** If you're developing a reverse engineering tool that needs to analyze or interact with a target application written in Fortran, you might need to compile small Fortran snippets or libraries to test interactions or understand specific Fortran features. Meson, using this file, would be the build system managing that compilation.
* **Example:** Imagine you want to hook a function in a Fortran library within an Android application using Frida. You might write a Frida agent that includes some Fortran code to efficiently interact with that library. Meson, guided by `fortran.py`, would compile that Fortran part of your agent.

**In essence, `fortran.py` enables the building of reverse engineering tools that leverage or interact with Fortran code.**

**Involvement of Binary 底层, Linux, Android 内核及框架 Knowledge:**

This file touches upon these areas indirectly through the compilation process:

* **Binary 底层 (Binary Low-Level):**
    * **Compiler Flags:**  The compiler flags defined in this file (e.g., optimization levels, debugging flags) directly influence the generated machine code (the binary). Understanding these flags is crucial for reverse engineers analyzing the behavior and performance of compiled Fortran code.
    * **Linking:** The linker settings managed here determine how different parts of the compiled code and libraries are combined into the final executable. This is fundamental to understanding the structure of a binary.
    * **Fortran Modules:** The way Fortran modules are compiled and linked affects the binary's structure and how different parts of the Fortran code interact.

* **Linux:**
    * **Compiler Executables:** On Linux, this file would interact with Fortran compilers like `gfortran`, which are standard tools in the Linux development environment.
    * **Shared Libraries:**  The process of finding and linking Fortran libraries (.so files on Linux) is handled here.
    * **File System Paths:** The code manipulates file paths to locate compiler executables, include directories, and library paths, all within the Linux file system structure.

* **Android Kernel and Framework (Indirect):**
    * **Cross-Compilation:** The `is_cross` parameter in the compiler initialization indicates support for cross-compiling. When building Frida gadgets for Android, a cross-compiler is used (likely targeting ARM architecture). This file would be involved in configuring the Fortran compiler for that cross-compilation.
    * **Native Libraries:** Android applications often use native libraries (written in C, C++, and potentially Fortran). If a Frida gadget interacts with such a Fortran native library, the compilation of that gadget's Fortran code would be managed by this file, respecting Android's specific build environment.

**Example Scenarios:**

* **Scenario 1 (Logical Inference):**
    * **Hypothetical Input:** Meson is building a project for Linux, detects the `gfortran` compiler version 9.0, and needs to compile a Fortran source file.
    * **Logical Steps:**
        1. Meson identifies the compiler as `gfortran`.
        2. It instantiates the `GnuFortranCompiler` class.
        3. When compiling, Meson calls methods like `get_optimization_args('0')` (no optimization), which would return `[]` (an empty list of arguments for gfortran at optimization level 0).
        4. If debugging is enabled, `get_debug_args(True)` might return `['-g']` for gfortran.
    * **Hypothetical Output:** The command line used to compile the Fortran file would include `-g` if debugging is enabled and no optimization flags.

* **Scenario 2 (User/Programming Error):**
    * **User Error:** A user might have an old version of `gfortran` installed that doesn't support the `-std=f2018` flag, but they specify `fortran_std: 'f2018'` in their `meson_options.txt`.
    * **How this manifests:** When Meson calls `get_option_compile_args` in `GnuFortranCompiler`, it would try to add `-std=f2018`. If the compiler doesn't recognize this flag, the compilation would fail with an error message from `gfortran` itself, indicating an invalid command-line option.
    * **Debugging Clue:** The error message from the compiler would point to the problematic flag. The user or developer would need to check the installed `gfortran` version and the supported standards.

**User Operations Leading to This Code:**

Here's a step-by-step breakdown of how a user's actions can lead to the execution of code within `fortran.py`:

1. **User develops a Frida gadget or a standalone application using Fortran.**  The project would have Fortran source files (e.g., `.f90`, `.f`).
2. **User decides to use the Meson build system.** They create a `meson.build` file at the root of their project.
3. **The `meson.build` file specifies that Fortran is a language being used in the project.** This could be done using the `fortran_library()` or `executable()` Meson functions.
4. **User runs the command `meson setup builddir`** (or a similar command to configure the build).
5. **Meson analyzes the project and detects the use of Fortran.**
6. **Meson searches for a Fortran compiler.** It will look in standard locations and the user's `PATH` environment variable.
7. **Meson identifies the specific Fortran compiler** (e.g., `gfortran`, `ifort`).
8. **Based on the identified compiler, Meson loads the corresponding class from `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/fortran.py`**. For example, if `gfortran` is found, the `GnuFortranCompiler` class is instantiated.
9. **During the configuration and build process, Meson calls various methods of the loaded compiler class** to:
    * **Check the compiler's version.**
    * **Perform a sanity check.**
    * **Determine the correct command-line arguments for compiling and linking.** This is where methods like `get_optimization_args`, `get_debug_args`, `get_module_outdir_args`, etc., are invoked.
10. **When the user runs `meson compile -C builddir` (or `ninja -C builddir`)**, the actual compilation commands are executed using the information gathered from the `fortran.py` file.

**In summary, `fortran.py` is a crucial component within Frida's build system (Meson) that enables the compilation of Fortran code, which can be part of Frida itself or user-developed extensions and tools. It abstracts away the complexities of different Fortran compilers, providing a consistent way for Meson to manage the Fortran build process.**

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2017 The Meson development team

from __future__ import annotations

import typing as T
import os

from .. import coredata
from .compilers import (
    clike_debug_args,
    Compiler,
    CompileCheckMode,
)
from .mixins.clike import CLikeCompiler
from .mixins.gnu import GnuCompiler,  gnu_optimization_args
from .mixins.intel import IntelGnuLikeCompiler, IntelVisualStudioLikeCompiler
from .mixins.clang import ClangCompiler
from .mixins.elbrus import ElbrusCompiler
from .mixins.pgi import PGICompiler

from mesonbuild.mesonlib import (
    version_compare, MesonException,
    LibType, OptionKey,
)

if T.TYPE_CHECKING:
    from ..coredata import MutableKeyedOptionDictType, KeyedOptionDictType
    from ..dependencies import Dependency
    from ..envconfig import MachineInfo
    from ..environment import Environment
    from ..linkers.linkers import DynamicLinker
    from ..mesonlib import MachineChoice


class FortranCompiler(CLikeCompiler, Compiler):

    language = 'fortran'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        Compiler.__init__(self, [], exelist, version, for_machine, info,
                          is_cross=is_cross, full_version=full_version, linker=linker)
        CLikeCompiler.__init__(self)

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        raise MesonException('Fortran does not have "has_function" capability.\n'
                             'It is better to test if a Fortran capability is working like:\n\n'
                             "meson.get_compiler('fortran').links('block; end block; end program')\n\n"
                             'that example is to see if the compiler has Fortran 2008 Block element.')

    def _get_basic_compiler_args(self, env: 'Environment', mode: CompileCheckMode) -> T.Tuple[T.List[str], T.List[str]]:
        cargs = env.coredata.get_external_args(self.for_machine, self.language)
        largs = env.coredata.get_external_link_args(self.for_machine, self.language)
        return cargs, largs

    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        source_name = 'sanitycheckf.f90'
        code = 'program main; print *, "Fortran compilation is working."; end program\n'
        return self._sanity_check_impl(work_dir, environment, source_name, code)

    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        return gnu_optimization_args[optimization_level]

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        return clike_debug_args[is_debug]

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-cpp'] + super().get_preprocess_only_args()

    def get_module_incdir_args(self) -> T.Tuple[str, ...]:
        return ('-I', )

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-module', path]

    def compute_parameters_with_absolute_paths(self, parameter_list: T.List[str],
                                               build_dir: str) -> T.List[str]:
        for idx, i in enumerate(parameter_list):
            if i[:2] == '-I' or i[:2] == '-L':
                parameter_list[idx] = i[:2] + os.path.normpath(os.path.join(build_dir, i[2:]))

        return parameter_list

    def module_name_to_filename(self, module_name: str) -> str:
        if '_' in module_name:  # submodule
            s = module_name.lower()
            if self.id in {'gcc', 'intel', 'intel-cl'}:
                filename = s.replace('_', '@') + '.smod'
            elif self.id in {'pgi', 'flang'}:
                filename = s.replace('_', '-') + '.mod'
            else:
                filename = s + '.mod'
        else:  # module
            filename = module_name.lower() + '.mod'

        return filename

    def find_library(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                     libtype: LibType = LibType.PREFER_SHARED, lib_prefix_warning: bool = True) -> T.Optional[T.List[str]]:
        code = 'stop; end program'
        return self._find_library_impl(libname, env, extra_dirs, code, libtype, lib_prefix_warning)

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_arguments(args, env, 'stop; end program')

    def has_multi_link_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_link_arguments(args, env, 'stop; end program')

    def get_options(self) -> 'MutableKeyedOptionDictType':
        return self.update_options(
            super().get_options(),
            self.create_option(coredata.UserComboOption,
                               OptionKey('std', machine=self.for_machine, lang=self.language),
                               'Fortran language standard to use',
                               ['none'],
                               'none'),
        )


class GnuFortranCompiler(GnuCompiler, FortranCompiler):

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 defines: T.Optional[T.Dict[str, str]] = None,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        GnuCompiler.__init__(self, defines)
        default_warn_args = ['-Wall']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-Wpedantic', '-fimplicit-none'],
                          'everything': default_warn_args + ['-Wextra', '-Wpedantic', '-fimplicit-none']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        fortran_stds = ['legacy', 'f95', 'f2003']
        if version_compare(self.version, '>=4.4.0'):
            fortran_stds += ['f2008']
        if version_compare(self.version, '>=8.0.0'):
            fortran_stds += ['f2018']
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none'] + fortran_stds
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        if std.value != 'none':
            args.append('-std=' + std.value)
        return args

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        # Disabled until this is fixed:
        # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=62162
        # return ['-cpp', '-MD', '-MQ', outtarget]
        return []

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-J' + path]

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # We need to apply the search prefix here, as these link arguments may
        # be passed to a different compiler with a different set of default
        # search paths, such as when using Clang for C/C++ and gfortran for
        # fortran,
        search_dirs: T.List[str] = []
        for d in self.get_compiler_dirs(env, 'libraries'):
            search_dirs.append(f'-L{d}')
        return search_dirs + ['-lgfortran', '-lm']

    def has_header(self, hname: str, prefix: str, env: 'Environment', *,
                   extra_args: T.Union[None, T.List[str], T.Callable[['CompileCheckMode'], T.List[str]]] = None,
                   dependencies: T.Optional[T.List['Dependency']] = None,
                   disable_cache: bool = False) -> T.Tuple[bool, bool]:
        '''
        Derived from mixins/clike.py:has_header, but without C-style usage of
        __has_include which breaks with GCC-Fortran 10:
        https://github.com/mesonbuild/meson/issues/7017
        '''
        code = f'{prefix}\n#include <{hname}>'
        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies, mode=CompileCheckMode.PREPROCESS, disable_cache=disable_cache)


class ElbrusFortranCompiler(ElbrusCompiler, FortranCompiler):
    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 defines: T.Optional[T.Dict[str, str]] = None,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine, is_cross,
                                 info, linker=linker, full_version=full_version)
        ElbrusCompiler.__init__(self)

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        fortran_stds = ['f95', 'f2003', 'f2008', 'gnu', 'legacy', 'f2008ts']
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none'] + fortran_stds
        return opts

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-J' + path]


class G95FortranCompiler(FortranCompiler):

    LINKER_PREFIX = '-Wl,'
    id = 'g95'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-Wall']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-Wextra'],
                          '3': default_warn_args + ['-Wextra', '-pedantic'],
                          'everything': default_warn_args + ['-Wextra', '-pedantic']}

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-fmod=' + path]


class SunFortranCompiler(FortranCompiler):

    LINKER_PREFIX = '-Wl,'
    id = 'sun'

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-fpp']

    def get_always_args(self) -> T.List[str]:
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        return []

    def get_module_incdir_args(self) -> T.Tuple[str, ...]:
        return ('-M', )

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-moddir=' + path]

    def openmp_flags(self) -> T.List[str]:
        return ['-xopenmp']


class IntelFortranCompiler(IntelGnuLikeCompiler, FortranCompiler):

    file_suffixes = ('f90', 'f', 'for', 'ftn', 'fpp', )
    id = 'intel'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        # FIXME: Add support for OS X and Windows in detect_fortran_compiler so
        # we are sent the type of compiler
        IntelGnuLikeCompiler.__init__(self)
        default_warn_args = ['-warn', 'general', '-warn', 'truncated_source']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['-warn', 'unused'],
                          '3': ['-warn', 'all'],
                          'everything': ['-warn', 'all']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none', 'legacy', 'f95', 'f2003', 'f2008', 'f2018']
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        stds = {'legacy': 'none', 'f95': 'f95', 'f2003': 'f03', 'f2008': 'f08', 'f2018': 'f18'}
        if std.value != 'none':
            args.append('-stand=' + stds[std.value])
        return args

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-cpp', '-EP']

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # TODO: needs default search path added
        return ['-lifcore', '-limf']

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return ['-gen-dep=' + outtarget, '-gen-depformat=make']


class IntelLLVMFortranCompiler(IntelFortranCompiler):

    id = 'intel-llvm'


class IntelClFortranCompiler(IntelVisualStudioLikeCompiler, FortranCompiler):

    file_suffixes = ('f90', 'f', 'for', 'ftn', 'fpp', )
    always_args = ['/nologo']

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice,
                 is_cross: bool, info: 'MachineInfo', target: str,
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        IntelVisualStudioLikeCompiler.__init__(self, target)

        default_warn_args = ['/warn:general', '/warn:truncated_source']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args + ['/warn:unused'],
                          '3': ['/warn:all'],
                          'everything': ['/warn:all']}

    def get_options(self) -> 'MutableKeyedOptionDictType':
        opts = FortranCompiler.get_options(self)
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        opts[key].choices = ['none', 'legacy', 'f95', 'f2003', 'f2008', 'f2018']
        return opts

    def get_option_compile_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        args: T.List[str] = []
        key = OptionKey('std', machine=self.for_machine, lang=self.language)
        std = options[key]
        stds = {'legacy': 'none', 'f95': 'f95', 'f2003': 'f03', 'f2008': 'f08', 'f2018': 'f18'}
        if std.value != 'none':
            args.append('/stand:' + stds[std.value])
        return args

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['/module:' + path]


class IntelLLVMClFortranCompiler(IntelClFortranCompiler):

    id = 'intel-llvm-cl'

class PathScaleFortranCompiler(FortranCompiler):

    id = 'pathscale'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-fullwarn']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def openmp_flags(self) -> T.List[str]:
        return ['-mp']


class PGIFortranCompiler(PGICompiler, FortranCompiler):

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        PGICompiler.__init__(self)

        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args + ['-Mdclchk'],
                          'everything': default_warn_args + ['-Mdclchk']}

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # TODO: needs default search path added
        return ['-lpgf90rtl', '-lpgf90', '-lpgf90_rpm1', '-lpgf902',
                '-lpgf90rtl', '-lpgftnrtl', '-lrt']


class NvidiaHPC_FortranCompiler(PGICompiler, FortranCompiler):

    id = 'nvidia_hpc'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        PGICompiler.__init__(self)

        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args + ['-Mdclchk'],
                          'everything': default_warn_args + ['-Mdclchk']}


class FlangFortranCompiler(ClangCompiler, FortranCompiler):

    id = 'flang'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        ClangCompiler.__init__(self, {})
        default_warn_args = ['-Minform=inform']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        # We need to apply the search prefix here, as these link arguments may
        # be passed to a different compiler with a different set of default
        # search paths, such as when using Clang for C/C++ and gfortran for
        # fortran,
        # XXX: Untested....
        search_dirs: T.List[str] = []
        for d in self.get_compiler_dirs(env, 'libraries'):
            search_dirs.append(f'-L{d}')
        return search_dirs + ['-lflang', '-lpgmath']

class ArmLtdFlangFortranCompiler(FlangFortranCompiler):

    id = 'armltdflang'

class Open64FortranCompiler(FortranCompiler):

    id = 'open64'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        default_warn_args = ['-fullwarn']
        self.warn_args = {'0': [],
                          '1': default_warn_args,
                          '2': default_warn_args,
                          '3': default_warn_args,
                          'everything': default_warn_args}

    def openmp_flags(self) -> T.List[str]:
        return ['-mp']


class NAGFortranCompiler(FortranCompiler):

    id = 'nagfor'

    def __init__(self, exelist: T.List[str], version: str, for_machine: MachineChoice, is_cross: bool,
                 info: 'MachineInfo',
                 linker: T.Optional['DynamicLinker'] = None,
                 full_version: T.Optional[str] = None):
        FortranCompiler.__init__(self, exelist, version, for_machine,
                                 is_cross, info, linker=linker,
                                 full_version=full_version)
        # Warnings are on by default; -w disables (by category):
        self.warn_args = {
            '0': ['-w=all'],
            '1': [],
            '2': [],
            '3': [],
            'everything': [],
        }

    def get_always_args(self) -> T.List[str]:
        return self.get_nagfor_quiet(self.version)

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        return ['-mdir', path]

    @staticmethod
    def get_nagfor_quiet(version: str) -> T.List[str]:
        return ['-quiet'] if version_compare(version, '>=7100') else []

    def get_pic_args(self) -> T.List[str]:
        return ['-PIC']

    def get_preprocess_only_args(self) -> T.List[str]:
        return ['-fpp']

    def get_std_exe_link_args(self) -> T.List[str]:
        return self.get_always_args()

    def openmp_flags(self) -> T.List[str]:
        return ['-openmp']

"""

```