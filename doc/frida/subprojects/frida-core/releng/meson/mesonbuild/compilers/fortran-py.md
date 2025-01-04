Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of the `fortran.py` file within the Frida project. They're particularly interested in connections to reverse engineering, low-level details, reasoning, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan & High-Level Overview:**

The first step is to read through the code and identify the main components. I see:

* **Imports:** Standard Python imports plus imports from other parts of the Meson build system (`..coredata`, `.compilers`, `.mixins`, `mesonbuild.mesonlib`). This immediately tells me this file is part of a larger build system.
* **Class `FortranCompiler`:**  This is the core of the file. It inherits from `CLikeCompiler` and `Compiler`, suggesting it handles the specifics of compiling Fortran code.
* **Subclasses of `FortranCompiler`:**  There are many subclasses like `GnuFortranCompiler`, `IntelFortranCompiler`, etc. This indicates support for various Fortran compilers.
* **Methods within the classes:** Methods like `__init__`, `has_function`, `sanity_check`, `get_optimization_args`, `get_debug_args`, `get_module_outdir_args`, `find_library`, etc. suggest these classes are responsible for tasks related to compiling, linking, and checking Fortran code.

**3. Deeper Dive into Functionality:**

Now, I'll go through each significant part and try to understand its purpose:

* **`FortranCompiler` base class:**
    * `language = 'fortran'`: Clearly defines the language being handled.
    * `__init__`: Initializes compiler properties like executable path, version, target machine, etc.
    * `has_function`:  Intentionally raises an exception, indicating Fortran doesn't have the same concept of functions for compile-time checks as C/C++. It suggests using `links` instead. *This is a key piece of information for the user.*
    * `_get_basic_compiler_args`:  Retrieves compiler and linker flags from Meson's configuration.
    * `sanity_check`:  Performs a basic compilation test to ensure the compiler is working.
    * `get_optimization_args`, `get_debug_args`, `get_preprocess_only_args`:  Return compiler flags for optimization, debugging, and preprocessing.
    * `get_module_incdir_args`, `get_module_outdir_args`:  Handle Fortran module paths.
    * `compute_parameters_with_absolute_paths`:  Ensures paths are absolute, important for consistent builds.
    * `module_name_to_filename`: Converts Fortran module names to filenames (handling submodules). *This is specific to Fortran and could be relevant to reverse engineering if someone is examining compiled modules.*
    * `find_library`:  Searches for Fortran libraries.
    * `has_multi_arguments`, `has_multi_link_arguments`: Checks if the compiler supports multiple arguments or link arguments in a single invocation.
    * `get_options`: Defines configurable options for the Fortran compiler (like the language standard).

* **Subclasses (e.g., `GnuFortranCompiler`, `IntelFortranCompiler`):**
    * These subclasses override and specialize the methods of the base class to handle the specific quirks and features of each Fortran compiler (GNU, Intel, PGI, etc.).
    * They often define default warning flags, supported language standards, and compiler-specific flags for modules, dependencies, etc.

**4. Connecting to Reverse Engineering:**

* **Module Handling (`module_name_to_filename`, `get_module_outdir_args`):** When reverse engineering Fortran code, understanding how modules are compiled and named is crucial. This code shows the naming conventions for different compilers (e.g., `.mod` vs. `.smod`).
* **Compiler-Specific Behavior:** The many subclasses highlight that different Fortran compilers have different behaviors and flags. A reverse engineer might need to know which compiler was used to build a binary to understand its structure and potential optimizations.
* **Debugging Information (`get_debug_args`):** While this code doesn't directly *do* debugging, it sets up the flags that influence whether debugging symbols are included in the compiled binary, which is essential for reverse engineering.
* **Standard Library Linking (`language_stdlib_only_link_flags`):** Knowing which standard libraries are linked is important for understanding dependencies when analyzing a compiled Fortran application.

**5. Connecting to Low-Level Details, Linux/Android Kernel/Framework:**

* **Binary Compilation:** The entire purpose of this code is to orchestrate the compilation process, which ultimately results in machine code (binary).
* **Compiler Flags:**  Flags like `-I`, `-L`, `-std`, optimization levels, and warning levels directly affect the generated binary.
* **Linking:** The code handles linking libraries, which is a fundamental step in creating executable binaries.
* **Operating System Interactions:**  The code interacts with the operating system to execute the compiler and linker.
* **Cross-Compilation (`is_cross`):** The code supports cross-compilation, which is essential for building software for different architectures (like building Android apps on a Linux machine). While it doesn't directly interact with the Android kernel, it's part of the toolchain used to build software that *could* run on Android.

**6. Logical Reasoning (Hypothetical Input/Output):**

* **Input:**  A Meson build definition (`meson.build`) specifies that a Fortran project should be built using the GNU Fortran compiler (`gfortran`).
* **Processing:** Meson will identify `gfortran` as the compiler and instantiate `GnuFortranCompiler`. It will call methods on this object to get the necessary compiler and linker flags based on user-defined options (like optimization level or Fortran standard).
* **Output:** The `GnuFortranCompiler` object will return lists of strings representing the command-line arguments to be passed to `gfortran`. For example, `get_optimization_args('3')` might return `['-O3']`, and `get_module_outdir_args('build/modules')` might return `['-Jbuild/modules']`.

**7. Common User Errors:**

* **Incorrect Compiler Selection:**  If the user forces the use of a specific Fortran compiler that isn't installed or compatible with their system, Meson will likely fail.
* **Invalid Language Standard:** Specifying an unsupported Fortran standard (e.g., using `-std=f2018` with an older compiler) will lead to compiler errors. The `get_options` and `get_option_compile_args` methods try to prevent this, but users can still make mistakes.
* **Missing Dependencies:**  If the Fortran code relies on external libraries that aren't found, the linking stage will fail.
* **Incorrect Module Paths:** If module include paths are not correctly specified, the compiler won't be able to find necessary module files.

**8. User Path to This Code (Debugging Scenario):**

A developer working on Frida might encounter this code during debugging in the following scenarios:

1. **Adding Support for a New Fortran Compiler:**  If Frida needs to interact with software built with a Fortran compiler that isn't currently supported by Meson, a developer would need to create a new subclass in this file.
2. **Troubleshooting Build Issues:** If a user reports a problem building Frida or a target application that uses Fortran, a developer might examine this code to understand how Meson is invoking the Fortran compiler and linker. They might add print statements or use a debugger to inspect the arguments being generated.
3. **Understanding Build System Mechanics:**  A new contributor to Frida might read this code to understand how Meson handles different programming languages and compilers.
4. **Investigating Feature Requests:** If a user requests a new feature related to Fortran compilation (e.g., supporting a specific compiler flag), a developer would likely modify this file.

By following this systematic approach, I can comprehensively analyze the code and provide a detailed explanation that addresses all aspects of the user's request. The key is to break down the code into smaller, manageable parts and then connect those parts to the broader context of Frida, reverse engineering, and software development.This Python code file, `fortran.py`, is a module within the Meson build system that specifically handles **Fortran language compilation**. Meson is used by the Frida dynamic instrumentation toolkit to manage its build process. Therefore, this file defines how Meson interacts with Fortran compilers when building Frida or projects that Frida might interact with.

Here's a breakdown of its functionalities:

**1. Defining Fortran Compiler Abstraction:**

* **`FortranCompiler` Class:** This is the base class that defines the common interface and behavior for all Fortran compilers supported by Meson. It inherits from `CLikeCompiler` (for C-like language features) and `Compiler`.
* **Compiler-Specific Subclasses:**  The file contains numerous subclasses of `FortranCompiler`, each representing a specific Fortran compiler like `GnuFortranCompiler` (gfortran), `IntelFortranCompiler` (ifort), `PGIFortranCompiler`, `FlangFortranCompiler`, etc. These subclasses customize the behavior for their respective compilers.

**2. Core Compilation Functionalities:**

* **`__init__`:**  Initializes the compiler object with information like the compiler executable path, version, target machine, and whether it's a cross-compilation.
* **`sanity_check`:**  Performs a basic compilation test to verify that the Fortran compiler is working correctly. It compiles a simple "Hello, world!" program.
* **`compile` (inherited from `Compiler`):**  This method (though not explicitly shown in this snippet, it's part of the base class) is responsible for taking Fortran source code and invoking the compiler to produce object files.
* **`link` (inherited from `Compiler`):** Similarly, this method handles the linking stage, taking object files and libraries to create the final executable or shared library.
* **`get_optimization_args`:**  Returns compiler flags for different levels of optimization (e.g., `-O0`, `-O2`, `-O3` for GCC/gfortran).
* **`get_debug_args`:** Returns compiler flags for enabling or disabling debugging information (e.g., `-g` for GCC/gfortran).
* **`get_preprocess_only_args`:** Returns flags to instruct the compiler to only perform preprocessing (e.g., `-cpp` for gfortran).
* **`get_module_incdir_args`:** Returns the flag used to specify include directories for Fortran modules (e.g., `-I`).
* **`get_module_outdir_args`:** Returns the flags used to specify the output directory for compiled Fortran module files (e.g., `-module <path>` for gfortran, `-J<path>` for other versions).
* **`compute_parameters_with_absolute_paths`:** Ensures that include and library paths are absolute, which is crucial for consistent builds.
* **`module_name_to_filename`:**  Converts a Fortran module name to its corresponding filename based on compiler conventions (e.g., `module.mod` or `module@submodule.smod`).

**3. Dependency and Library Handling:**

* **`find_library`:**  Searches for a specified Fortran library in given directories.
* **`has_multi_arguments`, `has_multi_link_arguments`:** Checks if the compiler supports passing multiple arguments or link arguments in a single invocation.

**4. Language Standard and Feature Detection:**

* **`get_options`:**  Defines the configurable options specific to the Fortran compiler, such as the Fortran language standard to use (e.g., Fortran 95, Fortran 2003).
* **`get_option_compile_args`:** Returns compiler flags based on the selected options (e.g., `-std=f95` for gfortran).
* **`has_function`:**  While Fortran doesn't have the same "function" concept as C for compile-time checks, this method is present but raises an exception, suggesting using the `links` method to test for Fortran features.
* **`has_header`:** Checks if a given header file exists and can be included. This is adapted from the C/C++ world but applied to Fortran.

**5. Compiler-Specific Flags and Behavior:**

* The subclasses like `GnuFortranCompiler`, `IntelFortranCompiler`, etc., override methods to provide compiler-specific flags for warnings, dependency generation, OpenMP support, and standard library linking.

**Relationship to Reverse Engineering:**

While this file itself doesn't directly perform reverse engineering, it's a foundational component for building tools (like Frida itself or extensions for it) that *can* be used for reverse engineering. Here's how:

* **Building Instrumentation Tools:** Frida is a dynamic instrumentation tool. This file ensures that the Fortran parts of Frida (if any) or external libraries Frida interacts with can be correctly compiled. Reverse engineers often use instrumentation tools to understand how software works at runtime.
* **Analyzing Fortran Binaries:** If a reverse engineer is analyzing a target application written in Fortran, they might need to understand the specific Fortran compiler and its options used to build that application. This file provides insights into the common compiler flags and conventions used in the Fortran ecosystem. Knowing the compiler and its flags can help understand potential optimizations or language features used.
* **Creating Custom Tools:** Developers might use Meson and its Fortran compiler support to build custom reverse engineering tools that need to interact with or analyze Fortran code.

**Examples of Connections to Binary Bottom, Linux, Android Kernel & Framework:**

* **Binary Bottom:** This code directly deals with the process of taking human-readable Fortran code and transforming it into machine code (binary). The compiler flags control aspects of this binary generation, such as optimization levels, debugging symbols, and target architecture.
* **Linux:** Many of the listed Fortran compilers (like gfortran, Intel Fortran) are commonly used on Linux. The flags and conventions handled in this file are often Linux-centric. The search paths for libraries and the way executables are linked are all influenced by the underlying Linux operating system.
* **Android Kernel & Framework:** While less direct, Frida can be used to instrument processes on Android. If those processes (or libraries they depend on) are built using Fortran, this file plays a role in the build process of the instrumentation tools used on Android. The cross-compilation capabilities within Meson, which this file contributes to, are essential for building Android applications on a non-Android host. The interaction with shared libraries (`.so` files on Linux/Android) is also relevant.

**Examples of Logical Reasoning (Hypothetical Input & Output):**

* **Scenario:** Meson is configuring a build where the user has specified the GNU Fortran compiler (gfortran) and wants to compile with optimization level 2.
* **Input:** The build system identifies the compiler as gfortran and the optimization level as "2".
* **Processing:** The `GnuFortranCompiler` class's `get_optimization_args('2')` method will be called.
* **Output:** This method will likely return the list `['-O2']`, which will be added to the compiler command-line arguments.

* **Scenario:** Meson needs to find the include directory for Fortran modules.
* **Input:** The build system needs to determine the appropriate flag for specifying include directories for the current Fortran compiler.
* **Processing:** For a `GnuFortranCompiler` instance, the `get_module_incdir_args()` method will be called.
* **Output:** This method will return the tuple `('-I', )`.

**Examples of User or Programming Common Usage Errors:**

* **Incorrect Compiler Selection:** If a user tries to force the use of a Fortran compiler that is not installed or is not correctly detected by Meson, the build process will fail. Meson might try to execute a non-existent compiler.
* **Specifying an Unsupported Language Standard:** If a user sets the Fortran standard to "f2018" but is using an older compiler that doesn't support it, the compiler will throw an error. The `get_options` method tries to limit the choices based on the compiler version, but manual configuration could still lead to errors.
* **Missing Fortran Module Dependencies:** If a Fortran source file depends on a module that Meson cannot find (e.g., the module's path isn't in the include directories), the compilation will fail. This is a common issue when working with modular Fortran code.
* **Mixing Compiler Flags:**  Users might try to manually add compiler flags that conflict with the flags Meson is already adding, leading to unexpected behavior or compilation errors.

**User Operations Leading to This Code (Debugging Context):**

Imagine a developer working on the Frida project encounters an issue related to building Frida on a system where Fortran is involved (perhaps a dependency uses Fortran). Here's a possible sequence:

1. **Running the Meson Configuration:** The developer runs `meson setup builddir` to configure the build.
2. **Meson Detects Fortran:** Meson's compiler detection logic identifies a Fortran compiler (e.g., gfortran) on the system.
3. **Meson Uses `fortran.py`:** Meson loads the `fortran.py` module to handle the Fortran compiler.
4. **Problem Arises (Example):**  The build fails with an error related to Fortran module dependencies.
5. **Debugging:** The developer starts investigating the build logs and notices the command-line arguments being passed to the Fortran compiler.
6. **Tracing Back:** The developer might want to understand *how* Meson is generating those arguments. They would then look at the `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/fortran.py` file to see the logic behind the `get_module_incdir_args`, `get_module_outdir_args`, and other methods that construct the compiler commands.
7. **Setting Breakpoints/Adding Prints:**  The developer might add print statements within the `fortran.py` file or use a debugger to inspect the values of variables and the execution flow to understand why the module dependencies are not being handled correctly.
8. **Identifying the Issue:**  They might find a bug in how Meson is determining the include paths or a missing feature in the Fortran compiler support.
9. **Fixing the Code:** The developer would then modify the `fortran.py` file to correct the logic or add the necessary functionality.

In essence, this `fortran.py` file is a crucial piece of the Frida build system when Fortran code is involved. Developers working on Frida or projects that interact with Frida might need to understand or debug this code to ensure correct compilation and linking of Fortran components.

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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