Response:
Let's break down the request and the provided Python code to construct the answer.

**1. Understanding the Core Request:**

The primary goal is to analyze a specific Python file (`fortran.py`) within the Frida project, focusing on its functionality and its relevance to reverse engineering, low-level concepts, and potential user errors. The request also asks for an explanation of how a user might end up interacting with this code during debugging.

**2. Deconstructing the Python Code:**

The code defines several classes, all inheriting from `FortranCompiler`, representing different Fortran compilers (GNU, Intel, PGI, etc.). Each class configures compiler-specific options, arguments, and behaviors for the Meson build system.

**Key Observations from the Code:**

* **Compiler Abstraction:** The code provides an abstraction layer for various Fortran compilers, allowing Meson to interact with them in a unified way.
* **Configuration:**  It defines how to invoke each compiler (executable names), what arguments to pass for different tasks (compiling, linking, preprocessing, debugging, optimization), and how to handle compiler-specific features (modules, include paths, etc.).
* **Standard Support:** It manages different Fortran language standards (f95, f2003, etc.).
* **Warning Levels:** It configures warning levels for different compilers.
* **Library Linking:** It handles finding and linking Fortran libraries.
* **Interoperability:** It considers how Fortran interacts with other languages (like C/C++) through standard library linking.

**3. Connecting to the Request's Specific Points:**

* **Functionality:**  This is straightforward – describe what the code *does*.
* **Reverse Engineering:** This requires identifying how the ability to build software (the primary function of the code) relates to reverse engineering. The key is that to reverse engineer, you often need to *rebuild* or *analyze* the target software, potentially with modifications. Understanding compiler options is crucial for this.
* **Binary/Low-Level, Linux/Android Kernel/Framework:**  Think about what's involved in compilation. It produces binaries. The code interacts with the operating system (finding libraries, executing compilers). While it doesn't directly touch kernel code *in this file*, the *output* of the compilers it configures will run on these systems. Android is a Linux derivative, so much of the Linux compilation knowledge applies. Frameworks might have specific compilation requirements, and this code helps manage those.
* **Logical Reasoning (Hypothetical Input/Output):** Focus on specific methods and their expected behavior based on their names and code. For instance, `get_module_outdir_args` should take a path and return compiler arguments to specify the output directory for module files.
* **User Errors:** Consider common mistakes when configuring build systems or using compilers. Incorrect paths, missing dependencies, wrong language standard, or improper use of compiler options are good examples.
* **User Operation and Debugging:**  Think about the steps a developer takes to build software using Meson and how they might encounter issues related to the Fortran compiler configuration.

**4. Structuring the Answer:**

A well-structured answer is essential. I'll use the categories provided in the prompt:

* **功能 (Functionality):** Start with a high-level overview and then detail specific capabilities.
* **与逆向方法的关系 (Relationship to Reverse Engineering):** Explain the connection between building and reverse engineering. Provide concrete examples.
* **二进制底层，Linux, Android内核及框架的知识 (Binary/Low-Level, Linux/Android Kernel/Framework):** Discuss how the code relates to these concepts, even if indirectly.
* **逻辑推理 (Logical Reasoning):** Select a few illustrative functions and demonstrate the expected input and output.
* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Give practical examples of mistakes users might make.
* **用户操作是如何一步步的到达这里，作为调试线索 (User Operations Leading to This Code):** Outline a typical Meson build process and where things might go wrong related to Fortran compilation.

**5. Refining the Details:**

* **Compiler-Specific Examples:** When discussing functionality, highlight how different compilers are handled (e.g., module file naming).
* **Concrete Reverse Engineering Scenarios:**  Don't just say "rebuilding."  Give examples like "rebuilding with debug symbols" or "modifying compiler flags to disable optimizations."
* **Link to Frida:**  While the code itself isn't directly Frida's instrumentation logic, emphasize that it's part of Frida's *build system*, which is necessary to create Frida itself.
* **Clarity and Conciseness:**  Use clear language and avoid unnecessary jargon.

**Self-Correction/Refinement During Thought Process:**

* **Initial Thought:** Focus solely on the direct code functionality.
* **Correction:**  Realize the request asks for broader implications, including reverse engineering and low-level aspects. Expand the scope accordingly.
* **Initial Thought:**  List all functions and their inputs/outputs for logical reasoning.
* **Correction:** Select a few key, illustrative functions to avoid being overly verbose.
* **Initial Thought:** Describe user errors in abstract terms.
* **Correction:** Provide concrete, relatable examples of user mistakes.

By following these steps, I can create a comprehensive and accurate answer that addresses all aspects of the request.
This Python code file, `fortran.py`, is part of the Meson build system, which is used by the Frida dynamic instrumentation toolkit to manage its build process. Specifically, this file defines classes and logic for handling Fortran compilers within Meson. Let's break down its functionalities and their relation to your points:

**功能 (Functionality):**

1. **Abstraction of Fortran Compilers:** The core purpose is to provide an abstract interface for different Fortran compilers (like GNU Fortran, Intel Fortran, PGI, etc.). This allows Meson to work with various Fortran compilers in a consistent way, regardless of their specific command-line arguments or behaviors.

2. **Compiler Detection and Configuration:**  While the code itself doesn't perform the direct detection, it defines how Meson interacts with a detected Fortran compiler. It stores information like the compiler's executable path (`exelist`), version, and target machine.

3. **Defining Compiler-Specific Arguments:** The file contains classes for various Fortran compilers, each specifying:
    * **Default Warning Arguments:**  Arguments to control compiler warnings at different levels.
    * **Optimization Arguments:** How to pass optimization flags.
    * **Debug Arguments:** How to enable debugging information.
    * **Preprocessing Arguments:**  Arguments for pre-processing Fortran code.
    * **Module Handling:** How to specify include directories for Fortran modules (`-I`), and output directories for generated module files (`-module`, `-J`, etc.). Fortran modules are similar to header files in C/C++.
    * **Language Standard Options:**  Arguments to specify the Fortran language standard to use (e.g., f95, f2003, f2008).
    * **Dependency Generation:**  Arguments to generate dependency files (though some are commented out due to known issues).
    * **Library Linking:** How to find and link Fortran libraries.
    * **OpenMP Flags:**  Arguments to enable OpenMP parallel processing.

4. **Sanity Checks:**  The `sanity_check` method defines how to compile a simple Fortran program to verify that the compiler is working correctly.

5. **Feature Detection (Limited):** While not as extensive as in C/C++, there are methods like `has_multi_arguments` and `has_multi_link_arguments` to check if the compiler supports certain argument combinations. The `has_function` method is explicitly noted as not being well-suited for Fortran, suggesting alternative ways to check Fortran features.

6. **Path Handling:** The `compute_parameters_with_absolute_paths` function ensures that include and library paths are absolute, which is important for consistent builds.

7. **Module Name to Filename Conversion:** The `module_name_to_filename` method defines how Fortran module names are translated into file names, which varies between compilers.

**与逆向方法的关系 (Relationship to Reverse Engineering):**

This file plays a role in reverse engineering indirectly by being part of the build process for Frida. Here's how it connects:

* **Building Frida:** To use Frida for dynamic instrumentation, you first need to build it. This `fortran.py` file helps Meson correctly configure and use the Fortran compiler during Frida's build process if Frida or its dependencies include Fortran code.
* **Analyzing Binaries with Fortran Components:** If you are reverse engineering a target application that is partially written in Fortran, understanding how it was compiled (including the Fortran compiler and its options) can be helpful. This file provides insights into the kind of options Meson might use when building Fortran code. Knowing the compiler, standard, and optimization levels can give clues about the generated binary's structure and behavior.
* **Rebuilding or Modifying Fortran Components:** In some reverse engineering scenarios, you might need to rebuild parts of a target application. If those parts are in Fortran, this file shows the configuration necessary for that rebuilding process within a Meson-based project like Frida.

**举例说明 (Example):**

Imagine you are reverse engineering a scientific application that uses a Fortran library for numerical computations. To understand the library's behavior deeply, you might want to recompile it with debug symbols enabled. This `fortran.py` file contains the logic (in methods like `get_debug_args`) that Meson would use to pass the correct debug flags (e.g., `-g` for GCC Fortran, `/debug:full` for Intel Fortran on Windows) to the Fortran compiler when you configure the build with a debug option.

**涉及到二进制底层，linux, android内核及框架的知识 (Involvement of Binary Low-Level, Linux, Android Kernel & Framework):**

* **Binary Generation:** The ultimate output of the Fortran compilers configured by this file is machine code, the binary representation of the Fortran program, which is the foundation of software execution.
* **Linking:** The file helps manage the linking process, where compiled Fortran code is combined with other libraries (potentially written in C/C++) to create the final executable or shared library. This linking process involves understanding binary formats (like ELF on Linux, Mach-O on macOS, PE on Windows) and symbol resolution.
* **Operating System Interaction:** The compiler needs to interact with the operating system (Linux, Android) to find libraries and execute system calls. The `-L` flags specified in the code direct the linker where to search for libraries, which are typically organized within the OS's file system.
* **Android:** While this specific file doesn't directly interact with the Android kernel, if Frida is being built for Android and includes Fortran components, this file ensures the Fortran code is compiled correctly for the Android environment. The compiled Fortran code will then run within the Android userspace, interacting with the Android framework through system calls and libraries.

**举例说明 (Example):**

The `language_stdlib_only_link_flags` methods in the `GnuFortranCompiler` and `IntelFortranCompiler` classes specify the standard Fortran runtime libraries (like `libgfortran`, `libifcore`). These libraries provide essential runtime support for Fortran programs and are linked into the final binary. On Linux and Android, these libraries are usually standard shared objects (`.so` files) located in system directories.

**如果做了逻辑推理，请给出假设输入与输出 (Logical Reasoning - Hypothetical Input and Output):**

Let's consider the `get_module_outdir_args` method in the `GnuFortranCompiler` class:

* **假设输入 (Hypothetical Input):** `path = '/tmp/fortran_modules'`
* **逻辑推理 (Logic):** The method returns `['-J' + path]`.
* **预期输出 (Expected Output):** `['-J/tmp/fortran_modules']`

This means that when Meson needs to tell the GNU Fortran compiler where to place the generated module files, it will use the `-J/tmp/fortran_modules` command-line argument.

Another example, consider the `module_name_to_filename` method:

* **假设输入 (Hypothetical Input for GNU Fortran):** `module_name = 'my_module'`
* **逻辑推理 (Logic):** The method returns `module_name.lower() + '.mod'`.
* **预期输出 (Expected Output):** `'my_module.mod'`

* **假设输入 (Hypothetical Input for GNU Fortran - Submodule):** `module_name = 'parent_module_submodule'`
* **逻辑推理 (Logic):** The method checks for `_` and replaces it with `@` for GCC/Intel.
* **预期输出 (Expected Output):** `'parent@module@submodule.smod'`

**如果涉及用户或者编程常见的使用错误，请举例说明 (Common User or Programming Errors):**

1. **Incorrect Compiler Path:** If the user has not correctly configured the path to their Fortran compiler, Meson will fail to find it. This is a common initial setup error.

2. **Missing Dependencies:** If the Fortran code being compiled relies on external libraries that are not installed or whose paths are not correctly specified, the linking stage will fail. The user might need to adjust library search paths or install the missing libraries.

3. **Incompatible Compiler Version:**  Some Fortran code might require a specific version of the compiler. If the user's compiler is too old or too new, compilation errors might occur. This file tries to handle different compiler versions by adjusting options, but mismatches can still happen.

4. **Incorrect Language Standard:** If the user tries to compile code that uses features from a newer Fortran standard with a compiler configured for an older standard (or vice-versa), compilation errors will arise. The `get_options` methods allow users to specify the standard, and choosing the wrong one is a common mistake.

5. **Mixing Compilers:** If a project mixes Fortran with other languages (like C/C++), ensuring compatibility between the compilers used for each language and their respective runtime libraries is crucial. Misconfigurations can lead to linking errors.

**举例说明 (Example):**

A user might try to build Frida on a system where the GNU Fortran compiler is not in the system's `PATH`. When Meson tries to detect the Fortran compiler, it will fail, and the build process will stop with an error message indicating that the Fortran compiler was not found.

Another example: A user might be trying to compile a Fortran 2008 program but has configured Meson to use the `f95` standard for the GNU Fortran compiler. The compiler will likely produce errors when it encounters features not available in the Fortran 95 standard.

**说明用户操作是如何一步步的到达这里，作为调试线索 (User Operations Leading Here as a Debugging Clue):**

1. **User Attempts to Build Frida:** The user starts by trying to build the Frida project using the standard build instructions, which typically involve running `meson setup _build` and `ninja -C _build`.

2. **Meson Invokes Compiler Detection:** During the `meson setup` phase, Meson needs to detect the available compilers for different languages, including Fortran.

3. **Meson Loads `fortran.py`:**  If the project configuration (e.g., `meson.build` files) indicates that Fortran code needs to be compiled, Meson will load the `fortran.py` file to understand how to handle Fortran compilers.

4. **Compiler Detection Logic:** Meson uses logic (not entirely within this file, but influenced by it) to search for Fortran compiler executables (like `gfortran`, `ifort`, etc.) in standard locations.

5. **`FortranCompiler` Class Instantiation:** If a Fortran compiler is found, Meson will instantiate the appropriate `FortranCompiler` subclass (e.g., `GnuFortranCompiler` if `gfortran` is found), passing information like the executable path and version.

6. **Compilation or Feature Checks:**  Later, during the `ninja` phase, when actual Fortran code needs to be compiled, Meson will use the methods defined in the instantiated `FortranCompiler` object (like `get_compile_args`, `get_module_outdir_args`) to construct the command-line arguments for the Fortran compiler.

7. **Debugging Scenario:** If the build fails during the Fortran compilation stage, a developer might investigate why. Looking at the error messages from the compiler, they might realize that incorrect compiler arguments are being used. This would lead them to examine the `fortran.py` file to understand how Meson configures the Fortran compiler and whether the correct compiler class and options are being selected. They might check if the detected compiler version is correct or if the language standard is being set appropriately.

In essence, `fortran.py` is a crucial part of Frida's build system when Fortran is involved. When build issues arise related to Fortran code, this file becomes a key point of investigation to understand how the build system is interacting with the Fortran compiler.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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