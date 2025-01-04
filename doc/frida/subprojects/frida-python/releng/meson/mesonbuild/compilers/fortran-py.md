Response:
Let's break down the thought process for analyzing the provided Python code. The goal is to understand its function within the Frida project and connect it to relevant concepts like reverse engineering, low-level details, and potential user errors.

**1. Initial Understanding of the File's Purpose:**

The file path `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/fortran.py` immediately tells us a few things:

* **Frida Project:** This code is part of the Frida dynamic instrumentation toolkit.
* **Frida-Python Subproject:**  It specifically relates to the Python bindings of Frida.
* **Releng (Release Engineering):** This suggests the file is involved in the build and release process.
* **Meson Build System:**  The `meson` directory indicates that Frida-Python uses the Meson build system.
* **Compiler Handling:** The `compilers` directory and `fortran.py` filename strongly suggest this file defines how Meson handles Fortran compilers when building Frida-Python.

**2. High-Level Functionality Identification:**

Skimming the code reveals classes like `FortranCompiler`, `GnuFortranCompiler`, `IntelFortranCompiler`, etc. This confirms the primary function is to define how different Fortran compilers are invoked and configured within the Meson build process for the Frida-Python component. It's about telling Meson how to compile Fortran code if Frida-Python needs it (or if it links against Fortran libraries).

**3. Connecting to Reverse Engineering:**

The key connection here is *indirect*. Frida itself is a powerful reverse engineering tool. This file isn't *directly* performing reverse engineering. Instead, it's enabling the *building* of the Python bindings of Frida, which is *used* for reverse engineering.

* **Example:** Imagine a Frida Python script needs to interact with a target application that uses a Fortran library for some numerical computations. This `fortran.py` file ensures that if the Frida-Python build needs to link against such a Fortran library, the Meson build system knows how to correctly invoke the Fortran compiler and linker.

**4. Identifying Low-Level/Kernel/Framework Connections:**

Again, the connection is *indirect*. Frida, at its core, operates at a very low level, interacting with process memory, system calls, and sometimes even the kernel. This `fortran.py` file doesn't directly manipulate these things. However:

* **Linking:**  The file deals with linking, which is a crucial low-level process of combining compiled code into executables or libraries.
* **Operating System Dependencies:**  Compiler flags and library linking are often OS-specific (Linux, Android, Windows). The code handles different compilers (GNU, Intel, etc.), which have their own OS-specific nuances.
* **Android Framework:** While not explicitly mentioned, if Frida-Python is used to instrument Android applications, those applications might use Fortran libraries. This file ensures that the Frida-Python build can handle such scenarios.

**5. Looking for Logical Reasoning and Assumptions:**

The code contains conditional logic based on compiler versions (e.g., `version_compare`). This demonstrates logical reasoning:  certain compiler features or flags are only available in specific versions.

* **Assumption/Input-Output Example:**  Assume the `GnuFortranCompiler` is being used and its version is "8.1.0". The `get_options` method checks the version. The input is the compiler version. The output will be a list of supported Fortran standards, including 'f2018', because the version check `version_compare(self.version, '>=8.0.0')` will be true. If the version was "4.3.0", 'f2018' would *not* be included.

**6. Identifying Potential User Errors:**

The code interacts with Meson's configuration system and user-defined options. Potential errors arise from:

* **Incorrect Compiler Installation/Path:** If the user hasn't correctly installed a Fortran compiler or Meson can't find it, the build will fail.
* **Conflicting Options:**  Users might try to set compiler options that conflict with each other or are not supported by the chosen Fortran compiler. Meson tries to handle this, but some errors might still slip through.
* **Missing Dependencies:** If the Frida-Python project has dependencies on external Fortran libraries, and those libraries are not installed or their paths are not correctly configured, linking errors will occur.

**7. Tracing User Actions to the File:**

To reach this code, a user would typically:

1. **Download the Frida source code.**
2. **Navigate to the `frida-python` subdirectory.**
3. **Run the Meson configuration command:** `meson setup build` (or similar).
4. **Meson reads the `meson.build` files.**
5. **Meson detects the need for a Fortran compiler (if Fortran code is involved).**
6. **Meson consults files like this `fortran.py` to determine how to interact with the detected Fortran compiler.**

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  This file directly instruments Fortran code.
* **Correction:**  No, it's about *building* the tooling that *can* instrument, but it's focused on the build process itself.
* **Initial thought:**  The code deals with very specific kernel interactions.
* **Refinement:** While it enables the building of a tool that *can* do that, this file's direct scope is compiler interaction and linking, which are lower-level than application logic but not necessarily kernel-level within this file itself.

By following this thought process, breaking down the file's purpose, and connecting it to the broader context of Frida and reverse engineering, we can arrive at a comprehensive understanding of its functionality and relevance.
This Python code file, `fortran.py`, is part of the Meson build system's logic for handling Fortran compilers. Meson is used by the Frida project to manage its build process across different platforms. This specific file provides the instructions and logic for how Meson should interact with various Fortran compilers (like gfortran, Intel Fortran, etc.) when building software that includes Fortran code.

Here's a breakdown of its functionalities:

**1. Definition of Fortran Compiler Classes:**

* The file defines a base class `FortranCompiler` and several subclasses, each representing a specific Fortran compiler implementation (e.g., `GnuFortranCompiler`, `IntelFortranCompiler`, `PGIFortranCompiler`).
* Each class encapsulates compiler-specific information and methods for tasks like:
    * **Identifying the compiler:**  Storing the compiler's executable path (`exelist`), version, and a unique ID.
    * **Basic compilation and linking:** Providing methods for performing sanity checks to ensure the compiler is working.
    * **Handling compiler arguments:** Defining default arguments, optimization flags, debug flags, and flags for preprocessing, module handling, and dependency generation.
    * **Library searching:**  Providing methods to find required Fortran libraries.
    * **Language standards:**  Managing Fortran language standard options (e.g., f95, f2003, f2018).
    * **Warning levels:** Defining arguments for different warning levels.
    * **OpenMP support:** Providing flags for enabling OpenMP parallelism.
    * **Module file management:** Specifying how to include and output Fortran module files.

**2. Abstraction of Compiler Differences:**

* The code aims to abstract away the differences between various Fortran compilers. Meson uses these classes to generate the correct compiler commands regardless of which Fortran compiler is being used on the system.
* For instance, the way to specify the output directory for module files (`.mod` or `.smod`) differs between compilers, and this file handles those variations.

**3. Integration with Meson Build System:**

* These classes are used by Meson during the configuration and compilation phases of a build process.
* When Meson encounters Fortran source files, it will use the appropriate `FortranCompiler` subclass based on the detected compiler to generate the necessary build commands.

**Relation to Reverse Engineering:**

While this file doesn't directly perform reverse engineering, it plays a crucial role in building Frida, which is a powerful dynamic instrumentation toolkit used extensively in reverse engineering.

* **Building Frida's Components:** If Frida's codebase or its Python bindings (frida-python) include any Fortran code or need to link against Fortran libraries, this file ensures that the Fortran parts are correctly compiled and linked during the build process.
* **Indirect Support for Reverse Engineering:** By enabling the successful build of Frida, this file indirectly supports reverse engineering activities. Without the ability to compile and link necessary components, Frida wouldn't be functional.

**Example:**

Imagine a scenario where Frida needs to interact with a target application that utilizes a Fortran library for some numerical computations. During the build of Frida, if the system has a GNU Fortran compiler (gfortran) installed, Meson will use the `GnuFortranCompiler` class defined in this file. This class provides the correct flags and commands to compile any Fortran code within Frida and link against the necessary Fortran runtime libraries (`-lgfortran`). This ensures that Frida can function correctly when interacting with the target application's Fortran components.

**Involvement of Binary Underpinnings, Linux, Android Kernel/Framework:**

* **Binary Underpinnings:**  Compilers translate human-readable code (like Fortran) into machine code (binary instructions). This file defines how that translation happens for Fortran within the Frida build process. The compiler flags and linking steps managed here directly influence the final binary output.
* **Linux and Android:**  The code doesn't explicitly target a specific kernel, but the presence of compiler-specific logic (especially for GNU compilers which are common on Linux and Android) and handling of shared libraries (linking) indicates an awareness of operating system conventions. The `language_stdlib_only_link_flags` method in `GnuFortranCompiler`, for example, explicitly includes `-lgfortran`, which is the GNU Fortran standard library, common on Linux.
* **Framework (Indirect):** While not directly interacting with the Android framework, if Frida is being built to instrument Android applications, this file helps ensure that any Fortran components involved in that process (either in Frida itself or in libraries it links against) are built correctly for the Android environment. The build system needs to generate binaries compatible with the target platform's architecture and libraries.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `get_module_outdir_args` method in the `GnuFortranCompiler` class:

* **Hypothetical Input:** The user is building a Frida component that uses Fortran modules. Meson needs to tell the Fortran compiler where to place the compiled module files (`.mod`). The `path` argument passed to this method could be something like `'build/modules'`.
* **Logical Reasoning:** The `GnuFortranCompiler` uses the `-J` flag followed by the path to specify the module output directory.
* **Hypothetical Output:** The method would return `['-Jbuild/modules']`. This list of strings is then used by Meson to construct the actual compiler command.

**Common User/Programming Errors and Examples:**

* **Incorrect Fortran Compiler Installation:** If a user tries to build Frida on a system where a Fortran compiler isn't installed or isn't in the system's PATH, Meson will likely fail during the configuration stage, and this file (or the broader Meson infrastructure) will report an error about not finding a suitable Fortran compiler.
* **Example:**  The user runs `meson setup build` but doesn't have gfortran installed (or it's not in their PATH). Meson will try to find a Fortran compiler, and if it fails, it will output an error message like: "Could not auto-detect Fortran compiler."

* **Conflicting Compiler Options:**  Users might try to pass compiler options that are incompatible or conflict with the defaults set in this file or in Meson's configuration. This could lead to compilation errors.
* **Example:** A user might try to force a specific Fortran standard that isn't supported by the detected compiler version. Meson might pass this option, but the underlying compiler will throw an error during compilation.

* **Missing Fortran Dependencies:** If the Frida build depends on external Fortran libraries that are not installed, the linking stage will fail. This file's `find_library` method is used to locate libraries, but if the library isn't present in the standard locations or specified extra directories, the build will fail.
* **Example:** The Frida component needs to link against a numerical Fortran library like LAPACK, but it's not installed. The linker will complain about missing symbols.

**User Operation to Reach This Code as a Debugging Clue:**

1. **User Attempts to Build Frida:** The user downloads the Frida source code and navigates to the root directory.
2. **User Initiates Meson Configuration:** The user runs a command like `meson setup build`.
3. **Meson Detects Fortran Code or Dependencies:** During the configuration, Meson scans the `meson.build` files and detects that either some source files are Fortran (`.f90`, `.f`, etc.) or that a dependency requires a Fortran compiler.
4. **Meson Searches for a Fortran Compiler:** Meson uses logic (not solely within this file, but involving other Meson components) to search for available Fortran compilers on the system (e.g., by looking in standard locations or based on environment variables).
5. **Meson Loads the Appropriate Fortran Compiler Class:** Based on the detected compiler (e.g., gfortran), Meson loads the corresponding class from `frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/fortran.py` (e.g., `GnuFortranCompiler`).
6. **Error Occurs (Hypothetically):** Let's say the build fails with a Fortran-related error, such as "unrecognized command-line option '-Wpedantic'".
7. **Debugging:** The developer investigating the issue might:
    * **Examine the Meson logs:** These logs will show the exact compiler commands that were executed.
    * **Trace back the compiler command generation:** They would then look at the `GnuFortranCompiler` class in `fortran.py` to see where the `-Wpedantic` option is being added (in this case, within the `warn_args` dictionary).
    * **Identify the root cause:**  They might discover that the version of gfortran on the user's system doesn't support `-Wpedantic` or that there's a typo in the option definition within the Python code.

Therefore, this file becomes a crucial point of investigation when debugging Fortran-related build issues within the Frida project. Understanding its structure and the logic within its classes is essential for diagnosing problems related to how Meson interacts with Fortran compilers.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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