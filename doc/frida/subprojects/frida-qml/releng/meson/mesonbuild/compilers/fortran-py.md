Response:
My thinking process to analyze the provided Python code for the Frida project goes like this:

1. **Understand the Context:** The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/fortran.py` immediately tells me this is part of Frida's build system (using Meson) and deals with Fortran compilers. Frida itself is a dynamic instrumentation toolkit. Knowing this is crucial for connecting the code to reverse engineering.

2. **Identify the Core Functionality:** The file defines several classes, all inheriting from `FortranCompiler` (and often other mixin classes). Each class represents a specific Fortran compiler (like GNU Fortran, Intel Fortran, etc.). The primary purpose is to provide Meson with the necessary information and methods to use these compilers within the build process. This includes:
    * **Compiler Identification:**  Each class has an `id` attribute.
    * **Execution:**  Information about how to execute the compiler (the `exelist`).
    * **Arguments and Flags:**  Methods to get the correct command-line arguments for various tasks like compilation, linking, debugging, optimization, and pre-processing.
    * **Language Standards:**  Handling different Fortran language standards.
    * **Module Management:**  Dealing with Fortran modules (like include directories and output directories).
    * **Library Linking:**  Finding and linking Fortran libraries.
    * **Sanity Checks:**  Basic checks to ensure the compiler is working.
    * **Warnings:**  Controlling compiler warning levels.
    * **Dependency Generation:**  Generating dependency files for faster builds.

3. **Connect to Reverse Engineering:**  Frida's core purpose is dynamic instrumentation, allowing you to inspect and modify the behavior of running processes. While this file isn't directly involved in the *instrumentation* part, it's essential for building Frida itself, or potentially for building components that Frida might interact with. Here's how it relates:
    * **Building Frida's Components:** If Frida uses Fortran for any of its internal tools or libraries, this file is crucial for compiling that code. This compiled code becomes part of Frida, the reverse engineering tool.
    * **Instrumenting Fortran Code:**  While not explicitly stated in the file, knowing how Fortran compilers work (their flags, module systems, etc.) can be helpful when *instrumenting* Fortran applications with Frida. You might need to understand how the target application was built to effectively instrument it. For example, knowing the module naming conventions helps in understanding the structure of the compiled Fortran code.

4. **Identify Interactions with Binary, Linux/Android Kernel/Framework:**
    * **Binary Compilation:**  The code's primary function is to drive the compilation process, which results in binary executables or libraries. The various compiler flags directly affect the generated binary code.
    * **Operating System Dependencies:**  The code interacts with the underlying operating system by executing compiler commands. Some compiler flags or linking options might be OS-specific. The paths and conventions used for libraries can also be OS-dependent.
    * **Kernel/Framework (Indirect):** While this code doesn't directly interact with the kernel or Android framework, the *output* of the compilation process (the binaries) will run on these systems. The choice of compiler and flags can affect how these binaries interact with the OS and potentially the framework. For instance, specific compiler flags might be needed for code that interacts with certain kernel features.

5. **Look for Logical Reasoning and Examples:**
    * **Conditional Logic:**  The code uses `if` statements to handle different compiler versions and operating systems (implicitly through the compiler classes). For example, the `GnuFortranCompiler` adds Fortran 2008 and 2018 standards based on the compiler version.
    * **Mapping and Configuration:** The `warn_args` dictionaries map warning levels to specific compiler flags. The `get_options` methods define configurable build options.
    * **Module Name Conversion:** The `module_name_to_filename` method demonstrates a specific logic for converting Fortran module names to filenames, which varies between compilers.

6. **Consider User Errors:**
    * **Incorrect Compiler:** If the user configures Meson to use the wrong Fortran compiler, this code might generate incorrect build commands, leading to compilation errors.
    * **Invalid Options:**  Users might provide invalid compiler options via Meson, which could be passed through by this code and cause compiler errors.
    * **Missing Dependencies:** If the user tries to link against a Fortran library that isn't installed or configured correctly, the `find_library` method might fail.

7. **Trace User Operations (Debugging Clues):**
    * **Meson Setup:** The user starts by setting up a Meson build environment. This involves a `meson.build` file that specifies the project's build requirements, including the use of Fortran.
    * **Compiler Selection:** Meson (or the user through configuration) selects a Fortran compiler. This is where the appropriate class in this Python file comes into play.
    * **Compilation/Linking:** When Meson needs to compile Fortran code, it will instantiate the relevant compiler class and call its methods (like `compile`, `link`, etc.) to generate the necessary compiler commands.
    * **Error Reporting:** If something goes wrong during compilation or linking, the error messages might contain information about the compiler commands generated by this code, which can be used for debugging.

By following these steps, I can systematically analyze the code and extract the information requested in the prompt, making connections to Frida's purpose and relevant technical areas.
This Python code file, located within the Frida project's build system, defines how the Meson build tool interacts with various Fortran compilers. It essentially provides a standardized interface for Meson to compile Fortran code regardless of the specific Fortran compiler being used (like GNU Fortran, Intel Fortran, etc.).

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Abstraction Layer for Fortran Compilers:**  The primary purpose is to create an abstraction layer. Meson doesn't need to know the specific command-line arguments or quirks of every Fortran compiler. This file provides classes (like `GnuFortranCompiler`, `IntelFortranCompiler`) that encapsulate this compiler-specific knowledge.

2. **Defining Compiler Capabilities:** Each compiler class defines:
   - **Executable Path:** Where the Fortran compiler executable is located (`exelist`).
   - **Version:** The version of the compiler.
   - **Default Arguments:** Common arguments passed to the compiler.
   - **Warning Levels:** How to enable different levels of compiler warnings.
   - **Optimization Levels:** Compiler flags for different optimization levels.
   - **Debug Flags:** Compiler flags for generating debugging information.
   - **Preprocessing:** How to run the preprocessor.
   - **Module Handling:** How to specify include and output directories for Fortran modules.
   - **Library Linking:** How to find and link Fortran libraries.
   - **Language Standards:**  Support for different Fortran language standards (e.g., F95, F2003).
   - **Dependency Generation:**  How to generate dependency files for faster builds.
   - **Sanity Checks:** A basic test to ensure the compiler is working.

3. **Standardizing Compiler Interactions:**  Meson calls methods defined in these classes (e.g., `get_compile_args`, `get_link_args`) to get the correct compiler commands. This makes the build process portable across different Fortran compilers.

**Relationship to Reverse Engineering:**

While this file doesn't directly *perform* reverse engineering, it's crucial for **building tools** that *do*. Here's how it connects:

* **Building Frida Components:** If Frida itself or any of its subprojects (like `frida-qml`) are written using Fortran (unlikely but possible for performance-critical numerical computations), this file is essential for compiling that Fortran code into executable binaries or libraries that become part of the Frida tool.
* **Instrumenting Fortran Applications:** While Frida primarily targets C/C++, JavaScript, and other languages, understanding how Fortran code is compiled and linked can be helpful if you need to instrument a Fortran application. This file provides insights into the compiler flags and conventions used in Fortran development. For example, knowing the conventions for module naming (`module_name_to_filename`) can help understand the structure of compiled Fortran code.

**Examples related to Reverse Engineering:**

* **Understanding Compiler Flags:** If you are reverse-engineering a Fortran application and see unusual behavior, knowing the compiler flags used during its build (which this file helps define for Meson) can provide clues. For instance, aggressive optimization flags might make the disassembled code harder to follow.
* **Identifying Fortran Libraries:** If you encounter calls to external libraries in a Fortran application, this file shows how Meson finds and links these libraries. This knowledge can be useful for identifying the purpose of those libraries.
* **Debugging Symbols:** The `get_debug_args` methods show how to enable the generation of debugging symbols. If you have a Fortran application with debugging symbols, understanding the flags used to generate them can aid in debugging and reverse engineering.

**Involvement of Binary底层, Linux, Android 内核及框架知识:**

* **Binary 底层 (Binary Low-Level):** This file is directly involved in the process of taking Fortran source code and turning it into binary executables or libraries. The compiler flags it manages control aspects of the generated binary code, such as optimization levels, debugging information, and target architecture.
* **Linux:** The file operates within a Linux environment (or other Unix-like systems where these compilers are common). It assumes standard command-line compiler invocation and uses conventions like `-I` for include directories and `-L` for library paths.
* **Android 内核及框架 (Android Kernel and Framework):** While not directly interacting with the Android kernel or framework *in this specific file*, if Frida is being built for Android and needs to compile Fortran code, the compiler configurations here would be adapted for the Android target. This might involve specifying the target architecture (e.g., ARM), using the Android NDK's Fortran compiler (if available), and potentially linking against Android-specific libraries.

**Examples related to Binary, Linux, Android:**

* **Target Architecture:** When cross-compiling Fortran code for a different architecture (e.g., building Frida for an ARM-based Android device on an x86 Linux machine), the compiler flags managed by this file would need to be configured to target that architecture.
* **Shared Libraries:** The handling of library linking (`find_library`) is crucial for building shared libraries (`.so` files on Linux/Android), which are a fundamental part of both systems.
* **System Calls:** While Fortran itself doesn't directly interact with the kernel as much as C/C++, if the Fortran code being compiled makes system calls (through Fortran interfaces to C libraries), the compiler and linker settings managed here ensure those calls are resolved correctly in the final binary.

**Logical Reasoning and Examples (Hypothetical):**

Let's take the `GnuFortranCompiler` class and its `get_option_compile_args` method:

* **Assumption:** The user has set the Fortran standard option to "f2008" in their Meson configuration.
* **Input:** The `options` dictionary passed to `get_option_compile_args` contains the key `std` with the value "f2008".
* **Logical Reasoning:** The code checks the value of the `std` option. If it's not "none", it adds the appropriate compiler flag to the `args` list.
* **Output:** The method returns the list `['-std=f2008']`.

Another example with `module_name_to_filename`:

* **Assumption:** The Fortran compiler being used is GCC (`self.id == 'gcc'`).
* **Input:** `module_name` is "my_module_submodule".
* **Logical Reasoning:** The code checks if "_" is in the module name (indicating a submodule). Since it's GCC, it replaces "_" with "@" and adds the ".smod" extension.
* **Output:** The method returns "my_module@submodule.smod".

**User or Programming Common Usage Errors:**

1. **Incorrect Compiler Selection:**  If a user has multiple Fortran compilers installed and Meson picks the wrong one, this could lead to build errors if the code uses features not supported by that compiler. This file tries to handle different compilers, but a misconfiguration can still occur.

   * **Example:** The user intends to use gfortran but their system's `PATH` environment variable prioritizes another Fortran compiler. Meson might incorrectly identify and use that compiler, leading to errors when compiling code that relies on gfortran-specific features.

2. **Missing Dependencies (Libraries):** If the Fortran code depends on external libraries that are not installed or whose paths are not correctly configured, the linking process will fail.

   * **Example:** The `meson.build` file specifies linking against a library named "mylib". If this library isn't in the standard library paths or the user hasn't provided the correct `-L` path, the `find_library` method will return `None`, and the linking step will fail.

3. **Invalid Compiler Options:** Users might try to set custom compiler options in their Meson configuration that are not supported by the specific Fortran compiler being used.

   * **Example:** A user adds `-Werror` (treat warnings as errors) to their Fortran options, but the selected compiler doesn't support this flag. This will lead to a compiler error.

**User Operation Steps Leading Here (Debugging Clues):**

1. **Project Setup:** The user has a project that includes Fortran source code. They have a `meson.build` file that specifies how to build the project, including the use of the Fortran language.
2. **Meson Configuration:** The user runs `meson setup builddir` to configure the build. Meson detects the available Fortran compiler on the system. This is where the logic in `mesonbuild/compilers/fortran.py` is used to identify the compiler and its capabilities.
3. **Compilation:** The user runs `meson compile -C builddir` to start the compilation process.
4. **Compiler Invocation:** Meson uses the classes and methods in this file to generate the correct command-line arguments to invoke the Fortran compiler on each Fortran source file. For example, it might call `compiler.get_compile_args()` to get the compilation flags.
5. **Linking:** After compiling the individual source files, Meson uses the information in this file to link the resulting object files into an executable or library. It might call `compiler.get_link_args()` and `compiler.find_library()` during this stage.
6. **Error/Success:** If there are errors during compilation or linking, the error messages often contain the exact compiler commands that were executed. By examining these commands, a developer can trace back to the logic within `frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/fortran.py` to understand how those commands were constructed and identify potential issues in the Meson configuration or the compiler setup.

In summary, this file is a foundational part of Frida's build system when dealing with Fortran code. It abstracts away the complexities of individual Fortran compilers, allowing Meson to manage the build process in a consistent way. While not directly involved in runtime instrumentation, it plays a vital role in creating the tools and potentially instrumenting Fortran applications.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/fortran.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```