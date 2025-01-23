Response:
Let's break down the request and the provided Python code to construct a comprehensive answer.

**1. Understanding the Core Request:**

The request asks for an analysis of the Python code, specifically focusing on:

* **Functionality:** What does this code do?
* **Relevance to Reverse Engineering:**  How does it relate to the process of understanding software?
* **Low-Level Aspects:**  How does it interact with the operating system (Linux, Android kernels), binary code, and frameworks?
* **Logical Reasoning:** What are the inputs and outputs of its components?
* **Common User Errors:** What mistakes might a user make while interacting with this code?
* **User Journey:** How does a user end up at this specific file in the Frida project?

**2. Initial Code Inspection and Keyword Identification:**

I started by quickly scanning the code for key terms and patterns:

* `mesonbuild`: This immediately tells me it's part of the Meson build system.
* `modules`, `ModuleState`, `ModuleObject`, `ExtensionModule`: These suggest this code defines the structure and base classes for Meson modules.
* `find_program`, `find_tool`, `dependency`: These are functions for locating external tools and libraries, common in build systems.
* `test`:  Indicates support for running tests.
* `get_option`:  Suggests access to build system configuration.
* `include_dirs`: Relates to managing header file locations.
* `Interpreter`:  A central object in Meson that manages the build process.
* `build.*`:  References to various build system concepts like `Executable`, `CustomTarget`, etc.
* `MachineChoice`:  Deals with cross-compilation (host vs. target machine).
* `SPDX-License-Identifier`:  Standard license declaration.
* `dataclasses`: Used for defining data classes.
* `typing`:  Type hinting for better code readability and static analysis.

**3. Deconstructing Functionality:**

Based on the keywords, I deduced the primary function of this file: **defining the core infrastructure for Meson modules**. It provides base classes and utility functions that individual Meson modules can use. This involves:

* **Module State Management:**  The `ModuleState` class encapsulates the context in which a module operates, providing access to project settings, directories, and the Meson interpreter.
* **Module Object Hierarchy:** `ModuleObject`, `MutableModuleObject`, `NewExtensionModule`, `ExtensionModule`, `NotFoundExtensionModule` define a class hierarchy for structuring different types of modules.
* **Common Module Operations:** Functions like `find_program`, `find_tool`, `dependency`, `test`, and `get_option` offer standardized ways for modules to interact with the build system and external resources.

**4. Connecting to Reverse Engineering:**

The connection to reverse engineering comes primarily through Frida's nature as a dynamic instrumentation tool. Meson is used to build Frida itself. Therefore, the mechanisms for finding tools and libraries (like `find_program`, `find_tool`, `dependency`) within this file are crucial for the Frida build process. These tools and libraries might include compilers, linkers, and potentially other reverse engineering-related utilities or libraries Frida depends on.

**5. Identifying Low-Level and Kernel/Framework Interactions:**

The mentions of "binary底层" (binary bottom layer), "linux, android内核及框架" (Linux, Android kernel and frameworks) made me think about *how* the build process interacts with these.

* **`find_program` and `find_tool`:** These functions are essential for locating compilers, linkers, and other binary tools needed to build Frida for different target platforms (including Linux and Android). The specific compilers and linkers used will have direct interaction with the target operating system's ABI (Application Binary Interface) and system calls.
* **Cross-Compilation (`MachineChoice`):**  Frida is often used to instrument processes on different architectures than the host machine. Meson's handling of cross-compilation, as suggested by `MachineChoice`, is relevant to building Frida for Android from a Linux development machine, for example.
* **Dependencies:** Frida likely relies on system libraries or frameworks (especially on Android). The `dependency` function handles finding and linking against these. On Android, this could include system libraries, NDK components, or even framework APIs.

**6. Formulating Logical Reasoning Examples:**

I considered hypothetical scenarios for input and output of the key functions:

* **`find_program`:**  *Input:*  Request to find the `gcc` compiler. *Output:* The path to the `gcc` executable on the system.
* **`get_option`:** *Input:* Request for the value of the `optimization_level` build option. *Output:*  Could be `"0"`, `"1"`, `"2"`, `"3"`, or `"s"`.
* **`dependency`:** *Input:* Request for the `openssl` library. *Output:* An object representing the found OpenSSL library, including its include directories and library paths.

**7. Considering Common User Errors:**

I thought about typical mistakes users make when working with build systems:

* **Incorrect toolchain setup:** The user might not have the required compilers or other tools installed or configured correctly in their `PATH`. This would cause `find_program` or `find_tool` to fail.
* **Missing dependencies:**  The user might be missing libraries that Frida depends on. This would cause the `dependency` function to fail.
* **Incorrect build options:**  The user might specify invalid or conflicting build options, which could lead to errors handled by the build system (though not directly in this specific file).

**8. Tracing the User Journey:**

Finally, I mapped out how a user would encounter this file:

1. **Developer wants to build Frida:**  A developer working with Frida needs to compile it from source.
2. **Using Meson:** Frida's build system is based on Meson.
3. **Meson execution:** The developer runs the `meson` command to configure the build.
4. **Module loading:** Meson loads and executes various modules to handle different aspects of the build process.
5. **Core module initialization:** The `__init__.py` file within `mesonbuild/modules` is a central part of the Meson module system and gets loaded early on to set up the basic module infrastructure.
6. **Frida-specific build files:**  Frida's `meson.build` files (and potentially other related files) will use the functionalities provided by the modules defined here.

**Self-Correction/Refinement:**

During the process, I might have initially focused too narrowly on the specifics of Frida. I realized the core functionality of this file is about the *generic* Meson module system. While the context is Frida, the code itself is about Meson's internal workings. Therefore, I adjusted the explanation to emphasize the general purpose of the file while still connecting it to Frida's build process. I also made sure to explain the relationships between the different classes (`ModuleObject`, `ExtensionModule`, etc.).
This Python code defines the foundational structure and common utilities for modules within the Meson build system. Since Frida uses Meson for its build process, this file is crucial for extending Meson's capabilities to handle Frida-specific build requirements. Let's break down its functionality and connections to reverse engineering, low-level details, and potential user errors.

**Functionality of `__init__.py` in Meson Modules:**

This file primarily serves as a blueprint and utility library for creating Meson modules. Here's a breakdown of its key components and their functions:

1. **Base Classes for Modules (`ModuleObject`, `MutableModuleObject`, `NewExtensionModule`, `ExtensionModule`, `NotFoundExtensionModule`):**
   - These classes provide a structured way to define Meson modules. Modules extend these base classes to add custom functionalities to the build system.
   - `ModuleObject` is the most basic, providing a dictionary (`methods`) to store the functions the module exposes.
   - `MutableModuleObject` is likely for modules that can modify their internal state.
   - `NewExtensionModule` and `ExtensionModule` (the latter being a legacy version) are used for modules that want to signal whether they were successfully found or initialized (`found_method`).
   - `NotFoundExtensionModule` is a specific case for modules that couldn't be located.

2. **`ModuleState` Class:**
   - This class acts as a container holding the current state of the Meson interpreter when a module function is called. It provides modules with access to vital information like:
     - Project source and build directories.
     - Subproject information.
     - Current line number in the Meson build file.
     - Environment variables.
     - Project name and version.
     - Build targets, data, headers, and man pages.
     - Global and project-specific arguments.
     - Current node in the Meson abstract syntax tree.
     - Whether the current subproject is build-only.

3. **Utility Functions in `ModuleState`:**
   - **`get_include_args`:** Converts a list of include directories (strings or `IncludeDirs` objects) into a list of compiler-compatible `-I` arguments.
   - **`find_program`:**  Searches for an external program (like a compiler or linker) on the system. It can also check the program's version.
   - **`find_tool`:**  Similar to `find_program`, but specifically designed to find tools that might be specified in machine files or through `pkg-config` variables.
   - **`dependency`:**  Resolves dependencies on external libraries or packages, using mechanisms like `pkg-config`.
   - **`test`:**  Registers a test to be run as part of the build process.
   - **`get_option`:**  Retrieves the value of a Meson build option.
   - **`is_user_defined_option`:** Checks if a specific build option was set by the user.
   - **`process_include_dirs`:** Converts a mixed iterable of strings and `IncludeDirs` into an iterable of `IncludeDirs` objects.
   - **`add_language`:**  Adds support for a specific programming language to the build.

4. **`ModuleInfo` Dataclass:**
   - Holds metadata about a module, such as its name, when it was added, deprecated, or stabilized.

5. **`ModuleReturnValue` Class:**
   - Represents the return value of a module function, which can include a standard return value and a list of new build objects created by the module.

6. **Target Class Stubs (e.g., `GResourceTarget`, `GirTarget`, `TypelibTarget`):**
   - These are likely placeholders or base classes for custom target types that specific Meson modules might define (though they don't contain much implementation here).

**Relationship to Reverse Engineering:**

Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. This `__init__.py` file, being a part of Frida's build system, plays an indirect but crucial role:

* **Building Frida Itself:**  The core function is to facilitate the compilation and linking of the Frida tools and libraries. This involves finding compilers, linkers, and necessary dependencies – all essential for producing the final Frida binaries.
* **Extensibility for Frida-Specific Tasks:** Frida might extend Meson with its own modules. This file provides the framework for creating those modules. These Frida-specific modules could automate tasks relevant to the reverse engineering workflow, such as:
    * **Packaging Frida for different platforms:**  Creating `.deb`, `.rpm`, or `.apk` packages.
    * **Generating specific build artifacts:**  Perhaps for injecting Frida into processes.
    * **Integrating with other reverse engineering tools:**  Automating steps in a larger analysis pipeline.

**Example:** Imagine a Frida Meson module that automates the process of building FridaGadget (the injectable library). This module might use `find_program` to locate the Android NDK's compilers, `dependency` to link against necessary Android libraries, and potentially create custom build targets using classes like `CustomTarget`.

**In the context of reverse engineering, this file ensures that the necessary infrastructure exists to build the tools (Frida) that are then used for reverse engineering.**

**Involvement of Binary 底层 (Bottom Layer), Linux, Android Kernel & Framework:**

* **`find_program` and Compilers/Linkers:** When building Frida (or any software), `find_program` is used to locate the compilers (like GCC, Clang) and linkers. These tools directly interact with the target system's ABI (Application Binary Interface) and instruction set architecture. This is the fundamental interaction with the "binary bottom layer."  For building Frida on Linux or Android, the respective system's compilers and linkers are crucial.
* **`dependency` and System Libraries:**  Frida likely depends on system libraries (e.g., `glibc` on Linux, various Android system libraries). The `dependency` function ensures these libraries are found and linked correctly. On Android, this can involve understanding the Android framework and NDK (Native Development Kit).
* **Cross-Compilation (`MachineChoice`):**  Frida is often used to instrument processes on different architectures (e.g., instrumenting an ARM Android app from an x86 development machine). The `MachineChoice` enum and related logic within Meson (and accessible to modules) are critical for setting up the correct toolchains and build environments for cross-compilation.
* **Building for Android:** When building Frida for Android, the Meson modules (or Frida-specific extensions) would use information from the Android NDK, potentially interacting with the Android SDK and build tools. This involves knowledge of the Android framework's structure and how native code interacts with it.

**Example:**  When building Frida for Android, `find_program` might locate `aarch64-linux-android-gcc` from the NDK. `dependency` might ensure that `liblog.so` (the Android logging library) is linked correctly.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `find_program` function within `ModuleState`:

**Hypothetical Input:**

* **`prog`:** `"gcc"` (string representing the program to find)
* **`required`:** `True` (the program is mandatory for the build)
* **`version_func`:** `None` (no specific version check)
* **`wanted`:** `""` (no specific version requirement)
* **`silent`:** `False` (allow output if not found)
* **`for_machine`:** `MachineChoice.HOST` (search for a program for the host machine)

**Hypothetical Output:**

If GCC is installed and in the system's `PATH`, the output would be an `ExternalProgram` object representing the GCC executable. This object would contain:

* **Path to the executable:**  e.g., `/usr/bin/gcc`
* **Whether it was found:** `True`
* **Potentially version information:** If `version_func` were provided.

**If GCC were not found, and `required` was `True`, Meson would raise an error, halting the build process.** If `required` were `False`, the `ExternalProgram` object would indicate that the program was not found.

**Common User or Programming Errors:**

1. **Incorrect Toolchain Setup:**
   - **Error:**  A user might try to build Frida for Android without having the Android NDK properly installed and configured.
   - **Symptom:** `find_program` would fail to locate the Android compilers (like `arm-linux-androideabi-gcc`), leading to a build error.
   - **User Action:** The user needs to ensure the NDK is installed and the necessary environment variables (e.g., `ANDROID_NDK_ROOT`) are set correctly.

2. **Missing Dependencies:**
   - **Error:** The user's system might be missing a library that Frida depends on (e.g., `libssl-dev`).
   - **Symptom:** The `dependency` function would fail to find the required package, resulting in a build error.
   - **User Action:** The user needs to install the missing dependency using their system's package manager (e.g., `apt-get install libssl-dev`).

3. **Misconfigured Build Options:**
   - **Error:** The user might pass incorrect or conflicting options to the `meson` command.
   - **Symptom:** This might not directly cause an error in *this* file, but it could lead to errors later in the build process or unexpected behavior. For example, providing an incorrect path to a dependency.
   - **User Action:** The user needs to review the Meson build options and ensure they are correct for their target platform and desired configuration.

4. **Incorrectly Implementing a Meson Module:**
   - **Error:** If someone is writing a new Meson module, they might misuse the `ModuleState` API or implement module methods incorrectly.
   - **Symptom:** This could lead to runtime errors during the Meson configuration or build process, or unexpected behavior of the module.
   - **User Action:** The module developer needs to carefully read the Meson documentation and understand the intended usage of the `ModuleState` methods and base classes.

**User Operation Stepping to This File (Debugging Clue):**

A user would indirectly reach this file during the Frida build process:

1. **Download Frida Source:** The user clones the Frida Git repository.
2. **Navigate to Build Directory:** The user creates a build directory (e.g., `build`) and navigates into it.
3. **Run Meson Configuration:** The user executes `meson setup ..` (or similar) to configure the build.
4. **Meson Loads Modules:**  As Meson processes the `meson.build` files in the Frida source, it needs to load and initialize its modules.
5. **`__init__.py` is Executed:** The Python interpreter executes the `__init__.py` file within the `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/` directory to initialize the module infrastructure.
6. **Potential Debugging Scenario:** If there's an error during module loading or if a Frida-specific module is being developed, a developer might need to step through the code in this `__init__.py` file or in the specific module's code to understand how the module system is being initialized and used. They might use Python debugging tools (like `pdb`) to trace the execution flow and inspect the `ModuleState` and other relevant variables.

In summary, while the user doesn't directly interact with this `__init__.py` file, it's a fundamental part of the machinery that enables Frida to be built. Understanding its functionality is crucial for anyone working on Frida's build system or developing custom Meson modules for Frida-related tasks.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/__init__.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 The Meson development team

# This file contains the base representation for import('modname')

from __future__ import annotations
import dataclasses
import typing as T

from .. import build, mesonlib
from ..build import IncludeDirs
from ..interpreterbase.decorators import noKwargs, noPosargs
from ..mesonlib import relpath, HoldableObject, MachineChoice
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from ..interpreter import Interpreter
    from ..interpreter.interpreter import ProgramVersionFunc
    from ..interpreterbase import TYPE_var, TYPE_kwargs
    from ..programs import OverrideProgram
    from ..wrap import WrapMode
    from ..dependencies import Dependency

class ModuleState:
    """Object passed to all module methods.

    This is a WIP API provided to modules, it should be extended to have everything
    needed so modules does not touch any other part of Meson internal APIs.
    """

    def __init__(self, interpreter: 'Interpreter') -> None:
        # Keep it private, it should be accessed only through methods.
        self._interpreter = interpreter

        self.source_root = interpreter.environment.get_source_dir()
        self.build_to_src = relpath(interpreter.environment.get_source_dir(),
                                    interpreter.environment.get_build_dir())
        self.subproject = interpreter.subproject
        self.subdir = interpreter.subdir
        self.root_subdir = interpreter.root_subdir
        self.current_lineno = interpreter.current_lineno
        self.environment = interpreter.environment
        self.project_name = interpreter.build.project_name
        self.project_version = interpreter.build.dep_manifest[interpreter.active_projectname].version
        # The backend object is under-used right now, but we will need it:
        # https://github.com/mesonbuild/meson/issues/1419
        self.backend = interpreter.backend
        self.targets = interpreter.build.targets
        self.data = interpreter.build.data
        self.headers = interpreter.build.get_headers()
        self.man = interpreter.build.get_man()
        self.global_args = interpreter.build.global_args.host
        self.project_args = interpreter.build.projects_args.host.get(interpreter.subproject, {})
        self.current_node = interpreter.current_node
        self.is_build_only_subproject = interpreter.coredata.is_build_only

    def get_include_args(self, include_dirs: T.Iterable[T.Union[str, build.IncludeDirs]], prefix: str = '-I') -> T.List[str]:
        if not include_dirs:
            return []

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()

        dirs_str: T.List[str] = []
        for dirs in include_dirs:
            if isinstance(dirs, str):
                dirs_str += [f'{prefix}{dirs}']
            else:
                dirs_str.extend([f'{prefix}{i}' for i in dirs.to_string_list(srcdir, builddir)])
                dirs_str.extend([f'{prefix}{i}' for i in dirs.get_extra_build_dirs()])

        return dirs_str

    def find_program(self, prog: T.Union[mesonlib.FileOrString, T.List[mesonlib.FileOrString]],
                     required: bool = True,
                     version_func: T.Optional[ProgramVersionFunc] = None,
                     wanted: T.Union[str, T.List[str]] = '', silent: bool = False,
                     for_machine: MachineChoice = MachineChoice.HOST) -> T.Union[ExternalProgram, build.Executable, OverrideProgram]:
        if not isinstance(prog, list):
            prog = [prog]
        return self._interpreter.find_program_impl(prog, required=required, version_func=version_func,
                                                   wanted=wanted, silent=silent, for_machine=for_machine)

    def find_tool(self, name: str, depname: str, varname: str, required: bool = True,
                  wanted: T.Optional[str] = None) -> T.Union['build.Executable', ExternalProgram, 'OverrideProgram']:
        # Look in overrides in case it's built as subproject
        progobj = self._interpreter.program_from_overrides([name], [], MachineChoice.HOST)
        if progobj is not None:
            return progobj

        # Look in machine file
        prog_list = self.environment.lookup_binary_entry(MachineChoice.HOST, name)
        if prog_list is not None:
            return ExternalProgram.from_entry(name, prog_list)

        # Check if pkgconfig has a variable
        dep = self.dependency(depname, native=True, required=False, wanted=wanted)
        if dep.found() and dep.type_name == 'pkgconfig':
            value = dep.get_variable(pkgconfig=varname)
            if value:
                progobj = ExternalProgram(value)
                if not progobj.found():
                    msg = (f'Dependency {depname!r} tool variable {varname!r} contains erroneous value: {value!r}\n\n'
                           f'This is a distributor issue -- please report it to your {depname} provider.')
                    raise mesonlib.MesonException(msg)
                return progobj

        # Normal program lookup
        return self.find_program(name, required=required, wanted=wanted)

    def dependency(self, depname: str, native: bool = False, required: bool = True,
                   wanted: T.Optional[str] = None) -> 'Dependency':
        kwargs: T.Dict[str, object] = {'native': native, 'required': required}
        if wanted:
            kwargs['version'] = wanted
        # FIXME: Even if we fix the function, mypy still can't figure out what's
        # going on here. And we really dont want to call interpreter
        # implementations of meson functions anyway.
        return self._interpreter.func_dependency(self.current_node, [depname], kwargs) # type: ignore

    def test(self, args: T.Tuple[str, T.Union[build.Executable, build.Jar, 'ExternalProgram', mesonlib.File]],
             workdir: T.Optional[str] = None,
             env: T.Union[T.List[str], T.Dict[str, str], str] = None,
             depends: T.List[T.Union[build.CustomTarget, build.BuildTarget]] = None) -> None:
        kwargs = {'workdir': workdir,
                  'env': env,
                  'depends': depends,
                  }
        # typed_* takes a list, and gives a tuple to func_test. Violating that constraint
        # makes the universe (or at least use of this function) implode
        real_args = list(args)
        # TODO: Use interpreter internal API, but we need to go through @typed_kwargs
        self._interpreter.func_test(self.current_node, real_args, kwargs)

    def get_option(self, name: str, subproject: str = '',
                   machine: MachineChoice = MachineChoice.HOST,
                   lang: T.Optional[str] = None,
                   module: T.Optional[str] = None) -> T.Union[T.List[str], str, int, bool, 'WrapMode']:
        return self.environment.coredata.get_option(mesonlib.OptionKey(name, subproject, machine, lang, module))

    def is_user_defined_option(self, name: str, subproject: str = '',
                               machine: MachineChoice = MachineChoice.HOST,
                               lang: T.Optional[str] = None,
                               module: T.Optional[str] = None) -> bool:
        key = mesonlib.OptionKey(name, subproject, machine, lang, module)
        return key in self._interpreter.user_defined_options.cmd_line_options

    def process_include_dirs(self, dirs: T.Iterable[T.Union[str, IncludeDirs]]) -> T.Iterable[IncludeDirs]:
        """Convert raw include directory arguments to only IncludeDirs

        :param dirs: An iterable of strings and IncludeDirs
        :return: None
        :yield: IncludeDirs objects
        """
        for d in dirs:
            if isinstance(d, IncludeDirs):
                yield d
            else:
                yield self._interpreter.build_incdir_object([d])

    def add_language(self, lang: str, for_machine: MachineChoice) -> None:
        self._interpreter.add_languages([lang], True, for_machine)

class ModuleObject(HoldableObject):
    """Base class for all objects returned by modules
    """
    def __init__(self) -> None:
        self.methods: T.Dict[
            str,
            T.Callable[[ModuleState, T.List['TYPE_var'], 'TYPE_kwargs'], T.Union[ModuleReturnValue, 'TYPE_var']]
        ] = {}


class MutableModuleObject(ModuleObject):
    pass


@dataclasses.dataclass
class ModuleInfo:

    """Metadata about a Module."""

    name: str
    added: T.Optional[str] = None
    deprecated: T.Optional[str] = None
    unstable: bool = False
    stabilized: T.Optional[str] = None


class NewExtensionModule(ModuleObject):

    """Class for modern modules

    provides the found method.
    """

    INFO: ModuleInfo

    def __init__(self) -> None:
        super().__init__()
        self.methods.update({
            'found': self.found_method,
        })

    @noPosargs
    @noKwargs
    def found_method(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> bool:
        return self.found()

    @staticmethod
    def found() -> bool:
        return True

    def postconf_hook(self, b: build.Build) -> None:
        pass

# FIXME: Port all modules to stop using self.interpreter and use API on
# ModuleState instead. Modules should stop using this class and instead use
# ModuleObject base class.
class ExtensionModule(NewExtensionModule):
    def __init__(self, interpreter: 'Interpreter') -> None:
        super().__init__()
        self.interpreter = interpreter

class NotFoundExtensionModule(NewExtensionModule):

    """Class for modern modules

    provides the found method.
    """

    def __init__(self, name: str) -> None:
        super().__init__()
        self.INFO = ModuleInfo(name)

    @staticmethod
    def found() -> bool:
        return False


def is_module_library(fname: mesonlib.FileOrString) -> bool:
    '''
    Check if the file is a library-like file generated by a module-specific
    target, such as GirTarget or TypelibTarget
    '''
    suffix = fname.split('.')[-1]
    return suffix in {'gir', 'typelib'}


class ModuleReturnValue:
    def __init__(self, return_value: T.Optional['TYPE_var'],
                 new_objects: T.Sequence[T.Union['TYPE_var', 'mesonlib.ExecutableSerialisation']]) -> None:
        self.return_value = return_value
        assert isinstance(new_objects, list)
        self.new_objects: T.List[T.Union['TYPE_var', 'mesonlib.ExecutableSerialisation']] = new_objects

class GResourceTarget(build.CustomTarget):
    source_dirs: T.List[str] = []

class GResourceHeaderTarget(build.CustomTarget):
    pass

class GirTarget(build.CustomTarget):
    pass

class TypelibTarget(build.CustomTarget):
    pass

class VapiTarget(build.CustomTarget):
    pass
```