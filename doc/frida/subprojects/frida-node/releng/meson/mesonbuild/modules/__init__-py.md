Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Initial Understanding of the File's Purpose:**

The file path `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/__init__.py` immediately suggests this is part of the Meson build system used within the Frida project. The `__init__.py` file signifies this directory `modules` is a Python package, and this file initializes that package. Given the context of "modules," it's likely defining the structure and base classes for extending Meson's functionality.

**2. Identifying Key Classes and Their Roles:**

A quick scan reveals several important classes:

* `ModuleState`: This class appears to hold contextual information passed to module methods. The attributes within it (like `source_root`, `build_to_src`, `interpreter`, `environment`, etc.) point towards it being a bridge between the module's logic and Meson's internal state.
* `ModuleObject`: This looks like the base class for all custom modules. The `methods` dictionary suggests a way to register functions that can be called from Meson build files.
* `MutableModuleObject`:  Likely a variation of `ModuleObject`, possibly allowing modifications to its state.
* `ModuleInfo`: A dataclass for storing metadata about modules (name, deprecation status, etc.).
* `NewExtensionModule` and `ExtensionModule`: These seem to be specific types of modules. The presence of `found_method` in `NewExtensionModule` indicates a common way for modules to report their availability. The comment about `ExtensionModule` using `self.interpreter` is a key observation, suggesting a potential evolution in the module architecture.
* `NotFoundExtensionModule`: Clearly designed for modules that aren't available.
* `ModuleReturnValue`: A structure for packaging the result of a module function, including the return value and potentially new build objects.
* `GResourceTarget`, `GResourceHeaderTarget`, `GirTarget`, `TypelibTarget`, `VapiTarget`: These look like specialized custom build targets, likely related to specific technologies (like GObject resources, introspection, etc.).

**3. Analyzing Key Methods and Logic:**

* **`ModuleState.__init__`:** Populating this with data from the `Interpreter` strongly confirms its role as a context provider.
* **`ModuleState.get_include_args`:**  This clearly deals with handling include directories, a very common task in building software.
* **`ModuleState.find_program` and `find_tool`:** These are crucial for finding external tools and programs required during the build process. The logic around overrides, machine files, and pkg-config is noteworthy.
* **`ModuleState.dependency`:**  This method handles finding and managing dependencies, a cornerstone of any build system.
* **`ModuleState.test`:**  This facilitates running tests as part of the build.
* **`ModuleState.get_option` and `is_user_defined_option`:**  These deal with accessing and checking Meson's configuration options.
* **`ModuleState.process_include_dirs`:**  A utility for standardizing include directory handling.
* **`ModuleState.add_language`:**  Allows modules to declare that a specific language is needed for the project.
* **`NewExtensionModule.found_method` and `found`:**  Provide a standard way to check if a module is available.
* **`is_module_library`:**  A simple helper to identify specific file types.

**4. Connecting to the Prompt's Questions:**

Now, systematically address each point in the prompt:

* **Functionality:**  Summarize the roles of the key classes and methods identified in steps 2 and 3. Focus on the core purpose of providing a framework for extending Meson.
* **Relationship to Reversing:**  Think about how the capabilities provided by these modules could be used in a reverse engineering context. Frida's focus on dynamic instrumentation immediately brings to mind the need to interact with processes, potentially compile code on the fly, and access system resources. The module system facilitates integrating these kinds of tools and logic into the build process for setting up the reverse engineering environment.
* **Binary/Low-Level/Kernel Knowledge:** Consider what operations the modules might need to perform. Finding programs, managing dependencies (especially native ones), and potentially compiling code all touch on these areas. The mention of Android in the prompt also hints at the potential use of these modules for setting up or interacting with Android build environments, which definitely involves kernel and framework knowledge.
* **Logical Inference:** Examine methods that take input and produce output. `get_include_args` is a prime example. Hypothesize different input scenarios (string paths, `IncludeDirs` objects) and trace how the method would process them to generate compiler flags.
* **Common Usage Errors:**  Think about how a user might misuse the provided functions. Incorrectly specifying paths in `find_program`, typos in dependency names, or providing the wrong type of arguments to methods are all possibilities.
* **User Journey/Debugging Clues:**  Imagine a user interacting with Meson. They would write a `meson.build` file, use the `import()` function to load a module, and then call methods provided by that module. Errors within the module's code or incorrect usage of its API would lead to stack traces that would point back to this file, especially the module loading and method invocation mechanisms.

**5. Structuring the Answer:**

Organize the information gathered in step 4 into a clear and coherent response, addressing each point of the prompt systematically. Use code snippets and concrete examples where appropriate. Emphasize the connections between the code and the concepts of reverse engineering, low-level details, and potential errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file directly implements a specific Frida feature.
* **Correction:**  The file path and content clearly indicate it's about Meson modules, a general build system concept. Frida is *using* Meson and extending it through this mechanism.
* **Initial thought:** Focus heavily on the specific target types (`GirTarget`, etc.).
* **Correction:** While these are relevant, the core functionality lies in the base classes like `ModuleState` and `ModuleObject`, which provide the general infrastructure. The target types are specific examples of how this infrastructure is used.
* **Refinement:** When explaining the relationship to reverse engineering, be specific about *how* these modules could be used in that context (e.g., setting up a debugging environment, integrating custom tools). Avoid vague statements.

By following this thought process, breaking down the code, and systematically addressing the prompt's questions, we can generate a comprehensive and informative answer.
This Python file, located within the Meson build system's module infrastructure for Frida's Node.js bindings, defines the foundational elements for creating and using custom modules within the Meson build process. Essentially, it provides the building blocks for extending Meson's capabilities. Let's break down its functionalities in relation to your questions:

**1. Core Functionalities:**

* **Module Base Classes (`ModuleObject`, `MutableModuleObject`, `NewExtensionModule`, `ExtensionModule`, `NotFoundExtensionModule`):** These classes serve as templates for creating specific Meson modules. They define a standard structure for modules, including:
    * **Methods Dictionary:** A place to register functions that the module exposes to the `meson.build` files.
    * **`found()` method:** Indicates whether the module is available or not (especially for `NewExtensionModule` and its variations).
    * **`postconf_hook()`:** A hook that can be executed after the configuration phase of the build.
    * **`INFO` attribute:** (in `NewExtensionModule`) Stores metadata about the module like its name, when it was added, and deprecation status.

* **`ModuleState` Class:** This crucial class acts as a context object passed to the methods of a module. It provides access to various aspects of the current Meson build environment, such as:
    * **Project Information:** Name, version, source and build directories, subproject details.
    * **Environment Details:**  Compiler information, machine architecture.
    * **Build Artifacts:** Targets, data files, headers, man pages.
    * **Configuration Options:** Global and project-specific arguments.
    * **Interpreter Instance:**  Provides access to Meson's internal functionalities (though the comments suggest this is being phased out in favor of using `ModuleState` methods).

* **Utility Methods within `ModuleState`:** These methods offer common operations that module developers might need:
    * **`get_include_args()`:**  Generates compiler include flags from a list of directories.
    * **`find_program()`:** Locates an external program.
    * **`find_tool()`:**  Specifically finds build tools, potentially looking in overrides, machine files, and pkg-config variables.
    * **`dependency()`:**  Resolves and retrieves information about project dependencies.
    * **`test()`:**  Registers a test to be run as part of the build process.
    * **`get_option()` and `is_user_defined_option()`:**  Retrieves and checks the status of Meson build options.
    * **`process_include_dirs()`:**  Converts include directory arguments to a standard `IncludeDirs` object.
    * **`add_language()`:**  Declares the usage of a specific programming language.

* **`ModuleReturnValue` Class:**  Used to encapsulate the return value of a module method, including the actual returned value and any new build objects created by the module.

* **Specialized Target Classes (`GResourceTarget`, `GResourceHeaderTarget`, `GirTarget`, `TypelibTarget`, `VapiTarget`):** These likely represent pre-defined custom target types that are commonly used within the GNOME ecosystem (related to GObject resources, introspection, etc.). While not directly about module *creation*, their presence here suggests that these might be provided as building blocks within certain Meson modules.

* **`is_module_library()` Function:** A simple utility to check if a file is a library-like output from a module-specific target.

**2. Relationship to Reverse Engineering (with Examples):**

This file is fundamental to how Frida, a dynamic instrumentation toolkit heavily used in reverse engineering, integrates with the Meson build system. Here's how it relates:

* **Extending Build Capabilities:** Frida often needs custom build steps for its various components. Meson modules allow Frida developers to define these custom steps within their build process.
    * **Example:** A Frida module could be created to automate the process of generating code stubs from header files for different target architectures. This involves parsing headers (a common reverse engineering task), generating C code, and compiling it. The module would use `find_program()` to locate compilers and potentially tools like `clang` or `gcc`, and `custom_target()` (within the module's methods) to define the code generation and compilation steps.

* **Integrating External Tools:** Reverse engineering frequently involves using specialized tools. Meson modules can simplify the integration of these tools into the build workflow.
    * **Example:**  A module might integrate a disassembler like `capstone` or `keystone`. The module could provide functions to disassemble specific code sections or assemble new code during the build process. `find_program()` would be used to locate these tools.

* **Conditional Build Logic:**  Frida supports multiple platforms and architectures. Modules can implement logic to conditionally include or exclude certain build steps or dependencies based on the target environment. This is crucial for handling platform-specific code in reverse engineering scenarios.
    * **Example:** A module could check the target operating system and architecture using information from `ModuleState.environment` and then decide whether to compile and link a specific hooking library.

* **Generating Target-Specific Code:** Frida often needs to generate code that interacts with the target process's memory and functions. Modules can automate the creation of this code based on target characteristics.
    * **Example:**  A module could analyze a target executable format (PE, ELF, Mach-O) and generate Frida scripts or C code that can interact with specific functions or data structures within that executable. This would involve interacting with binary formats, a core aspect of reverse engineering.

**3. Relationship to Binary, Linux, Android Kernel/Framework Knowledge (with Examples):**

The functionalities defined in this file are essential for tasks that touch upon low-level aspects:

* **Finding and Using Binary Tools:** The `find_program()` and `find_tool()` methods are directly involved in locating binary executables (compilers, linkers, assemblers, debuggers, etc.) that are crucial for building software that interacts with the underlying system.
    * **Example:**  When building Frida for Android, a module might need to find the Android NDK's compilers (`arm-linux-androideabi-gcc`, `aarch64-linux-android-clang`) to cross-compile Frida's agent for the target device.

* **Handling Dependencies (Including Native Ones):** The `dependency()` method allows modules to declare dependencies, which can include native libraries (e.g., `libc`, `libdl`). Building Frida, which often needs to interact directly with system libraries, heavily relies on managing these native dependencies.
    * **Example:**  On Linux, Frida needs to link against `libpthread` for threading support. A module would use `dependency('threads')` to ensure this dependency is met.

* **Dealing with Include Directories:** The `get_include_args()` and `process_include_dirs()` methods are fundamental for managing header file paths. When working with kernel headers or system libraries (common in reverse engineering and system-level programming), correct include paths are critical.
    * **Example:** When building Frida components that interact with the Android kernel, modules might need to include headers from the Android kernel source tree.

* **Custom Build Steps for Kernel Modules or System Components:** While Frida itself isn't a kernel module, the principles of custom build steps facilitated by this file can be applied to building software that interacts closely with the kernel or framework.
    * **Example (Hypothetical):**  Imagine a Frida extension that needs to compile a small kernel module for specific hooking purposes. A Meson module could orchestrate the compilation of this kernel module, using tools like `make` and `insmod`, by defining a `custom_target()` within its methods.

**4. Logical Inference (with Hypothetical Input/Output):**

Let's consider the `get_include_args()` method:

* **Hypothetical Input:**
    ```python
    include_dirs = ["/path/to/headers", build.IncludeDirs(["relative/path"], is_system=False)]
    prefix = "-I"
    ```

* **Logical Processing:** The `get_include_args()` method would iterate through the `include_dirs`:
    * For the string "/path/to/headers", it would simply prepend the `prefix`, resulting in "-I/path/to/headers".
    * For the `IncludeDirs` object, it would convert the relative path "relative/path" to an absolute path based on the source and build directories (assuming these are known to the `ModuleState`). It would also check the `is_system` flag (which is `False` here) and potentially add extra build directories if needed.

* **Hypothetical Output:**
    ```python
    ["-I/path/to/headers", "-I/absolute/path/to/source/relative/path"]
    ```
    (The exact output for the `IncludeDirs` part depends on the source and build directory structure.)

**5. Common User or Programming Errors (with Examples):**

* **Incorrect Path in `find_program()`:** If a module calls `state.find_program('my-custom-tool')` but `my-custom-tool` is not in the system's PATH or a configured binary directory, the build will fail with an error indicating the program was not found.

* **Typo in Dependency Name:**  If a module uses `state.dependency('my-lib')` but the actual dependency is named `mylib`, the dependency resolution will fail.

* **Providing the Wrong Type of Argument to a Module Method:** If a module's method expects a list of strings but the user provides a single string in their `meson.build` file, a type error will occur during the build configuration phase.

* **Incorrectly Handling `IncludeDirs`:**  If a module tries to directly manipulate the string paths within an `IncludeDirs` object without using its provided methods, it might lead to incorrect include paths being generated.

* **Not Checking the `found()` Status of a Module:** If a module depends on another optional module, it should check the `found()` status of the dependency before attempting to use its methods. Failing to do so could result in runtime errors during the build process.

**6. User Operation Steps to Reach This Code (Debugging Clues):**

A user would indirectly reach this code by interacting with Frida's build system:

1. **Clone the Frida repository:** The user would start by obtaining the Frida source code.
2. **Navigate to the `frida-node` subdirectory:** Since this file is within `frida/subprojects/frida-node`, the user is likely building the Node.js bindings for Frida.
3. **Run the Meson configuration command:** The user would execute a command like `meson setup build` (or similar) from the `frida-node` directory or its parent. This command triggers Meson to read the `meson.build` files.
4. **`meson.build` file imports a custom module:**  Within the `meson.build` files in the `frida-node` project, there will be lines that import custom Meson modules (likely located in other Python files within the Frida project). The `import('modname')` statement is the entry point for using these modules.
5. **Module method is called:** The `meson.build` files will then call methods defined within the imported modules using the module object returned by the `import()` function.
6. **Execution within the module:** When a module method is called, Meson creates a `ModuleState` object and passes it to the method, along with the arguments provided in the `meson.build` file. The code within this `__init__.py` file defines the base classes and utilities that are used by those module methods.

**Debugging Scenario:** If a user encounters an error related to a custom Frida Meson module, the debugging process might involve:

* **Examining the error message:** Meson often provides traceback information that points to the line in the `meson.build` file where the error occurred or to the relevant code within the custom module.
* **Inspecting the custom module's code:** The developer would look at the Python code of the specific module being used to understand its logic and how it interacts with the `ModuleState` and the base classes defined in `__init__.py`.
* **Setting breakpoints:**  If necessary, developers can use Python debugging tools to set breakpoints within the custom module's code and step through its execution to understand the flow of control and the values of variables, including the `ModuleState`.

In essence, this `__init__.py` file is a foundational part of Frida's build system, enabling a modular and extensible build process that is essential for a complex project like Frida, which needs to support multiple platforms and integrate various tools and libraries.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/__init__.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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