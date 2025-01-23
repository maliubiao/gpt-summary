Response:
Let's break down the thought process for analyzing this Python code snippet. The goal is to understand its functionality, its relevance to reverse engineering, low-level concepts, logical reasoning, common errors, and how a user might reach this code.

**1. Initial Understanding of the File's Purpose:**

* **File Path:** `frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/kwargs.py`  This path gives strong clues.
    * `frida`: Indicates this is part of the Frida dynamic instrumentation toolkit.
    * `subprojects/frida-tools`: Suggests this is a utility or build-related component within Frida.
    * `releng/meson`:  Points to the use of the Meson build system for release engineering.
    * `mesonbuild/interpreter`: This is the core of Meson's interpretation of its build definition files (`meson.build`).
    * `kwargs.py`: The filename strongly suggests that this file defines the structure and expected keyword arguments for various functions within the Meson build system, specifically as used by Frida.

* **File Content - Imports and Docstring:** The imports confirm the Meson context (`build`, `coredata`, `compilers`, etc.). The docstring clearly states "Keyword Argument type annotations."  This solidifies the initial understanding.

**2. Deconstructing the Code - Type Definitions:**

The code is primarily a collection of `TypedDict` definitions. Each `TypedDict` represents the expected keyword arguments for a specific function or group of related functions within Meson.

* **Iterate Through `TypedDict`s:** Go through each `TypedDict` one by one. Identify the name (e.g., `FuncAddProjectArgs`, `BaseTest`, `CustomTarget`). The name often hints at the Meson function it's associated with (though not always directly).
* **Analyze the Fields:** For each field in a `TypedDict`, note its name, its type annotation (e.g., `T.List[str]`, `bool`, `T.Optional[str]`, `Literal[...]`), and any comments provided.
* **Look for Patterns and Connections:** Notice recurring patterns and shared bases. For example, `FuncBenchmark` and `FuncTest` share fields, indicating a hierarchical relationship. Fields like `depends`, `env`, `install_dir` appear in multiple `TypedDict`s, suggesting common functionalities.

**3. Connecting to Frida and Reverse Engineering:**

This is where the knowledge of Frida comes in. How do the Meson build system and the defined keyword arguments relate to Frida's core functionality?

* **Frida's Purpose:** Frida is used for dynamic instrumentation – injecting code into running processes to observe and modify their behavior. This is a key technique in reverse engineering.
* **Build Process for Instrumentation:**  Consider how Frida itself is built. It likely involves compiling native code, creating libraries, and packaging components for different platforms (Linux, Android, etc.). The Meson build system orchestrates this.
* **Mapping `TypedDict`s to Frida's Needs:**  Start connecting the defined keyword arguments to steps in the Frida build process:
    * `FuncAddProjectArgs`:  Setting compiler flags for different architectures (native vs. target).
    * `FuncTest`, `FuncBenchmark`: Defining and running tests as part of the build process, crucial for ensuring Frida's functionality. These tests might even *use* Frida itself to test instrumented programs.
    * `CustomTarget`, `RunTarget`: Executing custom build steps or running specific commands, which could include tasks like code generation or packaging.
    * `Executable`, `SharedLibrary`, `StaticLibrary`: Defining how Frida's core components (the agent, the core library, etc.) are built.
    * `FuncInstallSubdir`, `FuncInstallData`: Handling the installation of Frida components to the correct locations.

**4. Identifying Low-Level and Kernel/Framework Connections:**

* **Compilation and Linking:** The presence of fields like `c_args`, `cpp_args`, `link_args`, and the definition of different library types (static, shared) clearly relate to the low-level compilation and linking processes.
* **Platform Specifics:** The `native: MachineChoice` field highlights the need to build Frida for different target architectures (x86, ARM, etc.).
* **Installation Locations:**  Fields like `install_dir` directly relate to file system organization and where Frida's components are placed, which is relevant to how it interacts with the operating system.
* **Android Context:** While not explicitly Android-specific in *this* file, consider that Frida heavily targets Android. The build process likely involves steps specific to Android, which might be configured using these keyword arguments in other parts of the Meson build definition.

**5. Logical Reasoning and Hypothetical Inputs/Outputs:**

* **Focus on Specific `TypedDict`s:** Pick a few `TypedDict`s with clear functionality, like `FuncTest` or `CustomTarget`.
* **Assume Input Values:**  Imagine how a developer would use the corresponding Meson functions and provide values for the keyword arguments.
* **Predict the Outcome:**  Based on the field names and types, infer what Meson will do with those inputs. For instance, with `FuncTest`, setting `is_parallel=True` suggests that Meson will try to run tests concurrently. With `CustomTarget`, providing a list of commands will lead to those commands being executed during the build.

**6. Identifying Potential User Errors:**

* **Type Mismatches:** The strong typing provided by `TypedDict` helps prevent errors. A common mistake would be providing a value of the wrong type (e.g., a string instead of a boolean).
* **Missing Required Arguments:**  While `TypedDict` enforces the presence of non-`Optional` fields, the logic of the build system might still require certain combinations of arguments.
* **Incorrect File Paths:** Providing incorrect paths for source files or dependencies is a classic build error.
* **Misunderstanding Argument Semantics:** Users might misunderstand the purpose of certain arguments and provide inappropriate values.

**7. Tracing User Operations (Debugging Context):**

* **`meson.build` Files:**  Users interact with Meson by writing `meson.build` files. These files contain calls to Meson functions (like `executable()`, `test()`, `custom_target()`).
* **Meson Command-Line:** Users run Meson commands (e.g., `meson setup`, `meson compile`, `meson test`).
* **Meson Interpreter:** When Meson runs, its interpreter parses the `meson.build` files. When it encounters a function call, it uses the information in `kwargs.py` to validate the provided keyword arguments.
* **Reaching `kwargs.py`:**  If a user makes a mistake in the keyword arguments of a Meson function call in their `meson.build` file, the Meson interpreter will raise an error, potentially referencing the definitions in `kwargs.py` (though the error message might not directly point to this file).

**Self-Correction/Refinement During the Process:**

* **Initial Overgeneralization:**  Initially, one might be tempted to explain the entire Meson build system. It's important to focus specifically on what this `kwargs.py` file contributes.
* **Lack of Concrete Examples:**  Abstract explanations are less helpful. Actively thinking of concrete examples (e.g., setting compiler flags, running a specific test command) makes the analysis more tangible.
* **Connecting Back to Frida's Core Purpose:**  Constantly asking "How does this relate to Frida's dynamic instrumentation capabilities?" helps to filter out irrelevant details and focus on the most important aspects.

By following these steps, combining code analysis with domain knowledge (Frida, build systems), and considering user interactions and potential errors, we can arrive at a comprehensive understanding of the `kwargs.py` file's role.
This Python file, `kwargs.py`, located within the Frida project's build system configuration, primarily serves as a **definition of the expected keyword arguments for various functions used in the Meson build system**. Think of it as a type annotation file that helps Meson understand the valid inputs for its built-in functions when constructing the Frida project.

Here's a breakdown of its functionalities:

**1. Defining Keyword Argument Structures (Type Annotations):**

* **Purpose:** The core function of this file is to define `TypedDict` classes. Each `TypedDict` acts as a blueprint specifying the names, expected data types, and whether they are required or optional for the keyword arguments of specific Meson functions.
* **Example:** The `FuncAddProjectArgs` `TypedDict` defines the expected keyword arguments for functions like `add_global_arguments` and `add_project_arguments`. It specifies that these functions expect a `native` argument of type `MachineChoice` and a `language` argument as a list of strings.

**2. Enhancing Code Readability and Maintainability:**

* **Clarity:** By explicitly defining the expected keyword arguments, the code becomes more readable and easier to understand. Developers can quickly see what arguments are expected by various Meson functions.
* **Error Prevention:** These type annotations can be used by static analysis tools and the Meson interpreter itself to detect potential errors early in the development process, such as passing the wrong type of argument or missing a required argument.

**3. Supporting Meson's Internal Type Checking:**

* **Validation:** Meson uses these type definitions during the build process to validate the arguments passed to its functions in the `meson.build` files. If the arguments don't match the defined types, Meson will likely raise an error.

**Relationship to Reverse Engineering:**

While this file itself doesn't directly perform reverse engineering, it plays a crucial role in **building the Frida tools**, which are heavily used for reverse engineering.

* **Building Frida's Components:** Frida consists of various components (e.g., the Frida server, command-line tools, language bindings). This `kwargs.py` file helps define how these components are built using Meson.
* **Defining Build Targets:** The `TypedDict`s like `Executable`, `SharedLibrary`, `StaticLibrary`, and `CustomTarget` are used to define how different binary targets (executables, libraries) of Frida are built. This involves specifying source files, dependencies, compiler flags, and linker options. These are fundamental aspects of understanding how software is constructed, which is often a preliminary step in reverse engineering.
* **Example:**  Imagine Frida needs to build a shared library (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows) that will be injected into a target process. The `SharedLibrary` `TypedDict` will define the expected arguments for the Meson function that creates this shared library target. This includes specifying the source code files, any dependent libraries, and potentially flags related to code generation or linking that are relevant to how Frida interacts with the target process at a low level.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This file indirectly reflects knowledge of these areas by defining the build process for Frida, which directly interacts with them.

* **Binary Bottom:**
    * **Executable and Library Types:** The definitions for `Executable`, `SharedLibrary`, `StaticLibrary`, and `SharedModule` directly deal with the different types of binary artifacts that are created during the build process. Understanding these distinctions is crucial when working with compiled code at a binary level.
    * **Compiler and Linker Flags:** While not explicitly defined *here*, the keyword arguments these `TypedDict`s represent (like `c_args`, `cpp_args`, `link_args`) are used to pass flags to the compiler and linker. These flags directly influence the generated binary code, its layout in memory, and its interaction with the operating system.
* **Linux and Android Kernel/Framework:**
    * **Shared Libraries and Modules:** The concepts of shared libraries (`.so`) and shared modules are core to both Linux and Android. Frida often injects shared libraries into running processes. The `SharedLibrary` and `SharedModule` definitions are essential for building these components correctly.
    * **Installation Directories:** The `FuncInstallSubdir` and `FuncInstallData` `TypedDict`s define how files are installed, including specifying installation directories. These directories often correspond to standard locations within Linux and Android file systems where libraries and executables are expected to reside for the operating system to find and load them.
    * **Android Specifics (Implicit):** While not explicitly mentioning "Android" in most of these definitions, the fact that Frida heavily targets Android means that the build process configured through these `TypedDict`s will involve steps and configurations relevant to the Android environment (e.g., cross-compilation, handling Android ABIs).

**Logical Reasoning with Assumptions:**

Let's take the `FuncTest` `TypedDict` as an example:

* **Assumption Input:**  A developer wants to define a test case for a Frida component. In their `meson.build` file, they might call the `test()` function with the following keyword arguments:
   ```python
   test(
       'my_cool_test',
       './run_my_test.sh',
       args: ['--verbose', '--count=10'],
       timeout: 30,
       is_parallel: True,
       suite: ['unit']
   )
   ```
* **Logical Reasoning based on `FuncTest`:**
    * Meson will expect an `args` keyword with a list of strings.
    * It will expect a `timeout` keyword with an integer representing seconds.
    * It will expect `is_parallel` to be a boolean.
    * It will expect `suite` to be a list of strings.
* **Output/Behavior:**  Meson will configure a test named "my_cool_test" that executes the script `./run_my_test.sh` with the specified arguments. The test will have a timeout of 30 seconds and will be scheduled to run in parallel with other tests. It will be categorized under the "unit" test suite.

**Common User/Programming Errors:**

* **Incorrect Data Types:**
    * **Example:**  Providing a string for the `timeout` argument in `FuncTest` instead of an integer (e.g., `timeout: "30"`). Meson would likely raise a type error based on the `int` annotation.
* **Missing Required Arguments:**
    * **Example:** If a `TypedDict` has a field that is not `Optional`, and the user omits that keyword argument in their `meson.build` file, Meson will report an error.
* **Misspelled Keyword Arguments:**
    * **Example:**  Typing `argss` instead of `args` in the `test()` function call. Meson would not recognize this as a valid keyword argument defined in `FuncTest`.
* **Providing Incorrect Values for `Literal` Types:**
    * **Example:**  If a `TypedDict` uses `Literal` to restrict values (e.g., `protocol: Literal['exitcode', 'tap']`), providing a different string would lead to an error.
* **Incorrectly Specifying File Paths:**
    * **Example:** Providing a non-existent file path for a source file in an `Executable` definition.

**User Operations Leading Here (Debugging Context):**

1. **Writing `meson.build` files:** A developer working on Frida writes `meson.build` files to define how the project should be built.
2. **Using Meson Functions:** Within these `meson.build` files, they call various Meson built-in functions like `executable()`, `shared_library()`, `test()`, `custom_target()`, etc.
3. **Providing Keyword Arguments:** When calling these Meson functions, the developer provides keyword arguments to configure the build process.
4. **Meson Interpretation:** When the developer runs the `meson` command to configure the build (e.g., `meson setup builddir`), the Meson interpreter parses the `meson.build` files.
5. **Validation Against `kwargs.py`:** The interpreter uses the definitions in `kwargs.py` to validate the keyword arguments provided by the developer.
6. **Error Detection:** If the developer has made a mistake (e.g., incorrect type, missing argument), the Meson interpreter will likely raise an error message, often indicating the problematic function call and the type of error. While the error message might not directly point to `kwargs.py`, understanding that this file defines the expected arguments is crucial for debugging.

In summary, `kwargs.py` is a foundational file within Frida's Meson build system that defines the structure and expected types for keyword arguments used in build definitions. It plays an indirect but essential role in building the Frida tools used for reverse engineering and reflects underlying knowledge of binary formats, operating system concepts, and software development practices. Understanding this file helps in comprehending how Frida is constructed and in debugging build-related issues.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2021 The Meson Developers
# Copyright © 2021 Intel Corporation
from __future__ import annotations

"""Keyword Argument type annotations."""

import typing as T

from typing_extensions import TypedDict, Literal, Protocol, NotRequired

from .. import build
from .. import coredata
from ..compilers import Compiler
from ..dependencies.base import Dependency
from ..mesonlib import EnvironmentVariables, MachineChoice, File, FileMode, FileOrString, OptionKey
from ..modules.cmake import CMakeSubprojectOptions
from ..programs import ExternalProgram
from .type_checking import PkgConfigDefineType, SourcesVarargsType

class FuncAddProjectArgs(TypedDict):

    """Keyword Arguments for the add_*_arguments family of arguments.

    including `add_global_arguments`, `add_project_arguments`, and their
    link variants

    Because of the use of a convertor function, we get the native keyword as
    a MachineChoice instance already.
    """

    native: MachineChoice
    language: T.List[str]


class BaseTest(TypedDict):

    """Shared base for the Rust module."""

    args: T.List[T.Union[str, File, build.Target]]
    should_fail: bool
    timeout: int
    workdir: T.Optional[str]
    depends: T.List[T.Union[build.CustomTarget, build.BuildTarget]]
    priority: int
    env: EnvironmentVariables
    suite: T.List[str]


class FuncBenchmark(BaseTest):

    """Keyword Arguments shared between `test` and `benchmark`."""

    protocol: Literal['exitcode', 'tap', 'gtest', 'rust']


class FuncTest(FuncBenchmark):

    """Keyword Arguments for `test`

    `test` only adds the `is_parallel` argument over benchmark, so inheritance
    is helpful here.
    """

    is_parallel: bool


class ExtractRequired(TypedDict):

    """Keyword Arguments consumed by the `extract_required_kwargs` function.

    Any function that uses the `required` keyword argument which accepts either
    a boolean or a feature option should inherit it's arguments from this class.
    """

    required: T.Union[bool, coredata.UserFeatureOption]


class ExtractSearchDirs(TypedDict):

    """Keyword arguments consumed by the `extract_search_dirs` function.

    See the not in `ExtractRequired`
    """

    dirs: T.List[str]


class FuncGenerator(TypedDict):

    """Keyword rguments for the generator function."""

    arguments: T.List[str]
    output: T.List[str]
    depfile: T.Optional[str]
    capture:  bool
    depends: T.List[T.Union[build.BuildTarget, build.CustomTarget]]


class GeneratorProcess(TypedDict):

    """Keyword Arguments for generator.process."""

    preserve_path_from: T.Optional[str]
    extra_args: T.List[str]
    env: EnvironmentVariables

class DependencyMethodPartialDependency(TypedDict):

    """ Keyword Arguments for the dep.partial_dependency methods """

    compile_args: bool
    link_args: bool
    links: bool
    includes: bool
    sources: bool

class BuildTargeMethodExtractAllObjects(TypedDict):
    recursive: bool

class FuncInstallSubdir(TypedDict):

    install_dir: str
    strip_directory: bool
    exclude_files: T.List[str]
    exclude_directories: T.List[str]
    install_mode: FileMode
    follow_symlinks: T.Optional[bool]


class FuncInstallData(TypedDict):

    install_dir: str
    sources: T.List[FileOrString]
    rename: T.List[str]
    install_mode: FileMode
    follow_symlinks: T.Optional[bool]


class FuncInstallHeaders(TypedDict):

    install_dir: T.Optional[str]
    install_mode: FileMode
    subdir: T.Optional[str]
    follow_symlinks: T.Optional[bool]


class FuncInstallMan(TypedDict):

    install_dir: T.Optional[str]
    install_mode: FileMode
    locale: T.Optional[str]


class FuncImportModule(ExtractRequired):

    disabler: bool


class FuncIncludeDirectories(TypedDict):

    is_system: bool

class FuncAddLanguages(ExtractRequired):

    native: T.Optional[bool]

class RunTarget(TypedDict):

    command: T.List[T.Union[str, build.BuildTarget, build.CustomTarget, ExternalProgram, File]]
    depends: T.List[T.Union[build.BuildTarget, build.CustomTarget]]
    env: EnvironmentVariables


class CustomTarget(TypedDict):

    build_always: bool
    build_always_stale: T.Optional[bool]
    build_by_default: T.Optional[bool]
    capture: bool
    command: T.List[T.Union[str, build.BuildTarget, build.CustomTarget,
                            build.CustomTargetIndex, ExternalProgram, File]]
    console: bool
    depend_files: T.List[FileOrString]
    depends: T.List[T.Union[build.BuildTarget, build.CustomTarget]]
    depfile: T.Optional[str]
    env: EnvironmentVariables
    feed: bool
    input: T.List[T.Union[str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex,
                          build.ExtractedObjects, build.GeneratedList, ExternalProgram, File]]
    install: bool
    install_dir: T.List[T.Union[str, T.Literal[False]]]
    install_mode: FileMode
    install_tag: T.List[T.Optional[str]]
    output: T.List[str]

class AddTestSetup(TypedDict):

    exe_wrapper: T.List[T.Union[str, ExternalProgram]]
    gdb: bool
    timeout_multiplier: int
    is_default: bool
    exclude_suites: T.List[str]
    env: EnvironmentVariables


class Project(TypedDict):

    version: T.Optional[FileOrString]
    meson_version: T.Optional[str]
    default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]
    license: T.List[str]
    subproject_dir: str


class _FoundProto(Protocol):

    """Protocol for subdir arguments.

    This allows us to define any object that has a found(self) -> bool method
    """

    def found(self) -> bool: ...


class Subdir(TypedDict):

    if_found: T.List[_FoundProto]


class Summary(TypedDict):

    section: str
    bool_yn: bool
    list_sep: T.Optional[str]


class FindProgram(ExtractRequired, ExtractSearchDirs):

    default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]
    native: MachineChoice
    version: T.List[str]


class RunCommand(TypedDict):

    check: bool
    capture: T.Optional[bool]
    env: EnvironmentVariables


class FeatureOptionRequire(TypedDict):

    error_message: T.Optional[str]


class DependencyPkgConfigVar(TypedDict):

    default: T.Optional[str]
    define_variable: PkgConfigDefineType


class DependencyGetVariable(TypedDict):

    cmake: T.Optional[str]
    pkgconfig: T.Optional[str]
    configtool: T.Optional[str]
    internal: T.Optional[str]
    default_value: T.Optional[str]
    pkgconfig_define: PkgConfigDefineType


class ConfigurationDataSet(TypedDict):

    description: T.Optional[str]

class VcsTag(TypedDict):

    command: T.List[T.Union[str, build.BuildTarget, build.CustomTarget,
                            build.CustomTargetIndex, ExternalProgram, File]]
    fallback: T.Optional[str]
    input: T.List[T.Union[str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex,
                          build.ExtractedObjects, build.GeneratedList, ExternalProgram, File]]
    output: T.List[str]
    replace_string: str


class ConfigureFile(TypedDict):

    output: str
    capture: bool
    format: T.Literal['meson', 'cmake', 'cmake@']
    output_format: T.Literal['c', 'json', 'nasm']
    depfile: T.Optional[str]
    install: T.Optional[bool]
    install_dir: T.Union[str, T.Literal[False]]
    install_mode: FileMode
    install_tag: T.Optional[str]
    encoding: str
    command: T.Optional[T.List[T.Union[build.Executable, ExternalProgram, Compiler, File, str]]]
    input: T.List[FileOrString]
    configuration: T.Optional[T.Union[T.Dict[str, T.Union[str, int, bool]], build.ConfigurationData]]
    macro_name: T.Optional[str]


class Subproject(ExtractRequired):

    default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]
    version: T.List[str]
    native: MachineChoice


class DoSubproject(ExtractRequired):

    default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]
    version: T.List[str]
    cmake_options: T.List[str]
    options: T.Optional[CMakeSubprojectOptions]
    for_machine: MachineChoice


class _BaseBuildTarget(TypedDict):

    """Arguments used by all BuildTarget like functions.

    This really exists because Jar is so different than all of the other
    BuildTarget functions.
    """

    build_by_default: bool
    build_rpath: str
    extra_files: T.List[FileOrString]
    gnu_symbol_visibility: str
    install: bool
    install_mode: FileMode
    install_rpath: str
    implicit_include_directories: bool
    link_depends: T.List[T.Union[str, File, build.CustomTarget, build.CustomTargetIndex, build.BuildTarget]]
    link_language: T.Optional[str]
    name_prefix: T.Optional[str]
    name_suffix: T.Optional[str]
    native: MachineChoice
    objects: T.List[build.ObjectTypes]
    override_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]
    depend_files: NotRequired[T.List[File]]
    resources: T.List[str]


class _BuildTarget(_BaseBuildTarget):

    """Arguments shared by non-JAR functions"""

    d_debug: T.List[T.Union[str, int]]
    d_import_dirs: T.List[T.Union[str, build.IncludeDirs]]
    d_module_versions: T.List[T.Union[str, int]]
    d_unittest: bool
    rust_dependency_map: T.Dict[str, str]
    sources: SourcesVarargsType
    c_args: T.List[str]
    cpp_args: T.List[str]
    cuda_args: T.List[str]
    fortran_args: T.List[str]
    d_args: T.List[str]
    objc_args: T.List[str]
    objcpp_args: T.List[str]
    rust_args: T.List[str]
    vala_args: T.List[T.Union[str, File]]  # Yes, Vala is really special
    cs_args: T.List[str]
    swift_args: T.List[str]
    cython_args: T.List[str]
    nasm_args: T.List[str]
    masm_args: T.List[str]


class _LibraryMixin(TypedDict):

    rust_abi: T.Optional[Literal['c', 'rust']]


class Executable(_BuildTarget):

    export_dynamic: T.Optional[bool]
    gui_app: T.Optional[bool]
    implib: T.Optional[T.Union[str, bool]]
    pie: T.Optional[bool]
    vs_module_defs: T.Optional[T.Union[str, File, build.CustomTarget, build.CustomTargetIndex]]
    win_subsystem: T.Optional[str]


class _StaticLibMixin(TypedDict):

    prelink: bool
    pic: T.Optional[bool]


class StaticLibrary(_BuildTarget, _StaticLibMixin, _LibraryMixin):
    pass


class _SharedLibMixin(TypedDict):

    darwin_versions: T.Optional[T.Tuple[str, str]]
    soversion: T.Optional[str]
    version: T.Optional[str]
    vs_module_defs: T.Optional[T.Union[str, File, build.CustomTarget, build.CustomTargetIndex]]


class SharedLibrary(_BuildTarget, _SharedLibMixin, _LibraryMixin):
    pass


class SharedModule(_BuildTarget, _LibraryMixin):

    vs_module_defs: T.Optional[T.Union[str, File, build.CustomTarget, build.CustomTargetIndex]]


class Library(_BuildTarget, _SharedLibMixin, _StaticLibMixin, _LibraryMixin):

    """For library, both_library, and as a base for build_target"""

    c_static_args: NotRequired[T.List[str]]
    c_shared_args: NotRequired[T.List[str]]
    cpp_static_args: NotRequired[T.List[str]]
    cpp_shared_args: NotRequired[T.List[str]]
    cuda_static_args: NotRequired[T.List[str]]
    cuda_shared_args: NotRequired[T.List[str]]
    fortran_static_args: NotRequired[T.List[str]]
    fortran_shared_args: NotRequired[T.List[str]]
    d_static_args: NotRequired[T.List[str]]
    d_shared_args: NotRequired[T.List[str]]
    objc_static_args: NotRequired[T.List[str]]
    objc_shared_args: NotRequired[T.List[str]]
    objcpp_static_args: NotRequired[T.List[str]]
    objcpp_shared_args: NotRequired[T.List[str]]
    rust_static_args: NotRequired[T.List[str]]
    rust_shared_args: NotRequired[T.List[str]]
    vala_static_args: NotRequired[T.List[T.Union[str, File]]]  # Yes, Vala is really special
    vala_shared_args: NotRequired[T.List[T.Union[str, File]]]  # Yes, Vala is really special
    cs_static_args: NotRequired[T.List[str]]
    cs_shared_args: NotRequired[T.List[str]]
    swift_static_args: NotRequired[T.List[str]]
    swift_shared_args: NotRequired[T.List[str]]
    cython_static_args: NotRequired[T.List[str]]
    cython_shared_args: NotRequired[T.List[str]]
    nasm_static_args: NotRequired[T.List[str]]
    nasm_shared_args: NotRequired[T.List[str]]
    masm_static_args: NotRequired[T.List[str]]
    masm_shared_args: NotRequired[T.List[str]]


class BuildTarget(Library):

    target_type: Literal['executable', 'shared_library', 'static_library',
                         'shared_module', 'both_libraries', 'library', 'jar']


class Jar(_BaseBuildTarget):

    main_class: str
    java_resources: T.Optional[build.StructuredSources]
    sources: T.Union[str, File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList, build.ExtractedObjects, build.BuildTarget]
    java_args: T.List[str]


class FuncDeclareDependency(TypedDict):

    compile_args: T.List[str]
    d_import_dirs: T.List[T.Union[build.IncludeDirs, str]]
    d_module_versions: T.List[T.Union[str, int]]
    dependencies: T.List[Dependency]
    extra_files: T.List[FileOrString]
    include_directories: T.List[T.Union[build.IncludeDirs, str]]
    link_args: T.List[str]
    link_whole: T.List[T.Union[build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex]]
    link_with: T.List[build.LibTypes]
    objects: T.List[build.ExtractedObjects]
    sources: T.List[T.Union[FileOrString, build.GeneratedTypes]]
    variables: T.Dict[str, str]
    version: T.Optional[str]
```