Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Initial Understanding of the Goal:**

The request asks for a functional breakdown of the Python code, explicitly highlighting connections to reverse engineering, low-level details (kernel, OS), logical reasoning, common user errors, and debugging.

**2. High-Level Overview of the Code:**

The first thing that jumps out is the presence of `TypedDict` and `Protocol` from the `typing` and `typing_extensions` modules. This strongly suggests the code is defining type hints for keyword arguments used in a larger system. The file path also gives a crucial context: `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/kwargs.py`. This tells us these type hints are likely used within the Meson build system, specifically for the Frida-CLR subproject.

**3. Deconstructing the Code - Category by Category:**

I'll go through the code section by section, trying to categorize the purpose of each `TypedDict`:

* **Project & Build Setup:**  `FuncAddProjectArgs`, `BaseTest`, `FuncBenchmark`, `FuncTest`, `ExtractRequired`, `ExtractSearchDirs`, `FuncGenerator`, `GeneratorProcess`, `FuncInstallSubdir`, `FuncInstallData`, `FuncInstallHeaders`, `FuncInstallMan`, `FuncImportModule`, `FuncIncludeDirectories`, `FuncAddLanguages`, `RunTarget`, `CustomTarget`, `AddTestSetup`, `Project`, `Subdir`, `Summary`, `FindProgram`, `RunCommand`, `FeatureOptionRequire`, `DependencyPkgConfigVar`, `DependencyGetVariable`, `ConfigurationDataSet`, `VcsTag`, `ConfigureFile`, `Subproject`, `DoSubproject`. These types deal with project configuration, building, testing, installation, and dependency management.

* **Target Definitions:** `_BaseBuildTarget`, `_BuildTarget`, `_LibraryMixin`, `Executable`, `_StaticLibMixin`, `StaticLibrary`, `_SharedLibMixin`, `SharedLibrary`, `SharedModule`, `Library`, `BuildTarget`, `Jar`. These clearly define the properties of different types of build targets (executables, libraries).

* **Dependency Management:** `DependencyMethodPartialDependency`, `FuncDeclareDependency`. These deal specifically with how dependencies are declared and used.

* **Internal Logic/Helper Types:** `_FoundProto`. This seems to be a utility type used within the context of `Subdir`.

**4. Connecting to the Request's Specific Points:**

Now, I'll iterate through the request's specific requirements:

* **Functionality:**  List the purpose of each `TypedDict`. This involves summarizing what each type seems to represent in the build process (e.g., `FuncTest` defines the arguments for a test).

* **Reverse Engineering:**  Think about how these types relate to inspecting and manipulating software. Frida is a dynamic instrumentation toolkit, so the build process likely involves setting up the environment and targets for instrumentation. Examples:
    * `CustomTarget`: Building a tool that extracts information from a binary.
    * `SharedLibrary`:  Instrumenting a shared library to observe its behavior.

* **Binary/Low-Level/OS/Kernel:** Frida interacts deeply with the target process. How do these build settings relate?
    * `install_dir`: Where Frida components or instrumented libraries are placed.
    * `c_args`, `link_args`:  Compiler and linker flags that affect the generated binary code.
    * `EnvironmentVariables`: Setting up the runtime environment for the instrumented process.
    * `SharedLibrary`:  The core mechanism for code injection and instrumentation on many platforms.

* **Logical Reasoning (Assumptions and Outputs):** For some types, I can make assumptions about inputs and outputs. For example, `FuncAddProjectArgs` takes `language` as input, which would influence the build system's choice of compilers and build steps. `CustomTarget` takes `command` and `output`, suggesting the execution of a command that produces an output file.

* **User Errors:**  Consider how users might misuse these build settings.
    * Incorrect paths in `install_dir`.
    * Missing dependencies in `depends`.
    * Mismatched types in `sources`.
    * Incorrect command syntax in `CustomTarget`.

* **User Operation and Debugging:**  How does a user's action lead to this code being used?  The user likely interacts with the Meson build system by writing a `meson.build` file. This file uses functions that accept keyword arguments corresponding to these `TypedDict` definitions. If there's a type mismatch, Meson will likely throw an error, potentially referencing these type definitions internally during its validation.

**5. Structuring the Explanation:**

Organize the findings into clear sections for each of the request's points. Use bullet points and examples to make the explanation easier to understand.

**6. Refining and Reviewing:**

Read through the explanation to ensure it's accurate, comprehensive, and addresses all aspects of the request. Check for clarity and conciseness. For instance, initially, I might just list the functionality. But then I would refine it by adding specific examples related to Frida and reverse engineering.

This iterative process of understanding the code, categorizing its elements, connecting them to the specific requirements, and structuring the explanation is key to producing a helpful and informative response. The context provided by the file path was extremely valuable in making the connections to Frida and reverse engineering.
This Python file, `kwargs.py`, within the Frida project, defines type annotations for keyword arguments used in various Meson build system functions. Essentially, it acts as a schema or blueprint for the expected inputs of these functions, ensuring type safety and making the codebase more understandable.

Let's break down its functionality based on your request:

**1. Functionality Listing:**

This file primarily serves as a repository for `TypedDict` and `Protocol` definitions. Each `TypedDict` represents the structure of keyword arguments expected by a specific Meson build function or a group of related functions. Here's a breakdown of the functionalities implied by these definitions:

* **Project Configuration (`FuncAddProjectArgs`, `Project`):** Defines arguments for configuring the overall project, including language support, versioning, default options, and licensing.
* **Testing and Benchmarking (`BaseTest`, `FuncBenchmark`, `FuncTest`, `AddTestSetup`):** Specifies arguments for defining and running tests and benchmarks, including dependencies, timeouts, environment variables, and execution protocols.
* **Dependency Management (`ExtractRequired`, `ExtractSearchDirs`, `DependencyMethodPartialDependency`, `FuncDeclareDependency`, `DependencyPkgConfigVar`, `DependencyGetVariable`):** Defines arguments related to finding and declaring dependencies on other libraries or components, including search paths, required status, and methods for extracting dependency information.
* **Code Generation and Processing (`FuncGenerator`, `GeneratorProcess`, `ConfigureFile`, `VcsTag`):**  Specifies arguments for generating source code or other files during the build process, including input and output files, dependencies, and custom commands.
* **Installation (`FuncInstallSubdir`, `FuncInstallData`, `FuncInstallHeaders`, `FuncInstallMan`):** Defines arguments for installing built artifacts to specific directories, including file modes, exclusion rules, and locale settings for man pages.
* **Module Importing (`FuncImportModule`):** Defines arguments for importing external Meson modules.
* **Include Directories (`FuncIncludeDirectories`):** Specifies arguments for adding include directories for the compiler.
* **Language Handling (`FuncAddLanguages`):** Defines arguments for specifying the programming languages used in the project.
* **Running External Commands (`RunTarget`, `RunCommand`):** Defines arguments for executing external commands during the build process, including dependencies, environment variables, and capture settings.
* **Custom Build Steps (`CustomTarget`):** Defines arguments for creating custom build steps with specific commands, inputs, outputs, dependencies, and installation settings.
* **Subproject Management (`Subproject`, `DoSubproject`):** Defines arguments for including and managing subprojects within the main build.
* **Build Target Definitions (`_BaseBuildTarget`, `_BuildTarget`, `_LibraryMixin`, `Executable`, `_StaticLibMixin`, `StaticLibrary`, `_SharedLibMixin`, `SharedLibrary`, `SharedModule`, `Library`, `BuildTarget`, `Jar`):** Defines the common and specific arguments for building different types of targets like executables, static libraries, shared libraries, and JAR files, including source files, compiler flags, linking options, installation paths, and platform-specific settings.
* **Utility and Information (`Subdir`, `Summary`, `FindProgram`, `ConfigurationDataSet`, `FeatureOptionRequire`):** Defines arguments for conditional logic based on found dependencies, summarizing build information, finding external programs, and configuring data sets.

**2. Relationship with Reverse Engineering:**

While this file itself doesn't perform reverse engineering, the build configurations it defines are crucial for setting up the environment for reverse engineering tasks using Frida. Here's how:

* **Building Frida Itself:** This file is part of Frida's build system. Successfully building Frida is the first step to using it for reverse engineering. The various build targets and their configurations ensure Frida is built correctly for the target platform (Linux, Android, etc.).
* **Building Instrumentation Scripts/Gadgets:**  Reverse engineers often write custom scripts or "gadgets" (small pieces of code injected into a process) to perform instrumentation. The build system, guided by configurations potentially influenced by types defined here, would be used to compile and package these scripts or gadgets.
* **Targeting Specific Architectures and Platforms:** The `native: MachineChoice` argument seen in many `TypedDict` definitions is directly related to cross-compilation, which is essential when reverse engineering software on different architectures (e.g., analyzing an ARM Android app from an x86 Linux machine).
* **Controlling Compiler and Linker Options:** The `*_args` families (e.g., `c_args`, `link_args`) allow for fine-grained control over the compilation and linking process. This is relevant in reverse engineering when you need to build tools or libraries with specific flags to interact with the target process effectively. For example, you might need to disable certain security features or enable debugging symbols.
* **Building Shared Libraries for Injection:**  Frida heavily relies on injecting shared libraries into target processes. The `SharedLibrary` and related `TypedDict` definitions manage how these libraries are built.

**Example:**

Imagine you're reverse engineering an Android application. You might use Frida to inject a custom shared library that hooks into specific functions. The `SharedLibrary` `TypedDict` would define the keyword arguments for the `shared_library()` Meson function used in Frida's or your custom gadget's `meson.build` file. This includes:

* `sources`: The C/C++ source files of your instrumentation library.
* `c_args`: Compiler flags needed for Android (e.g., defining the Android NDK path).
* `link_args`: Linker flags to link against Android-specific libraries.
* `install_dir`:  Potentially where this library should be placed on the development machine or a target device for testing.

**3. Binary 底层, Linux, Android 内核及框架知识:**

These type definitions indirectly touch upon binary, low-level, Linux, and Android kernel/framework knowledge:

* **Binary Structure:** The build process ultimately generates binary files (executables, libraries). The `TypedDict` definitions for build targets like `Executable`, `SharedLibrary`, and `StaticLibrary` implicitly deal with the structure of these binaries (e.g., linking, symbol visibility).
* **Compiler and Linker Flags:**  The `*_args` fields directly correspond to compiler and linker flags. Understanding these flags requires knowledge of how compilers like GCC or Clang work at a low level and how they generate machine code.
* **Shared Libraries and Dynamic Linking:**  The `SharedLibrary` `TypedDict` and related concepts like `soversion` and `darwin_versions` are fundamental to understanding how shared libraries work on Linux and macOS, including dynamic linking and versioning.
* **Android NDK (Native Development Kit):** When building Frida components or instrumentation for Android, compiler and linker flags specific to the Android NDK are used. These are configured through the `*_args` fields.
* **Kernel Interaction (Indirect):** Frida itself interacts heavily with the operating system kernel (Linux, Android). While this file doesn't directly define kernel interactions, the build process it describes ensures that Frida and its components are built in a way that allows for these interactions (e.g., by linking against necessary system libraries).
* **File Modes and Permissions:** `FileMode` is used in `FuncInstall*` `TypedDict`s, reflecting the underlying operating system's file permission system.

**4. Logical Reasoning (Hypothetical Input & Output):**

Consider the `FuncTest` `TypedDict`:

* **Hypothetical Input:**
    ```python
    test(
        'my_cool_test',
        'test_my_code.py',
        args=['--verbose'],
        timeout=60,
        is_parallel=True
    )
    ```
* **Logical Reasoning:** The `FuncTest` `TypedDict` defines the expected keyword arguments for the `test()` function in Meson. The input above matches the structure:
    * `'my_cool_test'` would likely be the test name.
    * `'test_my_code.py'` is the script to execute for the test.
    * `args=['--verbose']` provides command-line arguments to the test script.
    * `timeout=60` sets a timeout of 60 seconds for the test.
    * `is_parallel=True` indicates the test can run in parallel with other tests.
* **Hypothetical Output (within Meson's processing):** Meson's interpreter, using the `FuncTest` definition, would validate that these arguments are of the correct types (strings, list of strings, integer, boolean). It would then use this information to generate the necessary build system commands to execute the test.

**5. Common User/Programming Errors:**

* **Incorrect Type for Arguments:**  Providing a string when a list is expected, or an integer when a boolean is needed. For example, in `FuncTest`, if a user provides `timeout='sixty'` (a string) instead of `timeout=60` (an integer), Meson would likely raise a type error, possibly referencing these `TypedDict` definitions internally.
* **Missing Required Arguments:** If a `TypedDict` doesn't use `NotRequired`, the argument is mandatory. For instance, the `command` argument in `CustomTarget` is required. Forgetting to provide it would lead to a build error.
* **Incorrect Path Types:**  Providing a string for a `File` object or vice-versa could cause issues. Meson often handles string paths and `File` objects differently.
* **Mismatched Argument Names:**  Typos in keyword argument names would lead to Meson not recognizing the argument and potentially raising an error or using default values unexpectedly.
* **Incorrect List Element Types:** If a `TypedDict` specifies `T.List[str]`, providing a list containing non-string elements would be an error.

**Example:**

```python
# Incorrect usage based on FuncInstallData
install_data(
    'my_config',  # Should be a list of sources
    install_dir='/etc/myprogram'
)
```

This would likely cause an error because `sources` in `FuncInstallData` is defined as `T.List[FileOrString]`, expecting a list of file paths or `File` objects, not a single string.

**6. User Operations and Debugging Clues:**

A user's actions leading to this code being relevant often involve writing or modifying `meson.build` files. Here's a likely sequence:

1. **User Writes `meson.build`:** A developer working on a Frida component or a custom instrumentation tool starts by creating or editing a `meson.build` file.
2. **Using Meson Functions:**  Within the `meson.build` file, the user calls various Meson functions like `executable()`, `shared_library()`, `test()`, `custom_target()`, etc., providing keyword arguments to configure these functions.
3. **Meson Interpretation:** When the user runs the `meson` command to configure the build, the Meson interpreter parses the `meson.build` file.
4. **Keyword Argument Validation:**  The interpreter uses the type information defined in files like `kwargs.py` to validate the keyword arguments provided by the user. It checks if the argument names are correct and if the values are of the expected types.
5. **Error Reporting (If Any):** If there's a mismatch between the provided arguments and the definitions in `kwargs.py`, Meson will raise an error. The error message might not directly reference `kwargs.py`, but it will indicate the problematic function call and the type of error (e.g., "expected a list, got a string").
6. **Debugging:** When debugging build issues, developers might:
    * **Carefully review the `meson.build` file:** Check for typos in argument names and ensure the types of values passed to functions match the expected types.
    * **Consult Meson documentation:** The documentation for each Meson function will implicitly describe the expected keyword arguments, which are defined in files like this.
    * **Examine Meson's error messages:**  Error messages often point to the specific function call and argument causing the problem.
    * **Potentially inspect Meson's internal code (advanced):** In rare cases, developers might delve into Meson's source code to understand how it's processing the arguments and where the validation is happening.

In essence, `kwargs.py` plays a crucial role in ensuring the correctness and consistency of the Meson build system's configuration, which is essential for building Frida and related tools used in dynamic instrumentation and reverse engineering. It acts as a contract between the user's build definitions and Meson's internal logic.

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```