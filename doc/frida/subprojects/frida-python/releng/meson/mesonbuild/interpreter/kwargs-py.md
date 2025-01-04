Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Goal:**

The request asks for a functional analysis of a Python file related to the Frida dynamic instrumentation tool. The key is to identify *what* the code does and connect it to Frida's purpose and the context of reverse engineering, low-level programming, etc.

**2. High-Level Code Review and Pattern Recognition:**

The first thing that jumps out is the heavy use of `TypedDict` and `Literal` from the `typing` and `typing_extensions` modules. This immediately suggests that the file is focused on defining the structure and allowed values for keyword arguments in a Meson build system context. The file path confirms this, as it's within the Meson interpreter.

**3. Identifying the Core Functionality:**

The core function is clearly the definition of various `TypedDict` classes. Each class represents the allowed keyword arguments for a specific function within the Meson build system. The names of the classes (e.g., `FuncAddProjectArgs`, `FuncTest`, `CustomTarget`) are very descriptive and give strong hints about the functions they relate to.

**4. Connecting to Reverse Engineering (Frida Context):**

Now, the task is to connect these generic build system concepts to the specific domain of Frida and reverse engineering. This requires some background knowledge of Frida and dynamic instrumentation.

* **Dynamic Instrumentation:** Frida injects code into running processes. This involves manipulating memory, function calls, and hooking. Keywords like `CustomTarget` (for running external commands), `EnvironmentVariables`, and the presence of arguments related to compilation (like `c_args`, `cpp_args`) become relevant.
* **Frida's Python Bindings:** The file path `frida/subprojects/frida-python` indicates this code relates to the Python bindings of Frida. This means it's involved in how users interact with Frida through Python.
* **Build Systems (Meson):** Frida needs to be built. Meson is the build system used. Understanding that this file defines the valid inputs to Meson functions is crucial.

**5. Categorizing and Providing Examples:**

Once the core functionality and its relevance to Frida are understood, the next step is to categorize the functionalities and provide concrete examples. This involves:

* **Reverse Engineering Relevance:** Look for keywords and concepts directly related to reverse engineering tasks. Examples include injecting code (`CustomTarget`), setting up the environment (`EnvironmentVariables`), and potentially interacting with specific system calls or libraries through compilation flags.
* **Binary/Kernel/Framework Relevance:** Identify arguments related to compilation (linking, including), target architecture (`MachineChoice`), and potentially Android-specific build processes if context suggests it.
* **Logical Inference:** Examine how the different keyword arguments might interact. For example, how `required` might influence the build process or how different `install_*` arguments control installation behavior. Formulate hypothetical scenarios with inputs and expected outputs.
* **User Errors:** Think about common mistakes users might make when using these build functions. This could involve providing incorrect types for arguments, missing required arguments, or misunderstanding the purpose of certain options.
* **Debugging Clues:**  Consider how a developer might end up looking at this file during debugging. This usually happens when there are errors in the build process, and understanding the expected inputs can help pinpoint the source of the problem.

**6. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original request:

* List the functionalities.
* Provide examples related to reverse engineering.
* Provide examples related to binary/kernel/framework aspects.
* Give examples of logical inference (input/output).
* Illustrate common user errors.
* Explain how a user might reach this file during debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Might focus too much on the specific data types themselves.
* **Correction:**  Shift focus to the *purpose* of these data types, which is defining valid keyword arguments for build functions.
* **Initial thought:**  Might miss the Frida context and treat this as a generic Meson file.
* **Correction:**  Actively try to connect the functionality to Frida's use cases and its role in dynamic instrumentation.
* **Initial thought:** Examples might be too abstract.
* **Correction:**  Make examples concrete and relatable to common reverse engineering or build system scenarios. Use specific keywords and function names where possible.

By following these steps, combining code analysis with domain knowledge, and focusing on the "why" behind the code, a comprehensive and accurate answer can be generated.
This Python file, `kwargs.py`, located within the Frida project's build system definition (Meson), primarily serves as a **centralized repository for type annotations of keyword arguments used in various Meson build functions**. It leverages Python's type hinting features and the `typing` and `typing_extensions` libraries to define the expected types and structures for these keyword arguments.

Here's a breakdown of its functionalities:

**1. Defining the Structure of Keyword Arguments:**

* **`TypedDict` for Structure:** The file heavily utilizes `TypedDict` to create dictionary-like structures that explicitly define the expected keys and their corresponding data types for keyword arguments. This enhances code readability, maintainability, and allows for static type checking.
* **Granular Definitions:**  It defines specific `TypedDict` classes for individual Meson functions or groups of related functions. For example, `FuncAddProjectArgs` defines the keywords for `add_project_arguments`, and `FuncTest` defines the keywords for the `test` function.
* **Optional and Required Arguments:** It uses `NotRequired` from `typing_extensions` to indicate optional keyword arguments within the `TypedDict` definitions. This clarifies which arguments are mandatory and which are not.
* **Literal Type Restrictions:** The `Literal` type is used to restrict the allowed values for certain string-based keyword arguments, providing better validation and preventing typos. For example, in `FuncBenchmark`, `protocol` can only be one of the specified literal values.
* **Union Types for Flexibility:** `T.Union` allows a keyword argument to accept values of different types, increasing flexibility where needed. For instance, the `args` in `BaseTest` can be a string, a `File` object, or a `build.Target`.

**2. Providing Type Hints for Meson Functions:**

* **Improved Code Understanding:**  By having these type annotations, developers working on the Meson interpreter can easily understand the expected input for different Meson functions. This reduces ambiguity and potential errors.
* **Static Type Checking:** Tools like MyPy can use these type hints to perform static analysis of the Meson interpreter code, catching type-related errors before runtime.
* **Documentation:** These type annotations serve as a form of documentation, clearly outlining the available keyword arguments and their types for each function.

**3. Facilitating Code Generation and Tooling:**

* **Potentially used by tooling:**  While not explicitly stated in the code, these type definitions could be used by code generation tools or IDEs to provide better autocompletion and suggestions when writing Meson build files.

**Relationship to Reverse Engineering (with Examples):**

This file itself doesn't directly perform reverse engineering. However, it plays a crucial role in defining how Frida is built and configured, which is a prerequisite for using Frida in reverse engineering. The keyword arguments defined here can influence how Frida interacts with the target system.

* **Example 1: `CustomTarget` and Code Injection:**  The `CustomTarget` TypedDict defines the structure for the `custom_target` Meson function. In a Frida build script, you might use `custom_target` to compile a small shared library that will be injected into a target process. The `command` keyword would specify the compiler command, and `input` and `output` would define the source files and the resulting shared library. This directly relates to the core functionality of Frida: injecting and executing code in a target process.

   ```python
   # Hypothetical usage in a meson.build file
   custom_target('my_injector',
       input: 'injector.c',
       output: 'injector.so',
       command: ['cc', '-shared', '-fPIC', '@INPUT@', '-o', '@OUTPUT@']
   )
   ```
   The `kwargs.py` file ensures that the `command` is a list of strings (or other allowed types), `input` is a list of files, and `output` is a list of strings.

* **Example 2: `EnvironmentVariables` and Target Process Configuration:** The `env` keyword appears in several `TypedDict` definitions like `FuncBenchmark`, `FuncTest`, `RunTarget`, and `CustomTarget`. This allows setting environment variables for the processes being launched or the build environment itself. In a reverse engineering context, you might need to set specific environment variables for the target application to behave in a particular way or to enable debugging features. `kwargs.py` ensures that `env` is an instance of `EnvironmentVariables`, enforcing type safety.

* **Example 3: `BuildTarget` and Frida's Agent:**  The various `BuildTarget` related `TypedDict` classes (like `Executable`, `SharedLibrary`) define the structure for building Frida's core components and agents. When building a Frida gadget (a shared library injected into an application), you'd use Meson functions like `shared_library`, and the keyword arguments defined in these `TypedDict` classes (e.g., `sources`, `c_args`, `link_with`) determine how the gadget is compiled and linked.

**Relationship to Binary底层, Linux, Android Kernel & Framework (with Examples):**

The definitions in `kwargs.py` indirectly touch upon these areas by controlling the compilation and linking processes that ultimately generate the Frida binaries that interact with these low-level aspects.

* **Example 1: Compiler Flags (`c_args`, `cpp_args`, etc.):** The `_BuildTarget` and its subclasses include keywords like `c_args`, `cpp_args`, etc., which allow passing compiler-specific flags. These flags are crucial for controlling how code is compiled for different architectures (including ARM for Android), defining preprocessor macros, and enabling specific compiler optimizations or debugging symbols. This directly impacts the generated binary code and its interaction with the underlying OS and hardware.

   ```python
   # Hypothetical usage in a meson.build file
   executable('my_frida_tool',
       'main.c',
       c_args: ['-Wall', '-DDEBUG_MODE']
   )
   ```
   `kwargs.py` ensures that `c_args` is a list of strings, preventing accidental passing of non-string values.

* **Example 2: Linking (`link_with`, `link_depends`):** Keywords like `link_with` and `link_depends` in `BuildTarget` and `FuncDeclareDependency` control the linking process, specifying which libraries the target binary should be linked against. When building Frida, these keywords are used to link against system libraries (like `libc` on Linux) or Android framework libraries.

* **Example 3: Target Architecture (`native`):**  The `native` keyword (of type `MachineChoice`) in several `TypedDict` definitions specifies the target architecture for the build. This is fundamental when building Frida for different platforms like Linux, Windows, macOS, or Android (ARM, x86).

**Logical Inference (with Examples):**

The type definitions themselves don't perform explicit logical inference. However, they enforce constraints that can lead to predictable outcomes during the build process.

* **Hypothetical Input:** A Meson build file attempts to pass an integer to the `timeout` keyword of the `test` function.
* **`kwargs.py` Definition:** The `FuncTest` `TypedDict` defines `timeout` as `int`.
* **Output:** The Meson interpreter, using these type definitions, will likely raise an error during the configuration phase, indicating a type mismatch. This prevents a potentially flawed build process.

* **Hypothetical Input:** A Meson build file uses the `install_dir` keyword in `FuncInstallData` but provides a list of strings instead of a single string.
* **`kwargs.py` Definition:**  `FuncInstallData` defines `install_dir` as `str`.
* **Output:** Meson will likely raise an error due to the type mismatch.

**User or Programming Common Usage Errors (with Examples):**

These type definitions help prevent common errors that users might make when writing `meson.build` files.

* **Example 1: Incorrect Type for Keyword Argument:** A user might accidentally pass a boolean value to the `is_parallel` keyword of the `test` function, where it expects a boolean. `kwargs.py` defines `is_parallel: bool` in `FuncTest`, so Meson will flag this as a type error.

* **Example 2: Missing Required Keyword Argument:** If a Meson function requires a specific keyword argument (not marked as `NotRequired`), and the user omits it, the type definitions won't directly catch this. However, the Meson interpreter's logic, guided by these definitions, will likely raise an error indicating the missing argument.

* **Example 3: Typo in Keyword Argument Name:** If a user makes a typo in a keyword argument name (e.g., `commmand` instead of `command` in `CustomTarget`), `kwargs.py` won't directly prevent this. However, the Meson interpreter will not recognize the misspelled keyword and may either ignore it or raise an error related to unexpected arguments.

**User Operation Steps to Reach This File (as a Debugging Clue):**

A user might encounter this file during debugging in the following scenarios:

1. **Investigating Meson Build Errors:** If the Meson build process fails with an error message related to incorrect keyword arguments or type mismatches, a developer might need to examine the `kwargs.py` file to understand the expected structure and types for the relevant Meson functions. The error message might point to a specific function, and looking up its corresponding `TypedDict` in `kwargs.py` can provide clarity.

2. **Developing Custom Meson Modules or Functionality:** Developers extending Meson or writing custom build logic might refer to `kwargs.py` to see how keyword arguments are typically defined and structured within the Frida project's Meson setup. This helps maintain consistency and best practices.

3. **Understanding Frida's Build System:** When trying to understand how Frida is built, developers might explore the Meson build files and the underlying interpreter code. `kwargs.py` provides valuable insights into the expected inputs for various build-related functions.

4. **Contributing to Frida Development:** Developers contributing to the Frida project might need to modify or add new Meson functions. In this case, they would likely need to define new `TypedDict` structures in `kwargs.py` to specify the keyword arguments for their new functions.

In essence, `kwargs.py` is a foundational file for the Frida project's build system, ensuring type safety and providing a clear definition of the interface for various Meson build functions. While it doesn't directly perform reverse engineering, its definitions are crucial for building the tools that enable reverse engineering activities.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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