Response:
Let's break down the thought process for analyzing this Python code and answering the request.

**1. Understanding the Core Request:**

The primary goal is to understand the *functionality* of the `kwargs.py` file within the Frida project. The request also asks to connect this functionality to various technical domains (reverse engineering, low-level, kernel, etc.) and to provide examples, usage errors, and debugging context.

**2. Initial Code Scan and Purpose Identification:**

My first step was to quickly scan the code to get a general idea of what it does. The filename (`kwargs.py`) and the docstring ("Keyword Argument type annotations") immediately suggest this file defines data structures related to function arguments. The `TypedDict` imports confirm this. The presence of imports from `..build`, `..coredata`, `..compilers`, etc., indicates this file is part of a larger build system (likely Meson, as hinted by the copyright).

**3. Dissecting `TypedDict` Definitions:**

The core of the analysis lies in examining each `TypedDict` definition. For each one, I asked:

* **What function or concept does this represent?** The name of the `TypedDict` (e.g., `FuncAddProjectArgs`, `FuncTest`, `CustomTarget`) usually gives a strong clue.
* **What are the key arguments/fields?** I looked at the keys within the `TypedDict` and their associated types.
* **What is the purpose of each argument?** Sometimes the name is self-explanatory (e.g., `timeout`, `install_dir`). Other times, I needed to infer from the context (e.g., `native: MachineChoice` likely relates to cross-compilation).
* **Are there any relationships between `TypedDict`s?** Inheritance (like `FuncTest(FuncBenchmark)`) shows shared arguments.

**4. Connecting to Technical Domains:**

This is where I drew connections between the defined argument structures and the technical areas mentioned in the request.

* **Reverse Engineering:** I looked for arguments that directly influence the build process and might be manipulated during reverse engineering. Arguments related to library linking (`link_with`, `link_args`), compiler flags (`c_args`, `cpp_args`), and output file naming (`name_prefix`, `name_suffix`) are relevant here. The ability to define custom targets (`CustomTarget`) is also important for orchestrating complex build steps.
* **Binary/Low-Level:**  Arguments dealing with object files (`objects`), linking (`link_args`), architecture (`native`), and specific compiler options for different languages (like `nasm_args` for assembly) point to lower-level concerns.
* **Linux/Android Kernel & Framework:**  While not explicitly targeting kernel development, the arguments related to shared libraries (`SharedLibrary`), modules (`SharedModule`), and the use of tools like `pkg-config` suggest interactions with system libraries and potentially framework components. The `install_dir` argument is relevant for deploying built artifacts.
* **Logic and Reasoning:**  The `ExtractRequired` and `ExtractSearchDirs` `TypedDict`s, used as base classes, demonstrate a pattern for handling "required" and "search paths" arguments consistently. This is a form of logical organization.

**5. Generating Examples and Scenarios:**

For each connection to a technical domain, I tried to create concrete examples. The goal was to illustrate *how* these arguments are used and their potential impact. For instance, showing how `link_args` could be used to link against a specific library or how `c_args` could add optimization flags. For logic, I focused on the reusability of the `ExtractRequired` pattern.

**6. Identifying User Errors:**

I considered common mistakes a developer might make when using a build system. This involved thinking about:

* **Incorrect types:**  Providing a string when a list is expected.
* **Missing required arguments:** Forgetting a mandatory argument.
* **Conflicting arguments:**  Setting arguments that contradict each other.
* **Incorrect paths:** Providing wrong file or directory paths.

**7. Tracing User Actions (Debugging Context):**

This part required imagining the steps a user would take that would eventually lead to the code defined in this file being used. The key is understanding that this file defines the *structure* of arguments passed to Meson build functions. Therefore, the user's interaction involves writing `meson.build` files that *call* these functions with specific keyword arguments.

**8. Structuring the Output:**

Finally, I organized the information into the requested categories: Functionality, Relationship to Reverse Engineering, etc. I used clear headings, bullet points, and code examples to make the explanation easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial focus was too granular:** At first, I tried to explain every single argument in detail. I realized this was too much information and shifted to focusing on the *purpose* and *relevance* of groups of arguments.
* **Need for concrete examples:**  Simply stating that "it relates to reverse engineering" isn't enough. I needed to illustrate *how* with specific examples.
* **Clarifying the "user journey":** I had to think carefully about the abstraction levels. The user doesn't directly interact with `kwargs.py`. They interact with Meson functions, which *use* the definitions in this file.

By following these steps, I was able to produce a comprehensive answer that addressed all aspects of the request, connecting the technical details of the code to broader concepts and practical usage scenarios.
This Python file, `kwargs.py`, located within the Frida project's build system configuration, primarily serves as a **centralized definition of keyword arguments (kwargs) with their corresponding type annotations** for various Meson build functions.

Think of it as a type hinting blueprint for the parameters that can be passed to different Meson functions used to define how Frida is built. This enhances code readability, maintainability, and allows Meson (the build system) to perform type checking, potentially catching errors early in the build process.

Here's a breakdown of its functionalities and connections to various technical domains:

**1. Defining Keyword Argument Signatures:**

* **Functionality:** The core purpose is to define the valid keyword arguments for different Meson build functions like `add_project_arguments`, `test`, `benchmark`, `custom_target`, `executable`, `shared_library`, etc. It uses Python's `typing` module and `typing_extensions.TypedDict` to create structured type hints for these keyword arguments.
* **Example:** The `FuncTest` TypedDict defines the allowed keyword arguments for the `test()` Meson function, such as `args`, `should_fail`, `timeout`, `is_parallel`, etc., along with their expected types (list of strings/files/targets, boolean, integer).

**2. Enforcing Type Safety:**

* **Functionality:** By providing explicit type annotations, Meson can validate the arguments passed to these functions in the `meson.build` files. This helps prevent common programming errors where arguments of the wrong type are used.
* **Example:** If a user mistakenly passes an integer to the `args` keyword of the `test()` function (which expects a list), Meson, leveraging these type hints, can issue an error during the configuration stage, preventing a potentially harder-to-debug runtime issue later.

**3. Documentation and Introspection:**

* **Functionality:** These type definitions serve as documentation for the available keyword arguments and their expected types for Meson function users (Frida developers writing `meson.build` files). Tools and IDEs can use this information for auto-completion and help messages.

**Relationship to Reverse Engineering:**

While this file itself doesn't directly perform reverse engineering, it plays a crucial role in *building* Frida, which is a powerful dynamic instrumentation toolkit used extensively in reverse engineering.

* **Example:**  The `Executable`, `SharedLibrary`, and `StaticLibrary` TypedDicts define arguments like `c_args`, `cpp_args`, `link_args`, and `link_with`. These arguments directly influence how the Frida binaries (executables and libraries) are compiled and linked. A reverse engineer might need to understand which libraries Frida depends on (specified via `link_with`) or what compiler flags were used (`c_args`) to better analyze its behavior. Knowing these build-time configurations can provide valuable insights into Frida's internal workings.
* **Example:** The `CustomTarget` TypedDict allows defining arbitrary build steps with specific commands. A reverse engineer examining Frida's build system might find custom targets that perform actions like code generation or obfuscation, which are relevant to understanding the final binary.

**Relationship to Binary Underlying, Linux, Android Kernel & Framework:**

This file indirectly relates to these areas by defining how Frida's components are built for these platforms.

* **Binary Underlying:**  Arguments like `objects` in the `_BuildTarget` TypedDict deal with compiled object files, which are the direct output of the compilation process and the building blocks of the final binaries. Options like `pie` (Position Independent Executable) in the `Executable` TypedDict directly affect the binary's structure and how it's loaded into memory.
* **Linux:** Many build options are Linux-specific or common in Linux development. For example, the `gnu_symbol_visibility` argument in `_BaseBuildTarget` is relevant for controlling symbol visibility in shared libraries on Linux.
* **Android Kernel & Framework:**  While not explicitly Android-specific in this particular file, the broader Frida project utilizes Meson to build Frida for Android. The flexibility of Meson and the types defined here allow for specifying compiler flags, linker options, and dependencies that are specific to the Android environment. For example, Frida's Android agent might be built as a shared library (`SharedModule` or `SharedLibrary`) with specific linking requirements for interacting with the Android framework.
* **Example:**  The `install_dir` argument, present in various TypedDicts related to installation, dictates where the built Frida components (executables, libraries, headers) are placed on the target system (which could be a Linux or Android system).

**Logical Reasoning with Assumptions:**

Let's consider the `ExtractRequired` TypedDict:

```python
class ExtractRequired(TypedDict):
    """Keyword Arguments consumed by the `extract_required_kwargs` function.

    Any function that uses the `required` keyword argument which accepts either
    a boolean or a feature option should inherit it's arguments from this class.
    """

    required: T.Union[bool, coredata.UserFeatureOption]
```

* **Assumption:** There exists a function named `extract_required_kwargs` within the Frida build system.
* **Input:** A Meson function call uses the keyword argument `required` with either a boolean value (e.g., `required=True`) or a `coredata.UserFeatureOption` object (representing a configurable feature).
* **Output:** The `extract_required_kwargs` function (presumably) processes this `required` argument. If `required=True`, the functionality associated with that function is enabled. If it's a `UserFeatureOption`, the function likely checks the current setting of that feature (enabled or disabled) to determine its behavior.

**User or Programming Common Usage Errors:**

* **Incorrect Type:** A user might provide a string instead of a boolean for the `required` argument if they don't refer to the documentation or if their IDE doesn't provide proper type hinting.
    * **Example:** In a `meson.build` file, writing `subproject('mylib', required='yes')` instead of `subproject('mylib', required=True)`. Meson would likely raise an error during configuration due to the type mismatch.
* **Missing Required Argument:** If a `TypedDict` doesn't mark an argument as `NotRequired`, it's implicitly mandatory. Forgetting to provide such an argument will lead to an error.
    * **Example:** The `Jar` TypedDict requires `main_class`. If a user calls the `jar()` Meson function without specifying `main_class`, Meson will report a missing required keyword argument.
* **Misspelling Keyword Arguments:** Typos in keyword argument names will cause Meson to not recognize them.
    * **Example:**  Writing `test(name: 'mytest', arg=['val'])` instead of `test(name='mytest', args=['val'])`. Meson will likely either ignore the misspelled argument or raise an error if it encounters an unexpected keyword.

**User Operations Leading to This Code (Debugging Clues):**

1. **Writing `meson.build` files:** Frida developers create `meson.build` files to define the build process. These files contain calls to Meson functions (like `executable()`, `shared_library()`, `test()`, etc.) with keyword arguments.
2. **Running `meson setup`:** When a user runs `meson setup <build_directory>`, Meson parses the `meson.build` files.
3. **Meson Interpreter:** The Meson interpreter reads the `meson.build` files and, during this process, it uses the definitions in `kwargs.py` to understand the valid keyword arguments and their expected types for the functions being called.
4. **Type Checking:** Meson performs type checking based on the annotations in `kwargs.py`. If any type mismatches or missing required arguments are detected, Meson will report errors during the `meson setup` phase.

Therefore, this `kwargs.py` file is crucial for the initial configuration and validation stage of the Frida build process. It acts as a schema that defines the structure and types of the arguments used in the build definition. When debugging build issues, especially those related to argument errors or type mismatches, examining the definitions in `kwargs.py` can provide valuable clues about the expected structure and types of the arguments for various Meson functions used in Frida's `meson.build` files.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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