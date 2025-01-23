Response:
Let's break down the thought process for analyzing this Python file.

**1. Understanding the Core Purpose:**

The filename `kwargs.py` and the introductory comment "Keyword Argument type annotations" immediately suggest that this file defines the expected keyword arguments for various functions within the Meson build system. The `typing` and `typing_extensions` imports confirm this.

**2. Identifying the Key Data Structure:**

The extensive use of `TypedDict` is the central element. Each `TypedDict` represents the allowed keyword arguments for a specific Meson function. This is the primary way Meson enforces type safety and clarifies the expected input for its various commands.

**3. Analyzing Individual `TypedDict` Definitions:**

For each `TypedDict`, I'll consider:

* **Name:** The name often hints at the Meson function it describes (e.g., `FuncTest` for the `test` function).
* **Inheritance:**  Does it inherit from other `TypedDict`s?  This reveals shared arguments and relationships between functions (e.g., `FuncTest` inheriting from `FuncBenchmark`).
* **Members:**  Each member represents a keyword argument. The type annotation (e.g., `T.List[str]`, `bool`, `T.Optional[str]`) is crucial for understanding what kind of data is expected.
* **Special Types:** Look for uses of `Literal`, `Union`, `Optional`, `NotRequired`, `Protocol`. These add nuances to the allowed values.
* **Comments:**  The docstrings provide valuable context about the purpose of the arguments.

**4. Connecting to Frida (The User's Context):**

The initial prompt mentions Frida. The path `frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/kwargs.py` is a strong indication that this file is *part of* Frida's build process, specifically when building the Node.js bindings for Frida. Therefore, the functions described by these keyword arguments are likely used when defining how Frida's Node.js components are built.

**5. Relating to Reverse Engineering:**

Now, consider how these build system concepts relate to reverse engineering:

* **Target Building (Executable, Libraries):**  Reverse engineers often work with executables and libraries. The definitions for `Executable`, `SharedLibrary`, `StaticLibrary` directly relate to how Frida itself is built (and potentially how it interacts with target processes). Knowing how Frida is compiled, linked, and packaged can be useful in understanding its behavior.
* **Custom Targets:** Frida might use custom targets for specialized build steps, potentially related to code generation, instrumentation setup, or packaging. Understanding these can give insights into Frida's internal workings.
* **Dependencies:** The `Dependency` related types show how Frida declares its dependencies on other libraries. Knowing these dependencies can be important for understanding Frida's capabilities and potential points of interaction.
* **Installation:** The `FuncInstall*` types describe how Frida's components are installed. This is relevant for setting up a Frida environment for reverse engineering tasks.
* **Testing and Benchmarking:** The `FuncTest` and `FuncBenchmark` types hint at Frida's testing infrastructure. Analyzing tests can reveal intended usage patterns and internal APIs.

**6. Thinking about the Binary Level, Kernel, and Frameworks:**

Frida heavily interacts with the underlying operating system and target processes. This makes several keyword arguments relevant:

* **Compiler Flags (`c_args`, `cpp_args`, etc.):** These flags directly influence the compiled binary code, impacting performance, security features (like PIE), and debugging information.
* **Linker Flags (`link_args`):** These control how different parts of the binary are linked together, which affects the runtime behavior and dependencies.
* **System Libraries (`link_with`):**  Linking against system libraries (like `libc`) is fundamental for low-level operations.
* **Installation Directories (`install_dir`):**  Knowing where Frida components are installed on Linux/Android is essential for using Frida in those environments.
* **Custom Targets for Native Code:** Frida often involves compiling native code that interacts directly with the target process. Custom targets likely manage these steps.

**7. Considering Logic and Examples:**

For logical reasoning, think about how Meson uses these definitions. If a function expects a `T.List[str]` for `sources`, providing a single string would be a type error. The `required` keyword exemplifies this – it enforces whether an argument *must* be provided.

**8. Identifying User Errors and Debugging:**

User errors often arise from:

* **Incorrect data types:** Providing a string when a list is expected, or vice versa.
* **Missing required arguments:** Not providing a keyword argument marked as `required=True` (implicitly through the `ExtractRequired` inheritance).
* **Invalid values for `Literal` types:**  Using a string not listed in a `Literal` definition.

The file path itself is a debugging clue. If a Frida build fails with type errors, inspecting this file can reveal the expected argument types for the function causing the problem.

**Self-Correction/Refinement During the Process:**

Initially, I might focus too much on the specific details of each `TypedDict`. However, the prompt asks for *functionality* and connections to reverse engineering. Therefore, I'd need to step back and synthesize the information, focusing on the *types of things* this file defines (build targets, dependencies, installation steps) and how those relate to Frida's role in dynamic instrumentation. I would also make sure to connect the technical details back to concrete examples relevant to the user's context (Frida and reverse engineering).
This Python file, `kwargs.py`, located within the Frida project's build system, primarily serves as a **central repository for defining the expected keyword arguments (kwargs) and their types for various functions within the Meson build system.**

Essentially, it acts as a **type annotation specification** for Meson functions used in Frida's build process. This provides several benefits:

* **Improved Code Readability and Maintainability:** By explicitly defining the expected keyword arguments and their types, the code becomes easier to understand and maintain. Developers can quickly see what arguments a function accepts and what type of data is expected for each.
* **Static Type Checking:** Tools like MyPy can use these type annotations to perform static analysis and catch potential type errors *before* runtime, leading to more robust and reliable builds.
* **IDE Support:** IDEs can leverage these type annotations to provide better code completion, error highlighting, and other helpful features for developers working on the Frida build system.
* **Documentation:** These definitions serve as a form of documentation, clearly outlining the accepted parameters for Meson functions.

Let's break down its functionality with examples related to reverse engineering, binary level details, and potential user errors:

**1. Defining Keyword Arguments for Meson Build Functions:**

The file uses `typing.TypedDict` to create structured dictionaries that represent the keyword arguments for different Meson build functions. Each `TypedDict` corresponds to a specific function or a group of related functions.

**Examples:**

* **`FuncAddProjectArgs`:** Defines keyword arguments for functions like `add_global_arguments` and `add_project_arguments`. It specifies that these functions accept `native` (for target architecture) and `language` (a list of programming languages).
* **`FuncTest`:** Defines keyword arguments for the `test` function, including `args`, `should_fail`, `timeout`, `is_parallel`, etc., used for defining and running tests as part of the build process.
* **`Executable`, `SharedLibrary`, `StaticLibrary`:**  These define the keyword arguments for building different types of binary targets (executables, shared libraries, static libraries). They include arguments like `sources`, compiler-specific arguments (`c_args`, `cpp_args`), linker arguments (`link_args` implicitly handled), dependencies (`depends`), etc.

**2. Relationship to Reverse Engineering:**

This file indirectly relates to reverse engineering by defining how the Frida tools themselves are built. Understanding the build process can provide insights into the structure and dependencies of Frida, which can be helpful in advanced reverse engineering scenarios.

**Example:**

* **`Executable` definition:** If you're reverse engineering Frida's core components (like `frida-server`), understanding the `Executable` `TypedDict` can tell you what source files are compiled (`sources`), what compiler flags are used (e.g., via `c_args`), and what libraries it's linked against (via `link_with` in `FuncDeclareDependency`, though not directly in `Executable`). This information can be valuable for recreating the build environment or understanding how Frida was compiled.

**3. Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge:**

Several definitions directly or indirectly touch upon low-level concepts and OS-specific knowledge:

* **`MachineChoice`:**  Used in several definitions (e.g., `FuncAddProjectArgs`, `FindProgram`), this indicates the target architecture (e.g., x86, ARM, Android, Linux). This is fundamental when dealing with compiled binaries.
* **Compiler-Specific Arguments (`c_args`, `cpp_args`, etc.):** These keywords directly correspond to command-line flags passed to compilers like GCC or Clang. Understanding these flags requires knowledge of compiler internals and how they affect the generated binary code (e.g., optimization levels, debugging symbols, architecture-specific instructions).
* **Linker Arguments (implicit):** While not explicitly listed as `link_args` in many target definitions, the concept is present in dependencies (`depends`, `link_with`) and the overall build process. Linking is a crucial step in combining compiled object files into executable binaries or libraries. This requires understanding symbol resolution, library paths, and how shared libraries are loaded at runtime (especially relevant on Linux and Android).
* **`install_dir` and `install_mode`:** These keywords in `FuncInstall*` definitions relate to how the built artifacts are placed on the target system. On Linux and Android, understanding file system permissions (`install_mode`) and standard installation directories is important.
* **`EnvironmentVariables`:** Used in definitions like `BaseTest` and `CustomTarget`, this highlights the influence of the environment on the build process and potentially on the execution of tests or custom commands.
* **`win_subsystem` in `Executable`:**  This is specific to Windows and indicates whether the executable is a console or GUI application, reflecting OS-level distinctions.

**Example:**

* When building Frida for Android, the `native: MachineChoice` argument would be set to something like `android_arm64` or `android_arm`. The `c_args` and `cpp_args` might include flags specific to the Android NDK (Native Development Kit) and the target Android architecture. The linking process would involve Android-specific system libraries.

**4. Logical Reasoning and Examples of Input/Output:**

The file itself doesn't perform direct logical reasoning at runtime. Instead, it *defines the structure* that Meson uses for logical reasoning during the build process. Meson uses these type definitions to validate the input provided in the `meson.build` files.

**Hypothetical Input and Output (within a `meson.build` file):**

```python
# Hypothetical usage in meson.build
executable(
  'my_tool',
  'my_tool.c',
  cpp_args: ['-O2', '-Wall'],
  link_with: my_library,
  install: true
)
```

* **Input:** Meson parses this `executable` call and uses the `Executable` `TypedDict` from `kwargs.py` to validate the keyword arguments.
* **Logical Reasoning (by Meson):**
    * It checks if `cpp_args` is a list of strings (as defined in `Executable`).
    * It checks if `link_with` is a valid target object (as inferred from its type).
    * It checks if `install` is a boolean.
* **Output:** If the input conforms to the types defined in `kwargs.py`, Meson proceeds with the build process. If there's a type mismatch, Meson will raise an error.

**5. User or Programming Common Usage Errors:**

This file helps *prevent* common usage errors by enforcing type constraints. However, misunderstandings of these definitions can still lead to errors in `meson.build` files.

**Examples of User Errors:**

* **Incorrect Type for Keyword Argument:**
  ```python
  # Error: cpp_args should be a list of strings
  executable('my_tool', 'my_tool.c', cpp_args: '-O2')
  ```
  Meson would raise an error because `cpp_args` is defined as `T.List[str]` in `Executable`, but a single string was provided.

* **Missing Required Argument (if `ExtractRequired` is used):** Some `TypedDict`s inherit from `ExtractRequired`, which includes a `required` field. If a function uses these kwargs and `required` is set to `True` for a specific argument in the function's logic (not directly in this file), omitting that argument in `meson.build` would cause an error.

* **Invalid Value for `Literal`:**
  ```python
  # Error: win_subsystem must be one of the allowed literals
  executable('my_gui_app', 'gui.c', win_subsystem: 'windows_gui')
  ```
  If `win_subsystem` in the `Executable` definition uses `Literal` with specific allowed values (e.g., `['windows', 'console']`), providing a different string would result in an error.

**6. User Operation to Reach This Point (Debugging Clue):**

Users typically don't interact with `kwargs.py` directly. This file is part of the internal workings of the Meson build system used by Frida. A user would encounter this file indirectly when:

1. **Writing or modifying `meson.build` files:**  When a user writes a `meson.build` file to define how Frida components are built, they are essentially providing input that Meson validates against the definitions in `kwargs.py`.
2. **Running the `meson` command:** When the user runs `meson setup builddir` or `ninja`, Meson parses the `meson.build` files and uses the type information in `kwargs.py` to understand the expected structure and types of the build definitions.
3. **Encountering build errors:** If a user makes a mistake in their `meson.build` file that violates the type definitions in `kwargs.py`, Meson will likely raise an error message. While the error message might not directly point to `kwargs.py`, understanding that Meson uses such type definitions is a crucial debugging step for Frida developers.

**As a debugging clue:** If a Frida developer encounters a Meson build error related to incorrect argument types for a specific Meson function (e.g., `executable`, `library`, `test`), inspecting the corresponding `TypedDict` definition in `kwargs.py` can help them understand the expected argument names and types, leading to the resolution of the error in the `meson.build` file. The file path itself indicates the location of these definitions within the Frida project's build system.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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