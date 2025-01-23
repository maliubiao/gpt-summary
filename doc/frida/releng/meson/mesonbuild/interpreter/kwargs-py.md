Response:
Let's break down the thought process for analyzing this Python file.

**1. Initial Understanding of the File's Purpose:**

The filename `kwargs.py` within the `frida/releng/meson/mesonbuild/interpreter` path immediately suggests that this file defines keyword arguments used within the Meson build system's interpreter, specifically related to Frida. The docstring confirms this. The SPDX license header and copyright also provide context.

**2. Core Functionality - Defining Keyword Arguments:**

The primary function is clearly defining various `TypedDict` classes. These classes act as type hints for the keyword arguments expected by different functions within the Meson build system. This allows for static type checking and better code maintainability.

**3. Identifying Key Concepts and Relationships:**

* **Meson Build System:** The context is the Meson build system. Understanding Meson's core concepts (targets, dependencies, options, etc.) is crucial.
* **Frida:**  This file is part of the Frida project. This implies that these keyword arguments are used in Meson build definitions specifically for Frida components.
* **Type Hints (TypedDict, Literal, Protocol, etc.):** The file heavily uses Python's type hinting features. Recognizing these is essential for understanding the data structures being defined.
* **Build Targets:**  Keywords related to building executables, libraries, custom targets, etc., are prominent. This points to the file's role in defining how Frida's components are built.
* **Dependencies:**  Keywords related to managing dependencies are also present, indicating how Frida links against other libraries.
* **Testing and Benchmarking:**  Keywords related to `test` and `benchmark` functions suggest that this file helps define how Frida's tests are structured and executed.
* **Installation:** Keywords related to installation (e.g., `install_dir`, `install_mode`) indicate how Frida's built artifacts are installed.

**4. Analyzing Individual `TypedDict` Classes:**

For each `TypedDict`, the process involves:

* **Identifying the Function/Context:**  The class name often hints at the function or area where these arguments are used (e.g., `FuncAddProjectArgs`, `FuncTest`, `CustomTarget`).
* **Understanding Each Key:** For each key within the `TypedDict`, try to understand its purpose and data type. The docstrings within the `TypedDict` are often helpful.
* **Recognizing Common Patterns:** Notice recurring keys like `args`, `depends`, `env`, `install`, etc., across multiple `TypedDict`s. This indicates common functionality or concepts within the build system.

**5. Connecting to Reverse Engineering (Hypothesis and Examples):**

* **Thinking about Frida's Use Case:** Frida is a dynamic instrumentation toolkit used for reverse engineering, debugging, and security research. How might these keyword arguments relate to those activities?
* **Instrumentation:** Frida injects code into running processes. The `command` keyword in `RunTarget` and `CustomTarget` could be used to specify the Frida script or agent to run.
* **Targeting Processes:** While not explicitly present, one could *hypothesize* that future extensions might involve keywords to specify the target process to instrument.
* **Examining Specific Keywords:**  `env` (environment variables) could be relevant for controlling the target process's environment during instrumentation.

**6. Connecting to Low-Level Concepts (Hypothesis and Examples):**

* **Operating System Focus:** Frida operates at a low level, interacting with the OS kernel and process memory.
* **Binary Manipulation:**  Keywords like `c_args`, `cpp_args`, etc., relate to compiler flags, which directly influence the generated binary code.
* **Linking:** Keywords related to linking (`link_args`, `link_with`) are essential for combining compiled object files into executables or libraries. This involves understanding how symbols are resolved at the binary level.
* **Kernel Interaction (Indirect):** While not directly exposed here, the build process ultimately creates binaries that interact with the kernel. Compiler flags and linking options can impact these interactions (e.g., system calls).
* **Android Specifics (Potential):** Though not explicitly detailed in *this* file, Frida is heavily used on Android. One could *hypothesize* the existence of other Meson modules or files with keywords specific to Android (NDK, etc.).

**7. Logical Reasoning and Examples (Input/Output):**

* **Focus on Specific `TypedDict`s:** Choose a simpler `TypedDict` to illustrate the concept. `FuncTest` is a good example.
* **Defining Inputs:**  Create a hypothetical scenario with values for the keywords.
* **Predicting Outputs/Actions:**  Based on the input, what would the Meson build system do with this information?  For `FuncTest`, it would register a test with the given name, arguments, etc.

**8. User Errors and Debugging (Hypothesis and Examples):**

* **Think about Common Mistakes:** What are typical errors developers make when using build systems?
* **Type Mismatches:**  Providing a string when an integer is expected is a classic error.
* **Missing Required Arguments:** For `TypedDict`s inheriting from `ExtractRequired`, omitting the `required` key would be an error.
* **Incorrect File Paths:**  Providing a non-existent file in the `sources` list.
* **Debugging Strategy:** How would a user reach this code during debugging?  They would likely be investigating issues with how their build definitions are being interpreted by Meson, potentially setting breakpoints within Meson's interpreter.

**9. Structuring the Answer:**

Organize the findings into logical sections with clear headings, as demonstrated in the provided good answer. Use bullet points and examples to make the information easy to understand. Start with a general overview and then delve into more specific details.

**Self-Correction/Refinement during the thought process:**

* **Initial Overwhelm:** The sheer number of `TypedDict`s can be intimidating. Focus on understanding the purpose of a few key ones first, and then generalize.
* **Avoiding Speculation:**  While it's tempting to make broad claims about Frida's internals, stick to what can be inferred directly from the code and the context of a build system. Use qualifiers like "potentially" or "could be" when speculating.
* **Iterative Understanding:**  Come back to the code and refine your understanding as you learn more about Meson and Frida. This isn't a one-pass process.
This Python file, `kwargs.py`, within the Frida project's Meson build system definition, serves as a central repository for **defining the expected keyword arguments for various functions used in the Meson build scripts**. It uses Python's type hinting features (`TypedDict`, `Literal`, `Protocol`, `NotRequired`) to provide structured and type-safe definitions for these keyword arguments.

Here's a breakdown of its functionality:

**1. Defining Typed Keyword Arguments:**

   - The primary function is to create `TypedDict` classes. Each `TypedDict` represents the expected keyword arguments for a specific Meson function or a group of related functions.
   - This enforces a clear structure for the arguments, making the build scripts more readable and less prone to errors due to incorrect or missing arguments.
   - Examples include `FuncAddProjectArgs` for `add_project_arguments`, `FuncTest` for the `test` function, `CustomTarget` for the `custom_target` function, and many more.

**2. Providing Type Information:**

   - By using type hints, the file explicitly declares the expected data type for each keyword argument (e.g., `str`, `bool`, `T.List[str]`, `File`, `build.Target`).
   - This allows static type checkers (like MyPy) to verify the correctness of the Meson build scripts, catching potential type errors before runtime.
   - It improves code maintainability by making the expected input types explicit.

**3. Grouping Related Arguments:**

   - The file logically groups related keyword arguments into specific `TypedDict` classes. This makes it easier to understand the purpose and usage of different sets of arguments.
   - For instance, all the keyword arguments related to defining a test case are grouped within `FuncTest`.

**4. Inheritance and Reusability:**

   - Some `TypedDict` classes inherit from others (e.g., `FuncTest` inherits from `FuncBenchmark`). This promotes code reuse and reduces redundancy by sharing common sets of arguments.

**Relationship to Reverse Engineering:**

While this file itself doesn't directly perform reverse engineering, it plays a crucial role in **building the Frida tool**, which is heavily used for dynamic instrumentation and reverse engineering.

* **Building Frida's Components:** The definitions in `kwargs.py` are used when the Frida developers write Meson build scripts to compile Frida's core library, command-line tools, and other components. These components are then used by reverse engineers to inspect and modify the behavior of running processes.

* **Example:** The `Executable` `TypedDict` defines keywords like `sources`, `c_args`, `cpp_args`, `link_with`, etc. When building Frida's core library (`frida-core`), the Meson build script will use these keywords to specify the source code files, compiler flags, and libraries to link against. Reverse engineers then use this `frida-core` library to perform instrumentation.

**Involvement of Binary底层, Linux, Android Kernel & Framework Knowledge:**

The definitions in `kwargs.py` indirectly reflect the underlying system details that Frida interacts with.

* **Compiler and Linker Flags:** Keywords like `c_args`, `cpp_args`, `link_args` (present in many `TypedDict`s like `Executable`, `SharedLibrary`) directly correspond to compiler and linker flags. These flags are crucial for controlling how the binary code is generated, optimized, and linked. This involves a deep understanding of how compilers work at the binary level.

* **Library Types:** Keywords like `link_with` (in `FuncDeclareDependency`) refer to different types of libraries (`shared_library`, `static_library`). Understanding the difference between these library types and how they are loaded by the operating system (Linux, Android) is fundamental.

* **Operating System Specifics:** Keywords like `win_subsystem` (in `Executable`) indicate platform-specific settings. The existence of such keywords highlights the need to consider the target operating system when building Frida. Frida needs to work across different platforms (Linux, macOS, Windows, Android, iOS).

* **Android Context (Indirect):** While not explicitly Android kernel specific in *this* file, the fact that Frida is a prominent tool on Android implies that the build system (and therefore these keyword arguments in other related files) needs to handle building native components for Android using the NDK (Native Development Kit). This involves understanding the Android framework and how native code interacts with it.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `FuncTest` `TypedDict`:

**Hypothetical Input:**

```python
test_kwargs = {
    "name": "my_important_test",
    "args": ["--verbose", "input.txt"],
    "timeout": 60,
    "is_parallel": True,
    "suite": ["integration"],
}
```

**Logical Reasoning:**

When the Meson interpreter encounters a `test()` function call in a `meson.build` file and it receives these `test_kwargs`, it will:

1. **Validate:** Check if the provided keys (`name`, `args`, `timeout`, `is_parallel`, `suite`) are valid according to the `FuncTest` definition.
2. **Type Check:** Verify that the values associated with each key match the expected types (e.g., `name` is a string, `args` is a list of strings).
3. **Register Test:**  If validation and type checking pass, Meson will register a test named "my_important_test".
4. **Test Execution:** When the `meson test` command is executed, Meson will run this test. It will execute a command with the provided `args` (`--verbose`, `input.txt`). The test will have a timeout of 60 seconds and will be executed in parallel with other parallelizable tests. It will be categorized under the "integration" test suite.

**User/Programming Common Usage Errors:**

* **Typographical Errors in Keyword Names:**
   ```python
   # Incorrect keyword: 'arg' instead of 'args'
   test('my_test', main.c, arg=['some', 'options'])
   ```
   This will likely result in a Meson error because the interpreter won't recognize the `arg` keyword in the context of the `test()` function.

* **Incorrect Data Types:**
   ```python
   # Incorrect type: timeout should be an integer
   test('my_test', main.c, timeout='sixty')
   ```
   Meson's type checking (or runtime checks) will raise an error because the `timeout` keyword expects an integer, not a string.

* **Missing Required Arguments (if any were marked as such):**  While most in this file are optional or have defaults, if a `TypedDict` had a field without `NotRequired`, omitting it would cause an error.

* **Providing Invalid Values for `Literal` Types:**
   ```python
   # Incorrect value for 'protocol' (only 'exitcode', 'tap', 'gtest', 'rust' are allowed)
   benchmark('my_benchmark', my_bench, protocol='custom')
   ```
   This will result in a Meson error because the `protocol` keyword has a restricted set of allowed values.

**User Operation Steps to Reach This Code (Debugging):**

1. **Writing a `meson.build` file:** A Frida developer or contributor is writing or modifying the build definition file (`meson.build`) for a Frida component.
2. **Using Meson Functions with Keyword Arguments:**  They use functions like `executable()`, `shared_library()`, `test()`, `custom_target()`, etc., and pass keyword arguments to these functions.
3. **Running Meson Commands:** The developer executes Meson commands like `meson setup builddir`, `meson compile -C builddir`, or `meson test -C builddir`.
4. **Encountering Errors:** If there are errors related to the keyword arguments (e.g., typo, incorrect type), Meson will report an error during the setup or compilation phase.
5. **Debugging (Optional):**
   - The developer might look at the Meson error message, which might indirectly point to the problematic keyword argument.
   - To understand the expected arguments, they might need to consult the Meson documentation or, if working on Frida's build system, **directly examine the `kwargs.py` file**. This file serves as the source of truth for the valid keyword arguments and their types.
   - Advanced debugging might involve stepping through the Meson interpreter's code (if they are contributing to Meson itself or deeply investigating a build issue). In that case, they would directly encounter this `kwargs.py` file as the interpreter processes the build definitions.

In summary, `kwargs.py` is a foundational file for ensuring type safety and structure in Frida's Meson build definitions. It plays a vital role in defining how Frida's components are built, implicitly touching upon various aspects of software development, including compiler/linker behavior and operating system concepts, which are relevant to reverse engineering efforts that utilize Frida.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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