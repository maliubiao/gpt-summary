Response:
Let's break down the thought process for analyzing this Python code and generating the explanation.

**1. Understanding the Goal:**

The core request is to understand the *purpose* and *functionality* of this specific Python file within the Frida project. The user is asking for a breakdown of what this code *does*. The prompt also explicitly asks for connections to reverse engineering, low-level concepts (kernels, etc.), logic, potential errors, and how a user might reach this code during debugging.

**2. Initial Code Scan & High-Level Interpretation:**

The first step is a quick read-through of the code. Keywords like `TypedDict`, `Literal`, `Protocol`, class names like `FuncAddProjectArgs`, `BaseTest`, `CustomTarget`, and imports from `..build`, `..coredata`, etc., immediately suggest that this file defines *type hints* and *data structures* related to the Meson build system. It's likely used for validating and documenting the expected arguments (keyword arguments specifically) of various Meson functions.

**3. Deeper Dive into Key Constructs:**

* **`TypedDict`:** The prevalence of `TypedDict` is the most crucial observation. It signifies that this file is all about defining the *structure* of keyword arguments for different Meson build functions. Each `TypedDict` represents the expected keywords and their types for a specific function or group of related functions.

* **Class Names:** The class names are highly descriptive. `FuncAddProjectArgs` clearly relates to functions for adding project-level arguments. `BaseTest` is likely a base class for test-related function arguments. `CustomTarget` defines the arguments for creating custom build targets. These names provide strong clues about the purpose of each `TypedDict`.

* **Type Annotations:** The use of `T.List`, `T.Optional`, `T.Union`, `Literal`, `bool`, `str`, `int`, and references to other Meson types (like `build.Target`, `coredata.UserFeatureOption`, `Dependency`) further confirms the role of type hinting and structure definition.

* **Imports:** The imports are informative. Importing from `..build`, `..coredata`, `..compilers`, `..dependencies`, `..mesonlib`, `..modules.cmake`, and `..programs` confirms that this file is deeply integrated with the Meson build system and its concepts.

**4. Connecting to the Prompts Specific Questions:**

* **Functionality:** This becomes clearer – the file defines the structure and types of keyword arguments for various Meson functions. This helps Meson validate user input and generate correct build configurations.

* **Reverse Engineering:**  The connection isn't *direct* in terms of Frida's runtime behavior. However, understanding the build process is crucial for reverse engineering. Knowing how Frida is built, what build options are available (which these `TypedDict`s define), and how dependencies are managed can be invaluable for analyzing Frida's internals or modifying its build.

* **Binary/Low-Level/Kernel/Framework:** Again, the connection isn't direct code execution. However, the *arguments* defined here (like compiler flags, linker options, dependency specifications) directly influence the generated binaries, the way they link against libraries, and how they interact with the operating system. For example, understanding how `link_args` are defined can help in analyzing linking issues in a reverse engineering context. The `native: MachineChoice` field relates directly to cross-compilation and targeting different architectures.

* **Logic/Input/Output:** The "logic" here is the definition of the expected structure. A hypothetical input would be a Meson build file using a function like `executable()` with various keyword arguments. The "output" is the interpretation and validation of these arguments by Meson. The `TypedDict`s act as a schema.

* **User Errors:**  If a user provides incorrect keyword arguments (wrong type, misspelled name, missing required arguments), Meson, using these type definitions, can detect and report these errors. Examples like providing a string for a boolean or missing a `required` argument are straightforward.

* **Debugging Path:** The thought here is: *How would a developer end up looking at this file?*  The most likely scenario is during debugging of Meson itself or when trying to understand how a particular Meson function works and what arguments it accepts. Error messages from Meson might point to issues with argument parsing, leading a developer to investigate these type definitions.

**5. Structuring the Explanation:**

A logical structure for the explanation is:

1. **Overall Purpose:** Start with a high-level summary of what the file does.
2. **Key Concepts:** Explain the core elements like `TypedDict` and their significance.
3. **Functionality Breakdown:**  Go through the different categories of `TypedDict` and their associated Meson features.
4. **Connections to the Prompts:** Address each specific question in the prompt (reverse engineering, low-level, logic, errors, debugging).
5. **Examples:** Provide concrete examples to illustrate the concepts, especially for user errors and the debugging path.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the individual `TypedDict` definitions. It's important to step back and see the overall pattern and the broader purpose of the file within the Meson ecosystem.
* The connection to reverse engineering and low-level concepts is indirect but important. It's about the *influence* of these build definitions on the final binary.
* For the debugging path, thinking about realistic scenarios where a developer would need this information is key. Error messages and understanding Meson internals are good starting points.

By following these steps, combining code analysis with understanding the context of the Frida project and the Meson build system, we can arrive at a comprehensive and accurate explanation.
这个Python文件 `kwargs.py` 定义了大量用于描述 Meson 构建系统中各种函数 **关键字参数** 的类型注解 (type hints)。Meson 是 Frida 使用的构建系统，因此这个文件对于理解 Frida 的构建过程至关重要。

**功能列举:**

1. **定义 Meson 函数的关键字参数类型:**  该文件使用 `typing.TypedDict` 来定义各种 Meson 构建函数 (如 `executable`, `library`, `test`, `custom_target` 等) 可以接受的关键字参数及其对应的数据类型。这就像为函数的参数创建了一个严格的结构化描述。

2. **提供类型安全:** 这些类型注解使得 Meson 可以在构建时进行更严格的类型检查。如果用户在 `meson.build` 文件中传递了错误的参数类型，Meson 可以提前捕获这些错误，而不是等到构建过程的后期才出现难以理解的错误。

3. **文档作用:**  这些类型定义本身就构成了一份关于 Meson 函数可用关键字参数的文档。开发者可以通过查看这个文件来了解某个函数可以接受哪些参数以及参数的类型。

4. **辅助代码编辑器和 IDE:** 支持类型注解的代码编辑器和 IDE (如 PyCharm, VS Code) 可以利用这些信息提供更好的代码补全、错误提示和静态分析功能，帮助开发者更高效地编写 `meson.build` 文件。

5. **模块化和组织:** 将关键字参数的定义集中在一个文件中，有助于组织和维护 Meson 的代码。

**与逆向方法的关系及举例:**

虽然这个文件本身不直接参与 Frida 的运行时逆向操作，但它定义了 Frida 的构建方式，而构建过程直接影响最终生成的可执行文件和库。理解构建过程对于逆向工程非常有帮助。

**举例说明:**

* **`Executable` 和 `SharedLibrary` 的关键字参数:**  这些 `TypedDict` 定义了生成可执行文件和共享库时可以使用的选项，例如：
    * `c_args`, `cpp_args`:  指定 C/C++ 编译器的命令行参数。逆向工程师可以通过分析 Frida 的 `meson.build` 文件中使用的这些参数，了解 Frida 在编译时启用了哪些优化、定义了哪些宏，这些信息可能揭示 Frida 的内部工作原理或绕过某些安全机制。例如，如果启用了 `-DDEBUG` 宏，可能意味着 Frida 的某些部分包含调试信息。
    * `link_args`: 指定链接器的命令行参数。逆向工程师可以查看 Frida 链接了哪些库，以及使用了哪些链接器选项。这有助于理解 Frida 的依赖关系和如何与系统交互。
    * `pie`:  Position Independent Executable (地址无关可执行文件)。查看是否启用了 `pie` 可以了解 Frida 的安全特性。启用 `pie` 可以增加地址空间布局随机化 (ASLR) 的效果，使逆向分析更困难。
    * `vs_module_defs`:  用于指定 Visual Studio 的模块定义文件。在 Windows 平台上逆向 Frida 时，了解是否使用了模块定义文件以及其内容，可以帮助理解 Frida 的符号导出和导入。

* **`CustomTarget` 的关键字参数:**  这个 `TypedDict` 定义了创建自定义构建目标时可以使用的选项，例如 `command` 指定了要执行的命令。在 Frida 的构建过程中，可能会使用自定义目标来执行代码生成、资源处理等操作。逆向工程师可以通过分析自定义目标的命令，了解 Frida 的构建流程和可能存在的代码生成逻辑。

**涉及到二进制底层，Linux, Android内核及框架的知识及举例:**

这些类型定义间接地反映了构建过程中的一些底层概念：

* **`MachineChoice`:**  指定构建的目标机器架构 (例如 x86, ARM)。这直接关系到生成的二进制文件的指令集和架构。对于逆向 Android 上的 Frida，了解目标架构 (通常是 ARM) 至关重要。

* **`install_mode`:**  指定安装文件的权限模式。这与 Linux 和 Android 的文件系统权限模型相关。

* **`link_language`:**  指定链接时使用的语言。这在混合语言项目中很重要，并且会影响链接器的行为。

* **各种语言特定的参数 (如 `c_args`, `swift_args` 等):**  这些参数可以包含与特定操作系统或平台相关的编译器和链接器选项。例如，针对 Android 内核模块的编译可能需要特定的 GCC 选项。

**逻辑推理及假设输入与输出:**

这里的 "逻辑" 主要是指 Meson 如何使用这些类型定义来验证用户提供的构建配置。

**假设输入:**  一个 `meson.build` 文件中使用了 `executable()` 函数，并传递了一些关键字参数。

```python
executable(
  'my_frida_tool',
  'main.c',
  c_args: ['-O2', '-Wall'],
  link_args: ['-lpthread'],
  install: true,
  # 错误的参数类型
  debug_symbols: "yes"
)
```

**输出 (Meson 的行为):**

Meson 会根据 `Executable` 的 `TypedDict` 定义来检查 `executable()` 函数的关键字参数。

* `c_args` 和 `link_args` 的类型是 `T.List[str]`，所以 `['-O2', '-Wall']` 和 `['-lpthread']` 是合法的。
* `install` 的类型是 `bool`，所以 `true` 是合法的。
* `debug_symbols` 不是 `Executable` `TypedDict` 中定义的关键字参数，或者如果存在，它的类型应该是 `bool` 而不是字符串 `"yes"`。因此，Meson 会报告一个类型错误或未知的关键字参数错误。

**涉及用户或者编程常见的使用错误及举例:**

* **类型错误:** 用户传递了错误的参数类型。
    * **例子:**  在 `executable()` 中将字符串赋值给期望布尔值的 `install` 参数 (`install: "true"` 而不是 `install: true`)。
* **拼写错误:** 用户拼错了关键字参数的名称。
    * **例子:** 将 `c_args` 拼写成 `cargs`。Meson 会报告一个未知的关键字参数。
* **缺少必需的参数:** 某些参数可能是必需的，但用户没有提供。虽然这个文件没有显式声明哪些参数是必需的 (这通常在 Meson 的其他代码中处理)，但理解 `TypedDict` 可以帮助开发者推断哪些参数是重要的。
* **使用了不适用的参数:**  某些参数可能只适用于特定的目标类型。例如，`vs_module_defs` 主要用于 Windows 平台。在非 Windows 平台上使用可能会导致错误或被忽略。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个 Frida 开发者或贡献者，或者仅仅是想深入理解 Frida 的构建过程，你可能会：

1. **阅读 Frida 的构建脚本 `meson.build` 文件:** 你会看到各种 Meson 函数的调用，例如 `executable()`, `library()`, `test()` 等，以及它们使用的关键字参数。

2. **遇到构建错误:**  如果 `meson.build` 文件中使用了不正确的关键字参数，Meson 会报错。错误信息可能会指向相关的 Meson 函数。

3. **查阅 Meson 的文档:**  Meson 的官方文档会描述这些函数和它们的参数。

4. **深入 Meson 的源代码 (例如这个 `kwargs.py` 文件):**  为了更精确地了解某个函数的参数类型和含义，你可能会查看 Meson 的源代码。特别是当文档不够详细或者你想了解 Meson 内部是如何处理这些参数的时候。

5. **使用 IDE 的代码跳转功能:**  在支持代码跳转的 IDE 中，你可以从 `meson.build` 文件中使用的 Meson 函数跳转到 Meson 源代码中定义这些函数参数的地方，最终可能会定位到像 `kwargs.py` 这样的文件。

总而言之，`frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/kwargs.py` 文件虽然不直接参与 Frida 的运行时逆向，但它详细定义了 Frida 构建过程中使用的各种 Meson 函数的关键字参数类型，对于理解 Frida 的构建流程、排查构建错误以及深入了解 Frida 的编译选项都非常有价值。它就像一份 Meson 构建蓝图的局部细节图。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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