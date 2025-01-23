Response:
Let's break down the thought process for analyzing this Python code and generating the requested explanation.

**1. Understanding the Core Purpose:**

The first step is to recognize that this file (`kwargs.py`) resides within the Meson build system's interpreter. The filename itself is a strong hint: "kwargs" likely stands for keyword arguments. The imports reinforce this, especially the `typing` and `typing_extensions` modules used for type hinting, and the `build`, `coredata`, `compilers`, etc., modules from Meson.

The immediate conclusion is that this file defines the *expected keyword arguments* for various Meson build system functions. It's essentially a schema or a contract for how these functions should be called.

**2. Identifying Key Structures:**

The code is primarily composed of `TypedDict` definitions. Recognizing this is crucial because `TypedDict` in Python allows for creating dictionary types with specific key-value pairs and their respective types. Each `TypedDict` corresponds to a specific Meson function or a group of related functions.

**3. Mapping `TypedDict` to Meson Functions (Implicitly):**

While the code doesn't explicitly name the Meson functions, the `TypedDict` names are highly suggestive. For example:

* `FuncAddProjectArgs`:  Likely related to `add_project_arguments` or `add_global_arguments`.
* `FuncTest`: Clearly for the `test()` function.
* `FuncBenchmark`:  For `benchmark()`.
* `FuncInstallSubdir`, `FuncInstallData`, `FuncInstallHeaders`, `FuncInstallMan`:  All related to installation commands.
* `CustomTarget`:  For the `custom_target()` function.
* `Executable`, `StaticLibrary`, `SharedLibrary`:  For defining different types of build targets.

This implicit mapping is the core of the file's functionality. It provides structure and type safety to the Meson interpreter.

**4. Analyzing Individual `TypedDict` Members:**

Once the purpose is clear, analyze the members (keys and their types) within each `TypedDict`. Pay attention to:

* **Primitive Types:** `str`, `int`, `bool`, `list`, `dict`, `tuple`.
* **Meson-Specific Types:** `File`, `BuildTarget`, `CustomTarget`, `Dependency`, `IncludeDirs`, `EnvironmentVariables`, `MachineChoice`, `OptionKey`, etc. Understanding these types provides insight into the concepts Meson deals with.
* **Type Hints:** `T.Optional`, `T.List`, `T.Union`, `Literal`, `NotRequired`. These indicate optional arguments, lists of arguments, arguments that can be one of several types, specific allowed string values, and arguments that are not strictly required.

**5. Connecting to Reverse Engineering, Binaries, Kernels, etc.:**

Now, the crucial step is to connect these Meson concepts to the requested domains.

* **Reverse Engineering:** Look for arguments that control how binaries are built, linked, and executed. Things like:
    * `c_args`, `cpp_args`, `link_args`: Compiler and linker flags. These are directly used in reverse engineering to understand how software was built and potentially to modify its behavior.
    * `export_dynamic`, `pie`: Security-related build options relevant to reverse engineering.
    * `vs_module_defs`:  Windows-specific module definitions.
    * `install_dir`: Where the built artifacts are placed.
    * `run_target`: Defining commands to run after building, potentially for testing or validation.

* **Binary/Low-Level:** Focus on aspects that directly interact with the compiled output:
    * `objects`:  Specifying object files.
    * `link_with`:  Linking against libraries.
    * `soversion`, `darwin_versions`:  Versioning for shared libraries.
    * `install_mode`: File permissions.
    * `nasm_args`, `masm_args`:  Assembler arguments.

* **Linux/Android Kernel & Frameworks:**  This is more indirect. Meson itself is cross-platform, but the *things it builds* can target these systems. Look for:
    * Arguments related to shared libraries (`.so` on Linux, `.so` or `.dylib` on Android).
    * Options for position-independent executables (`pie`), common in modern Linux distributions and Android.
    * While not explicit here, Meson can be used to build kernel modules or Android system components. The flags and build targets defined here would be used in that process.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

For logical reasoning, pick a simple `TypedDict` and illustrate how Meson might use the information. The `FuncTest` example is good because it's relatively straightforward:

* **Input:**  A user defines a test with a name, a command to run, and sets `is_parallel` to `True`.
* **Processing:** Meson's test runner would read this information. The `is_parallel=True` would inform the runner to execute this test concurrently with other parallelizable tests.
* **Output:** The test would be executed, and the results (pass/fail, logs) would be reported.

**7. User/Programming Errors:**

Think about common mistakes developers make when using build systems:

* **Incorrect Types:** Passing a string when an integer is expected. Type hinting helps catch this.
* **Missing Required Arguments:** Forgetting to specify a mandatory argument. `NotRequired` helps identify optional ones.
* **Invalid Literal Values:**  Using a string that's not allowed by a `Literal` type.
* **Incorrect File Paths:** Providing a non-existent file path for a source file.

**8. Debugging Clues (How to Reach This Code):**

Imagine a developer using Frida and encountering a build error related to how arguments are being passed to a Meson function. The debugging steps would involve:

1. **Examining the Meson Log:** Look for error messages indicating incorrect argument types or missing arguments.
2. **Consulting the Meson Documentation:**  Refer to the documentation for the specific Meson function being used (e.g., `add_library`, `custom_target`).
3. **Tracing the Code:** If the error is within Meson itself, a developer might need to step through the Meson interpreter's code. This is where knowing the file structure (like `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/kwargs.py`) becomes important. They'd look at how the arguments are being processed and validated against the `TypedDict` definitions in this file.

By following these steps, you can systematically analyze the code and generate a comprehensive explanation covering the requested aspects. The key is to understand the code's purpose within the larger system (Meson) and then connect the specific details to the broader concepts of reverse engineering, low-level programming, and common usage scenarios.
这个文件 `kwargs.py` 是 Frida 动态 instrumentation 工具中 Meson 构建系统的一部分，它定义了各种 Meson 构建函数所接受的**关键字参数的类型注解 (Type Hints)**。 简单来说，它就像一份合同，规定了调用 Meson 函数时可以使用的参数名称以及这些参数应该是什么类型。

**它的主要功能可以概括为：**

1. **类型校验和文档：**  为 Meson 解释器提供类型信息，用于在构建时检查用户提供的关键字参数是否符合预期类型。这有助于在早期发现编程错误。同时，这些类型注解也作为文档，清晰地说明了每个函数的可用参数及其类型。
2. **代码提示和自动补全：**  对于支持类型注解的编辑器和 IDE，这些定义可以提供更好的代码提示和自动补全功能，提高开发效率。
3. **代码生成和元编程：**  Meson 内部可以使用这些类型信息进行代码生成或其他元编程操作，例如自动生成文档或构建辅助工具。

**与逆向方法的关系及举例说明：**

这个文件本身并不直接执行逆向操作，但它定义了构建过程中关键步骤的参数，这些步骤直接影响最终生成的可执行文件和库的行为，因此与逆向分析息息相关。

**举例说明：**

* **`_BuildTarget` (以及其子类 `Executable`, `SharedLibrary`, `StaticLibrary` 等):**  这些类型定义了构建目标（如可执行文件、共享库、静态库）的各种属性。逆向工程师需要了解这些属性，才能理解目标文件的构建方式和依赖关系。
    * 例如，`c_args`, `cpp_args`, `link_args` 定义了传递给 C/C++ 编译器和链接器的参数。逆向工程师可以通过分析构建脚本中这些参数的设置，了解编译时是否启用了某些优化选项、是否使用了特定的库、以及如何处理符号信息等。这些信息对于理解程序的行为和进行调试非常重要。
    * `install_rpath` 定义了运行时库的搜索路径。逆向工程师可以通过分析这个路径，了解程序运行时依赖哪些库，以及这些库的加载顺序，这对于解决库依赖问题或进行Hook操作很有帮助。
    * `gnu_symbol_visibility` 定义了符号的可见性。逆向工程师可以通过了解符号的可见性，判断哪些函数和变量是导出的，可以被外部访问，这对于动态分析和Hook至关重要。

* **`CustomTarget`:**  允许用户自定义构建步骤。逆向工程师可能会遇到使用 `custom_target` 执行一些预处理或后处理操作的构建脚本，例如解压资源、签名文件等。理解 `CustomTarget` 的参数（如 `command`, `input`, `output`) 可以帮助逆向工程师理解这些自定义步骤的目的和操作。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

虽然这个文件本身是 Python 代码，但它描述的构建过程和参数与底层的二进制、操作系统特性密切相关。

**举例说明：**

* **二进制底层：**
    * `objects`:  表示编译生成的对象文件。理解对象文件的结构对于理解编译过程至关重要。
    * `link_with`: 指定需要链接的库。链接是二进制文件生成的核心步骤。
    * `install_mode`:  定义了安装后文件的权限，这直接关系到二进制文件的执行权限。
* **Linux：**
    * `install_rpath`:  在 Linux 系统中用于指定运行时库搜索路径。
    * `soversion`:  共享库的版本信息，Linux 中用于处理库的兼容性问题。
    * `export_dynamic`:  控制动态链接符号的导出，在 Linux 中影响动态库的加载和符号解析。
* **Android 内核及框架：**
    * 尽管这里没有直接涉及到 Android 特有的参数，但 Meson 可以用于构建 Android 平台上的应用程序和库。上述关于共享库、链接和编译参数的知识同样适用于 Android 环境。例如，理解如何构建共享库以及如何指定其依赖关系对于逆向分析 Android Native 代码非常重要。

**逻辑推理，假设输入与输出：**

假设我们有一个简单的 `meson.build` 文件，其中使用 `executable` 函数定义了一个可执行文件：

```meson
project('my_app', 'c')
executable('my_program', 'main.c', c_args : ['-Wall', '-O2'])
```

**假设输入：**

* Meson 解释器在解析 `meson.build` 文件时，遇到了 `executable` 函数调用。
* `executable` 函数的关键字参数为 `{'target_name': 'my_program', 'sources': ['main.c'], 'kwargs': {'c_args': ['-Wall', '-O2']}}`。

**逻辑推理过程：**

1. Meson 解释器会查找 `kwargs.py` 文件中 `Executable` 对应的 `TypedDict` 定义。
2. 它会检查提供的关键字参数 `c_args` 是否存在于 `Executable` 的定义中，并且类型是否为 `T.List[str]`。
3. 因为 `c_args` 存在且类型匹配，所以类型检查通过。

**输出：**

* Meson 解释器继续执行构建过程，并将 `c_args` 中的 `['-Wall', '-O2']` 传递给 C 编译器。

**涉及用户或者编程常见的使用错误及举例说明：**

这个文件定义了类型，如果用户在 `meson.build` 文件中使用了错误的类型，Meson 会报错。

**举例说明：**

* **错误的类型：**  如果用户错误地将一个整数传递给 `c_args` 参数：
  ```meson
  executable('my_program', 'main.c', c_args : 123) # 错误：c_args 应该是一个字符串列表
  ```
  Meson 解释器在解析时会检查 `c_args` 的类型，发现它不是 `T.List[str]`，会抛出类型错误，提示用户 `c_args` 应该是一个字符串列表。

* **使用了不存在的参数：** 如果用户使用了 `Executable` 类型中未定义的关键字参数：
  ```meson
  executable('my_program', 'main.c', unknown_arg : 'value') # 错误：unknown_arg 不是 Executable 的有效参数
  ```
  Meson 解释器在解析时会检查 `unknown_arg` 是否在 `Executable` 的 `TypedDict` 中定义，如果不存在，会报错提示该参数无效。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户创建或修改 `meson.build` 文件，并在其中使用了 Meson 提供的构建函数，例如 `executable`, `shared_library`, `custom_target` 等。
2. **用户运行 Meson 命令：** 用户在命令行中执行 `meson setup builddir` 或 `meson compile -C builddir` 等命令，指示 Meson 开始解析构建文件并执行构建过程。
3. **Meson 解释器解析 `meson.build`：** Meson 的解释器开始读取和解析 `meson.build` 文件。当遇到函数调用时，例如 `executable('my_program', 'main.c', c_args : ['-Wall'])`，解释器会提取函数名和关键字参数。
4. **类型检查：**  对于包含关键字参数的函数调用，解释器会查找 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/kwargs.py` 文件中对应函数的 `TypedDict` 定义（例如 `Executable` 对应 `executable` 函数）。
5. **参数校验：** 解释器会将用户提供的关键字参数与 `TypedDict` 中定义的参数进行比对，检查参数名称是否合法，参数类型是否匹配。
6. **错误报告（如果发生）：** 如果用户提供的参数名称错误或类型不匹配，Meson 解释器会抛出相应的错误信息，指出错误发生的参数和期望的类型。

**作为调试线索：**

当用户遇到 Meson 构建错误时，特别是涉及到参数类型或参数名称的错误，可以参考以下步骤进行调试：

1. **查看 Meson 错误信息：**  错误信息通常会指出哪个函数调用出现了问题以及具体的错误原因（例如，类型不匹配，未知参数）。
2. **查阅 Meson 文档：**  查看对应 Meson 函数的官方文档，了解其接受的参数和类型。
3. **查看 `kwargs.py` 文件：**  如果文档不够详细，可以直接查看 `kwargs.py` 文件中对应函数的 `TypedDict` 定义，确认允许使用的参数名称和类型。例如，如果错误信息提示 `c_args` 必须是字符串列表，可以在 `Executable` 的定义中找到 `c_args: T.List[str]` 来确认。
4. **检查 `meson.build` 文件：**  仔细检查 `meson.build` 文件中出错的函数调用，确认参数名称和类型是否与 `kwargs.py` 中的定义一致。

总而言之，`kwargs.py` 文件虽然不直接参与 Frida 的动态 instrumentation 过程，但它作为 Meson 构建系统的一部分，通过定义关键字参数的类型，确保了构建过程的正确性和可靠性，对于理解 Frida 的构建方式以及进行问题排查都具有重要的参考价值。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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