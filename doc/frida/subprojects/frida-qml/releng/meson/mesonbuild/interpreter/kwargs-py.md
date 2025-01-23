Response:
Let's break down the thought process to analyze this Python code snippet. The goal is to understand its purpose and connections to reverse engineering, low-level concepts, and common usage errors.

**1. Initial Understanding of the File Path and Context:**

The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/kwargs.py` immediately provides crucial context:

* **Frida:** This is the main project. Knowing Frida is a dynamic instrumentation toolkit is key.
* **subprojects/frida-qml:** This indicates a specific part of Frida related to QML (Qt Meta Language), suggesting a UI component.
* **releng/meson:** This points to the release engineering and build system. Meson is a build system generator.
* **mesonbuild/interpreter:** This is the core of Meson's interpretation logic.
* **kwargs.py:** The filename suggests this file defines keyword arguments used in Meson's build definition files (`meson.build`).

Therefore, the core function of this file is likely defining the *structure and allowed parameters* for various build-related functions within the Frida-QML subproject's Meson build setup.

**2. Examining the Code Structure:**

The code consists primarily of `TypedDict` definitions. This immediately signals that the code is about defining data structures with specific types for each key. The comments within each `TypedDict` provide further context, linking them to specific Meson functions (e.g., `add_project_arguments`, `test`, `custom_target`).

**3. Identifying Key Themes and Functionality:**

As I read through the `TypedDict` definitions, several themes emerge:

* **Build Targets:**  Many definitions relate to building executables, libraries (static, shared, modules), and JAR files. Keywords like `sources`, `c_args`, `link_args`, `install_dir` are typical of build system configurations.
* **Testing and Benchmarking:** `FuncTest` and `FuncBenchmark` define parameters for running tests and benchmarks, including success/failure criteria, timeouts, and dependencies.
* **Dependencies:**  `FuncDeclareDependency` and related definitions deal with specifying external libraries and their requirements (compile flags, link flags, include directories).
* **Custom Actions:** `CustomTarget` and `RunTarget` allow defining arbitrary build steps beyond standard compilation and linking.
* **Installation:** Several definitions handle installing built artifacts to specific locations.
* **Project Configuration:**  `Project` defines top-level project settings.
* **Code Generation:** `FuncGenerator` describes how to generate files during the build process.
* **Subprojects:** Definitions for `Subproject` and `DoSubproject` manage the inclusion of other Meson or CMake projects.

**4. Connecting to Reverse Engineering:**

With the understanding that this file defines the build process for Frida-QML, I can start making connections to reverse engineering:

* **Instrumentation:** Frida's core purpose is dynamic instrumentation. The build system defines how the instrumentation agent and related tools are built. The `kwargs.py` defines how to compile and link these components.
* **Targeting Specific Platforms:** Keywords like `native: MachineChoice` indicate the ability to build for different architectures, which is crucial in reverse engineering to target specific devices (e.g., Android, iOS).
* **Injecting Code:** While this file doesn't directly handle the *injection* logic, it defines how the injectable components (e.g., Frida gadgets) are built.
* **Understanding Frida's Architecture:** The presence of `frida-qml` as a subproject suggests a modular architecture, where a UI component is built separately. This is important for understanding Frida's overall structure.

**5. Identifying Low-Level and Kernel Connections:**

Several aspects point to low-level and kernel concerns:

* **`c_args`, `cpp_args`, `link_args`:** These directly control the compiler and linker, which operate at a low level, manipulating object files and executable formats.
* **Shared Libraries (`SharedLibrary`, `SharedModule`):** Building shared libraries is fundamental to dynamic linking, a core concept in operating systems.
* **`install_rpath`:**  This sets the runtime search path for shared libraries, a critical operating system concept.
* **Android (Implied):** While not explicitly mentioned in every definition, the fact that this is part of Frida, and Frida is heavily used on Android, implies that many of these build options are relevant to Android development (e.g., NDK usage, different ABIs).
* **`vs_module_defs`:** This relates to Windows DLL exports, a platform-specific low-level detail.

**6. Imagining User Interactions and Debugging:**

To understand how a user might trigger the use of these definitions, I consider the typical Frida development workflow:

* **Writing a Frida Script:** A user writes JavaScript code to interact with a target process.
* **Building Frida Components (Less Common for End-Users):** While end-users might not directly interact with `meson.build`, developers contributing to Frida would. They might modify these files to add new features, fix bugs, or change build options.
* **Debugging Build Issues:** If there's an error during the Frida build process, understanding these keyword arguments is essential for troubleshooting. For example, an incorrect `link_args` setting could cause linking failures.

**7. Considering Common Errors and Assumptions:**

* **Incorrect Type for Arguments:**  Meson relies on these type definitions. If a user (or developer modifying the `meson.build` file) provides the wrong type for a keyword argument (e.g., a string instead of a list of strings for `sources`), Meson will likely raise an error.
* **Missing Required Arguments:**  The `ExtractRequired` mixin indicates that some arguments are mandatory. Forgetting to provide a required argument will lead to an error.
* **Incorrect File Paths:**  Providing invalid file paths for source files or dependencies is a common build error.
* **Conflicting Options:** Some options might conflict with each other. Meson attempts to detect these conflicts, and these type definitions help in that process.

**8. Iterative Refinement:**

My initial understanding gets refined as I dig deeper into the definitions. For example, seeing the various language-specific argument keywords (`c_args`, `cpp_args`, `rust_args`) reinforces the idea that Meson handles multi-language projects.

By following this thought process, moving from the general context to the specific details of the code, and constantly connecting the code back to the core functionality of Frida and the surrounding build environment, I can arrive at a comprehensive analysis similar to the example provided in the initial prompt.
这个文件 `kwargs.py` 定义了 Frida 动态 instrumentation 工具在构建过程中使用 Meson 构建系统时，各种函数的**关键字参数类型注解**。简单来说，它就像一个蓝图，规定了在 `meson.build` 文件中调用各种 Meson 内置函数或 Frida 自定义函数时，允许使用的关键字参数以及它们的类型。

**功能列举:**

这个文件的主要功能是为 Meson 构建系统中各种函数的关键字参数提供静态类型信息。 这有助于：

1. **提高代码可读性和可维护性:**  通过明确指定参数类型，开发者更容易理解函数期望的输入，减少因参数类型错误导致的 bug。
2. **增强类型检查:**  类型注解可以被 MyPy 等静态类型检查工具使用，在编译之前发现潜在的类型错误。
3. **支持 IDE 的代码补全和提示:**  IDE 可以利用这些类型信息为开发者提供更智能的代码补全和参数提示。
4. **作为 Meson 内部参数处理的规范:**  Meson 解释器可以使用这些定义来验证 `meson.build` 文件中提供的参数是否正确。

**与逆向方法的关系及举例说明:**

虽然这个文件本身不是逆向工具，但它定义了 Frida 构建过程中的参数，而 Frida 本身是一个强大的逆向工具。 理解这些参数可以帮助逆向工程师理解 Frida 是如何被构建和配置的，从而更好地利用 Frida 进行逆向分析。

**举例:**

* **`Executable` 类型:**  定义了构建可执行文件时可以使用的关键字参数，例如 `sources` (源代码文件列表), `c_args` (C 编译器参数), `link_args` (链接器参数) 等。 在逆向过程中，我们可能需要构建自定义的 Frida 客户端或工具，理解这些参数对于正确编译这些工具至关重要。例如，我们可能需要添加特定的链接库 (`link_args`) 来支持某些 Frida 功能。
* **`SharedLibrary` 类型:** 定义了构建共享库时可以使用的参数，如 `soversion` (共享库版本)。 Frida Agent 通常是以共享库的形式注入到目标进程中的。 理解这些参数有助于理解 Frida Agent 的构建方式。
* **`CustomTarget` 类型:**  允许定义自定义的构建目标，执行任意命令。  逆向工程师可能利用这个功能在 Frida 的构建过程中执行一些预处理或后处理脚本，例如，从目标设备的库中提取信息用于后续分析。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个文件虽然是 Python 代码，但它描述的构建过程直接关系到二进制文件的生成和底层系统交互。

**举例:**

* **`c_args`, `cpp_args`, `link_args` 等:**  这些参数直接传递给底层的编译器和链接器 (例如 GCC, Clang, ld)。 逆向工程师需要理解这些编译链接选项才能理解 Frida 组件是如何被编译成机器码的，以及它们在运行时如何与操作系统交互。 例如， `-fPIC` 参数对于构建能在地址空间任意加载的共享库至关重要，这在 Frida Agent 注入过程中是必须的。
* **`install_rpath`:**  这个参数用于设置可执行文件或共享库的运行时库搜索路径。 理解 `rpath` 的工作原理对于理解 Frida 如何找到其依赖的库非常重要，尤其是在不同的 Linux 发行版和 Android 版本中，库的路径可能不同。
* **`win_subsystem` (在 `Executable` 中):**  这个参数在 Windows 平台上指定了可执行文件的子系统 (例如 `windows`, `console`)，这直接影响了程序的运行方式和入口点。
* **构建共享库 (如 `SharedLibrary` 类型):**  共享库是 Linux 和 Android 等操作系统中实现动态链接的关键机制。 Frida Agent 通常以共享库的形式工作。 理解共享库的构建过程和加载机制对于理解 Frida 的工作原理至关重要。
* **Android 特有考虑 (虽然文件中没有显式提及，但 Frida 广泛应用于 Android):** 构建 Frida 用于 Android 可能涉及到 NDK (Native Development Kit) 的使用，以及针对不同 Android ABI (Application Binary Interface) 的编译。 理解这些底层的 Android 构建细节有助于构建能在 Android 设备上运行的 Frida 版本。

**逻辑推理及假设输入与输出:**

这个文件本身主要是类型定义，逻辑推理更多体现在 Meson 构建系统如何使用这些定义。

**假设输入:**  一个 `meson.build` 文件中调用了 `executable()` 函数，并传入了以下关键字参数:

```python
executable(
  'my_frida_tool',
  sources = ['main.c', 'utils.c'],
  c_args = ['-Wall', '-O2'],
  link_args = ['-lpthread']
)
```

**逻辑推理:**

1. Meson 解释器在解析 `executable()` 函数时，会查找 `kwargs.py` 中 `Executable` 类型的定义。
2. 它会检查 `meson.build` 中提供的关键字参数 (`sources`, `c_args`, `link_args`) 是否在 `Executable` 类型的定义中存在。
3. 它会验证这些参数的值类型是否与 `Executable` 类型定义中指定的类型匹配 (例如，`sources` 应该是 `T.List[FileOrString]`)。

**输出:**

* 如果所有参数都正确且类型匹配，Meson 将继续执行构建过程，并将这些参数传递给底层的构建工具 (例如，Ninja)。
* 如果参数名称错误或类型不匹配，Meson 将抛出一个错误，指出 `meson.build` 文件中的问题。

**涉及用户或编程常见的使用错误及举例说明:**

这些类型定义有助于防止用户在编写 `meson.build` 文件时犯常见的错误。

**举例:**

* **错误的参数类型:**  假设用户在 `meson.build` 中错误地将一个字符串传递给了期望文件列表的 `sources` 参数：

   ```python
   executable('my_tool', sources = 'main.c') # 错误：应该是一个列表
   ```

   由于 `Executable` 类型中 `sources` 被定义为 `SourcesVarargsType` (本质上是 `T.List[FileOrString]`)，静态类型检查器或 Meson 解释器会检测到类型错误。

* **使用不存在的关键字参数:** 假设用户错误地使用了 `executable()` 函数不支持的关键字参数：

   ```python
   executable('my_tool', sources = ['main.c'], optimization_level = 2) # 错误：optimization_level 不是有效参数
   ```

   由于 `optimization_level` 没有在 `Executable` 类型中定义，Meson 解释器会报错。

* **忘记必要的参数:** 某些参数可能被标记为 `NotRequired`，意味着它们是可选的。但如果某个重要的参数缺失，可能导致构建失败。虽然 `kwargs.py` 主要关注类型，但它也隐含地定义了哪些参数是合法的。

**用户操作如何一步步到达这里作为调试线索:**

当 Frida 的开发者或者用户尝试修改 Frida 的构建配置时，他们会编辑 `meson.build` 文件。 如果他们在 `meson.build` 文件中使用了错误的关键字参数或者提供了错误类型的参数值，Meson 构建系统在解析 `meson.build` 文件时就会遇到错误。

**调试线索:**

1. **用户编辑 `meson.build` 文件:**  这是错误的起点。用户可能添加、删除或修改了 `meson.build` 文件中的构建目标定义 (例如 `executable()`, `shared_library()`, `custom_target()`).
2. **运行 Meson 构建命令:** 用户通常会运行 `meson setup build` 或 `ninja` 命令来启动构建过程。
3. **Meson 解析 `meson.build`:** Meson 解释器开始读取和解析 `meson.build` 文件。
4. **遇到函数调用:** 当 Meson 解释器遇到像 `executable()` 这样的函数调用时，它会查找该函数的定义以及其期望的关键字参数。
5. **查找 `kwargs.py`:** Meson 解释器会查阅 `kwargs.py` 文件中对应的类型定义 (例如 `Executable` 对应 `executable()` 函数)。
6. **参数类型检查:** Meson 将 `meson.build` 文件中提供的关键字参数与 `kwargs.py` 中定义的类型进行比较。
7. **发现错误:** 如果参数名称不匹配或者参数类型不一致，Meson 会抛出一个错误，指出错误的发生位置和原因。 错误信息可能会指向具体的 `meson.build` 文件行数和错误的参数名称。

通过查看错误信息和 `kwargs.py` 文件中相应的类型定义，开发者可以快速定位 `meson.build` 文件中的问题，例如使用了错误的参数名称或提供了错误的参数类型。 `kwargs.py` 文件就像一个参考手册，帮助理解 Meson 构建系统期望的参数格式。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/kwargs.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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