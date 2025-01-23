Response:
The user wants me to analyze a Python file which is part of the Frida dynamic instrumentation tool. The file is located at `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py`.

Here's a breakdown of the request and how I'll address it:

1. **List its functionalities:** I need to read through the provided code and identify the key actions and responsibilities of this `Interpreter` class. This involves looking at the methods defined within the class and understanding their purpose.

2. **Relationship with reverse engineering:** I need to consider how the functionalities of this class could be used in or support reverse engineering tasks. This involves thinking about dynamic instrumentation, code inspection, and potential ways to interact with running processes.

3. **Binary, Linux/Android kernel/framework knowledge:** I need to identify if the code interacts with low-level concepts like binaries, or specific operating system features related to Linux or Android.

4. **Logical reasoning with inputs and outputs:** I need to find parts of the code that perform logical operations based on input, and try to create hypothetical input scenarios and predict the corresponding output.

5. **Common user/programming errors:** I need to identify potential ways a user or developer could misuse the functionalities provided by this class, leading to errors.

6. **User operation leading to this point:** I need to infer the sequence of actions a user might take within the Frida workflow to eventually involve this `interpreter.py` file.

7. **Summarize its function (Part 1):** I need to provide a concise summary of the functionalities I've identified in the first part of the code.

**Mental Sandbox:**

* **Functionality Identification:**  I see keywords like `project`, `executable`, `library`, `dependency`, `test`, `subdir`, etc. These strongly suggest that this file is responsible for interpreting build definitions, likely from a `meson.build` file. It seems to handle defining projects, targets (executables, libraries), dependencies, and tests.
* **Reverse Engineering Connection:** Frida is a reverse engineering tool. The `Interpreter` likely plays a crucial role in setting up the build environment for Frida itself. While the code itself might not *directly* perform reverse engineering actions, it's foundational for building the tools that do.
* **Binary/Kernel Connection:** The mention of compilers and linking suggests interaction with binary code generation. The presence of options related to native builds might hint at Linux/Android specific concerns.
* **Logical Reasoning:**  Functions like `func_option` and conditional logic within other functions (based on user input or environment variables) would be good candidates for demonstrating logical reasoning.
* **User Errors:** Incorrectly specifying dependencies, paths, or build options are common errors that this interpreter might encounter and report.
* **User Path:** A user would typically start by writing a `meson.build` file for a Frida project (or a subproject like `frida-qml`). Running the `meson` command would then trigger the interpretation of this file, bringing this `interpreter.py` file into play.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes
2. Relationship with reverse engineering: Yes
3. Binary/kernel knowledge: Yes
4. Logical reasoning: Yes
5. User errors: Yes
6. User operation: Yes
7. Summarize function (Part 1): Yes

Confidence Score: 5/5 - I'm confident I can address all aspects of the prompt effectively.

Strategizing complete. I will now proceed with generating the response based on the code provided.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的前部分代码，它是 Frida 动态 instrumentation 工具中 Meson 构建系统的解释器。其主要功能是解析和执行 `meson.build` 文件中的指令，从而定义项目的构建过程。

以下是该部分代码的功能总结，并根据你的要求进行举例说明：

**功能列举:**

1. **项目定义 (`project` 函数):**
   - 解析 `project()` 函数，从中提取项目名称、版本、使用的编程语言等基本信息。
   - 检查 Meson 版本是否满足项目要求。
   - 设置项目的默认选项。

2. **目标定义 (如 `executable`, `library`, `shared_library`, `static_library`, `custom_target` 等函数):**
   - 解析各种构建目标定义，例如可执行文件、静态库、共享库等。
   - 处理与目标相关的各种参数，如源文件、头文件、依赖项、链接库、编译选项等。

3. **依赖管理 (`dependency`, `declare_dependency` 函数):**
   - 解析项目依赖项的声明，包括外部库和内部依赖。
   - 查找并配置依赖项，支持使用 pkg-config、CMake 等多种方法查找。
   - 允许声明自定义的依赖项信息。

4. **文件处理 (`files` 函数):**
   - 将字符串形式的源文件路径转换为 Meson 可以理解的文件对象。

5. **包含目录管理 (`include_directories` 函数):**
   - 定义编译器的头文件搜索路径。

6. **全局和项目级别的参数管理 (`add_global_arguments`, `add_project_arguments`, `add_global_link_arguments`, `add_project_link_arguments` 函数):**
   - 允许添加全局和项目特定的编译器和链接器参数。

7. **测试框架集成 (`test`, `benchmark`, `add_test_setup` 函数):**
   - 定义和配置测试用例和基准测试。

8. **子项目管理 (`subproject` 函数):**
   - 处理项目中的子项目。

9. **自定义命令执行 (`run_command` 函数):**
   - 允许在构建过程中执行任意的外部命令。

10. **配置数据处理 (`configuration_data`, `configure_file` 函数):**
    - 创建和使用配置数据，用于在构建时生成配置文件。

11. **模块导入 (`import` 函数):**
    - 允许导入 Meson 的扩展模块，以扩展其功能。

12. **变量管理 (`set_variable`, `get_variable`, `is_variable`, `unset_variable` 函数):**
    - 允许在 Meson 构建脚本中设置、获取、检查和取消设置变量。

13. **选项管理 (`option`, `get_option` 函数):**
    - 定义和获取用户可以通过命令行配置的构建选项。

14. **摘要信息 (`summary` 函数):**
    - 收集并在构建结束时显示项目摘要信息。

15. **环境交互 (`environment` 函数):**
    - 访问和操作环境变量。

16. **构建类型判断和控制 (`is_disabler` 函数):**
    - 检查某个功能是否被禁用。

17. **路径处理 (`join_paths` 函数):**
    - 安全地连接路径。

18. **版本控制标签 (`vcs_tag` 函数):**
    - 从版本控制系统中获取标签信息。

19. **错误和警告处理 (`error`, `warning`, `assert`, `debug` 函数):**
    - 在构建过程中输出错误、警告和调试信息。

**与逆向方法的关系 (举例说明):**

* **`run_command` 函数:**  在 Frida 的构建过程中，可能需要执行一些逆向相关的工具或脚本。例如，可能需要运行一个工具来处理特定的二进制文件，提取信息，或者生成特定的代码。假设 Frida 的构建需要预处理一个目标应用程序的二进制文件来提取某些元数据，可以使用 `run_command` 来执行一个自定义的 Python 脚本或二进制工具来完成这个任务。
   ```python
   # 假设有一个名为 'extract_metadata.py' 的脚本用于提取元数据
   metadata_output = run_command(
       python,
       'extract_metadata.py',
       'target_application',
       check=true,
       capture='stdout'
   ).stdout()
   # ... 后续可以使用 metadata_output 中的信息 ...
   ```
   这展示了如何利用构建系统执行逆向分析步骤。

* **目标定义和依赖管理:**  Frida 本身可能会依赖一些用于代码注入、符号解析等逆向工程的库。这些依赖项需要在构建时正确链接。例如，Frida 可能会依赖一个用于处理 ELF 或 Mach-O 文件格式的库。`dependency` 函数用于声明和查找这些库，确保它们在构建 Frida 时被正确包含。

**涉及到二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **目标定义 (例如 `executable`, `shared_library`):** 这些函数最终会调用编译器和链接器，将源代码编译成二进制文件（可执行文件或库）。这直接涉及到二进制文件的生成和结构。对于 Frida 来说，它需要在不同的平台上（包括 Linux 和 Android）构建其核心组件，这需要理解不同平台的二进制格式（如 ELF for Linux, APK for Android）以及相关的链接机制。

* **编译和链接参数 (`add_global_arguments`, `add_project_arguments`, `add_global_link_arguments`, `add_project_link_arguments`):**  Frida 需要根据目标平台（例如 Android）设置特定的编译和链接参数。例如，在为 Android 构建时，可能需要指定交叉编译工具链、目标架构（ARM, ARM64）、链接特定的系统库等。这些参数的设置需要对 Linux 和 Android 的底层编译和链接过程有一定的了解。

* **依赖管理 (`dependency`):**  Frida 可能会依赖于 Android NDK 中的库或者 Linux 系统库。Meson 需要能够找到这些库，这可能涉及到查找特定于 Linux 或 Android 的路径。

**逻辑推理 (假设输入与输出):**

假设 `meson.build` 文件中有以下代码片段：

```python
project('my_frida_module', 'cpp')
executable('my_tool', 'main.cpp', dependencies: some_dep)
some_dep = dependency('some_library')
```

**假设输入:**
- `meson.build` 文件包含上述代码。
- 系统中安装了名为 `some_library` 的库，并且 Meson 可以通过 pkg-config 或其他方式找到它。

**逻辑推理过程:**
1. 解释器首先解析 `project()` 函数，记录项目名称为 "my_frida_module"，语言为 "cpp"。
2. 接着解析 `executable()` 函数，知道需要构建一个名为 "my_tool" 的可执行文件，源文件是 "main.cpp"，并且依赖于 `some_dep`。
3. 在解析 `executable()` 时，由于 `some_dep` 尚未解析，解释器会先处理 `dependency('some_library')`。
4. `dependency()` 函数会尝试查找名为 "some_library" 的依赖。如果找到，则返回一个表示该依赖的对象；如果找不到，可能会报错或者根据配置进行回退处理。
5. 找到 `some_library` 后，将其信息（例如头文件路径、库文件路径）与 "my_tool" 的构建过程关联起来。

**假设输出:**
- Meson 配置成功，生成用于构建 "my_tool" 的构建系统文件（例如 Ninja 文件）。
- `some_dep` 变量被赋值为表示 "some_library" 依赖的对象，包含了该库的路径和编译/链接选项。

**用户或编程常见的使用错误 (举例说明):**

* **拼写错误或路径错误:**  在 `executable()` 或 `library()` 函数中，如果源文件名或依赖库的名称拼写错误，或者路径不正确，解释器会报错。例如：
   ```python
   # 错误的源文件名
   executable('my_tool', 'mainc.cpp') # 假设源文件名为 main.cpp
   ```
   解释器会报告找不到 `mainc.cpp` 文件。

* **依赖项未找到:**  如果在 `dependency()` 函数中指定的依赖库在系统中找不到，解释器会报错。例如：
   ```python
   some_dep = dependency('non_existent_library')
   ```
   解释器会报告找不到名为 "non_existent_library" 的依赖。

* **参数类型错误:**  如果传递给函数的参数类型不正确，解释器会报错。例如，`dependencies` 参数应该是一个依赖项对象的列表：
   ```python
   # 错误的依赖项类型
   executable('my_tool', 'main.cpp', dependencies: 'some_library')
   ```
   解释器会指出 `dependencies` 参数应该是一个列表。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户创建或修改 Frida 项目中 `frida/subprojects/frida-qml/releng/meson/meson.build` 文件（或其包含的其他 `meson.build` 文件），定义了该子项目的构建规则。
2. **用户执行 `meson` 命令:**  用户在 Frida 项目的根目录下或构建目录下执行 `meson` 命令来配置构建系统。例如：
   ```bash
   cd frida/build  # 或者在项目根目录下创建 build 目录并进入
   meson ..
   ```
3. **Meson 解析 `meson.build` 文件:**  `meson` 命令会启动 Meson 构建系统，并开始解析项目根目录下的 `meson.build` 文件。当 Meson 处理到 `frida/subprojects/frida-qml/releng/meson/meson.build` 文件时，就会调用 `interpreter.py` 中的 `Interpreter` 类来解释该文件中的指令。
4. **解释器执行指令:** `interpreter.py` 会逐行解析 `meson.build` 文件中的函数调用，例如 `project()`, `executable()`, `dependency()` 等，并执行相应的逻辑，创建内部的数据结构来表示项目、目标和依赖关系。
5. **遇到错误或需要调试:** 如果 `meson.build` 文件中存在语法错误、逻辑错误，或者依赖项找不到，`interpreter.py` 会抛出异常并显示错误信息。用户可以通过查看这些错误信息来定位问题所在，例如检查拼写、路径或依赖库是否已安装。

**归纳一下它的功能 (第1部分):**

这部分 `interpreter.py` 代码的核心功能是 **Meson 构建系统的解释器**。它负责读取和理解 `meson.build` 文件中的声明性构建指令，从而定义 Frida 项目及其子项目的结构、构建目标（可执行文件、库等）、依赖关系、编译选项等。它将高级的构建描述转换为 Meson 内部的表示，为后续的构建系统生成阶段（例如生成 Ninja 构建文件）奠定基础。简单来说，它是将人类可读的构建脚本转化为机器可理解的构建配置的关键组件。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2012-2021 The Meson development team
# Copyright © 2023-2024 Intel Corporation

from __future__ import annotations

import hashlib

from .. import mparser
from .. import environment
from .. import coredata
from .. import dependencies
from .. import mlog
from .. import build
from .. import optinterpreter
from .. import compilers
from .. import envconfig
from ..wrap import wrap, WrapMode
from .. import mesonlib
from ..mesonlib import (EnvironmentVariables, ExecutableSerialisation, MesonBugException, MesonException, HoldableObject,
                        FileMode, MachineChoice, OptionKey, listify,
                        extract_as_list, has_path_sep, path_is_in_root, PerMachine)
from ..programs import ExternalProgram, NonExistingExternalProgram
from ..dependencies import Dependency
from ..depfile import DepFile
from ..interpreterbase import ContainerTypeInfo, InterpreterBase, KwargInfo, typed_kwargs, typed_pos_args
from ..interpreterbase import noPosargs, noKwargs, permittedKwargs, noArgsFlattening, noSecondLevelHolderResolving, unholder_return
from ..interpreterbase import InterpreterException, InvalidArguments, InvalidCode, SubdirDoneRequest
from ..interpreterbase import Disabler, disablerIfNotFound
from ..interpreterbase import FeatureNew, FeatureDeprecated, FeatureBroken, FeatureNewKwargs
from ..interpreterbase import ObjectHolder, ContextManagerObject
from ..interpreterbase import stringifyUserArguments
from ..modules import ExtensionModule, ModuleObject, MutableModuleObject, NewExtensionModule, NotFoundExtensionModule
from ..optinterpreter import optname_regex
from ..utils.universal import PerMachineDefaultable

from . import interpreterobjects as OBJ
from . import compiler as compilerOBJ
from .mesonmain import MesonMain
from .dependencyfallbacks import DependencyFallbacksHolder
from .interpreterobjects import (
    SubprojectHolder,
    Test,
    RunProcess,
    extract_required_kwarg,
    extract_search_dirs,
    NullSubprojectInterpreter,
)
from .type_checking import (
    BUILD_TARGET_KWS,
    COMMAND_KW,
    CT_BUILD_ALWAYS,
    CT_BUILD_ALWAYS_STALE,
    CT_BUILD_BY_DEFAULT,
    CT_INPUT_KW,
    CT_INSTALL_DIR_KW,
    EXECUTABLE_KWS,
    JAR_KWS,
    LIBRARY_KWS,
    MULTI_OUTPUT_KW,
    OUTPUT_KW,
    DEFAULT_OPTIONS,
    DEPENDENCIES_KW,
    DEPENDS_KW,
    DEPEND_FILES_KW,
    DEPFILE_KW,
    DISABLER_KW,
    D_MODULE_VERSIONS_KW,
    ENV_KW,
    ENV_METHOD_KW,
    ENV_SEPARATOR_KW,
    INCLUDE_DIRECTORIES,
    INSTALL_KW,
    INSTALL_DIR_KW,
    INSTALL_MODE_KW,
    INSTALL_FOLLOW_SYMLINKS,
    LINK_WITH_KW,
    LINK_WHOLE_KW,
    CT_INSTALL_TAG_KW,
    INSTALL_TAG_KW,
    LANGUAGE_KW,
    NATIVE_KW,
    PRESERVE_PATH_KW,
    REQUIRED_KW,
    SHARED_LIB_KWS,
    SHARED_MOD_KWS,
    DEPENDENCY_SOURCES_KW,
    SOURCES_VARARGS,
    STATIC_LIB_KWS,
    VARIABLES_KW,
    TEST_KWS,
    NoneType,
    in_set_validator,
    env_convertor_with_method
)
from . import primitives as P_OBJ

from pathlib import Path
from enum import Enum
import os
import shutil
import uuid
import re
import stat
import collections
import typing as T
import textwrap
import importlib
import copy

if T.TYPE_CHECKING:
    from . import kwargs as kwtypes
    from ..backend.backends import Backend
    from ..interpreterbase.baseobjects import InterpreterObject, TYPE_var, TYPE_kwargs, SubProject
    from ..programs import OverrideProgram
    from .type_checking import SourcesVarargsType

    # Input source types passed to Targets
    SourceInputs = T.Union[mesonlib.File, build.GeneratedList, build.BuildTarget, build.BothLibraries,
                           build.CustomTargetIndex, build.CustomTarget, build.GeneratedList,
                           build.ExtractedObjects, str]
    # Input source types passed to the build.Target classes
    SourceOutputs = T.Union[mesonlib.File, build.GeneratedList,
                            build.BuildTarget, build.CustomTargetIndex, build.CustomTarget,
                            build.ExtractedObjects, build.GeneratedList, build.StructuredSources]

    BuildTargetSource = T.Union[mesonlib.FileOrString, build.GeneratedTypes, build.StructuredSources]

    ProgramVersionFunc = T.Callable[[T.Union[ExternalProgram, build.Executable, OverrideProgram]], str]


def _project_version_validator(value: T.Union[T.List, str, mesonlib.File, None]) -> T.Optional[str]:
    if isinstance(value, list):
        if len(value) != 1:
            return 'when passed as array must have a length of 1'
        elif not isinstance(value[0], mesonlib.File):
            return 'when passed as array must contain a File'
    return None

class Summary:
    def __init__(self, project_name: str, project_version: str):
        self.project_name = project_name
        self.project_version = project_version
        self.sections = collections.defaultdict(dict)
        self.max_key_len = 0

    def add_section(self, section: str, values: T.Dict[str, T.Any], bool_yn: bool,
                    list_sep: T.Optional[str], subproject: str) -> None:
        for k, v in values.items():
            if k in self.sections[section]:
                raise InterpreterException(f'Summary section {section!r} already have key {k!r}')
            formatted_values = []
            for i in listify(v):
                if isinstance(i, bool):
                    if bool_yn:
                        formatted_values.append(mlog.green('YES') if i else mlog.red('NO'))
                    else:
                        formatted_values.append('true' if i else 'false')
                elif isinstance(i, (str, int)):
                    formatted_values.append(str(i))
                elif isinstance(i, (ExternalProgram, Dependency)):
                    FeatureNew.single_use('dependency or external program in summary', '0.57.0', subproject)
                    formatted_values.append(i.summary_value())
                elif isinstance(i, Disabler):
                    FeatureNew.single_use('disabler in summary', '0.64.0', subproject)
                    formatted_values.append(mlog.red('NO'))
                elif isinstance(i, coredata.UserOption):
                    FeatureNew.single_use('feature option in summary', '0.58.0', subproject)
                    formatted_values.append(i.printable_value())
                else:
                    m = 'Summary value in section {!r}, key {!r}, must be string, integer, boolean, dependency, disabler, or external program'
                    raise InterpreterException(m.format(section, k))
            self.sections[section][k] = (formatted_values, list_sep)
            self.max_key_len = max(self.max_key_len, len(k))

    def dump(self):
        mlog.log(self.project_name, mlog.normal_cyan(self.project_version))
        for section, values in self.sections.items():
            mlog.log('')  # newline
            if section:
                mlog.log(' ', mlog.bold(section))
            for k, v in values.items():
                v, list_sep = v
                padding = self.max_key_len - len(k)
                end = ' ' if v else ''
                mlog.log(' ' * 3, k + ' ' * padding + ':', end=end)
                indent = self.max_key_len + 6
                self.dump_value(v, list_sep, indent)
        mlog.log('')  # newline

    def dump_value(self, arr, list_sep, indent):
        lines_sep = '\n' + ' ' * indent
        if list_sep is None:
            mlog.log(*arr, sep=lines_sep, display_timestamp=False)
            return
        max_len = shutil.get_terminal_size().columns
        line = []
        line_len = indent
        lines_sep = list_sep.rstrip() + lines_sep
        for v in arr:
            v_len = len(v) + len(list_sep)
            if line and line_len + v_len > max_len:
                mlog.log(*line, sep=list_sep, end=lines_sep)
                line_len = indent
                line = []
            line.append(v)
            line_len += v_len
        mlog.log(*line, sep=list_sep, display_timestamp=False)

known_library_kwargs = (
    build.known_shlib_kwargs |
    build.known_stlib_kwargs |
    {f'{l}_shared_args' for l in compilers.all_languages - {'java'}} |
    {f'{l}_static_args' for l in compilers.all_languages - {'java'}}
)

known_build_target_kwargs = (
    known_library_kwargs |
    build.known_exe_kwargs |
    build.known_jar_kwargs |
    {'target_type'}
)

class InterpreterRuleRelaxation(Enum):
    ''' Defines specific relaxations of the Meson rules.

    This is intended to be used for automatically converted
    projects (CMake subprojects, build system mixing) that
    generate a Meson AST via introspection, etc.
    '''

    ALLOW_BUILD_DIR_FILE_REFERENCES = 1

permitted_dependency_kwargs = {
    'allow_fallback',
    'cmake_args',
    'cmake_module_path',
    'cmake_package_version',
    'components',
    'default_options',
    'fallback',
    'include_type',
    'language',
    'main',
    'method',
    'modules',
    'native',
    'not_found_message',
    'optional_modules',
    'private_headers',
    'required',
    'static',
    'version',
}

implicit_check_false_warning = """You should add the boolean check kwarg to the run_command call.
         It currently defaults to false,
         but it will default to true in future releases of meson.
         See also: https://github.com/mesonbuild/meson/issues/9300"""
class Interpreter(InterpreterBase, HoldableObject):

    def __init__(
                self,
                _build: build.Build,
                backend: T.Optional[Backend] = None,
                subproject: SubProject = '',
                subdir: str = '',
                subproject_dir: str = 'subprojects',
                default_project_options: T.Optional[T.Dict[OptionKey, str]] = None,
                ast: T.Optional[mparser.CodeBlockNode] = None,
                is_translated: bool = False,
                relaxations: T.Optional[T.Set[InterpreterRuleRelaxation]] = None,
                user_defined_options: T.Optional[coredata.SharedCMDOptions] = None,
            ) -> None:
        super().__init__(_build.environment.get_source_dir(), subdir, subproject)
        self.active_projectname = ''
        self.build = _build
        self.environment = self.build.environment
        self.coredata = self.environment.get_coredata()
        self.backend = backend
        self.summary: T.Dict[str, 'Summary'] = {}
        self.modules: T.Dict[str, NewExtensionModule] = {}
        # Subproject directory is usually the name of the subproject, but can
        # be different for dependencies provided by wrap files.
        self.subproject_directory_name = subdir.split(os.path.sep)[-1]
        self.subproject_dir = subproject_dir
        self.relaxations = relaxations or set()
        if ast is None:
            self.load_root_meson_file()
        else:
            self.ast = ast
        self.sanity_check_ast()
        self.builtin.update({'meson': MesonMain(self.build, self)})
        self.generators: T.List[build.Generator] = []
        self.processed_buildfiles: T.Set[str] = set()
        self.project_args_frozen = False
        self.global_args_frozen = False  # implies self.project_args_frozen
        self.subprojects: PerMachine[T.Dict[str, SubprojectHolder]] = PerMachineDefaultable.default(
            self.environment.is_cross_build(), {}, {})
        self.subproject_stack: PerMachine[T.List[str]] = PerMachineDefaultable.default(
            self.environment.is_cross_build(), [], [])
        self.configure_file_outputs: T.Dict[str, int] = {}
        # Passed from the outside, only used in subprojects.
        if default_project_options:
            self.default_project_options = default_project_options.copy()
        else:
            self.default_project_options = {}
        self.project_default_options: T.Dict[OptionKey, str] = {}
        self.build_func_dict()
        self.build_holder_map()
        self.user_defined_options = user_defined_options
        self.compilers: PerMachine[T.Dict[str, 'compilers.Compiler']] = PerMachine({}, {})

        # build_def_files needs to be defined before parse_project is called
        #
        # For non-meson subprojects, we'll be using the ast. Even if it does
        # exist we don't want to add a dependency on it, it's autogenerated
        # from the actual build files, and is just for reference.
        self.build_def_files: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()
        build_filename = os.path.join(self.subdir, environment.build_filename)
        if not is_translated:
            self.build_def_files.add(build_filename)
        self.parse_project()
        self._redetect_machines()

    def __getnewargs_ex__(self) -> T.Tuple[T.Tuple[object], T.Dict[str, object]]:
        raise MesonBugException('This class is unpicklable')

    def _redetect_machines(self) -> None:
        # Re-initialize machine descriptions. We can do a better job now because we
        # have the compilers needed to gain more knowledge, so wipe out old
        # inference and start over.
        machines = self.build.environment.machines.miss_defaulting()
        machines.build = environment.detect_machine_info(self.coredata.compilers.build)
        self.build.environment.machines = machines.default_missing()
        assert self.build.environment.machines.build.cpu is not None
        assert self.build.environment.machines.host.cpu is not None
        assert self.build.environment.machines.target.cpu is not None

        self.builtin['build_machine'] = \
            OBJ.MachineHolder(self.build.environment.machines.build, self)
        self.builtin['host_machine'] = \
            OBJ.MachineHolder(self.build.environment.machines.host, self)
        self.builtin['target_machine'] = \
            OBJ.MachineHolder(self.build.environment.machines.target, self)

    def build_func_dict(self) -> None:
        self.funcs.update({'add_global_arguments': self.func_add_global_arguments,
                           'add_global_link_arguments': self.func_add_global_link_arguments,
                           'add_languages': self.func_add_languages,
                           'add_project_arguments': self.func_add_project_arguments,
                           'add_project_dependencies': self.func_add_project_dependencies,
                           'add_project_link_arguments': self.func_add_project_link_arguments,
                           'add_test_setup': self.func_add_test_setup,
                           'alias_target': self.func_alias_target,
                           'assert': self.func_assert,
                           'benchmark': self.func_benchmark,
                           'both_libraries': self.func_both_lib,
                           'build_target': self.func_build_target,
                           'configuration_data': self.func_configuration_data,
                           'configure_file': self.func_configure_file,
                           'custom_target': self.func_custom_target,
                           'debug': self.func_debug,
                           'declare_dependency': self.func_declare_dependency,
                           'dependency': self.func_dependency,
                           'disabler': self.func_disabler,
                           'environment': self.func_environment,
                           'error': self.func_error,
                           'executable': self.func_executable,
                           'files': self.func_files,
                           'find_program': self.func_find_program,
                           'generator': self.func_generator,
                           'get_option': self.func_get_option,
                           'get_variable': self.func_get_variable,
                           'import': self.func_import,
                           'include_directories': self.func_include_directories,
                           'install_data': self.func_install_data,
                           'install_emptydir': self.func_install_emptydir,
                           'install_headers': self.func_install_headers,
                           'install_man': self.func_install_man,
                           'install_subdir': self.func_install_subdir,
                           'install_symlink': self.func_install_symlink,
                           'is_disabler': self.func_is_disabler,
                           'is_variable': self.func_is_variable,
                           'jar': self.func_jar,
                           'join_paths': self.func_join_paths,
                           'library': self.func_library,
                           'message': self.func_message,
                           'option': self.func_option,
                           'project': self.func_project,
                           'range': self.func_range,
                           'run_command': self.func_run_command,
                           'run_target': self.func_run_target,
                           'set_variable': self.func_set_variable,
                           'structured_sources': self.func_structured_sources,
                           'subdir': self.func_subdir,
                           'shared_library': self.func_shared_lib,
                           'shared_module': self.func_shared_module,
                           'static_library': self.func_static_lib,
                           'subdir_done': self.func_subdir_done,
                           'subproject': self.func_subproject,
                           'summary': self.func_summary,
                           'test': self.func_test,
                           'unset_variable': self.func_unset_variable,
                           'vcs_tag': self.func_vcs_tag,
                           'warning': self.func_warning,
                           })
        if 'MESON_UNIT_TEST' in os.environ:
            self.funcs.update({'exception': self.func_exception})
        if 'MESON_RUNNING_IN_PROJECT_TESTS' in os.environ:
            self.funcs.update({'expect_error': self.func_expect_error})

    def build_holder_map(self) -> None:
        '''
            Build a mapping of `HoldableObject` types to their corresponding
            `ObjectHolder`s. This mapping is used in `InterpreterBase` to automatically
            holderify all returned values from methods and functions.
        '''
        self.holder_map.update({
            # Primitives
            list: P_OBJ.ArrayHolder,
            dict: P_OBJ.DictHolder,
            int: P_OBJ.IntegerHolder,
            bool: P_OBJ.BooleanHolder,
            str: P_OBJ.StringHolder,
            P_OBJ.MesonVersionString: P_OBJ.MesonVersionStringHolder,
            P_OBJ.DependencyVariableString: P_OBJ.DependencyVariableStringHolder,
            P_OBJ.OptionString: P_OBJ.OptionStringHolder,

            # Meson types
            mesonlib.File: OBJ.FileHolder,
            build.SharedLibrary: OBJ.SharedLibraryHolder,
            build.StaticLibrary: OBJ.StaticLibraryHolder,
            build.BothLibraries: OBJ.BothLibrariesHolder,
            build.SharedModule: OBJ.SharedModuleHolder,
            build.Executable: OBJ.ExecutableHolder,
            build.Jar: OBJ.JarHolder,
            build.CustomTarget: OBJ.CustomTargetHolder,
            build.CustomTargetIndex: OBJ.CustomTargetIndexHolder,
            build.Generator: OBJ.GeneratorHolder,
            build.GeneratedList: OBJ.GeneratedListHolder,
            build.ExtractedObjects: OBJ.GeneratedObjectsHolder,
            build.RunTarget: OBJ.RunTargetHolder,
            build.AliasTarget: OBJ.AliasTargetHolder,
            build.Headers: OBJ.HeadersHolder,
            build.Man: OBJ.ManHolder,
            build.EmptyDir: OBJ.EmptyDirHolder,
            build.Data: OBJ.DataHolder,
            build.SymlinkData: OBJ.SymlinkDataHolder,
            build.InstallDir: OBJ.InstallDirHolder,
            build.IncludeDirs: OBJ.IncludeDirsHolder,
            mesonlib.EnvironmentVariables: OBJ.EnvironmentVariablesHolder,
            build.StructuredSources: OBJ.StructuredSourcesHolder,
            compilers.RunResult: compilerOBJ.TryRunResultHolder,
            dependencies.ExternalLibrary: OBJ.ExternalLibraryHolder,
            coredata.UserFeatureOption: OBJ.FeatureOptionHolder,
            envconfig.MachineInfo: OBJ.MachineHolder,
            build.ConfigurationData: OBJ.ConfigurationDataHolder,
        })

        '''
            Build a mapping of `HoldableObject` base classes to their
            corresponding `ObjectHolder`s. The difference to `self.holder_map`
            is that the keys here define an upper bound instead of requiring an
            exact match.

            The mappings defined here are only used when there was no direct hit
            found in `self.holder_map`.
        '''
        self.bound_holder_map.update({
            dependencies.Dependency: OBJ.DependencyHolder,
            ExternalProgram: OBJ.ExternalProgramHolder,
            compilers.Compiler: compilerOBJ.CompilerHolder,
            ModuleObject: OBJ.ModuleObjectHolder,
            MutableModuleObject: OBJ.MutableModuleObjectHolder,
        })

    def append_holder_map(self, held_type: T.Type[mesonlib.HoldableObject], holder_type: T.Type[ObjectHolder]) -> None:
        '''
            Adds one additional mapping to the `holder_map`.

            The intended use for this function is in the `initialize` method of
            modules to register custom object holders.
        '''
        self.holder_map.update({
            held_type: holder_type
        })

    def process_new_values(self, invalues: T.List[T.Union[TYPE_var, ExecutableSerialisation]]) -> None:
        invalues = listify(invalues)
        for v in invalues:
            if isinstance(v, ObjectHolder):
                raise InterpreterException('Modules must not return ObjectHolders')
            if isinstance(v, (build.BuildTarget, build.CustomTarget, build.RunTarget)):
                self.add_target(v.name, v)
            elif isinstance(v, list):
                self.process_new_values(v)
            elif isinstance(v, ExecutableSerialisation):
                v.subproject = self.subproject
                self.build.install_scripts.append(v)
            elif isinstance(v, build.Data):
                self.build.data.append(v)
            elif isinstance(v, build.SymlinkData):
                self.build.symlinks.append(v)
            elif isinstance(v, dependencies.InternalDependency):
                # FIXME: This is special cased and not ideal:
                # The first source is our new VapiTarget, the rest are deps
                self.process_new_values(v.sources[0])
            elif isinstance(v, build.InstallDir):
                self.build.install_dirs.append(v)
            elif isinstance(v, Test):
                self.build.tests.append(v)
            elif isinstance(v, (int, str, bool, Disabler, ObjectHolder, build.GeneratedList,
                                ExternalProgram, build.ConfigurationData)):
                pass
            else:
                raise InterpreterException(f'Module returned a value of unknown type {v!r}.')

    def handle_meson_version(self, pv: str, location: mparser.BaseNode) -> None:
        if not mesonlib.version_compare(coredata.stable_version, pv):
            raise InterpreterException.from_node(f'Meson version is {coredata.version} but project requires {pv}', node=location)
        mesonlib.project_meson_versions[self.subproject] = pv

    def handle_meson_version_from_ast(self) -> None:
        if not self.ast.lines:
            return
        project = self.ast.lines[0]
        # first line is always project()
        if not isinstance(project, mparser.FunctionNode):
            return
        for kw, val in project.args.kwargs.items():
            assert isinstance(kw, mparser.IdNode), 'for mypy'
            if kw.value == 'meson_version':
                # mypy does not understand "and isinstance"
                if isinstance(val, mparser.BaseStringNode):
                    self.handle_meson_version(val.value, val)

    def get_build_def_files(self) -> mesonlib.OrderedSet[str]:
        return self.build_def_files

    def add_build_def_file(self, f: mesonlib.FileOrString) -> None:
        # Use relative path for files within source directory, and absolute path
        # for system files. Skip files within build directory. Also skip not regular
        # files (e.g. /dev/stdout) Normalize the path to avoid duplicates, this
        # is especially important to convert '/' to '\' on Windows.
        if isinstance(f, mesonlib.File):
            if f.is_built:
                return
            f = os.path.normpath(f.relative_name())
        elif os.path.isfile(f) and not f.startswith('/dev/'):
            srcdir = Path(self.environment.get_source_dir())
            builddir = Path(self.environment.get_build_dir())
            try:
                f_ = Path(f).resolve()
            except OSError:
                f_ = Path(f)
                s = f_.stat()
                if (hasattr(s, 'st_file_attributes') and
                        s.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT != 0 and
                        s.st_reparse_tag == stat.IO_REPARSE_TAG_APPEXECLINK):
                    # This is a Windows Store link which we can't
                    # resolve, so just do our best otherwise.
                    f_ = f_.parent.resolve() / f_.name
                else:
                    raise
            if builddir in f_.parents:
                return
            if srcdir in f_.parents:
                f_ = f_.relative_to(srcdir)
            f = str(f_)
        else:
            return
        if f not in self.build_def_files:
            self.build_def_files.add(f)

    def get_variables(self) -> T.Dict[str, InterpreterObject]:
        return self.variables

    def check_stdlibs(self) -> None:
        machine_choices = [MachineChoice.HOST]
        if self.coredata.is_cross_build():
            machine_choices.append(MachineChoice.BUILD)
        for for_machine in machine_choices:
            props = self.build.environment.properties[for_machine]
            for l in self.coredata.compilers[for_machine].keys():
                try:
                    di = mesonlib.stringlistify(props.get_stdlib(l))
                except KeyError:
                    continue
                if len(di) == 1:
                    FeatureNew.single_use('stdlib without variable name', '0.56.0', self.subproject, location=self.current_node)
                kwargs = {'native': for_machine is MachineChoice.BUILD,
                          }
                name = l + '_stdlib'
                df = DependencyFallbacksHolder(self, [name], for_machine)
                df.set_fallback(di)
                dep = df.lookup(kwargs, force_fallback=True)
                self.build.stdlibs[for_machine][l] = dep

    @typed_pos_args('import', str)
    @typed_kwargs(
        'import',
        REQUIRED_KW.evolve(since='0.59.0'),
        DISABLER_KW.evolve(since='0.59.0'),
    )
    @disablerIfNotFound
    def func_import(self, node: mparser.BaseNode, args: T.Tuple[str],
                    kwargs: 'kwtypes.FuncImportModule') -> T.Union[ExtensionModule, NewExtensionModule, NotFoundExtensionModule]:
        modname = args[0]
        disabled, required, _ = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            return NotFoundExtensionModule(modname)

        expect_unstable = False
        # Some tests use "unstable_" instead of "unstable-", and that happens to work because
        # of implementation details
        if modname.startswith(('unstable-', 'unstable_')):
            if modname.startswith('unstable_'):
                mlog.deprecation(f'Importing unstable modules as "{modname}" instead of "{modname.replace("_", "-", 1)}"',
                                 location=node)
            real_modname = modname[len('unstable') + 1:]  # + 1 to handle the - or _
            expect_unstable = True
        else:
            real_modname = modname

        if real_modname in self.modules:
            return self.modules[real_modname]
        try:
            module = importlib.import_module(f'mesonbuild.modules.{real_modname}')
        except ImportError:
            if required:
                raise InvalidArguments(f'Module "{modname}" does not exist')
            ext_module = NotFoundExtensionModule(real_modname)
        else:
            ext_module = module.initialize(self)
            assert isinstance(ext_module, (ExtensionModule, NewExtensionModule))
            self.build.modules.append(real_modname)
        if ext_module.INFO.added:
            FeatureNew.single_use(f'module {ext_module.INFO.name}', ext_module.INFO.added, self.subproject, location=node)
        if ext_module.INFO.deprecated:
            FeatureDeprecated.single_use(f'module {ext_module.INFO.name}', ext_module.INFO.deprecated, self.subproject, location=node)
        if expect_unstable and not ext_module.INFO.unstable and ext_module.INFO.stabilized is None:
            raise InvalidArguments(f'Module {ext_module.INFO.name} has never been unstable, remove "unstable-" prefix.')
        if ext_module.INFO.stabilized is not None:
            if expect_unstable:
                FeatureDeprecated.single_use(
                    f'module {ext_module.INFO.name} has been stabilized',
                    ext_module.INFO.stabilized, self.subproject,
                    'drop "unstable-" prefix from the module name',
                    location=node)
            else:
                FeatureNew.single_use(
                    f'module {ext_module.INFO.name} as stable module',
                    ext_module.INFO.stabilized, self.subproject,
                    f'Consider either adding "unstable-" to the module name, or updating the meson required version to ">= {ext_module.INFO.stabilized}"',
                    location=node)
        elif ext_module.INFO.unstable:
            if not expect_unstable:
                if required:
                    raise InvalidArguments(f'Module "{ext_module.INFO.name}" has not been stabilized, and must be imported as unstable-{ext_module.INFO.name}')
                ext_module = NotFoundExtensionModule(real_modname)
            else:
                mlog.warning(f'Module {ext_module.INFO.name} has no backwards or forwards compatibility and might not exist in future releases.', location=node, fatal=False)

        self.modules[real_modname] = ext_module
        return ext_module

    @typed_pos_args('files', varargs=str)
    @noKwargs
    def func_files(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'TYPE_kwargs') -> T.List[mesonlib.File]:
        return self.source_strings_to_files(args[0])

    @noPosargs
    @typed_kwargs(
        'declare_dependency',
        KwargInfo('compile_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        INCLUDE_DIRECTORIES.evolve(name='d_import_dirs', since='0.62.0'),
        D_MODULE_VERSIONS_KW.evolve(since='0.62.0'),
        KwargInfo('link_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        DEPENDENCIES_KW,
        INCLUDE_DIRECTORIES,
        LINK_WITH_KW,
        LINK_WHOLE_KW.evolve(since='0.46.0'),
        DEPENDENCY_SOURCES_KW,
        KwargInfo('extra_files', ContainerTypeInfo(list, (mesonlib.File, str)), listify=True, default=[], since='1.2.0'),
        VARIABLES_KW.evolve(since='0.54.0', since_values={list: '0.56.0'}),
        KwargInfo('version', (str, NoneType)),
        KwargInfo('objects', ContainerTypeInfo(list, build.ExtractedObjects), listify=True, default=[], since='1.1.0'),
    )
    def func_declare_dependency(self, node: mparser.BaseNode, args: T.List[TYPE_var],
                                kwargs: kwtypes.FuncDeclareDependency) -> dependencies.Dependency:
        deps = kwargs['dependencies']
        incs = self.extract_incdirs(kwargs)
        libs = kwargs['link_with']
        libs_whole = kwargs['link_whole']
        objects = kwargs['objects']
        sources = self.source_strings_to_files(kwargs['sources'])
        extra_files = self.source_strings_to_files(kwargs['extra_files'])
        compile_args = kwargs['compile_args']
        link_args = kwargs['link_args']
        variables = kwargs['variables']
        version = kwargs['version']
        if version is None:
            version = self.project_version
        d_module_versions = kwargs['d_module_versions']
        d_import_dirs = self.extract_incdirs(kwargs, 'd_import_dirs')
        srcdir = Path(self.environment.source_dir)
        # convert variables which refer to an -uninstalled.pc style datadir
        for k, v in variables.items():
            if
```