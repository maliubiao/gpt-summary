Response:
The user wants to understand the functionality of the `interpreter.py` file in the Frida dynamic instrumentation tool. They are interested in how it relates to reverse engineering, low-level binary operations, Linux/Android kernel and framework knowledge, logical reasoning, potential user errors, and debugging.

I need to:
1. **Summarize the core functionalities** of the provided code snippet.
2. **Identify connections to reverse engineering techniques** and provide examples.
3. **Pinpoint aspects related to binary operations and Linux/Android internals** with illustrative examples.
4. **Analyze for logical reasoning** and present hypothetical input/output scenarios.
5. **Recognize common usage errors** and demonstrate them.
6. **Explain the user actions** that lead to the execution of this code.
7. **Conclude with a concise summary** of the file's purpose as the first part of a larger analysis.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的前一部分代码，它是 Frida 动态 instrumentation 工具中 Meson 构建系统的解释器。它的主要功能是解析 `meson.build` 文件，并根据其中的指令来配置和生成构建系统。

以下是该文件代码片段的功能归纳：

1. **初始化构建环境**: `Interpreter` 类的 `__init__` 方法负责初始化解释器，包括加载 `meson.build` 文件，设置构建目录、源码目录、子项目信息等。它还创建了内置函数字典 (`self.builtin`) 和可以被解释执行的函数字典 (`self.funcs`)。

2. **解析 `meson.build` 文件**: 解释器会读取并解析 `meson.build` 文件（以及可能存在的子目录中的 `meson.build` 文件），构建抽象语法树 (AST)，并执行其中的函数调用。

3. **提供内置函数**:  该文件定义了大量的内置函数，这些函数对应了 `meson.build` 文件中可以调用的指令。这些函数涵盖了项目定义 (`project`)、目标创建 (`executable`, `library`, `custom_target`)、依赖管理 (`dependency`, `declare_dependency`)、安装规则 (`install_data`, `install_headers`)、测试定义 (`test`)、以及其他构建相关的操作。

4. **管理构建目标**: 解释器负责创建和管理各种构建目标，如可执行文件、静态库、动态库、自定义目标等。它会将这些目标存储在内部数据结构中，以便后续的构建系统生成器使用。

5. **处理依赖关系**:  解释器能够处理项目之间的依赖关系和外部库的依赖关系。它提供了 `dependency` 和 `declare_dependency` 函数来查找或声明依赖项，并将其链接到构建目标。

6. **处理选项和配置**: 解释器允许在 `meson.build` 文件中定义项目选项 (`option`)，并在构建时根据用户提供的选项值进行配置。 `configuration_data` 函数用于创建可以在构建过程中使用的配置数据文件。

7. **支持子项目**: 解释器能够处理子项目 (`subproject`)，允许将大型项目分解为更小的、可管理的模块。

8. **提供模块扩展机制**: 解释器支持通过模块 (`import`) 来扩展其功能，这些模块可以提供额外的函数和对象。

9. **记录构建信息**:  `Summary` 类用于收集和展示构建概要信息，例如项目名称、版本、配置选项等。

10. **管理全局和项目级别的参数**:  `add_global_arguments`, `add_project_arguments`, `add_global_link_arguments`, `add_project_link_arguments` 等函数允许添加编译器和链接器参数。

**与逆向方法的关系及其举例说明：**

* **依赖项分析**:  在逆向工程中，理解目标程序依赖的库是非常重要的。Meson 解释器通过 `dependency` 函数处理依赖项，它可以帮助逆向工程师了解目标程序的构建时依赖了哪些库。例如，如果一个 Frida Gadget 目标使用了 `libssl`，那么在 `meson.build` 文件中可能会有类似 `dependency('openssl')` 的调用，这为逆向分析提供了线索。
* **构建目标类型**:  解释器区分不同类型的构建目标（可执行文件、共享库等）。在逆向工程中，识别目标程序是可执行文件还是共享库是第一步。`executable()` 和 `shared_library()` 函数的使用可以揭示目标的类型。例如，Frida 可能会构建一个动态库作为 Gadget 注入到目标进程中，这可以通过 `shared_library()` 函数创建。
* **自定义构建步骤**: `custom_target` 函数允许定义任意的构建步骤。在逆向工程中，可能需要自定义工具来处理特定的二进制格式或执行特定的预处理。例如，Frida 可能会使用 `custom_target` 来生成一些辅助文件，或者执行代码混淆/解混淆步骤。
* **全局和项目参数**: `add_global_arguments` 和 `add_project_arguments` 可以添加编译参数。逆向工程师可能需要了解目标程序在构建时使用了哪些编译参数，因为这些参数可能会影响程序的行为或安全性。例如，是否启用了符号信息（`-g`）会影响调试难度。

**涉及二进制底层、Linux、Android 内核及框架的知识及其举例说明：**

* **共享库和模块**:  `shared_library` 和 `shared_module` 函数用于构建动态链接库。Frida 本身就是一个动态 instrumentation 框架，其核心组件 `frida-gum` 就是一个共享库。在 Android 上，Frida Gadget 也以共享库的形式注入到目标进程。
* **可执行文件**: `executable` 函数用于构建可执行文件。Frida 包含一些命令行工具，如 `frida`、`frida-ps` 等，这些都是通过 `executable` 函数构建的。
* **编译和链接参数**:  解释器处理编译和链接参数，这些参数直接影响最终生成的二进制文件。例如，`-fPIC` 参数对于构建在 Android 上加载的共享库是必需的。
* **依赖项查找**:  解释器需要知道如何在不同的操作系统和环境下查找依赖库。这涉及到对 Linux 和 Android 文件系统结构的理解，例如常见的库路径 `/lib`, `/usr/lib`, `/system/lib` 等。
* **本机构建 (`native: true`)**:  在交叉编译环境中，解释器需要区分主机构建和目标机构建。对于 Frida 这样的工具，可能需要在主机上构建一些辅助工具。`native: true` 参数用于指定构建目标为在构建机器上运行的程序。

**逻辑推理及其假设输入与输出：**

假设 `meson.build` 文件中包含以下代码：

```python
project('my_frida_module', 'c')
executable('my_tool', 'main.c')
mylib = shared_library('mylib', 'mylib.c')

if get_option('enable_debug'):
    add_project_arguments('-g', language: 'c')

my_option = get_option('my_custom_option')
message('Custom option value:', my_option)
```

* **假设输入**: 用户在配置时设置了 `-Denable_debug=true` 和 `-Dmy_custom_option=hello`。
* **逻辑推理**:
    * 解释器会解析 `project()` 函数，设置项目名称和语言。
    * `executable()` 和 `shared_library()` 函数会被调用，创建相应的构建目标。
    * `get_option('enable_debug')` 会返回 `true`，因为用户设置了该选项。
    * `add_project_arguments('-g', language: 'c')` 会被执行，将 `-g` 添加到 C 代码的编译参数中。
    * `get_option('my_custom_option')` 会返回 'hello'。
    * `message()` 函数会输出 "Custom option value: hello"。
* **假设输出**: 构建系统配置完成后，会包含一个名为 `my_tool` 的可执行文件和一个名为 `mylib` 的共享库。C 代码的编译命令中会包含 `-g` 参数。控制台会输出 "Custom option value: hello"。

**涉及用户或编程常见的使用错误及其举例说明：**

* **类型错误**:  例如，在需要字符串的地方传递了整数。
    ```python
    # 错误：'123' 应该是字符串
    executable('my_tool', 123)
    ```
    解释器会抛出类似 "Invalid arguments for function 'executable': Argument 'sources' has type <class 'int'> but should be <class 'str'>" 的错误。
* **函数参数错误**:  传递了函数不支持的参数或缺少必需的参数。
    ```python
    # 错误：缺少必需的 'sources' 参数
    executable('my_tool')
    ```
    解释器会抛出类似 "Invalid arguments for function 'executable': The following keyword arguments are mandatory: sources" 的错误。
* **作用域错误**:  尝试访问未定义的变量。
    ```python
    if some_condition:
        my_var = 'hello'
    message(my_var) # 如果 some_condition 为假，my_var 未定义
    ```
    解释器在执行到 `message(my_var)` 时，如果 `my_var` 未定义，会抛出错误。
* **选项名称拼写错误**:  在 `get_option()` 中使用了错误的选项名称。
    ```python
    option('my_option', type: 'string', default: 'default_value')
    value = get_option('my_optioon') # 拼写错误
    ```
    这会导致 `get_option()` 返回默认值，或者如果选项是必需的，则可能导致后续逻辑错误。
* **循环依赖**:  在子项目中引入了循环依赖关系，导致构建系统无法完成配置。Meson 会检测到循环依赖并报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户下载或克隆了 Frida 的源代码。**
2. **用户想要构建 Frida，因此进入 Frida 的构建目录，或者执行类似 `meson setup build` 的命令来创建一个构建目录。**
3. **Meson 构建系统开始工作，首先会查找项目根目录下的 `meson.build` 文件。**
4. **Meson 初始化解释器 (`interpreter.py`)，并将 `meson.build` 文件的内容加载到解释器中。**
5. **解释器逐行解析 `meson.build` 文件，执行其中的函数调用。**
6. **当解释器执行到与构建目标、依赖项、选项等相关的函数时，它会调用 `interpreter.py` 中定义的相应函数（例如 `func_executable`, `func_library`, `func_dependency`）。**
7. **如果 `meson.build` 文件中存在语法错误或逻辑错误，解释器会在解析过程中抛出异常，并指出错误的位置，这可以作为调试的线索。**
8. **在调试过程中，用户可能会检查 `meson.build` 文件，查看相关的函数调用和参数是否正确。**
9. **如果涉及到自定义模块，用户可能需要检查对应的模块代码。**
10. **如果构建过程中出现意外行为，理解 `interpreter.py` 的工作原理可以帮助用户理解 Meson 是如何处理 `meson.build` 文件的，从而定位问题。**

**功能归纳（第1部分）：**

这部分 `interpreter.py` 代码主要负责 Meson 构建系统的初始化和 `meson.build` 文件的初步解析。它定义了解释器类和一些基础的数据结构，用于存储构建过程中的信息。核心功能是提供了解释 `meson.build` 文件中声明式指令的基础框架，包括内置函数的定义和执行环境的搭建，为后续构建目标的创建和依赖关系的解析奠定了基础。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
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
"""


```