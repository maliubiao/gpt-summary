Response:
My thought process to arrive at the summary of the `interpreter.py` file went something like this:

1. **Understand the Context:** The prompt clearly states this is a source code file for a dynamic instrumentation tool (Frida), specifically within the Meson build system for the Python bindings. This immediately tells me the file is crucial for interpreting build instructions and managing the build process.

2. **Initial Scan and Keyword Spotting:** I quickly scanned the code, looking for obvious patterns and keywords. I noticed:
    * Imports from `..`:  Indicates interaction with other parts of the Frida build system.
    * Imports from `mesonbuild`:  Confirms this is a Meson interpreter.
    * Function definitions (using `def`): Suggests this file defines a class with methods for handling build logic.
    * Decorators like `@typed_pos_args`, `@typed_kwargs`:  Hints at type checking and argument parsing.
    * Names of common build system concepts: `project`, `executable`, `library`, `dependency`, `test`, `install`, etc.
    * Class `Interpreter`:  This is likely the core class defining the interpreter's functionality.
    * Class `Summary`: Suggests a way to generate build summaries.
    * References to different operating systems and architectures (implicitly through concepts like native builds and cross-compilation).

3. **Focus on the `Interpreter` Class:** The name "Interpreter" is a strong clue. I focused on its `__init__` method to understand its initialization process and key attributes:
    * `build`:  A `build.Build` object – suggests access to the overall build state.
    * `environment`:  An `environment.Environment` object – indicates access to environment details (compiler paths, etc.).
    * `coredata`:  Core build data, likely containing configuration information.
    * `modules`:  A dictionary for managing Meson modules.
    * `funcs`:  A dictionary mapping function names to their implementations. This is a key indicator of the interpreter's capabilities.
    * `holder_map`, `bound_holder_map`:  Relate to how the interpreter handles and wraps different types of objects, important for type safety and object management within the build system.

4. **Analyze Key Methods:** I then examined some of the prominent methods:
    * Methods starting with `func_`: These are the built-in functions exposed within the Meson build scripts. I noted the wide range of functionalities they cover, from defining targets (`executable`, `library`, `custom_target`), managing dependencies (`dependency`, `declare_dependency`), controlling installation (`install_data`, `install_headers`), and more.
    * `process_new_values`:  Indicates how the interpreter handles return values from build functions, processing them and updating the build state.
    * `handle_meson_version`:  Shows it checks for compatibility with required Meson versions.
    * `add_build_def_file`:  Suggests it tracks the files that define the build.
    * `func_import`:  Crucial for extending the interpreter's functionality through modules.

5. **Identify Core Functionalities:** Based on the identified keywords, attributes, and methods, I started grouping the functionalities:
    * **Build Definition Interpretation:** The primary role – processing `meson.build` files and understanding the build structure.
    * **Target Management:** Creating and managing build targets (executables, libraries, etc.).
    * **Dependency Management:** Finding, declaring, and linking against dependencies.
    * **Installation Management:** Defining what gets installed and where.
    * **Module Handling:**  Extending functionality through Meson modules.
    * **Configuration and Options:** Handling project options and configurations.
    * **Project Metadata:** Managing project name, version, and summaries.
    * **Environment Awareness:**  Understanding the build environment (compilers, machine information).
    * **Error Handling and Validation:** Checking for invalid arguments and potential issues.

6. **Connect to Concepts Mentioned in the Prompt:** I then revisited the prompt and explicitly connected the identified functionalities to the concepts mentioned:
    * **Reverse Engineering:**  The ability to define custom targets and run commands is relevant to executing reverse engineering tools.
    * **Binary Layer, Linux, Android Kernel/Framework:**  While not explicitly manipulating bits, the compiler and linker interactions, the concept of shared libraries, and the ability to manage dependencies are all deeply tied to the underlying OS and binary formats. The `find_program` function is relevant for finding system tools.
    * **Logical Reasoning:**  The conditional execution based on options and the processing of dependencies involves logical reasoning within the interpreter. The `assert` function is a direct example.
    * **User Errors:**  The type checking decorators and the exception handling in various functions suggest an effort to catch common user errors.

7. **Structure the Summary:** Finally, I organized my findings into a clear and concise summary, highlighting the key functions and their implications. I made sure to address the specific points raised in the prompt (reverse engineering, binary layer, logical reasoning, user errors). I also noted it was the first part of a larger file, suggesting the functions described are foundational.

By following this process of scanning, focusing, analyzing, connecting, and structuring, I could effectively summarize the functionality of the provided code snippet. The iterative nature of this process allows for refinement and a more complete understanding of the code's purpose.
这是Frida动态仪器工具的源代码文件 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` 的第一部分，主要负责 **解释和执行 Meson 构建定义文件（通常是 `meson.build`）**。它的核心功能是读取并理解用户编写的构建指令，然后将其转换为 Meson 构建系统的内部表示，以便后续的构建过程能够顺利进行。

以下是该部分代码的功能归纳：

**核心解释器功能:**

* **初始化构建环境:**  `Interpreter` 类是核心，它在初始化时加载构建环境信息，包括源代码目录、构建目录、使用的编译器等。
* **解析 Meson 文件:**  读取 `meson.build` 文件，将其解析为抽象语法树 (AST)，并对 AST 进行初步的合法性检查。
* **管理内置函数:**  维护一个字典 `funcs`，存储了 Meson 语言的内置函数及其对应的 Python 实现。这些函数提供了构建系统所需的各种操作，例如添加编译目标、声明依赖项、安装文件等。
* **处理项目定义:**  解析并处理 `project()` 函数，从中获取项目名称、版本等基本信息。
* **处理子项目:**  支持构建子项目，并维护子项目的状态和信息。
* **管理全局和项目级别的参数:**  提供函数来添加全局和项目级别的编译/链接参数。
* **处理模块导入:**  允许导入和使用 Meson 模块以扩展构建功能。
* **管理构建目标:**  提供函数来定义各种构建目标，例如可执行文件、静态库、共享库、自定义目标等。
* **管理依赖项:**  处理项目依赖项，包括查找外部依赖和声明内部依赖。
* **处理安装规则:**  支持定义各种安装规则，例如安装数据文件、头文件、man page 等。
* **提供构建摘要:**  `Summary` 类用于生成构建配置的摘要信息。
* **类型检查和参数验证:**  使用装饰器（如 `@typed_pos_args`, `@typed_kwargs`）进行函数参数的类型检查和验证，以减少用户错误。
* **版本控制:**  处理 `meson_version` 声明，确保项目与 Meson 版本兼容。
* **对象持有和管理:**  使用 `HoldableObject` 和 `ObjectHolder` 机制来管理和传递构建过程中的各种对象。

**与逆向方法的关系举例:**

虽然该文件本身不直接执行逆向操作，但它提供的功能可以用于构建和管理与逆向工程相关的工具和项目。

* **构建逆向工具:**  可以使用 Meson 来构建诸如反汇编器、调试器、动态分析工具等逆向工程工具。例如，可以使用 `executable()` 函数定义一个逆向工具的可执行文件，使用 `dependency()` 函数链接该工具所需的库（如 Capstone, Keystone 等）。
* **Hook 代码的编译和部署:**  在 Frida 的上下文中，可以使用 Meson 来构建和打包需要注入到目标进程中的 Hook 代码（例如，使用 C/C++ 编写的 Gadget）。`custom_target()` 函数可以用于定义编译 Gadget 代码的步骤。
* **构建测试逆向结果的工具:**  可以使用 Meson 来构建用于测试逆向分析结果的工具。例如，可以定义一些测试用例，验证对目标程序 Hook 后的行为是否符合预期。

**涉及到二进制底层，Linux, Android内核及框架的知识举例:**

该文件在处理构建定义时，会涉及到一些与底层系统相关的概念：

* **编译器和链接器参数:**  `add_global_arguments`, `add_project_arguments`, `add_global_link_arguments`, `add_project_link_arguments` 等函数处理编译和链接器参数，这些参数直接影响生成的二进制代码，例如指定架构、优化级别、链接库等。
* **共享库和静态库:**  `shared_library()`, `static_library()` 函数用于定义不同类型的库，这涉及到操作系统加载和链接二进制文件的机制。
* **可执行文件格式:**  `executable()` 函数生成的二进制文件遵循特定的操作系统可执行文件格式（例如 Linux 的 ELF，Windows 的 PE）。
* **依赖项查找:**  `dependency()` 函数需要理解不同操作系统和构建系统中查找依赖库的方式，例如通过 pkg-config、CMake find_package 等。
* **安装路径:**  `install_data()`, `install_headers()` 等函数需要理解不同操作系统下标准的文件安装路径。
* **交叉编译:**  Meson 支持交叉编译，这意味着它需要处理不同目标架构的编译器和链接器。
* **Android 特定的构建:**  虽然代码中没有直接提及 Android 内核，但 Frida 本身常用于 Android 平台的动态分析，因此该解释器需要能够处理构建 Android 平台上的库和可执行文件的需求。这可能涉及到 NDK 的使用、ABI 的选择等。

**逻辑推理的假设输入与输出:**

假设 `meson.build` 文件包含以下内容：

```meson
project('my_reverse_tool', 'cpp')

executable('mytool', 'main.cpp', dependencies: [dependency('capstone')])
```

**假设输入:**

* `meson.build` 文件的内容如上所示。
* 系统已安装 Capstone 库，并且 pkg-config 可以找到它。

**逻辑推理与输出:**

1. **解析 `project()`:** 解释器会解析 `project('my_reverse_tool', 'cpp')`，记录项目名称为 "my_reverse_tool"，编程语言为 "cpp"。
2. **解析 `executable()`:** 解释器会解析 `executable('mytool', 'main.cpp', dependencies: [dependency('capstone')])`，识别出一个名为 "mytool" 的可执行目标，源文件是 "main.cpp"。
3. **解析 `dependency()`:** 解释器会解析 `dependency('capstone')`，尝试查找名为 "capstone" 的依赖项。它可能会使用 pkg-config 来查找 Capstone 库的头文件和链接库路径。
4. **创建构建目标:** 解释器会创建一个内部表示，描述如何构建 "mytool" 可执行文件，包括使用的编译器、源文件、链接的 Capstone 库等信息。

**输出:**

解释器会将构建目标 "mytool" 的信息存储在内部数据结构中，以便后续的构建后端（例如 Ninja）能够生成实际的构建命令。  这包括：

* 可执行文件的名称: "mytool"
* 源文件: `mesonlib.File('main.cpp')` （假设 main.cpp 在当前源目录）
* 依赖项:  `dependencies.PkgConfigDependency` 对象，包含了 Capstone 库的信息（头文件路径、链接库路径等）。

**用户或编程常见的使用错误举例:**

* **拼写错误或不存在的函数名:**  如果在 `meson.build` 中使用了不存在的函数名，例如 `executables(...)` 而不是 `executable(...)`，解释器会抛出 `InvalidCode` 异常。
* **参数类型错误:**  如果某个函数期望一个字符串参数，但用户传递了一个整数，解释器会通过 `@typed_pos_args` 或 `@typed_kwargs` 检测到类型错误并抛出 `InvalidArguments` 异常。例如，如果 `executable()` 函数的第一个参数（目标名称）传递的是一个列表，就会报错。
* **缺少必要的参数:**  有些函数有强制性的参数，如果用户在调用时没有提供，解释器会抛出 `InvalidArguments` 异常。例如，`project()` 函数必须提供项目名称。
* **传递了不允许的关键字参数:**  如果用户在调用函数时传递了函数不支持的关键字参数，解释器会抛出 `InvalidArguments` 异常。
* **文件路径错误:**  如果在 `files()` 函数中指定了不存在的文件路径，或者在 `executable()` 函数中指定的源文件不存在，解释器可能会在后续阶段报错。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:**  用户根据项目需求，编写包含项目定义、构建目标、依赖项等信息的 `meson.build` 文件。
2. **用户运行 `meson` 命令:**  用户在项目根目录下运行 `meson <build_directory>` 命令，指示 Meson 开始构建配置过程。
3. **Meson 加载解释器:**  `meson` 命令会加载并初始化 `interpreter.py` 中的 `Interpreter` 类。
4. **解释器读取 `meson.build`:**  `Interpreter` 类会读取当前目录下的 `meson.build` 文件。
5. **解释器解析 `meson.build`:**  解释器使用内部的解析器将 `meson.build` 的文本内容转换为抽象语法树 (AST)。
6. **解释器执行 AST:**  解释器遍历 AST 的节点，根据不同的节点类型调用相应的 Python 函数（例如 `func_project`, `func_executable`, `func_dependency` 等）。
7. **执行到 `executable()` 函数:**  如果 `meson.build` 文件中包含了 `executable()` 函数的调用，解释器会执行 `Interpreter` 类中的 `func_executable()` 方法。
8. **`func_executable()` 方法执行:**  `func_executable()` 方法会接收用户传递的参数（目标名称、源文件、依赖项等），并进行类型检查和验证。
9. **创建内部目标表示:**  `func_executable()` 方法会创建或更新内部的数据结构，表示待构建的可执行目标。

**调试线索:**

当出现构建问题时，理解用户操作到达 `interpreter.py` 的过程可以帮助调试：

* **检查 `meson.build` 文件:**  确认 `meson.build` 文件的语法是否正确，函数名是否拼写正确，参数类型是否符合预期。
* **查看 Meson 的输出信息:**  Meson 在执行过程中会输出详细的日志信息，可以从中找到解释器执行到哪个函数时出错，以及具体的错误信息。
* **使用断点调试:**  如果需要更深入地了解解释器的执行过程，可以使用 Python 调试器（例如 `pdb`）在 `interpreter.py` 中设置断点，逐步跟踪代码的执行，查看变量的值，理解解释器的内部状态。
* **理解 Meson 的错误提示:**  Meson 的错误提示通常会指出错误的 `meson.build` 行号和相关的函数调用，可以帮助快速定位问题。

**总结:**

`frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的这一部分是 Meson 构建系统的核心组件，负责解析和执行构建定义文件。它提供了丰富的功能来描述项目的构建结构、管理依赖项、定义安装规则等。理解其功能对于编写和维护 Meson 构建文件至关重要，也有助于理解 Frida 项目的构建过程。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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