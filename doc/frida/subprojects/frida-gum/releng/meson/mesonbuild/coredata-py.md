Response:
The user wants to understand the functionality of the `coredata.py` file in the Frida project. I need to analyze the code and identify its main purposes and how it relates to reverse engineering, binary manipulation, operating system concepts, logical reasoning, and common user errors.

**Plan:**

1. **Identify Core Functionality:**  Read through the code to understand the main classes and their responsibilities. Focus on what data is stored and how it's used.
2. **Relate to Reverse Engineering:**  Consider how the stored information or the file's functionality might be used in the context of dynamic instrumentation and reverse engineering.
3. **Identify OS/Kernel Concepts:** Look for references to operating system concepts like paths, directories, and potentially interaction with the underlying system.
4. **Find Logical Reasoning:** Analyze code that involves conditional logic, data validation, or decision-making processes. Identify potential inputs and outputs.
5. **Pinpoint User Errors:** Look for validation logic or areas where incorrect user input could cause issues.
6. **Trace User Interaction:**  Infer how a user's actions might lead to this file being executed or its data being accessed, especially within the context of debugging.
7. **Summarize Functionality:** Condense the findings into a concise summary.
好的，根据您提供的 `frida/subprojects/frida-gum/releng/meson/mesonbuild/coredata.py` 文件的源代码，我来归纳一下它的功能：

**核心功能：持久化构建配置数据**

这个 `coredata.py` 文件的主要目的是定义和管理 Frida 动态插桩工具在构建过程中需要持久化存储的核心数据。  这些数据需要在多次 Meson 构建调用之间保持一致，以便 Meson 能够跟踪构建状态、配置选项、依赖关系等信息。  `CoreData` 类是这个文件的核心，它包含了所有需要持久化的信息。

**具体功能点：**

1. **存储构建配置选项 (Options):**
    *   定义了各种类型的用户可配置选项 (例如：字符串、布尔值、整数、枚举、数组、特性开关、标准版本等)，通过 `UserOption` 及其子类实现。
    *   存储了用户通过命令行或配置文件设置的选项值。
    *   处理选项值的验证、转换和默认值。
    *   支持子项目特定的选项配置。

2. **管理编译器信息 (Compilers):**
    *   存储了用于构建项目的编译器信息，包括不同编程语言的编译器。
    *   区分构建机器 (build machine) 和宿主机 (host machine) 的编译器配置。

3. **缓存依赖关系信息 (Dependencies):**
    *   维护了一个依赖项缓存 (`DependencyCache`)，用于存储已找到的依赖项信息，避免重复搜索。
    *   区分构建机器和宿主机的依赖项。
    *   支持不同类型的依赖查找机制 (例如：Pkg-config, CMake)。

4. **缓存编译器检查结果 (Compiler Check Cache):**
    *   缓存了编译器特性检查的结果 (`compiler_check_cache`)，以加速后续构建，避免重复进行相同的编译器检查。
    *   缓存了运行检查的结果 (`run_check_cache`)。

5. **缓存 CMake 状态 (CMake State Cache):**
    *   维护了一个 CMake 状态缓存 (`CMakeStateCache`)，用于存储 CMake 编译器的内部状态，以减少 CMake 的启动开销。

6. **存储构建过程中的唯一标识符 (GUIDs):**
    *   存储了用于不同构建阶段的唯一标识符 (例如：测试、重新生成、安装)。
    *   存储了目标 (target) 的 GUID。

7. **记录 Meson 命令:**
    *   存储了用于启动 Meson 的完整命令，用于跟踪构建环境。

8. **处理交叉编译配置 (Cross Compilation):**
    *   存储了交叉编译配置文件路径 (`cross_files`)。
    *   区分构建机器和宿主机的配置。

9. **版本管理:**
    *   存储了当前 Meson 的版本号。

10. **支持选项视图 (OptionsView):**
    *   提供了一种用于查看和访问选项的机制，可以针对特定的子项目和覆盖进行定制。

**与逆向方法的关联及举例说明：**

虽然这个文件本身不是直接进行逆向操作的代码，但它存储的构建配置信息会影响最终生成的可执行文件和库，从而间接影响逆向分析。

*   **编译选项 (Optimization Levels, Debug Symbols):**  用户可以通过 Meson 的选项配置（例如 `buildtype`）来控制编译器的优化级别和是否包含调试符号。
    *   **例子：** 如果构建时设置了 `buildtype=debug`，编译器会生成包含调试符号的二进制文件，这使得逆向工程师可以使用调试器（如 GDB 或 LLDB）进行单步调试和查看变量值，从而更容易理解程序的执行流程。相反，`buildtype=release` 会启用优化，移除调试符号，增加逆向难度。
*   **代码生成选项 (Architecture, Instruction Set):** 交叉编译配置文件会指定目标平台的架构和指令集。
    *   **例子：**  在进行 Android 平台的逆向分析时，可能需要先使用 Meson 配置针对 ARM 架构的交叉编译环境。`coredata.py` 中会记录这个配置，确保构建过程生成的目标二进制文件是 ARM 架构的，可以使用针对 ARM 的反汇编器（如 IDA Pro 或 Ghidra）进行分析。
*   **库的链接方式 (Static vs. Shared):** Meson 允许配置库的链接方式。
    *   **例子：** 如果将一个库静态链接到可执行文件中，那么该库的代码会直接嵌入到可执行文件中。逆向工程师在分析该可执行文件时，可以直接看到库的代码。如果使用动态链接，则需要在运行时加载库，逆向分析时可能需要同时分析主程序和动态链接库。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

*   **二进制底层:**
    *   编译选项直接影响生成的二进制文件的结构和内容（例如，指令的选择、内存布局）。
    *   交叉编译的概念涉及到为不同于当前运行平台的架构生成二进制代码。
*   **Linux:**
    *   文件路径和目录结构 (例如 `libdir`, `bindir`, `prefix`) 是 Linux 系统中常见的概念，用于指定安装路径。
    *   `umask` 选项涉及到 Linux 文件权限管理。
    *   依赖查找可能涉及到 `pkg-config`，这是一个在 Linux 上常用的用于查找库依赖的工具。
*   **Android 内核及框架:**
    *   交叉编译通常用于为 Android 设备构建软件。
    *   构建 Android 库或可执行文件可能需要链接 Android NDK 提供的库。
    *   一些选项可能与 Android 特定的构建设置有关，尽管在这个文件中没有直接体现。

**逻辑推理及假设输入与输出：**

*   **`validate_value` 方法：** 许多 `UserOption` 子类都有 `validate_value` 方法，用于验证用户提供的选项值是否合法。
    *   **假设输入：** 对于 `UserBooleanOption`，输入可能是字符串 `"True"` 或 `"false"`。
    *   **输出：**  `validate_value` 会将其转换为布尔值 `True` 或 `False`。如果输入是其他无法转换为布尔值的字符串，则会抛出 `MesonException`。
*   **`sanitize_prefix` 方法：** 用于清理和验证安装前缀路径。
    *   **假设输入：** 用户提供的 `prefix` 可能是相对路径 `"./install"` 或带有尾部斜杠的绝对路径 `"/opt/frida/"`。
    *   **输出：**  如果输入是相对路径，则会抛出 `MesonException`。如果是绝对路径并带有尾部斜杠，则会移除斜杠，输出 `"/opt/frida"`。

**涉及用户或编程常见的使用错误及举例说明：**

*   **无效的选项值：** 用户可能为某个选项提供了超出其允许范围或类型的错误值。
    *   **例子：**  对于 `UserIntegerOption`，如果选项定义了最小值和最大值，用户提供了超出这个范围的整数，`validate_value` 方法会抛出 `MesonException`。
*   **拼写错误的选项名：** 用户在命令行或配置文件中可能拼错了选项的名称。
    *   **例子：** 如果用户想设置 `buildtype`，但错误地输入了 `buldtype`，Meson 会无法识别该选项。虽然 `coredata.py` 不直接处理这种情况，但选项的定义在这里，错误的输入不会被正确解析。
*   **使用了已弃用的选项：**  某些选项可能已被标记为 `deprecated`。
    *   **例子：**  `UserOption` 类有 `deprecated` 属性，如果用户尝试设置一个已弃用的选项，Meson 可能会发出警告。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户执行 `meson setup` 或 `meson configure` 命令：** 这是启动 Meson 构建系统的入口点。
2. **Meson 解析命令行参数和配置文件：**  Meson 会读取用户提供的选项，包括通过 `--option=value` 传递的命令行参数和 `meson_options.txt` 或 `meson.options` 文件中的配置。
3. **`coredata.py` 被加载和初始化：**  Meson 需要管理构建状态，因此会加载 `coredata.py` 文件并创建 `CoreData` 类的实例。
4. **选项值被存储到 `CoreData` 实例中：**  解析得到的选项值会通过 `CoreData` 实例的 `options` 属性进行存储，并经过 `validate_value` 等方法的验证。
5. **在后续的构建过程中使用 `CoreData` 中的信息：**  当 Meson 执行编译、链接、测试等操作时，会从 `CoreData` 实例中读取配置信息，例如编译器路径、编译选项、依赖项位置等。

**作为调试线索：** 如果构建过程中出现与配置相关的错误，例如使用了错误的编译器、链接了错误的库、或者某些功能未按预期启用，那么检查 `CoreData` 中存储的选项值可能是一个重要的调试线索。可以查看在 `meson setup` 或 `meson configure` 阶段，用户提供的选项是否被正确解析和存储。

**总结 `coredata.py` 的功能:**

`coredata.py` 定义了 Frida 项目中 Meson 构建系统用于持久化存储构建核心配置数据的结构和类。它负责管理用户选项、编译器信息、依赖关系缓存、编译器检查结果等关键信息，确保构建过程的可追溯性和一致性。这个文件是 Meson 构建系统的核心组成部分，对于理解和调试构建过程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2024 The Meson development team
# Copyright © 2023-2024 Intel Corporation

from __future__ import annotations

import copy

from . import mlog, mparser
import pickle, os, uuid
import sys
from itertools import chain
from pathlib import PurePath
from collections import OrderedDict, abc
from dataclasses import dataclass

from .mesonlib import (
    HoldableObject, MesonBugException,
    MesonException, EnvironmentException, MachineChoice, PerMachine,
    PerMachineDefaultable, default_libdir, default_libexecdir,
    default_prefix, default_datadir, default_includedir, default_infodir,
    default_localedir, default_mandir, default_sbindir, default_sysconfdir,
    listify_array_value, OptionKey, OptionType, stringlistify,
    pickle_load
)
from .wrap import WrapMode
import ast
import argparse
import configparser
import enum
import shlex
import typing as T

if T.TYPE_CHECKING:
    from typing_extensions import Protocol

    from . import dependencies
    from .compilers.compilers import Compiler, CompileResult, RunResult, CompileCheckMode
    from .dependencies.detect import TV_DepID
    from .environment import Environment
    from .mesonlib import FileOrString
    from .cmake.traceparser import CMakeCacheEntry
    from .interpreterbase import SubProject

    class SharedCMDOptions(Protocol):

        """Representation of command line options from Meson setup, configure,
        and dist.

        :param projectoptions: The raw list of command line options given
        :param cmd_line_options: command line options parsed into an OptionKey:
            str mapping
        """

        cmd_line_options: T.Dict[OptionKey, str]
        projectoptions: T.List[str]
        cross_file: T.List[str]
        native_file: T.List[str]

    OptionDictType = T.Union[T.Dict[str, 'UserOption[T.Any]'], 'OptionsView']
    MutableKeyedOptionDictType = T.Dict['OptionKey', 'UserOption[T.Any]']
    KeyedOptionDictType = T.Union[MutableKeyedOptionDictType, 'OptionsView']
    CompilerCheckCacheKey = T.Tuple[T.Tuple[str, ...], str, FileOrString, T.Tuple[str, ...], CompileCheckMode]
    # code, args
    RunCheckCacheKey = T.Tuple[str, T.Tuple[str, ...]]

    # typeshed
    StrOrBytesPath = T.Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]

# Check major_versions_differ() if changing versioning scheme.
#
# Pip requires that RCs are named like this: '0.1.0.rc1'
# But the corresponding Git tag needs to be '0.1.0rc1'
version = '1.4.99'

# The next stable version when we are in dev. This is used to allow projects to
# require meson version >=1.2.0 when using 1.1.99. FeatureNew won't warn when
# using a feature introduced in 1.2.0 when using Meson 1.1.99.
stable_version = version
if stable_version.endswith('.99'):
    stable_version_array = stable_version.split('.')
    stable_version_array[-1] = '0'
    stable_version_array[-2] = str(int(stable_version_array[-2]) + 1)
    stable_version = '.'.join(stable_version_array)

backendlist = ['ninja', 'vs', 'vs2010', 'vs2012', 'vs2013', 'vs2015', 'vs2017', 'vs2019', 'vs2022', 'xcode', 'none']
genvslitelist = ['vs2022']
buildtypelist = ['plain', 'debug', 'debugoptimized', 'release', 'minsize', 'custom']

DEFAULT_YIELDING = False

# Can't bind this near the class method it seems, sadly.
_T = T.TypeVar('_T')


def get_genvs_default_buildtype_list() -> list[str]:
    # just debug, debugoptimized, and release for now
    # but this should probably be configurable through some extra option, alongside --genvslite.
    return buildtypelist[1:-2]


class MesonVersionMismatchException(MesonException):
    '''Build directory generated with Meson version is incompatible with current version'''
    def __init__(self, old_version: str, current_version: str, extra_msg: str = '') -> None:
        super().__init__(f'Build directory has been generated with Meson version {old_version}, '
                         f'which is incompatible with the current version {current_version}.'
                         + extra_msg)
        self.old_version = old_version
        self.current_version = current_version


class UserOption(T.Generic[_T], HoldableObject):
    def __init__(self, name: str, description: str, choices: T.Optional[T.Union[str, T.List[_T]]],
                 yielding: bool,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__()
        self.name = name
        self.choices = choices
        self.description = description
        if not isinstance(yielding, bool):
            raise MesonException('Value of "yielding" must be a boolean.')
        self.yielding = yielding
        self.deprecated = deprecated
        self.readonly = False

    def listify(self, value: T.Any) -> T.List[T.Any]:
        return [value]

    def printable_value(self) -> T.Union[str, int, bool, T.List[T.Union[str, int, bool]]]:
        assert isinstance(self.value, (str, int, bool, list))
        return self.value

    # Check that the input is a valid value and return the
    # "cleaned" or "native" version. For example the Boolean
    # option could take the string "true" and return True.
    def validate_value(self, value: T.Any) -> _T:
        raise RuntimeError('Derived option class did not override validate_value.')

    def set_value(self, newvalue: T.Any) -> bool:
        oldvalue = getattr(self, 'value', None)
        self.value = self.validate_value(newvalue)
        return self.value != oldvalue

class UserStringOption(UserOption[str]):
    def __init__(self, name: str, description: str, value: T.Any, yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, None, yielding, deprecated)
        self.set_value(value)

    def validate_value(self, value: T.Any) -> str:
        if not isinstance(value, str):
            raise MesonException(f'The value of option "{self.name}" is "{value}", which is not a string.')
        return value

class UserBooleanOption(UserOption[bool]):
    def __init__(self, name: str, description: str, value: bool, yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, [True, False], yielding, deprecated)
        self.set_value(value)

    def __bool__(self) -> bool:
        return self.value

    def validate_value(self, value: T.Any) -> bool:
        if isinstance(value, bool):
            return value
        if not isinstance(value, str):
            raise MesonException(f'Option "{self.name}" value {value} cannot be converted to a boolean')
        if value.lower() == 'true':
            return True
        if value.lower() == 'false':
            return False
        raise MesonException(f'Option "{self.name}" value {value} is not boolean (true or false).')

class UserIntegerOption(UserOption[int]):
    def __init__(self, name: str, description: str, value: T.Any, yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        min_value, max_value, default_value = value
        self.min_value = min_value
        self.max_value = max_value
        c: T.List[str] = []
        if min_value is not None:
            c.append('>=' + str(min_value))
        if max_value is not None:
            c.append('<=' + str(max_value))
        choices = ', '.join(c)
        super().__init__(name, description, choices, yielding, deprecated)
        self.set_value(default_value)

    def validate_value(self, value: T.Any) -> int:
        if isinstance(value, str):
            value = self.toint(value)
        if not isinstance(value, int):
            raise MesonException(f'Value {value!r} for option "{self.name}" is not an integer.')
        if self.min_value is not None and value < self.min_value:
            raise MesonException(f'Value {value} for option "{self.name}" is less than minimum value {self.min_value}.')
        if self.max_value is not None and value > self.max_value:
            raise MesonException(f'Value {value} for option "{self.name}" is more than maximum value {self.max_value}.')
        return value

    def toint(self, valuestring: str) -> int:
        try:
            return int(valuestring)
        except ValueError:
            raise MesonException(f'Value string "{valuestring}" for option "{self.name}" is not convertible to an integer.')

class OctalInt(int):
    # NinjaBackend.get_user_option_args uses str() to converts it to a command line option
    # UserUmaskOption.toint() uses int(str, 8) to convert it to an integer
    # So we need to use oct instead of dec here if we do not want values to be misinterpreted.
    def __str__(self) -> str:
        return oct(int(self))

class UserUmaskOption(UserIntegerOption, UserOption[T.Union[str, OctalInt]]):
    def __init__(self, name: str, description: str, value: T.Any, yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, (0, 0o777, value), yielding, deprecated)
        self.choices = ['preserve', '0000-0777']

    def printable_value(self) -> str:
        if self.value == 'preserve':
            return self.value
        return format(self.value, '04o')

    def validate_value(self, value: T.Any) -> T.Union[str, OctalInt]:
        if value == 'preserve':
            return 'preserve'
        return OctalInt(super().validate_value(value))

    def toint(self, valuestring: T.Union[str, OctalInt]) -> int:
        try:
            return int(valuestring, 8)
        except ValueError as e:
            raise MesonException(f'Invalid mode for option "{self.name}" {e}')

class UserComboOption(UserOption[str]):
    def __init__(self, name: str, description: str, choices: T.List[str], value: T.Any,
                 yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, choices, yielding, deprecated)
        if not isinstance(self.choices, list):
            raise MesonException(f'Combo choices for option "{self.name}" must be an array.')
        for i in self.choices:
            if not isinstance(i, str):
                raise MesonException(f'Combo choice elements for option "{self.name}" must be strings.')
        self.set_value(value)

    def validate_value(self, value: T.Any) -> str:
        if value not in self.choices:
            if isinstance(value, bool):
                _type = 'boolean'
            elif isinstance(value, (int, float)):
                _type = 'number'
            else:
                _type = 'string'
            optionsstring = ', '.join([f'"{item}"' for item in self.choices])
            raise MesonException('Value "{}" (of type "{}") for option "{}" is not one of the choices.'
                                 ' Possible choices are (as string): {}.'.format(
                                     value, _type, self.name, optionsstring))
        return value

class UserArrayOption(UserOption[T.List[str]]):
    def __init__(self, name: str, description: str, value: T.Union[str, T.List[str]],
                 split_args: bool = False,
                 allow_dups: bool = False, yielding: bool = DEFAULT_YIELDING,
                 choices: T.Optional[T.List[str]] = None,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, choices if choices is not None else [], yielding, deprecated)
        self.split_args = split_args
        self.allow_dups = allow_dups
        self.set_value(value)

    def listify(self, value: T.Any) -> T.List[T.Any]:
        try:
            return listify_array_value(value, self.split_args)
        except MesonException as e:
            raise MesonException(f'error in option "{self.name}": {e!s}')

    def validate_value(self, value: T.Union[str, T.List[str]]) -> T.List[str]:
        newvalue = self.listify(value)

        if not self.allow_dups and len(set(newvalue)) != len(newvalue):
            msg = 'Duplicated values in array option is deprecated. ' \
                  'This will become a hard error in the future.'
            mlog.deprecation(msg)
        for i in newvalue:
            if not isinstance(i, str):
                raise MesonException(f'String array element "{newvalue!s}" for option "{self.name}" is not a string.')
        if self.choices:
            bad = [x for x in newvalue if x not in self.choices]
            if bad:
                raise MesonException('Value{} "{}" for option "{}" {} not in allowed choices: "{}"'.format(
                    '' if len(bad) == 1 else 's',
                    ', '.join(bad),
                    self.name,
                    'is' if len(bad) == 1 else 'are',
                    ', '.join(self.choices))
                )
        return newvalue

    def extend_value(self, value: T.Union[str, T.List[str]]) -> None:
        """Extend the value with an additional value."""
        new = self.validate_value(value)
        self.set_value(self.value + new)


class UserFeatureOption(UserComboOption):
    static_choices = ['enabled', 'disabled', 'auto']

    def __init__(self, name: str, description: str, value: T.Any, yielding: bool = DEFAULT_YIELDING,
                 deprecated: T.Union[bool, str, T.Dict[str, str], T.List[str]] = False):
        super().__init__(name, description, self.static_choices, value, yielding, deprecated)
        self.name: T.Optional[str] = None  # TODO: Refactor options to all store their name

    def is_enabled(self) -> bool:
        return self.value == 'enabled'

    def is_disabled(self) -> bool:
        return self.value == 'disabled'

    def is_auto(self) -> bool:
        return self.value == 'auto'

class UserStdOption(UserComboOption):
    '''
    UserOption specific to c_std and cpp_std options. User can set a list of
    STDs in preference order and it selects the first one supported by current
    compiler.

    For historical reasons, some compilers (msvc) allowed setting a GNU std and
    silently fell back to C std. This is now deprecated. Projects that support
    both GNU and MSVC compilers should set e.g. c_std=gnu11,c11.

    This is not using self.deprecated mechanism we already have for project
    options because we want to print a warning if ALL values are deprecated, not
    if SOME values are deprecated.
    '''
    def __init__(self, lang: str, all_stds: T.List[str]) -> None:
        self.lang = lang.lower()
        self.all_stds = ['none'] + all_stds
        # Map a deprecated std to its replacement. e.g. gnu11 -> c11.
        self.deprecated_stds: T.Dict[str, str] = {}
        opt_name = 'cpp_std' if lang == 'c++' else f'{lang}_std'
        super().__init__(opt_name, f'{lang} language standard to use', ['none'], 'none')

    def set_versions(self, versions: T.List[str], gnu: bool = False, gnu_deprecated: bool = False) -> None:
        assert all(std in self.all_stds for std in versions)
        self.choices += versions
        if gnu:
            gnu_stds_map = {f'gnu{std[1:]}': std for std in versions}
            if gnu_deprecated:
                self.deprecated_stds.update(gnu_stds_map)
            else:
                self.choices += gnu_stds_map.keys()

    def validate_value(self, value: T.Union[str, T.List[str]]) -> str:
        try:
            candidates = listify_array_value(value)
        except MesonException as e:
            raise MesonException(f'error in option "{self.name}": {e!s}')
        unknown = ','.join(std for std in candidates if std not in self.all_stds)
        if unknown:
            raise MesonException(f'Unknown option "{self.name}" value {unknown}. Possible values are {self.all_stds}.')
        # Check first if any of the candidates are not deprecated
        for std in candidates:
            if std in self.choices:
                return std
        # Fallback to a deprecated std if any
        for std in candidates:
            newstd = self.deprecated_stds.get(std)
            if newstd is not None:
                mlog.deprecation(
                    f'None of the values {candidates} are supported by the {self.lang} compiler.\n' +
                    f'However, the deprecated {std} std currently falls back to {newstd}.\n' +
                    'This will be an error in the future.\n' +
                    'If the project supports both GNU and MSVC compilers, a value such as\n' +
                    '"c_std=gnu11,c11" specifies that GNU is preferred but it can safely fallback to plain c11.')
                return newstd
        raise MesonException(f'None of values {candidates} are supported by the {self.lang.upper()} compiler. ' +
                             f'Possible values for option "{self.name}" are {self.choices}')

@dataclass
class OptionsView(abc.Mapping):
    '''A view on an options dictionary for a given subproject and with overrides.
    '''

    # TODO: the typing here could be made more explicit using a TypeDict from
    # python 3.8 or typing_extensions
    options: KeyedOptionDictType
    subproject: T.Optional[str] = None
    overrides: T.Optional[T.Mapping[OptionKey, T.Union[str, int, bool, T.List[str]]]] = None

    def __getitem__(self, key: OptionKey) -> UserOption:
        # FIXME: This is fundamentally the same algorithm than interpreter.get_option_internal().
        # We should try to share the code somehow.
        key = key.evolve(subproject=self.subproject)
        if not key.is_project():
            opt = self.options.get(key)
            if opt is None or opt.yielding:
                opt = self.options[key.as_root()]
        else:
            opt = self.options[key]
            if opt.yielding:
                opt = self.options.get(key.as_root(), opt)
        if self.overrides:
            override_value = self.overrides.get(key.as_root())
            if override_value is not None:
                opt = copy.copy(opt)
                opt.set_value(override_value)
        return opt

    def __iter__(self) -> T.Iterator[OptionKey]:
        return iter(self.options)

    def __len__(self) -> int:
        return len(self.options)

class DependencyCacheType(enum.Enum):

    OTHER = 0
    PKG_CONFIG = 1
    CMAKE = 2

    @classmethod
    def from_type(cls, dep: 'dependencies.Dependency') -> 'DependencyCacheType':
        # As more types gain search overrides they'll need to be added here
        if dep.type_name == 'pkgconfig':
            return cls.PKG_CONFIG
        if dep.type_name == 'cmake':
            return cls.CMAKE
        return cls.OTHER


class DependencySubCache:

    def __init__(self, type_: DependencyCacheType):
        self.types = [type_]
        self.__cache: T.Dict[T.Tuple[str, ...], 'dependencies.Dependency'] = {}

    def __getitem__(self, key: T.Tuple[str, ...]) -> 'dependencies.Dependency':
        return self.__cache[key]

    def __setitem__(self, key: T.Tuple[str, ...], value: 'dependencies.Dependency') -> None:
        self.__cache[key] = value

    def __contains__(self, key: T.Tuple[str, ...]) -> bool:
        return key in self.__cache

    def values(self) -> T.Iterable['dependencies.Dependency']:
        return self.__cache.values()


class DependencyCache:

    """Class that stores a cache of dependencies.

    This class is meant to encapsulate the fact that we need multiple keys to
    successfully lookup by providing a simple get/put interface.
    """

    def __init__(self, builtins: 'KeyedOptionDictType', for_machine: MachineChoice):
        self.__cache: T.MutableMapping[TV_DepID, DependencySubCache] = OrderedDict()
        self.__builtins = builtins
        self.__pkg_conf_key = OptionKey('pkg_config_path', machine=for_machine)
        self.__cmake_key = OptionKey('cmake_prefix_path', machine=for_machine)

    def __calculate_subkey(self, type_: DependencyCacheType) -> T.Tuple[str, ...]:
        data: T.Dict[DependencyCacheType, T.List[str]] = {
            DependencyCacheType.PKG_CONFIG: stringlistify(self.__builtins[self.__pkg_conf_key].value),
            DependencyCacheType.CMAKE: stringlistify(self.__builtins[self.__cmake_key].value),
            DependencyCacheType.OTHER: [],
        }
        assert type_ in data, 'Someone forgot to update subkey calculations for a new type'
        return tuple(data[type_])

    def __iter__(self) -> T.Iterator['TV_DepID']:
        return self.keys()

    def put(self, key: 'TV_DepID', dep: 'dependencies.Dependency') -> None:
        t = DependencyCacheType.from_type(dep)
        if key not in self.__cache:
            self.__cache[key] = DependencySubCache(t)
        subkey = self.__calculate_subkey(t)
        self.__cache[key][subkey] = dep

    def get(self, key: 'TV_DepID') -> T.Optional['dependencies.Dependency']:
        """Get a value from the cache.

        If there is no cache entry then None will be returned.
        """
        try:
            val = self.__cache[key]
        except KeyError:
            return None

        for t in val.types:
            subkey = self.__calculate_subkey(t)
            try:
                return val[subkey]
            except KeyError:
                pass
        return None

    def values(self) -> T.Iterator['dependencies.Dependency']:
        for c in self.__cache.values():
            yield from c.values()

    def keys(self) -> T.Iterator['TV_DepID']:
        return iter(self.__cache.keys())

    def items(self) -> T.Iterator[T.Tuple['TV_DepID', T.List['dependencies.Dependency']]]:
        for k, v in self.__cache.items():
            vs: T.List[dependencies.Dependency] = []
            for t in v.types:
                subkey = self.__calculate_subkey(t)
                if subkey in v:
                    vs.append(v[subkey])
            yield k, vs

    def clear(self) -> None:
        self.__cache.clear()


class CMakeStateCache:
    """Class that stores internal CMake compiler states.

    This cache is used to reduce the startup overhead of CMake by caching
    all internal CMake compiler variables.
    """

    def __init__(self) -> None:
        self.__cache: T.Dict[str, T.Dict[str, T.List[str]]] = {}
        self.cmake_cache: T.Dict[str, 'CMakeCacheEntry'] = {}

    def __iter__(self) -> T.Iterator[T.Tuple[str, T.Dict[str, T.List[str]]]]:
        return iter(self.__cache.items())

    def items(self) -> T.Iterator[T.Tuple[str, T.Dict[str, T.List[str]]]]:
        return iter(self.__cache.items())

    def update(self, language: str, variables: T.Dict[str, T.List[str]]):
        if language not in self.__cache:
            self.__cache[language] = {}
        self.__cache[language].update(variables)

    @property
    def languages(self) -> T.Set[str]:
        return set(self.__cache.keys())


# Can't bind this near the class method it seems, sadly.
_V = T.TypeVar('_V')

# This class contains all data that must persist over multiple
# invocations of Meson. It is roughly the same thing as
# cmakecache.

class CoreData:

    def __init__(self, options: SharedCMDOptions, scratch_dir: str, meson_command: T.List[str]):
        self.lang_guids = {
            'default': '8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942',
            'c': '8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942',
            'cpp': '8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942',
            'test': '3AC096D0-A1C2-E12C-1390-A8335801FDAB',
            'directory': '2150E333-8FDC-42A3-9474-1A3956D46DE8',
        }
        self.test_guid = str(uuid.uuid4()).upper()
        self.regen_guid = str(uuid.uuid4()).upper()
        self.install_guid = str(uuid.uuid4()).upper()
        self.meson_command = meson_command
        self.target_guids = {}
        self.version = version
        self.options: 'MutableKeyedOptionDictType' = {}
        self.is_build_only = False
        self.cross_files = self.__load_config_files(options, scratch_dir, 'cross')
        self.compilers: PerMachine[T.Dict[str, Compiler]] = PerMachine(OrderedDict(), OrderedDict())

        # Stores the (name, hash) of the options file, The name will be either
        # "meson_options.txt" or "meson.options".
        # This is used by mconf to reload the option file if it's changed.
        self.options_files: T.Dict[SubProject, T.Optional[T.Tuple[str, str]]] = {}

        # Set of subprojects that have already been initialized once, this is
        # required to be stored and reloaded with the coredata, as we don't
        # want to overwrite options for such subprojects.
        self.initialized_subprojects: T.Set[str] = set()

        # For host == build configurations these caches should be the same.
        self.deps: PerMachine[DependencyCache] = PerMachineDefaultable.default(
            self.is_cross_build(),
            DependencyCache(self.options, MachineChoice.BUILD),
            DependencyCache(self.options, MachineChoice.HOST))

        self.compiler_check_cache: T.Dict['CompilerCheckCacheKey', 'CompileResult'] = OrderedDict()
        self.run_check_cache: T.Dict['RunCheckCacheKey', 'RunResult'] = OrderedDict()

        # CMake cache
        self.cmake_cache: PerMachine[CMakeStateCache] = PerMachine(CMakeStateCache(), CMakeStateCache())

        # Only to print a warning if it changes between Meson invocations.
        self.config_files = self.__load_config_files(options, scratch_dir, 'native')
        self.builtin_options_libdir_cross_fixup()
        self.init_builtins('')

    def copy_as_build(self) -> CoreData:
        """Create a copy if this coredata, but for the build machine.

        If this is not a cross build, then a reference to self will be returned
        instead.
        """
        if not self.is_cross_build():
            return self

        new = copy.copy(self)
        new.is_build_only = True

        new.options = {}
        new.init_builtins('')
        new.options.update({k: v for k, v in self.options.items()
                            if k.machine is MachineChoice.HOST and not self.is_per_machine_option(k)})
        new.options.update({k.as_host(): v for k, v in self.options.items()
                            if k.machine is MachineChoice.BUILD})
        new.options.update({k: v for k, v in self.options.items()
                            if k.machine is MachineChoice.BUILD})

        # Use only the build deps, not any host ones
        new.deps = PerMachineDefaultable(self.deps.build).default_missing()
        new.compilers = PerMachineDefaultable(self.compilers.build).default_missing()
        new.cmake_cache = PerMachineDefaultable(self.cmake_cache.build).default_missing()

        # Drop any cross files, since this is not a cross compile
        new.cross_files = []

        return new

    def merge(self, other: CoreData) -> None:
        build_only_boundary = not self.is_build_only and other.is_build_only
        if not build_only_boundary:
            return

        self.options.update({k: v for k, v in other.options.items()
                             if k.machine is MachineChoice.HOST and not self.is_per_machine_option(k)})
        self.options.update({k: v for k, v in other.options.items()
                             if k.machine is MachineChoice.BUILD})
        self.options.update({k.as_build(): v for k, v in other.options.items()
                             if k.machine is MachineChoice.HOST and k.subproject and k.is_project()})

    @staticmethod
    def __load_config_files(options: SharedCMDOptions, scratch_dir: str, ftype: str) -> T.List[str]:
        # Need to try and make the passed filenames absolute because when the
        # files are parsed later we'll have chdir()d.
        if ftype == 'cross':
            filenames = options.cross_file
        else:
            filenames = options.native_file

        if not filenames:
            return []

        found_invalid: T.List[str] = []
        missing: T.List[str] = []
        real: T.List[str] = []
        for i, f in enumerate(filenames):
            f = os.path.expanduser(os.path.expandvars(f))
            if os.path.exists(f):
                if os.path.isfile(f):
                    real.append(os.path.abspath(f))
                    continue
                elif os.path.isdir(f):
                    found_invalid.append(os.path.abspath(f))
                else:
                    # in this case we've been passed some kind of pipe, copy
                    # the contents of that file into the meson private (scratch)
                    # directory so that it can be re-read when wiping/reconfiguring
                    copy = os.path.join(scratch_dir, f'{uuid.uuid4()}.{ftype}.ini')
                    with open(f, encoding='utf-8') as rf:
                        with open(copy, 'w', encoding='utf-8') as wf:
                            wf.write(rf.read())
                    real.append(copy)

                    # Also replace the command line argument, as the pipe
                    # probably won't exist on reconfigure
                    filenames[i] = copy
                    continue
            if sys.platform != 'win32':
                paths = [
                    os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share')),
                ] + os.environ.get('XDG_DATA_DIRS', '/usr/local/share:/usr/share').split(':')
                for path in paths:
                    path_to_try = os.path.join(path, 'meson', ftype, f)
                    if os.path.isfile(path_to_try):
                        real.append(path_to_try)
                        break
                else:
                    missing.append(f)
            else:
                missing.append(f)

        if missing:
            if found_invalid:
                mlog.log('Found invalid candidates for', ftype, 'file:', *found_invalid)
            mlog.log('Could not find any valid candidate for', ftype, 'files:', *missing)
            raise MesonException(f'Cannot find specified {ftype} file: {f}')
        return real

    def builtin_options_libdir_cross_fixup(self) -> None:
        # By default set libdir to "lib" when cross compiling since
        # getting the "system default" is always wrong on multiarch
        # platforms as it gets a value like lib/x86_64-linux-gnu.
        if self.cross_files:
            BUILTIN_OPTIONS[OptionKey('libdir')].default = 'lib'

    def sanitize_prefix(self, prefix: str) -> str:
        prefix = os.path.expanduser(prefix)
        if not os.path.isabs(prefix):
            raise MesonException(f'prefix value {prefix!r} must be an absolute path')
        if prefix.endswith('/') or prefix.endswith('\\'):
            # On Windows we need to preserve the trailing slash if the
            # string is of type 'C:\' because 'C:' is not an absolute path.
            if len(prefix) == 3 and prefix[1] == ':':
                pass
            # If prefix is a single character, preserve it since it is
            # the root directory.
            elif len(prefix) == 1:
                pass
            else:
                prefix = prefix[:-1]
        return prefix

    def sanitize_dir_option_value(self, prefix: str, option: OptionKey, value: T.Any) -> T.Any:
        '''
        If the option is an installation directory option, the value is an
        absolute path and resides within prefix, return the value
        as a path relative to the prefix. Otherwise, return it as is.

        This way everyone can do f.ex, get_option('libdir') and usually get
        the library directory relative to prefix, even though it really
        should not be relied upon.
        '''
        try:
            value = PurePath(value)
        except TypeError:
            return value
        if option.name.endswith('dir') and value.is_absolute() and \
           option not in BUILTIN_DIR_NOPREFIX_OPTIONS:
            try:
                # Try to relativize the path.
                value = value.relative_to(prefix)
            except ValueError:
                # Path is not relative, let’s keep it as is.
                pass
            if '..' in value.parts:
                raise MesonException(
                    f'The value of the \'{option}\' option is \'{value}\' but '
                    'directory options are not allowed to contain \'..\'.\n'
                    f'If you need a path outside of the {prefix!r} prefix, '
                    'please use an absolute path.'
                )
        # .as_posix() keeps the posix-like file separators Meson uses.
        return value.as_posix()

    def init_builtins(self, subproject: str) -> None:
        # Create builtin options with default
```