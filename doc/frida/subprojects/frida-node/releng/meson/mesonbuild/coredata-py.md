Response:
The user wants to understand the functionality of the `coredata.py` file in the Frida project. They are asking for a breakdown of its purpose and how it relates to different aspects of software development and reverse engineering.

**Plan:**

1. **Summarize the core functionality:** Identify the main purpose of the `CoreData` class and its role in the Meson build system.
2. **Relate to reverse engineering:**  Explain how the data stored in `CoreData` could be relevant in a reverse engineering context, focusing on Frida's dynamic instrumentation capabilities.
3. **Connect to low-level concepts:** Detail how the file interacts with operating system specifics like Linux, Android, and binary details.
4. **Identify logical reasoning:** Look for instances where the code makes decisions based on input and provide example inputs and outputs.
5. **Point out common user errors:**  Analyze potential pitfalls users might encounter while interacting with the options managed by this file.
6. **Trace user interaction:** Describe how a user's actions can eventually lead to the execution of this code.
7. **Conclude with a summary:** Reiterate the main functions of the file.
这是 Frida 动态 instrumentation 工具的 `coredata.py` 文件的源代码，它在 Frida 的构建过程中起着核心的数据管理作用。总的来说，这个文件的主要功能是：

**归纳功能：**

1. **存储和管理构建系统的核心配置数据：**  `CoreData` 类是 Meson 构建系统在构建过程中需要持久化保存的关键数据的容器。它类似于 CMake 的缓存，存储了诸如编译器信息、构建选项、依赖项信息等。这些数据需要在多次 Meson 调用之间保持一致。
2. **处理和验证用户提供的构建选项：**  文件中定义了各种 `UserOption` 类（例如 `UserStringOption`, `UserBooleanOption`, `UserComboOption` 等），用于表示不同类型的构建选项。这些类负责验证用户输入的值是否合法，并将其转换为内部表示形式。
3. **管理跨平台构建配置：**  `CoreData` 能够处理交叉编译的配置，包括读取和解析交叉编译定义文件 (`cross_file`)。
4. **缓存编译和运行检查的结果：** 为了提高构建效率，`CoreData` 维护了编译器特性检查 (`compiler_check_cache`) 和运行结果检查 (`run_check_cache`) 的缓存，避免重复执行相同的检查。
5. **管理依赖项信息：** `DependencyCache` 类用于存储和检索已找到的依赖项信息，支持不同类型的依赖项（例如 pkg-config 和 CMake 依赖项）。
6. **管理 CMake 状态缓存：** `CMakeStateCache` 用于缓存内部的 CMake 编译器状态，以减少 CMake 的启动开销。
7. **提供构建选项的视图：** `OptionsView` 类允许以特定的作用域（例如，针对特定的子项目）查看和访问构建选项。

**更详细的功能说明以及与逆向、底层知识、逻辑推理和用户错误的关系：**

2. **与逆向的方法的关系：**

    *   **例子：** 在逆向分析 Frida 本身或使用 Frida 构建工具时，理解 `coredata.py` 中管理的构建选项至关重要。例如，Frida 编译时可能有一些选项控制着注入行为、代码生成或调试信息的包含。逆向工程师可以通过分析这些选项来了解 Frida 的构建方式和潜在的行为特性。
    *   **例子：**  `UserOption` 类中定义的选项，如编译器优化级别、是否启用调试符号等，会直接影响最终生成的 Frida 可执行文件或库的特性。逆向分析时需要考虑这些编译选项的影响。

3. **涉及到二进制底层、Linux、Android 内核及框架的知识：**

    *   **例子：** `default_libdir`, `default_libexecdir` 等变量涉及 Linux 和 Android 等系统的标准目录结构。这些默认路径用于安装编译后的库和可执行文件，理解这些路径对于在目标系统上部署和使用 Frida 非常重要。
    *   **例子：** 交叉编译配置文件 (`cross_file`) 中会定义目标平台的架构、操作系统版本、编译器路径等信息。这些信息与目标平台的底层细节紧密相关，例如 Android 内核版本、ABI 等。
    *   **例子：**  代码中涉及到对不同后端（如 Ninja、Visual Studio、Xcode）的支持，这意味着 `CoreData` 需要处理与不同构建系统相关的配置和路径，这些构建系统最终会生成底层的二进制代码。

4. **逻辑推理：**

    *   **假设输入：** 用户在配置 Frida 构建时，通过命令行指定了 `--buildtype=debug`。
    *   **输出：** `CoreData` 会将 `buildtype` 选项的值设置为 "debug"，并且可能会影响其他相关选项，例如编译器优化级别会降低，调试符号会被启用。在后续的编译过程中，Meson 会根据这个选项来调用相应的编译器和链接器参数。
    *   **假设输入：**  用户指定了 `--cross-file my_android_config.ini`。
    *   **输出：** `CoreData.__load_config_files` 函数会解析 `my_android_config.ini` 文件，提取目标 Android 平台的配置信息，并存储在 `self.cross_files` 中。后续的构建过程会根据这些信息配置交叉编译器和构建环境。

5. **涉及用户或者编程常见的使用错误：**

    *   **例子：** 用户在设置字符串类型的选项时，错误地传入了数字或布尔值，例如 `--prefix=123`。`UserStringOption.validate_value` 方法会抛出 `MesonException` 异常，提示用户输入的值不是字符串类型。
    *   **例子：** 用户在设置枚举类型的选项时，输入了不在允许列表中的值，例如 `--backend=ant`，而 `backendlist` 中没有 "ant"。`UserComboOption.validate_value` 方法会抛出异常，指出可能的选项。
    *   **例子：** 用户指定的交叉编译配置文件路径不存在或不是有效的文件。`CoreData.__load_config_files` 会捕获 `FileNotFoundError` 或相关异常，并抛出 `MesonException`，提示用户指定的文件不存在。

6. **说明用户操作是如何一步步的到达这里，作为调试线索：**

    1. **用户执行 `meson setup <build_directory>` 命令：**  这是配置 Meson 构建系统的第一步。
    2. **Meson 解析命令行参数：** Meson 会解析用户在命令行中提供的选项，例如 `--prefix`, `--buildtype`, `--cross-file` 等。
    3. **创建 `CoreData` 实例：** Meson 初始化构建系统时，会创建 `CoreData` 的实例，并将解析到的命令行选项传递给它。
    4. **加载配置文件：** `CoreData.__load_config_files` 函数会被调用，用于加载 `cross_file` 和 `native_file` 等配置文件。
    5. **初始化内置选项：** `CoreData.init_builtins` 函数会被调用，初始化 Meson 的内置选项，并根据加载的配置文件和命令行参数更新选项的值。
    6. **验证和存储选项：** `UserOption` 类的 `validate_value` 方法会被调用，用于验证用户提供的选项值是否合法。合法的选项值会被存储在 `CoreData.options` 字典中。

    **调试线索：**  如果在构建过程中出现配置相关的问题，例如提示找不到编译器、依赖项或者选项值不合法，可以检查用户在 `meson setup` 命令中提供的选项，以及相关的配置文件 (`cross_file`, `native_file`) 是否正确。`CoreData` 的初始化过程是处理这些配置信息的关键阶段。

总之，`coredata.py` 文件是 Frida 构建系统的核心组成部分，负责管理和维护构建过程中的关键配置数据，处理用户提供的选项，并提供缓存机制以提高构建效率。理解这个文件的功能有助于理解 Frida 的构建过程和配置方式。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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
"""


```