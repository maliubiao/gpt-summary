Response:
The user wants a summary of the functionality of the provided Python code file, which is part of the Frida dynamic instrumentation tool. The file is located at `frida/releng/meson/mesonbuild/coredata.py`.

Here's a breakdown of the requested information and how to approach it:

1. **List the functionalities:** This requires analyzing the classes, methods, and data structures defined in the code. Key functionalities likely involve managing build configurations, storing project options, handling dependencies, and managing caches.

2. **Relationship to reverse engineering:** Identify parts of the code that might be relevant to reverse engineering, such as handling native libraries, managing compiler settings, and potentially dealing with binary outputs. Provide concrete examples.

3. **Binary, Linux, Android kernel/framework knowledge:** Look for areas where the code interacts with low-level concepts, such as file paths, operating system specifics (like default directories), and cross-compilation.

4. **Logical reasoning (input/output):**  If the code contains functions or methods that perform transformations or decisions based on input, provide examples of how different inputs would lead to specific outputs.

5. **Common user/programming errors:** Identify potential pitfalls for users or developers interacting with this code, such as providing incorrect option values or misconfiguring build settings.

6. **User operation to reach this code:** Describe the steps a user might take when using Frida that would eventually involve this specific file. This is related to the configuration and build process.

7. **Overall summary of functionality:** Provide a concise overview of the file's primary purpose.

**Mental Sandbox Simulation:**

* **Scanning for key classes and data structures:** `CoreData`, `UserOption`, `DependencyCache`, `CMakeStateCache`. These seem central to the file's purpose.
* **Analyzing `CoreData`:** It holds various configuration parameters, compiler information, and caches. This looks like the main data repository for the build process.
* **Examining `UserOption` subclasses:** These define different types of configurable options (string, boolean, integer, etc.). This is how users customize the build.
* **Considering the file path:** `frida/releng/meson/mesonbuild/coredata.py`. The `mesonbuild` directory suggests this is part of the Meson build system integration for Frida's release engineering (`releng`).
* **Thinking about Frida's use case:** Frida is for dynamic instrumentation. This means it needs to be built for various target platforms (potentially involving cross-compilation) and needs to manage dependencies on native libraries.

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes
2. Relationship to reverse engineering: Yes
3. Binary/kernel knowledge: Yes
4. Logical reasoning: Yes
5. User errors: Yes
6. User operation: Yes
7. Summarize functionality: Yes

Confidence Score: 5/5 - The code seems well-structured, and I can infer the functionalities and relate them to the requested areas.

**Strategizing complete.** I will now proceed with generating the response by analyzing the code section by section and addressing each of the user's requests.
这是 frida 动态 Instrumentation 工具的源代码文件 `frida/releng/meson/mesonbuild/coredata.py` 的第一部分。这个文件是 Meson 构建系统中 `coredata` 模块的一部分，负责存储和管理构建过程中的核心数据。以下是根据代码内容对其功能的归纳：

**功能归纳：**

1. **定义核心数据结构 (`CoreData` 类):**  `CoreData` 类是这个文件的核心，它作为一个容器，保存了构建过程中需要持久化的各种重要信息。这包括：
    * 版本信息 (`version`, `stable_version`)
    * 选项配置 (`options`)，包括用户自定义选项和内置选项。
    * 目标 GUID (`target_guids`) 和构建过程 GUID (`regen_guid`, `install_guid`)。
    * 编译器信息 (`compilers`)，区分 build 机器和 host 机器。
    * 依赖信息 (`deps`)，用于缓存已找到的依赖项，同样区分 build 和 host 机器。
    * 编译器检查缓存 (`compiler_check_cache`) 和运行检查缓存 (`run_check_cache`)，用于优化构建速度。
    * CMake 状态缓存 (`cmake_cache`)，用于缓存 CMake 相关信息。
    * 交叉编译配置文件 (`cross_files`) 和原生编译配置文件 (`config_files`)。
    * Meson 命令 (`meson_command`)。
    * 已初始化的子项目 (`initialized_subprojects`)。
    * 选项文件信息 (`options_files`)。

2. **定义用户可配置选项 (`UserOption` 及其子类):** 文件中定义了 `UserOption` 基类以及各种类型的用户选项，例如：
    * `UserStringOption`: 字符串选项。
    * `UserBooleanOption`: 布尔选项。
    * `UserIntegerOption`: 整数选项。
    * `UserUmaskOption`: 用于设置 umask 的特殊整数选项。
    * `UserComboOption`: 枚举值选项。
    * `UserArrayOption`: 字符串数组选项。
    * `UserFeatureOption`: 特性开关选项 (enabled, disabled, auto)。
    * `UserStdOption`:  用于选择 C/C++ 标准的特殊选项。

3. **处理选项视图 (`OptionsView` 类):** `OptionsView` 提供了一种在特定子项目和覆盖设置下查看选项的方式，允许访问和修改选项值。

4. **管理依赖缓存 (`DependencyCache` 类):** `DependencyCache` 用于存储和检索已找到的依赖项。它会根据依赖项的类型（例如，pkg-config, CMake）和配置（例如，`pkg_config_path`, `cmake_prefix_path`）进行组织，以提高查找效率。

5. **管理 CMake 状态缓存 (`CMakeStateCache` 类):** `CMakeStateCache` 用于缓存 CMake 的内部状态，以减少重复调用 CMake 的开销。

6. **加载和处理配置文件:**  代码包含加载交叉编译 (`cross`) 和原生编译 (`native`) 配置文件的逻辑。它会尝试从命令行参数、标准位置或指定的路径加载这些文件。

7. **提供辅助函数:**  例如 `sanitize_prefix` 用于清理 `prefix` 选项的值，确保它是绝对路径。 `builtin_options_libdir_cross_fixup` 用于在交叉编译时调整 `libdir` 的默认值。

**与逆向方法的关系举例:**

* **管理编译选项:**  `CoreData` 存储了影响二进制文件构建方式的各种编译选项，例如优化级别、调试信息开关、目标架构等。在逆向分析时，了解这些编译选项有助于理解二进制文件的特性。例如，如果启用了调试符号 (`debug=true`)，逆向分析师可以获得更多的符号信息，从而更容易理解代码逻辑。
* **处理交叉编译配置:**  Frida 作为一个需要在多种平台上运行的工具，很可能需要进行交叉编译。`CoreData` 中加载和存储的交叉编译配置文件 (`cross_files`) 定义了目标平台的编译器、链接器、库路径等信息。逆向分析在目标平台上运行的 Frida 组件时，理解其构建所使用的交叉编译配置至关重要。
    * **举例:** 如果交叉编译配置文件中指定了目标架构是 `arm64`，那么逆向工程师在分析该平台上的 Frida 组件时，就需要使用针对 `arm64` 架构的反汇编器和调试器。
* **依赖管理:** `DependencyCache` 存储了 Frida 构建时所依赖的外部库的信息。逆向分析时，了解 Frida 的依赖项可以帮助理解其功能，并可能发现潜在的安全漏洞。

**涉及二进制底层、Linux、Android 内核及框架的知识举例:**

* **默认目录配置:** 代码中使用了 `default_libdir`, `default_libexecdir` 等函数来获取不同操作系统下的默认安装目录。这些目录与二进制文件的安装位置息息相关。例如，在 Linux 系统中，共享库通常安装在 `/usr/lib` 或 `/usr/local/lib`，可执行文件安装在 `/usr/bin` 或 `/usr/local/bin`。
* **处理 umask:** `UserUmaskOption` 用于设置文件创建的默认权限掩码。这直接涉及到 Linux 和 Unix-like 系统底层的权限管理。
* **交叉编译:** 整个 `CoreData` 结构中对 build 机器和 host 机器的区分，以及对交叉编译配置文件的处理，都直接关系到在 Linux 和 Android 等平台上进行交叉编译的知识。Android 开发经常涉及到在主机上为 Android 设备构建二进制文件。
* **库路径配置 (`libdir`):** 在交叉编译时，`builtin_options_libdir_cross_fixup` 尝试将 `libdir` 默认设置为 "lib"，这是因为在多架构的 Linux 系统上获取系统默认库路径可能会出错。这反映了对 Linux 系统库组织结构的理解。

**逻辑推理举例 (假设输入与输出):**

假设用户设置了一个名为 `my_feature` 的 Feature Option：

* **假设输入:** 用户在命令行中执行 `meson configure -Dmy_feature=enabled`。
* **输出:**  `CoreData.options` 中会包含一个 `UserFeatureOption` 实例，其 `name` 属性为 `'my_feature'`，`value` 属性为 `'enabled'`。

假设用户设置了一个 Array Option：

* **假设输入:** 用户在 `meson_options.txt` 中定义了 `option('my_array', type : 'array', default : [], description : 'My array option')`，并在命令行中执行 `meson configure -Dmy_array='a,b,c'`。
* **输出:** `CoreData.options` 中会包含一个 `UserArrayOption` 实例，其 `name` 属性为 `'my_array'`，`value` 属性为 `['a', 'b', 'c']`。

**涉及用户或者编程常见的使用错误举例:**

* **选项值类型错误:** 用户尝试为 `UserIntegerOption` 提供一个字符串值，例如 `meson configure -Dmy_int_option=abc`。这会导致 `validate_value` 方法抛出 `MesonException`，提示用户输入的值不是整数。
* **Combo Option 的非法值:** 用户为 `UserComboOption` 提供了一个不在 `choices` 列表中的值，例如，如果一个枚举选项只有 `'opt1'` 和 `'opt2'` 两个选项，用户执行 `meson configure -Dmy_combo_option=opt3`，则会报错。
* **Prefix 选项的非绝对路径:** 用户为 `prefix` 选项提供了一个相对路径，例如 `meson configure --prefix build`。`sanitize_prefix` 方法会抛出 `MesonException`，要求 `prefix` 必须是绝对路径。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户运行 `meson setup <build_directory>` 或 `meson configure <build_directory>`:** 这是 Meson 构建过程的入口点。
2. **Meson 解析命令行参数和配置文件:** Meson 会读取用户提供的命令行选项 (`-D...`) 和项目根目录下的 `meson_options.txt` 或 `meson.options` 文件。
3. **创建 `CoreData` 实例:** 在配置阶段，Meson 会创建一个 `CoreData` 实例，用于存储解析到的配置信息。
4. **加载和验证选项值:**  对于每个选项，Meson 会根据其类型创建相应的 `UserOption` 子类实例，并调用 `validate_value` 方法来验证用户提供的值是否合法。这些选项值会被存储在 `CoreData.options` 中。
5. **处理交叉编译配置 (如果适用):** 如果用户提供了 `--cross-file` 参数，Meson 会加载指定的交叉编译配置文件，并将其信息存储在 `CoreData.cross_files` 中。
6. **进行依赖查找:** Meson 会使用 `DependencyCache` 来缓存和检索项目依赖的库。

因此，当用户在配置构建环境时，Meson 内部就会创建和操作 `CoreData` 实例，并将各种配置信息存储在该对象中。如果构建过程中出现配置错误，例如选项值类型不匹配，错误信息通常会指向相关的选项名称，这可以帮助用户追溯到 `CoreData` 中存储的错误配置。

总而言之，`frida/releng/meson/mesonbuild/coredata.py` 文件定义了 Meson 构建系统的核心数据结构，负责存储和管理构建过程中的各种配置信息，包括用户选项、编译器信息、依赖信息和缓存数据。它是 Meson 构建流程中至关重要的一部分，为后续的编译、链接等操作提供了必要的上下文。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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