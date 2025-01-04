Response:
The user wants a summary of the functionalities present in the provided Python code. The code defines the `CoreData` class, which seems to manage persistent build configuration data for the Frida dynamic instrumentation tool (based on the file path).

Here's a breakdown of the thinking process:

1. **Identify the core purpose:** The file name `coredata.py` and the presence of a class named `CoreData` strongly suggest this file is responsible for managing the central data related to the build process. The comments within the code also confirm this.

2. **Scan for key classes and data structures:**  Look for defined classes, data structures (like dictionaries, lists), and enums. The presence of `UserOption`, `UserStringOption`, `UserBooleanOption`, etc., indicates management of user-configurable build options. `DependencyCache` and `CMakeStateCache` suggest handling external dependencies and CMake integration. `PerMachine` suggests handling different settings for build and host machines.

3. **Analyze class functionalities (specifically `CoreData`):**
    * **Initialization (`__init__`)**:  What data is loaded or initialized when `CoreData` is created?  This includes:
        * Language GUIDs (likely for Visual Studio project generation).
        * Unique identifiers (`uuid`) for different build phases (test, regen, install).
        * Storing the Meson command used for invocation.
        * The current Meson version.
        * A dictionary to store build options (`self.options`).
        * Flags for build-only mode.
        * Handling cross-compilation configuration files.
        * Storing compiler information.
        * Managing options files for subprojects.
        * Tracking initialized subprojects.
        * Caching dependencies and CMake states for both build and host machines.
        * Caching results of compiler and run checks.
        * Loading "native" configuration files.
        * Initializing built-in options.
    * **Copying (`copy_as_build`)**: What happens when a copy of `CoreData` for the build machine is created? It seems to filter or adjust certain data structures, particularly options, dependencies, and compilers, to be relevant to the build machine in a cross-compilation scenario.
    * **Merging (`merge`)**: How is `CoreData` merged with another instance? This appears to handle the case where a build-only `CoreData` needs to be integrated back.
    * **Loading Configuration Files (`__load_config_files`)**:  How are cross and native configuration files handled? This involves searching for the files in specified locations and handling different file types (regular files, directories, pipes).
    * **Built-in Options (`builtin_options_libdir_cross_fixup`, `init_builtins`)**: How are default build options handled, especially in cross-compilation scenarios?
    * **Path Sanitization (`sanitize_prefix`, `sanitize_dir_option_value`)**:  How are user-provided paths validated and potentially transformed? This involves ensuring absolute paths and handling relative paths for installation directories.

4. **Identify supporting classes and their roles:**
    * **`UserOption` and its subclasses (`UserStringOption`, `UserBooleanOption`, etc.)**: These represent different types of configurable build options with validation and handling logic.
    * **`OptionsView`**: Provides a read-only view of the build options, potentially with overrides for subprojects.
    * **`DependencyCache` and `DependencySubCache`**: Manage a cache of resolved dependencies, considering different dependency types (like pkg-config and CMake).
    * **`CMakeStateCache`**: Caches internal CMake compiler states to speed up subsequent CMake invocations.

5. **Look for global constants and functions:**  Note down any important global variables like `version`, `backendlist`, `buildtypelist`, and the helper function `get_genvs_default_buildtype_list`.

6. **Synthesize a summary:** Combine the observations from the previous steps into a concise description of the file's functionality. Focus on the main purpose of `CoreData` and the key data it manages.

7. **Refine the summary:** Ensure the language is clear and avoids jargon where possible. Group related functionalities for better readability.

By following these steps, we can arrive at a comprehensive summary of the provided Python code's functionality, as demonstrated in the provided example answer. The key is to understand the structure of the code, the purpose of the main classes, and the types of data being managed.
好的，根据您提供的 `frida/subprojects/frida-clr/releng/meson/mesonbuild/coredata.py` 文件的源代码，我将归纳一下它的功能。

**功能归纳：**

该 Python 文件定义了 `CoreData` 类以及一系列辅助类和常量，用于存储和管理 Meson 构建系统的核心数据。这些数据需要在 Meson 的多次调用之间保持持久性，类似于 CMake 的缓存。

**`CoreData` 类及其相关功能主要包括：**

1. **存储构建配置信息：**
   -  存储构建过程中的各种选项（options），包括用户自定义的选项和内置选项。
   -  区分不同机器（构建机器 build 和宿主机 host）的选项。
   -  支持子项目（subproject）特定的选项。
   -  管理和加载交叉编译（cross-compilation）和原生编译（native compilation）的配置文件。
   -  记录 Meson 命令本身，用于重新生成构建系统。
   -  存储 Meson 的版本信息。

2. **管理依赖关系缓存：**
   -  维护一个依赖项（dependencies）的缓存，以加速后续的依赖查找。
   -  针对不同的依赖查找方法（例如，pkg-config, CMake）进行区分存储。
   -  区分构建机器和宿主机器的依赖。

3. **管理 CMake 状态缓存：**
   -  缓存内部 CMake 编译器的状态，用于优化 CMake 的启动性能。
   -  区分构建机器和宿主机器的 CMake 缓存。

4. **管理编译和运行检查缓存：**
   -  存储编译检查（compiler check）的结果，避免重复执行相同的检查。
   -  存储运行检查（run check）的结果，同样用于避免重复执行。

5. **处理构建目录的生命周期：**
   -  检测构建目录是否由不兼容的 Meson 版本生成。

6. **提供构建选项的抽象和管理：**
   -  定义了 `UserOption` 类及其子类（例如 `UserStringOption`, `UserBooleanOption`, `UserComboOption` 等），用于表示不同类型的用户可配置选项。
   -  提供选项的验证、类型转换和默认值管理。
   -  支持选项的废弃标记。

7. **处理安装路径：**
   -  管理安装路径（例如 `prefix`, `bindir`, `libdir` 等），并提供路径规范化的功能。

8. **支持构建过程中的唯一标识符：**
   -  生成用于不同构建阶段（例如测试、重新生成、安装）的唯一 GUID。

**与逆向方法的关联 (如果存在)：**

虽然该文件本身不直接包含逆向工程的代码，但它所管理的数据和功能对于理解和可能地修改 Frida 的构建过程至关重要。

**举例说明：**

假设你想修改 Frida CLR 组件的构建方式，例如更改其安装路径或使用的编译器选项。你可以：

1. **查看用户选项：**  通过查看 `CoreData` 中定义的 `UserOption` 子类，你可以了解哪些构建选项是可配置的。例如，你可能会找到一个控制 CLR 库安装路径的选项。

2. **修改构建选项：**  如果存在相应的选项，你可以在 Meson 的配置步骤中通过命令行或配置文件来修改这些选项。`CoreData` 负责存储和读取这些选项的值。

3. **理解依赖关系：**  如果你想了解 Frida CLR 依赖于哪些库，`DependencyCache` 中的信息会很有帮助。 যদিও এই ক্যাশে সরাসরি নির্ভরশীলতা রেজল্ভিং কোড নয়, এটি রেজোলিউশনের ফলাফলের স্ন্যাপশট প্রদান করে।

**涉及二进制底层、Linux、Android 内核及框架的知识 (如果存在)：**

该文件本身的代码主要是 Meson 构建系统的逻辑，不直接涉及二进制底层、内核或框架的具体实现。然而，它所管理的数据间接地与这些方面相关：

**举例说明：**

* **编译器选项：** `CoreData` 存储的编译器选项（例如优化级别、目标架构）会直接影响最终生成的二进制文件的特性。
* **依赖库路径：**  依赖关系缓存中存储的库路径会影响链接器如何找到所需的共享库，这与操作系统的库加载机制相关。
* **交叉编译：**  `CoreData` 对交叉编译的支持意味着它需要处理不同平台之间的差异，包括二进制格式、系统调用约定等。

**逻辑推理 (如果存在)：**

该文件包含一定的逻辑推理，主要体现在选项的验证和处理上。

**假设输入与输出：**

**假设输入：** 用户在 Meson 配置时设置了选项 `libdir` 为 `/opt/frida/libs`。

**逻辑推理：** `CoreData` 中的 `sanitize_prefix` 和 `sanitize_dir_option_value` 方法会被调用来验证和处理这个路径。

**输出：**
* `sanitize_prefix` 确保 `/opt/frida/libs` 是一个绝对路径。
* `sanitize_dir_option_value` 可能会将其相对于 `prefix` 选项的值进行相对化（如果适用）。最终，这个值会被存储在 `CoreData` 的 `options` 字典中。

**用户或编程常见的使用错误 (如果存在)：**

1. **Meson 版本不匹配：** 如果用户尝试使用一个由旧版本 Meson 生成的构建目录与新版本的 Meson 一起使用，`MesonVersionMismatchException` 会被抛出。

2. **提供了无效的选项值：**  例如，为一个布尔选项提供了非 "true" 或 "false" 的字符串值，或者为组合框选项提供了不在可选列表中的值。`UserOption` 的 `validate_value` 方法会负责检查并抛出异常。

3. **指定了不存在的配置文件：** 如果用户在命令行中通过 `--cross-file` 或 `--native-file` 指定了不存在的文件，`CoreData.__load_config_files` 会抛出 `MesonException`。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **用户执行 `meson setup <build_directory>` 或 `meson configure <build_directory>` 命令。**
2. **Meson 读取 `meson.build` 文件并解析项目定义。**
3. **Meson 处理命令行选项和环境变量。**
4. **在初始化阶段，Meson 会创建或加载 `CoreData` 对象。**
5. **`CoreData.__init__` 方法会被调用，开始加载各种配置信息：**
   -  解析命令行中指定的交叉编译和原生编译配置文件。
   -  初始化内置选项。
   -  如果存在旧的构建目录，则加载旧的 `CoreData` 数据。
6. **在配置过程中，用户设置的选项值会被存储到 `CoreData.options` 中。**
7. **在后续的构建过程中，Meson 会从 `CoreData` 中读取配置信息，例如编译器设置、依赖库路径等。**

**总结一下它的功能（针对第 1 部分）：**

`coredata.py` 文件的主要功能是定义和实现 `CoreData` 类，该类作为 Meson 构建系统的核心数据容器，负责存储和管理构建配置信息、依赖关系缓存、CMake 状态缓存、编译和运行检查结果，以及处理构建目录的生命周期。 它也定义了用于抽象和管理用户可配置构建选项的类。  该文件是 Meson 构建系统持久化配置信息和优化构建过程的关键组成部分。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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