Response:
The user wants to understand the functionality of the `coredata.py` file in the Frida project. This file seems to be related to Meson, the build system used by Frida. I need to analyze the code and explain its purpose, focusing on the following aspects:

1. **General Functionality**: What is the overall role of this file?
2. **Relationship to Reverse Engineering**: How does it connect to the techniques used in reverse engineering?
3. **Binary/Kernel/Framework Knowledge**: Does it involve low-level concepts related to operating systems like Linux or Android?
4. **Logical Reasoning**: Are there any parts of the code that perform logical deductions based on input?
5. **Common User Errors**: What mistakes might users make that relate to this file?
6. **User Operations Leading Here**: How does a user interact with Frida or its build process to reach this part of the code?
7. **Summary of Functionality**: A concise overview of the file's purpose.

Based on the code, `coredata.py` appears to be responsible for managing and persisting configuration data for the Meson build system used by Frida. It handles things like project options, dependency information, compiler settings, and cached results.

Let's break down the analysis:

**1. General Functionality**:

- **Storing Configuration**:  It holds various configuration settings for the build process.
- **Managing Options**:  It defines how user-configurable options are handled (types, validation, etc.). The `UserOption` class and its subclasses are central to this.
- **Dependency Management**: It maintains a cache of found dependencies (`DependencyCache`).
- **Caching Compiler Checks**: It stores the results of compiler feature checks (`compiler_check_cache`, `run_check_cache`).
- **CMake Integration**: It appears to have some interaction with CMake, potentially for finding dependencies or other build-related tasks (`CMakeStateCache`).
- **Persistence**: The name "coredata" suggests that the information stored here needs to persist across different Meson invocations.

**2. Relationship to Reverse Engineering**:

- **Frida Configuration**: As this is a Frida file, the options managed here likely influence how Frida itself is built. This can indirectly affect reverse engineering workflows that rely on specific Frida capabilities or build configurations. For example, debug vs. release builds can impact the information available for reverse engineering.
- **Dependency Handling**:  Frida likely depends on other libraries. The way these dependencies are found and linked (managed by this file) can impact the final Frida binary that a reverse engineer would interact with.

**3. Binary/Kernel/Framework Knowledge**:

- **Build System Basics**: This file deals with core aspects of a build system, which inherently involves understanding how software is compiled and linked into binary executables.
- **Platform Differences**: The presence of `PerMachine` suggests that the configuration can vary between the build and host machines, which is relevant when cross-compiling (e.g., building Frida for Android on a Linux machine). This hints at understanding different target architectures and operating systems.
- **Installation Directories**: Options like `libdir`, `bindir`, etc., are standard in build systems and relate to where the compiled binaries and libraries are placed on the target system. This connects to the fundamental structure of operating systems.
- **CMake Integration**: CMake is another build system, often used for projects with native code. Interacting with CMake implies understanding its concepts and how it interacts with compilers and linkers.

**4. Logical Reasoning**:

- **Option Validation**: The `validate_value` methods in the `UserOption` subclasses perform logical checks to ensure that the user-provided option values are valid (e.g., a boolean option can only be 'true' or 'false').
- **Dependency Lookup**: The `DependencyCache` attempts to retrieve dependencies based on various criteria. The logic of searching and caching dependencies involves reasoning about how to locate the required libraries.
- **Prefix Sanitization**: The `sanitize_prefix` function applies logic to ensure the `prefix` directory is a valid absolute path.

**5. Common User Errors**:

- **Invalid Option Values**: Users might provide incorrect values for build options (e.g., typing "ture" instead of "true" for a boolean option). The validation logic in this file would catch such errors.
- **Incorrect File Paths**: When specifying cross-compilation files or other configuration files, users might provide incorrect or non-existent paths. The file loading logic in this file handles such cases and raises errors.
- **Conflicting Options**: While not explicitly shown in this snippet, other parts of the Meson system might have logic to detect and report conflicting option settings.

**6. User Operations Leading Here**:

- **Running `meson setup`**: This command initializes the build environment and parses the `meson_options.txt` (or `meson.options`) file and command-line options. The code in `coredata.py` is directly involved in processing these options and storing them.
- **Running `meson configure`**:  This command can be used to reconfigure the build, potentially changing options. The loading and management of options in this file are relevant here.
- **Cross-compiling**: When building Frida for a different architecture (e.g., Android), users provide cross-compilation files. The handling of `cross_file` in this code is part of that process.
- **Using `mconf`**: This tool allows interactive modification of build options, which would interact with the option management features of this file.

**7. Summary of Functionality**:

The `coredata.py` file in the Frida project (within the Meson build system) is responsible for managing and persisting core build configuration data. This includes handling user-defined options, managing dependencies, caching compiler check results, and integrating with other build tools like CMake. It ensures that the build process has access to the necessary settings and avoids redundant computations.

好的，根据您提供的 `frida/subprojects/frida-swift/releng/meson/mesonbuild/coredata.py` 文件的第一部分源代码，我来归纳一下它的功能：

**`coredata.py` 的主要功能是管理和存储 Meson 构建系统的核心数据，这些数据需要在多次 Meson 调用之间保持持久性。** 它扮演着类似 CMake 的缓存文件的角色，但更加结构化和面向 Meson 的内部运作。

具体来说，从提供的代码片段中可以看出，`coredata.py` 主要负责以下方面：

1. **定义和管理用户可配置的构建选项（Options）**:
   - 它定义了各种类型的用户选项，例如字符串 (`UserStringOption`)、布尔值 (`UserBooleanOption`)、整数 (`UserIntegerOption`)、枚举 (`UserComboOption`) 和数组 (`UserArrayOption`) 等。
   - 每个选项都包含名称、描述、可选的合法值范围或列表，以及是否为“yielding”选项（可能与选项的延迟评估有关）。
   - 它还处理选项的验证，确保用户提供的值符合预期。

2. **存储和管理构建系统的内置选项 (Built-in Options)**:
   - 代码中提到 `init_builtins` 函数，这表明 `coredata.py` 负责初始化 Meson 预定义的构建选项，例如安装路径 (`prefix`, `bindir`, `libdir`)、构建类型 (`buildtype`) 和后端 (`backend`) 等。

3. **处理跨平台编译 (Cross-compilation) 配置**:
   - 它加载和存储跨平台编译的配置文件 (`cross_file`) 和本地编译的配置文件 (`native_file`)，这些文件定义了目标平台的编译器和库路径等信息。

4. **缓存依赖项信息 (Dependency Cache)**:
   - `DependencyCache` 类用于缓存已找到的依赖项，以便在后续构建过程中快速检索，避免重复查找。它支持不同类型的依赖项（例如 pkg-config 和 CMake）。

5. **缓存编译器检查结果 (Compiler Check Cache)**:
   - `compiler_check_cache` 和 `run_check_cache` 字典用于存储编译器特性检查和运行测试的结果，以优化构建速度。

6. **管理 CMake 状态缓存 (CMake State Cache)**:
   - `CMakeStateCache` 类用于存储内部 CMake 编译器状态，这表明 Meson 可以与 CMake 项目集成或使用 CMake 查找依赖项。

7. **存储构建过程中的各种 GUID**:
   - 它生成并存储用于不同目的的 UUID，例如测试 (`test_guid`)、重新生成 (`regen_guid`) 和安装 (`install_guid`)，这些可能用于跟踪构建过程或生成唯一的标识符。

8. **存储当前 Meson 版本**:
   - `version` 变量存储了当前使用的 Meson 版本，这可能用于检查构建目录是否与当前 Meson 版本兼容。

9. **支持子项目 (Subprojects)**:
   - 代码中出现了 `SubProject` 类型，并提到了 `initialized_subprojects`，这表明 `coredata.py` 能够处理包含多个子项目的构建。

10. **提供选项的视图 (OptionsView)**:
    - `OptionsView` 类允许为特定的子项目或在存在覆盖设置的情况下查看选项。

**与逆向方法的关联举例说明:**

虽然这个文件本身不直接涉及逆向分析的具体技术，但它管理的构建配置会影响最终生成的可执行文件和库，这些文件是逆向分析的目标。

* **调试信息**:  用户可以通过 Meson 选项 (`buildtype=debug`) 配置生成包含调试符号的二进制文件。逆向工程师在分析时通常会利用这些符号来理解代码结构和变量含义。`coredata.py` 负责存储和管理这个 `buildtype` 选项。
* **优化级别**: Meson 允许设置不同的优化级别 (`buildtype=release`, `buildtype=minsize`)。高优化级别的代码更难逆向，因为编译器会进行各种转换和内联。`coredata.py` 管理这些优化相关的选项。
* **静态或动态链接**: 构建选项可能会影响库的链接方式。逆向工程师需要了解目标程序依赖哪些库以及如何加载这些库。`coredata.py` 中管理的依赖项信息和链接选项会影响最终的链接结果。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **安装路径**:  像 `libdir`、`bindir` 这样的选项直接关系到编译产物在 Linux 或 Android 系统中的安装位置。这些路径是操作系统约定的标准路径，理解这些路径有助于理解软件的部署和运行方式。
* **交叉编译**:  `coredata.py` 处理交叉编译配置文件。进行 Android 平台的逆向分析，通常需要在非 Android 环境下构建 Frida Agent。理解交叉编译的原理，例如目标平台的 SDK、编译器和库路径，是必要的。`coredata.py` 中的 `cross_file` 配置项就体现了这一点。
* **依赖项搜索路径**:  `DependencyCache` 涉及查找依赖库的过程，这可能涉及到 Linux 系统中的 `LD_LIBRARY_PATH` 环境变量，或者 Android 系统中类似的机制。

**逻辑推理的假设输入与输出举例:**

假设用户设置了一个布尔类型的选项 `my_feature`：

**假设输入:**
- 用户在 `meson_options.txt` 文件中设置 `my_feature = true`。

**逻辑推理:**
- `coredata.py` 在解析选项时，`UserBooleanOption` 的 `validate_value` 方法会接收字符串 `"true"` 作为输入。
- `validate_value` 方法会进行逻辑判断，将 `"true"` 转换为 Python 的布尔值 `True`。

**输出:**
- 选项 `my_feature` 的值在 `coredata` 中被存储为 `True`。

**涉及用户或编程常见的使用错误举例说明:**

* **拼写错误或无效的选项值**: 用户可能会在 `meson_options.txt` 中错误地输入选项值，例如将布尔值写成 `"ture"` 而不是 `"true"`。`UserBooleanOption` 的 `validate_value` 方法会捕获这种错误并抛出异常。
* **指定不存在的配置文件**: 用户在运行 `meson setup` 时，通过 `--cross-file` 或 `--native-file` 参数指定了不存在的配置文件路径。`CoreData.__load_config_files` 方法会检测到文件不存在并抛出 `MesonException`。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户下载 Frida 源代码**: 用户从 Frida 的 GitHub 仓库或其他来源获取了 Frida 的源代码。
2. **用户尝试构建 Frida**: 用户进入 Frida 的构建目录（通常是 `frida/build` 或类似名称），并尝试运行 Meson 来配置构建系统：
   ```bash
   cd frida/build
   meson setup ..
   ```
3. **Meson 初始化**: `meson setup` 命令会执行 Meson 的初始化过程。
4. **解析构建选项**: Meson 会读取项目根目录下的 `meson_options.txt` 或 `meson.options` 文件，以及用户通过命令行传递的选项。
5. **加载 `coredata.py`**:  Meson 内部会加载 `frida/subprojects/frida-swift/releng/meson/mesonbuild/coredata.py` 文件，因为它是 Meson 构建系统核心数据管理的一部分。
6. **创建 `CoreData` 实例**: Meson 会创建 `CoreData` 类的实例，用于存储和管理构建配置信息。
7. **解析和验证选项**:  `CoreData` 实例会调用其方法（例如 `init_builtins`）来解析和验证用户提供的选项，包括读取配置文件和命令行参数。
8. **存储核心数据**:  解析后的选项、依赖项信息、编译器检查结果等会被存储在 `CoreData` 实例的属性中。

在调试 Meson 构建问题时，如果怀疑是选项配置错误或依赖项查找失败，开发者可能会查看 `coredata.py` 的相关代码，了解 Meson 是如何加载、解析和存储这些信息的，从而找到问题的根源。例如，可以通过打印 `CoreData` 实例中的选项值或检查缓存的内容来辅助调试。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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