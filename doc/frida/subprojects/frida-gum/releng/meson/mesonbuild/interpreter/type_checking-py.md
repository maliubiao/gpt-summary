Response:
The user wants to understand the functionality of the Python code provided, which is related to type checking within the Frida dynamic instrumentation tool's Meson build system integration.

Here's a plan to address the request:

1. **Identify the Core Functionality:**  The primary goal of this file is to define and enforce type constraints for function arguments within the Meson build system as used by Frida.

2. **Explain Key Concepts:** Define terms like "type checking", "Meson", and how they relate to build systems.

3. **Categorize Functionality:** Group the functions and variables based on their purpose (e.g., validators, converters, keyword argument definitions).

4. **Illustrate with Examples:** Provide concrete examples of how these type checks work, particularly in the context of reverse engineering, binary manipulation, and interactions with the operating system.

5. **Address Specific Questions:** Systematically go through the user's questions about reverse engineering, binary/OS interaction, logical inference, common errors, and debugging.

6. **Structure the Output:** Organize the information clearly with headings and bullet points for readability.
这个Python文件 `type_checking.py` 是 Frida 动态 instrumentation 工具构建系统中 Meson 构建工具的一部分，它的主要功能是为 Meson 构建系统中定义的函数参数提供**严格的类型检查**和**数据转换**。这有助于确保构建配置的正确性，减少因类型错误导致的构建失败。

以下是该文件的详细功能列表：

**1. 定义和实现各种类型检查的验证器 (Validators):**

   - **`in_set_validator(choices: T.Set[str])`**: 检查输入字符串是否在给定的字符串集合中。
     - **例子:**  可以用于验证编译器类型，例如 `in_set_validator({'gcc', 'clang'})`。
   - **`_language_validator(l: T.List[str])`**: 验证 `language` 关键字参数，确保提供的语言是 Meson 支持的语言。
     - **关系到二进制底层:**  不同的编程语言（如 C, C++, Assembly）会编译成不同的机器码，这个验证器确保构建系统知道要使用哪个编译器和链接器。
   - **`_install_mode_validator(mode: T.List[T.Union[str, bool, int]])`**: 验证 `install_mode` 关键字参数，用于设置安装文件的权限。
     - **关系到 Linux:** 文件权限是 Linux 操作系统的重要概念，这个验证器确保提供的权限字符串格式正确（如 "rwxr-xr-x"）。
   - **`_validate_shlib_version(val: T.Optional[str])`**: 验证共享库的版本号格式是否正确（如 "1", "1.0", "1.0.1"）。
     - **关系到二进制底层:**  共享库的版本号对于动态链接器在运行时加载正确的库版本至关重要。
   - **`variables_validator(contents: T.Union[str, T.List[str], T.Dict[str, str]])`**: 验证环境变量的格式。
     - **关系到 Linux 和 Android 框架:**  环境变量可以影响程序的运行行为，包括动态库的查找路径 (`LD_LIBRARY_PATH`)，这在 Android 框架中也很常见。
   - **`_env_validator(...)`**: 验证环境变量的设置，确保格式正确。
     - **关系到 Linux 和 Android 框架:**  与 `variables_validator` 类似，确保环境变量设置的格式正确性。
   - **`_options_validator(...)`**: 验证构建选项的格式。
   - **`_output_validator(outputs: T.List[str])`**: 验证输出文件名的格式，防止包含路径分隔符等非法字符。
   - **`link_whole_validator(...)`**: 验证 `link_whole` 关键字参数，确保只包含静态库和自定义目标，不允许动态链接库。
     - **关系到二进制底层:**  `link_whole` 强制将静态库的所有符号链接到最终的可执行文件或共享库中。
   - **`_objects_validator(...)`**: 验证 `objects` 关键字参数，确保提供的都是目标文件。
     - **关系到二进制底层:**  目标文件是编译的中间产物，包含机器码。
   - **`_name_validator(...)`, `_name_suffix_validator(...)`**: 验证名称前缀和后缀的格式。
   - **`_validate_win_subsystem(...)`**: 验证 Windows 子系统类型。
     - **关系到二进制底层:**  Windows 可执行文件需要指定子系统，例如 GUI 应用或控制台应用。
   - **`_validate_darwin_versions(...)`**: 验证 macOS 的部署目标版本。
   - **其他针对特定关键字参数的验证器:** 例如，检查 `rust_crate_type` 和 `rust_abi` 的合法值。

**2. 定义和实现数据转换器 (Convertors):**

   - **`_install_mode_convertor(mode: T.Optional[T.List[T.Union[str, bool, int]]])`**: 将 `install_mode` 的 DSL 形式转换为 `FileMode` 对象。
   - **`_lower_strlist(input: T.List[str])`**: 将字符串列表转换为小写。
   - **`variables_convertor(...)`**: 将不同格式的环境变量定义转换为字典。
   - **`env_convertor_with_method(...)`, `_env_convertor(...)`**: 将不同格式的环境变量定义转换为 `EnvironmentVariables` 对象。
   - **`split_equal_string(input: str)`**: 将形如 "key=value" 的字符串分割成键值对。
   - **`_override_options_convertor(...)`**: 将不同格式的覆盖选项转换为字典。
   - **`_convert_darwin_versions(...)`**: 将 macOS 部署目标版本转换为元组。
   - **`_pkgconfig_define_convertor(...)`**: 将 pkg-config 定义转换为元组。
   - **其他针对特定关键字参数的转换器:** 例如，将布尔值转换为 `MachineChoice` 枚举。

**3. 定义用于描述函数参数的 `KwargInfo` 对象:**

   - 该文件定义了大量的 `KwargInfo` 对象，每个对象都描述了一个 Meson 构建函数（如 `executable`, `shared_library`, `custom_target` 等）的关键字参数。
   - `KwargInfo` 对象包含了参数的名称、类型、默认值、是否必须、验证器、转换器、以及该参数引入或废弃的版本信息。
   - **例子:** `LANGUAGE_KW = KwargInfo('language', ContainerTypeInfo(list, str, allow_empty=False), listify=True, required=True, validator=_language_validator, convertor=_lower_strlist)` 定义了 `language` 参数的类型是字符串列表，不能为空，必须提供，并且使用 `_language_validator` 进行验证，使用 `_lower_strlist` 进行转换。

**与逆向方法的关系及举例说明:**

- **验证共享库版本 (`_validate_shlib_version`)**: 在逆向工程中，经常需要分析不同版本的共享库。此验证器确保构建系统正确处理库的版本信息，这对于复现特定的构建环境或理解不同版本库的行为至关重要。
  - **例子:**  假设你正在逆向一个使用 `libcrypto.so.1.0.0` 的程序。如果构建脚本中 `version` 参数错误地设置为 "1.1"，则构建会失败，提示版本格式不正确。
- **环境变量验证 (`_env_validator`)**:  在某些逆向场景中，程序的行为可能受到环境变量的影响。例如，某些反调试技术会检查特定的环境变量。此验证器确保在构建测试环境时，可以正确设置所需的环境变量。
  - **例子:**  一些恶意软件分析需要在特定的环境变量下运行才能触发特定行为。可以使用 Meson 构建系统创建一个测试环境，通过 `env` 参数设置这些环境变量。如果环境变量格式错误，构建系统会报错。
- **链接选项验证 (`link_whole_validator`)**: 在逆向静态链接的二进制文件时，了解哪些库是被完整链接进来的很有帮助。此验证器确保构建系统正确处理静态链接的库。
  - **例子:**  如果你想创建一个包含所有依赖库的静态链接的可执行文件，可以使用 `link_whole` 参数。如果错误地将动态库添加进去，构建系统会报错。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

- **语言验证 (`_language_validator`)**: 不同的语言会产生不同的二进制代码和链接方式。C/C++ 代码通常需要链接器，而 Java 代码则运行在 JVM 上。
  - **例子:**  如果构建一个 Frida Gadget (一个注入到进程中的共享库)，需要指定 C 或 C++ 作为语言。如果错误地指定为 Java，构建系统会报错。
- **安装模式验证 (`_install_mode_validator`)**:  Linux 和 Android 系统使用权限模型来控制文件的访问。此验证器确保安装文件的权限设置是有效的。
  - **例子:**  在 Android 中，可执行文件需要具有执行权限才能运行。构建脚本可以使用 `install_mode` 参数设置正确的权限 (例如 "0755" 或 "rwxr-xr-x")。
- **Windows 子系统验证 (`_validate_win_subsystem`)**:  Windows 可执行文件需要指定其运行的子系统，例如 GUI 应用或控制台应用。这会影响操作系统的加载和执行方式。
  - **例子:**  如果你正在构建一个 Windows 平台的 Frida 工具，需要根据其用途选择合适的子系统。
- **macOS 部署目标版本验证 (`_validate_darwin_versions`)**: 确保构建的二进制文件能在目标 macOS 版本上运行。

**逻辑推理的假设输入与输出:**

- **假设输入:**  `install_mode` 参数设置为 `['rwxr-xr-x', 644]`。
- **输出:** `_install_mode_validator` 返回 `None` (表示输入有效)。`_install_mode_convertor` 将其转换为 `FileMode("rwxr-xr-x", "644", None)`。
- **假设输入:** `language` 参数设置为 `['python']`.
- **输出:** `_language_validator` 返回一个包含错误信息的字符串，因为 "python" 不是一个用于编译的语言。

**涉及用户或者编程常见的使用错误及举例说明:**

- **错误的 `install_mode` 格式:** 用户可能错误地提供类似 `['rwxr-xr-x', 'abc']` 的 `install_mode`，其中 "abc" 不是有效的用户或组 ID。`_install_mode_validator` 会捕捉到这个错误。
- **拼写错误的语言名称:** 用户可能在 `language` 参数中输入 `['c++']` (缺少第二个 '+')。`_language_validator` 会提示未知的语言。
- **输出文件名包含路径:** 用户可能在 `output` 参数中输入 `'bin/my_executable'`. `_output_validator` 会阻止这种行为，因为输出文件名不应该包含路径。
- **在 `link_whole` 中添加动态库:** 用户可能会错误地将一个共享库传递给 `link_whole` 参数。`link_whole_validator` 会检测到这个错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户编写项目构建配置文件 `meson.build`，其中使用了 Frida 提供的 Meson 函数，例如 `executable()` 或 `shared_library()`，并设置了各种关键字参数。
2. **用户运行 `meson` 命令配置构建:** 用户在项目目录下运行 `meson setup builddir` 命令，Meson 工具会读取 `meson.build` 文件并解析构建配置。
3. **Meson 调用解释器处理 `meson.build`:** Meson 的解释器会执行 `meson.build` 文件中的代码。
4. **解释器遇到需要类型检查的函数调用:** 当解释器遇到像 `executable(sources=['main.c'], name='my_app', install_mode=['rwxr-xr-x', 'invalid'])` 这样的函数调用时，它会提取关键字参数。
5. **调用 `type_checking.py` 中的验证器:**  对于每个需要进行类型检查的关键字参数，解释器会查找对应的 `KwargInfo` 对象，并调用其关联的验证器函数（如 `_install_mode_validator`）。
6. **验证器检测到错误:** 在上面的例子中，`_install_mode_validator` 会检测到 'invalid' 不是有效的用户或组 ID，并返回一个错误消息。
7. **Meson 报告错误并停止:** Meson 工具会将验证器返回的错误消息呈现给用户，并中止构建配置过程。

因此，当用户在配置构建时遇到与类型相关的错误，错误信息很可能来自 `type_checking.py` 中定义的验证器函数。这表明用户在 `meson.build` 文件中使用了不符合类型要求的参数值。可以通过检查 `meson.build` 文件中相关函数的参数来定位和修复错误。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/type_checking.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2021 Intel Corporation

"""Helpers for strict type checking."""

from __future__ import annotations
import itertools, os, re
import typing as T

from .. import compilers
from ..build import (CustomTarget, BuildTarget,
                     CustomTargetIndex, ExtractedObjects, GeneratedList, IncludeDirs,
                     BothLibraries, SharedLibrary, StaticLibrary, Jar, Executable, StructuredSources)
from ..coredata import UserFeatureOption
from ..dependencies import Dependency, InternalDependency
from ..interpreterbase.decorators import KwargInfo, ContainerTypeInfo
from ..mesonlib import (File, FileMode, MachineChoice, listify, has_path_sep,
                        OptionKey, EnvironmentVariables)
from ..programs import ExternalProgram

# Helper definition for type checks that are `Optional[T]`
NoneType: T.Type[None] = type(None)

if T.TYPE_CHECKING:
    from typing_extensions import Literal

    from ..build import ObjectTypes
    from ..interpreterbase import TYPE_var
    from ..mesonlib import EnvInitValueType

    _FullEnvInitValueType = T.Union[EnvironmentVariables, T.List[str], T.List[T.List[str]], EnvInitValueType, str, None]
    PkgConfigDefineType = T.Optional[T.Tuple[T.Tuple[str, str], ...]]
    SourcesVarargsType = T.List[T.Union[str, File, CustomTarget, CustomTargetIndex, GeneratedList, StructuredSources, ExtractedObjects, BuildTarget]]


def in_set_validator(choices: T.Set[str]) -> T.Callable[[str], T.Optional[str]]:
    """Check that the choice given was one of the given set."""

    def inner(check: str) -> T.Optional[str]:
        if check not in choices:
            return f"must be one of {', '.join(sorted(choices))}, not {check}"
        return None

    return inner


def _language_validator(l: T.List[str]) -> T.Optional[str]:
    """Validate language keyword argument.

    Particularly for functions like `add_compiler()`, and `add_*_args()`
    """
    diff = {a.lower() for a in l}.difference(compilers.all_languages)
    if diff:
        return f'unknown languages: {", ".join(diff)}'
    return None


def _install_mode_validator(mode: T.List[T.Union[str, bool, int]]) -> T.Optional[str]:
    """Validate the `install_mode` keyword argument.

    This is a rather odd thing, it's a scalar, or an array of 3 values in the form:
    [(str | False), (str | int | False) = False, (str | int | False) = False]
    where the second and third components are not required and default to False.
    """
    if not mode:
        return None
    if True in mode:
        return 'components can only be permission strings, numbers, or False'
    if len(mode) > 3:
        return 'may have at most 3 elements'

    perms = mode[0]
    if not isinstance(perms, (str, bool)):
        return 'first component must be a permissions string or False'

    if isinstance(perms, str):
        if not len(perms) == 9:
            return ('permissions string must be exactly 9 characters in the form rwxr-xr-x,'
                    f' got {len(perms)}')
        for i in [0, 3, 6]:
            if perms[i] not in {'-', 'r'}:
                return f'permissions character {i+1} must be "-" or "r", not {perms[i]}'
        for i in [1, 4, 7]:
            if perms[i] not in {'-', 'w'}:
                return f'permissions character {i+1} must be "-" or "w", not {perms[i]}'
        for i in [2, 5]:
            if perms[i] not in {'-', 'x', 's', 'S'}:
                return f'permissions character {i+1} must be "-", "s", "S", or "x", not {perms[i]}'
        if perms[8] not in {'-', 'x', 't', 'T'}:
            return f'permission character 9 must be "-", "t", "T", or "x", not {perms[8]}'

        if len(mode) >= 2 and not isinstance(mode[1], (int, str, bool)):
            return 'second component can only be a string, number, or False'
        if len(mode) >= 3 and not isinstance(mode[2], (int, str, bool)):
            return 'third component can only be a string, number, or False'

    return None


def _install_mode_convertor(mode: T.Optional[T.List[T.Union[str, bool, int]]]) -> FileMode:
    """Convert the DSL form of the `install_mode` keyword argument to `FileMode`"""

    if not mode:
        return FileMode()

    # This has already been validated by the validator. False denotes "use
    # default". mypy is totally incapable of understanding it, because
    # generators clobber types via homogeneous return. But also we *must*
    # convert the first element different from the rest
    m1 = mode[0] if isinstance(mode[0], str) else None
    rest = (m if isinstance(m, (str, int)) else None for m in mode[1:])

    return FileMode(m1, *rest)


def _lower_strlist(input: T.List[str]) -> T.List[str]:
    """Lower a list of strings.

    mypy (but not pyright) gets confused about using a lambda as the convertor function
    """
    return [i.lower() for i in input]


def _validate_shlib_version(val: T.Optional[str]) -> T.Optional[str]:
    if val is not None and not re.fullmatch(r'[0-9]+(\.[0-9]+){0,2}', val):
        return (f'Invalid Shared library version "{val}". '
                'Must be of the form X.Y.Z where all three are numbers. Y and Z are optional.')
    return None


def variables_validator(contents: T.Union[str, T.List[str], T.Dict[str, str]]) -> T.Optional[str]:
    if isinstance(contents, str):
        contents = [contents]
    if isinstance(contents, dict):
        variables = contents
    else:
        variables = {}
        for v in contents:
            try:
                key, val = v.split('=', 1)
            except ValueError:
                return f'variable {v!r} must have a value separated by equals sign.'
            variables[key.strip()] = val.strip()
    for k, v in variables.items():
        if not k:
            return 'empty variable name'
        if any(c.isspace() for c in k):
            return f'invalid whitespace in variable name {k!r}'
    return None


def variables_convertor(contents: T.Union[str, T.List[str], T.Dict[str, str]]) -> T.Dict[str, str]:
    if isinstance(contents, str):
        contents = [contents]
    if isinstance(contents, dict):
        return contents
    variables = {}
    for v in contents:
        key, val = v.split('=', 1)
        variables[key.strip()] = val.strip()
    return variables


NATIVE_KW = KwargInfo(
    'native', bool,
    default=False,
    convertor=lambda n: MachineChoice.BUILD if n else MachineChoice.HOST)

LANGUAGE_KW = KwargInfo(
    'language', ContainerTypeInfo(list, str, allow_empty=False),
    listify=True,
    required=True,
    validator=_language_validator,
    convertor=_lower_strlist)

INSTALL_MODE_KW: KwargInfo[T.List[T.Union[str, bool, int]]] = KwargInfo(
    'install_mode',
    ContainerTypeInfo(list, (str, bool, int)),
    listify=True,
    default=[],
    validator=_install_mode_validator,
    convertor=_install_mode_convertor,
)

REQUIRED_KW: KwargInfo[T.Union[bool, UserFeatureOption]] = KwargInfo(
    'required',
    (bool, UserFeatureOption),
    default=True,
    # TODO: extract_required_kwarg could be converted to a convertor
)

DISABLER_KW: KwargInfo[bool] = KwargInfo('disabler', bool, default=False)

def _env_validator(value: T.Union[EnvironmentVariables, T.List['TYPE_var'], T.Dict[str, 'TYPE_var'], str, None],
                   only_dict_str: bool = True) -> T.Optional[str]:
    def _splitter(v: str) -> T.Optional[str]:
        split = v.split('=', 1)
        if len(split) == 1:
            return f'"{v}" is not two string values separated by an "="'
        return None

    if isinstance(value, str):
        v = _splitter(value)
        if v is not None:
            return v
    elif isinstance(value, list):
        for i in listify(value):
            if not isinstance(i, str):
                return f"All array elements must be a string, not {i!r}"
            v = _splitter(i)
            if v is not None:
                return v
    elif isinstance(value, dict):
        # We don't need to spilt here, just do the type checking
        for k, dv in value.items():
            if only_dict_str:
                if any(i for i in listify(dv) if not isinstance(i, str)):
                    return f"Dictionary element {k} must be a string or list of strings not {dv!r}"
            elif isinstance(dv, list):
                if any(not isinstance(i, str) for i in dv):
                    return f"Dictionary element {k} must be a string, bool, integer or list of strings, not {dv!r}"
            elif not isinstance(dv, (str, bool, int)):
                return f"Dictionary element {k} must be a string, bool, integer or list of strings, not {dv!r}"
    # We know that otherwise we have an EnvironmentVariables object or None, and
    # we're okay at this point
    return None

def _options_validator(value: T.Union[EnvironmentVariables, T.List['TYPE_var'], T.Dict[str, 'TYPE_var'], str, None]) -> T.Optional[str]:
    # Reusing the env validator is a little overkill, but nicer than duplicating the code
    return _env_validator(value, only_dict_str=False)

def split_equal_string(input: str) -> T.Tuple[str, str]:
    """Split a string in the form `x=y`

    This assumes that the string has already been validated to split properly.
    """
    a, b = input.split('=', 1)
    return (a, b)

# Split _env_convertor() and env_convertor_with_method() to make mypy happy.
# It does not want extra arguments in KwargInfo convertor callable.
def env_convertor_with_method(value: _FullEnvInitValueType,
                              init_method: Literal['set', 'prepend', 'append'] = 'set',
                              separator: str = os.pathsep) -> EnvironmentVariables:
    if isinstance(value, str):
        return EnvironmentVariables(dict([split_equal_string(value)]), init_method, separator)
    elif isinstance(value, list):
        return EnvironmentVariables(dict(split_equal_string(v) for v in listify(value)), init_method, separator)
    elif isinstance(value, dict):
        return EnvironmentVariables(value, init_method, separator)
    elif value is None:
        return EnvironmentVariables()
    return value

def _env_convertor(value: _FullEnvInitValueType) -> EnvironmentVariables:
    return env_convertor_with_method(value)

ENV_KW: KwargInfo[T.Union[EnvironmentVariables, T.List, T.Dict, str, None]] = KwargInfo(
    'env',
    (EnvironmentVariables, list, dict, str, NoneType),
    validator=_env_validator,
    convertor=_env_convertor,
)

DEPFILE_KW: KwargInfo[T.Optional[str]] = KwargInfo(
    'depfile',
    (str, type(None)),
    validator=lambda x: 'Depfile must be a plain filename with a subdirectory' if has_path_sep(x) else None
)

# TODO: CustomTargetIndex should be supported here as well
DEPENDS_KW: KwargInfo[T.List[T.Union[BuildTarget, CustomTarget]]] = KwargInfo(
    'depends',
    ContainerTypeInfo(list, (BuildTarget, CustomTarget)),
    listify=True,
    default=[],
)

DEPEND_FILES_KW: KwargInfo[T.List[T.Union[str, File]]] = KwargInfo(
    'depend_files',
    ContainerTypeInfo(list, (File, str)),
    listify=True,
    default=[],
)

COMMAND_KW: KwargInfo[T.List[T.Union[str, BuildTarget, CustomTarget, CustomTargetIndex, ExternalProgram, File]]] = KwargInfo(
    'command',
    # TODO: should accept CustomTargetIndex as well?
    ContainerTypeInfo(list, (str, BuildTarget, CustomTarget, CustomTargetIndex, ExternalProgram, File), allow_empty=False),
    required=True,
    listify=True,
    default=[],
)

def _override_options_convertor(raw: T.Union[str, T.List[str], T.Dict[str, T.Union[str, int, bool, T.List[str]]]]) -> T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]:
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, list):
        output: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]] = {}
        for each in raw:
            k, v = split_equal_string(each)
            output[OptionKey.from_string(k)] = v
        return output
    return {OptionKey.from_string(k): v for k, v in raw.items()}


OVERRIDE_OPTIONS_KW: KwargInfo[T.Union[str, T.Dict[str, T.Union[str, int, bool, T.List[str]]], T.List[str]]] = KwargInfo(
    'override_options',
    (str, ContainerTypeInfo(list, str), ContainerTypeInfo(dict, (str, int, bool, list))),
    default={},
    validator=_options_validator,
    convertor=_override_options_convertor,
    since_values={dict: '1.2.0'},
)


def _output_validator(outputs: T.List[str]) -> T.Optional[str]:
    output_set = set(outputs)
    if len(output_set) != len(outputs):
        seen = set()
        for el in outputs:
            if el in seen:
                return f"contains {el!r} multiple times, but no duplicates are allowed."
            seen.add(el)
    for i in outputs:
        if i == '':
            return 'Output must not be empty.'
        elif i.strip() == '':
            return 'Output must not consist only of whitespace.'
        elif has_path_sep(i):
            return f'Output {i!r} must not contain a path segment.'
        elif '@INPUT' in i:
            return f'output {i!r} contains "@INPUT", which is invalid. Did you mean "@PLAINNAME@" or "@BASENAME@?'

    return None

MULTI_OUTPUT_KW: KwargInfo[T.List[str]] = KwargInfo(
    'output',
    ContainerTypeInfo(list, str, allow_empty=False),
    listify=True,
    required=True,
    default=[],
    validator=_output_validator,
)

OUTPUT_KW: KwargInfo[str] = KwargInfo(
    'output',
    str,
    required=True,
    validator=lambda x: _output_validator([x])
)

CT_INPUT_KW: KwargInfo[T.List[T.Union[str, File, ExternalProgram, BuildTarget, CustomTarget, CustomTargetIndex, ExtractedObjects, GeneratedList]]] = KwargInfo(
    'input',
    ContainerTypeInfo(list, (str, File, ExternalProgram, BuildTarget, CustomTarget, CustomTargetIndex, ExtractedObjects, GeneratedList)),
    listify=True,
    default=[],
)

CT_INSTALL_TAG_KW: KwargInfo[T.List[T.Union[str, bool]]] = KwargInfo(
    'install_tag',
    ContainerTypeInfo(list, (str, bool)),
    listify=True,
    default=[],
    since='0.60.0',
    convertor=lambda x: [y if isinstance(y, str) else None for y in x],
)

INSTALL_TAG_KW: KwargInfo[T.Optional[str]] = KwargInfo('install_tag', (str, NoneType))

INSTALL_FOLLOW_SYMLINKS: KwargInfo[T.Optional[bool]] = KwargInfo(
    'follow_symlinks',
    (bool, NoneType),
    since='1.3.0',
)

INSTALL_KW = KwargInfo('install', bool, default=False)

CT_INSTALL_DIR_KW: KwargInfo[T.List[T.Union[str, Literal[False]]]] = KwargInfo(
    'install_dir',
    ContainerTypeInfo(list, (str, bool)),
    listify=True,
    default=[],
    validator=lambda x: 'must be `false` if boolean' if True in x else None,
)

CT_BUILD_BY_DEFAULT: KwargInfo[T.Optional[bool]] = KwargInfo('build_by_default', (bool, type(None)), since='0.40.0')

CT_BUILD_ALWAYS: KwargInfo[T.Optional[bool]] = KwargInfo(
    'build_always', (bool, NoneType),
    deprecated='0.47.0',
    deprecated_message='combine build_by_default and build_always_stale instead.',
)

CT_BUILD_ALWAYS_STALE: KwargInfo[T.Optional[bool]] = KwargInfo(
    'build_always_stale', (bool, NoneType),
    since='0.47.0',
)

INSTALL_DIR_KW: KwargInfo[T.Optional[str]] = KwargInfo('install_dir', (str, NoneType))

INCLUDE_DIRECTORIES: KwargInfo[T.List[T.Union[str, IncludeDirs]]] = KwargInfo(
    'include_directories',
    ContainerTypeInfo(list, (str, IncludeDirs)),
    listify=True,
    default=[],
)

DEFAULT_OPTIONS = OVERRIDE_OPTIONS_KW.evolve(name='default_options')

ENV_METHOD_KW = KwargInfo('method', str, default='set', since='0.62.0',
                          validator=in_set_validator({'set', 'prepend', 'append'}))

ENV_SEPARATOR_KW = KwargInfo('separator', str, default=os.pathsep)

DEPENDENCIES_KW: KwargInfo[T.List[Dependency]] = KwargInfo(
    'dependencies',
    # InternalDependency is a subclass of Dependency, but we want to
    # print it in error messages
    ContainerTypeInfo(list, (Dependency, InternalDependency)),
    listify=True,
    default=[],
)

D_MODULE_VERSIONS_KW: KwargInfo[T.List[T.Union[str, int]]] = KwargInfo(
    'd_module_versions',
    ContainerTypeInfo(list, (str, int)),
    listify=True,
    default=[],
)

_link_with_error = '''can only be self-built targets, external dependencies (including libraries) must go in "dependencies".'''

# Allow Dependency for the better error message? But then in other cases it will list this as one of the allowed types!
LINK_WITH_KW: KwargInfo[T.List[T.Union[BothLibraries, SharedLibrary, StaticLibrary, CustomTarget, CustomTargetIndex, Jar, Executable]]] = KwargInfo(
    'link_with',
    ContainerTypeInfo(list, (BothLibraries, SharedLibrary, StaticLibrary, CustomTarget, CustomTargetIndex, Jar, Executable, Dependency)),
    listify=True,
    default=[],
    validator=lambda x: _link_with_error if any(isinstance(i, Dependency) for i in x) else None,
)

def link_whole_validator(values: T.List[T.Union[StaticLibrary, CustomTarget, CustomTargetIndex, Dependency]]) -> T.Optional[str]:
    for l in values:
        if isinstance(l, (CustomTarget, CustomTargetIndex)) and l.links_dynamically():
            return f'{type(l).__name__} returning a shared library is not allowed'
        if isinstance(l, Dependency):
            return _link_with_error
    return None

LINK_WHOLE_KW: KwargInfo[T.List[T.Union[BothLibraries, StaticLibrary, CustomTarget, CustomTargetIndex]]] = KwargInfo(
    'link_whole',
    ContainerTypeInfo(list, (BothLibraries, StaticLibrary, CustomTarget, CustomTargetIndex, Dependency)),
    listify=True,
    default=[],
    validator=link_whole_validator,
)

DEPENDENCY_SOURCES_KW: KwargInfo[T.List[T.Union[str, File, CustomTarget, CustomTargetIndex, GeneratedList]]] = KwargInfo(
    'sources',
    ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList)),
    listify=True,
    default=[],
)

SOURCES_VARARGS = (str, File, CustomTarget, CustomTargetIndex, GeneratedList, StructuredSources, ExtractedObjects, BuildTarget)

BT_SOURCES_KW: KwargInfo[SourcesVarargsType] = KwargInfo(
    'sources',
    (NoneType, ContainerTypeInfo(list, SOURCES_VARARGS)),
    listify=True,
    default=[],
)

VARIABLES_KW: KwargInfo[T.Dict[str, str]] = KwargInfo(
    'variables',
    # str is listified by validator/convertor, cannot use listify=True here because
    # that would listify dict too.
    (str, ContainerTypeInfo(list, str), ContainerTypeInfo(dict, str)), # type: ignore
    validator=variables_validator,
    convertor=variables_convertor,
    default={},
)

PRESERVE_PATH_KW: KwargInfo[bool] = KwargInfo('preserve_path', bool, default=False, since='0.63.0')

TEST_KWS: T.List[KwargInfo] = [
    KwargInfo('args', ContainerTypeInfo(list, (str, File, BuildTarget, CustomTarget, CustomTargetIndex)),
              listify=True, default=[]),
    KwargInfo('should_fail', bool, default=False),
    KwargInfo('timeout', int, default=30),
    KwargInfo('workdir', (str, NoneType), default=None,
              validator=lambda x: 'must be an absolute path' if not os.path.isabs(x) else None),
    KwargInfo('protocol', str,
              default='exitcode',
              validator=in_set_validator({'exitcode', 'tap', 'gtest', 'rust'}),
              since_values={'gtest': '0.55.0', 'rust': '0.57.0'}),
    KwargInfo('priority', int, default=0, since='0.52.0'),
    # TODO: env needs reworks of the way the environment variable holder itself works probably
    ENV_KW,
    DEPENDS_KW.evolve(since='0.46.0'),
    KwargInfo('suite', ContainerTypeInfo(list, str), listify=True, default=['']),  # yes, a list of empty string
    KwargInfo('verbose', bool, default=False, since='0.62.0'),
]

# Cannot have a default value because we need to check that rust_crate_type and
# rust_abi are mutually exclusive.
RUST_CRATE_TYPE_KW: KwargInfo[T.Union[str, None]] = KwargInfo(
    'rust_crate_type', (str, NoneType),
    since='0.42.0',
    since_values={'proc-macro': '0.62.0'},
    deprecated='1.3.0',
    deprecated_message='Use rust_abi or rust.proc_macro() instead.',
    validator=in_set_validator({'bin', 'lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro'}))

RUST_ABI_KW: KwargInfo[T.Union[str, None]] = KwargInfo(
    'rust_abi', (str, NoneType),
    since='1.3.0',
    validator=in_set_validator({'rust', 'c'}))

_VS_MODULE_DEFS_KW: KwargInfo[T.Optional[T.Union[str, File, CustomTarget, CustomTargetIndex]]] = KwargInfo(
    'vs_module_defs',
    (str, File, CustomTarget, CustomTargetIndex, NoneType),
    since_values={CustomTargetIndex: '1.3.0'}
)

_BASE_LANG_KW: KwargInfo[T.List[str]] = KwargInfo(
    'UNKNOWN',
    ContainerTypeInfo(list, (str)),
    listify=True,
    default=[],
)

_LANGUAGE_KWS: T.List[KwargInfo[T.List[str]]] = [
    _BASE_LANG_KW.evolve(name=f'{lang}_args')
    for lang in compilers.all_languages - {'rust', 'vala', 'java'}
]
# Cannot use _BASE_LANG_KW here because Vala is special for types
_LANGUAGE_KWS.append(KwargInfo(
    'vala_args', ContainerTypeInfo(list, (str, File)), listify=True, default=[]))
_LANGUAGE_KWS.append(_BASE_LANG_KW.evolve(name='rust_args', since='0.41.0'))

# We need this deprecated values more than the non-deprecated values. So we'll evolve them out elsewhere.
_JAVA_LANG_KW: KwargInfo[T.List[str]] = _BASE_LANG_KW.evolve(
    name='java_args',
    deprecated='1.3.0',
    deprecated_message='This does not, and never has, done anything. It should be removed'
)

def _objects_validator(vals: T.List[ObjectTypes]) -> T.Optional[str]:
    non_objects: T.List[str] = []

    for val in vals:
        if isinstance(val, (str, File, ExtractedObjects)):
            continue
        else:
            non_objects.extend(o for o in val.get_outputs() if not compilers.is_object(o))

    if non_objects:
        return f'{", ".join(non_objects)!r} are not objects'

    return None


# Applies to all build_target like classes
_ALL_TARGET_KWS: T.List[KwargInfo] = [
    OVERRIDE_OPTIONS_KW,
    KwargInfo('build_by_default', bool, default=True, since='0.38.0'),
    KwargInfo('extra_files', ContainerTypeInfo(list, (str, File)), default=[], listify=True),
    # Accursed. We allow this for backwards compat and warn in the interpreter.
    KwargInfo('install', object, default=False),
    INSTALL_MODE_KW,
    KwargInfo('implicit_include_directories', bool, default=True, since='0.42.0'),
    NATIVE_KW,
    KwargInfo('resources', ContainerTypeInfo(list, str), default=[], listify=True),
    KwargInfo(
        'objects',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList, ExtractedObjects)),
        listify=True,
        default=[],
        validator=_objects_validator,
        since_values={
            ContainerTypeInfo(list, (GeneratedList, CustomTarget, CustomTargetIndex)):
                ('1.1.0', 'generated sources as positional "objects" arguments')
        },
    ),
]


def _name_validator(arg: T.Optional[T.Union[str, T.List]]) -> T.Optional[str]:
    if isinstance(arg, list) and arg:
        return 'must be empty when passed as an array to signify the default value.'
    return None


def _name_suffix_validator(arg: T.Optional[T.Union[str, T.List]]) -> T.Optional[str]:
    if arg == '':
        return 'must not be a empty string. An empty array may be passed if you want Meson to use the default behavior.'
    return _name_validator(arg)


_NAME_PREFIX_KW: KwargInfo[T.Optional[T.Union[str, T.List]]] = KwargInfo(
    'name_prefix',
    (str, NoneType, list),
    validator=_name_validator,
    convertor=lambda x: None if isinstance(x, list) else x,
)


# Applies to all build_target classes except jar
_BUILD_TARGET_KWS: T.List[KwargInfo] = [
    *_ALL_TARGET_KWS,
    *_LANGUAGE_KWS,
    BT_SOURCES_KW,
    INCLUDE_DIRECTORIES.evolve(name='d_import_dirs'),
    _NAME_PREFIX_KW,
    _NAME_PREFIX_KW.evolve(name='name_suffix', validator=_name_suffix_validator),
    RUST_CRATE_TYPE_KW,
    KwargInfo('d_debug', ContainerTypeInfo(list, (str, int)), default=[], listify=True),
    D_MODULE_VERSIONS_KW,
    KwargInfo('d_unittest', bool, default=False),
    KwargInfo(
        'rust_dependency_map',
        ContainerTypeInfo(dict, str),
        default={},
        since='1.2.0',
    ),
    KwargInfo('build_rpath', str, default='', since='0.42.0'),
    KwargInfo(
        'gnu_symbol_visibility',
        str,
        default='',
        validator=in_set_validator({'', 'default', 'internal', 'hidden', 'protected', 'inlineshidden'}),
        since='0.48.0',
    ),
    KwargInfo('install_rpath', str, default=''),
    KwargInfo(
        'link_depends',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, BuildTarget)),
        default=[],
        listify=True,
    ),
    KwargInfo(
        'link_language',
        (str, NoneType),
        validator=in_set_validator(set(compilers.all_languages)),
        since='0.51.0',
    ),
]

def _validate_win_subsystem(value: T.Optional[str]) -> T.Optional[str]:
    if value is not None:
        if re.fullmatch(r'(boot_application|console|efi_application|efi_boot_service_driver|efi_rom|efi_runtime_driver|native|posix|windows)(,\d+(\.\d+)?)?', value) is None:
            return f'Invalid value for win_subsystem: {value}.'
    return None


def _validate_darwin_versions(darwin_versions: T.List[T.Union[str, int]]) -> T.Optional[str]:
    if len(darwin_versions) > 2:
        return f"Must contain between 0 and 2 elements, not {len(darwin_versions)}"
    if len(darwin_versions) == 1:
        darwin_versions = 2 * darwin_versions
    for v in darwin_versions:
        if isinstance(v, int):
            v = str(v)
        if not re.fullmatch(r'[0-9]+(\.[0-9]+){0,2}', v):
            return 'must be X.Y.Z where X, Y, Z are numbers, and Y and Z are optional'
        try:
            parts = v.split('.')
        except ValueError:
            return f'badly formed value: "{v}, not in X.Y.Z form'
        if len(parts) in {1, 2, 3} and int(parts[0]) > 65535:
            return 'must be X.Y.Z where X is [0, 65535] and Y, Z are optional'
        if len(parts) in {2, 3} and int(parts[1]) > 255:
            return 'must be X.Y.Z where Y is [0, 255] and Y, Z are optional'
        if len(parts) == 3 and int(parts[2]) > 255:
            return 'must be X.Y.Z where Z is [0, 255] and Y, Z are optional'
    return None


def _convert_darwin_versions(val: T.List[T.Union[str, int]]) -> T.Optional[T.Tuple[str, str]]:
    if not val:
        return None
    elif len(val) == 1:
        v = str(val[0])
        return (v, v)
    return (str(val[0]), str(val[1]))


_DARWIN_VERSIONS_KW: KwargInfo[T.List[T.Union[str, int]]] = KwargInfo(
    'darwin_versions',
    ContainerTypeInfo(list, (str, int)),
    default=[],
    listify=True,
    validator=_validate_darwin_versions,
    convertor=_convert_darwin_versions,
    since='0.48.0',
)

# Arguments exclusive to Executable. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_EXECUTABLE_KWS: T.List[KwargInfo] = [
    KwargInfo('export_dynamic', (bool, NoneType), since='0.45.0'),
    KwargInfo('gui_app', (bool, NoneType), deprecated='0.56.0', deprecated_message="Use 'win_subsystem' instead"),
    KwargInfo('implib', (bool, str, NoneType), since='0.42.0'),
    KwargInfo('pie', (bool, NoneType)),
    KwargInfo(
        'win_subsystem',
        (str, NoneType),
        convertor=lambda x: x.lower() if isinstance(x, str) else None,
        validator=_validate_win_subsystem,
    ),
]

# The total list of arguments used by Executable
EXECUTABLE_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_EXECUTABLE_KWS,
    _VS_MODULE_DEFS_KW.evolve(since='1.3.0', since_values=None),
    _JAVA_LANG_KW,
]

# Arguments exclusive to library types
_EXCLUSIVE_LIB_KWS: T.List[KwargInfo] = [
    RUST_ABI_KW,
]

# Arguments exclusive to StaticLibrary. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_STATIC_LIB_KWS: T.List[KwargInfo] = [
    KwargInfo('prelink', bool, default=False, since='0.57.0'),
    KwargInfo('pic', (bool, NoneType), since='0.36.0'),
]

# The total list of arguments used by StaticLibrary
STATIC_LIB_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _JAVA_LANG_KW,
]

# Arguments exclusive to SharedLibrary. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_SHARED_LIB_KWS: T.List[KwargInfo] = [
    _DARWIN_VERSIONS_KW,
    KwargInfo('soversion', (str, int, NoneType), convertor=lambda x: str(x) if x is not None else None),
    KwargInfo('version', (str, NoneType), validator=_validate_shlib_version),
]

# The total list of arguments used by SharedLibrary
SHARED_LIB_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments exclusive to SharedModule. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_SHARED_MOD_KWS: T.List[KwargInfo] = []

# The total list of arguments used by SharedModule
SHARED_MOD_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments exclusive to JAR. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_JAR_KWS: T.List[KwargInfo] = [
    KwargInfo('main_class', str, default=''),
    KwargInfo('java_resources', (StructuredSources, NoneType), since='0.62.0'),
    _JAVA_LANG_KW.evolve(deprecated=None, deprecated_message=None),
]

# The total list of arguments used by JAR
JAR_KWS = [
    *_ALL_TARGET_KWS,
    *_EXCLUSIVE_JAR_KWS,
    KwargInfo(
        'sources',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList, ExtractedObjects, BuildTarget)),
        listify=True,
        default=[],
    ),
    *[a.evolve(deprecated='1.3.0', deprecated_message='This argument has never done anything in jar(), and should be removed')
      for a in _LANGUAGE_KWS],
]

_SHARED_STATIC_ARGS: T.List[KwargInfo[T.List[str]]] = [
    *[l.evolve(name=l.name.replace('_', '_static_'), since='1.3.0')
      for l in _LANGUAGE_KWS],
    *[l.evolve(name=l.name.replace('_', '_shared_'), since='1.3.0')
      for l in _LANGUAGE_KWS],
]

# Arguments used by both_library and library
LIBRARY_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_LIB_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_SHARED_STATIC_ARGS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments used by build_Target
BUILD_TARGET_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_EXCLUSIVE_EXECUTABLE_KWS,
    *_SHARED_STATIC_ARGS,
    *[a.evolve(deprecated='1.3.0', deprecated_message='The use of "jar" in "build_target()" is deprecated, and this argument is only used by jar()')
      for a in _EXCLUSIVE_JAR_KWS],
    KwargInfo(
        'target_type',
        str,
        required=True,
        validator=in_set_validator({
            'executable', 'shared_library', 'static_library', 'shared_module',
            'both_libraries', 'library', 'jar'
        }),
        since_values={
            'shared_module': '0.51.0',
        },
        deprecated_values={
            'jar': ('1.3.0', 'use the "jar()" function directly'),
        }
    )
]

def _pkgconfig_define_convertor(x: T.List[str]) -> PkgConfigDefineType:
    if x:
        keys = itertools.islice(x, 0, None, 2)
        vals = itertools.islice(x, 1, None, 2)
        return tuple(zip(keys, vals))
    return None

PKGCONFIG_DEFINE_KW: KwargInfo = KwargInfo(
    'pkgconfig_define',
    ContainerTypeInfo(list, str, pairs=True),
    default=[],
    convertor=_pkgconfig_define_convertor,
)

"""

```