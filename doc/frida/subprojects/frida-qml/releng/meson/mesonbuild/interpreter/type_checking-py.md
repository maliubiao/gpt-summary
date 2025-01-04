Response:
My thinking process to answer the request about `type_checking.py` goes like this:

1. **Understand the Core Purpose:** The file name itself, `type_checking.py`, immediately suggests its main function: enforcing type constraints within the Frida build system. The initial comment confirms this, mentioning "helpers for strict type checking."  This means the code defines mechanisms to ensure that function arguments and other data have the expected types.

2. **Identify Key Concepts:** I scanned the code for recurring patterns and important classes/functions. I noticed:
    * **`KwargInfo`:**  This class appears to be central. It holds information about keyword arguments, including their expected type, validators, and converters. This is the primary way type checking is implemented.
    * **Validators (`_validate_*`):** Functions like `_language_validator`, `_install_mode_validator`, etc., are responsible for performing more complex checks beyond basic type matching. They ensure that the *values* of arguments are valid within the context of the build system.
    * **Converters (`_convert_*`):** Functions like `_install_mode_convertor` transform the input values into the desired internal representation. This handles cases where the user input format differs from the internal data structure.
    * **`ContainerTypeInfo`:** This helps define the expected types for collections (lists, dictionaries) and specify the allowed types of their elements.
    * **Specific Keyword Argument Definitions:**  Lots of variables like `LANGUAGE_KW`, `INSTALL_MODE_KW`, etc., are instances of `KwargInfo`, each representing a specific argument used in Frida's build definitions.
    * **Categorization of Keyword Arguments:** The code groups keyword arguments by the Meson functions they relate to (e.g., `TEST_KWS` for testing functions, `EXECUTABLE_KWS` for executable definitions).

3. **Relate to Frida's Functionality:** Knowing Frida's purpose as a dynamic instrumentation tool is crucial. I considered how type checking in the build system supports that:
    * **Correct Build Configuration:** Ensuring arguments like compiler flags, library dependencies, and source file lists are correctly specified is vital for building Frida components that interact with target processes.
    * **Preventing Errors:** Type checking catches mistakes early in the build process, saving developers from runtime errors caused by misconfigured builds.
    * **Consistency:** It enforces a consistent way of defining build steps and dependencies.

4. **Address Specific Questions:** I then systematically addressed each part of the request:

    * **Functionality:**  I summarized the core function (type checking) and then listed the specific mechanisms (validators, converters, `KwargInfo`).
    * **Relationship to Reversing:** I connected type checking to the process of building Frida, which is essential for reverse engineering using Frida. I gave examples of how specific keyword arguments relate to manipulating target processes (e.g., `link_with` for hooking libraries).
    * **Binary/Kernel/Framework Knowledge:** I identified keyword arguments and validators that touch upon lower-level aspects, such as linking (`link_with`, `link_whole`), architecture (`native`), and operating system specifics (`win_subsystem`, `darwin_versions`).
    * **Logical Inference:**  I chose the `_install_mode_validator` as a good example of how the code performs logical checks on the structure and content of an argument. I provided an input and the expected error output.
    * **User/Programming Errors:**  I focused on common mistakes users might make when writing Meson build files, such as incorrect types for arguments or invalid string formats. I provided examples related to source files and library dependencies.
    * **User Operation to Reach the Code:** I described the typical workflow of a Frida developer and how incorrect build definitions would trigger the type checking logic in this file. I used the example of a user making a mistake in a `meson.build` file.

5. **Structure and Refine:** I organized my answer logically, using headings and bullet points to make it easier to read. I reviewed the code snippets to ensure accuracy and clarity. I tried to use precise language and avoid jargon where possible. For instance, instead of just saying "it checks types," I elaborated on *how* it checks types (validators, converters, `KwargInfo`).

By following this systematic approach, I could break down the complex code into understandable components and explain its role within the larger Frida project, specifically addressing all the points raised in the request.这是 frida 动态 instrumentation 工具中一个名为 `type_checking.py` 的源代码文件，位于 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/` 目录下。它的主要功能是为 Meson 构建系统中的解释器提供**严格的类型检查辅助功能**。这意味着它定义了一系列工具和规则，用于验证 Meson 构建文件中函数调用时传递的参数是否符合预期的类型和格式。

以下是该文件的功能详细列表，并结合逆向、底层、内核、框架知识以及常见错误进行举例说明：

**主要功能:**

1. **定义 `KwargInfo` 类:**  这是核心类，用于描述函数调用的关键字参数。它包含了参数的名称、预期类型、默认值、验证器（validator）和转换器（convertor）等信息。

2. **提供各种类型验证器 (Validators):**  定义了一系列函数（以 `_validate_` 开头），用于执行更复杂的参数值检查，超出简单的类型匹配。例如：
   * `in_set_validator`: 检查参数值是否在给定的集合中。
   * `_language_validator`: 验证 `language` 参数是否是已知的编程语言。
   * `_install_mode_validator`: 验证文件安装模式的字符串格式。
   * `variables_validator`: 验证环境变量的格式。
   * `_output_validator`: 验证输出文件名的格式。
   * `link_whole_validator`: 验证 `link_whole` 参数中库的类型。
   * 以及其他针对特定参数的验证器，如 `_validate_shlib_version` (共享库版本), `_validate_win_subsystem` (Windows 子系统), `_validate_darwin_versions` (macOS 版本)。

3. **提供类型转换器 (Convertors):** 定义了一系列函数（通常以 `_convert_` 结尾），用于将用户提供的参数值转换为 Meson 内部使用的格式。例如：
   * `_install_mode_convertor`: 将安装模式的字符串或数字列表转换为 `FileMode` 对象。
   * `variables_convertor`: 将环境变量的不同表示形式（字符串、列表、字典）转换为字典。
   * `_lower_strlist`: 将字符串列表转换为小写。
   * `env_convertor`: 将环境变量的不同表示形式转换为 `EnvironmentVariables` 对象。
   * `_override_options_convertor`: 将 `override_options` 参数转换为 `OptionKey` 到值的字典。
   * `_pkgconfig_define_convertor`: 将 pkg-config 定义转换为元组。

4. **定义预定义的 `KwargInfo` 实例:**  为 Meson 中常用的关键字参数创建了 `KwargInfo` 实例，并指定了它们的类型、验证器、转换器等。这些实例以 `*_KW` 结尾，例如 `LANGUAGE_KW`, `INSTALL_MODE_KW`, `SOURCES_VARARGS`, `DEPENDENCIES_KW` 等。这些预定义的实例涵盖了构建目标（executable, library）、测试、依赖项等多个方面。

5. **组织特定构建目标和功能的关键字参数:** 将相关的 `KwargInfo` 实例分组到一起，形成了针对不同构建目标（如 `EXECUTABLE_KWS`, `SHARED_LIB_KWS`, `STATIC_LIB_KWS`, `JAR_KWS`）和功能（如 `TEST_KWS`）的参数列表。这使得在 Meson 解释器中更容易查找和应用正确的类型检查规则。

**与逆向的关系 (举例说明):**

* **`LINK_WITH_KW` 和 `LINK_WHOLE_KW`:** 这两个关键字参数用于指定链接时需要包含的库。在逆向工程中，Frida 经常需要与目标进程的库进行交互（例如，通过 hook 函数）。通过 `link_with` 可以链接到外部库，而 `link_whole` 用于链接静态库，确保库中的所有符号都被包含进来。
   * **例子:** 假设你需要编写一个 Frida 脚本，通过 hook 目标进程中的 `libc.so` 中的 `malloc` 函数来追踪内存分配。在编译 Frida 模块时，你可能不需要显式地链接 `libc.so`，因为它通常是默认链接的。但是，如果你需要链接到其他的自定义库或特定的静态库，就需要使用 `link_with` 或 `link_whole` 在 `meson.build` 文件中指定。

**涉及二进制底层、Linux, Android 内核及框架的知识 (举例说明):**

* **`NATIVE_KW`:**  指定构建的目标架构是主机架构还是构建架构。这与交叉编译的概念相关，在逆向 Android 应用时非常重要，因为你需要针对 Android 设备的 ARM 架构进行编译。
   * **例子:** 在为 Android 设备构建 Frida Gadget 时，你需要确保 `native` 参数设置为 `False`（或不设置，默认为 `False`），以进行交叉编译到 ARM 架构。如果设置为 `True`，则会尝试在你的开发机上（例如 x86_64）构建，这显然是错误的。
* **`win_subsystem` (在 `EXECUTABLE_KWS` 中):**  用于指定 Windows 可执行文件的子系统（例如，console, windows）。这直接影响到可执行文件的 PE 头部的设置，决定了操作系统如何加载和执行该程序。
   * **例子:**  如果你正在逆向一个 Windows GUI 应用程序，并且需要构建一个与之交互的 Frida 模块，那么理解 `win_subsystem` 参数可以帮助你配置生成的模块，使其与目标进程的运行环境相匹配。
* **`darwin_versions` (在 `SHARED_LIB_KWS` 中):**  用于指定 macOS 共享库的最低支持的操作系统版本。这涉及到 macOS 的动态链接器和操作系统版本控制机制。
   * **例子:**  在逆向 macOS 软件时，你可能需要构建针对特定 macOS 版本的 Frida 模块。`darwin_versions` 参数可以确保你的模块只在兼容的系统上运行。
* **`install_mode`:**  指定安装文件的权限。这直接涉及到 Linux 的文件系统权限模型。
   * **例子:** 当你使用 Frida 将自定义的 Agent 部署到目标 Android 设备时，你需要确保该 Agent 具有执行权限。`install_mode` 参数可以控制安装后文件的权限位。

**逻辑推理 (假设输入与输出):**

* **`_install_mode_validator`:**
    * **假设输入:** `['rwxr-xr-x', 'user', 644]`
    * **逻辑:** 验证第一个元素是合法的权限字符串，后续元素是用户或组名，以及可选的数字权限模式。
    * **预期输出:** `None` (如果输入合法)
    * **假设输入 (错误):** `['rwxr-xr', 'user']`
    * **预期输出:**  `'permissions string must be exactly 9 characters in the form rwxr-xr-x, got 8'` (因为权限字符串长度不正确)

**用户或编程常见的使用错误 (举例说明):**

* **`SOURCES_VARARGS` 和 `BT_SOURCES_KW`:**  指定构建目标的源文件。常见的错误是提供了错误的类型，例如传递了一个目录字符串而不是一个文件对象或文件名字符串。
   * **例子:** 用户在 `meson.build` 文件中定义一个可执行目标时，错误地将源文件参数写成了目录路径：
     ```meson
     executable('my_program', 'src_dir', ...) # 错误，'src_dir' 应该是一个文件
     ```
     `type_checking.py` 中的 `BT_SOURCES_KW` 定义了 `sources` 参数应该接受的类型，当 Meson 解释器解析到这里时，会调用相应的验证逻辑，发现 'src_dir' 不是允许的类型，从而报错。

* **`DEPENDENCIES_KW` 和 `LINK_WITH_KW` 的混淆:** 用户可能会将外部依赖项（例如，通过 `dependency()` 函数找到的库）错误地放在 `link_with` 中，或者将内部构建的目标放在 `dependencies` 中。
   * **例子:**
     ```meson
     # 假设 'mylib' 是一个通过 dependency('mylib') 找到的外部库
     executable('my_program', 'main.c', link_with: mylib) # 错误，外部依赖应该放在 dependencies
     ```
     `LINK_WITH_KW` 的验证器会检查 `link_with` 中的元素是否是内部构建的目标，如果发现外部依赖项，则会产生错误消息，提示用户应该使用 `dependencies`。

* **`INSTALL_MODE_KW` 的格式错误:** 用户可能提供了不符合预期格式的安装模式字符串。
   * **例子:**
     ```meson
     install_data('my_config', install_dir: '/etc', install_mode: 'rwxrwxrwxz') # 错误，'z' 不是合法的权限字符
     ```
     `_install_mode_validator` 会检查权限字符串的每个字符是否合法，并报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:**  用户开始一个 Frida 模块的开发，或者修改现有的构建配置，编写或修改 `meson.build` 文件。这个文件中包含了使用 Meson 提供的各种函数（如 `executable`, `shared_library`, `custom_target` 等）来定义构建目标和配置的信息。

2. **用户运行 `meson` 命令配置构建:** 用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建。Meson 会读取 `meson.build` 文件并解析其中的内容。

3. **Meson 解释器执行 `meson.build`:** Meson 的解释器会逐行执行 `meson.build` 文件中的代码。当遇到函数调用时，例如 `executable('my_agent', 'agent.c', dependencies: ..., link_with: ...)`，解释器需要检查传递给这些函数的参数是否有效。

4. **调用类型检查逻辑:** 对于每个函数的关键字参数，Meson 解释器会查找该参数对应的 `KwargInfo` 实例（在 `type_checking.py` 中定义）。然后，它会：
   * **检查参数类型:**  验证参数的 Python 类型是否与 `KwargInfo` 中指定的类型一致。
   * **调用验证器 (Validator):** 如果定义了验证器函数，则会调用该函数来执行更细致的检查，例如字符串格式、取值范围等。
   * **调用转换器 (Convertor):** 如果定义了转换器函数，则会调用该函数将用户提供的参数值转换为 Meson 内部使用的格式。

5. **发现类型错误并报错:** 如果在类型检查或验证阶段发现错误，Meson 解释器会生成相应的错误消息，指出哪个参数出现了问题以及错误的原因。例如，如果用户传递给 `sources` 参数的不是字符串或文件对象，就会触发类型错误。

6. **调试线索:**  当用户收到与类型相关的 Meson 错误时，`type_checking.py` 文件就是调试的重要线索。错误消息通常会指明哪个参数出现了问题。用户可以查看 `type_checking.py` 中该参数的 `KwargInfo` 定义，了解期望的类型、验证规则和转换逻辑，从而找到 `meson.build` 文件中错误的原因。

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/type_checking.py` 文件是 Frida 构建系统的重要组成部分，它通过定义类型检查规则，帮助开发者在构建阶段尽早发现 `meson.build` 文件中的错误，保证构建过程的正确性和可靠性，这对于像 Frida 这样复杂的工具链来说至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/type_checking.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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