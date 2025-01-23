Response:
The user wants a summary of the functionalities implemented in the provided Python code. I need to go through each class and its methods and explain what they do. Specifically, I need to identify connections to:
1. **Reverse engineering**: Anything that helps in understanding or manipulating compiled code.
2. **Binary, Linux, Android kernel/framework**: Operations close to the system level.
3. **Logic/Reasoning**:  Conditional operations or data transformations. I'll create example inputs and outputs for these.
4. **Common User Errors**:  Mistakes a user might make when using these functionalities.
5. **Debugging Flow**: How a user's actions might lead to this code being executed.

Here's a breakdown of the classes and their core functions:

*   **`extract_required_kwarg`**:  Parses the `required` keyword argument, which can be a boolean or a feature option. This is related to build system configuration.
*   **`extract_search_dirs`**:  Validates and expands search directory paths. This is part of the build system's dependency resolution.
*   **`FeatureOptionHolder`**:  Manages the state of a user-configurable feature (enabled, disabled, auto). This directly impacts the build process based on user choices.
*   **`RunProcess`**:  Executes external commands. This is crucial for interacting with build tools, compilers, and potentially reverse engineering tools.
*   **`EnvironmentVariablesHolder`**:  Manages environment variables. This influences how commands are executed and can be used to control aspects of the target system.
*   **`ConfigurationDataHolder`**:  Stores configuration data used during the build process. This is not directly related to reverse engineering, but it affects the generated binaries.
*   **`DependencyHolder`**:  Represents a dependency (e.g., a library). It provides methods to query information about the dependency. This can be relevant for understanding how different components are linked.
*   **`_ExternalProgramHolder` / `ExternalProgramHolder`**:  Represents an external executable. Essential for running tools during the build.
*   **`ExternalLibraryHolder`**: Represents an external library. Crucial for linking against pre-built components.
*   **`MachineHolder`**:  Provides information about the target machine. This is important for cross-compilation and understanding the environment where the built software will run.
*   **`IncludeDirsHolder`**:  Represents include directories. Important for compilation.
*   **`FileHolder`**:  Represents a file.
*   **`HeadersHolder`**: Represents header files.
*   **`DataHolder`**: Represents data files.
*   **`SymlinkDataHolder`**: Represents symbolic links.
*   **`InstallDirHolder`**: Represents installation directories.
*   **`ManHolder`**: Represents man pages.
*   **`EmptyDirHolder`**: Represents empty directories.
*   **`GeneratedObjectsHolder`**: Represents generated object files.
*   **`Test`**: Represents a test case.

Now, I'll formulate the summary focusing on the requested connections.
这是一个定义了多种用于在 Frida 动态Instrumentation 工具的构建过程中表示和操作不同对象的类的 Python 源代码文件。这些对象主要用于 Meson 构建系统中的解释器环境。

**主要功能归纳:**

1. **Feature Option 管理 (`FeatureOptionHolder`):**  允许脚本操作和查询用户定义的功能选项的状态（启用、禁用、自动）。
2. **进程执行 (`RunProcess`):**  封装了执行外部命令的操作，并提供了访问其返回码、标准输出和标准错误的方法。
3. **环境变量管理 (`EnvironmentVariablesHolder`):**  提供了一种在构建过程中设置、取消设置、追加和前置环境变量的方法。
4. **配置数据管理 (`ConfigurationDataHolder`):**  用于存储和操作构建配置数据，这些数据可以在构建过程中被使用。
5. **依赖项表示 (`DependencyHolder`):**  表示项目依赖的库或其他组件，并提供查询依赖项信息（如是否找到、版本、名称）和获取特定部分信息的方法。
6. **外部程序表示 (`ExternalProgramHolder`):**  表示在构建过程中使用的外部可执行程序，并提供查询程序信息（如是否找到、路径、版本）的方法。
7. **外部库表示 (`ExternalLibraryHolder`):**  表示项目依赖的外部库文件。
8. **目标机器信息 (`MachineHolder`):**  提供关于目标构建机器的架构和操作系统信息。
9. **文件和目录表示 (`FileHolder`, `IncludeDirsHolder`, `HeadersHolder`, `DataHolder`, `SymlinkDataHolder`, `InstallDirHolder`, `ManHolder`, `EmptyDirHolder`):**  表示构建过程中涉及的各种文件和目录。
10. **生成对象表示 (`GeneratedObjectsHolder`):** 表示从特定构建步骤中提取的生成对象。
11. **测试用例表示 (`Test`):** 表示构建系统中定义的测试用例及其相关属性。

**与逆向方法的关系及举例:**

虽然这个文件本身不直接包含逆向分析的代码，但它所提供的构建系统功能对于构建和测试逆向工程工具至关重要。

*   **构建 Frida 自身:** Frida 是一个动态 instrumentation 工具，这个文件是 Frida 构建系统的一部分。逆向工程师可以使用 Frida 来分析二进制程序。因此，这个文件间接地服务于逆向方法。
*   **执行逆向工具:** `RunProcess` 类可以被用来在构建过程中执行其他逆向分析工具，例如反汇编器、调试器或静态分析器。
    *   **举例:** 假设构建脚本需要在构建后运行 `objdump` 来检查生成的二进制文件的符号表。可以使用 `RunProcess` 执行 `objdump` 命令，并将输出保存下来进行进一步处理或验证。
*   **依赖项处理:**  在构建依赖于特定逆向工程库的项目时，`DependencyHolder` 可以用来查找和链接这些库。
    *   **举例:**  一个 Frida 模块可能依赖于 `capstone` 反汇编库。构建系统会使用 `DependencyHolder` 来查找 `capstone` 库，并将其链接到 Frida 模块中。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

*   **二进制底层:**  虽然代码本身是 Python，但它操作的对象（如可执行文件、库文件）以及构建过程的最终产物都是二进制文件。
    *   **举例:** `ExternalProgramHolder` 代表的外部程序通常是编译后的二进制可执行文件。
*   **Linux:**  构建系统需要在 Linux 环境下运行，并且可能需要处理特定于 Linux 的构建选项和工具。
    *   **举例:**  `RunProcess` 执行的命令很可能是在 Linux 终端中使用的命令。
*   **Android 内核及框架:** Frida 主要用于 Android 平台的动态 instrumentation。虽然这个文件没有直接操作 Android 内核代码，但它参与了构建 Frida 及其组件的过程，这些组件最终会在 Android 系统上运行并与 Android 框架进行交互。
    *   **举例:**  Frida Agent 需要注入到 Android 应用程序进程中，这涉及到 Android 的进程模型和内存管理。构建系统需要正确地构建 Frida Agent，以便它能够在 Android 环境中正常工作。

**逻辑推理及假设输入与输出:**

*   **`FeatureOptionHolder.require_method`:**
    *   **假设输入:**  一个 `FeatureOptionHolder` 对象，其 `value` 为 "enabled"，`require_method` 的参数 `args` 为 `(False,)`，`kwargs` 为 `{'error_message': 'Feature is required'}`。
    *   **输出:**  抛出一个 `InterpreterException`，错误消息为 "Feature <feature_name> cannot be enabled: Feature is required"。这是因为条件为 `False`，表示该功能是必需的，但当前状态是启用，与需求冲突。
*   **`RunProcess.run_command`:**
    *   **假设输入:** `cmd` 为一个表示 `ls` 命令的 `ExternalProgram` 对象，`args` 为 `['-l']`，其他参数为有效的目录和环境信息。
    *   **输出:**  返回一个元组 `(returncode, stdout, stderr)`，其中 `returncode` 为 0（如果 `ls` 命令执行成功），`stdout` 包含目录列表的详细信息，`stderr` 为空字符串。

**涉及用户或编程常见的使用错误及举例:**

*   **`extract_search_dirs`:** 用户可能会提供一个相对路径作为搜索目录。
    *   **举例:** 用户在构建脚本中设置 `dirs: ['my_libs']`。这会导致 `extract_search_dirs` 抛出 `InvalidCode` 异常，因为 'my_libs' 不是绝对路径。
*   **`ConfigurationDataHolder.set_method`:**  在配置数据对象被使用后尝试修改它。
    *   **举例:**  用户在 `configure_file` 函数之后再次调用 `config.set()`，如果 `configure_file` 已经使用了该配置对象，则会抛出 `InterpreterException`。
*   **`DependencyHolder.get_pkgconfig_variable`:**  尝试在一个非 pkg-config 依赖项上调用此方法。
    *   **举例:**  如果一个依赖项是通过 `find_library` 找到的普通库文件，而不是通过 pkg-config 文件找到的，调用 `dep.get_pkgconfig_variable('some_var')` 会抛出 `InvalidArguments` 异常。

**用户操作如何一步步的到达这里作为调试线索:**

当用户运行 `meson` 命令来配置 Frida 的构建时，Meson 构建系统会解析 `meson.build` 文件。这些文件中包含了调用各种 Meson 内置函数来定义构建过程的指令。

1. **配置阶段开始:** 用户执行 `meson setup builddir` 命令。
2. **解析 `meson.build`:** Meson 解析项目根目录以及子目录下的 `meson.build` 文件。
3. **遇到相关函数调用:**  在 `meson.build` 文件中，可能会调用以下函数，这些函数会间接或直接地使用到 `interpreterobjects.py` 中定义的类：
    *   `feature()`:  创建用户可配置的功能选项，会创建 `FeatureOptionHolder` 对象。
    *   `run_command()`:  执行外部命令，会创建 `RunProcess` 对象。
    *   `environment()`:  操作环境变量，会创建 `EnvironmentVariablesHolder` 对象。
    *   `configuration_data()`:  创建配置数据对象，会创建 `ConfigurationDataHolder` 对象。
    *   `dependency()` 或 `find_dependency()`:  查找依赖项，会创建 `DependencyHolder` 对象。
    *   `find_program()`:  查找外部程序，会创建 `ExternalProgramHolder` 对象。
    *   `declare_dependency()`:  声明内部依赖项。
    *   `executable()`, `library()`:  定义可执行文件和库，可能会间接创建与文件和目录相关的 Holder 对象。
    *   `test()`: 定义测试用例，会创建 `Test` 对象。
4. **解释器执行:** Meson 的解释器会执行这些函数调用，并创建相应的对象。例如，当解释器执行 `feature('my_feature', ...)` 时，会创建一个 `FeatureOptionHolder` 实例。
5. **错误发生 (调试线索):** 如果在 `meson.build` 文件中使用了错误的值或不当的方式调用了这些函数，就会触发 `interpreterobjects.py` 中定义的类的错误处理逻辑，例如抛出 `InterpreterException` 或 `InvalidArguments`。调试时，可以检查 Meson 的输出信息，它通常会指出错误发生的文件和行号，以及相关的错误消息，这些信息可以帮助开发者追溯到具体的 `meson.build` 文件调用以及 `interpreterobjects.py` 中的哪个方法触发了错误。

总结来说，`interpreterobjects.py` 定义了 Meson 构建系统中用于表示各种构建元素的 Python 对象，这些对象的功能涵盖了从用户选项管理到外部命令执行的各个方面，是 Meson 构建系统核心功能的重要组成部分。对于 Frida 这样的动态 instrumentation 工具，它提供的构建能力对于工具本身的构建和依赖项管理至关重要。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
from __future__ import annotations
import os
import shlex
import subprocess
import copy
import textwrap

from pathlib import Path, PurePath

from .. import mesonlib
from .. import coredata
from .. import build
from .. import mlog

from ..modules import ModuleReturnValue, ModuleObject, ModuleState, ExtensionModule
from ..backend.backends import TestProtocol
from ..interpreterbase import (
                               ContainerTypeInfo, KwargInfo, MesonOperator,
                               MesonInterpreterObject, ObjectHolder, MutableInterpreterObject,
                               FeatureNew, FeatureDeprecated,
                               typed_pos_args, typed_kwargs, typed_operator,
                               noArgsFlattening, noPosargs, noKwargs, unholder_return,
                               flatten, resolve_second_level_holders, InterpreterException, InvalidArguments, InvalidCode)
from ..interpreter.type_checking import NoneType, ENV_KW, ENV_SEPARATOR_KW, PKGCONFIG_DEFINE_KW
from ..dependencies import Dependency, ExternalLibrary, InternalDependency
from ..programs import ExternalProgram
from ..mesonlib import HoldableObject, OptionKey, listify, Popen_safe

import typing as T

if T.TYPE_CHECKING:
    from . import kwargs
    from ..cmake.interpreter import CMakeInterpreter
    from ..envconfig import MachineInfo
    from ..interpreterbase import FeatureCheckBase, InterpreterObject, SubProject, TYPE_var, TYPE_kwargs, TYPE_nvar, TYPE_nkwargs
    from .interpreter import Interpreter

    from typing_extensions import TypedDict

    class EnvironmentSeparatorKW(TypedDict):

        separator: str

_ERROR_MSG_KW: KwargInfo[T.Optional[str]] = KwargInfo('error_message', (str, NoneType))


def extract_required_kwarg(kwargs: 'kwargs.ExtractRequired',
                           subproject: 'SubProject',
                           feature_check: T.Optional[FeatureCheckBase] = None,
                           default: bool = True) -> T.Tuple[bool, bool, T.Optional[str]]:
    val = kwargs.get('required', default)
    disabled = False
    required = False
    feature: T.Optional[str] = None
    if isinstance(val, coredata.UserFeatureOption):
        if not feature_check:
            feature_check = FeatureNew('User option "feature"', '0.47.0')
        feature_check.use(subproject)
        feature = val.name
        if val.is_disabled():
            disabled = True
        elif val.is_enabled():
            required = True
    elif isinstance(val, bool):
        required = val
    else:
        raise InterpreterException('required keyword argument must be boolean or a feature option')

    # Keep boolean value in kwargs to simplify other places where this kwarg is
    # checked.
    # TODO: this should be removed, and those callers should learn about FeatureOptions
    kwargs['required'] = required

    return disabled, required, feature

def extract_search_dirs(kwargs: 'kwargs.ExtractSearchDirs') -> T.List[str]:
    search_dirs_str = mesonlib.stringlistify(kwargs.get('dirs', []))
    search_dirs = [Path(d).expanduser() for d in search_dirs_str]
    for d in search_dirs:
        if mesonlib.is_windows() and d.root.startswith('\\'):
            # a Unix-path starting with `/` that is not absolute on Windows.
            # discard without failing for end-user ease of cross-platform directory arrays
            continue
        if not d.is_absolute():
            raise InvalidCode(f'Search directory {d} is not an absolute path.')
    return [str(s) for s in search_dirs]

class FeatureOptionHolder(ObjectHolder[coredata.UserFeatureOption]):
    def __init__(self, option: coredata.UserFeatureOption, interpreter: 'Interpreter'):
        super().__init__(option, interpreter)
        if option and option.is_auto():
            # TODO: we need to cast here because options is not a TypedDict
            auto = T.cast('coredata.UserFeatureOption', self.env.coredata.options[OptionKey('auto_features')])
            self.held_object = copy.copy(auto)
            self.held_object.name = option.name
        self.methods.update({'enabled': self.enabled_method,
                             'disabled': self.disabled_method,
                             'allowed': self.allowed_method,
                             'auto': self.auto_method,
                             'require': self.require_method,
                             'disable_auto_if': self.disable_auto_if_method,
                             'enable_auto_if': self.enable_auto_if_method,
                             'disable_if': self.disable_if_method,
                             'enable_if': self.enable_if_method,
                             })

    @property
    def value(self) -> str:
        return 'disabled' if not self.held_object else self.held_object.value

    def as_disabled(self) -> coredata.UserFeatureOption:
        disabled = copy.deepcopy(self.held_object)
        disabled.value = 'disabled'
        return disabled

    def as_enabled(self) -> coredata.UserFeatureOption:
        enabled = copy.deepcopy(self.held_object)
        enabled.value = 'enabled'
        return enabled

    @noPosargs
    @noKwargs
    def enabled_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'enabled'

    @noPosargs
    @noKwargs
    def disabled_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'disabled'

    @noPosargs
    @noKwargs
    @FeatureNew('feature_option.allowed()', '0.59.0')
    def allowed_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value != 'disabled'

    @noPosargs
    @noKwargs
    def auto_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.value == 'auto'

    def _disable_if(self, condition: bool, message: T.Optional[str]) -> coredata.UserFeatureOption:
        if not condition:
            return copy.deepcopy(self.held_object)

        if self.value == 'enabled':
            err_msg = f'Feature {self.held_object.name} cannot be enabled'
            if message:
                err_msg += f': {message}'
            raise InterpreterException(err_msg)
        return self.as_disabled()

    @FeatureNew('feature_option.require()', '0.59.0')
    @typed_pos_args('feature_option.require', bool)
    @typed_kwargs(
        'feature_option.require',
        _ERROR_MSG_KW,
    )
    def require_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        return self._disable_if(not args[0], kwargs['error_message'])

    @FeatureNew('feature_option.disable_if()', '1.1.0')
    @typed_pos_args('feature_option.disable_if', bool)
    @typed_kwargs(
        'feature_option.disable_if',
        _ERROR_MSG_KW,
    )
    def disable_if_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        return self._disable_if(args[0], kwargs['error_message'])

    @FeatureNew('feature_option.enable_if()', '1.1.0')
    @typed_pos_args('feature_option.enable_if', bool)
    @typed_kwargs(
        'feature_option.enable_if',
        _ERROR_MSG_KW,
    )
    def enable_if_method(self, args: T.Tuple[bool], kwargs: 'kwargs.FeatureOptionRequire') -> coredata.UserFeatureOption:
        if not args[0]:
            return copy.deepcopy(self.held_object)

        if self.value == 'disabled':
            err_msg = f'Feature {self.held_object.name} cannot be disabled'
            if kwargs['error_message']:
                err_msg += f': {kwargs["error_message"]}'
            raise InterpreterException(err_msg)
        return self.as_enabled()

    @FeatureNew('feature_option.disable_auto_if()', '0.59.0')
    @noKwargs
    @typed_pos_args('feature_option.disable_auto_if', bool)
    def disable_auto_if_method(self, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> coredata.UserFeatureOption:
        return copy.deepcopy(self.held_object) if self.value != 'auto' or not args[0] else self.as_disabled()

    @FeatureNew('feature_option.enable_auto_if()', '1.1.0')
    @noKwargs
    @typed_pos_args('feature_option.enable_auto_if', bool)
    def enable_auto_if_method(self, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> coredata.UserFeatureOption:
        return self.as_enabled() if self.value == 'auto' and args[0] else copy.deepcopy(self.held_object)


class RunProcess(MesonInterpreterObject):

    def __init__(self,
                 cmd: ExternalProgram,
                 args: T.List[str],
                 env: mesonlib.EnvironmentVariables,
                 source_dir: str,
                 build_dir: str,
                 subdir: str,
                 mesonintrospect: T.List[str],
                 in_builddir: bool = False,
                 check: bool = False,
                 capture: bool = True) -> None:
        super().__init__()
        if not isinstance(cmd, ExternalProgram):
            raise AssertionError('BUG: RunProcess must be passed an ExternalProgram')
        self.capture = capture
        self.returncode, self.stdout, self.stderr = self.run_command(cmd, args, env, source_dir, build_dir, subdir, mesonintrospect, in_builddir, check)
        self.methods.update({'returncode': self.returncode_method,
                             'stdout': self.stdout_method,
                             'stderr': self.stderr_method,
                             })

    def run_command(self,
                    cmd: ExternalProgram,
                    args: T.List[str],
                    env: mesonlib.EnvironmentVariables,
                    source_dir: str,
                    build_dir: str,
                    subdir: str,
                    mesonintrospect: T.List[str],
                    in_builddir: bool,
                    check: bool = False) -> T.Tuple[int, str, str]:
        command_array = cmd.get_command() + args
        menv = {'MESON_SOURCE_ROOT': source_dir,
                'MESON_BUILD_ROOT': build_dir,
                'MESON_SUBDIR': subdir,
                'MESONINTROSPECT': ' '.join([shlex.quote(x) for x in mesonintrospect]),
                }
        if in_builddir:
            cwd = os.path.join(build_dir, subdir)
        else:
            cwd = os.path.join(source_dir, subdir)
        child_env = os.environ.copy()
        child_env.update(menv)
        child_env = env.get_env(child_env)
        stdout = subprocess.PIPE if self.capture else subprocess.DEVNULL
        mlog.debug('Running command:', mesonlib.join_args(command_array))
        try:
            p, o, e = Popen_safe(command_array, stdout=stdout, env=child_env, cwd=cwd)
            if self.capture:
                mlog.debug('--- stdout ---')
                mlog.debug(o)
            else:
                o = ''
                mlog.debug('--- stdout disabled ---')
            mlog.debug('--- stderr ---')
            mlog.debug(e)
            mlog.debug('')

            if check and p.returncode != 0:
                raise InterpreterException('Command `{}` failed with status {}.'.format(mesonlib.join_args(command_array), p.returncode))

            return p.returncode, o, e
        except FileNotFoundError:
            raise InterpreterException('Could not execute command `%s`.' % mesonlib.join_args(command_array))

    @noPosargs
    @noKwargs
    def returncode_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> int:
        return self.returncode

    @noPosargs
    @noKwargs
    def stdout_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.stdout

    @noPosargs
    @noKwargs
    def stderr_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.stderr

class EnvironmentVariablesHolder(ObjectHolder[mesonlib.EnvironmentVariables], MutableInterpreterObject):

    def __init__(self, obj: mesonlib.EnvironmentVariables, interpreter: 'Interpreter'):
        super().__init__(obj, interpreter)
        self.methods.update({'set': self.set_method,
                             'unset': self.unset_method,
                             'append': self.append_method,
                             'prepend': self.prepend_method,
                             })

    def __repr__(self) -> str:
        repr_str = "<{0}: {1}>"
        return repr_str.format(self.__class__.__name__, self.held_object.envvars)

    def __deepcopy__(self, memo: T.Dict[str, object]) -> 'EnvironmentVariablesHolder':
        # Avoid trying to copy the interpreter
        return EnvironmentVariablesHolder(copy.deepcopy(self.held_object), self.interpreter)

    def warn_if_has_name(self, name: str) -> None:
        # Multiple append/prepend operations was not supported until 0.58.0.
        if self.held_object.has_name(name):
            m = f'Overriding previous value of environment variable {name!r} with a new one'
            FeatureNew(m, '0.58.0').use(self.subproject, self.current_node)

    @typed_pos_args('environment.set', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.set', ENV_SEPARATOR_KW)
    def set_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.held_object.set(name, values, kwargs['separator'])

    @FeatureNew('environment.unset', '1.4.0')
    @typed_pos_args('environment.unset', str)
    @noKwargs
    def unset_method(self, args: T.Tuple[str], kwargs: TYPE_kwargs) -> None:
        self.held_object.unset(args[0])

    @typed_pos_args('environment.append', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.append', ENV_SEPARATOR_KW)
    def append_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.warn_if_has_name(name)
        self.held_object.append(name, values, kwargs['separator'])

    @typed_pos_args('environment.prepend', str, varargs=str, min_varargs=1)
    @typed_kwargs('environment.prepend', ENV_SEPARATOR_KW)
    def prepend_method(self, args: T.Tuple[str, T.List[str]], kwargs: 'EnvironmentSeparatorKW') -> None:
        name, values = args
        self.warn_if_has_name(name)
        self.held_object.prepend(name, values, kwargs['separator'])


_CONF_DATA_SET_KWS: KwargInfo[T.Optional[str]] = KwargInfo('description', (str, NoneType))


class ConfigurationDataHolder(ObjectHolder[build.ConfigurationData], MutableInterpreterObject):

    def __init__(self, obj: build.ConfigurationData, interpreter: 'Interpreter'):
        super().__init__(obj, interpreter)
        self.methods.update({'set': self.set_method,
                             'set10': self.set10_method,
                             'set_quoted': self.set_quoted_method,
                             'has': self.has_method,
                             'get': self.get_method,
                             'keys': self.keys_method,
                             'get_unquoted': self.get_unquoted_method,
                             'merge_from': self.merge_from_method,
                             })

    def __deepcopy__(self, memo: T.Dict) -> 'ConfigurationDataHolder':
        return ConfigurationDataHolder(copy.deepcopy(self.held_object), self.interpreter)

    def is_used(self) -> bool:
        return self.held_object.used

    def __check_used(self) -> None:
        if self.is_used():
            raise InterpreterException("Can not set values on configuration object that has been used.")

    @typed_pos_args('configuration_data.set', str, (str, int, bool))
    @typed_kwargs('configuration_data.set', _CONF_DATA_SET_KWS)
    def set_method(self, args: T.Tuple[str, T.Union[str, int, bool]], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        self.held_object.values[args[0]] = (args[1], kwargs['description'])

    @typed_pos_args('configuration_data.set_quoted', str, str)
    @typed_kwargs('configuration_data.set_quoted', _CONF_DATA_SET_KWS)
    def set_quoted_method(self, args: T.Tuple[str, str], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        escaped_val = '\\"'.join(args[1].split('"'))
        self.held_object.values[args[0]] = (f'"{escaped_val}"', kwargs['description'])

    @typed_pos_args('configuration_data.set10', str, (int, bool))
    @typed_kwargs('configuration_data.set10', _CONF_DATA_SET_KWS)
    def set10_method(self, args: T.Tuple[str, T.Union[int, bool]], kwargs: 'kwargs.ConfigurationDataSet') -> None:
        self.__check_used()
        # bool is a subclass of int, so we need to check for bool explicitly.
        # We already have typed_pos_args checking that this is either a bool or
        # an int.
        if not isinstance(args[1], bool):
            mlog.deprecation('configuration_data.set10 with number. The `set10` '
                             'method should only be used with booleans',
                             location=self.interpreter.current_node)
            if args[1] < 0:
                mlog.warning('Passing a number that is less than 0 may not have the intended result, '
                             'as meson will treat all non-zero values as true.',
                             location=self.interpreter.current_node)
        self.held_object.values[args[0]] = (int(args[1]), kwargs['description'])

    @typed_pos_args('configuration_data.has', (str, int, bool))
    @noKwargs
    def has_method(self, args: T.Tuple[T.Union[str, int, bool]], kwargs: TYPE_kwargs) -> bool:
        return args[0] in self.held_object.values

    @FeatureNew('configuration_data.get()', '0.38.0')
    @typed_pos_args('configuration_data.get', str, optargs=[(str, int, bool)])
    @noKwargs
    def get_method(self, args: T.Tuple[str, T.Optional[T.Union[str, int, bool]]],
                   kwargs: TYPE_kwargs) -> T.Union[str, int, bool]:
        name = args[0]
        if name in self.held_object:
            return self.held_object.get(name)[0]
        elif args[1] is not None:
            return args[1]
        raise InterpreterException(f'Entry {name} not in configuration data.')

    @FeatureNew('configuration_data.get_unquoted()', '0.44.0')
    @typed_pos_args('configuration_data.get_unquoted', str, optargs=[(str, int, bool)])
    @noKwargs
    def get_unquoted_method(self, args: T.Tuple[str, T.Optional[T.Union[str, int, bool]]],
                            kwargs: TYPE_kwargs) -> T.Union[str, int, bool]:
        name = args[0]
        if name in self.held_object:
            val = self.held_object.get(name)[0]
        elif args[1] is not None:
            val = args[1]
        else:
            raise InterpreterException(f'Entry {name} not in configuration data.')
        if isinstance(val, str) and val[0] == '"' and val[-1] == '"':
            return val[1:-1]
        return val

    def get(self, name: str) -> T.Tuple[T.Union[str, int, bool], T.Optional[str]]:
        return self.held_object.values[name]

    @FeatureNew('configuration_data.keys()', '0.57.0')
    @noPosargs
    @noKwargs
    def keys_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> T.List[str]:
        return sorted(self.keys())

    def keys(self) -> T.List[str]:
        return list(self.held_object.values.keys())

    @typed_pos_args('configuration_data.merge_from', build.ConfigurationData)
    @noKwargs
    def merge_from_method(self, args: T.Tuple[build.ConfigurationData], kwargs: TYPE_kwargs) -> None:
        from_object = args[0]
        self.held_object.values.update(from_object.values)


_PARTIAL_DEP_KWARGS = [
    KwargInfo('compile_args', bool, default=False),
    KwargInfo('link_args',    bool, default=False),
    KwargInfo('links',        bool, default=False),
    KwargInfo('includes',     bool, default=False),
    KwargInfo('sources',      bool, default=False),
]

class DependencyHolder(ObjectHolder[Dependency]):
    def __init__(self, dep: Dependency, interpreter: 'Interpreter'):
        super().__init__(dep, interpreter)
        self.methods.update({'found': self.found_method,
                             'type_name': self.type_name_method,
                             'version': self.version_method,
                             'name': self.name_method,
                             'get_pkgconfig_variable': self.pkgconfig_method,
                             'get_configtool_variable': self.configtool_method,
                             'get_variable': self.variable_method,
                             'partial_dependency': self.partial_dependency_method,
                             'include_type': self.include_type_method,
                             'as_system': self.as_system_method,
                             'as_link_whole': self.as_link_whole_method,
                             })

    def found(self) -> bool:
        return self.found_method([], {})

    @noPosargs
    @noKwargs
    def type_name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.type_name

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        if self.held_object.type_name == 'internal':
            return True
        return self.held_object.found()

    @noPosargs
    @noKwargs
    def version_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_version()

    @noPosargs
    @noKwargs
    def name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_name()

    @FeatureDeprecated('dependency.get_pkgconfig_variable', '0.56.0',
                       'use dependency.get_variable(pkgconfig : ...) instead')
    @typed_pos_args('dependency.get_pkgconfig_variable', str)
    @typed_kwargs(
        'dependency.get_pkgconfig_variable',
        KwargInfo('default', str, default=''),
        PKGCONFIG_DEFINE_KW.evolve(name='define_variable')
    )
    def pkgconfig_method(self, args: T.Tuple[str], kwargs: 'kwargs.DependencyPkgConfigVar') -> str:
        from ..dependencies.pkgconfig import PkgConfigDependency
        if not isinstance(self.held_object, PkgConfigDependency):
            raise InvalidArguments(f'{self.held_object.get_name()!r} is not a pkgconfig dependency')
        if kwargs['define_variable'] and len(kwargs['define_variable']) > 1:
            FeatureNew.single_use('dependency.get_pkgconfig_variable keyword argument "define_variable"  with more than one pair',
                                  '1.3.0', self.subproject, location=self.current_node)
        return self.held_object.get_variable(
            pkgconfig=args[0],
            default_value=kwargs['default'],
            pkgconfig_define=kwargs['define_variable'],
        )

    @FeatureNew('dependency.get_configtool_variable', '0.44.0')
    @FeatureDeprecated('dependency.get_configtool_variable', '0.56.0',
                       'use dependency.get_variable(configtool : ...) instead')
    @noKwargs
    @typed_pos_args('dependency.get_config_tool_variable', str)
    def configtool_method(self, args: T.Tuple[str], kwargs: TYPE_kwargs) -> str:
        from ..dependencies.configtool import ConfigToolDependency
        if not isinstance(self.held_object, ConfigToolDependency):
            raise InvalidArguments(f'{self.held_object.get_name()!r} is not a config-tool dependency')
        return self.held_object.get_variable(
            configtool=args[0],
            default_value='',
        )

    @FeatureNew('dependency.partial_dependency', '0.46.0')
    @noPosargs
    @typed_kwargs('dependency.partial_dependency', *_PARTIAL_DEP_KWARGS)
    def partial_dependency_method(self, args: T.List[TYPE_nvar], kwargs: 'kwargs.DependencyMethodPartialDependency') -> Dependency:
        pdep = self.held_object.get_partial_dependency(**kwargs)
        return pdep

    @FeatureNew('dependency.get_variable', '0.51.0')
    @typed_pos_args('dependency.get_variable', optargs=[str])
    @typed_kwargs(
        'dependency.get_variable',
        KwargInfo('cmake', (str, NoneType)),
        KwargInfo('pkgconfig', (str, NoneType)),
        KwargInfo('configtool', (str, NoneType)),
        KwargInfo('internal', (str, NoneType), since='0.54.0'),
        KwargInfo('default_value', (str, NoneType)),
        PKGCONFIG_DEFINE_KW,
    )
    def variable_method(self, args: T.Tuple[T.Optional[str]], kwargs: 'kwargs.DependencyGetVariable') -> str:
        default_varname = args[0]
        if default_varname is not None:
            FeatureNew('Positional argument to dependency.get_variable()', '0.58.0').use(self.subproject, self.current_node)
        if kwargs['pkgconfig_define'] and len(kwargs['pkgconfig_define']) > 1:
            FeatureNew.single_use('dependency.get_variable keyword argument "pkgconfig_define" with more than one pair',
                                  '1.3.0', self.subproject, 'In previous versions, this silently returned a malformed value.',
                                  self.current_node)
        return self.held_object.get_variable(
            cmake=kwargs['cmake'] or default_varname,
            pkgconfig=kwargs['pkgconfig'] or default_varname,
            configtool=kwargs['configtool'] or default_varname,
            internal=kwargs['internal'] or default_varname,
            default_value=kwargs['default_value'],
            pkgconfig_define=kwargs['pkgconfig_define'],
        )

    @FeatureNew('dependency.include_type', '0.52.0')
    @noPosargs
    @noKwargs
    def include_type_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.get_include_type()

    @FeatureNew('dependency.as_system', '0.52.0')
    @noKwargs
    @typed_pos_args('dependency.as_system', optargs=[str])
    def as_system_method(self, args: T.Tuple[T.Optional[str]], kwargs: TYPE_kwargs) -> Dependency:
        return self.held_object.generate_system_dependency(args[0] or 'system')

    @FeatureNew('dependency.as_link_whole', '0.56.0')
    @noKwargs
    @noPosargs
    def as_link_whole_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> Dependency:
        if not isinstance(self.held_object, InternalDependency):
            raise InterpreterException('as_link_whole method is only supported on declare_dependency() objects')
        new_dep = self.held_object.generate_link_whole_dependency()
        return new_dep

_EXTPROG = T.TypeVar('_EXTPROG', bound=ExternalProgram)

class _ExternalProgramHolder(ObjectHolder[_EXTPROG]):
    def __init__(self, ep: _EXTPROG, interpreter: 'Interpreter') -> None:
        super().__init__(ep, interpreter)
        self.methods.update({'found': self.found_method,
                             'path': self.path_method,
                             'version': self.version_method,
                             'full_path': self.full_path_method})

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.found()

    @noPosargs
    @noKwargs
    @FeatureDeprecated('ExternalProgram.path', '0.55.0',
                       'use ExternalProgram.full_path() instead')
    def path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._full_path()

    @noPosargs
    @noKwargs
    @FeatureNew('ExternalProgram.full_path', '0.55.0')
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self._full_path()

    def _full_path(self) -> str:
        if not self.found():
            raise InterpreterException('Unable to get the path of a not-found external program')
        path = self.held_object.get_path()
        assert path is not None
        return path

    @noPosargs
    @noKwargs
    @FeatureNew('ExternalProgram.version', '0.62.0')
    def version_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if not self.found():
            raise InterpreterException('Unable to get the version of a not-found external program')
        try:
            return self.held_object.get_version(self.interpreter)
        except mesonlib.MesonException:
            return 'unknown'

    def found(self) -> bool:
        return self.held_object.found()

class ExternalProgramHolder(_ExternalProgramHolder[ExternalProgram]):
    pass

class ExternalLibraryHolder(ObjectHolder[ExternalLibrary]):
    def __init__(self, el: ExternalLibrary, interpreter: 'Interpreter'):
        super().__init__(el, interpreter)
        self.methods.update({'found': self.found_method,
                             'type_name': self.type_name_method,
                             'partial_dependency': self.partial_dependency_method,
                             })

    @noPosargs
    @noKwargs
    def type_name_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.type_name

    @noPosargs
    @noKwargs
    def found_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> bool:
        return self.held_object.found()

    @FeatureNew('dependency.partial_dependency', '0.46.0')
    @noPosargs
    @typed_kwargs('dependency.partial_dependency', *_PARTIAL_DEP_KWARGS)
    def partial_dependency_method(self, args: T.List[TYPE_nvar], kwargs: 'kwargs.DependencyMethodPartialDependency') -> Dependency:
        pdep = self.held_object.get_partial_dependency(**kwargs)
        return pdep

# A machine that's statically known from the cross file
class MachineHolder(ObjectHolder['MachineInfo']):
    def __init__(self, machine_info: 'MachineInfo', interpreter: 'Interpreter'):
        super().__init__(machine_info, interpreter)
        self.methods.update({'system': self.system_method,
                             'cpu': self.cpu_method,
                             'cpu_family': self.cpu_family_method,
                             'endian': self.endian_method,
                             'kernel': self.kernel_method,
                             'subsystem': self.subsystem_method,
                             })

    @noPosargs
    @noKwargs
    def cpu_family_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.cpu_family

    @noPosargs
    @noKwargs
    def cpu_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.cpu

    @noPosargs
    @noKwargs
    def system_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.system

    @noPosargs
    @noKwargs
    def endian_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.endian

    @noPosargs
    @noKwargs
    def kernel_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if self.held_object.kernel is not None:
            return self.held_object.kernel
        raise InterpreterException('Kernel not defined or could not be autodetected.')

    @noPosargs
    @noKwargs
    def subsystem_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        if self.held_object.subsystem is not None:
            return self.held_object.subsystem
        raise InterpreterException('Subsystem not defined or could not be autodetected.')


class IncludeDirsHolder(ObjectHolder[build.IncludeDirs]):
    pass

class FileHolder(ObjectHolder[mesonlib.File]):
    def __init__(self, file: mesonlib.File, interpreter: 'Interpreter'):
        super().__init__(file, interpreter)
        self.methods.update({'full_path': self.full_path_method,
                             })

    @noPosargs
    @noKwargs
    @FeatureNew('file.full_path', '1.4.0')
    def full_path_method(self, args: T.List[TYPE_var], kwargs: TYPE_kwargs) -> str:
        return self.held_object.absolute_path(self.env.source_dir, self.env.build_dir)

class HeadersHolder(ObjectHolder[build.Headers]):
    pass

class DataHolder(ObjectHolder[build.Data]):
    pass

class SymlinkDataHolder(ObjectHolder[build.SymlinkData]):
    pass

class InstallDirHolder(ObjectHolder[build.InstallDir]):
    pass

class ManHolder(ObjectHolder[build.Man]):
    pass

class EmptyDirHolder(ObjectHolder[build.EmptyDir]):
    pass

class GeneratedObjectsHolder(ObjectHolder[build.ExtractedObjects]):
    pass

class Test(MesonInterpreterObject):
    def __init__(self, name: str, project: str, suite: T.List[str],
                 exe: T.Union[ExternalProgram, build.Executable, build.CustomTarget, build.CustomTargetIndex],
                 depends: T.List[T.Union[build.CustomTarget, build.BuildTarget]],
                 is_parallel: bool,
                 cmd_args: T.List[T.Union[str, mesonlib.File, build.Target]],
                 env: mesonlib.EnvironmentVariables,
                 should_fail: bool, timeout: int, workdir: T.Optional[str], protocol: str,
                 priority: int, verbose: bool):
```