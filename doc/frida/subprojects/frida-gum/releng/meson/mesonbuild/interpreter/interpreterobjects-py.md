Response:
My thinking process to answer the request about the `interpreterobjects.py` file goes like this:

1. **Understand the Goal:** The request asks for the functionalities of the Python code, focusing on its relationship to reverse engineering, low-level details, logical reasoning, common user errors, and debugging. It also specifically asks for a summary of its functions.

2. **Initial Scan and Categorization:** I'll quickly read through the code, noting the types of classes and methods present. I see classes like `FeatureOptionHolder`, `RunProcess`, `EnvironmentVariablesHolder`, `ConfigurationDataHolder`, `DependencyHolder`, `ExternalProgramHolder`, etc. This immediately suggests that the file deals with representing and manipulating various aspects of a build system's configuration and execution environment.

3. **Focus on Key Classes and Their Methods:**  I'll examine the methods within each class to understand their specific purpose. For instance:
    * `FeatureOptionHolder`:  Methods like `enabled_method`, `disabled_method`, `require_method` clearly relate to managing build features and their on/off states.
    * `RunProcess`: Methods like `returncode_method`, `stdout_method`, `stderr_method` point to the execution of external commands and capturing their output.
    * `EnvironmentVariablesHolder`: `set_method`, `append_method`, `prepend_method` obviously deal with manipulating environment variables.
    * `DependencyHolder`: `found_method`, `version_method`, `get_variable` indicate interaction with software dependencies.

4. **Identify Connections to Reverse Engineering (Instruction 2):** I consider how these functionalities might be relevant to reverse engineering. The `RunProcess` class is a prime candidate here. Reverse engineers often need to run tools (like disassemblers, debuggers, or custom scripts) as part of their analysis. The ability to execute external programs, capture their output, and check their return codes is directly applicable.

5. **Look for Low-Level/Kernel/Framework Connections (Instruction 3):** I search for keywords or concepts related to the operating system, kernel, or specific frameworks.
    *  The `RunProcess` class interacts with the operating system to execute commands.
    *  Environment variables (handled by `EnvironmentVariablesHolder`) are a fundamental part of the operating system environment.
    *  Dependencies, especially external libraries (`ExternalLibraryHolder`), can be operating system libraries or framework components. The methods for finding and querying them relate to the underlying system.

6. **Analyze for Logical Reasoning (Instruction 4):**  I look for methods that make decisions or perform conditional logic.
    * The `FeatureOptionHolder` has methods like `disable_if_method` and `enable_if_method` which clearly implement conditional logic based on boolean inputs. I can then create a simple scenario to demonstrate this logic.

7. **Consider Common User Errors (Instruction 5):**  I think about how a user might misuse the provided functionality.
    * For `ConfigurationDataHolder`, attempting to modify configuration data after it has been used in the build process is a likely error. The code explicitly checks for this.
    * Incorrect paths in `extract_search_dirs` is another potential user error.

8. **Trace User Operations (Instruction 6):** I consider how a user's actions in a build system definition might lead to the execution of this code. The `meson.build` file is the entry point for a Meson build. Declaring dependencies, running external commands, and configuring build options are all actions that would involve the classes in this file.

9. **Synthesize and Summarize (Instruction 7):**  Finally, I gather my observations and formulate a concise summary of the file's purpose. The core function is to provide Python objects that represent and manage build system concepts like features, processes, environment variables, configuration data, dependencies, and external programs.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** I might initially focus too much on the details of each method.
* **Correction:** I'll step back and focus on the higher-level purpose of each class and how it contributes to the overall functionality.
* **Initial thought:** I might struggle to connect every class to reverse engineering.
* **Correction:** I'll focus on the most direct and relevant connections, like `RunProcess`, and acknowledge that other aspects are more indirectly related (e.g., managing dependencies might indirectly help in setting up a reverse engineering environment).
* **Initial thought:**  My logical reasoning examples might be too complex.
* **Correction:** I'll simplify the examples to clearly illustrate the input and output based on the defined logic.

By following this structured approach, I can systematically analyze the code and address all the specific points raised in the request, resulting in a comprehensive and informative answer.
This Python source code file, `interpreterobjects.py`, is a crucial part of the Frida dynamic instrumentation tool's build system, which uses Meson. It defines Python classes that represent various build system entities within the Meson interpreter. These objects are manipulated during the build configuration phase and are essential for orchestrating the compilation, linking, and installation of Frida components.

Here's a breakdown of its functionalities, addressing the specific points raised in the prompt:

**1. Functionalities:**

This file defines a collection of Python classes that act as wrappers or "holders" around internal Meson build system objects. These holders provide methods to interact with and query information about these underlying objects. Key functionalities include:

* **Managing Build Features (`FeatureOptionHolder`):**  Allows querying and manipulating user-configurable build options (features). You can check if a feature is enabled, disabled, or set to auto, and conditionally disable or enable them based on other factors.
* **Executing External Processes (`RunProcess`):** Provides a way to run external commands as part of the build process. It captures the command's return code, standard output, and standard error.
* **Handling Environment Variables (`EnvironmentVariablesHolder`):** Enables setting, unsetting, appending to, and prepending to environment variables that will be used during the build.
* **Managing Configuration Data (`ConfigurationDataHolder`):** Allows setting and retrieving configuration values that can be used in generated header files or other build artifacts.
* **Working with Dependencies (`DependencyHolder`):** Represents external libraries or other Meson-defined dependencies. It provides methods to check if a dependency is found, get its version, retrieve compile and link arguments, and create partial dependencies.
* **Representing External Programs (`ExternalProgramHolder`):**  Wraps external executables, allowing you to check if they are found and retrieve their paths and versions.
* **Representing External Libraries (`ExternalLibraryHolder`):** Similar to `DependencyHolder`, but specifically for external libraries.
* **Describing Machine Information (`MachineHolder`):** Provides access to information about the target machine (system, CPU, endianness, etc.).
* **Handling Installable Files and Directories (`FileHolder`, `HeadersHolder`, `DataHolder`, `SymlinkDataHolder`, `InstallDirHolder`, `ManHolder`, `EmptyDirHolder`):**  Represents various types of files and directories that will be installed as part of the build.
* **Managing Generated Objects (`GeneratedObjectsHolder`):** Represents objects generated by custom commands.
* **Defining Tests (`Test`):** Represents test cases that can be executed after the build.

**2. Relationship to Reverse Engineering:**

This file, while part of the *build* system, has indirect but important relationships to reverse engineering, particularly in the context of a tool like Frida:

* **Executing External Tools (`RunProcess`):** During Frida's build process, it might need to execute other tools (e.g., code generators, static analysis tools). In a reverse engineering context, you might use this mechanism to integrate your own custom analysis scripts or tools into the Frida build.
    * **Example:**  Imagine you want to run a custom script that analyzes Frida's generated code for security vulnerabilities. You could use the `RunProcess` object within the Meson build files to execute this script, passing it the necessary build artifacts as input. The script's output could then be used to generate warnings or errors during the build.
* **Managing Dependencies (`DependencyHolder`):** Frida likely depends on various libraries. The way these dependencies are handled during the build (finding them, getting their include paths and link libraries) is fundamental for ensuring Frida can be built correctly. Understanding how Frida's dependencies are managed can be relevant when trying to reverse engineer Frida itself or when extending its functionality.
    * **Example:** If you're trying to understand how Frida interacts with a specific library on a target system, knowing how that library is located and linked during Frida's build (using the information from `DependencyHolder`) can provide valuable clues.
* **Configuration Options (`FeatureOptionHolder`, `ConfigurationDataHolder`):**  Frida's behavior can often be customized through build-time options. These classes manage those options. Understanding these options is crucial for anyone wanting to build a specific version or variant of Frida for reverse engineering purposes.
    * **Example:**  Frida might have a build option to enable or disable certain debugging features. Someone reversing Frida would need to know how to check the state of this option (using `FeatureOptionHolder`) to understand if the binary they are analyzing was built with those debugging features enabled.

**3. Relationship to Binary, Linux, Android Kernel/Framework:**

This file interacts with these low-level aspects indirectly through the Meson build system:

* **Binary Level:** The ultimate output of the build process orchestrated by Meson (and involving these objects) is binary code (executables, libraries). The choices made during the build (dependencies, compiler flags, etc., managed by these objects) directly affect the final binary.
* **Linux/Android Kernel/Framework:** Frida often targets Linux and Android. The build system needs to know about the specific characteristics of these platforms.
    * **`MachineHolder`:** This class directly represents information about the target machine's operating system (Linux, Android), CPU architecture, etc. This information is crucial for configuring the build correctly for the target environment.
    * **Dependencies:** Frida might depend on libraries specific to Linux or Android (e.g., system libraries, Android framework components). The `DependencyHolder` helps locate these platform-specific dependencies.
    * **Cross-Compilation:** If Frida is being cross-compiled for Android from a Linux host, the build system (and thus these objects) needs to handle the differences in toolchains, libraries, and system headers between the host and target.
* **Environment Variables:** Environment variables set using `EnvironmentVariablesHolder` can influence the behavior of the compiler and linker, which are fundamental tools for producing binary code on Linux and Android.

**4. Logical Reasoning (Hypothetical Input and Output):**

Let's take the `FeatureOptionHolder` as an example:

* **Hypothetical Input:**
    * A `FeatureOptionHolder` object representing a feature named "scripting" which is currently set to "auto".
    * A call to the `disable_auto_if_method` with the argument `True`.
* **Logical Reasoning:** The `disable_auto_if_method` checks if the feature is currently "auto". If it is, and the provided boolean argument is `True`, it will return a new `UserFeatureOption` object where the "scripting" feature is disabled.
* **Hypothetical Output:** A new `FeatureOptionHolder` object where the underlying `UserFeatureOption` for "scripting" has its value set to "disabled".

**5. User/Programming Common Usage Errors:**

* **Modifying Configuration After Use (`ConfigurationDataHolder`):** A common error is trying to set a configuration value using `set_method` after the configuration data has already been used to generate a file.
    * **Example:** A user might call `configure_file()` with a `ConfigurationDataHolder` object and then later try to modify that same object. This will raise an `InterpreterException` because the configuration is considered immutable once used.
* **Incorrect Path in Search Directories (`extract_search_dirs`):** When searching for dependencies or files, users might provide relative paths instead of absolute paths in the `dirs` argument.
    * **Example:**  A user might write `find_library('mylib', dirs : ['my/relative/path'])`. This would lead to an `InvalidCode` exception because the path is not absolute.
* **Incorrectly Assuming External Program is Found (`ExternalProgramHolder`):** Users might try to access the path or version of an external program without first checking if it was found using the `found()` method.
    * **Example:** A user might write `prog = find_program('mytool')` and then immediately try to get its path: `prog.path()`. If `mytool` is not found on the system, `prog.path()` will raise an `InterpreterException`.

**6. User Operation Steps to Reach Here (Debugging Clue):**

A user's actions that would lead to the execution of the code in `interpreterobjects.py` are typically within the `meson.build` files of a Frida project or any project using Meson:

1. **Run `meson setup` or `meson configure`:** This command initiates the configuration phase of the Meson build system. Meson parses the `meson.build` files.
2. **Meson Interpreter Execution:** During parsing, Meson executes the Python code in the `meson.build` files.
3. **Using Meson Built-in Functions:**  Users call Meson functions within their `meson.build` files that interact with the objects defined in `interpreterobjects.py`. Examples include:
    * `feature_option(...)`: Creates a `FeatureOptionHolder`.
    * `run_process(...)`: Creates a `RunProcess` object and executes a command.
    * `environment()`: Creates an `EnvironmentVariablesHolder`.
    * `configuration_data()`: Creates a `ConfigurationDataHolder`.
    * `dependency(...)` or `find_library(...)`:  Can result in the creation of `DependencyHolder` or `ExternalLibraryHolder` objects.
    * `find_program(...)`: Creates an `ExternalProgramHolder`.
    * `declare_dependency(...)`: Creates an `InternalDependency` which can be wrapped by `DependencyHolder`.
    * `executable(...)`, `shared_library(...)`:  While not directly in this file, the properties of the resulting build targets can be queried and manipulated, indirectly involving these objects.
4. **Method Calls on Interpreter Objects:** The `meson.build` files might then call methods on these created objects. For instance:
    * `feature_option('my_feature').enabled()`
    * `prog = find_program('gcc'); if prog.found(): ...`
    * `env = environment(); env.set('MY_VAR', 'my_value')`
    * `config = configuration_data(); config.set('VERSION', '1.0')`

**In summary, `interpreterobjects.py` defines the building blocks for representing and manipulating build system elements within the Meson interpreter. It provides a Pythonic interface to interact with features, external commands, environment variables, dependencies, and other aspects necessary to configure and execute the build process for a project like Frida.** This file is not directly involved in Frida's runtime behavior or instrumentation capabilities but is essential for its construction.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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
     
"""


```