Response:
The user wants a summary of the functionality of the provided Python code. I need to go through the code and identify the main classes and their methods, understanding what each part does. Since this is part 1 of 2, I should focus on the functionalities present in this specific part of the code.

Here is a breakdown of the classes and their apparent functions:

*   **`extract_required_kwarg`**:  A function to extract and process the 'required' keyword argument, especially when it relates to feature options.
*   **`extract_search_dirs`**: A function to extract and validate search directory paths.
*   **`FeatureOptionHolder`**: Manages user-configurable feature options (enabled, disabled, auto).
*   **`RunProcess`**: Executes external commands and captures their output.
*   **`EnvironmentVariablesHolder`**: Manages environment variables (setting, unsetting, appending, prepending).
*   **`ConfigurationDataHolder`**: Manages configuration data (setting, getting, checking for existence of values).
*   **`DependencyHolder`**:  Represents a dependency and provides methods to query its properties (found, version, name, etc.).
*   **`_ExternalProgramHolder`**: (Base class) Represents an external program and provides methods to check if it's found and get its path and version.
*   **`ExternalProgramHolder`**: Represents an external program.
*   **`ExternalLibraryHolder`**: Represents an external library.
*   **`MachineHolder`**: Represents information about the target machine.
*   **`IncludeDirsHolder`**: Represents include directories.
*   **`FileHolder`**: Represents a file.
*   **`HeadersHolder`**: Represents header files.
*   **`DataHolder`**: Represents data files.
*   **`SymlinkDataHolder`**: Represents symlink data.
*   **`InstallDirHolder`**: Represents install directories.
*   **`ManHolder`**: Represents man pages.
*   **`EmptyDirHolder`**: Represents empty directories.
*   **`GeneratedObjectsHolder`**: Represents generated object files.
*   **`Test`**: Represents a test case.

The code seems to be defining objects that represent various build system concepts (features, external programs, dependencies, configuration, etc.) and providing methods to interact with them within the Meson build system's Python interpreter.
This Python code defines a set of classes that represent various objects and functionalities within the Frida dynamic instrumentation tool's build system, which is based on Meson. These classes act as wrappers or holders around core Meson build system objects, exposing methods that can be used within the Meson build definition files (typically `meson.build`).

Here's a breakdown of the functionalities implemented in this part of the code:

**Core Functionalities:**

1. **Feature Option Management (`FeatureOptionHolder`):**
    *   Provides an interface to interact with user-defined feature options.
    *   Allows checking if a feature is enabled, disabled, or set to auto.
    *   Provides methods to conditionally disable or enable features based on specific criteria.
    *   Allows requiring a feature to be enabled, raising an error if it's not.

2. **External Process Execution (`RunProcess`):**
    *   Enables the execution of external commands during the build process.
    *   Captures the return code, standard output, and standard error of the executed command.
    *   Provides methods to access these results.

3. **Environment Variable Manipulation (`EnvironmentVariablesHolder`):**
    *   Allows setting, unsetting, appending to, and prepending to environment variables that will be used during the build.

4. **Configuration Data Management (`ConfigurationDataHolder`):**
    *   Provides a way to store and manage configuration data that can be used to customize the build.
    *   Supports setting string, integer, and boolean values with optional descriptions.
    *   Allows checking for the existence of a configuration value and retrieving its value (with or without quotes).
    *   Provides functionality to merge configuration data from other configuration objects.

5. **Dependency Handling (`DependencyHolder`):**
    *   Represents a dependency (either external libraries or internal project components).
    *   Provides methods to check if the dependency was found.
    *   Allows retrieving the dependency's type, version, and name.
    *   Supports fetching variables from dependency information using different methods like `pkg-config` or `configtool`.
    *   Introduces the concept of "partial dependencies" to extract specific parts of a dependency (e.g., only compile flags).
    *   Allows marking a dependency as a system dependency or requiring it to be linked "whole".

6. **External Program Representation (`_ExternalProgramHolder`, `ExternalProgramHolder`):**
    *   Represents an external executable.
    *   Provides methods to check if the program was found and retrieve its full path and version.

7. **External Library Representation (`ExternalLibraryHolder`):**
    *   Represents an external library.
    *   Allows checking if the library was found and getting its type name.
    *   Supports creating partial dependencies from external libraries.

8. **Target Machine Information (`MachineHolder`):**
    *   Provides access to information about the target machine architecture (system, CPU, endianness, kernel, subsystem).

9. **Build System Object Holders (`IncludeDirsHolder`, `FileHolder`, `HeadersHolder`, `DataHolder`, `SymlinkDataHolder`, `InstallDirHolder`, `ManHolder`, `EmptyDirHolder`, `GeneratedObjectsHolder`):**
    *   These classes act as simple wrappers around various Meson build system objects representing include directories, files, headers, data files, symlinks, installation directories, man pages, empty directories, and generated objects. They often expose basic methods to access information about the held object.

10. **Test Case Representation (`Test`):**
    *   Represents a test case definition within the build system.

**Relationship to Reverse Engineering:**

Several functionalities in this code relate to reverse engineering, particularly when dealing with external libraries and programs that might be targets of or used during reverse engineering efforts:

*   **Dependency Handling (`DependencyHolder`):**  When reverse engineering a binary, you often need to understand its dependencies. This code helps manage and query information about these dependencies, like their names, versions, and required flags. For example, you might use this information to identify specific versions of libraries that have known vulnerabilities or behaviors.
    *   **Example:** If a reverse engineer is analyzing a program that depends on `libssl`, the `DependencyHolder` could be used to determine the exact version of `libssl` being used during the build. This is crucial because different versions might have different security properties or API behaviors.

*   **External Program Execution (`RunProcess`):**  Reverse engineering workflows often involve using external tools. This functionality allows the build system to execute these tools as part of the build process. For example, a disassembler or a static analyzer could be run.
    *   **Example:** A reverse engineer might want to run `objdump` on a compiled binary as part of the build process to extract symbol information or examine the assembly code. `RunProcess` would facilitate this.

*   **External Program Representation (`ExternalProgramHolder`):** Knowing the path and version of external tools used in the build can be important for reproducibility and for understanding the environment in which the target was built.
    *   **Example:** If a specific version of a compiler was used, knowing this can help in reproducing the build environment or understanding compiler-specific optimizations that might affect reverse engineering analysis.

**Relationship to Binary Low-Level, Linux, Android Kernel, and Framework Knowledge:**

The code touches upon these areas in the following ways:

*   **Binary Low-Level:** The code deals with build artifacts (executables, libraries), which are binary files. The dependency handling and external program execution are often related to manipulating or analyzing these binary files.
    *   **Example:** When linking libraries, the build system needs to understand the binary format (e.g., ELF) to correctly link object files.

*   **Linux Kernel:**  While not directly manipulating the kernel, the build system can be configured for Linux targets. Dependency resolution and handling of system libraries are relevant here.
    *   **Example:** When building for Linux, the `DependencyHolder` might interact with system package managers to find libraries required by the project.

*   **Android Kernel and Framework:**  Frida is heavily used in Android reverse engineering. This build system likely supports building Frida components for Android. The concepts of dependencies (which might include Android framework libraries) and external programs (like the Android NDK toolchain) are directly applicable.
    *   **Example:** The build system might need to locate and link against specific Android system libraries or use tools from the Android NDK for compilation.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `FeatureOptionHolder`:

*   **Hypothetical Input:** A `meson.build` file defines a feature option named `debug_symbols` with a default value of "auto". The user runs Meson and explicitly sets `-Ddebug_symbols=enabled`.
*   **Logical Reasoning:** When the `enabled_method()` of the `FeatureOptionHolder` for `debug_symbols` is called, it will check the current value of the feature option.
*   **Output:** The `enabled_method()` will return `True` because the user explicitly enabled the feature.

Let's consider the `RunProcess`:

*   **Hypothetical Input:**  A `meson.build` file uses `RunProcess` to execute `ls -l` in the current source directory.
*   **Logical Reasoning:** The `run_command()` method will execute the `ls -l` command using `subprocess.Popen_safe`.
*   **Output:** The `stdout_method()` of the resulting `RunProcess` object will return a string containing the output of the `ls -l` command, listing the files and directories in the source directory. The `returncode_method()` will likely return 0 (assuming the command succeeds).

**Common User or Programming Errors:**

*   **Incorrect Path in `extract_search_dirs`:** Users might provide relative paths instead of absolute paths for search directories. The code explicitly checks for this and raises an `InvalidCode` exception.
    *   **Example:**  `dirs: ['my_include']` would be an error because 'my_include' is not an absolute path.

*   **Setting Configuration Data After Use:**  Users might try to modify a `ConfigurationDataHolder` object after it has been used in a build target. The `__check_used()` method prevents this and raises an `InterpreterException`.
    *   **Example:** Defining a configuration value, then using it in a compilation step, and later trying to change that configuration value.

*   **Accessing Non-Existent Configuration Data:**  Users might try to retrieve a configuration value using `get_method()` that hasn't been set. This will raise an `InterpreterException`.
    *   **Example:** Calling `config_data.get('non_existent_key')` without a default value.

*   **Incorrectly Assuming a Dependency is Found:** Users might proceed with build logic assuming a dependency is found without checking the result of `dependency.found()`.

**User Operations Leading to This Code (Debugging Clues):**

A user's interaction with Meson that eventually leads to the execution of code in `interpreterobjects.py` involves the following steps:

1. **Writing `meson.build` files:** The user defines their build logic using Meson's DSL in `meson.build` files. These files will contain calls to functions that create the objects defined in `interpreterobjects.py`.

2. **Running the `meson` command:** The user executes the `meson` command, typically providing source and build directories.

3. **Meson Interpreter Execution:** The `meson` command starts the Meson interpreter, which parses and executes the `meson.build` files.

4. **Object Creation:** When the interpreter encounters functions like `feature_option()`, `run_command()`, `environment()`, `configuration_data()`, `dependency()`, `find_program()`, `find_library()`, etc., it instantiates the corresponding holder objects defined in `interpreterobjects.py`.

5. **Method Calls:**  The `meson.build` files will often call methods on these objects (e.g., `feature.enabled()`, `process.stdout()`, `env.set()`, `config.set()`, `dependency.found()`, `program.path()`). These method calls are resolved to the methods defined in the holder classes in `interpreterobjects.py`.

**Example Debugging Scenario:**

Let's say a user is getting an error like "Command `my_tool --version` failed with status 1". This could lead a developer to investigate the `RunProcess` class. The developer might trace the execution flow:

1. The user's `meson.build` file calls a function that internally creates a `RunProcess` object with `my_tool --version` as the command.
2. The `run_command()` method in `RunProcess` is executed.
3. The `Popen_safe` function executes the command, and it returns a non-zero return code.
4. The `check=True` argument was likely passed to the `RunProcess` constructor, causing the `InterpreterException` to be raised when the return code is not 0.

By examining the `RunProcess` class and the arguments passed to it, the developer can understand how the external command is being executed and why it might be failing.

**Summary of Functionalities (Part 1):**

This part of the `interpreterobjects.py` file in Frida's build system defines the Python representations of various build system concepts. It provides the core building blocks for interacting with features, executing external commands, managing environment variables and configuration data, and handling dependencies and external programs within the Meson build environment. These objects and their methods are crucial for defining the build logic and customizing the build process for Frida.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreterobjects.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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