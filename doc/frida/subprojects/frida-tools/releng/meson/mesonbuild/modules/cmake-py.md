Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand what this Python code does, specifically within the context of the Frida dynamic instrumentation tool. The prompt asks for its functions, relevance to reverse engineering, low-level details, logic, potential errors, and how a user might end up interacting with it.

**2. Initial Code Scan (High-Level):**

* **Imports:**  Immediately, I see imports like `os`, `pathlib`, `shutil`, suggesting file system operations. Imports from within the Meson build system (`.`, `..`) indicate this code is part of Meson's functionality. The `cmake` import is a huge clue – this code likely deals with integrating CMake projects.
* **Class Structure:**  There are several classes: `CMakeSubproject`, `CMakeSubprojectOptions`, and `CmakeModule`. This suggests a modular design.
* **Docstrings:** The initial docstring provides context: it's part of Frida, in a specific directory related to CMake within the Meson build system. This reinforces the CMake integration idea.
* **Copyright and License:** Standard boilerplate, but good to note.

**3. Deeper Dive into Each Class:**

* **`CMakeSubproject`:**  The methods like `get_variable`, `dependency`, `include_directories`, `target`, `target_type`, and `target_list` strongly suggest this class provides a way to interact with a *CMake subproject* from within the Meson build. The methods seem to mirror common CMake concepts. The `_args_to_info` method hints at parsing information about CMake targets.
* **`CMakeSubprojectOptions`:** Methods like `add_cmake_defines`, `set_override_option`, `set_install`, `append_compile_args`, and `append_link_args` clearly indicate this class is for configuring how the CMake subproject is built. It allows setting CMake definitions, overriding options, controlling installation, and adding compiler/linker flags.
* **`CmakeModule`:** This appears to be the main entry point. The `write_basic_package_version_file` and `configure_package_config_file` methods suggest it handles generating CMake package configuration files. The `subproject` method is the key for actually including and integrating a CMake subproject. `subproject_options` seems to return an instance of the `CMakeSubprojectOptions` class. The `detect_cmake` and `detect_voidp_size` methods indicate some environment detection is happening.

**4. Connecting to the Prompt's Questions:**

* **Functionality:**  Based on the method names and what they do, I can start listing the core functionalities. The key is CMake subproject integration and package configuration file generation.
* **Reverse Engineering:** This is where thinking about Frida comes in. Frida instruments binaries. CMake is often used to build those binaries. This module allows Frida's build system (Meson) to include and manage the build of components built with CMake. This is crucial if Frida needs to interact with or instrument software built using CMake. Examples of interacting with libraries or executables built with CMake within Frida's build process are relevant.
* **Binary/Low-Level/Kernel:**  The `detect_voidp_size` method directly touches on a low-level concept (pointer size). CMake itself deals with compilation and linking, which are fundamentally binary operations. If Frida needs to interact with or load libraries built with CMake (e.g., kernel modules, Android framework components), this module plays a role. The CMake package config files also influence how those libraries are found and linked.
* **Logic/Input/Output:** The `write_basic_package_version_file` and `configure_package_config_file` methods have clear inputs (template files, configuration data) and outputs (generated CMake config files). I can describe the transformations that happen. The `subproject` method takes a directory as input and potentially outputs an object representing the integrated subproject.
* **User Errors:**  Looking at the argument parsing and type checking (e.g., `@stringArgs`, `@typed_kwargs`), I can identify potential user errors like passing the wrong types of arguments, missing required arguments, or using mutually exclusive options.
* **User Journey:**  Think about how someone developing Frida might use this. They would write `meson.build` files. To include a CMake project, they'd use the `cmake.subproject()` function. To configure package files, they'd use `cmake.write_basic_package_version_file()` or `cmake.configure_package_config_file()`. This gives the steps to reach this code.

**5. Structuring the Answer:**

Organize the information logically, addressing each part of the prompt. Use clear headings and bullet points for readability. Provide specific examples to illustrate the points, especially for reverse engineering and low-level concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this just *finds* CMake. **Correction:** The methods clearly show it's about *integrating* CMake projects.
* **Overly technical:** Avoid overly jargon-filled explanations. Explain concepts clearly, even to someone who might not be a CMake expert.
* **Missing connections:**  Ensure I explicitly link the code's functions to the broader context of Frida and reverse engineering. Don't just describe the code; explain *why* it's relevant.
* **Insufficient examples:**  Make sure the examples are concrete and illustrate the point effectively. Don't just say "it can set compiler flags"; give an example of *which* flag and *why* it might be used in a reverse engineering context.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer to the prompt.
This Python code file, `cmake.py`, is a module within the Meson build system that provides functionality for integrating CMake-based subprojects into a larger Meson-based build. Since Frida itself uses Meson for its build system, this module is crucial for incorporating any dependencies or components that rely on CMake.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Integrating CMake Subprojects (`subproject`):**
   - This is the primary function. It allows a Meson project to include and build a CMake-based project as a subproject.
   - It takes the directory of the CMake project as input.
   - It allows specifying CMake-specific options (`cmake_options`) and a `CMakeSubprojectOptions` object for more fine-grained control.
   - It returns a `CMakeSubproject` object which provides methods to interact with the built CMake subproject.

2. **Configuring CMake Subproject Options (`subproject_options`):**
   - This function creates and returns a `CMakeSubprojectOptions` object.
   - This object allows setting various options for the CMake subproject, such as:
     - Adding CMake definitions (`add_cmake_defines`).
     - Overriding CMake options (`set_override_option`).
     - Controlling installation of targets (`set_install`).
     - Appending compiler arguments (`append_compile_args`).
     - Appending linker arguments (`append_link_args`).

3. **Interacting with CMake Subproject Targets (`CMakeSubproject` class):**
   - This class provides methods to retrieve information and dependencies from the built CMake subproject.
   - `get_variable()`:  Retrieves the value of a CMake variable.
   - `dependency()`:  Creates a Meson dependency object from a CMake target, allowing linking against it.
   - `include_directories()`: Retrieves the include directories of a CMake target.
   - `target()`: Retrieves the Meson target object representing a CMake target.
   - `target_type()`:  Gets the type of a CMake target (e.g., "executable", "library").
   - `target_list()`: Returns a list of all targets in the CMake subproject.
   - `found_method()`: Checks if the CMake subproject was successfully found and integrated.

4. **Generating CMake Package Configuration Files:**
   - `write_basic_package_version_file()`: Creates a basic CMake config-version file that specifies the version and compatibility of a package. This helps CMake's `find_package` mechanism locate the package.
   - `configure_package_config_file()`:  Generates a more advanced CMake package configuration file from a template. This allows defining targets, libraries, include paths, and other settings that are exported for use by projects that depend on this package.

5. **Internal Utilities:**
   - `detect_cmake()`: Checks if CMake is available on the system.
   - `detect_voidp_size()`: Determines the size of a void pointer, which is sometimes needed for CMake configuration.
   - `create_package_file()`: A helper function to perform the actual file writing for package configuration files, including variable substitution.

**Relationship to Reverse Engineering:**

This module is directly relevant to reverse engineering in the context of Frida because:

* **Frida's Own Dependencies:** Frida itself might rely on libraries or components built using CMake. This module allows Frida's build system to seamlessly integrate these dependencies. For example, if Frida needed a specific crypto library built with CMake, this module would be used to include and link against it.
* **Instrumenting Software with CMake Dependencies:** When using Frida to instrument applications, those applications might themselves depend on libraries built with CMake. Understanding how Frida's build system handles CMake projects can be helpful when trying to understand the environment in which the target application runs.
* **Building Frida Gadgets/Modules:**  Developers creating Frida gadgets or modules might choose to use CMake for their own build process. This module provides the mechanism for incorporating these externally built components into the Frida ecosystem.

**Example of Reverse Engineering Relevance:**

Let's say Frida needs to interact with a specific Android system service that's built using the Android build system (which often involves CMake or similar tools). A Frida module might need to link against libraries provided by this service.

```python
# In a meson.build file for a Frida module

cmake_service = cmake.subproject('path/to/android/service/cmake/build')

service_library = cmake_service.dependency('service_core')  # Assuming 'service_core' is a target in the CMake project

frida_module = shared_library(
    'my_frida_module',
    'my_frida_module.c',
    dependencies: service_library,
    # ... other settings
)
```

In this example, `cmake.subproject` is used to integrate the Android service's CMake build. Then, `cmake_service.dependency('service_core')` retrieves the dependency information for the `service_core` library built by CMake, allowing the Frida module to link against it. This is crucial for interacting with that specific service during runtime instrumentation.

**Involvement of Binary/Low-Level, Linux, Android Kernel & Framework Knowledge:**

* **Binary/Low-Level:** CMake fundamentally deals with compiling and linking binary code. This module abstracts some of that away, but the underlying purpose is to manage the build process that results in executable code and libraries. The `detect_voidp_size()` function directly interacts with a low-level concept (pointer size).
* **Linux:** CMake is heavily used in the Linux ecosystem for building software. This module facilitates the integration of Linux-based CMake projects.
* **Android Kernel & Framework:** While Android's primary build system is not pure CMake, CMake is increasingly used for parts of the Android framework and for native libraries used by Android applications. This module could be used if Frida needs to interact with or instrument components built with CMake within the Android environment. The example above directly illustrates this. The generated CMake package configuration files help CMake's `find_package` locate libraries, which is essential for linking in native Android development.

**Logic and Reasoning (Hypothetical Input & Output):**

Let's consider the `configure_package_config_file` function:

**Hypothetical Input:**

```python
# In a meson.build file
config_data = configuration_data()
config_data.set('MY_MACRO', 'some_value')

cmake.configure_package_config_file(
    configuration: config_data,
    input: 'my_package_config.cmake.in',
    name: 'MyPackage',
    install_dir: join_paths(get_option('libdir'), 'cmake', 'MyPackage')
)
```

**And the content of `my_package_config.cmake.in`:**

```cmake
@PACKAGE_INIT@

set(MY_SETTING "@cmake@MY_MACRO@")
```

**Hypothetical Output (content of the generated `MyPackageConfig.cmake`):**

```cmake
####### Expanded from \@PACKAGE_INIT\@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was my_package_config.cmake.in ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../..\" ABSOLUTE)
# ... (potential extra lines from PACKAGE_INIT_EXT) ...
macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

####################################################################################

set(MY_SETTING "some_value")
```

**Explanation of Logic:**

1. The `configure_package_config_file` function reads the input template file (`my_package_config.cmake.in`).
2. It inserts the `PACKAGE_INIT_BASE` and potentially `PACKAGE_INIT_EXT` blocks at the `@PACKAGE_INIT@` marker. These blocks contain standard CMake code for setting up package paths.
3. It then substitutes variables in the template. `@cmake@MY_MACRO@` is replaced with the value of the `MY_MACRO` variable from the `config_data`.
4. The resulting CMake file is written to the specified output location.

**Common User/Programming Errors:**

1. **Incorrect Path to CMake Subproject:** Providing an invalid or non-existent path to the CMake subproject in `cmake.subproject()`.
   ```python
   # Error: Path is wrong
   cmake_proj = cmake.subproject('../wrong_cmake_dir')
   ```
2. **Missing CMakeLists.txt:** The directory specified for the CMake subproject doesn't contain a `CMakeLists.txt` file.
3. **Typos in CMake Target Names:**  Incorrectly spelling the name of a CMake target when using methods like `dependency()` or `target()`.
   ```python
   cmake_lib = cmake_sub.dependency('inccorect_target_name') # Error: Typo
   ```
4. **Using `options` and `cmake_options` Together:**  The code explicitly prevents using both the `options` keyword argument with a `CMakeSubprojectOptions` object and the `cmake_options` list directly in `cmake.subproject()`.
   ```python
   options = cmake.subproject_options()
   options.add_cmake_defines({'MY_DEFINE': 'value'})
   cmake_proj = cmake.subproject('my_cmake_proj', options: options, cmake_options: ['-DMY_OTHER_DEFINE=value']) # Error
   ```
5. **Incorrect `install_dir` in Package Configuration:** Specifying an `install_dir` that doesn't align with the actual installation layout, causing CMake's `find_package` to fail.
6. **Incorrect Variable Syntax in Template:**  Using the wrong syntax for variables in the input template file for `configure_package_config_file`.

**User Operations Leading to This Code (Debugging Clues):**

A user would interact with this code indirectly by writing `meson.build` files for their Frida project (or a project that uses Frida). Here's a step-by-step scenario:

1. **User wants to include a CMake-based library in their Frida module.**
2. **The user adds a `cmake.subproject()` call in their `meson.build` file,** specifying the path to the CMake project.
   ```python
   # meson.build
   cmake_mylib = cmake.subproject('path/to/my_cmake_lib')
   ```
3. **The user wants to link against a specific library built by the CMake project.**
4. **The user calls `cmake_mylib.dependency('mylibrary')`** to get a Meson dependency object.
   ```python
   my_dep = cmake_mylib.dependency('mylibrary')
   ```
5. **The user uses this dependency when defining their Frida module.**
   ```python
   frida_module = shared_library('my_frida_module', 'my_module.c', dependencies: my_dep)
   ```
6. **When Meson processes the `meson.build` file, it will execute the code in `cmake.py` to:**
   - Detect CMake if it hasn't already.
   - Configure and build the CMake subproject.
   - Extract information about the CMake targets (like include directories and libraries).
   - Create Meson dependency objects that represent the CMake outputs.

**Debugging Scenario:**

If a user encounters an error like "CMake target 'mylibrary' does not exist", they might start debugging by:

1. **Verifying the path in `cmake.subproject()` is correct.**
2. **Checking the `CMakeLists.txt` file of the subproject to ensure a target named 'mylibrary' is defined.**
3. **Potentially adding a `message(cmake_mylib.target_list())` in their `meson.build` to see the available CMake targets.** This would call the `target_list()` method in `cmake.py`.
4. **Examining the CMake build logs (usually in the Meson build directory) to see if the CMake subproject built successfully.**

In essence, this `cmake.py` module acts as a bridge between the Meson build system and the CMake build system, enabling the integration of CMake-based components into Frida projects. Understanding its functions and how they are used in `meson.build` files is crucial for anyone working with Frida who needs to incorporate external libraries or projects built with CMake.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2018 The Meson development team

from __future__ import annotations
import re
import os, os.path, pathlib
import shutil
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleObject, ModuleInfo

from .. import build, mesonlib, mlog, dependencies
from ..cmake import TargetOptions, cmake_defines_to_args
from ..interpreter import SubprojectHolder
from ..interpreter.type_checking import NATIVE_KW, REQUIRED_KW, INSTALL_DIR_KW, NoneType, in_set_validator
from ..interpreterbase import (
    FeatureNew,
    FeatureNewKwargs,

    stringArgs,
    permittedKwargs,
    noPosargs,
    noKwargs,

    InvalidArguments,
    InterpreterException,

    typed_pos_args,
    typed_kwargs,
    KwargInfo,
    ContainerTypeInfo,
)

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..cmake import SingleTargetOptions
    from ..environment import Environment
    from ..interpreter import Interpreter, kwargs
    from ..interpreterbase import TYPE_kwargs, TYPE_var

    class WriteBasicPackageVersionFile(TypedDict):

        arch_independent: bool
        compatibility: str
        install_dir: T.Optional[str]
        name: str
        version: str

    class ConfigurePackageConfigFile(TypedDict):

        configuration: T.Union[build.ConfigurationData, dict]
        input: T.Union[str, mesonlib.File]
        install_dir: T.Optional[str]
        name: str

    class Subproject(kwargs.ExtractRequired):

        options: T.Optional[CMakeSubprojectOptions]
        cmake_options: T.List[str]
        native: mesonlib.MachineChoice


COMPATIBILITIES = ['AnyNewerVersion', 'SameMajorVersion', 'SameMinorVersion', 'ExactVersion']

# Taken from https://github.com/Kitware/CMake/blob/master/Modules/CMakePackageConfigHelpers.cmake
PACKAGE_INIT_BASE = '''
####### Expanded from \\@PACKAGE_INIT\\@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was @inputFileName@ ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/@PACKAGE_RELATIVE_PATH@" ABSOLUTE)
'''
PACKAGE_INIT_EXT = '''
# Use original install prefix when loaded through a "/usr move"
# cross-prefix symbolic link such as /lib -> /usr/lib.
get_filename_component(_realCurr "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
get_filename_component(_realOrig "@absInstallDir@" REALPATH)
if(_realCurr STREQUAL _realOrig)
  set(PACKAGE_PREFIX_DIR "@installPrefix@")
endif()
unset(_realOrig)
unset(_realCurr)
'''
PACKAGE_INIT_SET_AND_CHECK = '''
macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

####################################################################################
'''

class CMakeSubproject(ModuleObject):
    def __init__(self, subp: SubprojectHolder):
        assert isinstance(subp, SubprojectHolder)
        assert subp.cm_interpreter is not None
        super().__init__()
        self.subp = subp
        self.cm_interpreter = subp.cm_interpreter
        self.methods.update({'get_variable': self.get_variable,
                             'dependency': self.dependency,
                             'include_directories': self.include_directories,
                             'target': self.target,
                             'target_type': self.target_type,
                             'target_list': self.target_list,
                             'found': self.found_method,
                             })

    def _args_to_info(self, args: T.List[str]) -> T.Dict[str, str]:
        if len(args) != 1:
            raise InterpreterException('Exactly one argument is required.')

        tgt = args[0]
        res = self.cm_interpreter.target_info(tgt)
        if res is None:
            raise InterpreterException(f'The CMake target {tgt} does not exist\n' +
                                       '  Use the following command in your meson.build to list all available targets:\n\n' +
                                       '    message(\'CMake targets:\\n - \' + \'\\n - \'.join(<cmake_subproject>.target_list()))')

        # Make sure that all keys are present (if not this is a bug)
        assert all(x in res for x in ['inc', 'src', 'dep', 'tgt', 'func'])
        return res

    @noKwargs
    @stringArgs
    def get_variable(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> TYPE_var:
        return self.subp.get_variable_method(args, kwargs)

    @FeatureNewKwargs('dependency', '0.56.0', ['include_type'])
    @permittedKwargs({'include_type'})
    @stringArgs
    def dependency(self, state: ModuleState, args: T.List[str], kwargs: T.Dict[str, str]) -> dependencies.Dependency:
        info = self._args_to_info(args)
        if info['func'] == 'executable':
            raise InvalidArguments(f'{args[0]} is an executable and does not support the dependency() method. Use target() instead.')
        orig = self.get_variable(state, [info['dep']], {})
        assert isinstance(orig, dependencies.Dependency)
        actual = orig.include_type
        if 'include_type' in kwargs and kwargs['include_type'] != actual:
            mlog.debug('Current include type is {}. Converting to requested {}'.format(actual, kwargs['include_type']))
            return orig.generate_system_dependency(kwargs['include_type'])
        return orig

    @noKwargs
    @stringArgs
    def include_directories(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> build.IncludeDirs:
        info = self._args_to_info(args)
        return self.get_variable(state, [info['inc']], kwargs)

    @noKwargs
    @stringArgs
    def target(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> build.Target:
        info = self._args_to_info(args)
        return self.get_variable(state, [info['tgt']], kwargs)

    @noKwargs
    @stringArgs
    def target_type(self, state: ModuleState, args: T.List[str], kwargs: TYPE_kwargs) -> str:
        info = self._args_to_info(args)
        return info['func']

    @noPosargs
    @noKwargs
    def target_list(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> T.List[str]:
        return self.cm_interpreter.target_list()

    @noPosargs
    @noKwargs
    @FeatureNew('CMakeSubproject.found()', '0.53.2')
    def found_method(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> bool:
        return self.subp is not None


class CMakeSubprojectOptions(ModuleObject):
    def __init__(self) -> None:
        super().__init__()
        self.cmake_options: T.List[str] = []
        self.target_options = TargetOptions()

        self.methods.update(
            {
                'add_cmake_defines': self.add_cmake_defines,
                'set_override_option': self.set_override_option,
                'set_install': self.set_install,
                'append_compile_args': self.append_compile_args,
                'append_link_args': self.append_link_args,
                'clear': self.clear,
            }
        )

    def _get_opts(self, kwargs: dict) -> SingleTargetOptions:
        if 'target' in kwargs:
            return self.target_options[kwargs['target']]
        return self.target_options.global_options

    @typed_pos_args('subproject_options.add_cmake_defines', varargs=dict)
    @noKwargs
    def add_cmake_defines(self, state: ModuleState, args: T.Tuple[T.List[T.Dict[str, TYPE_var]]], kwargs: TYPE_kwargs) -> None:
        self.cmake_options += cmake_defines_to_args(args[0])

    @typed_pos_args('subproject_options.set_override_option', str, str)
    @permittedKwargs({'target'})
    def set_override_option(self, state: ModuleState, args: T.Tuple[str, str], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).set_opt(args[0], args[1])

    @typed_pos_args('subproject_options.set_install', bool)
    @permittedKwargs({'target'})
    def set_install(self, state: ModuleState, args: T.Tuple[bool], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).set_install(args[0])

    @typed_pos_args('subproject_options.append_compile_args', str, varargs=str, min_varargs=1)
    @permittedKwargs({'target'})
    def append_compile_args(self, state: ModuleState, args: T.Tuple[str, T.List[str]], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).append_args(args[0], args[1])

    @typed_pos_args('subproject_options.append_link_args', varargs=str, min_varargs=1)
    @permittedKwargs({'target'})
    def append_link_args(self, state: ModuleState, args: T.Tuple[T.List[str]], kwargs: TYPE_kwargs) -> None:
        self._get_opts(kwargs).append_link_args(args[0])

    @noPosargs
    @noKwargs
    def clear(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> None:
        self.cmake_options.clear()
        self.target_options = TargetOptions()


class CmakeModule(ExtensionModule):
    cmake_detected = False
    cmake_root = None

    INFO = ModuleInfo('cmake', '0.50.0')

    def __init__(self, interpreter: Interpreter) -> None:
        super().__init__(interpreter)
        self.methods.update({
            'write_basic_package_version_file': self.write_basic_package_version_file,
            'configure_package_config_file': self.configure_package_config_file,
            'subproject': self.subproject,
            'subproject_options': self.subproject_options,
        })

    def detect_voidp_size(self, env: Environment) -> int:
        compilers = env.coredata.compilers.host
        compiler = compilers.get('c', None)
        if not compiler:
            compiler = compilers.get('cpp', None)

        if not compiler:
            raise mesonlib.MesonException('Requires a C or C++ compiler to compute sizeof(void *).')

        return compiler.sizeof('void *', '', env)[0]

    def detect_cmake(self, state: ModuleState) -> bool:
        if self.cmake_detected:
            return True

        cmakebin = state.find_program('cmake', silent=False)
        if not cmakebin.found():
            return False

        p, stdout, stderr = mesonlib.Popen_safe(cmakebin.get_command() + ['--system-information', '-G', 'Ninja'])[0:3]
        if p.returncode != 0:
            mlog.log(f'error retrieving cmake information: returnCode={p.returncode} stdout={stdout} stderr={stderr}')
            return False

        match = re.search('\nCMAKE_ROOT \\"([^"]+)"\n', stdout.strip())
        if not match:
            mlog.log('unable to determine cmake root')
            return False

        cmakePath = pathlib.PurePath(match.group(1))
        self.cmake_root = os.path.join(*cmakePath.parts)
        self.cmake_detected = True
        return True

    @noPosargs
    @typed_kwargs(
        'cmake.write_basic_package_version_file',
        KwargInfo('arch_independent', bool, default=False, since='0.62.0'),
        KwargInfo('compatibility', str, default='AnyNewerVersion', validator=in_set_validator(set(COMPATIBILITIES))),
        KwargInfo('name', str, required=True),
        KwargInfo('version', str, required=True),
        INSTALL_DIR_KW,
    )
    def write_basic_package_version_file(self, state: ModuleState, args: TYPE_var, kwargs: 'WriteBasicPackageVersionFile') -> ModuleReturnValue:
        arch_independent = kwargs['arch_independent']
        compatibility = kwargs['compatibility']
        name = kwargs['name']
        version = kwargs['version']

        if not self.detect_cmake(state):
            raise mesonlib.MesonException('Unable to find cmake')

        pkgroot = pkgroot_name = kwargs['install_dir']
        if pkgroot is None:
            pkgroot = os.path.join(state.environment.coredata.get_option(mesonlib.OptionKey('libdir')), 'cmake', name)
            pkgroot_name = os.path.join('{libdir}', 'cmake', name)

        template_file = os.path.join(self.cmake_root, 'Modules', f'BasicConfigVersion-{compatibility}.cmake.in')
        if not os.path.exists(template_file):
            raise mesonlib.MesonException(f'your cmake installation doesn\'t support the {compatibility} compatibility')

        version_file = os.path.join(state.environment.scratch_dir, f'{name}ConfigVersion.cmake')

        conf: T.Dict[str, T.Union[str, bool, int]] = {
            'CVF_VERSION': version,
            'CMAKE_SIZEOF_VOID_P': str(self.detect_voidp_size(state.environment)),
            'CVF_ARCH_INDEPENDENT': arch_independent,
        }
        mesonlib.do_conf_file(template_file, version_file, build.ConfigurationData(conf), 'meson')

        res = build.Data([mesonlib.File(True, state.environment.get_scratch_dir(), version_file)], pkgroot, pkgroot_name, None, state.subproject)
        return ModuleReturnValue(res, [res])

    def create_package_file(self, infile: str, outfile: str, PACKAGE_RELATIVE_PATH: str, extra: str, confdata: build.ConfigurationData) -> None:
        package_init = PACKAGE_INIT_BASE.replace('@PACKAGE_RELATIVE_PATH@', PACKAGE_RELATIVE_PATH)
        package_init = package_init.replace('@inputFileName@', os.path.basename(infile))
        package_init += extra
        package_init += PACKAGE_INIT_SET_AND_CHECK

        try:
            with open(infile, encoding='utf-8') as fin:
                data = fin.readlines()
        except Exception as e:
            raise mesonlib.MesonException(f'Could not read input file {infile}: {e!s}')

        result = []
        regex = mesonlib.get_variable_regex('cmake@')
        for line in data:
            line = line.replace('@PACKAGE_INIT@', package_init)
            line, _missing = mesonlib.do_replacement(regex, line, 'cmake@', confdata)

            result.append(line)

        outfile_tmp = outfile + "~"
        with open(outfile_tmp, "w", encoding='utf-8') as fout:
            fout.writelines(result)

        shutil.copymode(infile, outfile_tmp)
        mesonlib.replace_if_different(outfile, outfile_tmp)

    @noPosargs
    @typed_kwargs(
        'cmake.configure_package_config_file',
        KwargInfo('configuration', (build.ConfigurationData, dict), required=True),
        KwargInfo('input',
                  (str, mesonlib.File, ContainerTypeInfo(list, mesonlib.File)), required=True,
                  validator=lambda x: 'requires exactly one file' if isinstance(x, list) and len(x) != 1 else None,
                  convertor=lambda x: x[0] if isinstance(x, list) else x),
        KwargInfo('name', str, required=True),
        INSTALL_DIR_KW,
    )
    def configure_package_config_file(self, state: ModuleState, args: TYPE_var, kwargs: 'ConfigurePackageConfigFile') -> build.Data:
        inputfile = kwargs['input']
        if isinstance(inputfile, str):
            inputfile = mesonlib.File.from_source_file(state.environment.source_dir, state.subdir, inputfile)

        ifile_abs = inputfile.absolute_path(state.environment.source_dir, state.environment.build_dir)

        name = kwargs['name']

        (ofile_path, ofile_fname) = os.path.split(os.path.join(state.subdir, f'{name}Config.cmake'))
        ofile_abs = os.path.join(state.environment.build_dir, ofile_path, ofile_fname)

        install_dir = kwargs['install_dir']
        if install_dir is None:
            install_dir = os.path.join(state.environment.coredata.get_option(mesonlib.OptionKey('libdir')), 'cmake', name)

        conf = kwargs['configuration']
        if isinstance(conf, dict):
            FeatureNew.single_use('cmake.configure_package_config_file dict as configuration', '0.62.0', state.subproject, location=state.current_node)
            conf = build.ConfigurationData(conf)

        prefix = state.environment.coredata.get_option(mesonlib.OptionKey('prefix'))
        abs_install_dir = install_dir
        if not os.path.isabs(abs_install_dir):
            abs_install_dir = os.path.join(prefix, install_dir)

        # path used in cmake scripts are POSIX even on Windows
        PACKAGE_RELATIVE_PATH = pathlib.PurePath(os.path.relpath(prefix, abs_install_dir)).as_posix()
        extra = ''
        if re.match('^(/usr)?/lib(64)?/.+', abs_install_dir):
            extra = PACKAGE_INIT_EXT.replace('@absInstallDir@', abs_install_dir)
            extra = extra.replace('@installPrefix@', prefix)

        self.create_package_file(ifile_abs, ofile_abs, PACKAGE_RELATIVE_PATH, extra, conf)
        conf.used = True

        conffile = os.path.normpath(inputfile.relative_name())
        self.interpreter.build_def_files.add(conffile)

        res = build.Data([mesonlib.File(True, ofile_path, ofile_fname)], install_dir, install_dir, None, state.subproject)
        self.interpreter.build.data.append(res)

        return res

    @FeatureNew('subproject', '0.51.0')
    @typed_pos_args('cmake.subproject', str)
    @typed_kwargs(
        'cmake.subproject',
        REQUIRED_KW,
        NATIVE_KW.evolve(since='1.3.0'),
        KwargInfo('options', (CMakeSubprojectOptions, NoneType), since='0.55.0'),
        KwargInfo(
            'cmake_options',
            ContainerTypeInfo(list, str),
            default=[],
            listify=True,
            deprecated='0.55.0',
            deprecated_message='Use options instead',
        ),
    )
    def subproject(self, state: ModuleState, args: T.Tuple[str], kwargs_: Subproject) -> T.Union[SubprojectHolder, CMakeSubproject]:
        if kwargs_['cmake_options'] and kwargs_['options'] is not None:
            raise InterpreterException('"options" cannot be used together with "cmake_options"')
        dirname = args[0]
        kw: kwargs.DoSubproject = {
            'required': kwargs_['required'],
            'options': kwargs_['options'],
            'cmake_options': kwargs_['cmake_options'],
            'default_options': {},
            'version': [],
            'for_machine': kwargs_['native'],
        }
        subp = self.interpreter.do_subproject(dirname, kw, force_method='cmake')
        if not subp.found():
            return subp
        return CMakeSubproject(subp)

    @FeatureNew('subproject_options', '0.55.0')
    @noKwargs
    @noPosargs
    def subproject_options(self, state: ModuleState, args: TYPE_var, kwargs: TYPE_kwargs) -> CMakeSubprojectOptions:
        return CMakeSubprojectOptions()

def initialize(*args: T.Any, **kwargs: T.Any) -> CmakeModule:
    return CmakeModule(*args, **kwargs)
```