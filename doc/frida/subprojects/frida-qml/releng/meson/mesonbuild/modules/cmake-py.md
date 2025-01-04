Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `cmake.py` file within the Frida project. They're particularly interested in how it relates to reverse engineering, low-level concepts, logical reasoning (within the code), common user errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and High-Level Understanding:**

A quick scan reveals several important aspects:

* **Module Structure:** It's a Meson module named `cmake`. Meson is a build system, so this module likely helps integrate CMake projects into Meson-based builds.
* **Key Classes:**  `CMakeSubproject`, `CMakeSubprojectOptions`, and `CmakeModule`. These suggest the module handles CMake subprojects and their configuration.
* **Function Names:** Functions like `write_basic_package_version_file`, `configure_package_config_file`, `subproject`, `get_variable`, `dependency`, `target`, etc., give hints about specific functionalities.
* **Imports:**  Imports from `mesonbuild`, `cmake`, and `interpreter` confirm the integration with the Meson build system and interaction with CMake.

**3. Deeper Dive into Functionality (Iterative Process):**

Now, I'll go through each class and its methods, trying to understand their purpose and how they interact.

* **`CMakeSubproject`:** This seems to represent a CMake subproject within the Meson build. The methods provide ways to access information about CMake targets:
    * `get_variable`:  Gets a CMake variable's value.
    * `dependency`:  Represents a CMake dependency, potentially used for linking.
    * `include_directories`: Gets include directories of a CMake target.
    * `target`: Gets a CMake target as a Meson target.
    * `target_type`: Gets the type of a CMake target (e.g., library, executable).
    * `target_list`: Lists all available CMake targets.
    * `found_method`: Checks if the CMake subproject was successfully found.

* **`CMakeSubprojectOptions`:** This class allows configuring how the CMake subproject is built:
    * `add_cmake_defines`: Adds CMake definitions (like `-D`).
    * `set_override_option`: Sets CMake options.
    * `set_install`: Controls whether CMake targets are installed.
    * `append_compile_args`: Adds compiler flags for CMake targets.
    * `append_link_args`: Adds linker flags for CMake targets.
    * `clear`: Resets the options.

* **`CmakeModule`:** This is the main module class.
    * `write_basic_package_version_file`: Creates a basic CMake package version file.
    * `configure_package_config_file`: Creates a more advanced CMake package configuration file.
    * `subproject`:  The core function for including a CMake subproject.
    * `subproject_options`: Creates an object to configure CMake subprojects.
    * Helper functions: `detect_voidp_size` and `detect_cmake`.

**4. Connecting to User's Specific Questions:**

Now, I'll explicitly address each part of the user's request:

* **Functionality List:**  Summarize the purpose of each class and its key methods in clear, concise terms.

* **Relation to Reverse Engineering:** This is where the Frida context becomes crucial. I need to consider how integrating CMake projects might be relevant to Frida's instrumentation capabilities. The key connection is that Frida often interacts with and modifies the behavior of existing compiled code. CMake is a common build system for such code (especially native libraries). Therefore, the ability to include and configure CMake projects within a Frida build setup is valuable for extending Frida's capabilities or building tools that work alongside instrumented applications. *Example:* Building a custom native agent using CMake that Frida can load.

* **Binary/Low-Level, Linux/Android Kernel/Framework:**  Consider where low-level concepts are involved:
    * CMake itself deals with compiler and linker flags, which directly affect binary generation.
    * The `detect_voidp_size` function specifically probes the target architecture's pointer size, a fundamental low-level detail.
    * When integrating with Android, CMake is often used for building native components of Android apps. The resulting libraries can interact with the Android framework. *Example:* Building a native Android library that Frida then instruments.

* **Logical Reasoning:** Look for conditional logic, loops, and data transformations. In this code, the logic is primarily around:
    * Parsing arguments and keyword arguments.
    * Interacting with the Meson API (e.g., creating build targets, data files).
    * Generating CMake configuration files based on templates and user input.
    * *Example:* The `configure_package_config_file` function's logic for generating the `PACKAGE_INIT` section. I can create hypothetical inputs (template file content, configuration data) and trace how the output file is generated.

* **Common User Errors:** Think about what mistakes a developer might make when using this module:
    * Incorrect function arguments (wrong types, missing arguments).
    * Conflicting options (e.g., using both `cmake_options` and `options`).
    * Incorrect paths to CMake subprojects or configuration files.
    * Mismatched CMake versions or missing CMake features. *Example:* Trying to use a `compatibility` setting not supported by the installed CMake version.

* **User Steps to Reach the Code (Debugging Context):** Consider a scenario where a developer is working on a Frida-related project that uses CMake subprojects. They might encounter issues during the build process. The steps could involve:
    * Creating a `meson.build` file that uses the `cmake.subproject()` function.
    * Running `meson setup` or `ninja`.
    * Encountering errors related to finding CMake, configuring the subproject, or linking issues.
    * The developer might then need to inspect the generated build files or even step through the Meson code (including this `cmake.py` file) to understand the problem.

**5. Structuring the Answer:**

Finally, organize the information clearly, using headings and bullet points to address each part of the user's request. Provide concrete examples to illustrate the concepts. Ensure the language is precise and avoids jargon where possible, or explains it when necessary.
This Python code defines a Meson build system module named `cmake`. It provides functionality to integrate CMake-based subprojects into a Meson build and to generate CMake package configuration files. Here's a breakdown of its features:

**Core Functionality:**

1. **Integrating CMake Subprojects (`subproject`):**
   - Allows including external projects that use CMake as their build system within a larger Meson project.
   - Provides options to configure the CMake subproject, such as setting CMake definitions, overriding CMake options, and controlling installation.
   - Exposes information about the CMake subproject's targets (libraries, executables, etc.) to the Meson build.

2. **Generating CMake Package Configuration Files (`write_basic_package_version_file`, `configure_package_config_file`):**
   - Facilitates creating files that help other CMake projects find and use the current project as a dependency.
   - `write_basic_package_version_file` generates a simple version file.
   - `configure_package_config_file` generates a more comprehensive configuration file from a template, allowing for variable substitution based on the Meson build configuration.

3. **Accessing CMake Target Information (`CMakeSubproject` class):**
   - After including a CMake subproject, this class provides methods to query information about its targets:
     - `get_variable`: Retrieves the value of a CMake variable.
     - `dependency`:  Represents a CMake target (typically a library) as a Meson dependency.
     - `include_directories`: Gets the include directories of a CMake target.
     - `target`: Gets a CMake target as a Meson build target.
     - `target_type`: Returns the type of a CMake target (e.g., "library", "executable").
     - `target_list`: Lists all targets in the CMake subproject.
     - `found_method`: Checks if the CMake subproject was successfully found.

4. **Configuring CMake Subproject Options (`CMakeSubprojectOptions` class):**
   - Allows setting various options for the CMake subproject:
     - `add_cmake_defines`: Adds CMake definitions (like `-DVAR=VALUE`).
     - `set_override_option`: Sets specific CMake options.
     - `set_install`: Controls whether CMake targets should be installed.
     - `append_compile_args`: Adds compiler flags for specific targets.
     - `append_link_args`: Adds linker flags for specific targets.
     - `clear`: Resets the options.

5. **Detecting CMake:**
   - The module attempts to automatically detect the CMake executable and its root directory.

**Relationship to Reverse Engineering:**

This module is relevant to reverse engineering in scenarios where you want to:

* **Integrate with or analyze software built with CMake:** Many projects, especially those involving native code or cross-platform development, use CMake. Frida, being a dynamic instrumentation tool, often targets such software. This module allows building Frida tools or extensions that depend on or interact with CMake-based libraries.

   **Example:** Imagine you're reverse-engineering a game engine built with CMake. You might write a Frida script that needs to interact with a specific rendering library within that engine. You could use this `cmake.py` module to include the game engine's build system as a subproject in your Frida tool's build. This would allow you to link against the engine's libraries and potentially call functions or access data structures within them from your Frida script's agent code.

* **Build custom native agents or extensions for Frida using CMake:**  Frida allows loading custom native code (agents) into the target process. You might choose to build these agents using CMake for better control over the build process, especially if they have complex dependencies.

   **Example:** You might be building a sophisticated Frida agent that requires a specific C++ library (e.g., for parsing data structures). This library could be built using CMake. You'd use `cmake.subproject` to include the library's build and then link your Frida agent against it.

**Involvement of Binary, Linux, Android Kernel & Framework:**

This module interacts with these concepts because CMake is a build system that ultimately produces binary executables and libraries for various platforms, including Linux and Android.

* **Binary Underlying:** CMake manages the compilation and linking process, directly influencing the final binary output. The `append_compile_args` and `append_link_args` methods allow fine-tuning the compiler and linker behavior, which directly affects the generated binary code.

   **Example:** When building a native Android library as a CMake subproject, this module helps in setting up the correct compiler flags and linker settings to produce an `.so` file compatible with the Android runtime environment.

* **Linux:** CMake is widely used on Linux. The module's ability to find the CMake executable and its root directory is essential for Linux-based development.

   **Example:** If you're building a Frida tool on Linux that interacts with a CMake-based library, this module ensures that the correct compiler and linker are invoked with the necessary flags for the Linux environment.

* **Android Kernel & Framework:** While this module itself doesn't directly interact with the Android kernel, it plays a crucial role when building native components for Android applications. Android development often involves using the Native Development Kit (NDK), which uses CMake as its default build system.

   **Example:** When building a Frida gadget (a shared library injected into an Android app) using CMake, this module helps configure the build process to target the Android architecture and link against necessary Android framework libraries. The `detect_voidp_size` function is relevant here as pointer sizes can vary across architectures (e.g., 32-bit vs. 64-bit Android).

**Logical Reasoning:**

The code involves logical reasoning in several places:

* **Conditional Logic:**  The `detect_cmake` function checks if CMake is found before proceeding. The `configure_package_config_file` function has logic to determine the installation directory and generate the appropriate `PACKAGE_INIT` content based on whether the installation directory is within `/usr/lib` or similar.

   **Example:**  In `configure_package_config_file`, if the `install_dir` is not explicitly provided by the user, it defaults to a path under the system's library directory (e.g., `/usr/lib/cmake`). This is a logical deduction based on common practices for installing CMake packages.

   **Hypothetical Input:**
   ```python
   cmake_mod.configure_package_config_file(
       state,
       configuration={'my_var': 'hello'},
       input='my_config.cmake.in',
       name='MyPackage'
   )
   ```
   **Output:** The function will:
   1. Read the content of `my_config.cmake.in`.
   2. Replace any occurrences of `@cmake@my_var@` with `hello`.
   3. Generate a `MyPackageConfig.cmake` file in the build directory.
   4. If no `install_dir` was specified, it will schedule the installation of this file to a default CMake package installation location (e.g., `/usr/lib/cmake/MyPackage`).

* **Data Transformation:** The `cmake_defines_to_args` function converts a dictionary of CMake definitions into a list of command-line arguments (e.g., `{'ENABLE_FEATURE': True}` becomes `['-DENABLE_FEATURE=ON']`).

**User or Programming Common Usage Errors:**

* **Incorrect Arguments to Functions:**
   - Passing the wrong type of argument to a function (e.g., a string instead of a boolean for the `set_install` option).
   - Missing required arguments for functions like `write_basic_package_version_file` (e.g., forgetting to specify `name` or `version`).

   **Example:**
   ```python
   # Error: Passing a string where a boolean is expected
   subproject_options.set_install("yes")
   ```
   This would likely raise an `InvalidArguments` exception because `set_install` expects a boolean value.

* **Conflicting Options:**
   - Trying to use both the deprecated `cmake_options` and the newer `options` keyword argument in `cmake.subproject`.

   **Example:**
   ```python
   cmake.subproject(
       'my_cmake_project',
       required=True,
       options=cmake.subproject_options(),
       cmake_options=['-DMY_OPTION=VALUE']
   )
   ```
   This would raise an `InterpreterException` as the code explicitly checks for this conflict.

* **Incorrect Paths:**
   - Providing an incorrect path to the CMake subproject directory in `cmake.subproject`.
   - Specifying a non-existent input file for `configure_package_config_file`.

* **Using Features Not Available in the Installed CMake Version:**
   - Specifying a `compatibility` level in `write_basic_package_version_file` that is not supported by the user's installed CMake version.

   **Example:** If the user's CMake version is old and doesn't support `SameMinorVersion` compatibility, calling `write_basic_package_version_file` with `compatibility='SameMinorVersion'` will result in an error.

* **Misunderstanding CMake Concepts:**
   - Incorrectly setting CMake definitions or options without understanding their impact on the CMake build process.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user would typically interact with this code indirectly through their `meson.build` file when they are:

1. **Including a CMake Subproject:**
   - The user adds a `cmake.subproject()` call in their `meson.build` file, specifying the directory of the CMake project they want to include.
   - When Meson processes this file, it will instantiate the `CmakeModule` and call the `subproject` method.

2. **Configuring a CMake Subproject:**
   - Before or during the `cmake.subproject()` call, the user might use `cmake.subproject_options()` to create a configuration object and then use its methods (`add_cmake_defines`, `set_override_option`, etc.) to customize the CMake subproject's build.

3. **Generating CMake Package Configuration Files:**
   - The user calls `cmake.write_basic_package_version_file()` or `cmake.configure_package_config_file()` in their `meson.build` to generate files that help other CMake projects find their project.

**Debugging Scenarios:**

If a user encounters issues, they might end up inspecting this code or related Meson internals during debugging:

* **CMake Subproject Not Found:** If the path to the CMake subproject is incorrect, the `subproject` method will fail, and the user might investigate why the `SubprojectHolder` is not found.

* **CMake Configuration Errors:** If the CMake subproject fails to configure (e.g., due to missing dependencies or incorrect options), the user might look at how the options are being passed to the CMake invocation within the `subproject` method.

* **Generated CMake Config Files Are Incorrect:** If the generated `MyPackageConfig.cmake` file has incorrect content, the user might examine the logic in `configure_package_config_file`, particularly the variable substitution and the generation of the `PACKAGE_INIT` section.

* **Linking Errors:** If there are issues linking against targets from the CMake subproject, the user might investigate how the `dependency` and `target` methods of the `CMakeSubproject` class are being used to expose the CMake targets to the Meson build.

By understanding the functionality of this `cmake.py` module, developers can effectively integrate CMake-based projects into their Meson builds and troubleshoot any issues that may arise during this process.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```