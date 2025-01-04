Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding - The Big Picture**

The first step is to recognize the code's purpose. The header comments clearly state it's a module (`cmake.py`) within the Frida dynamic instrumentation tool, specifically for interacting with CMake-based subprojects. This immediately tells us its primary function is bridging the gap between the Meson build system (used by Frida) and CMake.

**2. Core Functionality Identification - What are the main tasks?**

I'll scan the class and function definitions, paying attention to the names and docstrings (though none are provided in the example, in real-world scenarios, docstrings are crucial). Key names like `write_basic_package_version_file`, `configure_package_config_file`, `subproject`, `subproject_options`, and methods within `CMakeSubproject` and `CMakeSubprojectOptions` (like `get_variable`, `dependency`, `add_cmake_defines`) immediately suggest core functionalities.

*   **Package Configuration:** The `write_basic_package_version_file` and `configure_package_config_file` functions clearly deal with generating CMake package configuration files.
*   **Subproject Handling:**  The `subproject` function and the `CMakeSubproject` class manage the integration and interaction with CMake subprojects.
*   **CMake Options:** The `subproject_options` function and the `CMakeSubprojectOptions` class allow users to configure the CMake subproject.
*   **Target Information:**  Methods within `CMakeSubproject` like `get_variable`, `dependency`, `target`, `target_type`, and `target_list` focus on retrieving information about CMake targets.

**3. Relation to Reverse Engineering - Where does it fit?**

Since this is part of Frida, a dynamic instrumentation tool, the connection to reverse engineering is inherent. Frida allows runtime manipulation of applications. CMake is often used to build native libraries or applications that might be targets of reverse engineering. This module facilitates including and using such CMake-built components within Frida.

*   **Example:**  A reverse engineer might want to use a library built with CMake (perhaps for cryptography or data processing) within a Frida script. This module would allow them to easily link against that library.

**4. Binary/Low-Level, Linux, Android Knowledge - Identifying relevant concepts.**

Now, I'll look for code patterns or function names that hint at these deeper aspects:

*   **Binary/Low-Level:** The function `detect_voidp_size` explicitly deals with the size of a pointer, a fundamental concept in low-level programming and memory management. The generation of CMake config files is also relevant because these files guide the linking process of binary components.
*   **Linux:**  The code interacts with file paths (`os.path`, `pathlib`), executes external commands (`mesonlib.Popen_safe`), and deals with concepts like library directories (e.g.,  `{libdir}`). These are all common in Linux environments. The example with `/usr/lib` is a concrete Linux path.
*   **Android:** While not explicitly mentioning Android *kernel*, the use of Frida strongly implies potential interaction with Android applications. The module facilitates using native components in that context.
*   **Frameworks:** Although not directly interacting with *kernel* frameworks, the idea of integrating external (CMake-built) components into a larger Meson-based build (like Frida itself) is a form of framework extension.

**5. Logical Reasoning - Analyzing assumptions and outputs.**

For this, I'll consider specific function inputs and how they might be processed:

*   **`write_basic_package_version_file`:**  *Assumption:* The user provides a `name` and `version`. *Output:*  A CMake config version file is generated in the build directory.
*   **`configure_package_config_file`:** *Assumption:*  The user provides an `input` CMake template file and a `configuration` dictionary. *Output:* A processed CMake config file is created, with variables from the `configuration` replaced.
*   **`subproject`:** *Assumption:* The user provides a path to a CMake project. *Output:*  A `CMakeSubproject` object is returned, allowing access to the CMake project's targets and variables.

**6. User Errors - Spotting potential pitfalls.**

I'll look for situations where a user might misuse the module:

*   **Incorrect Paths:** Providing incorrect paths to CMake subprojects or input files.
*   **Missing CMake:**  Not having CMake installed or accessible in the PATH. The code explicitly checks for this.
*   **Type Mismatches:** Providing the wrong types of arguments to functions (though type hinting helps mitigate this).
*   **Conflicting Options:**  Using both `cmake_options` and `options` in `subproject`. The code explicitly checks for this.
*   **Unsupported CMake Versions:** Using a `compatibility` setting not supported by the installed CMake version.

**7. Debugging - Tracing the execution flow.**

To understand how a user reaches a specific point in the code, I'll think about the typical workflow:

1. The user writes a `meson.build` file.
2. In this file, they use the `cmake.subproject()` function to include a CMake project.
3. They might then use methods of the returned `CMakeSubproject` object (like `dependency()` or `target()`) to interact with targets in the CMake subproject.
4. If something goes wrong, they might need to debug within the `cmake.py` module itself, following the call stack from their `meson.build` file into this code. For instance, an error in `dependency()` would lead them to investigate the `_args_to_info` method and how it retrieves target information.

**Self-Correction/Refinement during the Process:**

*   Initially, I might focus too much on the specific syntax. I need to pull back and understand the *purpose* of each function.
*   I need to remember the context: this is *part of Frida*. This immediately highlights the reverse engineering connection.
*   I should pay close attention to error handling and validation within the code, as these often point to potential user errors.
*   When thinking about logical reasoning, I should consider both successful and unsuccessful scenarios to understand the inputs and expected outputs fully.

By following these steps, combining code analysis with an understanding of the broader context (Frida, CMake, build systems), and considering potential user interactions, I can effectively analyze the provided Python code and address all the prompt's requirements.
This Python code file, `cmake.py`, is a module within the Meson build system that provides functionality for interacting with CMake-based subprojects. It allows Meson projects to incorporate and utilize components built with CMake. Let's break down its features and connections:

**Functionalities:**

1. **`write_basic_package_version_file`**:
    *   **Function:** Generates a basic CMake package version file (e.g., `YourPackageConfigVersion.cmake`). This file is crucial for CMake's `find_package()` mechanism to determine the compatibility of a found package with the required version.
    *   **Purpose:**  Allows a Meson project to expose itself as a findable CMake package, even if it's not primarily a CMake project. This is useful for interoperability.
    *   **Arguments:** Takes arguments like `name`, `version`, `compatibility` (e.g., "AnyNewerVersion", "ExactVersion"), and `install_dir`.

2. **`configure_package_config_file`**:
    *   **Function:** Processes a CMake configuration file template (e.g., `YourPackageConfig.cmake.in`) and generates the actual configuration file (e.g., `YourPackageConfig.cmake`). It replaces variables in the template with values provided in the `configuration` argument.
    *   **Purpose:** Enables the creation of CMake package configuration files that define targets, include directories, library locations, and other essential information for using the package. This is the core of how CMake projects consume dependencies.
    *   **Arguments:** Takes `configuration` (a dictionary or Meson's `ConfigurationData`), `input` (the template file), `name`, and `install_dir`.

3. **`subproject`**:
    *   **Function:**  Integrates a CMake subproject into the current Meson build. It executes the CMake build process for the specified directory.
    *   **Purpose:** Allows Meson to build and link against libraries or other artifacts produced by a CMake project. This is the primary way to use CMake-based dependencies within a Meson project.
    *   **Arguments:** Takes the `dirname` of the CMake subproject and optional arguments like `required`, `native`, `options`, and `cmake_options`.

4. **`subproject_options`**:
    *   **Function:** Creates an object (`CMakeSubprojectOptions`) that allows configuring options for a CMake subproject before it's built.
    *   **Purpose:** Provides a way to pass CMake-specific definitions, override options, control installation, and append compiler/linker flags to the CMake build.

5. **`CMakeSubproject` Class**:
    *   **Function:** Represents an instantiated CMake subproject within Meson. It provides methods to interact with the built CMake project.
    *   **Methods:**
        *   **`get_variable`**: Retrieves the value of a CMake variable from the subproject.
        *   **`dependency`**: Returns a Meson dependency object representing a target in the CMake subproject, allowing it to be linked against.
        *   **`include_directories`**: Returns Meson include directories object for a target, making its headers available.
        *   **`target`**: Returns a Meson target object representing a built artifact (library, executable) from the CMake subproject.
        *   **`target_type`**: Returns the type of a CMake target (e.g., "library", "executable").
        *   **`target_list`**: Returns a list of all available targets in the CMake subproject.
        *   **`found_method`**: Indicates whether the CMake subproject was successfully found and integrated.

6. **`CMakeSubprojectOptions` Class**:
    *   **Function:**  Holds configuration options for a CMake subproject.
    *   **Methods:**
        *   **`add_cmake_defines`**: Adds `-D` definitions to the CMake command line.
        *   **`set_override_option`**: Sets a specific CMake option using `-DOPTION=VALUE`.
        *   **`set_install`**: Controls whether targets in the subproject should be installed.
        *   **`append_compile_args`**: Appends compiler arguments for specific languages or globally.
        *   **`append_link_args`**: Appends linker arguments.
        *   **`clear`**: Resets the CMake subproject options.

7. **Internal Helper Functions**:
    *   **`detect_cmake`**: Checks if CMake is installed and retrieves its root directory.
    *   **`detect_voidp_size`**:  Detects the size of a `void*` pointer using the available C/C++ compiler, crucial for generating correct version files.
    *   **`create_package_file`**:  Handles the core logic of processing the CMake config file template, including variable substitution.

**Relationship with Reverse Engineering:**

This module is highly relevant to reverse engineering in several ways, especially when dealing with targets that use CMake for their build process:

*   **Interoperability with Native Libraries:** Reverse engineers often need to interact with or analyze native libraries (written in C, C++, etc.). If these libraries are built with CMake, this module allows Frida (which uses Meson) to easily incorporate them into its own build process or into scripts that load and interact with these libraries at runtime.
    *   **Example:** A reverse engineer wants to use a cryptographic library built with CMake within a Frida script to decrypt data during runtime analysis. They can use `cmake.subproject()` to build the library and then `dependency()` to link against it.
*   **Analyzing CMake-Based Applications:** When reverse engineering an application built with CMake, understanding its build structure and dependencies is crucial. This module provides a way to programmatically access information about the targets, include directories, and dependencies of the CMake project.
    *   **Example:** A reverse engineer is analyzing a game engine built with CMake. They can use `cmake.subproject()` to integrate the engine's build system and then use `target_list()` to get a list of all the libraries and executables, helping them understand the project's components.
*   **Generating CMake Configuration for Frida Modules:** If a Frida module needs to expose itself to other CMake-based tools or projects, `write_basic_package_version_file` and `configure_package_config_file` can be used to generate the necessary CMake package configuration files.

**Binary/Bottom Layer, Linux, Android Kernel & Framework Knowledge:**

*   **Binary/Bottom Layer:**
    *   The module directly deals with compiling and linking native code. Functions like `append_compile_args` and `append_link_args` directly manipulate the commands used to generate binary executables and libraries.
    *   `detect_voidp_size` is a low-level operation, as the size of a pointer is fundamental to memory management and architecture.
    *   The generated CMake configuration files are used by the CMake build system to manage the linking of binary objects.
*   **Linux:**
    *   The code uses standard Python `os` and `pathlib` modules for interacting with the file system, which is essential on Linux.
    *   The examples in the code (like the `PACKAGE_INIT_EXT` block dealing with `/usr/lib`) are specific to Linux file system conventions.
    *   The execution of CMake as an external process (`mesonlib.Popen_safe`) is a common pattern in build systems on Linux.
*   **Android Kernel & Framework:** While this module doesn't directly interact with the Android kernel in the same way as kernel modules, it's relevant for:
    *   **Native Libraries on Android:** Android applications often include native libraries built with CMake (e.g., for performance-critical tasks). This module enables integrating and using these libraries within Frida scripts running on Android.
    *   **Reverse Engineering Android Native Code:** When reverse engineering Android applications with native components, understanding how these components are built (often with CMake) is important. This module provides tools to interact with that build process.
    *   **Frida's Own Build Process on Android:**  Frida itself needs to be built for Android, and it likely uses similar mechanisms for managing native dependencies.

**Logical Reasoning (Assumptions and Outputs):**

Let's take the `configure_package_config_file` function as an example:

*   **Assumption:** The user provides a valid CMake template file (`input`) containing placeholders like `@MY_VARIABLE@` and a `configuration` dictionary with corresponding keys and values (e.g., `{'MY_VARIABLE': 'some_value'}`).
*   **Assumption:** The user provides a `name` for the package (e.g., "MyLib").
*   **Assumption:** The user specifies an `install_dir` (or relies on the default).
*   **Input:** `configuration={'MY_VARIABLE': 'value123'}, input='MyLibConfig.cmake.in', name='MyLib'` where `MyLibConfig.cmake.in` contains the line `set(MY_SETTING "@MY_VARIABLE@")`.
*   **Output:** A file named `MyLibConfig.cmake` will be created in the build directory (or specified `install_dir`) containing the line `set(MY_SETTING "value123")`. The `@MY_VARIABLE@` placeholder will be replaced with the value from the `configuration` dictionary.

**User or Programming Common Usage Errors:**

1. **Incorrect Path to CMake Subproject:**
    *   **Error:**  Providing a wrong directory path to the `cmake.subproject()` function.
    *   **Example:** `cmake.subproject('../wrong_cmake_dir')` when the CMake project is actually in `../my_cmake_project`.
    *   **Consequence:** Meson will fail to find the CMake project, leading to a build error.

2. **Missing CMake Installation:**
    *   **Error:** Trying to use the `cmake` module without CMake being installed on the system or accessible in the `PATH`.
    *   **Consequence:** The `detect_cmake` function will fail, and subsequent calls to CMake-related functions will raise an exception.

3. **Incorrectly Formatted CMake Template:**
    *   **Error:** Providing a malformed CMake template file to `configure_package_config_file` that doesn't follow CMake syntax.
    *   **Example:** Missing closing parentheses or using incorrect variable syntax.
    *   **Consequence:** While `cmake.py` itself might not immediately error, the generated `YourPackageConfig.cmake` file will likely cause errors when CMake tries to parse it later.

4. **Mismatched Configuration Variables:**
    *   **Error:** Providing a `configuration` dictionary to `configure_package_config_file` with keys that don't match the placeholders in the input template file.
    *   **Example:** Template has `@MY_VAR@`, but the configuration has `{'OTHER_VAR': 'value'}`.
    *   **Consequence:** The placeholders in the generated CMake file will not be replaced, potentially leading to unexpected behavior or errors in CMake.

5. **Conflicting Options in `subproject`:**
    *   **Error:** Using both the deprecated `cmake_options` and the newer `options` keyword argument in `cmake.subproject()`.
    *   **Example:** `cmake.subproject('my_cmake', cmake_options=['-DDEBUG=1'], options=cmake.subproject_options().add_cmake_defines({'RELEASE': '0'}))`
    *   **Consequence:** The code explicitly checks for this and raises an `InterpreterException`.

**User Operation Steps to Reach This Code (Debugging Scenario):**

1. **User has a Meson project that needs to use a library built with CMake.**
2. **In their `meson.build` file, they use the `cmake.subproject()` function to include the CMake project.**
   ```python
   cmake_proj = cmake.subproject('path/to/my_cmake_lib')
   mylib_dep = cmake_proj.dependency('mylibrary')
   executable('my_app', 'main.c', dependencies: mylib_dep)
   ```
3. **During the Meson configuration or build process, an error occurs related to the CMake subproject.**  This could be due to:
    *   CMake failing to configure or build.
    *   Meson failing to find a target in the CMake subproject.
    *   Linking errors because of incorrect include directories or library paths.
4. **The user might need to debug the interaction between Meson and CMake.** They might:
    *   Examine the Meson log output to see the exact CMake commands being executed.
    *   Inspect the generated files in the Meson build directory related to the CMake subproject.
    *   **Potentially step through the `cmake.py` code in a debugger (if they are developing or troubleshooting Meson itself or a custom Meson module).**
5. **To reach specific parts of `cmake.py` during debugging:**
    *   **If the error is during CMake subproject integration:** They might set breakpoints in the `subproject()` function to see how the CMake build is being invoked and if any errors are reported.
    *   **If the error is related to finding a CMake target:** They might set breakpoints in the `CMakeSubproject.dependency()` or `CMakeSubproject.target()` methods to understand how the target information is being retrieved from the CMake subproject's build system.
    *   **If the error involves generating CMake package configuration files:** They might set breakpoints in `write_basic_package_version_file()` or `configure_package_config_file()` to check the values of variables and the contents of the generated files.

In essence, this `cmake.py` module acts as a bridge between the Meson and CMake build systems, and users will interact with it whenever they need to incorporate CMake-built components into their Meson projects. Understanding its functionalities is crucial for successfully managing projects with mixed build systems.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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