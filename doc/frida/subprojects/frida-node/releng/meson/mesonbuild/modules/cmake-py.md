Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The request asks for the functionalities of the `cmake.py` module within the Frida project, specifically looking for connections to reverse engineering, low-level details (kernel, etc.), logical reasoning, potential user errors, and how users might reach this code.

**2. Initial Code Scan - High-Level Overview:**

My first step is always to skim the code for imports, class definitions, and major function definitions. This gives me a general understanding of the module's purpose.

* **Imports:**  `re`, `os`, `pathlib`, `shutil`, `typing`. These suggest file manipulation, regular expressions, and type hinting. The presence of `from . import ...` hints at its integration within a larger Meson build system.
* **Classes:** `CMakeSubproject`, `CMakeSubprojectOptions`, `CmakeModule`. This immediately tells me the module is object-oriented and likely deals with CMake subprojects.
* **Functions in `CmakeModule`:** `write_basic_package_version_file`, `configure_package_config_file`, `subproject`, `subproject_options`. These seem to be the core functionalities exposed by the module.

**3. Focusing on Core Functionalities:**

I'll examine the functions in `CmakeModule` first, as they represent the main interface of this module.

* **`write_basic_package_version_file`:** This clearly deals with generating a CMake package version file. The keywords like "compatibility" (`AnyNewerVersion`, etc.) and the file template path containing "BasicConfigVersion" solidify this. It interacts with CMake's own modules.
* **`configure_package_config_file`:** This function generates a CMake package configuration file based on a template and provided configuration data. It involves file reading, string replacement (`@PACKAGE_INIT@`), and writing.
* **`subproject`:**  This is the most important function. It's responsible for integrating CMake subprojects into the Meson build. It takes a directory as input and allows specifying CMake options. The return types `SubprojectHolder` and `CMakeSubproject` confirm this.
* **`subproject_options`:** This function creates an object (`CMakeSubprojectOptions`) to manage options for CMake subprojects.

**4. Deep Dive into `CMakeSubproject`:**

This class represents a specific CMake subproject within the Meson environment. Its methods are about interacting with the CMake project:

* **`get_variable`:**  Retrieves CMake variables.
* **`dependency`:**  Declares a dependency on a CMake target.
* **`include_directories`:** Gets include directories of a CMake target.
* **`target`:**  Retrieves a CMake target.
* **`target_type`:**  Gets the type of a CMake target (e.g., library, executable).
* **`target_list`:** Lists all available CMake targets in the subproject.
* **`found_method`:** Checks if the CMake subproject was successfully found.

**5. Analyzing `CMakeSubprojectOptions`:**

This class manages options that can be passed to the CMake subproject during its configuration:

* **`add_cmake_defines`:** Adds `-D` definitions to the CMake command line.
* **`set_override_option`:** Sets CMake cache variables using `-D<var>:<type>=<value>`.
* **`set_install`:** Controls whether a target should be installed.
* **`append_compile_args`:** Adds compiler flags for specific targets.
* **`append_link_args`:** Adds linker flags.
* **`clear`:** Resets the options.

**6. Connecting to the Prompts:**

Now, I'll systematically address each part of the request:

* **Functionalities:**  This has been largely covered in steps 3, 4, and 5. I'll summarize them clearly in the final answer.
* **Relationship to Reverse Engineering:**  The key here is *how* these functionalities could be used. The ability to access CMake targets, their dependencies, include directories, and set build options are crucial for integrating external libraries or components – which might be targets of reverse engineering or necessary for building reverse engineering tools. Frida itself is a dynamic instrumentation tool used for reverse engineering, so this module plays a role in *building* Frida.
* **Binary/Low-Level, Linux/Android Kernel/Framework:** The keywords are "compile args," "link args," and the general purpose of Frida. Frida interacts with processes at a very low level. This module, by allowing the setting of compile/link flags, helps control how Frida is built and linked against system libraries (potentially including Android framework libraries). The `detect_voidp_size` function also touches upon architecture-specific details.
* **Logical Reasoning (Assumptions/Input/Output):** I'll focus on the conditional logic within the functions, especially in `configure_package_config_file` and the checks in `write_basic_package_version_file`. I'll create simple scenarios to illustrate the flow.
* **User/Programming Errors:** Look for potential mistakes users might make when calling these functions, such as incorrect argument types, missing required arguments, or using deprecated features. The docstrings and type hints provide clues.
* **User Journey/Debugging:** Think about the typical Meson build process. How does a user end up interacting with these CMake functions?  It usually involves declaring a CMake subproject within their `meson.build` file. This provides the steps for the debugging narrative.

**7. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original request with specific examples and explanations. Use bullet points and clear headings to enhance readability. Ensure the language is accessible to someone familiar with build systems and potentially reverse engineering concepts.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer that addresses all aspects of the prompt. The process involves understanding the code's purpose, dissecting its components, and then connecting those components to the specific questions asked.
This Python code defines a Meson module named `cmake`, which provides functionality for integrating CMake-based subprojects into a Meson build system. It essentially acts as a bridge between Meson and CMake. Let's break down its functionalities:

**Core Functionalities:**

1. **`write_basic_package_version_file`:**
   - **Purpose:** Generates a basic CMake package version file (`<name>ConfigVersion.cmake`). This file is used by CMake's `find_package()` command to determine the version compatibility of a package.
   - **Functionality:**
     - Takes package name, version, and compatibility requirements as input.
     - Detects the CMake installation on the system.
     - Uses a CMake template file (`BasicConfigVersion-<compatibility>.cmake.in`) to create the version file.
     - Performs variable substitution within the template (e.g., setting the version).
     - Installs the generated file to the specified directory.
   - **Relevance to Reverse Engineering:** While not directly a reverse engineering *method*, this is crucial for managing dependencies when building tools *used for* reverse engineering. If a reverse engineering tool depends on a CMake-based library, this function helps ensure the correct version is found during the build process.

2. **`configure_package_config_file`:**
   - **Purpose:** Creates a CMake package configuration file (`<name>Config.cmake`) from a template. This file contains information about the package's targets (libraries, executables, etc.), include directories, and dependencies.
   - **Functionality:**
     - Takes a template input file, package name, and configuration data as input.
     - Reads the template file.
     - Performs variable substitution using the provided configuration data.
     - Adds boilerplate CMake code (`PACKAGE_INIT_BASE`, `PACKAGE_INIT_EXT`, `PACKAGE_INIT_SET_AND_CHECK`) for setting up the package prefix and checking for the existence of referenced files.
     - Installs the generated configuration file.
   - **Relevance to Reverse Engineering:** Similar to the previous function, this is vital for building and managing dependencies of reverse engineering tools. Many reverse engineering frameworks or libraries might provide CMake configuration files, and this function allows Meson to utilize them.

3. **`subproject`:**
   - **Purpose:** Integrates a CMake-based subproject into the Meson build. This allows you to include and build CMake projects as part of your larger Meson project.
   - **Functionality:**
     - Takes the directory of the CMake subproject as input.
     - Executes CMake to configure and potentially build the subproject.
     - Provides access to the targets, dependencies, and variables defined in the CMake subproject.
     - Returns a `CMakeSubproject` object that allows further interaction with the CMake subproject.
   - **Relevance to Reverse Engineering:** This is highly relevant. Many reverse engineering tools or libraries are built using CMake. This function allows a Frida build (which uses Meson) to seamlessly incorporate these external CMake projects. For example, if Frida needs to link against a specific disassembler library built with CMake, this function would be used.

4. **`subproject_options`:**
   - **Purpose:** Creates an object (`CMakeSubprojectOptions`) to manage options that are passed to the CMake subproject during its configuration.
   - **Functionality:**
     - Provides methods to add CMake definitions (`add_cmake_defines`), set override options (`set_override_option`), control installation (`set_install`), and append compiler/linker arguments (`append_compile_args`, `append_link_args`).
   - **Relevance to Reverse Engineering:**  This is crucial for tailoring the build of external CMake projects to the specific needs of Frida or the reverse engineering task. You might need to define specific preprocessor macros, set compiler flags for debugging, or link against particular libraries.

**Functionalities of the `CMakeSubproject` Class (returned by `cmake.subproject`)**

1. **`get_variable`:** Retrieves the value of a CMake variable from the subproject.
2. **`dependency`:** Declares a dependency on a target from the CMake subproject. This allows Meson to track and build the CMake target before other targets that depend on it.
3. **`include_directories`:** Returns the include directories associated with a CMake target, allowing other parts of the Meson build to include headers from the CMake project.
4. **`target`:** Returns a Meson build target object representing a target from the CMake subproject (e.g., a library or executable).
5. **`target_type`:** Returns the type of a CMake target (e.g., "library", "executable").
6. **`target_list`:** Lists all available targets in the CMake subproject.
7. **`found_method`:** Checks if the CMake subproject was successfully found and configured.

**Relationship to Reverse Engineering:**

* **Direct Integration of Reverse Engineering Tools/Libraries:** The primary relationship is enabling the integration of existing reverse engineering tools or libraries that are built with CMake into the Frida build process. For instance, Frida might need to use a specific memory analysis library or a disassembler engine that has a CMake build system.
* **Customization of External Components:**  The `subproject_options` allow for fine-tuning the build of these external components. You might need to enable specific features, disable optimizations for debugging, or link against specific system libraries relevant to the target being reverse engineered.

**Examples of Reverse Engineering Relevance:**

* **Scenario:** Frida needs to use the Capstone disassembly library. Capstone has a CMake build system.
    - The `cmake.subproject` function would be used in Frida's `meson.build` to include the Capstone source code as a subproject.
    - `cmake.subproject_options` could be used to set specific Capstone build options (e.g., enabling support for a specific architecture).
    - `cmake_subproject.dependency('capstone')` would create a Meson dependency on the Capstone library target, ensuring it's built before Frida components that rely on it.
    - `cmake_subproject.include_directories('capstone')` would provide the include paths for Capstone's headers, allowing Frida's C/C++ code to use Capstone's API.

**Involvement of Binary底层, Linux, Android内核及框架 Knowledge:**

* **Compiler and Linker Arguments:** The `append_compile_args` and `append_link_args` functions directly interact with the underlying compiler and linker. When building Frida, which often interacts with low-level system features, you might need to pass specific flags:
    - **Example (Linux/Android):**  You might need to add compiler flags like `-fPIC` (for position-independent code, common in shared libraries) or `-march=armv7-a` (to target a specific ARM architecture). Linker flags might include `-pthread` for multithreading support or `-ldl` for dynamic linking.
* **`detect_voidp_size`:** This function determines the size of a void pointer, which is architecture-dependent (e.g., 4 bytes on 32-bit systems, 8 bytes on 64-bit systems). This is crucial for correct memory management and data structure alignment when dealing with low-level code or kernel interactions.
* **Package Configuration and Installation:**  The `write_basic_package_version_file` and `configure_package_config_file` functions are related to how libraries and their dependencies are managed on Linux and other systems. CMake package configuration is a standard mechanism for this. Understanding how libraries are found and linked at a system level is important here.
* **Cross-Compilation:** When building Frida for Android, you'll be cross-compiling. The CMake module helps manage the build process for the target architecture.

**Logical Reasoning (Hypothetical Input and Output):**

**Example with `configure_package_config_file`:**

* **Hypothetical Input:**
    - `input` file (template):
      ```cmake
      # @PACKAGE_INIT@
      set(MY_LIB_INCLUDE_DIRS "@my_include_dir@")
      ```
    - `configuration` data: `{'my_include_dir': '/usr/local/include/mylib'}`
    - `name`: `mylib`
* **Hypothetical Output (`mylibConfig.cmake`):**
    ```cmake
    ####### Expanded from \@PACKAGE_INIT\@ by configure_package_config_file() #######
    ####### Any changes to this file will be overwritten by the next CMake run ####
    ####### The input file was <path_to_template>/template.cmake ########

    get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

    macro(set_and_check _var _file)
      set(${_var} "${_file}")
      if(NOT EXISTS "${_file}")
        message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
      endif()
    endmacro()

    ####################################################################################
    set(MY_LIB_INCLUDE_DIRS "/usr/local/include/mylib")
    ```
    * **Reasoning:** The function reads the template, substitutes `@my_include_dir@` with the provided value, and adds the standard CMake initialization boilerplate.

**User or Programming Common Usage Errors:**

1. **Incorrect Path in `subproject`:**
   - **Error:** Providing a non-existent or incorrect path to the CMake subproject directory.
   - **Example:** `cmake.subproject('path/to/nonexistent/cmake_project')`
   - **Result:** Meson will likely fail with an error indicating that the directory could not be found.

2. **Missing Required Arguments:**
   - **Error:** Not providing the required arguments to functions like `write_basic_package_version_file` or `configure_package_config_file`.
   - **Example:** `cmake.write_basic_package_version_file(name='mylib')` (missing `version`).
   - **Result:** Meson will raise a `TypeError` or `InvalidArguments` exception.

3. **Incorrect Data Types in `subproject_options`:**
   - **Error:** Providing arguments of the wrong type to methods like `add_cmake_defines`.
   - **Example:** `subproject_options.add_cmake_defines('-DDEBUG')` (should be a dictionary).
   - **Result:** Meson will raise a `TypeError`.

4. **Using Deprecated Features:**
   - **Error:** Using the `cmake_options` keyword argument in `subproject` when `options` is the preferred way.
   - **Example:** `cmake.subproject('my_cmake_proj', cmake_options=['-DDEBUG=1'])`
   - **Result:** Meson will likely issue a warning, and the functionality might be removed in future versions.

5. **Conflicting Options:**
   - **Error:** Providing conflicting options to the CMake subproject that CMake itself cannot handle.
   - **Example:** Setting incompatible compiler flags.
   - **Result:** The CMake configuration step within the subproject might fail.

**User Operation Steps to Reach This Code (Debugging Scenario):**

Let's say a Frida developer is trying to integrate a new CMake-based library into Frida:

1. **Edit `meson.build`:** The developer adds a `cmake.subproject()` call to their `meson.build` file, specifying the path to the new library's source code.
   ```python
   my_cmake_lib = cmake.subproject('path/to/my_cmake_lib')
   ```

2. **Configure Options (Optional):** If the library needs specific build options, they might use `cmake.subproject_options()`:
   ```python
   cmake_opts = cmake.subproject_options()
   cmake_opts.add_cmake_defines({'MY_FEATURE': 'ON'})
   my_cmake_lib = cmake.subproject('path/to/my_cmake_lib', options=cmake_opts)
   ```

3. **Declare Dependency:**  To use the library in Frida's code, they declare a dependency:
   ```python
   frida_core_lib = library('frida-core', ..., dependencies : my_cmake_lib.dependency('my_cmake_target'))
   ```

4. **Include Headers:**  To include headers from the CMake library:
   ```python
   frida_core_lib = library('frida-core', ..., include_directories : my_cmake_lib.include_directories('my_cmake_target'))
   ```

5. **Run Meson:** The developer runs `meson setup builddir` or `ninja` to build the project.

**Debugging Scenarios that Might Lead to Examining `cmake.py`:**

* **Subproject Not Found:** If the `cmake.subproject()` call fails because the path is incorrect, the error message might lead the developer to investigate how `cmake.subproject` works, potentially examining the source code.
* **CMake Configuration Errors:** If the CMake subproject configuration fails (due to missing dependencies or incorrect options), the developer might look at how Meson invokes CMake and how the options are passed (leading to `cmake.py` and `CMakeSubprojectOptions`).
* **Linking Errors:** If Frida fails to link against the CMake library, the developer might need to understand how Meson creates the dependency and link flags, again potentially examining the `dependency()` and `target()` methods in `CMakeSubproject`.
* **Troubleshooting Package Configuration:** If there are issues with finding the CMake package using `find_package()` in other CMake projects, a developer might look at how `write_basic_package_version_file` and `configure_package_config_file` generate the configuration files.

In summary, this `cmake.py` module is a crucial component for integrating external CMake projects into the Frida build system, which is essential for incorporating and leveraging various reverse engineering tools and libraries. Understanding its functionalities and potential error points is important for developers working on Frida or projects that depend on CMake-based components.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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