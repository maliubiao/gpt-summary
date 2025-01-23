Response:
Let's break down the thought process for analyzing the Python code and generating the explanation.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "cmake," "subproject," "package," and function names like `write_basic_package_version_file`, `configure_package_config_file`, and `subproject` immediately suggest that this module is designed to interact with CMake projects from within a Meson build system.

**2. Identifying Key Classes and Functions:**

Next, I'd identify the major components:

* **`CmakeModule`:** This is the main module class, the entry point, and likely contains the core functionality. Its methods are the primary actions users can take.
* **`CMakeSubproject`:** This class represents a CMake subproject integrated into the Meson build. Its methods allow access to information about the CMake project.
* **`CMakeSubprojectOptions`:** This class manages options that can be applied to a CMake subproject during its integration.
* **Helper Functions:**  Functions like `detect_cmake`, `detect_voidp_size`, and `create_package_file` seem to perform supporting tasks.

**3. Analyzing Functionality (Method by Method):**

Now, I'd go through each method in the key classes and try to understand its purpose:

* **`CmakeModule` Methods:**
    * `write_basic_package_version_file`:  The name suggests it creates a basic version file for a CMake package. The arguments (`arch_independent`, `compatibility`, `name`, `version`, `install_dir`) reinforce this.
    * `configure_package_config_file`: This likely generates a CMake package configuration file based on a template and provided configuration.
    * `subproject`: This is clearly the core function for integrating a CMake subproject. The arguments (`required`, `native`, `options`, `cmake_options`) control the integration process.
    * `subproject_options`:  This likely returns an instance of `CMakeSubprojectOptions`, allowing users to configure the CMake subproject.
    * `detect_cmake`, `detect_voidp_size`:  Internal helper functions for checking CMake availability and determining pointer size.

* **`CMakeSubproject` Methods:**
    * `get_variable`:  Retrieves a CMake variable value.
    * `dependency`:  Represents a CMake dependency as a Meson dependency.
    * `include_directories`: Gets the include directories of a CMake target.
    * `target`:  Retrieves a CMake target as a Meson target.
    * `target_type`: Returns the type of a CMake target (e.g., executable, library).
    * `target_list`: Lists all available CMake targets.
    * `found_method`: Indicates whether the CMake subproject was successfully found.

* **`CMakeSubprojectOptions` Methods:**
    * `add_cmake_defines`:  Adds CMake definitions.
    * `set_override_option`: Sets CMake options, potentially overriding defaults.
    * `set_install`: Controls installation of CMake targets.
    * `append_compile_args`, `append_link_args`:  Adds compiler and linker flags to CMake targets.
    * `clear`: Resets the CMake subproject options.

**4. Identifying Connections to Reverse Engineering, Binary/OS Concepts, and Logic:**

As I analyzed each function, I'd be looking for connections to the specified topics:

* **Reverse Engineering:**  The ability to inspect CMake targets (`target`, `target_type`, `target_list`, `get_variable`) and their dependencies (`dependency`, `include_directories`) is directly relevant to understanding the structure and build process of a software project, which is a key part of reverse engineering.
* **Binary/OS Concepts:**
    * `detect_voidp_size`: This explicitly deals with the size of a pointer, a fundamental binary-level concept and OS-dependent aspect.
    * Compiler/linker flags (`append_compile_args`, `append_link_args`):  These directly influence the generation of binary code and linking of libraries, which are core to understanding compiled software.
    * Installation directories (`install_dir` kwargs):  Understanding where files are installed is crucial for analyzing deployed software.
* **Logic/Assumptions:**
    * The `write_basic_package_version_file` makes assumptions about the CMake installation and available compatibility modes.
    * The `configure_package_config_file` relies on the structure of CMake configuration files.

**5. Constructing Examples and Explanations:**

Once I have a good understanding of the functionality and its connections, I can construct illustrative examples and explain the implications:

* **Reverse Engineering Example:** Focus on how to use `target_list` and `target` to inspect a CMake library and its include paths.
* **Binary/OS Example:** Highlight `detect_voidp_size` and the compiler/linker flag manipulation.
* **Logic Example:** Create a scenario for `write_basic_package_version_file` with specific inputs and the expected output file content.
* **User Error Example:** Focus on common mistakes like providing incorrect arguments to functions or trying to use incompatible options.

**6. Detailing User Steps for Debugging:**

For the debugging aspect, I'd think about how a user would typically interact with this module and how they might end up in this specific file. This involves tracing back from a Meson build failure or a need to customize CMake integration.

**7. Structuring the Output:**

Finally, I'd organize the information logically, using clear headings and bullet points to make it easy to read and understand. I would start with a general overview and then delve into specific functionalities and examples.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretations:** I might initially misunderstand the purpose of a function. By looking at the arguments, return types, and how it's used elsewhere, I would refine my understanding.
* **Missing Connections:** I might initially miss a connection to reverse engineering or binary concepts. Going back through the function descriptions with those specific areas in mind helps identify these connections.
* **Clarity and Accuracy:**  I would review my explanations and examples to ensure they are clear, concise, and technically accurate. I would avoid jargon where possible or explain it clearly.

By following these steps, I can systematically analyze the Python code and generate a comprehensive and informative explanation that addresses all the requirements of the prompt.
This Python code defines a Meson module named `cmake` that facilitates the integration of CMake-based subprojects into a Meson build system. It provides several functions to interact with and manage these CMake subprojects. Let's break down its functionalities:

**Core Functionalities:**

1. **Integrating CMake Subprojects:**
   - **`subproject(dirname, **kwargs)`:**  This is the primary function for including a CMake project as a subproject within a Meson build. It takes the directory of the CMake project as input and various keyword arguments to configure the integration.
   - **`subproject_options()`:** Returns an object (`CMakeSubprojectOptions`) that allows users to define specific options for a CMake subproject, like CMake definitions, target-specific settings, and compiler/linker arguments.

2. **Accessing Information from CMake Subprojects:**
   - **`CMakeSubproject` Class:**  An object returned by `subproject()` that provides methods to query information about the integrated CMake project:
     - **`get_variable(variable_name)`:** Retrieves the value of a CMake variable defined in the subproject.
     - **`dependency(target_name, **kwargs)`:**  Obtains a Meson dependency object representing a CMake target (typically a library). This allows Meson targets to link against CMake libraries.
     - **`include_directories(target_name)`:** Gets the include directories associated with a specific CMake target.
     - **`target(target_name)`:** Retrieves a Meson build target object representing a CMake target (executable or library).
     - **`target_type(target_name)`:** Returns the type of a CMake target (e.g., "executable", "library").
     - **`target_list()`:** Lists all available targets within the CMake subproject.
     - **`found_method()`:** Checks if the CMake subproject was successfully found and integrated.

3. **Generating CMake Package Configuration Files:**
   - **`write_basic_package_version_file(name, version, **kwargs)`:**  Creates a basic CMake package version file (e.g., `YourPackageConfigVersion.cmake`). This file is used by `find_package()` in CMake to check the version compatibility of your package.
   - **`configure_package_config_file(input, configuration, name, **kwargs)`:** Generates a CMake package configuration file (e.g., `YourPackageConfig.cmake`) from a template (`input`). This file defines how to use your package when it's found by `find_package()`. It can include information about libraries, include directories, and other dependencies.

4. **Managing CMake Options:**
   - **`CMakeSubprojectOptions` Class:**
     - **`add_cmake_defines(defines)`:** Adds CMake definitions (e.g., `-DENABLE_FEATURE=ON`) to be passed to the CMake configure step.
     - **`set_override_option(option_name, value, **kwargs)`:**  Sets or overrides CMake options (the same options you'd use with `-D` on the CMake command line). You can target specific CMake targets with this.
     - **`set_install(enable, **kwargs)`:** Controls whether a specific CMake target should be installed during the Meson install step.
     - **`append_compile_args(language, *args, **kwargs)`:** Adds compiler arguments for a specific language (e.g., 'c', 'cpp') when building the CMake subproject. You can target specific CMake targets.
     - **`append_link_args(*args, **kwargs)`:** Adds linker arguments when building the CMake subproject. You can target specific CMake targets.
     - **`clear()`:** Clears all the options set for the CMake subproject.

**Relationship to Reverse Engineering:**

This module is highly relevant to reverse engineering in scenarios where you're dealing with software that uses CMake as its build system. Here's how:

* **Inspecting CMake Project Structure:**  The `CMakeSubproject` methods like `target_list()`, `target_type()`, `get_variable()`, and `include_directories()` allow you to programmatically inspect the structure of the CMake project being integrated. This helps understand the available libraries, executables, their dependencies, and how they are built. For example, you can use `target_list()` to see all targets and then `target_type()` to identify libraries, which are often the focus of reverse engineering efforts.
* **Understanding Build Configuration:**  By examining the CMake options and definitions set using `add_cmake_defines()` and `set_override_option()`, you can understand how the software is configured during the build process. This can reveal important compile-time flags or feature toggles that influence the behavior of the final binaries. For instance, you might find debug symbols are enabled or specific features are turned on/off.
* **Analyzing Dependencies:** The `dependency()` method is crucial for understanding the linking relationships between different components of the software. Knowing which libraries a particular executable depends on is a fundamental step in reverse engineering, as it allows you to trace the flow of execution and identify potential areas of interest.
* **Extracting Build Artifacts:** While Meson manages the actual build, understanding the CMake targets allows you to identify the names of the generated libraries and executables. This information is essential for locating the binary files you want to analyze.

**Example of Reverse Engineering Use Case:**

Suppose you have a closed-source application built with CMake that you want to analyze. You might use this Meson module in a custom build script to:

1. **Integrate the CMake project:**  Use `cmake.subproject('path/to/cmake/project')`.
2. **List available targets:** Call `<cmake_subproject_object>.target_list()` to see all the libraries and executables defined in the CMake project.
3. **Inspect a specific library:** Use `<cmake_subproject_object>.target('mylibrary')` to get a Meson target object representing the CMake library named "mylibrary".
4. **Get include directories:**  Use `<cmake_subproject_object>.include_directories('mylibrary')` to find the header files used by this library, which can provide insights into its functionality.
5. **Examine dependencies:** Use `<cmake_subproject_object>.dependency('mylibrary')` to see what other libraries "mylibrary" links against.

**Relationship to Binary底层, Linux, Android Kernel & Framework:**

This module interacts with binary-level concepts and operating system features indirectly through its management of the CMake build process.

* **Binary Level:**
    - **`detect_voidp_size(env)`:** This function directly probes the size of a void pointer, which is a fundamental concept in low-level programming and depends on the target architecture (e.g., 32-bit vs. 64-bit). This is necessary for generating correct CMake package configuration files that might need to be architecture-aware.
    - **Compiler and Linker Arguments:** The `append_compile_args()` and `append_link_args()` methods allow fine-grained control over how the code is compiled and linked. These arguments directly affect the generated binary code, including optimization levels, debugging information, and linking against specific system libraries.
* **Linux:**
    - The generated CMake package configuration files often use standard Linux paths for libraries (e.g., `/usr/lib`, `/usr/local/lib`). The module handles generating these paths correctly.
    - The detection of CMake itself relies on finding the `cmake` executable in the system's PATH, a standard Linux mechanism.
* **Android Kernel & Framework (Less Direct):**
    - While this module doesn't directly interact with the Android kernel, if the CMake subproject being integrated is part of an Android build (e.g., a native library used by an Android app), the module facilitates its compilation and integration into the Android build process.
    - The generated CMake package configuration files could be used by other components within the Android build system.

**Example of Binary/OS Interaction:**

The `detect_voidp_size()` function illustrates a direct interaction with a binary-level concept. When Meson configures the CMake subproject, it might need to know the pointer size for certain CMake operations or for generating architecture-specific configuration files. The function uses the compiler to determine this value.

**Logic and Assumptions:**

* **`write_basic_package_version_file()` Assumptions:** This function assumes the existence of specific CMake template files (`BasicConfigVersion-{compatibility}.cmake.in`) within the CMake installation. It also relies on the user providing the correct compatibility string from the predefined set (`COMPATIBILITIES`).
    * **Input:** `name="MyLib"`, `version="1.2.3"`, `compatibility="SameMajorVersion"`
    * **Output:** A file named `MyLibConfigVersion.cmake` will be generated in the build directory, containing CMake code that checks if the required version of `MyLib` has the same major version as 1.2.3.
* **`configure_package_config_file()` Logic:** This function takes an input template file and substitutes variables prefixed with `cmake@` with values from the provided `configuration` dictionary.
    * **Input Template:**
      ```cmake
      set(MY_LIB_INCLUDE_DIRS "@cmake@includedir@")
      ```
    * **`configuration`:** `{'includedir': '/opt/mylib/include'}`
    * **Output:**
      ```cmake
      set(MY_LIB_INCLUDE_DIRS "/opt/mylib/include")
      ```

**User/Programming Common Errors:**

* **Incorrect Subproject Path:** Providing an incorrect or non-existent path to the CMake subproject directory in `cmake.subproject()`.
    * **Error:** Meson will fail to find the CMakeLists.txt file and the subproject integration will fail. The error message will likely indicate that the specified directory does not exist or doesn't contain a CMake project definition.
* **Using Incompatible CMake Options:** Setting CMake options that are not recognized by the CMake project or that conflict with other settings.
    * **Error:** The CMake configure step within the subproject integration will fail, producing errors from CMake itself, which Meson will then report.
* **Misunderstanding Target Names:**  Using incorrect target names when calling methods like `dependency()`, `target()`, or `include_directories()`.
    * **Error:**  The `CMakeSubproject` methods will raise an `InterpreterException` indicating that the specified CMake target does not exist. The error message often suggests using `target_list()` to see available targets.
* **Incorrect Keyword Arguments:**  Providing incorrect or misspelled keyword arguments to the functions.
    * **Error:** Meson's argument parsing will fail, leading to `TypeError` or `InvalidArguments` exceptions. For example, misspelling `cmake_options` as `cmake_opts`.
* **Forgetting `required=True`:**  If a CMake subproject is essential for the overall build, forgetting to set `required=True` in `cmake.subproject()` might lead to a successful build even if the CMake subproject fails to integrate (if the rest of the Meson build doesn't depend on it), potentially causing runtime errors later.

**User Steps to Reach This Code (Debugging):**

1. **Encountering a Problem with a CMake Subproject:** A user might be trying to integrate a CMake project into their Meson build and encountering errors.
2. **Examining the Meson Build Log:** The Meson build log might point to issues within the CMake subproject integration, perhaps indicating failures in the CMake configure or build steps.
3. **Looking at the `meson.build` File:** The user would inspect their `meson.build` file where they're using the `cmake.subproject()` function and related methods.
4. **Tracing the Execution:** To understand how Meson interacts with the CMake project, a developer might step through the Meson source code using a debugger or by adding print statements.
5. **Finding the `cmake.py` Module:**  By tracing the execution of the `cmake.subproject()` function or other related calls, the developer would eventually arrive at the code within `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/cmake.py`. They might be looking at this file to understand:
    * How the CMake subproject is being invoked.
    * How the provided options are being passed to CMake.
    * What information is being extracted from the CMake project.
    * Potential reasons for integration failures.
6. **Specific Scenarios Leading to This File:**
    * **"CMake configure failed" error:** The user would investigate how Meson calls CMake and if the options are correct.
    * **"Target not found" error when using `dependency()` or `target()`:** The user would examine how Meson resolves CMake target names.
    * **Issues with generated CMake package configuration files:** The user would look at the logic in `write_basic_package_version_file()` and `configure_package_config_file()`.

In essence, this `cmake.py` module acts as a bridge between the Meson build system and CMake projects, allowing developers to leverage existing CMake-based code within a Meson environment. Understanding its functionalities is crucial for successfully integrating and managing these subprojects.

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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