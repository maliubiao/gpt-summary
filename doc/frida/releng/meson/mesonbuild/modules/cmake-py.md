Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The primary goal is to analyze the `cmake.py` file from the Frida project and explain its functionalities, especially in the context of reverse engineering, low-level details, logic, potential user errors, and debugging context.

2. **Initial Code Scan and High-Level Purpose:** First, quickly scan the imports and class names. Notice keywords like "cmake," "subproject," "package," "version," and "options." This immediately suggests the file is related to integrating CMake projects and managing package configurations within the Meson build system. The Frida directory context (`frida/releng/meson/mesonbuild/modules/`) reinforces that this is part of Frida's build process, likely for handling dependencies or sub-components built with CMake.

3. **Identify Key Classes and Their Roles:**
    * **`CMakeSubproject`:**  Seems to represent a CMake subproject being integrated. Its methods like `get_variable`, `dependency`, `include_directories`, `target` point to retrieving information from the CMake subproject.
    * **`CMakeSubprojectOptions`:**  Likely used to configure how a CMake subproject is built (CMake defines, compiler/linker flags, etc.).
    * **`CmakeModule`:**  The main module class. Its methods like `write_basic_package_version_file`, `configure_package_config_file`, and `subproject` reveal core functionalities.

4. **Analyze Individual Functions and Methods:** Go through each function/method and understand its purpose:
    * **Helper Functions (e.g., `detect_voidp_size`, `detect_cmake`, `create_package_file`):** These perform supporting tasks like finding CMake, determining pointer size, and generating configuration files.
    * **`write_basic_package_version_file`:**  Clearly about creating a CMake version file. Look for how it uses templates and configuration data.
    * **`configure_package_config_file`:**  Deals with generating CMake package configuration files, handling input files and variable substitution.
    * **`subproject`:**  The core function for integrating CMake subprojects. Note the parameters and how it uses Meson's `do_subproject`.
    * **Methods within `CMakeSubproject`:** Focus on how they interact with the underlying CMake subproject (through `self.cm_interpreter`).
    * **Methods within `CMakeSubprojectOptions`:** Focus on how they modify build settings for the CMake subproject.

5. **Connect Functionality to Reverse Engineering Concepts:** Think about how CMake integration is relevant to reverse engineering tools like Frida:
    * **Dependency Management:** Frida likely depends on libraries or components built with CMake. This module helps manage those dependencies.
    * **Native Code Integration:** Frida interacts with the target process at a low level. CMake is often used for building native components, making this module crucial for integrating them.
    * **Configuration and Customization:** The options for CMake subprojects allow Frida's build process to adapt to different target environments or build configurations.

6. **Identify Low-Level and Kernel Aspects:** Consider how the code touches on lower levels:
    * **`detect_voidp_size`:** Directly interacts with compiler capabilities to determine pointer size, a fundamental low-level concept.
    * **CMake Itself:** CMake is a build system often used for compiling native code, including kernel modules or framework components (though not directly managed *by* this script, but it facilitates their use).
    * **Dependency Linking:**  Managing dependencies (libraries) is essential when dealing with compiled code.

7. **Look for Logic and Potential Inputs/Outputs:**
    * **Conditional Logic:** Note `if` statements, especially those that depend on user-provided arguments or the state of the build environment.
    * **Data Transformations:**  See how data flows through the functions, e.g., from input files to generated configuration files.
    * **Function Arguments and Return Values:**  What inputs do functions expect, and what do they produce?  This helps in understanding their behavior. For example, `subproject` returns a `SubprojectHolder` or `CMakeSubproject`.

8. **Consider User Errors and Debugging:**
    * **Argument Validation:**  Are there checks for invalid arguments (e.g., `InvalidArguments` exceptions)?
    * **Error Handling:** How does the code react to missing CMake, invalid configurations, or missing files?
    * **User Configuration:** What are the common configuration options (like `cmake_options`, `options`) that users might misuse?
    * **Debugging Clues:** The `target_list` method in `CMakeSubproject` is explicitly mentioned as a debugging aid.

9. **Trace User Actions:** Imagine the steps a user would take that would lead to this code being executed:
    * Running the Meson build system (`meson build`).
    * The `meson.build` file using the `cmake.subproject` function.
    * Potentially configuring CMake options using `cmake.subproject_options`.
    * The build system needing to generate CMake package configuration files.

10. **Structure the Explanation:** Organize the findings into logical sections:
    * Overall Functionality
    * Relationship to Reverse Engineering
    * Low-Level/Kernel Aspects
    * Logic and Examples
    * User Errors
    * Debugging Context

11. **Refine and Elaborate:**  Review the code and the initial analysis. Add more specific examples and details. For instance, instead of just saying "manages dependencies," explain *how* it does this (e.g., using `dependency()` method to create Meson dependencies from CMake targets). Ensure the explanations are clear and concise. Use code snippets where helpful. Be precise with terminology.

By following these steps, you can systematically analyze the code and generate a comprehensive explanation covering the requested aspects. The key is to move from a high-level understanding to a detailed examination of individual components, and then to synthesize the information in the context of the given prompts.
This Python code file, `cmake.py`, is a module within the Meson build system that provides functionality for interacting with CMake projects and generating CMake-related files. Since Frida uses Meson as its build system, this module allows Frida to integrate and manage components that might be built using CMake.

Let's break down its functionalities based on your request:

**1. Functionalities of `cmake.py`:**

* **Integrating CMake Subprojects:**
    * The core functionality is the `subproject` method, which allows embedding and building CMake-based subprojects within a larger Meson project. This is crucial when Frida depends on external libraries or components that use CMake as their build system.
    * It handles the configuration of these subprojects using the `subproject_options` method, allowing users to set CMake definitions, override options, and control installation.
    * The `CMakeSubproject` class provides methods to extract information from the built CMake subproject, such as variables, dependencies, include directories, and target information.

* **Generating CMake Package Configuration Files:**
    * The `write_basic_package_version_file` method generates a basic CMake configuration version file (`<name>ConfigVersion.cmake`). This file is used by CMake's `find_package` mechanism to check the compatibility of a package.
    * The `configure_package_config_file` method generates a more comprehensive CMake package configuration file (`<name>Config.cmake`) from a template. This file defines targets, include paths, library locations, and other information needed to use the package.

* **Utilities for CMake Interaction:**
    * The module includes functions like `detect_cmake` to check if CMake is installed and to find its root directory.
    * `detect_voidp_size` attempts to determine the size of a void pointer, which can be relevant for CMake configurations.
    * `create_package_file` is a helper function for generating the package configuration file content with variable substitution.

**2. Relationship to Reverse Engineering with Examples:**

* **Integrating External Libraries:** Frida often relies on external libraries for various functionalities. Some of these libraries might use CMake as their build system. The `cmake.subproject` method allows Frida's build system to include and build these libraries.
    * **Example:** Imagine Frida needs to use a custom library for disassembling code that is built using CMake. The `meson.build` file could use `cmake.subproject('path/to/disassembler')` to integrate this library. Then, within Frida's code, it can link against the targets defined by the CMake subproject.

* **Extracting Information from CMake Projects:**  After building a CMake subproject, Frida might need information about the resulting libraries or executables. The methods in the `CMakeSubproject` class are used for this.
    * **Example:** If the disassembled library from the previous example exposes its include directories as a CMake target, Frida can use `cmake_subproject.include_directories('disassembler-headers')` to get the necessary include paths for compiling Frida's components that use this library.
    * **Example:** Frida might need the path to a specific static library built by the CMake subproject. It could use `cmake_subproject.target('disassembler-lib')` to get a Meson `StaticLibrary` object representing that target, from which it can extract the file path.

**3. Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge with Examples:**

* **`detect_voidp_size`:** This function directly relates to low-level binary representation. The size of a pointer is fundamental to memory management and data structures in compiled languages like C and C++, which are prevalent in operating system kernels and frameworks. Determining this size is often necessary for correct cross-compilation or when dealing with platform-specific data structures.
    * **Example:** When cross-compiling Frida for an Android device with a 64-bit architecture, the size of a pointer will be 8 bytes. This information might be needed to configure CMake options for the subproject to ensure compatibility.

* **CMake for Native Libraries:** CMake is a common build system for native libraries, which form the core of operating systems and frameworks. Frida, being a dynamic instrumentation tool, heavily interacts with these native components. This module facilitates the integration of such native components built with CMake.
    * **Example (Android):**  Frida might need to interact with specific system libraries on Android. If these libraries have a CMake build system, this module allows Frida's build process to find and link against them correctly.

* **Package Configuration for System Libraries:** The generated CMake package configuration files are used to locate dependencies, often system libraries. This is crucial for Frida to find the necessary libraries at runtime.
    * **Example (Linux):** If Frida depends on a library like `glib` which might have a CMake configuration file installed on the system, Meson (through this module) can use that information to link against `glib`.

**4. Logic and Reasoning with Hypothetical Input/Output:**

Let's consider the `subproject` method:

**Hypothetical Input:**

```python
# In meson.build
cmake_dep = import('cmake')
disassembler_options = cmake_dep.subproject_options()
disassembler_options.add_cmake_defines({'BUILD_SHARED_LIBS': 'OFF'})
disassembler = cmake_dep.subproject('external/disassembler', options: disassembler_options)
```

**Reasoning:**

* The `cmake.subproject_options()` creates an object to configure the CMake subproject.
* `add_cmake_defines({'BUILD_SHARED_LIBS': 'OFF'})` tells CMake to build the disassembler as a static library.
* `cmake.subproject('external/disassembler', options: disassembler_options)` initiates the build of the CMake project located in the `external/disassembler` directory, applying the specified options.

**Hypothetical Output:**

* If the CMake project builds successfully, the `disassembler` variable will be a `CMakeSubproject` object.
* You can then use methods of this object:
    * `disassembler.found()` would return `True`.
    * `disassembler.target('disassembler-lib')` would return a Meson `StaticLibrary` object representing the built static library (assuming the CMake project defines a target named `disassembler-lib`).
    * `disassembler.include_directories('include')` would return a Meson `IncludeDirs` object representing the include directories exposed by the CMake project.

**5. User or Programming Common Usage Errors with Examples:**

* **Incorrect Path in `subproject`:** Providing a wrong path to the CMake subproject directory will cause an error during the Meson configuration stage.
    * **Example:** `cmake_dep.subproject('wrong/path/to/cmake')` will likely result in Meson not finding the `CMakeLists.txt` file.

* **Typos in CMake Target Names:** When using methods like `target` or `dependency`, a typo in the CMake target name will lead to an error.
    * **Example:** If the CMake target is named `my-library`, but you use `cmake_subproject.target('my-libary')`, it will raise an `InterpreterException` saying the target doesn't exist.

* **Mixing `cmake_options` and `options` in `subproject`:** The code explicitly checks for this and raises an error.
    * **Example:** `cmake_dep.subproject('...', cmake_options: ['-DCMAKE_BUILD_TYPE=Release'], options: my_options)` is invalid because both ways of providing CMake options are used.

* **Incorrectly Specifying Configuration Data:** When using `configure_package_config_file`, providing incorrect data types or missing required keys in the `configuration` dictionary can lead to errors during file generation.
    * **Example:** If the template expects a string variable `@MY_VERSION@` but the configuration provides an integer, the substitution might fail or produce unexpected results.

**6. User Operations to Reach This Code (Debugging Clues):**

1. **User initiates the Meson build process:**  This is typically done by running `meson setup build` or `ninja` in the build directory.
2. **Meson parses `meson.build` files:**  When Meson encounters `import('cmake')`, this `cmake.py` module is loaded.
3. **`cmake.subproject()` is called:** The user's `meson.build` file likely contains a call to `cmake.subproject()` to integrate a CMake-based dependency. This is a key entry point into this module.
4. **Meson executes the `subproject` method:** This method then orchestrates the discovery and potential building of the CMake subproject.
5. **Error during CMake subproject build:** If the CMake subproject fails to build, the errors from CMake will be propagated, providing debugging information.
6. **Using `CMakeSubproject` methods for inspection:** If the CMake subproject builds successfully, developers might use the methods of the returned `CMakeSubproject` object (e.g., `target_list()`, `get_variable()`) to inspect the results and debug integration issues. The `target_list()` method is explicitly mentioned in the code as a debugging aid.
7. **Troubleshooting package configuration:** If there are issues with finding or using packages built by Frida, developers might need to examine the generated configuration files using `write_basic_package_version_file` or `configure_package_config_file`.

**In summary,** this `cmake.py` module is a crucial part of Frida's build system, enabling the integration of CMake-based components. It handles building these components, extracting information from them, and generating necessary CMake configuration files for packaging and dependency management. Understanding this module is important for anyone contributing to Frida or troubleshooting its build process, especially when dealing with external libraries or platform-specific native code.

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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