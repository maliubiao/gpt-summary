Response:
Let's break down the thought process for analyzing this Python code.

1. **Understanding the Goal:** The request asks for the functionality of the `cmake.py` file within the Frida project, specifically focusing on its relevance to reverse engineering, binary/kernel interactions, logical reasoning, common user errors, and debugging.

2. **Initial Code Scan and High-Level Understanding:**  I'd first scan the imports and class/function definitions to get a general sense of the file's purpose. Keywords like "cmake," "subproject," "package," "version," and "options" immediately stand out. The file clearly deals with integrating CMake projects within a Meson build system.

3. **Deconstructing the Classes:**  The code defines several key classes:
    * `CMakeSubproject`:  This likely represents an instance of a CMake subproject that has been integrated. Its methods (`get_variable`, `dependency`, `include_directories`, `target`, etc.) suggest ways to access information and dependencies from the CMake project.
    * `CMakeSubprojectOptions`: This seems to provide a way to configure how the CMake subproject is built (adding defines, setting options, etc.).
    * `CmakeModule`: This is the main module that exposes the functionality to Meson. Its methods (`write_basic_package_version_file`, `configure_package_config_file`, `subproject`, `subproject_options`) are the entry points for users.

4. **Analyzing Individual Functions/Methods:** For each significant function or method, I would ask myself:
    * **What does it do?** (Core functionality)
    * **How does it relate to CMake?** (Interaction with the underlying CMake system)
    * **Are there any reverse engineering implications?** (Thinking about how this might be used to hook into or analyze software built with CMake)
    * **Are there any low-level/kernel/framework aspects?** (Considerations of compilation, linking, system libraries, etc.)
    * **Is there logical reasoning involved?** (Conditional logic, data manipulation, etc.)
    * **What are the potential user errors?** (Incorrect arguments, missing dependencies, etc.)

5. **Connecting the Dots for Reverse Engineering:**  I'd look for methods that expose information about the CMake project's build process.
    * `get_variable`: Allows access to CMake variables, which could include paths, compiler flags, and other build settings relevant to reverse engineering analysis.
    * `dependency`, `include_directories`, `target`:  Provide access to the CMake project's dependencies, include paths, and built targets. This is crucial for understanding the project's structure and how its components interact, which is vital for reverse engineering.
    * `target_type`:  Knowing the type of a target (library, executable) is basic information needed for analysis.
    * `subproject`:  Integrating a CMake subproject itself can be part of setting up a reverse engineering environment.

6. **Identifying Binary/Kernel/Framework Relevance:**  This comes into play primarily through the compilation and linking aspects.
    * `append_compile_args`, `append_link_args` in `CMakeSubprojectOptions`: Directly modify the compiler and linker flags used for building the CMake subproject. This directly impacts the generated binary.
    * `detect_voidp_size`:  Deals with pointer size, a fundamental concept in binary representation and architecture.
    * The general interaction with CMake implies handling build processes that ultimately produce binaries for specific operating systems (Linux, Android). While the *Python code itself* doesn't directly interact with the kernel, it orchestrates the build process that *does*.

7. **Looking for Logical Reasoning:**  This is present in the conditional logic within the functions.
    * The `dependency` method checks the `include_type` and potentially converts the dependency.
    * The `detect_cmake` function uses return codes and string matching to verify CMake's presence and retrieve information.
    * The `create_package_file` function uses regular expressions and string manipulation.

8. **Considering User Errors:** I'd think about the constraints and requirements of the functions.
    * Incorrect arguments to functions (e.g., `get_variable` requiring exactly one argument).
    * Providing incompatible keyword arguments.
    * Not having CMake installed when using CMake-related functions.
    * Using deprecated features.

9. **Tracing User Actions for Debugging:**  To understand how a user reaches this code, I'd imagine a scenario where someone is building a project using Meson and integrating a CMake subproject. The steps would involve:
    * Writing a `meson.build` file.
    * Using the `cmake.subproject()` function in `meson.build`.
    * Potentially using `cmake.subproject_options()` to configure the subproject.
    * Running the `meson` command to configure the build.
    * If errors occur, the traceback would lead back to this `cmake.py` file.

10. **Structuring the Output:** Finally, I would organize the findings into the requested categories (functionality, reverse engineering, binary/kernel, logical reasoning, user errors, debugging) with clear explanations and examples. Using bullet points and code snippets makes the explanation easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Perhaps overemphasizing direct kernel interaction within the Python code itself.
* **Correction:** Realizing the Python code primarily *orchestrates* build processes that *result* in binaries that interact with the kernel. The focus should be on the build process and the information it exposes.
* **Initial Thought:**  Focusing too much on the individual lines of code.
* **Correction:** Stepping back to understand the higher-level purpose of each function and class and how they contribute to the overall functionality.
* **Considering the target audience:**  Someone interested in reverse engineering Frida. This means highlighting the aspects most relevant to analyzing and manipulating software.

By following this structured approach, breaking down the code into manageable parts, and constantly relating the functionality back to the specific requirements of the prompt, it's possible to generate a comprehensive and accurate analysis of the `cmake.py` file.
This Python file, `cmake.py`, is a module within the Meson build system that provides functionality for integrating CMake-based subprojects into a Meson build. It allows Meson projects to depend on and interact with projects that use CMake as their build system.

Here's a breakdown of its functionality:

**1. Integrating CMake Subprojects:**

* **`subproject()`:** This is the core function for including a CMake project as a subproject within a Meson build. It takes the directory of the CMake project as input and handles the process of configuring and building that subproject using CMake.
* **`subproject_options()`:**  Provides a way to configure options specifically for the CMake subproject. This includes:
    * **`add_cmake_defines()`:**  Allows setting CMake definitions (variables) for the subproject.
    * **`set_override_option()`:** Enables overriding CMake's own option settings.
    * **`set_install()`:** Controls whether targets within the CMake subproject should be installed.
    * **`append_compile_args()`:** Adds extra compiler flags for specific targets in the CMake subproject.
    * **`append_link_args()`:** Adds extra linker flags for the CMake subproject.
    * **`clear()`:** Resets the CMake subproject options.
* **`CMakeSubproject` class:**  Represents an instance of a CMake subproject. It provides methods to access information and dependencies from the built CMake project:
    * **`get_variable()`:** Retrieves the value of a CMake variable from the subproject.
    * **`dependency()`:**  Creates a Meson dependency object representing a library or target from the CMake subproject.
    * **`include_directories()`:** Returns the include directories of a CMake target as a Meson include directories object.
    * **`target()`:** Returns a Meson target object representing a built target (library, executable) from the CMake subproject.
    * **`target_type()`:**  Returns the type of a CMake target (e.g., "library", "executable").
    * **`target_list()`:**  Lists all available targets in the CMake subproject.
    * **`found_method()`:** Indicates whether the CMake subproject was successfully found and integrated.

**2. Generating CMake Package Configuration Files:**

* **`write_basic_package_version_file()`:** Creates a basic `YourPackageConfigVersion.cmake` file for a Meson project. This file is used by CMake's `find_package()` command to determine the version and compatibility of the package.
* **`configure_package_config_file()`:**  Generates a more advanced CMake package configuration file (`YourPackageConfig.cmake`) from a template. This allows a Meson project to be found as a dependency by CMake-based projects. It supports variable substitution using `@cmake@variable@`.

**3. Internal Utilities:**

* **`detect_cmake()`:** Checks if the CMake executable is available on the system.
* **`detect_voidp_size()`:** Determines the size of a void pointer on the target architecture (used in version file generation).
* **`create_package_file()`:**  A helper function used by `configure_package_config_file()` to perform the file generation and variable substitution.

**Relationship to Reverse Engineering:**

This module is highly relevant to reverse engineering, especially when dealing with software projects that are built using CMake and you want to analyze or modify them using tools like Frida.

* **Interoperability with CMake Projects:** Frida itself might depend on libraries or components built using CMake. This module allows the Frida build system (Meson) to seamlessly integrate these CMake-based dependencies.
* **Accessing CMake Build Information:**  Reverse engineers often need to understand the build process and dependencies of a target application. `CMakeSubproject`'s methods like `get_variable()`, `dependency()`, `include_directories()`, and `target()` provide a programmatic way to access this information from the Meson build system. This can be useful for:
    * **Identifying dependencies:** Knowing which libraries a target links against is crucial for understanding its functionality and potential hooking points.
    * **Locating header files:**  `include_directories()` helps find the header files used during compilation, which are essential for understanding data structures and function signatures.
    * **Getting target information:** `target()` can provide information about the built libraries or executables, which can be used to locate them for analysis.
* **Modifying Build Settings:**  While primarily for building, the ability to modify CMake options and compiler/linker flags through `subproject_options` could be indirectly used in a reverse engineering context. For example, one might want to build a debug version of a CMake dependency with specific flags to aid in analysis.

**Example:** Imagine a Frida gadget (a library injected into a process) that depends on a cryptographic library built with CMake. The `cmake.subproject()` function would be used in the Frida build system to include this crypto library. A reverse engineer could then use `frida-core`'s Python bindings to:

```python
# Assuming 'crypto_lib' is the name of the CMake subproject in meson.build
crypto_subproject = cmake.subproject('path/to/crypto/lib')
if crypto_subproject.found():
    # Get the Meson dependency object for the main crypto library target
    crypto_dep = crypto_subproject.dependency('crypto')
    print(f"Crypto library include directories: {crypto_subproject.include_directories('crypto')}")
    # Get the path to the built crypto library
    crypto_target = crypto_subproject.target('crypto')
    print(f"Crypto library path: {crypto_target.absolute_path()}")
```

**Involvement of Binary底层, Linux, Android 内核及框架知识:**

This module indirectly involves these concepts because CMake is a build system commonly used for projects targeting these platforms.

* **Binary 底层 (Binary Low-Level):** The ultimate output of the CMake subproject is binary code (executables, shared libraries). The module facilitates the building of these binaries. The `detect_voidp_size()` function directly deals with a low-level binary representation detail (pointer size). Compiler and linker flags manipulated by `append_compile_args()` and `append_link_args()` directly influence the generated binary.
* **Linux:** CMake is heavily used for Linux development. The generated CMake package configuration files are often placed in standard Linux system directories like `/usr/lib/cmake`. The module's logic for package file generation might consider Linux conventions.
* **Android Kernel and Framework:** While not explicitly Android-specific in this code, CMake is also a popular build system for Android NDK (Native Development Kit) projects. If a Frida component depends on native Android libraries built with CMake, this module would be used for integration. The concept of install directories (`install_dir` keyword) relates to how libraries are organized on Android. The detection of `CMAKE_ROOT` hints at interacting with the CMake installation which is platform-specific.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `dependency()` method:

**Hypothetical Input:**

* `args`: `['my_cmake_lib']` (the name of a CMake target that is a library)
* The CMake subproject has successfully built a shared library named `my_cmake_lib`.
* The CMakeLists.txt for `my_cmake_lib` defines include directories.

**Output:**

The `dependency()` method would:

1. Call `_args_to_info()` to get information about the `my_cmake_lib` target from the CMake subproject's build information. This information would include the CMake variable name that holds the dependency object (likely representing compiler flags and include paths).
2. Call `get_variable()` with the identified variable name to retrieve the actual Meson dependency object.
3. Return this Meson dependency object. This object could then be used in Meson to link against `my_cmake_lib` or access its include directories.

**User or Programming Common Usage Errors:**

* **Incorrect Subproject Path:** Providing an incorrect path to the CMake subproject in `cmake.subproject()`. This would likely result in an error during the Meson configuration stage, indicating that the CMake project could not be found.
* **Typos in Target Names:**  Using the wrong target name in methods like `dependency()` or `target()`. This would lead to an `InterpreterException` because the specified CMake target does not exist. The error message even suggests how to list available targets for debugging.
* **Mixing `options` and `cmake_options`:** The code explicitly checks for this and raises an `InterpreterException` if both are used simultaneously in `cmake.subproject()`. This prevents ambiguity in how CMake options are handled.
* **Using Incompatible Compatibility Settings:** In `write_basic_package_version_file()`, specifying a `compatibility` value that is not supported by the installed CMake version will raise a `mesonlib.MesonException`.
* **Forgetting `required: True`:** When a CMake subproject is essential, not setting `required: True` in `cmake.subproject()` might lead to unexpected behavior if the subproject isn't found, as Meson might proceed without it.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User has a Meson project that needs to integrate a CMake project.**
2. **The user adds a `cmake.subproject()` call in their `meson.build` file.**  This is the primary entry point to this module.
3. **When the user runs `meson setup builddir` (or `meson configure builddir`), Meson's interpreter encounters the `cmake.subproject()` call.** This triggers the execution of the `subproject()` method in `cmake.py`.
4. **Inside `subproject()`, Meson might need to configure and build the CMake subproject.** This involves invoking CMake itself.
5. **If the user then uses methods of the returned `CMakeSubproject` object (e.g., `dependency()`, `target()`), the corresponding methods in the `CMakeSubproject` class in `cmake.py` will be called.**
6. **If there are errors during the CMake subproject configuration or build, or if the user provides incorrect arguments to the `cmake` module's functions, exceptions will be raised within this `cmake.py` file.** The traceback of the error will point to the specific line of code in `cmake.py` where the error occurred.
7. **If the user is generating CMake package configuration files for their Meson project using `cmake.write_basic_package_version_file()` or `cmake.configure_package_config_file()`, those specific functions in `cmake.py` will be executed.**

Therefore, if a user encounters issues related to integrating CMake projects within their Meson build, or when their Meson project is being used as a dependency by a CMake project, they are likely to interact with the code in `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/cmake.py`. Debugging might involve examining the arguments passed to the functions in this module, the state of the CMake subproject, and any error messages generated by CMake itself.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/cmake.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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