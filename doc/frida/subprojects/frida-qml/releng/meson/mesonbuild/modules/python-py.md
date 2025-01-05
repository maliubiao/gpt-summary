Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for the functionalities of the `python.py` file within the Frida project, particularly concerning reverse engineering, binary/kernel interactions, logical reasoning, common user errors, and debugging steps.

2. **High-Level Overview:**  The file is a Meson module named `python`. Meson is a build system. Therefore, this module is about integrating Python functionality into the build process. It likely helps in building Python extensions or interacting with Python installations.

3. **Identify Key Classes:**  The code defines several classes:
    * `PythonExternalProgram`:  Represents an external Python executable. This immediately suggests interaction with the *system's* Python installation(s).
    * `PythonInstallation`:  Wraps a `PythonExternalProgram` and provides methods for common Python-related build tasks. This is the primary interface for using Python in the build.
    * `PythonModule`:  The Meson module itself, responsible for finding and managing Python installations.

4. **Analyze Class Functionalities (Iterative Approach):** Go through each class and its methods, considering what each method does in the context of a build system.

    * **`PythonExternalProgram`:**
        * `sanity()`:  Checks if the Python installation is valid (essential for any external program). The mention of `distutils` hints at building Python extensions.
        * `_get_path()`:  Retrieves installation paths (like `platlib`, `purelib`). This is crucial for knowing where to install Python modules. The logic around `install_env` (system vs. venv) is important for managing dependencies.

    * **`PythonInstallation`:**  This class is richer in functionality.
        * `extension_module_method()`:  Clearly for building Python extension modules (like `.so` or `.pyd` files). The keyword arguments (`subdir`, `limited_api`) and the handling of dependencies are key. The "limited API" is a specific concept in Python C API development.
        * `_convert_api_version_to_py_version_hex()`:  A utility for the limited API, showing direct interaction with Python's internal versioning.
        * `_dependency_method_impl()`:  Handles finding Python dependencies.
        * `dependency_method()`:  Exposes the dependency finding, with options for disabling the check.
        * `install_sources_method()`:  Installs Python source files, with options for pure Python vs. platform-specific locations.
        * `get_install_dir_method()` and `_get_install_dir_impl()`:  Determine where to install files.
        * `language_version_method()`:  Gets the Python version.
        * `has_path_method()`, `get_path_method()`, `has_variable_method()`, `get_variable_method()`:  Provide access to information about the Python installation.
        * `path_method()`:  Gets the path to the Python executable.

    * **`PythonModule`:**
        * `_get_install_scripts()`:  Generates scripts for byte-compiling Python files during installation. This is a standard Python optimization.
        * `postconf_hook()`:  Integrates the byte-compilation scripts into the Meson build process.
        * `_get_win_pythonpath()`:  Windows-specific logic to find Python installations.
        * `_find_installation_impl()`:  The core logic for locating a Python installation on the system. It handles different ways of specifying the Python executable.
        * `find_installation()`:  The public interface for finding a Python installation. It includes checks for required modules.

5. **Connect to Reverse Engineering:** Look for clues related to how these functions could be relevant to reverse engineering.
    * Building extension modules (`extension_module_method`) is *directly* relevant. Frida itself uses extension modules. This code likely helps build Frida's components.
    * The handling of different Python installations and virtual environments is useful when targeting specific environments during reverse engineering.
    * The "limited API" concept is relevant when interacting with the Python runtime at a lower level, which is sometimes necessary in advanced reverse engineering.

6. **Connect to Binary/Kernel/OS:** Look for interactions with the underlying system.
    * The execution of external Python programs (`PythonExternalProgram`).
    * The handling of installation paths (`platlib`, `purelib`) is OS-specific.
    * The Windows-specific logic (`_get_win_pythonpath()`).
    * Byte compilation is an OS-level operation.

7. **Identify Logical Reasoning and Assumptions:**
    * The logic for choosing between system and virtual environment Python installations (`_get_path`).
    * The logic for finding Python executables, including fallback mechanisms (`_find_installation_impl`).
    * The assumptions about how Python versions are named on different platforms.

8. **Find User Errors:**  Think about how a user might misuse these functions.
    * Providing incorrect paths to Python installations.
    * Trying to use mutually exclusive options (e.g., `subdir` and `install_dir`).
    * Specifying an invalid limited API version.
    * Requiring modules that are not installed.

9. **Trace User Operations (Debugging Context):** Consider how a user's actions in a build system might lead to this code being executed. This involves understanding the basic Meson workflow.

10. **Refine and Structure:** Organize the findings into logical sections with clear headings and examples. Ensure the language is accessible and explains the technical terms. Use the prompt's keywords (functionality, reverse engineering, binary, etc.) to structure the answer.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is just about finding the Python executable.
* **Correction:**  No, the `extension_module_method` and installation logic indicate it's about *building* things with Python.
* **Initial thought:** The reverse engineering connection is weak.
* **Correction:** The fact that Frida is building *itself* with this code, and Frida is a reverse engineering tool, makes the connection strong. Extension modules are a key component of Frida.
* **Initial thought:**  Just list the methods.
* **Correction:** Explain the *purpose* of each method in the context of building software.

By following these steps, and iteratively refining the understanding, you can construct a comprehensive and accurate answer to the request.
This Python file, located within the Frida project's build system (Meson), defines a Meson module named `python`. Its primary function is to **manage and interact with Python installations** during the build process. This involves discovering Python interpreters, compiling Python extension modules, and installing Python packages and data.

Let's break down its functionalities with specific examples related to reverse engineering, binary/kernel interactions, logical reasoning, user errors, and debugging.

**Functionalities:**

1. **Finding Python Installations (`find_installation`):**
   - This is the core function for locating Python interpreters on the system. It can search based on:
     - Default Python executables (`python`, `python3`).
     - User-specified Python executables (via command-line arguments or environment variables).
     - Specific Python versions (e.g., `python2`, `python3.7`).
   - It checks if the found installation is valid and has necessary components like `distutils`.
   - It can also verify if specific Python modules are installed in the found interpreter.

   **Example related to Reverse Engineering:**
   - When Frida needs to build its Python bindings (which are extension modules allowing Python scripts to interact with Frida's core), this function is used to find the Python interpreter that will be used for this process. A reverse engineer might need to target a specific Python version, and this function allows specifying that.

2. **Building Python Extension Modules (`extension_module_method`):**
   - This function compiles Python extension modules (e.g., `.so` on Linux, `.pyd` on Windows). These modules are written in C, C++, or other languages and provide a way to extend Python's functionality with native code.
   - It handles dependencies, compiler flags, and linking necessary libraries.
   - It supports the "limited API" for Python extensions, ensuring compatibility across different Python versions.

   **Example related to Reverse Engineering:**
   - Frida's core is often written in C/C++ for performance and low-level access. The Python bindings, which allow you to control Frida from Python scripts, are built using this functionality. These extension modules are crucial for Frida's reverse engineering capabilities.

   **Example related to Binary Underlying:**
   - When building an extension module, the function interacts with the system's compiler (like GCC or Clang) and linker. It passes compiler flags (`c_args`, `cpp_args`) that might be necessary for interacting with specific system libraries or kernel headers. The generated `.so` or `.pyd` file is a binary file that the Python interpreter can load and execute.

3. **Installing Python Sources (`install_sources_method`):**
   - This function installs Python source files (`.py`) to the appropriate locations within the installation prefix.
   - It distinguishes between "pure" Python files (platform-independent) and platform-specific files.

   **Example related to Reverse Engineering:**
   - After building Frida's core and Python bindings, this function would be used to install the Python scripts and modules that come with Frida, making them accessible to users.

4. **Getting Python Installation Directories (`get_install_dir_method`):**
   - This function determines the installation directories for Python packages (e.g., `platlib` for platform-specific libraries, `purelib` for pure Python libraries).

   **Example related to Binary Underlying and Linux/Android Kernel/Framework:**
   - On Linux and Android, the location of `platlib` and `purelib` can vary depending on the Python installation (system-wide or within a virtual environment). `platlib` might point to directories where shared libraries are installed, potentially interacting with system-level components.

5. **Managing Python Dependencies (`dependency_method`):**
   - This function finds and manages dependencies on other Python packages.

6. **Accessing Python Installation Information (`has_path_method`, `get_path_method`, `has_variable_method`, `get_variable_method`):**
   - These functions provide access to information about the found Python installation, such as installation paths (`paths`), environment variables (`variables`), and other configuration details.

**Logical Reasoning:**

- **Conditional Logic for Finding Python:** The `find_installation` function uses a series of checks and fallbacks to locate a Python interpreter.
  - **Assumption:** The user might specify a Python executable explicitly, or rely on the default `python` or `python3`.
  - **Input:**  Optional Python executable name or path string.
  - **Output:** A `PythonExternalProgram` object representing the found Python installation, or a `NonExistingExternalProgram` object if not found.
- **Determining Installation Paths:** The `_get_install_dir_impl` method uses a logical condition based on the `pure` argument to decide whether to use `purelib_install_path` or `platlib_install_path`.
  - **Assumption:** Pure Python code can be installed in a platform-independent location, while extension modules need to go to a platform-specific location.
  - **Input:** A boolean `pure` indicating if the code is pure Python, and a `subdir`.
  - **Output:** An `OptionString` representing the installation directory.
- **Limited API Handling:** The `extension_module_method` includes logic to handle the Python Limited API.
  - **Assumption:** The user might want to build an extension module that is compatible with a range of Python versions using the Limited API.
  - **Input:** The `limited_api` keyword argument specifying the desired API version.
  - **Output:** Modifies compiler flags and linker arguments to build the extension with the specified Limited API.

**Examples of User or Programming Common Usage Errors:**

1. **Incorrect Python Executable Path:**
   - **Error:**  A user might specify a non-existent or incorrect path to a Python executable when configuring the build.
   - **How to Reach Here:** The user might set an environment variable like `PYTHON` or pass a command-line argument to Meson that points to a wrong Python executable. The `find_installation` function would then fail to find a valid Python installation.
   - **Debugging Clue:** Meson would output an error message indicating that the specified Python executable was not found or is not a valid Python installation.

2. **Conflicting Installation Options:**
   - **Error:** A user might try to use both `subdir` and `install_dir` arguments in `extension_module_method`, which are mutually exclusive.
   - **How to Reach Here:** The user would write a `meson.build` file that calls `python.extension_module` with both `subdir` and `install_dir` set.
   - **Debugging Clue:** The `extension_module_method` explicitly checks for this condition and raises an `InvalidArguments` exception.

3. **Missing Required Python Modules:**
   - **Error:** The build might require specific Python modules that are not installed in the target Python environment.
   - **How to Reach Here:** The `find_installation` function can be instructed to check for specific modules using the `modules` keyword argument. If those modules are missing, and the `required` argument is True, it will raise an exception.
   - **Debugging Clue:** Meson would output an error message stating that the required Python module(s) were not found in the specified Python installation.

4. **Incorrect Limited API Version:**
   - **Error:** A user might specify an invalid or unsupported Limited API version when building an extension module.
   - **How to Reach Here:** The user would call `python.extension_module` with the `limited_api` argument set to an incorrect value (e.g., a version lower than 3.2 or higher than the detected Python version).
   - **Debugging Clue:** The `_convert_api_version_to_py_version_hex` function performs validation and raises an `InvalidArguments` exception if the API version is incorrect.

**User Operations to Reach This Code (Debugging Lineage):**

1. **Project Configuration:** A user starts by configuring a Frida project that uses Python components. This typically involves running the `meson` command in the project's root directory.
2. **Meson Processing:** Meson reads the `meson.build` files in the project.
3. **Python Module Invocation:** If the `meson.build` files contain calls to the `python` Meson module (e.g., `python.find_installation()`, `python.extension_module()`), the code in `python.py` will be executed.
4. **`find_installation` Execution:** If the `meson.build` calls `python.find_installation()`, this function will try to locate a suitable Python interpreter based on the provided arguments or defaults.
5. **`extension_module` Execution:** If the `meson.build` calls `python.extension_module()`, this function will orchestrate the compilation of a Python extension module. This involves:
   - Using the Python interpreter found by `find_installation`.
   - Invoking the system's compiler with appropriate flags.
   - Linking the resulting object files into a shared library.
6. **Installation Phase:** During the installation phase (triggered by `meson install`), functions like `install_sources_method` and `get_install_dir_method` are used to place Python files in the correct locations.

**In Summary:**

This `python.py` file is a crucial part of Frida's build system, responsible for integrating Python into the build process. It handles the discovery of Python interpreters, the compilation of extension modules that form the bridge between Frida's core and its Python API, and the installation of Python components. Its functionalities are deeply intertwined with the underlying operating system, compilers, and Python's internal structure, making it relevant to understanding how Frida, a reverse engineering tool, is built and how it interacts with target systems.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2018 The Meson development team

from __future__ import annotations

import copy, json, os, shutil, re
import typing as T

from . import ExtensionModule, ModuleInfo
from .. import mesonlib
from .. import mlog
from ..coredata import UserFeatureOption
from ..build import known_shmod_kwargs, CustomTarget, CustomTargetIndex, BuildTarget, GeneratedList, StructuredSources, ExtractedObjects, SharedModule
from ..dependencies import NotFoundDependency
from ..dependencies.detect import get_dep_identifier, find_external_dependency
from ..dependencies.python import BasicPythonExternalProgram, python_factory, _PythonDependencyBase
from ..interpreter import extract_required_kwarg, permitted_dependency_kwargs, primitives as P_OBJ
from ..interpreter.interpreterobjects import _ExternalProgramHolder
from ..interpreter.type_checking import NoneType, PRESERVE_PATH_KW, SHARED_MOD_KWS
from ..interpreterbase import (
    noPosargs, noKwargs, permittedKwargs, ContainerTypeInfo,
    InvalidArguments, typed_pos_args, typed_kwargs, KwargInfo,
    FeatureNew, FeatureNewKwargs, disablerIfNotFound
)
from ..mesonlib import MachineChoice, OptionKey
from ..programs import ExternalProgram, NonExistingExternalProgram

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict, NotRequired

    from . import ModuleState
    from ..build import Build, Data
    from ..dependencies import Dependency
    from ..interpreter import Interpreter
    from ..interpreter.interpreter import BuildTargetSource
    from ..interpreter.kwargs import ExtractRequired, SharedModule as SharedModuleKw
    from ..interpreterbase.baseobjects import TYPE_var, TYPE_kwargs

    class PyInstallKw(TypedDict):

        pure: T.Optional[bool]
        subdir: str
        install_tag: T.Optional[str]

    class FindInstallationKw(ExtractRequired):

        disabler: bool
        modules: T.List[str]
        pure: T.Optional[bool]

    class ExtensionModuleKw(SharedModuleKw):

        subdir: NotRequired[T.Optional[str]]

    MaybePythonProg = T.Union[NonExistingExternalProgram, 'PythonExternalProgram']


mod_kwargs = {'subdir', 'limited_api'}
mod_kwargs.update(known_shmod_kwargs)
mod_kwargs -= {'name_prefix', 'name_suffix'}

_MOD_KWARGS = [k for k in SHARED_MOD_KWS if k.name not in {'name_prefix', 'name_suffix'}]


class PythonExternalProgram(BasicPythonExternalProgram):

    # This is a ClassVar instead of an instance bool, because although an
    # installation is cached, we actually copy it, modify attributes such as pure,
    # and return a temporary one rather than the cached object.
    run_bytecompile: T.ClassVar[T.Dict[str, bool]] = {}

    def sanity(self, state: T.Optional['ModuleState'] = None) -> bool:
        ret = super().sanity()
        if ret:
            self.platlib = self._get_path(state, 'platlib')
            self.purelib = self._get_path(state, 'purelib')
            self.run_bytecompile.setdefault(self.info['version'], False)
        return ret

    def _get_path(self, state: T.Optional['ModuleState'], key: str) -> str:
        rel_path = self.info['install_paths'][key][1:]
        if not state:
            # This happens only from run_project_tests.py
            return rel_path
        value = T.cast('str', state.get_option(f'{key}dir', module='python'))
        if value:
            if state.is_user_defined_option('install_env', module='python'):
                raise mesonlib.MesonException(f'python.{key}dir and python.install_env are mutually exclusive')
            return value

        install_env = state.get_option('install_env', module='python')
        if install_env == 'auto':
            install_env = 'venv' if self.info['is_venv'] else 'system'

        if install_env == 'system':
            rel_path = os.path.join(self.info['variables']['prefix'], rel_path)
        elif install_env == 'venv':
            if not self.info['is_venv']:
                raise mesonlib.MesonException('python.install_env cannot be set to "venv" unless you are in a venv!')
            # inside a venv, deb_system is *never* active hence info['paths'] may be wrong
            rel_path = self.info['sysconfig_paths'][key]

        return rel_path


_PURE_KW = KwargInfo('pure', (bool, NoneType))
_SUBDIR_KW = KwargInfo('subdir', str, default='')
_LIMITED_API_KW = KwargInfo('limited_api', str, default='', since='1.3.0')
_DEFAULTABLE_SUBDIR_KW = KwargInfo('subdir', (str, NoneType))

class PythonInstallation(_ExternalProgramHolder['PythonExternalProgram']):
    def __init__(self, python: 'PythonExternalProgram', interpreter: 'Interpreter'):
        _ExternalProgramHolder.__init__(self, python, interpreter)
        info = python.info
        prefix = self.interpreter.environment.coredata.get_option(mesonlib.OptionKey('prefix'))
        assert isinstance(prefix, str), 'for mypy'
        self.variables = info['variables']
        self.suffix = info['suffix']
        self.limited_api_suffix = info['limited_api_suffix']
        self.paths = info['paths']
        self.pure = python.pure
        self.platlib_install_path = os.path.join(prefix, python.platlib)
        self.purelib_install_path = os.path.join(prefix, python.purelib)
        self.version = info['version']
        self.platform = info['platform']
        self.is_pypy = info['is_pypy']
        self.link_libpython = info['link_libpython']
        self.methods.update({
            'extension_module': self.extension_module_method,
            'dependency': self.dependency_method,
            'install_sources': self.install_sources_method,
            'get_install_dir': self.get_install_dir_method,
            'language_version': self.language_version_method,
            'found': self.found_method,
            'has_path': self.has_path_method,
            'get_path': self.get_path_method,
            'has_variable': self.has_variable_method,
            'get_variable': self.get_variable_method,
            'path': self.path_method,
        })

    @permittedKwargs(mod_kwargs)
    @typed_pos_args('python.extension_module', str, varargs=(str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList, StructuredSources, ExtractedObjects, BuildTarget))
    @typed_kwargs('python.extension_module', *_MOD_KWARGS, _DEFAULTABLE_SUBDIR_KW, _LIMITED_API_KW, allow_unknown=True)
    def extension_module_method(self, args: T.Tuple[str, T.List[BuildTargetSource]], kwargs: ExtensionModuleKw) -> 'SharedModule':
        if 'install_dir' in kwargs:
            if kwargs['subdir'] is not None:
                raise InvalidArguments('"subdir" and "install_dir" are mutually exclusive')
        else:
            # We want to remove 'subdir', but it may be None and we want to replace it with ''
            # It must be done this way since we don't allow both `install_dir`
            # and `subdir` to be set at the same time
            subdir = kwargs.pop('subdir') or ''

            kwargs['install_dir'] = self._get_install_dir_impl(False, subdir)

        target_suffix = self.suffix

        new_deps = mesonlib.extract_as_list(kwargs, 'dependencies')
        pydep = next((dep for dep in new_deps if isinstance(dep, _PythonDependencyBase)), None)
        if pydep is None:
            pydep = self._dependency_method_impl({})
            if not pydep.found():
                raise mesonlib.MesonException('Python dependency not found')
            new_deps.append(pydep)
            FeatureNew.single_use('python_installation.extension_module with implicit dependency on python',
                                  '0.63.0', self.subproject, 'use python_installation.dependency()',
                                  self.current_node)

        limited_api_version = kwargs.pop('limited_api')
        allow_limited_api = self.interpreter.environment.coredata.get_option(OptionKey('allow_limited_api', module='python'))
        if limited_api_version != '' and allow_limited_api:

            target_suffix = self.limited_api_suffix

            limited_api_version_hex = self._convert_api_version_to_py_version_hex(limited_api_version, pydep.version)
            limited_api_definition = f'-DPy_LIMITED_API={limited_api_version_hex}'

            new_c_args = mesonlib.extract_as_list(kwargs, 'c_args')
            new_c_args.append(limited_api_definition)
            kwargs['c_args'] = new_c_args

            new_cpp_args = mesonlib.extract_as_list(kwargs, 'cpp_args')
            new_cpp_args.append(limited_api_definition)
            kwargs['cpp_args'] = new_cpp_args

            # When compiled under MSVC, Python's PC/pyconfig.h forcibly inserts pythonMAJOR.MINOR.lib
            # into the linker path when not running in debug mode via a series #pragma comment(lib, "")
            # directives. We manually override these here as this interferes with the intended
            # use of the 'limited_api' kwarg
            for_machine = kwargs['native']
            compilers = self.interpreter.environment.coredata.compilers[for_machine]
            if any(compiler.get_id() == 'msvc' for compiler in compilers.values()):
                pydep_copy = copy.copy(pydep)
                pydep_copy.find_libpy_windows(self.env, limited_api=True)
                if not pydep_copy.found():
                    raise mesonlib.MesonException('Python dependency supporting limited API not found')

                new_deps.remove(pydep)
                new_deps.append(pydep_copy)

                pyver = pydep.version.replace('.', '')
                python_windows_debug_link_exception = f'/NODEFAULTLIB:python{pyver}_d.lib'
                python_windows_release_link_exception = f'/NODEFAULTLIB:python{pyver}.lib'

                new_link_args = mesonlib.extract_as_list(kwargs, 'link_args')

                is_debug = self.interpreter.environment.coredata.options[OptionKey('debug')].value
                if is_debug:
                    new_link_args.append(python_windows_debug_link_exception)
                else:
                    new_link_args.append(python_windows_release_link_exception)

                kwargs['link_args'] = new_link_args

        kwargs['dependencies'] = new_deps

        # msys2's python3 has "-cpython-36m.dll", we have to be clever
        # FIXME: explain what the specific cleverness is here
        split, target_suffix = target_suffix.rsplit('.', 1)
        args = (args[0] + split, args[1])

        kwargs['name_prefix'] = ''
        kwargs['name_suffix'] = target_suffix

        if kwargs['gnu_symbol_visibility'] == '' and \
                (self.is_pypy or mesonlib.version_compare(self.version, '>=3.9')):
            kwargs['gnu_symbol_visibility'] = 'inlineshidden'

        return self.interpreter.build_target(self.current_node, args, kwargs, SharedModule)

    def _convert_api_version_to_py_version_hex(self, api_version: str, detected_version: str) -> str:
        python_api_version_format = re.compile(r'[0-9]\.[0-9]{1,2}')
        decimal_match = python_api_version_format.fullmatch(api_version)
        if not decimal_match:
            raise InvalidArguments(f'Python API version invalid: "{api_version}".')
        if mesonlib.version_compare(api_version, '<3.2'):
            raise InvalidArguments(f'Python Limited API version invalid: {api_version} (must be greater than 3.2)')
        if mesonlib.version_compare(api_version, '>' + detected_version):
            raise InvalidArguments(f'Python Limited API version too high: {api_version} (detected {detected_version})')

        version_components = api_version.split('.')
        major = int(version_components[0])
        minor = int(version_components[1])

        return '0x{:02x}{:02x}0000'.format(major, minor)

    def _dependency_method_impl(self, kwargs: TYPE_kwargs) -> Dependency:
        for_machine = self.interpreter.machine_from_native_kwarg(kwargs)
        identifier = get_dep_identifier(self._full_path(), kwargs)

        dep = self.interpreter.coredata.deps[for_machine].get(identifier)
        if dep is not None:
            return dep

        new_kwargs = kwargs.copy()
        new_kwargs['required'] = False
        candidates = python_factory(self.interpreter.environment, for_machine, new_kwargs, self.held_object)
        dep = find_external_dependency('python', self.interpreter.environment, new_kwargs, candidates)

        self.interpreter.coredata.deps[for_machine].put(identifier, dep)
        return dep

    @disablerIfNotFound
    @permittedKwargs(permitted_dependency_kwargs | {'embed'})
    @FeatureNewKwargs('python_installation.dependency', '0.53.0', ['embed'])
    @noPosargs
    def dependency_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> 'Dependency':
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            mlog.log('Dependency', mlog.bold('python'), 'skipped: feature', mlog.bold(feature), 'disabled')
            return NotFoundDependency('python', self.interpreter.environment)
        else:
            dep = self._dependency_method_impl(kwargs)
            if required and not dep.found():
                raise mesonlib.MesonException('Python dependency not found')
            return dep

    @typed_pos_args('install_data', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'python_installation.install_sources',
        _PURE_KW,
        _SUBDIR_KW,
        PRESERVE_PATH_KW,
        KwargInfo('install_tag', (str, NoneType), since='0.60.0')
    )
    def install_sources_method(self, args: T.Tuple[T.List[T.Union[str, mesonlib.File]]],
                               kwargs: 'PyInstallKw') -> 'Data':
        self.held_object.run_bytecompile[self.version] = True
        tag = kwargs['install_tag'] or 'python-runtime'
        pure = kwargs['pure'] if kwargs['pure'] is not None else self.pure
        install_dir = self._get_install_dir_impl(pure, kwargs['subdir'])
        return self.interpreter.install_data_impl(
            self.interpreter.source_strings_to_files(args[0]),
            install_dir,
            mesonlib.FileMode(), rename=None, tag=tag, install_data_type='python',
            preserve_path=kwargs['preserve_path'])

    @noPosargs
    @typed_kwargs('python_installation.install_dir', _PURE_KW, _SUBDIR_KW)
    def get_install_dir_method(self, args: T.List['TYPE_var'], kwargs: 'PyInstallKw') -> str:
        self.held_object.run_bytecompile[self.version] = True
        pure = kwargs['pure'] if kwargs['pure'] is not None else self.pure
        return self._get_install_dir_impl(pure, kwargs['subdir'])

    def _get_install_dir_impl(self, pure: bool, subdir: str) -> P_OBJ.OptionString:
        if pure:
            base = self.purelib_install_path
            name = '{py_purelib}'
        else:
            base = self.platlib_install_path
            name = '{py_platlib}'

        return P_OBJ.OptionString(os.path.join(base, subdir), os.path.join(name, subdir))

    @noPosargs
    @noKwargs
    def language_version_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return self.version

    @typed_pos_args('python_installation.has_path', str)
    @noKwargs
    def has_path_method(self, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> bool:
        return args[0] in self.paths

    @typed_pos_args('python_installation.get_path', str, optargs=[object])
    @noKwargs
    def get_path_method(self, args: T.Tuple[str, T.Optional['TYPE_var']], kwargs: 'TYPE_kwargs') -> 'TYPE_var':
        path_name, fallback = args
        try:
            return self.paths[path_name]
        except KeyError:
            if fallback is not None:
                return fallback
            raise InvalidArguments(f'{path_name} is not a valid path name')

    @typed_pos_args('python_installation.has_variable', str)
    @noKwargs
    def has_variable_method(self, args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> bool:
        return args[0] in self.variables

    @typed_pos_args('python_installation.get_variable', str, optargs=[object])
    @noKwargs
    def get_variable_method(self, args: T.Tuple[str, T.Optional['TYPE_var']], kwargs: 'TYPE_kwargs') -> 'TYPE_var':
        var_name, fallback = args
        try:
            return self.variables[var_name]
        except KeyError:
            if fallback is not None:
                return fallback
            raise InvalidArguments(f'{var_name} is not a valid variable name')

    @noPosargs
    @noKwargs
    @FeatureNew('Python module path method', '0.50.0')
    def path_method(self, args: T.List['TYPE_var'], kwargs: 'TYPE_kwargs') -> str:
        return super().path_method(args, kwargs)


class PythonModule(ExtensionModule):

    INFO = ModuleInfo('python', '0.46.0')

    def __init__(self, interpreter: 'Interpreter') -> None:
        super().__init__(interpreter)
        self.installations: T.Dict[str, MaybePythonProg] = {}
        self.methods.update({
            'find_installation': self.find_installation,
        })

    def _get_install_scripts(self) -> T.List[mesonlib.ExecutableSerialisation]:
        backend = self.interpreter.backend
        ret = []
        optlevel = self.interpreter.environment.coredata.get_option(mesonlib.OptionKey('bytecompile', module='python'))
        if optlevel == -1:
            return ret
        if not any(PythonExternalProgram.run_bytecompile.values()):
            return ret

        installdata = backend.create_install_data()
        py_files = []

        def should_append(f, isdir: bool = False):
            # This uses the install_plan decorated names to see if the original source was propagated via
            # install_sources() or get_install_dir().
            return f.startswith(('{py_platlib}', '{py_purelib}')) and (f.endswith('.py') or isdir)

        for t in installdata.targets:
            if should_append(t.out_name):
                py_files.append((t.out_name, os.path.join(installdata.prefix, t.outdir, os.path.basename(t.fname))))
        for d in installdata.data:
            if should_append(d.install_path_name):
                py_files.append((d.install_path_name, os.path.join(installdata.prefix, d.install_path)))
        for d in installdata.install_subdirs:
            if should_append(d.install_path_name, True):
                py_files.append((d.install_path_name, os.path.join(installdata.prefix, d.install_path)))

        import importlib.resources
        pycompile = os.path.join(self.interpreter.environment.get_scratch_dir(), 'pycompile.py')
        with open(pycompile, 'wb') as f:
            f.write(importlib.resources.read_binary('mesonbuild.scripts', 'pycompile.py'))

        for i in self.installations.values():
            if isinstance(i, PythonExternalProgram) and i.run_bytecompile[i.info['version']]:
                i = T.cast('PythonExternalProgram', i)
                manifest = f'python-{i.info["version"]}-installed.json'
                manifest_json = []
                for name, f in py_files:
                    if f.startswith((os.path.join(installdata.prefix, i.platlib), os.path.join(installdata.prefix, i.purelib))):
                        manifest_json.append(name)
                with open(os.path.join(self.interpreter.environment.get_scratch_dir(), manifest), 'w', encoding='utf-8') as f:
                    json.dump(manifest_json, f)
                cmd = i.command + [pycompile, manifest, str(optlevel)]

                script = backend.get_executable_serialisation(cmd, verbose=True, tag='python-runtime',
                                                              installdir_map={'py_purelib': i.purelib, 'py_platlib': i.platlib})
                ret.append(script)
        return ret

    def postconf_hook(self, b: Build) -> None:
        b.install_scripts.extend(self._get_install_scripts())

    # https://www.python.org/dev/peps/pep-0397/
    @staticmethod
    def _get_win_pythonpath(name_or_path: str) -> T.Optional[str]:
        if not name_or_path.startswith(('python2', 'python3')):
            return None
        if not shutil.which('py'):
            # program not installed, return without an exception
            return None
        ver = f'-{name_or_path[6:]}'
        cmd = ['py', ver, '-c', "import sysconfig; print(sysconfig.get_config_var('BINDIR'))"]
        _, stdout, _ = mesonlib.Popen_safe(cmd)
        directory = stdout.strip()
        if os.path.exists(directory):
            return os.path.join(directory, 'python')
        else:
            return None

    def _find_installation_impl(self, state: 'ModuleState', display_name: str, name_or_path: str, required: bool) -> MaybePythonProg:
        if not name_or_path:
            python = PythonExternalProgram('python3', mesonlib.python_command)
        else:
            tmp_python = ExternalProgram.from_entry(display_name, name_or_path)
            python = PythonExternalProgram(display_name, ext_prog=tmp_python)

            if not python.found() and mesonlib.is_windows():
                pythonpath = self._get_win_pythonpath(name_or_path)
                if pythonpath is not None:
                    name_or_path = pythonpath
                    python = PythonExternalProgram(name_or_path)

            # Last ditch effort, python2 or python3 can be named python
            # on various platforms, let's not give up just yet, if an executable
            # named python is available and has a compatible version, let's use
            # it
            if not python.found() and name_or_path in {'python2', 'python3'}:
                tmp_python = ExternalProgram.from_entry(display_name, 'python')
                python = PythonExternalProgram(name_or_path, ext_prog=tmp_python)

        if python.found():
            if python.sanity(state):
                return python
            else:
                sanitymsg = f'{python} is not a valid python or it is missing distutils'
                if required:
                    raise mesonlib.MesonException(sanitymsg)
                else:
                    mlog.warning(sanitymsg, location=state.current_node)

        return NonExistingExternalProgram(python.name)

    @disablerIfNotFound
    @typed_pos_args('python.find_installation', optargs=[str])
    @typed_kwargs(
        'python.find_installation',
        KwargInfo('required', (bool, UserFeatureOption), default=True),
        KwargInfo('disabler', bool, default=False, since='0.49.0'),
        KwargInfo('modules', ContainerTypeInfo(list, str), listify=True, default=[], since='0.51.0'),
        _PURE_KW.evolve(default=True, since='0.64.0'),
    )
    def find_installation(self, state: 'ModuleState', args: T.Tuple[T.Optional[str]],
                          kwargs: 'FindInstallationKw') -> MaybePythonProg:
        feature_check = FeatureNew('Passing "feature" option to find_installation', '0.48.0')
        disabled, required, feature = extract_required_kwarg(kwargs, state.subproject, feature_check)

        # FIXME: this code is *full* of sharp corners. It assumes that it's
        # going to get a string value (or now a list of length 1), of `python2`
        # or `python3` which is completely nonsense.  On windows the value could
        # easily be `['py', '-3']`, or `['py', '-3.7']` to get a very specific
        # version of python. On Linux we might want a python that's not in
        # $PATH, or that uses a wrapper of some kind.
        np: T.List[str] = state.environment.lookup_binary_entry(MachineChoice.HOST, 'python') or []
        fallback = args[0]
        display_name = fallback or 'python'
        if not np and fallback is not None:
            np = [fallback]
        name_or_path = np[0] if np else None

        if disabled:
            mlog.log('Program', name_or_path or 'python', 'found:', mlog.red('NO'), '(disabled by:', mlog.bold(feature), ')')
            return NonExistingExternalProgram()

        python = self.installations.get(name_or_path)
        if not python:
            python = self._find_installation_impl(state, display_name, name_or_path, required)
            self.installations[name_or_path] = python

        want_modules = kwargs['modules']
        found_modules: T.List[str] = []
        missing_modules: T.List[str] = []
        if python.found() and want_modules:
            for mod in want_modules:
                p, *_ = mesonlib.Popen_safe(
                    python.command +
                    ['-c', f'import {mod}'])
                if p.returncode != 0:
                    missing_modules.append(mod)
                else:
                    found_modules.append(mod)

        msg: T.List['mlog.TV_Loggable'] = ['Program', python.name]
        if want_modules:
            msg.append('({})'.format(', '.join(want_modules)))
        msg.append('found:')
        if python.found() and not missing_modules:
            msg.extend([mlog.green('YES'), '({})'.format(' '.join(python.command))])
        else:
            msg.append(mlog.red('NO'))
        if found_modules:
            msg.append('modules:')
            msg.append(', '.join(found_modules))

        mlog.log(*msg)

        if not python.found():
            if required:
                raise mesonlib.MesonException('{} not found'.format(name_or_path or 'python'))
            return NonExistingExternalProgram(python.name)
        elif missing_modules:
            if required:
                raise mesonlib.MesonException('{} is missing modules: {}'.format(name_or_path or 'python', ', '.join(missing_modules)))
            return NonExistingExternalProgram(python.name)
        else:
            assert isinstance(python, PythonExternalProgram), 'for mypy'
            python = copy.copy(python)
            python.pure = kwargs['pure']
            return python

        raise mesonlib.MesonBugException('Unreachable code was reached (PythonModule.find_installation).')


def initialize(interpreter: 'Interpreter') -> PythonModule:
    mod = PythonModule(interpreter)
    mod.interpreter.append_holder_map(PythonExternalProgram, PythonInstallation)
    return mod

"""

```