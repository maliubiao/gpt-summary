Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive response.

**1. Initial Understanding & Goal:**

The first step is to understand the core purpose of the file. The header comment clearly states it's a Meson module for handling Python within the Frida build system. The goal is to list its functionalities and relate them to reverse engineering, low-level concepts, logic, common errors, and debugging context.

**2. High-Level Feature Identification (Skimming):**

A quick skim reveals key classes and methods:

* `PythonExternalProgram`: Represents a Python executable.
* `PythonInstallation`: Wraps a `PythonExternalProgram` and provides methods for interacting with it within the Meson build.
* `PythonModule`: The main Meson module, responsible for finding and managing Python installations.

These class names immediately suggest the core functionality: managing Python dependencies and integration within the build process.

**3. Detailed Functionality Analysis (Method by Method):**

The next step involves going through each class and method, understanding its purpose and how it contributes to the overall functionality. This is where close reading and understanding the arguments, return values, and internal logic is crucial.

* **`PythonExternalProgram`:**
    * `sanity()`: Checks if the Python installation is valid.
    * `_get_path()`:  Determines installation paths (purelib, platlib) based on environment and options. *This is relevant to understanding where Python packages are installed.*

* **`PythonInstallation`:**
    * `__init__()`:  Initializes with a `PythonExternalProgram` and sets up its methods.
    * `extension_module_method()`: Compiles Python extension modules. *This is highly relevant to reverse engineering as extensions often contain performance-critical or platform-specific code.*
    * `_convert_api_version_to_py_version_hex()`: Converts API version strings to hex. *This is a detail related to the CPython API.*
    * `_dependency_method_impl()`:  Finds the Python dependency.
    * `dependency_method()`: Exposes `_dependency_method_impl` with error handling.
    * `install_sources_method()`: Installs Python source files. *Useful for distributing Python code.*
    * `get_install_dir_method()`: Gets the installation directory for Python packages.
    * `_get_install_dir_impl()`: Implements the logic for getting install directories.
    * `language_version_method()`: Returns the Python version.
    * `has_path_method()`, `get_path_method()`, `has_variable_method()`, `get_variable_method()`:  Access information about the Python installation.
    * `path_method()`: Returns the path to the Python executable.

* **`PythonModule`:**
    * `__init__()`: Initializes the module and stores found installations.
    * `_get_install_scripts()`: Generates scripts for byte-compiling Python files. *Related to optimization and distribution.*
    * `postconf_hook()`:  Registers the byte-compilation scripts with the Meson build system.
    * `_get_win_pythonpath()`:  Special logic for finding Python on Windows.
    * `_find_installation_impl()`:  Core logic for locating a Python installation. *This is crucial for build system flexibility.*
    * `find_installation()`:  Exposes the installation finding functionality with options.

**4. Connecting to Reverse Engineering, Low-Level Concepts, etc.:**

Once the functionality of each method is understood, the next step is to connect these functionalities to the specific areas requested:

* **Reverse Engineering:**  Focus on methods that deal with compiled code (`extension_module_method`) or interacting with the Python runtime and its modules (dependency handling, installation paths). Think about how a reverse engineer might encounter these concepts.

* **Binary/Low-Level:**  Look for interactions with compiled code (`extension_module_method`), system paths, and potentially the CPython API (limited API).

* **Linux/Android Kernel/Framework:** While not directly interacting with the kernel, consider the context of cross-compilation (the `native` keyword), the different installation paths on Linux, and the potential for building extensions that interact with Android's framework (although this specific file doesn't have Android-specific code).

* **Logic/Assumptions:** Identify conditional statements and how different inputs affect the output. Consider edge cases and potential assumptions made by the code.

* **User/Programming Errors:** Think about how a user might misuse the provided functions (e.g., conflicting arguments, providing incorrect paths, missing dependencies).

* **Debugging Clues:** Consider how a developer would end up in this code during the build process. What actions would lead to the execution of these specific methods?

**5. Generating Examples and Explanations:**

For each area, create specific examples that illustrate the connection. For logic and errors, formulate hypothetical inputs and outputs. For debugging, trace back user actions to the point where this code might be involved.

**6. Structuring the Response:**

Organize the information clearly using headings and bullet points for readability. Start with a summary of the main functions and then delve into the details for each category.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just finds Python."
* **Correction:** "No, it *manages* Python installations for the *build system*, including compiling extensions and handling dependencies."

* **Initial thought on reverse engineering:** "Not much here."
* **Correction:** "The `extension_module_method` is key, as reverse engineers often analyze compiled extensions."

* **Realizing the interconnectedness:**  The `find_installation` method is the entry point, and its results are used by other methods. Understanding this flow is important.

* **Paying attention to detail:** The different keyword arguments and their purpose are important for understanding the flexibility of the module.

By following these steps, combining high-level understanding with detailed analysis, and actively seeking connections to the requested areas, a comprehensive and accurate response can be generated. The key is to not just describe *what* the code does but also *why* and *how* it's relevant in different contexts.
This Python file, `python.py`, is a module within the Meson build system specifically designed to handle Python-related build tasks for the Frida project. Let's break down its functionality:

**Core Functionalities:**

1. **Finding and Managing Python Installations:**
   - The module allows the build system to locate available Python installations on the host machine.
   - It can search for specific Python versions (e.g., Python 2 or Python 3) or Python installations at particular paths.
   - It stores found Python installations and their associated information.

2. **Compiling Python Extension Modules:**
   - It provides a function (`extension_module_method`) to compile Python extension modules (typically written in C or C++) that can be loaded by Python.
   - It handles details like setting include directories, library paths, and compiler flags necessary for building these extensions.
   - It supports the "Limited API" for Python extensions, allowing for more stable binary interfaces across different Python versions.

3. **Managing Python Dependencies:**
   - It provides a way to declare and find dependencies on other Python packages or libraries required by the project.
   - It integrates with Meson's dependency management system.

4. **Installing Python Files:**
   - It offers functionality to install Python source files (`.py`) into the appropriate locations within the installation prefix.
   - It can differentiate between "pure" Python files (platform-independent) and platform-specific files.

5. **Generating Bytecode:**
   - It includes logic to generate bytecode (`.pyc` or `.pyo`) for installed Python files, which can improve startup time.

6. **Providing Information about Python Installations:**
   - It exposes methods to retrieve information about a specific Python installation, such as:
     - Installation paths (e.g., `purelib`, `platlib`).
     - Variables (e.g., the installation prefix).
     - The Python version.
     - Whether it's a PyPy installation.

**Relationship to Reverse Engineering (with Examples):**

This module is directly relevant to reverse engineering, particularly when dealing with software that uses Python extensions or has embedded Python components, which is common in dynamic instrumentation tools like Frida.

* **Building Frida's Python Bindings:** Frida itself has Python bindings that allow users to interact with its core functionality from Python scripts. This module is crucial for compiling these bindings.
    * **Example:**  When building Frida, this module's `extension_module_method` would be used to compile the C code that bridges Frida's core with the Python API. Reverse engineers examining Frida's Python API would be interacting with the results of this compilation.

* **Analyzing Python Extensions:** Reverse engineers often need to analyze the implementation of Python extensions to understand their behavior or find vulnerabilities. This module is involved in the process of building those extensions, so understanding how it works can be helpful in setting up build environments for analysis.
    * **Example:** If a reverse engineer wants to study a custom Frida gadget (a small piece of code injected into a process) written as a Python extension, they might need to use a build system like Meson (and this `python.py` module) to compile it themselves for experimentation or analysis.

* **Understanding Frida's Internal Structure:**  Frida's architecture involves a core component (often written in C/C++) and a Python layer for scripting and user interaction. This module manages the integration between these layers.
    * **Example:** A reverse engineer examining how Frida scripts interact with the target process might look at the compiled Python extensions that provide this communication, and this module is what builds those extensions.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge (with Examples):**

This module touches upon these areas, particularly in the context of building cross-platform software like Frida:

* **Binary Bottom:** The compilation of Python extension modules directly involves interacting with binary code. The `extension_module_method` will invoke compilers (like GCC or Clang) and linkers to produce shared libraries (`.so` on Linux, `.dll` on Windows).
    * **Example:** When compiling a Frida gadget as a Python extension, this module will pass compiler flags to generate machine code for the target architecture (e.g., ARM for Android).

* **Linux:** The module understands Linux-specific concepts like shared libraries and standard installation paths. It also handles potential differences in how Python is packaged and installed on Linux distributions.
    * **Example:** The code for determining installation paths (`_get_path`) considers the standard locations for Python libraries on Linux.

* **Android Kernel & Framework (Indirectly):** While this specific file might not directly interact with the Android kernel, it's crucial for building Frida components that *do*. Frida often injects code into Android processes, which requires understanding the Android runtime environment. This module helps build the Python interface to Frida that facilitates this interaction.
    * **Example:** When building Frida for Android, this module will help compile the necessary shared libraries that will eventually be loaded into Android processes, allowing Python scripts to interact with the Android framework.

**Logical Reasoning and Assumptions (with Examples):**

The module makes logical decisions based on the provided configuration and the detected environment.

* **Assumption:** The code assumes that if a user specifies a `subdir` for installing Python files, they want those files to be placed within that subdirectory under the main Python library directory (either `purelib` or `platlib`).
    * **Input:**  `python.install_sources(['my_script.py'], subdir: 'my_frida_gadget')`
    * **Output:** The `my_script.py` file will be installed to a location like `/usr/lib/python3.x/site-packages/my_frida_gadget/my_script.py` (or a similar location depending on the system and Python installation).

* **Reasoning:** The `find_installation` method tries various strategies to locate a Python installation. It first checks if a specific path is given, then falls back to searching for common Python executables in the system's PATH.
    * **Input:**  The user doesn't specify a Python installation explicitly.
    * **Output:** The module will attempt to find a Python executable named `python3` (or potentially `python` as a fallback).

**User or Programming Common Usage Errors (with Examples):**

Users and developers can make mistakes when using this module, which this code tries to handle or at least provide information about.

* **Conflicting `subdir` and `install_dir`:** The code explicitly checks if both `subdir` and `install_dir` are provided to the `extension_module_method` and raises an error if they are, as these options are mutually exclusive.
    * **Example Error:** `meson.build` contains: `python.extension_module('my_ext', 'my_ext.c', subdir: 'my_subdir', install_dir: '/opt/my_install')`
    * **Error Message:** The Meson build will fail with an `InvalidArguments` exception stating that "subdir" and "install_dir" are mutually exclusive.

* **Missing Python Dependency:** If a Python extension depends on another Python package that is not installed, the build process might fail. While this module doesn't directly install Python packages, it helps manage these dependencies.
    * **Example Error:** A Python extension requires the `requests` library, but it's not installed in the target Python environment.
    * **Error Indication:** The compilation or linking of the extension might fail, or the built extension might fail to load at runtime with an `ImportError`.

* **Incorrect Python API Version:** When using the "Limited API", specifying an incompatible API version can lead to build errors.
    * **Example Error:**  Specifying `limited_api: '3.1'` when the detected Python version is 3.7.
    * **Error Message:** The module will raise an `InvalidArguments` exception because the specified API version is too low.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user would typically interact with this code indirectly through the Meson build system by defining Python-related build targets in their `meson.build` file. Here's a likely sequence:

1. **User creates a `meson.build` file:** This file defines the project's build logic.
2. **User declares a Python extension module:** In the `meson.build` file, the user calls the `python.extension_module()` function to define how a Python extension should be built.
   ```meson
   py3 = import('python').find_installation()
   my_extension = py3.extension_module(
       'my_module',
       'my_module.c',
       dependencies: some_dependency,
       subdir: 'my_package'
   )
   ```
3. **User runs `meson setup builddir`:** This command configures the build based on the `meson.build` file. Meson will parse the `meson.build` file and, upon encountering the `import('python')`, it will load this `python.py` module.
4. **Meson calls `find_installation()`:**  The `py3 = import('python').find_installation()` line will trigger the `find_installation` method within this module to locate a suitable Python installation.
5. **Meson calls `extension_module()`:** The `py3.extension_module(...)` line will call the `extension_module_method` within the `PythonInstallation` class (associated with the found Python installation). This is where the compilation of the extension is handled.
6. **Potentially, Meson calls `install_sources()`:** If the `meson.build` includes lines like `install_data()` with Python files or uses `python.install_sources()`, the `install_sources_method` in this module will be invoked during the installation phase (`meson install`).

**As a debugging clue, if a user is experiencing issues related to Python extensions, dependencies, or installation paths in their Frida build, examining the behavior of the functions within this `python.py` file would be a crucial step in understanding the problem.**  For instance, placing print statements within these functions can help trace the execution flow and the values of important variables.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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