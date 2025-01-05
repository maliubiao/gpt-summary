Response:
Let's break down the thought process for analyzing the provided Python code.

1. **Understand the Goal:** The request asks for the functionality of the Python code, its relation to reverse engineering, its use of low-level concepts, any logical reasoning, potential user errors, and how a user reaches this code. Essentially, it's a comprehensive analysis of the code's purpose and context within the Frida project.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for recognizable keywords and patterns. Words like "meson," "install," "extension," "module," "dependency," "python," "build," "target," "linux," "android," and version numbers jump out. These provide initial clues about the code's domain and purpose.

3. **Identify the Core Functionality:** The filename (`python.py`) and the module name (`PythonModule`) strongly suggest this code is responsible for integrating Python functionality into the Meson build system. The functions `find_installation`, `extension_module`, `install_sources`, and `dependency_method` appear to be the main actions the module performs.

4. **Analyze Key Functions:**  Go through the most prominent functions, understanding their inputs, operations, and outputs.

    * **`find_installation`:** This function aims to locate a Python installation on the system. It tries various methods and handles cases where the required Python version or modules are missing. This is crucial for setting up the Python environment for building.

    * **`extension_module`:**  This function is responsible for building Python extension modules (like `.so` or `.pyd` files). It handles compiling the source code, linking against Python libraries, and managing dependencies. The "limited API" aspect is interesting and hints at more advanced usage.

    * **`install_sources`:**  This function handles installing Python source files. It determines the correct installation directory based on whether the files are "pure" Python or platform-specific. Byte compilation after installation is a notable feature.

    * **`dependency_method`:** This function deals with finding and managing dependencies required by Python extensions. It interacts with Meson's dependency management system.

5. **Connect to Reverse Engineering:** Consider how these functionalities relate to reverse engineering. Frida is a dynamic instrumentation toolkit often used in reverse engineering. Building Python extensions for Frida likely involves:

    * Creating custom instrumentation logic in Python.
    * Building these Python extensions as shared libraries.
    * Frida loading these extensions to interact with target processes.

    This makes `extension_module` and the dependency handling particularly relevant. The ability to specify compilation flags and link arguments can be used to interact with target system libraries.

6. **Identify Low-Level Concepts:** Look for interactions with the operating system and underlying system structures.

    * **File Paths and Installation Directories:** The code manipulates file paths and determines installation locations (e.g., `platlib`, `purelib`). This involves understanding the standard Python directory structure on Linux and potentially Android.
    * **Shared Libraries (`SharedModule`):**  Building extension modules inherently involves creating shared libraries, a core concept in operating systems.
    * **Compilation Flags and Linker Arguments:**  The `c_args`, `cpp_args`, and `link_args` keywords expose low-level build settings.
    * **Virtual Environments (`venv`):** The code explicitly checks for and handles Python virtual environments, a common practice in Python development, particularly relevant when isolating Frida's dependencies.
    * **Windows Specifics:** The code has a section dealing with how Python is located on Windows (`_get_win_pythonpath`), indicating cross-platform considerations.

7. **Analyze Logical Reasoning:** Examine functions for conditional logic and decision-making.

    * **`find_installation`:** The logic for finding the Python installation involves checking environment variables, common names, and even using the `py` launcher on Windows. The fallback mechanisms and error handling are key parts of its reasoning.
    * **`extension_module`:** The handling of `limited_api` and the MSVC linker exception demonstrates complex conditional logic based on Python versions and the compiler used.

8. **Consider User Errors:** Think about common mistakes a user might make when interacting with this module.

    * **Incorrect Python Installation:** Specifying a non-existent or incompatible Python installation in Meson configuration.
    * **Missing Dependencies:**  Failing to install necessary Python packages or system libraries.
    * **Conflicting Options:**  Setting mutually exclusive options like `subdir` and `install_dir`.
    * **Incorrect API Version:**  Providing an invalid or unsupported Python API version when building limited API extensions.

9. **Trace User Actions:**  Imagine the steps a user would take that lead to this code being executed.

    * **Writing a `meson.build` file:**  The user defines their build process in this file, potentially using the `python.find_installation` and `python.extension_module` functions.
    * **Running `meson setup`:**  This command parses the `meson.build` file and configures the build environment. The `find_installation` function is likely called here.
    * **Running `meson compile`:** This command compiles the code. The `extension_module` function is invoked to build Python extensions.
    * **Running `meson install`:**  This command installs the built artifacts. The `install_sources` function is used to place Python files in the correct locations.

10. **Structure the Analysis:**  Organize the findings into the categories requested: functionality, relation to reverse engineering, low-level knowledge, logical reasoning, user errors, and user actions. Use clear and concise language with illustrative examples. For code snippets, highlight the relevant parts.

11. **Refine and Review:** Go back through the analysis, checking for accuracy, completeness, and clarity. Ensure the examples are relevant and easy to understand. For example, when discussing the `limited_api`, briefly explain what it is and why it's relevant.

This systematic approach, combining code reading, keyword analysis, understanding the overall context (Frida and Meson), and considering the user perspective, allows for a thorough and insightful analysis of the provided source code.
This Python code snippet is part of the Meson build system, specifically within the `frida-swift` subproject (likely related to building Swift bindings for Frida). It defines a Meson module named `python` that provides functionalities for interacting with Python during the build process.

Here's a breakdown of its features and their relevance to the aspects you mentioned:

**Functionality:**

1. **Finding Python Installations (`find_installation`):**
   - This is a core function that allows the build system to locate a suitable Python interpreter on the user's system.
   - It can search for specific Python versions (e.g., "python3") or rely on the default Python.
   - It can check if the found Python installation has specific required modules.
   - It returns a `PythonInstallation` object representing the found Python interpreter.

2. **Building Python Extension Modules (`extension_module`):**
   - This function is used to compile and link Python extension modules (typically `.so` files on Linux or `.pyd` on Windows).
   - It takes source files (C, C++, etc.) and other build targets as input.
   - It allows specifying compiler and linker flags, including those related to the Python API (like `limited_api`).
   - It handles platform-specific details like suffixing the output file name (e.g., adding the Python ABI tag).

3. **Installing Python Sources (`install_sources`):**
   - This function is responsible for copying Python source files (``.py``) to the installation directory.
   - It differentiates between "pure" Python files (platform-independent) and platform-specific ones.
   - It allows specifying a subdirectory within the Python installation where the files should be placed.
   - It can trigger byte compilation of the installed Python files.

4. **Getting Python Installation Details:**
   - Several methods on the `PythonInstallation` object provide information about the found Python interpreter:
     - `get_install_dir`: Returns the installation directory for Python packages.
     - `language_version`: Returns the Python version string.
     - `has_path`, `get_path`:  Accesses paths defined in Python's configuration (e.g., `stdlib`, `platstdlib`).
     - `has_variable`, `get_variable`: Accesses variables from Python's configuration (e.g., `prefix`, `abiflags`).
     - `path`: Returns the path to the Python executable itself.

5. **Managing Python Dependencies (`dependency_method`):**
   - This function allows declaring dependencies on the Python interpreter itself or other Python-related libraries.
   - It integrates with Meson's dependency management system.

6. **Byte Compilation:**
   - The module includes logic to trigger byte compilation of installed Python files (`.pyc` or `__pycache__`) during the installation process, potentially optimizing runtime performance.

**Relationship to Reverse Engineering:**

This module is directly relevant to reverse engineering, especially in the context of Frida:

* **Frida Extensions:** Frida often relies on Python extensions to implement instrumentation logic. These extensions are written in C/C++ and interact with Frida's core API. The `extension_module` function is crucial for building these extensions.
    * **Example:** Imagine a Frida module that needs to hook a specific function in a target application. The core hooking logic might be written in C++ and exposed to Python through an extension module built using `extension_module`.

* **Interacting with Target Processes:**  Python scripts, often interacting with Frida through its Python bindings, control the instrumentation process. This module ensures that the correct Python interpreter is found to run these scripts.

* **Dynamic Analysis:** Frida is used for dynamic analysis. The ability to build and install Python components within the build system is essential for deploying and managing Frida's Python-based instrumentation.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This code touches upon these concepts in the following ways:

* **Shared Libraries (`SharedModule`):** Building extension modules results in shared libraries (``.so`` on Linux, `dll` on Windows, `.dylib` on macOS). These are binary files loaded at runtime by the operating system or other programs (like the Python interpreter in this case). This is a fundamental concept in operating systems.

* **Compilation and Linking:** The `extension_module` function orchestrates the compilation and linking process, which involves interacting with compilers (like GCC or Clang) and linkers. Understanding how these tools work is essential for building binary software.

* **Python C API (`limited_api`):** The `limited_api` keyword allows building extensions against a stable subset of the Python C API. This is crucial for ensuring binary compatibility across different Python versions. It directly interacts with the low-level C structures and functions of the Python interpreter.
    * **Example:** When building a Frida extension, using `limited_api` can help ensure that the extension built for Python 3.7 will also work with Python 3.8 without recompilation (within certain limitations).

* **Installation Paths (`platlib`, `purelib`):** The code deals with standard Python installation directories like `platlib` (platform-specific libraries) and `purelib` (platform-independent libraries). Understanding the structure of Python installations on Linux and Android is necessary to correctly place the built extensions and Python files.

* **Virtual Environments (`venv`):** The code explicitly handles Python virtual environments. This is a common practice on Linux and other systems to isolate Python projects and their dependencies. Understanding how virtual environments work and how to locate the correct Python interpreter within them is important.

* **Windows Specifics (`_get_win_pythonpath`):** The code includes logic to find Python installations on Windows using the `py` launcher. This highlights the need to handle platform-specific ways of locating executables and libraries.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario:** Building a Frida extension module named `_my_frida_module.so` on Linux.

**Hypothetical Input (within `meson.build`):**

```meson
python3 = import('python').find_installation('python3')

my_extension = python3.extension_module(
  '_my_frida_module',
  'src/my_frida_module.c',
  dependencies: frida_headers, # Assuming 'frida_headers' is a dependency object
  c_args: ['-DDEBUG_BUILD'],
  install_dir: python3.get_install_dir() / 'my_package'
)
```

**Hypothetical Output (during the build process):**

1. **`find_installation('python3')`:**
   - **Assumption:** The system has Python 3 installed and its executable is in the system's PATH.
   - **Output:** A `PythonInstallation` object representing the located Python 3 interpreter (e.g., `/usr/bin/python3`).

2. **`extension_module(...)`:**
   - **Input:**  The name `_my_frida_module`, the source file `src/my_frida_module.c`, the `frida_headers` dependency, the `-DDEBUG_BUILD` C compiler flag, and the target installation directory.
   - **Process:**
     - Meson will invoke the C compiler (likely GCC or Clang) to compile `src/my_frida_module.c`.
     - It will include the headers provided by the `frida_headers` dependency.
     - It will pass the `-DDEBUG_BUILD` flag to the compiler.
     - It will link the compiled object file against the necessary Python libraries (obtained from the `PythonInstallation` object) and any libraries from `frida_headers`.
     - It will create a shared library file named `_my_frida_module.so` in the build directory.
   - **Output:** A `SharedModule` object representing the built extension module.

3. **`install_dir: python3.get_install_dir() / 'my_package'`:**
   - **Assumption:** `python3.pure` is True (default for `get_install_dir`).
   - **Output:** A string representing the installation directory, something like `/usr/lib/python3.x/site-packages/my_package` (on Linux).

**User or Programming Common Usage Errors:**

1. **Incorrect Python Interpreter Specification:**
   - **Error:** Specifying a Python interpreter that doesn't exist or is not a valid Python installation in `find_installation`.
   - **Example:** `python.find_installation('python2.6')` on a system without Python 2.6.
   - **Consequence:** The build process will fail with an error message indicating that the specified Python interpreter was not found.

2. **Missing Dependencies for Extension Modules:**
   - **Error:** Not providing necessary dependencies (like Frida headers or other required libraries) when building an extension module.
   - **Example:** Forgetting to link against the Frida core library when building a Frida extension.
   - **Consequence:** The linking stage of the extension module build will fail with unresolved symbols.

3. **Conflicting Installation Options:**
   - **Error:** Providing both `subdir` and `install_dir` to `extension_module` or `install_sources`. The code explicitly checks for this.
   - **Example:**
     ```meson
     python3.extension_module(
       '_my_module',
       'src/my_module.c',
       subdir: 'my_package',
       install_dir: python3.get_install_dir() / 'another_package'
     )
     ```
   - **Consequence:** Meson will raise an `InvalidArguments` exception.

4. **Incorrect `limited_api` Version:**
   - **Error:** Specifying a `limited_api` version that is not supported by the Python interpreter being used.
   - **Example:** Using `limited_api: '3.10'` with a Python 3.7 interpreter.
   - **Consequence:**  The build might fail during compilation due to missing API symbols or result in a runtime error when the extension is loaded.

5. **Incorrect File Paths in `install_sources`:**
   - **Error:** Providing incorrect paths to the Python source files to be installed.
   - **Example:** `python3.install_sources('wrong_path/my_module.py')` if the file doesn't exist.
   - **Consequence:** Meson will likely report an error that the specified file cannot be found.

**User Operation Steps to Reach This Code (Debugging Context):**

Let's imagine a scenario where a user is trying to build a Frida extension for their Swift project and encounters an error related to the Python module. Here's how they might end up inspecting this `python.py` file:

1. **User Writes `meson.build`:** The user creates a `meson.build` file to define their project's build process. This file will likely include calls to the `python` module's functions, such as `find_installation` and `extension_module`.

2. **User Runs `meson setup builddir`:** The user executes the `meson setup` command to configure the build environment. During this phase, Meson parses the `meson.build` file. If there's an issue with finding the Python interpreter or a syntax error in how the Python module is used, Meson might report an error.

3. **Error Encountered (Example: Python Not Found):**  The user might see an error like:
   ```
   meson.build:XX:0: ERROR: Program 'python3' not found.
   ```

4. **User Starts Debugging:** To understand why Python is not being found, the user might:
   - **Check their PATH environment variable:** To ensure Python is actually accessible.
   - **Examine the `meson.build` file:** To verify the correct Python interpreter name is being used.
   - **Look at Meson's output:** For more detailed error messages or traceback information.

5. **Tracing the Error to the Python Module:** If the error seems related to Meson's handling of Python, the user might start looking at the Meson source code. Knowing that the error involves finding the Python interpreter, they might search for relevant keywords in the Meson source.

6. **Finding `python.py`:** By searching for files containing "python" and related terms within the Meson source directory (specifically under `frida/subprojects/frida-swift/releng/meson/mesonbuild/modules`), they would likely find this `python.py` file.

7. **Inspecting the Code:** The user would then open `python.py` and examine the `find_installation` function and related logic to understand how Meson attempts to locate Python and identify potential issues. They might set breakpoints or add print statements within this code if they were developing Meson itself to debug the problem more deeply.

In essence, users often end up looking at source code like this when they encounter build errors and need to understand the underlying mechanisms of the build system to diagnose and fix the problem. It's a common part of the debugging process for developers working with complex build systems like Meson.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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