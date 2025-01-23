Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Goal:**

The primary goal is to understand the functionality of the `python.py` module within the Frida dynamic instrumentation tool. The request also specifies looking for connections to reverse engineering, low-level concepts (kernel, etc.), logic, user errors, and debugging information.

**2. High-Level Overview (Skimming the Code):**

First, I'd quickly skim the code to get a general sense of its purpose. Keywords like `ExtensionModule`, `PythonExternalProgram`, `PythonInstallation`, `find_installation`, and function names like `extension_module_method`, `dependency_method`, `install_sources_method` immediately suggest this module deals with integrating Python into the build process managed by Meson.

**3. Core Classes and Their Roles:**

Next, I'd focus on the major classes:

*   **`PythonExternalProgram`:** This seems to represent an actual Python executable. The `sanity` method suggests it checks if a given Python installation is valid. The `_get_path` method hints at handling different installation layouts (system vs. virtual environment).

*   **`PythonInstallation`:** This class appears to be a wrapper around a `PythonExternalProgram`, providing a higher-level interface within the Meson build system. It offers methods to create Python extension modules, manage dependencies, install Python sources, and retrieve Python-related information (paths, variables).

*   **`PythonModule`:** This is the main module class registered with Meson. It contains methods like `find_installation` to locate Python interpreters and `_get_install_scripts` for handling post-installation tasks (like byte compilation).

**4. Analyzing Key Functions and Methods:**

Now, I would delve into the significant functions and methods, focusing on their purpose and implementation details:

*   **`find_installation`:** This is crucial for locating Python interpreters. I'd note its parameters (`name_or_path`, `required`, `modules`) and how it handles different scenarios (explicit path, environment lookup, Windows registry). The logic for checking module availability is also important.

*   **`extension_module_method`:** This method is central to building Python extension modules. I'd pay attention to how it handles source files, dependencies, and the `limited_api` option (which is highly relevant to reverse engineering and ABI stability). The manipulation of `target_suffix`, `c_args`, `cpp_args`, and `link_args` is significant.

*   **`dependency_method`:** This manages Python dependencies within the Meson build. The interaction with `find_external_dependency` is a key point.

*   **`install_sources_method` and `get_install_dir_method`:** These relate to installing Python code. The `pure` argument distinguishes between platform-specific and pure Python code.

*   **`_get_install_scripts`:**  This deals with post-installation steps like byte compilation, which optimizes Python code for execution.

**5. Identifying Connections to the Prompt's Requirements:**

As I analyze the code, I would actively look for connections to the prompt's specific requests:

*   **Reverse Engineering:** The `limited_api` feature is a strong indicator, as it's used to create extension modules with a stable ABI, a common concern when interacting with other software (including reverse engineering scenarios). The ability to build extension modules themselves is fundamental for tools like Frida.

*   **Binary/Low-Level:** The handling of shared libraries (`SharedModule`), C/C++ arguments (`c_args`, `cpp_args`), and linker arguments (`link_args`) touches on binary compilation. The discussion of MSVC and `.lib` files is a specific example.

*   **Linux/Android Kernel/Framework:** While the code doesn't directly interact with kernel code, the concept of building shared libraries is relevant to how Frida injects into processes on these platforms. The handling of different Python installation paths is also important in diverse environments like Android.

*   **Logic and Assumptions:** Analyzing the conditional statements (e.g., handling `subdir` and `install_dir`, the logic in `_find_installation_impl`) helps understand the module's decision-making process. I'd think about potential edge cases or assumptions.

*   **User Errors:** Identifying potential misuses of the API (e.g., conflicting arguments like `subdir` and `install_dir`, providing an invalid API version) is important.

*   **Debugging Clues:**  Understanding how a user might reach this code (e.g., by using Meson to build a project that includes Python extensions) provides context for debugging.

**6. Structuring the Output:**

Finally, I would organize the findings into a clear and structured format, addressing each point in the prompt:

*   **Functionality:**  List the primary actions the module performs.
*   **Reverse Engineering:** Provide concrete examples of how the module's features relate to reverse engineering.
*   **Binary/Low-Level:** Explain the connections to these concepts with specific code examples.
*   **Kernel/Framework:** Discuss the relevance of the module to these areas, even if indirectly.
*   **Logic and Assumptions:**  Present a hypothetical input and output scenario.
*   **User Errors:** Give examples of common mistakes.
*   **Debugging:** Describe the user steps that would lead to this code.

**Self-Correction/Refinement:**

During the analysis, I might encounter areas where my initial understanding is incomplete. For instance, I might need to look up what "limited API" means in the context of Python or research how Meson handles shared libraries. I would revisit the code and adjust my interpretations as needed. I'd also double-check that I'm directly addressing all parts of the prompt. For example, if I initially focus too much on the build process, I'd make sure to specifically address the debugging and user error aspects.
This Python code file, `python.py`, is a module within the Meson build system that provides functionality for managing Python dependencies and building Python extension modules. It's specifically designed to integrate Python projects and extensions into a larger build managed by Meson.

Here's a breakdown of its functionalities with connections to reverse engineering, binary/low-level concepts, and potential user errors:

**Functionalities:**

1. **Finding Python Installations:**
    *   The `find_installation` method allows Meson to locate a suitable Python interpreter on the system. This involves searching standard locations, respecting user-specified paths, and even handling platform-specific quirks (like the `py` launcher on Windows).
    *   It can optionally check if specific Python modules are available in the found installation.

2. **Creating Python Extension Modules:**
    *   The `extension_module_method` is the core function for building Python extension modules (typically written in C, C++, or other languages).
    *   It takes source files, dependencies, and various keyword arguments to define how the extension should be built (e.g., include directories, link libraries, compiler flags).
    *   It handles the platform-specific naming conventions for extension modules (e.g., `.so` on Linux, `.pyd` on Windows).
    *   It supports the "limited API" for Python extensions, which aims for binary compatibility across different Python versions.

3. **Managing Python Dependencies:**
    *   The `dependency_method` allows declaring dependencies on the Python interpreter itself or specific Python libraries.
    *   It uses Meson's dependency resolution mechanisms to find and link against the required Python components.

4. **Installing Python Sources:**
    *   The `install_sources_method` handles the installation of pure Python files into the correct locations within the installation prefix.
    *   It distinguishes between platform-specific (`platlib`) and platform-independent (`purelib`) installation directories.

5. **Retrieving Python Installation Information:**
    *   Methods like `get_install_dir`, `has_path`, `get_path`, `has_variable`, and `get_variable` provide access to information about the located Python installation, such as installation paths, configuration variables, and available paths.

6. **Byte Compilation:**
    *   The module handles the byte compilation of installed Python files (`.py` to `.pyc` or `.pyo`) to improve runtime performance. It generates installation scripts to perform this step after the main installation.

**Relation to Reverse Engineering:**

*   **Building Frida Gadget/Agent:**  Frida itself relies heavily on building Python extension modules (the Frida gadget or agent that gets injected into target processes). This `python.py` module is directly involved in compiling these extensions. Reverse engineers often need to build Frida from source or modify its components, making understanding this build process crucial.
*   **Interfacing with Native Code:** When reverse engineering, you often need to interact with native code from Python scripts. Frida does this extensively. The `extension_module_method` is the mechanism for creating these interfaces. Understanding how to build such extensions is essential for writing Frida scripts that interact with low-level process details.
*   **Limited API and Stability:** The support for the "limited API" is relevant because it allows building extensions that *should* be compatible across different Python versions. This can be important in reverse engineering scenarios where the target process might be using a specific Python version. Building a Frida gadget with the limited API increases the chance of it working across a wider range of targets.

    *   **Example:** Imagine you are reverse engineering an application that uses Python 3.7. If you build a Frida gadget using the standard Python API for your development Python 3.10, it might not load correctly in the target process. Using the limited API (and specifying a compatible version) during the build process managed by this module can help mitigate this issue.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

*   **Shared Libraries (`SharedModule`):** The `extension_module_method` ultimately creates shared libraries (`.so` on Linux, `.dylib` on macOS, `.pyd` on Windows). Understanding how shared libraries work, including linking, symbol visibility, and dependencies, is crucial for debugging issues with Python extensions.
*   **C/C++ Compilation:** Building Python extensions often involves compiling C or C++ code. This module passes compiler and linker flags (`c_args`, `cpp_args`, `link_args`) to the underlying compiler. Knowledge of these flags and the compilation process is necessary for advanced use cases.
*   **Python Installation Paths:** The code deals with different Python installation paths (`platlib`, `purelib`). On Linux and Android, these paths can vary depending on the distribution, virtual environments, and whether it's a system-installed Python or one bundled with an application. Understanding these path conventions is important for ensuring extensions are installed correctly.
*   **Virtual Environments (venv):** The code explicitly handles virtual environments (`is_venv`). This is a common practice in Python development, and understanding how virtual environments isolate Python installations and dependencies is relevant here.
*   **Platform Differences (Windows, Linux):** The code includes platform-specific logic, like handling the Windows `py` launcher and the way Python libraries are linked on MSVC. This highlights the need to consider platform-specific details when building Python extensions.
*   **Kernel (Indirect):** While this module doesn't directly interact with the kernel, the shared libraries it creates eventually run within the process's address space, which is managed by the kernel. Understanding concepts like memory management and process loading (which the kernel handles) can be relevant for debugging complex extension issues.
*   **Android Framework (Indirect):** When working with Android, the Python environment might be part of the Android runtime or a separate installation. The module's ability to locate and use a specific Python installation is important in this context. Frida on Android often interacts with the Android framework through Python extensions.

    *   **Example:** When building the Frida server for Android, this module would be used to compile the Python extension that allows Frida to interact with Android system services and perform instrumentation. This involves understanding the Android NDK (Native Development Kit) and how to build native libraries for Android.

**Logical Reasoning with Assumptions (Hypothetical Input and Output):**

**Scenario:** Building a simple Python extension module named `_myext.so` from a C source file `myext.c` that depends on the Python development headers.

**Assumed Input (within a `meson.build` file):**

```python
python3 = import('python').find_installation()

myext = python3.extension_module(
    '_myext',
    'myext.c',
    dependencies: python3.dependency()
)
```

**Expected Output (Conceptual - depends on the build system's output):**

*   Meson will locate a Python 3 installation on the system.
*   It will use the compiler associated with that Python installation (likely `gcc` or `clang` on Linux).
*   It will compile `myext.c` into an object file.
*   It will link the object file into a shared library named `_myext.so` (or the platform-specific equivalent).
*   The linking process will include the necessary Python libraries (obtained from `python3.dependency()`).
*   The resulting `_myext.so` file will be placed in the build directory.

**User or Programming Common Usage Errors:**

1. **Incorrect Python Installation Not Found:**
    *   **Error:** If the user doesn't have Python installed or the specified Python interpreter path is incorrect, `find_installation()` will fail, leading to an error.
    *   **Example:** `meson.build` specifies `python2` but only Python 3 is installed.

2. **Missing Python Development Headers:**
    *   **Error:** When building extension modules, the Python development headers (e.g., `Python.h`) are required. If these are not installed, the compilation will fail.
    *   **Example:** On Debian/Ubuntu, the user needs to install the `python3-dev` package.

3. **Mismatched Architecture:**
    *   **Error:** Attempting to build a Python extension with an architecture that doesn't match the Python interpreter's architecture (e.g., building a 32-bit extension for a 64-bit Python) will lead to linking errors or runtime issues.

4. **Conflicting Dependencies:**
    *   **Error:** If the extension module has other native dependencies, ensuring those are correctly specified and found by Meson is crucial. Conflicts between Python dependencies and other native libraries can arise.

5. **Incorrect `limited_api` Usage:**
    *   **Error:** Specifying an incompatible `limited_api` version or trying to use API features not available in the specified limited API can lead to compilation errors or runtime crashes.
    *   **Example:** Setting `limited_api='3.9'` when the installed Python version is 3.7.

6. **Mixing `subdir` and `install_dir`:**
    *   **Error:** The code explicitly states that `subdir` and `install_dir` are mutually exclusive when calling `extension_module`. Using both will raise an `InvalidArguments` exception.

    ```python
    # Incorrect:
    python3.extension_module('_myext', 'myext.c', subdir: 'my_package', install_dir: '/opt/my_install')
    ```

**User Operations Leading to This Code (Debugging Clues):**

1. **Running `meson` to configure a build:** A user will typically start by running the `meson` command in their project's source directory to configure the build system. This process parses the `meson.build` files, including those that use the `python` module.

2. **`import('python')`:**  If a `meson.build` file contains the line `python = import('python')`, this will load the `python.py` module.

3. **Calling `find_installation()`:**  The user's `meson.build` file might call `python.find_installation()` to locate a Python interpreter. This will execute the `find_installation` method in the `PythonModule` class.

4. **Calling `extension_module()`:** If the project needs to build a Python extension, the `meson.build` file will call `python.extension_module()`. This is where the core logic of compiling the extension resides.

5. **Calling `dependency()`:**  To link against the Python library, `python.dependency()` will be called, which executes the `dependency_method`.

6. **Calling `install_sources()` or `get_install_dir()`:** If the project includes pure Python files that need to be installed, these methods will be invoked.

**In Summary:**

This `python.py` module is a crucial component for integrating Python into Meson-based build systems. It handles the complexities of finding Python installations, building extension modules, and managing dependencies. Its features are highly relevant to reverse engineering, especially when working with tools like Frida that heavily rely on Python extensions to interact with target processes. Understanding this module provides insights into how Frida and similar tools are built and how to extend their capabilities.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
```