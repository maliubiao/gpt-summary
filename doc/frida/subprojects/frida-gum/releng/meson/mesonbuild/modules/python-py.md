Response:
The user wants to understand the functionality of the Python module within the Frida dynamic instrumentation tool's Meson build system. I need to break down the code and explain its purpose, highlighting connections to reverse engineering, low-level operations, and potential user errors.

Here's a plan:

1. **High-Level Overview:** Briefly explain the role of this module in the build process.
2. **Functionality Breakdown:** Go through the key classes and methods, explaining their purpose.
3. **Reverse Engineering Relevance:** Identify aspects that are useful in a reverse engineering context.
4. **Low-Level/Kernel/Framework Interactions:** Point out parts dealing with binary compilation, platform specifics, and system paths.
5. **Logical Reasoning:** Analyze methods that involve conditional logic and provide examples of inputs and outputs.
6. **Common User Errors:** Identify potential mistakes users might make when interacting with this module.
7. **User Journey:** Explain how a user might end up triggering this code.

**Detailed Breakdown of Code Sections:**

*   **Imports:** Note the imported modules and their general purpose (e.g., `os` for file system operations, `shutil` for file manipulation, `json` for data serialization).
*   **Class `PythonExternalProgram`:** This seems to represent a Python installation. Focus on its methods for checking sanity, getting paths (`platlib`, `purelib`), and how it handles virtual environments and system installations.
*   **Class `PythonInstallation`:** This appears to be a wrapper around `PythonExternalProgram`, providing methods for interacting with a specific Python installation. Highlight methods like `extension_module_method` (building Python extensions), `dependency_method` (finding Python dependencies), and `install_sources_method` (installing Python files).
*   **Class `PythonModule`:** This is the main module. Focus on `find_installation` (locating Python interpreters), `_get_install_scripts` (handling bytecode compilation during installation), and how it interacts with the Meson build system.

**Connecting to Concepts:**

*   **Reverse Engineering:** Building Python extensions is crucial for interacting with target processes in Frida. Understanding how this module helps create those extensions is key.
*   **Binary/Low-Level:**  The `extension_module_method` deals with compiling shared libraries, which is a binary-level operation. The handling of limited API versions also touches on binary compatibility.
*   **Linux/Android/Framework:**  The path handling (`platlib`, `purelib`) and the distinction between system and virtual environments are OS-specific. Bytecode compilation is a Python framework concept.

**Example Scenarios:**

*   **Logical Reasoning:**  For `_get_install_dir_impl`, show how the `pure` flag affects the output path.
*   **User Errors:**  Illustrate a scenario where a user provides incompatible arguments to `extension_module_method` or tries to use a Python feature not supported by the found installation.

**User Journey (Debugging Context):**  Imagine a developer building a Frida gadget that includes a Python extension. If the build fails, they might investigate the Meson log and trace back to this module's execution.
这是 Frida 动态Instrumentation 工具的 Meson 构建系统中负责处理 Python 相关功能的模块。它提供了一系列方法，用于查找 Python 解释器、构建 Python 扩展模块、安装 Python 源码等。

以下是该文件的功能列表以及与逆向、底层知识、逻辑推理和用户错误的关联说明：

**功能列表：**

1. **查找 Python 解释器 (`find_installation`):**
    *   允许用户指定或自动查找系统中的 Python 解释器。
    *   可以检查找到的解释器是否满足最低版本要求，并且是否安装了特定的模块。
    *   支持在 Windows 上通过 `py` 启动器查找 Python。
2. **构建 Python 扩展模块 (`extension_module_method`):**
    *   编译 C、C++ 或其他语言编写的 Python 扩展模块（通常是 `.so` 或 `.pyd` 文件）。
    *   处理模块的依赖关系，包括显式指定的和其他 Python 依赖。
    *   支持 Python 的 Limited API，允许构建与多个 Python 版本兼容的扩展。
    *   可以设置扩展模块的安装目录。
    *   处理不同平台上的扩展名后缀。
    *   可以设置 GNU 符号可见性。
3. **获取 Python 依赖 (`dependency_method`):**
    *   查找 Python 解释器本身的依赖，例如 Python 库文件。
    *   允许指定是否嵌入 Python 依赖。
4. **安装 Python 源码 (`install_sources_method`):**
    *   将 Python 源代码文件安装到指定的安装目录。
    *   可以选择是否只安装纯 Python 代码 (pure)。
    *   可以指定子目录和安装标签。
5. **获取 Python 安装目录 (`get_install_dir_method`):**
    *   根据是否为纯 Python 代码，返回 `purelib` 或 `platlib` 的安装路径。
6. **获取 Python 语言版本 (`language_version_method`):**
    *   返回找到的 Python 解释器的版本号。
7. **检查 Python 路径 (`has_path_method`):**
    *   检查 Python 解释器的配置信息中是否存在指定的路径名称。
8. **获取 Python 路径 (`get_path_method`):**
    *   获取 Python 解释器配置信息中指定路径名称对应的值。
9. **检查 Python 变量 (`has_variable_method`):**
    *   检查 Python 解释器的配置信息中是否存在指定的变量名称。
10. **获取 Python 变量 (`get_variable_method`):**
    *   获取 Python 解释器配置信息中指定变量名称对应的值。
11. **获取 Python 解释器路径 (`path_method`):**
    *   返回找到的 Python 解释器的可执行文件路径。
12. **处理安装后脚本 (`postconf_hook`, `_get_install_scripts`):**
    *   生成在安装后执行的脚本，用于对已安装的 Python 文件进行字节码编译 (`.pyc` 或 `.pyo`)。

**与逆向方法的关联：**

*   **构建 Frida Gadget 的 Python 扩展:** Frida 允许使用 Python 编写 Gadget 插件。此模块的 `extension_module_method` 功能用于编译这些 Python 扩展，这些扩展将被注入到目标进程中进行动态 Instrumentation。
    *   **举例:** Frida 用户编写了一个名为 `my_agent.c` 的 C 扩展，用于在目标进程中 hook 特定函数。在 `meson.build` 文件中，他们会使用 `python.extension_module('my_agent', 'my_agent.c')` 来编译生成 `my_agent.so` (Linux) 或 `my_agent.pyd` (Windows)。这个编译过程就是由该模块的 `extension_module_method` 来处理的。
*   **查找目标进程所需的 Python 环境:** 在某些逆向场景中，可能需要知道目标进程使用的 Python 环境。此模块的 `find_installation` 功能可以帮助查找系统中安装的 Python，并可能通过模块检查等方式来推断目标进程的环境。

**涉及到二进制底层，Linux, Android 内核及框架的知识：**

*   **编译共享库 (`extension_module_method`):** 构建 Python 扩展模块涉及将 C/C++ 代码编译成共享库 (`.so` 或 `.dylib` 或 `.pyd`)，这是一个底层的二进制操作。需要理解编译器、链接器的工作原理以及不同平台的共享库格式。
    *   **举例:**  在 Linux 上，使用 GCC 或 Clang 将 C 代码编译成 `.so` 文件，需要指定 `-shared` 标志。在 Windows 上，使用 MSVC 编译成 `.dll` 并重命名为 `.pyd`。该模块需要处理这些平台差异。
*   **Python Limited API (`extension_module_method`):**  Limited API 是一种尝试在不同 Python 版本之间保持二进制兼容性的机制。理解 Python 的 C API 以及 Limited API 的限制对于正确构建扩展至关重要。
    *   **举例:** 通过设置 `limited_api` 参数，例如 `python.extension_module('my_agent', 'my_agent.c', limited_api='3.7')`，告诉构建系统生成一个与 Python 3.7 或更高版本（但符合 3.7 Limited API 规范）兼容的扩展。
*   **系统路径 (`PythonExternalProgram`, `PythonInstallation`):**  查找 Python 解释器和其库文件需要了解不同操作系统上 Python 的安装路径约定，例如 `purelib` 和 `platlib` 的位置。
    *   **举例:** 在 Linux 上，纯 Python 库通常位于 `/usr/lib/python3.x/site-packages`，而平台相关的库可能在 `/usr/lib/python3.x/plat-x86_64-linux-gnu/`. 在 Android 上，路径会有所不同。
*   **字节码编译 (`_get_install_scripts`):** Python 源码通常会被编译成字节码以提高加载速度。理解 Python 的字节码格式以及 `.pyc` 文件的作用有助于理解 Python 的运行机制。
    *   **举例:**  当安装 Python 包时，Meson 会生成一个安装后脚本来运行 Python 解释器并使用 `compileall` 模块将 `.py` 文件编译成 `.pyc` 文件。
*   **虚拟环境 (`PythonExternalProgram`):**  该模块需要区分系统安装的 Python 和虚拟环境中的 Python，因为它们的库文件路径和配置可能不同。
    *   **举例:**  如果在一个虚拟环境中使用 Frida，`find_installation` 方法需要能够正确识别并使用该虚拟环境中的 Python 解释器和库。

**逻辑推理：**

*   **`_get_install_dir_impl(self, pure: bool, subdir: str)`:**
    *   **假设输入:** `pure=True`, `subdir='my_package'`
    *   **输出:**  一个 `P_OBJ.OptionString` 对象，其值类似于 `os.path.join(self.purelib_install_path, 'my_package')`，并且其 name 属性类似于 `{py_purelib}/my_package`。
    *   **解释:** 如果 `pure` 为 `True`，则安装目录会基于纯 Python 库的路径 (`purelib_install_path`) 构建，并附加指定的子目录。
*   **`find_installation(...)` 的逻辑:**
    *   **假设输入:** 用户没有指定 Python 路径，但系统中安装了 Python 3。
    *   **输出:**  `find_installation` 方法会尝试找到系统默认的 Python 3 解释器，并返回一个 `PythonExternalProgram` 对象，其中包含了该解释器的信息（路径、版本等）。
    *   **假设输入:** 用户指定 `modules=['requests']`，但系统中找到的 Python 没有安装 `requests` 模块。
    *   **输出:**  如果 `required=True`，则会抛出一个 `mesonlib.MesonException`，指出缺少 `requests` 模块。如果 `required=False`，则会返回一个 `NonExistingExternalProgram` 对象，并在日志中记录缺少模块。

**涉及用户或者编程常见的使用错误：**

*   **指定不存在的 Python 解释器路径 (`find_installation`):**
    *   **错误:** 用户在 `meson.build` 中指定了一个不存在的 Python 解释器路径，例如 `python.find_installation('/path/to/nonexistent/python')`。
    *   **结果:** 如果 `required=True` (默认)，构建过程会失败，并提示找不到指定的 Python 解释器。
*   **构建扩展模块时缺少依赖 (`extension_module_method`):**
    *   **错误:**  C/C++ 扩展代码依赖于某个库，但在 `meson.build` 中没有正确指定该依赖。
    *   **结果:** 编译过程可能会失败，链接器会报告找不到所需的库。
*   **`subdir` 和 `install_dir` 参数冲突 (`extension_module_method`):**
    *   **错误:** 用户同时指定了 `subdir` 和 `install_dir` 参数，例如 `python.extension_module('my_module', 'my_module.c', subdir='plugins', install_dir='/opt/my_plugins')`.
    *   **结果:** 会抛出一个 `InvalidArguments` 异常，因为这两个参数是互斥的。
*   **Limited API 版本与实际 Python 版本不兼容 (`extension_module_method`):**
    *   **错误:**  指定了一个高于当前 Python 版本的 Limited API，例如在 Python 3.7 环境下指定 `limited_api='3.8'`。
    *   **结果:** 会抛出一个 `InvalidArguments` 异常，提示 Limited API 版本过高。
*   **在非虚拟环境中设置 `install_env='venv'` (`PythonExternalProgram`):**
    *   **错误:** 用户在非虚拟环境中设置了 `python.install_env = 'venv'`。
    *   **结果:** 会抛出一个 `mesonlib.MesonException`，提示只能在虚拟环境中设置 `install_env` 为 `venv`。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户配置构建环境:** 用户首先需要安装 Frida 和其依赖，包括 Meson 构建系统。
2. **用户编写 Frida Gadget 代码:** 用户编写 C/C++ 代码来实现 Frida Gadget 的功能，可能包含一个或多个 Python 扩展模块。
3. **用户编写 `meson.build` 文件:** 用户在项目的根目录下创建一个 `meson.build` 文件，用于描述如何构建项目。在这个文件中，用户会使用 `python` 模块提供的函数来处理 Python 相关的构建任务。
    *   **例如:**  用户可能会使用 `python.find_installation()` 来查找 Python 解释器。
    *   用户会使用 `python.extension_module()` 来编译 Python 扩展模块。
    *   用户可能会使用 `python.install_sources()` 来安装 Python 源码文件。
4. **用户运行 Meson 构建命令:** 用户在项目根目录下运行 `meson setup build` 命令来配置构建环境，或者运行 `meson compile -C build` 来进行实际的编译。
5. **Meson 解析 `meson.build` 文件:** Meson 读取 `meson.build` 文件，并执行其中的 Python 代码。当遇到 `python.find_installation()` 或 `python.extension_module()` 等函数时，就会调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/python.py` 文件中相应的函数。
6. **执行 Python 模块代码:**  该 Python 文件中的代码会被执行，例如 `find_installation` 方法会尝试查找 Python 解释器，`extension_module_method` 方法会调用编译器来构建扩展模块。
7. **构建过程中出现错误:** 如果在上述任何步骤中出现错误（例如找不到 Python 解释器、编译失败等），Meson 会输出错误信息。
8. **用户查看 Meson 日志:** 用户可以查看 Meson 的详细日志（通常在 `build/meson-log.txt` 中），以了解构建过程中发生了什么。日志信息可能会包含调用到 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/python.py` 中特定函数的堆栈信息或错误消息。
9. **用户分析错误信息并调试:** 用户根据错误信息和日志，可以追溯到是哪个 `python` 模块的函数调用导致了错误，并分析是哪个参数配置不正确或缺少了哪些依赖。例如，如果编译 Python 扩展失败，错误信息可能会指向编译器错误，用户需要检查扩展代码或依赖配置。

因此，当用户在构建 Frida Gadget 并且涉及到 Python 扩展或依赖时，Meson 构建系统会自然地执行到这个 `python.py` 文件中的代码。如果构建过程中出现与 Python 相关的问题，查看 Meson 日志并分析这个文件的代码逻辑可以帮助用户定位问题所在。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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