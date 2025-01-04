Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Request:**

The core request is to understand the functionality of the `python.py` file within the Frida dynamic instrumentation tool, specifically looking for connections to reverse engineering, low-level interactions, logical reasoning, common user errors, and debugging context.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the imports and class definitions to get a general sense of what the code is doing. I see imports related to Meson (the build system), suggesting this file integrates Python functionality into the build process. Keywords like `ExtensionModule`, `SharedModule`, `CustomTarget`, and `Dependency` hint at building Python extensions and handling dependencies. The presence of `frida` in the initial prompt tells us this is Frida-specific, though the code itself primarily focuses on generic Python integration within Meson.

**3. Identifying Key Classes and Their Roles:**

* **`PythonExternalProgram`:**  Represents an installed Python interpreter. It handles sanity checks and determines installation paths (like `purelib` and `platlib`). This is a crucial entry point for interacting with a specific Python installation.
* **`PythonInstallation`:** Wraps a `PythonExternalProgram` and provides methods for interacting with that specific installation within the Meson build context. Methods like `extension_module_method`, `dependency_method`, and `install_sources_method` are the primary actions users would take.
* **`PythonModule`:** The main module that Meson loads. It manages multiple Python installations (`self.installations`) and provides the `find_installation` method to locate a suitable Python interpreter.

**4. Focusing on Functionality Based on the Request:**

Now, I'd go through the code more carefully, specifically looking for features relevant to the request:

* **Reverse Engineering:**  I'd look for things that might help in analyzing or manipulating existing code. The `extension_module_method` is a prime candidate here. Building a Python extension is a common task in reverse engineering, often to hook into or interact with a target process. The ability to specify compile arguments (`c_args`, `cpp_args`) and link arguments (`link_args`) is relevant.
* **Binary/Low-Level, Linux/Android Kernel/Framework:**  I'd search for interactions with system paths, compilation flags, and anything that seems OS-specific. The logic within `PythonExternalProgram._get_path` and the handling of `limited_api` in `extension_module_method` (especially the MSVC-specific workaround) touch on these areas. The mention of `sysconfig` also hints at accessing system-level Python configuration.
* **Logical Reasoning:** I'd analyze conditional statements and how different inputs affect the output or behavior. The logic in `find_installation` for selecting a Python interpreter and the logic in `extension_module_method` for handling `limited_api` are examples.
* **User Errors:** I'd think about common mistakes users might make when using these functions. Mixing `subdir` and `install_dir`, providing incorrect API versions, or not having the required Python modules installed are good examples.
* **Debugging Context:** I'd consider how a user might end up in this code during a build process. The `find_installation` method is likely an early step, and other methods are called as part of building Python extensions or installing data.

**5. Generating Examples and Explanations:**

As I identify relevant functionality, I'd start constructing examples and explanations based on the code. This involves:

* **Functionality Listing:**  Summarizing the purpose of key methods.
* **Reverse Engineering Examples:** Showing how `extension_module_method` can be used to build a Frida gadget.
* **Binary/Low-Level Examples:** Explaining the `limited_api` functionality and its implications for binary compatibility.
* **Logical Reasoning Examples:**  Creating scenarios with different inputs to `find_installation` and tracing the expected output.
* **User Error Examples:** Demonstrating common mistakes and the resulting errors.
* **Debugging Path:** Outlining the steps a user might take that would lead to the execution of this code.

**6. Iterative Refinement:**

After the initial analysis, I'd review my findings and the code to ensure accuracy and completeness. I'd look for areas where my explanations could be clearer or where I've missed important details. For example, I might initially overlook the byte compilation logic in `PythonModule` and then add it upon a second pass.

**Self-Correction Example During the Process:**

Initially, I might focus too much on the Frida aspect mentioned in the prompt and try to find Frida-specific code in this file. However, upon closer inspection, it becomes clear that this file deals primarily with generic Python integration within the Meson build system. The Frida connection is that Frida *uses* Meson for its build process and this module helps manage its Python components. So, I'd correct my focus to the broader Python integration aspects while still highlighting where it could be used in a Frida context (like building gadgets).

By following this structured approach, I can systematically analyze the code and generate a comprehensive and accurate response to the request.
好的，让我们来详细分析一下 `frida/releng/meson/mesonbuild/modules/python.py` 这个文件的功能。

**文件功能概览**

这个文件是 Meson 构建系统中用于处理 Python 相关任务的模块。它提供了一组函数和类，允许 Meson 构建系统：

1. **查找和管理 Python 解释器:**  能够查找系统中可用的 Python 解释器，并允许用户指定要使用的特定 Python 解释器。
2. **构建 Python 扩展模块:**  支持构建用 C、C++ 或其他语言编写的 Python 扩展模块 (通常是 `.so` 或 `.pyd` 文件)。
3. **安装 Python 源代码文件:**  可以将 Python 源代码文件安装到指定的位置。
4. **获取 Python 安装目录:**  可以获取 Python 库的安装路径（例如 `purelib` 和 `platlib`）。
5. **处理 Python 依赖:**  能够查找和管理 Python 模块的依赖关系。
6. **执行 Python 脚本 (用于字节码编译):** 在安装过程中执行 Python 脚本来编译 `.py` 文件为 `.pyc` 或 `.pyo` 文件。
7. **获取 Python 配置信息:**  可以获取 Python 解释器的各种配置信息，例如版本、平台、变量和路径。

**与逆向方法的关联及举例说明**

这个文件与逆向工程有密切关系，主要体现在以下几点：

1. **构建 Frida Gadget:** Frida 作为一个动态 instrumentation 工具，其核心组件之一 "Gadget" 通常是以 Python 扩展模块的形式注入到目标进程中。`extension_module_method` 就是用来构建这些 Gadget 的关键函数。

   **举例说明:**  假设你正在开发一个 Frida Gadget，用于 hook 某个 Android 应用的 Native 层函数。你需要用 C/C++ 编写 hook 代码，并使用 `extension_module_method` 将其编译成一个 `.so` 文件，Frida 才能加载并注入到目标进程。

   ```python
   python.extension_module(
       '_my_gadget',  # 扩展模块的名字
       'my_gadget.c', # C 源代码文件
       c_args=['-Wall'],
       link_args=['-landroid'],
       install_dir=python.get_install_dir(subdir='my_package')
   )
   ```
   在这个例子中，`extension_module` 方法会将 `my_gadget.c` 编译成名为 `_my_gadget.so` 的共享库，并安装到 Python 包 `my_package` 的目录下。

2. **动态库注入和交互:**  逆向工程中经常需要将自定义的动态库注入到目标进程中，并与目标进程进行交互。Python 扩展模块是实现这一目标的常用方式。`extension_module_method` 使得使用 Meson 构建这种注入库变得更加方便。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

1. **二进制底层 (编译和链接):**  `extension_module_method` 涉及到将 C/C++ 代码编译成机器码，并链接成共享库。这需要理解编译器的选项 (`c_args`, `cpp_args`) 和链接器的选项 (`link_args`)。

   **举例说明:**  当构建 Android 平台的 Frida Gadget 时，你可能需要指定目标架构的 ABI (Application Binary Interface)，例如使用 `-march=armv7-a` 或 `-march=arm64-v8a` 作为 `c_args`。链接时可能需要链接到 Android 的标准 C 库 (`-lc`) 或其他系统库 (`-landroid`)。

2. **Linux 共享库 (`.so`):** Python 扩展模块在 Linux 上通常是 `.so` 文件。Meson 需要知道如何构建这种类型的共享库。

3. **Android 动态库 (`.so`):**  在 Android 上，Native 代码通常编译成 `.so` 文件。Frida Gadget 也是如此。`extension_module_method` 的参数允许指定 Android 特有的编译和链接选项。

   **举例说明:**  在 `extension_module_method` 中使用 `link_args=['-landroid']` 就表明需要链接 Android 的 C 库，这在开发 Android Native 代码时是常见的操作。

4. **Python Limited API:**  `extension_module_method` 中对 `limited_api` 参数的处理涉及到 Python 的稳定 ABI (Application Binary Interface)。使用 Limited API 可以提高扩展模块在不同 Python 版本之间的兼容性，但这需要对 Python 的底层 ABI 有一定的了解。

   **举例说明:**  设置 `limited_api='3.7'` 意味着你希望你的扩展模块使用 Python 3.7 的稳定 ABI 进行编译，这样它在 Python 3.7 及更高版本的 Python 解释器中更可能兼容。

**逻辑推理及假设输入与输出**

1. **`find_installation` 方法:**  该方法根据用户提供的参数（例如 Python 的路径或名称）尝试找到合适的 Python 解释器。

   **假设输入:**
   ```python
   python.find_installation()  # 不提供参数，默认查找
   ```
   **假设输出:**  返回一个 `PythonInstallation` 对象，代表系统中默认的 Python 3 解释器（如果找到）。

   **假设输入:**
   ```python
   python.find_installation('/usr/bin/python2.7', required=False) # 指定 Python 2.7 的路径，允许找不到
   ```
   **假设输出:** 如果找到 `/usr/bin/python2.7`，则返回一个 `PythonInstallation` 对象。如果找不到，且 `required=False`，则返回一个 `NonExistingExternalProgram` 对象。

2. **`extension_module_method` 方法:**  该方法根据提供的源代码文件和编译选项，生成并安装 Python 扩展模块。

   **假设输入:**
   ```python
   python.extension_module(
       '_my_module',
       'my_module.c',
       c_args=['-O2'],
       install_dir=python.get_install_dir(subdir='my_package')
   )
   ```
   **假设输出:**  在构建目录中生成 `_my_module.so` (或 `.pyd` 在 Windows 上)，并将其安装到 Python 库的 `my_package` 子目录下。

**涉及用户或编程常见的使用错误及举例说明**

1. **`subdir` 和 `install_dir` 互斥使用:** `extension_module_method` 中明确指出 `subdir` 和 `install_dir` 参数是互斥的。

   **错误示例:**
   ```python
   python.extension_module(
       '_my_module',
       'my_module.c',
       subdir='my_package',
       install_dir='/opt/my_install_path'  # 错误：同时指定了 subdir 和 install_dir
   )
   ```
   **错误说明:**  用户不应该同时指定相对子目录 `subdir` 和绝对安装路径 `install_dir`，因为这会导致安装位置的歧义。

2. **找不到所需的 Python 模块:** 在使用 `find_installation` 时，如果指定了 `modules` 参数，但 Meson 无法在找到的 Python 解释器中导入这些模块，则会报错。

   **错误示例:**
   ```python
   python.find_installation(modules=['non_existent_module'], required=True)
   ```
   **错误说明:**  如果系统中安装的 Python 解释器没有名为 `non_existent_module` 的模块，且 `required=True`，则 Meson 构建会失败。

3. **Python Limited API 版本不兼容:**  如果在 `extension_module_method` 中指定的 `limited_api` 版本高于当前使用的 Python 解释器版本，则会报错。

   **错误示例:**  假设你使用的是 Python 3.7，但指定了 `limited_api='3.8'`。

   **错误说明:**  Limited API 的版本必须小于等于当前 Python 解释器的版本。

**用户操作是如何一步步到达这里的，作为调试线索**

通常，用户是通过编写 `meson.build` 文件来配置 Meson 构建的。当 `meson` 命令被执行时，Meson 会解析 `meson.build` 文件，并根据其中的指令调用相应的模块和方法。

以下是一个用户操作如何一步步到达 `python.py` 的情景：

1. **用户编写 `meson.build` 文件:**  用户在其项目的根目录下创建 `meson.build` 文件，并希望构建一个 Python 扩展模块。

   ```meson
   project('myproject', 'c')
   py3 = import('python').find_installation()
   py3.extension_module('_my_extension', 'my_extension.c')
   ```

2. **用户执行 `meson setup builddir`:** 用户在终端中执行 `meson setup builddir` 命令，指示 Meson 在 `builddir` 目录下配置构建系统。

3. **Meson 解析 `meson.build`:** Meson 读取 `meson.build` 文件，遇到 `import('python')`，会加载 `frida/releng/meson/mesonbuild/modules/python.py` 模块。

4. **调用 `find_installation`:**  执行 `py3 = import('python').find_installation()` 时，会调用 `python.py` 中的 `PythonModule` 类的 `find_installation` 方法，查找 Python 3 解释器。

5. **调用 `extension_module`:**  执行 `py3.extension_module('_my_extension', 'my_extension.c')` 时，会调用 `PythonInstallation` 类的 `extension_module_method` 方法，开始构建 Python 扩展模块。

**调试线索:**

当用户遇到与 Python 相关的构建问题时，可以关注以下几点：

* **检查 `meson.build` 文件中与 Python 相关的调用:**  确认是否正确使用了 `find_installation` 和 `extension_module` 等方法，参数是否正确。
* **查看 Meson 的输出信息:** Meson 在配置和构建过程中会输出详细的信息，包括找到的 Python 解释器路径、编译命令、链接命令等。这些信息可以帮助定位问题。
* **使用 Meson 的调试功能:** Meson 提供了一些调试选项，例如 `-Dpython. சார்ந்த_python=/path/to/python` 可以强制指定使用的 Python 解释器，用于排除 Python 解释器查找问题。
* **检查 Python 解释器的状态:** 确认系统中是否安装了所需的 Python 解释器，以及是否安装了必要的 Python 模块。

总而言之，`frida/releng/meson/mesonbuild/modules/python.py` 是 Frida 构建系统中至关重要的一个模块，它负责处理与 Python 相关的各种任务，特别是构建 Python 扩展模块，这对于 Frida Gadget 的开发和逆向工程实践至关重要。 理解这个模块的功能有助于更好地利用 Meson 构建 Frida 项目，并解决可能遇到的 Python 相关构建问题。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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