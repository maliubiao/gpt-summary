Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understand the Goal:** The request asks for a breakdown of the code's functionality, its relationship to reverse engineering, its use of low-level/kernel concepts, its logical reasoning, potential user errors, and debugging clues.

2. **High-Level Overview:** First, I'd skim the code to get a general sense of its purpose. Keywords like "meson", "python", "extension_module", "dependency", "install", and the file path (`frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/python.py`) strongly suggest this code is part of a build system (Meson) and deals with building Python extensions. The `frida-tools` context indicates this is specifically about building Python components within the Frida framework.

3. **Identify Core Components:**  I'd look for key classes and functions. The presence of `PythonExternalProgram`, `PythonInstallation`, and `PythonModule` suggests a hierarchical structure for representing and managing Python installations within the build process. The methods within these classes likely represent specific actions that can be performed.

4. **Functionality Breakdown (Iterative Process):** I'd go through each class and its methods, summarizing their purpose. This is an iterative process:

    * **`PythonExternalProgram`:** This seems to represent a Python executable. The `sanity` method likely checks if the Python installation is valid. The `_get_path` method appears to determine installation paths (like `purelib` and `platlib`). The `run_bytecompile` class variable hints at bytecode compilation.

    * **`PythonInstallation`:** This class seems to wrap a `PythonExternalProgram` and provides higher-level methods for interacting with it within the Meson build system. Methods like `extension_module_method`, `dependency_method`, `install_sources_method`, and `get_install_dir_method` are key indications of its role. I'd pay attention to the decorators like `@permittedKwargs` and `@typed_pos_args` as they define the function's interface.

    * **`PythonModule`:** This appears to be the main entry point for this Meson module. It manages multiple Python installations (`self.installations`) and provides the `find_installation` method to locate Python interpreters. The `postconf_hook` suggests this module interacts with the overall build configuration. The `_get_win_pythonpath` method is a specific detail about handling Python on Windows.

5. **Connecting to Reverse Engineering:**  Now, the specific request to link functionality to reverse engineering. The key connection point here is the building of "extension modules."  Reverse engineering often involves:

    * **Analyzing compiled code:** Python extension modules are often compiled C/C++ code, which is precisely what this module helps build.
    * **Hooking/instrumentation:** Frida's core purpose. This module likely plays a role in building the Python bindings that Frida uses for its instrumentation capabilities.

6. **Identifying Low-Level/Kernel Aspects:** I'd look for concepts that relate to the underlying operating system and execution environment:

    * **Shared Libraries/Modules:** The `extension_module_method` builds shared libraries (`SharedModule`). This is a core OS concept.
    * **File Paths and Installation:** The code deals extensively with file paths (`platlib`, `purelib`, installation directories), which are OS-specific.
    * **Windows-specific logic:** The `_get_win_pythonpath` method is explicitly about handling the Windows environment.
    * **Bytecode Compilation:** This process transforms Python source into a lower-level bytecode format executed by the Python VM.
    * **Limited API:** The "limited API" concept in Python extension building is related to ABI stability and avoiding direct interaction with Python's internal structures.

7. **Logical Reasoning and Assumptions:**  I'd examine parts of the code where decisions are made based on conditions:

    * **`_get_path` and `install_env`:**  The logic for determining installation paths based on whether the user is in a virtual environment.
    * **`extension_module_method` and `limited_api`:** The conditional logic for adding compiler flags and linker arguments based on the `limited_api` setting.
    * **`find_installation`:** The logic for searching for Python executables, including fallback mechanisms.

8. **User Errors:** Think about how a user might misuse the provided functions:

    * **Incorrect keyword arguments:** Providing invalid or conflicting arguments to functions like `extension_module`.
    * **Specifying non-existent Python interpreters:**  Providing an invalid path to `find_installation`.
    * **Missing dependencies:** Trying to build an extension module without the necessary Python development headers or libraries.
    * **Virtual environment issues:**  Mismatched expectations about whether a virtual environment is active.

9. **Debugging Clues:**  Consider how a developer would trace execution to this code:

    * **Meson build process:**  The user would be running `meson` commands to configure and build the project.
    * **Build logs:** Meson generates logs that would show the execution of these Python module functions.
    * **Error messages:**  The code includes `mesonlib.MesonException` calls, which would provide specific error messages to the user.
    * **Frida's build system:** If building Frida, the user's actions would involve commands specific to Frida's build process, which internally use Meson.

10. **Structure and Presentation:** Finally, organize the findings into clear categories as requested by the prompt. Use examples to illustrate the points. Use formatting (like bold text) to highlight key terms.

**Self-Correction/Refinement:**

* **Initial thought:**  Maybe this is *directly* involved in Frida's hooking. **Correction:**  More likely it's involved in *building* the Python components that *enable* Frida's hooking.
* **Overlooking details:** Initially, I might miss the significance of the `limited_api` keyword. Re-reading the code more carefully reveals its purpose in controlling the Python C API.
* **Ambiguity:**  The request to explain "how a user operation reaches here" is a bit broad. Clarify that it's through the Meson build system configuration and execution.

By following these steps, combining careful code reading with general knowledge of build systems, Python extensions, and reverse engineering concepts, I can construct a comprehensive and accurate explanation of the provided code.
好的，让我们来详细分析一下这个Python源代码文件 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/python.py` 的功能。

**主要功能概述:**

这个文件是 Meson 构建系统中用于处理 Python 相关构建任务的模块。它提供了一系列功能，允许 Meson 构建系统查找、配置和使用 Python 解释器，并构建 Python 扩展模块。 简单来说，它的核心职责是：**让 Meson 知道如何构建和管理 Python 代码，特别是 Python 的 C 扩展模块。**

**功能详细列举与说明:**

1. **查找和管理 Python 解释器 (`find_installation`):**
   - **功能:**  允许 Meson 构建系统在用户的系统中查找合适的 Python 解释器。可以指定 Python 的版本（例如 `python3`）、或者提供 Python 可执行文件的路径。
   - **逆向关系:** 在逆向工程中，你可能需要在特定的 Python 环境下运行 Frida 脚本。这个功能确保 Frida 的构建系统能够找到与你的逆向环境匹配的 Python 解释器。
   - **二进制底层/内核/框架:**  它会调用底层的系统命令（如 `which python3` 或直接执行提供的路径）来找到 Python 解释器。它还会读取 Python 解释器的配置信息，例如安装路径 (`purelib`, `platlib`)。在 Windows 上，它会尝试使用 `py` 启动器来查找 Python。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  `meson.get_compiler('python').find_installation()`  （在 `meson.build` 文件中调用）
     - **可能输出:**  一个代表找到的 Python 解释器的对象，包含了它的路径、版本等信息。 如果找不到，则会抛出异常或返回一个表示未找到的对象。
   - **用户错误:** 用户可能没有安装 Python，或者指定的 Python 版本不存在。
   - **调试线索:** 当 Meson 配置失败并提示找不到 Python 时，或者使用了错误的 Python 版本时，就会涉及到这个功能。用户在运行 `meson setup build` 时，Meson 会调用这个函数来查找 Python。

2. **创建 Python 扩展模块 (`extension_module_method`):**
   - **功能:**  允许将 C/C++ 代码编译成 Python 可以导入的扩展模块 (`.so` 或 `.pyd` 文件)。
   - **逆向关系:** Frida 的核心功能是用 C/C++ 实现的，并通过 Python 扩展模块提供 Python 接口。这个功能负责构建 Frida 的 Python 绑定。
   - **二进制底层/内核/框架:** 这个功能会调用 C/C++ 编译器（例如 GCC 或 MSVC）来编译 C/C++ 源代码。它需要理解 Python 的 C API，并生成与 Python 解释器兼容的二进制代码。`limited_api` 参数涉及到 Python 的稳定 ABI。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `python.extension_module('my_extension', 'my_extension.c', dependencies: python.dependency())`
     - **可能输出:** 一个代表构建完成的共享库目标 (`SharedModule`) 的对象。Meson 会在构建目录中生成 `my_extension.so` 或 `my_extension.pyd`。
   - **用户错误:** 用户可能提供了错误的源文件，或者依赖了不存在的库，或者 C/C++ 代码不符合 Python C API 的规范。
   - **调试线索:** 当构建 Frida 时，如果编译 Python 扩展模块失败，错误信息会指向这里。用户在 `meson compile` 时会触发这个功能。

3. **获取 Python 依赖 (`dependency_method`):**
   - **功能:**  允许声明对 Python 解释器本身的依赖。这可以确保在构建扩展模块时，链接到正确的 Python 库。
   - **逆向关系:** 构建 Frida 的 Python 扩展模块时，需要链接到 Python 的动态链接库 (`libpython`).
   - **二进制底层/内核/框架:**  这个功能会查找 Python 的开发库和头文件。在不同的操作系统上，Python 库的名称和位置可能不同。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `python.dependency()`
     - **可能输出:**  一个代表 Python 依赖的对象，包含了 Python 库的路径和头文件路径。
   - **用户错误:**  通常情况下，如果 Python 安装正确，这个功能不会出错。但如果 Python 的开发包没有安装，可能会失败。
   - **调试线索:** 如果链接 Python 库时出现问题，错误信息可能会指向这里。

4. **安装 Python 源代码文件 (`install_sources_method`):**
   - **功能:**  允许将 Python 源代码文件安装到指定的位置。
   - **逆向关系:**  Frida 的 Python 脚本和模块需要安装到 Python 的 site-packages 目录下才能被导入和使用。
   - **文件系统:** 这个功能涉及到文件复制操作。`pure` 参数决定安装到 `purelib` 还是 `platlib` 目录。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `python.install_sources('my_script.py', subdir: 'frida')`
     - **可能输出:** 一个代表安装数据的对象 (`Data`)。在安装阶段，`my_script.py` 会被复制到 Python 安装目录下的 `frida` 子目录中。
   - **用户错误:** 用户可能指定了不存在的源文件或错误的安装子目录。
   - **调试线索:**  当安装 Frida 后，如果发现某些 Python 文件没有正确安装，可能与这个功能有关。用户在 `meson install` 时会触发。

5. **获取 Python 安装目录 (`get_install_dir_method`):**
   - **功能:**  返回 Python 库的安装目录，例如 `purelib` (纯 Python 模块) 或 `platlib` (平台相关的模块)。
   - **逆向关系:**  在构建和安装过程中，需要知道 Python 模块的安装位置。
   - **文件系统:**  这个功能依赖于 Python 解释器的配置信息。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `python.get_install_dir(pure: True)`
     - **可能输出:**  一个字符串，表示纯 Python 模块的安装路径。
   - **用户错误:**  通常不会出错。
   - **调试线索:**  在需要确定 Python 模块安装位置时可能会用到。

6. **获取 Python 语言版本 (`language_version_method`):**
   - **功能:**  返回当前使用的 Python 解释器的版本。
   - **逆向关系:**  在某些情况下，需要根据 Python 版本执行不同的操作。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `python.language_version()`
     - **可能输出:**  一个字符串，表示 Python 的版本号，例如 "3.10.0"。

7. **检查 Python 路径是否存在 (`has_path_method`, `get_path_method`):**
   - **功能:**  允许查询 Python 解释器配置中的特定路径，例如 `stdlib` (标准库路径)。
   - **逆向关系:**  在某些构建场景下，可能需要知道标准库的路径。

8. **检查 Python 变量是否存在 (`has_variable_method`, `get_variable_method`):**
   - **功能:**  允许查询 Python 解释器配置中的特定变量，例如 `prefix` (Python 安装前缀)。

9. **安装后处理钩子 (`postconf_hook`):**
   - **功能:**  在 Meson 配置完成后执行一些操作，例如添加安装脚本来编译 Python 字节码。
   - **二进制底层:** 涉及 Python 字节码的编译。

**与逆向方法的举例说明:**

* **构建 Frida 的 Python 绑定:**  当构建 Frida 时，`extension_module_method` 会被用来编译 Frida 核心的 C/C++ 代码，并生成 `_frida.so` 或 `_frida.pyd` 扩展模块，这是 Frida Python API 的基础。
* **查找目标进程的 Python 解释器:**  如果你想用 Frida attach 到一个运行中的 Python 进程，你可能需要知道目标进程使用的 Python 解释器的路径。虽然这个模块本身不直接做 attach 操作，但它提供的查找 Python 解释器的能力是相关的。

**涉及到二进制底层, linux, android内核及框架的知识的举例说明:**

* **编译 C 扩展模块:**  `extension_module_method` 涉及到 C/C++ 编译器的使用，以及链接到 Python 的 C API 库。这直接触及到二进制代码的生成和链接过程。在 Linux 和 Android 上，会生成 `.so` 文件。
* **`limited_api` 参数:**  这个参数控制是否使用 Python 的稳定 ABI。使用稳定 ABI 可以提高扩展模块在不同 Python 版本之间的兼容性，但这会限制可以使用的 Python C API。这涉及到 Python 解释器的内部结构和 ABI 兼容性。
* **查找 Python 安装路径:**  `_get_path` 方法需要理解不同操作系统上 Python 的安装约定，例如 Linux 上的 `/usr/lib/pythonX.Y/site-packages` 和 Windows 上的 `Lib\site-packages`。
* **Windows 特殊处理 (`_get_win_pythonpath`):**  在 Windows 上，查找 Python 解释器可能需要使用 `py` 启动器，这体现了对 Windows 特定机制的了解。
* **字节码编译 (`postconf_hook`):**  Python 代码通常会被编译成字节码 (`.pyc`) 以提高加载速度。这个钩子函数会生成安装脚本来执行字节码编译，这涉及到 Python 字节码的知识。

**逻辑推理的假设输入与输出 (补充):**

* **`_find_installation_impl`:**
    - **假设输入:**  `state` (模块状态), `display_name` ("python3"), `name_or_path` (None), `required` (True)
    - **可能输出:**  如果系统中有 `python3` 可执行文件，则返回一个 `PythonExternalProgram` 对象，表示找到的 Python 3 解释器。如果找不到，并且 `required` 为 True，则抛出 `mesonlib.MesonException`。
* **`_convert_api_version_to_py_version_hex`:**
    - **假设输入:** `api_version` ("3.7"), `detected_version` ("3.10.0")
    - **可能输出:**  字符串 "0x03070000"，这是 Python 3.7 的 Limited API 版本对应的十六进制表示。

**涉及用户或者编程常见的使用错误的举例说明:**

* **`extension_module_method`:** 用户可能错误地将 `subdir` 和 `install_dir` 都设置了值，导致冲突。代码中会抛出 `InvalidArguments` 异常。
* **`find_installation`:** 用户可能在 `meson.build` 文件中指定了一个不存在的 Python 解释器路径，导致构建失败。
* **`install_sources_method`:** 用户可能忘记设置 `subdir` 参数，导致文件被安装到 Python 根目录下，这通常不是期望的行为。
* **类型错误:**  由于使用了 `typed_pos_args` 和 `typed_kwargs`，如果用户传递了错误类型的参数，例如将字符串传递给期望布尔值的参数，Meson 会在配置阶段就报错。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **配置构建环境:** 用户首先会运行 `meson setup build` 命令，指定构建目录。
2. **读取 `meson.build`:** Meson 会解析项目根目录下的 `meson.build` 文件。
3. **调用 Python 模块:** 在 `meson.build` 文件中，可能会有类似 `python = import('python').find_installation()` 的语句，这会触发 `PythonModule` 的 `find_installation` 方法。
4. **查找 Python 解释器:** `find_installation` 方法会根据配置查找合适的 Python 解释器。
5. **构建扩展模块:** 如果 `meson.build` 中有 `python.extension_module(...)` 的调用，那么在编译阶段（运行 `meson compile` 命令）会执行 `extension_module_method` 来构建 Python 扩展模块。
6. **安装文件:**  如果运行 `meson install` 命令，`install_sources_method` 会被调用来安装 Python 源代码文件。
7. **处理安装后任务:**  在配置完成后，`postconf_hook` 会被调用，添加编译 Python 字节码的安装脚本。

**调试线索:**

* **配置错误:** 如果 `meson setup build` 失败，并提示找不到 Python，那么问题很可能出在 `find_installation` 方法中。检查 `meson.build` 文件中对 Python 的配置，以及系统环境变量。
* **编译错误:** 如果 `meson compile` 失败，并且涉及到 Python 扩展模块，那么需要检查 `extension_module_method` 的调用，以及相关的 C/C++ 源代码。编译器和链接器的错误信息会提供更详细的线索。
* **安装错误:** 如果 `meson install` 后发现 Python 文件没有正确安装，检查 `install_sources_method` 的调用，确认源文件路径和安装目录是否正确。

总而言之，这个文件是 Meson 构建系统中处理 Python 相关任务的核心组件，它连接了 Meson 的构建逻辑和 Python 的生态系统，使得 Frida 这样的项目能够方便地构建和管理其 Python 接口。理解这个文件的功能对于调试 Frida 的构建过程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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