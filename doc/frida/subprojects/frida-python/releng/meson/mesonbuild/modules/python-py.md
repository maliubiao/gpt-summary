Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request is to analyze the provided Python code, which is a module for the Meson build system related to Python integration. The core task is to identify its functionalities, relate them to reverse engineering (if applicable), discuss low-level aspects (like kernel interaction), logical reasoning, potential user errors, and debugging entry points.

2. **Initial Scan and Keywords:**  A quick skim of the code reveals keywords and concepts:
    * `frida`:  This immediately signals a connection to the Frida dynamic instrumentation tool, confirming the context provided in the prompt.
    * `meson`: Indicates this is a module for the Meson build system.
    * `python`:  The module deals with Python integration.
    * `extension_module`, `install_sources`, `dependency`: These suggest build-related functionalities for Python extensions.
    * `SharedModule`, `CustomTarget`, `BuildTarget`:  These are Meson build system concepts.
    * `purelib`, `platlib`: These are standard Python installation directories, hinting at managing Python package locations.
    * `limited_api`:  Relates to Python's stable ABI.

3. **Functionality Breakdown (High-Level):** Based on the initial scan, the module's primary responsibilities seem to be:
    * **Finding Python Installations:** Locating available Python interpreters on the system.
    * **Building Python Extension Modules:**  Compiling shared libraries that can be imported by Python.
    * **Managing Python Dependencies:**  Handling dependencies required for Python projects and extensions.
    * **Installing Python Sources:**  Copying Python files to the correct installation locations.
    * **Getting Python Installation Information:** Providing access to paths and variables from the Python installation.

4. **Relating to Reverse Engineering:** Now, the crucial step is to connect these functionalities to reverse engineering.
    * **Frida Connection:**  The module is part of Frida. Frida's core function is to inject code into running processes. Python is a common language for scripting Frida interactions. Therefore, this module likely helps build Python extensions that *become* the Frida instrumentation logic.
    * **`extension_module`:** This is a direct link. Reverse engineers often write custom Frida scripts in Python, which might require interacting with native code. `extension_module` builds the bridge for this interaction. *Example:* Imagine a reverse engineer wants to hook a native function. They might write a Python script that uses a custom extension module (built using this code) to perform the actual hooking in C/C++.
    * **Dynamic Analysis:** The entire premise of Frida is dynamic analysis. This module contributes to the toolchain that enables this.

5. **Binary/Low-Level, Linux/Android Kernel/Framework:**  Look for clues about interaction with the underlying system.
    * **`SharedModule`:** Shared libraries are a fundamental binary concept. Building them involves compilers, linkers, and understanding ABI compatibility.
    * **`limited_api`:** This directly addresses binary compatibility between Python extensions and different Python versions. It's a mechanism to create more stable binary interfaces.
    * **`c_args`, `cpp_args`, `link_args`:** These keywords in `extension_module_method` clearly indicate the manipulation of compiler and linker flags, which are crucial for building native code.
    * **Linux/Android:** While the code itself isn't OS-specific *at this level*, the *purpose* of Frida often involves targeting Linux and Android. The generated shared modules will eventually run within processes on those systems, potentially interacting with kernel APIs (though that interaction wouldn't be directly within *this* Python code). *Example:* A Frida script (using an extension built with this module) might interact with Android's Binder framework to intercept IPC calls.

6. **Logical Reasoning (Hypothetical Input/Output):**  Consider the functions and how they transform data.
    * **`find_installation`:** *Input:*  Optionally a specific Python executable path. *Output:* A `PythonInstallation` object representing the found Python, or a `NonExistingExternalProgram` if not found.
    * **`extension_module`:** *Input:* A name for the module, source files (Python, C/C++), and keyword arguments like `subdir`. *Output:* A `SharedModule` object representing the compiled extension. The output path would depend on the `subdir` and the Python installation's `platlib` or `purelib`.

7. **User/Programming Errors:** Think about how users might misuse the API.
    * **`find_installation`:** Providing an invalid path or name for Python. Forgetting to install necessary Python modules if `modules` is specified.
    * **`extension_module`:**  Incorrectly specifying dependencies. Providing incompatible compiler flags. Mixing `subdir` and `install_dir`. Using a `limited_api` version higher than the detected Python version.

8. **Debugging Entry Point:** How does a user end up interacting with this code?
    * **Meson Build Files:**  Users define their build system using `meson.build` files. They would call functions from the `python` module within these files.
    * **`find_installation()`:** A user might start by using `python.find_installation()` to locate a specific Python interpreter.
    * **`extension_module()`:** If they need to build a Python extension, they would use `python.extension_module()`.
    * **Error Messages:** If there's an error in the `meson.build` file related to Python, the stack trace would lead back to this module.

9. **Refinement and Organization:**  After the initial brainstorming, organize the findings into the requested categories. Use clear and concise language. Provide specific examples to illustrate the points. Ensure the explanations connect the code's functionality back to the broader context of Frida and reverse engineering.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Focusing too much on the Python code's internal logic.
* **Correction:**  Shift focus to the *purpose* and *impact* of the code within the Frida ecosystem. How does it *enable* reverse engineering?
* **Initial Thought:**  Listing all the functions without explaining their significance.
* **Correction:** Group related functions and explain their combined effect (e.g., how `find_installation` and `extension_module` work together).
* **Initial Thought:**  Overlooking the connection to build systems and the user interaction with `meson.build` files.
* **Correction:** Explicitly mention how users interact with this module through Meson's DSL.

By following these steps, including the self-correction, we can arrive at a comprehensive and insightful analysis of the provided Python code.
好的，让我们来详细分析一下这个 `python.py` 文件，它是 Frida 动态 instrumentation 工具中用于 Meson 构建系统的 Python 模块。

**主要功能列举：**

这个文件定义了一个 Meson 构建系统的模块，专门用于处理 Python 相关的构建任务。其核心功能可以概括为：

1. **查找和管理 Python 解释器:**
   - `find_installation()`:  允许 Meson 构建系统查找系统中的 Python 解释器。它可以根据名称（例如 "python3"）或路径来查找。
   - 缓存已找到的 Python 解释器实例，避免重复查找。

2. **构建 Python 扩展模块:**
   - `extension_module()`:  用于构建 Python 的 C/C++ 扩展模块（通常是 `.so` 或 `.pyd` 文件）。
   - 允许指定源文件（C/C++ 代码），依赖项，编译和链接参数。
   - 支持 `limited_api` 选项，用于构建与不同 Python 版本二进制兼容的扩展。

3. **安装 Python 源代码:**
   - `install_sources()`:  用于安装 Python 源代码文件到指定目录。
   - 可以选择安装到纯 Python 库目录 (`purelib`) 或平台相关库目录 (`platlib`)。

4. **获取 Python 安装信息:**
   - 提供各种方法来获取已找到的 Python 解释器的信息：
     - `get_install_dir()`: 获取 Python 包的安装目录。
     - `language_version()`: 获取 Python 的版本号。
     - `has_path()`, `get_path()`: 检查和获取 Python 配置路径（例如 `stdlib`, `platstdlib`）。
     - `has_variable()`, `get_variable()`: 检查和获取 Python 的配置变量（例如 `prefix`, `base`).
     - `path()`: 获取 Python 解释器自身的路径。

5. **处理 Python 依赖:**
   - `dependency()`:  允许查找和声明 Python 依赖项。

6. **支持 Bytecode 编译:**
   - 自动处理 Python 文件的 bytecode 编译 (`.pyc`)，在安装后运行 `pycompile.py` 脚本。

**与逆向方法的关系及举例说明：**

Frida 本身就是一个强大的逆向工程工具。这个 Python 模块在 Frida 的构建过程中扮演着关键角色，因为它允许构建 Frida 的 Python 绑定（`frida-python`）。

* **构建 Frida 的 Python 接口:** Frida 的核心是用 C/C++ 编写的，而 `frida-python` 提供了 Python 接口来控制和与 Frida 交互。 `extension_module()` 就被用于构建这个 Python 接口的 C 扩展模块。
    * **例子:**  Frida 的 Python API 允许你编写 Python 脚本来 hook 目标进程的函数、读取内存、调用函数等。这些功能背后是由 C 扩展模块实现的，该模块是通过这个 `python.py` 文件构建的。

* **为 Frida 用户提供构建工具:**  如果 Frida 用户想要开发自定义的 Python 扩展模块，以便在 Frida 脚本中使用更底层的操作或集成其他 C/C++ 库，他们可以使用 Meson 和这个模块来构建自己的扩展。
    * **例子:**  一个逆向工程师可能需要一个 Python 扩展来执行一些特定的内存操作，或者集成一个自定义的反汇编引擎。他们可以使用 Meson 和 `extension_module()` 来构建这个扩展，然后在 Frida 脚本中导入并使用。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

这个模块虽然本身是用 Python 编写的，但它涉及了与底层系统交互和二进制代码构建相关的概念：

* **构建共享库 (`SharedModule`)**:  `extension_module()` 的核心是构建共享库 (`.so` 在 Linux 上，`.dylib` 在 macOS 上，`.pyd` 在 Windows 上）。这涉及到理解编译、链接过程，以及操作系统加载和管理动态链接库的机制。
    * **例子:**  构建 Frida 的 Python 扩展模块时，需要将 C 代码编译成与 Python 解释器兼容的共享库。这需要指定正确的头文件路径、链接 Python 库等。

* **`limited_api` (稳定 ABI):**  这个特性允许构建的 Python 扩展模块在不同版本的 Python 解释器之间保持二进制兼容性。这涉及到理解 Python 的 C API 以及 ABI (Application Binary Interface) 的概念。
    * **例子:**  Frida 可能会选择使用 `limited_api` 构建其 Python 扩展，这样用户在不同的 Python 环境下安装 `frida-python` 时，通常不需要重新编译扩展模块。

* **与操作系统相关的安装路径 (`purelib`, `platlib`):**  Python 的安装目录结构是与操作系统相关的。`purelib` 用于存放平台无关的 Python 代码，而 `platlib` 用于存放平台相关的扩展模块。这个模块需要知道这些路径，以便将文件安装到正确的位置。
    * **例子:**  在 Linux 上，`platlib` 可能位于 `/usr/lib/python3.x/site-packages`，而在 macOS 上可能位于 `/Library/Frameworks/Python.framework/Versions/3.x/lib/python3.x/site-packages`。

* **条件编译和链接参数 (`c_args`, `cpp_args`, `link_args`):**  `extension_module()` 允许指定传递给 C/C++ 编译器和链接器的参数。这些参数可以用于控制编译优化级别、包含特定的宏定义、链接特定的库等。这些参数通常是平台相关的。
    * **例子:**  在构建 Frida 的 Android 支持时，可能需要指定 Android NDK 提供的头文件和库路径。

**逻辑推理（假设输入与输出）：**

假设我们有一个简单的 C 文件 `my_extension.c`，我们想用这个模块构建一个名为 `_my_extension.so` 的 Python 扩展模块。

**假设输入:**

```python
python.extension_module(
    '_my_extension',
    files('my_extension.c'),
    subdir='my_package'
)
```

**预期输出:**

- Meson 会调用 C 编译器（例如 GCC 或 Clang）来编译 `my_extension.c`。
- Meson 会调用链接器来创建一个名为 `_my_extension.so` 的共享库。
- 该共享库会被安装到 Python 安装路径下的 `my_package` 子目录中，具体路径取决于 Python 的配置（`purelib` 或 `platlib`）。例如，可能安装到 `/usr/lib/python3.x/site-packages/my_package/_my_extension.so`。
- 返回一个代表该共享库构建目标的 `SharedModule` 对象。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **找不到 Python 解释器:**
   - **错误:**  用户没有安装 Python，或者指定的 Python 名称/路径不正确。
   - **例子:** 在 `meson.build` 中使用 `python.find_installation('python2.6')`，但系统中没有安装 Python 2.6。
   - **结果:**  `find_installation()` 会失败，导致构建过程出错。

2. **构建扩展模块时缺少依赖:**
   - **错误:**  C/C++ 扩展模块依赖了某些库，但这些库没有被正确声明为依赖项，或者系统上缺少这些库。
   - **例子:**  `my_extension.c` 中使用了 `libuv` 库，但在 `extension_module()` 中没有指定 `dependencies: find_library('uv')`。
   - **结果:**  链接器会报错，找不到 `libuv` 相关的符号。

3. **`subdir` 和 `install_dir` 冲突使用:**
   - **错误:**  同时指定了 `subdir` 和 `install_dir`，这两个参数是互斥的。
   - **例子:**
     ```python
     python.extension_module(
         '_my_extension',
         files('my_extension.c'),
         subdir='my_package',
         install_dir=python.get_install_dir(pure: False) / 'another_dir'
     )
     ```
   - **结果:**  Meson 会抛出 `InvalidArguments` 异常。

4. **`limited_api` 版本不兼容:**
   - **错误:**  指定的 `limited_api` 版本高于当前 Python 解释器的版本。
   - **例子:**  使用 Python 3.7 构建扩展，但指定了 `limited_api='3.9'`。
   - **结果:**  `extension_module()` 会抛出 `InvalidArguments` 异常。

5. **安装源文件时 `pure` 参数使用不当:**
   - **错误:**  尝试将包含平台相关代码的源文件安装到 `purelib` 目录。
   - **例子:**  安装一个包含 C 扩展的 `.so` 文件时，设置 `pure=True`。
   - **结果:**  可能会导致运行时错误，因为平台相关的模块应该放在 `platlib`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本或需要构建 Python 扩展:**  用户可能正在开发一个 Frida 脚本，需要与自定义的 C/C++ 代码交互以实现特定的功能，或者他们正在为 Frida 本身贡献代码。

2. **配置 Meson 构建系统:**  用户会在项目的根目录下创建一个 `meson.build` 文件，并在其中使用 `project()` 函数定义项目，然后使用 `python.find_installation()` 来查找 Python 解释器。

3. **使用 `python.extension_module()` 构建 Python 扩展:**  在 `meson.build` 文件中，用户会调用 `python.extension_module()` 函数，提供扩展模块的名称、源文件、依赖项等信息。

4. **运行 Meson 配置命令:**  用户在终端中运行 `meson setup builddir` 命令，Meson 会读取 `meson.build` 文件，并执行其中的 Python 代码，包括调用 `python.py` 模块中的函数。

5. **Meson 调用 `python.py` 中的函数:**  当 Meson 解析到 `python.extension_module()` 等调用时，它会执行 `frida/subprojects/frida-python/releng/meson/mesonbuild/modules/python.py` 文件中定义的相应方法。

6. **如果构建过程中出现错误:**  例如，如果指定的 Python 解释器找不到，或者构建扩展模块时缺少依赖，Meson 会报错，错误信息中可能会包含与 `python.py` 文件相关的调用栈信息。

**调试线索:**

- **查看 `meson.build` 文件:** 检查用户是如何调用 `python.find_installation()` 和 `python.extension_module()` 的，确认参数是否正确。
- **检查 Meson 的配置输出:**  运行 `meson setup --reconfigure builddir -v` 可以查看详细的配置过程，包括 Meson 如何查找 Python 解释器，以及构建扩展模块时使用的编译器和链接器命令。
- **查看编译和链接错误信息:**  如果构建扩展模块失败，查看详细的编译和链接错误信息，这些信息通常会指出缺少哪些头文件、库文件或符号。
- **检查 Python 解释器的状态:**  确认用户系统中安装了 Python，并且指定的 Python 版本是可用的。
- **使用 Meson 的调试功能:**  Meson 提供了一些调试选项，可以帮助理解构建过程中的变量和状态。

总而言之，`frida/subprojects/frida-python/releng/meson/mesonbuild/modules/python.py` 文件是 Frida 项目中用于管理 Python 相关构建任务的关键模块，它提供了查找 Python 解释器、构建 Python 扩展模块和安装 Python 源代码等功能，对于 Frida 的 Python 绑定和希望开发自定义 Frida 扩展的用户来说至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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