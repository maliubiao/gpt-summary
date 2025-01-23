Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its purpose and relate it to broader concepts like reverse engineering, low-level details, and common errors.

**1. Initial Understanding - What is this file about?**

The first line gives us the crucial context: `frida/releng/meson/mesonbuild/dependencies/python.py`. This immediately tells us:

* **Frida:** It's part of the Frida dynamic instrumentation toolkit. This is a huge clue that reverse engineering is likely involved.
* **Meson:** It's related to the Meson build system. This suggests dependency management and building software that might interact with Python.
* **`mesonbuild/dependencies/python.py`:** This pinpoint suggests it's responsible for handling Python dependencies *within* the Meson build process.

**2. Core Functionality - What does the code *do*?**

Skimming the code reveals various classes and functions. Key observations:

* **`BasicPythonExternalProgram`:** This looks like a way to find and introspect Python installations. It runs a Python script (`python_info.py`) to gather details like version, paths, and platform.
* **Dependency Classes (`PythonPkgConfigDependency`, `PythonFrameworkDependency`, `PythonSystemDependency`):** These classes represent different ways to find and link against Python libraries. They inherit from base dependency classes provided by Meson.
* **`python_factory`:** This function seems to be the central point for finding a suitable Python dependency. It tries different methods (pkg-config, system libraries, frameworks).
* **`Pybind11ConfigToolDependency`, `NumPyConfigToolDependency`:** These handle dependencies for specific Python libraries used in native extensions.

**3. Connecting to Reverse Engineering:**

With the "Frida" context, the connection to reverse engineering becomes clearer:

* **Dynamic Instrumentation:** Frida allows modifying the behavior of running processes. To do this effectively, it often needs to interact with the target process's dependencies, including Python if the target uses it.
* **Native Extensions:** Frida itself or the tools it uses might be built with native extensions (e.g., using `pybind11`) that need to link against specific Python versions and libraries.

**4. Identifying Low-Level Interactions:**

Look for code that interacts with the operating system or underlying system components:

* **Path Manipulation (`os.path.join`, `Pathlib.Path`):**  Dealing with file system paths is a common low-level task.
* **Process Execution (`mesonlib.Popen_safe`):**  Running external commands (like `python_info.py`) is a system-level interaction.
* **Environment Variables (`os.environ`):**  Modifying environment variables (like `PKG_CONFIG_LIBDIR`) affects how programs find libraries.
* **Operating System Checks (`mesonlib.is_windows()`):**  Conditional logic based on the operating system indicates platform-specific behavior.
* **Architecture Detection (`detect_cpu_family`):**  Checking the CPU architecture is relevant for binary compatibility.
* **Library Linking:** The code explicitly deals with finding and specifying libraries to link against (`self.link_args`). This is a fundamental step in building executable code.

**5. Logical Reasoning and Assumptions:**

* **Assumption:** The `python_info.py` script (not shown) is assumed to reliably provide the necessary introspection data.
* **Logic:** The `python_factory` function uses a priority-based approach to finding Python. It tries `pkgconfig` first, then falls back to `system` and `framework` methods. This makes sense for a robust dependency resolution mechanism.
* **Input/Output:** If the `installation` parameter to `python_factory` is provided, it directly uses that specific Python installation. Otherwise, it attempts to find a suitable Python on the system. The output is a list of "dependency generators" that Meson can use to find the actual dependency information.

**6. User/Programming Errors:**

Think about how a user or developer might misuse this:

* **Incorrect Python Installation:** If the system Python is broken or the wrong version, Meson might fail to find the correct dependency.
* **Missing Dependencies (pybind11, NumPy):** If these libraries are not installed or not in the expected locations, the build will fail.
* **Environment Issues:** Incorrectly set environment variables (like `PKG_CONFIG_LIBDIR`) could mislead the dependency detection.
* **Cross-Compilation Problems:**  Trying to build for a different architecture than the available Python installation will cause errors (handled by the architecture checks).
* **Debug/Release Mismatches (Windows):**  The code explicitly warns about the potential issues when linking a debug build against a release Python interpreter (and vice versa) on Windows.

**7. Tracing User Operations (Debugging Clues):**

Consider how a user might end up invoking this code:

1. **User wants to build a Frida component or a tool that depends on Frida.**
2. **They use the `meson` command to configure the build.**
3. **Meson reads the `meson.build` files, which specify dependencies (including Python).**
4. **Meson's dependency resolution system kicks in.**
5. **For Python dependencies, Meson calls the `python_factory` function in this `python.py` file.**
6. **The `python_factory` tries different methods to find a suitable Python installation based on the build environment and user configuration.**
7. **If successful, Meson stores the dependency information and uses it during the compilation and linking stages.**
8. **If unsuccessful, Meson reports an error, and the user might need to investigate their Python installation or build environment.**

By following these steps, we can systematically dissect the code, understand its purpose within the Frida/Meson ecosystem, and connect it to broader concepts relevant to reverse engineering and software development. The key is to combine code analysis with domain knowledge and consideration of potential usage scenarios.
这个文件 `frida/releng/meson/mesonbuild/dependencies/python.py` 是 Frida 动态 Instrumentation 工具中，用于处理 Python 依赖项的 Meson 构建系统模块。它的主要功能是：

**1. 查找和配置 Python 解释器：**

* **检测系统中的 Python 解释器：** 它通过尝试执行 `python3` 命令，并运行一个内部脚本 `python_info.py` 来获取关于 Python 解释器的详细信息，例如版本、安装路径、平台、编译选项等。
* **支持指定特定的 Python 解释器：**  虽然代码中没有直接展示，但 Meson 构建系统允许用户通过环境变量或命令行参数指定要使用的 Python 解释器。这个模块会根据这些指定来查找和配置。
* **区分不同的 Python 变种：**  它可以区分 CPython 和 PyPy，并根据不同的变种进行相应的处理。
* **处理虚拟环境：** 它能检测当前是否在虚拟环境中运行，并考虑虚拟环境的路径设置。

**2. 提供 Python 依赖项信息给 Meson 构建系统：**

* **定义不同的 Python 依赖项类型：**  它定义了 `PythonPkgConfigDependency`、`PythonFrameworkDependency` 和 `PythonSystemDependency` 等类，分别对应通过 `pkg-config`、Framework (macOS) 和系统库查找 Python 依赖项的方法。
* **生成编译和链接参数：**  根据找到的 Python 解释器信息，它会生成用于编译 native 扩展模块所需的编译参数 (例如 `-I/usr/include/python3.x`) 和链接参数 (例如 `-lpython3.x`)。
* **处理 "embed" 模式：**  它支持 Python 的 "embed" 模式，即 Python 被嵌入到应用程序中，而不是作为独立的共享库。在这种模式下，链接方式会有所不同。

**3. 处理特定的 Python 库依赖：**

* **`Pybind11ConfigToolDependency`：**  专门用于查找和配置 `pybind11` 库的依赖项。`pybind11` 是一个用于创建 Python C++ 绑定的库，Frida 可能会使用它。
* **`NumPyConfigToolDependency`：** 专门用于查找和配置 `NumPy` 库的依赖项。`NumPy` 是 Python 中用于科学计算的基础库，Frida 的一些组件或扩展可能需要它。

**4. 提供依赖查找的策略和回退机制：**

* **定义依赖查找方法：** 通过 `DependencyMethods` 枚举定义了不同的依赖查找方法，例如 `PKGCONFIG`、`SYSTEM`、`EXTRAFRAMEWORK` 和 `CONFIG_TOOL`。
* **`python_factory` 函数：**  这是一个工厂函数，根据配置的查找方法，尝试不同的策略来找到合适的 Python 依赖项。它会优先尝试 `pkg-config`，然后是系统库，最后是 Framework (在 macOS 上)。

**与逆向方法的关系及举例说明：**

这个文件直接支持 Frida 这样的逆向工具的构建。Frida 需要与目标进程中的 Python 解释器进行交互，才能实现动态 instrumentation。

* **查找目标进程的 Python 解释器：**  虽然这个文件主要处理 Frida 构建时的 Python 依赖，但它体现了查找 Python 解释器的能力。在 Frida 的运行时组件中，也需要类似的逻辑来找到目标进程使用的 Python 解释器。
* **构建 native 扩展模块：** Frida 的核心功能和一些扩展通常是用 C/C++ 编写的，并编译成 Python 的 native 扩展模块。这个文件生成的编译和链接参数对于构建这些扩展至关重要。
    * **举例：** 假设 Frida 的一个模块需要调用目标进程中 Python 的某个 C API。在编译这个模块时，就需要使用 Python 的头文件 (`Python.h`) 和链接 Python 的库文件 (`libpython3.x.so`)。这个文件就负责找到这些文件，并提供给编译器和链接器。

**涉及到二进制底层，Linux, Android内核及框架的知识及举例说明：**

* **二进制底层：**
    * **链接库 (Linking):** 这个文件生成的链接参数直接关系到最终生成的可执行文件或共享库的二进制结构，确保程序运行时能正确找到 Python 的库文件。
    * **ABI (Application Binary Interface):**  代码中会考虑 Python 的 ABI 兼容性问题，例如通过 `ABIFLAGS` 变量来处理不同的 Python 构建。
* **Linux：**
    * **共享库查找：** 在 Linux 上，`pkg-config` 是一个标准的工具，用于查找共享库的编译和链接参数。这个文件使用了 `PkgConfigDependency` 来利用 `pkg-config` 查找 Python 依赖。
    * **系统库路径：**  `PythonSystemDependency` 会搜索 Linux 系统中标准的 Python 库路径。
* **Android 内核及框架：**
    * **交叉编译：**  虽然代码中没有显式处理 Android 特有的逻辑，但 Frida 作为一个跨平台工具，其构建系统需要支持 Android 平台的交叉编译。这个文件在查找 Python 依赖时，需要考虑到目标平台 (Android) 的 Python 环境，这可能与主机环境不同。
    * **Android NDK：** 如果 Frida 的某些组件需要在 Android 上运行，并且使用了 Python 的 native 扩展，那么构建过程可能需要使用 Android NDK (Native Development Kit)。这个文件在生成编译参数时，需要适配 NDK 提供的 Python 环境。

**逻辑推理及假设输入与输出：**

* **假设输入：**  Meson 构建系统尝试查找名为 `python3` 的依赖项，并且用户没有明确指定 Python 解释器的路径。
* **逻辑推理：**
    1. `python_factory` 函数被调用。
    2. 根据默认的查找方法，它会先尝试 `PKGCONFIG`。
    3. 如果系统中安装了 Python，并且配置了 `pkg-config` 文件 (例如 `python3.pc`)，`PythonPkgConfigDependency` 会尝试解析这个文件。
    4. 如果 `pkg-config` 找不到，或者没有安装 `pkg-config` 文件，`python_factory` 会回退到 `SYSTEM` 方法。
    5. `PythonSystemDependency` 会尝试直接执行 `python3` 命令，并运行 `python_info.py` 来获取信息。
    6. 它会根据获取的信息，推断出 Python 的头文件路径、库文件路径以及需要的编译和链接参数。
* **假设输出：**
    * **成功找到 Python:**  `PythonSystemDependency` 实例的 `is_found` 属性为 `True`，并且其 `compile_args` 和 `link_args` 属性包含了正确的编译和链接参数。
    * **未找到 Python:** `PythonSystemDependency` 实例的 `is_found` 属性为 `False`，Meson 构建系统会报告找不到 Python 依赖项的错误。

**用户或编程常见的使用错误及举例说明：**

* **未安装 Python 或 Python 不在 PATH 环境变量中：**  如果系统上没有安装 Python 3，或者 `python3` 命令不在系统的 PATH 环境变量中，`BasicPythonExternalProgram` 的 `sanity()` 方法会失败，导致后续的依赖查找失败。
    * **错误示例：**  用户在没有安装 Python 3 的系统上尝试构建 Frida，Meson 会报错找不到 Python 解释器。
* **错误的 `pkg-config` 配置：** 如果 Python 的 `pkg-config` 文件 (`python3.pc`) 配置错误，例如指向了错误的头文件或库文件路径，`PythonPkgConfigDependency` 可能会生成错误的编译或链接参数。
    * **错误示例：** 用户手动修改了 Python 的安装路径，但 `pkg-config` 文件没有同步更新，导致构建失败。
* **在 Windows 上混合使用不同架构的 Python 和构建工具：**  在 Windows 上，Python 有 32 位和 64 位版本。如果构建工具 (例如 Visual Studio) 的架构与 Python 的架构不匹配，链接过程会失败。代码中的 `find_libpy_windows` 函数会尝试检测这种不匹配。
    * **错误示例：** 用户使用 64 位的 Visual Studio 尝试链接 32 位的 Python 库，会导致链接错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida：** 用户通常会下载 Frida 的源代码，并使用 Meson 构建系统进行配置和编译，命令类似于 `meson build` 或 `ninja`。
2. **Meson 解析 `meson.build` 文件：** Meson 会读取项目根目录下的 `meson.build` 文件，以及子目录中的 `meson.build` 文件，这些文件描述了项目的构建规则和依赖项。
3. **声明 Python 依赖：**  在 Frida 的某个 `meson.build` 文件中，会声明对 Python 的依赖，可能类似于 `python3 = dependency('python3')`。
4. **调用依赖查找机制：** 当 Meson 处理到这个依赖声明时，会调用相应的依赖查找机制。对于名为 `python3` 的依赖，Meson 会找到并调用 `packages['python3']` 对应的工厂函数，也就是 `python_factory`。
5. **`python_factory` 执行：** `python_factory` 函数会根据配置的查找方法，创建并尝试不同的 Python 依赖项对象 (例如 `PythonPkgConfigDependency` 或 `PythonSystemDependency`)。
6. **`BasicPythonExternalProgram` 的执行：** 在查找 Python 解释器时，会创建 `BasicPythonExternalProgram` 实例，并调用其 `sanity()` 方法来执行 `python3` 和 `python_info.py` 脚本。
7. **错误或成功：** 如果找到合适的 Python 依赖项，Meson 会继续进行后续的构建步骤。如果找不到，Meson 会报错，提示用户缺少 Python 依赖或配置错误。

**作为调试线索：**

* **构建日志：**  查看 Meson 的构建日志，可以了解 Meson 尝试了哪些查找方法，以及执行 `python3` 和 `python_info.py` 的结果。
* **环境变量：**  检查相关的环境变量，例如 `PATH`、`PKG_CONFIG_PATH`、`PKG_CONFIG_LIBDIR`，这些环境变量会影响依赖查找的结果。
* **Python 安装：**  确认系统是否安装了 Python 3，并且可以从命令行执行 `python3` 命令。
* **`pkg-config` 配置：**  如果怀疑 `pkg-config` 有问题，可以尝试手动执行 `pkg-config --cflags python3` 和 `pkg-config --libs python3` 命令来查看其输出。
* **指定的 Python 解释器：**  如果用户通过 Meson 的配置选项指定了特定的 Python 解释器，需要检查该解释器是否有效。

总而言之，`frida/releng/meson/mesonbuild/dependencies/python.py` 文件在 Frida 的构建过程中扮演着关键角色，负责查找和配置 Python 依赖项，确保 Frida 的 native 扩展模块能够正确编译和链接到 Python 解释器。 理解这个文件的功能有助于理解 Frida 的构建过程，并在遇到 Python 相关的构建问题时提供调试思路。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/dependencies/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 The Meson development team

from __future__ import annotations

import functools, json, os, textwrap
from pathlib import Path
import typing as T

from .. import mesonlib, mlog
from .base import process_method_kw, DependencyException, DependencyMethods, DependencyTypeName, ExternalDependency, SystemDependency
from .configtool import ConfigToolDependency
from .detect import packages
from .factory import DependencyFactory
from .framework import ExtraFrameworkDependency
from .pkgconfig import PkgConfigDependency
from ..environment import detect_cpu_family
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from .factory import DependencyGenerator
    from ..environment import Environment
    from ..mesonlib import MachineChoice

    class PythonIntrospectionDict(TypedDict):

        install_paths: T.Dict[str, str]
        is_pypy: bool
        is_venv: bool
        link_libpython: bool
        sysconfig_paths: T.Dict[str, str]
        paths: T.Dict[str, str]
        platform: str
        suffix: str
        limited_api_suffix: str
        variables: T.Dict[str, str]
        version: str

    _Base = ExternalDependency
else:
    _Base = object


class Pybind11ConfigToolDependency(ConfigToolDependency):

    tools = ['pybind11-config']

    # any version of the tool is valid, since this is header-only
    allow_default_for_cross = True

    # pybind11 in 2.10.4 added --version, sanity-check another flag unique to it
    # in the meantime
    skip_version = '--pkgconfigdir'

    def __init__(self, name: str, environment: Environment, kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--includes'], 'compile_args')


class NumPyConfigToolDependency(ConfigToolDependency):

    tools = ['numpy-config']

    def __init__(self, name: str, environment: Environment, kwargs: T.Dict[str, T.Any]):
        super().__init__(name, environment, kwargs)
        if not self.is_found:
            return
        self.compile_args = self.get_config_value(['--cflags'], 'compile_args')


class BasicPythonExternalProgram(ExternalProgram):
    def __init__(self, name: str, command: T.Optional[T.List[str]] = None,
                 ext_prog: T.Optional[ExternalProgram] = None):
        if ext_prog is None:
            super().__init__(name, command=command, silent=True)
        else:
            self.name = name
            self.command = ext_prog.command
            self.path = ext_prog.path
            self.cached_version = None

        # We want strong key values, so we always populate this with bogus data.
        # Otherwise to make the type checkers happy we'd have to do .get() for
        # everycall, even though we know that the introspection data will be
        # complete
        self.info: 'PythonIntrospectionDict' = {
            'install_paths': {},
            'is_pypy': False,
            'is_venv': False,
            'link_libpython': False,
            'sysconfig_paths': {},
            'paths': {},
            'platform': 'sentinel',
            'suffix': 'sentinel',
            'limited_api_suffix': 'sentinel',
            'variables': {},
            'version': '0.0',
        }
        self.pure: bool = True

    def _check_version(self, version: str) -> bool:
        if self.name == 'python2':
            return mesonlib.version_compare(version, '< 3.0')
        elif self.name == 'python3':
            return mesonlib.version_compare(version, '>= 3.0')
        return True

    def sanity(self) -> bool:
        # Sanity check, we expect to have something that at least quacks in tune

        import importlib.resources

        with importlib.resources.path('mesonbuild.scripts', 'python_info.py') as f:
            cmd = self.get_command() + [str(f)]
            env = os.environ.copy()
            env['SETUPTOOLS_USE_DISTUTILS'] = 'stdlib'
            p, stdout, stderr = mesonlib.Popen_safe(cmd, env=env)

        try:
            info = json.loads(stdout)
        except json.JSONDecodeError:
            info = None
            mlog.debug('Could not introspect Python (%s): exit code %d' % (str(p.args), p.returncode))
            mlog.debug('Program stdout:\n')
            mlog.debug(stdout)
            mlog.debug('Program stderr:\n')
            mlog.debug(stderr)

        if info is not None and self._check_version(info['version']):
            self.info = T.cast('PythonIntrospectionDict', info)
            return True
        else:
            return False


class _PythonDependencyBase(_Base):

    def __init__(self, python_holder: 'BasicPythonExternalProgram', embed: bool):
        self.embed = embed
        self.version: str = python_holder.info['version']
        self.platform = python_holder.info['platform']
        self.variables = python_holder.info['variables']
        self.paths = python_holder.info['paths']
        self.is_pypy = python_holder.info['is_pypy']
        # The "-embed" version of python.pc / python-config was introduced in 3.8,
        # and distutils extension linking was changed to be considered a non embed
        # usage. Before then, this dependency always uses the embed=True handling
        # because that is the only one that exists.
        #
        # On macOS and some Linux distros (Debian) distutils doesn't link extensions
        # against libpython, even on 3.7 and below. We call into distutils and
        # mirror its behavior. See https://github.com/mesonbuild/meson/issues/4117
        self.link_libpython = python_holder.info['link_libpython'] or embed
        self.info: T.Optional[T.Dict[str, str]] = None
        if mesonlib.version_compare(self.version, '>= 3.0'):
            self.major_version = 3
        else:
            self.major_version = 2


class PythonPkgConfigDependency(PkgConfigDependency, _PythonDependencyBase):

    def __init__(self, name: str, environment: 'Environment',
                 kwargs: T.Dict[str, T.Any], installation: 'BasicPythonExternalProgram',
                 libpc: bool = False):
        if libpc:
            mlog.debug(f'Searching for {name!r} via pkgconfig lookup in LIBPC')
        else:
            mlog.debug(f'Searching for {name!r} via fallback pkgconfig lookup in default paths')

        PkgConfigDependency.__init__(self, name, environment, kwargs)
        _PythonDependencyBase.__init__(self, installation, kwargs.get('embed', False))

        if libpc and not self.is_found:
            mlog.debug(f'"python-{self.version}" could not be found in LIBPC, this is likely due to a relocated python installation')

        # pkg-config files are usually accurate starting with python 3.8
        if not self.link_libpython and mesonlib.version_compare(self.version, '< 3.8'):
            self.link_args = []


class PythonFrameworkDependency(ExtraFrameworkDependency, _PythonDependencyBase):

    def __init__(self, name: str, environment: 'Environment',
                 kwargs: T.Dict[str, T.Any], installation: 'BasicPythonExternalProgram'):
        ExtraFrameworkDependency.__init__(self, name, environment, kwargs)
        _PythonDependencyBase.__init__(self, installation, kwargs.get('embed', False))


class PythonSystemDependency(SystemDependency, _PythonDependencyBase):

    def __init__(self, name: str, environment: 'Environment',
                 kwargs: T.Dict[str, T.Any], installation: 'BasicPythonExternalProgram'):
        SystemDependency.__init__(self, name, environment, kwargs)
        _PythonDependencyBase.__init__(self, installation, kwargs.get('embed', False))

        # match pkg-config behavior
        if self.link_libpython:
            # link args
            if mesonlib.is_windows():
                self.find_libpy_windows(environment, limited_api=False)
            else:
                self.find_libpy(environment)
        else:
            self.is_found = True

        # compile args
        inc_paths = mesonlib.OrderedSet([
            self.variables.get('INCLUDEPY'),
            self.paths.get('include'),
            self.paths.get('platinclude')])

        self.compile_args += ['-I' + path for path in inc_paths if path]

        # https://sourceforge.net/p/mingw-w64/mailman/message/30504611/
        # https://github.com/python/cpython/pull/100137
        if mesonlib.is_windows() and self.get_windows_python_arch().endswith('64') and mesonlib.version_compare(self.version, '<3.12'):
            self.compile_args += ['-DMS_WIN64=']

        if not self.clib_compiler.has_header('Python.h', '', environment, extra_args=self.compile_args):
            self.is_found = False

    def find_libpy(self, environment: 'Environment') -> None:
        if self.is_pypy:
            if self.major_version == 3:
                libname = 'pypy3-c'
            else:
                libname = 'pypy-c'
            libdir = os.path.join(self.variables.get('base'), 'bin')
            libdirs = [libdir]
        else:
            libname = f'python{self.version}'
            if 'DEBUG_EXT' in self.variables:
                libname += self.variables['DEBUG_EXT']
            if 'ABIFLAGS' in self.variables:
                libname += self.variables['ABIFLAGS']
            libdirs = []

        largs = self.clib_compiler.find_library(libname, environment, libdirs)
        if largs is not None:
            self.link_args = largs
            self.is_found = True

    def get_windows_python_arch(self) -> str:
        if self.platform.startswith('mingw'):
            if 'x86_64' in self.platform:
                return 'x86_64'
            elif 'i686' in self.platform:
                return 'x86'
            elif 'aarch64' in self.platform:
                return 'aarch64'
            else:
                raise DependencyException(f'MinGW Python built with unknown platform {self.platform!r}, please file a bug')
        elif self.platform == 'win32':
            return 'x86'
        elif self.platform in {'win64', 'win-amd64'}:
            return 'x86_64'
        elif self.platform in {'win-arm64'}:
            return 'aarch64'
        raise DependencyException('Unknown Windows Python platform {self.platform!r}')

    def get_windows_link_args(self, limited_api: bool) -> T.Optional[T.List[str]]:
        if self.platform.startswith('win'):
            vernum = self.variables.get('py_version_nodot')
            verdot = self.variables.get('py_version_short')
            imp_lower = self.variables.get('implementation_lower', 'python')
            if self.static:
                libpath = Path('libs') / f'libpython{vernum}.a'
            else:
                comp = self.get_compiler()
                if comp.id == "gcc":
                    if imp_lower == 'pypy' and verdot == '3.8':
                        # The naming changed between 3.8 and 3.9
                        libpath = Path('libpypy3-c.dll')
                    elif imp_lower == 'pypy':
                        libpath = Path(f'libpypy{verdot}-c.dll')
                    else:
                        libpath = Path(f'python{vernum}.dll')
                else:
                    if limited_api:
                        vernum = vernum[0]
                    libpath = Path('libs') / f'python{vernum}.lib'
                    # For a debug build, pyconfig.h may force linking with
                    # pythonX_d.lib (see meson#10776). This cannot be avoided
                    # and won't work unless we also have a debug build of
                    # Python itself (except with pybind11, which has an ugly
                    # hack to work around this) - so emit a warning to explain
                    # the cause of the expected link error.
                    buildtype = self.env.coredata.get_option(mesonlib.OptionKey('buildtype'))
                    assert isinstance(buildtype, str)
                    debug = self.env.coredata.get_option(mesonlib.OptionKey('debug'))
                    # `debugoptimized` buildtype may not set debug=True currently, see gh-11645
                    is_debug_build = debug or buildtype == 'debug'
                    vscrt_debug = False
                    if mesonlib.OptionKey('b_vscrt') in self.env.coredata.options:
                        vscrt = self.env.coredata.options[mesonlib.OptionKey('b_vscrt')].value
                        if vscrt in {'mdd', 'mtd', 'from_buildtype', 'static_from_buildtype'}:
                            vscrt_debug = True
                    if is_debug_build and vscrt_debug and not self.variables.get('Py_DEBUG'):
                        mlog.warning(textwrap.dedent('''\
                            Using a debug build type with MSVC or an MSVC-compatible compiler
                            when the Python interpreter is not also a debug build will almost
                            certainly result in a failed build. Prefer using a release build
                            type or a debug Python interpreter.
                            '''))
            # base_prefix to allow for virtualenvs.
            lib = Path(self.variables.get('base_prefix')) / libpath
        elif self.platform.startswith('mingw'):
            if self.static:
                libname = self.variables.get('LIBRARY')
            else:
                libname = self.variables.get('LDLIBRARY')
            lib = Path(self.variables.get('LIBDIR')) / libname
        else:
            raise mesonlib.MesonBugException(
                'On a Windows path, but the OS doesn\'t appear to be Windows or MinGW.')
        if not lib.exists():
            mlog.log('Could not find Python3 library {!r}'.format(str(lib)))
            return None
        return [str(lib)]

    def find_libpy_windows(self, env: 'Environment', limited_api: bool = False) -> None:
        '''
        Find python3 libraries on Windows and also verify that the arch matches
        what we are building for.
        '''
        try:
            pyarch = self.get_windows_python_arch()
        except DependencyException as e:
            mlog.log(str(e))
            self.is_found = False
            return
        arch = detect_cpu_family(env.coredata.compilers.host)
        if arch != pyarch:
            mlog.log('Need', mlog.bold(self.name), f'for {arch}, but found {pyarch}')
            self.is_found = False
            return
        # This can fail if the library is not found
        largs = self.get_windows_link_args(limited_api)
        if largs is None:
            self.is_found = False
            return
        self.link_args = largs
        self.is_found = True

    @staticmethod
    def log_tried() -> str:
        return 'sysconfig'

def python_factory(env: 'Environment', for_machine: 'MachineChoice',
                   kwargs: T.Dict[str, T.Any],
                   installation: T.Optional['BasicPythonExternalProgram'] = None) -> T.List['DependencyGenerator']:
    # We can't use the factory_methods decorator here, as we need to pass the
    # extra installation argument
    methods = process_method_kw({DependencyMethods.PKGCONFIG, DependencyMethods.SYSTEM}, kwargs)
    embed = kwargs.get('embed', False)
    candidates: T.List['DependencyGenerator'] = []
    from_installation = installation is not None
    # When not invoked through the python module, default installation.
    if installation is None:
        installation = BasicPythonExternalProgram('python3', mesonlib.python_command)
        installation.sanity()
    pkg_version = installation.info['variables'].get('LDVERSION') or installation.info['version']

    if DependencyMethods.PKGCONFIG in methods:
        if from_installation:
            pkg_libdir = installation.info['variables'].get('LIBPC')
            pkg_embed = '-embed' if embed and mesonlib.version_compare(installation.info['version'], '>=3.8') else ''
            pkg_name = f'python-{pkg_version}{pkg_embed}'

            # If python-X.Y.pc exists in LIBPC, we will try to use it
            def wrap_in_pythons_pc_dir(name: str, env: 'Environment', kwargs: T.Dict[str, T.Any],
                                       installation: 'BasicPythonExternalProgram') -> 'ExternalDependency':
                if not pkg_libdir:
                    # there is no LIBPC, so we can't search in it
                    empty = ExternalDependency(DependencyTypeName('pkgconfig'), env, {})
                    empty.name = 'python'
                    return empty

                old_pkg_libdir = os.environ.pop('PKG_CONFIG_LIBDIR', None)
                old_pkg_path = os.environ.pop('PKG_CONFIG_PATH', None)
                os.environ['PKG_CONFIG_LIBDIR'] = pkg_libdir
                try:
                    return PythonPkgConfigDependency(name, env, kwargs, installation, True)
                finally:
                    def set_env(name: str, value: str) -> None:
                        if value is not None:
                            os.environ[name] = value
                        elif name in os.environ:
                            del os.environ[name]
                    set_env('PKG_CONFIG_LIBDIR', old_pkg_libdir)
                    set_env('PKG_CONFIG_PATH', old_pkg_path)

            candidates.append(functools.partial(wrap_in_pythons_pc_dir, pkg_name, env, kwargs, installation))
            # We only need to check both, if a python install has a LIBPC. It might point to the wrong location,
            # e.g. relocated / cross compilation, but the presence of LIBPC indicates we should definitely look for something.
            if pkg_libdir is not None:
                candidates.append(functools.partial(PythonPkgConfigDependency, pkg_name, env, kwargs, installation))
        else:
            candidates.append(functools.partial(PkgConfigDependency, 'python3', env, kwargs))

    if DependencyMethods.SYSTEM in methods:
        candidates.append(functools.partial(PythonSystemDependency, 'python', env, kwargs, installation))

    if DependencyMethods.EXTRAFRAMEWORK in methods:
        nkwargs = kwargs.copy()
        if mesonlib.version_compare(pkg_version, '>= 3'):
            # There is a python in /System/Library/Frameworks, but that's python 2.x,
            # Python 3 will always be in /Library
            nkwargs['paths'] = ['/Library/Frameworks']
        candidates.append(functools.partial(PythonFrameworkDependency, 'Python', env, nkwargs, installation))

    return candidates

packages['python3'] = python_factory

packages['pybind11'] = pybind11_factory = DependencyFactory(
    'pybind11',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL, DependencyMethods.CMAKE],
    configtool_class=Pybind11ConfigToolDependency,
)

packages['numpy'] = numpy_factory = DependencyFactory(
    'numpy',
    [DependencyMethods.PKGCONFIG, DependencyMethods.CONFIG_TOOL],
    configtool_class=NumPyConfigToolDependency,
)
```