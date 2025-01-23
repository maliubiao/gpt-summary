Response:
Let's break down the thought process to analyze this Python code.

**1. Understanding the Goal:**

The request asks for a functional breakdown of a Python file within the Frida project, specifically concerning Python dependency management. It also probes for connections to reverse engineering, low-level details, logical reasoning, user errors, and debugging.

**2. Initial Scan and Keyword Spotting:**

I first skimmed the code, looking for recognizable keywords and patterns. "Dependency," "Python," "pkgconfig," "system," "framework," "compile_args," "link_args," "version," "introspection," "Windows," "Linux," and "Android" jumped out. This immediately suggested the file deals with finding and configuring Python installations needed by Frida's build process.

**3. Core Functionality Identification:**

I started grouping related code blocks:

* **Dependency Classes:**  `Pybind11ConfigToolDependency`, `NumPyConfigToolDependency`, `PythonPkgConfigDependency`, `PythonFrameworkDependency`, `PythonSystemDependency`. These clearly represent different ways of finding Python and related libraries. The inheritance structure (`_PythonDependencyBase`) hints at shared logic.
* **Python Introspection:** The `BasicPythonExternalProgram` class and its `sanity` method stood out. The use of `importlib.resources` and `json.loads` suggested a mechanism to get detailed information about a Python installation by running a separate script.
* **Dependency Factory:** The `python_factory` function is crucial. It orchestrates the different methods for finding Python based on user-specified preferences.
* **Platform-Specific Logic:**  Sections dealing with Windows (`find_libpy_windows`, `get_windows_link_args`, `get_windows_python_arch`) and mentions of Linux and Android implied platform-specific handling.
* **External Tools:** References to `pybind11-config` and `numpy-config` indicated the use of external tools for certain Python packages.

**4. Analyzing Individual Components:**

I then examined each identified component in more detail:

* **`BasicPythonExternalProgram`:**  The core idea here is to execute the Python interpreter with a special script (`python_info.py`) to gather crucial details like version, paths, and platform information. This is *introspection*.
* **Dependency Classes:** Each class represents a distinct strategy for finding Python dependencies:
    * `ConfigToolDependency` (and subclasses): Uses tools like `pybind11-config` and `numpy-config`.
    * `PkgConfigDependency`: Relies on `.pc` files.
    * `SystemDependency`: Searches in standard system locations.
    * `FrameworkDependency`:  Specific to macOS.
    The `_PythonDependencyBase` class holds common attributes like version and platform. The `embed` flag suggests handling embedded Python scenarios.
* **`python_factory`:** This function embodies the logic of trying different dependency discovery methods. The order of trying `PKGCONFIG` and `SYSTEM` is significant. The handling of `installation` argument allows specifying a particular Python interpreter.
* **Platform Logic:** The Windows-specific functions focus on finding the correct Python library (`.lib` or `.dll`) and ensuring architecture compatibility. The MinGW handling is also specific.

**5. Connecting to the Request's Specific Points:**

Now, I explicitly addressed the prompts:

* **Functionality:** Summarized the core task as finding and providing information about Python dependencies.
* **Reverse Engineering:**  Linked it to analyzing and manipulating Python-based applications or libraries, highlighting the importance of understanding the target's Python environment.
* **Binary/Low-Level/Kernel/Framework:**  Identified the aspects related to finding and linking against Python libraries (DLLs/shared objects), and the platform-specific checks. The mention of Android NDK and the need for correct Python builds for Android was a key connection.
* **Logical Reasoning:** Focused on the `python_factory` function's decision-making process—trying different methods in a specific order based on availability and user preferences.
* **User Errors:**  Brainstormed common mistakes, like having the wrong Python version or architecture, not having necessary development packages, or issues with virtual environments.
* **User Operations/Debugging:**  Traced back the steps that would lead to this code being executed within the Meson build system, emphasizing its role in resolving dependencies.

**6. Structuring the Output:**

Finally, I organized the information logically, using headings and bullet points for clarity. I provided concrete examples to illustrate the concepts. I aimed for a balance between technical detail and understandable explanations.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the individual classes without clearly explaining their combined purpose. I then realized the importance of highlighting the `python_factory` as the central orchestrator.
* I made sure to explicitly connect the code to the Frida project's context as a dynamic instrumentation tool.
* I double-checked the code comments and variable names to ensure my explanations were accurate. For example, the `embed` parameter and its implications became clearer upon closer inspection.
* I tried to anticipate potential follow-up questions by providing details about different dependency resolution strategies.

By following this structured thought process, I could effectively analyze the code and provide a comprehensive answer addressing all aspects of the request.
这是 frida 动态 instrumentation 工具中负责处理 Python 依赖项的源代码文件。它属于 Meson 构建系统的配置部分，具体负责在构建 frida-swift 组件时，查找和配置所需的 Python 环境和相关库。

以下是该文件的功能列表，并根据要求进行详细说明：

**功能列表：**

1. **查找 Python 解释器:**  该文件定义了 `BasicPythonExternalProgram` 类，用于查找系统中的 Python 解释器（python2 或 python3）。它会执行 Python 解释器并运行一个脚本来获取 Python 的详细信息，例如版本、安装路径、平台信息等。

2. **定义不同类型的 Python 依赖:** 文件中定义了多种处理 Python 依赖的方式，包括：
    * **`PythonPkgConfigDependency`:** 使用 `pkg-config` 工具查找 Python 依赖项的配置信息（如编译选项、链接库）。
    * **`PythonFrameworkDependency`:**  在 macOS 系统上，将 Python 依赖项视为 Framework 进行查找。
    * **`PythonSystemDependency`:**  在系统标准路径中查找 Python 依赖项。
    * **`Pybind11ConfigToolDependency` 和 `NumPyConfigToolDependency`:**  专门用于查找 `pybind11` 和 `numpy` 这两个 Python 包的配置信息，它们使用各自的配置工具 (`pybind11-config` 和 `numpy-config`)。

3. **提供 Python 依赖信息:**  每个依赖类在找到 Python 后，会提取并存储编译参数 (`compile_args`) 和链接参数 (`link_args`)，这些参数将用于编译和链接 frida-swift 的代码。

4. **处理嵌入式 Python:**  该文件考虑了嵌入式 Python 的情况 (`embed=True` 参数)，并能据此调整依赖查找和链接策略。

5. **平台特定的处理:**  文件中包含针对 Windows 平台的特殊处理，例如查找 Python 库 (`.lib` 或 `.dll`) 的方法 (`find_libpy_windows`)，以及获取 Windows Python 架构信息 (`get_windows_python_arch`)。

6. **提供依赖查找的工厂方法:**  `python_factory` 函数是一个工厂方法，根据用户提供的参数 (`kwargs`) 和系统环境，决定使用哪种方法来查找 Python 依赖项。它会尝试不同的策略 (pkg-config, system, framework) 来定位合适的 Python。

7. **`pybind11` 和 `numpy` 的特殊处理:**  文件中定义了专门的 `DependencyFactory` 用于 `pybind11` 和 `numpy`，表明这两个库在 frida-swift 的构建中扮演着重要角色。

**与逆向方法的关联及举例：**

* **动态库加载和符号解析:**  在逆向分析中，我们经常需要理解目标程序依赖的动态库以及这些库中的符号。该文件负责查找 Python 的动态库 (`.so` 在 Linux 上, `.dll` 在 Windows 上, `.dylib` 在 macOS 上)。例如，如果 frida-swift 需要调用 Python C API，它就需要链接到 Python 的动态库。`PythonSystemDependency` 类中的 `find_libpy` 和 `find_libpy_windows` 方法就体现了这一点，它们尝试找到 Python 的共享库。

   **举例:**  假设目标 Android 应用使用了 frida-swift 来进行 hook。为了让 hook 代码能够与 Python 运行时交互，frida-swift 需要找到设备上的 `libpython.so` (或其他平台对应的 Python 共享库)。这个文件就负责配置 frida-swift 在编译时如何链接到这个库。

* **理解目标程序的依赖:**  逆向工程师常常需要分析目标程序的依赖关系，以理解其工作原理和潜在的注入点。这个文件揭示了 frida-swift 对 Python 的依赖，以及查找这些依赖的不同方法。这有助于逆向工程师理解 frida-swift 的构建过程和运行环境需求。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

* **二进制链接:** `PythonSystemDependency` 类中的 `find_libpy` 方法涉及到在 Linux 系统上查找 Python 的共享库。这需要了解 Linux 下动态链接的机制，例如库的搜索路径、`.so` 文件的命名规则等。

   **举例:**  在 Linux 上，`find_libpy` 方法会尝试查找名为 `libpythonX.Y.so` 的文件，其中 `X.Y` 是 Python 的版本号。这需要理解 Linux 动态链接器如何根据库名查找对应的二进制文件。

* **Windows 平台 DLL 加载:** `PythonSystemDependency` 类中的 `find_libpy_windows` 和 `get_windows_link_args` 方法处理 Windows 平台上的 Python 库查找，涉及对 DLL 文件、`.lib` 导入库的理解。

   **举例:**  在 Windows 上，`get_windows_link_args` 可能会找到 `python3XX.dll` 和 `python3XX.lib` 文件。逆向工程师需要理解 `.dll` 是实际的动态链接库，而 `.lib` 是用于链接时提供符号信息的导入库。

* **Android NDK 构建:** 虽然该文件本身没有直接涉及 Android 内核，但 frida 作为跨平台工具，其 Android 部分的构建肯定会用到 Android NDK。该文件在配置 Python 依赖时，需要确保找到的 Python 库是与 Android 平台的架构兼容的。

   **举例:**  在为 Android 构建 frida-swift 时，可能需要使用针对特定架构（如 ARM、ARM64）编译的 Python 库。这个文件在实际运行时，需要确保找到的 Python 库与目标 Android 设备的 CPU 架构匹配。

* **macOS Framework:** `PythonFrameworkDependency` 类体现了对 macOS 系统特性的理解，Python 可以作为 Framework 进行安装和链接。

   **举例:** 在 macOS 上，Python 库可能位于 `/Library/Frameworks/Python.framework` 目录下。该类会查找这个目录以找到 Python 的相关文件。

**逻辑推理及假设输入与输出：**

* **`python_factory` 的逻辑推理:**  `python_factory` 函数根据 `kwargs` 中指定的 `method` (例如 `pkgconfig`, `system`) 来决定尝试哪种依赖查找方式。如果用户指定了 `pkgconfig`，它会首先尝试使用 `PkgConfigDependency`。如果失败，并且 `system` 也被允许，则会尝试 `SystemDependency`。

   **假设输入:**  `kwargs = {'method': 'pkgconfig'}`，系统安装了 Python 3 并配置了 pkg-config。
   **预期输出:** `python_factory` 会返回一个列表，其中包含一个尝试使用 `PythonPkgConfigDependency` 的函数。这个函数在执行后，应该能够找到 Python 3 的配置信息，并返回一个表示 Python 依赖的对象。

   **假设输入:** `kwargs = {'method': 'system'}`，系统安装了 Python 3 但没有配置 pkg-config。
   **预期输出:** `python_factory` 会返回一个列表，其中包含一个尝试使用 `PythonSystemDependency` 的函数。这个函数在执行后，应该能够在系统的标准路径中找到 Python 3，并返回一个表示 Python 依赖的对象。

**涉及用户或编程常见的使用错误及举例：**

* **Python 版本不匹配:** 用户可能安装了错误的 Python 版本，导致构建过程找不到所需的 Python 库或头文件。

   **举例:**  如果 frida-swift 依赖 Python 3.7 或更高版本，而用户系统上只安装了 Python 2.7，该文件在查找 Python 时可能会找到错误的解释器，或者根本找不到，从而导致构建失败。Meson 会报错提示找不到 Python 或 Python 版本不符合要求。

* **缺少 Python 开发头文件:**  在 Linux 上，用户可能只安装了 Python 解释器，而没有安装 Python 的开发包 (例如 `python3-dev` 或 `python3-devel`)，这会导致找不到 `Python.h` 头文件。

   **举例:** `PythonSystemDependency` 类在初始化时会检查是否存在 `Python.h` 头文件。如果用户没有安装开发包，这个检查会失败，导致依赖查找失败。

* **虚拟环境问题:** 用户可能在一个 Python 虚拟环境中工作，但 Meson 构建系统可能没有正确激活该虚拟环境，导致找到的是系统级别的 Python 而不是虚拟环境中的 Python。

   **举例:**  如果用户在一个虚拟环境中安装了特定版本的 Python 包（如 `pybind11`），但构建系统找到了系统级别的 Python，那么 `Pybind11ConfigToolDependency` 可能会找不到虚拟环境中的 `pybind11-config` 工具。

* **Windows 平台架构不匹配:** 在 Windows 上，如果构建架构（例如 x64）与安装的 Python 解释器架构（例如 x86）不匹配，会导致链接错误。

   **举例:** `PythonSystemDependency` 中的 `get_windows_python_arch` 方法会尝试获取 Python 的架构，并与当前构建的架构进行比较。如果两者不匹配，Meson 会报错提示架构不兼容。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 frida-swift:** 用户通过某种方式（例如，运行 `meson build` 命令）启动 frida-swift 的构建过程。

2. **Meson 解析构建配置:** Meson 读取 frida-swift 的 `meson.build` 文件，其中会声明对 Python 的依赖。

3. **Meson 调用依赖查找机制:**  当 Meson 处理到 Python 依赖时，它会调用相应的 dependency factory，即 `frida/subprojects/frida-swift/releng/meson/mesonbuild/dependencies/python.py` 文件中的 `python_factory` 函数。

4. **`python_factory` 根据配置尝试查找 Python:** `python_factory` 会根据 `meson.build` 文件中的配置（或者默认配置）以及系统环境，尝试不同的方法来查找 Python 解释器和相关库。这可能包括：
   * 查找环境变量中指定的 Python 路径。
   * 运行 `pkg-config --modversion python3` 命令。
   * 在系统标准路径中搜索 `python3` 或 `python` 可执行文件。

5. **依赖类执行具体的查找操作:** 如果 `python_factory` 决定使用 `PythonSystemDependency`，那么该类的初始化方法会被调用，它会尝试运行 Python 解释器并执行脚本来获取信息，检查头文件是否存在，并尝试查找 Python 的共享库。

6. **记录查找结果和错误:** Meson 会记录依赖查找的结果，如果找到 Python，会提取其编译和链接参数。如果查找失败，Meson 会报错，指出缺少 Python 或版本不匹配等问题。

**作为调试线索:**

* **查看 Meson 的构建日志:**  Meson 的构建日志会详细记录依赖查找的过程，包括尝试了哪些方法，执行了哪些命令，以及是否成功找到依赖。这些日志可以帮助开发者理解为什么 Python 依赖查找失败。

* **检查 Meson 的配置选项:**  用户可以通过 Meson 的配置选项（例如 `-Dpython3_executable=/path/to/python3`）来显式指定 Python 解释器的路径。检查这些选项是否正确设置可以排除因 Python 路径错误导致的问题。

* **检查系统环境变量:**  某些依赖查找方法会依赖于特定的环境变量（例如 `PKG_CONFIG_PATH`）。检查这些环境变量是否正确配置可以帮助诊断 `pkg-config` 相关的问题。

* **手动执行查找命令:**  开发者可以手动执行 `pkg-config --modversion python3` 或 Python 解释器来验证系统上 Python 的状态，从而判断是否是 Python 安装本身的问题。

总之，这个 Python 文件是 frida-swift 构建过程中至关重要的一部分，它负责定位和配置 Python 依赖，确保 frida-swift 能够正确地与 Python 运行时环境进行交互。理解其功能和工作原理对于调试 frida-swift 的构建问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/dependencies/python.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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