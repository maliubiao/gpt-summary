Response:
Let's break down the thought process for analyzing this Python code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `hotdoc.py` file within the Frida project. The prompt specifically asks for connections to reverse engineering, low-level details (Linux, Android), logical reasoning, common user errors, and how a user might reach this code.

**2. Initial Skim and Keyword Spotting:**

I'd first quickly read through the code, looking for keywords and recognizable patterns. Things that immediately stand out are:

* **`hotdoc`**: This is clearly the central theme. I know (or would quickly research) that Hotdoc is a documentation generator.
* **`meson`**:  The file path (`frida/releng/meson/mesonbuild/modules/hotdoc.py`) and imports (`from .. import build, mesonlib`) strongly indicate this is a Meson build system module.
* **`CustomTarget`**: This is a key Meson concept for defining build steps outside the standard compiler/linker flow. It suggests Hotdoc integration is being treated as a custom build step.
* **`ExternalProgram`**: This confirms that the code interacts with the `hotdoc` executable.
* **`generate_doc`**: This is a crucial function name, suggesting the primary purpose of the module.
* **`dependencies`**, `include_paths`, `extra_assets`, `subprojects`: These keywords point to configuration options for the documentation generation process.
* **`install`**: This indicates integration with the installation process.
* **Error handling (`MesonException`, `InvalidArguments`)**: This highlights robustness and checks for incorrect usage.

**3. Deeper Dive - Function by Function (or Logical Block):**

Next, I'd go through the code more deliberately, examining each class and function:

* **`ensure_list`**: A utility function to ensure a value is a list. Simple but important for handling input.
* **`MIN_HOTDOC_VERSION`**: Defines the minimum supported Hotdoc version. This tells us about version compatibility.
* **`file_types`**: Restricts the types of arguments accepted for certain parameters.
* **`HotdocExternalProgram`**:  A wrapper around `subprocess` to execute the `hotdoc` command. This is the core interaction with the documentation tool. The `run_hotdoc` method is the key.
* **`HotdocTargetBuilder`**: This is the workhorse. It's responsible for taking user-provided arguments and constructing the command-line arguments for the `hotdoc` configuration step. I'd pay attention to how it handles different argument types (`str`, `File`, `CustomTarget`, etc.) and how it builds the `cmd` list. The `process_*` methods are crucial.
* **`HotdocTargetHolder`**:  A Meson concept for providing methods on the `HotdocTarget` object within the Meson build definition. The `config_path_method` is a specific example.
* **`HotdocTarget`**: Represents the documentation generation as a Meson custom target. It stores the configuration and dependencies.
* **`HotDocModule`**: This is the entry point of the Meson module. It initializes the `HotdocExternalProgram` and registers the `generate_doc` method. The version check is important. The `has_extensions` method is an interesting helper.
* **`generate_doc`**: This is the main function exposed to Meson build files. It instantiates `HotdocTargetBuilder` and orchestrates the documentation generation process. It defines the expected keyword arguments and their types.
* **`initialize`**: The standard function for Meson modules to register themselves.

**4. Connecting to the Prompt's Specific Questions:**

Now, with a solid understanding of the code, I can address the specific points in the prompt:

* **Functionality:**  Summarize the main purpose – generating documentation using Hotdoc. Highlight the configuration and build steps.
* **Reverse Engineering:**  Think about how documentation aids in RE. It provides insights into APIs, data structures, and program behavior. The example of understanding function parameters and return values is relevant.
* **Binary/Low-Level, Linux/Android Kernel/Framework:** While this module *itself* doesn't directly touch kernel code or binary manipulation, its *output* (the documentation) is crucial for understanding such systems. Emphasize how good documentation helps reverse engineers understand the low-level workings of Frida itself (which *does* interact with these levels).
* **Logical Reasoning (Input/Output):**  Focus on the `generate_doc` function and its arguments. Pick a few key arguments like `sitemap`, `index`, and `project_version`, and show how providing them leads to specific command-line arguments for Hotdoc.
* **User Errors:** Look for validation checks and potential misconfigurations. Incorrect file paths, wrong argument types, and missing dependencies are common errors. The `InvalidArguments` exceptions provide clues.
* **User Path to the Code (Debugging):**  Think about the steps a developer would take when using Frida and encountering issues with documentation generation. Starting with the Meson build system, defining the Hotdoc target, and then potentially needing to debug issues would lead them to this module.

**5. Structuring the Response:**

Organize the information clearly, using headings and bullet points. Start with a high-level summary and then delve into the specifics for each aspect of the prompt. Use code examples where appropriate to illustrate points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This module just runs Hotdoc."  **Correction:**  It's more than that. It *configures* Hotdoc with project-specific information, handles dependencies, and integrates it into the Meson build process.
* **Initial thought:** "The reverse engineering connection is weak." **Correction:** The *output* is key for RE, even if the module itself doesn't perform RE. Frame it that way.
* **Initial thought:** "Just list all the functions." **Correction:**  Group related functionalities and explain *why* they are there, not just *what* they do.

By following this structured analysis, breaking down the code, and connecting it back to the specific questions in the prompt, I can generate a comprehensive and informative response.
好的，让我们来详细分析一下 `frida/releng/meson/mesonbuild/modules/hotdoc.py` 这个 Frida 项目中用于集成 Hotdoc 文档生成工具的源代码文件。

**文件功能概述:**

这个 Python 模块的主要功能是为 Frida 项目提供一个接口，以便在 Meson 构建系统中方便地使用 Hotdoc 来生成项目文档。它定义了一系列函数和类，用于配置 Hotdoc 的运行，处理依赖关系，以及将生成的文档集成到构建和安装过程中。

**功能详细列表:**

1. **查找和验证 Hotdoc:**
   - `HotDocModule.__init__`:  初始化模块时，会查找系统上是否存在 `hotdoc` 可执行文件。
   - 如果找不到 `hotdoc`，会抛出 `MesonException` 异常。
   - 检查找到的 `hotdoc` 版本是否满足最低版本要求 (`MIN_HOTDOC_VERSION = '0.8.100'`)，如果不满足也会抛出异常。

2. **检查 Hotdoc 扩展:**
   - `HotDocModule.has_extensions`:  允许检查 Hotdoc 是否启用了特定的扩展。这通过运行 `hotdoc --has-extension=<extension_name>` 并检查返回码来实现。

3. **生成 Hotdoc 文档配置:**
   - `HotdocTargetBuilder`:  负责构建 Hotdoc 的配置。
   - 收集项目名称、输出目录等基本信息。
   - 处理各种用户提供的参数，例如：
     - `sitemap`, `index`:  指定 Hotdoc 的站点地图和首页文件。
     - `project_version`:  项目版本号。
     - `html_extra_theme`:  额外的 HTML 主题。
     - `include_paths`:  额外的头文件搜索路径。
     - `dependencies`:  项目依赖项，用于提取 C/C++ 头文件路径。
     - `depends`:  文档生成目标依赖的其他构建目标。
     - `gi_c_source_roots`:  GObject Introspection C 源码根目录。
     - `extra_assets`:  额外的静态资源文件。
     - `extra_extension_paths`:  额外的 Hotdoc 扩展路径。
     - `subprojects`:  依赖的其他 Hotdoc 文档生成目标。
     - `install`:  是否安装生成的文档。
   - 将配置参数转换为 `hotdoc conf` 命令的参数。
   - 生成 Hotdoc 的配置文件 (`<target_name>-doc.json`)。

4. **创建 Hotdoc 构建目标:**
   - `HotdocTarget`:  表示一个 Hotdoc 文档生成的目标，继承自 `CustomTarget`。
   - 定义了生成文档的命令：`hotdoc run --conf-file <config_file> --builddir <build_dir>`。
   - 管理文档生成目标的依赖关系。

5. **处理文档安装:**
   - 如果 `generate_doc` 中 `install` 参数为 `True`，则会创建一个安装脚本。
   - 安装脚本会将生成的 HTML 文档安装到指定目录（通常是 `${datadir}/doc/<project_name>/html`）。
   - 如果启用了 `devhelp_activate`，则会将 `devhelp` 格式的文档安装到 `${datadir}/devhelp`。

**与逆向方法的关系及举例:**

文档在逆向工程中扮演着重要的角色。良好的文档可以帮助逆向工程师理解目标软件的架构、API、数据结构和工作流程，从而提高逆向分析的效率和准确性。

* **理解 Frida 的内部结构和 API:**  Frida 作为一个动态插桩工具，拥有丰富的 API 供开发者使用。通过 Hotdoc 生成的文档，逆向工程师可以：
    - **查找函数和类的信息:** 了解 Frida 提供的各种函数的功能、参数和返回值，例如 `Interceptor.attach()`, `Memory.readByteArray()`, `NativePointer`.
    - **理解数据结构:**  了解 Frida 内部使用的数据结构，例如 `Module`, `Process`, `Thread` 的属性和关系。
    - **学习使用方法:**  通过文档中的示例代码和说明，学习如何使用 Frida 的 API 来实现特定的逆向任务，例如 hook 函数、修改内存、跟踪函数调用。

**二进制底层、Linux、Android 内核及框架的知识及举例:**

虽然这个模块本身是用 Python 编写的，但它生成的文档是关于 Frida 这个工具的，而 Frida 深入到二进制底层，并且在 Linux 和 Android 平台上有广泛的应用。

* **二进制底层知识:** Frida 能够操作进程的内存、修改指令、调用本地函数等，这些都涉及到对二进制代码和内存布局的理解。Hotdoc 生成的文档可以帮助用户理解 Frida 如何与这些底层机制交互。例如，文档可能会解释 `Memory` 模块如何读写进程内存，以及 `Interceptor` 如何修改函数的执行流程。
* **Linux 内核知识:** Frida 在 Linux 上运行时，会利用 Linux 内核提供的各种机制，例如 ptrace 系统调用。Frida 的文档可能会解释其内部实现如何利用这些内核特性来实现动态插桩。
* **Android 内核和框架知识:**  Frida 在 Android 平台上也广泛使用，可以用来分析 Android 应用和系统服务。文档可能会涉及到 Android 特有的概念，例如 ART 虚拟机、Zygote 进程、Binder 通信等，并解释 Frida 如何在这些环境中进行插桩。

**逻辑推理、假设输入与输出:**

假设用户在 `meson.build` 文件中调用了 `hotdoc.generate_doc` 函数，并提供了一些参数：

**假设输入:**

```python
hotdoc_module = import('hotdoc')
hotdoc_module.generate_doc(
  'MyProject',
  sitemap: files('sitemap.xml'),
  index: files('index.md'),
  project_version: '1.0.0',
  include_paths: ['include'],
  dependencies: [mylib],
)
```

其中 `mylib` 是一个通过 `declare_library()` 定义的库。

**逻辑推理:**

1. `HotDocModule.generate_doc` 函数会被调用。
2. `HotdocTargetBuilder` 会被创建，并传入项目名称 'MyProject' 和提供的参数。
3. `HotdocTargetBuilder` 会处理 `sitemap` 和 `index` 参数，将 `File` 对象转换为 Hotdoc 期望的格式。
4. `project_version` 参数会被直接传递给 Hotdoc。
5. `include_paths` 参数会被添加到 Hotdoc 的头文件搜索路径中。
6. `dependencies` 参数中的 `mylib` 会被分析，提取其包含的头文件路径，并添加到 Hotdoc 的 C/C++ 头文件搜索路径中。
7. `HotdocTargetBuilder` 会生成 Hotdoc 的配置文件，其中包含了上述配置信息。
8. 一个 `HotdocTarget` 构建目标会被创建，其命令会调用 `hotdoc run` 并指定生成的配置文件。

**可能的输出 (Hotdoc 配置文件片段):**

```json
{
  "project-name": "MyProject",
  "project-version": "1.0.0",
  "index": "index.md",
  "sitemap": "sitemap.xml",
  "include-path": [
    "include",
    "<mylib 的头文件路径1>",
    "<mylib 的头文件路径2>"
  ]
}
```

**用户或编程常见的使用错误及举例:**

1. **未安装 Hotdoc 或版本不兼容:** 如果系统上没有安装 `hotdoc` 或者安装的版本低于 `MIN_HOTDOC_VERSION`，Meson 构建会失败并提示错误信息。

   ```
   meson.build:XX:0: ERROR: hotdoc executable not found
   或
   meson.build:XX:0: ERROR: hotdoc 0.8.100 required but not found.)
   ```

2. **提供的文件路径错误:**  如果 `sitemap` 或 `index` 指定的文件不存在，Hotdoc 在运行时会报错。

   ```python
   hotdoc_module.generate_doc(
     'MyProject',
     sitemap: files('non_existent_sitemap.xml'), # 错误的文件名
     index: files('index.md'),
     project_version: '1.0.0',
   )
   ```

3. **依赖项未正确声明:** 如果文档中需要引用某个库的头文件，但该库没有作为 `dependencies` 传递给 `generate_doc`，Hotdoc 可能无法找到相应的头文件，导致文档生成错误。

4. **参数类型错误:**  `generate_doc` 函数对参数类型有严格的要求。如果传递了错误类型的参数，Meson 会在配置阶段报错。

   ```python
   hotdoc_module.generate_doc(
     'MyProject',
     sitemap: 'sitemap.xml', # 应该是 files() 对象
     index: files('index.md'),
     project_version: 1.0, # 应该是字符串
   )
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 项目开发者想要生成项目文档。**
2. **他们决定使用 Hotdoc 作为文档生成工具。**
3. **为了将 Hotdoc 集成到 Frida 的 Meson 构建系统中，他们需要在 `meson.build` 文件中调用 `hotdoc.generate_doc` 函数。**
4. **在编写 `meson.build` 文件时，开发者可能会参考 Frida 项目中已有的 `meson.build` 文件或者 Meson 官方文档中关于 Hotdoc 模块的使用说明。**
5. **如果在使用 `hotdoc.generate_doc` 时遇到了问题（例如文档生成失败、配置错误等），开发者可能会想要查看 `hotdoc.py` 的源代码来理解其内部实现和参数处理逻辑，以便找到问题的原因。**
6. **开发者可能会在 IDE 中打开 `frida/releng/meson/mesonbuild/modules/hotdoc.py` 文件，逐行阅读代码，查看函数的功能、参数的含义以及错误处理机制。**
7. **他们可能会在 `HotdocTargetBuilder` 类中查找关于特定参数的处理逻辑，例如 `dependencies` 或 `include_paths`，来确认这些参数是否被正确传递给 Hotdoc。**
8. **如果涉及到构建错误，开发者可能会检查 `generate_hotdoc_config` 函数，查看生成的 Hotdoc 配置文件是否符合预期。**
9. **如果涉及到安装错误，开发者可能会查看安装脚本的生成逻辑，确认安装路径是否正确。**

总而言之，开发者查看 `hotdoc.py` 源代码通常是为了调试文档生成过程中的问题，理解 Hotdoc 模块的具体实现，以及确认 `meson.build` 文件中的配置是否正确。这个文件是连接 Frida 项目构建系统和 Hotdoc 文档生成工具的关键桥梁。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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

'''This module provides helper functions for generating documentation using hotdoc'''

import os, subprocess
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleInfo
from .. import build, mesonlib, mlog
from ..build import CustomTarget, CustomTargetIndex
from ..dependencies import Dependency, InternalDependency
from ..interpreterbase import (
    InvalidArguments, noPosargs, noKwargs, typed_kwargs, FeatureDeprecated,
    ContainerTypeInfo, KwargInfo, typed_pos_args
)
from ..interpreter.interpreterobjects import _CustomTargetHolder
from ..interpreter.type_checking import NoneType
from ..mesonlib import File, MesonException
from ..programs import ExternalProgram

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from ..environment import Environment
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_kwargs, TYPE_var

    _T = T.TypeVar('_T')

    class GenerateDocKwargs(TypedDict):
        sitemap: T.Union[str, File, CustomTarget, CustomTargetIndex]
        index: T.Union[str, File, CustomTarget, CustomTargetIndex]
        project_version: str
        html_extra_theme: T.Optional[str]
        include_paths: T.List[str]
        dependencies: T.List[T.Union[Dependency, build.StaticLibrary, build.SharedLibrary, CustomTarget, CustomTargetIndex]]
        depends: T.List[T.Union[CustomTarget, CustomTargetIndex]]
        gi_c_source_roots: T.List[str]
        extra_assets: T.List[str]
        extra_extension_paths: T.List[str]
        subprojects: T.List['HotdocTarget']
        install: bool

def ensure_list(value: T.Union[_T, T.List[_T]]) -> T.List[_T]:
    if not isinstance(value, list):
        return [value]
    return value


MIN_HOTDOC_VERSION = '0.8.100'

file_types = (str, File, CustomTarget, CustomTargetIndex)


class HotdocExternalProgram(ExternalProgram):
    def run_hotdoc(self, cmd: T.List[str]) -> int:
        return subprocess.run(self.get_command() + cmd, stdout=subprocess.DEVNULL).returncode


class HotdocTargetBuilder:

    def __init__(self, name: str, state: ModuleState, hotdoc: HotdocExternalProgram, interpreter: Interpreter, kwargs):
        self.hotdoc = hotdoc
        self.build_by_default = kwargs.pop('build_by_default', False)
        self.kwargs = kwargs
        self.name = name
        self.state = state
        self.interpreter = interpreter
        self.include_paths: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()

        self.builddir = state.environment.get_build_dir()
        self.sourcedir = state.environment.get_source_dir()
        self.subdir = state.subdir
        self.build_command = state.environment.get_build_command()

        self.cmd: T.List[TYPE_var] = ['conf', '--project-name', name, "--disable-incremental-build",
                                      '--output', os.path.join(self.builddir, self.subdir, self.name + '-doc')]

        self._extra_extension_paths = set()
        self.extra_assets = set()
        self.extra_depends = []
        self._subprojects = []

    def process_known_arg(self, option: str, argname: T.Optional[str] = None, value_processor: T.Optional[T.Callable] = None) -> None:
        if not argname:
            argname = option.strip("-").replace("-", "_")

        value = self.kwargs.pop(argname)
        if value is not None and value_processor:
            value = value_processor(value)

        self.set_arg_value(option, value)

    def set_arg_value(self, option: str, value: TYPE_var) -> None:
        if value is None:
            return

        if isinstance(value, bool):
            if value:
                self.cmd.append(option)
        elif isinstance(value, list):
            # Do not do anything on empty lists
            if value:
                # https://bugs.python.org/issue9334 (from 2010 :( )
                # The syntax with nargs=+ is inherently ambiguous
                # A workaround for this case is to simply prefix with a space
                # every value starting with a dash
                escaped_value = []
                for e in value:
                    if isinstance(e, str) and e.startswith('-'):
                        escaped_value += [' %s' % e]
                    else:
                        escaped_value += [e]
                if option:
                    self.cmd.extend([option] + escaped_value)
                else:
                    self.cmd.extend(escaped_value)
        else:
            # argparse gets confused if value(s) start with a dash.
            # When an option expects a single value, the unambiguous way
            # to specify it is with =
            if isinstance(value, str):
                self.cmd.extend([f'{option}={value}'])
            else:
                self.cmd.extend([option, value])

    def check_extra_arg_type(self, arg: str, value: TYPE_var) -> None:
        if isinstance(value, list):
            for v in value:
                self.check_extra_arg_type(arg, v)
            return

        valid_types = (str, bool, File, build.IncludeDirs, CustomTarget, CustomTargetIndex, build.BuildTarget)
        if not isinstance(value, valid_types):
            raise InvalidArguments('Argument "{}={}" should be of type: {}.'.format(
                arg, value, [t.__name__ for t in valid_types]))

    def process_extra_args(self) -> None:
        for arg, value in self.kwargs.items():
            option = "--" + arg.replace("_", "-")
            self.check_extra_arg_type(arg, value)
            self.set_arg_value(option, value)

    def get_value(self, types, argname, default=None, value_processor=None,
                  mandatory=False, force_list=False):
        if not isinstance(types, list):
            types = [types]
        try:
            uvalue = value = self.kwargs.pop(argname)
            if value_processor:
                value = value_processor(value)

            for t in types:
                if isinstance(value, t):
                    if force_list and not isinstance(value, list):
                        return [value], uvalue
                    return value, uvalue
            raise MesonException(f"{argname} field value {value} is not valid,"
                                 f" valid types are {types}")
        except KeyError:
            if mandatory:
                raise MesonException(f"{argname} mandatory field not found")

            if default is not None:
                return default, default

        return None, None

    def add_extension_paths(self, paths: T.Union[T.List[str], T.Set[str]]) -> None:
        for path in paths:
            if path in self._extra_extension_paths:
                continue

            self._extra_extension_paths.add(path)
            self.cmd.extend(["--extra-extension-path", path])

    def replace_dirs_in_string(self, string: str) -> str:
        return string.replace("@SOURCE_ROOT@", self.sourcedir).replace("@BUILD_ROOT@", self.builddir)

    def process_gi_c_source_roots(self) -> None:
        if self.hotdoc.run_hotdoc(['--has-extension=gi-extension']) != 0:
            return

        value = self.kwargs.pop('gi_c_source_roots')
        value.extend([
            os.path.join(self.sourcedir, self.state.root_subdir),
            os.path.join(self.builddir, self.state.root_subdir)
        ])

        self.cmd += ['--gi-c-source-roots'] + value

    def process_dependencies(self, deps: T.List[T.Union[Dependency, build.StaticLibrary, build.SharedLibrary, CustomTarget, CustomTargetIndex]]) -> T.List[str]:
        cflags = set()
        for dep in mesonlib.listify(ensure_list(deps)):
            if isinstance(dep, InternalDependency):
                inc_args = self.state.get_include_args(dep.include_directories)
                cflags.update([self.replace_dirs_in_string(x)
                               for x in inc_args])
                cflags.update(self.process_dependencies(dep.libraries))
                cflags.update(self.process_dependencies(dep.sources))
                cflags.update(self.process_dependencies(dep.ext_deps))
            elif isinstance(dep, Dependency):
                cflags.update(dep.get_compile_args())
            elif isinstance(dep, (build.StaticLibrary, build.SharedLibrary)):
                self.extra_depends.append(dep)
                for incd in dep.get_include_dirs():
                    cflags.update(incd.get_incdirs())
            elif isinstance(dep, HotdocTarget):
                # Recurse in hotdoc target dependencies
                self.process_dependencies(dep.get_target_dependencies())
                self._subprojects.extend(dep.subprojects)
                self.process_dependencies(dep.subprojects)
                self.include_paths.add(os.path.join(self.builddir, dep.hotdoc_conf.subdir))
                self.cmd += ['--extra-assets=' + p for p in dep.extra_assets]
                self.add_extension_paths(dep.extra_extension_paths)
            elif isinstance(dep, (CustomTarget, build.BuildTarget)):
                self.extra_depends.append(dep)
            elif isinstance(dep, CustomTargetIndex):
                self.extra_depends.append(dep.target)

        return [f.strip('-I') for f in cflags]

    def process_extra_assets(self) -> None:
        self._extra_assets = self.kwargs.pop('extra_assets')

        for assets_path in self._extra_assets:
            self.cmd.extend(["--extra-assets", assets_path])

    def process_subprojects(self) -> None:
        value = self.kwargs.pop('subprojects')

        self.process_dependencies(value)
        self._subprojects.extend(value)

    def flatten_config_command(self) -> T.List[str]:
        cmd = []
        for arg in mesonlib.listify(self.cmd, flatten=True):
            if isinstance(arg, File):
                arg = arg.absolute_path(self.state.environment.get_source_dir(),
                                        self.state.environment.get_build_dir())
            elif isinstance(arg, build.IncludeDirs):
                for inc_dir in arg.get_incdirs():
                    cmd.append(os.path.join(self.sourcedir, arg.get_curdir(), inc_dir))
                    cmd.append(os.path.join(self.builddir, arg.get_curdir(), inc_dir))

                continue
            elif isinstance(arg, (build.BuildTarget, CustomTarget)):
                self.extra_depends.append(arg)
                arg = self.interpreter.backend.get_target_filename_abs(arg)
            elif isinstance(arg, CustomTargetIndex):
                self.extra_depends.append(arg.target)
                arg = self.interpreter.backend.get_target_filename_abs(arg)

            cmd.append(arg)

        return cmd

    def generate_hotdoc_config(self) -> None:
        cwd = os.path.abspath(os.curdir)
        ncwd = os.path.join(self.sourcedir, self.subdir)
        mlog.log('Generating Hotdoc configuration for: ', mlog.bold(self.name))
        os.chdir(ncwd)
        if self.hotdoc.run_hotdoc(self.flatten_config_command()) != 0:
            raise MesonException('hotdoc failed to configure')
        os.chdir(cwd)

    def ensure_file(self, value: T.Union[str, File, CustomTarget, CustomTargetIndex]) -> T.Union[File, CustomTarget, CustomTargetIndex]:
        if isinstance(value, list):
            res = []
            for val in value:
                res.append(self.ensure_file(val))
            return res

        if isinstance(value, str):
            return File.from_source_file(self.sourcedir, self.subdir, value)

        return value

    def ensure_dir(self, value: str) -> str:
        if os.path.isabs(value):
            _dir = value
        else:
            _dir = os.path.join(self.sourcedir, self.subdir, value)

        if not os.path.isdir(_dir):
            raise InvalidArguments(f'"{_dir}" is not a directory.')

        return os.path.relpath(_dir, os.path.join(self.builddir, self.subdir))

    def check_forbidden_args(self) -> None:
        for arg in ['conf_file']:
            if arg in self.kwargs:
                raise InvalidArguments(f'Argument "{arg}" is forbidden.')

    def make_targets(self) -> T.Tuple[HotdocTarget, mesonlib.ExecutableSerialisation]:
        self.check_forbidden_args()
        self.process_known_arg("--index", value_processor=self.ensure_file)
        self.process_known_arg("--project-version")
        self.process_known_arg("--sitemap", value_processor=self.ensure_file)
        self.process_known_arg("--html-extra-theme", value_processor=self.ensure_dir)
        self.include_paths.update(self.ensure_dir(v) for v in self.kwargs.pop('include_paths'))
        self.process_known_arg('--c-include-directories', argname="dependencies", value_processor=self.process_dependencies)
        self.process_gi_c_source_roots()
        self.process_extra_assets()
        self.add_extension_paths(self.kwargs.pop('extra_extension_paths'))
        self.process_subprojects()
        self.extra_depends.extend(self.kwargs.pop('depends'))

        install = self.kwargs.pop('install')
        self.process_extra_args()

        fullname = self.name + '-doc'
        hotdoc_config_name = fullname + '.json'
        hotdoc_config_path = os.path.join(
            self.builddir, self.subdir, hotdoc_config_name)
        with open(hotdoc_config_path, 'w', encoding='utf-8') as f:
            f.write('{}')

        self.cmd += ['--conf-file', hotdoc_config_path]
        self.include_paths.add(os.path.join(self.builddir, self.subdir))
        self.include_paths.add(os.path.join(self.sourcedir, self.subdir))

        depfile = os.path.join(self.builddir, self.subdir, self.name + '.deps')
        self.cmd += ['--deps-file-dest', depfile]

        for path in self.include_paths:
            self.cmd.extend(['--include-path', path])

        if self.state.environment.coredata.get_option(mesonlib.OptionKey('werror', subproject=self.state.subproject)):
            self.cmd.append('--fatal-warnings')
        self.generate_hotdoc_config()

        target_cmd = self.build_command + ["--internal", "hotdoc"] + \
            self.hotdoc.get_command() + ['run', '--conf-file', hotdoc_config_name] + \
            ['--builddir', os.path.join(self.builddir, self.subdir)]

        target = HotdocTarget(fullname,
                              subdir=self.subdir,
                              subproject=self.state.subproject,
                              environment=self.state.environment,
                              hotdoc_conf=File.from_built_file(
                                  self.subdir, hotdoc_config_name),
                              extra_extension_paths=self._extra_extension_paths,
                              extra_assets=self._extra_assets,
                              subprojects=self._subprojects,
                              is_build_only_subproject=self.interpreter.coredata.is_build_only,
                              command=target_cmd,
                              extra_depends=self.extra_depends,
                              outputs=[fullname],
                              sources=[],
                              depfile=os.path.basename(depfile),
                              build_by_default=self.build_by_default)

        install_script = None
        if install:
            datadir = os.path.join(self.state.get_option('prefix'), self.state.get_option('datadir'))
            devhelp = self.kwargs.get('devhelp_activate', False)
            if not isinstance(devhelp, bool):
                FeatureDeprecated.single_use('hotdoc.generate_doc() devhelp_activate must be boolean', '1.1.0', self.state.subproject)
                devhelp = False
            if devhelp:
                install_from = os.path.join(fullname, 'devhelp')
                install_to = os.path.join(datadir, 'devhelp')
            else:
                install_from = os.path.join(fullname, 'html')
                install_to = os.path.join(datadir, 'doc', self.name, 'html')

            install_script = self.state.backend.get_executable_serialisation(self.build_command + [
                "--internal", "hotdoc",
                "--install", install_from,
                "--docdir", install_to,
                '--name', self.name,
                '--builddir', os.path.join(self.builddir, self.subdir)] +
                self.hotdoc.get_command() +
                ['run', '--conf-file', hotdoc_config_name])
            install_script.tag = 'doc'

        return (target, install_script)


class HotdocTargetHolder(_CustomTargetHolder['HotdocTarget']):
    def __init__(self, target: HotdocTarget, interp: Interpreter):
        super().__init__(target, interp)
        self.methods.update({'config_path': self.config_path_method})

    @noPosargs
    @noKwargs
    def config_path_method(self, *args: T.Any, **kwargs: T.Any) -> str:
        conf = self.held_object.hotdoc_conf.absolute_path(self.interpreter.environment.source_dir,
                                                          self.interpreter.environment.build_dir)
        return conf


class HotdocTarget(CustomTarget):
    def __init__(self, name: str, subdir: str, subproject: str, hotdoc_conf: File,
                 extra_extension_paths: T.Set[str], extra_assets: T.List[str],
                 subprojects: T.List['HotdocTarget'], environment: Environment,
                 is_build_only_subproject: bool, **kwargs: T.Any):
        super().__init__(name, subdir, subproject, environment, **kwargs, build_only_subproject=is_build_only_subproject, absolute_paths=True)
        self.hotdoc_conf = hotdoc_conf
        self.extra_extension_paths = extra_extension_paths
        self.extra_assets = extra_assets
        self.subprojects = subprojects

    def __getstate__(self) -> dict:
        # Make sure we do not try to pickle subprojects
        res = self.__dict__.copy()
        res['subprojects'] = []

        return res


class HotDocModule(ExtensionModule):

    INFO = ModuleInfo('hotdoc', '0.48.0')

    def __init__(self, interpreter: Interpreter):
        super().__init__(interpreter)
        self.hotdoc = HotdocExternalProgram('hotdoc')
        if not self.hotdoc.found():
            raise MesonException('hotdoc executable not found')
        version = self.hotdoc.get_version(interpreter)
        if not mesonlib.version_compare(version, f'>={MIN_HOTDOC_VERSION}'):
            raise MesonException(f'hotdoc {MIN_HOTDOC_VERSION} required but not found.)')

        self.methods.update({
            'has_extensions': self.has_extensions,
            'generate_doc': self.generate_doc,
        })

    @noKwargs
    @typed_pos_args('hotdoc.has_extensions', varargs=str, min_varargs=1)
    def has_extensions(self, state: ModuleState, args: T.Tuple[T.List[str]], kwargs: TYPE_kwargs) -> bool:
        return self.hotdoc.run_hotdoc([f'--has-extension={extension}' for extension in args[0]]) == 0

    @typed_pos_args('hotdoc.generate_doc', str)
    @typed_kwargs(
        'hotdoc.generate_doc',
        KwargInfo('sitemap', file_types, required=True),
        KwargInfo('index', file_types, required=True),
        KwargInfo('project_version', str, required=True),
        KwargInfo('html_extra_theme', (str, NoneType)),
        KwargInfo('include_paths', ContainerTypeInfo(list, str), listify=True, default=[]),
        # --c-include-directories
        KwargInfo(
            'dependencies',
            ContainerTypeInfo(list, (Dependency, build.StaticLibrary, build.SharedLibrary,
                                     CustomTarget, CustomTargetIndex)),
            listify=True,
            default=[],
        ),
        KwargInfo(
            'depends',
            ContainerTypeInfo(list, (CustomTarget, CustomTargetIndex)),
            listify=True,
            default=[],
            since='0.64.1',
        ),
        KwargInfo('gi_c_source_roots', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('extra_assets', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('extra_extension_paths', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('subprojects', ContainerTypeInfo(list, HotdocTarget), listify=True, default=[]),
        KwargInfo('install', bool, default=False),
        allow_unknown=True
    )
    def generate_doc(self, state: ModuleState, args: T.Tuple[str], kwargs: GenerateDocKwargs) -> ModuleReturnValue:
        project_name = args[0]
        if any(isinstance(x, (CustomTarget, CustomTargetIndex)) for x in kwargs['dependencies']):
            FeatureDeprecated.single_use('hotdoc.generate_doc dependencies argument with custom_target',
                                         '0.64.1', state.subproject, 'use `depends`', state.current_node)
        builder = HotdocTargetBuilder(project_name, state, self.hotdoc, self.interpreter, kwargs)
        target, install_script = builder.make_targets()
        targets: T.List[T.Union[HotdocTarget, mesonlib.ExecutableSerialisation]] = [target]
        if install_script:
            targets.append(install_script)

        return ModuleReturnValue(target, targets)


def initialize(interpreter: Interpreter) -> HotDocModule:
    mod = HotDocModule(interpreter)
    mod.interpreter.append_holder_map(HotdocTarget, HotdocTargetHolder)
    return mod
```