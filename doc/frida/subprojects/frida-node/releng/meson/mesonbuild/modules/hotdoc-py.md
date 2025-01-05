Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive response.

**1. Understanding the Core Purpose:**

The first step is to identify the main function of the code. The filename `hotdoc.py` and the initial comment clearly indicate this module is for generating documentation using `hotdoc`. The `frida` prefix suggests this is part of the Frida project.

**2. Decomposition into Functional Units:**

Next, I look for classes and functions to understand the code's organization and major components. Key elements I identify are:

* **`HotdocExternalProgram`:**  This class handles the execution of the external `hotdoc` command.
* **`HotdocTargetBuilder`:** This class appears to be responsible for configuring and creating the `hotdoc` documentation build target. It processes various input arguments.
* **`HotdocTarget`:**  This class represents the actual Meson custom target for building the documentation.
* **`HotdocTargetHolder`:** This is a Meson-specific class for holding and exposing methods of the `HotdocTarget`.
* **`HotDocModule`:** This is the main Meson module that exposes the functionality to the Meson build system. The `generate_doc` method is the primary entry point for users.

**3. Analyzing Key Functionalities and Interactions:**

With the structure identified, I delve into the functions and methods to understand how they work and interact. I pay attention to:

* **Argument Processing in `HotdocTargetBuilder`:** How are different arguments (`sitemap`, `index`, `dependencies`, etc.) handled?  Are there any specific data transformations or validations? The `process_known_arg`, `set_arg_value`, and `process_extra_args` methods are central here.
* **Dependency Handling:** How are dependencies (other libraries, targets, etc.) incorporated into the `hotdoc` configuration? The `process_dependencies` method is crucial here.
* **Configuration Generation:** How is the `hotdoc` configuration file created? The `generate_hotdoc_config` method is key.
* **Target Creation:** How is the Meson `CustomTarget` created? The `make_targets` method handles this.
* **Installation:** How is the generated documentation installed? The `install` keyword argument and related logic are important.

**4. Identifying Connections to Reverse Engineering, Binary/Kernel/Framework Knowledge:**

This requires thinking about what aspects of documentation generation might be relevant to reverse engineering and low-level systems.

* **Reverse Engineering:** Documentation often describes APIs, data structures, and internal workings. Generating documentation for Frida itself (a dynamic instrumentation tool) directly supports reverse engineering efforts. The documentation generated by this module would likely detail Frida's API, allowing users to understand how to interact with and control running processes.
* **Binary/Kernel/Framework:**  Frida interacts deeply with operating system internals. The documentation might contain information about system calls, memory layout, and other low-level details relevant to hooking and instrumenting processes. The handling of C include directories and dependencies suggests that the documentation can cover code interacting with these lower levels.

**5. Looking for Logic and Potential Inputs/Outputs:**

Here, I focus on functions that perform transformations or make decisions. The `HotdocTargetBuilder` is the primary area for this. I consider:

* **Input Arguments:**  What are the expected types and formats of the arguments to `generate_doc`?
* **Conditional Logic:** Are there `if` statements or other conditional checks that influence the output? For example, the handling of the `install` flag.
* **Data Transformations:** How are input values modified or combined? The processing of include paths and dependencies involves such transformations.

**6. Spotting Potential User Errors:**

I think about common mistakes developers might make when using this module:

* **Incorrect File Paths:** Providing wrong paths for sitemap or index files.
* **Missing Dependencies:** Forgetting to specify necessary dependencies.
* **Type Mismatches:** Providing arguments of the wrong type.
* **Misunderstanding Installation:** Incorrectly setting the `install` flag or expecting the documentation to be installed in a specific location.

**7. Tracing User Actions (Debugging Clues):**

I consider how a user might interact with Meson and end up triggering this code:

* **Meson Build Definition:** The user would need to define a `hotdoc.generate_doc()` call within their `meson.build` file.
* **Meson Configuration:**  The user would run `meson setup` to configure the build.
* **Meson Compilation:** The user would run `meson compile` (or similar commands like `ninja`) to build the documentation target.
* **Error Scenario:** If something goes wrong, the error message or stack trace might point back to this specific module.

**8. Structuring the Response:**

Finally, I organize the information into a clear and comprehensive response, addressing each of the prompt's requirements:

* **Functionality:** A bulleted list summarizing the key capabilities.
* **Relationship to Reverse Engineering:** An explanation with examples.
* **Involvement of Low-Level Knowledge:**  Another explanation with examples.
* **Logic and Input/Output:** A section detailing assumptions and potential outcomes.
* **Common User Errors:**  A list of typical mistakes.
* **User Steps (Debugging):** A description of how a user might reach this code.

By following these steps, I can systematically analyze the code, understand its purpose and interactions, and generate a detailed and informative response that addresses all aspects of the prompt. The process involves both code comprehension and reasoning about the software's context and potential usage.
这个文件 `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/hotdoc.py` 是 Frida 项目中，用于集成和管理使用 Hotdoc 工具生成文档的 Meson 模块。Hotdoc 是一个用于生成 API 文档的工具，它通常用于 C 和 C++ 项目。

以下是该文件的功能列表，以及与逆向、底层知识、逻辑推理和用户错误相关的说明：

**功能列表:**

1. **提供 Meson DSL 接口来生成 Hotdoc 文档:**  它允许开发者在 `meson.build` 文件中使用 `hotdoc.generate_doc()` 函数来配置和生成文档。
2. **配置 Hotdoc 运行参数:**  它接受各种参数，例如：
    * `sitemap`:  指定站点地图文件。
    * `index`:  指定首页文件。
    * `project_version`:  指定项目版本。
    * `html_extra_theme`:  指定额外的 HTML 主题。
    * `include_paths`:  指定头文件搜索路径。
    * `dependencies`:  指定依赖项，用于提取编译参数和头文件路径。
    * `depends`: 指定文档生成目标所依赖的其他构建目标。
    * `gi_c_source_roots`: 指定 GObject Introspection C 源码根目录。
    * `extra_assets`:  指定额外的静态资源文件。
    * `extra_extension_paths`: 指定额外的 Hotdoc 扩展路径。
    * `subprojects`:  指定依赖的其他 Hotdoc 文档生成目标。
    * `install`:  指定是否安装生成的文档。
3. **生成 Hotdoc 配置文件:**  它使用传入的参数生成 Hotdoc 的配置文件 (`<target_name>-doc.json`)。
4. **创建 Meson 自定义构建目标 (Custom Target):** 它创建一个 `HotdocTarget` 类型的自定义目标，该目标负责执行 Hotdoc 命令来生成文档。
5. **处理依赖关系:** 它能够处理依赖的库、目标和头文件路径，并将这些信息传递给 Hotdoc。
6. **支持安装生成的文档:**  如果 `install` 参数设置为 `True`，它会生成一个安装脚本，将生成的文档安装到指定目录。
7. **检查 Hotdoc 版本:**  它会检查系统中安装的 Hotdoc 版本是否满足最低要求。
8. **支持 Hotdoc 扩展:** 它提供了检查 Hotdoc 是否支持特定扩展的功能 (`has_extensions`)。

**与逆向方法的关系及举例说明:**

* **API 文档是逆向的重要资源:**  对于 Frida 这样的动态插桩工具，其 API 文档至关重要。逆向工程师需要了解 Frida 提供的各种函数、类和方法，才能有效地使用它来分析和修改目标进程的行为。`hotdoc.py` 负责生成 Frida 的 C/C++ API 文档，这直接帮助逆向工程师理解 Frida 的工作方式。
    * **举例:**  Frida 的 API 中可能包含用于 attach 到进程的函数 `frida_session_attach()`, 用于加载脚本的函数 `frida_script_load()`, 以及用于 hook 函数的 API。这些 API 的详细用法、参数和返回值都会在 Hotdoc 生成的文档中说明，逆向工程师可以通过查阅这些文档来学习如何使用 Frida 进行逆向分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **处理 C/C++ 头文件:**  Hotdoc 主要用于 C/C++ 项目，因此 `hotdoc.py` 需要处理 C/C++ 的头文件路径 (`include_paths`) 和依赖关系 (`dependencies`)。这些依赖项可能包含与底层系统交互的头文件。
    * **举例:** Frida 的代码可能包含与 Linux 系统调用相关的头文件，例如 `<unistd.h>`，或者与 Android 的 Binder 机制相关的头文件。`hotdoc.py` 需要能够正确地找到这些头文件，才能生成包含这些底层 API 的文档。
* **GObject Introspection 支持:**  `gi_c_source_roots` 参数表明该模块支持使用 GObject Introspection 来生成文档。GObject Introspection 常用于 Linux 桌面环境（如 GNOME），它允许在运行时获取 C 代码的类型信息。这暗示 Frida 的某些部分可能使用了 GObject，或者需要记录与 GObject 相关的 API。
    * **举例:**  Frida 可能使用了 GLib 库（一个基于 GObject 的库）提供的功能。`hotdoc.py` 通过 GObject Introspection 可以提取 GLib 相关 API 的信息并生成文档。
* **依赖处理可能涉及编译参数:**  `process_dependencies` 函数会处理依赖项，并尝试提取编译参数 (例如 `-I` 指定的头文件路径)。这说明文档生成过程需要理解构建系统的某些概念。
    * **举例:**  如果 Frida 依赖于一个静态库，该静态库在编译时指定了一些特殊的头文件搜索路径，`hotdoc.py` 需要能够从这个依赖项中提取这些路径，以便 Hotdoc 能够找到相关的头文件。

**逻辑推理及假设输入与输出:**

假设我们有以下的 `meson.build` 片段：

```meson
hotdoc_mod = import('hotdoc')

hotdoc_mod.generate_doc(
  'MyProject',
  sitemap: 'reference/sitemap.xml',
  index: 'reference/index.md',
  project_version: '1.0',
  include_paths: ['include', 'src/include'],
  dependencies: [mylib], # 假设 mylib 是一个库目标
  install: true
)
```

* **假设输入:**
    * `project_name`: 'MyProject'
    * `kwargs['sitemap']`: 'reference/sitemap.xml' (相对于源代码目录)
    * `kwargs['index']`: 'reference/index.md' (相对于源代码目录)
    * `kwargs['project_version']`: '1.0'
    * `kwargs['include_paths']`: `['include', 'src/include']`
    * `kwargs['dependencies']`:  `mylib` (一个 `build.StaticLibrary` 或 `build.SharedLibrary` 对象)
    * `kwargs['install']`: `True`

* **逻辑推理:**
    1. `HotdocTargetBuilder` 会被创建，接收这些参数。
    2. `process_known_arg` 会处理 `sitemap`, `index`, `project_version` 等基本参数。
    3. `process_dependencies` 会处理 `mylib` 依赖，提取其头文件路径。假设 `mylib` 的头文件位于 `mylib/include`。
    4. `generate_hotdoc_config` 会生成一个 JSON 配置文件，其中会包含项目名称、版本、头文件搜索路径等信息。
    5. 一个名为 `MyProject-doc` 的 `HotdocTarget` 会被创建，其命令会包含运行 Hotdoc 的指令，并指定生成的配置文件。
    6. 由于 `install` 为 `True`，会生成一个安装脚本，将生成的文档从 `MyProject-doc/html` 安装到 `$prefix/share/doc/MyProject/html` (假设默认的安装前缀)。

* **假设输出:**
    * 一个名为 `MyProject-doc.json` 的 Hotdoc 配置文件被创建在构建目录下。
    * 一个名为 `MyProject-doc` 的构建目标被添加到 Meson 的构建图中。
    * 当执行构建时，Hotdoc 会被调用，根据配置文件和源文件生成文档。
    * 如果执行安装，生成的 HTML 文档会被复制到安装目录。

**涉及用户或编程常见的使用错误及举例说明:**

1. **错误的路径:** 用户可能提供不存在的站点地图文件或索引文件路径。
    * **举例:**  如果在 `meson.build` 中 `sitemap: 'ref/sitemap.xml'`，但实际上该文件位于 `reference/sitemap.xml`，Hotdoc 会报错，因为找不到输入文件。
2. **缺少依赖:**  用户可能忘记将文档中引用的库或目标添加到 `dependencies`。
    * **举例:**  如果文档中描述了 `mylib` 库的 API，但 `dependencies` 中没有包含 `mylib`，Hotdoc 可能无法正确找到 `mylib` 的头文件，导致文档生成不完整或报错。
3. **类型错误:**  用户可能提供了错误类型的参数。
    * **举例:**  如果 `project_version` 期望是字符串，但用户传递了一个整数 `1.0` (在某些语言中可能被解析为浮点数)，`typed_kwargs` 可能会抛出类型错误。
4. **Hotdoc 版本不兼容:**  如果系统安装的 Hotdoc 版本低于 `MIN_HOTDOC_VERSION`，模块会抛出异常。
    * **举例:** 如果系统中安装的是 Hotdoc 0.8.99，执行 `meson setup` 时会报错，提示需要更高版本的 Hotdoc。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在其项目的根目录下创建或编辑 `meson.build` 文件，并在其中使用 `hotdoc.generate_doc()` 函数来定义如何生成文档。
2. **用户运行 `meson setup`:** 用户在构建目录下运行 `meson setup <source_dir>` 命令。Meson 会解析 `meson.build` 文件，并执行其中的模块代码。当解析到 `import('hotdoc')` 时，`HotDocModule` 的 `__init__` 方法会被调用，检查 Hotdoc 的存在和版本。当解析到 `hotdoc_mod.generate_doc()` 时，`HotDocModule` 的 `generate_doc` 方法会被调用。
3. **`generate_doc` 调用 `HotdocTargetBuilder`:** `generate_doc` 方法会创建一个 `HotdocTargetBuilder` 实例，并将用户在 `meson.build` 中提供的参数传递给它。
4. **`HotdocTargetBuilder` 处理参数:** `HotdocTargetBuilder` 的各种方法（如 `process_known_arg`, `process_dependencies`）会被调用，用于处理和验证用户提供的参数。
5. **生成配置文件和构建目标:** `HotdocTargetBuilder` 生成 Hotdoc 配置文件，并创建一个 `HotdocTarget` 自定义构建目标。这个目标会被添加到 Meson 的内部数据结构中。
6. **用户运行 `meson compile` (或 `ninja`)**: 当用户运行构建命令时，Meson 会执行之前创建的 `HotdocTarget` 目标。这会调用 Hotdoc 工具，使用生成的配置文件和提供的源文件来生成文档。
7. **调试线索:** 如果文档生成过程中出现错误，例如 Hotdoc 报错找不到文件，或者 Meson 报告构建失败，开发者可以检查以下内容：
    * **`meson.build` 文件:** 检查 `hotdoc.generate_doc()` 的参数是否正确，路径是否正确。
    * **Hotdoc 版本:** 确认系统中安装的 Hotdoc 版本是否满足要求。
    * **依赖关系:** 检查 `dependencies` 参数是否包含了所有需要的库或目标。
    * **构建日志:** 查看 Meson 和 Hotdoc 的构建日志，以获取更详细的错误信息。
    * **Hotdoc 配置文件:** 检查生成的 `*-doc.json` 文件内容是否符合预期，例如头文件搜索路径是否正确。

总而言之，`hotdoc.py` 作为一个 Meson 模块，将 Hotdoc 文档生成工具集成到 Frida 的构建系统中，方便开发者管理和生成 Frida 的 API 文档。理解其功能和参数对于正确配置和调试文档生成过程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/hotdoc.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```