Response:
My thinking process to analyze the Python code and answer the user's request goes through these stages:

1. **Understand the Core Purpose:** The docstring at the beginning clearly states this is a helper script for IDE developers to extract build information. This sets the context for everything else. The focus is on *introspection* – looking into the build system's configuration and state.

2. **Identify Key Modules and Data Structures:** I start looking for important imports and data structures.
    * `argparse`:  Indicates command-line interface capabilities.
    * `json`:  Confirms the input/output format is JSON.
    * `os`, `pathlib`:  Suggests file system interactions.
    * `build.py`, `coredata.py`, `backends.py`: These are strong indicators of interaction with the core Meson build system. Specifically, `build.Build` likely holds the build graph, `coredata.CoreData` holds build options, and `backends.Backend` represents the specific build backend (like Ninja).
    * `IntrospectionInterpreter`: A class specifically designed for analyzing `meson.build` files.
    * The `IntroCommand` class and the `get_meson_introspection_types` function define the available introspection commands.

3. **Analyze the Introspection Commands:** I go through the `get_meson_introspection_types` function and the associated `IntroCommand` definitions. This gives a comprehensive list of what information can be extracted:
    * `ast`: Abstract Syntax Tree of `meson.build`.
    * `benchmarks`, `tests`: Information about tests and benchmarks.
    * `buildoptions`: Build configuration options.
    * `buildsystem_files`: Files that make up the build system.
    * `compilers`: Information about used compilers.
    * `dependencies`: External and internal dependencies.
    * `installed`, `install_plan`: Details about installed files.
    * `machines`: Host, build, and target machine information.
    * `projectinfo`: Project-level information.
    * `targets`:  Information about build targets (executables, libraries, etc.).

4. **Relate to Reverse Engineering:**  With the understanding of the available information, I consider how it relates to reverse engineering. The key is that this tool provides insights into *how* a target is built, its dependencies, and its structure. This is extremely valuable for reverse engineers:
    * **Dependencies:** Knowing the libraries a binary depends on (`dependencies`, `depends`) is crucial for understanding its functionality and potential vulnerabilities.
    * **Compiler Flags:**  Compiler flags (`target_sources` within `targets`) can reveal optimization levels, debugging information, and security features enabled during compilation.
    * **Build System:** Understanding the build system files (`buildsystem_files`) and the build process itself can help in reproducing builds or identifying custom build steps.
    * **Installation Paths:**  Knowing where files are installed (`installed`, `install_plan`) helps locate relevant binaries and libraries after installation.
    * **Target Types:** Understanding the type of target (`targets` - library, executable, etc.) is fundamental.

5. **Identify Low-Level/Kernel/Framework Aspects:** I look for clues suggesting interaction with the operating system or lower levels:
    * **Compilers:** Compiler information is inherently low-level.
    * **Machines:**  Information about the host, build, and target machines reveals architecture details.
    * **Dependencies:**  System libraries often involve kernel or framework components.
    * **Installation Paths:**  Installation directories often adhere to OS conventions.

6. **Look for Logic and Assumptions:**  I analyze functions like `list_targets`, `list_dependencies`, etc., to see the logic involved in extracting and structuring the information. I look for potential assumptions in the code (e.g., the structure of `builddata`).

7. **Consider User Errors:**  I think about how a user might misuse this tool or encounter errors:
    * **Incorrect Build Directory:** Specifying the wrong build directory is a common mistake.
    * **Outdated Build:**  Using the tool on an old build directory might lead to errors or incomplete information.
    * **Specifying Non-Existent Options:** Although the code uses flags, if a user tries to manually manipulate the JSON output or expects certain data to always be present, they might encounter issues.

8. **Trace User Operations:** I consider the steps a user would take to reach this code:
    * **Installation:** The user would have installed the `frida` package.
    * **Build Directory:**  The user would be in or have access to a Meson build directory for a project using Frida.
    * **Command Execution:** The user would execute a command like `meson introspect` or a custom script leveraging this module.

9. **Structure the Answer:** Finally, I organize the findings into the categories requested by the user: functionality, relationship to reverse engineering, low-level aspects, logic/assumptions, user errors, and user operation tracing. I provide concrete examples where appropriate.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate answer to the user's request. The key is to move from the high-level purpose to the specific details of the code, always keeping the user's perspective and the context of Frida in mind.
这个Python源代码文件 `mintro.py` 是 Frida 动态 instrumentation 工具中 `frida-qml` 子项目的一部分，它位于 `releng/meson/mesonbuild/` 目录下。这个文件的主要功能是 **为 IDE 开发者提供一个辅助脚本，用于提取关于 Meson 构建系统的信息**。这些信息以 JSON 格式输出，方便 IDE 进行解析和利用。

以下是该文件的具体功能分解：

**主要功能：**

1. **信息提取框架:** 提供了一个框架，允许提取各种关于 Meson 构建系统的信息，例如：
    * 构建目标 (targets) 列表
    * 源文件列表
    * 编译器标志 (compiler flags)
    * 单元测试 (tests) 列表
    * 基准测试 (benchmarks) 列表
    * 安装文件 (installed files) 列表
    * 构建选项 (build options)
    * 外部依赖 (dependencies)
    * 项目信息 (project information)
    * 构成构建系统的文件 (build system files)
    * 使用的编译器 (compilers)
    * 主机、构建和目标机器的信息 (machines)
    * meson.build 文件的抽象语法树 (AST)

2. **命令行接口:** 使用 `argparse` 模块定义了命令行参数，允许用户指定要提取的信息类型。例如，使用 `--targets` 参数可以获取目标列表。

3. **JSON 输出:**  将提取的信息以 JSON 格式输出到标准输出，方便其他程序（特别是 IDE）进行解析。

4. **后端支持 (主要是 Ninja):**  目前的实现主要针对 Ninja 构建后端。对于其他使用生成项目文件的后端，这些信息可能不需要通过这种方式提取。

5. **与 Meson 构建系统的集成:**  它深入 Meson 的内部结构，例如 `build.Build` (构建数据), `coredata.CoreData` (核心配置数据), `backends.Backend` (构建后端接口) 等，来获取所需的信息。

**与逆向方法的关系及举例说明：**

该工具提供的很多信息对于逆向工程师来说非常有价值，可以帮助他们理解目标程序的构建过程和依赖关系。

* **目标信息 (`targets`):**
    * **功能:** 列出所有构建目标（例如，可执行文件、共享库）。
    * **逆向关系:**  逆向工程师可以利用这个信息来快速了解项目中构建了哪些可执行文件或库，从而确定他们想要分析的目标。例如，如果逆向分析一个包含多个可执行文件的项目，可以通过目标列表来定位主程序。
    * **举例:**  假设一个 Frida 相关的项目构建了一个名为 `frida-agent` 的共享库。通过运行 `python mintro.py --targets`，逆向工程师可以找到 `frida-agent` 的名称、输出路径等信息，方便后续的加载和分析。

* **依赖信息 (`dependencies`):**
    * **功能:** 列出目标所依赖的外部库和内部库。
    * **逆向关系:** 了解目标依赖哪些库对于理解其功能至关重要。外部库可能揭示了目标使用了特定的第三方库来实现某些功能，内部库则说明了模块之间的组织结构。这有助于逆向工程师缩小分析范围，并找到关键的功能实现。
    * **举例:**  如果一个 Frida 插件依赖于 `glib` 库进行某些操作，`mintro.py --dependencies` 的输出会包含 `glib` 的信息，逆向工程师可以通过查找 `glib` 的相关文档来理解这部分功能。

* **编译器信息 (`compilers`):**
    * **功能:** 提供构建过程中使用的编译器及其版本信息。
    * **逆向关系:** 编译器和编译选项会影响生成二进制文件的结构和特性。了解编译器信息可以帮助逆向工程师选择合适的反汇编工具和调试策略。
    * **举例:**  如果目标是用 GCC 编译的，并且开启了某些优化选项，逆向工程师可能需要使用支持 GCC 特定优化的反汇编器，并注意识别优化后的代码模式。

* **构建选项 (`buildoptions`):**
    * **功能:** 列出构建时使用的各种配置选项。
    * **逆向关系:** 构建选项会影响程序的行为和特性。例如，调试符号的开关、优化级别的设置等。了解这些选项有助于理解目标二进制文件的特性，例如是否包含调试信息。
    * **举例:**  如果构建时启用了调试符号 (`-Dbuildtype=debug`)，逆向工程师在分析时就能利用这些符号进行更方便的调试。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

虽然这个脚本本身是用 Python 编写的，但它提取的信息直接关联到二进制底层和操作系统相关的概念。

* **二进制底层:**
    * **目标类型 (`target['type']`):**  区分可执行文件、共享库、静态库等二进制文件的类型，这些都是操作系统加载和链接的基础概念。
    * **文件名 (`target['filename']`):**  输出的实际二进制文件名，反映了文件系统的组织方式。
    * **编译器和链接器信息 (`compilers`):** 编译器和链接器是将源代码转换为机器码的关键工具，其工作原理直接涉及二进制文件的结构。

* **Linux:**
    * **共享库 (`target['type'] == 'shared_library'`):**  Linux 系统中动态链接库的概念。
    * **依赖关系 (`dependencies`):**  反映了 Linux 系统中库的加载和链接机制。
    * **安装路径 (`install_filename`):**  可能涉及到 Linux 系统中标准的安装目录，例如 `/usr/lib`, `/usr/bin` 等。

* **Android 内核及框架 (间接):**
    * 虽然代码没有直接提及 Android 特有的概念，但 Frida 本身常用于 Android 平台的动态 instrumentation。通过 `mintro.py` 了解 Frida 相关组件的构建信息，有助于理解 Frida 在 Android 系统中的工作方式。例如，了解 Frida Agent 的构建依赖，可以帮助理解其与 Android 框架的交互方式。

**逻辑推理及假设输入与输出：**

脚本中存在一些逻辑推理，主要是根据 Meson 的内部数据结构来推断和组织输出信息。

**假设输入:**  在一个已经成功配置（`meson setup`）的 Frida 项目的构建目录下运行该脚本。

**输出示例 (部分):**

假设运行 `python mintro.py --targets`

```json
[
  {
    "name": "frida-agent",
    "id": "frida-agent@sha",
    "type": "shared_library",
    "defined_in": "/path/to/frida/src/agent/meson.build",
    "filename": [
      "meson-out/src/agent/libfrida-agent.so"
    ],
    "build_by_default": true,
    "target_sources": [
      // ... 编译器和源文件信息
    ],
    "depends": [
      "frida-core@sha"
    ],
    "extra_files": [],
    "subproject": null,
    "installed": true,
    "install_filename": [
      "/usr/local/lib/libfrida-agent.so"
    ]
  },
  // ... 其他目标
]
```

**逻辑推理的例子：**

* **`list_targets` 函数:**  遍历 `builddata.get_targets()` 获取所有目标，并根据目标类型、输出文件等信息构建 JSON 输出。这里假设 `builddata` 对象包含了完整的构建目标信息。
* **`list_dependencies` 函数:**  遍历 `coredata.deps.host.values()` 获取主机平台的依赖，并从中提取名称、版本等信息。假设 `coredata.deps.host` 包含了所有主机平台的依赖项。

**用户或编程常见的使用错误及举例说明：**

1. **在非构建目录下运行:**
   * **错误:** 如果在没有运行 `meson setup` 的源代码目录下运行该脚本，它将无法找到必要的构建信息文件。
   * **现象:** 可能会输出错误信息，例如 "Current directory is not a meson build directory."

2. **指定错误的构建目录:**
   * **错误:**  使用 `-Dbuilddir=/wrong/path` 参数指定了错误的构建目录。
   * **现象:**  脚本无法找到 `meson-info.json` 或其他必要的内部文件，导致信息提取失败。

3. **请求不存在的信息类型:**
   * **错误:**  使用了一个不存在的命令行参数，例如 `--nonexistent-info`.
   * **现象:** `argparse` 会处理这种情况，通常会显示帮助信息或报错。

4. **依赖于特定的后端，但使用了错误的后端参数：**
   * **错误:**  某些信息提取可能依赖于特定的构建后端（例如，Ninja）。如果使用 `--backend=other` 但请求的信息是 Ninja 特有的，可能会得到不完整或错误的输出。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **用户安装了 Frida:**  首先，用户需要安装 Frida 动态 instrumentation 工具。
2. **用户尝试构建 Frida 或其相关项目 (frida-qml):** 用户可能正在尝试从源代码构建 Frida 或一个使用了 Frida 的项目，例如 `frida-qml`。这通常涉及到使用 `git clone` 获取源代码，然后使用 `meson setup build` 命令配置构建环境。
3. **用户想要了解构建系统的详细信息:**  出于开发、调试或逆向的目的，用户可能需要了解构建过程中生成了哪些目标、依赖了哪些库、使用了哪些编译选项等。
4. **用户发现了 `mintro.py`:** 用户可能通过查看 Frida 的源代码，或者在搜索如何获取 Meson 构建信息时，发现了 `mintro.py` 这个脚本。
5. **用户执行 `mintro.py`:** 用户在 Frida 的构建目录下（或者指定了正确的构建目录）运行该脚本，并带上相应的命令行参数来获取所需的信息。例如：
   ```bash
   cd frida/build  # 进入 Frida 的构建目录
   python ../subprojects/frida-qml/releng/meson/mesonbuild/mintro.py --targets --dependencies
   ```

作为调试线索，如果用户报告了 `mintro.py` 的问题，例如输出了错误的信息或者无法正常工作，开发者可以按照以下步骤进行调试：

1. **确认用户是否在正确的构建目录下运行了脚本。**
2. **检查用户使用的命令行参数是否正确。**
3. **确认构建环境是否配置正确（是否成功运行了 `meson setup`）。**
4. **检查 `meson-info.json` 和 `intro-*.json` 文件是否存在且内容正确。** 这些文件是由 Meson 构建系统生成的，`mintro.py` 依赖于这些文件来提取信息。
5. **如果问题涉及到特定的信息类型，可以检查 `mintro.py` 中负责提取该信息的函数逻辑。**
6. **可以尝试手动解析 `meson-info.json` 和 `intro-*.json` 文件，看是否能找到期望的信息。** 这有助于判断是 `mintro.py` 的解析逻辑有问题，还是 Meson 构建系统生成的信息本身就不正确。

总而言之，`mintro.py` 是 Frida 项目中一个用于内省 Meson 构建系统的工具，它为开发者和逆向工程师提供了方便的方式来获取构建相关的关键信息。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/mintro.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2014-2016 The Meson development team

from __future__ import annotations

"""This is a helper script for IDE developers. It allows you to
extract information such as list of targets, files, compiler flags,
tests and so on. All output is in JSON for simple parsing.

Currently only works for the Ninja backend. Others use generated
project files and don't need this info."""

from contextlib import redirect_stdout
import collections
import dataclasses
import json
import os
from pathlib import Path, PurePath
import sys
import typing as T

from . import build, mesonlib, coredata as cdata
from .ast import IntrospectionInterpreter, BUILD_TARGET_FUNCTIONS, AstConditionLevel, AstIDGenerator, AstIndentationGenerator, AstJSONPrinter
from .backend import backends
from .dependencies import Dependency
from . import environment
from .interpreterbase import ObjectHolder
from .mesonlib import OptionKey
from .mparser import FunctionNode, ArrayNode, ArgumentNode, BaseStringNode

if T.TYPE_CHECKING:
    import argparse

    from .interpreter import Interpreter
    from .mparser import BaseNode

def get_meson_info_file(info_dir: str) -> str:
    return os.path.join(info_dir, 'meson-info.json')

def get_meson_introspection_version() -> str:
    return '1.0.0'

def get_meson_introspection_required_version() -> T.List[str]:
    return ['>=1.0', '<2.0']

class IntroCommand:
    def __init__(self,
                 desc: str,
                 func: T.Optional[T.Callable[[], T.Union[dict, list]]] = None,
                 no_bd: T.Optional[T.Callable[[IntrospectionInterpreter], T.Union[dict, list]]] = None) -> None:
        self.desc = desc + '.'
        self.func = func
        self.no_bd = no_bd

def get_meson_introspection_types(coredata: T.Optional[cdata.CoreData] = None,
                                  builddata: T.Optional[build.Build] = None,
                                  backend: T.Optional[backends.Backend] = None) -> 'T.Mapping[str, IntroCommand]':
    if backend and builddata:
        benchmarkdata = backend.create_test_serialisation(builddata.get_benchmarks())
        testdata = backend.create_test_serialisation(builddata.get_tests())
        installdata = backend.create_install_data()
        interpreter = backend.interpreter
    else:
        benchmarkdata = testdata = installdata = None

    # Enforce key order for argparse
    return collections.OrderedDict([
        ('ast', IntroCommand('Dump the AST of the meson file', no_bd=dump_ast)),
        ('benchmarks', IntroCommand('List all benchmarks', func=lambda: list_benchmarks(benchmarkdata))),
        ('buildoptions', IntroCommand('List all build options', func=lambda: list_buildoptions(coredata), no_bd=list_buildoptions_from_source)),
        ('buildsystem_files', IntroCommand('List files that make up the build system', func=lambda: list_buildsystem_files(builddata, interpreter))),
        ('compilers', IntroCommand('List used compilers', func=lambda: list_compilers(coredata))),
        ('dependencies', IntroCommand('List external dependencies', func=lambda: list_deps(coredata, backend), no_bd=list_deps_from_source)),
        ('scan_dependencies', IntroCommand('Scan for dependencies used in the meson.build file', no_bd=list_deps_from_source)),
        ('installed', IntroCommand('List all installed files and directories', func=lambda: list_installed(installdata))),
        ('install_plan', IntroCommand('List all installed files and directories with their details', func=lambda: list_install_plan(installdata))),
        ('machines', IntroCommand('Information about host, build, and target machines', func=lambda: list_machines(builddata))),
        ('projectinfo', IntroCommand('Information about projects', func=lambda: list_projinfo(builddata), no_bd=list_projinfo_from_source)),
        ('targets', IntroCommand('List top level targets', func=lambda: list_targets(builddata, installdata, backend), no_bd=list_targets_from_source)),
        ('tests', IntroCommand('List all unit tests', func=lambda: list_tests(testdata))),
    ])

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: argparse.ArgumentParser) -> None:
    intro_types = get_meson_introspection_types()
    for key, val in intro_types.items():
        flag = '--' + key.replace('_', '-')
        parser.add_argument(flag, action='store_true', dest=key, default=False, help=val.desc)

    parser.add_argument('--backend', choices=sorted(cdata.backendlist), dest='backend', default='ninja',
                        help='The backend to use for the --buildoptions introspection.')
    parser.add_argument('-a', '--all', action='store_true', dest='all', default=False,
                        help='Print all available information.')
    parser.add_argument('-i', '--indent', action='store_true', dest='indent', default=False,
                        help='Enable pretty printed JSON.')
    parser.add_argument('-f', '--force-object-output', action='store_true', dest='force_dict', default=False,
                        help='Always use the new JSON format for multiple entries (even for 0 and 1 introspection commands)')
    parser.add_argument('builddir', nargs='?', default='.', help='The build directory')

def dump_ast(intr: IntrospectionInterpreter) -> T.Dict[str, T.Any]:
    printer = AstJSONPrinter()
    intr.ast.accept(printer)
    return printer.result

def list_installed(installdata: backends.InstallData) -> T.Dict[str, str]:
    res = {}
    if installdata is not None:
        for t in installdata.targets:
            res[os.path.join(installdata.build_dir, t.fname)] = \
                os.path.join(installdata.prefix, t.outdir, os.path.basename(t.fname))
        for i in installdata.data:
            res[i.path] = os.path.join(installdata.prefix, i.install_path)
        for i in installdata.headers:
            res[i.path] = os.path.join(installdata.prefix, i.install_path, os.path.basename(i.path))
        for i in installdata.man:
            res[i.path] = os.path.join(installdata.prefix, i.install_path)
        for i in installdata.install_subdirs:
            res[i.path] = os.path.join(installdata.prefix, i.install_path)
        for s in installdata.symlinks:
            basename = os.path.basename(s.name)
            res[basename] = os.path.join(installdata.prefix, s.install_path, basename)
    return res

def list_install_plan(installdata: backends.InstallData) -> T.Dict[str, T.Dict[str, T.Dict[str, T.Optional[str]]]]:
    plan: T.Dict[str, T.Dict[str, T.Dict[str, T.Optional[str]]]] = {
        'targets': {
            os.path.join(installdata.build_dir, target.fname): {
                'destination': target.out_name,
                'tag': target.tag or None,
                'subproject': target.subproject or None,
            }
            for target in installdata.targets
        },
    }
    for key, data_list in {
        'data': installdata.data,
        'man': installdata.man,
        'headers': installdata.headers,
        'install_subdirs': installdata.install_subdirs
    }.items():
        # Mypy doesn't recognize SubdirInstallData as a subclass of InstallDataBase
        for data in data_list: # type: ignore[attr-defined]
            data_type = data.data_type or key
            install_path_name = data.install_path_name
            if key == 'headers':  # in the headers, install_path_name is the directory
                install_path_name = os.path.join(install_path_name, os.path.basename(data.path))

            entry = {
                'destination': install_path_name,
                'tag': data.tag or None,
                'subproject': data.subproject or None,
            }

            if key == 'install_subdirs':
                exclude_files, exclude_dirs = data.exclude or ([], [])
                entry['exclude_dirs'] = list(exclude_dirs)
                entry['exclude_files'] = list(exclude_files)

            plan[data_type] = plan.get(data_type, {})
            plan[data_type][data.path] = entry

    return plan

def get_target_dir(coredata: cdata.CoreData, subdir: str) -> str:
    if coredata.get_option(OptionKey('layout')) == 'flat':
        return 'meson-out'
    else:
        return subdir

def list_targets_from_source(intr: IntrospectionInterpreter) -> T.List[T.Dict[str, T.Union[bool, str, T.List[T.Union[str, T.Dict[str, T.Union[str, T.List[str], bool]]]]]]]:
    tlist: T.List[T.Dict[str, T.Union[bool, str, T.List[T.Union[str, T.Dict[str, T.Union[str, T.List[str], bool]]]]]]] = []
    root_dir = Path(intr.source_root)

    def nodes_to_paths(node_list: T.List[BaseNode]) -> T.List[Path]:
        res: T.List[Path] = []
        for n in node_list:
            args: T.List[BaseNode] = []
            if isinstance(n, FunctionNode):
                args = list(n.args.arguments)
                if n.func_name.value in BUILD_TARGET_FUNCTIONS:
                    args.pop(0)
            elif isinstance(n, ArrayNode):
                args = n.args.arguments
            elif isinstance(n, ArgumentNode):
                args = n.arguments
            for j in args:
                if isinstance(j, BaseStringNode):
                    assert isinstance(j.value, str)
                    res += [Path(j.value)]
                elif isinstance(j, str):
                    res += [Path(j)]
        res = [root_dir / i['subdir'] / x for x in res]
        res = [x.resolve() for x in res]
        return res

    for i in intr.targets:
        sources = nodes_to_paths(i['sources'])
        extra_f = nodes_to_paths(i['extra_files'])
        outdir = get_target_dir(intr.coredata, i['subdir'])

        tlist += [{
            'name': i['name'],
            'id': i['id'],
            'type': i['type'],
            'defined_in': i['defined_in'],
            'filename': [os.path.join(outdir, x) for x in i['outputs']],
            'build_by_default': i['build_by_default'],
            'target_sources': [{
                'language': 'unknown',
                'compiler': [],
                'parameters': [],
                'sources': [str(x) for x in sources],
                'generated_sources': []
            }],
            'depends': [],
            'extra_files': [str(x) for x in extra_f],
            'subproject': None, # Subprojects are not supported
            'installed': i['installed']
        }]

    return tlist

def list_targets(builddata: build.Build, installdata: backends.InstallData, backend: backends.Backend) -> T.List[T.Any]:
    tlist: T.List[T.Any] = []
    build_dir = builddata.environment.get_build_dir()
    src_dir = builddata.environment.get_source_dir()

    # Fast lookup table for installation files
    install_lookuptable = {}
    for i in installdata.targets:
        basename = os.path.basename(i.fname)
        install_lookuptable[basename] = [str(PurePath(installdata.prefix, i.outdir, basename))]
    for s in installdata.symlinks:
        # Symlink's target must already be in the table. They share the same list
        # to support symlinks to symlinks recursively, such as .so -> .so.0 -> .so.1.2.3
        basename = os.path.basename(s.name)
        try:
            install_lookuptable[basename] = install_lookuptable[os.path.basename(s.target)]
            install_lookuptable[basename].append(str(PurePath(installdata.prefix, s.install_path, basename)))
        except KeyError:
            pass

    for (idname, target) in builddata.get_targets().items():
        if not isinstance(target, build.Target):
            raise RuntimeError('The target object in `builddata.get_targets()` is not of type `build.Target`. Please file a bug with this error message.')

        outdir = get_target_dir(builddata.environment.coredata, target.get_output_subdir())
        t = {
            'name': target.get_basename(),
            'id': idname,
            'type': target.get_typename(),
            'defined_in': os.path.normpath(os.path.join(src_dir, target.get_source_subdir(), environment.build_filename)),
            'filename': [os.path.join(build_dir, outdir, x) for x in target.get_outputs()],
            'build_by_default': target.build_by_default,
            'target_sources': backend.get_introspection_data(idname, target),
            'extra_files': [os.path.normpath(os.path.join(src_dir, x.subdir, x.fname)) for x in target.extra_files],
            'subproject': target.subproject or None,
            'dependencies': [d.name for d in getattr(target, 'external_deps', [])],
            'depends': [lib.get_id() for lib in getattr(target, 'dependencies', [])]
        }

        vs_module_defs = getattr(target, 'vs_module_defs', None)
        if vs_module_defs is not None:
            t['vs_module_defs'] = vs_module_defs.relative_name()
        win_subsystem = getattr(target, 'win_subsystem', None)
        if win_subsystem is not None:
            t['win_subsystem'] = win_subsystem

        if installdata and target.should_install():
            t['installed'] = True
            ifn = [install_lookuptable.get(x, [None]) for x in target.get_outputs()]
            t['install_filename'] = [x for sublist in ifn for x in sublist]  # flatten the list
        else:
            t['installed'] = False
        tlist.append(t)
    return tlist

def list_buildoptions_from_source(intr: IntrospectionInterpreter) -> T.List[T.Dict[str, T.Union[str, bool, int, T.List[str]]]]:
    subprojects = [i['name'] for i in intr.project_data['subprojects']]
    return list_buildoptions(intr.coredata, subprojects)

def list_buildoptions(coredata: cdata.CoreData, subprojects: T.Optional[T.List[str]] = None) -> T.List[T.Dict[str, T.Union[str, bool, int, T.List[str]]]]:
    optlist: T.List[T.Dict[str, T.Union[str, bool, int, T.List[str]]]] = []
    subprojects = subprojects or []

    dir_option_names = set(cdata.BUILTIN_DIR_OPTIONS)
    test_option_names = {OptionKey('errorlogs'),
                         OptionKey('stdsplit')}

    dir_options: 'cdata.MutableKeyedOptionDictType' = {}
    test_options: 'cdata.MutableKeyedOptionDictType' = {}
    core_options: 'cdata.MutableKeyedOptionDictType' = {}
    for k, v in coredata.options.items():
        if k in dir_option_names:
            dir_options[k] = v
        elif k in test_option_names:
            test_options[k] = v
        elif k.is_builtin():
            core_options[k] = v
            if not v.yielding:
                for s in subprojects:
                    core_options[k.evolve(subproject=s)] = v

    def add_keys(options: 'cdata.KeyedOptionDictType', section: str) -> None:
        for key, opt in sorted(options.items()):
            optdict = {'name': str(key), 'value': opt.value, 'section': section,
                       'machine': key.machine.get_lower_case_name() if coredata.is_per_machine_option(key) else 'any'}
            if isinstance(opt, cdata.UserStringOption):
                typestr = 'string'
            elif isinstance(opt, cdata.UserBooleanOption):
                typestr = 'boolean'
            elif isinstance(opt, cdata.UserComboOption):
                optdict['choices'] = opt.choices
                typestr = 'combo'
            elif isinstance(opt, cdata.UserIntegerOption):
                typestr = 'integer'
            elif isinstance(opt, cdata.UserArrayOption):
                typestr = 'array'
                if opt.choices:
                    optdict['choices'] = opt.choices
            else:
                raise RuntimeError("Unknown option type")
            optdict['type'] = typestr
            optdict['description'] = opt.description
            optlist.append(optdict)

    add_keys(core_options, 'core')
    add_keys({k: v for k, v in coredata.options.items() if k.is_backend()}, 'backend')
    add_keys({k: v for k, v in coredata.options.items() if k.is_base()}, 'base')
    add_keys(
        {k: v for k, v in sorted(coredata.options.items(), key=lambda i: i[0].machine) if k.is_compiler()},
        'compiler',
    )
    add_keys(dir_options, 'directory')
    add_keys({k: v for k, v in coredata.options.items() if k.is_project()}, 'user')
    add_keys(test_options, 'test')
    return optlist

def find_buildsystem_files_list(src_dir: str) -> T.List[str]:
    build_files = frozenset({'meson.build', 'meson.options', 'meson_options.txt'})
    # I feel dirty about this. But only slightly.
    filelist: T.List[str] = []
    for root, _, files in os.walk(src_dir):
        filelist.extend(os.path.relpath(os.path.join(root, f), src_dir)
                        for f in build_files.intersection(files))
    return filelist

def list_buildsystem_files(builddata: build.Build, interpreter: Interpreter) -> T.List[str]:
    src_dir = builddata.environment.get_source_dir()
    filelist = list(interpreter.get_build_def_files())
    filelist = [PurePath(src_dir, x).as_posix() for x in filelist]
    return filelist

def list_compilers(coredata: cdata.CoreData) -> T.Dict[str, T.Dict[str, T.Dict[str, str]]]:
    compilers: T.Dict[str, T.Dict[str, T.Dict[str, str]]] = {}
    for machine in ('host', 'build'):
        compilers[machine] = {}
        for language, compiler in getattr(coredata.compilers, machine).items():
            compilers[machine][language] = {
                'id': compiler.get_id(),
                'exelist': compiler.get_exelist(),
                'linker_exelist': compiler.get_linker_exelist(),
                'file_suffixes': compiler.file_suffixes,
                'default_suffix': compiler.get_default_suffix(),
                'version': compiler.version,
                'full_version': compiler.full_version,
                'linker_id': compiler.get_linker_id(),
            }
    return compilers

def list_deps_from_source(intr: IntrospectionInterpreter) -> T.List[T.Dict[str, T.Union[str, bool]]]:
    result: T.List[T.Dict[str, T.Union[str, bool]]] = []
    for i in intr.dependencies:
        keys = [
            'name',
            'required',
            'version',
            'has_fallback',
            'conditional',
        ]
        result += [{k: v for k, v in i.items() if k in keys}]
    return result

def list_deps(coredata: cdata.CoreData, backend: backends.Backend) -> T.List[T.Dict[str, T.Union[str, T.List[str]]]]:
    result: T.Dict[str, T.Dict[str, T.Union[str, T.List[str]]]] = {}

    def _src_to_str(src_file: T.Union[mesonlib.FileOrString, build.CustomTarget, build.StructuredSources, build.CustomTargetIndex, build.GeneratedList]) -> T.List[str]:
        if isinstance(src_file, str):
            return [src_file]
        if isinstance(src_file, mesonlib.File):
            return [src_file.absolute_path(backend.source_dir, backend.build_dir)]
        if isinstance(src_file, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)):
            return src_file.get_outputs()
        if isinstance(src_file, build.StructuredSources):
            return [f for s in src_file.as_list() for f in _src_to_str(s)]
        raise mesonlib.MesonBugException(f'Invalid file type {type(src_file)}.')

    def _create_result(d: Dependency, varname: T.Optional[str] = None) -> T.Dict[str, T.Any]:
        return {
            'name': d.name,
            'type': d.type_name,
            'version': d.get_version(),
            'compile_args': d.get_compile_args(),
            'link_args': d.get_link_args(),
            'include_directories': [i for idirs in d.get_include_dirs() for i in idirs.to_string_list(backend.source_dir, backend.build_dir)],
            'sources': [f for s in d.get_sources() for f in _src_to_str(s)],
            'extra_files': [f for s in d.get_extra_files() for f in _src_to_str(s)],
            'dependencies': [e.name for e in d.ext_deps],
            'depends': [lib.get_id() for lib in getattr(d, 'libraries', [])],
            'meson_variables': [varname] if varname else [],
        }

    for d in coredata.deps.host.values():
        if d.found():
            result[d.name] = _create_result(d)

    for varname, holder in backend.interpreter.variables.items():
        if isinstance(holder, ObjectHolder):
            d = holder.held_object
            if isinstance(d, Dependency) and d.found():
                if d.name in result:
                    T.cast('T.List[str]', result[d.name]['meson_variables']).append(varname)
                else:
                    result[d.name] = _create_result(d, varname)

    return list(result.values())

def get_test_list(testdata: T.List[backends.TestSerialisation]) -> T.List[T.Dict[str, T.Union[str, int, T.List[str], T.Dict[str, str]]]]:
    result: T.List[T.Dict[str, T.Union[str, int, T.List[str], T.Dict[str, str]]]] = []
    for t in testdata:
        to: T.Dict[str, T.Union[str, int, T.List[str], T.Dict[str, str]]] = {}
        if isinstance(t.fname, str):
            fname = [t.fname]
        else:
            fname = t.fname
        to['cmd'] = fname + t.cmd_args
        if isinstance(t.env, mesonlib.EnvironmentVariables):
            to['env'] = t.env.get_env({})
        else:
            to['env'] = t.env
        to['name'] = t.name
        to['workdir'] = t.workdir
        to['timeout'] = t.timeout
        to['suite'] = t.suite
        to['is_parallel'] = t.is_parallel
        to['priority'] = t.priority
        to['protocol'] = str(t.protocol)
        to['depends'] = t.depends
        to['extra_paths'] = t.extra_paths
        result.append(to)
    return result

def list_tests(testdata: T.List[backends.TestSerialisation]) -> T.List[T.Dict[str, T.Union[str, int, T.List[str], T.Dict[str, str]]]]:
    return get_test_list(testdata)

def list_benchmarks(benchdata: T.List[backends.TestSerialisation]) -> T.List[T.Dict[str, T.Union[str, int, T.List[str], T.Dict[str, str]]]]:
    return get_test_list(benchdata)

def list_machines(builddata: build.Build) -> T.Dict[str, T.Dict[str, T.Union[str, bool]]]:
    machines: T.Dict[str, T.Dict[str, T.Union[str, bool]]] = {}
    for m in ('host', 'build', 'target'):
        machine = getattr(builddata.environment.machines, m)
        machines[m] = dataclasses.asdict(machine)
        machines[m]['is_64_bit'] = machine.is_64_bit
        machines[m]['exe_suffix'] = machine.get_exe_suffix()
        machines[m]['object_suffix'] = machine.get_object_suffix()
    return machines

def list_projinfo(builddata: build.Build) -> T.Dict[str, T.Union[str, T.List[T.Dict[str, str]]]]:
    result: T.Dict[str, T.Union[str, T.List[T.Dict[str, str]]]] = {
        'version': builddata.project_version,
        'descriptive_name': builddata.project_name,
        'subproject_dir': builddata.subproject_dir,
    }
    subprojects = []
    for k, v in builddata.subprojects.host.items():
        c: T.Dict[str, str] = {
            'name': k,
            'version': v,
            'descriptive_name': builddata.projects.host.get(k),
        }
        subprojects.append(c)
    result['subprojects'] = subprojects
    return result

def list_projinfo_from_source(intr: IntrospectionInterpreter) -> T.Dict[str, T.Union[str, T.List[T.Dict[str, str]]]]:
    sourcedir = intr.source_root
    files = find_buildsystem_files_list(sourcedir)
    files = [os.path.normpath(x) for x in files]

    for i in intr.project_data['subprojects']:
        basedir = os.path.join(intr.subproject_dir, i['name'])
        i['buildsystem_files'] = [x for x in files if x.startswith(basedir)]
        files = [x for x in files if not x.startswith(basedir)]

    intr.project_data['buildsystem_files'] = files
    intr.project_data['subproject_dir'] = intr.subproject_dir
    return intr.project_data

def print_results(options: argparse.Namespace, results: T.Sequence[T.Tuple[str, T.Union[dict, T.List[T.Any]]]], indent: T.Optional[int]) -> int:
    if not results and not options.force_dict:
        print('No command specified')
        return 1
    elif len(results) == 1 and not options.force_dict:
        # Make to keep the existing output format for a single option
        print(json.dumps(results[0][1], indent=indent))
    else:
        out = {}
        for i in results:
            out[i[0]] = i[1]
        print(json.dumps(out, indent=indent))
    return 0

def get_infodir(builddir: T.Optional[str] = None) -> str:
    infodir = 'meson-info'
    if builddir is not None:
        infodir = os.path.join(builddir, infodir)
    return infodir

def get_info_file(infodir: str, kind: T.Optional[str] = None) -> str:
    return os.path.join(infodir,
                        'meson-info.json' if not kind else f'intro-{kind}.json')

def load_info_file(infodir: str, kind: T.Optional[str] = None) -> T.Any:
    with open(get_info_file(infodir, kind), encoding='utf-8') as fp:
        return json.load(fp)

def run(options: argparse.Namespace) -> int:
    datadir = 'meson-private'
    infodir = get_infodir(options.builddir)
    if options.builddir is not None:
        datadir = os.path.join(options.builddir, datadir)
    indent = 4 if options.indent else None
    results: T.List[T.Tuple[str, T.Union[dict, T.List[T.Any]]]] = []
    sourcedir = '.' if options.builddir == 'meson.build' else options.builddir[:-11]
    intro_types = get_meson_introspection_types()

    if 'meson.build' in [os.path.basename(options.builddir), options.builddir]:
        # Make sure that log entries in other parts of meson don't interfere with the JSON output
        with redirect_stdout(sys.stderr):
            backend = backends.get_backend_from_name(options.backend)
            assert backend is not None
            intr = IntrospectionInterpreter(sourcedir, '', backend.name, visitors = [AstIDGenerator(), AstIndentationGenerator(), AstConditionLevel()])
            intr.analyze()

        for key, val in intro_types.items():
            if (not options.all and not getattr(options, key, False)) or not val.no_bd:
                continue
            results += [(key, val.no_bd(intr))]
        return print_results(options, results, indent)

    try:
        raw = load_info_file(infodir)
        intro_vers = raw.get('introspection', {}).get('version', {}).get('full', '0.0.0')
    except FileNotFoundError:
        if not os.path.isdir(datadir) or not os.path.isdir(infodir):
            print('Current directory is not a meson build directory.\n'
                  'Please specify a valid build dir or change the working directory to it.')
        else:
            print('Introspection file {} does not exist.\n'
                  'It is also possible that the build directory was generated with an old\n'
                  'meson version. Please regenerate it in this case.'.format(get_info_file(infodir)))
        return 1

    vers_to_check = get_meson_introspection_required_version()
    for i in vers_to_check:
        if not mesonlib.version_compare(intro_vers, i):
            print('Introspection version {} is not supported. '
                  'The required version is: {}'
                  .format(intro_vers, ' and '.join(vers_to_check)))
            return 1

    # Extract introspection information from JSON
    for i, v in intro_types.items():
        if not v.func:
            continue
        if not options.all and not getattr(options, i, False):
            continue
        try:
            results += [(i, load_info_file(infodir, i))]
        except FileNotFoundError:
            print('Introspection file {} does not exist.'.format(get_info_file(infodir, i)))
            return 1

    return print_results(options, results, indent)

updated_introspection_files: T.List[str] = []

def write_intro_info(intro_info: T.Sequence[T.Tuple[str, T.Union[dict, T.List[T.Any]]]], info_dir: str) -> None:
    for kind, data in intro_info:
        out_file = os.path.join(info_dir, f'intro-{kind}.json')
        tmp_file = os.path.join(info_dir, 'tmp_dump.json')
        with open(tmp_file, 'w', encoding='utf-8') as fp:
            json.dump(data, fp)
            fp.flush() # Not sure if this is needed
        os.replace(tmp_file, out_file)
        updated_introspection_files.append(kind)

def generate_introspection_file(builddata: build.Build, backend: backends.Backend) -> None:
    coredata = builddata.environment.get_coredata()
    intro_types = get_meson_introspection_types(coredata=coredata, builddata=builddata, backend=backend)
    intro_info: T.List[T.Tuple[str, T.Union[dict, T.List[T.Any]]]] = []

    for key, val in intro_types.items():
        if not val.func:
            continue
        intro_info += [(key, val.func())]

    write_intro_info(intro_info, builddata.environment.info_dir)

def update_build_options(coredata: cdata.CoreData, info_dir: str) -> None:
    intro_info = [
        ('buildoptions', list_buildoptions(coredata))
    ]

    write_intro_info(intro_info, info_dir)

def split_version_string(version: str) -> T.Dict[str, T.Union[str, int]]:
    vers_list = version.split('.')
    return {
        'full': version,
        'major': int(vers_list[0] if len(vers_list) > 0 else 0),
        'minor': int(vers_list[1] if len(vers_list) > 1 else 0),
        'patch': int(vers_list[2] if len(vers_list) > 2 else 0)
    }

def write_meson_info_file(builddata: build.Build, errors: list, build_files_updated: bool = False) -> None:
    info_dir = builddata.environment.info_dir
    info_file = get_meson_info_file(info_dir)
    intro_types = get_meson_introspection_types()
    intro_info = {}

    for i, v in intro_types.items():
        if not v.func:
            continue
        intro_info[i] = {
            'file': f'intro-{i}.json',
            'updated': i in updated_introspection_files
        }

    info_data = {
        'meson_version': split_version_string(cdata.version),
        'directories': {
            'source': builddata.environment.get_source_dir(),
            'build': builddata.environment.get_build_dir(),
            'info': info_dir,
        },
        'introspection': {
            'version': split_version_string(get_meson_introspection_version()),
            'information': intro_info,
        },
        'build_files_updated': build_files_updated,
    }

    if errors:
        info_data['error'] = True
        info_data['error_list'] = [x if isinstance(x, str) else str(x) for x in errors]
    else:
        info_data['error'] = False

    # Write the data to disc
    tmp_file = os.path.join(info_dir, 'tmp_dump.json')
    with open(tmp_file, 'w', encoding='utf-8') as fp:
        json.dump(info_data, fp)
        fp.flush()
    os.replace(tmp_file, info_file)
```