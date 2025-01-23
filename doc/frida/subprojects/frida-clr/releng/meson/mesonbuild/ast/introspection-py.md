Response:
Let's break down the request and the provided Python code to generate a comprehensive answer.

**1. Understanding the Goal:**

The core request is to analyze the provided Python code for the `IntrospectionInterpreter` class within the Frida project. The analysis needs to cover functionality, connections to reverse engineering, low-level details (binary, kernel, etc.), logical reasoning, potential user errors, and how a user might trigger this code.

**2. Deconstructing the Code:**

I need to go through the code section by section to understand its purpose and interactions.

* **Imports:**  Identify the imported modules and their likely roles (`compilers`, `environment`, `mesonlib`, `optinterpreter`, `coredata`, `build`, `interpreterbase`, `mparser`). This gives a high-level view of the code's dependencies and context (Meson build system).
* **`IntrospectionHelper`:** This seems like a simple data structure to hold configuration related to cross-compilation and command-line options.
* **`IntrospectionInterpreter` Class:** This is the core of the code. I need to understand its methods:
    * `__init__`: Initialization, setting up the environment, options, and function mappings. Note the "stolen from interpreter.Interpreter" comment.
    * `func_project`: Processing the `project()` call in the Meson build file, handling project name, version, languages, and subprojects.
    * `do_subproject`: Recursively analyzing subprojects.
    * `func_add_languages`: Handling the `add_languages()` call.
    * `_add_languages`: Actually detecting and configuring compilers for specified languages.
    * `func_dependency`: Handling the `dependency()` call.
    * `build_target`: A central function for processing target definitions (executables, libraries, etc.). It seems to extract information about the target.
    * `build_library`:  Handles the generic `library()` call based on the default library type.
    * `func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`: These seem like wrappers around `build_target` for specific target types.
    * `is_subproject`: Checks if this interpreter is for a subproject.
    * `analyze`: Orchestrates the analysis process (loading, sanity checks, parsing, running).
    * `extract_subproject_dir`:  A quick way to get the subproject directory.

**3. Connecting to the Request's Constraints:**

Now, I need to connect the code's functionality to the specific requirements of the prompt:

* **Functionality:**  List the high-level tasks the code performs. This involves summarizing the purpose of the key methods.
* **Reverse Engineering:** Look for connections. The code parses build files, which define how software is built. This information is crucial for understanding the structure of the built software, a key aspect of reverse engineering. Consider how the extracted information (targets, dependencies) would be used in reverse engineering.
* **Binary/Low-Level/Kernel/Framework:** Frida is a dynamic instrumentation tool. While this *specific* code deals with build system introspection, it's part of the broader Frida ecosystem that *does* interact with these low-level aspects. The *build process* defines how binaries are created and linked. Dependencies point to libraries that interact with the operating system, potentially including kernel components or frameworks.
* **Logical Reasoning:**  Identify any conditional logic or decision-making processes within the code. The handling of subprojects and different target types involves logical flow. I need to consider potential inputs and the corresponding outputs.
* **User Errors:**  Think about what could go wrong from a user's perspective when using the Meson build system. Incorrect syntax in `meson.build`, missing dependencies, etc., can lead to errors during the introspection phase.
* **User Steps (Debugging):**  Imagine a developer using Frida. How might they end up needing to understand this part of the code?  Perhaps they are debugging build issues, trying to understand how Frida itself is built, or contributing to Frida's development.

**4. Structuring the Answer:**

I need to organize the information clearly and address each point of the request explicitly. I'll use headings and bullet points to enhance readability.

**5. Pre-computation and Pre-analysis (Internal Thought Process):**

* **Key Insight:** This code is *not* directly instrumenting processes. It's part of the *build system* for Frida. It analyzes the project's build definition to understand its structure and dependencies *before* the actual building happens.
* **Analogy:** Think of it like reading the blueprint of a house before construction starts. The blueprint tells you about the rooms, materials, and how they connect. This code reads the "blueprint" of the software project.
* **Focus on Introspection:**  The name "IntrospectionInterpreter" is a strong clue. It's about examining the structure and properties of the build system itself.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This code instruments build processes."  **Correction:**  No, it *analyzes* build definitions. The instrumentation happens in other parts of Frida.
* **Emphasis on Context:**  It's crucial to highlight that this is a *pre-build* step. It doesn't directly interact with running processes.
* **Connecting to Frida's Purpose:**  While the code itself isn't doing instrumentation, understanding the build process is important for a tool like Frida. It needs to know about the structure of the target applications it will instrument.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这个Python源代码文件 `introspection.py` 是 Frida 动态instrumentation 工具中，Meson 构建系统的一部分，负责在不执行实际构建的情况下，**内省（introspection）** Meson 构建文件 (`meson.build`) 的结构和定义。它的主要目的是提取关于项目的信息，例如目标（可执行文件、库等）、依赖项和项目配置选项。

以下是它的功能列表，并根据你的要求进行了详细说明：

**1. 解析 Meson 构建文件 (`meson.build`)：**

*   `IntrospectionInterpreter` 类继承自 `AstInterpreter`，它负责解析 `meson.build` 文件的抽象语法树（AST）。
*   它遍历 AST，识别特定的函数调用，例如 `project()`, `executable()`, `library()`, `dependency()` 等，这些函数定义了项目的结构和构建目标。

**2. 提取项目元数据：**

*   **`func_project()`:** 处理 `project()` 函数调用，提取项目的名称、版本和使用的编程语言。
*   它还会查找 `meson.options` 或 `meson_options.txt` 文件，并解析其中的项目选项。
*   它记录项目默认选项（`default_options`）和子项目信息。

**3. 识别构建目标：**

*   **`func_executable()`, `func_static_lib()`, `func_shared_lib()`, `func_shared_module()`, `func_library()`, `func_jar()`:** 这些函数分别处理定义不同类型构建目标的函数调用。
*   **`build_target()`:**  这是一个核心方法，被上述函数调用，用于提取构建目标的关键信息，包括名称、类型、源文件、输出路径、是否安装、构建依赖等。
*   它会递归地遍历源文件列表，解析数组、函数调用和变量引用，以找到所有相关的源文件节点。

**4. 识别依赖项：**

*   **`func_dependency()`:** 处理 `dependency()` 函数调用，提取项目依赖项的名称、是否必需、版本要求以及是否存在回退（fallback）选项。

**5. 处理编程语言：**

*   **`func_add_languages()`:** 处理 `add_languages()` 函数调用，记录项目中使用的编程语言。
*   **`_add_languages()`:**  尝试检测指定语言的编译器。即使没有构建目录，它也能尝试找到可用的编译器。

**6. 处理子项目：**

*   **`do_subproject()`:**  递归地分析子项目目录下的 `meson.build` 文件，提取子项目的信息。
*   **`extract_subproject_dir()`:**  快速提取 `project()` 函数中 `subproject_dir` 参数的值。

**与逆向的方法的关系及举例说明：**

这个文件虽然本身不执行动态 instrumentation，但它提取的信息对于逆向工程至关重要。

*   **理解软件结构:** 通过解析 `meson.build`，逆向工程师可以了解目标软件的模块划分（通过库），入口点（通过可执行文件），以及各个组件之间的依赖关系。这有助于理解软件的整体架构。
    *   **举例:** 如果逆向一个使用了多个共享库的程序，`introspection.py` 提取的库列表和它们之间的依赖关系可以帮助逆向工程师确定从哪里开始分析，以及哪些库可能包含关键功能。
*   **识别目标函数和代码:**  `introspection.py` 提取的源文件列表可以帮助逆向工程师定位特定的代码模块和函数。
    *   **举例:**  如果逆向工程师想找到处理特定网络协议的代码，他们可以通过分析 `meson.build` 中与网络相关的库或源文件来缩小搜索范围。
*   **了解构建配置:**  项目选项（通过 `meson.options`）可以影响软件的行为。逆向工程师可以通过了解这些选项来推断某些功能的启用或禁用状态。
    *   **举例:**  如果一个软件有调试模式选项，逆向工程师可以通过检查构建选项来判断目标软件是否以调试模式构建，这会影响后续的调试和分析策略。
*   **为 Frida Instrumentation 提供信息:**  虽然 `introspection.py` 不直接进行 instrumentation，但 Frida 工具链的其他部分可能会利用这些信息来确定要 hook 的目标函数、库或者理解进程的内存布局。
    *   **举例:** Frida 可以使用 `introspection.py` 提取的可执行文件名和库文件名，来定位进程空间中的目标模块，并进行函数 hook。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

虽然这个文件本身是构建系统的一部分，并不直接操作二进制或内核，但它处理的信息与这些底层概念密切相关。

*   **二进制文件类型:** 它处理不同类型的构建目标：可执行文件（可以直接运行的二进制文件）、静态库（`.a` 或 `.lib`，链接时复制到可执行文件中）、共享库（`.so` 或 `.dll`，运行时加载）。这些都是操作系统级别的二进制文件类型。
    *   **举例:**  `func_executable()` 处理生成可执行文件的配置，这最终会生成一个包含机器码的二进制文件。
*   **库依赖和链接:** 它解析库依赖关系。这些依赖关系在二进制链接阶段会用到，决定了哪些库会被链接到可执行文件或共享库中。在 Linux 和 Android 中，这涉及到共享库的加载和符号解析。
    *   **举例:**  如果 `introspection.py` 提取到某个可执行文件依赖于 `libssl.so`，这意味着在运行时，操作系统需要加载 `libssl.so` 才能正常运行该可执行文件。
*   **平台特定的构建配置:** Meson 支持交叉编译，`introspection.py` 可以处理针对不同平台（如 Linux、Android）的构建配置。这会涉及到针对特定平台的编译器和链接器选项。
    *   **举例:**  在 Android 构建中，可能需要指定 Android NDK 的路径和目标架构，这些信息可以通过 Meson 的配置传递给编译器和链接器。
*   **Android 框架 (间接):**  虽然代码没有直接涉及 Android 框架 API，但构建过程中可能会涉及到 Android SDK 或 NDK 中的库。`introspection.py` 会识别这些库作为依赖项。
    *   **举例:**  如果一个 Frida 模块需要与 Android 系统服务交互，其构建文件可能会依赖于 Android 框架提供的共享库，`introspection.py` 会提取这些依赖信息。

**逻辑推理及假设输入与输出：**

这个文件做了很多逻辑推理来解析构建文件。

**假设输入:** 一个简单的 `meson.build` 文件：

```meson
project('my_app', 'c')

executable('my_program', 'main.c', sources: ['utils.c'])

dependency('zlib')
```

**输出（部分）:**

*   `project_data`: `{'descriptive_name': 'my_app', 'version': 'undefined'}`
*   `targets`: `[{'name': 'my_program', 'type': 'executable', 'sources': [/* 指向 'main.c' 和 'utils.c' 节点的引用 */]}]`
*   `dependencies`: `[{'name': 'zlib', 'required': True, 'version': [], 'has_fallback': False, 'conditional': False, 'node': /* 指向 dependency() 调用的节点引用 */}]`

**逻辑推理示例：**

*   当遇到 `executable('my_program', 'main.c', sources: ['utils.c'])` 时，`func_executable()` 被调用，然后调用 `build_target()`。
*   `build_target()` 会解析参数，提取目标名称 `'my_program'`，类型 `'executable'`，并遍历 `sources` 参数，找到 `'main.c'` 和 `'utils.c'` 对应的 AST 节点。
*   当遇到 `dependency('zlib')` 时，`func_dependency()` 被调用，提取依赖项名称 `'zlib'`，并设置 `required` 为默认值 `True`。

**涉及用户或编程常见的使用错误及举例说明：**

*   **`InvalidArguments` 异常:**
    *   **错误:** 用户在 `project()` 函数中提供的参数不足（例如，只提供了项目名称，没有指定语言）。
    *   **用户操作:** 在 `meson.build` 中写入 `project('my_app')`。
    *   **调试线索:** 当 `IntrospectionInterpreter` 解析到 `project()` 调用时，`func_project()` 会检查参数数量，如果小于 1，则抛出 `InvalidArguments` 异常。
*   **`InvalidArguments` 异常 (再次调用 `project()`):**
    *   **错误:** 用户在一个 `meson.build` 文件中多次调用 `project()` 函数。
    *   **用户操作:** 在 `meson.build` 中写入两个 `project()` 调用。
    *   **调试线索:** `func_project()` 会检查 `self.project_node` 是否已设置。如果已设置，说明 `project()` 已经被调用过，会抛出 `InvalidArguments` 异常。
*   **依赖项名称不是字符串:**
    *   **错误:** 用户在 `dependency()` 函数中提供的依赖项名称不是字符串类型。
    *   **用户操作:** 在 `meson.build` 中写入 `dependency(123)`。
    *   **调试线索:**  `func_dependency()` 中会检查 `args[0]` 的类型，如果不是字符串，可能会导致后续处理错误或抛出异常（虽然代码中没有显式类型检查，但后续操作可能会失败）。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户不会直接与 `introspection.py` 文件交互。这个文件是 Meson 构建系统内部的一部分。以下是用户操作如何间接触发这个代码的执行，作为调试线索：

1. **用户尝试配置 Frida 项目的构建:** 用户通常会运行 `meson setup builddir` 命令来配置 Frida 项目的构建。
2. **Meson 解析构建文件:**  `meson setup` 命令会调用 Meson 构建系统，Meson 会首先解析项目根目录下的 `meson.build` 文件。
3. **`IntrospectionInterpreter` 的创建和使用:** 在解析 `meson.build` 的早期阶段，Meson 会创建 `IntrospectionInterpreter` 的实例。
4. **分析 `meson.build`:**  `IntrospectionInterpreter` 的 `analyze()` 方法会被调用，它会加载、解析和运行 `meson.build` 文件，但不会执行实际的构建命令。
5. **提取信息:**  `IntrospectionInterpreter` 会调用其内部的各种 `func_*` 方法来提取项目信息，例如 `func_project()`, `func_executable()`, `func_dependency()` 等。
6. **存储内省结果:**  提取的信息会被存储在 `IntrospectionInterpreter` 实例的成员变量中（例如 `self.project_data`, `self.targets`, `self.dependencies`）。
7. **后续使用:**  Meson 构建系统的其他部分会使用这些内省结果来生成构建系统文件（例如 Ninja 文件），用于后续的编译和链接过程。

**作为调试线索:**

*   如果用户在配置 Frida 构建时遇到错误，错误信息可能会指向 `meson.build` 文件中的特定行或函数调用。
*   开发者在调试 Frida 的构建系统时，可能会需要查看 `introspection.py` 的代码，以理解 Meson 是如何解析 `meson.build` 文件并提取信息的。
*   如果构建过程中出现了关于目标、依赖或项目选项的问题，可以追溯到 `introspection.py` 中相应的处理逻辑，查看提取的信息是否正确。
*   例如，如果一个依赖项没有被正确识别，开发者可以检查 `func_dependency()` 的实现，查看是否有逻辑错误或者对 `meson.build` 语法的理解偏差。

总而言之，`introspection.py` 是 Frida 构建过程中的一个关键组件，它负责在不执行实际构建的情况下，预先分析构建配置，为后续的构建步骤提供必要的信息。它提取的信息对于理解 Frida 的项目结构和依赖关系至关重要，也为逆向工程提供了有价值的线索。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/ast/introspection.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright © 2024 Intel Corporation

# This class contains the basic functionality needed to run any interpreter
# or an interpreter-based tool

from __future__ import annotations
import copy
import os
import typing as T

from .. import compilers, environment, mesonlib, optinterpreter
from .. import coredata as cdata
from ..build import Executable, Jar, SharedLibrary, SharedModule, StaticLibrary
from ..compilers import detect_compiler_for
from ..interpreterbase import InvalidArguments, SubProject
from ..mesonlib import MachineChoice, OptionKey
from ..mparser import BaseNode, ArithmeticNode, ArrayNode, ElementaryNode, IdNode, FunctionNode, BaseStringNode
from .interpreter import AstInterpreter

if T.TYPE_CHECKING:
    from ..build import BuildTarget
    from ..interpreterbase import TYPE_var
    from .visitor import AstVisitor


# TODO: it would be nice to not have to duplicate this
BUILD_TARGET_FUNCTIONS = [
    'executable', 'jar', 'library', 'shared_library', 'shared_module',
    'static_library', 'both_libraries'
]

class IntrospectionHelper:
    # mimic an argparse namespace
    def __init__(self, cross_file: T.Optional[str]):
        self.cross_file = [cross_file] if cross_file is not None else []
        self.native_file: T.List[str] = []
        self.cmd_line_options: T.Dict[OptionKey, str] = {}
        self.projectoptions: T.List[str] = []

    def __eq__(self, other: object) -> bool:
        return NotImplemented

class IntrospectionInterpreter(AstInterpreter):
    # Interpreter to detect the options without a build directory
    # Most of the code is stolen from interpreter.Interpreter
    def __init__(self,
                 source_root: str,
                 subdir: str,
                 backend: str,
                 visitors: T.Optional[T.List[AstVisitor]] = None,
                 cross_file: T.Optional[str] = None,
                 subproject: SubProject = SubProject(''),
                 subproject_dir: str = 'subprojects',
                 env: T.Optional[environment.Environment] = None):
        visitors = visitors if visitors is not None else []
        super().__init__(source_root, subdir, subproject, visitors=visitors)

        options = IntrospectionHelper(cross_file)
        self.cross_file = cross_file
        if env is None:
            self.environment = environment.Environment(source_root, None, options)
        else:
            self.environment = env
        self.subproject_dir = subproject_dir
        self.coredata = self.environment.get_coredata()
        self.backend = backend
        self.default_options = {OptionKey('backend'): self.backend}
        self.project_data: T.Dict[str, T.Any] = {}
        self.targets: T.List[T.Dict[str, T.Any]] = []
        self.dependencies: T.List[T.Dict[str, T.Any]] = []
        self.project_node: BaseNode = None

        self.funcs.update({
            'add_languages': self.func_add_languages,
            'dependency': self.func_dependency,
            'executable': self.func_executable,
            'jar': self.func_jar,
            'library': self.func_library,
            'project': self.func_project,
            'shared_library': self.func_shared_lib,
            'shared_module': self.func_shared_module,
            'static_library': self.func_static_lib,
            'both_libraries': self.func_both_lib,
        })

    def func_project(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        if self.project_node:
            raise InvalidArguments('Second call to project()')
        self.project_node = node
        if len(args) < 1:
            raise InvalidArguments('Not enough arguments to project(). Needs at least the project name.')

        proj_name = args[0]
        proj_vers = kwargs.get('version', 'undefined')
        proj_langs = self.flatten_args(args[1:])
        if isinstance(proj_vers, ElementaryNode):
            proj_vers = proj_vers.value
        if not isinstance(proj_vers, str):
            proj_vers = 'undefined'
        self.project_data = {'descriptive_name': proj_name, 'version': proj_vers}

        optfile = os.path.join(self.source_root, self.subdir, 'meson.options')
        if not os.path.exists(optfile):
            optfile = os.path.join(self.source_root, self.subdir, 'meson_options.txt')
        if os.path.exists(optfile):
            oi = optinterpreter.OptionInterpreter(self.subproject)
            oi.process(optfile)
            assert isinstance(proj_name, str), 'for mypy'
            self.coredata.update_project_options(oi.options, T.cast('SubProject', proj_name))

        def_opts = self.flatten_args(kwargs.get('default_options', []))
        _project_default_options = mesonlib.stringlistify(def_opts)
        self.project_default_options = cdata.create_options_dict(_project_default_options, self.subproject)
        self.default_options.update(self.project_default_options)
        self.coredata.set_default_options(self.default_options, self.subproject, self.environment)

        if not self.is_subproject() and 'subproject_dir' in kwargs:
            spdirname = kwargs['subproject_dir']
            if isinstance(spdirname, BaseStringNode):
                assert isinstance(spdirname.value, str)
                self.subproject_dir = spdirname.value
        if not self.is_subproject():
            self.project_data['subprojects'] = []
            subprojects_dir = os.path.join(self.source_root, self.subproject_dir)
            if os.path.isdir(subprojects_dir):
                for i in os.listdir(subprojects_dir):
                    if os.path.isdir(os.path.join(subprojects_dir, i)):
                        self.do_subproject(SubProject(i))

        self.coredata.init_backend_options(self.backend)
        options = {k: v for k, v in self.environment.options.items() if k.is_backend()}

        self.coredata.set_options(options)
        self._add_languages(proj_langs, True, MachineChoice.HOST)
        self._add_languages(proj_langs, True, MachineChoice.BUILD)

    def do_subproject(self, dirname: SubProject) -> None:
        subproject_dir_abs = os.path.join(self.environment.get_source_dir(), self.subproject_dir)
        subpr = os.path.join(subproject_dir_abs, dirname)
        try:
            subi = IntrospectionInterpreter(subpr, '', self.backend, cross_file=self.cross_file, subproject=dirname, subproject_dir=self.subproject_dir, env=self.environment, visitors=self.visitors)
            subi.analyze()
            subi.project_data['name'] = dirname
            self.project_data['subprojects'] += [subi.project_data]
        except (mesonlib.MesonException, RuntimeError):
            return

    def func_add_languages(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        kwargs = self.flatten_kwargs(kwargs)
        required = kwargs.get('required', True)
        assert isinstance(required, (bool, cdata.UserFeatureOption)), 'for mypy'
        if isinstance(required, cdata.UserFeatureOption):
            required = required.is_enabled()
        if 'native' in kwargs:
            native = kwargs.get('native', False)
            self._add_languages(args, required, MachineChoice.BUILD if native else MachineChoice.HOST)
        else:
            for for_machine in [MachineChoice.BUILD, MachineChoice.HOST]:
                self._add_languages(args, required, for_machine)

    def _add_languages(self, raw_langs: T.List[TYPE_var], required: bool, for_machine: MachineChoice) -> None:
        langs: T.List[str] = []
        for l in self.flatten_args(raw_langs):
            if isinstance(l, str):
                langs.append(l)
            elif isinstance(l, BaseStringNode):
                langs.append(l.value)

        for lang in sorted(langs, key=compilers.sort_clink):
            lang = lang.lower()
            if lang not in self.coredata.compilers[for_machine]:
                try:
                    comp = detect_compiler_for(self.environment, lang, for_machine, True, self.subproject)
                except mesonlib.MesonException:
                    # do we even care about introspecting this language?
                    if required:
                        raise
                    else:
                        continue
                if self.subproject:
                    options = {}
                    for k in comp.get_options():
                        v = copy.copy(self.coredata.options[k])
                        k = k.evolve(subproject=self.subproject)
                        options[k] = v
                    self.coredata.add_compiler_options(options, lang, for_machine, self.environment, self.subproject)

    def func_dependency(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> None:
        args = self.flatten_args(args)
        kwargs = self.flatten_kwargs(kwargs)
        if not args:
            return
        name = args[0]
        has_fallback = 'fallback' in kwargs
        required = kwargs.get('required', True)
        version = kwargs.get('version', [])
        if not isinstance(version, list):
            version = [version]
        if isinstance(required, ElementaryNode):
            required = required.value
        if not isinstance(required, bool):
            required = False
        self.dependencies += [{
            'name': name,
            'required': required,
            'version': version,
            'has_fallback': has_fallback,
            'conditional': node.condition_level > 0,
            'node': node
        }]

    def build_target(self, node: BaseNode, args: T.List[TYPE_var], kwargs_raw: T.Dict[str, TYPE_var], targetclass: T.Type[BuildTarget]) -> T.Optional[T.Dict[str, T.Any]]:
        args = self.flatten_args(args)
        if not args or not isinstance(args[0], str):
            return None
        name = args[0]
        srcqueue = [node]
        extra_queue = []

        # Process the sources BEFORE flattening the kwargs, to preserve the original nodes
        if 'sources' in kwargs_raw:
            srcqueue += mesonlib.listify(kwargs_raw['sources'])

        if 'extra_files' in kwargs_raw:
            extra_queue += mesonlib.listify(kwargs_raw['extra_files'])

        kwargs = self.flatten_kwargs(kwargs_raw, True)

        def traverse_nodes(inqueue: T.List[BaseNode]) -> T.List[BaseNode]:
            res: T.List[BaseNode] = []
            while inqueue:
                curr = inqueue.pop(0)
                arg_node = None
                assert isinstance(curr, BaseNode)
                if isinstance(curr, FunctionNode):
                    arg_node = curr.args
                elif isinstance(curr, ArrayNode):
                    arg_node = curr.args
                elif isinstance(curr, IdNode):
                    # Try to resolve the ID and append the node to the queue
                    assert isinstance(curr.value, str)
                    var_name = curr.value
                    if var_name in self.assignments:
                        tmp_node = self.assignments[var_name]
                        if isinstance(tmp_node, (ArrayNode, IdNode, FunctionNode)):
                            inqueue += [tmp_node]
                elif isinstance(curr, ArithmeticNode):
                    inqueue += [curr.left, curr.right]
                if arg_node is None:
                    continue
                arg_nodes = arg_node.arguments.copy()
                # Pop the first element if the function is a build target function
                if isinstance(curr, FunctionNode) and curr.func_name.value in BUILD_TARGET_FUNCTIONS:
                    arg_nodes.pop(0)
                elementary_nodes = [x for x in arg_nodes if isinstance(x, (str, BaseStringNode))]
                inqueue += [x for x in arg_nodes if isinstance(x, (FunctionNode, ArrayNode, IdNode, ArithmeticNode))]
                if elementary_nodes:
                    res += [curr]
            return res

        source_nodes = traverse_nodes(srcqueue)
        extraf_nodes = traverse_nodes(extra_queue)

        # Make sure nothing can crash when creating the build class
        kwargs_reduced = {k: v for k, v in kwargs.items() if k in targetclass.known_kwargs and k in {'install', 'build_by_default', 'build_always'}}
        kwargs_reduced = {k: v.value if isinstance(v, ElementaryNode) else v for k, v in kwargs_reduced.items()}
        kwargs_reduced = {k: v for k, v in kwargs_reduced.items() if not isinstance(v, BaseNode)}
        for_machine = MachineChoice.HOST
        objects: T.List[T.Any] = []
        empty_sources: T.List[T.Any] = []
        # Passing the unresolved sources list causes errors
        kwargs_reduced['_allow_no_sources'] = True
        target = targetclass(name, self.subdir, self.subproject, for_machine, empty_sources, None, objects,
                             self.environment, self.coredata.compilers[for_machine], self.coredata.is_build_only, kwargs_reduced)
        target.process_compilers_late()

        new_target = {
            'name': target.get_basename(),
            'id': target.get_id(),
            'type': target.get_typename(),
            'defined_in': os.path.normpath(os.path.join(self.source_root, self.subdir, environment.build_filename)),
            'subdir': self.subdir,
            'build_by_default': target.build_by_default,
            'installed': target.should_install(),
            'outputs': target.get_outputs(),
            'sources': source_nodes,
            'extra_files': extraf_nodes,
            'kwargs': kwargs,
            'node': node,
        }

        self.targets += [new_target]
        return new_target

    def build_library(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        default_library = self.coredata.get_option(OptionKey('default_library'))
        if default_library == 'shared':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif default_library == 'static':
            return self.build_target(node, args, kwargs, StaticLibrary)
        elif default_library == 'both':
            return self.build_target(node, args, kwargs, SharedLibrary)
        return None

    def func_executable(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, Executable)

    def func_static_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, StaticLibrary)

    def func_shared_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedLibrary)

    def func_both_lib(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedLibrary)

    def func_shared_module(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, SharedModule)

    def func_library(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_library(node, args, kwargs)

    def func_jar(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        return self.build_target(node, args, kwargs, Jar)

    def func_build_target(self, node: BaseNode, args: T.List[TYPE_var], kwargs: T.Dict[str, TYPE_var]) -> T.Optional[T.Dict[str, T.Any]]:
        if 'target_type' not in kwargs:
            return None
        target_type = kwargs.pop('target_type')
        if isinstance(target_type, ElementaryNode):
            target_type = target_type.value
        if target_type == 'executable':
            return self.build_target(node, args, kwargs, Executable)
        elif target_type == 'shared_library':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif target_type == 'static_library':
            return self.build_target(node, args, kwargs, StaticLibrary)
        elif target_type == 'both_libraries':
            return self.build_target(node, args, kwargs, SharedLibrary)
        elif target_type == 'library':
            return self.build_library(node, args, kwargs)
        elif target_type == 'jar':
            return self.build_target(node, args, kwargs, Jar)
        return None

    def is_subproject(self) -> bool:
        return self.subproject != ''

    def analyze(self) -> None:
        self.load_root_meson_file()
        self.sanity_check_ast()
        self.parse_project()
        self.run()

    def extract_subproject_dir(self) -> T.Optional[str]:
        '''Fast path to extract subproject_dir kwarg.
           This is faster than self.parse_project() which also initialize options
           and also calls parse_project() on every subproject.
        '''
        if not self.ast.lines:
            return None
        project = self.ast.lines[0]
        # first line is always project()
        if not isinstance(project, FunctionNode):
            return None
        for kw, val in project.args.kwargs.items():
            assert isinstance(kw, IdNode), 'for mypy'
            if kw.value == 'subproject_dir':
                # mypy does not understand "and isinstance"
                if isinstance(val, BaseStringNode):
                    return val.value
        return None
```