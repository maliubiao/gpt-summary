Response:
The user wants a summary of the functionality of the provided Python code, which is a part of the `frida-clr` project, specifically the `rewriter.py` file located in `frida/subprojects/frida-clr/releng/meson/mesonbuild/`.

The request asks for several things:
1. **List the functionalities:**  What does this script do?
2. **Relation to reverse engineering:** How does it relate to reverse engineering techniques?
3. **Involvement of low-level/kernel knowledge:** Does it interact with binary data, Linux/Android kernel, or frameworks?
4. **Logical inference:** Are there any logical deductions happening, and what are the inputs/outputs?
5. **Common user errors:** What mistakes might a user make while using it?
6. **User steps to reach this code:** How does a user's action lead to the execution of this script?
7. **Overall function (summary):** A concise description of the script's purpose.

Based on the code, the primary function of this script is to **modify Meson build files (`meson.build`)**. It provides commands to add, remove, and modify various elements within these files.

Here's a breakdown of how to address each point:

1. **Functionalities:** This is the most straightforward. I need to list the different actions the script can perform, based on the command-line arguments it accepts. Keywords like "add", "rm", "move", and the different subparsers ("target", "kwargs", "default-options", "command") will be key here.

2. **Relation to reverse engineering:**  Consider how modifying build files could be useful in a reverse engineering context. For example, adding specific source files, changing linking options, or modifying dependencies could be relevant when analyzing or instrumenting a target application.

3. **Low-level/kernel knowledge:**  The code itself doesn't seem to directly interact with kernel APIs or binary data. However, the *effects* of modifying build files can have implications for the compiled binary. For instance, linking with specific libraries or enabling certain compiler flags (which can be controlled via `default-options`) can touch upon low-level aspects. The script operates at the Meson build system level, which is a layer above direct binary manipulation.

4. **Logical inference:** The script performs logical checks and transformations based on the input commands and the structure of the Meson build file. Examples include finding specific targets or dependencies, parsing keyword arguments, and adding/removing elements from lists. I need to think of a specific command and trace the logic of how the script would handle it.

5. **Common user errors:** This will involve considering how a user might misuse the command-line interface or provide incorrect data. Examples include typos in target names, providing the wrong type of value for a keyword argument, or trying to remove a non-existent source file.

6. **User steps to reach this code:**  The script is a command-line tool. A user would typically invoke it directly, likely as part of a build process or a separate manipulation step. Understanding the context of Frida and its build system (Meson) is important here.

7. **Overall function (summary):** This should be a concise statement capturing the core purpose of the script, which is the programmatic modification of Meson build definitions.

**Mental Sandbox:**

* **Functionalities:** I can create a bulleted list based on the `add_arguments` function and the `rewriter_keys` dictionary.
* **Reverse Engineering:** Imagine a scenario where a reverse engineer wants to add a custom instrumentation library to a target. They could use this script to modify the target's `meson.build` file to link with their library.
* **Low-level:**  Think about the `default-options` subcommand. A user might use it to set compiler flags like `-fPIC` or `-m32`, which directly affect the generated binary.
* **Logical Inference:** If a user wants to add a source file to a target, the script first locates the target's definition in the AST, then finds the appropriate list of source files, and adds the new file. Input: target name, source file path. Output: modified AST with the added source.
* **User Errors:** A user might try to add a source file to a target that doesn't exist, or they might misspell a keyword argument. The script has error handling, but it's important to highlight potential user mistakes.
* **User Steps:** A developer working on Frida might want to automate the process of adding or removing dependencies. They would use the `rewriter.py` script with specific commands.
* **Overall Function:**  "A tool to programmatically edit Meson build files."

**Confidence Check:**

* Can I list the functionalities? Yes.
* Can I relate it to reverse engineering? Yes.
* Can I explain the low-level/kernel aspects? Yes, though indirectly.
* Can I provide input/output examples for logical inference? Yes.
* Can I list common user errors? Yes.
* Can I describe the user's steps? Yes.
* Can I provide an overall summary? Yes.

Strategizing complete. I will now generate the response based on the above analysis.

frida/subprojects/frida-clr/releng/meson/mesonbuild/rewriter.py 是 Frida 动态 instrumentation 工具的一个源代码文件，它的主要功能是**修改现有的 Meson 构建定义文件 (通常是 `meson.build`)**。 这使得开发者可以自动化地更改项目的构建配置，而无需手动编辑这些文件。

以下是它功能的详细列表和相关的解释：

**主要功能:**

* **添加文件到目标 (Add file to a target):**  允许向已定义的构建目标（例如可执行文件、库）添加新的源文件。
* **从目标中移除文件 (Remove files from a target):** 允许从已定义的构建目标中移除现有的源文件。
* **修改目标的关键字参数 (Modify keyword arguments):** 允许修改构建函数（例如 `executable()`, `library()`, `dependency()`）的关键字参数，例如更改依赖项、设置编译选项等。
* **修改项目默认选项 (Modify project default options):** 允许更改 `project()` 函数定义的项目级默认选项。
* **执行 JSON 命令 (Execute a JSON array of commands):**  允许通过 JSON 格式的命令批量执行上述操作。
* **获取目标或依赖的信息 (Info):**  可以获取指定目标或依赖的配置信息，例如关键字参数的值。

**与逆向方法的关联及举例说明:**

这个工具在逆向工程中可能扮演辅助角色，主要体现在以下方面：

* **添加自定义的 instrumentation 代码:** 逆向工程师可能需要在目标应用程序中插入自定义的代码来监控其行为。可以使用此工具将包含 instrumentation 代码的源文件添加到目标构建定义中，然后在重新编译后，这些代码会被包含在最终的可执行文件中。

    **举例:** 假设你想为一个名为 `my_target` 的可执行文件添加一个名为 `my_instrumentation.c` 的源文件。你可以使用如下命令：

    ```bash
    python rewriter.py target my_target add my_instrumentation.c
    ```

* **修改链接库:**  在逆向分析时，可能需要目标程序链接到特定的库，例如用于 hook 函数的库。可以使用此工具修改目标构建定义，添加或移除链接的库。

    **举例:**  假设你想让 `my_target` 链接到名为 `my_hook_library` 的静态库。你可以使用如下命令：

    ```bash
    python rewriter.py kwargs target my_target operation add kwargs 'link_with=["my_hook_library"]'
    ```

* **修改编译选项:**  为了方便调试或分析，可能需要修改编译选项，例如禁用优化、添加调试符号等。可以使用此工具修改项目的默认选项或特定目标的选项。

    **举例:**  假设你想为 `my_target` 添加 `-g` 编译选项以包含调试符号。你可以使用如下命令：

    ```bash
    python rewriter.py kwargs target my_target operation add kwargs 'c_args=["-g"]'
    ```

**涉及二进制底层、Linux/Android 内核及框架的知识的举例说明:**

虽然 `rewriter.py` 本身主要操作的是 Meson 构建文件，但它所做的更改最终会影响到编译和链接过程，从而涉及到二进制底层和操作系统层面的知识：

* **链接库 (`link_with`):**  通过添加或移除 `link_with` 关键字参数，工具会影响链接器如何将不同的目标文件和库文件组合成最终的可执行文件或库。这涉及到操作系统的动态链接器（例如 Linux 上的 `ld-linux.so`）的工作原理。在 Android 上，会涉及到 `linker`。

    **举例:**  添加一个共享库到 `link_with` 列表中，意味着最终生成的可执行文件在运行时需要找到并加载这个共享库，这依赖于操作系统的库搜索路径和加载机制。

* **编译选项 (如 `c_args`, `cpp_args`):** 通过修改这些关键字参数，可以传递特定的编译选项给底层的编译器（例如 GCC, Clang）。这些选项会直接影响生成的机器码，例如是否进行优化、是否包含调试信息、目标架构等。

    **举例:**  使用 `-fPIC` 编译选项是为了生成位置无关代码，这对于创建共享库是必要的。这个选项直接影响编译器如何生成指令。

* **目标类型 (如 `executable`, `shared_library`):**  选择不同的目标类型会指示 Meson 生成不同类型的输出文件，这依赖于底层的编译和链接工具链，以及操作系统对不同类型文件的处理方式。

    **举例:**  选择 `shared_library` 会指示 Meson 使用特定的链接器选项来生成共享库文件 (`.so` 在 Linux 上，`.dylib` 在 macOS 上，`.dll` 在 Windows 上)，这些文件具有特定的二进制结构。

**逻辑推理的假设输入与输出:**

假设有以下 `meson.build` 文件内容：

```meson
project('my_project', 'c')

executable('my_target', 'main.c', 'utils.c')
```

**假设输入:**

```bash
python rewriter.py target my_target add extra_files my_config.ini
```

**逻辑推理:**

1. 工具会解析 `meson.build` 文件，找到名为 `my_target` 的目标。
2. 工具会检查 `my_target` 的定义中是否已经存在 `extra_files` 关键字参数。
3. 如果不存在，工具会在 `executable()` 函数调用中添加 `extra_files: ['my_config.ini']`。
4. 如果存在，工具会将 `'my_config.ini'` 添加到 `extra_files` 对应的列表中。

**可能的输出 (修改后的 `meson.build` 文件内容):**

```meson
project('my_project', 'c')

executable('my_target', 'main.c', 'utils.c', extra_files: ['my_config.ini'])
```

**涉及用户或编程常见的使用错误及举例说明:**

* **目标名称拼写错误:** 用户可能会在命令行中输入错误的目標名称，导致工具无法找到目标并报错。

    **举例:**  如果目标名为 `my_app`，但用户输入 `my_ap`，工具会提示找不到名为 `my_ap` 的目标。

* **提供的源文件路径不存在:** 用户可能尝试添加一个不存在的源文件到目标。

    **举例:**  如果用户尝试添加 `non_existent.c`，但该文件不存在，工具虽然会记录该操作，但可能不会产生预期的构建结果。

* **为关键字参数提供错误类型的值:**  用户可能为某个关键字参数提供了错误类型的值，例如本应是字符串列表的参数，却提供了单个字符串。

    **举例:**  如果 `link_with` 期望一个库名称列表，用户错误地提供了 `link_with="mylib"`（字符串），工具会抛出类型错误。

* **在错误的上下文中使用操作:**  例如，尝试在 `project()` 函数上使用针对 `target` 的操作。

    **举例:**  运行 `python rewriter.py target my_project add main.c` 会因为 `my_project` 是项目名称而不是目标名称而失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接手动编写或修改 `frida/subprojects/frida-clr/releng/meson/mesonbuild/rewriter.py` 这个文件本身。 用户操作到达这里通常是通过以下步骤：

1. **用户想要修改 Frida CLR 项目的构建配置。** 这可能是为了添加自定义代码、修改依赖项、更改编译选项等目的。
2. **用户查阅 Frida CLR 的文档或 Meson 的文档，了解到可以使用 `rewriter.py` 工具来自动化这些修改。**
3. **用户在命令行中执行 `rewriter.py` 脚本，并提供相应的参数，指定要修改的目标、操作类型以及要添加或移除的文件或参数。** 例如，用户执行了类似 `python rewriter.py target my_target add my_instrumentation.c` 的命令。
4. **`rewriter.py` 脚本被 Python 解释器执行。**
5. **脚本解析命令行参数，并根据参数调用相应的处理函数（例如 `process_target`）。**
6. **脚本读取并解析 `meson.build` 文件，构建抽象语法树 (AST)。**
7. **脚本在 AST 中查找指定的目标或函数调用。**
8. **脚本根据用户的操作修改 AST。**
9. **脚本将修改后的 AST 重新格式化并写回 `meson.build` 文件。**

作为调试线索，如果构建过程出现问题，开发者可能会检查 `meson.build` 文件是否被 `rewriter.py` 脚本正确修改。 他们可以查看脚本的日志输出，或者手动检查修改后的 `meson.build` 文件，确认脚本是否按照预期执行了操作。 如果脚本执行出错，开发者可能需要查看脚本的源代码（即 `rewriter.py`）来理解其内部逻辑和错误处理机制。

**归纳一下它的功能 (第 1 部分):**

`frida/subprojects/frida-clr/releng/meson/mesonbuild/rewriter.py` 的主要功能是提供一个命令行工具，用于自动化地修改 Frida CLR 项目的 Meson 构建定义文件 (`meson.build`)。 它允许用户添加、移除目标文件，修改目标的关键字参数，以及更改项目的默认选项，从而方便地管理和调整项目的构建配置。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/rewriter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016 The Meson development team

# This tool is used to manipulate an existing Meson build definition.
#
# - add a file to a target
# - remove files from a target
# - move targets
# - reindent?
from __future__ import annotations

from .ast import IntrospectionInterpreter, BUILD_TARGET_FUNCTIONS, AstConditionLevel, AstIDGenerator, AstIndentationGenerator, AstPrinter
from mesonbuild.mesonlib import MesonException, setup_vsenv
from . import mlog, environment
from functools import wraps
from .mparser import Token, ArrayNode, ArgumentNode, AssignmentNode, BaseStringNode, BooleanNode, ElementaryNode, IdNode, FunctionNode, StringNode, SymbolNode
import json, os, re, sys
import typing as T

if T.TYPE_CHECKING:
    from argparse import ArgumentParser, HelpFormatter
    from .mparser import BaseNode

class RewriterException(MesonException):
    pass

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: ArgumentParser, formatter: T.Callable[[str], HelpFormatter]) -> None:
    parser.add_argument('-s', '--sourcedir', type=str, default='.', metavar='SRCDIR', help='Path to source directory.')
    parser.add_argument('-V', '--verbose', action='store_true', default=False, help='Enable verbose output')
    parser.add_argument('-S', '--skip-errors', dest='skip', action='store_true', default=False, help='Skip errors instead of aborting')
    subparsers = parser.add_subparsers(dest='type', title='Rewriter commands', description='Rewrite command to execute')

    # Target
    tgt_parser = subparsers.add_parser('target', aliases=['tgt'], help='Modify a target', formatter_class=formatter)
    tgt_parser.add_argument('-s', '--subdir', default='', dest='subdir', help='Subdirectory of the new target (only for the "add_target" action)')
    tgt_parser.add_argument('--type', dest='tgt_type', choices=rewriter_keys['target']['target_type'][2], default='executable',
                            help='Type of the target to add (only for the "add_target" action)')
    tgt_parser.add_argument('target', help='Name or ID of the target')
    tgt_parser.add_argument('operation', choices=['add', 'rm', 'add_target', 'rm_target', 'add_extra_files', 'rm_extra_files', 'info'],
                            help='Action to execute')
    tgt_parser.add_argument('sources', nargs='*', help='Sources to add/remove')

    # KWARGS
    kw_parser = subparsers.add_parser('kwargs', help='Modify keyword arguments', formatter_class=formatter)
    kw_parser.add_argument('operation', choices=rewriter_keys['kwargs']['operation'][2],
                           help='Action to execute')
    kw_parser.add_argument('function', choices=list(rewriter_func_kwargs.keys()),
                           help='Function type to modify')
    kw_parser.add_argument('id', help='ID of the function to modify (can be anything for "project")')
    kw_parser.add_argument('kwargs', nargs='*', help='Pairs of keyword and value')

    # Default options
    def_parser = subparsers.add_parser('default-options', aliases=['def'], help='Modify the project default options', formatter_class=formatter)
    def_parser.add_argument('operation', choices=rewriter_keys['default_options']['operation'][2],
                            help='Action to execute')
    def_parser.add_argument('options', nargs='*', help='Key, value pairs of configuration option')

    # JSON file/command
    cmd_parser = subparsers.add_parser('command', aliases=['cmd'], help='Execute a JSON array of commands', formatter_class=formatter)
    cmd_parser.add_argument('json', help='JSON string or file to execute')

class RequiredKeys:
    def __init__(self, keys):
        self.keys = keys

    def __call__(self, f):
        @wraps(f)
        def wrapped(*wrapped_args, **wrapped_kwargs):
            assert len(wrapped_args) >= 2
            cmd = wrapped_args[1]
            for key, val in self.keys.items():
                typ = val[0] # The type of the value
                default = val[1] # The default value -- None is required
                choices = val[2] # Valid choices -- None is for everything
                if key not in cmd:
                    if default is not None:
                        cmd[key] = default
                    else:
                        raise RewriterException('Key "{}" is missing in object for {}'
                                                .format(key, f.__name__))
                if not isinstance(cmd[key], typ):
                    raise RewriterException('Invalid type of "{}". Required is {} but provided was {}'
                                            .format(key, typ.__name__, type(cmd[key]).__name__))
                if choices is not None:
                    assert isinstance(choices, list)
                    if cmd[key] not in choices:
                        raise RewriterException('Invalid value of "{}": Possible values are {} but provided was "{}"'
                                                .format(key, choices, cmd[key]))
            return f(*wrapped_args, **wrapped_kwargs)

        return wrapped

def _symbol(val: str) -> SymbolNode:
    return SymbolNode(Token('', '', 0, 0, 0, (0, 0), val))

class MTypeBase:
    def __init__(self, node: T.Optional[BaseNode] = None):
        if node is None:
            self.node = self.new_node()
        else:
            self.node = node
        self.node_type = None
        for i in self.supported_nodes():
            if isinstance(self.node, i):
                self.node_type = i

    @classmethod
    def new_node(cls, value=None):
        # Overwrite in derived class
        raise RewriterException('Internal error: new_node of MTypeBase was called')

    @classmethod
    def supported_nodes(cls):
        # Overwrite in derived class
        return []

    def can_modify(self):
        return self.node_type is not None

    def get_node(self):
        return self.node

    def add_value(self, value):
        # Overwrite in derived class
        mlog.warning('Cannot add a value of type', mlog.bold(type(self).__name__), '--> skipping')

    def remove_value(self, value):
        # Overwrite in derived class
        mlog.warning('Cannot remove a value of type', mlog.bold(type(self).__name__), '--> skipping')

    def remove_regex(self, value):
        # Overwrite in derived class
        mlog.warning('Cannot remove a regex in type', mlog.bold(type(self).__name__), '--> skipping')

class MTypeStr(MTypeBase):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def new_node(cls, value=None):
        if value is None:
            value = ''
        return StringNode(Token('', '', 0, 0, 0, None, str(value)))

    @classmethod
    def supported_nodes(cls):
        return [StringNode]

class MTypeBool(MTypeBase):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def new_node(cls, value=None):
        return BooleanNode(Token('', '', 0, 0, 0, None, bool(value)))

    @classmethod
    def supported_nodes(cls):
        return [BooleanNode]

class MTypeID(MTypeBase):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def new_node(cls, value=None):
        if value is None:
            value = ''
        return IdNode(Token('', '', 0, 0, 0, None, str(value)))

    @classmethod
    def supported_nodes(cls):
        return [IdNode]

class MTypeList(MTypeBase):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def new_node(cls, value=None):
        if value is None:
            value = []
        elif not isinstance(value, list):
            return cls._new_element_node(value)
        args = ArgumentNode(Token('', '', 0, 0, 0, None, ''))
        args.arguments = [cls._new_element_node(i) for i in value]
        return ArrayNode(_symbol('['), args, _symbol(']'))

    @classmethod
    def _new_element_node(cls, value):
        # Overwrite in derived class
        raise RewriterException('Internal error: _new_element_node of MTypeList was called')

    def _ensure_array_node(self):
        if not isinstance(self.node, ArrayNode):
            tmp = self.node
            self.node = self.new_node()
            self.node.args.arguments = [tmp]

    @staticmethod
    def _check_is_equal(node, value) -> bool:
        # Overwrite in derived class
        return False

    @staticmethod
    def _check_regex_matches(node, regex: str) -> bool:
        # Overwrite in derived class
        return False

    def get_node(self):
        if isinstance(self.node, ArrayNode):
            if len(self.node.args.arguments) == 1:
                return self.node.args.arguments[0]
        return self.node

    @classmethod
    def supported_element_nodes(cls):
        # Overwrite in derived class
        return []

    @classmethod
    def supported_nodes(cls):
        return [ArrayNode] + cls.supported_element_nodes()

    def add_value(self, value):
        if not isinstance(value, list):
            value = [value]
        self._ensure_array_node()
        for i in value:
            self.node.args.arguments += [self._new_element_node(i)]

    def _remove_helper(self, value, equal_func):
        def check_remove_node(node):
            for j in value:
                if equal_func(i, j):
                    return True
            return False

        if not isinstance(value, list):
            value = [value]
        self._ensure_array_node()
        removed_list = []
        for i in self.node.args.arguments:
            if not check_remove_node(i):
                removed_list += [i]
        self.node.args.arguments = removed_list

    def remove_value(self, value):
        self._remove_helper(value, self._check_is_equal)

    def remove_regex(self, regex: str):
        self._remove_helper(regex, self._check_regex_matches)

class MTypeStrList(MTypeList):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def _new_element_node(cls, value):
        return StringNode(Token('', '', 0, 0, 0, None, str(value)))

    @staticmethod
    def _check_is_equal(node, value) -> bool:
        if isinstance(node, BaseStringNode):
            return node.value == value
        return False

    @staticmethod
    def _check_regex_matches(node, regex: str) -> bool:
        if isinstance(node, BaseStringNode):
            return re.match(regex, node.value) is not None
        return False

    @classmethod
    def supported_element_nodes(cls):
        return [StringNode]

class MTypeIDList(MTypeList):
    def __init__(self, node: T.Optional[BaseNode] = None):
        super().__init__(node)

    @classmethod
    def _new_element_node(cls, value):
        return IdNode(Token('', '', 0, 0, 0, None, str(value)))

    @staticmethod
    def _check_is_equal(node, value) -> bool:
        if isinstance(node, IdNode):
            return node.value == value
        return False

    @staticmethod
    def _check_regex_matches(node, regex: str) -> bool:
        if isinstance(node, BaseStringNode):
            return re.match(regex, node.value) is not None
        return False

    @classmethod
    def supported_element_nodes(cls):
        return [IdNode]

rewriter_keys = {
    'default_options': {
        'operation': (str, None, ['set', 'delete']),
        'options': (dict, {}, None)
    },
    'kwargs': {
        'function': (str, None, None),
        'id': (str, None, None),
        'operation': (str, None, ['set', 'delete', 'add', 'remove', 'remove_regex', 'info']),
        'kwargs': (dict, {}, None)
    },
    'target': {
        'target': (str, None, None),
        'operation': (str, None, ['src_add', 'src_rm', 'target_rm', 'target_add', 'extra_files_add', 'extra_files_rm', 'info']),
        'sources': (list, [], None),
        'subdir': (str, '', None),
        'target_type': (str, 'executable', ['both_libraries', 'executable', 'jar', 'library', 'shared_library', 'shared_module', 'static_library']),
    }
}

rewriter_func_kwargs = {
    'dependency': {
        'language': MTypeStr,
        'method': MTypeStr,
        'native': MTypeBool,
        'not_found_message': MTypeStr,
        'required': MTypeBool,
        'static': MTypeBool,
        'version': MTypeStrList,
        'modules': MTypeStrList
    },
    'target': {
        'build_by_default': MTypeBool,
        'build_rpath': MTypeStr,
        'dependencies': MTypeIDList,
        'gui_app': MTypeBool,
        'link_with': MTypeIDList,
        'export_dynamic': MTypeBool,
        'implib': MTypeBool,
        'install': MTypeBool,
        'install_dir': MTypeStr,
        'install_rpath': MTypeStr,
        'pie': MTypeBool
    },
    'project': {
        'default_options': MTypeStrList,
        'meson_version': MTypeStr,
        'license': MTypeStrList,
        'subproject_dir': MTypeStr,
        'version': MTypeStr
    }
}

class Rewriter:
    def __init__(self, sourcedir: str, generator: str = 'ninja', skip_errors: bool = False):
        self.sourcedir = sourcedir
        self.interpreter = IntrospectionInterpreter(sourcedir, '', generator, visitors = [AstIDGenerator(), AstIndentationGenerator(), AstConditionLevel()])
        self.skip_errors = skip_errors
        self.modified_nodes = []
        self.to_remove_nodes = []
        self.to_add_nodes = []
        self.functions = {
            'default_options': self.process_default_options,
            'kwargs': self.process_kwargs,
            'target': self.process_target,
        }
        self.info_dump = None

    def analyze_meson(self):
        mlog.log('Analyzing meson file:', mlog.bold(os.path.join(self.sourcedir, environment.build_filename)))
        self.interpreter.analyze()
        mlog.log('  -- Project:', mlog.bold(self.interpreter.project_data['descriptive_name']))
        mlog.log('  -- Version:', mlog.cyan(self.interpreter.project_data['version']))

    def add_info(self, cmd_type: str, cmd_id: str, data: dict):
        if self.info_dump is None:
            self.info_dump = {}
        if cmd_type not in self.info_dump:
            self.info_dump[cmd_type] = {}
        self.info_dump[cmd_type][cmd_id] = data

    def print_info(self):
        if self.info_dump is None:
            return
        sys.stderr.write(json.dumps(self.info_dump, indent=2))

    def on_error(self):
        if self.skip_errors:
            return mlog.cyan('-->'), mlog.yellow('skipping')
        return mlog.cyan('-->'), mlog.red('aborting')

    def handle_error(self):
        if self.skip_errors:
            return None
        raise MesonException('Rewriting the meson.build failed')

    def find_target(self, target: str):
        def check_list(name: str) -> T.List[BaseNode]:
            result = []
            for i in self.interpreter.targets:
                if name in {i['name'], i['id']}:
                    result += [i]
            return result

        targets = check_list(target)
        if targets:
            if len(targets) == 1:
                return targets[0]
            else:
                mlog.error('There are multiple targets matching', mlog.bold(target))
                for i in targets:
                    mlog.error('  -- Target name', mlog.bold(i['name']), 'with ID', mlog.bold(i['id']))
                mlog.error('Please try again with the unique ID of the target', *self.on_error())
                self.handle_error()
                return None

        # Check the assignments
        tgt = None
        if target in self.interpreter.assignments:
            node = self.interpreter.assignments[target]
            if isinstance(node, FunctionNode):
                if node.func_name.value in {'executable', 'jar', 'library', 'shared_library', 'shared_module', 'static_library', 'both_libraries'}:
                    tgt = self.interpreter.assign_vals[target]

        return tgt

    def find_dependency(self, dependency: str):
        def check_list(name: str):
            for i in self.interpreter.dependencies:
                if name == i['name']:
                    return i
            return None

        dep = check_list(dependency)
        if dep is not None:
            return dep

        # Check the assignments
        if dependency in self.interpreter.assignments:
            node = self.interpreter.assignments[dependency]
            if isinstance(node, FunctionNode):
                if node.func_name.value == 'dependency':
                    name = self.interpreter.flatten_args(node.args)[0]
                    dep = check_list(name)

        return dep

    @RequiredKeys(rewriter_keys['default_options'])
    def process_default_options(self, cmd):
        # First, remove the old values
        kwargs_cmd = {
            'function': 'project',
            'id': "/",
            'operation': 'remove_regex',
            'kwargs': {
                'default_options': [f'{x}=.*' for x in cmd['options'].keys()]
            }
        }
        self.process_kwargs(kwargs_cmd)

        # Then add the new values
        if cmd['operation'] != 'set':
            return

        kwargs_cmd['operation'] = 'add'
        kwargs_cmd['kwargs']['default_options'] = []

        cdata = self.interpreter.coredata
        options = {
            **{str(k): v for k, v in cdata.options.items()},
            **{str(k): v for k, v in cdata.options.items()},
            **{str(k): v for k, v in cdata.options.items()},
            **{str(k): v for k, v in cdata.options.items()},
            **{str(k): v for k, v in cdata.options.items()},
        }

        for key, val in sorted(cmd['options'].items()):
            if key not in options:
                mlog.error('Unknown options', mlog.bold(key), *self.on_error())
                self.handle_error()
                continue

            try:
                val = options[key].validate_value(val)
            except MesonException as e:
                mlog.error('Unable to set', mlog.bold(key), mlog.red(str(e)), *self.on_error())
                self.handle_error()
                continue

            kwargs_cmd['kwargs']['default_options'] += [f'{key}={val}']

        self.process_kwargs(kwargs_cmd)

    @RequiredKeys(rewriter_keys['kwargs'])
    def process_kwargs(self, cmd):
        mlog.log('Processing function type', mlog.bold(cmd['function']), 'with id', mlog.cyan("'" + cmd['id'] + "'"))
        if cmd['function'] not in rewriter_func_kwargs:
            mlog.error('Unknown function type', cmd['function'], *self.on_error())
            return self.handle_error()
        kwargs_def = rewriter_func_kwargs[cmd['function']]

        # Find the function node to modify
        node = None
        arg_node = None
        if cmd['function'] == 'project':
            # msys bash may expand '/' to a path. It will mangle '//' to '/'
            # but in order to keep usage shell-agnostic, also allow `//` as
            # the function ID such that it will work in both msys bash and
            # other shells.
            if {'/', '//'}.isdisjoint({cmd['id']}):
                mlog.error('The ID for the function type project must be "/" or "//" not "' + cmd['id'] + '"', *self.on_error())
                return self.handle_error()
            node = self.interpreter.project_node
            arg_node = node.args
        elif cmd['function'] == 'target':
            tmp = self.find_target(cmd['id'])
            if tmp:
                node = tmp['node']
                arg_node = node.args
        elif cmd['function'] == 'dependency':
            tmp = self.find_dependency(cmd['id'])
            if tmp:
                node = tmp['node']
                arg_node = node.args
        if not node:
            mlog.error('Unable to find the function node')
        assert isinstance(node, FunctionNode)
        assert isinstance(arg_node, ArgumentNode)
        # Transform the key nodes to plain strings
        arg_node.kwargs = {k.value: v for k, v in arg_node.kwargs.items()}

        # Print kwargs info
        if cmd['operation'] == 'info':
            info_data = {}
            for key, val in sorted(arg_node.kwargs.items()):
                info_data[key] = None
                if isinstance(val, ElementaryNode):
                    info_data[key] = val.value
                elif isinstance(val, ArrayNode):
                    data_list = []
                    for i in val.args.arguments:
                        element = None
                        if isinstance(i, ElementaryNode):
                            element = i.value
                        data_list += [element]
                    info_data[key] = data_list

            self.add_info('kwargs', '{}#{}'.format(cmd['function'], cmd['id']), info_data)
            return # Nothing else to do

        # Modify the kwargs
        num_changed = 0
        for key, val in sorted(cmd['kwargs'].items()):
            if key not in kwargs_def:
                mlog.error('Cannot modify unknown kwarg', mlog.bold(key), *self.on_error())
                self.handle_error()
                continue

            if cmd['operation'] == 'delete':
                # Remove the key from the kwargs
                if key not in arg_node.kwargs:
                    mlog.log('  -- Key', mlog.bold(key), 'is already deleted')
                    continue
                mlog.log('  -- Deleting', mlog.bold(key), 'from the kwargs')
                del arg_node.kwargs[key]
            elif cmd['operation'] == 'set':
                # Replace the key from the kwargs
                mlog.log('  -- Setting', mlog.bold(key), 'to', mlog.yellow(str(val)))
                arg_node.kwargs[key] = kwargs_def[key].new_node(val)
            else:
                # Modify the value from the kwargs

                if key not in arg_node.kwargs:
                    arg_node.kwargs[key] = None
                modifier = kwargs_def[key](arg_node.kwargs[key])
                if not modifier.can_modify():
                    mlog.log('  -- Skipping', mlog.bold(key), 'because it is too complex to modify')
                    continue

                # Apply the operation
                val_str = str(val)
                if cmd['operation'] == 'add':
                    mlog.log('  -- Adding', mlog.yellow(val_str), 'to', mlog.bold(key))
                    modifier.add_value(val)
                elif cmd['operation'] == 'remove':
                    mlog.log('  -- Removing', mlog.yellow(val_str), 'from', mlog.bold(key))
                    modifier.remove_value(val)
                elif cmd['operation'] == 'remove_regex':
                    mlog.log('  -- Removing all values matching', mlog.yellow(val_str), 'from', mlog.bold(key))
                    modifier.remove_regex(val)

                # Write back the result
                arg_node.kwargs[key] = modifier.get_node()

            num_changed += 1

        # Convert the keys back to IdNode's
        arg_node.kwargs = {IdNode(Token('', '', 0, 0, 0, None, k)): v for k, v in arg_node.kwargs.items()}
        for k, v in arg_node.kwargs.items():
            k.level = v.level
        if num_changed > 0 and node not in self.modified_nodes:
            self.modified_nodes += [node]

    def find_assignment_node(self, node: BaseNode) -> AssignmentNode:
        if node.ast_id and node.ast_id in self.interpreter.reverse_assignment:
            return self.interpreter.reverse_assignment[node.ast_id]
        return None

    @RequiredKeys(rewriter_keys['target'])
    def process_target(self, cmd):
        mlog.log('Processing target', mlog.bold(cmd['target']), 'operation', mlog.cyan(cmd['operation']))
        target = self.find_target(cmd['target'])
        if target is None and cmd['operation'] != 'target_add':
            mlog.error('Unknown target', mlog.bold(cmd['target']), *self.on_error())
            return self.handle_error()

        # Make source paths relative to the current subdir
        def rel_source(src: str) -> str:
            subdir = os.path.abspath(os.path.join(self.sourcedir, target['subdir']))
            if os.path.isabs(src):
                return os.path.relpath(src, subdir)
            elif not os.path.exists(src):
                return src # Trust the user when the source doesn't exist
            # Make sure that the path is relative to the subdir
            return os.path.relpath(os.path.abspath(src), subdir)

        if target is not None:
            cmd['sources'] = [rel_source(x) for x in cmd['sources']]

        # Utility function to get a list of the sources from a node
        def arg_list_from_node(n):
            args = []
            if isinstance(n, FunctionNode):
                args = list(n.args.arguments)
                if n.func_name.value in BUILD_TARGET_FUNCTIONS:
                    args.pop(0)
            elif isinstance(n, ArrayNode):
                args = n.args.arguments
            elif isinstance(n, ArgumentNode):
                args = n.arguments
            return args

        to_sort_nodes = []

        if cmd['operation'] == 'src_add':
            node = None
            if target['sources']:
                node = target['sources'][0]
            else:
                node = target['node']
            assert node is not None

            # Generate the current source list
            src_list = []
            for i in target['sources']:
                for j in arg_list_from_node(i):
                    if isinstance(j, BaseStringNode):
                        src_list += [j.value]

            # Generate the new String nodes
            to_append = []
            for i in sorted(set(cmd['sources'])):
                if i in src_list:
                    mlog.log('  -- Source', mlog.green(i), 'is already defined for the target --> skipping')
                    continue
                mlog.log('  -- Adding source', mlog.green(i), 'at',
                         mlog.yellow(f'{node.filename}:{node.lineno}'))
                token = Token('string', node.filename, 0, 0, 0, None, i)
                to_append += [StringNode(token)]

            # Append to the AST at the right place
            arg_node = None
            if isinstance(node, (FunctionNode, ArrayNode)):
                arg_node = node.args
            elif isinstance(node, ArgumentNode):
                arg_node = node
            assert arg_node is not None
            arg_node.arguments += to_append

            # Mark the node as modified
            if arg_node not in to_sort_nodes and not isinstance(node, FunctionNode):
                to_sort_nodes += [arg_node]
            if node not in self.modified_nodes:
                self.modified_nodes += [node]

        elif cmd['operation'] == 'src_rm':
            # Helper to find the exact string node and its parent
            def find_node(src):
                for i in target['sources']:
                    for j in arg_list_from_node(i):
                        if isinstance(j, BaseStringNode):
                            if j.value == src:
                                return i, j
                return None, None

            for i in cmd['sources']:
                # Try to find the node with the source string
                root, string_node = find_node(i)
                if root is None:
                    mlog.warning('  -- Unable to find source', mlog.green(i), 'in the target')
                    continue

                # Remove the found string node from the argument list
                arg_node = None
                if isinstance(root, (FunctionNode, ArrayNode)):
                    arg_node = root.args
                elif isinstance(root, ArgumentNode):
                    arg_node = root
                assert arg_node is not None
                mlog.log('  -- Removing source', mlog.green(i), 'from',
                         mlog.yellow(f'{string_node.filename}:{string_node.lineno}'))
                arg_node.arguments.remove(string_node)

                # Mark the node as modified
                if arg_node not in to_sort_nodes and not isinstance(root, FunctionNode):
                    to_sort_nodes += [arg_node]
                if root not in self.modified_nodes:
                    self.modified_nodes += [root]

        elif cmd['operation'] == 'extra_files_add':
            tgt_function: FunctionNode = target['node']
            mark_array = True
            try:
                node = target['extra_files'][0]
            except IndexError:
                # Specifying `extra_files` with a list that flattens to empty gives an empty
                # target['extra_files'] list, account for that.
                try:
                    extra_files_key = next(k for k in tgt_function.args.kwargs.keys() if isinstance(k, IdNode) and k.value == 'extra_files')
                    node = tgt_function.args.kwargs[extra_files_key]
                except StopIteration:
                    # Target has no extra_files kwarg, create one
                    node = ArrayNode(_symbol('['), ArgumentNode(Token('', tgt_function.filename, 0, 0, 0, None, '[]')), _symbol(']'))
                    tgt_function.args.kwargs[IdNode(Token('string', tgt_function.filename, 0, 0, 0, None, 'extra_files'))] = node
                    mark_array = False
                    if tgt_function not in self.modified_nodes:
                        self.modified_nodes += [tgt_function]
                target['extra_files'] = [node]
            if isinstance(node, IdNode):
                node = self.interpreter.assignments[node.value]
                target['extra_files'] = [node]
            if not isinstance(node, ArrayNode):
                mlog.error('Target', mlog.bold(cmd['target']), 'extra_files argument must be a list', *self.on_error())
                return self.handle_error()

            # Generate the current extra files list
            extra_files_list = []
            for i in target['extra_files']:
                for j in arg_list_from_node(i):
                    if isinstance(j, BaseStringNode):
                        extra_files_list += [j.value]

            # Generate the new String nodes
            to_append = []
            for i in sorted(set(cmd['sources'])):
                if i in extra_files_list:
                    mlog.log('  -- Extra file', mlog.green(i), 'is already defined for the target --> skipping')
                    continue
                mlog.log('  -- Adding extra file', mlog.green(i), 'at',
                         mlog.yellow(f'{node.filename}:{node.lineno}'))
                token = Token('string', node.filename, 0, 0, 0, None, i)
                to_append += [StringNode(token)]

            # Append to the AST at the right place
            arg_node = node.args
            arg_node.arguments += to_append

            # Mark the node as modified
            if arg_node not in to_sort_nodes:
                to_sort_nodes += [arg_node]
            # If the extra_files array is newly created, don't mark it as its parent function node already is,
            # otherwise this would cause double modification.
            if mark_array and node not in self.modified_nodes:
                self.modified_nodes += [node]

        elif cmd['operation'] == 'extra_files_rm':
            # Helper to find the exact string node and its parent
            def find_node(src):
                for i in target['extra_files']:
                    for j in arg_list_from_node(i):
                        if isinstance(j, BaseStringNode):
                            if j.value == src:
                                return i, j
                return None, None

            for i in cmd['sources']:
                # Try to find the node with the source string
                root, string_node = find_node(i)
                if root is None:
                    mlog.warning('  -- Unable to find extra file', mlog.green(i), 'in the target')
                    continue

                # Remove the found string node from the argument list
                arg_node = root.args
                mlog.log('  -- Removing extra file', mlog.green(i), 'from',
                         mlog.yellow(f'{string_node.filename}:{string_node.lineno}'))
                arg_node.arguments.remove(string_node)

                # Mark the node as modified
                if arg_node not in to_sort_nodes and not isinstance(root, FunctionNode):
                    to_sort_nodes += [arg_node]
                if root not in self.modified_nodes:
                    self.modified_nodes += [root]

        elif cmd
"""


```