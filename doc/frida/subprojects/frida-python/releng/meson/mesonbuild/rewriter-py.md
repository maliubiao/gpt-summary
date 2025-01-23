Response:
My thinking process to analyze the provided Python code for `fridaDynamic`'s `rewriter.py` goes like this:

1. **Understand the Core Purpose:** The initial comments clearly state that this tool manipulates existing Meson build definitions. Keywords like "add," "remove," and "move" immediately point to modification of the build system's structure.

2. **Identify Key Data Structures:** I scan the code for important classes and dictionaries that hold the state or configuration. `rewriter_keys`, `rewriter_func_kwargs`, and the `Rewriter` class itself stand out. These likely define the operations possible and the structure of the Meson files being manipulated.

3. **Break Down Functionality by Command:** The `add_arguments` function is a good starting point. It shows the different subcommands (`target`, `kwargs`, `default-options`, `command`) the rewriter can handle. This helps categorize the functionality.

4. **Analyze Each Subcommand:**
    * **`target`:** This seems to deal with modifying build targets (executables, libraries, etc.). The `operation` argument lists actions like `add`, `rm`, `add_target`, `rm_target`, `add_extra_files`, `rm_extra_files`, and `info`. This suggests operations related to source files, entire targets, and extra files associated with targets.
    * **`kwargs`:**  This focuses on modifying keyword arguments of specific Meson functions. The `function` argument lists potential functions (like `dependency`, `target`, `project`), and `operation` includes `set`, `delete`, `add`, `remove`, `remove_regex`, and `info`. This implies the ability to change parameters of various build system elements.
    * **`default-options`:** This specifically addresses modifying project-wide default options. The `operation` choices are `set` and `delete`.
    * **`command`:** This allows executing a series of commands defined in a JSON format, providing a way to perform multiple operations at once.

5. **Examine the `Rewriter` Class:** This class seems to be the heart of the tool. I look at its methods:
    * `__init__`: Initializes the rewriter, including an `IntrospectionInterpreter` (suggesting it analyzes existing Meson files).
    * `analyze_meson`:  Confirms the analysis of Meson files.
    * `process_default_options`, `process_kwargs`, `process_target`: These methods correspond to the subcommands and likely contain the core logic for each operation.
    * `find_target`, `find_dependency`:  Helper methods for locating specific elements within the Meson structure.
    * Methods related to `info_dump`: Suggest the tool can provide information about the current state.
    * `on_error`, `handle_error`:  Deal with error handling.

6. **Identify Connections to Reverse Engineering and Low-Level Concepts:**
    * **Reverse Engineering:** The ability to modify build definitions is directly relevant. If a reverse engineer wants to add a custom hooking library to a target, or remove certain compiler flags, this tool could facilitate that.
    * **Binary/Low-Level:** While the tool itself doesn't manipulate binaries directly, its actions *affect* the binaries produced. Adding/removing source files, changing compiler options (via `kwargs`), or modifying linking dependencies all have low-level implications.
    * **Linux/Android:** The presence of `fridaDynamic` in the path strongly suggests a connection to these platforms. The manipulation of build targets (executables, shared libraries) is a common task in Linux/Android development.

7. **Look for Logic and Assumptions:** The `@RequiredKeys` decorator indicates input validation. The `process_*` methods contain conditional logic based on the `operation` argument. The code assumes a well-formed Meson build system to begin with.

8. **Consider User Errors:**  The code includes error handling (`try...except`, `mlog.error`). Common user errors would be:
    * Incorrect target names or IDs.
    * Invalid keyword argument names or values.
    * Specifying non-existent source files.
    * Providing malformed JSON for the `command` subcommand.

9. **Trace User Actions:**  A user would typically interact with this script via the command line. They would use `meson rewriter` followed by a subcommand and its specific arguments. The `add_arguments` function defines the structure of these commands.

10. **Summarize Functionality (as requested in the prompt):** Based on the analysis, I would then synthesize a summary of the tool's capabilities.

**Self-Correction/Refinement:** Initially, I might focus too much on the individual lines of code. However, by stepping back and looking at the overall structure (subcommands, main class methods), I can get a better understanding of the high-level functionality. Recognizing the role of `IntrospectionInterpreter` is also crucial for understanding how the tool interacts with existing Meson builds. The `RequiredKeys` decorator provides a strong hint about input validation.

好的，让我们来分析一下 `frida/subprojects/frida-python/releng/meson/mesonbuild/rewriter.py` 文件的功能。

**主要功能归纳:**

这个 Python 脚本 `rewriter.py` 是 Frida 动态 Instrumentation 工具链的一部分，它用于**修改现有的 Meson 构建定义文件 (`meson.build`)**。  其核心目标是自动化地对构建配置进行更改，而无需手动编辑 `meson.build` 文件。

**详细功能列表:**

1. **操作构建目标 (Targets):**
   - **添加源文件 (`add` 或 `src_add` 操作):** 可以向已存在的构建目标（例如可执行文件、库）添加新的源文件。
   - **移除源文件 (`rm` 或 `src_rm` 操作):** 可以从已存在的构建目标中移除指定的源文件。
   - **添加目标 (`add_target` 操作):**  可以创建新的构建目标，例如添加一个新的可执行文件或库。
   - **移除目标 (`rm_target` 操作):** 可以删除已存在的构建目标。
   - **添加额外文件 (`add_extra_files` 操作):** 可以向目标添加额外的非源代码文件，例如配置文件、资源文件等。
   - **移除额外文件 (`rm_extra_files` 操作):** 可以从目标移除指定的额外文件。
   - **获取目标信息 (`info` 操作):**  可以查看指定目标的详细信息。

2. **操作关键字参数 (Keyword Arguments - Kwargs):**
   - **设置/修改关键字参数 (`set` 操作):**  可以设置或修改 Meson 构建函数（如 `executable`, `library`, `dependency` 等）的关键字参数的值。
   - **删除关键字参数 (`delete` 操作):** 可以移除 Meson 构建函数中指定的关键字参数。
   - **添加列表类型的关键字参数的值 (`add` 操作):**  可以向列表类型的关键字参数（例如 `sources`, `dependencies`）添加新的值。
   - **移除列表类型的关键字参数的值 (`remove` 操作):** 可以从列表类型的关键字参数中移除特定的值。
   - **使用正则表达式移除列表类型的关键字参数的值 (`remove_regex` 操作):** 可以根据正则表达式从列表类型的关键字参数中移除匹配的值。
   - **获取关键字参数信息 (`info` 操作):** 可以查看指定函数调用的关键字参数信息。

3. **操作默认选项 (Default Options):**
   - **设置默认选项 (`set` 操作):** 可以设置项目的默认构建选项。
   - **删除默认选项 (`delete` 操作):** 可以删除项目的默认构建选项。

4. **执行命令 (Command):**
   - 可以读取一个 JSON 格式的命令列表，并依次执行这些命令，实现批量修改。

**与逆向方法的关系及举例说明:**

`rewriter.py` 与逆向工程有密切关系，因为它允许逆向工程师在不手动修改 `meson.build` 文件的情况下，自动化地更改构建流程，以便于注入代码、添加调试符号、修改编译选项等。

**举例说明:**

假设逆向工程师想要向一个名为 `target_app` 的可执行文件中注入一个名为 `hook.c` 的自定义 hooking 库。他们可以使用 `rewriter.py` 来实现：

```bash
python rewriter.py target target_app add hook.c
```

这会将 `hook.c` 添加到 `target_app` 的源文件列表中，下次构建时，该 hooking 库的代码将会被编译链接到 `target_app` 中。

或者，如果要修改 `target_app` 的链接库，添加 `mylib`：

```bash
python rewriter.py kwargs target target_app add dependencies mylib
```

这会在 `target_app` 的 `dependencies` 关键字参数中添加 `mylib`。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

`rewriter.py` 本身不直接操作二进制或内核，但它修改的 `meson.build` 文件直接影响最终生成的二进制文件和构建过程，这些构建过程可能涉及到 Linux/Android 特有的概念。

**举例说明:**

- **修改链接选项 (`link_with`):**  可以修改目标链接的库，这直接影响到二进制文件的依赖关系和加载行为，这在 Linux/Android 中非常重要。例如，添加或移除对特定系统库的链接。
- **修改编译选项 (`default_options` 或特定目标的 `kwargs`):**  可以修改编译器标志（例如添加 `-DDEBUG` 来启用调试符号，或者修改优化级别），这会影响生成的二进制代码的特性，例如是否包含调试信息，性能如何等。
- **指定目标类型 (`target_type`):**  可以指定构建目标的类型，例如 `shared_library` (共享库) 或 `executable` (可执行文件)，这在 Linux/Android 中有明确的含义和加载机制。
- **操作安装路径 (`install_dir`):**  可以指定构建产物安装到 Linux/Android 文件系统中的哪个位置。

**逻辑推理、假设输入与输出:**

`rewriter.py` 做了许多逻辑推理，例如：

**假设输入:** 用户执行命令 `python rewriter.py target my_app rm old_source.c`

**逻辑推理:**
1. `rewriter.py` 会解析 `meson.build` 文件。
2. 它会尝试找到名为 `my_app` 的构建目标。
3. 它会在 `my_app` 的源文件列表中查找 `old_source.c`。
4. 如果找到，它会从列表中移除该源文件。

**输出:**  `meson.build` 文件将被修改，`my_app` 的源文件列表中将不再包含 `old_source.c`。

**用户或编程常见的使用错误及举例说明:**

1. **目标名称错误:** 如果用户输入的构建目标名称在 `meson.build` 文件中不存在，`rewriter.py` 会报错。
   ```bash
   python rewriter.py target non_existent_app add new_source.c  # 假设 non_existent_app 不存在
   ```
   **错误:** `Unable to find the function node` 或类似的错误信息。

2. **关键字参数名称错误:**  如果用户尝试修改不存在的关键字参数，`rewriter.py` 会报错。
   ```bash
   python rewriter.py kwargs target my_app set invalid_option value  # 假设 invalid_option 不是 my_app 的有效关键字参数
   ```
   **错误:** `Cannot modify unknown kwarg invalid_option`

3. **提供错误的值类型:**  如果关键字参数有特定的类型要求（例如，一个布尔值，但用户提供了字符串），`rewriter.py` 可能会报错或进行类型转换（取决于具体实现）。

4. **JSON 命令格式错误:** 如果使用 `command` 子命令，提供的 JSON 格式不正确，`rewriter.py` 会无法解析并报错。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在 Frida 项目中工作，需要修改构建配置。**
2. **用户可能希望自动化一些构建配置的修改，而不是手动编辑 `meson.build`。**
3. **用户查阅 Frida 的文档或者源代码，找到了 `rewriter.py` 这个工具。**
4. **用户根据 `rewriter.py` 的命令行参数说明，构造了相应的命令来执行所需的操作。**
5. **用户在命令行中执行 `python rewriter.py ...` 命令。**
6. **`rewriter.py` 被执行，解析命令行参数，并根据参数调用相应的处理函数（例如 `process_target`, `process_kwargs` 等）。**
7. **如果出现错误，`rewriter.py` 会打印错误信息，帮助用户定位问题。**

**第 1 部分功能归纳:**

`rewriter.py` 作为一个 Meson 构建定义文件的修改工具，其主要功能是**允许用户通过命令行操作，自动化地添加、删除和修改构建目标、目标的关键字参数以及项目的默认选项**。 它提供了一种比手动编辑 `meson.build` 文件更方便和可脚本化的方式来调整 Frida 项目的构建配置。这在逆向工程中非常有用，可以方便地集成自定义代码或修改编译行为。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/rewriter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```