Response:
The user wants a summary of the Python code provided. The code is part of `frida`, a dynamic instrumentation toolkit, specifically the `rewriter.py` file which manipulates Meson build definitions.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:**  I need to go through the code and identify the core actions the `Rewriter` class and its associated functions perform. This includes adding/removing files, modifying target properties, and working with default options.

2. **Relate to reverse engineering:** I should think about how manipulating build systems can aid reverse engineering. For example, adding extra logging sources or removing optimizations.

3. **Binary, Linux, Android knowledge:**  The code interacts with build systems, which eventually compile to binaries. It doesn't directly manipulate kernel code, but understanding the build process on Linux and Android is relevant, especially when thinking about targets and dependencies.

4. **Logical reasoning (input/output):** For key functions, I can create hypothetical examples of how commands are structured and what the expected outcome in the Meson build file would be.

5. **User errors:**  Consider common mistakes users might make when trying to use this tool, like incorrect syntax or providing invalid target names.

6. **User operation flow:**  Outline the steps a user might take to end up invoking this rewriter, likely starting with a desire to modify their Frida build.

7. **Summarize the functionality (for part 1):**  Condense the identified features into a concise overview.
这是 `frida` 动态 instrumentation 工具中 `frida-gum` 子项目的 `releng/meson/mesonbuild/rewriter.py` 文件的源代码。该文件的主要功能是**修改现有的 Meson 构建定义文件 (`meson.build`)**。

以下是该文件功能的详细列举和说明：

**核心功能:**

1. **操作构建目标 (Targets):**
   - **添加源文件到目标 (`add`):**  可以将新的源文件添加到已存在的构建目标中。
   - **从目标移除源文件 (`rm`):** 可以从已存在的构建目标中移除指定的源文件。
   - **添加新的构建目标 (`add_target`):** 可以在 `meson.build` 文件中添加一个全新的构建目标（例如可执行文件、库等）。
   - **移除构建目标 (`rm_target`):** 可以从 `meson.build` 文件中移除一个已存在的构建目标。
   - **添加额外的文件到目标 (`add_extra_files`):**  可以向目标添加一些非源代码的额外文件，例如数据文件。
   - **从目标移除额外的文件 (`rm_extra_files`):** 可以从目标中移除指定的额外文件。
   - **获取目标信息 (`info`):**  可以查看指定目标的详细信息。

2. **操作关键字参数 (Keyword Arguments - Kwargs):**
   - **设置关键字参数 (`set`):**  可以设置指定函数调用中的关键字参数的值。
   - **删除关键字参数 (`delete`):** 可以删除指定函数调用中的关键字参数。
   - **添加关键字参数的值 (`add`):**  如果关键字参数是列表类型，可以向列表中添加新的值。
   - **移除关键字参数的值 (`remove`):** 如果关键字参数是列表类型，可以从列表中移除指定的值。
   - **通过正则表达式移除关键字参数的值 (`remove_regex`):** 如果关键字参数是列表类型，可以使用正则表达式匹配并移除列表中的值。
   - **获取关键字参数信息 (`info`):** 可以查看指定函数调用的关键字参数信息。

3. **操作默认选项 (Default Options):**
   - **设置默认选项 (`set`):** 可以设置项目的默认构建选项。
   - **删除默认选项 (`delete`):** 可以删除项目的默认构建选项。

4. **执行 JSON 命令 (JSON Command):**
   - 可以读取一个包含多个命令的 JSON 文件或字符串，并按顺序执行这些命令。

**与逆向方法的关系及举例说明:**

该工具可以通过修改构建定义来影响最终生成的二进制文件，从而间接地与逆向分析相关：

* **添加额外的编译选项:** 逆向工程师可能希望在编译目标时禁用某些优化 (`-O0`) 或者添加调试符号 (`-g`)，以便更容易地进行调试和分析。通过 `kwargs` 命令修改 `target` 函数的关键字参数，可以实现这一点。
   * **假设输入:**  要为名为 `my_target` 的可执行目标添加 `-O0` 编译选项。
   * **命令:**
     ```bash
     python rewriter.py kwargs set target my_target c_args -O0
     ```
   * **效果:**  会在 `meson.build` 文件中 `executable('my_target', ...)` 的调用中添加或修改 `c_args: ['-O0']`。

* **添加额外的源文件:** 逆向工程师可能希望在目标中加入自定义的日志代码或 hook 代码，以便在运行时观察程序的行为。通过 `target add` 命令可以实现。
   * **假设输入:**  要向名为 `frida-agent` 的目标添加 `my_hook.c` 文件。
   * **命令:**
     ```bash
     python rewriter.py target add frida-agent my_hook.c
     ```
   * **效果:**  会在 `meson.build` 文件中 `executable('frida-agent', ...)` 或 `library('frida-agent', ...)` 的源文件列表中添加 `my_hook.c`。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然该脚本本身不直接操作二进制或内核，但其操作会影响最终的编译结果，这涉及到这些底层知识：

* **目标类型 (Target Types):**  `add_target` 命令允许创建不同类型的目标，例如 `executable` (可执行文件), `library` (库), `shared_library` (共享库), `static_library` (静态库)。这些概念直接关联到 Linux 和 Android 系统中程序和库的构建和链接方式。
    * 例如，选择 `shared_library` 会生成 `.so` 文件（在 Linux 上）或 `.so` 或 `.dylib` 文件（在 Android 上），可以被其他程序动态加载。
* **依赖关系 (Dependencies):** 虽然该代码段没有直接展示操作依赖关系，但 Meson 构建系统本身管理着目标之间的依赖，这对于理解程序的构建和运行至关重要。例如，一个可执行文件可能依赖于一个共享库。
* **编译和链接选项:** 通过 `kwargs` 修改编译选项 (`c_args`, `cpp_args`, `link_args`) 直接影响二进制文件的生成过程，涉及到编译器（如 GCC, Clang）和链接器的工作原理。

**逻辑推理的假设输入与输出:**

* **假设输入 (添加源文件):**
   ```json
   {
       "type": "target",
       "target": "my_app",
       "operation": "add",
       "sources": ["new_feature.c", "utils.c"]
   }
   ```
* **预期输出 (假设 `my_app` 目标存在且当前源文件列表为 `main.c`):** `meson.build` 文件中 `executable('my_app', 'main.c', ...)` 可能会被修改为 `executable('my_app', 'main.c', 'new_feature.c', 'utils.c', ...)`。

* **假设输入 (设置默认选项):**
   ```json
   {
       "type": "default-options",
       "operation": "set",
       "options": {"optimization": "0", "werror": "true"}
   }
   ```
* **预期输出:** `meson.build` 文件中 `project(...)` 调用中会添加或修改 `default_options: ['optimization=0', 'werror=true']`。

**涉及用户或编程常见的使用错误及举例说明:**

* **目标名称错误:** 如果用户尝试操作一个不存在的目标，例如：
   ```bash
   python rewriter.py target add non_existent_target new_source.c
   ```
   脚本会报错 `Unknown target non_existent_target`。
* **操作类型错误:**  如果用户使用了不支持的操作类型，例如：
   ```bash
   python rewriter.py target invalid_operation my_target some_source.c
   ```
   脚本会提示 `invalid_operation` 不是一个有效的操作。
* **关键字参数名称错误:** 如果用户尝试修改一个目标或函数不存在的关键字参数，例如：
   ```bash
   python rewriter.py kwargs set target my_target non_existent_kwarg some_value
   ```
   脚本会报错 `Cannot modify unknown kwarg non_existent_kwarg`。
* **JSON 命令格式错误:** 如果用户提供的 JSON 文件或字符串格式不正确，脚本将无法解析并报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要修改 Frida 的构建方式:**  例如，他们可能想添加一些额外的源文件来 hook 特定的函数，或者修改编译选项以便于调试 Frida Agent。
2. **用户查阅 Frida 的文档或源代码:** 了解到可以使用 `rewriter.py` 脚本来修改 `meson.build` 文件。
3. **用户构造 `rewriter.py` 命令:** 根据需要修改的内容，用户会使用 `target`, `kwargs`, 或 `default-options` 等子命令，并提供相应的参数，例如目标名称、源文件名、关键字参数等。
4. **用户执行 `rewriter.py` 脚本:**  通过命令行运行该脚本，并观察其输出。
5. **如果出现错误:** 用户需要根据错误信息检查命令的语法、目标名称、源文件名、关键字参数是否正确。`rewriter.py` 的 verbose 输出 (`-V`) 可以提供更详细的调试信息。

**归纳一下它的功能 (第 1 部分):**

`rewriter.py` 脚本的主要功能是提供一套命令行工具，用于以编程方式修改 Frida 项目的 `meson.build` 构建定义文件。它允许用户执行各种操作，包括添加、移除和修改构建目标及其属性，以及管理项目的默认构建选项。这使得用户可以自动化或简化对 Frida 构建过程的定制，例如添加额外的源文件、修改编译选项等。该工具通过解析和修改 `meson.build` 文件的抽象语法树 (AST) 来实现这些功能。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/rewriter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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