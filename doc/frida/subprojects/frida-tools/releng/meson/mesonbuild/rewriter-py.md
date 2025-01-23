Response:
The user wants a summary of the functionality of the provided Python code. I need to analyze the code and identify its main purpose and the actions it can perform.

The code is part of a tool called "fridaDynamic instrumentation tool" and resides in `frida/subprojects/frida-tools/releng/meson/mesonbuild/rewriter.py`. This suggests it's related to manipulating Meson build files within the Frida project.

Key aspects to look for:
- Command-line arguments and their purpose.
- Actions the script can perform (e.g., adding/removing files, modifying target properties).
- Interactions with Meson build files.
- Any logic related to parsing and modifying the structure of Meson files.

Based on the code, it appears to be a tool for programmatically modifying Meson build definitions. It offers functionalities like adding or removing source files from targets, modifying target properties (keyword arguments), and managing default project options.
这个Python源代码文件 `rewriter.py` 是 `frida-tools` 的一部分，专门用于修改现有的 Meson 构建定义文件 (`meson.build`)。它提供了一系列命令来自动化地更改构建配置，而不是手动编辑这些文件。

以下是该文件主要功能的归纳：

1. **解析和分析 Meson 构建文件:**
   - 它使用 `IntrospectionInterpreter` 来读取和理解 `meson.build` 文件的结构和内容。
   - 它可以识别项目名称、版本以及定义的目标（targets）和依赖（dependencies）。

2. **修改构建目标 (Targets):**
   - **添加/删除源文件 (`add`, `rm` 操作):** 可以向现有的构建目标添加或删除源文件。
   - **添加/删除目标 (`add_target`, `rm_target` 操作):**  虽然代码中看到了 `add_target` 和 `rm_target`，但具体的实现逻辑在后续部分，这里的功能是解析相关的命令行参数。
   - **添加/删除额外文件 (`add_extra_files`, `rm_extra_files` 操作):** 可以向构建目标添加或删除额外的文件。
   - **查看目标信息 (`info` 操作):** 可以查看指定目标的详细信息。

3. **修改关键字参数 (Keyword Arguments - kwargs):**
   - **设置/删除/添加/移除/正则移除关键字参数的值 (`set`, `delete`, `add`, `remove`, `remove_regex` 操作):**  可以修改 `meson.build` 文件中函数调用（例如 `executable()`, `library()`, `dependency()` 等）的关键字参数的值。

4. **修改默认选项 (Default Options):**
   - **设置/删除默认选项 (`set`, `delete` 操作):** 可以修改项目级别的默认构建选项。

5. **执行 JSON 命令:**
   - 可以接收一个 JSON 格式的命令列表并执行相应的操作，实现批量修改。

6. **错误处理:**
   - 提供了跳过错误 (`--skip-errors`) 的选项，或者在遇到错误时中止操作。

7. **提供详细输出:**
   - 可以通过 `--verbose` 参数启用详细的输出，以便了解工具的执行过程。

**与逆向方法的关系举例说明：**

假设你正在逆向一个使用了 Frida 的 Android 应用程序，并且你想修改其构建过程以包含一些自定义的脚本或库。你可以使用这个 `rewriter.py` 工具来自动完成以下操作：

- **向目标添加源文件：**  假设你想将一个特定的 C++ hook 代码文件添加到应用程序的 Frida gadget 库中。你可以使用 `target add <gadget_target_name> <hook_source_file.cpp>` 命令，`rewriter.py` 会自动修改 `meson.build` 文件，将这个源文件添加到 gadget 的编译列表中。这避免了手动编辑 `meson.build` 文件可能引入的错误。

**涉及二进制底层，Linux, Android内核及框架的知识的举例说明：**

虽然 `rewriter.py` 本身是一个高层次的 Python 脚本，用于操作 Meson 构建文件，但它所修改的构建配置最终会影响到二进制的生成和链接过程。

- **修改目标类型:**  例如，将一个目标从 `shared_library` 修改为 `static_library`，这直接影响到生成二进制文件的类型和链接方式。共享库在运行时加载，而静态库则在链接时直接嵌入到可执行文件中。这涉及到操作系统（Linux/Android）的库加载机制和二进制文件的格式 (ELF)。
- **修改链接选项 (`link_with`):**  通过 `kwargs` 命令修改 `link_with` 参数，可以指定目标链接哪些其他的库。这涉及到链接器的行为，以及操作系统中库的查找路径和依赖关系。在 Android 开发中，这可能涉及到链接 NDK 提供的库或者系统库。
- **修改编译选项 (通过 `default_options`):**  可以修改编译器标志，例如添加 `-fPIC` 来生成位置无关代码，这对于生成共享库至关重要，尤其是在 Android 这种动态链接的环境下。这直接涉及到编译器的底层工作原理和目标平台的 ABI (Application Binary Interface)。

**逻辑推理的假设输入与输出：**

假设 `meson.build` 文件中定义了一个名为 `my_app` 的可执行目标，并且它的源文件列表如下：

```meson
executable('my_app',
  'src/main.c',
  'src/utils.c',
  install: true
)
```

**假设输入命令:**

```bash
python rewriter.py target my_app add new_feature.c
```

**预期输出 (修改后的 `meson.build` 文件内容):**

```meson
executable('my_app',
  'src/main.c',
  'src/utils.c',
  'new_feature.c',
  install: true
)
```

这里，`rewriter.py` 推理出用户想要将 `new_feature.c` 添加到 `my_app` 目标的源文件列表中，并修改了 `meson.build` 文件。

**涉及用户或编程常见的使用错误的举例说明：**

- **拼写错误的目标名称:**  用户可能会错误地输入目标名称，例如 `python rewriter.py target my_ap add new_file.c`。`rewriter.py` 会尝试查找名为 `my_ap` 的目标，但由于拼写错误找不到，会报错提示用户目标不存在。
- **尝试添加已存在的文件:**  如果用户尝试添加一个已经存在于目标源文件列表中的文件，例如 `python rewriter.py target my_app add src/main.c`，`rewriter.py` 会检测到该文件已存在并跳过添加，避免重复。
- **错误的关键字参数名称:**  用户可能尝试修改一个不存在的关键字参数，例如 `python rewriter.py kwargs set executable my_app non_existent_arg=value`。`rewriter.py` 会检查关键字参数的有效性并报错。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 工具开发/维护人员想要自动化修改 Frida 工具自身的构建配置。**
2. **他们决定使用 Meson 作为构建系统，并编写了一些用于修改 `meson.build` 文件的脚本。**
3. **为了更方便地自动化这些修改，他们开发了 `rewriter.py` 工具。**
4. **在开发或调试过程中，他们可能需要添加新的源文件到某个目标，例如：**
   - 他们正在开发一个新的 Frida 模块。
   - 他们需要向 Frida gadget 中添加一些新的 hook 代码。
5. **他们可能会使用如下命令来调用 `rewriter.py`:**
   ```bash
   python frida/subprojects/frida-tools/releng/meson/mesonbuild/rewriter.py \
       target gadget-android add src/new_hook.cc
   ```
6. **当出现问题时，例如添加的源文件没有被正确编译，或者在构建过程中出现其他错误，开发人员可能会：**
   - 检查 `rewriter.py` 的输出，确认它是否正确地修改了 `meson.build` 文件。
   - 使用 `--verbose` 参数运行 `rewriter.py` 以获取更详细的日志。
   - 检查 `meson.build` 文件，确认修改是否符合预期。
   - 回顾他们使用的 `rewriter.py` 命令，检查是否存在拼写错误或其他参数错误。
   - 如果 `rewriter.py` 的行为不符合预期，他们可能会深入研究 `rewriter.py` 的源代码，例如当前提供的这段代码，来理解其内部逻辑并找到问题所在。

总而言之，`rewriter.py` 是一个方便的工具，用于自动化修改 Meson 构建文件，简化了 Frida 工具的构建配置管理，并降低了手动修改出错的风险。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/rewriter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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