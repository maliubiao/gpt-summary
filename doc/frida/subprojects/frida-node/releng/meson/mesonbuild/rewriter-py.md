Response:
Let's break down the thought process for analyzing the provided Python code snippet.

**1. Initial Understanding of the Goal:**

The prompt asks for the *functionality* of the `rewriter.py` file within the Frida project. It also asks for specific examples related to reverse engineering, low-level details, logic, common user errors, and debugging. The "Part 1 of 2" suggests further analysis will be required later. The immediate goal is to summarize the core capabilities.

**2. High-Level Code Examination (Skimming):**

A quick scan reveals several key elements:

* **Imports:** Libraries like `json`, `os`, `re`, `argparse`, and modules from within the Frida project (`.ast`, `mesonbuild.mesonlib`, `.mlog`, `.environment`, `.mparser`). This hints at command-line argument parsing, JSON handling, file system operations, regular expressions, and interaction with the Meson build system's internal representation.
* **Class `Rewriter`:**  This seems to be the central class. It has methods like `process_default_options`, `process_kwargs`, and `process_target`, suggesting its main role is to modify Meson build files based on commands.
* **Subparsers (`argparse`):**  The code uses `argparse` to define subcommands like `target`, `kwargs`, `default-options`, and `command`. This reinforces the idea of command-line driven modifications.
* **`rewriter_keys` and `rewriter_func_kwargs`:** These dictionaries likely define the structure and allowed values for the commands. `rewriter_keys` seems to define the arguments for the subcommands, while `rewriter_func_kwargs` probably describes the keyword arguments for specific Meson functions (like `target`, `dependency`, `project`).
* **`MType...` Classes:** Classes like `MTypeStr`, `MTypeBool`, `MTypeList`, etc., appear to represent different data types within the Meson build files. They provide methods for adding, removing, and modifying these types.
* **Error Handling:** The code includes `RewriterException` and uses `mlog.error` and `mlog.warning` for logging. The `--skip-errors` flag suggests a mechanism to continue even if errors occur.
* **AST Manipulation:**  References to `ast` (Abstract Syntax Tree) and the `.ast` module indicate the tool works by directly modifying the parsed structure of the `meson.build` file.

**3. Focused Analysis of Key Functionality:**

Based on the skimming, the core functionality revolves around modifying `meson.build` files. Let's examine the main subcommands:

* **`target` Subcommand:** The arguments (`add`, `rm`, `add_target`, `rm_target`, `add_extra_files`, `rm_extra_files`) and the `process_target` method clearly point to modifying build targets: adding/removing source files, potentially adding/removing entire targets, and managing extra files.
* **`kwargs` Subcommand:**  The `process_kwargs` method and arguments like `set`, `delete`, `add`, `remove`, `remove_regex` suggest modifying keyword arguments of specific Meson functions (e.g., adding a dependency to a target, changing a project option).
* **`default-options` Subcommand:** The `process_default_options` method is designed to change project-wide default options.
* **`command` Subcommand:** This likely allows executing a series of modification commands defined in a JSON format.

**4. Connecting to the Prompt's Specific Questions:**

Now, let's link the identified functionality to the specific questions in the prompt:

* **Reverse Engineering:**  Modifying build targets and dependencies can be useful in reverse engineering. For example, you might *add* a debugging flag or *remove* optimization flags to a specific target to make it easier to analyze. Adding extra files could include instrumentation code.
* **Binary/Low-Level/Kernel:** The code itself doesn't directly interact with binaries or the kernel. However, *modifying the build process* can indirectly impact these areas. For instance, adding a compiler flag (`-g`) affects the generated binary. Adding a dependency might pull in a library that interacts with the kernel.
* **Logic/Assumptions:** The `process_default_options` method has logic to validate options against the available options in the `coredata`. This assumes the `IntrospectionInterpreter` has correctly loaded this information. An example input could be `{'operation': 'set', 'options': {'warning_level': '3'}}`, and the output would be a modified `meson.build` file.
* **User Errors:** A common error is providing an incorrect target name, function name, or keyword argument. The code attempts to handle this with error messages. For instance, trying to add a source to a non-existent target would trigger an error.
* **User Steps/Debugging:**  The command-line arguments provide the user's input. The `Rewriter` class then parses this input and uses the `IntrospectionInterpreter` to find the relevant nodes in the AST. Debugging would involve stepping through the `process_*` methods to see how the AST is being manipulated based on the user's commands.

**5. Synthesizing the Summary (Part 1):**

Based on the analysis, we can now create a concise summary of the file's functionality. The core idea is that this script allows programmatic modification of `meson.build` files, targeting various aspects of the build definition.

**6. Self-Correction/Refinement:**

Initially, I might have focused too much on the individual methods. However, the prompt asks for *functionality*. Therefore, framing the answer around the *subcommands* and their high-level actions provides a better overview of what the tool does from a user perspective. Also, emphasizing the connection to the Meson build system and its AST is crucial for understanding its internal workings. Realizing that the binary/kernel interaction is *indirect* is also an important refinement.
This Python code file, `rewriter.py`, is a command-line tool designed to **modify existing Meson build definition files (`meson.build`) in a structured and automated way.**  It provides functionalities to:

**Core Functionalities:**

1. **Manipulate Build Targets:**
    *   **Add or remove source files:**  Allows adding new source files to an existing build target (like an executable or library) or removing existing ones.
    *   **Add or remove entire targets:** Enables the addition of new build targets or the removal of existing ones from the `meson.build` file.
    *   **Add or remove extra files:** Manages extra files associated with a target, which might be data files or other non-source code assets.

2. **Modify Keyword Arguments of Functions:**
    *   **Set, delete, add, or remove keyword arguments:** Provides fine-grained control over the keyword arguments passed to various Meson functions like `executable()`, `library()`, `dependency()`, and `project()`.
    *   **Remove keyword arguments based on regular expressions:** Allows for more flexible removal of keyword arguments based on pattern matching.

3. **Modify Project Default Options:**
    *   **Set or delete default project options:**  Allows changing the default values of options defined in the `project()` function, impacting the overall build configuration.

4. **Execute JSON Command Sequences:**
    *   **Process a series of commands defined in a JSON file or string:** Enables batch processing of multiple modifications to the `meson.build` file.

**Relation to Reverse Engineering (with Examples):**

This tool is highly relevant to reverse engineering workflows as it allows for targeted modifications of the build process to facilitate analysis. Here are some examples:

*   **Adding Debug Symbols:**  You can modify the keyword arguments of a target's definition to ensure debug symbols are included in the generated binary.
    *   **Assumption:** You know the target name (e.g., "my_executable").
    *   **Input (command-line example):**
        ```bash
        python rewriter.py kwargs -s <source_dir> set target my_executable buildtype debuginfo
        ```
    *   **Output:** The `meson.build` file will be updated to include `buildtype: 'debuginfo'` in the `executable()` function call for "my_executable". This ensures the compiled binary contains debugging information.

*   **Disabling Optimizations:** To make the code easier to step through and analyze, you might want to disable compiler optimizations.
    *   **Assumption:** You know the target name.
    *   **Input (command-line example):**
        ```bash
        python rewriter.py kwargs -s <source_dir> set target my_executable optimization '0'
        ```
    *   **Output:** The `meson.build` file will be modified to include `optimization: '0'` for the target, instructing the compiler to disable optimizations.

*   **Adding Instrumentation Code:** You could add a new source file containing your instrumentation logic to a specific target.
    *   **Assumption:** You have an instrumentation file named `instrumentation.c`.
    *   **Input (command-line example):**
        ```bash
        python rewriter.py target -s <source_dir> add my_executable instrumentation.c
        ```
    *   **Output:** The `meson.build` file will be updated to include `instrumentation.c` in the list of source files for the "my_executable" target.

*   **Modifying Dependencies:** You might want to link against a custom library or remove a dependency to isolate a specific part of the code.
    *   **Assumption:** You know the target name and the dependency name.
    *   **Input (command-line example to remove a dependency):**
        ```bash
        python rewriter.py kwargs -s <source_dir> remove target my_executable dependencies unwanted_lib
        ```
    *   **Output:** The `meson.build` file will be modified to remove "unwanted_lib" from the `dependencies` keyword argument of the "my_executable" target.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge (with Examples):**

While the `rewriter.py` script itself doesn't directly interact with the binary level or the kernel, its actions have a profound impact on the build process that leads to the creation of binaries and their interaction with the underlying system.

*   **Compiler Flags (Binary Bottom):** By modifying keyword arguments like `c_args` or `cpp_args` in target definitions, you can directly control the compiler flags used during compilation. This directly impacts the generated machine code and binary structure. For example, adding `-m32` or `-m64` flags changes the target architecture of the binary.

*   **Linker Flags (Binary Bottom):** Similarly, modifying `link_args` affects how the linker combines object files into the final executable or library. This can influence memory layout, symbol resolution, and dynamic linking behavior.

*   **Library Dependencies (Linux/Android Framework):**  When adding or removing dependencies using the `rewriter.py` script, you are directly influencing which shared libraries a binary will link against. This is crucial in Linux and Android environments where applications often rely on system libraries or framework components. For example, adding a dependency on `libbinder` in an Android project would enable the target to use Binder IPC mechanisms.

*   **Target Types (Linux/Android):** The script allows creating different target types like `executable`, `shared_library`, `static_library`, and `shared_module`. Understanding the distinctions between these types is essential for Linux and Android development. For instance, creating a `shared_library` will result in a `.so` file that can be dynamically loaded, which is common in these environments.

*   **Install Paths (Linux/Android):** Modifying the `install_dir` keyword argument controls where the built artifacts are installed on the system. This is vital for packaging and deployment on Linux and Android systems, where specific directory structures are often required.

**Logical Reasoning (with Hypothesis & Output):**

Let's consider a scenario where you want to add a new source file to a target only if a specific condition is met (although the provided code doesn't show conditional logic for adding sources directly, it demonstrates the principle of targeted modification).

*   **Hypothesis:**  You want to add `debug_utils.c` to the `my_application` target *only if* the Meson option `enable_debugging` is set to `true`. (Note: This specific conditional source addition might require further manual modification of the `meson.build` after using `rewriter.py` to get the basic structure right).

*   **Input (command-line examples - illustrating how you might *prepare* for such a condition):**

    1. **Check existing options (not directly `rewriter.py` but a prerequisite):**  You'd first inspect your `meson_options.txt` or the `meson.build` file to see if the `enable_debugging` option exists.
    2. **Potentially modify options (using `rewriter.py`):** If the option doesn't exist, you might use `rewriter.py` to add it to the `project()` definition.
    3. **Modify the target (using `rewriter.py`):** You would add the source unconditionally initially.

*   **Output (of the `rewriter.py` command to add the source unconditionally):** The `meson.build` file for the `my_application` target would now include `debug_utils.c` in its source list.

*   **Further Modification (manual):** To implement the conditional logic, you would then *manually edit* the `meson.build` file to wrap the addition of `debug_utils.c` within an `if get_option('enable_debugging')` block. The `rewriter.py` helps with the basic structural changes, but more complex logic might require manual adjustments.

**User/Programming Common Usage Errors (with Examples):**

1. **Incorrect Target Name:**  Providing a target name that doesn't exist in the `meson.build` file will lead to an error.
    *   **Example Input:** `python rewriter.py target -s <source_dir> add non_existent_target new_source.c`
    *   **Error:** The `rewriter.py` script will likely report an "Unknown target" error.

2. **Typographical Errors in Keyword Arguments:**  Misspelling a keyword argument name will cause the script to fail or have unintended consequences.
    *   **Example Input:** `python rewriter.py kwargs -s <source_dir> set target my_executable depndencies my_lib` (Note the typo "depndencies").
    *   **Error:** Meson itself might later complain about an unknown keyword argument, or the dependency might not be linked correctly.

3. **Incorrect Data Types for Keyword Arguments:** Providing a value of the wrong type for a keyword argument will result in an error.
    *   **Example Input:** `python rewriter.py kwargs -s <source_dir> set target my_executable install not_a_boolean` (Trying to set `install` to a non-boolean value).
    *   **Error:** The `rewriter.py` script or Meson will likely report a type mismatch error.

4. **Trying to Modify Non-Modifiable Elements:**  Attempting to modify elements that the `rewriter.py` is not designed to handle will likely result in no change or an error.

5. **Forgetting to Specify the Source Directory:** The `-s` or `--sourcedir` argument is usually mandatory, and omitting it will cause the script to not find the `meson.build` file.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user would typically interact with this code through the command line. The following steps would lead them to execute the `rewriter.py` script:

1. **Navigate to the Frida Source Directory:** The user would first navigate their terminal to the `frida` project's root directory or a relevant subdirectory.
2. **Identify the `rewriter.py` Script:** The user would know or discover that the `rewriter.py` script is located at `frida/subprojects/frida-node/releng/meson/mesonbuild/rewriter.py`.
3. **Formulate the Modification Command:** Based on their desired changes to the `meson.build` file, the user would construct a command-line invocation of the `rewriter.py` script using its various options and subcommands.
4. **Execute the Command:** The user would then execute the constructed command in their terminal.
5. **Observe the Output and Changes:** The `rewriter.py` script would then process the command, potentially modifying the `meson.build` file, and print output indicating the actions taken (or errors encountered).

**As a debugging clue:** If a user is reporting issues with the build process after attempting to modify the `meson.build` file, you would investigate the commands they used with `rewriter.py`. You'd check for typos, incorrect target names, wrong argument types, and whether the intended modification was supported by the tool. Examining the modified `meson.build` file would also be crucial to understand the actual changes made.

**Part 1 Summary of Functionality:**

The `rewriter.py` script within the Frida project is a powerful command-line tool for **programmatically manipulating Meson build definition files (`meson.build`)**. It allows users to add, remove, and modify build targets, their source files, keyword arguments of various Meson functions, and project default options. This tool simplifies the process of making targeted changes to the build system, which is particularly useful for tasks like debugging, instrumentation, and customizing the build process for specific needs, including reverse engineering scenarios.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/rewriter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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