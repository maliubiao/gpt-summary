Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand the functionality of `interpreterbase.py` within the context of Frida and reverse engineering.

**1. Initial Understanding of the Context:**

*   The file path `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/interpreterbase.py` immediately tells us this is part of Frida's Python bindings and uses the Meson build system.
*   The "interpreterbase" suggests this file defines the core logic for interpreting some language or configuration within the build process.
*   Frida is a dynamic instrumentation toolkit, primarily used for reverse engineering, security analysis, and debugging.

**2. High-Level Code Inspection:**

*   **Imports:**  The imports provide clues about dependencies. `environment`, `mparser`, `mesonlib` point to Meson's internal modules for handling build environments, parsing, and general utilities. `baseobjects`, `exceptions`, `decorators`, `disabler`, `helpers`, `operator`, `_unholder` are likely custom modules within Meson's interpreter framework. Standard Python modules like `os`, `copy`, `re`, `pathlib`, `typing`, and `textwrap` indicate common functionalities used.
*   **Class `InterpreterBase`:** This is the central class. Its methods will define the core actions of the interpreter.
*   **Methods within `InterpreterBase`:** Quickly scanning the method names provides a broad overview of the interpreter's capabilities: `load_root_meson_file`, `parse_project`, `run`, `evaluate_codeblock`, `evaluate_statement`, `function_call`, `method_call`, `assignment`, `get_variable`, `set_variable`, etc. These names strongly suggest a process of parsing and executing code.

**3. Deeper Dive into Key Functionality:**

*   **Parsing (`load_root_meson_file`, `parse_project`):** The code reads a `meson.build` file, parses it using `mparser.Parser`, and performs an initial parsing of the `project()` function. This immediately connects to build systems – Meson uses `meson.build` to define build instructions.
*   **Evaluation (`evaluate_codeblock`, `evaluate_statement`):**  This is the heart of the interpreter. The `evaluate_statement` method has a large `if/elif` block handling various node types from the parsed AST (`mparser`). This indicates the interpreter understands different language constructs (function calls, assignments, if statements, loops, etc.).
*   **Variable Management (`variables`, `get_variable`, `set_variable`):** The interpreter maintains a `variables` dictionary to store values. This is standard for any programming language interpreter.
*   **Function and Method Calls (`function_call`, `method_call`):** The code handles calling functions and methods, which are essential for executing logic. The distinction between functions (global) and methods (associated with objects) is important.
*   **Operators (`operator.MesonOperator`):** The use of `MesonOperator` suggests that the interpreter supports various operators (arithmetic, comparison, logical) and that these operations are handled in a structured way.
*   **Data Structures (Arrays, Dictionaries):** The interpreter handles arrays (`evaluate_arraystatement`) and dictionaries (`evaluate_dictstatement`).
*   **Control Flow (If, Foreach, Continue, Break):**  The interpreter can execute conditional statements (`evaluate_if`) and loops (`evaluate_foreach`), and handles `continue` and `break` statements.

**4. Connecting to Reverse Engineering:**

*   **Dynamic Instrumentation:** The file is part of Frida, a dynamic instrumentation tool. The interpreter likely plays a role in executing scripts or commands that interact with a running process being instrumented.
*   **Scripting:** The parsing and evaluation of code blocks strongly suggest that Frida uses a scripting language (or a subset thereof) defined by the `meson.build` syntax. This scripting language controls Frida's actions during instrumentation.
*   **Interaction with Target Process:** While this specific file doesn't directly interact with target processes, it sets the stage for that interaction by defining how commands/scripts are interpreted. Other parts of Frida will use the information gathered by this interpreter to perform actions like hooking functions, reading/writing memory, etc.

**5. Identifying Binary/Kernel/Framework Relationships:**

*   **Meson Build System:** Meson itself is used for building software, often involving compilation of C/C++ code that interacts with the operating system kernel and frameworks. While this file doesn't *directly* manipulate binaries or kernel, it's part of the *build process* that creates them.
*   **Frida's Architecture:** Frida works by injecting an agent into a target process. The interpreter could be involved in setting up the environment or configuring the agent that gets injected.
*   **Android Context (Possible):** While not explicitly stated in the code, Frida is heavily used on Android. The build system and scripting language defined here could be used to build or configure Frida components specific to Android.

**6. Logical Reasoning and Examples:**

*   **Conditional Logic (If):**  If the interpreter encounters an `if` statement, it evaluates the condition. *Example:* `if version >= '1.0':  do_something()`
*   **Looping (Foreach):**  If the interpreter encounters a `foreach` loop, it iterates over a collection. *Example:* `foreach file in files: print(file)`
*   **Function Calls:** When a function is called, the interpreter looks up the function definition and executes it. *Example:* `my_function(arg1, arg2='value')`

**7. Common User/Programming Errors:**

*   **Syntax Errors:** Incorrectly formatted `meson.build` files will cause parsing errors.
*   **Type Errors:**  Passing arguments of the wrong type to functions (e.g., a string where an integer is expected).
*   **Undefined Variables:**  Trying to use a variable that hasn't been assigned a value.
*   **Incorrect Argument Order:** Providing keyword arguments before positional arguments.
*   **Assigning in Argument Lists:** Trying to use `=` for keyword arguments instead of `:`.

**8. Tracing User Operations:**

*   A user wants to build Frida's Python bindings.
*   They run the `meson` command in the `frida-python` directory.
*   Meson starts by reading the `meson.build` file in the root of the project.
*   This `meson.build` file might contain `subproject('frida-python')`, which would lead Meson to the `frida/subprojects/frida-python/meson.build` file.
*   Within `frida/subprojects/frida-python/meson.build`, there might be further logic that causes Meson to interpret files in the `releng/meson` directory, eventually leading to the execution of code within `interpreterbase.py`.
*   The interpreter in `interpreterbase.py` would then parse and execute the Meson language constructs within those `meson.build` files to configure the build process.

By following this systematic approach, we can dissect the code and understand its role within the larger Frida project, connecting it to reverse engineering principles and identifying potential areas for user error.
这个文件 `interpreterbase.py` 是 Frida 动态 instrumentation 工具中 Frida-Python 组件的一部分，并且是 Meson 构建系统的一个关键组成部分。它定义了一个用于解释 Meson 构建定义文件的基础解释器类 `InterpreterBase`。这个解释器负责读取、解析和执行 `meson.build` 文件中的代码，这些文件描述了如何构建 Frida-Python 组件。

以下是 `interpreterbase.py` 文件的主要功能：

**1. Meson 构建文件解释和执行:**

*   **读取和解析 `meson.build` 文件:** `load_root_meson_file` 方法负责读取指定目录下的 `meson.build` 文件，并使用 `mparser.Parser` 将其解析成抽象语法树 (AST)。
*   **执行 AST 节点:** `evaluate_codeblock` 和 `evaluate_statement` 方法递归地遍历 AST，并执行其中的各种语句，例如函数调用、变量赋值、条件语句、循环语句等。
*   **支持多种语句类型:** 代码中可以看到对 `FunctionNode`, `AssignmentNode`, `IfClauseNode`, `ForeachClauseNode` 等多种 AST 节点类型的处理，这意味着解释器能够理解和执行 Meson 构建文件中定义的各种操作。

**2. 变量管理:**

*   **存储变量:** `self.variables` 字典用于存储在解释过程中创建和赋值的变量。
*   **获取和设置变量:** `get_variable` 和 `set_variable` 方法用于访问和修改这些变量。
*   **内置变量:** `self.builtin` 字典用于存储内置的 Meson 变量。

**3. 函数和方法调用:**

*   **处理函数调用:** `function_call` 方法负责查找并执行在 `self.funcs` 中注册的函数。这些函数是 Meson 构建系统提供的各种构建操作，例如编译源代码、链接库等。
*   **处理方法调用:** `method_call` 方法负责在对象上调用方法。这些对象通常是 Meson 提供的内置对象或通过函数调用创建的对象。

**4. 支持表达式求值:**

*   **算术运算:** `evaluate_arithmeticstatement` 方法处理加减乘除等算术运算。
*   **比较运算:** `evaluate_comparison` 方法处理相等、不等、大于、小于等比较运算。
*   **逻辑运算:** `evaluate_andstatement`, `evaluate_orstatement`, `evaluate_notstatement` 方法处理与、或、非等逻辑运算。
*   **字符串操作:** 支持格式化字符串 (`evaluate_fstring`)。
*   **数组和字典:** 支持创建和操作数组 (`evaluate_arraystatement`) 和字典 (`evaluate_dictstatement`)。
*   **索引操作:** `evaluate_indexing` 方法处理对数组或字典的索引操作。

**5. 控制流:**

*   **条件语句:** `evaluate_if` 方法执行 `if-elif-else` 语句。
*   **循环语句:** `evaluate_foreach` 方法执行 `foreach` 循环。
*   **`continue` 和 `break`:** 支持在循环中使用 `continue` 和 `break` 语句。

**6. 错误处理:**

*   **抛出异常:** 代码中定义了多种异常类型，例如 `InterpreterException`, `InvalidArguments`, `InvalidCode` 等，用于在解释过程中遇到错误时抛出。
*   **提供错误信息:** 异常信息通常包含错误发生的行号和列号，有助于用户定位问题。

**7. 与逆向方法的关联 (举例说明):**

虽然 `interpreterbase.py` 本身不直接涉及 Frida 的核心逆向功能（如代码注入、hooking 等），但它是构建 Frida-Python 组件的基础。Frida-Python 提供了 Python 接口来使用 Frida 的逆向功能。因此，理解 `interpreterbase.py` 的功能有助于理解 Frida-Python 是如何构建和部署的。

**举例说明:**

假设你想使用 Frida-Python 来 hook 一个 Android 应用的某个函数。首先，你需要安装 Frida 和 Frida-Python。这个安装过程就涉及到 Meson 构建系统，而 `interpreterbase.py` 就参与了解释 Frida-Python 的 `meson.build` 文件，从而指导构建过程。

例如，`meson.build` 文件可能会定义 Frida-Python 依赖的库、需要编译的源代码文件、以及如何将这些组件打包成可安装的 Python 包。`interpreterbase.py` 会读取这些定义并执行相应的构建操作。

**8. 涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

*   **二进制底层:** Meson 构建系统通常用于构建需要编译成机器码的软件，这涉及到二进制文件的生成和处理。虽然 `interpreterbase.py` 不直接操作二进制数据，但它控制着生成这些二进制文件的过程。
*   **Linux:** Frida 主要在 Linux 系统上开发和使用。Meson 构建系统可以配置为针对 Linux 平台进行构建，例如指定链接 Linux 特有的库。
*   **Android 内核及框架:** Frida 广泛应用于 Android 平台的逆向工程。Frida-Python 的构建可能需要依赖 Android SDK 或 NDK 中的组件，并且需要配置构建过程以生成能在 Android 上运行的库。`interpreterbase.py` 可以处理 `meson.build` 文件中与 Android 平台相关的构建配置。

**举例说明:**

`meson.build` 文件中可能会有条件判断，根据目标平台（例如 Linux 或 Android）选择不同的编译器或链接不同的库。`interpreterbase.py` 在解释这些条件判断时，会根据当前的构建环境做出决策，从而影响最终生成的二进制文件。

例如，对于 Android 平台，`meson.build` 可能会指定使用 Android NDK 提供的交叉编译工具链，并将生成的库打包成 `.so` 文件。`interpreterbase.py` 会执行这些构建指令。

**9. 逻辑推理 (假设输入与输出):**

假设 `meson.build` 文件包含以下代码：

```meson
my_variable = 10
if my_variable > 5:
    message('Variable is greater than 5')
    output = 'yes'
else:
    output = 'no'
```

**假设输入:** 上述 `meson.build` 代码。

**输出:**

*   `self.variables['my_variable']` 的值为一个 `InterpreterObject`，其内部值是整数 `10`。
*   执行 `if` 语句时，由于 `my_variable > 5` 为真，会执行 `if` 代码块中的语句。
*   `message('Variable is greater than 5')` 函数会被调用（假设 `message` 函数已在 `self.funcs` 中注册），并在构建过程中输出 "Variable is greater than 5" 的消息。
*   `self.variables['output']` 的值为一个 `InterpreterObject`，其内部值是字符串 `"yes"`。

**10. 用户或编程常见的使用错误 (举例说明):**

*   **语法错误:** 在 `meson.build` 文件中使用了错误的语法，例如拼写错误的函数名、缺少冒号等。`interpreterbase.py` 在解析 `meson.build` 文件时会抛出 `mparser.ParseException` 异常。
*   **类型错误:** 将错误类型的参数传递给函数。例如，某个函数期望接收一个整数，但用户传递了一个字符串。`interpreterbase.py` 在执行函数调用时可能会抛出 `InvalidArguments` 异常。
*   **未定义的变量:** 在 `meson.build` 文件中使用了未定义的变量。`interpreterbase.py` 在尝试获取该变量的值时会抛出 `InvalidCode` 异常，提示 "Unknown variable"。
*   **赋值操作符使用错误:** 在期望进行比较的地方使用了赋值操作符 `=`，或者在函数调用中错误地使用了 `=` 而不是 `:` 来指定关键字参数。`interpreterbase.py` 会抛出相应的 `InvalidArguments` 或 `InvalidCode` 异常。

**举例说明用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户想要构建 Frida-Python:** 用户在命令行中进入 Frida-Python 的源代码目录。
2. **用户运行 Meson 命令:** 用户执行 `meson setup build` 或类似的命令来配置构建环境。
3. **Meson 读取顶层 `meson.build`:** Meson 工具首先会读取项目根目录下的 `meson.build` 文件。
4. **Meson 处理 `subproject()`:** 顶层的 `meson.build` 文件可能包含 `subproject('frida-python')` 这样的语句，指示 Meson 处理 Frida-Python 子项目的构建定义。
5. **Meson 进入 Frida-Python 子项目目录:** Meson 会进入 `frida/subprojects/frida-python` 目录，并读取该目录下的 `meson.build` 文件。
6. **`interpreterbase.py` 被加载和使用:** Meson 内部会实例化 `InterpreterBase` 类，并使用其方法来解析和执行 `frida/subprojects/frida-python/meson.build` 文件以及可能存在的其他相关的 `meson.build` 文件（例如在 `releng/meson` 目录下）。
7. **解释器执行构建指令:** `interpreterbase.py` 会执行 `meson.build` 文件中定义的各种函数调用，例如 `project()`, `find_library()`, `declare_dependency()`, `pyproject_install()` 等，从而完成 Frida-Python 的构建配置。

如果构建过程中出现错误，例如 `meson.build` 文件中存在语法错误或类型错误，`interpreterbase.py` 在解析或执行相应的语句时会抛出异常，并在终端输出错误信息，包括错误发生的文件名、行号和列号。这些信息可以帮助用户定位并修复 `meson.build` 文件中的问题。

总而言之，`interpreterbase.py` 是 Frida-Python 构建过程的核心组件，它负责解释 Meson 构建定义文件，指导构建系统的行为，并确保 Frida-Python 组件能够正确地构建出来。理解这个文件的功能对于理解 Frida-Python 的构建流程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreterbase/interpreterbase.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2017 The Meson development team

# This class contains the basic functionality needed to run any interpreter
# or an interpreter-based tool.
from __future__ import annotations

from .. import environment, mparser, mesonlib

from .baseobjects import (
    InterpreterObject,
    MesonInterpreterObject,
    MutableInterpreterObject,
    ObjectHolder,
    IterableObject,
    ContextManagerObject,

    HoldableTypes,
)

from .exceptions import (
    BreakRequest,
    ContinueRequest,
    InterpreterException,
    InvalidArguments,
    InvalidCode,
    SubdirDoneRequest,
)

from .decorators import FeatureNew
from .disabler import Disabler, is_disabled
from .helpers import default_resolve_key, flatten, resolve_second_level_holders, stringifyUserArguments
from .operator import MesonOperator
from ._unholder import _unholder

import os, copy, re, pathlib
import typing as T
import textwrap

if T.TYPE_CHECKING:
    from .baseobjects import InterpreterObjectTypeVar, SubProject, TYPE_kwargs, TYPE_var
    from ..interpreter import Interpreter

    HolderMapType = T.Dict[
        T.Union[
            T.Type[mesonlib.HoldableObject],
            T.Type[int],
            T.Type[bool],
            T.Type[str],
            T.Type[list],
            T.Type[dict],
        ],
        # For some reason, this has to be a callable and can't just be ObjectHolder[InterpreterObjectTypeVar]
        T.Callable[[InterpreterObjectTypeVar, 'Interpreter'], ObjectHolder[InterpreterObjectTypeVar]]
    ]

    FunctionType = T.Dict[
        str,
        T.Callable[[mparser.BaseNode, T.List[TYPE_var], T.Dict[str, TYPE_var]], TYPE_var]
    ]


class InvalidCodeOnVoid(InvalidCode):

    def __init__(self, op_type: str) -> None:
        super().__init__(f'Cannot perform {op_type!r} operation on void statement.')


class InterpreterBase:
    def __init__(self, source_root: str, subdir: str, subproject: 'SubProject'):
        self.source_root = source_root
        self.funcs: FunctionType = {}
        self.builtin: T.Dict[str, InterpreterObject] = {}
        # Holder maps store a mapping from an HoldableObject to a class ObjectHolder
        self.holder_map: HolderMapType = {}
        self.bound_holder_map: HolderMapType = {}
        self.subdir = subdir
        self.root_subdir = subdir
        self.subproject = subproject
        self.variables: T.Dict[str, InterpreterObject] = {}
        self.argument_depth = 0
        self.current_lineno = -1
        # Current node set during a function call. This can be used as location
        # when printing a warning message during a method call.
        self.current_node: mparser.BaseNode = None
        # This is set to `version_string` when this statement is evaluated:
        # meson.version().compare_version(version_string)
        # If it was part of a if-clause, it is used to temporally override the
        # current meson version target within that if-block.
        self.tmp_meson_version: T.Optional[str] = None

    def handle_meson_version_from_ast(self, strict: bool = True) -> None:
        # do nothing in an AST interpreter
        return

    def load_root_meson_file(self) -> None:
        mesonfile = os.path.join(self.source_root, self.subdir, environment.build_filename)
        if not os.path.isfile(mesonfile):
            raise InvalidArguments(f'Missing Meson file in {mesonfile}')
        with open(mesonfile, encoding='utf-8') as mf:
            code = mf.read()
        if code.isspace():
            raise InvalidCode('Builder file is empty.')
        assert isinstance(code, str)
        try:
            self.ast = mparser.Parser(code, mesonfile).parse()
            self.handle_meson_version_from_ast()
        except mparser.ParseException as me:
            me.file = mesonfile
            if me.ast:
                # try to detect parser errors from new syntax added by future
                # meson versions, and just tell the user to update meson
                self.ast = me.ast
                self.handle_meson_version_from_ast()
            raise me

    def parse_project(self) -> None:
        """
        Parses project() and initializes languages, compilers etc. Do this
        early because we need this before we parse the rest of the AST.
        """
        self.evaluate_codeblock(self.ast, end=1)

    def sanity_check_ast(self) -> None:
        def _is_project(ast: mparser.CodeBlockNode) -> object:
            if not isinstance(ast, mparser.CodeBlockNode):
                raise InvalidCode('AST is of invalid type. Possibly a bug in the parser.')
            if not ast.lines:
                raise InvalidCode('No statements in code.')
            first = ast.lines[0]
            return isinstance(first, mparser.FunctionNode) and first.func_name.value == 'project'

        if not _is_project(self.ast):
            p = pathlib.Path(self.source_root).resolve()
            found = p
            for parent in p.parents:
                if (parent / 'meson.build').is_file():
                    with open(parent / 'meson.build', encoding='utf-8') as f:
                        code = f.read()

                    try:
                        ast = mparser.Parser(code, 'empty').parse()
                    except mparser.ParseException:
                        continue

                    if _is_project(ast):
                        found = parent
                        break
                else:
                    break

            error = 'first statement must be a call to project()'
            if found != p:
                raise InvalidCode(f'Not the project root: {error}\n\nDid you mean to run meson from the directory: "{found}"?')
            else:
                raise InvalidCode(f'Invalid source tree: {error}')

    def run(self) -> None:
        # Evaluate everything after the first line, which is project() because
        # we already parsed that in self.parse_project()
        try:
            self.evaluate_codeblock(self.ast, start=1)
        except SubdirDoneRequest:
            pass

    def evaluate_codeblock(self, node: mparser.CodeBlockNode, start: int = 0, end: T.Optional[int] = None) -> None:
        if node is None:
            return
        if not isinstance(node, mparser.CodeBlockNode):
            e = InvalidCode('Tried to execute a non-codeblock. Possibly a bug in the parser.')
            e.lineno = node.lineno
            e.colno = node.colno
            raise e
        statements = node.lines[start:end]
        i = 0
        while i < len(statements):
            cur = statements[i]
            try:
                self.current_lineno = cur.lineno
                self.evaluate_statement(cur)
            except Exception as e:
                if getattr(e, 'lineno', None) is None:
                    # We are doing the equivalent to setattr here and mypy does not like it
                    # NOTE: self.current_node is continually updated during processing
                    e.lineno = self.current_node.lineno                                               # type: ignore
                    e.colno = self.current_node.colno                                                 # type: ignore
                    e.file = os.path.join(self.source_root, self.subdir, environment.build_filename)  # type: ignore
                raise e
            i += 1 # In THE FUTURE jump over blocks and stuff.

    def evaluate_statement(self, cur: mparser.BaseNode) -> T.Optional[InterpreterObject]:
        self.current_node = cur
        if isinstance(cur, mparser.FunctionNode):
            return self.function_call(cur)
        elif isinstance(cur, mparser.PlusAssignmentNode):
            self.evaluate_plusassign(cur)
        elif isinstance(cur, mparser.AssignmentNode):
            self.assignment(cur)
        elif isinstance(cur, mparser.MethodNode):
            return self.method_call(cur)
        elif isinstance(cur, mparser.BaseStringNode):
            if isinstance(cur, mparser.MultilineFormatStringNode):
                return self.evaluate_multiline_fstring(cur)
            elif isinstance(cur, mparser.FormatStringNode):
                return self.evaluate_fstring(cur)
            else:
                return self._holderify(cur.value)
        elif isinstance(cur, mparser.BooleanNode):
            return self._holderify(cur.value)
        elif isinstance(cur, mparser.IfClauseNode):
            return self.evaluate_if(cur)
        elif isinstance(cur, mparser.IdNode):
            return self.get_variable(cur.value)
        elif isinstance(cur, mparser.ComparisonNode):
            return self.evaluate_comparison(cur)
        elif isinstance(cur, mparser.ArrayNode):
            return self.evaluate_arraystatement(cur)
        elif isinstance(cur, mparser.DictNode):
            return self.evaluate_dictstatement(cur)
        elif isinstance(cur, mparser.NumberNode):
            return self._holderify(cur.value)
        elif isinstance(cur, mparser.AndNode):
            return self.evaluate_andstatement(cur)
        elif isinstance(cur, mparser.OrNode):
            return self.evaluate_orstatement(cur)
        elif isinstance(cur, mparser.NotNode):
            return self.evaluate_notstatement(cur)
        elif isinstance(cur, mparser.UMinusNode):
            return self.evaluate_uminusstatement(cur)
        elif isinstance(cur, mparser.ArithmeticNode):
            return self.evaluate_arithmeticstatement(cur)
        elif isinstance(cur, mparser.ForeachClauseNode):
            self.evaluate_foreach(cur)
        elif isinstance(cur, mparser.IndexNode):
            return self.evaluate_indexing(cur)
        elif isinstance(cur, mparser.TernaryNode):
            return self.evaluate_ternary(cur)
        elif isinstance(cur, mparser.ContinueNode):
            raise ContinueRequest()
        elif isinstance(cur, mparser.BreakNode):
            raise BreakRequest()
        elif isinstance(cur, mparser.ParenthesizedNode):
            return self.evaluate_statement(cur.inner)
        elif isinstance(cur, mparser.TestCaseClauseNode):
            return self.evaluate_testcase(cur)
        else:
            raise InvalidCode("Unknown statement.")
        return None

    def evaluate_arraystatement(self, cur: mparser.ArrayNode) -> InterpreterObject:
        (arguments, kwargs) = self.reduce_arguments(cur.args)
        if len(kwargs) > 0:
            raise InvalidCode('Keyword arguments are invalid in array construction.')
        return self._holderify([_unholder(x) for x in arguments])

    @FeatureNew('dict', '0.47.0')
    def evaluate_dictstatement(self, cur: mparser.DictNode) -> InterpreterObject:
        def resolve_key(key: mparser.BaseNode) -> str:
            if not isinstance(key, mparser.BaseStringNode):
                FeatureNew.single_use('Dictionary entry using non literal key', '0.53.0', self.subproject)
            key_holder = self.evaluate_statement(key)
            if key_holder is None:
                raise InvalidArguments('Key cannot be void.')
            str_key = _unholder(key_holder)
            if not isinstance(str_key, str):
                raise InvalidArguments('Key must be a string')
            return str_key
        arguments, kwargs = self.reduce_arguments(cur.args, key_resolver=resolve_key, duplicate_key_error='Duplicate dictionary key: {}')
        assert not arguments
        return self._holderify({k: _unholder(v) for k, v in kwargs.items()})

    def evaluate_notstatement(self, cur: mparser.NotNode) -> InterpreterObject:
        v = self.evaluate_statement(cur.value)
        if v is None:
            raise InvalidCodeOnVoid('not')
        if isinstance(v, Disabler):
            return v
        return self._holderify(v.operator_call(MesonOperator.NOT, None))

    def evaluate_if(self, node: mparser.IfClauseNode) -> T.Optional[Disabler]:
        assert isinstance(node, mparser.IfClauseNode)
        for i in node.ifs:
            # Reset self.tmp_meson_version to know if it gets set during this
            # statement evaluation.
            self.tmp_meson_version = None
            result = self.evaluate_statement(i.condition)
            if result is None:
                raise InvalidCodeOnVoid('if')
            if isinstance(result, Disabler):
                return result
            if not isinstance(result, InterpreterObject):
                raise mesonlib.MesonBugException(f'Argument to if ({result}) is not an InterpreterObject but {type(result).__name__}.')
            res = result.operator_call(MesonOperator.BOOL, None)
            if not isinstance(res, bool):
                raise InvalidCode(f'If clause {result!r} does not evaluate to true or false.')
            if res:
                prev_meson_version = mesonlib.project_meson_versions[self.subproject]
                if self.tmp_meson_version:
                    mesonlib.project_meson_versions[self.subproject] = self.tmp_meson_version
                try:
                    self.evaluate_codeblock(i.block)
                finally:
                    mesonlib.project_meson_versions[self.subproject] = prev_meson_version
                return None
        if not isinstance(node.elseblock, mparser.EmptyNode):
            self.evaluate_codeblock(node.elseblock.block)
        return None

    def evaluate_testcase(self, node: mparser.TestCaseClauseNode) -> T.Optional[Disabler]:
        result = self.evaluate_statement(node.condition)
        if isinstance(result, Disabler):
            return result
        if not isinstance(result, ContextManagerObject):
            raise InvalidCode(f'testcase clause {result!r} does not evaluate to a context manager.')
        with result:
            self.evaluate_codeblock(node.block)
        return None

    def evaluate_comparison(self, node: mparser.ComparisonNode) -> InterpreterObject:
        val1 = self.evaluate_statement(node.left)
        if val1 is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the left-hand side')
        if isinstance(val1, Disabler):
            return val1
        val2 = self.evaluate_statement(node.right)
        if val2 is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the right-hand side')
        if isinstance(val2, Disabler):
            return val2

        # New code based on InterpreterObjects
        operator = {
            'in': MesonOperator.IN,
            'notin': MesonOperator.NOT_IN,
            '==': MesonOperator.EQUALS,
            '!=': MesonOperator.NOT_EQUALS,
            '>': MesonOperator.GREATER,
            '<': MesonOperator.LESS,
            '>=': MesonOperator.GREATER_EQUALS,
            '<=': MesonOperator.LESS_EQUALS,
        }[node.ctype]

        # Check if the arguments should be reversed for simplicity (this essentially converts `in` to `contains`)
        if operator in (MesonOperator.IN, MesonOperator.NOT_IN):
            val1, val2 = val2, val1

        val1.current_node = node
        return self._holderify(val1.operator_call(operator, _unholder(val2)))

    def evaluate_andstatement(self, cur: mparser.AndNode) -> InterpreterObject:
        l = self.evaluate_statement(cur.left)
        if l is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the left-hand side')
        if isinstance(l, Disabler):
            return l
        l_bool = l.operator_call(MesonOperator.BOOL, None)
        if not l_bool:
            return self._holderify(l_bool)
        r = self.evaluate_statement(cur.right)
        if r is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the right-hand side')
        if isinstance(r, Disabler):
            return r
        return self._holderify(r.operator_call(MesonOperator.BOOL, None))

    def evaluate_orstatement(self, cur: mparser.OrNode) -> InterpreterObject:
        l = self.evaluate_statement(cur.left)
        if l is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the left-hand side')
        if isinstance(l, Disabler):
            return l
        l_bool = l.operator_call(MesonOperator.BOOL, None)
        if l_bool:
            return self._holderify(l_bool)
        r = self.evaluate_statement(cur.right)
        if r is None:
            raise mesonlib.MesonException('Cannot compare a void statement on the right-hand side')
        if isinstance(r, Disabler):
            return r
        return self._holderify(r.operator_call(MesonOperator.BOOL, None))

    def evaluate_uminusstatement(self, cur: mparser.UMinusNode) -> InterpreterObject:
        v = self.evaluate_statement(cur.value)
        if v is None:
            raise InvalidCodeOnVoid('unary minus')
        if isinstance(v, Disabler):
            return v
        v.current_node = cur
        return self._holderify(v.operator_call(MesonOperator.UMINUS, None))

    def evaluate_arithmeticstatement(self, cur: mparser.ArithmeticNode) -> InterpreterObject:
        l = self.evaluate_statement(cur.left)
        if isinstance(l, Disabler):
            return l
        r = self.evaluate_statement(cur.right)
        if isinstance(r, Disabler):
            return r
        if l is None or r is None:
            raise InvalidCodeOnVoid(cur.operation)

        mapping: T.Dict[str, MesonOperator] = {
            'add': MesonOperator.PLUS,
            'sub': MesonOperator.MINUS,
            'mul': MesonOperator.TIMES,
            'div': MesonOperator.DIV,
            'mod': MesonOperator.MOD,
        }
        l.current_node = cur
        res = l.operator_call(mapping[cur.operation], _unholder(r))
        return self._holderify(res)

    def evaluate_ternary(self, node: mparser.TernaryNode) -> T.Optional[InterpreterObject]:
        assert isinstance(node, mparser.TernaryNode)
        result = self.evaluate_statement(node.condition)
        if result is None:
            raise mesonlib.MesonException('Cannot use a void statement as condition for ternary operator.')
        if isinstance(result, Disabler):
            return result
        result.current_node = node
        result_bool = result.operator_call(MesonOperator.BOOL, None)
        if result_bool:
            return self.evaluate_statement(node.trueblock)
        else:
            return self.evaluate_statement(node.falseblock)

    @FeatureNew('multiline format strings', '0.63.0')
    def evaluate_multiline_fstring(self, node: mparser.MultilineFormatStringNode) -> InterpreterObject:
        return self.evaluate_fstring(node)

    @FeatureNew('format strings', '0.58.0')
    def evaluate_fstring(self, node: T.Union[mparser.FormatStringNode, mparser.MultilineFormatStringNode]) -> InterpreterObject:
        def replace(match: T.Match[str]) -> str:
            var = str(match.group(1))
            try:
                val = _unholder(self.variables[var])
                if isinstance(val, (list, dict)):
                    FeatureNew.single_use('List or dictionary in f-string', '1.3.0', self.subproject, location=self.current_node)
                try:
                    return stringifyUserArguments(val, self.subproject)
                except InvalidArguments as e:
                    raise InvalidArguments(f'f-string: {str(e)}')
            except KeyError:
                raise InvalidCode(f'Identifier "{var}" does not name a variable.')

        res = re.sub(r'@([_a-zA-Z][_0-9a-zA-Z]*)@', replace, node.value)
        return self._holderify(res)

    def evaluate_foreach(self, node: mparser.ForeachClauseNode) -> None:
        assert isinstance(node, mparser.ForeachClauseNode)
        items = self.evaluate_statement(node.items)
        if not isinstance(items, IterableObject):
            raise InvalidArguments('Items of foreach loop do not support iterating')

        tsize = items.iter_tuple_size()
        if len(node.varnames) != (tsize or 1):
            raise InvalidArguments(f'Foreach expects exactly {tsize or 1} variables for iterating over objects of type {items.display_name()}')

        for i in items.iter_self():
            if tsize is None:
                if isinstance(i, tuple):
                    raise mesonlib.MesonBugException(f'Iteration of {items} returned a tuple even though iter_tuple_size() is None')
                self.set_variable(node.varnames[0].value, self._holderify(i))
            else:
                if not isinstance(i, tuple):
                    raise mesonlib.MesonBugException(f'Iteration of {items} did not return a tuple even though iter_tuple_size() is {tsize}')
                if len(i) != tsize:
                    raise mesonlib.MesonBugException(f'Iteration of {items} did not return a tuple even though iter_tuple_size() is {tsize}')
                for j in range(tsize):
                    self.set_variable(node.varnames[j].value, self._holderify(i[j]))
            try:
                self.evaluate_codeblock(node.block)
            except ContinueRequest:
                continue
            except BreakRequest:
                break

    def evaluate_plusassign(self, node: mparser.PlusAssignmentNode) -> None:
        assert isinstance(node, mparser.PlusAssignmentNode)
        varname = node.var_name.value
        addition = self.evaluate_statement(node.value)
        if addition is None:
            raise InvalidCodeOnVoid('plus assign')

        # Remember that all variables are immutable. We must always create a
        # full new variable and then assign it.
        old_variable = self.get_variable(varname)
        old_variable.current_node = node
        new_value = self._holderify(old_variable.operator_call(MesonOperator.PLUS, _unholder(addition)))
        self.set_variable(varname, new_value)

    def evaluate_indexing(self, node: mparser.IndexNode) -> InterpreterObject:
        assert isinstance(node, mparser.IndexNode)
        iobject = self.evaluate_statement(node.iobject)
        if iobject is None:
            raise InterpreterException('Tried to evaluate indexing on void.')
        if isinstance(iobject, Disabler):
            return iobject
        index_holder = self.evaluate_statement(node.index)
        if index_holder is None:
            raise InvalidArguments('Cannot use void statement as index.')
        index = _unholder(index_holder)

        iobject.current_node = node
        return self._holderify(iobject.operator_call(MesonOperator.INDEX, index))

    def function_call(self, node: mparser.FunctionNode) -> T.Optional[InterpreterObject]:
        func_name = node.func_name.value
        (h_posargs, h_kwargs) = self.reduce_arguments(node.args)
        (posargs, kwargs) = self._unholder_args(h_posargs, h_kwargs)
        if is_disabled(posargs, kwargs) and func_name not in {'get_variable', 'set_variable', 'unset_variable', 'is_disabler'}:
            return Disabler()
        if func_name in self.funcs:
            func = self.funcs[func_name]
            func_args = posargs
            if not getattr(func, 'no-args-flattening', False):
                func_args = flatten(posargs)
            if not getattr(func, 'no-second-level-holder-flattening', False):
                func_args, kwargs = resolve_second_level_holders(func_args, kwargs)
            self.current_node = node
            res = func(node, func_args, kwargs)
            return self._holderify(res) if res is not None else None
        else:
            self.unknown_function_called(func_name)
            return None

    def method_call(self, node: mparser.MethodNode) -> T.Optional[InterpreterObject]:
        invocable = node.source_object
        obj: T.Optional[InterpreterObject]
        if isinstance(invocable, mparser.IdNode):
            object_display_name = f'variable "{invocable.value}"'
            obj = self.get_variable(invocable.value)
        else:
            object_display_name = invocable.__class__.__name__
            obj = self.evaluate_statement(invocable)
        method_name = node.name.value
        (h_args, h_kwargs) = self.reduce_arguments(node.args)
        (args, kwargs) = self._unholder_args(h_args, h_kwargs)
        if is_disabled(args, kwargs):
            return Disabler()
        if not isinstance(obj, InterpreterObject):
            raise InvalidArguments(f'{object_display_name} is not callable.')
        # TODO: InterpreterBase **really** shouldn't be in charge of checking this
        if method_name == 'extract_objects':
            if isinstance(obj, ObjectHolder):
                self.validate_extraction(obj.held_object)
            elif not isinstance(obj, Disabler):
                raise InvalidArguments(f'Invalid operation "extract_objects" on {object_display_name} of type {type(obj).__name__}')
        obj.current_node = self.current_node = node
        res = obj.method_call(method_name, args, kwargs)
        return self._holderify(res) if res is not None else None

    def _holderify(self, res: T.Union[TYPE_var, InterpreterObject]) -> InterpreterObject:
        if isinstance(res, HoldableTypes):
            # Always check for an exact match first.
            cls = self.holder_map.get(type(res), None)
            if cls is not None:
                # Casts to Interpreter are required here since an assertion would
                # not work for the `ast` module.
                return cls(res, T.cast('Interpreter', self))
            # Try the boundary types next.
            for typ, cls in self.bound_holder_map.items():
                if isinstance(res, typ):
                    return cls(res, T.cast('Interpreter', self))
            raise mesonlib.MesonBugException(f'Object {res} of type {type(res).__name__} is neither in self.holder_map nor self.bound_holder_map.')
        elif isinstance(res, ObjectHolder):
            raise mesonlib.MesonBugException(f'Returned object {res} of type {type(res).__name__} is an object holder.')
        elif isinstance(res, MesonInterpreterObject):
            return res
        raise mesonlib.MesonBugException(f'Unknown returned object {res} of type {type(res).__name__} in the parameters.')

    def _unholder_args(self,
                       args: T.List[InterpreterObject],
                       kwargs: T.Dict[str, InterpreterObject]) -> T.Tuple[T.List[TYPE_var], TYPE_kwargs]:
        return [_unholder(x) for x in args], {k: _unholder(v) for k, v in kwargs.items()}

    def unknown_function_called(self, func_name: str) -> None:
        raise InvalidCode(f'Unknown function "{func_name}".')

    def reduce_arguments(
                self,
                args: mparser.ArgumentNode,
                key_resolver: T.Callable[[mparser.BaseNode], str] = default_resolve_key,
                duplicate_key_error: T.Optional[str] = None,
            ) -> T.Tuple[
                T.List[InterpreterObject],
                T.Dict[str, InterpreterObject]
            ]:
        assert isinstance(args, mparser.ArgumentNode)
        if args.incorrect_order():
            raise InvalidArguments('All keyword arguments must be after positional arguments.')
        self.argument_depth += 1
        reduced_pos = [self.evaluate_statement(arg) for arg in args.arguments]
        if any(x is None for x in reduced_pos):
            raise InvalidArguments('At least one value in the arguments is void.')
        reduced_kw: T.Dict[str, InterpreterObject] = {}
        for key, val in args.kwargs.items():
            reduced_key = key_resolver(key)
            assert isinstance(val, mparser.BaseNode)
            reduced_val = self.evaluate_statement(val)
            if reduced_val is None:
                raise InvalidArguments(f'Value of key {reduced_key} is void.')
            self.current_node = key
            if duplicate_key_error and reduced_key in reduced_kw:
                raise InvalidArguments(duplicate_key_error.format(reduced_key))
            reduced_kw[reduced_key] = reduced_val
        self.argument_depth -= 1
        final_kw = self.expand_default_kwargs(reduced_kw)
        return reduced_pos, final_kw

    def expand_default_kwargs(self, kwargs: T.Dict[str, T.Optional[InterpreterObject]]) -> T.Dict[str, T.Optional[InterpreterObject]]:
        if 'kwargs' not in kwargs:
            return kwargs
        to_expand = _unholder(kwargs.pop('kwargs'))
        if not isinstance(to_expand, dict):
            raise InterpreterException('Value of "kwargs" must be dictionary.')
        if 'kwargs' in to_expand:
            raise InterpreterException('Kwargs argument must not contain a "kwargs" entry. Points for thinking meta, though. :P')
        for k, v in to_expand.items():
            if k in kwargs:
                raise InterpreterException(f'Entry "{k}" defined both as a keyword argument and in a "kwarg" entry.')
            kwargs[k] = self._holderify(v)
        return kwargs

    def assignment(self, node: mparser.AssignmentNode) -> None:
        assert isinstance(node, mparser.AssignmentNode)
        if self.argument_depth != 0:
            raise InvalidArguments(textwrap.dedent('''\
                Tried to assign values inside an argument list.
                To specify a keyword argument, use : instead of =.
            '''))
        var_name = node.var_name.value
        if not isinstance(var_name, str):
            raise InvalidArguments('Tried to assign value to a non-variable.')
        value = self.evaluate_statement(node.value)
        # For mutable objects we need to make a copy on assignment
        if isinstance(value, MutableInterpreterObject):
            value = copy.deepcopy(value)
        self.set_variable(var_name, value)

    def set_variable(self, varname: str, variable: T.Union[TYPE_var, InterpreterObject], *, holderify: bool = False) -> None:
        if variable is None:
            raise InvalidCode('Can not assign void to variable.')
        if holderify:
            variable = self._holderify(variable)
        else:
            # Ensure that we are always storing ObjectHolders
            if not isinstance(variable, InterpreterObject):
                raise mesonlib.MesonBugException(f'set_variable in InterpreterBase called with a non InterpreterObject {variable} of type {type(variable).__name__}')
        if not isinstance(varname, str):
            raise InvalidCode('First argument to set_variable must be a string.')
        if re.match('[_a-zA-Z][_0-9a-zA-Z]*$', varname) is None:
            raise InvalidCode('Invalid variable name: ' + varname)
        if varname in self.builtin:
            raise InvalidCode(f'Tried to overwrite internal variable "{varname}"')
        self.variables[varname] = variable

    def get_variable(self, varname: str) -> InterpreterObject:
        if varname in self.builtin:
            return self.builtin[varname]
        if varname in self.variables:
            return self.variables[varname]
        raise InvalidCode(f'Unknown variable "{varname}".')

    def validate_extraction(self, buildtarget: mesonlib.HoldableObject) -> None:
        raise InterpreterException('validate_extraction is not implemented in this context (please file a bug)')
```