Response:
Let's break down the thought process for analyzing the `interpreterbase.py` file.

**1. Understanding the Goal:** The request asks for a functional breakdown of the Python code, focusing on its role in Frida (dynamic instrumentation), its connection to reverse engineering, low-level aspects (kernel, binaries), logical reasoning, error handling, and how a user might reach this code.

**2. Initial Scan and Keyword Spotting:** I'd first skim the code, looking for keywords and patterns that reveal its purpose. Keywords like `Interpreter`, `parse`, `evaluate`, `function_call`, `method_call`, `variable`, `assignment`, and imports like `mparser` and `environment` immediately suggest this is related to parsing and executing some kind of language. The presence of `mesonbuild` in the path and comments mentioning "Meson development team" strongly indicate this code is part of the Meson build system.

**3. Identifying Core Functionality (Function-by-Function or Block-by-Block):**  I'd then go through the code more systematically, analyzing each significant function and class:

   * **`InterpreterBase.__init__`:**  This sets up the basic state of the interpreter: source root, subproject, dictionaries for functions, built-ins, variables, etc. This tells me it's managing the environment for execution.
   * **`load_root_meson_file`:** This is clearly responsible for reading and parsing the main `meson.build` file. The use of `mparser.Parser` is a key detail. Error handling for missing or empty files is also important.
   * **`parse_project`:** This explicitly mentions parsing the `project()` function, which is central to Meson. This suggests a two-pass approach (parse project info first).
   * **`sanity_check_ast`:** This confirms that the first line of `meson.build` must be `project()`. It also shows how Meson tries to guide the user if they run it from the wrong directory.
   * **`run`:** This is the main execution loop, calling `evaluate_codeblock`.
   * **`evaluate_codeblock`:** This iterates through statements in a code block and calls `evaluate_statement`. It also handles exceptions.
   * **`evaluate_statement`:** This is the core dispatch function. It uses `isinstance` to determine the type of AST node and calls the appropriate evaluation logic (e.g., `function_call`, `assignment`, `evaluate_if`). This is the heart of the interpreter.
   * **Evaluation functions for various AST nodes (`evaluate_arraystatement`, `evaluate_dictstatement`, `evaluate_if`, `evaluate_comparison`, etc.):** These implement the semantics of the Meson language constructs. I'd pay attention to how they handle different data types and operators.
   * **`function_call` and `method_call`:** These handle the execution of functions and methods. The distinction is important (top-level vs. object-bound). The handling of `Disabler` is interesting and suggests a mechanism for conditionally disabling parts of the build.
   * **`reduce_arguments`:** This function processes arguments to function and method calls, handling both positional and keyword arguments.
   * **`assignment` and `set_variable`/`get_variable`:** These manage variable assignments and lookups. The immutability note in `evaluate_plusassign` is significant.
   * **`_holderify` and `_unholder_args`:** These functions seem to deal with wrapping and unwrapping values, likely related to Meson's type system and how it represents values internally.

**4. Connecting to Frida and Reverse Engineering:**  This requires a bit of inference. The file path (`frida/subprojects/frida-node/releng/meson/...`) strongly suggests this is *used by* Frida. Meson is a build system, so this interpreter is likely responsible for processing the build files that *define how Frida is built*. While the interpreter itself doesn't directly *perform* dynamic instrumentation, it's crucial for setting up the build environment that produces the Frida tools.

   * **Example:**  A `meson.build` file might define compiler flags, library dependencies, and target architectures. This interpreter processes that information, which *indirectly* affects how Frida binaries are built and thus how they interact with target processes during reverse engineering.

**5. Identifying Low-Level Connections:** Again, it's indirect. The interpreter itself is high-level Python. However, the *output* of the Meson build process (which this interpreter drives) directly involves:

   * **Binaries:**  Compilers, linkers, and other tools are invoked based on the `meson.build` instructions.
   * **Linux/Android Kernel/Framework:**  Frida often interacts with these. The build system needs to handle platform-specific configurations. The interpreter processes instructions related to these configurations.

**6. Logical Reasoning (Assumptions and Outputs):** I'd look for conditional statements and how they affect program flow.

   * **Example (from `evaluate_if`):**
      * **Input:** An `IfClauseNode` with a condition that evaluates to `True`.
      * **Output:** The code block within the `if` statement is executed.
      * **Input:** An `IfClauseNode` with a condition that evaluates to `False`, and an `else` block.
      * **Output:** The code block within the `else` statement is executed.

**7. Common User Errors:** I'd think about what mistakes a user might make when writing `meson.build` files.

   * **Example:** Incorrect syntax, using an undefined variable, providing the wrong number of arguments to a function, trying to assign a value inside a function call's argument list. The code has explicit checks and error messages for many of these.

**8. Tracing User Actions:** How does a user's action lead to this code being executed?

   * **Scenario:** A user runs `meson build` in their Frida build directory.
   * **Steps:**
      1. Meson is invoked.
      2. Meson locates the `meson.build` file.
      3. Meson creates an `InterpreterBase` instance.
      4. `load_root_meson_file` is called to parse `meson.build`.
      5. `parse_project` is called to handle the `project()` call.
      6. `run` is called to execute the rest of the `meson.build` file, which involves calling `evaluate_codeblock` and `evaluate_statement` within this `interpreterbase.py` file.

**9. Review and Refine:** After the initial analysis, I'd review my findings, ensuring they are accurate and well-organized. I'd look for connections between different parts of the code and try to synthesize a coherent explanation of its overall purpose. I would also ensure I've addressed all aspects of the original request.
This Python code defines the `InterpreterBase` class, which is a fundamental component of the Meson build system's interpreter. Meson is used by Frida to manage its build process. Therefore, this file plays a crucial role in how Frida is compiled and structured.

Here's a breakdown of its functionalities:

**Core Functionalities of `InterpreterBase`:**

1. **Parsing and Evaluating Meson Build Files:**
   - `load_root_meson_file()`: Reads the `meson.build` file, which defines the build instructions for a project. It uses the `mparser` module to parse the file's contents into an Abstract Syntax Tree (AST).
   - `parse_project()`: Specifically parses the `project()` function call, which is the first and mandatory statement in a `meson.build` file. This function initializes project-level settings like languages and compilers.
   - `evaluate_codeblock()`: Executes a block of code represented by an AST node. It iterates through the statements and calls `evaluate_statement()` for each one.
   - `evaluate_statement()`:  This is the central dispatch function. It determines the type of statement (function call, assignment, conditional, loop, etc.) and calls the appropriate evaluation method.
   - Various `evaluate_*` methods (e.g., `evaluate_if`, `evaluate_foreach`, `evaluate_comparison`, `evaluate_arithmeticstatement`): These methods implement the logic for specific language constructs in Meson. They handle conditional execution, looping, comparisons, arithmetic operations, and more.

2. **Managing Interpreter State:**
   - `__init__()`: Initializes the interpreter's state, including the source root, current subdirectory, variables, functions, and built-in objects.
   - `variables`: Stores variables defined in the `meson.build` file.
   - `funcs`: Stores built-in and custom functions available in the Meson language.
   - `builtin`: Stores built-in objects provided by Meson.
   - `subdir`, `root_subdir`: Tracks the current directory being processed during the build.
   - `argument_depth`: Helps detect errors like assignments within argument lists.
   - `current_lineno`, `current_node`:  Used for error reporting, keeping track of the current line and AST node being processed.

3. **Function and Method Calls:**
   - `function_call()`: Handles calls to top-level functions defined in Meson. It resolves the function name, extracts arguments, and executes the function.
   - `method_call()`: Handles calls to methods of objects. It retrieves the object, resolves the method name, extracts arguments, and calls the method.
   - `reduce_arguments()`:  Processes the arguments passed to functions and methods, handling both positional and keyword arguments.

4. **Variable Management:**
   - `assignment()`: Handles variable assignments (using the `=` operator).
   - `evaluate_plusassign()`: Handles the `+=` operator for modifying variables.
   - `set_variable()`: Sets the value of a variable in the interpreter's scope.
   - `get_variable()`: Retrieves the value of a variable.

5. **Control Flow:**
   - `evaluate_if()`: Implements conditional execution using `if`, `elif`, and `else` statements.
   - `evaluate_foreach()`: Implements looping over collections of items.
   - `evaluate_ternary()`: Handles the ternary conditional operator (`condition ? true_value : false_value`).
   - Handling `BreakRequest` and `ContinueRequest`:  Allows for breaking out of or continuing loops.

6. **Data Type Handling:**
   - `evaluate_arraystatement()`: Creates list (array) objects.
   - `evaluate_dictstatement()`: Creates dictionary objects.
   - Handling of strings, booleans, and numbers.

7. **Error Handling:**
   - Raises various `InterpreterException` subclasses (e.g., `InvalidArguments`, `InvalidCode`) to indicate errors in the `meson.build` file.
   - Includes checks for invalid syntax, incorrect argument types, undefined variables, and other common mistakes.

8. **Feature Management:**
   - Uses the `@FeatureNew` decorator to mark when certain language features were introduced in Meson.

**Relationship to Reverse Engineering (Indirect):**

The `interpreterbase.py` file itself doesn't directly perform reverse engineering. However, it's a crucial part of the build system that *creates* Frida, the dynamic instrumentation tool used for reverse engineering. Here's how it's related:

* **Building Frida:** This interpreter processes the `meson.build` files in the Frida project. These files define:
    * **Source code compilation:** Which C/C++ files need to be compiled and how (compiler flags, include paths).
    * **Library linking:** Which libraries Frida needs to link against.
    * **Target platforms:** How to build Frida for different operating systems (Linux, Android, etc.) and architectures.
    * **Packaging:** How to package Frida for distribution.
* **Influence on Frida's Capabilities:** The build process managed by this interpreter determines the final structure and capabilities of the Frida tools. For example, build options might enable or disable certain features in Frida.
* **Example:** A `meson.build` file might contain a conditional statement (`if`) that checks the target operating system. Based on this, it might include specific platform-dependent code. The `evaluate_if()` function in this file would handle this logic, influencing which parts of Frida get built for a particular platform.

**Relationship to Binary Bottom, Linux, Android Kernel and Frameworks (Indirect):**

Again, this Python code doesn't directly interact with the binary level or the kernel. However, it's instrumental in the *process* that generates binaries that *do* interact with these levels:

* **Compiler and Linker Invocation:** The `meson.build` files, processed by this interpreter, contain instructions that lead to the execution of compilers (like GCC or Clang) and linkers. These tools directly work with binary code.
* **Platform-Specific Compilation:**  The interpreter handles logic for building Frida on different operating systems (Linux, Android). This involves setting compiler flags and linking against libraries specific to those platforms, including libraries that interact with the kernel or framework.
* **Example:**  For Android, the `meson.build` might specify the use of the Android NDK (Native Development Kit) and link against libraries like `libdl.so` (for dynamic linking) which are essential for interacting with the Android framework at a lower level. The interpreter helps orchestrate this.

**Logical Reasoning (Assumptions and Outputs):**

Let's consider the `evaluate_comparison()` function as an example of logical reasoning:

* **Assumption:** The input `node` is a `mparser.ComparisonNode` representing a comparison operation (e.g., `a == b`, `x > y`).
* **Inputs:**
    * `node.left`: An AST node representing the left-hand side of the comparison.
    * `node.right`: An AST node representing the right-hand side of the comparison.
    * `node.ctype`: The type of comparison (e.g., `'=='`, `'>'`, `'in'`).
* **Process:**
    1. `evaluate_statement()` is called on `node.left` and `node.right` to get the actual values being compared.
    2. The comparison operator is mapped from `node.ctype` to a `MesonOperator` enum.
    3. The `operator_call()` method of the left-hand side object (which is an `InterpreterObject`) is invoked with the operator and the un-holderized right-hand side value.
* **Output:** An `InterpreterObject` holding a boolean value (`True` or `False`) indicating the result of the comparison.

**Example Input and Output for `evaluate_if()`:**

* **Input (AST for `if debug\n  message('Debug mode is on')\nendif`):**
    * `node`: An `mparser.IfClauseNode`.
    * `node.ifs[0].condition`: An `mparser.IdNode` with the value `"debug"`.
    * `node.ifs[0].block`: An `mparser.CodeBlockNode` containing a `mparser.FunctionNode` for `message()`.
* **Assumption:** The variable `"debug"` exists in the interpreter's scope.
* **Process:**
    1. `evaluate_statement(node.ifs[0].condition)` is called, which retrieves the value of the `"debug"` variable. Let's assume it's `True`.
    2. The `operator_call(MesonOperator.BOOL, None)` method of the `debug` object is called, which likely returns the boolean value itself.
    3. Since the condition is `True`, `evaluate_codeblock(node.ifs[0].block)` is called, executing the `message()` function.
* **Output:** The `message()` function would be executed, potentially printing "Debug mode is on" to the console (depending on how the `message()` function is implemented).

**Common User or Programming Errors:**

This code includes checks for many common errors in `meson.build` files:

1. **Syntax Errors:** The `mparser` catches basic syntax errors, but the interpreter can catch more subtle issues.
    * **Example:** `project(name = 'MyProject', 'cpp')` (missing comma).
2. **Type Errors:** Passing arguments of the wrong type to functions.
    * **Example:** `configure_file(input: 123, output: 'config.h')` (input should be a string).
3. **Undefined Variables:** Using a variable that hasn't been assigned a value.
    * **Example:** `message(unknown_variable)`
4. **Incorrect Number of Arguments:** Calling a function with the wrong number of arguments.
    * **Example:** `library('mylib')` (missing source files).
5. **Assignments in Argument Lists:**  Trying to assign a value using `=` inside a function call's arguments (should use `:` for keyword arguments).
    * **Example:** `library(name = 'mylib', sources = ['a.cpp', b = 'c.cpp'])`
6. **Using `void` Statements:** Trying to use the result of a statement that doesn't return a value (like an assignment) in a context where a value is expected.
    * **Example:** `if (my_var = true)`

**User Operations Leading to This Code:**

A user interacts with this code indirectly by running Meson to build a project (like Frida). Here's a typical flow:

1. **User Creates or Modifies `meson.build`:** The user writes or edits the `meson.build` file, defining the build instructions.
2. **User Runs `meson` Command:** The user executes the `meson` command (e.g., `meson setup builddir`, `meson compile -C builddir`).
3. **Meson Parses `meson.build`:**  Meson starts by calling `load_root_meson_file()` to parse the `meson.build` file into an AST.
4. **Interpreter is Created:** An instance of `InterpreterBase` (or a subclass) is created to interpret the AST.
5. **Interpretation Begins:**
   - `parse_project()` is called to process the `project()` statement.
   - `run()` is called to begin evaluating the rest of the `meson.build` file.
   - `evaluate_codeblock()` and `evaluate_statement()` are called recursively to process each statement in the file.
   - Depending on the statements, functions like `function_call()`, `assignment()`, `evaluate_if()`, etc., are invoked.
6. **Build System is Configured:** Based on the interpretation of the `meson.build` file, Meson configures the underlying build system (like Ninja).
7. **Compilation and Linking:**  The configured build system then executes the commands to compile the source code and link the libraries.

**As a Debugging Clue:**

If a developer is debugging issues with the Frida build process, understanding this code is crucial:

* **Error Messages:** Error messages originating from the interpreter (e.g., "Invalid argument", "Unknown function") directly point to issues within the `meson.build` file and the logic in this code.
* **Build Configuration:**  By examining how the interpreter processes different statements, a developer can understand how the build configuration is being generated.
* **Custom Functions and Modules:** If Frida uses custom Meson modules or functions, understanding how `function_call()` and method resolution work is essential.
* **Conditional Logic:** Debugging complex build logic involving `if` statements requires understanding how `evaluate_if()` determines which parts of the build configuration are active.

In summary, `interpreterbase.py` is a core component of Meson's build system, responsible for parsing and executing the build instructions defined in `meson.build` files. While it doesn't directly perform reverse engineering or interact with the binary level, it's fundamental to the process of building tools like Frida, which are used for those purposes. Understanding its functionality is essential for anyone working on the Frida build system or debugging build-related issues.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreterbase/interpreterbase.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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