Response:
Let's break down the thought process to analyze this Python code and generate the detailed explanation.

**1. Initial Understanding and Purpose:**

The first step is to recognize that this is a core component of an interpreter, specifically for the Meson build system. The file path `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreterbase/interpreterbase.py` hints that Frida (a dynamic instrumentation toolkit) uses Meson for its build process, and this code is part of Meson itself, specifically the base interpreter functionality.

**2. High-Level Functionality Identification:**

Reading through the class definition `InterpreterBase`, several key responsibilities become apparent:

* **Parsing:** It loads and parses `meson.build` files.
* **Evaluation:** It evaluates the parsed Abstract Syntax Tree (AST) of the build files.
* **Variable Management:** It handles variables and their assignments.
* **Function and Method Calls:** It executes function and method calls.
* **Control Flow:** It manages `if`, `foreach`, and other control flow structures.
* **Type Handling:** It deals with different data types and custom `InterpreterObject` wrappers.
* **Error Handling:** It raises various exceptions for invalid code or arguments.

**3. Detailed Functionality Breakdown (Iterating Through the Code):**

Now, go through the code section by section, noting the purpose of each method and its interactions:

* **`__init__`:**  Initialization - stores paths, initializes dictionaries for functions, built-ins, variables, etc.
* **`load_root_meson_file`:** Reads and parses the `meson.build` file using the `mparser` module. Crucial for starting the interpretation.
* **`parse_project`:** Evaluates the initial `project()` function call. Essential for setting up the project's languages and compilers.
* **`sanity_check_ast`:** Ensures the first line is a `project()` call, verifying basic file structure.
* **`run`:**  The main execution loop after the `project()` call.
* **`evaluate_codeblock`:** Executes a sequence of statements within a code block (like inside an `if` or `foreach`).
* **`evaluate_statement`:**  The central dispatcher – determines the type of statement and calls the appropriate evaluation method. This is a critical function.
* **Evaluation methods for different statement types (`evaluate_arraystatement`, `evaluate_dictstatement`, `evaluate_if`, `evaluate_comparison`, etc.):** Each of these handles a specific type of node in the AST, performing the corresponding logic. Pay close attention to how they interact with `InterpreterObject`s and the `MesonOperator`.
* **`function_call` and `method_call`:**  Handle the execution of functions and methods, including argument processing.
* **`_holderify` and `_unholder_args`:** Manage the wrapping and unwrapping of Python objects into `InterpreterObject`s. This is a key part of Meson's type system within the interpreter.
* **`reduce_arguments`:**  Processes arguments passed to functions and methods, handling positional and keyword arguments.
* **`assignment` and `set_variable`:** Manage variable assignment and storage.
* **`get_variable`:** Retrieves variable values.
* **Exception classes (`InvalidCodeOnVoid`) and imports:** Note the error handling and dependencies on other Meson modules.

**4. Connecting to Reverse Engineering:**

Think about how the functionality relates to reverse engineering:

* **Dynamic Instrumentation (Frida connection):** The very existence of this code within the Frida project highlights its use in dynamically instrumenting processes. Meson builds Frida, and this interpreter is part of that build process. The build scripts might define steps to prepare Frida for instrumentation.
* **Understanding Build Processes:** Reverse engineers often need to understand how software is built to analyze it effectively. Meson is a build system, and understanding how Meson interprets build files is crucial for comprehending the build process of a target application.

**5. Connecting to Low-Level Concepts:**

Consider the low-level implications:

* **Build Systems and Toolchains:** Meson interacts with compilers, linkers, and other tools, which are inherently low-level. The build process translates high-level source code into machine code.
* **Kernel and Framework Knowledge:** While the interpreter itself doesn't directly manipulate the kernel, the build scripts it interprets *can* include steps to build kernel modules, Android framework components, or libraries that interact with these layers.

**6. Logical Reasoning and Examples:**

For logical reasoning, pick a specific scenario, like an `if` statement:

* **Assumption:**  A build file contains `if is_windows(): message('Building on Windows') endif`.
* **Input:** The AST representation of this `if` statement, the current operating system.
* **Output:** If the system is Windows, the `message` function is executed; otherwise, it's skipped.

Similarly, for function calls, consider a simple function:

* **Assumption:** The build file has `my_function(1, arg='hello')`.
* **Input:** The AST for this function call.
* **Output:** The `function_call` method would find the `my_function` in `self.funcs`, extract the arguments `[1]` and `{'arg': 'hello'}`, and execute the function.

**7. Common User Errors:**

Think about mistakes users make when writing `meson.build` files:

* **Syntax Errors:** Incorrect syntax (e.g., missing parentheses, typos). The parser (`mparser`) handles these initially, but the interpreter will encounter errors later if the parsing is flawed.
* **Type Mismatches:** Passing the wrong type of argument to a function.
* **Undefined Variables:** Using a variable before it's assigned.
* **Incorrect Keyword Arguments:** Using positional arguments where keyword arguments are expected, or vice versa.

**8. Tracing User Actions (Debugging Clues):**

Imagine a user encountering an error within this interpreter. How did they get there?

1. **User writes a `meson.build` file.**
2. **User runs `meson setup builddir`.**
3. **Meson reads and parses the `meson.build` file, creating the AST.**
4. **The interpreter (this code) starts evaluating the AST.**
5. **During evaluation, a specific statement (represented by a node in the AST) is being processed by `evaluate_statement`.**
6. **This leads to a call to a specific evaluation function (e.g., `evaluate_if`, `function_call`).**
7. **An error occurs within that evaluation function (e.g., `InvalidArguments`, `InvalidCode`).**

This step-by-step trace helps understand how a user's actions lead to the execution of this specific code.

**9. Structuring the Explanation:**

Finally, organize the findings into a clear and comprehensive explanation, using headings and examples. Start with a general overview, then delve into specifics, and finally connect the code to broader concepts like reverse engineering and low-level details. Use the identified functionalities as a structure for the explanation.
This Python code defines the `InterpreterBase` class, which serves as the foundation for interpreting the Meson build system's language. Frida, as a dynamic instrumentation toolkit, uses Meson for its build process. This file is a core component of Meson within the Frida project.

Let's break down its functionalities:

**Core Functionalities of `InterpreterBase`:**

1. **Parsing Meson Build Files:**
   - `load_root_meson_file()`: Reads the `meson.build` file from the specified source directory and parses its content using the `mparser` module, creating an Abstract Syntax Tree (AST). This AST represents the structure of the build instructions.
   - `parse_project()`: Specifically evaluates the `project()` function call, which is the first required statement in a `meson.build` file. This step initializes project-level settings like supported languages and compilers.
   - `sanity_check_ast()`: Ensures that the first statement in the `meson.build` file is indeed a `project()` call, enforcing a basic structure.

2. **Evaluating the Abstract Syntax Tree (AST):**
   - `run()`:  The main entry point for executing the parsed `meson.build` file after the `project()` call.
   - `evaluate_codeblock()`:  Executes a block of code represented by a `CodeBlockNode` in the AST, iterating through its statements.
   - `evaluate_statement()`:  The central dispatcher that determines the type of a statement (e.g., function call, assignment, if-clause) and calls the appropriate evaluation method.
   - Specific `evaluate_*` methods (e.g., `evaluate_if`, `evaluate_foreach`, `evaluate_comparison`, `evaluate_arithmeticstatement`): Each of these methods handles the evaluation of a specific type of AST node, implementing the logic for that construct.

3. **Variable Management:**
   - `variables`: A dictionary (`T.Dict[str, InterpreterObject]`) storing variables defined in the `meson.build` file and their corresponding `InterpreterObject` values.
   - `set_variable()`: Assigns a value to a variable, ensuring type consistency and preventing overwriting of built-in variables.
   - `get_variable()`: Retrieves the value of a variable.
   - `evaluate_assignment()`: Handles assignment statements (`=` operator).
   - `evaluate_plusassign()`: Handles plus-assignment statements (`+=` operator).

4. **Function and Method Calls:**
   - `funcs`: A dictionary (`FunctionType`) mapping function names to their Python implementations.
   - `function_call()`: Executes a function call by looking up the function in `self.funcs`, processing arguments, and calling the corresponding Python function.
   - `method_call()`: Executes a method call on an object. It retrieves the object, looks up the method, processes arguments, and calls the method.

5. **Control Flow:**
   - `evaluate_if()`: Implements the logic for `if`, `elif`, and `else` statements.
   - `evaluate_foreach()`: Implements the logic for `foreach` loops.
   - `evaluate_ternary()`: Implements the logic for ternary operators (`condition ? true_value : false_value`).
   - Handling of `continue` and `break` statements within loops.

6. **Type Handling and Object Wrapping:**
   - `InterpreterObject`: A base class (or related classes like `MesonInterpreterObject`, `MutableInterpreterObject`, `ObjectHolder`) for wrapping Python objects to provide Meson-specific behavior and type safety within the interpreter.
   - `holder_map` and `bound_holder_map`: Dictionaries that map Python types to their corresponding `ObjectHolder` classes. `ObjectHolder` acts as a wrapper around Python objects, providing a consistent interface for operations within the interpreter.
   - `_holderify()`:  Wraps a Python object into an appropriate `InterpreterObject` (usually an `ObjectHolder`).
   - `_unholder_args()`:  Unwraps `InterpreterObject` arguments back to their underlying Python values before passing them to Python functions.

7. **Argument Processing:**
   - `reduce_arguments()`: Processes the arguments passed to functions and methods, handling both positional and keyword arguments.
   - `expand_default_kwargs()`:  Handles the special `kwargs` argument which allows passing a dictionary of keyword arguments.

8. **Error Handling:**
   - Defines custom exception classes like `InterpreterException`, `InvalidArguments`, `InvalidCode`, etc., for reporting errors during interpretation.
   - Includes mechanisms to track the current line number and file for error reporting.

**Relationship to Reverse Engineering (with examples):**

This code, being the interpreter for Meson build files, directly impacts how Frida is built. Understanding it is crucial for reverse engineers who want to:

* **Analyze Frida's Build Process:** By examining the `meson.build` files and how this interpreter processes them, a reverse engineer can understand the steps involved in compiling and linking Frida's components, including:
    - **Compiler Flags and Definitions:** The `meson.build` files will contain instructions on how to invoke the compiler, including flags and preprocessor definitions. Understanding these can reveal compile-time configurations that influence Frida's behavior.
    - **Dependencies:** The build files specify the libraries and other components that Frida depends on. This knowledge is essential for understanding Frida's architecture and potential attack surfaces.
    - **Custom Build Steps:** Frida might have custom build steps defined in the `meson.build` files. Understanding how these steps are executed by the interpreter can reveal specific build logic.

    **Example:**  A reverse engineer might find a conditional statement in `meson.build` that sets a specific compiler flag only when building for a particular architecture. This could indicate architecture-specific optimizations or workarounds.

* **Modify Frida's Build:**  If a reverse engineer wants to modify Frida's build process (e.g., to inject custom code or change its behavior), understanding this interpreter is paramount. They need to know how to manipulate the `meson.build` files in a way that the interpreter will understand.

    **Example:** A reverse engineer might add a new compilation unit or link against a different library by modifying the `sources` or `link_with` arguments in the `meson.build` file.

**Relationship to Binary Bottom, Linux, Android Kernel & Framework (with examples):**

While the interpreter itself doesn't directly interact with the binary level or the kernel, the *build process it orchestrates* does.

* **Binary Bottom:** The ultimate output of the Meson build process is binary executables and libraries. The interpreter's job is to guide the compilation and linking steps that produce these binaries. Understanding the build process can reveal how different parts of Frida are compiled and linked together.

    **Example:** The `meson.build` files will specify the linker flags used to create the final Frida library or executable. These flags can have implications for security features like Position Independent Executables (PIE) or Relocation Read-Only (RELRO).

* **Linux and Android Kernel & Framework:**  Frida often interacts deeply with the operating system kernel and framework, especially on Linux and Android. The build process might involve:
    - **Building Kernel Modules:**  If Frida requires kernel-level components, the `meson.build` files could contain instructions for building these modules.
    - **Compiling Against System Libraries:** Frida will likely depend on system libraries provided by the Linux or Android environment. The build files will specify these dependencies.
    - **Targeting Specific Architectures:** The build process needs to handle different target architectures (e.g., x86, ARM) and potentially incorporate architecture-specific code.

    **Example:**  On Android, the `meson.build` files might include logic to compile Frida's agent library to target different Android architectures (arm, arm64, x86, x86_64) and link against Android system libraries.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

```meson
# Part of a meson.build file
my_variable = 'hello'
if get_env('DEBUG') == '1':
  message('Debug mode is enabled!')
  my_variable += ' world'
endif
```

**Interpreter's Logical Reasoning:**

1. **`evaluate_assignment(node_for_my_variable_assignment)`:**
   - Evaluates the right-hand side: `'hello'` (a string literal).
   - Sets the variable `my_variable` in `self.variables` to an `InterpreterObject` holding the string `'hello'`.

2. **`evaluate_if(node_for_if_clause)`:**
   - **`evaluate_comparison(node_for_get_env_comparison)`:**
     - **`function_call(node_for_get_env)`:** Calls the `get_env` function (presumably a built-in or defined function) with the argument `'DEBUG'`. **Assume the environment variable `DEBUG` is set to `'1'`.** The function returns the string `'1'`.
     - Compares the result `'1'` with the string literal `'1'`. The comparison evaluates to `True`.
   - Since the condition is `True`, the interpreter executes the code block within the `if` statement.
     - **`function_call(node_for_message)`:** Calls the `message` function with the argument `'Debug mode is enabled!'`, which would print this message during the build process.
     - **`evaluate_plusassign(node_for_my_variable_plus_assign)`:**
       - Gets the current value of `my_variable` from `self.variables`: `'hello'`.
       - Evaluates the right-hand side: `' world'`.
       - Performs string concatenation: `'hello' + ' world'` resulting in `'hello world'`.
       - Updates the value of `my_variable` in `self.variables` to an `InterpreterObject` holding `'hello world'`.

**Hypothetical Output (during the build process):**

```
Debug mode is enabled!
```

And the variable `my_variable` in the interpreter's state would hold the value `'hello world'`.

**Common User/Programming Errors (and how they might reach this code):**

1. **Syntax Errors in `meson.build`:**
   - **Example:** `if get_env('DEBUG') = '1'` (incorrect assignment operator).
   - **How it reaches the code:** The `mparser.Parser` in `load_root_meson_file()` would likely raise a `mparser.ParseException` before even reaching the evaluation stage.

2. **Type Mismatches:**
   - **Example:** Calling a function that expects a string with an integer argument.
   - **How it reaches the code:** The `function_call()` method would call the specific function implementation. If the Python function expects a string and receives an integer, it would raise a `TypeError` which would be caught and wrapped in an `InterpreterException`.

3. **Using Undefined Variables:**
   - **Example:** `message(undefined_variable)`.
   - **How it reaches the code:** The `evaluate_statement()` for the `IdNode` `undefined_variable` would be called, leading to `get_variable('undefined_variable')`. This would raise an `InvalidCode` exception because the variable is not in `self.variables`.

4. **Incorrect Number of Arguments to a Function:**
   - **Example:** Calling a function that expects two arguments with only one.
   - **How it reaches the code:** The `function_call()` method would call the specific function implementation. If the Python function expects a specific number of arguments and receives a different number, it would raise a `TypeError` which would be caught and wrapped in an `InterpreterException`.

**User Operations to Reach This Code (as a Debugging Clue):**

1. **User writes or modifies a `meson.build` file.**
2. **User runs the `meson` command (e.g., `meson setup builddir` or `meson compile -C builddir`).**
3. **Meson loads and parses the `meson.build` file using `load_root_meson_file()`.**
4. **The interpreter (an instance of a class inheriting from `InterpreterBase`) is created.**
5. **The interpreter starts evaluating the AST, beginning with `parse_project()` and then `run()`.**
6. **As the interpreter traverses the AST, `evaluate_codeblock()` and `evaluate_statement()` are called for each node.**
7. **Specific statements (like function calls, assignments, or control flow structures) trigger the corresponding `evaluate_*` methods within the `InterpreterBase` class.**
8. **If an error occurs during any of these evaluation steps (e.g., an invalid function call, a type mismatch, or an undefined variable), an exception is raised within the `InterpreterBase` methods, providing debugging information (like the line number and file).**

Therefore, this `interpreterbase.py` file is a crucial piece of the Meson build system, responsible for understanding and executing the build instructions defined in `meson.build` files. Its functionality directly impacts how projects like Frida are built, and understanding it is valuable for reverse engineers who need to analyze or modify the build process.

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreterbase/interpreterbase.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```