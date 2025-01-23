Response:
Let's break down the thought process for analyzing the provided Python code snippet. The goal is to understand its functionality and relate it to reverse engineering and low-level concepts, as well as common usage scenarios and debugging.

**1. Initial Skim and Identification of Purpose:**

The first step is to quickly read through the code, paying attention to class names, function names, and imported modules. Keywords like "interpreter," "meson," "AST," "evaluate," "function_call," "method_call," and the file path itself (`frida/releng/meson/mesonbuild/interpreterbase/interpreterbase.py`) strongly suggest this is the core of an interpreter for a build system (Meson) used by Frida.

**2. Identifying Key Classes and Their Roles:**

* **`InterpreterBase`:** This is the central class. Its methods seem to handle the execution of the build scripts. The presence of `evaluate_...` methods suggests it walks and executes an Abstract Syntax Tree (AST).
* **`InterpreterObject`, `MesonInterpreterObject`, `MutableInterpreterObject`, `ObjectHolder`, `IterableObject`, `ContextManagerObject`:** These classes seem to represent different types of values or objects within the interpreted language. `ObjectHolder` likely wraps native Python objects to manage their interaction within the interpreter.
* **`Disabler`:** This suggests a mechanism for conditionally disabling parts of the build process.
* **Exception Classes (`BreakRequest`, `ContinueRequest`, `InterpreterException`, etc.):** These indicate how the interpreter handles control flow and errors.

**3. Analyzing Core Functionality:**

* **AST Parsing and Evaluation:** The `load_root_meson_file`, `parse_project`, `sanity_check_ast`, `run`, and `evaluate_codeblock` methods clearly point to the process of reading, parsing, and executing the Meson build files. The `evaluate_statement` method is the workhorse for processing individual AST nodes.
* **Variable Management:**  The `variables` dictionary, along with `set_variable` and `get_variable`, manages the state of variables during interpretation.
* **Function and Method Calls:** `function_call` and `method_call` handle executing built-in functions and methods on objects.
* **Operator Overloading:** The `operator_call` methods within the `InterpreterObject` hierarchy, coupled with the `MesonOperator` enum, suggest that the interpreted language supports various operators (+, -, *, /, ==, !=, etc.).
* **Control Flow:**  `evaluate_if`, `evaluate_foreach`, `evaluate_ternary` handle conditional execution and looping.
* **String Formatting:** `evaluate_fstring` indicates support for formatted strings.
* **Argument Handling:** `reduce_arguments` processes arguments passed to functions and methods, differentiating between positional and keyword arguments.

**4. Connecting to Reverse Engineering:**

This is where deeper thinking comes in. How does an interpreter for a build system relate to reverse engineering, particularly in the context of Frida?

* **Dynamic Instrumentation Setup:** Frida uses Meson to build its agent libraries that get injected into target processes. Understanding how Meson scripts are interpreted helps in understanding the build process of Frida itself. If you were trying to modify Frida's build process, this code would be relevant.
* **Frida's Internal DSL (Domain Specific Language):**  While this code is for Meson, the concept of an interpreter is core to many dynamic instrumentation tools. Frida itself has a JavaScript API, and understanding interpreters helps conceptualize how that API is processed. Think of this as a simplified model for understanding how Frida executes your JavaScript code.
* **Build System Vulnerabilities:**  In some scenarios, vulnerabilities can exist within build systems themselves. Understanding the interpreter logic could be relevant if you were researching the security of the Meson build system.

**5. Identifying Interactions with Low-Level Concepts:**

* **File System Operations:** `os.path.join`, `os.path.isfile`, and reading files (`with open(...)`) demonstrate interaction with the file system, which is a fundamental low-level concept.
* **Process Execution (Implicit):** While not explicitly present in this snippet, a build system ultimately leads to compiling and linking code, which involves invoking compilers and linkers – interacting with the operating system to create and manage processes. This is an implicit connection.
* **Kernel and Framework (Android Context):**  Frida often interacts with the internals of operating systems, including the Linux and Android kernels. While this specific interpreter code doesn't directly manipulate kernel structures, the *purpose* of Frida, which relies on this build system, is deeply tied to these low-level aspects. The build scripts might configure compilation flags or link against libraries that directly interact with the kernel or Android framework.

**6. Logic Inference (Hypothetical Input/Output):**

Choose a simple function call within the code. For example, consider an `if` statement:

* **Input:**  A Meson script containing: `if some_variable == 'value': print('yes') endif`
* **Interpreter Action:** The `evaluate_if` function would be called. It would evaluate the comparison `some_variable == 'value'` by:
    * Getting the value of `some_variable` using `get_variable`.
    * Creating `InterpreterObject` instances for both the variable's value and the string literal `'value'`.
    * Calling the `operator_call` method with `MesonOperator.EQUALS`.
* **Output:** If the comparison is true, the `evaluate_codeblock` method would be called for the `print('yes')` block. If false, the `else` block (if present) would be evaluated.

**7. Common Usage Errors:**

Think about common mistakes when writing code in *any* language, and how they might manifest within this interpreter:

* **Incorrect Syntax:**  The parser will catch many of these, but issues within expressions might lead to `InvalidCode` exceptions.
* **Type Mismatches:** Trying to perform operations on incompatible types (e.g., adding a string to a number) would be handled by the `operator_call` methods and likely raise an `InterpreterException`.
* **Undefined Variables:** Using a variable before it's assigned would trigger the `InvalidCode` exception in `get_variable`.
* **Incorrect Argument Order/Types:**  The `reduce_arguments` function and function/method implementations would catch these, raising `InvalidArguments`.

**8. Debugging Scenario (How to reach this code):**

Imagine a user encountering an error during the Frida build process:

1. **User Action:** The user runs a `meson` command to configure the Frida build (e.g., `meson setup build`).
2. **Meson Execution:** Meson starts interpreting the `meson.build` files in the Frida source tree.
3. **Error Encountered:**  Let's say there's a syntax error in one of the `meson.build` files, or a function is called with the wrong arguments.
4. **Parser/Interpreter Execution:** The parser (`mparser.Parser`) or the interpreter (`InterpreterBase`) encounters the error. The `evaluate_statement` method, while processing the AST, might raise an `InvalidCode` or `InvalidArguments` exception.
5. **Stack Trace:**  The Python interpreter would produce a stack trace. If the error originates within the interpretation logic, the stack trace would lead into the methods of `InterpreterBase`, potentially highlighting the specific line of code within `interpreterbase.py` where the error occurred.

This step-by-step breakdown allows for a structured and comprehensive analysis of the provided code, covering its functionality, relevance to reverse engineering, low-level interactions, logic, common errors, and debugging scenarios.
This Python code snippet belongs to the `InterpreterBase` class within the Frida dynamic instrumentation tool's build system (Meson). This class is fundamental to how Meson interprets and executes the build instructions defined in `meson.build` files. Let's break down its functionalities:

**Core Functionalities of `InterpreterBase`:**

1. **Meson Build File Interpretation:** The primary function of this class is to interpret the Meson build files (`meson.build`). It reads these files, parses them into an Abstract Syntax Tree (AST), and then evaluates the statements within the AST to configure the build process.

2. **AST Traversal and Evaluation:**
   - It uses methods like `evaluate_codeblock` and `evaluate_statement` to recursively traverse the AST.
   - `evaluate_statement` handles different types of AST nodes (function calls, assignments, if statements, loops, etc.), executing the corresponding logic.

3. **Variable Management:**
   - It maintains a dictionary `self.variables` to store variables defined in the build files.
   - Methods like `set_variable` and `get_variable` are used to manage these variables.

4. **Function and Method Call Handling:**
   - `function_call` handles calls to built-in Meson functions (e.g., `project()`, `library()`).
   - `method_call` handles calls to methods on objects within the Meson language.

5. **Operator Overloading:**
   - It implements operator overloading for various operations (comparison, arithmetic, logical) using the `operator_call` method on `InterpreterObject` instances.

6. **Control Flow Management:**
   - It implements control flow structures like `if`, `foreach`, and ternary operators using methods like `evaluate_if`, `evaluate_foreach`, and `evaluate_ternary`.
   - It handles `break` and `continue` statements within loops.

7. **String Manipulation:**
   - It supports formatted strings (f-strings) through `evaluate_fstring` and `evaluate_multiline_fstring`.

8. **Argument Handling:**
   - `reduce_arguments` is responsible for processing arguments passed to functions and methods, handling both positional and keyword arguments.

9. **Error Handling:**
   - It defines and raises various exception types (`InterpreterException`, `InvalidArguments`, `InvalidCode`, etc.) to handle errors during interpretation.

10. **Type Handling and Object Management:**
    - It uses `InterpreterObject`, `MesonInterpreterObject`, and other related classes to represent different types of values within the Meson language.
    - `ObjectHolder` is used to wrap native Python objects so they can be used within the interpreter.
    - `_holderify` converts Python values into `InterpreterObject` instances.
    - `_unholder_args` extracts the underlying Python values from `InterpreterObject` instances.

11. **Disabling Logic:**
    - The `Disabler` class and `is_disabled` function provide a mechanism to conditionally disable parts of the build process.

**Relationship with Reverse Engineering:**

This code is directly related to reverse engineering in the context of Frida because:

* **Frida's Build System:** Frida uses Meson as its build system. Understanding how Meson interprets build files is crucial for anyone wanting to modify or debug Frida's build process. Reverse engineers working with Frida might need to understand the build structure, how different components are compiled and linked, and how dependencies are managed. This code is the engine that drives that process.

* **Understanding Build Logic:** By analyzing this code, a reverse engineer can understand the specific logic encoded in Frida's `meson.build` files. This includes understanding how different parts of Frida are configured, what build options are available, and how conditional compilation is implemented.

**Example:**

Let's say a `meson.build` file contains the following:

```meson
if host_machine.system() == 'linux'
  add_definitions('-DFRIDA_LINUX')
endif
```

The `InterpreterBase` class would handle this as follows:

1. **Parsing:** The parser would create an `IfClauseNode` representing this `if` statement.
2. **Evaluation:** The `evaluate_if` method would be called.
3. **Condition Evaluation:** `evaluate_statement` would be called on the condition `host_machine.system() == 'linux'`.
   - This would involve a `method_call` to the `system()` method of the `host_machine` object.
   - A `comparison` node would be evaluated using `evaluate_comparison`.
4. **Block Execution:** If the condition evaluates to `True`, `evaluate_codeblock` would be called on the block containing `add_definitions('-DFRIDA_LINUX')`.
   - This would involve a `function_call` to the `add_definitions` function.

**Relationship with Binary Bottom, Linux, Android Kernel, and Framework:**

While this specific Python code doesn't directly interact with the binary bottom, Linux kernel, or Android kernel, it's indirectly related because:

* **Build Configuration:** The interpreted Meson files configure how Frida's C/C++ code is compiled and linked. This compilation process generates the binary code that interacts directly with the underlying operating system, including the kernel.

* **Conditional Compilation for Platforms:** Meson is used to handle platform-specific configurations. For example, the `host_machine.system()` call (as seen in the example above) allows the build system to execute different commands or define different compiler flags based on whether the target system is Linux, Android, etc. This directly impacts the final binaries that interact with the kernel.

* **Library Linking:** Meson manages the linking of libraries. Frida often links against system libraries or Android framework libraries to perform its instrumentation tasks. The `InterpreterBase` class processes instructions that control this linking process.

**Example:**

A `meson.build` file might contain:

```meson
if target_machine.system() == 'android'
  dependency('android-ndk')
  shared_library('frida-agent', 'agent.c', dependencies: android_ndk)
endif
```

The interpreter would:

1. Evaluate the condition `target_machine.system() == 'android'`.
2. If true, it would handle the `dependency()` function call to locate the Android NDK.
3. It would then process the `shared_library()` function call, potentially setting up specific compiler flags and linker options required for building shared libraries on Android. This involves knowledge of the Android NDK and how shared libraries are built for Android.

**Logical Inference (Hypothetical Input and Output):**

**Input (Meson code):**

```meson
my_variable = 10 + 5
if my_variable > 12
  message('Variable is greater than 12')
else
  message('Variable is not greater than 12')
endif
```

**Interpreter Steps:**

1. **`assignment(node)`:**  Evaluates `10 + 5` using `evaluate_arithmeticstatement`, resulting in `15`. Sets the variable `my_variable` to `15`.
2. **`evaluate_if(node)`:**
   - **Condition Evaluation:**
     - `get_variable('my_variable')` returns the `InterpreterObject` representing `15`.
     - `evaluate_statement(12)` creates an `InterpreterObject` for `12`.
     - `evaluate_comparison(node)` with `>` operator compares `15` and `12`, resulting in `True`.
   - **Block Execution:** Since the condition is `True`, `evaluate_codeblock` is called for the `if` block.
   - **`function_call(node)`:** The `message('Variable is greater than 12')` function call is executed.

**Output (from the interpreter's perspective):**

The interpreter would trigger the execution of the `message()` function, which would likely print "Variable is greater than 12" to the console during the Meson configuration phase.

**Common User or Programming Errors:**

1. **Syntax Errors in `meson.build`:**  Typos, incorrect grammar, or invalid Meson language constructs will be caught by the parser or the interpreter, leading to exceptions like `mparser.ParseException` or `InvalidCode`.

   **Example:** `libary('mylib', 'source.c')` (incorrect spelling of `library`).

2. **Type Mismatches:**  Trying to perform operations on incompatible types.

   **Example:** `my_variable = 'hello' + 5` would likely raise an `InterpreterException` within `evaluate_arithmeticstatement` because you can't directly add a string and an integer in Meson (without explicit conversion).

3. **Using Undefined Variables:**  Referencing a variable that hasn't been assigned a value.

   **Example:** `message(undefined_variable)` would raise an `InvalidCode` exception in `get_variable`.

4. **Incorrect Function Arguments:**  Passing the wrong number or type of arguments to a Meson function.

   **Example:** `library('mylib')` (missing the source file argument) would be caught by the `function_call` logic or within the specific function's implementation.

5. **Logical Errors in Build Logic:**  Incorrect conditions in `if` statements or loops that don't behave as expected. This might not cause a runtime error in the interpreter but could lead to an incorrectly configured build.

**How User Operations Reach This Code (Debugging Clue):**

1. **User Executes Meson Command:** The user typically starts by running a Meson command, such as `meson setup builddir` to configure the build, or `meson compile -C builddir` to compile the project.

2. **Meson Invokes the Interpreter:** When `meson setup` is executed, Meson loads and parses the `meson.build` file in the project's root directory and any subdirectories. This involves creating an instance of `InterpreterBase`.

3. **Parsing and AST Generation:** The `load_root_meson_file` method is called to read the `meson.build` file, and a parser (`mparser.Parser`) is used to generate the AST.

4. **Interpretation and Evaluation:** The `run` method of `InterpreterBase` is called to begin evaluating the AST. This involves calls to `evaluate_codeblock` and `evaluate_statement` for each node in the AST.

5. **Error Encountered (Debugging Scenario):** If the user has made an error in their `meson.build` file (e.g., a syntax error or an invalid function call), the parser or the interpreter will detect this error during the parsing or evaluation phase.

6. **Exception Raised:**  The relevant exception (e.g., `mparser.ParseException`, `InvalidCode`, `InvalidArguments`) is raised within the `InterpreterBase` code.

7. **Stack Trace:** The Python interpreter will generate a stack trace, showing the sequence of function calls that led to the error. This stack trace will typically include calls within the `frida/releng/meson/mesonbuild/interpreterbase/interpreterbase.py` file, pointing to the specific line of code where the error occurred.

**Example Debugging Scenario:**

If a user gets an error like:

```
meson.build:3:0: ERROR: Unknown function "libary".
```

The debugging process would involve:

1. The user ran `meson setup builddir`.
2. Meson loaded and parsed `meson.build`.
3. The parser encountered the misspelled function name "libary".
4. Within `InterpreterBase`, the `function_call` method (or a related parsing stage) would have detected that "libary" is not a known function.
5. An `InvalidCode` exception (or a `mparser.ParseException`) would be raised within `interpreterbase.py`.
6. The stack trace would point to the line in `interpreterbase.py` where the unknown function was detected, as well as the line in the `meson.build` file where the error occurred.

Therefore, understanding the structure and functionality of `InterpreterBase` is essential for anyone debugging Meson build issues or wanting to deeply understand how Frida's build process works.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreterbase/interpreterbase.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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