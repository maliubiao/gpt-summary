Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand the code's functionality, its relevance to reverse engineering, its interactions with low-level systems, its logical flow, potential user errors, and how a user might reach this code.

**1. Initial Skim and Understanding the Context:**

* **File Path:** `frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreterbase/interpreterbase.py`  This tells us a lot. It's part of Frida (a dynamic instrumentation toolkit), specifically related to Swift. It's within a `releng` (release engineering) directory, using Meson (a build system), and this file is named `interpreterbase.py`. The "interpreter" part is a huge clue. This file likely handles the execution of some kind of scripting language or DSL used by Meson.
* **Copyright and License:**  Apache 2.0. Standard open-source license.
* **Imports:**  `environment`, `mparser`, `mesonlib`, various modules from `.baseobjects`, `.exceptions`, `.decorators`, `.disabler`, `.helpers`, `.operator`, `._unholder`, and standard Python libraries like `os`, `copy`, `re`, `pathlib`, `typing`, `textwrap`. These imports hint at the components this code interacts with: parsing Meson files, managing environment settings, handling exceptions, decorators (likely for feature management), disabling features, helper functions, and regular expressions.

**2. Identifying Core Functionality - The "Interpreter" Aspect:**

* **Class `InterpreterBase`:** The name is the biggest indicator. This class is the foundation for interpreting something.
* **`load_root_meson_file()`:**  Reads and parses a `meson.build` file. This is the entry point for the build system's instructions.
* **`parse_project()`:**  Processes the `project()` function call in the Meson file, which likely sets up the project's basic configuration.
* **`run()`:**  Executes the rest of the parsed Meson code.
* **`evaluate_codeblock()`, `evaluate_statement()`:** These are the heart of the interpreter. They recursively traverse the Abstract Syntax Tree (AST) and execute individual statements. The `evaluate_statement` method has a large `if-elif-else` block handling different node types in the AST (function calls, assignments, if statements, loops, etc.).
* **Function and Method Calls (`function_call()`, `method_call()`):**  Handle the execution of built-in functions and methods on objects within the Meson language.

**3. Connecting to Reverse Engineering:**

* **Frida Context:** Knowing this is part of Frida is key. Frida is used for dynamic instrumentation, which is a crucial reverse engineering technique. It allows you to inject code into running processes and observe/modify their behavior.
* **Meson's Role:** Meson, in this context, is used to build Frida's components, including the Swift bindings. The Meson scripts likely describe how to compile, link, and package the Frida Swift components.
* **Instrumentation (Indirect):** While this specific file doesn't *directly* perform instrumentation, it sets the stage. The Meson scripts it interprets define *what* gets built. These built components are what Frida uses for instrumentation. Think of it as the build instructions for the tools used in reverse engineering.

**4. Identifying Interactions with Low-Level Systems:**

* **Operating System (`os` module):**  Used for file system operations (checking if files exist, opening files).
* **File Paths and Build Processes:** The code deals with reading `meson.build` files, which are central to the build process on Linux and other systems.
* **Kernel and Frameworks (Indirect):** While not directly manipulating the kernel, the code is part of Frida, which *does*. The build process defined by these Meson files will compile code that interacts with the target system's frameworks and potentially the kernel (depending on Frida's internals).
* **Binary Handling (Implicit):** The end result of the build process is binary executables or libraries. While this Python code doesn't directly manipulate binary data, it's part of the pipeline that creates those binaries.

**5. Analyzing Logical Reasoning:**

* **Conditional Evaluation (`evaluate_if()`, `evaluate_comparison()`, `evaluate_andstatement()`, `evaluate_orstatement()`):**  The code implements logical operators and conditional execution based on the truthiness of expressions. This is fundamental to any programming language interpreter.
* **Looping (`evaluate_foreach()`):**  The code supports looping constructs, allowing repetitive execution of code blocks.
* **Variable Management:** The interpreter keeps track of variables and their values.

**6. Identifying Potential User Errors:**

* **Invalid `meson.build` Syntax:**  The code includes error handling for parsing errors (`mparser.ParseException`), missing `meson.build` files, empty files, and incorrect project definitions.
* **Using Void Statements:** The code explicitly checks for and raises errors when trying to perform operations on "void" statements (statements that don't produce a value).
* **Incorrect Argument Usage:**  Errors are raised for incorrect argument order (keyword arguments before positional), using keyword arguments in array construction, and providing the wrong number of variables in `foreach` loops.
* **Type Errors:**  The code checks for type compatibility in comparisons, arithmetic operations, and indexing.
* **Overwriting Built-in Variables:** The interpreter prevents users from accidentally overwriting internal variables.

**7. Tracing User Actions to the Code:**

* **Running the Meson Build System:** A user would typically run a command like `meson build` or `ninja` from the root of their Frida Swift project.
* **Meson Reads `meson.build`:** Meson, as part of its initialization, reads and parses the `meson.build` file located in the project's source directory.
* **`InterpreterBase` is Instantiated:** Meson creates an instance of the `InterpreterBase` class to handle the interpretation of the `meson.build` file.
* **`load_root_meson_file()` is Called:**  This method reads the contents of the `meson.build` file.
* **Parsing:** The `mparser.Parser` is used to create the AST.
* **`parse_project()` is Called:**  The `project()` call is evaluated.
* **`run()` is Called:** The rest of the `meson.build` file is executed by traversing the AST through `evaluate_codeblock()` and `evaluate_statement()`.

**Self-Correction/Refinement During the Process:**

* **Initial Focus on Direct Frida Functionality:**  At first, one might focus too much on the "Frida" part and expect direct instrumentation code. However, the file path and the presence of "meson" quickly indicate its role in the build system.
* **Understanding the "Interpreter" Concept:** Realizing this is a language interpreter is crucial. The code structure (AST traversal, statement evaluation) then makes more sense.
* **Connecting Meson to Frida:** The key realization is that Meson builds Frida. This code is part of the *build process*, not the runtime instrumentation itself. It defines *how* the Frida tools are created.
* **More Specific Examples:** Initially, the examples for reverse engineering or low-level interactions might be too general. Thinking about concrete scenarios (e.g., building a Frida gadget for Android) helps provide more specific and relevant examples.

By following these steps, systematically analyzing the code, and refining the understanding based on the context and code structure, a comprehensive analysis like the example provided can be achieved.
This Python code snippet belongs to the `InterpreterBase` class within the Meson build system, which is used by Frida to manage its build process. `InterpreterBase` serves as the foundation for interpreting Meson's build definition language. Let's break down its functionalities and relate them to the concepts you mentioned.

**Functionalities of `interpreterbase.py`:**

1. **Meson Language Interpretation:** The core purpose of this file is to define the base logic for interpreting the Meson build definition language. It provides the mechanisms to:
    * **Parse `meson.build` files:** The `load_root_meson_file` method reads and parses the main build definition file (`meson.build`).
    * **Evaluate statements:** The `evaluate_statement` method is the central piece, handling the execution of various Meson language constructs (function calls, assignments, conditionals, loops, etc.).
    * **Manage variables:** It keeps track of variables defined in the `meson.build` file and their values.
    * **Handle function and method calls:** The `function_call` and `method_call` methods manage the invocation of built-in Meson functions and methods on objects.
    * **Implement control flow:** It handles `if`, `foreach`, `continue`, and `break` statements to control the execution flow of the Meson build script.
    * **Perform arithmetic and logical operations:** It evaluates arithmetic, comparison, and logical expressions.
    * **Handle data structures:** It supports arrays and dictionaries.

2. **Object Handling:** Meson uses a system of "holders" to manage different types of objects within the interpreter. This file defines:
    * **Object Holders:** The `ObjectHolder` class (imported) is a base class for wrapping native Python objects to be used within the Meson interpreter.
    * **Holder Mapping:** The `holder_map` and `bound_holder_map` dictionaries map Python types to their corresponding `ObjectHolder` classes, allowing the interpreter to wrap Python objects appropriately.

3. **Error Handling:** It includes mechanisms for catching and handling errors during the interpretation process, such as:
    * **`InterpreterException` and its subclasses:** Defines various exception types for different error conditions in the Meson language.
    * **`InvalidCode`:** Raised for syntactically incorrect Meson code.
    * **`InvalidArguments`:** Raised when functions or methods are called with incorrect arguments.

4. **Feature Management:** It integrates with Meson's feature management system:
    * **`@FeatureNew` decorator:** Used to mark when specific language features were introduced in Meson versions.
    * **`Disabler`:** A class to represent disabled features or blocks of code.

**Relationship to Reverse Engineering:**

While this specific file doesn't directly perform reverse engineering, it plays a crucial role in the **build process of Frida itself**, which is a powerful dynamic instrumentation tool heavily used in reverse engineering.

* **Building Frida's Components:** The Meson build system, driven by the interpretation logic in this file, is responsible for compiling and linking Frida's core components, including the Frida Swift bindings. This involves compiling C/C++ code, potentially Swift code, and other languages.
* **Configuration and Customization:**  Meson allows Frida's developers to configure the build process, enabling/disabling features, specifying dependencies, and tailoring the build for different platforms (Linux, Android, etc.). This configuration is done through `meson.build` files, which are interpreted by the code in this file.
* **Preparing for Instrumentation:**  The successful build of Frida, managed by Meson, is a prerequisite for using Frida to perform dynamic instrumentation on applications for reverse engineering purposes.

**Examples of Relationship to Reverse Engineering:**

Imagine a Frida developer wants to add a new feature to Frida's Swift bindings that requires a specific library. They would modify the `meson.build` file to:

```meson
swift_library('my_new_feature',
  sources: 'my_new_feature.swift',
  dependencies: some_dependency, # This dependency information is processed by this interpreter
)
```

The `InterpreterBase` would process this `swift_library` function call, resolve the `some_dependency`, and instruct the build system on how to compile and link the new feature. This built feature would then be used in reverse engineering tasks.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This file doesn't directly interact with the binary level or kernel/frameworks. However, the **build process it manages** is deeply connected to these areas:

* **Binary Bottom:** The Meson build system orchestrates the compilation and linking of source code into binary executables and libraries. The compilers and linkers invoked by Meson work directly at the binary level.
* **Linux and Android Kernel:** When building Frida for Linux or Android, Meson will configure the build process to target those specific operating systems and their kernel ABIs. This might involve using specific compiler flags, linking against kernel headers, and handling platform-specific dependencies.
* **Android Frameworks:** Building Frida for Android often involves interacting with Android's framework (e.g., ART runtime). Meson would manage the dependencies on Android SDK components and ensure that the built Frida components can interact correctly with the Android runtime environment.

**Example:** When building Frida for Android, the `meson.build` file might contain instructions to:

```meson
executable('frida-server',
  sources: 'frida-server.c',
  # ... other settings
  c_args: ['-DANDROID', '-I/path/to/android/ndk/sysroot/usr/include'], # Specifying Android-specific compiler flags
  link_args: ['-landroid'], # Linking against Android-specific libraries
)
```

The `InterpreterBase` would process these directives and instruct the underlying build tools (like `gcc` or `clang`) to compile the `frida-server` executable with the specified Android-specific settings.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:** A `meson.build` file containing the following snippet:

```meson
my_variable = 10 + 5
if my_variable > 12:
    print('Variable is greater than 12')
else:
    print('Variable is not greater than 12')
```

**Processing within `InterpreterBase`:**

1. **`evaluate_statement(AssignmentNode)`:**  The interpreter encounters the assignment `my_variable = 10 + 5`.
2. **`evaluate_arithmeticstatement(ArithmeticNode)`:** It evaluates `10 + 5`, resulting in the integer `15`.
3. **`assignment(AssignmentNode)`:** The value `15` is assigned to the variable `my_variable` in the interpreter's `variables` dictionary.
4. **`evaluate_statement(IfClauseNode)`:** The `if` statement is encountered.
5. **`evaluate_comparison(ComparisonNode)`:** The condition `my_variable > 12` is evaluated.
6. **`get_variable(IdNode)`:** The value of `my_variable` (which is `15`) is retrieved.
7. **Comparison:** `15 > 12` evaluates to `True`.
8. **`evaluate_codeblock(CodeBlockNode)`:** The code block within the `if` statement is executed.
9. **`function_call(FunctionNode)`:** The `print` function is called with the argument `'Variable is greater than 12'`.

**Hypothetical Output (from Meson's perspective):** Meson would then proceed with the build process based on the evaluation of the `meson.build` file. In this specific example, the `print` function within Meson would output the string to the console during the Meson configuration stage.

**User or Programming Common Usage Errors:**

1. **Incorrect Syntax in `meson.build`:**  Users might write invalid Meson code, such as typos in function names, missing colons, or incorrect argument types.

   **Example:**
   ```meson
   # Typo in function name
   configurate_file(input : 'config.in', output : 'config.h')
   ```
   The `InterpreterBase` would raise an `InvalidCode` exception when trying to find the function `configurate_file`.

2. **Incorrect Argument Types:** Calling a Meson function with arguments of the wrong type.

   **Example:**
   ```meson
   add_subdirectory(true) # Expected a string for subdirectory name
   ```
   The `InterpreterBase` would raise an `InvalidArguments` exception because `add_subdirectory` expects a string.

3. **Referencing Undefined Variables:** Trying to use a variable that hasn't been assigned a value.

   **Example:**
   ```meson
   if my_undefined_variable: # my_undefined_variable was never assigned
       print('Something')
   ```
   The `InterpreterBase` would raise an `InvalidCode` exception when trying to `get_variable('my_undefined_variable')`.

**How User Operations Reach This Code (Debugging Clues):**

1. **User runs `meson setup builddir`:** This command initiates the Meson configuration process.
2. **Meson locates the `meson.build` file:** Meson searches for the `meson.build` file in the source directory.
3. **`InterpreterBase` is instantiated:** Meson creates an instance of the `InterpreterBase` class to handle the interpretation.
4. **`load_root_meson_file()` is called:** This method reads and parses the `meson.build` file. If there are parsing errors, exceptions from `mparser` will be raised.
5. **`parse_project()` is called:** This method specifically handles the `project()` function call. Errors here often relate to missing or incorrect project information.
6. **`run()` is called:** This method starts the main interpretation loop, calling `evaluate_codeblock` and `evaluate_statement` for each statement in the `meson.build` file.

**Debugging Scenario:**

If a user encounters an error during the Meson configuration, the error message will often include a traceback pointing to the line in the `meson.build` file where the error occurred. The `InterpreterBase` methods like `evaluate_statement` and the exception handling mechanisms are what generate these error messages.

For example, if a user gets an `InvalidArguments` error, the traceback might show that the error originated within the `function_call` method when trying to call a specific Meson function with incorrect arguments. This would give the user a starting point to examine the function call in their `meson.build` file and identify the issue.

In summary, `interpreterbase.py` is the foundational component for interpreting the Meson build language within the Frida project. While it doesn't directly perform reverse engineering, it is essential for building the tools that are used for reverse engineering. It manages the execution of build scripts, handles variables and functions, and provides error reporting, making it a critical piece of Frida's development infrastructure.

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreterbase/interpreterbase.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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