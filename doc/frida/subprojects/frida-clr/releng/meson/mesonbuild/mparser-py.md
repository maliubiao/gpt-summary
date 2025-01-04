Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understand the Goal:** The request is to analyze a Python file (`mparser.py`) from the Frida project and identify its functionalities, especially concerning reverse engineering, low-level interactions, logic, potential errors, and debugging contexts. The prompt emphasizes providing examples and context.

2. **Initial Scan and Keywords:**  A quick read-through reveals several key terms and concepts:
    * **Parsing/Parser:**  The name `mparser.py` and classes like `Parser` and `Lexer` immediately suggest this file deals with parsing some kind of language.
    * **Tokens:** The `Token` class and `Lexer`'s `lex` method indicate the input is broken down into tokens.
    * **Abstract Syntax Tree (AST):**  Classes like `BaseNode`, `StringNode`, `FunctionNode`, etc., and the `accept` method suggest the code builds an AST to represent the parsed input.
    * **Keywords:** The `Lexer` defines a set of keywords like `if`, `else`, `foreach`, etc., which hints at a structured language.
    * **Exceptions:** `ParseException` and `BlockParseException` point to error handling during parsing.
    * **Frida:** The file path `frida/subprojects/frida-clr/releng/meson/mesonbuild/mparser.py` places it within the Frida project context.
    * **Meson:**  The presence of "Meson development team" in the copyright and the file path components suggests this parser is for the Meson build system's configuration language.

3. **Deconstruct Functionality (Lexer):**
    * **Tokenization:** The `Lexer` class is responsible for breaking down the input `code` string into a stream of `Token` objects. This is the fundamental first step of parsing.
    * **Regular Expressions:** The `token_specification` uses regular expressions to define the patterns for different token types (identifiers, numbers, strings, operators, keywords, etc.). This is a standard technique in lexical analysis.
    * **Keyword Handling:** The `keywords` and `future_keywords` sets manage reserved words in the language.
    * **Error Handling:** The `ParseException` is raised for lexical errors (e.g., unsupported characters).
    * **Multiline String Handling:** The code specifically handles multiline strings with `'''`, addressing a common pitfall.

4. **Deconstruct Functionality (Parser):**
    * **AST Construction:** The `Parser` class takes the token stream from the `Lexer` and constructs an AST. The various `*Node` classes represent different syntactic elements of the language.
    * **Recursive Descent Parsing:** The structure of the `Parser`'s methods (e.g., `e1`, `e2`, `e3`, ...) suggests a recursive descent parsing approach, where each method handles a specific level of grammar precedence.
    * **Precedence Handling:** The numbered `e1` to `e9` methods likely correspond to different operator precedence levels in the language grammar.
    * **Error Handling:** The `ParseException` and `BlockParseException` are raised for syntactic errors. `BlockParseException` provides more context for errors within code blocks.
    * **Specific Language Constructs:** The presence of methods like `if_statement`, `foreach_statement`, and nodes like `IfNode`, `ForeachClauseNode` indicates the parser handles control flow and looping constructs.
    * **Function and Method Calls:**  The `FunctionNode` and `MethodNode` classes and the `e7` method handle function and method call syntax.
    * **Data Structures:** `ArrayNode` and `DictNode` handle the parsing of lists and dictionaries.

5. **Connecting to the Prompt's Specific Points:**

    * **Reverse Engineering:** The parser itself isn't directly involved in *runtime* reverse engineering. However, it parses the *build configuration* for Frida's CLR bridge. This configuration likely *influences* how the bridge interacts with the CLR at runtime, which could be a target of reverse engineering. *Example:*  Imagine the configuration specifies which CLR assemblies to load. A reverse engineer might analyze the parsed configuration to understand Frida's CLR interaction points.

    * **Binary/Low-Level/Kernel/Framework:**  Again, the parser is about *configuration*. However, the *output* of this parsing process (the AST or the data it generates) would be used by other parts of Frida to interact with the underlying system. *Example:* The configuration might specify compiler flags or paths to native libraries. These directly relate to binary compilation and linking. While the parser doesn't *do* these things, it sets the stage.

    * **Logical Reasoning:** The parser implements logical reasoning in terms of grammar rules and precedence. *Example:*  The `e2` and `e3` methods correctly parse `a or b and c` as `a or (b and c)` due to the order of operations. *Hypothetical Input:* `if a and b or c:` *Output (AST structure):* An `IfNode` where the `condition` is an `OrNode` with `AndNode(a, b)` as the left operand and `c` as the right operand.

    * **User/Programming Errors:** The parser explicitly handles several common errors: using double quotes, newlines in single-quoted strings, incorrect order of keyword arguments. *Example:* If a user writes `print("hello")`, the parser will raise a `ParseException` about double quotes.

    * **Debugging:** The file path itself (`frida/subprojects/...`) is a clue. Developers working on Frida's CLR bridge would interact with this code. The error messages generated by the parser would be debugging breadcrumbs. *Scenario:* A developer adds a new feature to the Meson build and introduces a syntax error in a `.meson` file. The parser will flag the error, pointing them to this `mparser.py` and the location of the error.

6. **Summarization (Part 1):**  The final step is to synthesize the observations into a concise summary, focusing on the core function of parsing the Meson build language for the Frida CLR bridge. Highlighting the AST construction and error handling is crucial.

This detailed thought process combines code analysis with understanding the project context and explicitly addressing the different aspects of the prompt. It involves iterative reading, keyword identification, breaking down the code into functional units, and then connecting those units to the specific questions asked.
This Python code file, `mparser.py`, is a crucial component of the Frida dynamic instrumentation toolkit. Specifically, it's the **parser** for a language used within the Meson build system to configure how the `frida-clr` subproject (which deals with instrumenting .NET/CLR applications) is built.

Here's a breakdown of its functionalities:

**Core Function: Parsing a Domain-Specific Language**

At its heart, `mparser.py` defines a lexer and a parser for a language that resembles Python but is tailored for build system configurations. It takes a text file (likely a `.meson` file) as input and transforms it into an Abstract Syntax Tree (AST). This AST is a structured representation of the code, making it easier for other parts of the Meson build system to understand and process the configuration instructions.

**Key Functionalities:**

1. **Lexical Analysis (Lexer):**
   - **Tokenization:** The `Lexer` class breaks down the input text into a stream of meaningful units called "tokens." These tokens represent keywords (`if`, `else`, `foreach`), identifiers (variable names), literals (strings, numbers, booleans), operators (`+`, `-`, `=`), and punctuation (`(`, `)`, `[`).
   - **Regular Expressions:**  It uses regular expressions (`re` module) to define patterns for recognizing different token types.
   - **Keyword Recognition:** It identifies reserved keywords and future keywords.
   - **Whitespace and Comment Handling:** It handles whitespace and comments, often ignoring them or using them for structure.
   - **String Literal Handling:** It handles single and multiline string literals, including escape sequences and f-strings.
   - **Error Reporting (Lexical Errors):** It raises `ParseException` for lexical errors, like encountering unsupported characters.

2. **Syntactic Analysis (Parser):**
   - **AST Construction:** The `Parser` class takes the stream of tokens from the `Lexer` and builds the AST.
   - **Grammar Rules:** It implements the grammar rules of the configuration language, defining how tokens can be combined to form valid statements and expressions.
   - **Recursive Descent Parsing:** The structure of the `Parser`'s methods (like `e1`, `e2`, etc.) suggests a recursive descent parsing strategy, where different methods handle different levels of operator precedence and grammar rules.
   - **Handling Different Language Constructs:** It has logic to parse various language constructs, such as:
     - Assignments (`a = 1`)
     - Conditional statements (`if`, `elif`, `else`)
     - Loops (`foreach`)
     - Function calls (`function_name(arg1, arg2)`)
     - Method calls (`object.method_name(arg)`)
     - Array and dictionary literals (`[1, 2]`, `{'a': 1}`)
     - Binary and unary operators (`+`, `-`, `and`, `or`, `not`)
     - Comparisons (`==`, `!=`, `<`, `>`, `in`)
     - Ternary operator (`condition ? true_value : false_value`)
   - **Error Reporting (Syntactic Errors):** It raises `ParseException` or `BlockParseException` for syntactic errors, like incorrect syntax or missing tokens. `BlockParseException` provides more context for errors within blocks of code.

3. **Abstract Syntax Tree (AST) Representation:**
   - **Node Classes:** It defines various classes (`BaseNode`, `StringNode`, `FunctionNode`, `IfNode`, etc.) to represent different elements of the parsed code in the AST. These nodes store information about the token's value, position (line number, column number), and relationships to other nodes.
   - **Visitor Pattern (Partial):** The `accept` method in `BaseNode` suggests the potential use of the visitor pattern to traverse and operate on the AST.

**Relationship to Reverse Engineering:**

While `mparser.py` itself doesn't directly perform reverse engineering at runtime, it plays an indirect but important role:

* **Configuration for Instrumentation:** The language parsed by this file configures how Frida instruments .NET/CLR applications. This configuration can specify things like:
    * Which assemblies or classes to target.
    * Specific methods to hook or intercept.
    * Custom logic to execute when certain events occur in the target application.
* **Understanding Frida's Behavior:**  Reverse engineers analyzing Frida's CLR support might need to understand the syntax and semantics of the configuration language parsed by `mparser.py` to decipher how Frida is being used or to create their own custom instrumentation scripts.
* **Analyzing Frida Internals:** Understanding how this parser works can provide insights into the internal design and architecture of Frida's CLR bridge.

**Example of Reverse Engineering Relevance:**

Imagine a `.meson` configuration file contains the line:

```
frida_module('MyTargetAssembly.dll', hooks : [
    { 'class': 'MyNamespace.MyClass', 'method': 'MyMethod', 'on_enter': 'my_enter_handler' }
])
```

A reverse engineer would need to understand the syntax defined by `mparser.py` to interpret this line as instructing Frida to hook the `MyMethod` in the `MyNamespace.MyClass` of `MyTargetAssembly.dll` and call the `my_enter_handler` function when the method is entered.

**Relationship to Binary/Low-Level, Linux, Android Kernel & Framework:**

Again, `mparser.py` is primarily a parser. Its connection to these areas is through the *purpose* of the code it parses:

* **Binary Interaction:** The configuration might influence how Frida interacts with the binary code of the target .NET application (e.g., setting breakpoints, reading/writing memory).
* **Operating System Interaction:** The configuration could potentially specify OS-level interactions or dependencies.
* **Android Framework (Indirect):** While this specific file is for the CLR bridge, the broader Frida project is heavily used on Android. The concepts of parsing configuration to guide instrumentation are similar across Frida's different components.

**Example of Binary/Low-Level Relevance:**

The parsed configuration might tell Frida to hook a specific function at a certain memory address within a loaded DLL. This directly involves low-level binary concepts.

**Logical Reasoning:**

The parser embodies logical reasoning by following the grammar rules of the language.

**Hypothetical Input:**

```
my_variable = 10 + 5
if my_variable > 12:
    print("Large")
else:
    print("Small")
```

**Hypothetical Output (Simplified AST Structure):**

```
CodeBlockNode(
  lines: [
    AssignmentNode(
      var_name: IdNode(value='my_variable'),
      operator: SymbolNode(value='='),
      value: ArithmeticNode(
        left: NumberNode(value=10),
        operator: SymbolNode(value='+'),
        right: NumberNode(value=5)
      )
    ),
    IfClauseNode(
      if_node: IfNode(
        condition: ComparisonNode(
          left: IdNode(value='my_variable'),
          operator: SymbolNode(value='>'),
          right: NumberNode(value=12)
        ),
        block: CodeBlockNode(
          lines: [
            FunctionNode(
              func_name: IdNode(value='print'),
              args: ArgumentNode(
                arguments: [StringNode(value='Large')]
              )
            )
          ]
        )
      ),
      elseblock: ElseNode(
        block: CodeBlockNode(
          lines: [
            FunctionNode(
              func_name: IdNode(value='print'),
              args: ArgumentNode(
                arguments: [StringNode(value='Small')]
              )
            )
          ]
        )
      )
    )
  ]
)
```

**User or Programming Common Usage Errors:**

The parser is designed to catch errors in the configuration files. Some common errors include:

* **Incorrect Syntax:**  Typing keywords wrong, missing parentheses or brackets, using incorrect operators.
    * **Example:** `if my_value = 5` (should be `==`) would cause a `ParseException`.
* **Using Double Quotes:** The parser explicitly disallows double quotes for strings.
    * **Example:** `message = "Hello"` would raise a `ParseException`.
* **Newline in Single-Quoted Strings:**  For multiline strings, triple single quotes (`'''`) should be used.
    * **Example:** `long_string = 'This is a\nmultiline string'` would trigger a warning and potentially an error in future versions.
* **Incorrect Order of Keyword Arguments:** If keyword arguments are specified before positional arguments in a function call.

**User Operation to Reach Here (Debugging Context):**

A developer working on Frida's CLR support might end up examining `mparser.py` in the following scenarios:

1. **Syntax Errors in Configuration:** When a user writes an invalid `.meson` file for `frida-clr`, the Meson build system will call this parser. If the parser encounters an error, it will raise a `ParseException` or `BlockParseException`, pinpointing the location of the error in the `.meson` file. The developer might then look at `mparser.py` to understand how the parsing is done and why their syntax is incorrect.
2. **Debugging Frida's CLR Functionality:** If Frida's CLR instrumentation isn't working as expected, a developer might trace the execution flow. Since the configuration drives the instrumentation, they might step through the parsing process in `mparser.py` to see how the configuration is being interpreted and if there are any discrepancies.
3. **Extending the Configuration Language:** If a developer wants to add new features or capabilities to the `frida-clr` configuration, they would need to modify the grammar and parsing logic in `mparser.py`.
4. **Understanding Meson Build System Internals:** Developers working on the Meson build system itself might need to understand how different subprojects integrate their own parsers.

**Summary of Functionalities (Part 1):**

`mparser.py` is the **parser for the configuration language used by the `frida-clr` subproject within the Meson build system**. It performs **lexical analysis** to break the configuration text into tokens and **syntactic analysis** to build an Abstract Syntax Tree (AST) representing the configuration's structure and meaning. This process involves defining grammar rules, handling different language constructs (assignments, conditionals, loops, function calls, etc.), and reporting errors for invalid syntax. The parsed configuration is then used by other parts of Frida to guide the dynamic instrumentation of .NET/CLR applications.

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2014-2017 The Meson development team

from __future__ import annotations
from dataclasses import dataclass, field
import re
import codecs
import os
import typing as T

from .mesonlib import MesonException
from . import mlog

if T.TYPE_CHECKING:
    from typing_extensions import Literal

    from .ast import AstVisitor

    BaseNodeT = T.TypeVar('BaseNodeT', bound='BaseNode')

# This is the regex for the supported escape sequences of a regular string
# literal, like 'abc\x00'
ESCAPE_SEQUENCE_SINGLE_RE = re.compile(r'''
    ( \\U[A-Fa-f0-9]{8}   # 8-digit hex escapes
    | \\u[A-Fa-f0-9]{4}   # 4-digit hex escapes
    | \\x[A-Fa-f0-9]{2}   # 2-digit hex escapes
    | \\[0-7]{1,3}        # Octal escapes
    | \\N\{[^}]+\}        # Unicode characters by name
    | \\[\\'abfnrtv]      # Single-character escapes
    )''', re.UNICODE | re.VERBOSE)

def decode_match(match: T.Match[str]) -> str:
    return codecs.decode(match.group(0).encode(), 'unicode_escape')

class ParseException(MesonException):

    ast: T.Optional[CodeBlockNode] = None

    def __init__(self, text: str, line: str, lineno: int, colno: int) -> None:
        # Format as error message, followed by the line with the error, followed by a caret to show the error column.
        super().__init__(mlog.code_line(text, line, colno))
        self.lineno = lineno
        self.colno = colno

class BlockParseException(ParseException):
    def __init__(
                self,
                text: str,
                line: str,
                lineno: int,
                colno: int,
                start_line: str,
                start_lineno: int,
                start_colno: int,
            ) -> None:
        # This can be formatted in two ways - one if the block start and end are on the same line, and a different way if they are on different lines.

        if lineno == start_lineno:
            # If block start and end are on the same line, it is formatted as:
            # Error message
            # Followed by the line with the error
            # Followed by a caret to show the block start
            # Followed by underscores
            # Followed by a caret to show the block end.
            MesonException.__init__(self, "{}\n{}\n{}".format(text, line, '{}^{}^'.format(' ' * start_colno, '_' * (colno - start_colno - 1))))
        else:
            # If block start and end are on different lines, it is formatted as:
            # Error message
            # Followed by the line with the error
            # Followed by a caret to show the error column.
            # Followed by a message saying where the block started.
            # Followed by the line of the block start.
            # Followed by a caret for the block start.
            MesonException.__init__(self, "%s\n%s\n%s\nFor a block that started at %d,%d\n%s\n%s" % (text, line, '%s^' % (' ' * colno), start_lineno, start_colno, start_line, "%s^" % (' ' * start_colno)))
        self.lineno = lineno
        self.colno = colno

TV_TokenTypes = T.TypeVar('TV_TokenTypes', int, str, bool)

@dataclass(eq=False)
class Token(T.Generic[TV_TokenTypes]):
    tid: str
    filename: str
    line_start: int
    lineno: int
    colno: int
    bytespan: T.Tuple[int, int]
    value: TV_TokenTypes

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.tid == other
        elif isinstance(other, Token):
            return self.tid == other.tid
        return NotImplemented

class Lexer:
    def __init__(self, code: str):
        if code.startswith(codecs.BOM_UTF8.decode('utf-8')):
            line, *_ = code.split('\n', maxsplit=1)
            raise ParseException('Builder file must be encoded in UTF-8 (with no BOM)', line, lineno=0, colno=0)

        self.code = code
        self.keywords = {'true', 'false', 'if', 'else', 'elif',
                         'endif', 'and', 'or', 'not', 'foreach', 'endforeach',
                         'in', 'continue', 'break'}
        self.future_keywords = {'return'}
        self.in_unit_test = 'MESON_RUNNING_IN_PROJECT_TESTS' in os.environ
        if self.in_unit_test:
            self.keywords.update({'testcase', 'endtestcase'})
        self.token_specification = [
            # Need to be sorted longest to shortest.
            ('whitespace', re.compile(r'[ \t]+')),
            ('multiline_fstring', re.compile(r"f'''(.|\n)*?'''", re.M)),
            ('fstring', re.compile(r"f'([^'\\]|(\\.))*'")),
            ('id', re.compile('[_a-zA-Z][_0-9a-zA-Z]*')),
            ('number', re.compile(r'0[bB][01]+|0[oO][0-7]+|0[xX][0-9a-fA-F]+|0|[1-9]\d*')),
            ('eol_cont', re.compile(r'\\[ \t]*(#.*)?\n')),
            ('eol', re.compile(r'\n')),
            ('multiline_string', re.compile(r"'''(.|\n)*?'''", re.M)),
            ('comment', re.compile(r'#.*')),
            ('lparen', re.compile(r'\(')),
            ('rparen', re.compile(r'\)')),
            ('lbracket', re.compile(r'\[')),
            ('rbracket', re.compile(r'\]')),
            ('lcurl', re.compile(r'\{')),
            ('rcurl', re.compile(r'\}')),
            ('dblquote', re.compile(r'"')),
            ('string', re.compile(r"'([^'\\]|(\\.))*'")),
            ('comma', re.compile(r',')),
            ('plusassign', re.compile(r'\+=')),
            ('dot', re.compile(r'\.')),
            ('plus', re.compile(r'\+')),
            ('dash', re.compile(r'-')),
            ('star', re.compile(r'\*')),
            ('percent', re.compile(r'%')),
            ('fslash', re.compile(r'/')),
            ('colon', re.compile(r':')),
            ('equal', re.compile(r'==')),
            ('nequal', re.compile(r'!=')),
            ('assign', re.compile(r'=')),
            ('le', re.compile(r'<=')),
            ('lt', re.compile(r'<')),
            ('ge', re.compile(r'>=')),
            ('gt', re.compile(r'>')),
            ('questionmark', re.compile(r'\?')),
        ]

    def getline(self, line_start: int) -> str:
        return self.code[line_start:self.code.find('\n', line_start)]

    def lex(self, filename: str) -> T.Generator[Token, None, None]:
        line_start = 0
        lineno = 1
        loc = 0
        par_count = 0
        bracket_count = 0
        curl_count = 0
        col = 0
        while loc < len(self.code):
            matched = False
            value: str = ''
            for (tid, reg) in self.token_specification:
                mo = reg.match(self.code, loc)
                if mo:
                    curline = lineno
                    curline_start = line_start
                    col = mo.start() - line_start
                    matched = True
                    span_start = loc
                    loc = mo.end()
                    span_end = loc
                    bytespan = (span_start, span_end)
                    value = mo.group()
                    if tid == 'lparen':
                        par_count += 1
                    elif tid == 'rparen':
                        par_count -= 1
                    elif tid == 'lbracket':
                        bracket_count += 1
                    elif tid == 'rbracket':
                        bracket_count -= 1
                    elif tid == 'lcurl':
                        curl_count += 1
                    elif tid == 'rcurl':
                        curl_count -= 1
                    elif tid == 'dblquote':
                        raise ParseException('Double quotes are not supported. Use single quotes.', self.getline(line_start), lineno, col)
                    elif tid in {'string', 'fstring'}:
                        if value.find("\n") != -1:
                            msg = ("Newline character in a string detected, use ''' (three single quotes) "
                                   "for multiline strings instead.\n"
                                   "This will become a hard error in a future Meson release.")
                            mlog.warning(mlog.code_line(msg, self.getline(line_start), col), location=BaseNode(lineno, col, filename))
                        value = value[2 if tid == 'fstring' else 1:-1]
                    elif tid in {'multiline_string', 'multiline_fstring'}:
                        value = value[4 if tid == 'multiline_fstring' else 3:-3]
                        lines = value.split('\n')
                        if len(lines) > 1:
                            lineno += len(lines) - 1
                            line_start = mo.end() - len(lines[-1])
                    elif tid == 'eol_cont':
                        lineno += 1
                        line_start = loc
                        tid = 'whitespace'
                    elif tid == 'eol':
                        lineno += 1
                        line_start = loc
                        if par_count > 0 or bracket_count > 0 or curl_count > 0:
                            tid = 'whitespace'
                    elif tid == 'id':
                        if value in self.keywords:
                            tid = value
                        else:
                            if value in self.future_keywords:
                                mlog.warning(f"Identifier '{value}' will become a reserved keyword in a future release. Please rename it.",
                                             location=BaseNode(lineno, col, filename))
                    yield Token(tid, filename, curline_start, curline, col, bytespan, value)
                    break
            if not matched:
                raise ParseException('lexer', self.getline(line_start), lineno, col)

@dataclass
class BaseNode:
    lineno: int
    colno: int
    filename: str = field(hash=False)
    end_lineno: int = field(hash=False)
    end_colno: int = field(hash=False)
    whitespaces: T.Optional[WhitespaceNode] = field(hash=False)

    def __init__(self, lineno: int, colno: int, filename: str,
                 end_lineno: T.Optional[int] = None, end_colno: T.Optional[int] = None) -> None:
        self.lineno = lineno
        self.colno = colno
        self.filename = filename
        self.end_lineno = end_lineno if end_lineno is not None else lineno
        self.end_colno = end_colno if end_colno is not None else colno
        self.whitespaces = None

        # Attributes for the visitors
        self.level = 0
        self.ast_id = ''
        self.condition_level = 0

    def accept(self, visitor: 'AstVisitor') -> None:
        fname = 'visit_{}'.format(type(self).__name__)
        if hasattr(visitor, fname):
            func = getattr(visitor, fname)
            if callable(func):
                func(self)

    def append_whitespaces(self, token: Token) -> None:
        if self.whitespaces is None:
            self.whitespaces = WhitespaceNode(token)
        else:
            self.whitespaces.append(token)


@dataclass(unsafe_hash=True)
class WhitespaceNode(BaseNode):

    value: str

    def __init__(self, token: Token[str]):
        super().__init__(token.lineno, token.colno, token.filename)
        self.value = ''
        self.append(token)

    def append(self, token: Token[str]) -> None:
        self.value += token.value

@dataclass(unsafe_hash=True)
class ElementaryNode(T.Generic[TV_TokenTypes], BaseNode):

    value: TV_TokenTypes
    bytespan: T.Tuple[int, int] = field(hash=False)

    def __init__(self, token: Token[TV_TokenTypes]):
        super().__init__(token.lineno, token.colno, token.filename)
        self.value = token.value
        self.bytespan = token.bytespan

class BooleanNode(ElementaryNode[bool]):
    pass

class IdNode(ElementaryNode[str]):
    pass

@dataclass(unsafe_hash=True)
class NumberNode(ElementaryNode[int]):

    raw_value: str = field(hash=False)

    def __init__(self, token: Token[str]):
        BaseNode.__init__(self, token.lineno, token.colno, token.filename)
        self.raw_value = token.value
        self.value = int(token.value, base=0)
        self.bytespan = token.bytespan

class BaseStringNode(ElementaryNode[str]):
    pass

@dataclass(unsafe_hash=True)
class StringNode(BaseStringNode):

    raw_value: str = field(hash=False)

    def __init__(self, token: Token[str], escape: bool = True):
        super().__init__(token)
        self.value = ESCAPE_SEQUENCE_SINGLE_RE.sub(decode_match, token.value) if escape else token.value
        self.raw_value = token.value

class FormatStringNode(StringNode):
    pass

@dataclass(unsafe_hash=True)
class MultilineStringNode(BaseStringNode):

    def __init__(self, token: Token[str]):
        super().__init__(token)
        self.value = token.value

class MultilineFormatStringNode(MultilineStringNode):
    pass

class ContinueNode(ElementaryNode):
    pass

class BreakNode(ElementaryNode):
    pass

class SymbolNode(ElementaryNode[str]):
    pass

@dataclass(unsafe_hash=True)
class ArgumentNode(BaseNode):

    arguments: T.List[BaseNode] = field(hash=False)
    commas: T.List[SymbolNode] = field(hash=False)
    columns: T.List[SymbolNode] = field(hash=False)
    kwargs: T.Dict[BaseNode, BaseNode] = field(hash=False)

    def __init__(self, token: Token[TV_TokenTypes]):
        super().__init__(token.lineno, token.colno, token.filename)
        self.arguments = []
        self.commas = []
        self.columns = []
        self.kwargs = {}
        self.order_error = False

    def prepend(self, statement: BaseNode) -> None:
        if self.num_kwargs() > 0:
            self.order_error = True
        if not isinstance(statement, EmptyNode):
            self.arguments = [statement] + self.arguments

    def append(self, statement: BaseNode) -> None:
        if self.num_kwargs() > 0:
            self.order_error = True
        if not isinstance(statement, EmptyNode):
            self.arguments += [statement]

    def set_kwarg(self, name: IdNode, value: BaseNode) -> None:
        if any((isinstance(x, IdNode) and name.value == x.value) for x in self.kwargs):
            mlog.warning(f'Keyword argument "{name.value}" defined multiple times.', location=self)
            mlog.warning('This will be an error in future Meson releases.')
        self.kwargs[name] = value

    def set_kwarg_no_check(self, name: BaseNode, value: BaseNode) -> None:
        self.kwargs[name] = value

    def num_args(self) -> int:
        return len(self.arguments)

    def num_kwargs(self) -> int:
        return len(self.kwargs)

    def incorrect_order(self) -> bool:
        return self.order_error

    def __len__(self) -> int:
        return self.num_args() # Fixme

@dataclass(unsafe_hash=True)
class ArrayNode(BaseNode):

    lbracket: SymbolNode
    args: ArgumentNode
    rbracket: SymbolNode

    def __init__(self, lbracket: SymbolNode, args: ArgumentNode, rbracket: SymbolNode):
        super().__init__(lbracket.lineno, lbracket.colno, args.filename, end_lineno=rbracket.lineno, end_colno=rbracket.colno+1)
        self.lbracket = lbracket
        self.args = args
        self.rbracket = rbracket

@dataclass(unsafe_hash=True)
class DictNode(BaseNode):

    lcurl: SymbolNode
    args: ArgumentNode
    rcurl: SymbolNode

    def __init__(self, lcurl: SymbolNode, args: ArgumentNode, rcurl: SymbolNode):
        super().__init__(lcurl.lineno, lcurl.colno, args.filename, end_lineno=rcurl.lineno, end_colno=rcurl.colno+1)
        self.lcurl = lcurl
        self.args = args
        self.rcurl = rcurl

class EmptyNode(BaseNode):
    pass

@dataclass(unsafe_hash=True)
class BinaryOperatorNode(BaseNode):

    left: BaseNode
    operator: SymbolNode
    right: BaseNode

    def __init__(self, left: BaseNode, operator: SymbolNode, right: BaseNode):
        super().__init__(left.lineno, left.colno, left.filename)
        self.left = left
        self.operator = operator
        self.right = right

class OrNode(BinaryOperatorNode):
    pass

class AndNode(BinaryOperatorNode):
    pass

@dataclass(unsafe_hash=True)
class ComparisonNode(BinaryOperatorNode):

    ctype: COMPARISONS

    def __init__(self, ctype: COMPARISONS, left: BaseNode, operator: SymbolNode, right: BaseNode):
        super().__init__(left, operator, right)
        self.ctype = ctype

@dataclass(unsafe_hash=True)
class ArithmeticNode(BinaryOperatorNode):

    # TODO: use a Literal for operation
    operation: str

    def __init__(self, operation: str, left: BaseNode, operator: SymbolNode, right: BaseNode):
        super().__init__(left, operator, right)
        self.operation = operation

@dataclass(unsafe_hash=True)
class UnaryOperatorNode(BaseNode):

    operator: SymbolNode
    value: BaseNode

    def __init__(self, token: Token[TV_TokenTypes], operator: SymbolNode, value: BaseNode):
        super().__init__(token.lineno, token.colno, token.filename)
        self.operator = operator
        self.value = value

class NotNode(UnaryOperatorNode):
    pass

class UMinusNode(UnaryOperatorNode):
    pass

@dataclass(unsafe_hash=True)
class CodeBlockNode(BaseNode):

    pre_whitespaces: T.Optional[WhitespaceNode] = field(hash=False)
    lines: T.List[BaseNode] = field(hash=False)

    def __init__(self, token: Token[TV_TokenTypes]):
        super().__init__(token.lineno, token.colno, token.filename)
        self.pre_whitespaces = None
        self.lines = []

    def append_whitespaces(self, token: Token) -> None:
        if self.lines:
            self.lines[-1].append_whitespaces(token)
        elif self.pre_whitespaces is None:
            self.pre_whitespaces = WhitespaceNode(token)
        else:
            self.pre_whitespaces.append(token)

@dataclass(unsafe_hash=True)
class IndexNode(BaseNode):

    iobject: BaseNode
    lbracket: SymbolNode
    index: BaseNode
    rbracket: SymbolNode

    def __init__(self, iobject: BaseNode, lbracket: SymbolNode, index: BaseNode, rbracket: SymbolNode):
        super().__init__(iobject.lineno, iobject.colno, iobject.filename)
        self.iobject = iobject
        self.lbracket = lbracket
        self.index = index
        self.rbracket = rbracket

@dataclass(unsafe_hash=True)
class MethodNode(BaseNode):

    source_object: BaseNode
    dot: SymbolNode
    name: IdNode
    lpar: SymbolNode
    args: ArgumentNode
    rpar: SymbolNode

    def __init__(self, source_object: BaseNode, dot: SymbolNode, name: IdNode, lpar: SymbolNode, args: ArgumentNode, rpar: SymbolNode):
        super().__init__(name.lineno, name.colno, name.filename, end_lineno=rpar.lineno, end_colno=rpar.colno+1)
        self.source_object = source_object
        self.dot = dot
        self.name = name
        self.lpar = lpar
        self.args = args
        self.rpar = rpar

@dataclass(unsafe_hash=True)
class FunctionNode(BaseNode):

    func_name: IdNode
    lpar: SymbolNode
    args: ArgumentNode
    rpar: SymbolNode

    def __init__(self, func_name: IdNode, lpar: SymbolNode, args: ArgumentNode, rpar: SymbolNode):
        super().__init__(func_name.lineno, func_name.colno, func_name.filename, end_lineno=rpar.end_lineno, end_colno=rpar.end_colno+1)
        self.func_name = func_name
        self.lpar = lpar
        self.args = args
        self.rpar = rpar

@dataclass(unsafe_hash=True)
class AssignmentNode(BaseNode):

    var_name: IdNode
    operator: SymbolNode
    value: BaseNode

    def __init__(self, var_name: IdNode, operator: SymbolNode, value: BaseNode):
        super().__init__(var_name.lineno, var_name.colno, var_name.filename)
        self.var_name = var_name
        self.operator = operator
        self.value = value

class PlusAssignmentNode(AssignmentNode):
    pass

@dataclass(unsafe_hash=True)
class ForeachClauseNode(BaseNode):

    foreach_: SymbolNode = field(hash=False)
    varnames: T.List[IdNode] = field(hash=False)
    commas: T.List[SymbolNode] = field(hash=False)
    column: SymbolNode = field(hash=False)
    items: BaseNode
    block: CodeBlockNode
    endforeach: SymbolNode = field(hash=False)

    def __init__(self, foreach_: SymbolNode, varnames: T.List[IdNode], commas: T.List[SymbolNode], column: SymbolNode, items: BaseNode, block: CodeBlockNode, endforeach: SymbolNode):
        super().__init__(foreach_.lineno, foreach_.colno, foreach_.filename)
        self.foreach_ = foreach_
        self.varnames = varnames
        self.commas = commas
        self.column = column
        self.items = items
        self.block = block
        self.endforeach = endforeach


@dataclass(unsafe_hash=True)
class IfNode(BaseNode):

    if_: SymbolNode
    condition: BaseNode
    block: CodeBlockNode

    def __init__(self, linenode: BaseNode, if_node: SymbolNode, condition: BaseNode, block: CodeBlockNode):
        super().__init__(linenode.lineno, linenode.colno, linenode.filename)
        self.if_ = if_node
        self.condition = condition
        self.block = block

@dataclass(unsafe_hash=True)
class ElseNode(BaseNode):

    else_: SymbolNode
    block: CodeBlockNode

    def __init__(self, else_: SymbolNode, block: CodeBlockNode):
        super().__init__(block.lineno, block.colno, block.filename)
        self.else_ = else_
        self.block = block

@dataclass(unsafe_hash=True)
class IfClauseNode(BaseNode):

    ifs: T.List[IfNode] = field(hash=False)
    elseblock: T.Union[EmptyNode, ElseNode]
    endif: SymbolNode

    def __init__(self, linenode: BaseNode):
        super().__init__(linenode.lineno, linenode.colno, linenode.filename)
        self.ifs = []
        self.elseblock = EmptyNode(linenode.lineno, linenode.colno, linenode.filename)

@dataclass(unsafe_hash=True)
class TestCaseClauseNode(BaseNode):

    testcase: SymbolNode
    condition: BaseNode
    block: CodeBlockNode
    endtestcase: SymbolNode

    def __init__(self, testcase: SymbolNode, condition: BaseNode, block: CodeBlockNode, endtestcase: SymbolNode):
        super().__init__(condition.lineno, condition.colno, condition.filename)
        self.testcase = testcase
        self.condition = condition
        self.block = block
        self.endtestcase = endtestcase

@dataclass(unsafe_hash=True)
class TernaryNode(BaseNode):

    condition: BaseNode
    questionmark: SymbolNode
    trueblock: BaseNode
    column: SymbolNode
    falseblock: BaseNode

    def __init__(self, condition: BaseNode, questionmark: SymbolNode, trueblock: BaseNode, column: SymbolNode, falseblock: BaseNode):
        super().__init__(condition.lineno, condition.colno, condition.filename)
        self.condition = condition
        self.questionmark = questionmark
        self.trueblock = trueblock
        self.column = column
        self.falseblock = falseblock


@dataclass(unsafe_hash=True)
class ParenthesizedNode(BaseNode):

    lpar: SymbolNode = field(hash=False)
    inner: BaseNode
    rpar: SymbolNode = field(hash=False)

    def __init__(self, lpar: SymbolNode, inner: BaseNode, rpar: SymbolNode):
        super().__init__(lpar.lineno, lpar.colno, inner.filename, end_lineno=rpar.lineno, end_colno=rpar.colno+1)
        self.lpar = lpar
        self.inner = inner
        self.rpar = rpar


if T.TYPE_CHECKING:
    COMPARISONS = Literal['==', '!=', '<', '<=', '>=', '>', 'in', 'notin']

comparison_map: T.Mapping[str, COMPARISONS] = {
    'equal': '==',
    'nequal': '!=',
    'lt': '<',
    'le': '<=',
    'gt': '>',
    'ge': '>=',
    'in': 'in',
    'not in': 'notin',
}

# Recursive descent parser for Meson's definition language.
# Very basic apart from the fact that we have many precedence
# levels so there are not enough words to describe them all.
# Enter numbering:
#
# 1 assignment
# 2 or
# 3 and
# 4 comparison
# 5 arithmetic
# 6 negation
# 7 funcall, method call
# 8 parentheses
# 9 plain token

class Parser:
    def __init__(self, code: str, filename: str):
        self.lexer = Lexer(code)
        self.stream = self.lexer.lex(filename)
        self.current: Token = Token('eof', '', 0, 0, 0, (0, 0), None)
        self.previous = self.current
        self.current_ws: T.List[Token] = []

        self.getsym()
        self.in_ternary = False

    def create_node(self, node_type: T.Type[BaseNodeT], *args: T.Any, **kwargs: T.Any) -> BaseNodeT:
        node = node_type(*args, **kwargs)
        for ws_token in self.current_ws:
            node.append_whitespaces(ws_token)
        self.current_ws = []
        return node

    def getsym(self) -> None:
        self.previous = self.current
        try:
            self.current = next(self.stream)

            while self.current.tid in {'eol', 'comment', 'whitespace'}:
                self.current_ws.append(self.current)
                if self.current.tid == 'eol':
                    break
                self.current = next(self.stream)

        except StopIteration:
            self.current = Token('eof', '', self.current.line_start, self.current.lineno, self.current.colno + self.current.bytespan[1] - self.current.bytespan[0], (0, 0), None)

    def getline(self) -> str:
        return self.lexer.getline(self.current.line_start)

    def accept(self, s: str) -> bool:
        if self.current.tid == s:
            self.getsym()
            return True
        return False

    def accept_any(self, tids: T.Tuple[str, ...]) -> str:
        tid = self.current.tid
        if tid in tids:
            self.getsym()
            return tid
        return ''

    def expect(self, s: str) -> bool:
        if self.accept(s):
            return True
        raise ParseException(f'Expecting {s} got {self.current.tid}.', self.getline(), self.current.lineno, self.current.colno)

    def block_expect(self, s: str, block_start: Token) -> bool:
        if self.accept(s):
            return True
        raise BlockParseException(f'Expecting {s} got {self.current.tid}.', self.getline(), self.current.lineno, self.current.colno, self.lexer.getline(block_start.line_start), block_start.lineno, block_start.colno)

    def parse(self) -> CodeBlockNode:
        block = self.codeblock()
        try:
            self.expect('eof')
        except ParseException as e:
            e.ast = block
            raise
        return block

    def statement(self) -> BaseNode:
        return self.e1()

    def e1(self) -> BaseNode:
        left = self.e2()
        if self.accept('plusassign'):
            operator = self.create_node(SymbolNode, self.previous)
            value = self.e1()
            if not isinstance(left, IdNode):
                raise ParseException('Plusassignment target must be an id.', self.getline(), left.lineno, left.colno)
            assert isinstance(left.value, str)
            return self.create_node(PlusAssignmentNode, left, operator, value)
        elif self.accept('assign'):
            operator = self.create_node(SymbolNode, self.previous)
            value = self.e1()
            if not isinstance(left, IdNode):
                raise ParseException('Assignment target must be an id.',
                                     self.getline(), left.lineno, left.colno)
            assert isinstance(left.value, str)
            return self.create_node(AssignmentNode, left, operator, value)
        elif self.accept('questionmark'):
            if self.in_ternary:
                raise ParseException('Nested ternary operators are not allowed.',
                                     self.getline(), left.lineno, left.colno)

            qm_node = self.create_node(SymbolNode, self.previous)
            self.in_ternary = True
            trueblock = self.e1()
            self.expect('colon')
            column_node = self.create_node(SymbolNode, self.previous)
            falseblock = self.e1()
            self.in_ternary = False
            return self.create_node(TernaryNode, left, qm_node, trueblock, column_node, falseblock)
        return left

    def e2(self) -> BaseNode:
        left = self.e3()
        while self.accept('or'):
            operator = self.create_node(SymbolNode, self.previous)
            if isinstance(left, EmptyNode):
                raise ParseException('Invalid or clause.',
                                     self.getline(), left.lineno, left.colno)
            left = self.create_node(OrNode, left, operator, self.e3())
        return left

    def e3(self) -> BaseNode:
        left = self.e4()
        while self.accept('and'):
            operator = self.create_node(SymbolNode, self.previous)
            if isinstance(left, EmptyNode):
                raise ParseException('Invalid and clause.',
                                     self.getline(), left.lineno, left.colno)
            left = self.create_node(AndNode, left, operator, self.e4())
        return left

    def e4(self) -> BaseNode:
        left = self.e5()
        for nodename, operator_type in comparison_map.items():
            if self.accept(nodename):
                operator = self.create_node(SymbolNode, self.previous)
                return self.create_node(ComparisonNode, operator_type, left, operator, self.e5())
        if self.accept('not'):
            ws = self.current_ws.copy()
            not_token = self.previous
            if self.accept('in'):
                in_token = self.previous
                self.current_ws = self.current_ws[len(ws):]  # remove whitespaces between not and in
                temp_node = EmptyNode(in_token.lineno, in_token.colno, in_token.filename)
                for w in ws:
                    temp_node.append_whitespaces(w)

                not_token.bytespan = (not_token.bytespan[0], in_token.bytespan[1])
                not_token.value += temp_node.whitespaces.value + in_token.value
                operator = self.create_node(SymbolNode, not_token)
                return self.create_node(ComparisonNode, 'notin', left, operator, self.e5())
        return left

    def e5(self) -> BaseNode:
        return self.e5addsub()

    def e5addsub(self) -> BaseNode:
        op_map = {
            'plus': 'add',
            'dash': 'sub',
        }
        left = self.e5muldiv()
        while True:
            op = self.accept_any(tuple(op_map.keys()))
            if op:
                operator = self.create_node(SymbolNode, self.previous)
                left = self.create_node(ArithmeticNode, op_map[op], left, operator, self.e5muldiv())
            else:
                break
        return left

    def e5muldiv(self) -> BaseNode:
        op_map = {
            'percent': 'mod',
            'star': 'mul',
            'fslash': 'div',
        }
        left = self.e6()
        while True:
            op = self.accept_any(tuple(op_map.keys()))
            if op:
                operator = self.create_node(SymbolNode, self.previous)
                left = self.create_node(ArithmeticNode, op_map[op], left, operator, self.e6())
            else:
                break
        return left

    def e6(self) -> BaseNode:
        if self.accept('not'):
            operator = self.create_node(SymbolNode, self.previous)
            return self.create_node(NotNode, self.current, operator, self.e7())
        if self.accept('dash'):
            operator = self.create_node(SymbolNode, self.previous)
            return self.create_node(UMinusNode, self.current, operator, self.e7())
        return self.e7()

    def e7(self) -> BaseNode:
        left = self.e8()
        block_start = self.current
        if self.accept('lparen'):
            lpar = self.create_node(SymbolNode, block_start)
            args = self.args()
            self.block_expect('rparen', block_start)
            rpar = self.create_node(SymbolNode, self.previous)
            if not isinstance(left, IdNode):
                raise ParseException('Function call must be applied to plain id',
                                     self.getline(), left.lineno, left.colno)
            assert isinstance(left.value, str)
            left = self.create_node(FunctionNode, left, lpar, args, rpar)
        go_again = True
        while go_again:
            go_again = False
            if self.accept('dot'):
                go_again = True
                left = self.method_call(left)
            if self.accept('lbracket'):
                go_again = True
                left = self.index_call(left)
        return left

    def e8(self) -> BaseNode:
        block_start = self.current
        if self.accept('lparen'):
            lpar = self.create_node(SymbolNode, block_start)
            e = self.statement()
            self.block_expect('rparen', block_start)
            rpar = self.create_node(SymbolNode, self.previous)
            return ParenthesizedNode(lpar, e, rpar)
        elif self.accept('lbracket'):
            lbracket = self.create_node(SymbolNode, block_start)
            args = self.args()
            self.block_expect('rbracket', block_start)
            rbracket = self.create_node(SymbolNode, self.previous)
            return self.create_node(ArrayNode, lbracket, args, rbracket)
        elif self.accept('lcurl'):
            lcurl = se
"""


```