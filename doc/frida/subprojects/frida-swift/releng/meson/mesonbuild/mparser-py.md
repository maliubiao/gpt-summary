Response:
The user wants a summary of the functionality of the provided Python code. This file, `mparser.py`, is part of the Frida dynamic instrumentation tool and is responsible for parsing a specific domain-specific language used in Meson build files.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename `mparser.py` and the mention of "Meson build files" immediately suggest that this code is a *parser*. Parsers take text input (code) and convert it into a structured representation (an Abstract Syntax Tree or AST).

2. **Lexical Analysis (Lexing):**  The code contains a `Lexer` class. Lexers are the first step in parsing. They break down the input text into a stream of tokens. The `token_specification` attribute in the `Lexer` confirms this, as it defines regular expressions for various language elements like keywords, identifiers, operators, etc.

3. **Syntactic Analysis (Parsing):** The code contains a `Parser` class. Parsers take the token stream from the lexer and build the AST based on the grammar of the language. The various `e1`, `e2`, ... methods in the `Parser` class strongly suggest a recursive descent parser implementation, where each method handles a specific grammar rule or precedence level.

4. **Abstract Syntax Tree (AST):**  The code defines numerous classes like `CodeBlockNode`, `AssignmentNode`, `FunctionNode`, etc. These classes represent the nodes in the AST. Each node holds information about a specific language construct.

5. **Error Handling:** The code includes `ParseException` and `BlockParseException` classes. These are used to report errors during the parsing process, indicating issues with the syntax of the input code.

6. **Relationship to Reverse Engineering (as requested):**  Frida is a tool for dynamic instrumentation, often used in reverse engineering. While the *parser itself* doesn't directly perform reverse engineering, it's a crucial component for tools like Frida that need to understand and manipulate software behavior. The DSL it parses might be used to define hooks, breakpoints, or other instrumentation logic.

7. **Relationship to Binary/Kernel/Frameworks (as requested):**  Again, the *parser itself* isn't directly interacting with these low-level aspects. However, the *output* of the parser (the AST) is likely used by other parts of Frida that *do* interact with these levels. The parsed DSL might configure how Frida interacts with processes at a binary level or hooks into Android framework components.

8. **Logical Reasoning/Input-Output (as requested):**  While detailed input/output examples would require tracing the parsing process, the core idea is:
    * **Input:** Textual code written in the Meson DSL.
    * **Output:** A structured AST representation of that code.

9. **Common User Errors (as requested):** The `Lexer` and `Parser` classes contain checks for common syntax errors, such as using double quotes instead of single quotes for strings or having newlines within single-quoted strings.

10. **User Operation and Debugging (as requested):**  A user interacts with this code indirectly when they use Frida and write scripts that Frida needs to interpret. If there's a syntax error in their Frida script (which likely follows the grammar defined by this parser), this `mparser.py` will be invoked, and it will throw a `ParseException`. This exception provides debugging information to the user about where the error occurred.

11. **Structure the Summary:** Organize the identified functionalities into logical categories like "Lexing," "Parsing," "AST Generation," and so on. This makes the summary clear and easy to understand.

12. **Address the "Part 1" request:**  Conclude by summarizing the overall functionality as requested in the prompt for the first part.

By following these steps, we can arrive at a comprehensive and accurate summary of the `mparser.py` file's functionality, addressing all the specific points raised in the user's prompt.
好的，让我们来分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/mparser.py` 这个文件的功能。

**主要功能归纳：**

这个 Python 源代码文件定义了一个用于解析 Meson 构建系统所使用的特定领域语言（DSL）的解析器。其核心功能是将 Meson 构建文件中的文本代码转换成一种结构化的表示形式，即抽象语法树（AST）。

更具体来说，它包含了以下几个关键组成部分和功能：

1. **词法分析器 (Lexer):**
   - `Lexer` 类负责将输入的 Meson 代码字符串分解成一系列称为“token”的词法单元。
   - 它使用正则表达式来识别不同的语言元素，例如关键字 (`if`, `else`, `foreach`)、标识符、数字、字符串、运算符等。
   - 它还处理注释和空白字符。
   - 词法分析器会识别并报告一些基本的语法错误，例如使用了双引号而不是单引号。

2. **语法分析器 (Parser):**
   - `Parser` 类负责接收词法分析器产生的 token 流，并根据 Meson 语言的语法规则构建抽象语法树（AST）。
   - 它实现了递归下降解析算法，通过一系列的 `e1`, `e2`, ... 等方法来处理不同优先级的表达式和语句。
   - 它识别各种语法结构，例如赋值语句、函数调用、方法调用、数组、字典、条件语句 (`if`, `elif`, `else`)、循环语句 (`foreach`) 等。
   - 语法分析器会检查语法错误，例如期望某个 token 但实际遇到了其他 token。

3. **抽象语法树 (AST) 节点定义:**
   - 文件中定义了大量的类，例如 `CodeBlockNode`, `AssignmentNode`, `FunctionNode`, `IfNode`, `ForeachClauseNode` 等，这些类代表了 Meson 语言中不同的语法结构。
   - 每个 AST 节点都存储了该语法结构的相关信息，例如所在的文件名、行号、列号，以及子节点等。

4. **错误处理:**
   - 定义了 `ParseException` 和 `BlockParseException` 异常类，用于在词法分析和语法分析过程中发生错误时抛出。
   - 这些异常包含了错误发生的文本、行号、列号等信息，有助于用户定位错误。

**与逆向方法的关联 (及举例说明):**

虽然这个文件本身不直接执行逆向操作，但它是 Frida 工具链的一部分，而 Frida 是一个被广泛用于动态分析和逆向工程的工具。

- **Frida 脚本的解析:**  用户在使用 Frida 进行动态插桩时，通常会编写 JavaScript 或 Python 脚本来定义他们想要执行的操作，例如 hook 函数、修改内存等。  在某些情况下，Frida 可能需要解析一些类似配置文件的内容，这些配置文件的语法可能与这里定义的 Meson 语言类似。虽然这里解析的是 Meson 的构建文件，但理解解析器的工作原理有助于理解 Frida 如何处理用户的输入指令。
- **动态分析配置:** 假设 Frida 的某些高级功能允许用户使用类似于 Meson 语法的配置文件来描述动态分析的流程或条件。那么，这个解析器（或者类似的解析器）就负责理解这些配置，并将它们转换成 Frida 可以执行的内部表示。

**与二进制底层，Linux, Android 内核及框架的知识的关联 (及举例说明):**

这个 `mparser.py` 文件专注于语法解析，本身并不直接涉及二进制底层、内核或框架的交互。 然而：

- **编译过程:** Meson 是一个构建系统，它的输出是用于编译和链接最终二进制文件的指令。`mparser.py` 解析的 Meson 构建文件定义了如何构建目标软件，这最终会涉及到二进制文件的生成。
- **Frida 的应用场景:** Frida 常被用于分析运行在 Linux 和 Android 平台上的程序，包括应用程序和系统框架。理解构建过程和构建文件有助于逆向工程师了解目标软件的结构和依赖关系，为后续的动态分析提供上下文信息。

**逻辑推理 (及假设输入与输出):**

虽然代码本身执行的是语法分析，并没有复杂的业务逻辑，但解析过程涉及到对 token 流的逻辑判断和结构化。

**假设输入 (Meson 代码片段):**

```meson
project('my_project', 'cpp')

if get_option('enable_feature')
  add_subdirectory('feature_module')
endif

my_executable = executable('my_app', 'main.cpp')
```

**预期输出 (AST 的大致结构):**

虽然直接输出 AST 对象的文本表示会很冗长，但可以描述其结构：

- 一个 `CodeBlockNode` 作为根节点。
- 包含多个子节点，例如：
    - 一个 `FunctionNode` 代表 `project('my_project', 'cpp')` 调用。
    - 一个 `IfClauseNode` 代表 `if` 语句。
        - `IfNode` 包含条件表达式 `FunctionNode` (代表 `get_option('enable_feature')`) 和一个子 `CodeBlockNode`。
        - 子 `CodeBlockNode` 包含一个 `FunctionNode` 代表 `add_subdirectory('feature_module')` 调用。
    - 一个 `AssignmentNode` 代表 `my_executable = executable('my_app', 'main.cpp')`。

**用户或编程常见的使用错误 (及举例说明):**

- **字符串引号不匹配:**
  ```meson
  my_string = "hello'  # 错误：使用了双引号开始，单引号结束
  ```
  `Lexer` 会抛出 `ParseException`，提示双引号不被支持。用户应该使用单引号或三引号。

- **`if` 语句缺少 `endif`:**
  ```meson
  if true
    message('inside if')
  # 错误：缺少 endif
  ```
  `Parser` 在解析到文件末尾时，期望 `endif` token，但没有找到，会抛出 `BlockParseException`。

- **函数调用参数错误:**
  ```meson
  executable('my_app')  # 错误：缺少源文件参数
  ```
  虽然 `mparser.py` 负责解析语法结构，但更高级的语义检查（例如函数参数个数）会在后续阶段进行。不过，如果语法结构本身错误（例如括号不匹配），`mparser.py` 就会报错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Meson 构建文件 `meson.build`:** 这是用户与 Meson 构建系统交互的起点。用户在文件中描述项目的构建规则。
2. **用户运行 `meson` 命令:**  用户在项目根目录下执行 `meson setup builddir` 或类似的命令来配置构建。
3. **Meson 读取并解析 `meson.build`:** Meson 构建系统会读取项目中的 `meson.build` 文件。
4. **调用 `mparser.py` 进行语法解析:**  Meson 内部会调用 `mparser.py` 中的 `Parser` 类来解析 `meson.build` 文件的内容。
5. **如果 `meson.build` 文件存在语法错误:**  `mparser.py` 在解析过程中会遇到不符合语法规则的 token 序列，从而抛出 `ParseException` 或 `BlockParseException`。
6. **Meson 显示错误信息:**  Meson 会捕获这些异常，并向用户显示包含文件名、行号、列号以及错误信息的提示，帮助用户定位并修复 `meson.build` 文件中的错误。

因此，当用户收到与 `mparser.py` 相关的错误提示时，这意味着他们在编写 `meson.build` 文件时引入了语法错误，导致解析器无法正确理解其意图。调试线索就是错误信息中指示的文件和行列号，用户需要检查这些位置附近的 Meson 代码。

**本部分功能归纳：**

`frida/subprojects/frida-swift/releng/meson/mesonbuild/mparser.py` 文件的主要功能是**对 Meson 构建系统使用的领域特定语言进行词法分析和语法分析，将源代码转换成抽象语法树（AST）**。它是 Meson 构建过程中的关键组成部分，负责理解构建文件的结构和内容，并为后续的构建步骤提供结构化的数据表示。虽然它本身不直接执行逆向操作或与底层系统交互，但它是 Frida 工具链的一部分，理解其工作原理有助于理解 Frida 如何处理配置和用户输入，并且它解析的构建文件内容也为理解目标软件的构建过程提供了重要信息。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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