Response:
The user wants a summary of the functionality of the provided Python code. The code is a parser for a domain-specific language, likely used within the Frida dynamic instrumentation framework.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The filename `mparser.py` and the code's structure (Lexer, Parser, Node classes) strongly indicate that this file is responsible for parsing input text into a structured representation (an Abstract Syntax Tree - AST).

2. **Lexical Analysis (Lexer):**
   - The `Lexer` class is responsible for breaking down the raw input string into a stream of tokens.
   - It defines regular expressions for various token types (keywords, identifiers, numbers, strings, operators, punctuation).
   - It handles whitespace and comments.
   - It manages line and column numbers for error reporting.
   - Special handling for multiline strings and f-strings is present.

3. **Syntactic Analysis (Parser):**
   - The `Parser` class takes the token stream from the `Lexer` and builds the AST.
   - It uses a recursive descent parsing approach, evident in the `e1`, `e2`, ..., `e8` functions, which represent different precedence levels of the grammar.
   - It defines node classes (like `AssignmentNode`, `IfNode`, `FunctionNode`) to represent the structure of the parsed code.
   - It handles operator precedence and associativity.
   - It includes error handling for syntax errors.

4. **Abstract Syntax Tree (AST):**
   - The `@dataclass` definitions for various `*Node` classes represent the nodes of the AST.
   - Each node stores information about its position in the source code (line and column numbers, filename).
   - Different node types represent different syntactic constructs (e.g., assignments, function calls, conditional statements, loops).

5. **Error Handling:**
   - `ParseException` and `BlockParseException` are used to signal errors during parsing.
   - The error messages include context like the line number and the problematic line of code.

6. **Relationship to Reverse Engineering (Indirect):** While this code doesn't directly perform reverse engineering, it's a *tool* that could be used in a reverse engineering context. Frida is a dynamic instrumentation tool, and this parser likely processes scripts or configuration that *control* Frida's behavior. These scripts could be used to inspect and modify the behavior of running processes, a common activity in reverse engineering.

7. **Binary/OS/Kernel Concepts (Indirect):** Similar to reverse engineering, the parser itself doesn't directly interact with these low-level concepts. However, the *language* it parses is likely used to interact with these concepts *via* Frida. For instance, the parsed language might have functions to hook into specific kernel functions or read memory from a process.

8. **Logical Reasoning (Present):** The parser implements logical reasoning in the sense that it follows a predefined grammar to interpret the input. The precedence levels in the `e1` to `e8` functions ensure that expressions are parsed correctly according to operator precedence rules.

9. **User Errors (Addressed):** The parser handles common syntax errors (e.g., expecting a specific token, incorrect operator usage, unclosed parentheses). The error messages aim to guide the user to fix these errors.

10. **User Operation to Reach Here:**  A user would write a script or configuration file in the language that this parser understands. Frida would then use this parser to process that input before executing the instrumentation tasks.

11. **Summary of Functionality:** Based on the above points, the core functionality is parsing a specific language into an AST. This AST then serves as an intermediate representation for further processing by Frida.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/mparser.py` 文件的第一部分源代码，它主要负责将文本形式的 Meson 构建定义文件解析成一种结构化的表示形式，即抽象语法树（AST）。以下是它的功能归纳：

**主要功能：词法分析和语法分析（Parsing）**

1. **词法分析 (Lexing):**
   - `Lexer` 类负责将输入的 Meson 代码字符串分解成一个个有意义的单元，称为“词法单元”（tokens）。
   - 它定义了一系列的正则表达式来识别不同类型的 tokens，例如：
     - 关键字 (keywords): `true`, `false`, `if`, `else` 等
     - 标识符 (identifiers):  变量名、函数名等
     - 数字 (numbers):  整数、二进制数、八进制数、十六进制数
     - 字符串 (strings):  单引号或三单引号括起来的文本
     - F-字符串 (f-strings):  以 `f'` 或 `f'''` 开头的格式化字符串
     - 运算符 (operators): `+`, `-`, `*`, `/`, `=`, `==`, `!=` 等
     - 分隔符 (delimiters): `(`, `)`, `[`, `]`, `{`, `}` 等
     - 注释 (comments): 以 `#` 开头的行
     - 空格 (whitespace) 和换行符 (newlines)
   - `lex` 方法是 `Lexer` 的核心，它遍历输入代码，根据定义的规则识别并产生 token 流。
   - 它会处理转义字符，例如 `\n`, `\t`, `\x00` 等。
   - 它会检查一些基本的错误，例如在字符串中使用双引号（建议使用单引号）。
   - 对于未来的关键字，会发出警告信息。

2. **语法分析 (Parsing):**
   - `Parser` 类接收 `Lexer` 生成的 token 流，并根据 Meson 语言的语法规则，将这些 tokens 组织成一个抽象语法树（AST）。
   - 它使用递归下降的解析方法，通过一系列的 `e1`, `e2`, ..., `e8` 函数来处理不同优先级的表达式。
   - 它定义了各种 AST 节点类（以 `*Node` 结尾），用于表示不同的语法结构，例如：
     - `AssignmentNode`: 赋值语句
     - `IfNode`: `if` 条件语句
     - `ForeachClauseNode`: `foreach` 循环语句
     - `FunctionNode`: 函数调用
     - `MethodNode`: 方法调用
     - `ArrayNode`: 数组字面量
     - `DictNode`: 字典字面量
     - `BinaryOperatorNode`: 二元运算符表达式
     - `UnaryOperatorNode`: 一元运算符表达式
     - `StringNode`: 字符串字面量
     - `NumberNode`: 数字字面量
     - `IdNode`: 标识符
     - `CodeBlockNode`: 代码块
   - `parse` 方法是 `Parser` 的入口点，它调用 `codeblock` 方法开始解析，并期望最终到达文件末尾 (`eof`)。
   - `statement` 方法解析一个单独的语句。
   - `e1` 到 `e8` 等方法对应不同优先级的表达式解析规则，例如赋值语句、逻辑运算、比较运算、算术运算、函数调用等。
   - 它会处理运算符的优先级和结合性。
   - 它会创建相应的 AST 节点来表示解析出的语法结构。
   - 它会处理括号 `()` 来改变运算优先级。

3. **错误处理:**
   - 定义了 `ParseException` 和 `BlockParseException` 异常类，用于在词法分析和语法分析过程中遇到错误时抛出。
   - 异常信息会包含错误发生的位置（行号、列号）和错误附近的上下文代码，方便用户定位错误。

4. **AST 节点:**
   - 定义了多种 `@dataclass` 装饰的类来表示 AST 中的各种节点。
   - 每个节点都包含了其在源代码中的位置信息（`lineno`, `colno`, `filename`）。
   - 不同的节点类型存储不同的语法信息，例如变量名、运算符、子表达式等。
   - `accept` 方法用于实现访问者模式，允许对 AST 进行遍历和操作。

**与逆向方法的关系举例说明：**

虽然这个文件本身不直接执行逆向操作，但它是 Frida 工具链的一部分，而 Frida 是一个常用的动态 instrumentation 工具，广泛应用于逆向工程。

**举例：** 假设有一个 Frida 脚本，它使用 Meson 的语法来定义一些配置或者逻辑。例如，脚本可能包含一个函数调用，指示 Frida 应该 hook 哪个函数。`mparser.py` 的作用就是将这个脚本解析成 AST，然后 Frida 的其他组件会遍历这个 AST，理解用户的意图，并执行相应的 instrumentation 操作。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例说明：**

同样，这个文件本身并不直接涉及这些底层知识，但它解析的 Meson 语言可能会被用来描述与这些底层概念交互的操作。

**举例：**  在 Frida 的上下文中，一个 Meson 脚本可能会定义要 hook 的函数的内存地址。这个地址是二进制层面的概念。或者，脚本可能配置 Frida 在 Android 框架的特定组件中注入代码。这些都是与 Android 框架相关的知识。

**如果做了逻辑推理，请给出假设输入与输出:**

假设输入以下 Meson 代码片段：

```meson
if a > 10:
    b = a + 5
endif
```

`mparser.py` 解析后会生成如下结构的 AST（简化表示）：

```
CodeBlockNode
  IfClauseNode
    IfNode
      condition: ComparisonNode (>)
        left: IdNode (a)
        right: NumberNode (10)
      block: CodeBlockNode
        AssignmentNode
          var_name: IdNode (b)
          value: ArithmeticNode (+)
            left: IdNode (a)
            right: NumberNode (5)
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **语法错误:** 用户在编写 Meson 代码时，可能违反语法规则，例如：
   ```meson
   if a = 10  # 应该使用 == 进行比较
       print('hello')
   endif
   ```
   `mparser.py` 会抛出 `ParseException`，提示用户期望的是 `==` 而不是 `=`。

2. **字符串引号不匹配:**
   ```meson
   name = 'invalid string"
   ```
   `mparser.py` 会抛出 `ParseException`，因为字符串的引号没有正确闭合。

3. **使用了不支持的双引号:**
   ```meson
   message = "Hello"  # 应该使用单引号
   ```
   `mparser.py` 的 `Lexer` 会检测到双引号并抛出 `ParseException`，提示用户使用单引号。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. 用户编写一个 Frida 脚本，该脚本使用 Meson 语言的语法来定义 instrumentation 行为。
2. Frida 工具在执行脚本时，会调用 Meson 构建系统的相关组件。
3. Meson 构建系统会读取用户的脚本文件。
4. Meson 构建系统的某个组件会调用 `mparser.py` 中的 `Parser` 类来解析用户编写的脚本内容。
5. `Lexer` 类首先对脚本内容进行词法分析，将其分解成 token 流。
6. `Parser` 类接收 token 流，并根据语法规则构建 AST。
7. 如果在解析过程中遇到语法错误，`ParseException` 或 `BlockParseException` 会被抛出，其中包含了错误发生的位置信息，可以帮助用户调试脚本。

**功能归纳（第 1 部分）：**

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/mparser.py` 文件的第一部分主要负责 Meson 构建定义文件的 **词法分析** 和 **语法分析**，将文本代码转换为结构化的 **抽象语法树 (AST)**，并提供基本的 **错误处理** 能力。它是理解和处理 Meson 构建配置文件的核心组件。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/mparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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