Response:
The user wants a summary of the Python code provided. I need to identify the main components and their roles within the context of the frida dynamic instrumentation tool. The code seems to be a parser for a domain-specific language (DSL), likely used to configure or script Frida's behavior.

Here's a breakdown of the functionalities I can identify:

1. **Lexical Analysis (Lexer):** The `Lexer` class is responsible for breaking down the input code string into a stream of tokens. It defines regular expressions for various language elements like keywords, identifiers, numbers, strings, operators, and punctuation.
2. **Syntactic Analysis (Parser):** The `Parser` class takes the token stream from the lexer and builds an Abstract Syntax Tree (AST) representing the grammatical structure of the input code. It uses a recursive descent approach and defines methods for parsing different language constructs.
3. **Abstract Syntax Tree (AST) Nodes:** The code defines various classes representing nodes in the AST, such as `CodeBlockNode`, `AssignmentNode`, `FunctionNode`, `IfNode`, etc. Each node represents a specific construct in the language.
4. **Error Handling:** The code includes `ParseException` and `BlockParseException` for reporting errors during the parsing process. These exceptions provide information about the location of the error in the source code.
5. **Token Representation:** The `Token` class represents a single unit of code identified by the lexer, containing its type, value, and location in the source.
6. **Whitespace Handling:**  The code includes mechanisms to handle whitespace and comments, often by associating them with the preceding or following AST nodes.

Now, let's connect these functionalities to the specific prompts:

*   **Relationship with reverse engineering:** This parser is crucial for Frida as it allows users to write scripts or configurations that instruct Frida on how to interact with and modify running processes. This is a core aspect of dynamic instrumentation and reverse engineering.
*   **Binary, Linux, Android knowledge:**  While the parser itself doesn't directly interact with binaries or the OS kernel, the language it parses is designed to control Frida's interaction with these elements. For instance, the parsed scripts might define breakpoints, hook function calls, or modify memory, all of which require understanding of binary structures and OS internals.
*   **Logical reasoning:** The parser implements the grammar of the language. Given a specific sequence of tokens (input), it should produce a specific AST structure (output) if the input is grammatically correct.
*   **User errors:**  Common errors would be syntax errors in the input code, like misspelled keywords, incorrect punctuation, or mismatched parentheses. The parser's error handling is designed to catch these.
*   **User operation leading to this code:** A user would write a Frida script (likely a `.frida` file or code passed to Frida programmatically). This script would then be passed to Frida, which in turn would use this parser to interpret the script's instructions.

Finally, I need to summarize the core functionality of the code in this first part.
这是 `frida/subprojects/frida-python/releng/meson/mesonbuild/mparser.py` 文件的第一部分源代码，它主要定义了用于解析 Meson 构建系统所使用的领域特定语言 (DSL) 的词法分析器 (Lexer) 和抽象语法树 (AST) 的结构。

**主要功能归纳:**

1. **词法分析 (Lexing):**
    *   定义了 `Lexer` 类，负责将输入的 Meson 代码字符串分解成一系列的 `Token` 对象。
    *   使用正则表达式 `token_specification` 来识别不同的语法元素，例如关键字、标识符、数字、字符串、运算符、括号等。
    *   处理 Unicode 转义字符和多行字符串。
    *   识别并标记注释和空白符。
    *   处理行尾续行符。
    *   对双引号的使用发出警告。
    *   对未来保留关键字发出警告。
    *   在词法分析阶段检测 UTF-8 BOM 头并抛出异常。

2. **抽象语法树 (AST) 的定义:**
    *   定义了一系列类来表示 Meson 语言的各种语法结构，例如：
        *   `BaseNode`: 所有 AST 节点的基类，包含行号、列号、文件名等位置信息。
        *   `WhitespaceNode`: 表示空白符。
        *   `ElementaryNode`:  基本类型节点的基类，如布尔值、标识符、数字、字符串。
        *   `BooleanNode`, `IdNode`, `NumberNode`, `StringNode`, `FormatStringNode`, `MultilineStringNode`, `MultilineFormatStringNode`:  表示不同类型的字面量。
        *   `ContinueNode`, `BreakNode`:  表示 `continue` 和 `break` 语句。
        *   `SymbolNode`: 表示运算符或分隔符。
        *   `ArgumentNode`: 表示函数或方法调用的参数列表。
        *   `ArrayNode`, `DictNode`: 表示数组和字典。
        *   `BinaryOperatorNode`, `OrNode`, `AndNode`, `ComparisonNode`, `ArithmeticNode`: 表示二元运算。
        *   `UnaryOperatorNode`, `NotNode`, `UMinusNode`: 表示一元运算。
        *   `CodeBlockNode`: 表示代码块。
        *   `IndexNode`: 表示索引操作。
        *   `MethodNode`, `FunctionNode`: 表示方法和函数调用。
        *   `AssignmentNode`, `PlusAssignmentNode`: 表示赋值操作。
        *   `ForeachClauseNode`: 表示 `foreach` 循环语句。
        *   `IfNode`, `ElseNode`, `IfClauseNode`: 表示 `if-else` 条件语句。
        *   `TestCaseClauseNode`: 表示测试用例语句 (在单元测试环境下可用)。
        *   `TernaryNode`: 表示三元运算符。
        *   `ParenthesizedNode`: 表示带括号的表达式。
    *   每个 AST 节点都存储了其在源代码中的位置信息。

3. **错误处理:**
    *   定义了 `ParseException` 和 `BlockParseException` 异常类，用于在词法分析或语法分析过程中发生错误时抛出。
    *   这些异常类包含了错误消息以及错误发生的位置信息，有助于用户定位错误。

4. **Token 类:**
    *   定义了 `Token` 类，用于表示词法分析器生成的每个词法单元，包含其类型、值、文件名、起始行号、行号、列号和字节跨度等信息。

**与逆向方法的关系 (举例说明):**

虽然此代码本身是一个解析器，不直接执行逆向操作，但它解析的语言 (Meson 的 DSL) 可以用于定义 Frida 的脚本，而 Frida 本身是一个动态插桩工具，广泛应用于逆向工程。

**举例:**  假设有一个 Meson 构建文件定义了一个 Frida 脚本，该脚本会在目标进程的某个函数入口处设置断点并打印参数。Meson 解析器会解析这个构建文件，其中就包含了 Frida 脚本的路径或者内容。虽然这个 Python 文件本身不执行断点设置，但它是理解和处理 Frida 脚本这一逆向工程步骤的基础。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

这个解析器本身不直接涉及这些底层知识。但是，它解析的 Meson 构建文件通常会配置如何编译和链接与底层交互的代码，例如：

*   **二进制底层:** Meson 可以配置编译选项，生成特定架构的二进制文件，例如 ARM 或 x86。
*   **Linux/Android 内核:** Meson 可以配置构建针对特定 Linux 或 Android 内核版本的驱动程序或库。
*   **Android 框架:** Meson 可以配置构建与 Android 框架层交互的应用或库。

**逻辑推理 (假设输入与输出):**

**假设输入:**  Meson 代码字符串 `a = (1 + 2) * 3`

**输出:**  将生成一个 AST，其根节点可能是一个 `AssignmentNode`，包含以下结构：

*   `var_name`:  一个 `IdNode`，值为 "a"。
*   `operator`:  一个 `SymbolNode`，值为 "="。
*   `value`:  一个 `ArithmeticNode` (乘法)，其 `left` 是一个 `ParenthesizedNode`，包含一个 `ArithmeticNode` (加法)，`right` 是一个 `NumberNode`，值为 3。

**涉及用户或编程常见的使用错误 (举例说明):**

*   **语法错误:** 用户在 Meson 文件中使用了错误的语法，例如拼写错误的关键字 `iff` 而不是 `if`。词法分析器会将其识别为未知的 `id`，后续的语法分析会失败并抛出 `ParseException`。
*   **字符串未闭合:** 用户在字符串字面量中使用单引号 `'` 但没有正确闭合，例如 `'hello`。词法分析器可能会扫描到文件末尾才报错。
*   **使用了不支持的双引号:** 用户使用了双引号 `"` 而不是单引号 `'` 来定义字符串，词法分析器会抛出 `ParseException`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Meson 构建文件 (`meson.build`)**：这个文件包含了项目的构建配置，包括编译器选项、依赖项、源代码文件等。
2. **用户运行 `meson` 命令**：这个命令会读取 `meson.build` 文件并解析它以生成构建系统所需的配置。
3. **Meson 工具调用 `mparser.py`**:  当 `meson` 命令执行时，它会加载并使用 `mparser.py` 文件中的 `Lexer` 和相关的 AST 节点类来解析 `meson.build` 文件。
4. **如果 `meson.build` 文件中存在语法错误**：`Lexer` 或后续的 `Parser` (在下一部分代码中) 会抛出异常，异常信息中会包含错误的位置信息，指向 `mparser.py` 中定义的位置。

因此，如果用户报告 Meson 构建失败并提供了错误消息和行号，就可以追踪到 `mparser.py` 中的代码，来理解是如何进行词法分析以及 AST 的构建的，从而帮助定位构建文件中具体的语法错误。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/mparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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