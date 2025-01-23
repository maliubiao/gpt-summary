Response:
My thinking process to arrive at the summary of `mparser.py` goes through these stages:

1. **Understand the Goal:** The request asks for a functional summary of the Python code provided, focusing on its role in reverse engineering, interaction with low-level components, logical reasoning, common user errors, and debugging context. It also explicitly asks for a summary in the first part.

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code looking for key terms and structural elements that indicate its purpose. I see:
    * `SPDX-License-Identifier: Apache-2.0`:  Indicates open-source licensing.
    * `Copyright 2014-2017 The Meson development team`:  Identifies the creators and timeframe.
    * `from __future__ import annotations`: Modern Python type hinting.
    * `dataclasses`: Heavy use of dataclasses, suggesting structured data representation.
    * `re`: Regular expressions, likely for lexical analysis.
    * `codecs`: Encoding/decoding, specifically UTF-8 handling.
    * `MesonException`, `ParseException`, `BlockParseException`: Custom exception handling for parsing errors.
    * `Token`, `Lexer`:  Components of a lexical analyzer.
    * Various `*Node` classes (e.g., `CodeBlockNode`, `IfNode`, `FunctionNode`):  Abstract Syntax Tree (AST) node definitions.
    * `Parser`: The core parsing logic.
    * Keywords like `if`, `else`, `foreach`, `true`, `false`:  Language grammar elements.

3. **Identify Core Functionality (Lexing and Parsing):** The presence of `Lexer` and `Parser` immediately suggests that this file is responsible for taking source code as input and transforming it into a structured representation. The `Token` class represents the basic units of the language.

4. **Determine the Target Language:**  The keywords (`if`, `else`, `foreach`) and the context (part of Frida) strongly suggest that this code parses a domain-specific language (DSL) used within the Meson build system. This is further supported by the specific keywords like `testcase` which are specific to testing within Meson.

5. **Abstract Syntax Tree (AST) Construction:** The numerous `*Node` classes clearly indicate the construction of an AST. These nodes represent the syntactic elements of the parsed language. I note the different types of nodes (e.g., expressions, statements, blocks).

6. **Error Handling:** The `ParseException` and `BlockParseException` classes, along with the error formatting logic, highlight the importance of robust error reporting during parsing.

7. **Connection to Reverse Engineering (Potential):** While the file itself doesn't perform direct reverse engineering, it's a *tool* used by Frida. Frida *is* a reverse engineering tool. This file is responsible for understanding the *scripting language* used to control Frida's dynamic instrumentation. Therefore, the connection is indirect but crucial:  it parses the instructions that *drive* the reverse engineering process.

8. **Low-Level Interaction (Hints):**  The UTF-8 handling and the concept of byte spans (`bytespan` in `Token`) suggest an awareness of the underlying representation of the code. While the *parser* doesn't directly manipulate kernel structures, the *language it parses* likely controls such interactions in other parts of Frida.

9. **Logical Reasoning (Parsing Logic):** The `Parser` class implements a recursive descent parser. The functions `e1`, `e2`, `e3`, etc., represent different precedence levels in the grammar, showing the logical steps involved in parsing expressions. The `if`, `foreach`, etc., parsing shows the logic for handling control flow.

10. **User Errors:** The exceptions (`ParseException`, `BlockParseException`) and the specific error messages (e.g., about double quotes, newlines in strings, keyword argument redefinition) provide direct examples of common user mistakes when writing code in the target language.

11. **Debugging Context:** The file's role in parsing means that if a Frida script has syntax errors, this file will be the first point of failure, raising exceptions with line and column numbers to help the user locate the error.

12. **Structure the Summary:** Based on the above analysis, I structure the summary to cover the key functional areas: lexical analysis, parsing, AST creation, error handling, and its role within the larger Frida context. I also make sure to touch on the points specifically requested in the prompt (reverse engineering, low-level aspects, logic, user errors, debugging).

13. **Refine and Elaborate:** I review the initial summary and add details to make it more comprehensive and accurate. For example, I explicitly mention the recursive descent parsing strategy and the purpose of different node types in the AST. I also clarify the indirect link to reverse engineering.

This systematic approach allows me to understand the purpose and functionality of the `mparser.py` file even without having prior knowledge of the Meson build system in detail. The code itself provides strong clues about its role and design.
好的，让我们来分析一下 `frida/subprojects/frida-tools/releng/meson/mesonbuild/mparser.py` 这个文件的功能。

**文件功能归纳：**

`mparser.py` 文件是 Frida 工具链中，Meson 构建系统的一个子项目，其核心功能是**解析 Meson 构建描述语言**。更具体地说，它实现了 Meson 构建文件的**词法分析（Lexing）**和**语法分析（Parsing）**，并将源代码转换成一个**抽象语法树（AST）**。

以下是更详细的功能点：

1. **词法分析 (Lexing):**
    *   `Lexer` 类负责将输入的 Meson 构建脚本代码分解成一个个有意义的单元，称为 **Token (词法单元)**。
    *   它定义了各种 Token 的类型，例如：标识符（`id`）、数字（`number`）、字符串（`string`）、关键字（`if`、`else` 等）、运算符（`+`、`-`、`=` 等）、括号（`()`、`[]`、`{}`）等等。
    *   使用正则表达式 (`re` 模块) 来匹配代码中的不同模式，识别出 Token。
    *   处理注释、空白符和行尾符。
    *   能够识别并处理转义字符。
    *   支持多行字符串和 f-string。

2. **语法分析 (Parsing):**
    *   `Parser` 类负责接收 `Lexer` 生成的 Token 流，并根据 Meson 语言的语法规则，将其组织成一个**抽象语法树 (AST)**。
    *   AST 是代码结构的一种树形表示，忽略了代码中的一些细节（例如空格和注释），专注于代码的逻辑结构。
    *   定义了各种 AST 节点类型，例如：`CodeBlockNode`（代码块）、`IfNode`（if 语句）、`FunctionNode`（函数调用）、`AssignmentNode`（赋值语句）、`ArrayNode`（数组）、`DictNode`（字典）等等。
    *   实现了递归下降的解析器，通过一系列的 `e1`、`e2`、`e3` 等方法来处理不同优先级的表达式。
    *   处理各种语法结构，例如：赋值、条件语句、循环语句、函数调用、方法调用、数组和字典的定义等。

3. **错误处理:**
    *   定义了 `ParseException` 和 `BlockParseException` 异常类，用于在词法分析和语法分析过程中遇到错误时抛出。
    *   提供详细的错误信息，包括错误发生的代码行、行号、列号，以及相关的上下文信息，帮助用户定位错误。

4. **AST 节点的定义:**
    *   定义了各种表示 Meson 语言结构的 AST 节点类，这些类使用 `dataclasses` 装饰器，方便创建和管理节点的数据。
    *   每个节点都包含位置信息（行号、列号、文件名），用于在错误报告和代码分析中定位回源代码。
    *   不同类型的节点存储不同的信息，例如：变量名、运算符、表达式、代码块等。

**与逆向方法的关系及举例说明：**

虽然 `mparser.py` 本身不直接执行逆向操作，但它是 Frida 工具链的一部分，而 Frida 是一个强大的动态代码插桩框架，广泛应用于逆向工程。`mparser.py` 的作用是解析 Frida 使用的构建脚本（可能是 Meson 构建文件或者自定义的脚本语言），这些脚本用于描述如何构建 Frida 的各个组件。

**举例说明：**

假设 Frida 的某个组件的构建过程需要根据不同的操作系统进行不同的编译选项设置。这个逻辑可能会写在 Meson 构建文件中。`mparser.py` 就负责解析这个构建文件，理解其中的条件判断语句（例如 `if os == 'windows'`）和变量赋值，从而让构建系统知道在 Windows 平台上应该使用哪些编译选项。

在逆向工程中，理解目标软件的构建过程和依赖关系是非常重要的。通过分析像 `mparser.py` 这样的工具，逆向工程师可以更好地理解 Frida 是如何构建和工作的，从而更有效地使用 Frida 进行代码插桩和分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

`mparser.py` 本身并不直接涉及这些底层的知识。它的主要任务是解析文本形式的构建描述文件。然而，它解析的结果会直接影响到 Frida 工具链的构建过程，而 Frida 的许多功能都深入到操作系统内核和框架的底层。

**举例说明：**

*   **Linux 内核：**  Frida 需要与 Linux 内核进行交互才能实现代码插桩。Meson 构建文件可能会根据 Linux 内核版本或特性来选择不同的编译选项或依赖库。`mparser.py` 解析这些构建文件，确保 Frida 在不同的 Linux 环境下能够正确编译和运行。
*   **Android 框架：** Frida 在 Android 平台上可以用来 hook Java 层和 Native 层的代码。构建过程中可能需要链接 Android SDK 中的特定库。Meson 构建文件会描述这些依赖关系，`mparser.py` 解析这些信息，确保构建出的 Frida 能够正确地与 Android 系统交互。
*   **二进制底层：** 构建过程最终会生成二进制文件（例如，Frida 的动态链接库）。Meson 构建文件可能会指定链接器选项、优化级别等影响二进制文件结构的参数。`mparser.py` 解析这些参数，间接地影响最终生成的二进制文件的特性。

**逻辑推理的假设输入与输出：**

假设我们有以下简单的 Meson 构建代码片段：

```meson
project('my_frida_module', 'cpp')

my_option = get_option('my_custom_option')

if my_option == 'enabled':
    message('Custom option is enabled')
    # ... 一些构建操作
else:
    message('Custom option is disabled')
    # ... 另一些构建操作

my_variable = 'some_value'
```

**假设输入 (code 字符串)：** 上述代码片段的字符串形式。

**输出 (AST)：**  `Parser` 解析后会生成一个 `CodeBlockNode` 类型的 AST，其中包含以下主要的子节点：

*   一个 `FunctionNode`，表示 `project('my_frida_module', 'cpp')` 函数调用。
*   一个 `AssignmentNode`，表示 `my_option = get_option('my_custom_option')` 赋值语句。
*   一个 `IfClauseNode`，表示 `if...else` 语句，包含：
    *   一个 `IfNode`，表示 `if my_option == 'enabled'`，包含：
        *   一个 `ComparisonNode`，表示 `my_option == 'enabled'` 比较表达式。
        *   一个 `CodeBlockNode`，表示 `if` 代码块中的 `message('Custom option is enabled')`。
    *   一个 `ElseNode`，表示 `else` 代码块中的 `message('Custom option is disabled')`。
*   一个 `AssignmentNode`，表示 `my_variable = 'some_value'` 赋值语句。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **语法错误：**  拼写错误的关键字、缺少冒号、括号不匹配等。

    ```meson
    if my_option = 'enabled'  # 错误：应该是 ==
        message('Error')
    endif
    ```

    `mparser.py` 会抛出 `ParseException`，指出错误发生的行号和列号，例如：“Expecting == got =.”

2. **字符串使用双引号：** Meson 推荐使用单引号表示字符串。

    ```meson
    my_string = "hello"  # 错误：应该使用单引号
    ```

    `Lexer` 会抛出 `ParseException`，提示用户使用单引号。

3. **在单引号字符串中使用换行符：**  单引号字符串不支持直接换行，需要使用三引号。

    ```meson
    my_string = 'hello
    world'  # 错误：单引号字符串中包含换行符
    ```

    `Lexer` 会发出警告，建议使用三引号。

4. **关键字参数顺序错误：**  在函数调用中，位置参数必须在关键字参数之前。

    ```meson
    my_function(kwarg1: 'value1', 'positional_arg') # 错误：位置参数在关键字参数之后
    ```

    `Parser` 会在解析 `ArgumentNode` 时检测到 `order_error`，并发出警告。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Meson 构建文件：** 用户创建或修改 `meson.build` 文件，或者其他 Meson 构建系统相关的 `.meson` 文件。

2. **用户运行 Meson 构建命令：**  例如，在终端中执行 `meson setup builddir` 或 `ninja` 命令。

3. **Meson 系统解析构建文件：** Meson 系统在初始化构建过程或构建目标时，需要解析用户编写的构建文件。

4. **调用 `mparser.py` 进行解析：** Meson 系统内部会调用 `mparser.py` 中的 `Parser` 类来解析构建文件的内容。

5. **如果构建文件存在语法错误：**  `mparser.py` 在词法分析或语法分析阶段会抛出 `ParseException` 或 `BlockParseException` 异常。

6. **Meson 系统报告错误：** Meson 系统会捕获这些异常，并根据异常中包含的行号、列号和错误信息，向用户报告构建文件中的错误。

**作为调试线索：** 当用户遇到 Meson 构建错误时，错误信息中通常会包含文件名、行号和列号，这些信息直接来源于 `mparser.py` 抛出的异常。用户可以根据这些信息定位到出错的构建代码，并进行修改。理解 `mparser.py` 的工作原理可以帮助用户更好地理解 Meson 的错误报告，并更快地找到问题的根源。

**总结 `mparser.py` 的功能 (针对第 1 部分):**

`mparser.py` 文件的主要功能是**解析 Meson 构建描述语言**，它通过 `Lexer` 进行**词法分析**，将源代码分解成 Token，然后通过 `Parser` 进行**语法分析**，将 Token 流转换成**抽象语法树 (AST)**。这个过程会进行错误检查，并在遇到语法错误时抛出异常。`mparser.py` 是 Frida 工具链中理解和处理构建配置的核心组件。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mparser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```