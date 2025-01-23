Response:
The user wants a summary of the functionality of the provided Python code. This code is a parser for the TOML file format, as indicated by the file path and class name.

Here's a breakdown of how to address the specific points in the request:

1. **List the functions:**  The core purpose of this code is parsing TOML. I need to identify the key methods that perform this parsing.

2. **Relationship to reverse engineering:**  TOML is a configuration file format. In reverse engineering, configuration files often need to be analyzed to understand the behavior of an application. This parser would be useful for programmatically accessing and manipulating TOML data during a reverse engineering process.

3. **Relationship to binary, Linux, Android kernel/framework:** While the *parser* itself doesn't directly interact with these low-level aspects, TOML files might be used in such contexts. For instance, an Android application might use a TOML file for configuration. The parser becomes relevant when analyzing such applications.

4. **Logical reasoning (input/output):** The primary input is a string containing TOML data. The output is a structured representation of that data (a `TOMLDocument` object). I can create a simple example to illustrate this.

5. **Common user/programming errors:**  Parsing errors occur when the TOML input is malformed. I should look at the exception types defined in the code (e.g., `ParseError`, `UnexpectedCharError`) to identify potential error scenarios.

6. **User steps to reach this code (debugging context):**  The user would typically be interacting with Frida, which likely uses this parser internally when dealing with TOML configuration files related to its Swift interop functionality.

7. **Summary of functionality (for Part 1):**  Based on the above, the primary function is to parse TOML text into a structured Python object.

**Mental Sandbox:**

* **Can I directly link the parser to binary operations?**  Not really. The parser operates on text. However, the *data* it parses could influence binary behavior.
* **How does Frida relate?** Frida is a dynamic instrumentation tool. It might need to parse configuration to understand how to interact with a target process, including Swift components.
* **What's a simple TOML input/output example?**  `"key = \"value\""` would parse into a dictionary-like structure where the key "key" maps to the string "value".
* **What are some typical TOML errors?** Missing quotes, invalid characters, incorrect formatting of dates/numbers.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与逆向的方法有关系，请做出对应的举例说明: Yes
* 如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明: Yes (indirectly)
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第1部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I am confident I can address all aspects of the request.

Strategizing complete. I will now generate the response following these steps.
这是 `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/parser.py` 文件的源代码，它是 Frida 动态 instrumentation 工具中 `tomlkit` 库的一部分。`tomlkit` 库专门用于解析和处理 TOML (Tom's Obvious, Minimal Language) 格式的文件。

**这个文件的主要功能是实现 TOML 格式的解析器。更具体地说，它的功能包括：**

1. **词法分析和语法分析 (Lexing and Parsing):**  它接收一个 TOML 格式的字符串或字节流作为输入，并将其分解成有意义的单元（tokens），然后根据 TOML 的语法规则将这些单元组织成一个结构化的表示形式。

2. **解析各种 TOML 数据类型:**  能够识别和解析 TOML 规范中定义的各种数据类型，包括：
    * **字符串 (String):**  支持基本字符串、多行基本字符串、字面量字符串和多行字面量字符串，并处理转义字符。
    * **整数 (Integer):**  支持正负整数，以及二进制、八进制和十六进制表示。
    * **浮点数 (Float):**  支持正负浮点数，包括科学计数法和特殊值（如 `inf` 和 `nan`）。
    * **布尔值 (Bool):**  识别 `true` 和 `false`。
    * **日期和时间 (Date and Time):**  支持符合 RFC 3339 标准的日期、时间和日期时间格式。
    * **数组 (Array):**  解析包含各种数据类型的数组。
    * **内联表 (Inline Table):**  解析单行的键值对表。
    * **表 (Table):**  解析用 `[table_name]` 定义的标准表。
    * **数组表 (Array of Tables - AoT):**  解析用 `[[table_name]]` 定义的表数组。

3. **处理空白符和注释:**  能够正确处理 TOML 文件中的空格、制表符、换行符等空白字符，并识别和忽略注释。

4. **错误处理:**  在解析过程中遇到不符合 TOML 语法规则的内容时，能够抛出各种具体的异常，例如：
    * `ParseError`:  通用的解析错误。
    * `UnexpectedCharError`:  遇到意料之外的字符。
    * `UnexpectedEofError`:  在不期望的时候到达文件末尾。
    * `InvalidCharInStringError`:  字符串中包含无效字符。
    * `InvalidControlChar`:  使用了无效的控制字符。
    * `InvalidUnicodeValueError`:  Unicode 转义值无效。
    * `InvalidNumberError`:  数字格式错误。
    * `InvalidDateError`, `InvalidTimeError`, `InvalidDateTimeError`:  日期或时间格式错误。
    * `EmptyKeyError`:  键为空。
    * `EmptyTableNameError`:  表名为空。

5. **构建 TOML 文档对象:**  将解析后的 TOML 数据构建成一个 `TOMLDocument` 对象，该对象提供了访问和操作 TOML 数据的接口。

**它与逆向的方法的关系及举例说明：**

在软件逆向工程中，经常需要分析应用程序的配置文件以了解其行为和配置信息。TOML 是一种常见的配置文件格式。`parser.py` 中的解析器可以用于：

* **解析程序的配置文件:**  如果一个被逆向的程序使用了 TOML 格式的配置文件，可以使用这个解析器来读取配置信息，例如 API 密钥、服务器地址、调试选项等。
    * **举例:**  假设一个 Android 应用的 native 层使用 TOML 文件 `config.toml` 存储了服务器的 IP 地址和端口：
        ```toml
        server_ip = "192.168.1.100"
        server_port = 8080
        ```
        在逆向分析时，可以使用 `tomlkit` 库中的解析器来读取这些值，以便了解程序连接的服务器信息。

* **修改程序的配置:**  在某些逆向场景中，可能需要修改程序的配置文件来改变其行为。可以使用 `tomlkit` 解析配置文件，修改相应的键值，然后将修改后的内容写回文件。

* **分析内存中的 TOML 数据:**  在动态分析过程中，如果程序将 TOML 配置加载到内存中，可以使用 Frida 拦截相关函数，提取内存中的 TOML 数据，并使用此解析器进行解析。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

这个 Python 脚本本身主要处理的是文本格式的解析，它并不直接与二进制底层、Linux 或 Android 内核交互。然而，它解析的 TOML 数据可能会涉及到这些方面：

* **二进制数据配置:**  TOML 文件可能包含与二进制数据相关的配置，例如，一个嵌入式系统可能会使用 TOML 文件配置硬件寄存器的地址和初始值。虽然解析器本身不处理二进制，但它提供的结构化数据可以方便地用于进一步的二进制操作。
* **Linux 系统配置:**  某些 Linux 应用程序或服务可能使用 TOML 作为配置文件格式。例如，一个守护进程可能会使用 TOML 文件指定监听端口、日志路径等系统资源。
* **Android 框架配置:**  尽管 Android 更常见的是使用 XML 或 JSON 作为配置文件格式，但理论上也可以使用 TOML。如果某个 Android 组件使用了 TOML 配置，这个解析器就能派上用场。例如，一个自定义的 Android 服务可能会使用 TOML 文件来定义其行为参数。

**逻辑推理的假设输入与输出：**

假设输入一个简单的 TOML 字符串：

```toml
name = "Alice"
age = 30
is_student = false
```

解析器 `parse()` 方法的输出将会是一个 `TOMLDocument` 对象，该对象可以被访问，例如：

```python
parser = Parser("""
name = "Alice"
age = 30
is_student = false
""")
doc = parser.parse()
print(doc["name"])       # 输出: Alice
print(doc["age"])        # 输出: 30
print(doc["is_student"]) # 输出: False
```

**涉及用户或者编程常见的使用错误及举例说明：**

1. **TOML 语法错误:** 用户提供的 TOML 字符串不符合 TOML 规范。
    * **举例:** 忘记在字符串值周围添加引号：
      ```python
      parser = Parser("name = Alice")  # 缺少引号
      try:
          parser.parse()
      except ParseError as e:
          print(e)  # 输出类似: UnexpectedCharError('A', ...)
      ```

2. **类型不匹配:**  虽然 TOML 是弱类型的，但在使用解析后的数据时，可能会发生类型相关的错误。
    * **举例:**  假设配置文件中年龄是字符串，但程序期望是整数：
      ```toml
      age = "30"
      ```
      解析后，`doc["age"]` 是一个字符串 `"30"`，如果程序尝试将其当作整数进行算术运算，则会出错。

3. **键不存在:** 尝试访问 `TOMLDocument` 中不存在的键。
    * **举例:**  配置文件中没有 `email` 字段：
      ```python
      parser = Parser("name = 'Bob'")
      doc = parser.parse()
      print(doc["email"])  # 会抛出 KeyError
      ```

**说明用户操作是如何一步步的到达这里，作为调试线索：**

通常情况下，用户不会直接调用 `parser.py` 中的代码。用户操作通常是通过 Frida 的 API 进行的，而 Frida 内部会使用 `tomlkit` 来处理相关的 TOML 配置。以下是一些可能到达这个解析器的场景：

1. **Frida 工具的配置:**  用户可能在编写 Frida 脚本或使用 Frida 的命令行工具时，需要加载或解析 TOML 格式的配置文件。例如，Frida 的插件或者某些高级功能可能使用 TOML 来定义其行为。当 Frida 需要解析这些配置文件时，就会使用 `tomlkit` 库中的解析器。

2. **Frida 与 Swift 的交互:**  这个文件的路径 `frida/subprojects/frida-swift/` 表明它与 Frida 对 Swift 代码的动态 instrumentation 支持有关。可能存在一些 Swift 相关的配置选项，以 TOML 格式存储，Frida 在与 Swift 应用交互时需要解析这些配置。

3. **调试 Frida 自身或其组件:**  如果开发者在调试 Frida 的 Swift 支持模块或 `tomlkit` 库本身，他们可能会直接运行或单步执行 `parser.py` 中的代码，以了解解析过程中的细节或查找 bug。

**总结 `parser.py` 的功能 (第 1 部分)：**

`frida/subprojects/frida-swift/releng/tomlkit/tomlkit/parser.py` 文件的核心功能是**实现了一个完整的 TOML 格式解析器**。它能够将 TOML 格式的文本数据转换成结构化的 Python 对象 (`TOMLDocument`)，从而方便程序访问和操作 TOML 文件中的配置信息。这个解析器支持 TOML 规范中定义的所有数据类型和语法规则，并提供了详细的错误处理机制。在 Frida 的上下文中，这个解析器主要用于处理与 Frida 工具自身或其对 Swift 代码支持相关的 TOML 配置文件。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tomlkit/parser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
from __future__ import annotations

import datetime
import re
import string

from tomlkit._compat import decode
from tomlkit._utils import RFC_3339_LOOSE
from tomlkit._utils import _escaped
from tomlkit._utils import parse_rfc3339
from tomlkit.container import Container
from tomlkit.exceptions import EmptyKeyError
from tomlkit.exceptions import EmptyTableNameError
from tomlkit.exceptions import InternalParserError
from tomlkit.exceptions import InvalidCharInStringError
from tomlkit.exceptions import InvalidControlChar
from tomlkit.exceptions import InvalidDateError
from tomlkit.exceptions import InvalidDateTimeError
from tomlkit.exceptions import InvalidNumberError
from tomlkit.exceptions import InvalidTimeError
from tomlkit.exceptions import InvalidUnicodeValueError
from tomlkit.exceptions import ParseError
from tomlkit.exceptions import UnexpectedCharError
from tomlkit.exceptions import UnexpectedEofError
from tomlkit.items import AoT
from tomlkit.items import Array
from tomlkit.items import Bool
from tomlkit.items import BoolType
from tomlkit.items import Comment
from tomlkit.items import Date
from tomlkit.items import DateTime
from tomlkit.items import Float
from tomlkit.items import InlineTable
from tomlkit.items import Integer
from tomlkit.items import Item
from tomlkit.items import Key
from tomlkit.items import KeyType
from tomlkit.items import Null
from tomlkit.items import SingleKey
from tomlkit.items import String
from tomlkit.items import StringType
from tomlkit.items import Table
from tomlkit.items import Time
from tomlkit.items import Trivia
from tomlkit.items import Whitespace
from tomlkit.source import Source
from tomlkit.toml_char import TOMLChar
from tomlkit.toml_document import TOMLDocument


CTRL_I = 0x09  # Tab
CTRL_J = 0x0A  # Line feed
CTRL_M = 0x0D  # Carriage return
CTRL_CHAR_LIMIT = 0x1F
CHR_DEL = 0x7F


class Parser:
    """
    Parser for TOML documents.
    """

    def __init__(self, string: str | bytes) -> None:
        # Input to parse
        self._src = Source(decode(string))

        self._aot_stack: list[Key] = []

    @property
    def _state(self):
        return self._src.state

    @property
    def _idx(self):
        return self._src.idx

    @property
    def _current(self):
        return self._src.current

    @property
    def _marker(self):
        return self._src.marker

    def extract(self) -> str:
        """
        Extracts the value between marker and index
        """
        return self._src.extract()

    def inc(self, exception: type[ParseError] | None = None) -> bool:
        """
        Increments the parser if the end of the input has not been reached.
        Returns whether or not it was able to advance.
        """
        return self._src.inc(exception=exception)

    def inc_n(self, n: int, exception: type[ParseError] | None = None) -> bool:
        """
        Increments the parser by n characters
        if the end of the input has not been reached.
        """
        return self._src.inc_n(n=n, exception=exception)

    def consume(self, chars, min=0, max=-1):
        """
        Consume chars until min/max is satisfied is valid.
        """
        return self._src.consume(chars=chars, min=min, max=max)

    def end(self) -> bool:
        """
        Returns True if the parser has reached the end of the input.
        """
        return self._src.end()

    def mark(self) -> None:
        """
        Sets the marker to the index's current position
        """
        self._src.mark()

    def parse_error(self, exception=ParseError, *args, **kwargs):
        """
        Creates a generic "parse error" at the current position.
        """
        return self._src.parse_error(exception, *args, **kwargs)

    def parse(self) -> TOMLDocument:
        body = TOMLDocument(True)

        # Take all keyvals outside of tables/AoT's.
        while not self.end():
            # Break out if a table is found
            if self._current == "[":
                break

            # Otherwise, take and append one KV
            item = self._parse_item()
            if not item:
                break

            key, value = item
            if (key is not None and key.is_multi()) or not self._merge_ws(value, body):
                # We actually have a table
                try:
                    body.append(key, value)
                except Exception as e:
                    raise self.parse_error(ParseError, str(e)) from e

            self.mark()

        while not self.end():
            key, value = self._parse_table()
            if isinstance(value, Table) and value.is_aot_element():
                # This is just the first table in an AoT. Parse the rest of the array
                # along with it.
                value = self._parse_aot(value, key)

            try:
                body.append(key, value)
            except Exception as e:
                raise self.parse_error(ParseError, str(e)) from e

        body.parsing(False)

        return body

    def _merge_ws(self, item: Item, container: Container) -> bool:
        """
        Merges the given Item with the last one currently in the given Container if
        both are whitespace items.

        Returns True if the items were merged.
        """
        last = container.last_item()
        if not last:
            return False

        if not isinstance(item, Whitespace) or not isinstance(last, Whitespace):
            return False

        start = self._idx - (len(last.s) + len(item.s))
        container.body[-1] = (
            container.body[-1][0],
            Whitespace(self._src[start : self._idx]),
        )

        return True

    def _is_child(self, parent: Key, child: Key) -> bool:
        """
        Returns whether a key is strictly a child of another key.
        AoT siblings are not considered children of one another.
        """
        parent_parts = tuple(parent)
        child_parts = tuple(child)

        if parent_parts == child_parts:
            return False

        return parent_parts == child_parts[: len(parent_parts)]

    def _parse_item(self) -> tuple[Key | None, Item] | None:
        """
        Attempts to parse the next item and returns it, along with its key
        if the item is value-like.
        """
        self.mark()
        with self._state as state:
            while True:
                c = self._current
                if c == "\n":
                    # Found a newline; Return all whitespace found up to this point.
                    self.inc()

                    return None, Whitespace(self.extract())
                elif c in " \t\r":
                    # Skip whitespace.
                    if not self.inc():
                        return None, Whitespace(self.extract())
                elif c == "#":
                    # Found a comment, parse it
                    indent = self.extract()
                    cws, comment, trail = self._parse_comment_trail()

                    return None, Comment(Trivia(indent, cws, comment, trail))
                elif c == "[":
                    # Found a table, delegate to the calling function.
                    return
                else:
                    # Beginning of a KV pair.
                    # Return to beginning of whitespace so it gets included
                    # as indentation for the KV about to be parsed.
                    state.restore = True
                    break

        return self._parse_key_value(True)

    def _parse_comment_trail(self, parse_trail: bool = True) -> tuple[str, str, str]:
        """
        Returns (comment_ws, comment, trail)
        If there is no comment, comment_ws and comment will
        simply be empty.
        """
        if self.end():
            return "", "", ""

        comment = ""
        comment_ws = ""
        self.mark()

        while True:
            c = self._current

            if c == "\n":
                break
            elif c == "#":
                comment_ws = self.extract()

                self.mark()
                self.inc()  # Skip #

                # The comment itself
                while not self.end() and not self._current.is_nl():
                    code = ord(self._current)
                    if code == CHR_DEL or code <= CTRL_CHAR_LIMIT and code != CTRL_I:
                        raise self.parse_error(InvalidControlChar, code, "comments")

                    if not self.inc():
                        break

                comment = self.extract()
                self.mark()

                break
            elif c in " \t\r":
                self.inc()
            else:
                raise self.parse_error(UnexpectedCharError, c)

            if self.end():
                break

        trail = ""
        if parse_trail:
            while self._current.is_spaces() and self.inc():
                pass

            if self._current == "\r":
                self.inc()

            if self._current == "\n":
                self.inc()

            if self._idx != self._marker or self._current.is_ws():
                trail = self.extract()

        return comment_ws, comment, trail

    def _parse_key_value(self, parse_comment: bool = False) -> tuple[Key, Item]:
        # Leading indent
        self.mark()

        while self._current.is_spaces() and self.inc():
            pass

        indent = self.extract()

        # Key
        key = self._parse_key()

        self.mark()

        found_equals = self._current == "="
        while self._current.is_kv_sep() and self.inc():
            if self._current == "=":
                if found_equals:
                    raise self.parse_error(UnexpectedCharError, "=")
                else:
                    found_equals = True
        if not found_equals:
            raise self.parse_error(UnexpectedCharError, self._current)

        if not key.sep:
            key.sep = self.extract()
        else:
            key.sep += self.extract()

        # Value
        val = self._parse_value()
        # Comment
        if parse_comment:
            cws, comment, trail = self._parse_comment_trail()
            meta = val.trivia
            if not meta.comment_ws:
                meta.comment_ws = cws

            meta.comment = comment
            meta.trail = trail
        else:
            val.trivia.trail = ""

        val.trivia.indent = indent

        return key, val

    def _parse_key(self) -> Key:
        """
        Parses a Key at the current position;
        WS before the key must be exhausted first at the callsite.
        """
        self.mark()
        while self._current.is_spaces() and self.inc():
            # Skip any leading whitespace
            pass
        if self._current in "\"'":
            return self._parse_quoted_key()
        else:
            return self._parse_bare_key()

    def _parse_quoted_key(self) -> Key:
        """
        Parses a key enclosed in either single or double quotes.
        """
        # Extract the leading whitespace
        original = self.extract()
        quote_style = self._current
        key_type = next((t for t in KeyType if t.value == quote_style), None)

        if key_type is None:
            raise RuntimeError("Should not have entered _parse_quoted_key()")

        key_str = self._parse_string(
            StringType.SLB if key_type == KeyType.Basic else StringType.SLL
        )
        if key_str._t.is_multiline():
            raise self.parse_error(UnexpectedCharError, key_str._t.value)
        original += key_str.as_string()
        self.mark()
        while self._current.is_spaces() and self.inc():
            pass
        original += self.extract()
        key = SingleKey(str(key_str), t=key_type, sep="", original=original)
        if self._current == ".":
            self.inc()
            key = key.concat(self._parse_key())

        return key

    def _parse_bare_key(self) -> Key:
        """
        Parses a bare key.
        """
        while (
            self._current.is_bare_key_char() or self._current.is_spaces()
        ) and self.inc():
            pass

        original = self.extract()
        key = original.strip()
        if not key:
            # Empty key
            raise self.parse_error(EmptyKeyError)

        if " " in key:
            # Bare key with spaces in it
            raise self.parse_error(ParseError, f'Invalid key "{key}"')

        key = SingleKey(key, KeyType.Bare, "", original)

        if self._current == ".":
            self.inc()
            key = key.concat(self._parse_key())

        return key

    def _parse_value(self) -> Item:
        """
        Attempts to parse a value at the current position.
        """
        self.mark()
        c = self._current
        trivia = Trivia()

        if c == StringType.SLB.value:
            return self._parse_basic_string()
        elif c == StringType.SLL.value:
            return self._parse_literal_string()
        elif c == BoolType.TRUE.value[0]:
            return self._parse_true()
        elif c == BoolType.FALSE.value[0]:
            return self._parse_false()
        elif c == "[":
            return self._parse_array()
        elif c == "{":
            return self._parse_inline_table()
        elif c in "+-" or self._peek(4) in {
            "+inf",
            "-inf",
            "inf",
            "+nan",
            "-nan",
            "nan",
        }:
            # Number
            while self._current not in " \t\n\r#,]}" and self.inc():
                pass

            raw = self.extract()

            item = self._parse_number(raw, trivia)
            if item is not None:
                return item

            raise self.parse_error(InvalidNumberError)
        elif c in string.digits:
            # Integer, Float, Date, Time or DateTime
            while self._current not in " \t\n\r#,]}" and self.inc():
                pass

            raw = self.extract()

            m = RFC_3339_LOOSE.match(raw)
            if m:
                if m.group(1) and m.group(5):
                    # datetime
                    try:
                        dt = parse_rfc3339(raw)
                        assert isinstance(dt, datetime.datetime)
                        return DateTime(
                            dt.year,
                            dt.month,
                            dt.day,
                            dt.hour,
                            dt.minute,
                            dt.second,
                            dt.microsecond,
                            dt.tzinfo,
                            trivia,
                            raw,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidDateTimeError)

                if m.group(1):
                    try:
                        dt = parse_rfc3339(raw)
                        assert isinstance(dt, datetime.date)
                        date = Date(dt.year, dt.month, dt.day, trivia, raw)
                        self.mark()
                        while self._current not in "\t\n\r#,]}" and self.inc():
                            pass

                        time_raw = self.extract()
                        time_part = time_raw.rstrip()
                        trivia.comment_ws = time_raw[len(time_part) :]
                        if not time_part:
                            return date

                        dt = parse_rfc3339(raw + time_part)
                        assert isinstance(dt, datetime.datetime)
                        return DateTime(
                            dt.year,
                            dt.month,
                            dt.day,
                            dt.hour,
                            dt.minute,
                            dt.second,
                            dt.microsecond,
                            dt.tzinfo,
                            trivia,
                            raw + time_part,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidDateError)

                if m.group(5):
                    try:
                        t = parse_rfc3339(raw)
                        assert isinstance(t, datetime.time)
                        return Time(
                            t.hour,
                            t.minute,
                            t.second,
                            t.microsecond,
                            t.tzinfo,
                            trivia,
                            raw,
                        )
                    except ValueError:
                        raise self.parse_error(InvalidTimeError)

            item = self._parse_number(raw, trivia)
            if item is not None:
                return item

            raise self.parse_error(InvalidNumberError)
        else:
            raise self.parse_error(UnexpectedCharError, c)

    def _parse_true(self):
        return self._parse_bool(BoolType.TRUE)

    def _parse_false(self):
        return self._parse_bool(BoolType.FALSE)

    def _parse_bool(self, style: BoolType) -> Bool:
        with self._state:
            style = BoolType(style)

            # only keep parsing for bool if the characters match the style
            # try consuming rest of chars in style
            for c in style:
                self.consume(c, min=1, max=1)

            return Bool(style, Trivia())

    def _parse_array(self) -> Array:
        # Consume opening bracket, EOF here is an issue (middle of array)
        self.inc(exception=UnexpectedEofError)

        elems: list[Item] = []
        prev_value = None
        while True:
            # consume whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES + TOMLChar.NL)
            indent = self._src[mark : self._idx]
            newline = set(TOMLChar.NL) & set(indent)
            if newline:
                elems.append(Whitespace(indent))
                continue

            # consume comment
            if self._current == "#":
                cws, comment, trail = self._parse_comment_trail(parse_trail=False)
                elems.append(Comment(Trivia(indent, cws, comment, trail)))
                continue

            # consume indent
            if indent:
                elems.append(Whitespace(indent))
                continue

            # consume value
            if not prev_value:
                try:
                    elems.append(self._parse_value())
                    prev_value = True
                    continue
                except UnexpectedCharError:
                    pass

            # consume comma
            if prev_value and self._current == ",":
                self.inc(exception=UnexpectedEofError)
                elems.append(Whitespace(","))
                prev_value = False
                continue

            # consume closing bracket
            if self._current == "]":
                # consume closing bracket, EOF here doesn't matter
                self.inc()
                break

            raise self.parse_error(UnexpectedCharError, self._current)

        try:
            res = Array(elems, Trivia())
        except ValueError:
            pass
        else:
            return res

    def _parse_inline_table(self) -> InlineTable:
        # consume opening bracket, EOF here is an issue (middle of array)
        self.inc(exception=UnexpectedEofError)

        elems = Container(True)
        trailing_comma = None
        while True:
            # consume leading whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES)
            raw = self._src[mark : self._idx]
            if raw:
                elems.add(Whitespace(raw))

            if not trailing_comma:
                # None: empty inline table
                # False: previous key-value pair was not followed by a comma
                if self._current == "}":
                    # consume closing bracket, EOF here doesn't matter
                    self.inc()
                    break

                if (
                    trailing_comma is False
                    or trailing_comma is None
                    and self._current == ","
                ):
                    # Either the previous key-value pair was not followed by a comma
                    # or the table has an unexpected leading comma.
                    raise self.parse_error(UnexpectedCharError, self._current)
            else:
                # True: previous key-value pair was followed by a comma
                if self._current == "}" or self._current == ",":
                    raise self.parse_error(UnexpectedCharError, self._current)

            key, val = self._parse_key_value(False)
            elems.add(key, val)

            # consume trailing whitespace
            mark = self._idx
            self.consume(TOMLChar.SPACES)
            raw = self._src[mark : self._idx]
            if raw:
                elems.add(Whitespace(raw))

            # consume trailing comma
            trailing_comma = self._current == ","
            if trailing_comma:
                # consume closing bracket, EOF here is an issue (middle of inline table)
                self.inc(exception=UnexpectedEofError)

        return InlineTable(elems, Trivia())

    def _parse_number(self, raw: str, trivia: Trivia) -> Item | None:
        # Leading zeros are not allowed
        sign = ""
        if raw.startswith(("+", "-")):
            sign = raw[0]
            raw = raw[1:]

        if len(raw) > 1 and (
            raw.startswith("0")
            and not raw.startswith(("0.", "0o", "0x", "0b", "0e"))
            or sign
            and raw.startswith(".")
        ):
            return None

        if raw.startswith(("0o", "0x", "0b")) and sign:
            return None

        digits = "[0-9]"
        base = 10
        if raw.startswith("0b"):
            digits = "[01]"
            base = 2
        elif raw.startswith("0o"):
            digits = "[0-7]"
            base = 8
        elif raw.startswith("0x"):
            digits = "[0-9a-f]"
            base = 16

        # Underscores should be surrounded by digits
        clean = re.sub(f"(?i)(?<={digits})_(?={digits})", "", raw).lower()

        if "_" in clean:
            return None

        if (
            clean.endswith(".")
            or not clean.startswith("0x")
            and clean.split("e", 1)[0].endswith(".")
        ):
            return None

        try:
            return Integer(int(sign + clean, base), trivia, sign + raw)
        except ValueError:
            try:
                return Float(float(sign + clean), trivia, sign + raw)
            except ValueError:
                return None

    def _parse_literal_string(self) -> String:
        with self._state:
            return self._parse_string(StringType.SLL)

    def _parse_basic_string(self) -> String:
        with self._state:
            return self._parse_string(StringType.SLB)

    def _parse_escaped_char(self, multiline):
        if multiline and self._current.is_ws():
            # When the last non-whitespace character on a line is
            # a \, it will be trimmed along with all whitespace
            # (including newlines) up to the next non-whitespace
            # character or closing delimiter.
            # """\
            #     hello \
            #     world"""
            tmp = ""
            while self._current.is_ws():
                tmp += self._current
                # consume the whitespace, EOF here is an issue
                # (middle of string)
                self.inc(exception=UnexpectedEofError)
                continue

            # the escape followed by whitespace must have a newline
            # before any other chars
            if "\n" not in tmp:
                raise self.parse_error(InvalidCharInStringError, self._current)

            return ""

        if self._current in _escaped:
            c = _escaped[self._current]

            # consume this char, EOF here is an issue (middle of string)
            self.inc(exception=UnexpectedEofError)

            return c

        if self._current in {"u", "U"}:
            # this needs to be a unicode
            u, ue = self._peek_unicode(self._current == "U")
            if u is not None:
                # consume the U char and the unicode value
                self.inc_n(len(ue) + 1)

                return u

            raise self.parse_error(InvalidUnicodeValueError)

        raise self.parse_error(InvalidCharInStringError, self._current)

    def _parse_string(self, delim: StringType) -> String:
        # only keep parsing for string if the current character matches the delim
        if self._current != delim.unit:
            raise self.parse_error(
                InternalParserError,
                f"Invalid character for string type {delim}",
            )

        # consume the opening/first delim, EOF here is an issue
        # (middle of string or middle of delim)
        self.inc(exception=UnexpectedEofError)

        if self._current == delim.unit:
            # consume the closing/second delim, we do not care if EOF occurs as
            # that would simply imply an empty single line string
            if not self.inc() or self._current != delim.unit:
                # Empty string
                return String(delim, "", "", Trivia())

            # consume the third delim, EOF here is an issue (middle of string)
            self.inc(exception=UnexpectedEofError)

            delim = delim.toggle()  # convert delim to multi delim

        self.mark()  # to extract the original string with whitespace and all
        value = ""

        # A newline immediately following the opening delimiter will be trimmed.
        if delim.is_multiline():
            if self._current == "\n":
                # consume the newline, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)
            else:
                cur = self._current
                with self._state(restore=True):
                    if self.inc():
                        cur += self._current
                if cur == "\r\n":
                    self.inc_n(2, exception=UnexpectedEofError)

        escaped = False  # whether the previous key was ESCAPE
        while True:
            code = ord(self._current)
            if (
                delim.is_singleline()
                and not escaped
                and (code == CHR_DEL or code <= CTRL_CHAR_LIMIT and code != CTRL_I)
            ) or (
                delim.is_multiline()
                and not escaped
                and (
                    code == CHR_DEL
                    or code <= CTRL_CHAR_LIMIT
                    and code not in [CTRL_I, CTRL_J, CTRL_M]
                )
            ):
                raise self.parse_error(InvalidControlChar, code, "strings")
            elif not escaped and self._current == delim.unit:
                # try to process current as a closing delim
                original = self.extract()

                close = ""
                if delim.is_multiline():
                    # Consume the delimiters to see if we are at the end of the string
                    close = ""
                    while self._current == delim.unit:
                        close += self._current
                        self.inc()

                    if len(close) < 3:
                        # Not a triple quote, leave in result as-is.
                        # Adding back the characters we already consumed
                        value += close
                        continue

                    if len(close) == 3:
                        # We are at the end of the string
                        return String(delim, value, original, Trivia())

                    if len(close) >= 6:
                        raise self.parse_error(InvalidCharInStringError, self._current)

                    value += close[:-3]
                    original += close[:-3]

                    return String(delim, value, original, Trivia())
                else:
                    # consume the closing delim, we do not care if EOF occurs as
                    # that would simply imply the end of self._src
                    self.inc()

                return String(delim, value, original, Trivia())
            elif delim.is_basic() and escaped:
                # attempt to parse the current char as an escaped value, an exception
                # is raised if this fails
                value += self._parse_escaped_char(delim.is_multiline())

                # no longer escaped
                escaped = False
            elif delim.is_basic() and self._current == "\\":
                # the next char is being escaped
                escaped = True

                # consume this char, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)
            else:
                # this is either a literal string where we keep everything as is,
                # or this is not a special escaped char in a basic string
                value += self._current

                # consume this char, EOF here is an issue (middle of string)
                self.inc(exception=UnexpectedEofError)

    def _parse_table(
        self, parent_name: Key | None = None, parent: Table | None = None
    ) -> tuple[Key, Table | AoT]:
        """
        Parses a table element.
        """
        if self._current != "[":
            raise self.parse_error(
                InternalParserError, "_parse_table() called on non-bracket character."
            )

        indent = self.extract()
        self.inc()  # Skip opening bracket

        if self.end():
            raise self.parse_error(UnexpectedEofError)

        is_aot = False
        if self._current == "[":
            if not self.inc():
                raise self.parse_error(UnexpectedEofError)

            is_aot = True
        try:
            key = self._parse_key()
        except EmptyKeyError:
            raise self.parse_error(EmptyTableNameError) from None
        if self.end():
            raise self.parse_error(UnexpectedEofError)
        elif self._current != "]":
            raise self.parse_error(UnexpectedCharError, self._current)

        key.sep = ""
        full_key = key
        name_parts = tuple(key)
        if any(" " in part.key.strip() and part.is_bare() for part in name_parts):
            raise self.parse_error(
                ParseError, f'Invalid table name "{full_key.as_string()}"'
            )

        missing_table = False
        if parent_name:
            parent_name_parts = tuple(parent_name)
        else:
            parent_name_parts = ()

        if len(name_parts) > len(parent_name_parts) + 1:
            missing_table = True

        name_parts = name_parts[len(parent_name_parts) :]

        values = Container(True)

        self.inc()  # Skip closing bracket
        if is_aot:
            # TODO: Verify close bracket
            self.inc()

        cws, comment, trail = self._parse_comment_trail()

        result = Null()
        table = Table(
            values,
            Trivia(indent, cws, comment, trail),
            is_aot,
            name=name_parts[0].key if name_parts else key.key,
            display_name=full_key.as_string(),
            is_super_table=False,
        )

        if len(name_parts) > 1:
            if missing_table:
                # Missing super table
                # i.e. a table initialized like this: [foo.bar]
                # without initializing [foo]
                #
                # So we have to create the parent tables
                table = Table(
                    Container(True),
                    Trivia("", cws, comment, trail),
                    is_aot and name_parts[0] in self._aot_stack,
                    is_super_table=True,
                    name=name_parts[0].key,
                )

            result = table
            key = name_parts[0]

            for i, _name in enumerate(name_parts[1:]):
                child = table.get(
                    _name,
                    Table(
                        Container(True),
                        Trivia(indent, cws, comment, trail),
                        is_aot and i == len(name_parts) - 2,
                        is_super_table=i < len(name_parts) - 2,
                        name=_name.key,
                        display_name=full_key.as_string()
                        if i == len(name_parts) - 2
                        else None,
                    ),
                )
```