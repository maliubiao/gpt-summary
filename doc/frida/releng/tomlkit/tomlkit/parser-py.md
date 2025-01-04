Response:
The user wants a summary of the provided Python code for a TOML parser. I need to identify the core functionalities of this parser and how it relates to concepts like reverse engineering, low-level details, and potential user errors.

Here's a breakdown of the thought process to address each part of the request:

1. **Core Functionalities:**  The most obvious function is parsing TOML. This involves reading a TOML string and converting it into a structured representation. I need to look for keywords and methods related to parsing (like `parse`, `_parse_item`, `_parse_key_value`, etc.) and the data structures it creates (like `TOMLDocument`, `Table`, `Array`, etc.). It also needs to handle different TOML data types (strings, numbers, booleans, dates, arrays, tables).

2. **Relationship to Reverse Engineering:**  Frida is a dynamic instrumentation toolkit often used in reverse engineering. TOML is a configuration file format. The connection lies in the fact that reverse engineering often involves analyzing configuration files of applications. Frida might use this parser to read and potentially modify TOML configuration files of a target application during runtime.

3. **Binary/Kernel/Framework Knowledge:**  The code itself doesn't directly interact with binary data or the kernel. However, the *purpose* of Frida connects it to these areas. Frida instruments processes, which involves interacting with the operating system's mechanisms for process control and memory access. The parser, as a component of Frida, indirectly supports this by enabling the reading of configuration files that might influence how Frida interacts with the target process.

4. **Logical Deduction (Assumptions and Outputs):**  I need to identify methods that involve decision-making based on input. Parsing inherently involves this. For example, based on the current character, the parser decides whether it's parsing a string, number, array, or table. I can create simple input examples and predict the output structure.

5. **Common User/Programming Errors:**  As a parser, it handles syntax. Common errors would be violations of the TOML specification. Looking at the exception classes (like `ParseError`, `InvalidNumberError`, `UnexpectedCharError`) will give clues about potential user mistakes.

6. **User Operation Flow (Debugging Clue):** To reach this code, a user would be using Frida and some part of Frida's functionality would need to parse a TOML file. This could be through a Frida script that loads a configuration file or through Frida's internal mechanisms if it uses TOML for configuration.

7. **Summarization (For Part 1):** Finally, I need to synthesize the identified functionalities into a concise summary specifically for the first part of the explanation.

**Pre-computation/Analysis of the Code:**

* **Import Statements:**  Note the imports from `tomlkit._compat`, `tomlkit.exceptions`, `tomlkit.items`, etc. This reveals the parser is part of a larger `tomlkit` library. The `items` module indicates the different TOML data structures it can handle. The `exceptions` module highlights the types of parsing errors it can encounter.
* **`Parser` Class:**  This is the central class. The `parse()` method is the main entry point.
* **Helper Methods:**  Methods like `_parse_key`, `_parse_value`, `_parse_string`, `_parse_table`, etc., break down the parsing process into smaller, manageable units.
* **Regular Expressions:**  The use of `re` for matching date/time formats is important.
* **State Management:** The `with self._state:` construct suggests a way to manage the parsing state, possibly for backtracking or error handling.

By considering these points, I can construct a comprehensive answer that addresses all aspects of the user's request for the first part of the file.
这是 `frida/releng/tomlkit/tomlkit/parser.py` 文件的第一部分源代码，它实现了 Frida 动态 instrumentation 工具中用于解析 TOML (Tom's Obvious, Minimal Language) 配置文件的解析器。

**功能归纳:**

该代码的主要功能是定义了一个 `Parser` 类，用于将 TOML 格式的字符串或字节流解析成 Python 对象。  具体来说，它能识别 TOML 规范中定义的各种元素，例如：

* **键值对 (Key-Value Pairs):**  解析形如 `key = value` 的语句。
* **表格 (Tables):** 解析形如 `[table_name]` 的标准表格和形如 `[[array_of_tables]]` 的表格数组。
* **数据类型:** 解析以下 TOML 支持的数据类型：
    * **字符串 (Strings):** 包括基本字符串、字面字符串、多行基本字符串和多行字面字符串。
    * **整数 (Integers):**  支持十进制、十六进制、八进制和二进制表示。
    * **浮点数 (Floats):** 支持标准表示和特殊值 (如 `inf`, `nan`)。
    * **布尔值 (Booleans):** `true` 和 `false`。
    * **日期和时间 (Dates and Times):**  解析符合 RFC 3339 标准的日期、时间和日期时间。
    * **数组 (Arrays):** 解析形如 `[item1, item2, ...]` 的数组。
    * **内联表格 (Inline Tables):** 解析形如 `{ key1 = value1, key2 = value2 }` 的单行表格。
* **注释 (Comments):**  识别并处理以 `#` 开头的注释。
* **空白符 (Whitespace):**  正确处理空格、制表符和换行符。

**与其他概念的关联和举例说明:**

**1. 与逆向的方法的关系:**

* **配置分析:** 在逆向工程中，目标应用程序经常使用配置文件来存储其设置和参数。TOML 是一种常见的配置文件格式。Frida 可以使用此解析器来读取目标应用程序的 TOML 配置文件，从而了解应用程序的运行方式和配置，为后续的动态分析提供基础。

    **举例说明:** 假设一个 Android 应用的配置文件 `config.toml` 中包含了服务器地址和端口：

    ```toml
    server_address = "192.168.1.100"
    server_port = 8080
    ```

    Frida 脚本可以使用这个解析器读取这些值，然后在运行时修改它们，例如将 `server_address` 修改为攻击者的服务器，以进行中间人攻击。

**2. 涉及到二进制底层，Linux, Android 内核及框架的知识:**

* **文件系统访问:** 虽然解析器本身不直接操作二进制底层或内核，但 Frida 在使用此解析器读取配置文件时，需要与操作系统（例如 Linux 或 Android）的文件系统进行交互。这涉及到文件 I/O 操作，是操作系统内核提供的功能。
* **进程内存空间:** 在 Frida 进行动态插桩时，它会将自身注入到目标进程的内存空间中。如果配置文件路径是相对于目标进程的，Frida 需要理解目标进程的上下文来正确解析路径并访问文件。
* **Android 框架 (间接):** 对于 Android 应用，配置文件可能存储在应用的私有数据目录中。Frida 需要利用 Android 框架提供的权限和 API 来访问这些目录。虽然解析器本身不涉及 Android 框架的直接调用，但它服务于 Frida 的目标，而 Frida 与 Android 框架有密切的交互。

    **举例说明:**  一个 Frida 脚本可能需要读取 Android 应用 `/data/data/com.example.app/config.toml` 文件。Frida 内部会使用文件系统相关的系统调用（Linux 内核）来打开和读取文件。

**3. 如果做了逻辑推理，请给出假设输入与输出:**

* **假设输入:**
    ```toml
    [database]
    server = "192.168.1.1"
    ports = [ 8001, 8001, 8002 ]
    connection_max = 5000
    enabled = true
    ```

* **输出 (Python 对象):**  `parser.parse()` 方法会返回一个 `TOMLDocument` 对象，其内部结构类似于嵌套的字典和列表，可以访问如下：

    ```python
    document = parser.parse()
    print(document["database"]["server"])  # 输出: "192.168.1.1"
    print(document["database"]["ports"])   # 输出: [8001, 8001, 8002]
    print(document["database"]["enabled"].value) # 输出: True (需要访问 Bool 对象的 value 属性)
    ```

**4. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **语法错误:**  TOML 语法有严格的规定。用户提供的 TOML 字符串如果存在语法错误，解析器会抛出异常。

    **举例说明:**
    ```toml
    name = "Tom"
    age = 30,  # 尾部逗号在 TOML 中是不允许的
    ```
    解析这段代码会抛出 `UnexpectedCharError` 异常。

* **类型错误:**  虽然 TOML 会自动推断类型，但在某些情况下，格式不正确会导致解析错误。

    **举例说明:**
    ```toml
    port = "8080" # 字符串类型的端口，但可能程序期望是整数
    ```
    虽然解析不会报错，但后续使用该配置的程序可能因为类型不匹配而出现问题。这不算是解析器本身的错误，而是用户配置的逻辑错误。然而，像将非数字字符串赋值给期望整数类型的键，也可能导致解析器抛出异常（取决于具体的 TOML 库实现和严格程度）。

* **空键名或表名:** TOML 不允许空的键名或表名。

    **举例说明:**
    ```toml
    = "value"  # 空键名
    []         # 空表名
    ```
    解析这些代码会分别抛出 `EmptyKeyError` 和 `EmptyTableNameError` 异常。

**5. 说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本，目的是对目标进程进行动态插桩。
2. **加载配置文件 (可选):**  在脚本中，用户可能需要读取目标应用程序的配置文件，以便了解其配置信息或修改配置。
3. **使用 TOML 解析功能:** Frida 内部或用户显式地使用了 `tomlkit` 库来解析 TOML 格式的配置文件。例如，可能会有类似这样的代码：

   ```python
   import frida
   import tomlkit

   def on_message(message, data):
       print(message)

   session = frida.attach("com.example.app")
   script = session.create_script("""
       // ... 一些 Frida 代码 ...
       var config_content = readTextFile("/data/data/com.example.app/config.toml");
       send({type: 'config', content: config_content});
   """)
   script.on('message', on_message)
   script.load()

   # 在 Python 端接收到配置文件内容
   config_content = ... # 从 on_message 获取
   try:
       config = tomlkit.parse(config_content) # 这里会调用 tomlkit 的解析器
       print(config["server_address"])
   except tomlkit.exceptions.ParseError as e:
       print("解析 TOML 失败:", e)
   ```

4. **Frida 内部调用:**  也可能 Frida 自身的一些组件或模块使用 TOML 作为配置格式，当 Frida 初始化或执行特定操作时，会内部调用 `tomlkit` 的解析器。
5. **解析器执行:** 当调用 `tomlkit.parse()` 函数时，`parser.py` 中的 `Parser` 类会被实例化，并开始解析提供的 TOML 字符串。
6. **调试线索:** 如果解析过程中出现错误，例如抛出 `UnexpectedCharError`，用户可以通过查看异常信息和 `parser.py` 的源代码，定位到具体的错误位置和原因，例如哪个字符不符合 TOML 语法。

**总结 (针对第 1 部分):**

`frida/releng/tomlkit/tomlkit/parser.py` 的第一部分代码定义了一个 TOML 解析器，负责将 TOML 格式的文本数据转换成 Python 可以操作的数据结构。它能够处理 TOML 规范中定义的各种元素和数据类型，是 Frida 工具中用于读取和理解配置文件的重要组成部分。这个解析器与逆向工程相关，因为它允许 Frida 分析目标应用程序的配置；虽然不直接涉及底层操作，但其应用场景与操作系统和框架息息相关；通过假设输入可以预测其输出；并能捕获用户常见的语法错误。用户通过 Frida 脚本或 Frida 内部机制触发 TOML 解析过程，当解析出错时，这段代码成为调试的重要线索。

Prompt: 
```
这是目录为frida/releng/tomlkit/tomlkit/parser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
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

            
"""


```