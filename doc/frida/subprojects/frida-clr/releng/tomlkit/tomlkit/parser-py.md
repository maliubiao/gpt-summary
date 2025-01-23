Response:
Let's break down the thought process for analyzing this Python code and generating the response.

**1. Understanding the Request:**

The core request is to analyze the provided Python code (`tomlkit/parser.py`) and describe its functionality, especially in relation to:

* **General Functionality:** What does this code do?
* **Reverse Engineering:** How might this code be relevant to reverse engineering?
* **Low-Level Details:**  Does it interact with operating system kernels or frameworks?
* **Logic and Reasoning:** Can we infer logic through input/output examples?
* **Common User Errors:** What mistakes might a programmer make when using this code?
* **Debugging Context:** How does a user end up using this code during debugging?
* **Summarization:** Provide a concise summary of the code's function.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and patterns. This helps establish the high-level purpose. Keywords like:

* `Parser` (the class name)
* `TOMLDocument`
* `_parse_...` (many methods starting with this prefix)
* `Key`, `Value`, `Table`, `Array`, `String`, `Integer`, etc. (item types)
* `exceptions` (various parsing error types)
* `Source`
* `consume`, `inc`, `mark` (methods suggesting input processing)

These immediately suggest that the code is responsible for parsing TOML (Tom's Obvious, Minimal Language) files.

**3. Deeper Dive into Core Functionality (the `parse` method):**

The `parse` method is the entry point for parsing. Observing its structure reveals the high-level parsing process:

* **Initialization:** Creates a `TOMLDocument`.
* **Initial Key-Value Pairs:**  Handles key-value pairs outside of tables.
* **Table Parsing:**  Detects and parses table headers (`[...]`).
* **Array of Tables (AoT):** Handles the `[[...]]` syntax.
* **Appending to Document:**  Adds parsed elements to the `TOMLDocument`.

This confirms the core function: taking TOML text and converting it into a structured representation.

**4. Examining Parsing Sub-methods (`_parse_...`):**

The numerous `_parse_...` methods are crucial. Analyzing them provides details on how specific TOML elements are handled:

* **`_parse_item`:**  Handles top-level items (key-values, comments, whitespace).
* **`_parse_key_value`:**  Parses key-value pairs.
* **`_parse_key` (and its variations):**  Parses different key formats (bare, quoted).
* **`_parse_value`:**  The central dispatcher for parsing various value types (strings, numbers, booleans, arrays, inline tables).
* **`_parse_string` (and its variations):** Parses different string types (basic, literal, multiline).
* **`_parse_number`:**  Parses integers and floats.
* **`_parse_bool`:** Parses boolean values.
* **`_parse_array`:** Parses arrays.
* **`_parse_inline_table`:** Parses inline tables.
* **`_parse_table`:** Parses table headers and their content.
* **`_parse_aot`:** Specifically handles arrays of tables.

**5. Connecting to Reverse Engineering:**

This is where the "Frida" context becomes important. Knowing that this is part of Frida, a dynamic instrumentation tool, suggests how TOML parsing is relevant:

* **Configuration:** Frida likely uses TOML for configuration files. Reverse engineers might analyze these files to understand Frida's behavior, customization options, or how specific targets are instrumented.
* **Scripting:**  Frida uses JavaScript, but configuration *related* to scripts or instrumentation might be defined in TOML.
* **Analysis of Tooling:** Understanding how Frida itself is configured can be part of reverse engineering *Frida* itself.

**6. Identifying Low-Level Interactions (or Lack Thereof):**

A careful examination of the code shows no direct interaction with the Linux kernel, Android frameworks, or binary formats. It operates purely on text. The focus is on the *syntax* of TOML, not on system-level operations. Therefore, the response correctly notes the absence of such interactions.

**7. Inferring Logic and Reasoning (Input/Output):**

By looking at the parsing methods and the TOML syntax they handle, we can construct simple examples:

* **Basic Key-Value:** `key = "value"`  ->  `Key("key")`, `String("value")`
* **Table:** `[table]` -> `Key("table")`, `Table(...)`
* **Array:** `array = [1, 2, 3]` -> `Key("array")`, `Array(...)`

This helps illustrate the transformation process.

**8. Identifying User Errors:**

Based on the parsing rules and the exception types, we can deduce common errors:

* **Incorrect Syntax:**  Mismatched quotes, missing commas, invalid characters.
* **Empty Keys/Table Names:** The parser explicitly checks for these.
* **Invalid Numbers/Dates:** The parser attempts to convert strings to numbers and dates, which can fail.

**9. Debugging Context:**

The user likely interacts with this code indirectly when:

* **Frida Configuration:** Modifying a TOML configuration file.
* **Frida Scripting (Indirectly):**  If Frida scripts rely on TOML configuration.
* **Developing or Debugging Frida Itself:**  If contributing to or troubleshooting Frida's internals. Setting breakpoints in this parser would be a way to understand how configuration is being loaded.

**10. Summarization:**

Finally, synthesize the key findings into a concise summary:  The code parses TOML configuration files for the Frida dynamic instrumentation tool.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Might this code interact with file I/O?  *Correction:* Yes, but the provided snippet focuses on the parsing *logic* after the file content is loaded into a string.
* **Initial Thought:**  Could this be used to parse binary data formats? *Correction:* No, TOML is a text-based format. The code operates on strings.
* **Ensuring Relevance to Frida:**  Continuously connecting the functionality back to the context of Frida is essential for answering the specific requirements of the prompt.

By following these steps, combining code analysis with an understanding of the request's nuances (especially the Frida context), and performing some logical deduction, we can generate a comprehensive and accurate response.
好的，这是对 `frida/subprojects/frida-clr/releng/tomlkit/tomlkit/parser.py` 文件（第一部分）的功能归纳：

**文件功能概述：**

`parser.py` 文件的核心功能是 **解析 TOML (Tom's Obvious, Minimal Language) 格式的文本数据，并将其转换为 Python 对象**。它实现了 TOML 语法的分析器，能够识别 TOML 文件中的各种元素，例如键值对、表格、数组、内联表格、字符串、数字、布尔值、日期和时间等。

**详细功能点：**

1. **TOML 文档解析入口 (`parse` 方法):**
   - 接收 TOML 格式的字符串或字节流作为输入。
   - 创建一个 `TOMLDocument` 对象，用于存储解析后的数据。
   - 循环处理输入，首先解析位于任何表格之外的全局键值对。
   - 遇到 `[` 字符时，识别为表格的开始，并调用 `_parse_table` 方法进行解析。
   - 遇到 `[[` 字符时，识别为数组表格 (Array of Tables, AoT) 的开始，并调用 `_parse_aot` 方法进行解析。
   - 将解析出的键值对和表格添加到 `TOMLDocument` 对象中。
   - 最终返回一个表示整个 TOML 文档结构的 `TOMLDocument` 对象。

2. **核心解析逻辑 (`_parse_item`, `_parse_key_value`, `_parse_key`, `_parse_value` 等方法):**
   - `_parse_item`: 尝试解析下一个 TOML 项（可能是键值对、注释或空白）。
   - `_parse_key_value`: 解析键值对，包括键的解析和值的解析。
   - `_parse_key`: 解析键名，支持裸键 (bare key) 和带引号的键 (quoted key)。
   - `_parse_value`: 解析各种类型的 TOML 值，包括字符串、数字、布尔值、数组和内联表格。
   - 针对不同类型的 TOML 值，有专门的解析方法，例如：
     - `_parse_basic_string`, `_parse_literal_string`: 解析不同类型的字符串。
     - `_parse_number`: 解析整数和浮点数。
     - `_parse_true`, `_parse_false`: 解析布尔值。
     - `_parse_array`: 解析数组。
     - `_parse_inline_table`: 解析内联表格。

3. **表格和数组表格解析 (`_parse_table`, `_parse_aot`):**
   - `_parse_table`: 解析标准 TOML 表格，识别表格名并处理表格内的键值对。
   - `_parse_aot`: 解析数组表格，允许在同一个数组下定义多个具有相同名称的表格。

4. **错误处理:**
   - 定义了多种异常类 (例如 `ParseError`, `UnexpectedCharError`, `InvalidNumberError` 等) 来处理解析过程中遇到的各种错误情况。
   - 在解析过程中，会检查输入是否符合 TOML 语法规范，并在发现错误时抛出相应的异常。

5. **空白和注释处理:**
   - 能够识别和处理 TOML 文件中的空白字符（空格、制表符、换行符）。
   - 能够解析和存储注释信息，包括注释前后的空白。

6. **字符处理和输入管理:**
   - 使用 `Source` 类来管理输入字符串，并提供前进、标记、提取等操作。
   - 定义了 `TOMLChar` 类来辅助判断字符类型。

**与逆向方法的关系及举例：**

该解析器本身 **不是直接用于逆向** 二进制代码的工具。然而，它在 Frida 框架中扮演着重要的角色，因为 **Frida 可能使用 TOML 文件来配置其行为或存储相关信息**。逆向工程师在分析 Frida 时，可能会遇到需要理解或修改 Frida 的配置文件的情况，这时就需要用到 TOML 解析器。

**举例：**

假设 Frida 的一个插件或模块的配置文件是 TOML 格式，例如 `plugin_config.toml`：

```toml
[plugin]
enabled = true
log_level = "INFO"
target_process = "com.example.app"

[instrumentation]
hook_functions = ["func1", "func2"]
```

逆向工程师如果想了解该插件的配置，就需要解析这个 `plugin_config.toml` 文件。Frida 内部就会使用 `tomlkit.parser.Parser` 来完成这个任务。逆向工程师可能需要：

- **分析配置项：** 了解 `enabled`、`log_level`、`target_process` 等配置项的含义，从而理解插件的行为。
- **修改配置：**  例如，将 `enabled` 改为 `false` 来禁用插件，或者修改 `hook_functions` 来调整需要 hook 的函数。

**二进制底层、Linux、Android 内核及框架的知识：**

该解析器 **本身不直接涉及** 二进制底层、Linux/Android 内核或框架的知识。它的主要任务是处理文本格式的数据。然而，**Frida 作为动态插桩工具，其核心功能是与这些底层系统进行交互的**。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户编写或修改 Frida 脚本:** 用户可能会编写 JavaScript 脚本来使用 Frida 的功能，这些脚本可能会读取或处理配置文件。
2. **Frida 加载配置文件:** 当 Frida 启动或执行相关操作时，它可能会读取 TOML 格式的配置文件。
3. **tomlkit 被调用:**  Frida 内部的代码会调用 `tomlkit` 库来解析这些 TOML 配置文件。具体来说，会创建 `Parser` 实例并调用其 `parse` 方法。
4. **解析过程出错:** 如果 TOML 配置文件存在语法错误，`Parser` 可能会抛出异常。
5. **调试:**  在开发 Frida 插件或调试 Frida 行为时，开发者可能会遇到与配置文件解析相关的问题，从而需要查看 `parser.py` 的源代码来理解解析过程或定位错误原因。例如，开发者可能会在 `parse` 方法或某个 `_parse_...` 方法中设置断点，来观察解析过程中的变量值和执行流程。

**总结其功能：**

`frida/subprojects/frida-clr/releng/tomlkit/tomlkit/parser.py` 的核心功能是 **实现了一个用于解析 TOML 格式文本的分析器**。它负责将 TOML 文本转换为结构化的 Python 对象，是 Frida 框架中处理配置文件的关键组成部分。虽然它本身不直接参与底层操作或逆向过程，但为 Frida 提供了读取和理解配置信息的能力，这在 Frida 的使用和分析中至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tomlkit/parser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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