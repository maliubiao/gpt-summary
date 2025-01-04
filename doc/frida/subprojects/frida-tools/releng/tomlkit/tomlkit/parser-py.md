Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The core request is to analyze the provided Python code (a TOML parser) and explain its functionality, particularly in the context of reverse engineering, low-level details, logical reasoning, potential errors, and how a user might reach this code. It's crucial to address *all* these aspects.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick skim of the code, looking for important keywords, class names, and function names. This gives a high-level understanding of the code's purpose. Keywords like `Parser`, `TOMLDocument`, `String`, `Integer`, `Array`, `Table`, and exception names like `ParseError`, `InvalidNumberError`, etc., immediately suggest this is about parsing TOML (a configuration file format).

**3. Deeper Dive into Key Classes and Methods:**

Next, focus on the most important classes and methods:

* **`Parser` class:** This is the central class. Its `__init__` method likely initializes the parsing process. The `parse()` method is the main entry point for parsing the TOML string. Other methods starting with `_parse_` clearly handle different parts of the TOML grammar (keys, values, tables, strings, numbers, etc.).
* **Item classes (e.g., `String`, `Integer`, `Array`, `Table`):** These represent the parsed TOML elements. Understanding their structure is important.
* **Exception classes:**  These indicate potential errors during parsing, which is relevant to understanding user errors.

**4. Mapping Code to TOML Grammar:**

Start connecting the code to the structure of a TOML file. For instance:

* `_parse_table()` deals with `[table]` or `[[array of tables]]`.
* `_parse_key_value()` handles `key = value`.
* The various `_parse_..._string()` methods handle different string quote styles.
* `_parse_array()` deals with `[item1, item2]`.

**5. Addressing Specific Requirements:**

Now, systematically address each part of the request:

* **Functionality:**  Summarize the core purpose of the code: parsing TOML into a structured representation. List the main parsing components (keys, values, tables, etc.).
* **Relationship to Reverse Engineering:**  This requires thinking about *how* TOML parsing fits into a dynamic instrumentation tool like Frida. Configuration files often control tool behavior. Therefore, the parser allows Frida to load settings from TOML. Examples include specifying breakpoints, scripts to run, or target processes.
* **Binary/Kernel/Framework Knowledge:** Look for hints in the code. The code itself doesn't directly interact with binaries or the kernel. However, the *purpose* of Frida does. The TOML parser enables *configuring* Frida, which then *will* interact with these low-level systems. The connection is indirect but important. Think about what kind of configuration options might relate to these areas (e.g., specifying memory addresses). Android framework examples could involve package names or component names to hook.
* **Logical Reasoning (Input/Output):** Choose a simple TOML input and mentally (or by actually running a similar parser) trace how this parser would likely process it. Show the resulting structure. This demonstrates the transformation the parser performs.
* **User/Programming Errors:** Look at the exception types. These directly indicate common mistakes users or programs making TOML files might make (invalid syntax, incorrect data types, etc.). Provide concrete TOML examples that trigger these errors.
* **User Operations to Reach the Code (Debugging Clue):**  Think about the steps a user takes to use Frida that *might* involve TOML configuration. This involves scenarios where the user explicitly provides a TOML file or where Frida might use a default TOML configuration. This helps understand the context of the code within the larger Frida ecosystem.
* **Summary of Functionality:** Briefly reiterate the main purpose of the code.

**6. Structuring the Output:**

Organize the information logically using headings and bullet points for clarity. Provide specific examples and explanations for each requirement.

**7. Refinement and Review:**

Read through the generated explanation. Is it clear, accurate, and comprehensive?  Are there any missing points or areas that need further clarification?  For instance, initially, I might have focused too much on the *technical* parsing details and not enough on the *Frida context*. Review helps to correct this. Also, double-check that all parts of the original request have been addressed.

**Self-Correction Example during the Process:**

Initially, when thinking about the "binary/kernel/framework" aspect, I might have thought the parser itself does low-level operations. However, rereading the code reveals it's purely a *text* parser. The connection is that the *output* of this parser (the configuration) is used by other *parts* of Frida that *do* interact with those low-level systems. This distinction is crucial.

By following this systematic approach, you can effectively analyze and explain complex code, addressing all the specific requirements of the prompt.
这是 `frida/subprojects/frida-tools/releng/tomlkit/tomlkit/parser.py` 文件的第 1 部分，它实现了 TOML 格式的解析器。让我们分解一下它的功能：

**主要功能:**

1. **TOML 文档解析:** 该文件的核心功能是将 TOML 格式的字符串或字节流解析成一个结构化的 Python 对象 (`TOMLDocument`)。这个 `TOMLDocument` 对象可以方便地访问 TOML 文件中定义的数据。

2. **词法分析和语法分析:**  `Parser` 类内部实现了词法分析（将输入分解成 token）和语法分析（根据 TOML 语法规则将 token 组合成有意义的结构）。虽然代码中没有显式的词法分析器，但它通过逐字符读取和匹配模式来完成类似的任务。

3. **处理 TOML 的各种元素:**  该解析器能够处理 TOML 规范中定义的各种元素，包括：
    * **键值对 (Key-Value Pairs):**  解析 `key = value` 这样的结构，并支持带引号的键和裸键。
    * **字符串 (Strings):** 支持基本字符串 (双引号)、字面字符串 (单引号) 以及它们的多行版本，并处理转义字符。
    * **整数 (Integers):**  解析不同进制的整数 (十进制、二进制、八进制、十六进制)。
    * **浮点数 (Floats):** 解析标准的浮点数格式。
    * **布尔值 (Booleans):** 解析 `true` 和 `false`。
    * **日期和时间 (Date and Time):** 解析符合 RFC 3339 规范的日期、时间和日期时间。
    * **数组 (Arrays):** 解析 `[item1, item2, ...]` 格式的数组。
    * **内联表 (Inline Tables):** 解析 `{ key1 = value1, key2 = value2 }` 格式的内联表。
    * **标准表 (Standard Tables):** 解析 `[table-name]` 格式的标准表。
    * **数组表 (Array of Tables):** 解析 `[[array-of-tables-name]]` 格式的数组表。
    * **注释 (Comments):**  识别并处理 `#` 开头的注释。
    * **空白 (Whitespace):** 处理空格、制表符和换行符。

4. **错误处理:**  解析器包含了详细的错误处理机制，当遇到不符合 TOML 规范的输入时，会抛出各种 `tomlkit.exceptions` 中定义的异常，例如 `ParseError`、`InvalidNumberError`、`UnexpectedCharError` 等，帮助用户定位错误。

5. **追踪源代码位置:** `Source` 类负责管理输入源，并记录当前解析的位置，这使得在抛出错误时能够提供更精确的错误信息。

**与逆向方法的关系 (举例说明):**

在动态 instrumentation 场景下，逆向工程师经常需要配置工具的行为。TOML 是一种常用的配置文件格式。 `tomlkit.parser.py` 的作用就是让 Frida 工具能够读取和理解 TOML 配置文件。

**举例:**

假设一个 Frida 脚本需要配置目标进程的某些行为，例如要 hook 的函数地址或者需要修改的内存地址。 这些配置信息可以放在一个 TOML 文件中：

```toml
[target]
process_name = "my_target_app"

[hooks]
function_address = "0x12345678"
replace_value = 100
```

Frida 工具会使用 `tomlkit.parser.py` 来解析这个 TOML 文件，然后根据解析出的配置信息来执行相应的 hook 操作。  逆向工程师通过修改 TOML 文件，就可以灵活地调整 Frida 脚本的行为，而无需修改脚本代码本身。

**涉及到二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

虽然 `tomlkit.parser.py` 本身是一个纯粹的文本解析器，不直接涉及二进制底层或内核操作，但它解析出的数据会被 Frida 工具的其他部分使用，而这些部分会涉及到这些底层知识。

**举例:**

* **二进制底层:**  TOML 文件中可能会配置需要 hook 的函数地址（如上面的 `function_address`）。`tomlkit.parser.py` 解析出这个字符串 "0x12345678"，然后 Frida 的其他模块会将这个字符串转换为真正的内存地址，并进行 hook 操作，这涉及到对目标进程内存布局的理解。
* **Linux/Android 内核:**  TOML 文件中可能会配置要跟踪的系统调用。解析器解析出系统调用名称后，Frida 需要调用 Linux 或 Android 内核提供的接口来进行系统调用跟踪。
* **Android 框架:**  在 Android 逆向中，TOML 文件可能包含要 hook 的 Java 类名和方法名。解析器解析这些字符串后，Frida 需要利用 Android 的 Dalvik/ART 虚拟机机制来查找和 hook 对应的方法。

**逻辑推理 (假设输入与输出):**

**假设输入 (TOML 字符串):**

```toml
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00-08:00
```

**预期输出 (简化的 Python 表示):**

```python
{
    'title': 'TOML Example',
    'owner': {
        'name': 'Tom Preston-Werner',
        'dob': datetime.datetime(1979, 5, 27, 7, 32, 0, tzinfo=datetime.timezone(datetime.timedelta(seconds=-28800)))
    }
}
```

解析器会将 TOML 字符串转换成一个嵌套的 Python 字典和基本数据类型的结构。

**用户或编程常见的使用错误 (举例说明):**

1. **语法错误:**  用户可能在 TOML 文件中使用了错误的语法，例如：
   ```toml
   name = "value"  # 正确
   name  "value"   # 错误，缺少等号
   ```
   解析器会抛出 `UnexpectedCharError`。

2. **类型不匹配:**  虽然 TOML 本身是弱类型的，但在 Frida 脚本中使用解析出的值时，可能会出现类型不匹配的问题。例如，TOML 中定义了一个字符串，但 Frida 脚本期望一个整数。这通常不是解析器本身的问题，而是使用解析结果的代码的问题。

3. **缩进错误 (在数组中):**  虽然 TOML 对缩进不敏感，但在数组的定义中，不一致的缩进可能导致理解上的歧义。虽然解析器能够处理，但建议保持一致的风格。

4. **重复的键:** TOML 规范中不允许在同一个表或内联表中存在重复的键。
   ```toml
   name = "a"
   name = "b"  # 错误
   ```
   解析器会抛出相应的错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:**  逆向工程师首先会编写一个 Frida 脚本 (`.js` 文件) 来实现动态 instrumentation 的逻辑。
2. **使用 TOML 配置文件 (可选):** 为了更灵活地配置脚本，工程师可能会创建一个 TOML 格式的配置文件 (`.toml`)，用于存储脚本的参数和设置。
3. **在 Frida 脚本中加载 TOML 文件:**  Frida 脚本会使用 `fs` 模块读取 TOML 文件的内容，然后使用 `tomlkit` 库 (或 Frida 提供的封装) 来解析 TOML 文件。
   ```javascript
   const fs = require('fs');
   const toml = require('tomlkit');

   const configData = fs.readFileSync('config.toml', 'utf8');
   const config = toml.parse(configData);

   console.log(config.target.process_name);
   ```
4. **执行 Frida 命令:**  工程师会使用 Frida 的命令行工具 (`frida` 或 `frida-trace` 等) 来运行脚本，并指定目标进程和配置文件。
   ```bash
   frida -p <process_id> -l my_script.js
   # 或者使用配置文件
   frida -p <process_id> -l my_script.js --options config.toml
   ```
5. **`tomlkit.parser.py` 的调用:** 当 Frida 脚本调用 `toml.parse()` 函数时，实际上就会调用 `tomlkit` 库中的解析器，也就是 `tomlkit/parser.py` 文件中的代码。
6. **调试线索:** 如果在解析 TOML 文件时出现错误，例如 Frida 报错提示 "TOML parse error"，那么就可以怀疑是 TOML 文件的格式有问题。此时，调试线索会指向 `tomlkit.parser.py` 文件，需要检查 TOML 文件是否符合语法规范，以及是否包含了无法解析的字符或结构。

**归纳一下它的功能 (针对第 1 部分):**

`tomlkit/parser.py` 的第 1 部分主要负责构建 TOML 解析器的基础框架和核心的解析逻辑。它定义了 `Parser` 类，用于接收 TOML 输入并逐步解析其中的各种元素 (键值对、字符串、数字、日期时间等)。这一部分的代码已经涵盖了 TOML 语法中大部分基本类型的解析，并包含了错误处理机制，为后续解析更复杂的结构 (表和数组表) 奠定了基础。 重点在于将 TOML 文本转换为 Python 可以理解和操作的数据结构。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tomlkit/parser.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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