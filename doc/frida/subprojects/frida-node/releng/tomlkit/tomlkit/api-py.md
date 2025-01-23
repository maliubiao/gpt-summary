Response:
Let's break down the thought process for analyzing the `api.py` file.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the `api.py` file within the `tomlkit` library, specifically focusing on its relationship with reverse engineering, low-level operations, logical reasoning, common user errors, and debugging.

**2. Initial Scan and Identification of Core Functionality:**

The first step is to quickly read through the code, identifying the main functions and the types they handle. Keywords like `loads`, `dumps`, `load`, `dump`, `parse`, `document`, and the various `*_` functions for creating specific TOML elements (like `integer`, `string`, `table`, etc.) immediately stand out. The import statements also give hints about the file's purpose (handling TOML data, working with dates/times, collections, and custom types).

**3. Categorizing Functions by Purpose:**

Next, group the functions based on their primary responsibility:

* **Parsing/Loading:** `loads`, `load`, `parse` - converting TOML from strings or files to Python objects.
* **Dumping/Saving:** `dumps`, `dump` - converting Python objects to TOML strings or files.
* **Object Creation:**  `document`, `integer`, `float_`, `boolean`, `string`, `date`, `time`, `datetime`, `array`, `table`, `inline_table`, `aot`, `key`, `value`, `key_value`, `ws`, `nl`, `comment` - creating individual TOML elements.
* **Customization:** `register_encoder`, `unregister_encoder` - extending the library's ability to handle custom data types.

**4. Connecting to Reverse Engineering:**

This requires thinking about how TOML files are used and how a library like `tomlkit` might be relevant in a reverse engineering context.

* **Configuration Files:** TOML is often used for configuration. Reverse engineers might encounter TOML files within applications or embedded systems. The ability to *parse* these files is crucial for understanding the application's settings.
* **Data Structures:**  TOML can represent structured data. Reverse engineers might analyze TOML files to understand data formats used by a program.
* **Dynamic Analysis (with Frida):** Since the context is "fridaDynamic instrumentation tool," the connection becomes clearer. Frida can be used to intercept function calls and examine data. `tomlkit` could be used within a Frida script to parse configuration data read from memory or files by the target application. Conversely, it could be used to *create* TOML data to inject into the application.

**5. Exploring Low-Level Aspects:**

This involves looking for clues about interactions with the operating system or data representation.

* **File I/O:** The `load` and `dump` functions directly interact with the file system.
* **Data Types:**  The functions handling `date`, `time`, and `datetime` touch on the underlying representation of these data types.
* **String Encoding:** While not explicitly low-level kernel stuff, the handling of strings (especially with `literal`, `multiline`, and `escape` options) touches on data representation.

**6. Identifying Logical Reasoning:**

This focuses on functions that perform transformations or make decisions based on input.

* **Parsing Logic:**  The `parse` function (and the underlying `Parser` class, though not detailed here) performs complex logical analysis to interpret the TOML syntax.
* **Type Conversion:** Functions like `integer`, `float_`, `boolean`, `date`, `time`, `datetime` perform type conversions based on the input string.
* **`dumps` and `sort_keys`:** The decision to sort keys introduces a logical step in the output process.
* **`String.from_raw`:** The logic within this method (though not explicitly shown) to determine string types and handle escaping is a form of logical reasoning.

**7. Considering User Errors:**

Think about common mistakes developers might make when using the library.

* **Incorrect Input Types:** Passing a non-string/bytes to `loads` or `parse`, or incorrect data types to the object creation functions.
* **Invalid TOML Syntax:** Trying to parse a string that doesn't conform to the TOML specification.
* **File Handling Errors:**  Issues with file paths or permissions when using `load` or `dump`.
* **Misunderstanding String Options:** Incorrectly using `literal`, `multiline`, or `escape` when creating strings.
* **Type Mismatches with Custom Encoders:**  Custom encoders not returning a valid TOMLKit item.

**8. Tracing User Actions (Debugging Context):**

Imagine a developer using Frida and encountering this code. How might they arrive at `api.py`?

* **Importing `tomlkit`:** The developer explicitly imports the library in their Frida script.
* **Calling Functions:** The developer calls functions like `tomlkit.loads()` or `tomlkit.parse()` to process TOML data obtained from the target application.
* **Stepping Through Code:** Using a debugger (if available with Frida or their development environment), they might step into the `tomlkit` code to understand its behavior.
* **Investigating Errors:** If they encounter parsing errors or unexpected output, they might trace the execution to pinpoint the source of the issue within `tomlkit`.

**9. Structuring the Output:**

Finally, organize the findings into clear sections, using headings and bullet points for readability. Provide concrete examples for each point to illustrate the concepts. Use the function names directly in the explanation to link the functionality to the code. Make sure to directly address each point in the original request (functionality, reverse engineering, low-level, logic, user errors, debugging).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the individual `item` function. Realize the higher-level functions are more important for understanding the overall purpose.
* **Realization:** The context of Frida is crucial for connecting to reverse engineering. Emphasize how `tomlkit` could be used within Frida scripts.
* **Clarity:** Ensure the examples are clear and directly relate to the explained functionality. Avoid overly technical jargon where simpler terms suffice.
* **Completeness:** Double-check that all aspects of the original request have been addressed.

By following these steps, combining code analysis with conceptual understanding and consideration of the broader context, we can effectively analyze the `api.py` file and provide a comprehensive explanation.
好的，让我们来分析一下 `frida/subprojects/frida-node/releng/tomlkit/tomlkit/api.py` 这个文件，它是 frida 动态 instrumentation 工具中 `tomlkit` 库的 API 定义文件。`tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。

**文件功能列表：**

这个文件定义了 `tomlkit` 库的用户接口，提供了一系列函数用于操作 TOML 数据。主要功能包括：

1. **加载 TOML 数据:**
   - `loads(string: str | bytes) -> TOMLDocument`: 将 TOML 格式的字符串或字节串解析成 `TOMLDocument` 对象。
   - `load(fp: IO[str] | IO[bytes]) -> TOMLDocument`: 从文件对象中读取 TOML 数据并解析成 `TOMLDocument` 对象。
   - `parse(string: str | bytes) -> TOMLDocument`:  与 `loads` 功能相同，将 TOML 字符串或字节串解析为 `TOMLDocument`。

2. **导出 TOML 数据:**
   - `dumps(data: Mapping, sort_keys: bool = False) -> str`: 将 `TOMLDocument` 或 Python 字典等映射类型的数据转换成 TOML 格式的字符串。`sort_keys` 参数可以控制输出时是否对键进行排序。
   - `dump(data: Mapping, fp: IO[str], *, sort_keys: bool = False) -> None`: 将 `TOMLDocument` 或 Python 字典等映射类型的数据写入到指定的文件对象中。`sort_keys` 参数同样用于控制键的排序。

3. **创建 TOML 对象:**
   - `document() -> TOMLDocument`: 创建一个新的空的 `TOMLDocument` 对象，用于构建 TOML 数据结构。
   - 一系列用于创建不同 TOML 数据类型的函数，例如：
     - `integer(raw: str | int) -> Integer`: 创建整数类型的 TOML 项。
     - `float_(raw: str | float) -> Float`: 创建浮点数类型的 TOML 项。
     - `boolean(raw: str) -> Bool`: 创建布尔类型的 TOML 项。
     - `string(...) -> String`: 创建字符串类型的 TOML 项，可以指定是否为字面量字符串、多行字符串以及是否进行转义。
     - `date(raw: str) -> Date`: 创建日期类型的 TOML 项。
     - `time(raw: str) -> Time`: 创建时间类型的 TOML 项。
     - `datetime(raw: str) -> DateTime`: 创建日期时间类型的 TOML 项。
     - `array(raw: str = None) -> Array`: 创建数组类型的 TOML 项。
     - `table(is_super_table: bool | None = None) -> Table`: 创建表格类型的 TOML 项。
     - `inline_table() -> InlineTable`: 创建内联表格类型的 TOML 项。
     - `aot() -> AoT`: 创建数组表格类型的 TOML 项。
     - `key(k: str | Iterable[str]) -> Key`: 创建键，可以是简单键或点号分隔的键。
     - `value(raw: str) -> _Item`: 解析一个简单的 TOML 值。
     - `key_value(src: str) -> tuple[Key, _Item]`: 解析一个键值对。
     - `ws(src: str) -> Whitespace`: 创建空白符。
     - `nl() -> Whitespace`: 创建换行符。
     - `comment(string: str) -> Comment`: 创建注释。

4. **自定义编码器:**
   - `register_encoder(encoder: E) -> E`: 注册自定义编码器，用于处理无法默认转换的 Python 对象到 TOML 类型的转换。
   - `unregister_encoder(encoder: Encoder) -> None`: 注销已注册的自定义编码器。

**与逆向方法的关联及举例说明：**

`tomlkit` 作为一个 TOML 解析库，在逆向工程中主要用于处理目标程序使用的 TOML 配置文件。

**举例说明:**

假设你需要逆向一个使用 TOML 格式存储配置信息的 Android 应用。你通过某种方式（例如，解包 APK 并提取文件，或者使用 Frida 从内存中读取）获得了该应用的配置文件 `config.toml`。

```toml
# Configuration file for the awesome app

[database]
server = "192.168.1.10"
ports = [ 8001, 8001, 8002 ]
connection_max = 5000
enabled = true

[owner]
name = "John Doe"
dob = 1979-05-27T07:32:00-08:00
```

使用 Frida 和 `tomlkit`，你可以编写脚本来解析这个配置文件并获取其中的信息：

```python
import frida
import tomlkit

# ... 连接到目标进程的代码 ...

# 假设你已经从文件或内存中读取了 config.toml 的内容
toml_content = """
# Configuration file for the awesome app

[database]
server = "192.168.1.10"
ports = [ 8001, 8001, 8002 ]
connection_max = 5000
enabled = true

[owner]
name = "John Doe"
dob = 1979-05-27T07:32:00-08:00
"""

try:
    config = tomlkit.loads(toml_content)
    database_server = config['database']['server']
    max_connections = config['database']['connection_max']
    owner_name = config['owner']['name']

    print(f"Database Server: {database_server}")
    print(f"Max Connections: {max_connections}")
    print(f"Owner Name: {owner_name}")

except tomlkit.exceptions.ParseError as e:
    print(f"Error parsing TOML: {e}")
```

在这个例子中，`tomlkit.loads()` 函数被用来解析 TOML 配置文件内容，使得你可以方便地访问配置项，例如数据库服务器地址、最大连接数和所有者姓名。这对于理解目标应用的配置和行为非常有帮助。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

`tomlkit` 本身是一个纯 Python 库，主要处理文本格式的 TOML 数据，它本身并不直接涉及二进制底层、Linux/Android 内核或框架的交互。然而，在逆向工程的上下文中，`tomlkit` 常常与其他工具和技术结合使用，这些工具和技术可能会涉及到这些底层知识。

**举例说明:**

1. **从 Android 应用中提取配置文件:** 你可能需要使用 `adb` 命令（与 Android 框架交互）来从 Android 设备中拉取应用的配置文件。这个过程涉及到文件系统操作和 Android 权限模型等知识。

2. **使用 Frida 从内存中读取配置数据:** 使用 Frida 时，你可能会编写 JavaScript 代码来查找目标应用中存储配置信息的内存地址，并读取其内容。这需要对目标应用的内存布局、进程空间以及 Frida 的内存操作 API 有所了解。读取到的内存数据可能是二进制格式，需要先转换为字符串，才能用 `tomlkit` 解析。

3. **Hook 系统调用:** 在某些情况下，应用的配置文件可能在运行时动态加载，你可能需要 Hook 与文件操作相关的系统调用（如 `open`, `read`，这些是 Linux 内核提供的接口），来截获应用的配置读取行为，并获取配置文件的内容，再用 `tomlkit` 解析。

**逻辑推理的假设输入与输出：**

`tomlkit` 的核心功能是解析和生成 TOML 数据，其中解析过程涉及到对 TOML 语法规则的逻辑推理。

**假设输入：**

```toml
[package]
name = "tomlkit"
version = "0.11.8"
authors = ["Sébastien Eustace <sebastien@connexion.gg>"]

[dependencies]
python = ">=3.7"
```

**逻辑推理过程 (`tomlkit.loads` 内部)：**

1. **识别节 (Section):**  解析器遇到 `[package]`，识别出一个名为 "package" 的节（Table）。
2. **识别键值对 (Key-Value Pairs):**
   - 遇到 `name = "tomlkit"`，识别出键 "name" 和字符串值 "tomlkit"。
   - 遇到 `version = "0.11.8"`，识别出键 "version" 和字符串值 "0.11.8"。
   - 遇到 `authors = ["Sébastien Eustace <sebastien@connexion.gg>"]`，识别出键 "authors" 和字符串数组 `["Sébastien Eustace <sebastien@connexion.gg>"]`。
3. **识别新的节:** 遇到 `[dependencies]`，识别出另一个名为 "dependencies" 的节。
4. **继续识别键值对:**
   - 遇到 `python = ">=3.7"`，识别出键 "python" 和字符串值 ">=3.7"。

**输出 (Python 字典表示):**

```python
{
    'package': {
        'name': 'tomlkit',
        'version': '0.11.8',
        'authors': ['Sébastien Eustace <sebastien@connexion.gg>']
    },
    'dependencies': {
        'python': '>=3.7'
    }
}
```

`tomlkit.loads` 函数会根据 TOML 的语法规则，将输入的文本数据结构化地解析成 Python 的字典和列表等数据结构。

**用户或编程常见的使用错误及举例说明：**

1. **解析非法的 TOML 格式:**

   ```python
   import tomlkit

   invalid_toml = """
   name = "tomlkit"
   version = 0.11.8  # 缺少引号
   """

   try:
       data = tomlkit.loads(invalid_toml)
   except tomlkit.exceptions.ParseError as e:
       print(f"解析错误: {e}")
   ```
   **错误说明:** TOML 规范要求字符串值必须使用引号括起来。`tomlkit` 会抛出 `ParseError` 异常来指示语法错误。

2. **尝试将不支持的 Python 对象转储为 TOML:**

   ```python
   import tomlkit

   data = {"complex": complex(1, 2)}

   try:
       toml_string = tomlkit.dumps(data)
   except TypeError as e:
       print(f"类型错误: {e}")
   ```
   **错误说明:** 默认情况下，`tomlkit` 不支持将复数类型直接转换为 TOML。需要注册自定义编码器才能处理这类情况。

3. **文件操作错误 (例如，文件不存在或权限不足):**

   ```python
   import tomlkit

   try:
       with open("nonexistent_config.toml", "r") as f:
           config = tomlkit.load(f)
   except FileNotFoundError as e:
       print(f"文件未找到: {e}")
   ```
   **错误说明:**  当使用 `tomlkit.load` 或 `tomlkit.dump` 操作文件时，需要确保文件存在且具有相应的读写权限。

4. **误用字符串类型创建函数:**

   ```python
   import tomlkit

   # 期望创建一个字面量字符串，但错误地使用了基本字符串的函数
   literal_str = tomlkit.string("C:\\path\\to\\file")
   print(literal_str) # 输出: 'C:\\path\\to\\file'，反斜杠被转义

   # 正确创建字面量字符串的方式
   literal_str_correct = tomlkit.string("C:\\path\\to\\file", literal=True)
   print(literal_str_correct) # 输出: 'C:\\path\\to\\file'，反斜杠未转义
   ```
   **错误说明:**  `tomlkit.string` 函数的 `literal` 参数用于指定创建的是否为字面量字符串。不正确地使用参数会导致意外的转义行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设一个 Frida 用户在编写脚本时遇到了与 TOML 配置相关的错误，以下是可能的调试路径：

1. **用户编写 Frida 脚本，尝试解析目标应用的配置文件。** 这可能涉及到从文件中读取配置内容，或者从内存中读取。
2. **用户调用 `tomlkit.loads()` 或 `tomlkit.parse()` 函数，传入配置文件的字符串内容。**
3. **如果 TOML 内容格式错误，`tomlkit` 会抛出 `tomlkit.exceptions.ParseError` 异常。** 用户会看到错误信息，指出哪一行或哪个位置存在语法错误。
4. **用户可能会检查传入 `loads` 函数的字符串内容，确认是否与预期的 TOML 格式一致。**
5. **如果需要深入了解解析过程，用户可能会尝试单步调试 Frida 脚本，进入 `tomlkit.loads` 的实现。** 这将引导他们进入 `api.py` 文件，特别是 `loads` 和 `parse` 函数。
6. **在 `api.py` 中，用户可以查看 `Parser` 类的调用，理解 TOML 的解析流程。**
7. **如果问题与自定义类型的编码有关，用户可能会查看 `register_encoder` 的使用，以及自定义编码器的实现。**
8. **如果涉及到文件操作，用户可能会检查 `load` 和 `dump` 函数，确认文件路径、权限等是否正确。**

总而言之，`api.py` 文件是 `tomlkit` 库的核心接口，用户通过调用这里定义的函数来完成 TOML 数据的解析、生成和操作。当出现问题时，理解这个文件中各个函数的功能和使用方式，是进行调试的关键。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tomlkit/api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
from __future__ import annotations

import contextlib
import datetime as _datetime

from collections.abc import Mapping
from typing import IO
from typing import Iterable
from typing import TypeVar

from tomlkit._utils import parse_rfc3339
from tomlkit.container import Container
from tomlkit.exceptions import UnexpectedCharError
from tomlkit.items import CUSTOM_ENCODERS
from tomlkit.items import AoT
from tomlkit.items import Array
from tomlkit.items import Bool
from tomlkit.items import Comment
from tomlkit.items import Date
from tomlkit.items import DateTime
from tomlkit.items import DottedKey
from tomlkit.items import Encoder
from tomlkit.items import Float
from tomlkit.items import InlineTable
from tomlkit.items import Integer
from tomlkit.items import Item as _Item
from tomlkit.items import Key
from tomlkit.items import SingleKey
from tomlkit.items import String
from tomlkit.items import StringType as _StringType
from tomlkit.items import Table
from tomlkit.items import Time
from tomlkit.items import Trivia
from tomlkit.items import Whitespace
from tomlkit.items import item
from tomlkit.parser import Parser
from tomlkit.toml_document import TOMLDocument


def loads(string: str | bytes) -> TOMLDocument:
    """
    Parses a string into a TOMLDocument.

    Alias for parse().
    """
    return parse(string)


def dumps(data: Mapping, sort_keys: bool = False) -> str:
    """
    Dumps a TOMLDocument into a string.
    """
    if not isinstance(data, Container) and isinstance(data, Mapping):
        data = item(dict(data), _sort_keys=sort_keys)

    try:
        # data should be a `Container` (and therefore implement `as_string`)
        # for all type safe invocations of this function
        return data.as_string()  # type: ignore[attr-defined]
    except AttributeError as ex:
        msg = f"Expecting Mapping or TOML Container, {type(data)} given"
        raise TypeError(msg) from ex


def load(fp: IO[str] | IO[bytes]) -> TOMLDocument:
    """
    Load toml document from a file-like object.
    """
    return parse(fp.read())


def dump(data: Mapping, fp: IO[str], *, sort_keys: bool = False) -> None:
    """
    Dump a TOMLDocument into a writable file stream.

    :param data: a dict-like object to dump
    :param sort_keys: if true, sort the keys in alphabetic order
    """
    fp.write(dumps(data, sort_keys=sort_keys))


def parse(string: str | bytes) -> TOMLDocument:
    """
    Parses a string or bytes into a TOMLDocument.
    """
    return Parser(string).parse()


def document() -> TOMLDocument:
    """
    Returns a new TOMLDocument instance.
    """
    return TOMLDocument()


# Items
def integer(raw: str | int) -> Integer:
    """Create an integer item from a number or string."""
    return item(int(raw))


def float_(raw: str | float) -> Float:
    """Create an float item from a number or string."""
    return item(float(raw))


def boolean(raw: str) -> Bool:
    """Turn `true` or `false` into a boolean item."""
    return item(raw == "true")


def string(
    raw: str,
    *,
    literal: bool = False,
    multiline: bool = False,
    escape: bool = True,
) -> String:
    """Create a string item.

    By default, this function will create *single line basic* strings, but
    boolean flags (e.g. ``literal=True`` and/or ``multiline=True``)
    can be used for personalization.

    For more information, please check the spec: `<https://toml.io/en/v1.0.0#string>`__.

    Common escaping rules will be applied for basic strings.
    This can be controlled by explicitly setting ``escape=False``.
    Please note that, if you disable escaping, you will have to make sure that
    the given strings don't contain any forbidden character or sequence.
    """
    type_ = _StringType.select(literal, multiline)
    return String.from_raw(raw, type_, escape)


def date(raw: str) -> Date:
    """Create a TOML date."""
    value = parse_rfc3339(raw)
    if not isinstance(value, _datetime.date):
        raise ValueError("date() only accepts date strings.")

    return item(value)


def time(raw: str) -> Time:
    """Create a TOML time."""
    value = parse_rfc3339(raw)
    if not isinstance(value, _datetime.time):
        raise ValueError("time() only accepts time strings.")

    return item(value)


def datetime(raw: str) -> DateTime:
    """Create a TOML datetime."""
    value = parse_rfc3339(raw)
    if not isinstance(value, _datetime.datetime):
        raise ValueError("datetime() only accepts datetime strings.")

    return item(value)


def array(raw: str = None) -> Array:
    """Create an array item for its string representation.

    :Example:

    >>> array("[1, 2, 3]")  # Create from a string
    [1, 2, 3]
    >>> a = array()
    >>> a.extend([1, 2, 3])  # Create from a list
    >>> a
    [1, 2, 3]
    """
    if raw is None:
        raw = "[]"

    return value(raw)


def table(is_super_table: bool | None = None) -> Table:
    """Create an empty table.

    :param is_super_table: if true, the table is a super table

    :Example:

    >>> doc = document()
    >>> foo = table(True)
    >>> bar = table()
    >>> bar.update({'x': 1})
    >>> foo.append('bar', bar)
    >>> doc.append('foo', foo)
    >>> print(doc.as_string())
    [foo.bar]
    x = 1
    """
    return Table(Container(), Trivia(), False, is_super_table)


def inline_table() -> InlineTable:
    """Create an inline table.

    :Example:

    >>> table = inline_table()
    >>> table.update({'x': 1, 'y': 2})
    >>> print(table.as_string())
    {x = 1, y = 2}
    """
    return InlineTable(Container(), Trivia(), new=True)


def aot() -> AoT:
    """Create an array of table.

    :Example:

    >>> doc = document()
    >>> aot = aot()
    >>> aot.append(item({'x': 1}))
    >>> doc.append('foo', aot)
    >>> print(doc.as_string())
    [[foo]]
    x = 1
    """
    return AoT([])


def key(k: str | Iterable[str]) -> Key:
    """Create a key from a string. When a list of string is given,
    it will create a dotted key.

    :Example:

    >>> doc = document()
    >>> doc.append(key('foo'), 1)
    >>> doc.append(key(['bar', 'baz']), 2)
    >>> print(doc.as_string())
    foo = 1
    bar.baz = 2
    """
    if isinstance(k, str):
        return SingleKey(k)
    return DottedKey([key(_k) for _k in k])


def value(raw: str) -> _Item:
    """Parse a simple value from a string.

    :Example:

    >>> value("1")
    1
    >>> value("true")
    True
    >>> value("[1, 2, 3]")
    [1, 2, 3]
    """
    parser = Parser(raw)
    v = parser._parse_value()
    if not parser.end():
        raise parser.parse_error(UnexpectedCharError, char=parser._current)
    return v


def key_value(src: str) -> tuple[Key, _Item]:
    """Parse a key-value pair from a string.

    :Example:

    >>> key_value("foo = 1")
    (Key('foo'), 1)
    """
    return Parser(src)._parse_key_value()


def ws(src: str) -> Whitespace:
    """Create a whitespace from a string."""
    return Whitespace(src, fixed=True)


def nl() -> Whitespace:
    """Create a newline item."""
    return ws("\n")


def comment(string: str) -> Comment:
    """Create a comment item."""
    return Comment(Trivia(comment_ws="  ", comment="# " + string))


E = TypeVar("E", bound=Encoder)


def register_encoder(encoder: E) -> E:
    """Add a custom encoder, which should be a function that will be called
    if the value can't otherwise be converted. It should takes a single value
    and return a TOMLKit item or raise a ``TypeError``.
    """
    CUSTOM_ENCODERS.append(encoder)
    return encoder


def unregister_encoder(encoder: Encoder) -> None:
    """Unregister a custom encoder."""
    with contextlib.suppress(ValueError):
        CUSTOM_ENCODERS.remove(encoder)
```