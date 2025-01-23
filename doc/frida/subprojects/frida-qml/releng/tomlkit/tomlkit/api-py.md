Response:
Let's break down the thought process for analyzing the `api.py` file and generating the explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the Python code and explain its functionalities in the context of Frida, reverse engineering, low-level details, logic, common errors, and debugging. This means going beyond a simple description of what each function does.

**2. Initial Code Scan and Identification of Key Components:**

The first step is to read through the code to identify the core building blocks and purpose. Keywords like `tomlkit`, `parse`, `dump`, `loads`, `dumps`, and various item types (like `Integer`, `String`, `Table`, etc.) immediately suggest this is a library for handling TOML files. The file name `api.py` reinforces that this is the public interface of the `tomlkit` library.

**3. Functional Breakdown and Grouping:**

Next, I mentally grouped the functions based on their apparent purpose:

* **Loading/Parsing:**  `loads`, `load`, `parse` (string/bytes to TOML object)
* **Dumping/Serialization:** `dumps`, `dump` (TOML object to string/file)
* **Creating TOML Items:** `integer`, `float_`, `boolean`, `string`, `date`, `time`, `datetime`, `array`, `table`, `inline_table`, `aot`, `key`, `value`, `key_value`, `ws`, `nl`, `comment` (constructing individual TOML elements)
* **Utility/Configuration:** `document`, `register_encoder`, `unregister_encoder` (creating a new document, handling custom data types)

**4. Relating to Frida and Reverse Engineering:**

This is the crucial step for connecting the code to the specific context. I considered how TOML files are used in software development and reverse engineering:

* **Configuration:** TOML is often used for configuration files. In reverse engineering, examining configuration files can reveal important information about how a program works, its settings, dependencies, etc. Frida, being a dynamic instrumentation tool, might need to parse configuration files to understand target applications or configure its own behavior. This led to the example of Frida reading a configuration file.
* **Data Exchange:** TOML could be used to represent data exchanged between components or stored in memory. Frida scripts could use this library to parse such data during runtime inspection.

**5. Identifying Low-Level, Kernel, and Framework Connections (and Recognizing Limitations):**

This requires careful consideration of what TOML is and what the library does.

* **TOML's Abstraction:** TOML is a high-level data format. This `tomlkit` library works at the TOML level, not directly at the binary level or within the OS kernel.
* **Indirect Connections:** The connection to low-level details is *indirect*. The *data* represented in TOML could describe low-level configurations (e.g., memory addresses, hardware settings). The *library* itself doesn't directly interact with the kernel.
* **Operating System Agnostic Nature of TOML:** TOML is designed to be cross-platform. Therefore, the library itself isn't inherently tied to Linux or Android kernels. However, TOML files are used in these environments, hence the connection.

**6. Developing Logic Examples (Input/Output):**

For each function, especially the creation functions, I considered simple examples to illustrate their usage. This involved:

* **Choosing appropriate input types:** Strings, numbers, booleans, lists, dictionaries.
* **Predicting the output type:**  Instances of the specific TOML item classes.
* **Demonstrating how these items can be used within a `TOMLDocument`.**

**7. Identifying Potential User Errors:**

This involves thinking about how a programmer might misuse the library:

* **Incorrect input types:** Providing a string when an integer is expected, or vice versa.
* **Invalid TOML syntax:** Passing strings that don't conform to the TOML specification.
* **Misunderstanding the purpose of different string types (literal, multiline).**
* **Forgetting to handle exceptions.**

**8. Tracing User Operations to Reach the Code:**

This requires outlining the steps a user would take to utilize this library:

* **Installation:** Using `pip install tomlkit`.
* **Importing:** `import tomlkit`.
* **Using the functions:**  Providing concrete examples of calling `loads`, `dumps`, `load`, `dump`, and the item creation functions.

**9. Structuring the Explanation:**

Finally, I organized the information into logical sections:

* **Overall Functionality:** A high-level summary.
* **Detailed Function Breakdown:**  Explaining each function with its purpose, arguments, and return value.
* **Connections to Reverse Engineering:**  Illustrating the use cases in that context.
* **Low-Level/Kernel Connections:** Explaining the indirect relationship.
* **Logic Examples:** Providing input/output scenarios.
* **Common User Errors:**  Highlighting potential pitfalls.
* **Debugging Clues (How to Reach the Code):**  Outlining the user interaction steps.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This library directly interacts with the file system."  **Correction:** While `load` and `dump` interact with files, the core parsing logic works on strings/bytes.
* **Initial thought:** "This is heavily involved in kernel operations." **Correction:**  TOML is an application-level format. The connection to the kernel is through the data *represented* in TOML, not the parsing library itself.
* **Ensuring clarity:** Using clear and concise language, providing code examples, and avoiding overly technical jargon where possible.

By following these steps, I aimed to provide a comprehensive and insightful explanation of the `api.py` file within the specified context.
这是一个名为 `api.py` 的 Python 源代码文件，属于 `frida` 动态仪器工具的 `tomlkit` 子项目。`tomlkit` 看起来是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 格式文件的库。

**核心功能列举:**

这个 `api.py` 文件定义了 `tomlkit` 库的公共 API，提供了以下主要功能：

1. **加载 TOML 数据:**
   - `loads(string)`: 将 TOML 格式的字符串或字节串解析成 `TOMLDocument` 对象。
   - `load(fp)`: 从文件类对象中读取 TOML 数据并解析成 `TOMLDocument` 对象。
   - `parse(string)`:  与 `loads` 功能相同，将字符串或字节串解析为 `TOMLDocument`。

2. **导出 TOML 数据:**
   - `dumps(data, sort_keys=False)`: 将 `TOMLDocument` 对象或 Python 字典等映射类型数据转换为 TOML 格式的字符串。可以控制是否对键进行排序。
   - `dump(data, fp, *, sort_keys=False)`: 将 `TOMLDocument` 对象或 Python 字典等映射类型数据写入到可写的文件流中，以 TOML 格式保存。同样可以控制键的排序。

3. **创建 TOML 数据结构 (Items):**
   - `document()`: 创建一个新的空的 `TOMLDocument` 对象。
   - `integer(raw)`:  从数字或字符串创建 TOML 整数项。
   - `float_(raw)`: 从数字或字符串创建 TOML 浮点数项。
   - `boolean(raw)`: 从字符串 `"true"` 或 `"false"` 创建 TOML 布尔值项。
   - `string(raw, *, literal=False, multiline=False, escape=True)`: 创建 TOML 字符串项。可以指定是否为字面量字符串、多行字符串，以及是否需要转义。
   - `date(raw)`: 从字符串创建 TOML 日期项。
   - `time(raw)`: 从字符串创建 TOML 时间项。
   - `datetime(raw)`: 从字符串创建 TOML 日期时间项。
   - `array(raw=None)`: 创建 TOML 数组项。可以从字符串创建，也可以创建空数组后添加元素。
   - `table(is_super_table=None)`: 创建一个空的 TOML 表 (Section)。`is_super_table` 用于指示是否为内联表。
   - `inline_table()`: 创建一个 TOML 内联表。
   - `aot()`: 创建一个 TOML 表数组 (Array of Tables)。
   - `key(k)`: 创建 TOML 键。可以是单个键，也可以是点号分隔的键路径。
   - `value(raw)`: 从字符串解析简单的 TOML 值。
   - `key_value(src)`: 从字符串解析键值对。
   - `ws(src)`: 创建 TOML 空白符项。
   - `nl()`: 创建 TOML 换行符项。
   - `comment(string)`: 创建 TOML 注释项。

4. **自定义编码器:**
   - `register_encoder(encoder)`: 注册一个自定义的编码器函数，用于处理不能直接转换为 TOML 类型的 Python 对象。
   - `unregister_encoder(encoder)`: 注销已注册的自定义编码器。

**与逆向方法的关联及举例说明:**

TOML 格式常用于配置文件，在逆向工程中，分析目标程序的配置文件可以获取重要的信息，例如：

* **程序行为的配置:**  了解程序的功能模块、运行参数、网络设置等。
* **数据存储位置:**  获取数据库连接信息、文件路径等。
* **内部数据结构:**  配置文件可能反映了程序内部的一些数据组织方式。

`tomlkit` 这样的库在 Frida 中就可以用于解析目标程序的 TOML 配置文件。

**举例说明:**

假设目标 Android 应用的配置文件为 `config.toml`，内容如下：

```toml
api_url = "https://api.example.com/v1"
debug_mode = true
data_paths = ["/sdcard/app_data", "/data/local/tmp"]

[database]
host = "localhost"
port = 5432
```

Frida 脚本可以使用 `tomlkit` 来解析这个文件，并根据配置信息来动态地修改程序的行为。

```python
import frida
import tomlkit
import os

# 假设我们已经附加到目标进程
session = frida.attach("com.example.app")

# 模拟从文件中读取配置 (在实际场景中，你可能需要找到配置文件在设备上的路径并读取)
config_content = """
api_url = "https://api.example.com/v1"
debug_mode = true
data_paths = ["/sdcard/app_data", "/data/local/tmp"]

[database]
host = "localhost"
port = 5432
"""

config = tomlkit.loads(config_content)

# 获取 API URL 并打印
api_url = config.get("api_url")
print(f"API URL: {api_url}")

# 检查是否开启了调试模式
debug_mode = config.get("debug_mode")
if debug_mode:
    print("调试模式已开启")

# 获取数据路径
data_paths = config.get("data_paths")
print(f"数据路径: {data_paths}")

# 获取数据库配置
database_config = config.get("database")
if database_config:
    db_host = database_config.get("host")
    db_port = database_config.get("port")
    print(f"数据库主机: {db_host}, 端口: {db_port}")

# 可以根据配置信息，使用 Frida 修改程序行为，例如 Hook 网络请求，修改数据路径等。
```

在这个例子中，`tomlkit.loads()` 函数被用来解析 TOML 配置文件，然后我们可以通过访问 `config` 字典来获取配置信息。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然 `tomlkit` 本身是一个纯 Python 库，专注于 TOML 格式的解析和生成，但它在 Frida 的上下文中，可以用于处理与底层系统和框架相关的信息。

**举例说明:**

1. **解析系统配置文件:**  在 Android 逆向中，我们可能需要解析系统级别的配置文件，例如 `build.prop` 或某些服务进程的配置文件，这些文件可能采用类 TOML 的格式 (虽然不一定是严格的 TOML)。`tomlkit` 可以作为解析工具的一部分。

2. **处理 Native 代码配置:**  一些 Android 应用的 Native (C/C++) 代码可能使用 TOML 格式的配置文件。Frida 可以注入到应用进程中，读取这些配置文件，并使用 `tomlkit` 进行解析，从而了解 Native 代码的行为。

3. **框架层面的配置:**  某些 Android 框架或库可能使用 TOML 作为其配置方式。通过 Frida 拦截对这些配置文件的访问，并使用 `tomlkit` 解析，可以了解框架的运行方式和配置。

**需要注意的是，`tomlkit` 本身不直接操作二进制数据或与内核交互。它的作用是解析文本格式的配置文件。**  在 Frida 的场景下，它通常与 Frida 的 API 结合使用，例如 `Memory.readByteArray()` 读取内存中的配置数据，然后用 `tomlkit` 解析。

**逻辑推理的假设输入与输出:**

假设我们有以下 TOML 字符串：

**假设输入:**

```toml
title = "TOML Example"
owner = { name = "Tom Preston-Werner", dob = 1979-05-27T07:32:00-08:00 }

[database]
server = "192.168.1.1"
ports = [ 8001, 8001, 8002 ]
connection_max = 5000
enabled = true

[servers.alpha]
ip = "10.0.0.1"
dc = "eqdc10"

[servers.beta]
ip = "10.0.0.2"
dc = "eqdc10"
```

如果我们使用 `tomlkit.loads()` 解析它，则 **假设输出** 将是一个 `TOMLDocument` 对象，该对象可以像 Python 字典一样访问：

```python
import tomlkit

toml_string = """
title = "TOML Example"
owner = { name = "Tom Preston-Werner", dob = 1979-05-27T07:32:00-08:00 }

[database]
server = "192.168.1.1"
ports = [ 8001, 8001, 8002 ]
connection_max = 5000
enabled = true

[servers.alpha]
ip = "10.0.0.1"
dc = "eqdc10"

[servers.beta]
ip = "10.0.0.2"
dc = "eqdc10"
"""

data = tomlkit.loads(toml_string)

print(data["title"])  # 输出: TOML Example
print(data["owner"]["name"]) # 输出: Tom Preston-Werner
print(data["database"]["ports"]) # 输出: [8001, 8001, 8002]
print(data["servers"]["alpha"]["ip"]) # 输出: 10.0.0.1
```

**用户或编程常见的使用错误及举例说明:**

1. **尝试解析非 TOML 格式的字符串:**

   ```python
   import tomlkit

   invalid_toml = "this is not toml"
   try:
       data = tomlkit.loads(invalid_toml)
   except tomlkit.exceptions.ParseError as e:
       print(f"解析错误: {e}")
   ```

2. **类型错误的使用:**  例如，尝试将非字符串传递给期望字符串参数的函数。

   ```python
   import tomlkit

   try:
       tomlkit.integer("abc") # 期望传入可以转换为 int 的字符串或数字
   except ValueError as e:
       print(f"值错误: {e}")
   ```

3. **忘记处理文件 I/O 异常:** 当使用 `load` 或 `dump` 操作文件时，可能会发生文件不存在、权限不足等异常。

   ```python
   import tomlkit

   try:
       with open("nonexistent.toml", "r") as f:
           data = tomlkit.load(f)
   except FileNotFoundError as e:
       print(f"文件未找到: {e}")
   ```

4. **不理解不同字符串类型的区别:** 例如，混淆基本字符串和字面量字符串。

   ```python
   import tomlkit

   basic_string = tomlkit.string("C:\\Path\\To\\File") # 反斜杠会被转义
   literal_string = tomlkit.string(r"C:\Path\To\File", literal=True) # 反斜杠不会被转义

   print(basic_string) # 输出: "C:\\\\Path\\\\To\\\\File"
   print(literal_string) # 输出: 'C:\\Path\\To\\File'
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索。**

假设用户正在使用 Frida 脚本来分析一个目标 Android 应用，并且该应用使用 TOML 文件来存储某些配置。以下是用户操作可能如何到达 `api.py` 的：

1. **用户编写 Frida 脚本:** 用户编写一个 Python 脚本，使用 Frida 的 API 来附加到目标 Android 应用的进程。

2. **导入 `tomlkit` 库:**  为了解析应用的 TOML 配置文件，用户需要在脚本中导入 `tomlkit` 库：

   ```python
   import frida
   import tomlkit
   # ... rest of the script
   ```

3. **获取 TOML 配置文件内容:** 用户需要找到目标应用存储配置文件的位置。这可能涉及到：
   - **静态分析:** 分析 APK 包，查找可能的配置文件路径。
   - **动态分析:** 使用 Frida 拦截文件操作相关的系统调用，例如 `open`, `read`，来找到配置文件的路径和内容。
   - **内存搜索:** 如果配置文件内容加载到了内存中，可以使用 Frida 的内存搜索功能来找到它。

4. **使用 `tomlkit` 解析配置:** 一旦获取到 TOML 文件的内容 (通常是字符串或字节串)，用户会调用 `tomlkit.loads()` 或 `tomlkit.parse()` 来解析内容。

   ```python
   config_content = "api_endpoint = 'https://example.com'" # 假设从文件中读取到的内容
   try:
       config = tomlkit.loads(config_content)
       print(config["api_endpoint"])
   except tomlkit.exceptions.ParseError as e:
       print(f"解析 TOML 失败: {e}")
   ```

5. **调试过程中遇到问题:** 如果解析过程中出现错误（例如 TOML 格式不正确），或者用户对解析结果有疑问，他们可能会查看 `tomlkit` 的源代码来了解其工作原理，或者设置断点来调试解析过程。这就是用户可能最终查看 `frida/subprojects/frida-qml/releng/tomlkit/tomlkit/api.py` 文件的原因。

**作为调试线索:**

* **异常信息:** 如果在解析过程中抛出异常，例如 `tomlkit.exceptions.ParseError`，异常信息通常会提供一些关于错误位置的线索，帮助用户定位问题。
* **代码审查:** 用户可以通过阅读 `api.py` 中的代码，了解 `loads`、`parse` 等函数的实现细节，例如它们是如何调用底层的解析器 (`Parser`)，以及如何处理不同的 TOML 元素。
* **断点调试:** 用户可以在 Frida 脚本中设置断点，逐步执行 `tomlkit` 的代码，查看变量的值，从而理解解析过程中的状态变化。例如，可以查看 `Parser` 对象的内部状态，或者查看正在解析的字符。

总而言之，`api.py` 文件是 `tomlkit` 库的入口点，提供了用户与该库交互的主要方式。在 Frida 的上下文中，它使得用户能够方便地解析目标应用的 TOML 配置文件，从而辅助逆向分析和动态 instrumentation。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tomlkit/api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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