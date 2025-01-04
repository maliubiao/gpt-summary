Response:
The user wants me to analyze a Python source code file for the `tomlkit` library, which is part of the `frida-node` project within the `frida` dynamic instrumentation tool.

I need to:
1. **List the functionalities** of the code.
2. **Explain its relation to reverse engineering**, providing examples.
3. **Explain its connection to binary, Linux/Android kernel/framework knowledge**, providing examples.
4. **Illustrate logical reasoning** with input/output examples.
5. **Point out common user/programming errors**, giving examples.
6. **Describe the user path to reach this code**, acting as a debugging clue.
7. **Summarize the functionalities** as part one of a two-part analysis.

**Functionalities:**

The code defines classes and functions for representing and manipulating TOML (Tom's Obvious, Minimal Language) data structures. This includes:
- Representing basic TOML types: booleans, integers, floats, strings, datetimes, dates, and times.
- Representing complex TOML types: arrays and tables (inline and standard).
- Handling metadata associated with TOML items (trivia like whitespace and comments).
- Converting Python objects to TOML items and vice versa.
- Defining different string types (basic, literal, single-line, multi-line) and their escaping rules.
- Representing TOML keys (bare, basic quoted, literal quoted, dotted).

**Relationship to Reverse Engineering:**

TOML files are often used for configuration in software. In reverse engineering, understanding and potentially modifying configuration files can be crucial for:
- **Analyzing application behavior:** Configuration files can reveal settings, paths, API keys, and other parameters that influence how an application runs.
- **Modifying application behavior:** By changing configuration values, a reverse engineer might be able to bypass certain checks, enable debug features, or redirect network traffic.
- **Understanding data structures:** TOML can represent hierarchical data, which can provide insights into how an application stores and organizes information.

**Example:** Imagine reversing an Android application that uses a TOML file to store server URLs. Using Frida, a reverse engineer could:
1. Locate where the application reads the TOML file.
2. Use Frida's file system interception to read the TOML content.
3. Use a TOML parsing library (like `tomlkit`) to analyze the structure and extract the server URLs.
4. Potentially modify the TOML content in memory or on disk to redirect the application to a different server for analysis or manipulation.

**Connection to Binary, Linux/Android Kernel/Framework:**

While this specific Python code doesn't directly interact with the binary level or kernel, the broader context of Frida and its use of TOML for configuration does.

- **Frida's Core:** Frida injects a JavaScript engine into the target process. This engine interacts with the process's memory at a binary level.
- **Configuration of Frida:**  Frida itself might use TOML files to configure its behavior or the scripts it executes.
- **Android Framework:** Android applications often rely on configuration files for various purposes. Understanding how these files are structured (potentially in TOML format) can be important when analyzing or modifying Android application behavior.

**Example:** A Frida script might use a TOML configuration file to specify:
- Which functions to hook in a target process.
- The addresses of specific memory locations to monitor.
- Custom logic to apply based on certain conditions read from the configuration.

**Logical Reasoning:**

The `item()` function demonstrates logical reasoning by determining the appropriate TOML item type based on the Python object's type.

**Assumption:** The input is a Python object.

**Example Input and Output:**

- **Input:** `42` (integer)
  **Output:** `Integer(42, Trivia(), '42')`

- **Input:** `{"name": "Frida", "version": 16.0}` (dictionary)
  **Output:** `Table(Container({'name': String('Frida', Trivia(), '"Frida"'), 'version': Float(16.0, Trivia(), '16.0')}), Trivia(), False)` (The exact representation might vary slightly based on internal sorting)

**Common User/Programming Errors:**

- **Incorrect TOML Syntax:** If a user manually creates or modifies a TOML file with syntax errors, `tomlkit` might fail to parse it.
  **Example:** Missing quotes around a string value or an invalid date format.

- **Type Mismatch:** Trying to convert a Python object to a TOML type that doesn't have a natural representation.
  **Example:** Attempting to use a custom Python class without a registered encoder. The code raises a `_ConvertError` in this case.

- **Misunderstanding Escaping:** Incorrectly handling escape sequences in strings when creating TOML.
  **Example:** Not escaping backslashes in basic strings.

**User Path to Reach This Code (Debugging Clue):**

A user would likely interact with this code indirectly when using Frida to:

1. **Load a script that uses `tomlkit`:** The Frida script itself might parse a TOML configuration file using a library that internally relies on `tomlkit`.
2. **Interact with a target application that uses TOML:** The target application might load its configuration from a TOML file. A Frida script could then use `tomlkit` to parse and analyze this configuration.
3. **Develop tools or scripts that generate TOML:** A developer might use `tomlkit` to create or modify TOML files programmatically as part of their Frida-based tooling.

If a user encounters an error related to TOML parsing or manipulation within a Frida script, and the traceback points to files within the `tomlkit` directory (specifically `items.py`), this indicates that the issue lies within how TOML data is being represented or handled by the library.

**Summary of Functionalities (Part 1):**

This Python code defines the core data structures and logic for representing and manipulating TOML data within the `tomlkit` library. It provides classes for various TOML item types (integers, strings, booleans, dates, arrays, tables, etc.) and functions for converting between Python objects and these TOML representations. The code also handles metadata (trivia) associated with TOML elements.

这是 `frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 文件的功能列表：

1. **定义 TOML 数据类型的 Python 类:**  该文件定义了各种 Python 类来表示 TOML 规范中定义的各种数据类型，例如：
    - `Bool`: 布尔值 (`true`, `false`)
    - `Integer`: 整数
    - `Float`: 浮点数
    - `String`: 字符串 (支持单行、多行、基本和字面量等多种形式)
    - `DateTime`: 日期和时间
    - `Date`: 日期
    - `Time`: 时间
    - `Array`: 数组
    - `Table`: 表 (包括行内表 `InlineTable`)
    - `AoT`: 表格数组 (Array of Tables)
    - `Key`:  键 (支持裸键、基本引号键和字面量引号键，以及点号分隔的键 `DottedKey`)
    - `Trivia`:  存储与 TOML 元素相关的元数据，例如前后的空白、注释和尾随换行符。
    - `Whitespace`: 表示空白字符。
    - `Comment`: 表示注释。

2. **提供将 Python 对象转换为 TOML 项的功能:** `item()` 函数负责将 Python 的基本数据类型（如 `int`, `float`, `str`, `bool`, `dict`, `list`, `datetime`, `date`, `time`）转换为对应的 `tomlkit` 的 `Item` 子类实例。这使得在 Python 代码中可以方便地创建和操作 TOML 数据结构。

3. **处理 TOML 字符串的不同类型和转义:**  `StringType` 枚举类定义了 TOML 字符串的四种类型（单行基本、多行基本、单行字面量、多行字面量），并提供了方法来选择合适的类型，以及管理每种类型允许和禁止的转义序列。

4. **表示和操作 TOML 键:** `Key` 类及其子类 `SingleKey` 和 `DottedKey` 用于表示 TOML 中的键，包括不同类型的引号和点号分隔的键。

5. **管理 TOML 元素的元数据:** `Trivia` 类用于存储与每个 TOML 项相关的空白和注释信息，这对于保持 TOML 文件的格式和可读性非常重要。

6. **实现 TOML 项的基本操作:** `Item` 类是所有 TOML 项类的基类，定义了一些通用方法，例如 `as_string()` (将 TOML 项转换为其 TOML 字符串表示形式), `comment()` (添加注释), `indent()` (添加缩进) 和 `unwrap()` (返回原始的 Python 对象值)。

7. **支持自定义类型编码:** 通过 `CUSTOM_ENCODERS` 列表，用户可以注册自定义的编码器，以便将特定的 Python 对象类型转换为 `tomlkit` 的 `Item`。

**与逆向的方法的关系及举例说明:**

在逆向工程中，配置文件经常采用 TOML 格式。`tomlkit` 提供的功能可以帮助逆向工程师：

* **解析和分析应用程序的配置文件:** 很多应用程序使用 TOML 文件存储配置信息，例如服务器地址、API 密钥、功能开关等。使用 `tomlkit` 可以方便地读取和解析这些配置信息，从而了解应用程序的运行方式。
    * **举例:** 假设一个 Android 应用在 `/data/data/<package_name>/config.toml` 文件中存储了服务器地址。逆向工程师可以使用 Frida 找到读取该文件的代码，然后使用 `tomlkit` 解析文件内容，提取出服务器地址。

* **修改应用程序的配置:**  逆向工程师可能需要修改应用程序的配置文件来改变其行为。`tomlkit` 可以用来修改 TOML 文件的内容，然后将修改后的内容写回文件或者注入到应用程序的内存中。
    * **举例:**  继续上面的例子，逆向工程师可以使用 `tomlkit` 修改 `config.toml` 中的服务器地址，将其指向一个由逆向工程师控制的服务器，以便监控应用程序的网络请求。

* **理解应用程序的数据结构:** TOML 可以用来表示复杂的数据结构，`tomlkit` 可以帮助逆向工程师理解应用程序如何组织和存储数据。
    * **举例:** 某个 Linux 守护进程的配置文件使用 TOML 格式定义了多个模块的配置参数，每个模块都有自己的子表和数组。使用 `tomlkit` 可以将这个配置文件解析成 Python 的字典和列表，方便分析每个模块的配置。

**涉及到二进制底层，linux, android内核及框架的知识及举例说明:**

虽然 `items.py` 本身是 Python 代码，没有直接涉及到二进制底层或内核，但 `frida` 工具作为一个动态插桩框架，其核心功能是与目标进程的二进制代码进行交互的。`tomlkit` 作为 `frida` 项目的一部分，在以下方面间接关联到这些底层知识：

* **Frida 的脚本配置:** Frida 脚本本身或者 Frida 工具的配置可能使用 TOML 文件。例如，一个 Frida 脚本可能使用 TOML 文件来指定需要 hook 的函数名称、内存地址等。
    * **举例:** 一个 Frida 脚本的配置文件 `hook_config.toml` 可能包含需要 hook 的函数的名称和地址：
    ```toml
    [functions]
    "com.example.app.MainActivity.onCreate" = "0x12345678"
    "com.example.app.MyClass.myMethod" = "0x87654321"
    ```
    Frida 脚本可以使用 `tomlkit` 解析这个文件，然后根据配置信息进行 hook 操作。

* **目标进程的配置分析:**  逆向分析的 Android 或 Linux 应用程序可能使用 TOML 文件作为配置文件。`tomlkit` 可以帮助 Frida 脚本解析这些配置文件，从而了解目标进程的运行参数和行为。
    * **举例:**  一个 Android 应用的 Native 层可能读取一个 TOML 配置文件来初始化一些底层库。Frida 可以 hook 文件读取函数，使用 `tomlkit` 解析读取到的 TOML 内容，从而了解 Native 层的配置。

**如果做了逻辑推理，请给出假设输入与输出:**

`item()` 函数中存在逻辑推理，根据输入值的类型来创建不同的 `Item` 对象。

**假设输入与输出示例:**

* **假设输入:** `value = True`
   **输出:** `Bool(True, Trivia())`

* **假设输入:** `value = 123`
   **输出:** `Integer(123, Trivia(), '123')`

* **假设输入:** `value = "hello"`
   **输出:** `String('hello', Trivia(), '"hello"')`

* **假设输入:** `value = [1, 2, 3]`
   **输出:** `Array([Integer(1, Trivia(), '1'), Integer(2, Trivia(), '2'), Integer(3, Trivia(), '3')], Trivia(), False)`

* **假设输入:** `value = {"name": "Frida", "version": 16.0}`
   **输出:** `Table(Container({'name': String('Frida', Trivia(), '"Frida"'), 'version': Float(16.0, Trivia(), '16.0')}), Trivia(), False)` (输出的具体顺序可能因为字典的无序性而略有不同)

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **尝试将不支持的 Python 类型转换为 TOML 项:** `item()` 函数对于不能转换为 TOML 规范中类型的 Python 对象会抛出 `_ConvertError`。
   * **举例:**  如果尝试 `item(object())`，会抛出 `_ConvertError: Invalid type <class 'object'>`。

2. **自定义编码器返回非 Item 子类的对象:**  如果注册了自定义的编码器，但编码器返回的对象不是 `Item` 的子类，则会抛出 `_ConvertError`。
   * **举例:**  如果一个自定义编码器将一个 Python 集合编码为一个普通的 Python 列表，而不是 `Array` 对象，就会报错。

3. **误用字符串类型:**  用户可能不理解 TOML 字符串的不同类型及其转义规则，导致创建的 TOML 文件不符合规范。
    * **举例:**  在基本字符串中没有正确转义反斜杠，例如 `String('C:\path\to\file')`，应该写成 `String('C:\\path\\to\\file')`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

一个用户通常不会直接操作 `items.py` 文件，而是通过使用 `tomlkit` 库的功能来间接调用其中的代码。以下是一些可能的操作路径，最终可能因为错误而导致调试到这个文件：

1. **使用 `tomlkit.loads()` 解析 TOML 字符串:** 用户可能在 Frida 脚本中使用 `tomlkit.loads()` 函数来解析一个包含 TOML 格式配置信息的字符串。如果该字符串格式错误，`tomlkit` 的解析过程可能会在创建 `Item` 对象时出错，从而导致在这个文件中抛出异常。

2. **使用 `tomlkit.dumps()` 生成 TOML 字符串:** 用户可能在 Frida 脚本中使用 `tomlkit.dumps()` 函数将 Python 数据结构转换为 TOML 格式的字符串。如果用户提供的数据结构中包含了无法转换为有效 TOML 类型的对象，`item()` 函数会抛出异常。

3. **自定义类型编码时出错:**  用户可能实现了自定义的编码器并将其添加到 `CUSTOM_ENCODERS` 中。如果这个编码器存在错误，例如返回了非 `Item` 子类的对象，当 `item()` 函数尝试使用这个编码器时就会报错。

4. **在 Frida 脚本中使用依赖 `tomlkit` 的第三方库:** 用户可能使用的某个第三方库内部使用了 `tomlkit` 来处理 TOML 数据。该库的错误使用或者 TOML 数据的错误格式可能会导致 `tomlkit` 内部的错误，最终指向 `items.py`。

当调试信息或错误堆栈指向 `frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 时，这通常意味着问题出在 TOML 数据的表示、转换或者解析过程中。用户需要检查提供的 TOML 数据是否符合规范，以及是否正确地使用了 `tomlkit` 的 API。

**归纳一下它的功能 (第 1 部分):**

总而言之，`frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 文件的主要功能是定义了 `tomlkit` 库用于表示和操作 TOML 数据结构的核心类和函数。它负责将 Python 数据类型映射到 TOML 的概念，处理不同类型的 TOML 数据，并提供基本的 TOML 数据操作功能，例如创建、转换和格式化。这个文件是 `tomlkit` 库的基础，为上层 API 提供了底层的实现支持。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
from __future__ import annotations

import abc
import copy
import dataclasses
import math
import re
import string
import sys

from datetime import date
from datetime import datetime
from datetime import time
from datetime import tzinfo
from enum import Enum
from typing import TYPE_CHECKING
from typing import Any
from typing import Callable
from typing import Collection
from typing import Iterable
from typing import Iterator
from typing import Sequence
from typing import TypeVar
from typing import cast
from typing import overload

from tomlkit._compat import PY38
from tomlkit._compat import decode
from tomlkit._types import _CustomDict
from tomlkit._types import _CustomFloat
from tomlkit._types import _CustomInt
from tomlkit._types import _CustomList
from tomlkit._types import wrap_method
from tomlkit._utils import CONTROL_CHARS
from tomlkit._utils import escape_string
from tomlkit.exceptions import InvalidStringError


if TYPE_CHECKING:
    from tomlkit import container


ItemT = TypeVar("ItemT", bound="Item")
Encoder = Callable[[Any], "Item"]
CUSTOM_ENCODERS: list[Encoder] = []
AT = TypeVar("AT", bound="AbstractTable")


class _ConvertError(TypeError, ValueError):
    """An internal error raised when item() fails to convert a value.
    It should be a TypeError, but due to historical reasons
    it needs to subclass ValueError as well.
    """


@overload
def item(value: bool, _parent: Item | None = ..., _sort_keys: bool = ...) -> Bool:
    ...


@overload
def item(value: int, _parent: Item | None = ..., _sort_keys: bool = ...) -> Integer:
    ...


@overload
def item(value: float, _parent: Item | None = ..., _sort_keys: bool = ...) -> Float:
    ...


@overload
def item(value: str, _parent: Item | None = ..., _sort_keys: bool = ...) -> String:
    ...


@overload
def item(
    value: datetime, _parent: Item | None = ..., _sort_keys: bool = ...
) -> DateTime:
    ...


@overload
def item(value: date, _parent: Item | None = ..., _sort_keys: bool = ...) -> Date:
    ...


@overload
def item(value: time, _parent: Item | None = ..., _sort_keys: bool = ...) -> Time:
    ...


@overload
def item(
    value: Sequence[dict], _parent: Item | None = ..., _sort_keys: bool = ...
) -> AoT:
    ...


@overload
def item(value: Sequence, _parent: Item | None = ..., _sort_keys: bool = ...) -> Array:
    ...


@overload
def item(value: dict, _parent: Array = ..., _sort_keys: bool = ...) -> InlineTable:
    ...


@overload
def item(value: dict, _parent: Item | None = ..., _sort_keys: bool = ...) -> Table:
    ...


@overload
def item(value: ItemT, _parent: Item | None = ..., _sort_keys: bool = ...) -> ItemT:
    ...


def item(value: Any, _parent: Item | None = None, _sort_keys: bool = False) -> Item:
    """Create a TOML item from a Python object.

    :Example:

    >>> item(42)
    42
    >>> item([1, 2, 3])
    [1, 2, 3]
    >>> item({'a': 1, 'b': 2})
    a = 1
    b = 2
    """

    from tomlkit.container import Container

    if isinstance(value, Item):
        return value

    if isinstance(value, bool):
        return Bool(value, Trivia())
    elif isinstance(value, int):
        return Integer(value, Trivia(), str(value))
    elif isinstance(value, float):
        return Float(value, Trivia(), str(value))
    elif isinstance(value, dict):
        table_constructor = (
            InlineTable if isinstance(_parent, (Array, InlineTable)) else Table
        )
        val = table_constructor(Container(), Trivia(), False)
        for k, v in sorted(
            value.items(),
            key=lambda i: (isinstance(i[1], dict), i[0]) if _sort_keys else 1,
        ):
            val[k] = item(v, _parent=val, _sort_keys=_sort_keys)

        return val
    elif isinstance(value, (list, tuple)):
        if (
            value
            and all(isinstance(v, dict) for v in value)
            and (_parent is None or isinstance(_parent, Table))
        ):
            a = AoT([])
            table_constructor = Table
        else:
            a = Array([], Trivia())
            table_constructor = InlineTable

        for v in value:
            if isinstance(v, dict):
                table = table_constructor(Container(), Trivia(), True)

                for k, _v in sorted(
                    v.items(),
                    key=lambda i: (isinstance(i[1], dict), i[0] if _sort_keys else 1),
                ):
                    i = item(_v, _parent=table, _sort_keys=_sort_keys)
                    if isinstance(table, InlineTable):
                        i.trivia.trail = ""

                    table[k] = i

                v = table

            a.append(v)

        return a
    elif isinstance(value, str):
        return String.from_raw(value)
    elif isinstance(value, datetime):
        return DateTime(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            value.tzinfo,
            Trivia(),
            value.isoformat().replace("+00:00", "Z"),
        )
    elif isinstance(value, date):
        return Date(value.year, value.month, value.day, Trivia(), value.isoformat())
    elif isinstance(value, time):
        return Time(
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            value.tzinfo,
            Trivia(),
            value.isoformat(),
        )
    else:
        for encoder in CUSTOM_ENCODERS:
            try:
                rv = encoder(value)
            except TypeError:
                pass
            else:
                if not isinstance(rv, Item):
                    raise _ConvertError(
                        f"Custom encoder returned {type(rv)}, not a subclass of Item"
                    )
                return rv

    raise _ConvertError(f"Invalid type {type(value)}")


class StringType(Enum):
    # Single Line Basic
    SLB = '"'
    # Multi Line Basic
    MLB = '"""'
    # Single Line Literal
    SLL = "'"
    # Multi Line Literal
    MLL = "'''"

    @classmethod
    def select(cls, literal=False, multiline=False) -> StringType:
        return {
            (False, False): cls.SLB,
            (False, True): cls.MLB,
            (True, False): cls.SLL,
            (True, True): cls.MLL,
        }[(literal, multiline)]

    @property
    def escaped_sequences(self) -> Collection[str]:
        # https://toml.io/en/v1.0.0#string
        escaped_in_basic = CONTROL_CHARS | {"\\"}
        allowed_in_multiline = {"\n", "\r"}
        return {
            StringType.SLB: escaped_in_basic | {'"'},
            StringType.MLB: (escaped_in_basic | {'"""'}) - allowed_in_multiline,
            StringType.SLL: (),
            StringType.MLL: (),
        }[self]

    @property
    def invalid_sequences(self) -> Collection[str]:
        # https://toml.io/en/v1.0.0#string
        forbidden_in_literal = CONTROL_CHARS - {"\t"}
        allowed_in_multiline = {"\n", "\r"}
        return {
            StringType.SLB: (),
            StringType.MLB: (),
            StringType.SLL: forbidden_in_literal | {"'"},
            StringType.MLL: (forbidden_in_literal | {"'''"}) - allowed_in_multiline,
        }[self]

    @property
    def unit(self) -> str:
        return self.value[0]

    def is_basic(self) -> bool:
        return self in {StringType.SLB, StringType.MLB}

    def is_literal(self) -> bool:
        return self in {StringType.SLL, StringType.MLL}

    def is_singleline(self) -> bool:
        return self in {StringType.SLB, StringType.SLL}

    def is_multiline(self) -> bool:
        return self in {StringType.MLB, StringType.MLL}

    def toggle(self) -> StringType:
        return {
            StringType.SLB: StringType.MLB,
            StringType.MLB: StringType.SLB,
            StringType.SLL: StringType.MLL,
            StringType.MLL: StringType.SLL,
        }[self]


class BoolType(Enum):
    TRUE = "true"
    FALSE = "false"

    def __bool__(self):
        return {BoolType.TRUE: True, BoolType.FALSE: False}[self]

    def __iter__(self):
        return iter(self.value)

    def __len__(self):
        return len(self.value)


@dataclasses.dataclass
class Trivia:
    """
    Trivia information (aka metadata).
    """

    # Whitespace before a value.
    indent: str = ""
    # Whitespace after a value, but before a comment.
    comment_ws: str = ""
    # Comment, starting with # character, or empty string if no comment.
    comment: str = ""
    # Trailing newline.
    trail: str = "\n"

    def copy(self) -> Trivia:
        return dataclasses.replace(self)


class KeyType(Enum):
    """
    The type of a Key.

    Keys can be bare (unquoted), or quoted using basic ("), or literal (')
    quotes following the same escaping rules as single-line StringType.
    """

    Bare = ""
    Basic = '"'
    Literal = "'"


class Key(abc.ABC):
    """Base class for a key"""

    sep: str
    _original: str
    _keys: list[SingleKey]
    _dotted: bool
    key: str

    @abc.abstractmethod
    def __hash__(self) -> int:
        pass

    @abc.abstractmethod
    def __eq__(self, __o: object) -> bool:
        pass

    def is_dotted(self) -> bool:
        """If the key is followed by other keys"""
        return self._dotted

    def __iter__(self) -> Iterator[SingleKey]:
        return iter(self._keys)

    def concat(self, other: Key) -> DottedKey:
        """Concatenate keys into a dotted key"""
        keys = self._keys + other._keys
        return DottedKey(keys, sep=self.sep)

    def is_multi(self) -> bool:
        """Check if the key contains multiple keys"""
        return len(self._keys) > 1

    def as_string(self) -> str:
        """The TOML representation"""
        return self._original

    def __str__(self) -> str:
        return self.as_string()

    def __repr__(self) -> str:
        return f"<Key {self.as_string()}>"


class SingleKey(Key):
    """A single key"""

    def __init__(
        self,
        k: str,
        t: KeyType | None = None,
        sep: str | None = None,
        original: str | None = None,
    ) -> None:
        if t is None:
            if not k or any(
                c not in string.ascii_letters + string.digits + "-" + "_" for c in k
            ):
                t = KeyType.Basic
            else:
                t = KeyType.Bare

        self.t = t
        if sep is None:
            sep = " = "

        self.sep = sep
        self.key = k
        if original is None:
            key_str = escape_string(k) if t == KeyType.Basic else k
            original = f"{t.value}{key_str}{t.value}"

        self._original = original
        self._keys = [self]
        self._dotted = False

    @property
    def delimiter(self) -> str:
        """The delimiter: double quote/single quote/none"""
        return self.t.value

    def is_bare(self) -> bool:
        """Check if the key is bare"""
        return self.t == KeyType.Bare

    def __hash__(self) -> int:
        return hash(self.key)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Key):
            return isinstance(other, SingleKey) and self.key == other.key

        return self.key == other


class DottedKey(Key):
    def __init__(
        self,
        keys: Iterable[SingleKey],
        sep: str | None = None,
        original: str | None = None,
    ) -> None:
        self._keys = list(keys)
        if original is None:
            original = ".".join(k.as_string() for k in self._keys)

        self.sep = " = " if sep is None else sep
        self._original = original
        self._dotted = False
        self.key = ".".join(k.key for k in self._keys)

    def __hash__(self) -> int:
        return hash(tuple(self._keys))

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, DottedKey) and self._keys == __o._keys


class Item:
    """
    An item within a TOML document.
    """

    def __init__(self, trivia: Trivia) -> None:
        self._trivia = trivia

    @property
    def trivia(self) -> Trivia:
        """The trivia element associated with this item"""
        return self._trivia

    @property
    def discriminant(self) -> int:
        raise NotImplementedError()

    def as_string(self) -> str:
        """The TOML representation"""
        raise NotImplementedError()

    @property
    def value(self) -> Any:
        return self

    def unwrap(self) -> Any:
        """Returns as pure python object (ppo)"""
        raise NotImplementedError()

    # Helpers

    def comment(self, comment: str) -> Item:
        """Attach a comment to this item"""
        if not comment.strip().startswith("#"):
            comment = "# " + comment

        self._trivia.comment_ws = " "
        self._trivia.comment = comment

        return self

    def indent(self, indent: int) -> Item:
        """Indent this item with given number of spaces"""
        if self._trivia.indent.startswith("\n"):
            self._trivia.indent = "\n" + " " * indent
        else:
            self._trivia.indent = " " * indent

        return self

    def is_boolean(self) -> bool:
        return isinstance(self, Bool)

    def is_table(self) -> bool:
        return isinstance(self, Table)

    def is_inline_table(self) -> bool:
        return isinstance(self, InlineTable)

    def is_aot(self) -> bool:
        return isinstance(self, AoT)

    def _getstate(self, protocol=3):
        return (self._trivia,)

    def __reduce__(self):
        return self.__reduce_ex__(2)

    def __reduce_ex__(self, protocol):
        return self.__class__, self._getstate(protocol)


class Whitespace(Item):
    """
    A whitespace literal.
    """

    def __init__(self, s: str, fixed: bool = False) -> None:
        self._s = s
        self._fixed = fixed

    @property
    def s(self) -> str:
        return self._s

    @property
    def value(self) -> str:
        """The wrapped string of the whitespace"""
        return self._s

    @property
    def trivia(self) -> Trivia:
        raise RuntimeError("Called trivia on a Whitespace variant.")

    @property
    def discriminant(self) -> int:
        return 0

    def is_fixed(self) -> bool:
        """If the whitespace is fixed, it can't be merged or discarded from the output."""
        return self._fixed

    def as_string(self) -> str:
        return self._s

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {repr(self._s)}>"

    def _getstate(self, protocol=3):
        return self._s, self._fixed


class Comment(Item):
    """
    A comment literal.
    """

    @property
    def discriminant(self) -> int:
        return 1

    def as_string(self) -> str:
        return (
            f"{self._trivia.indent}{decode(self._trivia.comment)}{self._trivia.trail}"
        )

    def __str__(self) -> str:
        return f"{self._trivia.indent}{decode(self._trivia.comment)}"


class Integer(Item, _CustomInt):
    """
    An integer literal.
    """

    def __new__(cls, value: int, trivia: Trivia, raw: str) -> Integer:
        return int.__new__(cls, value)

    def __init__(self, value: int, trivia: Trivia, raw: str) -> None:
        super().__init__(trivia)
        self._original = value
        self._raw = raw
        self._sign = False

        if re.match(r"^[+\-]\d+$", raw):
            self._sign = True

    def unwrap(self) -> int:
        return self._original

    __int__ = unwrap

    def __hash__(self) -> int:
        return hash(self.unwrap())

    @property
    def discriminant(self) -> int:
        return 2

    @property
    def value(self) -> int:
        """The wrapped integer value"""
        return self

    def as_string(self) -> str:
        return self._raw

    def _new(self, result):
        raw = str(result)
        if self._sign:
            sign = "+" if result >= 0 else "-"
            raw = sign + raw

        return Integer(result, self._trivia, raw)

    def _getstate(self, protocol=3):
        return int(self), self._trivia, self._raw

    # int methods
    __abs__ = wrap_method(int.__abs__)
    __add__ = wrap_method(int.__add__)
    __and__ = wrap_method(int.__and__)
    __ceil__ = wrap_method(int.__ceil__)
    __eq__ = int.__eq__
    __floor__ = wrap_method(int.__floor__)
    __floordiv__ = wrap_method(int.__floordiv__)
    __invert__ = wrap_method(int.__invert__)
    __le__ = int.__le__
    __lshift__ = wrap_method(int.__lshift__)
    __lt__ = int.__lt__
    __mod__ = wrap_method(int.__mod__)
    __mul__ = wrap_method(int.__mul__)
    __neg__ = wrap_method(int.__neg__)
    __or__ = wrap_method(int.__or__)
    __pos__ = wrap_method(int.__pos__)
    __pow__ = wrap_method(int.__pow__)
    __radd__ = wrap_method(int.__radd__)
    __rand__ = wrap_method(int.__rand__)
    __rfloordiv__ = wrap_method(int.__rfloordiv__)
    __rlshift__ = wrap_method(int.__rlshift__)
    __rmod__ = wrap_method(int.__rmod__)
    __rmul__ = wrap_method(int.__rmul__)
    __ror__ = wrap_method(int.__ror__)
    __round__ = wrap_method(int.__round__)
    __rpow__ = wrap_method(int.__rpow__)
    __rrshift__ = wrap_method(int.__rrshift__)
    __rshift__ = wrap_method(int.__rshift__)
    __rxor__ = wrap_method(int.__rxor__)
    __trunc__ = wrap_method(int.__trunc__)
    __xor__ = wrap_method(int.__xor__)

    def __rtruediv__(self, other):
        result = int.__rtruediv__(self, other)
        if result is NotImplemented:
            return result
        return Float._new(self, result)

    def __truediv__(self, other):
        result = int.__truediv__(self, other)
        if result is NotImplemented:
            return result
        return Float._new(self, result)


class Float(Item, _CustomFloat):
    """
    A float literal.
    """

    def __new__(cls, value: float, trivia: Trivia, raw: str) -> Float:
        return float.__new__(cls, value)

    def __init__(self, value: float, trivia: Trivia, raw: str) -> None:
        super().__init__(trivia)
        self._original = value
        self._raw = raw
        self._sign = False

        if re.match(r"^[+\-].+$", raw):
            self._sign = True

    def unwrap(self) -> float:
        return self._original

    __float__ = unwrap

    def __hash__(self) -> int:
        return hash(self.unwrap())

    @property
    def discriminant(self) -> int:
        return 3

    @property
    def value(self) -> float:
        """The wrapped float value"""
        return self

    def as_string(self) -> str:
        return self._raw

    def _new(self, result):
        raw = str(result)

        if self._sign:
            sign = "+" if result >= 0 else "-"
            raw = sign + raw

        return Float(result, self._trivia, raw)

    def _getstate(self, protocol=3):
        return float(self), self._trivia, self._raw

    # float methods
    __abs__ = wrap_method(float.__abs__)
    __add__ = wrap_method(float.__add__)
    __eq__ = float.__eq__
    __floordiv__ = wrap_method(float.__floordiv__)
    __le__ = float.__le__
    __lt__ = float.__lt__
    __mod__ = wrap_method(float.__mod__)
    __mul__ = wrap_method(float.__mul__)
    __neg__ = wrap_method(float.__neg__)
    __pos__ = wrap_method(float.__pos__)
    __pow__ = wrap_method(float.__pow__)
    __radd__ = wrap_method(float.__radd__)
    __rfloordiv__ = wrap_method(float.__rfloordiv__)
    __rmod__ = wrap_method(float.__rmod__)
    __rmul__ = wrap_method(float.__rmul__)
    __round__ = wrap_method(float.__round__)
    __rpow__ = wrap_method(float.__rpow__)
    __rtruediv__ = wrap_method(float.__rtruediv__)
    __truediv__ = wrap_method(float.__truediv__)
    __trunc__ = float.__trunc__

    if sys.version_info >= (3, 9):
        __ceil__ = float.__ceil__
        __floor__ = float.__floor__
    else:
        __ceil__ = math.ceil
        __floor__ = math.floor


class Bool(Item):
    """
    A boolean literal.
    """

    def __init__(self, t: int, trivia: Trivia) -> None:
        super().__init__(trivia)

        self._value = bool(t)

    def unwrap(self) -> bool:
        return bool(self)

    @property
    def discriminant(self) -> int:
        return 4

    @property
    def value(self) -> bool:
        """The wrapped boolean value"""
        return self._value

    def as_string(self) -> str:
        return str(self._value).lower()

    def _getstate(self, protocol=3):
        return self._value, self._trivia

    def __bool__(self):
        return self._value

    __nonzero__ = __bool__

    def __eq__(self, other):
        if not isinstance(other, bool):
            return NotImplemented

        return other == self._value

    def __hash__(self):
        return hash(self._value)

    def __repr__(self):
        return repr(self._value)


class DateTime(Item, datetime):
    """
    A datetime literal.
    """

    def __new__(
        cls,
        year: int,
        month: int,
        day: int,
        hour: int,
        minute: int,
        second: int,
        microsecond: int,
        tzinfo: tzinfo | None,
        *_: Any,
        **kwargs: Any,
    ) -> datetime:
        return datetime.__new__(
            cls,
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tzinfo=tzinfo,
            **kwargs,
        )

    def __init__(
        self,
        year: int,
        month: int,
        day: int,
        hour: int,
        minute: int,
        second: int,
        microsecond: int,
        tzinfo: tzinfo | None,
        trivia: Trivia | None = None,
        raw: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(trivia or Trivia())

        self._raw = raw or self.isoformat()

    def unwrap(self) -> datetime:
        (
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tzinfo,
            _,
            _,
        ) = self._getstate()
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo)

    @property
    def discriminant(self) -> int:
        return 5

    @property
    def value(self) -> datetime:
        return self

    def as_string(self) -> str:
        return self._raw

    def __add__(self, other):
        if PY38:
            result = datetime(
                self.year,
                self.month,
                self.day,
                self.hour,
                self.minute,
                self.second,
                self.microsecond,
                self.tzinfo,
            ).__add__(other)
        else:
            result = super().__add__(other)

        return self._new(result)

    def __sub__(self, other):
        if PY38:
            result = datetime(
                self.year,
                self.month,
                self.day,
                self.hour,
                self.minute,
                self.second,
                self.microsecond,
                self.tzinfo,
            ).__sub__(other)
        else:
            result = super().__sub__(other)

        if isinstance(result, datetime):
            result = self._new(result)

        return result

    def replace(self, *args: Any, **kwargs: Any) -> datetime:
        return self._new(super().replace(*args, **kwargs))

    def astimezone(self, tz: tzinfo) -> datetime:
        result = super().astimezone(tz)
        if PY38:
            return result
        return self._new(result)

    def _new(self, result) -> DateTime:
        raw = result.isoformat()

        return DateTime(
            result.year,
            result.month,
            result.day,
            result.hour,
            result.minute,
            result.second,
            result.microsecond,
            result.tzinfo,
            self._trivia,
            raw,
        )

    def _getstate(self, protocol=3):
        return (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.microsecond,
            self.tzinfo,
            self._trivia,
            self._raw,
        )


class Date(Item, date):
    """
    A date literal.
    """

    def __new__(cls, year: int, month: int, day: int, *_: Any) -> date:
        return date.__new__(cls, year, month, day)

    def __init__(
        self, year: int, month: int, day: int, trivia: Trivia, raw: str
    ) -> None:
        super().__init__(trivia)

        self._raw = raw

    def unwrap(self) -> date:
        (year, month, day, _, _) = self._getstate()
        return date(year, month, day)

    @property
    def discriminant(self) -> int:
        return 6

    @property
    def value(self) -> date:
        return self

    def as_string(self) -> str:
        return self._raw

    def __add__(self, other):
        if PY38:
            result = date(self.year, self.month, self.day).__add__(other)
        else:
            result = super().__add__(other)

        return self._new(result)

    def __sub__(self, other):
        if PY38:
            result = date(self.year, self.month, self.day).__sub__(other)
        else:
            result = super().__sub__(other)

        if isinstance(result, date):
            result = self._new(result)

        return result

    def replace(self, *args: Any, **kwargs: Any) -> date:
        return self._new(super().replace(*args, **kwargs))

    def _new(self, result):
        raw = result.isoformat()

        return Date(result.year, result.month, result.day, self._trivia, raw)

    def _getstate(self, protocol=3):
        return (self.year, self.month, self.day, self._trivia, self._raw)


class Time(Item, time):
    """
    A time literal.
    """

    def __new__(
        cls,
        hour: int,
        minute: int,
        second: int,
        microsecond: int,
        tzinfo: tzinfo | None,
        *_: Any,
    ) -> time:
        return time.__new__(cls, hour, minute, second, microsecond, tzinfo)

    def __init__(
        self,
        hour: int,
        minute: int,
        second: int,
        microsecond: int,
        tzinfo: tzinfo | None,
        trivia: Trivia,
        raw: str,
    ) -> None:
        super().__init__(trivia)

        self._raw = raw

    def unwrap(self) -> time:
        (hour, minute, second, microsecond, tzinfo, _, _) = self._getstate()
        return time(hour, minute, second, microsecond, tzinfo)

    @property
    def discriminant(self) -> int:
        return 7

    @property
    def value(self) -> time:
        return self

    def as_string(self) -> str:
        return self._raw

    def replace(self, *args: Any, **kwargs: Any) -> time:
        return self._new(super().replace(*args, **kwargs))

    def _new(self, result):
        raw = result.isoformat()

        return Time(
            result.hour,
            result.minute,
            result.second,
            result.microsecond,
            result.tzinfo,
            self._trivia,
            raw,
        )

    def _getstate(self, protocol: int = 3) -> tuple:
        return (
            self.hour,
            self.minute,
            self.second,
            self.microsecond,
            self.tzinfo,
            self._trivia,
            self._raw,
        )


class _ArrayItemGroup:
    __slots__ = ("value", "indent", "comma", "comment")

    def __init__(
        self,
        value: Item | None = None,
        indent: Whitespace | None = None,
        comma: Whitespace | None = None,
        comment: Comment | None = None,
    ) -> None:
        self.value = value
        self.indent = indent
        self.comma = comma
        self.comment = comment

    def __iter__(self) -> Iterator[Item]:
        return filter(
            lambda x: x is not None, (self.indent, self.value, self.comma, self.comment)
        )

    def __repr__(self) -> str:
        return repr(tuple(self))

    def is_whitespace(self) -> bool:
        return self.value is None and self.comment is None

    def __bool__(self) -> bool:
        try:
            next(iter(self))
        except StopIteration:
            return False
        return True


class Array(Item, _CustomList):
    """
    An array literal
    """

    def __init__(
        self, value: list[Item], trivia: Trivia, multiline: bool = False
    ) -> None:
        super().__init__(trivia)
        list.__init__(
            self,
            [v for v in value if not isinstance(v, (Whitespace, Comment, Null))],
        )
        self._index_map: dict[int, int] = {}
        self._value = self._group_values(value)
        self._multiline = multiline
        self._reindex()

    def _group_values(self, value: list[Item]) -> list[_ArrayItemGroup]:
        """Group the values into (indent, value, comma, comment) tuples"""
        groups = []
        this_group = _ArrayItemGroup()
        for item in value:
            if isinstance(item, Whitespace):
                if "," not in item.s:
                    groups.append(this_group)
                    this_group = _ArrayItemGroup(indent=item)
                else:
                    if this_group.value is None:
                        # when comma is met and no value is provided, add a dummy Null
                        this_group.value = Null()
                    this_group.comma = item
            elif isinstance(item, Comment):
                if this_group.value is None:
                    this_group.value = Null()
                this_group.comment = item
            elif this_group.value is None:
                this_group.value = item
            else:
                groups.append(this_group)
                this_group = _ArrayItemGroup(value=item)
        groups.append(this_group)
        return [group for group in groups if group]

    def unwrap(self) -> list[Any]:
        unwrapped = []
        for v in self:
            if hasattr(v, "unwrap"):
                unwrapped.append(v.unwrap())
            else:
                unwrapped.append(v)
        return unwrapped

    @property
    def discriminant(self) -> int:
        return 8

    @property
    def value(self) -> list:
        return self

    def _iter_items(self) -> Iterator[Item]:
        for v in self._value:
            yield from v

    def multiline(self, multiline: bool) -> Array:
        """Change the array to display in multiline or not.

        :Example:

        >>> a = item([1, 2, 3])
        >>> print(a.as_string())
        [1, 2, 3]
        >>> print(a.multiline(True).as_string())
        [
            1,
            2,
            3,
        ]
        """
        self._multiline = multiline

        return self

    def as_string(self) -> str:
        if not self._multiline or not self._value:
            return f'[{"".join(v.as_string() for v in self._iter_items())}]'

        s = "[\n"
        s += "".join(
            self.trivia.indent
            + " " * 4
            + v.value.as_string()
            + ("," if not isinstance(v.value, Null) else "")
            + (v.comment.as_string() if v.comment is not None else "")
            + "\n"
            for v in self._value
            if v.value is not None
        )
        s += self.trivia.indent + "]"

        return s

    def _reindex(self) -> None:
        self._index_map.clear()
        index = 0
        for i, v in enumerate(self._value):
            if v.value is None or isinstance(v.value, Null):
                continue
            self._index_map[index] = i
            index += 1

    def add_line(
        self,
        *items: Any,
        indent: str = "    ",
        comment: str | None = None,
        add_comma: bool = True,
        newline: bool = True,
    ) -> None:
        """Add multiple items in a line to control the format precisely.
        When add_comma is True, only accept actual values and
        ", " will be added between values automatically.

        :Example:

        >>> a = array()
        >>> a.add_line(1, 2, 3)
        >>> a.add_line(4, 5, 6)
        >>> a.add_line(indent="")
        >>> print(a.as_string())
        [
            1, 2, 3,
            4, 5, 6,
        ]
        """
        new_values: list[Item] = []
        first_indent = f"\n{indent}" if newline else indent
        if first_indent:
            new_values.append(Whitespace(first_indent))
        whitespace = ""
        data_values = []
        for i, el in enumerate(items):
            it = item(el, _parent=self)
            if isinstance(it, Comment) or add_comma and isinstance(el, Whitespace):
                raise ValueError(f"item type {type(it)} is not allowed in add_line")
            if not isinstance(it, Whitespace):
                if whitespace:
                    new_values.append(Whitespace(whitespace))
                    whitespace = "
"""


```