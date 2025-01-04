Response:
The user is asking for a summary of the functionality of the Python code provided, which is a part of the `tomlkit` library within the `frida` project. I need to analyze the code and identify its key features and how they relate to the broader context of a dynamic instrumentation tool, reverse engineering, and low-level system knowledge.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The file is named `items.py` and is part of the `tomlkit` library. `tomlkit` is designed to parse and generate TOML (Tom's Obvious, Minimal Language) files. Therefore, the primary function is to represent different TOML elements as Python objects.

2. **Analyze the Classes:**  Go through the classes defined in the code and understand what each represents:
    * `Trivia`: Metadata associated with TOML elements (whitespace, comments).
    * `KeyType`, `Key`, `SingleKey`, `DottedKey`: Represent TOML keys, handling both simple and dotted keys with different quoting styles.
    * `Item`: Base class for all TOML items.
    * `Whitespace`, `Comment`: Represent literal whitespace and comments in the TOML structure.
    * `Integer`, `Float`, `Bool`, `String`: Represent basic TOML data types.
    * `DateTime`, `Date`, `Time`: Represent date and time data types.
    * `Array`, `_ArrayItemGroup`: Represent TOML arrays, handling multiline formatting and elements with associated metadata.
    * `Table`, `InlineTable`: Represent TOML tables (sections).
    * `AoT`: Represents Array of Tables.

3. **Analyze the Functions:** Identify the main functions and their roles:
    * `item()`: A factory function to create `Item` instances from Python objects. This is crucial for converting Python data into TOML structures.

4. **Look for Relationships to Reverse Engineering/Dynamic Instrumentation:** Consider how the ability to parse and generate TOML could be relevant in the context of `frida`. TOML is often used for configuration files. Frida might use TOML to define instrumentation settings, hook configurations, or analysis parameters.

5. **Identify Low-Level/Kernel/Framework Connections:** Look for any hints that suggest interaction with lower levels. In this specific file, the focus is on TOML representation, so direct low-level interactions are unlikely to be apparent. However, the *use* of the TOML library within Frida might involve configuring hooks that *do* interact with the kernel or framework.

6. **Analyze Logical Reasoning and Assumptions:**  Examine the `item()` function for how it converts Python types to TOML types. Pay attention to any conditional logic or assumptions made during the conversion. Consider what input types would result in what output TOML structures.

7. **Consider User Errors:** Think about how a user might misuse the `tomlkit` library. This could involve providing invalid Python data types for conversion or expecting the library to handle TOML syntax errors (which are typically handled at the parsing stage).

8. **Trace User Operations (Debugging Context):** Imagine a scenario where a developer is using Frida and encountering issues with a TOML configuration file. How might they end up looking at this specific `items.py` file?  They might be stepping through the `tomlkit` code in a debugger to understand how their configuration is being processed.

9. **Synthesize the Findings into a Summary:**  Organize the identified features and relationships into a concise summary of the file's functionality.

**Self-Correction/Refinement during thought process:**

* **Initial Thought:**  This file directly manipulates binary data or kernel structures.
* **Correction:**  On closer inspection, the file deals with representing TOML data structures in Python. While TOML might *configure* low-level aspects, this file itself is an abstraction layer.

* **Initial Thought:**  The reverse engineering aspect is unclear.
* **Refinement:**  TOML configuration files are common in software, including those being reverse-engineered. Frida using TOML for configuration makes this library relevant to reverse engineering workflows.

* **Initial Thought:**  The user error aspect is limited to incorrect TOML syntax.
* **Refinement:**  User errors could also involve providing Python data types that cannot be directly translated to valid TOML, leading to exceptions within the `item()` function.
这是 `frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py` 文件的功能总结，它主要负责 **定义和实现了 TOML (Tom's Obvious, Minimal Language) 规范中各种数据类型的 Python 对象表示形式**。这些对象不仅存储了数据的值，还包含了与 TOML 格式相关的元数据，例如空白符、注释等。

以下是更详细的功能点：

**核心功能:**

1. **TOML 数据类型的表示:**
   -  定义了 Python 类来表示 TOML 规范中的各种数据类型，例如：
      - `Integer`: 整数
      - `Float`: 浮点数
      - `Bool`: 布尔值
      - `String`: 字符串（支持不同类型的引号和多行）
      - `DateTime`, `Date`, `Time`: 日期和时间
      - `Array`: 数组
      - `Table`: 表（相当于字典）
      - `InlineTable`: 内联表
      - `AoT`: 数组表 (Array of Tables)
   - 每个类都继承自基类 `Item`，提供了一些公共属性和方法。

2. **元数据管理 (`Trivia`):**
   - 使用 `Trivia` 类来存储与每个 TOML 项相关的格式化信息，例如：
      - `indent`: 前导空格
      - `comment_ws`: 注释前的空格
      - `comment`: 注释内容
      - `trail`: 尾部换行符
   - 这允许在解析和生成 TOML 时保留原始格式。

3. **类型转换 (`item()` 函数):**
   - 提供 `item()` 函数，用于将 Python 的基本数据类型（如 `int`, `float`, `str`, `list`, `dict`, `datetime` 等）转换为对应的 `Item` 子类的实例。
   - 这个函数是构建 TOML 文档结构的关键入口。

4. **字符串类型处理 (`StringType`):**
   - 定义了 `StringType` 枚举，用于区分不同类型的 TOML 字符串（单行基本、多行基本、单行字面、多行字面），并提供了方法来选择和判断字符串类型，以及获取其转义和非法字符序列。

5. **键的表示 (`Key`, `SingleKey`, `DottedKey`):**
   - 定义了 `Key` 相关的类来表示 TOML 的键，支持：
      - `SingleKey`: 单个键 (可以是裸键、基本引号或字面引号)
      - `DottedKey`: 点分隔的键 (用于表示嵌套的表)
      - `KeyType`: 枚举，表示键的类型（裸键、基本引号、字面引号）。

6. **数组项分组 (`_ArrayItemGroup`):**
   -  `_ArrayItemGroup` 类用于在 `Array` 中对数组元素及其相关的空白符、逗号和注释进行分组管理，方便格式化输出。

7. **自定义类型编码 (`CUSTOM_ENCODERS`):**
   - 允许注册自定义的编码器函数到 `CUSTOM_ENCODERS` 列表中，以便将自定义的 Python 对象转换为 TOML `Item`。

**与逆向方法的关联 (举例说明):**

假设一个 Android 应用的配置文件使用了 TOML 格式来存储一些配置信息，例如服务器地址、API 密钥等。逆向工程师可以使用 Frida 来 Hook 应用的配置加载过程，获取到表示这些配置信息的 Python 字典或对象。

`tomlkit.items.item()` 函数就可以用于将这些 Python 对象转换回 TOML 的 `Item` 对象，并以 TOML 字符串的形式输出，方便逆向工程师查看和理解原始配置文件的结构和内容。

**示例:**

```python
import frida
import tomlkit

# ... (使用 Frida 连接到目标进程并 Hook 配置加载函数) ...

def on_config_loaded(config_dict):
    """假设 config_dict 是从目标进程中获取的 Python 字典"""
    toml_item = tomlkit.item(config_dict)
    print(tomlkit.dumps(toml_item)) # 将 Item 对象转换为 TOML 字符串并打印

# ... (Frida 脚本其他部分) ...
```

**涉及二进制底层, linux, android内核及框架的知识 (举例说明):**

虽然 `items.py` 本身不直接涉及二进制操作或内核交互，但它所属的 `tomlkit` 库在 Frida 的上下文中被使用时，可以间接地与这些概念关联起来。

例如，一个 Frida 脚本可能会 Hook Android 框架中的某个组件，该组件从一个位于文件系统上的 TOML 配置文件中读取配置。`tomlkit` 负责解析这个 TOML 文件，将其转换为 `Item` 对象，然后 Frida 脚本可以访问这些对象来了解应用的配置。

在这个过程中：

- **文件系统:** TOML 配置文件存储在文件系统中，这是操作系统层面的概念。
- **Android 框架:**  被 Hook 的组件属于 Android 框架，Frida 需要理解 Android 框架的结构和运行机制才能进行 Hook 操作。
- **二进制底层:**  Frida 通过动态修改目标进程的内存来实现 Hook，这涉及对目标进程的二进制代码进行操作。虽然 `items.py` 不直接操作二进制，但它处理的数据来源于对二进制程序的分析结果。

**逻辑推理 (假设输入与输出):**

**假设输入:**

```python
data = {
    "server": {
        "address": "127.0.0.1",
        "port": 8080
    },
    "users": [
        {"name": "Alice", "id": 1},
        {"name": "Bob", "id": 2}
    ]
}
```

**调用:**

```python
toml_item = tomlkit.item(data)
```

**预期输出 (粗略表示，实际是 `Item` 对象):**

一个 `Table` 对象，包含：

- 一个键为 `"server"` 的 `Table` 对象，该表包含键 `"address"` (值为 `String("127.0.0.1")`) 和 `"port"` (值为 `Integer(8080)`)。
- 一个键为 `"users"` 的 `AoT` 对象，该数组包含两个 `Table` 对象，分别表示 Alice 和 Bob 的用户信息。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **尝试将无法转换为有效 TOML 类型的 Python 对象传递给 `item()`:**

   ```python
   class MyObject:
       pass

   my_obj = MyObject()
   try:
       toml_item = tomlkit.item(my_obj)
   except tomlkit.exceptions._ConvertError as e:
       print(f"Error: {e}")
   ```

   **说明:**  `item()` 函数不知道如何将 `MyObject` 转换为 TOML 类型，会抛出 `_ConvertError`。用户需要为自定义类型注册编码器或确保只传递可转换为 TOML 的 Python 类型。

2. **在期望简单值的地方创建了复杂的 `Item` 对象:**

   ```python
   my_table = tomlkit.table()
   my_table["key"] = tomlkit.table() # 期望一个简单值，却赋值了一个 Table 对象
   ```

   **说明:** 虽然这是合法的 TOML 结构，但在某些使用场景下，用户可能错误地假设某个键对应的是一个简单值，而实际赋值了一个更复杂的 `Item` 对象。这可能会导致后续处理逻辑出错。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写了一个 Frida 脚本来分析某个程序，该程序使用了 TOML 配置文件。**
2. **脚本中使用了 `frida-clr` 桥接来与 .NET 程序交互（因为路径中包含 `frida-clr`）。**
3. **为了理解或修改程序的配置，用户希望查看或修改 TOML 配置文件的内容。**
4. **用户可能在 Frida 脚本中使用了 `tomlkit` 库来解析或生成 TOML 文件。**
5. **在调试过程中，用户可能遇到了与 TOML 数据的表示或转换相关的问题，例如：**
   -  Python 对象无法正确转换为 TOML。
   -  生成的 TOML 格式不符合预期。
   -  想要深入了解 `tomlkit` 如何表示不同的 TOML 数据类型。
6. **为了排查问题，用户可能会查看 `tomlkit` 的源代码，最终定位到 `frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py` 文件，查看各种 `Item` 类的定义和 `item()` 函数的实现，以了解 TOML 数据是如何在 `tomlkit` 中被表示和处理的。**
7. **用户可能会设置断点或打印日志来跟踪 `item()` 函数的调用过程，查看哪些 Python 对象被转换成了哪些 `Item` 对象。**

**功能归纳 (第1部分):**

`frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py` 文件的主要功能是 **定义了用于表示 TOML 数据结构的 Python 对象模型**。它提供了各种 `Item` 子类来对应 TOML 规范中的不同数据类型，并使用 `Trivia` 类来管理格式化相关的元数据。`item()` 函数作为工厂方法，负责将 Python 数据类型转换为相应的 `Item` 对象。这个模块是 `tomlkit` 库的核心组成部分，为 TOML 文件的解析、生成和操作提供了基础的数据结构表示。它允许开发者在 Python 中以面向对象的方式操作 TOML 数据，并保留了原始的格式信息。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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