Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Request:**

The core request is to analyze a specific Python file (`items.py`) from the `tomlkit` library, part of the `frida` project. The request asks for:

* **Functionality:** What does this code do?
* **Relevance to Reversing:** How might it relate to reverse engineering?
* **Low-Level Concepts:** Does it interact with binary, Linux/Android kernels, or frameworks?
* **Logic & Examples:** Provide input/output examples if logical processing is involved.
* **User Errors:** Identify common mistakes users might make.
* **Debugging Context:** How does a user reach this code during debugging?
* **Summary of Functionality:** A concise overview.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for keywords and patterns that provide clues about its purpose. I'd look for:

* **Imports:** `datetime`, `enum`, `typing`, `re`, `dataclasses`, `abc`. These indicate the code deals with data structures, types, regular expressions, and abstract base classes. The `tomlkit` imports are a strong signal about its core purpose.
* **Class Definitions:** `Item`, `Integer`, `String`, `Array`, `Table`, etc. This suggests the code defines a hierarchy of objects representing different TOML data types.
* **Functions:** `item()`. This is likely a central function for converting Python objects to TOML items.
* **Decorators:** `@overload`, `@dataclasses.dataclass`, `@abc.abstractmethod`, `@property`. These provide metadata and structure to the code.
* **String Literals:** Look for examples like `'"'`, `"""`, `'`, `'''`. These strongly suggest the code deals with parsing and formatting strings, potentially according to a specific syntax (TOML in this case).
* **Regular Expressions:** The presence of `re` confirms string manipulation and pattern matching.

**3. Deduce Core Functionality: TOML Handling**

The filename (`items.py`), the package name (`tomlkit`), and the presence of classes like `Table`, `Array`, `String`, `Integer` strongly suggest that this file is responsible for representing TOML data structures in Python. The `item()` function appears to be the entry point for converting Python values into their TOML counterparts.

**4. Analyze Key Classes and Functions:**

* **`Item` (and subclasses):** This is the base class for all TOML data types. Subclasses like `Integer`, `String`, `Bool`, `Array`, `Table`, etc., represent the specific TOML types. The methods like `as_string()` suggest they handle serialization (converting to string representation). The `unwrap()` method hints at deserialization or accessing the underlying Python value.
* **`Trivia`:** This class likely stores metadata associated with TOML elements, such as whitespace and comments. This is crucial for preserving the original formatting of a TOML document.
* **`item()` function:**  This function has multiple `@overload` decorators, indicating it can handle various Python input types and convert them into the corresponding `Item` subclass. The logic within the function implements the type-specific conversion rules.
* **`Key` (and subclasses):** Deals with representing TOML keys, distinguishing between bare, basic, and literal keys.

**5. Connect to Reverse Engineering (Frida Context):**

Knowing this code is part of Frida is key. Frida is used for dynamic instrumentation, often in the context of reverse engineering. Here's how `tomlkit/items.py` could be relevant:

* **Configuration:** TOML is a human-readable configuration format. Frida might use TOML files to configure its behavior, scripts, or hooks. This code would be used to parse and represent those configuration settings within Frida.
* **Data Representation:** When inspecting the state of a process, Frida might need to represent data structures in a clear and structured way. TOML's hierarchical nature makes it suitable for this, and `tomlkit` would provide the tools for this representation.
* **Inter-Process Communication:** Frida interacts with target processes. TOML could be used as a format for exchanging data or commands between Frida and injected scripts.

**6. Consider Low-Level Concepts:**

While the code itself is high-level Python, its *use within Frida* can touch on low-level aspects:

* **Memory Inspection:** Frida operates by injecting into processes and inspecting memory. The data structures represented by `tomlkit` might reflect the in-memory state of the target application.
* **Inter-Process Communication:** Frida's core functionality involves communicating with the target process, which operates at a lower level.
* **Configuration of Low-Level Hooks:** Frida hooks into function calls. The configuration of these hooks (what functions to hook, what to do when hooked) could be stored in TOML and parsed using this code.

**7. Generate Examples and Identify Potential Errors:**

* **Logical Processing:** The `item()` function performs logical type checking and conversion. Examples of Python input and their resulting TOML representation are easy to create (as shown in the answer).
* **User Errors:** Common mistakes might involve trying to convert unsupported Python types, or having inconsistencies in the TOML structure if manually creating or modifying TOML data.

**8. Trace User Steps to Debugging:**

Think about the typical Frida workflow:

1. **Write a Frida script:** This script might load configuration from a TOML file.
2. **Run Frida:** Frida loads the script and injects it into the target process.
3. **Encounter an error:**  If there's an issue parsing the TOML file, the debugger might step into `tomlkit` code, potentially including `items.py`, to investigate the source of the error. The user might be manually inspecting TOML data structures or stepping through the parsing process.

**9. Summarize Functionality:**

Finally, condense the findings into a concise summary that captures the essence of the file's purpose.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like a generic data serialization library."  **Correction:** Realizing the Frida context and the TOML-specific class names shifts the focus to TOML parsing and representation within the context of dynamic instrumentation.
* **Considering low-level:** Initially, I might have focused only on the Python code. **Refinement:** Thinking about how Frida *uses* this code in its low-level interactions with target processes provides a crucial link.
* **User errors:**  Initially, I might have focused on syntax errors in TOML. **Refinement:** Considering errors related to *programmatic* usage of `tomlkit`, like passing incorrect Python types to `item()`, is also important.

By following these steps, combining code analysis with understanding the broader context of Frida and TOML, a comprehensive analysis of `items.py` can be achieved.
这是 `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py` 文件的第一部分，它定义了 `tomlkit` 库中用于表示 TOML (Tom's Obvious, Minimal Language) 数据的各种项（items）的类和函数。`tomlkit` 是一个用于解析、操作和生成 TOML 文档的 Python 库。

以下是该文件的功能归纳：

**核心功能：定义 TOML 数据结构的 Python 表示**

该文件主要负责定义 Python 类来对应 TOML 规范中的不同数据类型，以及相关的元数据（trivia）。这使得 `tomlkit` 能够以面向对象的方式在 Python 中操作 TOML 数据。

**具体功能点：**

1. **TOML 数据类型表示：** 定义了表示各种 TOML 数据类型的 Python 类：
   - `Integer`: 整数
   - `Float`: 浮点数
   - `Bool`: 布尔值
   - `String`: 字符串（支持不同类型的引号）
   - `DateTime`: 日期和时间
   - `Date`: 日期
   - `Time`: 时间
   - `Array`: 数组
   - `Table`: 表格 (类似于 Python 的字典)
   - `InlineTable`: 内联表格
   - `AoT`: 数组 of 表格

2. **元数据 (Trivia) 管理：** 定义了 `Trivia` 类来存储与 TOML 项相关的非语义信息，例如：
   - `indent`: 缩进
   - `comment_ws`: 注释前的空格
   - `comment`: 注释内容
   - `trail`: 尾随换行符

3. **类型转换函数 `item()`:**  提供了一个核心函数 `item(value)`，用于将 Python 对象转换为相应的 TOML 项对象。这个函数根据 Python 对象的类型，创建 `Integer`, `String`, `Array`, `Table` 等类的实例。

4. **字符串类型枚举 `StringType`:** 定义了 `StringType` 枚举来表示 TOML 中不同类型的字符串（基本单行/多行，字面单行/多行），并提供了用于选择和处理这些类型的便捷方法。

5. **布尔类型枚举 `BoolType`:** 定义了 `BoolType` 枚举来表示 TOML 中的 `true` 和 `false`。

6. **键类型枚举 `KeyType` 和 `Key` 类：** 定义了 `KeyType` 枚举来表示 TOML 中键的不同类型（裸键、基本引号键、字面引号键），以及 `Key` 及其子类 `SingleKey` 和 `DottedKey` 来表示 TOML 中的键。

7. **抽象基类 `Item`:** 定义了 `Item` 作为所有 TOML 项类的抽象基类，提供了公共的接口和属性，例如 `trivia` (获取元数据), `as_string()` (生成 TOML 字符串表示), `unwrap()` (获取原始 Python 值)。

8. **空白和注释表示：** 定义了 `Whitespace` 和 `Comment` 类来显式地表示 TOML 文档中的空白和注释，以便在操作和生成 TOML 时保留这些信息。

9. **内部转换错误 `_ConvertError`:** 定义了一个内部异常类，用于在 `item()` 函数无法将 Python 值转换为 TOML 项时抛出。

**与逆向方法的关系：**

虽然这个文件本身并不直接涉及二进制代码分析或内存操作，但它在 Frida 动态插桩工具的上下文中与逆向方法有重要的关系：

* **配置管理:** 在逆向工程过程中，Frida 脚本可能需要读取或修改目标应用程序的配置文件。如果目标应用使用 TOML 作为配置文件格式，那么 `tomlkit` 提供的功能就可以用于解析这些配置文件，提取配置信息，或者修改配置并将其写回。

   **举例说明:**  一个 Frida 脚本可能需要读取一个 TOML 配置文件，其中包含了应用程序的 API 端点地址。脚本可以使用 `tomlkit` 加载该文件，然后访问对应的键来获取 API 地址，并用于后续的 API hook 操作。

* **数据交换和表示:**  在 Frida 脚本中，可能需要将从目标进程中提取的数据以一种结构化的方式呈现给用户或存储到文件中。TOML 是一种易于阅读和编写的格式，`tomlkit` 可以将 Python 数据结构转换为 TOML 字符串，方便用户理解和分析。

   **举例说明:**  一个 Frida 脚本 hook 了一个函数，并提取了该函数的参数和返回值。为了方便用户查看，脚本可以使用 `tomlkit` 将这些参数和返回值组织成一个 TOML 格式的字符串并打印出来。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

这个文件本身是纯 Python 代码，不直接涉及这些底层知识。然而，`tomlkit` 在 Frida 中的应用场景可能会间接地与这些领域相关：

* **配置文件格式:**  目标应用程序（可能是运行在 Linux 或 Android 上的二进制程序）可能会使用 TOML 作为配置文件格式。`tomlkit` 用于解析这些配置文件，从而间接地接触到这些系统。

* **数据结构序列化:**  当 Frida 脚本与目标进程交互时，可能需要将一些数据结构序列化成字符串进行传递或存储。TOML 可以作为一种序列化格式，`tomlkit` 提供了序列化到 TOML 的能力。

**逻辑推理的假设输入与输出：**

`item()` 函数是该文件中进行逻辑推理的核心。

**假设输入：**

```python
value1 = 123
value2 = "hello"
value3 = True
value4 = [1, 2, "three"]
value5 = {"name": "John", "age": 30}
```

**输出：**

```python
item(value1)  # 输出: <Integer 123>
item(value2)  # 输出: <String 'hello'>
item(value3)  # 输出: <Bool True>
item(value4)  # 输出: <Array [1, 2, 'three']>
item(value5)  # 输出: <Table name = "John"\nage = 30>
```

**涉及用户或编程常见的使用错误：**

* **尝试转换不支持的类型:**  `item()` 函数会抛出 `_ConvertError` 如果传入了无法转换为 TOML 项的 Python 对象。

   **举例说明:**

   ```python
   class MyObject:
       pass

   try:
       item(MyObject())
   except _ConvertError as e:
       print(e)  # 输出类似: Invalid type <class '__main__.MyObject'>
   ```

* **在不支持的地方使用 `_parent` 参数:** `_parent` 参数主要用于内部处理，不应该由用户直接传递，否则可能会导致意外的行为。

* **假设 `item()` 函数会修改传入的 Python 对象:** `item()` 函数创建的是新的 TOML 项对象，不会修改原始的 Python 对象。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个调试线索，用户到达这里可能有以下步骤：

1. **编写 Frida 脚本:** 用户编写了一个 Frida 脚本，该脚本需要处理 TOML 格式的数据。
2. **使用 `tomlkit` 库:**  脚本中导入并使用了 `tomlkit` 库来加载、解析或生成 TOML 数据。例如，使用了 `tomlkit.load()` 函数加载一个 TOML 文件。
3. **遇到与 TOML 项相关的错误:**  在脚本执行过程中，可能因为 TOML 数据格式不正确、类型转换错误或其他原因，导致 `tomlkit` 内部的函数（例如 `item()`）抛出异常。
4. **进行调试:** 用户使用 Frida 的调试功能或其他 Python 调试工具，逐步执行脚本代码。
5. **进入 `tomlkit` 源代码:** 当调试器执行到 `tomlkit` 库的内部代码时，可能会进入 `items.py` 文件，特别是 `item()` 函数或其他与创建 TOML 项相关的代码，以便查看变量的值，理解错误发生的原因。

**总结一下它的功能：**

这个文件的主要功能是定义了 `tomlkit` 库中用于表示各种 TOML 数据类型的 Python 类，以及一个用于将 Python 对象转换为这些 TOML 项对象的关键函数 `item()`。它为 `tomlkit` 提供了构建和操作 TOML 数据结构的基础，是 `tomlkit` 库的核心组成部分。在 Frida 的上下文中，这个文件对于处理 TOML 配置文件、表示从目标进程中提取的数据等方面非常重要。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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