Response:
The user wants a summary of the functionality of the Python code in `frida/releng/tomlkit/tomlkit/items.py`.

I need to:
1. **Identify the core purpose of the code:** This file seems to define classes and functions for representing TOML data structures in Python.
2. **List the key functionalities:** This includes creating, manipulating, and representing TOML items like integers, floats, strings, booleans, dates, times, arrays, and tables.
3. **Note any connections to reverse engineering:**  Frida is a dynamic instrumentation toolkit used in reverse engineering. I need to look for aspects of this code that might be relevant to inspecting or modifying program behavior at runtime.
4. **Look for interactions with low-level concepts:**  This could involve details about binary data, Linux/Android kernels, or frameworks.
5. **Identify logical reasoning or transformations:**  Are there functions that take specific inputs and produce predictable outputs based on certain rules?
6. **Point out potential user errors:** Are there ways a programmer could misuse this code?
7. **Infer how a user might reach this code:**  What steps would a Frida user take to interact with this specific file?

**Functionality Breakdown:**

*   **Data Representation:** Defines Python classes (e.g., `Integer`, `Float`, `String`, `Bool`, `DateTime`, `Array`, `Table`) to represent different TOML data types.
*   **TOML Item Creation:** The `item()` function acts as a factory to create instances of these TOML item classes from Python values. It handles type conversion from Python to TOML.
*   **Metadata Handling:** The `Trivia` class is used to store metadata associated with TOML items, such as whitespace and comments.
*   **Key Handling:** The `Key` and its subclasses (`SingleKey`, `DottedKey`) manage the representation of keys in TOML tables.
*   **String Type Management:** The `StringType` enum manages different types of TOML strings (basic, literal, single-line, multi-line) and their escaping rules.
*   **Output Formatting:**  The `as_string()` method in each item class is responsible for generating the TOML string representation of the item.
*   **Array Manipulation:** The `Array` class includes methods like `multiline()` and `add_line()` for formatting and adding elements.
*   **Type Conversion and Validation:** The code includes checks for valid TOML syntax and handles conversions between Python types and TOML types.

**Connections to Reverse Engineering:**

Frida uses this library to parse and represent TOML configuration files. In a reverse engineering context, a user might:

*   **Inspect Frida's configuration:** Frida's behavior can be customized using TOML configuration. This code is used to parse these configuration files, allowing users to understand how Frida is set up.
*   **Modify Frida's configuration dynamically:** Although this specific file doesn't directly handle dynamic modification, it provides the building blocks for representing and potentially altering configuration settings that Frida might reload.

**Low-Level Concepts:**

While this code primarily deals with TOML syntax and data structures, some aspects touch on lower-level concepts:

*   **String Encoding:** The use of `decode()` suggests handling different character encodings, which is relevant when dealing with data from various sources, including potentially from processes being inspected.
*   **Control Characters:** The `CONTROL_CHARS` constant and the `StringType` class's handling of escaped sequences relate to how non-printable characters are represented, which is a fundamental aspect of data representation at a lower level.

**Logical Reasoning:**

The `item()` function implements logical reasoning based on the type of the input `value` to create the appropriate TOML item.

*   **Hypothesis:** Input is a Python dictionary `{'a': 1, 'b': 'test'}`.
*   **Output:** An instance of the `Table` class with `Integer` and `String` items as values, formatted as `a = 1\nb = "test"`.

**User Errors:**

*   **Incorrect Data Types:**  Passing a Python object that cannot be represented in TOML (and for which no custom encoder is defined) will raise a `_ConvertError`. For example, trying to `item(complex(1, 2))` without a custom encoder.
*   **Invalid String Characters:** Attempting to create a literal string with characters that are not allowed in literal strings will lead to parsing errors later in the process (although this specific file focuses on *representing* items, not parsing).

**User Operation as Debugging Clue:**

A user might end up looking at this file in the following debugging scenarios:

1. **Investigating TOML Parsing Issues:** If Frida fails to load a TOML configuration file, a developer might trace the parsing process and find themselves in this code, examining how TOML items are being constructed.
2. **Understanding TOML Representation:** A user might want to understand how Frida represents TOML data internally, perhaps to modify or generate TOML configurations programmatically. They might look at the `as_string()` methods to see how Python objects are translated to TOML syntax.
3. **Developing Custom Frida Modules:** Someone writing a Frida module that interacts with or modifies TOML configuration files might need to understand the data structures defined in this file.

**Summary of Functionality (for Part 1):**

This Python file defines the core data structures and logic for representing TOML (Tom's Obvious, Minimal Language) data within the Frida dynamic instrumentation toolkit. It provides classes for various TOML item types (like integers, strings, booleans, dates, arrays, and tables), along with mechanisms to create these items from Python objects, manage associated metadata (whitespace, comments), and generate their corresponding TOML string representations. The file lays the foundation for Frida to parse, manipulate, and output TOML configuration data.

这是 `frida/releng/tomlkit/tomlkit/items.py` 文件的第 1 部分，它主要负责定义表示 TOML (Tom's Obvious, Minimal Language) 数据结构的各种 Python 类。这些类用于在内存中表示 TOML 文件中的不同类型的项，例如整数、浮点数、字符串、布尔值、日期、时间、数组和表格。

**主要功能归纳:**

1. **定义 TOML 数据类型的 Python 表示:**  文件中定义了诸如 `Integer`, `Float`, `String`, `Bool`, `DateTime`, `Date`, `Time`, `Array`, `Table`, `InlineTable`, `AoT` (Array of Tables) 等类，每个类都对应一种 TOML 数据类型。

2. **提供从 Python 对象创建 TOML 项的方法:**  `item()` 函数充当一个工厂方法，可以将 Python 内置类型（如 `int`, `float`, `str`, `bool`, `dict`, `list`, `datetime` 等）转换为相应的 TOML 项对象。

3. **处理 TOML 项的元数据 (Trivia):**  `Trivia` 类用于存储与 TOML 项相关的格式信息，例如前导空格、注释前的空格、注释内容和尾随换行符。这允许在重新生成 TOML 时保留原始格式。

4. **管理 TOML 键:**  `Key`, `SingleKey`, `DottedKey` 等类用于表示 TOML 键，包括裸键、基本引号键和字面引号键，并支持点分隔的键。

5. **定义不同类型的 TOML 字符串:** `StringType` 枚举定义了基本字符串和字面字符串，以及单行和多行变体，并包含了对转义序列和非法序列的处理逻辑。

6. **提供 TOML 项的字符串表示:**  每个 TOML 项类都有一个 `as_string()` 方法，用于生成该项的 TOML 格式的字符串表示。

7. **数组的特殊处理:** `Array` 类提供了 `multiline()` 方法来控制数组是否以多行格式显示，以及 `add_line()` 方法用于更精细地控制数组元素的格式。

**与逆向方法的关联及举例说明:**

Frida 是一个动态插桩工具，常用于逆向工程。虽然这个文件本身主要关注 TOML 数据的表示，但它在 Frida 的上下文中对于理解和操作程序的配置信息至关重要。

*   **配置文件的解析和表示:**  Frida 本身或其加载的脚本可能使用 TOML 文件进行配置。`tomlkit` 库，包括这个 `items.py` 文件，负责解析这些配置文件，并将配置项表示为这里定义的 Python 对象。在逆向过程中，理解这些配置项如何被表示可以帮助分析 Frida 的行为或目标程序的配置方式。
    *   **举例:**  假设一个 Frida 脚本的配置文件 `config.toml` 中有如下内容：
        ```toml
        enabled = true
        threshold = 100
        modules = ["module1", "module2"]
        ```
        Frida 在加载这个文件时，会使用 `tomlkit` 将 `enabled` 表示为一个 `Bool` 对象，`threshold` 表示为一个 `Integer` 对象，`modules` 表示为一个 `Array` 对象。逆向工程师可以通过检查这些对象的属性来了解配置文件的内容。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件本身的代码抽象层次较高，主要关注 TOML 语法和数据结构，直接涉及二进制底层、Linux/Android 内核的知识较少。不过，在 Frida 的整体框架中，`tomlkit` 解析的配置信息可能会影响 Frida 与目标进程的交互方式，而这些交互可能涉及到操作系统层面。

*   **间接影响 Frida 的行为:**  例如，一个 TOML 配置项可能指定了 Frida 需要 hook 的函数地址或共享库名称。这些信息最终会被 Frida 转换为对目标进程内存的底层操作。
    *   **举例:**  假设一个 Frida 脚本的配置中指定了要 hook 的函数名：
        ```toml
        [hooks]
        "libnative.so" = ["target_function"]
        ```
        `tomlkit` 会将 `"libnative.so"` 和 `"target_function"` 表示为 `String` 对象。Frida 的后续逻辑会使用这些字符串去解析目标进程的 ELF 文件，查找 `target_function` 的地址，并在其入口点设置断点或 hook。这个过程涉及到对二进制文件格式（如 ELF）的理解和对进程内存的操作。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  Python 字典 `{'name': 'Frida', 'version': 16.0}`
*   **输出:**  调用 `item()` 函数后，会创建一个 `Table` 对象，其中包含两个 `SingleKey` 对象（`name`, `version`) 和两个 `String` 对象 (`'Frida'`, `'16.0'`)。当调用该 `Table` 对象的 `as_string()` 方法时，会输出类似 `name = "Frida"\nversion = "16.0"\n` 的字符串。

**涉及用户或编程常见的使用错误及举例说明:**

*   **尝试使用 Python 对象直接作为 TOML 项:**  用户可能会尝试直接将一个自定义的 Python 类实例赋值给一个 TOML 文档的某个键，而 `tomlkit` 默认情况下无法处理这种类型，除非提供了自定义的编码器。
    *   **举例:**
        ```python
        class MyObject:
            def __init__(self, value):
                self.value = value

        my_obj = MyObject(123)
        # 假设 doc 是一个 tomlkit.document() 对象
        # doc['my_object'] = my_obj  # 这会导致错误，因为 MyObject 无法直接转换为 TOML 项
        ```
        用户需要先使用 `item()` 函数将其转换为 `Item` 的子类，或者注册一个自定义的编码器到 `CUSTOM_ENCODERS` 列表中。

*   **在 `add_line()` 中使用不合法的项类型:** `Array` 类的 `add_line()` 方法有特定的使用方式，如果 `add_comma` 设置为 `True`，则不应该直接添加 `Whitespace` 或 `Comment` 类型的项。
    *   **举例:**
        ```python
        from tomlkit import array, ws, comment

        arr = array()
        # arr.add_line(1, ws(", "), 2)  # 如果 add_comma 默认为 True，这将引发 ValueError
        ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写或修改 Frida 脚本:**  用户可能会编写一个 Frida 脚本，该脚本需要读取或生成 TOML 配置文件。
2. **Frida 执行脚本并解析 TOML 文件:**  当 Frida 执行脚本时，如果脚本中使用了 `tomlkit` 库来加载 TOML 文件，那么 `tomlkit` 的解析器会读取 TOML 文件的内容。
3. **`tomlkit` 创建 TOML 项对象:**  在解析过程中，`tomlkit` 会根据 TOML 文件中的不同内容，调用 `item()` 函数来创建 `Integer`, `String`, `Array` 等类的实例。这个过程中，可能会涉及到 `items.py` 文件中定义的各种类。
4. **用户调试或查看内部表示:**  如果用户在调试过程中想要了解 `tomlkit` 是如何表示 TOML 数据的，或者遇到与 TOML 解析相关的问题，他们可能会查看 `items.py` 文件的源代码，以理解不同 TOML 项类的结构和行为。例如，他们可能会查看 `as_string()` 方法的实现，以了解 TOML 项是如何被序列化回字符串的。

总而言之，`frida/releng/tomlkit/tomlkit/items.py` 文件是 `tomlkit` 库的核心组成部分，它定义了用于表示 TOML 数据的 Python 对象模型，为 Frida 及其脚本处理 TOML 配置文件提供了基础。理解这个文件的功能对于深入了解 Frida 的配置机制以及调试与 TOML 解析相关的问题至关重要。

Prompt: 
```
这是目录为frida/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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