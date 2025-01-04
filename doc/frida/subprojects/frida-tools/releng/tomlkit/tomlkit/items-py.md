Response:
Let's break down the thought process for analyzing the `items.py` file.

1. **Understand the Goal:** The request asks for the functionalities of this Python file, its relevance to reverse engineering, its interaction with low-level systems, logical inferences, common user errors, and debugging clues. It specifically mentions this is part 1 of 2 and requests a summary.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for significant keywords, class names, and function names. This gives a high-level understanding. Keywords like `Item`, `String`, `Integer`, `Float`, `Bool`, `DateTime`, `Array`, `Table`, `Trivia`, `Encoder`, and function names like `item`, `as_string`, `unwrap`, `comment`, `indent`, `multiline` stand out. The presence of `tomlkit` in the import paths is a strong indicator that this file deals with TOML data structures.

3. **Categorize Functionality by Class:** The file is heavily object-oriented. A good approach is to examine each class and its methods to determine its purpose:

    * **`_ConvertError`:** A custom exception for failed type conversions during the `item()` function. This relates to how Python objects are translated into TOML.

    * **`item()` function:** This is crucial. It acts as a factory function, taking a Python object and returning a corresponding TOML `Item` subclass. The `@overload` decorators indicate it handles different Python types. The logic inside the function shows how each Python type (bool, int, float, dict, list, str, datetime, date, time) is converted into its TOML representation. It also handles custom encoders.

    * **`StringType` and `BoolType`:** Enums defining TOML string and boolean types and their properties (e.g., escaping, quoting). This hints at how TOML syntax is structured.

    * **`Trivia`:**  A dataclass to hold metadata about TOML elements (whitespace, comments). This is important for preserving formatting.

    * **`KeyType` and `Key` (and subclasses `SingleKey`, `DottedKey`):** Classes related to TOML keys, handling bare, basic, and literal keys, and dotted keys. This is fundamental to how TOML data is organized.

    * **`Item` (abstract base class):**  Defines the common interface for all TOML items (`as_string`, `unwrap`, `comment`, `indent`). The `discriminant` property suggests a way to identify the type of item.

    * **`Whitespace` and `Comment`:** Represent whitespace and comment tokens in TOML. They are special types of `Item` that don't directly hold user data.

    * **Primitive Type Classes (`Integer`, `Float`, `Bool`, `DateTime`, `Date`, `Time`):**  These represent the basic TOML data types, inheriting from `Item` and their corresponding Python types. They store the value and formatting information (`Trivia`, `_raw`).

    * **Collection Type Classes (`Array`, `_ArrayItemGroup`):** These represent TOML arrays, handling multiline formatting, commas, and comments within arrays. The `_ArrayItemGroup` helps manage the structure of array elements with their associated whitespace and comments.

4. **Relate to Reverse Engineering:** Think about how these TOML structures might be used in a dynamic instrumentation context like Frida. Configuration files are a prime example. The ability to parse and potentially modify TOML could be used to:

    * Change Frida's behavior.
    * Inject custom configurations into a target process.
    * Understand the settings of a protected application.

5. **Consider Low-Level Details:** The code itself doesn't directly interact with the kernel or CPU. However, the *purpose* of Frida and TOML's role in it connect to these areas. Frida manipulates processes at a low level. TOML could define how Frida interacts with these processes. Think about configuration files for Frida scripts, defining hooks, breakpoints, etc.

6. **Identify Logical Inferences:** Look for functions that transform data or make decisions based on input. The `item()` function is the key here. Trace the flow of execution for different input types. Consider edge cases (empty lists, empty dictionaries, different string quoting).

7. **Anticipate User Errors:**  Think about common mistakes when working with configuration files or when trying to programmatically create TOML. Type mismatches, invalid string characters, and incorrect formatting are possibilities.

8. **Trace User Actions (Debugging Clues):** Imagine a user interacting with Frida. How might they end up using this code? They might:

    * Load a TOML configuration file.
    * Programmatically create TOML to configure Frida scripts.
    * Encounter an error when Frida tries to parse a TOML file.

9. **Synthesize and Structure the Answer:**  Organize the findings into the requested categories:

    * **Functionality:** Provide a concise summary of the main purpose of the file and then detail the role of each significant class and function.

    * **Reverse Engineering:** Explain the connection to configuration files, dynamic analysis settings, and potential manipulation of application behavior through TOML.

    * **Low-Level Details:** Connect TOML's use in Frida to the underlying actions Frida performs (process manipulation, hooking).

    * **Logical Inferences:** Use the `item()` function as the primary example, showing input-output relationships for different types.

    * **User Errors:** Provide concrete examples of common mistakes.

    * **Debugging Clues:** Describe how a user might trigger this code and what clues it provides during debugging.

10. **Write the Summary:** Briefly reiterate the core function of the file in the context of the larger Frida project.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on the syntax of the code.
* **Correction:** Shift focus to the *purpose* and *behavior* of the code in the context of Frida and TOML.
* **Initial thought:** Treat each class in isolation.
* **Correction:** Emphasize how the classes work together, especially the `item()` factory function connecting Python types to TOML `Item` subclasses.
* **Initial thought:**  Overlook the connection to reverse engineering.
* **Correction:** Explicitly link TOML to configuration files and the ability to influence Frida's behavior during dynamic analysis.
* **Initial thought:**  Provide overly technical explanations of each class.
* **Correction:**  Prioritize clarity and explain the high-level purpose before diving into implementation details. Use examples to illustrate concepts.
好的，我们来详细分析一下 `frida/subprojects/frida-tools/releng/tomlkit/tomlkit/items.py` 这个文件的功能。

**文件功能概览**

`items.py` 文件是 `tomlkit` 库的核心组成部分，它定义了用于表示 TOML (Tom's Obvious, Minimal Language) 文档中各种元素的 Python 类。  其主要功能是：

1. **定义 TOML 数据类型的 Python 表示：**  该文件为 TOML 规范中定义的各种数据类型（如字符串、整数、浮点数、布尔值、日期时间、数组、表格等）提供了相应的 Python 类。这些类不仅存储了数据的值，还包含了与格式相关的元数据（例如，注释、前导/尾随空格等），这些元数据存储在 `Trivia` 类中。

2. **提供 Python 对象到 TOML 元素的转换机制：**  `item()` 函数是核心的工厂函数，它接收一个 Python 对象作为输入，并根据其类型返回相应的 TOML `Item` 子类的实例。这使得在 Python 代码中创建和操作 TOML 数据变得简单直观。

3. **支持 TOML 元素的字符串表示：** 每个 TOML `Item` 子类都实现了 `as_string()` 方法，用于生成该元素在 TOML 文档中的字符串表示形式。这对于将 Python 对象序列化为 TOML 格式至关重要。

4. **管理 TOML 格式细节：**  `Trivia` 类用于存储 TOML 元素的格式信息，例如注释、缩进和尾随换行符。这使得 `tomlkit` 能够保留和生成格式良好的 TOML 文档。

5. **支持自定义类型编码：**  通过 `CUSTOM_ENCODERS` 列表和相关的逻辑，`tomlkit` 允许用户注册自定义的编码器，以便将特定的 Python 对象类型转换为 TOML 中的表示。

**与逆向方法的关联及举例说明**

`items.py` 本身并不直接包含用于逆向工程的代码，但它作为 `tomlkit` 库的一部分，在逆向分析中可能扮演以下角色：

* **解析和生成配置文件：**  很多软件，包括用于动态 instrumentation 的工具（如 Frida），会使用 TOML 作为配置文件格式。逆向工程师可以使用 `tomlkit` 来解析目标软件的配置文件，了解其行为和设置。他们也可以使用 `tomlkit` 生成修改后的配置文件，用于测试或绕过某些限制。

   **举例：** 假设一个 Android 应用使用 TOML 文件 `config.toml` 来配置其功能。逆向工程师可以使用 Frida 脚本加载该文件：

   ```python
   import tomlkit
   import frida

   session = frida.attach("com.example.app")
   script = session.create_script("""
       // ... Frida 脚本代码 ...
   """)
   script.load()

   # 假设 config.toml 文件内容如下：
   # api_url = "https://api.example.com"
   # debug_mode = false

   config_str = """
   api_url = "https://api.example.com"
   debug_mode = false
   """
   config = tomlkit.loads(config_str)
   api_url = config['api_url']
   debug_mode = config['debug_mode']
   print(f"API URL: {api_url}, Debug Mode: {debug_mode}")

   # 修改配置并生成新的 TOML 内容
   config['debug_mode'] = True
   new_config_str = tomlkit.dumps(config)
   print(f"New Config:\n{new_config_str}")
   ```

* **修改内存中的配置数据：** 如果目标程序在内存中以某种结构化方式存储了配置数据，逆向工程师可能需要理解这种结构，并可能需要修改这些数据。如果该结构与 TOML 的概念相似（例如，键值对、嵌套结构），那么理解 `tomlkit` 如何表示这些概念有助于分析内存中的数据。

**涉及二进制底层、Linux/Android 内核及框架的知识**

`items.py` 本身并不直接涉及这些底层知识，但 `tomlkit` 和 Frida 的使用场景会涉及到：

* **二进制底层：**  当 Frida 与目标进程交互时，它会涉及到内存读写、函数 Hook 等操作，这些都是在二进制层面进行的。`tomlkit` 解析的配置可能会影响 Frida 如何执行这些底层操作，例如，指定要 Hook 的函数地址或范围。

* **Linux/Android 内核：**  Frida 依赖于操作系统提供的机制来进行进程注入、内存访问等操作。如果 TOML 配置文件中包含与操作系统相关的设置（例如，文件路径、权限设置等），那么这些设置最终会影响 Frida 与内核的交互。

* **Android 框架：**  在 Android 逆向中，TOML 配置文件可能用于配置 Frida 脚本如何与 Android 框架中的组件（例如，Activity、Service）进行交互。例如，配置文件可能指定要 Hook 的特定系统服务或 API。

**逻辑推理及假设输入与输出**

`item()` 函数是进行逻辑推理的关键部分。让我们看几个例子：

**假设输入：** `value = 123`
**输出：** `Integer(123, Trivia(), '123')`
**推理：**  `item()` 函数识别到输入是整数类型，因此创建了一个 `Integer` 类的实例。该实例包含了整数值 `123`，一个默认的 `Trivia` 对象，以及原始字符串表示 `'123'`。

**假设输入：** `value = {"name": "Alice", "age": 30}`
**输出：**  `Table({'name': String("Alice", Trivia(), '"Alice"'), 'age': Integer(30, Trivia(), '30')}, Trivia(), False)`
**推理：** `item()` 函数识别到输入是字典，因此创建了一个 `Table` 实例。它遍历字典的键值对，并递归调用 `item()` 函数来创建值对应的 TOML 元素（这里是 `String` 和 `Integer`）。 `Trivia()` 是默认的， `False` 表示这不是内联表格。

**假设输入：** `value = [1, "hello", True]`
**输出：** `Array([Integer(1, Trivia(), '1'), String("hello", Trivia(), '"hello"'), Bool(True, Trivia())], Trivia(), False)`
**推理：** `item()` 函数识别到输入是列表，创建了一个 `Array` 实例。它遍历列表元素，并为每个元素调用 `item()` 创建相应的 TOML 元素。 `Trivia()` 是默认的， `False` 表示不是多行数组。

**涉及用户或编程常见的使用错误及举例说明**

* **尝试将不支持的 Python 类型转换为 TOML：**  如果用户尝试将 `item()` 函数应用于一个 `tomlkit` 无法转换为标准 TOML 类型的 Python 对象，将会抛出 `_ConvertError`。

   **举例：**

   ```python
   import tomlkit

   class MyObject:
       pass

   my_object = MyObject()
   try:
       toml_item = tomlkit.item(my_object)
   except tomlkit.exceptions._ConvertError as e:
       print(f"Error: {e}")
   ```

* **假设 `_sort_keys=True` 但值类型不支持排序：**  虽然 `item()` 函数提供了 `_sort_keys` 参数，但如果字典的值是不可比较的类型，排序操作可能会失败。

* **手动创建 `Item` 子类时忽略 `Trivia`：**  虽然可以直接实例化 `Integer`、`String` 等类，但如果用户没有正确处理 `Trivia` 对象，可能会导致生成的 TOML 文档格式不正确。

**用户操作如何一步步到达这里 (调试线索)**

作为调试线索，用户操作通常会通过 `tomlkit` 库的其他部分间接地到达 `items.py`。以下是一些可能的路径：

1. **加载 TOML 文件：** 用户调用 `tomlkit.load()` 或 `tomlkit.loads()` 函数来解析 TOML 文件或字符串。这些函数内部会调用 `items.py` 中定义的类和函数来创建 TOML 元素的 Python 表示。

   ```python
   import tomlkit

   with open("config.toml", "r") as f:
       data = tomlkit.load(f)  # 内部会使用 items.py 中的类
   ```

2. **创建和修改 TOML 数据结构：** 用户直接使用 `tomlkit.document()` 创建空的 TOML 文档，并使用类似字典的操作添加或修改数据。这些操作会调用 `item()` 函数来将 Python 对象转换为 TOML 元素。

   ```python
   import tomlkit

   doc = tomlkit.document()
   doc['title'] = "My Document"  # 内部会调用 item("My Document")
   doc['owner'] = {'name': 'Tom'} # 内部会调用 item({'name': 'Tom'})
   ```

3. **将 Python 对象转换为 TOML 元素：** 用户可能直接调用 `tomlkit.item()` 函数来将一个 Python 对象转换为对应的 TOML `Item` 实例。

   ```python
   import tomlkit

   my_int = tomlkit.item(42)
   print(type(my_int)) # 输出: <class 'tomlkit.items.Integer'>
   ```

4. **序列化 TOML 数据结构：** 用户调用 `tomlkit.dump()` 或 `tomlkit.dumps()` 函数将 TOML 数据结构序列化为字符串。这些函数会调用 `items.py` 中各个 `Item` 子类的 `as_string()` 方法来生成字符串表示。

   ```python
   import tomlkit

   doc = tomlkit.document()
   doc['key'] = 'value'
   toml_string = tomlkit.dumps(doc) # 内部会调用 String 类的 as_string()
   ```

当调试与 `tomlkit` 相关的问题时，例如解析错误或序列化格式不正确，检查 `items.py` 中定义的类和 `item()` 函数的行为可以帮助理解 `tomlkit` 如何表示和处理不同的 TOML 元素。

**总结 (第 1 部分功能归纳)**

`frida/subprojects/frida-tools/releng/tomlkit/tomlkit/items.py` 文件的主要功能是定义了用于表示 TOML 文档中各种数据类型的 Python 类，并提供了 Python 对象到 TOML 元素的转换机制。它负责管理 TOML 元素的格式细节，并支持生成 TOML 格式的字符串表示。该文件是 `tomlkit` 库的核心，使得在 Python 代码中能够方便地创建、操作和序列化 TOML 数据。 虽然它本身不包含直接的逆向代码，但作为 Frida 配置解析的工具，它在逆向工程中扮演着重要的角色。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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