Response:
Let's break down the thought process for analyzing this Python code and answering the user's request.

**1. Understanding the Goal:**

The user wants a comprehensive analysis of the `container.py` file within the context of Frida. They are interested in:

* **Functionality:** What does this code *do*?
* **Reverse Engineering Relevance:** How is this code related to the practice of reverse engineering?
* **Low-Level/Kernel/Framework Relevance:** Does it interact with lower levels of the system?
* **Logical Inference:** Are there any implicit assumptions or logical deductions made within the code?
* **Common User Errors:**  What mistakes could a user make while interacting with this code or its surrounding system?
* **User Journey:** How does a user end up interacting with this specific code?

**2. Initial Code Scan & Keyword Identification:**

My first step is to quickly scan the code for recognizable patterns and keywords. This gives me a high-level understanding before diving deep. I'm looking for:

* **Class names:** `Container`, `OutOfOrderTableProxy` (These seem important for the core functionality)
* **Method names:** `add`, `append`, `remove`, `item`, `as_string`, `unwrap`, `value`, `__getitem__`, `__setitem__`, `__delitem__` (These suggest dictionary-like behavior and manipulation of data)
* **Data structures:** `_map` (a dictionary), `_body` (a list of tuples), `_table_keys` (a list). These hold the actual data.
* **Error handling:**  `KeyAlreadyPresent`, `NonExistentKey`, `TOMLKitError` (This tells me about the expected error conditions)
* **TOML specific terms:** `Table`, `AoT` (Array of Tables), `Comment`, `Whitespace`, `Key` (This strongly indicates that the code is about parsing or manipulating TOML files).
* **Frida specific context:**  The file path `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/container.py` suggests this is part of Frida's tooling for Swift interaction and relies on a `tomlkit` library.
* **Operations:**  Adding, removing, replacing, and retrieving items, which points to data management.
* **Serialization/Deserialization:**  `unwrap`, `as_string` suggest conversion to and from Python objects and TOML strings.

**3. Deeper Dive into Key Components:**

Now I focus on the core classes and their methods:

* **`Container` Class:**
    * It inherits from `_CustomDict`, implying it's designed to behave like a dictionary but with custom behavior.
    * The `_map` and `_body` are the central data stores. `_map` seems to be an index for quickly finding items by key, while `_body` maintains the order and includes metadata like comments and whitespace.
    * The methods like `add`, `append`, `remove`, `__getitem__`, `__setitem__`, `__delitem__` confirm its dictionary-like nature but with TOML-specific considerations.
    * Methods like `as_string` indicate its role in representing the TOML structure as a string.
    * The handling of `Table` and `AoT` elements suggests it understands the hierarchical structure of TOML.
    * The `parsing` method hints at managing the parsing state.

* **`OutOfOrderTableProxy` Class:**
    * This class seems to handle a special case of TOML table definitions that appear out of order. It acts as a proxy to the main `Container`.

**4. Connecting to Reverse Engineering:**

Knowing that Frida is a dynamic instrumentation toolkit, I consider how TOML files are used in that context. Configuration files are a common use case. This `container.py` likely plays a role in:

* **Reading and parsing Frida configuration:** Frida might use TOML to define settings, hooks, or scripts.
* **Manipulating configuration:**  Perhaps Frida's internals need to modify the configuration dynamically.
* **Generating configuration:**  Frida might generate TOML configuration files based on user input or internal states.

This leads to examples of how reverse engineers might interact with this: inspecting Frida's configuration, modifying it for custom hooks, or understanding how Frida itself parses configuration.

**5. Considering Low-Level/Kernel/Framework Aspects:**

While the code itself doesn't directly interact with the kernel or low-level APIs, I consider the *purpose* of Frida. Frida *instruments* processes, which inherently involves interacting with the operating system's process management and memory management. Therefore, while `container.py` is a high-level utility, it's *part of a larger system* that does interact with the lower levels. The configuration it manages could influence Frida's low-level behavior.

**6. Logical Inference and Assumptions:**

I examine the logic in methods like `append` and `_handle_dotted_key`. The code makes assumptions about the structure of TOML and how different elements should be added and ordered. The existence of `OutOfOrderTableProxy` suggests the TOML specification allows for some flexibility in table declaration order.

**7. Identifying User Errors:**

Based on the error handling and the API, I can deduce potential user errors:

* **Adding duplicate keys:** The `KeyAlreadyPresent` exception indicates this.
* **Trying to access non-existent keys:** The `NonExistentKey` exception highlights this.
* **Incorrectly formatting TOML:** While this code parses TOML, users interacting with the *larger Frida system* might provide malformed TOML that this code would then have to handle (or throw an error).

**8. Tracing the User Journey:**

I consider how a user would end up involving this specific file. This requires thinking about the typical Frida workflow:

* **Installation:** Users install Frida, which includes its Python components.
* **Configuration:** Users might create or modify Frida configuration files (often in TOML).
* **Frida scripts:**  Frida scripts might interact with Frida's internal configuration, potentially using the `tomlkit` library.
* **Debugging/Development:** Developers working on Frida itself would directly interact with this code.

**9. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each point of the user's request with specific examples and explanations. I use headings and bullet points for readability.

**Self-Correction/Refinement:**

During the process, I might realize I've made an assumption that isn't entirely accurate. For instance, I might initially think this code directly interacts with the filesystem, but upon closer inspection, realize it only manipulates the *in-memory representation* of the TOML data. I would then correct my understanding and the corresponding parts of the answer. Similarly, I might need to revisit the TOML specification to ensure my understanding of "out-of-order tables" is correct.
好的，我们来详细分析一下 `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/container.py` 这个文件，它是 Frida 工具中用于处理 TOML 配置文件的关键部分。

**功能列举:**

这个 `container.py` 文件定义了一个名为 `Container` 的类，以及一个辅助类 `OutOfOrderTableProxy`。 `Container` 类的主要功能是：

1. **存储和管理 TOML 数据:**  它作为一个自定义的字典（继承自 `_CustomDict`），用于存储 TOML 文件中的键值对、表（tables）和数组（arrays of tables）。
2. **维护 TOML 结构信息:** 除了存储值，它还保留了 TOML 文件中的结构信息，例如注释（comments）、空白符（whitespaces）、以及键值对和表的顺序。这对于在修改 TOML 文件后保持其原始格式非常重要。
3. **实现字典接口:** `Container` 类实现了 Python 字典的常用方法，如 `__getitem__`、`__setitem__`、`__delitem__`、`__len__`、`__iter__` 等，使得可以像操作普通字典一样操作 TOML 数据。
4. **支持 TOML 特有的数据结构:**  它专门处理 TOML 中的表（`Table`）和数组表（`AoT` - Array of Tables），并提供了添加、删除和访问这些结构的方法。
5. **处理带点的键（Dotted Keys）:** 支持 TOML 中使用点(`.`)分隔的键，可以将嵌套的键值对添加到相应的表中。
6. **序列化和反序列化:** 提供了 `unwrap()` 方法将 `Container` 对象转换为纯 Python 对象（字典），以及 `as_string()` 方法将 `Container` 对象渲染成 TOML 字符串。
7. **处理乱序表（Out-of-Order Tables）:** 通过 `OutOfOrderTableProxy` 类，支持处理 TOML 文件中定义的顺序不一致的表。
8. **错误处理:**  定义了 `KeyAlreadyPresent` 和 `NonExistentKey` 等异常，用于处理在添加或访问键时可能出现的错误。
9. **复制功能:** 提供了 `copy()` 方法用于创建 `Container` 对象的副本。

**与逆向方法的关系及举例说明:**

在逆向工程中，配置文件常常包含着目标程序的重要信息，例如服务器地址、API 密钥、功能开关、调试选项等。Frida 作为一个动态插桩工具，经常需要读取和修改目标进程的配置。`container.py` 在这里扮演着解析和操作 TOML 配置文件的角色。

**举例说明:**

假设一个 Android 应用使用 TOML 文件 `config.toml` 存储其后台服务的地址：

```toml
[server]
address = "https://api.example.com"
port = 8080
```

使用 Frida 脚本逆向该应用时，你可能需要动态修改这个地址来将应用流量重定向到你自己的服务器。Frida 内部会使用 `tomlkit` 库（包含 `container.py`）来解析这个 `config.toml` 文件，并将其加载到 `Container` 对象中。然后，你可以通过类似字典操作的方式修改 `address` 的值：

```python
import frida
import tomlkit

# 假设已经通过某种方式获取了 config.toml 的内容
toml_content = """
[server]
address = "https://api.example.com"
port = 8080
"""

# 使用 tomlkit 解析 TOML 内容
doc = tomlkit.loads(toml_content)

# 修改 server.address 的值
doc['server']['address'] = "https://your-server.com"

# 将修改后的 TOML 内容转换回字符串
modified_toml = tomlkit.dumps(doc)

print(modified_toml)
```

在这个例子中，虽然你没有直接操作 `container.py` 中的类，但 `tomlkit.loads()` 内部会创建 `Container` 对象来存储解析后的 TOML 数据，并且你可以通过字典操作来访问和修改其中的值。 这使得逆向工程师可以方便地检查和修改目标程序的配置，而无需手动解析 TOML 格式。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

`container.py` 本身是一个纯 Python 模块，它主要处理的是文本格式的数据（TOML）。它本身不直接涉及到二进制底层、Linux/Android 内核或框架的交互。

然而，它作为 Frida 工具链的一部分，其处理的 TOML 数据 *可以间接地影响* 到 Frida 与这些底层的交互。

**举例说明:**

1. **Frida 模块配置:** Frida 允许开发者编写自定义的 JavaScript 模块来扩展其功能。这些模块的配置信息可能存储在 TOML 文件中。`container.py` 负责解析这些配置文件，并将配置信息传递给 Frida 核心。Frida 核心（是用 C/C++ 编写的）会根据这些配置，与目标进程进行交互，这涉及到内存读写、函数 Hook 等底层操作。

2. **Android 框架 Hook:**  假设一个 Frida 脚本需要 Hook Android 框架中的某个方法。该脚本可能需要从配置文件中读取目标方法所在的类名和方法名。`container.py` 负责解析这个配置文件，然后 Frida 核心会根据解析出的信息，调用 Android Runtime (ART) 提供的 API 来实现 Hook 操作。这涉及到对 Android 虚拟机和底层 Native 代码的理解。

**逻辑推理及假设输入与输出:**

`container.py` 中存在一些逻辑推理，例如在 `append()` 方法中，当添加新的键值对或表时，它会考虑已存在的元素类型和顺序，来决定如何插入新元素，以保持 TOML 文件的结构和格式。

**假设输入与输出:**

**假设输入 1:**

```python
container = Container()
container.add("name", "Alice")
container.add(tomlkit.comment("# This is a comment"))
container.add("age", 30)
```

**输出 1 (通过 `container.as_string()`):**

```toml
name = "Alice"
# This is a comment
age = 30
```

**假设输入 2:**

```python
container = Container()
table = tomlkit.table()
table["city"] = "New York"
container.add("person", table)
```

**输出 2 (通过 `container.as_string()`):**

```toml
[person]
city = "New York"
```

**假设输入 3 (处理带点键):**

```python
container = Container()
container.add("owner.name", "Bob")
container.add("owner.age", 40)
```

**输出 3 (通过 `container.as_string()`):**

```toml
[owner]
name = "Bob"
age = 40
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **尝试添加已存在的键:**

   ```python
   container = Container()
   container.add("name", "Alice")
   try:
       container.add("name", "Bob")
   except KeyAlreadyPresent:
       print("Error: Key 'name' already exists.")
   ```

2. **尝试访问不存在的键:**

   ```python
   container = Container()
   try:
       age = container["age"]
   except NonExistentKey:
       print("Error: Key 'age' does not exist.")
   ```

3. **在需要 Item 对象的地方传递了普通 Python 对象:**  虽然 `container.py` 会尝试转换，但在某些情况下可能导致意外行为。例如，直接将一个字典赋值给一个键，而不是使用 `tomlkit.table()` 创建 `Table` 对象。

4. **不理解 TOML 的结构:** 例如，错误地认为可以直接在一个标量值下添加子键，这在 TOML 中是不允许的。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户安装 Frida 和 Frida 的 Python 绑定:** 这是使用 Frida 的前提。
2. **用户尝试编写 Frida 脚本来操作目标进程的配置文件:** 用户可能需要读取、修改或生成目标进程使用的 TOML 格式的配置文件。
3. **用户在 Frida 脚本中使用了 `tomlkit` 库:** 为了方便地处理 TOML 数据，用户可能会选择使用 `tomlkit` 库。
4. **用户调用 `tomlkit.load()` 或 `tomlkit.loads()` 函数:** 这些函数会调用 `container.py` 中的 `Container` 类来解析 TOML 文件或字符串，并创建一个 `Container` 对象来存储解析后的数据。
5. **用户通过 `Container` 对象的方法（如 `add`、`__getitem__`、`__setitem__` 等）来操作 TOML 数据:**  如果用户在操作过程中遇到了问题，例如添加了重复的键或访问了不存在的键，那么错误信息会指向 `container.py` 中的相关代码，例如 `KeyAlreadyPresent` 异常会在 `append()` 方法中抛出，`NonExistentKey` 异常会在 `item()` 或 `__getitem__` 方法中抛出。

**作为调试线索:**

当在 Frida 脚本中使用 `tomlkit` 遇到错误时，`container.py` 文件可以作为调试的线索：

* **异常类型:**  查看抛出的异常类型（如 `KeyAlreadyPresent`、`NonExistentKey`）可以快速定位问题的性质。
* **堆栈跟踪:** 堆栈跟踪信息会指向 `container.py` 中抛出异常的具体代码行，帮助理解错误发生的上下文。
* **理解 `Container` 类的行为:** 理解 `Container` 类的内部实现，例如 `_map` 和 `_body` 的作用，可以帮助分析数据是如何存储和操作的，从而找到逻辑上的错误。
* **查看相关方法:**  仔细检查 `add`、`append`、`remove`、`item` 等方法的实现，可以了解 TOML 数据是如何被添加、删除和访问的，从而发现潜在的问题。

总而言之，`frida/subprojects/frida-swift/releng/tomlkit/tomlkit/container.py` 是 Frida 工具中处理 TOML 配置文件的核心组件，它提供了存储、管理和操作 TOML 数据的能力，并间接地影响着 Frida 与底层系统和框架的交互。理解这个文件的功能和实现，对于使用 Frida 进行逆向工程和调试是非常有帮助的。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
from __future__ import annotations

import copy

from typing import Any
from typing import Iterator

from tomlkit._compat import decode
from tomlkit._types import _CustomDict
from tomlkit._utils import merge_dicts
from tomlkit.exceptions import KeyAlreadyPresent
from tomlkit.exceptions import NonExistentKey
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import AoT
from tomlkit.items import Comment
from tomlkit.items import Item
from tomlkit.items import Key
from tomlkit.items import Null
from tomlkit.items import SingleKey
from tomlkit.items import Table
from tomlkit.items import Trivia
from tomlkit.items import Whitespace
from tomlkit.items import item as _item


_NOT_SET = object()


class Container(_CustomDict):
    """
    A container for items within a TOMLDocument.

    This class implements the `dict` interface with copy/deepcopy protocol.
    """

    def __init__(self, parsed: bool = False) -> None:
        self._map: dict[SingleKey, int | tuple[int, ...]] = {}
        self._body: list[tuple[Key | None, Item]] = []
        self._parsed = parsed
        self._table_keys = []

    @property
    def body(self) -> list[tuple[Key | None, Item]]:
        return self._body

    def unwrap(self) -> dict[str, Any]:
        """Returns as pure python object (ppo)"""
        unwrapped = {}
        for k, v in self.items():
            if k is None:
                continue

            if isinstance(k, Key):
                k = k.key

            if hasattr(v, "unwrap"):
                v = v.unwrap()

            if k in unwrapped:
                merge_dicts(unwrapped[k], v)
            else:
                unwrapped[k] = v

        return unwrapped

    @property
    def value(self) -> dict[str, Any]:
        """The wrapped dict value"""
        d = {}
        for k, v in self._body:
            if k is None:
                continue

            k = k.key
            v = v.value

            if isinstance(v, Container):
                v = v.value

            if k in d:
                merge_dicts(d[k], v)
            else:
                d[k] = v

        return d

    def parsing(self, parsing: bool) -> None:
        self._parsed = parsing

        for _, v in self._body:
            if isinstance(v, Table):
                v.value.parsing(parsing)
            elif isinstance(v, AoT):
                for t in v.body:
                    t.value.parsing(parsing)

    def add(self, key: Key | Item | str, item: Item | None = None) -> Container:
        """
        Adds an item to the current Container.

        :Example:

        >>> # add a key-value pair
        >>> doc.add('key', 'value')
        >>> # add a comment or whitespace or newline
        >>> doc.add(comment('# comment'))
        """
        if item is None:
            if not isinstance(key, (Comment, Whitespace)):
                raise ValueError(
                    "Non comment/whitespace items must have an associated key"
                )

            key, item = None, key

        return self.append(key, item)

    def _handle_dotted_key(self, key: Key, value: Item) -> None:
        if isinstance(value, (Table, AoT)):
            raise TOMLKitError("Can't add a table to a dotted key")
        name, *mid, last = key
        name._dotted = True
        table = current = Table(Container(True), Trivia(), False, is_super_table=True)
        for _name in mid:
            _name._dotted = True
            new_table = Table(Container(True), Trivia(), False, is_super_table=True)
            current.append(_name, new_table)
            current = new_table

        last.sep = key.sep
        current.append(last, value)

        self.append(name, table)
        return

    def _get_last_index_before_table(self) -> int:
        last_index = -1
        for i, (k, v) in enumerate(self._body):
            if isinstance(v, Null):
                continue  # Null elements are inserted after deletion

            if isinstance(v, Whitespace) and not v.is_fixed():
                continue

            if isinstance(v, (Table, AoT)) and not k.is_dotted():
                break
            last_index = i
        return last_index + 1

    def _validate_out_of_order_table(self, key: SingleKey | None = None) -> None:
        if key is None:
            for k in self._map:
                assert k is not None
                self._validate_out_of_order_table(k)
            return
        if key not in self._map or not isinstance(self._map[key], tuple):
            return
        OutOfOrderTableProxy(self, self._map[key])

    def append(
        self, key: Key | str | None, item: Item, validate: bool = True
    ) -> Container:
        """Similar to :meth:`add` but both key and value must be given."""
        if not isinstance(key, Key) and key is not None:
            key = SingleKey(key)

        if not isinstance(item, Item):
            item = _item(item)

        if key is not None and key.is_multi():
            self._handle_dotted_key(key, item)
            return self

        if isinstance(item, (AoT, Table)) and item.name is None:
            item.name = key.key

        prev = self._previous_item()
        prev_ws = isinstance(prev, Whitespace) or ends_with_whitespace(prev)
        if isinstance(item, Table):
            if not self._parsed:
                item.invalidate_display_name()
            if (
                self._body
                and not (self._parsed or item.trivia.indent or prev_ws)
                and not key.is_dotted()
            ):
                item.trivia.indent = "\n"

        if isinstance(item, AoT) and self._body and not self._parsed:
            item.invalidate_display_name()
            if item and not ("\n" in item[0].trivia.indent or prev_ws):
                item[0].trivia.indent = "\n" + item[0].trivia.indent

        if key is not None and key in self:
            current_idx = self._map[key]
            if isinstance(current_idx, tuple):
                current_body_element = self._body[current_idx[-1]]
            else:
                current_body_element = self._body[current_idx]

            current = current_body_element[1]

            if isinstance(item, Table):
                if not isinstance(current, (Table, AoT)):
                    raise KeyAlreadyPresent(key)

                if item.is_aot_element():
                    # New AoT element found later on
                    # Adding it to the current AoT
                    if not isinstance(current, AoT):
                        current = AoT([current, item], parsed=self._parsed)

                        self._replace(key, key, current)
                    else:
                        current.append(item)

                    return self
                elif current.is_aot():
                    if not item.is_aot_element():
                        # Tried to define a table after an AoT with the same name.
                        raise KeyAlreadyPresent(key)

                    current.append(item)

                    return self
                elif current.is_super_table():
                    if item.is_super_table():
                        # We need to merge both super tables
                        if (
                            key.is_dotted()
                            or current_body_element[0].is_dotted()
                            or self._table_keys[-1] != current_body_element[0]
                        ):
                            if key.is_dotted() and not self._parsed:
                                idx = self._get_last_index_before_table()
                            else:
                                idx = len(self._body)

                            if idx < len(self._body):
                                self._insert_at(idx, key, item)
                            else:
                                self._raw_append(key, item)

                            if validate:
                                self._validate_out_of_order_table(key)

                            return self

                        # Create a new element to replace the old one
                        current = copy.deepcopy(current)
                        for k, v in item.value.body:
                            current.append(k, v)
                        self._body[
                            current_idx[-1]
                            if isinstance(current_idx, tuple)
                            else current_idx
                        ] = (current_body_element[0], current)

                        return self
                    elif current_body_element[0].is_dotted():
                        raise TOMLKitError("Redefinition of an existing table")
                elif not item.is_super_table():
                    raise KeyAlreadyPresent(key)
            elif isinstance(item, AoT):
                if not isinstance(current, AoT):
                    # Tried to define an AoT after a table with the same name.
                    raise KeyAlreadyPresent(key)

                for table in item.body:
                    current.append(table)

                return self
            else:
                raise KeyAlreadyPresent(key)

        is_table = isinstance(item, (Table, AoT))
        if (
            key is not None
            and self._body
            and not self._parsed
            and (not is_table or key.is_dotted())
        ):
            # If there is already at least one table in the current container
            # and the given item is not a table, we need to find the last
            # item that is not a table and insert after it
            # If no such item exists, insert at the top of the table
            last_index = self._get_last_index_before_table()

            if last_index < len(self._body):
                return self._insert_at(last_index, key, item)
            else:
                previous_item = self._body[-1][1]
                if not (
                    isinstance(previous_item, Whitespace)
                    or ends_with_whitespace(previous_item)
                    or "\n" in previous_item.trivia.trail
                ):
                    previous_item.trivia.trail += "\n"

        self._raw_append(key, item)
        return self

    def _raw_append(self, key: Key | None, item: Item) -> None:
        if key in self._map:
            current_idx = self._map[key]
            if not isinstance(current_idx, tuple):
                current_idx = (current_idx,)

            current = self._body[current_idx[-1]][1]
            if key is not None and not isinstance(current, Table):
                raise KeyAlreadyPresent(key)

            self._map[key] = current_idx + (len(self._body),)
        elif key is not None:
            self._map[key] = len(self._body)

        self._body.append((key, item))
        if item.is_table():
            self._table_keys.append(key)

        if key is not None:
            dict.__setitem__(self, key.key, item.value)

        return self

    def _remove_at(self, idx: int) -> None:
        key = self._body[idx][0]
        index = self._map.get(key)
        if index is None:
            raise NonExistentKey(key)
        self._body[idx] = (None, Null())

        if isinstance(index, tuple):
            index = list(index)
            index.remove(idx)
            if len(index) == 1:
                index = index.pop()
            else:
                index = tuple(index)
            self._map[key] = index
        else:
            dict.__delitem__(self, key.key)
            self._map.pop(key)

    def remove(self, key: Key | str) -> Container:
        """Remove a key from the container."""
        if not isinstance(key, Key):
            key = SingleKey(key)

        idx = self._map.pop(key, None)
        if idx is None:
            raise NonExistentKey(key)

        if isinstance(idx, tuple):
            for i in idx:
                self._body[i] = (None, Null())
        else:
            self._body[idx] = (None, Null())

        dict.__delitem__(self, key.key)

        return self

    def _insert_after(
        self, key: Key | str, other_key: Key | str, item: Any
    ) -> Container:
        if key is None:
            raise ValueError("Key cannot be null in insert_after()")

        if key not in self:
            raise NonExistentKey(key)

        if not isinstance(key, Key):
            key = SingleKey(key)

        if not isinstance(other_key, Key):
            other_key = SingleKey(other_key)

        item = _item(item)

        idx = self._map[key]
        # Insert after the max index if there are many.
        if isinstance(idx, tuple):
            idx = max(idx)
        current_item = self._body[idx][1]
        if "\n" not in current_item.trivia.trail:
            current_item.trivia.trail += "\n"

        # Increment indices after the current index
        for k, v in self._map.items():
            if isinstance(v, tuple):
                new_indices = []
                for v_ in v:
                    if v_ > idx:
                        v_ = v_ + 1

                    new_indices.append(v_)

                self._map[k] = tuple(new_indices)
            elif v > idx:
                self._map[k] = v + 1

        self._map[other_key] = idx + 1
        self._body.insert(idx + 1, (other_key, item))

        if key is not None:
            dict.__setitem__(self, other_key.key, item.value)

        return self

    def _insert_at(self, idx: int, key: Key | str, item: Any) -> Container:
        if idx > len(self._body) - 1:
            raise ValueError(f"Unable to insert at position {idx}")

        if not isinstance(key, Key):
            key = SingleKey(key)

        item = _item(item)

        if idx > 0:
            previous_item = self._body[idx - 1][1]
            if not (
                isinstance(previous_item, Whitespace)
                or ends_with_whitespace(previous_item)
                or isinstance(item, (AoT, Table))
                or "\n" in previous_item.trivia.trail
            ):
                previous_item.trivia.trail += "\n"

        # Increment indices after the current index
        for k, v in self._map.items():
            if isinstance(v, tuple):
                new_indices = []
                for v_ in v:
                    if v_ >= idx:
                        v_ = v_ + 1

                    new_indices.append(v_)

                self._map[k] = tuple(new_indices)
            elif v >= idx:
                self._map[k] = v + 1

        if key in self._map:
            current_idx = self._map[key]
            if not isinstance(current_idx, tuple):
                current_idx = (current_idx,)
            self._map[key] = current_idx + (idx,)
        else:
            self._map[key] = idx
        self._body.insert(idx, (key, item))

        dict.__setitem__(self, key.key, item.value)

        return self

    def item(self, key: Key | str) -> Item:
        """Get an item for the given key."""
        if not isinstance(key, Key):
            key = SingleKey(key)

        idx = self._map.get(key)
        if idx is None:
            raise NonExistentKey(key)

        if isinstance(idx, tuple):
            # The item we are getting is an out of order table
            # so we need a proxy to retrieve the proper objects
            # from the parent container
            return OutOfOrderTableProxy(self, idx)

        return self._body[idx][1]

    def last_item(self) -> Item | None:
        """Get the last item."""
        if self._body:
            return self._body[-1][1]

    def as_string(self) -> str:
        """Render as TOML string."""
        s = ""
        for k, v in self._body:
            if k is not None:
                if isinstance(v, Table):
                    s += self._render_table(k, v)
                elif isinstance(v, AoT):
                    s += self._render_aot(k, v)
                else:
                    s += self._render_simple_item(k, v)
            else:
                s += self._render_simple_item(k, v)

        return s

    def _render_table(self, key: Key, table: Table, prefix: str | None = None) -> str:
        cur = ""

        if table.display_name is not None:
            _key = table.display_name
        else:
            _key = key.as_string()

            if prefix is not None:
                _key = prefix + "." + _key

        if not table.is_super_table() or (
            any(
                not isinstance(v, (Table, AoT, Whitespace, Null))
                for _, v in table.value.body
            )
            and not key.is_dotted()
        ):
            open_, close = "[", "]"
            if table.is_aot_element():
                open_, close = "[[", "]]"

            newline_in_table_trivia = (
                "\n" if "\n" not in table.trivia.trail and len(table.value) > 0 else ""
            )
            cur += (
                f"{table.trivia.indent}"
                f"{open_}"
                f"{decode(_key)}"
                f"{close}"
                f"{table.trivia.comment_ws}"
                f"{decode(table.trivia.comment)}"
                f"{table.trivia.trail}"
                f"{newline_in_table_trivia}"
            )
        elif table.trivia.indent == "\n":
            cur += table.trivia.indent

        for k, v in table.value.body:
            if isinstance(v, Table):
                if v.is_super_table():
                    if k.is_dotted() and not key.is_dotted():
                        # Dotted key inside table
                        cur += self._render_table(k, v)
                    else:
                        cur += self._render_table(k, v, prefix=_key)
                else:
                    cur += self._render_table(k, v, prefix=_key)
            elif isinstance(v, AoT):
                cur += self._render_aot(k, v, prefix=_key)
            else:
                cur += self._render_simple_item(
                    k, v, prefix=_key if key.is_dotted() else None
                )

        return cur

    def _render_aot(self, key, aot, prefix=None):
        _key = key.as_string()
        if prefix is not None:
            _key = prefix + "." + _key

        cur = ""
        _key = decode(_key)
        for table in aot.body:
            cur += self._render_aot_table(table, prefix=_key)

        return cur

    def _render_aot_table(self, table: Table, prefix: str | None = None) -> str:
        cur = ""
        _key = prefix or ""
        open_, close = "[[", "]]"

        cur += (
            f"{table.trivia.indent}"
            f"{open_}"
            f"{decode(_key)}"
            f"{close}"
            f"{table.trivia.comment_ws}"
            f"{decode(table.trivia.comment)}"
            f"{table.trivia.trail}"
        )

        for k, v in table.value.body:
            if isinstance(v, Table):
                if v.is_super_table():
                    if k.is_dotted():
                        # Dotted key inside table
                        cur += self._render_table(k, v)
                    else:
                        cur += self._render_table(k, v, prefix=_key)
                else:
                    cur += self._render_table(k, v, prefix=_key)
            elif isinstance(v, AoT):
                cur += self._render_aot(k, v, prefix=_key)
            else:
                cur += self._render_simple_item(k, v)

        return cur

    def _render_simple_item(self, key, item, prefix=None):
        if key is None:
            return item.as_string()

        _key = key.as_string()
        if prefix is not None:
            _key = prefix + "." + _key

        return (
            f"{item.trivia.indent}"
            f"{decode(_key)}"
            f"{key.sep}"
            f"{decode(item.as_string())}"
            f"{item.trivia.comment_ws}"
            f"{decode(item.trivia.comment)}"
            f"{item.trivia.trail}"
        )

    def __len__(self) -> int:
        return dict.__len__(self)

    def __iter__(self) -> Iterator[str]:
        return iter(dict.keys(self))

    # Dictionary methods
    def __getitem__(self, key: Key | str) -> Item | Container:
        item = self.item(key)
        if isinstance(item, Item) and item.is_boolean():
            return item.value

        return item

    def __setitem__(self, key: Key | str, value: Any) -> None:
        if key is not None and key in self:
            old_key = next(filter(lambda k: k == key, self._map))
            self._replace(old_key, key, value)
        else:
            self.append(key, value)

    def __delitem__(self, key: Key | str) -> None:
        self.remove(key)

    def setdefault(self, key: Key | str, default: Any) -> Any:
        super().setdefault(key, default=default)
        return self[key]

    def _replace(self, key: Key | str, new_key: Key | str, value: Item) -> None:
        if not isinstance(key, Key):
            key = SingleKey(key)

        idx = self._map.get(key)
        if idx is None:
            raise NonExistentKey(key)

        self._replace_at(idx, new_key, value)

    def _replace_at(
        self, idx: int | tuple[int], new_key: Key | str, value: Item
    ) -> None:
        value = _item(value)

        if isinstance(idx, tuple):
            for i in idx[1:]:
                self._body[i] = (None, Null())

            idx = idx[0]

        k, v = self._body[idx]
        if not isinstance(new_key, Key):
            if (
                isinstance(value, (AoT, Table)) != isinstance(v, (AoT, Table))
                or new_key != k.key
            ):
                new_key = SingleKey(new_key)
            else:  # Inherit the sep of the old key
                new_key = k

        del self._map[k]
        self._map[new_key] = idx
        if new_key != k:
            dict.__delitem__(self, k)

        if isinstance(value, (AoT, Table)) != isinstance(v, (AoT, Table)):
            # new tables should appear after all non-table values
            self.remove(k)
            for i in range(idx, len(self._body)):
                if isinstance(self._body[i][1], (AoT, Table)):
                    self._insert_at(i, new_key, value)
                    idx = i
                    break
            else:
                idx = -1
                self.append(new_key, value)
        else:
            # Copying trivia
            if not isinstance(value, (Whitespace, AoT)):
                value.trivia.indent = v.trivia.indent
                value.trivia.comment_ws = value.trivia.comment_ws or v.trivia.comment_ws
                value.trivia.comment = value.trivia.comment or v.trivia.comment
                value.trivia.trail = v.trivia.trail
            self._body[idx] = (new_key, value)

        if hasattr(value, "invalidate_display_name"):
            value.invalidate_display_name()  # type: ignore[attr-defined]

        if isinstance(value, Table):
            # Insert a cosmetic new line for tables if:
            # - it does not have it yet OR is not followed by one
            # - it is not the last item, or
            # - The table being replaced has a newline
            last, _ = self._previous_item_with_index()
            idx = last if idx < 0 else idx
            has_ws = ends_with_whitespace(value)
            replace_has_ws = (
                isinstance(v, Table)
                and v.value.body
                and isinstance(v.value.body[-1][1], Whitespace)
            )
            next_ws = idx < last and isinstance(self._body[idx + 1][1], Whitespace)
            if (idx < last or replace_has_ws) and not (next_ws or has_ws):
                value.append(None, Whitespace("\n"))

            dict.__setitem__(self, new_key.key, value.value)

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return repr(self.value)

    def __eq__(self, other: dict) -> bool:
        if not isinstance(other, dict):
            return NotImplemented

        return self.value == other

    def _getstate(self, protocol):
        return (self._parsed,)

    def __reduce__(self):
        return self.__reduce_ex__(2)

    def __reduce_ex__(self, protocol):
        return (
            self.__class__,
            self._getstate(protocol),
            (self._map, self._body, self._parsed, self._table_keys),
        )

    def __setstate__(self, state):
        self._map = state[0]
        self._body = state[1]
        self._parsed = state[2]
        self._table_keys = state[3]

        for key, item in self._body:
            if key is not None:
                dict.__setitem__(self, key.key, item.value)

    def copy(self) -> Container:
        return copy.copy(self)

    def __copy__(self) -> Container:
        c = self.__class__(self._parsed)
        for k, v in dict.items(self):
            dict.__setitem__(c, k, v)

        c._body += self.body
        c._map.update(self._map)

        return c

    def _previous_item_with_index(
        self, idx: int | None = None, ignore=(Null,)
    ) -> tuple[int, Item] | None:
        """Find the immediate previous item before index ``idx``"""
        if idx is None or idx > len(self._body):
            idx = len(self._body)
        for i in range(idx - 1, -1, -1):
            v = self._body[i][-1]
            if not isinstance(v, ignore):
                return i, v
        return None

    def _previous_item(self, idx: int | None = None, ignore=(Null,)) -> Item | None:
        """Find the immediate previous item before index ``idx``.
        If ``idx`` is not given, the last item is returned.
        """
        prev = self._previous_item_with_index(idx, ignore)
        return prev[-1] if prev else None


class OutOfOrderTableProxy(_CustomDict):
    def __init__(self, container: Container, indices: tuple[int]) -> None:
        self._container = container
        self._internal_container = Container(True)
        self._tables = []
        self._tables_map = {}

        for i in indices:
            _, item = self._container._body[i]

            if isinstance(item, Table):
                self._tables.append(item)
                table_idx = len(self._tables) - 1
                for k, v in item.value.body:
                    self._internal_container.append(k, v, validate=False)
                    self._tables_map[k] = table_idx
                    if k is not None:
                        dict.__setitem__(self, k.key, v)

        self._internal_container._validate_out_of_order_table()

    def unwrap(self) -> str:
        return self._internal_container.unwrap()

    @property
    def value(self):
        return self._internal_container.value

    def __getitem__(self, key: Key | str) -> Any:
        if key not in self._internal_container:
            raise NonExistentKey(key)

        return self._internal_container[key]

    def __setitem__(self, key: Key | str, item: Any) -> None:
        if key in self._tables_map:
            table = self._tables[self._tables_map[key]]
            table[key] = item
        elif self._tables:
            table = self._tables[0]
            table[key] = item
        else:
            self._container[key] = item

        self._internal_container[key] = item
        if key is not None:
            dict.__setitem__(self, key, item)

    def _remove_table(self, table: Table) -> None:
        """Remove table from the parent container"""
        self._tables.remove(table)
        for idx, item in enumerate(self._container._body):
            if item[1] is table:
                self._container._remove_at(idx)
                break

    def __delitem__(self, key: Key | str) -> None:
        if key in self._tables_map:
            table = self._tables[self._tables_map[key]]
            del table[key]
            if not table and len(self._tables) > 1:
                self._remove_table(table)
            del self._tables_map[key]
        else:
            raise NonExistentKey(key)

        del self._internal_container[key]
        if key is not None:
            dict.__delitem__(self, key)

    def __iter__(self) -> Iterator[str]:
        return iter(dict.keys(self))

    def __len__(self) -> int:
        return dict.__len__(self)

    def setdefault(self, key: Key | str, default: Any) -> Any:
        super().setdefault(key, default=default)
        return self[key]


def ends_with_whitespace(it: Any) -> bool:
    """Returns ``True`` if the given item ``it`` is a ``Table`` or ``AoT`` object
    ending with a ``Whitespace``.
    """
    return (
        isinstance(it, Table) and isinstance(it.value._previous_item(), Whitespace)
    ) or (isinstance(it, AoT) and len(it) > 0 and isinstance(it[-1], Whitespace))

"""

```