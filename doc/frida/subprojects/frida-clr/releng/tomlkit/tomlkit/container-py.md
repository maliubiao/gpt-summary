Response:
Let's break down the thought process for analyzing this Python code and generating the requested explanations.

**1. Understanding the Core Task:**

The central goal is to analyze a specific Python file (`container.py` from the `tomlkit` library) and explain its functionality in the context of dynamic instrumentation (Frida), reverse engineering, low-level concepts, potential errors, and debugging.

**2. Initial Code Scan and Purpose Identification:**

The first step is to read through the code to get a general idea of what it does. Keywords like `Container`, `Table`, `AoT` (Array of Tables), `Key`, `Item`, and methods like `add`, `append`, `remove`, `render` immediately suggest this code is about representing and manipulating structured data. The filename `tomlkit` hints at the TOML data format. The class `Container` seems like the primary data structure.

**3. Deconstructing Functionality:**

Next, analyze each class and method individually:

* **`Container` Class:** This is the core. Focus on the `__init__`, `add`, `append`, `remove`, `item`, `as_string`, `__getitem__`, `__setitem__`, `__delitem__`, and rendering methods (`_render_table`, `_render_aot`, etc.). Notice the internal representation using `_map` (for key lookups) and `_body` (for ordered items). The `unwrap` and `value` properties suggest different ways to access the underlying data.

* **`OutOfOrderTableProxy` Class:**  This appears to handle a specific case: tables defined out of their natural order in the TOML structure. It acts as a proxy, managing access and modifications for these tables within the main `Container`.

* **Helper Functions:** `ends_with_whitespace` is a utility function for formatting.

**4. Connecting to the Requirements:**

Now, systematically address each of the user's requests:

* **Functionality Listing:** Summarize the purpose of the `Container` class and its key methods. Focus on what actions can be performed (adding, removing, accessing, rendering data).

* **Relationship to Reverse Engineering:** This is where the connection to Frida comes in. Consider *how* manipulating TOML data *within a running process* could be useful. The key idea is modifying configuration, settings, or data structures that an application uses. Think about scenarios like changing server addresses, feature flags, or internal variables. Provide concrete examples to illustrate these use cases.

* **Binary/Low-Level Concepts:**  TOML itself is a text-based format, so direct interaction with raw binary data is unlikely within *this specific file*. However, the *data being represented* by the TOML could influence low-level behavior. Think about configuration files that affect memory allocation, network protocols, or other system resources. Android kernel/framework examples could involve modifying system properties or service configurations (though `tomlkit` might not be the direct tool for those, the *concept* is relevant).

* **Logical Reasoning (Input/Output):**  Choose a simple but illustrative method (like `add` or `append`). Define a clear initial state (an empty container) and a specific input. Predict the output based on the code's logic (the container now holds the added data).

* **Common Usage Errors:** Think about typical mistakes when working with dictionaries or data structures. KeyAlreadyPresent and NonExistentKey errors are explicitly defined in the code, making them good candidates. Explain the scenarios that would lead to these errors.

* **User Path to This Code (Debugging Context):** Imagine a developer using Frida and needing to understand or modify TOML data within an application. Trace the steps: find a TOML structure, identify the need to modify it, use Frida to interact with the application's memory, potentially encounter this `container.py` code while inspecting the relevant objects.

**5. Structuring the Output:**

Organize the information clearly using headings and bullet points, as requested. Provide code examples where appropriate to illustrate the points.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus heavily on the TOML parsing aspects.
* **Correction:** Realize the request is about the *functionality* of the `Container` *class*, not necessarily the intricacies of TOML parsing itself. The focus should be on the manipulation of the data structure.

* **Initial thought:**  Overemphasize low-level binary manipulation within `tomlkit`.
* **Correction:**  Adjust the focus to how the *data represented* by the TOML can influence lower levels, even if `tomlkit` itself doesn't directly touch raw bytes.

* **Initial thought:** Provide very technical code examples for input/output.
* **Correction:** Simplify the examples to be easily understandable and directly related to the chosen methods.

By following these steps, including deconstruction, connection to requirements, and refinement, we can arrive at a comprehensive and accurate explanation of the provided Python code within the requested context.
这是 `frida/subprojects/frida-clr/releng/tomlkit/tomlkit/container.py` 文件的功能列表和相关解释：

**主要功能：**

1. **TOML 数据容器:**  `Container` 类是 `tomlkit` 库中用于存储和操作 TOML (Tom's Obvious, Minimal Language) 数据的核心容器。它类似于 Python 的字典 (dict)，但专门用于表示 TOML 结构。

2. **存储 TOML 项:**  它可以存储各种 TOML 中的基本元素，包括：
    * **键值对 (Key-Value Pairs):**  将键 (`Key`) 与对应的项 (`Item`) 关联起来，项可以是字符串、数字、布尔值、数组、内联表等。
    * **表 (Table):**  表示 TOML 中的 `[section]`，可以包含子键值对和其他子表。
    * **数组表 (Array of Tables, AoT):** 表示 TOML 中的 `[[array_of_tables]]`，用于存储相同结构的多个表。
    * **注释 (Comment):**  存储 TOML 文件中的注释信息。
    * **空白 (Whitespace):**  存储 TOML 文件中的空格和换行符，用于保持格式。

3. **字典接口实现:**  `Container` 类实现了 Python 字典的常用接口，例如 `__getitem__` (通过键访问)、`__setitem__` (设置键值对)、`__delitem__` (删除键)、`__len__` (获取长度)、`__iter__` (迭代键) 等。这使得可以像操作普通字典一样操作 TOML 数据。

4. **添加项 (`add`, `append`):**  提供了方法向容器中添加新的 TOML 项，可以添加键值对、表、数组表、注释和空白。`add` 方法更通用，而 `append` 方法需要同时提供键和项。

5. **删除项 (`remove`):**  可以根据键从容器中删除对应的项。

6. **获取项 (`item`):**  根据键获取对应的 TOML 项对象。

7. **渲染为 TOML 字符串 (`as_string`):**  将容器中的 TOML 数据渲染成符合 TOML 语法的字符串，用于输出或保存到文件。

8. **处理点号键 (`_handle_dotted_key`):**  支持 TOML 中的点号键（例如 `a.b.c`），会自动创建嵌套的表结构来存储这些键值对。

9. **处理无序表 (`OutOfOrderTableProxy`):**  提供了一种机制来处理 TOML 中定义的无序表（在其他键值对之后定义）。`OutOfOrderTableProxy` 充当代理，允许像访问普通表一样访问和修改这些无序表。

10. **复制 (`copy`, `__copy__`):**  支持容器的浅拷贝和深拷贝。

**与逆向方法的关联及举例：**

该文件本身是 `tomlkit` 库的一部分，主要负责 TOML 数据的表示和操作。它与逆向方法的直接关系在于，在逆向工程中，经常需要分析和修改应用程序的配置文件，而 TOML 是一种常见的配置文件格式。

**举例说明:**

假设你正在逆向一个使用 TOML 配置文件存储服务器地址和端口的应用程序。使用 Frida，你可以：

1. **找到配置数据:**  通过内存搜索或 hook 相关函数，找到应用程序中存储 TOML 配置数据的 `Container` 对象。
2. **修改配置:** 使用 Frida 的 Python API，你可以调用 `Container` 对象的方法来修改配置。例如，修改服务器地址：
   ```python
   # 假设 'config_container' 是代表配置数据的 Container 对象
   config_container['server']['address'] = 'new_server_address'
   ```
3. **影响程序行为:**  修改配置后，应用程序可能会连接到新的服务器地址，从而改变其行为。

**二进制底层、Linux、Android 内核及框架知识的关联及举例：**

虽然 `container.py` 文件本身是用 Python 编写的，不直接涉及二进制底层或内核，但它处理的数据 (TOML 配置文件) 可以影响这些方面。

**举例说明:**

1. **二进制底层:**  应用程序的 TOML 配置文件可能会包含影响内存分配大小、缓存策略或其他底层行为的参数。通过修改这些参数，可以在一定程度上影响应用程序的二进制层面的行为。

2. **Linux/Android 内核:** 在 Android 系统中，某些系统服务或框架组件的配置可能使用 TOML 格式。虽然 Frida 通常不直接操作内核层面的数据结构，但如果应用程序读取并使用了这些 TOML 配置，修改这些配置可能会间接影响内核相关的行为（例如，网络配置、权限设置等）。

3. **Android 框架:**  Android 应用程序的某些设置，例如 Activity 的启动模式、权限声明等，可能会通过读取配置文件来确定。如果这些配置文件是 TOML 格式的，那么可以使用 Frida 和 `tomlkit` 来修改这些设置，从而影响应用程序在 Android 框架下的行为。

**逻辑推理 (假设输入与输出):**

假设我们有一个空的 `Container` 对象 `c`：

**假设输入：**

```python
c.add('name', 'Alice')
c.append('age', _item(30)) # _item 是 tomlkit.items.item
c.add(Comment('# This is a comment'))
```

**预期输出：**

`c._body` 将包含以下元素（顺序可能略有不同，取决于内部实现细节）：

```
[(SingleKey('name'), String('Alice', Trivia(), False)),
 (SingleKey('age'), Integer(30, Trivia(), False)),
 (None, Comment('# This is a comment'))]
```

并且 `c._map` 将包含：

```
{SingleKey('name'): 0, SingleKey('age'): 1}
```

**用户或编程常见的使用错误及举例：**

1. **尝试添加已存在的键 (`KeyAlreadyPresent`):**

   ```python
   c.add('name', 'Alice')
   c.add('name', 'Bob')  # 会抛出 KeyAlreadyPresent 异常
   ```

2. **尝试访问不存在的键 (`NonExistentKey`):**

   ```python
   value = c['non_existent_key']  # 会抛出 NonExistentKey 异常
   ```

3. **向点号键添加表 (`TOMLKitError`):**

   ```python
   c.add('a.b', {'c': 1}) # 尝试将字典直接作为值添加到点号键，如果 a.b 已经存在且不是表，会报错
   ```

**用户操作如何一步步到达这里 (调试线索):**

1. **用户使用 Frida 连接到目标进程:** 用户首先使用 Frida 提供的客户端 (例如 Python 或 JavaScript API) 连接到他们想要调试的目标应用程序进程。

2. **用户想要检查或修改 TOML 配置文件:**  用户可能知道或怀疑目标应用程序使用了 TOML 格式的配置文件来存储某些设置。

3. **用户在内存中搜索相关的对象或变量:** 用户可能会使用 Frida 的内存搜索功能，查找包含特定 TOML 键或值的字符串，或者查找已知与配置相关的对象。

4. **用户找到一个 `Container` 对象:** 通过内存搜索或 hook 相关的代码，用户最终找到了一个表示 TOML 配置数据的 `tomlkit.container.Container` 对象实例。

5. **用户尝试理解 `Container` 对象的内容和结构:** 为了理解如何修改配置，用户可能需要查看 `Container` 对象的内部结构，例如 `_body` 和 `_map` 属性。这时，他们可能会查看 `container.py` 的源代码，以了解这些属性的含义和 `Container` 类的方法。

6. **用户使用 `Container` 对象的方法进行操作:**  一旦理解了 `Container` 类的功能，用户就可以使用其提供的方法 (例如 `__getitem__`, `__setitem__`, `add`, `remove`) 来读取、修改或添加 TOML 配置数据。

总而言之，`frida/subprojects/frida-clr/releng/tomlkit/tomlkit/container.py` 文件定义了 `tomlkit` 库中用于表示和操作 TOML 数据的核心容器类，这对于使用 Frida 进行动态 Instrumentation 以分析和修改使用 TOML 配置文件的应用程序至关重要。 了解这个类的功能可以帮助逆向工程师更好地理解应用程序的配置方式，并利用 Frida 动态地改变应用程序的行为。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```