Response:
Let's break down the thought process for analyzing this Python code and generating the response.

**1. Understanding the Request:**

The request asks for several things about the provided Python code:

* **Functionality:** What does the code do?
* **Relationship to Reversing:** How does it connect to reverse engineering?
* **Binary/Kernel/Framework Relevance:** Does it interact with low-level systems?
* **Logical Reasoning:** Can we infer input/output based on the code?
* **Common Usage Errors:** What mistakes might developers make using this code?
* **User Journey:** How does a user end up interacting with this code?

**2. Initial Code Scan - Identifying the Core Purpose:**

The first thing to notice is the class name `Container` and the imports related to `tomlkit`. This immediately suggests the code is about managing data structures, specifically for TOML (Tom's Obvious, Minimal Language) files. TOML is a human-readable configuration file format.

**3. Detailed Analysis - Deconstructing the Functionality:**

Now, let's go through the code block by block, focusing on the methods and their roles:

* **`__init__`:** Initializes the container with dictionaries (`_map`) and lists (`_body`) to store TOML data. The `parsed` flag is important for understanding how parsing is handled.
* **`body`:**  A simple property to access the internal `_body`.
* **`unwrap`:**  Crucial for understanding data representation. It converts the internal structure into standard Python dictionaries, making the TOML data usable.
* **`value`:** Similar to `unwrap` but focuses specifically on the values.
* **`parsing`:**  Indicates whether the container is currently in a parsing state, which affects how new elements are added (e.g., indentation).
* **`add`:**  A user-friendly method to add key-value pairs or standalone elements like comments.
* **`_handle_dotted_key`:** Handles TOML keys with dots (e.g., `owner.name`), creating nested tables.
* **`_get_last_index_before_table`:**  Manages insertion order, ensuring tables are generally placed after non-table entries.
* **`_validate_out_of_order_table`:**  Deals with a specific TOML feature where tables can appear out of logical order.
* **`append`:**  The core method for adding elements. It handles various scenarios, including adding to existing tables, creating arrays of tables (AoT), and dealing with duplicate keys. This is a complex method, and its logic is key to understanding the container's behavior.
* **`_raw_append`:**  The lower-level method for actually adding items to the internal structures.
* **`_remove_at`, `remove`:** Methods for deleting elements.
* **`_insert_after`, `_insert_at`:** Methods for inserting elements at specific positions.
* **`item`:** Retrieves an item based on its key. It also handles the `OutOfOrderTableProxy`.
* **`last_item`:** Gets the last item in the container.
* **`as_string`:**  The crucial method for converting the internal representation back into a TOML string. It handles different TOML elements (tables, AoTs, simple key-value pairs) and their formatting. The `_render_*` helper methods are responsible for the detailed formatting.
* **`__len__`, `__iter__`:** Standard dictionary-like methods.
* **`__getitem__`, `__setitem__`, `__delitem__`:** Implement the dictionary interface for accessing, setting, and deleting items.
* **`setdefault`:**  A standard dictionary method.
* **`_replace`, `_replace_at`:** Methods for modifying existing elements.
* **`__str__`, `__repr__`, `__eq__`:** Standard object representation methods.
* **`_getstate`, `__reduce__`, `__reduce_ex__`, `__setstate__`:**  Methods for pickling and unpickling the object.
* **`copy`, `__copy__`:** Methods for creating copies of the container.
* **`_previous_item_with_index`, `_previous_item`:** Helper methods for finding preceding items.

**4. Connecting to the Request's Specific Points:**

* **Functionality:**  The detailed analysis above covers this. Summarize the key features like storing, manipulating, and serializing TOML data.
* **Reversing:** Think about how TOML files are used in software. Configuration files are common. In reverse engineering, understanding configuration is crucial. Frida often interacts with applications that use configuration. Give concrete examples.
* **Binary/Kernel/Framework:** Consider how configuration plays a role at different levels. Think about application settings, framework parameters (like in Android), or even kernel module configurations (though less directly). Provide examples.
* **Logical Reasoning:**  Choose a simple method like `add` or `append` and demonstrate how a specific input would lead to a predictable output in the internal data structures.
* **Common Usage Errors:**  Think about what mistakes developers might make with a dictionary-like structure, especially considering TOML's specific rules (like duplicate keys).
* **User Journey:** Trace back how someone using Frida might end up needing to manipulate TOML. Think about modifying application behavior through configuration injection.

**5. Structuring the Response:**

Organize the findings into clear sections, addressing each point in the request systematically. Use headings and bullet points for readability. Provide code examples where appropriate.

**6. Refinement and Language:**

Review the generated response for clarity, accuracy, and conciseness. Ensure the language is appropriate for someone with a technical understanding. Use terms like "dynamic instrumentation" and "reverse engineering" correctly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is about parsing TOML.
* **Correction:** While parsing *is* involved (indicated by the `parsed` flag), the core functionality is about *managing* the parsed TOML structure.
* **Initial thought:**  Focus heavily on the individual lines of code.
* **Correction:**  Shift focus to the higher-level functionality of each method and how they interact.
* **Initial thought:**  The connection to reversing might be weak.
* **Correction:**  Realize that configuration files are a key target in reverse engineering, and Frida often interacts with applications that use them.

By following this structured thought process, breaking down the problem, and connecting the code analysis to the specific points in the request, a comprehensive and accurate response can be generated.
这是 `frida/subprojects/frida-core/releng/tomlkit/tomlkit/container.py` 文件，它是 frida 动态插桩工具中用于处理 TOML 配置文件的 `tomlkit` 库的一部分。该文件定义了一个名为 `Container` 的类，该类用于表示 TOML 文档中的一个容器，它可以是整个文档，也可以是 TOML 表格或数组。

以下是 `Container` 类的功能列表：

**核心功能：**

1. **存储和组织 TOML 数据:** `Container` 类使用内部的 `_map` (字典) 和 `_body` (列表) 来存储 TOML 文件中的键值对、表格、数组等结构化数据。`_map` 用于快速查找键对应的元素在 `_body` 中的位置，`_body` 则按顺序存储键值对和其它 TOML 元素。
2. **实现类似字典的接口:** `Container` 类继承自 `_CustomDict` 并实现了 Python 字典的常用接口，例如 `__getitem__`、`__setitem__`、`__delitem__`、`__len__`、`__iter__` 等，使得可以像操作字典一样操作 TOML 数据。
3. **支持 TOML 规范:** 该类能够处理 TOML 规范中定义的各种元素，包括：
    * **键值对:** 存储简单的键值对。
    * **表格 (Table):** 表示 TOML 中的 `[table]` 结构，可以包含子键值对和子表格。
    * **数组 (Array of Tables - AoT):** 表示 TOML 中的 `[[array of tables]]` 结构，用于存储多个具有相同键的表格。
    * **内联表格 (Inline Table):**  虽然 `Container` 本身不直接表示内联表格，但它可以存储和管理内联表格的值。
    * **注释和空白:** 保留 TOML 文件中的注释和空白信息，这对于保持文件格式和可读性很重要。
    * **点分键 (Dotted Keys):** 支持使用点号分隔的键，例如 `owner.name`，用于表示嵌套的结构。
4. **提供数据访问和修改方法:** 提供了 `add`、`append`、`remove`、`_insert_after`、`_insert_at`、`_replace` 等方法来添加、删除、插入和修改 TOML 数据。
5. **支持数据转换:** 提供 `unwrap()` 方法将 `Container` 对象转换为标准的 Python 字典，方便在 Python 代码中使用。`value` 属性也提供了类似的功能。
6. **TOML 序列化:** 提供 `as_string()` 方法将 `Container` 对象序列化回 TOML 格式的字符串。这包括正确地渲染表格、数组、键值对、注释和空白。
7. **复制功能:**  实现了 `copy()` 和 `__copy__()` 方法，可以创建 `Container` 对象的浅拷贝。
8. **处理乱序表格:** 实现了 `OutOfOrderTableProxy` 类来处理 TOML 中允许的乱序表格定义。

**与逆向方法的关联及举例说明:**

`Container` 类在 Frida 这样的动态插桩工具中与逆向方法紧密相关，因为它允许用户读取、修改目标进程的配置信息。许多应用程序使用配置文件（例如 TOML）来存储各种设置，包括服务器地址、API 密钥、功能开关等等。

**举例说明：**

假设一个 Android 应用使用 TOML 文件存储其 API 服务器地址。逆向工程师可以使用 Frida 来：

1. **读取配置文件:** 使用 Frida 脚本读取应用的 TOML 配置文件，并将其解析成 `Container` 对象。
2. **修改配置值:**  通过 `Container` 提供的类似字典的接口，修改存储 API 服务器地址的键对应的值。例如，如果 API 服务器地址存储在 `[network]` 表格的 `api_url` 键中，可以使用类似 `container['network']['api_url'] = '新的服务器地址'` 的方式修改。
3. **将修改后的配置写回 (如果可能):** 虽然 `Container` 本身主要用于表示内存中的 TOML 数据，但在某些情况下，可以将修改后的 `Container` 对象序列化回 TOML 字符串，并尝试将其写回应用的配置文件，或者注入到应用使用的配置管理模块中。
4. **观察应用行为:** 修改配置后，观察应用的行为是否发生了预期的改变，例如应用是否连接到了新的 API 服务器。

**二进制底层、Linux、Android 内核及框架的知识关联及举例说明:**

`Container` 类本身是一个纯粹的 Python 类，主要处理的是 TOML 数据的结构化表示和操作。它并不直接涉及到二进制底层、Linux 或 Android 内核。然而，它在 Frida 工具链中的应用会间接地涉及到这些方面：

**举例说明：**

1. **读取 Android 应用的配置文件:**  在 Android 平台上，应用的配置文件可能存储在 APK 包中或者应用的数据目录下。Frida 脚本需要能够访问这些文件系统路径，这涉及到 Linux 文件系统权限和 Android 应用沙箱的知识。Frida 提供的 API 允许读取目标进程可以访问的文件。
2. **修改内存中的配置:** 更常见的情况是，应用在启动时将配置文件加载到内存中。Frida 可以通过内存操作 API 直接修改目标进程内存中的 TOML 数据结构（即 `Container` 对象或其内部数据）。这需要了解目标进程的内存布局，以及如何使用 Frida 的内存读写功能。
3. **Hook 配置加载函数:** 逆向工程师可能会 hook 应用中负责加载 TOML 配置文件的函数。当这些函数被调用时，Frida 脚本可以拦截并修改加载后的 `Container` 对象，从而在应用使用配置之前修改其内容。这涉及到对目标应用二进制代码的分析和理解，以及 Frida 的函数 hook 功能。
4. **理解 Android 框架的配置机制:** Android 框架本身也使用各种配置文件。虽然 `Container` 主要用于应用级别的配置，但理解 Android 系统如何管理配置（例如通过 `Settings` Provider 等）有助于更全面地进行逆向分析和修改。

**逻辑推理、假设输入与输出:**

假设我们有以下简单的 TOML 内容：

```toml
name = "Tom"
age = 30

[address]
city = "New York"
zip = "10001"
```

**假设输入：**  使用 `tomlkit.parse()` 解析上述 TOML 字符串，得到一个 `Container` 对象 `doc`。

**逻辑推理和输出示例：**

1. **`doc['name']`:**  根据字典接口，`doc['name']` 会返回一个 `String` 类型的 `Item` 对象，其 `value` 属性为 `"Tom"`。
2. **`doc['address']['city']`:**  `doc['address']` 会返回一个表示 `[address]` 表格的 `Container` 对象。然后，`['city']` 操作会返回该子容器中 `city` 键对应的 `String` 类型的 `Item` 对象，其 `value` 属性为 `"New York"`。
3. **`doc.add('email', 'tom@example.com')`:**  调用 `add` 方法后，`doc` 容器会添加一个新的键值对，`email` 对应的值为 `String` 类型的 `Item` 对象，其 `value` 属性为 `"tom@example.com"`。  再次序列化 `doc` 会包含 `email = "tom@example.com"` 这一行。
4. **`doc['address']['street'] = 'Broadway'`:**  如果 `address` 表格中没有 `street` 键，则会添加一个新的键值对。如果存在，则会更新其值。

**用户或编程常见的使用错误及举例说明:**

1. **尝试访问不存在的键:**
   ```python
   # 假设 'country' 键不存在
   try:
       country = doc['country']  # 会抛出 NonExistentKey 异常
   except NonExistentKey:
       print("键 'country' 不存在")
   ```
2. **尝试添加已存在的键 (非表格或 AoT 的情况):**
   ```python
   doc.add('name', 'Jerry') # 会抛出 KeyAlreadyPresent 异常，因为 'name' 已经存在
   ```
3. **在应该使用 `append` 添加表格数组元素时使用了 `add`:**
   ```toml
   [[fruits]]
   name = "apple"

   [[fruits]]
   name = "banana"
   ```
   如果使用 `doc.add('fruits', {'name': 'orange'})`，则会尝试覆盖已有的 `fruits` 键（如果它不是一个 AoT），或者如果 `fruits` 是 AoT，则可能不会按预期添加新元素。应该使用 `doc['fruits'].append({'name': 'orange'})`。
4. **错误地假设 `unwrap()` 返回的是可修改的对象:** `unwrap()` 返回的是一个标准的 Python 字典，对该字典的修改不会直接反映到原始的 `Container` 对象上。需要修改 `Container` 对象本身的方法。
5. **在不应该添加表格到点分键时尝试添加:**
   ```python
   # 假设 doc 中 'owner' 键已经存在且不是表格
   try:
       doc.add('owner.address', {'city': 'London'}) # 会抛出 TOMLKitError
   except TOMLKitError:
       print("不能将表格添加到点分键")
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户正在使用 Frida 脚本来调试一个目标 Android 应用，并且怀疑应用的某些行为是由配置文件控制的。以下是用户操作的可能步骤，最终会涉及到 `container.py`：

1. **编写 Frida 脚本:** 用户开始编写一个 Frida 脚本，目标是读取或修改应用的配置文件。
2. **查找配置文件路径或加载配置的函数:** 用户可能需要通过静态分析或动态分析找到应用配置文件的存储路径，或者找到应用中负责加载配置文件的函数。
3. **使用 Frida API 读取文件或 hook 函数:**
   * **读取文件:** 如果找到了文件路径，用户可能会使用 Frida 的 `Java.open` 或 `Process.enumerateModules` 等 API 来读取文件内容。
   * **Hook 函数:** 如果找到了加载配置的函数，用户会使用 Frida 的 `Interceptor.attach` 来 hook 该函数。
4. **解析 TOML 内容:** 读取到的文件内容（或 hook 到的函数返回的配置数据）是字符串形式的 TOML。用户会使用 `tomlkit` 库（frida-core 的一部分）的 `tomlkit.parse()` 函数来解析这个字符串，创建 `Container` 对象。这一步就直接用到了 `container.py` 中定义的 `Container` 类。
5. **操作 `Container` 对象:**  用户现在可以像操作 Python 字典一样操作 `Container` 对象，读取、修改配置项。
6. **将修改后的配置应用到目标进程 (可选):**
   * **修改内存:** 用户可能会使用 Frida 的内存写入 API 将修改后的 `Container` 对象序列化回 TOML 字符串，并将其写回到目标进程内存中之前加载配置的位置。
   * **调用目标函数:**  如果 hook 了加载配置的函数，用户可以在 hook 的实现中修改 `Container` 对象，然后让原始函数使用修改后的配置。
7. **观察目标应用的行为:** 用户运行修改后的应用，观察其行为是否符合预期，以此验证配置修改是否成功。

**作为调试线索:**

当用户在 Frida 脚本中操作 TOML 数据时遇到问题，例如无法读取特定的配置项，或者修改配置后应用行为没有改变，`container.py` 文件的代码可以作为调试线索：

* **理解数据结构:** 查看 `Container` 类的内部结构 (`_map`, `_body`) 可以帮助理解 TOML 数据是如何被存储和组织的，从而更好地定位问题所在。
* **分析方法实现:**  如果操作 TOML 数据时出现异常，例如 `KeyAlreadyPresent` 或 `NonExistentKey`，查看 `add`、`append`、`remove` 等方法的实现可以帮助理解这些异常的触发条件。
* **查看序列化逻辑:** 如果修改后的配置没有生效，查看 `as_string()` 方法的实现可以帮助理解 TOML 是如何被序列化回字符串的，确保生成的字符串格式正确。
* **理解乱序表格处理:** 如果涉及到乱序表格，了解 `OutOfOrderTableProxy` 的工作原理至关重要。

总而言之，`frida/subprojects/frida-core/releng/tomlkit/tomlkit/container.py` 中的 `Container` 类是 Frida 动态插桩工具中处理 TOML 配置文件的核心组件，它提供了存储、操作和序列化 TOML 数据的能力，这对于逆向工程师分析和修改目标应用的配置信息至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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