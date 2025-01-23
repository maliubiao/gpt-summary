Response:
Let's break down the thought process for analyzing the `container.py` file.

**1. Initial Reading and High-Level Understanding:**

The first step is to read through the code to get a general sense of what it's doing. Keywords like `Container`, `Table`, `AoT` (Array of Tables), `Key`, `Item`, and methods like `add`, `append`, `remove`, `render`, and dictionary-like operations (`__getitem__`, `__setitem__`, etc.) immediately suggest this code is dealing with structured data. The presence of "TOML" in the path reinforces this idea – it's likely handling TOML data structures.

**2. Identifying Core Functionality - The `Container` Class:**

The `Container` class is central. Its docstring states it's "A container for items within a TOMLDocument."  This is the core data structure for representing TOML data. I'd focus on understanding its attributes and methods:

* **`_map`:**  A dictionary mapping `SingleKey` to integer indices or tuples of indices. This suggests an efficient way to look up items by key, even if multiple items share the same key (like in Array of Tables).
* **`_body`:** A list of tuples, where each tuple contains a `Key` (or `None` for comments/whitespace) and an `Item`. This seems to be the ordered representation of the TOML data, preserving the sequence of elements.
* **`_parsed`:** A boolean flag, likely indicating whether the container has been fully parsed from a TOML source.
* **Methods like `add`, `append`, `remove`:** These are standard dictionary-like operations for manipulating the container's contents. The difference between `add` and `append` needs closer inspection.
* **Methods like `unwrap`, `value`:** These seem to be about extracting the underlying Python data structures from the `Container`.
* **Methods related to rendering (`as_string`, `_render_table`, `_render_aot`, etc.):**  These handle the conversion of the `Container` back into a TOML string representation.

**3. Focusing on Specific Instructions:**

Now, address each part of the request systematically:

* **"列举一下它的功能" (List its functions):**  This requires summarizing the purpose of the class and its key methods. Think about what operations you can perform with a `Container`. (Storing data, adding/removing items, retrieving items, rendering to string, etc.)

* **"如果它与逆向的方法有关系，请做出对应的举例说明" (If it's related to reverse engineering, provide examples):**  Consider how structured data parsing is used in reverse engineering. Frida is a dynamic instrumentation tool, so the connection likely lies in inspecting and modifying application state at runtime. TOML files are often used for configuration, so the ability to parse and modify them during execution is valuable.

* **"如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明" (If it involves low-level binary, Linux/Android kernel/framework knowledge, provide examples):** This requires thinking about *where* and *how* Frida interacts with the target system. Configuration files often influence low-level behavior. Imagine an Android app using a TOML file to configure native libraries or system services. Frida could modify this TOML to alter that behavior. This bridges the gap between high-level configuration and low-level execution.

* **"如果做了逻辑推理，请给出假设输入与输出" (If it does logical inference, provide example inputs and outputs):**  The code primarily manipulates data structures. Logical inference in the strict AI sense isn't a core function here. However, the code *does* make decisions based on the structure of the TOML data (e.g., handling dotted keys, Array of Tables). Focus on these structural manipulations.

* **"如果涉及用户或者编程常见的使用错误，请举例说明" (If it involves common user/programming errors, provide examples):**  Think about the constraints of TOML and the API provided by the `Container`. Common errors could involve trying to add duplicate keys, adding incorrect data types, or manipulating the container in ways that violate TOML syntax.

* **"说明用户操作是如何一步步的到达这里，作为调试线索" (Explain how a user might reach this code, as debugging clues):** Trace the typical Frida workflow. A user writes a Frida script, which interacts with a target process. If that process reads or writes TOML files, Frida might use the `tomlkit` library (and thus this `container.py` file) internally to handle that data. Focus on the scenarios where TOML parsing and manipulation are necessary.

**4. Deeper Dive into Specific Methods (for more detailed understanding):**

To get a deeper understanding, examine the more complex methods:

* **`_handle_dotted_key`:** How are nested keys handled?
* **`append`:**  How does it deal with adding new items, especially tables and AoTs?  The logic for handling existing keys and merging/appending is crucial.
* **`_raw_append`:** What's the difference between `append` and `_raw_append`?
* **`_render_table`, `_render_aot`, `_render_simple_item`:** How is the TOML string generated, and how is formatting (indentation, comments, etc.) preserved?
* **`OutOfOrderTableProxy`:** What is this class for, and why is it needed?  (Hint: Handling tables that appear out of order in the TOML source).

**5. Structuring the Answer:**

Organize the findings logically, following the structure of the original request. Use clear headings and bullet points to make the information easy to read and understand. Provide concrete examples for each point.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This code just parses TOML."
* **Correction:** "It's more than just parsing. It also provides a mutable representation of the TOML data, allowing for modification and re-serialization."

* **Initial thought about reverse engineering:** "It's used to parse configuration files."
* **Refinement:** "In the context of Frida, it's about *dynamically* inspecting and *modifying* those configurations *during runtime* to influence the target application's behavior."

By following this iterative process of reading, analyzing, and focusing on the specific requirements, one can arrive at a comprehensive and accurate understanding of the `container.py` file and its role within Frida.
这是一个名为 `container.py` 的 Python 源代码文件，它属于 `frida` 动态 instrumentation 工具中的 `tomlkit` 子项目。`tomlkit` 库的作用是解析、修改和生成 TOML (Tom's Obvious, Minimal Language) 格式的配置文件。`container.py` 文件定义了 `Container` 类，这个类是 `tomlkit` 库中用于存储 TOML 文档内容的中心数据结构。

**`container.py` 的功能:**

1. **存储 TOML 数据:** `Container` 类本质上是一个有序的字典（继承自 `_CustomDict`），它用于存储 TOML 文件中的键值对、表格（tables）和数组表格（arrays of tables）。它内部使用 `_map` 字典来快速查找键对应的位置，并使用 `_body` 列表来维护元素的插入顺序和格式（包括注释、空白等）。

2. **表示 TOML 结构:**  `Container` 不仅存储值，还存储与 TOML 元素相关的元数据，如注释 (`Comment`)、空白 (`Whitespace`)、键 (`Key`) 等，从而完整地表示了 TOML 文件的结构和格式。

3. **支持 TOML 规范:**  它实现了 TOML 规范中定义的各种数据结构，包括：
    * 键值对 (key-value pairs)
    * 标准表格 (standard tables)
    * 内联表格 (inline tables，虽然这里没直接体现，但 `Container` 可以存储内联表格解析后的内容)
    * 数组表格 (arrays of tables)
    * 点分键 (dotted keys)

4. **提供类似字典的操作:** `Container` 实现了 Python 字典的接口，允许使用 `[]` 访问、赋值、删除元素，以及使用 `get`、`items`、`keys`、`values` 等方法进行操作。

5. **支持添加和修改 TOML 内容:**  提供了 `add`、`append` 方法用于添加新的键值对、表格或注释等。`__setitem__` 方法可以修改已存在的键的值。

6. **支持删除 TOML 内容:** 提供了 `remove` 和 `__delitem__` 方法用于删除指定的键及其对应的内容。

7. **保持 TOML 格式:**  在添加、修改元素时，会尽量保持 TOML 文件的原始格式，包括缩进、注释和空白。

8. **渲染为 TOML 字符串:**  提供了 `as_string` 方法将 `Container` 对象转换回 TOML 格式的字符串，这个过程会考虑之前存储的格式信息。

9. **深拷贝和浅拷贝:** 支持 `copy` 和 `__copy__` 方法，用于创建 `Container` 对象的副本。

10. **处理点分键:** 能够正确处理 TOML 中的点分键，将其转换为嵌套的 `Container` 或 `Table` 对象。

11. **处理数组表格:** 能够存储和操作 TOML 中的数组表格，并保持其结构。

**与逆向方法的关系及举例说明:**

在动态逆向分析中，配置文件常常包含重要的程序行为参数、API 密钥、服务器地址等信息。`frida` 作为动态 instrumentation 工具，可以利用 `tomlkit` 库来：

* **读取和解析目标进程的 TOML 配置文件:**  逆向工程师可以使用 Frida 脚本读取目标进程加载的 TOML 配置文件，并使用 `tomlkit` 将其解析为 `Container` 对象，方便查看配置信息。

   ```python
   import frida
   import tomlkit

   def on_message(message, data):
       print(message)

   session = frida.attach("目标进程")
   script = session.create_script("""
       var fs = require('fs');
       var tomlkit = require('tomlkit');
       var configPath = "/path/to/config.toml"; // 假设配置文件路径

       try {
           var configFileContent = fs.readFileSync(configPath, 'utf8');
           var config = tomlkit.parse(configFileContent);
           send({type: 'config', payload: JSON.stringify(config)});
       } catch (e) {
           send({type: 'error', payload: e.toString()});
       }
   """)
   script.on('message', on_message)
   script.load()
   # ... 等待消息 ...
   ```

* **修改目标进程的 TOML 配置:**  逆向工程师可以通过修改 `Container` 对象中的数据，然后将其转换回 TOML 字符串，并将其写回文件或注入到目标进程的内存中，从而动态地改变程序的行为。

   ```python
   import frida
   import tomlkit

   def on_message(message, data):
       if message['type'] == 'config':
           config_data = json.loads(message['payload'])
           doc = tomlkit.document()
           doc.update(config_data)

           # 修改配置，假设要修改 "server.address"
           doc['server']['address'] = "new.server.address"

           new_config_toml = tomlkit.dumps(doc)
           print("修改后的配置:\n", new_config_toml)
           # 在实际场景中，你需要将 new_config_toml 写入文件或注入到进程

   # ... (连接 Frida 和加载脚本的代码与上面类似) ...
   ```

* **Hook 目标进程中处理 TOML 配置的代码:** 可以 hook 目标进程中读取或解析 TOML 配置文件的函数，截取其读取的配置内容，或在解析后修改 `Container` 对象，再让程序继续执行，实现动态干预配置加载的过程。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

`container.py` 本身是纯 Python 代码，主要处理 TOML 数据的逻辑表示，直接涉及二进制底层、内核的知识较少。但其在 `frida` 中的应用场景会间接关联到这些方面：

* **文件路径:** 代码中可能需要指定 TOML 配置文件的路径（如上面的 `/path/to/config.toml`），这涉及到文件系统、操作系统路径表示等基本概念，在 Linux 和 Android 上路径的表示方式有所不同。

* **进程内存操作:**  虽然 `container.py` 不直接操作内存，但在 Frida 的上下文中，修改后的 TOML 配置可能需要被注入到目标进程的内存中，替换原有的配置数据。这涉及到进程内存管理、地址空间等底层知识。

* **Hook 技术:**  Frida 的核心功能是 hook，当 hook 读取配置文件的 API 时（例如 Linux 上的 `open`, `read` 或 Android 框架中的相关 API），就需要理解这些 API 的工作方式以及参数传递，这涉及到操作系统 API 和可能的系统调用。

* **Android 框架:** 在 Android 逆向中，应用的配置可能存储在特定的位置，例如 `shared_preferences` 或特定的数据目录下。虽然 `tomlkit` 直接处理 TOML，但定位到这些配置文件的过程需要了解 Android 的文件系统结构和应用数据存储方式。

**逻辑推理及假设输入与输出:**

`Container` 类主要进行数据存储和操作，逻辑推理主要体现在处理 TOML 规范的细节上，例如：

* **处理点分键的逻辑:** 当添加一个点分键 `a.b.c = 1` 时，`Container` 需要判断 `a` 和 `b` 是否已存在，如果不存在则创建对应的 `Table` 对象。

   **假设输入:**
   ```python
   container = Container()
   key = Key.from_string("a.b.c")
   item = _item(1)
   container._handle_dotted_key(key, item)
   ```
   **预期输出:** `container` 的 `_body` 中会包含一个键为 `a` 的 `Table` 对象，该 `Table` 对象的 `value` 又是一个 `Container`，其中包含键为 `b` 的 `Table` 对象，其 `value` 又是一个 `Container`，最终包含键为 `c`，值为 `1` 的键值对。

* **处理数组表格的逻辑:** 当添加一个属于数组表格的元素时，需要将其添加到对应的 `AoT` (Array of Tables) 对象中。

   **假设输入:**
   ```python
   container = Container()
   aot_key = Key.from_string("servers")
   table1 = Table(Container(), Trivia(), False, is_aot_element=True)
   table1.value['host'] = _item("alpha")
   table2 = Table(Container(), Trivia(), False, is_aot_element=True)
   table2.value['host'] = _item("beta")
   aot = AoT([table1, table2])
   container.append(aot_key, aot)
   ```
   **预期输出:** `container` 的 `_body` 中会包含一个键为 `servers` 的 `AoT` 对象，该 `AoT` 对象内部包含两个 `Table` 对象，分别表示数组表格的两个元素。

**用户或编程常见的使用错误及举例说明:**

1. **尝试添加已存在的键:**  TOML 规范中，在同一个表格下不允许存在重复的键。

   ```python
   container = Container()
   container['name'] = "old_name"
   try:
       container['name'] = "new_name" # 这样会替换
   except KeyAlreadyPresent:
       print("Error: Key already exists")

   container.add('key1', 'value1')
   try:
       container.add('key1', 'another_value') # 抛出 KeyAlreadyPresent 异常
   except KeyAlreadyPresent:
       print("Error: Key already exists")
   ```

2. **错误地使用 `add` 方法:** `add` 方法对于非注释和空白的 `Item`，必须同时提供键和值。

   ```python
   container = Container()
   try:
       container.add(Comment("# a comment")) # 正确
       container.add(Whitespace("\n"))      # 正确
       container.add("value")             # 错误，缺少键，抛出 ValueError
   except ValueError as e:
       print(f"Error: {e}")
   ```

3. **尝试在点分键路径中添加表格:** TOML 规范不允许在点分键的中间路径上直接添加表格。

   ```python
   container = Container()
   key = Key.from_string("a.b")
   table = Table(Container())
   try:
       container._handle_dotted_key(key, table) # 抛出 TOMLKitError
   except TOMLKitError as e:
       print(f"Error: {e}")
   ```

4. **假设键存在而直接访问导致 `NonExistentKey` 异常:**

   ```python
   container = Container()
   try:
       value = container['non_existent_key'] # 抛出 NonExistentKey 异常
   except NonExistentKey as e:
       print(f"Error: {e}")

   # 应该先检查键是否存在
   if 'non_existent_key' in container:
       value = container['non_existent_key']
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

当 Frida 用户编写脚本与目标进程交互，并且这个目标进程使用了 TOML 格式的配置文件时，`container.py` 的代码可能会被执行。以下是一个可能的调试线索：

1. **Frida 脚本尝试读取目标进程的配置文件:** 用户编写了一个 Frida 脚本，该脚本尝试读取目标进程使用的 TOML 配置文件。这可能通过调用目标进程的文件操作函数，或者通过内存搜索找到已加载的配置数据。

2. **Frida 脚本使用 `tomlkit` 解析 TOML 数据:**  脚本中使用了 `tomlkit` 库（或者 Frida 内部使用了 `tomlkit`）来解析读取到的 TOML 字符串。`tomlkit.parse()` 函数会将 TOML 数据转换成 `Container` 对象。

3. **`tomlkit` 库调用 `container.py` 中的 `Container` 类:**  在解析过程中，`tomlkit` 库会创建 `Container` 类的实例来存储解析后的 TOML 数据。`container.py` 中的 `__init__` 方法会被调用。

4. **用户尝试访问或修改 `Container` 对象中的数据:**  脚本可能会尝试访问 `Container` 对象中的特定键值，例如 `config['server']['address']`，这会调用 `Container` 类的 `__getitem__` 方法。如果尝试修改，则会调用 `__setitem__` 方法。

5. **在添加或修改过程中触发 `container.py` 中的逻辑:**  例如，如果用户尝试添加一个新的键值对，`Container` 的 `add` 或 `append` 方法会被调用。如果添加的是点分键，则会执行 `_handle_dotted_key` 方法。

6. **可能出现的异常导致调试:** 如果用户操作不当（如尝试添加已存在的键），`container.py` 中可能会抛出 `KeyAlreadyPresent` 等异常。Frida 脚本的错误信息可能会指向 `container.py` 文件的相关代码行，引导用户进行调试。

**示例调试场景:**

假设用户编写了一个 Frida 脚本，尝试修改目标进程的数据库连接地址：

```python
import frida
import tomlkit

def on_message(message, data):
    print(message)

session = frida.attach("目标进程")
script = session.create_script("""
    var fs = require('fs');
    var tomlkit = require('tomlkit');
    var configPath = "/path/to/target.toml";

    try {
        var configFileContent = fs.readFileSync(configPath, 'utf8');
        var config = tomlkit.parse(configFileContent);
        config.database.host = "new_db_host"; // 尝试修改数据库主机地址
        send({type: 'modified_config', payload: tomlkit.dumps(config)});
    } catch (e) {
        send({type: 'error', payload: e.toString()});
    }
""")
script.on('message', on_message)
script.load()
```

如果目标进程的 TOML 配置文件中，数据库配置的结构不是 `config.database.host`，而是 `config.db_settings.host`，那么在执行 `config.database.host = "new_db_host"` 时，由于 `config['database']` 不存在，`container.py` 的 `__getitem__` 方法会抛出 `NonExistentKey` 异常。Frida 的错误信息会包含堆栈跟踪，指向 `container.py` 中抛出异常的位置，从而帮助用户定位错误原因，检查配置文件的结构并修改脚本。

总结来说，`container.py` 是 `tomlkit` 库的核心组成部分，负责以结构化的方式存储和操作 TOML 数据。在 Frida 的动态逆向分析场景中，它使得读取、修改目标进程的 TOML 配置成为可能，为逆向工程师提供了强大的工具。理解 `Container` 类的功能和可能出现的错误，有助于编写更健壮的 Frida 脚本。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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