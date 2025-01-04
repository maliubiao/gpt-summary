Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The primary goal is to analyze the provided Python code snippet (`frida/releng/tomlkit/tomlkit/container.py`) and explain its functionality, especially in the context of reverse engineering, binary interaction, kernel/framework knowledge, logical reasoning, user errors, and debugging.

2. **Initial Skim and Identify Key Classes/Concepts:** Quickly read through the code to get a high-level understanding. Notice the class `Container` and the imports related to TOML (`tomlkit`). Keywords like `add`, `append`, `remove`, `item`, `_render_`, `unwrap`, and `value` stand out. The presence of `AoT` (Array of Tables) and `Table` is also significant.

3. **Focus on the `Container` Class:** This is the core of the code. Realize it's designed to represent a TOML document's structure, acting like a dictionary but with added features to maintain formatting and order.

4. **Analyze Key Methods and Their Functionality:** Go through the methods one by one and try to understand their purpose:
    * `__init__`: Initializes the container with internal data structures (`_map`, `_body`).
    * `unwrap`: Converts the TOML structure back into standard Python dictionaries and lists. This is immediately relevant to reverse engineering as it's about data representation.
    * `value`:  Similar to `unwrap`, but focuses on the underlying values.
    * `add`, `append`: Methods for adding new key-value pairs, comments, or whitespace. Notice the special handling for dotted keys.
    * `remove`:  Deletes items from the container.
    * `_render_*`:  Methods for converting the internal representation back into a TOML string. This involves formatting and is crucial for understanding how the data is serialized.
    * `__getitem__`, `__setitem__`, `__delitem__`:  Standard dictionary-like access methods.
    * `copy`, `__copy__`:  Methods for creating copies of the container.

5. **Connect to Reverse Engineering:** Think about how TOML is used in configuration files. Frida uses TOML for configuration. The `Container` class is essential for:
    * **Parsing configuration:**  Frida reads TOML configs, and this class likely plays a role in parsing.
    * **Modifying configuration:**  Frida might allow modifying configs programmatically, and this class would provide the interface for doing so.
    * **Serializing configuration:** When changes are made, the `_render_*` methods would be used to write the updated config back to a file.

6. **Consider Binary Interaction/Kernel/Framework Knowledge:** While the code itself doesn't directly interact with binaries or the kernel, understand the *context*. Frida *does*. Therefore:
    * **Configuration for hooking:** Frida's configuration (potentially managed by this code) defines *what* to hook in a target process. This directly relates to manipulating the binary's behavior.
    * **Inter-process communication:**  While not explicitly in this file, recognize that Frida needs to communicate between the host and the target process. Configuration might play a role in setting up this communication.
    * **Platform specifics:** Although the code is abstract, remember that Frida works on different platforms (Linux, Android). Configuration might have platform-specific settings.

7. **Analyze Logical Reasoning (Assumptions and Outputs):** Look for methods that involve decision-making, like handling dotted keys or adding tables. Create simple examples:
    * **Input:**  Adding a simple key-value pair. **Output:**  The key and value are stored in `_body` and `_map`.
    * **Input:**  Adding a dotted key. **Output:**  Nested `Table` objects are created.
    * **Input:**  Adding a table after a non-table item. **Output:**  The code inserts the table in the correct position to maintain TOML structure.

8. **Identify Potential User Errors:** Think about common mistakes when working with data structures:
    * **Adding duplicate keys:** The `KeyAlreadyPresent` exception is a clear indicator of this.
    * **Accessing non-existent keys:** The `NonExistentKey` exception handles this.
    * **Incorrect data types:** Though not heavily enforced here, consider the possibility of users trying to add data that doesn't fit the TOML format.

9. **Trace User Operations (Debugging Perspective):** Imagine how a user might end up interacting with this code:
    * **Starting Frida:**  Frida likely loads its configuration files.
    * **Script execution:** A Frida script might programmatically access or modify configuration using the `tomlkit` library and this `Container` class.
    * **Debugging a script:** If a script fails to load or behaves unexpectedly, a developer might step into the `tomlkit` code to see how the configuration is being parsed or manipulated.

10. **Address the `OutOfOrderTableProxy` Class:** Understand that this class deals with a specific edge case in TOML parsing – tables defined out of order. It provides a view into the underlying data while maintaining the correct structure.

11. **Structure the Answer:** Organize the findings into the requested categories: functionality, reverse engineering, binary/kernel/framework, logical reasoning, user errors, and debugging. Provide specific examples for each. Use clear and concise language.

12. **Review and Refine:**  Read through the entire analysis to ensure accuracy, clarity, and completeness. Check for any missed points or areas that need further explanation. For example, initially, I might not have emphasized the role of `_map` in maintaining order and efficiently looking up items. Reviewing helps catch such omissions.
`frida/releng/tomlkit/tomlkit/container.py` 文件定义了 `Container` 类，这个类是 `tomlkit` 库中用于表示 TOML 文档内部结构的核心组件。它本质上是一个有序的字典，但为了精确地表示 TOML 文件的格式，它还维护了项（items）的原始顺序、注释、空格等信息。

以下是 `Container` 类的功能及其与逆向、底层知识、逻辑推理、用户错误和调试的关联：

**Container 类的主要功能:**

1. **存储 TOML 数据:** `Container` 实例用于存储从 TOML 文件解析出的键值对。这些键值对可以是基本类型（字符串、数字、布尔值、日期等），也可以是表格 (Table) 或数组表格 (Array of Tables, AoT)。

2. **维护插入顺序:**  与标准的 Python 字典不同，`Container` 保持了键值对插入的顺序，这对于保持 TOML 文件的格式至关重要。

3. **存储元数据:**  除了键值对，`Container` 还存储了与每个项关联的元数据，例如注释 (`Comment`)、空格 (`Whitespace`) 和换行符 (`Trivia`)。这使得 `tomlkit` 能够以与原始文件尽可能一致的方式重新生成 TOML 字符串。

4. **支持点号键 (Dotted Keys):** `Container` 可以处理像 `a.b.c = value` 这样的点号键，将其转化为嵌套的 `Container` 和 `Table` 结构。

5. **支持表格 (Table) 和数组表格 (AoT):** `Container` 可以包含 `Table` 和 `AoT` 类型的项，用于表示 TOML 文件中的表格和数组表格结构。

6. **提供类似字典的接口:**  `Container` 实现了 Python 字典的常用方法，如 `__getitem__`、`__setitem__`、`__delitem__`、`items()`、`keys()`、`values()` 等，使得用户可以使用类似字典的方式访问和操作 TOML 数据。

7. **unwrap() 方法:** 提供将 `Container` 对象及其包含的 `Table` 和 `AoT` 对象转换为标准的 Python 字典和列表结构的方法，方便用户进行数据处理。

8. **as_string() 方法:** 提供将 `Container` 对象重新渲染为 TOML 字符串的方法，保留了原始的格式和元数据。

9. **处理表格的插入和管理:**  特别是对于无序表格 (out-of-order tables)，`Container` 使用 `OutOfOrderTableProxy` 来处理，确保在读取时能够正确地访问这些表格的内容。

**与逆向方法的关联及举例:**

在动态逆向分析中，我们经常需要检查和修改应用程序的配置文件。TOML 是一种常见的配置文件格式。`frida` 作为动态插桩工具，可能需要在运行时读取或修改目标进程的 TOML 配置文件。

* **读取配置文件:** 当目标进程加载 TOML 配置文件时，`frida` 可以使用 hook 技术拦截文件读取操作，并将文件内容交给 `tomlkit` 进行解析，生成 `Container` 对象。通过分析 `Container` 对象的内容，逆向工程师可以了解应用程序的配置信息，例如服务器地址、API 密钥、调试开关等。

* **修改配置文件:** `frida` 也可以利用 `tomlkit` 创建或修改 `Container` 对象，然后将其渲染为 TOML 字符串，并将修改后的内容写回文件或注入到目标进程的内存中。这可以用于动态地修改应用程序的配置，例如启用调试模式、修改服务器地址等，而无需重启应用程序。

**举例说明:**

假设目标 Android 应用的配置文件 `config.toml` 包含以下内容：

```toml
server_address = "https://api.example.com"
debug_mode = false

[database]
host = "localhost"
port = 5432
```

使用 `frida` 脚本，可以读取并修改 `debug_mode`：

```python
import frida
import tomlkit

def on_message(message, data):
    print(f"[*] Message: {message}")

session = frida.attach("com.example.app")
script = session.create_script("""
    const configFilePath = "/data/data/com.example.app/files/config.toml";
    const configContent = readFile(configFilePath);
    send({ type: 'config', payload: configContent });
""")
script.on('message', on_message)
script.load()

# 接收到配置文件内容
# ... (等待 on_message 被调用) ...

# 假设 message.payload 包含了 config.toml 的内容
config_content = message['payload']
config_data = tomlkit.parse(config_content)

# 修改 debug_mode
config_data['debug_mode'] = True

# 将修改后的配置渲染为 TOML 字符串
modified_config_content = tomlkit.dumps(config_data)
print(f"[*] Modified config: {modified_config_content}")

# 可以将 modified_config_content 写回文件或注入到内存中
```

在这个例子中，`tomlkit.parse()` 函数会将 `config.toml` 的内容解析成一个 `Container` 对象。我们可以像操作字典一样访问和修改 `config_data` 中的值。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

`Container` 类本身是一个纯 Python 的数据结构，它并不直接涉及二进制底层、Linux、Android 内核或框架。然而，它在 `frida` 这个动态插桩工具的上下文中，间接地与这些领域相关联。

* **文件路径:** 代码中提到的文件路径 `/data/data/com.example.app/files/config.toml` 是 Android 应用私有数据目录下的一个路径，这涉及到 Android 文件系统的知识。

* **文件操作:** `frida` 脚本中使用 `readFile()` 函数读取文件，这背后涉及到操作系统底层的文件 I/O 操作。在 Linux 和 Android 中，这些操作会通过系统调用进入内核。

* **内存操作:** 如果 `frida` 需要将修改后的配置注入到目标进程的内存中，这会涉及到进程内存管理、地址空间等底层概念。

* **动态链接库 (DLL/SO) 配置:** 一些应用程序的配置可能存储在动态链接库中，`frida` 可以 hook 动态链接库的加载过程，解析其内部的配置数据（如果使用了 TOML 格式）。

**举例说明:**

在 Android 逆向中，一些 native 库可能使用 TOML 配置文件。`frida` 可以 hook `dlopen` 或类似的函数，拦截 native 库的加载，并在加载后解析其内部的 TOML 配置。

**逻辑推理及假设输入与输出:**

`Container` 类内部包含了一些逻辑推理，例如处理点号键、合并字典等。

**假设输入:**

```python
container = Container()
key = Key("a.b.c")
value_item = _item("test")
container._handle_dotted_key(key, value_item)
```

**预期输出:**

`container` 的 `_body` 列表中会包含一个键为 `"a"`，值为一个 `Table` 对象的项。该 `Table` 对象内部又包含一个键为 `"b"`，值为一个 `Table` 对象的项，最终的 `Table` 对象包含键为 `"c"`，值为 `value_item` 的项。

**假设输入:**

```python
container = Container()
container.add("key1", "value1")
container.add(Comment("# This is a comment"))
container.add("key2", "value2")
```

**预期输出:**

`container._body` 将包含三个元素，按照添加的顺序排列：
1. `(SingleKey("key1"), <Item representing "value1">)`
2. `(None, <Comment object>)`
3. `(SingleKey("key2"), <Item representing "value2">)`

**涉及用户或编程常见的使用错误及举例:**

1. **尝试添加已存在的键:**

   ```python
   container = Container()
   container.add("key", "value1")
   try:
       container.add("key", "value2")
   except KeyAlreadyPresent as e:
       print(f"Error: {e}")
   ```

2. **访问不存在的键:**

   ```python
   container = Container()
   try:
       value = container["non_existent_key"]
   except NonExistentKey as e:
       print(f"Error: {e}")
   ```

3. **在需要键值对的地方只添加了值 (非注释或空格):**

   ```python
   container = Container()
   try:
       container.add("just a value")
   except ValueError as e:
       print(f"Error: {e}")
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

当用户使用 `frida` 与目标进程交互，并且涉及到读取或修改 TOML 配置文件时，`tomlkit` 库就会被调用，`Container` 类就会被实例化和使用。以下是一些可能的步骤：

1. **用户编写 `frida` 脚本:** 用户编写一个 Python 脚本，使用 `frida` API 连接到目标进程。

2. **脚本需要读取配置文件:** 脚本可能需要读取目标进程的配置文件以获取某些参数或信息。

3. **`frida` 脚本调用自定义函数或使用 `frida` 提供的工具函数:** 这些函数可能会执行一些操作，导致目标进程读取配置文件。

4. **hook 文件读取操作:** `frida` 脚本可能会使用 `Interceptor` 或类似的 API hook 目标进程的文件读取函数 (如 `open`, `fopen`, `read` 等)。

5. **拦截到配置文件读取:** 当目标进程尝试读取 TOML 配置文件时，hook 被触发。

6. **将文件内容传递给 `tomlkit`:** hook 函数获取到文件内容，并调用 `tomlkit.parse()` 函数。

7. **`tomlkit.parse()` 创建 `Container` 对象:** `tomlkit.parse()` 函数会解析 TOML 文件的内容，并创建一个 `Container` 对象来存储解析后的数据。在这个过程中，`Container` 类的 `__init__`、`add`、`append` 等方法会被调用。

8. **脚本访问 `Container` 对象:** `frida` 脚本可以通过 `tomlkit` 返回的 `Container` 对象访问和操作配置数据。

9. **调试:** 如果在脚本执行过程中出现与配置相关的错误，例如无法找到特定的配置项，或者配置项的值不符合预期，开发者可能会检查 `Container` 对象的内容，查看解析是否正确。他们可能会在关键步骤打印 `Container` 对象的状态，或者单步执行 `tomlkit` 的代码来理解解析过程。

**调试线索:**

* **异常信息:** 例如 `KeyAlreadyPresent` 或 `NonExistentKey` 异常表明在操作 `Container` 对象时出现了键相关的错误。
* **`print(container)`:** 打印 `Container` 对象可以查看其内部存储的键值对和结构。
* **打印 `container.body`:** 查看 `_body` 列表可以了解项的原始顺序和元数据。
* **使用 `tomlkit.dumps(container)`:** 将 `Container` 对象重新渲染为 TOML 字符串，可以检查其格式是否符合预期。
* **单步调试 `tomlkit` 代码:** 使用调试器 (如 `pdb`) 可以单步执行 `tomlkit` 的代码，查看 `Container` 对象是如何构建和操作的。

总而言之，`frida/releng/tomlkit/tomlkit/container.py` 文件中的 `Container` 类是 `tomlkit` 库处理 TOML 数据的核心，它在 `frida` 动态逆向分析中扮演着重要的角色，用于解析、修改和生成 TOML 配置文件，从而实现对目标进程行为的动态控制和观察。虽然 `Container` 类本身是纯 Python 实现，但其应用场景与操作系统底层、内核和框架知识密切相关。

Prompt: 
```
这是目录为frida/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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