Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The core request is to analyze the given Python code snippet for its functionalities, connections to reverse engineering, low-level details (kernel, etc.), logical inferences, potential user errors, and how a user might reach this code during debugging.

**2. Initial Skim and Keyword Recognition:**

First, quickly skim the code, looking for recognizable patterns and keywords. Words like `dict`, `list`, `append`, `remove`, `insert`, `key`, `value`, `table`, `comment`, `whitespace`, `TOML`, and exception names like `KeyAlreadyPresent` and `NonExistentKey` immediately jump out. This gives a high-level idea that the code is dealing with structured data, likely key-value pairs, and has some concept of document structure. The `frida` in the file path is a strong indicator it's related to dynamic instrumentation.

**3. Identifying the Core Class: `Container`**

The `Container` class is central. Its docstring ("A container for items within a TOMLDocument") confirms it's about managing TOML (Tom's Obvious, Minimal Language) data. The methods it implements suggest dictionary-like behavior (`__getitem__`, `__setitem__`, `__delitem__`, `keys`, `items`), but with added structure and ordering considerations.

**4. Analyzing Key Methods and their Functionalities:**

Go through the methods of the `Container` class, focusing on what each one does. Consider the inputs, the internal data structures (`_map`, `_body`), and the outputs.

* **`__init__`:** Initializes the container, using `_map` for key lookups and `_body` for ordered storage.
* **`add`, `append`:** These methods are about adding data. Notice the handling of different types of items (key-value pairs, comments, whitespace), and the special logic for tables and arrays of tables (AoT). The dotted key handling (`_handle_dotted_key`) is important.
* **`remove`:**  Handles deleting items, updating both `_map` and `_body`.
* **`_insert_at`, `_insert_after`:**  Methods for inserting items at specific positions, maintaining order.
* **`item`:** Retrieves an item by key. The `OutOfOrderTableProxy` is a crucial detail here.
* **`as_string`:** Converts the container back into a TOML string. This involves rendering different item types (tables, AoT, simple key-value pairs).
* **Dictionary-like methods (`__getitem__`, `__setitem__`, etc.):**  Implement the dictionary interface.

**5. Connecting to Reverse Engineering and Dynamic Instrumentation:**

At this point, the `frida` context becomes important. Think about *why* a dynamic instrumentation tool would need to parse and manipulate TOML.

* **Configuration:** TOML is often used for configuration files. Frida might need to read or modify the configuration of a running process.
* **Interception and Modification:** During runtime, Frida could intercept data being passed around (which might be serialized as TOML) and modify it.
* **Analyzing Data Structures:** The ability to represent structured data like TOML in a manipulable way within Frida is valuable for inspecting the state of an application.

**6. Identifying Low-Level and Kernel Connections:**

Think about where TOML might come from in a system.

* **Configuration Files:** These are stored on the filesystem, so there's a link to the OS's file system layer.
* **Inter-Process Communication (IPC):**  Though less common than JSON or Protobuf for IPC, TOML *could* be used. This would involve operating system mechanisms for data transfer between processes.
* **Application Frameworks (Android):**  Android uses various configuration files. While TOML isn't a primary format, it's plausible for specific components or libraries to use it.

**7. Logical Inference (Hypothetical Input/Output):**

Choose a simple scenario, like adding a key-value pair, and trace the execution flow through the relevant methods (`add`, `append`). Consider the internal state changes (`_map`, `_body`). Think about how dotted keys are handled.

**8. Identifying User Errors:**

Look for potential pitfalls for someone using this library:

* **Adding Duplicate Keys:** The `KeyAlreadyPresent` exception is a clear indicator of this.
* **Accessing Non-Existent Keys:** The `NonExistentKey` exception.
* **Incorrect Data Types:** Though not explicitly enforced in this code snippet, using the library with the wrong data types could lead to issues later on during serialization or processing.

**9. Tracing User Operations to the Code:**

Imagine a developer using Frida. How would they end up interacting with this `tomlkit` library?

* **Frida Scripting:** A user writes a Frida script to interact with a target application.
* **Configuration Manipulation:** The script aims to read or modify the target's configuration, which is stored in a TOML file.
* **Frida's TOML Parsing:** Frida (or a library it uses, like `tomlkit`) parses the TOML file. The `Container` class comes into play to represent this parsed data.
* **Debugging/Inspection:** If something goes wrong (e.g., the configuration isn't being modified correctly), the developer might step through the Frida script and potentially into the `tomlkit` code to understand what's happening.

**10. Review and Refine:**

Go back through the analysis, ensuring that the explanations are clear, concise, and address all parts of the original request. Check for any inaccuracies or missing details. For example, ensure the explanations about the `OutOfOrderTableProxy` are clear.

This iterative process of skimming, detailed analysis, contextualization, and imagining user scenarios allows for a comprehensive understanding of the code's purpose and its role within a larger system like Frida.
这个 `container.py` 文件是 `tomlkit` 库的核心组件之一，`tomlkit` 是一个用于处理 TOML (Tom's Obvious, Minimal Language) 格式的 Python 库。由于 `frida` 使用 `tomlkit`，我们可以推断这个文件在 `frida` 中用于解析和操作 TOML 格式的配置文件或数据。

下面是这个文件的功能列表，并结合逆向、底层、逻辑推理、用户错误和调试线索进行说明：

**文件功能:**

1. **存储和管理 TOML 数据:** `Container` 类作为一个自定义的字典，用于存储 TOML 文档中的键值对、表格 (tables) 和数组表格 (arrays of tables)。它维护了数据的顺序和结构。
2. **支持 TOML 规范:**  实现了 TOML 规范中关于表格、数组表格、内联表格、点号键 (dotted keys) 等概念的表示和操作。
3. **提供字典接口:** `Container` 类实现了 Python 字典的接口，如 `__getitem__`, `__setitem__`, `__delitem__`, `keys()`, `items()` 等，方便用户以熟悉的方式访问和修改 TOML 数据。
4. **处理注释和空白:**  能够存储和管理 TOML 文件中的注释和空白字符，这对于保留原始格式至关重要。
5. **提供序列化功能:**  `as_string()` 方法可以将 `Container` 对象转换回 TOML 格式的字符串。
6. **支持复制和深复制:**  实现了 `copy` 和 `deepcopy` 方法，可以创建 `Container` 对象的副本。
7. **处理键的添加、删除和更新:** 提供了 `add()`, `append()`, `remove()`, `_replace()` 等方法来管理 `Container` 中的条目。
8. **处理 "Out-of-order" 表格:**  引入了 `OutOfOrderTableProxy` 类来处理 TOML 中表格可以不按声明顺序出现的特性。

**与逆向的关系:**

* **动态配置修改:** 在逆向分析过程中，我们可能需要动态修改目标进程的配置。如果目标进程使用 TOML 作为配置文件格式，Frida 可以使用 `tomlkit` 解析配置，通过操作 `Container` 对象来修改配置项，然后将其写回文件或注入到进程内存中。
    * **举例说明:** 假设一个 Android 应用的设置保存在一个名为 `config.toml` 的文件中，Frida 脚本可以使用 `tomlkit` 读取这个文件，找到名为 `debug_mode` 的布尔值键，将其值从 `false` 修改为 `true`，然后将修改后的配置写回文件或通过其他方式让应用读取新的配置。
* **数据结构分析:**  逆向工程师可以使用 Frida 拦截目标进程中读取 TOML 配置的代码，并使用 `tomlkit` 解析读取到的数据，方便地查看和分析配置信息。
    * **举例说明:**  某个 Linux 守护进程启动时会读取一个 TOML 配置文件。使用 Frida，我们可以在进程加载配置文件后，hook 相关的函数，获取到表示配置数据的 `Container` 对象，然后打印出其内容，从而了解程序的配置信息。

**涉及二进制底层，Linux, Android 内核及框架的知识:**

* **文件系统操作:**  Frida 读取和写入 TOML 配置文件涉及到操作系统 (Linux, Android) 的文件系统 API 调用。`tomlkit` 本身不直接操作文件，但 Frida 会使用标准的文件 I/O 操作来读取文件内容，然后交给 `tomlkit` 解析。
* **进程内存操作:**  在动态修改配置的场景中，Frida 可能需要将修改后的 TOML 数据写入到目标进程的内存空间，这涉及到操作系统提供的进程间通信 (IPC) 或内存操作 API。
* **Android 框架:**  在 Android 平台上，应用程序可能会将配置存储在私有数据目录下。Frida 需要具备访问这些目录的权限。此外，Android 框架也可能使用特定的机制来管理配置信息，Frida 需要了解这些机制才能有效地进行修改。
* **字符编码:** TOML 文件通常使用 UTF-8 编码。`tomlkit` 库需要处理字符编码的转换，这涉及到对底层字符编码知识的理解。`tomlkit._compat.decode` 函数可能就与此有关。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个简单的 TOML 字符串:
  ```toml
  title = "TOML Example"

  [owner]
  name = "Tom Preston-Werner"
  dob = 1979-05-27T07:32:00-08:00
  ```
* **输出 (使用 `Container` 解析后):**  一个 `Container` 对象，其内部的 `_map` 和 `_body` 会存储相应的键值对和结构信息。例如，`_map` 可能包含 `{'title': 0, 'owner': 1}`，`_body` 可能包含 `(SingleKey('title'), Item(...))` 和 `(SingleKey('owner'), Table(...))` 等元素。访问 `container.value` 将会得到一个 Python 字典：
  ```python
  {'title': 'TOML Example', 'owner': {'name': 'Tom Preston-Werner', 'dob': datetime.datetime(1979, 5, 27, 7, 32, tzinfo=datetime.timezone(datetime.timedelta(seconds=-28800)))}}
  ```
* **假设输入:**  调用 `container.add('new_key', 'new_value')`
* **输出:**  `Container` 对象的 `_body` 列表末尾会添加一个新的元组 `(SingleKey('new_key'), Item(...))`，并且 `_map` 会更新为 `{'title': 0, 'owner': 1, 'new_key': 2}` (假设之前只有两个键)。

**用户或编程常见的使用错误:**

* **添加已存在的键:**  如果用户尝试使用 `add` 或 `append` 添加一个已经存在的键，`tomlkit` 会抛出 `KeyAlreadyPresent` 异常。
    * **举例说明:**
      ```python
      container = Container()
      container.add("name", "Original Name")
      try:
          container.add("name", "New Name")
      except KeyAlreadyPresent as e:
          print(f"Error: {e}")
      ```
* **访问不存在的键:**  尝试访问 `Container` 中不存在的键会抛出 `NonExistentKey` 异常。
    * **举例说明:**
      ```python
      container = Container()
      try:
          value = container["non_existent_key"]
      except NonExistentKey as e:
          print(f"Error: {e}")
      ```
* **类型错误:**  虽然 `Container` 存储的是 `Item` 对象，但用户在使用时可能会错误地假设值的类型。
* **不理解 "Out-of-order" 表格:** 用户可能认为表格必须按照声明的顺序出现，但 TOML 允许乱序。`OutOfOrderTableProxy` 的存在是为了处理这种情况，但用户如果不了解这个机制可能会遇到困惑。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户为了逆向某个程序，编写了一个 Frida 脚本。
2. **脚本需要处理 TOML 配置:** 脚本的功能涉及到读取或修改目标程序的 TOML 配置文件。
3. **Frida 脚本使用 `tomlkit`:**  Frida 脚本中使用了 `import tomlkit` 来导入 `tomlkit` 库。
4. **读取 TOML 文件:** 脚本中使用 `tomlkit.load(open('config.toml'))` 或类似的方式加载 TOML 文件内容到 `tomlkit` 的数据结构中，这会创建 `Container` 对象。
5. **操作 `Container` 对象:**  脚本中可能会调用 `container.get('setting')`, `container['new_setting'] = value`, `container.add_table('new_table')` 等方法来访问和修改配置。这些操作会涉及到 `container.py` 文件中的代码。
6. **遇到问题需要调试:**  如果在脚本执行过程中遇到与 TOML 数据处理相关的问题（例如，配置修改没有生效，或者读取到的配置不正确），用户可能会使用 Frida 的调试功能（例如 `console.log` 输出，或者使用更高级的调试工具）来查看 `Container` 对象的内容和状态。
7. **单步调试进入 `tomlkit` 源码:**  如果用户想要深入了解问题的原因，可能会单步调试 Frida 脚本，最终进入 `tomlkit` 库的源代码，例如 `container.py` 文件，来查看 `Container` 对象内部的状态和方法的执行流程。用户可能会关注 `_map` 和 `_body` 的内容，以及各种添加、删除和更新方法是如何工作的。

总而言之，`container.py` 是 `tomlkit` 库中用于表示和操作 TOML 数据结构的核心部分。在 Frida 的上下文中，它主要用于解析和修改目标程序的 TOML 配置文件，帮助逆向工程师进行动态分析和配置修改。 理解这个文件的功能对于使用 Frida 进行涉及 TOML 配置的逆向工程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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