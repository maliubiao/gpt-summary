Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its functionality within the context of Frida, reverse engineering, and low-level interactions.

**1. Initial Code Scan and Keyword Recognition:**

First, I'd quickly scan the code, looking for recognizable keywords and patterns:

* **Class `Container`:**  This immediately suggests a data structure that holds other data. The name implies it's a central storage unit.
* **`_map` and `_body`:** These are likely the internal storage mechanisms. `_map` probably maps keys to locations, and `_body` probably holds the actual data in some ordered form (a list of tuples).
* **`add`, `append`, `remove`, `insert`, `replace`:** These are standard methods for manipulating collections, reinforcing the idea of a data container.
* **`unwrap`, `value`, `as_string`:** These suggest different ways to access and represent the data within the container. `unwrap` hints at converting to a standard Python dictionary. `as_string` suggests serialization, likely to TOML format.
* **`Table`, `AoT`, `Key`, `Item`, `Comment`, `Whitespace`:** These names clearly point to elements within a TOML document structure. `Table` and `AoT` (Array of Tables) are core TOML concepts.
* **Exceptions like `KeyAlreadyPresent`, `NonExistentKey`:** Indicate error handling related to key management, standard for dictionary-like structures.
* **`parsing`:**  This might relate to whether the container is currently being built from parsing a TOML document.
* **`copy`, `deepcopy`:** Standard Python mechanisms for object duplication.
* **`OutOfOrderTableProxy`:**  This suggests a special handling mechanism for tables that appear out of the expected order in a TOML file.

**2. Connecting to TOML Concepts:**

The keywords and class names strongly indicate this code deals with TOML (Tom's Obvious, Minimal Language) parsing and manipulation. Knowing the basics of TOML is crucial here:

* **Key-value pairs:** The fundamental building block.
* **Tables:**  Organize key-value pairs into logical groups, denoted by `[table_name]`.
* **Arrays of Tables (AoT):** Allow multiple tables with the same name, denoted by `[[table_name]]`.
* **Dotted keys:**  A way to represent nested structures (e.g., `owner.name = "Tom"`).

**3. Inferring Functionality from Methods:**

Now, let's analyze the methods in more detail, connecting them to TOML concepts:

* **`__init__`:** Initializes the container, likely creating the internal `_map` and `_body`.
* **`add`, `append`:** Add key-value pairs, tables, comments, or whitespace to the container. The handling of dotted keys in `_handle_dotted_key` becomes apparent.
* **`remove`:** Removes an entry based on its key.
* **`insert_after`, `_insert_at`:** Provides fine-grained control over where items are placed in the container, potentially important for preserving the original order of elements in a TOML file.
* **`item`:** Retrieves an item by its key. The `OutOfOrderTableProxy` comes into play here.
* **`unwrap`, `value`:**  Provide different ways to access the data as Python dictionaries. `unwrap` seems to recursively convert nested structures.
* **`as_string`:**  This is crucial for understanding how the container represents the TOML structure as a string. The `_render_table`, `_render_aot`, and `_render_simple_item` methods are responsible for this.

**4. Relating to Frida and Reverse Engineering:**

This is where the context provided in the prompt is essential. Frida is a dynamic instrumentation toolkit. Why would a tool like Frida need to parse and manipulate TOML?

* **Configuration:** Frida might use TOML files for configuration. This code could be responsible for reading and modifying those configurations.
* **Agent Communication:** Frida agents often communicate with the host process. TOML could be used as a format for exchanging data or commands.
* **Instrumentation Logic:**  Perhaps the instrumentation logic itself is defined or configured using TOML.

The ability to parse and manipulate TOML becomes relevant in reverse engineering when:

* **Analyzing Application Configuration:**  Many applications use configuration files, and TOML is becoming increasingly popular. Frida could use this to inspect or modify app settings on the fly.
* **Intercepting Communication:** If an application uses TOML to serialize data for network communication, Frida could use this code to parse and understand the intercepted data.
* **Modifying Behavior:** By changing values in the TOML structure, Frida could alter the application's behavior.

**5. Considering Low-Level and Kernel Aspects:**

While this specific code doesn't directly interact with the kernel or low-level binary operations, the *context* of Frida is important.

* **Frida's Core Functionality:** Frida *does* interact heavily with process memory, function hooks, and system calls. This TOML parsing could be part of a larger Frida agent that *performs* these low-level actions.
* **Configuration of Frida Itself:** Frida's own behavior might be configured using TOML.

**6. Thinking About Logic and Assumptions:**

The code makes assumptions about the structure of TOML documents. For example, the handling of dotted keys and the different ways tables and AoTs are added and managed reflects the TOML specification.

**7. Identifying Potential User Errors:**

By looking at the exception types, we can infer potential errors:

* **`KeyAlreadyPresent`:**  Trying to add a key that already exists.
* **`NonExistentKey`:** Trying to remove or access a key that doesn't exist.
* **`ValueError`:**  Incorrect usage of methods, like trying to add a non-comment without a key.

**8. Tracing User Operations (Debugging Clues):**

To understand how a user might end up interacting with this code:

1. **Frida Script Starts:** A user writes a Frida script.
2. **Configuration Loading:** The script might need to load configuration from a TOML file using `tomlkit`.
3. **Dynamic Modification:** The script could then use the `Container` object to modify these configuration settings based on runtime conditions.
4. **Serialization:**  The modified configuration could then be serialized back to TOML using the `as_string` method, perhaps to be written back to a file or sent over a network.
5. **Inspecting Data:** During debugging, a developer might inspect the `Container` object to see the current state of the TOML data.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this is just a generic TOML parser.
* **Correction:** The file path `frida/subprojects/frida-tools/releng/tomlkit/tomlkit/container.py` strongly suggests it's part of the Frida project and therefore has a specific purpose within that context.
* **Initial thought:**  Focus solely on the low-level aspects.
* **Correction:** While Frida *can* do low-level stuff, this specific file is about data structure manipulation at a higher level (TOML). The connection to low-level comes through Frida's overall purpose.

By following this iterative process of scanning, connecting to domain knowledge (TOML), analyzing methods, and considering the surrounding context (Frida), we can arrive at a comprehensive understanding of the code's functionality and its relevance to the broader domain.
这个 `container.py` 文件是 `tomlkit` 库的核心组件之一，`tomlkit` 是一个用于处理 TOML 格式的 Python 库。而 `tomlkit` 又被 `frida-tools` 项目使用，所以这个文件在 Frida 的动态 instrumentation 过程中扮演着解析和操作 TOML 配置文件的角色。

让我们分解一下它的功能，并结合你提出的几个方面进行说明：

**1. 功能列举:**

* **存储和管理 TOML 数据:** `Container` 类作为一个自定义的字典，用于存储 TOML 文件中的键值对、表格（tables）和数组表格（arrays of tables）。它维护了 TOML 数据的结构和顺序。
* **解析 TOML 结构:** 虽然这个文件本身不负责底层的 TOML 语法解析，但它接收解析后的结果（`parsed=True` 的标志位），并将其组织成易于操作的数据结构。
* **提供类似字典的接口:**  `Container` 类实现了 Python 字典的接口 (如 `__getitem__`, `__setitem__`, `__delitem__`, `items()`, `keys()`, `values()`, `len()`)，使得用户可以用熟悉的方式访问和修改 TOML 数据。
* **支持 TOML 特有的结构:**  它特别处理了 TOML 中的表格（`Table`）和数组表格（`AoT`），以及带点的键（dotted keys）。
* **保持 TOML 格式特性:**  它在添加、删除或修改数据时，会尝试保持原始 TOML 文件的格式，例如注释、空白符和换行符的位置。
* **提供数据访问的不同方式:**  `unwrap()` 方法将 `Container` 对象转换为标准的 Python 字典，方便与不直接支持 `tomlkit` 的代码交互。 `value` 属性也提供了类似的功能，但返回的是原始值的引用。
* **支持复制和深复制:**  实现了 `copy` 和 `deepcopy` 方法，方便创建数据的副本。
* **序列化为 TOML 字符串:** `as_string()` 方法可以将 `Container` 对象转换回符合 TOML 规范的字符串。
* **处理“无序表格” (Out-of-Order Tables):** `OutOfOrderTableProxy` 类用于处理 TOML 文件中表格定义顺序不符合规范的情况，提供了一种访问和修改这些表格的方式。

**2. 与逆向方法的联系 (举例说明):**

在 Frida 的上下文中，这个文件很可能用于处理目标应用程序的配置文件。逆向工程师经常需要查看或修改应用程序的配置来理解其行为或进行特定的测试。

* **示例:** 假设一个 Android 应用程序使用 TOML 文件存储其服务器地址和端口。逆向工程师可以使用 Frida 加载这个配置文件，并通过 `Container` 对象找到并修改服务器地址，将其指向一个由逆向工程师控制的服务器，从而拦截应用程序的网络请求进行分析。

   ```python
   import frida
   import tomlkit

   # ... 连接到目标应用程序 ...

   # 假设我们已经获得了配置文件的内容 (例如，从文件中读取或内存中获取)
   toml_content = """
   [network]
   server_address = "old.example.com"
   server_port = 8080
   """

   doc = tomlkit.parse(toml_content)
   container = doc  # tomlkit.parse 返回的是一个 Document 对象，它继承自 Container

   # 修改服务器地址
   container["network"]["server_address"] = "new.attacker.com"

   # 将修改后的配置序列化回 TOML 字符串
   modified_toml = tomlkit.dumps(doc)

   print(modified_toml)
   # 可以将 modified_toml 写回文件或注入到目标进程的内存中
   ```

* **底层原理:** Frida 可以通过内存搜索找到配置文件在进程内存中的位置，然后读取其内容。`tomlkit` 可以解析这些内容，`Container` 对象则提供了方便的接口来修改配置项。修改后的内容可以写回内存，从而动态改变应用程序的行为。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

虽然 `container.py` 本身没有直接的底层二进制操作，但它在 Frida 的生态系统中，其作用与这些底层知识密切相关：

* **二进制数据解析:**  TOML 文件最终是以二进制形式存储在文件系统或内存中。Frida 需要能够读取这些二进制数据，并将其转换为字符串传递给 `tomlkit` 进行解析。
* **内存操作:** Frida 能够在 Linux 或 Android 等操作系统上，直接读取和修改目标进程的内存。如果配置文件被加载到内存中，Frida 可以找到其地址，读取二进制数据，解析成 `Container` 对象，修改后再将修改后的 TOML 字符串转换回二进制数据写回内存。
* **文件系统交互:**  在 Android 或 Linux 上，应用程序的配置文件通常存储在特定的文件路径下。Frida 可以通过系统调用（例如 `open`, `read`, `write`）与文件系统交互，读取配置文件的内容，使用 `tomlkit` 解析和修改，然后将修改后的内容写回文件。
* **Android 框架:**  在 Android 平台上，应用程序的配置也可能存储在 `SharedPreferences` 或其他 Android 特有的数据存储机制中。Frida 可以通过 Hook Android 框架的 API 来拦截对这些配置的访问，并使用 `tomlkit` 来解析和修改配置数据。

**4. 逻辑推理 (假设输入与输出):**

* **假设输入:** 一个包含嵌套表格和数组表格的 TOML 字符串。
   ```toml
   [database]
   server = "192.168.1.1"
   ports = [ 8001, 8001, 8002 ]
   connection_max = 5000
   enabled = true

   [[servers]]
   ip = "10.0.0.1"
   role = "primary"

   [[servers]]
   ip = "10.0.0.2"
   role = "secondary"
   ```

* **输出 (通过 `container.unwrap()`):** 一个对应的 Python 字典。
   ```python
   {
       'database': {
           'server': '192.168.1.1',
           'ports': [8001, 8001, 8002],
           'connection_max': 5000,
           'enabled': True
       },
       'servers': [
           {'ip': '10.0.0.1', 'role': 'primary'},
           {'ip': '10.0.0.2', 'role': 'secondary'}
       ]
   }
   ```

* **逻辑推理过程:** `tomlkit.parse()` 函数会使用底层的解析器将 TOML 字符串转换为 `Container` 对象。`container.unwrap()` 方法遍历 `Container` 对象的内部结构 (`_body`)，将 `Key` 和 `Item` 对象转换为 Python 的键值对，并处理表格和数组表格的嵌套关系，最终构建成一个标准的 Python 字典。

**5. 用户或编程常见的使用错误 (举例说明):**

* **尝试添加已存在的键:**
   ```python
   import tomlkit

   doc = tomlkit.document()
   doc["name"] = "Alice"
   try:
       doc["name"] = "Bob"  # 报错: KeyAlreadyPresent
   except tomlkit.exceptions.KeyAlreadyPresent as e:
       print(e)

   # 正确的做法是直接修改，或者先删除再添加
   doc["name"] = "Bob"
   ```
* **访问不存在的键:**
   ```python
   import tomlkit

   doc = tomlkit.document()
   try:
       value = doc["age"]  # 报错: NonExistentKey
   except tomlkit.exceptions.NonExistentKey as e:
       print(e)

   # 可以使用 get() 方法并提供默认值
   value = doc.get("age", 0)
   print(value)
   ```
* **在期望简单值的地方添加表格:**
   ```python
   import tomlkit

   doc = tomlkit.document()
   try:
       doc["settings"] = tomlkit.table() # 报错: TOMLKitError: Can't add a table to a dotted key
   except tomlkit.exceptions.TOMLKitError as e:
       print(e)

   # 表格应该在顶层或作为其他表格的子项添加
   sub_table = tomlkit.table()
   sub_table["timeout"] = 10
   doc["settings"] = sub_table
   ```
* **不理解 `add()` 和 `append()` 的区别:**  `add()` 可以添加注释和空白符，而 `append()` 用于添加键值对，并且键是必须的。
   ```python
   import tomlkit

   doc = tomlkit.document()
   doc.append("key", "value")
   doc.add(tomlkit.comment("# This is a comment"))
   try:
       doc.add("just a value") # 报错: ValueError: Non comment/whitespace items must have an associated key
   except ValueError as e:
       print(e)
   ```

**6. 用户操作如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:**  用户想要动态分析一个应用程序，并决定检查或修改其配置文件。
2. **Frida 脚本加载配置文件:**  脚本可能使用类似下面的代码来加载应用程序的 TOML 配置文件。这可能涉及到读取文件或从内存中获取数据。
   ```python
   import frida
   import tomlkit

   # ... 连接到目标进程 ...

   # 假设配置文件路径已知
   config_file_path = "/path/to/app.toml"
   with open(config_file_path, "r") as f:
       toml_content = f.read()

   doc = tomlkit.parse(toml_content)
   container = doc
   ```
3. **Frida 脚本访问或修改配置:**  脚本使用 `container` 对象提供的接口（如 `container["section"]["key"]`）来访问配置值，或者使用 `container["section"]["key"] = new_value` 来修改配置。
4. **调试脚本遇到问题:**  如果脚本在访问或修改配置时遇到错误（例如，`KeyError`，这可能被 `tomlkit` 的异常包裹），或者修改后的配置没有生效，用户可能会需要深入 `tomlkit` 的代码来理解发生了什么。
5. **进入 `container.py`:**  为了调试问题，用户可能会单步执行 Frida 脚本，或者查看 `tomlkit` 的源代码。当代码执行到访问或修改 `Container` 对象的方法时（例如 `__getitem__`, `__setitem__`, `add`, `append`），就会进入 `container.py` 文件。
6. **查看 `_map` 和 `_body`:**  用户可能会检查 `Container` 对象的内部状态，例如 `_map` 字典和 `_body` 列表，来理解 TOML 数据的存储结构和索引方式，从而找出配置项是否存在、键是否正确等等。
7. **分析异常堆栈:**  如果出现异常，用户会查看异常堆栈信息，这会指向 `container.py` 中的具体代码行，帮助定位问题。

总而言之，`container.py` 在 Frida 的动态 instrumentation 过程中扮演着解析和操作 TOML 配置文件的关键角色，为逆向工程师提供了方便的接口来理解和修改目标应用程序的行为。理解这个文件的功能，有助于更好地利用 Frida 进行逆向分析和调试。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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