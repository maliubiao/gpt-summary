Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding of the Context:**

The first step is recognizing the code's origin and purpose. The prompt explicitly states: "这是目录为frida/subprojects/frida-core/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件". This immediately tells us:

* **Tool:** Frida, a dynamic instrumentation toolkit.
* **Language:** Python.
* **File:** `items.py` within the `tomlkit` subproject of Frida.
* **Purpose:** Likely related to representing items (data structures) within TOML files. TOML is a configuration file format.

**2. High-Level Code Structure Scan:**

Next, I quickly scan the code to identify the major building blocks:

* **Class Definitions:**  I see several classes: `Whitespace`, `Comment`, `Trivia`, `Key`, `Integer`, `Float`, `Boolean`, `Datetime`, `Array`, `AbstractTable`, `Table`, `InlineTable`, `String`, `AoT`, and `Null`. This suggests the code is about modeling different TOML data types and related formatting elements.
* **Inheritance:** Notice the inheritance relationships. Many classes inherit from `Item`. `Table` and `InlineTable` inherit from `AbstractTable`. `Array` and `AoT` have a custom list-like behavior. This indicates a hierarchical structure for representing TOML.
* **Methods:**  I look at common method names like `__init__`, `__str__`, `__repr__`, `unwrap`, `append`, `remove`, `insert`, `__getitem__`, `__setitem__`, `__delitem__`, `copy`, `as_string`. These give clues about how these classes are used and manipulated.
* **Data Attributes:**  Attributes like `_value`, `_trivia`, `name`, `_body` indicate the core data each class holds.

**3. Deep Dive into Individual Classes (Focusing on Functionality):**

Now, I examine each class more closely, focusing on what it *does*:

* **Formatting Elements (`Whitespace`, `Comment`, `Trivia`):**  These are clearly for handling the non-data parts of a TOML file – spaces, newlines, comments. This is crucial for preserving the original formatting when modifying TOML.
* **Basic Data Types (`Integer`, `Float`, `Boolean`, `Datetime`, `String`):**  These represent the fundamental TOML data types. The `unwrap` method is common, suggesting a way to get the raw Python value. The `String` class has extra complexity related to handling different string types and escaping.
* **Collection Types (`Array`, `Table`, `InlineTable`, `AoT`):**
    * **`Array`:**  Represents a TOML array (list). The code shows methods for adding, removing, and modifying elements, while also managing whitespace and commas for formatting.
    * **`AbstractTable`:** A base class for tables, providing common functionality like adding, removing, and accessing key-value pairs.
    * **`Table`:** Represents a standard TOML table (like `[section]`). It has methods for appending items and handling indentation, crucial for structured TOML. The `is_super_table` logic is interesting, indicating an internal representation detail for nested tables.
    * **`InlineTable`:** Represents an inline TOML table (like `{ a = 1, b = 2 }`). It focuses on compact representation.
    * **`AoT` (Array of Tables):** Represents `[[tables]]`. It's essentially a list of `Table` objects.
* **`Key`:** Represents a TOML key, potentially dotted (like `a.b.c`).
* **`Null`:** Represents a non-existent or null value.

**4. Connecting to Reverse Engineering:**

At this point, I consider how this code relates to reverse engineering:

* **Dynamic Instrumentation (Frida):**  Frida allows inspecting and modifying the behavior of running processes. To work with configuration files that might influence a target application's behavior, Frida needs to be able to parse and potentially modify these files.
* **TOML as Configuration:**  Many applications use configuration files like TOML. Reverse engineers often need to understand these configurations to analyze the application's logic or behavior.
* **Modifying Configurations:**  Frida, through `tomlkit`, could be used to change TOML configurations on the fly to test different scenarios or bypass certain checks in the target application.

**5. Identifying Links to Binary, Kernel, Android:**

Now I think about the lower-level aspects:

* **Binary Level (Indirect):** While the Python code itself isn't directly manipulating bits and bytes, it's part of a *tool* (Frida) that *does*. `tomlkit` helps Frida understand configuration files, which can influence how the *binary* behaves.
* **Linux/Android Kernel/Framework (Indirect):**  Applications running on Linux or Android often use configuration files. Frida, running on these platforms, might need to interact with these files to analyze or modify applications. The configuration can affect how the application interacts with the OS and its frameworks.

**6. Logical Reasoning, Assumptions, and Examples:**

I start to formulate examples to illustrate the code's behavior:

* **Adding an item to an array:**  Consider the `Array.append()` method. What happens with whitespace and commas?  I create a mental scenario with specific inputs and expected outputs.
* **Inserting an item into a table:** How does `Table.append()` handle indentation?
* **Common errors:** What could go wrong when using this code?  Trying to assign a slice to an `Array` element is explicitly disallowed.

**7. Tracing User Actions (Debugging Perspective):**

I imagine how a user would end up interacting with this code:

1. A Frida script needs to parse a TOML file.
2. `tomlkit` is used to load and represent the TOML data.
3. The script might then access or modify elements of the parsed TOML structure, leading to the execution of methods within these classes (like `append`, `__setitem__`, etc.).

**8. Summarization (Instruction #2):**

Finally, based on the detailed analysis, I synthesize a concise summary of the code's functionality, reiterating its role in representing and manipulating TOML data structures for Frida.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on Low-Level Details:**  I might initially focus too much on how Frida *uses* this code at the binary level. I need to remember to focus on what *this specific code* does.
* **Clarifying Indirect vs. Direct Relationships:**  It's important to distinguish when the code *directly* deals with low-level concepts and when it's an abstraction used by a tool that *eventually* interacts with those concepts.
* **Ensuring Examples are Clear and Relevant:** My examples need to be specific and clearly illustrate the points I'm making.

By following these steps, combining code examination with contextual knowledge and example generation, I can arrive at a comprehensive and accurate explanation of the provided Python code.
好的，让我们继续分析 `frida/subprojects/frida-core/releng/tomlkit/tomlkit/items.py` 文件的第二部分内容，并归纳其功能。

**功能归纳:**

这部分代码主要定义了用于表示 TOML (Tom's Obvious, Minimal Language) 数据结构的各种 Item 类。这些类不仅存储了 TOML 的值，还包含了格式化信息，如空格、注释、缩进等，以便在修改 TOML 数据后能够尽可能地保留原始格式。

具体来说，这些类实现了以下核心功能：

1. **TOML 数据类型表示:**  定义了各种 Python 类来映射 TOML 的基本数据类型，包括：
    * `Integer`: 整数
    * `Float`: 浮点数
    * `Boolean`: 布尔值
    * `Datetime`: 日期时间
    * `String`: 字符串 (区分不同类型的字符串)
    * `Array`: 数组 (列表)
    * `Table`: 表 (键值对的集合，类似于 Python 的字典)
    * `InlineTable`: 内联表 (紧凑型的表)
    * `AoT`: 数组表 (表的数组)
    * `Null`: 空值

2. **格式化信息存储:** 每个 Item 类都继承自 `Item`，并包含一个 `Trivia` 对象，用于存储与该 Item 相关的格式化信息，例如前后的空格、注释、缩进等。这使得在修改 TOML 数据时，可以保留或调整原始的格式。

3. **数据访问和修改:**  提供了类似于 Python 内置数据类型的接口来访问和修改 TOML 数据，例如：
    * 使用 `__getitem__` 和 `__setitem__` 访问和修改数组和表中的元素。
    * 使用 `append`、`insert`、`remove` 等方法操作数组和表。
    * `unwrap()` 方法可以将 Item 对象转换为 Python 的原生数据类型。

4. **字符串表示:**  每个 Item 类都实现了 `as_string()` 方法，用于将 Item 对象转换回 TOML 格式的字符串表示。

5. **复制功能:**  提供了 `copy()` 方法来实现 Item 对象的浅拷贝。

6. **内部结构管理:**  例如 `Array` 类使用 `_index_map` 来维护逻辑索引和在 `_value` 列表中的实际位置的映射，以便更高效地进行操作。

7. **特殊 Table 类型:**  定义了 `Table` 和 `InlineTable` 两种不同类型的表，分别对应 TOML 中标准表和内联表的语法。

8. **数组表支持:** `AoT` 类用于表示 TOML 中的数组表，它是一个包含多个 `Table` 对象的列表。

9. **空值表示:** `Null` 类用于表示 TOML 中可能存在的逻辑上的空值。

**与逆向方法的关联及举例说明:**

这个文件的代码是 Frida 工具的一部分，而 Frida 常用于动态逆向工程。`tomlkit` 提供了对 TOML 文件的解析和操作能力，这在逆向分析中非常有用，因为许多应用程序使用 TOML 作为配置文件。

**举例说明:**

假设一个 Android 应用使用 TOML 文件存储了一些关键配置，例如服务器地址、API 密钥等。逆向工程师可以使用 Frida 加载这个应用的进程，然后使用 `tomlkit` 解析其配置文件。

```python
import frida
import tomlkit

# 连接到目标应用
session = frida.attach("com.example.app")

# 在目标进程中执行脚本
script = session.create_script("""
    // 假设应用的配置文件路径已知
    var config_path = "/data/data/com.example.app/config.toml";
    var config_content = "";

    // 读取文件内容 (这里只是一个简化的示例，实际操作可能需要更复杂的文件访问方式)
    // ...

    // 使用 tomlkit 解析配置文件
    var tomlkit_module = Module.load("tomlkit");
    var toml_string = tomlkit_module.exports.loads(config_content);

    // 修改配置，例如修改服务器地址
    toml_string.get("network").set("server_address", "new_server_address");

    // 将修改后的 TOML 内容写回文件 (同样是简化示例)
    var new_config_content = tomlkit_module.exports.dumps(toml_string);
    // ...
""")
script.load()
script.wait_for_unload()
```

在这个例子中，`tomlkit` 提供的功能允许逆向工程师：

* **读取应用的 TOML 配置文件:**  获取应用的配置信息。
* **解析 TOML 内容:**  将 TOML 字符串转换为易于操作的数据结构。
* **修改配置项:**  动态地修改应用的配置，例如更改服务器地址，以便将应用重定向到恶意服务器进行分析。
* **重新序列化为 TOML:** 将修改后的数据结构转换回 TOML 格式的字符串。
* **可能写回文件 (需要文件系统访问权限):**  虽然示例中只是展示了修改，但如果具备权限，可以将修改后的配置写回文件，永久改变应用的配置。

**涉及的二进制底层、Linux、Android 内核及框架知识的举例说明:**

虽然 `items.py` 本身是用 Python 编写的，主要处理的是 TOML 数据的逻辑表示，但它作为 Frida 工具的一部分，间接地与底层知识相关联：

* **二进制底层:**  Frida 作为一个动态 instrumentation 工具，其核心功能是修改目标进程的内存和执行流程，这直接涉及到二进制代码的层面。`tomlkit` 使得 Frida 能够理解和操作应用程序使用的配置文件，从而可以影响应用程序的二进制行为。例如，修改配置文件中的某个标志位可能会改变应用程序执行的代码路径。
* **Linux/Android 内核:**  在 Linux 或 Android 平台上运行的应用程序，其行为受到操作系统内核的管理。通过 Frida 修改应用的配置，可能会影响应用与操作系统内核的交互。例如，修改网络相关的配置可能会改变应用的网络连接行为，这涉及到内核的网络协议栈。
* **Android 框架:**  Android 应用依赖于 Android 框架提供的各种服务和 API。通过修改应用的配置，可能会影响应用与 Android 框架的交互方式。例如，修改权限相关的配置可能会影响应用对系统资源的访问。

**逻辑推理的假设输入与输出:**

**假设输入:**  一个 `Array` 对象，其内部 `_value` 列表表示一个包含整数和注释的 TOML 数组：`[ 1, # comment, 2 ]`。

```python
from tomlkit.items import Array, Integer, Comment, Whitespace, Trivia

array_item = Array(Trivia())
array_item._value = [
    Integer(1, "1", Trivia()),
    Whitespace(", "),
    Comment(Trivia(comment="comment")),
    Whitespace(", "),
    Integer(2, "2", Trivia())
]
array_item._reindex() # 重新建立索引
```

**操作:**  调用 `array_item.append(3, comment="another comment")`

**预期输出:**  `array_item` 的内部 `_value` 列表将会变成：

```
[
    Integer(1, "1", Trivia()),
    Whitespace(", "),
    Comment(Trivia(comment="comment")),
    Whitespace(", "),
    Integer(2, "2", Trivia()),
    Whitespace(", "),
    Integer(3, "3", Trivia(indent=" ")),  # 注意缩进
    Comment(Trivia(indent=" ", comment="another comment"))
]
```

并且，`array_item` 的逻辑值也会更新为 `[1, 2, 3]`。注意，`append` 操作会在末尾添加新的元素和注释，并根据上下文添加必要的空格和逗号。

**用户或编程常见的使用错误举例说明:**

1. **尝试将非 Item 类型直接赋值给 Array 或 Table 的元素:**

   ```python
   from tomlkit.items import Array

   my_array = Array(Trivia())
   my_array.append(1) # 正确，会自动转换为 Integer Item
   my_array[0] = "string" # 错误，应该使用 Item 对象
   ```

   **错误原因:** `Array` 和 `Table` 内部存储的是 `Item` 对象，而不是 Python 原生的数据类型。直接赋值非 `Item` 对象会导致类型错误或不一致。

2. **在应该使用 Key 对象的地方使用了字符串:**

   ```python
   from tomlkit.items import Table, Key

   my_table = Table({}, Trivia(), False)
   my_table["my_key"] = 1 # 内部会自动将 "my_key" 转换为 Key 对象
   my_table[Key("another_key")] = 2 # 正确
   ```

   虽然 `Table` 的 `__setitem__` 方法在某些情况下可以接受字符串作为键，但更严谨的做法是使用 `Key` 对象，尤其是在需要更精细地控制键的格式时。

**用户操作是如何一步步到达这里的调试线索:**

当在 Frida 脚本中使用 `tomlkit` 库来操作 TOML 数据时，用户执行的以下操作可能会最终触发 `items.py` 文件中的代码：

1. **加载 TOML 文件:**  用户可能会使用 `tomlkit.load(f)` 或 `tomlkit.loads(s)` 函数来解析 TOML 文件或字符串。这些函数会调用 `tomlkit` 的解析器，解析器会根据 TOML 语法创建 `items.py` 中定义的各种 `Item` 对象来表示 TOML 的结构。

2. **访问 TOML 数据:** 用户可能会通过索引或键来访问解析后的 TOML 数据结构，例如 `doc["section"]["key"]` 或 `array[0]`。这些操作会调用 `Array` 或 `Table` 对象的 `__getitem__` 方法。

3. **修改 TOML 数据:**  用户可能会修改 TOML 数据，例如添加新的元素到数组、修改表中的值等。这些操作会调用 `Array` 的 `append`、`insert` 方法，或者 `Table` 的 `__setitem__`、`append` 方法。

4. **序列化回 TOML:** 用户可能会使用 `tomlkit.dump(doc, f)` 或 `tomlkit.dumps(doc)` 将修改后的 TOML 数据结构转换回 TOML 格式的字符串。这个过程会调用各个 `Item` 对象的 `as_string()` 方法。

**作为调试线索:**  如果在 Frida 脚本中使用 `tomlkit` 时遇到错误，例如类型错误、数据结构异常等，可以检查以下几点：

* **确认加载的 TOML 文件格式是否正确。**
* **检查访问或修改 TOML 数据的方式是否符合 `tomlkit` 的 API 规范。**
* **使用断点或日志输出中间的 `Item` 对象的状态，例如其 `value` 和 `trivia` 属性，来理解数据结构的变化。**
* **仔细阅读错误信息，通常会指示出错的具体方法和参数，从而定位到 `items.py` 中的相关代码。**

总而言之，`frida/subprojects/frida-core/releng/tomlkit/tomlkit/items.py` 定义了 `tomlkit` 库用于表示和操作 TOML 数据结构的核心类，它使得 Frida 能够方便地解析、修改和生成 TOML 配置文件，这在动态逆向工程中是一个非常有用的功能。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
"
                new_values.append(it)
                data_values.append(it.value)
                if add_comma:
                    new_values.append(Whitespace(","))
                    if i != len(items) - 1:
                        new_values.append(Whitespace(" "))
            elif "," not in it.s:
                whitespace += it.s
            else:
                new_values.append(it)
        if whitespace:
            new_values.append(Whitespace(whitespace))
        if comment:
            indent = " " if items else ""
            new_values.append(
                Comment(Trivia(indent=indent, comment=f"# {comment}", trail=""))
            )
        list.extend(self, data_values)
        if len(self._value) > 0:
            last_item = self._value[-1]
            last_value_item = next(
                (
                    v
                    for v in self._value[::-1]
                    if v.value is not None and not isinstance(v.value, Null)
                ),
                None,
            )
            if last_value_item is not None:
                last_value_item.comma = Whitespace(",")
            if last_item.is_whitespace():
                self._value[-1:-1] = self._group_values(new_values)
            else:
                self._value.extend(self._group_values(new_values))
        else:
            self._value.extend(self._group_values(new_values))
        self._reindex()

    def clear(self) -> None:
        """Clear the array."""
        list.clear(self)
        self._index_map.clear()
        self._value.clear()

    def __len__(self) -> int:
        return list.__len__(self)

    def __getitem__(self, key: int | slice) -> Any:
        rv = cast(Item, list.__getitem__(self, key))
        if rv.is_boolean():
            return bool(rv)
        return rv

    def __setitem__(self, key: int | slice, value: Any) -> Any:
        it = item(value, _parent=self)
        list.__setitem__(self, key, it)
        if isinstance(key, slice):
            raise ValueError("slice assignment is not supported")
        if key < 0:
            key += len(self)
        self._value[self._index_map[key]].value = it

    def insert(self, pos: int, value: Any) -> None:
        it = item(value, _parent=self)
        length = len(self)
        if not isinstance(it, (Comment, Whitespace)):
            list.insert(self, pos, it)
        if pos < 0:
            pos += length
            if pos < 0:
                pos = 0

        idx = 0  # insert position of the self._value list
        default_indent = " "
        if pos < length:
            try:
                idx = self._index_map[pos]
            except KeyError as e:
                raise IndexError("list index out of range") from e
        else:
            idx = len(self._value)
            if idx >= 1 and self._value[idx - 1].is_whitespace():
                # The last item is a pure whitespace(\n ), insert before it
                idx -= 1
                if (
                    self._value[idx].indent is not None
                    and "\n" in self._value[idx].indent.s
                ):
                    default_indent = "\n    "
        indent: Item | None = None
        comma: Item | None = Whitespace(",") if pos < length else None
        if idx < len(self._value) and not self._value[idx].is_whitespace():
            # Prefer to copy the indentation from the item after
            indent = self._value[idx].indent
        if idx > 0:
            last_item = self._value[idx - 1]
            if indent is None:
                indent = last_item.indent
            if not isinstance(last_item.value, Null) and "\n" in default_indent:
                # Copy the comma from the last item if 1) it contains a value and
                # 2) the array is multiline
                comma = last_item.comma
            if last_item.comma is None and not isinstance(last_item.value, Null):
                # Add comma to the last item to separate it from the following items.
                last_item.comma = Whitespace(",")
        if indent is None and (idx > 0 or "\n" in default_indent):
            # apply default indent if it isn't the first item or the array is multiline.
            indent = Whitespace(default_indent)
        new_item = _ArrayItemGroup(value=it, indent=indent, comma=comma)
        self._value.insert(idx, new_item)
        self._reindex()

    def __delitem__(self, key: int | slice):
        length = len(self)
        list.__delitem__(self, key)

        if isinstance(key, slice):
            indices_to_remove = list(
                range(key.start or 0, key.stop or length, key.step or 1)
            )
        else:
            indices_to_remove = [length + key if key < 0 else key]
        for i in sorted(indices_to_remove, reverse=True):
            try:
                idx = self._index_map[i]
            except KeyError as e:
                if not isinstance(key, slice):
                    raise IndexError("list index out of range") from e
            else:
                del self._value[idx]
                if (
                    idx == 0
                    and len(self._value) > 0
                    and self._value[idx].indent
                    and "\n" not in self._value[idx].indent.s
                ):
                    # Remove the indentation of the first item if not newline
                    self._value[idx].indent = None
        if len(self._value) > 0:
            v = self._value[-1]
            if not v.is_whitespace():
                # remove the comma of the last item
                v.comma = None

        self._reindex()

    def _getstate(self, protocol=3):
        return list(self._iter_items()), self._trivia, self._multiline


class AbstractTable(Item, _CustomDict):
    """Common behaviour of both :class:`Table` and :class:`InlineTable`"""

    def __init__(self, value: container.Container, trivia: Trivia):
        Item.__init__(self, trivia)

        self._value = value

        for k, v in self._value.body:
            if k is not None:
                dict.__setitem__(self, k.key, v)

    def unwrap(self) -> dict[str, Any]:
        unwrapped = {}
        for k, v in self.items():
            if isinstance(k, Key):
                k = k.key
            if hasattr(v, "unwrap"):
                v = v.unwrap()
            unwrapped[k] = v

        return unwrapped

    @property
    def value(self) -> container.Container:
        return self._value

    @overload
    def append(self: AT, key: None, value: Comment | Whitespace) -> AT:
        ...

    @overload
    def append(self: AT, key: Key | str, value: Any) -> AT:
        ...

    def append(self, key, value):
        raise NotImplementedError

    @overload
    def add(self: AT, key: Comment | Whitespace) -> AT:
        ...

    @overload
    def add(self: AT, key: Key | str, value: Any = ...) -> AT:
        ...

    def add(self, key, value=None):
        if value is None:
            if not isinstance(key, (Comment, Whitespace)):
                msg = "Non comment/whitespace items must have an associated key"
                raise ValueError(msg)

            key, value = None, key

        return self.append(key, value)

    def remove(self: AT, key: Key | str) -> AT:
        self._value.remove(key)

        if isinstance(key, Key):
            key = key.key

        if key is not None:
            dict.__delitem__(self, key)

        return self

    def setdefault(self, key: Key | str, default: Any) -> Any:
        super().setdefault(key, default)
        return self[key]

    def __str__(self):
        return str(self.value)

    def copy(self: AT) -> AT:
        return copy.copy(self)

    def __repr__(self) -> str:
        return repr(self.value)

    def __iter__(self) -> Iterator[str]:
        return iter(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __delitem__(self, key: Key | str) -> None:
        self.remove(key)

    def __getitem__(self, key: Key | str) -> Item:
        return cast(Item, self._value[key])

    def __setitem__(self, key: Key | str, value: Any) -> None:
        if not isinstance(value, Item):
            value = item(value, _parent=self)

        is_replace = key in self
        self._value[key] = value

        if key is not None:
            dict.__setitem__(self, key, value)

        if is_replace:
            return
        m = re.match("(?s)^[^ ]*([ ]+).*$", self._trivia.indent)
        if not m:
            return

        indent = m.group(1)

        if not isinstance(value, Whitespace):
            m = re.match("(?s)^([^ ]*)(.*)$", value.trivia.indent)
            if not m:
                value.trivia.indent = indent
            else:
                value.trivia.indent = m.group(1) + indent + m.group(2)


class Table(AbstractTable):
    """
    A table literal.
    """

    def __init__(
        self,
        value: container.Container,
        trivia: Trivia,
        is_aot_element: bool,
        is_super_table: bool | None = None,
        name: str | None = None,
        display_name: str | None = None,
    ) -> None:
        super().__init__(value, trivia)

        self.name = name
        self.display_name = display_name
        self._is_aot_element = is_aot_element
        self._is_super_table = is_super_table

    @property
    def discriminant(self) -> int:
        return 9

    def __copy__(self) -> Table:
        return type(self)(
            self._value.copy(),
            self._trivia.copy(),
            self._is_aot_element,
            self._is_super_table,
            self.name,
            self.display_name,
        )

    def append(self, key: Key | str | None, _item: Any) -> Table:
        """
        Appends a (key, item) to the table.
        """
        if not isinstance(_item, Item):
            _item = item(_item, _parent=self)

        self._value.append(key, _item)

        if isinstance(key, Key):
            key = next(iter(key)).key
            _item = self._value[key]

        if key is not None:
            dict.__setitem__(self, key, _item)

        m = re.match(r"(?s)^[^ ]*([ ]+).*$", self._trivia.indent)
        if not m:
            return self

        indent = m.group(1)

        if not isinstance(_item, Whitespace):
            m = re.match("(?s)^([^ ]*)(.*)$", _item.trivia.indent)
            if not m:
                _item.trivia.indent = indent
            else:
                _item.trivia.indent = m.group(1) + indent + m.group(2)

        return self

    def raw_append(self, key: Key | str | None, _item: Any) -> Table:
        """Similar to :meth:`append` but does not copy indentation."""
        if not isinstance(_item, Item):
            _item = item(_item)

        self._value.append(key, _item, validate=False)

        if isinstance(key, Key):
            key = next(iter(key)).key
            _item = self._value[key]

        if key is not None:
            dict.__setitem__(self, key, _item)

        return self

    def is_aot_element(self) -> bool:
        """True if the table is the direct child of an AOT element."""
        return self._is_aot_element

    def is_super_table(self) -> bool:
        """A super table is the intermediate parent of a nested table as in [a.b.c].
        If true, it won't appear in the TOML representation."""
        if self._is_super_table is not None:
            return self._is_super_table
        # If the table has only one child and that child is a table, then it is a super table.
        if len(self) != 1:
            return False
        only_child = next(iter(self.values()))
        return isinstance(only_child, (Table, AoT))

    def as_string(self) -> str:
        return self._value.as_string()

    # Helpers

    def indent(self, indent: int) -> Table:
        """Indent the table with given number of spaces."""
        super().indent(indent)

        m = re.match("(?s)^[^ ]*([ ]+).*$", self._trivia.indent)
        if not m:
            indent_str = ""
        else:
            indent_str = m.group(1)

        for _, item in self._value.body:
            if not isinstance(item, Whitespace):
                item.trivia.indent = indent_str + item.trivia.indent

        return self

    def invalidate_display_name(self):
        """Call ``invalidate_display_name`` on the contained tables"""
        self.display_name = None

        for child in self.values():
            if hasattr(child, "invalidate_display_name"):
                child.invalidate_display_name()

    def _getstate(self, protocol: int = 3) -> tuple:
        return (
            self._value,
            self._trivia,
            self._is_aot_element,
            self._is_super_table,
            self.name,
            self.display_name,
        )


class InlineTable(AbstractTable):
    """
    An inline table literal.
    """

    def __init__(
        self, value: container.Container, trivia: Trivia, new: bool = False
    ) -> None:
        super().__init__(value, trivia)

        self._new = new

    @property
    def discriminant(self) -> int:
        return 10

    def append(self, key: Key | str | None, _item: Any) -> InlineTable:
        """
        Appends a (key, item) to the table.
        """
        if not isinstance(_item, Item):
            _item = item(_item, _parent=self)

        if not isinstance(_item, (Whitespace, Comment)):
            if not _item.trivia.indent and len(self._value) > 0 and not self._new:
                _item.trivia.indent = " "
            if _item.trivia.comment:
                _item.trivia.comment = ""

        self._value.append(key, _item)

        if isinstance(key, Key):
            key = key.key

        if key is not None:
            dict.__setitem__(self, key, _item)

        return self

    def as_string(self) -> str:
        buf = "{"
        last_item_idx = next(
            (
                i
                for i in range(len(self._value.body) - 1, -1, -1)
                if self._value.body[i][0] is not None
            ),
            None,
        )
        for i, (k, v) in enumerate(self._value.body):
            if k is None:
                if i == len(self._value.body) - 1:
                    if self._new:
                        buf = buf.rstrip(", ")
                    else:
                        buf = buf.rstrip(",")

                buf += v.as_string()

                continue

            v_trivia_trail = v.trivia.trail.replace("\n", "")
            buf += (
                f"{v.trivia.indent}"
                f'{k.as_string() + ("." if k.is_dotted() else "")}'
                f"{k.sep}"
                f"{v.as_string()}"
                f"{v.trivia.comment}"
                f"{v_trivia_trail}"
            )

            if last_item_idx is not None and i < last_item_idx:
                buf += ","
                if self._new:
                    buf += " "

        buf += "}"

        return buf

    def __setitem__(self, key: Key | str, value: Any) -> None:
        if hasattr(value, "trivia") and value.trivia.comment:
            value.trivia.comment = ""
        super().__setitem__(key, value)

    def __copy__(self) -> InlineTable:
        return type(self)(self._value.copy(), self._trivia.copy(), self._new)

    def _getstate(self, protocol: int = 3) -> tuple:
        return (self._value, self._trivia)


class String(str, Item):
    """
    A string literal.
    """

    def __new__(cls, t, value, original, trivia):
        return super().__new__(cls, value)

    def __init__(self, t: StringType, _: str, original: str, trivia: Trivia) -> None:
        super().__init__(trivia)

        self._t = t
        self._original = original

    def unwrap(self) -> str:
        return str(self)

    @property
    def discriminant(self) -> int:
        return 11

    @property
    def value(self) -> str:
        return self

    def as_string(self) -> str:
        return f"{self._t.value}{decode(self._original)}{self._t.value}"

    def __add__(self: ItemT, other: str) -> ItemT:
        if not isinstance(other, str):
            return NotImplemented
        result = super().__add__(other)
        original = self._original + getattr(other, "_original", other)

        return self._new(result, original)

    def _new(self, result: str, original: str) -> String:
        return String(self._t, result, original, self._trivia)

    def _getstate(self, protocol=3):
        return self._t, str(self), self._original, self._trivia

    @classmethod
    def from_raw(cls, value: str, type_=StringType.SLB, escape=True) -> String:
        value = decode(value)

        invalid = type_.invalid_sequences
        if any(c in value for c in invalid):
            raise InvalidStringError(value, invalid, type_.value)

        escaped = type_.escaped_sequences
        string_value = escape_string(value, escaped) if escape and escaped else value

        return cls(type_, decode(value), string_value, Trivia())


class AoT(Item, _CustomList):
    """
    An array of table literal
    """

    def __init__(
        self, body: list[Table], name: str | None = None, parsed: bool = False
    ) -> None:
        self.name = name
        self._body: list[Table] = []
        self._parsed = parsed

        super().__init__(Trivia(trail=""))

        for table in body:
            self.append(table)

    def unwrap(self) -> list[dict[str, Any]]:
        unwrapped = []
        for t in self._body:
            if hasattr(t, "unwrap"):
                unwrapped.append(t.unwrap())
            else:
                unwrapped.append(t)
        return unwrapped

    @property
    def body(self) -> list[Table]:
        return self._body

    @property
    def discriminant(self) -> int:
        return 12

    @property
    def value(self) -> list[dict[Any, Any]]:
        return [v.value for v in self._body]

    def __len__(self) -> int:
        return len(self._body)

    @overload
    def __getitem__(self, key: slice) -> list[Table]:
        ...

    @overload
    def __getitem__(self, key: int) -> Table:
        ...

    def __getitem__(self, key):
        return self._body[key]

    def __setitem__(self, key: slice | int, value: Any) -> None:
        raise NotImplementedError

    def __delitem__(self, key: slice | int) -> None:
        del self._body[key]
        list.__delitem__(self, key)

    def insert(self, index: int, value: dict) -> None:
        value = item(value, _parent=self)
        if not isinstance(value, Table):
            raise ValueError(f"Unsupported insert value type: {type(value)}")
        length = len(self)
        if index < 0:
            index += length
        if index < 0:
            index = 0
        elif index >= length:
            index = length
        m = re.match("(?s)^[^ ]*([ ]+).*$", self._trivia.indent)
        if m:
            indent = m.group(1)

            m = re.match("(?s)^([^ ]*)(.*)$", value.trivia.indent)
            if not m:
                value.trivia.indent = indent
            else:
                value.trivia.indent = m.group(1) + indent + m.group(2)
        prev_table = self._body[index - 1] if 0 < index and length else None
        next_table = self._body[index + 1] if index < length - 1 else None
        if not self._parsed:
            if prev_table and "\n" not in value.trivia.indent:
                value.trivia.indent = "\n" + value.trivia.indent
            if next_table and "\n" not in next_table.trivia.indent:
                next_table.trivia.indent = "\n" + next_table.trivia.indent
        self._body.insert(index, value)
        list.insert(self, index, value)

    def invalidate_display_name(self):
        """Call ``invalidate_display_name`` on the contained tables"""
        for child in self:
            if hasattr(child, "invalidate_display_name"):
                child.invalidate_display_name()

    def as_string(self) -> str:
        b = ""
        for table in self._body:
            b += table.as_string()

        return b

    def __repr__(self) -> str:
        return f"<AoT {self.value}>"

    def _getstate(self, protocol=3):
        return self._body, self.name, self._parsed


class Null(Item):
    """
    A null item.
    """

    def __init__(self) -> None:
        super().__init__(Trivia(trail=""))

    def unwrap(self) -> None:
        return None

    @property
    def discriminant(self) -> int:
        return -1

    @property
    def value(self) -> None:
        return None

    def as_string(self) -> str:
        return ""

    def _getstate(self, protocol=3) -> tuple:
        return ()

"""


```