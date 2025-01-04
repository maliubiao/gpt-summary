Response:
The user is asking for a functional breakdown of the provided Python code snippet, which is a part of the `tomlkit` library within the `frida` project. The request specifically asks to:

1. **List the functionalities** of the code.
2. **Relate to reverse engineering** with examples if applicable.
3. **Mention connections to binary, Linux, Android kernel/frameworks** with examples.
4. **Explain logical reasoning** with input/output examples.
5. **Illustrate common user/programming errors** with examples.
6. **Describe the user journey** to reach this code as a debugging step.
7. **Summarize the overall function** of the code.

This is the second part of a two-part request, so I need to ensure the summary builds on the understanding from the first part (though the first part wasn't provided here).

Let's analyze the code section by section:

**Classes and their functionalities:**

*   **`Array(list, Item, _CustomList)`:**
    *   Represents a TOML array.
    *   Manages a list of `Item` objects.
    *   Handles adding, inserting, deleting, and clearing array elements.
    *   Maintains whitespace and comments within the array.
    *   Supports indexing and slicing.
    *   Includes logic for re-indexing to maintain consistency between the underlying list and the `_value` list which holds `_ArrayItemGroup` objects.
*   **`AbstractTable(Item, _CustomDict)`:**
    *   An abstract base class for `Table` and `InlineTable`.
    *   Provides common functionalities for table-like structures.
    *   Stores key-value pairs.
    *   Offers methods for appending, adding, removing, and getting items.
    *   Includes an `unwrap` method to get the raw dictionary representation.
    *   Manages trivia (whitespace and comments).
*   **`Table(AbstractTable)`:**
    *   Represents a standard TOML table (e.g., `[table_name]`).
    *   Extends `AbstractTable` with table-specific attributes like `is_aot_element` and `is_super_table`.
    *   Includes methods for appending items and managing indentation.
    *   Has a method to `invalidate_display_name`, likely related to how the table is presented or serialized.
*   **`InlineTable(AbstractTable)`:**
    *   Represents an inline TOML table (e.g., `{ key1 = "value1", key2 = "value2" }`).
    *   Extends `AbstractTable` and has specific logic for inline table formatting.
    *   Its `as_string` method formats the output according to inline table syntax.
*   **`String(str, Item)`:**
    *   Represents a TOML string literal.
    *   Stores the string value, the original representation, and the string type (e.g., basic, literal).
    *   Provides an `as_string` method to get the TOML representation of the string.
    *   Includes a `from_raw` class method for creating `String` objects from raw string values.
*   **`AoT(Item, _CustomList)`:**
    *   Represents an Array of Tables (e.g., `[[tables]]`).
    *   Manages a list of `Table` objects.
    *   Supports appending, inserting, and deleting tables.
    *   Has an `unwrap` method to get a list of dictionaries.
    *   Includes logic for maintaining indentation between tables.
*   **`Null(Item)`:**
    *   Represents a null value, although TOML doesn't have explicit null. This might be used internally for handling missing or default values.

**Relating to reverse engineering:**

`tomlkit` is used to parse and manipulate TOML files. In reverse engineering, configuration files are often in TOML format. Tools like Frida might use TOML for their configuration. This code would be relevant for:

*   **Analyzing configuration:** Reading and understanding the configuration of a target application or Frida itself.
*   **Modifying behavior:** Changing configuration values to alter the execution flow or behavior of a target.
*   **Dynamic instrumentation:**  Frida could use this to dynamically update configuration based on runtime conditions.

**Connections to binary, Linux, Android kernel/frameworks:**

While the code itself is high-level Python, its purpose relates to these areas:

*   **Binary analysis:**  Configuration files often dictate how a binary behaves. Understanding and modifying these files is part of binary analysis.
*   **Linux/Android systems:** Applications running on these systems frequently use configuration files. Frida itself runs on these platforms and might interact with system-level configurations.
*   **Android framework:**  Android apps might use TOML for internal configurations. Frida could interact with these configurations within an Android process.

**Logical Reasoning:**

Consider the `Array.insert` method:

*   **Input:** An `Array` object, a position `pos` (integer), and a `value` of any type.
*   **Assumption:** The user wants to insert `value` at the specified `pos` in the array, maintaining TOML formatting (whitespace, commas).
*   **Logic:** The method determines the correct position in the internal `_value` list (which holds formatted items), handles indentation and commas based on the context of insertion, and updates the internal data structures.
*   **Output:** The `Array` object with the new item inserted, and its internal structures updated.

**Common User/Programming Errors:**

*   **Incorrect type for array element:** Trying to insert a dictionary directly into an `Array` might lead to errors if the code expects a specific `Item` type. For example, `my_array.insert(0, {"key": "value"})` might fail if the code expects a basic type or a specific `Item` subclass.
*   **Slicing assignment in `Array.__setitem__`:** The code explicitly raises a `ValueError` for slice assignment. A user might try to do something like `my_array[1:3] = [value1, value2]`, which is not supported.
*   **Incorrectly formatted TOML when creating or modifying:** While this code handles the internal representation, manual creation of `Item` objects with incorrect trivia could lead to malformed TOML output.

**User Journey for Debugging:**

Imagine a scenario where a Frida script is not correctly modifying a TOML configuration file within a target process. The user might:

1. **Write a Frida script:** This script reads the TOML configuration, attempts to modify a specific array, and writes it back.
2. **Run the Frida script:** Attach Frida to the target process and execute the script.
3. **Observe unexpected behavior:** The configuration file is either not updated, gets corrupted, or the target application doesn't behave as expected.
4. **Start debugging:**
    *   Print the internal representation of the `Array` object before and after modification.
    *   Step through the `Array.insert` or `Array.__setitem__` methods using a debugger (if possible).
    *   Realize that the whitespace or comma handling is not as expected, leading to parsing issues.
    *   Examine the `items.py` code to understand how these elements are managed internally, especially the `_ArrayItemGroup` and the logic in `_reindex`.
    *   Identify if the issue is in how the user's script is creating or modifying `Item` objects or if there's a bug in `tomlkit` itself.

**Summary of Functionality:**

This code defines the core data structures for representing and manipulating TOML arrays, tables (both standard and inline), strings, and arrays of tables within the `tomlkit` library. It provides methods for accessing, modifying, and formatting these TOML elements, ensuring that the structural integrity and formatting (including whitespace and comments) of the TOML document are maintained. It's a crucial part of how `tomlkit` allows users to programmatically interact with TOML data.

好的，这是对 `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py` 文件第二部分的分析和功能归纳：

**功能列举：**

这部分代码主要定义了 `tomlkit` 库中用于表示各种 TOML 数据类型的 Python 类，并实现了对这些数据进行操作的方法。具体功能包括：

*   **`Array` 类:**
    *   表示 TOML 中的数组。
    *   存储数组中的 `Item` 对象（可以是其他 TOML 数据类型）。
    *   提供添加 (`append`, `insert`)、删除 (`__delitem__`)、清空 (`clear`) 数组元素的方法。
    *   支持通过索引 (`__getitem__`, `__setitem__`) 访问和修改数组元素。
    *   维护数组元素的顺序、逗号、空格和注释。
    *   内部使用 `_ArrayItemGroup` 管理元素及其格式信息。
*   **`AbstractTable` 类:**
    *   作为 `Table` 和 `InlineTable` 的抽象基类，提供表格类型的通用功能。
    *   存储键值对，键可以是字符串或 `Key` 对象，值可以是任何 `Item` 对象。
    *   提供添加 (`append`, `add`)、删除 (`remove`, `__delitem__`)、获取 (`__getitem__`)、设置 (`__setitem__`) 表格项的方法。
    *   包含 `unwrap` 方法，用于获取原始的 Python 字典表示。
*   **`Table` 类:**
    *   表示 TOML 中的标准表格 (例如 `[table_name]`)。
    *   继承自 `AbstractTable`。
    *   具有 `is_aot_element` 和 `is_super_table` 属性，用于标识其在 TOML 结构中的角色。
    *   提供 `raw_append` 方法，用于在不复制缩进的情况下添加元素。
    *   `indent` 方法用于设置表格的缩进。
    *   `invalidate_display_name` 方法用于使子表格的显示名称失效。
*   **`InlineTable` 类:**
    *   表示 TOML 中的内联表格 (例如 `{ key1 = "value1", key2 = "value2" }`)。
    *   继承自 `AbstractTable`。
    *   `as_string` 方法用于生成内联表格的 TOML 字符串表示。
*   **`String` 类:**
    *   表示 TOML 中的字符串。
    *   存储字符串的值、原始表示和类型 (`StringType`)。
    *   `as_string` 方法用于生成带引号的 TOML 字符串表示。
    *   提供 `from_raw` 类方法，用于从原始字符串创建 `String` 对象。
*   **`AoT` 类:**
    *   表示 TOML 中的数组表格 (Array of Tables，例如 `[[tables]]`)。
    *   存储一个 `Table` 对象的列表。
    *   提供添加 (`append`, `insert`)、删除 (`__delitem__`) 表格的方法。
    *   支持通过索引 (`__getitem__`) 访问表格。
    *   `invalidate_display_name` 方法用于使包含的表格的显示名称失效。
*   **`Null` 类:**
    *   表示 TOML 中的空值（尽管 TOML 规范中没有明确的空值，这里可能用于内部表示）。

**与逆向方法的关联：**

这些类是 `tomlkit` 库的核心组成部分，`tomlkit` 用于解析和生成 TOML 文件。在逆向工程中，TOML 文件常被用作应用程序的配置文件。

*   **读取和分析配置:** 逆向工程师可以使用 Frida 和 `tomlkit` 读取目标应用程序的 TOML 配置文件，理解其配置信息，例如服务器地址、API 密钥、调试选项等。
    *   **举例:** 假设一个 Android 应用的配置文件 `config.toml` 中包含一个 API 端点数组 `api_endpoints = ["https://api.example.com/v1", "https://api.example.com/v2"]`。使用 Frida，可以先读取该文件，然后使用 `tomlkit` 解析成 `Array` 对象，遍历数组中的 `String` 对象以获取每个端点。
*   **修改配置并观察行为:** 通过修改 `tomlkit` 解析后的 TOML 对象，并将修改后的内容写回文件或注入到目标进程，可以动态地改变应用程序的行为，用于测试或绕过某些安全机制。
    *   **举例:**  在上述例子中，可以使用 `Array.append` 方法向 `api_endpoints` 数组添加一个新的恶意 API 端点，观察应用程序是否会尝试连接。
*   **动态插桩辅助:**  Frida 可以利用这些类在运行时构建或修改 TOML 数据结构，用于控制目标应用的某些行为或提供自定义的配置。

**涉及二进制底层，Linux, Android 内核及框架的知识：**

*   **二进制文件解析:** 虽然 `tomlkit` 处理的是文本格式的 TOML，但它解析的配置信息最终会影响到二进制程序的行为。理解 TOML 的结构有助于理解二进制文件如何加载和使用配置。
*   **Linux/Android 配置文件:**  Linux 和 Android 系统中的很多应用程序都使用配置文件。`tomlkit` 可以用于分析和修改这些配置文件。
*   **Android 框架交互:**  在 Android 逆向中，可能需要分析或修改 APK 包内的配置文件，这些文件有时是 TOML 格式。Frida 可以借助 `tomlkit` 来实现对这些配置文件的操作。

**逻辑推理的例子：**

考虑 `Array.insert` 方法：

*   **假设输入:** 一个 `Array` 对象，其内部 `_value` 列表为 `[Whitespace("\n"), _ArrayItemGroup(value=String(...), indent=Whitespace("    "))]`，`pos = 1`，`value = "new_item"`。
*   **逻辑推理:** 方法会首先创建一个新的 `_ArrayItemGroup` 对象，包含 `value`。然后，根据 `pos` 的值，它会尝试在 `_value` 列表中找到合适的插入位置。由于 `pos` 为 1，并且当前索引 1 对应一个已有的元素，方法会尝试复用或调整其缩进和逗号信息，以保证插入后数组的格式正确。由于前一个元素有缩进，新的元素也会被添加相应的缩进。
*   **预期输出:** `_value` 列表变为 `[Whitespace("\n"), _ArrayItemGroup(value=String(...), indent=Whitespace("    ")), _ArrayItemGroup(value=String("new_item"), indent=Whitespace("    "), comma=Whitespace(","))]`， 并且 `self` 列表也包含了新的元素。

**用户或编程常见的使用错误：**

*   **在 `Array.__setitem__` 中使用切片赋值:**  代码明确抛出 `ValueError("slice assignment is not supported")`，说明用户不能直接使用切片来批量修改数组元素，需要逐个修改或使用其他方法。
    *   **举例:** `my_array[1:3] = ["a", "b"]` 会抛出异常。
*   **插入非法的数组元素类型:**  虽然 `Array.insert` 接受 `Any` 类型，但如果插入的对象不能被正确转换为 `Item`，可能会导致后续处理出错。
    *   **举例:** 如果 `item(value, _parent=self)`  无法处理 `value` 的类型，可能会抛出异常或生成不符合预期的 TOML 结构。
*   **不理解 `_reindex` 的作用:**  直接操作 `_value` 列表而不调用 `_reindex` 可能会导致 `_index_map` 与实际的数组元素索引不一致，从而引发错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户正在编写一个 Frida 脚本来修改目标应用程序的 TOML 配置文件中的一个数组。

1. **读取 TOML 文件:** 用户使用 Frida 的文件操作 API 读取目标进程中的 TOML 配置文件内容。
2. **使用 `tomlkit.parse` 解析:** 将读取到的 TOML 字符串传递给 `tomlkit.parse()` 函数，得到一个 `Document` 对象。
3. **访问数组:** 通过 Document 对象访问到想要修改的数组，例如 `doc["my_array"]`，得到一个 `Array` 对象。
4. **尝试修改数组:** 用户尝试使用索引赋值或 `insert` 方法来修改数组中的元素。例如，`doc["my_array"][1] = "new_value"` 或 `doc["my_array"].insert(0, "another_value")`。
5. **遇到问题:** 修改后的 TOML 内容不符合预期，例如格式错误、丢失了空格或逗号，或者目标应用程序无法正确解析修改后的配置文件。
6. **开始调试:** 用户可能会打印 `Array` 对象的内部状态，查看 `_value` 和 `_index_map` 的内容，发现问题可能出在元素格式的处理上。
7. **查看 `items.py` 源代码:**  为了理解 `Array` 对象是如何管理元素的，用户可能会查看 `frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py` 文件中 `Array` 类的实现，特别是 `insert`、`__setitem__` 和 `_reindex` 方法，以了解元素是如何被添加和格式化的。这有助于理解为什么修改后的 TOML 格式不正确，并找到修复脚本的方法。

**功能归纳：**

总而言之，`frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py` 的这一部分定义了 `tomlkit` 库中用于表示各种 TOML 数据类型的核心类，并提供了操作这些数据结构的必要方法。这些类负责存储数据本身以及相关的格式信息（如空格、逗号、注释），使得 `tomlkit` 能够解析、修改和生成符合 TOML 规范的文档。在 Frida 动态插桩的上下文中，这些类对于读取、分析和修改目标应用程序的 TOML 配置文件至关重要，从而实现对目标程序行为的动态控制和干预。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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