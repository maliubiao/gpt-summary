Response:
The user wants a summary of the functionality of the provided Python code, which is part of the `tomlkit` library. I need to analyze each class and its methods to understand its role and purpose. I should also look for connections to reverse engineering, low-level systems (Linux, Android kernel/framework), logical inference, common user errors, and debugging.

**Plan:**

1. **Class-by-class analysis:** Go through each class (`Array`, `AbstractTable`, `Table`, `InlineTable`, `String`, `AoT`, `Null`) and describe its core functionality.
2. **Reverse Engineering:**  Identify how the manipulation of TOML structures (reading, modifying) can be relevant to reverse engineering, for example, when dealing with configuration files.
3. **Low-level systems:** Look for any indications of interaction with operating system kernels or Android framework components. This seems unlikely given the nature of a TOML parser, but I should double-check.
4. **Logical Inference:**  Analyze methods for any complex conditional logic or decision-making processes. The `append`, `insert`, and `delete` methods in `Array` and `AbstractTable` are good candidates. I will create hypothetical inputs and outputs to illustrate the logic.
5. **User Errors:** Consider common mistakes users might make when working with TOML data, and how this library might handle or expose those errors. Type mismatches or incorrect structure come to mind.
6. **User Journey (Debugging):**  Think about a scenario where a user might interact with this code, tracing the steps leading to this part of the `tomlkit` library. This often involves parsing or modifying TOML files.
7. **Summarize Functionality:**  Provide a concise overview of the file's purpose.
好的，这是文件 `frida/subprojects/frida-tools/releng/tomlkit/tomlkit/items.py` 的第二部分源代码的功能归纳：

**核心功能总结：**

该文件定义了 `tomlkit` 库中用于表示 TOML 结构中各种**数据项（Items）**的 Python 类。这些类不仅存储了数据的值，还包含了格式化 TOML 输出所需的额外信息，例如空白符、注释和缩进。  这些类是构建和操作 TOML 文档抽象语法树 (AST) 的基本构建块。

**详细功能分解：**

*   **`Array` 类:**
    *   **功能:** 表示 TOML 中的数组。它继承自 Python 的 `list`，并扩展了其功能以跟踪和管理数组元素的格式化信息（空白、逗号、注释）。
    *   **逆向关系举例:** 在逆向工程中，配置文件经常使用数组来存储一系列参数或选项。例如，一个 Android 应用的 `AndroidManifest.xml` 文件 (虽然不是 TOML，但概念类似) 可能包含一个 `<uses-permission>` 标签数组，用于声明所需的权限。使用 `frida` 修改应用程序行为时，可能需要解析和修改 TOML 配置文件中的数组，以改变应用的某些行为。
    *   **二进制底层/内核/框架知识:** 虽然 `Array` 类本身不直接涉及二进制底层或内核知识，但它操作的数据可能来源于或影响这些层面。例如，一个描述网络配置的 TOML 文件中的 IP 地址数组，最终会被操作系统内核用于网络管理。在 Android 框架中，一些配置信息也可能以类似结构存储。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:** 一个 `Array` 对象，包含整数 `[1, 2, 3]`，用户调用 `append(4)`。
        *   **输出:** `Array` 对象会变成 `[1, 2, 3, 4]`，并且内部的 `_value` 列表会相应更新，可能还会添加逗号和空格等格式化元素。
    *   **用户错误举例:** 用户尝试使用切片赋值，例如 `array[1:3] = [5, 6]`，会抛出 `ValueError("slice assignment is not supported")`。
    *   **用户操作到达此处 (调试线索):** 用户可能通过 `tomlkit` 库加载了一个 TOML 文件，并且正在尝试修改其中的一个数组。例如，用户可能调用了 `toml_document["settings"]["ports"].append(8080)`，其中 `toml_document["settings"]["ports"]` 返回一个 `Array` 对象。

*   **`AbstractTable` 类:**
    *   **功能:**  作为 `Table` 和 `InlineTable` 的基类，提供了表结构的通用行为，例如存储键值对、添加、删除和访问元素。
    *   **逆向关系举例:** 逆向工程中经常需要分析程序的配置文件，这些文件可能以分层结构组织，类似于 TOML 的表。例如，一个游戏的配置文件可能包含多个表，分别描述不同的游戏设置（图形、音频、网络等）。使用 Frida，可以读取并修改这些表中的值来改变游戏的运行行为。
    *   **二进制底层/内核/框架知识:**  与 `Array` 类似，`AbstractTable` 本身不直接操作底层，但其数据可以代表底层系统的配置。例如，一个 Linux 服务的配置文件可能使用表来组织服务参数。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:** 一个空的 `AbstractTable` 对象，用户调用 `append("name", "value")`。
        *   **输出:** 表对象会包含一个键值对 `"name": "value"`，并且内部的 `_value` 会存储对应的 `Key` 和 `Item` 对象。
    *   **用户错误举例:** 用户尝试向 `AbstractTable` 添加非 `Comment` 或 `Whitespace` 类型的 `key` 为 `None` 的项，会抛出 `ValueError("Non comment/whitespace items must have an associated key")`。
    *   **用户操作到达此处 (调试线索):** 用户可能正在通过 `tomlkit` 创建或修改 TOML 文档中的表。例如，用户可能调用了 `toml_document.add_table("new_section")` 或者修改现有表的键值对 `toml_document["settings"]["debug"] = True`。

*   **`Table` 类:**
    *   **功能:** 表示 TOML 中的标准表（以 `[section]` 形式定义）。它继承自 `AbstractTable` 并添加了特定于标准表的属性，如是否为数组中的表元素 (`is_aot_element`) 和是否为超级表 (`is_super_table`)。
    *   **逆向关系举例:**  如同 `AbstractTable` 的例子，`Table` 类直接对应于配置文件中的节 (section)。逆向分析时，理解和修改这些节是常见的操作。
    *   **用户操作到达此处 (调试线索):** 用户正在操作 TOML 文档中的一个标准表。例如，通过 `toml_document["section_name"]` 访问到的对象就是一个 `Table` 实例。

*   **`InlineTable` 类:**
    *   **功能:** 表示 TOML 中的内联表（以 `{ key = value, ... }` 形式定义）。它继承自 `AbstractTable` 并针对内联表的格式化进行了调整。
    *   **逆向关系举例:** 内联表常用于表示嵌套较浅的配置信息。逆向时，可能需要修改内联表中的值来快速调整某些设置。
    *   **用户操作到达此处 (调试线索):** 用户正在操作 TOML 文档中的一个内联表。例如，当赋值给一个已存在的内联表字段时，或者创建一个新的内联表。

*   **`String` 类:**
    *   **功能:** 表示 TOML 中的字符串字面量。它继承自 Python 的 `str`，并存储了原始字符串表示和字符串类型信息（例如，基本字符串、多行字符串）。
    *   **逆向关系举例:**  配置文件中字符串类型的配置项非常常见，例如文件路径、URL、API 密钥等。逆向时，可能需要修改这些字符串来重定向程序行为或绕过某些检查。
    *   **用户操作到达此处 (调试线索):** 用户正在访问或修改 TOML 文档中的一个字符串值。例如，`toml_document["path"]` 返回的可能是一个 `String` 对象。

*   **`AoT` 类:**
    *   **功能:** 表示 TOML 中的数组表 (Array of Tables)，以 `[[tables]]` 形式定义。它包含一个 `Table` 对象的列表。
    *   **逆向关系举例:** 数组表用于表示一组具有相同结构的配置项。例如，一个网络服务的配置文件可能使用数组表来定义多个服务器实例的配置。逆向时，可能需要添加、删除或修改数组表中的元素。
    *   **用户操作到达此处 (调试线索):** 用户正在操作 TOML 文档中的一个数组表。例如，通过 `toml_document["servers"]` 访问到的对象可能是一个 `AoT` 实例。

*   **`Null` 类:**
    *   **功能:** 表示一个空值或占位符。在某些操作中，可能需要表示一个逻辑上的 "不存在" 的值。
    *   **逆向关系举例:** 虽然 TOML 本身没有显式的 null 值，但在 `tomlkit` 的内部表示中，`Null` 可能用于表示某些解析或操作过程中的空状态。
    *   **用户操作到达此处 (调试线索):** 在某些复杂的 TOML 文档操作中，可能会遇到 `Null` 对象，但这通常是库内部的处理，用户不太可能直接创建或操作 `Null` 实例。

**总结 `items.py` 的功能:**

`items.py` 定义了 `tomlkit` 库中用于表示各种 TOML 数据类型（数组、表、内联表、字符串、数组表）的类。这些类不仅存储数据值，还维护了格式化信息，使得库能够以保留原始格式的方式读取和写入 TOML 文件。 这些类是构建和操作 TOML 文档抽象语法树的关键组成部分，为用户提供了以编程方式访问和修改 TOML 数据的能力。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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