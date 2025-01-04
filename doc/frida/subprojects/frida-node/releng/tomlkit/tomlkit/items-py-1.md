Response:
The user wants to understand the functionality of the provided Python code snippet, which is part of the `tomlkit` library within the `frida` project.

To address the user's request, I need to:

1. **Identify the core purpose of the code:** Based on the class names and methods, this file seems to define different types of TOML items, like arrays, tables (inline and standard), strings, and comments. It also handles the structure and formatting of these items.
2. **List the functionalities of each class:**  Describe what each class is responsible for and the actions it can perform (e.g., adding, removing, modifying elements).
3. **Relate to reverse engineering (if applicable):**  Consider how manipulating TOML files, the format this code handles, could be relevant in a reverse engineering context, especially in relation to Frida.
4. **Connect to low-level/kernel concepts (if applicable):** Determine if any operations or data structures directly interact with or represent concepts from the Linux/Android kernel or framework.
5. **Explain logical reasoning:** Identify any methods or processes that involve decision-making or conditional logic, providing example inputs and outputs.
6. **Point out potential user errors:** Highlight common mistakes a user might make when interacting with these classes or the TOML format in general.
7. **Describe the user path to reach this code:**  Speculate on how a user interacting with Frida might end up triggering the execution of code in this file.
8. **Summarize the overall functionality:** Provide a concise summary of the code's purpose.
这是 `frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 文件（第二部分）的功能归纳：

该文件定义了 `tomlkit` 库中用于表示 TOML 结构中各种**数据项**的 Python 类。这些类不仅存储了数据的值，还包含了与格式相关的元信息，例如空白符、注释和缩进。

**主要功能归纳：**

* **定义了多种 TOML 数据项类型：**
    * **`Array`:** 表示 TOML 中的数组，可以包含多种类型的值。它维护了数组元素的顺序和格式信息，支持添加、删除、插入和修改元素。
    * **`AbstractTable`:**  作为 `Table` 和 `InlineTable` 的抽象基类，提供了表格类型的通用行为，如添加、删除键值对，获取值等。
    * **`Table`:** 表示 TOML 中的标准表格（用 `[section]` 声明），支持添加键值对，管理子项的缩进，以及判断是否为数组表元素或父表格。
    * **`InlineTable`:** 表示 TOML 中的内联表格（用 `{ key = value }` 声明），功能类似于 `Table`，但格式紧凑，不支持多行。
    * **`String`:** 表示 TOML 中的字符串，区分不同的字符串类型（基本字符串、字面字符串、多行基本字符串、多行字面字符串），并存储原始字符串和格式信息。
    * **`AoT` (Array of Tables):** 表示 TOML 中的数组表（用 `[[section]]` 声明），包含一组 `Table` 对象。
    * **`Null`:** 表示一个空值项。

* **管理数据项的结构和格式：**
    * 每个数据项类都继承自 `Item`，拥有 `trivia` 属性，用于存储与该项相关的空白符、注释等格式信息。
    * 方法如 `indent()` 可以调整 `Table` 的缩进。
    * `as_string()` 方法可以将数据项转换回 TOML 格式的字符串。

* **提供数据访问和操作接口：**
    * 实现了 Python 容器的常见接口，如 `__len__`，`__getitem__`，`__setitem__`，`__delitem__`，`insert`，`append` 等，方便用户操作 TOML 数据。
    * `unwrap()` 方法可以将 `tomlkit` 的数据项对象转换为标准的 Python 数据类型（如 `dict`，`list`，`str` 等）。

* **处理 TOML 语法细节：**
    * 例如，`Array` 类在添加元素时会处理逗号和空白符的添加。
    * `String` 类会根据字符串类型进行转义或处理。

**与逆向方法的关联举例：**

在逆向工程中，配置文件经常以 TOML 格式存在。Frida 可以用于运行时修改目标进程的内存，而 `tomlkit` 提供的功能可以方便地修改进程中加载的 TOML 配置文件。

**举例：** 假设一个 Android 应用的配置文件 `config.toml` 中包含了服务器地址：

```toml
[network]
server_address = "old.example.com"
```

使用 Frida 和 `tomlkit`，可以动态地修改这个地址：

1. 使用 Frida 连接到目标应用进程。
2. 找到配置文件 `config.toml` 在内存中的表示（假设已经被解析为 `tomlkit` 的数据结构）。
3. 使用 `tomlkit` 的 API 访问 `network.server_address` 对应的 `String` 对象。
4. 调用 `String` 对象的某些方法（例如，直接修改其内部表示，或者重新创建一个新的 `String` 对象并替换原有的对象）将其值修改为 `new.example.com`。
5. 目标应用在后续操作中会使用新的服务器地址。

**涉及二进制底层、Linux、Android 内核及框架的知识举例：**

虽然 `tomlkit` 本身是一个纯 Python 库，不直接操作二进制底层或内核，但它操作的数据最终会以某种形式存在于内存中。

* **内存布局：**  当 Frida 修改 `tomlkit` 对象时，实际上是在修改目标进程的堆内存。理解目标进程的内存布局，例如 TOML 数据结构在内存中的组织方式，有助于更精确地进行修改。
* **字符串编码：**  `tomlkit` 需要处理 TOML 文件中字符串的编码（通常是 UTF-8）。在逆向过程中，需要了解目标应用如何处理字符串编码，以确保修改后的字符串格式正确。
* **配置文件加载：**  理解目标应用如何加载和解析 TOML 配置文件（例如，是否使用了某些特定的库或系统调用）有助于确定修改的时机和方式。

**逻辑推理举例：**

在 `Array` 类的 `_add_item` 方法中，对于添加元素的逗号和空白符的处理就包含逻辑推理。

**假设输入：**

* `self._value` (内部存储的元素列表) 为 `[Item("value1"), Item("value2")]`
* `new_values` (要添加的新元素列表) 为 `[Item("value3")]`
* `comment` 为 `"add new item"`

**输出：**

`self._value` 将被更新为类似 `[Item("value1"), Whitespace(","), Whitespace(" "), Item("value2"), Whitespace(","), Whitespace(" "), Item("value3"), Comment(Trivia(indent=' ', comment='# add new item', trail=''))]`

**推理过程：**

1. 遍历现有的 `self._value`，在非最后一个元素后添加逗号和空格。
2. 将新的 `new_values` 添加到列表中。
3. 如果有注释，则创建一个 `Comment` 对象并添加到列表末尾，并根据现有元素决定是否需要添加前导空格。

**用户或编程常见的使用错误举例：**

* **在 `Array` 中使用 `__setitem__` 进行切片赋值：**  `Array` 的 `__setitem__` 方法明确抛出 `ValueError("slice assignment is not supported")`，因为切片赋值可能会导致内部索引混乱。用户应该使用其他方法如循环或列表推导来修改多个元素。
* **错误地假设 `is_super_table` 的行为：** 用户可能错误地认为所有只有一个子项的 `Table` 都是 super table，但实际上只有当该子项是另一个 `Table` 或 `AoT` 时才是。
* **不理解 `raw_append` 和 `append` 的区别：** 用户可能在需要保持原有缩进时错误地使用了 `append`，导致缩进被修改。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户想要使用 Frida 修改一个正在运行的 Python 应用程序的 TOML 配置文件。

1. **编写 Frida 脚本：** 用户编写一个 Frida 脚本，该脚本需要访问目标进程中已加载的 TOML 数据结构。
2. **查找 TOML 数据结构：** 用户可能使用 Frida 的内存扫描功能或者 Hook 相关的库函数（例如，用于加载配置文件的函数）来定位到代表 TOML 数据的 `tomlkit` 对象。
3. **操作 `tomlkit` 对象：**  一旦找到 `tomlkit` 对象（例如，一个 `Table` 或 `AoT` 实例），用户可能会尝试访问或修改其中的数据项。例如，他们可能会调用 `table["setting"]` 来获取一个值，或者调用 `array.append(new_value)` 来添加一个元素。
4. **执行到 `items.py` 中的代码：** 当用户在 Frida 脚本中执行类似 `array.append(new_value)` 的操作时，就会调用到 `frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 文件中 `Array` 类的 `append` 方法，或者与元素创建相关的代码，例如 `item()` 函数。
5. **调试 `items.py`：** 如果用户的 Frida 脚本在操作 TOML 数据时遇到问题（例如，数据格式不符合预期），他们可能会查看 `items.py` 的源代码，了解 `tomlkit` 是如何表示和操作这些数据项的，以便找到问题的原因。

总而言之，`frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py` 定义了 `tomlkit` 库中用于表示和操作 TOML 数据结构的各种类，这些类不仅存储了数据的值，还包含了格式信息，并提供了方便的 API 供用户进行访问和修改。这使得在运行时动态地操作和修改 TOML 配置文件成为可能，这在逆向工程和动态分析中非常有用。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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