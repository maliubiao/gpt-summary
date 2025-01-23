Response:
The user wants a summary of the functionality of the Python code provided, specifically focusing on its relevance to reverse engineering, binary/kernel/framework interactions, logical reasoning, common user errors, and debugging.

**Plan:**

1. **High-Level Overview:** Understand the main purpose of the code. It seems to be part of a TOML parser/manipulator.
2. **Functionality Breakdown:** Go through each class and its methods, summarizing their roles.
3. **Reverse Engineering Relevance:** Identify areas where this code might be used in a reverse engineering context (e.g., modifying configuration files).
4. **Binary/Kernel/Framework Interactions:** Determine if the code directly interacts with these low-level components. It seems more like a high-level parsing library.
5. **Logical Reasoning:** Look for methods that involve decision-making or conditional logic.
6. **Common User Errors:** Think about how users might misuse the API of this library.
7. **Debugging:** Consider how a user might end up in this specific code during a debugging session.
8. **Summary:** Combine the above points into a concise summary.
这是 `frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py` 文件的第二部分，延续了第一部分对 TOML (Tom's Obvious, Minimal Language) 格式的解析和操作功能。这部分主要定义了表示 TOML 中各种数据类型的 Python 类，并提供了操作这些数据的方法。

**功能归纳:**

这部分代码定义了以下用于表示 TOML 元素的类，并提供了对这些元素进行操作的功能：

*   **`Array(list, Item)`**:  表示 TOML 中的数组。
    *   可以像 Python 列表一样操作（添加、删除、插入元素）。
    *   维护了内部的 `_value` 列表，该列表存储的是 `_ArrayItemGroup` 对象，包含了实际的值以及格式化信息（例如逗号、空格、缩进、注释）。
    *   提供了 `append` 方法用于向数组添加元素，并能处理添加逗号、空格和注释。
    *   `clear` 方法用于清空数组。
    *   `__getitem__`, `__setitem__`, `__delitem__`, `insert` 等方法重载了 Python 列表的操作。
    *   `_reindex` 方法用于更新内部索引映射，以便快速查找元素的格式化信息。
*   **`AbstractTable(Item, _CustomDict)`**:  `Table` 和 `InlineTable` 的抽象基类，定义了表类型的通用行为。
    *   存储键值对，并能以字典的方式访问。
    *   `unwrap` 方法将表转换成标准的 Python 字典。
    *   `append` 和 `add` 方法用于向表中添加元素。
    *   `remove` 方法用于移除表中的元素。
    *   `setdefault` 方法类似于 Python 字典的同名方法。
    *   `__iter__`, `__len__`, `__delitem__`, `__getitem__`, `__setitem__` 等方法重载了字典的操作。
*   **`Table(AbstractTable)`**:  表示 TOML 中的标准表格（用 `[table]` 声明）。
    *   继承了 `AbstractTable` 的功能。
    *   有 `name` 和 `display_name` 属性，用于存储表名。
    *   `is_aot_element` 方法判断是否是数组表格 (Array of Tables) 的元素。
    *   `is_super_table` 方法判断是否是嵌套表格的中间父级表格（例如 `[a.b.c]` 中的 `a` 和 `a.b`）。
    *   `raw_append` 方法与 `append` 类似，但不复制缩进。
    *   `indent` 方法用于调整表格的缩进。
    *   `invalidate_display_name` 方法用于递归地使子表格的显示名称失效。
*   **`InlineTable(AbstractTable)`**:  表示 TOML 中的内联表格（用 `{ key = value }` 声明）。
    *   继承了 `AbstractTable` 的功能。
    *   `append` 方法在添加元素时会处理空格和注释。
    *   `as_string` 方法将内联表格转换为字符串表示形式。
*   **`String(str, Item)`**:  表示 TOML 中的字符串。
    *   继承自 Python 的 `str` 类。
    *   存储字符串的类型 (`StringType`) 和原始表示 (`_original`)。
    *   `unwrap` 方法返回原始字符串值。
    *   `as_string` 方法返回带引号的字符串表示形式。
    *   `from_raw` 类方法用于创建 `String` 对象，并能处理转义。
*   **`AoT(Item, _CustomList)`**:  表示 TOML 中的数组表格（Array of Tables，用 `[[tables]]` 声明）。
    *   包含一个 `_body` 列表，存储 `Table` 对象。
    *   可以像 Python 列表一样操作包含的表格。
    *   `unwrap` 方法将数组表格转换为包含字典的 Python 列表。
    *   `invalidate_display_name` 方法用于递归地使包含的表格的显示名称失效。
*   **`Null(Item)`**:  表示一个空值。

**与逆向方法的关系及举例说明:**

这些类在逆向工程中主要用于处理和解析 TOML 配置文件。很多应用程序或组件使用 TOML 格式来存储配置信息。

*   **读取和修改配置文件:**  逆向工程师可以使用 Frida 脚本加载目标进程，然后使用 `tomlkit` 库解析其使用的 TOML 配置文件。例如，如果某个 Android 应用的配置存储在 TOML 文件中，逆向工程师可以使用 Frida 脚本读取这个文件，修改其中的某些值（例如服务器地址、功能开关等），然后将修改后的配置写回或让应用重新加载。
    ```python
    import frida
    import tomlkit

    # 假设已经附加到目标进程
    session = frida.attach("com.example.app")

    script = session.create_script("""
    function read_toml_config(filepath) {
        const file = new File(filepath, "r");
        const content = file.read();
        file.close();
        return content;
    }

    function modify_toml_config(content) {
        const config = tomlkit.parse(content);
        config.server.address = "new.server.com";
        return tomlkit.dumps(config);
    }

    rpc.exports = {
        readAndModifyConfig: function(filepath) {
            const content = read_toml_config(filepath);
            const modifiedContent = modify_toml_config(content);
            return modifiedContent;
        }
    };
    """)
    script.load()

    # 假设配置文件路径为 /data/data/com.example.app/config.toml
    config_path = "/data/data/com.example.app/config.toml"
    modified_config = script.exports.read_and_modify_config(config_path)
    print(modified_config)
    ```
    在这个例子中，虽然没有直接使用 `items.py` 中的类，但 `tomlkit.parse` 和 `tomlkit.dumps` 的底层实现会用到这些类来表示和操作 TOML 数据。

*   **理解应用行为:** 通过解析应用的 TOML 配置文件，逆向工程师可以更好地理解应用的内部结构、功能模块和运行参数，从而推断其行为。例如，查找应用使用的 API 密钥、服务器地址、功能开关等。

**涉及二进制底层，linux, android内核及框架的知识及举例说明:**

这个 `items.py` 文件本身是一个纯 Python 代码文件，主要关注 TOML 数据的逻辑表示和操作，**不直接涉及**二进制底层、Linux/Android 内核或框架的知识。它是一个高层次的抽象，用于处理文本格式的配置文件。

Frida 作为动态插桩工具，其核心功能依赖于与目标进程的交互，这涉及到操作系统底层的进程管理、内存操作等。但是，`tomlkit` 库作为 Frida 的一个子项目，其职责在于解析和操作 TOML 数据，与 Frida 的底层插桩机制是分离的。

**逻辑推理及假设输入与输出:**

*   **`Array.append()` 的逻辑:**
    *   **假设输入:** 一个 `Array` 对象 `arr`，当前内容为 `[1, 2]`，要添加元素 `3`，并添加注释 `# this is three`。
    *   **预期输出:** `arr` 的内部 `_value` 列表会新增包含值 `3` 和注释信息的 `_ArrayItemGroup` 对象。最终序列化输出的字符串可能是 `[ 1, 2, 3, # this is three ]` 或 `[ 1, 2, 3,  # this is three ]`，取决于已有的格式和是否需要添加额外的空格。

*   **`Table.__setitem__()` 的逻辑:**
    *   **假设输入:** 一个 `Table` 对象 `tbl`，包含一个键值对 `"name": "old_name"`，要设置 `"name": "new_name"`。
    *   **预期输出:** `tbl` 内部存储的键值对中 `"name"` 对应的值会被更新为表示字符串 `"new_name"` 的 `String` 对象。

**涉及用户或者编程常见的使用错误及举例说明:**

*   **尝试向 `Array` 中插入非法的索引:**
    ```python
    arr = Array([])
    arr.append(1)
    arr.insert(5, 2)  # IndexError: list index out of range
    ```

*   **在需要 `Key` 对象的地方传递字符串给 `Table` 的 `append` 方法:**
    ```python
    table = Table(container.Container([]), Trivia())
    table.append("key", "value") # 应该使用 Key("key")
    ```

*   **对 `Array` 进行切片赋值 (slice assignment)，这是不支持的:**
    ```python
    arr = Array([1, 2, 3])
    arr[0:2] = [4, 5] # ValueError: slice assignment is not supported
    ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本，需要解析或修改目标应用的 TOML 配置文件。**
2. **在 Frida 脚本中，用户导入了 `tomlkit` 库。**
3. **用户使用 `tomlkit.parse()` 函数解析 TOML 配置文件内容，或者创建了一个新的 `tomlkit` 对象。**
4. **用户开始操作解析后的 TOML 对象，例如访问数组元素、修改表格中的值等。**  这些操作会调用 `items.py` 中定义的类的相应方法，例如 `Array.__getitem__()`，`Table.__setitem__()` 等。
5. **如果在操作过程中出现了错误，例如尝试插入超出范围的索引，或者类型不匹配，Python 解释器会抛出异常。**
6. **作为调试线索，异常堆栈信息会指向 `items.py` 文件中引发异常的具体代码行。**  例如，如果用户尝试对 `Array` 进行切片赋值，异常会发生在 `Array.__setitem__()` 方法中。

总而言之，`items.py` 是 `tomlkit` 库的核心组成部分，负责将 TOML 格式的数据结构化地表示为 Python 对象，并提供了一系列方法来操作这些对象。这使得用户可以通过编程方式方便地读取、修改和生成 TOML 数据。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```