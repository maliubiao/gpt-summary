Response:
The user wants a summary of the Python code provided, focusing on its functionalities and how they relate to reverse engineering, low-level details, logical reasoning, common user errors, and debugging.

**Plan:**

1. **Identify Core Functionalities:** Analyze the classes (`Array`, `AbstractTable`, `Table`, `InlineTable`, `String`, `AoT`, `Null`) and their methods to understand their purposes.
2. **Relate to Reverse Engineering:** Look for aspects that could be used to manipulate or inspect data structures, potentially within a running process.
3. **Identify Low-Level Aspects:** Determine if the code interacts with operating system kernels, memory management, or specific hardware features (though this seems unlikely in this specific file).
4. **Analyze Logical Reasoning:**  Examine methods for conditional logic, data manipulation, and how they transform inputs to outputs. Create hypothetical input/output examples.
5. **Spot Potential User Errors:** Identify common pitfalls when using the classes and their methods.
6. **Trace User Operations:**  Imagine how a user might interact with the Frida framework to eventually trigger the execution of this code.
7. **Summarize Overall Functionality:** Combine the findings into a concise description of the file's role.
这是 `frida/releng/tomlkit/tomlkit/items.py` 文件的第二部分，延续了第一部分的内容，主要定义了用于表示 TOML (Tom's Obvious, Minimal Language) 数据结构的各种 Python 类。这些类旨在以结构化的方式存储和操作 TOML 数据，同时保留格式信息，如空格、注释等。

**功能归纳:**

该文件定义了以下用于表示 TOML 元素的类，并提供了操作这些元素的方法：

* **`AbstractTable`:**  一个抽象基类，定义了 `Table` 和 `InlineTable` 的共同行为，例如添加、删除、获取和设置键值对。
* **`Table`:** 表示 TOML 中的表格（Section），可以包含键值对和其他子表格或数组。它维护了表格的结构、名称、是否为数组中的元素等信息。
* **`InlineTable`:**  表示 TOML 中的内联表格，通常用于简洁地表示小型的键值对集合。
* **`String`:** 表示 TOML 中的字符串字面量，区分不同类型的字符串（基本字符串、多行基本字符串、字面字符串、多行字面字符串），并存储原始字符串表示。
* **`AoT` (Array of Tables):** 表示 TOML 中的表格数组，即具有相同名称的多个表格。
* **`Null`:**  表示一个空的 TOML 项。

**与逆向方法的关联及举例:**

这些类是 Frida 动态插桩工具处理和表示目标进程内存中的配置数据的核心。在逆向工程中，理解目标程序的配置文件格式至关重要。TOML 是一种常见的配置文件格式。

* **数据结构表示:**  `Table` 和 `AoT` 可以用来表示目标进程中读取的 TOML 配置文件内容。逆向工程师可以使用 Frida 拦截文件读取操作，解析 TOML 文件内容，并将其表示为这些类的实例。
* **动态修改配置:** 逆向工程师可以使用这些类的方法（例如 `Table.append()`, `Table.__setitem__()`, `AoT.append()`) 在运行时修改目标程序的配置。例如，可以修改服务器地址、端口号、功能开关等。

**举例说明:**

假设目标进程读取了一个包含以下内容的 TOML 文件：

```toml
[server]
address = "127.0.0.1"
port = 8080

[[server.users]]
name = "alice"
admin = true

[[server.users]]
name = "bob"
admin = false
```

使用 Frida 和 `tomlkit`，逆向工程师可以：

1. **拦截文件读取并解析 TOML:** Frida 脚本可以 hook 文件读取函数，当目标进程尝试读取配置文件时，获取文件内容。然后使用 `tomlkit` 的解析功能将 TOML 内容转换为 `Table` 和 `AoT` 对象的嵌套结构。
2. **访问和修改配置:**
   ```python
   # 假设 parsed_toml 是解析后的 Table 对象
   server_address = parsed_toml["server"]["address"]  # 获取服务器地址 (String 对象)
   print(server_address.value)  # 输出: 127.0.0.1

   parsed_toml["server"]["port"] = 9000  # 修改端口号 (将 int 转换为 Item 对象)

   # 添加一个新用户
   new_user_table = Table(container.Container([]), Trivia())
   new_user_table["name"] = "charlie"
   new_user_table["admin"] = False
   parsed_toml["server"]["users"].append(new_user_table) # 向 AoT 中添加新的 Table

   # 将修改后的 TOML 数据写回内存或文件 (如果需要)
   ```

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

虽然 `items.py` 本身不直接涉及二进制底层或内核交互，但它在 Frida 的上下文中扮演着重要角色，而 Frida 本身就广泛使用了这些知识。

* **内存操作:** Frida 的核心功能是动态插桩，这涉及到在目标进程的内存中注入代码、修改指令、读取和写入内存数据。`tomlkit` 创建的 `Table` 和 `AoT` 对象可以代表目标进程内存中的配置数据结构，方便 Frida 脚本操作这些内存。
* **进程间通信 (IPC):** Frida 客户端（运行逆向工程师的脚本）与 Frida 服务端（注入到目标进程）之间需要进行 IPC。`tomlkit` 对象可能作为 IPC 消息的一部分进行传递，用于传递配置信息。
* **Android 框架:** 在 Android 逆向中，很多配置信息可能存储在特定的文件格式中，也可能通过 Android 的 SettingsProvider 等机制管理。`tomlkit` 可以用于解析和修改这些配置文件或数据。

**逻辑推理的假设输入与输出:**

假设我们有一个 `Table` 对象 `my_table`:

**假设输入:**

```python
my_table = Table(container.Container([]), Trivia())
my_table["name"] = "example"
my_table["version"] = 1
```

**输出 (一些方法调用):**

* `len(my_table)` 输出: `2`
* `my_table["name"].value` 输出: `"example"` (假设 "example" 是一个基本字符串)
* `my_table.unwrap()` 输出: `{'name': 'example', 'version': 1}`
* `isinstance(my_table["version"], Number)` (假设 Number 类也在其他地方定义) 输出: `True`

**涉及用户或者编程常见的使用错误及举例:**

* **类型错误:** 尝试将不兼容的类型赋值给 TOML 项。例如，TOML 规范可能不允许将列表直接赋值给一个标量键。
   ```python
   my_table["settings"] = [1, 2, 3]  # 如果 TOML 结构期望的是标量值，则会出错
   ```
* **键名错误:** 访问不存在的键会导致 `KeyError`。
   ```python
   print(my_table["non_existent_key"])  # 抛出 KeyError
   ```
* **修改只读属性:**  某些属性可能被设计为只读，尝试修改会引发异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 并连接到目标进程:**  用户首先使用 Frida 客户端工具 (例如 `frida` Python 库) 连接到他们想要逆向的目标进程。
2. **用户编写 Frida 脚本:**  用户编写 JavaScript 或 Python 脚本，使用 Frida 的 API 来拦截函数调用、读取内存等。
3. **脚本中涉及 TOML 解析或生成:**  如果脚本需要处理目标进程的 TOML 配置文件，或者需要构造 TOML 数据发送给目标进程，那么会使用 `tomlkit` 库。
4. **创建或操作 `Table`, `AoT` 等对象:**  在脚本中，用户可能会调用 `tomlkit.parse()` 来解析 TOML 字符串，这将创建 `Table`, `AoT`, `String` 等类的实例。用户也可能手动创建这些类的实例来构建 TOML 数据。
5. **调用 `items.py` 中定义的方法:**  当用户在脚本中操作这些 `tomlkit` 对象时，例如访问键值、添加元素、修改值等，最终会调用 `items.py` 文件中定义的各种方法（例如 `__getitem__`, `__setitem__`, `append` 等）。
6. **调试过程:** 如果在操作 TOML 数据时出现错误，例如数据结构不符合预期，用户可能会使用调试工具来查看 `Table`, `AoT` 等对象的状态，从而深入到 `items.py` 的代码中，了解具体的执行流程和数据变化。

**总结 `items.py` 的功能:**

总而言之，`frida/releng/tomlkit/tomlkit/items.py` 定义了用于表示和操作 TOML 数据结构的 Python 类，这些类在 Frida 动态插桩工具中扮演着关键角色，使得逆向工程师能够方便地读取、修改和生成目标进程的 TOML 配置信息。它抽象了底层的 TOML 语法，提供了面向对象的接口来处理 TOML 数据，并保留了格式信息。

### 提示词
```
这是目录为frida/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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