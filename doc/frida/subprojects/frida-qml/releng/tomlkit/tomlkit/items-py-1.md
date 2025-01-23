Response:
The user wants a summary of the functionality of the Python code provided, specifically focusing on its relationship to reverse engineering, binary/OS/kernel details, logical inferences, common user errors, and debugging.

Here's a plan to address each point:

1. **Summarize functionality**: Identify the main purpose of the code by analyzing the classes and their methods.
2. **Reverse engineering relation**: Look for features or patterns that are commonly used or related to reverse engineering tasks.
3. **Binary/OS/kernel relation**: Identify if any code directly interacts with or refers to low-level concepts like memory, processes, or OS-specific features.
4. **Logical inference**: Analyze if the code makes any deductions or assumptions based on input data.
5. **User errors**: Identify potential mistakes a user could make while interacting with or using this code.
6. **User operation to reach the code**: Speculate on the user actions that would lead to the execution of this specific file within the broader Frida context.
7. **Overall summarization**:  Provide a concise summary of the code's role.
这是 `frida/subprojects/frida-qml/releng/tomlkit/tomlkit/items.py` 文件的第二部分，其主要功能是定义了用于表示 TOML (Tom's Obvious, Minimal Language) 数据结构中的各种元素的 Python 类。这些类继承自 `Item` 类，并用于构建和操作 TOML 文档的抽象语法树 (AST)。

**归纳一下它的功能：**

这部分代码主要负责定义了 TOML 数据结构中更复杂的元素类型，以及一些辅助类，包括：

* **`Array`**: 表示 TOML 中的数组。
* **`AbstractTable`**:  作为 `Table` 和 `InlineTable` 的基类，定义了表类型的通用行为。
* **`Table`**: 表示 TOML 中的标准表格。
* **`InlineTable`**: 表示 TOML 中的内联表格。
* **`String`**: 表示 TOML 中的字符串。
* **`AoT` (Array of Tables)**: 表示 TOML 中的表格数组。
* **`Null`**: 表示一个空的或不存在的值。

这些类提供了操作这些 TOML 元素的方法，例如添加、删除、修改元素，以及将它们转换为字符串表示。它们是 `tomlkit` 库的核心组成部分，用于解析、修改和生成 TOML 文档。

**与逆向的方法的关系以及举例说明：**

这个文件本身的功能更偏向于 **数据表示和操作**，而不是直接参与逆向分析。但是，`tomlkit` 库作为 Frida 的一部分，其功能与逆向是相关的。

* **配置文件解析和修改：**  逆向工程师经常需要分析和修改应用程序的配置文件。如果应用程序使用 TOML 格式的配置文件，`tomlkit` 就可以被用来解析这些文件，方便地修改其中的参数，然后重新生成修改后的文件。例如，一个 Android 应用程序的 native 层的配置文件可能是 TOML 格式的，逆向工程师可以使用 Frida 加载这个配置文件，使用 `tomlkit` 修改某个关键参数（例如服务器地址），然后让应用程序加载修改后的配置来测试不同的行为。
* **动态插桩过程中的数据交换：** Frida 可以在运行时修改应用程序的内存和行为。`tomlkit` 可以作为一种结构化的数据交换格式，在 Frida 脚本和目标应用程序之间传递复杂的配置信息或状态数据。例如，逆向工程师可能需要向目标进程发送一个包含多个参数的配置对象，使用 TOML 可以清晰地组织这些参数。

**涉及到二进制底层，linux, android内核及框架的知识以及举例说明：**

这个文件本身 **不直接** 涉及到二进制底层、Linux 或 Android 内核及框架的知识。它的作用域是处理 TOML 格式的数据。

但是，`tomlkit` 作为 Frida 生态的一部分，其应用场景会间接涉及到这些底层知识：

* **Frida 的底层操作：** Frida 需要与目标进程进行交互，涉及到进程内存读写、函数 Hook 等底层操作。这些操作通常是在 Linux 或 Android 等操作系统上进行的。虽然 `items.py` 不直接操作这些底层细节，但它处理的配置数据可能最终会影响 Frida 如何进行这些底层操作。
* **Android 框架中的配置：** Android 系统和应用程序经常使用配置文件来管理各种参数。例如，AndroidManifest.xml、各种 `.ini` 或 `.conf` 文件。虽然 `items.py` 处理的是 TOML，但如果某个 Android 组件使用了 TOML 配置文件，那么这个文件就可能在逆向 Android 框架时被使用到。

**做了逻辑推理，请给出假设输入与输出：**

这个文件中的类主要进行数据的组织和表示，逻辑推理更多体现在对 TOML 格式规则的遵守上。以下是一个关于 `Array` 类的逻辑推理的例子：

**假设输入:** 一个 `Array` 对象，其内部 `_value` 列表中包含多个 `_ArrayItemGroup` 对象，每个对象表示数组中的一个元素，可能包含前导空格、逗号和注释。现在调用 `append` 方法添加一个新的整数值 `100`，并带有注释 `# This is a new value`。

**输出:**

1. 一个新的 `_ArrayItemGroup` 对象会被创建，包含表示整数 `100` 的 `Integer` 对象。
2. 如果数组是多行的，新的 `_ArrayItemGroup` 对象可能会带有适当的缩进。
3. 如果在添加新元素之前，最后一个元素没有逗号分隔，则会在最后一个元素的 `comma` 属性中添加一个 `Whitespace(",")` 对象。
4. 新的 `_ArrayItemGroup` 对象会被添加到 `_value` 列表中。
5. 如果提供了注释，会创建一个 `Comment` 对象并添加到 `_value` 列表中。
6. `_index_map` 会被更新以反映数组的新结构。

**涉及用户或者编程常见的使用错误，请举例说明：**

* **在 `Array` 中使用不支持的切片赋值：**  `__setitem__` 方法中明确指出 "slice assignment is not supported"。如果用户尝试使用切片赋值来修改数组，例如 `my_array[1:3] = [new_item1, new_item2]`，将会抛出 `ValueError("slice assignment is not supported")` 异常。
* **向 `AbstractTable` 的 `append` 方法传递不合法的参数：** `AbstractTable` 的 `append` 方法需要根据传入的参数类型进行不同的处理。如果用户尝试在不应该传递 `None` 作为键的时候传递了 `None`，可能会导致错误或异常。
* **修改 `InlineTable` 元素的 `trivia.comment`：**  `InlineTable` 的 `append` 方法中会移除新添加元素的注释。用户可能会期望在内联表格的元素中保留注释，但实际上会被清除。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

要执行到 `frida/subprojects/frida-qml/releng/tomlkit/tomlkit/items.py` 文件中的代码，通常是因为用户在 Frida 脚本中操作了 TOML 数据结构。可能的步骤如下：

1. **用户编写 Frida 脚本：**  用户编写一个 Frida 脚本，目的是 hook 某个应用程序，并需要读取或修改该应用程序的 TOML 配置文件。
2. **使用 `frida` 或 `frida-compile` 运行脚本：**  用户使用 Frida 命令行工具或编译后的脚本来附加到目标进程。
3. **脚本中使用 `tomlkit` 加载 TOML 文件：**  脚本中使用了 `tomlkit` 库来加载目标应用程序的 TOML 配置文件，例如：
   ```python
   import tomlkit
   # 假设 config_path 是 TOML 文件的路径
   with open(config_path, "r") as f:
       config = tomlkit.load(f)
   ```
4. **脚本中访问或修改 TOML 数据：** 用户在脚本中访问或修改了加载的 TOML 数据，例如：
   ```python
   config["section"]["key"] = "new_value"  # 修改值
   config["new_section"] = {"new_key": "another_value"} # 添加新的 section
   del config["section"]["old_key"] # 删除 key
   ```
   当用户执行这些操作时，`tomlkit` 库内部会创建和操作 `items.py` 中定义的各种对象（如 `Table`, `String`, `Array` 等）。
5. **如果涉及调试，可能会单步执行到这里：** 如果用户在使用 IDE 或 Frida 的调试功能，并且单步执行涉及到 TOML 数据的操作，那么调试器就可能会进入到 `items.py` 文件中，以便查看这些对象的创建和修改过程。

总而言之，`items.py` 是 `tomlkit` 库的核心，负责 TOML 数据的表示。用户通过 Frida 脚本与 `tomlkit` 交互，最终会触发 `items.py` 中类的实例化和方法调用。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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