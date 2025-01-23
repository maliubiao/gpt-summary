Response:
The user wants a functional breakdown of the provided Python code, specifically the `items.py` file from the `tomlkit` library, a part of the Frida dynamic instrumentation toolkit. The breakdown should include:

1. **Core Functionality:** What does this code do?
2. **Relevance to Reversing:** How does it relate to reverse engineering techniques?
3. **Low-Level Details:** Does it interact with the binary level, Linux/Android kernels, or frameworks?
4. **Logical Reasoning:** Can we infer inputs and outputs based on the code?
5. **Common Usage Errors:** What mistakes might users make when using this code?
6. **User Journey to This Code:** How might a user's actions lead to this code being executed (as a debugging aid)?
7. **Summary of Functionality:**  A concise recap of the file's purpose.

Let's analyze the code section by section:

- **`Whitespace` and `Comment` classes:** These seem to represent whitespace and comments in a TOML file, storing their string representation and optional indentation.
- **`Trivia` class:** This likely bundles together the indentation, comment, and trailing whitespace associated with a TOML item.
- **`StringType` enum:** Defines different types of strings in TOML (basic, literal, multi-line).
- **`InvalidStringError` exception:** Raised when an invalid string is encountered.
- **`Key` class:** Represents a key in a TOML structure, potentially dotted (e.g., `a.b.c`).
- **`item` function:**  Seems like a factory function to create the appropriate `Item` subclass based on the input value's type.
- **`Item` class:**  An abstract base class for all TOML items (values, tables, arrays, etc.), managing trivia.
- **`_CustomList` and `_CustomDict` mixins:** Provide custom implementations for list and dictionary behavior, likely for managing the underlying representation of TOML arrays and tables.
- **`Integer`, `Float`, `Boolean`, `DateTime` classes:** Represent specific TOML data types, inheriting from `Item`.
- **`Array` class:** Represents a TOML array, handling comma placement, indentation, and management of underlying `_ArrayItemGroup` elements.
- **`AbstractTable` class:**  Abstract base for `Table` and `InlineTable`, providing common functionality for managing key-value pairs.
- **`Table` class:** Represents a standard TOML table (e.g., `[section]`).
- **`InlineTable` class:** Represents an inline TOML table (e.g., `{ a = 1, b = 2 }`).
- **`String` class:** Represents a TOML string, handling different string types.
- **`AoT` class:** Represents an array of tables (e.g., `[[array_of_tables]]`).
- **`Null` class:** Represents a null or empty item.

**High-Level Purpose:** The code defines classes and structures to represent various elements of a TOML (Tom's Obvious, Minimal Language) file. It seems designed to parse, manipulate, and serialize TOML data while preserving formatting (whitespace, comments).

**Relevance to Reversing (Hypothesis):** Frida uses TOML for configuration. This code likely plays a role in reading, modifying, and writing Frida's configuration files. In reverse engineering, you might want to modify Frida's behavior by altering its configuration. This code provides the tools to do that programmatically.

**Low-Level Details (Unlikely):**  Based on the code, there's no direct interaction with binary code, kernels, or low-level system calls. It operates at the level of text parsing and data structure manipulation.

**Logical Reasoning (Example):**
- **Input:** An `Array` object. Calling `append(value)` on it.
- **Output:** The `value` is added to the array, potentially with a preceding comma and appropriate indentation based on existing elements.

**Common Usage Errors (Example):**
- Modifying the `_value` attribute directly instead of using the provided methods (`append`, `insert`, etc.), potentially breaking the internal consistency of the TOML structure (e.g., incorrect comma placement).

**User Journey (Debugging Aid):**
1. A user starts Frida and provides a script.
2. Frida's core might need to read its configuration file (TOML).
3. The TOML parser would use classes from `items.py` to represent the configuration data in memory.
4. If the user's script modifies Frida's configuration programmatically (though the API), this code would be used to update the in-memory representation.
5. If Frida needs to write the modified configuration back to a file, this code would handle the serialization.

Now, let's synthesize the answer based on these observations.
好的，让我们来归纳一下 `frida/subprojects/frida-gum/releng/tomlkit/tomlkit/items.py` 这个文件的功能。

**主要功能归纳:**

这个 Python 文件定义了一系列类，用于表示 TOML (Tom's Obvious, Minimal Language) 格式的各种元素。它的核心功能是提供一个结构化的方式来表示和操作 TOML 数据，同时保留其格式信息（例如，空格、注释、逗号等）。

具体来说，它实现了以下功能：

1. **TOML 元素建模:**
   - 定义了表示 TOML 中各种数据类型的类，例如：
     - `String`: 字符串
     - `Integer`: 整数
     - `Float`: 浮点数
     - `Boolean`: 布尔值
     - `DateTime`: 日期时间
     - `Array`: 数组
     - `Table`: 表 (sections)
     - `InlineTable`: 内联表
     - `AoT`: 表格数组
   - 定义了辅助表示格式信息的类：
     - `Whitespace`: 空格
     - `Comment`: 注释
     - `Trivia`:  用于存储与 TOML 元素相关的格式信息（缩进、注释、尾随空格）。
     - `Key`: 表示 TOML 中的键。

2. **TOML 数据操作:**
   - 提供了对 TOML 数组 (`Array`) 和表 (`Table`, `InlineTable`) 进行增、删、改、查操作的方法，例如 `append`, `insert`, `remove`, `__getitem__`, `__setitem__` 等。
   - 允许以编程方式修改 TOML 结构和值，同时尽可能保留原始格式。

3. **TOML 数据序列化:**
   - 每个表示 TOML 元素的类都实现了 `as_string()` 方法，用于将其转换回 TOML 格式的字符串。

4. **内部数据管理:**
   - 使用 `_CustomList` 和 `_CustomDict` 等内部类来管理数组和表的元素，以便在进行操作时能够正确维护格式信息。

**与逆向方法的关联及举例:**

这个文件本身并不直接实现逆向技术，但它为 Frida 提供了操作配置文件的能力，这在逆向工程中非常有用。

**举例说明：**

假设 Frida 的一个功能可以通过 TOML 配置文件进行配置，例如，指定要 hook 的函数名称。

1. **读取配置:** Frida 内部会使用 `tomlkit` 库（包含 `items.py`）来读取该配置文件，并将配置信息解析成 `Table` 或其他相应的 `Item` 对象。
2. **修改配置:**  一个逆向工程师可能希望修改 Frida 的行为，例如，添加或修改要 hook 的函数。他可以通过 Frida 的 API 操作代表该配置文件的 `Table` 对象，比如使用 `table_object.append(Key("new_hook_function"), String(StringType.SLB, "my_function", "'my_function'", Trivia()))` 来添加一个新的 hook 函数。
3. **保存配置:** 修改后的配置可以使用 `table_object.as_string()` 方法转换回 TOML 字符串，并保存到配置文件中。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

`items.py` 这个文件本身并不直接涉及二进制底层、Linux/Android 内核或框架的知识。它的作用域限定在 TOML 数据的表示和操作上。

Frida 的其他部分，例如 Gum 引擎，会涉及到这些底层知识，但 `items.py` 只是为这些组件提供了一种方便的方式来管理配置数据。

**逻辑推理及假设输入与输出:**

**假设输入:** 一个 `Array` 对象，其中包含一些 `Integer` 对象。

```python
from tomlkit import array, integer, ws, comment, Trivia
from tomlkit.items import Array

arr = Array([integer(1), ws(", "), integer(2)], Trivia())
```

**操作:** 调用 `append` 方法添加一个新的整数和一个注释。

```python
arr.append(3, comment="添加第三个元素")
```

**预期输出 (内部 `_value` 属性的变化):**

原始的 `arr._value` 可能是类似这样的结构：

```
[_ArrayItemGroup(value=<Integer 1>, indent=None, comma=Whitespace(', ')), _ArrayItemGroup(value=<Integer 2>, indent=None, comma=None)]
```

执行 `append` 后，`arr._value` 可能会变成：

```
[_ArrayItemGroup(value=<Integer 1>, indent=None, comma=Whitespace(', ')), _ArrayItemGroup(value=<Integer 2>, indent=None, comma=Whitespace(', ')), _ArrayItemGroup(value=<Integer 3>, indent=' ', comma=None, comment=<Comment # 添加第三个元素>)]
```

注意：实际的内部结构可能更复杂，包含更多格式信息。这里简化了表示。

**涉及用户或编程常见的使用错误及举例:**

1. **直接修改内部属性:** 用户可能会尝试直接修改 `_value` 列表，而不是使用 `append`, `insert` 等方法。这可能会导致 TOML 格式不正确，例如缺少逗号或空格。

   ```python
   arr = Array([integer(1), integer(2)], Trivia())
   arr._value.append(integer(3))  # 错误的做法，可能导致格式问题
   ```

2. **类型错误:**  尝试将不兼容的类型添加到数组或表中。

   ```python
   table = Table({}, Trivia())
   table["key"] = 123  # 正确，会自动转换为 Integer 对象
   table["another_key"] = [1, 2] # 错误，需要使用 Array 对象
   ```

3. **不理解格式保留:**  用户可能会期望手动添加空格和逗号，但 `tomlkit` 会自动处理这些，重复操作可能会导致格式混乱。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

假设用户在使用 Frida 时遇到了一个与配置文件相关的问题。以下是可能的调试路径：

1. **用户启动 Frida 或运行 Frida 脚本:**  Frida 在启动时或执行脚本时，可能需要读取其配置文件。
2. **配置文件解析:** Frida 内部会使用 `tomlkit` 库来解析配置文件。当解析到数组或表等复杂结构时，会创建相应的 `Array` 或 `Table` 对象。
3. **操作 TOML 数据:**  如果用户的 Frida 脚本需要读取或修改配置文件的某些部分，那么会涉及到对 `Array` 或 `Table` 对象的操作，例如访问元素、添加新的键值对等。
4. **遇到问题:** 如果配置文件格式不正确，或者用户的脚本操作不当，可能会导致 `tomlkit` 抛出异常，或者配置数据与预期不符。
5. **调试:** 在调试过程中，开发者可能会查看 `Array` 或 `Table` 对象的内部状态（例如 `_value` 属性）来了解 TOML 数据的表示方式。如果怀疑是 `tomlkit` 的问题，可能会深入到 `items.py` 的源代码中，查看 `append`, `insert` 等方法的实现，以理解数据是如何被添加和管理的。

**总结 `items.py` 的功能 (基于第 2 部分):**

在提供的代码片段中，主要关注的是 `Array`, `AbstractTable`, `Table`, `InlineTable`, `String`, `AoT`, 和 `Null` 这些类的具体实现。

- **`Array`:**  实现了 TOML 数组的增、删、改操作，并负责维护数组元素的格式，例如逗号和空格。`_group_values` 方法可能用于将原始值分组到带有格式信息的 `_ArrayItemGroup` 中。
- **`AbstractTable`:** 为 `Table` 和 `InlineTable` 提供了共享的接口和实现，例如添加、删除、获取元素等。
- **`Table`:**  表示标准的 TOML 表格（使用 `[]` 定义），支持添加键值对，并能处理缩进等格式。`is_super_table` 方法用于判断是否为嵌套表的中间层。
- **`InlineTable`:** 表示内联表格（使用 `{}` 定义），其 `as_string` 方法的实现方式与标准表格略有不同，因为它需要在一行内输出。
- **`String`:**  表示 TOML 字符串，存储字符串的类型（例如，基本字符串、字面量字符串）和原始表示形式。
- **`AoT`:** 表示表格数组（使用 `[[]]` 定义），它包含一个 `Table` 对象的列表。
- **`Null`:**  表示一个空值。

总的来说，这一部分代码详细定义了各种 TOML 元素的内部结构和操作方式，是 `tomlkit` 库的核心组成部分，负责将 TOML 文本转换为 Python 对象，并允许以编程方式进行操作和修改，同时尽可能保留原始格式。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/tomlkit/tomlkit/items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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