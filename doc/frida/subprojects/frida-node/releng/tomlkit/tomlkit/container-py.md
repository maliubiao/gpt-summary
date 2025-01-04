Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand the functionality of the `Container` class within the `tomlkit` library. Here's a structured approach:

1. **Understand the Context:** The first sentence of the prompt is crucial. It tells us this is part of the `frida` dynamic instrumentation tool and specifically the `tomlkit` library, which is responsible for handling TOML files. This immediately gives us a strong clue about the code's purpose: it's about representing and manipulating TOML data structures.

2. **High-Level Overview:**  Quickly scan the class definition and its methods. Keywords like `add`, `append`, `remove`, `insert`, `item`, `as_string`, `__getitem__`, `__setitem__`, `__delitem__` strongly suggest this class is designed to behave like a dictionary or a container of some kind. The presence of `Table` and `AoT` (Array of Tables) imports points towards handling structured data within TOML.

3. **Core Functionality - Method by Method:** Go through each method and try to understand its purpose. Focus on the key actions and data manipulations:

    * **`__init__`:** Initializes the container, using `_map` (a dictionary) and `_body` (a list) as the primary data structures. The `parsed` flag suggests it tracks the parsing state.
    * **`body`:** Returns the internal `_body` list.
    * **`unwrap`:** Converts the TOML structure into a standard Python dictionary. This is key for interoperability.
    * **`value`:** Similar to `unwrap` but potentially returns wrapped `Container` objects for nested structures.
    * **`parsing`:**  Sets a parsing flag and recursively propagates it to nested `Table` and `AoT` objects.
    * **`add`:** Adds an item, handling cases with and without an explicit key.
    * **`_handle_dotted_key`:** Deals with TOML keys that have dots (e.g., `a.b.c`). This is important for understanding how hierarchical structures are managed.
    * **`_get_last_index_before_table`:**  A helper function likely related to maintaining the order of tables and other elements within the TOML structure.
    * **`_validate_out_of_order_table`:**  Related to how `tomlkit` handles tables that appear after their content.
    * **`append`:**  A fundamental method for adding key-value pairs or other items. It includes significant logic for handling existing keys, tables, and arrays of tables.
    * **`_raw_append`:**  A lower-level append method that directly manipulates the internal data structures.
    * **`_remove_at`, `remove`:** Methods for deleting items.
    * **`_insert_after`, `_insert_at`:** Methods for inserting items at specific locations.
    * **`item`:** Retrieves an item by key.
    * **`last_item`:** Gets the last item in the container.
    * **`as_string`:** Converts the `Container` back into a TOML string representation. This is crucial for outputting the modified TOML.
    * **`_render_table`, `_render_aot`, `_render_aot_table`, `_render_simple_item`:**  Private rendering methods used by `as_string` to format the TOML output.
    * **`__len__`, `__iter__`:** Implement the standard Python container interface.
    * **`__getitem__`, `__setitem__`, `__delitem__`:**  Implement dictionary-like access using square brackets.
    * **`setdefault`:**  Standard dictionary method.
    * **`_replace`, `_replace_at`:** Methods for updating existing items.
    * **`__str__`, `__repr__`, `__eq__`:**  Standard Python methods for string representation and equality comparison.
    * **`_getstate`, `__reduce__`, `__reduce_ex__`, `__setstate__`:** Methods for pickling and unpickling the object.
    * **`copy`, `__copy__`:** Methods for creating copies of the container.
    * **`_previous_item_with_index`, `_previous_item`:** Helper methods for finding the previous item in the `_body` list.

4. **Identify Key Concepts and Relationships:**

    * **TOML Structure:** Recognize the handling of tables (`[table]`), arrays of tables (`[[aot]]`), and key-value pairs.
    * **Internal Representation:** Understand how `_map` (for key-based lookup) and `_body` (for maintaining order and metadata like comments and whitespace) work together.
    * **Immutability/Mutability:** Notice how the methods modify the internal state of the `Container`.
    * **Error Handling:**  See the use of exceptions like `KeyAlreadyPresent` and `NonExistentKey`.
    * **Rendering:**  Understand the process of converting the internal representation back to a TOML string.

5. **Address Specific Prompt Requirements:**  Now, systematically go through each of the specific questions in the prompt:

    * **Functionality:**  Summarize the main actions the class performs (add, remove, modify, render TOML).
    * **Relationship to Reversing:** Think about how modifying TOML files could be useful in reverse engineering (e.g., changing configuration settings, altering program behavior by changing data).
    * **Binary/Kernel/Framework Knowledge:**  Consider if any operations directly interact with low-level systems. In this case, the code primarily deals with in-memory data structures and string manipulation, not direct kernel or binary interactions. However, the *purpose* within Frida implies interaction with a running process. The TOML likely configures some aspect of Frida or the target process.
    * **Logical Inference:** Look for methods that make decisions based on the state of the container (e.g., how `append` handles different item types and existing keys). Create input/output examples.
    * **Common Usage Errors:** Identify potential mistakes a user could make (e.g., adding duplicate keys, incorrect key types).
    * **User Steps to Reach Here (Debugging):**  Imagine a scenario where this code is executed during a Frida session. How would a user interact with Frida to cause this code to be involved?  This leads to the idea of scripts that modify TOML configurations.

6. **Refine and Organize:**  Structure the findings logically, using clear headings and examples. Ensure the language is precise and avoids jargon where possible, explaining technical terms when necessary.

7. **Review and Iterate:** Read through the analysis to ensure it's accurate, comprehensive, and addresses all aspects of the prompt. Correct any errors or omissions. For instance, initially, I might not have explicitly connected the "parsed" flag to the preservation of formatting, and a review would help me add that detail.

This structured approach combines code comprehension with an understanding of the broader context and the specific requirements of the prompt. It allows for a thorough and well-organized analysis.
This Python code defines the `Container` class within the `tomlkit` library, which is used for parsing, manipulating, and generating TOML (Tom's Obvious, Minimal Language) documents. Here's a breakdown of its functionality:

**Core Functionality of the `Container` Class:**

* **Representation of TOML Structures:** The `Container` class acts as a dictionary-like structure to hold TOML data. It can represent the root of a TOML document or nested tables within it.
* **Ordered Key-Value Storage:**  Unlike standard Python dictionaries, `Container` preserves the order of keys as they appear in the TOML document. This is achieved using the `_body` list, which stores key-item pairs in order.
* **Metadata Storage:** Besides the actual values, `Container` also stores metadata associated with TOML elements, such as:
    * **Comments:** Comments associated with keys or tables.
    * **Whitespace:** Whitespace and newlines to maintain the original formatting of the TOML document.
    * **Trivia:**  A container for whitespace and comments associated with an item.
* **Manipulation of TOML Data:** It provides methods to add, remove, update, and retrieve TOML elements (key-value pairs, tables, arrays of tables).
* **Handling Different TOML Types:** It can store various TOML item types like:
    * **Key-value pairs:**  Represented by `Key` and other item types (strings, numbers, booleans, etc.).
    * **Tables:** Represented by the `Table` class, which is itself a `Container`.
    * **Arrays of Tables (AoT):** Represented by the `AoT` class, containing a list of `Table` instances.
* **String Rendering:**  It has the ability to render the contained TOML data back into a formatted TOML string, preserving the original structure and metadata.
* **Dotted Key Handling:**  It supports adding and managing keys with dots (e.g., `owner.name`), which represent nested tables.
* **Out-of-Order Table Handling:** It has mechanisms to handle TOML where tables might appear after the key-value pairs they contain.
* **Copying and Deepcopying:**  It implements the `copy` and `deepcopy` protocols for creating copies of the container.

**Relationship to Reverse Engineering:**

The `Container` class, being part of `tomlkit`, is indirectly related to reverse engineering through its ability to manipulate configuration files that might be in TOML format.

* **Modifying Configuration:** In reverse engineering, you might encounter applications that use TOML files for configuration. Using Frida and `tomlkit`, you could:
    * **Parse the configuration file:** Load the TOML configuration into a `Container` object.
    * **Modify settings:**  Use the `Container`'s methods (e.g., `__setitem__`, `append`) to change configuration values.
    * **Inject the modified configuration:**  Potentially write the modified TOML back to the file or manipulate the application's memory to use the altered configuration.

**Example:**

Let's say an Android application stores network settings in a TOML file like this:

```toml
[network]
timeout = 10
server_address = "https://example.com"
```

Using Frida, you could modify the `timeout` value:

```python
import frida
import tomlkit

# Assume you have a Frida session attached to the Android app
session = frida.attach("com.example.app")

# Imagine a function in the app reads the TOML config file into a string
# and stores it in a global variable 'toml_config_string'

script = session.create_script("""
    var tomlString = Module.findExportByName(null, "get_toml_config_string")(); // Hypothetical function
    send(tomlString);
""")
script.on('message', on_message)
script.load()

def on_message(message, data):
    if message['type'] == 'send':
        toml_string = message['payload']
        doc = tomlkit.parse(toml_string)
        doc['network']['timeout'] = 60  # Modify the timeout
        modified_toml_string = tomlkit.dumps(doc)
        print(modified_toml_string)
        # You could then inject this modified string back into the app's memory
        # or try to force the app to reload the configuration.
```

**Binary Underlying, Linux, Android Kernel, and Framework Knowledge:**

While the `Container` class itself doesn't directly interact with the binary level or the kernel, its usage within Frida for dynamic instrumentation implies interaction with these layers:

* **Frida's Interaction:** Frida works by injecting a JavaScript engine into the target process. The Python code you write interacts with this engine. Modifying TOML configurations often involves:
    * **Reading memory:**  Finding where the application stores the TOML configuration in its memory. This requires knowledge of the application's memory layout, which can be obtained through reverse engineering techniques.
    * **Writing memory:**  Injecting the modified TOML string back into the application's memory. This requires understanding memory addresses and potentially bypassing security measures.
* **File System Interaction (Less Direct):**  If the application reads the TOML configuration from a file, you might need to interact with the Android file system to modify the file directly. This could involve:
    * **Knowing the file path:**  Figuring out where the configuration file is located within the Android app's data directory.
    * **Using Frida APIs:**  Potentially using Frida to execute system calls or interact with file system APIs.
* **Application Framework (Android):**  Understanding how Android applications manage configurations (e.g., using `SharedPreferences` as an alternative to TOML) is crucial for knowing where and how to apply modifications.

**Logical Inference (Hypothetical Input and Output):**

**Scenario:** Adding a new key-value pair to an existing table.

**Input:**

```python
container = tomlkit.table()
container.append("name", "My App")
container.append("version", "1.0")
```

**Method Call:**

```python
container.add("author", "John Doe")
```

**Output (Internal `_body` list would be updated):**

The internal `_body` of the `container` would now have a new entry for the "author" key and its value. The exact structure depends on the internal representation of `Key` and the item type for "John Doe", but it would look something like:

```
[
    (SingleKey('name'), String('My App')),
    (SingleKey('version'), String('1.0')),
    (SingleKey('author'), String('John Doe'))
]
```

**Output (Rendering to TOML string):**

```toml
name = "My App"
version = "1.0"
author = "John Doe"
```

**Common Usage Errors:**

* **Adding Duplicate Keys:** TOML doesn't allow duplicate keys within the same table. Trying to add a key that already exists will raise a `KeyAlreadyPresent` exception.

   ```python
   container = tomlkit.table()
   container.add("name", "App A")
   try:
       container.add("name", "App B")  # This will raise KeyAlreadyPresent
   except tomlkit.exceptions.KeyAlreadyPresent as e:
       print(e)
   ```

* **Incorrect Key Types:**  Using non-string types as keys directly might lead to errors. While `tomlkit` might handle simple cases, it's best to use strings for keys.

   ```python
   container = tomlkit.table()
   try:
       container[123] = "value"  # Might not be directly supported as a key
   except Exception as e:
       print(e)
   ```

* **Modifying Immutable Values:**  If you retrieve a value and try to modify it in place without setting it back in the container, the changes might not be reflected.

   ```python
   container = tomlkit.parse("name = ['a', 'b']")
   name_list = container['name']
   name_list.append('c')
   print(container['name'])  # Output: ['a', 'b'] - the change is not reflected
   container['name'] = name_list # Correct way to update
   print(container['name'])  # Output: ['a', 'b', 'c']
   ```

**User Operations Leading to This Code (Debugging Clues):**

A user, while using Frida to instrument an application, might reach this code in the following steps:

1. **Identify a TOML Configuration:** The user first needs to determine that the target application uses a TOML file or string for its configuration. This might involve:
    * **Static Analysis:** Examining the application's code or resources.
    * **Dynamic Observation:** Observing the application's behavior and noticing patterns that suggest the use of configuration files.
2. **Access the TOML Data:** The user needs to access the TOML data within the running application. This often involves using Frida to:
    * **Hook function calls:** Intercept functions that read the TOML file or process the TOML string in memory.
    * **Read memory:** Directly read the memory location where the TOML data is stored.
3. **Parse the TOML Data:** Once the TOML data is obtained (as a string), the user would use `tomlkit.parse()` to convert it into a `Container` object. This is where the `Container` class comes into play.
4. **Manipulate the `Container`:** The user would then use the methods of the `Container` class (e.g., `add`, `__setitem__`, `remove`) to modify the configuration.
5. **Apply the Changes:** Finally, the user would need to apply the changes back to the application. This could involve:
    * **Writing the modified TOML back to a file.**
    * **Injecting the modified TOML string back into the application's memory.**
    * **Calling functions within the application that reload or re-read the configuration.**

**Example Debugging Scenario:**

A user is trying to debug why a certain feature is disabled in an Android app. They suspect a configuration setting in a TOML file. They use Frida to:

1. **Hook the file reading function:** They use Frida to intercept the function that reads the TOML configuration file from the file system.
2. **Get the TOML content:** Inside the hook, they extract the TOML content as a string.
3. **Parse the TOML:** They use `tomlkit.parse()` to create a `Container` object.
4. **Inspect the `Container`:** They examine the `Container` object to find the relevant configuration key and its value.
5. **Modify the `Container`:** They use `container['feature_flags']['enable_experimental'] = True` to enable the feature.
6. **Render the modified TOML:** They use `tomlkit.dumps(container)` to get the modified TOML string.
7. **Replace the original TOML:** They use Frida to overwrite the original TOML content in memory or attempt to force the app to reload the configuration from the modified string.

This step-by-step process illustrates how a user's actions while debugging with Frida can directly involve the functionality of the `Container` class in `tomlkit`.

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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