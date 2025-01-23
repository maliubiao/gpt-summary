Response:
Let's break down the thought process for analyzing this Python code and addressing the user's request.

**1. Understanding the Goal:**

The primary goal is to analyze the provided Python code (`container.py`) and describe its functionality, especially in the context of Frida, reverse engineering, and low-level systems. The user also wants specific examples related to logical reasoning, common errors, and how a user might reach this code.

**2. Initial Code Examination (Skimming):**

First, I'd quickly skim the code to get a general idea of its structure and purpose. Keywords like `Container`, `Table`, `AoT`, `Key`, `Item`, `add`, `append`, `remove`, `parsing`, `as_string`, and methods like `__getitem__`, `__setitem__`, `__delitem__` immediately suggest this code is about managing structured data, likely in a TOML format. The presence of `_map` and `_body` hints at an internal representation of the data.

**3. Identifying Core Functionality:**

Next, I'd go through the code more methodically, focusing on the key classes and methods:

* **`Container`:**  This is the central class. It behaves like a dictionary but has extra features for preserving the order and structure of TOML data. I'd look at its methods to understand how data is added, accessed, modified, and rendered. The methods related to `Table` and `AoT` (Array of Tables) are significant for TOML.
* **`OutOfOrderTableProxy`:** This class seems designed to handle a specific case: tables defined out of the typical order in a TOML file. This is a more advanced feature and worth noting.
* **Item-related classes (`Key`, `SingleKey`, `Table`, `AoT`, `Comment`, `Whitespace`, `Null`):** These classes represent the building blocks of a TOML document. Understanding how they are used within `Container` is crucial.
* **Error Handling (`KeyAlreadyPresent`, `NonExistentKey`, `TOMLKitError`):** These exceptions indicate what kind of problems the code anticipates.

**4. Connecting to User's Specific Questions:**

Now I'd address each part of the user's request systematically:

* **Functionality:**  Summarize the purpose of the `Container` class and its key methods. Emphasize that it's about managing TOML data while preserving structure and formatting.

* **Relationship to Reverse Engineering:** This is where the Frida context comes in. I need to think about how configuration files are used in software, including reverse engineering tools. TOML is a common format for configuration. Frida likely uses it to store settings. The ability to parse and manipulate these settings programmatically is relevant for dynamic instrumentation. *Example:* Imagine a Frida script that modifies a configuration value to disable a security feature during runtime analysis.

* **Binary/Kernel/Framework Relevance:** This requires knowledge of how configuration plays a role in these areas.
    * **Binary:**  Configuration can affect program behavior.
    * **Linux/Android Kernel:** While less direct, configuration files might influence kernel module loading or system settings (though TOML isn't typical for *core* kernel config).
    * **Android Framework:**  Android makes extensive use of configuration files (e.g., XML, but conceptually similar). Thinking about how settings affect framework components is key. *Example:*  Modifying a setting to enable debug logging in an Android service.

* **Logical Reasoning (Input/Output):** I need to pick a simple method and illustrate its behavior with a clear example. `add` or `append` are good choices. Focus on a simple case to demonstrate the relationship between input (key, value) and output (modification of the internal `_body` and `_map`).

* **Common Usage Errors:**  Consider what could go wrong when using a dictionary-like structure. Trying to add a duplicate key is a classic error. Using the wrong type of key or value could also be an issue.

* **User Operation (Debugging Clues):**  Trace a plausible path a user might take to end up inspecting this code. The most likely scenario is a developer working with Frida Python bindings, encountering an issue with TOML configuration, and then looking at the underlying implementation. Mentioning error messages and the debugging process is important.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points to improve readability. Start with a general overview and then delve into the specific aspects requested by the user. Provide clear examples for each point.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the code directly interacts with the file system for reading/writing TOML.
* **Correction:** On closer inspection, the code focuses on the *in-memory representation* and manipulation of TOML data. Reading and writing are likely handled by other parts of the `tomlkit` library.

* **Initial thought:** The connection to the kernel is very direct.
* **Correction:**  The connection is more likely indirect, via configuration files that *influence* kernel behavior or are used by user-space programs interacting with the kernel.

* **Ensuring Clarity:** Use precise language and avoid jargon where possible. Explain TOML concepts if necessary. Make sure the examples are easy to understand.

By following this systematic thought process, breaking down the problem, and iteratively refining the analysis, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
This Python code file, `container.py`, is part of the `tomlkit` library, which is used for parsing, manipulating, and serializing TOML (Tom's Obvious, Minimal Language) documents in Python. As the path indicates, it's specifically within the Frida project's Python bindings, suggesting Frida uses TOML for configuration or data representation.

Here's a breakdown of its functionality:

**Core Functionality of the `Container` Class:**

The `Container` class is the heart of this file. It's designed to represent a TOML table (or the root of a TOML document) and behaves like an ordered dictionary with extra features to preserve TOML structure and formatting. Key functionalities include:

1. **Data Storage:**  It stores TOML key-value pairs and other elements like comments and whitespace in the `_body` list, maintaining the order they appeared in the original TOML.
2. **Key Mapping:** The `_map` dictionary provides efficient lookup of items by their keys, mapping keys to their indices (or a tuple of indices for out-of-order tables) within the `_body`.
3. **Ordered Iteration:** Unlike standard Python dictionaries, it preserves the order of items when iterating.
4. **TOML Structure Preservation:** It stores not just the values but also associated trivia (whitespace, comments) for each item, enabling faithful serialization back to TOML.
5. **Table and Array of Tables (AoT) Handling:**  It specifically handles TOML tables (using nested `Container` instances) and arrays of tables.
6. **Dotted Key Handling:** It supports adding and managing items with dotted keys (e.g., `a.b.c = value`), creating nested tables as needed.
7. **"Unwrapping" to Python Objects:** The `unwrap()` method converts the `Container` into a standard Python dictionary, recursively unwrapping nested containers.
8. **Parsing State Management:** The `parsing()` method tracks whether the container is currently being parsed, influencing how new items are added (e.g., whether to add default indentation).
9. **Adding Items (`add`, `append`):** Provides methods for adding new key-value pairs, comments, or whitespace.
10. **Removing Items (`remove`):** Allows removing items by their keys.
11. **Inserting Items (`_insert_after`, `_insert_at`):** Provides fine-grained control over where new items are inserted.
12. **Accessing Items (`__getitem__`, `item`):** Enables accessing items by key, returning the `Item` object or its value.
13. **Rendering to TOML (`as_string`, `_render_table`, etc.):**  Methods to serialize the `Container` back into a TOML string, preserving original formatting.
14. **Error Handling:** Raises specific exceptions like `KeyAlreadyPresent` and `NonExistentKey`.
15. **Copying and Deepcopying:** Implements `copy` and `deepcopy` for creating copies of the container.
16. **Out-of-Order Table Handling:** The `OutOfOrderTableProxy` class specifically deals with tables defined out of the typical order in a TOML file, allowing manipulation of these tables as if they were in order.

**Relationship to Reverse Engineering and Frida:**

This code is directly relevant to reverse engineering when using Frida:

* **Frida Configuration:** Frida likely uses TOML files to store its own configuration settings, script options, or target application configurations. This `container.py` code would be used by Frida's Python bindings to parse and manipulate these configuration files.
    * **Example:** A Frida script might read a TOML configuration file to determine which functions to hook or which memory regions to monitor. The `Container` class would be used to load the TOML data into memory, and methods like `__getitem__` would be used to access specific configuration values.
* **Target Application Configuration:**  If the target application being instrumented by Frida uses TOML for its own configuration, Frida scripts could use `tomlkit` (and this `container.py`) to read, modify, and even rewrite the application's configuration on the fly. This allows for dynamic alteration of application behavior during runtime analysis.
    * **Example:** An Android application might store API keys or feature flags in a TOML file. A Frida script could use `tomlkit` to change these values to bypass licensing checks or enable hidden features during reverse engineering.

**Relevance to Binary Underlying, Linux/Android Kernel & Framework:**

While `tomlkit` itself doesn't directly interact with the binary level or the kernel, its usage within Frida has implications:

* **Binary Level (Indirect):**  By manipulating configuration files, Frida scripts can indirectly influence the behavior of compiled binaries. For instance, changing a setting that controls logging verbosity or the enabling/disabling of certain modules in a native application.
* **Linux/Android Kernel (Indirect):**  Similarly, if user-space applications or daemons interact with kernel modules based on configuration files (which could be in TOML format, though less common at the core kernel level), Frida could potentially influence this interaction by modifying those configuration files.
* **Android Framework (More Direct):** Android applications frequently use configuration files (often XML, but the concept is the same). Frida, being a powerful tool for instrumenting Android processes, can use libraries like `tomlkit` to interact with these configurations.
    * **Example:** An Android service might read its operational parameters from a TOML file. A Frida script could modify this TOML file to alter the service's behavior, perhaps to inject custom data or bypass security checks. The `parsing()` method in `Container` might be used to ensure the updated configuration is correctly interpreted.

**Logical Reasoning (Hypothetical Input & Output):**

Let's say you have a TOML file `config.toml` with the following content:

```toml
[database]
server = "192.168.1.10"
ports = [ 8000, 8001, 8002 ]

[application]
debug_mode = true
log_level = "INFO"
```

**Hypothetical Frida Script Snippet:**

```python
import tomlkit

with open("config.toml", "r") as f:
    config = tomlkit.load(f)

# Accessing a value
server_address = config["database"]["server"]
print(f"Server address: {server_address}")  # Output: Server address: 192.168.1.10

# Modifying a value
config["application"]["debug_mode"] = False

# Adding a new value
config["application"]["new_setting"] = "example"

# Serializing back to TOML (would involve other tomlkit functions)
# new_toml_string = tomlkit.dumps(config)
```

**How `container.py` is involved:**

* When `tomlkit.load(f)` is called, the TOML parser in `tomlkit` would create a `Container` object representing the root of the TOML document.
* Accessing values like `config["database"]` and `config["application"]["debug_mode"]` would internally use the `__getitem__` method of the `Container` class to navigate the `_body` and `_map`.
* Modifying values like `config["application"]["debug_mode"] = False` would call the `__setitem__` method of the `Container`, updating the corresponding `Item` within the `_body`.
* Adding a new value would involve the `append` or `add` methods of the `Container`.

**Common Usage Errors:**

Users might make the following errors when interacting with `Container` objects (or indirectly via `tomlkit`):

1. **Accessing a Non-Existent Key:**
   ```python
   # Assuming 'nonexistent_key' doesn't exist in the TOML
   try:
       value = config["nonexistent_key"]  # This will raise a NonExistentKey exception
   except tomlkit.exceptions.NonExistentKey as e:
       print(f"Error: {e}")
   ```
   This happens because the `__getitem__` method checks the `_map` and raises `NonExistentKey` if the key isn't found.

2. **Adding a Key That Already Exists (without intending to overwrite):**
   ```python
   config["database"]["server"] = "new_server"  # This will overwrite the existing "server" value

   # If you try to add the same key again directly, it might depend on the context
   # and might raise KeyAlreadyPresent in some scenarios, especially during parsing.
   ```
   The `append` method, for example, checks for existing keys and can raise `KeyAlreadyPresent`. The `__setitem__` method, however, typically overwrites existing keys.

3. **Incorrect Data Types:** TOML has specific data types. Trying to assign a Python object that doesn't map well to a TOML type might lead to unexpected behavior or errors during serialization.

4. **Modifying Structure Incorrectly:**  Directly manipulating the `_body` or `_map` without understanding their structure can lead to inconsistencies and break the internal logic of the `Container`. Users should generally use the provided methods like `add`, `append`, `remove`, etc.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Writing a Frida Script:** A user is developing a Frida script to instrument an application that uses TOML for configuration.
2. **Using `tomlkit`:** The script imports and uses the `tomlkit` library to parse the application's TOML configuration file.
   ```python
   import frida
   import tomlkit

   def on_message(message, data):
       print(message)

   session = frida.attach("target_application")
   script = session.create_script("""
       // ... JavaScript code ...
   """)
   script.on('message', on_message)
   script.load()

   with open("app_config.toml", "r") as f:
       config = tomlkit.load(f)

   # ... access or modify config using tomlkit ...
   ```
3. **Encountering an Error or Unexpected Behavior:** The script might fail to parse the TOML correctly, might not access the desired configuration values, or might not serialize changes as expected.
4. **Debugging with a Python Debugger (e.g., `pdb`):** The user might use a debugger to step through their Python code. They might set breakpoints in their script or even within the `tomlkit` library to understand what's happening.
5. **Stepping into `tomlkit` Code:** If the issue lies within how `tomlkit` is handling the TOML structure, the user might step into the `tomlkit` library's code.
6. **Landing in `container.py`:**  While debugging, the user might step into the methods of the `Container` class (e.g., `__getitem__`, `append`, `_render_table`) to examine how the TOML data is being stored and manipulated internally. They might inspect the `_body` and `_map` attributes to understand the internal representation.
7. **Examining the Source Code:**  Out of curiosity or to understand the implementation details, the user might open the `container.py` file directly to see the source code of the `Container` class and its related components. This is especially likely if they encounter exceptions raised by the `Container` and want to understand the conditions under which those exceptions are triggered.

In summary, `container.py` is a crucial component of the `tomlkit` library, responsible for representing and manipulating TOML data in a structured and ordered manner. Its presence in Frida's Python bindings highlights the importance of configuration file handling in dynamic instrumentation and reverse engineering workflows.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/tomlkit/tomlkit/container.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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