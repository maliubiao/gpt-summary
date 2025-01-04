Response:
Let's break down the thought process for analyzing this Python code. The goal is to extract the functionality, identify connections to reverse engineering, low-level concepts, reasoning, common errors, and trace user interaction.

**1. Initial Understanding - What is this?**

The first lines clearly state this is a test file (`test_toml_document.py`) for the `tomlkit` library, part of the `frida-gum` project within the Frida dynamic instrumentation tool. This immediately gives context: we're dealing with testing the behavior of a TOML parsing/manipulation library.

**2. High-Level Functionality Scan:**

Skimming through the test function names (e.g., `test_document_is_a_dict`, `test_toml_document_without_super_tables`, `test_adding_an_element_to_existing_table_with_ws_remove_ws`) provides a good overview of the functionalities being tested. The tests cover:

* **Basic TOML parsing:** Loading and accessing data.
* **Data types:** Handling strings, integers, booleans, dates, lists, dictionaries (tables).
* **Table manipulation:** Adding, deleting, updating, and moving elements and tables.
* **Dotted keys:** Accessing nested data using `a.b.c` syntax.
* **Array of Tables (AOT):** Handling lists of tables.
* **Whitespace and formatting:** Ensuring correct output formatting.
* **Pickling and copying:** Testing serialization and object duplication.
* **Error handling:**  Checking for `NonExistentKey` exceptions.
* **Output formatting:** Verifying the `as_string()` method.

**3. Identifying Reverse Engineering Connections:**

This requires thinking about how TOML might be used in reverse engineering scenarios. Key considerations:

* **Configuration files:** Software often uses configuration files in formats like TOML. Reverse engineers need to parse these to understand program behavior, settings, and dependencies.
* **Frida context:**  Since this is within Frida, think about how Frida uses configuration. Frida might use TOML for its own settings or when interacting with target processes that use TOML.
* **Example:** The `pyproject.toml` example file hints at Python project configuration. A reverse engineer might encounter this when analyzing Python applications.

**4. Identifying Low-Level/Kernel Connections:**

This requires connecting the code's actions to lower-level concepts:

* **File I/O:** Parsing TOML involves reading files.
* **Memory Management:**  Creating and manipulating data structures (dictionaries, lists) involves memory allocation.
* **String manipulation:**  Parsing involves processing text.
* **Frida's interaction with processes:** Frida instruments *running* processes. Configuration (like TOML) might be read at the start of a process.
* **Operating System Concepts:**  File systems, process memory.
* **Android Kernel/Framework (less direct but possible):** Android apps might use configuration files. Frida can be used on Android.

**5. Logical Reasoning and Input/Output Examples:**

For each test, consider:

* **Input:** The TOML content being parsed.
* **Operation:** The actions performed on the parsed document (e.g., adding, deleting, updating).
* **Expected Output:** The resulting TOML string after the operation.

Example:  For `test_document_is_a_dict`, the input is the "example" TOML, and the code verifies the structure and values within the parsed document.

**6. Common User Errors:**

Think about mistakes a programmer might make when using a TOML library:

* **Incorrect key access:** Trying to access a non-existent key.
* **Invalid TOML syntax:**  While the tests *use* valid TOML, a user might try to parse invalid TOML. This test file doesn't directly test invalid syntax handling, but it's a common error to consider.
* **Incorrect data types:** Trying to assign a value of the wrong type.
* **Misunderstanding table nesting:** Incorrectly assuming the structure of tables.

**7. Tracing User Interaction (Debugging Clue):**

Imagine a user debugging an issue where Frida isn't behaving as expected. How might they end up looking at this test file?

* **Frida development:**  Someone contributing to Frida might be writing or debugging TOML parsing logic.
* **Troubleshooting Frida scripts:**  A user's Frida script might be failing because of incorrect TOML configuration. They might delve into Frida's internals (including `frida-gum`) to understand how it handles configuration.
* **Reporting bugs:** A user might find a bug in TOML parsing and provide this test file (or similar information) when reporting the issue.

**8. Iterative Refinement:**

After the initial pass, review the code and the generated analysis. Are there any missed connections or areas where the explanation could be clearer?  For example, ensure the reverse engineering examples are concrete and relevant to Frida. Double-check the assumptions made for logical reasoning and user errors.

By following this structured approach, combining code analysis with domain knowledge (reverse engineering, low-level concepts), and considering potential user scenarios, we can generate a comprehensive and informative explanation of the code's functionality and its relevance in various contexts.
This Python code file, `test_toml_document.py`, is part of the test suite for the `tomlkit` library. `tomlkit` is a Python library used for parsing, manipulating, and generating TOML (Tom's Obvious, Minimal Language) documents. TOML is a configuration file format that is easy to read due to its simple syntax.

Here's a breakdown of its functionalities:

**Core Functionality: Testing TOML Document Manipulation**

The primary goal of this file is to test the behavior of the `tomlkit.document` class, which represents a parsed TOML document. It verifies various operations that can be performed on a TOML document, including:

* **Parsing:**  Loading TOML strings into `tomlkit.document` objects using `tomlkit.parse()`.
* **Accessing Data:** Retrieving values from the document using dictionary-like access (e.g., `doc["owner"]["name"]`). It tests both bracket notation and the `get()` method.
* **Data Type Handling:** Verifying that different TOML data types (strings, integers, booleans, dates, arrays, tables, inline tables) are parsed correctly.
* **Table and Sub-table Management:**
    * Accessing and manipulating nested tables (e.g., `doc["servers"]["alpha"]`).
    * Creating new tables and sub-tables.
    * Handling "super tables" (tables defined using dotted keys like `[tool.poetry]`).
    * Managing arrays of tables (`[[products]]`).
* **Modification:**
    * Updating existing values.
    * Adding new key-value pairs.
    * Setting default values using `setdefault()`.
    * Deleting keys using `del`.
    * Replacing entire tables or values.
* **Whitespace and Formatting:** Testing that whitespace is preserved or handled correctly during parsing and when modifying the document.
* **Output Generation:**  Verifying the `as_string()` method, which converts the `tomlkit.document` back into a TOML formatted string. It checks that the output matches the expected format after various operations.
* **Pickling and Copying:** Testing that `tomlkit.document` objects can be serialized using `pickle` and copied using `copy.copy()` and `copy.deepcopy()`.
* **Unwrapping:** Testing the `unwrap()` method, which converts the `tomlkit.document` into a standard Python dictionary.
* **Order Preservation:** Verifying that the order of elements in the TOML document is maintained during parsing and modification, especially for out-of-order tables.
* **Comments:** While not explicitly tested for direct manipulation in this file, the examples demonstrate that `tomlkit` can parse TOML with comments.
* **Error Handling:**  Testing that accessing non-existent keys raises the `NonExistentKey` exception.

**Relationship to Reverse Engineering**

TOML is a popular configuration file format. In reverse engineering, you might encounter TOML files used by:

* **Applications:**  Applications often use configuration files to store settings, preferences, and other parameters. Understanding these settings can be crucial to understanding the application's behavior.
* **Libraries and Frameworks:** Libraries and frameworks might use TOML for their own configuration or for defining project metadata (like `pyproject.toml` in Python projects, as seen in the examples).
* **Game Engines:** Some game engines use TOML for configuring game assets, levels, or gameplay mechanics.

**Example of Reverse Engineering Relevance:**

Imagine you are reverse engineering a closed-source application. You discover a configuration file named `settings.toml` with the following content:

```toml
[network]
server_address = "192.168.1.100"
port = 8080
use_ssl = true

[logging]
level = "info"
log_file = "/var/log/app.log"
```

Using a dynamic instrumentation tool like Frida, you could use a library like `tomlkit` (or reimplement the parsing logic) to parse this configuration file at runtime. This would allow you to:

1. **Inspect the current settings:** Understand how the application is currently configured.
2. **Modify settings on the fly:** Change the `server_address`, `port`, or `log_level` to observe how the application behaves with different configurations without restarting it. This is a powerful technique for exploring application behavior and finding vulnerabilities.
3. **Hook into configuration loading:**  Identify the code responsible for loading the TOML file and potentially intercept or modify the parsed configuration data before it's used by the application.

**Binary Underpinnings, Linux/Android Kernel/Framework Knowledge**

While `tomlkit` itself is a high-level Python library, understanding how it operates and how it might be used in a Frida context touches upon lower-level concepts:

* **File I/O:**  Parsing a TOML file involves reading data from the file system. This relies on operating system APIs for file access (e.g., `open()`, `read()` in Python, which map to system calls in Linux/Android kernels).
* **Memory Management:**  Creating and manipulating the `tomlkit.document` object involves allocating and managing memory to store the parsed data. Python's memory management handles this, but understanding how memory is organized within a process is relevant.
* **String Processing:**  Parsing TOML involves significant string manipulation to identify keys, values, and delimiters.
* **Frida's Integration:** When using `tomlkit` within Frida, you're operating within the address space of the target process. Understanding how Frida injects code and interacts with the target process's memory is important.
* **Android Context (if the target is an Android app):**
    * **File System Differences:**  Android has a different file system structure than traditional Linux systems.
    * **Permissions:** Accessing configuration files might require specific permissions within the Android application's sandbox.
    * **Framework APIs:** Android applications might use framework APIs to access configuration data, potentially in formats other than TOML. Understanding these APIs can be relevant if you're trying to intercept configuration loading at a higher level.

**Logical Reasoning, Assumptions, Input/Output**

Many of the tests in the file demonstrate logical reasoning about how TOML documents should behave. Here's an example:

**Test:** `test_adding_an_element_to_existing_table_with_ws_remove_ws()`

**Assumption:** When adding a new key-value pair to a table, `tomlkit` should insert it at an appropriate location within the table's definition, potentially adjusting whitespace for readability.

**Input TOML:**

```toml
[foo]

[foo.bar]
```

**Operation:** `doc["foo"]["int"] = 34`

**Expected Output TOML:**

```toml
[foo]
int = 34

[foo.bar]
```

**Reasoning:** The test expects the new key-value pair (`int = 34`) to be added within the `[foo]` table, before the definition of the sub-table `[foo.bar]`. It also expects any empty lines around the table header to be preserved.

**Common User Errors**

This test suite helps prevent common user errors when *using* the `tomlkit` library. Examples of errors a programmer might make when working with TOML and `tomlkit`:

* **Incorrect Key Access:**  Trying to access a key that doesn't exist will raise a `NonExistentKey` error, as tested in `test_values_can_still_be_set_for_out_of_order_tables()`. Without such testing, users might get unexpected `None` values or other issues.
* **Assuming Order of Insertion:**  While `tomlkit` generally preserves order, understanding how out-of-order tables are handled is important. This test suite ensures consistent behavior.
* **Incorrectly Modifying Structure:**  Users might try to replace tables with values or vice-versa in unexpected ways. The tests verify how `tomlkit` handles these scenarios (e.g., `test_replace_with_table()`, `test_replace_table_with_value()`).
* **Misunderstanding Whitespace Handling:**  Users might expect whitespace to be treated in a particular way. Tests like `test_adding_an_element_to_existing_table_with_ws_remove_ws()` ensure predictable whitespace management.

**User Operations and Debugging Clues**

How might a user end up looking at `test_toml_document.py` as a debugging clue?

1. **Frida Script Development:** A user writing a Frida script to interact with an application that uses TOML for configuration might encounter unexpected behavior. They might suspect an issue with how their script is parsing or manipulating the TOML.
2. **`tomlkit` Library Usage:** If a user is directly using the `tomlkit` library in their Python code and encounters a bug or unexpected behavior related to TOML document manipulation, they might look at the test suite to understand how the library is *supposed* to work and potentially find similar test cases that reveal the source of their issue.
3. **Bug Reporting:** If a user believes they have found a bug in the `tomlkit` library itself, they might examine the test suite to see if the bug is already covered by a failing test or if they can create a new test case that demonstrates the bug.
4. **Contributing to Frida/`tomlkit`:**  A developer contributing to the Frida or `tomlkit` projects would certainly use and examine these test files to ensure their changes don't introduce regressions or to add new tests for new features.
5. **Investigating Frida Internals:** If a user is deeply investigating how Frida works internally, especially the parts related to interacting with target processes and potentially parsing configuration files, they might find themselves examining the test suites of Frida's subprojects like `frida-gum` and its dependencies like `tomlkit`.

In summary, `test_toml_document.py` is a crucial part of ensuring the reliability and correctness of the `tomlkit` library, which is a valuable tool in various contexts, including reverse engineering with Frida. It tests a wide range of TOML document manipulation functionalities, helping to prevent common errors and providing a reference for understanding the library's intended behavior.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
import copy
import json
import pickle

from datetime import datetime
from textwrap import dedent

import pytest

import tomlkit

from tests.util import assert_is_ppo
from tomlkit import parse
from tomlkit import ws
from tomlkit._utils import _utc
from tomlkit.api import document
from tomlkit.exceptions import NonExistentKey


def test_document_is_a_dict(example):
    content = example("example")

    doc = parse(content)

    assert isinstance(doc, dict)
    assert "owner" in doc

    # owner
    owner = doc["owner"]
    assert doc.get("owner") == owner
    assert isinstance(owner, dict)
    assert "name" in owner
    assert owner["name"] == "Tom Preston-Werner"
    assert owner["organization"] == "GitHub"
    assert owner["bio"] == "GitHub Cofounder & CEO\nLikes tater tots and beer."
    assert owner["dob"] == datetime(1979, 5, 27, 7, 32, tzinfo=_utc)

    # database
    database = doc["database"]
    assert isinstance(database, dict)
    assert database["server"] == "192.168.1.1"
    assert database["ports"] == [8001, 8001, 8002]
    assert database["connection_max"] == 5000
    assert database["enabled"] is True

    # servers
    servers = doc["servers"]
    assert isinstance(servers, dict)

    alpha = servers["alpha"]
    assert servers.get("alpha") == alpha
    assert isinstance(alpha, dict)
    assert alpha["ip"] == "10.0.0.1"
    assert alpha["dc"] == "eqdc10"

    beta = servers["beta"]
    assert isinstance(beta, dict)
    assert beta["ip"] == "10.0.0.2"
    assert beta["dc"] == "eqdc10"
    assert beta["country"] == "中国"

    # clients
    clients = doc["clients"]
    assert isinstance(clients, dict)

    data = clients["data"]
    assert isinstance(data, list)
    assert data[0] == ["gamma", "delta"]
    assert data[1] == [1, 2]

    assert clients["hosts"] == ["alpha", "omega"]

    # Products
    products = doc["products"]
    assert isinstance(products, list)

    hammer = products[0]
    assert hammer == {"name": "Hammer", "sku": 738594937}

    nail = products[1]
    assert nail["name"] == "Nail"
    assert nail["sku"] == 284758393
    assert nail["color"] == "gray"

    nail["color"] = "black"
    assert nail["color"] == "black"
    assert doc["products"][1]["color"] == "black"
    assert nail.get("color") == "black"

    content = """foo = "bar"
"""

    doc = parse(content)
    doc.update({"bar": "baz"})

    assert (
        doc.as_string()
        == """foo = "bar"
bar = "baz"
"""
    )

    doc.update({"bar": "boom"})

    assert (
        doc.as_string()
        == """foo = "bar"
bar = "boom"
"""
    )

    assert doc.setdefault("bar", "waldo") == "boom"

    assert (
        doc.as_string()
        == """foo = "bar"
bar = "boom"
"""
    )

    assert doc.setdefault("thud", "waldo") == "waldo"

    assert (
        doc.as_string()
        == """foo = "bar"
bar = "boom"
thud = "waldo"
"""
    )


def test_toml_document_without_super_tables():
    content = """[tool.poetry]
name = "foo"
"""

    doc = parse(content)
    assert "tool" in doc
    assert "poetry" in doc["tool"]

    assert doc["tool"]["poetry"]["name"] == "foo"

    doc["tool"]["poetry"]["name"] = "bar"

    assert (
        doc.as_string()
        == """[tool.poetry]
name = "bar"
"""
    )

    d = {}
    d.update(doc)

    assert "tool" in d


def test_toml_document_unwrap():
    content = """[tool.poetry]
name = "foo"
"""

    doc = parse(content)
    unwrapped = doc.unwrap()
    assert_is_ppo(unwrapped, dict)
    assert_is_ppo(list(unwrapped.keys())[0], str)
    assert_is_ppo(unwrapped["tool"], dict)
    assert_is_ppo(list(unwrapped["tool"].keys())[0], str)
    assert_is_ppo(unwrapped["tool"]["poetry"]["name"], str)


def test_toml_document_with_dotted_keys(example):
    content = example("0.5.0")

    doc = parse(content)

    assert "physical" in doc
    assert "color" in doc["physical"]
    assert "shape" in doc["physical"]
    assert doc["physical"]["color"] == "orange"
    assert doc["physical"]["shape"] == "round"

    assert "site" in doc
    assert "google.com" in doc["site"]
    assert doc["site"]["google.com"]

    assert doc["a"]["b"]["c"] == 1
    assert doc["a"]["b"]["d"] == 2


def test_toml_document_super_table_with_different_sub_sections(example):
    content = example("pyproject")

    doc = parse(content)
    tool = doc["tool"]

    assert "poetry" in tool
    assert "black" in tool


def test_adding_an_element_to_existing_table_with_ws_remove_ws():
    content = """[foo]

[foo.bar]

"""

    doc = parse(content)
    doc["foo"]["int"] = 34

    expected = """[foo]
int = 34

[foo.bar]

"""

    assert expected == doc.as_string()


def test_document_with_aot_after_sub_tables():
    content = """[foo.bar]
name = "Bar"

[foo.bar.baz]
name = "Baz"

[[foo.bar.tests]]
name = "Test 1"
"""

    doc = parse(content)
    assert doc["foo"]["bar"]["tests"][0]["name"] == "Test 1"


def test_document_with_new_sub_table_after_other_table():
    content = """[foo]
name = "Bar"

[bar]
name = "Baz"

[foo.baz]
name = "Test 1"
"""

    doc = parse(content)
    assert doc["foo"]["name"] == "Bar"
    assert doc["bar"]["name"] == "Baz"
    assert doc["foo"]["baz"]["name"] == "Test 1"

    assert doc.as_string() == content


def test_document_with_new_sub_table_after_other_table_delete():
    content = """[foo]
name = "Bar"

[bar]
name = "Baz"

[foo.baz]
name = "Test 1"
"""

    doc = parse(content)

    del doc["foo"]

    assert (
        doc.as_string()
        == """[bar]
name = "Baz"

"""
    )


def test_document_with_new_sub_table_after_other_table_replace():
    content = """[foo]
name = "Bar"

[bar]
name = "Baz"

[foo.baz]
name = "Test 1"
"""

    doc = parse(content)

    doc["foo"] = {"a": "b"}

    assert (
        doc.as_string()
        == """[foo]
a = "b"

[bar]
name = "Baz"

"""
    )


def test_inserting_after_element_with_no_new_line_adds_a_new_line():
    doc = parse("foo = 10")
    doc["bar"] = 11

    expected = """foo = 10
bar = 11
"""

    assert expected == doc.as_string()

    doc = parse("# Comment")
    doc["bar"] = 11

    expected = """# Comment
bar = 11
"""

    assert expected == doc.as_string()


def test_inserting_after_deletion():
    doc = parse("foo = 10\n")
    del doc["foo"]

    doc["bar"] = 11

    expected = """bar = 11
"""

    assert expected == doc.as_string()


def test_toml_document_with_dotted_keys_inside_table(example):
    content = example("0.5.0")

    doc = parse(content)
    t = doc["table"]

    assert "a" in t

    assert t["a"]["b"]["c"] == 1
    assert t["a"]["b"]["d"] == 2
    assert t["a"]["c"] == 3


def test_toml_document_with_super_aot_after_super_table(example):
    content = example("pyproject")

    doc = parse(content)
    aot = doc["tool"]["foo"]

    assert isinstance(aot, list)

    first = aot[0]
    assert first["name"] == "first"

    second = aot[1]
    assert second["name"] == "second"


def test_toml_document_has_always_a_new_line_after_table_header():
    content = """[section.sub]"""

    doc = parse(content)
    assert doc.as_string() == """[section.sub]"""

    doc["section"]["sub"]["foo"] = "bar"
    assert (
        doc.as_string()
        == """[section.sub]
foo = "bar"
"""
    )

    del doc["section"]["sub"]["foo"]

    assert doc.as_string() == """[section.sub]"""


def test_toml_document_is_pickable(example):
    content = example("example")

    doc = parse(content)
    assert pickle.loads(pickle.dumps(doc)).as_string() == content


def test_toml_document_set_super_table_element():
    content = """[site.user]
name = "John"
"""

    doc = parse(content)
    doc["site"]["user"] = "Tom"

    assert (
        doc.as_string()
        == """[site]
user = "Tom"
"""
    )


def test_toml_document_can_be_copied():
    content = "[foo]\nbar=1"

    doc = parse(content)
    doc = copy.copy(doc)

    assert (
        doc.as_string()
        == """[foo]
bar=1"""
    )

    assert doc == {"foo": {"bar": 1}}
    assert doc["foo"]["bar"] == 1
    assert json.loads(json.dumps(doc)) == {"foo": {"bar": 1}}

    doc = parse(content)
    doc = doc.copy()

    assert (
        doc.as_string()
        == """[foo]
bar=1"""
    )

    assert doc == {"foo": {"bar": 1}}
    assert doc["foo"]["bar"] == 1
    assert json.loads(json.dumps(doc)) == {"foo": {"bar": 1}}


def test_getting_inline_table_is_still_an_inline_table():
    content = """\
[tool.poetry]
name = "foo"

[tool.poetry.dependencies]

[tool.poetry.dev-dependencies]
"""

    doc = parse(content)
    poetry_section = doc["tool"]["poetry"]
    dependencies = poetry_section["dependencies"]
    dependencies["foo"] = tomlkit.inline_table()
    dependencies["foo"]["version"] = "^2.0"
    dependencies["foo"]["source"] = "local"
    dependencies["bar"] = tomlkit.inline_table()
    dependencies["bar"]["version"] = "^3.0"
    dependencies["bar"]["source"] = "remote"
    dev_dependencies = poetry_section["dev-dependencies"]
    dev_dependencies["baz"] = tomlkit.inline_table()
    dev_dependencies["baz"]["version"] = "^4.0"
    dev_dependencies["baz"]["source"] = "other"

    assert (
        doc.as_string()
        == """\
[tool.poetry]
name = "foo"

[tool.poetry.dependencies]
foo = {version = "^2.0", source = "local"}
bar = {version = "^3.0", source = "remote"}

[tool.poetry.dev-dependencies]
baz = {version = "^4.0", source = "other"}
"""
    )


def test_declare_sub_table_with_intermediate_table():
    content = """
[students]
tommy = 87
mary = 66

[subjects]
maths = "maths"
english = "english"

[students.bob]
score = 91
"""

    doc = parse(content)
    assert {"tommy": 87, "mary": 66, "bob": {"score": 91}} == doc["students"]
    assert {"tommy": 87, "mary": 66, "bob": {"score": 91}} == doc.get("students")


def test_values_can_still_be_set_for_out_of_order_tables():
    content = """
[a.a]
key = "value"

[a.b]

[a.a.c]
"""

    doc = parse(content)
    doc["a"]["a"]["key"] = "new_value"

    assert doc["a"]["a"]["key"] == "new_value"

    expected = """
[a.a]
key = "new_value"

[a.b]

[a.a.c]
"""

    assert expected == doc.as_string()

    doc["a"]["a"]["bar"] = "baz"

    expected = """
[a.a]
key = "new_value"
bar = "baz"

[a.b]

[a.a.c]
"""

    assert expected == doc.as_string()

    del doc["a"]["a"]["key"]

    expected = """
[a.a]
bar = "baz"

[a.b]

[a.a.c]
"""

    assert expected == doc.as_string()

    with pytest.raises(NonExistentKey):
        doc["a"]["a"]["key"]

    with pytest.raises(NonExistentKey):
        del doc["a"]["a"]["key"]


def test_out_of_order_table_can_add_multiple_tables():
    content = """\
[a.a.b]
x = 1
[foo]
bar = 1
[a.a.c]
y = 1
[a.a.d]
z = 1
"""
    doc = parse(content)
    assert doc.as_string() == content
    assert doc["a"]["a"] == {"b": {"x": 1}, "c": {"y": 1}, "d": {"z": 1}}


def test_out_of_order_tables_are_still_dicts():
    content = """
[a.a]
key = "value"

[a.b]

[a.a.c]
"""

    doc = parse(content)
    assert isinstance(doc["a"], dict)
    assert isinstance(doc["a"]["a"], dict)

    table = doc["a"]["a"]
    assert "key" in table
    assert "c" in table
    assert table.get("key") == "value"
    assert {} == table.get("c")
    assert table.get("d") is None
    assert table.get("d", "foo") == "foo"

    assert table.setdefault("d", "bar") == "bar"
    assert table["d"] == "bar"

    assert table.pop("key") == "value"
    assert "key" not in table

    assert table.pop("missing", default="baz") == "baz"

    with pytest.raises(KeyError):
        table.pop("missing")


def test_string_output_order_is_preserved_for_out_of_order_tables():
    content = """
[tool.poetry]
name = "foo"

[tool.poetry.dependencies]
python = "^3.6"
bar = "^1.0"


[build-system]
requires = ["poetry-core"]
backend = "poetry.core.masonry.api"


[tool.other]
a = "b"
"""

    doc = parse(content)
    constraint = tomlkit.inline_table()
    constraint["version"] = "^1.0"
    doc["tool"]["poetry"]["dependencies"]["bar"] = constraint

    assert doc["tool"]["poetry"]["dependencies"]["bar"]["version"] == "^1.0"

    expected = """
[tool.poetry]
name = "foo"

[tool.poetry.dependencies]
python = "^3.6"
bar = {version = "^1.0"}


[build-system]
requires = ["poetry-core"]
backend = "poetry.core.masonry.api"


[tool.other]
a = "b"
"""

    assert expected == doc.as_string()


def test_remove_from_out_of_order_table():
    content = """[a]
x = 1

[c]
z = 3

[a.b]
y = 2
"""
    document = parse(content)
    del document["a"]["b"]
    assert (
        document.as_string()
        == """[a]
x = 1

[c]
z = 3

"""
    )
    assert json.dumps(document) == '{"a": {"x": 1}, "c": {"z": 3}}'


def test_updating_nested_value_keeps_correct_indent():
    content = """
[Key1]
      [key1.Key2]
      Value1 = 10
      Value2 = 30
"""

    doc = parse(content)
    doc["key1"]["Key2"]["Value1"] = 20

    expected = """
[Key1]
      [key1.Key2]
      Value1 = 20
      Value2 = 30
"""

    assert doc.as_string() == expected


def test_repr():
    content = """
namespace.key1 = "value1"
namespace.key2 = "value2"
[tool.poetry.foo]
option = "test"
[tool.poetry.bar]
option = "test"
inline = {"foo" = "bar", "bar" = "baz"}
"""

    doc = parse(content)

    assert (
        repr(doc)
        == "{'namespace': {'key1': 'value1', 'key2': 'value2'}, 'tool': {'poetry': {'foo': {'option': 'test'}, 'bar': {'option': 'test', 'inline': {'foo': 'bar', 'bar': 'baz'}}}}}"
    )

    assert (
        repr(doc["tool"])
        == "{'poetry': {'foo': {'option': 'test'}, 'bar': {'option': 'test', 'inline': {'foo': 'bar', 'bar': 'baz'}}}}"
    )

    assert repr(doc["namespace"]) == "{'key1': 'value1', 'key2': 'value2'}"


def test_deepcopy():
    content = """
[tool]
name = "foo"
[tool.project.section]
option = "test"
"""
    doc = parse(content)
    copied = copy.deepcopy(doc)
    assert copied == doc
    assert copied.as_string() == content


def test_move_table():
    content = """a = 1
[x]
a = 1

[y]
b = 1
"""
    doc = parse(content)
    doc["a"] = doc.pop("x")
    doc["z"] = doc.pop("y")
    assert (
        doc.as_string()
        == """[a]
a = 1

[z]
b = 1
"""
    )


def test_replace_with_table():
    content = """a = 1
b = 2
c = 3
"""
    doc = parse(content)
    doc["b"] = {"foo": "bar"}
    assert (
        doc.as_string()
        == """a = 1
c = 3

[b]
foo = "bar"
"""
    )


def test_replace_table_with_value():
    content = """[foo]
a = 1

[bar]
b = 2
"""
    doc = parse(content)
    doc["bar"] = 42
    assert (
        doc.as_string()
        == """bar = 42
[foo]
a = 1

"""
    )


def test_replace_preserve_sep():
    content = """a   =   1

[foo]
b  =  "what"
"""
    doc = parse(content)
    doc["a"] = 2
    doc["foo"]["b"] = "how"
    assert (
        doc.as_string()
        == """a   =   2

[foo]
b  =  "how"
"""
    )


def test_replace_with_table_of_nested():
    example = """\
    [a]
    x = 1

    [a.b]
    y = 2
    """
    doc = parse(dedent(example))
    doc["c"] = doc.pop("a")
    expected = """\
    [c]
    x = 1

    [c.b]
    y = 2
    """
    assert doc.as_string().strip() == dedent(expected).strip()


def test_replace_with_aot_of_nested():
    example = """\
    [a]
    x = 1

    [[a.b]]
    y = 2

    [[a.b]]

    [a.b.c]
    z = 2

    [[a.b.c.d]]
    w = 2
    """
    doc = parse(dedent(example))
    doc["f"] = doc.pop("a")
    expected = """\
    [f]
    x = 1

    [[f.b]]
    y = 2

    [[f.b]]

    [f.b.c]
    z = 2

    [[f.b.c.d]]
    w = 2
    """
    assert doc.as_string().strip() == dedent(expected).strip()


def test_replace_with_comment():
    content = 'a = "1"'
    doc = parse(content)
    a = tomlkit.item(int(doc["a"]))
    a.comment("`a` should be an int")
    doc["a"] = a
    expected = "a = 1 # `a` should be an int"
    assert doc.as_string() == expected

    content = 'a = "1, 2, 3"'
    doc = parse(content)
    a = tomlkit.array()
    a.comment("`a` should be an array")
    for x in doc["a"].split(","):
        a.append(int(x.strip()))
    doc["a"] = a
    expected = "a = [1, 2, 3] # `a` should be an array"
    assert doc.as_string() == expected

    doc = parse(content)
    a = tomlkit.inline_table()
    a.comment("`a` should be an inline-table")
    for x in doc["a"].split(","):
        i = int(x.strip())
        a.append(chr(ord("a") + i - 1), i)
    doc["a"] = a
    expected = "a = {a = 1, b = 2, c = 3} # `a` should be an inline-table"
    assert doc.as_string() == expected


def test_no_spurious_whitespaces():
    content = """\
    [x]
    a = 1

    [y]
    b = 2
    """
    doc = parse(dedent(content))
    doc["z"] = doc.pop("y")
    expected = """\
    [x]
    a = 1

    [z]
    b = 2
    """
    assert doc.as_string() == dedent(expected)
    doc["w"] = {"c": 3}
    expected = """\
    [x]
    a = 1

    [z]
    b = 2

    [w]
    c = 3
    """
    assert doc.as_string() == dedent(expected)

    doc = parse(dedent(content))
    del doc["x"]
    doc["z"] = {"c": 3}
    expected = """\
    [y]
    b = 2

    [z]
    c = 3
    """
    assert doc.as_string() == dedent(expected)


def test_pop_add_whitespace_and_insert_table_work_togheter():
    content = """\
    a = 1
    b = 2
    c = 3
    d = 4
    """
    doc = parse(dedent(content))
    doc.pop("a")
    doc.pop("b")
    doc.add(ws("\n"))
    doc["e"] = {"foo": "bar"}
    expected = """\
    c = 3
    d = 4

    [e]
    foo = "bar"
    """
    text = doc.as_string()
    out = parse(text)
    assert out["d"] == 4
    assert "d" not in out["e"]
    assert text == dedent(expected)


def test_add_newline_before_super_table():
    doc = document()
    doc["a"] = 1
    doc["b"] = {"c": {}}
    doc["d"] = {"e": {}}
    expected = """\
    a = 1

    [b.c]

    [d.e]
    """
    assert doc.as_string() == dedent(expected)


def test_remove_item_from_super_table():
    content = """\
    [hello.one]
    a = 1

    [hello.two]
    b = 1
    """
    doc = parse(dedent(content))
    del doc["hello"]["two"]
    expected = """\
    [hello.one]
    a = 1

    """
    assert doc.as_string() == dedent(expected)


def test_nested_table_update_display_name():
    content = """\
    [parent]

    [parent.foo]
    x = 1
    """

    doc = parse(dedent(content))
    sub = """\
    [foo]
    y = 2

    [bar]
    z = 3
    """
    doc["parent"].update(parse(dedent(sub)))
    expected = """\
    [parent]

    [parent.foo]
    y = 2

    [parent.bar]
    z = 3
    """
    assert doc.as_string() == dedent(expected)


def test_build_table_with_dotted_key():
    doc = tomlkit.document()
    data = {
        "a.b.c": 1,
        "a.b.d": 2,
        "a": {"c": {"foo": "bar"}},
        "a.d.e": 3,
    }

    for key, value in data.items():
        if "." not in key:
            doc.append(key, value)
        else:
            doc.append(tomlkit.key(key.split(".")), value)

    expected = """\
a.b.c = 1
a.b.d = 2
a.d.e = 3

[a.c]
foo = "bar"
"""
    assert doc.as_string() == expected
    assert json.loads(json.dumps(doc)) == {
        "a": {"b": {"c": 1, "d": 2}, "d": {"e": 3}, "c": {"foo": "bar"}}
    }


def test_parse_subtables_no_extra_indent():
    expected = """\
[a]
    [a.b.c]
        foo = 1

    [a.b.d]
        bar = 2
"""
    doc = parse(expected)
    assert doc.as_string() == expected


def test_item_preserves_the_order():
    t = tomlkit.inline_table()
    t.update({"a": 1, "b": 2})
    doc = {"name": "foo", "table": t, "age": 42}
    expected = """\
name = "foo"
table = {a = 1, b = 2}
age = 42
"""
    assert tomlkit.dumps(doc) == expected

"""

```