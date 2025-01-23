Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for an analysis of the provided Python code, focusing on its functionalities, relation to reverse engineering, low-level/kernel interactions, logical reasoning, common errors, and debugging contexts.

2. **Initial Scan and Keyword Recognition:**  Quickly skim the code, looking for familiar keywords and patterns. Keywords like `import`, `def`, `class`, `assert`, `dict`, `list`, `datetime`, `parse`, `update`, `delete`, `pickle`, `json`, etc., give clues about the code's purpose. The file path `frida/subprojects/frida-node/releng/tomlkit/tests/test_toml_document.py` immediately suggests this is a test file for a library (`tomlkit`) likely used within the Frida ecosystem.

3. **Identify Core Functionality:** The filename and the presence of `parse` and `as_string` strongly indicate the code is about manipulating TOML documents. The tests cover various aspects of this manipulation: creating, reading, updating, deleting, and formatting TOML data.

4. **Group Tests by Functionality:**  Mentally group the test functions based on the TOML features they are testing. For example:
    * Basic dictionary-like behavior (`test_document_is_a_dict`)
    * Handling dotted keys (`test_toml_document_with_dotted_keys`)
    * Working with subtables (`test_toml_document_without_super_tables`, `test_document_with_new_sub_table_after_other_table`)
    * Array of Tables (AOT) (`test_document_with_aot_after_sub_tables`, `test_toml_document_super_aot_after_super_table`)
    * Pickling and copying (`test_toml_document_is_pickable`, `test_toml_document_can_be_copied`)
    * Preserving formatting (whitespace, comments)
    * Error handling (`test_values_can_still_be_set_for_out_of_order_tables` mentioning `NonExistentKey`)

5. **Relate to Reverse Engineering (Frida Context):** The file path hints at Frida. Think about how TOML might be used in a dynamic instrumentation tool like Frida:
    * **Configuration:** Frida might use TOML to store its own configuration settings (target process, scripts to load, etc.).
    * **Inter-process Communication:** While less direct, TOML could be used to format data exchanged between Frida and other components.
    * **Scripting Metadata:**  Frida scripts themselves might have metadata stored in TOML format.

6. **Consider Low-Level/Kernel Aspects:**  While the *test code* itself doesn't directly interact with the kernel, the *library being tested* (tomlkit) is likely used within Frida. Frida, being a dynamic instrumentation tool, *does* have extensive low-level interactions. Connect the dots:
    * Frida injects into processes.
    * It reads and modifies process memory.
    * It interacts with system calls.
    * It might hook functions in libraries or the kernel.
    * Configuration for these operations *could* be stored in TOML.

7. **Analyze Logical Reasoning:**  Look for tests that implicitly demonstrate logical steps:
    * **Updating values:**  A value is changed, and the output is asserted to reflect that change.
    * **Deleting keys:** A key is removed, and subsequent attempts to access it raise an error.
    * **Conditional behavior:**  Inserting after an element without a newline adds one.

8. **Identify Potential User Errors:** Think about common mistakes when working with configuration files or data structures:
    * Incorrect key names (leading to `NonExistentKey`).
    * Unexpected data types.
    * Formatting errors in hand-written TOML.
    * Trying to access or modify data in a way that violates TOML's structure.

9. **Trace User Operations to the Test File (Debugging Context):** Imagine a scenario where a Frida user encounters an issue related to TOML configuration:
    * A user modifies a Frida configuration file (likely TOML).
    * Frida attempts to parse this file.
    * If parsing fails or the configuration is misinterpreted, unexpected behavior occurs.
    * To debug this, a developer might look at the TOML parsing logic and its tests (like this file) to understand how the library handles different TOML structures and potential errors.

10. **Structure the Output:** Organize the findings into the requested categories: functionalities, relation to reverse engineering, low-level/kernel aspects, logical reasoning, user errors, and debugging context. Provide specific examples from the code to illustrate each point.

11. **Refine and Elaborate:**  Review the analysis and add more details or explanations where needed. For instance, when discussing low-level aspects, be specific about the types of interactions Frida has. For user errors, give concrete examples of incorrect TOML.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a TOML parsing library test."
* **Correction:** "Wait, the file path mentions Frida. How does TOML fit into Frida's functionality?" This leads to connecting TOML to configuration.
* **Initial thought:** "The tests don't show any low-level code."
* **Correction:** "The tests are for the *tomlkit* library. Frida *uses* this library, and Frida *does* interact with low-level systems. So, indirectly, this library is involved in those interactions."
* **Initial thought:**  Focus only on the direct actions in the tests.
* **Correction:** Expand to think about the *implications* of these actions, such as what happens when a user makes a mistake in a TOML configuration file that Frida uses.

By following this structured approach, combining code analysis with contextual knowledge (about Frida and TOML), and incorporating self-correction, a comprehensive and accurate analysis can be generated.
This Python file `test_toml_document.py` is part of the test suite for the `tomlkit` library, which is a TOML (Tom's Obvious, Minimal Language) parser and serializer for Python. Its primary function is to **thoroughly test the `tomlkit.api.document` class and its ability to represent and manipulate TOML documents in memory.**

Here's a breakdown of its functionalities:

**Core Functionality: Testing TOML Document Manipulation**

* **Parsing TOML:** The tests use `tomlkit.parse()` to load TOML strings into `Document` objects. This verifies the parser's ability to handle various TOML syntax elements like:
    * Key-value pairs
    * Tables (standard and inline)
    * Sub-tables (dotted keys)
    * Arrays
    * Arrays of tables (AOT)
    * Different data types (strings, integers, booleans, datetimes)
    * Comments
* **Accessing and Retrieving Data:**  Tests verify that data within the `Document` object can be accessed like a Python dictionary using bracket notation (`doc["key"]`) and the `get()` method.
* **Updating Data:** The tests demonstrate how to modify existing values and add new key-value pairs or tables to the `Document` using dictionary-like assignment (`doc["key"] = value`) and the `update()` method.
* **Deleting Data:** Tests cover removing key-value pairs and entire tables using the `del` keyword.
* **Creating and Setting Default Values:**  The `setdefault()` method is tested for adding new items only if they don't already exist.
* **String Representation (`as_string()`):** A crucial part is testing that the `as_string()` method correctly serializes the in-memory `Document` back into a TOML string, preserving formatting (whitespace, comments, order in many cases).
* **Unwrapping:** The `unwrap()` method is tested to ensure it returns a standard Python dictionary representing the TOML structure.
* **Pickling and Copying:** Tests verify that `Document` objects can be serialized using `pickle` and copied using `copy.copy()` and `copy.deepcopy()`, ensuring data integrity.
* **Working with Inline Tables:** Specific tests ensure correct handling of inline tables.
* **Out-of-Order Tables:**  A significant portion of the tests focuses on handling TOML where tables and sub-tables are defined in a non-hierarchical order. This verifies that `tomlkit` can correctly build the nested structure.
* **Preserving Order:** While TOML is generally order-insensitive, the tests check if `tomlkit` preserves the order of key-value pairs and tables in the output string when possible.
* **Comments:** Tests verify that comments are preserved during parsing and serialization.
* **Whitespace:** Tests ensure that whitespace around key-value assignments and table headers is handled correctly.
* **Moving and Replacing Tables:**  Tests cover scenarios where entire tables are moved (`pop`) or replaced with other values or tables.
* **Representations (`__repr__`):** The tests verify the string representation of the `Document` object for debugging purposes.
* **Error Handling:** While not explicitly raising exceptions in most tests, the structure implicitly tests for correct behavior when keys are missing or when modifying data. The `test_values_can_still_be_set_for_out_of_order_tables` explicitly tests for `NonExistentKey`.

**Relation to Reverse Engineering (Indirect)**

While this specific test file doesn't directly involve reverse engineering techniques, the `tomlkit` library itself can be valuable in reverse engineering contexts:

* **Analyzing Configuration Files:**  Many applications, including those targeted by dynamic instrumentation tools like Frida, use configuration files in TOML format. `tomlkit` allows you to parse and inspect these configuration files to understand how the application is set up and potentially identify interesting parameters or behaviors.
    * **Example:**  Imagine reverse engineering a game where the game's settings (graphics, audio, network) are stored in a TOML file. Using `tomlkit`, you could parse this file to understand which settings influence specific aspects of the game's behavior.
* **Modifying Application Behavior:**  In some cases, you might want to modify an application's behavior by altering its configuration file. `tomlkit` allows you to parse the TOML, make changes to the in-memory representation, and then serialize it back to a file.
    * **Example:**  If a piece of malware uses a TOML configuration to specify its command-and-control server, you could use `tomlkit` to parse the configuration, change the server address, and then potentially analyze where the malware attempts to connect.

**Relation to Binary, Linux/Android Kernel/Framework Knowledge (Indirect)**

Again, this specific *test file* doesn't directly interact with these low-level components. However, the broader context of Frida and the potential use of `tomlkit` within it connects to these areas:

* **Frida Configuration:** Frida itself might use TOML for its own configuration (e.g., specifying which processes to attach to, which scripts to load). Understanding how Frida's configuration is structured often involves interacting with the file system and parsing files, where a library like `tomlkit` comes into play.
* **Application Internals:**  When reverse engineering, you often need to understand how applications work at a lower level. Configuration files (potentially in TOML format) can provide insights into:
    * **API Keys and Secrets:**  Configuration files might contain sensitive information that is relevant for understanding how an application interacts with external services.
    * **Feature Flags:**  TOML can be used to enable or disable features within an application, providing clues about its internal structure and capabilities.
    * **Internal Addresses and Ports:**  For network-related applications, TOML might specify default ports or server addresses.
* **Android Framework:**  While less common than other formats like XML or Protobuf, it's conceivable that some Android applications or even parts of the Android framework could utilize TOML for configuration. `tomlkit` could be used to analyze these configurations on an Android device.

**Logical Reasoning (Implicit in Tests)**

The tests themselves are a form of logical reasoning:

* **Assumption:** If we parse a TOML string with a specific structure and then serialize it back, the output should match the original (or a predictably formatted version).
* **Input:** A specific TOML string (e.g., with nested tables, arrays).
* **Process:** Parsing the string into a `Document` object and then calling `as_string()`.
* **Output:** The resulting TOML string.
* **Assertion:** The output string matches the expected string.

For example, in `test_document_with_new_sub_table_after_other_table_delete`:

* **Input:** The TOML string defines three tables: `foo`, `bar`, and `foo.baz`.
* **Action:** The `del doc["foo"]` operation is performed.
* **Expected Output:** The serialized string should only contain the `bar` table.
* **Assertion:** `doc.as_string()` is compared against the expected string.

**User or Programming Common Usage Errors (Illustrative)**

The tests implicitly highlight potential user errors when working with `tomlkit` or TOML in general:

* **Incorrect Key Names:** Trying to access a key that doesn't exist (e.g., `doc["nonexistent_key"]`) would raise a `KeyError` (or potentially a `NonExistentKey` as tested).
* **Type Mismatches:**  Assuming a value is a string when it's actually an integer.
* **Incorrect TOML Syntax:** If a user tries to parse a string with invalid TOML syntax, `tomlkit.parse()` would raise a parsing error.
* **Forgetting to Serialize Changes:** Modifying the `Document` object in memory but forgetting to call `as_string()` to save the changes back to a file.
* **Misunderstanding Table Structure:**  Assuming a table exists at a certain level when it's actually a sub-table or vice-versa.
    * **Example:**  Trying to access `doc["tool"]["poetry"]["name"]` when the TOML actually has `[tool.poetry.name]` (which is invalid TOML, but illustrates a conceptual misunderstanding).

**User Operations Leading to This Code (Debugging Context)**

A developer working on the `frida-node` project (which uses Frida) might end up looking at this test file in several scenarios:

1. **Developing or Debugging `tomlkit`:** If they are contributing to or fixing bugs in the `tomlkit` library itself, they would be directly working with these tests to ensure the library functions correctly.
2. **Investigating Issues with Frida Configuration:** If a user reports a problem with how Frida is parsing or handling its TOML configuration files, a developer might look at these tests to understand how `tomlkit` behaves with different TOML structures and to potentially reproduce the user's issue.
    * **Scenario:** A user reports that a particular configuration setting in their Frida setup isn't being applied correctly. A developer might examine the Frida configuration file, try parsing it with `tomlkit`, and then look at these tests to see if `tomlkit` is handling the relevant TOML syntax as expected.
3. **Adding New Features to Frida that Involve TOML:** If a new feature in Frida requires reading or writing TOML configuration, developers might refer to these tests to understand best practices for using `tomlkit` and to write new tests for their own code.
4. **Troubleshooting Integration Between Frida and Node.js:** Since the file path includes `frida-node`, the tests could be relevant for understanding how TOML configuration is handled within the Node.js bindings for Frida. If there are issues with configuration in this context, these tests could provide insights.

In summary, `test_toml_document.py` is a crucial part of ensuring the correctness of the `tomlkit` library, which, while not directly a reverse engineering tool itself, can be a valuable utility in the broader context of dynamic instrumentation and application analysis, especially within the Frida ecosystem.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```