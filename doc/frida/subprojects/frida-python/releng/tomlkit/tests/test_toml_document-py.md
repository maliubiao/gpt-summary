Response:
Let's break down the thought process for analyzing the Python code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `test_toml_document.py` file within the Frida project. Specifically, the prompt asks for:

* A summary of the file's functions.
* Connections to reverse engineering.
* Connections to low-level OS concepts (Linux, Android, kernel).
* Examples of logical reasoning within the tests.
* Common user errors the tests might expose.
* How a user might reach this code (debugging context).

**2. Initial Code Scan and Identifying the Purpose:**

The filename `test_toml_document.py` immediately suggests this file contains tests for a module related to TOML documents. The imports at the top (`import copy`, `import json`, `import pickle`, `from datetime`, `from textwrap`, `import pytest`, `import tomlkit`, etc.) confirm this. `tomlkit` is clearly the library being tested. The presence of `pytest` indicates these are unit tests.

**3. Analyzing Individual Test Functions:**

The next step is to examine the individual test functions (those starting with `def test_`). Each test function focuses on a specific aspect of how `tomlkit` handles TOML documents. As I read through each test, I try to understand:

* **What is being set up?** (e.g., loading a TOML string, creating a `tomlkit` document).
* **What action is being performed?** (e.g., accessing elements, modifying values, adding new elements, deleting elements, copying, pickling).
* **What is being asserted?** (e.g., the type of an object, the value of an element, the string representation of the document).

**4. Grouping Functionalities and Summarization:**

After analyzing several test functions, patterns emerge. The tests cover operations like:

* **Basic parsing and access:**  Reading values from a TOML document using dictionary-like syntax.
* **Modification:**  Changing existing values.
* **Addition:**  Adding new keys and values, including tables and arrays of tables.
* **Deletion:**  Removing keys and tables.
* **String representation (`as_string()`):** Ensuring the output TOML string is correct, including formatting and whitespace.
* **Data structure behavior:**  Verifying that `tomlkit` documents behave like dictionaries.
* **Advanced features:** Handling dotted keys, super tables, arrays of tables, inline tables.
* **Serialization and copying:** Testing `pickle`, `copy`, and `deepcopy`.
* **Error handling:** Testing for `NonExistentKey`.
* **Preserving order:** Ensuring that the order of elements in the TOML is maintained.

This analysis allows me to create the "Functionality List" in the answer.

**5. Connecting to Reverse Engineering:**

This requires a bit more thought. While the code itself isn't directly performing reverse engineering, its purpose – testing a TOML parser – has clear relevance. Configuration files are ubiquitous in software. Reverse engineers often need to understand and potentially modify these files. TOML is a common configuration format. Therefore, a reliable TOML parser is a valuable tool for a reverse engineer. I then brainstorm examples of how configuration files are used in reverse engineering scenarios (e.g., analyzing game settings, identifying API endpoints).

**6. Connecting to Low-Level OS Concepts:**

This requires thinking about where TOML configuration might be used in the context of the target environment of Frida (likely Linux/Android). Configuration files are used for system settings, service configurations, and application settings. I consider where these configurations might reside in a Linux or Android environment and how Frida might interact with processes that use these configurations.

**7. Identifying Logical Reasoning in Tests:**

This involves looking for tests that set up specific conditions and then verify the outcome based on expected logical behavior. The tests that manipulate the TOML structure (adding, deleting, updating) and then assert the final string representation are good examples of this. The "Hypothetical Input and Output" section provides a clear example.

**8. Identifying Common User Errors:**

This involves thinking about how someone might misuse the `tomlkit` library or write incorrect TOML. Examples include:

* Trying to access non-existent keys.
* Incorrectly formatted TOML.
* Expecting dictionary-like behavior that isn't fully implemented.

The test cases that raise `NonExistentKey` are direct examples of this.

**9. Tracing User Operations (Debugging Context):**

This requires understanding how a developer using Frida would interact with this code. The most likely scenario is that a developer is working on or debugging the Python bindings for Frida (`frida-python`). They might be:

* Running unit tests as part of the development process.
* Investigating a bug related to TOML parsing or manipulation within Frida's Python components.
* Modifying the `tomlkit` library itself or its integration within Frida.

This helps explain the steps a developer would take to arrive at this specific test file.

**10. Refinement and Structuring the Answer:**

Finally, I organize the information into the requested sections of the prompt, ensuring clarity and providing specific examples for each point. I review the answer to make sure it's comprehensive and addresses all aspects of the question. I pay attention to the phrasing and try to make the connections to reverse engineering and low-level concepts as explicit as possible.
这个文件 `test_toml_document.py` 是 `frida-python` 项目中 `tomlkit` 子项目的测试文件，专门用于测试 `tomlkit` 库中关于 TOML 文档对象 (`tomlkit.api.document`) 的功能。

以下是它的功能列表，以及与逆向、二进制底层、内核框架、逻辑推理、用户错误和调试线索相关的说明：

**功能列表:**

1. **解析 TOML 内容:**  测试 `tomlkit.parse()` 函数能否正确地将 TOML 格式的字符串解析为 `Document` 对象，并验证解析后的数据结构（例如，字典、列表、字符串、数字、布尔值、日期时间对象）是否正确。
2. **访问和操作文档元素:**  测试如何使用类似字典的语法 (`doc["key"]`) 和方法 (`doc.get("key")`) 来访问 `Document` 对象中的元素，包括标量值、表格 (table)、内联表格 (inline table) 和数组 (array)。
3. **修改文档元素:** 测试如何修改 `Document` 对象中的元素的值，包括标量值、表格和内联表格中的值。
4. **添加新元素:** 测试如何向 `Document` 对象中添加新的键值对，包括标量值和新的表格。
5. **删除元素:** 测试如何从 `Document` 对象中删除键值对。
6. **更新文档内容:** 测试如何使用 `update()` 方法合并或更新 `Document` 对象的内容。
7. **设置默认值:** 测试 `setdefault()` 方法的功能。
8. **处理带点号的键 (Dotted Keys):** 测试 `tomlkit` 如何处理和表示带有 `.` 的键，这些键用于表示嵌套的表格结构。
9. **处理超级表格 (Super Tables) 和子表格 (Sub-tables):** 测试 `tomlkit` 如何处理和表示嵌套的表格结构，以及如何访问和操作这些表格。
10. **处理数组表格 (Array of Tables, AOT):** 测试 `tomlkit` 如何处理和表示数组类型的表格。
11. **保持 TOML 格式:** 测试在修改 `Document` 对象后，`as_string()` 方法能否正确地将修改后的内容格式化为 TOML 字符串，并保持原有的格式和注释。
12. **复制文档:** 测试 `copy.copy()` 和 `copy.deepcopy()` 方法能否正确地复制 `Document` 对象。
13. **序列化和反序列化:** 测试 `pickle` 模块能否正确地序列化和反序列化 `Document` 对象。
14. **处理内联表格:** 测试如何创建和操作内联表格。
15. **处理无序表格 (Out-of-order Tables):** 测试 `tomlkit` 如何处理在 TOML 文件中定义顺序不符合规范的表格。
16. **保留输出顺序:** 测试在修改文档后，输出的 TOML 字符串是否能尽可能地保留原始的元素顺序。
17. **处理注释:** 虽然这个文件没有直接测试注释，但 `tomlkit` 的目标是保留格式，所以间接会涉及到注释的处理。
18. **测试异常情况:** 测试在访问不存在的键时是否会抛出预期的异常 (`NonExistentKey`)。

**与逆向的方法的关系:**

* **配置文件解析:** 逆向工程中，分析目标软件的配置文件是常见的任务。许多程序使用 TOML 作为配置文件格式。这个测试文件验证了 `tomlkit` 解析 TOML 配置文件的能力，这对于编写自动化逆向分析工具（例如基于 Frida 的脚本）来读取和理解目标程序的配置至关重要。

   **举例说明:** 假设你要逆向一个使用 TOML 配置文件存储 API 密钥和服务器地址的应用程序。你可以使用 Frida 脚本加载这个配置文件，解析它，并提取出密钥和地址，以便进一步分析网络通信。`tomlkit` 的正确性直接影响到你从配置文件中获取信息的准确性。

**涉及二进制底层、Linux, Android内核及框架的知识:**

* **配置文件位置:**  虽然 `tomlkit` 本身不直接涉及二进制底层或内核，但在逆向分析中，配置文件的位置可能与这些概念相关。例如，在 Linux 或 Android 系统中，应用程序的配置文件可能位于特定的目录，需要了解文件系统路径和权限。
* **Frida 的集成:** `tomlkit` 作为 `frida-python` 的一部分，其目的是辅助 Frida 进行动态 instrumentation。在 Frida 的上下文中，理解目标进程的内存布局、如何注入代码、以及如何与目标进程进行通信是关键。`tomlkit` 帮助处理目标进程的配置信息，但其本身并不直接操作内存或内核。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
  ```toml
  [owner]
  name = "Alice"
  age = 30
  ```
* **测试代码:**
  ```python
  content = """
  [owner]
  name = "Alice"
  age = 30
  """
  doc = parse(content)
  assert doc["owner"]["name"] == "Alice"
  assert doc["owner"]["age"] == 30
  ```
* **预期输出:** 测试通过，因为 `tomlkit` 能正确解析 TOML 并通过字典访问到对应的值。

* **假设输入:**
  ```toml
  [database]
  enabled = true
  ports = [8000, 8080]
  ```
* **测试代码:**
  ```python
  content = """
  [database]
  enabled = true
  ports = [8000, 8080]
  """
  doc = parse(content)
  assert doc["database"]["enabled"] is True
  assert doc["database"]["ports"] == [8000, 8080]
  ```
* **预期输出:** 测试通过，验证了布尔值和数组的解析。

**涉及用户或者编程常见的使用错误:**

* **访问不存在的键:** 用户可能会尝试访问 TOML 文档中不存在的键，导致错误。测试用例 `test_out_of_order_tables_are_still_dicts` 中就测试了访问不存在的键时抛出 `KeyError` 的情况，这模拟了用户常犯的错误。
   ```python
   with pytest.raises(KeyError):
       table.pop("missing")
   ```
* **假设输入错误的 TOML 格式:** 虽然这个测试文件没有明确测试格式错误，但 `tomlkit` 的其他部分肯定会处理这种情况。用户可能会输入不符合 TOML 规范的字符串，导致解析失败。
* **类型假设错误:** 用户可能假设从 TOML 中读取的值是特定的类型，但实际类型不符。例如，期望一个字符串是整数。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发或维护 Frida Python 绑定 (`frida-python`):** 一个开发者可能正在开发或修复 `frida-python` 中与 TOML 文件处理相关的部分。
2. **修改或添加 `tomlkit` 功能:**  如果涉及 `tomlkit` 库本身的修改，开发者会编写或修改测试用例来验证新功能或修复的正确性。
3. **运行单元测试:**  在开发过程中，开发者会运行 `pytest` 命令来执行所有的单元测试，或者指定执行 `test_toml_document.py` 文件中的测试。
   ```bash
   pytest frida/subprojects/frida-python/releng/tomlkit/tests/test_toml_document.py
   ```
4. **测试失败或需要调试:** 如果某个测试用例失败，开发者会查看失败的测试用例代码，分析断言失败的原因。这会引导他们阅读 `test_toml_document.py` 中的具体测试逻辑。
5. **检查 TOML 解析和操作逻辑:** 开发者会仔细检查测试用例中使用的 TOML 字符串，以及对 `Document` 对象执行的操作，例如添加、删除、修改元素，来定位问题所在。
6. **使用断点或日志:** 为了更深入地了解执行过程，开发者可能会在测试代码中设置断点或添加日志语句，以便在运行时查看 `Document` 对象的状态和变量的值。

总而言之，`test_toml_document.py` 是确保 `tomlkit` 库中 TOML 文档对象功能正确性的关键组成部分，对于任何使用 `tomlkit` 的项目（包括 `frida-python`）来说，保证其可靠性至关重要。在逆向工程的上下文中，它确保了我们能够准确地解析目标应用程序的 TOML 配置文件，为进一步的分析工作奠定基础。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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