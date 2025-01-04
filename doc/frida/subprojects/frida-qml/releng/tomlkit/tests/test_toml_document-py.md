Response:
Let's break down the thought process to analyze the provided Python code for the `test_toml_document.py` file.

**1. Initial Understanding of the Context:**

The first step is to recognize the file path: `frida/subprojects/frida-qml/releng/tomlkit/tests/test_toml_document.py`. This immediately tells us several things:

* **Frida:** It's part of the Frida dynamic instrumentation toolkit. This suggests a connection to reverse engineering, security analysis, and potentially interacting with running processes.
* **frida-qml:**  This indicates a specific component of Frida dealing with QML (Qt Meta Language), often used for user interfaces.
* **releng:** This likely stands for "release engineering" or "reliability engineering," suggesting tools and processes related to building, testing, and ensuring the quality of the software.
* **tomlkit:** This is the core of the file's purpose. It's a library for working with TOML (Tom's Obvious, Minimal Language) files.
* **tests:**  This explicitly labels the file as containing tests for the `tomlkit` library, specifically for handling TOML documents.
* **test_toml_document.py:** This strongly implies the file contains tests for the `TomlDocument` class or the functionalities related to representing and manipulating TOML documents in `tomlkit`.

**2. High-Level Code Analysis (Skimming):**

Next, a quick skim of the code reveals the following key elements:

* **Imports:**  Libraries like `copy`, `json`, `pickle`, `datetime`, `textwrap`, and `pytest` are used. `tomlkit` itself and specific parts of it (`parse`, `ws`, `document`, `NonExistentKey`) are imported. This confirms the file's purpose is testing `tomlkit` functionality.
* **Test Functions:** The code consists of numerous functions starting with `test_`. This is the convention in `pytest`, indicating individual test cases.
* **Example Usage:**  Many test cases use example TOML strings (either directly embedded or loaded via `example("...")`).
* **Assertions:**  Each test function uses `assert` statements to verify expected behavior. These checks compare the parsed TOML data, the string representation of the TOML document, or check for expected exceptions.
* **Focus on Document Manipulation:**  The tests cover a wide range of operations on TOML documents, including:
    * Accessing values (using dictionary-like syntax)
    * Modifying values
    * Adding new keys and tables
    * Deleting keys and tables
    * Handling different TOML structures (tables, inline tables, arrays of tables)
    * Preserving whitespace and comments
    * Copying and pickling documents
    * Handling out-of-order tables

**3. Detailed Analysis - Connecting to the Prompt's Requirements:**

Now, let's address each point in the prompt systematically:

* **Functionality:**  The core function is testing the ability of the `tomlkit` library to parse, manipulate, and serialize TOML documents correctly. Specifically, it tests the `TomlDocument` object's behavior as a dictionary-like structure for representing TOML data.

* **Relationship to Reverse Engineering:**  This is where the Frida context becomes important. TOML is often used for configuration files. In reverse engineering:
    * **Example:**  A malware sample might have a TOML configuration file embedded or loaded. Frida could use `tomlkit` (or a similar library) to parse this configuration, understand the malware's settings, and potentially modify them to analyze its behavior.

* **Binary, Linux/Android Kernel/Framework:** While `tomlkit` itself is a higher-level library, the context of Frida implies potential interaction with lower levels.
    * **Example:** Frida might inject a QML-based interface into an Android application. The UI's configuration could be stored in a TOML file. Frida uses its core mechanisms (which involve interacting with the target process's memory and execution) to access and potentially modify this TOML data via `tomlkit`. The parsing and manipulation happen in the Frida agent's process, but the *source* of the data is within the target process.

* **Logical Reasoning (Input/Output):**  Many test cases demonstrate this directly.
    * **Example:**
        * **Input:** `content = """foo = "bar"\n"""`
        * **Operation:** `doc = parse(content); doc.update({"bar": "baz"})`
        * **Output:** `"""foo = "bar"\nbar = "baz"\n"""`

* **User/Programming Errors:** The tests implicitly show potential errors.
    * **Example:** The `test_toml_document_set_super_table_element` shows how assigning a non-table value to a super-table entry replaces the entire table. This could be an unintended consequence if the user expects to modify a nested element.
    * **Example:** The `test_values_can_still_be_set_for_out_of_order_tables` and related tests highlight the complexity of handling out-of-order tables, which might lead to unexpected behavior if not fully understood. Trying to access a non-existent key will raise a `NonExistentKey` exception.

* **User Operation and Debugging:**  To reach this test file, a developer would typically:
    1. **Install Frida:** This involves system-level installations.
    2. **Clone the Frida repository:** This brings the source code onto their machine.
    3. **Navigate to the specific directory:** `frida/subprojects/frida-qml/releng/tomlkit/tests/`.
    4. **Run the tests:**  Using a command like `pytest test_toml_document.py`.

    **Debugging:** If a test fails, the developer would examine:
    * The input TOML string.
    * The operations performed in the test.
    * The expected output vs. the actual output.
    * The `tomlkit` code itself if the bug seems to be in the library.

**4. Refinement and Structuring the Answer:**

Finally, the information gathered needs to be organized and presented clearly, mirroring the structure of the prompt. This involves summarizing the functionality, providing concrete examples for each point (reverse engineering, binary interaction, logical reasoning, errors), and outlining the typical user journey. Using terms like "dynamic instrumentation," "configuration files," and "memory injection" helps connect the code to its broader context within Frida.
这个Python源代码文件 `test_toml_document.py` 是 Frida 动态Instrumentation 工具中 `tomlkit` 子项目的一部分，专门用于测试 `tomlkit` 库中处理 TOML 文档的功能。 `tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。

以下是该文件的功能及其与您提出的几个方面的关系：

**功能概览:**

这个文件包含了大量的单元测试，用于验证 `tomlkit` 库中 `TomlDocument` 类的各种功能，包括：

* **解析 TOML 文档:** 测试 `tomlkit.parse()` 函数能否正确地将 TOML 格式的字符串解析成 `TomlDocument` 对象。
* **访问和修改文档内容:** 测试如何像操作 Python 字典一样访问和修改 `TomlDocument` 对象中的键值对，包括嵌套的表格和数组。
* **创建和更新文档:** 测试如何向已有的 `TomlDocument` 对象添加新的键值对、表格和数组。
* **删除文档内容:** 测试如何从 `TomlDocument` 对象中删除键值对和表格。
* **序列化回 TOML 字符串:** 测试 `TomlDocument.as_string()` 方法能否将修改后的文档正确地转换回 TOML 格式的字符串。
* **处理不同类型的 TOML 数据:** 测试对字符串、数字、布尔值、日期时间、数组、内联表格以及表格数组的处理。
* **处理带注释的 TOML 数据:**  测试是否能保留和正确处理 TOML 文件中的注释。
* **处理点号分隔的键:** 测试对使用点号分隔的键（如 `a.b.c`）的解析和操作。
* **处理表格数组 (Array of Tables):** 测试对 TOML 中表格数组的解析和操作。
* **处理行内表格 (Inline Table):** 测试对 TOML 中行内表格的解析和操作。
* **处理无序表格 (Out-of-order Tables):** 测试 `tomlkit` 对 TOML 规范中允许的无序表格的处理能力。
* **复制和序列化文档:** 测试 `copy.copy()`, `copy.deepcopy()`, `pickle.dumps()`, `json.dumps()` 等方法对 `TomlDocument` 对象的支持。
* **处理空白符:** 测试在解析和生成 TOML 字符串时对空白符的处理。
* **错误处理:** 间接地通过不抛出异常来测试某些预期的行为。

**与逆向方法的关系 (举例说明):**

在逆向工程中，配置文件经常被用来存储程序的设置、参数或其他的元数据。TOML 是一种流行的配置文件格式，因为它易于阅读和编写。Frida 可以用来动态地检查和修改目标进程的内存，如果目标程序使用了 TOML 配置文件，`tomlkit` 这样的库就可以在 Frida 脚本中用来解析和操作这些配置。

**举例说明:**

假设一个 Android 应用的配置存储在 `config.toml` 文件中，内容如下：

```toml
[server]
ip = "127.0.0.1"
port = 8080

[security]
enabled = true
```

在 Frida 脚本中，你可以读取这个配置文件（可能需要从目标进程的内存中读取），然后使用 `tomlkit` 解析它：

```python
import frida
import tomlkit

# ... 连接到目标进程的代码 ...

# 假设 config_data 是从目标进程内存中读取的 config.toml 内容
config_data = """
[server]
ip = "127.0.0.1"
port = 8080

[security]
enabled = true
"""

doc = tomlkit.parse(config_data)

# 修改服务器端口
doc["server"]["port"] = 9000

# 禁用安全功能
doc["security"]["enabled"] = False

# 将修改后的配置转换回 TOML 字符串
modified_config = doc.as_string()

print(modified_config)
```

然后，你可以将 `modified_config` 写回目标进程的内存，从而动态地修改应用程序的行为。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

虽然 `tomlkit` 本身是一个纯 Python 库，不直接涉及二进制底层或内核知识，但在 Frida 的上下文中，它被用作与目标进程交互的工具。

**举例说明:**

1. **内存读取和写入 (底层/框架):**  Frida 的核心功能是能够读取和写入目标进程的内存。在上面的逆向例子中，读取 `config.toml` 的内容以及将修改后的配置写回内存，都涉及到对目标进程内存的底层操作，这依赖于操作系统提供的 API (例如 Linux 的 `ptrace` 或 Android 的 `/proc/<pid>/mem`) 和 Frida 封装的跨平台接口。
2. **进程间通信 (框架):** Frida 脚本运行在 Frida Server 进程中，需要通过进程间通信机制与目标进程进行交互。这涉及到操作系统提供的 IPC 机制。
3. **Android 框架:** 如果目标是 Android 应用，读取配置文件可能涉及到访问 Android 文件系统，这会涉及到 Android 框架提供的 API 和权限管理。

**逻辑推理 (假设输入与输出):**

很多测试用例都体现了逻辑推理，即基于输入的 TOML 数据和执行的操作，预测输出的 TOML 字符串或对象结构。

**举例说明:**

**假设输入:**

```toml
foo = 10
```

**操作:**

```python
doc = parse("foo = 10")
doc["bar"] = 11
```

**预期输出:**

```toml
foo = 10
bar = 11
```

另一个例子：

**假设输入:**

```toml
[a.a]
key = "value"

[a.b]

[a.a.c]
```

**操作:**

```python
doc = parse("""
[a.a]
key = "value"

[a.b]

[a.a.c]
""")
doc["a"]["a"]["key"] = "new_value"
```

**预期输出:**

```toml
[a.a]
key = "new_value"

[a.b]

[a.a.c]
```

**涉及用户或编程常见的使用错误 (举例说明):**

测试用例也间接地展示了一些用户可能犯的错误以及 `tomlkit` 如何处理这些情况。

**举例说明:**

1. **尝试访问不存在的键:** `test_values_can_still_be_set_for_out_of_order_tables` 测试用例中使用 `pytest.raises(NonExistentKey)` 来验证尝试访问不存在的键会抛出 `NonExistentKey` 异常。这是一个常见的编程错误。
2. **类型错误:** 虽然这个文件没有显式测试类型错误，但在实际使用中，用户可能会尝试将不兼容的数据类型赋给 TOML 的某个字段，`tomlkit` 在序列化时可能会抛出异常。
3. **TOML 格式错误:** 如果用户尝试解析格式错误的 TOML 字符串，`tomlkit.parse()` 会抛出相应的解析错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

一个开发人员或安全研究人员通常会按照以下步骤到达这个测试文件进行调试：

1. **遇到与 TOML 文件处理相关的问题:**  在 Frida 脚本开发或分析目标程序时，发现 `tomlkit` 在解析或生成 TOML 文件时出现了不期望的行为。
2. **定位到 `tomlkit` 子项目:** 由于问题与 TOML 处理相关，会查看 Frida 源码中与 TOML 相关的部分，找到 `frida/subprojects/frida-qml/releng/tomlkit` 目录。
3. **寻找测试文件:** 为了理解 `tomlkit` 的正确用法或验证 bug 是否存在，会查看 `tomlkit` 的测试目录 `tests`，并找到 `test_toml_document.py`，因为它看起来是测试 `TomlDocument` 核心功能的。
4. **阅读测试用例:** 仔细阅读测试用例，理解 `tomlkit` 的各种功能和预期行为。
5. **复现问题或编写新的测试用例:** 尝试复现之前遇到的问题，或者编写新的测试用例来验证特定的场景。
6. **运行测试:** 使用 `pytest` 命令运行 `test_toml_document.py` 文件，观察测试结果。
7. **调试代码:** 如果测试失败，可以使用调试器 (例如 `pdb` 或 IDE 的调试功能) 来逐步执行测试代码和 `tomlkit` 的相关代码，找出问题所在。
8. **修改代码并重新测试:** 修复 `tomlkit` 中的 bug 或调整 Frida 脚本，然后重新运行测试，直到所有测试都通过。

总之，`test_toml_document.py` 是 `tomlkit` 库的核心测试文件，它详细地测试了 `TomlDocument` 类的各种功能，这对于确保 `tomlkit` 在 Frida 这样的动态 Instrumentation 工具中正确可靠地处理 TOML 配置文件至关重要。理解这个文件的内容可以帮助开发者和安全研究人员更好地使用 `tomlkit`，并排查与 TOML 处理相关的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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