Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its function and relate it to reverse engineering concepts.

**1. Initial Skim and Keyword Spotting:**

The first step is a quick scan of the code, looking for recognizable keywords and patterns. I see:

* `import tomlkit`:  This immediately tells me the code is about parsing or manipulating TOML files.
* `tests`:  The file is in a `tests` directory, so it's clearly testing functionality.
* `assert`: This is a common keyword in testing, used to verify expected outcomes.
* `parse`, `document`, `as_string`: These are likely functions or methods within the `tomlkit` library for reading, representing, and writing TOML data.
* `dict`, `list`, `datetime`, `pickle`, `json`, `copy`: These are standard Python data types and libraries used for data manipulation and serialization.
* Various examples with `[section]`, `key = value`, `[[array of tables]]`: These strongly suggest the code is working with the structure of TOML.

**2. Understanding the Core Functionality:**

The file name `test_toml_document.py` strongly suggests that the central object being tested is a "TOML document."  The `parse()` function is clearly used to create these document objects from string content. The `as_string()` method is used to get the string representation back. This implies the `tomlkit` library provides a way to represent and modify TOML data in memory.

**3. Analyzing the Test Cases:**

The various `test_...` functions provide specific examples of how the `tomlkit` library (and its `Document` object) works. I'd go through a few representative ones:

* **`test_document_is_a_dict(example)`:** This shows basic access to TOML data using dictionary-like syntax (`doc["owner"]`). It also demonstrates accessing nested values and different TOML data types (strings, integers, booleans, dates, arrays). The use of `doc.get()` shows another way to access values.

* **`test_toml_document_without_super_tables()`:**  This introduces the concept of "super tables" (dotted keys like `tool.poetry`). It checks if the library correctly handles these structures.

* **`test_adding_an_element_to_existing_table_with_ws_remove_ws()`:**  This highlights how the library manages whitespace when modifying TOML.

* **`test_document_with_new_sub_table_after_other_table_delete()`:** This shows how to delete sections within the TOML document.

* **`test_toml_document_is_pickable(example)`:** This indicates that the `Document` object can be serialized using `pickle`, which is important for saving and restoring state.

**4. Relating to Reverse Engineering:**

Now, the crucial step is connecting this to reverse engineering. I'd consider:

* **Configuration Files:** TOML is often used for configuration. Reverse engineers frequently encounter configuration files (e.g., `.ini`, `.conf`, custom formats). Understanding how a tool like `tomlkit` parses and manipulates these could be useful for:
    * **Analyzing application behavior:** Configuration dictates how an application runs.
    * **Modifying application behavior:**  Patching or altering configurations can change functionality (e.g., disabling features, changing server addresses).
    * **Extracting information:** Configuration files can contain secrets, API keys, or other valuable data.

* **Dynamic Instrumentation (Frida Context):** The fact that this code is part of Frida is a major clue. Frida is about *dynamically* analyzing and modifying running processes. How does TOML fit in?
    * **Frida Scripts as Configuration:**  Frida scripts themselves might use TOML for configuration.
    * **Target Application Configuration:** The *target* application being instrumented by Frida might use TOML for its configuration. Frida could use `tomlkit` to read or even modify the target application's configuration in memory.

**5. Connecting to Lower-Level Concepts:**

This requires thinking about how TOML relates to the underlying system:

* **Binary Representation (Indirect):** While TOML is text-based, the *application* using it will likely process it into in-memory data structures. Reverse engineers often need to understand how these text-based formats are translated into binary data. `tomlkit` helps bridge that gap by providing a structured in-memory representation.
* **Linux/Android (Potentially):** Configuration files are prevalent in Linux and Android systems. Applications running on these platforms frequently use configuration. Frida also heavily supports these platforms, strengthening the connection.
* **Kernel/Framework (Less Direct):**  While TOML isn't directly a kernel or framework concept, applications running *on top* of these layers use configuration. Frida might interact with these applications at a level where understanding their configuration is valuable.

**6. Logic, Assumptions, and Errors:**

* **Logic:**  The tests themselves are logical deductions about how the `tomlkit` library should behave. "If I parse this TOML, and then access this key, I should get this value."
* **Assumptions:** The tests assume valid TOML input. They don't extensively test error handling for malformed TOML (though some implicit error handling might be present in the `parse()` function).
* **User Errors:**  The tests implicitly demonstrate common usage patterns. Incorrect key access (`doc["nonexistent_key"]`) would lead to errors. Trying to set values with incorrect types might also cause issues (though this isn't explicitly tested here).

**7. Debugging and User Journey:**

The file is a test suite. A developer working on `tomlkit` would run these tests to ensure their code is working correctly. If a bug is found, they might add new test cases to reproduce the issue. A user of `tomlkit` wouldn't directly interact with this test file, but understanding these tests can help them understand how to use the library correctly.

**Self-Correction/Refinement During the Process:**

Initially, I might focus too much on the specific details of each test case. The key is to step back and identify the *broader purpose* and the core concepts being demonstrated. Also, the connection to Frida is crucial – recognizing that this isn't just a general TOML library but a component within a dynamic instrumentation tool significantly shapes the interpretation of its relevance to reverse engineering.
这个文件 `test_toml_document.py` 是 `frida-core` 项目中 `tomlkit` 子项目的测试文件，专门用于测试 `tomlkit` 库中处理 TOML 文档 (`Document` 对象) 的各种功能。`tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 格式配置文件的 Python 库。

以下是该文件列举的功能，以及与逆向、底层知识、逻辑推理、用户错误和调试线索的关联说明：

**功能列举：**

1. **解析 TOML 内容并创建文档对象:**
   - 测试使用 `tomlkit.parse()` 函数将 TOML 格式的字符串解析成 `Document` 对象。
   - 验证解析后的文档对象是否为 Python 的 `dict` 子类，并能像字典一样访问其中的键值对。
   - 测试解析各种 TOML 数据类型，如字符串、整数、浮点数、布尔值、日期时间、数组、内联表等。
   - 测试解析带有嵌套表（sub-table）和数组表 (array of tables) 的 TOML 结构。
   - 测试解析带有带点键 (dotted keys) 的 TOML 结构，例如 `a.b.c = 1`。

2. **访问和修改文档对象中的数据:**
   - 测试使用字典的访问方式 (`doc["key"]`) 和 `get()` 方法来获取文档中的值。
   - 测试修改文档中已存在的值。
   - 测试使用 `update()` 方法合并或更新文档内容。
   - 测试 `setdefault()` 方法，在键不存在时设置默认值。

3. **处理带有超级表 (Super Tables) 的 TOML:**
   - 测试解析和操作带有带点键的表，例如 `[tool.poetry]`。

4. **解包文档对象:**
   - 测试 `unwrap()` 方法，将 `Document` 对象转换为普通的 Python `dict` 对象。

5. **处理空白符 (Whitespace):**
   - 测试在添加元素时如何处理空白符，例如移除多余的空白行。

6. **处理数组表 (Array of Tables):**
   - 测试在子表之后添加数组表的情况。

7. **插入和删除元素:**
   - 测试在现有表中添加新的键值对。
   - 测试在删除元素后插入新元素的情况。
   - 测试删除整个表或超级表。

8. **复制和深拷贝文档对象:**
   - 测试使用 `copy.copy()` 和 `copy.deepcopy()` 创建文档对象的副本。

9. **序列化和反序列化:**
   - 测试使用 `pickle` 模块序列化和反序列化文档对象。
   - 测试使用 `json` 模块将文档对象转换为 JSON 字符串。

10. **处理内联表 (Inline Tables):**
    - 测试获取到的内联表对象是否仍然是内联表类型。

11. **处理无序表 (Out-of-Order Tables):**
    - 测试即使 TOML 文件中的表定义顺序不符合严格的层级关系，`tomlkit` 也能正确解析和操作。
    - 测试在无序表中添加、修改和删除键值对。
    - 测试无序表仍然表现得像 Python 字典。
    - 测试无序表在字符串输出时保持原始顺序。

12. **更新嵌套值并保持缩进:**
    - 测试更新深层嵌套的值时，输出的 TOML 字符串是否保持正确的缩进。

13. **`__repr__` 方法:**
    - 测试文档对象的字符串表示形式。

14. **移动表:**
    - 测试将一个表从一个键移动到另一个键。

15. **替换值和表:**
    - 测试将一个值替换为一个表，或者将一个表替换为一个值。
    - 测试替换操作是否保留了原有的空白符。

16. **替换为带有注释的项:**
    - 测试将一个值替换为带有注释的 `Item` 对象。

17. **避免多余的空格:**
    - 测试在修改文档后，输出的 TOML 字符串不会有多余的空格。

18. **组合操作:**
    - 测试 `pop`、添加空白符和插入表等操作的组合使用。

19. **在超级表前添加换行符:**
    - 测试在创建包含超级表的文档时，是否正确添加换行符。

20. **从超级表中移除项:**
    - 测试删除超级表中的子表。

21. **嵌套表更新显示名称:**
    - 测试更新嵌套表时，是否正确显示名称。

22. **使用带点键构建表:**
    - 测试使用带点键的方式构建 TOML 表。

23. **解析子表时不添加额外的缩进:**
    - 验证解析嵌套的子表时，不会添加不必要的额外缩进。

24. **项保留顺序:**
    - 测试内联表中的项是否保留了添加时的顺序。

**与逆向的方法的关系：**

* **分析配置文件:** 逆向工程师经常需要分析应用程序的配置文件，以了解其行为、配置选项和内部参数。如果目标应用程序使用 TOML 格式的配置文件，`tomlkit` 这样的库可以帮助逆向工程师以编程方式解析和操作这些配置文件，提取关键信息或修改配置来观察程序行为。
    * **举例:** 假设一个被逆向的程序使用 TOML 文件来存储服务器地址、端口号和 API 密钥。使用 `tomlkit`，可以编写 Frida 脚本来读取这些配置，甚至在运行时修改服务器地址以重定向程序流量到自己的服务器。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

虽然 `tomlkit` 本身是一个纯 Python 库，不直接涉及二进制底层或操作系统内核，但它处理的数据（配置文件）经常与这些底层概念相关：

* **Linux/Android 配置文件:** Linux 和 Android 系统中很多应用程序和服务使用配置文件进行管理。`tomlkit` 可以用于解析这些系统级别的配置文件，例如服务单元的配置文件、网络配置等。
* **框架配置:** 一些应用程序框架（例如某些 Python Web 框架）可能使用 TOML 作为配置文件格式。逆向工程师可能需要分析这些配置来理解应用程序的架构和组件。
* **Frida 的应用场景:** 在 Frida 的上下文中，`tomlkit` 可能被用于：
    * **Frida 脚本的配置:**  Frida 脚本本身可能使用 TOML 文件来配置其行为，例如指定要 hook 的函数、要修改的内存地址等。
    * **目标进程的配置:**  Frida 脚本可以读取目标进程加载的 TOML 配置文件，根据配置信息动态调整 hook 策略。
    * **Android 框架的某些配置:** 虽然 Android 主要使用 XML 和 प्रॉपर्टी 文件，但一些应用或组件可能会使用 TOML，Frida 可以利用 `tomlkit` 进行解析。

**逻辑推理的例子：**

* **假设输入:**
  ```toml
  [database]
  server = "192.168.1.1"
  ports = [8000, 8001]
  enabled = true
  ```
* **操作:** 使用 `doc = parse(input_string)` 解析，然后访问 `doc["database"]["ports"]`。
* **输出:** `[8000, 8001]` (Python 列表)

* **假设输入:**
  ```toml
  [owner]
  name = "John Doe"
  age = 30
  ```
* **操作:** 使用 `doc = parse(input_string)` 解析，然后执行 `doc["owner"].get("city", "Unknown")`。
* **输出:** `"Unknown"` (因为 "city" 键不存在，返回默认值)

**涉及用户或编程常见的使用错误：**

* **尝试访问不存在的键:**
  ```python
  doc = parse("[settings]\nvalue = 10")
  print(doc["option"])  # KeyError: 'option'
  ```
* **类型不匹配:** 虽然 TOMLKit 会尽力保持类型，但如果用户期望的类型与 TOML 中的类型不符，可能会导致错误。
* **TOML 格式错误:** 如果用户尝试解析不符合 TOML 语法的字符串，`tomlkit.parse()` 会抛出异常。
  ```python
  try:
      doc = parse("invalid toml")
  except tomlkit.exceptions.ParseError as e:
      print(f"解析错误: {e}")
  ```
* **修改后未正确写回文件:** 用户修改了 `Document` 对象，但忘记使用 `tomlkit.dumps(doc)` 将其转换回字符串并写回文件。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发 `tomlkit` 库:**  `tomlkit` 的开发者编写了这个测试文件，以确保库的各个功能按预期工作。他们会编写各种测试用例，覆盖不同的 TOML 结构、数据类型和操作方式。
2. **`frida-core` 项目使用 `tomlkit`:**  `frida-core` 依赖于 `tomlkit` 来处理 TOML 配置文件。在 `frida-core` 的开发过程中，如果涉及到读取或生成 TOML 配置，开发者可能会修改或添加 `tomlkit` 的功能。
3. **运行测试:**  在开发过程中，开发者会定期运行这些测试用例，以验证代码的正确性。如果某个功能出现 bug，相关的测试用例可能会失败，指示开发者需要修复代码。
4. **调试 `tomlkit` 或使用它的代码:** 如果在使用 `tomlkit` 的过程中遇到问题（例如解析错误、数据访问错误），开发者可能会查看这些测试用例，了解 `tomlkit` 的预期行为，并找到调试的线索。例如，如果他们不确定如何处理带点键的表，可以参考 `test_toml_document_with_dotted_keys` 这个测试用例。
5. **贡献代码:** 其他开发者向 `tomlkit` 项目贡献代码时，也需要编写或修改测试用例，确保新代码的正确性，并避免破坏现有功能。

总而言之，`test_toml_document.py` 是 `tomlkit` 库的核心测试文件，它详细地测试了库处理 TOML 文档的各种能力。理解这个文件的内容，可以帮助我们了解 `tomlkit` 的功能特性，以及在逆向工程和动态 instrumentation 的场景下如何利用它来处理 TOML 格式的配置文件。对于调试使用 `tomlkit` 的代码，或者理解 `frida-core` 中如何使用 `tomlkit`，这个文件都是一个重要的参考。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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