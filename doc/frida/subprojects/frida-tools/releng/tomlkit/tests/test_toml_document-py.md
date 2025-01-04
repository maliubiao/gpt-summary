Response:
Let's break down the thought process for analyzing the Python code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to analyze the given Python code (`test_toml_document.py`) and explain its functionalities, relate them to reverse engineering, discuss low-level aspects, identify logical reasoning, point out user errors, and trace the user's path to this code.

**2. Initial Code Scan and Identification of Key Areas:**

A quick scan reveals several key elements:

* **Imports:** Libraries like `copy`, `json`, `pickle`, `datetime`, `textwrap`, `pytest`, and `tomlkit`. This immediately tells me the code is about testing TOML (Tom's Obvious, Minimal Language) parsing and manipulation.
* **`test_` prefixed functions:** These are clearly unit tests, likely using the `pytest` framework.
* **String literals:**  Lots of multi-line strings representing TOML content.
* **`parse()` function:**  This strongly suggests the core functionality is parsing TOML data.
* **Assertions (`assert`):**  Used extensively to verify expected behavior.
* **Manipulation of dictionaries:** The code creates, updates, deletes, and accesses elements within dictionaries that represent TOML structures.
* **`as_string()` method:** Likely used to serialize the internal TOML representation back into a string.
* **Focus on document structure:**  The tests deal with tables, subtables, arrays of tables, inline tables, and dotted keys, all characteristic of TOML.

**3. Deeper Dive into Functionalities (and relating to the request):**

Now, I go through each test function and try to understand what it's testing. For each test, I consider the points from the request:

* **Core Functionality:** What is this test verifying? (e.g., "parsing a basic TOML document," "updating a value in a table," "deleting a table").
* **Reverse Engineering Relevance:**  Does this relate to how one might analyze a configuration file or data format in reverse engineering?  (Yes, TOML is a config format).
* **Low-Level/Kernel/Framework:**  Is there anything directly related to binary, Linux, Android, etc.? (In this specific file, mostly no. The focus is on the *logic* of TOML manipulation, not low-level system interaction).
* **Logical Reasoning:** Are there input examples and expected outputs?  (Yes, the TOML strings are inputs, and the assertions define the expected outputs).
* **User Errors:** Could a user make a mistake related to this functionality? (e.g., typos in keys, incorrect data types).
* **User Path:** How would a user end up testing this specific functionality? (They would be working with TOML files and potentially using the `tomlkit` library to process them).

**Example of Detailed Analysis for `test_document_is_a_dict(example)`:**

* **Core Functionality:**  Tests that parsing a TOML document results in a Python dictionary where keys correspond to TOML keys and values correspond to TOML values. It verifies accessing and retrieving values.
* **Reverse Engineering:**  A common task in reverse engineering is parsing configuration files. TOML is a popular format. Understanding how a TOML parser works is relevant. This test shows how TOML structures map to Python dictionaries, a key step in programmatically analyzing them.
* **Low-Level:**  Not directly low-level. It's about the higher-level abstraction of a TOML document.
* **Logical Reasoning:**  Input: The TOML string in `example("example")`. Output: The assertions verifying the structure and values of the resulting dictionary.
* **User Errors:**  If a user expects the TOML to be parsed into something other than a dictionary, or if they misspell keys when accessing the dictionary, they would encounter errors.
* **User Path:** A user would likely be writing code that uses `tomlkit` to read and process TOML configuration files. If they encounter issues with accessing or understanding the data, they might look at or even modify tests like this to understand how the parser works.

**4. Synthesizing the Information:**

After analyzing individual tests, I group the functionalities and look for overarching themes. I then structure the answer according to the prompt's requirements.

* **的功能:**  Summarize the major capabilities demonstrated by the tests (parsing, accessing, modifying, serializing, handling different TOML structures).
* **与逆向的关系:** Explain *why* these functionalities are relevant to reverse engineering (configuration file analysis). Give concrete examples.
* **二进制底层等知识:** Discuss if and how the code relates to lower-level concepts. In this case, it's mostly about the *logic* of TOML, but I could mention that underlying TOML parsing might involve byte-level processing of the file, even if this test file doesn't directly show it.
* **逻辑推理:** Provide examples of input TOML and the resulting Python dictionary structure (like the `example("example")` breakdown).
* **用户或编程常见错误:** Illustrate common mistakes users might make (key errors, type mismatches, assuming a specific structure).
* **用户操作是如何一步步的到达这里:**  Describe the typical development/debugging workflow that would lead someone to examine this test file.

**5. Iteration and Refinement:**

Review the generated answer for clarity, accuracy, and completeness. Ensure that the examples are clear and the explanations are easy to understand. For instance, initially, I might not have explicitly connected "dotted keys" to configuration file namespaces, but during review, I'd realize that's a good point to highlight.

**Self-Correction Example during the Process:**

Initially, I might have focused too much on the specific details of each test. However, during the synthesis phase, I would realize that the prompt asks for broader functionalities and connections. So, I would then adjust my approach to group similar tests and explain the overall capabilities of the `tomlkit` library as demonstrated by these tests. I might also initially overlook the "user path" aspect and add that in during the refinement stage.
这个Python源代码文件 `test_toml_document.py` 是 `frida-tools` 项目中 `tomlkit` 子项目的一部分，专门用于测试 `tomlkit` 库中关于 TOML 文档对象 (`tomlkit.api.document`) 的功能。`tomlkit` 是一个用于处理 TOML 格式文件的 Python 库。

**以下是该文件列举的功能：**

1. **TOML 文档的解析和基本访问:**
   - 测试将 TOML 格式的字符串解析为 `tomlkit` 的文档对象。
   - 验证可以通过字典的语法 (`doc["key"]`) 和 `get()` 方法来访问文档中的键值对。
   - 测试访问不同类型的 TOML 数据，如字符串、整数、布尔值、数组、日期时间以及嵌套的表 (table)。

2. **TOML 文档的修改:**
   - 测试修改文档中已存在的值。
   - 测试使用 `update()` 方法批量更新文档中的键值对。
   - 测试使用 `setdefault()` 方法设置默认值，仅当键不存在时才添加。

3. **处理带有点号的键 (Dotted Keys):**
   - 测试解析和访问带有层级结构的键，例如 `a.b.c`。
   - 验证这种键会被正确地解析为嵌套的字典结构。

4. **处理超级表 (Super Tables) 和子表 (Sub-tables):**
   - 测试解析和访问 TOML 中的表和子表结构，例如 `[tool.poetry]`。
   - 验证可以正确地访问深层嵌套的子表。

5. **处理数组类型的表 (Array of Tables - AOT):**
   - 测试解析和访问数组类型的表，即 `[[products]]` 这种结构。
   - 验证可以访问 AOT 中的元素，并修改其值。

6. **维护 TOML 格式的完整性:**
   - 测试在添加或修改元素后，`as_string()` 方法能够正确地将文档序列化回 TOML 格式的字符串。
   - 验证插入新元素时，会添加必要的换行符以保持格式规范。
   - 测试删除元素后，输出的 TOML 字符串是正确的。

7. **对象操作:**
   - 测试文档对象的复制 (`copy.copy()` 和 `doc.copy()`) 和深拷贝 (`copy.deepcopy()`)。
   - 测试文档对象可以被序列化和反序列化 (使用 `pickle`)。
   - 测试文档对象可以转换为 JSON 格式 (`json.dumps()`)。

8. **处理内联表 (Inline Tables):**
   - 测试获取到的内联表仍然是内联表对象，可以继续操作。

9. **处理乱序的表 (Out-of-Order Tables):**
   - 测试 TOML 中表的定义顺序不影响解析和访问。
   - 验证在乱序的表中添加、修改和删除元素的功能。
   - 确保乱序表的字符串输出仍然保持原始顺序。

10. **删除操作:**
    - 测试使用 `del` 关键字删除文档中的键值对或表。

11. **处理注释:**
    - 虽然这个文件主要关注文档结构，但也有测试用注释替换值的情况，这涉及到 `tomlkit.item()` 的使用。

**与逆向的方法的关系及举例说明:**

TOML 格式常用于应用程序的配置文件。在逆向工程中，理解和修改程序的配置文件是常见的任务。

* **读取和分析配置文件:** 逆向工程师可能需要读取目标程序的 TOML 配置文件，以了解程序的配置参数、服务器地址、API 密钥等信息。 `tomlkit` 提供的解析功能，就像这个测试文件所展示的，可以帮助逆向工程师将 TOML 文件加载到 Python 中进行分析。
   ```python
   # 假设从文件中读取了 TOML 内容
   toml_content = """
   [server]
   address = "192.168.1.100"
   port = 8080

   [api]
   key = "secret_api_key"
   """
   import tomlkit
   doc = tomlkit.parse(toml_content)
   server_address = doc["server"]["address"] # "192.168.1.100"
   api_key = doc["api"]["key"]             # "secret_api_key"
   print(f"Server Address: {server_address}, API Key: {api_key}")
   ```
* **修改配置文件进行调试或绕过:** 逆向工程师可能需要修改程序的配置文件以改变其行为，例如禁用某些功能、修改服务器地址以重定向流量、或者绕过某些验证。`tomlkit` 提供的修改功能，如更新、添加、删除键值对，可以用于自动化地修改 TOML 配置文件。
   ```python
   # 继续上面的例子
   doc["server"]["port"] = 9000  # 修改端口
   doc["api"]["enabled"] = False # 禁用 API 功能

   modified_toml = tomlkit.dumps(doc) # 将修改后的文档转换为 TOML 字符串
   print(modified_toml)
   # 然后将 modified_toml 写回配置文件
   ```

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个 `test_toml_document.py` 文件本身并没有直接涉及二进制底层、Linux/Android 内核或框架的知识。它主要关注的是 `tomlkit` 库对 TOML 格式的逻辑处理。

然而，在 `frida` 这个动态 instrumentation 工具的上下文中，`tomlkit` 的使用可能与这些底层知识间接相关：

* **Frida 的配置:** `frida` 本身或其相关工具可能使用 TOML 文件作为配置文件。这些配置文件可能涉及到 Frida Agent 的加载路径、脚本配置、目标进程的过滤规则等。这些规则可能涉及到进程 ID、进程名、甚至是更底层的内核对象信息。虽然 `test_toml_document.py` 不直接处理这些，但它确保了 `frida` 可以可靠地解析和操作这些配置文件。
* **Android 框架的配置:** 在 Android 逆向中，可能会遇到使用 TOML 格式的配置文件来管理应用的行为或框架的配置。例如，某些定制 ROM 或安全工具可能会使用 TOML 来定义拦截规则或权限配置。

**逻辑推理及假设输入与输出:**

许多测试用例都包含了逻辑推理，即给定一个 TOML 输入，验证解析后的文档对象的结构和值是否符合预期。

**假设输入:**

```toml
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
requests = "2.25.1"
```

**预期输出 (通过测试断言验证):**

```python
import tomlkit
content = """
[package]
name = "my-app"
version = "1.0.0"

[dependencies]
requests = "2.25.1"
"""
doc = tomlkit.parse(content)
assert doc["package"]["name"] == "my-app"
assert doc["package"]["version"] == "1.0.0"
assert doc["dependencies"]["requests"] == "2.25.1"
```

**涉及用户或者编程常见的使用错误及举例说明:**

* **键名拼写错误:** 用户在访问 TOML 文档时，如果键名拼写错误，会导致 `KeyError`。
   ```python
   doc = tomlkit.parse("""name = "test" """)
   # 错误示例
   try:
       print(doc["naem"])
   except KeyError as e:
       print(f"Error: {e}") # 输出: Error: 'naem'
   ```
* **假设了不存在的层级结构:**  如果用户尝试访问不存在的嵌套键，也会导致 `KeyError`。
   ```python
   doc = tomlkit.parse("""[server]""")
   # 错误示例
   try:
       print(doc["server"]["address"])
   except KeyError as e:
       print(f"Error: {e}") # 输出: Error: 'address'
   ```
* **类型假设错误:** 用户可能假设某个键的值是特定的类型，但实际上是另一种类型。
   ```python
   doc = tomlkit.parse("""port = "8080" """) # 注意 port 是字符串
   # 错误示例 (假设 port 是整数)
   # result = doc["port"] + 1 # TypeError: can only concatenate str (not "int") to str
   ```
* **修改 TOML 结构时的不一致性:**  用户在手动构建或修改 TOML 数据时，可能会引入格式错误，导致解析失败。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

一个开发人员或测试人员可能出于以下原因查看或运行这个测试文件：

1. **开发 `tomlkit` 库:** 如果开发者正在开发或维护 `tomlkit` 库，他们会编写和运行这些测试用例来确保代码的功能正确性，覆盖各种 TOML 语法和操作场景。
2. **调试 `tomlkit` 库中的 Bug:** 当 `tomlkit` 库出现 Bug，例如解析错误或修改行为异常时，开发者会检查相关的测试用例，或者编写新的测试用例来复现和定位问题。`test_toml_document.py` 中关于文档对象操作的测试是排查这类问题的关键。
3. **使用 `frida-tools` 遇到与 TOML 配置相关的问题:**  如果 `frida-tools` 的某个功能依赖于 TOML 配置文件，并且出现了与配置加载或解析相关的问题，开发人员可能会追溯到 `tomlkit` 库，并查看其测试用例以了解 `tomlkit` 的行为是否符合预期。
4. **学习 `tomlkit` 库的使用方法:**  新的 `tomlkit` 用户可能会阅读这些测试用例，以了解如何使用 `tomlkit` 提供的 API 来解析、访问和修改 TOML 文档。测试用例通常包含了清晰的使用示例。
5. **贡献代码到 `frida-tools` 或 `tomlkit`:**  如果有人想为这两个项目贡献代码，他们需要理解现有的测试用例，并编写新的测试用例来验证他们添加或修改的功能。

总而言之，`test_toml_document.py` 是 `tomlkit` 库的核心测试文件，它详细地验证了 TOML 文档对象的各种功能，对于确保库的正确性和稳定性至关重要，并且在开发、调试和学习 `tomlkit` 以及依赖于 `tomlkit` 的项目（如 `frida-tools`）时扮演着重要的角色。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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