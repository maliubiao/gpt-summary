Response:
Let's break down the thought process to analyze the Python code and fulfill the user's request.

**1. Understanding the Core Task:**

The request asks for an analysis of a specific Python file (`test_toml_document.py`) from the Frida project. The key is to identify its *functionality* and relate it to several specific concepts: reverse engineering, low-level operations (kernel, etc.), logical reasoning, common user errors, and debugging context.

**2. Initial Scan and Purpose Identification:**

The first step is to quickly scan the code. The presence of `import pytest`, function definitions starting with `test_`, and assertions (`assert`) strongly indicate that this is a *test file*. The filename itself, `test_toml_document.py`, further suggests it's testing the functionality of a class or module related to "toml documents." The imports `tomlkit` and `from tomlkit import parse` confirm this.

**3. Deeper Dive into Functionality:**

Now, the goal is to understand *what* aspects of TOML documents are being tested. Reading the test function names and the assertions within them reveals the following:

* **Basic Parsing and Access:** `test_document_is_a_dict` checks if parsing a TOML string creates a dictionary-like object and if accessing elements by key works as expected.
* **Table Handling:** Several tests (e.g., `test_toml_document_without_super_tables`, `test_toml_document_with_dotted_keys`) focus on how different table structures (sub-tables, dotted keys) are parsed and accessed.
* **Modification:** Tests like `test_adding_an_element_to_existing_table_with_ws_remove_ws`,  `test_document_set_super_table_element`, and various `test_replace_*` functions demonstrate testing the ability to modify TOML documents (adding, deleting, updating elements).
* **Output and Serialization:**  `test_document_is_pickable`, `test_toml_document_can_be_copied`, and the various `.as_string()` calls show testing the ability to serialize the TOML document back into a string format. The copying tests also involve `json.dumps`, indicating testing compatibility with standard Python serialization.
* **Edge Cases and Specific Features:** Tests like those involving inline tables, arrays of tables, and preserving whitespace address more nuanced aspects of the TOML specification.

**4. Connecting to the Specified Concepts:**

This is where the analysis becomes more targeted.

* **Reverse Engineering:** The key insight here is that *Frida is a dynamic instrumentation tool used for reverse engineering*. Therefore, this TOML parsing functionality is likely used to *configure* Frida or the targets it interacts with. TOML is a human-readable format, making it suitable for configuration files. The example of modifying configuration values during runtime becomes a direct link to dynamic instrumentation.

* **Binary/Low-Level, Linux/Android Kernel/Framework:** While the *test code itself* doesn't directly interact with the kernel or raw binary, the *underlying Frida tool* likely uses this TOML parsing for configuring its interactions with these low-level systems. For instance, Frida might use a TOML file to specify memory addresses to hook or functions to intercept within an Android process.

* **Logical Reasoning (Hypothetical Inputs/Outputs):** This involves picking a test function and tracing the logic. For example, in `test_inserting_after_element_with_no_new_line_adds_a_new_line`, the input "foo = 10" leads to the output "foo = 10\nbar = 11" when "bar = 11" is added. This demonstrates a clear input-output relationship based on the code's logic.

* **User/Programming Errors:**  Think about how a user might misuse the `tomlkit` library. Trying to access a non-existent key is a common error. The `test_values_can_still_be_set_for_out_of_order_tables` function with its `pytest.raises(NonExistentKey)` is a perfect example of testing how the library handles such errors.

* **Debugging Context (User Operations):** This requires thinking about the *workflow* of a Frida user. They might start by writing a Frida script (possibly with some configuration). This script might then be run using the Frida CLI, which in turn might parse a configuration file (likely in TOML format). The steps from writing the script to encountering a potential parsing error provide the debugging context.

**5. Structuring the Answer:**

Finally, organize the findings into a clear and structured response, addressing each point of the user's request. Use headings and bullet points to enhance readability. Provide concrete code snippets and explanations to illustrate the connections to the specified concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the `tomlkit` library itself.
* **Correction:**  Shift focus to *why* this test file exists within the *Frida project*. The connection to dynamic instrumentation is crucial.
* **Initial thought:**  Assume direct kernel interaction within the test code.
* **Correction:** Recognize that the test code *validates* the TOML parsing logic, which is *used by* Frida when interacting with lower levels. The connection is indirect but important.
* **Refinement:**  Ensure the examples for each concept are clear, concise, and directly relevant to the code being analyzed.
这是一个名为 `test_toml_document.py` 的 Python 源代码文件，属于 Frida 动态 instrumentation 工具项目中的 `frida-swift` 子项目，更具体地说是 `tomlkit` 组件的测试代码。`tomlkit` 是一个用于解析和操作 TOML 格式配置文件的库。这个测试文件专门用于测试 `tomlkit` 库中处理整个 TOML 文档的功能。

**以下是它的功能列表：**

1. **解析 TOML 字符串:** 测试 `tomlkit.parse()` 函数能否正确地将 TOML 格式的字符串解析成 Python 字典或类似字典的对象。
2. **访问 TOML 元素:** 测试解析后的文档对象是否可以像 Python 字典一样通过键来访问其中的值，包括普通键、嵌套键（点号分隔）。
3. **处理不同 TOML 数据类型:** 测试能否正确处理 TOML 中的各种数据类型，如字符串、整数、浮点数、布尔值、日期时间、数组和内联表。
4. **处理表格 (Tables):** 测试对 TOML 中的标准表格、子表格（使用点号分隔的键）、数组表格 (Array of Tables) 的解析和访问。
5. **修改 TOML 文档:** 测试能否修改解析后的文档对象中的值，包括更新现有键的值，添加新的键值对，删除键值对。
6. **保留格式和结构:** 测试在修改文档后，将其转换回字符串时，是否能尽可能地保留原始 TOML 文件的格式和结构，例如空格、换行符、注释等。（虽然这个文件本身没有直接测试注释的保留，但 `tomlkit` 的目标是如此）。
7. **处理无父表格的子表格:** 测试解析和操作不依赖于显式父表格声明的子表格。
8. **解包 (Unwrap) 功能:** 测试将 `tomlkit` 的文档对象转换为标准的 Python 字典的功能。
9. **处理带点号的键:** 测试直接使用带点号的键来访问和操作嵌套结构的功能。
10. **处理不同子节的超级表格:** 测试具有不同子节的超级表格的解析和操作。
11. **在现有表格中添加元素:** 测试在已存在的表格中添加新的键值对。
12. **处理数组表格后的子表格:** 测试数组表格后定义子表格的情况。
13. **处理其他表格后的新子表格:** 测试在一个表格定义后定义新的子表格的情况。
14. **删除和替换表格:** 测试删除和替换整个表格的功能。
15. **在元素后插入内容:** 测试在已有的元素后插入新的元素，并确保添加必要的换行符。
16. **处理删除后的插入:** 测试在删除元素后插入新元素的情况。
17. **处理表格内的带点号的键:** 测试在表格内部使用带点号的键来访问和操作嵌套结构。
18. **处理超级表格后的数组表格:** 测试在超级表格后定义数组表格的情况。
19. **确保表格头后总有新行:** 测试在表格头声明后是否会添加新的换行符。
20. **可序列化 (Picklable):** 测试文档对象是否可以使用 `pickle` 模块进行序列化和反序列化。
21. **设置超级表格元素:** 测试直接设置超级表格的元素。
22. **可复制 (Copyable):** 测试文档对象是否可以使用 `copy` 模块进行浅拷贝和深拷贝。
23. **处理内联表格:** 测试获取内联表格时，其类型仍然是内联表格。
24. **声明带有中间表格的子表格:** 测试声明子表格时，如果中间的表格不存在，是否能正确处理。
25. **处理无序表格:** 测试 TOML 文件中表格定义顺序不一致时，是否能正确解析和操作。
26. **处理无序表格的输出顺序:** 测试在操作无序表格后，输出字符串时是否能保持原有的顺序。
27. **从无序表格中删除元素:** 测试从无序表格中删除元素的功能。
28. **更新嵌套值并保持缩进:** 测试更新嵌套的值时，是否能保持正确的缩进。
29. **`repr()` 表示:** 测试文档对象的字符串表示形式。
30. **深拷贝:**  测试文档对象的深拷贝功能。
31. **移动表格:** 测试移动表格位置的功能。
32. **替换为表格:** 测试用一个表格来替换现有元素。
33. **用值替换表格:** 测试用一个非表格的值来替换现有的表格。
34. **替换时保留分隔符:** 测试在替换元素时，是否能保留原始的空格分隔符。
35. **替换为嵌套表格:** 测试将一个元素替换为一个嵌套的表格结构。
36. **替换为嵌套的数组表格:** 测试将一个元素替换为一个嵌套的数组表格结构。
37. **替换为带注释的项:** 测试将一个元素替换为带有注释的项（例如，数字、数组、内联表）。
38. **没有多余的空格:** 测试在操作文档后，不会引入不必要的空格。
39. **`pop`、添加空格和插入表格的协同工作:** 测试这些操作组合在一起时的行为。
40. **在超级表格前添加换行符:** 测试在添加超级表格时是否会添加必要的换行符。
41. **从超级表格中删除元素:** 测试从超级表格中删除指定元素。
42. **嵌套表格更新显示名称:** 测试更新嵌套表格的显示名称。
43. **使用点号键构建表格:** 测试使用点号分隔的键来构建表格。
44. **解析子表格时没有额外的缩进:** 测试解析子表格时不会添加额外的缩进。
45. **项保留顺序:** 测试内联表格中的项是否能保留添加的顺序。

**与逆向方法的关系及举例说明：**

Frida 是一个动态 instrumentation 工具，常用于逆向工程。TOML 作为一种人类可读的配置文件格式，很可能被 Frida 或其相关的脚本所使用。这个测试文件确保了 Frida 使用的 TOML 解析库 (`tomlkit`) 的正确性，这对于逆向分析的以下方面至关重要：

* **配置 Frida 自身:**  Frida 的某些行为或插件可能通过 TOML 文件进行配置。例如，用户可能需要指定要 hook 的函数、内存地址、或者设置一些运行时参数。如果 TOML 解析出错，可能导致 Frida 无法正常工作，影响逆向分析。
    * **举例:**  假设一个 Frida 插件使用 TOML 文件来定义需要监控的 API 调用列表：
    ```toml
    [monitoring]
    api_calls = ["open", "read", "write"]
    ```
    如果 `tomlkit` 解析 `api_calls` 失败，插件就无法正确获取需要监控的 API，从而导致逆向分析的信息缺失。

* **解析目标程序或环境的配置:** 逆向分析的对象可能也有自己的配置文件，而 Frida 脚本可能需要读取这些配置来辅助分析。如果目标程序的配置是 TOML 格式，那么 `tomlkit` 的正确性就直接影响到 Frida 脚本能否正确理解目标程序的行为。
    * **举例:**  一个 Android 应用可能使用 TOML 文件来存储一些应用设置，Frida 脚本需要读取这些设置来判断应用的某些行为逻辑。解析错误会导致脚本对应用行为的理解偏差。

* **生成或修改配置文件:**  在某些逆向场景中，可能需要动态修改目标程序的配置文件以改变其行为。如果目标程序的配置文件是 TOML 格式，Frida 脚本就需要使用 `tomlkit` 来生成或修改这些文件。
    * **举例:**  一个游戏客户端使用 TOML 文件存储服务器地址，一个 Frida 脚本可能需要修改这个文件来连接到私服。如果 `tomlkit` 修改文件时出错，可能导致客户端无法正常连接。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

虽然这个测试文件本身主要关注 TOML 解析的逻辑，并没有直接涉及二进制底层或操作系统内核，但 `tomlkit` 作为 Frida 生态的一部分，其正确性对于 Frida 与这些底层组件的交互至关重要：

* **Frida 与目标进程的交互:** Frida 通过注入代码到目标进程中进行 instrument。配置信息（可能来自 TOML 文件）会影响 Frida 如何在目标进程的内存空间中进行操作，例如 hook 函数的地址、修改内存的值等。错误的 TOML 解析可能导致 Frida 操作错误的内存地址，引发崩溃或不可预测的行为。
    * **举例:** 一个 Frida 脚本可能使用 TOML 配置指定要 hook 的函数在内存中的偏移地址。`tomlkit` 解析错误可能导致使用了错误的偏移量，最终 hook 到了错误的地址，导致程序崩溃。

* **Frida 与 Android 框架的交互:** 在 Android 逆向中，Frida 经常需要与 Android 框架层的服务进行交互。一些 Frida 模块或脚本可能使用 TOML 文件来配置与特定 Android 服务的交互参数。
    * **举例:**  一个 Frida 脚本可能使用 TOML 文件配置要监听的 Android Broadcast 事件。如果 TOML 解析错误，脚本可能无法正确注册监听器，导致错失关键的系统事件信息。

**逻辑推理的假设输入与输出举例：**

考虑 `test_document_is_a_dict(example)` 这个测试函数。

* **假设输入:**  `example("example")` 函数返回一个包含以下 TOML 内容的字符串（简化版本）：
    ```toml
    [owner]
    name = "Tom"
    organization = "GitHub"

    [database]
    server = "192.168.1.1"
    ports = [8001, 8002]
    ```
* **逻辑推理:**  `parse(content)` 函数应该将这个字符串解析成一个 Python 字典。
* **预期输出:**  `doc` 变量应该是一个字典，其中包含以下结构：
    ```python
    {
        "owner": {
            "name": "Tom",
            "organization": "GitHub"
        },
        "database": {
            "server": "192.168.1.1",
            "ports": [8001, 8002]
        }
    }
    ```
    测试会进一步断言 `isinstance(doc, dict)` 和 ` "owner" in doc` 等条件是否成立。

**用户或编程常见的使用错误及举例说明：**

* **尝试访问不存在的键:**  用户在使用解析后的 TOML 文档时，可能会尝试访问一个不存在的键，就像操作普通字典一样。`tomlkit` 应该能够抛出合适的异常。
    * **举例:**
    ```python
    content = """name = "test" """
    doc = parse(content)
    try:
        print(doc["version"])  # 尝试访问不存在的键 "version"
    except NonExistentKey:
        print("Key 'version' not found.")
    ```
    这个测试文件中的 `test_values_can_still_be_set_for_out_of_order_tables` 函数就测试了当访问或删除不存在的键时，是否会抛出 `NonExistentKey` 异常。

* **假设 TOML 结构与实际不符:**  用户可能假设 TOML 文件中存在某个表格或键，但实际情况并非如此。
    * **举例:**  一个 Frida 脚本期望读取 `config.toml` 文件中的 `api.endpoint` 配置，但该文件实际结构如下：
    ```toml
    [server]
    address = "localhost:8080"
    ```
    脚本如果直接访问 `config["api"]["endpoint"]` 将会出错。良好的 TOML 解析库应该能提供清晰的错误信息，帮助用户调试。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写或修改 Frida 脚本:**  用户为了进行逆向分析，会编写 Frida 脚本，这些脚本可能需要读取或生成配置文件。
2. **脚本中使用了 TOML 配置文件:**  为了方便管理配置信息，用户选择使用 TOML 格式的配置文件。
3. **Frida 脚本调用 `tomlkit` 库:**  在脚本中，用户使用 `tomlkit` 库来解析 TOML 文件。例如：
   ```python
   import tomlkit

   with open("config.toml", "r") as f:
       config = tomlkit.load(f)

   api_key = config["api"]["key"]
   print(f"API Key: {api_key}")
   ```
4. **脚本执行出错或行为异常:**  如果 TOML 文件格式错误，或者 `tomlkit` 库本身存在 Bug，脚本在解析 TOML 文件时可能会出错，导致脚本执行失败或产生意想不到的结果。
5. **开发者定位到 `tomlkit` 组件:**  当发现问题与 TOML 配置有关时，开发者可能会深入到 Frida 项目的 `frida-swift/releng/tomlkit` 目录，查看 `tomlkit` 库的源代码或测试代码，以了解其工作原理和可能存在的 Bug。
6. **查看测试文件 `test_toml_document.py`:**  为了验证 `tomlkit` 是否按预期工作，或者排查特定功能的 Bug，开发者会查看相关的测试文件，例如 `test_toml_document.py`，来理解该库的各种功能和测试用例。通过阅读测试代码，开发者可以了解如何正确使用 `tomlkit`，或者找到潜在的 Bug 所在。

总而言之，`test_toml_document.py` 是 `tomlkit` 库的核心测试文件，它确保了该库能够正确地解析和操作各种 TOML 文档结构，这对于依赖 `tomlkit` 的 Frida 工具和脚本的稳定运行至关重要，特别是在逆向工程领域，精确地读取和操作配置文件是成功进行分析的基础。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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