Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The request asks for an analysis of a Python file (`test_toml_document.py`) within the context of the Frida dynamic instrumentation tool. The key is to identify the file's purpose, relate it to reverse engineering concepts (if applicable), and consider connections to lower-level systems like Linux/Android kernels. It also specifically asks for examples of logic, user errors, and debugging context.

**2. Initial Code Examination and Purpose Identification:**

The first step is to read the code. The filename (`test_toml_document.py`) and the presence of imports like `pytest` immediately suggest this is a test file. Looking at the function names (`test_document_is_a_dict`, `test_toml_document_unwrap`, etc.) reinforces this. The code uses the `tomlkit` library and interacts with TOML data. Therefore, the primary function of this file is to test the functionality of the `tomlkit` library, particularly how it handles TOML documents.

**3. Identifying Key Functionality Being Tested:**

Scan through the test functions and note the different aspects of `tomlkit`'s `Document` class being examined. Keywords like `parse`, `as_string`, `update`, `delete`, `copy`, `pickle`, and the handling of different TOML structures (tables, inline tables, arrays of tables, dotted keys) are important.

**4. Connecting to Reverse Engineering (Initial Thought - May Not Be Direct):**

The prompt asks about reverse engineering. At first glance, testing a TOML library doesn't seem directly related. However, TOML is a configuration file format. Think about where configuration files are used. Applications, especially complex ones, often use configuration files. In reverse engineering, understanding an application's configuration can be crucial for understanding its behavior. While this test file isn't *performing* reverse engineering, the library it's testing could be used in tools that *do* reverse engineering. For example, a Frida script might read a TOML configuration file to customize its behavior.

**5. Considering Binary/Kernel/Framework Aspects (Again, May Not Be Direct):**

The same principle applies to the lower-level aspects. `tomlkit` itself is a higher-level Python library. It doesn't directly interact with the kernel. *However*, applications running on Linux or Android might use TOML for configuration. Frida, as a dynamic instrumentation tool, interacts with these applications at runtime. Therefore, understanding how to parse and manipulate TOML could be relevant when working with applications on these platforms.

**6. Logic and Input/Output Examples:**

Many test functions provide implicit logic examples. The `test_document_is_a_dict` function loads a TOML example and asserts that various data structures within it are parsed correctly. The `test_adding_an_element_to_existing_table_with_ws_remove_ws` function demonstrates how adding a key-value pair to a table affects whitespace. To make these explicit, think about specific input TOML, the action taken by the test, and the expected output.

**7. User/Programming Errors:**

Look for test cases that deal with unexpected or invalid situations. The `test_values_can_still_be_set_for_out_of_order_tables` test implicitly shows a potential issue if the user assumes the order of table definition dictates access. The `test_out_of_order_tables_are_still_dicts` test with `KeyError` when popping a missing key illustrates a common Python dictionary error. Think about what could go wrong when a user interacts with the `tomlkit` API.

**8. Debugging Context - Tracing the User's Path:**

This requires imagining how someone using Frida might end up needing to understand this test file. The key is the association with Frida mentioned in the prompt.

* **Scenario:** A Frida script developer wants to modify a configuration file used by a target application. The file is in TOML format.
* **Problem:** The developer is unsure how `tomlkit` (which might be a dependency or a useful tool) handles certain TOML structures or operations.
* **Action:** The developer might search for `tomlkit` examples or tests to understand its behavior. Finding this test file in the Frida repository provides concrete usage examples.

**9. Structuring the Answer:**

Organize the findings into the requested categories:

* **Functionality:** Summarize the core purpose and list specific aspects of the `tomlkit.Document` class being tested.
* **Reverse Engineering:** Explain the indirect link through configuration files and Frida scripts.
* **Binary/Kernel/Framework:**  Again, emphasize the indirect connection via applications running on these systems.
* **Logic and Input/Output:** Select a few representative test cases and explicitly state the input, operation, and output.
* **User Errors:**  Provide examples of common errors a programmer using `tomlkit` might encounter.
* **Debugging Context:** Describe a plausible scenario where a Frida user would find this file relevant.

**Self-Correction/Refinement:**

* **Initial thought:**  This test file is purely about `tomlkit`.
* **Correction:**  The prompt emphasizes the Frida context. While the file itself doesn't *do* Frida instrumentation, it's part of the Frida project and helps understand a library that could be used with Frida. Highlighting this connection is crucial.
* **Initial thought:** Focus only on the positive tests.
* **Correction:**  Include examples of tests that demonstrate potential error conditions or unexpected behavior, as this helps illustrate common user mistakes.

By following this structured approach, even with limited initial information about the broader Frida project, we can effectively analyze the provided Python code and address all the requirements of the prompt.
好的，让我们来分析一下 `frida/releng/tomlkit/tests/test_toml_document.py` 这个文件。

**文件功能列表:**

这个 Python 文件是 `tomlkit` 库的测试文件，专门用于测试 `tomlkit.api.document` 模块中 `Document` 类的各种功能。`Document` 类是 `tomlkit` 中表示 TOML 文档的核心类。  具体来说，这个文件测试了以下功能：

1. **基础字典行为模拟:** 验证 `Document` 类是否像 Python 字典一样工作，包括：
    * 获取和设置键值对 (`doc["key"]`, `doc.get("key")`, `doc["key"] = value`)
    * 检查键是否存在 (`"key" in doc`)
    * 迭代
    * 获取子项 (`doc["table"]["subkey"]`)
2. **TOML 结构解析和表示:** 测试 `Document` 类是否能正确解析各种 TOML 结构，例如：
    * 表格 (`[section]`)
    * 子表格 (`[section.subsection]`)
    * 内联表格 (`key = { a = 1, b = 2 }`)
    * 数组 (`key = [1, 2, 3]`)
    * 数组表格 (`[[array_of_tables]]`)
    * 各种数据类型 (字符串, 数字, 布尔值, 日期时间)
    * 带有点的键 (`a.b.c = value`)
3. **文档修改操作:** 测试对 `Document` 对象进行修改的功能，包括：
    * 添加新的键值对 (`doc["new_key"] = value`)
    * 更新已有的键值对 (`doc["existing_key"] = new_value`)
    * 删除键值对 (`del doc["key"]`)
    * 使用 `update()` 方法合并字典
    * 使用 `setdefault()` 方法设置默认值
4. **输出 TOML 字符串:** 测试将 `Document` 对象转换回 TOML 格式字符串的功能 (`doc.as_string()`)，并验证输出的格式是否正确，包括：
    * 保留原始的格式和注释 (尽管这个文件没有显式地测试注释的保留，但 `tomlkit` 的目标是如此)
    * 正确处理空白符
    * 维护表格和键值对的顺序
5. **与其他 Python 功能的集成:**
    * `pickle` 序列化和反序列化
    * `copy` 浅拷贝和深拷贝
    * `json` 序列化 (间接通过与字典的相似性)
6. **处理带有点的键:**  测试对带有点的键的解析、访问和修改。
7. **处理无序表格:** 测试 TOML 规范中允许的无序表格定义，并验证 `tomlkit` 能正确处理。
8. **处理数组表格:** 测试数组表格的解析和访问。
9. **异常处理:**  测试在访问不存在的键时是否抛出 `NonExistentKey` 异常。

**与逆向方法的关系及举例说明:**

虽然这个文件本身是测试代码，不直接进行逆向操作，但 `tomlkit` 库在逆向工程中可能扮演以下角色：

* **解析应用程序的配置文件:** 许多应用程序使用 TOML 作为配置文件格式。逆向工程师可能需要解析这些配置文件来了解应用程序的行为、配置选项、服务器地址、API 密钥等敏感信息。
    * **举例:**  假设一个逆向工程师正在分析一个 Android 应用程序，发现其使用一个名为 `config.toml` 的文件存储服务器地址和加密密钥。使用 `tomlkit` 可以解析这个文件，提取关键信息，例如：

    ```python
    import tomlkit

    config_content = """
    [server]
    address = "https://api.example.com"
    port = 443

    [security]
    api_key = "super_secret_key"
    """

    doc = tomlkit.parse(config_content)
    server_address = doc["server"]["address"]
    api_key = doc["security"]["api_key"]

    print(f"Server Address: {server_address}")
    print(f"API Key: {api_key}")
    ```

* **修改应用程序的配置文件进行测试或破解:**  在某些情况下，逆向工程师可能需要修改应用程序的配置文件来改变其行为，例如禁用某些功能、修改许可验证、指向自己的服务器等。`tomlkit` 可以用于加载、修改和重新生成 TOML 配置文件。
    * **举例:**  假设一个桌面应用程序的配置文件 `settings.toml` 中有一个布尔值 `enable_debug_mode`。逆向工程师可以使用 `tomlkit` 将其设置为 `true` 以启用调试功能：

    ```python
    import tomlkit

    with open("settings.toml", "r") as f:
        doc = tomlkit.load(f)

    doc["application"]["enable_debug_mode"] = True

    with open("settings.toml", "w") as f:
        tomlkit.dump(doc, f)
    ```

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

`tomlkit` 本身是一个纯 Python 库，主要处理文本格式的 TOML 数据，因此它不直接涉及二进制底层、内核或框架的编程。然而，它所处理的数据 (TOML 配置文件) 可能与这些底层概念相关：

* **应用程序配置:**  在 Linux 和 Android 系统上运行的应用程序经常使用配置文件来定义其行为。这些配置文件可能包含与操作系统交互的设置，例如文件路径、网络配置、权限设置等。
* **系统服务配置:**  Linux 系统上的许多服务 (例如 `systemd` 服务) 使用配置文件进行管理。这些配置文件可能使用 TOML 或其他格式。
* **Android 框架配置:** Android 系统的一些框架组件也可能使用配置文件。虽然 Android 主要使用 XML 和 Properties 文件，但使用 TOML 的情况也可能存在。

**举例说明 (间接关系):**

假设一个 Frida 脚本需要读取 Android 应用程序的配置文件，该配置文件恰好是 TOML 格式，并且包含了应用程序连接的 Binder 服务的名称。虽然 `tomlkit` 不直接与 Binder 交互，但它可以帮助 Frida 脚本获取 Binder 服务名称：

```python
import frida
import tomlkit
import sys

package_name = "com.example.app"

try:
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
function main() {
  // 假设已经通过某种方式读取到了配置文件的内容
  const tomlContent = `
  [binder]
  service_name = "MyCustomService"
  `;
  const tomlkit = require('tomlkit');
  const config = tomlkit.parse(tomlContent);
  const serviceName = config.binder.service_name;
  console.log("Binder Service Name:", serviceName);

  // 这里可以进一步使用 serviceName 与 Binder 服务交互
}

setImmediate(main);
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

在这个例子中，Frida 脚本在 JavaScript 环境中使用了一个类似 `tomlkit` 的库 (或者直接使用 `eval` 执行 Python 代码)，解析了 TOML 配置文件，并提取了 Binder 服务名称。然后，这个名称可以被 Frida 用来 hook 或监视与该 Binder 服务的通信。

**逻辑推理、假设输入与输出:**

许多测试用例都展示了逻辑推理。我们选择一个例子：

**测试用例:** `test_document_with_dotted_keys`

**假设输入 (TOML 字符串):**

```toml
[physical]
color = "orange"
shape = "round"

[site."google.com"]
# just a value

[a.b]
c = 1
d = 2
```

**逻辑推理:** `tomlkit.parse()` 函数应该能够正确解析带有点的键，并将它们映射到嵌套的字典结构中。

**预期输出 (Python 字典结构):**

```python
{
    'physical': {'color': 'orange', 'shape': 'round'},
    'site': {'google.com': {}},
    'a': {'b': {'c': 1, 'd': 2}}
}
```

**用户或编程常见的使用错误及举例说明:**

1. **尝试访问不存在的键而不进行检查:** 这会导致 `NonExistentKey` 异常。
    * **错误示例:**
    ```python
    import tomlkit

    content = """name = "Alice" """
    doc = tomlkit.parse(content)
    age = doc["age"]  # 假设 TOML 中没有 "age" 键
    print(age)
    ```
    * **正确做法:**
    ```python
    import tomlkit

    content = """name = "Alice" """
    doc = tomlkit.parse(content)
    if "age" in doc:
        age = doc["age"]
        print(age)
    else:
        print("Age not found in the document.")

    # 或者使用 get 方法提供默认值
    age = doc.get("age", None)
    if age is not None:
        print(age)
    ```

2. **假设表格的顺序与定义顺序相同:** 虽然 `tomlkit` 努力保留顺序，但在某些修改操作后，顺序可能发生变化。依赖表格的绝对顺序可能会导致问题。
    * **说明:**  TOML 规范本身并不强制要求表格顺序。

3. **不理解带有点的键的层级结构:**  可能会错误地认为 `a.b.c` 可以直接作为顶级键访问。
    * **错误示例:**
    ```python
    import tomlkit

    content = """a.b.c = 1"""
    doc = tomlkit.parse(content)
    value = doc["a.b.c"]  # 错误，应该先访问 'a'，再 'b'，最后 'c'
    print(value)
    ```
    * **正确做法:**
    ```python
    import tomlkit

    content = """a.b.c = 1"""
    doc = tomlkit.parse(content)
    value = doc["a"]["b"]["c"]
    print(value)
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

想象一个 Frida 用户在调试一个使用了 TOML 配置文件的应用程序：

1. **用户启动 Frida 并附加到目标进程。**
2. **用户编写 Frida 脚本，希望读取或修改目标应用程序的 TOML 配置文件。**  用户可能需要了解 `tomlkit` 库的工作方式才能在 Frida 的 JavaScript 环境中解析或生成 TOML 数据 (虽然 Frida 脚本主要使用 JavaScript，但可以执行 Python 代码或与 Python 交互)。
3. **用户在编写脚本时遇到了关于 `tomlkit` 如何处理特定 TOML 结构 (例如，带有点的键或数组表格) 的疑问。**
4. **为了理解 `tomlkit` 的行为，用户可能会查看 `tomlkit` 的源代码或者相关的测试文件。**  `test_toml_document.py` 文件提供了大量关于 `Document` 类用法的示例。
5. **用户可能会查看特定的测试用例，例如 `test_document_with_dotted_keys`，来了解 `tomlkit` 如何解析和表示带有点的键。**  这个测试用例展示了如何通过嵌套的字典结构访问这些值。
6. **用户也可能查看修改操作的测试用例，例如 `test_adding_an_element_to_existing_table_with_ws_remove_ws`，来了解修改 TOML 文档后格式是否会被正确维护。**
7. **通过阅读这些测试用例，用户可以更好地理解 `tomlkit` 的 API 和行为，从而更有效地编写 Frida 脚本来处理目标应用程序的 TOML 配置文件。**

总而言之，`test_toml_document.py` 虽然是测试代码，但对于理解 `tomlkit` 库的功能和行为至关重要，这对于需要处理 TOML 格式配置文件的 Frida 用户来说非常有帮助。它可以作为调试和学习 `tomlkit` 用法的宝贵资源。

Prompt: 
```
这是目录为frida/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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