Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `test_toml_document.py` file within the Frida project. We need to identify what it tests and how that relates to broader concepts like reverse engineering, low-level details, and common user errors.

**2. Initial Scan and High-Level Purpose:**

A quick skim of the code reveals several key things:

* **Imports:** `tomlkit`, `pytest`, `datetime`, `json`, `pickle`, etc. This immediately tells us the code is heavily involved with parsing and manipulating TOML files, and it uses `pytest` for testing.
* **Function Names:**  Functions like `test_document_is_a_dict`, `test_toml_document_unwrap`, `test_toml_document_with_dotted_keys`, and so on, strongly suggest each function tests a specific aspect of how `tomlkit` handles TOML documents.
* **Example Usage:**  The tests often load TOML content (either directly as strings or from external "example" files) and then perform assertions on the parsed document.

**3. Deciphering the Functionality (Iterative Process):**

Now, we need to go through the tests more systematically. For each test function, we ask:

* **What specific TOML feature is being tested?**  Is it basic parsing, handling tables, arrays of tables, dotted keys, inline tables, comments, etc.?
* **What kind of operations are being performed on the parsed document?**  Accessing values, updating values, deleting values, inserting new elements, copying, pickling, etc.
* **What are the assertions checking?** Are they checking the structure of the parsed data (is it a dict, a list?), the values of specific keys, the output format when converting back to a string, or error conditions?

**Example of Deeper Dive (for `test_document_is_a_dict`):**

1. **Input:** `example("example")` - This implies loading a TOML file named "example".
2. **Parsing:** `doc = parse(content)` -  The core function being tested is `tomlkit.parse`.
3. **Assertions:**
   * `isinstance(doc, dict)` -  Verifies that the parsed TOML is represented as a Python dictionary.
   * `"owner" in doc` - Checks for the presence of a top-level key.
   * Accessing nested keys (`doc["owner"]["name"]`) and verifying their values.
   * Checking different data types within the TOML (string, integer, boolean, array, datetime).
   * Testing the `get()` method, which is standard Python dictionary behavior.
   * Testing `update()` and `setdefault()`, again, standard dictionary methods applied to the TOML document.
4. **Conclusion:** This test focuses on verifying that `tomlkit` correctly parses a basic TOML file and represents it as a dictionary, allowing standard dictionary operations.

**4. Connecting to Reverse Engineering (Hypothesizing and Refining):**

Once we have a grasp of the core functionality, we can start thinking about its relevance to reverse engineering:

* **Configuration Files:** TOML is often used for configuration files. Reverse engineers frequently encounter configuration files in software they are analyzing. Understanding how to parse and manipulate these files programmatically (using a tool like Frida and a library like `tomlkit`) can be crucial for tasks like:
    * **Analyzing application behavior:** Configuration settings often dictate how an application behaves.
    * **Modifying application behavior:**  Dynamically changing configuration settings during runtime (using Frida) can be a powerful reverse engineering technique.
    * **Extracting information:**  Configuration files can contain valuable information about the application, such as API keys, server addresses, etc.

* **Frida's Role:**  Frida is a dynamic instrumentation toolkit. This means it allows you to inject code into running processes and interact with their memory and functionality. The `frida-clr` part of the path suggests this specific code might be related to interacting with the Common Language Runtime (CLR), which is used by .NET applications. Therefore, manipulating .NET application configuration files becomes a plausible scenario.

**5. Considering Low-Level Details, Kernels, and Frameworks:**

At this level, the connection is less direct but still important:

* **File I/O:**  Parsing TOML involves reading data from files. This relies on underlying operating system mechanisms for file input/output.
* **Memory Management:** When Frida injects code and manipulates data, it interacts directly with the process's memory space. Understanding how the TOML data is represented in memory (as Python dictionaries, which have their own memory layout) can be relevant in more advanced reverse engineering scenarios.
* **CLR (for `frida-clr`):**  If this is related to .NET, understanding the structure of .NET assemblies and how configuration is handled within the CLR becomes relevant. `tomlkit` provides a higher-level abstraction, but knowing the underlying mechanisms provides a more complete picture.

**6. Logical Reasoning (Input/Output Examples):**

For this, we look at the test cases themselves. Each test function provides a clear example of input TOML and the expected behavior/output after manipulation. We can simply reiterate these examples in our answer.

**7. User Errors:**

Here, we consider how a programmer might misuse the `tomlkit` library based on the tests:

* **Incorrect Key Access:** Trying to access a non-existent key will raise an exception (as demonstrated by the `test_values_can_still_be_set_for_out_of_order_tables` test).
* **Type Mismatches:**  While not explicitly shown in every test, trying to assign a value of the wrong type (e.g., assigning a string to a key that should hold an integer) could lead to issues, though `tomlkit` seems to handle basic type conversions implicitly in some cases.
* **Incorrect TOML Syntax:** Providing malformed TOML input will cause the `parse()` function to raise an exception.

**8. Debugging Scenario:**

To explain how a user might end up in this code during debugging, we need to connect it to Frida's workflow:

1. **User wants to analyze a .NET application's configuration.**
2. **They use Frida to attach to the running .NET process.**
3. **They need to parse a TOML configuration file used by the application.**
4. **They might use Frida's Python API and the `tomlkit` library (which seems to be part of the `frida-clr` project).**
5. **If they encounter issues parsing or manipulating the TOML, they might step through the `tomlkit` code itself (including these test files) to understand how it works and where the problem lies.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is just a generic TOML testing library.
* **Correction:** The `frida/subprojects/frida-clr` path strongly suggests a connection to Frida and the CLR. This context should be emphasized.
* **Initial thought:** Focus heavily on low-level binary details.
* **Refinement:** While low-level details are relevant in reverse engineering, the primary focus of this code is on parsing and manipulating TOML *data*. The connection to low-level aspects is more about the context in which this library might be used.

By following this iterative process of scanning, deciphering, connecting, and refining, we can arrive at a comprehensive and accurate answer to the prompt's questions.
这个Python源代码文件 `test_toml_document.py` 是 Frida 动态 instrumentation 工具中 `tomlkit` 子项目的一部分，用于测试 `tomlkit` 库处理 TOML 文档的功能。`tomlkit` 库本身是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 格式文件的 Python 库。

下面是该文件的功能列表以及与逆向方法、二进制底层、内核框架知识和用户错误的关联说明：

**功能列表:**

1. **解析 TOML 字符串:** 测试 `tomlkit.parse()` 函数能否正确解析各种格式的 TOML 字符串，包括基本的键值对、表格 (tables)、内联表格 (inline tables)、数组 (arrays)、数组表格 (array of tables) 以及带有点号的键 (dotted keys)。
2. **访问 TOML 数据:** 测试解析后的 TOML 文档对象 (通常是一个字典或类似字典的对象) 是否可以像 Python 字典一样访问其内容，包括使用 `[]` 运算符和 `get()` 方法。
3. **修改 TOML 数据:** 测试是否可以修改 TOML 文档中的值，包括更新现有键的值和添加新的键值对。
4. **删除 TOML 数据:** 测试是否可以删除 TOML 文档中的键值对或表格。
5. **处理不同类型的 TOML 数据:** 测试是否能正确处理字符串、整数、布尔值、日期时间 (datetime)、数组和表格等各种 TOML 数据类型。
6. **处理带空格的 TOML 结构:** 测试在 TOML 结构中添加或删除元素时，是否能正确处理空格和换行符，保持格式的正确性。
7. **处理数组表格 (Array of Tables):** 测试对数组表格的访问、修改和添加操作。
8. **处理带有点号的键 (Dotted Keys):** 测试对带有点号的键的解析和访问，以及在表格中使用带有点号的键。
9. **处理无父表格的子表格 (Super Tables):** 测试对类似 `[tool.poetry]` 这样的子表格的解析和操作。
10. **处理乱序的表格 (Out-of-Order Tables):** 测试 `tomlkit` 是否能正确处理在 TOML 文件中定义顺序不一致的表格，并能正确地访问和修改这些表格中的数据。
11. **复制和 Pickle 序列化:** 测试 TOML 文档对象是否可以被复制 (`copy.copy`, `copy.deepcopy`) 和 Pickle 序列化，并在反序列化后保持其内容和结构。
12. **转换为字符串:** 测试 `as_string()` 方法能否将修改后的 TOML 文档对象正确地转换回 TOML 格式的字符串。
13. **保留原始格式:**  测试在修改 TOML 文档后，是否尽可能地保留了原始的格式，例如空格和换行符。
14. **测试 `update()` 和 `setdefault()` 方法:**  验证这些字典常用方法在 TOML 文档对象上的行为是否符合预期。
15. **测试 `unwrap()` 方法:**  验证 `unwrap()` 方法是否能返回一个标准的 Python 字典。
16. **测试 `pop()` 方法:** 验证从 TOML 文档中弹出键值对的功能。
17. **测试添加注释:** 测试在修改 TOML 元素时添加注释的功能。
18. **测试移动表格:** 测试移动 TOML 文档中的表格的功能。
19. **测试替换表格或值:** 测试用新的表格或值替换现有键的功能。

**与逆向方法的关系及举例说明:**

* **分析配置文件:** 逆向工程中，经常需要分析目标程序使用的配置文件，这些文件可能采用 TOML 格式。`tomlkit` 提供的功能可以帮助逆向工程师程序化地读取、解析和修改这些配置文件。
    * **举例:**  假设一个恶意软件的配置文件 `config.toml` 中存储了 C&C 服务器的地址和端口。逆向工程师可以使用 Frida 和 `tomlkit` 读取这个文件，提取出 C&C 服务器的信息，用于后续的分析。

      ```python
      import frida
      import tomlkit

      def on_message(message, data):
          if message['type'] == 'send':
              print(f"[*] {message['payload']}")

      session = frida.attach("target_process")
      script = session.create_script("""
      // 假设目标进程会读取配置文件，我们在这里模拟读取文件内容
      var configFileContent = `
      [server]
      address = "evil.example.com"
      port = 8080
      `;
      send(configFileContent);
      """)
      script.on('message', on_message)
      script.load()
      session.detach()

      # 从 Frida 接收到的配置文件内容
      config_content = """
      [server]
      address = "evil.example.com"
      port = 8080
      """
      doc = tomlkit.parse(config_content)
      server_address = doc['server']['address']
      server_port = doc['server']['port']
      print(f"[*] C&C Server Address: {server_address}")
      print(f"[*] C&C Server Port: {server_port}")
      ```

* **动态修改程序行为:**  在动态分析过程中，逆向工程师可能希望修改程序的配置来观察其行为变化。`tomlkit` 可以用于修改内存中表示配置信息的 TOML 数据结构。
    * **举例:**  某个应用程序使用 TOML 配置文件来决定是否启用某个安全特性。逆向工程师可以使用 Frida 找到内存中表示该配置的 TOML 数据结构，并使用 `tomlkit` 修改相应的布尔值为 `true`，从而启用该特性进行分析。这通常需要结合 Frida 的内存操作 API。

**涉及到二进制底层、Linux, Android 内核及框架的知识及举例说明:**

这个测试文件本身并没有直接涉及到二进制底层、Linux/Android 内核的知识。它主要关注的是 TOML 格式的解析和操作，属于应用层面的逻辑。

然而，`tomlkit` 作为 Frida 的一个子项目，其应用场景是与动态 instrumentation 紧密相关的。在实际使用中，可能会涉及到以下方面：

* **内存操作:** Frida 需要能够读取和写入目标进程的内存，才能获取和修改配置信息。这涉及到操作系统底层的内存管理机制。
* **进程间通信 (IPC):** Frida 与目标进程之间的通信可能涉及到操作系统提供的 IPC 机制，例如管道、共享内存等。
* **动态链接和加载:** 如果目标程序动态加载配置相关的库，Frida 可能需要处理这些动态加载的模块。
* **平台差异:**  虽然 `tomlkit` 本身是平台无关的，但 Frida 在不同的操作系统 (Linux, Android, Windows, macOS) 上实现动态 instrumentation 的方式是不同的，会涉及到各自的内核 API 和框架。

**逻辑推理及假设输入与输出:**

许多测试用例都包含了逻辑推理，通过假设特定的输入 TOML 结构，然后验证 `tomlkit` 的处理结果是否符合预期。

* **假设输入:**
  ```toml
  [owner]
  name = "Alice"
  age = 30
  ```
* **代码操作:**
  ```python
  import tomlkit
  content = """
  [owner]
  name = "Alice"
  age = 30
  """
  doc = tomlkit.parse(content)
  print(doc['owner']['name'])
  doc['owner']['age'] = 31
  print(doc.as_string())
  ```
* **预期输出:**
  ```
  Alice
  [owner]
  name = "Alice"
  age = 31
  ```

* **假设输入 (带有点号的键):**
  ```toml
  a.b.c = 1
  ```
* **代码操作:**
  ```python
  import tomlkit
  content = "a.b.c = 1"
  doc = tomlkit.parse(content)
  print(doc['a']['b']['c'])
  ```
* **预期输出:**
  ```
  1
  ```

**涉及用户或者编程常见的使用错误及举例说明:**

* **尝试访问不存在的键:**  如果用户尝试访问 TOML 文档中不存在的键，会抛出 `NonExistentKey` 异常。
    * **举例:**
      ```python
      import tomlkit
      from tomlkit.exceptions import NonExistentKey
      content = "[owner]\nname = "Alice""
      doc = tomlkit.parse(content)
      try:
          print(doc['owner']['age']) # 'age' 键不存在
      except NonExistentKey:
          print("Error: Key 'age' not found.")
      ```

* **假设 TOML 结构与预期不符:** 用户在编写代码时，可能假设 TOML 文件中存在特定的表格或键，但实际文件内容不一致，导致程序出错。
    * **举例:**
      ```python
      import tomlkit
      content = "[server]\naddress = "localhost""
      doc = tomlkit.parse(content)
      try:
          port = doc['server']['port'] # 假设存在 'port' 键
          print(f"Server port: {port}")
      except KeyError:
          print("Error: 'port' key not found in 'server' table.")
      ```

* **不理解 TOML 语法:**  用户可能编写出不符合 TOML 语法的字符串，导致 `tomlkit.parse()` 函数抛出异常。
    * **举例:**
      ```python
      import tomlkit
      content = "name = Alice" # 缺少表格定义
      try:
          doc = tomlkit.parse(content)
      except tomlkit.exceptions.ParseError as e:
          print(f"Parsing error: {e}")
      ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要使用 Frida 对某个程序进行动态分析。**
2. **该程序使用了 TOML 格式的配置文件。**
3. **用户希望使用 Frida 脚本来读取或修改该程序的配置文件内容。**
4. **用户在 Frida 脚本中引入了 `tomlkit` 库，因为 Frida 已经包含了这个库。**
5. **用户编写 Frida 脚本，使用 `tomlkit.parse()` 函数解析从目标进程内存中读取到的 TOML 字符串，或者直接解析本地的 TOML 文件。**
6. **在脚本执行过程中，如果解析或操作 TOML 文档时出现问题，用户可能需要查看 `tomlkit` 的源代码来理解其内部工作原理，以便找到问题所在。**
7. **`test_toml_document.py` 文件就是 `tomlkit` 库的一部分，包含了大量的测试用例，可以帮助用户理解 `tomlkit` 的各种功能和用法。**
8. **用户可能会查看这个测试文件中的特定测试用例，例如与他们遇到的问题类似的场景，来寻找调试的灵感。**
9. **例如，如果用户在处理带有点号的键时遇到问题，他们可能会查看 `test_toml_document_with_dotted_keys` 这个测试函数，来理解 `tomlkit` 是如何处理这类键的。**
10. **此外，如果用户怀疑 `tomlkit` 在处理某种特定的 TOML 结构时存在 bug，他们可能会查看相关的测试用例，或者自己编写新的测试用例来验证他们的假设。**

总而言之，`test_toml_document.py` 是 `tomlkit` 库的功能验证和示例展示，对于使用 Frida 进行动态分析并需要处理 TOML 配置文件的用户来说，它可以作为理解 `tomlkit` 工作原理和排查问题的宝贵资源。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tests/test_toml_document.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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