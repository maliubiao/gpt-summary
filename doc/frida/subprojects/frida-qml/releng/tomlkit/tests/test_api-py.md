Response:
Let's break down the thought process for analyzing this Python code snippet for the Frida dynamic instrumentation tool.

**1. Understanding the Goal:**

The request asks for a functional breakdown of a specific Python file within the Frida project, focusing on its relevance to reverse engineering, low-level operations, and potential user errors. The key is to bridge the gap between the code's purpose (TOML parsing) and its possible applications in dynamic instrumentation.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and structural elements. I see:

* **`import` statements:** `io`, `json`, `os`, `datetime`, `types`, `pytest`, `tomlkit`. This tells me the code deals with input/output, JSON serialization, file system operations, date/time manipulation, type handling, unit testing (via `pytest`), and, most importantly, the `tomlkit` library itself.
* **Function definitions:**  `json_serial`, `test_parse_can_parse_valid_toml_files`, `test_load_from_file_object`, `test_parsed_document_are_properly_json_representable`, `test_parse_raises_errors_for_invalid_toml_files`, `test_original_string_and_dumped_string_are_equal`, and many more. This indicates a test suite.
* **`@pytest.mark.parametrize`:** This is a clear sign of parameterization in the tests, meaning the same test logic is applied to various input values.
* **`assert` statements:** These are the core of the tests, verifying expected outcomes.
* **Exception handling:** `pytest.raises` is used to check if specific exceptions are raised for invalid TOML input.
* **`tomlkit` API usage:** Functions like `parse`, `loads`, `dump`, `dumps`, `integer`, `float_`, `boolean`, etc., are being called. This confirms the file is testing the `tomlkit` library's API.
* **File path manipulation:** `os.path.join` suggests the code is working with file system paths.
* **String manipulation:** Various string formatting and comparison operations are present.

**3. Identifying Core Functionality:**

The repeated use of `parse`, `loads`, `dump`, and `dumps` points to the primary function of the code: **testing the parsing and serialization capabilities of the `tomlkit` library.**  TOML is a configuration file format, so the tests are verifying that `tomlkit` can correctly read valid TOML and write TOML back out.

**4. Connecting to Reverse Engineering:**

Now comes the crucial step: how does this relate to reverse engineering with Frida?

* **Configuration files:** Reverse engineering often involves analyzing applications that use configuration files. Frida might interact with or modify these files. Understanding how to parse and manipulate TOML is valuable here. *Example:* A game might store settings in a TOML file. Frida could modify these settings at runtime.
* **Inter-process communication:**  While not explicitly demonstrated in *this* file, TOML could be used as a data exchange format between different parts of a larger system being analyzed with Frida.

**5. Identifying Low-Level/Kernel Connections (and Lack Thereof):**

A careful review of the imports and the operations performed reveals **no direct interaction with the Linux kernel, Android kernel, or low-level binary operations in *this specific file***. It's purely focused on TOML parsing. It's important to state this explicitly to avoid making incorrect assumptions. However, *Frida itself* heavily relies on these low-level aspects. This file is *supporting infrastructure* for Frida's broader capabilities.

**6. Logical Reasoning and Input/Output:**

The `@pytest.mark.parametrize` decorator makes it easy to identify the intended inputs and expected outputs for many tests. For example, the tests for valid TOML files use `.toml` files as input and expect a `TOMLDocument` object as output. The tests for invalid TOML files expect specific exceptions to be raised. I can pick representative examples to illustrate this.

**7. User Errors:**

The tests specifically targeting invalid TOML syntax (using `invalid_example` fixture) directly highlight potential user errors. These are the mistakes a developer or someone writing a TOML configuration file might make. The test names themselves are descriptive of the errors (e.g., "section_with_trailing_characters").

**8. Tracing User Operations (Debugging Context):**

To understand how a user might end up in this code during debugging, I need to think about the development workflow of Frida or a tool built with Frida:

1. **User wants to interact with a process:**  The user starts a Frida script or tool targeting a specific application.
2. **Configuration is needed:** The Frida script or the target application might need to read configuration data. This data could be in TOML format.
3. **`tomlkit` is used:** The Frida code (or a library it uses) employs `tomlkit` to parse the TOML file.
4. **An error occurs:**  If the TOML file is malformed, `tomlkit` will raise an exception. This is where these tests become relevant. A developer debugging this scenario might step into the `tomlkit` code and encounter these error handling mechanisms.

**9. Structuring the Answer:**

Finally, I need to structure the information clearly, following the points requested in the original prompt:

* **Functionality:** Start with a high-level summary of the file's purpose.
* **Reverse Engineering:**  Explain the connection to reverse engineering, providing concrete examples.
* **Low-Level/Kernel:** Address this specifically, clarifying whether the file directly interacts with these layers.
* **Logical Reasoning:** Provide input/output examples based on the parameterized tests.
* **User Errors:** List common user errors that the tests cover.
* **Debugging:** Explain how a user might reach this code during debugging.

By following this systematic approach, I can effectively analyze the code snippet and provide a comprehensive and informative answer. The key is to not just describe what the code *does*, but to connect it to the broader context of Frida and reverse engineering.
这个Python源代码文件 `test_api.py` 是 Frida 工具链中 `tomlkit` 子项目的一部分。`tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 格式配置文件的 Python 库。 `test_api.py` 的主要功能是 **测试 `tomlkit` 库的公共 API (Application Programming Interface)**。

具体来说，它测试了 `tomlkit` 提供的各种函数和类，以确保它们能够正确地解析有效的 TOML 文件和字符串，并且在遇到无效的 TOML 数据时能够抛出预期的异常。

以下是根据你的要求对 `test_api.py` 功能的详细列举和说明：

**1. 功能列举：**

* **解析有效的 TOML 数据:**
    * 使用 `tomlkit.parse()` 函数解析 TOML 字符串。
    * 使用 `tomlkit.loads()` 函数解析 TOML 字符串。
    * 使用 `tomlkit.load()` 函数从文件对象中加载 TOML 数据。
* **JSON 表示:** 验证解析后的 TOML 文档可以正确地转换为 JSON 格式，以便与其他系统进行数据交换。
* **处理无效的 TOML 数据:** 测试解析器在遇到各种不符合 TOML 规范的输入时是否会抛出正确的异常，例如：
    * 意外的字符 (`UnexpectedCharError`)
    * 无效的数字 (`InvalidNumberError`)
    * 无效的日期、时间或日期时间 (`InvalidDateError`, `InvalidTimeError`, `InvalidDateTimeError`)
    * 尾随逗号
    * 单行字符串中的换行符 (`InvalidControlChar`)
    * 字符串中的非法字符 (`InvalidCharInStringError`)
    * 数组和内联表中的错误逗号使用
* **转储 TOML 数据:**
    * 使用 `tomlkit.dumps()` 函数将 Python 数据结构转换为 TOML 字符串。
    * 使用 `tomlkit.dump()` 函数将 Python 数据结构写入文件对象。
    * 测试转储原始字典和 `MappingProxyType` 对象。
    * 测试转储包含元组的字典（元组会被转换为数组）。
* **创建 TOML 数据类型:** 测试 `tomlkit` 提供的用于创建不同 TOML 数据类型（如整数、浮点数、布尔值、日期、时间、数组、表格、内联表格、数组表格 (AoT)、键）的工厂函数。
* **创建和操作 TOML 文档结构:** 测试如何创建 `TOMLDocument` 对象，并向其中添加键值对、表格和数组表格。
* **处理带点的键:** 测试如何处理和创建带有 `.` 的键名，用于表示嵌套的表格结构。
* **解析布尔值:** 专门测试如何解析布尔值 "true" 和 "false"，并确保不会将类似 "true" 或 "false" 开头的字符串误解析为布尔值。
* **处理字符串:** 测试创建不同类型的 TOML 字符串，包括：
    * 普通字符串
    * 带有转义字符的字符串
    * 字面量字符串 (literal strings)
    * 多行基本字符串
    * 多行字面量字符串
* **处理空引号的表格名:** 测试解析和转储表格名为空字符串的情况。

**2. 与逆向方法的关系 (举例说明):**

虽然 `tomlkit` 本身是一个纯粹的 TOML 解析库，但它在 Frida 这样的动态 instrumentation 工具中扮演着重要的角色，因为许多应用程序和系统使用配置文件来存储其行为和设置。 逆向工程师可以使用 Frida 来：

* **查看和修改应用程序的配置:** 应用程序可能使用 TOML 文件来存储各种参数，例如服务器地址、调试标志、功能开关等。 使用 Frida 和 `tomlkit`，逆向工程师可以在运行时读取这些配置文件，并根据需要修改它们来改变应用程序的行为。
    * **例子:** 假设一个 Android 应用将其 API 端点存储在一个名为 `config.toml` 的文件中。逆向工程师可以使用 Frida 脚本读取这个文件，修改 API 端点指向一个代理服务器，然后让应用在运行时使用修改后的配置。
* **分析配置文件的结构和内容:** 理解应用程序的配置文件格式对于理解其工作原理至关重要。`tomlkit` 提供了方便的 API 来解析 TOML 文件，让逆向工程师可以轻松地检查配置项及其值。
    * **例子:**  一个 Linux 守护进程的配置文件可能包含各种服务参数和安全设置。逆向工程师可以使用 Frida 附加到该进程，并使用 `tomlkit` 解析其配置文件，从而了解服务的配置方式。
* **Hook 与配置相关的函数:** 逆向工程师可以 hook 应用程序中读取配置文件的函数，并在 `tomlkit` 解析 TOML 数据后拦截其结果，从而动态地分析应用程序如何使用配置信息。
    * **例子:** 在逆向一个使用 TOML 配置的网络应用程序时，可以 hook 其加载配置文件的函数，在 `tomlkit.load()` 返回后，打印出解析后的配置字典，以便观察应用程序使用的配置。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

`test_api.py` 文件本身 **不直接** 涉及二进制底层、Linux/Android 内核或框架的知识。它专注于测试 Python 代码。然而，`tomlkit` 作为 Frida 生态系统的一部分，最终会服务于与这些底层概念相关的任务。

* **二进制底层:** Frida 能够注入到进程的内存空间并执行代码。应用程序的 TOML 配置文件可能影响其在内存中的数据结构和行为。通过修改配置，逆向工程师可以间接地影响应用程序的底层行为。
* **Linux/Android 内核:** 某些系统级的应用程序或守护进程可能使用 TOML 配置文件来管理其在内核中的行为或资源分配。虽然 `tomlkit` 不直接与内核交互，但通过 Frida 修改这些配置，可以间接地影响内核相关的行为。
    * **例子:**  一个 Android 系统服务可能使用 TOML 文件来配置其权限或资源限制。逆向工程师可以使用 Frida 修改这个配置文件（如果可行），从而尝试绕过某些安全限制。
* **Android 框架:** Android 应用程序可能会使用 TOML 文件来配置其组件的行为，例如 Activity 或 Service。Frida 可以用来读取和修改这些配置，从而影响应用程序在 Android 框架内的运行方式。
    * **例子:** 一个 Android 应用可能使用 TOML 文件来指定启动时加载的模块或插件。逆向工程师可以使用 Frida 修改这个配置文件，添加或替换要加载的模块，从而扩展或修改应用的功能。

**4. 逻辑推理 (假设输入与输出):**

测试用例中包含了大量的逻辑推理，通过断言 (assert) 验证了在给定输入下，`tomlkit` 函数应该产生的输出或抛出的异常。以下是一些例子：

* **假设输入 (有效的 TOML):**
  ```toml
  title = "TOML Example"

  [owner]
  name = "Tom Preston-Werner"
  dob = 1979-05-27T07:32:00-08:00
  ```
  **预期输出:** `tomlkit.parse()` 或 `tomlkit.loads()` 会返回一个 `TOMLDocument` 对象，其内容对应于上述 TOML 结构，例如：
  ```python
  {'title': 'TOML Example', 'owner': {'name': 'Tom Preston-Werner', 'dob': datetime.datetime(1979, 5, 27, 7, 32, tzinfo=datetime.timezone(datetime.timedelta(seconds=-28800)))}}
  ```

* **假设输入 (无效的 TOML):**
  ```toml
  title = "TOML Example"
  name = Tom  # 缺少引号
  ```
  **预期输出:** `tomlkit.parse()` 或 `tomlkit.loads()` 会抛出一个 `tomlkit.exceptions.UnexpectedCharError` 异常，因为 "Tom" 应该用引号括起来。

* **假设输入 (Python 字典):**
  ```python
  data = {"name": "Frida", "version": 16.0}
  ```
  **预期输出:** `tomlkit.dumps(data)` 会返回以下 TOML 字符串：
  ```toml
  name = "Frida"
  version = 16
  ```

**5. 用户或编程常见的使用错误 (举例说明):**

测试用例中针对无效 TOML 数据的测试，实际上就反映了用户在编写 TOML 文件时可能犯的错误：

* **忘记给字符串加引号:**
    ```toml
    name = John Doe  # 错误，应该写成 name = "John Doe"
    ```
    `test_parse_raises_errors_for_invalid_toml_files` 中的 `key_value_with_trailing_chars` 测试覆盖了这种情况。

* **在单行字符串中使用换行符:**
    ```toml
    description = "This is a
    multi-line description." # 错误，单行字符串不允许直接换行
    ```
    `test_parse_raises_errors_for_invalid_toml_files` 中的 `newline_in_singleline_string` 测试覆盖了这种情况。

* **使用了非法的控制字符:**
    ```toml
    message = "Hello\x01World" # 错误，某些控制字符在字符串中是非法的
    ```
    尽管此文件没有直接测试这个，但 TOML 规范禁止某些控制字符。

* **数组或内联表中错误地使用逗号:**
    ```toml
    ports = [80,, 443]  # 错误，连续的逗号
    config = {key1: value1,} # 错误，尾随逗号
    ```
    `test_parse_raises_errors_for_invalid_toml_files` 中有多个测试覆盖了数组和内联表中逗号使用错误的情况。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

作为一个测试文件，用户通常不会直接“到达” `test_api.py`。它的目的是在开发 `tomlkit` 库时，通过运行测试来验证代码的正确性。 然而，在调试 Frida 或使用 Frida 的过程中，如果涉及到 TOML 配置文件解析，并且遇到了错误，那么调试过程可能会间接地涉及到 `tomlkit` 和其测试：

1. **用户编写或使用了依赖 TOML 配置的 Frida 脚本。**
2. **Frida 脚本在解析 TOML 配置文件时遇到了错误。** 这可能是因为配置文件格式不正确，或者 `tomlkit` 库本身存在 bug (可能性较小，因为有完善的测试)。
3. **如果错误是由于配置文件格式不正确，** 用户需要检查自己的 TOML 文件，比对 TOML 规范，并可能参考 `tomlkit` 的错误提示信息。 `test_api.py` 中对各种无效 TOML 数据的测试可以帮助理解哪些 TOML 语法是错误的。
4. **如果怀疑是 `tomlkit` 库的 bug，** 开发人员可能会运行 `tomlkit` 的测试套件（包括 `test_api.py`）来验证库的正确性。
5. **在调试 `tomlkit` 库本身时，** 开发人员会逐步执行 `test_api.py` 中的测试用例，设置断点，观察变量的值，以找出 bug 的根源。

**总结:**

`test_api.py` 是 `tomlkit` 库的关键组成部分，它通过大量的测试用例确保了 `tomlkit` 能够可靠地解析和生成 TOML 数据。虽然用户不会直接与此文件交互，但其测试覆盖了用户在使用 TOML 过程中可能遇到的各种情况，并且在调试与 TOML 配置相关的 Frida 脚本时，可以作为理解 TOML 语法和 `tomlkit` 行为的重要参考。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tests/test_api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import io
import json
import os

from datetime import date
from datetime import datetime
from datetime import time
from types import MappingProxyType

import pytest

import tomlkit

from tomlkit import dump
from tomlkit import dumps
from tomlkit import load
from tomlkit import loads
from tomlkit import parse
from tomlkit.exceptions import InvalidCharInStringError
from tomlkit.exceptions import InvalidControlChar
from tomlkit.exceptions import InvalidDateError
from tomlkit.exceptions import InvalidDateTimeError
from tomlkit.exceptions import InvalidNumberError
from tomlkit.exceptions import InvalidStringError
from tomlkit.exceptions import InvalidTimeError
from tomlkit.exceptions import UnexpectedCharError
from tomlkit.items import AoT
from tomlkit.items import Array
from tomlkit.items import Bool
from tomlkit.items import Date
from tomlkit.items import DateTime
from tomlkit.items import Float
from tomlkit.items import InlineTable
from tomlkit.items import Integer
from tomlkit.items import Key
from tomlkit.items import Table
from tomlkit.items import Time
from tomlkit.toml_document import TOMLDocument


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date, time)):
        return obj.isoformat()

    raise TypeError(f"Type {type(obj)} not serializable")


@pytest.mark.parametrize(
    "example_name",
    [
        "example",
        "fruit",
        "hard",
        "sections_with_same_start",
        "pyproject",
        "0.5.0",
        "test",
        "newline_in_strings",
        "preserve_quotes_in_string",
        "string_slash_whitespace_newline",
        "table_names",
    ],
)
def test_parse_can_parse_valid_toml_files(example, example_name):
    assert isinstance(parse(example(example_name)), TOMLDocument)
    assert isinstance(loads(example(example_name)), TOMLDocument)


@pytest.mark.parametrize(
    "example_name",
    [
        "example",
        "fruit",
        "hard",
        "sections_with_same_start",
        "pyproject",
        "0.5.0",
        "test",
        "newline_in_strings",
        "preserve_quotes_in_string",
        "string_slash_whitespace_newline",
        "table_names",
    ],
)
def test_load_from_file_object(example_name):
    with open(
        os.path.join(os.path.dirname(__file__), "examples", example_name + ".toml"),
        encoding="utf-8",
    ) as fp:
        assert isinstance(load(fp), TOMLDocument)


@pytest.mark.parametrize("example_name", ["0.5.0", "pyproject", "table_names"])
def test_parsed_document_are_properly_json_representable(
    example, json_example, example_name
):
    doc = json.loads(json.dumps(parse(example(example_name)), default=json_serial))
    json_doc = json.loads(json_example(example_name))

    assert doc == json_doc


@pytest.mark.parametrize(
    "example_name,error",
    [
        ("section_with_trailing_characters", UnexpectedCharError),
        ("key_value_with_trailing_chars", UnexpectedCharError),
        ("array_with_invalid_chars", UnexpectedCharError),
        ("invalid_number", InvalidNumberError),
        ("invalid_date", InvalidDateError),
        ("invalid_time", InvalidTimeError),
        ("invalid_datetime", InvalidDateTimeError),
        ("trailing_comma", UnexpectedCharError),
        ("newline_in_singleline_string", InvalidControlChar),
        ("string_slash_whitespace_char", InvalidCharInStringError),
        ("array_no_comma", UnexpectedCharError),
        ("array_duplicate_comma", UnexpectedCharError),
        ("array_leading_comma", UnexpectedCharError),
        ("inline_table_no_comma", UnexpectedCharError),
        ("inline_table_duplicate_comma", UnexpectedCharError),
        ("inline_table_leading_comma", UnexpectedCharError),
        ("inline_table_trailing_comma", UnexpectedCharError),
    ],
)
def test_parse_raises_errors_for_invalid_toml_files(
    invalid_example, error, example_name
):
    with pytest.raises(error):
        parse(invalid_example(example_name))


@pytest.mark.parametrize(
    "example_name",
    [
        "example",
        "fruit",
        "hard",
        "sections_with_same_start",
        "pyproject",
        "0.5.0",
        "test",
        "table_names",
    ],
)
def test_original_string_and_dumped_string_are_equal(example, example_name):
    content = example(example_name)
    parsed = parse(content)

    assert content == dumps(parsed)


def test_a_raw_dict_can_be_dumped():
    s = dumps({"foo": "bar"})

    assert s == 'foo = "bar"\n'


def test_mapping_types_can_be_dumped():
    x = MappingProxyType({"foo": "bar"})
    assert dumps(x) == 'foo = "bar"\n'


def test_dumps_weird_object():
    with pytest.raises(TypeError):
        dumps(object())


def test_dump_tuple_value_as_array():
    x = {"foo": (1, 2)}
    assert dumps(x) == "foo = [1, 2]\n"

    x = {"foo": ({"a": 1}, {"a": 2})}
    assert dumps(x) == "[[foo]]\na = 1\n\n[[foo]]\na = 2\n"


def test_dump_to_file_object():
    doc = {"foo": "bar"}
    fp = io.StringIO()
    dump(doc, fp)
    assert fp.getvalue() == 'foo = "bar"\n'


def test_integer():
    i = tomlkit.integer("34")

    assert isinstance(i, Integer)


def test_float():
    i = tomlkit.float_("34.56")

    assert isinstance(i, Float)


def test_boolean():
    i = tomlkit.boolean("true")

    assert isinstance(i, Bool)


def test_date():
    dt = tomlkit.date("1979-05-13")

    assert isinstance(dt, Date)

    with pytest.raises(ValueError):
        tomlkit.date("12:34:56")


def test_time():
    dt = tomlkit.time("12:34:56")

    assert isinstance(dt, Time)

    with pytest.raises(ValueError):
        tomlkit.time("1979-05-13")


def test_datetime():
    dt = tomlkit.datetime("1979-05-13T12:34:56")

    assert isinstance(dt, DateTime)

    with pytest.raises(ValueError):
        tomlkit.time("1979-05-13")


def test_array():
    a = tomlkit.array()

    assert isinstance(a, Array)

    a = tomlkit.array("[1,2, 3]")

    assert isinstance(a, Array)


def test_table():
    t = tomlkit.table()

    assert isinstance(t, Table)


def test_inline_table():
    t = tomlkit.inline_table()

    assert isinstance(t, InlineTable)


def test_aot():
    t = tomlkit.aot()

    assert isinstance(t, AoT)


def test_key():
    k = tomlkit.key("foo")

    assert isinstance(k, Key)


def test_key_value():
    k, i = tomlkit.key_value("foo = 12")

    assert isinstance(k, Key)
    assert isinstance(i, Integer)


def test_string():
    s = tomlkit.string('foo "')

    assert s.value == 'foo "'
    assert s.as_string() == '"foo \\""'


def test_item_dict_to_table():
    t = tomlkit.item({"foo": {"bar": "baz"}})

    assert t.value == {"foo": {"bar": "baz"}}
    assert (
        t.as_string()
        == """[foo]
bar = "baz"
"""
    )


def test_item_mixed_aray():
    example = [{"a": 3}, "b", 42]
    expected = '[{a = 3}, "b", 42]'
    t = tomlkit.item(example)
    assert t.as_string().strip() == expected
    assert dumps({"x": {"y": example}}).strip() == "[x]\ny = " + expected


def test_build_super_table():
    doc = tomlkit.document()
    table = tomlkit.table(True)
    table.add("bar", {"x": 1})
    doc.add("foo", table)
    assert doc.as_string() == "[foo.bar]\nx = 1\n"


def test_add_dotted_key():
    doc = tomlkit.document()
    doc.add(tomlkit.key(["foo", "bar"]), 1)
    assert doc.as_string() == "foo.bar = 1\n"

    table = tomlkit.table()
    table.add(tomlkit.key(["foo", "bar"]), 1)
    assert table.as_string() == "foo.bar = 1\n"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("false", False),
    ],
)
def test_value_parses_boolean(raw, expected):
    parsed = tomlkit.value(raw)
    assert parsed == expected


@pytest.mark.parametrize(
    "raw", ["t", "f", "tru", "fals", "test", "friend", "truthy", "falsify"]
)
def test_value_rejects_values_looking_like_bool_at_start(raw):
    """Reproduces https://github.com/sdispater/tomlkit/issues/165"""
    with pytest.raises(tomlkit.exceptions.ParseError):
        tomlkit.value(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "truee",
        "truely",
        "true-thoughts",
        "true_hip_hop",
    ],
)
def test_value_rejects_values_having_true_prefix(raw):
    """Values that have ``true`` or ``false`` as prefix but then have additional chars are rejected."""
    with pytest.raises(tomlkit.exceptions.ParseError):
        tomlkit.value(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "falsee",
        "falsely",
        "false-ideas",
        "false_prophet",
    ],
)
def test_value_rejects_values_having_false_prefix(raw):
    """Values that have ``true`` or ``false`` as prefix but then have additional chars are rejected."""
    with pytest.raises(tomlkit.exceptions.ParseError):
        tomlkit.value(raw)


@pytest.mark.parametrize(
    "raw",
    [
        '"foo"1.2',
        "truefalse",
        "1.0false",
        "100true",
        "truetrue",
        "falsefalse",
        "1.2.3.4",
        "[][]",
        "{a=[][]}[]",
        "true[]",
        "false{a=1}",
    ],
)
def test_value_rejects_values_with_appendage(raw):
    """Values that appear valid at the beginning but leave chars unparsed are rejected."""
    with pytest.raises(tomlkit.exceptions.ParseError):
        tomlkit.value(raw)


def test_create_super_table_with_table():
    data = {"foo": {"bar": {"a": 1}}}
    assert dumps(data) == "[foo.bar]\na = 1\n"


def test_create_super_table_with_aot():
    data = {"foo": {"bar": [{"a": 1}]}}
    assert dumps(data) == "[[foo.bar]]\na = 1\n"


@pytest.mark.parametrize(
    "kwargs, example, expected",
    [
        ({}, "My\nString", '"My\\nString"'),
        ({"escape": False}, "My String\t", '"My String\t"'),
        ({"literal": True}, "My String\t", "'My String\t'"),
        ({"escape": True, "literal": True}, "My String\t", "'My String\t'"),
        ({}, "My String\u0001", '"My String\\u0001"'),
        ({}, "My String\u000b", '"My String\\u000b"'),
        ({}, "My String\x08", '"My String\\b"'),
        ({}, "My String\x0c", '"My String\\f"'),
        ({}, "My String\x01", '"My String\\u0001"'),
        ({}, "My String\x06", '"My String\\u0006"'),
        ({}, "My String\x12", '"My String\\u0012"'),
        ({}, "My String\x7f", '"My String\\u007f"'),
        ({"escape": False}, "My String\u0001", '"My String\u0001"'),
        ({"multiline": True}, "\nMy\nString\n", '"""\nMy\nString\n"""'),
        ({"multiline": True}, 'My"String', '"""My"String"""'),
        ({"multiline": True}, 'My""String', '"""My""String"""'),
        ({"multiline": True}, 'My"""String', '"""My""\\"String"""'),
        ({"multiline": True}, 'My""""String', '"""My""\\""String"""'),
        (
            {"multiline": True},
            '"""My"""Str"""ing"""',
            '"""""\\"My""\\"Str""\\"ing""\\""""',
        ),
        ({"multiline": True, "literal": True}, "My\nString", "'''My\nString'''"),
        ({"multiline": True, "literal": True}, "My'String", "'''My'String'''"),
        ({"multiline": True, "literal": True}, "My\r\nString", "'''My\r\nString'''"),
        (
            {"literal": True},
            r"C:\Users\nodejs\templates",
            r"'C:\Users\nodejs\templates'",
        ),
        ({"literal": True}, r"<\i\c*\s*>", r"'<\i\c*\s*>'"),
        (
            {"multiline": True, "literal": True},
            r"I [dw]on't need \d{2} apples",
            r"'''I [dw]on't need \d{2} apples'''",
        ),
    ],
)
def test_create_string(kwargs, example, expected):
    value = tomlkit.string(example, **kwargs)
    assert value.as_string() == expected


@pytest.mark.parametrize(
    "kwargs, example",
    [
        ({"literal": True}, "My'String"),
        ({"literal": True}, "My\nString"),
        ({"literal": True}, "My\r\nString"),
        ({"literal": True}, "My\bString"),
        ({"literal": True}, "My\x08String"),
        ({"literal": True}, "My\x0cString"),
        ({"literal": True}, "My\x7fString"),
        ({"multiline": True, "literal": True}, "My'''String"),
    ],
)
def test_create_string_with_invalid_characters(kwargs, example):
    with pytest.raises(InvalidStringError):
        tomlkit.string(example, **kwargs)


def test_parse_empty_quoted_table_name():
    content = "['']\nx = 1\n"
    parsed = loads(content)
    assert parsed == {"": {"x": 1}}
    assert dumps(parsed) == content
```