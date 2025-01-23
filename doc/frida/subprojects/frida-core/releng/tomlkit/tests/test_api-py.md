Response:
Let's break down the thought process for analyzing the provided Python code for `test_api.py`.

**1. Initial Understanding - The Core Purpose:**

The filename "test_api.py" immediately suggests this is a test file. Combined with the directory path `frida/subprojects/frida-core/releng/tomlkit/tests/`, it becomes clear that this file tests the API of a Python library named "tomlkit". Tomlkit, judging by the name, likely deals with TOML (Tom's Obvious, Minimal Language) files.

**2. Identifying Key Functionality - Imports and Test Structure:**

* **Imports:** The `import` statements reveal the main functionalities being tested. We see imports from `datetime`, `types`, `pytest`, `tomlkit` itself, and specific exceptions from `tomlkit.exceptions`. This tells us the tests cover parsing, dumping (serializing), and handling errors related to TOML. The presence of `json` suggests the library also supports or interacts with JSON.
* **`pytest`:**  The use of `@pytest.mark.parametrize` is a strong indicator of parameterization in the tests, meaning the same test function is run with different inputs. This is efficient for testing various scenarios.
* **Test Function Names:**  Function names like `test_parse_can_parse_valid_toml_files`, `test_load_from_file_object`, `test_parse_raises_errors_for_invalid_toml_files`, `test_original_string_and_dumped_string_are_equal`, and similar, clearly describe the aspect of the API being tested.

**3. Detailed Analysis of Key Areas:**

Now, let's delve deeper into the code, focusing on the specific instructions in the prompt:

* **Functionality Listing:** Go through each test function and describe what it checks. Focus on the core action (parsing, dumping, loading, etc.) and the expected outcome (success, error, equality, etc.).

* **Relationship to Reverse Engineering:** This requires connecting the *purpose* of TOML and Frida with reverse engineering concepts. TOML is often used for configuration. Frida is a dynamic instrumentation tool. Therefore, a TOML parser is likely used by Frida to read configuration files that control its behavior during reverse engineering sessions. Think about *what* those configurations might be (target process names, scripts to inject, etc.).

* **Binary/Kernel/Android Relevance:**  Consider how configuration might relate to these areas. For example, Frida on Android might need configuration specifying which processes to attach to, which often involves process names or IDs (which are OS-level concepts). While this *specific* test file doesn't directly manipulate binaries or kernel structures, it's a *dependency* for Frida's ability to interact with them.

* **Logical Reasoning (Input/Output):** Look at the `@pytest.mark.parametrize` decorators. These explicitly define the inputs and, in some cases, the expected outputs (like the JSON representable tests). For error cases, the expected output is the *type* of exception.

* **User/Programming Errors:**  The tests for invalid TOML (`test_parse_raises_errors_for_invalid_toml_files`) directly address this. Analyze the specific error types being tested (e.g., `UnexpectedCharError`, `InvalidNumberError`). These represent common mistakes users might make when writing TOML.

* **User Journey/Debugging Clues:**  Imagine a user trying to use Frida. They might create a configuration file. If that file has syntax errors, the `tomlkit` library (being tested here) will be the first point of failure, raising an exception. This test file ensures those exceptions are raised correctly and provide useful information. Think about the steps a developer takes: writing code, running tests, debugging errors.

**4. Structuring the Answer:**

Organize the findings logically, mirroring the prompt's requirements. Use clear headings and bullet points for readability. Provide concrete examples where requested (e.g., for reverse engineering scenarios, user errors).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just testing a TOML parser."
* **Correction:** "It's testing a TOML parser *used by Frida*. This connection is important for the reverse engineering aspect."
* **Initial thought:** "The tests just check if parsing works."
* **Refinement:** "They also check for error handling, JSON representation, and that the dumped output matches the input, indicating correctness and data integrity."
* **Thinking about user journey:**  Initially focused on the code itself. Then considered: "How does a *user* interact with Frida and potentially encounter this code?" This leads to the configuration file scenario.

By following this structured approach, analyzing the code, connecting it to the broader context of Frida, and considering the user perspective, a comprehensive and accurate answer can be generated.
这是 `frida/subprojects/frida-core/releng/tomlkit/tests/test_api.py` 文件的源代码，它属于 Frida 动态 instrumentation 工具的 tomlkit 子项目。`tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。这个测试文件 `test_api.py` 的主要目的是测试 `tomlkit` 库的公共 API 的功能是否正常。

**以下是该文件的功能列表：**

1. **解析有效的 TOML 文件 (`test_parse_can_parse_valid_toml_files`, `test_load_from_file_object`):**
   - 测试 `tomlkit.parse()` 和 `tomlkit.loads()` 函数是否能够正确地解析各种有效的 TOML 文件内容（从字符串或文件对象中读取）。
   - 使用 `@pytest.mark.parametrize` 装饰器来对多个示例 TOML 文件进行测试。
   - 断言解析结果是 `tomlkit.toml_document.TOMLDocument` 类型的对象。
   - 测试 `tomlkit.load()` 函数是否能从文件对象中正确加载 TOML 数据。

2. **将解析的 TOML 文档转换为 JSON (`test_parsed_document_are_properly_json_representable`):**
   - 测试 `tomlkit` 解析的 TOML 文档是否可以正确地转换为 JSON 格式。
   - 使用 `json.dumps()` 和自定义的 `json_serial` 函数来处理 `datetime`, `date`, `time` 等 TOML 特有的数据类型。
   - 比对 `tomlkit` 解析后转化的 JSON 和预期的 JSON 结果。

3. **处理无效的 TOML 文件 (`test_parse_raises_errors_for_invalid_toml_files`):**
   - 测试 `tomlkit.parse()` 函数在遇到格式错误的 TOML 文件时是否会抛出预期的异常。
   - 使用 `@pytest.mark.parametrize` 装饰器来测试各种类型的无效 TOML 语法，并断言抛出的异常类型是否正确 (例如 `UnexpectedCharError`, `InvalidNumberError` 等)。

4. **保持 TOML 内容的完整性 (`test_original_string_and_dumped_string_are_equal`):**
   - 测试 `tomlkit.dumps()` 函数是否能够将解析后的 TOML 文档重新序列化为与原始字符串内容相同的 TOML 格式。这验证了库在解析和生成过程中不会丢失或修改信息。

5. **导出 (dump) Python 数据结构为 TOML 字符串 (`test_a_raw_dict_can_be_dumped`, `test_mapping_types_can_be_dumped`, `test_dumps_weird_object`, `test_dump_tuple_value_as_array`):**
   - 测试 `tomlkit.dumps()` 函数是否能够将 Python 的字典 (包括 `MappingProxyType`) 和其他数据结构转换为 TOML 格式的字符串。
   - 针对不支持导出的对象类型，测试是否会抛出 `TypeError`。
   - 测试元组类型的值在导出时是否被正确处理为 TOML 的数组。

6. **导出 TOML 数据到文件对象 (`test_dump_to_file_object`):**
   - 测试 `tomlkit.dump()` 函数是否能够将 TOML 数据写入到文件对象中。

7. **创建和操作 TOML 数据类型的对象 (`test_integer` 到 `test_key_value`):**
   - 测试 `tomlkit` 库提供的用于创建不同 TOML 数据类型 (如 `Integer`, `Float`, `Bool`, `Date`, `Time`, `DateTime`, `Array`, `Table`, `InlineTable`, `AoT`, `Key`) 的工厂函数。
   - 断言创建的对象是期望的类型。
   - 对于 `Date`, `Time`, `DateTime` 等类型，测试了传入错误格式字符串时是否会抛出 `ValueError`。

8. **操作和格式化字符串 (`test_string`, `test_create_string`, `test_create_string_with_invalid_characters`):**
   - 测试 `tomlkit.string()` 函数的创建和格式化功能，包括转义字符、多行字符串、字面量字符串等。
   - 测试当使用 `literal=True` 时，如果字符串包含不允许的字符（如换行符），是否会抛出 `InvalidStringError`。

9. **构建复杂的 TOML 结构 (`test_item_dict_to_table`, `test_item_mixed_aray`, `test_build_super_table`, `test_add_dotted_key`, `test_create_super_table_with_table`, `test_create_super_table_with_aot`):**
   - 测试如何使用 `tomlkit` 的 API 来构建更复杂的 TOML 结构，例如表 (table) 和数组表 (array of tables)。
   - 测试添加带点的键 (dotted key)。

10. **解析基本值 (`test_value_parses_boolean` 等):**
    - 测试 `tomlkit.value()` 函数是否能够正确解析基本的 TOML 值，例如布尔值。
    - 重点测试了对看起来像布尔值但实际不是的字符串的处理，以及对带有后缀的有效值的处理，确保解析的准确性并避免歧义。

11. **处理空的带引号的表名 (`test_parse_empty_quoted_table_name`):**
    - 测试 `tomlkit` 是否能够正确解析和导出带有空字符串引号的表名。

**与逆向方法的关系举例说明：**

Frida 是一个动态 instrumentation 工具，常用于逆向工程、安全研究和漏洞分析。TOML 作为一种易读易写的配置文件格式，可以用于配置 Frida 的行为。

**例子：** 假设 Frida 的一个模块允许用户通过配置文件指定要 hook 的函数名和目标进程。这个配置文件可能使用 TOML 格式：

```toml
[target]
process_name = "com.example.app"

[hooks]
  [[hooks.functions]]
  name = "open"
  module = "libc.so"

  [[hooks.functions]]
  name = "read"
  module = "libc.so"
```

`tomlkit` 库在 Frida 内部就会被用来解析这个 TOML 配置文件，从而让 Frida 知道要 hook 哪些进程的哪些函数。`test_api.py` 中测试的解析功能确保了 Frida 能够正确理解用户的配置意图。例如，如果配置文件中 `process_name` 的值写成了 `com.example.app\n` (包含换行符)，`test_parse_raises_errors_for_invalid_toml_files` 中的 `newline_in_singleline_string` 测试就会覆盖这种情况，确保 `tomlkit` 能正确地抛出错误，防止 Frida 使用错误的配置。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明：**

虽然 `test_api.py` 本身没有直接操作二进制底层、内核或框架，但它所测试的 `tomlkit` 库是 Frida 的一个组成部分，而 Frida 的功能是与这些底层系统紧密相关的。

**例子：** 在 Android 逆向中，用户可能需要配置 Frida hook 系统服务中的特定函数。这些系统服务通常运行在特殊的进程中，并且函数的实现在底层的共享库中。TOML 配置文件可能会包含类似以下的配置：

```toml
[target]
process_name = "system_server"

[hooks]
  [[hooks.functions]]
  name = "getSystemService"
  module = "/system/lib64/libandroid_runtime.so"
```

这里的 `process_name` 指的是 Linux 进程名，`module` 指的是 Linux 下的共享库路径。`tomlkit` 需要能够正确解析这些信息，Frida 才能根据这些配置，在目标进程的内存空间中找到对应的函数地址并进行 hook 操作。如果 `test_api.py` 中的测试覆盖了各种可能的路径格式（例如绝对路径、相对路径、包含特殊字符的路径），就能保证 Frida 在处理实际的配置时不会因为 `tomlkit` 的解析错误而失败。

**逻辑推理的假设输入与输出举例：**

在 `test_parse_can_parse_valid_toml_files` 中，假设输入是一个包含以下内容的字符串：

```toml
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00-08:00
```

**假设输入：** 上述 TOML 字符串。

**预期输出：** 一个 `tomlkit.toml_document.TOMLDocument` 对象，其内容可以通过 Python 字典访问，例如 `parsed_doc['title']` 应该返回字符串 `"TOML Example"`，`parsed_doc['owner']['name']` 应该返回字符串 `"Tom Preston-Werner"`， `parsed_doc['owner']['dob']` 应该返回一个 `datetime` 对象。

**用户或编程常见的使用错误举例说明：**

`test_parse_raises_errors_for_invalid_toml_files` 专门测试了用户可能犯的错误。

**例子：** 用户在编写 TOML 配置文件时，可能会错误地在数组元素之间漏掉逗号：

```toml
fruits = [ "apple" "banana" "orange" ] # 缺少逗号
```

`test_api.py` 中名为 `array_no_comma` 的测试用例会使用类似的错误 TOML，并断言 `tomlkit.parse()` 会抛出 `UnexpectedCharError` 异常。这模拟了用户错误，并验证了 `tomlkit` 能够正确地识别并报告这种错误。

另一个例子是用户在字符串中使用了不允许的控制字符：

```toml
message = "Hello\nWorld" # 在单行字符串中使用换行符
```

`newline_in_singleline_string` 测试会验证 `tomlkit` 是否抛出 `InvalidControlChar` 异常。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户编写 Frida 脚本或配置：** 用户想要使用 Frida 对目标程序进行动态分析，可能会编写一个 Frida 脚本或者配置文件来指定需要 hook 的函数、替换的实现、需要监控的内存地址等等。

2. **Frida 加载配置：** 当 Frida 启动并开始执行时，如果用户提供了配置文件，Frida 内部的代码会读取这个配置文件。如果配置文件是 TOML 格式的，Frida 会调用 `tomlkit` 库来解析这个文件。

3. **`tomlkit` 解析 TOML：** Frida 内部会调用类似 `tomlkit.parse(config_content)` 或 `tomlkit.load(config_file)` 的函数，将 TOML 文件的内容传递给 `tomlkit`。

4. **`test_api.py` 的作用：** 在开发 `tomlkit` 库的过程中，为了确保 `tomlkit` 能够正确地解析各种合法的 TOML 文件，并且能够正确地识别和报告非法的 TOML 格式，开发者会编写像 `test_api.py` 这样的测试文件。

5. **调试线索：** 如果用户在使用 Frida 时遇到了配置加载错误，例如 Frida 报告配置文件格式不正确，那么开发者在调试 Frida 自身或 `tomlkit` 库时，就可以参考 `test_api.py` 中的测试用例。
   - 如果用户报告某个合法的 TOML 文件无法被 Frida 加载，开发者可以查看 `test_api.py` 中是否有类似的 TOML 结构被成功解析的测试用例，如果没有，可能需要在 `test_api.py` 中添加新的测试用例来覆盖这种情况，并在 `tomlkit` 中修复解析错误。
   - 如果用户报告某个非法的 TOML 文件没有被 Frida 识别出来，导致了意外的行为，开发者可以查看 `test_api.py` 中是否有针对类似错误语法的测试用例，确保 `tomlkit` 能够正确地抛出异常。

总而言之，`test_api.py` 是 `tomlkit` 库的单元测试文件，它通过各种测试用例来验证 `tomlkit` API 的功能是否正确，这直接关系到 Frida 是否能够正确地解析和处理 TOML 格式的配置文件，从而影响 Frida 的正常运行和用户的使用体验。 当 Frida 的开发者需要调试 TOML 解析相关的问题时，`test_api.py` 提供了一系列的测试案例作为参考和验证的手段。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/tomlkit/tests/test_api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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