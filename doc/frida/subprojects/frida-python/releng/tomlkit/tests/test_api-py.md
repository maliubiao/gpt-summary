Response:
Let's break down the thought process for analyzing this Python code.

**1. Understanding the Goal:**

The primary request is to analyze a Python file (`test_api.py`) from the `tomlkit` library, a TOML parser and serializer. The focus is on its *functionality* and how it relates to broader concepts like reverse engineering, low-level details, logic, user errors, and debugging.

**2. Initial Skim and Keyword Recognition:**

A quick read-through reveals several key aspects:

* **Testing Framework (pytest):** The `@pytest.mark.parametrize` decorator is a strong indicator of a testing file. This means the code's primary function is to verify the behavior of other parts of the `tomlkit` library.
* **TOML Handling:** The code imports and uses `tomlkit` functions like `parse`, `loads`, `dump`, `dumps`, `load`. It also deals with TOML data structures like `Table`, `Array`, `Integer`, etc. This confirms the library's core purpose.
* **Error Handling:**  Imports like `InvalidCharInStringError`, `UnexpectedCharError`, etc., and the use of `pytest.raises` suggest the code tests how `tomlkit` handles invalid TOML.
* **Example Files:** References to `example` and `invalid_example` functions and the use of file paths like `os.path.join(os.path.dirname(__file__), "examples", ...)` point to the existence of external TOML example files for testing.
* **JSON Conversion:** The `json_serial` function and the tests involving `json.dumps` indicate that the tests also verify the ability to represent TOML data as JSON.

**3. Deeper Dive into Functionality (By Category):**

Now, let's address each part of the request systematically.

* **Core Functionality:** The tests primarily focus on:
    * **Parsing Valid TOML:**  Testing `parse` and `loads` with various valid TOML examples.
    * **Loading from Files:** Testing `load` to ensure it can read TOML from file objects.
    * **JSON Representation:** Verifying that parsed TOML can be correctly converted to JSON and back.
    * **Handling Invalid TOML:**  Testing `parse` with invalid TOML examples and ensuring the expected exceptions are raised.
    * **Dumping TOML:** Testing `dumps` to convert TOML data structures back into string format and verifying that the dumped output matches the original input.
    * **Dumping Various Data Types:** Testing `dumps` with dictionaries, `MappingProxyType`, and tuples.
    * **Creating TOML Elements:** Testing the creation of specific TOML elements like `Integer`, `Float`, `Array`, `Table`, etc., using `tomlkit.integer()`, `tomlkit.array()`, etc.
    * **String Handling:** Testing different ways to create and represent strings, including escaping, literals, and multiline strings.

* **Relationship to Reverse Engineering:** This requires thinking about how a tool like `tomlkit` might be used in a reverse engineering context.
    * **Configuration Files:**  Applications and libraries often use configuration files in TOML format. Reverse engineers might need to parse these files to understand an application's settings or behavior.
    * **Data Analysis:** TOML might be used to store data that a reverse engineer needs to examine.
    * **Dynamic Analysis (Frida Context):** Given the file path `frida/subprojects/frida-python/releng/tomlkit/tests/test_api.py`,  the connection to Frida is crucial. Frida allows inspecting and manipulating the runtime behavior of processes. A reverse engineer using Frida might encounter TOML configuration within a target process and need to parse it.

* **Binary/Low-Level/Kernel/Framework:** This requires considering if the *testing* code itself interacts with these low-level aspects. In this case, it doesn't directly manipulate memory, interact with system calls, or delve into kernel structures. However, the *library being tested* (`tomlkit`) might have underlying implementations that touch on these areas (e.g., character encoding, memory allocation), even if the tests don't directly expose that. The connection to Android is less direct from this specific test file, but if the Frida context involves Android app analysis, the TOML files could relate to app configuration.

* **Logic and Assumptions:**  The testing logic is primarily based on the assumption that for valid TOML, parsing and then dumping should result in the original string. For invalid TOML, specific exceptions should be raised. Input/output examples are straightforward based on the test cases.

* **User Errors:** The tests that check for `UnexpectedCharError`, `InvalidNumberError`, etc., directly demonstrate common user errors when writing TOML. Examples include missing commas, invalid characters, incorrect date/time formats, etc.

* **Debugging Trace:**  The file path itself provides a strong hint. A developer working on Frida's Python bindings who is using `tomlkit` might have encountered an issue while parsing TOML. To debug this, they would likely write unit tests like these to isolate and verify the behavior of the parsing logic. The steps involve: writing TOML, attempting to parse it, encountering an error, and then creating a test case to reproduce and fix the error.

**4. Structuring the Answer:**

Organize the findings into clear categories as requested in the prompt:

* **Functionality:** List the primary actions the code performs.
* **Relationship to Reverse Engineering:** Explain the potential use cases in reverse engineering, especially within the Frida context.
* **Binary/Low-Level/Kernel/Framework:**  Acknowledge the indirect connection and explain where the underlying library *might* touch on these.
* **Logic and Assumptions:** Describe the core testing logic and provide input/output examples.
* **User Errors:** Give concrete examples of common TOML syntax errors that the tests catch.
* **Debugging Trace:** Explain how a developer would arrive at this test file during a debugging process.

**5. Refinement and Clarity:**

Review the generated answer for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. For instance, when discussing user errors, provide specific examples of invalid TOML. Make sure the connection to Frida is explicitly addressed, given the file path.

By following this systematic process, combining code analysis with an understanding of the broader context (reverse engineering, Frida, TOML), one can effectively analyze and explain the functionality of the provided Python code.
这个Python源代码文件 `test_api.py` 是 `tomlkit` 库的测试文件。`tomlkit` 是一个用于解析和生成 TOML (Tom's Obvious, Minimal Language) 格式的库。 该测试文件的主要功能是验证 `tomlkit` 库的 API（Application Programming Interface）的各种功能是否按预期工作。

以下是该文件的详细功能列表：

**核心功能测试:**

1. **解析有效的 TOML 文件和字符串:**
   - 使用 `@pytest.mark.parametrize` 装饰器，测试 `parse()` 和 `loads()` 函数是否能够正确解析多个有效的 TOML 示例文件和字符串。
   - 验证解析结果是否为 `TOMLDocument` 类型的对象。
   - **举例说明:** 测试用例 `test_parse_can_parse_valid_toml_files` 和 `test_load_from_file_object` 涵盖了多种 TOML 语法，例如基本的键值对、表格、数组、内联表格等。

2. **从文件对象加载 TOML:**
   - 测试 `load()` 函数是否能够从打开的文件对象中正确加载 TOML 数据。

3. **将解析后的 TOML 文档转换为 JSON:**
   - 测试解析后的 `TOMLDocument` 对象是否可以正确地使用 `json.dumps()` 进行 JSON 序列化。
   - 定义了一个自定义的 JSON 序列化函数 `json_serial()` 来处理 `datetime`, `date`, `time` 对象。
   - **举例说明:** 测试用例 `test_parsed_document_are_properly_json_representable` 验证了 TOML 数据转换为 JSON 后的结构和内容是否与预期的 JSON 结构一致。

4. **处理无效的 TOML 文件和字符串并抛出异常:**
   - 使用 `@pytest.mark.parametrize` 装饰器，测试 `parse()` 函数在遇到各种无效的 TOML 语法时是否会抛出预期的异常，例如 `UnexpectedCharError`, `InvalidNumberError`, `InvalidDateError` 等。
   - **举例说明:** 测试用例 `test_parse_raises_errors_for_invalid_toml_files` 列举了各种不合法的 TOML 语法，例如尾随字符、无效数字、无效日期、缺少逗号等，并验证 `parse()` 函数是否会抛出相应的异常。

5. **验证原始字符串与转储后的字符串是否一致:**
   - 测试 `dumps()` 函数是否能够将解析后的 `TOMLDocument` 对象转换回与原始 TOML 字符串相同的格式。这有助于验证格式化和保留注释等信息的能力。

6. **转储各种 Python 数据结构为 TOML 字符串:**
   - 测试 `dumps()` 函数是否能够将 Python 字典、`MappingProxyType` 对象以及包含元组的字典等数据结构转换为有效的 TOML 字符串。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `{"foo": "bar"}`
     - **输出:** `'foo = "bar"\n'`
     - **假设输入:** `MappingProxyType({"foo": "bar"})`
     - **输出:** `'foo = "bar"\n'`
     - **假设输入:** `{"foo": (1, 2)}`
     - **输出:** `'foo = [1, 2]\n'`
     - **假设输入:** `{"foo": ({"a": 1}, {"a": 2})}`
     - **输出:** `'[[foo]]\na = 1\n\n[[foo]]\na = 2\n'`

7. **将 TOML 数据转储到文件对象:**
   - 测试 `dump()` 函数是否能够将 TOML 数据写入到文件对象中。

8. **创建各种 TOML 数据类型对象:**
   - 测试 `tomlkit` 模块提供的用于创建特定 TOML 数据类型对象的函数，例如 `integer()`, `float_()`, `boolean()`, `date()`, `time()`, `datetime()`, `array()`, `table()`, `inline_table()`, `aot()` (Array of Tables), `key()`, `key_value()`, `string()`, `item()` 等。
   - 验证创建的对象是否是预期的类型。
   - **举例说明:** 测试用例 `test_integer`, `test_float`, `test_boolean` 等分别测试了创建整数、浮点数和布尔值对象的功能。

9. **测试 `string()` 函数的各种选项:**
   - 测试 `tomlkit.string()` 函数的 `escape`, `literal`, `multiline` 等参数，验证它们是否能够按照预期生成不同格式的 TOML 字符串。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `tomlkit.string("My\nString")`
     - **输出:** `'"My\\nString"'`
     - **假设输入:** `tomlkit.string("My String\t", escape=False)`
     - **输出:** `'"My String\t"'`
     - **假设输入:** `tomlkit.string("My String\t", literal=True)`
     - **输出:** `"'My String\t'"`
     - **假设输入:** `tomlkit.string("\nMy\nString\n", multiline=True)`
     - **输出:** `'''\nMy\nString\n'''`

10. **测试 `value()` 函数解析布尔值:**
    - 测试 `tomlkit.value()` 函数是否能够正确解析字符串形式的布尔值 (`"true"` 和 `"false"`)。
    - 同时测试了 `value()` 函数对于看起来像布尔值但实际上不是的字符串的处理，确保它会抛出异常。

11. **测试创建带有点号的键的表格:**
    - 验证是否可以使用点号分隔的键来创建嵌套的表格结构。

12. **测试创建超级表格 (Super Table):**
    - 测试通过嵌套的字典或 Array of Tables 来创建 TOML 中的隐式表格结构。

**与逆向方法的关联:**

尽管这个测试文件本身不直接涉及二进制操作或内存级别的逆向，但 `tomlkit` 库在逆向工程中可能会被使用，原因如下：

- **配置文件解析:** 许多应用程序，特别是用 Python 编写的，可能会使用 TOML 文件作为配置文件。逆向工程师需要解析这些配置文件来理解应用程序的设置和行为。例如，一个 Android 应用的后台服务可能使用 TOML 来配置其运行参数。使用 Frida 动态分析该服务时，可能需要解析其 TOML 配置文件来了解其工作方式。
- **数据格式:** 有些自定义的通信协议或数据存储格式可能会使用类似 TOML 的结构。逆向工程师可能需要编写脚本来解析这些数据。

**二进制底层、Linux、Android 内核及框架的知识:**

这个测试文件本身没有直接涉及到这些底层知识。但是，`tomlkit` 库在某些场景下可能会间接地与这些知识产生联系：

- **字符编码:** TOML 规范定义了使用 UTF-8 编码。`tomlkit` 库需要处理字符编码，这在跨平台和处理不同语言的文本时很重要，与底层操作系统处理字符的方式有关。
- **文件操作:** `load()` 和 `dump()` 函数涉及到文件 I/O 操作，这依赖于操作系统提供的文件系统 API，例如 Linux 的 `open()`, `read()`, `write()` 等系统调用。在 Android 上，这些操作会通过 Android 的框架层与 Linux 内核交互。
- **内存管理:**  虽然测试代码没有显式地操作内存，但 `tomlkit` 库在解析和生成 TOML 数据时，会在内存中创建和管理数据结构。

**逻辑推理 (更复杂的例子):**

- **假设输入 (TOML 字符串):**
  ```toml
  [package]
  name = "my-package"
  version = "1.2.3"

  [dependencies]
  requests = "2.28.1"
  ```
- **预期输出 (解析后的 Python 字典):**
  ```python
  {
      'package': {'name': 'my-package', 'version': '1.2.3'},
      'dependencies': {'requests': '2.28.1'}
  }
  ```
  测试用例验证了 `parse()` 或 `loads()` 函数是否能将上述 TOML 字符串正确地解析成这样的 Python 字典结构。

**用户或编程常见的使用错误:**

- **拼写错误或语法错误:** 用户在编写 TOML 文件时可能会犯拼写错误或违反 TOML 语法规则，例如缺少引号、逗号、等号等。测试用例中 `test_parse_raises_errors_for_invalid_toml_files` 就覆盖了这些常见错误。
  - **举例说明:**
    - 错误的 TOML: `name = my-package` (缺少字符串引号)
    - `tomlkit` 会抛出 `InvalidStringError` 或类似的异常。
    - 错误的 TOML: `[section  ]` (section 名称中包含尾随空格)
    - `tomlkit` 会抛出 `UnexpectedCharError`。
    - 错误的 TOML: `array = [1, 2,]` (尾随逗号)
    - `tomlkit` 会抛出 `UnexpectedCharError`。
- **尝试解析非 TOML 格式的文本:** 用户可能会错误地尝试使用 `tomlkit` 解析其他格式的文本文件。
  - **举例说明:** 如果用户尝试用 `tomlkit.parse()` 解析一个 JSON 文件，会因为不符合 TOML 语法而抛出异常。
- **假设 TOML 结构固定不变:**  在编程中，如果代码假设 TOML 文件的结构是固定的，但实际文件结构发生了变化，可能会导致解析错误或程序逻辑错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发人员或测试人员，要到达这个测试文件并运行它，通常的步骤如下：

1. **获取 `tomlkit` 源代码:**  开发者从 GitHub 仓库克隆了 `frida` 项目，其中包含了 `tomlkit` 作为子项目。
2. **安装开发依赖:** 为了运行测试，需要安装 `tomlkit` 的开发依赖，通常使用 `pip install -e .[dev]` 在 `frida/subprojects/frida-python/releng/tomlkit` 目录下执行。
3. **运行测试:** 使用 `pytest` 命令在 `frida/subprojects/frida-python/releng/tomlkit/tests/` 目录下运行测试。`pytest` 会自动发现并执行 `test_api.py` 文件中的测试用例。
4. **遇到 Bug 或需要添加新功能:**
   - 如果在开发或使用 `tomlkit` 的过程中发现了解析 TOML 时的错误，开发者会编写一个新的测试用例来重现这个 bug，并将该测试添加到 `test_api.py` 中。
   - 如果需要添加新的功能，例如支持新的 TOML 语法或选项，开发者也会编写相应的测试用例来验证新功能的正确性。
5. **调试测试用例:** 如果某个测试用例失败，开发者会使用调试器（例如 `pdb` 或 IDE 的调试功能）来逐步执行测试代码，查看变量的值，分析失败的原因。他们可能会在 `test_api.py` 文件中设置断点，以便更深入地了解 `tomlkit` 的行为。
6. **查看现有的测试用例作为参考:**  当需要理解 `tomlkit` API 的使用方式或如何测试某个特定功能时，开发者会查看 `test_api.py` 中的现有测试用例作为示例。

总而言之，`test_api.py` 是 `tomlkit` 库的核心测试文件，它全面地测试了库的各种 API 功能，确保了 `tomlkit` 能够正确地解析和生成 TOML 数据，并且能够处理各种有效的和无效的 TOML 格式。对于逆向工程师来说，了解如何使用 `tomlkit` 以及其测试用例，有助于他们在分析使用 TOML 配置文件的应用程序时更加高效。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/tomlkit/tests/test_api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```