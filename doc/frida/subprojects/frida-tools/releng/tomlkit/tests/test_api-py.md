Response:
My thought process to analyze the Python code and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the `test_api.py` file's functionality, specifically within the context of Frida and reverse engineering, while also touching on low-level concepts, logical reasoning, common errors, and debugging.

2. **Identify the Core Function:** The filename and the imports (`tomlkit`, `pytest`) immediately suggest this is a test suite for the `tomlkit` library. `tomlkit` is for parsing and generating TOML files.

3. **High-Level Functionality Summary:**  The primary function of this file is to **test the API of the `tomlkit` library**. This involves:
    * **Parsing valid TOML:**  Checking if `tomlkit` can correctly parse valid TOML files and strings.
    * **Loading TOML from files:**  Verifying file loading capabilities.
    * **JSON representability:** Ensuring parsed TOML can be converted to JSON and back.
    * **Error handling:** Testing if `tomlkit` correctly raises exceptions for invalid TOML.
    * **Dumping TOML:**  Confirming that `tomlkit` can serialize TOML back to strings and files.
    * **Creating TOML elements programmatically:** Testing the functions for creating various TOML data types (integers, floats, strings, arrays, tables, etc.).
    * **String manipulation and formatting:** Examining how `tomlkit` handles different string types and escaping.

4. **Reverse Engineering Relevance:**  Think about how TOML might be used in reverse engineering. Configuration files are a prime example. Frida, being a dynamic instrumentation framework, often interacts with applications that might use TOML for configuration. Therefore, the ability to parse and potentially modify TOML is valuable in a reverse engineering context.

5. **Low-Level/Kernel Relevance:**  TOML itself is a high-level format. Direct links to the Linux kernel or Android framework are unlikely. However,  consider *how* Frida uses TOML. Configuration for Frida scripts or settings for specific instrumentation tasks could be stored in TOML. While the *parsing* is done by `tomlkit`, the *use* of that configuration might affect low-level interactions (e.g., setting breakpoints, modifying memory).

6. **Logical Reasoning:** Look for tests that involve comparisons or transformations. The tests comparing the parsed TOML to JSON representations demonstrate a form of logical validation. The tests checking if the original TOML string matches the dumped string after parsing also involve a logical comparison.

7. **User/Programming Errors:** Focus on the negative test cases. The `test_parse_raises_errors_for_invalid_toml_files` section directly addresses common mistakes users might make when writing TOML.

8. **Debugging Context (User Journey):** Imagine a user using Frida. They might:
    * Write a Frida script that reads configuration from a TOML file.
    * Encounter an error when parsing the TOML.
    * Need to debug the TOML file's syntax.
    * The tests in this file act as checks that `tomlkit` correctly identifies these syntax errors, which aids the user in their debugging.

9. **Code Deep Dive (Iterative Refinement):**  Go through the code section by section, noting the specific functionalities being tested. Pay attention to the `@pytest.mark.parametrize` decorators, as they indicate multiple test cases for the same functionality.

10. **Structure the Answer:** Organize the findings into the categories requested: functionality, reverse engineering relevance, low-level relevance, logical reasoning, common errors, and debugging context. Provide concrete examples from the code where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a basic unit test file."
* **Correction:**  Realize that while it *is* a unit test, the library being tested (`tomlkit`) has indirect relevance to Frida and reverse engineering through configuration files.
* **Initial thought:** Focus heavily on kernel/low-level aspects.
* **Correction:**  Recognize that the direct link is weak. Shift focus to *how* Frida *uses* the output of a TOML parser.
* **Initial thought:**  List all the test cases individually.
* **Correction:** Group similar test cases under broader functionality descriptions for better clarity.

By following these steps and engaging in self-correction, I can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the request.
这是 `frida/subprojects/frida-tools/releng/tomlkit/tests/test_api.py` 文件的功能列表，以及它与逆向、底层知识、逻辑推理、用户错误和调试线索的关系：

**功能列表:**

该文件是 `tomlkit` 库的 API 测试套件，用于验证 `tomlkit` 库的各种功能是否正常工作。它主要测试以下方面：

1. **解析有效的 TOML 文件和字符串:**
   - 测试 `tomlkit.parse()` 和 `tomlkit.loads()` 函数是否能正确解析符合 TOML 规范的文件和字符串。
   - 使用 `pytest.mark.parametrize` 装饰器对多个有效的 TOML 示例文件进行测试。
   - 验证解析结果是否为 `tomlkit.toml_document.TOMLDocument` 类型的对象。

2. **从文件对象加载 TOML 数据:**
   - 测试 `tomlkit.load()` 函数是否能从打开的文件对象中正确加载 TOML 数据。

3. **解析后的 TOML 文档可以正确地转换为 JSON 格式:**
   - 测试解析后的 `TOMLDocument` 对象是否可以使用 `json.dumps()` 进行序列化，并能通过自定义的 `json_serial` 函数处理 `datetime`, `date`, `time` 等对象。
   - 将解析后的 TOML 数据与预期的 JSON 数据进行比较，验证转换的正确性。

4. **解析无效的 TOML 文件时会抛出预期的异常:**
   - 测试 `tomlkit.parse()` 函数在解析包含语法错误的 TOML 文件时是否会抛出相应的异常，例如 `UnexpectedCharError`, `InvalidNumberError`, `InvalidDateError` 等。
   - 使用 `pytest.raises()` 上下文管理器来断言是否抛出了预期的异常。

5. **原始 TOML 字符串和 dump 后的字符串相等:**
   - 测试使用 `tomlkit.dumps()` 将解析后的 `TOMLDocument` 对象转换回字符串时，是否与原始的 TOML 字符串内容一致，验证了序列化的保真度。

6. **可以直接 dump 原始的 Python 字典和 MappingProxyType 对象:**
   - 测试 `tomlkit.dumps()` 函数可以直接处理 Python 的字典和 `MappingProxyType` 对象，并将其转换为 TOML 格式的字符串。

7. **dump 无法处理的对象时会抛出 TypeError:**
   - 测试 `tomlkit.dumps()` 函数在尝试处理无法转换为 TOML 格式的对象时，是否会抛出 `TypeError`。

8. **将元组值 dump 为数组:**
   - 测试 `tomlkit.dumps()` 函数可以将 Python 的元组值转换为 TOML 的数组格式。

9. **将 TOML 数据 dump 到文件对象:**
   - 测试 `tomlkit.dump()` 函数可以将 TOML 数据写入到文件对象中。

10. **测试各种 TOML 数据类型的创建函数:**
    - 测试 `tomlkit.integer()`, `tomlkit.float_()`, `tomlkit.boolean()`, `tomlkit.date()`, `tomlkit.time()`, `tomlkit.datetime()`, `tomlkit.array()`, `tomlkit.table()`, `tomlkit.inline_table()`, `tomlkit.aot()`, `tomlkit.key()`, `tomlkit.key_value()`, `tomlkit.string()` 等函数是否能正确创建相应的 TOML 数据类型对象。
    - 针对日期、时间和日期时间类型，测试了无效的输入是否会抛出 `ValueError`。

11. **测试 `tomlkit.item()` 函数:**
    - 测试 `tomlkit.item()` 函数是否能根据传入的 Python 对象创建相应的 TOML item 对象，并能正确转换为字符串表示。

12. **构建超级表格 (Super Table):**
    - 测试如何使用 `tomlkit.document()` 和 `tomlkit.table(True)` 创建带有点号的表格名 (e.g., `[foo.bar]`)。

13. **添加带有点号的 Key:**
    - 测试如何使用 `tomlkit.key()` 函数创建带有点号的 Key，并将其添加到文档或表格中。

14. **测试 `tomlkit.value()` 函数:**
    - 测试 `tomlkit.value()` 函数是否能正确解析布尔值，并对看起来像布尔值但实际不是的字符串进行拒绝。
    - 测试 `tomlkit.value()` 函数是否会拒绝在有效值后附加字符的情况。

15. **创建带有嵌套表格和数组的 TOML 数据结构:**
    - 测试如何使用 `tomlkit` 创建包含嵌套表格 (使用字典) 和数组 (Array of Tables) 的复杂 TOML 数据结构。

16. **测试字符串的创建和格式化选项:**
    - 测试 `tomlkit.string()` 函数的各种参数，如 `escape`, `literal`, `multiline`，以及它们对字符串格式化的影响。
    - 测试使用 `literal` 参数创建字符串时，包含某些特殊字符会抛出 `InvalidStringError`。

17. **解析空的带引号的表格名:**
    - 测试 `tomlkit` 是否能正确解析和 dump 带有空的带引号的表格名 (e.g., `['']`)。

**与逆向的方法的关系及举例说明:**

TOML 格式常用于配置文件的编写。在逆向工程中，你可能会遇到应用程序使用 TOML 文件来存储其配置信息。`tomlkit` 库可以帮助你：

* **解析应用程序的配置文件:**  你可以使用 `tomlkit.load()` 或 `tomlkit.loads()` 读取并解析目标应用程序的 TOML 配置文件，了解其运行参数和设置。
    ```python
    import tomlkit

    # 假设 app.toml 是目标应用的配置文件
    with open("app.toml", "r") as f:
        config = tomlkit.load(f)

    # 访问配置信息
    api_key = config["api"]["key"]
    log_level = config["logging"]["level"]
    print(f"API Key: {api_key}, Log Level: {log_level}")
    ```
* **修改应用程序的配置文件 (用于测试或破解):**  在某些情况下，你可能需要修改应用程序的配置文件来改变其行为。你可以使用 `tomlkit` 加载配置，修改其中的值，然后使用 `tomlkit.dump()` 将修改后的配置写回文件。
    ```python
    import tomlkit

    with open("app.toml", "r") as f:
        config = tomlkit.load(f)

    # 修改配置
    config["logging"]["level"] = "DEBUG"

    with open("app_modified.toml", "w") as f:
        tomlkit.dump(config, f)
    ```
* **理解应用程序的配置结构:** 通过解析 TOML 文件，你可以更好地理解应用程序的配置结构和各个配置项的作用，这对于逆向分析非常有帮助。

**涉及到二进制底层, linux, android内核及框架的知识及举例说明:**

虽然 `tomlkit` 库本身是用于解析和生成 TOML 文本格式的，与二进制底层、内核等没有直接关系，但其解析的配置信息可能会影响到应用程序在这些层面的行为。例如：

* **Linux 系统服务配置:**  某些 Linux 系统服务可能使用 TOML 格式的配置文件。通过解析这些文件，你可以了解服务的启动参数、网络设置、权限控制等底层信息。
* **Android 应用配置:**  虽然 Android 应用更常见使用 XML 或 JSON 进行配置，但理论上也可以使用 TOML。如果遇到这种情况，`tomlkit` 可以帮助你理解应用的配置，例如权限请求、组件声明等。
* **Frida 脚本配置:** 在 Frida 脚本中，你可能会使用 TOML 文件来配置脚本的行为，例如需要 hook 的函数地址、要修改的内存地址等。这些配置会直接影响 Frida 与目标进程的底层交互。

**做了逻辑推理及假设输入与输出:**

测试代码中多处体现了逻辑推理，例如：

* **断言解析结果的类型:**  测试代码假设如果成功解析了 TOML，那么结果应该是 `TOMLDocument` 类型的对象。
    ```python
    def test_parse_can_parse_valid_toml_files(example, example_name):
        assert isinstance(parse(example(example_name)), TOMLDocument)
    ```
    **假设输入:** 一个有效的 TOML 字符串。
    **预期输出:** `tomlkit.toml_document.TOMLDocument` 类型的对象。

* **断言 dump 后的字符串与原始字符串一致:** 测试代码假设将解析后的 TOML 对象重新转换为字符串后，应该与原始字符串相同。
    ```python
    def test_original_string_and_dumped_string_are_equal(example, example_name):
        content = example(example_name)
        parsed = parse(content)
        assert content == dumps(parsed)
    ```
    **假设输入:** 一个有效的 TOML 字符串。
    **预期输出:**  与输入完全相同的 TOML 字符串。

* **断言解析无效 TOML 时抛出特定异常:** 测试代码假设当解析包含特定错误的 TOML 字符串时，会抛出预期的异常类型。
    ```python
    def test_parse_raises_errors_for_invalid_toml_files(invalid_example, error, example_name):
        with pytest.raises(error):
            parse(invalid_example(example_name))
    ```
    **假设输入:** 一个包含特定 TOML 语法错误的字符串 (例如，`section_with_trailing_characters`)。
    **预期输出:** 抛出 `UnexpectedCharError` 异常。

**涉及用户或者编程常见的使用错误及举例说明:**

测试代码通过测试解析无效的 TOML 示例，间接反映了用户或编程中可能出现的常见错误：

* **节标题后有多余字符:**  `section_with_trailing_characters` 测试用例模拟了用户在节标题 `[section]` 后添加了多余字符，例如 `[section]abc`。
* **键值对后有多余字符:** `key_value_with_trailing_chars` 测试用例模拟了用户在键值对 `key = "value"` 后添加了多余字符，例如 `key = "value"abc`。
* **数组中包含无效字符或缺少逗号:** `array_with_invalid_chars`, `array_no_comma`, `array_duplicate_comma`, `array_leading_comma` 等测试用例模拟了用户在定义数组时可能犯的错误，如包含非法字符、缺少逗号、逗号重复或出现在开头。
* **内联表格中缺少逗号或有多余逗号:** `inline_table_no_comma`, `inline_table_duplicate_comma`, `inline_table_leading_comma`, `inline_table_trailing_comma` 等测试用例模拟了用户在定义内联表格时可能犯的错误。
* **字符串中包含非法控制字符:** `newline_in_singleline_string` 测试用例模拟了用户在单行字符串中包含了换行符。
* **数字、日期、时间和日期时间格式错误:** `invalid_number`, `invalid_date`, `invalid_time`, `invalid_datetime` 等测试用例模拟了用户在编写这些类型的值时可能出现的格式错误。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

假设一个 Frida 用户在编写 Frida 脚本时需要读取一个 TOML 配置文件，步骤如下：

1. **用户编写 Frida 脚本:** 用户创建了一个 Python 脚本，该脚本需要从一个名为 `config.toml` 的文件中读取配置信息。
2. **用户使用 `tomlkit` 库:**  脚本中使用了 `tomlkit` 库来解析 TOML 文件。
   ```python
   import frida
   import tomlkit

   def on_message(message, data):
       print(message)

   device = frida.get_usb_device()
   pid = device.spawn(["com.example.app"])
   session = device.attach(pid)

   with open("config.toml", "r") as f:
       config = tomlkit.load(f)

   # 从配置中获取需要 hook 的函数名
   function_name = config["hook"]["function"]

   script = session.create_script(f"""
       Interceptor.attach(ptr('{config["hook"]["address"]}'), {{
           onEnter: function(args) {{
               send("Entering function: {function_name}");
           }}
       }});
   """)
   script.on('message', on_message)
   script.load()
   device.resume(pid)
   input()
   ```
3. **用户编写 `config.toml` 文件:** 用户创建了一个 `config.toml` 文件，用于配置 Frida 脚本的行为。
   ```toml
   [hook]
   address = "0x12345678"
   function = "targetFunction"
   ```
4. **用户运行 Frida 脚本:** 用户在终端中执行 Frida 脚本，例如：`frida -f com.example.app script.py`。
5. **出现 `tomlkit` 相关的错误:**  如果 `config.toml` 文件中存在语法错误，例如：
   ```toml
   [hook]
   address = 0x12345678  # 错误：十六进制数应该用引号括起来
   function = "targetFunction"
   ```
   `tomlkit.load(f)` 会抛出一个异常，例如 `tomlkit.exceptions.InvalidNumberError`。
6. **调试线索:**  错误信息会指向 `tomlkit` 库，提示用户 TOML 文件中存在数字格式错误。用户可以查看 `frida/subprojects/frida-tools/releng/tomlkit/tests/test_api.py` 文件中关于 `InvalidNumberError` 的测试用例，了解哪些类型的数字格式是不被 `tomlkit` 接受的。例如，看到 `test_parse_raises_errors_for_invalid_toml_files` 中包含 `("invalid_number", InvalidNumberError)`，用户会意识到可能是数字格式的问题。
7. **排查错误:** 用户检查 `config.toml` 文件，发现 `address` 的值没有用引号括起来，修改为 `"0x12345678"` 后，再次运行脚本，错误消失。

因此，`test_api.py` 文件中的测试用例就像一个参考手册，当用户在使用 `tomlkit` 过程中遇到错误时，可以通过查看这些测试用例来理解 `tomlkit` 的行为和期望，从而帮助定位和解决问题。这些测试用例覆盖了各种有效的和无效的 TOML 语法，为用户提供了丰富的调试线索。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tests/test_api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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