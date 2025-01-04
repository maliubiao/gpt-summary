Response:
Let's break down the thought process to analyze the provided Python code for the `tomlkit` library tests.

1. **Understand the Goal:** The overarching goal is to analyze the given Python code file (`test_api.py`) and extract information about its functionality, its relation to reverse engineering, its involvement with low-level details, its logical inferences, potential user errors, and how a user might arrive at this code.

2. **Initial Scan and High-Level Overview:**  The first step is to quickly scan the code to get a general idea of what it does. Keywords like `import`, function definitions (`def`), and the presence of `pytest` markers (`@pytest.mark.parametrize`) immediately suggest this is a test suite. The imports like `tomlkit`, `load`, `dumps`, and `parse` strongly indicate that this code is testing the API of a TOML parsing and serialization library.

3. **Identify Core Functionality by Analyzing Imports and Function Calls:**
    * **`tomlkit` imports:**  The core functions like `dump`, `dumps`, `load`, `loads`, `parse`, and various item types (`AoT`, `Array`, `Bool`, etc.) reveal the fundamental purpose of `tomlkit`: parsing TOML into Python objects and serializing Python objects back into TOML.
    * **`pytest` usage:** The `@pytest.mark.parametrize` decorator indicates that the tests are designed to run with different inputs, making the testing more comprehensive. The parameters often relate to filenames (e.g., "example.toml", "invalid.toml").
    * **Test function names:** Names like `test_parse_can_parse_valid_toml_files`, `test_load_from_file_object`, `test_parse_raises_errors_for_invalid_toml_files`, `test_original_string_and_dumped_string_are_equal`, etc., directly tell us what each test is verifying.

4. **Categorize Functionality Based on the Prompt's Requirements:** Now, go through the code more systematically and map the identified functionality to the specific questions in the prompt:

    * **Functionality:** This is the most straightforward. List the core operations the tests verify: parsing, dumping, loading from files, string manipulation, handling different TOML data types, and error handling.

    * **Relation to Reverse Engineering:** This requires a bit more inference. Consider *why* someone would need to parse configuration files. In the context of Frida, which is for dynamic instrumentation, configuration files often control the behavior of tools or scripts. Therefore, the ability to parse TOML is useful for understanding and potentially modifying the behavior of software. The examples of modifying configurations or extracting data are relevant here.

    * **Binary/Low-Level, Linux/Android Kernel/Framework:**  This section needs careful consideration. The `tomlkit` library itself is a high-level library. It doesn't directly interact with the kernel or binary code. *However*, the *purpose* of Frida is to interact with these low-level components. The connection is indirect. Configuration files parsed by `tomlkit` might *instruct* Frida to perform low-level operations. Think of it as `tomlkit` handling the instructions, and Frida executing them on the binary. It's important not to overstate the direct involvement.

    * **Logical Reasoning (Input/Output):** The parameterized tests are perfect examples of this. Choose a few representative tests, like `test_parse_can_parse_valid_toml_files` and `test_parse_raises_errors_for_invalid_toml_files`. For valid TOML, the output is a `TOMLDocument`. For invalid TOML, a specific exception is raised. This demonstrates the logical flow of the parser.

    * **User Errors:** Look for tests that explicitly check for exceptions raised by incorrect TOML syntax or invalid usage. The `test_parse_raises_errors_for_invalid_toml_files` group is the primary source here. List the kinds of syntax errors that are caught.

    * **User Journey/Debugging Clues:**  Think about how a developer using Frida and potentially encountering issues with TOML configuration might end up looking at these tests. They might be:
        * Writing a Frida script that uses a TOML configuration file.
        * Getting an error related to parsing the TOML file.
        * Trying to understand how `tomlkit` works to debug their issue.
        * Contributing to Frida and needing to understand the testing infrastructure.

5. **Refine and Structure the Output:**  Organize the extracted information clearly, using headings and bullet points as in the provided good example answer. Use clear and concise language. Ensure the examples provided are relevant and illustrative. For the "User Journey," try to create a plausible narrative.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code directly interacts with the Android kernel." **Correction:** While Frida interacts with the kernel, `tomlkit` is a high-level parser. The connection is through the configuration files that *control* Frida's behavior.
* **Initial thought:** "Just list all the test functions." **Correction:**  Group the functionalities thematically for better readability and understanding.
* **Initial thought:**  "Focus only on the `parse` function." **Correction:** The tests cover parsing, dumping, and loading, so address all of these core functions.
* **Struggling with "Logical Reasoning":**  Remember that parameterized tests are essentially function calls with specific inputs and expected outputs. Frame the examples in terms of "if input is X, then output is Y (or exception Z)."

By following these steps, iteratively refining the analysis, and focusing on the prompt's specific requirements, you can arrive at a comprehensive and accurate understanding of the provided code.
这个 Python 源代码文件 `test_api.py` 是 `frida-swift` 项目中 `tomlkit` 子项目的测试文件。`tomlkit` 是一个用于解析和操作 TOML (Tom's Obvious, Minimal Language) 配置文件的 Python 库。这个测试文件的主要目的是验证 `tomlkit` 库的 API 功能是否正确。

以下是该文件的功能列表：

1. **解析有效的 TOML 文件:**
   -  测试 `tomlkit.parse()` 和 `tomlkit.loads()` 函数能够正确解析各种有效的 TOML 格式的字符串或文件。
   -  使用 `@pytest.mark.parametrize` 装饰器，针对多个预定义的有效 TOML 示例文件（如 "example.toml", "fruit.toml" 等）进行测试。
   -  验证解析后的结果是 `tomlkit.toml_document.TOMLDocument` 类型的对象。
   -  **与逆向的关系举例:** 在逆向工程中，经常需要分析目标程序的配置文件来了解其行为。如果目标程序使用 TOML 格式的配置文件，那么 `tomlkit` 这样的库就能帮助逆向工程师解析这些文件，提取配置信息，例如服务器地址、API 密钥、功能开关等。Frida 可以用来动态地修改这些配置，而 `tomlkit` 则帮助我们理解原始配置的结构。

2. **从文件对象加载 TOML 数据:**
   -  测试 `tomlkit.load()` 函数能够从打开的文件对象中读取并解析 TOML 数据。
   -  同样使用 `@pytest.mark.parametrize` 针对多个示例文件进行测试。

3. **验证解析后的文档可以转换为 JSON 表示:**
   -  测试解析后的 `TOMLDocument` 对象可以无损地转换为 JSON 格式。
   -  这通常用于方便地与其他系统或工具进行数据交换。
   -  **与逆向的关系举例:**  在逆向分析中，有时需要将配置信息以通用的格式（如 JSON）导出，以便与其他分析工具或脚本进行处理。

4. **测试解析无效的 TOML 文件并抛出相应的异常:**
   -  测试 `tomlkit.parse()` 函数在遇到无效的 TOML 语法时，会抛出预期的异常，例如 `UnexpectedCharError`，`InvalidNumberError` 等。
   -  使用 `@pytest.mark.parametrize` 针对多个预定义的无效 TOML 示例文件进行测试。
   -  **与逆向的关系举例:**  在逆向工程中，有时会遇到格式不正确的配置文件。了解 TOML 解析器如何处理这些错误可以帮助我们判断配置文件是否被篡改或损坏。

5. **验证原始 TOML 字符串和 dump 后的字符串是否一致:**
   -  测试 `tomlkit.dumps()` 函数能够将解析后的 `TOMLDocument` 对象重新序列化为 TOML 字符串，并且该字符串与原始的 TOML 字符串相同。
   -  这验证了 `tomlkit` 在解析和序列化过程中的无损性。
   -  **与逆向的关系举例:**  在逆向过程中，我们可能需要修改 TOML 配置文件，然后再将其写回文件。确保修改后的文件格式正确且与原始格式尽可能一致是很重要的。

6. **测试 dump 函数可以处理不同类型的 Python 对象:**
   -  测试 `tomlkit.dumps()` 可以将 Python 字典 (`dict`) 和 `MappingProxyType` 对象转换为 TOML 字符串。
   -  测试 `tomlkit.dump()` 可以将 TOML 数据写入文件对象。
   -  测试 `tomlkit.dumps()` 在遇到无法处理的对象时会抛出 `TypeError`。

7. **测试 `tomlkit` 提供的各种 TOML 数据类型构建函数:**
   -  测试 `tomlkit.integer()`, `tomlkit.float_()`, `tomlkit.boolean()`, `tomlkit.date()`, `tomlkit.time()`, `tomlkit.datetime()`, `tomlkit.array()`, `tomlkit.table()`, `tomlkit.inline_table()`, `tomlkit.aot()`, `tomlkit.key()` 等函数可以创建相应的 TOML 数据类型对象。

8. **测试 `tomlkit` 的键值对处理:**
   -  测试 `tomlkit.key_value()` 函数可以解析键值对。

9. **测试字符串处理，包括转义和字面量字符串:**
   -  测试 `tomlkit.string()` 函数可以创建和表示不同类型的 TOML 字符串，包括带引号的字符串、字面量字符串以及多行字符串。
   -  测试了不同转义场景。
   -  **与逆向的关系举例:**  在分析配置文件时，理解不同类型的 TOML 字符串表示方式（例如，转义字符的处理，字面量字符串中反斜杠的含义）非常重要。

10. **测试 `tomlkit.item()` 函数处理不同类型的 Python 对象:**
    -  测试将 Python 字典和列表转换为对应的 TOML item 表示。

11. **测试创建超级表 (super table) 的功能:**
    -  测试如何使用 `tomlkit` 创建带有点分隔键的表。

12. **测试 `tomlkit.value()` 函数解析不同类型的 TOML 值:**
    -  包括布尔值、数字、字符串等。
    -  测试了对看起来像布尔值但实际上不是的字符串的处理，避免误解析。

13. **测试使用字典和 AoT (Array of Tables) 创建超级表:**
    -  验证了使用嵌套的 Python 字典和列表可以创建复杂的 TOML 结构。

14. **测试创建字符串时的各种选项:**
    -  例如 `escape` (是否转义特殊字符), `literal` (是否为字面量字符串), `multiline` (是否为多行字符串)。

15. **测试解析空的带引号的表名:**
    -  验证了 `tomlkit` 可以处理这种情况。

**与二进制底层，Linux, Android 内核及框架的知识的关系:**

这个测试文件本身并不直接涉及二进制底层、Linux 或 Android 内核及框架的知识。`tomlkit` 是一个纯 Python 库，运行在用户空间，专注于处理 TOML 格式的文本数据。

然而，在 Frida 的上下文中，`tomlkit` 的作用是解析 Frida 工具或脚本的配置文件。这些配置文件可能会间接地影响 Frida 如何与目标进程的二进制代码、Linux/Android 内核或框架进行交互。

**举例说明:**

假设一个 Frida 脚本使用 TOML 配置文件来指定要 hook 的函数地址：

```toml
[hook_config]
target_function_address = "0x12345678"
```

Frida 脚本会使用 `tomlkit` 来解析这个文件，然后将 `target_function_address` 的值传递给 Frida 的 hook API，从而在目标进程的指定内存地址上设置 hook。

在这个例子中：

- **二进制底层:**  `target_function_address` 直接指向目标进程的二进制代码。
- **Linux/Android 内核/框架:** 如果 hook 的目标函数是系统调用或者 Android 框架的函数，那么 `tomlkit` 解析的配置信息就间接地影响了 Frida 与内核/框架的交互。

**逻辑推理 (假设输入与输出):**

假设有一个测试用例 `test_value_parses_boolean`：

**假设输入:** TOML 字符串 `"true"`

**预期输出:** Python 布尔值 `True`

这个测试用例验证了 `tomlkit.value("true")` 应该返回 `True`。

假设有一个测试用例 `test_parse_raises_errors_for_invalid_toml_files`，其中 `example_name` 为 `"trailing_comma"`，对应的无效 TOML 内容为：

```toml
[section,]
key = "value"
```

**假设输入:** 上述无效的 TOML 字符串。

**预期输出:** `tomlkit.exceptions.UnexpectedCharError` 异常被抛出。

这个测试用例验证了 `tomlkit` 在遇到尾随逗号的语法错误时会抛出正确的异常。

**用户或编程常见的使用错误举例:**

1. **TOML 语法错误:** 用户可能会在配置文件中写错 TOML 语法，例如忘记闭合引号、使用不合法的字符等。测试用例 `test_parse_raises_errors_for_invalid_toml_files` 覆盖了这些场景。例如，在数组中缺少逗号：

   ```toml
   arr = [1 2]  # 错误，应该用逗号分隔
   ```

   `tomlkit` 会抛出 `UnexpectedCharError`。

2. **类型不匹配:** 用户可能期望配置文件中的某个值是特定的类型，但实际值不是。虽然 `tomlkit` 主要负责解析语法，但如果后续代码错误地处理了 `tomlkit` 返回的数据类型，也会导致问题。例如，期望一个整数，但配置中是一个字符串。

3. **文件路径错误:**  在使用 `tomlkit.load()` 时，如果提供的文件路径不存在或没有读取权限，会抛出 `FileNotFoundError` 或 `PermissionError`。这虽然不是 `tomlkit` 本身的错误，但属于使用上的常见问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写或修改了一个使用 `tomlkit` 的 Python 脚本或 Frida 脚本。** 这个脚本需要读取 TOML 格式的配置文件。

2. **脚本在尝试解析 TOML 文件时遇到了问题。** 这可能是因为配置文件格式错误，或者 `tomlkit` 库本身存在 bug。

3. **用户开始调试。** 他们可能会尝试以下步骤：
   - **检查配置文件内容:**  确认配置文件的语法是否正确。
   - **查看 `tomlkit` 的文档:**  了解 `tomlkit` 的 API 和用法。
   - **搜索 `tomlkit` 的 issue 或寻求社区帮助:** 看看是否有人遇到了类似的问题。
   - **查看 `tomlkit` 的源代码或测试代码:** 为了更深入地理解 `tomlkit` 的工作原理，用户可能会查看 `test_api.py` 这样的测试文件，了解 `tomlkit` 的开发者是如何测试其功能的，以及哪些类型的错误会被捕获。

4. **在查看 `test_api.py` 时，用户可以找到以下调试线索:**
   - **了解 `tomlkit` 支持哪些有效的 TOML 语法。** 测试用例 `test_parse_can_parse_valid_toml_files` 列举了各种有效的 TOML 示例。
   - **了解 `tomlkit` 会抛出哪些类型的异常来指示不同的语法错误。** 测试用例 `test_parse_raises_errors_for_invalid_toml_files` 详细列出了各种无效的 TOML 示例及其对应的异常。这可以帮助用户诊断配置文件中的错误类型。
   - **理解 `tomlkit` 如何处理不同类型的 TOML 数据。**  测试用例涉及到整数、浮点数、布尔值、字符串、日期时间、数组、表等，帮助用户理解 `tomlkit` 的解析规则。
   - **学习如何正确地使用 `tomlkit` 的 API。**  测试用例演示了 `parse()`, `loads()`, `load()`, `dumps()`, `dump()` 等函数的使用方法。

总之，`test_api.py` 文件对于 `tomlkit` 库的开发者和用户来说都是非常有价值的。它不仅保证了库的质量，也为用户提供了学习和调试的参考。在 Frida 的场景下，理解 `tomlkit` 的测试可以帮助逆向工程师更好地处理目标程序的 TOML 配置文件。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/tomlkit/tests/test_api.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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