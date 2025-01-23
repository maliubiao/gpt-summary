Response:
Let's break down the thought process for analyzing the Python code.

**1. Initial Understanding and Purpose:**

The first step is to recognize that this is a Python test file (`test_items.py`) within the `tomlkit` library. `tomlkit` is evident from the imports. The filename suggests it's testing the behavior of different "items" within a TOML structure. TOML is a configuration file format. Therefore, the tests are likely verifying how various TOML data types (integers, strings, arrays, tables, etc.) are represented and manipulated within the `tomlkit` library.

**2. Identifying Key Components (Imports and Fixtures):**

Next, examine the imports and fixtures.

* **Imports:** The imports tell us the core elements being tested. We see imports from `datetime`, `math`, `pickle`, `pytest`, and most importantly, from `tomlkit` itself (`api`, `parse`, `exceptions`, and specific `items` classes). This confirms the purpose identified earlier. The `tests.util` imports indicate utility functions for testing.
* **Fixtures:** The `@pytest.fixture()` decorators define setup functions. `tz_pst` and `tz_utc` are clearly setting up timezone objects for testing datetime handling. This points to testing the library's ability to handle timezones correctly.

**3. Analyzing Individual Test Functions:**

The core of the analysis involves going through each test function and understanding its purpose. Look for patterns and keywords:

* **`test_item_base_has_no_unwrap()`:** This checks that the base `Item` class doesn't implement `unwrap`, suggesting polymorphism and specific `unwrap` behavior in subclasses.
* **`test_*_unwrap()` functions:**  These tests (e.g., `test_integer_unwrap`, `test_string_unwrap`) are clearly testing the `unwrap()` method for different TOML types. The `unwrap()` method likely converts the `tomlkit` representation back to standard Python types.
* **`test_array_unwrap()` and `test_abstract_table_unwrap()`:**  These test how complex structures like arrays and tables are unwrapped. The `assert_is_ppo` function suggests they're checking if the unwrapped values are plain Python objects (lists and dictionaries).
* **`test_key_comparison()`:**  This is a straightforward test of the `Key` object's comparison operators.
* **`test_items_can_be_appended_to_and_removed_from_a_table()` and `test_items_can_be_appended_to_and_removed_from_an_inline_table()`:** These tests focus on the mutability of tables (standard and inline). They check adding and removing key-value pairs.
* **`test_inf_and_nan_are_supported()` and `test_hex_octal_and_bin_integers_are_supported()`:**  These indicate the library's ability to handle specific numerical TOML features.
* **`test_array_behaves_like_a_list()` and related tests:** These explore how the `Array` object mimics standard Python list behavior (appending, deleting, indexing, etc.) while maintaining TOML formatting (multiline, comments).
* **Tests involving arithmetic operations (`test_add_float_to_int`, `test_integers_behave_like_ints`, etc.):** These verify how `tomlkit` handles arithmetic operations on its item types and how it might promote types (e.g., int to float).
* **Tests involving date and time manipulation (`test_datetimes_behave_like_datetimes`, `test_dates_behave_like_dates`, `test_times_behave_like_times`):**  These extensively test the library's datetime handling, including timezones.
* **`test_strings_behave_like_strs()`:** Checks string concatenation and how it's represented in TOML.
* **`test_tables_behave_like_dicts()`:** Verifies that `tomlkit`'s `Table` object behaves like a Python dictionary.
* **`test_items_are_pickable()`:** Tests if the `tomlkit` items can be serialized and deserialized using `pickle`.
* **Tests concerning inline tables and comments (`test_trim_comments_when_building_inline_table`, `test_deleting_inline_table_element_does_not_leave_trailing_separator`):** These focus on the nuances of inline table formatting and comment handling.
* **`test_booleans_comparison()`:**  A basic test for boolean object comparison.
* **`test_table_copy()` and `test_copy_copy()`:** These check the behavior of copying `Table` and `Array` objects.
* **`test_escape_key()`:**  Tests how special characters in keys are escaped.
* **`test_custom_encoders()`:** Demonstrates how to extend `tomlkit` to handle custom data types using encoders.

**4. Connecting to Reverse Engineering and Lower-Level Concepts:**

As the tests are analyzed, actively think about how each functionality relates to reverse engineering and underlying concepts:

* **Configuration Files:**  Recognize that TOML is used for configuration. Reverse engineers often encounter configuration files when analyzing software. Understanding how to parse and manipulate them programmatically is valuable.
* **Data Structures:** The tests for arrays and tables highlight how data is structured and accessed. This is crucial in reverse engineering to understand how data is organized in memory or files.
* **Data Types:** The tests for different data types (integers, floats, strings, booleans, dates, times) are fundamental. Reverse engineers need to identify and interpret these data types in binary or memory dumps.
* **Serialization:** The `pickle` tests relate to how objects are serialized. This is relevant in understanding how data is persisted and transferred.
* **String Handling:**  The string tests, especially those involving escape sequences, are relevant for analyzing text-based configuration or data.
* **Date and Time:** Understanding how dates and times are stored and manipulated is important in analyzing timestamps, scheduling information, etc.
* **Error Handling:** The `pytest.raises` checks demonstrate how the library handles errors, which can be useful in understanding potential failure points in the target software.

**5. Formulating Examples and Explanations:**

Based on the understanding of the test functions, formulate concrete examples:

* **Reverse Engineering:**  Give examples of how manipulating TOML could be used to modify application behavior or extract configuration details.
* **Low-Level Concepts:**  Connect the tested features to concepts like memory layout (arrays, tables), system calls (for date/time), and data representation (binary, hex).
* **Logical Reasoning:** Construct simple input TOML and predict the output after specific operations (e.g., adding an element to an array).
* **User Errors:**  Imagine common mistakes a user might make when working with TOML and how these tests might catch them.
* **Debugging:** Explain how reaching this test file during debugging provides clues about the area of the library being used.

**6. Structuring the Answer:**

Finally, organize the analysis into a clear and structured response, addressing each of the prompt's points:

* **Functionality:**  Provide a high-level summary and then detail the functionality of specific groups of tests.
* **Reverse Engineering:**  Give targeted examples.
* **Low-Level Concepts:**  Provide relevant explanations.
* **Logical Reasoning:**  Present input/output examples.
* **User Errors:**  Illustrate common mistakes.
* **Debugging:** Explain the context of reaching this file.

By following these steps, we can systematically analyze the code and provide a comprehensive and informative answer that addresses all aspects of the prompt. The key is to not just list what the code *does*, but to explain *why* it does it and how it connects to broader concepts like reverse engineering and system-level understanding.这个文件 `test_items.py` 是 `frida-node` 项目中 `tomlkit` 子项目的一部分。`tomlkit` 是一个用于解析、操作和序列化 TOML 格式配置文件的 Python 库。 这个测试文件专门用于测试 `tomlkit` 中各种 **Item** 类的功能。  **Item** 类代表了 TOML 文件中的各种基本数据类型和结构，例如整数、字符串、布尔值、日期、数组、表格等。

以下是 `test_items.py` 的详细功能列表，并结合逆向、底层知识、逻辑推理、用户错误和调试线索进行说明：

**功能列表：**

1. **测试基本数据类型的解包 (Unwrap):**
   - 测试将 `tomlkit` 的 `Integer`, `String`, `Bool`, `Null`, `Float`, `Datetime`, `Time`, `Date` 等 **Item** 对象转换为 Python 原生数据类型 (int, str, bool, None, float, datetime, time, date) 的 `unwrap()` 方法。
   - **逆向关系：** 在逆向工程中，我们经常需要从配置文件或数据结构中提取原始数据。`tomlkit` 能够将 TOML 格式的数据解析成易于操作的 Python 对象，方便我们分析配置信息。`unwrap()` 方法模拟了将 `tomlkit` 内部表示转换成我们熟悉的 Python 类型。
   - **二进制底层/内核/框架知识：**  不同的数据类型在底层有不同的二进制表示。例如，整数有不同的字节序和大小，浮点数遵循 IEEE 754 标准，日期和时间可能需要考虑时区。虽然 `tomlkit` 自身不直接操作二进制，但它处理的 *是* 这些数据类型的抽象表示。

2. **测试数组 (Array) 的解包和操作:**
   - 测试将 `tomlkit` 的 `Array` 对象转换为 Python `list`，并验证数组中元素的类型。
   - 测试数组的增删改查操作，例如 `append()`, `remove()`,  索引访问和切片等，以及多行数组的格式化。
   - **逆向关系：** 配置文件中经常使用数组来存储列表数据，例如插件列表、黑名单、白名单等。理解如何解析和操作这些数组对于分析软件行为至关重要。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入 (TOML):** `a = [1, 2, "hello"]`
     - **预期输出 (Python):** `doc["a"].unwrap()` 将返回 `[1, 2, "hello"]`，并且每个元素的类型正确 (int, int, str)。
     - **假设输入 (TOML):** `a = [1, 2]`  执行 `doc["a"].append(3)`
     - **预期输出 (TOML 字符串):** `a = [1, 2, 3]`

3. **测试表格 (Table) 和内联表格 (InlineTable) 的解包和操作:**
   - 测试将 `tomlkit` 的 `Table` 和 `InlineTable` 对象转换为 Python `dict`，并验证键值对的类型。
   - 测试表格的添加、删除键值对操作，以及字符串表示 (`as_string()`)。
   - **逆向关系：** TOML 的表格用于组织配置项，可以嵌套。理解表格的结构和如何访问其中的数据是理解软件配置的关键。内联表格用于简洁地表示小的键值对。
   - **用户常见使用错误：**  尝试删除不存在的键会抛出 `NonExistentKey` 异常。例如，如果 TOML 文件中没有 `foo` 键，执行 `table.remove(Key("foo"))` 将导致错误。

4. **测试键 (Key) 的比较:**
   - 测试 `tomlkit` 的 `Key` 对象与其他 `Key` 对象和字符串的比较操作。
   - **逆向关系：**  在操作 TOML 数据时，需要比较键是否相等，以便访问或修改特定的配置项。

5. **测试特殊数值的支持:**
   - 测试对无穷大 (`inf`)、负无穷大 (`-inf`) 和 NaN (`nan`) 浮点数的解析和表示。
   - 测试对十六进制 (`0x`), 八进制 (`0o`), 和二进制 (`0b`) 整数的解析。
   - **二进制底层知识：** 这些特殊数值在底层有特定的二进制表示。例如，NaN 有多种不同的表示形式。

6. **测试键的字符串类型推断:**
   - 测试 `tomlkit` 如何根据键的字符串内容自动判断键的类型 (基本型或带引号的)。

7. **测试数组的行为类似列表:**
   - 验证 `tomlkit` 的 `Array` 对象是否支持 Python 列表的常见操作，如 `+=`, `del`, `pop()`, 索引赋值, `clear()` 等。

8. **测试多行数组的格式化:**
   - 测试如何将 `Array` 对象格式化为多行，提高可读性。

9. **测试修改带注释的数组:**
   - 验证在修改（添加、插入、删除元素）多行或带注释的数组时，`tomlkit` 是否能正确地维护格式和注释。

10. **测试将字典添加到数组:**
    - 验证将 Python 字典添加到 `tomlkit` 数组后，字典会被转换为 `tomlkit` 的内联表格。

11. **测试字典到表格的转换:**
    - 测试将 Python 字典作为 `tomlkit` 的 Item 值时，如何转换为 TOML 的表格结构。

12. **测试对数值类型进行算术运算:**
    - 测试对 `tomlkit` 的 `Integer` 和 `Float` 对象进行加减乘除等运算，并验证类型转换 (例如，整数加浮点数结果为浮点数)。
    - **逻辑推理 (假设输入与输出):**
      - **假设输入 (TOML):** `my_int = 10`，执行 `doc["my_int"] += 5.0`
      - **预期输出 (TOML 字符串):** `my_int = 15.0` (类型变为浮点数)

13. **测试日期和时间类型的操作:**
    - 测试对 `tomlkit` 的 `Datetime`, `Date`, `Time` 对象进行算术运算（例如，timedelta 的加减）和属性修改（例如，替换年份，调整时区）。
    - **内核/框架知识：**  日期和时间处理涉及到操作系统提供的 API 和时区数据库。`tomlkit` 依赖 Python 的 `datetime` 模块，后者可能会利用底层的 C 库来实现高效的时间操作。
    - **用户常见使用错误：**  时区处理不当可能导致时间计算错误。测试用例中使用了 `tz_utc` 和 `tz_pst` fixture 来测试时区相关的操作。

14. **测试字符串类型的操作:**
    - 测试 `tomlkit` 的 `String` 对象是否支持字符串拼接操作。

15. **测试表格的行为类似字典:**
    - 验证 `tomlkit` 的 `Table` 对象是否支持 Python 字典的常见操作，如 `update()`, `get()`, `setdefault()`。

16. **测试 Item 对象的序列化 (Pickling):**
    - 测试 `tomlkit` 的各种 Item 对象是否可以使用 `pickle` 模块进行序列化和反序列化。
    - **逆向关系：**  序列化可以将对象的状态保存到文件中或通过网络传输，这在逆向工程中用于保存分析结果或与其他工具交换数据。

17. **测试在构建内联表格时去除注释:**
    - 验证在将带有注释的键值对添加到内联表格时，注释不会被包含在内联表格的字符串表示中。

18. **测试删除内联表格元素不会留下尾部分隔符:**
    - 验证在删除内联表格的最后一个或中间元素时，生成的字符串表示不会有多余的逗号。

19. **测试布尔值的比较:**
    - 验证 `tomlkit` 的 `Bool` 对象的布尔值比较行为。

20. **测试表格的复制:**
    - 测试 `tomlkit` 的 `Table` 对象的 `copy()` 方法，确保复制是深拷贝，修改原始表格不会影响复制后的表格。

21. **测试数组的复制:**
    - 测试 `copy.copy()` 函数对 `tomlkit` `Array` 对象的复制行为。

22. **测试键的转义:**
    - 测试 `tomlkit` 如何转义键字符串中的特殊字符。

23. **测试自定义编码器:**
    - 演示如何使用 `tomlkit.api.register_encoder` 注册自定义编码器来处理 `tomlkit` 默认不支持的数据类型 (例如 `decimal.Decimal`)。
    - **用户常见使用错误：**  尝试将 `tomlkit` 默认不支持的类型直接赋值给 Item 会导致 `TypeError`。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在使用 `frida-node` 提供的功能时，遇到了 TOML 配置文件解析或操作相关的问题。以下是可能到达 `test_items.py` 的调试步骤：

1. **问题报告/复现：** 用户报告或开发者自己复现了与 TOML 文件处理相关的 Bug，例如配置文件未能正确加载、修改后的配置未能正确保存等。
2. **代码审查/调试：** 开发者开始审查 `frida-node` 中处理 TOML 文件的代码，很可能会涉及到 `tomlkit` 这个子项目。
3. **定位到 `tomlkit`：** 通过代码调用关系，开发者会发现 `frida-node` 使用了 `tomlkit` 库来处理 TOML 文件。
4. **查看 `tomlkit` 测试：** 为了理解 `tomlkit` 的工作原理和预期行为，开发者会查看 `tomlkit` 的测试用例。`test_items.py` 是测试核心 Item 对象功能的关键文件，因此很可能会被查阅。
5. **运行特定测试：** 开发者可能会运行 `test_items.py` 中的特定测试用例，来验证 `tomlkit` 在特定场景下的行为是否符合预期。例如，如果问题与数组操作有关，可能会运行 `test_array_unwrap` 或 `test_array_behaves_like_a_list` 等测试。
6. **断点调试：** 如果测试用例失败或行为异常，开发者可能会在 `test_items.py` 或 `tomlkit` 的源代码中设置断点，逐步执行代码，观察变量的值，从而找出问题所在。

**总结：**

`test_items.py` 是 `tomlkit` 库的核心测试文件，它详尽地测试了各种 TOML 数据类型的表示和操作。理解这个文件的功能有助于理解 `tomlkit` 的工作原理，这对于使用 `frida-node` 处理 TOML 配置，或者在逆向工程中分析 TOML 配置文件都是非常有价值的。文件中涉及到的各种测试用例覆盖了 TOML 语法的各种细节和常见用法，也考虑了用户可能遇到的错误情况，是保证 `tomlkit` 库质量的重要组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import copy
import math
import pickle

from datetime import date
from datetime import datetime
from datetime import time
from datetime import timedelta
from datetime import timezone

import pytest

from tests.util import assert_is_ppo
from tests.util import elementary_test
from tomlkit import api
from tomlkit import parse
from tomlkit.exceptions import NonExistentKey
from tomlkit.items import Array
from tomlkit.items import Bool
from tomlkit.items import Comment
from tomlkit.items import InlineTable
from tomlkit.items import Integer
from tomlkit.items import Item
from tomlkit.items import KeyType
from tomlkit.items import Null
from tomlkit.items import SingleKey as Key
from tomlkit.items import String
from tomlkit.items import StringType
from tomlkit.items import Table
from tomlkit.items import Trivia
from tomlkit.items import item
from tomlkit.parser import Parser


@pytest.fixture()
def tz_pst():
    try:
        from datetime import timezone

        return timezone(timedelta(hours=-8), "PST")
    except ImportError:
        from datetime import tzinfo

        class PST(tzinfo):
            def utcoffset(self, dt):
                return timedelta(hours=-8)

            def tzname(self, dt):
                return "PST"

            def dst(self, dt):
                return timedelta(0)

        return PST()


@pytest.fixture()
def tz_utc():
    try:
        from datetime import timezone

        return timezone.utc
    except ImportError:
        from datetime import tzinfo

        class UTC(tzinfo):
            def utcoffset(self, dt):
                return timedelta(hours=0)

            def tzname(self, dt):
                return "UTC"

            def dst(self, dt):
                return timedelta(0)

        return UTC()


def test_item_base_has_no_unwrap():
    trivia = Trivia(indent="\t", comment_ws=" ", comment="For unit test")
    item = Item(trivia)
    try:
        item.unwrap()
    except NotImplementedError:
        pass
    else:
        raise AssertionError("`items.Item` should not implement `unwrap`")


def test_integer_unwrap():
    elementary_test(item(666), int)


def test_float_unwrap():
    elementary_test(item(2.78), float)


def test_false_unwrap():
    elementary_test(item(False), bool)


def test_true_unwrap():
    elementary_test(item(True), bool)


def test_datetime_unwrap():
    dt = datetime.now(tz=timezone.utc)
    elementary_test(item(dt), datetime)


def test_string_unwrap():
    elementary_test(item("hello"), str)


def test_null_unwrap():
    n = Null()
    elementary_test(n, type(None))


def test_aot_unwrap():
    d = item([{"a": "A"}, {"b": "B"}])
    unwrapped = d.unwrap()
    assert_is_ppo(unwrapped, list)
    for du, _ in zip(unwrapped, d):
        assert_is_ppo(du, dict)
        for ku in du:
            vu = du[ku]
            assert_is_ppo(ku, str)
            assert_is_ppo(vu, str)


def test_time_unwrap():
    t = time(3, 8, 14)
    elementary_test(item(t), time)


def test_date_unwrap():
    d = date.today()
    elementary_test(item(d), date)


def test_array_unwrap():
    trivia = Trivia(indent="\t", comment_ws=" ", comment="For unit test")
    i = item(666)
    f = item(2.78)
    b = item(False)
    a = Array([i, f, b], trivia)
    a_unwrapped = a.unwrap()
    assert_is_ppo(a_unwrapped, list)
    assert_is_ppo(a_unwrapped[0], int)
    assert_is_ppo(a_unwrapped[1], float)
    assert_is_ppo(a_unwrapped[2], bool)


def test_abstract_table_unwrap():
    table = item({"foo": "bar"})
    super_table = item({"table": table, "baz": "borg"})

    table_unwrapped = super_table.unwrap()
    sub_table = table_unwrapped["table"]
    assert_is_ppo(table_unwrapped, dict)
    assert_is_ppo(sub_table, dict)
    for ku in sub_table:
        vu = sub_table[ku]
        assert_is_ppo(ku, str)
        assert_is_ppo(vu, str)


def test_key_comparison():
    k = Key("foo")

    assert k == Key("foo")
    assert k == "foo"
    assert k != "bar"
    assert k != 5


def test_items_can_be_appended_to_and_removed_from_a_table():
    string = """[table]
"""

    parser = Parser(string)
    _, table = parser._parse_table()

    assert isinstance(table, Table)
    assert table.as_string() == ""

    table.append(Key("foo"), String(StringType.SLB, "bar", "bar", Trivia(trail="\n")))

    assert table.as_string() == 'foo = "bar"\n'

    table.append(
        Key("baz"),
        Integer(34, Trivia(comment_ws="   ", comment="# Integer", trail=""), "34"),
    )

    assert table.as_string() == 'foo = "bar"\nbaz = 34   # Integer'

    table.remove(Key("baz"))

    assert table.as_string() == 'foo = "bar"\n'

    table.remove(Key("foo"))

    assert table.as_string() == ""

    with pytest.raises(NonExistentKey):
        table.remove(Key("foo"))


def test_items_can_be_appended_to_and_removed_from_an_inline_table():
    string = """table = {}
"""

    parser = Parser(string)
    _, table = parser._parse_item()

    assert isinstance(table, InlineTable)
    assert table.as_string() == "{}"

    table.append(Key("foo"), String(StringType.SLB, "bar", "bar", Trivia(trail="")))

    assert table.as_string() == '{foo = "bar"}'

    table.append(Key("baz"), Integer(34, Trivia(trail=""), "34"))

    assert table.as_string() == '{foo = "bar", baz = 34}'

    table.remove(Key("baz"))

    assert table.as_string() == '{foo = "bar"}'

    table.remove(Key("foo"))

    assert table.as_string() == "{}"

    with pytest.raises(NonExistentKey):
        table.remove(Key("foo"))


def test_inf_and_nan_are_supported(example):
    content = example("0.5.0")
    doc = parse(content)

    assert doc["sf1"] == float("inf")
    assert doc["sf2"] == float("inf")
    assert doc["sf3"] == float("-inf")

    assert math.isnan(doc["sf4"])
    assert math.isnan(doc["sf5"])
    assert math.isnan(doc["sf6"])


def test_hex_octal_and_bin_integers_are_supported(example):
    content = example("0.5.0")
    doc = parse(content)

    assert doc["hex1"] == 3735928559
    assert doc["hex2"] == 3735928559
    assert doc["hex3"] == 3735928559

    assert doc["oct1"] == 342391
    assert doc["oct2"] == 493

    assert doc["bin1"] == 214


def test_key_automatically_sets_proper_string_type_if_not_bare():
    key = Key("foo.bar")

    assert key.t == KeyType.Basic

    key = Key("")
    assert key.t == KeyType.Basic


def test_array_behaves_like_a_list():
    a = item([1, 2])

    assert a == [1, 2]
    assert a.as_string() == "[1, 2]"

    a += [3, 4]
    assert a == [1, 2, 3, 4]
    assert a.as_string() == "[1, 2, 3, 4]"

    del a[2]
    assert a == [1, 2, 4]
    assert a.as_string() == "[1, 2, 4]"

    assert a.pop() == 4
    assert a == [1, 2]
    assert a.as_string() == "[1, 2]"

    a[0] = 4
    assert a == [4, 2]
    a[-2] = 0
    assert a == [0, 2]

    del a[-2]
    assert a == [2]
    assert a.as_string() == "[2]"

    a.clear()
    assert a == []
    assert a.as_string() == "[]"

    content = """a = [1, 2,] # Comment
"""
    doc = parse(content)
    assert str(doc["a"]) == "[1, 2]"

    assert doc["a"] == [1, 2]
    doc["a"] += [3, 4]
    assert doc["a"] == [1, 2, 3, 4]
    assert (
        doc.as_string()
        == """a = [1, 2, 3, 4] # Comment
"""
    )


def test_array_multiline():
    t = item([1, 2, 3, 4, 5, 6, 7, 8])
    t.multiline(True)

    expected = """\
[
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
]"""

    assert expected == t.as_string()

    t = item([])
    t.multiline(True)

    assert t.as_string() == "[]"


def test_array_multiline_modify():
    doc = parse(
        """\
a = [
    "abc"
]"""
    )
    doc["a"].append("def")
    expected = """\
a = [
    "abc",
    "def"
]"""
    assert expected == doc.as_string()
    doc["a"].insert(1, "ghi")
    expected = """\
a = [
    "abc",
    "ghi",
    "def"
]"""
    assert expected == doc.as_string()


def test_append_to_empty_array():
    doc = parse("x = [ ]")
    doc["x"].append("a")
    assert doc.as_string() == 'x = ["a" ]'
    doc = parse("x = [\n]")
    doc["x"].append("a")
    assert doc.as_string() == 'x = [\n    "a"\n]'


def test_modify_array_with_comment():
    doc = parse("x = [ # comment\n]")
    doc["x"].append("a")
    assert doc.as_string() == 'x = [ # comment\n    "a"\n]'
    doc = parse(
        """\
x = [
    "a",
    # comment
    "b"
]"""
    )
    doc["x"].insert(1, "c")
    expected = """\
x = [
    "a",
    # comment
    "c",
    "b"
]"""
    assert doc.as_string() == expected
    doc = parse(
        """\
x = [
    1  # comment
]"""
    )
    doc["x"].append(2)
    assert (
        doc.as_string()
        == """\
x = [
    1,  # comment
    2
]"""
    )
    doc["x"].pop(0)
    assert doc.as_string() == "x = [\n    2\n]"


def test_append_to_multiline_array_with_comment():
    doc = parse(
        """\
x = [
    # Here is a comment
    1,
    2
]
"""
    )
    doc["x"].multiline(True).append(3)
    assert (
        doc.as_string()
        == """\
x = [
    # Here is a comment
    1,
    2,
    3,
]
"""
    )
    assert doc["x"].pop() == 3
    assert (
        doc.as_string()
        == """\
x = [
    # Here is a comment
    1,
    2,
]
"""
    )


def test_append_dict_to_array():
    doc = parse("x = []")
    doc["x"].append({"name": "John Doe", "email": "john@doe.com"})
    expected = 'x = [{name = "John Doe",email = "john@doe.com"}]'
    assert doc.as_string() == expected
    # Make sure the produced string is valid
    assert parse(doc.as_string()) == doc


def test_dicts_are_converted_to_tables():
    t = item({"foo": {"bar": "baz"}})

    assert (
        t.as_string()
        == """[foo]
bar = "baz"
"""
    )


def test_array_add_line():
    t = api.array()
    t.add_line(1, 2, 3, comment="Line 1")
    t.add_line(4, 5, 6, comment="Line 2")
    t.add_line(7, api.ws(","), api.ws(" "), 8, add_comma=False)
    t.add_line(comment="Line 4")
    t.add_line(indent="")
    assert len(t) == 8
    assert list(t) == [1, 2, 3, 4, 5, 6, 7, 8]
    assert (
        t.as_string()
        == """[
    1, 2, 3, # Line 1
    4, 5, 6, # Line 2
    7, 8,
    # Line 4
]"""
    )


def test_array_add_line_invalid_value():
    t = api.array()
    with pytest.raises(ValueError, match="is not allowed"):
        t.add_line(1, api.ws(" "))
    with pytest.raises(ValueError, match="is not allowed"):
        t.add_line(Comment(Trivia("  ", comment="test")))
    assert len(t) == 0


def test_dicts_are_converted_to_tables_and_keep_order():
    t = item(
        {
            "foo": {
                "bar": "baz",
                "abc": 123,
                "baz": [{"c": 3, "b": 2, "a": 1}],
            },
        }
    )

    assert (
        t.as_string()
        == """[foo]
bar = "baz"
abc = 123

[[foo.baz]]
c = 3
b = 2
a = 1
"""
    )


def test_dicts_are_converted_to_tables_and_are_sorted_if_requested():
    t = item(
        {
            "foo": {
                "bar": "baz",
                "abc": 123,
                "baz": [{"c": 3, "b": 2, "a": 1}],
            },
        },
        _sort_keys=True,
    )

    assert (
        t.as_string()
        == """[foo]
abc = 123
bar = "baz"

[[foo.baz]]
a = 1
b = 2
c = 3
"""
    )


def test_dicts_with_sub_dicts_are_properly_converted():
    t = item(
        {"foo": {"bar": {"string": "baz"}, "int": 34, "float": 3.14}}, _sort_keys=True
    )

    assert (
        t.as_string()
        == """[foo]
float = 3.14
int = 34

[foo.bar]
string = "baz"
"""
    )


def test_item_array_of_dicts_converted_to_aot():
    a = item({"foo": [{"bar": "baz"}]})

    assert (
        a.as_string()
        == """[[foo]]
bar = "baz"
"""
    )


def test_add_float_to_int():
    content = "[table]\nmy_int = 2043"
    doc = parse(content)
    doc["table"]["my_int"] += 5.0
    assert doc["table"]["my_int"] == 2048.0
    assert isinstance(doc["table"]["my_int"], float)


def test_sub_float_from_int():
    content = "[table]\nmy_int = 2048"
    doc = parse(content)
    doc["table"]["my_int"] -= 5.0
    assert doc["table"]["my_int"] == 2043.0
    assert isinstance(doc["table"]["my_int"], float)


def test_sub_int_from_float():
    content = "[table]\nmy_int = 2048.0"
    doc = parse(content)
    doc["table"]["my_int"] -= 5
    assert doc["table"]["my_int"] == 2043.0


def test_add_sum_int_with_float():
    content = "[table]\nmy_int = 2048.3"
    doc = parse(content)
    doc["table"]["my_int"] += 5
    assert doc["table"]["my_int"] == 2053.3


def test_integers_behave_like_ints():
    i = item(34)

    assert i == 34
    assert i.as_string() == "34"

    i += 1
    assert i == 35
    assert i.as_string() == "35"

    i -= 2
    assert i == 33
    assert i.as_string() == "33"

    i /= 2
    assert i == 16.5
    assert i.as_string() == "16.5"

    doc = parse("int = +34")
    doc["int"] += 1

    assert doc.as_string() == "int = +35"


def test_floats_behave_like_floats():
    i = item(34.12)

    assert i == 34.12
    assert i.as_string() == "34.12"

    i += 1
    assert i == 35.12
    assert i.as_string() == "35.12"

    i -= 2
    assert i == 33.12
    assert i.as_string() == "33.12"

    doc = parse("float = +34.12")
    doc["float"] += 1

    assert doc.as_string() == "float = +35.12"


def test_datetimes_behave_like_datetimes(tz_utc, tz_pst):
    i = item(datetime(2018, 7, 22, 12, 34, 56))

    assert i == datetime(2018, 7, 22, 12, 34, 56)
    assert i.as_string() == "2018-07-22T12:34:56"

    i += timedelta(days=1)
    assert i == datetime(2018, 7, 23, 12, 34, 56)
    assert i.as_string() == "2018-07-23T12:34:56"

    i -= timedelta(days=2)
    assert i == datetime(2018, 7, 21, 12, 34, 56)
    assert i.as_string() == "2018-07-21T12:34:56"

    i = i.replace(year=2019, tzinfo=tz_utc)
    assert i == datetime(2019, 7, 21, 12, 34, 56, tzinfo=tz_utc)
    assert i.as_string() == "2019-07-21T12:34:56+00:00"

    i = i.astimezone(tz_pst)
    assert i == datetime(2019, 7, 21, 4, 34, 56, tzinfo=tz_pst)
    assert i.as_string() == "2019-07-21T04:34:56-08:00"

    doc = parse("dt = 2018-07-22T12:34:56-05:00")
    doc["dt"] += timedelta(days=1)

    assert doc.as_string() == "dt = 2018-07-23T12:34:56-05:00"


def test_dates_behave_like_dates():
    i = item(date(2018, 7, 22))

    assert i == date(2018, 7, 22)
    assert i.as_string() == "2018-07-22"

    i += timedelta(days=1)
    assert i == datetime(2018, 7, 23)
    assert i.as_string() == "2018-07-23"

    i -= timedelta(days=2)
    assert i == date(2018, 7, 21)
    assert i.as_string() == "2018-07-21"

    i = i.replace(year=2019)
    assert i == datetime(2019, 7, 21)
    assert i.as_string() == "2019-07-21"

    doc = parse("dt = 2018-07-22 # Comment")
    doc["dt"] += timedelta(days=1)

    assert doc.as_string() == "dt = 2018-07-23 # Comment"


def test_parse_datetime_followed_by_space():
    # issue #260
    doc = parse("dt = 2018-07-22 ")
    assert doc["dt"] == date(2018, 7, 22)
    assert doc.as_string() == "dt = 2018-07-22 "

    doc = parse("dt = 2013-01-24 13:48:01.123456 ")
    assert doc["dt"] == datetime(2013, 1, 24, 13, 48, 1, 123456)
    assert doc.as_string() == "dt = 2013-01-24 13:48:01.123456 "


def test_times_behave_like_times():
    i = item(time(12, 34, 56))

    assert i == time(12, 34, 56)
    assert i.as_string() == "12:34:56"

    i = i.replace(hour=13)
    assert i == time(13, 34, 56)
    assert i.as_string() == "13:34:56"


def test_strings_behave_like_strs():
    i = item("foo")

    assert i == "foo"
    assert i.as_string() == '"foo"'

    i += " bar"
    assert i == "foo bar"
    assert i.as_string() == '"foo bar"'

    i += " é"
    assert i == "foo bar é"
    assert i.as_string() == '"foo bar é"'

    doc = parse('str = "foo" # Comment')
    doc["str"] += " bar"

    assert doc.as_string() == 'str = "foo bar" # Comment'


def test_string_add_preserve_escapes():
    i = api.value('"foo\\"bar"')
    i += " baz"

    assert i == 'foo"bar baz'
    assert i.as_string() == '"foo\\"bar baz"'


def test_tables_behave_like_dicts():
    t = item({"foo": "bar"})

    assert (
        t.as_string()
        == """foo = "bar"
"""
    )

    t.update({"bar": "baz"})

    assert (
        t.as_string()
        == """foo = "bar"
bar = "baz"
"""
    )

    t.update({"bar": "boom"})

    assert (
        t.as_string()
        == """foo = "bar"
bar = "boom"
"""
    )

    assert t.get("bar") == "boom"
    assert t.setdefault("foobar", "fuzz") == "fuzz"
    assert (
        t.as_string()
        == """foo = "bar"
bar = "boom"
foobar = "fuzz"
"""
    )


def test_items_are_pickable():
    n = item(12)

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "12"

    n = item(12.34)

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "12.34"

    n = item(True)

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "true"

    n = item(datetime(2018, 10, 11, 12, 34, 56, 123456))

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "2018-10-11T12:34:56.123456"

    n = item(date(2018, 10, 11))

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "2018-10-11"

    n = item(time(12, 34, 56, 123456))

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "12:34:56.123456"

    n = item([1, 2, 3])

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == "[1, 2, 3]"

    n = item({"foo": "bar"})

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == 'foo = "bar"\n'

    n = api.inline_table()
    n["foo"] = "bar"

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == '{foo = "bar"}'

    n = item("foo")

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == '"foo"'

    n = item([{"foo": "bar"}])

    s = pickle.dumps(n)
    assert pickle.loads(s).as_string() == 'foo = "bar"\n'


def test_trim_comments_when_building_inline_table():
    table = api.inline_table()
    row = parse('foo = "bar"  # Comment')
    table.update(row)
    assert table.as_string() == '{foo = "bar"}'
    value = item("foobaz")
    value.comment("Another comment")
    table.append("baz", value)
    assert "# Another comment" not in table.as_string()
    assert table.as_string() == '{foo = "bar", baz = "foobaz"}'


def test_deleting_inline_table_element_does_not_leave_trailing_separator():
    table = api.inline_table()
    table["foo"] = "bar"
    table["baz"] = "boom"

    assert table.as_string() == '{foo = "bar", baz = "boom"}'

    del table["baz"]

    assert table.as_string() == '{foo = "bar"}'

    table = api.inline_table()
    table["foo"] = "bar"

    del table["foo"]

    table["baz"] = "boom"

    assert table.as_string() == '{baz = "boom"}'


def test_deleting_inline_table_element_does_not_leave_trailing_separator2():
    doc = parse('a = {foo = "bar", baz = "boom"}')
    table = doc["a"]
    assert table.as_string() == '{foo = "bar", baz = "boom"}'

    del table["baz"]
    assert table.as_string() == '{foo = "bar" }'

    del table["foo"]
    assert table.as_string() == "{ }"

    table["baz"] = "boom"

    assert table.as_string() == '{ baz = "boom"}'


def test_booleans_comparison():
    boolean = Bool(True, Trivia())

    assert boolean

    boolean = Bool(False, Trivia())

    assert not boolean

    s = """[foo]
value = false
"""

    content = parse(s)

    assert {"foo": {"value": False}} == content
    assert {"value": False} == content["foo"]


def test_table_copy():
    table = item({"foo": "bar"})
    table_copy = table.copy()
    assert isinstance(table_copy, Table)
    table["foo"] = "baz"
    assert table_copy["foo"] == "bar"
    assert table_copy.as_string() == 'foo = "bar"\n'


def test_copy_copy():
    result = parse(
        """
    [tool.poetry]
    classifiers = [
    # comment
        "a",
        "b",
    ]
    """
    )
    classifiers = result["tool"]["poetry"]["classifiers"]
    new = copy.copy(classifiers)
    assert new == classifiers


@pytest.mark.parametrize(
    "key_str,escaped",
    [("\\", '"\\\\"'), ('"', '"\\""'), ("\t", '"\\t"'), ("\x10", '"\\u0010"')],
)
def test_escape_key(key_str, escaped):
    assert api.key(key_str).as_string() == escaped


def test_custom_encoders():
    import decimal

    @api.register_encoder
    def encode_decimal(obj):
        if isinstance(obj, decimal.Decimal):
            return api.float_(str(obj))
        raise TypeError

    assert api.item(decimal.Decimal("1.23")).as_string() == "1.23"

    with pytest.raises(TypeError):
        api.item(object())

    assert api.dumps({"foo": decimal.Decimal("1.23")}) == "foo = 1.23\n"
    api.unregister_encoder(encode_decimal)
```