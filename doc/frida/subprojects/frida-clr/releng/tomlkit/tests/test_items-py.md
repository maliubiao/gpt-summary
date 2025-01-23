Response:
My thinking process to analyze the Python code and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for a functional breakdown of the provided Python code (`test_items.py`), focusing on its relationship to reverse engineering, low-level operations, logical reasoning, common user errors, and debugging context within the Frida framework.

2. **Identify the Core Purpose:**  The filename `test_items.py` and the presence of `pytest` fixtures and assertions strongly suggest this is a unit test file. It tests the functionality of various "item" types used in the `tomlkit` library, which likely handles TOML (Tom's Obvious, Minimal Language) parsing and manipulation.

3. **Break Down Functionality by Code Structure:**  I'll go through the code section by section, noting the key actions and concepts:

    * **Imports:**  List the imported modules (`copy`, `math`, `pickle`, `datetime`, `pytest`) and their likely roles (data manipulation, mathematical operations, serialization, date/time handling, testing). The `tomlkit` imports are crucial and hint at the library's structure.

    * **Fixtures (`tz_pst`, `tz_utc`):** Recognize these as setup functions for tests, providing timezone objects for datetime testing. Note that they handle potential `ImportError` for older Python versions.

    * **Individual Test Functions (`test_...`):** Each function tests a specific aspect of `tomlkit`'s item handling. I'll analyze each one for its specific focus. Look for assertions (`assert`) to understand what's being verified.

4. **Relate to Reverse Engineering (if applicable):**  This requires connecting the tested functionality to common reverse engineering tasks. Think about how data formats and manipulation are involved in reverse engineering:

    * **Configuration Files:** TOML is often used for configuration. Understanding how to parse and modify it programmatically is valuable in reverse engineering scenarios where you might want to change application behavior by altering config files.
    * **Data Structures:** The tests cover various data types (integers, floats, strings, arrays, tables/dictionaries, dates/times). Reverse engineers frequently encounter these when analyzing program data structures or serialized formats.
    * **Dynamic Instrumentation:** Since this is within the Frida project, consider how TOML manipulation might be used *within* a Frida script. Perhaps a Frida script reads a configuration file to determine which functions to hook or what values to modify.

5. **Relate to Low-Level/Kernel/Framework (if applicable):**  This requires identifying connections to operating system concepts.

    * **Data Representation:**  While the `tomlkit` library itself is high-level, its underlying operations involve representing data in memory. The tests for different data types implicitly touch upon how those types are stored.
    * **File I/O:** TOML files are stored on disk. Although the tests don't directly show file I/O, the library being tested must perform it.
    * **Timezones:** The timezone fixtures relate to OS-level time management.

6. **Identify Logical Reasoning:**  Look for tests that demonstrate manipulation or transformation of data based on certain rules.

    * **`test_array_behaves_like_a_list()`:**  This shows logical reasoning by verifying that the `tomlkit` `Array` behaves consistently with standard Python lists.
    * **`test_dicts_are_converted_to_tables()`:**  This tests the logic of converting Python dictionaries to TOML tables.
    * **Arithmetic Operations on Items:** Tests involving `+=`, `-=`, `/=` demonstrate how `tomlkit` items overload operators and perform logical conversions (e.g., adding a float to an int).

7. **Identify Common User Errors:**  Think about how a programmer might misuse the library and how the tests catch those errors.

    * **`test_items_can_be_appended_to_and_removed_from_a_table()` and similar tests:** These demonstrate how to correctly add and remove items. A user error would be trying to remove a non-existent key, which is explicitly tested with `pytest.raises(NonExistentKey)`.
    * **Type Mismatches (implicitly):**  While not explicitly testing error handling for incompatible types in all cases, the focus on type conversions (e.g., int to float) suggests potential user errors if they expect different behavior.
    * **Incorrect Syntax (indirectly):** The parsing tests in `tomlkit` (although not directly in this file) are related to user errors in writing TOML. This test file verifies the *results* of correct parsing.

8. **Trace User Operations (Debugging Context):**  Consider how a user would end up running these tests.

    * **Developer Workflow:**  A developer working on the `frida-clr` project (which includes `tomlkit`) would run these tests as part of their development process to ensure their changes haven't broken existing functionality.
    * **CI/CD:**  These tests are likely part of a continuous integration system, automatically run whenever code changes are made.
    * **Manual Testing/Debugging:** If a bug is suspected in TOML handling, a developer might run these tests specifically to isolate the issue.

9. **Synthesize and Organize:** Group the identified functionalities and relationships into clear categories as requested by the prompt. Provide concrete examples from the code to illustrate each point.

10. **Refine and Review:** Read through the analysis to ensure it's accurate, well-organized, and addresses all parts of the prompt. Make sure the examples are relevant and easy to understand. For example, initially, I might have missed the connection to Frida's use case, so I'd go back and refine that aspect. Similarly, double-check the logical reasoning and user error sections for clarity and accuracy.
这个Python源代码文件 `test_items.py` 是 Frida 动态 instrumentation工具中 `tomlkit` 子项目的一部分。它的主要功能是**测试 `tomlkit` 库中各种数据项 (items) 的行为和特性**。`tomlkit` 是一个用于解析、操作和序列化 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。

以下是该文件功能的详细列表，并根据您的要求进行了分类和举例说明：

**1. 测试 `tomlkit` 中不同数据类型的表示和操作:**

* **基本数据类型:**
    * **整数 (Integer):** 测试整数的创建、解包 (`unwrap` 方法返回 Python 原生的 `int` 类型)、字符串表示 (`as_string` 方法返回 TOML 格式的字符串)。
        * **举例:** `test_integer_unwrap`, `test_hex_octal_and_bin_integers_are_supported`, `test_integers_behave_like_ints`
    * **浮点数 (Float):** 测试浮点数的创建、解包、字符串表示，以及对特殊值 (如 `inf` 和 `NaN`) 的支持。
        * **举例:** `test_float_unwrap`, `test_inf_and_nan_are_supported`, `test_floats_behave_like_floats`
    * **布尔值 (Bool):** 测试布尔值的创建、解包、字符串表示，以及布尔值的比较。
        * **举例:** `test_false_unwrap`, `test_true_unwrap`, `test_booleans_comparison`
    * **字符串 (String):** 测试字符串的创建、解包、字符串表示，包括不同类型的字符串 (基本字符串、多行字符串) 和转义字符的处理。
        * **举例:** `test_string_unwrap`, `test_strings_behave_like_strs`, `test_string_add_preserve_escapes`, `test_escape_key`
    * **空值 (Null):** 测试空值的创建和解包。
        * **举例:** `test_null_unwrap`
* **复合数据类型:**
    * **数组 (Array):** 测试数组的创建、解包 (返回 Python `list`)、字符串表示、元素的添加、删除、修改，以及多行数组的表示。
        * **举例:** `test_array_unwrap`, `test_array_behaves_like_a_list`, `test_array_multiline`, `test_append_to_empty_array`, `test_modify_array_with_comment`, `test_append_dict_to_array`, `test_array_add_line`
    * **内联表格 (InlineTable):** 测试内联表格的创建、解包 (返回 Python `dict`)、字符串表示、元素的添加和删除。
        * **举例:** `test_items_can_be_appended_to_and_removed_from_an_inline_table`, `test_trim_comments_when_building_inline_table`, `test_deleting_inline_table_element_does_not_leave_trailing_separator`
    * **表格 (Table):** 测试表格的创建、解包 (返回 Python `dict`)、字符串表示、元素的添加和删除，以及将 Python 字典转换为 TOML 表格的过程。
        * **举例:** `test_items_can_be_appended_to_and_removed_from_a_table`, `test_abstract_table_unwrap`, `test_tables_behave_like_dicts`, `test_dicts_are_converted_to_tables`, `test_dicts_with_sub_dicts_are_properly_converted`
    * **数组中的表格 (Array of Tables - AOT):** 测试将包含字典的 Python 列表转换为 TOML 的数组中的表格。
        * **举例:** `test_aot_unwrap`, `test_item_array_of_dicts_converted_to_aot`
* **日期和时间类型:**
    * **日期时间 (Datetime):** 测试日期时间的创建、解包、字符串表示，以及日期时间的算术运算。
        * **举例:** `test_datetime_unwrap`, `test_datetimes_behave_like_datetimes`, `test_parse_datetime_followed_by_space`
    * **日期 (Date):** 测试日期的创建、解包、字符串表示，以及日期的算术运算。
        * **举例:** `test_date_unwrap`, `test_dates_behave_like_dates`
    * **时间 (Time):** 测试时间的创建、解包和字符串表示。
        * **举例:** `test_time_unwrap`, `test_times_behave_like_times`

**2. 与逆向方法的关系 (间接关系):**

这个测试文件本身并不直接进行逆向操作，但它测试的 `tomlkit` 库在 Frida 的上下文中可能用于以下逆向相关的场景：

* **解析和修改应用程序的配置文件:** 许多应用程序使用 TOML 作为配置文件格式。Frida 可以使用 `tomlkit` 读取、修改目标应用程序的配置文件，从而改变其行为。
    * **举例:** 假设一个 Android 应用程序的配置文件 `config.toml` 中包含一个调试标志 `debug_enabled = false`。一个 Frida 脚本可以使用 `tomlkit` 解析这个文件，将 `debug_enabled` 的值改为 `true`，然后将修改后的配置写回，从而启用应用程序的调试模式，以便进行更深入的分析。
* **动态修改应用程序的内部数据结构 (间接):**  虽然 `tomlkit` 操作的是 TOML 文件，但在某些情况下，应用程序可能会将 TOML 配置加载到内存中的数据结构。理解 TOML 的结构和如何用 `tomlkit` 操作它可以帮助逆向工程师理解和修改这些内存中的数据。
* **Frida 脚本的配置:** Frida 脚本本身可能使用 TOML 文件来管理其自身的配置，例如要 hook 的函数、要修改的内存地址等。`tomlkit` 用于解析这些配置。

**3. 涉及到二进制底层，Linux, Android 内核及框架的知识 (间接关系):**

* **数据序列化和反序列化:** TOML 是一种文本格式，但最终需要被解析成内存中的数据结构，并在需要时被序列化回文本。这涉及到数据在不同表示形式之间的转换，是计算机底层操作的基础。
* **文件系统操作:**  读取和写入 TOML 配置文件涉及到操作系统提供的文件系统 API。虽然测试代码本身没有直接调用这些 API，但 `tomlkit` 库在实际使用中会依赖它们。在 Linux 和 Android 上，这涉及到系统调用。
* **字符编码:** TOML 文件是文本文件，需要处理字符编码问题 (通常是 UTF-8)。理解字符编码对于正确解析和生成 TOML 文件至关重要，这涉及到操作系统和编程语言的字符处理机制。

**4. 逻辑推理 (基于测试用例):**

测试用例通常会设定特定的输入和预期输出，以验证代码的逻辑是否正确。

* **假设输入:** 一个包含 TOML 数据的字符串，例如 `"[table]\nkey = \"value\""`。
* **预期输出:**  使用 `tomlkit` 解析后，应该得到一个表示该 TOML 结构的 Python 对象，例如一个字典 `{'table': {'key': 'value'}}`。测试用例会断言解析结果是否符合预期。
* **假设输入:**  一个 `tomlkit` 的 `Table` 对象，添加一个新的键值对。
* **预期输出:** `Table` 对象的字符串表示会更新，包含新添加的键值对，并且格式符合 TOML 规范。

**5. 涉及用户或者编程常见的使用错误:**

测试用例也会覆盖一些常见的用户错误情况。

* **尝试访问不存在的键:** `test_items_can_be_appended_to_and_removed_from_a_table` 和 `test_items_can_be_appended_to_and_removed_from_an_inline_table` 中使用了 `pytest.raises(NonExistentKey)` 来测试尝试删除不存在的键时是否会抛出正确的异常。这是用户在使用字典或表格时常见的错误。
* **不正确的 TOML 语法 (间接):** 虽然这个测试文件不直接测试解析错误，但如果用户编写了不符合 TOML 规范的字符串，`tomlkit` 的解析器会抛出异常。开发人员编写测试用例时会考虑到这些常见的语法错误。
* **类型不匹配 (隐式):**  测试用例中对不同数据类型进行操作，例如 `test_add_float_to_int` 测试了将浮点数加到整数上，验证了 `tomlkit` 的处理方式。用户可能会错误地期望不同类型的操作会产生不同的结果。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

作为 Frida 的开发人员或用户，可能会在以下情况下接触到这个测试文件：

1. **开发 `tomlkit` 库:** 如果您正在开发或维护 `tomlkit` 库，您会编写和运行这些测试用例来确保代码的正确性。您可能会修改代码，然后运行这些测试来验证您的修改没有引入新的错误。
2. **开发 `frida-clr` 子项目:**  `tomlkit` 是 `frida-clr` 的一个子项目。如果您正在开发 `frida-clr` 的功能，并且该功能涉及到读取或操作 TOML 配置文件，您可能会需要调试与 `tomlkit` 相关的代码。这时，您可以查看这些测试用例来了解 `tomlkit` 的预期行为，或者编写新的测试用例来复现您遇到的问题。
3. **使用 Frida 脚本时遇到与 TOML 解析相关的问题:** 如果您编写了一个 Frida 脚本，该脚本使用 `tomlkit` 解析 TOML 文件，并且遇到了错误，您可能会查阅 `tomlkit` 的文档和测试用例来寻找问题的原因。您可能会尝试运行相关的测试用例来验证 `tomlkit` 的行为是否符合预期。
4. **贡献代码到 Frida 项目:** 如果您想为 Frida 项目贡献代码，您可能会需要理解现有的测试用例，并为您的新代码编写相应的测试用例。

**总而言之，`test_items.py` 是 `tomlkit` 库的核心测试文件，它详细测试了库中各种数据项的创建、操作和序列化行为。虽然它不直接进行逆向操作，但它测试的库在 Frida 的上下文中可以用于解析和修改应用程序的配置文件，这在逆向工程中是一个常见的需求。理解这些测试用例有助于开发人员确保 `tomlkit` 库的正确性，也有助于 Frida 用户理解如何使用该库以及如何调试与之相关的问题。**

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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