Response:
The user wants to understand the functionality of the Python code provided. I need to go through the code and identify its purpose, relating it to reverse engineering, low-level concepts, and potential user errors.

**Plan:**

1. **Overall Functionality:** Determine the main goal of the code. It seems to be testing functionality related to parsing and manipulating TOML data structures.
2. **Reverse Engineering Relevance:** Identify if any part of the code or the TOML format itself is useful in reverse engineering scenarios.
3. **Binary/Kernel/Framework Knowledge:** Look for any interactions or representations of low-level concepts.
4. **Logical Reasoning:**  Find examples where the code tests specific input-output scenarios based on logical rules or assumptions.
5. **User Errors:** Identify common mistakes a user might make when using this library or interacting with TOML.
6. **Debugging Scenario:**  Describe how a user might end up in this code as part of a debugging process.
这个Python源代码文件 `test_items.py` 是 `frida-tools` 项目中 `tomlkit` 子项目的一部分。`tomlkit` 是一个用于解析、操作和生成 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。`test_items.py` 的主要功能是 **测试 `tomlkit` 库中表示 TOML 数据项的各种类的功能和行为**。

具体来说，它测试了以下功能：

1. **TOML 数据类型的表示和解包 (Unwrapping):**
    *   测试了各种 TOML 数据类型（如整数、浮点数、布尔值、日期时间、字符串、数组、表格等）对应的 Python 类的 `unwrap()` 方法，该方法将 `tomlkit` 的项对象转换回 Python 的原生数据类型。
    *   例如，`test_integer_unwrap()` 测试了 `item(666)` (一个 `tomlkit.items.Integer` 对象) 的 `unwrap()` 方法是否返回 Python 的 `int` 类型。

2. **TOML 数据项的比较:**
    *   测试了 `tomlkit.items.Key` 对象的比较操作，确保它可以与字符串或其他 `Key` 对象正确比较。
    *   例如，`test_key_comparison()` 测试了 `Key("foo")` 是否等于字符串 `"foo"`。

3. **表格 (Table) 和内联表格 (Inline Table) 的操作:**
    *   测试了向表格和内联表格中添加和删除条目的功能。
    *   例如，`test_items_can_be_appended_to_and_removed_from_a_table()` 测试了使用 `append()` 和 `remove()` 方法向 `tomlkit.items.Table` 对象中添加和删除键值对。

4. **支持 TOML 的特定语法:**
    *   测试了对 TOML 中特殊数值表示的支持，如 `inf` (无穷大), `-inf` (负无穷大) 和 `NaN` (非数字)。
    *   例如，`test_inf_and_nan_are_supported()` 测试了 `tomlkit` 能否正确解析包含 `inf` 和 `NaN` 的 TOML 文件。
    *   测试了对十六进制、八进制和二进制整数的支持。
    *   例如，`test_hex_octal_and_bin_integers_are_supported()` 测试了 `tomlkit` 能否正确解析不同进制的整数。

5. **数组 (Array) 的操作:**
    *   测试了 `tomlkit.items.Array` 对象的各种列表操作，如添加元素、删除元素、修改元素等。
    *   例如，`test_array_behaves_like_a_list()` 测试了 `Array` 对象是否能像 Python 的 `list` 一样进行切片、追加、删除等操作。
    *   测试了多行数组的表示和修改。

6. **将 Python 字典转换为 TOML 表格:**
    *   测试了将 Python 字典转换为 `tomlkit` 表格对象的功能，包括保持顺序和排序。
    *   例如，`test_dicts_are_converted_to_tables()` 测试了将 Python 字典传递给 `item()` 函数后，是否能生成正确的 TOML 表格字符串。

7. **不同数据类型之间的运算:**
    *   测试了 `tomlkit` 的数值类型（如 `Integer`）与 Python 的数值类型之间的运算，以及运算后类型的转换。
    *   例如，`test_add_float_to_int()` 测试了将浮点数加到 `tomlkit.items.Integer` 对象上后，对象是否变成了 `float` 类型。

8. **各种 TOML 数据类型的行为:**
    *   测试了 `tomlkit` 中表示日期、时间、日期时间、字符串等对象的行为，包括比较、运算和字符串表示。
    *   例如，`test_datetimes_behave_like_datetimes()` 测试了 `tomlkit.items.DateTime` 对象的加减 `timedelta` 操作。

9. **对象的序列化 (Pickling):**
    *   测试了 `tomlkit` 的项对象是否可以被 `pickle` 模块序列化和反序列化。

10. **内联表格的注释处理:**
    *   测试了在构建内联表格时如何处理注释。

11. **布尔值的比较:**
    *   测试了 `tomlkit.items.Bool` 对象的布尔值行为。

12. **对象的复制 (Copying):**
    *   测试了 `tomlkit` 的表格和数组对象的浅拷贝功能。

13. **键的转义:**
    *   测试了 `tomlkit` 如何转义键名中的特殊字符。

14. **自定义编码器:**
    *   测试了 `tomlkit` 允许用户注册自定义编码器来处理特定类型的对象。

**与逆向方法的关联：**

这个文件本身更多的是关于 TOML 格式的解析和操作，直接的逆向关联较少。然而，在逆向工程中，配置文件经常采用不同的格式，包括 TOML。`tomlkit` 这样的库可以用于：

*   **解析逆向目标程序的配置文件:**  如果一个逆向目标程序使用 TOML 格式存储配置信息，可以使用 `tomlkit` 来解析这些配置文件，提取关键参数，辅助理解程序行为。
    *   **举例:** 假设你逆向一个 Android 应用，发现它的 native 代码读取了一个名为 `config.toml` 的文件。你可以使用 `tomlkit` 解析这个文件，找到服务器地址、API 密钥等信息。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

这个文件本身并没有直接涉及到这些底层知识。它主要关注的是 TOML 格式的抽象表示。然而，`frida` 工具本身是一个动态插桩工具，会涉及到这些底层知识。`tomlkit` 作为 `frida-tools` 的一部分，其应用场景可能会涉及到：

*   **Frida 脚本配置:**  Frida 脚本可能使用 TOML 文件来配置一些选项，例如 hook 的函数地址、要修改的内存地址等。这些地址和信息是与二进制底层相关的。
*   **Frida 模块配置:**  一些 Frida 模块可能使用 TOML 文件来定义它们的行为，这些行为可能涉及到操作系统 API、内核结构等。

**逻辑推理：**

代码中充满了逻辑推理的测试用例。以下是一个例子：

*   **假设输入:** 一个包含整数的 `tomlkit.items.Integer` 对象。
*   **操作:** 调用其 `unwrap()` 方法。
*   **预期输出:**  一个 Python 的 `int` 类型的值，并且值与原始的整数相同。
*   **代码体现:** `test_integer_unwrap()` 函数验证了这个逻辑。

**用户或编程常见的使用错误：**

这个测试文件也间接地反映了一些用户可能犯的错误：

*   **尝试解包 (unwrap) 基类 `Item`:** 用户可能会尝试直接调用 `tomlkit.items.Item` 基类的 `unwrap()` 方法，这是不允许的，会抛出 `NotImplementedError`。`test_item_base_has_no_unwrap()` 就测试了这个情况。
*   **尝试删除不存在的键:**  用户可能会尝试从表格或内联表格中删除不存在的键，这会抛出 `NonExistentKey` 异常。`test_items_can_be_appended_to_and_removed_from_a_table()` 和 `test_items_can_be_appended_to_and_removed_from_an_inline_table()` 中就测试了这种情况。
*   **在应该使用值的地方使用了空格或注释:** 用户可能在构建数组时，在不应该出现空格或注释的地方使用了它们，`test_array_add_line_invalid_value()` 检查了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

一个开发人员或用户可能在以下情况下会接触到这个测试文件，作为调试线索：

1. **提交代码到 `frida-tools` 项目:**  如果开发者修改了 `tomlkit` 库中关于数据项表示的代码，他们会运行这些测试来确保他们的修改没有破坏现有的功能。测试失败会提供调试线索。
2. **使用 `tomlkit` 库遇到问题:**  用户在使用 `tomlkit` 解析或操作 TOML 文件时遇到意外行为，可能会查看相关的测试文件，例如 `test_items.py`，来理解库的预期行为，或者找到类似的测试用例来帮助他们理解问题。
3. **调试 `frida-tools` 的相关功能:**  如果 `frida-tools` 的某个功能依赖于 `tomlkit` 来处理配置文件，并且该功能出现问题，开发者可能会需要深入到 `tomlkit` 的代码中进行调试，这时 `test_items.py` 可以作为理解 `tomlkit` 内部工作原理的参考。
4. **学习 `tomlkit` 库的用法:**  新的开发者可能通过阅读测试文件来学习如何使用 `tomlkit` 库的各种 API，例如如何创建和操作不同类型的 TOML 数据项。

总而言之，`test_items.py` 是 `tomlkit` 库的核心测试文件，它详细地测试了各种 TOML 数据项的表示和操作，对于理解 `tomlkit` 库的功能和调试相关问题至关重要。虽然它本身不直接涉及逆向的二进制层面，但 `tomlkit` 作为配置文件解析库，在逆向工程中处理 TOML 格式的配置文件时是有应用价值的。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```