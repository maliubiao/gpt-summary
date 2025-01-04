Response:
Let's break down the thought process for analyzing this Python code.

1. **Understand the Goal:** The request asks for the *functionality* of the code, its relation to *reverse engineering*, *low-level details*, *logical inference*, *common user errors*, and the *user journey* to this code. The file path `frida/subprojects/frida-python/releng/tomlkit/tests/test_items.py` immediately suggests this is a *test suite* for a TOML library (`tomlkit`) within the Frida project.

2. **Initial Scan and Keyword Spotting:** Quickly skim the code, looking for familiar programming concepts and relevant terms:
    * `import`:  Lots of standard Python libraries (`datetime`, `math`, `pickle`) and `pytest` (for testing). Crucially, imports from `tomlkit` and its submodules (`api`, `parse`, `exceptions`, `items`, `parser`).
    * `@pytest.fixture()`: Indicates setup functions for tests. `tz_pst` and `tz_utc` suggest handling of timezones, which can be tricky.
    * `def test_*()`:  The core of the test suite. Each function tests a specific aspect.
    * `unwrap()`:  Appears frequently, suggesting a core functionality of the `tomlkit` library – converting internal representations to standard Python types.
    * `assert`:  Used extensively for verifying expected outcomes.
    * `append()`, `remove()`, `update()`, `pop()`, `insert()`, `clear()`: Standard list/dictionary operations, likely being tested for their interaction with `tomlkit`'s data structures.
    * `as_string()`:  Indicates a method for converting `tomlkit` objects back to their string representation.
    * `parse()`:  Function to parse TOML strings.
    * Specific TOML features: "inf", "nan", hex/octal/binary integers, multiline arrays, inline tables.

3. **Categorize Functionality based on Test Names:**  The test function names are highly descriptive. Group them mentally or in a list:
    * **`unwrap` testing:** `test_item_base_has_no_unwrap`, `test_integer_unwrap`, etc. This is a primary focus.
    * **Key operations:** `test_key_comparison`, `test_key_automatically_sets_proper_string_type_if_not_bare`.
    * **Table/InlineTable manipulation:** `test_items_can_be_appended_to_and_removed_from_a_table`, `test_items_can_be_appended_to_and_removed_from_an_inline_table`.
    * **TOML feature testing:** `test_inf_and_nan_are_supported`, `test_hex_octal_and_bin_integers_are_supported`.
    * **Array behavior:** `test_array_behaves_like_a_list`, `test_array_multiline`, etc.
    * **Type coercion and arithmetic:** `test_add_float_to_int`, `test_integers_behave_like_ints`, `test_datetimes_behave_like_datetimes`, etc.
    * **String behavior:** `test_strings_behave_like_strs`, `test_string_add_preserve_escapes`.
    * **Dictionary/Table behavior:** `test_tables_behave_like_dicts`.
    * **Serialization:** `test_items_are_pickable`.
    * **Edge cases and error handling:** Tests involving comments, trailing separators, `NonExistentKey`.
    * **Copying:** `test_table_copy`, `test_copy_copy`.
    * **Key escaping:** `test_escape_key`.
    * **Customization:** `test_custom_encoders`.

4. **Connect to Reverse Engineering (Frida Context):**  Consider how this TOML library fits within Frida. Frida is for *dynamic instrumentation*. Configuration is crucial. TOML is a human-readable format often used for configuration. Thus, `tomlkit` likely helps Frida's Python bindings parse configuration files used to define instrumentation logic, script behavior, or connection parameters. *Example:*  A Frida script configuration file might specify target processes, function hooks, and data to intercept, all defined in TOML.

5. **Relate to Low-Level/Kernel/Framework:**  TOML itself isn't inherently low-level. However, *how Frida uses* the parsed information is. The configuration could instruct Frida to interact with:
    * **Binary Structure:**  Specifying memory addresses or offsets.
    * **Linux/Android Kernel:** Defining system calls to trace or modify.
    * **Android Framework:** Targeting specific Java classes or methods. *Example:*  A TOML config could specify hooking `android.app.Activity.onCreate`.

6. **Identify Logical Inference (with Hypothetical Inputs/Outputs):**  Look for tests where the outcome isn't immediately obvious and involves some internal logic. Good examples are the array manipulation tests (multiline, adding with comments).
    * *Hypothetical Input (for `test_array_multiline_modify`):*  A TOML string with a single-element multiline array.
    * *Logical Step:* The test appends and inserts elements, which requires `tomlkit` to correctly adjust the formatting (newlines, indentation, commas).
    * *Expected Output:* The correctly formatted TOML string after modification.

7. **Spot Common User Errors:** Focus on tests that handle exceptions or unusual input.
    * `test_items_can_be_appended_to_and_removed_from_a_table` with `NonExistentKey`:  Illustrates trying to remove a non-existent key.
    * The array modification tests with comments highlight potential issues with maintaining formatting when manually editing TOML.
    * Incorrect data types being assigned could also be a source of errors, though this test suite focuses on the *library's* behavior, not explicit user input validation.

8. **Trace the User Journey (Debugging Clues):** Imagine a developer using Frida:
    1. Writes a Frida script that relies on a TOML configuration file.
    2. Runs the script, and it doesn't behave as expected.
    3. Suspects the configuration is being parsed incorrectly.
    4. Might use debugging tools to inspect the parsed TOML data structures within the Frida script.
    5. If they suspect a bug in `tomlkit`, they might look at the `tomlkit` codebase and potentially run these very test cases to understand how `tomlkit` handles different TOML constructs. The file path itself indicates this is part of the `tomlkit` test suite, a key debugging resource for developers working on or using this library.

9. **Refine and Structure:** Organize the findings into logical sections as requested by the prompt. Use clear language and provide concrete examples where possible. Ensure the answer flows well and addresses all aspects of the initial request. Use bullet points and code snippets for clarity.

This systematic approach, combining code scanning, understanding the project context, and thinking about user scenarios, allows for a comprehensive analysis of the test file's purpose and implications.
这个Python源代码文件 `test_items.py` 是 `fridaDynamic instrumentation tool` 中 `tomlkit` 子项目的一部分。 `tomlkit` 是一个用于解析和操作 TOML (Tom's Obvious, Minimal Language) 文件的库。 这个测试文件专门用于测试 `tomlkit` 库中各种数据项（Items）的创建、操作和行为。

以下是 `test_items.py` 的功能列表：

**核心功能：测试 `tomlkit.items` 模块中的各种数据项类的功能，包括：**

* **基本数据类型:**
    * `Integer`: 测试整数的创建、解包（unwrap）为Python的 `int` 类型，以及算术运算。
    * `String`: 测试字符串的创建、解包为Python的 `str` 类型，以及字符串拼接操作。
    * `Bool`: 测试布尔值的创建和解包为Python的 `bool` 类型，以及布尔值的真假判断。
    * `Float`: 测试浮点数的创建和解包为Python的 `float` 类型。
    * `Null`: 测试空值的创建和解包为Python的 `None` 类型。
* **复合数据类型:**
    * `Array`: 测试数组（列表）的创建、解包为Python的 `list` 类型，以及列表的增删改查操作（`append`, `remove`, `insert`, `pop`, `clear`），包括多行数组的处理。
    * `Table`: 测试表格（字典）的创建、解包为Python的 `dict` 类型，以及字典的增删改查操作（`append`, `remove`, `update`, `get`, `setdefault`）。
    * `InlineTable`: 测试内联表格的创建、解包和操作，类似于单行字典。
* **日期和时间类型:**
    * `Datetime`: 测试日期时间对象的创建和解包为Python的 `datetime` 类型，以及日期时间的算术运算（`timedelta`）。
    * `Date`: 测试日期对象的创建和解包为Python的 `date` 类型，以及日期的算术运算。
    * `Time`: 测试时间对象的创建和解包为Python的 `time` 类型。
* **其他 Item 类:**
    * `Key`: 测试键的创建和比较。
    * `Comment`: 虽然没有直接测试 `Comment` 类的功能，但在其他测试中涉及到注释的处理。
    * `Trivia`:  测试空白符和注释的存储和处理，用于保持 TOML 文件的格式。

**具体功能点：**

* **解包 (unwrap):** 测试将 `tomlkit` 的数据项对象转换回 Python 原生数据类型的功能。
* **字符串表示 (as_string):** 测试将 `tomlkit` 的数据项对象转换回 TOML 字符串表示的功能，包括格式化（例如多行数组）。
* **比较操作:** 测试 `tomlkit` 数据项之间的比较，以及数据项与 Python 原生类型之间的比较。
* **增删改查操作:** 测试对数组和表格进行添加、删除和修改操作。
* **类型转换:** 测试在某些操作下，数据项的类型是否会发生转换（例如，整数加浮点数变为浮点数）。
* **特殊值处理:** 测试对 TOML 中的特殊值（如 `inf`, `-inf`, `nan`）和不同进制整数的支持。
* **Pickle 序列化:** 测试 `tomlkit` 的数据项对象是否可以被 `pickle` 模块序列化和反序列化。
* **自定义编码器:** 测试用户可以注册自定义的编码器来处理特定类型的 Python 对象。
* **拷贝操作:** 测试 `tomlkit` 数据项的拷贝行为 (浅拷贝)。

**与逆向方法的关系：**

`tomlkit` 作为一个 TOML 解析库，在逆向工程中常用于处理和分析应用的配置文件。许多应用程序使用 TOML 格式来存储配置信息。

**举例说明：**

假设一个 Android 应用使用 TOML 文件存储其网络配置，例如 API 地址、超时时间等。逆向工程师可以使用 Frida 注入到该应用进程中，并使用 `tomlkit` 库来解析该应用的 TOML 配置文件，从而获取关键的配置信息，用于进一步的分析或修改。

例如，可以编写一个 Frida 脚本，使用 `tomlkit` 读取配置文件，找到 API 地址，并 Hook 网络请求相关的函数，来观察或修改应用发出的请求目标。

**涉及到二进制底层，Linux, Android 内核及框架的知识：**

这个测试文件本身并不直接涉及二进制底层、Linux/Android 内核及框架的知识。它的主要关注点是如何正确地解析和操作 TOML 格式的数据。

但是，`tomlkit` 作为 Frida 生态系统的一部分，其最终目的是为了辅助动态分析和 instrumentation。因此，解析出的 TOML 配置信息 *可能* 会间接地影响到与这些底层知识相关的操作。

**举例说明：**

* **二进制底层:** TOML 配置文件可能包含需要 Hook 的函数的内存地址或偏移量。`tomlkit` 解析这些信息后，Frida 可以根据这些地址在内存中进行 Hook 操作。
* **Linux 内核:** 配置文件可能定义了需要跟踪的系统调用。Frida 可以读取这些配置，并使用 Linux 内核提供的跟踪机制（如 `ptrace` 或 eBPF）来监控这些系统调用。
* **Android 框架:** 配置文件可能指定了需要 Hook 的 Android Framework 的类和方法。Frida 可以利用 Android 的运行时环境 (ART) 或 Dalvik 的机制来拦截和修改这些方法的行为。

**逻辑推理（假设输入与输出）：**

测试用例中充满了逻辑推理的例子。以下举一个例子：

**假设输入 (TOML 字符串):**

```toml
array_of_ints = [ 1, 2, 3 ]
```

**测试代码片段:**

```python
def test_array_behaves_like_a_list():
    a = item([1, 2])
    assert a == [1, 2]
    assert a.as_string() == "[1, 2]"

    a += [3, 4]
    assert a == [1, 2, 3, 4]
    assert a.as_string() == "[1, 2, 3, 4]"
```

**逻辑推理:**

1. 创建一个 `tomlkit.items.Array` 对象 `a`，初始包含元素 `1` 和 `2`。
2. 断言 `a` 与 Python 列表 `[1, 2]` 相等。
3. 断言 `a` 转换为 TOML 字符串后为 `"[1, 2]"`。
4. 使用 `+=` 操作符向 `a` 中添加元素 `3` 和 `4`。
5. 断言 `a` 与 Python 列表 `[1, 2, 3, 4]` 相等。
6. 断言 `a` 转换为 TOML 字符串后为 `"[1, 2, 3, 4]"`。

**输出:** 如果断言都通过，则说明 `tomlkit.items.Array` 对象在行为上与 Python 列表类似，并且其字符串表示符合预期。

**涉及用户或者编程常见的使用错误：**

* **尝试访问不存在的 Key:** `test_items_can_be_appended_to_and_removed_from_a_table` 中测试了删除不存在的 Key 会抛出 `NonExistentKey` 异常。这是用户常见的错误，因为在访问或操作字典时，需要确保 Key 的存在。
* **类型不匹配:** 虽然测试中没有直接展示用户的类型错误，但是测试了类型转换的行为（例如整数加浮点数），这暗示了用户可能因为类型不匹配而导致程序行为不符合预期。
* **TOML 格式错误:** 这个测试文件本身侧重于 `tomlkit` 库的功能，没有直接测试 TOML 格式错误的处理。但是，如果用户提供的 TOML 文件格式不正确，`tomlkit` 的解析器会抛出异常。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要使用 Frida 进行动态 instrumentation。**
2. **用户的目标应用使用了 TOML 文件来存储配置信息。**
3. **用户需要在 Frida 脚本中读取和解析该 TOML 文件，以便根据配置执行相应的 instrumentation 操作。**
4. **用户使用了 `frida-python` 提供的 `tomlkit` 库来解析 TOML 文件。**
5. **在开发或调试 Frida 脚本的过程中，用户可能遇到了与 TOML 数据项处理相关的问题，例如：**
    *  从 TOML 文件中读取的值类型不正确。
    *  对 TOML 数据进行操作后，其字符串表示不符合预期。
    *  尝试访问或修改不存在的配置项。
6. **为了理解 `tomlkit` 的行为或排查问题，用户可能会查看 `tomlkit` 的源代码，包括测试文件 `test_items.py`。**
7. **用户可以通过阅读 `test_items.py` 中的测试用例，了解 `tomlkit` 如何处理各种 TOML 数据类型，以及如何进行常见的操作。**
8. **例如，如果用户在处理数组时遇到了问题，他们可以查看 `test_array_behaves_like_a_list` 或 `test_array_multiline` 等测试用例，了解数组的预期行为和用法。**
9. **如果用户尝试删除一个表格中不存在的键，并遇到了错误，他们可以查看 `test_items_can_be_appended_to_and_removed_from_a_table` 中关于 `NonExistentKey` 的测试，从而理解错误的原因。**

总而言之，`test_items.py` 是 `tomlkit` 库的核心测试文件，它详细地测试了库中各种数据项的功能和行为。对于使用 Frida 进行逆向工程并需要处理 TOML 配置文件的用户来说，理解这个测试文件的内容可以帮助他们更好地使用 `tomlkit` 库，并排查可能遇到的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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