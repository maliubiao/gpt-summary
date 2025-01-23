Response:
My thought process to answer the request goes through these stages:

1. **Understand the Core Task:** The primary goal is to analyze the given Python code (a test suite for a TOML parsing library) and describe its functionality, specifically looking for connections to reverse engineering, low-level aspects, logical reasoning, common errors, and debugging.

2. **Identify the Library Under Test:** The code clearly tests a library named "tomlkit". Knowing this is crucial because the tests' purpose is to verify the correct behavior of *tomlkit*.

3. **Analyze Imports and Fixtures:**  The imports (`datetime`, `math`, `pickle`, `pytest`, `tomlkit.*`) and pytest fixtures (`tz_pst`, `tz_utc`) provide key insights. They reveal the data types `tomlkit` handles (integers, floats, booleans, strings, dates, times, arrays, tables/dictionaries) and the testing framework used. The fixtures are about handling timezones, which is relevant for accurate date/time parsing.

4. **Categorize Test Functions:**  I'll go through each `test_` function and try to categorize its purpose. Common patterns emerge:
    * **`test_*_unwrap`:** These functions test the `unwrap()` method, which converts `tomlkit`'s internal representations back to standard Python types.
    * **`test_*_comparison`:** These verify equality and inequality operations.
    * **`test_items_can_be_appended_to_and_removed_from_*`:** These focus on modifying TOML structures (tables and inline tables).
    * **`test_*_are_supported`:**  These check if `tomlkit` correctly parses and represents specific TOML features (like infinity, NaN, different integer bases).
    * **`test_*_behaves_like_*`:**  These ensure that `tomlkit` objects act similarly to their Python counterparts (lists, dictionaries, etc.) with respect to operators and methods.
    * **Tests involving `as_string()`:**  These verify that `tomlkit` can correctly serialize its internal representation back to a TOML string.
    * **Tests involving `parse()`:** These check the library's ability to read and interpret TOML strings.
    * **Tests involving `copy` and `pickle`:** These examine the ability to create independent copies and serialize/deserialize `tomlkit` objects.

5. **Connect to the Request's Specific Points:** Now, I'll revisit the request's requirements and see how the analyzed tests relate:

    * **Functionality:** This is the most straightforward. I'll summarize the various aspects being tested (parsing different data types, manipulating tables and arrays, serialization, etc.).

    * **Reverse Engineering:** This requires more thought. While the tests themselves *aren't* reverse engineering, they *support* a tool (Frida) that *is* used for dynamic analysis, a form of reverse engineering. The ability to parse and manipulate configuration files (like TOML) is crucial for Frida's flexibility and control over target processes. I'll give examples of how TOML could be used in Frida scripts for configuring hooks, specifying addresses, etc.

    * **Binary/Low-Level, Linux/Android Kernel/Framework:**  Again, the tests are high-level Python. However, I'll connect `tomlkit`'s role to the broader context of Frida. Frida interacts with the target process at a low level. Configuration through TOML could influence *how* Frida interacts – which functions to hook, memory addresses to access, etc. This indirectly links the tests to these lower-level aspects.

    * **Logical Reasoning (Input/Output):** Many tests demonstrate logical reasoning. I'll pick a few good examples where the input TOML string and the expected output (either the parsed Python object or the serialized TOML string) are clear. The array manipulation tests are good candidates here.

    * **User/Programming Errors:**  The tests with `pytest.raises` explicitly check for error conditions. I'll highlight these as examples of anticipated user errors (like trying to remove a non-existent key). I can also discuss common mistakes users might make when writing TOML that `tomlkit` would catch.

    * **User Operation/Debugging:** I'll explain the typical workflow: a user writes a Frida script (which might use TOML for configuration), and if something goes wrong, these unit tests help ensure that the TOML parsing part of Frida is working correctly. This provides a debugging angle.

6. **Structure the Answer:** I'll organize the answer according to the request's categories to make it clear and easy to follow. I'll use headings and bullet points.

7. **Refine and Elaborate:**  I'll review my answer, ensuring the explanations are clear, concise, and provide enough context. I'll make sure the examples are relevant and easy to understand. For instance, when discussing reverse engineering, I'll give concrete examples of Frida use cases where TOML would be beneficial.

By following these steps, I can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the request. The key is to not just describe what the tests *do*, but also to connect them to the broader context of Frida and the concepts mentioned in the prompt.
这个Python文件 `test_items.py` 是 Frida 动态 instrumentation 工具中 `tomlkit` 子项目的一个测试文件。 `tomlkit` 是一个用于解析和操作 TOML (Tom's Obvious, Minimal Language) 配置文件的库。 这个测试文件的主要功能是验证 `tomlkit` 库中各种表示 TOML 数据项的类的行为是否符合预期。

下面详细列举一下它的功能，并根据你的要求进行说明：

**1. 验证 TOML 数据项的解析和表示：**

*   **基本数据类型：** 测试了 `tomlkit` 如何表示和处理 TOML 中的基本数据类型，例如：
    *   **Integer (整数):**  `test_integer_unwrap`, `test_hex_octal_and_bin_integers_are_supported`, `test_integers_behave_like_ints`
    *   **Float (浮点数):** `test_float_unwrap`, `test_inf_and_nan_are_supported`, `test_floats_behave_like_floats`, `test_add_float_to_int`, `test_sub_float_from_int`, `test_sub_int_from_float`, `test_add_sum_int_with_float`
    *   **Boolean (布尔值):** `test_false_unwrap`, `test_true_unwrap`, `test_booleans_comparison`
    *   **String (字符串):** `test_string_unwrap`, `test_strings_behave_like_strs`, `test_string_add_preserve_escapes`, `test_escape_key`
    *   **Datetime (日期时间):** `test_datetime_unwrap`, `test_datetimes_behave_like_datetimes`, `test_parse_datetime_followed_by_space`
    *   **Date (日期):** `test_date_unwrap`, `test_dates_behave_like_dates`
    *   **Time (时间):** `test_time_unwrap`, `test_times_behave_like_times`
    *   **Null (空值):** `test_null_unwrap`

*   **复杂数据类型：**
    *   **Array (数组):** `test_array_unwrap`, `test_array_behaves_like_a_list`, `test_array_multiline`, `test_array_multiline_modify`, `test_append_to_empty_array`, `test_modify_array_with_comment`, `test_append_to_multiline_array_with_comment`, `test_append_dict_to_array`, `test_array_add_line`, `test_array_add_line_invalid_value`, `test_item_array_of_dicts_converted_to_aot`, `test_copy_copy`
    *   **Table (表格/字典):** `test_abstract_table_unwrap`, `test_items_can_be_appended_to_and_removed_from_a_table`, `test_dicts_are_converted_to_tables`, `test_dicts_are_converted_to_tables_and_keep_order`, `test_dicts_are_converted_to_tables_and_are_sorted_if_requested`, `test_dicts_with_sub_dicts_are_properly_converted`, `test_tables_behave_like_dicts`, `test_trim_comments_when_building_inline_table`, `test_deleting_inline_table_element_does_not_leave_trailing_separator`, `test_deleting_inline_table_element_does_not_leave_trailing_separator2`, `test_table_copy`
    *   **Inline Table (内联表格/字典):** `test_items_can_be_appended_to_and_removed_from_an_inline_table`

**2. 验证 `unwrap()` 方法：**

*   许多测试函数（如 `test_integer_unwrap`, `test_string_unwrap` 等）都使用了 `unwrap()` 方法。这个方法的作用是将 `tomlkit` 内部表示的 TOML 数据项转换回对应的 Python 原生类型。这对于在 Python 代码中使用解析后的 TOML 数据至关重要。

**3. 验证数据项的比较操作：**

*   `test_key_comparison`: 验证 `Key` 对象的比较行为。
*   其他一些测试也隐含地验证了不同类型数据项的比较，例如数组和字典的比较。

**4. 验证数据项的修改操作：**

*   测试了向 `Table` 和 `InlineTable` 添加和删除键值对的功能 (`test_items_can_be_appended_to_and_removed_from_a_table`, `test_items_can_be_appended_to_and_removed_from_an_inline_table`)。
*   测试了 `Array` 对象的类似列表的操作，例如追加、删除、修改元素 (`test_array_behaves_like_a_list`, `test_array_multiline_modify`, `test_append_to_empty_array`, `test_modify_array_with_comment`, `test_append_to_multiline_array_with_comment`)。
*   测试了对数值类型（整数、浮点数）、日期时间、字符串等进行加减等操作的行为 (`test_integers_behave_like_ints`, `test_floats_behave_like_floats`, `test_datetimes_behave_like_datetimes`, `test_dates_behave_like_dates`, `test_times_behave_like_times`, `test_strings_behave_like_strs`)。

**5. 验证序列化为 TOML 字符串的功能：**

*   许多测试函数都使用了 `as_string()` 方法来验证 `tomlkit` 将其内部表示的数据项转换回 TOML 格式字符串的能力。这对于将修改后的 TOML 数据写回文件非常重要。

**6. 验证错误处理：**

*   `test_items_can_be_appended_to_and_removed_from_a_table` 和 `test_items_can_be_appended_to_and_removed_from_an_inline_table` 中使用 `pytest.raises(NonExistentKey)` 来验证尝试删除不存在的键时是否会抛出预期的异常。
*   `test_array_add_line_invalid_value` 验证了向数组添加非法值时是否会抛出 `ValueError`。

**7. 验证高级特性：**

*   **自定义编码器:** `test_custom_encoders` 验证了用户可以自定义如何将特定 Python 对象编码为 TOML 支持的类型。
*   **Pickling (序列化):** `test_items_are_pickable` 验证了 `tomlkit` 的数据项可以被序列化和反序列化，这对于缓存或进程间通信很有用。
*   **复制 (Copying):** `test_table_copy` 和 `test_copy_copy` 验证了 `tomlkit` 数据项的复制行为。

**它与逆向的方法的关系及举例说明：**

Frida 是一个动态插桩工具，常用于逆向工程、安全研究和漏洞分析。TOML 是一种常用的配置文件格式。`tomlkit` 作为 Frida 的一个子项目，使得 Frida 能够方便地解析和修改目标进程中使用的 TOML 配置文件。

**举例说明：**

假设一个 Android 应用使用 TOML 文件来存储一些配置信息，例如服务器地址、API 密钥、调试模式开关等。

1. **读取配置：** 使用 Frida，你可以拦截应用读取配置文件的操作，然后使用 `tomlkit` 将文件内容解析成 Python 对象，方便分析其中的配置项。
2. **修改配置：** 你可以使用 `tomlkit` 修改解析后的配置对象，例如将调试模式开关设置为 `true`，或者修改服务器地址指向一个你控制的服务器。
3. **注入修改后的配置：**  然后，你可以使用 Frida 将修改后的 TOML 配置重新注入到目标进程，从而动态地改变应用的运行时行为，而无需重新编译或重新安装应用。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

虽然 `tomlkit` 本身是一个纯 Python 库，不直接涉及二进制底层或操作系统内核，但它作为 Frida 的一部分，在 Frida 的上下文中会间接地涉及到这些知识。

**举例说明：**

1. **内存操作 (二进制底层):** 当 Frida 使用 `tomlkit` 解析出配置信息后，这些信息可能会被用来指导 Frida 如何在目标进程的内存中进行操作。例如，配置文件中可能包含需要 hook 的函数的地址，Frida 需要将这些地址转换为内存中的实际位置。
2. **进程间通信 (Linux/Android):** Frida 通过进程间通信与目标进程进行交互。`tomlkit` 解析出的配置信息可能包含与通信相关的设置，例如通信端口、协议等。
3. **Android 框架：** 在 Android 逆向中，应用的配置文件可能涉及到 Android 框架的某些组件或服务。通过修改这些配置，可以影响应用与 Android 框架的交互方式。例如，修改权限相关的配置可能会绕过某些安全检查。

**如果做了逻辑推理，请给出假设输入与输出：**

许多测试用例都包含了逻辑推理。以下举一个例子：

**测试用例：** `test_array_behaves_like_a_list`

**假设输入 (通过 `parse` 函数创建 `doc` 对象):**

```toml
a = [1, 2,] # Comment
```

**逻辑推理：**

*   TOML 数组 `[1, 2,]` 应该被解析为一个包含整数 1 和 2 的 Python 列表。
*   对该数组进行 `+= [3, 4]` 操作，应该将列表元素 3 和 4 追加到数组末尾。

**预期输出：**

*   `assert doc["a"] == [1, 2]`  # 验证初始解析结果
*   `assert doc["a"] == [1, 2, 3, 4]` # 验证追加操作后的结果
*   `assert doc.as_string() == """a = [1, 2, 3, 4] # Comment\n"""` # 验证序列化后的 TOML 字符串

**如果涉及用户或者编程常见的使用错误，请举例说明：**

*   **尝试删除不存在的键：**  如 `test_items_can_be_appended_to_and_removed_from_a_table` 和 `test_items_can_be_appended_to_and_removed_from_an_inline_table` 中验证的那样，尝试删除 `Table` 或 `InlineTable` 中不存在的键会导致 `NonExistentKey` 异常。

    ```python
    import tomlkit

    config = tomlkit.table()
    config["foo"] = "bar"

    try:
        del config["baz"]  # "baz" 不存在
    except tomlkit.exceptions.NonExistentKey:
        print("尝试删除不存在的键")
    ```

*   **向数组添加非法值：** 如 `test_array_add_line_invalid_value` 中验证的那样，尝试向 `Array` 对象的行中添加 `Whitespace` 或 `Comment` 等非法值会抛出 `ValueError`。

    ```python
    import tomlkit

    my_array = tomlkit.array()
    try:
        my_array.add_line(1, tomlkit.ws(" ")) # 空格不是合法的数组元素
    except ValueError:
        print("尝试向数组添加非法值")
    ```

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本：** 用户为了逆向或分析某个程序，编写了一个 Frida 脚本。
2. **脚本需要读取或修改 TOML 配置：**  该脚本的功能可能涉及到读取目标进程的 TOML 配置文件，或者生成新的 TOML 配置并注入到目标进程。
3. **Frida 脚本使用了 `tomlkit` 库：**  为了处理 TOML 文件，Frida 脚本中导入并使用了 `tomlkit` 库。
4. **脚本运行出错或行为不符合预期：**  在运行 Frida 脚本时，可能因为 TOML 文件的解析或操作出现问题，导致脚本出错或目标程序的行为不符合预期。
5. **开始调试：** 用户开始调试 Frida 脚本。作为调试的一部分，用户可能需要确认 `tomlkit` 库是否正确地解析了 TOML 文件，或者是否按照预期修改了 TOML 数据。
6. **查看 `tomlkit` 的测试用例：**  为了理解 `tomlkit` 的行为，或者确认自己对 `tomlkit` 的使用方式是否正确，用户可能会查看 `tomlkit` 的源代码和测试用例。`test_items.py` 就是一个非常有用的参考，它可以帮助用户了解 `tomlkit` 如何处理各种 TOML 数据类型，以及常见的操作方式和可能的错误。

总而言之，`test_items.py` 是 `tomlkit` 库的关键测试文件，它详尽地测试了库中各种数据项类的功能和行为，对于理解 `tomlkit` 的工作原理以及在 Frida 脚本中正确使用 `tomlkit` 进行 TOML 配置文件的处理至关重要。 在逆向工程的上下文中，确保配置文件的正确解析和修改是实现动态分析和控制目标程序行为的基础。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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