Response:
Let's break down the thought process to analyze the given Python code for the `tomlkit` library.

**1. Understanding the Core Request:**

The request asks for a functional breakdown of the provided Python code (`test_items.py`), specifically within the context of the `frida` dynamic instrumentation tool. It also probes for connections to reverse engineering, low-level concepts, logical reasoning, common user errors, and debugging.

**2. Initial Code Scan and Identification of Key Areas:**

The first step is to quickly read through the code to get a general understanding. Keywords like `test_`, `assert`, `pytest`, and imports like `tomlkit`, `datetime`, `math`, `pickle` immediately stand out. This signals that the code is a set of unit tests for the `tomlkit` library. The library itself appears to handle TOML (Tom's Obvious, Minimal Language) data.

**3. Deconstructing Functionality by Category:**

To organize the analysis, I'll categorize the tests based on what they are testing. This makes it easier to identify the library's functionalities:

* **Basic Type Handling:** Tests like `test_integer_unwrap`, `test_string_unwrap`, `test_bool_unwrap`, etc., focus on verifying how basic data types (integers, strings, booleans) are handled by `tomlkit`. The `unwrap()` method seems crucial for converting `tomlkit`'s internal representation back to Python's native types.

* **Complex Type Handling:** Tests like `test_array_unwrap`, `test_abstract_table_unwrap`, and tests involving `datetime`, `date`, and `time` demonstrate how `tomlkit` handles structured data (arrays/lists, tables/dictionaries) and specific date/time objects.

* **Key Operations:**  `test_key_comparison` focuses on how keys are compared.

* **Table/Inline Table Manipulation:**  Tests involving `append` and `remove` on `Table` and `InlineTable` instances demonstrate how to modify TOML tables programmatically. The `as_string()` method is key here for inspecting the resulting TOML representation.

* **Advanced TOML Features:**  Tests for `inf` and `nan`, and different integer bases (hex, octal, bin) indicate that `tomlkit` supports the full TOML specification.

* **Array Behavior:** The tests for `test_array_behaves_like_a_list`, `test_array_multiline`, etc., confirm that `tomlkit`'s `Array` object behaves like Python's built-in list, with support for multiline formatting and comments.

* **Type Coercion/Arithmetic:** Tests involving adding floats to ints and vice versa explore how `tomlkit` handles arithmetic operations on its internal representations of numbers.

* **Operator Overloading:** The tests for how integers, floats, datetimes, etc., "behave like" their Python counterparts (`+=`, `-=`, etc.) show that `tomlkit` overloads these operators for convenient manipulation.

* **Serialization:** The `test_items_are_pickable` test verifies that `tomlkit` objects can be serialized and deserialized using Python's `pickle` module.

* **Edge Cases/Specific Scenarios:**  Tests like `test_trim_comments_when_building_inline_table` and the tests for deleting elements focus on specific edge cases or potentially tricky scenarios in TOML parsing and manipulation.

* **Customization:** `test_custom_encoders` shows how users can extend `tomlkit` to handle custom data types.

**4. Connecting to the Broader Context (Frida and Reverse Engineering):**

This is where the "thinking beyond the code" comes in. While the code itself is a test suite for a TOML library, the prompt asks about its relation to `frida`. Here's the reasoning:

* **Configuration:**  Configuration files are vital in software. TOML is a human-readable format often used for configuration. Frida likely uses configuration files (potentially in TOML format) to define settings, scripts to load, targets to attach to, etc. This is the most direct connection.

* **Data Exchange:** In reverse engineering, one often needs to extract data from a process or provide data to it. While less direct, TOML could be a format used for exchanging structured data between Frida scripts and external tools or for representing data extracted from a target process.

**5. Identifying Low-Level Concepts and Kernel/Framework Relevance:**

This requires some knowledge of Frida's internals and typical reverse engineering tasks:

* **Binary Data Representation:** While `tomlkit` deals with text-based TOML, the *purpose* of Frida often involves inspecting and manipulating binary data in memory. The configuration loaded by `tomlkit` might *describe* how to interpret or modify this binary data (e.g., offsets, data types).

* **Linux/Android Kernel/Framework:** Frida interacts with the operating system kernel to perform its instrumentation. Configuration files might specify kernel modules to interact with, system calls to hook, or processes to target. On Android, it might involve interacting with the Android framework.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

This involves picking a test case and imagining a specific input and the expected outcome:

* **Example:**  Take `test_append_to_empty_array`. The *input* is a TOML string `x = [ ]`. The code then appends the string "a". The *expected output* is the TOML string `x = ["a" ]`. This demonstrates the basic functionality of adding elements to an array.

**7. Identifying User/Programming Errors:**

This requires thinking about how someone might misuse the `tomlkit` library based on the tests:

* **Key Errors:** The `NonExistentKey` exception highlights a common error: trying to remove a key that doesn't exist.
* **Type Errors:**  The custom encoders section hints at potential errors when trying to serialize unsupported data types without providing a custom encoder.
* **Incorrect TOML Syntax:** Although not directly tested in *this* file,  users could easily make syntax errors in their TOML files, which `tomlkit` would need to handle (though the parsing logic is likely in other files).

**8. Tracing User Operations to the Code (Debugging Clues):**

This involves considering how a user's actions might lead to the execution of this specific test file:

* **Developing/Testing `tomlkit`:** A developer working on `tomlkit` would run these tests as part of their development process to ensure the library functions correctly.
* **Contributing to Frida:** If Frida depends on `tomlkit`, a developer making changes to how Frida uses TOML might indirectly trigger these tests.
* **Debugging Frida Issues:** If a Frida user encounters an issue related to TOML configuration, a Frida developer might run these `tomlkit` tests to isolate whether the problem lies within `tomlkit` itself.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a test file, it doesn't *do* anything directly."  **Correction:** Realize that test files *demonstrate* functionality and are crucial for understanding how a library is *intended* to be used.
* **Focusing too much on Frida's low-level:**  Recognize that the primary subject of the code is `tomlkit`. The Frida connection is about the *context* in which `tomlkit` might be used.
* **Overlooking common errors:** Initially, I might focus on more complex scenarios. **Correction:**  Remember to include basic user errors like incorrect key access.

By following these steps of code scanning, categorization, contextualization, logical reasoning, and consideration of errors and debugging, we arrive at a comprehensive analysis of the provided code snippet.
这个文件是 Frida 动态 instrumentation 工具中 `tomlkit` 子项目的一部分，其主要功能是 **测试 `tomlkit` 库中各种数据项 (items) 的行为和特性**。 `tomlkit` 是一个用于解析、操作和生成 TOML (Tom's Obvious, Minimal Language) 文件的 Python 库。

**具体功能列表:**

1. **测试基本数据类型的处理:**
   - 验证 `Integer`, `String`, `Bool`, `Null` 等基本类型在 `tomlkit` 中的创建、表示和解包 (unwrap) 行为。
   - 例如：测试整数类型能否正确解包为 Python 的 `int` 类型。

2. **测试复杂数据类型的处理:**
   - 验证 `Array` (数组), `Table` (表格), `InlineTable` (内联表格) 等复杂类型在 `tomlkit` 中的创建、操作和解包行为。
   - 例如：测试数组能否正确解包为 Python 的 `list` 类型，表格能否正确解包为 Python 的 `dict` 类型。

3. **测试日期和时间类型的处理:**
   - 验证 `datetime`, `date`, `time`, `timedelta`, `timezone` 等日期和时间类型在 `tomlkit` 中的创建、表示和解包行为。
   - 例如：测试包含时区信息的 `datetime` 对象能否正确解析和表示。

4. **测试键 (Key) 的比较:**
   - 验证 `Key` 对象的比较行为，例如与字符串的比较。

5. **测试表格和内联表格的增删操作:**
   - 验证向 `Table` 和 `InlineTable` 对象添加和删除键值对的功能，包括处理不存在的键的情况。

6. **测试特殊数值的处理:**
   - 验证 `tomlkit` 是否支持 TOML 规范中的 `inf` (无穷大) 和 `nan` (非数字) 值。

7. **测试不同进制整数的处理:**
   - 验证 `tomlkit` 是否支持 TOML 规范中的十六进制、八进制和二进制整数。

8. **测试数组的类似列表行为:**
   - 验证 `Array` 对象是否具有类似 Python `list` 的操作，如追加、删除、索引、切片等。

9. **测试数组的多行表示:**
   - 验证 `Array` 对象在多行格式下的表示和修改。

10. **测试向空数组添加元素:**
    - 验证向空数组添加元素是否能正确格式化 TOML 输出。

11. **测试修改带有注释的数组:**
    - 验证在修改带有注释的数组时，注释是否能被正确保留和处理。

12. **测试向多行数组添加字典:**
    - 验证向数组中添加字典时，字典是否能被正确转换为内联表格或普通表格。

13. **测试字典到表格的转换:**
    - 验证 Python 的 `dict` 对象如何转换为 `tomlkit` 的 `Table` 对象，并控制其输出格式（例如，是否排序键）。

14. **测试浮点数与整数的运算:**
    - 验证 `tomlkit` 中的整数类型在与浮点数进行加减运算时的行为和类型转换。

15. **测试各种数据类型的运算符重载:**
    - 验证 `Integer`, `Float`, `datetime`, `date`, `time`, `String` 等类型是否能像 Python 内置类型一样使用运算符（如 `+=`, `-=`, `*=`, `/=`).

16. **测试字符串的拼接和转义:**
    - 验证字符串的拼接操作和特殊字符的转义处理。

17. **测试表格的类似字典行为:**
    - 验证 `Table` 对象是否具有类似 Python `dict` 的操作，如 `update`, `get`, `setdefault` 等。

18. **测试对象的序列化 (Pickle):**
    - 验证 `tomlkit` 的各种数据项是否可以被 Python 的 `pickle` 模块序列化和反序列化。

19. **测试构建内联表格时去除注释:**
    - 验证在从带有注释的行构建内联表格时，注释是否被正确去除。

20. **测试删除内联表格元素时不留尾部分隔符:**
    - 验证在删除内联表格的最后一个元素时，是否不会留下多余的逗号。

21. **测试布尔值的比较:**
    - 验证 `Bool` 对象的布尔值比较行为。

22. **测试表格的复制:**
    - 验证 `Table` 对象的 `copy()` 方法是否能创建独立的副本。

23. **测试转义键名:**
    - 验证特殊字符的键名是否能被正确转义。

24. **测试自定义编码器:**
    - 验证 `tomlkit` 是否支持注册自定义编码器来处理特定的 Python 对象类型。

**与逆向方法的关系:**

`tomlkit` 本身是一个处理配置文件的库，与直接的二进制逆向技术关系不大。然而，在逆向工程中，我们经常需要处理程序的配置文件，这些文件可能采用 TOML 格式。

**举例说明:**

* **Frida 脚本配置:** Frida 脚本本身或 Frida 的一些插件可能使用 TOML 文件来配置其行为，例如指定要 hook 的函数、要修改的内存地址、要注入的代码等。`tomlkit` 可以用于解析这些配置文件，使得 Frida 脚本能够读取和使用配置信息。
* **逆向分析工具的配置:**  一些逆向分析工具可能使用 TOML 作为配置文件格式，用于设置工具的各种选项，例如反汇编器的风格、调试器的行为等。
* **提取目标程序的配置:**  在逆向分析目标程序时，可能会发现目标程序使用 TOML 文件存储配置信息。使用 Frida 和 `tomlkit`，可以编写脚本来读取目标程序的配置文件（如果可以访问），从而更好地理解程序的行为。

**涉及到二进制底层，Linux, Android 内核及框架的知识:**

这个测试文件本身的代码并没有直接涉及到二进制底层、Linux/Android 内核或框架的知识。它主要关注的是 `tomlkit` 库的逻辑和 TOML 格式的处理。

**举例说明 (虽然测试文件本身不涉及):**

* **Frida 与内核交互:** Frida 本身作为一个动态 instrumentation 工具，其核心功能是与目标进程甚至内核进行交互。例如，Frida 可以在运行时修改目标进程的内存、hook 函数调用等。这些操作涉及到操作系统底层的进程管理、内存管理、系统调用等知识。
* **Android 框架 Hook:** 在 Android 逆向中，Frida 经常被用于 hook Android Framework 层的函数，例如 Activity 的生命周期函数、系统服务的 API 等。这需要对 Android Framework 的结构和工作原理有一定的了解。
* **二进制数据解析:** 虽然 `tomlkit` 处理的是文本格式的 TOML，但在逆向过程中，我们经常需要解析二进制数据结构，例如 ELF 文件格式、DEX 文件格式等。这需要对二进制数据格式和字节序等概念有深入的理解。

**逻辑推理 (假设输入与输出):**

假设输入以下 TOML 字符串并使用 `tomlkit` 解析：

```toml
[user]
name = "Alice"
age = 30
is_active = true
```

`tomlkit` 的解析器会将这个字符串转换为一个 Python 字典结构：

```python
{
    'user': {
        'name': 'Alice',
        'age': 30,
        'is_active': True
    }
}
```

**用户或编程常见的使用错误 (举例说明):**

1. **尝试删除不存在的键:**

   ```python
   doc = parse('[table]\nfoo = "bar"')
   table = doc['table']
   table.remove(Key('baz'))  # 'baz' 不存在，会抛出 NonExistentKey 异常
   ```

2. **类型不匹配的运算:**

   ```python
   doc = parse('[table]\ncount = 10')
   doc['table']['count'] += '5'  # 尝试将字符串加到整数上，虽然 Python 不会直接报错，但在 tomlkit 的上下文中可能会导致意外结果或类型错误
   ```

3. **TOML 语法错误:** 用户编写的 TOML 文件可能存在语法错误，例如键值对缺少等号、字符串没有正确闭合等，这会导致 `tomlkit` 解析失败并抛出异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写或修改了 Frida 脚本或相关工具的配置文件:** 用户可能为了配置 Frida 脚本的行为，例如指定要 hook 的函数或要修改的参数，编辑了一个 TOML 格式的配置文件。
2. **Frida 脚本或工具使用 `tomlkit` 库加载和解析该配置文件:**  Frida 脚本或工具的代码中使用了 `tomlkit.parse()` 函数来读取和解析用户提供的 TOML 文件。
3. **在解析或操作 TOML 数据时遇到了问题或预期外的行为:**  例如，配置文件中的某个值没有被正确读取，或者在修改配置文件后保存时格式不正确。
4. **开发者或用户需要调试 `tomlkit` 库本身:**  为了排查问题，开发者可能会运行 `tomlkit` 的单元测试，例如这个 `test_items.py` 文件，来验证 `tomlkit` 的各项功能是否正常工作。
5. **查看 `test_items.py` 中的特定测试用例:**  开发者可能会关注与他们遇到的问题相关的测试用例，例如涉及到表格操作、数据类型处理或特殊值处理的测试，来理解 `tomlkit` 的预期行为并找到问题所在。

总而言之，`test_items.py` 是 `tomlkit` 库的核心测试文件，用于确保库的各个组成部分能够按照预期工作，这对于依赖 `tomlkit` 的 Frida 这样的工具的稳定性和可靠性至关重要。 当 Frida 用户在使用配置文件时遇到问题，或者 Frida 开发者需要确保对配置文件的处理是正确的时候，这些测试用例就成为了重要的参考和调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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