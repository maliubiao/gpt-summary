Response:
Let's break down the thought process for analyzing this Python test file.

**1. Initial Understanding of the File's Purpose:**

The filename `test_items.py` within a `tests` directory immediately suggests this file contains unit tests. The path `frida/subprojects/frida-qml/releng/tomlkit/tests/` tells us it's part of the Frida project, specifically related to QML, release engineering, and a library called `tomlkit`. `tomlkit` likely deals with TOML files (a configuration file format). The specific focus is on testing "items," suggesting it's testing the individual components or data types within a TOML structure.

**2. Deconstructing the Code - Identifying Key Components and Functionality:**

* **Imports:** I start by looking at the imports. `copy`, `math`, `pickle`, `datetime` modules are standard Python. The imports from `tomlkit` (`api`, `parse`, `exceptions`, `items`, `parser`) are crucial. These tell us the file tests how `tomlkit` handles different data types (`Array`, `Bool`, `String`, `Integer`, `Table`, etc.) and how it parses and serializes them.
* **Fixtures (`@pytest.fixture`)**: `tz_pst` and `tz_utc` are fixtures. This immediately signals that timezones are a concern in some of the tests. They are creating custom timezone objects for testing purposes, likely due to potential differences in how timezones are handled across systems.
* **Test Functions (`def test_...`)**: These are the core of the file. Each function tests a specific aspect of how `tomlkit` handles "items." I start categorizing these tests:
    * **`unwrap()` methods:** Several tests like `test_integer_unwrap`, `test_string_unwrap`, etc., focus on the `unwrap()` method. This suggests that `tomlkit` wraps TOML data types in its own objects, and `unwrap()` extracts the underlying Python type.
    * **Comparison (`test_key_comparison`)**: Testing how keys are compared.
    * **Appending and Removing Items (`test_items_can_be_appended_to_and_removed_from_a_table`, `test_items_can_be_appended_to_and_removed_from_an_inline_table`)**: Testing the mutability of TOML tables (dictionaries).
    * **Data Type Support (`test_inf_and_nan_are_supported`, `test_hex_octal_and_bin_integers_are_supported`)**:  Verifying support for specific TOML features like infinity, NaN, and different integer bases.
    * **List-like Behavior of Arrays (`test_array_behaves_like_a_list`)**: Testing if `tomlkit`'s `Array` object behaves like a standard Python list.
    * **Multiline Arrays (`test_array_multiline`, `test_array_multiline_modify`)**: Testing how multiline arrays are handled.
    * **Conversion of Dictionaries to Tables (`test_dicts_are_converted_to_tables`, `test_dicts_are_converted_to_tables_and_keep_order`, etc.)**: Testing the conversion between Python dictionaries and TOML tables.
    * **Arithmetic Operations on TOML Types (`test_add_float_to_int`, `test_integers_behave_like_ints`, etc.)**: Testing if basic arithmetic operations work correctly on `tomlkit`'s wrapped number types.
    * **Datetime and Date Handling (`test_datetimes_behave_like_datetimes`, `test_dates_behave_like_dates`, `test_times_behave_like_times`)**:  Specific tests for datetime, date, and time objects, including timezone handling.
    * **String Manipulation (`test_strings_behave_like_strs`, `test_string_add_preserve_escapes`)**: Testing string operations.
    * **Table Manipulation (`test_tables_behave_like_dicts`)**: Testing if `tomlkit`'s `Table` behaves like a Python dictionary.
    * **Pickling (`test_items_are_pickable`)**:  Testing if `tomlkit` objects can be serialized and deserialized.
    * **Inline Table Specifics (`test_trim_comments_when_building_inline_table`, `test_deleting_inline_table_element_does_not_leave_trailing_separator`)**:  Tests specific to inline tables.
    * **Boolean Handling (`test_booleans_comparison`)**: Testing boolean values.
    * **Copying (`test_table_copy`, `test_copy_copy`)**: Testing the `copy` functionality.
    * **Key Escaping (`test_escape_key`)**: Testing how special characters in keys are handled.
    * **Custom Encoders (`test_custom_encoders`)**: Testing the ability to register custom functions to handle specific data types during serialization.

**3. Connecting to Reverse Engineering and Underlying Concepts:**

Now, I look for connections to reverse engineering, binary, kernel, and framework knowledge.

* **Reverse Engineering:**  Configuration files are *essential* in reverse engineering. Understanding how an application is configured (through TOML in this case) is crucial. Frida itself uses configuration. Therefore, the ability to correctly parse and manipulate TOML files is a foundational capability for Frida and its users.
* **Binary/Low-Level:** While this specific test file doesn't directly manipulate bits or memory addresses, the underlying `tomlkit` library deals with the *representation* of data. The tests for different integer bases (hex, octal, binary) touch on how numbers are represented at a lower level.
* **Linux/Android Kernel/Framework:**  Configuration often dictates how applications interact with the operating system. While not explicitly testing kernel code, the ability to parse and modify configuration can influence how a program behaves at a system level. In the Android context, configuration files can affect application permissions, services, and other framework interactions.
* **Frida Context:**  Frida dynamically instruments applications. Imagine wanting to modify a configuration value in a running process. `tomlkit` provides the tools to parse the existing configuration, modify the relevant value, and potentially serialize it back. This is a direct application of this library in a Frida context.

**4. Logic, Input/Output, and User Errors:**

* **Logical Reasoning:**  Many tests implicitly use logical reasoning. For example, the tests for appending and removing elements from tables are based on the logic of data structure manipulation. The tests for arithmetic operations verify the logical correctness of these operations on the custom `tomlkit` types.
* **Hypothetical Inputs and Outputs:** For each test function, I try to imagine what the input TOML (or Python data) is and what the expected output (or behavior) should be. This helps in understanding the test's purpose.
* **User Errors:** I consider common mistakes developers might make when working with configuration files. Examples include:
    * Incorrectly formatting TOML.
    * Trying to access non-existent keys.
    * Expecting standard Python behavior when dealing with `tomlkit`'s wrapped objects.

**5. Debugging Scenario:**

I consider how a user might end up needing these tests. A common scenario is when a user encounters a bug or unexpected behavior related to TOML parsing or manipulation within Frida. They might then run these tests (or write new ones) to pinpoint the issue. The file serves as both a set of validation checks and a debugging resource.

**Self-Correction/Refinement:**

During this process, I might go back and refine my understanding. For example, if I see a test using `pickle`, I might initially overlook its significance. But then, realizing that pickling is about serialization, I'd understand that the test is verifying the ability to save and load `tomlkit` objects. Similarly, seeing the custom timezone fixtures would prompt me to consider the importance of timezone handling in configuration files.
这是一个名为 `test_items.py` 的 Python 源代码文件，它位于 `frida/subprojects/frida-qml/releng/tomlkit/tests/` 目录下。从目录结构来看，`tomlkit` 很可能是一个用于处理 TOML 格式配置文件的库，而这个 `test_items.py` 文件包含了针对 `tomlkit` 中 "items" (即 TOML 文件中的各种数据类型和结构) 的单元测试。

下面列举一下 `test_items.py` 的功能：

1. **测试不同 TOML 数据类型的正确解析和表示:**
   - 涵盖了整数 (Integer)、浮点数 (float)、布尔值 (Bool)、字符串 (String)、日期时间 (datetime)、日期 (date)、时间 (time)、空值 (Null) 等基本数据类型。
   - 测试了数组 (Array) 和内联表格 (InlineTable)。
   - 测试了表格 (Table) 及其嵌套结构。

2. **测试 `unwrap()` 方法:**
   - 验证了 `unwrap()` 方法能够正确地将 `tomlkit` 内部表示的数据类型转换回 Python 的原生数据类型 (例如，`tomlkit.items.Integer` 转换为 `int`)。

3. **测试键 (Key) 的比较:**
   - 验证了 `tomlkit.items.Key` 对象可以与字符串以及其他 `Key` 对象进行正确的比较。

4. **测试表格 (Table) 和内联表格 (InlineTable) 的增删操作:**
   - 验证了可以向表格和内联表格中添加新的键值对。
   - 验证了可以从表格和内联表格中删除指定的键值对。
   - 验证了当尝试删除不存在的键时会抛出 `NonExistentKey` 异常。

5. **测试特殊数值的支持:**
   - 验证了对正负无穷大 (inf, -inf) 和 NaN (Not a Number) 的支持。
   - 验证了对十六进制、八进制和二进制整数的支持。

6. **测试数组 (Array) 的行为:**
   - 验证了 `tomlkit.items.Array` 对象表现得像 Python 的 `list`，支持索引、切片、添加、删除等操作。
   - 测试了多行数组的表示和修改。
   - 测试了向空数组添加元素，以及在带有注释的数组中添加、插入和删除元素。
   - 测试了向数组中添加字典的情况。

7. **测试字典到表格的转换:**
   - 验证了 Python 的 `dict` 对象可以被正确地转换为 TOML 的表格 (Table)。
   - 测试了嵌套字典的转换，包括保持插入顺序和按键排序的情况。
   - 测试了字典数组到 TOML 数组OfTables (AOT) 的转换。

8. **测试数值类型的运算:**
   - 验证了 `tomlkit` 的整数和浮点数对象可以像 Python 的 `int` 和 `float` 一样进行加减乘除等运算。
   - 测试了不同数值类型之间的运算，例如整数加浮点数。

9. **测试日期和时间类型的运算和格式化:**
   - 验证了 `tomlkit` 的日期时间、日期和时间对象可以像 Python 的 `datetime.datetime`、`datetime.date` 和 `datetime.time` 一样进行运算 (例如，加减 `timedelta`)。
   - 验证了日期和时间对象的字符串表示符合 TOML 规范。

10. **测试字符串 (String) 类型的操作:**
    - 验证了 `tomlkit.items.String` 对象可以像 Python 的 `str` 一样进行拼接操作。
    - 测试了字符串添加操作时对转义字符的处理。

11. **测试表格 (Table) 类型像字典一样操作:**
    - 验证了 `tomlkit.items.Table` 对象可以像 Python 的 `dict` 一样进行 `update`, `get`, `setdefault` 等操作。

12. **测试对象的序列化 (Pickling):**
    - 验证了 `tomlkit` 的各种 Item 对象可以使用 `pickle` 模块进行序列化和反序列化。

13. **测试内联表格的注释处理:**
    - 验证了在构建内联表格时，会去除不必要的注释。

14. **测试删除内联表格元素后的分隔符处理:**
    - 验证了删除内联表格中的元素后，不会留下多余的逗号分隔符。

15. **测试布尔值的比较:**
    - 验证了 `tomlkit.items.Bool` 对象的真值判断。

16. **测试表格的复制:**
    - 验证了可以使用 `copy()` 方法复制表格对象，并且修改原始表格不会影响复制后的表格。

17. **测试键的转义:**
    - 验证了在表示键时，特殊字符会被正确转义。

18. **测试自定义编码器:**
    - 验证了可以注册自定义的编码器来处理特定的 Python 对象类型，以便将其转换为 TOML 兼容的格式。

**与逆向的方法的关系及其举例说明:**

这个测试文件本身不是直接的逆向分析工具，但它所属的 `tomlkit` 库在逆向工程中扮演着重要的角色。逆向工程师经常需要分析和修改软件的配置文件，而 TOML 是一种常见的配置文件格式。

**举例说明:**

假设一个被逆向的程序使用 TOML 文件存储其配置信息，例如 API 密钥、服务器地址、调试选项等。逆向工程师可以使用 Frida 动态地修改这些配置信息来观察程序的行为，或者绕过某些限制。`tomlkit` 库就提供了在 Frida 脚本中解析和修改 TOML 文件的能力。

例如，一个 Frida 脚本可能包含以下操作：

1. **读取目标进程的配置文件:** 使用 Frida 的文件 I/O 操作读取目标进程加载的 TOML 配置文件。
2. **解析 TOML 内容:** 使用 `tomlkit.parse()` 函数将读取到的 TOML 字符串解析成 `tomlkit` 的文档对象。
3. **修改配置项:**  访问和修改文档对象中的配置项，例如 `doc["api_keys"]["production"] = "new_key"`。
4. **将修改后的配置写回文件或直接影响程序行为:**  虽然 `tomlkit` 主要关注解析和表示，但在 Frida 的上下文中，修改后的值可以直接影响到正在运行的程序，无需写回文件。

**涉及到二进制底层、Linux、Android内核及框架的知识及其举例说明:**

这个测试文件本身并不直接涉及二进制底层、内核或框架的细节，它主要关注的是 TOML 数据的逻辑处理。然而，它所测试的 `tomlkit` 库在更广泛的 Frida 使用场景中，可能会间接地与这些知识领域产生关联。

**举例说明:**

* **二进制底层:**  在逆向过程中，可能需要分析二进制数据中嵌入的配置信息。虽然 `tomlkit` 不直接解析二进制数据，但如果配置信息是以某种方式从二进制数据中提取出来并表示为 TOML 格式，那么 `tomlkit` 就可以用来处理。
* **Linux/Android 内核:**  应用程序的行为可能受到内核参数或配置的影响。如果这些内核相关的配置也以 TOML 格式存储，那么可以使用 `tomlkit` 来解析和理解它们。
* **Android 框架:** Android 应用的某些配置信息，例如 `AndroidManifest.xml` 中定义的元数据，或者应用内部的一些配置文件，可能会被转换为其他格式，但如果存在 TOML 格式的配置，`tomlkit` 就能派上用场。此外，Frida Hook 框架本身在某些高级用法中可能会涉及到对底层系统调用的理解。

**逻辑推理的假设输入与输出:**

大多数测试函数都包含了逻辑推理。以下举例说明：

**假设输入:**  一个包含整数的 TOML 字符串 `"int_value = 123"`。

**测试代码:**
```python
def test_integer_unwrap():
    elementary_test(item(666), int)
```
在这个测试中，`item(666)` 创建了一个 `tomlkit.items.Integer` 对象。`elementary_test` 函数 (虽然未在代码中给出具体实现，但通常用于断言) 会检查 `item(666).unwrap()` 的返回值是否为 `int` 类型，并且值是否为 `666`。

**假设输入:**  一个包含数组的 TOML 字符串 `a = [1, 2, "three"]`。

**测试代码:**
```python
def test_array_unwrap():
    # ... (创建 Array 对象)
    a_unwrapped = a.unwrap()
    assert_is_ppo(a_unwrapped, list)
    assert_is_ppo(a_unwrapped[0], int)
    assert_is_ppo(a_unwrapped[1], int)
    assert_is_ppo(a_unwrapped[2], str)
```
在这个测试中，逻辑推理是：TOML 数组应该被解析成 Python 的列表，并且数组中的每个元素应该被转换为对应的 Python 类型。

**用户或编程常见的使用错误及其举例说明:**

1. **尝试访问不存在的键:**

   ```python
   doc = parse("[table]\nfoo = 'bar'")
   try:
       value = doc["table"]["baz"]
   except NonExistentKey:
       print("Key 'baz' not found.")
   ```
   测试用例 `test_items_can_be_appended_to_and_removed_from_a_table` 中就验证了当尝试删除不存在的键时会抛出 `NonExistentKey` 异常。

2. **类型错误的操作:**

   ```python
   doc = parse("count = 10")
   try:
       result = doc["count"] + " items"  # 尝试将整数与字符串相加
   except TypeError:
       print("Invalid operation: cannot add string to integer.")
   ```
   虽然 `tomlkit` 允许一些类型之间的运算 (例如整数和浮点数)，但某些操作仍然会导致类型错误。

3. **不理解 `unwrap()` 的作用:**

   用户可能直接操作 `tomlkit` 的 Item 对象，而不是先使用 `unwrap()` 获取原生 Python 类型，导致一些方法调用错误。

   ```python
   doc = parse("age = 30")
   age_item = doc["age"]
   # print(age_item.upper())  # 错误：Integer 对象没有 upper() 方法
   print(age_item.unwrap() + 5) # 正确：先 unwrap 成 int
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Frida 对一个目标应用进行动态分析，并且该应用使用了 TOML 配置文件。

1. **用户编写 Frida 脚本:**  用户想要修改应用配置中的某个值，例如服务器地址。他编写了一个 Frida 脚本来完成这个任务。
2. **Frida 脚本读取配置文件:** 脚本使用 Frida 的 `Memory.readUtf8String()` 或类似的方法读取目标进程内存中的配置文件内容，或者使用 `fs` 模块读取文件系统上的配置文件。
3. **使用 `tomlkit` 解析配置文件:** 脚本使用 `tomlkit.parse()` 函数将读取到的配置内容解析成一个 `tomlkit` 文档对象。
4. **尝试修改配置值:** 用户尝试通过键来访问和修改配置值，例如 `doc["server"]["address"] = "new_address"`。
5. **遇到问题或 Bug:**  可能出现以下情况：
   - **`NonExistentKey` 异常:** 用户输入的键名错误，导致尝试访问不存在的键。
   - **修改未生效:**  用户修改了值，但应用的行为没有改变，可能是因为修改的方式不正确，或者理解错了配置项的作用。
   - **`TypeError`:** 用户尝试对 `tomlkit` 的 Item 对象进行不正确的操作。

**作为调试线索:**

当用户遇到上述问题时，他可能会：

1. **查看 Frida 控制台的错误信息:**  Python 解释器会抛出异常，提供错误类型和堆栈信息。
2. **打印 `tomlkit` 对象的内容:** 使用 `print(doc)` 或 `print(doc.as_string())` 来查看解析后的 TOML 结构，确认键名是否正确，数据类型是否符合预期。
3. **查阅 `tomlkit` 的文档或示例:** 了解如何正确地访问和修改 `tomlkit` 对象。
4. **查看 `test_items.py` 文件:**  如果怀疑是 `tomlkit` 库本身的问题，或者想更深入地了解 `tomlkit` 的行为，用户可能会查看 `test_items.py` 文件，了解 `tomlkit` 针对不同场景的测试用例，从而找到解决问题的方法或验证自己的理解。例如，查看 `test_items_can_be_appended_to_and_removed_from_a_table` 可以帮助用户理解如何正确地添加或删除表格中的元素，以及 `NonExistentKey` 异常的产生原因。查看关于数据类型运算的测试用例可以帮助用户理解 `tomlkit` 中不同数据类型之间的行为。

总而言之，`test_items.py` 是 `tomlkit` 库的核心测试文件，它详细地验证了库中各种数据类型和操作的正确性，对于理解 `tomlkit` 的功能和排查相关问题非常有帮助，也间接地为 Frida 用户在使用 TOML 配置文件时提供了参考和保障。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/tomlkit/tests/test_items.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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