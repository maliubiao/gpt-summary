Response:
The user wants to understand the functionality of the provided Python code snippet. This is the third part of a series of questions about this file. I need to summarize the functionalities demonstrated in this specific part of the code.

The code primarily focuses on testing the `@typed_kwargs` decorator and related functionalities in the `mesonbuild` library. This decorator appears to enforce type checking and other constraints on keyword arguments passed to Python functions.

Here's a breakdown of the functionalities covered:

1. **`rtIsNot` Function Testing:** Checks if the `rtIsNot` function correctly handles default values when the input is not `None`.

2. **`typed_kwarg_container_pairs` Testing:**  Verifies that the `typed_kwargs` decorator can enforce that container types (like lists) have an even number of elements when `pairs=True` is specified. This suggests it's designed to handle key-value pairs within a list.

3. **`typed_kwarg_since` Testing:** Examines the behavior of `typed_kwargs` in managing the introduction and deprecation of keyword arguments based on Meson versions. It checks if warnings are correctly issued when using arguments before they were introduced or after they were deprecated.

4. **`typed_kwarg_validator` Testing:**  Tests the ability of `typed_kwargs` to use a custom validator function to check the validity of a keyword argument.

5. **`typed_kwarg_convertor` Testing:**  Verifies the functionality of converting keyword arguments to a specific type using a custom converter function.

6. **`typed_kwarg_since_values` Testing:**  A more complex test that explores the `since_values` and `deprecated_values` features of `typed_kwargs`. It checks if warnings are generated correctly based on the Meson version and the specific values passed to the keyword arguments. This includes handling different data types (strings, integers, lists, dictionaries) and nested structures.

7. **`typed_kwarg_evolve` Testing:**  Tests the `evolve` method of the `KwargInfo` class, which likely allows for creating modified copies of keyword argument specifications.

8. **`typed_kwarg_default_type` Testing:** Checks how `typed_kwargs` handles default values for keyword arguments with multiple possible types.

9. **`typed_kwarg_invalid_default_type` Testing:** Verifies that an error is raised when an invalid default value is provided for a keyword argument with type constraints.

10. **`typed_kwarg_container_in_tuple` Testing:**  Tests that `typed_kwargs` can correctly handle container types specified within a tuple of allowed types.

11. **CPU Architecture Detection (`detect_cpu_family`, `detect_cpu`):** Tests the functions responsible for detecting the CPU family and specific CPU architecture of the system. It mocks different system outputs to simulate various platforms and compiler configurations.

12. **Interpreter Pickling Test:** Checks that the `Interpreter` class in `mesonbuild` is not picklable and raises a `MesonBugException` if attempted. This is likely to prevent accidental serialization of complex interpreter state.

13. **Meson Version Comparison (`major_versions_differ`):** Tests a function that determines if two Meson versions represent different major releases.

14. **Option Key Parsing (`option_key_from_string`):** Tests the ability to parse a string representation of a Meson option key into an `OptionKey` object, which includes information like the option name, language, and machine type.

**Relationship to Reverse Engineering:**

The code itself doesn't directly perform reverse engineering. However, the underlying tool, Frida, is used for dynamic instrumentation, a technique often employed in reverse engineering. This code tests the infrastructure that supports Frida's QML integration, which could be used to inspect and manipulate QML applications. In a reverse engineering context, this could involve:

* **Inspecting QML object properties and signals:** Understanding the structure and behavior of QML applications.
* **Hooking QML functions:** Modifying the execution flow of a QML application to observe or alter its behavior.
* **Analyzing data passed between QML and native code:** Examining the interfaces and data structures used by the application.

**Binary/Low-Level, Linux/Android Kernel/Framework Knowledge:**

* **CPU Architecture Detection:** The `detect_cpu_family` and `detect_cpu` functions interact with operating system APIs (like `platform.processor` and `platform.machine`) to determine the system's architecture. This is fundamental for building software that runs correctly on different hardware. On Linux and Android, this might involve reading system files or calling specific syscalls.
* **Compiler Defines:** The mocking of `any_compiler_has_define` suggests that the CPU detection logic can also rely on compiler-specific preprocessor definitions. This is a common technique in build systems to adapt to different compiler capabilities and target architectures.

**Logical Inference (Hypothetical Input/Output):**

* **`test_typed_kwarg_container_pairs`:**
    * **Input:** `{'input': ['a', 'b']}`
    * **Output:** No exception, the test passes.
    * **Input:** `{'input': ['a']}`
    * **Output:** `MesonException: testfunc keyword argument 'input' was of type array[str] but should have been array[str] that has even size`

* **`test_typed_kwarg_validator`:**
    * **Input:** `{'input': 'foo'}`
    * **Output:** No exception, the test passes.
    * **Input:** `{'input': 'bar'}`
    * **Output:** `MesonException: testfunc keyword argument "input" invalid!`

**User/Programming Errors:**

* **Incorrect Keyword Argument Type:**  The `@typed_kwargs` decorator is designed to catch these errors. For example, passing an integer when a string is expected.
* **Missing Required Keyword Arguments:** If a `KwargInfo` is defined with `required=True`, failing to provide that argument will raise an error.
* **Providing Invalid Values for Keyword Arguments:** The `validator` functionality allows catching cases where the type is correct, but the value itself is invalid according to some custom logic.
* **Using Deprecated Arguments or Values:** The `since` and `deprecated` features, along with `since_values` and `deprecated_values`, aim to guide users towards the correct usage and warn them about outdated features. Ignoring these warnings can lead to code that breaks in future versions.
* **Incorrectly assuming container sizes:** For instance, in `test_typed_kwarg_container_pairs`, the user might assume any list of strings is valid, but the `pairs=True` constraint enforces a specific structure.

**User Operations Leading to This Code (Debugging Context):**

A developer working on the Frida project, specifically the QML integration, might be:

1. **Implementing or modifying a function that takes keyword arguments.**
2. **Using the `@typed_kwargs` decorator to enforce type safety and other constraints on these arguments.**
3. **Writing unit tests (like the ones in this file) to ensure the `@typed_kwargs` decorator and the decorated functions behave as expected.**
4. **Debugging a test failure related to incorrect keyword argument usage, versioning issues, or validation failures.** The stack trace would eventually lead them to this code to understand why the test is failing.

**Summary of Functionality (Part 3):**

This part of the `internaltests.py` file extensively tests the functionality of the `@typed_kwargs` decorator in `mesonbuild`. It verifies its ability to enforce type checking, handle default values, manage the introduction and deprecation of arguments and their values based on Meson versions, use custom validators and converters, and handle container types with specific constraints. Additionally, it tests CPU architecture detection logic, the non-picklable nature of the `Interpreter` class, Meson version comparison, and the parsing of Meson option keys. Essentially, this section focuses on the robustness and correctness of the argument handling mechanisms within the `mesonbuild` system.

这是 `frida/subprojects/frida-qml/releng/meson/unittests/internaltests.py` 文件的第三部分，主要集中在测试 Meson 构建系统中用于处理函数关键字参数的 `typed_kwargs` 装饰器及其相关功能。以下是该部分代码功能的归纳：

**主要功能：测试 `typed_kwargs` 装饰器及其相关特性**

`typed_kwargs` 装饰器用于对函数的关键字参数进行类型检查、默认值设置、版本控制（引入和废弃）以及自定义验证等功能。这部分代码通过大量的单元测试来验证这些特性是否按预期工作。

**具体测试的功能点：**

1. **`rtIsNot` 函数的测试:** 验证一个辅助函数 `rtIsNot`，该函数用于断言一个值不是默认值。

2. **带 `pairs=True` 的容器类型关键字参数测试 (`test_typed_kwarg_container_pairs`):**
   - 验证当使用 `ContainerTypeInfo` 并设置 `pairs=True` 时，可以强制关键字参数的容器类型（例如列表）必须包含偶数个元素，通常用于表示键值对。
   - **举例说明：**
     - **假设输入:** `{'input': ['a', 'b']}`  **输出:** 测试通过，因为列表包含偶数个元素。
     - **假设输入:** `{'input': ['a']}`  **输出:** 抛出 `MesonException`，提示列表大小应为偶数。

3. **关键字参数的版本控制测试 (`test_typed_kwarg_since`):**
   - 测试 `typed_kwargs` 装饰器中 `since` 和 `deprecated` 属性的功能，用于标记关键字参数的引入版本和废弃版本。
   - 验证在不同 Meson 版本下，使用已引入或已废弃的关键字参数时是否会产生相应的警告信息。
   - **与逆向方法的关系：** 在逆向工程中，了解软件不同版本的功能变化非常重要。这种版本控制机制可以帮助开发者和逆向工程师了解某个功能是在哪个版本引入的，又是在哪个版本被废弃的。
   - **用户操作是如何一步步的到达这里，作为调试线索：** 用户在编写 `meson.build` 文件时使用了某个模块或函数，该函数的定义使用了带有 `since` 或 `deprecated` 标记的关键字参数。当使用的 Meson 版本与这些标记不符时，就会触发警告信息，促使开发者查看此处的测试代码以理解警告产生的原因和版本控制规则。

4. **关键字参数的自定义验证器测试 (`test_typed_kwarg_validator`):**
   - 测试 `typed_kwargs` 装饰器中 `validator` 属性的功能，允许使用自定义函数来验证关键字参数的值是否合法。
   - **举例说明：**
     - **假设输入:** `{'input': 'foo'}`  **输出:** 测试通过，因为验证器函数允许值为 'foo'。
     - **假设输入:** `{'input': 'bar'}`  **输出:** 抛出 `MesonException`，提示关键字参数 "input" 无效。

5. **关键字参数的类型转换器测试 (`test_typed_kwarg_convertor`):**
   - 测试 `typed_kwargs` 装饰器中 `convertor` 属性的功能，允许在接收到关键字参数后，使用自定义函数将其转换为期望的类型。
   - **举例说明：**  测试中，布尔值 `True` 被转换为 `MachineChoice.BUILD`，`False` 被转换为 `MachineChoice.HOST`。

6. **关键字参数值的版本控制测试 (`test_typed_kwarg_since_values`):**
   - 测试 `typed_kwargs` 装饰器中 `since_values` 和 `deprecated_values` 属性的功能，用于标记关键字参数的特定值的引入版本和废弃版本。
   - 验证在不同 Meson 版本下，使用已引入或已废弃的关键字参数值时是否会产生相应的警告信息。
   - **用户操作是如何一步步的到达这里，作为调试线索：** 类似于 `test_typed_kwarg_since`，但更细粒度地针对参数的特定值进行版本控制。用户可能使用了某个特定参数值，而该值在当前 Meson 版本下已被废弃或尚未引入，从而触发警告，引导开发者查看此处的测试用例。

7. **`KwargInfo` 对象的演化测试 (`test_typed_kwarg_evolve`):**
   - 测试 `KwargInfo` 类的 `evolve` 方法，该方法允许创建一个新的 `KwargInfo` 对象，并修改其某些属性（例如默认值），而保持其他属性不变。

8. **关键字参数默认值类型测试 (`test_typed_kwarg_default_type`):**
   - 验证 `typed_kwargs` 装饰器能够正确处理具有多种可能类型的关键字参数的默认值。

9. **关键字参数无效默认值类型测试 (`test_typed_kwarg_invalid_default_type`):**
   - 验证当为关键字参数设置了与其类型不符的默认值时，会抛出 `AssertionError`。

10. **元组中包含容器类型的关键字参数测试 (`test_typed_kwarg_container_in_tuple`):**
    - 测试当关键字参数允许的类型是包含容器类型的元组时，`typed_kwargs` 装饰器是否能正确处理。

11. **CPU 家族检测测试 (`test_detect_cpu_family`):**
    - 测试 `detect_cpu_family` 函数，该函数用于检测当前系统的 CPU 家族（例如 x86, arm, ppc64）。
    - **涉及到二进制底层知识：** 该函数需要读取系统信息来判断 CPU 类型，这可能涉及到读取特定的系统文件或调用底层的 API。
    - **涉及到 Linux 知识：** 在 Linux 系统中，可以通过 `/proc/cpuinfo` 等文件获取 CPU 信息。
    - **涉及到 Android 内核及框架的知识：**  Android 基于 Linux 内核，也存在类似的机制来获取 CPU 信息。
    - **用户操作是如何一步步的到达这里，作为调试线索：** Meson 在配置构建环境时需要了解目标平台的 CPU 架构，以便选择合适的编译器和构建选项。如果自动检测到的 CPU 架构不正确，开发者可能会查看此处的测试代码来了解 Meson 是如何进行 CPU 检测的。

12. **CPU 检测测试 (`test_detect_cpu`):**
    - 测试 `detect_cpu` 函数，该函数用于检测当前系统的具体 CPU 架构（例如 x86_64, armv7l）。
    - **与 `test_detect_cpu_family` 类似，涉及到二进制底层、Linux 和 Android 的知识。**

13. **Interpreter 对象不可序列化测试 (`test_interpreter_unpicklable`):**
    - 测试 `mesonbuild.interpreter.Interpreter` 对象是否不可被 `pickle` 序列化，如果尝试序列化会抛出 `mesonbuild.mesonlib.MesonBugException`。
    - 这通常是为了防止意外地序列化包含复杂状态的 Interpreter 对象，导致反序列化时出现问题。

14. **主要版本差异测试 (`test_major_versions_differ`):**
    - 测试 `coredata.major_versions_differ` 函数，用于判断两个 Meson 版本号是否属于不同的主要版本。

15. **从字符串创建 OptionKey 测试 (`test_option_key_from_string`):**
    - 测试 `OptionKey.from_string` 方法，该方法用于将字符串形式的选项键转换为 `OptionKey` 对象。

**总结：**

这部分代码是 Frida 构建系统中关于 Meson 构建配置的关键组成部分，专注于测试函数关键字参数的处理机制。它确保了类型安全、版本控制的正确性，并且能够进行自定义的验证和转换。此外，还包含了对底层 CPU 架构检测以及构建系统核心组件属性的测试。这些测试对于保证 Frida 项目在不同平台和 Meson 版本下的稳定性和可靠性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
rtIsNot(kwargs['input'], default)

        _(None, mock.Mock(), [], {})

    def test_typed_kwarg_container_pairs(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str, pairs=True), listify=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.List[str]]) -> None:
            self.assertEqual(kwargs['input'], ['a', 'b'])

        _(None, mock.Mock(), [], {'input': ['a', 'b']})

        with self.assertRaises(MesonException) as cm:
            _(None, mock.Mock(), [], {'input': ['a']})
        self.assertEqual(str(cm.exception), "testfunc keyword argument 'input' was of type array[str] but should have been array[str] that has even size")

    def test_typed_kwarg_since(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', str, since='1.0', since_message='Its awesome, use it',
                      deprecated='2.0', deprecated_message='Its terrible, dont use it')
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertIsInstance(kwargs['input'], str)
            self.assertEqual(kwargs['input'], 'foo')

        with self.subTest('use before available'), \
                mock.patch('sys.stdout', io.StringIO()) as out, \
                mock.patch('mesonbuild.mesonlib.project_meson_versions', {'': '0.1'}):
            # With Meson 0.1 it should trigger the "introduced" warning but not the "deprecated" warning
            _(None, mock.Mock(subproject=''), [], {'input': 'foo'})
            self.assertRegex(out.getvalue(), r'WARNING:.*introduced.*input arg in testfunc. Its awesome, use it')
            self.assertNotRegex(out.getvalue(), r'WARNING:.*deprecated.*input arg in testfunc. Its terrible, dont use it')

        with self.subTest('no warnings should be triggered'), \
                mock.patch('sys.stdout', io.StringIO()) as out, \
                mock.patch('mesonbuild.mesonlib.project_meson_versions', {'': '1.5'}):
            # With Meson 1.5 it shouldn't trigger any warning
            _(None, mock.Mock(subproject=''), [], {'input': 'foo'})
            self.assertNotRegex(out.getvalue(), r'WARNING:.*')

        with self.subTest('use after deprecated'), \
                mock.patch('sys.stdout', io.StringIO()) as out, \
                mock.patch('mesonbuild.mesonlib.project_meson_versions', {'': '2.0'}):
            # With Meson 2.0 it should trigger the "deprecated" warning but not the "introduced" warning
            _(None, mock.Mock(subproject=''), [], {'input': 'foo'})
            self.assertRegex(out.getvalue(), r'WARNING:.*deprecated.*input arg in testfunc. Its terrible, dont use it')
            self.assertNotRegex(out.getvalue(), r'WARNING:.*introduced.*input arg in testfunc. Its awesome, use it')

    def test_typed_kwarg_validator(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', str, default='', validator=lambda x: 'invalid!' if x != 'foo' else None)
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            pass

        # Should be valid
        _(None, mock.Mock(), tuple(), dict(input='foo'))

        with self.assertRaises(MesonException) as cm:
            _(None, mock.Mock(), tuple(), dict(input='bar'))
        self.assertEqual(str(cm.exception), "testfunc keyword argument \"input\" invalid!")

    def test_typed_kwarg_convertor(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('native', bool, default=False, convertor=lambda n: MachineChoice.BUILD if n else MachineChoice.HOST)
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, MachineChoice]) -> None:
            assert isinstance(kwargs['native'], MachineChoice)

        _(None, mock.Mock(), tuple(), dict(native=True))

    @mock.patch('mesonbuild.mesonlib.project_meson_versions', {'': '1.0'})
    def test_typed_kwarg_since_values(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str), listify=True, default=[], deprecated_values={'foo': '0.9'}, since_values={'bar': '1.1'}),
            KwargInfo('output', ContainerTypeInfo(dict, str), default={}, deprecated_values={'foo': '0.9', 'foo2': ('0.9', 'dont use it')}, since_values={'bar': '1.1', 'bar2': ('1.1', 'use this')}),
            KwargInfo('install_dir', (bool, str, NoneType), deprecated_values={False: '0.9'}),
            KwargInfo(
                'mode',
                (str, type(None)),
                validator=in_set_validator({'clean', 'build', 'rebuild', 'deprecated', 'since'}),
                deprecated_values={'deprecated': '1.0'},
                since_values={'since': '1.1'}),
            KwargInfo('dict', (ContainerTypeInfo(list, str), ContainerTypeInfo(dict, str)), default={},
                      since_values={list: '1.9'}),
            KwargInfo('new_dict', (ContainerTypeInfo(list, str), ContainerTypeInfo(dict, str)), default={},
                      since_values={dict: '1.1'}),
            KwargInfo('foo', (str, int, ContainerTypeInfo(list, str), ContainerTypeInfo(dict, str), ContainerTypeInfo(list, int)), default={},
                      since_values={str: '1.1', ContainerTypeInfo(list, str): '1.2', ContainerTypeInfo(dict, str): '1.3'},
                      deprecated_values={int: '0.8', ContainerTypeInfo(list, int): '0.9'}),
            KwargInfo('tuple', (ContainerTypeInfo(list, (str, int))), default=[], listify=True,
                      since_values={ContainerTypeInfo(list, str): '1.1', ContainerTypeInfo(list, int): '1.2'}),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            pass

        with self.subTest('deprecated array string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'input': ['foo']})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "input" value "foo".*""")

        with self.subTest('new array string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'input': ['bar']})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "input" value "bar".*""")

        with self.subTest('deprecated dict string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'output': {'foo': 'a'}})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "output" value "foo".*""")

        with self.subTest('deprecated dict string value with msg'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'output': {'foo2': 'a'}})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "output" value "foo2" in dict keys. dont use it.*""")

        with self.subTest('new dict string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'output': {'bar': 'b'}})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "output" value "bar".*""")

        with self.subTest('new dict string value with msg'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'output': {'bar2': 'a'}})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "output" value "bar2" in dict keys. use this.*""")

        with self.subTest('new string type'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'foo': 'foo'})
            self.assertRegex(out.getvalue(), r"""WARNING: Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "foo" of type str.*""")

        with self.subTest('new array of string type'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'foo': ['foo']})
            self.assertRegex(out.getvalue(), r"""WARNING: Project targets '1.0'.*introduced in '1.2': "testfunc" keyword argument "foo" of type array\[str\].*""")

        with self.subTest('new dict of string type'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'foo': {'plop': 'foo'}})
            self.assertRegex(out.getvalue(), r"""WARNING: Project targets '1.0'.*introduced in '1.3': "testfunc" keyword argument "foo" of type dict\[str\].*""")

        with self.subTest('deprecated int value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'foo': 1})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.8': "testfunc" keyword argument "foo" of type int.*""")

        with self.subTest('deprecated array int value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'foo': [1]})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "foo" of type array\[int\].*""")

        with self.subTest('new list[str] value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'tuple': ['foo', 42]})
            self.assertRegex(out.getvalue(), r"""WARNING: Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "tuple" of type array\[str\].*""")
            self.assertRegex(out.getvalue(), r"""WARNING: Project targets '1.0'.*introduced in '1.2': "testfunc" keyword argument "tuple" of type array\[int\].*""")

        with self.subTest('deprecated array string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'input': 'foo'})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "input" value "foo".*""")

        with self.subTest('new array string value'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'input': 'bar'})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "input" value "bar".*""")

        with self.subTest('non string union'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'install_dir': False})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '0.9': "testfunc" keyword argument "install_dir" value "False".*""")

        with self.subTest('deprecated string union'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'mode': 'deprecated'})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*deprecated since '1.0': "testfunc" keyword argument "mode" value "deprecated".*""")

        with self.subTest('new string union'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'mode': 'since'})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "mode" value "since".*""")

        with self.subTest('new container'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'dict': ['a=b']})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.9': "testfunc" keyword argument "dict" of type list.*""")

        with self.subTest('new container set to default'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {'new_dict': {}})
            self.assertRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "new_dict" of type dict.*""")

        with self.subTest('new container default'), mock.patch('sys.stdout', io.StringIO()) as out:
            _(None, mock.Mock(subproject=''), [], {})
            self.assertNotRegex(out.getvalue(), r"""WARNING:.Project targets '1.0'.*introduced in '1.1': "testfunc" keyword argument "new_dict" of type dict.*""")

    def test_typed_kwarg_evolve(self) -> None:
        k = KwargInfo('foo', str, required=True, default='foo')
        v = k.evolve(default='bar')
        self.assertEqual(k.name, 'foo')
        self.assertEqual(k.name, v.name)
        self.assertEqual(k.types, str)
        self.assertEqual(k.types, v.types)
        self.assertEqual(k.required, True)
        self.assertEqual(k.required, v.required)
        self.assertEqual(k.default, 'foo')
        self.assertEqual(v.default, 'bar')

    def test_typed_kwarg_default_type(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('no_default', (str, ContainerTypeInfo(list, str), NoneType)),
            KwargInfo('str_default', (str, ContainerTypeInfo(list, str)), default=''),
            KwargInfo('list_default', (str, ContainerTypeInfo(list, str)), default=['']),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertEqual(kwargs['no_default'], None)
            self.assertEqual(kwargs['str_default'], '')
            self.assertEqual(kwargs['list_default'], [''])
        _(None, mock.Mock(), [], {})

    def test_typed_kwarg_invalid_default_type(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('invalid_default', (str, ContainerTypeInfo(list, str), NoneType), default=42),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            pass
        self.assertRaises(AssertionError, _, None, mock.Mock(), [], {})

    def test_typed_kwarg_container_in_tuple(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', (str, ContainerTypeInfo(list, str))),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertEqual(kwargs['input'], args[0])
        _(None, mock.Mock(), [''], {'input': ''})
        _(None, mock.Mock(), [['']], {'input': ['']})
        self.assertRaises(InvalidArguments, _, None, mock.Mock(), [], {'input': 42})

    def test_detect_cpu_family(self) -> None:
        """Test the various cpu families that we detect and normalize.

        This is particularly useful as both documentation, and to keep testing
        platforms that are less common.
        """

        @contextlib.contextmanager
        def mock_trial(value: str) -> T.Iterable[None]:
            """Mock all of the ways we could get the trial at once."""
            mocked = mock.Mock(return_value=value)

            with mock.patch('mesonbuild.environment.detect_windows_arch', mocked), \
                    mock.patch('mesonbuild.environment.platform.processor', mocked), \
                    mock.patch('mesonbuild.environment.platform.machine', mocked):
                yield

        cases = [
            ('x86', 'x86'),
            ('i386', 'x86'),
            ('bepc', 'x86'),  # Haiku
            ('earm', 'arm'),  # NetBSD
            ('arm', 'arm'),
            ('ppc64', 'ppc64'),
            ('powerpc64', 'ppc64'),
            ('powerpc', 'ppc'),
            ('ppc', 'ppc'),
            ('macppc', 'ppc'),
            ('power macintosh', 'ppc'),
            ('mips64el', 'mips'),
            ('mips64', 'mips'),
            ('mips', 'mips'),
            ('mipsel', 'mips'),
            ('ip30', 'mips'),
            ('ip35', 'mips'),
            ('parisc64', 'parisc'),
            ('sun4u', 'sparc64'),
            ('sun4v', 'sparc64'),
            ('amd64', 'x86_64'),
            ('x64', 'x86_64'),
            ('i86pc', 'x86_64'),  # Solaris
            ('aarch64', 'aarch64'),
            ('aarch64_be', 'aarch64'),
        ]

        cc = ClangCCompiler([], [], 'fake', MachineChoice.HOST, False, mock.Mock())

        with mock.patch('mesonbuild.environment.any_compiler_has_define', mock.Mock(return_value=False)):
            for test, expected in cases:
                with self.subTest(test, has_define=False), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu_family({'c': cc})
                    self.assertEqual(actual, expected)

        with mock.patch('mesonbuild.environment.any_compiler_has_define', mock.Mock(return_value=True)):
            for test, expected in [('x86_64', 'x86'), ('aarch64', 'arm'), ('ppc', 'ppc64'), ('mips64', 'mips64')]:
                with self.subTest(test, has_define=True), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu_family({'c': cc})
                    self.assertEqual(actual, expected)

        # machine_info_can_run calls detect_cpu_family with no compilers at all
        with mock.patch(
            'mesonbuild.environment.any_compiler_has_define',
            mock.Mock(side_effect=AssertionError('Should not be called')),
        ):
            for test, expected in [('mips64', 'mips64')]:
                with self.subTest(test, has_compiler=False), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu_family({})
                    self.assertEqual(actual, expected)

    def test_detect_cpu(self) -> None:

        @contextlib.contextmanager
        def mock_trial(value: str) -> T.Iterable[None]:
            """Mock all of the ways we could get the trial at once."""
            mocked = mock.Mock(return_value=value)

            with mock.patch('mesonbuild.environment.detect_windows_arch', mocked), \
                    mock.patch('mesonbuild.environment.platform.processor', mocked), \
                    mock.patch('mesonbuild.environment.platform.machine', mocked):
                yield

        cases = [
            ('amd64', 'x86_64'),
            ('x64', 'x86_64'),
            ('i86pc', 'x86_64'),
            ('earm', 'arm'),
            ('mips64el', 'mips'),
            ('mips64', 'mips'),
            ('mips', 'mips'),
            ('mipsel', 'mips'),
            ('aarch64', 'aarch64'),
            ('aarch64_be', 'aarch64'),
        ]

        cc = ClangCCompiler([], [], 'fake', MachineChoice.HOST, False, mock.Mock())

        with mock.patch('mesonbuild.environment.any_compiler_has_define', mock.Mock(return_value=False)):
            for test, expected in cases:
                with self.subTest(test, has_define=False), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu({'c': cc})
                    self.assertEqual(actual, expected)

        with mock.patch('mesonbuild.environment.any_compiler_has_define', mock.Mock(return_value=True)):
            for test, expected in [('x86_64', 'i686'), ('aarch64', 'arm'), ('ppc', 'ppc64'), ('mips64', 'mips64')]:
                with self.subTest(test, has_define=True), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu({'c': cc})
                    self.assertEqual(actual, expected)

        with mock.patch(
            'mesonbuild.environment.any_compiler_has_define',
            mock.Mock(side_effect=AssertionError('Should not be called')),
        ):
            for test, expected in [('mips64', 'mips64')]:
                with self.subTest(test, has_compiler=False), mock_trial(test):
                    actual = mesonbuild.environment.detect_cpu({})
                    self.assertEqual(actual, expected)

    @mock.patch('mesonbuild.interpreter.Interpreter.load_root_meson_file', mock.Mock(return_value=None))
    @mock.patch('mesonbuild.interpreter.Interpreter.sanity_check_ast', mock.Mock(return_value=None))
    @mock.patch('mesonbuild.interpreter.Interpreter.parse_project', mock.Mock(return_value=None))
    def test_interpreter_unpicklable(self) -> None:
        build = mock.Mock()
        build.environment = mock.Mock()
        build.environment.get_source_dir = mock.Mock(return_value='')
        with mock.patch('mesonbuild.interpreter.Interpreter._redetect_machines', mock.Mock()), \
                self.assertRaises(mesonbuild.mesonlib.MesonBugException):
            i = mesonbuild.interpreter.Interpreter(build)
            pickle.dumps(i)

    def test_major_versions_differ(self) -> None:
        # Return True when going to next major release, when going to dev cycle,
        # when going to rc cycle or when going out of rc cycle.
        self.assertTrue(coredata.major_versions_differ('0.59.0', '0.60.0'))
        self.assertTrue(coredata.major_versions_differ('0.59.0', '0.59.99'))
        self.assertTrue(coredata.major_versions_differ('0.59.0', '0.60.0.rc1'))
        self.assertTrue(coredata.major_versions_differ('0.59.99', '0.60.0.rc1'))
        self.assertTrue(coredata.major_versions_differ('0.60.0.rc1', '0.60.0'))
        # Return False when going to next point release or when staying in dev/rc cycle.
        self.assertFalse(coredata.major_versions_differ('0.60.0', '0.60.0'))
        self.assertFalse(coredata.major_versions_differ('0.60.0', '0.60.1'))
        self.assertFalse(coredata.major_versions_differ('0.59.99', '0.59.99'))
        self.assertFalse(coredata.major_versions_differ('0.60.0.rc1', '0.60.0.rc2'))

    def test_option_key_from_string(self) -> None:
        cases = [
            ('c_args', OptionKey('args', lang='c', _type=OptionType.COMPILER)),
            ('build.cpp_args', OptionKey('args', machine=MachineChoice.BUILD, lang='cpp', _type=OptionType.COMPILER)),
            ('prefix', OptionKey('prefix', _type=OptionType.BUILTIN)),
            ('made_up', OptionKey('made_up', _type=OptionType.PROJECT)),

            # TODO: the from_String method should be splitting the prefix off of
            # these, as we have the type already, but it doesn't. For now have a
            # test so that we don't change the behavior un-intentionally
            ('b_lto', OptionKey('b_lto', _type=OptionType.BASE)),
            ('backend_startup_project', OptionKey('backend_startup_project', _type=OptionType.BACKEND)),
        ]

        for raw, expected in cases:
            with self.subTest(raw):
                self.assertEqual(OptionKey.from_string(raw), expected)
```