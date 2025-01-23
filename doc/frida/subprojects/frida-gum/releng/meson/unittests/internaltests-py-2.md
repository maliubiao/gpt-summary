Response:
My thought process to analyze the Python code and generate the summary involved several steps:

1. **Understand the Goal:** The request asks for a functional summary of the Python code, focusing on its relationship with reverse engineering, low-level details (kernel, etc.), logical reasoning, common user errors, debugging context, and finally, a concise overall summary. The "part 3 of 3" suggests prior context might be relevant, but I need to analyze this code independently.

2. **Initial Code Scan and High-Level Understanding:** I first scanned the code to identify key elements. I noticed a lot of tests (`test_`), decorators like `@typed_kwargs`, and assertions (`self.assertEqual`, `self.assertRaises`, `self.assertRegex`). This immediately suggested a unit testing file. The name `internaltests.py` and the directory structure `frida/subprojects/frida-gum/releng/meson/unittests/` further confirm this. The code appears to be testing the functionality of the `typed_kwargs` decorator and related helper functions within the Meson build system, specifically within the Frida-gum project.

3. **Focus on Core Functionality:** The central piece of code appears to be the `typed_kwargs` decorator and the `KwargInfo` class. These seem to be responsible for enforcing type checking, providing default values, and handling deprecation/introduction warnings for keyword arguments in functions. The various test functions are verifying different aspects of this functionality (e.g., basic type checking, container types, `since`/`deprecated` attributes, validators, converters).

4. **Relate to Reverse Engineering (Instruction 2):**  I considered how this type checking and argument validation might relate to reverse engineering. Frida is a dynamic instrumentation toolkit, meaning it interacts with running processes. Incorrect argument types passed to Frida functions *could* lead to unexpected behavior or crashes in the target process, which would be relevant during reverse engineering. For example, providing an incorrect address format or size to a Frida function manipulating memory would be a likely scenario. However, this specific *test* code is about validating the *Meson build system* itself, not directly the runtime behavior of Frida. So the connection is indirect.

5. **Identify Low-Level Aspects (Instruction 3):**  The code itself doesn't directly manipulate binary code, interact with the Linux/Android kernel, or delve into framework specifics. It's focused on build system logic. The presence of `MachineChoice` and checks for CPU architecture (`detect_cpu_family`, `detect_cpu`) hints at cross-compilation considerations, which are relevant in embedded systems and potentially Android development, but the *test* code only *simulates* these scenarios.

6. **Analyze Logical Reasoning (Instruction 4):** The tests demonstrate logical reasoning by setting up specific input conditions (e.g., different keyword argument values, different Meson versions) and asserting the expected outputs or behaviors (e.g., warnings being printed, exceptions being raised). The `since` and `deprecated` tests involve conditional logic based on version numbers.

7. **Consider User Errors (Instruction 5):**  The tests that raise `MesonException` or `InvalidArguments` exemplify common user errors in build systems. For instance, providing the wrong type for a keyword argument, providing an odd number of elements when an even number is expected, or using a deprecated argument in a newer version of Meson.

8. **Trace User Operations (Instruction 6):**  To understand how a user might reach this test code, I thought about the typical Frida development workflow. A developer working on Frida (or Frida-gum) would likely be using the Meson build system. If they introduce or modify the way keyword arguments are handled in a function, they would need to write unit tests to ensure the changes are correct and existing functionality isn't broken. Running the Meson test suite (`meson test`) would execute this `internaltests.py` file.

9. **Synthesize a Summary (Instruction 7):**  Finally, I combined my observations into a concise summary highlighting the core functionality (testing `typed_kwargs`), its purpose (ensuring build system correctness), and the kinds of checks it performs (type validation, deprecation handling, etc.).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the code directly tests Frida's runtime behavior.
* **Correction:** Realized the file path and test names point to testing the *build system* (Meson) itself, specifically the argument handling mechanism.
* **Initial thought:** The low-level aspect is about direct memory manipulation.
* **Correction:**  The low-level aspect is more about the build system's awareness of different architectures (`MachineChoice`, CPU detection), which is important for compiling code for different targets, including mobile (Android).
* **Considered the "part 3 of 3"**:  While the prompt mentioned this, the provided code snippet was self-contained enough to analyze without needing prior parts. If the other parts were available, I would have looked for dependencies or context that would further inform the functionality of this specific file.

By following these steps, I aimed to provide a comprehensive and accurate answer to the prompt, covering all the requested aspects.
这是frida动态instrumentation工具源代码文件 `frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py` 的第三部分，主要集中在测试 Meson 构建系统中用于处理函数关键字参数的装饰器 `@typed_kwargs` 及其相关功能。

**功能归纳:**

该文件的主要功能是测试 Meson 构建系统中 `mesonbuild.decorators.typed_kwargs` 装饰器的各种特性和边缘情况，以确保其能够正确地处理和验证函数接收的关键字参数。 具体来说，它测试了以下功能：

1. **类型检查:** 验证 `@typed_kwargs` 能够正确地检查关键字参数的类型是否符合预期，包括基本类型 (如 `str`, `bool`) 和容器类型 (如 `list`, `dict`)。
2. **默认值处理:** 确认 `@typed_kwargs` 能够正确地处理和设置关键字参数的默认值。
3. **`listify` 功能:** 测试 `listify=True` 参数，确保当传入单个值时，能将其转换为包含该值的列表。
4. **容器类型 `pairs=True` 功能:** 验证对于键值对形式的容器类型，`pairs=True` 参数能够强制容器大小为偶数。
5. **`since` 和 `deprecated` 功能:** 测试 `@typed_kwargs` 如何处理关键字参数的引入 (`since`) 和弃用 (`deprecated`)，并根据 Meson 版本发出相应的警告信息。
6. **值验证器 (`validator`) 功能:**  验证 `@typed_kwargs` 能够使用自定义的验证函数来检查关键字参数的值是否有效。
7. **类型转换器 (`convertor`) 功能:** 测试 `@typed_kwargs` 能够使用自定义的转换函数将关键字参数的值转换为所需的类型。
8. **`since_values` 和 `deprecated_values` 功能:** 验证 `@typed_kwargs` 能够针对关键字参数的特定值进行引入和弃用警告。
9. **类型演化 (`evolve`) 功能:** 测试 `KwargInfo` 对象的 `evolve` 方法，允许在不修改原有对象的情况下创建具有修改后属性的新对象。
10. **默认值类型校验:** 确保提供的默认值类型与声明的类型兼容。
11. **容器类型作为联合类型:** 测试关键字参数类型可以是多种类型的联合，其中包括容器类型。
12. **CPU 架构检测:** 测试 Meson 构建系统中检测 CPU 架构的功能，这对于跨平台编译非常重要。
13. **CPU 型号检测:** 测试 Meson 构建系统中检测更具体的 CPU 型号的功能。
14. **解释器不可序列化:** 确认 Meson 的解释器对象无法被 `pickle` 序列化，这可能是出于安全或设计考虑。
15. **主要版本差异判断:** 测试判断两个版本号是否属于不同主要版本的功能。
16. **选项键解析:** 测试从字符串解析出 `OptionKey` 对象的功能，这用于管理构建选项。

**与逆向方法的关系及举例说明:**

虽然这个文件本身是在测试构建系统的功能，但它间接地与逆向方法有关：

* **构建 Frida 工具:** Frida 是一款用于动态 instrumentation 的逆向工程工具。这个测试文件属于 Frida 项目的一部分，其目的是确保 Frida 的构建系统能够正确工作。一个稳定可靠的构建系统是开发和维护 Frida 这样的复杂逆向工具的基础。
* **参数处理的健壮性:**  `@typed_kwargs` 确保了 Frida 构建脚本中定义的函数能够接收到正确类型的参数。这有助于防止由于参数类型错误导致的构建失败或潜在的运行时问题。在逆向工程中，我们经常需要与各种工具和脚本交互，确保参数传递的正确性非常重要。
* **版本兼容性:** `since` 和 `deprecated` 功能有助于 Frida 开发团队管理 API 的演进，并向用户提供关于功能引入和弃用的明确信息。这对于使用 Frida 进行逆向分析的用户来说非常重要，因为他们需要了解不同 Frida 版本之间的差异。

**二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个测试文件本身没有直接操作二进制底层、Linux 或 Android 内核，但其中一些测试涉及的概念与这些领域相关：

* **CPU 架构检测 (`test_detect_cpu_family`, `test_detect_cpu`):**  逆向工程通常需要关注目标程序的运行平台。了解目标设备的 CPU 架构 (例如 ARM, x86) 是进行静态分析、动态调试和编写 Frida 脚本的关键。Meson 构建系统需要能够正确检测构建机器和目标机器的 CPU 架构，以便选择正确的编译器和链接器设置。
    * **举例:**  在为 Android 设备构建 Frida-gum 时，Meson 需要能够检测到目标设备是 ARM 架构，并选择 ARM 交叉编译器。
* **`MachineChoice`:**  这个枚举类型 (BUILD, HOST)  反映了构建系统需要区分构建机器和目标机器的概念，这在交叉编译的场景下非常重要。Android 开发通常涉及在主机上为 ARM 架构的 Android 设备进行交叉编译。

**逻辑推理、假设输入与输出:**

许多测试用例都包含了逻辑推理，它们基于特定的输入假设，并验证输出是否符合预期。以下举例说明：

* **测试 `test_typed_kwarg_since`:**
    * **假设输入:**  定义一个带有 `since` 和 `deprecated` 属性的关键字参数的函数，并在不同的 Meson 版本下调用该函数。
    * **预期输出:**  根据当前的 Meson 版本，程序会输出相应的警告信息，提示该参数是在哪个版本引入的或者在哪个版本被弃用的。例如，在 Meson 0.1 下使用 `since='1.0'` 的参数会发出 "introduced" 警告，而在 Meson 2.0 下使用 `deprecated='2.0'` 的参数会发出 "deprecated" 警告。
* **测试 `test_typed_kwarg_container_pairs`:**
    * **假设输入:** 定义一个 `pairs=True` 的列表类型关键字参数的函数，并分别传入长度为偶数和奇数的列表。
    * **预期输出:** 当传入长度为偶数的列表时，测试通过。当传入长度为奇数的列表时，会抛出 `MesonException` 异常，提示列表大小应为偶数。

**用户或编程常见的使用错误及举例说明:**

这个测试文件模拟了一些用户在使用 `@typed_kwargs` 时可能犯的错误：

* **类型错误:**  例如，在 `test_typed_kwarg_basic` 中，尝试将一个整数 `1` 赋值给期望字符串类型的关键字参数 `mytype`，会导致 `InvalidArguments` 异常。
* **缺少必需的参数:**  虽然在这个代码片段中没有直接体现，但在其他部分的测试中可能会有测试缺少 `required=True` 的关键字参数的情况。
* **使用已弃用的参数或值:** `test_typed_kwarg_since_values` 测试了在不同 Meson 版本下使用已弃用的参数值时会发出警告。用户如果忽略这些警告，可能会导致代码在未来的 Meson 版本中无法正常工作。
* **为 `pairs=True` 的容器传入奇数大小的数据:** `test_typed_kwarg_container_pairs` 展示了这种错误，用户需要确保提供的数据符合 `pairs=True` 的要求。
* **提供无效的值给带有 `validator` 的参数:** `test_typed_kwarg_validator` 展示了如果用户提供的参数值不满足验证函数的条件，将会抛出异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发人员，要修改或调试与 `@typed_kwargs` 相关的代码，可能会经历以下步骤：

1. **发现问题:** 在使用 Meson 构建系统时，遇到了关于关键字参数处理的错误或不符合预期的行为。这可能是用户报告的 bug，或者在开发新功能时发现的。
2. **定位代码:** 通过错误信息、堆栈跟踪或代码审查，定位到可能与问题相关的代码，很可能涉及到使用了 `@typed_kwargs` 的函数定义。
3. **查看测试:**  为了理解 `@typed_kwargs` 的预期行为以及如何正确使用它，开发人员会查看相关的单元测试，例如 `frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py` 中的测试用例。
4. **运行测试:** 开发人员可能会修改测试用例来重现问题，或者编写新的测试用例来验证修复方案。他们会使用 Meson 的测试命令 (例如 `meson test`) 来运行这些测试。
5. **调试代码:** 如果测试失败，开发人员会使用调试器或其他调试工具来分析代码的执行流程，找出问题所在。他们可能会单步执行 `@typed_kwargs` 装饰器的代码，或者相关辅助函数的代码。
6. **修复问题:**  根据调试结果，修改 `@typed_kwargs` 的实现或者使用它的代码，以解决问题。
7. **验证修复:**  修改代码后，重新运行测试用例，确保所有的测试都通过，从而验证修复方案的正确性。

**总结 (基于第三部分):**

作为第三部分，这个文件主要集中测试了 Meson 构建系统中用于增强函数关键字参数处理的装饰器 `@typed_kwargs` 的各种功能。它通过大量的单元测试用例，覆盖了类型检查、默认值处理、引入/弃用机制、值验证、类型转换等多个方面，确保了这个装饰器能够按照预期工作，从而提高了 Frida 构建系统的健壮性和可靠性。虽然该文件本身不直接涉及 Frida 的运行时行为或底层细节，但它对于确保 Frida 项目构建过程的正确性至关重要，间接地支持了 Frida 作为一款强大的逆向工程工具的功能。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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