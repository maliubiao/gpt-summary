Response:
The user wants to understand the functionality of the provided Python code. This code is a unit test file for the Frida dynamic instrumentation tool, specifically focusing on internal functionalities within the Meson build system integration.

To address the user's request, I need to:

1. **Summarize the main purpose of the code:** It tests various aspects of how keyword arguments are handled in Meson's build definitions, especially focusing on type checking, default values, deprecation/introduction warnings, and value validation.

2. **Identify connections to reverse engineering:** While the code itself isn't directly performing reverse engineering, the concepts it tests (like inspecting function arguments and potentially modifying behavior based on those arguments) are related to the core principles of dynamic instrumentation used in reverse engineering.

3. **Highlight low-level/kernel/framework aspects:** The code touches upon concepts like CPU architecture detection, which relates to low-level system information. It also indirectly relates to build systems that manage the compilation and linking of software, which can involve interactions with the operating system and its frameworks.

4. **Analyze logical reasoning:** The tests often involve setting up specific inputs (keyword arguments) and verifying the expected output or behavior (e.g., exceptions, warnings). I need to identify these input-output relationships.

5. **Point out potential user errors:** The tests often validate how the system reacts to incorrect or unexpected inputs, which can be translated to common user errors in defining build configurations.

6. **Explain the user's path to this code:**  This file is part of the internal testing framework of Frida's Meson build system. A user wouldn't typically interact with this file directly. They would interact with Meson by writing `meson.build` files, configuring the build, and running the build process. Understanding this file helps developers ensure the correctness of Meson's argument handling.

7. **Synthesize a final summary:** Based on the above points, I need to create a concise overview of the file's purpose and its role within the larger Frida project.
这是Frida动态Instrumentation工具的源代码文件 `internaltests.py` 的第三部分，它主要包含了一系列的单元测试，用于验证Frida Node.js绑定在构建过程中的内部功能，特别是与Meson构建系统集成的相关特性。

**归纳其功能：**

这个文件的核心功能是测试 Meson 构建系统中用于处理函数和方法的关键字参数的装饰器 (`@typed_kwargs`) 的各种行为。它涵盖了以下几个关键方面：

1. **类型检查和强制转换:** 验证 `@typed_kwargs` 装饰器能否正确地检查关键字参数的类型，并在需要时进行类型转换 (`listify=True`)。
2. **默认值处理:** 测试 `@typed_kwargs` 是否能正确处理关键字参数的默认值。
3. **版本控制 (since/deprecated):** 验证 `@typed_kwargs` 能否根据 Meson 的版本信息，对引入 (since) 和废弃 (deprecated) 的关键字参数或其值发出警告。
4. **参数校验器 (validator):** 测试 `@typed_kwargs` 是否能使用自定义的校验函数来验证关键字参数的值。
5. **参数转换器 (convertor):** 验证 `@typed_kwargs` 是否能使用自定义的转换函数来改变关键字参数的值。
6. **容器类型处理:**  测试 `@typed_kwargs` 对列表 (`list`) 和字典 (`dict`) 等容器类型参数的处理，包括元素类型检查和成对出现的要求 (`pairs=True`)。
7. **CPU体系结构检测:** 测试 Frida Node.js 绑定在不同平台上检测 CPU 体系结构的功能。
8. **内部对象的可pickle性:** 检查 Frida Node.js 绑定的某些内部对象 (如 `Interpreter`) 是否可以被 pickle 序列化，以避免潜在的错误。
9. **Meson版本比较:** 测试用于比较 Meson 版本号的功能。
10. **Meson选项键解析:** 验证从字符串解析 Meson 构建选项键的功能。

**与逆向方法的关系 (举例说明):**

虽然这个文件本身不是直接进行逆向操作，但它测试的功能是 Frida 这种动态 Instrumentation 工具的基础。`@typed_kwargs` 保证了构建系统能够正确地配置 Frida Node.js 绑定，这对于最终用户使用 Frida 进行逆向分析至关重要。

* **举例说明:**  在 Frida 中，用户可能需要指定要注入的目标进程的架构 (例如，`--arch arm64`)。Meson 构建系统需要正确地解析和验证这个参数。`internaltests.py` 中对 CPU 体系结构检测的测试，以及对 `@typed_kwargs` 类型检查的测试，确保了当用户提供错误的架构信息时，构建系统能够给出明确的错误提示，而不是默默地构建出不兼容的版本，从而影响逆向分析的有效性。

**涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明):**

* **二进制底层 (CPU体系结构检测):**  `test_detect_cpu_family` 和 `test_detect_cpu` 函数直接涉及到检测不同平台的 CPU 体系结构 (如 x86, ARM, MIPS 等)。这些体系结构是二进制代码运行的基础，理解它们对于逆向工程至关重要。Frida 需要根据目标进程的 CPU 架构来加载和执行相应的 Instrumentation 代码。
* **Linux/Android 内核及框架 (间接关系):**  虽然代码本身没有直接操作内核，但 Frida 作为一种动态 Instrumentation 工具，其核心功能是修改目标进程的内存和行为。在 Linux 和 Android 系统上，这涉及到对进程地址空间、系统调用、以及运行时环境的深入理解。Meson 构建系统需要正确地配置编译选项和链接库，以便生成的 Frida Node.js 绑定能够与目标系统兼容并正常工作。例如，构建脚本可能需要根据目标平台的 libc 版本来选择合适的链接选项。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  调用一个使用了 `@typed_kwargs` 装饰器的函数，并传递一个类型错误的关键字参数，例如，该参数期望一个字符串，但传入了一个整数。
* **预期输出:**  `@typed_kwargs` 装饰器应该抛出一个 `MesonException` 异常，明确指出参数类型错误，并说明期望的类型是什么。例如，在 `test_typed_kwarg_type_mismatch` 中就测试了这种情况。

**涉及用户或者编程常见的使用错误 (举例说明):**

* **类型错误:** 用户在定义 Meson 构建选项或者调用 Meson 定义的函数时，可能会传递类型错误的参数。例如，某个选项期望一个布尔值，用户却传递了一个字符串 "true"。`internaltests.py` 中大量的类型检查测试，就是为了防止这类错误发生，并提供清晰的错误信息。
* **使用已废弃的参数或值:**  随着软件的迭代，某些参数或参数值可能会被废弃。如果用户仍然使用这些废弃的特性，可能会导致警告甚至错误。`test_typed_kwarg_since_values` 验证了当用户使用已废弃的参数值时，系统是否能正确地发出警告。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

这个 `internaltests.py` 文件是 Frida Node.js 绑定项目内部的测试代码，普通用户在正常使用 Frida 时不会直接接触到这个文件。以下是可能到达这里的场景（主要针对开发者）：

1. **Frida Node.js 绑定开发:**  开发者在修改 Frida Node.js 绑定的代码，特别是涉及到 Meson 构建配置或者函数参数处理的部分时，会编写或修改相关的单元测试，包括 `internaltests.py`。
2. **调试 Meson 构建集成问题:**  当 Frida Node.js 绑定的构建过程出现问题时，开发者可能会运行这些单元测试来定位问题。例如，如果某个关键字参数的处理逻辑发生错误，相关的单元测试会失败，从而提供调试线索。
3. **了解 Frida Node.js 绑定的内部机制:**  开发者可以通过阅读 `internaltests.py` 中的测试用例，了解 Frida Node.js 绑定是如何使用 Meson 的 `@typed_kwargs` 装饰器来处理函数参数的，以及各种参数类型、默认值、版本控制和校验机制是如何工作的。

总而言之，`internaltests.py` 是 Frida Node.js 绑定项目质量保证的关键部分，它通过大量的单元测试，确保了 Meson 构建系统能够正确地配置和构建 Frida Node.js 绑定，从而为用户提供稳定可靠的动态 Instrumentation 工具。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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