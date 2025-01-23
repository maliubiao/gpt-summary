Response:
The user wants to understand the functionality of the Python code provided. I need to analyze the code and describe its purpose, highlighting connections to reverse engineering, low-level concepts, and potential user errors.

**Plan:**

1. **Identify the core functionality:** The code seems to be related to testing argument parsing and validation, specifically using decorators like `@typed_kwargs`.
2. **Reverse Engineering Relevance:**  Consider how argument validation and type checking might be relevant to reverse engineering, especially when interacting with dynamic analysis tools like Frida.
3. **Low-Level Concepts:** Check for any interaction with OS primitives, kernel concepts, or architecture-specific details. The `detect_cpu_family` and `detect_cpu` functions are key here.
4. **Logical Inference:**  Analyze test cases that demonstrate input-output relationships.
5. **User Errors:** Identify scenarios where incorrect usage of the tested functions could lead to errors.
6. **Debugging Context:** Consider how a user might end up running these tests, relating it to the development workflow of Frida or Meson.
7. **Summarize:** Provide a concise overview of the file's purpose based on the analysis.
这是frida动态 instrumentation工具中，用于测试其构建系统Meson中内部实用工具功能的单元测试文件。

**主要功能归纳:**

该文件 `internaltests.py` 的主要功能是测试 Meson 构建系统中用于定义和验证函数参数的内部机制，特别是使用了 `typed_kwargs` 装饰器的相关功能。  它通过一系列单元测试来确保这些参数处理机制能够正确地进行类型检查、默认值设置、版本控制（since/deprecated）、自定义校验以及类型转换。

**具体功能点拆解与举例说明:**

1. **类型检查 (`test_typed_kwarg_string`, `test_typed_kwarg_bool`, `test_typed_kwarg_container`, `test_typed_kwarg_container_pairs`, `test_typed_kwarg_container_in_tuple`):**
    *   **功能:** 验证使用 `typed_kwargs` 装饰器定义的函数，其参数能够按照预期的类型接收输入。
    *   **逆向关系举例:** 在编写 Frida 脚本时，如果某个 Frida API 函数 (例如，用于 hook 函数的 `Interceptor.attach`) 使用了类似的参数类型检查机制，那么这个测试文件就像是在验证 Frida 内部参数处理的正确性。如果逆向工程师错误地传递了参数类型（例如，本应传递字符串却传递了整数），Frida 内部的类型检查机制（如果存在且被正确测试）就能捕获到这个错误，并提供相应的错误信息。
    *   **假设输入与输出:**
        *   假设被测试的函数定义了 `input` 参数为字符串类型。
        *   **输入:** `{'input': 'hello'}`
        *   **输出:** 测试通过
        *   **输入:** `{'input': 123}`
        *   **输出:** 抛出 `MesonException`，提示类型错误。
    *   **用户错误举例:** 用户在编写 Meson 构建脚本时，可能会错误地配置某个选项的类型，例如，将一个期望字符串的选项配置成了布尔值。这些单元测试可以帮助 Meson 的开发者确保这种错误配置会被及时发现。

2. **默认值 (`test_typed_kwarg_default`, `test_typed_kwarg_default_type`):**
    *   **功能:** 验证 `typed_kwargs` 装饰器能够正确地设置和使用参数的默认值。
    *   **用户错误举例:** 用户可能忘记在 Meson 构建脚本中设置某个可选参数，如果该参数有合理的默认值，并且该功能经过了充分的测试，那么程序可以正常运行而不会出错。

3. **版本控制 (`test_typed_kwarg_since`, `test_typed_kwarg_since_values`):**
    *   **功能:** 验证 `typed_kwargs` 装饰器能够根据 Meson 的版本来控制参数的引入和废弃，并发出相应的警告信息。
    *   **逆向关系举例:** Frida 本身也有版本迭代，某些 API 可能会在特定版本引入或废弃。类似的机制可以帮助 Frida 开发者在版本升级时提供向后兼容性或提醒用户更新他们的脚本。
    *   **涉及二进制底层/框架知识:**  版本控制可能涉及到对 Frida 内部数据结构或 API 接口的修改。例如，旧版本的 Frida 可能使用一种数据结构来表示内存范围，新版本可能采用了更高效或更完善的结构。版本控制机制需要感知这些底层变化。
    *   **假设输入与输出:**
        *   假设参数 `input` 在版本 '1.1' 引入。
        *   **输入 (Meson 版本 1.0):** 使用了 `input` 参数
        *   **输出:** 产生警告信息，提示该参数是在更高版本引入的。
        *   假设参数 `output` 在版本 '2.0' 废弃。
        *   **输入 (Meson 版本 2.0):** 使用了 `output` 参数
        *   **输出:** 产生警告信息，提示该参数已废弃。

4. **自定义校验器 (`test_typed_kwarg_validator`):**
    *   **功能:** 验证 `typed_kwargs` 装饰器允许使用自定义的校验函数来对参数值进行更复杂的检查。
    *   **逆向关系举例:**  在 Frida 中，某些 API 可能需要参数满足特定的格式或范围。例如，一个表示内存地址的参数可能需要是一个 4 字节或 8 字节的整数，并且在有效的内存区域内。自定义校验器可以用来实现这些更细粒度的检查。
    *   **假设输入与输出:**
        *   假设参数 `input` 的校验器要求其值为 'foo'。
        *   **输入:** `{'input': 'foo'}`
        *   **输出:** 测试通过
        *   **输入:** `{'input': 'bar'}`
        *   **输出:** 抛出 `MesonException`，提示参数无效。

5. **类型转换器 (`test_typed_kwarg_convertor`):**
    *   **功能:** 验证 `typed_kwargs` 装饰器可以用于在接收参数后对其进行类型转换。
    *   **逆向关系举例:**  Frida 某些 API 可能接收字符串形式的参数，但内部需要将其转换为特定的枚举类型或数据结构。类型转换器可以简化这种处理。
    *   **涉及编程常见的使用错误:** 用户可能传递了错误格式的字符串，导致转换失败。例如，API 期望接收 "HOST" 或 "BUILD"，用户却传递了 "local"。

6. **CPU 架构检测 (`test_detect_cpu_family`, `test_detect_cpu`):**
    *   **功能:** 测试 Meson 检测目标平台 CPU 架构的能力。
    *   **涉及二进制底层/Linux/Android 内核及框架的知识:**  CPU 架构是底层编译和执行的基础。`detect_cpu_family` 和 `detect_cpu` 函数需要理解不同操作系统和硬件平台表示 CPU 架构的方式（例如，通过环境变量、系统调用等），并进行规范化。这涉及到对 Linux 和 Android 内核中获取 CPU 信息的相关接口的了解。
    *   **逆向关系举例:** Frida 需要知道目标设备的 CPU 架构才能正确地加载和执行 Agent 代码。例如，针对 ARM64 架构编译的 Agent 代码无法在 x86 设备上运行。
    *   **假设输入与输出:**
        *   **输入 (运行在 x86_64 系统):** 调用 `detect_cpu_family`
        *   **输出:** 'x86_64'
        *   **输入 (运行在 ARM64 系统):** 调用 `detect_cpu_family`
        *   **输出:** 'aarch64'

7. **Interpreter 的不可序列化测试 (`test_interpreter_unpicklable`):**
    *   **功能:**  测试 Meson 的 Interpreter 对象是否故意设计为不可序列化 (unpicklable)。这通常是为了防止在构建过程中出现状态不一致的问题。
    *   **涉及编程常见的使用错误:** 开发者可能会尝试将 Interpreter 对象进行序列化（例如，使用 `pickle`），如果该对象被设计为不可序列化，则会抛出异常。这个测试验证了这种行为的预期性。

8. **版本差异比较 (`test_major_versions_differ`):**
    *   **功能:**  测试用于比较 Meson 版本差异的工具函数，特别是判断是否跨越了主版本号。这在版本控制相关的逻辑中非常重要。

9. **选项键解析 (`test_option_key_from_string`):**
    *   **功能:** 测试将字符串形式的选项键转换为内部 `OptionKey` 对象的函数。这有助于在 Meson 内部统一处理各种构建选项。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接运行这些单元测试。这些测试是 Meson 或 Frida 开发者在开发和维护过程中使用的。一个用户可能会间接地触发与这些测试相关的代码，例如：

1. **配置 Frida 的构建选项:** 用户在构建 Frida 时，会使用 Meson 配置各种选项（例如，目标架构、编译器等）。Meson 内部的 `typed_kwargs` 机制会处理这些选项的解析和验证。如果用户配置了错误的选项值，与 `typed_kwargs` 相关的代码可能会抛出异常。
2. **运行 Frida 脚本:** 当 Frida 脚本调用 Frida 提供的 API 时，这些 API 的参数也可能使用了类似的类型检查和验证机制。如果用户在脚本中传递了错误的参数，Frida 内部的参数处理代码（其行为可能受到类似 `typed_kwargs` 机制的影响）会捕获到错误。
3. **开发 Meson 构建系统:** 如果用户是 Meson 的开发者，他们会编写和运行这些单元测试来确保代码的正确性。他们可能会修改 `internaltests.py` 文件来添加新的测试用例或修复现有的 bug。

**总结它的功能 (第3部分归纳):**

总的来说，`frida/subprojects/frida-tools/releng/meson/unittests/internaltests.py` 这个文件专注于测试 Meson 构建系统中用于定义和验证函数参数的关键内部机制。它通过各种单元测试用例，覆盖了类型检查、默认值、版本控制、自定义校验、类型转换以及 CPU 架构检测等功能。这些测试确保了 Meson 能够可靠地处理构建选项，并在用户提供不正确的参数时能够给出清晰的错误提示，从而提高构建系统的健壮性和用户体验。从逆向工程的角度来看，这些测试也间接保证了 Frida 内部参数处理的正确性，这对于 Frida API 的稳定性和脚本开发的可靠性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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