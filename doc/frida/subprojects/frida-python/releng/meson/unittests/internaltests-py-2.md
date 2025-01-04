Response:
The user wants a summary of the functionalities of the Python code provided. I need to go through the code and identify the purpose of each test function. The code seems to be testing various aspects of the `typed_kwargs` decorator and related functionalities in the Frida instrumentation tool.

Here's a breakdown of the code's apparent functionalities:

1. **Testing the `typed_kwargs` decorator:** The core function seems to be testing the `typed_kwargs` decorator, which is used to enforce type hints and other constraints on keyword arguments of a function.
2. **Testing default values:** Verifying that default values for keyword arguments are handled correctly.
3. **Testing container types:** Ensuring that the decorator correctly handles keyword arguments that are containers (like lists and dictionaries) with specific element types. It also tests for even sized pairs in containers.
4. **Testing `since` and `deprecated` attributes:** Checking the behavior of the `since` and `deprecated` attributes of `KwargInfo`, including emitting warnings based on the Meson version.
5. **Testing custom validators:** Verifying that custom validator functions for keyword arguments are executed and raise exceptions when validation fails.
6. **Testing custom convertors:** Ensuring that custom conversion functions for keyword arguments are applied correctly.
7. **Testing `since_values` and `deprecated_values`:** Checking the behavior of these attributes for specific values within keyword arguments, including emitting warnings based on the Meson version.
8. **Testing `evolve` method:** Verifying the functionality of the `evolve` method of `KwargInfo` for creating modified copies.
9. **Testing default value types:** Ensuring that the types of default values are compatible with the allowed types.
10. **Testing invalid default types:** Checking that an error is raised when an invalid default value type is provided.
11. **Testing container types within tuples:** Ensuring that container types can be correctly specified within a tuple of allowed types.
12. **Testing CPU family detection:**  Verifying the logic for detecting and normalizing CPU family names based on system information and compiler defines. This likely relates to cross-compilation or architecture-specific builds.
13. **Testing CPU detection:** Similar to CPU family detection, but focusing on more specific CPU names.
14. **Testing interpreter pickling:** Checking that the `Interpreter` class cannot be pickled, likely to prevent issues with state management.
15. **Testing major version difference detection:**  Verifying a function that determines if two version strings represent different major releases.
16. **Testing option key parsing:**  Ensuring that option keys can be correctly parsed from strings.

Now, let's consider how these functionalities relate to the user's request, specifically regarding reverse engineering, binary details, and common user errors.
This Python code file, located within the `frida-python` project's testing infrastructure, primarily focuses on **unit testing the functionality of the `typed_kwargs` decorator and related helper classes.** This decorator is likely used within the Frida codebase to enforce type hints and other constraints on the keyword arguments of functions, particularly those exposed to users or other parts of the system.

Here's a breakdown of its functionalities:

**Core Functionality: Testing `typed_kwargs` Decorator**

The majority of the tests in this file revolve around validating the behavior of the `typed_kwargs` decorator and the `KwargInfo` class. These tests ensure that:

*   **Type checking:** The decorator correctly enforces the specified types for keyword arguments. It raises errors if the provided argument doesn't match the expected type (e.g., expecting a string but getting an integer).
*   **Default values:** Default values specified for keyword arguments are correctly applied when the argument is not provided.
*   **Container type handling:**  The decorator correctly handles keyword arguments that are lists or dictionaries, including checking the types of elements within those containers. It also tests for specific constraints on containers, like requiring an even number of elements for "pairs".
*   **`since` and `deprecated` functionality:** The decorator can issue warnings when a keyword argument is used before its introduction (`since`) or after its deprecation (`deprecated`), based on the project's Meson version.
*   **Custom validators:** The decorator can utilize custom validator functions to enforce more complex constraints on keyword arguments.
*   **Custom convertors:** The decorator can use custom converter functions to transform the provided argument into the expected type.
*   **`since_values` and `deprecated_values`:** Similar to `since` and `deprecated` but for specific values within a keyword argument. Warnings are issued based on the project's Meson version when specific values are used.
*   **Evolving keyword arguments:**  The `evolve` method allows creating a new `KwargInfo` instance with modifications (like changing the default value) while keeping other attributes the same.
*   **Handling of `NoneType`:**  The decorator correctly handles cases where `None` is an allowed type for a keyword argument.
*   **Container types within tuples:**  The decorator can handle scenarios where a keyword argument can be either a specific type or a container type (e.g., either a string or a list of strings).

**Relationship to Reverse Engineering:**

While this specific file doesn't directly perform reverse engineering, the underlying functionality it tests is crucial for tools like Frida that are used in dynamic analysis and reverse engineering.

*   **User interface and API stability:**  By enforcing type hints and providing warnings for deprecated features, `typed_kwargs` helps maintain a stable and predictable user interface for Frida's Python API. This is important for reverse engineers who rely on these APIs for scripting and automation. If argument types suddenly changed without notice, existing scripts would break.
*   **Preventing common user errors:** The type checking and validation mechanisms help prevent common errors that users might make when interacting with Frida's APIs, making the tool more user-friendly.

**Example:** Imagine a Frida function to hook a specific function address. Without type checking, a user might accidentally pass a string representing the address instead of an integer. The `typed_kwargs` decorator could enforce that the address argument is an integer, preventing a runtime error deep within Frida's core.

**Relationship to Binary底层, Linux, Android 内核及框架:**

While the code itself is Python-level, the concepts it tests are relevant to interacting with lower-level systems:

*   **Machine architecture detection:** The tests for `detect_cpu_family` and `detect_cpu` directly interact with system calls and platform information to determine the underlying CPU architecture (e.g., x86, ARM, MIPS). This is essential for Frida, which needs to understand the target architecture to correctly perform hooking, code injection, and other instrumentation tasks.
*   **Compiler flags and settings:** The detection of CPU architecture is often linked to compiler flags and settings used during the build process. Frida needs to be aware of these to ensure compatibility and correct operation on different platforms.
*   **Interacting with system APIs:**  Frida, at its core, interacts with operating system APIs (like ptrace on Linux) to perform its instrumentation. The Python API provides a higher-level abstraction, and `typed_kwargs` helps ensure that the arguments passed from Python are the correct types expected by the underlying C/C++ Frida code that interacts with these system APIs.

**Example:** When attaching to a process on Android, Frida needs to know the target device's architecture (ARM, ARM64, etc.) to load the correct agent library. The `detect_cpu` functions contribute to this process.

**Logical Reasoning with Assumptions:**

The tests in this file are inherently based on logical reasoning and assumptions:

*   **Assumption:** The `typed_kwargs` decorator should correctly identify the type of the provided keyword argument.
    *   **Input:** A function decorated with `typed_kwargs` expecting an integer, and the user provides the string "123".
    *   **Output:** A `MesonException` is raised indicating a type mismatch.
*   **Assumption:** The `since` and `deprecated` mechanism should issue warnings based on the current Meson version.
    *   **Input:** A keyword argument marked `since='1.0'` is used when the project's Meson version is '0.9'.
    *   **Output:** A warning message is printed to the console indicating that the argument is used before its introduction.
*   **Assumption:** Custom validator functions should be executed, and if they return an error message, a `MesonException` should be raised.
    *   **Input:** A keyword argument with a validator that checks if the input is "foo", and the user provides "bar".
    *   **Output:** A `MesonException` is raised with the validator's error message.

**Common User or Programming Errors:**

This testing file indirectly addresses common user errors by ensuring the `typed_kwargs` decorator works correctly. Examples of errors it helps prevent:

*   **Incorrect argument types:** Passing a string when an integer is expected, or a list when a dictionary is required. The tests ensure that the decorator catches these errors early.
*   **Using deprecated features:** Users might unknowingly use keyword arguments or values that have been deprecated. The `since` and `deprecated` tests ensure that warnings are issued to guide users towards the correct usage.
*   **Providing invalid values:**  Custom validators can catch more specific errors, like providing a file path that doesn't exist or a port number outside the valid range.

**User Operation Flow as a Debugging Clue:**

While this file is for internal testing, understanding how a user might reach a point where these checks are relevant is important for debugging:

1. **User writes a Frida script:** A user interacts with the `frida` Python module and calls functions from its API.
2. **Function call with keyword arguments:** The user calls a Frida function and provides values for its keyword arguments.
3. **`typed_kwargs` decorator is applied:** The Frida function they called is decorated with `@typed_kwargs`.
4. **Type checking and validation:** The `typed_kwargs` decorator intercepts the keyword arguments and performs type checking, default value application, validation, and conversion based on the `KwargInfo` definitions.
5. **Error or warning (if applicable):** If the user provides an incorrect type, an invalid value, or uses a deprecated feature, the `typed_kwargs` decorator will raise an exception or issue a warning. This is where the tests in this file are crucial for ensuring this mechanism works correctly.

**Example Debugging Scenario:**

A user reports getting a cryptic error when calling `frida.spawn(..., env={'LD_PRELOAD': 123})`. The developers might look at the definition of `frida.spawn` and see that the `env` argument is decorated with `@typed_kwargs`, expecting a dictionary of strings. The tests in this file would have ensured that providing an integer like `123` as a value in the `env` dictionary would raise a clear type error, helping the developers quickly identify the user's mistake.

**Summary of Functionality (Part 3):**

This Python file provides **unit tests for the `typed_kwargs` decorator and related functionality within the Frida instrumentation tool**. It verifies that the decorator correctly enforces type hints, handles default values, manages container types, issues warnings for deprecated features, utilizes custom validators and convertors, and accurately detects the underlying CPU architecture. This ensures a more robust and user-friendly Python API for Frida, preventing common user errors and contributing to the stability of the tool used in dynamic analysis and reverse engineering.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
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

"""


```