Response:
The user wants a summary of the functionality of the Python code provided, specifically focusing on its relevance to reverse engineering, low-level interactions, logical reasoning, common user errors, debugging context, and an overall summarization.

Here's a breakdown of the thought process to achieve the desired output:

1. **Understand the Code's Core Purpose:** The code is a unit test suite (`internaltests.py`) for the `frida-node` project, specifically within the `meson` build system's context. This means it's designed to verify the correct behavior of various internal functionalities of `frida-node` during the build process.

2. **Identify Key Functionality Blocks:**  Go through the test functions (`test_...`) and group them by the core functionality they are testing. The major areas identified are:
    * Version Comparison (`test_version_compare`)
    * MSVC Toolset Version Detection (`test_msvc_toolset_version`)
    * Argument Splitting and Quoting (`test_split_args`, `test_quote_arg`)
    * Dependency File Parsing (`test_depfile`)
    * Logging Mechanisms (`test_log_once`, `test_log_once_ansi`)
    * Library Path Sorting (`test_sort_libpaths`)
    * Dependency Factory Ordering (`test_dependency_factory_order`)
    * JSON Schema Validation (`test_validate_json`)
    * Argument Type Validation (`test_typed_pos_args_*`, `test_typed_kwarg_*`)

3. **Analyze Relevance to Reverse Engineering:**  Consider how each functionality block might relate to reverse engineering with Frida:
    * **Version Comparison:** Important for ensuring compatibility between Frida components. If versions mismatch, reverse engineering scripts might fail.
    * **MSVC Toolset Version:** Relevant when Frida interacts with Windows binaries, ensuring the correct compiler and runtime environment are used.
    * **Argument Splitting/Quoting:**  Crucial for correctly passing arguments to Frida commands or spawned processes. Incorrect quoting can lead to unexpected behavior during reverse engineering sessions.
    * **Dependency File Parsing:**  While less directly related to *using* Frida, it's important for *building* Frida and ensuring all necessary libraries are included. This can indirectly impact the capabilities available during reverse engineering.
    * **Logging:** Helps in debugging Frida itself or reverse engineering scripts that use Frida.
    * **Library Path Sorting:** Ensures Frida can find required libraries, which is vital for its operation during reverse engineering.
    * **Dependency Factory Order:** Affects how Frida locates and links against dependencies, important for its core functionality in hooking and instrumenting processes.
    * **JSON Schema Validation:** Used for validating configuration files or data structures used by Frida, which can indirectly affect reverse engineering workflows.
    * **Argument Type Validation:**  Ensures that internal Frida functions receive the correct types of arguments, preventing errors during reverse engineering tasks.

4. **Analyze Relevance to Low-Level/Kernel/Framework:**
    * **MSVC Toolset Version:** Directly related to the Windows development environment and the build process for native Windows components.
    * **Argument Splitting/Quoting (Windows):**  Highlights the intricacies of Windows command-line parsing, which is relevant when Frida interacts with or spawns processes on Windows.
    * **Dependency File Parsing:**  Reflects how build systems manage dependencies, which often involves linking against low-level system libraries.
    * **Library Path Sorting:** Directly deals with how the operating system (Linux, Android) locates shared libraries, a fundamental concept in OS architecture.

5. **Identify Logical Reasoning and Hypothetical Scenarios:** Focus on test cases that involve comparisons, conditional logic, or specific input-output expectations:
    * **Version Comparison:**  The extensive list of version strings and expected comparison results demonstrates logical reasoning. The "assumptions" are the version comparison rules themselves.
    * **Argument Splitting/Quoting:** The test cases with various combinations of quotes and backslashes exemplify how the code reasons about command-line parsing.
    * **Dependency File Parsing:**  The tests for cycles in dependencies show how the code handles complex graph-like relationships.

6. **Pinpoint Potential User/Programming Errors:** Look for test cases that expose common mistakes developers might make:
    * **Argument Splitting/Quoting:** Incorrect quoting is a frequent source of command-line errors.
    * **Argument Type Validation:**  Passing the wrong type of argument to a function is a very common programming error.
    * **Missing Required Arguments:** Forcing users to provide necessary information prevents runtime errors.

7. **Construct the Debugging Path:**  Imagine a scenario where a test in this file fails. How would a developer arrive here?
    * Start with a change in the code that affects one of the functionalities being tested.
    * The automated test suite (likely run during development or CI) would identify the failure in `internaltests.py`.
    * The developer would then examine the specific failing test case and the code it exercises to understand the root cause.

8. **Summarize the Functionality:**  Combine the understanding of the individual test functions into a concise overall summary of what the file achieves.

9. **Structure the Output:** Organize the findings according to the user's request, using clear headings and bullet points for readability. Provide specific examples from the code where relevant. Maintain a distinction between direct functionality and its implications for reverse engineering/low-level aspects.

10. **Review and Refine:**  Read through the generated summary to ensure accuracy, clarity, and completeness. Check that all aspects of the user's prompt have been addressed. For example, double-check that the input and output assumptions for logical reasoning are clearly stated.
```python
k_args)

    def test_version_compare(self):
        comparefunc = mesonbuild.mesonlib.version_compare_many
        for (a, b, result) in [
                ('0.99.beta19', '>= 0.99.beta14', True),
        ]:
            self.assertEqual(comparefunc(a, b)[0], result)

        for (a, b, op) in [
                # examples from https://fedoraproject.org/wiki/Archive:Tools/RPM/VersionComparison
                ("1.0010", "1.9", operator.gt),
                ("1.05", "1.5", operator.eq),
                ("1.0", "1", operator.gt),
                ("2.50", "2.5", operator.gt),
                ("fc4", "fc.4", operator.eq),
                ("FC5", "fc4", operator.lt),
                ("2a", "2.0", operator.lt),
                ("1.0", "1.fc4", operator.gt),
                ("3.0.0_fc", "3.0.0.fc", operator.eq),
                # from RPM tests
                ("1.0", "1.0", operator.eq),
                ("1.0", "2.0", operator.lt),
                ("2.0", "1.0", operator.gt),
                ("2.0.1", "2.0.1", operator.eq),
                ("2.0", "2.0.1", operator.lt),
                ("2.0.1", "2.0", operator.gt),
                ("2.0.1a", "2.0.1a", operator.eq),
                ("2.0.1a", "2.0.1", operator.gt),
                ("2.0.1", "2.0.1a", operator.lt),
                ("5.5p1", "5.5p1", operator.eq),
                ("5.5p1", "5.5p2", operator.lt),
                ("5.5p2", "5.5p1", operator.gt),
                ("5.5p10", "5.5p10", operator.eq),
                ("5.5p1", "5.5p10", operator.lt),
                ("5.5p10", "5.5p1", operator.gt),
                ("10xyz", "10.1xyz", operator.lt),
                ("10.1xyz", "10xyz", operator.gt),
                ("xyz10", "xyz10", operator.eq),
                ("xyz10", "xyz10.1", operator.lt),
                ("xyz10.1", "xyz10", operator.gt),
                ("xyz.4", "xyz.4", operator.eq),
                ("xyz.4", "8", operator.lt),
                ("8", "xyz.4", operator.gt),
                ("xyz.4", "2", operator.lt),
                ("2", "xyz.4", operator.gt),
                ("5.5p2", "5.6p1", operator.lt),
                ("5.6p1", "5.5p2", operator.gt),
                ("5.6p1", "6.5p1", operator.lt),
                ("6.5p1", "5.6p1", operator.gt),
                ("6.0.rc1", "6.0", operator.gt),
                ("6.0", "6.0.rc1", operator.lt),
                ("10b2", "10a1", operator.gt),
                ("10a2", "10b2", operator.lt),
                ("1.0aa", "1.0aa", operator.eq),
                ("1.0a", "1.0aa", operator.lt),
                ("1.0aa", "1.0a", operator.gt),
                ("10.0001", "10.0001", operator.eq),
                ("10.0001", "10.1", operator.eq),
                ("10.1", "10.0001", operator.eq),
                ("10.0001", "10.0039", operator.lt),
                ("10.0039", "10.0001", operator.gt),
                ("4.999.9", "5.0", operator.lt),
                ("5.0", "4.999.9", operator.gt),
                ("20101121", "20101121", operator.eq),
                ("20101121", "20101122", operator.lt),
                ("20101122", "20101121", operator.gt),
                ("2_0", "2_0", operator.eq),
                ("2.0", "2_0", operator.eq),
                ("2_0", "2.0", operator.eq),
                ("a", "a", operator.eq),
                ("a+", "a+", operator.eq),
                ("a+", "a_", operator.eq),
                ("a_", "a+", operator.eq),
                ("+a", "+a", operator.eq),
                ("+a", "_a", operator.eq),
                ("_a", "+a", operator.eq),
                ("+_", "+_", operator.eq),
                ("_+", "+_", operator.eq),
                ("_+", "_+", operator.eq),
                ("+", "_", operator.eq),
                ("_", "+", operator.eq),
                # other tests
                ('0.99.beta19', '0.99.beta14', operator.gt),
                ("1.0.0", "2.0.0", operator.lt),
                (".0.0", "2.0.0", operator.lt),
                ("alpha", "beta", operator.lt),
                ("1.0", "1.0.0", operator.lt),
                ("2.456", "2.1000", operator.lt),
                ("2.1000", "3.111", operator.lt),
                ("2.001", "2.1", operator.eq),
                ("2.34", "2.34", operator.eq),
                ("6.1.2", "6.3.8", operator.lt),
                ("1.7.3.0", "2.0.0", operator.lt),
                ("2.24.51", "2.25", operator.lt),
                ("2.1.5+20120813+gitdcbe778", "2.1.5", operator.gt),
                ("3.4.1", "3.4b1", operator.gt),
                ("041206", "200090325", operator.lt),
                ("0.6.2+git20130413", "0.6.2", operator.gt),
                ("2.6.0+bzr6602", "2.6.0", operator.gt),
                ("2.6.0", "2.6b2", operator.gt),
                ("2.6.0+bzr6602", "2.6b2x", operator.gt),
                ("0.6.7+20150214+git3a710f9", "0.6.7", operator.gt),
                ("15.8b", "15.8.0.1", operator.lt),
                ("1.2rc1", "1.2.0", operator.lt),
        ]:
            ver_a = Version(a)
            ver_b = Version(b)
            if op is operator.eq:
                for o, name in [(op, 'eq'), (operator.ge, 'ge'), (operator.le, 'le')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
            if op is operator.lt:
                for o, name in [(op, 'lt'), (operator.le, 'le'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
                for o, name in [(operator.gt, 'gt'), (operator.ge, 'ge'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
            if op is operator.gt:
                for o, name in [(op, 'gt'), (operator.ge, 'ge'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
                for o, name in [(operator.lt, 'lt'), (operator.le, 'le'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')

    def test_msvc_toolset_version(self):
        '''
        Ensure that the toolset version returns the correct value for this MSVC
        '''
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Test only applies to MSVC-like compilers')
        toolset_ver = cc.get_toolset_version()
        self.assertIsNotNone(toolset_ver)
        # Visual Studio 2015 and older versions do not define VCToolsVersion
        # TODO: ICL doesn't set this in the VSC2015 profile either
        if cc.id == 'msvc' and int(''.join(cc.version.split('.')[0:2])) < 1910:
            return
        if 'VCToolsVersion' in os.environ:
            vctools_ver = os.environ['VCToolsVersion']
        else:
            self.assertIn('VCINSTALLDIR', os.environ)
            # See https://devblogs.microsoft.com/cppblog/finding-the-visual-c-compiler-tools-in-visual-studio-2017/
            vctools_ver = (Path(os.environ['VCINSTALLDIR']) / 'Auxiliary' / 'Build' / 'Microsoft.VCToolsVersion.default.txt').read_text(encoding='utf-8')
        self.assertTrue(vctools_ver.startswith(toolset_ver),
                        msg=f'{vctools_ver!r} does not start with {toolset_ver!r}')

    def test_split_args(self):
        split_args = mesonbuild.mesonlib.split_args
        join_args = mesonbuild.mesonlib.join_args
        if is_windows():
            test_data = [
                # examples from https://docs.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
                (r'"a b c" d e', ['a b c', 'd', 'e'], True),
                (r'"ab\"c" "\\" d', ['ab"c', '\\', 'd'], False),
                (r'a\\\b d"e f"g h', [r'a\\\b', 'de fg', 'h'], False),
                (r'a\\\"b c d', [r'a\"b', 'c', 'd'], False),
                (r'a\\\\"b c" d e', [r'a\\b c', 'd', 'e'], False),
                # other basics
                (r'""', [''], True),
                (r'a b c d "" e', ['a', 'b', 'c', 'd', '', 'e'], True),
                (r"'a b c' d e", ["'a", 'b', "c'", 'd', 'e'], True),
                (r"'a&b&c' d e", ["'a&b&c'", 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], True),
                (r"'a & b & c d e'", ["'a", '&', 'b', '&', 'c', 'd', "e'"], True),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),
                # more illustrative tests
                (r'cl test.cpp /O1 /Fe:test.exe', ['cl', 'test.cpp', '/O1', '/Fe:test.exe'], True),
                (r'cl "test.cpp /O1 /Fe:test.exe"', ['cl', 'test.cpp /O1 /Fe:test.exe'], True),
                (r'cl /DNAME=\"Bob\" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob\"" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], True),
                (r'cl /DNAME=\"Bob, Alice\" test.cpp', ['cl', '/DNAME="Bob,', 'Alice"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob, Alice\"" test.cpp', ['cl', '/DNAME="Bob, Alice"', 'test.cpp'], True),
                (r'cl C:\path\with\backslashes.cpp', ['cl', r'C:\path\with\backslashes.cpp'], True),
                (r'cl C:\\path\\with\\double\\backslashes.cpp', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], True),
                (r'cl "C:\\path\\with\\double\\backslashes.cpp"', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], False),
                (r'cl C:\path with spaces\test.cpp', ['cl', r'C:\path', 'with', r'spaces\test.cpp'], False),
                (r'cl "C:\path with spaces\test.cpp"', ['cl', r'C:\path with spaces\test.cpp'], True),
                (r'cl /DPATH="C:\path\with\backslashes test.cpp', ['cl', r'/DPATH=C:\path\with\backslashes test.cpp'], False),
                (r'cl /DPATH=\"C:\\ends\\with\\backslashes\\\" test.cpp', ['cl', r'/DPATH="C:\\ends\\with\\backslashes\"', 'test.cpp'], False),
                (r'cl /DPATH="C:\\ends\\with\\backslashes\\" test.cpp', ['cl', '/DPATH=C:\\\\ends\\\\with\\\\backslashes\\', 'test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\"', 'test.cpp'], True),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\ test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\"', 'test.cpp'], True),
            ]
        else:
            test_data = [
                (r"'a b c' d e", ['a b c', 'd', 'e'], True),
                (r"a/b/c d e", ['a/b/c', 'd', 'e'], True),
                (r"a\b\c d e", [r'abc', 'd', 'e'], False),
                (r"a\\b\\c d e", [r'a\b\c', 'd', 'e'], False),
                (r'"a b c" d e', ['a b c', 'd', 'e'], False),
                (r'"a\\b\\c\\" d e', ['a\\b\\c\\', 'd', 'e'], False),
                (r"'a\b\c\' d e", ['a\\b\\c\\', 'd', 'e'], True),
                (r"'a&b&c' d e", ['a&b&c', 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], False),
                (r"'a & b & c d e'", ['a & b & c d e'], True),
                (r"abd'e f'g h", [r'abde fg', 'h'], False),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),

                ('g++ -DNAME="Bob" test.cpp', ['g++', '-DNAME=Bob', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob\"' test.cpp", ['g++', '-DNAME="Bob"', 'test.cpp'], True),
                ('g++ -DNAME="Bob, Alice" test.cpp', ['g++', '-DNAME=Bob, Alice', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob, Alice\"' test.cpp", ['g++', '-DNAME="Bob, Alice"', 'test.cpp'], True),
            ]

        for (cmd, expected, roundtrip) in test_data:
            self.assertEqual(split_args(cmd), expected)
            if roundtrip:
                self.assertEqual(join_args(expected), cmd)

    def test_quote_arg(self):
        split_args = mesonbuild.mesonlib.split_args
        quote_arg = mesonbuild.mesonlib.quote_arg
        if is_windows():
            test_data = [
                ('', '""'),
                ('arg1', 'arg1'),
                ('/option1', '/option1'),
                ('/Ovalue', '/Ovalue'),
                ('/OBob&Alice', '/OBob&Alice'),
                ('/Ovalue with spaces', r'"/Ovalue with spaces"'),
                (r'/O"value with spaces"', r'"/O\"value with spaces\""'),
                (r'/OC:\path with spaces\test.exe', r'"/OC:\path with spaces\test.exe"'),
                ('/LIBPATH:C:\\path with spaces\\ends\\with\\backslashes\\', r'"/LIBPATH:C:\path with spaces\ends\with\backslashes\\"'),
                ('/LIBPATH:"C:\\path with spaces\\ends\\with\\backslashes\\\\"', r'"/LIBPATH:\"C:\path with spaces\ends\with\backslashes\\\\\""'),
                (r'/DMSG="Alice said: \"Let\'s go\""', r'"/DMSG=\"Alice said: \\\"Let\'s go\\\"\""'),
            ]
        else:
            test_data = [
                ('arg1', 'arg1'),
                ('--option1', '--option1'),
                ('-O=value', '-O=value'),
                ('-O=Bob&Alice', "'-O=Bob&Alice'"),
                ('-O=value with spaces', "'-O=value with spaces'"),
                ('-O="value with spaces"', '\'-O=\"value with spaces\"\''),
                ('-O=/path with spaces/test', '\'-O=/path with spaces/test\''),
                ('-DMSG="Alice said: \\"Let\'s go\\""', "'-DMSG=\"Alice said: \\\"Let'\"'\"'s go\\\"\"'"),
            ]

        for (arg, expected) in test_data:
            self.assertEqual(quote_arg(arg), expected)
            self.assertEqual(split_args(expected)[0], arg)

    def test_depfile(self):
        for (f, target, expdeps) in [
                # empty, unknown target
                ([''], 'unknown', set()),
                # simple target & deps
                (['meson/foo.o  : foo.c   foo.h'], 'meson/foo.o', set({'foo.c', 'foo.h'})),
                (['meson/foo.o: foo.c foo.h'], 'foo.c', set()),
                # get all deps
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'meson/foo.o', set({'foo.c', 'foo.h', 'gen.py'})),
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'foo.c', set({'gen.py'})),
                # linue continuation, multiple targets
                (['foo.o \\', 'foo.h: bar'], 'foo.h', set({'bar'})),
                (['foo.o \\', 'foo.h: bar'], 'foo.o', set({'bar'})),
                # \\ handling
                (['foo: Program\\ F\\iles\\\\X'], 'foo', set({'Program Files\\X'})),
                # $ handling
                (['f$o.o: c/b'], 'f$o.o', set({'c/b'})),
                (['f$$o.o: c/b'], 'f$o.o', set({'c/b'})),
                # cycles
                (['a: b', 'b: a'], 'a', set({'a', 'b'})),
                (['a: b', 'b: a'], 'b', set({'a', 'b'})),
        ]:
            d = mesonbuild.depfile.DepFile(f)
            deps = d.get_all_dependencies(target)
            self.assertEqual(sorted(deps), sorted(expdeps))

    def test_log_once(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog._logger.log_file', f), \
                mock.patch('mesonbuild.mlog._logger.logged_once', set()):
            mesonbuild.mlog.log('foo', once=True)
            mesonbuild.mlog.log('foo', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual, 'foo', actual)

    def test_log_once_ansi(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog._logger.log_file', f), \
                mock.patch('mesonbuild.mlog._logger.logged_once', set()):
            mesonbuild.mlog.log(mesonbuild.mlog.bold('foo'), once=True)
            mesonbuild.mlog.log(mesonbuild.mlog.bold('foo'), once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            mesonbuild.mlog.log('foo', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            f.truncate()

            mesonbuild.mlog.warning('bar', once=True)
            mesonbuild.mlog.warning('bar', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('bar'), 1, actual)

    def test_sort_libpaths(self):
        sort_libpaths = mesonbuild.dependencies.base.sort_libpaths
        self.assertEqual(sort_libpaths(
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/local/lib', '/home/mesonuser/.local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/libdata/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])

    def test_dependency_factory_order(self):
        b = mesonbuild.dependencies.base
        F = mesonbuild.dependencies.factory
        with tempfile.TemporaryDirectory() as tmpdir:
            with chdir(tmpdir):
                env = get_fake_env()
                env.scratch_dir = tmpdir

                f = F.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.PKGCONFIG, b.DependencyMethods.CMAKE]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['pkgconfig', 'cmake'])

                f = F.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.CMAKE, b.DependencyMethods.PKGCONFIG]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['cmake', 'pkgconfig'])

    def test_validate_json(self) -> None:
        """Validate the json schema for the test cases."""
        try:
            from fastjsonschema import compile, JsonSchemaValueException as JsonSchemaFailure
            fast = True
        except ImportError:
            try:
                from jsonschema import validate, ValidationError as JsonSchemaFailure
                fast = False
            except:
                if is_ci():
                    raise
                raise unittest.SkipTest('neither Python fastjsonschema nor jsonschema module not found.')

        with open('data/test.schema.json', 'r', encoding='utf-8') as f:
            data = json.loads(f.read())

        if fast:
            schema_validator = compile(data)
        else:
            schema_validator = lambda x: validate(x, schema=data)

        errors: T.List[T.Tuple[Path, Exception]] = []
        for p in Path('test cases').glob('**/test.json'):
            try:
                schema_validator(json.loads(p.read_text(encoding='utf-8')))
            except JsonSchemaFailure as e:
                errors.append((p.resolve(), e))

        for f, e in errors:
            print(f'Failed to validate: "{f}"')
            print(str(e))

        self.assertFalse(errors)

    def test_typed_pos_args_types(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], str)
            self.assertIsInstance(args[1], int)
            self.assertIsInstance(args[2], bool)

        _(None, mock.Mock(), ['string', 1, False], None)

    def test_typed_pos_args_types_invalid(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 1.0, False], None)
        self.assertEqual(str(cm.exception), 'foo argument 2 was of type "float" but should have been "int"')

    def test_typed_pos_args_types_wrong_number(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 1], None)
        self.assertEqual(str(cm.exception), 'foo takes exactly 3 arguments, but got 2.')

        with self
### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
k_args)

    def test_version_compare(self):
        comparefunc = mesonbuild.mesonlib.version_compare_many
        for (a, b, result) in [
                ('0.99.beta19', '>= 0.99.beta14', True),
        ]:
            self.assertEqual(comparefunc(a, b)[0], result)

        for (a, b, op) in [
                # examples from https://fedoraproject.org/wiki/Archive:Tools/RPM/VersionComparison
                ("1.0010", "1.9", operator.gt),
                ("1.05", "1.5", operator.eq),
                ("1.0", "1", operator.gt),
                ("2.50", "2.5", operator.gt),
                ("fc4", "fc.4", operator.eq),
                ("FC5", "fc4", operator.lt),
                ("2a", "2.0", operator.lt),
                ("1.0", "1.fc4", operator.gt),
                ("3.0.0_fc", "3.0.0.fc", operator.eq),
                # from RPM tests
                ("1.0", "1.0", operator.eq),
                ("1.0", "2.0", operator.lt),
                ("2.0", "1.0", operator.gt),
                ("2.0.1", "2.0.1", operator.eq),
                ("2.0", "2.0.1", operator.lt),
                ("2.0.1", "2.0", operator.gt),
                ("2.0.1a", "2.0.1a", operator.eq),
                ("2.0.1a", "2.0.1", operator.gt),
                ("2.0.1", "2.0.1a", operator.lt),
                ("5.5p1", "5.5p1", operator.eq),
                ("5.5p1", "5.5p2", operator.lt),
                ("5.5p2", "5.5p1", operator.gt),
                ("5.5p10", "5.5p10", operator.eq),
                ("5.5p1", "5.5p10", operator.lt),
                ("5.5p10", "5.5p1", operator.gt),
                ("10xyz", "10.1xyz", operator.lt),
                ("10.1xyz", "10xyz", operator.gt),
                ("xyz10", "xyz10", operator.eq),
                ("xyz10", "xyz10.1", operator.lt),
                ("xyz10.1", "xyz10", operator.gt),
                ("xyz.4", "xyz.4", operator.eq),
                ("xyz.4", "8", operator.lt),
                ("8", "xyz.4", operator.gt),
                ("xyz.4", "2", operator.lt),
                ("2", "xyz.4", operator.gt),
                ("5.5p2", "5.6p1", operator.lt),
                ("5.6p1", "5.5p2", operator.gt),
                ("5.6p1", "6.5p1", operator.lt),
                ("6.5p1", "5.6p1", operator.gt),
                ("6.0.rc1", "6.0", operator.gt),
                ("6.0", "6.0.rc1", operator.lt),
                ("10b2", "10a1", operator.gt),
                ("10a2", "10b2", operator.lt),
                ("1.0aa", "1.0aa", operator.eq),
                ("1.0a", "1.0aa", operator.lt),
                ("1.0aa", "1.0a", operator.gt),
                ("10.0001", "10.0001", operator.eq),
                ("10.0001", "10.1", operator.eq),
                ("10.1", "10.0001", operator.eq),
                ("10.0001", "10.0039", operator.lt),
                ("10.0039", "10.0001", operator.gt),
                ("4.999.9", "5.0", operator.lt),
                ("5.0", "4.999.9", operator.gt),
                ("20101121", "20101121", operator.eq),
                ("20101121", "20101122", operator.lt),
                ("20101122", "20101121", operator.gt),
                ("2_0", "2_0", operator.eq),
                ("2.0", "2_0", operator.eq),
                ("2_0", "2.0", operator.eq),
                ("a", "a", operator.eq),
                ("a+", "a+", operator.eq),
                ("a+", "a_", operator.eq),
                ("a_", "a+", operator.eq),
                ("+a", "+a", operator.eq),
                ("+a", "_a", operator.eq),
                ("_a", "+a", operator.eq),
                ("+_", "+_", operator.eq),
                ("_+", "+_", operator.eq),
                ("_+", "_+", operator.eq),
                ("+", "_", operator.eq),
                ("_", "+", operator.eq),
                # other tests
                ('0.99.beta19', '0.99.beta14', operator.gt),
                ("1.0.0", "2.0.0", operator.lt),
                (".0.0", "2.0.0", operator.lt),
                ("alpha", "beta", operator.lt),
                ("1.0", "1.0.0", operator.lt),
                ("2.456", "2.1000", operator.lt),
                ("2.1000", "3.111", operator.lt),
                ("2.001", "2.1", operator.eq),
                ("2.34", "2.34", operator.eq),
                ("6.1.2", "6.3.8", operator.lt),
                ("1.7.3.0", "2.0.0", operator.lt),
                ("2.24.51", "2.25", operator.lt),
                ("2.1.5+20120813+gitdcbe778", "2.1.5", operator.gt),
                ("3.4.1", "3.4b1", operator.gt),
                ("041206", "200090325", operator.lt),
                ("0.6.2+git20130413", "0.6.2", operator.gt),
                ("2.6.0+bzr6602", "2.6.0", operator.gt),
                ("2.6.0", "2.6b2", operator.gt),
                ("2.6.0+bzr6602", "2.6b2x", operator.gt),
                ("0.6.7+20150214+git3a710f9", "0.6.7", operator.gt),
                ("15.8b", "15.8.0.1", operator.lt),
                ("1.2rc1", "1.2.0", operator.lt),
        ]:
            ver_a = Version(a)
            ver_b = Version(b)
            if op is operator.eq:
                for o, name in [(op, 'eq'), (operator.ge, 'ge'), (operator.le, 'le')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
            if op is operator.lt:
                for o, name in [(op, 'lt'), (operator.le, 'le'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
                for o, name in [(operator.gt, 'gt'), (operator.ge, 'ge'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
            if op is operator.gt:
                for o, name in [(op, 'gt'), (operator.ge, 'ge'), (operator.ne, 'ne')]:
                    self.assertTrue(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')
                for o, name in [(operator.lt, 'lt'), (operator.le, 'le'), (operator.eq, 'eq')]:
                    self.assertFalse(o(ver_a, ver_b), f'{ver_a} {name} {ver_b}')

    def test_msvc_toolset_version(self):
        '''
        Ensure that the toolset version returns the correct value for this MSVC
        '''
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_argument_syntax() != 'msvc':
            raise unittest.SkipTest('Test only applies to MSVC-like compilers')
        toolset_ver = cc.get_toolset_version()
        self.assertIsNotNone(toolset_ver)
        # Visual Studio 2015 and older versions do not define VCToolsVersion
        # TODO: ICL doesn't set this in the VSC2015 profile either
        if cc.id == 'msvc' and int(''.join(cc.version.split('.')[0:2])) < 1910:
            return
        if 'VCToolsVersion' in os.environ:
            vctools_ver = os.environ['VCToolsVersion']
        else:
            self.assertIn('VCINSTALLDIR', os.environ)
            # See https://devblogs.microsoft.com/cppblog/finding-the-visual-c-compiler-tools-in-visual-studio-2017/
            vctools_ver = (Path(os.environ['VCINSTALLDIR']) / 'Auxiliary' / 'Build' / 'Microsoft.VCToolsVersion.default.txt').read_text(encoding='utf-8')
        self.assertTrue(vctools_ver.startswith(toolset_ver),
                        msg=f'{vctools_ver!r} does not start with {toolset_ver!r}')

    def test_split_args(self):
        split_args = mesonbuild.mesonlib.split_args
        join_args = mesonbuild.mesonlib.join_args
        if is_windows():
            test_data = [
                # examples from https://docs.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
                (r'"a b c" d e', ['a b c', 'd', 'e'], True),
                (r'"ab\"c" "\\" d', ['ab"c', '\\', 'd'], False),
                (r'a\\\b d"e f"g h', [r'a\\\b', 'de fg', 'h'], False),
                (r'a\\\"b c d', [r'a\"b', 'c', 'd'], False),
                (r'a\\\\"b c" d e', [r'a\\b c', 'd', 'e'], False),
                # other basics
                (r'""', [''], True),
                (r'a b c d "" e', ['a', 'b', 'c', 'd', '', 'e'], True),
                (r"'a b c' d e", ["'a", 'b', "c'", 'd', 'e'], True),
                (r"'a&b&c' d e", ["'a&b&c'", 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], True),
                (r"'a & b & c d e'", ["'a", '&', 'b', '&', 'c', 'd', "e'"], True),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),
                # more illustrative tests
                (r'cl test.cpp /O1 /Fe:test.exe', ['cl', 'test.cpp', '/O1', '/Fe:test.exe'], True),
                (r'cl "test.cpp /O1 /Fe:test.exe"', ['cl', 'test.cpp /O1 /Fe:test.exe'], True),
                (r'cl /DNAME=\"Bob\" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob\"" test.cpp', ['cl', '/DNAME="Bob"', 'test.cpp'], True),
                (r'cl /DNAME=\"Bob, Alice\" test.cpp', ['cl', '/DNAME="Bob,', 'Alice"', 'test.cpp'], False),
                (r'cl "/DNAME=\"Bob, Alice\"" test.cpp', ['cl', '/DNAME="Bob, Alice"', 'test.cpp'], True),
                (r'cl C:\path\with\backslashes.cpp', ['cl', r'C:\path\with\backslashes.cpp'], True),
                (r'cl C:\\path\\with\\double\\backslashes.cpp', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], True),
                (r'cl "C:\\path\\with\\double\\backslashes.cpp"', ['cl', r'C:\\path\\with\\double\\backslashes.cpp'], False),
                (r'cl C:\path with spaces\test.cpp', ['cl', r'C:\path', 'with', r'spaces\test.cpp'], False),
                (r'cl "C:\path with spaces\test.cpp"', ['cl', r'C:\path with spaces\test.cpp'], True),
                (r'cl /DPATH="C:\path\with\backslashes test.cpp', ['cl', r'/DPATH=C:\path\with\backslashes test.cpp'], False),
                (r'cl /DPATH=\"C:\\ends\\with\\backslashes\\\" test.cpp', ['cl', r'/DPATH="C:\\ends\\with\\backslashes\"', 'test.cpp'], False),
                (r'cl /DPATH="C:\\ends\\with\\backslashes\\" test.cpp', ['cl', '/DPATH=C:\\\\ends\\\\with\\\\backslashes\\', 'test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\"', 'test.cpp'], True),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\ test.cpp'], False),
                (r'cl "/DNAME=\"C:\\ends\\with\\backslashes\\\\\"" test.cpp', ['cl', r'/DNAME="C:\\ends\\with\\backslashes\\"', 'test.cpp'], True),
            ]
        else:
            test_data = [
                (r"'a b c' d e", ['a b c', 'd', 'e'], True),
                (r"a/b/c d e", ['a/b/c', 'd', 'e'], True),
                (r"a\b\c d e", [r'abc', 'd', 'e'], False),
                (r"a\\b\\c d e", [r'a\b\c', 'd', 'e'], False),
                (r'"a b c" d e', ['a b c', 'd', 'e'], False),
                (r'"a\\b\\c\\" d e', ['a\\b\\c\\', 'd', 'e'], False),
                (r"'a\b\c\' d e", ['a\\b\\c\\', 'd', 'e'], True),
                (r"'a&b&c' d e", ['a&b&c', 'd', 'e'], True),
                (r"a & b & c d e", ['a', '&', 'b', '&', 'c', 'd', 'e'], False),
                (r"'a & b & c d e'", ['a & b & c d e'], True),
                (r"abd'e f'g h", [r'abde fg', 'h'], False),
                ('a  b\nc\rd \n\re', ['a', 'b', 'c', 'd', 'e'], False),

                ('g++ -DNAME="Bob" test.cpp', ['g++', '-DNAME=Bob', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob\"' test.cpp", ['g++', '-DNAME="Bob"', 'test.cpp'], True),
                ('g++ -DNAME="Bob, Alice" test.cpp', ['g++', '-DNAME=Bob, Alice', 'test.cpp'], False),
                ("g++ '-DNAME=\"Bob, Alice\"' test.cpp", ['g++', '-DNAME="Bob, Alice"', 'test.cpp'], True),
            ]

        for (cmd, expected, roundtrip) in test_data:
            self.assertEqual(split_args(cmd), expected)
            if roundtrip:
                self.assertEqual(join_args(expected), cmd)

    def test_quote_arg(self):
        split_args = mesonbuild.mesonlib.split_args
        quote_arg = mesonbuild.mesonlib.quote_arg
        if is_windows():
            test_data = [
                ('', '""'),
                ('arg1', 'arg1'),
                ('/option1', '/option1'),
                ('/Ovalue', '/Ovalue'),
                ('/OBob&Alice', '/OBob&Alice'),
                ('/Ovalue with spaces', r'"/Ovalue with spaces"'),
                (r'/O"value with spaces"', r'"/O\"value with spaces\""'),
                (r'/OC:\path with spaces\test.exe', r'"/OC:\path with spaces\test.exe"'),
                ('/LIBPATH:C:\\path with spaces\\ends\\with\\backslashes\\', r'"/LIBPATH:C:\path with spaces\ends\with\backslashes\\"'),
                ('/LIBPATH:"C:\\path with spaces\\ends\\with\\backslashes\\\\"', r'"/LIBPATH:\"C:\path with spaces\ends\with\backslashes\\\\\""'),
                (r'/DMSG="Alice said: \"Let\'s go\""', r'"/DMSG=\"Alice said: \\\"Let\'s go\\\"\""'),
            ]
        else:
            test_data = [
                ('arg1', 'arg1'),
                ('--option1', '--option1'),
                ('-O=value', '-O=value'),
                ('-O=Bob&Alice', "'-O=Bob&Alice'"),
                ('-O=value with spaces', "'-O=value with spaces'"),
                ('-O="value with spaces"', '\'-O=\"value with spaces\"\''),
                ('-O=/path with spaces/test', '\'-O=/path with spaces/test\''),
                ('-DMSG="Alice said: \\"Let\'s go\\""', "'-DMSG=\"Alice said: \\\"Let'\"'\"'s go\\\"\"'"),
            ]

        for (arg, expected) in test_data:
            self.assertEqual(quote_arg(arg), expected)
            self.assertEqual(split_args(expected)[0], arg)

    def test_depfile(self):
        for (f, target, expdeps) in [
                # empty, unknown target
                ([''], 'unknown', set()),
                # simple target & deps
                (['meson/foo.o  : foo.c   foo.h'], 'meson/foo.o', set({'foo.c', 'foo.h'})),
                (['meson/foo.o: foo.c foo.h'], 'foo.c', set()),
                # get all deps
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'meson/foo.o', set({'foo.c', 'foo.h', 'gen.py'})),
                (['meson/foo.o: foo.c foo.h',
                  'foo.c: gen.py'], 'foo.c', set({'gen.py'})),
                # linue continuation, multiple targets
                (['foo.o \\', 'foo.h: bar'], 'foo.h', set({'bar'})),
                (['foo.o \\', 'foo.h: bar'], 'foo.o', set({'bar'})),
                # \\ handling
                (['foo: Program\\ F\\iles\\\\X'], 'foo', set({'Program Files\\X'})),
                # $ handling
                (['f$o.o: c/b'], 'f$o.o', set({'c/b'})),
                (['f$$o.o: c/b'], 'f$o.o', set({'c/b'})),
                # cycles
                (['a: b', 'b: a'], 'a', set({'a', 'b'})),
                (['a: b', 'b: a'], 'b', set({'a', 'b'})),
        ]:
            d = mesonbuild.depfile.DepFile(f)
            deps = d.get_all_dependencies(target)
            self.assertEqual(sorted(deps), sorted(expdeps))

    def test_log_once(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog._logger.log_file', f), \
                mock.patch('mesonbuild.mlog._logger.logged_once', set()):
            mesonbuild.mlog.log('foo', once=True)
            mesonbuild.mlog.log('foo', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual, 'foo', actual)

    def test_log_once_ansi(self):
        f = io.StringIO()
        with mock.patch('mesonbuild.mlog._logger.log_file', f), \
                mock.patch('mesonbuild.mlog._logger.logged_once', set()):
            mesonbuild.mlog.log(mesonbuild.mlog.bold('foo'), once=True)
            mesonbuild.mlog.log(mesonbuild.mlog.bold('foo'), once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            mesonbuild.mlog.log('foo', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('foo'), 1, actual)

            f.truncate()

            mesonbuild.mlog.warning('bar', once=True)
            mesonbuild.mlog.warning('bar', once=True)
            actual = f.getvalue().strip()
            self.assertEqual(actual.count('bar'), 1, actual)

    def test_sort_libpaths(self):
        sort_libpaths = mesonbuild.dependencies.base.sort_libpaths
        self.assertEqual(sort_libpaths(
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/local/lib', '/home/mesonuser/.local/lib', '/usr/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/lib/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])
        self.assertEqual(sort_libpaths(
            ['/usr/lib', '/usr/local/lib', '/home/mesonuser/.local/lib'],
            ['/home/mesonuser/.local/lib/pkgconfig', '/usr/local/libdata/pkgconfig']),
            ['/home/mesonuser/.local/lib', '/usr/local/lib', '/usr/lib'])

    def test_dependency_factory_order(self):
        b = mesonbuild.dependencies.base
        F = mesonbuild.dependencies.factory
        with tempfile.TemporaryDirectory() as tmpdir:
            with chdir(tmpdir):
                env = get_fake_env()
                env.scratch_dir = tmpdir

                f = F.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.PKGCONFIG, b.DependencyMethods.CMAKE]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['pkgconfig', 'cmake'])

                f = F.DependencyFactory(
                    'test_dep',
                    methods=[b.DependencyMethods.CMAKE, b.DependencyMethods.PKGCONFIG]
                )
                actual = [m() for m in f(env, MachineChoice.HOST, {'required': False})]
                self.assertListEqual([m.type_name for m in actual], ['cmake', 'pkgconfig'])

    def test_validate_json(self) -> None:
        """Validate the json schema for the test cases."""
        try:
            from fastjsonschema import compile, JsonSchemaValueException as JsonSchemaFailure
            fast = True
        except ImportError:
            try:
                from jsonschema import validate, ValidationError as JsonSchemaFailure
                fast = False
            except:
                if is_ci():
                    raise
                raise unittest.SkipTest('neither Python fastjsonschema nor jsonschema module not found.')

        with open('data/test.schema.json', 'r', encoding='utf-8') as f:
            data = json.loads(f.read())

        if fast:
            schema_validator = compile(data)
        else:
            schema_validator = lambda x: validate(x, schema=data)

        errors: T.List[T.Tuple[Path, Exception]] = []
        for p in Path('test cases').glob('**/test.json'):
            try:
                schema_validator(json.loads(p.read_text(encoding='utf-8')))
            except JsonSchemaFailure as e:
                errors.append((p.resolve(), e))

        for f, e in errors:
            print(f'Failed to validate: "{f}"')
            print(str(e))

        self.assertFalse(errors)

    def test_typed_pos_args_types(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], str)
            self.assertIsInstance(args[1], int)
            self.assertIsInstance(args[2], bool)

        _(None, mock.Mock(), ['string', 1, False], None)

    def test_typed_pos_args_types_invalid(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 1.0, False], None)
        self.assertEqual(str(cm.exception), 'foo argument 2 was of type "float" but should have been "int"')

    def test_typed_pos_args_types_wrong_number(self) -> None:
        @typed_pos_args('foo', str, int, bool)
        def _(obj, node, args: T.Tuple[str, int, bool], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 1], None)
        self.assertEqual(str(cm.exception), 'foo takes exactly 3 arguments, but got 2.')

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 1, True, True], None)
        self.assertEqual(str(cm.exception), 'foo takes exactly 3 arguments, but got 4.')

    def test_typed_pos_args_varargs(self) -> None:
        @typed_pos_args('foo', str, varargs=str)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], str)
            self.assertIsInstance(args[1], list)
            self.assertIsInstance(args[1][0], str)
            self.assertIsInstance(args[1][1], str)

        _(None, mock.Mock(), ['string', 'var', 'args'], None)

    def test_typed_pos_args_varargs_not_given(self) -> None:
        @typed_pos_args('foo', str, varargs=str)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], str)
            self.assertIsInstance(args[1], list)
            self.assertEqual(args[1], [])

        _(None, mock.Mock(), ['string'], None)

    def test_typed_pos_args_varargs_invalid(self) -> None:
        @typed_pos_args('foo', str, varargs=str)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 'var', 'args', 0], None)
        self.assertEqual(str(cm.exception), 'foo argument 4 was of type "int" but should have been "str"')

    def test_typed_pos_args_varargs_invalid_multiple_types(self) -> None:
        @typed_pos_args('foo', str, varargs=(str, list))
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 'var', 'args', 0], None)
        self.assertEqual(str(cm.exception), 'foo argument 4 was of type "int" but should have been one of: "str", "list"')

    def test_typed_pos_args_max_varargs(self) -> None:
        @typed_pos_args('foo', str, varargs=str, max_varargs=5)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], str)
            self.assertIsInstance(args[1], list)
            self.assertIsInstance(args[1][0], str)
            self.assertIsInstance(args[1][1], str)

        _(None, mock.Mock(), ['string', 'var', 'args'], None)

    def test_typed_pos_args_max_varargs_exceeded(self) -> None:
        @typed_pos_args('foo', str, varargs=str, max_varargs=1)
        def _(obj, node, args: T.Tuple[str, T.Tuple[str, ...]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 'var', 'args'], None)
        self.assertEqual(str(cm.exception), 'foo takes between 1 and 2 arguments, but got 3.')

    def test_typed_pos_args_min_varargs(self) -> None:
        @typed_pos_args('foo', varargs=str, max_varargs=2, min_varargs=1)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertIsInstance(args, tuple)
            self.assertIsInstance(args[0], list)
            self.assertIsInstance(args[0][0], str)
            self.assertIsInstance(args[0][1], str)

        _(None, mock.Mock(), ['string', 'var'], None)

    def test_typed_pos_args_min_varargs_not_met(self) -> None:
        @typed_pos_args('foo', str, varargs=str, min_varargs=1)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string'], None)
        self.assertEqual(str(cm.exception), 'foo takes at least 2 arguments, but got 1.')

    def test_typed_pos_args_min_and_max_varargs_exceeded(self) -> None:
        @typed_pos_args('foo', str, varargs=str, min_varargs=1, max_varargs=2)
        def _(obj, node, args: T.Tuple[str, T.Tuple[str, ...]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', 'var', 'args', 'bar'], None)
        self.assertEqual(str(cm.exception), 'foo takes between 2 and 3 arguments, but got 4.')

    def test_typed_pos_args_min_and_max_varargs_not_met(self) -> None:
        @typed_pos_args('foo', str, varargs=str, min_varargs=1, max_varargs=2)
        def _(obj, node, args: T.Tuple[str, T.Tuple[str, ...]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string'], None)
        self.assertEqual(str(cm.exception), 'foo takes between 2 and 3 arguments, but got 1.')

    def test_typed_pos_args_variadic_and_optional(self) -> None:
        @typed_pos_args('foo', str, optargs=[str], varargs=str, min_varargs=0)
        def _(obj, node, args: T.Tuple[str, T.List[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(AssertionError) as cm:
            _(None, mock.Mock(), ['string'], None)
        self.assertEqual(
            str(cm.exception),
            'varargs and optargs not supported together as this would be ambiguous')

    def test_typed_pos_args_min_optargs_not_met(self) -> None:
        @typed_pos_args('foo', str, str, optargs=[str])
        def _(obj, node, args: T.Tuple[str, T.Optional[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string'], None)
        self.assertEqual(str(cm.exception), 'foo takes at least 2 arguments, but got 1.')

    def test_typed_pos_args_min_optargs_max_exceeded(self) -> None:
        @typed_pos_args('foo', str, optargs=[str])
        def _(obj, node, args: T.Tuple[str, T.Optional[str]], kwargs) -> None:
            self.assertTrue(False)  # should not be reachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), ['string', '1', '2'], None)
        self.assertEqual(str(cm.exception), 'foo takes at most 2 arguments, but got 3.')

    def test_typed_pos_args_optargs_not_given(self) -> None:
        @typed_pos_args('foo', str, optargs=[str])
        def _(obj, node, args: T.Tuple[str, T.Optional[str]], kwargs) -> None:
            self.assertEqual(len(args), 2)
            self.assertIsInstance(args[0], str)
            self.assertEqual(args[0], 'string')
            self.assertIsNone(args[1])

        _(None, mock.Mock(), ['string'], None)

    def test_typed_pos_args_optargs_some_given(self) -> None:
        @typed_pos_args('foo', str, optargs=[str, int])
        def _(obj, node, args: T.Tuple[str, T.Optional[str], T.Optional[int]], kwargs) -> None:
            self.assertEqual(len(args), 3)
            self.assertIsInstance(args[0], str)
            self.assertEqual(args[0], 'string')
            self.assertIsInstance(args[1], str)
            self.assertEqual(args[1], '1')
            self.assertIsNone(args[2])

        _(None, mock.Mock(), ['string', '1'], None)

    def test_typed_pos_args_optargs_all_given(self) -> None:
        @typed_pos_args('foo', str, optargs=[str])
        def _(obj, node, args: T.Tuple[str, T.Optional[str]], kwargs) -> None:
            self.assertEqual(len(args), 2)
            self.assertIsInstance(args[0], str)
            self.assertEqual(args[0], 'string')
            self.assertIsInstance(args[1], str)

        _(None, mock.Mock(), ['string', '1'], None)

    def test_typed_kwarg_basic(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', str, default='')
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertIsInstance(kwargs['input'], str)
            self.assertEqual(kwargs['input'], 'foo')

        _(None, mock.Mock(), [], {'input': 'foo'})

    def test_typed_kwarg_missing_required(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', str, required=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertTrue(False)  # should be unreachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), [], {})
        self.assertEqual(str(cm.exception), 'testfunc is missing required keyword argument "input"')

    def test_typed_kwarg_missing_optional(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', (str, type(None))),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.Optional[str]]) -> None:
            self.assertIsNone(kwargs['input'])

        _(None, mock.Mock(), [], {})

    def test_typed_kwarg_default(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', str, default='default'),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, str]) -> None:
            self.assertEqual(kwargs['input'], 'default')

        _(None, mock.Mock(), [], {})

    def test_typed_kwarg_container_valid(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str), default=[], required=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.List[str]]) -> None:
            self.assertEqual(kwargs['input'], ['str'])

        _(None, mock.Mock(), [], {'input': ['str']})

    def test_typed_kwarg_container_invalid(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str), required=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.List[str]]) -> None:
            self.assertTrue(False)  # should be unreachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), [], {'input': {}})
        self.assertEqual(str(cm.exception), "testfunc keyword argument 'input' was of type dict[] but should have been array[str]")

    def test_typed_kwarg_contained_invalid(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(dict, str), required=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.Dict[str, str]]) -> None:
            self.assertTrue(False)  # should be unreachable

        with self.assertRaises(InvalidArguments) as cm:
            _(None, mock.Mock(), [], {'input': {'key': 1, 'bar': 2}})
        self.assertEqual(str(cm.exception), "testfunc keyword argument 'input' was of type dict[int] but should have been dict[str]")

    def test_typed_kwarg_container_listify(self) -> None:
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str), default=[], listify=True),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.List[str]]) -> None:
            self.assertEqual(kwargs['input'], ['str'])

        _(None, mock.Mock(), [], {'input': 'str'})

    def test_typed_kwarg_container_default_copy(self) -> None:
        default: T.List[str] = []
        @typed_kwargs(
            'testfunc',
            KwargInfo('input', ContainerTypeInfo(list, str), listify=True, default=default),
        )
        def _(obj, node, args: T.Tuple, kwargs: T.Dict[str, T.List[str]]) -> None:
            self.asse
```