Response:
The user wants a summary of the functionality of the Python code provided, which is part of the Meson build system's test suite. I need to analyze the code and list the testing scenarios it covers. The prompt also asks for specific connections to reverse engineering, low-level aspects (kernels, etc.), logical reasoning (with input/output examples), common user errors, and how a user might reach this code during debugging.

**Plan:**

1. **Overall Function:** Identify that this file contains unit tests for Meson, particularly focusing on system-level functionalities and integration with other build systems.
2. **Specific Test Cases:**  Go through each `test_` function and summarize what it's testing.
3. **Reverse Engineering Relevance:** Look for tests involving binary introspection, dependency analysis, or anything that might be used to understand a built system.
4. **Low-Level Relevance:**  Identify tests involving specific OS features (like `nostdlib` on Linux), or interaction with other build systems (CMake).
5. **Logical Reasoning:** For tests that process input and check output (like `test_introspect_ast_source`), describe the assumed input and expected output.
6. **User Errors:** Consider scenarios where users might misuse Meson features and how these tests might catch those errors.
7. **Debugging Path:** Think about how a developer working on Meson or a user facing build issues might end up examining these test files.
8. **Summarize:**  Provide a concise overview of the file's purpose.
这是frida动态 instrumentation工具的源代码文件的一部分，它是一个单元测试文件，用于测试Meson构建系统的各种功能。由于它位于 `frida/subprojects/frida-node/releng/meson/` 路径下，可以推断这些测试是针对frida-node项目使用Meson构建时的一些特定场景。

**功能归纳:**

这个文件 `allplatformstests.py` 的主要功能是包含了一系列集成测试，用于验证 Meson 构建系统在各种平台上的行为是否符合预期。 这些测试覆盖了 Meson 的核心功能，包括：

1. **构建流程的核心命令测试:** 测试 `meson`, `meson compile`, `meson configure` 等核心命令的功能和参数。
2. **构建目标测试:**  测试不同类型的构建目标（例如，可执行文件、共享库、静态库、别名目标、运行目标）的创建和执行。
3. **代码内省功能测试:**  测试 Meson 的代码内省能力，例如提取抽象语法树 (AST) 信息、扫描依赖关系等。
4. **依赖管理测试:**  测试 Meson 如何处理项目依赖，包括外部依赖和子项目依赖，以及 `wrap-git` 和 `wrap-redirect` 功能。
5. **与外部构建系统集成测试:** 测试 Meson 与 CMake 等其他构建系统的集成能力。
6. **配置选项和摘要信息测试:**  测试 Meson 如何处理用户定义的配置选项，以及生成构建摘要信息的功能。
7. **测试框架集成测试:**  测试 Meson 集成不同测试框架的能力，例如生成 JUnit 格式的测试报告。
8. **代码覆盖率测试:**  测试 Meson 的代码覆盖率生成功能。
9. **交叉编译相关测试:**  测试 Meson 如何处理交叉编译的配置文件。
10. **版本比较测试:**  测试 Meson 的版本比较功能。
11. **其他高级功能测试:**  例如，自定义目标、对象提取、无标准库构建 (`nostdlib`) 等。

**与逆向的方法的关系及举例说明:**

这个文件本身是测试代码，直接用于测试构建系统，与通常意义上的“逆向”方法关系不大。但是，其中一些测试覆盖了与逆向工程相关的概念：

* **二进制结构和依赖关系分析:**  `test_introspect_dependencies_from_source` 函数测试了 Meson 从源代码中提取依赖关系的功能。在逆向工程中，理解目标二进制文件的依赖关系是至关重要的，这可以帮助分析其功能和潜在的攻击面。Meson 提供的这种内省能力，可以帮助开发者在构建阶段就了解依赖情况。
    * **举例说明:**  假设 `meson.build` 文件中使用了 `dependency('zlib')`，`test_introspect_dependencies_from_source` 会验证能否正确识别出 `zlib` 这个依赖项。在逆向分析一个二进制文件时，如果发现它链接了 `zlib` 库，逆向工程师可能会关注该库是否存在已知的漏洞。
* **抽象语法树 (AST) 分析:** `test_introspect_ast_source` 函数测试了 Meson 分析构建文件并生成 AST 的能力。虽然这直接作用于构建脚本而非目标二进制，但 AST 分析是静态代码分析的基础，在逆向工程中也常用于理解代码结构和逻辑。
    * **举例说明:** 该测试会解析 `meson.build` 文件，并验证解析出的节点类型和属性是否正确。例如，如果 `meson.build` 中有 `if true:` 语句，AST 中应该包含一个 `IfNode`，其 `condition` 属性对应一个 `BooleanNode` 且值为 `True`。这类似于逆向工程师使用反编译器生成代码的抽象表示，以便更好地理解程序流程。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明:**

虽然这个测试文件主要关注构建系统本身，但其中一些测试涉及到了操作系统层面的概念：

* **可执行文件后缀:**  `test_alias_target` 和 `test_meson_compile` 函数中使用了 `exe_suffix` 变量，这与不同操作系统上可执行文件的后缀名有关（例如，Windows 是 `.exe`，Linux 通常没有后缀）。这体现了构建系统需要处理平台差异性。
* **共享库和静态库命名:** `test_meson_compile` 函数中根据不同的操作系统 (Windows, Linux, macOS) 和环境 (MSYS2, Cygwin) 检查共享库和静态库的命名规则。这反映了构建系统需要了解底层的链接器和库加载机制。
    * **举例说明:** 在 Linux 上，共享库通常以 `lib` 开头，以 `.so` 结尾，而在 Windows 上是 `.dll`。这个测试会验证 Meson 在构建时是否正确生成了符合平台规范的库文件。
* **`nostdlib` 测试:** `test_nostdlib` 函数涉及到在没有标准 C 库的情况下构建程序。这通常用于嵌入式系统或内核开发，属于非常底层的编程。虽然这个测试是在用户态进行的，但它模拟了构建此类低级代码的场景。
    * **举例说明:**  这个测试会创建一个模拟的 C 标准库 `mylibc`，然后配置 Meson 使用这个“标准库”进行构建。这在逆向分析不依赖标准库的固件或操作系统组件时，可以提供一些构建上的参考。
* **代码覆盖率工具:**  `test_coverage*` 系列的测试使用了 `gcovr` 和 `llvm-cov` 等代码覆盖率工具。这些工具通常与编译器配合使用，用于分析程序执行过程中哪些代码被执行了，哪些没有。这在逆向工程中，特别是进行动态分析时，可以帮助理解代码的执行路径和覆盖率。

**逻辑推理的假设输入与输出:**

* **`test_introspect_ast_source`:**
    * **假设输入:** 一个包含 `if a > b:` 语句的 `meson.build` 文件。
    * **预期输出:**  `res_nb` 包含一个表示该语句的 JSON 结构，其中包含一个 `IfNode`，其 `condition` 属性是一个 `ComparisonNode`， `ctype` 为 `>`，`left` 和 `right` 属性分别是表示变量 `a` 和 `b` 的 `IdNode`。
* **`test_introspect_dependencies_from_source`:**
    * **假设输入:** 一个包含 `dependency('threads')` 和 `dependency('zlib', required: false)` 的 `meson.build` 文件。
    * **预期输出:** `res_nb` 包含一个列表，其中包含两个字典，分别表示 `threads` 和 `zlib` 依赖。`threads` 的 `required` 字段为 `True`，`zlib` 的 `required` 字段为 `False`。

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误的构建目标名称:** 在 `test_meson_compile` 中，测试了使用 `meson compile <target>` 命令时，如果指定了不存在的目标或者名称不唯一的目标，Meson 的处理方式。用户可能会拼写错误目标名称，或者在子项目中使用了与父项目相同的目标名称，导致构建失败或构建了错误的目标。
    * **举例说明:** 用户可能想构建名为 `my_program` 的可执行文件，但错误地输入了 `meson compile myprogram`，Meson 应该能够给出提示或错误信息。
* **错误的配置选项:** 在 `test_summary` 中，测试了配置选项的设置和显示。用户可能错误地设置了某个配置选项的值，例如将布尔值设置为字符串，或者提供了无效的路径。Meson 在初始化阶段会进行检查，并在摘要信息中显示配置结果，帮助用户发现错误。
    * **举例说明:** 用户可能希望禁用某个功能，错误地输入了 `-Dfeature=off`（字符串），而不是 `-Dfeature=false`（布尔值）。Meson 应该能够正确解析，并在摘要中显示 `feature` 的状态。
* **`wrap-git` 配置错误:** `test_wrap_git` 测试了 `wrap-git` 功能，用户可能在 `.wrap` 文件中配置了错误的 Git 仓库 URL 或修订版本，导致子项目拉取失败或版本不一致。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

开发者在开发或维护 frida-node 项目时，如果修改了与构建流程相关的代码，或者想要验证 Meson 构建配置的正确性，可能会运行这些单元测试。

1. **修改了 Meson 构建脚本或相关代码:**  开发者可能修改了 `meson.build` 文件、自定义模块、或者与 Meson 集成相关的 Python 代码。
2. **运行单元测试:** 为了确保修改没有引入错误，开发者会运行 frida-node 项目的单元测试。这通常涉及到执行一个测试命令，该命令会发现并运行 `allplatformstests.py` 中的测试用例。
3. **测试失败:** 如果某个测试用例失败，例如 `test_introspect_ast_source` 失败，开发者会查看测试代码和相关的 Meson 代码，以找出问题所在。
4. **调试 `allplatformstests.py`:**  开发者可能会在 `allplatformstests.py` 中设置断点，或者添加日志输出，来检查测试的执行过程，例如 `res_nb` 的内容，以及 `accept_node` 函数的调用情况，从而理解为什么 AST 的结构不符合预期。
5. **追踪到 Meson 源代码:**  通过调试测试代码，开发者可能会定位到 Meson 源代码中负责解析构建脚本或生成 AST 的部分，进一步分析问题根源。

总而言之， `allplatformstests.py` 是 frida-node 项目中 Meson 构建系统功能和稳定性的一个重要保障。开发者通过编写和运行这些测试，可以尽早发现和修复构建流程中的问题。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
i[k]

            sources = []
            for j in i['target_sources']:
                sources += j.get('sources', [])
            i['target_sources'] = [{
                'language': 'unknown',
                'compiler': [],
                'parameters': [],
                'sources': sources,
                'generated_sources': []
            }]

        self.maxDiff = None
        self.assertListEqual(res_nb, res_wb)

    def test_introspect_ast_source(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--ast'] + self.meson_args)

        node_counter = {}

        def accept_node(json_node):
            self.assertIsInstance(json_node, dict)
            for i in ['lineno', 'colno', 'end_lineno', 'end_colno']:
                self.assertIn(i, json_node)
                self.assertIsInstance(json_node[i], int)
            self.assertIn('node', json_node)
            n = json_node['node']
            self.assertIsInstance(n, str)
            self.assertIn(n, nodes)
            if n not in node_counter:
                node_counter[n] = 0
            node_counter[n] = node_counter[n] + 1
            for nodeDesc in nodes[n]:
                key = nodeDesc[0]
                func = nodeDesc[1]
                self.assertIn(key, json_node)
                if func is None:
                    tp = nodeDesc[2]
                    self.assertIsInstance(json_node[key], tp)
                    continue
                func(json_node[key])

        def accept_node_list(node_list):
            self.assertIsInstance(node_list, list)
            for i in node_list:
                accept_node(i)

        def accept_kwargs(kwargs):
            self.assertIsInstance(kwargs, list)
            for i in kwargs:
                self.assertIn('key', i)
                self.assertIn('val', i)
                accept_node(i['key'])
                accept_node(i['val'])

        nodes = {
            'BooleanNode': [('value', None, bool)],
            'IdNode': [('value', None, str)],
            'NumberNode': [('value', None, int)],
            'StringNode': [('value', None, str)],
            'FormatStringNode': [('value', None, str)],
            'ContinueNode': [],
            'BreakNode': [],
            'ArgumentNode': [('positional', accept_node_list), ('kwargs', accept_kwargs)],
            'ArrayNode': [('args', accept_node)],
            'DictNode': [('args', accept_node)],
            'EmptyNode': [],
            'OrNode': [('left', accept_node), ('right', accept_node)],
            'AndNode': [('left', accept_node), ('right', accept_node)],
            'ComparisonNode': [('left', accept_node), ('right', accept_node), ('ctype', None, str)],
            'ArithmeticNode': [('left', accept_node), ('right', accept_node), ('op', None, str)],
            'NotNode': [('right', accept_node)],
            'CodeBlockNode': [('lines', accept_node_list)],
            'IndexNode': [('object', accept_node), ('index', accept_node)],
            'MethodNode': [('object', accept_node), ('args', accept_node), ('name', None, str)],
            'FunctionNode': [('args', accept_node), ('name', None, str)],
            'AssignmentNode': [('value', accept_node), ('var_name', None, str)],
            'PlusAssignmentNode': [('value', accept_node), ('var_name', None, str)],
            'ForeachClauseNode': [('items', accept_node), ('block', accept_node), ('varnames', None, list)],
            'IfClauseNode': [('ifs', accept_node_list), ('else', accept_node)],
            'IfNode': [('condition', accept_node), ('block', accept_node)],
            'UMinusNode': [('right', accept_node)],
            'TernaryNode': [('condition', accept_node), ('true', accept_node), ('false', accept_node)],
        }

        accept_node(res_nb)

        for n, c in [('ContinueNode', 2), ('BreakNode', 1), ('NotNode', 3)]:
            self.assertIn(n, node_counter)
            self.assertEqual(node_counter[n], c)

    def test_introspect_dependencies_from_source(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--scan-dependencies'] + self.meson_args)
        expected = [
            {
                'name': 'threads',
                'required': True,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'zlib',
                'required': False,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'bugDep1',
                'required': True,
                'version': [],
                'has_fallback': False,
                'conditional': False
            },
            {
                'name': 'somethingthatdoesnotexist',
                'required': True,
                'version': ['>=1.2.3'],
                'has_fallback': False,
                'conditional': True
            },
            {
                'name': 'look_i_have_a_fallback',
                'required': True,
                'version': ['>=1.0.0', '<=99.9.9'],
                'has_fallback': True,
                'conditional': True
            }
        ]
        self.maxDiff = None
        self.assertListEqual(res_nb, expected)

    def test_unstable_coredata(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        # just test that the command does not fail (e.g. because it throws an exception)
        self._run([*self.meson_command, 'unstable-coredata', self.builddir])

    @skip_if_no_cmake
    def test_cmake_prefix_path(self):
        testdir = os.path.join(self.unit_test_dir, '62 cmake_prefix_path')
        self.init(testdir, extra_args=['-Dcmake_prefix_path=' + os.path.join(testdir, 'prefix')])

    @skip_if_no_cmake
    def test_cmake_parser(self):
        testdir = os.path.join(self.unit_test_dir, '63 cmake parser')
        self.init(testdir, extra_args=['-Dcmake_prefix_path=' + os.path.join(testdir, 'prefix')])

    def test_alias_target(self):
        testdir = os.path.join(self.unit_test_dir, '64 alias target')
        self.init(testdir)
        self.build()
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'prog' + exe_suffix))
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'hello.txt'))
        self.run_target('build-all')
        self.assertPathExists(os.path.join(self.builddir, 'prog' + exe_suffix))
        self.assertPathExists(os.path.join(self.builddir, 'hello.txt'))
        out = self.run_target('aliased-run')
        self.assertIn('a run target was here', out)

    def test_configure(self):
        testdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(testdir)
        self._run(self.mconf_command + [self.builddir])

    def test_summary(self):
        testdir = os.path.join(self.unit_test_dir, '71 summary')
        out = self.init(testdir, extra_args=['-Denabled_opt=enabled', f'-Dpython={sys.executable}'])
        expected = textwrap.dedent(r'''
            Some Subproject 2.0

                string : bar
                integer: 1
                boolean: true

            subsub undefined

                Something: Some value

            My Project 1.0

              Configuration
                Some boolean   : false
                Another boolean: true
                Some string    : Hello World
                A list         : string
                                 1
                                 true
                empty list     :
                enabled_opt    : enabled
                A number       : 1
                yes            : YES
                no             : NO
                comma list     : a, b, c

              Stuff
                missing prog   : NO
                existing prog  : ''' + ExternalProgram('python3', [sys.executable], silent=True).path + '''
                missing dep    : NO
                external dep   : YES 1.2.3
                internal dep   : YES
                disabler       : NO

              Plugins
                long comma list: alpha, alphacolor, apetag, audiofx, audioparsers, auparse,
                                 autodetect, avi

              Subprojects (for host machine)
                sub            : YES
                sub2           : NO Problem encountered: This subproject failed
                subsub         : YES (from sub2)

              User defined options
                backend        : ''' + self.backend_name + '''
                libdir         : lib
                prefix         : /usr
                enabled_opt    : enabled
                python         : ''' + sys.executable + '''
            ''')
        expected_lines = expected.split('\n')[1:]
        out_start = out.find(expected_lines[0])
        out_lines = out[out_start:].split('\n')[:len(expected_lines)]
        for e, o in zip(expected_lines, out_lines):
            if e.startswith('    external dep'):
                self.assertRegex(o, r'^    external dep   : (YES [0-9.]*|NO)$')
            else:
                self.assertEqual(o, e)

    def test_meson_compile(self):
        """Test the meson compile command."""

        def get_exe_name(basename: str) -> str:
            if is_windows():
                return f'{basename}.exe'
            else:
                return basename

        def get_shared_lib_name(basename: str) -> str:
            if mesonbuild.environment.detect_msys2_arch():
                return f'lib{basename}.dll'
            elif is_windows():
                return f'{basename}.dll'
            elif is_cygwin():
                return f'cyg{basename}.dll'
            elif is_osx():
                return f'lib{basename}.dylib'
            else:
                return f'lib{basename}.so'

        def get_static_lib_name(basename: str) -> str:
            return f'lib{basename}.a'

        # Base case (no targets or additional arguments)

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)

        self._run([*self.meson_command, 'compile', '-C', self.builddir])
        self.assertPathExists(os.path.join(self.builddir, get_exe_name('trivialprog')))

        # `--clean`

        self._run([*self.meson_command, 'compile', '-C', self.builddir, '--clean'])
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))

        # Target specified in a project with unique names

        testdir = os.path.join(self.common_test_dir, '6 linkshared')
        self.init(testdir, extra_args=['--wipe'])
        # Multiple targets and target type specified
        self._run([*self.meson_command, 'compile', '-C', self.builddir, 'mylib', 'mycpplib:shared_library'])
        # Check that we have a shared lib, but not an executable, i.e. check that target actually worked
        self.assertPathExists(os.path.join(self.builddir, get_shared_lib_name('mylib')))
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('prog')))
        self.assertPathExists(os.path.join(self.builddir, get_shared_lib_name('mycpplib')))
        self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('cppprog')))

        # Target specified in a project with non unique names

        testdir = os.path.join(self.common_test_dir, '185 same target name')
        self.init(testdir, extra_args=['--wipe'])
        self._run([*self.meson_command, 'compile', '-C', self.builddir, './foo'])
        self.assertPathExists(os.path.join(self.builddir, get_static_lib_name('foo')))
        self._run([*self.meson_command, 'compile', '-C', self.builddir, 'sub/foo'])
        self.assertPathExists(os.path.join(self.builddir, 'sub', get_static_lib_name('foo')))

        # run_target

        testdir = os.path.join(self.common_test_dir, '51 run target')
        self.init(testdir, extra_args=['--wipe'])
        out = self._run([*self.meson_command, 'compile', '-C', self.builddir, 'py3hi'])
        self.assertIn('I am Python3.', out)

        # `--$BACKEND-args`

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        if self.backend is Backend.ninja:
            self.init(testdir, extra_args=['--wipe'])
            # Dry run - should not create a program
            self._run([*self.meson_command, 'compile', '-C', self.builddir, '--ninja-args=-n'])
            self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))
        elif self.backend is Backend.vs:
            self.init(testdir, extra_args=['--wipe'])
            self._run([*self.meson_command, 'compile', '-C', self.builddir])
            # Explicitly clean the target through msbuild interface
            self._run([*self.meson_command, 'compile', '-C', self.builddir, '--vs-args=-t:{}:Clean'.format(re.sub(r'[\%\$\@\;\.\(\)\']', '_', get_exe_name('trivialprog')))])
            self.assertPathDoesNotExist(os.path.join(self.builddir, get_exe_name('trivialprog')))

    def test_spurious_reconfigure_built_dep_file(self):
        testdir = os.path.join(self.unit_test_dir, '73 dep files')

        # Regression test: Spurious reconfigure was happening when build
        # directory is inside source directory.
        # See https://gitlab.freedesktop.org/gstreamer/gst-build/-/issues/85.
        srcdir = os.path.join(self.builddir, 'srctree')
        shutil.copytree(testdir, srcdir)
        builddir = os.path.join(srcdir, '_build')
        self.change_builddir(builddir)

        self.init(srcdir)
        self.build()

        # During first configure the file did not exist so no dependency should
        # have been set. A rebuild should not trigger a reconfigure.
        self.clean()
        out = self.build()
        self.assertNotIn('Project configured', out)

        self.init(srcdir, extra_args=['--reconfigure'])

        # During the reconfigure the file did exist, but is inside build
        # directory, so no dependency should have been set. A rebuild should not
        # trigger a reconfigure.
        self.clean()
        out = self.build()
        self.assertNotIn('Project configured', out)

    def _test_junit(self, case: str) -> None:
        try:
            import lxml.etree as et
        except ImportError:
            raise SkipTest('lxml required, but not found.')

        schema = et.XMLSchema(et.parse(str(Path(self.src_root) / 'data' / 'schema.xsd')))

        self.init(case)
        self.run_tests()

        junit = et.parse(str(Path(self.builddir) / 'meson-logs' / 'testlog.junit.xml'))
        try:
            schema.assertValid(junit)
        except et.DocumentInvalid as e:
            self.fail(e.error_log)

    def test_junit_valid_tap(self):
        self._test_junit(os.path.join(self.common_test_dir, '206 tap tests'))

    def test_junit_valid_exitcode(self):
        self._test_junit(os.path.join(self.common_test_dir, '41 test args'))

    def test_junit_valid_gtest(self):
        self._test_junit(os.path.join(self.framework_test_dir, '2 gtest'))

    def test_link_language_linker(self):
        # TODO: there should be some way to query how we're linking things
        # without resorting to reading the ninja.build file
        if self.backend is not Backend.ninja:
            raise SkipTest('This test reads the ninja file')

        testdir = os.path.join(self.common_test_dir, '225 link language')
        self.init(testdir)

        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, encoding='utf-8') as f:
            contents = f.read()

        self.assertRegex(contents, r'build main(\.exe)?.*: c_LINKER')
        self.assertRegex(contents, r'build (lib|cyg)?mylib.*: c_LINKER')

    def test_commands_documented(self):
        '''
        Test that all listed meson commands are documented in Commands.md.
        '''

        # The docs directory is not in release tarballs.
        if not os.path.isdir('docs'):
            raise SkipTest('Doc directory does not exist.')
        doc_path = 'docs/markdown/Commands.md'

        md = None
        with open(doc_path, encoding='utf-8') as f:
            md = f.read()
        self.assertIsNotNone(md)

        ## Get command sections

        section_pattern = re.compile(r'^### (.+)$', re.MULTILINE)
        md_command_section_matches = [i for i in section_pattern.finditer(md)]
        md_command_sections = dict()
        for i, s in enumerate(md_command_section_matches):
            section_end = len(md) if i == len(md_command_section_matches) - 1 else md_command_section_matches[i + 1].start()
            md_command_sections[s.group(1)] = (s.start(), section_end)

        ## Validate commands

        md_commands = {k for k,v in md_command_sections.items()}
        help_output = self._run(self.meson_command + ['--help'])
        # Python's argument parser might put the command list to its own line. Or it might not.
        self.assertTrue(help_output.startswith('usage: '))
        lines = help_output.split('\n')
        line1 = lines[0]
        line2 = lines[1]
        if '{' in line1:
            cmndline = line1
        else:
            self.assertIn('{', line2)
            cmndline = line2
        cmndstr = cmndline.split('{')[1]
        self.assertIn('}', cmndstr)
        help_commands = set(cmndstr.split('}')[0].split(','))
        self.assertTrue(len(help_commands) > 0, 'Must detect some command names.')

        self.assertEqual(md_commands | {'help'}, help_commands, f'Doc file: `{doc_path}`')

        ## Validate that each section has proper placeholders

        def get_data_pattern(command):
            return re.compile(
                r'{{ ' + command + r'_usage.inc }}[\r\n]'
                r'.*?'
                r'{{ ' + command + r'_arguments.inc }}[\r\n]',
                flags = re.MULTILINE|re.DOTALL)

        for command in md_commands:
            m = get_data_pattern(command).search(md, pos=md_command_sections[command][0], endpos=md_command_sections[command][1])
            self.assertIsNotNone(m, f'Command `{command}` is missing placeholders for dynamic data. Doc file: `{doc_path}`')

    def _check_coverage_files(self, types=('text', 'xml', 'html')):
        covdir = Path(self.builddir) / 'meson-logs'
        files = []
        if 'text' in types:
            files.append('coverage.txt')
        if 'xml' in types:
            files.append('coverage.xml')
        if 'html' in types:
            files.append('coveragereport/index.html')
        for f in files:
            self.assertTrue((covdir / f).is_file(), msg=f'{f} is not a file')

    def test_coverage(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage')
        self._check_coverage_files()

    def test_coverage_complex(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '105 generatorcustom')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage')
        self._check_coverage_files()

    def test_coverage_html(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-html')
        self._check_coverage_files(['html'])

    def test_coverage_text(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-text')
        self._check_coverage_files(['text'])

    def test_coverage_xml(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage-xml')
        self._check_coverage_files(['xml'])

    def test_coverage_escaping(self):
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with coverage on MSYS2')
        gcovr_exe, gcovr_new_rootdir = mesonbuild.environment.detect_gcovr()
        if not gcovr_exe:
            raise SkipTest('gcovr not found, or too old')
        testdir = os.path.join(self.common_test_dir, '243 escape++')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'clang':
            if not mesonbuild.environment.detect_llvm_cov():
                raise SkipTest('llvm-cov not found')
        if cc.get_id() == 'msvc':
            raise SkipTest('Test only applies to non-MSVC compilers')
        self.init(testdir, extra_args=['-Db_coverage=true'])
        self.build()
        self.run_tests()
        self.run_target('coverage')
        self._check_coverage_files()

    def test_cross_file_constants(self):
        with temp_filename() as crossfile1, temp_filename() as crossfile2:
            with open(crossfile1, 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent(
                    '''
                    [constants]
                    compiler = 'gcc'
                    '''))
            with open(crossfile2, 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent(
                    '''
                    [constants]
                    toolchain = '/toolchain/'
                    common_flags = ['--sysroot=' + toolchain / 'sysroot']

                    [properties]
                    c_args = common_flags + ['-DSOMETHING']
                    cpp_args = c_args + ['-DSOMETHING_ELSE']
                    rel_to_src = '@GLOBAL_SOURCE_ROOT@' / 'tool'
                    rel_to_file = '@DIRNAME@' / 'tool'
                    no_escaping = '@@DIRNAME@@' / 'tool'

                    [binaries]
                    c = toolchain / compiler
                    '''))

            values = mesonbuild.coredata.parse_machine_files([crossfile1, crossfile2], self.builddir)
            self.assertEqual(values['binaries']['c'], '/toolchain/gcc')
            self.assertEqual(values['properties']['c_args'],
                             ['--sysroot=/toolchain/sysroot', '-DSOMETHING'])
            self.assertEqual(values['properties']['cpp_args'],
                             ['--sysroot=/toolchain/sysroot', '-DSOMETHING', '-DSOMETHING_ELSE'])
            self.assertEqual(values['properties']['rel_to_src'], os.path.join(self.builddir, 'tool'))
            self.assertEqual(values['properties']['rel_to_file'], os.path.join(os.path.dirname(crossfile2), 'tool'))
            self.assertEqual(values['properties']['no_escaping'], os.path.join(f'@{os.path.dirname(crossfile2)}@', 'tool'))

    @skipIf(is_windows(), 'Directory cleanup fails for some reason')
    def test_wrap_git(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            srcdir = os.path.join(tmpdir, 'src')
            shutil.copytree(os.path.join(self.unit_test_dir, '80 wrap-git'), srcdir)
            upstream = os.path.join(srcdir, 'subprojects', 'wrap_git_upstream')
            upstream_uri = Path(upstream).as_uri()
            git_init(upstream)
            with open(os.path.join(srcdir, 'subprojects', 'wrap_git.wrap'), 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent('''
                  [wrap-git]
                  url = {}
                  patch_directory = wrap_git_builddef
                  revision = master
                '''.format(upstream_uri)))
            out = self.init(srcdir)
            self.build()
            self.run_tests()

            # Make sure the warning does not occur on the first init.
            out_of_date_warning = 'revision may be out of date'
            self.assertNotIn(out_of_date_warning, out)

            # Change the wrap's revisions, reconfigure, and make sure it does
            # warn on the reconfigure.
            with open(os.path.join(srcdir, 'subprojects', 'wrap_git.wrap'), 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent('''
                  [wrap-git]
                  url = {}
                  patch_directory = wrap_git_builddef
                  revision = not-master
                '''.format(upstream_uri)))
            out = self.init(srcdir, extra_args='--reconfigure')
            self.assertIn(out_of_date_warning, out)

    def test_extract_objects_custom_target_no_warning(self):
        testdir = os.path.join(self.common_test_dir, '22 object extraction')

        out = self.init(testdir)
        self.assertNotRegex(out, "WARNING:.*can't be converted to File object")

    def test_multi_output_custom_target_no_warning(self):
        testdir = os.path.join(self.common_test_dir, '228 custom_target source')

        out = self.init(testdir)
        self.assertNotRegex(out, 'WARNING:.*Using the first one.')
        self.build()
        self.run_tests()

    @skipUnless(is_linux() and (re.search('^i.86$|^x86$|^x64$|^x86_64$|^amd64$', platform.processor()) is not None),
        'Requires ASM compiler for x86 or x86_64 platform currently only available on Linux CI runners')
    def test_nostdlib(self):
        testdir = os.path.join(self.unit_test_dir, '77 nostdlib')
        machinefile = os.path.join(self.builddir, 'machine.txt')
        with open(machinefile, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [properties]
                c_stdlib = 'mylibc'
                '''))

        # Test native C stdlib
        self.meson_native_files = [machinefile]
        self.init(testdir)
        self.build()

        # Test cross C stdlib
        self.new_builddir()
        self.meson_native_files = []
        self.meson_cross_files = [machinefile]
        self.init(testdir)
        self.build()

    def test_meson_version_compare(self):
        testdir = os.path.join(self.unit_test_dir, '81 meson version compare')
        out = self.init(testdir)
        self.assertNotRegex(out, r'WARNING')

    def test_wrap_redirect(self):
        redirect_wrap = os.path.join(self.builddir, 'redirect.wrap')
        real_wrap = os.path.join(self.builddir, 'foo/subprojects/real.wrap')
        os.makedirs(os.path.dirname(real_wrap))

        # Invalid redirect, filename must have .wrap extension
        with open(redirect_wrap, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [wrap-redirect]
                filename = foo/subprojects/real.wrapper
                '''))
        with self.assertRaisesRegex(WrapException, 'wrap-redirect filename must be a .wrap file'):
            PackageDefinition(redirect_wrap)

        # Invalid redirect, filename cannot be in parent directory
        with open(redirect_wrap, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [wrap-redirect]
                filename = ../real.wrap
                '''))
        with self.assertRaisesRegex(WrapException, 'wrap-redirect filename cannot contain ".."'):
            PackageDefinition(redirect_wrap)

        # Invalid redirect, filename must be in foo/subprojects/real.wrap
        with open(redirect_wrap, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [wrap-redirect]
                filename = foo/real.wrap
                '''))
        with self.assertRaisesRegex(WrapException, 'wrap-redirect filename must be in the form foo/subprojects/bar.wrap'):
            PackageDefinition(redirect_wrap)

        # Correct redirect
        with open(redirect_wrap, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [wrap-redirect]
                filename = foo/subprojects/real.wrap
                '''))
        with open(real_wrap, 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent('''
                [wrap-git]
                url = http://invalid
                '''))
        wrap = PackageDefinition(redirect_wrap)
        self.assertEqual(wrap.get('url'), 'http://invalid')

    @skip_if_no_cmake
    def test_nested_cmake_rebuild(self) -> None:
        # This checks a bug where if a non-meson project is used as a third
        # level (or deeper) subproject it doesn't cause a rebuild if the build
        # files for that project are changed
        testdir = os.path.join(self.unit_test_dir, '84 nested subproject regenerate depends')
        cmakefile = Path(testdir) / 'subprojects' / 'sub2' / 'CMakeLists.txt'
        self.init(testdir)
        self.build()
        with cmakefile.open('a', encoding='utf-8'):
            os.utime(str(cmakefile))
        self.assertReconfiguredBuildIsNoop()

    def test_version_file(self):
        srcdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(srcdir)
        projinfo = self.introspect('--projectinfo')
        self.assertEqual(projinfo['version'], '1.0.0')

    def test_cflags_cppflags(self):
        envs = {'CPPFLAGS': '-DCPPFLAG',
                'CFLAGS': '-DCFLAG',
                'CXXFLAGS': '-
```