Response:
The user wants me to analyze a Python file related to the Frida dynamic instrumentation tool. This is the second part of a three-part file. I need to summarize its functionality and relate it to reverse engineering, binary analysis, Linux/Android kernel/framework knowledge, logical reasoning, common user errors, and debugging.

**Plan:**

1. **High-level overview:** Understand the main purpose of this code snippet. It seems to be responsible for running and reporting on tests.
2. **Functionality breakdown:** Analyze the classes and their methods to understand the specific actions performed.
3. **Reverse Engineering Relevance:** Identify if any parts of the code directly relate to reverse engineering techniques.
4. **Binary/Kernel/Framework Knowledge:** Determine if the code interacts with low-level concepts or specific OS components.
5. **Logical Reasoning:** Look for conditional logic and potential assumptions made by the code.
6. **User Errors:** Identify potential mistakes users might make when interacting with or configuring the testing framework.
7. **Debugging:** Explain how a user might end up interacting with this code during a debugging process.
8. **Summarize functionality:** Provide a concise summary of the code's purpose.好的，让我们来分析一下这段 `mtest.py` 文件的功能。

**这段代码的主要功能是处理和报告测试结果，并将结果以 XML 格式输出。** 它定义了用于表示测试运行状态、执行测试以及生成 JUnit 兼容的 XML 报告的类和方法。

以下是更详细的功能点：

**1. JUnit XML 报告生成:**

*   定义了 `JUnitFormatter` 类，专门用于生成 JUnit 风格的 XML 报告。
*   `__init__` 方法初始化 XML 报告的根元素 `<testsuites>`。
*   `log_test` 方法接收单个测试的结果，并将其添加到 XML 报告中。它会根据测试的结果状态（通过、失败、跳过、错误等）添加不同的 XML 元素 (`<testcase>`, `<skipped>`, `<error>`, `<failure>`)。
*   对于有子测试的测试套件，它会循环处理每个子测试的结果。
*   `finish` 方法计算所有测试的总数、错误数、失败数等，并将 `<testsuite>` 元素添加到根元素 `<testsuites>`，最后将 XML 树写入到文件中。

**2. 测试运行管理:**

*   定义了 `TestRun` 基类，用于表示单个测试的运行状态和结果。
*   `__init__` 方法初始化测试的各种属性，如状态 (`res`)、名称、超时时间、执行结果 (`results`)、返回码、标准输出/错误等。
*   `start` 方法记录测试的开始时间。
*   `complete` 方法标记测试完成，并根据 `should_fail` 属性调整测试结果（例如，预期失败但通过的测试会被标记为 `UNEXPECTEDPASS`）。
*   `complete_skip` 方法用于标记测试被跳过。
*   `get_log` 方法用于获取测试的日志信息，可以选择是否彩色化输出。
*   `needs_parsing` 属性指示测试的输出是否需要进一步解析。
*   `parse` 方法（在子类中实现）用于解析测试的输出。

**3. 不同测试协议的支持:**

*   定义了 `TestRunExitCode`、`TestRunGTest`、`TestRunTAP`、`TestRunRust` 等 `TestRun` 的子类，分别用于处理不同测试协议的输出。
*   `TestRunExitCode` 根据程序的退出码判断测试结果。
*   `TestRunGTest` 解析 Google Test 生成的 XML 报告。
*   `TestRunTAP` 解析 TAP (Test Anything Protocol) 格式的输出。它使用 `TAPParser` 来解析输出，并处理不同类型的 TAP 指令（例如，测试结果、跳过、错误等）。
*   `TestRunRust` 解析 Rust 测试框架的输出。

**4. 辅助功能:**

*   `replace_unencodable_xml_chars` 函数用于替换 XML 字符串中无法编码的字符，以确保生成的 XML 文件有效。
*   `decode` 函数尝试以 UTF-8 解码字节流，如果失败则尝试 ISO-8859-1 并忽略错误。
*   `read_decode` 异步读取并解码数据流，可以选择将数据放入队列或直接打印到控制台。
*   定义了用于异步操作的辅助函数，如 `queue_iter`、`complete`、`complete_all`。
*   定义了 `TestSubprocess` 类，用于管理测试进程的创建和监控，包括标准输出/错误的收集和进程的终止。

**与逆向方法的关联及举例:**

*   **动态分析验证:**  Frida 本身是一个动态插桩工具，这个测试框架用于验证 Frida 的功能是否正常。例如，可能会编写测试用例来验证 Frida 能否成功 hook 到某个函数，修改其行为，或者注入代码到目标进程。这里的测试可能模拟逆向工程师常用的操作，比如 hook 函数、替换返回值、监控函数调用等。
    *   **举例:**  假设有一个测试用例旨在验证 Frida 能否成功 hook `open` 系统调用。该测试用例会运行一个目标程序，该程序尝试打开一个文件，然后通过 Frida hook `open` 并记录其参数。测试框架会检查 Frida 的 hook 是否成功，以及是否正确记录了文件名。

**涉及二进制底层，Linux, Android内核及框架的知识及举例:**

*   **进程管理和控制:**  代码中使用了 `asyncio.create_subprocess_exec` 来创建和管理测试进程，这涉及到操作系统底层的进程创建和控制机制。在 Linux 和 Android 上，这会涉及到 `fork` 和 `exec` 等系统调用。
*   **信号处理:**  代码中使用了 `signal` 模块来处理信号，特别是 `SIGINT` (Ctrl+C)。在 GDB 调试模式下，需要临时忽略 `SIGINT` 信号，以便 GDB 能够正确处理。这涉及到操作系统底层的信号机制。
*   **文件系统操作:**  代码中涉及到创建临时文件、读取文件内容等操作，这涉及到操作系统的文件系统 API。
*   **跨平台兼容性:** 代码中对 Windows 和非 Windows 系统做了区分处理，例如进程终止的方式 (`taskkill` vs. `killpg`)。
*   **环境变量:** 测试执行时会设置和传递环境变量，例如 `PATH`，`MALLOC_PERTURB_`，`ASAN_OPTIONS` 等。这些环境变量会影响程序的运行环境，例如动态链接库的查找路径、内存分配的行为、以及地址空间布局随机化等。
    *   **举例:** 为了测试 Frida 在 Android 上的功能，可能需要在一个模拟的 Android 环境中运行测试。这会涉及到启动 Android 虚拟机或模拟器，并将测试程序和 Frida Agent 推送到设备上。测试脚本可能会设置特定的环境变量来模拟 Android 框架的某些行为。

**逻辑推理及假设输入与输出:**

*   **测试结果判断:** 代码中存在大量的条件判断，根据测试程序的返回码、输出内容（例如 TAP 协议的输出）来推断测试的结果状态（通过、失败、跳过等）。
    *   **假设输入:** 一个 TAP 协议的输出流，包含以下内容：
        ```
        1..2
        ok 1 This is test 1
        not ok 2 This is test 2
        ```
    *   **输出:**  `TestRunTAP` 的 `parse` 方法会解析这个输出，识别出两个测试用例，第一个通过，第二个失败，并将 `self.results` 更新为相应的状态。最终，`TestRunTAP.complete` 方法会根据子测试的结果将父测试标记为 `TestResult.FAIL`。
*   **JUnit XML 生成逻辑:** `JUnitFormatter`  根据 `TestResult` 的不同状态，生成不同的 XML 元素。
    *   **假设输入:** 一个 `TestRun` 对象，其 `res` 属性为 `TestResult.SKIP`，`name` 为 "my_skipped_test"，`project` 为 "my_project"。
    *   **输出:** `JUnitFormatter.log_test` 方法会生成类似以下的 XML 片段：
        ```xml
        <testsuite name="my_project" tests="1" errors="0" failures="0" skipped="1" time="...">
          <testcase name="my_skipped_test" classname="my_project" time="...">
            <skipped/>
          </testcase>
        </testsuite>
        ```

**涉及用户或者编程常见的使用错误及举例:**

*   **测试程序未构建:**  如果用户设置了 `options.no_rebuild` 并且测试程序还没有被构建，`SingleTestRunner._get_test_cmd` 方法会抛出 `TestException`。
    *   **举例:** 用户在没有执行 `ninja` 构建测试程序的情况下，直接运行测试命令，并且使用了 `--no-rebuild` 参数。
*   **交叉编译环境配置错误:**  如果进行交叉编译测试，但没有配置正确的 `exe_wrapper`，或者 `exe_wrapper` 不存在，会导致测试无法运行。
    *   **举例:** 用户在进行 Android NDK 的交叉编译测试时，没有在 Meson 的交叉编译文件中正确指定 `exe_wrapper`，或者指定的 wrapper 程序路径不正确。
*   **TAP 输出不规范:** 如果测试程序生成了不符合 TAP 协议规范的输出，`TestRunTAP` 的 `parse` 方法可能会无法正确解析，导致测试结果错误或产生警告。
    *   **举例:** 测试程序在 TAP 输出中混入了非 TAP 语法的文本，并且没有以 `#` 开头作为注释。
*   **超时时间设置不合理:** 用户设置的超时时间过短，导致一些需要较长时间运行的测试被误判为超时。
*   **环境变量冲突:** 用户设置的环境变量与测试程序需要的环境变量冲突，导致测试行为异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **配置测试:** 用户在 `meson.build` 文件中定义了测试用例，指定了测试程序、参数、协议等信息。
2. **运行测试命令:** 用户在构建目录下执行 `meson test` 命令，或者使用 `ninja test` 命令触发测试。
3. **测试框架加载:** Meson 的测试框架会加载测试用例的定义。
4. **创建 `SingleTestRunner`:**  对于每个测试用例，会创建一个 `SingleTestRunner` 对象，负责执行该测试。
5. **执行测试进程:** `SingleTestRunner.run` 方法会调用 `_run_cmd` 来创建并运行测试进程。
6. **收集输出:**  `TestSubprocess` 类负责异步收集测试进程的标准输出和标准错误。
7. **解析输出 (如果需要):** 如果测试协议需要解析，例如 TAP 或 Rust，会调用相应的 `parse` 方法来解析输出。
8. **生成 JUnit 报告:**  `JUnitFormatter` 会接收每个测试的结果，并将其添加到 XML 报告中。
9. **输出报告:** 测试完成后，`JUnitFormatter.finish` 方法会将生成的 XML 报告写入文件。

作为调试线索，当用户遇到测试失败或异常时，他们可能会查看以下信息：

*   **控制台输出:** 查看测试运行时的实时输出，包括标准输出和标准错误。
*   **日志文件:**  查看生成的详细日志文件（如果配置了）。
*   **JUnit XML 报告:**  查看 XML 报告，了解每个测试用例的具体结果、错误信息等。
*   **测试程序的源代码:**  检查测试程序本身是否存在 bug。
*   **Frida 脚本 (如果适用):**  检查 Frida 脚本是否正确，是否存在逻辑错误。

**归纳其功能:**

总而言之，这段代码是 Frida 测试框架的核心组成部分，它负责：

*   **执行定义好的测试用例，并管理测试进程。**
*   **根据不同的测试协议（例如 Exit Code, GTest, TAP, Rust）解析测试结果。**
*   **将测试结果汇总并生成 JUnit 兼容的 XML 报告。**
*   **提供处理测试超时、信号、环境变量等功能。**
*   **为用户提供调试信息，例如日志输出和详细的 XML 报告。**

这段代码是确保 Frida 工具质量和稳定性的关键部分，它允许开发者编写和运行各种测试用例，验证 Frida 的功能是否按预期工作。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
(sum(1 for r in test.results if r.result is TestResult.SKIP)),
                time=str(test.duration),
            )

            for subtest in test.results:
                # Both name and classname are required. Use the suite name as
                # the class name, so that e.g. GitLab groups testcases correctly.
                testcase = et.SubElement(suite, 'testcase', name=str(subtest), classname=suitename)
                if subtest.result is TestResult.SKIP:
                    et.SubElement(testcase, 'skipped')
                elif subtest.result is TestResult.ERROR:
                    et.SubElement(testcase, 'error')
                elif subtest.result is TestResult.FAIL:
                    et.SubElement(testcase, 'failure')
                elif subtest.result is TestResult.UNEXPECTEDPASS:
                    fail = et.SubElement(testcase, 'failure')
                    fail.text = 'Test unexpected passed.'
                elif subtest.result is TestResult.INTERRUPT:
                    fail = et.SubElement(testcase, 'error')
                    fail.text = 'Test was interrupted by user.'
                elif subtest.result is TestResult.TIMEOUT:
                    fail = et.SubElement(testcase, 'error')
                    fail.text = 'Test did not finish before configured timeout.'
                if subtest.explanation:
                    et.SubElement(testcase, 'system-out').text = subtest.explanation
            if test.stdo:
                out = et.SubElement(suite, 'system-out')
                out.text = replace_unencodable_xml_chars(test.stdo.rstrip())
            if test.stde:
                err = et.SubElement(suite, 'system-err')
                err.text = replace_unencodable_xml_chars(test.stde.rstrip())
        else:
            if test.project not in self.suites:
                suite = self.suites[test.project] = et.Element(
                    'testsuite', name=test.project, tests='1', errors='0',
                    failures='0', skipped='0', time=str(test.duration))
            else:
                suite = self.suites[test.project]
                suite.attrib['tests'] = str(int(suite.attrib['tests']) + 1)

            testcase = et.SubElement(suite, 'testcase', name=test.name,
                                     classname=test.project, time=str(test.duration))
            if test.res is TestResult.SKIP:
                et.SubElement(testcase, 'skipped')
                suite.attrib['skipped'] = str(int(suite.attrib['skipped']) + 1)
            elif test.res is TestResult.ERROR:
                et.SubElement(testcase, 'error')
                suite.attrib['errors'] = str(int(suite.attrib['errors']) + 1)
            elif test.res is TestResult.FAIL:
                et.SubElement(testcase, 'failure')
                suite.attrib['failures'] = str(int(suite.attrib['failures']) + 1)
            if test.stdo:
                out = et.SubElement(testcase, 'system-out')
                out.text = replace_unencodable_xml_chars(test.stdo.rstrip())
            if test.stde:
                err = et.SubElement(testcase, 'system-err')
                err.text = replace_unencodable_xml_chars(test.stde.rstrip())

    async def finish(self, harness: 'TestHarness') -> None:
        """Calculate total test counts and write out the xml result."""
        for suite in self.suites.values():
            self.root.append(suite)
            # Skipped is really not allowed in the "testsuits" element
            for attr in ['tests', 'errors', 'failures']:
                self.root.attrib[attr] = str(int(self.root.attrib[attr]) + int(suite.attrib[attr]))

        tree = et.ElementTree(self.root)
        with open(self.filename, 'wb') as f:
            tree.write(f, encoding='utf-8', xml_declaration=True)


class TestRun:
    TEST_NUM = 0
    PROTOCOL_TO_CLASS: T.Dict[TestProtocol, T.Type['TestRun']] = {}

    def __new__(cls, test: TestSerialisation, *args: T.Any, **kwargs: T.Any) -> T.Any:
        return super().__new__(TestRun.PROTOCOL_TO_CLASS[test.protocol])

    def __init__(self, test: TestSerialisation, test_env: T.Dict[str, str],
                 name: str, timeout: T.Optional[int], is_parallel: bool, verbose: bool):
        self.res = TestResult.PENDING
        self.test = test
        self._num: T.Optional[int] = None
        self.name = name
        self.timeout = timeout
        self.results: T.List[TAPParser.Test] = []
        self.returncode: T.Optional[int] = None
        self.starttime: T.Optional[float] = None
        self.duration: T.Optional[float] = None
        self.stdo = ''
        self.stde = ''
        self.additional_error = ''
        self.cmd: T.Optional[T.List[str]] = None
        self.env = test_env
        self.should_fail = test.should_fail
        self.project = test.project_name
        self.junit: T.Optional[et.ElementTree] = None
        self.is_parallel = is_parallel
        self.verbose = verbose
        self.warnings: T.List[str] = []

    def start(self, cmd: T.List[str]) -> None:
        self.res = TestResult.RUNNING
        self.starttime = time.time()
        self.cmd = cmd

    @property
    def num(self) -> int:
        if self._num is None:
            TestRun.TEST_NUM += 1
            self._num = TestRun.TEST_NUM
        return self._num

    @property
    def direct_stdout(self) -> bool:
        return self.verbose and not self.is_parallel and not self.needs_parsing

    def get_results(self) -> str:
        if self.results:
            # running or succeeded
            passed = sum(x.result.is_ok() for x in self.results)
            ran = sum(x.result is not TestResult.SKIP for x in self.results)
            if passed == ran:
                return f'{passed} subtests passed'
            else:
                return f'{passed}/{ran} subtests passed'
        return ''

    def get_exit_status(self) -> str:
        return returncode_to_status(self.returncode)

    def get_details(self) -> str:
        if self.res is TestResult.PENDING:
            return ''
        if self.returncode:
            return self.get_exit_status()
        return self.get_results()

    def _complete(self) -> None:
        if self.res == TestResult.RUNNING:
            self.res = TestResult.OK
        assert isinstance(self.res, TestResult)
        if self.should_fail and self.res in (TestResult.OK, TestResult.FAIL):
            self.res = TestResult.UNEXPECTEDPASS if self.res is TestResult.OK else TestResult.EXPECTEDFAIL
        if self.stdo and not self.stdo.endswith('\n'):
            self.stdo += '\n'
        if self.stde and not self.stde.endswith('\n'):
            self.stde += '\n'
        self.duration = time.time() - self.starttime

    @property
    def cmdline(self) -> T.Optional[str]:
        if not self.cmd:
            return None
        test_only_env = set(self.env.items()) - set(os.environ.items())
        return env_tuple_to_str(test_only_env) + \
            ' '.join(sh_quote(x) for x in self.cmd)

    def complete_skip(self) -> None:
        self.starttime = time.time()
        self.returncode = GNU_SKIP_RETURNCODE
        self.res = TestResult.SKIP
        self._complete()

    def complete(self) -> None:
        self._complete()

    def get_log(self, colorize: bool = False, stderr_only: bool = False) -> str:
        stdo = '' if stderr_only else self.stdo
        if self.stde or self.additional_error:
            res = ''
            if stdo:
                res += mlog.cyan('stdout:').get_text(colorize) + '\n'
                res += stdo
                if res[-1:] != '\n':
                    res += '\n'
            res += mlog.cyan('stderr:').get_text(colorize) + '\n'
            res += join_lines(self.stde, self.additional_error)
        else:
            res = stdo
        if res and res[-1:] != '\n':
            res += '\n'
        return res

    @property
    def needs_parsing(self) -> bool:
        return False

    async def parse(self, harness: 'TestHarness', lines: T.AsyncIterator[str]) -> None:
        async for l in lines:
            pass


class TestRunExitCode(TestRun):

    def complete(self) -> None:
        if self.res != TestResult.RUNNING:
            pass
        elif self.returncode == GNU_SKIP_RETURNCODE:
            self.res = TestResult.SKIP
        elif self.returncode == GNU_ERROR_RETURNCODE:
            self.res = TestResult.ERROR
        else:
            self.res = TestResult.FAIL if bool(self.returncode) else TestResult.OK
        super().complete()

TestRun.PROTOCOL_TO_CLASS[TestProtocol.EXITCODE] = TestRunExitCode


class TestRunGTest(TestRunExitCode):
    def complete(self) -> None:
        filename = f'{self.test.name}.xml'
        if self.test.workdir:
            filename = os.path.join(self.test.workdir, filename)

        try:
            with open(filename, 'r', encoding='utf8', errors='replace') as f:
                self.junit = et.parse(f)
        except FileNotFoundError:
            # This can happen if the test fails to run or complete for some
            # reason, like the rpath for libgtest isn't properly set. ExitCode
            # will handle the failure, don't generate a stacktrace.
            pass
        except et.ParseError as e:
            # ExitCode will handle the failure, don't generate a stacktrace.
            mlog.error(f'Unable to parse {filename}: {e!s}')

        super().complete()

TestRun.PROTOCOL_TO_CLASS[TestProtocol.GTEST] = TestRunGTest


class TestRunTAP(TestRun):
    @property
    def needs_parsing(self) -> bool:
        return True

    def complete(self) -> None:
        if self.returncode != 0 and not self.res.was_killed():
            self.res = TestResult.ERROR
            self.stde = self.stde or ''
            self.stde += f'\n(test program exited with status code {self.returncode})'
        super().complete()

    async def parse(self, harness: 'TestHarness', lines: T.AsyncIterator[str]) -> None:
        res = None
        warnings: T.List[TAPParser.UnknownLine] = []
        version = 12

        async for i in TAPParser().parse_async(lines):
            if isinstance(i, TAPParser.Version):
                version = i.version
            elif isinstance(i, TAPParser.Bailout):
                res = TestResult.ERROR
                harness.log_subtest(self, i.message, res)
            elif isinstance(i, TAPParser.Test):
                self.results.append(i)
                if i.result.is_bad():
                    res = TestResult.FAIL
                harness.log_subtest(self, i.name or f'subtest {i.number}', i.result)
            elif isinstance(i, TAPParser.UnknownLine):
                warnings.append(i)
            elif isinstance(i, TAPParser.Error):
                self.additional_error += 'TAP parsing error: ' + i.message
                res = TestResult.ERROR

        if warnings:
            unknown = str(mlog.yellow('UNKNOWN'))
            width = len(str(max(i.lineno for i in warnings)))
            for w in warnings:
                self.warnings.append(f'stdout: {w.lineno:{width}}: {unknown}: {w.message}')
            if version > 13:
                self.warnings.append('Unknown TAP output lines have been ignored. Please open a feature request to\n'
                                     'implement them, or prefix them with a # if they are not TAP syntax.')
            else:
                self.warnings.append(str(mlog.red('ERROR')) + ': Unknown TAP output lines for a supported TAP version.\n'
                                     'This is probably a bug in the test; if they are not TAP syntax, prefix them with a #')
        if all(t.result is TestResult.SKIP for t in self.results):
            # This includes the case where self.results is empty
            res = TestResult.SKIP

        if res and self.res == TestResult.RUNNING:
            self.res = res

TestRun.PROTOCOL_TO_CLASS[TestProtocol.TAP] = TestRunTAP


class TestRunRust(TestRun):
    @property
    def needs_parsing(self) -> bool:
        return True

    async def parse(self, harness: 'TestHarness', lines: T.AsyncIterator[str]) -> None:
        def parse_res(n: int, name: str, result: str) -> TAPParser.Test:
            if result == 'ok':
                return TAPParser.Test(n, name, TestResult.OK, None)
            elif result == 'ignored':
                return TAPParser.Test(n, name, TestResult.SKIP, None)
            elif result == 'FAILED':
                return TAPParser.Test(n, name, TestResult.FAIL, None)
            return TAPParser.Test(n, name, TestResult.ERROR,
                                  f'Unsupported output from rust test: {result}')

        n = 1
        async for line in lines:
            if line.startswith('test ') and not line.startswith('test result'):
                _, name, _, result = line.rstrip().split(' ')
                name = name.replace('::', '.')
                t = parse_res(n, name, result)
                self.results.append(t)
                harness.log_subtest(self, name, t.result)
                n += 1

        res = None

        if all(t.result is TestResult.SKIP for t in self.results):
            # This includes the case where self.results is empty
            res = TestResult.SKIP
        elif any(t.result is TestResult.ERROR for t in self.results):
            res = TestResult.ERROR
        elif any(t.result is TestResult.FAIL for t in self.results):
            res = TestResult.FAIL

        if res and self.res == TestResult.RUNNING:
            self.res = res

TestRun.PROTOCOL_TO_CLASS[TestProtocol.RUST] = TestRunRust

# Check unencodable characters in xml output and replace them with
# their printable representation
def replace_unencodable_xml_chars(original_str: str) -> str:
    # [1:-1] is needed for removing `'` characters from both start and end
    # of the string
    replacement_lambda = lambda illegal_chr: repr(illegal_chr.group())[1:-1]
    return UNENCODABLE_XML_CHRS_RE.sub(replacement_lambda, original_str)

def decode(stream: T.Union[None, bytes]) -> str:
    if stream is None:
        return ''
    try:
        return stream.decode('utf-8')
    except UnicodeDecodeError:
        return stream.decode('iso-8859-1', errors='ignore')

async def read_decode(reader: asyncio.StreamReader,
                      queue: T.Optional['asyncio.Queue[T.Optional[str]]'],
                      console_mode: ConsoleUser) -> str:
    stdo_lines = []
    try:
        while not reader.at_eof():
            # Prefer splitting by line, as that produces nicer output
            try:
                line_bytes = await reader.readuntil(b'\n')
            except asyncio.IncompleteReadError as e:
                line_bytes = e.partial
            except asyncio.LimitOverrunError as e:
                line_bytes = await reader.readexactly(e.consumed)
            if line_bytes:
                line = decode(line_bytes)
                stdo_lines.append(line)
                if console_mode is ConsoleUser.STDOUT:
                    print(line, end='', flush=True)
                if queue:
                    await queue.put(line)
        return ''.join(stdo_lines)
    except asyncio.CancelledError:
        return ''.join(stdo_lines)
    finally:
        if queue:
            await queue.put(None)

def run_with_mono(fname: str) -> bool:
    return fname.endswith('.exe') and not (is_windows() or is_cygwin())

def check_testdata(objs: T.List[TestSerialisation]) -> T.List[TestSerialisation]:
    if not isinstance(objs, list):
        raise MesonVersionMismatchException('<unknown>', coredata_version)
    for obj in objs:
        if not isinstance(obj, TestSerialisation):
            raise MesonVersionMismatchException('<unknown>', coredata_version)
        if not hasattr(obj, 'version'):
            raise MesonVersionMismatchException('<unknown>', coredata_version)
        if major_versions_differ(obj.version, coredata_version):
            raise MesonVersionMismatchException(obj.version, coredata_version)
    return objs

# Custom waiting primitives for asyncio

async def queue_iter(q: 'asyncio.Queue[T.Optional[str]]') -> T.AsyncIterator[str]:
    while True:
        item = await q.get()
        q.task_done()
        if item is None:
            break
        yield item

async def complete(future: asyncio.Future) -> None:
    """Wait for completion of the given future, ignoring cancellation."""
    try:
        await future
    except asyncio.CancelledError:
        pass

async def complete_all(futures: T.Iterable[asyncio.Future],
                       timeout: T.Optional[T.Union[int, float]] = None) -> None:
    """Wait for completion of all the given futures, ignoring cancellation.
       If timeout is not None, raise an asyncio.TimeoutError after the given
       time has passed.  asyncio.TimeoutError is only raised if some futures
       have not completed and none have raised exceptions, even if timeout
       is zero."""

    def check_futures(futures: T.Iterable[asyncio.Future]) -> None:
        # Raise exceptions if needed
        left = False
        for f in futures:
            if not f.done():
                left = True
            elif not f.cancelled():
                f.result()
        if left:
            raise asyncio.TimeoutError

    # Python is silly and does not have a variant of asyncio.wait with an
    # absolute time as deadline.
    loop = asyncio.get_running_loop()
    deadline = None if timeout is None else loop.time() + timeout
    while futures and (timeout is None or timeout > 0):
        done, futures = await asyncio.wait(futures, timeout=timeout,
                                           return_when=asyncio.FIRST_EXCEPTION)
        check_futures(done)
        if deadline:
            timeout = deadline - loop.time()

    check_futures(futures)


class TestSubprocess:
    def __init__(self, p: asyncio.subprocess.Process,
                 stdout: T.Optional[int], stderr: T.Optional[int],
                 postwait_fn: T.Callable[[], None] = None):
        self._process = p
        self.stdout = stdout
        self.stderr = stderr
        self.stdo_task: T.Optional[asyncio.Task[None]] = None
        self.stde_task: T.Optional[asyncio.Task[None]] = None
        self.postwait_fn = postwait_fn
        self.all_futures: T.List[asyncio.Future] = []
        self.queue: T.Optional[asyncio.Queue[T.Optional[str]]] = None

    def stdout_lines(self) -> T.AsyncIterator[str]:
        self.queue = asyncio.Queue()
        return queue_iter(self.queue)

    def communicate(self,
                    test: 'TestRun',
                    console_mode: ConsoleUser) -> T.Tuple[T.Optional[T.Awaitable[str]],
                                                          T.Optional[T.Awaitable[str]]]:
        async def collect_stdo(test: 'TestRun',
                               reader: asyncio.StreamReader,
                               console_mode: ConsoleUser) -> None:
            test.stdo = await read_decode(reader, self.queue, console_mode)

        async def collect_stde(test: 'TestRun',
                               reader: asyncio.StreamReader,
                               console_mode: ConsoleUser) -> None:
            test.stde = await read_decode(reader, None, console_mode)

        # asyncio.ensure_future ensures that printing can
        # run in the background, even before it is awaited
        if self.stdo_task is None and self.stdout is not None:
            decode_coro = collect_stdo(test, self._process.stdout, console_mode)
            self.stdo_task = asyncio.ensure_future(decode_coro)
            self.all_futures.append(self.stdo_task)
        if self.stderr is not None and self.stderr != asyncio.subprocess.STDOUT:
            decode_coro = collect_stde(test, self._process.stderr, console_mode)
            self.stde_task = asyncio.ensure_future(decode_coro)
            self.all_futures.append(self.stde_task)

        return self.stdo_task, self.stde_task

    async def _kill(self) -> T.Optional[str]:
        # Python does not provide multiplatform support for
        # killing a process and all its children so we need
        # to roll our own.
        p = self._process
        try:
            if is_windows():
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)])
            else:
                # Send a termination signal to the process group that setsid()
                # created - giving it a chance to perform any cleanup.
                os.killpg(p.pid, signal.SIGTERM)

                # Make sure the termination signal actually kills the process
                # group, otherwise retry with a SIGKILL.
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(p.wait(), timeout=0.5)
                if p.returncode is not None:
                    return None

                os.killpg(p.pid, signal.SIGKILL)

            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(p.wait(), timeout=1)
            if p.returncode is not None:
                return None

            # An earlier kill attempt has not worked for whatever reason.
            # Try to kill it one last time with a direct call.
            # If the process has spawned children, they will remain around.
            p.kill()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(p.wait(), timeout=1)
            if p.returncode is not None:
                return None
            return 'Test process could not be killed.'
        except ProcessLookupError:
            # Sometimes (e.g. with Wine) this happens.  There's nothing
            # we can do, probably the process already died so just wait
            # for the event loop to pick that up.
            await p.wait()
            return None
        finally:
            if self.stdo_task:
                self.stdo_task.cancel()
            if self.stde_task:
                self.stde_task.cancel()

    async def wait(self, test: 'TestRun') -> None:
        p = self._process

        self.all_futures.append(asyncio.ensure_future(p.wait()))
        try:
            await complete_all(self.all_futures, timeout=test.timeout)
        except asyncio.TimeoutError:
            test.additional_error += await self._kill() or ''
            test.res = TestResult.TIMEOUT
        except asyncio.CancelledError:
            # The main loop must have seen Ctrl-C.
            test.additional_error += await self._kill() or ''
            test.res = TestResult.INTERRUPT
        finally:
            if self.postwait_fn:
                self.postwait_fn()

        test.returncode = p.returncode or 0

class SingleTestRunner:

    def __init__(self, test: TestSerialisation, env: T.Dict[str, str], name: str,
                 options: argparse.Namespace):
        self.test = test
        self.options = options
        self.cmd = self._get_cmd()

        if self.cmd and self.test.extra_paths:
            env['PATH'] = os.pathsep.join(self.test.extra_paths + ['']) + env['PATH']
            winecmd = []
            for c in self.cmd:
                winecmd.append(c)
                if os.path.basename(c).startswith('wine'):
                    env['WINEPATH'] = get_wine_shortpath(
                        winecmd,
                        ['Z:' + p for p in self.test.extra_paths] + env.get('WINEPATH', '').split(';'),
                        self.test.workdir
                    )
                    break

        # If MALLOC_PERTURB_ is not set, or if it is set to an empty value,
        # (i.e., the test or the environment don't explicitly set it), set
        # it ourselves. We do this unconditionally for regular tests
        # because it is extremely useful to have.
        # Setting MALLOC_PERTURB_="0" will completely disable this feature.
        if ('MALLOC_PERTURB_' not in env or not env['MALLOC_PERTURB_']) and not options.benchmark:
            env['MALLOC_PERTURB_'] = str(random.randint(1, 255))

        # Sanitizers do not default to aborting on error. This is counter to
        # expectations when using -Db_sanitize and has led to confusion in the wild
        # in CI. Set our own values of {ASAN,UBSAN}_OPTIONS to rectify this, but
        # only if the user has not defined them.
        if ('ASAN_OPTIONS' not in env or not env['ASAN_OPTIONS']):
            env['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:print_summary=1'
        if ('UBSAN_OPTIONS' not in env or not env['UBSAN_OPTIONS']):
            env['UBSAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1'
        if ('MSAN_OPTIONS' not in env or not env['MSAN_OPTIONS']):
            env['UBSAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1'

        if self.options.gdb or self.test.timeout is None or self.test.timeout <= 0:
            timeout = None
        elif self.options.timeout_multiplier is None:
            timeout = self.test.timeout
        elif self.options.timeout_multiplier <= 0:
            timeout = None
        else:
            timeout = self.test.timeout * self.options.timeout_multiplier

        is_parallel = test.is_parallel and self.options.num_processes > 1 and not self.options.gdb
        verbose = (test.verbose or self.options.verbose) and not self.options.quiet
        self.runobj = TestRun(test, env, name, timeout, is_parallel, verbose)

        if self.options.gdb:
            self.console_mode = ConsoleUser.GDB
        elif self.runobj.direct_stdout:
            self.console_mode = ConsoleUser.STDOUT
        else:
            self.console_mode = ConsoleUser.LOGGER

    def _get_test_cmd(self) -> T.Optional[T.List[str]]:
        testentry = self.test.fname[0]
        if self.options.no_rebuild and self.test.cmd_is_built and not os.path.isfile(testentry):
            raise TestException(f'The test program {testentry!r} does not exist. Cannot run tests before building them.')
        if testentry.endswith('.jar'):
            return ['java', '-jar'] + self.test.fname
        elif not self.test.is_cross_built and run_with_mono(testentry):
            return ['mono'] + self.test.fname
        elif self.test.cmd_is_exe and self.test.is_cross_built and self.test.needs_exe_wrapper:
            if self.test.exe_wrapper is None:
                # Can not run test on cross compiled executable
                # because there is no execute wrapper.
                return None
            elif self.test.cmd_is_exe:
                # If the command is not built (ie, its a python script),
                # then we don't check for the exe-wrapper
                if not self.test.exe_wrapper.found():
                    msg = ('The exe_wrapper defined in the cross file {!r} was not '
                           'found. Please check the command and/or add it to PATH.')
                    raise TestException(msg.format(self.test.exe_wrapper.name))
                return self.test.exe_wrapper.get_command() + self.test.fname
        elif self.test.cmd_is_built and not self.test.cmd_is_exe and is_windows():
            test_cmd = ExternalProgram._shebang_to_cmd(self.test.fname[0])
            if test_cmd is not None:
                test_cmd += self.test.fname[1:]
            return test_cmd
        return self.test.fname

    def _get_cmd(self) -> T.Optional[T.List[str]]:
        test_cmd = self._get_test_cmd()
        if not test_cmd:
            return None
        return TestHarness.get_wrapper(self.options) + test_cmd

    @property
    def is_parallel(self) -> bool:
        return self.runobj.is_parallel

    @property
    def visible_name(self) -> str:
        return self.runobj.name

    @property
    def timeout(self) -> T.Optional[int]:
        return self.runobj.timeout

    async def run(self, harness: 'TestHarness') -> TestRun:
        if self.cmd is None:
            self.stdo = 'Not run because cannot execute cross compiled binaries.'
            harness.log_start_test(self.runobj)
            self.runobj.complete_skip()
        else:
            cmd = self.cmd + self.test.cmd_args + self.options.test_args
            self.runobj.start(cmd)
            harness.log_start_test(self.runobj)
            await self._run_cmd(harness, cmd)
        return self.runobj

    async def _run_subprocess(self, args: T.List[str], *,
                              stdout: T.Optional[int], stderr: T.Optional[int],
                              env: T.Dict[str, str], cwd: T.Optional[str]) -> TestSubprocess:
        # Let gdb handle ^C instead of us
        if self.options.gdb:
            previous_sigint_handler = signal.getsignal(signal.SIGINT)
            # Make the meson executable ignore SIGINT while gdb is running.
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        def preexec_fn() -> None:
            if self.options.gdb:
                # Restore the SIGINT handler for the child process to
                # ensure it can handle it.
                signal.signal(signal.SIGINT, signal.SIG_DFL)
            else:
                # We don't want setsid() in gdb because gdb needs the
                # terminal in order to handle ^C and not show tcsetpgrp()
                # errors avoid not being able to use the terminal.
                os.setsid()

        def postwait_fn() -> None:
            if self.options.gdb:
                # Let us accept ^C again
                signal.signal(signal.SIGINT, previous_sigint_handler)

        p = await asyncio.create_subprocess_exec(*args,
                                                 stdout=stdout,
                                                 stderr=stderr,
                                                 env=env,
                                                 cwd=cwd,
                                                 preexec_fn=preexec_fn if not is_windows() else None)
        return TestSubprocess(p, stdout=stdout, stderr=stderr,
                              postwait_fn=postwait_fn if not is_windows() else None)

    async def _run_cmd(self, harness: 'TestHarness', cmd: T.List[str]) -> None:
        if self.console_mode is ConsoleUser.GDB:
            stdout = None
            stderr = None
        else:
            stdout = asyncio.subprocess.PIPE
            stderr = asyncio.subprocess.STDOUT \
                if not self.options.split and not self.runobj.needs_parsing \
                else asyncio.subprocess.PIPE

        extra_cmd: T.List[str] = []
        if self.test.protocol is TestProtocol.GTEST:
            gtestname = self.test.name
            if self.test.workdir:
                gtestname = os.path.join(self.test.workdir, self.test.name)
            extra_cmd.append(f'--gtest_output=xml:{gtestname}.xml')

        p = await self._run_subprocess(cmd + extra_cmd,
                                       stdout=stdout,
                                       stderr=stderr,
                                       env=self.runobj.env,
                                       cwd=self.test.workdir)

        if self.runobj.needs_parsing:
            parse_coro = self.runobj.parse(harness, p.stdout_lines())
            parse_task = asyncio.ensure_future(parse_coro)
        else:
            parse_task = None

        stdo_task, stde_task = p.communicate(self.runobj, self.console_mode)
        await p.wait(self.runobj)

        if parse_task:
            await parse_task
        if stdo_task:
            await stdo_task
        if stde_task:
            await stde_task

        self.runobj.complete()


class TestHarness:
    def __init__(self, options: argparse.Namespace):
        self.options = options
        self.collected_failures: T.List[TestRun] = []
        self.fail_count = 0
        self.expectedfail_count = 0
        self.unexpectedpass_count = 0
        self.success_count = 0
        self.skip_count = 0
        self.timeout_count = 0
        self.test_count = 0
        self.name_max_len = 0
        self.is_run = False
        self.loggers: T.List[TestLogger] = []
        self.console_logger = ConsoleLogger()
        self.loggers.append(self.console_logger)
        self.need_console = False
        self.ninja: T.List[str] = None

        self.logfile_base: T.Optional[str] = None
        if self.options.logbase and not self.options.gdb:
            namebase = None
            self.logfile_base = os.path.join(self.options.wd, 'meson-logs', self.options.logbase)

            if self.options.wrapper:
                namebase = os.path.basename(self.get_wrapper(self.options)[0])
            elif self.options.setup:
                namebase = self.options.setup.replace(":", "_")

            if namebase:
                self.logfile_base += '-' + namebase.replace(' ', '_')

        self.prepare_build()
        self.load_
```