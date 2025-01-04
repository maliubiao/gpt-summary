Response:
The user wants to understand the functionality of the provided Python code snippet, which is part of the `mtest.py` file in the Frida project. This file seems to be responsible for running and reporting on tests.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file `mtest.py` is related to testing within the Frida build system. This is evident from the class names like `TestRun`, `TestHarness`, `SingleTestRunner`, and the interaction with test results (`TestResult`). The file also handles different testing protocols like `EXITCODE`, `GTEST`, `TAP`, and `RUST`.

2. **Analyze key classes:**
    * `TestRun`: Represents a single test execution. It tracks the test's status, duration, output (stdout/stderr), return code, and handles different test protocols.
    * `TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`: These are subclasses of `TestRun`, each implementing specific logic for handling different test output formats or execution methods.
    * `TestResult`: An enumeration likely defining possible test outcomes (PASS, FAIL, SKIP, ERROR, etc.).
    * `TestHarness`:  Manages the execution of multiple tests, collects results, and generates reports.
    * `SingleTestRunner`:  Responsible for running an individual test.

3. **Trace the flow of execution (Hypothetical):** Imagine a test case being executed:
    * A `TestSerialisation` object (not shown in the snippet but referenced) likely defines the test.
    * `SingleTestRunner` is instantiated with the `TestSerialisation` and environment details.
    * `SingleTestRunner.run()` is called, which potentially executes a subprocess.
    * The subprocess output is captured and potentially parsed based on the test protocol (`TAPParser`, XML parsing for `GTEST`).
    * The `TestRun` object tracks the progress and result.
    * `TestHarness` aggregates the `TestRun` results and generates reports (like JUnit XML).

4. **Connect to reverse engineering:** Frida is a dynamic instrumentation toolkit used extensively in reverse engineering. Therefore, the tests likely validate Frida's core functionalities, such as:
    * Injecting code into running processes.
    * Intercepting function calls.
    * Modifying process memory.
    * Interacting with the Android/Linux kernel or frameworks.

5. **Identify low-level interactions:** The code interacts with subprocesses, handles signals (SIGINT, SIGTERM, SIGKILL), and mentions `os.setsid()`, which suggests dealing with process groups. This points to interactions at the operating system level.

6. **Look for logical inferences:** The code makes decisions based on return codes (`GNU_SKIP_RETURNCODE`, `GNU_ERROR_RETURNCODE`), parses output based on the test protocol, and updates the test status accordingly. For example, a non-zero return code in an `EXITCODE` test generally indicates failure.

7. **Consider potential user errors:** The code handles `FileNotFoundError` and `et.ParseError` when parsing JUnit XML, indicating potential issues with test setup or execution. The mention of `MALLOC_PERTURB_` and sanitizer options suggests the tests might rely on specific environment settings.

8. **Relate to user actions:** To reach this code, a user would typically be running the Frida test suite as part of the development process or in a CI/CD pipeline. The specific command might involve a Meson command to run the tests.

9. **Focus on the provided snippet for Part 2:**  The snippet primarily deals with the `TestResult` aggregation and reporting (specifically to JUnit XML) within the `JunitXmlLogger` class, and the detailed logic of how different test protocols are handled within the `TestRun` and its subclasses.

10. **Synthesize the information for Part 2 summary:** Combine the insights from the analysis, specifically focusing on the functionality within the provided code block. This involves summarizing how test results are formatted for JUnit, and the protocol-specific handling of test execution and result parsing.
这是 `frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py` 文件的第二部分，主要功能是定义了测试结果的记录和报告机制，以及不同测试协议的执行和结果解析。

**归纳一下它的功能:**

这部分代码主要负责以下功能：

1. **JUnit XML 报告生成 (`JunitXmlLogger` 类):**
   - 它定义了一个 `JunitXmlLogger` 类，用于生成 JUnit 格式的 XML 测试报告。
   - 它可以记录每个测试套件（suite）和测试用例（testcase）的名称、执行时间、状态（成功、失败、跳过、错误等）。
   - 对于包含子测试的测试用例，它会详细记录每个子测试的结果。
   - 它会捕获并记录测试的标准输出 (`system-out`) 和标准错误 (`system-err`)。
   - 它会将最终的 XML 报告写入指定的文件中。

2. **测试运行管理 (`TestRun` 及其子类):**
   - 定义了一个 `TestRun` 基类，表示一个正在执行的测试。
   - 它记录了测试的状态（PENDING, RUNNING, OK, FAIL, SKIP, ERROR 等）、执行时间、返回码、标准输出/错误、以及任何额外的错误信息。
   - 它支持设置测试的超时时间。
   - 它定义了 `start()` 和 `complete()` 方法来标记测试的开始和结束。
   - 它根据测试的返回码判断测试的初步结果。
   - 定义了 `get_log()` 方法来获取测试的详细日志。
   - 定义了 `needs_parsing` 属性，指示是否需要进一步解析测试的输出。
   - 定义了 `parse()` 方法，用于异步解析测试的输出，提取更详细的测试结果。

3. **不同测试协议的处理 (`TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`):**
   - 定义了 `TestRunExitCode` 类，处理基于返回码判断结果的测试。
   - 定义了 `TestRunGTest` 类，继承自 `TestRunExitCode`，专门处理 Google Test 框架的测试，并解析其生成的 XML 报告。
   - 定义了 `TestRunTAP` 类，处理 TAP (Test Anything Protocol) 格式的测试输出，它可以解析 TAP 输出中的测试结果、跳过信息、错误信息等。
   - 定义了 `TestRunRust` 类，处理 Rust 语言的测试输出，解析其特定的输出格式。
   - 使用 `TestRun.PROTOCOL_TO_CLASS` 字典来根据测试的协议类型创建相应的 `TestRun` 对象。

4. **辅助功能:**
   - `replace_unencodable_xml_chars()` 函数用于替换 XML 输出中无法编码的字符，确保生成的 XML 文件有效。
   - `decode()` 函数用于尝试以 UTF-8 或 ISO-8859-1 解码字节流，处理不同编码的输出。
   - `read_decode()` 函数异步读取并解码数据流，并可以选择将数据放入队列或打印到控制台。
   - 提供了一些用于异步操作的辅助函数，如 `queue_iter()`, `complete()`, `complete_all()`。

**与逆向方法的关系:**

Frida 是一个动态插桩工具，广泛应用于逆向工程。这部分代码的功能直接支持 Frida 的测试，而这些测试很可能包含了验证 Frida 逆向功能的场景。

**举例说明:**

假设 Frida 的某个功能是拦截特定函数的调用并修改其参数。那么相应的测试可能会：

1. **编写一个目标程序:** 该程序会调用这个待测试的函数。
2. **编写一个 Frida 脚本:** 该脚本使用 Frida 的 API 来拦截目标程序中的目标函数，并进行参数修改。
3. **编写一个测试用例:** 该测试用例会启动目标程序，注入 Frida 脚本，然后验证函数是否被成功拦截，参数是否被成功修改，以及目标程序的行为是否符合预期。

在 `mtest.py` 中，运行这个测试用例时：

- `TestRun` 对象会记录测试的启动时间。
- `SingleTestRunner` (在之前的代码部分) 会执行目标程序并注入 Frida 脚本。
- 如果测试协议是 TAP，Frida 脚本或测试程序可能会输出 TAP 格式的结果，表明拦截和修改是否成功。
- `TestRunTAP` 对象会解析 TAP 输出，判断测试是否通过。
- `JunitXmlLogger` 会将测试结果记录到 JUnit XML 报告中，例如，如果参数修改失败，报告中会标记该测试用例为 `failure`。

**涉及到二进制底层，Linux, Android 内核及框架的知识:**

- **二进制底层:** Frida 的核心功能是操作进程的内存和执行流程，这涉及到对二进制代码的理解和操作。测试可能需要验证 Frida 在处理不同架构（如 ARM, x86）和不同指令集下的能力。例如，测试可能需要验证 Frida 能否正确地在内存中定位函数入口点，修改指令等。
- **Linux 内核:** Frida 依赖于 Linux 内核提供的功能（如 `ptrace` 系统调用）来实现动态插桩。测试可能需要验证 Frida 在不同版本的 Linux 内核上的兼容性，以及能否正确地利用内核接口进行操作。例如，测试可能验证 Frida 能否在开启了某些安全模块（如 SELinux）的 Linux 系统上正常工作。
- **Android 内核及框架:** Frida 广泛应用于 Android 平台的逆向分析。测试可能需要验证 Frida 对 Android 系统服务的 hook 能力，对 ART 虚拟机的插桩能力，以及对 Native 代码的拦截能力。例如，测试可能验证 Frida 能否 hook Android framework 中的某个 API，监控应用的特定行为。

**做了逻辑推理，给出假设输入与输出:**

假设我们有一个名为 `test_hook_function` 的测试用例，它使用 TAP 协议，并验证 Frida 能否成功 hook 一个函数并修改其返回值。

**假设输入:**

- **测试程序输出 (stdout):**
  ```
  1..1
  ok 1 Hooked function returned modified value
  ```
- **`TestSerialisation` 对象 (在之前的代码部分):**
  - `protocol`: `TestProtocol.TAP`
  - `name`: `test_hook_function`

**逻辑推理:**

- `TestRun` 对象被创建，协议为 `TAP`，因此实际创建的是 `TestRunTAP` 对象。
- `TestRunTAP.parse()` 方法会被调用来解析测试程序的输出。
- TAP 解析器会识别 `1..1` 表示有一个测试用例。
- 解析器会识别 `ok 1 Hooked function returned modified value`，表示第一个测试用例通过。
- `TestRunTAP` 对象的 `res` 属性会被设置为 `TestResult.OK`.

**输出:**

- **`TestRun` 对象的状态:** `TestResult.OK`
- **JUnit XML 报告 (`JunitXmlLogger` 生成):**
  ```xml
  <testcase name="test_hook_function" classname="...">
  </testcase>
  ```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的 JUnit XML 文件路径:** 用户可能在配置 `JunitXmlLogger` 时指定了一个无效的文件路径，导致报告无法生成或写入失败。这会导致程序抛出 `FileNotFoundError` 或其他 IO 相关的异常。
2. **TAP 输出格式不符合规范:** 如果测试程序输出的 TAP 格式不正确（例如，缺少版本声明，或者状态行格式错误），`TestRunTAP.parse()` 方法可能会解析失败，导致测试结果不准确，或者 `additional_error` 属性中会包含 TAP 解析错误信息。
3. **Google Test XML 报告缺失或损坏:** 对于 `TestRunGTest`，如果测试程序未能生成 XML 报告，或者生成的 XML 文件格式错误，`et.parse()` 会抛出 `FileNotFoundError` 或 `et.ParseError`。
4. **测试超时时间设置不当:** 用户可能设置了一个过短的超时时间，导致一些需要较长时间运行的测试被意外标记为 `TIMEOUT`。
5. **环境依赖问题:** 测试可能依赖特定的环境变量或外部程序，如果用户运行测试的环境缺少这些依赖，会导致测试失败。例如，Rust 测试可能依赖 Rust 编译环境。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建或测试 Frida 的 Node.js 绑定:** 用户可能执行了类似 `meson test` 或 `ninja test` 的命令来运行测试套件。
2. **Meson 构建系统开始执行测试:** Meson 会读取测试定义文件，并根据配置启动相应的测试 runner 脚本（例如，这个 `mtest.py`）。
3. **`mtest.py` 加载测试用例信息:**  `mtest.py` 的第一部分 (未提供) 会加载测试用例的定义，包括测试名称、执行命令、预期结果、测试协议等。
4. **`TestHarness` 创建并管理测试执行:**  `TestHarness` 类会创建 `SingleTestRunner` 对象来运行每个测试用例。
5. **`SingleTestRunner` 执行测试:** `SingleTestRunner` 会执行实际的测试命令，可能会启动一个子进程。
6. **根据测试协议创建 `TestRun` 对象:** 例如，如果测试协议是 `TAP`，会创建一个 `TestRunTAP` 对象。
7. **测试执行并产生输出:** 测试程序运行，并将结果输出到标准输出或标准错误。
8. **`TestRun` 对象捕获输出:** `TestSubprocess` 类负责捕获子进程的输出。
9. **`TestRun` 对象解析输出:**  如果 `needs_parsing` 为 `True`，例如对于 `TestRunTAP` 或 `TestRunRust`，会调用相应的 `parse()` 方法来解析输出。
10. **`JunitXmlLogger` 记录测试结果:** 在测试执行完成后，`JunitXmlLogger` 会收集每个 `TestRun` 对象的状态、执行时间、输出等信息，并将其格式化为 JUnit XML 报告。
11. **`JunitXmlLogger` 写入报告文件:**  最终，生成的 XML 报告会被写入到指定的文件中。

在调试过程中，如果某个测试失败，可以查看 JUnit XML 报告，了解具体的错误信息和输出，或者查看测试的详细日志 (`get_log()`)，这有助于定位问题所在。例如，如果报告中显示一个 TAP 测试失败，可以检查测试程序的标准输出，看是否有错误的 TAP 输出格式，或者查看标准错误，看是否有其他错误信息。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
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
"""


```