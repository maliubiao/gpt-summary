Response:
The user wants a summary of the Python code provided, which is part of the `frida` dynamic instrumentation tool. The specific file `mtest.py` seems to handle running and reporting on tests. I need to break down the code into its core functionalities and explain them in the context of testing and potentially reverse engineering.

Here's a plan:
1. **Identify the main classes and their purposes:**  Focus on classes like `JUnitLog`, `TestRun`, `TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`, `TestSubprocess`, `SingleTestRunner`, and `TestHarness`.
2. **Explain the role of each class:** Describe what each class is responsible for in the test execution and reporting process.
3. **Connect to reverse engineering concepts:**  If a class or functionality is relevant to reverse engineering (like running tests on instrumented code), provide examples.
4. **Highlight interaction with the OS and underlying systems:** Point out any interactions with Linux, Android, or low-level binary concepts.
5. **Analyze logical flow and potential input/output:**  Examine the logic within functions and predict outputs based on hypothetical inputs.
6. **Identify common user errors:**  Look for potential mistakes users might make when interacting with the testing framework.
7. **Trace user actions to this code:** Explain how a user's commands might lead to the execution of this specific Python file.
8. **Summarize the functionalities:**  Provide a concise overview of the file's purpose.
好的，这是 frida 项目中负责执行测试并生成报告的 `mtest.py` 文件的一部分代码。让我们来分析一下它的功能。

**功能归纳 (基于提供的代码片段):**

这段代码主要负责测试结果的收集、处理和报告生成，特别是以 JUnit XML 格式输出测试结果。它定义了多种处理不同测试协议的测试运行方式，并包含了管理测试执行过程的类。

**具体功能分解：**

1. **JUnit XML 报告生成 (`JUnitLog` 类):**
   - 该类负责将测试结果转换成 JUnit XML 格式，这是一种通用的测试报告格式，可以被 CI/CD 系统（如 GitLab）解析和展示。
   - 它会为每个测试套件（suite）和测试用例（testcase）创建 XML 元素，记录测试的名称、状态（通过、失败、跳过、错误等）、执行时间以及相关的输出（stdout 和 stderr）。
   - 对于包含子测试的情况，它会更细粒度地记录每个子测试的结果。
   - 它会将最终的 XML 树写入到指定的文件中。

2. **测试运行基类 (`TestRun` 类):**
   - 这是一个抽象基类，定义了测试运行的通用属性和方法。
   - 包含了测试的基本信息，如测试名称、超时时间、环境变量、执行结果、开始时间和持续时间、标准输出和标准错误输出等。
   - `start()` 方法标记测试开始执行。
   - `complete()` 方法标记测试完成，并根据返回码和 `should_fail` 属性设置最终的测试结果（通过、失败、预期失败、意外通过等）。
   - `complete_skip()` 方法用于标记测试被跳过。
   - `get_log()` 方法用于获取测试的输出日志，可以进行着色处理。
   - `needs_parsing` 属性指示该测试是否需要解析输出来获取更详细的结果。
   - `parse()` 方法是一个异步方法，用于解析测试的输出（如果 `needs_parsing` 为 `True`）。

3. **不同测试协议的实现 (`TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`):**
   - 这些类继承自 `TestRun`，针对不同的测试协议（如基于返回码、Google Test、TAP 协议、Rust 测试）实现了特定的完成和解析逻辑。
   - `TestRunExitCode`:  最简单的实现，根据程序的返回码来判断测试结果。
   - `TestRunGTest`:  专门处理 Google Test 的输出，会尝试解析 Google Test 生成的 XML 报告文件。
   - `TestRunTAP`:  处理 TAP (Test Anything Protocol) 格式的输出，会解析 TAP 输出中的状态、子测试结果等信息。
   - `TestRunRust`: 处理 Rust 测试的输出，解析 Rust 测试框架的特定输出格式。

4. **测试子进程管理 (`TestSubprocess` 类):**
   - 该类封装了 `asyncio` 提供的子进程管理功能。
   - 负责创建和管理测试执行的子进程，捕获其标准输出和标准错误输出。
   - 提供了 `communicate()` 方法来异步收集子进程的输出。
   - 实现了 `wait()` 方法来等待子进程完成，并处理超时和中断的情况，包括尝试优雅地终止子进程。
   - 提供了 `stdout_lines()` 方法以异步迭代的方式读取子进程的标准输出。

5. **单个测试用例的执行 (`SingleTestRunner` 类):**
   - 该类负责准备和执行单个测试用例。
   - 包含了测试的配置信息、环境变量、执行命令等。
   - `_get_cmd()` 方法用于构建测试执行的完整命令，包括可能的包装器（wrapper）。
   - `run()` 方法是执行测试的主要入口，会启动子进程并等待其完成。
   - `_run_subprocess()` 方法使用 `asyncio` 创建并运行子进程。
   - 考虑了跨平台编译、Mono 运行时、以及需要执行包装器的情况。

6. **测试流程管理 (`TestHarness` 类，虽然代码片段不完整，但可以推断其功能):**
   - 此类（代码片段未完全展示）负责管理整个测试流程。
   - 可能包含加载测试用例、并行执行测试、汇总测试结果、生成最终报告等功能。
   - 从提供的代码来看，它会维护一个 `loggers` 列表，用于记录测试过程中的信息，包括 `ConsoleLogger` 和 `JUnitLog`。
   - `log_start_test()` 和 `log_subtest()` 方法用于记录测试开始和子测试的结果。

**与逆向方法的关系：**

这段代码是 Frida 测试框架的一部分，而 Frida 本身就是一个动态插桩工具，广泛应用于逆向工程。因此，这段代码直接关系到逆向方法：

- **测试 Frida 的功能:**  这些测试用例很可能用于验证 Frida 的各种插桩功能是否正常工作，例如，hook 函数、修改内存、跟踪函数调用等。
- **验证插桩效果:** 逆向工程师可能会编写测试用例来验证他们使用 Frida 对目标程序进行插桩后，程序行为是否如预期那样被修改。例如，可以测试 hook 某个函数后，返回值是否被改变。
- **回归测试:**  当 Frida 的代码发生变更时，这些测试可以用来确保新的改动没有破坏现有的功能。这对于保证逆向工具的稳定性和可靠性至关重要。

**举例说明：**

假设有一个测试用例旨在验证 Frida 是否能成功 hook `open` 系统调用并记录其参数。这个测试用例可能会：

1. **运行一个目标程序:** 该程序会调用 `open` 函数打开一个文件。
2. **使用 Frida 进行插桩:** 测试框架会使用 Frida 提供的 API，hook 目标程序的 `open` 函数。在 hook 函数中，记录 `open` 函数的参数（例如，文件名和打开模式）。
3. **断言测试结果:** 测试用例会断言 Frida 的 hook 是否成功执行，并且记录的 `open` 函数参数与预期一致。
4. **`mtest.py` 的作用:**  `mtest.py` 中的类会负责启动目标程序，运行 Frida 进行插桩，收集测试用例的输出（可能包含 Frida 的日志），然后解析输出或者 JUnit 报告，判断测试是否通过，并将结果以 JUnit XML 格式输出。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

- **二进制底层:**  Frida 的插桩操作直接作用于目标进程的内存空间，涉及到对二进制代码的修改和执行流程的控制。测试用例需要验证这些底层操作的正确性。
- **Linux 系统调用:**  很多 Frida 的 hook 操作是针对 Linux 系统调用的，例如 `open`, `read`, `write`, `socket` 等。测试用例会涉及到对这些系统调用进行插桩和验证。
- **Android 框架:** Frida 也常用于 Android 平台的逆向分析。测试用例可能涉及到 hook Android 框架层的 API，例如 Java Native Interface (JNI) 函数、Binder 调用等。
- **进程管理:** `TestSubprocess` 类直接使用了操作系统提供的进程管理功能（通过 `asyncio` 封装），涉及到进程的创建、控制、信号处理等。

**举例说明：**

假设一个测试用例需要验证 Frida 能否 hook Android 应用程序中的 `onCreate` 方法。

1. **目标程序:**  一个简单的 Android APK 文件。
2. **Frida 插桩:**  测试框架会使用 Frida 连接到 Android 设备上的目标应用程序进程，并 hook 其 `onCreate` 方法。
3. **测试逻辑:**  hook 代码可能会记录 `onCreate` 方法被调用，或者修改其行为。
4. **`mtest.py` 的作用:**  `mtest.py` 会负责启动 Android 应用程序，运行 Frida 脚本进行插桩，收集测试结果（例如，检查 hook 是否被触发），并生成测试报告。

**逻辑推理与假设输入输出：**

假设有一个基于返回码的简单测试用例（使用 `TestRunExitCode`），测试一个程序 `my_program`，预期该程序在成功时返回 0。

**假设输入：**

- `test.protocol` 为 `TestProtocol.EXITCODE`
- `test.fname` 为 `['./my_program']`
- 测试用例执行后，`my_program` 的返回码为 0。

**逻辑推理：**

1. `SingleTestRunner` 会创建 `TestRunExitCode` 的实例。
2. 执行 `my_program` 子进程。
3. `TestSubprocess` 等待子进程结束，并获取其返回码。
4. `TestRunExitCode.complete()` 方法会被调用。
5. 由于返回码为 0，`self.res` 会被设置为 `TestResult.OK`。

**假设输出（JUnit XML 片段）：**

```xml
<testcase name="my_program" classname="your_project">
</testcase>
```

如果 `my_program` 返回非 0 的值，`self.res` 将会被设置为 `TestResult.FAIL`，JUnit XML 中会包含 `<failure>` 标签。

**用户或编程常见的使用错误：**

1. **测试程序路径错误:** 用户在定义测试用例时，可能会提供错误的测试程序路径，导致 `SingleTestRunner` 无法找到可执行文件。`mtest.py` 可能会抛出异常或将测试标记为失败。
2. **环境变量配置错误:** 测试用例可能依赖特定的环境变量，如果用户没有正确配置，会导致测试失败。`mtest.py` 会捕获子进程的错误输出，帮助用户定位问题。
3. **超时时间设置不当:**  如果测试用例的执行时间超过了设置的超时时间，`TestSubprocess.wait()` 会捕获 `asyncio.TimeoutError`，并将测试标记为超时。用户可能需要根据实际情况调整超时时间。
4. **TAP 输出格式不正确:** 如果测试用例使用 TAP 协议，但其输出不符合 TAP 规范，`TestRunTAP.parse()` 可能会解析失败，导致测试结果不准确或报错。
5. **依赖未构建:** 如果设置了 `options.no_rebuild`，但测试程序尚未构建，`SingleTestRunner._get_test_cmd()` 会抛出 `TestException`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户执行 Meson 测试命令:** 用户通常会使用 `meson test` 或 `ninja test` 命令来运行项目中的测试。
2. **Meson 解析测试定义:** Meson 会读取 `meson.build` 文件中定义的测试用例信息。
3. **调用 `mtest.py`:** Meson 会调用 `mtest.py` 脚本来执行测试。这通常发生在构建目录下的某个临时目录中。
4. **`TestHarness` 初始化:** `mtest.py` 首先会创建一个 `TestHarness` 实例来管理测试流程。
5. **加载测试用例:** `TestHarness` 会加载所有定义的测试用例。
6. **创建 `SingleTestRunner`:** 对于每个测试用例，`TestHarness` 会创建一个 `SingleTestRunner` 实例。
7. **执行测试:** `SingleTestRunner.run()` 方法会被调用，创建 `TestSubprocess` 来执行测试程序。
8. **收集和报告结果:** `TestSubprocess` 捕获输出，`TestRun` 及其子类解析输出并设置测试结果，最终 `JUnitLog` (如果配置) 生成 JUnit XML 报告。

**这是第2部分，共3部分，请归纳一下它的功能:**

这段代码的核心功能是**执行软件测试并生成 JUnit XML 格式的测试报告**。它通过定义不同的类来处理各种测试场景和协议，包括管理测试子进程、解析测试输出以及记录测试结果。它是 Frida 测试框架的关键组成部分，确保 Frida 功能的正确性和稳定性。这段代码的设计考虑了多种测试协议和执行环境，使其能够灵活地运行和报告各种类型的测试用例。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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