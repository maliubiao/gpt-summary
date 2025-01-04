Response:
The user wants a summary of the functionalities of the provided Python code snippet. I need to identify the core responsibilities of this code, paying special attention to aspects related to reverse engineering, binary analysis, operating system specifics (Linux, Android kernel/framework), logical reasoning, common user errors, and debugging workflows.

**Plan:**

1. **Identify the main classes and their purposes:**  `JUnitLog`, `TestRun`, `TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`, `TestSubprocess`, `SingleTestRunner`, `TestHarness`.
2. **Analyze the methods within each class:**  Focus on how they contribute to the overall testing process.
3. **Connect the functionalities to the requested aspects:**
    *   **Reverse Engineering:** Look for interactions with binaries, potentially through debugging or analysis.
    *   **Binary/Low-level:** Identify operations involving process execution, return codes, and memory management hints (like `MALLOC_PERTURB_`).
    *   **Linux/Android Kernel/Framework:**  Note system calls, signal handling, and mentions of Android (though not explicitly present in this snippet).
    *   **Logical Reasoning:** Examine conditional logic, especially around test outcomes and error handling.
    *   **User Errors:** Consider common mistakes users might make when configuring or running tests.
    *   **Debugging:** Identify elements facilitating debugging, such as GDB integration and logging.
    *   **User Operation Flow:** Infer how a user's actions might lead to the execution of this code.

**High-level Functionality Summary:**

The code appears to be a core component of a testing framework. It defines how individual tests are executed, their results are processed and reported, and how the overall testing process is managed. It supports various test protocols (ExitCode, GTest, TAP, Rust) and provides features for logging, timeout handling, and integration with debuggers like GDB.
这是 Frdia 动态 instrumentation tool 测试框架的一部分，专注于处理和报告测试结果，特别是以 JUnit XML 格式输出。

**功能归纳:**

1. **JUnit XML 报告生成:**  该部分代码的主要功能是生成符合 JUnit XML 格式的测试报告。它定义了一个 `JUnitLog` 类，负责将测试结果组织成 XML 结构，方便持续集成工具（如 GitLab）解析和展示。

2. **测试结果聚合和组织:** `JUnitLog` 类维护一个 `suites` 字典，用于按项目（或测试套件）组织测试用例。它将单个测试用例的结果（成功、失败、跳过等）添加到相应的 `<testcase>` 元素中。

3. **详细结果记录:**  对于每个测试用例，代码会记录其名称 (`name`)、所属类名 (`classname`)、执行时间 (`time`) 以及详细的结果状态（`skipped`, `error`, `failure`, `unexpectedpass`, `interrupt`, `timeout`）。

4. **标准输出和标准错误捕获:**  代码能够捕获并记录每个测试用例的标准输出 (`system-out`) 和标准错误 (`system-err`) 流，这对于调试失败的测试非常有用。

5. **子测试支持:**  代码能够处理包含子测试的测试用例（例如，TAP 协议的测试），并将每个子测试的结果作为独立的 `<testcase>` 记录在 JUnit 报告中。

6. **汇总统计:**  `JUnitLog` 在报告的根元素 `<testsuites>` 中汇总了测试的总数 (`tests`)、错误数 (`errors`)、失败数 (`failures`) 和跳过数 (`skipped`)。

**与逆向方法的关联和举例:**

虽然这段代码本身不直接进行逆向操作，但它作为 Frida 测试框架的一部分，其测试对象很可能涉及到逆向相关的工具或技术。

*   **举例:** 假设 Frida 的一个测试用例是检查某个 hook 是否成功修改了目标进程的函数行为。该测试用例的执行结果（成功或失败）会被 `mtest.py` 中的 `JUnitLog` 类记录下来，最终生成 JUnit 报告。如果测试失败，报告会包含相关的标准输出/错误信息，帮助开发者定位问题，例如 hook 代码的错误或者目标进程行为的异常。

**涉及二进制底层、Linux、Android 内核及框架的知识和举例:**

这段代码间接涉及到这些知识，因为它处理的是测试结果，而这些测试很可能与底层操作相关。

*   **二进制底层:**  测试用例可能执行一些涉及到二进制文件解析、代码注入或者内存操作的 Frida 功能。测试的结果反映了这些底层操作是否成功。例如，一个测试用例可能检查 Frida 是否能成功 hook 一个特定偏移地址的指令。
*   **Linux:**  在 Linux 环境下运行 Frida 测试，涉及到进程的创建、信号处理、管道操作等 Linux 系统调用。测试框架需要管理这些进程的生命周期，并捕获其输出。例如，代码中 `os.killpg` 用于杀死进程组，这是一个 Linux 特有的操作。
*   **Android 内核及框架:** 虽然这段代码没有直接提及 Android 特定的 API，但 Frida 常用于 Android 平台进行动态分析。测试用例可能涉及到 hook Android 系统服务、修改 ART 虚拟机行为等。测试结果会通过 `mtest.py` 生成报告。

**逻辑推理的假设输入与输出:**

假设有一个名为 "MyProject" 的测试套件，其中包含两个测试用例：`test_feature_a` 和 `test_feature_b`。

*   **假设输入:**
    *   `test_feature_a` 执行成功，duration 为 0.5 秒。
    *   `test_feature_b` 执行失败，duration 为 1.2 秒，标准错误输出为 "Segmentation fault"。
*   **预期输出 (部分 JUnit XML):**

```xml
<testsuites errors="0" failures="1" tests="2">
  <testsuite errors="0" failures="1" name="MyProject" tests="2" time="1.7">
    <testcase classname="MyProject" name="test_feature_a" time="0.5"/>
    <testcase classname="MyProject" name="test_feature_b" time="1.2">
      <failure>
      </failure>
      <system-err>Segmentation fault</system-err>
    </testcase>
  </testsuite>
</testsuites>
```

**涉及用户或编程常见的使用错误和举例:**

*   **错误的 JUnit 文件名:** 用户在配置测试框架时，可能会错误地指定 JUnit 报告的输出文件名或路径，导致报告无法正确生成或存储。
*   **XML 编码问题:**  如果测试输出包含无法编码为 UTF-8 的字符，`replace_unencodable_xml_chars` 函数会尝试替换，但如果替换逻辑不完善，可能会导致报告显示异常或者解析错误。
*   **测试用例命名不规范:**  如果测试用例的名称或类名包含 XML 不允许的字符，可能会导致 JUnit 报告格式错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 测试用例:** 开发者会编写 Python 或其他语言的测试代码，这些测试代码会调用 Frida 的 API 来进行动态 instrumentation 操作。
2. **用户配置 Meson 构建系统:** Frida 使用 Meson 作为其构建系统。用户需要在 `meson.build` 文件中配置测试用例，并指定使用 `mtest.py` 来运行和报告测试结果。
3. **用户运行测试命令:** 用户在命令行执行类似 `meson test` 或 `ninja test` 的命令来启动测试。
4. **Meson 调用 `mtest.py`:** Meson 会解析构建配置，并调用 `frida/subprojects/frida-core/releng/meson/mesonbuild/mtest.py` 脚本来执行配置的测试用例。
5. **测试执行和结果收集:** `mtest.py` 会启动各个测试进程，收集它们的输出和返回码。
6. **`JUnitLog` 处理测试结果:** 在测试结束后，`mtest.py` 中的 `JUnitLog` 类会被用来格式化测试结果，并将标准输出和标准错误等信息组织到 JUnit XML 报告中。
7. **生成 JUnit XML 文件:**  最终，`JUnitLog.finish()` 方法会将构建好的 XML 树写入到指定的文件中。

**总结其功能:**

总而言之，`frida/subprojects/frida-core/releng/meson/mesonbuild/mtest.py` 的这部分代码专注于将 Frida 测试框架的测试结果转换成标准的 JUnit XML 报告。这使得 Frida 的测试结果可以被各种持续集成工具方便地集成和分析，为开发者提供清晰的测试状态和失败信息，从而提高开发效率和代码质量。它通过结构化的 XML 格式，详细记录了每个测试用例的执行状态、耗时以及输出信息，为问题排查提供了重要的线索。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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