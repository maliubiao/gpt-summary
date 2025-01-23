Response:
The user wants a summary of the provided Python code. This code seems to be part of a testing framework, specifically for the Frida dynamic instrumentation tool. The request asks to identify functionalities, connections to reverse engineering, interactions with the binary level/OS/kernel, logical reasoning, user errors, and debugging steps.

Here's a plan to address the user's request:

1. **Identify the core classes and their purpose:**  Focus on `TestRun`, `TestRunExitCode`, `TestRunGTest`, `TestRunTAP`, `TestRunRust`, `SingleTestRunner`, and `TestHarness`. These appear to be the key components of the testing system.
2. **Detail the functionality of each key class:** Describe what each class does in the testing process.
3. **Connect to reverse engineering:**  Look for keywords or actions that relate to dynamic analysis, instrumentation, or interacting with running processes.
4. **Identify low-level interactions:** Pinpoint parts of the code that deal with subprocess execution, signal handling, and potentially file system interactions related to executables or libraries.
5. **Analyze logical reasoning:** Examine how test results are determined and aggregated, paying attention to conditional logic and state transitions.
6. **Consider user errors:** Think about common mistakes users might make when setting up or running tests that this code might encounter.
7. **Trace debugging steps:**  Infer how a developer might use this code to diagnose issues in the Frida tool or the tests themselves.
8. **Summarize the functionality:** Condense the findings into a concise summary.
这是Frida动态Instrumentation工具的测试框架中 `frida/releng/meson/mesonbuild/mtest.py` 文件的代码片段。 基于这段代码，我们可以归纳出以下功能：

**主要功能：生成和管理 JUnit 格式的测试报告**

这段代码的主要功能是创建一个 `JunitLog` 类，用于生成符合 JUnit XML 规范的测试报告。它记录了测试的执行状态（通过、失败、跳过、错误等）以及相关的输出（stdout 和 stderr）。

**功能分解：**

1. **`JunitLog` 类:**
   - 初始化：创建一个 JUnit XML 报告的根元素 `<testsuites>`。
   - `log_start()`:  当一个测试开始时，会根据测试是否包含子测试（使用 TAP 协议）来创建或更新 `<testsuite>` 元素。对于包含子测试的测试，会先创建一个 `<testsuite>` 元素，用于记录总体的统计信息。
   - `log_subtest()`: 当一个子测试完成时，会创建一个 `<testcase>` 元素，并将子测试的结果（跳过、错误、失败等）添加到其中。如果子测试有解释信息，也会记录在 `<system-out>` 标签中。
   - `log_test()`:  当一个不包含子测试的测试完成时，会创建一个 `<testcase>` 元素，并将测试结果添加到其中。
   - `finish()`:  在所有测试完成后，计算总体的测试统计信息，并将所有的 `<testsuite>` 元素添加到根元素 `<testsuites>` 下。最后，将生成的 XML 结构写入到指定的文件中。

2. **XML 结构生成:**
   - 代码使用 `xml.etree.ElementTree` 库来创建和操作 XML 元素。
   - 根据测试结果的不同，会在 `<testcase>` 元素下添加不同的子元素，如 `<skipped>`, `<error>`, `<failure>`。
   - 测试的 stdout 和 stderr 会被添加到 `<system-out>` 和 `<system-err>` 元素中，并会进行字符编码处理，以确保 XML 的有效性。

**与逆向方法的关联：**

虽然这段代码本身不直接执行逆向操作，但它是 Frida 测试框架的一部分，用于验证 Frida 功能的正确性。Frida 是一个用于动态分析和逆向工程的工具，因此，这个测试报告生成器记录的测试结果，最终会反映 Frida 在各种逆向场景下的表现。

**举例说明：**

假设 Frida 有一个测试用例，用于验证它是否能成功 hook 某个 Android 应用的函数，并修改其返回值。测试结果会被 `JunitLog` 记录下来。如果 hook 成功且返回值被正确修改，测试将会通过。如果 hook 失败或者返回值未被正确修改，测试将会失败，并在 JUnit 报告中标记出来，可能包含 Frida 的错误输出信息，帮助开发者定位问题。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

这段代码本身没有直接操作二进制底层、内核或框架，但它所记录的测试结果可能来源于与这些层面交互的 Frida 功能。

**举例说明：**

- **二进制底层：** Frida 可能会测试它在修改二进制代码时的正确性。如果修改后的二进制代码导致程序崩溃，测试会失败，相关信息会被记录。
- **Linux：** Frida 依赖于 Linux 的一些底层机制，例如进程间通信、内存管理等。相关的测试可能会验证 Frida 在这些方面的行为是否正确。
- **Android 内核及框架：** Frida 经常用于分析 Android 应用，它会与 Android 的 Dalvik/ART 虚拟机、Binder 机制等进行交互。相关的测试可能会验证 Frida 在 hook Java 方法、拦截 Binder 调用时的正确性。

**逻辑推理：**

代码中存在一些逻辑推理，主要是根据测试结果来判断最终的状态，并将其映射到 JUnit 的 XML 元素。

**假设输入与输出：**

假设一个名为 `test_hook_function` 的测试用例失败了，并且有 stderr 输出 "Failed to hook function X"。

**输入 (在 `log_test` 或 `log_subtest` 中):**

```python
test.res = TestResult.FAIL  # 或 subtest.result = TestResult.FAIL
test.stde = "Failed to hook function X"
test.name = "test_hook_function"
test.project = "frida_core" # 假设的 project 名称
```

**输出 (在生成的 JUnit 报告中)：**

```xml
<testsuite name="frida_core" tests="1" errors="0" failures="1" skipped="0" time="...">
  <testcase name="test_hook_function" classname="frida_core" time="...">
    <failure>
    </failure>
    <system-err>Failed to hook function X</system-err>
  </testcase>
</testsuite>
```

**涉及用户或编程常见的使用错误：**

这段代码本身不直接涉及用户操作，但它可以帮助开发者发现 Frida 内部的错误。例如，如果 Frida 在处理某些特定类型的二进制文件时出现错误，相关的测试会失败，错误信息会被记录在 JUnit 报告中。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者编写 Frida 的测试用例。** 这些测试用例会调用 Frida 的各种 API，模拟不同的逆向场景。
2. **开发者运行测试命令 (例如，使用 Meson 构建系统)。** Meson 会执行测试，并调用 `mtest.py` 中的相关代码。
3. **`mtest.py` 中的测试运行器会执行每个测试用例。**
4. **当测试用例执行完毕后，`JunitLog` 类的相应方法会被调用，记录测试结果和输出。**  例如，如果测试失败，`log_test` 或 `log_subtest` 会被调用，传递包含失败信息的 `test` 对象。
5. **最终，`finish` 方法会被调用，生成 JUnit 报告。** 开发者可以查看这个报告，了解哪些测试失败了，并查看相关的错误信息（存储在 `<system-err>` 中），从而定位 Frida 代码中的问题。

**归纳一下它的功能（第 2 部分）：**

这段代码的主要功能是 **生成详细的 JUnit 格式的测试报告**，用于记录 Frida 测试框架中每个测试用例和子测试的执行结果。它能够根据测试的状态（通过、失败、跳过、错误等）以及标准输出和标准错误，构建符合 JUnit 规范的 XML 报告，方便集成到持续集成系统和各种测试结果分析工具中。它为 Frida 开发者提供了一种标准化的方式来查看和分析测试结果，辅助他们进行调试和问题定位。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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