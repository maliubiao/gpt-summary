Response:
The user wants to understand the functionality of the provided Python code, which is a part of Frida's testing framework. I need to analyze the code and identify its core responsibilities. Specifically, I need to focus on:

1. **Core Functionality:** What does this script do?
2. **Relevance to Reverse Engineering:** Does it facilitate or interact with reverse engineering processes?
3. **Interaction with Low-Level Systems:** Does it interact with the binary level, Linux/Android kernel, or frameworks?
4. **Logical Deductions:** Are there any conditional operations where I can infer input-output relationships?
5. **Common User Errors:** What mistakes might a user make when using this script?
6. **User Journey:** How does a user's action lead to the execution of this code?
7. **Summary:**  A concise overview of the script's purpose.

Let's break down the code section by section to understand its functionality:

- **`metadata()`:**  Extracts unique test suite names from the list of tests.
- **`get_console_logger()`:** Returns a logger for console output.
- **`prepare_build()`:** Detects Ninja and exits if not found, or skips if `no_rebuild` is set.
- **`load_metadata()`:** Loads build and test data from Meson's build directory. It also checks if a rebuild is needed before loading data.
- **`load_tests()`:** Loads test definitions from a specific file.
- **`__enter__`, `__exit__`, `close_logfiles()`:**  Manages log file resources using a context manager.
- **`get_test_setup()`:** Retrieves test setup configurations.
- **`merge_setup_options()`:** Merges test setup options with command-line options.
- **`get_test_runner()`:** Creates a `SingleTestRunner` instance for a given test.
- **`process_test_result()`:** Processes the results of a test run and updates counters.
- **`numlen`, `max_left_width`, `get_test_num_prefix()`:** Helper functions for formatting test output.
- **`format()`:** Formats the output string for a test result.
- **`summary()`:** Generates a summary of the test results.
- **`total_failure_count()`:** Returns the total number of failed tests.
- **`doit()`:** The main execution method for running tests. It prepares the build, loads tests, and runs them.
- **`split_suite_string()`, `test_in_suites()`:** Helper functions for filtering tests based on suite names.
- **`test_suitable()`:** Determines if a test should be run based on include/exclude rules.
- **`tests_from_args()`:** Filters tests based on command-line arguments.
- **`get_tests()`:** Retrieves the list of tests to run.
- **`flush_logfiles()`, `open_logfiles()`:** Manages log file operations.
- **`get_wrapper()`:** Determines the command wrapper (like `gdb`).
- **`get_pretty_suite()`:**  Formats the test suite name for display.
- **`run_tests()`:** Orchestrates the execution of tests using asyncio.
- **`log_subtest()`, `log_start_test()`:** Methods for logging test events.
- **`_run_tests()`:** An asynchronous function to run tests concurrently. It handles signals (SIGINT, SIGTERM) for interrupting tests.
- **`list_tests()`:** Lists available tests.
- **`rebuild_deps()`:** Rebuilds necessary dependencies before running tests using Ninja.
- **`run()`:** The main function to parse arguments and initiate the test run.
- **`run_with_args()`:**  A wrapper to call `run` with a list of arguments.

**Overall Functionality:** This script is responsible for discovering, managing, and running tests within a Meson build environment for Frida. It handles test filtering, dependency rebuilding, result processing, and output formatting.

Now, let's address the specific points in the prompt.
好的，根据您提供的代码片段，这是 Frida 动态Instrumentation 工具中负责执行测试的 Python 脚本 `mtest.py` 的第三部分。在前两部分的基础上，我们可以归纳一下它的主要功能：

**核心功能归纳：**

这个脚本的主要功能是**执行和管理 Frida 项目的测试**。它提供了一套完整的机制来加载测试用例、配置测试环境、并行运行测试、收集测试结果并生成报告。具体来说，它负责：

1. **测试发现与加载:**  从 `meson-private/meson_test_setup.dat` 或 `meson_benchmark_setup.dat` 文件中加载测试用例的元数据，包括测试名称、所属套件、依赖关系、环境变量等。
2. **测试过滤:**  根据用户提供的命令行参数（如包含或排除的测试套件名称、特定的测试名称），以及测试本身的属性（如是否需要执行器包装器），来筛选需要执行的测试用例。
3. **构建准备 (可选):**  如果用户没有指定 `--no-rebuild`，脚本会尝试检测 `ninja` 构建工具，并在运行测试前，根据测试用例的依赖关系，使用 `ninja` 重新构建相关的目标文件。
4. **测试环境配置:**  合并命令行选项和测试用例的配置信息，包括是否使用 `gdb` 调试、超时时间倍率、执行器包装器等，并构建测试用例运行时的环境变量。
5. **测试执行:**  创建 `SingleTestRunner` 实例来执行单个测试用例。支持并行执行测试，通过 `asyncio` 模块实现并发控制。
6. **结果收集与处理:**  收集每个测试用例的运行结果（成功、失败、跳过、超时等），并更新相应的计数器。
7. **日志记录:**  将测试结果记录到不同的日志文件中，例如 JUnit XML、JSON 和文本格式，方便后续分析和报告生成。
8. **输出格式化:**  将测试运行的进度和结果以友好的格式输出到控制台。
9. **信号处理:**  监听 `SIGINT` (Ctrl+C) 和 `SIGTERM` 信号，允许用户中断测试执行。
10. **测试报告汇总:**  在测试结束后，输出测试结果的汇总信息，包括成功、失败、跳过、超时的用例数量。
11. **支持多种测试套件:** 允许测试用例组织在不同的套件中，方便按功能模块或组件进行测试。

**与逆向方法的关联及举例说明：**

Frida 本身是一个动态 Instrumentation 工具，常用于逆向工程、安全研究和动态分析。`mtest.py` 作为其测试框架的一部分，确保 Frida 的各种功能（包括用于逆向的方法）能够正常工作。

* **例子：测试代码注入功能:** 假设 Frida 有一个测试用例用于验证其代码注入功能是否正常工作。这个测试用例可能会创建一个目标进程，然后使用 Frida 的 API 将一段代码注入到该进程中，并验证注入的代码是否按预期执行。`mtest.py` 负责执行这个测试用例，如果测试失败，就表明 Frida 的代码注入功能可能存在问题，这直接关系到逆向工程师能否成功地将自己的代码注入到目标进程进行分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

Frida 的很多功能都涉及到与操作系统底层交互，因此其测试也必然会涉及到这些知识。

* **二进制底层:**
    * **例子：测试内存读写功能:** Frida 允许读取和修改目标进程的内存。测试用例可能会验证 Frida 是否能够正确地读取指定地址的内存值，或者成功地将新的值写入到指定的内存地址。这直接涉及到对进程内存布局和二进制数据结构的理解。
* **Linux 内核:**
    * **例子：测试系统调用Hook功能:** Frida 能够 Hook 系统调用。测试用例可能会验证 Frida 是否能够成功地 Hook 某个特定的系统调用，并在系统调用发生时执行自定义的代码。这需要理解 Linux 内核的系统调用机制。
* **Android 内核及框架:**
    * **例子：测试 ART (Android Runtime) Hook 功能:** Frida 可以在 Android 平台上 Hook ART 虚拟机中的方法。测试用例可能会验证 Frida 是否能够成功地 Hook Android 应用中的 Java 方法，并修改方法的行为。这需要对 Android 运行时环境和 Dalvik/ART 虚拟机有一定的了解。

**逻辑推理、假设输入与输出：**

脚本中存在一些逻辑判断，我们可以通过假设输入来推断输出。

* **假设输入:** 用户在命令行中运行 `meson test --include-suites core`。
* **逻辑推理:** `TestHarness.test_suitable()` 方法会检查每个测试用例是否属于 `core` 套件。只有属于 `core` 套件的测试用例才会返回 `True` 并被执行。
* **预期输出:**  只有标记为属于 `core` 套件的测试用例会被执行。控制台输出会显示这些测试用例的执行进度和结果。

* **假设输入:** 用户在命令行中运行 `meson test my_test_case`，并且存在一个名为 `my_test_case` 的测试用例。
* **逻辑推理:** `TestHarness.tests_from_args()` 方法会将命令行参数 `my_test_case` 与已加载的测试用例名称进行匹配。
* **预期输出:**  只有名为 `my_test_case` 的测试用例会被执行。

**涉及用户或编程常见的使用错误及举例说明：**

用户在使用 `meson test` 命令时可能会犯一些错误，脚本在一定程度上会进行检查和提示。

* **例子：指定了不存在的测试套件:** 用户运行 `meson test --include-suites non_existent_suite`，但实际上没有名为 `non_existent_suite` 的测试套件。
    * **脚本行为:** `TestHarness.test_in_suites()` 将不会找到匹配的套件，因此不会有任何测试被选中执行，可能会在控制台输出 "No suitable tests defined." 或者在 `tests_from_args` 中抛出 `MesonException`。
* **例子：同时指定了 `--wrapper` 和 `--gdb`:**  用户尝试同时使用自定义的包装器和 `gdb` 调试。
    * **脚本行为:** `run()` 函数中会检查这种情况，并打印错误消息 "Must not specify both a wrapper and gdb at the same time." 并返回错误码。
* **例子：指定了不存在的测试名称:** 用户运行 `meson test unknown_test`，但实际上没有名为 `unknown_test` 的测试用例。
    * **脚本行为:** `TestHarness.tests_from_args()` 会检测到该模式没有匹配到任何测试，并抛出 `MesonException`，提示 "unknown_test test name does not match any test"。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在 Frida 项目的构建目录下打开终端。**
2. **用户输入命令 `meson test [options]` 并按下回车键。** 这里的 `[options]` 可以是各种命令行参数，例如 `--verbose`, `--list`, `--suite`, 或具体的测试用例名称等。
3. **Meson 构建系统会解析用户的命令。**
4. **如果命令是 `meson test`，Meson 会调用 `mesonbuild/mtest.py` 脚本。**
5. **`mtest.py` 脚本开始执行，首先会解析命令行参数。**
6. **脚本会尝试加载构建元数据和测试用例信息。**
7. **根据用户提供的选项和测试用例的元数据，脚本会确定需要执行哪些测试。**
8. **如果需要，脚本会先尝试重新构建相关的依赖项。**
9. **脚本会创建测试运行器并开始执行测试。**
10. **在测试执行过程中，脚本会将测试结果输出到控制台，并记录到日志文件中。**
11. **测试执行完成后，脚本会输出测试结果的汇总信息。**

作为调试线索，如果用户报告测试执行有问题，可以：

* **检查用户提供的命令行参数是否正确。**
* **查看日志文件，获取更详细的测试执行信息。**
* **如果涉及到特定的测试用例，可以单独运行该测试用例进行调试。**
* **使用 `--verbose` 选项获取更详细的输出信息。**
* **如果怀疑是构建问题，可以尝试手动重新构建。**

总而言之，`mtest.py` 脚本是 Frida 测试流程的核心组成部分，它通过自动化测试来确保 Frida 作为一个动态 Instrumentation 工具的稳定性和可靠性，这对于依赖 Frida 进行逆向工程、安全研究等工作的用户来说至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
metadata()

        ss = set()
        for t in self.tests:
            for s in t.suite:
                ss.add(s)
        self.suites = list(ss)

    def get_console_logger(self) -> 'ConsoleLogger':
        assert self.console_logger
        return self.console_logger

    def prepare_build(self) -> None:
        if self.options.no_rebuild:
            return

        self.ninja = environment.detect_ninja()
        if not self.ninja:
            print("Can't find ninja, can't rebuild test.")
            # If ninja can't be found return exit code 127, indicating command
            # not found for shell, which seems appropriate here. This works
            # nicely for `git bisect run`, telling it to abort - no point in
            # continuing if there's no ninja.
            sys.exit(127)

    def load_metadata(self) -> None:
        startdir = os.getcwd()
        try:
            os.chdir(self.options.wd)

            # Before loading build / test data, make sure that the build
            # configuration does not need to be regenerated. This needs to
            # happen before rebuild_deps(), because we need the correct list of
            # tests and their dependencies to compute
            if not self.options.no_rebuild:
                teststdo = subprocess.run(self.ninja + ['-n', 'build.ninja'], capture_output=True).stdout
                if b'ninja: no work to do.' not in teststdo and b'samu: nothing to do' not in teststdo:
                    stdo = sys.stderr if self.options.list else sys.stdout
                    ret = subprocess.run(self.ninja + ['build.ninja'], stdout=stdo.fileno())
                    if ret.returncode != 0:
                        raise TestException(f'Could not configure {self.options.wd!r}')

            self.build_data = build.load(os.getcwd())
            if not self.options.setup:
                self.options.setup = self.build_data.test_setup_default_name
            if self.options.benchmark:
                self.tests = self.load_tests('meson_benchmark_setup.dat')
            else:
                self.tests = self.load_tests('meson_test_setup.dat')
        finally:
            os.chdir(startdir)

    def load_tests(self, file_name: str) -> T.List[TestSerialisation]:
        datafile = Path('meson-private') / file_name
        if not datafile.is_file():
            raise TestException(f'Directory {self.options.wd!r} does not seem to be a Meson build directory.')
        with datafile.open('rb') as f:
            objs = check_testdata(pickle.load(f))
        return objs

    def __enter__(self) -> 'TestHarness':
        return self

    def __exit__(self, exc_type: T.Any, exc_value: T.Any, traceback: T.Any) -> None:
        self.close_logfiles()

    def close_logfiles(self) -> None:
        for l in self.loggers:
            l.close()
        self.console_logger = None

    def get_test_setup(self, test: T.Optional[TestSerialisation]) -> build.TestSetup:
        if ':' in self.options.setup:
            if self.options.setup not in self.build_data.test_setups:
                sys.exit(f"Unknown test setup '{self.options.setup}'.")
            return self.build_data.test_setups[self.options.setup]
        else:
            full_name = test.project_name + ":" + self.options.setup
            if full_name not in self.build_data.test_setups:
                sys.exit(f"Test setup '{self.options.setup}' not found from project '{test.project_name}'.")
            return self.build_data.test_setups[full_name]

    def merge_setup_options(self, options: argparse.Namespace, test: TestSerialisation) -> T.Dict[str, str]:
        current = self.get_test_setup(test)
        if not options.gdb:
            options.gdb = current.gdb
        if options.gdb:
            options.verbose = True
        if options.timeout_multiplier is None:
            options.timeout_multiplier = current.timeout_multiplier
    #    if options.env is None:
    #        options.env = current.env # FIXME, should probably merge options here.
        if options.wrapper is None:
            options.wrapper = current.exe_wrapper
        elif current.exe_wrapper:
            sys.exit('Conflict: both test setup and command line specify an exe wrapper.')
        return current.env.get_env(os.environ.copy())

    def get_test_runner(self, test: TestSerialisation) -> SingleTestRunner:
        name = self.get_pretty_suite(test)
        options = deepcopy(self.options)
        if self.options.setup:
            env = self.merge_setup_options(options, test)
        else:
            env = os.environ.copy()
        test_env = test.env.get_env(env)
        env.update(test_env)
        if (test.is_cross_built and test.needs_exe_wrapper and
                test.exe_wrapper and test.exe_wrapper.found()):
            env['MESON_EXE_WRAPPER'] = join_args(test.exe_wrapper.get_command())
        return SingleTestRunner(test, env, name, options)

    def process_test_result(self, result: TestRun) -> None:
        if result.res is TestResult.TIMEOUT:
            self.timeout_count += 1
        elif result.res is TestResult.SKIP:
            self.skip_count += 1
        elif result.res is TestResult.OK:
            self.success_count += 1
        elif result.res in {TestResult.FAIL, TestResult.ERROR, TestResult.INTERRUPT}:
            self.fail_count += 1
        elif result.res is TestResult.EXPECTEDFAIL:
            self.expectedfail_count += 1
        elif result.res is TestResult.UNEXPECTEDPASS:
            self.unexpectedpass_count += 1
        else:
            sys.exit(f'Unknown test result encountered: {result.res}')

        if result.res.is_bad():
            self.collected_failures.append(result)
        for l in self.loggers:
            l.log(self, result)

    @property
    def numlen(self) -> int:
        return len(str(self.test_count))

    @property
    def max_left_width(self) -> int:
        return 2 * self.numlen + 2

    def get_test_num_prefix(self, num: int) -> str:
        return '{num:{numlen}}/{testcount} '.format(numlen=self.numlen,
                                                    num=num,
                                                    testcount=self.test_count)

    def format(self, result: TestRun, colorize: bool,
               max_left_width: int = 0,
               prefix: str = '',
               left: T.Optional[str] = None,
               middle: T.Optional[str] = None,
               right: T.Optional[str] = None) -> str:
        if left is None:
            left = self.get_test_num_prefix(result.num)

        # A non-default max_left_width lets the logger print more stuff before the
        # name, while ensuring that the rightmost columns remain aligned.
        max_left_width = max(max_left_width, self.max_left_width)

        if middle is None:
            middle = result.name
        extra_mid_width = max_left_width + self.name_max_len + 1 - uniwidth(middle) - uniwidth(left) - uniwidth(prefix)
        middle += ' ' * max(1, extra_mid_width)

        if right is None:
            right = '{res} {dur:{durlen}.2f}s'.format(
                res=result.res.get_text(colorize),
                dur=result.duration,
                durlen=self.duration_max_len + 3)
            details = result.get_details()
            if details:
                right += '   ' + details
        return prefix + left + middle + right

    def summary(self) -> str:
        return textwrap.dedent('''
            Ok:                 {:<4}
            Expected Fail:      {:<4}
            Fail:               {:<4}
            Unexpected Pass:    {:<4}
            Skipped:            {:<4}
            Timeout:            {:<4}
            ''').format(self.success_count, self.expectedfail_count, self.fail_count,
                        self.unexpectedpass_count, self.skip_count, self.timeout_count)

    def total_failure_count(self) -> int:
        return self.fail_count + self.unexpectedpass_count + self.timeout_count

    def doit(self) -> int:
        if self.is_run:
            raise RuntimeError('Test harness object can only be used once.')
        self.is_run = True
        tests = self.get_tests()
        if not tests:
            return 0
        if not self.options.no_rebuild and not rebuild_deps(self.ninja, self.options.wd, tests):
            # We return 125 here in case the build failed.
            # The reason is that exit code 125 tells `git bisect run` that the current
            # commit should be skipped.  Thus users can directly use `meson test` to
            # bisect without needing to handle the does-not-build case separately in a
            # wrapper script.
            sys.exit(125)

        self.name_max_len = max(uniwidth(self.get_pretty_suite(test)) for test in tests)
        self.options.num_processes = min(self.options.num_processes,
                                         len(tests) * self.options.repeat)
        startdir = os.getcwd()
        try:
            os.chdir(self.options.wd)
            runners: T.List[SingleTestRunner] = []
            for i in range(self.options.repeat):
                runners.extend(self.get_test_runner(test) for test in tests)
                if i == 0:
                    self.duration_max_len = max(len(str(int(runner.timeout or 99)))
                                                for runner in runners)
                    # Disable the progress report if it gets in the way
                    self.need_console = any(runner.console_mode is not ConsoleUser.LOGGER
                                            for runner in runners)

            self.test_count = len(runners)
            self.run_tests(runners)
        finally:
            os.chdir(startdir)
        return self.total_failure_count()

    @staticmethod
    def split_suite_string(suite: str) -> T.Tuple[str, str]:
        if ':' in suite:
            split = suite.split(':', 1)
            assert len(split) == 2
            return split[0], split[1]
        else:
            return suite, ""

    @staticmethod
    def test_in_suites(test: TestSerialisation, suites: T.List[str]) -> bool:
        for suite in suites:
            (prj_match, st_match) = TestHarness.split_suite_string(suite)
            for prjst in test.suite:
                (prj, st) = TestHarness.split_suite_string(prjst)

                # the SUITE can be passed as
                #     suite_name
                # or
                #     project_name:suite_name
                # so we need to select only the test belonging to project_name

                # this if handle the first case (i.e., SUITE == suite_name)

                # in this way we can run tests belonging to different
                # (sub)projects which share the same suite_name
                if not st_match and st == prj_match:
                    return True

                # these two conditions are needed to handle the second option
                # i.e., SUITE == project_name:suite_name

                # in this way we select the only the tests of
                # project_name with suite_name
                if prj_match and prj != prj_match:
                    continue
                if st_match and st != st_match:
                    continue
                return True
        return False

    def test_suitable(self, test: TestSerialisation) -> bool:
        if TestHarness.test_in_suites(test, self.options.exclude_suites):
            return False

        if self.options.include_suites:
            # Both force inclusion (overriding add_test_setup) and exclude
            # everything else
            return TestHarness.test_in_suites(test, self.options.include_suites)

        if self.options.setup:
            setup = self.get_test_setup(test)
            if TestHarness.test_in_suites(test, setup.exclude_suites):
                return False

        return True

    def tests_from_args(self, tests: T.List[TestSerialisation]) -> T.Generator[TestSerialisation, None, None]:
        '''
        Allow specifying test names like "meson test foo1 foo2", where test('foo1', ...)

        Also support specifying the subproject to run tests from like
        "meson test subproj:" (all tests inside subproj) or "meson test subproj:foo1"
        to run foo1 inside subproj. Coincidentally also "meson test :foo1" to
        run all tests with that name across all subprojects, which is
        identical to "meson test foo1"
        '''
        patterns: T.Dict[T.Tuple[str, str], bool] = {}
        for arg in self.options.args:
            # Replace empty components by wildcards:
            # '' -> '*:*'
            # 'name' -> '*:name'
            # ':name' -> '*:name'
            # 'proj:' -> 'proj:*'
            if ':' in arg:
                subproj, name = arg.split(':', maxsplit=1)
                if name == '':
                    name = '*'
                if subproj == '':  # in case arg was ':'
                    subproj = '*'
            else:
                subproj, name = '*', arg
            patterns[(subproj, name)] = False

        for t in tests:
            # For each test, find the first matching pattern
            # and mark it as used. yield the matching tests.
            for subproj, name in list(patterns):
                if fnmatch(t.project_name, subproj) and fnmatch(t.name, name):
                    patterns[(subproj, name)] = True
                    yield t
                    break

        for (subproj, name), was_used in patterns.items():
            if not was_used:
                # For each unused pattern...
                arg = f'{subproj}:{name}'
                for t in tests:
                    # ... if it matches a test, then it wasn't used because another
                    # pattern matched the same test before.
                    # Report it as a warning.
                    if fnmatch(t.project_name, subproj) and fnmatch(t.name, name):
                        mlog.warning(f'{arg} test name is redundant and was not used')
                        break
                else:
                    # If the pattern doesn't match any test,
                    # report it as an error. We don't want the `test` command to
                    # succeed on an invalid pattern.
                    raise MesonException(f'{arg} test name does not match any test')

    def get_tests(self, errorfile: T.Optional[T.IO] = None) -> T.List[TestSerialisation]:
        if not self.tests:
            print('No tests defined.', file=errorfile)
            return []

        tests = [t for t in self.tests if self.test_suitable(t)]
        if self.options.args:
            tests = list(self.tests_from_args(tests))

        if not tests:
            print('No suitable tests defined.', file=errorfile)
            return []

        return tests

    def flush_logfiles(self) -> None:
        for l in self.loggers:
            l.flush()

    def open_logfiles(self) -> None:
        if not self.logfile_base:
            return

        self.loggers.append(JunitBuilder(self.logfile_base + '.junit.xml'))
        self.loggers.append(JsonLogfileBuilder(self.logfile_base + '.json'))
        self.loggers.append(TextLogfileBuilder(self.logfile_base + '.txt', errors='surrogateescape'))

    @staticmethod
    def get_wrapper(options: argparse.Namespace) -> T.List[str]:
        wrap: T.List[str] = []
        if options.gdb:
            wrap = [options.gdb_path, '--quiet']
            if options.repeat > 1:
                wrap += ['-ex', 'run', '-ex', 'quit']
            # Signal the end of arguments to gdb
            wrap += ['--args']
        if options.wrapper:
            wrap += options.wrapper
        return wrap

    def get_pretty_suite(self, test: TestSerialisation) -> str:
        if len(self.suites) > 1 and test.suite:
            rv = TestHarness.split_suite_string(test.suite[0])[0]
            s = "+".join(TestHarness.split_suite_string(s)[1] for s in test.suite)
            if s:
                rv += ":"
            return rv + s + " / " + test.name
        else:
            return test.name

    def run_tests(self, runners: T.List[SingleTestRunner]) -> None:
        try:
            self.open_logfiles()

            # TODO: this is the default for python 3.8
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

            asyncio.run(self._run_tests(runners))
        finally:
            self.close_logfiles()

    def log_subtest(self, test: TestRun, s: str, res: TestResult) -> None:
        for l in self.loggers:
            l.log_subtest(self, test, s, res)

    def log_start_test(self, test: TestRun) -> None:
        for l in self.loggers:
            l.start_test(self, test)

    async def _run_tests(self, runners: T.List[SingleTestRunner]) -> None:
        semaphore = asyncio.Semaphore(self.options.num_processes)
        futures: T.Deque[asyncio.Future] = deque()
        running_tests: T.Dict[asyncio.Future, str] = {}
        interrupted = False
        ctrlc_times: T.Deque[float] = deque(maxlen=MAX_CTRLC)
        loop = asyncio.get_running_loop()

        async def run_test(test: SingleTestRunner) -> None:
            async with semaphore:
                if interrupted or (self.options.repeat > 1 and self.fail_count):
                    return
                res = await test.run(self)
                self.process_test_result(res)
                maxfail = self.options.maxfail
                if maxfail and self.fail_count >= maxfail and res.res.is_bad():
                    cancel_all_tests()

        def test_done(f: asyncio.Future) -> None:
            if not f.cancelled():
                f.result()
            futures.remove(f)
            try:
                del running_tests[f]
            except KeyError:
                pass

        def cancel_one_test(warn: bool) -> None:
            future = futures.popleft()
            futures.append(future)
            if warn:
                self.flush_logfiles()
                mlog.warning('CTRL-C detected, interrupting {}'.format(running_tests[future]))
            del running_tests[future]
            future.cancel()

        def cancel_all_tests() -> None:
            nonlocal interrupted
            interrupted = True
            while running_tests:
                cancel_one_test(False)

        def sigterm_handler() -> None:
            if interrupted:
                return
            self.flush_logfiles()
            mlog.warning('Received SIGTERM, exiting')
            cancel_all_tests()

        def sigint_handler() -> None:
            # We always pick the longest-running future that has not been cancelled
            # If all the tests have been CTRL-C'ed, just stop
            nonlocal interrupted
            if interrupted:
                return
            ctrlc_times.append(loop.time())
            if len(ctrlc_times) == MAX_CTRLC and ctrlc_times[-1] - ctrlc_times[0] < 1:
                self.flush_logfiles()
                mlog.warning('CTRL-C detected, exiting')
                cancel_all_tests()
            elif running_tests:
                cancel_one_test(True)
            else:
                self.flush_logfiles()
                mlog.warning('CTRL-C detected, exiting')
                interrupted = True

        for l in self.loggers:
            l.start(self)

        if sys.platform != 'win32':
            if os.getpgid(0) == os.getpid():
                loop.add_signal_handler(signal.SIGINT, sigint_handler)
            else:
                loop.add_signal_handler(signal.SIGINT, sigterm_handler)
            loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
        try:
            for runner in runners:
                if not runner.is_parallel:
                    await complete_all(futures)
                future = asyncio.ensure_future(run_test(runner))
                futures.append(future)
                running_tests[future] = runner.visible_name
                future.add_done_callback(test_done)
                if not runner.is_parallel:
                    await complete(future)
                if self.options.repeat > 1 and self.fail_count:
                    break

            await complete_all(futures)
        finally:
            if sys.platform != 'win32':
                loop.remove_signal_handler(signal.SIGINT)
                loop.remove_signal_handler(signal.SIGTERM)
            for l in self.loggers:
                await l.finish(self)

def list_tests(th: TestHarness) -> bool:
    tests = th.get_tests(errorfile=sys.stderr)
    for t in tests:
        print(th.get_pretty_suite(t))
    return not tests

def rebuild_deps(ninja: T.List[str], wd: str, tests: T.List[TestSerialisation]) -> bool:
    def convert_path_to_target(path: str) -> str:
        path = os.path.relpath(path, wd)
        if os.sep != '/':
            path = path.replace(os.sep, '/')
        return path

    assert len(ninja) > 0

    depends: T.Set[str] = set()
    targets: T.Set[str] = set()
    intro_targets: T.Dict[str, T.List[str]] = {}
    for target in load_info_file(get_infodir(wd), kind='targets'):
        intro_targets[target['id']] = [
            convert_path_to_target(f)
            for f in target['filename']]
    for t in tests:
        for d in t.depends:
            if d in depends:
                continue
            depends.update(d)
            targets.update(intro_targets[d])

    ret = subprocess.run(ninja + ['-C', wd] + sorted(targets)).returncode
    if ret != 0:
        print(f'Could not rebuild {wd}')
        return False

    return True

def run(options: argparse.Namespace) -> int:
    if options.benchmark:
        options.num_processes = 1

    if options.verbose and options.quiet:
        print('Can not be both quiet and verbose at the same time.')
        return 1

    check_bin = None
    if options.gdb:
        options.verbose = True
        if options.wrapper:
            print('Must not specify both a wrapper and gdb at the same time.')
            return 1
        check_bin = 'gdb'

    if options.wrapper:
        check_bin = options.wrapper[0]

    if check_bin is not None:
        exe = ExternalProgram(check_bin, silent=True)
        if not exe.found():
            print(f'Could not find requested program: {check_bin!r}')
            return 1

    b = build.load(options.wd)
    need_vsenv = T.cast('bool', b.environment.coredata.get_option(OptionKey('vsenv')))
    setup_vsenv(need_vsenv)

    if not options.no_rebuild:
        backend = b.environment.coredata.get_option(OptionKey('backend'))
        if backend == 'none':
            # nothing to build...
            options.no_rebuild = True
        elif backend != 'ninja':
            print('Only ninja backend is supported to rebuild tests before running them.')
            # Disable, no point in trying to build anything later
            options.no_rebuild = True

    with TestHarness(options) as th:
        try:
            if options.list:
                return list_tests(th)
            return th.doit()
        except TestException as e:
            print('Meson test encountered an error:\n')
            if os.environ.get('MESON_FORCE_BACKTRACE'):
                raise e
            else:
                print(e)
            return 1

def run_with_args(args: T.List[str]) -> int:
    parser = argparse.ArgumentParser(prog='meson test')
    add_arguments(parser)
    options = parser.parse_args(args)
    return run(options)
```