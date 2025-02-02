Response:
The user wants a summary of the functionality of the Python code provided, which is the third part of a larger code snippet. I need to analyze the code, focusing on the methods defined within the `TestHarness` class and the `rebuild_deps` and `run` functions. I should identify the core purpose of each function and how they contribute to the overall testing process. Specifically, I need to look for connections to reverse engineering, low-level details (binary, kernel, frameworks), logical reasoning, common user errors, and how a user might reach this part of the code.

**Plan:**

1. **Analyze `TestHarness` methods:**
   - `metadata()`:  Identifies unique test suites.
   - `get_console_logger()`: Returns the console logger instance.
   - `prepare_build()`: Checks for and verifies the presence of `ninja` for rebuilding.
   - `load_metadata()`: Loads build and test metadata, handling potential rebuilds.
   - `load_tests()`: Loads test definitions from a file.
   - `__enter__`, `__exit__`, `close_logfiles()`: Manage log file lifecycle.
   - `get_test_setup()`: Retrieves test setup configurations.
   - `merge_setup_options()`: Merges command-line options with test setup options.
   - `get_test_runner()`: Creates a `SingleTestRunner` instance for a given test.
   - `process_test_result()`: Processes and logs the results of a test run.
   - `numlen`, `max_left_width`, `get_test_num_prefix()`: Helper methods for formatting output.
   - `format()`: Formats the test result output string.
   - `summary()`: Generates a summary of the test run.
   - `total_failure_count()`: Calculates the total number of failures.
   - `doit()`: Orchestrates the entire testing process.
   - `split_suite_string()`, `test_in_suites()`, `test_suitable()`: Helper methods for filtering tests.
   - `tests_from_args()`: Filters tests based on command-line arguments.
   - `get_tests()`: Retrieves the final list of tests to run.
   - `flush_logfiles()`, `open_logfiles()`: Manage log file handling.
   - `get_wrapper()`: Determines the execution wrapper (e.g., gdb).
   - `get_pretty_suite()`: Generates a user-friendly test suite name.
   - `run_tests()`, `_run_tests()`: Asynchronously executes the tests.
   - `log_subtest()`, `log_start_test()`: Log individual test events.

2. **Analyze `rebuild_deps()` function:**  Identifies and rebuilds dependencies for tests.

3. **Analyze `run()` function:**  Parses arguments, loads build data, and runs the tests using `TestHarness`.

4. **Analyze `list_tests()` function:** Lists the available tests.

5. **Identify connections to reverse engineering:**  Focus on features like `gdb` integration, execution wrappers, and the ability to run specific tests.

6. **Identify connections to low-level details:** Look for interactions with the operating system (Linux, Android), subprocess execution, and environment variables.

7. **Identify logical reasoning:** Analyze the conditional logic used for filtering tests, handling different options, and processing results.

8. **Identify common user errors:** Think about incorrect command-line arguments, missing dependencies, or misconfigured test setups.

9. **Explain how a user reaches this code:**  Focus on the command-line invocation of `meson test`.

10. **Synthesize the functionality:**  Combine the analysis of individual components into a concise summary of the code's overall purpose.
这是 frida 动态 Instrumentation 工具的测试框架中负责执行和管理测试的模块。它提供了加载测试用例、配置测试环境、执行测试、收集测试结果以及生成测试报告的功能。

以下是其功能的归纳总结：

**核心功能：测试执行与管理**

* **加载测试元数据 (`metadata`, `load_metadata`, `load_tests`):**  从构建系统中加载测试用例的定义（名称、依赖、套件信息等）和构建配置信息。
* **准备构建环境 (`prepare_build`):**  检查 `ninja` 构建工具是否存在，如果需要且允许，则负责触发测试前的重新构建。
* **配置测试环境 (`get_test_setup`, `merge_setup_options`, `get_test_runner`):**  根据命令行选项和测试用例的配置，准备测试执行所需的各种参数，例如超时时间、环境变量、执行包装器（例如 `gdb`）。
* **执行测试 (`doit`, `run_tests`, `_run_tests`):**  根据配置并发或串行地执行测试用例。支持重复执行测试。
* **处理测试结果 (`process_test_result`):**  接收每个测试用例的执行结果（成功、失败、跳过、超时等），并更新统计信息。
* **生成测试报告 (`open_logfiles`, `log`, `summary`):**  将测试结果记录到不同的日志文件中 (JUnit XML, JSON, 文本)，并生成测试执行的总结报告。
* **测试用例过滤 (`get_tests`, `test_suitable`, `tests_from_args`):**  允许根据套件名称、命令行参数等条件选择需要执行的测试用例。
* **处理信号 (`sigint_handler`, `sigterm_handler`):**  优雅地处理 `SIGINT` (Ctrl+C) 和 `SIGTERM` 信号，允许用户中断测试执行。

**与逆向方法的关系及举例说明：**

* **集成调试器 (`get_wrapper`, `merge_setup_options`):**  该模块支持在 `gdb` 调试器下运行测试。这对于逆向分析非常有用，可以在测试执行过程中单步调试、查看内存、设置断点，以便理解代码行为或定位错误。
    * **举例:**  如果一个 Frida 模块在特定情况下崩溃，可以使用 `meson test --gdb <测试用例名称>` 在 `gdb` 下运行该测试用例，当程序崩溃时，`gdb` 会停止，允许逆向工程师检查崩溃时的堆栈信息和内存状态。
* **执行包装器 (`get_wrapper`, `merge_setup_options`):**  允许使用自定义的执行包装器运行测试。这可以用于在特定的受控环境中运行测试，例如使用 `valgrind` 进行内存泄漏检测，或者使用自定义的模拟器。
    * **举例:**  可以使用 `meson test --wrapper "valgrind --leak-check=full" <测试用例名称>` 来运行测试，`valgrind` 会在测试执行过程中检测内存泄漏。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **执行包装器和环境变量 (`get_test_runner`, `merge_setup_options`):**  测试可能需要特定的二进制工具或依赖于特定的环境变量。该模块允许设置这些环境变量或使用包装器来确保测试在正确的环境下运行。这与理解底层系统调用、库加载和进程执行相关。
    * **举例:**  Frida 可能需要在目标设备上执行一些操作。测试可能需要设置 `LD_LIBRARY_PATH` 来指向目标设备上的 Frida Agent 库。`get_test_runner` 和 `merge_setup_options` 可以用来设置这个环境变量。
* **跨平台编译 (`get_test_runner`):**  Frida 支持跨平台使用。测试框架需要处理在不同架构（例如 ARM, x86）上执行测试的情况。`get_test_runner` 中对 `is_cross_built` 和 `needs_exe_wrapper` 的判断就与此相关。对于交叉编译的测试，可能需要使用特定的执行包装器来在目标平台上运行可执行文件。
    * **举例:**  在 x86 主机上开发针对 Android ARM 设备的 Frida 模块时，测试框架需要能够将测试程序推送到 ARM 设备上并执行，这可能需要一个类似于 `adb shell` 的包装器。
* **进程管理和信号处理 (`_run_tests`, `sigint_handler`, `sigterm_handler`):**  测试框架需要能够启动和管理测试进程，并响应操作系统的信号。这涉及到对 Linux/Android 进程模型和信号机制的理解。
    * **举例:**  当用户按下 Ctrl+C 时，`sigint_handler` 会被调用，它可以选择中断当前正在运行的测试或直接退出测试框架。

**逻辑推理及假设输入与输出：**

* **测试用例过滤 (`test_suitable`, `tests_from_args`):**  这些函数根据用户提供的参数（例如 `--suite`, 测试用例名称）进行逻辑判断，决定哪些测试用例应该被执行。
    * **假设输入:**  `self.options.include_suites = ['suite1']`,  `test.suite = ['projectA:suite1']`
    * **输出:** `test_suitable(test)` 返回 `True`，因为测试用例属于指定的套件。
    * **假设输入:** `self.options.args = ['my_test']`, `tests` 列表中包含一个名为 "my_test" 的测试用例。
    * **输出:** `tests_from_args(tests)` 将会生成包含 "my_test" 的测试用例列表。
* **超时处理 (`_run_tests`, `SingleTestRunner.run`):**  测试框架会设置测试用例的超时时间，并在测试执行超时时进行相应的处理。
    * **假设输入:**  测试用例 `test_timeout` 设置了 5 秒的超时时间，但实际执行时间超过了 5 秒。
    * **输出:**  `process_test_result` 会接收到 `TestResult.TIMEOUT` 的结果，并且超时计数器会增加。

**用户或编程常见的使用错误及举例说明：**

* **指定不存在的测试用例或套件 (`tests_from_args`, `get_test_setup`):**  用户可能会在命令行中输入错误的测试用例名称或套件名称。
    * **举例:**  运行 `meson test non_existent_test`，`tests_from_args` 会抛出 `MesonException` 提示该测试用例不存在。
    * **举例:**  运行 `meson test --setup invalid_setup`，`get_test_setup` 会因为找不到对应的测试设置而退出。
* **同时指定冲突的选项 (`run`):**  用户可能会同时指定不兼容的命令行选项。
    * **举例:**  同时使用 `--gdb` 和 `--wrapper` 选项会导致程序打印错误信息并退出。
* **缺少构建工具 (`prepare_build`):**  如果系统中没有安装 `ninja`，并且需要重新构建，测试框架会报错。
    * **举例:**  在一个没有安装 `ninja` 的环境下运行 `meson test`，`prepare_build` 会检测到 `ninja` 不存在并打印错误信息。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在项目根目录下打开终端。**
2. **用户输入命令 `meson test` 或 `meson test <特定的测试用例或套件名称>`。**
3. **Meson 构建系统解析用户输入的命令。**
4. **Meson 调用 `frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py` 脚本。**
5. **`run_with_args` 函数解析命令行参数。**
6. **`run` 函数加载构建信息，并创建 `TestHarness` 实例。**
7. **如果用户指定了要运行特定的测试用例或套件，`get_tests` 和相关的过滤函数 (`test_suitable`, `tests_from_args`) 会根据用户的输入筛选出需要执行的测试用例。**
8. **如果需要重新构建，`prepare_build` 会调用 `ninja`。**
9. **`doit` 函数开始执行测试流程，包括配置测试环境 (`get_test_runner`) 和实际运行测试 (`run_tests`)。**
10. **在测试执行过程中，`_run_tests` 函数会并发或串行地运行各个测试用例。**
11. **每个测试用例的执行结果会被 `process_test_result` 处理并记录。**
12. **最后，`summary` 函数生成测试报告。**

总而言之， `mtest.py` 是 Frida 测试框架的核心执行引擎，负责管理和驱动测试的整个生命周期，并提供了丰富的配置选项和报告功能，方便开发者进行测试和调试。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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