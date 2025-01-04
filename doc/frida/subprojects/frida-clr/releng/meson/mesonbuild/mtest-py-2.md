Response:
The user wants to understand the functionality of the provided Python code, which is part of the Frida dynamic instrumentation tool. The request is broken down into specific aspects: general functionality, relationship with reverse engineering, interaction with low-level systems (Linux/Android kernel/framework), logical reasoning, common user errors, and how a user might arrive at executing this code.

**Plan:**

1. **Summarize the overall purpose of the script:**  It's a test runner for Meson build systems.
2. **Analyze the code sections to identify core functionalities:**  Loading test definitions, preparing the build environment, running tests, processing results, and generating reports.
3. **Connect functionalities to reverse engineering concepts:**  Dynamic instrumentation, testing modified code.
4. **Identify interactions with low-level systems:**  Execution of binaries, environment variables, potentially interacting with target processes.
5. **Look for logical reasoning and provide example inputs/outputs:**  Filtering tests based on arguments, suite inclusion/exclusion.
6. **Pinpoint common user errors:**  Incorrect command-line arguments, issues with the build environment.
7. **Trace the user's path to executing this script:**  Standard Meson testing workflow.
8. **Synthesize a summary of the script's functions.**
好的，这是Frida动态Instrumentation工具中`frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py`文件的第三部分，我将归纳一下它的功能：

**归纳 `mtest.py` 的功能：**

总的来说，`mtest.py` 脚本是用于运行和管理使用 Meson 构建系统构建的项目中的测试。它提供了一系列功能来加载、过滤、执行测试，并生成测试报告。

具体来说，从提供的代码片段来看，这部分代码主要负责以下功能：

1. **加载和管理测试元数据 (`metadata`):**  收集所有测试用例的套件 (suite) 信息，并存储在 `self.suites` 中。这用于后续对测试进行分类和过滤。

2. **获取控制台日志记录器 (`get_console_logger`):**  提供访问用于在控制台输出测试信息的日志记录器的接口.

3. **准备构建环境 (`prepare_build`):**
   - 检查是否需要重新构建 (根据 `options.no_rebuild`)。
   - 检测 `ninja` 构建工具，如果找不到则退出，因为测试可能依赖于最新的构建产物。

4. **加载测试元数据 (`load_metadata`):**
   - 切换到构建目录 (`options.wd`)。
   - 在加载测试数据之前，检查是否需要重新生成构建配置。这通过运行 `ninja -n build.ninja` 来实现，如果检测到有工作要做，则执行 `ninja build.ninja` 进行构建。
   - 加载构建数据 (`build_data`)，包括测试设置的默认名称。
   - 根据是否启用了基准测试选项 (`options.benchmark`)，加载不同的测试定义文件 (`meson_benchmark_setup.dat` 或 `meson_test_setup.dat`)。
   - 切换回原始工作目录。

5. **加载测试用例 (`load_tests`):**  从 `meson-private` 目录下的指定文件中反序列化加载测试用例对象。如果找不到测试定义文件，则会抛出异常。

6. **上下文管理 (`__enter__`, `__exit__`):**  实现 `with` 语句的支持，在进入时返回 `TestHarness` 实例，在退出时关闭日志文件。

7. **关闭日志文件 (`close_logfiles`):**  关闭所有已打开的日志记录器。

8. **获取测试设置 (`get_test_setup`):**
   - 根据 `options.setup` 的值，从构建数据中获取特定的测试设置。
   - 支持两种格式的设置名称：全局设置名 (`setup_name`) 和项目特定的设置名 (`project_name:setup_name`)。
   - 如果找不到指定的测试设置，则会退出。

9. **合并设置选项 (`merge_setup_options`):**
   - 将从测试设置中读取的选项与命令行选项进行合并。
   - 例如，如果命令行没有指定 `gdb`，则使用测试设置中的 `gdb` 值。
   - 如果同时在命令行和测试设置中指定了 `wrapper`，则会报错。
   - 返回合并后的环境变量。

10. **获取测试运行器 (`get_test_runner`):**
    - 为单个测试创建一个 `SingleTestRunner` 实例。
    - 复制命令行选项，并根据是否指定了测试设置来合并环境变量。
    - 如果是交叉编译并且需要可执行文件包装器 (`exe_wrapper`)，则将包装器的命令添加到环境变量 `MESON_EXE_WRAPPER` 中。

11. **处理测试结果 (`process_test_result`):**
    - 根据测试结果的类型（成功、失败、跳过、超时等）更新计数器。
    - 将失败的测试结果添加到 `collected_failures` 列表中。
    - 将测试结果记录到所有已注册的日志记录器中。

12. **格式化测试结果输出 (`format`):**  生成格式化的测试结果字符串，包括测试编号、名称、结果和持续时间。支持自定义前缀、左右内容和颜色。

13. **生成测试总结 (`summary`):**  生成测试运行的统计摘要，包括成功、失败、跳过和超时的测试数量。

14. **计算总失败数 (`total_failure_count`):**  计算所有失败类型的测试总数（包括 Fail, Unexpected Pass, Timeout）。

15. **执行测试 (`doit`):**
    - 检查是否已经运行过，避免重复运行。
    - 获取要运行的测试列表 (`get_tests`)。
    - 如果没有指定不重新构建 (`no_rebuild`) 并且存在需要构建的依赖，则调用 `rebuild_deps` 来构建依赖。
    - 计算测试名称的最大长度和超时时间的最大长度，用于格式化输出。
    - 根据重复次数创建 `SingleTestRunner` 实例列表。
    - 调用 `run_tests` 实际执行测试。
    - 返回总失败数作为退出码。

16. **分割套件字符串 (`split_suite_string`):**  将套件字符串分割成项目名和套件名。

17. **判断测试是否属于指定套件 (`test_in_suites`):**  检查一个测试是否属于给定的套件列表。支持使用 `suite_name` 或 `project_name:suite_name` 的格式指定套件。

18. **判断测试是否适合运行 (`test_suitable`):**
    - 根据排除套件 (`exclude_suites`) 选项来过滤测试。
    - 如果指定了包含套件 (`include_suites`) 选项，则只运行指定的套件中的测试。
    - 如果使用了测试设置，则会考虑测试设置中排除的套件。

19. **从命令行参数中获取测试用例 (`tests_from_args`):**
    - 允许用户通过命令行参数指定要运行的测试名称，支持通配符和项目名限定。
    - 检查提供的测试名称是否匹配实际存在的测试，并对冗余或无效的名称发出警告或错误。

20. **获取要运行的测试列表 (`get_tests`):**
    - 根据 `test_suitable` 方法过滤测试。
    - 如果提供了命令行参数，则进一步根据参数过滤测试。

21. **刷新日志文件 (`flush_logfiles`):**  强制将缓冲区中的日志数据写入文件。

22. **打开日志文件 (`open_logfiles`):**  根据配置打开不同格式的日志文件（JUnit XML, JSON, Text）。

23. **获取包装器 (`get_wrapper`):**  根据命令行选项 (`gdb`, `wrapper`) 构建用于执行测试的可执行文件包装器命令列表。

24. **生成易读的套件名称 (`get_pretty_suite`):**  生成更友好的测试套件名称，包含项目名和具体的套件名。

25. **运行测试 (`run_tests`):**
    - 初始化日志文件。
    - 设置异步事件循环策略（Windows）。
    - 使用 `asyncio.run` 启动异步测试执行器 (`_run_tests`)。
    - 在 `finally` 块中确保关闭日志文件。

26. **记录子测试结果 (`log_subtest`):**  将子测试的结果记录到日志中。

27. **记录测试开始 (`log_start_test`):**  将测试开始事件记录到日志中。

28. **异步运行测试 (`_run_tests`):**
    - 使用 `asyncio.Semaphore` 控制并发测试数量。
    - 创建异步任务来运行每个测试。
    - 处理测试完成的回调。
    - 实现对 `SIGINT` (Ctrl+C) 和 `SIGTERM` 信号的处理，允许用户中断测试执行。
    - 在开始和结束时通知日志记录器。

29. **列出测试用例 (`list_tests`):**  如果指定了 `--list` 选项，则列出所有适合运行的测试用例的名称。

30. **重新构建依赖 (`rebuild_deps`):**
    - 将文件路径转换为 Ninja 构建系统中的目标 (target) 名称。
    - 根据测试用例的依赖关系，构建需要重新构建的目标列表。
    - 运行 `ninja` 命令来构建这些目标。

31. **主运行函数 (`run`):**
    - 处理命令行选项，例如基准测试模式、verbose 和 quiet 选项的冲突。
    - 检查 `gdb` 或自定义包装器是否存在。
    - 加载构建信息。
    - 根据构建后端的类型，决定是否需要重新构建。
    - 创建 `TestHarness` 实例并执行测试，捕获并处理可能发生的 `TestException`。

32. **带参数运行 (`run_with_args`):**  解析命令行参数并调用 `run` 函数。

总而言之，这段代码是 `mtest.py` 脚本的核心执行逻辑，负责orchestration测试的加载、准备、执行和结果处理。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
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

"""


```