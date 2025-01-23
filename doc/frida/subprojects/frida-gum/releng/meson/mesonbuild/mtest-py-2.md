Response:
The user wants a summary of the Python code provided, specifically focusing on its function within the context of the Frida dynamic instrumentation tool. I need to break down the code's functionality, identify its relation to reverse engineering, discuss its use of low-level/kernel concepts, analyze any logical reasoning within, point out potential user errors, explain how a user might reach this code during debugging, and finally summarize its overall purpose.

Here's a plan:

1. **High-Level Functionality:** Understand the main goal of the `TestHarness` class and its associated methods. This involves test discovery, execution, and result reporting.
2. **Reverse Engineering Relevance:** Look for aspects related to dynamic analysis, such as running tests against a target, potentially involving process manipulation or inspection.
3. **Low-Level/Kernel Aspects:** Identify any interactions with the operating system, such as process management (using `subprocess`), file system operations, signal handling, and mentions of Linux/Android kernel or framework components.
4. **Logical Reasoning:** Analyze the conditional statements and control flow to understand the decision-making process, particularly in test selection and execution. I can infer inputs and outputs based on these decisions.
5. **User Errors:** Consider common mistakes a user might make when running or configuring tests that would lead to errors handled by this code.
6. **Debugging Scenario:**  Imagine a typical Frida development or testing workflow that would lead a user to interact with this testing framework.
7. **Summarize:** Condense the findings into a concise description of the code's role.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/mtest.py` 文件中 `TestHarness` 类及其相关函数的功能归纳：

**主要功能：**

这个 Python 脚本的主要功能是构建和运行 Frida 工具的测试套件。它使用 Meson 构建系统提供的元数据来发现、执行和报告测试结果。其核心是 `TestHarness` 类，负责管理整个测试过程。

**功能分解：**

1. **测试发现与加载 (`metadata`, `load_metadata`, `load_tests`, `get_tests`)：**
   -  从 Meson 构建系统生成的元数据文件（`meson_test_setup.dat` 或 `meson_benchmark_setup.dat`）中加载测试用例的信息。这些信息包括测试名称、所属套件、依赖项、环境变量等。
   -  根据用户提供的选项（例如，包含或排除的测试套件、特定的测试名称），过滤出需要运行的测试。

2. **构建准备 (`prepare_build`)：**
   -  检查是否需要重新构建测试目标。如果用户没有指定 `--no-rebuild` 选项，并且检测到 `ninja` 构建工具，则会尝试使用 `ninja build.ninja` 命令重新构建。

3. **测试执行 (`doit`, `run_tests`, `_run_tests`, `get_test_runner`)：**
   -  创建并管理测试执行器 (`SingleTestRunner`) 的实例。每个执行器负责运行单个测试。
   -  使用 `asyncio` 库实现并发测试执行，提高测试效率。
   -  支持测试的重复执行 (`--repeat` 选项)。
   -  处理测试超时和中断信号 (SIGINT, SIGTERM)。
   -  允许设置最大失败次数 (`--maxfail` 选项)，达到上限后会停止后续测试。

4. **测试配置 (`get_test_setup`, `merge_setup_options`)：**
   -  允许为测试定义不同的配置集合 (`test_setup`)，例如不同的超时时间、执行包装器 (`wrapper`) 或 GDB 配置。
   -  合并命令行选项和测试配置中的选项。

5. **结果处理与报告 (`process_test_result`, `summary`, 日志记录器类 `JunitBuilder`, `JsonLogfileBuilder`, `TextLogfileBuilder`)：**
   -  收集每个测试的执行结果 (成功、失败、跳过、超时等)。
   -  生成测试结果的摘要报告，包括各种状态的测试数量。
   -  支持将测试结果输出到不同格式的日志文件 (JUnit XML, JSON, 文本)。

6. **外部工具集成 (`get_wrapper`)：**
   -  支持使用 GDB 调试器或自定义的执行包装器 (`wrapper`) 来运行测试。

7. **依赖管理 (`rebuild_deps`)：**
   -  在运行测试之前，可以根据测试的依赖关系，使用 `ninja` 构建工具重新构建相关的目标。

**与逆向方法的联系及举例说明：**

* **动态分析环境搭建：** 这个脚本是 Frida 测试套件的一部分，而 Frida 本身是一个动态插桩工具，常用于逆向工程中的动态分析。这个脚本确保了 Frida 的核心功能在各种场景下都能正常工作。例如，可以编写一个测试用例来验证 Frida 能否成功 hook 指定进程的某个函数。
* **测试 hook 功能：**  可以编写测试用例来验证 Frida 的 JavaScript API 能否正确地 hook 函数、修改参数或返回值。 例如，可以有一个测试用例，目标程序是一个简单的计算器，测试用例使用 Frida hook 加法函数，确保无论输入什么，都返回一个预设的值。
* **验证内存操作：** 可以编写测试用例来检查 Frida 是否能够正确读取和写入目标进程的内存。 例如，一个测试用例可以启动一个程序，然后使用 Frida 修改该程序内存中的某个变量，并验证修改是否成功。
* **检查代码注入：** 可以编写测试用例来验证 Frida 能否成功将 JavaScript 代码注入到目标进程中并执行。 例如，可以有一个测试用例启动一个简单的程序，然后使用 Frida 注入一段 JavaScript 代码，该代码会在程序运行时打印一条消息。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制执行：** 脚本会调用可执行文件来运行测试，这涉及到操作系统如何加载和执行二进制文件的知识。
* **进程管理 (`subprocess`)：**  脚本使用 `subprocess` 模块来启动和管理测试进程，这涉及到操作系统进程创建、控制和通信的相关知识。
* **信号处理 (`signal`)：**  脚本使用了信号处理机制来捕获和处理 `SIGINT` (Ctrl+C) 和 `SIGTERM` 信号，这在 Unix-like 系统编程中很常见。
* **环境变量 (`os.environ`)：**  测试的执行环境会受到环境变量的影响，脚本会读取和修改环境变量。在 Frida 的场景下，某些测试可能需要特定的环境变量来模拟目标环境。
* **文件系统操作 (`os`, `Path`)：** 脚本需要读取测试元数据文件、创建日志文件等，涉及到文件和目录的操作。
* **执行包装器 (`wrapper`)：** 允许用户指定一个包装器来运行测试，这在需要模拟特定环境或使用特殊工具（例如 `xvfb-run` 用于运行图形界面测试）时很有用。这可能涉及到对操作系统进程启动机制的深入理解。
* **GDB 集成 (`--gdb`)：** 支持使用 GDB 调试器运行测试，这需要对 GDB 的使用以及调试原理有一定的了解。

**逻辑推理及假设输入与输出：**

假设输入用户执行命令：`meson test my_test`

* **假设 1：** `my_test` 是一个存在的测试用例名称。
    * **输出：** 脚本会找到并执行名为 `my_test` 的测试用例，并报告其执行结果（成功/失败等）。
* **假设 2：** `my_test` 不是任何已定义测试用例的名称。
    * **输出：** 脚本会抛出一个 `MesonException`，提示 `my_test` 测试名称不匹配任何测试。
* **假设输入用户执行命令：** `meson test suite1`
* **假设 3：** 存在一个或多个属于 `suite1` 测试套件的测试用例。
    * **输出：** 脚本会找到并执行所有属于 `suite1` 套件的测试用例，并报告它们的执行结果。
* **假设 4：** 不存在属于 `suite1` 测试套件的测试用例。
    * **输出：** 脚本会输出 "No suitable tests defined." 并返回。

**涉及用户或编程常见的使用错误及举例说明：**

* **指定不存在的测试名称或套件名称：**  例如，用户运行 `meson test non_existent_test`，脚本会报错提示找不到该测试。
* **同时指定了 `wrapper` 和 `--gdb`：**  脚本会检测到冲突并报错，因为这两种方式都试图控制测试的执行方式。
* **指定的 `wrapper` 或 GDB 路径不正确：**  脚本会尝试运行指定的程序，如果找不到该程序，则会报错。
* **在没有 Meson 构建目录中运行 `meson test`：** 脚本会尝试加载 `meson-private/meson_test_setup.dat` 文件，如果找不到会抛出 `TestException`。
* **测试依赖的构建目标没有构建：** 如果用户在运行测试前没有先进行构建，`rebuild_deps` 函数会尝试构建依赖，但如果构建失败，测试也会失败。
* **测试代码中存在错误导致程序崩溃或超时：**  脚本会捕获这些错误并报告为测试失败或超时。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 开发或修改：** 用户正在开发或修改 Frida 的核心组件 `frida-gum`。
2. **编写或修改测试用例：** 用户可能添加了新的功能或修复了 bug，并相应地编写或修改了测试用例。
3. **运行测试：** 用户在 `frida/subprojects/frida-gum/releng/meson` 目录下打开终端，并执行 `meson test` 命令，或者指定特定的测试用例或套件，例如 `meson test my_new_feature_test`。
4. **Meson 调用 `mtest.py`：** Meson 构建系统会解析 `meson.build` 文件，发现需要运行测试，并调用 `mtest.py` 脚本来执行测试。
5. **`mtest.py` 执行测试流程：**  `mtest.py` 脚本会按照其内部逻辑，加载测试元数据，准备构建（如果需要），执行选定的测试用例，并收集和报告测试结果。
6. **调试线索：** 如果测试失败，用户可以查看 `mtest.py` 的输出日志，了解哪些测试失败了，以及失败的原因。结合测试代码和 Frida 的代码，可以逐步定位问题所在。 用户还可以使用 `--verbose` 选项获取更详细的测试执行信息，或者使用 `--gdb` 选项在 GDB 中调试测试过程。

**总结功能：**

`frida/subprojects/frida-gum/releng/meson/mesonbuild/mtest.py` 脚本是 Frida 构建系统中负责运行和管理测试套件的核心组件。它通过读取 Meson 构建系统的元数据，发现并执行测试用例，收集测试结果并生成报告。它支持多种测试配置、并发执行、外部工具集成和依赖管理，确保 Frida 工具的稳定性和正确性。 这个脚本对于 Frida 的开发和维护至关重要，它提供了一种自动化的方式来验证代码的质量。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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