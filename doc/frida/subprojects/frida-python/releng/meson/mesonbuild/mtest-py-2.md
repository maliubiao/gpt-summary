Response:
The user wants to understand the functionality of the provided Python code, which is a part of the Frida dynamic instrumentation tool. The code is specifically located in `frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py` and is the third part of a larger code snippet.

To address the user's request, I need to:

1. **Summarize the functionality** of this specific code section.
2. **Identify connections to reverse engineering** techniques and provide examples.
3. **Point out aspects related to binary internals, Linux/Android kernels, and frameworks**, giving relevant examples.
4. **Analyze logical reasoning** within the code and provide input/output examples.
5. **Highlight common user/programming errors** and illustrate them.
6. **Explain the user journey** to reach this code as a debugging clue.

**Functionality Breakdown:**

This part of the code primarily deals with the execution and management of tests within the Meson build system. It includes functionalities for:

- Filtering and selecting tests based on various criteria (names, suites, setup).
- Running tests in parallel using asyncio.
- Handling test results (success, failure, skip, timeout, etc.).
- Generating test reports in different formats (JUnit, JSON, text).
- Handling signals (SIGINT, SIGTERM) to interrupt or terminate tests.
- Rebuilding dependencies before running tests.

**Connections to Reverse Engineering:**

Frida is a dynamic instrumentation toolkit, heavily used in reverse engineering. This test framework likely executes tests that verify the functionality of Frida's core features. These tests might involve:

- **Injecting code into running processes:** Tests could verify that Frida can successfully inject scripts into target processes, read and modify memory, and hook functions.
- **Interacting with system APIs:** Tests might check if Frida can correctly interact with system calls, library functions, and other OS-level APIs.
- **Bypassing security measures:**  While not directly visible in this code snippet, the test suite could include scenarios to ensure Frida's ability to bypass certain security checks (though this would be in the *tests* themselves, not the test *runner*).

**Binary Internals, Linux/Android Kernels, and Frameworks:**

- **Binary Internals:** The code interacts with the build system (Meson) which deals with compiling and linking binaries. The `rebuild_deps` function ensures that necessary binaries are built before testing.
- **Linux/Android Kernels:**  Frida's core functionality often involves interacting with kernel-level structures and system calls. While this code doesn't directly show kernel interaction, the tests it runs will heavily rely on these interactions. For instance, tests might verify hooking system calls on Linux or interacting with the Android Binder framework.
- **Frameworks:** For Android, tests could involve interacting with specific Android framework components or services to ensure Frida's capabilities in that environment.

**Logical Reasoning (Hypothetical Input/Output):**

Let's consider the `test_suitable` function:

- **Hypothetical Input:** `test` object representing a test named "crypto_test" in the "crypto" suite. `self.options.exclude_suites` is `["network"]`.
- **Reasoning:** The function checks if the test's suite is in the `exclude_suites`. "crypto" is not in `["network"]`.
- **Output:** `True` (the test is suitable).

- **Hypothetical Input:** Same `test` object. `self.options.include_suites` is `["network"]`.
- **Reasoning:** The function checks if the test's suite is in the `include_suites`. "crypto" is not in `["network"]`.
- **Output:** `False` (the test is not suitable).

**Common User/Programming Errors:**

- **Incorrect test name or suite specification:** The `tests_from_args` function tries to match user-provided test names. If a user provides a name that doesn't match any existing test, a `MesonException` is raised. For example, running `meson test non_existent_test` would lead to this error.
- **Conflicting options:** The code checks for conflicting options like specifying both `--wrapper` and `--gdb`. This prevents users from providing incompatible configurations.
- **Missing dependencies:** If the `rebuild_deps` function fails because a dependency cannot be built (e.g., missing compiler), the test run will likely fail.
- **Incorrect working directory:** If the user runs `meson test` from a directory that is not a Meson build directory, the `load_tests` function will raise a `TestException`.

**User Journey for Debugging:**

A developer debugging a Frida Python test might end up looking at this code in the following scenario:

1. **A test fails:** The developer notices a test failure in the output of `meson test`.
2. **Investigating the test execution:** To understand *how* the test was executed, they might trace the execution flow of the `meson test` command.
3. **Stepping into `mtest.py`:** Using a debugger or by examining the source code, they would find that `mtest.py` is responsible for running the tests.
4. **Analyzing test selection and execution:** They might examine functions like `get_tests`, `run_tests`, and `_run_tests` to understand how the failing test was selected, what environment it ran in, and how its results were processed.
5. **Looking at logging:** If the failure involves issues with logging or reporting, they might inspect the `open_logfiles`, `process_test_result`, and the logger classes (like `JunitBuilder`).
6. **Considering external factors:** If the failure seems related to missing dependencies or build issues, they might look at the `prepare_build` and `rebuild_deps` functions.

**Summary of Functionality (Part 3):**

This part of `mtest.py` focuses on the core logic of running and managing the test execution process. It handles:

- **Test Filtering and Selection:**  Based on command-line arguments and test setup configurations, it determines which tests to run.
- **Test Execution:** Using `asyncio`, it executes tests in parallel, managing concurrency and handling timeouts.
- **Result Processing:** It collects and processes the results of each test, tracking successes, failures, skips, etc.
- **Reporting:** It generates various test reports (JUnit, JSON, text) summarizing the test run.
- **Error Handling:** It handles exceptions during test execution and provides informative error messages.
- **Dependency Management:** It ensures that necessary dependencies are built before running tests.
- **Signal Handling:** It gracefully handles interrupt signals (SIGINT, SIGTERM) to stop the test run.

这是 frida 动态 instrumentation tool 的测试框架 `mesonbuild.mtest.py` 的第三部分，主要负责**执行测试用例并汇总结果**。以下是其功能的详细说明，并结合逆向、底层知识、逻辑推理和常见错误进行举例：

**功能归纳：**

这部分代码主要负责以下核心功能：

1. **测试用例的获取和过滤:**
   - `get_tests()`:  根据用户提供的参数（例如，指定的测试名称、suite 名称、排除的 suite 等）以及测试的元数据，筛选出需要执行的测试用例。
   - `tests_from_args()`: 处理用户在命令行中指定的测试用例名称或 suite 名称，并将其转化为具体的测试用例列表。
   - `test_suitable()`: 根据排除和包含的 suite 列表，判断某个测试用例是否应该被执行。

2. **测试执行前的准备:**
   - `prepare_build()`: 检查是否需要重新构建测试用例，如果需要则执行 `ninja build.ninja` 命令。
   - `rebuild_deps()`: 针对选定的测试用例，重新构建其依赖项，确保测试环境是最新的。

3. **测试用例的执行:**
   - `run_tests()`: 使用 `asyncio` 库异步并发地执行测试用例。
   - `_run_tests()`:  是 `run_tests()` 的核心异步实现，负责创建和管理测试用例的并发执行，并处理中断信号。
   - `get_test_runner()`: 为每个测试用例创建一个 `SingleTestRunner` 实例，负责执行单个测试。
   - `merge_setup_options()`: 合并从测试 setup 文件和命令行选项中获取的配置参数。

4. **测试结果的处理和记录:**
   - `process_test_result()`: 处理单个测试用例的执行结果，更新成功、失败、跳过等计数器，并将结果记录到不同的日志文件中。
   - `open_logfiles()`: 打开各种日志文件（JUnit XML, JSON, 文本）。
   - `close_logfiles()`: 关闭所有打开的日志文件。
   - `flush_logfiles()`: 刷新所有打开的日志文件。
   - `log_subtest()`, `log_start_test()`:  记录子测试和测试开始的信息到日志。

5. **测试结果的汇总和报告:**
   - `summary()`: 生成测试结果的简要汇总报告。
   - `total_failure_count()`: 返回所有失败的测试用例数量。
   - `format()`: 格式化测试结果输出。

6. **信号处理:**
   -  代码中使用了 `asyncio` 的信号处理机制来捕获 `SIGINT` (Ctrl+C) 和 `SIGTERM` 信号，允许用户中断测试执行。

**与逆向方法的关联及举例说明：**

* **测试 Frida 的注入和 Hook 功能:**  这部分代码执行的测试用例很可能包含了验证 Frida 是否能够成功注入到目标进程并 Hook 函数的功能。例如，可能存在一个测试用例，它会启动一个简单的目标程序，然后使用 Frida 注入代码来 Hook 目标程序中的某个函数，并验证 Hook 是否生效，例如修改函数的返回值或者记录函数的调用参数。

* **测试 Frida 对抗反 Hook 技术的有效性:**  逆向工程师经常会使用各种反 Hook 技术来阻止 Frida 的 Hook。相应的，Frida 的测试用例中也会包含测试 Frida 如何绕过这些反 Hook 机制的用例。这部分代码负责运行这些测试，验证 Frida 的健壮性。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **二进制文件的构建和依赖:** `rebuild_deps()` 函数涉及到二进制文件的构建过程。它需要了解如何根据依赖关系重新编译特定的目标文件。这与理解链接器、编译器以及构建系统的知识相关。

* **Linux/Android 进程管理和信号:**  `_run_tests()` 中处理 `SIGINT` 和 `SIGTERM` 信号，这涉及到操作系统级别的进程管理和信号机制。在 Linux 和 Android 系统中，这些信号用于控制进程的执行和终止。例如，当用户按下 Ctrl+C 时，操作系统会向正在运行的 `meson test` 进程发送 `SIGINT` 信号。

* **Android 框架的交互:** 如果测试涉及到 Android 平台的 Frida 功能，那么测试用例可能需要与 Android 框架进行交互。例如，测试 Frida 是否能够 Hook Android 系统服务中的方法，或者拦截 Binder 通信。这需要对 Android 框架的内部机制有所了解。

**逻辑推理及假设输入与输出：**

假设 `self.tests` 包含以下两个测试用例：

```python
# 简化的 TestSerialisation 对象
test1 = TestSerialisation(name='test_hook_basic', suite=['frida:core'])
test2 = TestSerialisation(name='test_memory_rw', suite=['frida:core'])
```

并且用户在命令行中执行 `meson test test_hook_basic`。

* **假设输入:** `self.options.args = ['test_hook_basic']`
* **`tests_from_args()` 的逻辑推理:** 函数会遍历 `self.tests` 中的每个测试用例，并与 `self.options.args` 中的模式进行匹配。
* **输出:** `get_tests()` 返回的 `tests` 列表将只包含 `test1` 这个测试用例。

**涉及用户或编程常见的使用错误及举例说明：**

* **拼写错误的测试用例名称:** 如果用户在命令行中输入了错误的测试用例名称，例如 `meson test test_hook_basc`，`tests_from_args()` 函数会抛出一个 `MesonException`，提示该测试用例名称不存在。

* **同时指定冲突的选项:**  代码中 `run()` 函数会检查一些冲突的选项，例如同时指定 `--wrapper` 和 `--gdb`。如果用户同时指定了这两个选项，程序会打印错误信息并退出。

* **没有在 Meson 构建目录下运行命令:** 如果用户在非 Meson 构建目录下执行 `meson test` 命令，`load_tests()` 函数会因为找不到 `meson-private/meson_test_setup.dat` 文件而抛出 `TestException`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者编写或修改了 Frida 的代码。**
2. **开发者想要验证其代码的正确性，因此运行了 `meson test` 命令。**
3. **`meson test` 命令会解析命令行参数，并加载构建配置。**
4. **根据构建配置和命令行参数，`meson test` 会调用 `mesonbuild.mtest.py` 中的 `run()` 函数。**
5. **`run()` 函数会创建 `TestHarness` 实例。**
6. **在 `TestHarness` 的 `doit()` 方法中，会调用 `get_tests()` 来获取需要执行的测试用例。**
7. **`get_tests()` 可能会调用 `tests_from_args()` 来处理用户指定的测试用例名称。**
8. **接下来，`doit()` 方法会调用 `run_tests()` 来执行这些测试用例。**
9. **`run_tests()` 内部会调用 `_run_tests()` 使用 `asyncio` 并发执行测试。**
10. **每个测试用例的执行结果会通过 `process_test_result()` 进行处理，并记录到日志文件中。**
11. **最后，`doit()` 方法会返回测试失败的总数。**

当开发者需要调试测试框架本身的问题，或者需要了解某个测试用例是如何被执行的，他们可能会逐步查看 `mesonbuild.mtest.py` 的代码，从 `run()` 函数开始，逐步跟踪到测试用例的获取、执行和结果处理的各个环节，以便理解整个测试流程。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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