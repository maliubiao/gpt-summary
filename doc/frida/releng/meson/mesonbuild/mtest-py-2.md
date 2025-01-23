Response:
The user wants a breakdown of the provided Python code for the `mtest.py` file in the Frida project. I need to analyze the code and explain its functionalities, especially concerning:

1. **General Functionality:** What does this script do?
2. **Reversing Relevance:** How does it relate to reverse engineering?
3. **Low-Level/Kernel Interaction:** Does it touch on binary, Linux/Android kernel, or framework aspects?
4. **Logical Reasoning:** Can I infer inputs and outputs for specific code blocks?
5. **Common User Errors:** What mistakes might users make when using this script?
6. **User Path to This Code:** How does a user's interaction lead to the execution of this code?
7. **Overall Summary:** A concise summary of the script's purpose.

Since this is part 3 of 3, I need to summarize the functionality that was likely discussed in the previous parts. Based on the code, this part seems to focus on the test execution itself, handling test results, and reporting.

**Plan:**

1. **High-Level Functionality:** Identify the main purpose of `TestHarness` and its methods.
2. **Reverse Engineering Connection:**  Frida is a dynamic instrumentation tool, so testing likely involves running code and inspecting its behavior, directly related to reverse engineering. I'll look for parts that facilitate this.
3. **Low-Level Aspects:** Pay attention to interactions with the operating system (process execution, signals), build systems (Ninja), and potential environment variables relevant to instrumentation or cross-compilation.
4. **Logical Reasoning:** Consider methods like `get_tests`, `run_tests`, and result processing to infer input/output.
5. **User Errors:** Think about command-line options and incorrect build setup.
6. **User Path:**  The command `meson test` likely triggers this script.
7. **Summary:** Condense the identified functionalities.
这是 Frida 动态插桩工具的 `frida/releng/meson/mesonbuild/mtest.py` 源代码文件的第三部分，其主要功能是 **执行测试用例并汇总测试结果**。

结合前两部分，我们可以推断出 `mtest.py` 的整体工作流程是：

1. **解析参数和配置：**  接收用户通过命令行传递的参数，例如要运行的测试、是否重建、日志输出等。
2. **加载测试元数据：** 从构建目录中加载关于测试用例的信息，包括测试名称、依赖、运行环境等。
3. **准备构建环境：**  检查是否需要重新构建测试依赖项，并调用 Ninja 进行构建。
4. **选择要运行的测试：** 根据用户指定的参数（如测试名称、套件等）过滤出需要执行的测试用例。
5. **执行测试用例：**  创建并运行每个测试用例，处理测试的输出和结果。
6. **汇总测试结果：**  统计测试的成功、失败、跳过、超时等状态，并生成测试报告。
7. **清理资源：** 关闭日志文件等。

**本部分代码的主要功能如下：**

* **`metadata()`:**  收集所有测试用例的套件 (suite) 信息，存储在 `self.suites` 中。
* **`get_console_logger()`:** 获取控制台日志记录器。
* **`prepare_build()`:** 检查并调用 Ninja 构建系统来重建测试依赖项，除非用户指定不重建。如果找不到 Ninja，则退出。
* **`load_metadata()`:**  切换到构建目录，加载构建数据 (`build_data`) 和测试设置数据 (`meson_test_setup.dat` 或 `meson_benchmark_setup.dat`)，其中包含了测试用例的详细信息。
* **`load_tests()`:**  从指定的文件中加载序列化后的测试用例对象。
* **`__enter__`, `__exit__`, `close_logfiles()`:**  用于管理日志文件的上下文，确保在测试结束后关闭日志。
* **`get_test_setup()`:** 获取指定测试用例的测试设置信息，例如超时时间、GDB 设置等。
* **`merge_setup_options()`:**  合并从命令行和测试设置中获取的选项，例如是否使用 GDB、超时乘数、环境变量等。如果命令行和测试设置都指定了执行包装器 (wrapper)，则会报错。
* **`get_test_runner()`:**  为指定的测试用例创建一个 `SingleTestRunner` 对象，负责实际运行测试。其中会处理环境变量、执行包装器等。
* **`process_test_result()`:**  处理单个测试用例的运行结果，更新成功、失败、跳过等计数器，并将结果记录到日志中。
* **`numlen`, `max_left_width`, `get_test_num_prefix()`:**  用于格式化测试结果输出，使其对齐。
* **`format()`:**  格式化单个测试结果的输出字符串，包括测试编号、名称、结果、持续时间等。
* **`summary()`:**  生成测试结果的汇总报告。
* **`total_failure_count()`:**  计算总的失败测试数量。
* **`doit()`:**  **核心功能：执行测试用例。**  获取要运行的测试用例，调用 Ninja 重建依赖项（如果需要），创建测试运行器，并发或串行执行测试，并返回失败的测试用例数量。
* **`split_suite_string()`, `test_in_suites()`:**  用于处理和比较测试套件字符串，用于过滤测试用例。
* **`test_suitable()`:**  判断一个测试用例是否适合运行，根据用户指定的包含和排除的套件以及测试设置进行判断。
* **`tests_from_args()`:**  根据用户在命令行中提供的参数（测试名称或套件）筛选出要运行的测试用例。如果提供的参数无法匹配到任何测试，则会报错。
* **`get_tests()`:**  获取所有需要运行的测试用例列表，会进行套件过滤和命令行参数过滤。
* **`flush_logfiles()`, `open_logfiles()`:**  用于管理日志文件，打开和刷新日志。
* **`get_wrapper()`:**  根据用户选项（如 `--gdb`, `--wrapper`）构建测试执行的包装器命令。
* **`get_pretty_suite()`:**  生成更友好的测试套件名称显示。
* **`run_tests()`:**  **异步执行测试用例的核心函数。**  使用 `asyncio` 并发或串行地运行测试用例，处理信号 (SIGINT, SIGTERM) 以响应用户中断。
* **`log_subtest()`, `log_start_test()`:**  记录子测试和测试开始事件到日志。
* **`_run_tests()`:**  `run_tests` 的异步实现，管理协程的创建、运行和取消，以及信号处理。
* **`list_tests()`:**  列出所有可用的测试用例。
* **`rebuild_deps()`:**  调用 Ninja 构建指定的测试目标依赖项。
* **`run()`:**  `mtest.py` 的入口函数，处理命令行参数，加载构建信息，创建 `TestHarness` 对象并执行测试。
* **`run_with_args()`:**  解析命令行参数并调用 `run()` 函数。

**与逆向方法的关系：**

`mtest.py` 是 Frida 测试框架的一部分，其主要目的是确保 Frida 工具本身的正确性和稳定性。通过运行各种测试用例，可以验证 Frida 的核心功能，例如：

* **代码注入和执行：** 测试 Frida 是否能够成功将代码注入到目标进程并执行。例如，测试可以编写一个简单的脚本注入到目标进程，然后检查脚本是否按预期运行。
* **内存操作：**  测试 Frida 是否能够正确读取和写入目标进程的内存。例如，测试可以读取目标进程中特定地址的值，或者修改内存中的数据，并验证操作结果。
* **函数 Hooking：**  测试 Frida 是否能够成功 Hook 目标进程中的函数，并在函数调用前后执行自定义代码。例如，测试可以 Hook 一个关键的 API 函数，记录其参数和返回值。
* **跨平台支持：**  测试 Frida 在不同操作系统（如 Linux、Android、Windows）上的兼容性。

**举例说明：**

假设有一个测试用例，用于验证 Frida 在 Android 上 Hook `open` 系统调用的功能。该测试用例可能会执行以下步骤：

1. 使用 Frida 脚本 Hook Android 系统库 `libc.so` 中的 `open` 函数。
2. 当 `open` 函数被调用时，Frida 脚本会记录被打开的文件路径。
3. 测试用例在被 Frida 注入的 Android 应用中尝试打开一个文件。
4. `mtest.py` 执行这个测试用例，并验证 Frida 脚本是否成功 Hook 了 `open` 函数，并记录了正确的文件路径。

**涉及到二进制底层，Linux, Android 内核及框架的知识：**

* **二进制底层：**  `mtest.py` 间接涉及到二进制底层知识，因为它运行的测试用例通常会操作目标进程的二进制代码和内存。例如，测试可能需要指定要 Hook 的函数的内存地址，或者读取特定内存地址的值。
* **Linux 内核：**  在 Linux 平台上，Frida 的测试可能涉及到与 Linux 内核的交互，例如系统调用 Hooking。`mtest.py` 会执行这些测试，验证 Frida 在 Linux 上的功能。
* **Android 内核及框架：**  在 Android 平台上，Frida 的测试会涉及到 Android 内核（基于 Linux）以及 Android 框架层面的知识。例如，测试可能需要 Hook Android 系统服务或 Java Framework 的 API。`mtest.py` 负责运行这些针对 Android 环境的测试。
* **进程和线程管理：**  `mtest.py` 需要创建和管理测试进程，以及处理并发测试的情况。这涉及到操作系统关于进程和线程管理的知识。
* **信号处理：**  `mtest.py` 实现了信号处理机制（SIGINT, SIGTERM），以便在用户中断测试时能够优雅地退出。

**举例说明：**

* 测试用例可能会验证 Frida 是否能够正确 Hook Android 的 `__openat` 系统调用，这直接涉及到 Linux 内核的系统调用机制。
* 测试用例可能会验证 Frida 是否能够 Hook Android Framework 中的 `Activity.onCreate()` 方法，这需要了解 Android 的组件生命周期和 Java Native Interface (JNI)。

**逻辑推理，假设输入与输出：**

假设用户运行命令： `meson test my_test`

* **假设输入：**
    * `self.options.args` 为 `['my_test']`
    * `self.tests` 包含了多个 `TestSerialisation` 对象，其中一个对象的 `name` 属性为 `'my_test'`。
* **逻辑推理过程（在 `tests_from_args()` 中）：**
    1. `patterns` 初始化为 `{'*:my_test': False}`。
    2. 遍历 `self.tests`。
    3. 当遍历到 `name` 为 `'my_test'` 的 `TestSerialisation` 对象时，`fnmatch(t.project_name, '*')` 和 `fnmatch(t.name, 'my_test')` 都返回 `True`。
    4. `patterns` 更新为 `{'*:my_test': True}`。
    5. 该 `TestSerialisation` 对象被 `yield` 返回。
* **假设输出：**
    * `get_tests()` 方法最终返回的 `tests` 列表中包含 `name` 为 `'my_test'` 的 `TestSerialisation` 对象。

**涉及用户或者编程常见的使用错误：**

* **指定不存在的测试名称或套件：**  用户在命令行中使用 `meson test non_existent_test`，但 `non_existent_test` 并非有效的测试用例名称。`tests_from_args()` 方法会抛出 `MesonException` 错误。
* **同时指定了冲突的选项：**  例如，同时使用了 `--wrapper` 和 `--gdb` 选项。`run()` 函数会检测到这种情况并返回错误。
* **构建目录不正确：**  用户在非 Meson 构建目录下运行 `meson test`，`load_tests()` 方法会抛出 `TestException`，因为找不到 `meson-private/meson_test_setup.dat` 文件。
* **忘记构建测试依赖项：**  用户在修改了测试代码后，直接运行 `meson test --no-rebuild`，可能导致测试失败，因为依赖项没有更新。
* **执行包装器配置错误：**  如果用户在测试设置或命令行中指定了错误的执行包装器路径，会导致测试无法正常运行。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. 用户在 Frida 项目的构建目录下打开终端。
2. 用户输入命令 `meson test [options]`，其中 `[options]` 可以包含各种参数，例如要运行的测试名称、是否重建、日志输出路径等。
3. Meson 工具接收到 `test` 命令，并解析命令行参数。
4. Meson 工具会执行 `frida/releng/meson/mesonbuild/mtest.py` 脚本，并将解析后的命令行参数传递给它。
5. 在 `mtest.py` 脚本中，`run_with_args()` 函数会被调用，解析参数并传递给 `run()` 函数。
6. `run()` 函数会创建 `TestHarness` 对象，并调用其 `doit()` 方法开始执行测试流程。
7. `doit()` 方法会调用 `get_tests()` 获取要运行的测试用例，其中会根据用户提供的参数调用 `tests_from_args()` 进行过滤。
8. `doit()` 方法会创建 `SingleTestRunner` 对象，并调用其 `run()` 方法实际执行测试。
9. 在测试执行过程中，`process_test_result()` 方法会被调用来处理测试结果。
10. 最后，`doit()` 方法会返回测试失败的数量。

作为调试线索，如果测试过程中出现问题，可以检查以下方面：

* **用户输入的命令行参数是否正确。**
* **构建目录是否正确，测试元数据文件是否存在。**
* **测试用例代码本身是否存在错误。**
* **Frida 工具本身是否存在 Bug。**
* **操作系统环境是否符合测试要求。**

**归纳一下它的功能 (结合前两部分):**

`frida/releng/meson/mesonbuild/mtest.py` 的主要功能是为 Frida 项目提供一个全面的测试框架。它负责：

1. **参数解析和配置管理：** 接收和处理用户通过命令行传递的测试选项。
2. **构建环境管理：**  确保测试依赖项是最新的，必要时调用构建系统进行重建。
3. **测试用例发现和加载：**  从构建目录中读取并加载测试用例的元数据信息。
4. **测试用例过滤和选择：**  根据用户指定的条件（如名称、套件）选择要执行的测试用例。
5. **测试执行和管理：**  创建测试运行器，并发或串行地执行测试用例，并捕获测试结果。
6. **测试结果处理和报告：**  汇总测试结果，生成各种格式的测试报告 (例如 JUnit, JSON, 文本)。
7. **错误处理和调试支持：**  提供错误提示，并支持使用 GDB 等工具进行调试。

总而言之，`mtest.py` 是 Frida 项目中至关重要的测试基础设施，它确保了 Frida 的代码质量和功能稳定性。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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