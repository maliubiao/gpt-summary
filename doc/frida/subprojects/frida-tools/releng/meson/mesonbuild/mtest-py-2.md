Response:
The user wants to understand the functionality of the provided Python code snippet, which is a part of the `frida-tools` project and specifically the `mtest.py` file responsible for running tests.

To address the user's request, I need to analyze the code and identify its key functionalities, particularly in relation to:

1. **Reverse Engineering:** How does this code relate to analyzing and understanding software behavior?
2. **Binary/Kernel Knowledge:** Does it interact with low-level system components?
3. **Logical Reasoning:** Are there conditional execution paths or data manipulation logic that can be demonstrated with examples?
4. **User Errors:** What common mistakes could a user make when interacting with this code or the tool it represents?
5. **User Workflow:** How does a user's interaction lead to the execution of this specific code?

Finally, I need to summarize the overall function of this code segment as the third part of a multi-part explanation.

**Plan:**

1. **High-level overview:** Understand the main purpose of the `TestHarness` class and its methods.
2. **Function-specific analysis:** Examine individual methods to determine their roles in the testing process.
3. **Relate to reverse engineering:** Identify aspects of the code that facilitate or interact with reverse engineering concepts.
4. **Identify kernel/binary interaction:** Look for operations that involve system calls, process execution, or handling binary data.
5. **Analyze logical flow:** Find conditional statements and data transformations, and create illustrative input/output scenarios.
6. **Consider user errors:** Think about how a user might misuse the command-line options or environment configurations.
7. **Trace user interaction:**  Describe the steps a user would take to initiate the test execution, leading to this code being executed.
8. **Summarize functionality:** Concisely describe the role of this code snippet within the larger testing framework.
这是 frida 动态instrumentation 工具的测试执行框架的核心部分。它负责加载、管理和运行测试用例，并汇总测试结果。

**功能列表:**

1. **加载测试元数据 (`load_metadata`)**:
   - 从构建目录中加载测试相关的元数据，包括测试用例列表、测试设置等。
   - 检查构建配置是否需要重新生成，并在必要时执行 `ninja build.ninja` 来更新构建。
   - 根据选项加载不同类型的测试数据（例如，常规测试或基准测试）。

2. **准备构建环境 (`prepare_build`)**:
   - 检测系统中是否存在 `ninja` 构建工具。如果不存在，则报错并退出。

3. **管理测试套件 (`metadata`)**:
   - 提取所有测试用例所属的测试套件名称。

4. **获取控制台日志记录器 (`get_console_logger`)**:
   - 提供访问控制台日志记录器的接口。

5. **加载测试用例 (`load_tests`)**:
   - 从指定的文件 (`meson_test_setup.dat` 或 `meson_benchmark_setup.dat`) 中反序列化加载测试用例对象。
   - 进行数据校验 (`check_testdata`)。

6. **管理日志文件 (`open_logfiles`, `close_logfiles`, `flush_logfiles`)**:
   - 打开用于记录测试结果的各种格式的日志文件（JUnit XML, JSON, Text）。
   - 关闭并刷新这些日志文件。

7. **获取测试设置 (`get_test_setup`)**:
   - 根据命令行选项 (`--setup`) 和测试用例信息，加载特定的测试设置。测试设置可能包含超时时间、执行器包装器 (wrapper) 等配置。

8. **合并测试设置选项 (`merge_setup_options`)**:
   - 将命令行选项和测试设置中的选项合并，例如 GDB 调试、超时乘数、执行器包装器等。
   - 处理命令行选项和测试设置中执行器包装器冲突的情况。
   - 获取测试运行所需的合并后的环境变量。

9. **创建单次测试运行器 (`get_test_runner`)**:
   - 为每个测试用例创建一个 `SingleTestRunner` 对象，该对象负责执行单个测试。
   - 传递测试用例对象、环境变量、测试名称和命令行选项。
   - 处理交叉编译场景下执行器包装器的设置。

10. **处理测试结果 (`process_test_result`)**:
    - 接收单个测试用例的运行结果，并更新各种统计计数器（成功、失败、跳过、超时等）。
    - 将失败的测试结果添加到 `collected_failures` 列表中。
    - 将测试结果传递给不同的日志记录器。

11. **格式化测试结果输出 (`format`)**:
    - 将单个测试用例的运行结果格式化为易于阅读的字符串，包含测试编号、名称、运行状态和持续时间。

12. **生成测试结果摘要 (`summary`)**:
    - 生成测试运行的总结报告，显示各种结果类型的计数。

13. **计算总失败次数 (`total_failure_count`)**:
    - 计算失败、意外通过和超时的测试用例总数。

14. **执行测试 (`doit`)**:
    - 这是测试执行的入口点。
    - 获取要运行的测试用例列表。
    - 在运行测试之前，根据依赖关系重新构建相关的目标文件 (`rebuild_deps`)。
    - 创建并运行 `SingleTestRunner` 对象来执行测试。
    - 可以重复运行测试用例。
    - 处理测试执行过程中的异常。

15. **解析测试套件字符串 (`split_suite_string`)**:
    - 将测试套件字符串（可能包含项目名称）分割成项目名称和套件名称。

16. **检查测试用例是否属于指定套件 (`test_in_suites`)**:
    - 判断一个测试用例是否属于指定的测试套件列表。

17. **判断测试用例是否适合运行 (`test_suitable`)**:
    - 根据命令行选项 (`--exclude-suites`, `--include-suites`) 和测试设置中的排除套件列表，判断一个测试用例是否应该被运行。

18. **从命令行参数中提取测试用例 (`tests_from_args`)**:
    - 允许用户通过命令行参数指定要运行的测试用例名称或测试套件。
    - 支持使用通配符匹配测试用例名称。
    - 检查命令行参数指定的测试用例是否存在。

19. **获取要运行的测试用例列表 (`get_tests`)**:
    - 组合使用 `test_suitable` 和 `tests_from_args` 来获取最终要运行的测试用例列表。

20. **静态方法获取执行器包装器 (`get_wrapper`)**:
    - 根据命令行选项 (`--gdb`, `--wrapper`) 构建用于执行测试的包装器命令列表。

21. **获取美观的测试套件名称 (`get_pretty_suite`)**:
    - 生成更易读的测试套件名称，包含项目名称（如果存在多个项目）和套件名称。

22. **异步运行测试 (`run_tests`, `_run_tests`)**:
    - 使用 `asyncio` 库异步并发地运行测试用例，提高测试效率。
    - 可以限制并发运行的测试用例数量。
    - 处理测试执行过程中的中断信号 (SIGINT, SIGTERM)。

23. **记录子测试结果 (`log_subtest`)**:
    - 记录单个测试用例中子测试的结果。

24. **记录测试开始 (`log_start_test`)**:
    - 记录单个测试用例的开始执行。

25. **列出测试用例 (`list_tests`)**:
    - 如果指定了 `--list` 选项，则列出所有可运行的测试用例名称。

26. **重新构建依赖 (`rebuild_deps`)**:
    - 在运行测试之前，根据测试用例的依赖关系，使用 `ninja` 重新构建相关的目标文件。

27. **主运行函数 (`run`, `run_with_args`)**:
    - 解析命令行参数。
    - 检查必要的外部程序（例如 `gdb` 或指定的包装器）是否存在。
    - 加载构建信息并处理与 Visual Studio 环境变量相关的设置。
    - 创建 `TestHarness` 对象并执行测试或列出测试用例。
    - 处理测试执行过程中的 `TestException` 异常。

**与逆向方法的关系及举例说明:**

这个脚本本身不直接执行逆向操作，但它用于测试 frida 工具的功能。frida 的核心作用是进行动态 instrumentation，这是一种重要的逆向工程技术。

**举例说明:**

假设 frida 的某个功能是 hook 函数调用并打印参数。这个脚本会包含一个测试用例，例如：

```python
# 在测试用例数据中定义一个测试
{
    'name': 'test_function_hook',
    'suite': ['api'],
    'command': ['python', 'test_function_hook.py'],  # 一个 Python 脚本，内部使用 frida 进行 hook
    'timeout': 10,
    'is_parallel': True,
    'needs_exe_wrapper': False,
    'project_name': 'frida-core'
}
```

当 `mtest.py` 运行这个测试用例时，它会执行 `test_function_hook.py` 脚本。该脚本内部会使用 frida 连接到目标进程，hook 某个函数，并验证 frida 是否成功 hook 并获取到了预期的参数。测试的成功与否间接验证了 frida 的逆向功能是否正常工作。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明:**

虽然 `mtest.py` 是 Python 代码，但它所测试的 frida 工具的核心功能是与操作系统底层交互的。

**举例说明:**

- **二进制底层:** frida 需要能够解析和修改目标进程的内存中的二进制代码，例如插入 hook 代码。测试用例可能会验证 frida 能否正确地 hook 到特定偏移地址的指令。
- **Linux 内核:** frida 在 Linux 上通常使用 `ptrace` 系统调用或其他内核机制来实现进程注入和代码注入。测试用例可能间接测试了 frida 对这些内核机制的封装是否正确。
- **Android 内核及框架:** frida 在 Android 上可以 hook Java 层（通过 ART 虚拟机）和 Native 层（通过 linker 或其他机制）。测试用例可能验证 frida 能否 hook Android Framework 中的关键函数，例如 Activity 的生命周期函数。

**逻辑推理及假设输入与输出:**

假设我们有以下测试用例：

```python
# 假设 meson_test_setup.dat 中有如下测试用例
[
    {
        'name': 'add_test',
        'suite': ['math'],
        'command': ['./add_test', '2', '3'],
        'timeout': 5,
        'is_parallel': True,
        'needs_exe_wrapper': False,
        'project_name': 'my_project'
    },
    {
        'name': 'subtract_test',
        'suite': ['math'],
        'command': ['./subtract_test', '5', '2'],
        'timeout': 5,
        'is_parallel': True,
        'needs_exe_wrapper': False,
        'project_name': 'my_project'
    }
]
```

**假设输入:**

用户执行命令 `meson test --setup ci --include-suites math add_test`

**逻辑推理:**

1. `TestHarness` 被创建并加载元数据。
2. `--setup ci` 表明要加载名为 `ci` 的测试设置。
3. `--include-suites math` 表明只运行属于 `math` 套件的测试。
4. `add_test` 作为命令行参数被传入，指定要运行名为 `add_test` 的测试。
5. `get_tests` 方法会先根据 `--include-suites` 筛选出 `add_test` 和 `subtract_test`。
6. 然后，`tests_from_args` 方法会进一步筛选，只保留名称匹配 `add_test` 的测试。
7. 最终，只有 `add_test` 测试用例会被执行。

**预期输出:**

控制台会显示 `add_test` 的运行结果，而 `subtract_test` 不会被执行。

**涉及用户或者编程常见的使用错误及举例说明:**

1. **指定不存在的测试用例名称:**
   - 用户执行 `meson test non_existent_test`。
   - `tests_from_args` 方法会抛出 `MesonException`，提示 `non_existent_test` 不匹配任何测试。

2. **指定不存在的测试套件:**
   - 用户在测试设置中指定了排除某个套件，但该套件名称拼写错误。
   - 测试可能会运行不应该被运行的测试用例，因为排除规则没有生效。

3. **命令行选项冲突:**
   - 用户同时指定了 `--gdb` 和 `--wrapper` 选项。
   - `run` 函数会检测到冲突并报错。

4. **忘记设置执行权限:**
   - 测试用例执行的是编译出的可执行文件，但用户忘记添加执行权限。
   - 测试执行会失败，`SingleTestRunner` 可能会捕获到 "Permission denied" 错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户修改 frida 的源代码:** 开发者修改了 frida 的一些核心功能。
2. **用户执行构建命令:** 为了验证修改，开发者需要重新编译 frida。他们会执行类似 `meson compile -C build` 的命令。
3. **用户执行测试命令:**  编译完成后，开发者运行测试命令来验证修改是否引入了 bug，例如 `meson test -C build` 或 `meson test -C build --verbose` 来获取更详细的输出。
4. **`meson test` 解析参数并加载测试框架:** `meson` 命令会解析 `test` 子命令以及相关的选项（例如 `-C build` 指定构建目录）。然后，它会加载 `frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py` 文件，创建 `TestHarness` 对象。
5. **`TestHarness` 加载测试元数据:** `TestHarness` 对象会根据构建目录下的文件（如 `meson-private/meson_test_setup.dat`) 加载测试用例信息。
6. **根据选项过滤测试用例:** 如果用户指定了 `--include-suites` 或特定的测试用例名称，`TestHarness` 会根据这些选项筛选要运行的测试。
7. **`TestHarness` 创建和执行 `SingleTestRunner`:**  对于每个要运行的测试用例，`TestHarness` 会创建一个 `SingleTestRunner` 对象，并调用其 `run` 方法来执行测试。
8. **`SingleTestRunner` 执行测试命令:** `SingleTestRunner` 会执行测试用例中定义的命令（例如运行一个可执行文件或 Python 脚本）。
9. **测试结果处理和报告:** `mtest.py` 中的 `process_test_result` 方法会接收每个测试的运行结果，并更新统计信息，最终生成测试报告。

**这是第3部分，共3部分，请归纳一下它的功能:**

作为测试框架的最后一部分，这段代码主要负责**执行准备好的测试用例并汇总最终的测试结果**。它接收经过筛选和配置的测试用例，利用 `SingleTestRunner` 并发地运行它们，收集每个测试的结果状态、运行时间等信息，并最终生成测试报告，总结测试的成功、失败、跳过和超时情况。它还处理测试执行过程中的各种事件，例如日志记录、信号处理和错误处理，确保测试过程的稳定性和可靠性。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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