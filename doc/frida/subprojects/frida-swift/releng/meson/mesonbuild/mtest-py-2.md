Response:
My thinking process to analyze the Python code and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Python code snippet, which is part of the `mesonbuild/mtest.py` file within the Frida project. They are particularly interested in its relevance to reverse engineering, interaction with low-level systems (kernel, etc.), logical reasoning, potential user errors, and debugging context.

2. **Identify the Core Functionality:** I start by scanning the class `TestHarness` and its methods. The names like `load_tests`, `run_tests`, `process_test_result`, `get_test_runner`, and `prepare_build` immediately suggest this code is responsible for *running and managing tests*. The surrounding code, like `list_tests`, `rebuild_deps`, and the `run` function, reinforces this idea.

3. **Break Down Key Methods:**  I go through the most important methods to understand their specific roles:
    * `metadata()`: Collects and organizes test suite information.
    * `prepare_build()`: Detects and ensures Ninja build system is available for rebuilding if needed.
    * `load_metadata()`: Loads build and test metadata, potentially triggering a rebuild if necessary.
    * `load_tests()`: Reads test definitions from a file.
    * `get_test_setup()`: Retrieves configuration settings for tests.
    * `merge_setup_options()`: Combines command-line options with test-specific setup options.
    * `get_test_runner()`: Creates an object responsible for running a single test.
    * `process_test_result()`: Handles the outcome of a test run (pass, fail, skip, etc.).
    * `run_tests()` and `_run_tests()`: The core logic for executing tests, managing concurrency, and handling interruptions.
    * `test_suitable()` and `tests_from_args()`: Methods for selecting which tests to run based on filters.
    * `rebuild_deps()`: Rebuilds dependencies before running tests.
    * `run()`: The main entry point for running tests.

4. **Relate to Reverse Engineering:** I consider how testing frameworks relate to reverse engineering. While the code *doesn't directly perform reverse engineering*, it's crucial for validating tools like Frida that *are* used in reverse engineering. Frida modifies running processes, and tests ensure these modifications work as expected without unintended side effects. This leads to the example of testing Frida's ability to hook a function.

5. **Identify Low-Level Interactions:** I look for keywords and concepts that indicate interaction with the operating system or lower levels:
    * `subprocess`:  Indicates interaction with external processes, likely the compiled test executables.
    * `os` module:  Used for file system operations and environment manipulation.
    * `asyncio`: Suggests asynchronous execution, potentially involving system calls or waiting for external events.
    * `ninja`:  A build system, implying compilation and linking of binaries.
    * Environment variables (`os.environ`):  Used to configure the test environment, potentially influencing how binaries are loaded and executed.
    * Mentions of Linux, Android (implicitly through Frida's context):  While not explicitly in this code, the surrounding context of Frida suggests these platforms are targets.

6. **Analyze Logical Reasoning:** I examine parts of the code that involve decision-making and filtering:
    * `test_suitable()`:  Makes decisions about whether to run a test based on include/exclude lists and setup configurations.
    * `tests_from_args()`:  Parses command-line arguments to select specific tests using wildcards.
    * The logic within `_run_tests()` for handling concurrency, timeouts, and interruptions.

7. **Consider User Errors:** I think about common mistakes users might make when interacting with a testing framework:
    * Incorrect test names or patterns in command-line arguments.
    * Specifying incompatible options (e.g., both `--wrapper` and `--gdb`).
    * Problems with the build environment (e.g., missing Ninja).

8. **Trace User Actions:** I imagine the steps a user would take to reach this code:
    1. Install Frida and its development dependencies.
    2. Navigate to the Frida source code directory.
    3. Run the `meson test` command (or a similar command that invokes the test suite).
    4. Meson, the build system, then executes scripts like `mtest.py` to discover and run the tests.

9. **Synthesize and Structure the Answer:** Finally, I organize my findings into the requested categories: functionality, reverse engineering relevance, low-level interactions, logical reasoning, user errors, and user journey. I provide concrete examples to illustrate each point.

10. **Address the "歸納一下它的功能" (Summarize its function) request:**  For the last part, I provide a concise summary highlighting the key responsibilities of the code.

By following this systematic approach, I can dissect the code, understand its purpose within the larger Frida project, and address the user's specific questions effectively. The key is to move from a general understanding to specific details, focusing on the relationships between different parts of the code and their implications for reverse engineering and system interaction.
好的，让我们来分析一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/mtest.py` 这个文件的功能。由于这是第三部分，我将重点总结之前的功能并结合这部分代码进行归纳。

**功能归纳总结 (基于全部三部分代码):**

`mtest.py` 是 Frida 项目中用于执行和管理测试的脚本，它是 Meson 构建系统的一部分。其主要功能可以归纳为：

1. **测试发现与加载:**
   - 能够从 Meson 的构建输出中加载测试用例的元数据（测试名称、依赖、环境等）。
   - 支持加载不同类型的测试设置数据（benchmark 或常规测试）。
   - 允许通过命令行参数指定要运行的特定测试用例或测试套件。

2. **测试准备与构建:**
   - 检查 Ninja 构建系统是否可用，用于在运行测试前重新构建必要的组件。
   - 能够在运行测试前根据测试依赖重新构建相关的目标文件。
   - 支持配置测试运行的环境变量，可以合并来自测试设置和命令行选项的环境变量。

3. **测试执行与管理:**
   - 创建并管理单个测试用例的运行器 (`SingleTestRunner`)。
   - 支持串行或并行执行测试用例，可以通过 `--num-processes` 控制并行度。
   - 能够处理测试超时，并设置超时乘数。
   - 支持在 GDB 调试器下运行测试。
   - 支持使用自定义的执行包装器 (wrapper)。
   - 可以重复运行测试多次 (`--repeat`)。

4. **测试结果处理与报告:**
   - 跟踪测试运行的结果 (成功、失败、跳过、超时等)。
   - 记录测试运行的详细信息，包括输出、错误信息和持续时间。
   - 可以将测试结果输出到不同的日志文件（JUnit XML, JSON, 文本）。
   - 提供测试结果的摘要报告，显示各种状态的测试数量。
   - 支持在发生一定数量的失败后停止测试 (`--maxfail`)。

5. **测试过滤与选择:**
   - 允许通过命令行参数 (`--include-suites`, `--exclude-suites`) 指定包含或排除的测试套件。
   - 支持通过命令行参数直接指定要运行的测试名称或模式。

6. **用户交互与控制:**
   - 能够处理 Ctrl-C 中断信号，可以优雅地停止当前运行的测试或立即退出。
   - 提供命令行选项来配置测试运行的各种行为。

**本部分代码的功能详解:**

这部分代码主要集中在 `TestHarness` 类的实现，以及一些辅助函数如 `list_tests`, `rebuild_deps`, 和 `run`。

* **`metadata()`:**  遍历所有测试用例，收集并去重它们所属的测试套件 (suite) 名称。
* **`get_console_logger()`:**  返回用于控制台输出的日志记录器。
* **`prepare_build()`:** 检查 Ninja 构建系统是否存在，如果不存在则退出。
* **`load_metadata()`:**  切换到构建目录，检查是否需要重新构建，加载构建数据和测试设置数据。
* **`load_tests()`:** 从指定的 `meson-private` 目录下的文件中加载序列化后的测试用例对象。
* **`__enter__` 和 `__exit__`:**  用于实现 `with` 语句，方便管理日志文件的打开和关闭。
* **`close_logfiles()`:** 关闭所有打开的日志文件。
* **`get_test_setup()`:** 根据选项和测试用例信息获取对应的测试设置。
* **`merge_setup_options()`:**  合并命令行选项和测试设置中的选项，处理 GDB 和 wrapper 的冲突。
* **`get_test_runner()`:**  创建 `SingleTestRunner` 实例，负责运行单个测试，并传递测试用例、环境变量和选项。
* **`process_test_result()`:**  根据测试结果更新各种计数器，并将结果记录到日志中。
* **`numlen` 和 `max_left_width`:**  用于格式化测试输出的辅助属性。
* **`get_test_num_prefix()`:**  生成测试序号前缀，用于格式化输出。
* **`format()`:**  格式化单个测试结果的输出字符串，包含测试序号、名称、结果和持续时间。
* **`summary()`:**  生成测试结果的摘要信息。
* **`total_failure_count()`:**  计算总的失败测试数量。
* **`doit()`:**  这是测试执行的主方法。它获取要运行的测试用例，并在必要时重新构建依赖，然后调用 `run_tests` 执行测试。
* **`split_suite_string()` 和 `test_in_suites()`:**  用于处理和匹配测试套件名称。
* **`test_suitable()`:**  判断一个测试用例是否符合当前的过滤条件（包含/排除套件）。
* **`tests_from_args()`:**  根据命令行参数指定的测试名称或模式，筛选出要运行的测试用例。
* **`get_tests()`:**  获取所有符合条件的测试用例。
* **`flush_logfiles()` 和 `open_logfiles()`:**  用于管理日志文件的刷新和打开。
* **`get_wrapper()`:**  根据命令行选项构建执行包装器的命令列表 (例如，GDB)。
* **`get_pretty_suite()`:**  生成更易读的测试套件名称。
* **`run_tests()` 和 `_run_tests()`:**  使用 `asyncio` 异步执行测试用例，管理并发，处理中断信号。
* **`log_subtest()` 和 `log_start_test()`:**  记录子测试和测试开始的事件到日志。
* **`list_tests()`:**  列出所有符合条件的测试用例的名称。
* **`rebuild_deps()`:**  在运行测试前，根据测试用例的依赖关系重新构建相关的构建目标。
* **`run()` 和 `run_with_args()`:**  解析命令行参数，创建 `TestHarness` 实例，并执行测试。

**与逆向方法的关联及举例说明:**

这个脚本本身并不直接执行逆向操作，但它是 Frida 测试框架的核心部分，而 Frida 是一个动态插桩工具，广泛用于逆向工程。

**举例说明:**

假设 Frida 的一个功能是能够 hook Swift 函数。这个脚本就会被用来测试这个功能是否正常工作。

1. **测试用例定义:**  会有一个测试用例 (在 `meson_test_setup.dat` 中定义) 包含一个需要被 hook 的 Swift 函数。
2. **测试执行:** `mtest.py` 会执行这个测试用例，该用例会使用 Frida API 来 hook 目标 Swift 函数。
3. **验证:** 测试用例会验证 hook 是否成功，例如，当目标函数被调用时，hook 是否被触发，并且能够修改函数的行为或获取相关信息。

**涉及二进制底层、Linux/Android 内核及框架的知识的举例说明:**

* **二进制底层:**  `rebuild_deps()` 函数通过 Ninja 重新构建测试所需的二进制文件。这些二进制文件可能包含编译后的 Swift 代码，涉及到目标平台的 ABI (Application Binary Interface) 和指令集。
* **Linux/Android 内核及框架:**
    * 当 Frida hook 一个函数时，它会在目标进程的内存中修改指令。测试用例的执行会涉及到操作系统加载和执行二进制文件的过程，以及进程内存管理等内核知识。
    * 在 Android 平台上，Frida 经常用于 hook Android Runtime (ART) 或 Native 代码。测试用例可能需要模拟 Android 特有的环境或调用特定的 Android Framework API。
    * `get_wrapper()` 函数中可以使用 `gdb`，这是一个底层的调试工具，可以直接操作进程的内存和寄存器。

**逻辑推理的假设输入与输出:**

假设我们有以下命令行输入：

```bash
meson test --include-suites "MySuite" "OtherProject:AnotherSuite" MyTest
```

**假设输入:**

* `self.tests`:  一个包含多个 `TestSerialisation` 对象的列表，代表所有已定义的测试用例。
* `self.options.include_suites`: `["MySuite", "OtherProject:AnotherSuite"]`
* `self.options.args`: `["MyTest"]`

**逻辑推理过程 (在 `get_tests()` 和相关函数中):**

1. **`test_suitable()` 过滤:**
   - 遍历 `self.tests` 中的每个测试用例 `t`。
   - 对于每个 `t`，检查 `TestHarness.test_in_suites(t, self.options.include_suites)`。
   - 如果 `t` 的套件是 "MySuite" (不带项目名) 或 "OtherProject:AnotherSuite"，则该测试通过第一层过滤。

2. **`tests_from_args()` 过滤:**
   - 将 `self.options.args` 转换为模式：`{('*', 'MyTest'): False}`。
   - 再次遍历通过 `test_suitable()` 过滤的测试用例。
   - 如果测试用例的名称匹配 "MyTest" (不考虑项目名)，则该测试通过第二层过滤。

**假设输出 (`get_tests()` 的返回值):**

一个 `TestSerialisation` 对象的列表，其中包含：

* 所有属于 "MySuite" 套件的测试用例。
* 所有属于 "OtherProject" 项目下 "AnotherSuite" 套件的测试用例。
* 所有名称为 "MyTest" 的测试用例（无论属于哪个套件或项目）。

**用户或编程常见的使用错误举例说明:**

1. **错误的测试名称或套件名称:** 用户在命令行中指定的测试名称或套件名称与实际定义的名称不符，导致没有测试被执行。
   ```bash
   meson test MyTst  # 应该为 MyTest
   meson test UnknowSuite:MyTest
   ```

2. **同时指定冲突的选项:** 用户同时使用了互斥的选项，例如同时指定了 `--wrapper` 和 `--gdb`。`merge_setup_options()` 函数会检测到这种冲突并报错退出。

3. **忘记构建或构建失败:** 用户在修改代码后直接运行测试，但没有先进行构建，或者构建过程中出现错误，导致测试依赖的二进制文件不存在或不正确。`prepare_build()` 和 `rebuild_deps()` 的存在是为了避免这种情况，但如果 Ninja 不可用，则会提示错误。

4. **在错误的目录下运行 `meson test`:** 用户在非构建目录下运行 `meson test`，导致无法找到 `meson-private` 目录和相关的测试数据文件。`load_metadata()` 中的检查会抛出 `TestException`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户修改了 Frida Swift 相关的代码。**
2. **用户想要验证他们的修改是否正确，或者是否有引入新的 bug。**
3. **用户在 Frida 的构建目录下打开终端。**
4. **用户输入命令 `meson test` (或带有特定选项的 `meson test ...`) 并执行。**
5. **Meson 构建系统解析用户的命令。**
6. **Meson 调用 `mtest.py` 脚本，并将相关的命令行参数传递给它。**
7. **`mtest.py` 脚本开始执行，首先会创建 `TestHarness` 对象。**
8. **根据用户的选项，`TestHarness` 对象会调用各种方法，例如 `load_metadata()`, `get_tests()`, `run_tests()` 等来加载、过滤和执行测试用例。**
9. **在测试执行过程中，如果出现错误，用户可以通过查看控制台输出或日志文件来获取调试信息。**

希望这个详细的分析能够帮助你理解 `mtest.py` 脚本的功能。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mtest.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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