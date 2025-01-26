Response:
Let's break down the thought process for analyzing this Go code snippet and generating the comprehensive Chinese response.

**1. Understanding the Request:**

The request asks for an analysis of a specific part of `go/src/testing/testing.go`. Key requirements include:

* **Functionality Listing:** What does this code *do*?
* **Go Feature Identification:** What broader Go feature does this code support?
* **Code Examples:** Illustrate the functionality with Go code.
* **Input/Output Assumptions:**  For code examples, specify inputs and expected outputs.
* **Command-Line Argument Handling:** Detail how command-line flags affect the code.
* **Common Mistakes:** Point out potential pitfalls for users.
* **Chinese Response:** All answers must be in Chinese.
* **Part 3 of 3:** This implies the previous parts likely covered related functionalities. The request explicitly asks for a *summary* of the functionality.

**2. Initial Code Scan and Keyword Recognition:**

I started by quickly scanning the code for important keywords and structures:

* **`testDeps` interface:** This suggests dependencies on other parts of the testing framework.
* **`MainStart` function:** This looks like the entry point for running tests.
* **`M` struct:** This seems to be the central manager for test execution.
* **`Run` method:** This is the core logic for running tests, benchmarks, fuzz targets, and examples.
* **Command-line flags:**  Variables like `parallel`, `matchFuzz`, `shuffle`, `timeout`, `cpuprofile`, `memprofile`, `coverprofile`, etc., immediately indicate command-line argument processing.
* **`runTests`, `runBenchmarks`, `runFuzzTests`, `runExamples`:** These suggest separate execution paths for different types of tests.
* **`before`, `after`:** These hint at setup and teardown logic.
* **Profiling-related code:**  `StartCPUProfile`, `WriteProfileTo`, `trace.Start`, etc., point to profiling capabilities.
* **Coverage-related code:**  `CoverMode`, `coverReport` suggest code coverage functionality.
* **`listTests`:**  This suggests the ability to list available tests.
* **`T` struct and `report` method:** This is likely related to individual test reporting.

**3. Deconstructing `MainStart` and `M`:**

* `MainStart`'s purpose became clear: it initializes the testing environment and creates the `M` instance. The `testDeps` argument is important as it abstracts away the underlying implementation details.
* The `M` struct holds all the necessary data for running tests: dependencies, lists of tests, benchmarks, fuzz targets, and examples.

**4. Analyzing the `Run` Method (The Core):**

This method is the heart of the provided code. I mentally stepped through its logic, paying attention to:

* **Multiple `m.Run()` calls:**  The comment about `m.numRun` highlights an interesting edge case and potential user error (calling `m.Run` multiple times).
* **Flag parsing:**  It handles parsing command-line arguments using the `flag` package.
* **`-v=json` handling:** The logic for redirecting `stderr` to `stdout` when using JSON output is a significant detail.
* **Input validation:** Checks for `-parallel` and `-test.fuzzcachedir`.
* **Listing tests (`-test.list`):**  The `listTests` function's purpose became apparent.
* **Shuffling (`-test.shuffle`):** The random shuffling of tests and benchmarks was identified.
* **CPU list (`-test.cpu`):**  The handling of specifying the number of CPUs to use.
* **`before()` and `after()`:** These clearly mark the setup and teardown phases.
* **Conditional execution:** The `if !*isFuzzWorker` block shows that fuzz workers have a different execution path.
* **Running different test types:** Calls to `runTests`, `runFuzzTests`, `runExamples`, and `runBenchmarks`.
* **Timeout handling:** The `startAlarm` and `stopAlarm` methods relate to the `-timeout` flag.
* **Failure reporting:**  The logic for setting the exit code based on test failures.
* **Fuzzing execution:** The `runFuzzing` call.

**5. Examining Supporting Functions:**

* **`listTests`:**  Clearly lists tests, benchmarks, fuzz targets, and examples based on a matching pattern.
* **`RunTests`:**  A wrapper around `runTests`, primarily for running regular tests.
* **`runTests`:**  The detailed logic for executing individual tests, including handling parallelism (`GOMAXPROCS`), retries (`-count`), and timeouts.
* **`before` and `after`:**  These handle setting up profiling, code coverage, and logging before tests run and writing out the results afterward.
* **`toOutputDir`:**  A utility function for managing output file paths.
* **`startAlarm`, `runningList`, `stopAlarm`:** These functions are specifically related to implementing the test timeout functionality.
* **`parseCpuList`:**  Parses the `-test.cpu` command-line argument.
* **`shouldFailFast`:** Implements the `-failfast` behavior.
* **`report` (within `T`):**  Handles reporting the status (pass, fail, skip) of individual tests.

**6. Connecting to Go Features:**

Based on the identified functionalities, I linked them to relevant Go testing features:

* **Test Execution:** The core functionality.
* **Benchmarks:**  The `-test.bench` flag and `runBenchmarks`.
* **Fuzzing:** The `-test.fuzz` flag and `runFuzzTests`, `runFuzzing`.
* **Examples:**  The handling of example functions.
* **Code Coverage:**  The `-test.coverprofile` and `-test.gocoverdir` flags and the `coverReport` function.
* **Profiling:** The `-test.cpuprofile`, `-test.memprofile`, etc., flags.
* **Parallel Execution:** The `-test.parallel` flag.
* **Test Listing:** The `-test.list` flag.
* **Test Shuffling:** The `-test.shuffle` flag.
* **Timeouts:** The `-test.timeout` flag.
* **Verbose Output:**  Implicitly handled by the `chatty` package.
* **Fail Fast:** The `-test.failfast` flag.

**7. Constructing Code Examples:**

For each identified feature, I thought about how a user would typically interact with it in a test file. This involved creating simple test functions, benchmark functions, fuzzing examples, and examples, and then demonstrating how command-line flags would affect their execution. I considered common scenarios and kept the examples concise and easy to understand.

**8. Identifying Common Mistakes:**

I drew upon my experience with Go testing to identify common pitfalls, focusing on:

* **Incorrect use of `-parallel`:** Understanding its effect on individual test function execution.
* **Misunderstanding `-count`:** Realizing that it reruns the *entire test suite*.
* **Forgetting `-test.run` or `-test.bench` when needed:** Especially when there are many tests or benchmarks.
* **Not understanding the implications of `-test.shuffle`:**  Particularly for debugging.
* **Confusing `-test.coverprofile` and `-test.gocoverdir`:**  Knowing their respective purposes.

**9. Structuring the Chinese Response:**

I organized the response logically, following the structure of the request:

* **功能列举 (Functionality Listing)**
* **Go 语言功能实现 (Go Feature Implementation)**
* **代码举例 (Code Examples)**
* **命令行参数处理 (Command-Line Argument Handling)**
* **使用者易犯错的点 (Common Mistakes)**
* **功能归纳 (Summary)**

Within each section, I used clear and concise Chinese, explaining the concepts and providing relevant details. For command-line arguments, I provided a table for better readability.

**10. Refinement and Review:**

Finally, I reviewed the entire response for clarity, accuracy, and completeness, ensuring that it addressed all aspects of the original request and flowed logically. I paid attention to using correct terminology and providing sufficient detail without being overly verbose. The "Part 3 of 3" prompt was key to focusing on summarizing rather than repeating details from the (hypothetical) previous parts.好的，这是 `go/src/testing/testing.go` 文件的第三部分代码分析。 基于前两部分，我们可以继续归纳其功能。

**功能归纳**

这部分 `testing.go` 代码主要负责 Go 语言测试框架中以下核心功能：

1. **测试执行管理 (Test Execution Management):**
   - 它是 `go test` 命令的核心执行逻辑，通过 `MainStart` 函数接收测试用例、基准测试、模糊测试目标和示例，并使用 `M` 结构体来管理它们的执行。
   - 负责解析命令行参数，如 `-parallel`（并行度）、`-test.run`（运行指定测试）、`-test.bench`（运行指定基准测试）、`-test.fuzz`（运行指定模糊测试目标）、`-count`（运行次数）、`-timeout`（超时时间）等。
   - 实现了测试用例、基准测试和模糊测试目标的随机排序 (`-test.shuffle`)，以帮助发现测试中的依赖性问题。
   - 提供了列出可执行测试、基准测试、模糊测试目标和示例的功能 (`-test.list`)。
   - 管理测试的生命周期，包括在测试开始前执行 `before` 方法，在测试结束后执行 `after` 方法。

2. **测试用例运行 (Test Case Execution):**
   - 实现了 `runTests` 函数，用于执行测试用例。
   - 支持通过 `-test.run` 参数使用正则表达式匹配要运行的测试用例。
   - 支持多次运行同一组测试用例 (`-count`)。
   - 支持并行执行测试用例 (`-parallel`)，并通过 `runtime.GOMAXPROCS` 控制使用的 CPU 核心数。
   - 实现了测试超时的管理，当测试超过指定时间后会触发 panic 并输出正在运行的测试列表。

3. **基准测试运行 (Benchmark Execution):** (尽管这部分代码没有直接展示 `runBenchmarks` 的具体实现，但它被调用了，且 `M` 结构体中包含了 `benchmarks` 字段，因此可以推断)
   - 负责执行基准测试函数。
   - 支持通过 `-test.bench` 参数使用正则表达式匹配要运行的基准测试。

4. **模糊测试运行 (Fuzz Testing Execution):**
   - 实现了 `runFuzzTests` 和 `runFuzzing` 函数，用于执行模糊测试。
   - 支持通过 `-test.fuzz` 参数使用正则表达式匹配要运行的模糊测试目标。
   - 模糊测试支持缓存 (`-test.fuzzcachedir`)。
   - 区分父进程和 worker 进程的模糊测试执行。

5. **示例运行 (Example Execution):** (同样，具体实现未展示，但被调用了)
   - 负责执行示例函数。
   - 支持通过 `-test.run` 参数使用正则表达式匹配要运行的示例。

6. **性能分析支持 (Profiling Support):**
   - 实现了对 CPU 性能分析 (`-test.cpuprofile`)、内存性能分析 (`-test.memprofile`)、阻塞性能分析 (`-test.blockprofile`) 和互斥锁性能分析 (`-test.mutexprofile`) 的支持。
   - 提供了在测试开始前启动性能分析，测试结束后将性能数据写入文件的功能。

7. **代码覆盖率支持 (Code Coverage Support):**
   - 支持生成代码覆盖率报告 (`-test.coverprofile`, `-test.gocoverdir`)，但前提是测试二进制文件在构建时启用了覆盖率功能。

8. **测试日志记录 (Test Logging):**
   - 支持将测试执行的详细日志记录到文件中 (`-testlog`)，供 `cmd/go` 工具使用。

9. **其他辅助功能:**
   - `-test.shuffle`:  随机化测试执行顺序。
   - `-test.failfast`:  在第一个测试失败后立即停止执行。
   - `-test.panic_on_exit0`:  当 `os.Exit(0)` 被调用时触发 panic (用于测试目的)。
   - 对 `-v=json` 命令行参数的处理，将 `stderr` 重定向到 `stdout` 以避免输出交错。

**总结来说，这部分代码是 Go 语言测试框架的核心引擎，它负责解析用户指令，调度和执行各种类型的测试（单元测试、基准测试、模糊测试、示例），并提供性能分析、代码覆盖率等辅助功能，最终生成测试报告并返回执行结果。** 它体现了 `go test` 命令的核心行为和机制。

希望这个归纳对您有所帮助！

Prompt: 
```
这是路径为go/src/testing/testing.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
y, error)
	CheckCorpus([]any, []reflect.Type) error
	ResetCoverage()
	SnapshotCoverage()
	InitRuntimeCoverage() (mode string, tearDown func(coverprofile string, gocoverdir string) (string, error), snapcov func() float64)
}

// MainStart is meant for use by tests generated by 'go test'.
// It is not meant to be called directly and is not subject to the Go 1 compatibility document.
// It may change signature from release to release.
func MainStart(deps testDeps, tests []InternalTest, benchmarks []InternalBenchmark, fuzzTargets []InternalFuzzTarget, examples []InternalExample) *M {
	registerCover2(deps.InitRuntimeCoverage())
	Init()
	return &M{
		deps:        deps,
		tests:       tests,
		benchmarks:  benchmarks,
		fuzzTargets: fuzzTargets,
		examples:    examples,
	}
}

var testingTesting bool
var realStderr *os.File

// Run runs the tests. It returns an exit code to pass to os.Exit.
func (m *M) Run() (code int) {
	defer func() {
		code = m.exitCode
	}()

	// Count the number of calls to m.Run.
	// We only ever expected 1, but we didn't enforce that,
	// and now there are tests in the wild that call m.Run multiple times.
	// Sigh. go.dev/issue/23129.
	m.numRun++

	// TestMain may have already called flag.Parse.
	if !flag.Parsed() {
		flag.Parse()
	}

	if chatty.json {
		// With -v=json, stdout and stderr are pointing to the same pipe,
		// which is leading into test2json. In general, operating systems
		// do a good job of ensuring that writes to the same pipe through
		// different file descriptors are delivered whole, so that writing
		// AAA to stdout and BBB to stderr simultaneously produces
		// AAABBB or BBBAAA on the pipe, not something like AABBBA.
		// However, the exception to this is when the pipe fills: in that
		// case, Go's use of non-blocking I/O means that writing AAA
		// or BBB might be split across multiple system calls, making it
		// entirely possible to get output like AABBBA. The same problem
		// happens inside the operating system kernel if we switch to
		// blocking I/O on the pipe. This interleaved output can do things
		// like print unrelated messages in the middle of a TestFoo line,
		// which confuses test2json. Setting os.Stderr = os.Stdout will make
		// them share a single pfd, which will hold a lock for each program
		// write, preventing any interleaving.
		//
		// It might be nice to set Stderr = Stdout always, or perhaps if
		// we can tell they are the same file, but for now -v=json is
		// a very clear signal. Making the two files the same may cause
		// surprises if programs close os.Stdout but expect to be able
		// to continue to write to os.Stderr, but it's hard to see why a
		// test would think it could take over global state that way.
		//
		// This fix only helps programs where the output is coming directly
		// from Go code. It does not help programs in which a subprocess is
		// writing to stderr or stdout at the same time that a Go test is writing output.
		// It also does not help when the output is coming from the runtime,
		// such as when using the print/println functions, since that code writes
		// directly to fd 2 without any locking.
		// We keep realStderr around to prevent fd 2 from being closed.
		//
		// See go.dev/issue/33419.
		realStderr = os.Stderr
		os.Stderr = os.Stdout
	}

	if *parallel < 1 {
		fmt.Fprintln(os.Stderr, "testing: -parallel can only be given a positive integer")
		flag.Usage()
		m.exitCode = 2
		return
	}
	if *matchFuzz != "" && *fuzzCacheDir == "" {
		fmt.Fprintln(os.Stderr, "testing: -test.fuzzcachedir must be set if -test.fuzz is set")
		flag.Usage()
		m.exitCode = 2
		return
	}

	if *matchList != "" {
		listTests(m.deps.MatchString, m.tests, m.benchmarks, m.fuzzTargets, m.examples)
		m.exitCode = 0
		return
	}

	if *shuffle != "off" {
		var n int64
		var err error
		if *shuffle == "on" {
			n = time.Now().UnixNano()
		} else {
			n, err = strconv.ParseInt(*shuffle, 10, 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, `testing: -shuffle should be "off", "on", or a valid integer:`, err)
				m.exitCode = 2
				return
			}
		}
		fmt.Println("-test.shuffle", n)
		rng := rand.New(rand.NewSource(n))
		rng.Shuffle(len(m.tests), func(i, j int) { m.tests[i], m.tests[j] = m.tests[j], m.tests[i] })
		rng.Shuffle(len(m.benchmarks), func(i, j int) { m.benchmarks[i], m.benchmarks[j] = m.benchmarks[j], m.benchmarks[i] })
	}

	parseCpuList()

	m.before()
	defer m.after()

	// Run tests, examples, and benchmarks unless this is a fuzz worker process.
	// Workers start after this is done by their parent process, and they should
	// not repeat this work.
	if !*isFuzzWorker {
		deadline := m.startAlarm()
		haveExamples = len(m.examples) > 0
		testRan, testOk := runTests(m.deps.MatchString, m.tests, deadline)
		fuzzTargetsRan, fuzzTargetsOk := runFuzzTests(m.deps, m.fuzzTargets, deadline)
		exampleRan, exampleOk := runExamples(m.deps.MatchString, m.examples)
		m.stopAlarm()
		if !testRan && !exampleRan && !fuzzTargetsRan && *matchBenchmarks == "" && *matchFuzz == "" {
			fmt.Fprintln(os.Stderr, "testing: warning: no tests to run")
			if testingTesting && *match != "^$" {
				// If this happens during testing of package testing it could be that
				// package testing's own logic for when to run a test is broken,
				// in which case every test will run nothing and succeed,
				// with no obvious way to detect this problem (since no tests are running).
				// So make 'no tests to run' a hard failure when testing package testing itself.
				fmt.Print(chatty.prefix(), "FAIL: package testing must run tests\n")
				testOk = false
			}
		}
		anyFailed := !testOk || !exampleOk || !fuzzTargetsOk || !runBenchmarks(m.deps.ImportPath(), m.deps.MatchString, m.benchmarks)
		if !anyFailed && race.Errors() > 0 {
			fmt.Print(chatty.prefix(), "testing: race detected outside of test execution\n")
			anyFailed = true
		}
		if anyFailed {
			fmt.Print(chatty.prefix(), "FAIL\n")
			m.exitCode = 1
			return
		}
	}

	fuzzingOk := runFuzzing(m.deps, m.fuzzTargets)
	if !fuzzingOk {
		fmt.Print(chatty.prefix(), "FAIL\n")
		if *isFuzzWorker {
			m.exitCode = fuzzWorkerExitCode
		} else {
			m.exitCode = 1
		}
		return
	}

	m.exitCode = 0
	if !*isFuzzWorker {
		fmt.Print(chatty.prefix(), "PASS\n")
	}
	return
}

func (t *T) report() {
	if t.parent == nil {
		return
	}
	dstr := fmtDuration(t.duration)
	format := "--- %s: %s (%s)\n"
	if t.Failed() {
		t.flushToParent(t.name, format, "FAIL", t.name, dstr)
	} else if t.chatty != nil {
		if t.Skipped() {
			t.flushToParent(t.name, format, "SKIP", t.name, dstr)
		} else {
			t.flushToParent(t.name, format, "PASS", t.name, dstr)
		}
	}
}

func listTests(matchString func(pat, str string) (bool, error), tests []InternalTest, benchmarks []InternalBenchmark, fuzzTargets []InternalFuzzTarget, examples []InternalExample) {
	if _, err := matchString(*matchList, "non-empty"); err != nil {
		fmt.Fprintf(os.Stderr, "testing: invalid regexp in -test.list (%q): %s\n", *matchList, err)
		os.Exit(1)
	}

	for _, test := range tests {
		if ok, _ := matchString(*matchList, test.Name); ok {
			fmt.Println(test.Name)
		}
	}
	for _, bench := range benchmarks {
		if ok, _ := matchString(*matchList, bench.Name); ok {
			fmt.Println(bench.Name)
		}
	}
	for _, fuzzTarget := range fuzzTargets {
		if ok, _ := matchString(*matchList, fuzzTarget.Name); ok {
			fmt.Println(fuzzTarget.Name)
		}
	}
	for _, example := range examples {
		if ok, _ := matchString(*matchList, example.Name); ok {
			fmt.Println(example.Name)
		}
	}
}

// RunTests is an internal function but exported because it is cross-package;
// it is part of the implementation of the "go test" command.
func RunTests(matchString func(pat, str string) (bool, error), tests []InternalTest) (ok bool) {
	var deadline time.Time
	if *timeout > 0 {
		deadline = time.Now().Add(*timeout)
	}
	ran, ok := runTests(matchString, tests, deadline)
	if !ran && !haveExamples {
		fmt.Fprintln(os.Stderr, "testing: warning: no tests to run")
	}
	return ok
}

func runTests(matchString func(pat, str string) (bool, error), tests []InternalTest, deadline time.Time) (ran, ok bool) {
	ok = true
	for _, procs := range cpuList {
		runtime.GOMAXPROCS(procs)
		for i := uint(0); i < *count; i++ {
			if shouldFailFast() {
				break
			}
			if i > 0 && !ran {
				// There were no tests to run on the first
				// iteration. This won't change, so no reason
				// to keep trying.
				break
			}
			ctx, cancelCtx := context.WithCancel(context.Background())
			tstate := newTestState(*parallel, newMatcher(matchString, *match, "-test.run", *skip))
			tstate.deadline = deadline
			t := &T{
				common: common{
					signal:    make(chan bool, 1),
					barrier:   make(chan bool),
					w:         os.Stdout,
					ctx:       ctx,
					cancelCtx: cancelCtx,
				},
				tstate: tstate,
			}
			if Verbose() {
				t.chatty = newChattyPrinter(t.w)
			}
			tRunner(t, func(t *T) {
				for _, test := range tests {
					t.Run(test.Name, test.F)
				}
			})
			select {
			case <-t.signal:
			default:
				panic("internal error: tRunner exited without sending on t.signal")
			}
			ok = ok && !t.Failed()
			ran = ran || t.ran
		}
	}
	return ran, ok
}

// before runs before all testing.
func (m *M) before() {
	if *memProfileRate > 0 {
		runtime.MemProfileRate = *memProfileRate
	}
	if *cpuProfile != "" {
		f, err := os.Create(toOutputDir(*cpuProfile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			return
		}
		if err := m.deps.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't start cpu profile: %s\n", err)
			f.Close()
			return
		}
		// Could save f so after can call f.Close; not worth the effort.
	}
	if *traceFile != "" {
		f, err := os.Create(toOutputDir(*traceFile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			return
		}
		if err := trace.Start(f); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't start tracing: %s\n", err)
			f.Close()
			return
		}
		// Could save f so after can call f.Close; not worth the effort.
	}
	if *blockProfile != "" && *blockProfileRate >= 0 {
		runtime.SetBlockProfileRate(*blockProfileRate)
	}
	if *mutexProfile != "" && *mutexProfileFraction >= 0 {
		runtime.SetMutexProfileFraction(*mutexProfileFraction)
	}
	if *coverProfile != "" && CoverMode() == "" {
		fmt.Fprintf(os.Stderr, "testing: cannot use -test.coverprofile because test binary was not built with coverage enabled\n")
		os.Exit(2)
	}
	if *gocoverdir != "" && CoverMode() == "" {
		fmt.Fprintf(os.Stderr, "testing: cannot use -test.gocoverdir because test binary was not built with coverage enabled\n")
		os.Exit(2)
	}
	if *testlog != "" {
		// Note: Not using toOutputDir.
		// This file is for use by cmd/go, not users.
		var f *os.File
		var err error
		if m.numRun == 1 {
			f, err = os.Create(*testlog)
		} else {
			f, err = os.OpenFile(*testlog, os.O_WRONLY, 0)
			if err == nil {
				f.Seek(0, io.SeekEnd)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		testlogFile = f
	}
	if *panicOnExit0 {
		m.deps.SetPanicOnExit0(true)
	}
}

// after runs after all testing.
func (m *M) after() {
	m.afterOnce.Do(func() {
		m.writeProfiles()
	})

	// Restore PanicOnExit0 after every run, because we set it to true before
	// every run. Otherwise, if m.Run is called multiple times the behavior of
	// os.Exit(0) will not be restored after the second run.
	if *panicOnExit0 {
		m.deps.SetPanicOnExit0(false)
	}
}

func (m *M) writeProfiles() {
	if *testlog != "" {
		if err := m.deps.StopTestLog(); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't write %s: %s\n", *testlog, err)
			os.Exit(2)
		}
		if err := testlogFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't write %s: %s\n", *testlog, err)
			os.Exit(2)
		}
	}
	if *cpuProfile != "" {
		m.deps.StopCPUProfile() // flushes profile to disk
	}
	if *traceFile != "" {
		trace.Stop() // flushes trace to disk
	}
	if *memProfile != "" {
		f, err := os.Create(toOutputDir(*memProfile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			os.Exit(2)
		}
		runtime.GC() // materialize all statistics
		if err = m.deps.WriteProfileTo("allocs", f, 0); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't write %s: %s\n", *memProfile, err)
			os.Exit(2)
		}
		f.Close()
	}
	if *blockProfile != "" && *blockProfileRate >= 0 {
		f, err := os.Create(toOutputDir(*blockProfile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			os.Exit(2)
		}
		if err = m.deps.WriteProfileTo("block", f, 0); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't write %s: %s\n", *blockProfile, err)
			os.Exit(2)
		}
		f.Close()
	}
	if *mutexProfile != "" && *mutexProfileFraction >= 0 {
		f, err := os.Create(toOutputDir(*mutexProfile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "testing: %s\n", err)
			os.Exit(2)
		}
		if err = m.deps.WriteProfileTo("mutex", f, 0); err != nil {
			fmt.Fprintf(os.Stderr, "testing: can't write %s: %s\n", *mutexProfile, err)
			os.Exit(2)
		}
		f.Close()
	}
	if CoverMode() != "" {
		coverReport()
	}
}

// toOutputDir returns the file name relocated, if required, to outputDir.
// Simple implementation to avoid pulling in path/filepath.
func toOutputDir(path string) string {
	if *outputDir == "" || path == "" {
		return path
	}
	// On Windows, it's clumsy, but we can be almost always correct
	// by just looking for a drive letter and a colon.
	// Absolute paths always have a drive letter (ignoring UNC).
	// Problem: if path == "C:A" and outputdir == "C:\Go" it's unclear
	// what to do, but even then path/filepath doesn't help.
	// TODO: Worth doing better? Probably not, because we're here only
	// under the management of go test.
	if runtime.GOOS == "windows" && len(path) >= 2 {
		letter, colon := path[0], path[1]
		if ('a' <= letter && letter <= 'z' || 'A' <= letter && letter <= 'Z') && colon == ':' {
			// If path starts with a drive letter we're stuck with it regardless.
			return path
		}
	}
	if os.IsPathSeparator(path[0]) {
		return path
	}
	return fmt.Sprintf("%s%c%s", *outputDir, os.PathSeparator, path)
}

// startAlarm starts an alarm if requested.
func (m *M) startAlarm() time.Time {
	if *timeout <= 0 {
		return time.Time{}
	}

	deadline := time.Now().Add(*timeout)
	m.timer = time.AfterFunc(*timeout, func() {
		m.after()
		debug.SetTraceback("all")
		extra := ""

		if list := runningList(); len(list) > 0 {
			var b strings.Builder
			b.WriteString("\nrunning tests:")
			for _, name := range list {
				b.WriteString("\n\t")
				b.WriteString(name)
			}
			extra = b.String()
		}
		panic(fmt.Sprintf("test timed out after %v%s", *timeout, extra))
	})
	return deadline
}

// runningList returns the list of running tests.
func runningList() []string {
	var list []string
	running.Range(func(k, v any) bool {
		list = append(list, fmt.Sprintf("%s (%v)", k.(string), highPrecisionTimeSince(v.(highPrecisionTime)).Round(time.Second)))
		return true
	})
	slices.Sort(list)
	return list
}

// stopAlarm turns off the alarm.
func (m *M) stopAlarm() {
	if *timeout > 0 {
		m.timer.Stop()
	}
}

func parseCpuList() {
	for _, val := range strings.Split(*cpuListStr, ",") {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		cpu, err := strconv.Atoi(val)
		if err != nil || cpu <= 0 {
			fmt.Fprintf(os.Stderr, "testing: invalid value %q for -test.cpu\n", val)
			os.Exit(1)
		}
		cpuList = append(cpuList, cpu)
	}
	if cpuList == nil {
		cpuList = append(cpuList, runtime.GOMAXPROCS(-1))
	}
}

func shouldFailFast() bool {
	return *failFast && numFailed.Load() > 0
}

"""




```