Response:
Let's break down the thought process for analyzing the provided Go documentation snippet and generating the answer.

**1. Understanding the Request:**

The core request is to analyze a Go file snippet (even though it's just a comment block) and determine its function within the `go` command. Specifically, it asks for:

* **Functionality:** What does this code *do* or what is it *about*?
* **Go Language Feature:**  What Go feature does it relate to?
* **Code Example:** Illustrate the feature with Go code, including assumptions and outputs.
* **Command-Line Arguments:** Detail any relevant command-line arguments.
* **Common Mistakes:** Highlight potential pitfalls for users.
* **Summary:** A concise overview of the functionality.
* **Context:**  Remember this is part 5 of 5, implying we've already processed previous parts (although we only have this part).

**2. Initial Scan and Keyword Identification:**

My first pass through the text focuses on identifying keywords and themes. I see:

* Package names (`main`, `documentation`)
* Module paths (e.g., `github.com/user/repo/http`)
* Environment variables (`GOPRIVATE`, `GOPROXY`, `GONOPROXY`, `GONOSUMDB`, `GOVCS`)
* `go test` command and its flags (`-bench`, `-cover`, `-cpu`, `-run`, etc.)
* Testing concepts (tests, benchmarks, fuzzing, examples)
* Version control systems (git, hg, bzr, fossil, svn)
* `go get` command

**3. Grouping and Categorizing Information:**

The identified keywords naturally fall into several categories:

* **Package Management and Modules:** The sections on package naming, reserved names, and environment variables related to module downloads (GOPRIVATE, etc.) clearly belong here.
* **Testing:** The extensive section on `go test` flags is a major part of the document. This includes different types of tests (unit, benchmark, fuzz), coverage analysis, and profiling.
* **Version Control:** The `GOVCS` section explicitly discusses how Go interacts with different version control systems.

**4. Inferring the File's Purpose (`alldocs.go`):**

The file name `alldocs.go` within the `cmd/go` directory strongly suggests that this file is responsible for generating or containing a comprehensive documentation resource for the `go` command. The content itself reinforces this idea – it reads like a detailed manual page or help text.

**5. Detailed Analysis of Each Section:**

Now I go through each section more carefully, extracting specific details and understanding their implications:

* **Package Names:**  The distinction between `main` (commands) and `documentation` is important. The special case of single-directory compilation is a niche but relevant detail.
* **Ignoring Files/Directories:**  The rules for ignoring `.` and `_` prefixed names and `testdata` directories are standard Go conventions.
* **Module Configuration (GOPRIVATE, etc.):**  I focus on how these variables control the interaction with module proxies and checksum databases, particularly for private modules. The examples provided in the text are helpful.
* **`go test` Flags:** This is the largest section. I identify the categories of flags (controlling test execution, profiling) and note the specific functionalities of many individual flags. The explanation of how `go test` rewrites flags is a key piece of information.
* **Testing Functions:**  I note the naming conventions for test, benchmark, fuzz, and example functions, and the special syntax for example output verification.
* **Version Control (GOVCS):**  I analyze how `GOVCS` allows fine-grained control over which VCS can be used for different module paths, focusing on the security implications and the default behavior.

**6. Addressing Specific Request Points:**

* **Functionality:**  Based on the analysis, the primary function is to provide comprehensive documentation for the `go` command, particularly focusing on package management, testing, and version control.
* **Go Feature:** The most prominent feature is the `go` command itself and its subcommands like `go test` and `go get`. Module management is another key feature.
* **Code Example:**  Since the snippet is documentation, a direct code implementation within this file isn't the point. Instead, I focus on illustrating how the documented *features* are used in Go code. This leads to examples of package declaration, environment variable usage, and `go test` commands. I make sure to provide sample input and expected output for the code example.
* **Command-Line Arguments:**  The `go test` section provides numerous examples of command-line arguments. I pick a few relevant ones to demonstrate their usage.
* **Common Mistakes:** I think about what users might misunderstand or get wrong based on the documentation. This leads to points about the `-args` flag and the distinction between `go test` flags and test binary flags.
* **Summary:** I condense the key functionalities into a brief overview.

**7. Iteration and Refinement:**

After drafting the initial answer, I review it for clarity, accuracy, and completeness. I ensure that the code examples are correct and easy to understand. I double-check that I've addressed all parts of the original request.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the `alldocs.go` file itself as a *program*. However, realizing it's within the `cmd/go` directory and contains extensive documentation, I shift my focus to its role as a documentation source rather than a piece of executable code. This leads to the understanding that the "functionality" is about *documenting* features, not implementing them directly in this file. This also informs the type of "code example" I provide – illustrating the *use* of the documented features.
这是 `go/src/cmd/go/alldocs.go` 文件的一部分内容，它实际上是 Go 语言 `go` 命令的 **帮助文档** 的一部分。更具体地说，它包含了 `go` 命令各种功能和概念的详细解释。

**功能归纳:**

这段文本的主要功能是作为 `go` 命令的参考文档，涵盖了以下几个核心方面：

1. **包管理和模块:**  解释了 Go 语言中包的命名规则，包括 `main` 和 `documentation` 这两个特殊包的含义。还介绍了如何使用模块来管理依赖，以及与下载非公开代码相关的配置（`GOPRIVATE`, `GOPROXY`, `GONOPROXY`, `GONOSUMDB` 等环境变量）。

2. **测试 (`go test`):**  详细列出了 `go test` 命令的各种标志及其作用，这些标志用于控制测试的执行方式、性能分析、覆盖率分析、模糊测试等。

3. **版本控制 (`GOVCS`):**  解释了 `GOVCS` 环境变量的作用，它允许用户控制 `go get` 命令在下载代码时可以使用的版本控制系统，以提高安全性。

**它是什么go语言功能的实现:**

虽然这段代码本身不是一个直接的 Go 语言功能的实现，但它是对 Go 语言核心功能（如包管理、测试和版本控制）的详细说明。  可以将它看作是 Go 工具链中“帮助”功能的实现基础数据。当你在命令行输入 `go help <topic>` 时，或者只是 `go` 或 `go help`，相关的信息就会从类似这样的文档中提取并展示出来。

**Go代码举例说明 (基于文档内容推理):**

虽然 `alldocs.go` 本身不是可执行的 Go 代码，但我们可以根据它描述的功能来举例说明。

**例子 1: 使用 `GOPRIVATE` 环境变量**

假设你有一个私有的 Git 仓库托管在 `git.internal.example.com` 上，你的 Go 模块路径以 `internal.example.com/` 开头。你需要设置 `GOPRIVATE` 环境变量来指示 Go 命令不要通过公共代理或校验和数据库下载这些模块。

**假设的输入 (命令行):**

```bash
export GOPRIVATE=internal.example.com/*
go get internal.example.com/myprivatemodule
```

**推理的输出 (go get 的行为):**

`go get` 命令会识别到 `internal.example.com/myprivatemodule` 匹配 `GOPRIVATE` 的模式，因此会尝试直接从 `git.internal.example.com` 下载，而不会尝试使用公共代理。

**例子 2: 使用 `go test` 的 `-bench` 标志运行基准测试**

假设你有一个名为 `benchmark_test.go` 的测试文件，其中包含一个名为 `BenchmarkMyFunction` 的基准测试函数。

**benchmark_test.go:**

```go
package mypackage

import "testing"

func BenchmarkMyFunction(b *testing.B) {
    for i := 0; i < b.N; i++ {
        // 要进行基准测试的代码
    }
}
```

**假设的输入 (命令行):**

```bash
go test -bench=.
```

**推理的输出 (终端输出):**

```
goos: linux
goarch: amd64
pkg: mypackage
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkMyFunction-20    	10000000	       100.0 ns/op
PASS
ok  	mypackage	1.052s
```

这个输出显示了 `BenchmarkMyFunction` 在多次迭代后的性能数据。

**命令行参数的具体处理:**

`alldocs.go` (作为文档) 详细描述了 `go test` 命令的各种标志。  `go` 命令本身在解析命令行参数时，会识别这些标志，并根据其定义执行相应的操作。

例如，当 `go test` 命令遇到 `-v` 标志时，它会设置一个内部的 verbose 标志，导致测试运行时输出更详细的信息。 当遇到 `-coverprofile cover.out` 时，它会指示测试运行完毕后生成一个覆盖率报告并保存到 `cover.out` 文件中。

`go` 命令的参数解析逻辑比较复杂，它需要区分哪些是 `go` 命令自身的标志，哪些是要传递给测试二进制文件的标志。  `-args` 标志就是一个例子，它可以将后面的所有参数直接传递给测试二进制文件，而不会被 `go test` 命令解析。

**使用者易犯错的点:**

1. **混淆 `go test` 标志和测试二进制文件的标志:**  用户可能会不清楚哪些标志是 `go test` 命令本身处理的，哪些是传递给编译后的测试二进制文件的。例如，`-cpuprofile` 在 `go test` 命令中会被识别并处理，但在直接运行测试二进制文件时需要加上 `test.` 前缀，变成 `-test.cpuprofile`。

   **错误示例:**

   ```bash
   go test -cpuprofile=prof.out  # 正确
   ./mypackage.test -cpuprofile=prof.out # 错误，应该使用 -test.cpuprofile
   ```

2. **不理解 `-args` 的作用:**  用户可能想传递一些特定的参数给测试函数，但错误地将这些参数放在 `go test` 标志的前面，导致 `go test` 将其解析为包名或未知的标志。

   **错误示例:**

   假设你的测试需要一个名为 `myinput.txt` 的文件作为输入：

   ```bash
   go test myinput.txt  # 错误，go test 会认为 myinput.txt 是一个包名
   go test -args myinput.txt # 正确，myinput.txt 会传递给测试二进制文件
   ```

3. **对 `-run` 和 `-skip` 的正则表达式理解不足:**  `go test` 使用斜杠 `/` 来分隔正则表达式的不同部分，以便匹配子测试。用户可能会不清楚如何编写正则表达式来精确地选择或排除特定的测试。

   **错误示例:**

   假设有一个测试函数 `TestA`，其中包含子测试 `TestA/sub1` 和 `TestA/sub2`。

   ```bash
   go test -run=TestA/sub  # 可能会意外地运行 TestA
   go test -run=TestA/sub1 # 只会运行 TestA/sub1
   ```

**总结 `alldocs.go` 的功能:**

`go/src/cmd/go/alldocs.go` 的核心功能是 **提供 `go` 命令及其子命令（如 `go test` 和 `go get`）的详细帮助文档**。它包含了关于包管理、模块、测试、版本控制等关键概念的解释和使用说明，是 Go 语言工具链的重要组成部分，帮助开发者理解和使用 Go 语言的各种功能。这段代码片段正是这些文档内容的其中一部分。

Prompt: 
```
这是路径为go/src/cmd/go/alldocs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共5部分，请归纳一下它的功能

"""
pattern:
// 'github.com/user/repo/http'.
//
// Packages in a program need not have unique package names,
// but there are two reserved package names with special meaning.
// The name main indicates a command, not a library.
// Commands are built into binaries and cannot be imported.
// The name documentation indicates documentation for
// a non-Go program in the directory. Files in package documentation
// are ignored by the go command.
//
// As a special case, if the package list is a list of .go files from a
// single directory, the command is applied to a single synthesized
// package made up of exactly those files, ignoring any build constraints
// in those files and ignoring any other files in the directory.
//
// Directory and file names that begin with "." or "_" are ignored
// by the go tool, as are directories named "testdata".
//
// # Configuration for downloading non-public code
//
// The go command defaults to downloading modules from the public Go module
// mirror at proxy.golang.org. It also defaults to validating downloaded modules,
// regardless of source, against the public Go checksum database at sum.golang.org.
// These defaults work well for publicly available source code.
//
// The GOPRIVATE environment variable controls which modules the go command
// considers to be private (not available publicly) and should therefore not use
// the proxy or checksum database. The variable is a comma-separated list of
// glob patterns (in the syntax of Go's path.Match) of module path prefixes.
// For example,
//
//	GOPRIVATE=*.corp.example.com,rsc.io/private
//
// causes the go command to treat as private any module with a path prefix
// matching either pattern, including git.corp.example.com/xyzzy, rsc.io/private,
// and rsc.io/private/quux.
//
// For fine-grained control over module download and validation, the GONOPROXY
// and GONOSUMDB environment variables accept the same kind of glob list
// and override GOPRIVATE for the specific decision of whether to use the proxy
// and checksum database, respectively.
//
// For example, if a company ran a module proxy serving private modules,
// users would configure go using:
//
//	GOPRIVATE=*.corp.example.com
//	GOPROXY=proxy.example.com
//	GONOPROXY=none
//
// The GOPRIVATE variable is also used to define the "public" and "private"
// patterns for the GOVCS variable; see 'go help vcs'. For that usage,
// GOPRIVATE applies even in GOPATH mode. In that case, it matches import paths
// instead of module paths.
//
// The 'go env -w' command (see 'go help env') can be used to set these variables
// for future go command invocations.
//
// For more details, see https://golang.org/ref/mod#private-modules.
//
// # Testing flags
//
// The 'go test' command takes both flags that apply to 'go test' itself
// and flags that apply to the resulting test binary.
//
// Several of the flags control profiling and write an execution profile
// suitable for "go tool pprof"; run "go tool pprof -h" for more
// information. The --alloc_space, --alloc_objects, and --show_bytes
// options of pprof control how the information is presented.
//
// The following flags are recognized by the 'go test' command and
// control the execution of any test:
//
//	-bench regexp
//	    Run only those benchmarks matching a regular expression.
//	    By default, no benchmarks are run.
//	    To run all benchmarks, use '-bench .' or '-bench=.'.
//	    The regular expression is split by unbracketed slash (/)
//	    characters into a sequence of regular expressions, and each
//	    part of a benchmark's identifier must match the corresponding
//	    element in the sequence, if any. Possible parents of matches
//	    are run with b.N=1 to identify sub-benchmarks. For example,
//	    given -bench=X/Y, top-level benchmarks matching X are run
//	    with b.N=1 to find any sub-benchmarks matching Y, which are
//	    then run in full.
//
//	-benchtime t
//	    Run enough iterations of each benchmark to take t, specified
//	    as a time.Duration (for example, -benchtime 1h30s).
//	    The default is 1 second (1s).
//	    The special syntax Nx means to run the benchmark N times
//	    (for example, -benchtime 100x).
//
//	-count n
//	    Run each test, benchmark, and fuzz seed n times (default 1).
//	    If -cpu is set, run n times for each GOMAXPROCS value.
//	    Examples are always run once. -count does not apply to
//	    fuzz tests matched by -fuzz.
//
//	-cover
//	    Enable coverage analysis.
//	    Note that because coverage works by annotating the source
//	    code before compilation, compilation and test failures with
//	    coverage enabled may report line numbers that don't correspond
//	    to the original sources.
//
//	-covermode set,count,atomic
//	    Set the mode for coverage analysis for the package[s]
//	    being tested. The default is "set" unless -race is enabled,
//	    in which case it is "atomic".
//	    The values:
//		set: bool: does this statement run?
//		count: int: how many times does this statement run?
//		atomic: int: count, but correct in multithreaded tests;
//			significantly more expensive.
//	    Sets -cover.
//
//	-coverpkg pattern1,pattern2,pattern3
//	    Apply coverage analysis in each test to packages whose import paths
//	    match the patterns. The default is for each test to analyze only
//	    the package being tested. See 'go help packages' for a description
//	    of package patterns. Sets -cover.
//
//	-cpu 1,2,4
//	    Specify a list of GOMAXPROCS values for which the tests, benchmarks or
//	    fuzz tests should be executed. The default is the current value
//	    of GOMAXPROCS. -cpu does not apply to fuzz tests matched by -fuzz.
//
//	-failfast
//	    Do not start new tests after the first test failure.
//
//	-fullpath
//	    Show full file names in the error messages.
//
//	-fuzz regexp
//	    Run the fuzz test matching the regular expression. When specified,
//	    the command line argument must match exactly one package within the
//	    main module, and regexp must match exactly one fuzz test within
//	    that package. Fuzzing will occur after tests, benchmarks, seed corpora
//	    of other fuzz tests, and examples have completed. See the Fuzzing
//	    section of the testing package documentation for details.
//
//	-fuzztime t
//	    Run enough iterations of the fuzz target during fuzzing to take t,
//	    specified as a time.Duration (for example, -fuzztime 1h30s).
//		The default is to run forever.
//	    The special syntax Nx means to run the fuzz target N times
//	    (for example, -fuzztime 1000x).
//
//	-fuzzminimizetime t
//	    Run enough iterations of the fuzz target during each minimization
//	    attempt to take t, as specified as a time.Duration (for example,
//	    -fuzzminimizetime 30s).
//		The default is 60s.
//	    The special syntax Nx means to run the fuzz target N times
//	    (for example, -fuzzminimizetime 100x).
//
//	-json
//	    Log verbose output and test results in JSON. This presents the
//	    same information as the -v flag in a machine-readable format.
//
//	-list regexp
//	    List tests, benchmarks, fuzz tests, or examples matching the regular
//	    expression. No tests, benchmarks, fuzz tests, or examples will be run.
//	    This will only list top-level tests. No subtest or subbenchmarks will be
//	    shown.
//
//	-parallel n
//	    Allow parallel execution of test functions that call t.Parallel, and
//	    fuzz targets that call t.Parallel when running the seed corpus.
//	    The value of this flag is the maximum number of tests to run
//	    simultaneously.
//	    While fuzzing, the value of this flag is the maximum number of
//	    subprocesses that may call the fuzz function simultaneously, regardless of
//	    whether T.Parallel is called.
//	    By default, -parallel is set to the value of GOMAXPROCS.
//	    Setting -parallel to values higher than GOMAXPROCS may cause degraded
//	    performance due to CPU contention, especially when fuzzing.
//	    Note that -parallel only applies within a single test binary.
//	    The 'go test' command may run tests for different packages
//	    in parallel as well, according to the setting of the -p flag
//	    (see 'go help build').
//
//	-run regexp
//	    Run only those tests, examples, and fuzz tests matching the regular
//	    expression. For tests, the regular expression is split by unbracketed
//	    slash (/) characters into a sequence of regular expressions, and each
//	    part of a test's identifier must match the corresponding element in
//	    the sequence, if any. Note that possible parents of matches are
//	    run too, so that -run=X/Y matches and runs and reports the result
//	    of all tests matching X, even those without sub-tests matching Y,
//	    because it must run them to look for those sub-tests.
//	    See also -skip.
//
//	-short
//	    Tell long-running tests to shorten their run time.
//	    It is off by default but set during all.bash so that installing
//	    the Go tree can run a sanity check but not spend time running
//	    exhaustive tests.
//
//	-shuffle off,on,N
//	    Randomize the execution order of tests and benchmarks.
//	    It is off by default. If -shuffle is set to on, then it will seed
//	    the randomizer using the system clock. If -shuffle is set to an
//	    integer N, then N will be used as the seed value. In both cases,
//	    the seed will be reported for reproducibility.
//
//	-skip regexp
//	    Run only those tests, examples, fuzz tests, and benchmarks that
//	    do not match the regular expression. Like for -run and -bench,
//	    for tests and benchmarks, the regular expression is split by unbracketed
//	    slash (/) characters into a sequence of regular expressions, and each
//	    part of a test's identifier must match the corresponding element in
//	    the sequence, if any.
//
//	-timeout d
//	    If a test binary runs longer than duration d, panic.
//	    If d is 0, the timeout is disabled.
//	    The default is 10 minutes (10m).
//
//	-v
//	    Verbose output: log all tests as they are run. Also print all
//	    text from Log and Logf calls even if the test succeeds.
//
//	-vet list
//	    Configure the invocation of "go vet" during "go test"
//	    to use the comma-separated list of vet checks.
//	    If list is empty, "go test" runs "go vet" with a curated list of
//	    checks believed to be always worth addressing.
//	    If list is "off", "go test" does not run "go vet" at all.
//
// The following flags are also recognized by 'go test' and can be used to
// profile the tests during execution:
//
//	-benchmem
//	    Print memory allocation statistics for benchmarks.
//	    Allocations made in C or using C.malloc are not counted.
//
//	-blockprofile block.out
//	    Write a goroutine blocking profile to the specified file
//	    when all tests are complete.
//	    Writes test binary as -c would.
//
//	-blockprofilerate n
//	    Control the detail provided in goroutine blocking profiles by
//	    calling runtime.SetBlockProfileRate with n.
//	    See 'go doc runtime.SetBlockProfileRate'.
//	    The profiler aims to sample, on average, one blocking event every
//	    n nanoseconds the program spends blocked. By default,
//	    if -test.blockprofile is set without this flag, all blocking events
//	    are recorded, equivalent to -test.blockprofilerate=1.
//
//	-coverprofile cover.out
//	    Write a coverage profile to the file after all tests have passed.
//	    Sets -cover.
//
//	-cpuprofile cpu.out
//	    Write a CPU profile to the specified file before exiting.
//	    Writes test binary as -c would.
//
//	-memprofile mem.out
//	    Write an allocation profile to the file after all tests have passed.
//	    Writes test binary as -c would.
//
//	-memprofilerate n
//	    Enable more precise (and expensive) memory allocation profiles by
//	    setting runtime.MemProfileRate. See 'go doc runtime.MemProfileRate'.
//	    To profile all memory allocations, use -test.memprofilerate=1.
//
//	-mutexprofile mutex.out
//	    Write a mutex contention profile to the specified file
//	    when all tests are complete.
//	    Writes test binary as -c would.
//
//	-mutexprofilefraction n
//	    Sample 1 in n stack traces of goroutines holding a
//	    contended mutex.
//
//	-outputdir directory
//	    Place output files from profiling in the specified directory,
//	    by default the directory in which "go test" is running.
//
//	-trace trace.out
//	    Write an execution trace to the specified file before exiting.
//
// Each of these flags is also recognized with an optional 'test.' prefix,
// as in -test.v. When invoking the generated test binary (the result of
// 'go test -c') directly, however, the prefix is mandatory.
//
// The 'go test' command rewrites or removes recognized flags,
// as appropriate, both before and after the optional package list,
// before invoking the test binary.
//
// For instance, the command
//
//	go test -v -myflag testdata -cpuprofile=prof.out -x
//
// will compile the test binary and then run it as
//
//	pkg.test -test.v -myflag testdata -test.cpuprofile=prof.out
//
// (The -x flag is removed because it applies only to the go command's
// execution, not to the test itself.)
//
// The test flags that generate profiles (other than for coverage) also
// leave the test binary in pkg.test for use when analyzing the profiles.
//
// When 'go test' runs a test binary, it does so from within the
// corresponding package's source code directory. Depending on the test,
// it may be necessary to do the same when invoking a generated test
// binary directly. Because that directory may be located within the
// module cache, which may be read-only and is verified by checksums, the
// test must not write to it or any other directory within the module
// unless explicitly requested by the user (such as with the -fuzz flag,
// which writes failures to testdata/fuzz).
//
// The command-line package list, if present, must appear before any
// flag not known to the go test command. Continuing the example above,
// the package list would have to appear before -myflag, but could appear
// on either side of -v.
//
// When 'go test' runs in package list mode, 'go test' caches successful
// package test results to avoid unnecessary repeated running of tests. To
// disable test caching, use any test flag or argument other than the
// cacheable flags. The idiomatic way to disable test caching explicitly
// is to use -count=1.
//
// To keep an argument for a test binary from being interpreted as a
// known flag or a package name, use -args (see 'go help test') which
// passes the remainder of the command line through to the test binary
// uninterpreted and unaltered.
//
// For instance, the command
//
//	go test -v -args -x -v
//
// will compile the test binary and then run it as
//
//	pkg.test -test.v -x -v
//
// Similarly,
//
//	go test -args math
//
// will compile the test binary and then run it as
//
//	pkg.test math
//
// In the first example, the -x and the second -v are passed through to the
// test binary unchanged and with no effect on the go command itself.
// In the second example, the argument math is passed through to the test
// binary, instead of being interpreted as the package list.
//
// # Testing functions
//
// The 'go test' command expects to find test, benchmark, and example functions
// in the "*_test.go" files corresponding to the package under test.
//
// A test function is one named TestXxx (where Xxx does not start with a
// lower case letter) and should have the signature,
//
//	func TestXxx(t *testing.T) { ... }
//
// A benchmark function is one named BenchmarkXxx and should have the signature,
//
//	func BenchmarkXxx(b *testing.B) { ... }
//
// A fuzz test is one named FuzzXxx and should have the signature,
//
//	func FuzzXxx(f *testing.F) { ... }
//
// An example function is similar to a test function but, instead of using
// *testing.T to report success or failure, prints output to os.Stdout.
// If the last comment in the function starts with "Output:" then the output
// is compared exactly against the comment (see examples below). If the last
// comment begins with "Unordered output:" then the output is compared to the
// comment, however the order of the lines is ignored. An example with no such
// comment is compiled but not executed. An example with no text after
// "Output:" is compiled, executed, and expected to produce no output.
//
// Godoc displays the body of ExampleXxx to demonstrate the use
// of the function, constant, or variable Xxx. An example of a method M with
// receiver type T or *T is named ExampleT_M. There may be multiple examples
// for a given function, constant, or variable, distinguished by a trailing _xxx,
// where xxx is a suffix not beginning with an upper case letter.
//
// Here is an example of an example:
//
//	func ExamplePrintln() {
//		Println("The output of\nthis example.")
//		// Output: The output of
//		// this example.
//	}
//
// Here is another example where the ordering of the output is ignored:
//
//	func ExamplePerm() {
//		for _, value := range Perm(4) {
//			fmt.Println(value)
//		}
//
//		// Unordered output: 4
//		// 2
//		// 1
//		// 3
//		// 0
//	}
//
// The entire test file is presented as the example when it contains a single
// example function, at least one other function, type, variable, or constant
// declaration, and no tests, benchmarks, or fuzz tests.
//
// See the documentation of the testing package for more information.
//
// # Controlling version control with GOVCS
//
// The 'go get' command can run version control commands like git
// to download imported code. This functionality is critical to the decentralized
// Go package ecosystem, in which code can be imported from any server,
// but it is also a potential security problem, if a malicious server finds a
// way to cause the invoked version control command to run unintended code.
//
// To balance the functionality and security concerns, the 'go get' command
// by default will only use git and hg to download code from public servers.
// But it will use any known version control system (bzr, fossil, git, hg, svn)
// to download code from private servers, defined as those hosting packages
// matching the GOPRIVATE variable (see 'go help private'). The rationale behind
// allowing only Git and Mercurial is that these two systems have had the most
// attention to issues of being run as clients of untrusted servers. In contrast,
// Bazaar, Fossil, and Subversion have primarily been used in trusted,
// authenticated environments and are not as well scrutinized as attack surfaces.
//
// The version control command restrictions only apply when using direct version
// control access to download code. When downloading modules from a proxy,
// 'go get' uses the proxy protocol instead, which is always permitted.
// By default, the 'go get' command uses the Go module mirror (proxy.golang.org)
// for public packages and only falls back to version control for private
// packages or when the mirror refuses to serve a public package (typically for
// legal reasons). Therefore, clients can still access public code served from
// Bazaar, Fossil, or Subversion repositories by default, because those downloads
// use the Go module mirror, which takes on the security risk of running the
// version control commands using a custom sandbox.
//
// The GOVCS variable can be used to change the allowed version control systems
// for specific packages (identified by a module or import path).
// The GOVCS variable applies when building package in both module-aware mode
// and GOPATH mode. When using modules, the patterns match against the module path.
// When using GOPATH, the patterns match against the import path corresponding to
// the root of the version control repository.
//
// The general form of the GOVCS setting is a comma-separated list of
// pattern:vcslist rules. The pattern is a glob pattern that must match
// one or more leading elements of the module or import path. The vcslist
// is a pipe-separated list of allowed version control commands, or "all"
// to allow use of any known command, or "off" to disallow all commands.
// Note that if a module matches a pattern with vcslist "off", it may still be
// downloaded if the origin server uses the "mod" scheme, which instructs the
// go command to download the module using the GOPROXY protocol.
// The earliest matching pattern in the list applies, even if later patterns
// might also match.
//
// For example, consider:
//
//	GOVCS=github.com:git,evil.com:off,*:git|hg
//
// With this setting, code with a module or import path beginning with
// github.com/ can only use git; paths on evil.com cannot use any version
// control command, and all other paths (* matches everything) can use
// only git or hg.
//
// The special patterns "public" and "private" match public and private
// module or import paths. A path is private if it matches the GOPRIVATE
// variable; otherwise it is public.
//
// If no rules in the GOVCS variable match a particular module or import path,
// the 'go get' command applies its default rule, which can now be summarized
// in GOVCS notation as 'public:git|hg,private:all'.
//
// To allow unfettered use of any version control system for any package, use:
//
//	GOVCS=*:all
//
// To disable all use of version control, use:
//
//	GOVCS=*:off
//
// The 'go env -w' command (see 'go help env') can be used to set the GOVCS
// variable for future go command invocations.
package main

"""




```