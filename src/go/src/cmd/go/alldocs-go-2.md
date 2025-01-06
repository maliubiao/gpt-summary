Response: The user wants to understand the functionality of the provided Go code snippet, which is part of `go/src/cmd/go/alldocs.go`. This file likely contains documentation used by the `go` command, specifically the output of `go help`.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core purpose:** The text starts with `pattern:` and then provides a large block of text. The surrounding context ("part of `go/src/cmd/go/alldocs.go`") and the content itself strongly suggest this is documentation for `go` commands. The topics covered (package names, private modules, testing flags, version control) are key functionalities of the `go` tool.

2. **Break down the content into logical sections:** The documentation is already structured with headings and subheadings. This makes it easier to categorize the functionality. The major topics are:
    * Package Naming Conventions
    * Private Module Configuration
    * `go test` Flags
    * `go test` Function Types
    * Version Control Configuration (GOVCS)

3. **Summarize each section's functionality:** For each section, extract the key information about what it describes or controls.

    * **Package Naming:** Explains `main` and `documentation` as reserved names, and how single-directory compilation works.
    * **Private Modules:** Describes `GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` environment variables for controlling access to private modules.
    * **Testing Flags:** Lists and explains various flags for the `go test` command, covering test execution, profiling, coverage, fuzzing, and more. This is the largest section and warrants careful summarization of the different categories of flags.
    * **Testing Functions:**  Explains the different types of functions recognized by `go test`: `TestXxx`, `BenchmarkXxx`, `FuzzXxx`, and `ExampleXxx`.
    * **Version Control (GOVCS):** Describes the `GOVCS` environment variable for controlling which version control systems are allowed for different packages.

4. **Look for opportunities to provide Go code examples:**  The request asks for code examples if the functionality can be illustrated. The `go test` flags are excellent candidates for this. Choose a few representative flags and demonstrate how they would be used in a `go test` command. Think about different categories of flags (execution control, profiling).

5. **Consider command-line argument processing:**  The `go test` section heavily involves command-line arguments. Explain how `go test` handles these arguments, including the optional `test.` prefix and the `-args` flag.

6. **Identify potential pitfalls for users:**  Think about common mistakes users might make when using the described features. The `-args` flag and the interaction of `go test` flags with the test binary itself are good examples.

7. **Address the "reasoning out Go language features" part:** This is more about interpreting the documentation than seeing code. The "Packages in a program need not have unique package names, but there are two reserved package names with special meaning." part is a core Go concept. Explain `main` and `documentation` in this context.

8. **Structure the final answer:** Organize the information clearly, using headings and bullet points. Address each part of the user's request systematically.

9. **Review and refine:**  Read through the answer to ensure it is accurate, comprehensive, and easy to understand. Check for any inconsistencies or missing information. Make sure the language used aligns with the provided documentation. For instance, use terms like "glob patterns" when discussing environment variables.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus solely on the `go test` flags since that's the largest section.
* **Correction:** Realize the prompt asks about the *entire* provided text, so include the package naming, private modules, and version control sections as well.
* **Initial thought:**  Just list the `go test` flags.
* **Refinement:** Group the `go test` flags by their purpose (execution, profiling, etc.) to make the explanation clearer.
* **Initial thought:**  Provide a single example of `go test`.
* **Refinement:** Provide multiple examples demonstrating different types of flags and their usage.
* **Initial thought:**  Not sure what "reasoning out Go language features" means in this context.
* **Refinement:**  Interpret it as understanding the underlying Go concepts that the documentation is describing, like the special meaning of `main` and `documentation`.

By following this structured approach, the generated answer effectively addresses all aspects of the user's request and provides a comprehensive overview of the functionality described in the provided text.
好的，我们来归纳一下这段 `go/src/cmd/go/alldocs.go` 代码片段的功能。

**功能归纳:**

这段代码片段是 Go 语言 `go` 命令帮助文档的一部分，它详细解释了以下几个核心概念和功能：

1. **Go 语言的包 (Packages):**
   - 解释了 Go 语言中包的概念，以及包名不必唯一，但 `main` 和 `documentation` 是保留的特殊包名。
   - `main` 包用于声明可执行命令，不能被导入。
   - `documentation` 包用于存放非 Go 程序的文档，其内的文件会被 `go` 命令忽略。
   - 阐述了当包列表是来自单个目录的 `.go` 文件列表时，`go` 命令会如何处理，即创建一个合成的包，忽略构建约束和目录中的其他文件。
   - 提到了 `.` 和 `_` 开头的目录和文件名以及 `testdata` 目录会被 `go` 工具忽略。

2. **非公开代码的下载配置 (Configuration for downloading non-public code):**
   - 介绍了如何配置 `go` 命令来下载非公开的代码，这涉及到不使用公开的 Go 模块代理和校验数据库。
   - 详细解释了 `GOPRIVATE`, `GONOPROXY`, 和 `GONOSUMDB` 这三个环境变量的作用，它们都是用逗号分隔的 glob 模式列表，用于匹配模块路径前缀。
   - 提供了使用这些环境变量的示例，以及如何使用 `go env -w` 命令来设置这些变量。
   - 引用了 Go 官方文档中关于私有模块的更多细节。

3. **`go test` 命令的标志 (Testing flags):**
   - 列举并详细解释了 `go test` 命令的各种标志，这些标志可以控制测试的执行行为、性能分析、覆盖率分析、模糊测试等方面。
   - 将这些标志分为控制测试执行和用于性能分析的两大类。
   - 详细描述了每个标志的作用、参数格式以及默认值。

4. **测试函数 (Testing functions):**
   - 解释了 `go test` 命令如何识别测试函数、基准测试函数、模糊测试函数和示例函数，以及它们的命名约定和函数签名。
   - 特别详细地说明了示例函数的格式，包括如何使用 `Output:` 和 `Unordered output:` 注释来验证输出。
   - 解释了当一个测试文件只包含一个示例函数，并且有其他声明时，整个文件会被作为示例展示。

5. **使用 GOVCS 控制版本控制 (Controlling version control with GOVCS):**
   - 解释了 `go get` 命令如何使用版本控制系统下载代码，并强调了其中的安全风险。
   - 介绍了 `GOVCS` 环境变量，用于更细粒度地控制允许 `go get` 命令使用的版本控制系统。
   - 详细描述了 `GOVCS` 变量的格式，包括模式匹配和允许的版本控制系统列表。
   - 提供了使用 `GOVCS` 变量的示例，以及特殊模式 `"public"` 和 `"private"` 的含义。
   - 说明了 `go get` 命令的默认行为，以及如何完全允许或禁用版本控制。

**可以推理出的 Go 语言功能的实现：**

这段文档描述了 `go` 工具中与**模块管理 (module management)** 和 **测试 (testing)** 相关的核心功能实现。

**模块管理 (Module Management):**

- **私有模块处理:** `GOPRIVATE`, `GONOPROXY`, 和 `GONOSUMDB` 的实现允许 `go` 命令在下载和校验模块时区分公有和私有模块，从而支持企业内部的代码管理。

```go
// 假设在 go/src/cmd/go/internal/modload 中有处理这些环境变量的逻辑
// (这只是一个概念性的例子，实际实现会更复杂)

package modload

import (
	"os"
	"path/filepath"
	"strings"
)

func isPrivate(modulePath string) bool {
	goprivate := os.Getenv("GOPRIVATE")
	if goprivate == "" {
		return false
	}
	patterns := strings.Split(goprivate, ",")
	for _, pattern := range patterns {
		matched, _ := filepath.Match(pattern, modulePath)
		if matched {
			return true
		}
	}
	return false
}

// 假设的输入和输出
// 输入: modulePath = "git.corp.example.com/xyzzy"
// 输出: true (如果 GOPRIVATE 设置为 "*.corp.example.com")

// 输入: modulePath = "rsc.io/public"
// 输出: false (如果 GOPRIVATE 设置为 "*.corp.example.com")
```

**测试 (Testing):**

- **`go test` 命令及其标志:**  `go test` 命令的各种标志（例如 `-bench`, `-cover`, `-cpuprofile` 等）的实现涉及到解析命令行参数，并根据这些参数配置测试的执行环境和行为。

```go
// 假设在 go/src/cmd/go/internal/testflag 中有处理 test 标志的逻辑
// (这只是一个概念性的例子)

package testflag

import (
	"flag"
	"fmt"
	"regexp"
	"time"
)

var (
	benchFlag    = flag.String("bench", "", "run only benchmarks matching regexp")
	benchtimeFlag = flag.Duration("benchtime", 1*time.Second, "run enough iterations of each benchmark to take t")
	coverFlag    = flag.Bool("cover", false, "enable coverage analysis")
	cpuprofileFlag = flag.String("cpuprofile", "", "write cpu profile to file")
	// ... 其他标志
)

func ParseTestFlags() {
	flag.Parse()
	if *benchFlag != "" {
		_, err := regexp.Compile(*benchFlag)
		if err != nil {
			fmt.Println("invalid benchmark regexp:", err)
			// 处理错误
		}
	}
	// ... 其他标志的处理
}

// 假设的命令行输入: go test -bench=. -benchtime=5s -cover -cpuprofile=cpu.prof

// 解析后:
// *benchFlag = "."
// *benchtimeFlag = 5s
// *coverFlag = true
// *cpuprofileFlag = "cpu.prof"
```

**命令行参数的具体处理:**

`go test` 命令在处理命令行参数时，会区分哪些是 `go test` 本身的标志，哪些是传递给测试二进制的标志。

- **`go test` 的标志:** 这些标志直接影响 `go test` 命令的行为，例如 `-v`, `-cover`, `-cpuprofile` 等。`go test` 会解析这些标志，并执行相应的操作，例如编译时启用覆盖率分析，或者在测试结束后生成性能分析文件。
- **传递给测试二进制的标志:**  有些标志可以带有可选的 `test.` 前缀（例如 `-test.v`）。当直接运行编译后的测试二进制时，前缀是强制的。`go test` 在调用测试二进制时，会根据需要重写或移除这些标志。
- **`-args` 标志:**  `go test` 遇到 `-args` 标志后，会将后续的所有参数原封不动地传递给测试二进制。这允许向测试二进制传递一些 `go test` 不识别的自定义参数。

**使用者易犯错的点：**

- **混淆 `go test` 标志和传递给测试二进制的标志:**  初学者可能会不清楚哪些标志是给 `go test` 用的，哪些是给测试二进制用的，以及何时需要使用 `test.` 前缀。

  ```bash
  # 错误示例：直接运行测试二进制时忘记添加 test. 前缀
  ./my_package.test -v  # 应该使用 -test.v

  # 正确示例：
  go test -v ./my_package

  # 正确示例：直接运行测试二进制
  go test -c ./my_package  # 先编译
  ./my_package.test -test.v
  ```

- **不理解 `-args` 的作用:**  当需要向测试二进制传递与 `go test` 标志冲突的参数或自定义参数时，可能会忘记使用 `-args`。

  ```bash
  # 错误示例：math 被误认为是包名
  go test math

  # 正确示例：使用 -args 将 math 传递给测试二进制
  go test -args math
  ```

- **测试缓存:**  `go test` 会缓存成功的测试结果，以避免重复运行。这在某些情况下可能会导致困惑，用户修改了代码但测试结果没有变化。可以使用 `-count=1` 等标志来禁用测试缓存。

  ```bash
  go test  # 可能使用缓存
  go test -count=1 # 禁用缓存
  ```

希望以上归纳和解释能够帮助你更好地理解这段 `go/src/cmd/go/alldocs.go` 代码片段的功能。

Prompt: 
```
这是路径为go/src/cmd/go/alldocs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共3部分，请归纳一下它的功能

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