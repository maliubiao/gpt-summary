Response:
My thinking process to answer the prompt goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided Go code snippet (`go/src/testing/testing.go`), focusing on its functionalities. It also asks for code examples, explanations of command-line arguments, and common pitfalls (which the snippet itself addresses somewhat). The key is to identify the *purpose* of the `testing` package based on the documentation.

2. **Identify the Core Functionality:** The very first lines of the comment are crucial: "Package testing provides support for automated testing of Go packages." This immediately establishes the central purpose.

3. **Break Down the Functionality into Key Areas:** I scanned the documentation for keywords and structural elements that denote different aspects of the testing framework. I identified these key areas:

    * **Test Functions:** The `func TestXxx(*testing.T)` pattern is fundamental.
    * **Test File Naming:**  The `_test.go` suffix is a core convention.
    * **Internal vs. External Testing:** The distinction between testing within the same package and testing from a `_test` package is highlighted.
    * **Assertions and Failure:** The `Error`, `Fail`, etc., methods are used to report issues.
    * **Benchmarks:** The `func BenchmarkXxx(*testing.B)` pattern and the `-bench` flag.
    * **Examples:** The `func ExampleXxx()` pattern and the `Output:` comment directive.
    * **Fuzzing:** The `func FuzzXxx(*testing.F)` pattern and the `-fuzz` flag.
    * **Skipping Tests:** The `t.Skip()` method and the `testing.Short()` function.
    * **Subtests and Sub-benchmarks:** The `t.Run()` and `b.Run()` methods.
    * **TestMain:** The `func TestMain(m *testing.M)` function for custom setup/teardown.
    * **Command-line Flags:**  The documentation explicitly mentions `go help test` and `go help testflag`, indicating the importance of command-line options.

4. **Organize the Information:**  I decided to structure the answer around these key areas, providing a clear and logical flow. I wanted to move from the most basic concepts (test functions) to more advanced ones (fuzzing, TestMain).

5. **Extract Specific Details and Examples:** For each key area, I looked for concrete information from the documentation:

    * **Test Functions:**  The naming convention and the `*testing.T` argument. I created a simple code example demonstrating a test function with an assertion. I included both internal and external testing examples as they were explicitly mentioned.
    * **Benchmarks:** The naming convention, the `*testing.B` argument, and the `-bench` flag. I included an example of a benchmark and explained the output.
    * **Examples:**  The naming conventions and the `Output:` comment. I pointed out the purpose of examples and the "Unordered output:" variation.
    * **Fuzzing:** The naming convention, the `*testing.F` argument, and the `-fuzz` flag. I summarized the core idea of fuzzing and the role of seed inputs.
    * **Skipping Tests:**  The `t.Skip()` method and the `testing.Short()` function, and the scenario where skipping is useful (short mode).
    * **Subtests:** The `t.Run()` method and how it allows for structured testing. I provided a simple example.
    * **TestMain:** The purpose of `TestMain` and the need to call `m.Run()`.

6. **Address Specific Requirements:**

    * **"功能 (Functions)":** I explicitly listed the functionalities in a concise way at the beginning of the summary.
    * **"推理出它是什么go语言功能的实现 (Deduce the Go language feature implemented)":**  I clearly stated that it implements the *automated testing* framework for Go.
    * **"go代码举例说明 (Illustrate with Go code examples)":** I provided code examples for test functions, benchmarks, and subtests.
    * **"假设的输入与输出 (Hypothetical input and output)":** For the benchmark example, I explained the meaning of the output.
    * **"命令行参数的具体处理 (Specific handling of command-line arguments)":** I listed several key command-line flags and briefly explained their purpose.
    * **"使用者易犯错的点 (Common mistakes users make)":**  I identified the importance of the `_test.go` naming convention and the two styles of testing (internal vs. external), which are common sources of confusion for beginners. I also highlighted the necessity of calling `t.Fail()` or related methods for a test to be considered a failure.
    * **"归纳一下它的功能 (Summarize its functions)":**  The initial bullet point list served as this summary.

7. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness. I checked for any grammatical errors or awkward phrasing. I made sure the examples were simple and easy to understand. I ensured I addressed all parts of the prompt.

By following these steps, I could systematically analyze the provided documentation and generate a comprehensive and informative answer that addresses all aspects of the request. The key was to identify the core purpose and then break it down into its constituent parts, providing specific details and examples for each.
这是 Go 语言标准库 `testing` 包的一部分，它提供了一套用于编写和运行单元测试、基准测试、示例和模糊测试的框架。

**功能归纳:**

这部分代码主要定义了 `testing` 包的基础结构和核心概念，包括：

* **测试函数的约定:**  定义了测试函数的命名规则 (`func TestXxx(*testing.T)`) 以及如何通过 `*testing.T` 参数报告测试结果（成功或失败）。
* **测试文件的约定:**  说明了测试文件应该以 `_test.go` 结尾，并且可以放在被测试的包内或单独的 `_test` 包中。
* **两种测试方式:**  介绍了同包测试（可以访问未导出标识符）和黑盒测试（只能访问导出标识符）。
* **基准测试的约定:**  定义了基准测试函数的命名规则 (`func BenchmarkXxx(*testing.B)`) 以及如何使用 `*testing.B` 参数来度量性能。
* **示例的约定:**  定义了示例函数的命名规则 (`func ExampleXxx()`) 以及如何通过 `// Output:` 注释来验证示例的输出。
* **模糊测试的约定:** 定义了模糊测试函数的命名规则 (`func FuzzXxx(*testing.F)`) 以及如何使用 `*testing.F` 参数进行模糊测试。
* **跳过测试:**  提供了在运行时跳过测试或基准测试的能力 (`t.Skip()`, `b.Skip()`)。
* **子测试和子基准测试:**  介绍了使用 `t.Run()` 和 `b.Run()` 创建嵌套的测试和基准测试的方法。
* **TestMain 函数:**  允许用户自定义测试执行的入口点，进行额外的 setup 和 teardown 操作。
* **测试相关的命令行参数:**  定义了一些用于控制测试行为的命令行参数，例如 `-test.run`、`-test.bench`、`-test.v` 等。
* **核心类型 `TB` 和结构体 `common`:**  定义了测试和基准测试的通用接口 `TB` 和共享属性的结构体 `common`。

**Go 语言功能的实现:**

这部分代码主要实现了 Go 语言的 **自动化测试** 功能。它通过约定的函数命名、文件命名和特定的 API（如 `*testing.T` 和 `*testing.B`）来让 `go test` 工具能够自动发现并执行测试、基准测试、示例和模糊测试。

**Go 代码举例说明:**

**1. 单元测试:**

```go
// 假设这是 go/src/mypackage/mypackage.go
package mypackage

func Add(a, b int) int {
	return a + b
}
```

```go
// 假设这是 go/src/mypackage/mypackage_test.go
package mypackage_test

import (
	"testing"
	"mypackage" // 注意导入的是被测试的包
)

func TestAdd(t *testing.T) {
	got := mypackage.Add(2, 3)
	want := 5
	if got != want {
		t.Errorf("Add(2, 3) = %d; want %d", got, want)
	}
}
```

**假设的输入与输出:**

* **输入:** 运行命令 `go test ./mypackage`
* **输出 (如果测试通过):**  `PASS` 后面可能会跟一些性能信息。
* **输出 (如果测试失败):**
```
--- FAIL: TestAdd (0.00s)
    mypackage_test.go:11: Add(2, 3) = 6; want 5
FAIL
exit status 1
FAIL	mypackage	0.001s
```

**2. 基准测试:**

```go
// 假设这是 go/src/mymodule/benchmark_test.go
package mymodule_test

import (
	"testing"
	"strings"
)

func BenchmarkRepeat(b *testing.B) {
	s := "a"
	for i := 0; i < b.N; i++ {
		strings.Repeat(s, 100)
	}
}
```

**假设的输入与输出:**

* **输入:** 运行命令 `go test -bench=. ./mymodule`
* **输出:**
```
goos: linux
goarch: amd64
pkg: mymodule
cpu: 13th Gen Intel(R) Core(TM) i7-13700H
BenchmarkRepeat-20    1458425              781.6 ns/op
PASS
ok      mymodule        1.439s
```
这个输出表示 `BenchmarkRepeat` 函数在 20 个 CPU 核心下运行，循环了 1458425 次，每次操作平均耗时 781.6 纳秒。 `b.N` 的值会由 `go test` 自动调整，以获得可靠的测量结果。

**3. 示例:**

```go
// 假设这是 go/src/myexample/example.go
package myexample

import "fmt"

func Hello(name string) {
	fmt.Println("Hello, " + name + "!")
}

func ExampleHello() {
	Hello("World")
	// Output: Hello, World!
}
```

**假设的输入与输出:**

* **输入:** 运行命令 `go test ./myexample`
* **输出 (如果示例输出匹配):** `PASS`
* **输出 (如果示例输出不匹配):**  会显示实际输出和期望输出的差异，导致测试失败。

**命令行参数的具体处理:**

这部分代码定义了一系列全局变量（例如 `short`, `failFast`, `match`, `bench`, `count` 等），这些变量会通过 `flag` 包与命令行参数绑定。 `Init()` 函数负责注册这些测试相关的命令行参数。

* **`-test.short`:**  布尔值，如果设置，表示运行较短的测试套件，用于节省时间。测试代码中可以使用 `testing.Short()` 函数来判断是否启用了短测试模式，并跳过一些耗时的测试。
* **`-test.failfast`:** 布尔值，如果设置，表示在第一个测试失败后立即停止测试执行。
* **`-test.outputdir`:** 字符串，指定测试输出文件（例如性能分析文件）存放的目录。
* **`-test.v`:**  可以设置为 `true` 或 `test2json`，用于启用更详细的测试输出。`true` 会打印每个测试的开始和结束信息，`test2json` 会输出 JSON 格式的测试结果，方便工具解析。
* **`-test.count`:**  整数，指定运行测试和基准测试的次数。
* **`-test.coverprofile`:** 字符串，指定生成代码覆盖率报告的文件名。
* **`-test.gocoverdir`:** 字符串，指定存放代码覆盖率中间文件的目录。
* **`-test.list`:** 字符串，指定一个正则表达式，用于列出匹配的测试、示例和基准测试名称，然后退出，不执行测试。
* **`-test.run`:** 字符串，指定一个正则表达式，只运行名称匹配的测试和示例。
* **`-test.skip`:** 字符串，指定一个正则表达式，排除名称匹配的测试和示例。
* **`-test.bench`:** 字符串，指定一个正则表达式，只运行名称匹配的基准测试。使用 `.` 可以匹配所有基准测试。
* **`-test.memprofile`:** 字符串，指定生成内存分配 profile 报告的文件名。
* **`-test.cpuprofile`:** 字符串，指定生成 CPU profile 报告的文件名。
* **`-test.blockprofile`:** 字符串，指定生成 goroutine 阻塞 profile 报告的文件名。
* **`-test.timeout`:**  持续时间，如果测试运行时间超过此值，则会 panic。
* **`-test.cpu`:**  逗号分隔的 CPU 数量列表，用于指定运行基准测试时使用的 CPU 核心数。
* **`-test.parallel`:** 整数，指定并行运行的最大测试数（默认值为 `runtime.GOMAXPROCS(0)`）。
* **`-test.shuffle`:**  字符串，控制测试和基准测试的执行顺序，可以设置为 `on`、`off` 或一个 `seed` 值用于可重复的随机顺序。
* **`-test.fullpath`:** 布尔值，如果设置，在错误消息中显示完整的文件路径。

**使用者易犯错的点:**

* **测试文件命名不规范:**  忘记使用 `_test.go` 后缀，导致 `go test` 无法识别测试文件。
* **测试函数命名不规范:**  测试函数名没有以 `Test` 开头或首字母小写，导致 `go test` 无法识别测试函数。
* **在黑盒测试中访问未导出的标识符:**  在 `_test` 包中编写测试时，尝试访问被测试包中未导出的函数或变量。
* **忘记调用 `t.Fail()` 或相关方法:**  即使测试逻辑判断出错误，如果没有调用 `t.Error`, `t.Fail`, `t.Fatal` 等方法，`go test` 仍然会认为测试通过。
* **对基准测试的 `b.N` 理解不透彻:**  基准测试的循环次数 `b.N` 由 `go test` 自动调整，不应该在基准测试函数中硬编码循环次数。
* **示例输出不匹配:**  示例代码的实际输出与 `// Output:` 注释的内容不一致，导致示例测试失败。
* **混淆 `t.Run()` 和并发:** 误以为 `t.Run()` 本身就实现了并发，需要显式地调用 `t.Parallel()` 才能使子测试并行运行。

总而言之，这部分 `testing` 包的代码是 Go 语言测试框架的核心，它定义了编写和运行各种类型测试的基础规范和工具，是保证 Go 代码质量的重要组成部分。

Prompt: 
```
这是路径为go/src/testing/testing.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testing provides support for automated testing of Go packages.
// It is intended to be used in concert with the "go test" command, which automates
// execution of any function of the form
//
//	func TestXxx(*testing.T)
//
// where Xxx does not start with a lowercase letter. The function name
// serves to identify the test routine.
//
// Within these functions, use the Error, Fail or related methods to signal failure.
//
// To write a new test suite, create a file that
// contains the TestXxx functions as described here,
// and give that file a name ending in "_test.go".
// The file will be excluded from regular
// package builds but will be included when the "go test" command is run.
//
// The test file can be in the same package as the one being tested,
// or in a corresponding package with the suffix "_test".
//
// If the test file is in the same package, it may refer to unexported
// identifiers within the package, as in this example:
//
//	package abs
//
//	import "testing"
//
//	func TestAbs(t *testing.T) {
//	    got := Abs(-1)
//	    if got != 1 {
//	        t.Errorf("Abs(-1) = %d; want 1", got)
//	    }
//	}
//
// If the file is in a separate "_test" package, the package being tested
// must be imported explicitly and only its exported identifiers may be used.
// This is known as "black box" testing.
//
//	package abs_test
//
//	import (
//		"testing"
//
//		"path_to_pkg/abs"
//	)
//
//	func TestAbs(t *testing.T) {
//	    got := abs.Abs(-1)
//	    if got != 1 {
//	        t.Errorf("Abs(-1) = %d; want 1", got)
//	    }
//	}
//
// For more detail, run "go help test" and "go help testflag".
//
// # Benchmarks
//
// Functions of the form
//
//	func BenchmarkXxx(*testing.B)
//
// are considered benchmarks, and are executed by the "go test" command when
// its -bench flag is provided. Benchmarks are run sequentially.
//
// For a description of the testing flags, see
// https://golang.org/cmd/go/#hdr-Testing_flags.
//
// A sample benchmark function looks like this:
//
//	func BenchmarkRandInt(b *testing.B) {
//	    for b.Loop() {
//	        rand.Int()
//	    }
//	}
//
// The output
//
//	BenchmarkRandInt-8   	68453040	        17.8 ns/op
//
// means that the body of the loop ran 68453040 times at a speed of 17.8 ns per loop.
//
// Only the body of the loop is timed, so benchmarks may do expensive
// setup before calling b.Loop, which will not be counted toward the
// benchmark measurement:
//
//	func BenchmarkBigLen(b *testing.B) {
//	    big := NewBig()
//	    for b.Loop() {
//	        big.Len()
//	    }
//	}
//
// If a benchmark needs to test performance in a parallel setting, it may use
// the RunParallel helper function; such benchmarks are intended to be used with
// the go test -cpu flag:
//
//	func BenchmarkTemplateParallel(b *testing.B) {
//	    templ := template.Must(template.New("test").Parse("Hello, {{.}}!"))
//	    b.RunParallel(func(pb *testing.PB) {
//	        var buf bytes.Buffer
//	        for pb.Next() {
//	            buf.Reset()
//	            templ.Execute(&buf, "World")
//	        }
//	    })
//	}
//
// A detailed specification of the benchmark results format is given
// in https://golang.org/design/14313-benchmark-format.
//
// There are standard tools for working with benchmark results at
// https://golang.org/x/perf/cmd.
// In particular, https://golang.org/x/perf/cmd/benchstat performs
// statistically robust A/B comparisons.
//
// # b.N-style benchmarks
//
// Prior to the introduction of [B.Loop], benchmarks were written in a
// different style using [B.N]. For example:
//
//	func BenchmarkRandInt(b *testing.B) {
//	    for range b.N {
//	        rand.Int()
//	    }
//	}
//
// In this style of benchmark, the benchmark function must run
// the target code b.N times. The benchmark function is called
// multiple times with b.N adjusted until the benchmark function
// lasts long enough to be timed reliably. This also means any setup
// done before the loop may be run several times.
//
// If a benchmark needs some expensive setup before running, the timer
// should be explicitly reset:
//
//	func BenchmarkBigLen(b *testing.B) {
//	    big := NewBig()
//	    b.ResetTimer()
//	    for range b.N {
//	        big.Len()
//	    }
//	}
//
// New benchmarks should prefer using [B.Loop], which is more robust
// and more efficient.
//
// # Examples
//
// The package also runs and verifies example code. Example functions may
// include a concluding line comment that begins with "Output:" and is compared with
// the standard output of the function when the tests are run. (The comparison
// ignores leading and trailing space.) These are examples of an example:
//
//	func ExampleHello() {
//	    fmt.Println("hello")
//	    // Output: hello
//	}
//
//	func ExampleSalutations() {
//	    fmt.Println("hello, and")
//	    fmt.Println("goodbye")
//	    // Output:
//	    // hello, and
//	    // goodbye
//	}
//
// The comment prefix "Unordered output:" is like "Output:", but matches any
// line order:
//
//	func ExamplePerm() {
//	    for _, value := range Perm(5) {
//	        fmt.Println(value)
//	    }
//	    // Unordered output: 4
//	    // 2
//	    // 1
//	    // 3
//	    // 0
//	}
//
// Example functions without output comments are compiled but not executed.
//
// The naming convention to declare examples for the package, a function F, a type T and
// method M on type T are:
//
//	func Example() { ... }
//	func ExampleF() { ... }
//	func ExampleT() { ... }
//	func ExampleT_M() { ... }
//
// Multiple example functions for a package/type/function/method may be provided by
// appending a distinct suffix to the name. The suffix must start with a
// lower-case letter.
//
//	func Example_suffix() { ... }
//	func ExampleF_suffix() { ... }
//	func ExampleT_suffix() { ... }
//	func ExampleT_M_suffix() { ... }
//
// The entire test file is presented as the example when it contains a single
// example function, at least one other function, type, variable, or constant
// declaration, and no test or benchmark functions.
//
// # Fuzzing
//
// 'go test' and the testing package support fuzzing, a testing technique where
// a function is called with randomly generated inputs to find bugs not
// anticipated by unit tests.
//
// Functions of the form
//
//	func FuzzXxx(*testing.F)
//
// are considered fuzz tests.
//
// For example:
//
//	func FuzzHex(f *testing.F) {
//	  for _, seed := range [][]byte{{}, {0}, {9}, {0xa}, {0xf}, {1, 2, 3, 4}} {
//	    f.Add(seed)
//	  }
//	  f.Fuzz(func(t *testing.T, in []byte) {
//	    enc := hex.EncodeToString(in)
//	    out, err := hex.DecodeString(enc)
//	    if err != nil {
//	      t.Fatalf("%v: decode: %v", in, err)
//	    }
//	    if !bytes.Equal(in, out) {
//	      t.Fatalf("%v: not equal after round trip: %v", in, out)
//	    }
//	  })
//	}
//
// A fuzz test maintains a seed corpus, or a set of inputs which are run by
// default, and can seed input generation. Seed inputs may be registered by
// calling (*F).Add or by storing files in the directory testdata/fuzz/<Name>
// (where <Name> is the name of the fuzz test) within the package containing
// the fuzz test. Seed inputs are optional, but the fuzzing engine may find
// bugs more efficiently when provided with a set of small seed inputs with good
// code coverage. These seed inputs can also serve as regression tests for bugs
// identified through fuzzing.
//
// The function passed to (*F).Fuzz within the fuzz test is considered the fuzz
// target. A fuzz target must accept a *T parameter, followed by one or more
// parameters for random inputs. The types of arguments passed to (*F).Add must
// be identical to the types of these parameters. The fuzz target may signal
// that it's found a problem the same way tests do: by calling T.Fail (or any
// method that calls it like T.Error or T.Fatal) or by panicking.
//
// When fuzzing is enabled (by setting the -fuzz flag to a regular expression
// that matches a specific fuzz test), the fuzz target is called with arguments
// generated by repeatedly making random changes to the seed inputs. On
// supported platforms, 'go test' compiles the test executable with fuzzing
// coverage instrumentation. The fuzzing engine uses that instrumentation to
// find and cache inputs that expand coverage, increasing the likelihood of
// finding bugs. If the fuzz target fails for a given input, the fuzzing engine
// writes the inputs that caused the failure to a file in the directory
// testdata/fuzz/<Name> within the package directory. This file later serves as
// a seed input. If the file can't be written at that location (for example,
// because the directory is read-only), the fuzzing engine writes the file to
// the fuzz cache directory within the build cache instead.
//
// When fuzzing is disabled, the fuzz target is called with the seed inputs
// registered with F.Add and seed inputs from testdata/fuzz/<Name>. In this
// mode, the fuzz test acts much like a regular test, with subtests started
// with F.Fuzz instead of T.Run.
//
// See https://go.dev/doc/fuzz for documentation about fuzzing.
//
// # Skipping
//
// Tests or benchmarks may be skipped at run time with a call to
// the Skip method of *T or *B:
//
//	func TestTimeConsuming(t *testing.T) {
//	    if testing.Short() {
//	        t.Skip("skipping test in short mode.")
//	    }
//	    ...
//	}
//
// The Skip method of *T can be used in a fuzz target if the input is invalid,
// but should not be considered a failing input. For example:
//
//	func FuzzJSONMarshaling(f *testing.F) {
//	    f.Fuzz(func(t *testing.T, b []byte) {
//	        var v interface{}
//	        if err := json.Unmarshal(b, &v); err != nil {
//	            t.Skip()
//	        }
//	        if _, err := json.Marshal(v); err != nil {
//	            t.Errorf("Marshal: %v", err)
//	        }
//	    })
//	}
//
// # Subtests and Sub-benchmarks
//
// The Run methods of T and B allow defining subtests and sub-benchmarks,
// without having to define separate functions for each. This enables uses
// like table-driven benchmarks and creating hierarchical tests.
// It also provides a way to share common setup and tear-down code:
//
//	func TestFoo(t *testing.T) {
//	    // <setup code>
//	    t.Run("A=1", func(t *testing.T) { ... })
//	    t.Run("A=2", func(t *testing.T) { ... })
//	    t.Run("B=1", func(t *testing.T) { ... })
//	    // <tear-down code>
//	}
//
// Each subtest and sub-benchmark has a unique name: the combination of the name
// of the top-level test and the sequence of names passed to Run, separated by
// slashes, with an optional trailing sequence number for disambiguation.
//
// The argument to the -run, -bench, and -fuzz command-line flags is an unanchored regular
// expression that matches the test's name. For tests with multiple slash-separated
// elements, such as subtests, the argument is itself slash-separated, with
// expressions matching each name element in turn. Because it is unanchored, an
// empty expression matches any string.
// For example, using "matching" to mean "whose name contains":
//
//	go test -run ''        # Run all tests.
//	go test -run Foo       # Run top-level tests matching "Foo", such as "TestFooBar".
//	go test -run Foo/A=    # For top-level tests matching "Foo", run subtests matching "A=".
//	go test -run /A=1      # For all top-level tests, run subtests matching "A=1".
//	go test -fuzz FuzzFoo  # Fuzz the target matching "FuzzFoo"
//
// The -run argument can also be used to run a specific value in the seed
// corpus, for debugging. For example:
//
//	go test -run=FuzzFoo/9ddb952d9814
//
// The -fuzz and -run flags can both be set, in order to fuzz a target but
// skip the execution of all other tests.
//
// Subtests can also be used to control parallelism. A parent test will only
// complete once all of its subtests complete. In this example, all tests are
// run in parallel with each other, and only with each other, regardless of
// other top-level tests that may be defined:
//
//	func TestGroupedParallel(t *testing.T) {
//	    for _, tc := range tests {
//	        tc := tc // capture range variable
//	        t.Run(tc.Name, func(t *testing.T) {
//	            t.Parallel()
//	            ...
//	        })
//	    }
//	}
//
// Run does not return until parallel subtests have completed, providing a way
// to clean up after a group of parallel tests:
//
//	func TestTeardownParallel(t *testing.T) {
//	    // This Run will not return until the parallel tests finish.
//	    t.Run("group", func(t *testing.T) {
//	        t.Run("Test1", parallelTest1)
//	        t.Run("Test2", parallelTest2)
//	        t.Run("Test3", parallelTest3)
//	    })
//	    // <tear-down code>
//	}
//
// # Main
//
// It is sometimes necessary for a test or benchmark program to do extra setup or teardown
// before or after it executes. It is also sometimes necessary to control
// which code runs on the main thread. To support these and other cases,
// if a test file contains a function:
//
//	func TestMain(m *testing.M)
//
// then the generated test will call TestMain(m) instead of running the tests or benchmarks
// directly. TestMain runs in the main goroutine and can do whatever setup
// and teardown is necessary around a call to m.Run. m.Run will return an exit
// code that may be passed to os.Exit. If TestMain returns, the test wrapper
// will pass the result of m.Run to os.Exit itself.
//
// When TestMain is called, flag.Parse has not been run. If TestMain depends on
// command-line flags, including those of the testing package, it should call
// flag.Parse explicitly. Command line flags are always parsed by the time test
// or benchmark functions run.
//
// A simple implementation of TestMain is:
//
//	func TestMain(m *testing.M) {
//		// call flag.Parse() here if TestMain uses flags
//		m.Run()
//	}
//
// TestMain is a low-level primitive and should not be necessary for casual
// testing needs, where ordinary test functions suffice.
package testing

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"internal/goexperiment"
	"internal/race"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/trace"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

var initRan bool

// Init registers testing flags. These flags are automatically registered by
// the "go test" command before running test functions, so Init is only needed
// when calling functions such as Benchmark without using "go test".
//
// Init is not safe to call concurrently. It has no effect if it was already called.
func Init() {
	if initRan {
		return
	}
	initRan = true
	// The short flag requests that tests run more quickly, but its functionality
	// is provided by test writers themselves. The testing package is just its
	// home. The all.bash installation script sets it to make installation more
	// efficient, but by default the flag is off so a plain "go test" will do a
	// full test of the package.
	short = flag.Bool("test.short", false, "run smaller test suite to save time")

	// The failfast flag requests that test execution stop after the first test failure.
	failFast = flag.Bool("test.failfast", false, "do not start new tests after the first test failure")

	// The directory in which to create profile files and the like. When run from
	// "go test", the binary always runs in the source directory for the package;
	// this flag lets "go test" tell the binary to write the files in the directory where
	// the "go test" command is run.
	outputDir = flag.String("test.outputdir", "", "write profiles to `dir`")
	// Report as tests are run; default is silent for success.
	flag.Var(&chatty, "test.v", "verbose: print additional output")
	count = flag.Uint("test.count", 1, "run tests and benchmarks `n` times")
	coverProfile = flag.String("test.coverprofile", "", "write a coverage profile to `file`")
	gocoverdir = flag.String("test.gocoverdir", "", "write coverage intermediate files to this directory")
	matchList = flag.String("test.list", "", "list tests, examples, and benchmarks matching `regexp` then exit")
	match = flag.String("test.run", "", "run only tests and examples matching `regexp`")
	skip = flag.String("test.skip", "", "do not list or run tests matching `regexp`")
	memProfile = flag.String("test.memprofile", "", "write an allocation profile to `file`")
	memProfileRate = flag.Int("test.memprofilerate", 0, "set memory allocation profiling `rate` (see runtime.MemProfileRate)")
	cpuProfile = flag.String("test.cpuprofile", "", "write a cpu profile to `file`")
	blockProfile = flag.String("test.blockprofile", "", "write a goroutine blocking profile to `file`")
	blockProfileRate = flag.Int("test.blockprofilerate", 1, "set blocking profile `rate` (see runtime.SetBlockProfileRate)")
	mutexProfile = flag.String("test.mutexprofile", "", "write a mutex contention profile to the named file after execution")
	mutexProfileFraction = flag.Int("test.mutexprofilefraction", 1, "if >= 0, calls runtime.SetMutexProfileFraction()")
	panicOnExit0 = flag.Bool("test.paniconexit0", false, "panic on call to os.Exit(0)")
	traceFile = flag.String("test.trace", "", "write an execution trace to `file`")
	timeout = flag.Duration("test.timeout", 0, "panic test binary after duration `d` (default 0, timeout disabled)")
	cpuListStr = flag.String("test.cpu", "", "comma-separated `list` of cpu counts to run each test with")
	parallel = flag.Int("test.parallel", runtime.GOMAXPROCS(0), "run at most `n` tests in parallel")
	testlog = flag.String("test.testlogfile", "", "write test action log to `file` (for use only by cmd/go)")
	shuffle = flag.String("test.shuffle", "off", "randomize the execution order of tests and benchmarks")
	fullPath = flag.Bool("test.fullpath", false, "show full file names in error messages")

	initBenchmarkFlags()
	initFuzzFlags()
}

var (
	// Flags, registered during Init.
	short                *bool
	failFast             *bool
	outputDir            *string
	chatty               chattyFlag
	count                *uint
	coverProfile         *string
	gocoverdir           *string
	matchList            *string
	match                *string
	skip                 *string
	memProfile           *string
	memProfileRate       *int
	cpuProfile           *string
	blockProfile         *string
	blockProfileRate     *int
	mutexProfile         *string
	mutexProfileFraction *int
	panicOnExit0         *bool
	traceFile            *string
	timeout              *time.Duration
	cpuListStr           *string
	parallel             *int
	shuffle              *string
	testlog              *string
	fullPath             *bool

	haveExamples bool // are there examples?

	cpuList     []int
	testlogFile *os.File

	numFailed atomic.Uint32 // number of test failures

	running sync.Map // map[string]time.Time of running, unpaused tests
)

type chattyFlag struct {
	on   bool // -v is set in some form
	json bool // -v=test2json is set, to make output better for test2json
}

func (*chattyFlag) IsBoolFlag() bool { return true }

func (f *chattyFlag) Set(arg string) error {
	switch arg {
	default:
		return fmt.Errorf("invalid flag -test.v=%s", arg)
	case "true", "test2json":
		f.on = true
		f.json = arg == "test2json"
	case "false":
		f.on = false
		f.json = false
	}
	return nil
}

func (f *chattyFlag) String() string {
	if f.json {
		return "test2json"
	}
	if f.on {
		return "true"
	}
	return "false"
}

func (f *chattyFlag) Get() any {
	if f.json {
		return "test2json"
	}
	return f.on
}

const marker = byte(0x16) // ^V for framing

func (f *chattyFlag) prefix() string {
	if f.json {
		return string(marker)
	}
	return ""
}

type chattyPrinter struct {
	w          io.Writer
	lastNameMu sync.Mutex // guards lastName
	lastName   string     // last printed test name in chatty mode
	json       bool       // -v=json output mode
}

func newChattyPrinter(w io.Writer) *chattyPrinter {
	return &chattyPrinter{w: w, json: chatty.json}
}

// prefix is like chatty.prefix but using p.json instead of chatty.json.
// Using p.json allows tests to check the json behavior without modifying
// the global variable. For convenience, we allow p == nil and treat
// that as not in json mode (because it's not chatty at all).
func (p *chattyPrinter) prefix() string {
	if p != nil && p.json {
		return string(marker)
	}
	return ""
}

// Updatef prints a message about the status of the named test to w.
//
// The formatted message must include the test name itself.
func (p *chattyPrinter) Updatef(testName, format string, args ...any) {
	p.lastNameMu.Lock()
	defer p.lastNameMu.Unlock()

	// Since the message already implies an association with a specific new test,
	// we don't need to check what the old test name was or log an extra NAME line
	// for it. (We're updating it anyway, and the current message already includes
	// the test name.)
	p.lastName = testName
	fmt.Fprintf(p.w, p.prefix()+format, args...)
}

// Printf prints a message, generated by the named test, that does not
// necessarily mention that tests's name itself.
func (p *chattyPrinter) Printf(testName, format string, args ...any) {
	p.lastNameMu.Lock()
	defer p.lastNameMu.Unlock()

	if p.lastName == "" {
		p.lastName = testName
	} else if p.lastName != testName {
		fmt.Fprintf(p.w, "%s=== NAME  %s\n", p.prefix(), testName)
		p.lastName = testName
	}

	fmt.Fprintf(p.w, format, args...)
}

// The maximum number of stack frames to go through when skipping helper functions for
// the purpose of decorating log messages.
const maxStackLen = 50

// common holds the elements common between T and B and
// captures common methods such as Errorf.
type common struct {
	mu          sync.RWMutex         // guards this group of fields
	output      []byte               // Output generated by test or benchmark.
	w           io.Writer            // For flushToParent.
	ran         bool                 // Test or benchmark (or one of its subtests) was executed.
	failed      bool                 // Test or benchmark has failed.
	skipped     bool                 // Test or benchmark has been skipped.
	done        bool                 // Test is finished and all subtests have completed.
	helperPCs   map[uintptr]struct{} // functions to be skipped when writing file/line info
	helperNames map[string]struct{}  // helperPCs converted to function names
	cleanups    []func()             // optional functions to be called at the end of the test
	cleanupName string               // Name of the cleanup function.
	cleanupPc   []uintptr            // The stack trace at the point where Cleanup was called.
	finished    bool                 // Test function has completed.
	inFuzzFn    bool                 // Whether the fuzz target, if this is one, is running.

	chatty         *chattyPrinter // A copy of chattyPrinter, if the chatty flag is set.
	bench          bool           // Whether the current test is a benchmark.
	hasSub         atomic.Bool    // whether there are sub-benchmarks.
	cleanupStarted atomic.Bool    // Registered cleanup callbacks have started to execute
	runner         string         // Function name of tRunner running the test.
	isParallel     bool           // Whether the test is parallel.

	parent   *common
	level    int               // Nesting depth of test or benchmark.
	creator  []uintptr         // If level > 0, the stack trace at the point where the parent called t.Run.
	name     string            // Name of test or benchmark.
	start    highPrecisionTime // Time test or benchmark started
	duration time.Duration
	barrier  chan bool // To signal parallel subtests they may start. Nil when T.Parallel is not present (B) or not usable (when fuzzing).
	signal   chan bool // To signal a test is done.
	sub      []*T      // Queue of subtests to be run in parallel.

	lastRaceErrors  atomic.Int64 // Max value of race.Errors seen during the test or its subtests.
	raceErrorLogged atomic.Bool

	tempDirMu  sync.Mutex
	tempDir    string
	tempDirErr error
	tempDirSeq int32

	ctx       context.Context
	cancelCtx context.CancelFunc
}

// Short reports whether the -test.short flag is set.
func Short() bool {
	if short == nil {
		panic("testing: Short called before Init")
	}
	// Catch code that calls this from TestMain without first calling flag.Parse.
	if !flag.Parsed() {
		panic("testing: Short called before Parse")
	}

	return *short
}

// testBinary is set by cmd/go to "1" if this is a binary built by "go test".
// The value is set to "1" by a -X option to cmd/link. We assume that
// because this is possible, the compiler will not optimize testBinary
// into a constant on the basis that it is an unexported package-scope
// variable that is never changed. If the compiler ever starts implementing
// such an optimization, we will need some technique to mark this variable
// as "changed by a cmd/link -X option".
var testBinary = "0"

// Testing reports whether the current code is being run in a test.
// This will report true in programs created by "go test",
// false in programs created by "go build".
func Testing() bool {
	return testBinary == "1"
}

// CoverMode reports what the test coverage mode is set to. The
// values are "set", "count", or "atomic". The return value will be
// empty if test coverage is not enabled.
func CoverMode() string {
	if goexperiment.CoverageRedesign {
		return cover2.mode
	}
	return cover.Mode
}

// Verbose reports whether the -test.v flag is set.
func Verbose() bool {
	// Same as in Short.
	if !flag.Parsed() {
		panic("testing: Verbose called before Parse")
	}
	return chatty.on
}

func (c *common) checkFuzzFn(name string) {
	if c.inFuzzFn {
		panic(fmt.Sprintf("testing: f.%s was called inside the fuzz target, use t.%s instead", name, name))
	}
}

// frameSkip searches, starting after skip frames, for the first caller frame
// in a function not marked as a helper and returns that frame.
// The search stops if it finds a tRunner function that
// was the entry point into the test and the test is not a subtest.
// This function must be called with c.mu held.
func (c *common) frameSkip(skip int) runtime.Frame {
	// If the search continues into the parent test, we'll have to hold
	// its mu temporarily. If we then return, we need to unlock it.
	shouldUnlock := false
	defer func() {
		if shouldUnlock {
			c.mu.Unlock()
		}
	}()
	var pc [maxStackLen]uintptr
	// Skip two extra frames to account for this function
	// and runtime.Callers itself.
	n := runtime.Callers(skip+2, pc[:])
	if n == 0 {
		panic("testing: zero callers found")
	}
	frames := runtime.CallersFrames(pc[:n])
	var firstFrame, prevFrame, frame runtime.Frame
	for more := true; more; prevFrame = frame {
		frame, more = frames.Next()
		if frame.Function == "runtime.gopanic" {
			continue
		}
		if frame.Function == c.cleanupName {
			frames = runtime.CallersFrames(c.cleanupPc)
			continue
		}
		if firstFrame.PC == 0 {
			firstFrame = frame
		}
		if frame.Function == c.runner {
			// We've gone up all the way to the tRunner calling
			// the test function (so the user must have
			// called tb.Helper from inside that test function).
			// If this is a top-level test, only skip up to the test function itself.
			// If we're in a subtest, continue searching in the parent test,
			// starting from the point of the call to Run which created this subtest.
			if c.level > 1 {
				frames = runtime.CallersFrames(c.creator)
				parent := c.parent
				// We're no longer looking at the current c after this point,
				// so we should unlock its mu, unless it's the original receiver,
				// in which case our caller doesn't expect us to do that.
				if shouldUnlock {
					c.mu.Unlock()
				}
				c = parent
				// Remember to unlock c.mu when we no longer need it, either
				// because we went up another nesting level, or because we
				// returned.
				shouldUnlock = true
				c.mu.Lock()
				continue
			}
			return prevFrame
		}
		// If more helper PCs have been added since we last did the conversion
		if c.helperNames == nil {
			c.helperNames = make(map[string]struct{})
			for pc := range c.helperPCs {
				c.helperNames[pcToName(pc)] = struct{}{}
			}
		}
		if _, ok := c.helperNames[frame.Function]; !ok {
			// Found a frame that wasn't inside a helper function.
			return frame
		}
	}
	return firstFrame
}

// decorate prefixes the string with the file and line of the call site
// and inserts the final newline if needed and indentation spaces for formatting.
// This function must be called with c.mu held.
func (c *common) decorate(s string, skip int) string {
	frame := c.frameSkip(skip)
	file := frame.File
	line := frame.Line
	if file != "" {
		if *fullPath {
			// If relative path, truncate file name at last file name separator.
		} else if index := strings.LastIndexAny(file, `/\`); index >= 0 {
			file = file[index+1:]
		}
	} else {
		file = "???"
	}
	if line == 0 {
		line = 1
	}
	buf := new(strings.Builder)
	// Every line is indented at least 4 spaces.
	buf.WriteString("    ")
	fmt.Fprintf(buf, "%s:%d: ", file, line)
	lines := strings.Split(s, "\n")
	if l := len(lines); l > 1 && lines[l-1] == "" {
		lines = lines[:l-1]
	}
	for i, line := range lines {
		if i > 0 {
			// Second and subsequent lines are indented an additional 4 spaces.
			buf.WriteString("\n        ")
		}
		buf.WriteString(line)
	}
	buf.WriteByte('\n')
	return buf.String()
}

// flushToParent writes c.output to the parent after first writing the header
// with the given format and arguments.
func (c *common) flushToParent(testName, format string, args ...any) {
	p := c.parent
	p.mu.Lock()
	defer p.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.output) > 0 {
		// Add the current c.output to the print,
		// and then arrange for the print to replace c.output.
		// (This displays the logged output after the --- FAIL line.)
		format += "%s"
		args = append(args[:len(args):len(args)], c.output)
		c.output = c.output[:0]
	}

	if c.chatty != nil && (p.w == c.chatty.w || c.chatty.json) {
		// We're flushing to the actual output, so track that this output is
		// associated with a specific test (and, specifically, that the next output
		// is *not* associated with that test).
		//
		// Moreover, if c.output is non-empty it is important that this write be
		// atomic with respect to the output of other tests, so that we don't end up
		// with confusing '=== NAME' lines in the middle of our '--- PASS' block.
		// Neither humans nor cmd/test2json can parse those easily.
		// (See https://go.dev/issue/40771.)
		//
		// If test2json is used, we never flush to parent tests,
		// so that the json stream shows subtests as they finish.
		// (See https://go.dev/issue/29811.)
		c.chatty.Updatef(testName, format, args...)
	} else {
		// We're flushing to the output buffer of the parent test, which will
		// itself follow a test-name header when it is finally flushed to stdout.
		fmt.Fprintf(p.w, c.chatty.prefix()+format, args...)
	}
}

type indenter struct {
	c *common
}

func (w indenter) Write(b []byte) (n int, err error) {
	n = len(b)
	for len(b) > 0 {
		end := bytes.IndexByte(b, '\n')
		if end == -1 {
			end = len(b)
		} else {
			end++
		}
		// An indent of 4 spaces will neatly align the dashes with the status
		// indicator of the parent.
		line := b[:end]
		if line[0] == marker {
			w.c.output = append(w.c.output, marker)
			line = line[1:]
		}
		const indent = "    "
		w.c.output = append(w.c.output, indent...)
		w.c.output = append(w.c.output, line...)
		b = b[end:]
	}
	return
}

// fmtDuration returns a string representing d in the form "87.00s".
func fmtDuration(d time.Duration) string {
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// TB is the interface common to T, B, and F.
type TB interface {
	Cleanup(func())
	Error(args ...any)
	Errorf(format string, args ...any)
	Fail()
	FailNow()
	Failed() bool
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Helper()
	Log(args ...any)
	Logf(format string, args ...any)
	Name() string
	Setenv(key, value string)
	Chdir(dir string)
	Skip(args ...any)
	SkipNow()
	Skipf(format string, args ...any)
	Skipped() bool
	TempDir() string
	Context() context.Context

	// A private method to prevent users implementing the
	// interface and so future additions to it will not
	// violate Go 1 compatibility.
	private()
}

var _ TB = (*T)(nil)
var _ TB = (*B)(nil)

// T is a type passed to Test functions to manage test state and support formatted test logs.
//
// A test ends when its Test function returns or calls any of the methods
// FailNow, Fatal, Fatalf, SkipNow, Skip, or Skipf. Those methods, as well as
// the Parallel method, must be called only from
"""




```