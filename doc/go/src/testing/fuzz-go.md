Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Scan and Purpose Identification:** The first step is to quickly scan the code for keywords and structural elements. Keywords like `package testing`, `func initFuzzFlags`, `type F`, `func (f *F) Fuzz`, and comments mentioning "fuzz test" strongly suggest this code is related to the fuzzing functionality within Go's `testing` package.

2. **Identify Key Structures and Functions:**  After the initial scan, I'd focus on identifying the core data structures and functions.
    * **`F` struct:** This is clearly the central struct for interacting with fuzz tests. Its methods are likely how users control and configure fuzzing.
    * **`F.Fuzz()` method:** This function's name screams "this is where the fuzzing happens."  Its documentation and signature are crucial.
    * **`F.Add()` method:**  This hints at providing initial "seed" data for the fuzzer.
    * **`initFuzzFlags()`:** This function name strongly suggests it's responsible for setting up command-line flags related to fuzzing.
    * **`runFuzzTests()` and `runFuzzing()`:**  These functions seem to be responsible for executing the fuzz tests in different modes.

3. **Analyze `initFuzzFlags()`:**  This is a straightforward function. It defines several command-line flags using `flag.String`, `flag.Var`. I would note down the name and purpose of each flag.

4. **Deep Dive into the `F` Struct and its Methods:** This is the most important part.
    * **`F` fields:** I'd examine the fields of the `F` struct to understand its internal state (e.g., `common`, `fstate`, `tstate`, `corpus`, `fuzzCalled`). The comments are helpful here.
    * **`F.Helper()`, `F.Fail()`, `F.Skipped()`:** These are standard testing methods, but the code includes checks for being called inside the fuzz target (`f.inFuzzFn`), which is important to note.
    * **`F.Add()`:**  Analyze how it adds values to the `corpus`. The type checking (`supportedTypes`) is also significant.
    * **`F.Fuzz()`:** This deserves the most attention. I'd break down its logic step-by-step:
        * **Argument Validation:**  Checks the signature of the provided fuzz function.
        * **Seed Corpus Loading:** Handles loading seed data from `testdata/fuzz` and via `F.Add`. The logic for coordinator and worker processes is distinct.
        * **`run()` function:**  This inner function seems to execute the fuzz target with a given input. It creates a `T` instance, which is standard Go testing.
        * **Fuzzing Modes (Coordinator/Worker/Seed Only):** The `switch f.fstate.mode` statement reveals the different ways fuzzing can be executed. This is a key architectural aspect.

5. **Understand Fuzzing Modes:** The code clearly distinguishes between `fuzzCoordinator`, `fuzzWorker`, and `seedCorpusOnly`. Understanding the responsibilities of each mode is crucial for explaining how the fuzzing engine works.

6. **Analyze `runFuzzTests()` and `runFuzzing()`:**
    * **`runFuzzTests()`:** Focuses on running the seed corpus without the fuzzing engine. It uses the standard `T` and `tRunner`.
    * **`runFuzzing()`:**  This function orchestrates the actual fuzzing process, potentially involving coordinator and worker processes. It uses the `F` struct and its methods.

7. **Identify Error Handling and Reporting:** Look for how errors are handled (e.g., `f.Fatal()`, `f.Errorf()`, the `fuzzCrashError` interface) and how results are reported (the `fuzzResult` struct).

8. **Look for Potential Pitfalls:**  The comments within the code provide hints about common mistakes, particularly around calling `*F` methods inside the fuzz target. The documentation for `F.Fuzz()` also provides important constraints.

9. **Structure the Answer:**  Organize the findings into logical sections:
    * **Functionality Overview:** A high-level summary of what the code does.
    * **Detailed Feature Breakdown:** Explain each major function and its purpose.
    * **Code Example:** Illustrate how to use the `F.Fuzz()` function. Include sample input and expected behavior.
    * **Command-Line Arguments:** Detail the flags defined in `initFuzzFlags()`.
    * **Common Mistakes:**  Explain the restrictions on using `*F` methods within the fuzz target.

10. **Refine and Review:**  Go back through the analysis and the generated answer to ensure accuracy, clarity, and completeness. Double-check the code examples and explanations of command-line flags. Ensure the language is clear and easy to understand.

**(Self-Correction Example during the process):**  Initially, I might have just thought "fuzzing" is one monolithic process. However, noticing the `fuzzCoordinator` and `fuzzWorker` modes prompted me to realize that the `testing` package uses a distributed approach for fuzzing. This would lead to a more nuanced explanation of `runFuzzing()`. Similarly, the comments about calling `*F` methods inside the fuzz target highlighted an important constraint that needs to be explained clearly in the "Common Mistakes" section.
这段代码是Go语言 `testing` 包中用于实现模糊测试（Fuzzing）功能的一部分。它定义了用于编写和运行模糊测试的结构体和方法。

以下是代码的主要功能：

**1. 模糊测试的入口和控制结构 (`F` 结构体及其方法):**

*   **`F` 结构体:**  `F` 是传递给模糊测试函数的类型，它提供了与模糊测试框架交互的方法。它类似于普通的 `T` 结构体，但专门用于模糊测试。
*   **`F.Add(args ...any)`:**  向模糊测试的种子语料库（seed corpus）添加初始输入。这些输入会在模糊测试开始时被首先执行。
*   **`F.Fuzz(ff any)`:**  这是启动模糊测试引擎的关键方法。它接收一个模糊目标函数 `ff` 作为参数。这个函数将被重复调用，每次使用不同的、由模糊测试引擎生成的输入。
*   **`F.Helper()`:**  标记调用函数为辅助函数，用于改进错误报告。
*   **`F.Fail()`, `F.Skipped()`:**  用于标记模糊测试失败或跳过，但与普通的单元测试略有不同，在模糊目标函数内部不能直接调用，应该使用 `t.Fail()` 等。

**2. 模糊测试的配置 (全局变量和 `initFuzzFlags` 函数):**

*   **`initFuzzFlags()`:**  初始化与模糊测试相关的命令行标志，允许用户在运行 `go test` 时控制模糊测试的行为。
*   **`matchFuzz *string` (`-test.fuzz`):**  一个正则表达式，用于指定要运行的模糊测试。只有名称匹配该正则表达式的模糊测试才会被执行。
*   **`fuzzDuration durationOrCountFlag` (`-test.fuzztime`):**  指定模糊测试运行的时间或迭代次数。默认情况下，模糊测试会无限期运行。
*   **`minimizeDuration durationOrCountFlag` (`-test.fuzzminimizetime`):**  指定在找到导致失败的输入后，用于最小化该输入的时间。最小化是指找到导致失败的最小输入。
*   **`fuzzCacheDir *string` (`-test.fuzzcachedir`):**  指定一个目录，用于存储有趣的模糊测试输入。这个选项主要供 `cmd/go` 工具使用。
*   **`isFuzzWorker *bool` (`-test.fuzzworker`):**  一个布尔标志，指示当前进程是否是模糊测试的工作进程。这个选项主要供 `cmd/go` 工具使用。

**3. 模糊测试的执行模式 (`fuzzState` 和 `fuzzMode`):**

*   **`fuzzState` 结构体:**  保存了模糊测试的全局状态，包括依赖注入的 `testDeps` 和当前的模糊测试模式 `fuzzMode`。
*   **`fuzzMode` 类型:**  定义了模糊测试的几种执行模式：
    *   `seedCorpusOnly`: 只运行种子语料库中的输入，不进行模糊生成。
    *   `fuzzCoordinator`:  作为协调器进程运行，负责协调工作进程进行模糊测试。
    *   `fuzzWorker`:  作为工作进程运行，接收协调器的指令并执行模糊测试。

**4. 模糊测试的运行函数 (`runFuzzTests` 和 `runFuzzing`):**

*   **`runFuzzTests(deps testDeps, fuzzTests []InternalFuzzTarget, deadline time.Time)`:**  运行匹配 `-test.run` 模式的模糊测试，但仅执行种子语料库中的输入，不会进行模糊生成。
*   **`runFuzzing(deps testDeps, fuzzTests []InternalFuzzTarget)`:**  根据 `-test.fuzz` 标志运行匹配的模糊测试。这个函数会启动模糊测试引擎，根据配置生成和变异输入。

**可以推理出它是什么go语言功能的实现：**

这段代码实现了 **Go语言的模糊测试功能**。 模糊测试是一种自动化测试技术，它通过向程序提供随机或半随机的输入，来发现潜在的错误、崩溃或安全漏洞。

**Go代码举例说明:**

```go
package mypackage

import (
	"strings"
	"testing"
)

func FuzzReverseString(f *testing.F) {
	// 添加一些种子输入
	f.Add("hello")
	f.Add("world")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		reversed := reverse(s)
		// 假设我们期望一个字符串反转两次后回到原始状态
		doubleReversed := reverse(reversed)
		if s != doubleReversed {
			t.Errorf("反转两次后不等于原始字符串: original = %q, reversed = %q, doubleReversed = %q", s, reversed, doubleReversed)
		}
	})
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
```

**假设的输入与输出：**

*   **输入：**  模糊测试引擎可能会生成各种字符串作为 `s` 的值，包括空字符串、包含特殊字符的字符串、非常长的字符串等等。
*   **输出：** 如果模糊测试引擎生成一个导致 `s != doubleReversed` 的字符串，`t.Errorf` 将会被调用，报告一个失败。 例如，如果 `reverse` 函数有缺陷，处理某些 Unicode 字符时可能出错，模糊测试就可能发现这样的输入。

**命令行参数的具体处理:**

*   **`-test.fuzz=<regexp>`:**  指定要运行的模糊测试的正则表达式。例如，`go test -fuzz=Reverse` 将只运行名称包含 "Reverse" 的模糊测试。
*   **`-test.fuzztime=<duration|count>`:**  指定模糊测试的运行时间或迭代次数。
    *   可以使用时间单位，如 `10s` (10秒)，`1m` (1分钟)。
    *   也可以使用 `N` 后跟一个数字表示迭代次数，例如 `1000` 表示运行 1000 次迭代。
    *   默认情况下，如果不指定 `-test.fuzztime`，模糊测试会无限期运行，直到被手动停止。
*   **`-test.fuzzminimizetime=<duration|count>`:** 指定在找到失败输入后，用于最小化该输入的时间或迭代次数。 最小化过程旨在找到导致失败的最小输入，这有助于理解问题的根本原因。
*   **`-test.fuzzcachedir=<directory>`:** 指定一个目录，用于存储有趣的模糊测试输入。这个目录通常由 `cmd/go` 工具内部使用，用户通常不需要手动设置。
*   **`-test.fuzzworker`:**  这是一个布尔标志，通常由 `cmd/go` 工具在内部使用，用于指示当前进程是一个模糊测试的工作进程。用户通常不需要手动设置。

**使用者易犯错的点:**

*   **在模糊目标函数内部调用 `*F` 的方法 (如 `f.Log`, `f.Error`, `f.Skip`):**  这是不允许的。模糊目标函数接收的是 `*testing.T` 类型的参数 `t`，应该使用 `t.Log`, `t.Error`, `t.Skip` 等方法。
    ```go
    func FuzzExample(f *testing.F) {
        f.Fuzz(func(t *testing.T, input string) {
            // 错误示例：在模糊目标函数内部使用 f.Log
            // f.Logf("processing input: %s", input)

            // 正确示例：使用 t.Log
            t.Logf("processing input: %s", input)

            if strings.Contains(input, "bad") {
                // 错误示例：在模糊目标函数内部使用 f.Fail
                // f.Fail()

                // 正确示例：使用 t.Fail
                t.Fail()
            }
        })
    }
    ```
*   **修改模糊目标函数的输入参数:**  模糊测试引擎可能会复用输入参数的内存，因此在模糊目标函数内部修改输入参数可能会导致意外的行为和竞争条件。应该将输入视为只读。
    ```go
    func FuzzModifyInput(f *testing.F) {
        f.Fuzz(func(t *testing.T, b []byte) {
            // 错误示例：修改输入 slice
            // b[0] = 0

            // 正确示例：复制一份再修改
            copyOfB := append([]byte{}, b...)
            // 对 copyOfB 进行修改操作
        })
    }
    ```
*   **模糊目标函数不是确定性的:** 模糊测试依赖于重现失败的输入。如果模糊目标函数的行为依赖于外部状态（如时间、随机数生成器的种子等），那么很难重现失败的场景。模糊目标函数应该对相同的输入产生相同的行为。
*   **模糊目标函数执行时间过长:**  如果模糊目标函数执行时间过长，会降低模糊测试的效率。应该尽量保持模糊目标函数的执行速度快。
*   **没有添加足够的种子语料库:**  好的种子语料库可以帮助模糊测试更快地找到有趣的输入和潜在的 bug。应该根据被测试代码的特性添加有代表性的种子输入。

总而言之，这段代码是 Go 语言模糊测试功能的核心实现，它允许开发者通过提供模糊目标函数和一些配置参数，自动化地测试代码的健壮性和潜在的错误。

Prompt: 
```
这是路径为go/src/testing/fuzz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testing

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

func initFuzzFlags() {
	matchFuzz = flag.String("test.fuzz", "", "run the fuzz test matching `regexp`")
	flag.Var(&fuzzDuration, "test.fuzztime", "time to spend fuzzing; default is to run indefinitely")
	flag.Var(&minimizeDuration, "test.fuzzminimizetime", "time to spend minimizing a value after finding a failing input")

	fuzzCacheDir = flag.String("test.fuzzcachedir", "", "directory where interesting fuzzing inputs are stored (for use only by cmd/go)")
	isFuzzWorker = flag.Bool("test.fuzzworker", false, "coordinate with the parent process to fuzz random values (for use only by cmd/go)")
}

var (
	matchFuzz        *string
	fuzzDuration     durationOrCountFlag
	minimizeDuration = durationOrCountFlag{d: 60 * time.Second, allowZero: true}
	fuzzCacheDir     *string
	isFuzzWorker     *bool

	// corpusDir is the parent directory of the fuzz test's seed corpus within
	// the package.
	corpusDir = "testdata/fuzz"
)

// fuzzWorkerExitCode is used as an exit code by fuzz worker processes after an
// internal error. This distinguishes internal errors from uncontrolled panics
// and other failures. Keep in sync with internal/fuzz.workerExitCode.
const fuzzWorkerExitCode = 70

// InternalFuzzTarget is an internal type but exported because it is
// cross-package; it is part of the implementation of the "go test" command.
type InternalFuzzTarget struct {
	Name string
	Fn   func(f *F)
}

// F is a type passed to fuzz tests.
//
// Fuzz tests run generated inputs against a provided fuzz target, which can
// find and report potential bugs in the code being tested.
//
// A fuzz test runs the seed corpus by default, which includes entries provided
// by (*F).Add and entries in the testdata/fuzz/<FuzzTestName> directory. After
// any necessary setup and calls to (*F).Add, the fuzz test must then call
// (*F).Fuzz to provide the fuzz target. See the testing package documentation
// for an example, and see the [F.Fuzz] and [F.Add] method documentation for
// details.
//
// *F methods can only be called before (*F).Fuzz. Once the test is
// executing the fuzz target, only (*T) methods can be used. The only *F methods
// that are allowed in the (*F).Fuzz function are (*F).Failed and (*F).Name.
type F struct {
	common
	fstate *fuzzState
	tstate *testState

	// inFuzzFn is true when the fuzz function is running. Most F methods cannot
	// be called when inFuzzFn is true.
	inFuzzFn bool

	// corpus is a set of seed corpus entries, added with F.Add and loaded
	// from testdata.
	corpus []corpusEntry

	result     fuzzResult
	fuzzCalled bool
}

var _ TB = (*F)(nil)

// corpusEntry is an alias to the same type as internal/fuzz.CorpusEntry.
// We use a type alias because we don't want to export this type, and we can't
// import internal/fuzz from testing.
type corpusEntry = struct {
	Parent     string
	Path       string
	Data       []byte
	Values     []any
	Generation int
	IsSeed     bool
}

// Helper marks the calling function as a test helper function.
// When printing file and line information, that function will be skipped.
// Helper may be called simultaneously from multiple goroutines.
func (f *F) Helper() {
	if f.inFuzzFn {
		panic("testing: f.Helper was called inside the fuzz target, use t.Helper instead")
	}

	// common.Helper is inlined here.
	// If we called it, it would mark F.Helper as the helper
	// instead of the caller.
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.helperPCs == nil {
		f.helperPCs = make(map[uintptr]struct{})
	}
	// repeating code from callerName here to save walking a stack frame
	var pc [1]uintptr
	n := runtime.Callers(2, pc[:]) // skip runtime.Callers + Helper
	if n == 0 {
		panic("testing: zero callers found")
	}
	if _, found := f.helperPCs[pc[0]]; !found {
		f.helperPCs[pc[0]] = struct{}{}
		f.helperNames = nil // map will be recreated next time it is needed
	}
}

// Fail marks the function as having failed but continues execution.
func (f *F) Fail() {
	// (*F).Fail may be called by (*T).Fail, which we should allow. However, we
	// shouldn't allow direct (*F).Fail calls from inside the (*F).Fuzz function.
	if f.inFuzzFn {
		panic("testing: f.Fail was called inside the fuzz target, use t.Fail instead")
	}
	f.common.Helper()
	f.common.Fail()
}

// Skipped reports whether the test was skipped.
func (f *F) Skipped() bool {
	// (*F).Skipped may be called by tRunner, which we should allow. However, we
	// shouldn't allow direct (*F).Skipped calls from inside the (*F).Fuzz function.
	if f.inFuzzFn {
		panic("testing: f.Skipped was called inside the fuzz target, use t.Skipped instead")
	}
	f.common.Helper()
	return f.common.Skipped()
}

// Add will add the arguments to the seed corpus for the fuzz test. This will be
// a no-op if called after or within the fuzz target, and args must match the
// arguments for the fuzz target.
func (f *F) Add(args ...any) {
	var values []any
	for i := range args {
		if t := reflect.TypeOf(args[i]); !supportedTypes[t] {
			panic(fmt.Sprintf("testing: unsupported type to Add %v", t))
		}
		values = append(values, args[i])
	}
	f.corpus = append(f.corpus, corpusEntry{Values: values, IsSeed: true, Path: fmt.Sprintf("seed#%d", len(f.corpus))})
}

// supportedTypes represents all of the supported types which can be fuzzed.
var supportedTypes = map[reflect.Type]bool{
	reflect.TypeOf(([]byte)("")):  true,
	reflect.TypeOf((string)("")):  true,
	reflect.TypeOf((bool)(false)): true,
	reflect.TypeOf((byte)(0)):     true,
	reflect.TypeOf((rune)(0)):     true,
	reflect.TypeOf((float32)(0)):  true,
	reflect.TypeOf((float64)(0)):  true,
	reflect.TypeOf((int)(0)):      true,
	reflect.TypeOf((int8)(0)):     true,
	reflect.TypeOf((int16)(0)):    true,
	reflect.TypeOf((int32)(0)):    true,
	reflect.TypeOf((int64)(0)):    true,
	reflect.TypeOf((uint)(0)):     true,
	reflect.TypeOf((uint8)(0)):    true,
	reflect.TypeOf((uint16)(0)):   true,
	reflect.TypeOf((uint32)(0)):   true,
	reflect.TypeOf((uint64)(0)):   true,
}

// Fuzz runs the fuzz function, ff, for fuzz testing. If ff fails for a set of
// arguments, those arguments will be added to the seed corpus.
//
// ff must be a function with no return value whose first argument is *T and
// whose remaining arguments are the types to be fuzzed.
// For example:
//
//	f.Fuzz(func(t *testing.T, b []byte, i int) { ... })
//
// The following types are allowed: []byte, string, bool, byte, rune, float32,
// float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64.
// More types may be supported in the future.
//
// ff must not call any *F methods, e.g. (*F).Log, (*F).Error, (*F).Skip. Use
// the corresponding *T method instead. The only *F methods that are allowed in
// the (*F).Fuzz function are (*F).Failed and (*F).Name.
//
// This function should be fast and deterministic, and its behavior should not
// depend on shared state. No mutable input arguments, or pointers to them,
// should be retained between executions of the fuzz function, as the memory
// backing them may be mutated during a subsequent invocation. ff must not
// modify the underlying data of the arguments provided by the fuzzing engine.
//
// When fuzzing, F.Fuzz does not return until a problem is found, time runs out
// (set with -fuzztime), or the test process is interrupted by a signal. F.Fuzz
// should be called exactly once, unless F.Skip or [F.Fail] is called beforehand.
func (f *F) Fuzz(ff any) {
	if f.fuzzCalled {
		panic("testing: F.Fuzz called more than once")
	}
	f.fuzzCalled = true
	if f.failed {
		return
	}
	f.Helper()

	// ff should be in the form func(*testing.T, ...interface{})
	fn := reflect.ValueOf(ff)
	fnType := fn.Type()
	if fnType.Kind() != reflect.Func {
		panic("testing: F.Fuzz must receive a function")
	}
	if fnType.NumIn() < 2 || fnType.In(0) != reflect.TypeOf((*T)(nil)) {
		panic("testing: fuzz target must receive at least two arguments, where the first argument is a *T")
	}
	if fnType.NumOut() != 0 {
		panic("testing: fuzz target must not return a value")
	}

	// Save the types of the function to compare against the corpus.
	var types []reflect.Type
	for i := 1; i < fnType.NumIn(); i++ {
		t := fnType.In(i)
		if !supportedTypes[t] {
			panic(fmt.Sprintf("testing: unsupported type for fuzzing %v", t))
		}
		types = append(types, t)
	}

	// Load the testdata seed corpus. Check types of entries in the testdata
	// corpus and entries declared with F.Add.
	//
	// Don't load the seed corpus if this is a worker process; we won't use it.
	if f.fstate.mode != fuzzWorker {
		for _, c := range f.corpus {
			if err := f.fstate.deps.CheckCorpus(c.Values, types); err != nil {
				// TODO(#48302): Report the source location of the F.Add call.
				f.Fatal(err)
			}
		}

		// Load seed corpus
		c, err := f.fstate.deps.ReadCorpus(filepath.Join(corpusDir, f.name), types)
		if err != nil {
			f.Fatal(err)
		}
		for i := range c {
			c[i].IsSeed = true // these are all seed corpus values
			if f.fstate.mode == fuzzCoordinator {
				// If this is the coordinator process, zero the values, since we don't need
				// to hold onto them.
				c[i].Values = nil
			}
		}

		f.corpus = append(f.corpus, c...)
	}

	// run calls fn on a given input, as a subtest with its own T.
	// run is analogous to T.Run. The test filtering and cleanup works similarly.
	// fn is called in its own goroutine.
	run := func(captureOut io.Writer, e corpusEntry) (ok bool) {
		if e.Values == nil {
			// The corpusEntry must have non-nil Values in order to run the
			// test. If Values is nil, it is a bug in our code.
			panic(fmt.Sprintf("corpus file %q was not unmarshaled", e.Path))
		}
		if shouldFailFast() {
			return true
		}
		testName := f.name
		if e.Path != "" {
			testName = fmt.Sprintf("%s/%s", testName, filepath.Base(e.Path))
		}
		if f.tstate.isFuzzing {
			// Don't preserve subtest names while fuzzing. If fn calls T.Run,
			// there will be a very large number of subtests with duplicate names,
			// which will use a large amount of memory. The subtest names aren't
			// useful since there's no way to re-run them deterministically.
			f.tstate.match.clearSubNames()
		}

		ctx, cancelCtx := context.WithCancel(f.ctx)

		// Record the stack trace at the point of this call so that if the subtest
		// function - which runs in a separate stack - is marked as a helper, we can
		// continue walking the stack into the parent test.
		var pc [maxStackLen]uintptr
		n := runtime.Callers(2, pc[:])
		t := &T{
			common: common{
				barrier:   make(chan bool),
				signal:    make(chan bool),
				name:      testName,
				parent:    &f.common,
				level:     f.level + 1,
				creator:   pc[:n],
				chatty:    f.chatty,
				ctx:       ctx,
				cancelCtx: cancelCtx,
			},
			tstate: f.tstate,
		}
		if captureOut != nil {
			// t.parent aliases f.common.
			t.parent.w = captureOut
		}
		t.w = indenter{&t.common}
		if t.chatty != nil {
			t.chatty.Updatef(t.name, "=== RUN   %s\n", t.name)
		}
		f.common.inFuzzFn, f.inFuzzFn = true, true
		go tRunner(t, func(t *T) {
			args := []reflect.Value{reflect.ValueOf(t)}
			for _, v := range e.Values {
				args = append(args, reflect.ValueOf(v))
			}
			// Before resetting the current coverage, defer the snapshot so that
			// we make sure it is called right before the tRunner function
			// exits, regardless of whether it was executed cleanly, panicked,
			// or if the fuzzFn called t.Fatal.
			if f.tstate.isFuzzing {
				defer f.fstate.deps.SnapshotCoverage()
				f.fstate.deps.ResetCoverage()
			}
			fn.Call(args)
		})
		<-t.signal
		if t.chatty != nil && t.chatty.json {
			t.chatty.Updatef(t.parent.name, "=== NAME  %s\n", t.parent.name)
		}
		f.common.inFuzzFn, f.inFuzzFn = false, false
		return !t.Failed()
	}

	switch f.fstate.mode {
	case fuzzCoordinator:
		// Fuzzing is enabled, and this is the test process started by 'go test'.
		// Act as the coordinator process, and coordinate workers to perform the
		// actual fuzzing.
		corpusTargetDir := filepath.Join(corpusDir, f.name)
		cacheTargetDir := filepath.Join(*fuzzCacheDir, f.name)
		err := f.fstate.deps.CoordinateFuzzing(
			fuzzDuration.d,
			int64(fuzzDuration.n),
			minimizeDuration.d,
			int64(minimizeDuration.n),
			*parallel,
			f.corpus,
			types,
			corpusTargetDir,
			cacheTargetDir)
		if err != nil {
			f.result = fuzzResult{Error: err}
			f.Fail()
			fmt.Fprintf(f.w, "%v\n", err)
			if crashErr, ok := err.(fuzzCrashError); ok {
				crashPath := crashErr.CrashPath()
				fmt.Fprintf(f.w, "Failing input written to %s\n", crashPath)
				testName := filepath.Base(crashPath)
				fmt.Fprintf(f.w, "To re-run:\ngo test -run=%s/%s\n", f.name, testName)
			}
		}
		// TODO(jayconrod,katiehockman): Aggregate statistics across workers
		// and add to FuzzResult (ie. time taken, num iterations)

	case fuzzWorker:
		// Fuzzing is enabled, and this is a worker process. Follow instructions
		// from the coordinator.
		if err := f.fstate.deps.RunFuzzWorker(func(e corpusEntry) error {
			// Don't write to f.w (which points to Stdout) if running from a
			// fuzz worker. This would become very verbose, particularly during
			// minimization. Return the error instead, and let the caller deal
			// with the output.
			var buf strings.Builder
			if ok := run(&buf, e); !ok {
				return errors.New(buf.String())
			}
			return nil
		}); err != nil {
			// Internal errors are marked with f.Fail; user code may call this too, before F.Fuzz.
			// The worker will exit with fuzzWorkerExitCode, indicating this is a failure
			// (and 'go test' should exit non-zero) but a failing input should not be recorded.
			f.Errorf("communicating with fuzzing coordinator: %v", err)
		}

	default:
		// Fuzzing is not enabled, or will be done later. Only run the seed
		// corpus now.
		for _, e := range f.corpus {
			name := fmt.Sprintf("%s/%s", f.name, filepath.Base(e.Path))
			if _, ok, _ := f.tstate.match.fullName(nil, name); ok {
				run(f.w, e)
			}
		}
	}
}

func (f *F) report() {
	if *isFuzzWorker || f.parent == nil {
		return
	}
	dstr := fmtDuration(f.duration)
	format := "--- %s: %s (%s)\n"
	if f.Failed() {
		f.flushToParent(f.name, format, "FAIL", f.name, dstr)
	} else if f.chatty != nil {
		if f.Skipped() {
			f.flushToParent(f.name, format, "SKIP", f.name, dstr)
		} else {
			f.flushToParent(f.name, format, "PASS", f.name, dstr)
		}
	}
}

// fuzzResult contains the results of a fuzz run.
type fuzzResult struct {
	N     int           // The number of iterations.
	T     time.Duration // The total time taken.
	Error error         // Error is the error from the failing input
}

func (r fuzzResult) String() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

// fuzzCrashError is satisfied by a failing input detected while fuzzing.
// These errors are written to the seed corpus and can be re-run with 'go test'.
// Errors within the fuzzing framework (like I/O errors between coordinator
// and worker processes) don't satisfy this interface.
type fuzzCrashError interface {
	error
	Unwrap() error

	// CrashPath returns the path of the subtest that corresponds to the saved
	// crash input file in the seed corpus. The test can be re-run with go test
	// -run=$test/$name $test is the fuzz test name, and $name is the
	// filepath.Base of the string returned here.
	CrashPath() string
}

// fuzzState holds fields common to all fuzz tests.
type fuzzState struct {
	deps testDeps
	mode fuzzMode
}

type fuzzMode uint8

const (
	seedCorpusOnly fuzzMode = iota
	fuzzCoordinator
	fuzzWorker
)

// runFuzzTests runs the fuzz tests matching the pattern for -run. This will
// only run the (*F).Fuzz function for each seed corpus without using the
// fuzzing engine to generate or mutate inputs.
func runFuzzTests(deps testDeps, fuzzTests []InternalFuzzTarget, deadline time.Time) (ran, ok bool) {
	ok = true
	if len(fuzzTests) == 0 || *isFuzzWorker {
		return ran, ok
	}
	m := newMatcher(deps.MatchString, *match, "-test.run", *skip)
	var mFuzz *matcher
	if *matchFuzz != "" {
		mFuzz = newMatcher(deps.MatchString, *matchFuzz, "-test.fuzz", *skip)
	}

	for _, procs := range cpuList {
		runtime.GOMAXPROCS(procs)
		for i := uint(0); i < *count; i++ {
			if shouldFailFast() {
				break
			}

			tstate := newTestState(*parallel, m)
			tstate.deadline = deadline
			fstate := &fuzzState{deps: deps, mode: seedCorpusOnly}
			root := common{w: os.Stdout} // gather output in one place
			if Verbose() {
				root.chatty = newChattyPrinter(root.w)
			}
			for _, ft := range fuzzTests {
				if shouldFailFast() {
					break
				}
				testName, matched, _ := tstate.match.fullName(nil, ft.Name)
				if !matched {
					continue
				}
				if mFuzz != nil {
					if _, fuzzMatched, _ := mFuzz.fullName(nil, ft.Name); fuzzMatched {
						// If this will be fuzzed, then don't run the seed corpus
						// right now. That will happen later.
						continue
					}
				}
				ctx, cancelCtx := context.WithCancel(context.Background())
				f := &F{
					common: common{
						signal:    make(chan bool),
						barrier:   make(chan bool),
						name:      testName,
						parent:    &root,
						level:     root.level + 1,
						chatty:    root.chatty,
						ctx:       ctx,
						cancelCtx: cancelCtx,
					},
					tstate: tstate,
					fstate: fstate,
				}
				f.w = indenter{&f.common}
				if f.chatty != nil {
					f.chatty.Updatef(f.name, "=== RUN   %s\n", f.name)
				}
				go fRunner(f, ft.Fn)
				<-f.signal
				if f.chatty != nil && f.chatty.json {
					f.chatty.Updatef(f.parent.name, "=== NAME  %s\n", f.parent.name)
				}
				ok = ok && !f.Failed()
				ran = ran || f.ran
			}
			if !ran {
				// There were no tests to run on this iteration.
				// This won't change, so no reason to keep trying.
				break
			}
		}
	}

	return ran, ok
}

// runFuzzing runs the fuzz test matching the pattern for -fuzz. Only one such
// fuzz test must match. This will run the fuzzing engine to generate and
// mutate new inputs against the fuzz target.
//
// If fuzzing is disabled (-test.fuzz is not set), runFuzzing
// returns immediately.
func runFuzzing(deps testDeps, fuzzTests []InternalFuzzTarget) (ok bool) {
	if len(fuzzTests) == 0 || *matchFuzz == "" {
		return true
	}
	m := newMatcher(deps.MatchString, *matchFuzz, "-test.fuzz", *skip)
	tstate := newTestState(1, m)
	tstate.isFuzzing = true
	fstate := &fuzzState{
		deps: deps,
	}
	root := common{w: os.Stdout}
	if *isFuzzWorker {
		root.w = io.Discard
		fstate.mode = fuzzWorker
	} else {
		fstate.mode = fuzzCoordinator
	}
	if Verbose() && !*isFuzzWorker {
		root.chatty = newChattyPrinter(root.w)
	}
	var fuzzTest *InternalFuzzTarget
	var testName string
	var matched []string
	for i := range fuzzTests {
		name, ok, _ := tstate.match.fullName(nil, fuzzTests[i].Name)
		if !ok {
			continue
		}
		matched = append(matched, name)
		fuzzTest = &fuzzTests[i]
		testName = name
	}
	if len(matched) == 0 {
		fmt.Fprintln(os.Stderr, "testing: warning: no fuzz tests to fuzz")
		return true
	}
	if len(matched) > 1 {
		fmt.Fprintf(os.Stderr, "testing: will not fuzz, -fuzz matches more than one fuzz test: %v\n", matched)
		return false
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	f := &F{
		common: common{
			signal:    make(chan bool),
			barrier:   nil, // T.Parallel has no effect when fuzzing.
			name:      testName,
			parent:    &root,
			level:     root.level + 1,
			chatty:    root.chatty,
			ctx:       ctx,
			cancelCtx: cancelCtx,
		},
		fstate: fstate,
		tstate: tstate,
	}
	f.w = indenter{&f.common}
	if f.chatty != nil {
		f.chatty.Updatef(f.name, "=== RUN   %s\n", f.name)
	}
	go fRunner(f, fuzzTest.Fn)
	<-f.signal
	if f.chatty != nil {
		f.chatty.Updatef(f.parent.name, "=== NAME  %s\n", f.parent.name)
	}
	return !f.failed
}

// fRunner wraps a call to a fuzz test and ensures that cleanup functions are
// called and status flags are set. fRunner should be called in its own
// goroutine. To wait for its completion, receive from f.signal.
//
// fRunner is analogous to tRunner, which wraps subtests started with T.Run.
// Unit tests and fuzz tests work a little differently, so for now, these
// functions aren't consolidated. In particular, because there are no F.Run and
// F.Parallel methods, i.e., no fuzz sub-tests or parallel fuzz tests, a few
// simplifications are made. We also require that F.Fuzz, F.Skip, or F.Fail is
// called.
func fRunner(f *F, fn func(*F)) {
	// When this goroutine is done, either because runtime.Goexit was called, a
	// panic started, or fn returned normally, record the duration and send
	// t.signal, indicating the fuzz test is done.
	defer func() {
		// Detect whether the fuzz test panicked or called runtime.Goexit
		// without calling F.Fuzz, F.Fail, or F.Skip. If it did, panic (possibly
		// replacing a nil panic value). Nothing should recover after fRunner
		// unwinds, so this should crash the process and print stack.
		// Unfortunately, recovering here adds stack frames, but the location of
		// the original panic should still be
		// clear.
		f.checkRaces()
		if f.Failed() {
			numFailed.Add(1)
		}
		err := recover()
		if err == nil {
			f.mu.RLock()
			fuzzNotCalled := !f.fuzzCalled && !f.skipped && !f.failed
			if !f.finished && !f.skipped && !f.failed {
				err = errNilPanicOrGoexit
			}
			f.mu.RUnlock()
			if fuzzNotCalled && err == nil {
				f.Error("returned without calling F.Fuzz, F.Fail, or F.Skip")
			}
		}

		// Use a deferred call to ensure that we report that the test is
		// complete even if a cleanup function calls F.FailNow. See issue 41355.
		didPanic := false
		defer func() {
			if !didPanic {
				// Only report that the test is complete if it doesn't panic,
				// as otherwise the test binary can exit before the panic is
				// reported to the user. See issue 41479.
				f.signal <- true
			}
		}()

		// If we recovered a panic or inappropriate runtime.Goexit, fail the test,
		// flush the output log up to the root, then panic.
		doPanic := func(err any) {
			f.Fail()
			if r := f.runCleanup(recoverAndReturnPanic); r != nil {
				f.Logf("cleanup panicked with %v", r)
			}
			for root := &f.common; root.parent != nil; root = root.parent {
				root.mu.Lock()
				root.duration += highPrecisionTimeSince(root.start)
				d := root.duration
				root.mu.Unlock()
				root.flushToParent(root.name, "--- FAIL: %s (%s)\n", root.name, fmtDuration(d))
			}
			didPanic = true
			panic(err)
		}
		if err != nil {
			doPanic(err)
		}

		// No panic or inappropriate Goexit.
		f.duration += highPrecisionTimeSince(f.start)

		if len(f.sub) > 0 {
			// Unblock inputs that called T.Parallel while running the seed corpus.
			// This only affects fuzz tests run as normal tests.
			// While fuzzing, T.Parallel has no effect, so f.sub is empty, and this
			// branch is not taken. f.barrier is nil in that case.
			f.tstate.release()
			close(f.barrier)
			// Wait for the subtests to complete.
			for _, sub := range f.sub {
				<-sub.signal
			}
			cleanupStart := highPrecisionTimeNow()
			err := f.runCleanup(recoverAndReturnPanic)
			f.duration += highPrecisionTimeSince(cleanupStart)
			if err != nil {
				doPanic(err)
			}
		}

		// Report after all subtests have finished.
		f.report()
		f.done = true
		f.setRan()
	}()
	defer func() {
		if len(f.sub) == 0 {
			f.runCleanup(normalPanic)
		}
	}()

	f.start = highPrecisionTimeNow()
	f.resetRaces()
	fn(f)

	// Code beyond this point will not be executed when FailNow or SkipNow
	// is invoked.
	f.mu.Lock()
	f.finished = true
	f.mu.Unlock()
}

"""



```