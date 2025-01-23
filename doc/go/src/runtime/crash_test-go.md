Response:
我的目标是理解给定的Go代码文件 `crash_test.go` 的功能，并用中文详细解释。以下是我的思考过程：

1. **代码概览和目标识别:**  首先，我浏览了代码的导入部分 (`import`) 和 `package` 声明，确定这是 `runtime_test` 包的一部分，并且涉及到 `testing` 包，这表明这是一个测试文件。文件名 `crash_test.go` 暗示这个文件主要关注运行时崩溃相关的测试。

2. **`TestMain` 函数分析:**  `TestMain` 函数是测试包的入口点。我注意到它使用了环境变量 `RUNTIME_TEST_ENTRYPOINT` 来决定执行不同的操作。
    * 如果 `RUNTIME_TEST_ENTRYPOINT` 是 "panic"，则调用 `crashViaPanic()`。
    * 如果是 "trap"，则调用 `crashViaTrap()`。
    * 如果是其他值，会打印错误并退出。
    * 如果为空，则执行正常的测试流程 `m.Run()`。
    * `TestMain` 还检查测试执行前后是否遗留了 "core" 文件，并根据情况设置退出状态。

3. **辅助函数分析:** 我关注了几个重要的辅助函数：
    * `runTestProg` 和 `runBuiltTestProg`:  这两个函数用于运行外部的测试程序。它们处理编译（如果需要）和执行，并捕获输出。关键点是它们使用了 `testenv` 包中的工具，这表明它们依赖于 Go 的测试环境。
    * `buildTestProg`:  这个函数负责编译测试程序。它使用了 `go build` 命令，并缓存了编译结果以避免重复编译。它还使用了锁 (`sync.Mutex`) 来控制并发编译的数量。

4. **测试用例分析:** 我仔细阅读了以 `Test` 开头的函数，尝试理解每个测试用例的目标。 我发现这些测试用例覆盖了各种运行时崩溃的情况，例如：
    * `TestVDSO`:  测试在 VDSO (Virtual Dynamically-linked Shared Object) 中发生信号的情况。
    * `TestCrashHandler`: 测试自定义的 crash handler 的行为。
    * `TestDeadlock`: 测试各种死锁场景的检测。
    * `TestStackOverflow`: 测试堆栈溢出。
    * `TestThreadExhaustion`: 测试线程耗尽。
    * `TestRecursivePanic`: 测试递归 panic 的处理。
    * `TestGoexitCrash`: 测试在 `runtime.Goexit` 后发生的崩溃。
    * `TestGoNil`: 测试调用 nil 函数的 goroutine。
    * `TestMainGoroutineID`: 测试主 goroutine 的 ID。
    * `TestBreakpoint`: 测试 `runtime.Breakpoint()` 函数。
    * `TestGoexitInPanic`: 测试在 panic 期间调用 `runtime.Goexit()`。
    * `TestRuntimePanicWithRuntimeError`: 测试运行时 panic 的类型是否为 `runtime.Error`。
    * `TestPanicAfterGoexit`: 测试 `runtime.Goexit()` 后的 panic。
    * `TestNetpollDeadlock`: 测试网络轮询死锁。
    * `TestPanicTraceback`: 测试 panic 的 traceback 信息。
    * `TestPanicDeadlock*`: 测试在 panic 处理过程中发生的死锁。
    * `TestMemPprof`: 测试内存 profiling 功能。
    * `TestConcurrentMapWrites*`: 测试并发 map 访问的检测。
    * `TestPanicInlined`: 测试内联函数中的 panic 堆栈信息。
    * `TestPanicRace`: 测试 panic 时的竞争条件。
    * `TestBadTraceback`: 测试错误的 traceback 信息。
    * `TestTimePprof`: 测试时间 profiling 功能。
    * `TestAbort`: 测试 `runtime.abort()` 函数。
    * `TestRuntimePanic`: 测试运行时 panic。
    * `TestG0StackOverflow`: 测试 g0 堆栈溢出。
    * `TestCrashWhileTracing`: 测试在 tracing 期间发生的崩溃。
    * `TestDoublePanic`: 测试多次 panic 的处理。
    * `TestPanicWhilePanicking`: 测试在 panic 处理过程中再次 panic。
    * `TestPanicOnUnsafeSlice`: 测试对 nil 指针使用 `unsafe.Slice`。
    * `TestNetpollWaiters`: 测试网络轮询等待者。

5. **代码推理和示例:**  我选取了一些有代表性的测试用例，思考它们是如何工作的，并尝试提供 Go 代码示例来解释它们测试的 Go 语言功能。 例如，对于 `TestCrashHandler`，我推理出它测试的是 `recover()` 函数捕获 panic 的能力，并给出了一个简单的 `defer recover()` 的示例。

6. **命令行参数处理:**  我注意到了 `TestMain` 函数中对环境变量 `RUNTIME_TEST_ENTRYPOINT` 的使用，并解释了它的作用以及可能的取值。我还注意到了 `buildTestProg` 函数中使用了 `flagQuick` 这个 flag。

7. **易犯错的点:** 我思考了使用者在使用这些功能时可能遇到的问题，例如并发 map 访问。

8. **组织答案:**  最后，我将所有分析结果组织成清晰的中文回答，包括功能列表、代码示例、命令行参数处理和易犯错的点。我努力使用准确的术语和简洁的语言来解释复杂的概念。

通过以上步骤，我能够全面理解 `crash_test.go` 文件的功能，并用中文进行详细的解释和举例说明。 我的重点在于理解测试用例背后的 Go 语言特性，以及如何通过阅读代码和结合测试用例来推断其功能。
这个 Go 语言文件 `go/src/runtime/crash_test.go` 的主要功能是 **测试 Go 语言运行时的崩溃处理机制和相关功能**。  它通过编写各种会导致程序崩溃的场景，然后验证运行时是否按照预期处理了这些崩溃，例如是否输出了正确的错误信息、是否触发了 panic、是否能够从 panic 中恢复、是否产生了 core dump 文件（如果配置允许）等等。

下面我将详细列举它的功能，并尝试推理它测试的 Go 语言功能，并给出代码示例：

**功能列举:**

1. **测试 panic 的基本处理:** 验证 `panic` 发生时，程序能否正常终止并打印错误信息。
2. **测试 recover 的功能:** 验证 `recover` 函数能否捕获 `panic`，从而避免程序崩溃。
3. **测试 deadlock 检测:** 验证运行时能否检测到死锁并报告错误。
4. **测试 stack overflow:** 验证运行时能否检测到栈溢出并报告错误。
5. **测试线程耗尽:** 验证运行时能否检测到线程耗尽并报告错误。
6. **测试递归 panic:** 验证运行时如何处理连续发生的 panic。
7. **测试 `runtime.Goexit`:** 验证 `runtime.Goexit` 的行为，以及在 `Goexit` 后程序的状态。
8. **测试调用 nil 函数的 goroutine:** 验证尝试启动一个 nil 函数的 goroutine 会导致 panic。
9. **测试获取主 goroutine ID:** 验证能否获取到主 goroutine 的 ID。
10. **测试没有额外的 helper goroutine:**  验证在某些特定场景下，只有主 goroutine 存在。
11. **测试 `runtime.Breakpoint`:** 验证 `runtime.Breakpoint` 函数是否能触发断点（通常用于调试）。
12. **测试在 panic 中调用 `runtime.Goexit`:** 验证在这种特殊情况下程序的行为。
13. **测试运行时 panic 的类型:** 验证运行时 panic 的错误类型是否为 `runtime.Error`。
14. **测试在 `runtime.Goexit` 后发生的 panic:** 验证在 `Goexit` 后是否还能触发和处理 panic。
15. **测试网络轮询相关的死锁:** 测试在涉及网络轮询的场景下是否能检测到死锁。
16. **测试 panic 的 traceback 信息:** 验证 panic 发生时能否打印出正确的调用栈信息。
17. **测试在 panic 处理过程中发生的死锁:** 验证在处理 panic 的 defer 函数中发生死锁的情况。
18. **测试内存 profiling 功能 (`runtime/pprof`)**:  通过生成内存 profile 文件并使用 `go tool pprof` 来验证其正确性。
19. **测试并发 map 访问的检测:** 验证运行时能否检测到并发地读写或修改 map 导致的错误。
20. **测试内联函数中 panic 的堆栈信息:** 验证即使 panic 发生在内联函数中，也能提供正确的堆栈信息。
21. **测试 panic 时的竞争条件:**  模拟高并发场景下的 panic，验证其处理的正确性。
22. **测试错误的 traceback 信息:**  故意构造错误的返回地址，验证运行时如何处理和报告这种情况。
23. **测试时间 profiling 功能 (`runtime/pprof`)**:  通过生成时间 profile 文件并使用 `go tool pprof` 来验证其正确性。
24. **测试 `runtime.abort`:** 验证 `runtime.abort` 函数会直接终止程序。
25. **测试运行时自身发生的 panic:** 模拟运行时内部发生 panic 的情况。
26. **测试 g0 堆栈溢出:**  验证处理 g0 (goroutine 0) 堆栈溢出的能力。
27. **测试在 tracing 期间发生的崩溃:** 验证在使用 `runtime/trace` 进行 tracing 时发生崩溃的情况。
28. **测试多次 panic 的处理:** 验证连续抛出多个 panic 时的处理机制。
29. **测试在 panic 处理过程中再次 panic:** 验证在 defer 函数中再次 panic 的情况。
30. **测试对 nil 指针使用 `unsafe.Slice` 导致的 panic:** 验证这种不安全操作是否会触发预期的 panic。
31. **测试网络轮询等待者:** 测试与网络轮询相关的等待者状态。

**Go 语言功能推理与代码示例:**

这个测试文件主要测试了 Go 语言的 **错误处理机制**，特别是 **`panic` 和 `recover`**，以及 **运行时诊断功能**，例如 **死锁检测** 和 **堆栈信息生成**。  此外，它还涉及到了 **goroutine 的生命周期管理** (例如 `runtime.Goexit`) 和 **性能分析工具** (`runtime/pprof`)。

**1. `panic` 和 `recover` 的基本使用:**

假设的输入：一个会触发 panic 的函数。

```go
package main

import "fmt"

func mightPanic() {
    panic("something went wrong")
}

func main() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from:", r)
        }
    }()

    mightPanic()
    fmt.Println("This will not be printed if panic occurs")
}
```

预期输出：
```
Recovered from: something went wrong
```

这个例子演示了 `recover` 如何捕获 `mightPanic` 函数中抛出的 `panic`，使得程序不会崩溃，而是执行 `recover` 中的代码。

**2. 死锁检测:**

假设的输入：一段导致死锁的代码。

```go
package main

import "sync"

func main() {
    var mu1, mu2 sync.Mutex
    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        mu1.Lock()
        defer mu1.Unlock()
        mu2.Lock() // 永远无法获取，因为另一个 goroutine 占用了 mu2
        defer mu2.Unlock()
        println("Goroutine 1")
    }()

    go func() {
        defer wg.Done()
        mu2.Lock()
        defer mu2.Unlock()
        mu1.Lock() // 永远无法获取，因为另一个 goroutine 占用了 mu1
        defer mu1.Unlock()
        println("Goroutine 2")
    }()

    wg.Wait()
}
```

预期输出： 运行时会检测到死锁并打印如下错误信息 (输出可能包含 goroutine 的堆栈信息):

```
fatal error: all goroutines are asleep - deadlock!
```

**3. `runtime.Goexit` 的行为:**

假设的输入：一个调用 `runtime.Goexit` 的 goroutine。

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
)

func worker(wg *sync.WaitGroup) {
	defer wg.Done()
	defer fmt.Println("Worker deferred function")
	fmt.Println("Worker starting")
	runtime.Goexit()
	fmt.Println("Worker after Goexit (will not be printed)")
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)
	go worker(&wg)
	wg.Wait()
	fmt.Println("Main finished")
}
```

预期输出：

```
Worker starting
Worker deferred function
Main finished
```

这个例子展示了 `runtime.Goexit` 会立即终止当前的 goroutine 的执行，但会执行该 goroutine 的 defer 函数。

**命令行参数的具体处理:**

这个测试文件本身是一个 Go 源代码文件，它会被 `go test` 命令执行。  它主要通过定义不同的测试函数（以 `Test` 开头）来实现其功能。

`TestMain` 函数是测试包的入口点，它会检查环境变量 `RUNTIME_TEST_ENTRYPOINT` 的值。这个环境变量用于在测试执行的不同阶段运行特定的代码。

* **`RUNTIME_TEST_ENTRYPOINT=panic`**:  当设置此环境变量时，`TestMain` 函数会调用 `crashViaPanic()`，这个函数在 `testdata/testprog/main.go` 中定义，它的作用是触发一个 `panic`。这允许测试在特定的崩溃场景下运行。
* **`RUNTIME_TEST_ENTRYPOINT=trap`**: 当设置此环境变量时，`TestMain` 函数会调用 `crashViaTrap()`，这个函数同样在 `testdata/testprog/main.go` 中定义，它的作用是触发一个操作系统的 trap 信号，例如访问空指针。

在正常的测试执行流程中（`RUNTIME_TEST_ENTRYPOINT` 为空），`TestMain` 会调用 `m.Run()` 来执行所有定义的测试函数。

**使用者易犯错的点:**

由于这个文件是 Go 运行时的一部分，普通 Go 开发者不会直接使用它。但是，理解它的测试方法对于编写健壮的 Go 代码和理解 Go 运行时的行为非常有帮助。

一个相关的易犯错的点是在使用 `recover` 时：

* **`recover` 必须在 `defer` 函数中调用:** 如果不在 `defer` 函数中调用 `recover`，它将不会捕获到任何 panic。

```go
package main

import "fmt"

func mightPanic() {
    panic("oh no")
}

func main() {
    // 错误的用法，recover 不会捕获 panic
    recover()
    mightPanic()
    fmt.Println("This will not be printed")
}
```

这个程序会直接崩溃，因为 `recover()` 在 `panic` 发生之前就被调用了，并且不在 `defer` 函数中。

总结来说，`go/src/runtime/crash_test.go` 是一个至关重要的测试文件，它确保了 Go 语言运行时在面对各种崩溃情况时能够按照预期工作，保证了 Go 语言的稳定性和可靠性。 它通过模拟各种崩溃场景，并验证运行时的处理逻辑，涵盖了 panic、recover、死锁检测、堆栈溢出等多个核心的运行时特性。

### 提示词
```
这是路径为go/src/runtime/crash_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"internal/testenv"
	traceparse "internal/trace"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/trace"
	"strings"
	"sync"
	"testing"
	"time"
)

var toRemove []string

const entrypointVar = "RUNTIME_TEST_ENTRYPOINT"

func TestMain(m *testing.M) {
	switch entrypoint := os.Getenv(entrypointVar); entrypoint {
	case "panic":
		crashViaPanic()
		panic("unreachable")
	case "trap":
		crashViaTrap()
		panic("unreachable")
	default:
		log.Fatalf("invalid %s: %q", entrypointVar, entrypoint)
	case "":
		// fall through to normal behavior
	}

	_, coreErrBefore := os.Stat("core")

	status := m.Run()
	for _, file := range toRemove {
		os.RemoveAll(file)
	}

	_, coreErrAfter := os.Stat("core")
	if coreErrBefore != nil && coreErrAfter == nil {
		fmt.Fprintln(os.Stderr, "runtime.test: some test left a core file behind")
		if status == 0 {
			status = 1
		}
	}

	os.Exit(status)
}

var testprog struct {
	sync.Mutex
	dir    string
	target map[string]*buildexe
}

type buildexe struct {
	once sync.Once
	exe  string
	err  error
}

func runTestProg(t *testing.T, binary, name string, env ...string) string {
	if *flagQuick {
		t.Skip("-quick")
	}

	testenv.MustHaveGoBuild(t)
	t.Helper()

	exe, err := buildTestProg(t, binary)
	if err != nil {
		t.Fatal(err)
	}

	return runBuiltTestProg(t, exe, name, env...)
}

func runBuiltTestProg(t *testing.T, exe, name string, env ...string) string {
	t.Helper()

	if *flagQuick {
		t.Skip("-quick")
	}

	start := time.Now()

	cmd := testenv.CleanCmdEnv(testenv.Command(t, exe, name))
	cmd.Env = append(cmd.Env, env...)
	if testing.Short() {
		cmd.Env = append(cmd.Env, "RUNTIME_TEST_SHORT=1")
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Logf("%v (%v): ok", cmd, time.Since(start))
	} else {
		if _, ok := err.(*exec.ExitError); ok {
			t.Logf("%v: %v", cmd, err)
		} else if errors.Is(err, exec.ErrWaitDelay) {
			t.Fatalf("%v: %v", cmd, err)
		} else {
			t.Fatalf("%v failed to start: %v", cmd, err)
		}
	}
	return string(out)
}

var serializeBuild = make(chan bool, 2)

func buildTestProg(t *testing.T, binary string, flags ...string) (string, error) {
	if *flagQuick {
		t.Skip("-quick")
	}
	testenv.MustHaveGoBuild(t)

	testprog.Lock()
	if testprog.dir == "" {
		dir, err := os.MkdirTemp("", "go-build")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		testprog.dir = dir
		toRemove = append(toRemove, dir)
	}

	if testprog.target == nil {
		testprog.target = make(map[string]*buildexe)
	}
	name := binary
	if len(flags) > 0 {
		name += "_" + strings.Join(flags, "_")
	}
	target, ok := testprog.target[name]
	if !ok {
		target = &buildexe{}
		testprog.target[name] = target
	}

	dir := testprog.dir

	// Unlock testprog while actually building, so that other
	// tests can look up executables that were already built.
	testprog.Unlock()

	target.once.Do(func() {
		// Only do two "go build"'s at a time,
		// to keep load from getting too high.
		serializeBuild <- true
		defer func() { <-serializeBuild }()

		// Don't get confused if testenv.GoToolPath calls t.Skip.
		target.err = errors.New("building test called t.Skip")

		exe := filepath.Join(dir, name+".exe")

		start := time.Now()
		cmd := exec.Command(testenv.GoToolPath(t), append([]string{"build", "-o", exe}, flags...)...)
		t.Logf("running %v", cmd)
		cmd.Dir = "testdata/" + binary
		cmd = testenv.CleanCmdEnv(cmd)

		// Add the rangefunc GOEXPERIMENT unconditionally since some tests depend on it.
		// TODO(61405): Remove this once it's enabled by default.
		edited := false
		for i := range cmd.Env {
			e := cmd.Env[i]
			if _, vars, ok := strings.Cut(e, "GOEXPERIMENT="); ok {
				cmd.Env[i] = "GOEXPERIMENT=" + vars + ",rangefunc"
				edited = true
			}
		}
		if !edited {
			cmd.Env = append(cmd.Env, "GOEXPERIMENT=rangefunc")
		}

		out, err := cmd.CombinedOutput()
		if err != nil {
			target.err = fmt.Errorf("building %s %v: %v\n%s", binary, flags, err, out)
		} else {
			t.Logf("built %v in %v", name, time.Since(start))
			target.exe = exe
			target.err = nil
		}
	})

	return target.exe, target.err
}

func TestVDSO(t *testing.T) {
	t.Parallel()
	output := runTestProg(t, "testprog", "SignalInVDSO")
	want := "success\n"
	if output != want {
		t.Fatalf("output:\n%s\n\nwanted:\n%s", output, want)
	}
}

func testCrashHandler(t *testing.T, cgo bool) {
	type crashTest struct {
		Cgo bool
	}
	var output string
	if cgo {
		output = runTestProg(t, "testprogcgo", "Crash")
	} else {
		output = runTestProg(t, "testprog", "Crash")
	}
	want := "main: recovered done\nnew-thread: recovered done\nsecond-new-thread: recovered done\nmain-again: recovered done\n"
	if output != want {
		t.Fatalf("output:\n%s\n\nwanted:\n%s", output, want)
	}
}

func TestCrashHandler(t *testing.T) {
	testCrashHandler(t, false)
}

func testDeadlock(t *testing.T, name string) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	output := runTestProg(t, "testprog", name)
	want := "fatal error: all goroutines are asleep - deadlock!\n"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestSimpleDeadlock(t *testing.T) {
	testDeadlock(t, "SimpleDeadlock")
}

func TestInitDeadlock(t *testing.T) {
	testDeadlock(t, "InitDeadlock")
}

func TestLockedDeadlock(t *testing.T) {
	testDeadlock(t, "LockedDeadlock")
}

func TestLockedDeadlock2(t *testing.T) {
	testDeadlock(t, "LockedDeadlock2")
}

func TestGoexitDeadlock(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	output := runTestProg(t, "testprog", "GoexitDeadlock")
	want := "no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.Contains(output, want) {
		t.Fatalf("output:\n%s\n\nwant output containing: %s", output, want)
	}
}

func TestStackOverflow(t *testing.T) {
	output := runTestProg(t, "testprog", "StackOverflow")
	want := []string{
		"runtime: goroutine stack exceeds 1474560-byte limit\n",
		"fatal error: stack overflow",
		// information about the current SP and stack bounds
		"runtime: sp=",
		"stack=[",
	}
	if !strings.HasPrefix(output, want[0]) {
		t.Errorf("output does not start with %q", want[0])
	}
	for _, s := range want[1:] {
		if !strings.Contains(output, s) {
			t.Errorf("output does not contain %q", s)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", output)
	}
}

func TestThreadExhaustion(t *testing.T) {
	output := runTestProg(t, "testprog", "ThreadExhaustion")
	want := "runtime: program exceeds 10-thread limit\nfatal error: thread exhaustion"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestRecursivePanic(t *testing.T) {
	output := runTestProg(t, "testprog", "RecursivePanic")
	want := `wrap: bad
panic: again

`
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

}

func TestRecursivePanic2(t *testing.T) {
	output := runTestProg(t, "testprog", "RecursivePanic2")
	want := `first panic
second panic
panic: third panic

`
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

}

func TestRecursivePanic3(t *testing.T) {
	output := runTestProg(t, "testprog", "RecursivePanic3")
	want := `panic: first panic

`
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

}

func TestRecursivePanic4(t *testing.T) {
	output := runTestProg(t, "testprog", "RecursivePanic4")
	want := `panic: first panic [recovered]
	panic: second panic
`
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

}

func TestRecursivePanic5(t *testing.T) {
	output := runTestProg(t, "testprog", "RecursivePanic5")
	want := `first panic
second panic
panic: third panic
`
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

}

func TestGoexitCrash(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	output := runTestProg(t, "testprog", "GoexitExit")
	want := "no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.Contains(output, want) {
		t.Fatalf("output:\n%s\n\nwant output containing: %s", output, want)
	}
}

func TestGoexitDefer(t *testing.T) {
	c := make(chan struct{})
	go func() {
		defer func() {
			r := recover()
			if r != nil {
				t.Errorf("non-nil recover during Goexit")
			}
			c <- struct{}{}
		}()
		runtime.Goexit()
	}()
	// Note: if the defer fails to run, we will get a deadlock here
	<-c
}

func TestGoNil(t *testing.T) {
	output := runTestProg(t, "testprog", "GoNil")
	want := "go of nil func value"
	if !strings.Contains(output, want) {
		t.Fatalf("output:\n%s\n\nwant output containing: %s", output, want)
	}
}

func TestMainGoroutineID(t *testing.T) {
	output := runTestProg(t, "testprog", "MainGoroutineID")
	want := "panic: test\n\ngoroutine 1 [running]:\n"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestNoHelperGoroutines(t *testing.T) {
	output := runTestProg(t, "testprog", "NoHelperGoroutines")
	matches := regexp.MustCompile(`goroutine [0-9]+ \[`).FindAllStringSubmatch(output, -1)
	if len(matches) != 1 || matches[0][0] != "goroutine 1 [" {
		t.Fatalf("want to see only goroutine 1, see:\n%s", output)
	}
}

func TestBreakpoint(t *testing.T) {
	output := runTestProg(t, "testprog", "Breakpoint")
	// If runtime.Breakpoint() is inlined, then the stack trace prints
	// "runtime.Breakpoint(...)" instead of "runtime.Breakpoint()".
	want := "runtime.Breakpoint("
	if !strings.Contains(output, want) {
		t.Fatalf("output:\n%s\n\nwant output containing: %s", output, want)
	}
}

func TestGoexitInPanic(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	// see issue 8774: this code used to trigger an infinite recursion
	output := runTestProg(t, "testprog", "GoexitInPanic")
	want := "fatal error: no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

// Issue 14965: Runtime panics should be of type runtime.Error
func TestRuntimePanicWithRuntimeError(t *testing.T) {
	testCases := [...]func(){
		0: func() {
			var m map[uint64]bool
			m[1234] = true
		},
		1: func() {
			ch := make(chan struct{})
			close(ch)
			close(ch)
		},
		2: func() {
			var ch = make(chan struct{})
			close(ch)
			ch <- struct{}{}
		},
		3: func() {
			var s = make([]int, 2)
			_ = s[2]
		},
		4: func() {
			n := -1
			_ = make(chan bool, n)
		},
		5: func() {
			close((chan bool)(nil))
		},
	}

	for i, fn := range testCases {
		got := panicValue(fn)
		if _, ok := got.(runtime.Error); !ok {
			t.Errorf("test #%d: recovered value %v(type %T) does not implement runtime.Error", i, got, got)
		}
	}
}

func panicValue(fn func()) (recovered any) {
	defer func() {
		recovered = recover()
	}()
	fn()
	return
}

func TestPanicAfterGoexit(t *testing.T) {
	// an uncaught panic should still work after goexit
	output := runTestProg(t, "testprog", "PanicAfterGoexit")
	want := "panic: hello"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestRecoveredPanicAfterGoexit(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	output := runTestProg(t, "testprog", "RecoveredPanicAfterGoexit")
	want := "fatal error: no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestRecoverBeforePanicAfterGoexit(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	t.Parallel()
	output := runTestProg(t, "testprog", "RecoverBeforePanicAfterGoexit")
	want := "fatal error: no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestRecoverBeforePanicAfterGoexit2(t *testing.T) {
	// External linking brings in cgo, causing deadlock detection not working.
	testenv.MustInternalLink(t, false)

	t.Parallel()
	output := runTestProg(t, "testprog", "RecoverBeforePanicAfterGoexit2")
	want := "fatal error: no goroutines (main called runtime.Goexit) - deadlock!"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestNetpollDeadlock(t *testing.T) {
	t.Parallel()
	output := runTestProg(t, "testprognet", "NetpollDeadlock")
	want := "done\n"
	if !strings.HasSuffix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestPanicTraceback(t *testing.T) {
	t.Parallel()
	output := runTestProg(t, "testprog", "PanicTraceback")
	want := "panic: hello\n\tpanic: panic pt2\n\tpanic: panic pt1\n"
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}

	// Check functions in the traceback.
	fns := []string{"main.pt1.func1", "panic", "main.pt2.func1", "panic", "main.pt2", "main.pt1"}
	for _, fn := range fns {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(fn) + `\(.*\n`)
		idx := re.FindStringIndex(output)
		if idx == nil {
			t.Fatalf("expected %q function in traceback:\n%s", fn, output)
		}
		output = output[idx[1]:]
	}
}

func testPanicDeadlock(t *testing.T, name string, want string) {
	// test issue 14432
	output := runTestProg(t, "testprog", name)
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestPanicDeadlockGosched(t *testing.T) {
	testPanicDeadlock(t, "GoschedInPanic", "panic: errorThatGosched\n\n")
}

func TestPanicDeadlockSyscall(t *testing.T) {
	testPanicDeadlock(t, "SyscallInPanic", "1\n2\npanic: 3\n\n")
}

func TestPanicLoop(t *testing.T) {
	output := runTestProg(t, "testprog", "PanicLoop")
	if want := "panic while printing panic value"; !strings.Contains(output, want) {
		t.Errorf("output does not contain %q:\n%s", want, output)
	}
}

func TestMemPprof(t *testing.T) {
	testenv.MustHaveGoRun(t)

	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}

	got, err := testenv.CleanCmdEnv(exec.Command(exe, "MemProf")).CombinedOutput()
	if err != nil {
		t.Fatalf("testprog failed: %s, output:\n%s", err, got)
	}
	fn := strings.TrimSpace(string(got))
	defer os.Remove(fn)

	for try := 0; try < 2; try++ {
		cmd := testenv.CleanCmdEnv(exec.Command(testenv.GoToolPath(t), "tool", "pprof", "-alloc_space", "-top"))
		// Check that pprof works both with and without explicit executable on command line.
		if try == 0 {
			cmd.Args = append(cmd.Args, exe, fn)
		} else {
			cmd.Args = append(cmd.Args, fn)
		}
		found := false
		for i, e := range cmd.Env {
			if strings.HasPrefix(e, "PPROF_TMPDIR=") {
				cmd.Env[i] = "PPROF_TMPDIR=" + os.TempDir()
				found = true
				break
			}
		}
		if !found {
			cmd.Env = append(cmd.Env, "PPROF_TMPDIR="+os.TempDir())
		}

		top, err := cmd.CombinedOutput()
		t.Logf("%s:\n%s", cmd.Args, top)
		if err != nil {
			t.Error(err)
		} else if !bytes.Contains(top, []byte("MemProf")) {
			t.Error("missing MemProf in pprof output")
		}
	}
}

var concurrentMapTest = flag.Bool("run_concurrent_map_tests", false, "also run flaky concurrent map tests")

func TestConcurrentMapWrites(t *testing.T) {
	if !*concurrentMapTest {
		t.Skip("skipping without -run_concurrent_map_tests")
	}
	testenv.MustHaveGoRun(t)
	output := runTestProg(t, "testprog", "concurrentMapWrites")
	want := "fatal error: concurrent map writes\n"
	// Concurrent writes can corrupt the map in a way that we
	// detect with a separate throw.
	want2 := "fatal error: small map with no empty slot (concurrent map writes?)\n"
	if !strings.HasPrefix(output, want) && !strings.HasPrefix(output, want2) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}
func TestConcurrentMapReadWrite(t *testing.T) {
	if !*concurrentMapTest {
		t.Skip("skipping without -run_concurrent_map_tests")
	}
	testenv.MustHaveGoRun(t)
	output := runTestProg(t, "testprog", "concurrentMapReadWrite")
	want := "fatal error: concurrent map read and map write\n"
	// Concurrent writes can corrupt the map in a way that we
	// detect with a separate throw.
	want2 := "fatal error: small map with no empty slot (concurrent map writes?)\n"
	if !strings.HasPrefix(output, want) && !strings.HasPrefix(output, want2) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}
func TestConcurrentMapIterateWrite(t *testing.T) {
	if !*concurrentMapTest {
		t.Skip("skipping without -run_concurrent_map_tests")
	}
	testenv.MustHaveGoRun(t)
	output := runTestProg(t, "testprog", "concurrentMapIterateWrite")
	want := "fatal error: concurrent map iteration and map write\n"
	// Concurrent writes can corrupt the map in a way that we
	// detect with a separate throw.
	want2 := "fatal error: small map with no empty slot (concurrent map writes?)\n"
	if !strings.HasPrefix(output, want) && !strings.HasPrefix(output, want2) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestConcurrentMapWritesIssue69447(t *testing.T) {
	testenv.MustHaveGoRun(t)
	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		output := runBuiltTestProg(t, exe, "concurrentMapWrites")
		if output == "" {
			// If we didn't detect an error, that's ok.
			// This case makes this test not flaky like
			// the other ones above.
			// (More correctly, this case makes this test flaky
			// in the other direction, in that it might not
			// detect a problem even if there is one.)
			continue
		}
		want := "fatal error: concurrent map writes\n"
		// Concurrent writes can corrupt the map in a way that we
		// detect with a separate throw.
		want2 := "fatal error: small map with no empty slot (concurrent map writes?)\n"
		if !strings.HasPrefix(output, want) && !strings.HasPrefix(output, want2) {
			t.Fatalf("output does not start with %q:\n%s", want, output)
		}
	}
}

type point struct {
	x, y *int
}

func (p *point) negate() {
	*p.x = *p.x * -1
	*p.y = *p.y * -1
}

// Test for issue #10152.
func TestPanicInlined(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("recover failed")
		}
		buf := make([]byte, 2048)
		n := runtime.Stack(buf, false)
		buf = buf[:n]
		if !bytes.Contains(buf, []byte("(*point).negate(")) {
			t.Fatalf("expecting stack trace to contain call to (*point).negate()")
		}
	}()

	pt := new(point)
	pt.negate()
}

// Test for issues #3934 and #20018.
// We want to delay exiting until a panic print is complete.
func TestPanicRace(t *testing.T) {
	testenv.MustHaveGoRun(t)

	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}

	// The test is intentionally racy, and in my testing does not
	// produce the expected output about 0.05% of the time.
	// So run the program in a loop and only fail the test if we
	// get the wrong output ten times in a row.
	const tries = 10
retry:
	for i := 0; i < tries; i++ {
		got, err := testenv.CleanCmdEnv(exec.Command(exe, "PanicRace")).CombinedOutput()
		if err == nil {
			t.Logf("try %d: program exited successfully, should have failed", i+1)
			continue
		}

		if i > 0 {
			t.Logf("try %d:\n", i+1)
		}
		t.Logf("%s\n", got)

		wants := []string{
			"panic: crash",
			"PanicRace",
			"created by ",
		}
		for _, want := range wants {
			if !bytes.Contains(got, []byte(want)) {
				t.Logf("did not find expected string %q", want)
				continue retry
			}
		}

		// Test generated expected output.
		return
	}
	t.Errorf("test ran %d times without producing expected output", tries)
}

func TestBadTraceback(t *testing.T) {
	output := runTestProg(t, "testprog", "BadTraceback")
	for _, want := range []string{
		"unexpected return pc",
		"called from 0xbad",
		"00000bad",    // Smashed LR in hex dump
		"<main.badLR", // Symbolization in hex dump (badLR1 or badLR2)
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not contain %q:\n%s", want, output)
		}
	}
}

func TestTimePprof(t *testing.T) {
	// This test is unreliable on any system in which nanotime
	// calls into libc.
	switch runtime.GOOS {
	case "aix", "darwin", "illumos", "openbsd", "solaris":
		t.Skipf("skipping on %s because nanotime calls libc", runtime.GOOS)
	}

	// Pass GOTRACEBACK for issue #41120 to try to get more
	// information on timeout.
	fn := runTestProg(t, "testprog", "TimeProf", "GOTRACEBACK=crash")
	fn = strings.TrimSpace(fn)
	defer os.Remove(fn)

	cmd := testenv.CleanCmdEnv(exec.Command(testenv.GoToolPath(t), "tool", "pprof", "-top", "-nodecount=1", fn))
	cmd.Env = append(cmd.Env, "PPROF_TMPDIR="+os.TempDir())
	top, err := cmd.CombinedOutput()
	t.Logf("%s", top)
	if err != nil {
		t.Error(err)
	} else if bytes.Contains(top, []byte("ExternalCode")) {
		t.Error("profiler refers to ExternalCode")
	}
}

// Test that runtime.abort does so.
func TestAbort(t *testing.T) {
	// Pass GOTRACEBACK to ensure we get runtime frames.
	output := runTestProg(t, "testprog", "Abort", "GOTRACEBACK=system")
	if want := "runtime.abort"; !strings.Contains(output, want) {
		t.Errorf("output does not contain %q:\n%s", want, output)
	}
	if strings.Contains(output, "BAD") {
		t.Errorf("output contains BAD:\n%s", output)
	}
	// Check that it's a signal traceback.
	want := "PC="
	// For systems that use a breakpoint, check specifically for that.
	switch runtime.GOARCH {
	case "386", "amd64":
		switch runtime.GOOS {
		case "plan9":
			want = "sys: breakpoint"
		case "windows":
			want = "Exception 0x80000003"
		default:
			want = "SIGTRAP"
		}
	}
	if !strings.Contains(output, want) {
		t.Errorf("output does not contain %q:\n%s", want, output)
	}
}

// For TestRuntimePanic: test a panic in the runtime package without
// involving the testing harness.
func init() {
	if os.Getenv("GO_TEST_RUNTIME_PANIC") == "1" {
		defer func() {
			if r := recover(); r != nil {
				// We expect to crash, so exit 0
				// to indicate failure.
				os.Exit(0)
			}
		}()
		runtime.PanicForTesting(nil, 1)
		// We expect to crash, so exit 0 to indicate failure.
		os.Exit(0)
	}
	if os.Getenv("GO_TEST_RUNTIME_NPE_READMEMSTATS") == "1" {
		runtime.ReadMemStats(nil)
		os.Exit(0)
	}
	if os.Getenv("GO_TEST_RUNTIME_NPE_FUNCMETHOD") == "1" {
		var f *runtime.Func
		_ = f.Entry()
		os.Exit(0)
	}

}

func TestRuntimePanic(t *testing.T) {
	testenv.MustHaveExec(t)
	cmd := testenv.CleanCmdEnv(exec.Command(os.Args[0], "-test.run=^TestRuntimePanic$"))
	cmd.Env = append(cmd.Env, "GO_TEST_RUNTIME_PANIC=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err == nil {
		t.Error("child process did not fail")
	} else if want := "runtime.unexportedPanicForTesting"; !bytes.Contains(out, []byte(want)) {
		t.Errorf("output did not contain expected string %q", want)
	}
}

func TestTracebackRuntimeFunction(t *testing.T) {
	testenv.MustHaveExec(t)
	cmd := testenv.CleanCmdEnv(exec.Command(os.Args[0], "-test.run=TestTracebackRuntimeFunction"))
	cmd.Env = append(cmd.Env, "GO_TEST_RUNTIME_NPE_READMEMSTATS=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err == nil {
		t.Error("child process did not fail")
	} else if want := "runtime.ReadMemStats"; !bytes.Contains(out, []byte(want)) {
		t.Errorf("output did not contain expected string %q", want)
	}
}

func TestTracebackRuntimeMethod(t *testing.T) {
	testenv.MustHaveExec(t)
	cmd := testenv.CleanCmdEnv(exec.Command(os.Args[0], "-test.run=TestTracebackRuntimeMethod"))
	cmd.Env = append(cmd.Env, "GO_TEST_RUNTIME_NPE_FUNCMETHOD=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err == nil {
		t.Error("child process did not fail")
	} else if want := "runtime.(*Func).Entry"; !bytes.Contains(out, []byte(want)) {
		t.Errorf("output did not contain expected string %q", want)
	}
}

// Test that g0 stack overflows are handled gracefully.
func TestG0StackOverflow(t *testing.T) {
	testenv.MustHaveExec(t)

	if runtime.GOOS == "ios" {
		testenv.SkipFlaky(t, 62671)
	}

	if os.Getenv("TEST_G0_STACK_OVERFLOW") != "1" {
		cmd := testenv.CleanCmdEnv(testenv.Command(t, os.Args[0], "-test.run=^TestG0StackOverflow$", "-test.v"))
		cmd.Env = append(cmd.Env, "TEST_G0_STACK_OVERFLOW=1")
		out, err := cmd.CombinedOutput()
		t.Logf("output:\n%s", out)
		// Don't check err since it's expected to crash.
		if n := strings.Count(string(out), "morestack on g0\n"); n != 1 {
			t.Fatalf("%s\n(exit status %v)", out, err)
		}
		if runtime.CrashStackImplemented {
			// check for a stack trace
			want := "runtime.stackOverflow"
			if n := strings.Count(string(out), want); n < 5 {
				t.Errorf("output does not contain %q at least 5 times:\n%s", want, out)
			}
			return // it's not a signal-style traceback
		}
		// Check that it's a signal-style traceback.
		if runtime.GOOS != "windows" {
			if want := "PC="; !strings.Contains(string(out), want) {
				t.Errorf("output does not contain %q:\n%s", want, out)
			}
		}
		return
	}

	runtime.G0StackOverflow()
}

// For TestCrashWhileTracing: test a panic without involving the testing
// harness, as we rely on stdout only containing trace output.
func init() {
	if os.Getenv("TEST_CRASH_WHILE_TRACING") == "1" {
		trace.Start(os.Stdout)
		trace.Log(context.Background(), "xyzzy-cat", "xyzzy-msg")
		panic("yzzyx")
	}
}

func TestCrashWhileTracing(t *testing.T) {
	testenv.MustHaveExec(t)

	cmd := testenv.CleanCmdEnv(testenv.Command(t, os.Args[0]))
	cmd.Env = append(cmd.Env, "TEST_CRASH_WHILE_TRACING=1")
	stdOut, err := cmd.StdoutPipe()
	var errOut bytes.Buffer
	cmd.Stderr = &errOut

	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start subprocess: %v", err)
	}
	r, err := traceparse.NewReader(stdOut)
	if err != nil {
		t.Fatalf("could not create trace.NewReader: %v", err)
	}
	var seen, seenSync bool
	i := 1
loop:
	for ; ; i++ {
		ev, err := r.ReadEvent()
		if err != nil {
			// We may have a broken tail to the trace -- that's OK.
			// We'll make sure we saw at least one complete generation.
			if err != io.EOF {
				t.Logf("error at event %d: %v", i, err)
			}
			break loop
		}
		switch ev.Kind() {
		case traceparse.EventSync:
			seenSync = true
		case traceparse.EventLog:
			v := ev.Log()
			if v.Category == "xyzzy-cat" && v.Message == "xyzzy-msg" {
				// Should we already stop reading here? More events may come, but
				// we're not guaranteeing a fully unbroken trace until the last
				// byte...
				seen = true
			}
		}
	}
	if err := cmd.Wait(); err == nil {
		t.Error("the process should have panicked")
	}
	if !seenSync {
		t.Errorf("expected at least one full generation to have been emitted before the trace was considered broken")
	}
	if !seen {
		t.Errorf("expected one matching log event matching, but none of the %d received trace events match", i)
	}
	t.Logf("stderr output:\n%s", errOut.String())
	needle := "yzzyx\n"
	if n := strings.Count(errOut.String(), needle); n != 1 {
		t.Fatalf("did not find expected panic message %q\n(exit status %v)", needle, err)
	}
}

// Test that panic message is not clobbered.
// See issue 30150.
func TestDoublePanic(t *testing.T) {
	output := runTestProg(t, "testprog", "DoublePanic", "GODEBUG=clobberfree=1")
	wants := []string{"panic: XXX", "panic: YYY"}
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Errorf("output:\n%s\n\nwant output containing: %s", output, want)
		}
	}
}

// Test that panic while panicking discards error message
// See issue 52257
func TestPanicWhilePanicking(t *testing.T) {
	tests := []struct {
		Want string
		Func string
	}{
		{
			"panic while printing panic value: important multi-line\n\terror message",
			"ErrorPanic",
		},
		{
			"panic while printing panic value: important multi-line\n\tstringer message",
			"StringerPanic",
		},
		{
			"panic while printing panic value: type",
			"DoubleErrorPanic",
		},
		{
			"panic while printing panic value: type",
			"DoubleStringerPanic",
		},
		{
			"panic while printing panic value: type",
			"CircularPanic",
		},
		{
			"important multi-line\n\tstring message",
			"StringPanic",
		},
		{
			"nil",
			"NilPanic",
		},
	}
	for _, x := range tests {
		output := runTestProg(t, "testprog", x.Func)
		if !strings.Contains(output, x.Want) {
			t.Errorf("output does not contain %q:\n%s", x.Want, output)
		}
	}
}

func TestPanicOnUnsafeSlice(t *testing.T) {
	output := runTestProg(t, "testprog", "panicOnNilAndEleSizeIsZero")
	want := "panic: runtime error: unsafe.Slice: ptr is nil and len is not zero"
	if !strings.Contains(output, want) {
		t.Errorf("output does not contain %q:\n%s", want, output)
	}
}

func TestNetpollWaiters(t *testing.T) {
	t.Parallel()
	output := runTestProg(t, "testprognet", "NetpollWaiters")
	want := "OK\n"
	if output != want {
		t.Fatalf("output is not %q\n%s", want, output)
	}
}
```