Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Type:** The first thing that jumps out is the `T` struct. The comment clearly states it's "the type passed to Test functions". This immediately signals that this code is about the testing framework in Go. The `common` field within `T` suggests shared functionality.

2. **Examine the `common` Struct:**  The `common` struct (even though its definition isn't shown) appears to be the workhorse. Many methods are defined on `*common`. The comment about `private()` reinforces the idea of internal structure.

3. **Categorize the Methods:**  Start grouping the methods by their apparent purpose. A quick scan reveals methods related to:
    * **Test Status:** `Fail`, `Failed`, `FailNow`, `Skip`, `SkipNow`, `Skipped`
    * **Logging/Output:** `Log`, `Logf`, `Error`, `Errorf`, `Fatal`, `Fatalf`, `Skip`, `Skipf`
    * **Test Structure:** `Name`, `Run`, `Parallel`, `Cleanup`, `Helper`
    * **Environment Manipulation:** `Setenv`, `Chdir`, `TempDir`
    * **Context Management:** `Context`
    * **Concurrency & Synchronization:** Hints of this are in `Parallel`, `tstate`, and the mutexes (`mu`).
    * **Internal/Lower-Level:** `log`, `logDepth`, `runCleanup`, `resetRaces`, `checkRaces`, `tRunner`

4. **Focus on Public Methods:**  The methods starting with uppercase letters (like `Fail`, `Log`, `Run`) are the public interface that test writers interact with. Understanding these is key to grasping the functionality.

5. **Infer Functionality from Method Names:** Method names are generally descriptive. For example:
    * `Fail()`:  Marks the test as failed.
    * `Log()`: Logs a message.
    * `Run()`: Runs a subtest.
    * `Parallel()`: Marks the test for parallel execution.
    * `Cleanup()`: Registers a cleanup function.
    * `Setenv()`: Sets an environment variable.

6. **Analyze Method Implementations (High-Level):**  Without diving deep into every line, look for key actions within the methods:
    * **Setting Flags:** `Fail` sets `c.failed = true`.
    * **Calling Other Methods:** `Error` calls `Log` and `Fail`. `Fatalf` calls `Logf` and `FailNow`.
    * **Concurrency Primitives:** `mu.Lock()`, `mu.Unlock()`, channels (`signal`, `barrier`).
    * **`runtime` Package Usage:** `runtime.Goexit()`, `runtime.Callers()`. This points to managing goroutine execution.
    * **Operating System Interaction:** `os.Setenv`, `os.Chdir`, `os.MkdirTemp`.

7. **Connect the Dots:**  Realize that `T` is the object that test functions receive. The methods on `T` and `common` provide the tools to control the test's execution, report results, and interact with the environment.

8. **Identify Key Go Testing Features:** Based on the methods and their behavior, identify the Go testing features being implemented:
    * **Test Structure:**  Subtests (`Run`).
    * **Test Outcomes:** Success/failure, skipping (`Fail`, `Skip`).
    * **Logging:**  Capturing output (`Log`).
    * **Parallel Execution:**  Running tests concurrently (`Parallel`).
    * **Resource Management:**  Temporary directories (`TempDir`), environment variables (`Setenv`), working directory (`Chdir`), cleanup functions (`Cleanup`).

9. **Consider Examples and Edge Cases:**  Think about how a test writer would use these methods. What are potential pitfalls?  The code itself gives hints (e.g., the panic in `Parallel` if called multiple times, the checks for running cleanup functions).

10. **Address Specific Prompts:** Once you have a good understanding of the code, go back and address the specific requirements of the prompt:
    * **List functions:**  Simply list the public methods.
    * **Infer Go language feature:** Connect the methods to the corresponding testing features.
    * **Provide code examples:**  Construct simple test functions that demonstrate the use of these methods.
    * **Infer command-line arguments:** Look for clues related to verbosity (`-test.v`).
    * **Identify common mistakes:** Think about scenarios where developers might misuse the methods (e.g., calling `FailNow` in a goroutine, using `Setenv` in parallel tests).
    * **Summarize functionality:**  Condense the understanding into a concise overview.

11. **Refine and Organize:** Review the analysis for clarity and accuracy. Organize the information logically.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `common` is just for basic stuff. **Correction:**  Realize `common` has a lot of the core logic, and `T` builds upon it.
* **Overlooking details:**  Initially, I might focus too much on the success/failure aspects. **Correction:** Notice the environment manipulation and resource management features are also important.
* **Vague understanding of concurrency:** Simply noting "concurrency" isn't enough. **Correction:**  Examine `Parallel` and the `tstate` to understand how Go manages parallel tests.
* **Missing error conditions:**  Initially, I might focus on the happy path. **Correction:** Look for `panic` calls and error handling (`Fatalf`) to understand how the testing framework reacts to problems.

By following this iterative process of examination, categorization, inference, and refinement, you can effectively analyze and understand the functionality of this Go code snippet.
## 对 go/src/testing/testing.go 第2部分的分析归纳

这部分代码主要定义了 `testing.T` 结构体及其关联的方法，这些方法构成了 Go 语言测试框架中用于编写和控制单个测试用例的核心 API。  `T` 类型提供了一系列方法，允许测试用例报告成功或失败、记录日志、进行子测试、执行并行测试以及管理测试环境。

**主要功能归纳：**

1. **测试状态管理和报告:**
   - **标记失败:** `Fail()`, `FailNow()`, `Error()`, `Errorf()`, `Fatal()`, `Fatalf()` 等方法用于标记测试用例失败。`FailNow()` 会立即停止当前测试用例的执行。
   - **标记跳过:** `Skip()`, `Skipf()`, `SkipNow()` 用于标记测试用例被跳过。
   - **查询状态:** `Failed()` 和 `Skipped()` 用于查询测试用例的失败或跳过状态。

2. **日志记录:**
   - `Log()`, `Logf()`:  用于记录测试过程中的信息，这些信息在测试失败或使用 `-test.v` 标志时会显示出来。对于 benchmark，日志总是会显示。

3. **子测试管理:**
   - `Run(name string, f func(t *T))`:  允许在一个测试用例中定义和运行子测试，可以方便地组织和隔离测试逻辑。

4. **并行测试控制:**
   - `Parallel()`:  声明当前测试用例可以与其他标记为 `Parallel()` 的测试用例并行执行。

5. **测试环境管理:**
   - `Setenv(key, value string)`:  设置环境变量，并在测试结束后恢复原始值。
   - `Chdir(dir string)`:  改变当前工作目录，并在测试结束后恢复原始目录。
   - `TempDir()`:  创建一个临时目录供测试使用，并在测试结束后自动删除。
   - `Cleanup(f func())`:  注册一个在测试（及其所有子测试）完成后执行的清理函数，清理函数按照后进先出的顺序执行。
   - `Context() context.Context`: 返回一个在 `Cleanup` 函数执行前被取消的上下文，允许测试用例优雅地关闭资源。

6. **辅助函数标记:**
   - `Helper()`:  标记一个函数为测试辅助函数，在打印文件和行号信息时会跳过该函数。

7. **数据竞争检测:**
   - 代码中包含对数据竞争的检测和处理逻辑 (`resetRaces()`, `checkRaces()`)，利用了 `sync/atomic` 包和 `runtime/race` 包的功能。

8. **内部机制:**
   - `tRunner()`:  是实际运行测试函数的 goroutine，负责处理测试函数的执行、错误捕获、cleanup 函数的调用等。

**与 Go 语言功能的关系：**

这部分代码是 Go 语言标准库 `testing` 包的核心组成部分，直接支持了 Go 语言的测试功能。它利用了以下 Go 语言特性：

- **结构体和方法:**  `T` 结构体和与之关联的方法定义了测试用例的接口。
- **goroutine 和 channel:**  `Parallel()` 和 `Run()` 方法使用了 goroutine 和 channel 来实现并行测试和子测试的同步。
- **defer 语句:**  在 `tRunner` 和其他方法中，`defer` 语句用于确保 cleanup 函数和资源释放的执行，即使测试发生 panic 或提前返回。
- **panic 和 recover:** `tRunner` 中使用了 `recover()` 来捕获测试用例中发生的 panic，并进行相应的处理。
- **上下文（context）:** `Context()` 方法返回一个上下文，用于通知 cleanup 函数测试即将结束。
- **原子操作（sync/atomic）:** 用于在并发环境下安全地更新测试状态和数据竞争计数。
- **反射（reflect）:**  虽然这部分代码没有直接展示反射的使用，但在完整的 `testing` 包中，反射被用于检查测试函数的签名等。

**代码举例说明：**

```go
package mypackage_test

import (
	"os"
	"testing"
)

func TestExample(t *testing.T) {
	// 使用 Log 记录信息
	t.Log("Starting test Example")

	// 使用 Error 标记失败，但继续执行
	if 1 != 2 {
		t.Error("One is not equal to two")
	}

	// 使用 Fatalf 标记失败并立即停止
	if os.Getenv("SHOULD_FAIL") == "true" {
		t.Fatalf("Test failed because SHOULD_FAIL is set")
	}

	// 运行子测试
	t.Run("SubTest1", func(st *testing.T) {
		st.Log("Running SubTest1")
		if 1+1 != 2 {
			st.Error("One plus one is not equal to two in SubTest1")
		}
	})

	// 并行执行子测试
	t.Run("ParallelTest", func(pt *testing.T) {
		pt.Parallel()
		pt.Log("Running ParallelTest")
		// 一些并行执行的逻辑
	})

	// 设置环境变量并使用 Cleanup 恢复
	t.Setenv("MY_VAR", "my_value")
	t.Cleanup(func() {
		t.Log("Cleaning up MY_VAR")
	})
	if os.Getenv("MY_VAR") != "my_value" {
		t.Errorf("MY_VAR is not set correctly")
	}

	// 创建临时目录
	tempDir := t.TempDir()
	t.Logf("Created temporary directory: %s", tempDir)
	// 临时目录会在测试结束后自动删除
}
```

**假设输入与输出（针对子测试）：**

**假设输入：**  一个包含上述 `TestExample` 函数的测试文件，且环境变量 `SHOULD_FAIL` 未设置。

**预期输出（可能包含时间戳）：**

```
=== RUN   TestExample
    testing_test.go:8: Starting test Example
    testing_test.go:12: One is not equal to two
=== RUN   TestExample/SubTest1
    testing_test.go:20: Running SubTest1
=== END   TestExample/SubTest1
=== RUN   TestExample/ParallelTest
=== PAUSE TestExample/ParallelTest
=== CONT  TestExample/ParallelTest
    testing_test.go:28: Running ParallelTest
=== END   TestExample/ParallelTest
    testing_test.go:33: Cleaning up MY_VAR
    testing_test.go:3: Created temporary directory: /tmp/go-buildxxxx/TestExample001
--- FAIL: TestExample (xxxxs)
    testing_test.go:12: One is not equal to two
PASS
ok      mypackage_test  xxxxs
```

**命令行参数的具体处理：**

虽然这段代码本身没有直接处理命令行参数的逻辑，但它提供的功能会受到 Go 测试工具 `go test` 的命令行参数影响。例如：

- `-test.v`: 启用详细输出，会显示 `Log` 记录的信息。
- `-test.run <regexp>`:  运行名称匹配正则表达式的测试用例或子测试。`t.Run` 中提供的子测试名称会参与匹配。
- `-test.parallel <n>`: 设置允许并行运行的测试用例的最大数量。这会影响 `t.Parallel()` 的行为。
- `-test.timeout <d>`: 设置测试用例的超时时间，`t.Deadline()` 可以获取这个超时时间。
- `-test.count <n>`:  多次运行每个测试用例。对于并行测试，每个实例仍然不会相互并行运行。

**使用者易犯错的点：**

1. **在错误的 goroutine 中调用 `FailNow()` 或 `SkipNow()`:**  这些方法必须在运行测试函数的 goroutine 中调用，如果在其他 goroutine 中调用，不会停止测试的执行，可能导致意想不到的结果。

   ```go
   func TestIncorrectFailNow(t *testing.T) {
       go func() {
           // 错误：在新的 goroutine 中调用 FailNow
           t.FailNow()
       }()
       // 测试会继续执行到这里
       t.Log("Test continues after incorrect FailNow")
   }
   ```

2. **在并行测试中使用 `Setenv()` 或 `Chdir()` 但没有意识到其全局影响:**  这些操作会影响整个进程，在并行测试中可能导致竞争条件和不可预测的行为。应该谨慎使用，或者考虑使用子测试并配合 `Cleanup` 进行隔离。

   ```go
   func TestParallelEnv(t *testing.T) {
       t.Parallel()
       t.Setenv("GLOBAL_VAR", "parallel_value") // 可能与其他并行测试冲突
       // ...
   }
   ```

3. **在 `Cleanup` 函数中调用会修改全局状态的操作，但未进行适当的同步:**  `Cleanup` 函数在测试结束后执行，但如果其中包含并发操作，可能需要在多个 `Cleanup` 函数之间进行同步。

4. **忘记在长时间运行的测试中使用 `t.Log` 或其他报告方法，导致测试超时难以诊断:**  及时记录日志可以帮助理解测试的执行过程和定位问题。

**总结：**

这部分 `testing.go` 的代码是 Go 语言测试框架的核心，它提供了 `testing.T` 类型及其一系列方法，用于编写、控制和报告测试用例的执行状态。它支持子测试、并行测试以及测试环境的管理，并提供了数据竞争检测的基础设施。理解这部分代码的功能对于编写高质量的 Go 语言测试至关重要。

Prompt: 
```
这是路径为go/src/testing/testing.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
 the goroutine running the
// Test function.
//
// The other reporting methods, such as the variations of Log and Error,
// may be called simultaneously from multiple goroutines.
type T struct {
	common
	denyParallel bool
	tstate       *testState // For running tests and subtests.
}

func (c *common) private() {}

// Name returns the name of the running (sub-) test or benchmark.
//
// The name will include the name of the test along with the names of
// any nested sub-tests. If two sibling sub-tests have the same name,
// Name will append a suffix to guarantee the returned name is unique.
func (c *common) Name() string {
	return c.name
}

func (c *common) setRan() {
	if c.parent != nil {
		c.parent.setRan()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ran = true
}

// Fail marks the function as having failed but continues execution.
func (c *common) Fail() {
	if c.parent != nil {
		c.parent.Fail()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// c.done needs to be locked to synchronize checks to c.done in parent tests.
	if c.done {
		panic("Fail in goroutine after " + c.name + " has completed")
	}
	c.failed = true
}

// Failed reports whether the function has failed.
func (c *common) Failed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.done && int64(race.Errors()) > c.lastRaceErrors.Load() {
		c.mu.RUnlock()
		c.checkRaces()
		c.mu.RLock()
	}

	return c.failed
}

// FailNow marks the function as having failed and stops its execution
// by calling runtime.Goexit (which then runs all deferred calls in the
// current goroutine).
// Execution will continue at the next test or benchmark.
// FailNow must be called from the goroutine running the
// test or benchmark function, not from other goroutines
// created during the test. Calling FailNow does not stop
// those other goroutines.
func (c *common) FailNow() {
	c.checkFuzzFn("FailNow")
	c.Fail()

	// Calling runtime.Goexit will exit the goroutine, which
	// will run the deferred functions in this goroutine,
	// which will eventually run the deferred lines in tRunner,
	// which will signal to the test loop that this test is done.
	//
	// A previous version of this code said:
	//
	//	c.duration = ...
	//	c.signal <- c.self
	//	runtime.Goexit()
	//
	// This previous version duplicated code (those lines are in
	// tRunner no matter what), but worse the goroutine teardown
	// implicit in runtime.Goexit was not guaranteed to complete
	// before the test exited. If a test deferred an important cleanup
	// function (like removing temporary files), there was no guarantee
	// it would run on a test failure. Because we send on c.signal during
	// a top-of-stack deferred function now, we know that the send
	// only happens after any other stacked defers have completed.
	c.mu.Lock()
	c.finished = true
	c.mu.Unlock()
	runtime.Goexit()
}

// log generates the output. It's always at the same stack depth.
func (c *common) log(s string) {
	c.logDepth(s, 3) // logDepth + log + public function
}

// logDepth generates the output at an arbitrary stack depth.
func (c *common) logDepth(s string, depth int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		// This test has already finished. Try and log this message
		// with our parent. If we don't have a parent, panic.
		for parent := c.parent; parent != nil; parent = parent.parent {
			parent.mu.Lock()
			defer parent.mu.Unlock()
			if !parent.done {
				parent.output = append(parent.output, parent.decorate(s, depth+1)...)
				return
			}
		}
		panic("Log in goroutine after " + c.name + " has completed: " + s)
	} else {
		if c.chatty != nil {
			if c.bench {
				// Benchmarks don't print === CONT, so we should skip the test
				// printer and just print straight to stdout.
				fmt.Print(c.decorate(s, depth+1))
			} else {
				c.chatty.Printf(c.name, "%s", c.decorate(s, depth+1))
			}

			return
		}
		c.output = append(c.output, c.decorate(s, depth+1)...)
	}
}

// Log formats its arguments using default formatting, analogous to Println,
// and records the text in the error log. For tests, the text will be printed only if
// the test fails or the -test.v flag is set. For benchmarks, the text is always
// printed to avoid having performance depend on the value of the -test.v flag.
func (c *common) Log(args ...any) {
	c.checkFuzzFn("Log")
	c.log(fmt.Sprintln(args...))
}

// Logf formats its arguments according to the format, analogous to Printf, and
// records the text in the error log. A final newline is added if not provided. For
// tests, the text will be printed only if the test fails or the -test.v flag is
// set. For benchmarks, the text is always printed to avoid having performance
// depend on the value of the -test.v flag.
func (c *common) Logf(format string, args ...any) {
	c.checkFuzzFn("Logf")
	c.log(fmt.Sprintf(format, args...))
}

// Error is equivalent to Log followed by Fail.
func (c *common) Error(args ...any) {
	c.checkFuzzFn("Error")
	c.log(fmt.Sprintln(args...))
	c.Fail()
}

// Errorf is equivalent to Logf followed by Fail.
func (c *common) Errorf(format string, args ...any) {
	c.checkFuzzFn("Errorf")
	c.log(fmt.Sprintf(format, args...))
	c.Fail()
}

// Fatal is equivalent to Log followed by FailNow.
func (c *common) Fatal(args ...any) {
	c.checkFuzzFn("Fatal")
	c.log(fmt.Sprintln(args...))
	c.FailNow()
}

// Fatalf is equivalent to Logf followed by FailNow.
func (c *common) Fatalf(format string, args ...any) {
	c.checkFuzzFn("Fatalf")
	c.log(fmt.Sprintf(format, args...))
	c.FailNow()
}

// Skip is equivalent to Log followed by SkipNow.
func (c *common) Skip(args ...any) {
	c.checkFuzzFn("Skip")
	c.log(fmt.Sprintln(args...))
	c.SkipNow()
}

// Skipf is equivalent to Logf followed by SkipNow.
func (c *common) Skipf(format string, args ...any) {
	c.checkFuzzFn("Skipf")
	c.log(fmt.Sprintf(format, args...))
	c.SkipNow()
}

// SkipNow marks the test as having been skipped and stops its execution
// by calling [runtime.Goexit].
// If a test fails (see Error, Errorf, Fail) and is then skipped,
// it is still considered to have failed.
// Execution will continue at the next test or benchmark. See also FailNow.
// SkipNow must be called from the goroutine running the test, not from
// other goroutines created during the test. Calling SkipNow does not stop
// those other goroutines.
func (c *common) SkipNow() {
	c.checkFuzzFn("SkipNow")
	c.mu.Lock()
	c.skipped = true
	c.finished = true
	c.mu.Unlock()
	runtime.Goexit()
}

// Skipped reports whether the test was skipped.
func (c *common) Skipped() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.skipped
}

// Helper marks the calling function as a test helper function.
// When printing file and line information, that function will be skipped.
// Helper may be called simultaneously from multiple goroutines.
func (c *common) Helper() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.helperPCs == nil {
		c.helperPCs = make(map[uintptr]struct{})
	}
	// repeating code from callerName here to save walking a stack frame
	var pc [1]uintptr
	n := runtime.Callers(2, pc[:]) // skip runtime.Callers + Helper
	if n == 0 {
		panic("testing: zero callers found")
	}
	if _, found := c.helperPCs[pc[0]]; !found {
		c.helperPCs[pc[0]] = struct{}{}
		c.helperNames = nil // map will be recreated next time it is needed
	}
}

// Cleanup registers a function to be called when the test (or subtest) and all its
// subtests complete. Cleanup functions will be called in last added,
// first called order.
func (c *common) Cleanup(f func()) {
	c.checkFuzzFn("Cleanup")
	var pc [maxStackLen]uintptr
	// Skip two extra frames to account for this function and runtime.Callers itself.
	n := runtime.Callers(2, pc[:])
	cleanupPc := pc[:n]

	fn := func() {
		defer func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.cleanupName = ""
			c.cleanupPc = nil
		}()

		name := callerName(0)
		c.mu.Lock()
		c.cleanupName = name
		c.cleanupPc = cleanupPc
		c.mu.Unlock()

		f()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanups = append(c.cleanups, fn)
}

// TempDir returns a temporary directory for the test to use.
// The directory is automatically removed when the test and
// all its subtests complete.
// Each subsequent call to t.TempDir returns a unique directory;
// if the directory creation fails, TempDir terminates the test by calling Fatal.
func (c *common) TempDir() string {
	c.checkFuzzFn("TempDir")
	// Use a single parent directory for all the temporary directories
	// created by a test, each numbered sequentially.
	c.tempDirMu.Lock()
	var nonExistent bool
	if c.tempDir == "" { // Usually the case with js/wasm
		nonExistent = true
	} else {
		_, err := os.Stat(c.tempDir)
		nonExistent = os.IsNotExist(err)
		if err != nil && !nonExistent {
			c.Fatalf("TempDir: %v", err)
		}
	}

	if nonExistent {
		c.Helper()

		// Drop unusual characters (such as path separators or
		// characters interacting with globs) from the directory name to
		// avoid surprising os.MkdirTemp behavior.
		mapper := func(r rune) rune {
			if r < utf8.RuneSelf {
				const allowed = "!#$%&()+,-.=@^_{}~ "
				if '0' <= r && r <= '9' ||
					'a' <= r && r <= 'z' ||
					'A' <= r && r <= 'Z' {
					return r
				}
				if strings.ContainsRune(allowed, r) {
					return r
				}
			} else if unicode.IsLetter(r) || unicode.IsNumber(r) {
				return r
			}
			return -1
		}
		pattern := strings.Map(mapper, c.Name())
		c.tempDir, c.tempDirErr = os.MkdirTemp("", pattern)
		if c.tempDirErr == nil {
			c.Cleanup(func() {
				if err := removeAll(c.tempDir); err != nil {
					c.Errorf("TempDir RemoveAll cleanup: %v", err)
				}
			})
		}
	}

	if c.tempDirErr == nil {
		c.tempDirSeq++
	}
	seq := c.tempDirSeq
	c.tempDirMu.Unlock()

	if c.tempDirErr != nil {
		c.Fatalf("TempDir: %v", c.tempDirErr)
	}

	dir := fmt.Sprintf("%s%c%03d", c.tempDir, os.PathSeparator, seq)
	if err := os.Mkdir(dir, 0777); err != nil {
		c.Fatalf("TempDir: %v", err)
	}
	return dir
}

// removeAll is like os.RemoveAll, but retries Windows "Access is denied."
// errors up to an arbitrary timeout.
//
// Those errors have been known to occur spuriously on at least the
// windows-amd64-2012 builder (https://go.dev/issue/50051), and can only occur
// legitimately if the test leaves behind a temp file that either is still open
// or the test otherwise lacks permission to delete. In the case of legitimate
// failures, a failing test may take a bit longer to fail, but once the test is
// fixed the extra latency will go away.
func removeAll(path string) error {
	const arbitraryTimeout = 2 * time.Second
	var (
		start     time.Time
		nextSleep = 1 * time.Millisecond
	)
	for {
		err := os.RemoveAll(path)
		if !isWindowsRetryable(err) {
			return err
		}
		if start.IsZero() {
			start = time.Now()
		} else if d := time.Since(start) + nextSleep; d >= arbitraryTimeout {
			return err
		}
		time.Sleep(nextSleep)
		nextSleep += time.Duration(rand.Int63n(int64(nextSleep)))
	}
}

// Setenv calls os.Setenv(key, value) and uses Cleanup to
// restore the environment variable to its original value
// after the test.
//
// Because Setenv affects the whole process, it cannot be used
// in parallel tests or tests with parallel ancestors.
func (c *common) Setenv(key, value string) {
	c.checkFuzzFn("Setenv")
	prevValue, ok := os.LookupEnv(key)

	if err := os.Setenv(key, value); err != nil {
		c.Fatalf("cannot set environment variable: %v", err)
	}

	if ok {
		c.Cleanup(func() {
			os.Setenv(key, prevValue)
		})
	} else {
		c.Cleanup(func() {
			os.Unsetenv(key)
		})
	}
}

// Chdir calls os.Chdir(dir) and uses Cleanup to restore the current
// working directory to its original value after the test. On Unix, it
// also sets PWD environment variable for the duration of the test.
//
// Because Chdir affects the whole process, it cannot be used
// in parallel tests or tests with parallel ancestors.
func (c *common) Chdir(dir string) {
	c.checkFuzzFn("Chdir")
	oldwd, err := os.Open(".")
	if err != nil {
		c.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		c.Fatal(err)
	}
	// On POSIX platforms, PWD represents “an absolute pathname of the
	// current working directory.” Since we are changing the working
	// directory, we should also set or update PWD to reflect that.
	switch runtime.GOOS {
	case "windows", "plan9":
		// Windows and Plan 9 do not use the PWD variable.
	default:
		if !filepath.IsAbs(dir) {
			dir, err = os.Getwd()
			if err != nil {
				c.Fatal(err)
			}
		}
		c.Setenv("PWD", dir)
	}
	c.Cleanup(func() {
		err := oldwd.Chdir()
		oldwd.Close()
		if err != nil {
			// It's not safe to continue with tests if we can't
			// get back to the original working directory. Since
			// we are holding a dirfd, this is highly unlikely.
			panic("testing.Chdir: " + err.Error())
		}
	})
}

// Context returns a context that is canceled just before
// Cleanup-registered functions are called.
//
// Cleanup functions can wait for any resources
// that shut down on Context.Done before the test or benchmark completes.
func (c *common) Context() context.Context {
	c.checkFuzzFn("Context")
	return c.ctx
}

// panicHandling controls the panic handling used by runCleanup.
type panicHandling int

const (
	normalPanic panicHandling = iota
	recoverAndReturnPanic
)

// runCleanup is called at the end of the test.
// If ph is recoverAndReturnPanic, it will catch panics, and return the
// recovered value if any.
func (c *common) runCleanup(ph panicHandling) (panicVal any) {
	c.cleanupStarted.Store(true)
	defer c.cleanupStarted.Store(false)

	if ph == recoverAndReturnPanic {
		defer func() {
			panicVal = recover()
		}()
	}

	// Make sure that if a cleanup function panics,
	// we still run the remaining cleanup functions.
	defer func() {
		c.mu.Lock()
		recur := len(c.cleanups) > 0
		c.mu.Unlock()
		if recur {
			c.runCleanup(normalPanic)
		}
	}()

	if c.cancelCtx != nil {
		c.cancelCtx()
	}

	for {
		var cleanup func()
		c.mu.Lock()
		if len(c.cleanups) > 0 {
			last := len(c.cleanups) - 1
			cleanup = c.cleanups[last]
			c.cleanups = c.cleanups[:last]
		}
		c.mu.Unlock()
		if cleanup == nil {
			return nil
		}
		cleanup()
	}
}

// resetRaces updates c.parent's count of data race errors (or the global count,
// if c has no parent), and updates c.lastRaceErrors to match.
//
// Any races that occurred prior to this call to resetRaces will
// not be attributed to c.
func (c *common) resetRaces() {
	if c.parent == nil {
		c.lastRaceErrors.Store(int64(race.Errors()))
	} else {
		c.lastRaceErrors.Store(c.parent.checkRaces())
	}
}

// checkRaces checks whether the global count of data race errors has increased
// since c's count was last reset.
//
// If so, it marks c as having failed due to those races (logging an error for
// the first such race), and updates the race counts for the parents of c so
// that if they are currently suspended (such as in a call to T.Run) they will
// not log separate errors for the race(s).
//
// Note that multiple tests may be marked as failed due to the same race if they
// are executing in parallel.
func (c *common) checkRaces() (raceErrors int64) {
	raceErrors = int64(race.Errors())
	for {
		last := c.lastRaceErrors.Load()
		if raceErrors <= last {
			// All races have already been reported.
			return raceErrors
		}
		if c.lastRaceErrors.CompareAndSwap(last, raceErrors) {
			break
		}
	}

	if c.raceErrorLogged.CompareAndSwap(false, true) {
		// This is the first race we've encountered for this test.
		// Mark the test as failed, and log the reason why only once.
		// (Note that the race detector itself will still write a goroutine
		// dump for any further races it detects.)
		c.Errorf("race detected during execution of test")
	}

	// Update the parent(s) of this test so that they don't re-report the race.
	parent := c.parent
	for parent != nil {
		for {
			last := parent.lastRaceErrors.Load()
			if raceErrors <= last {
				// This race was already reported by another (likely parallel) subtest.
				return raceErrors
			}
			if parent.lastRaceErrors.CompareAndSwap(last, raceErrors) {
				break
			}
		}
		parent = parent.parent
	}

	return raceErrors
}

// callerName gives the function name (qualified with a package path)
// for the caller after skip frames (where 0 means the current function).
func callerName(skip int) string {
	var pc [1]uintptr
	n := runtime.Callers(skip+2, pc[:]) // skip + runtime.Callers + callerName
	if n == 0 {
		panic("testing: zero callers found")
	}
	return pcToName(pc[0])
}

func pcToName(pc uintptr) string {
	pcs := []uintptr{pc}
	frames := runtime.CallersFrames(pcs)
	frame, _ := frames.Next()
	return frame.Function
}

const parallelConflict = `testing: test using t.Setenv or t.Chdir can not use t.Parallel`

// Parallel signals that this test is to be run in parallel with (and only with)
// other parallel tests. When a test is run multiple times due to use of
// -test.count or -test.cpu, multiple instances of a single test never run in
// parallel with each other.
func (t *T) Parallel() {
	if t.isParallel {
		panic("testing: t.Parallel called multiple times")
	}
	if t.denyParallel {
		panic(parallelConflict)
	}
	t.isParallel = true
	if t.parent.barrier == nil {
		// T.Parallel has no effect when fuzzing.
		// Multiple processes may run in parallel, but only one input can run at a
		// time per process so we can attribute crashes to specific inputs.
		return
	}

	// We don't want to include the time we spend waiting for serial tests
	// in the test duration. Record the elapsed time thus far and reset the
	// timer afterwards.
	t.duration += highPrecisionTimeSince(t.start)

	// Add to the list of tests to be released by the parent.
	t.parent.sub = append(t.parent.sub, t)

	// Report any races during execution of this test up to this point.
	//
	// We will assume that any races that occur between here and the point where
	// we unblock are not caused by this subtest. That assumption usually holds,
	// although it can be wrong if the test spawns a goroutine that races in the
	// background while the rest of the test is blocked on the call to Parallel.
	// If that happens, we will misattribute the background race to some other
	// test, or to no test at all — but that false-negative is so unlikely that it
	// is not worth adding race-report noise for the common case where the test is
	// completely suspended during the call to Parallel.
	t.checkRaces()

	if t.chatty != nil {
		t.chatty.Updatef(t.name, "=== PAUSE %s\n", t.name)
	}
	running.Delete(t.name)

	t.signal <- true   // Release calling test.
	<-t.parent.barrier // Wait for the parent test to complete.
	t.tstate.waitParallel()

	if t.chatty != nil {
		t.chatty.Updatef(t.name, "=== CONT  %s\n", t.name)
	}
	running.Store(t.name, highPrecisionTimeNow())
	t.start = highPrecisionTimeNow()

	// Reset the local race counter to ignore any races that happened while this
	// goroutine was blocked, such as in the parent test or in other parallel
	// subtests.
	//
	// (Note that we don't call parent.checkRaces here:
	// if other parallel subtests have already introduced races, we want to
	// let them report those races instead of attributing them to the parent.)
	t.lastRaceErrors.Store(int64(race.Errors()))
}

func (t *T) checkParallel() {
	// Non-parallel subtests that have parallel ancestors may still
	// run in parallel with other tests: they are only non-parallel
	// with respect to the other subtests of the same parent.
	// Since calls like SetEnv or Chdir affects the whole process, we need
	// to deny those if the current test or any parent is parallel.
	for c := &t.common; c != nil; c = c.parent {
		if c.isParallel {
			panic(parallelConflict)
		}
	}

	t.denyParallel = true
}

// Setenv calls os.Setenv(key, value) and uses Cleanup to
// restore the environment variable to its original value
// after the test.
//
// Because Setenv affects the whole process, it cannot be used
// in parallel tests or tests with parallel ancestors.
func (t *T) Setenv(key, value string) {
	t.checkParallel()
	t.common.Setenv(key, value)
}

// Chdir calls os.Chdir(dir) and uses Cleanup to restore the current
// working directory to its original value after the test. On Unix, it
// also sets PWD environment variable for the duration of the test.
//
// Because Chdir affects the whole process, it cannot be used
// in parallel tests or tests with parallel ancestors.
func (t *T) Chdir(dir string) {
	t.checkParallel()
	t.common.Chdir(dir)
}

// InternalTest is an internal type but exported because it is cross-package;
// it is part of the implementation of the "go test" command.
type InternalTest struct {
	Name string
	F    func(*T)
}

var errNilPanicOrGoexit = errors.New("test executed panic(nil) or runtime.Goexit")

func tRunner(t *T, fn func(t *T)) {
	t.runner = callerName(0)

	// When this goroutine is done, either because fn(t)
	// returned normally or because a test failure triggered
	// a call to runtime.Goexit, record the duration and send
	// a signal saying that the test is done.
	defer func() {
		t.checkRaces()

		// TODO(#61034): This is the wrong place for this check.
		if t.Failed() {
			numFailed.Add(1)
		}

		// Check if the test panicked or Goexited inappropriately.
		//
		// If this happens in a normal test, print output but continue panicking.
		// tRunner is called in its own goroutine, so this terminates the process.
		//
		// If this happens while fuzzing, recover from the panic and treat it like a
		// normal failure. It's important that the process keeps running in order to
		// find short inputs that cause panics.
		err := recover()
		signal := true

		t.mu.RLock()
		finished := t.finished
		t.mu.RUnlock()
		if !finished && err == nil {
			err = errNilPanicOrGoexit
			for p := t.parent; p != nil; p = p.parent {
				p.mu.RLock()
				finished = p.finished
				p.mu.RUnlock()
				if finished {
					if !t.isParallel {
						t.Errorf("%v: subtest may have called FailNow on a parent test", err)
						err = nil
					}
					signal = false
					break
				}
			}
		}

		if err != nil && t.tstate.isFuzzing {
			prefix := "panic: "
			if err == errNilPanicOrGoexit {
				prefix = ""
			}
			t.Errorf("%s%s\n%s\n", prefix, err, string(debug.Stack()))
			t.mu.Lock()
			t.finished = true
			t.mu.Unlock()
			err = nil
		}

		// Use a deferred call to ensure that we report that the test is
		// complete even if a cleanup function calls t.FailNow. See issue 41355.
		didPanic := false
		defer func() {
			// Only report that the test is complete if it doesn't panic,
			// as otherwise the test binary can exit before the panic is
			// reported to the user. See issue 41479.
			if didPanic {
				return
			}
			if err != nil {
				panic(err)
			}
			running.Delete(t.name)
			t.signal <- signal
		}()

		doPanic := func(err any) {
			t.Fail()
			if r := t.runCleanup(recoverAndReturnPanic); r != nil {
				t.Logf("cleanup panicked with %v", r)
			}
			// Flush the output log up to the root before dying.
			for root := &t.common; root.parent != nil; root = root.parent {
				root.mu.Lock()
				root.duration += highPrecisionTimeSince(root.start)
				d := root.duration
				root.mu.Unlock()
				root.flushToParent(root.name, "--- FAIL: %s (%s)\n", root.name, fmtDuration(d))
				if r := root.parent.runCleanup(recoverAndReturnPanic); r != nil {
					fmt.Fprintf(root.parent.w, "cleanup panicked with %v", r)
				}
			}
			didPanic = true
			panic(err)
		}
		if err != nil {
			doPanic(err)
		}

		t.duration += highPrecisionTimeSince(t.start)

		if len(t.sub) > 0 {
			// Run parallel subtests.

			// Decrease the running count for this test and mark it as no longer running.
			t.tstate.release()
			running.Delete(t.name)

			// Release the parallel subtests.
			close(t.barrier)
			// Wait for subtests to complete.
			for _, sub := range t.sub {
				<-sub.signal
			}

			// Run any cleanup callbacks, marking the test as running
			// in case the cleanup hangs.
			cleanupStart := highPrecisionTimeNow()
			running.Store(t.name, cleanupStart)
			err := t.runCleanup(recoverAndReturnPanic)
			t.duration += highPrecisionTimeSince(cleanupStart)
			if err != nil {
				doPanic(err)
			}
			t.checkRaces()
			if !t.isParallel {
				// Reacquire the count for sequential tests. See comment in Run.
				t.tstate.waitParallel()
			}
		} else if t.isParallel {
			// Only release the count for this test if it was run as a parallel
			// test. See comment in Run method.
			t.tstate.release()
		}
		t.report() // Report after all subtests have finished.

		// Do not lock t.done to allow race detector to detect race in case
		// the user does not appropriately synchronize a goroutine.
		t.done = true
		if t.parent != nil && !t.hasSub.Load() {
			t.setRan()
		}
	}()
	defer func() {
		if len(t.sub) == 0 {
			t.runCleanup(normalPanic)
		}
	}()

	t.start = highPrecisionTimeNow()
	t.resetRaces()
	fn(t)

	// code beyond here will not be executed when FailNow is invoked
	t.mu.Lock()
	t.finished = true
	t.mu.Unlock()
}

// Run runs f as a subtest of t called name. It runs f in a separate goroutine
// and blocks until f returns or calls t.Parallel to become a parallel test.
// Run reports whether f succeeded (or at least did not fail before calling t.Parallel).
//
// Run may be called simultaneously from multiple goroutines, but all such calls
// must return before the outer test function for t returns.
func (t *T) Run(name string, f func(t *T)) bool {
	if t.cleanupStarted.Load() {
		panic("testing: t.Run called during t.Cleanup")
	}

	t.hasSub.Store(true)
	testName, ok, _ := t.tstate.match.fullName(&t.common, name)
	if !ok || shouldFailFast() {
		return true
	}
	// Record the stack trace at the point of this call so that if the subtest
	// function - which runs in a separate stack - is marked as a helper, we can
	// continue walking the stack into the parent test.
	var pc [maxStackLen]uintptr
	n := runtime.Callers(2, pc[:])

	// There's no reason to inherit this context from parent. The user's code can't observe
	// the difference between the background context and the one from the parent test.
	ctx, cancelCtx := context.WithCancel(context.Background())
	t = &T{
		common: common{
			barrier:   make(chan bool),
			signal:    make(chan bool, 1),
			name:      testName,
			parent:    &t.common,
			level:     t.level + 1,
			creator:   pc[:n],
			chatty:    t.chatty,
			ctx:       ctx,
			cancelCtx: cancelCtx,
		},
		tstate: t.tstate,
	}
	t.w = indenter{&t.common}

	if t.chatty != nil {
		t.chatty.Updatef(t.name, "=== RUN   %s\n", t.name)
	}
	running.Store(t.name, highPrecisionTimeNow())

	// Instead of reducing the running count of this test before calling the
	// tRunner and increasing it afterwards, we rely on tRunner keeping the
	// count correct. This ensures that a sequence of sequential tests runs
	// without being preempted, even when their parent is a parallel test. This
	// may especially reduce surprises if *parallel == 1.
	go tRunner(t, f)

	// The parent goroutine will block until the subtest either finishes or calls
	// Parallel, but in general we don't know whether the parent goroutine is the
	// top-level test function or some other goroutine it has spawned.
	// To avoid confusing false-negatives, we leave the parent in the running map
	// even though in the typical case it is blocked.

	if !<-t.signal {
		// At this point, it is likely that FailNow was called on one of the
		// parent tests by one of the subtests. Continue aborting up the chain.
		runtime.Goexit()
	}

	if t.chatty != nil && t.chatty.json {
		t.chatty.Updatef(t.parent.name, "=== NAME  %s\n", t.parent.name)
	}
	return !t.failed
}

// Deadline reports the time at which the test binary will have
// exceeded the timeout specified by the -timeout flag.
//
// The ok result is false if the -timeout flag indicates “no timeout” (0).
func (t *T) Deadline() (deadline time.Time, ok bool) {
	deadline = t.tstate.deadline
	return deadline, !deadline.IsZero()
}

// testState holds all fields that are common to all tests. This includes
// synchronization primitives to run at most *parallel tests.
type testState struct {
	match    *matcher
	deadline time.Time

	// isFuzzing is true in the state used when generating random inputs
	// for fuzz targets. isFuzzing is false when running normal tests and
	// when running fuzz tests as unit tests (without -fuzz or when -fuzz
	// does not match).
	isFuzzing bool

	mu sync.Mutex

	// Channel used to signal tests that are ready to be run in parallel.
	startParallel chan bool

	// running is the number of tests currently running in parallel.
	// This does not include tests that are waiting for subtests to complete.
	running int

	// numWaiting is the number tests waiting to be run in parallel.
	numWaiting int

	// maxParallel is a copy of the parallel flag.
	maxParallel int
}

func newTestState(maxParallel int, m *matcher) *testState {
	return &testState{
		match:         m,
		startParallel: make(chan bool),
		maxParallel:   maxParallel,
		running:       1, // Set the count to 1 for the main (sequential) test.
	}
}

func (s *testState) waitParallel() {
	s.mu.Lock()
	if s.running < s.maxParallel {
		s.running++
		s.mu.Unlock()
		return
	}
	s.numWaiting++
	s.mu.Unlock()
	<-s.startParallel
}

func (s *testState) release() {
	s.mu.Lock()
	if s.numWaiting == 0 {
		s.running--
		s.mu.Unlock()
		return
	}
	s.numWaiting--
	s.mu.Unlock()
	s.startParallel <- true // Pick a waiting test to be run.
}

// No one should be using func Main anymore.
// See the doc comment on func Main and use MainStart instead.
var errMain = errors.New("testing: unexpected use of func Main")

type matchStringOnly func(pat, str string) (bool, error)

func (f matchStringOnly) MatchString(pat, str string) (bool, error)   { return f(pat, str) }
func (f matchStringOnly) StartCPUProfile(w io.Writer) error           { return errMain }
func (f matchStringOnly) StopCPUProfile()                             {}
func (f matchStringOnly) WriteProfileTo(string, io.Writer, int) error { return errMain }
func (f matchStringOnly) ImportPath() string                          { return "" }
func (f matchStringOnly) StartTestLog(io.Writer)                      {}
func (f matchStringOnly) StopTestLog() error                          { return errMain }
func (f matchStringOnly) SetPanicOnExit0(bool)                        {}
func (f matchStringOnly) CoordinateFuzzing(time.Duration, int64, time.Duration, int64, int, []corpusEntry, []reflect.Type, string, string) error {
	return errMain
}
func (f matchStringOnly) RunFuzzWorker(func(corpusEntry) error) error { return errMain }
func (f matchStringOnly) ReadCorpus(string, []reflect.Type) ([]corpusEntry, error) {
	return nil, errMain
}
func (f matchStringOnly) CheckCorpus([]any, []reflect.Type) error { return nil }
func (f matchStringOnly) ResetCoverage()                          {}
func (f matchStringOnly) SnapshotCoverage()                       {}

func (f matchStringOnly) InitRuntimeCoverage() (mode string, tearDown func(string, string) (string, error), snapcov func() float64) {
	return
}

// Main is an internal function, part of the implementation of the "go test" command.
// It was exported because it is cross-package and predates "internal" packages.
// It is no longer used by "go test" but preserved, as much as possible, for other
// systems that simulate "go test" using Main, but Main sometimes cannot be updated as
// new functionality is added to the testing package.
// Systems simulating "go test" should be updated to use MainStart.
func Main(matchString func(pat, str string) (bool, error), tests []InternalTest, benchmarks []InternalBenchmark, examples []InternalExample) {
	os.Exit(MainStart(matchStringOnly(matchString), tests, benchmarks, nil, examples).Run())
}

// M is a type passed to a TestMain function to run the actual tests.
type M struct {
	deps        testDeps
	tests       []InternalTest
	benchmarks  []InternalBenchmark
	fuzzTargets []InternalFuzzTarget
	examples    []InternalExample

	timer     *time.Timer
	afterOnce sync.Once

	numRun int

	// value to pass to os.Exit, the outer test func main
	// harness calls os.Exit with this code. See #34129.
	exitCode int
}

// testDeps is an internal interface of functionality that is
// passed into this package by a test's generated main package.
// The canonical implementation of this interface is
// testing/internal/testdeps's TestDeps.
type testDeps interface {
	ImportPath() string
	MatchString(pat, str string) (bool, error)
	SetPanicOnExit0(bool)
	StartCPUProfile(io.Writer) error
	StopCPUProfile()
	StartTestLog(io.Writer)
	StopTestLog() error
	WriteProfileTo(string, io.Writer, int) error
	CoordinateFuzzing(time.Duration, int64, time.Duration, int64, int, []corpusEntry, []reflect.Type, string, string) error
	RunFuzzWorker(func(corpusEntry) error) error
	ReadCorpus(string, []reflect.Type) ([]corpusEntr
"""




```