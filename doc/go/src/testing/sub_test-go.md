Response:
Let's break down the thought process for analyzing the Go code snippet and generating the Chinese response.

1. **Understanding the Goal:** The request asks for a functional breakdown of the `sub_test.go` file, including its purpose within the larger Go testing framework, illustrative code examples, handling of command-line arguments (if applicable), and common pitfalls for users. The response needs to be in Chinese.

2. **Initial Scan and Keyword Recognition:**  I started by quickly scanning the code for key Go testing concepts: `package testing`, `import`, `func Test...`, `func Benchmark...`, `t.Run`, `b.Run`, `t.Parallel()`, `t.FailNow()`, `t.SkipNow()`, `t.Cleanup()`, `t.Log`, `t.Error`, `t.Fatal`, `b.N`, `b.SetBytes`, `b.ReportAllocs`. These keywords immediately suggest the file deals with testing functionalities, specifically subtests and sub-benchmarks.

3. **Identifying Core Functionality Areas:**  Based on the keywords and the structure of the tests, I identified the main areas of functionality being tested:
    * **`TestTestState`:** This function clearly tests the internal state management of the testing framework, specifically how it handles parallel test execution limits. The `testState` struct and its methods `waitParallel` and `release` are central here.
    * **`TestTRun`:** This is the heart of subtest functionality. It tests various aspects of `t.Run`: sequential and parallel execution, failure propagation, skipping, output formatting (including chatty and JSON modes), synchronization using `t.Run`, error and fatal calls in subtests and their impact on parent tests, and cleanups.
    * **`TestBRun`:** This focuses on sub-benchmarks using `b.Run`, testing similar concepts to `TestTRun` but in the context of benchmarks: sequential execution, `SetBytes`, failure/skip behavior, memory allocation reporting, and cleanups.
    * **Individual smaller test functions:**  Functions like `TestBenchmarkOutput`, `TestBenchmarkStartsFrom1`, `TestBenchmarkReadMemStatsBeforeFirstRun`, `TestRacyOutput`, `TestLogAfterComplete`, `TestBenchmark`, `TestCleanup`, `TestConcurrentCleanup`, `TestCleanupCalledEvenAfterGoexit`, `TestRunCleanup`, `TestCleanupParallelSubtests`, and `TestNestedCleanup` test specific edge cases or features of the testing framework, primarily related to benchmarks and cleanups.

4. **Inferring the Purpose:**  Putting the identified areas together, I concluded that `sub_test.go` primarily implements and tests the subtest and sub-benchmark features within the Go `testing` package. This allows for more organized and granular testing.

5. **Generating Code Examples:**  For each major functionality area, I formulated simple Go code examples to demonstrate their usage. For instance:
    * `t.Run` for grouping tests.
    * `t.Parallel` for concurrent execution.
    * `t.FailNow` for immediate failure.
    * `t.SkipNow` for skipping tests.
    * `t.Cleanup` for deferred cleanup actions.
    * `b.Run` for grouping benchmarks.
    * `b.N` for iteration count in benchmarks.
    * `b.SetBytes` for reporting data processing rates.
    * `b.ReportAllocs` for memory allocation statistics.

6. **Reasoning About Command-Line Arguments:** I reviewed the code for any explicit handling of command-line flags. The `init()` function setting `benchTime.d` suggests an internal adjustment for testing purposes, but not direct parsing of command-line arguments within this specific file. Therefore, I concluded that the file itself doesn't directly handle command-line arguments related to test execution. However, it's important to note that the broader `go test` command *does* use flags that influence how these tests are run (e.g., `-v` for verbose output, which relates to the "chatty" concept).

7. **Identifying Common Pitfalls:** Based on the tested scenarios (especially those checking for error propagation and cleanup behavior), I identified potential pitfalls:
    * **Incorrectly assuming `t.FailNow()` will stop all execution:**  It only stops the *current* test and its siblings within the same `t.Run` group.
    * **Forgetting `t.Parallel()` can lead to unexpected concurrency issues if shared state isn't managed:**  The `TestRacyOutput` example hints at this.
    * **Misunderstanding the order of `t.Cleanup()` execution:** Cleanups run in reverse order of their declaration.

8. **Structuring the Response:** I organized the response into the requested sections: 功能介绍 (Functionality Introduction), 功能实现推理 (Functionality Implementation Inference with Code Examples), 命令行参数 (Command-Line Arguments), and 易犯错的点 (Common Pitfalls).

9. **Translating to Chinese:**  Finally, I translated all the explanations and code comments into clear and accurate Chinese. This involved careful attention to terminology related to software testing and Go programming. For example, translating "subtest" to "子测试", "benchmark" to "基准测试", "parallel" to "并行", etc. I also made sure the code examples were well-commented in Chinese.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Could the `init()` function be seen as handling a kind of "internal" command-line argument?  **Correction:** No, it's a fixed adjustment for the testing environment, not user-provided input.
* **Considering the scope:** Should I explain the entire `testing` package? **Correction:** The request focuses on *this specific file*, so I should limit the scope accordingly while providing context where necessary.
* **Ensuring clarity in examples:** Are the code examples too complex? **Correction:** Keep them concise and directly relevant to the concept being illustrated. Add comments to improve understanding.
* **Checking for completeness:** Did I address all aspects of the request? **Correction:** Review the original prompt to make sure I covered functionality, inference, code, arguments, and pitfalls.

By following these steps, I could systematically analyze the code and generate a comprehensive and accurate response in Chinese.
好的，让我们来分析一下 `go/src/testing/sub_test.go` 这个 Go 语言源文件。

**功能介绍**

这个文件主要实现了 Go 语言 `testing` 包中关于 **子测试 (Subtests)** 和 **子基准测试 (Sub-benchmarks)** 的功能。具体来说，它包含了：

1. **`TestTestState` 函数:**  这个函数测试了 `testing` 包内部用于管理并行测试状态的 `testState` 结构体及其相关方法。它验证了在限定最大并行数量的情况下，测试的启动、等待和完成状态的正确性。

2. **`TestTRun` 函数:**  这是核心的子测试功能测试函数。它测试了 `t.Run` 方法的各种行为，包括：
   - 顺序和并行子测试的执行。
   - `FailNow()` 如何跳过后续的同级测试。
   - 子测试中的失败如何向上冒泡影响父测试。
   - 使用 `SkipNow()` 跳过测试。
   - `t.Run` 的嵌套使用。
   - `chatty` 模式 (更详细的输出)。
   - `json` 模式的输出。
   - 子测试中调用父测试的 `Error` 和 `Fatal` 方法的影响。
   - 子测试 `panic` 时的处理。
   - 完成的子测试中记录日志的行为。
   - `Cleanup` 函数的执行时机和作用。

3. **`TestBRun` 函数:**  这个函数测试了 `testing` 包中关于子基准测试的功能，即 `b.Run` 方法。它测试了：
   - 顺序执行子基准测试。
   - `SetBytes` 方法用于设置操作的字节数。
   - 子基准测试中的失败和跳过行为。
   - `ReportAllocs` 方法用于报告内存分配情况。
   - `Cleanup` 函数在基准测试中的使用。

4. **其他辅助测试函数:**  文件中还包含了一些其他的测试函数，用于验证 `testing` 包中与子测试和子基准测试相关的特定行为，例如：
   - `TestBenchmarkOutput`: 测试基准测试的输出。
   - `TestBenchmarkStartsFrom1`: 确保基准测试的 `b.N` 从 1 开始。
   - `TestBenchmarkReadMemStatsBeforeFirstRun`: 验证在第一次基准测试运行前读取了内存统计信息。
   - `TestRacyOutput`: 测试并发写入测试输出时的竞争条件。
   - `TestLogAfterComplete`: 测试在测试完成后记录日志的行为。
   - `TestBenchmark`: 一个简单的基准测试用例。
   - `TestCleanup`, `TestConcurrentCleanup`, `TestCleanupCalledEvenAfterGoexit`, `TestRunCleanup`, `TestCleanupParallelSubtests`, `TestNestedCleanup`:  这些函数专门测试 `t.Cleanup` 的各种场景和行为。

**功能实现推理与代码示例**

这个文件是 `testing` 包自身的一部分，它通过编写测试用例来验证 `testing` 包的功能是否按预期工作。  我们可以推断出它测试了 Go 语言的子测试和子基准测试的实现。

**子测试 (Subtests)**

Go 语言的子测试允许在一个测试函数内部定义多个相关的测试用例，每个用例都有自己的名字，并可以独立运行。这使得测试结构更清晰，更容易定位问题。

```go
package main

import "testing"

func TestMathOperations(t *testing.T) {
	t.Run("Add", func(t *testing.T) {
		result := 2 + 3
		if result != 5 {
			t.Errorf("Add operation failed: expected 5, got %d", result)
		}
	})

	t.Run("Subtract", func(t *testing.T) {
		result := 5 - 2
		if result != 3 {
			t.Errorf("Subtract operation failed: expected 3, got %d", result)
		}
	})
}
```

**假设输入与输出：**

如果我们运行上面的测试代码 (`go test` 命令)，输出可能如下：

```
=== RUN   TestMathOperations
=== RUN   TestMathOperations/Add
=== PASS  TestMathOperations/Add (0.00s)
=== RUN   TestMathOperations/Subtract
=== PASS  TestMathOperations/Subtract (0.00s)
=== PASS  TestMathOperations (0.00s)
PASS
ok      _/tmp/example  0.001s
```

如果 `Add` 子测试失败，输出会类似：

```
=== RUN   TestMathOperations
=== RUN   TestMathOperations/Add
    example_test.go:7: Add operation failed: expected 5, got 6
--- FAIL: TestMathOperations/Add (0.00s)
=== RUN   TestMathOperations/Subtract
=== PASS  TestMathOperations/Subtract (0.00s)
--- FAIL: TestMathOperations (0.00s)
FAIL
exit status 1
FAIL    _/tmp/example  0.001s
```

**子基准测试 (Sub-benchmarks)**

类似于子测试，子基准测试允许在一个基准测试函数内部定义多个相关的基准测试用例。

```go
package main

import "testing"

func BenchmarkStringConcat(b *testing.B) {
	b.Run("Plus", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = "hello" + "world"
		}
	})

	b.Run("Sprintf", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = "hello" + "world" // 故意使用 +，和 Run 的名字对应
		}
	})
}
```

**假设输入与输出：**

如果我们运行上面的基准测试 (`go test -bench=.` 命令)，输出可能如下：

```
goos: linux
goarch: amd64
pkg: _/tmp/example
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkStringConcat/Plus-16         177619413                6.729 ns/op
BenchmarkStringConcat/Sprintf-16      177117404                6.747 ns/op
PASS
ok      _/tmp/example  2.460s
```

**命令行参数的具体处理**

这个 `sub_test.go` 文件本身主要是测试代码，它并不直接处理命令行参数。  `testing` 包的功能是受到 `go test` 命令的各种标志位控制的。一些相关的标志位包括：

- **`-run regexp`**:  指定要运行的测试函数或子测试的正则表达式。例如，`go test -run TestTRun/failnow` 将只运行 `TestTRun` 函数中名字包含 "failnow" 的子测试。
- **`-bench regexp`**: 指定要运行的基准测试函数或子基准测试的正则表达式。
- **`-v`**:  启用更详细的输出（对应代码中的 `chatty` 模式）。
- **`-json`**:  以 JSON 格式输出测试结果。
- **`-parallel n`**: 设置并行运行测试的最大数量。
- **`-count n`**:  多次运行每个测试。
- **`-benchtime d`**:  指定基准测试的运行时间。

`TestTRun` 函数中的一些测试用例，例如带有 `chatty: true` 和 `json: true` 的用例，实际上是在模拟和验证 `-v` 和 `-json` 标志位影响下的输出格式。

**易犯错的点**

1. **`t.FailNow()` 的作用域:**  新手可能会误以为 `t.FailNow()` 会立即停止所有测试的执行。实际上，它只会停止当前测试函数（或子测试）的执行，并跳过同一 `t.Run` 下的后续同级测试。父级测试会继续执行，除非它自身也失败了。

   ```go
   func TestParent(t *testing.T) {
       t.Run("sub1", func(t *testing.T) {
           t.FailNow() // 只会停止 sub1 的执行
           t.Log("不会执行到这里")
       })
       t.Run("sub2", func(t *testing.T) {
           t.Log("sub2 仍然会执行")
       })
       t.Log("Parent test 仍然会执行到这里")
   }
   ```

2. **并行子测试中的数据竞争:** 当使用 `t.Parallel()` 运行子测试时，需要格外小心共享变量的并发访问，避免数据竞争。

   ```go
   func TestParallelAccess(t *testing.T) {
       var counter int
       t.Run("p1", func(t *testing.T) {
           t.Parallel()
           counter++ // 潜在的数据竞争
       })
       t.Run("p2", func(t *testing.T) {
           t.Parallel()
           counter++ // 潜在的数据竞争
       })
   }
   ```
   应该使用同步机制（如互斥锁、原子操作等）来保护共享变量。

3. **`t.Cleanup()` 的执行顺序:** `t.Cleanup()` 注册的清理函数会在测试函数执行完毕后（无论成功、失败还是被跳过）按照 **后进先出 (LIFO)** 的顺序执行。如果不了解这个顺序，可能会导致清理操作的依赖问题。

   ```go
   func TestCleanupOrder(t *testing.T) {
       t.Cleanup(func() { t.Log("Cleanup 1") })
       t.Cleanup(func() { t.Log("Cleanup 2") })
       // 输出顺序会是 Cleanup 2, 然后 Cleanup 1
   }
   ```

总而言之，`go/src/testing/sub_test.go` 是 Go 语言 `testing` 包中关于子测试和子基准测试功能的核心测试文件，它通过大量的测试用例覆盖了这些功能的各种场景和边界情况，确保了这些功能的正确性和可靠性。理解这个文件的内容有助于更深入地理解 Go 语言的测试机制。

Prompt: 
```
这是路径为go/src/testing/sub_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testing

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func init() {
	// Make benchmark tests run 10x faster.
	benchTime.d = 100 * time.Millisecond
}

func TestTestState(t *T) {
	const (
		add1 = 0
		done = 1
	)
	type call struct {
		typ int // run or done
		// result from applying the call
		running int
		waiting int
		started bool
	}
	testCases := []struct {
		max int
		run []call
	}{{
		max: 1,
		run: []call{
			{typ: add1, running: 1, waiting: 0, started: true},
			{typ: done, running: 0, waiting: 0, started: false},
		},
	}, {
		max: 1,
		run: []call{
			{typ: add1, running: 1, waiting: 0, started: true},
			{typ: add1, running: 1, waiting: 1, started: false},
			{typ: done, running: 1, waiting: 0, started: true},
			{typ: done, running: 0, waiting: 0, started: false},
			{typ: add1, running: 1, waiting: 0, started: true},
		},
	}, {
		max: 3,
		run: []call{
			{typ: add1, running: 1, waiting: 0, started: true},
			{typ: add1, running: 2, waiting: 0, started: true},
			{typ: add1, running: 3, waiting: 0, started: true},
			{typ: add1, running: 3, waiting: 1, started: false},
			{typ: add1, running: 3, waiting: 2, started: false},
			{typ: add1, running: 3, waiting: 3, started: false},
			{typ: done, running: 3, waiting: 2, started: true},
			{typ: add1, running: 3, waiting: 3, started: false},
			{typ: done, running: 3, waiting: 2, started: true},
			{typ: done, running: 3, waiting: 1, started: true},
			{typ: done, running: 3, waiting: 0, started: true},
			{typ: done, running: 2, waiting: 0, started: false},
			{typ: done, running: 1, waiting: 0, started: false},
			{typ: done, running: 0, waiting: 0, started: false},
		},
	}}
	for i, tc := range testCases {
		tstate := &testState{
			startParallel: make(chan bool),
			maxParallel:   tc.max,
		}
		for j, call := range tc.run {
			doCall := func(f func()) chan bool {
				done := make(chan bool)
				go func() {
					f()
					done <- true
				}()
				return done
			}
			started := false
			switch call.typ {
			case add1:
				signal := doCall(tstate.waitParallel)
				select {
				case <-signal:
					started = true
				case tstate.startParallel <- true:
					<-signal
				}
			case done:
				signal := doCall(tstate.release)
				select {
				case <-signal:
				case <-tstate.startParallel:
					started = true
					<-signal
				}
			}
			if started != call.started {
				t.Errorf("%d:%d:started: got %v; want %v", i, j, started, call.started)
			}
			if tstate.running != call.running {
				t.Errorf("%d:%d:running: got %v; want %v", i, j, tstate.running, call.running)
			}
			if tstate.numWaiting != call.waiting {
				t.Errorf("%d:%d:waiting: got %v; want %v", i, j, tstate.numWaiting, call.waiting)
			}
		}
	}
}

func TestTRun(t *T) {
	realTest := t
	testCases := []struct {
		desc   string
		ok     bool
		maxPar int
		chatty bool
		json   bool
		output string
		f      func(*T)
	}{{
		desc:   "failnow skips future sequential and parallel tests at same level",
		ok:     false,
		maxPar: 1,
		output: `
--- FAIL: failnow skips future sequential and parallel tests at same level (N.NNs)
    --- FAIL: failnow skips future sequential and parallel tests at same level/#00 (N.NNs)
    `,
		f: func(t *T) {
			ranSeq := false
			ranPar := false
			t.Run("", func(t *T) {
				t.Run("par", func(t *T) {
					t.Parallel()
					ranPar = true
				})
				t.Run("seq", func(t *T) {
					ranSeq = true
				})
				t.FailNow()
				t.Run("seq", func(t *T) {
					realTest.Error("test must be skipped")
				})
				t.Run("par", func(t *T) {
					t.Parallel()
					realTest.Error("test must be skipped.")
				})
			})
			if !ranPar {
				realTest.Error("parallel test was not run")
			}
			if !ranSeq {
				realTest.Error("sequential test was not run")
			}
		},
	}, {
		desc:   "failure in parallel test propagates upwards",
		ok:     false,
		maxPar: 1,
		output: `
--- FAIL: failure in parallel test propagates upwards (N.NNs)
    --- FAIL: failure in parallel test propagates upwards/#00 (N.NNs)
        --- FAIL: failure in parallel test propagates upwards/#00/par (N.NNs)
        `,
		f: func(t *T) {
			t.Run("", func(t *T) {
				t.Parallel()
				t.Run("par", func(t *T) {
					t.Parallel()
					t.Fail()
				})
			})
		},
	}, {
		desc:   "skipping without message, chatty",
		ok:     true,
		chatty: true,
		output: `
=== RUN   skipping without message, chatty
--- SKIP: skipping without message, chatty (N.NNs)`,
		f: func(t *T) { t.SkipNow() },
	}, {
		desc:   "chatty with recursion",
		ok:     true,
		chatty: true,
		output: `
=== RUN   chatty with recursion
=== RUN   chatty with recursion/#00
=== RUN   chatty with recursion/#00/#00
--- PASS: chatty with recursion (N.NNs)
    --- PASS: chatty with recursion/#00 (N.NNs)
        --- PASS: chatty with recursion/#00/#00 (N.NNs)`,
		f: func(t *T) {
			t.Run("", func(t *T) {
				t.Run("", func(t *T) {})
			})
		},
	}, {
		desc:   "chatty with recursion and json",
		ok:     false,
		chatty: true,
		json:   true,
		output: `
^V=== RUN   chatty with recursion and json
^V=== RUN   chatty with recursion and json/#00
^V=== RUN   chatty with recursion and json/#00/#00
^V--- PASS: chatty with recursion and json/#00/#00 (N.NNs)
^V=== NAME  chatty with recursion and json/#00
^V=== RUN   chatty with recursion and json/#00/#01
    sub_test.go:NNN: skip
^V--- SKIP: chatty with recursion and json/#00/#01 (N.NNs)
^V=== NAME  chatty with recursion and json/#00
^V=== RUN   chatty with recursion and json/#00/#02
    sub_test.go:NNN: fail
^V--- FAIL: chatty with recursion and json/#00/#02 (N.NNs)
^V=== NAME  chatty with recursion and json/#00
^V--- FAIL: chatty with recursion and json/#00 (N.NNs)
^V=== NAME  chatty with recursion and json
^V--- FAIL: chatty with recursion and json (N.NNs)
^V=== NAME  `,
		f: func(t *T) {
			t.Run("", func(t *T) {
				t.Run("", func(t *T) {})
				t.Run("", func(t *T) { t.Skip("skip") })
				t.Run("", func(t *T) { t.Fatal("fail") })
			})
		},
	}, {
		desc: "skipping without message, not chatty",
		ok:   true,
		f:    func(t *T) { t.SkipNow() },
	}, {
		desc: "skipping after error",
		output: `
--- FAIL: skipping after error (N.NNs)
    sub_test.go:NNN: an error
    sub_test.go:NNN: skipped`,
		f: func(t *T) {
			t.Error("an error")
			t.Skip("skipped")
		},
	}, {
		desc:   "use Run to locally synchronize parallelism",
		ok:     true,
		maxPar: 1,
		f: func(t *T) {
			var count uint32
			t.Run("waitGroup", func(t *T) {
				for i := 0; i < 4; i++ {
					t.Run("par", func(t *T) {
						t.Parallel()
						atomic.AddUint32(&count, 1)
					})
				}
			})
			if count != 4 {
				t.Errorf("count was %d; want 4", count)
			}
		},
	}, {
		desc: "alternate sequential and parallel",
		// Sequential tests should partake in the counting of running threads.
		// Otherwise, if one runs parallel subtests in sequential tests that are
		// itself subtests of parallel tests, the counts can get askew.
		ok:     true,
		maxPar: 1,
		f: func(t *T) {
			t.Run("a", func(t *T) {
				t.Parallel()
				t.Run("b", func(t *T) {
					// Sequential: ensure running count is decremented.
					t.Run("c", func(t *T) {
						t.Parallel()
					})

				})
			})
		},
	}, {
		desc: "alternate sequential and parallel 2",
		// Sequential tests should partake in the counting of running threads.
		// Otherwise, if one runs parallel subtests in sequential tests that are
		// itself subtests of parallel tests, the counts can get askew.
		ok:     true,
		maxPar: 2,
		f: func(t *T) {
			for i := 0; i < 2; i++ {
				t.Run("a", func(t *T) {
					t.Parallel()
					time.Sleep(time.Nanosecond)
					for i := 0; i < 2; i++ {
						t.Run("b", func(t *T) {
							time.Sleep(time.Nanosecond)
							for i := 0; i < 2; i++ {
								t.Run("c", func(t *T) {
									t.Parallel()
									time.Sleep(time.Nanosecond)
								})
							}

						})
					}
				})
			}
		},
	}, {
		desc:   "stress test",
		ok:     true,
		maxPar: 4,
		f: func(t *T) {
			t.Parallel()
			for i := 0; i < 12; i++ {
				t.Run("a", func(t *T) {
					t.Parallel()
					time.Sleep(time.Nanosecond)
					for i := 0; i < 12; i++ {
						t.Run("b", func(t *T) {
							time.Sleep(time.Nanosecond)
							for i := 0; i < 12; i++ {
								t.Run("c", func(t *T) {
									t.Parallel()
									time.Sleep(time.Nanosecond)
									t.Run("d1", func(t *T) {})
									t.Run("d2", func(t *T) {})
									t.Run("d3", func(t *T) {})
									t.Run("d4", func(t *T) {})
								})
							}
						})
					}
				})
			}
		},
	}, {
		desc:   "skip output",
		ok:     true,
		maxPar: 4,
		f: func(t *T) {
			t.Skip()
		},
	}, {
		desc: "subtest calls error on parent",
		ok:   false,
		output: `
--- FAIL: subtest calls error on parent (N.NNs)
    sub_test.go:NNN: first this
    sub_test.go:NNN: and now this!
    sub_test.go:NNN: oh, and this too`,
		maxPar: 1,
		f: func(t *T) {
			t.Errorf("first this")
			outer := t
			t.Run("", func(t *T) {
				outer.Errorf("and now this!")
			})
			t.Errorf("oh, and this too")
		},
	}, {
		desc: "subtest calls fatal on parent",
		ok:   false,
		output: `
--- FAIL: subtest calls fatal on parent (N.NNs)
    sub_test.go:NNN: first this
    sub_test.go:NNN: and now this!
    --- FAIL: subtest calls fatal on parent/#00 (N.NNs)
        testing.go:NNN: test executed panic(nil) or runtime.Goexit: subtest may have called FailNow on a parent test`,
		maxPar: 1,
		f: func(t *T) {
			outer := t
			t.Errorf("first this")
			t.Run("", func(t *T) {
				outer.Fatalf("and now this!")
			})
			t.Errorf("Should not reach here.")
		},
	}, {
		desc: "subtest calls error on ancestor",
		ok:   false,
		output: `
--- FAIL: subtest calls error on ancestor (N.NNs)
    sub_test.go:NNN: Report to ancestor
    --- FAIL: subtest calls error on ancestor/#00 (N.NNs)
        sub_test.go:NNN: Still do this
    sub_test.go:NNN: Also do this`,
		maxPar: 1,
		f: func(t *T) {
			outer := t
			t.Run("", func(t *T) {
				t.Run("", func(t *T) {
					outer.Errorf("Report to ancestor")
				})
				t.Errorf("Still do this")
			})
			t.Errorf("Also do this")
		},
	}, {
		desc: "subtest calls fatal on ancestor",
		ok:   false,
		output: `
--- FAIL: subtest calls fatal on ancestor (N.NNs)
    sub_test.go:NNN: Nope`,
		maxPar: 1,
		f: func(t *T) {
			outer := t
			t.Run("", func(t *T) {
				for i := 0; i < 4; i++ {
					t.Run("", func(t *T) {
						outer.Fatalf("Nope")
					})
					t.Errorf("Don't do this")
				}
				t.Errorf("And neither do this")
			})
			t.Errorf("Nor this")
		},
	}, {
		desc:   "panic on goroutine fail after test exit",
		ok:     false,
		maxPar: 4,
		f: func(t *T) {
			ch := make(chan bool)
			t.Run("", func(t *T) {
				go func() {
					<-ch
					defer func() {
						if r := recover(); r == nil {
							realTest.Errorf("expected panic")
						}
						ch <- true
					}()
					t.Errorf("failed after success")
				}()
			})
			ch <- true
			<-ch
		},
	}, {
		desc: "log in finished sub test logs to parent",
		ok:   false,
		output: `
		--- FAIL: log in finished sub test logs to parent (N.NNs)
    sub_test.go:NNN: message2
    sub_test.go:NNN: message1
    sub_test.go:NNN: error`,
		maxPar: 1,
		f: func(t *T) {
			ch := make(chan bool)
			t.Run("sub", func(t2 *T) {
				go func() {
					<-ch
					t2.Log("message1")
					ch <- true
				}()
			})
			t.Log("message2")
			ch <- true
			<-ch
			t.Errorf("error")
		},
	}, {
		// A chatty test should always log with fmt.Print, even if the
		// parent test has completed.
		desc:   "log in finished sub test with chatty",
		ok:     false,
		chatty: true,
		output: `
		--- FAIL: log in finished sub test with chatty (N.NNs)`,
		maxPar: 1,
		f: func(t *T) {
			ch := make(chan bool)
			t.Run("sub", func(t2 *T) {
				go func() {
					<-ch
					t2.Log("message1")
					ch <- true
				}()
			})
			t.Log("message2")
			ch <- true
			<-ch
			t.Errorf("error")
		},
	}, {
		// If a subtest panics we should run cleanups.
		desc:   "cleanup when subtest panics",
		ok:     false,
		chatty: false,
		output: `
--- FAIL: cleanup when subtest panics (N.NNs)
    --- FAIL: cleanup when subtest panics/sub (N.NNs)
    sub_test.go:NNN: running cleanup`,
		f: func(t *T) {
			t.Cleanup(func() { t.Log("running cleanup") })
			t.Run("sub", func(t2 *T) {
				t2.FailNow()
			})
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *T) {
			tstate := newTestState(tc.maxPar, allMatcher())
			buf := &strings.Builder{}
			root := &T{
				common: common{
					signal:  make(chan bool),
					barrier: make(chan bool),
					name:    "",
					w:       buf,
				},
				tstate: tstate,
			}
			if tc.chatty {
				root.chatty = newChattyPrinter(root.w)
				root.chatty.json = tc.json
			}
			ok := root.Run(tc.desc, tc.f)
			tstate.release()

			if ok != tc.ok {
				t.Errorf("%s:ok: got %v; want %v", tc.desc, ok, tc.ok)
			}
			if ok != !root.Failed() {
				t.Errorf("%s:root failed: got %v; want %v", tc.desc, !ok, root.Failed())
			}
			if tstate.running != 0 || tstate.numWaiting != 0 {
				t.Errorf("%s:running and waiting non-zero: got %d and %d", tc.desc, tstate.running, tstate.numWaiting)
			}
			got := strings.TrimSpace(buf.String())
			want := strings.TrimSpace(tc.output)
			re := makeRegexp(want)
			if ok, err := regexp.MatchString(re, got); !ok || err != nil {
				t.Errorf("%s:output:\ngot:\n%s\nwant:\n%s", tc.desc, got, want)
			}
		})
	}
}

func TestBRun(t *T) {
	work := func(b *B) {
		for i := 0; i < b.N; i++ {
			time.Sleep(time.Nanosecond)
		}
	}
	testCases := []struct {
		desc   string
		failed bool
		chatty bool
		output string
		f      func(*B)
	}{{
		desc: "simulate sequential run of subbenchmarks.",
		f: func(b *B) {
			b.Run("", func(b *B) { work(b) })
			time1 := b.result.NsPerOp()
			b.Run("", func(b *B) { work(b) })
			time2 := b.result.NsPerOp()
			if time1 >= time2 {
				t.Errorf("no time spent in benchmark t1 >= t2 (%d >= %d)", time1, time2)
			}
		},
	}, {
		desc: "bytes set by all benchmarks",
		f: func(b *B) {
			b.Run("", func(b *B) { b.SetBytes(10); work(b) })
			b.Run("", func(b *B) { b.SetBytes(10); work(b) })
			if b.result.Bytes != 20 {
				t.Errorf("bytes: got: %d; want 20", b.result.Bytes)
			}
		},
	}, {
		desc: "bytes set by some benchmarks",
		// In this case the bytes result is meaningless, so it must be 0.
		f: func(b *B) {
			b.Run("", func(b *B) { b.SetBytes(10); work(b) })
			b.Run("", func(b *B) { work(b) })
			b.Run("", func(b *B) { b.SetBytes(10); work(b) })
			if b.result.Bytes != 0 {
				t.Errorf("bytes: got: %d; want 0", b.result.Bytes)
			}
		},
	}, {
		desc:   "failure carried over to root",
		failed: true,
		output: "--- FAIL: root",
		f:      func(b *B) { b.Fail() },
	}, {
		desc:   "skipping without message, chatty",
		chatty: true,
		output: "--- SKIP: root",
		f:      func(b *B) { b.SkipNow() },
	}, {
		desc:   "chatty with recursion",
		chatty: true,
		f: func(b *B) {
			b.Run("", func(b *B) {
				b.Run("", func(b *B) {})
			})
		},
	}, {
		desc: "skipping without message, not chatty",
		f:    func(b *B) { b.SkipNow() },
	}, {
		desc:   "skipping after error",
		failed: true,
		output: `
--- FAIL: root
    sub_test.go:NNN: an error
    sub_test.go:NNN: skipped`,
		f: func(b *B) {
			b.Error("an error")
			b.Skip("skipped")
		},
	}, {
		desc: "memory allocation",
		f: func(b *B) {
			const bufSize = 256
			alloc := func(b *B) {
				var buf [bufSize]byte
				for i := 0; i < b.N; i++ {
					_ = append([]byte(nil), buf[:]...)
				}
			}
			b.Run("", func(b *B) {
				alloc(b)
				b.ReportAllocs()
			})
			b.Run("", func(b *B) {
				alloc(b)
				b.ReportAllocs()
			})
			// runtime.MemStats sometimes reports more allocations than the
			// benchmark is responsible for. Luckily the point of this test is
			// to ensure that the results are not underreported, so we can
			// simply verify the lower bound.
			if got := b.result.MemAllocs; got < 2 {
				t.Errorf("MemAllocs was %v; want 2", got)
			}
			if got := b.result.MemBytes; got < 2*bufSize {
				t.Errorf("MemBytes was %v; want %v", got, 2*bufSize)
			}
		},
	}, {
		desc: "cleanup is called",
		f: func(b *B) {
			var calls, cleanups, innerCalls, innerCleanups int
			b.Run("", func(b *B) {
				calls++
				b.Cleanup(func() {
					cleanups++
				})
				b.Run("", func(b *B) {
					b.Cleanup(func() {
						innerCleanups++
					})
					innerCalls++
				})
				work(b)
			})
			if calls == 0 || calls != cleanups {
				t.Errorf("mismatched cleanups; got %d want %d", cleanups, calls)
			}
			if innerCalls == 0 || innerCalls != innerCleanups {
				t.Errorf("mismatched cleanups; got %d want %d", cleanups, calls)
			}
		},
	}, {
		desc:   "cleanup is called on failure",
		failed: true,
		f: func(b *B) {
			var calls, cleanups int
			b.Run("", func(b *B) {
				calls++
				b.Cleanup(func() {
					cleanups++
				})
				b.Fatalf("failure")
			})
			if calls == 0 || calls != cleanups {
				t.Errorf("mismatched cleanups; got %d want %d", cleanups, calls)
			}
		},
	}}
	hideStdoutForTesting = true
	defer func() {
		hideStdoutForTesting = false
	}()
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *T) {
			var ok bool
			buf := &strings.Builder{}
			// This is almost like the Benchmark function, except that we override
			// the benchtime and catch the failure result of the subbenchmark.
			root := &B{
				common: common{
					signal: make(chan bool),
					name:   "root",
					w:      buf,
				},
				benchFunc: func(b *B) { ok = b.Run("test", tc.f) }, // Use Run to catch failure.
				benchTime: durationOrCountFlag{d: 1 * time.Microsecond},
			}
			if tc.chatty {
				root.chatty = newChattyPrinter(root.w)
			}
			root.runN(1)
			if ok != !tc.failed {
				t.Errorf("%s:ok: got %v; want %v", tc.desc, ok, !tc.failed)
			}
			if !ok != root.Failed() {
				t.Errorf("%s:root failed: got %v; want %v", tc.desc, !ok, root.Failed())
			}
			// All tests are run as subtests
			if root.result.N != 1 {
				t.Errorf("%s: N for parent benchmark was %d; want 1", tc.desc, root.result.N)
			}
			got := strings.TrimSpace(buf.String())
			want := strings.TrimSpace(tc.output)
			re := makeRegexp(want)
			if ok, err := regexp.MatchString(re, got); !ok || err != nil {
				t.Errorf("%s:output:\ngot:\n%s\nwant:\n%s", tc.desc, got, want)
			}
		})
	}
}

func makeRegexp(s string) string {
	s = regexp.QuoteMeta(s)
	s = strings.ReplaceAll(s, "^V", "\x16")
	s = strings.ReplaceAll(s, ":NNN:", `:\d\d\d\d?:`)
	s = strings.ReplaceAll(s, "N\\.NNs", `\d*\.\d*s`)
	return s
}

func TestBenchmarkOutput(t *T) {
	// Ensure Benchmark initialized common.w by invoking it with an error and
	// normal case.
	Benchmark(func(b *B) { b.Error("do not print this output") })
	Benchmark(func(b *B) {})
}

func TestBenchmarkStartsFrom1(t *T) {
	var first = true
	Benchmark(func(b *B) {
		if first && b.N != 1 {
			panic(fmt.Sprintf("Benchmark() first N=%v; want 1", b.N))
		}
		first = false
	})
}

func TestBenchmarkReadMemStatsBeforeFirstRun(t *T) {
	var first = true
	Benchmark(func(b *B) {
		if first && (b.startAllocs == 0 || b.startBytes == 0) {
			panic("ReadMemStats not called before first run")
		}
		first = false
	})
}

type funcWriter struct {
	write func([]byte) (int, error)
}

func (fw *funcWriter) Write(b []byte) (int, error) {
	return fw.write(b)
}

func TestRacyOutput(t *T) {
	var runs int32  // The number of running Writes
	var races int32 // Incremented for each race detected
	raceDetector := func(b []byte) (int, error) {
		// Check if some other goroutine is concurrently calling Write.
		if atomic.LoadInt32(&runs) > 0 {
			atomic.AddInt32(&races, 1) // Race detected!
		}
		atomic.AddInt32(&runs, 1)
		defer atomic.AddInt32(&runs, -1)
		runtime.Gosched() // Increase probability of a race
		return len(b), nil
	}

	root := &T{
		common: common{w: &funcWriter{raceDetector}},
		tstate: newTestState(1, allMatcher()),
	}
	root.chatty = newChattyPrinter(root.w)
	root.Run("", func(t *T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				t.Run(fmt.Sprint(i), func(t *T) {
					t.Logf("testing run %d", i)
				})
			}(i)
		}
		wg.Wait()
	})

	if races > 0 {
		t.Errorf("detected %d racy Writes", races)
	}
}

// The late log message did not include the test name.  Issue 29388.
func TestLogAfterComplete(t *T) {
	tstate := newTestState(1, allMatcher())
	var buf bytes.Buffer
	t1 := &T{
		common: common{
			// Use a buffered channel so that tRunner can write
			// to it although nothing is reading from it.
			signal: make(chan bool, 1),
			w:      &buf,
		},
		tstate: tstate,
	}

	c1 := make(chan bool)
	c2 := make(chan string)
	tRunner(t1, func(t *T) {
		t.Run("TestLateLog", func(t *T) {
			go func() {
				defer close(c2)
				defer func() {
					p := recover()
					if p == nil {
						c2 <- "subtest did not panic"
						return
					}
					s, ok := p.(string)
					if !ok {
						c2 <- fmt.Sprintf("subtest panic with unexpected value %v", p)
						return
					}
					const want = "Log in goroutine after TestLateLog has completed: log after test"
					if !strings.Contains(s, want) {
						c2 <- fmt.Sprintf("subtest panic %q does not contain %q", s, want)
					}
				}()

				<-c1
				t.Log("log after test")
			}()
		})
	})
	close(c1)

	if s := <-c2; s != "" {
		t.Error(s)
	}
}

func TestBenchmark(t *T) {
	if Short() {
		t.Skip("skipping in short mode")
	}
	res := Benchmark(func(b *B) {
		for i := 0; i < 5; i++ {
			b.Run("", func(b *B) {
				for i := 0; i < b.N; i++ {
					time.Sleep(time.Millisecond)
				}
			})
		}
	})
	if res.NsPerOp() < 4000000 {
		t.Errorf("want >5ms; got %v", time.Duration(res.NsPerOp()))
	}
}

func TestCleanup(t *T) {
	var cleanups []int
	t.Run("test", func(t *T) {
		t.Cleanup(func() { cleanups = append(cleanups, 1) })
		t.Cleanup(func() { cleanups = append(cleanups, 2) })
	})
	if got, want := cleanups, []int{2, 1}; !slices.Equal(got, want) {
		t.Errorf("unexpected cleanup record; got %v want %v", got, want)
	}
}

func TestConcurrentCleanup(t *T) {
	cleanups := 0
	t.Run("test", func(t *T) {
		var wg sync.WaitGroup
		wg.Add(2)
		for i := 0; i < 2; i++ {
			i := i
			go func() {
				t.Cleanup(func() {
					// Although the calls to Cleanup are concurrent, the functions passed
					// to Cleanup should be called sequentially, in some nondeterministic
					// order based on when the Cleanup calls happened to be scheduled.
					// So these assignments to the cleanups variable should not race.
					cleanups |= 1 << i
				})
				wg.Done()
			}()
		}
		wg.Wait()
	})
	if cleanups != 1|2 {
		t.Errorf("unexpected cleanup; got %d want 3", cleanups)
	}
}

func TestCleanupCalledEvenAfterGoexit(t *T) {
	cleanups := 0
	t.Run("test", func(t *T) {
		t.Cleanup(func() {
			cleanups++
		})
		t.Cleanup(func() {
			runtime.Goexit()
		})
	})
	if cleanups != 1 {
		t.Errorf("unexpected cleanup count; got %d want 1", cleanups)
	}
}

func TestRunCleanup(t *T) {
	outerCleanup := 0
	innerCleanup := 0
	t.Run("test", func(t *T) {
		t.Cleanup(func() { outerCleanup++ })
		t.Run("x", func(t *T) {
			t.Cleanup(func() { innerCleanup++ })
		})
	})
	if innerCleanup != 1 {
		t.Errorf("unexpected inner cleanup count; got %d want 1", innerCleanup)
	}
	if outerCleanup != 1 {
		t.Errorf("unexpected outer cleanup count; got %d want 0", outerCleanup)
	}
}

func TestCleanupParallelSubtests(t *T) {
	ranCleanup := 0
	t.Run("test", func(t *T) {
		t.Cleanup(func() { ranCleanup++ })
		t.Run("x", func(t *T) {
			t.Parallel()
			if ranCleanup > 0 {
				t.Error("outer cleanup ran before parallel subtest")
			}
		})
	})
	if ranCleanup != 1 {
		t.Errorf("unexpected cleanup count; got %d want 1", ranCleanup)
	}
}

func TestNestedCleanup(t *T) {
	ranCleanup := 0
	t.Run("test", func(t *T) {
		t.Cleanup(func() {
			if ranCleanup != 2 {
				t.Errorf("unexpected cleanup count in first cleanup: got %d want 2", ranCleanup)
			}
			ranCleanup++
		})
		t.Cleanup(func() {
			if ranCleanup != 0 {
				t.Errorf("unexpected cleanup count in second cleanup: got %d want 0", ranCleanup)
			}
			ranCleanup++
			t.Cleanup(func() {
				if ranCleanup != 1 {
					t.Errorf("unexpected cleanup count in nested cleanup: got %d want 1", ranCleanup)
				}
				ranCleanup++
			})
		})
	})
	if ranCleanup != 3 {
		t.Errorf("unexpected cleanup count: got %d want 3", ranCleanup)
	}
}

"""



```