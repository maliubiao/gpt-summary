Response:
Let's break down the thought process for analyzing this Go code and generating the response.

**1. Initial Understanding & Purpose:**

The first step is to recognize the file path: `go/src/runtime/stack_test.go`. This immediately tells us it's part of the Go runtime and is specifically for *testing* the stack functionality. The package name `runtime_test` reinforces this. The initial comments about copyright and license are standard boilerplate and can be noted but aren't crucial for understanding the functionality.

**2. Identifying Key Test Functions:**

Next, I'd scan the code for functions starting with `Test`. These are the core test cases. Listing them out provides a high-level overview of what aspects of the stack are being tested:

* `TestStackMem`:  Memory usage related to stacks.
* `TestStackGrowth`:  How stacks grow.
* `TestStackGrowthCallback`: Stack growth in specific scenarios (channel, map, goroutine creation).
* `TestDeferPtrs`: How deferred function arguments are handled during stack growth.
* `TestDeferPtrsGoexit`, `TestDeferPtrsPanic`: Similar to `TestDeferPtrs` but with `Goexit` and `panic`.
* `TestDeferLeafSigpanic`:  Interaction of `defer` with `sigpanic` in leaf functions.
* `TestPanicUseStack`: How `panic` structures are updated during stack growth in deferred functions.
* `TestPanicFar`: Panic handling with a large stack.
* `TestStackCache`: Testing the stack cache mechanism.
* `TestStackOutput`, `TestStackAllOutput`: Output of stack information.
* `TestStackPanic`:  Panic behavior during stack copying.
* `TestStackWrapperCaller`, `TestStackWrapperCallers`, `TestStackWrapperStack`, `TestStackWrapperStackInlinePanic`, `TestStackWrapperStackPanic`, `TestCallersFromWrapper`: Testing interactions with method wrappers and stack traces.
* `TestTracebackSystemstack`, `TestTracebackAncestors`: Testing stack trace functionality, particularly with system stacks and ancestor information.
* `TestDeferLiveness`, `TestDeferHeapAndStack`: Testing the liveness of variables in `defer` closures and different allocation strategies for `defer`.
* `TestFramePointerAdjust`, `TestSystemstackFramePointerAdjust`: Testing frame pointer adjustments during stack operations.

**3. Grouping and Categorizing Functionality:**

Looking at the test names, common themes emerge. I'd group them logically:

* **Stack Growth & Memory:** `TestStackMem`, `TestStackGrowth`, `TestStackGrowthCallback`
* **Deferred Functions:** `TestDeferPtrs`, `TestDeferPtrsGoexit`, `TestDeferPtrsPanic`, `TestDeferLeafSigpanic`, `TestDeferLiveness`, `TestDeferHeapAndStack`
* **Panic & Recover:** `TestPanicUseStack`, `TestPanicFar`, `TestStackPanic`
* **Stack Information/Tracing:** `TestStackOutput`, `TestStackAllOutput`, `TestStackWrapperCaller`, `TestStackWrapperCallers`, `TestStackWrapperStack`, `TestStackWrapperStackInlinePanic`, `TestStackWrapperStackPanic`, `TestCallersFromWrapper`, `TestTracebackSystemstack`, `TestTracebackAncestors`
* **Stack Caching:** `TestStackCache`
* **Frame Pointers:** `TestFramePointerAdjust`, `TestSystemstackFramePointerAdjust`
* **Benchmarking:**  Functions starting with `Benchmark`. While not directly testing functionality, they provide performance metrics.

**4. Deeper Dive into Key Functions (and Code Inference):**

Now, I'd pick a few important test functions and analyze their code to understand *how* they test the functionality.

* **`TestStackMem`:** This test uses goroutines and recursion with a large array on the stack to measure stack memory consumption. The `MemStats` struct and its fields like `StackSys` and `StackInuse` are key to understanding what's being measured. The `GOMAXPROCS` manipulation hints at testing multi-threading scenarios.

* **`TestStackGrowth`:** This test runs `growStack` in different contexts (normal goroutine, locked goroutine, finalizer) to ensure stack growth works correctly in various situations. The use of `LockOSThread` and `SetFinalizer` are important details.

* **`TestDeferPtrs`:** This test sets a value in a variable and then uses a `defer` statement to modify it again. The key is understanding that if stack copying isn't done correctly, the `defer` might operate on an old memory location, and the final check would fail.

* **`TestStackOutput` and `TestStackAllOutput`:** These are straightforward tests of the `Stack` function, checking the format of the output.

* **`TestTracebackAncestors`:**  This test uses `runTestProg` which suggests it's running an external program with specific `GODEBUG` settings. The `tracebackancestors` setting is a clear indicator of the feature being tested. The regular expression matching confirms the output format.

**5. Inferring Go Language Features:**

Based on the tests, I can infer the Go language features being tested:

* **Goroutine Stacks:** The entire file is about testing stack behavior, which is fundamental to goroutines.
* **Stack Growth:** Several tests explicitly check how stacks grow dynamically.
* **`defer` Statement:**  A significant portion tests the correct execution and pointer adjustments within `defer`red functions.
* **`panic` and `recover`:** Tests verify the mechanisms for handling panics and recovering from them.
* **Finalizers:** `TestStackGrowth` includes a test in a finalizer, indicating testing of garbage collection interaction.
* **`runtime.Stack` and `runtime.Callers`:** These functions are directly tested for retrieving stack information.
* **Stack Caching:** `TestStackCache` explicitly targets this optimization.
* **Frame Pointers (on supported architectures):** The `TestFramePointerAdjust` functions indicate testing of frame pointer management.
* **`GODEBUG` settings:** The use of `GODEBUG=tracebackancestors` demonstrates the ability to influence runtime behavior for debugging and testing.

**6. Code Examples (If Applicable):**

For illustrating functionality, I'd choose a simpler test like `TestStackOutput` or the core concept of stack growth. The `growStack` function itself provides a good example of recursive function calls leading to stack growth.

**7. Command Line Arguments:**

The `TestTracebackAncestors` example provides a direct use case of the `GODEBUG` environment variable. I'd explain that it's used to control runtime debugging features.

**8. Common Mistakes:**

Thinking about how developers might misuse stack-related features, the interaction of `defer` and closures, especially with shared variables, comes to mind. This can lead to unexpected behavior if not understood properly.

**9. Structuring the Response:**

Finally, I'd organize the information logically using headings and bullet points for clarity, addressing each part of the prompt. Using code snippets and clear explanations is crucial. The tone should be informative and helpful.
这段代码是 Go 语言运行时（runtime）库中关于栈（stack）功能的测试代码。它主要用于测试 Go 语言在各种场景下对 goroutine 栈的管理，包括栈的分配、增长、收缩、拷贝以及与 `defer` 和 `panic/recover` 机制的交互。

以下是它的主要功能和相关的 Go 语言功能实现：

**1. 栈内存分配和管理 (Stack Memory Allocation and Management):**

* **功能:** 测试 goroutine 栈的内存使用情况，包括初始分配、增长和缓存行为。
* **相关 Go 语言功能:**
    * **Goroutine 栈:** Go 语言的每个 goroutine 都有自己的栈空间，用于存储函数调用信息、局部变量等。
    * **栈段缓存 (Stack Segment Cache):**  Go 运行时会缓存已释放的栈段，以便后续 goroutine 可以重用，减少内存分配的开销。
* **代码示例 (基于 `TestStackMem`):**
    ```go
    package main

    import (
        "fmt"
        "runtime"
        "time"
    )

    func recursiveFunc(k int) {
        if k == 0 {
            time.Sleep(time.Millisecond) // 模拟一些工作
            return
        }
        var a [1024]byte // 在栈上分配一个较大的数组
        recursiveFunc(k - 1)
        _ = a // 使用 a，防止编译器优化掉
    }

    func main() {
        runtime.GOMAXPROCS(1) // 设置单核运行，简化测试
        var memStatsBefore runtime.MemStats
        runtime.ReadMemStats(&memStatsBefore)

        const numGoroutines = 10
        done := make(chan bool)
        for i := 0; i < numGoroutines; i++ {
            go func() {
                recursiveFunc(128) // 深度递归
                done <- true
            }()
        }
        for i := 0; i < numGoroutines; i++ {
            <-done
        }

        var memStatsAfter runtime.MemStats
        runtime.ReadMemStats(&memStatsAfter)

        stackSysUsed := memStatsAfter.StackSys - memStatsBefore.StackSys
        fmt.Printf("栈内存使用量: %d 字节\n", stackSysUsed)
    }
    ```
    **假设输入:**  运行上述代码。
    **预期输出:**  会打印出 `栈内存使用量`，其数值会反映出 goroutine 栈分配的内存大小。

**2. 栈增长 (Stack Growth):**

* **功能:** 测试 goroutine 在运行过程中栈空间不足时自动增长的能力，包括在不同上下文 (普通 goroutine, 锁定线程的 goroutine, finalizer 中) 的增长。
* **相关 Go 语言功能:**
    * **自动栈增长:** Go 运行时会监控 goroutine 栈的使用情况，当栈即将溢出时，会自动分配更大的栈空间，并将旧栈的内容拷贝到新栈。
    * **`runtime.LockOSThread()` 和 `runtime.UnlockOSThread()`:**  用于将 goroutine 绑定到特定的操作系统线程。
    * **Finalizer (`runtime.SetFinalizer`)**:  与垃圾回收器关联的函数，在对象即将被回收时执行。
* **代码示例 (基于 `TestStackGrowth` 中的 `growStack` 函数):**
    ```go
    package main

    import (
        "fmt"
        "runtime"
        "sync/atomic"
    )

    func growStackIter(p *int, n int) {
        if n == 0 {
            *p = n + 1
            runtime.GC() // 手动触发 GC
            return
        }
        *p = n + 1
        x := 0
        growStackIter(&x, n-1)
        if x != n {
            panic("stack is corrupted")
        }
    }

    func growStack() {
        n := 1 << 10 // 1024
        for i := 0; i < n; i++ {
            x := 0
            growStackIter(&x, i)
            if x != i+1 {
                panic("stack is corrupted")
            }
        }
        runtime.GC()
    }

    func main() {
        growStack()
        fmt.Println("栈增长测试完成")
    }
    ```
    **假设输入:** 运行上述代码。
    **预期输出:**  程序正常运行并打印 "栈增长测试完成"，表明在深度递归过程中栈可以正常增长。

**3. `defer` 语句与栈拷贝 (Defer Statement and Stack Copying):**

* **功能:** 测试 `defer` 语句中引用的变量在栈拷贝时指针是否被正确调整，确保 `defer` 函数操作的是正确的内存地址。
* **相关 Go 语言功能:**
    * **`defer` 语句:** 用于在函数执行即将结束时执行某个函数调用，常用于资源清理。
    * **栈拷贝:** 当 goroutine 的栈增长时，需要将旧栈的内容（包括 `defer` 语句中捕获的变量地址）拷贝到新栈。
* **代码示例 (基于 `TestDeferPtrs`):**
    ```go
    package main

    import "fmt"

    func set(p *int, x int) {
        *p = x
    }

    func main() {
        var y int
        defer func() {
            if y != 42 {
                fmt.Println("defer 的栈引用未被正确调整")
            } else {
                fmt.Println("defer 的栈引用被正确调整")
            }
        }()
        defer set(&y, 42)
        // 这里可以添加一些导致栈增长的操作，例如深度递归
        fmt.Println("主函数执行完毕")
    }
    ```
    **假设输入:** 运行上述代码。
    **预期输出:**  会打印 "defer 的栈引用被正确调整"，即使在主函数执行过程中可能发生栈增长。

**4. `panic` 和 `recover` 与栈 (Panic and Recover with Stack):**

* **功能:** 测试 `panic` 发生时栈信息的捕获和 `recover` 恢复时的栈状态，以及在 `defer` 中使用 `recover` 的行为。
* **相关 Go 语言功能:**
    * **`panic`:** 用于报告运行时错误，中断当前 goroutine 的正常执行。
    * **`recover`:** 用于捕获 `panic`，阻止程序崩溃，通常在 `defer` 函数中使用。
* **代码示例 (基于 `TestPanicUseStack`):**
    ```go
    package main

    import (
        "fmt"
        "runtime"
    )

    func innerPanic() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Println("内部 panic 被捕获:", r)
                pc := make([]uintptr, 10)
                n := runtime.Callers(0, pc)
                frames := runtime.CallersFrames(pc[:n])
                for {
                    frame, more := frames.Next()
                    fmt.Printf("- %s:%d %s\n", frame.File, frame.Line, frame.Function)
                    if !more {
                        break
                    }
                }
            }
        }()
        panic("内部错误")
    }

    func outerFunc() {
        innerPanic()
    }

    func main() {
        defer func() {
            if r := recover(); r != nil {
                fmt.Println("外部 panic 被捕获:", r)
            }
        }()
        outerFunc()
        fmt.Println("程序继续执行") // 如果 recover 成功，这行会被执行
    }
    ```
    **假设输入:** 运行上述代码。
    **预期输出:**  会打印出内部 panic 被捕获的信息，以及 panic 发生时的函数调用栈信息。

**5. 获取栈信息 (Getting Stack Information):**

* **功能:** 测试 `runtime.Stack()` 和 `runtime.Callers()` 等函数获取当前或所有 goroutine 的栈信息的功能。
* **相关 Go 语言功能:**
    * **`runtime.Stack(buf []byte, all bool) int`:**  将当前 goroutine 或所有 goroutine 的栈信息格式化到 `buf` 中。
    * **`runtime.Callers(skip int, pc []uintptr) int`:**  获取调用栈的程序计数器 (PC) 值。
    * **`runtime.CallersFrames(callers []uintptr) *runtime.Frames`:** 将 `Callers` 返回的 PC 值转换为 `runtime.Frame` 结构体，包含文件名、行号、函数名等信息。
* **代码示例 (基于 `TestStackOutput`):**
    ```go
    package main

    import (
        "fmt"
        "runtime"
        "strings"
    )

    func main() {
        buf := make([]byte, 1024)
        n := runtime.Stack(buf, false)
        stackInfo := string(buf[:n])
        if strings.HasPrefix(stackInfo, "goroutine ") {
            fmt.Println("获取栈信息成功，以 'goroutine ' 开头")
            fmt.Println(stackInfo)
        } else {
            fmt.Println("获取栈信息失败")
        }
    }
    ```
    **假设输入:** 运行上述代码。
    **预期输出:**  会打印出当前 goroutine 的栈信息，并以 "goroutine " 开头。

**6. 栈缓存 (Stack Cache):**

* **功能:** 测试 goroutine 退出后其栈内存是否被缓存，以便后续 goroutine 可以重用，提高性能。
* **相关 Go 语言功能:**  Go 运行时中的栈分配器和垃圾回收器共同管理栈缓存。
* **代码示例:** `TestStackCache` 函数通过创建和销毁大量 goroutine 来测试栈缓存的效率。

**7. 方法包装器 (Method Wrappers) 和栈信息:**

* **功能:** 测试方法包装器（method wrappers，Go 编译器为了实现方法调用而生成的中间函数）是否会影响栈信息的输出，确保栈追踪的准确性。
* **相关 Go 语言功能:**  Go 的方法调用，特别是接口方法和值方法，可能涉及编译器生成的包装器。
* **代码示例:** `TestStackWrapperCaller` 等一系列 `TestStackWrapper...` 函数用于测试这种情况。

**8. 系统栈追踪 (System Stack Traceback):**

* **功能:** 测试追踪系统栈（用于执行 runtime 代码的特殊栈）的能力。
* **相关 Go 语言功能:**  `runtime.TracebackSystemstack` 函数。
* **代码示例:** `TestTracebackSystemstack` 函数测试了这个功能。

**9. 追踪祖先 Goroutine (Traceback Ancestors):**

* **功能:**  测试获取创建当前 goroutine 的祖先 goroutine 的栈信息。
* **相关 Go 语言功能:**  这通常涉及到 Go 运行时内部的 goroutine 管理和调度机制，以及 `GODEBUG` 环境变量中的 `tracebackancestors` 选项。
* **代码示例:** `TestTracebackAncestors` 函数通过运行一个外部程序并设置 `GODEBUG` 来测试。

**10. `defer` 闭包的活性 (Defer Closure Liveness):**

* **功能:**  测试在栈扫描时，`defer` 闭包中引用的变量是否被正确标记为活跃，防止被垃圾回收器错误回收。
* **相关 Go 语言功能:**  Go 垃圾回收器的栈扫描机制。
* **代码示例:** `TestDeferLiveness` 函数通过运行一个外部程序并设置 `GODEBUG` 来测试。

**11. `defer` 在堆和栈上的分配 (Defer Allocation on Heap and Stack):**

* **功能:**  测试 `defer` 调用的分配位置（栈上或堆上），以及对性能的影响。
* **相关 Go 语言功能:**  Go 编译器会根据 `defer` 调用的上下文决定将其分配在栈上还是堆上。
* **代码示例:** `TestDeferHeapAndStack` 函数通过创建不同数量的 `defer` 调用来测试。

**12. 帧指针调整 (Frame Pointer Adjust):**

* **功能:**  测试在栈增长和收缩后，帧指针是否被正确调整。帧指针用于在函数调用栈中定位函数的局部变量。
* **相关 Go 语言功能:**  与编译器和体系结构相关的栈帧布局。
* **代码示例:** `TestFramePointerAdjust` 和 `TestSystemstackFramePointerAdjust` 函数用于测试。

**涉及代码推理和假设的输入与输出:**

上面的代码示例中已经包含了基于测试代码的功能推理和假设的输入输出。

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。但是，它使用了一些环境变量，例如在 `TestTracebackAncestors` 和 `TestDeferLiveness` 中使用了 `GODEBUG` 环境变量来控制 runtime 的调试行为。

**使用者易犯错的点 (举例):**

* **在 `defer` 闭包中错误地捕获变量:**  如果 `defer` 闭包中直接引用循环变量，由于闭包是延迟执行的，可能会导致 `defer` 执行时访问到循环结束后的变量值。
    ```go
    package main

    import "fmt"

    func main() {
        for i := 0; i < 5; i++ {
            defer func() {
                fmt.Println(i) // 错误地捕获了循环变量 i
            }()
        }
    }
    ```
    **输出 (易错):**
    ```
    5
    5
    5
    5
    5
    ```
    **正确做法是传递变量值:**
    ```go
    package main

    import "fmt"

    func main() {
        for i := 0; i < 5; i++ {
            defer func(n int) {
                fmt.Println(n)
            }(i) // 将 i 的值传递给闭包
        }
    }
    ```
    **输出 (正确):**
    ```
    4
    3
    2
    1
    0
    ```

总而言之，这段测试代码覆盖了 Go 语言运行时系统中栈管理的各个重要方面，确保了 goroutine 栈的正确分配、增长、收缩以及与语言特性的良好集成。理解这些测试用例有助于深入了解 Go 语言的底层机制。

### 提示词
```
这是路径为go/src/runtime/stack_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"internal/testenv"
	"reflect"
	"regexp"
	. "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe" // for go:linkname
)

// TestStackMem measures per-thread stack segment cache behavior.
// The test consumed up to 500MB in the past.
func TestStackMem(t *testing.T) {
	const (
		BatchSize      = 32
		BatchCount     = 256
		ArraySize      = 1024
		RecursionDepth = 128
	)
	if testing.Short() {
		return
	}
	defer GOMAXPROCS(GOMAXPROCS(BatchSize))
	s0 := new(MemStats)
	ReadMemStats(s0)
	for b := 0; b < BatchCount; b++ {
		c := make(chan bool, BatchSize)
		for i := 0; i < BatchSize; i++ {
			go func() {
				var f func(k int, a [ArraySize]byte)
				f = func(k int, a [ArraySize]byte) {
					if k == 0 {
						time.Sleep(time.Millisecond)
						return
					}
					f(k-1, a)
				}
				f(RecursionDepth, [ArraySize]byte{})
				c <- true
			}()
		}
		for i := 0; i < BatchSize; i++ {
			<-c
		}

		// The goroutines have signaled via c that they are ready to exit.
		// Give them a chance to exit by sleeping. If we don't wait, we
		// might not reuse them on the next batch.
		time.Sleep(10 * time.Millisecond)
	}
	s1 := new(MemStats)
	ReadMemStats(s1)
	consumed := int64(s1.StackSys - s0.StackSys)
	t.Logf("Consumed %vMB for stack mem", consumed>>20)
	estimate := int64(8 * BatchSize * ArraySize * RecursionDepth) // 8 is to reduce flakiness.
	if consumed > estimate {
		t.Fatalf("Stack mem: want %v, got %v", estimate, consumed)
	}
	// Due to broken stack memory accounting (https://golang.org/issue/7468),
	// StackInuse can decrease during function execution, so we cast the values to int64.
	inuse := int64(s1.StackInuse) - int64(s0.StackInuse)
	t.Logf("Inuse %vMB for stack mem", inuse>>20)
	if inuse > 4<<20 {
		t.Fatalf("Stack inuse: want %v, got %v", 4<<20, inuse)
	}
}

// Test stack growing in different contexts.
func TestStackGrowth(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}

	var wg sync.WaitGroup

	// in a normal goroutine
	var growDuration time.Duration // For debugging failures
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		growStack(nil)
		growDuration = time.Since(start)
	}()
	wg.Wait()
	t.Log("first growStack took", growDuration)

	// in locked goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		LockOSThread()
		growStack(nil)
		UnlockOSThread()
	}()
	wg.Wait()

	// in finalizer
	var finalizerStart time.Time
	var started atomic.Bool
	var progress atomic.Uint32
	wg.Add(1)
	s := new(string) // Must be of a type that avoids the tiny allocator, or else the finalizer might not run.
	SetFinalizer(s, func(ss *string) {
		defer wg.Done()
		finalizerStart = time.Now()
		started.Store(true)
		growStack(&progress)
	})
	setFinalizerTime := time.Now()
	s = nil

	if d, ok := t.Deadline(); ok {
		// Pad the timeout by an arbitrary 5% to give the AfterFunc time to run.
		timeout := time.Until(d) * 19 / 20
		timer := time.AfterFunc(timeout, func() {
			// Panic — instead of calling t.Error and returning from the test — so
			// that we get a useful goroutine dump if the test times out, especially
			// if GOTRACEBACK=system or GOTRACEBACK=crash is set.
			if !started.Load() {
				panic("finalizer did not start")
			} else {
				panic(fmt.Sprintf("finalizer started %s ago (%s after registration) and ran %d iterations, but did not return", time.Since(finalizerStart), finalizerStart.Sub(setFinalizerTime), progress.Load()))
			}
		})
		defer timer.Stop()
	}

	GC()
	wg.Wait()
	t.Logf("finalizer started after %s and ran %d iterations in %v", finalizerStart.Sub(setFinalizerTime), progress.Load(), time.Since(finalizerStart))
}

// ... and in init
//func init() {
//	growStack()
//}

func growStack(progress *atomic.Uint32) {
	n := 1 << 10
	if testing.Short() {
		n = 1 << 8
	}
	for i := 0; i < n; i++ {
		x := 0
		growStackIter(&x, i)
		if x != i+1 {
			panic("stack is corrupted")
		}
		if progress != nil {
			progress.Store(uint32(i))
		}
	}
	GC()
}

// This function is not an anonymous func, so that the compiler can do escape
// analysis and place x on stack (and subsequently stack growth update the pointer).
func growStackIter(p *int, n int) {
	if n == 0 {
		*p = n + 1
		GC()
		return
	}
	*p = n + 1
	x := 0
	growStackIter(&x, n-1)
	if x != n {
		panic("stack is corrupted")
	}
}

func TestStackGrowthCallback(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup

	// test stack growth at chan op
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := make(chan int, 1)
		growStackWithCallback(func() {
			c <- 1
			<-c
		})
	}()

	// test stack growth at map op
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := make(map[int]int)
		growStackWithCallback(func() {
			_, _ = m[1]
			m[1] = 1
		})
	}()

	// test stack growth at goroutine creation
	wg.Add(1)
	go func() {
		defer wg.Done()
		growStackWithCallback(func() {
			done := make(chan bool)
			go func() {
				done <- true
			}()
			<-done
		})
	}()
	wg.Wait()
}

func growStackWithCallback(cb func()) {
	var f func(n int)
	f = func(n int) {
		if n == 0 {
			cb()
			return
		}
		f(n - 1)
	}
	for i := 0; i < 1<<10; i++ {
		f(i)
	}
}

// TestDeferPtrs tests the adjustment of Defer's argument pointers (p aka &y)
// during a stack copy.
func set(p *int, x int) {
	*p = x
}
func TestDeferPtrs(t *testing.T) {
	var y int

	defer func() {
		if y != 42 {
			t.Errorf("defer's stack references were not adjusted appropriately")
		}
	}()
	defer set(&y, 42)
	growStack(nil)
}

type bigBuf [4 * 1024]byte

// TestDeferPtrsGoexit is like TestDeferPtrs but exercises the possibility that the
// stack grows as part of starting the deferred function. It calls Goexit at various
// stack depths, forcing the deferred function (with >4kB of args) to be run at
// the bottom of the stack. The goal is to find a stack depth less than 4kB from
// the end of the stack. Each trial runs in a different goroutine so that an earlier
// stack growth does not invalidate a later attempt.
func TestDeferPtrsGoexit(t *testing.T) {
	for i := 0; i < 100; i++ {
		c := make(chan int, 1)
		go testDeferPtrsGoexit(c, i)
		if n := <-c; n != 42 {
			t.Fatalf("defer's stack references were not adjusted appropriately (i=%d n=%d)", i, n)
		}
	}
}

func testDeferPtrsGoexit(c chan int, i int) {
	var y int
	defer func() {
		c <- y
	}()
	defer setBig(&y, 42, bigBuf{})
	useStackAndCall(i, Goexit)
}

func setBig(p *int, x int, b bigBuf) {
	*p = x
}

// TestDeferPtrsPanic is like TestDeferPtrsGoexit, but it's using panic instead
// of Goexit to run the Defers. Those two are different execution paths
// in the runtime.
func TestDeferPtrsPanic(t *testing.T) {
	for i := 0; i < 100; i++ {
		c := make(chan int, 1)
		go testDeferPtrsGoexit(c, i)
		if n := <-c; n != 42 {
			t.Fatalf("defer's stack references were not adjusted appropriately (i=%d n=%d)", i, n)
		}
	}
}

func testDeferPtrsPanic(c chan int, i int) {
	var y int
	defer func() {
		if recover() == nil {
			c <- -1
			return
		}
		c <- y
	}()
	defer setBig(&y, 42, bigBuf{})
	useStackAndCall(i, func() { panic(1) })
}

//go:noinline
func testDeferLeafSigpanic1() {
	// Cause a sigpanic to be injected in this frame.
	//
	// This function has to be declared before
	// TestDeferLeafSigpanic so the runtime will crash if we think
	// this function's continuation PC is in
	// TestDeferLeafSigpanic.
	*(*int)(nil) = 0
}

// TestDeferLeafSigpanic tests defer matching around leaf functions
// that sigpanic. This is tricky because on LR machines the outer
// function and the inner function have the same SP, but it's critical
// that we match up the defer correctly to get the right liveness map.
// See issue #25499.
func TestDeferLeafSigpanic(t *testing.T) {
	// Push a defer that will walk the stack.
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("expected panic from nil pointer")
		}
		GC()
	}()
	// Call a leaf function. We must set up the exact call stack:
	//
	//  deferring function -> leaf function -> sigpanic
	//
	// On LR machines, the leaf function will have the same SP as
	// the SP pushed for the defer frame.
	testDeferLeafSigpanic1()
}

// TestPanicUseStack checks that a chain of Panic structs on the stack are
// updated correctly if the stack grows during the deferred execution that
// happens as a result of the panic.
func TestPanicUseStack(t *testing.T) {
	pc := make([]uintptr, 10000)
	defer func() {
		recover()
		Callers(0, pc) // force stack walk
		useStackAndCall(100, func() {
			defer func() {
				recover()
				Callers(0, pc) // force stack walk
				useStackAndCall(200, func() {
					defer func() {
						recover()
						Callers(0, pc) // force stack walk
					}()
					panic(3)
				})
			}()
			panic(2)
		})
	}()
	panic(1)
}

func TestPanicFar(t *testing.T) {
	var xtree *xtreeNode
	pc := make([]uintptr, 10000)
	defer func() {
		// At this point we created a large stack and unwound
		// it via recovery. Force a stack walk, which will
		// check the stack's consistency.
		Callers(0, pc)
	}()
	defer func() {
		recover()
	}()
	useStackAndCall(100, func() {
		// Kick off the GC and make it do something nontrivial.
		// (This used to force stack barriers to stick around.)
		xtree = makeTree(18)
		// Give the GC time to start scanning stacks.
		time.Sleep(time.Millisecond)
		panic(1)
	})
	_ = xtree
}

type xtreeNode struct {
	l, r *xtreeNode
}

func makeTree(d int) *xtreeNode {
	if d == 0 {
		return new(xtreeNode)
	}
	return &xtreeNode{makeTree(d - 1), makeTree(d - 1)}
}

// use about n KB of stack and call f
func useStackAndCall(n int, f func()) {
	if n == 0 {
		f()
		return
	}
	var b [1024]byte // makes frame about 1KB
	useStackAndCall(n-1+int(b[99]), f)
}

func useStack(n int) {
	useStackAndCall(n, func() {})
}

func growing(c chan int, done chan struct{}) {
	for n := range c {
		useStack(n)
		done <- struct{}{}
	}
	done <- struct{}{}
}

func TestStackCache(t *testing.T) {
	// Allocate a bunch of goroutines and grow their stacks.
	// Repeat a few times to test the stack cache.
	const (
		R = 4
		G = 200
		S = 5
	)
	for i := 0; i < R; i++ {
		var reqchans [G]chan int
		done := make(chan struct{})
		for j := 0; j < G; j++ {
			reqchans[j] = make(chan int)
			go growing(reqchans[j], done)
		}
		for s := 0; s < S; s++ {
			for j := 0; j < G; j++ {
				reqchans[j] <- 1 << uint(s)
			}
			for j := 0; j < G; j++ {
				<-done
			}
		}
		for j := 0; j < G; j++ {
			close(reqchans[j])
		}
		for j := 0; j < G; j++ {
			<-done
		}
	}
}

func TestStackOutput(t *testing.T) {
	b := make([]byte, 1024)
	stk := string(b[:Stack(b, false)])
	if !strings.HasPrefix(stk, "goroutine ") {
		t.Errorf("Stack (len %d):\n%s", len(stk), stk)
		t.Errorf("Stack output should begin with \"goroutine \"")
	}
}

func TestStackAllOutput(t *testing.T) {
	b := make([]byte, 1024)
	stk := string(b[:Stack(b, true)])
	if !strings.HasPrefix(stk, "goroutine ") {
		t.Errorf("Stack (len %d):\n%s", len(stk), stk)
		t.Errorf("Stack output should begin with \"goroutine \"")
	}
}

func TestStackPanic(t *testing.T) {
	// Test that stack copying copies panics correctly. This is difficult
	// to test because it is very unlikely that the stack will be copied
	// in the middle of gopanic. But it can happen.
	// To make this test effective, edit panic.go:gopanic and uncomment
	// the GC() call just before freedefer(d).
	defer func() {
		if x := recover(); x == nil {
			t.Errorf("recover failed")
		}
	}()
	useStack(32)
	panic("test panic")
}

func BenchmarkStackCopyPtr(b *testing.B) {
	c := make(chan bool)
	for i := 0; i < b.N; i++ {
		go func() {
			i := 1000000
			countp(&i)
			c <- true
		}()
		<-c
	}
}

func countp(n *int) {
	if *n == 0 {
		return
	}
	*n--
	countp(n)
}

func BenchmarkStackCopy(b *testing.B) {
	c := make(chan bool)
	for i := 0; i < b.N; i++ {
		go func() {
			count(1000000)
			c <- true
		}()
		<-c
	}
}

func count(n int) int {
	if n == 0 {
		return 0
	}
	return 1 + count(n-1)
}

func BenchmarkStackCopyNoCache(b *testing.B) {
	c := make(chan bool)
	for i := 0; i < b.N; i++ {
		go func() {
			count1(1000000)
			c <- true
		}()
		<-c
	}
}

func count1(n int) int {
	if n <= 0 {
		return 0
	}
	return 1 + count2(n-1)
}

func count2(n int) int  { return 1 + count3(n-1) }
func count3(n int) int  { return 1 + count4(n-1) }
func count4(n int) int  { return 1 + count5(n-1) }
func count5(n int) int  { return 1 + count6(n-1) }
func count6(n int) int  { return 1 + count7(n-1) }
func count7(n int) int  { return 1 + count8(n-1) }
func count8(n int) int  { return 1 + count9(n-1) }
func count9(n int) int  { return 1 + count10(n-1) }
func count10(n int) int { return 1 + count11(n-1) }
func count11(n int) int { return 1 + count12(n-1) }
func count12(n int) int { return 1 + count13(n-1) }
func count13(n int) int { return 1 + count14(n-1) }
func count14(n int) int { return 1 + count15(n-1) }
func count15(n int) int { return 1 + count16(n-1) }
func count16(n int) int { return 1 + count17(n-1) }
func count17(n int) int { return 1 + count18(n-1) }
func count18(n int) int { return 1 + count19(n-1) }
func count19(n int) int { return 1 + count20(n-1) }
func count20(n int) int { return 1 + count21(n-1) }
func count21(n int) int { return 1 + count22(n-1) }
func count22(n int) int { return 1 + count23(n-1) }
func count23(n int) int { return 1 + count1(n-1) }

type stkobjT struct {
	p *stkobjT
	x int64
	y [20]int // consume some stack
}

// Sum creates a linked list of stkobjTs.
func Sum(n int64, p *stkobjT) {
	if n == 0 {
		return
	}
	s := stkobjT{p: p, x: n}
	Sum(n-1, &s)
	p.x += s.x
}

func BenchmarkStackCopyWithStkobj(b *testing.B) {
	c := make(chan bool)
	for i := 0; i < b.N; i++ {
		go func() {
			var s stkobjT
			Sum(100000, &s)
			c <- true
		}()
		<-c
	}
}

func BenchmarkIssue18138(b *testing.B) {
	// Channel with N "can run a goroutine" tokens
	const N = 10
	c := make(chan []byte, N)
	for i := 0; i < N; i++ {
		c <- make([]byte, 1)
	}

	for i := 0; i < b.N; i++ {
		<-c // get token
		go func() {
			useStackPtrs(1000, false) // uses ~1MB max
			m := make([]byte, 8192)   // make GC trigger occasionally
			c <- m                    // return token
		}()
	}
}

func useStackPtrs(n int, b bool) {
	if b {
		// This code contributes to the stack frame size, and hence to the
		// stack copying cost. But since b is always false, it costs no
		// execution time (not even the zeroing of a).
		var a [128]*int // 1KB of pointers
		a[n] = &n
		n = *a[0]
	}
	if n == 0 {
		return
	}
	useStackPtrs(n-1, b)
}

type structWithMethod struct{}

func (s structWithMethod) caller() string {
	_, file, line, ok := Caller(1)
	if !ok {
		panic("Caller failed")
	}
	return fmt.Sprintf("%s:%d", file, line)
}

func (s structWithMethod) callers() []uintptr {
	pc := make([]uintptr, 16)
	return pc[:Callers(0, pc)]
}

func (s structWithMethod) stack() string {
	buf := make([]byte, 4<<10)
	return string(buf[:Stack(buf, false)])
}

func (s structWithMethod) nop() {}

func (s structWithMethod) inlinablePanic() { panic("panic") }

func TestStackWrapperCaller(t *testing.T) {
	var d structWithMethod
	// Force the compiler to construct a wrapper method.
	wrapper := (*structWithMethod).caller
	// Check that the wrapper doesn't affect the stack trace.
	if dc, ic := d.caller(), wrapper(&d); dc != ic {
		t.Fatalf("direct caller %q != indirect caller %q", dc, ic)
	}
}

func TestStackWrapperCallers(t *testing.T) {
	var d structWithMethod
	wrapper := (*structWithMethod).callers
	// Check that <autogenerated> doesn't appear in the stack trace.
	pcs := wrapper(&d)
	frames := CallersFrames(pcs)
	for {
		fr, more := frames.Next()
		if fr.File == "<autogenerated>" {
			t.Fatalf("<autogenerated> appears in stack trace: %+v", fr)
		}
		if !more {
			break
		}
	}
}

func TestStackWrapperStack(t *testing.T) {
	var d structWithMethod
	wrapper := (*structWithMethod).stack
	// Check that <autogenerated> doesn't appear in the stack trace.
	stk := wrapper(&d)
	if strings.Contains(stk, "<autogenerated>") {
		t.Fatalf("<autogenerated> appears in stack trace:\n%s", stk)
	}
}

func TestStackWrapperStackInlinePanic(t *testing.T) {
	// Test that inline unwinding correctly tracks the callee by creating a
	// stack of the form wrapper -> inlined function -> panic. If we mess up
	// callee tracking, it will look like the wrapper called panic and we'll see
	// the wrapper in the stack trace.
	var d structWithMethod
	wrapper := (*structWithMethod).inlinablePanic
	defer func() {
		err := recover()
		if err == nil {
			t.Fatalf("expected panic")
		}
		buf := make([]byte, 4<<10)
		stk := string(buf[:Stack(buf, false)])
		if strings.Contains(stk, "<autogenerated>") {
			t.Fatalf("<autogenerated> appears in stack trace:\n%s", stk)
		}
		// Self-check: make sure inlinablePanic got inlined.
		if !testenv.OptimizationOff() {
			if !strings.Contains(stk, "inlinablePanic(...)") {
				t.Fatalf("inlinablePanic not inlined")
			}
		}
	}()
	wrapper(&d)
}

type I interface {
	M()
}

func TestStackWrapperStackPanic(t *testing.T) {
	t.Run("sigpanic", func(t *testing.T) {
		// nil calls to interface methods cause a sigpanic.
		testStackWrapperPanic(t, func() { I.M(nil) }, "runtime_test.I.M")
	})
	t.Run("panicwrap", func(t *testing.T) {
		// Nil calls to value method wrappers call panicwrap.
		wrapper := (*structWithMethod).nop
		testStackWrapperPanic(t, func() { wrapper(nil) }, "runtime_test.(*structWithMethod).nop")
	})
}

func testStackWrapperPanic(t *testing.T, cb func(), expect string) {
	// Test that the stack trace from a panicking wrapper includes
	// the wrapper, even though elide these when they don't panic.
	t.Run("CallersFrames", func(t *testing.T) {
		defer func() {
			err := recover()
			if err == nil {
				t.Fatalf("expected panic")
			}
			pcs := make([]uintptr, 10)
			n := Callers(0, pcs)
			frames := CallersFrames(pcs[:n])
			for {
				frame, more := frames.Next()
				t.Log(frame.Function)
				if frame.Function == expect {
					return
				}
				if !more {
					break
				}
			}
			t.Fatalf("panicking wrapper %s missing from stack trace", expect)
		}()
		cb()
	})
	t.Run("Stack", func(t *testing.T) {
		defer func() {
			err := recover()
			if err == nil {
				t.Fatalf("expected panic")
			}
			buf := make([]byte, 4<<10)
			stk := string(buf[:Stack(buf, false)])
			if !strings.Contains(stk, "\n"+expect) {
				t.Fatalf("panicking wrapper %s missing from stack trace:\n%s", expect, stk)
			}
		}()
		cb()
	})
}

func TestCallersFromWrapper(t *testing.T) {
	// Test that invoking CallersFrames on a stack where the first
	// PC is an autogenerated wrapper keeps the wrapper in the
	// trace. Normally we elide these, assuming that the wrapper
	// calls the thing you actually wanted to see, but in this
	// case we need to keep it.
	pc := reflect.ValueOf(I.M).Pointer()
	frames := CallersFrames([]uintptr{pc})
	frame, more := frames.Next()
	if frame.Function != "runtime_test.I.M" {
		t.Fatalf("want function %s, got %s", "runtime_test.I.M", frame.Function)
	}
	if more {
		t.Fatalf("want 1 frame, got > 1")
	}
}

func TestTracebackSystemstack(t *testing.T) {
	if GOARCH == "ppc64" || GOARCH == "ppc64le" {
		t.Skip("systemstack tail call not implemented on ppc64x")
	}

	// Test that profiles correctly jump over systemstack,
	// including nested systemstack calls.
	pcs := make([]uintptr, 20)
	pcs = pcs[:TracebackSystemstack(pcs, 5)]
	// Check that runtime.TracebackSystemstack appears five times
	// and that we see TestTracebackSystemstack.
	countIn, countOut := 0, 0
	frames := CallersFrames(pcs)
	var tb strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&tb, "\n%s+0x%x %s:%d", frame.Function, frame.PC-frame.Entry, frame.File, frame.Line)
		switch frame.Function {
		case "runtime.TracebackSystemstack":
			countIn++
		case "runtime_test.TestTracebackSystemstack":
			countOut++
		}
		if !more {
			break
		}
	}
	if countIn != 5 || countOut != 1 {
		t.Fatalf("expected 5 calls to TracebackSystemstack and 1 call to TestTracebackSystemstack, got:%s", tb.String())
	}
}

func TestTracebackAncestors(t *testing.T) {
	goroutineRegex := regexp.MustCompile(`goroutine [0-9]+ \[`)
	for _, tracebackDepth := range []int{0, 1, 5, 50} {
		output := runTestProg(t, "testprog", "TracebackAncestors", fmt.Sprintf("GODEBUG=tracebackancestors=%d", tracebackDepth))

		numGoroutines := 3
		numFrames := 2
		ancestorsExpected := numGoroutines
		if numGoroutines > tracebackDepth {
			ancestorsExpected = tracebackDepth
		}

		matches := goroutineRegex.FindAllStringSubmatch(output, -1)
		if len(matches) != 2 {
			t.Fatalf("want 2 goroutines, got:\n%s", output)
		}

		// Check functions in the traceback.
		fns := []string{"main.recurseThenCallGo", "main.main", "main.printStack", "main.TracebackAncestors"}
		for _, fn := range fns {
			if !strings.Contains(output, "\n"+fn+"(") {
				t.Fatalf("expected %q function in traceback:\n%s", fn, output)
			}
		}

		if want, count := "originating from goroutine", ancestorsExpected; strings.Count(output, want) != count {
			t.Errorf("output does not contain %d instances of %q:\n%s", count, want, output)
		}

		if want, count := "main.recurseThenCallGo(...)", ancestorsExpected*(numFrames+1); strings.Count(output, want) != count {
			t.Errorf("output does not contain %d instances of %q:\n%s", count, want, output)
		}

		if want, count := "main.recurseThenCallGo(0x", 1; strings.Count(output, want) != count {
			t.Errorf("output does not contain %d instances of %q:\n%s", count, want, output)
		}
	}
}

// Test that defer closure is correctly scanned when the stack is scanned.
func TestDeferLiveness(t *testing.T) {
	output := runTestProg(t, "testprog", "DeferLiveness", "GODEBUG=clobberfree=1")
	if output != "" {
		t.Errorf("output:\n%s\n\nwant no output", output)
	}
}

func TestDeferHeapAndStack(t *testing.T) {
	P := 4     // processors
	N := 10000 //iterations
	D := 200   // stack depth

	if testing.Short() {
		P /= 2
		N /= 10
		D /= 10
	}
	c := make(chan bool)
	for p := 0; p < P; p++ {
		go func() {
			for i := 0; i < N; i++ {
				if deferHeapAndStack(D) != 2*D {
					panic("bad result")
				}
			}
			c <- true
		}()
	}
	for p := 0; p < P; p++ {
		<-c
	}
}

// deferHeapAndStack(n) computes 2*n
func deferHeapAndStack(n int) (r int) {
	if n == 0 {
		return 0
	}
	if n%2 == 0 {
		// heap-allocated defers
		for i := 0; i < 2; i++ {
			defer func() {
				r++
			}()
		}
	} else {
		// stack-allocated defers
		defer func() {
			r++
		}()
		defer func() {
			r++
		}()
	}
	r = deferHeapAndStack(n - 1)
	escapeMe(new([1024]byte)) // force some GCs
	return
}

// Pass a value to escapeMe to force it to escape.
var escapeMe = func(x any) {}

func TestFramePointerAdjust(t *testing.T) {
	switch GOARCH {
	case "amd64", "arm64":
	default:
		t.Skipf("frame pointer is not supported on %s", GOARCH)
	}
	output := runTestProg(t, "testprog", "FramePointerAdjust")
	if output != "" {
		t.Errorf("output:\n%s\n\nwant no output", output)
	}
}

// TestSystemstackFramePointerAdjust is a regression test for issue 59692 that
// ensures that the frame pointer of systemstack is correctly adjusted. See CL
// 489015 for more details.
func TestSystemstackFramePointerAdjust(t *testing.T) {
	growAndShrinkStack(512, [1024]byte{})
}

// growAndShrinkStack grows the stack of the current goroutine in order to
// shrink it again and verify that all frame pointers on the new stack have
// been correctly adjusted. stackBallast is used to ensure we're not depending
// on the current heuristics of stack shrinking too much.
func growAndShrinkStack(n int, stackBallast [1024]byte) {
	if n <= 0 {
		return
	}
	growAndShrinkStack(n-1, stackBallast)
	ShrinkStackAndVerifyFramePointers()
}
```