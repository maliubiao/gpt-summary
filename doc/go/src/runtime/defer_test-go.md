Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The primary goal is to analyze a Go test file (`defer_test.go`) and explain its functionality, focusing on the `defer` keyword.

2. **Identify Key Concepts:** The filename and the repeated use of `defer` in the test functions immediately highlight that the code is about testing the behavior of the `defer` statement in Go. Concepts like `panic`, `recover`, and the order of execution of deferred functions are likely central.

3. **Initial Scan for Patterns:**  Quickly read through the code, looking for common patterns. Notice the frequent use of:
    * `defer func() { ... }()`: Anonymous functions being deferred.
    * `recover()`: Used inside deferred functions.
    * `panic(...)`: Triggering panics with specific string or integer values.
    * `t.Fatal(...)`, `t.Fatalf(...)`:  Reporting test failures.
    * Comments explaining the purpose of individual tests.

4. **Analyze Individual Test Functions:**  Go through each `Test...` function one by one. For each function:
    * **Read the Comment:** The comment at the beginning of each test function often provides a concise summary of what the test is verifying. This is the most crucial starting point.
    * **Trace the Execution Flow:** Mentally simulate the execution of the code, paying close attention to the order in which `defer` statements are encountered and when `panic` is called.
    * **Identify the Expected Outcome:** Based on the code and the comment, determine what the test expects to happen (e.g., a specific panic value should be recovered, a certain order of execution for deferred functions).
    * **Focus on `defer` Behavior:**  Pay attention to *why* certain `defer` statements are behaving the way they are. Is it an "open-coded" defer (simple and directly in the function), or a non-open-coded defer (e.g., within a loop)?
    * **Understand `recover()`:** How is `recover()` being used? What value is it expected to return? When will it return `nil`?
    * **Connect `panic` and `recover`:**  How does the `panic` in the main part of the function interact with the `recover` in the `defer` functions?
    * **Look for Edge Cases:** Are there tests that explore more complex scenarios, such as nested defers, panics within defers, or conditional defers?

5. **Categorize Functionality:**  As you analyze the individual tests, start grouping them by the specific `defer` features they are testing. This helps in summarizing the overall functionality of the file. For example:
    * Basic `defer` execution and order.
    * `defer` in the presence of `panic` and `recover`.
    * Open-coded vs. non-open-coded defers.
    * Conditional defers.
    * Panics occurring within defer functions.
    * Interaction of `recover` with different levels of defer.
    * Passing arguments to deferred functions (including non-SSAable arguments).

6. **Identify Key Go Language Features Demonstrated:** Based on the categorization, pinpoint the Go language features being tested. The primary one is `defer`, but related concepts like `panic`, `recover`, function closures, and the execution order of statements are also important.

7. **Construct Examples:**  For the more interesting or less obvious test cases, create simplified Go code examples to illustrate the specific behavior being tested. This helps solidify understanding and makes the explanation clearer. Focus on isolating the key parts of the test.

8. **Address Potential Pitfalls:** Think about common mistakes developers might make when using `defer`. This often involves misunderstanding the order of execution or how `recover` works.

9. **Structure the Explanation:**  Organize the findings in a clear and logical way. Start with a high-level summary, then delve into the details of each test category. Use clear headings and bullet points. Provide code examples where relevant.

10. **Review and Refine:** Read through the explanation to ensure accuracy, clarity, and completeness. Check for any ambiguities or areas where further clarification might be needed. Ensure the code examples are correct and easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just testing basic `defer`."  **Correction:** Upon closer inspection, realize it covers more nuanced aspects like open/non-open coded defers, nested panics, and argument handling.
* **Confusion about open-coded vs. non-open-coded:** Research or recall the compiler optimization that makes simple `defer` statements more efficient. Understand the conditions that prevent open-coding (like being in a loop).
* **Difficulty explaining a complex test:**  Break down the test into smaller steps and trace the execution flow carefully. Draw diagrams or make notes if needed.
* **Realizing a missing aspect:**  Notice that the code touches on how `recover()` behaves when called indirectly from a deferred function. Add an explanation of this.

By following this structured approach and being willing to refine understanding along the way, a comprehensive and accurate explanation of the `defer_test.go` file can be generated.
这段代码是 Go 语言运行时（runtime）包中 `defer_test.go` 文件的一部分，它的主要功能是**测试 `defer` 语句在各种场景下的行为和正确性**。`defer` 是 Go 语言中一个非常重要的特性，用于在函数执行完毕（无论是正常返回还是发生 panic）后执行一些清理操作。

更具体地说，这段代码涵盖了以下方面的测试：

1. **`defer` 语句在 `panic` 发生时的执行:**
   - 确保即使函数因为 `panic` 而没有正常返回，`defer` 语句仍然会被执行。
   - 测试了无条件 `panic` 的情况下 `defer` 的执行。

2. **不同类型的 `defer` 语句的执行:**
   - 区分并测试了 "open-coded defer" 和 "non-open-coded defer"。
   - **Open-coded defer:**  Go 编译器在某些简单情况下会将 `defer` 直接内联到函数末尾，以提高性能。
   - **Non-open-coded defer:**  在复杂情况下（例如在循环中），`defer` 会以更传统的方式实现。
   - 代码测试了这两种类型的 `defer` 是否都能正常执行。

3. **`defer` 语句的执行顺序:**
   - 测试了多个 `defer` 语句的执行顺序，通常是后进先出（LIFO）。
   - 特别关注了条件 `defer` 的激活和执行顺序。

4. **`recover()` 函数的使用:**
   - 测试了 `recover()` 函数在 `defer` 函数中的行为，用于捕获 `panic` 并恢复程序的正常执行。
   - 验证了 `recover()` 只能捕获直接调用 `panic` 的 goroutine 的 panic。

5. **`defer` 语句的优化和消除:**
   - 测试了编译器优化（如常量传播和死代码消除）是否会正确处理 `defer` 语句，即使 `defer` 调用最终被移除，也不会导致错误。

6. **嵌套 `panic` 和 `recover` 的行为:**
   - 测试了在 `defer` 函数执行过程中再次发生 `panic` 的情况，以及 `recover()` 如何处理这些嵌套的 `panic`。

7. **`defer` 函数的参数传递:**
   - 测试了向 `defer` 函数传递参数时的行为，特别是对于不可 SSA 化的参数，确保参数只被求值一次。

8. **在没有显式 `return` 的函数中使用 `defer`:**
   - 测试了在函数末尾是无限循环的情况下，`defer` 语句的执行。

9. **复杂的 `panic` 和 `recover` 场景:**
   - 模拟了更复杂的场景，例如递归函数中的多次 `panic` 和 `recover`，以确保 `defer` 机制的健壮性。

10. **与 Goroutine 栈相关的 `defer` 问题:**
    - 测试了一些可能导致内存错误的边缘情况，例如栈的移动和 `defer` 结构的管理。

**Go 代码示例说明 `defer` 和 `recover` 的基本用法:**

```go
package main

import "fmt"

func main() {
	fmt.Println("开始执行 main 函数")

	// 使用 defer 注册一个在函数结束时执行的匿名函数
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("捕获到 panic:", r)
		}
		fmt.Println("defer 函数执行完毕")
	}()

	fmt.Println("main 函数中执行一些操作...")

	// 模拟一个可能触发 panic 的情况
	if true {
		panic("发生了一个错误！")
	}

	fmt.Println("这行代码不会被执行，因为前面发生了 panic")
}
```

**假设的输入与输出:**

上面的代码示例没有外部输入，它的输出是固定的。

**预期输出:**

```
开始执行 main 函数
main 函数中执行一些操作...
捕获到 panic: 发生了一个错误！
defer 函数执行完毕
```

**代码推理:**

1. `fmt.Println("开始执行 main 函数")` 首先被执行。
2. `defer func() { ... }()` 注册了一个匿名函数，这个函数会在 `main` 函数执行完毕后执行。
3. `fmt.Println("main 函数中执行一些操作...")` 接着被执行。
4. `if true { panic("发生了一个错误！") }`  由于条件为真，`panic("发生了一个错误！")` 被执行，导致程序进入 panic 状态。
5. Go 运行时开始查找当前 goroutine 的 `defer` 链表，并按照后进先出的顺序执行 `defer` 函数。
6. 在 `defer` 函数中，`recover()` 捕获了之前 `panic` 传递的值 `"发生了一个错误！"`，并将其赋值给 `r`。
7. `fmt.Println("捕获到 panic:", r)` 打印出捕获到的 panic 信息。
8. `fmt.Println("defer 函数执行完毕")` 被执行。
9. 由于 `recover()` 捕获了 `panic`，程序的执行可以从 `defer` 函数之后恢复（尽管在这个例子中 `main` 函数已经结束）。如果没有 `recover()`，程序将会终止并打印 panic 信息。
10. `fmt.Println("这行代码不会被执行，因为前面发生了 panic")` 这行代码由于在 `panic` 之后，不会被执行到。

**命令行参数:**

这段代码是测试代码，通常不会直接作为可执行程序运行，而是通过 `go test` 命令来运行。`go test` 命令有很多参数，用于控制测试的执行方式，例如：

- `-v`:  显示详细的测试输出。
- `-run <regexp>`:  只运行匹配正则表达式的测试函数。
- `-bench <regexp>`: 运行性能测试。
- `-coverprofile <file>`:  生成代码覆盖率报告。

例如，要运行 `runtime_test` 包下的所有测试，可以在包含 `go.mod` 文件的目录下执行：

```bash
go test ./go/src/runtime
```

或者，要只运行 `defer_test.go` 文件中的测试，可以执行：

```bash
go test -v ./go/src/runtime/defer_test.go
```

**使用者易犯错的点 (以 `defer` 和 `recover` 为例):**

1. **误解 `defer` 的执行时机:**  初学者可能认为 `defer` 语句在声明时立即执行，但实际上它是在函数执行即将结束（return 语句执行后，或者函数执行到末尾，或者发生 panic）时才执行。

   ```go
   func exampleDeferTiming() {
       fmt.Println("函数开始")
       defer fmt.Println("defer 语句执行")
       fmt.Println("函数结束")
   }

   // 输出:
   // 函数开始
   // 函数结束
   // defer 语句执行
   ```

2. **`recover()` 必须在 `defer` 函数中直接调用才有效:** `recover()` 只有在其直接调用的 `defer` 函数被 `panic` 触发时才能捕获 `panic`。在其他地方调用 `recover()` 不会起作用。

   ```go
   func incorrectRecover() {
       defer func() {
           anotherFunc() // recover 在 anotherFunc 中调用，无效
       }()
       panic("错误")
   }

   func anotherFunc() {
       if r := recover(); r != nil {
           fmt.Println("捕获到 panic:", r) // 不会执行
       }
   }

   // 运行 incorrectRecover() 会导致程序崩溃，因为 panic 没有被捕获。
   ```

3. **`defer` 函数访问闭包变量时，要注意变量的值在 `defer` 执行时的状态:** `defer` 函数可以访问其所在函数的变量（闭包），但访问的是 `defer` 执行时的变量值，而不是声明时的值。

   ```go
   func deferClosure() {
       i := 0
       defer fmt.Println("defer 执行时 i 的值:", i) // 输出 0
       i++
       fmt.Println("i 的值:", i) // 输出 1
   }
   ```

   如果想要 `defer` 访问声明时的值，可以将变量作为参数传递给 `defer` 的匿名函数：

   ```go
   func deferClosureFixed() {
       i := 0
       defer func(val int) {
           fmt.Println("defer 执行时传递的 i 的值:", val) // 输出 0
       }(i)
       i++
       fmt.Println("i 的值:", i) // 输出 1
   }
   ```

4. **忘记在可能发生 `panic` 的地方使用 `defer` 和 `recover` 进行错误处理:** 如果没有合适的 `recover` 机制，`panic` 会导致程序崩溃。

5. **在循环中使用 `defer` 可能导致资源泄漏:** 如果在循环中无节制地使用 `defer` 打开资源（例如文件），可能会导致资源耗尽，因为 `defer` 是在函数结束时才执行。应该谨慎管理循环中的资源。

这段 `defer_test.go` 代码通过各种细致的测试用例，确保了 Go 语言 `defer` 机制的正确性和健壮性，这对于构建可靠的 Go 程序至关重要。

### 提示词
```
这是路径为go/src/runtime/defer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"slices"
	"testing"
)

// Make sure open-coded defer exit code is not lost, even when there is an
// unconditional panic (hence no return from the function)
func TestUnconditionalPanic(t *testing.T) {
	defer func() {
		if recover() != "testUnconditional" {
			t.Fatal("expected unconditional panic")
		}
	}()
	panic("testUnconditional")
}

var glob int = 3

// Test an open-coded defer and non-open-coded defer - make sure both defers run
// and call recover()
func TestOpenAndNonOpenDefers(t *testing.T) {
	for {
		// Non-open defer because in a loop
		defer func(n int) {
			if recover() != "testNonOpenDefer" {
				t.Fatal("expected testNonOpen panic")
			}
		}(3)
		if glob > 2 {
			break
		}
	}
	testOpen(t, 47)
	panic("testNonOpenDefer")
}

//go:noinline
func testOpen(t *testing.T, arg int) {
	defer func(n int) {
		if recover() != "testOpenDefer" {
			t.Fatal("expected testOpen panic")
		}
	}(4)
	if arg > 2 {
		panic("testOpenDefer")
	}
}

// Test a non-open-coded defer and an open-coded defer - make sure both defers run
// and call recover()
func TestNonOpenAndOpenDefers(t *testing.T) {
	testOpen(t, 47)
	for {
		// Non-open defer because in a loop
		defer func(n int) {
			if recover() != "testNonOpenDefer" {
				t.Fatal("expected testNonOpen panic")
			}
		}(3)
		if glob > 2 {
			break
		}
	}
	panic("testNonOpenDefer")
}

var list []int

// Make sure that conditional open-coded defers are activated correctly and run in
// the correct order.
func TestConditionalDefers(t *testing.T) {
	list = make([]int, 0, 10)

	defer func() {
		if recover() != "testConditional" {
			t.Fatal("expected panic")
		}
		want := []int{4, 2, 1}
		if !slices.Equal(want, list) {
			t.Fatalf("wanted %v, got %v", want, list)
		}

	}()
	testConditionalDefers(8)
}

func testConditionalDefers(n int) {
	doappend := func(i int) {
		list = append(list, i)
	}

	defer doappend(1)
	if n > 5 {
		defer doappend(2)
		if n > 8 {
			defer doappend(3)
		} else {
			defer doappend(4)
		}
	}
	panic("testConditional")
}

// Test that there is no compile-time or run-time error if an open-coded defer
// call is removed by constant propagation and dead-code elimination.
func TestDisappearingDefer(t *testing.T) {
	switch runtime.GOOS {
	case "invalidOS":
		defer func() {
			t.Fatal("Defer shouldn't run")
		}()
	}
}

// This tests an extra recursive panic behavior that is only specified in the
// code. Suppose a first panic P1 happens and starts processing defer calls. If a
// second panic P2 happens while processing defer call D in frame F, then defer
// call processing is restarted (with some potentially new defer calls created by
// D or its callees). If the defer processing reaches the started defer call D
// again in the defer stack, then the original panic P1 is aborted and cannot
// continue panic processing or be recovered. If the panic P2 does a recover at
// some point, it will naturally remove the original panic P1 from the stack
// (since the original panic had to be in frame F or a descendant of F).
func TestAbortedPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r != nil {
			t.Fatalf("wanted nil recover, got %v", r)
		}
	}()
	defer func() {
		r := recover()
		if r != "panic2" {
			t.Fatalf("wanted %v, got %v", "panic2", r)
		}
	}()
	defer func() {
		panic("panic2")
	}()
	panic("panic1")
}

// This tests that recover() does not succeed unless it is called directly from a
// defer function that is directly called by the panic.  Here, we first call it
// from a defer function that is created by the defer function called directly by
// the panic.  In
func TestRecoverMatching(t *testing.T) {
	defer func() {
		r := recover()
		if r != "panic1" {
			t.Fatalf("wanted %v, got %v", "panic1", r)
		}
	}()
	defer func() {
		defer func() {
			// Shouldn't succeed, even though it is called directly
			// from a defer function, since this defer function was
			// not directly called by the panic.
			r := recover()
			if r != nil {
				t.Fatalf("wanted nil recover, got %v", r)
			}
		}()
	}()
	panic("panic1")
}

type nonSSAable [128]byte

type bigStruct struct {
	x, y, z, w, p, q int64
}

type containsBigStruct struct {
	element bigStruct
}

func mknonSSAable() nonSSAable {
	globint1++
	return nonSSAable{0, 0, 0, 0, 5}
}

var globint1, globint2, globint3 int

//go:noinline
func sideeffect(n int64) int64 {
	globint2++
	return n
}

func sideeffect2(in containsBigStruct) containsBigStruct {
	globint3++
	return in
}

// Test that nonSSAable arguments to defer are handled correctly and only evaluated once.
func TestNonSSAableArgs(t *testing.T) {
	globint1 = 0
	globint2 = 0
	globint3 = 0
	var save1 byte
	var save2 int64
	var save3 int64
	var save4 int64

	defer func() {
		if globint1 != 1 {
			t.Fatalf("globint1:  wanted: 1, got %v", globint1)
		}
		if save1 != 5 {
			t.Fatalf("save1:  wanted: 5, got %v", save1)
		}
		if globint2 != 1 {
			t.Fatalf("globint2:  wanted: 1, got %v", globint2)
		}
		if save2 != 2 {
			t.Fatalf("save2:  wanted: 2, got %v", save2)
		}
		if save3 != 4 {
			t.Fatalf("save3:  wanted: 4, got %v", save3)
		}
		if globint3 != 1 {
			t.Fatalf("globint3:  wanted: 1, got %v", globint3)
		}
		if save4 != 4 {
			t.Fatalf("save1:  wanted: 4, got %v", save4)
		}
	}()

	// Test function returning a non-SSAable arg
	defer func(n nonSSAable) {
		save1 = n[4]
	}(mknonSSAable())
	// Test composite literal that is not SSAable
	defer func(b bigStruct) {
		save2 = b.y
	}(bigStruct{1, 2, 3, 4, 5, sideeffect(6)})

	// Test struct field reference that is non-SSAable
	foo := containsBigStruct{}
	foo.element.z = 4
	defer func(element bigStruct) {
		save3 = element.z
	}(foo.element)
	defer func(element bigStruct) {
		save4 = element.z
	}(sideeffect2(foo).element)
}

//go:noinline
func doPanic() {
	panic("Test panic")
}

func TestDeferForFuncWithNoExit(t *testing.T) {
	cond := 1
	defer func() {
		if cond != 2 {
			t.Fatalf("cond: wanted 2, got %v", cond)
		}
		if recover() != "Test panic" {
			t.Fatal("Didn't find expected panic")
		}
	}()
	x := 0
	// Force a stack copy, to make sure that the &cond pointer passed to defer
	// function is properly updated.
	growStackIter(&x, 1000)
	cond = 2
	doPanic()

	// This function has no exit/return, since it ends with an infinite loop
	for {
	}
}

// Test case approximating issue #37664, where a recursive function (interpreter)
// may do repeated recovers/re-panics until it reaches the frame where the panic
// can actually be handled. The recurseFnPanicRec() function is testing that there
// are no stale defer structs on the defer chain after the interpreter() sequence,
// by writing a bunch of 0xffffffffs into several recursive stack frames, and then
// doing a single panic-recover which would invoke any such stale defer structs.
func TestDeferWithRepeatedRepanics(t *testing.T) {
	interpreter(0, 6, 2)
	recurseFnPanicRec(0, 10)
	interpreter(0, 5, 1)
	recurseFnPanicRec(0, 10)
	interpreter(0, 6, 3)
	recurseFnPanicRec(0, 10)
}

func interpreter(level int, maxlevel int, rec int) {
	defer func() {
		e := recover()
		if e == nil {
			return
		}
		if level != e.(int) {
			//fmt.Fprintln(os.Stderr, "re-panicing, level", level)
			panic(e)
		}
		//fmt.Fprintln(os.Stderr, "Recovered, level", level)
	}()
	if level+1 < maxlevel {
		interpreter(level+1, maxlevel, rec)
	} else {
		//fmt.Fprintln(os.Stderr, "Initiating panic")
		panic(rec)
	}
}

func recurseFnPanicRec(level int, maxlevel int) {
	defer func() {
		recover()
	}()
	recurseFn(level, maxlevel)
}

var saveInt uint32

func recurseFn(level int, maxlevel int) {
	a := [40]uint32{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}
	if level+1 < maxlevel {
		// Make sure a array is referenced, so it is not optimized away
		saveInt = a[4]
		recurseFn(level+1, maxlevel)
	} else {
		panic("recurseFn panic")
	}
}

// Try to reproduce issue #37688, where a pointer to an open-coded defer struct is
// mistakenly held, and that struct keeps a pointer to a stack-allocated defer
// struct, and that stack-allocated struct gets overwritten or the stack gets
// moved, so a memory error happens on GC.
func TestIssue37688(t *testing.T) {
	for j := 0; j < 10; j++ {
		g2()
		g3()
	}
}

type foo struct {
}

//go:noinline
func (f *foo) method1() {
}

//go:noinline
func (f *foo) method2() {
}

func g2() {
	var a foo
	ap := &a
	// The loop forces this defer to be heap-allocated and the remaining two
	// to be stack-allocated.
	for i := 0; i < 1; i++ {
		defer ap.method1()
	}
	defer ap.method2()
	defer ap.method1()
	ff1(ap, 1, 2, 3, 4, 5, 6, 7, 8, 9)
	// Try to get the stack to be moved by growing it too large, so
	// existing stack-allocated defer becomes invalid.
	rec1(2000)
}

func g3() {
	// Mix up the stack layout by adding in an extra function frame
	g2()
}

var globstruct struct {
	a, b, c, d, e, f, g, h, i int
}

func ff1(ap *foo, a, b, c, d, e, f, g, h, i int) {
	defer ap.method1()

	// Make a defer that has a very large set of args, hence big size for the
	// defer record for the open-coded frame (which means it won't use the
	// defer pool)
	defer func(ap *foo, a, b, c, d, e, f, g, h, i int) {
		if v := recover(); v != nil {
		}
		globstruct.a = a
		globstruct.b = b
		globstruct.c = c
		globstruct.d = d
		globstruct.e = e
		globstruct.f = f
		globstruct.g = g
		globstruct.h = h
	}(ap, a, b, c, d, e, f, g, h, i)
	panic("ff1 panic")
}

func rec1(max int) {
	if max > 0 {
		rec1(max - 1)
	}
}

func TestIssue43921(t *testing.T) {
	defer func() {
		expect(t, 1, recover())
	}()
	func() {
		// Prevent open-coded defers
		for {
			defer func() {}()
			break
		}

		defer func() {
			defer func() {
				expect(t, 4, recover())
			}()
			panic(4)
		}()
		panic(1)

	}()
}

func expect(t *testing.T, n int, err any) {
	if n != err {
		t.Fatalf("have %v, want %v", err, n)
	}
}

func TestIssue43920(t *testing.T) {
	var steps int

	defer func() {
		expect(t, 1, recover())
	}()
	defer func() {
		defer func() {
			defer func() {
				expect(t, 5, recover())
			}()
			defer panic(5)
			func() {
				panic(4)
			}()
		}()
		defer func() {
			expect(t, 3, recover())
		}()
		defer panic(3)
	}()
	func() {
		defer step(t, &steps, 1)
		panic(1)
	}()
}

func step(t *testing.T, steps *int, want int) {
	*steps++
	if *steps != want {
		t.Fatalf("have %v, want %v", *steps, want)
	}
}

func TestIssue43941(t *testing.T) {
	var steps int = 7
	defer func() {
		step(t, &steps, 14)
		expect(t, 4, recover())
	}()
	func() {
		func() {
			defer func() {
				defer func() {
					expect(t, 3, recover())
				}()
				defer panic(3)
				panic(2)
			}()
			defer func() {
				expect(t, 1, recover())
			}()
			defer panic(1)
		}()
		defer func() {}()
		defer func() {}()
		defer step(t, &steps, 10)
		defer step(t, &steps, 9)
		step(t, &steps, 8)
	}()
	func() {
		defer step(t, &steps, 13)
		defer step(t, &steps, 12)
		func() {
			defer step(t, &steps, 11)
			panic(4)
		}()

		// Code below isn't executed,
		// but removing it breaks the test case.
		defer func() {}()
		defer panic(-1)
		defer step(t, &steps, -1)
		defer step(t, &steps, -1)
		defer func() {}()
	}()
}
```