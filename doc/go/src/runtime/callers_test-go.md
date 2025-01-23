Response:
我的目标是理解给定的 Go 代码的功能，并根据要求进行解释和代码示例说明。

**第一步：理解代码结构和主要功能**

浏览代码，我注意到以下关键点：

1. **`package runtime_test`**:  这是一个针对 `runtime` 包的测试代码。
2. **`import`**: 导入了 `runtime`，`slices`, `strings`, 和 `testing` 包。这意味着代码主要测试 `runtime` 包的功能，并使用了 Go 的测试框架。
3. **`f1`, `f2`, `f3` 函数**: 这些是简单的调用链，用于模拟函数调用栈。 `f3` 函数可以选择性地 `panic`。
4. **`testCallers` 函数**:  核心测试函数之一。它接收一组 `uintptr` (程序计数器)，并使用 `runtime.CallersFrames` 将其转换为 `runtime.Frame` 结构体。然后，它检查这些帧是否对应预期的函数名和行号。
5. **`testCallersEqual` 函数**: 另一个核心测试函数，它验证通过 `runtime.CallersFrames` 获取的函数名序列是否与预期一致。
6. **`TestCallers` 和 `TestCallersPanic` 函数**:  使用 `f1` 调用 `testCallers`，分别测试正常情况和 `panic` 情况下的栈信息。
7. **`TestCallersDoublePanic` 等其他 `TestCallers...` 函数**: 这些函数都涉及到 `panic` 和 `recover` 的场景，并使用 `runtime.Callers` 来获取栈信息，然后使用 `testCallersEqual` 进行断言。这些测试覆盖了各种 `panic` 和 `recover` 的组合情况，包括嵌套的 `panic`，在 `recover` 之后获取栈信息，以及 `panic` 被中止的情况。
8. **`TestCallersEndlineno` 函数**: 测试了泛型函数实例化后，`runtime.Caller` 返回的行号是否正确。
9. **`BenchmarkCallers` 函数**:  包含了基准测试，用于衡量 `runtime.Callers` 的性能，考虑了缓存、内联等因素。
10. **`BenchmarkFPCallers` 和 `TestFPUnwindAfterRecovery`**:  涉及到 `runtime.FPCallers`，这很可能与使用帧指针进行栈回溯有关。`TestFPUnwindAfterRecovery` 特别关注在 `recover` 之后帧指针是否正确恢复，以保证后续的栈回溯不会崩溃。

**第二步：推断 Go 语言功能**

基于代码结构和测试用例，可以推断出这段代码主要测试了 `runtime` 包中与获取函数调用栈信息相关的几个功能：

*   **`runtime.Callers(skip int, pc []uintptr) int`**: 获取当前 goroutine 的调用栈，将程序计数器（PC）存储到 `pc` 切片中。 `skip` 参数用于跳过栈帧。
*   **`runtime.CallersFrames(pc []uintptr) *runtime.Frames`**: 将 `runtime.Callers` 返回的 PC 切片转换为一个可以迭代的 `runtime.Frames` 结构体，方便获取更详细的栈帧信息。
*   **`runtime.Frame` 结构体**: 包含关于单个栈帧的信息，如函数名、文件名和行号。
*   **`runtime.Caller(skip int) (pc uintptr, file string, line int, ok bool)`**: 获取指定栈帧的程序计数器、文件名和行号。
*   **`runtime.FPCallers(pc []uintptr) int`**:  类似于 `runtime.Callers`，但它可能使用帧指针来进行栈回溯。这个函数可能在某些架构上可用，而在没有帧指针的架构上可能不可用。

**第三步：编写代码示例**

根据推断出的功能，我可以编写一个示例来说明 `runtime.Callers` 和 `runtime.CallersFrames` 的用法。

**第四步：处理代码推理和假设**

在推理 `TestCallersPanic` 等测试用例时，我假设了 `panic` 和 `recover` 的行为，以及 `defer` 语句的执行顺序。这些假设与 Go 语言的规范一致。

**第五步：处理命令行参数**

这段代码是测试代码，本身不直接处理命令行参数。然而，Go 的测试框架 `go test` 接受各种命令行参数，例如 `-v` (显示详细输出) 和 `-run` (运行特定的测试用例)。

**第六步：识别易犯错的点**

使用者在使用 `runtime.Callers` 时，一个常见的错误是**对 `skip` 参数的理解不正确**，导致跳过了过多的栈帧，从而丢失了想要的信息。另一个潜在的错误是**提供的 `pc` 切片长度不足**，导致只能获取部分调用栈信息。在涉及到 `panic` 和 `recover` 的场景中，**对 `defer` 语句执行时机的理解偏差**也可能导致错误。

**最终组织答案**

现在我可以使用以上分析来组织最终的中文答案，确保覆盖所有要求，包括功能描述、代码示例、代码推理、命令行参数（针对测试框架）以及易犯错的点。 我的思考过程已经将所有信息串联起来，形成了最终答案的基础。

这个 `go/src/runtime/callers_test.go` 文件是 Go 语言运行时库的一部分，专门用于测试 `runtime` 包中与获取函数调用栈信息相关的功能。 具体来说，它主要测试了以下几个核心功能：

**1. `runtime.Callers(skip int, pc []uintptr) int`**:

   - **功能**:  该函数用于获取当前 goroutine 的调用栈信息，并将调用栈中每个调用帧的程序计数器（Program Counter, PC）存储到提供的 `pc` 切片中。
   - **参数**:
     - `skip`:  一个整数，表示要跳过的栈帧数。例如，如果 `skip` 为 0，则返回当前调用者的栈帧；如果 `skip` 为 1，则返回当前调用者的调用者的栈帧，以此类推。
     - `pc`:  一个 `uintptr` 类型的切片，用于存储获取到的程序计数器。
   - **返回值**: 返回实际存储到 `pc` 切片中的栈帧数量。
   - **测试目的**:  测试 `runtime.Callers` 能否正确地获取指定数量的调用栈帧的程序计数器。

**2. `runtime.CallersFrames(pc []uintptr) *runtime.Frames`**:

   - **功能**: 该函数接收一个由 `runtime.Callers` 返回的程序计数器切片，并返回一个可以迭代的 `runtime.Frames` 结构体。通过迭代这个 `runtime.Frames`，可以获取更详细的调用栈信息，例如函数名、文件名和行号。
   - **参数**: `pc`: 由 `runtime.Callers` 返回的程序计数器切片。
   - **返回值**: 一个指向 `runtime.Frames` 结构体的指针。
   - **测试目的**: 测试 `runtime.CallersFrames` 能否正确地将程序计数器转换为可用的栈帧信息。

**3. `runtime.Caller(skip int) (pc uintptr, file string, line int, ok bool)`**:

   - **功能**:  获取调用栈中指定栈帧的程序计数器、文件名和行号。
   - **参数**: `skip`:  要跳过的栈帧数，与 `runtime.Callers` 中的 `skip` 参数含义相同。
   - **返回值**:
     - `pc`:  程序计数器。
     - `file`:  文件名。
     - `line`:  行号。
     - `ok`:  一个布尔值，表示是否成功获取到栈帧信息。
   - **测试目的**: 测试 `runtime.Caller` 能否正确地获取指定栈帧的详细信息。

**4. `runtime.FPCallers(pc []uintptr) int`**:

   - **功能**:  类似于 `runtime.Callers`，但它可能使用帧指针（Frame Pointer）来遍历调用栈。这在某些架构上可能更高效。
   - **参数和返回值**: 与 `runtime.Callers` 相同。
   - **测试目的**: 测试 `runtime.FPCallers` 在支持帧指针的架构上能否正确获取调用栈信息。

**功能实现的代码示例：**

以下代码示例演示了 `runtime.Callers` 和 `runtime.CallersFrames` 的基本用法：

```go
package main

import (
	"fmt"
	"runtime"
)

func functionC() {
	functionB()
}

func functionB() {
	functionA()
}

func functionA() {
	pc := make([]uintptr, 10)
	n := runtime.Callers(0, pc)
	pc = pc[:n]
	frames := runtime.CallersFrames(pc)
	fmt.Println("Call Stack:")
	for {
		frame, more := frames.Next()
		fmt.Printf("- %s:%d %s\n", frame.File, frame.Line, frame.Function)
		if !more {
			break
		}
	}
}

func main() {
	functionC()
}
```

**假设的输入与输出：**

运行上述代码，输出可能如下（具体的路径和行号会根据你的环境而变化）：

```
Call Stack:
- /path/to/your/file.go:17 main.functionA
- /path/to/your/file.go:13 main.functionB
- /path/to/your/file.go:9 main.functionC
- /usr/local/go/src/runtime/proc.go:267 runtime.main
- /usr/local/go/src/runtime/asm_amd64.s:1650 runtime.goexit
```

**代码推理：**

在 `testCallers` 函数中，代码首先使用 `runtime.Callers` 获取调用栈的程序计数器，然后使用 `runtime.CallersFrames` 将其转换为 `runtime.Frame` 结构体。接着，它遍历这些帧，并将函数名和行号存储到 `map` 中。最后，它断言获取到的函数名和行号是否与预期的值相符。

例如，在 `TestCallers` 函数中，调用 `f1(false)` 会执行 `f1` -> `f2` -> `f3` 的调用链。在 `f3` 中，`runtime.Callers(0, ret)` 会获取当前的调用栈信息。`testCallers` 函数会验证栈中是否包含 `f1`、`f2` 和 `f3` 函数，并且它们的行号是否正确（分别是第 15、19 和 27 行）。

在 `TestCallersPanic` 函数中，当 `f1(true)` 被调用时，`f3` 函数会触发 `panic("f3")`。`defer` 语句中的代码会被执行，它会使用 `runtime.Callers` 获取 panic 时的调用栈，并验证栈中是否包含预期的函数，包括 `runtime.gopanic` 和 `runtime_test.TestCallersPanic` 的匿名函数，以及它们对应的行号。

**命令行参数：**

该文件本身是测试文件，不直接处理命令行参数。但是，当你使用 `go test` 命令运行这个测试文件时，可以使用一些标准的 `go test` 命令行参数，例如：

- **`-v`**:  显示详细的测试输出，包括每个测试用例的运行结果。
- **`-run <regexp>`**:  只运行名称与指定正则表达式匹配的测试用例。例如，`go test -run TestCallers` 将只运行名为 `TestCallers` 的测试用例。
- **`-bench <regexp>`**:  运行基准测试。例如，`go test -bench BenchmarkCallers` 将运行基准测试。

**使用者易犯错的点：**

1. **`skip` 参数理解不当**:  初学者可能会不清楚 `skip` 参数的作用，导致获取到的调用栈信息不符合预期。例如，如果想获取当前函数的调用者的信息，应该使用 `runtime.Callers(1, ...)` 而不是 `runtime.Callers(0, ...)`。

   ```go
   func caller() {
       pcs := make([]uintptr, 1)
       runtime.Callers(0, pcs) // 获取的是 caller 函数自身的 PC
       runtime.Callers(1, pcs) // 获取的是调用 caller 函数的函数的 PC
   }
   ```

2. **提供的 `pc` 切片长度不足**:  如果提供的 `pc` 切片长度小于实际的调用栈深度，`runtime.Callers` 只会填充部分栈帧。因此，在使用前需要确保切片有足够的容量。

   ```go
   func f() {
       pcs := make([]uintptr, 2) // 可能无法容纳完整的调用栈
       n := runtime.Callers(0, pcs)
       // n 可能小于实际的调用栈深度
   }
   ```

3. **在 `panic` 和 `recover` 的场景下获取栈信息**:  在 `defer` 函数中使用 `runtime.Callers` 获取栈信息时，需要理解此时的调用栈可能包含额外的运行时函数，例如 `runtime.gopanic` 和 `runtime.deferreturn`。`callers_test.go` 中的许多测试用例正是为了验证在这种复杂场景下获取栈信息的正确性。

4. **对 `runtime.CallersFrames` 的迭代**:  使用者需要理解 `runtime.CallersFrames` 返回的是一个迭代器，需要通过循环调用 `Next()` 方法来获取所有的栈帧信息。如果不正确地迭代，可能会丢失部分栈帧信息。

总而言之，`go/src/runtime/callers_test.go` 这个文件通过一系列的测试用例，细致地验证了 Go 语言运行时获取函数调用栈信息的相关功能，确保这些功能在各种场景下（包括正常的函数调用、panic 和 recover 等）都能正确工作。

### 提示词
```
这是路径为go/src/runtime/callers_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

func f1(pan bool) []uintptr {
	return f2(pan) // line 15
}

func f2(pan bool) []uintptr {
	return f3(pan) // line 19
}

func f3(pan bool) []uintptr {
	if pan {
		panic("f3") // line 24
	}
	ret := make([]uintptr, 20)
	return ret[:runtime.Callers(0, ret)] // line 27
}

func testCallers(t *testing.T, pcs []uintptr, pan bool) {
	m := make(map[string]int, len(pcs))
	frames := runtime.CallersFrames(pcs)
	for {
		frame, more := frames.Next()
		if frame.Function != "" {
			m[frame.Function] = frame.Line
		}
		if !more {
			break
		}
	}

	var seen []string
	for k := range m {
		seen = append(seen, k)
	}
	t.Logf("functions seen: %s", strings.Join(seen, " "))

	var f3Line int
	if pan {
		f3Line = 24
	} else {
		f3Line = 27
	}
	want := []struct {
		name string
		line int
	}{
		{"f1", 15},
		{"f2", 19},
		{"f3", f3Line},
	}
	for _, w := range want {
		if got := m["runtime_test."+w.name]; got != w.line {
			t.Errorf("%s is line %d, want %d", w.name, got, w.line)
		}
	}
}

func testCallersEqual(t *testing.T, pcs []uintptr, want []string) {
	t.Helper()

	got := make([]string, 0, len(want))

	frames := runtime.CallersFrames(pcs)
	for {
		frame, more := frames.Next()
		if !more || len(got) >= len(want) {
			break
		}
		got = append(got, frame.Function)
	}
	if !slices.Equal(want, got) {
		t.Fatalf("wanted %v, got %v", want, got)
	}
}

func TestCallers(t *testing.T) {
	testCallers(t, f1(false), false)
}

func TestCallersPanic(t *testing.T) {
	// Make sure we don't have any extra frames on the stack (due to
	// open-coded defer processing)
	want := []string{"runtime.Callers", "runtime_test.TestCallersPanic.func1",
		"runtime.gopanic", "runtime_test.f3", "runtime_test.f2", "runtime_test.f1",
		"runtime_test.TestCallersPanic"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("did not panic")
		}
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallers(t, pcs, true)
		testCallersEqual(t, pcs, want)
	}()
	f1(true)
}

func TestCallersDoublePanic(t *testing.T) {
	// Make sure we don't have any extra frames on the stack (due to
	// open-coded defer processing)
	want := []string{"runtime.Callers", "runtime_test.TestCallersDoublePanic.func1.1",
		"runtime.gopanic", "runtime_test.TestCallersDoublePanic.func1", "runtime.gopanic", "runtime_test.TestCallersDoublePanic"}

	defer func() {
		defer func() {
			pcs := make([]uintptr, 20)
			pcs = pcs[:runtime.Callers(0, pcs)]
			if recover() == nil {
				t.Fatal("did not panic")
			}
			testCallersEqual(t, pcs, want)
		}()
		if recover() == nil {
			t.Fatal("did not panic")
		}
		panic(2)
	}()
	panic(1)
}

// Test that a defer after a successful recovery looks like it is called directly
// from the function with the defers.
func TestCallersAfterRecovery(t *testing.T) {
	want := []string{"runtime.Callers", "runtime_test.TestCallersAfterRecovery.func1", "runtime_test.TestCallersAfterRecovery"}

	defer func() {
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
	}()
	defer func() {
		if recover() == nil {
			t.Fatal("did not recover from panic")
		}
	}()
	panic(1)
}

func TestCallersAbortedPanic(t *testing.T) {
	want := []string{"runtime.Callers", "runtime_test.TestCallersAbortedPanic.func2", "runtime_test.TestCallersAbortedPanic"}

	defer func() {
		r := recover()
		if r != nil {
			t.Fatalf("should be no panic remaining to recover")
		}
	}()

	defer func() {
		// panic2 was aborted/replaced by panic1, so when panic2 was
		// recovered, there is no remaining panic on the stack.
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
	}()
	defer func() {
		r := recover()
		if r != "panic2" {
			t.Fatalf("got %v, wanted %v", r, "panic2")
		}
	}()
	defer func() {
		// panic2 aborts/replaces panic1, because it is a recursive panic
		// that is not recovered within the defer function called by
		// panic1 panicking sequence
		panic("panic2")
	}()
	panic("panic1")
}

func TestCallersAbortedPanic2(t *testing.T) {
	want := []string{"runtime.Callers", "runtime_test.TestCallersAbortedPanic2.func2", "runtime_test.TestCallersAbortedPanic2"}
	defer func() {
		r := recover()
		if r != nil {
			t.Fatalf("should be no panic remaining to recover")
		}
	}()
	defer func() {
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
	}()
	func() {
		defer func() {
			r := recover()
			if r != "panic2" {
				t.Fatalf("got %v, wanted %v", r, "panic2")
			}
		}()
		func() {
			defer func() {
				// Again, panic2 aborts/replaces panic1
				panic("panic2")
			}()
			panic("panic1")
		}()
	}()
}

func TestCallersNilPointerPanic(t *testing.T) {
	// Make sure we don't have any extra frames on the stack (due to
	// open-coded defer processing)
	want := []string{"runtime.Callers", "runtime_test.TestCallersNilPointerPanic.func1",
		"runtime.gopanic", "runtime.panicmem", "runtime.sigpanic",
		"runtime_test.TestCallersNilPointerPanic"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("did not panic")
		}
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
	}()
	var p *int
	if *p == 3 {
		t.Fatal("did not see nil pointer panic")
	}
}

func TestCallersDivZeroPanic(t *testing.T) {
	// Make sure we don't have any extra frames on the stack (due to
	// open-coded defer processing)
	want := []string{"runtime.Callers", "runtime_test.TestCallersDivZeroPanic.func1",
		"runtime.gopanic", "runtime.panicdivide",
		"runtime_test.TestCallersDivZeroPanic"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("did not panic")
		}
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
	}()
	var n int
	if 5/n == 1 {
		t.Fatal("did not see divide-by-sizer panic")
	}
}

func TestCallersDeferNilFuncPanic(t *testing.T) {
	// Make sure we don't have any extra frames on the stack. We cut off the check
	// at runtime.sigpanic, because non-open-coded defers (which may be used in
	// non-opt or race checker mode) include an extra 'deferreturn' frame (which is
	// where the nil pointer deref happens).
	state := 1
	want := []string{"runtime.Callers", "runtime_test.TestCallersDeferNilFuncPanic.func1",
		"runtime.gopanic", "runtime.panicmem", "runtime.sigpanic"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("did not panic")
		}
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
		if state == 1 {
			t.Fatal("nil defer func panicked at defer time rather than function exit time")
		}

	}()
	var f func()
	defer f()
	// Use the value of 'state' to make sure nil defer func f causes panic at
	// function exit, rather than at the defer statement.
	state = 2
}

// Same test, but forcing non-open-coded defer by putting the defer in a loop.  See
// issue #36050
func TestCallersDeferNilFuncPanicWithLoop(t *testing.T) {
	state := 1
	want := []string{"runtime.Callers", "runtime_test.TestCallersDeferNilFuncPanicWithLoop.func1",
		"runtime.gopanic", "runtime.panicmem", "runtime.sigpanic", "runtime.deferreturn", "runtime_test.TestCallersDeferNilFuncPanicWithLoop"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("did not panic")
		}
		pcs := make([]uintptr, 20)
		pcs = pcs[:runtime.Callers(0, pcs)]
		testCallersEqual(t, pcs, want)
		if state == 1 {
			t.Fatal("nil defer func panicked at defer time rather than function exit time")
		}

	}()

	for i := 0; i < 1; i++ {
		var f func()
		defer f()
	}
	// Use the value of 'state' to make sure nil defer func f causes panic at
	// function exit, rather than at the defer statement.
	state = 2
}

// issue #51988
// Func.Endlineno was lost when instantiating generic functions, leading to incorrect
// stack trace positions.
func TestCallersEndlineno(t *testing.T) {
	testNormalEndlineno(t)
	testGenericEndlineno[int](t)
}

func testNormalEndlineno(t *testing.T) {
	defer testCallerLine(t, callerLine(t, 0)+1)
}

func testGenericEndlineno[_ any](t *testing.T) {
	defer testCallerLine(t, callerLine(t, 0)+1)
}

func testCallerLine(t *testing.T, want int) {
	if have := callerLine(t, 1); have != want {
		t.Errorf("callerLine(1) returned %d, but want %d\n", have, want)
	}
}

func callerLine(t *testing.T, skip int) int {
	_, _, line, ok := runtime.Caller(skip + 1)
	if !ok {
		t.Fatalf("runtime.Caller(%d) failed", skip+1)
	}
	return line
}

func BenchmarkCallers(b *testing.B) {
	b.Run("cached", func(b *testing.B) {
		// Very pcvalueCache-friendly, no inlining.
		callersCached(b, 100)
	})
	b.Run("inlined", func(b *testing.B) {
		// Some inlining, still pretty cache-friendly.
		callersInlined(b, 100)
	})
	b.Run("no-cache", func(b *testing.B) {
		// Cache-hostile
		callersNoCache(b, 100)
	})
}

func callersCached(b *testing.B, n int) int {
	if n <= 0 {
		pcs := make([]uintptr, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.Callers(0, pcs)
		}
		b.StopTimer()
		return 0
	}
	return 1 + callersCached(b, n-1)
}

func callersInlined(b *testing.B, n int) int {
	if n <= 0 {
		pcs := make([]uintptr, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.Callers(0, pcs)
		}
		b.StopTimer()
		return 0
	}
	return 1 + callersInlined1(b, n-1)
}
func callersInlined1(b *testing.B, n int) int { return callersInlined2(b, n) }
func callersInlined2(b *testing.B, n int) int { return callersInlined3(b, n) }
func callersInlined3(b *testing.B, n int) int { return callersInlined4(b, n) }
func callersInlined4(b *testing.B, n int) int { return callersInlined(b, n) }

func callersNoCache(b *testing.B, n int) int {
	if n <= 0 {
		pcs := make([]uintptr, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.Callers(0, pcs)
		}
		b.StopTimer()
		return 0
	}
	switch n % 16 {
	case 0:
		return 1 + callersNoCache(b, n-1)
	case 1:
		return 1 + callersNoCache(b, n-1)
	case 2:
		return 1 + callersNoCache(b, n-1)
	case 3:
		return 1 + callersNoCache(b, n-1)
	case 4:
		return 1 + callersNoCache(b, n-1)
	case 5:
		return 1 + callersNoCache(b, n-1)
	case 6:
		return 1 + callersNoCache(b, n-1)
	case 7:
		return 1 + callersNoCache(b, n-1)
	case 8:
		return 1 + callersNoCache(b, n-1)
	case 9:
		return 1 + callersNoCache(b, n-1)
	case 10:
		return 1 + callersNoCache(b, n-1)
	case 11:
		return 1 + callersNoCache(b, n-1)
	case 12:
		return 1 + callersNoCache(b, n-1)
	case 13:
		return 1 + callersNoCache(b, n-1)
	case 14:
		return 1 + callersNoCache(b, n-1)
	default:
		return 1 + callersNoCache(b, n-1)
	}
}

func BenchmarkFPCallers(b *testing.B) {
	b.Run("cached", func(b *testing.B) {
		// Very pcvalueCache-friendly, no inlining.
		fpCallersCached(b, 100)
	})
}

func fpCallersCached(b *testing.B, n int) int {
	if n <= 0 {
		pcs := make([]uintptr, 32)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			runtime.FPCallers(pcs)
		}
		b.StopTimer()
		return 0
	}
	return 1 + fpCallersCached(b, n-1)
}

func TestFPUnwindAfterRecovery(t *testing.T) {
	if !runtime.FramePointerEnabled {
		t.Skip("frame pointers not supported for this architecture")
	}
	// Make sure that frame pointer unwinding succeeds from a deferred
	// function run after recovering from a panic. It can fail if the
	// recovery does not properly restore the caller's frame pointer before
	// running the remaining deferred functions.
	//
	// This test does not verify the accuracy of the call stack (it
	// currently includes a frame from runtime.deferreturn which would
	// normally be omitted). It is only intended to check that producing the
	// call stack won't crash.
	defer func() {
		pcs := make([]uintptr, 32)
		for i := range pcs {
			// If runtime.recovery doesn't properly restore the
			// frame pointer before returning control to this
			// function, it will point somewhere lower in the stack
			// from one of the frames of runtime.gopanic() or one of
			// it's callees prior to recovery.  So, we put some
			// non-zero values on the stack to ensure that frame
			// pointer unwinding will crash if it sees the old,
			// invalid frame pointer.
			pcs[i] = 10
		}
		runtime.FPCallers(pcs)
		t.Logf("%v", pcs)
	}()
	defer func() {
		if recover() == nil {
			t.Fatal("did not recover from panic")
		}
	}()
	panic(1)
}
```