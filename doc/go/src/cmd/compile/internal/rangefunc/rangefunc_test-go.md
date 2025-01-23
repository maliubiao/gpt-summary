Response: Let's break down the thought process for analyzing this Go test file.

1. **Understand the Context:** The filename `rangefunc_test.go` and the package name `rangefunc_test` immediately suggest this code is testing some functionality related to "range functions." The presence of a `internal` directory in the path hints that this might be a feature under development or an internal optimization within the Go compiler.

2. **Identify Key Types and Functions:**  Scan the code for prominent type definitions and function signatures. The `Seq[T]` and `Seq2[T1, T2]` types are clearly central, representing functions that iterate and yield values. The functions like `OfSliceIndex`, `BadOfSliceIndex`, `VeryBadOfSliceIndex`, etc., look like different ways of creating these sequence generators.

3. **Analyze the `Seq` and `Seq2` Types:** These are function types that take a `yield` function as an argument. The `yield` function is the mechanism for producing the values in the sequence. The return type of `yield` (`bool`) is crucial – it indicates whether the iteration should continue. This immediately brings to mind the standard `range` loop in Go.

4. **Examine the `OfSliceIndex` Function:**  This function closely mirrors the behavior of `range` on a slice, returning both the index and the value. This is a strong clue that the code is exploring how `range` might be implemented or how custom iteration patterns could be created.

5. **Study the "Bad" Variations:** The functions like `BadOfSliceIndex`, `VeryBadOfSliceIndex`, `SwallowPanicOfSliceIndex`, and `PanickyOfSliceIndex` are deliberately written to violate expected behavior of iterators. They either ignore the `yield` return value or introduce panics. This strongly suggests that the tests are designed to verify how the Go runtime handles or detects misbehaving iterators, specifically in the context of the `range` loop.

6. **Recognize the Testing Framework:** The `import "testing"` and the presence of functions starting with `Test` indicate standard Go testing practices.

7. **Understand the `Check` Functions:** The `Check` and `Check2` functions are wrappers around the sequence generators. They introduce state tracking and panics if the loop body is called at unexpected times (after `break`, `return`, or iterator completion). This is a mechanism to *enforce* the correct behavior of the loop body and detect if an iterator is incorrectly continuing after it should have stopped.

8. **Infer the Goal:** Combining the observations, a likely goal of this code is to explore and test different implementations and behaviors of iteration in Go, potentially as part of a feature like "range functions" (as suggested by the path). The "bad" iterators serve as edge cases to ensure robustness and correctness of the core iteration mechanism. The `Check` functions provide a way to explicitly verify the expected control flow within `range` loops.

9. **Formulate an Explanation of the Functionality:** Based on the analysis, describe the core components: sequence generators (`Seq`, `Seq2`), standard and "bad" implementations, and the `Check` wrappers for verification.

10. **Infer the Go Language Feature:** The strong resemblance of `OfSliceIndex` to the standard `range` loop, combined with the testing of various iterator behaviors (including how breaks, continues, returns, and panics are handled), makes it highly probable that this code is related to the implementation or potential extensions of the `range` keyword in Go.

11. **Construct Go Code Examples:**  Demonstrate the standard `range` loop and compare it with the `OfSliceIndex` function to highlight the similarity. Then, show how the "bad" iterators violate the expected behavior.

12. **Address Code Reasoning (Assumptions and I/O):**  For the "bad" iterator examples, explicitly state the assumptions about how the `yield` return value should be handled and illustrate the incorrect output when these assumptions are violated.

13. **Consider Command-Line Arguments:**  Since this is a test file and doesn't directly involve running a standalone program, command-line arguments are unlikely to be directly processed within this file itself. The `go test` command is used to execute these tests, but the file's code doesn't parse command-line arguments in the way a typical application would.

14. **Identify Potential Pitfalls:** Focus on the core misunderstanding that the `yield` function's return value controls iteration. Illustrate this with the `BadOfSliceIndex` example, showcasing how ignoring the return value leads to unexpected behavior.

15. **Review and Refine:**  Read through the explanation, code examples, and potential pitfalls to ensure clarity, accuracy, and completeness. Make sure the connections between the different parts of the code and the inferred Go feature are clearly explained. For instance, explicitly mentioning how the `Check` functions act as assertions for the `range` loop's control flow.
这个Go语言文件 `go/src/cmd/compile/internal/rangefunc/rangefunc_test.go` 的主要功能是**测试与 “range function” 相关的 Go 语言特性**。

**具体功能分解:**

1. **定义了迭代器类型:**
   - `Seq[T any] func(yield func(T) bool)`:  定义了一个泛型函数类型 `Seq`，它代表一个可以产生 `T` 类型元素的序列。它接收一个 `yield` 函数作为参数。`yield` 函数用于产生序列中的元素，并返回一个布尔值，指示是否继续迭代。
   - `Seq2[T1, T2 any] func(yield func(T1, T2) bool)`: 类似 `Seq`，但产生两个类型 `T1` 和 `T2` 的元素。

2. **实现了不同的序列生成器:**
   - `OfSliceIndex[T any, S ~[]T](s S) Seq2[int, T]`:  这是一个“好”的序列生成器，它模拟了 `range` 关键字在切片上的行为，产生索引和值。它会检查 `yield` 的返回值，并在 `yield` 返回 `false` 时停止迭代。
   - `BadOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T]`:  这是一个“坏”的序列生成器，它忽略了 `yield` 的返回值，会一直迭代到切片结束。
   - `VeryBadOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T]`:  这是一个“非常坏”的序列生成器，不仅忽略了 `yield` 的返回值，还使用 `defer-recover` 包裹了 `yield` 的调用，即使 `yield` 内部发生 panic 也会继续迭代。
   - `SwallowPanicOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T]`:  这个生成器会捕获 `yield` 中发生的 panic，并将其转换为正常的返回（停止迭代）。
   - `PanickyOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T]`:  如果循环提前退出（`yield` 返回 `false`），这个生成器会触发 panic。
   - `CooperativeBadOfSliceIndex[T any, S ~[]T](s S, proceed chan any) Seq2[int, T]`: 这个生成器在一个 goroutine 中调用 `yield`，用于测试并发场景下的行为。
   - `TrickyIterator` 结构体及其方法 (`iterEcho`, `iterAll`, `iterOne`, `iterZero`, `fail`):  用于测试更复杂的迭代器行为，例如在循环结束后调用 `yield`。

3. **定义了用于检查迭代器行为的辅助函数:**
   - `Check2[U, V any](forall Seq2[U, V]) Seq2[U, V]`:  这是一个高阶函数，它包装了序列生成器 `forall`。它会在 `yield` 函数被调用时检查状态，以确保迭代器不会在不应该的时候继续迭代（例如在循环体返回 `false` 之后或迭代结束后）。如果检测到错误行为，会触发 panic。
   - `Check[U any](forall Seq[U]) Seq[U]`:  类似于 `Check2`，但用于 `Seq` 类型的迭代器。

4. **定义了用于匹配错误信息的辅助函数:**
   - `matchError(r any, x string) bool`:  用于检查 recover 捕获的错误信息是否符合预期，支持正则表达式匹配。
   - `matchErrorHelper(t *testing.T, r any, x string)`:  `matchError` 的测试辅助函数，用于记录日志或报告错误。

5. **定义了错误常量:**
   - `RERR_...`:  表示运行时错误，用于检查由于“坏”迭代器导致的运行时 panic。
   - `CERR_...`:  表示由 `Check` 函数检测到的错误。
   - `fail`:  存储了由 `Check` 函数触发的错误对象。

6. **包含了大量的测试用例 (以 `Test...` 开头的函数):**
   这些测试用例涵盖了各种场景，包括：
   - 正常的迭代行为 (`TestNoVars`, `TestBreak1`, `TestBreak2`, `TestContinue`, `TestBreak3`).
   - “坏”迭代器的行为以及 `Check` 函数的检测能力 (`TestCheck`, `TestCooperativeBadOfSliceIndex`, `TestCooperativeBadOfSliceIndexCheck`, `TestBreak1BadA`, `TestBreak1BadB`, `TestMultiCont*`, `TestMultiBreak*`).
   - 带有 `break`、`continue` 和 `goto` 语句的循环与“坏”迭代器的交互 (`TestBreak1BadA`, `TestBreak1BadB`, `TestMultiCont*`, `TestMultiBreak*`, `TestGotoA*`, `TestGotoB*`).
   - 带有 `panic` 和 `recover` 的迭代器行为 (`TestPanickyIterator*`, `TestVeryBad*`).
   - `defer` 语句在包含“坏”迭代器的循环中的行为 (`TestBreak1BadDefer`).
   - `return` 语句在包含“坏”迭代器的循环中的行为 (`TestReturns`).
   - 匿名函数和闭包在迭代器中的使用 (`TestPanicReturns`).
   - 在循环体 `panic` 之后是否会继续执行 (`TestRunBodyAfterPanic*`).
   - 多层循环和 `return` 语句的交互 (`TestTwoLevelReturn*`).
   - 更复杂的嵌套循环场景 (`Test70035`).

**推断 Go 语言功能实现:**

根据代码的结构和测试用例，可以推断出这个文件是用于测试 **Go 语言中 "range over function" 或类似特性的实现**。

传统的 `range` 关键字可以用于遍历数组、切片、字符串、map 和 channel。这里定义的 `Seq` 和 `Seq2` 类型以及相关的生成器函数，很可能是在探索或者实现一种新的 `range` 迭代方式，允许用户自定义迭代逻辑，通过提供一个生成元素的函数（`yield`）。

**Go 代码举例说明:**

假设 "range function" 的语法可能是这样的：

```go
package main

import "fmt"

// 定义一个生成偶数的序列
func Evens(yield func(int) bool) {
	for i := 0; ; i += 2 {
		if !yield(i) {
			return
		}
	}
}

func main() {
	// 使用 "range function" 遍历偶数序列
	for x := range Evens {
		fmt.Println(x)
		if x >= 10 {
			break
		}
	}
}
```

**假设输入与输出:**

在上面的例子中，`Evens` 函数就是一个 `Seq[int]` 的实现。当运行 `main` 函数时，预期输出为：

```
0
2
4
6
8
10
```

**命令行参数的具体处理:**

这个测试文件本身不直接处理命令行参数。它是作为 `go test` 命令的一部分运行的。`go test` 命令会编译并运行测试函数。你可以使用 `go test` 的各种标志来控制测试的执行，例如：

- `-v`:  显示所有测试的详细输出。
- `-run <regexp>`:  只运行匹配指定正则表达式的测试函数。
- `-bench <regexp>`:  运行性能测试。
- `-coverprofile <file>`:  生成代码覆盖率报告。

例如，要运行 `rangefunc_test.go` 文件中的所有测试，可以在该文件所在的目录下执行：

```bash
go test -v ./go/src/cmd/compile/internal/rangefunc/
```

要只运行名为 `TestBreak1` 的测试，可以执行：

```bash
go test -v -run TestBreak1 ./go/src/cmd/compile/internal/rangefunc/
```

**使用者易犯错的点:**

对于假设的 "range function" 特性，使用者容易犯错的点可能包括：

1. **忘记检查 `yield` 的返回值:**  就像 `BadOfSliceIndex` 的例子一样，如果自定义的序列生成器没有检查 `yield` 的返回值，就无法响应循环中的 `break` 或提前退出，可能导致无限循环或非预期的行为。

   ```go
   func BadEvens(yield func(int) bool) {
       for i := 0; ; i += 2 {
           yield(i) // 忘记检查 yield 的返回值
       }
   }

   func main() {
       for x := range BadEvens {
           fmt.Println(x)
           if x >= 10 {
               break // 这将不会生效，BadEvens 会一直生成偶数
           }
       }
       fmt.Println("Loop finished (or not?)") // 这行代码可能永远不会执行到
   }
   ```

   **预期输出（可能会一直运行或崩溃）：**
   ```
   0
   2
   4
   6
   8
   10
   12
   14
   ... // 无限输出
   ```

2. **在 `yield` 中或之后修改已经 yield 的值 (如果适用):**  如果 "range function" 的实现缓存了 `yield` 出去的值，并在后续使用，那么在 `yield` 返回后修改这些值可能会导致数据竞争或不可预测的结果。这需要根据具体的实现来判断。

3. **在 `yield` 中执行耗时或有副作用的操作，并且没有正确处理提前退出的情况:** 如果 `yield` 函数中包含昂贵的操作，并且循环可能提前退出，那么这些操作可能会在不需要的时候执行，影响性能。

4. **不理解 `Check` 函数的作用:**  在测试自定义的序列生成器时，如果直接使用而没有用 `Check` 或 `Check2` 包裹，可能无法及时发现一些细微的错误，例如在循环结束后仍然调用 `yield`。

总而言之，这个测试文件是 Go 语言编译器内部 `rangefunc` 功能的测试代码，旨在验证该功能在各种正常和异常情况下的行为，包括与 `break`、`continue`、`return`、`goto` 和 `panic` 的交互。它通过定义不同的序列生成器（包括“坏”的实现）和检查机制来确保该功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/rangefunc/rangefunc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rangefunc_test

import (
	"fmt"
	"regexp"
	"slices"
	"testing"
)

type Seq[T any] func(yield func(T) bool)
type Seq2[T1, T2 any] func(yield func(T1, T2) bool)

// OfSliceIndex returns a Seq2 over the elements of s. It is equivalent
// to range s.
func OfSliceIndex[T any, S ~[]T](s S) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			if !yield(i, v) {
				return
			}
		}
		return
	}
}

// BadOfSliceIndex is "bad" because it ignores the return value from yield
// and just keeps on iterating.
func BadOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			yield(i, v)
		}
		return
	}
}

// VeryBadOfSliceIndex is "very bad" because it ignores the return value from yield
// and just keeps on iterating, and also wraps that call in a defer-recover so it can
// keep on trying after the first panic.
func VeryBadOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			func() {
				defer func() {
					recover()
				}()
				yield(i, v)
			}()
		}
		return
	}
}

// SwallowPanicOfSliceIndex hides panics and converts them to normal return
func SwallowPanicOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			done := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						done = true
					}
				}()
				done = !yield(i, v)
			}()
			if done {
				return
			}
		}
		return
	}
}

// PanickyOfSliceIndex iterates the slice but panics if it exits the loop early
func PanickyOfSliceIndex[T any, S ~[]T](s S) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			if !yield(i, v) {
				panic(fmt.Errorf("Panicky iterator panicking"))
			}
		}
		return
	}
}

// CooperativeBadOfSliceIndex calls the loop body from a goroutine after
// a ping on a channel, and returns recover()on that same channel.
func CooperativeBadOfSliceIndex[T any, S ~[]T](s S, proceed chan any) Seq2[int, T] {
	return func(yield func(int, T) bool) {
		for i, v := range s {
			if !yield(i, v) {
				// if the body breaks, call yield just once in a goroutine
				go func() {
					<-proceed
					defer func() {
						proceed <- recover()
					}()
					yield(0, s[0])
				}()
				return
			}
		}
		return
	}
}

// TrickyIterator is a type intended to test whether an iterator that
// calls a yield function after loop exit must inevitably escape the
// closure; this might be relevant to future checking/optimization.
type TrickyIterator struct {
	yield func(int, int) bool
}

func (ti *TrickyIterator) iterEcho(s []int) Seq2[int, int] {
	return func(yield func(int, int) bool) {
		for i, v := range s {
			if !yield(i, v) {
				ti.yield = yield
				return
			}
			if ti.yield != nil && !ti.yield(i, v) {
				return
			}
		}
		ti.yield = yield
		return
	}
}

func (ti *TrickyIterator) iterAll(s []int) Seq2[int, int] {
	return func(yield func(int, int) bool) {
		ti.yield = yield // Save yield for future abuse
		for i, v := range s {
			if !yield(i, v) {
				return
			}
		}
		return
	}
}

func (ti *TrickyIterator) iterOne(s []int) Seq2[int, int] {
	return func(yield func(int, int) bool) {
		ti.yield = yield // Save yield for future abuse
		if len(s) > 0 {  // Not in a loop might escape differently
			yield(0, s[0])
		}
		return
	}
}

func (ti *TrickyIterator) iterZero(s []int) Seq2[int, int] {
	return func(yield func(int, int) bool) {
		ti.yield = yield // Save yield for future abuse
		// Don't call it at all, maybe it won't escape
		return
	}
}

func (ti *TrickyIterator) fail() {
	if ti.yield != nil {
		ti.yield(1, 1)
	}
}

const DONE = 0      // body of loop has exited in a non-panic way
const READY = 1     // body of loop has not exited yet, is not running
const PANIC = 2     // body of loop is either currently running, or has panicked
const EXHAUSTED = 3 // iterator function return, i.e., sequence is "exhausted"

const MISSING_PANIC = 4 // overload "READY" for panic call

// Check2 wraps the function body passed to iterator forall
// in code that ensures that it cannot (successfully) be called
// either after body return false (control flow out of loop) or
// forall itself returns (the iteration is now done).
//
// Note that this can catch errors before the inserted checks.
func Check2[U, V any](forall Seq2[U, V]) Seq2[U, V] {
	return func(body func(U, V) bool) {
		state := READY
		forall(func(u U, v V) bool {
			tmp := state
			state = PANIC
			if tmp != READY {
				panic(fail[tmp])
			}
			ret := body(u, v)
			if ret {
				state = READY
			} else {
				state = DONE
			}
			return ret
		})
		if state == PANIC {
			panic(fail[MISSING_PANIC])
		}
		state = EXHAUSTED
	}
}

func Check[U any](forall Seq[U]) Seq[U] {
	return func(body func(U) bool) {
		state := READY
		forall(func(u U) bool {
			tmp := state
			state = PANIC
			if tmp != READY {
				panic(fail[tmp])
			}
			ret := body(u)
			if ret {
				state = READY
			} else {
				state = DONE
			}
			return ret
		})
		if state == PANIC {
			panic(fail[MISSING_PANIC])
		}
		state = EXHAUSTED
	}
}

func matchError(r any, x string) bool {
	if r == nil {
		return false
	}
	if x == "" {
		return true
	}
	if p, ok := r.(errorString); ok {
		return p.Error() == x
	}
	if p, ok := r.(error); ok {
		e, err := regexp.Compile(x)
		if err != nil {
			panic(fmt.Errorf("Bad regexp '%s' passed to matchError", x))
		}
		return e.MatchString(p.Error())
	}
	return false
}

func matchErrorHelper(t *testing.T, r any, x string) {
	if matchError(r, x) {
		t.Logf("Saw expected panic '%v'", r)
	} else {
		t.Errorf("Saw wrong panic '%v', expected '%s'", r, x)
	}
}

// An errorString represents a runtime error described by a single string.
type errorString string

func (e errorString) Error() string {
	return string(e)
}

const (
	// RERR_ is for runtime error, and may be regexps/substrings, to simplify use of tests with tools
	RERR_DONE      = "runtime error: range function continued iteration after function for loop body returned false"
	RERR_PANIC     = "runtime error: range function continued iteration after loop body panic"
	RERR_EXHAUSTED = "runtime error: range function continued iteration after whole loop exit"
	RERR_MISSING   = "runtime error: range function recovered a loop body panic and did not resume panicking"

	// CERR_ is for checked errors in the Check combinator defined above, and should be literal strings
	CERR_PFX       = "checked rangefunc error: "
	CERR_DONE      = CERR_PFX + "loop iteration after body done"
	CERR_PANIC     = CERR_PFX + "loop iteration after panic"
	CERR_EXHAUSTED = CERR_PFX + "loop iteration after iterator exit"
	CERR_MISSING   = CERR_PFX + "loop iterator swallowed panic"
)

var fail []error = []error{
	errorString(CERR_DONE),
	errorString(CERR_PFX + "loop iterator, unexpected error"),
	errorString(CERR_PANIC),
	errorString(CERR_EXHAUSTED),
	errorString(CERR_MISSING),
}

// TestNoVars ensures that versions of rangefunc that use zero or one
// iteration variable (instead of two) run the proper number of times
// and in the one variable case supply the proper values.
// For #65236.
func TestNoVars(t *testing.T) {
	i, k := 0, 0
	for range Check2(OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
		i++
	}
	for j := range Check2(OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
		k += j
	}
	if i != 10 {
		t.Errorf("Expected 10, got %d", i)
	}
	if k != 45 {
		t.Errorf("Expected 45, got %d", k)
	}
}

func TestCheck(t *testing.T) {
	i := 0
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()
	for _, x := range Check2(BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
		i += x
		if i > 4*9 {
			break
		}
	}
}

func TestCooperativeBadOfSliceIndex(t *testing.T) {
	i := 0
	proceed := make(chan any)
	for _, x := range CooperativeBadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, proceed) {
		i += x
		if i >= 36 {
			break
		}
	}
	proceed <- true
	if r := <-proceed; r != nil {
		if matchError(r, RERR_EXHAUSTED) {
			t.Logf("Saw expected panic '%v'", r)
		} else {
			t.Errorf("Saw wrong panic '%v'", r)
		}
	} else {
		t.Error("Wanted to see a failure")
	}
	if i != 36 {
		t.Errorf("Expected i == 36, saw %d instead", i)
	} else {
		t.Logf("i = %d", i)
	}
}

func TestCooperativeBadOfSliceIndexCheck(t *testing.T) {
	i := 0
	proceed := make(chan any)
	for _, x := range Check2(CooperativeBadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, proceed)) {
		i += x
		if i >= 36 {
			break
		}
	}
	proceed <- true
	if r := <-proceed; r != nil {
		if matchError(r, CERR_EXHAUSTED) {
			t.Logf("Saw expected panic '%v'", r)
		} else {
			t.Errorf("Saw wrong panic '%v'", r)
		}

	} else {
		t.Error("Wanted to see a failure")
	}
	if i != 36 {
		t.Errorf("Expected i == 36, saw %d instead", i)
	} else {
		t.Logf("i = %d", i)
	}
}

func TestTrickyIterAll(t *testing.T) {
	trickItAll := TrickyIterator{}
	i := 0
	for _, x := range trickItAll.iterAll([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		i += x
		if i >= 36 {
			break
		}
	}

	if i != 36 {
		t.Errorf("Expected i == 36, saw %d instead", i)
	} else {
		t.Logf("i = %d", i)
	}

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	trickItAll.fail()
}

func TestTrickyIterOne(t *testing.T) {
	trickItOne := TrickyIterator{}
	i := 0
	for _, x := range trickItOne.iterOne([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		i += x
		if i >= 36 {
			break
		}
	}

	// Don't care about value, ought to be 36 anyhow.
	t.Logf("i = %d", i)

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	trickItOne.fail()
}

func TestTrickyIterZero(t *testing.T) {
	trickItZero := TrickyIterator{}
	i := 0
	for _, x := range trickItZero.iterZero([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		i += x
		if i >= 36 {
			break
		}
	}

	// Don't care about value, ought to be 0 anyhow.
	t.Logf("i = %d", i)

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	trickItZero.fail()
}

func TestTrickyIterZeroCheck(t *testing.T) {
	trickItZero := TrickyIterator{}
	i := 0
	for _, x := range Check2(trickItZero.iterZero([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})) {
		i += x
		if i >= 36 {
			break
		}
	}

	// Don't care about value, ought to be 0 anyhow.
	t.Logf("i = %d", i)

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	trickItZero.fail()
}

func TestTrickyIterEcho(t *testing.T) {
	trickItAll := TrickyIterator{}
	i := 0
	for _, x := range trickItAll.iterAll([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Logf("first loop i=%d", i)
		i += x
		if i >= 10 {
			break
		}
	}

	if i != 10 {
		t.Errorf("Expected i == 10, saw %d instead", i)
	} else {
		t.Logf("i = %d", i)
	}

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	i = 0
	for _, x := range trickItAll.iterEcho([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Logf("second loop i=%d", i)
		if x >= 5 {
			break
		}
	}

}

func TestTrickyIterEcho2(t *testing.T) {
	trickItAll := TrickyIterator{}
	var i int

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_EXHAUSTED) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	for k := range 2 {
		i = 0
		for _, x := range trickItAll.iterEcho([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			t.Logf("k,x,i=%d,%d,%d", k, x, i)
			i += x
			if i >= 10 {
				break
			}
		}
		t.Logf("i = %d", i)

		if i != 10 {
			t.Errorf("Expected i == 10, saw %d instead", i)
		}
	}
}

// TestBreak1 should just work, with well-behaved iterators.
// (The misbehaving iterator detector should not trigger.)
func TestBreak1(t *testing.T) {
	var result []int
	var expect = []int{1, 2, -1, 1, 2, -2, 1, 2, -3}
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4}) {
		if x == -4 {
			break
		}
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				break
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestBreak2 should just work, with well-behaved iterators.
// (The misbehaving iterator detector should not trigger.)
func TestBreak2(t *testing.T) {
	var result []int
	var expect = []int{1, 2, -1, 1, 2, -2, 1, 2, -3}
outer:
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4}) {
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				break
			}
			if x == -4 {
				break outer
			}

			result = append(result, y)
		}
		result = append(result, x)
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestContinue should just work, with well-behaved iterators.
// (The misbehaving iterator detector should not trigger.)
func TestContinue(t *testing.T) {
	var result []int
	var expect = []int{-1, 1, 2, -2, 1, 2, -3, 1, 2, -4}
outer:
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4}) {
		result = append(result, x)
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				continue outer
			}
			if x == -4 {
				break outer
			}

			result = append(result, y)
		}
		result = append(result, x-10)
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestBreak3 should just work, with well-behaved iterators.
// (The misbehaving iterator detector should not trigger.)
func TestBreak3(t *testing.T) {
	var result []int
	var expect = []int{100, 10, 2, 4, 200, 10, 2, 4, 20, 2, 4, 300, 10, 2, 4, 20, 2, 4, 30}
X:
	for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
	Y:
		for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
			if 10*y >= x {
				break
			}
			result = append(result, y)
			if y == 30 {
				continue X
			}
		Z:
			for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
				if z&1 == 1 {
					continue Z
				}
				result = append(result, z)
				if z >= 4 {
					continue Y
				}
			}
			result = append(result, -y) // should never be executed
		}
		result = append(result, x)
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestBreak1BadA should end in a panic when the outer-loop's
// single-level break is ignore by BadOfSliceIndex
func TestBreak1BadA(t *testing.T) {
	var result []int
	var expect = []int{1, 2, -1, 1, 2, -2, 1, 2, -3}

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	for _, x := range BadOfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		if x == -4 {
			break
		}
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				break
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
}

// TestBreak1BadB should end in a panic, sooner, when the inner-loop's
// (nested) single-level break is ignored by BadOfSliceIndex
func TestBreak1BadB(t *testing.T) {
	var result []int
	var expect = []int{1, 2} // inner breaks, panics, after before outer appends

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		if x == -4 {
			break
		}
		for _, y := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				break
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
}

// TestMultiCont0 tests multilevel continue with no bad iterators
// (it should just work)
func TestMultiCont0(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4, 2000}

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						continue W // modified to be multilevel
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiCont1 tests multilevel continue with a bad iterator
// in the outermost loop exited by the continue.
func TestMultiCont1(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range BadOfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						continue W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiCont2 tests multilevel continue with a bad iterator
// in a middle loop exited by the continue.
func TestMultiCont2(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range BadOfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						continue W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiCont3 tests multilevel continue with a bad iterator
// in the innermost loop exited by the continue.
func TestMultiCont3(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						continue W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiBreak0 tests multilevel break with a bad iterator
// in the outermost loop exited by the break (the outermost loop).
func TestMultiBreak0(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range BadOfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						break W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiBreak1 tests multilevel break with a bad iterator
// in an intermediate loop exited by the break.
func TestMultiBreak1(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range BadOfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						break W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiBreak2 tests multilevel break with two bad iterators
// in intermediate loops exited by the break.
func TestMultiBreak2(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range BadOfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range BadOfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						break W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// TestMultiBreak3 tests multilevel break with the bad iterator
// in the innermost loop exited by the break.
func TestMultiBreak3(t *testing.T) {
	var result []int
	var expect = []int{1000, 10, 2, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()

W:
	for _, w := range OfSliceIndex([]int{1000, 2000}) {
		result = append(result, w)
		if w == 2000 {
			break
		}
		for _, x := range OfSliceIndex([]int{100, 200, 300, 400}) {
			for _, y := range OfSliceIndex([]int{10, 20, 30, 40}) {
				result = append(result, y)
				for _, z := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
					if z&1 == 1 {
						continue
					}
					result = append(result, z)
					if z >= 4 {
						break W
					}
				}
				result = append(result, -y) // should never be executed
			}
			result = append(result, x)
		}
	}
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

func TestPanickyIterator1(t *testing.T) {
	var result []int
	var expect = []int{1, 2, 3, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, "Panicky iterator panicking") {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()
	for _, z := range PanickyOfSliceIndex([]int{1, 2, 3, 4}) {
		result = append(result, z)
		if z == 4 {
			break
		}
	}
}

func TestPanickyIterator1Check(t *testing.T) {
	var result []int
	var expect = []int{1, 2, 3, 4}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, "Panicky iterator panicking") {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()
	for _, z := range Check2(PanickyOfSliceIndex([]int{1, 2, 3, 4})) {
		result = append(result, z)
		if z == 4 {
			break
		}
	}
}

func TestPanickyIterator2(t *testing.T) {
	var result []int
	var expect = []int{100, 10, 1, 2}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a failure, result was %v", result)
		}
	}()
	for _, x := range OfSliceIndex([]int{100, 200}) {
		result = append(result, x)
	Y:
		// swallows panics and iterates to end BUT `break Y` disables the body, so--> 10, 1, 2
		for _, y := range VeryBadOfSliceIndex([]int{10, 20}) {
			result = append(result, y)

			// converts early exit into a panic --> 1, 2
			for k, z := range PanickyOfSliceIndex([]int{1, 2}) { // iterator panics
				result = append(result, z)
				if k == 1 {
					break Y
				}
			}
		}
	}
}

func TestPanickyIterator2Check(t *testing.T) {
	var result []int
	var expect = []int{100, 10, 1, 2}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a panic, result was %v", result)
		}
	}()
	for _, x := range Check2(OfSliceIndex([]int{100, 200})) {
		result = append(result, x)
	Y:
		// swallows panics and iterates to end BUT `break Y` disables the body, so--> 10, 1, 2
		for _, y := range Check2(VeryBadOfSliceIndex([]int{10, 20})) {
			result = append(result, y)

			// converts early exit into a panic --> 1, 2
			for k, z := range Check2(PanickyOfSliceIndex([]int{1, 2})) { // iterator panics
				result = append(result, z)
				if k == 1 {
					break Y
				}
			}
		}
	}
}

func TestPanickyIterator3(t *testing.T) {
	var result []int
	var expect = []int{100, 10, 1, 2}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a panic, result was %v", result)
		}
	}()
	for _, x := range OfSliceIndex([]int{100, 200}) {
		result = append(result, x)
	Y:
		// swallows panics and iterates to end BUT `break Y` disables the body, so--> 10, 1, 2
		// This is cross-checked against the checked iterator below; the combinator should behave the same.
		for _, y := range VeryBadOfSliceIndex([]int{10, 20}) {
			result = append(result, y)

			for k, z := range OfSliceIndex([]int{1, 2}) { // iterator does not panic
				result = append(result, z)
				if k == 1 {
					break Y
				}
			}
		}
	}
}
func TestPanickyIterator3Check(t *testing.T) {
	var result []int
	var expect = []int{100, 10, 1, 2}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a panic, result was %v", result)
		}
	}()
	for _, x := range Check2(OfSliceIndex([]int{100, 200})) {
		result = append(result, x)
	Y:
		// swallows panics and iterates to end BUT `break Y` disables the body, so--> 10, 1, 2
		for _, y := range Check2(VeryBadOfSliceIndex([]int{10, 20})) {
			result = append(result, y)

			for k, z := range Check2(OfSliceIndex([]int{1, 2})) { // iterator does not panic
				result = append(result, z)
				if k == 1 {
					break Y
				}
			}
		}
	}
}

func TestPanickyIterator4(t *testing.T) {
	var result []int
	var expect = []int{1, 2, 3}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a panic, result was %v", result)
		}
	}()
	for _, x := range SwallowPanicOfSliceIndex([]int{1, 2, 3, 4}) {
		result = append(result, x)
		if x == 3 {
			panic("x is 3")
		}
	}

}
func TestPanickyIterator4Check(t *testing.T) {
	var result []int
	var expect = []int{1, 2, 3}
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_MISSING) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("Expected %v, got %v", expect, result)
			}
		} else {
			t.Errorf("Wanted to see a panic, result was %v", result)
		}
	}()
	for _, x := range Check2(SwallowPanicOfSliceIndex([]int{1, 2, 3, 4})) {
		result = append(result, x)
		if x == 3 {
			panic("x is 3")
		}
	}

}

// veryBad tests that a loop nest behaves sensibly in the face of a
// "very bad" iterator.  In this case, "sensibly" means that the
// break out of X still occurs after the very bad iterator finally
// quits running (the control flow bread crumbs remain.)
func veryBad(s []int) []int {
	var result []int
X:
	for _, x := range OfSliceIndex([]int{1, 2, 3}) {

		result = append(result, x)

		for _, y := range VeryBadOfSliceIndex(s) {
			result = append(result, y)
			break X
		}
		for _, z := range OfSliceIndex([]int{100, 200, 300}) {
			result = append(result, z)
			if z == 100 {
				break
			}
		}
	}
	return result
}

// veryBadCheck wraps a "very bad" iterator with Check,
// demonstrating that the very bad iterator also hides panics
// thrown by Check.
func veryBadCheck(s []int) []int {
	var result []int
X:
	for _, x := range OfSliceIndex([]int{1, 2, 3}) {

		result = append(result, x)

		for _, y := range Check2(VeryBadOfSliceIndex(s)) {
			result = append(result, y)
			break X
		}
		for _, z := range OfSliceIndex([]int{100, 200, 300}) {
			result = append(result, z)
			if z == 100 {
				break
			}
		}
	}
	return result
}

// okay is the not-bad version of veryBad.
// They should behave the same.
func okay(s []int) []int {
	var result []int
X:
	for _, x := range OfSliceIndex([]int{1, 2, 3}) {

		result = append(result, x)

		for _, y := range OfSliceIndex(s) {
			result = append(result, y)
			break X
		}
		for _, z := range OfSliceIndex([]int{100, 200, 300}) {
			result = append(result, z)
			if z == 100 {
				break
			}
		}
	}
	return result
}

// TestVeryBad1 checks the behavior of an extremely poorly behaved iterator.
func TestVeryBad1(t *testing.T) {
	expect := []int{} // assignment does not happen
	var result []int

	defer func() {
		if r := recover(); r != nil {
			expectPanic(t, r, RERR_MISSING)
			if !slices.Equal(expect, result) {
				t.Errorf("(Inner) Expected %v, got %v", expect, result)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	result = veryBad([]int{10, 20, 30, 40, 50}) // odd length

}

func expectPanic(t *testing.T, r any, s string) {
	if matchError(r, s) {
		t.Logf("Saw expected panic '%v'", r)
	} else {
		t.Errorf("Saw wrong panic '%v'", r)
	}
}

func expectError(t *testing.T, err any, s string) {
	if matchError(err, s) {
		t.Logf("Saw expected error '%v'", err)
	} else {
		t.Errorf("Saw wrong error '%v'", err)
	}
}

// TestVeryBad2 checks the behavior of an extremely poorly behaved iterator.
func TestVeryBad2(t *testing.T) {
	result := []int{}
	expect := []int{}

	defer func() {
		if r := recover(); r != nil {
			expectPanic(t, r, RERR_MISSING)
			if !slices.Equal(expect, result) {
				t.Errorf("(Inner) Expected %v, got %v", expect, result)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	result = veryBad([]int{10, 20, 30, 40}) // even length

}

// TestVeryBadCheck checks the behavior of an extremely poorly behaved iterator,
// which also suppresses the exceptions from "Check"
func TestVeryBadCheck(t *testing.T) {
	expect := []int{}
	var result []int
	defer func() {
		if r := recover(); r != nil {
			expectPanic(t, r, CERR_MISSING)
		}
		if !slices.Equal(expect, result) {
			t.Errorf("Expected %v, got %v", expect, result)
		}
	}()

	result = veryBadCheck([]int{10, 20, 30, 40}) // even length

}

// TestOk is the nice version of the very bad iterator.
func TestOk(t *testing.T) {
	result := okay([]int{10, 20, 30, 40, 50}) // odd length
	expect := []int{1, 10}

	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
}

// testBreak1BadDefer checks that defer behaves properly even in
// the presence of loop bodies panicking out of bad iterators.
// (i.e., the instrumentation did not break defer in these loops)
func testBreak1BadDefer(t *testing.T) (result []int) {
	var expect = []int{1, 2, -1, 1, 2, -2, 1, 2, -3, -30, -20, -10}

	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_DONE) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
			if !slices.Equal(expect, result) {
				t.Errorf("(Inner) Expected %v, got %v", expect, result)
			}
		} else {
			t.Error("Wanted to see a failure")
		}
	}()

	for _, x := range BadOfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				break
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
	return
}

func TestBreak1BadDefer(t *testing.T) {
	var result []int
	var expect = []int{1, 2, -1, 1, 2, -2, 1, 2, -3, -30, -20, -10}
	result = testBreak1BadDefer(t)
	if !slices.Equal(expect, result) {
		t.Errorf("(Outer) Expected %v, got %v", expect, result)
	}
}

// testReturn1 has no bad iterators.
func testReturn1(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				return
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
	return
}

// testReturn2 has an outermost bad iterator
func testReturn2(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range BadOfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				return
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
	return
}

// testReturn3 has an innermost bad iterator
func testReturn3(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				return
			}
			result = append(result, y)
		}
	}
	return
}

// testReturn4 has no bad iterators, but exercises  return variable rewriting
// differs from testReturn1 because deferred append to "result" does not change
// the return value in this case.
func testReturn4(t *testing.T) (_ []int, _ []int, err any) {
	var result []int
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				return result, result, nil
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
	return
}

// TestReturns checks that returns through bad iterators behave properly,
// for inner and outer bad iterators.
func TestReturns(t *testing.T) {
	var result []int
	var result2 []int
	var expect = []int{-1, 1, 2, -10}
	var expect2 = []int{-1, 1, 2}
	var err any

	result, err = testReturn1(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	result, err = testReturn2(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		if matchError(err, RERR_DONE) {
			t.Logf("Saw expected panic '%v'", err)
		} else {
			t.Errorf("Saw wrong panic '%v'", err)
		}
	}

	result, err = testReturn3(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		if matchError(err, RERR_DONE) {
			t.Logf("Saw expected panic '%v'", err)
		} else {
			t.Errorf("Saw wrong panic '%v'", err)
		}
	}

	result, result2, err = testReturn4(t)
	if !slices.Equal(expect2, result) {
		t.Errorf("Expected %v, got %v", expect2, result)
	}
	if !slices.Equal(expect2, result2) {
		t.Errorf("Expected %v, got %v", expect2, result2)
	}
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
}

// testGotoA1 tests loop-nest-internal goto, no bad iterators.
func testGotoA1(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto A
			}
			result = append(result, y)
		}
		result = append(result, x)
	A:
	}
	return
}

// testGotoA2 tests loop-nest-internal goto, outer bad iterator.
func testGotoA2(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range BadOfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto A
			}
			result = append(result, y)
		}
		result = append(result, x)
	A:
	}
	return
}

// testGotoA3 tests loop-nest-internal goto, inner bad iterator.
func testGotoA3(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto A
			}
			result = append(result, y)
		}
		result = append(result, x)
	A:
	}
	return
}

func TestGotoA(t *testing.T) {
	var result []int
	var expect = []int{-1, 1, 2, -2, 1, 2, -3, 1, 2, -4, -30, -20, -10}
	var expect3 = []int{-1, 1, 2, -10} // first goto becomes a panic
	var err any

	result, err = testGotoA1(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	result, err = testGotoA2(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		if matchError(err, RERR_DONE) {
			t.Logf("Saw expected panic '%v'", err)
		} else {
			t.Errorf("Saw wrong panic '%v'", err)
		}
	}

	result, err = testGotoA3(t)
	if !slices.Equal(expect3, result) {
		t.Errorf("Expected %v, got %v", expect3, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		if matchError(err, RERR_DONE) {
			t.Logf("Saw expected panic '%v'", err)
		} else {
			t.Errorf("Saw wrong panic '%v'", err)
		}
	}
}

// testGotoB1 tests loop-nest-exiting goto, no bad iterators.
func testGotoB1(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto B
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
B:
	result = append(result, 999)
	return
}

// testGotoB2 tests loop-nest-exiting goto, outer bad iterator.
func testGotoB2(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range BadOfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range OfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto B
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
B:
	result = append(result, 999)
	return
}

// testGotoB3 tests loop-nest-exiting goto, inner bad iterator.
func testGotoB3(t *testing.T) (result []int, err any) {
	defer func() {
		err = recover()
	}()
	for _, x := range OfSliceIndex([]int{-1, -2, -3, -4, -5}) {
		result = append(result, x)
		if x == -4 {
			break
		}
		defer func() {
			result = append(result, x*10)
		}()
		for _, y := range BadOfSliceIndex([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) {
			if y == 3 {
				goto B
			}
			result = append(result, y)
		}
		result = append(result, x)
	}
B:
	result = append(result, 999)
	return
}

func TestGotoB(t *testing.T) {
	var result []int
	var expect = []int{-1, 1, 2, 999, -10}
	var expectX = []int{-1, 1, 2, -10}
	var err any

	result, err = testGotoB1(t)
	if !slices.Equal(expect, result) {
		t.Errorf("Expected %v, got %v", expect, result)
	}
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	result, err = testGotoB2(t)
	if !slices.Equal(expectX, result) {
		t.Errorf("Expected %v, got %v", expectX, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		if matchError(err, RERR_DONE) {
			t.Logf("Saw expected panic '%v'", err)
		} else {
			t.Errorf("Saw wrong panic '%v'", err)
		}
	}

	result, err = testGotoB3(t)
	if !slices.Equal(expectX, result) {
		t.Errorf("Expected %v, got %v", expectX, result)
	}
	if err == nil {
		t.Errorf("Missing expected error")
	} else {
		matchErrorHelper(t, err, RERR_DONE)
	}
}

// once returns an iterator that runs its loop body once with the supplied value
func once[T any](x T) Seq[T] {
	return func(yield func(T) bool) {
		yield(x)
	}
}

// terrify converts an iterator into one that panics with the supplied string
// if/when the loop body terminates early (returns false, for break, goto, outer
// continue, or return).
func terrify[T any](s string, forall Seq[T]) Seq[T] {
	return func(yield func(T) bool) {
		forall(func(v T) bool {
			if !yield(v) {
				panic(s)
			}
			return true
		})
	}
}

func use[T any](T) {
}

// f runs a not-rangefunc iterator that recovers from a panic that follows execution of a return.
// what does f return?
func f() string {
	defer func() { recover() }()
	defer panic("f panic")
	for _, s := range []string{"f return"} {
		return s
	}
	return "f not reached"
}

// g runs a rangefunc iterator that recovers from a panic that follows execution of a return.
// what does g return?
func g() string {
	defer func() { recover() }()
	for s := range terrify("g panic", once("g return")) {
		return s
	}
	return "g not reached"
}

// h runs a rangefunc iterator that recovers from a panic that follows execution of a return.
// the panic occurs in the rangefunc iterator itself.
// what does h return?
func h() (hashS string) {
	defer func() { recover() }()
	for s := range terrify("h panic", once("h return")) {
		hashS := s
		use(hashS)
		return s
	}
	return "h not reached"
}

func j() (hashS string) {
	defer func() { recover() }()
	for s := range terrify("j panic", once("j return")) {
		hashS = s
		return
	}
	return "j not reached"
}

// k runs a rangefunc iterator that recovers from a panic that follows execution of a return.
// the panic occurs in the rangefunc iterator itself.
// k includes an additional mechanism to for making the return happen
// what does k return?
func k() (hashS string) {
	_return := func(s string) { hashS = s }

	defer func() { recover() }()
	for s := range terrify("k panic", once("k return")) {
		_return(s)
		return
	}
	return "k not reached"
}

func m() (hashS string) {
	_return := func(s string) { hashS = s }

	defer func() { recover() }()
	for s := range terrify("m panic", once("m return")) {
		defer _return(s)
		return s + ", but should be replaced in a defer"
	}
	return "m not reached"
}

func n() string {
	defer func() { recover() }()
	for s := range terrify("n panic", once("n return")) {
		return s + func(s string) string {
			defer func() { recover() }()
			for s := range terrify("n closure panic", once(s)) {
				return s
			}
			return "n closure not reached"
		}(" and n closure return")
	}
	return "n not reached"
}

type terrifyTestCase struct {
	f func() string
	e string
}

func TestPanicReturns(t *testing.T) {
	tcs := []terrifyTestCase{
		{f, "f return"},
		{g, "g return"},
		{h, "h return"},
		{k, "k return"},
		{j, "j return"},
		{m, "m return"},
		{n, "n return and n closure return"},
	}

	for _, tc := range tcs {
		got := tc.f()
		if got != tc.e {
			t.Errorf("Got %s expected %s", got, tc.e)
		} else {
			t.Logf("Got expected %s", got)
		}
	}
}

// twice calls yield twice, the first time defer-recover-saving any panic,
// for re-panicking later if the second call to yield does not also panic.
// If the first call panicked, the second call ought to also panic because
// it was called after a panic-termination of the loop body.
func twice[T any](x, y T) Seq[T] {
	return func(yield func(T) bool) {
		var p any
		done := false
		func() {
			defer func() {
				p = recover()
			}()
			done = !yield(x)
		}()
		if done {
			return
		}
		yield(y)
		if p != nil {
			// do not swallow the panic
			panic(p)
		}
	}
}

func TestRunBodyAfterPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, RERR_PANIC) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Errorf("Wanted to see a failure, result")
		}
	}()
	for x := range twice(0, 1) {
		if x == 0 {
			panic("x is zero")
		}
	}
}

func TestRunBodyAfterPanicCheck(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if matchError(r, CERR_PANIC) {
				t.Logf("Saw expected panic '%v'", r)
			} else {
				t.Errorf("Saw wrong panic '%v'", r)
			}
		} else {
			t.Errorf("Wanted to see a failure, result")
		}
	}()
	for x := range Check(twice(0, 1)) {
		if x == 0 {
			panic("x is zero")
		}
	}
}

func TestTwoLevelReturn(t *testing.T) {
	f := func() int {
		for a := range twice(0, 1) {
			for b := range twice(0, 2) {
				x := a + b
				t.Logf("x=%d", x)
				if x == 3 {
					return x
				}
			}
		}
		return -1
	}
	y := f()
	if y != 3 {
		t.Errorf("Expected y=3, got y=%d\n", y)
	}
}

func TestTwoLevelReturnCheck(t *testing.T) {
	f := func() int {
		for a := range Check(twice(0, 1)) {
			for b := range Check(twice(0, 2)) {
				x := a + b
				t.Logf("a=%d, b=%d, x=%d", a, b, x)
				if x == 3 {
					return x
				}
			}
		}
		return -1
	}
	y := f()
	if y != 3 {
		t.Errorf("Expected y=3, got y=%d\n", y)
	}
}

func Bug70035(s1, s2, s3 []string) string {
	var c1 string
	for v1 := range slices.Values(s1) {
		var c2 string
		for v2 := range slices.Values(s2) {
			var c3 string
			for v3 := range slices.Values(s3) {
				c3 = c3 + v3
			}
			c2 = c2 + v2 + c3
		}
		c1 = c1 + v1 + c2
	}
	return c1
}

func Test70035(t *testing.T) {
	got := Bug70035([]string{"1", "2", "3"}, []string{"a", "b", "c"}, []string{"A", "B", "C"})
	want := "1aABCbABCcABC2aABCbABCcABC3aABCbABCcABC"
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
```