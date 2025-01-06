Response: Let's break down the thought process to analyze the given Go code snippet.

**1. Understanding the Core Purpose:**

The first and most crucial step is to understand the overarching goal of this code. The initial comments are key:

* `"// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1"`: This immediately signals that this code is designed for testing the compiler's inlining capabilities. The `-m` flag is a strong indicator, as it instructs the compiler to print inlining decisions.
* `"//go:build !goexperiment.newinliner"`: This suggests it's specifically testing the *old* inliner.
* `"// Test, using compiler diagnostic flags, that inlining is working."`:  This reinforces the testing purpose.
* `"// Compiles but does not run."`: This tells us we don't need to worry about runtime behavior or execution. The focus is on compilation and the compiler's inlining analysis.

**2. Identifying Key Patterns:**

Scanning through the code, several patterns emerge:

* **Function Definitions with `// ERROR "can inline ..."`:** This is the most prominent pattern. The comments explicitly state whether a function *can* be inlined. This is the core of the test.
* **Function Calls with `// ERROR "inlining call to ..."`:**  This indicates where the compiler *should* inline a function call.
* **`//go:noinline`:** This directive explicitly prevents a function from being inlined, serving as a negative test case.
* **Functions using `unsafe` package:** Functions like `add1` and `add2` use `unsafe.Pointer`, which often has implications for inlining. The comments about "leaking param to result" are specific to unsafe operations and their interaction with inlining.
* **Closures (Anonymous Functions):** Several functions define and use anonymous functions (closures). The comments indicate whether these closures are inlined. Terms like "func literal does not escape" are relevant here.
* **Switch Statements:** Several functions demonstrate inlining behavior with different types of switch statements (constant, type).
* **Loops (for):**  The code includes tests for inlining functions containing `for` loops.
* **Method Calls:**  The code includes examples of inlining method calls on structs.
* **`go` and `defer` statements:**  There are tests specifically for inlining functions called within `go` and `defer`.
* **Select Statements:** Inlining of `select` statements is also tested.

**3. Formulating the Functionality Summary:**

Based on these patterns, we can deduce the primary function of the code:

* **Systematic Testing of Go's Inliner:** The code acts as a comprehensive test suite for the Go compiler's inlining mechanism.
* **Verification of Inlining Decisions:**  It checks if the compiler correctly identifies functions that *can* be inlined and whether it *actually* inlines them at the call sites.
* **Testing Various Code Constructs:**  It covers a wide range of Go language features, including basic functions, functions with `unsafe`, closures, different kinds of control flow (switch, for), methods, `go` and `defer` statements, and `select` statements.
* **Regression Testing:** By providing explicit "ERROR" comments, it serves as a way to detect regressions in the inliner's behavior as the Go compiler evolves.

**4. Inferring the Go Feature:**

It's clear that the code is a test suite for **Go's function inlining optimization**.

**5. Providing Go Code Examples:**

To illustrate inlining, we can create simplified versions of the tested scenarios. Focus on demonstrating the core concepts like basic inlining, closures, and methods. Make sure these examples are runnable and easy to understand.

**6. Explaining Code Logic with Input and Output:**

For a representative function, like `f(x *byte)`, walk through the steps, explaining how the inlining would transform the code. Use a simple, concrete input to make the process clear. Highlight the "before" and "after" states of the code after inlining.

**7. Describing Command-Line Arguments:**

The comment `// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1` provides the key information. Explain the meaning of `-m` (for inlining diagnostics) and `-d=inlfuncswithclosures=1` (which seems specific to testing inlining of functions with closures). Mention that this isn't a standard Go command but likely a tool used within the Go development process.

**8. Identifying Common Mistakes (and why they aren't explicitly present):**

Review the code for scenarios where a developer might *expect* inlining but it doesn't happen. In this specific test file, the "errors" are pre-annotated. However, in general, common mistakes might involve:

* **Functions being too large or complex.**
* **Functions with loop nests.**
* **Functions that allocate significant memory.**
* **Functions called indirectly through interfaces (though this test file *does* test some method value scenarios).**
* **Functions marked `//go:noinline`.**

Since the test file *explicitly* marks inlining successes and failures,  the common mistakes aren't being demonstrated as *user* errors, but rather as scenarios the *compiler* is tested against. Therefore, the prompt's instruction to "举例说明，没有则不必说明" (give examples, otherwise don't) leads to the conclusion that we don't need to invent user error examples *outside* of the test's context. The test itself defines the expected inlining behavior.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific functions and their individual logic. Realizing the broader context of a *test suite* is crucial.
* I need to be precise about the meaning of the "ERROR" comments – they are assertions within the test, not necessarily runtime errors.
* The explanation of command-line arguments needs to be clear about the non-standard nature of the given flags.

By following these steps, focusing on the overarching purpose, identifying key patterns, and relating them back to the concept of function inlining, a comprehensive and accurate analysis can be achieved.
Based on the provided Go code snippet, here's a breakdown of its functionality:

**归纳一下它的功能 (Summary of its functionality):**

This Go code file, `inline.go`, serves as a **test suite for the Go compiler's inlining capabilities**. It contains a variety of Go functions with different characteristics (simple functions, functions using `unsafe`, functions with closures, switch statements, loops, method calls, `go` and `defer` statements, select statements). The file is designed to be compiled with specific compiler flags that enable diagnostic output about inlining decisions. The comments within the code act as **assertions**, indicating whether a function *should* be inlined and where specific function calls *should* be inlined.

**它是什么go语言功能的实现 (What Go language feature does it test):**

This code tests the **function inlining optimization** in the Go compiler. Function inlining is a compiler optimization where the body of a function call is directly inserted into the caller function, potentially improving performance by reducing function call overhead.

**go代码举例说明 (Go code examples illustrating the feature):**

```go
package main

import "fmt"

//go:noinline
func add(a, b int) int {
	return a + b
}

func multiply(a, b int) int {
	return add(a, b) * 2 // The compiler might inline the call to 'add' here
}

func main() {
	result := multiply(5, 3)
	fmt.Println(result) // Output: 16
}
```

In this example, the `multiply` function calls the `add` function. The Go compiler, under normal optimization settings, might inline the call to `add` within `multiply`, effectively transforming `multiply` into something like:

```go
func multiply(a, b int) int {
	return (a + b) * 2
}
```

The `//go:noinline` directive on `add` prevents it from being inlined, demonstrating how to control inlining behavior.

**介绍代码逻辑 (Explanation of code logic with assumed input/output):**

Let's take the `f` function as an example:

```go
func f(x *byte) *byte { // ERROR "can inline f" "leaking param: x to result"
	return add2(x, 1) // ERROR "inlining call to add2" "inlining call to add1"
}
```

**Assumed Input:** `x` is a pointer to a byte in memory. Let's say `x` points to memory address `0x1000`.

**Code Logic:**

1. The `f` function takes a pointer to a byte (`*byte`) as input.
2. It calls the `add2` function, passing the input pointer `x` and the uintptr `1`.

**Tracing `add2`:**

```go
func add2(p *byte, n uintptr) *byte { // ERROR "can inline add2" "leaking param: p to result"
	return (*byte)(add1(unsafe.Pointer(p), n)) // ERROR "inlining call to add1"
}
```

1. `add2` receives the pointer `p` (which is `x`, so `0x1000`) and the uintptr `n` (which is `1`).
2. It converts the `*byte` pointer `p` to an `unsafe.Pointer`.
3. It calls the `add1` function with the `unsafe.Pointer` and the uintptr `1`.

**Tracing `add1`:**

```go
func add1(p unsafe.Pointer, x uintptr) unsafe.Pointer { // ERROR "can inline add1" "leaking param: p to result"
	return unsafe.Pointer(uintptr(p) + x)
}
```

1. `add1` receives the `unsafe.Pointer` (representing `0x1000`) and the uintptr `x` (which is `1`).
2. It converts the `unsafe.Pointer` to a `uintptr` (which is the numerical representation of the memory address, so `0x1000`).
3. It adds the uintptr `x` (which is `1`) to the `uintptr` representation of the pointer (`0x1000 + 1 = 0x1001`).
4. It converts the resulting `uintptr` back to an `unsafe.Pointer`.
5. `add1` returns this new `unsafe.Pointer`.

**Back to `add2`:**

1. `add2` receives the `unsafe.Pointer` returned by `add1`.
2. It converts this `unsafe.Pointer` back to a `*byte` pointer.
3. `add2` returns this new `*byte` pointer.

**Back to `f`:**

1. `f` receives the `*byte` pointer returned by `add2`.
2. `f` returns this `*byte` pointer.

**Output (Hypothetical):** If `x` pointed to memory address `0x1000`, the function `f` would return a pointer to memory address `0x1001`.

**The "ERROR" comments indicate the compiler's expected inlining behavior:**

* `"can inline f"`: The compiler determines that the `f` function is eligible for inlining.
* `"leaking param: x to result"`: This indicates that the pointer `x` is passed as a parameter and its value (or a pointer derived from it) is returned, which can have implications for escape analysis and garbage collection.
* `"inlining call to add2"`:  When compiling `f`, the compiler should insert the code of `add2` directly into `f`.
* `"inlining call to add1"`: When the code of `add2` is inlined into `f`, the call to `add1` within the inlined `add2` should also be inlined.

**命令行参数的具体处理 (Specific handling of command-line arguments):**

The comment `// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1` at the beginning of the file indicates the specific compiler flags used when running this test. These are not standard Go build flags but are specific to the testing infrastructure used by the Go team.

* **`-0`**: This usually signifies no optimization, or a minimal level of optimization. However, in the context of compiler testing, it might mean a specific baseline configuration.
* **`-m`**: This is the key flag for observing inlining decisions. When the compiler is run with `-m`, it prints information about which functions are being inlined. This output is then compared against the `// ERROR "inlining call to ..."` comments in the code to verify the inlining behavior.
* **`-d=inlfuncswithclosures=1`**: This is a more specific and likely internal compiler debug flag. It probably enables or modifies the inlining behavior related to functions with closures.

**使用者易犯错的点 (Common mistakes users might make - though not directly illustrated in this test file):**

While this specific file is a test for compiler behavior, here are some common misunderstandings or mistakes users might make regarding inlining in Go:

1. **Assuming all small functions are always inlined:** The compiler makes decisions based on heuristics. Very complex small functions or functions called very infrequently might not be inlined.
2. **Over-reliance on `//go:noinline`:**  While useful for debugging, excessive use of `//go:noinline` can hinder performance. Let the compiler do its job unless you have a specific reason to prevent inlining.
3. **Not understanding the impact of escape analysis:** If a function argument or return value escapes to the heap (e.g., a pointer passed to a global variable), it can sometimes prevent inlining. The "leaking param" comments in the test file hint at this.
4. **Expecting inlining across package boundaries in all cases:** While possible, inlining across package boundaries is more complex and might not always happen, especially without Link-Time Optimization (LTO).
5. **Misinterpreting the output of `-m`:** The `-m` flag provides hints, but the exact inlining decisions can be complex and depend on various factors.

**In summary, `go/test/inline.go` is a crucial part of the Go compiler's testing infrastructure, specifically designed to verify the correctness and behavior of the function inlining optimization across a wide range of scenarios.** The comments within the code act as assertions about the expected inlining decisions made by the compiler when built with specific diagnostic flags.

Prompt: 
```
这是路径为go/test/inline.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1

//go:build !goexperiment.newinliner

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test, using compiler diagnostic flags, that inlining is working.
// Compiles but does not run.

package foo

import (
	"errors"
	"runtime"
	"unsafe"
)

func add2(p *byte, n uintptr) *byte { // ERROR "can inline add2" "leaking param: p to result"
	return (*byte)(add1(unsafe.Pointer(p), n)) // ERROR "inlining call to add1"
}

func add1(p unsafe.Pointer, x uintptr) unsafe.Pointer { // ERROR "can inline add1" "leaking param: p to result"
	return unsafe.Pointer(uintptr(p) + x)
}

func f(x *byte) *byte { // ERROR "can inline f" "leaking param: x to result"
	return add2(x, 1) // ERROR "inlining call to add2" "inlining call to add1"
}

//go:noinline
func g(x int) int {
	return x + 1
}

func h(x int) int { // ERROR "can inline h"
	return x + 2
}

func i(x int) int { // ERROR "can inline i"
	const y = 2
	return x + y
}

func j(x int) int { // ERROR "can inline j"
	switch {
	case x > 0:
		return x + 2
	default:
		return x + 1
	}
}

func f2() int { // ERROR "can inline f2"
	tmp1 := h
	tmp2 := tmp1
	return tmp2(0) // ERROR "inlining call to h"
}

var abc = errors.New("abc") // ERROR "inlining call to errors.New"

var somethingWrong error

// local closures can be inlined
func l(x, y int) (int, int, error) { // ERROR "can inline l"
	e := func(err error) (int, int, error) { // ERROR "can inline l.func1" "func literal does not escape" "leaking param: err to result"
		return 0, 0, err
	}
	if x == y {
		e(somethingWrong) // ERROR "inlining call to l.func1"
	} else {
		f := e
		f(nil) // ERROR "inlining call to l.func1"
	}
	_ = e // prevent simple deadcode elimination after inlining
	return y, x, nil
}

// any re-assignment prevents closure inlining
func m() int {
	foo := func() int { return 1 } // ERROR "can inline m.func1" "func literal does not escape"
	x := foo()
	foo = func() int { return 2 } // ERROR "can inline m.func2" "func literal does not escape"
	return x + foo()
}

// address taking prevents closure inlining
func n() int {
	foo := func() int { return 1 } // ERROR "can inline n.func1" "func literal does not escape"
	bar := &foo
	x := (*bar)() + foo()
	return x
}

// make sure assignment inside closure is detected
func o() int {
	foo := func() int { return 1 } // ERROR "can inline o.func1" "func literal does not escape"
	func(x int) {                  // ERROR "can inline o.func2"
		if x > 10 {
			foo = func() int { return 2 } // ERROR "can inline o.func2"
		}
	}(11) // ERROR "func literal does not escape" "inlining call to o.func2"
	return foo()
}

func p() int { // ERROR "can inline p"
	return func() int { return 42 }() // ERROR "can inline p.func1" "inlining call to p.func1"
}

func q(x int) int { // ERROR "can inline q"
	foo := func() int { return x * 2 } // ERROR "can inline q.func1" "func literal does not escape"
	_ = foo                            // prevent simple deadcode elimination after inlining
	return foo()                       // ERROR "inlining call to q.func1"
}

func r(z int) int {
	foo := func(x int) int { // ERROR "can inline r.func1" "func literal does not escape"
		return x + z
	}
	bar := func(x int) int { // ERROR "func literal does not escape" "can inline r.func2"
		return x + func(y int) int { // ERROR "can inline r.func2.1" "can inline r.r.func2.func3"
			return 2*y + x*z
		}(x) // ERROR "inlining call to r.func2.1"
	}
	_, _ = foo, bar // prevent simple deadcode elimination after inlining

	return foo(42) + bar(42) // ERROR "inlining call to r.func1" "inlining call to r.func2" "inlining call to r.r.func2.func3"
}

func s0(x int) int { // ERROR "can inline s0"
	foo := func() { // ERROR "can inline s0.func1" "func literal does not escape"
		x = x + 1
	}
	foo()   // ERROR "inlining call to s0.func1"
	_ = foo // prevent simple deadcode elimination after inlining
	return x
}

func s1(x int) int { // ERROR "can inline s1"
	foo := func() int { // ERROR "can inline s1.func1" "func literal does not escape"
		return x
	}
	x = x + 1
	_ = foo      // prevent simple deadcode elimination after inlining
	return foo() // ERROR "inlining call to s1.func1"
}

func switchBreak(x, y int) int { // ERROR "can inline switchBreak"
	var n int
	switch x {
	case 0:
		n = 1
	Done:
		switch y {
		case 0:
			n += 10
			break Done
		}
		n = 2
	}
	return n
}

func switchType(x interface{}) int { // ERROR "can inline switchType" "x does not escape"
	switch x.(type) {
	case int:
		return x.(int)
	default:
		return 0
	}
}

// Test that switches on constant things, with constant cases, only cost anything for
// the case that matches. See issue 50253.
func switchConst1(p func(string)) { // ERROR "can inline switchConst" "p does not escape"
	const c = 1
	switch c {
	case 0:
		p("zero")
	case 1:
		p("one")
	case 2:
		p("two")
	default:
		p("other")
	}
}

func switchConst2() string { // ERROR "can inline switchConst2"
	switch runtime.GOOS {
	case "linux":
		return "Leenooks"
	case "windows":
		return "Windoze"
	case "darwin":
		return "MackBone"
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100":
		return "Numbers"
	default:
		return "oh nose!"
	}
}
func switchConst3() string { // ERROR "can inline switchConst3"
	switch runtime.GOOS {
	case "Linux":
		panic("Linux")
	case "Windows":
		panic("Windows")
	case "Darwin":
		panic("Darwin")
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100":
		panic("Numbers")
	default:
		return "oh nose!"
	}
}
func switchConst4() { // ERROR "can inline switchConst4"
	const intSize = 32 << (^uint(0) >> 63)
	want := func() string { // ERROR "can inline switchConst4.func1"
		switch intSize {
		case 32:
			return "32"
		case 64:
			return "64"
		default:
			panic("unreachable")
		}
	}() // ERROR "inlining call to switchConst4.func1"
	_ = want
}

func inlineRangeIntoMe(data []int) { // ERROR "can inline inlineRangeIntoMe" "data does not escape"
	rangeFunc(data, 12) // ERROR "inlining call to rangeFunc"
}

func rangeFunc(xs []int, b int) int { // ERROR "can inline rangeFunc" "xs does not escape"
	for i, x := range xs {
		if x == b {
			return i
		}
	}
	return -1
}

type T struct{}

func (T) meth(int, int) {} // ERROR "can inline T.meth"

func k() (T, int, int) { return T{}, 0, 0 } // ERROR "can inline k"

func f3() { // ERROR "can inline f3"
	T.meth(k()) // ERROR "inlining call to k" "inlining call to T.meth"
	// ERRORAUTO "inlining call to T.meth"
}

func small1() { // ERROR "can inline small1"
	runtime.GC()
}
func small2() int { // ERROR "can inline small2"
	return runtime.GOMAXPROCS(0)
}
func small3(t T) { // ERROR "can inline small3"
	t.meth2(3, 5)
}
func small4(t T) { // not inlineable - has 2 calls.
	t.meth2(runtime.GOMAXPROCS(0), 5)
}
func (T) meth2(int, int) { // not inlineable - has 2 calls.
	runtime.GC()
	runtime.GC()
}

// Issue #29737 - make sure we can do inlining for a chain of recursive functions
func ee() { // ERROR "can inline ee"
	ff(100) // ERROR "inlining call to ff" "inlining call to gg" "inlining call to hh"
}

func ff(x int) { // ERROR "can inline ff"
	if x < 0 {
		return
	}
	gg(x - 1) // ERROR "inlining call to gg" "inlining call to hh"
}
func gg(x int) { // ERROR "can inline gg"
	hh(x - 1) // ERROR "inlining call to hh" "inlining call to ff"
}
func hh(x int) { // ERROR "can inline hh"
	ff(x - 1) // ERROR "inlining call to ff" "inlining call to gg"
}

// Issue #14768 - make sure we can inline for loops.
func for1(fn func() bool) { // ERROR "can inline for1" "fn does not escape"
	for {
		if fn() {
			break
		} else {
			continue
		}
	}
}

func for2(fn func() bool) { // ERROR "can inline for2" "fn does not escape"
Loop:
	for {
		if fn() {
			break Loop
		} else {
			continue Loop
		}
	}
}

// Issue #18493 - make sure we can do inlining of functions with a method value
type T1 struct{}

func (a T1) meth(val int) int { // ERROR "can inline T1.meth"
	return val + 5
}

func getMeth(t1 T1) func(int) int { // ERROR "can inline getMeth"
	return t1.meth // ERROR "t1.meth escapes to heap"
	// ERRORAUTO "inlining call to T1.meth"
}

func ii() { // ERROR "can inline ii"
	var t1 T1
	f := getMeth(t1) // ERROR "inlining call to getMeth" "t1.meth does not escape"
	_ = f(3)
}

// Issue #42194 - make sure that functions evaluated in
// go and defer statements can be inlined.
func gd1(int) {
	defer gd1(gd2()) // ERROR "inlining call to gd2"
	defer gd3()()    // ERROR "inlining call to gd3"
	go gd1(gd2())    // ERROR "inlining call to gd2"
	go gd3()()       // ERROR "inlining call to gd3"
}

func gd2() int { // ERROR "can inline gd2"
	return 1
}

func gd3() func() { // ERROR "can inline gd3"
	return ii
}

// Issue #42788 - ensure ODEREF OCONVNOP* OADDR is low cost.
func EncodeQuad(d []uint32, x [6]float32) { // ERROR "can inline EncodeQuad" "d does not escape"
	_ = d[:6]
	d[0] = float32bits(x[0]) // ERROR "inlining call to float32bits"
	d[1] = float32bits(x[1]) // ERROR "inlining call to float32bits"
	d[2] = float32bits(x[2]) // ERROR "inlining call to float32bits"
	d[3] = float32bits(x[3]) // ERROR "inlining call to float32bits"
	d[4] = float32bits(x[4]) // ERROR "inlining call to float32bits"
	d[5] = float32bits(x[5]) // ERROR "inlining call to float32bits"
}

// float32bits is a copy of math.Float32bits to ensure that
// these tests pass with `-gcflags=-l`.
func float32bits(f float32) uint32 { // ERROR "can inline float32bits"
	return *(*uint32)(unsafe.Pointer(&f))
}

// Ensure OCONVNOP is zero cost.
func Conv(v uint64) uint64 { // ERROR "can inline Conv"
	return conv2(conv2(conv2(v))) // ERROR "inlining call to (conv1|conv2)"
}
func conv2(v uint64) uint64 { // ERROR "can inline conv2"
	return conv1(conv1(conv1(conv1(v)))) // ERROR "inlining call to conv1"
}
func conv1(v uint64) uint64 { // ERROR "can inline conv1"
	return uint64(uint64(uint64(uint64(uint64(uint64(uint64(uint64(uint64(uint64(uint64(v)))))))))))
}

func select1(x, y chan bool) int { // ERROR "can inline select1" "x does not escape" "y does not escape"
	select {
	case <-x:
		return 1
	case <-y:
		return 2
	}
}

func select2(x, y chan bool) { // ERROR "can inline select2" "x does not escape" "y does not escape"
loop: // test that labeled select can be inlined.
	select {
	case <-x:
		break loop
	case <-y:
	}
}

func inlineSelect2(x, y chan bool) { // ERROR "can inline inlineSelect2" ERROR "x does not escape" "y does not escape"
loop:
	for i := 0; i < 5; i++ {
		if i == 3 {
			break loop
		}
		select2(x, y) // ERROR "inlining call to select2"
	}
}

// Issue #62211: inlining a function with unreachable "return"
// statements could trip up phi insertion.
func issue62211(x bool) { // ERROR "can inline issue62211"
	if issue62211F(x) { // ERROR "inlining call to issue62211F"
	}
	if issue62211G(x) { // ERROR "inlining call to issue62211G"
	}

	// Initial fix CL caused a "non-monotonic scope positions" failure
	// on code like this.
	if z := 0; false {
		panic(z)
	}
}

func issue62211F(x bool) bool { // ERROR "can inline issue62211F"
	if x || true {
		return true
	}
	return true
}

func issue62211G(x bool) bool { // ERROR "can inline issue62211G"
	if x || true {
		return true
	} else {
		return true
	}
}

"""



```