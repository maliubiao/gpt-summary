Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The first and most crucial step is to understand the *purpose* of this code. The comments at the beginning are key:

* `"// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1"`: This is a compiler directive. It tells the Go compiler (specifically the `go test` command used with error checking) to enable specific flags:
    * `-0`:  No optimization (or minimal optimization, depending on the context). This is important because we want to see the *potential* for inlining, not the optimized result.
    * `-m`:  Enable compiler optimizations output. This is how we get the "can inline..." messages.
    * `-d=inlfuncswithclosures=1`:  This likely enables inlining of functions containing closures, which is a specific aspect being tested.
* `"//go:build !goexperiment.newinliner"`: This build constraint indicates this test is for the *old* inliner, not the newer experimental one. This tells us we're looking at older inlining behavior.
* `"// Copyright ..."` and `"// Test, using compiler diagnostic flags, that inlining is working."`: These comments explicitly state that the code is a *test* to verify the inlining mechanism of the Go compiler. It's not meant to be a practical, runnable program in the typical sense.
* `"// Compiles but does not run."`: This confirms it's a test, not an application.

**2. Identifying the Core Mechanism:**

The core mechanism at play here is *function inlining*. The goal of inlining is to replace a function call with the actual code of the function at the call site. This can improve performance by reducing function call overhead.

**3. Analyzing Individual Functions and Annotations:**

The next step is to go through each function in the code and analyze:

* **The function's logic:** What does the function do? Is it simple or complex?
* **The `// ERROR ...` comments:** These are the *expected* compiler diagnostic messages. They are the heart of the test. They tell us:
    * `"can inline <function_name>"`:  The compiler believes this function is eligible for inlining.
    * `"inlining call to <function_name>"`: The compiler has decided to inline a call to this function.
    * `"leaking param: ... to result"`:  This indicates that a pointer parameter is being returned, which might have implications for garbage collection and escape analysis.
    * `"func literal does not escape"`: This means the anonymous function (closure) is only used within the scope it's defined in, and doesn't need to be allocated on the heap.

**4. Grouping Functions by Inlining Behavior/Reason:**

As you go through the functions, you'll start to notice patterns and reasons *why* certain functions are or aren't being inlined:

* **Simple Functions:**  Functions like `h`, `i`, and `j` are inlined because they have very little overhead.
* **Functions with Unsafe Operations:** `add1` and `add2` deal with `unsafe.Pointer`. While they can be inlined, the compiler notes the parameter "leakage" because of the nature of unsafe pointers.
* **Functions with Closures:**  Functions `l`, `m`, `n`, `o`, `p`, `q`, `r`, `s0`, and `s1` demonstrate various aspects of closure inlining. The tests show how reassignment, taking the address of a closure, and modifications within a closure can affect inlining.
* **Functions with Control Flow:** `switchBreak`, `switchType`, `switchConst1`, `switchConst2`, `switchConst3`, `switchConst4`, `for1`, and `for2` test inlining within `switch` and `for` statements. The constant switch cases are particularly interesting.
* **Functions with Method Calls:**  `T.meth`, `f3`, `small1`, `small2`, `small3`, `small4`, and `T.meth2` explore inlining of methods.
* **Recursive Functions:** `ee`, `ff`, `gg`, and `hh` test inlining in recursive scenarios.
* **Functions with Method Values:** `T1.meth`, `getMeth`, and `ii` focus on inlining when dealing with method values.
* **Functions with `go` and `defer`:** `gd1`, `gd2`, and `gd3` examine inlining within goroutines and deferred calls.
* **Functions with Low-Cost Operations:** `EncodeQuad`, `float32bits`, `Conv`, `conv1`, and `conv2` highlight inlining of functions with operations the compiler considers inexpensive.
* **Functions with `select` Statements:** `select1`, `select2`, and `inlineSelect2` test inlining of `select` blocks.
* **Functions with Unreachable Code:** `issue62211`, `issue62211F`, and `issue62211G` address a specific compiler issue related to inlining with unreachable `return` statements.

**5. Inferring Functionality and Providing Examples:**

Based on the analysis of the functions and the expected compiler output, you can start to infer the functionality being tested. For each category of functions, create simple Go code examples that illustrate the inlining behavior. The examples should be clear and concise, focusing on the specific aspect being demonstrated.

**6. Explaining Compiler Flags and Command-Line Arguments:**

The `// errorcheckwithauto ...` comment provides the necessary information about the compiler flags. Explain what each flag does and how it affects the inlining process and the test output.

**7. Identifying Potential Pitfalls:**

Think about how a developer might misunderstand or misuse inlining. Common pitfalls include:

* **Over-reliance on inlining for performance:**  Inlining is just one optimization, and not all functions are good candidates for it.
* **Unexpected behavior with closures:** Developers might not fully understand how closure inlining works and how factors like reassignment can prevent it.
* **Debugging challenges:** Inlined code can make debugging slightly harder as the call stack might look different.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code just defines a bunch of functions."  **Correction:**  "No, the `// ERROR` comments indicate this is a *test* of the inliner."
* **Initial thought:** "Inlining is always good for performance." **Correction:** "While it often improves performance, it's not guaranteed, and very large functions might not be inlined."
* **Focus on individual functions in isolation.** **Correction:**  Group functions by the inlining principle they are demonstrating (e.g., closures, control flow).

By following these steps, you can systematically analyze the provided Go code, understand its purpose, explain the inlining features it tests, provide illustrative examples, and highlight potential pitfalls for developers.
这段代码是 Go 语言编译器内联功能的测试用例。它通过设置特定的编译器诊断标志，来验证编译器是否按照预期执行了函数内联。

**功能概览:**

这段代码的主要功能是编写了一系列 Go 函数，并使用 `// ERROR` 注释来标记编译器在启用特定标志 (`-m`) 时应该输出的诊断信息。这些诊断信息主要关注以下几点：

1. **哪些函数可以被内联 (`can inline ...`)**: 编译器会分析函数体，判断其是否满足内联的条件。
2. **哪些函数调用被内联 (`inlining call to ...`)**: 编译器会尝试将符合条件的函数调用替换为被调用函数的代码。
3. **参数是否逃逸 (`leaking param: ... to result`, `... escapes to heap`, `... does not escape`)**:  内联器会分析参数是否会逃逸到堆上，这会影响内联的决策。
4. **闭包是否被内联 (`can inline ...func1`, `func literal does not escape`)**:  测试内联包含闭包的函数。
5. **特定代码结构的内联行为**: 测试 `switch` 语句、`for` 循环、`select` 语句等控制流结构在内联时的处理。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **函数内联 (Function Inlining)** 功能的测试。函数内联是一种编译器优化技术，它将函数调用处的代码替换为被调用函数的函数体。这样做可以减少函数调用的开销，提高程序的执行效率。

**Go 代码举例说明:**

以下是一些从提供的代码中提取出来的，并稍作修改以更清晰地展示内联效果的例子：

**示例 1: 简单函数的内联**

```go
package main

func add(a, b int) int { // 编译器会提示 "can inline add"
	return a + b
}

func main() { // 编译器会提示 "can inline main"
	result := add(2, 3) // 编译器会提示 "inlining call to add"
	println(result)
}

// 假设的编译器内联后的代码 (仅为示意，实际可能更复杂)
// func main() {
// 	result := 2 + 3
// 	println(result)
// }
```

**假设的输入与输出:**

* **输入:** 编译并运行上述代码。
* **输出:** `5`

**示例 2: 带有闭包的函数的内联**

```go
package main

func outer(x int) func() int { // 编译器会提示 "can inline outer"
	y := 10
	return func() int { // 编译器会提示 "can inline outer.func1" "func literal does not escape"
		return x + y
	}
}

func main() { // 编译器会提示 "can inline main"
	closure := outer(5) // 编译器会提示 "inlining call to outer"
	result := closure()  // 编译器会提示 "inlining call to outer.func1"
	println(result)
}

// 假设的编译器内联后的代码 (仅为示意)
// func main() {
// 	y := 10
// 	result := 5 + y
// 	println(result)
// }
```

**假设的输入与输出:**

* **输入:** 编译并运行上述代码。
* **输出:** `15`

**命令行参数的具体处理:**

这段代码本身不是一个可执行的程序，它是一个测试文件。它依赖于 Go 的测试工具链 (`go test`) 和特定的编译器标志来验证内联行为。

主要的命令行参数是传递给 `go test` 的，通过注释 `// errorcheckwithauto -0 -m -d=inlfuncswithclosures=1` 指定。

* **`-0`**:  表示禁用大部分优化。这很重要，因为我们希望看到内联 *发生* 的诊断信息，而不是优化器完全移除了函数调用。
* **`-m`**: 启用编译器优化/诊断信息输出。这使得编译器会打印出诸如 "can inline ..." 和 "inlining call to ..." 这样的消息。
* **`-d=inlfuncswithclosures=1`**:  这是一个更细粒度的调试标志，用于启用对包含闭包的函数的内联。

当使用 `go test` 运行这个文件时，Go 的测试框架会调用编译器，并传递这些标志。编译器会根据这些标志执行编译和诊断分析，然后将实际的诊断输出与代码中的 `// ERROR` 注释进行比较，以判断测试是否通过。

**使用者易犯错的点:**

1. **误以为所有小函数都会被内联:**  虽然内联通常针对小函数，但编译器会考虑多种因素，例如函数复杂度、调用频率、参数逃逸等。即使是很小的函数，如果编译器认为内联的成本高于收益，也可能不会被内联。

   ```go
   package main

   import "fmt"

   // 即使函数体很简单，如果调用次数不多，可能不会被内联
   func verySimpleFunc(x int) int {
       return x + 1
   }

   func main() {
       fmt.Println(verySimpleFunc(1))
       fmt.Println(verySimpleFunc(2))
       // ... 只有少数几次调用
   }
   ```

2. **过度依赖内联来解决性能问题:** 内联是一种有用的优化，但不应该被视为解决所有性能问题的银弹。过早地关注内联可能会导致代码可读性下降。应该先关注代码的整体结构和算法效率。

3. **不理解参数逃逸对内联的影响:** 如果函数的参数或返回值逃逸到堆上（例如，返回指向局部变量的指针），编译器可能无法内联该函数。

   ```go
   package main

   // 参数 p 逃逸到返回值，可能阻止内联
   func createPointer(val int) *int {
       x := val
       return &x
   }

   func main() {
       ptr := createPointer(10)
       fmt.Println(*ptr)
   }
   ```

4. **忽略编译器诊断信息:** 开发者应该关注编译器在使用 `-m` 标志时输出的内联相关的诊断信息。这些信息可以帮助理解编译器为什么会或不会内联特定的函数。

5. **在基准测试中得出不准确的结论:**  在进行性能基准测试时，如果没有正确理解内联的影响，可能会得出不准确的结论。例如，在 `-gcflags=-l` (禁用内联) 的情况下运行基准测试，结果可能会与启用内联时有很大差异。

总之，这段代码是 Go 语言编译器内联功能的一个测试用例，它通过诊断信息来验证内联行为。理解内联的工作原理和编译器的决策过程对于编写高效的 Go 代码非常重要。

### 提示词
```
这是路径为go/test/inline.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
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
```