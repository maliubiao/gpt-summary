Response: My thinking process to answer the request about `escape2n.go` goes like this:

1. **Understand the Goal:** The primary purpose of this Go code is to test the compiler's escape analysis. This means the code is intentionally crafted to create various scenarios where variables might or might not escape to the heap. The comments with `// ERROR ...` are crucial; they are *assertions* about the compiler's escape analysis output.

2. **Identify Key Features/Functionality:** Based on the code and the comments, the core functionality is to present a series of functions and code snippets demonstrating different escape scenarios. These scenarios involve:
    * Taking the address of local variables and returning them.
    * Assigning the address of local variables to global variables.
    * Passing pointers to functions.
    * Returning pointers from functions.
    * Using closures and how they capture variables.
    * Using data structures like structs, slices, and maps.
    * Interactions with interfaces.
    * Use of `go` routines and `defer` statements.
    * Type assertions and type switches.
    * String and slice operations.
    * Use of `unsafe.Pointer`.

3. **Infer the Broader Go Feature:**  The code directly tests **escape analysis**, a compiler optimization technique. Escape analysis determines whether a variable's lifetime extends beyond the scope in which it's created. If a variable might be accessed after the function returns (e.g., it's returned as a pointer, captured by a closure that outlives the function, or assigned to the heap), it "escapes" to the heap. Otherwise, it can reside on the stack, which is generally faster.

4. **Provide a Code Example:** I need to illustrate escape analysis in action. A simple function returning the address of a local variable is the most direct example of escaping to the heap. I'll provide a `main` function to call it and demonstrate the behavior.

5. **Explain Command-Line Arguments:** The initial comment `// errorcheck -0 -N -m -l` is the key here. I need to explain what these flags mean in the context of the Go compiler:
    * `-0`:  Optimization level 0 (disables optimizations, making escape analysis more explicit).
    * `-N`: Disable optimizations, specifically registerization. While the comment notes it shouldn't affect escape analysis, it's worth mentioning.
    * `-m`: Enable compiler optimizations output, which includes escape analysis details. This is the most important flag for this test.
    * `-l`:  Disable inlining. This is crucial because inlining can sometimes obscure escape behavior.

6. **Address Potential User Errors:**  The most common mistake when dealing with pointers and escape analysis is misunderstanding when a variable will be allocated on the heap. Specifically, users might assume a local variable always stays on the stack. I'll provide an example of this misconception. Another common error is not understanding how closures capture variables.

7. **Structure the Answer:**  I will organize the answer logically:
    * Start with a summary of the file's purpose.
    * Explain the Go feature being demonstrated (escape analysis).
    * Provide a clear Go code example with input and output (showing the heap allocation).
    * Detail the command-line arguments.
    * Highlight common mistakes users make.

8. **Refine and Review:** Before submitting, I'll reread the answer to ensure clarity, accuracy, and completeness, double-checking that I've addressed all parts of the original request. I'll ensure my code examples are correct and the explanations of the command-line arguments are precise. I'll also make sure the examples of user errors are relevant and easy to understand. For instance, I considered using more complex examples, but simpler ones are better for illustrating the core concepts. I also made sure to explicitly state that the `// ERROR` comments are not standard Go syntax but are specific to this test file.

By following these steps, I can provide a comprehensive and accurate answer to the user's request, going beyond simply listing the functions and actually explaining the *why* and *how* of the `escape2n.go` file.
`go/test/escape2n.go` 是 Go 语言编译器的测试文件，专门用于测试**逃逸分析 (escape analysis)** 功能的正确性。

**功能列举:**

1. **演示变量逃逸到堆上的各种场景:**  文件中定义了大量的函数，这些函数通过不同的方式操作变量，旨在触发各种变量逃逸到堆上的情况。
2. **使用编译器诊断标志验证逃逸分析结果:**  文件开头的 `// errorcheck -0 -N -m -l` 注释指示 Go 编译器在编译此文件时使用特定的标志。`-m` 标志会输出编译优化信息，其中包括逃逸分析的结果。注释中的 `// ERROR "..."` 行是对编译器输出的预期结果进行断言，用于验证逃逸分析是否正确。
3. **测试不同类型的逃逸:** 文件涵盖了各种导致变量逃逸的模式，例如：
    * 将局部变量的地址返回给调用者。
    * 将局部变量的地址赋值给全局变量。
    * 将局部变量的地址传递给指针类型的参数。
    * 闭包捕获外部变量。
    * 将变量传递给 `interface{}` 类型的参数。
    * 使用 `go` 关键字启动 goroutine 并访问局部变量。
    * 使用 `defer` 延迟执行并访问局部变量。
    * 在 `map` 或 `slice` 中存储局部变量的指针。
    * 对字符串和切片进行操作，可能导致底层数据逃逸。
4. **测试不同数据类型的逃逸:** 文件中的测试用例涵盖了基本类型（如 `int`）、指针类型、结构体、切片、映射、接口等。
5. **测试 `go:noescape` 指令:**  文件中包含使用 `//go:noescape` 指令标记的函数，用于测试编译器是否正确处理了强制禁止逃逸的情况。
6. **测试与 `unsafe` 包的交互:** 文件中包含使用 `unsafe.Pointer` 的示例，用于测试逃逸分析在处理不安全代码时的行为。
7. **测试循环和控制流对逃逸分析的影响:** 文件中包含了在循环和条件语句中定义变量的场景，以测试逃逸分析如何处理这些情况。

**Go 语言逃逸分析功能实现举例:**

逃逸分析是 Go 编译器的一个重要优化手段。它决定了变量应该分配在栈上还是堆上。分配在栈上的变量拥有更快的访问速度，而分配在堆上的变量拥有更长的生命周期。

**示例 1: 局部变量逃逸到堆上 (通过返回其地址)**

```go
package main

import "fmt"

func createValue() *int {
	x := 10
	return &x // x 的地址被返回，x 逃逸到堆上
}

func main() {
	ptr := createValue()
	fmt.Println(*ptr)
}
```

**假设输入与输出:**

* **输入:** 无
* **预期输出:** `10`

**编译器逃逸分析输出 (使用 `go build -gcflags=-m main.go`):**

```
./main.go:6:6: moved to heap: x
```

**解释:**  编译器检测到 `createValue` 函数返回了局部变量 `x` 的地址，这意味着 `x` 的生命周期可能超出函数的作用域，因此将其分配到堆上。

**示例 2: 局部变量逃逸到堆上 (通过闭包捕获)**

```go
package main

import "fmt"

func createClosure() func() {
	x := 20
	return func() { // 匿名函数捕获了外部变量 x
		fmt.Println(x)
	}
}

func main() {
	closure := createClosure()
	closure()
}
```

**假设输入与输出:**

* **输入:** 无
* **预期输出:** `20`

**编译器逃逸分析输出 (使用 `go build -gcflags=-m main.go`):**

```
./main.go:6:6: moved to heap: x
./main.go:7:9: func literal escapes to heap
```

**解释:** 匿名函数（闭包）引用了外部变量 `x`。即使 `createClosure` 函数执行完毕，闭包仍然可能被调用并访问 `x`，所以 `x` 逃逸到堆上，并且闭包本身也逃逸到了堆上。

**命令行参数处理:**

`go/test/escape2n.go` 本身不是一个可执行的程序，它是一个测试文件，需要使用 Go 编译器的测试工具链来执行。  文件开头的注释 `// errorcheck -0 -N -m -l`  指示了 `go tool compile` 命令应该使用的标志：

* **`-0`:**  禁用所有优化。这可以使逃逸分析的结果更加直接和明显。
* **`-N`:** 禁用寄存器优化。 虽然这通常不直接影响逃逸分析，但在某些情况下可以使分析结果更清晰。
* **`-m`:** 启用编译优化信息的打印，这会输出详细的逃逸分析结果，例如哪些变量移动到了堆上。这是验证逃逸分析的关键标志。
* **`-l`:** 禁用函数内联。内联可以将函数调用替换为函数体，这可能会改变变量的逃逸行为。禁用内联可以更精确地测试函数调用时的逃逸情况。

要运行此测试文件，通常不需要手动指定这些标志。Go 的测试框架会自动处理这些编译选项。

**使用者易犯错的点:**

1. **误认为局部变量总是在栈上:**  初学者可能认为在函数内部声明的变量总是分配在栈上。逃逸分析的目的是在保证程序正确性的前提下，尽可能地将变量分配在栈上以提高性能。但是，当变量的生命周期可能超出其声明的作用域时，它会被分配到堆上。

   **错误示例:**

   ```go
   package main

   import "fmt"

   func returnPointer() *int {
       i := 5
       return &i // 错误地认为 i 会一直存在于栈上
   }

   func main() {
       ptr := returnPointer()
       fmt.Println(*ptr) // 尽管能正常运行，但 ptr 指向的是堆上的内存
   }
   ```

2. **不理解闭包的变量捕获:**  闭包可以访问和修改其定义时所在作用域的变量。如果闭包的生命周期比其捕获的变量长，那么这些变量很可能会逃逸到堆上。

   **错误示例:**

   ```go
   package main

   import "fmt"

   func createCounters() []func() int {
       var counters []func() int
       for i := 0; i < 3; i++ {
           counters = append(counters, func() int {
               return i // 错误地认为每个闭包都会捕获不同的 i 值
           })
       }
       return counters
   }

   func main() {
       for _, counter := range createCounters() {
           fmt.Println(counter()) // 输出都是 3，因为闭包捕获的是同一个 i 变量的引用
       }
   }
   ```

   **正确的做法 (将 `i` 复制到闭包内部):**

   ```go
   package main

   import "fmt"

   func createCounters() []func() int {
       var counters []func() int
       for i := 0; i < 3; i++ {
           j := i // 将 i 的值复制到 j
           counters = append(counters, func() int {
               return j
           })
       }
       return counters
   }

   func main() {
       for _, counter := range createCounters() {
           fmt.Println(counter()) // 输出 0, 1, 2
       }
   }
   ```

3. **忽略 `go` 关键字对逃逸的影响:**  当使用 `go` 关键字启动一个新的 goroutine 时，如果该 goroutine 访问了当前函数的局部变量，这些变量通常会逃逸到堆上，以确保 goroutine 可以安全地访问它们。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func process(data int) {
       fmt.Println("Processing:", data)
   }

   func main() {
       for i := 0; i < 5; i++ {
           go process(i) // 错误地认为 process 函数会立即使用 i 的值
       }
       time.Sleep(time.Second) // 模拟等待 goroutine 完成，但可能不是所有 goroutine 都能正确拿到 i 的值
   }
   ```

   **正确的做法 (将数据作为参数传递给 goroutine):**

   ```go
   package main

   import (
       "fmt"
       "time"
   )

   func process(data int) {
       fmt.Println("Processing:", data)
   }

   func main() {
       for i := 0; i < 5; i++ {
           data := i // 在循环内部创建局部变量
           go process(data)
       }
       time.Sleep(time.Second)
   }
   ```

理解逃逸分析对于编写高性能的 Go 代码至关重要。虽然 Go 编译器会自动处理逃逸分析，但了解其原理可以帮助开发者避免一些潜在的性能陷阱。 `go/test/escape2n.go` 提供了一个很好的学习逃逸分析各种场景的资源。

Prompt: 
```
这是路径为go/test/escape2n.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// errorcheck -0 -N -m -l

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test, using compiler diagnostic flags, that the escape analysis is working.
// Compiles but does not run.  Inlining is disabled.
// Registerization is disabled too (-N), which should
// have no effect on escape analysis.

package foo

import (
	"fmt"
	"unsafe"
)

var gxx *int

func foo1(x int) { // ERROR "moved to heap: x$"
	gxx = &x
}

func foo2(yy *int) { // ERROR "leaking param: yy$"
	gxx = yy
}

func foo3(x int) *int { // ERROR "moved to heap: x$"
	return &x
}

type T *T

func foo3b(t T) { // ERROR "leaking param: t$"
	*t = t
}

// xx isn't going anywhere, so use of yy is ok
func foo4(xx, yy *int) { // ERROR "xx does not escape$" "yy does not escape$"
	xx = yy
}

// xx isn't going anywhere, so taking address of yy is ok
func foo5(xx **int, yy *int) { // ERROR "xx does not escape$" "yy does not escape$"
	xx = &yy
}

func foo6(xx **int, yy *int) { // ERROR "xx does not escape$" "leaking param: yy$"
	*xx = yy
}

func foo7(xx **int, yy *int) { // ERROR "xx does not escape$" "yy does not escape$"
	**xx = *yy
}

func foo8(xx, yy *int) int { // ERROR "xx does not escape$" "yy does not escape$"
	xx = yy
	return *xx
}

func foo9(xx, yy *int) *int { // ERROR "leaking param: xx to result ~r0 level=0$" "leaking param: yy to result ~r0 level=0$"
	xx = yy
	return xx
}

func foo10(xx, yy *int) { // ERROR "xx does not escape$" "yy does not escape$"
	*xx = *yy
}

func foo11() int {
	x, y := 0, 42
	xx := &x
	yy := &y
	*xx = *yy
	return x
}

var xxx **int

func foo12(yyy **int) { // ERROR "leaking param: yyy$"
	xxx = yyy
}

// Must treat yyy as leaking because *yyy leaks, and the escape analysis
// summaries in exported metadata do not distinguish these two cases.
func foo13(yyy **int) { // ERROR "leaking param content: yyy$"
	*xxx = *yyy
}

func foo14(yyy **int) { // ERROR "yyy does not escape$"
	**xxx = **yyy
}

func foo15(yy *int) { // ERROR "moved to heap: yy$"
	xxx = &yy
}

func foo16(yy *int) { // ERROR "leaking param: yy$"
	*xxx = yy
}

func foo17(yy *int) { // ERROR "yy does not escape$"
	**xxx = *yy
}

func foo18(y int) { // ERROR "moved to heap: y$"
	*xxx = &y
}

func foo19(y int) {
	**xxx = y
}

type Bar struct {
	i  int
	ii *int
}

func NewBar() *Bar {
	return &Bar{42, nil} // ERROR "&Bar{...} escapes to heap$"
}

func NewBarp(x *int) *Bar { // ERROR "leaking param: x$"
	return &Bar{42, x} // ERROR "&Bar{...} escapes to heap$"
}

func NewBarp2(x *int) *Bar { // ERROR "x does not escape$"
	return &Bar{*x, nil} // ERROR "&Bar{...} escapes to heap$"
}

func (b *Bar) NoLeak() int { // ERROR "b does not escape$"
	return *(b.ii)
}

func (b *Bar) Leak() *int { // ERROR "leaking param: b to result ~r0 level=0$"
	return &b.i
}

func (b *Bar) AlsoNoLeak() *int { // ERROR "leaking param: b to result ~r0 level=1$"
	return b.ii
}

func (b Bar) AlsoLeak() *int { // ERROR "leaking param: b to result ~r0 level=0$"
	return b.ii
}

func (b Bar) LeaksToo() *int { // ERROR "leaking param: b to result ~r0 level=0$"
	v := 0 // ERROR "moved to heap: v$"
	b.ii = &v
	return b.ii
}

func (b *Bar) LeaksABit() *int { // ERROR "leaking param: b to result ~r0 level=1$"
	v := 0 // ERROR "moved to heap: v$"
	b.ii = &v
	return b.ii
}

func (b Bar) StillNoLeak() int { // ERROR "b does not escape$"
	v := 0
	b.ii = &v
	return b.i
}

func goLeak(b *Bar) { // ERROR "leaking param: b$"
	go b.NoLeak()
}

type Bar2 struct {
	i  [12]int
	ii []int
}

func NewBar2() *Bar2 {
	return &Bar2{[12]int{42}, nil} // ERROR "&Bar2{...} escapes to heap$"
}

func (b *Bar2) NoLeak() int { // ERROR "b does not escape$"
	return b.i[0]
}

func (b *Bar2) Leak() []int { // ERROR "leaking param: b to result ~r0 level=0$"
	return b.i[:]
}

func (b *Bar2) AlsoNoLeak() []int { // ERROR "leaking param: b to result ~r0 level=1$"
	return b.ii[0:1]
}

func (b Bar2) AgainNoLeak() [12]int { // ERROR "b does not escape$"
	return b.i
}

func (b *Bar2) LeakSelf() { // ERROR "leaking param: b$"
	b.ii = b.i[0:4]
}

func (b *Bar2) LeakSelf2() { // ERROR "leaking param: b$"
	var buf []int
	buf = b.i[0:]
	b.ii = buf
}

func foo21() func() int {
	x := 42
	return func() int { // ERROR "func literal escapes to heap$"
		return x
	}
}

func foo21a() func() int {
	x := 42             // ERROR "moved to heap: x$"
	return func() int { // ERROR "func literal escapes to heap$"
		x++
		return x
	}
}

func foo22() int {
	x := 42
	return func() int { // ERROR "func literal does not escape$"
		return x
	}()
}

func foo23(x int) func() int {
	return func() int { // ERROR "func literal escapes to heap$"
		return x
	}
}

func foo23a(x int) func() int {
	f := func() int { // ERROR "func literal escapes to heap$"
		return x
	}
	return f
}

func foo23b(x int) *(func() int) {
	f := func() int { return x } // ERROR "func literal escapes to heap$" "moved to heap: f$"
	return &f
}

func foo23c(x int) func() int { // ERROR "moved to heap: x$"
	return func() int { // ERROR "func literal escapes to heap$"
		x++
		return x
	}
}

func foo24(x int) int {
	return func() int { // ERROR "func literal does not escape$"
		return x
	}()
}

var x *int

func fooleak(xx *int) int { // ERROR "leaking param: xx$"
	x = xx
	return *x
}

func foonoleak(xx *int) int { // ERROR "xx does not escape$"
	return *x + *xx
}

func foo31(x int) int { // ERROR "moved to heap: x$"
	return fooleak(&x)
}

func foo32(x int) int {
	return foonoleak(&x)
}

type Foo struct {
	xx *int
	x  int
}

var F Foo
var pf *Foo

func (f *Foo) fooleak() { // ERROR "leaking param: f$"
	pf = f
}

func (f *Foo) foonoleak() { // ERROR "f does not escape$"
	F.x = f.x
}

func (f *Foo) Leak() { // ERROR "leaking param: f$"
	f.fooleak()
}

func (f *Foo) NoLeak() { // ERROR "f does not escape$"
	f.foonoleak()
}

func foo41(x int) { // ERROR "moved to heap: x$"
	F.xx = &x
}

func (f *Foo) foo42(x int) { // ERROR "f does not escape$" "moved to heap: x$"
	f.xx = &x
}

func foo43(f *Foo, x int) { // ERROR "f does not escape$" "moved to heap: x$"
	f.xx = &x
}

func foo44(yy *int) { // ERROR "leaking param: yy$"
	F.xx = yy
}

func (f *Foo) foo45() { // ERROR "f does not escape$"
	F.x = f.x
}

// See foo13 above for explanation of why f leaks.
func (f *Foo) foo46() { // ERROR "leaking param content: f$"
	F.xx = f.xx
}

func (f *Foo) foo47() { // ERROR "leaking param: f$"
	f.xx = &f.x
}

var ptrSlice []*int

func foo50(i *int) { // ERROR "leaking param: i$"
	ptrSlice[0] = i
}

var ptrMap map[*int]*int

func foo51(i *int) { // ERROR "leaking param: i$"
	ptrMap[i] = i
}

func indaddr1(x int) *int { // ERROR "moved to heap: x$"
	return &x
}

func indaddr2(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	return *&x
}

func indaddr3(x *int32) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	return *(**int)(unsafe.Pointer(&x))
}

// From package math:

func Float32bits(f float32) uint32 {
	return *(*uint32)(unsafe.Pointer(&f))
}

func Float32frombits(b uint32) float32 {
	return *(*float32)(unsafe.Pointer(&b))
}

func Float64bits(f float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&f))
}

func Float64frombits(b uint64) float64 {
	return *(*float64)(unsafe.Pointer(&b))
}

// contrast with
func float64bitsptr(f float64) *uint64 { // ERROR "moved to heap: f$"
	return (*uint64)(unsafe.Pointer(&f))
}

func float64ptrbitsptr(f *float64) *uint64 { // ERROR "leaking param: f to result ~r0 level=0$"
	return (*uint64)(unsafe.Pointer(f))
}

func typesw(i interface{}) *int { // ERROR "leaking param: i to result ~r0 level=0$"
	switch val := i.(type) {
	case *int:
		return val
	case *int8:
		v := int(*val) // ERROR "moved to heap: v$"
		return &v
	}
	return nil
}

func exprsw(i *int) *int { // ERROR "leaking param: i to result ~r0 level=0$"
	switch j := i; *j + 110 {
	case 12:
		return j
	case 42:
		return nil
	}
	return nil
}

// assigning to an array element is like assigning to the array
func foo60(i *int) *int { // ERROR "leaking param: i to result ~r0 level=0$"
	var a [12]*int
	a[0] = i
	return a[1]
}

func foo60a(i *int) *int { // ERROR "i does not escape$"
	var a [12]*int
	a[0] = i
	return nil
}

// assigning to a struct field  is like assigning to the struct
func foo61(i *int) *int { // ERROR "leaking param: i to result ~r0 level=0$"
	type S struct {
		a, b *int
	}
	var s S
	s.a = i
	return s.b
}

func foo61a(i *int) *int { // ERROR "i does not escape$"
	type S struct {
		a, b *int
	}
	var s S
	s.a = i
	return nil
}

// assigning to a struct field is like assigning to the struct but
// here this subtlety is lost, since s.a counts as an assignment to a
// track-losing dereference.
func foo62(i *int) *int { // ERROR "leaking param: i$"
	type S struct {
		a, b *int
	}
	s := new(S) // ERROR "new\(S\) does not escape$"
	s.a = i
	return nil // s.b
}

type M interface {
	M()
}

func foo63(m M) { // ERROR "m does not escape$"
}

func foo64(m M) { // ERROR "leaking param: m$"
	m.M()
}

func foo64b(m M) { // ERROR "leaking param: m$"
	defer m.M()
}

type MV int

func (MV) M() {}

func foo65() {
	var mv MV
	foo63(&mv)
}

func foo66() {
	var mv MV // ERROR "moved to heap: mv$"
	foo64(&mv)
}

func foo67() {
	var mv MV
	foo63(mv) // ERROR "mv does not escape$"
}

func foo68() {
	var mv MV
	// escapes but it's an int so irrelevant
	foo64(mv) // ERROR "mv escapes to heap$"
}

func foo69(m M) { // ERROR "leaking param: m$"
	foo64(m)
}

func foo70(mv1 *MV, m M) { // ERROR "leaking param: m$" "leaking param: mv1$"
	m = mv1
	foo64(m)
}

func foo71(x *int) []*int { // ERROR "leaking param: x$"
	var y []*int
	y = append(y, x)
	return y
}

func foo71a(x int) []*int { // ERROR "moved to heap: x$"
	var y []*int
	y = append(y, &x)
	return y
}

func foo72() {
	var x int
	var y [1]*int
	y[0] = &x
}

func foo72aa() [10]*int {
	var x int // ERROR "moved to heap: x$"
	var y [10]*int
	y[0] = &x
	return y
}

func foo72a() {
	var y [10]*int
	for i := 0; i < 10; i++ {
		// escapes its scope
		x := i // ERROR "moved to heap: x$"
		y[i] = &x
	}
	return
}

func foo72b() [10]*int {
	var y [10]*int
	for i := 0; i < 10; i++ {
		x := i // ERROR "moved to heap: x$"
		y[i] = &x
	}
	return y
}

// issue 2145
func foo73() {
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for _, v := range s {
		vv := v
		// actually just escapes its scope
		defer func() { // ERROR "func literal escapes to heap$"
			println(vv)
		}()
	}
}

func foo731() {
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for _, v := range s {
		vv := v // ERROR "moved to heap: vv$"
		// actually just escapes its scope
		defer func() { // ERROR "func literal escapes to heap$"
			vv = 42
			println(vv)
		}()
	}
}

func foo74() {
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for _, v := range s {
		vv := v
		// actually just escapes its scope
		fn := func() { // ERROR "func literal escapes to heap$"
			println(vv)
		}
		defer fn()
	}
}

func foo74a() {
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for _, v := range s {
		vv := v // ERROR "moved to heap: vv$"
		// actually just escapes its scope
		fn := func() { // ERROR "func literal escapes to heap$"
			vv += 1
			println(vv)
		}
		defer fn()
	}
}

// issue 3975
func foo74b() {
	var array [3]func()
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for i, v := range s {
		vv := v
		// actually just escapes its scope
		array[i] = func() { // ERROR "func literal escapes to heap$"
			println(vv)
		}
	}
}

func foo74c() {
	var array [3]func()
	s := []int{3, 2, 1} // ERROR "\[\]int{...} does not escape$"
	for i, v := range s {
		vv := v // ERROR "moved to heap: vv$"
		// actually just escapes its scope
		array[i] = func() { // ERROR "func literal escapes to heap$"
			println(&vv)
		}
	}
}

func myprint(y *int, x ...interface{}) *int { // ERROR "leaking param: y to result ~r0 level=0$" "x does not escape$"
	return y
}

func myprint1(y *int, x ...interface{}) *interface{} { // ERROR "leaking param: x to result ~r0 level=0$" "y does not escape$"
	return &x[0]
}

func foo75(z *int) { // ERROR "z does not escape$"
	myprint(z, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo75a(z *int) { // ERROR "z does not escape$"
	myprint1(z, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo75esc(z *int) { // ERROR "leaking param: z$"
	gxx = myprint(z, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo75aesc(z *int) { // ERROR "z does not escape$"
	var ppi **interface{}       // assignments to pointer dereferences lose track
	*ppi = myprint1(z, 1, 2, 3) // ERROR "... argument escapes to heap$" "1 escapes to heap$" "2 escapes to heap$" "3 escapes to heap$"
}

func foo75aesc1(z *int) { // ERROR "z does not escape$"
	sink = myprint1(z, 1, 2, 3) // ERROR "... argument escapes to heap$" "1 escapes to heap$" "2 escapes to heap$" "3 escapes to heap$"
}

func foo76(z *int) { // ERROR "z does not escape"
	myprint(nil, z) // ERROR "... argument does not escape$"
}

func foo76a(z *int) { // ERROR "z does not escape"
	myprint1(nil, z) // ERROR "... argument does not escape$"
}

func foo76b() {
	myprint(nil, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo76c() {
	myprint1(nil, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo76d() {
	defer myprint(nil, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo76e() {
	defer myprint1(nil, 1, 2, 3) // ERROR "1 does not escape" "2 does not escape" "3 does not escape" "... argument does not escape$"
}

func foo76f() {
	for {
		// TODO: This one really only escapes its scope, but we don't distinguish yet.
		defer myprint(nil, 1, 2, 3) // ERROR "... argument does not escape$" "1 escapes to heap$" "2 escapes to heap$" "3 escapes to heap$"
	}
}

func foo76g() {
	for {
		defer myprint1(nil, 1, 2, 3) // ERROR "... argument does not escape$" "1 escapes to heap$" "2 escapes to heap$" "3 escapes to heap$"
	}
}

func foo77(z []interface{}) { // ERROR "z does not escape$"
	myprint(nil, z...) // z does not escape
}

func foo77a(z []interface{}) { // ERROR "z does not escape$"
	myprint1(nil, z...)
}

func foo77b(z []interface{}) { // ERROR "leaking param: z$"
	var ppi **interface{}
	*ppi = myprint1(nil, z...)
}

func foo77c(z []interface{}) { // ERROR "leaking param: z$"
	sink = myprint1(nil, z...)
}

func dotdotdot() {
	i := 0
	myprint(nil, &i) // ERROR "... argument does not escape$"

	j := 0
	myprint1(nil, &j) // ERROR "... argument does not escape$"
}

func foo78(z int) *int { // ERROR "moved to heap: z$"
	return &z
}

func foo78a(z int) *int { // ERROR "moved to heap: z$"
	y := &z
	x := &y
	return *x // really return y
}

func foo79() *int {
	return new(int) // ERROR "new\(int\) escapes to heap$"
}

func foo80() *int {
	var z *int
	for {
		// Really just escapes its scope but we don't distinguish
		z = new(int) // ERROR "new\(int\) escapes to heap$"
	}
	_ = z
	return nil
}

func foo81() *int {
	for {
		z := new(int) // ERROR "new\(int\) does not escape$"
		_ = z
	}
	return nil
}

func tee(p *int) (x, y *int) { return p, p } // ERROR "leaking param: p to result x level=0$" "leaking param: p to result y level=0$"

func noop(x, y *int) {} // ERROR "x does not escape$" "y does not escape$"

func foo82() {
	var x, y, z int // ERROR "moved to heap: x$" "moved to heap: y$" "moved to heap: z$"
	go noop(tee(&z))
	go noop(&x, &y)
	for {
		var u, v, w int // ERROR "moved to heap: u$" "moved to heap: v$" "moved to heap: w$"
		defer noop(tee(&u))
		defer noop(&v, &w)
	}
}

type Fooer interface {
	Foo()
}

type LimitedFooer struct {
	Fooer
	N int64
}

func LimitFooer(r Fooer, n int64) Fooer { // ERROR "leaking param: r$"
	return &LimitedFooer{r, n} // ERROR "&LimitedFooer{...} escapes to heap$"
}

func foo90(x *int) map[*int]*int { // ERROR "leaking param: x$"
	return map[*int]*int{nil: x} // ERROR "map\[\*int\]\*int{...} escapes to heap$"
}

func foo91(x *int) map[*int]*int { // ERROR "leaking param: x$"
	return map[*int]*int{x: nil} // ERROR "map\[\*int\]\*int{...} escapes to heap$"
}

func foo92(x *int) [2]*int { // ERROR "leaking param: x to result ~r0 level=0$"
	return [2]*int{x, nil}
}

// does not leak c
func foo93(c chan *int) *int { // ERROR "c does not escape$"
	for v := range c {
		return v
	}
	return nil
}

// does not leak m
func foo94(m map[*int]*int, b bool) *int { // ERROR "leaking param: m to result ~r0 level=1"
	for k, v := range m {
		if b {
			return k
		}
		return v
	}
	return nil
}

// does leak x
func foo95(m map[*int]*int, x *int) { // ERROR "m does not escape$" "leaking param: x$"
	m[x] = x
}

// does not leak m but does leak content
func foo96(m []*int) *int { // ERROR "leaking param: m to result ~r0 level=1"
	return m[0]
}

// does leak m
func foo97(m [1]*int) *int { // ERROR "leaking param: m to result ~r0 level=0$"
	return m[0]
}

// does not leak m
func foo98(m map[int]*int) *int { // ERROR "m does not escape$"
	return m[0]
}

// does leak m
func foo99(m *[1]*int) []*int { // ERROR "leaking param: m to result ~r0 level=0$"
	return m[:]
}

// does not leak m
func foo100(m []*int) *int { // ERROR "leaking param: m to result ~r0 level=1"
	for _, v := range m {
		return v
	}
	return nil
}

// does leak m
func foo101(m [1]*int) *int { // ERROR "leaking param: m to result ~r0 level=0$"
	for _, v := range m {
		return v
	}
	return nil
}

// does not leak m
func foo101a(m [1]*int) *int { // ERROR "m does not escape$"
	for i := range m { // ERROR "moved to heap: i$"
		return &i
	}
	return nil
}

// does leak x
func foo102(m []*int, x *int) { // ERROR "m does not escape$" "leaking param: x$"
	m[0] = x
}

// does not leak x
func foo103(m [1]*int, x *int) { // ERROR "m does not escape$" "x does not escape$"
	m[0] = x
}

var y []*int

// does not leak x but does leak content
func foo104(x []*int) { // ERROR "leaking param content: x"
	copy(y, x)
}

// does not leak x but does leak content
func foo105(x []*int) { // ERROR "leaking param content: x"
	_ = append(y, x...)
}

// does leak x
func foo106(x *int) { // ERROR "leaking param: x$"
	_ = append(y, x)
}

func foo107(x *int) map[*int]*int { // ERROR "leaking param: x$"
	return map[*int]*int{x: nil} // ERROR "map\[\*int\]\*int{...} escapes to heap$"
}

func foo108(x *int) map[*int]*int { // ERROR "leaking param: x$"
	return map[*int]*int{nil: x} // ERROR "map\[\*int\]\*int{...} escapes to heap$"
}

func foo109(x *int) *int { // ERROR "leaking param: x$"
	m := map[*int]*int{x: nil} // ERROR "map\[\*int\]\*int{...} does not escape$"
	for k, _ := range m {
		return k
	}
	return nil
}

func foo110(x *int) *int { // ERROR "leaking param: x$"
	m := map[*int]*int{nil: x} // ERROR "map\[\*int\]\*int{...} does not escape$"
	return m[nil]
}

func foo111(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0"
	m := []*int{x} // ERROR "\[\]\*int{...} does not escape$"
	return m[0]
}

func foo112(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	m := [1]*int{x}
	return m[0]
}

func foo113(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	m := Bar{ii: x}
	return m.ii
}

func foo114(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	m := &Bar{ii: x} // ERROR "&Bar{...} does not escape$"
	return m.ii
}

func foo115(x *int) *int { // ERROR "leaking param: x to result ~r0 level=0$"
	return (*int)(unsafe.Pointer(uintptr(unsafe.Pointer(x)) + 1))
}

func foo116(b bool) *int {
	if b {
		x := 1 // ERROR "moved to heap: x$"
		return &x
	} else {
		y := 1 // ERROR "moved to heap: y$"
		return &y
	}
	return nil
}

func foo117(unknown func(interface{})) { // ERROR "unknown does not escape$"
	x := 1 // ERROR "moved to heap: x$"
	unknown(&x)
}

func foo118(unknown func(*int)) { // ERROR "unknown does not escape$"
	x := 1 // ERROR "moved to heap: x$"
	unknown(&x)
}

func external(*int)

func foo119(x *int) { // ERROR "leaking param: x$"
	external(x)
}

func foo120() {
	// formerly exponential time analysis
L1:
L2:
L3:
L4:
L5:
L6:
L7:
L8:
L9:
L10:
L11:
L12:
L13:
L14:
L15:
L16:
L17:
L18:
L19:
L20:
L21:
L22:
L23:
L24:
L25:
L26:
L27:
L28:
L29:
L30:
L31:
L32:
L33:
L34:
L35:
L36:
L37:
L38:
L39:
L40:
L41:
L42:
L43:
L44:
L45:
L46:
L47:
L48:
L49:
L50:
L51:
L52:
L53:
L54:
L55:
L56:
L57:
L58:
L59:
L60:
L61:
L62:
L63:
L64:
L65:
L66:
L67:
L68:
L69:
L70:
L71:
L72:
L73:
L74:
L75:
L76:
L77:
L78:
L79:
L80:
L81:
L82:
L83:
L84:
L85:
L86:
L87:
L88:
L89:
L90:
L91:
L92:
L93:
L94:
L95:
L96:
L97:
L98:
L99:
L100:
	// use the labels to silence compiler errors
	goto L1
	goto L2
	goto L3
	goto L4
	goto L5
	goto L6
	goto L7
	goto L8
	goto L9
	goto L10
	goto L11
	goto L12
	goto L13
	goto L14
	goto L15
	goto L16
	goto L17
	goto L18
	goto L19
	goto L20
	goto L21
	goto L22
	goto L23
	goto L24
	goto L25
	goto L26
	goto L27
	goto L28
	goto L29
	goto L30
	goto L31
	goto L32
	goto L33
	goto L34
	goto L35
	goto L36
	goto L37
	goto L38
	goto L39
	goto L40
	goto L41
	goto L42
	goto L43
	goto L44
	goto L45
	goto L46
	goto L47
	goto L48
	goto L49
	goto L50
	goto L51
	goto L52
	goto L53
	goto L54
	goto L55
	goto L56
	goto L57
	goto L58
	goto L59
	goto L60
	goto L61
	goto L62
	goto L63
	goto L64
	goto L65
	goto L66
	goto L67
	goto L68
	goto L69
	goto L70
	goto L71
	goto L72
	goto L73
	goto L74
	goto L75
	goto L76
	goto L77
	goto L78
	goto L79
	goto L80
	goto L81
	goto L82
	goto L83
	goto L84
	goto L85
	goto L86
	goto L87
	goto L88
	goto L89
	goto L90
	goto L91
	goto L92
	goto L93
	goto L94
	goto L95
	goto L96
	goto L97
	goto L98
	goto L99
	goto L100
}

func foo121() {
	for i := 0; i < 10; i++ {
		defer myprint(nil, i) // ERROR "... argument does not escape$" "i escapes to heap$"
		go myprint(nil, i)    // ERROR "... argument does not escape$" "i escapes to heap$"
	}
}

// same as foo121 but check across import
func foo121b() {
	for i := 0; i < 10; i++ {
		defer fmt.Printf("%d", i) // ERROR "... argument does not escape$" "i escapes to heap$"
		go fmt.Printf("%d", i)    // ERROR "... argument does not escape$" "i escapes to heap$"
	}
}

// a harmless forward jump
func foo122() {
	var i *int

	goto L1
L1:
	i = new(int) // ERROR "new\(int\) does not escape$"
	_ = i
}

// a backward jump, increases loopdepth
func foo123() {
	var i *int

L1:
	i = new(int) // ERROR "new\(int\) escapes to heap$"

	goto L1
	_ = i
}

func foo124(x **int) { // ERROR "x does not escape$"
	var i int // ERROR "moved to heap: i$"
	p := &i
	func() { // ERROR "func literal does not escape$"
		*x = p
	}()
}

func foo125(ch chan *int) { // ERROR "ch does not escape$"
	var i int // ERROR "moved to heap: i$"
	p := &i
	func() { // ERROR "func literal does not escape$"
		ch <- p
	}()
}

func foo126() {
	var px *int // loopdepth 0
	for {
		// loopdepth 1
		var i int // ERROR "moved to heap: i$"
		func() {  // ERROR "func literal does not escape$"
			px = &i
		}()
	}
	_ = px
}

var px *int

func foo127() {
	var i int // ERROR "moved to heap: i$"
	p := &i
	q := p
	px = q
}

func foo128() {
	var i int
	p := &i
	q := p
	_ = q
}

func foo129() {
	var i int // ERROR "moved to heap: i$"
	p := &i
	func() { // ERROR "func literal does not escape$"
		q := p
		func() { // ERROR "func literal does not escape$"
			r := q
			px = r
		}()
	}()
}

func foo130() {
	for {
		var i int // ERROR "moved to heap: i$"
		func() {  // ERROR "func literal does not escape$"
			px = &i
		}()
	}
}

func foo131() {
	var i int // ERROR "moved to heap: i$"
	func() {  // ERROR "func literal does not escape$"
		px = &i
	}()
}

func foo132() {
	var i int   // ERROR "moved to heap: i$"
	go func() { // ERROR "func literal escapes to heap$"
		px = &i
	}()
}

func foo133() {
	var i int      // ERROR "moved to heap: i$"
	defer func() { // ERROR "func literal does not escape$"
		px = &i
	}()
}

func foo134() {
	var i int
	p := &i
	func() { // ERROR "func literal does not escape$"
		q := p
		func() { // ERROR "func literal does not escape$"
			r := q
			_ = r
		}()
	}()
}

func foo135() {
	var i int // ERROR "moved to heap: i$"
	p := &i
	go func() { // ERROR "func literal escapes to heap$"
		q := p
		func() { // ERROR "func literal does not escape$"
			r := q
			_ = r
		}()
	}()
}

func foo136() {
	var i int // ERROR "moved to heap: i$"
	p := &i
	go func() { // ERROR "func literal escapes to heap$"
		q := p
		func() { // ERROR "func literal does not escape$"
			r := q
			px = r
		}()
	}()
}

func foo137() {
	var i int // ERROR "moved to heap: i$"
	p := &i
	func() { // ERROR "func literal does not escape$"
		q := p
		go func() { // ERROR "func literal escapes to heap$"
			r := q
			_ = r
		}()
	}()
}

func foo138() *byte {
	type T struct {
		x [1]byte
	}
	t := new(T) // ERROR "new\(T\) escapes to heap$"
	return &t.x[0]
}

func foo139() *byte {
	type T struct {
		x struct {
			y byte
		}
	}
	t := new(T) // ERROR "new\(T\) escapes to heap$"
	return &t.x.y
}

// issue 4751
func foo140() interface{} {
	type T struct {
		X string
	}
	type U struct {
		X string
		T *T
	}
	t := &T{} // ERROR "&T{} escapes to heap$"
	return U{ // ERROR "U{...} escapes to heap$"
		X: t.X,
		T: t,
	}
}

//go:noescape

func F1([]byte)

func F2([]byte)

//go:noescape

func F3(x []byte) // ERROR "x does not escape$"

func F4(x []byte) // ERROR "leaking param: x$"

func G() {
	var buf1 [10]byte
	F1(buf1[:])

	var buf2 [10]byte // ERROR "moved to heap: buf2$"
	F2(buf2[:])

	var buf3 [10]byte
	F3(buf3[:])

	var buf4 [10]byte // ERROR "moved to heap: buf4$"
	F4(buf4[:])
}

type Tm struct {
	x int
}

func (t *Tm) M() { // ERROR "t does not escape$"
}

func foo141() {
	var f func()

	t := new(Tm) // ERROR "new\(Tm\) does not escape$"
	f = t.M      // ERROR "t.M does not escape$"
	_ = f
}

var gf func()

func foo142() {
	t := new(Tm) // ERROR "new\(Tm\) escapes to heap$"
	gf = t.M     // ERROR "t.M escapes to heap$"
}

// issue 3888.
func foo143() {
	for i := 0; i < 1000; i++ {
		func() { // ERROR "func literal does not escape$"
			for i := 0; i < 1; i++ {
				var t Tm
				t.M()
			}
		}()
	}
}

// issue 5773
// Check that annotations take effect regardless of whether they
// are before or after the use in the source code.

//go:noescape

func foo144a(*int)

func foo144() {
	var x int
	foo144a(&x)
	var y int
	foo144b(&y)
}

//go:noescape

func foo144b(*int)

// issue 7313: for loop init should not be treated as "in loop"

type List struct {
	Next *List
}

func foo145(l List) { // ERROR "l does not escape$"
	var p *List
	for p = &l; p.Next != nil; p = p.Next {
	}
}

func foo146(l List) { // ERROR "l does not escape$"
	var p *List
	p = &l
	for ; p.Next != nil; p = p.Next {
	}
}

func foo147(l List) { // ERROR "l does not escape$"
	var p *List
	p = &l
	for p.Next != nil {
		p = p.Next
	}
}

func foo148(l List) { // ERROR "l does not escape$"
	for p := &l; p.Next != nil; p = p.Next {
	}
}

// related: address of variable should have depth of variable, not of loop

func foo149(l List) { // ERROR "l does not escape$"
	var p *List
	for {
		for p = &l; p.Next != nil; p = p.Next {
		}
	}
}

// issue 7934: missed ... if element type had no pointers

var save150 []byte

func foo150(x ...byte) { // ERROR "leaking param: x$"
	save150 = x
}

func bar150() {
	foo150(1, 2, 3) // ERROR "... argument escapes to heap$"
}

// issue 7931: bad handling of slice of array

var save151 *int

func foo151(x *int) { // ERROR "leaking param: x$"
	save151 = x
}

func bar151() {
	var a [64]int // ERROR "moved to heap: a$"
	a[4] = 101
	foo151(&(&a)[4:8][0])
}

func bar151b() {
	var a [10]int // ERROR "moved to heap: a$"
	b := a[:]
	foo151(&b[4:8][0])
}

func bar151c() {
	var a [64]int // ERROR "moved to heap: a$"
	a[4] = 101
	foo151(&(&a)[4:8:8][0])
}

func bar151d() {
	var a [10]int // ERROR "moved to heap: a$"
	b := a[:]
	foo151(&b[4:8:8][0])
}

// issue 8120

type U struct {
	s *string
}

func (u *U) String() *string { // ERROR "leaking param: u to result ~r0 level=1$"
	return u.s
}

type V struct {
	s *string
}

func NewV(u U) *V { // ERROR "leaking param: u$"
	return &V{u.String()} // ERROR "&V{...} escapes to heap$"
}

func foo152() {
	a := "a" // ERROR "moved to heap: a$"
	u := U{&a}
	v := NewV(u)
	println(v)
}

// issue 8176 - &x in type switch body not marked as escaping

func foo153(v interface{}) *int { // ERROR "v does not escape"
	switch x := v.(type) {
	case int: // ERROR "moved to heap: x$"
		return &x
	}
	panic(0) // ERROR "0 escapes to heap"
}

// issue 8185 - &result escaping into result

func f() (x int, y *int) { // ERROR "moved to heap: x$"
	y = &x
	return
}

func g() (x interface{}) { // ERROR "moved to heap: x$"
	x = &x
	return
}

var sink interface{}

type Lit struct {
	p *int
}

func ptrlitNoescape() {
	// Both literal and element do not escape.
	i := 0
	x := &Lit{&i} // ERROR "&Lit{...} does not escape$"
	_ = x
}

func ptrlitNoEscape2() {
	// Literal does not escape, but element does.
	i := 0        // ERROR "moved to heap: i$"
	x := &Lit{&i} // ERROR "&Lit{...} does not escape$"
	sink = *x
}

func ptrlitEscape() {
	// Both literal and element escape.
	i := 0        // ERROR "moved to heap: i$"
	x := &Lit{&i} // ERROR "&Lit{...} escapes to heap$"
	sink = x
}

// self-assignments

type Buffer struct {
	arr    [64]byte
	arrPtr *[64]byte
	buf1   []byte
	buf2   []byte
	str1   string
	str2   string
}

func (b *Buffer) foo() { // ERROR "b does not escape$"
	b.buf1 = b.buf1[1:2]   // ERROR "\(\*Buffer\).foo ignoring self-assignment in b.buf1 = b.buf1\[1:2\]$"
	b.buf1 = b.buf1[1:2:3] // ERROR "\(\*Buffer\).foo ignoring self-assignment in b.buf1 = b.buf1\[1:2:3\]$"
	b.buf1 = b.buf2[1:2]   // ERROR "\(\*Buffer\).foo ignoring self-assignment in b.buf1 = b.buf2\[1:2\]$"
	b.buf1 = b.buf2[1:2:3] // ERROR "\(\*Buffer\).foo ignoring self-assignment in b.buf1 = b.buf2\[1:2:3\]$"
}

func (b *Buffer) bar() { // ERROR "leaking param: b$"
	b.buf1 = b.arr[1:2]
}

func (b *Buffer) arrayPtr() { // ERROR "b does not escape"
	b.buf1 = b.arrPtr[1:2]   // ERROR "\(\*Buffer\).arrayPtr ignoring self-assignment in b.buf1 = b.arrPtr\[1:2\]$"
	b.buf1 = b.arrPtr[1:2:3] // ERROR "\(\*Buffer\).arrayPtr ignoring self-assignment in b.buf1 = b.arrPtr\[1:2:3\]$"
}

func (b *Buffer) baz() { // ERROR "b does not escape$"
	b.str1 = b.str1[1:2] // ERROR "\(\*Buffer\).baz ignoring self-assignment in b.str1 = b.str1\[1:2\]$"
	b.str1 = b.str2[1:2] // ERROR "\(\*Buffer\).baz ignoring self-assignment in b.str1 = b.str2\[1:2\]$"
}

func (b *Buffer) bat() { // ERROR "leaking param content: b$"
	o := new(Buffer) // ERROR "new\(Buffer\) escapes to heap$"
	o.buf1 = b.buf1[1:2]
	sink = o
}

func quux(sp *string, bp *[]byte) { // ERROR "bp does not escape$" "sp does not escape$"
	*sp = (*sp)[1:2] // ERROR "quux ignoring self-assignment in \*sp = \(\*sp\)\[1:2\]$"
	*bp = (*bp)[1:2] // ERROR "quux ignoring self-assignment in \*bp = \(\*bp\)\[1:2\]$"
}

type StructWithString struct {
	p *int
	s string
}

// This is escape analysis false negative.
// We assign the pointer to x.p but leak x.s. Escape analysis coarsens flows
// to just x, and thus &i looks escaping.
func fieldFlowTracking() {
	var x StructWithString
	i := 0 // ERROR "moved to heap: i$"
	x.p = &i
	sink = x.s // ERROR "x.s escapes to heap$"
}

// String operations.

func slicebytetostring0() {
	b := make([]byte, 20) // ERROR "make\(\[\]byte, 20\) does not escape$"
	s := string(b)        // ERROR "string\(b\) does not escape$"
	_ = s
}

func slicebytetostring1() {
	b := make([]byte, 20) // ERROR "make\(\[\]byte, 20\) does not escape$"
	s := string(b)        // ERROR "string\(b\) does not escape$"
	s1 := s[0:1]
	_ = s1
}

func slicebytetostring2() {
	b := make([]byte, 20) // ERROR "make\(\[\]byte, 20\) does not escape$"
	s := string(b)        // ERROR "string\(b\) escapes to heap$"
	s1 := s[0:1]          // ERROR "moved to heap: s1$"
	sink = &s1
}

func slicebytetostring3() {
	b := make([]byte, 20) // ERROR "make\(\[\]byte, 20\) does not escape$"
	s := string(b)        // ERROR "string\(b\) escapes to heap$"
	s1 := s[0:1]
	sink = s1 // ERROR "s1 escapes to heap$"
}

func addstr0() {
	s0 := "a"
	s1 := "b"
	s := s0 + s1 // ERROR "s0 \+ s1 does not escape$"
	_ = s
}

func addstr1() {
	s0 := "a"
	s1 := "b"
	s := "c"
	s += s0 + s1 // ERROR "s0 \+ s1 does not escape$"
	_ = s
}

func addstr2() {
	b := make([]byte, 20) // ERROR "make\(\[\]byte, 20\) does not escape$"
	s0 := "a"
	s := string(b) + s0 // ERROR "string\(b\) \+ s0 does not escape$" "string\(b\) does not escape$"
	_ = s
}

func addstr3() {
	s0 := "a"
	s1 := "b"
	s := s0 + s1 // ERROR "s0 \+ s1 escapes to heap$"
	s2 := s[0:1]
	sink = s2 // ERROR "s2 escapes to heap$"
}

func intstring0() bool {
	// string does not escape
	x := '0'
	s := string(x) // ERROR "string\(x\) does not escape$"
	return s == "0"
}

func intstring1() string {
	// string does not escape, but the buffer does
	x := '0'
	s := string(x) // ERROR "string\(x\) escapes to heap$"
	return s
}

func intstring2() {
	// string escapes to heap
	x := '0'
	s := string(x) // ERROR "moved to heap: s$" "string\(x\) escapes to heap$"
	sink = &s
}

func stringtoslicebyte0() {
	s := "foo"
	x := []byte(s) // ERROR "\(\[\]byte\)\(s\) does not escape$" "zero-copy string->\[\]byte conversion"
	_ = x
}

func stringtoslicebyte1() []byte {
	s := "foo"
	return []byte(s) // ERROR "\(\[\]byte\)\(s\) escapes to heap$"
}

func stringtoslicebyte2() {
	s := "foo"
	sink = []byte(s) // ERROR "\(\[\]byte\)\(s\) escapes to heap$"
}

func stringtoslicerune0() {
	s := "foo"
	x := []rune(s) // ERROR "\(\[\]rune\)\(s\) does not escape$"
	_ = x
}

func stringtoslicerune1() []rune {
	s := "foo"
	return []rune(s) // ERROR "\(\[\]rune\)\(s\) escapes to heap$"
}

func stringtoslicerune2() {
	s := "foo"
	sink = []rune(s) // ERROR "\(\[\]rune\)\(s\) escapes to heap$"
}

func slicerunetostring0() {
	r := []rune{1, 2, 3} // ERROR "\[\]rune{...} does not escape$"
	s := string(r)       // ERROR "string\(r\) does not escape$"
	_ = s
}

func slicerunetostring1() string {
	r := []rune{1, 2, 3} // ERROR "\[\]rune{...} does not escape$"
	return string(r)     // ERROR "string\(r\) escapes to heap$"
}

func slicerunetostring2() {
	r := []rune{1, 2, 3} // ERROR "\[\]rune{...} does not escape$"
	sink = string(r)     // ERROR "string\(r\) escapes to heap$"
}

func makemap0() {
	m := make(map[int]int) // ERROR "make\(map\[int\]int\) does not escape$"
	m[0] = 0
	m[1]++
	delete(m, 1)
	sink = m[0] // ERROR "m\[0\] escapes to heap$"
}

func makemap1() map[int]int {
	return make(map[int]int) // ERROR "make\(map\[int\]int\) escapes to heap$"
}

func makemap2() {
	m := make(map[int]int) // ERROR "make\(map\[int\]int\) escapes to heap$"
	sink = m
}

func nonescapingEface(m map[interface{}]bool) bool { // ERROR "m does not escape$"
	return m["foo"] // ERROR ".foo. does not escape$"
}

func nonescapingIface(m map[M]bool) bool { // ERROR "m does not escape$"
	return m[MV(0)] // ERROR "MV\(0\) does not escape$"
}

func issue10353() {
	x := new(int) // ERROR "new\(int\) escapes to heap$"
	issue10353a(x)()
}

func issue10353a(x *int) func() { // ERROR "leaking param: x$"
	return func() { // ERROR "func literal escapes to heap$"
		println(*x)
	}
}

func issue10353b() {
	var f func()
	for {
		x := new(int) // ERROR "new\(int\) escapes to heap$"
		f = func() {  // ERROR "func literal escapes to heap$"
			println(*x)
		}
	}
	_ = f
}

func issue11387(x int) func() int {
	f := func() int { return x }    // ERROR "func literal escapes to heap"
	slice1 := []func() int{f}       // ERROR "\[\].* does not escape"
	slice2 := make([]func() int, 1) // ERROR "make\(.*\) does not escape"
	copy(slice2, slice1)
	return slice2[0]
}

func issue12397(x, y int) { // ERROR "moved to heap: y$"
	// x does not escape below, because all relevant code is dead.
	if false {
		gxx = &x
	} else {
		gxx = &y
	}

	if true {
		gxx = &y
	} else {
		gxx = &x
	}
}

"""



```