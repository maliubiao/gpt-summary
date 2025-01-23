Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code looking for familiar Go keywords and structures. Things that jump out are:

* `package types2_test`: This immediately tells me it's a test file for the `types2` package. The `_test` suffix is a strong indicator.
* `import`:  I see imports like `cmd/compile/internal/syntax`, `fmt`, `testing`, and the local package `cmd/compile/internal/types2` (aliased as `.`). This suggests the code is testing interactions with the Go compiler's type checking mechanisms.
* `var builtinCalls`: A slice of structs. This is a common pattern for test cases, suggesting this code tests various built-in functions.
* Struct fields `name`, `src`, `sig`: These strongly hint at a test structure where `name` is the built-in function's name, `src` is a source code snippet using it, and `sig` is the expected signature.
* `func TestBuiltinSignatures(t *testing.T)`:  This is a standard Go testing function.
* `DefPredeclaredTestFuncs()`: A function call within the test. This might be setting up some necessary environment for the tests.
* `mustTypecheck(src, nil, &Info{...})`:  This function name is very suggestive. It likely type-checks the given source code. The `Info` struct probably collects information about the type checking process.
* `Universe`, `Unsafe`: These look like references to the global scope and the `unsafe` package, respectively, which are important for built-in functions.

**2. Deciphering the `builtinCalls` Structure:**

The `builtinCalls` slice is the core of the test data. Each entry represents a test case for a specific built-in function. I'd examine a few entries in detail:

* `{"append", `var s []int; _ = append(s)`, `func([]int, ...int) []int`}`: This tests the `append` built-in with an integer slice. The `sig` string clearly describes the expected function signature.
* `{"cap", `var s [10]int; _ = cap(s)`, `invalid type`}`:  This one is interesting. "invalid type" suggests a test case where the built-in shouldn't work as a regular function call (likely because `cap` on an array literal is a compile-time constant).
* `{"len", `_ = len("foo")`, `invalid type`}`: Similar to `cap`, indicating compile-time evaluation.
* `{"make", `_ = make([]int, 10)`, `func([]int, int) []int`}`: Tests the `make` built-in for slices.
* `{"unsafe.Add", ...}`:  Confirms testing of built-ins within the `unsafe` package.

From this analysis, I can confidently conclude that `builtinCalls` holds test cases for checking the signatures of Go's built-in functions under various usage scenarios.

**3. Understanding the `TestBuiltinSignatures` Function:**

This function iterates through `builtinCalls`. The key part is the `testBuiltinSignature` call within the loop. The purpose is clearly to verify if the actual signature obtained from type-checking the `src` code matches the expected `sig`.

**4. Analyzing `testBuiltinSignature`:**

* It constructs a complete Go program `src` around the test snippet `src0`. The added parts (package, import, a dummy function) are necessary for the type checker to work correctly. The `unsafe` import and dummy type parameter are interesting details, possibly related to how type parameters are handled internally.
* `mustTypecheck`: This is the crucial function. It performs the type checking. The `Info` struct captures the results, specifically `Uses` (which tracks which identifier refers to which object) and `Types` (which maps expressions to their types).
* Finding the function call: The code iterates through the `types` map to find the `syntax.CallExpr`. This isolates the built-in function call being tested.
* Checking the type:  It retrieves the type of the function call from the `types` map and compares its string representation with the expected `want` signature.
* Verifying the built-in:  It then checks if the called function is indeed the expected built-in function by examining the `Uses` map. It handles cases where the built-in is called directly or through parentheses or the `unsafe` package.

**5. Inferring the Go Feature:**

Based on the code, the main Go feature being tested is the **correct typing and signature resolution of built-in functions**. The `types2` package is part of the Go compiler's type checker, and this test ensures that the type checker correctly identifies the signatures of built-in functions like `append`, `len`, `make`, `unsafe.Add`, etc., under different usage contexts.

**6. Crafting Examples and Identifying Potential Issues:**

Now I can create Go code examples to illustrate the functionality and potential pitfalls:

* **Example for `append`:** Demonstrates how `append` works with different slice types and variadic arguments.
* **Example for `len` and `cap`:**  Highlights the difference in behavior between arrays and slices and how `len` and `cap` apply.
* **Example for `make`:** Shows how `make` is used for creating slices, maps, and channels.
* **Example for `unsafe.Add`:**  Illustrates the usage of `unsafe.Add` and the need for caution.
* **Common Mistake (for `len` and `cap` on arrays):**  Emphasizes that `len` and `cap` on arrays are compile-time constants, not function calls in the same way as with slices. This directly relates to the "invalid type" entries in `builtinCalls`.

**7. CommandLine Arguments and Assumptions:**

Since the code is a test file, it doesn't directly process command-line arguments. However, the testing framework (`go test`) uses command-line flags. I'd explain that `go test` is used to run these tests.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the syntax tree manipulation (`syntax` package). However, realizing the core purpose is *type checking* led me to focus more on the `types2` package and the `TypeAndValue` information.
*  Seeing the "invalid type" signatures in `builtinCalls` was a key moment. It shifted my understanding from just checking function signatures to also understanding when these built-ins are treated as compile-time operations.
*  I double-checked the purpose of `DefPredeclaredTestFuncs()`. While the exact implementation isn't shown, the name suggests it sets up the standard built-in functions for the test environment.

By following this structured analysis, combining keyword spotting, understanding data structures, and inferring the overall purpose, I can arrive at a comprehensive explanation of the provided Go code.
这段代码是 Go 语言编译器内部 `types2` 包的测试文件 `builtins_test.go` 的一部分。它的主要功能是**测试 Go 语言内置函数（built-in functions）的签名（signature）是否符合预期**。

更具体地说，它通过构造包含对内置函数调用的 Go 源代码片段，然后使用 `types2` 包的类型检查功能来获取这些调用的类型信息，并将其与预期的签名进行比较。

**功能分解：**

1. **定义测试用例：** `builtinCalls` 变量是一个结构体切片，每个结构体定义了一个针对特定内置函数的测试用例。每个用例包含：
   - `name`: 内置函数的名称 (字符串)。
   - `src`: 一个 Go 语言源代码片段 (字符串)，其中调用了该内置函数。为了能被类型检查，通常会将其放在一个虚构的函数体内部。
   - `sig`: 期望的内置函数签名 (字符串)。如果期望类型检查失败或得到一个非函数类型（例如，对于在编译时求值的 `len` 和 `cap`），则会使用 `"invalid type"`。

2. **测试主函数：** `TestBuiltinSignatures` 函数是 Go 的标准测试函数。它负责执行所有的测试用例。
   - `DefPredeclaredTestFuncs()`: 这个函数（在代码中未显示具体实现，但根据命名推测）很可能是在 `types2` 包的测试环境中定义一些预声明的函数或类型，以便测试可以正常运行。
   - `seen` map:  用于记录已经测试过的内置函数，以确保所有预定义的内置函数都被覆盖到测试。
   - 遍历 `builtinCalls`: 循环遍历每个测试用例。
   - `testBuiltinSignature`:  调用该函数来执行单个内置函数的签名测试。
   - 检查遗漏的测试: 最后，它检查 `Universe` 和 `Unsafe` 作用域中的所有内置函数，确保 `builtinCalls` 中包含了对它们的测试。

3. **单个签名测试函数：** `testBuiltinSignature` 函数负责执行单个内置函数的签名测试。
   - 构建完整的源代码：它将测试用例中的 `src0` 嵌入到一个完整的 Go 源代码文件中，包括 `package p` 声明、 `import "unsafe"` 和一个包含该调用的虚构函数 `func _[P ~[]byte]() { ... }`。 使用泛型类型参数 `P ~[]byte` 的目的可能是为了在某些测试用例中引入类型参数相关的上下文，尽管在这个特定的测试场景中可能不是核心。
   - 类型检查：调用 `mustTypecheck` 函数（在代码中未显示具体实现，但很可能是 `types2` 包提供的类型检查函数）对构建的源代码进行类型检查。它传递一个 `Info` 结构体，用于接收类型检查的结果，包括 `Uses` (标识符的使用情况) 和 `Types` (表达式的类型信息)。
   - 查找函数调用表达式：它遍历 `types` map，查找源代码中的函数调用表达式 (`syntax.CallExpr`)。
   - 检查类型：获取函数调用表达式的类型 (`types[fun].Type`)，并将其字符串表示与期望的签名 `want` 进行比较。
   - 验证内置函数：它检查被调用的函数是否是预期的内置函数。这包括检查标识符是否解析为 `Builtin` 类型，以及内置函数的名称是否匹配。它还处理了通过括号或 `unsafe` 包调用的内置函数。

**它是什么 Go 语言功能的实现：**

这段代码主要测试的是 **Go 语言内置函数的类型系统和类型推断**。它确保编译器能够正确地识别内置函数的参数类型、返回值类型以及在不同上下文中的正确签名。

**Go 代码举例说明：**

假设我们要测试 `append` 内置函数。

```go
package main

func main() {
	var s []int
	s = append(s, 1, 2, 3) // 调用 append
	println(s)
}
```

这段代码中 `append(s, 1, 2, 3)` 会将元素 1, 2, 3 追加到切片 `s` 中。`types2` 包的测试会验证 `append` 在这种情况下的类型签名是 `func([]int, ...int) []int`。

**涉及代码推理，带上假设的输入与输出：**

考虑 `builtinCalls` 中的一个条目：

```go
{"len", `var s string; _ = len(s)`, `func(string) int`},
```

**假设输入 (源代码 `src`)：**

```go
package p; import "unsafe"; type _ unsafe.Pointer /* use unsafe */; func _[P ~[]byte]() { var s string; _ = len(s) }
```

**类型检查过程：**

1. `types2` 包的类型检查器会解析这段代码。
2. 它会识别 `len(s)` 是一个函数调用，并且 `len` 是一个内置函数。
3. 它会查找 `len` 内置函数在 `string` 类型上的签名。
4. 它会推断出 `len(s)` 的返回类型是 `int`。

**预期输出 (`sig`)：**

```
func(string) int
```

**涉及命令行参数的具体处理：**

这段代码本身是一个测试文件，不直接处理命令行参数。但是，要运行这些测试，你需要使用 Go 的测试工具 `go test`。

例如，在包含 `builtins_test.go` 文件的目录下运行：

```bash
go test -run TestBuiltinSignatures
```

- `go test`:  Go 语言的测试命令。
- `-run TestBuiltinSignatures`:  指定要运行的测试函数名（可以使用正则表达式匹配多个测试）。

Go 的测试框架会加载包含测试的包，执行指定的测试函数，并报告测试结果。

**使用者易犯错的点：**

对于使用内置函数的开发者来说，一些易犯错的点可能与内置函数的特殊行为有关：

1. **`len` 和 `cap` 用于数组和切片：**  新手可能会混淆 `len` 和 `cap` 在数组和切片上的行为。对于数组，`len` 和 `cap` 返回的是数组的固定大小，是编译时常量。对于切片，`len` 返回当前元素个数，`cap` 返回底层数组的容量，是运行时值。测试用例中 `{"len", \`_ = len("foo")\`, \`invalid type\`}` 和 `{"len", \`var s [10]int; _ = len(s)\`, \`invalid type\`}` 就体现了这一点，说明在这些上下文中 `len` 不会被视为一个普通的函数调用。

   **例子：**

   ```go
   package main

   func main() {
       arr := [5]int{1, 2, 3, 4, 5}
       sl := []int{1, 2, 3}

       println(len(arr)) // 输出 5 (编译时常量)
       println(cap(arr)) // 输出 5 (编译时常量)

       println(len(sl)) // 输出 3 (运行时值)
       println(cap(sl)) // 输出切片的容量 (运行时值)
   }
   ```

2. **`append` 的返回值：** `append` 函数可能会重新分配底层数组，因此必须使用其返回值来更新切片变量。

   **例子：**

   ```go
   package main

   func main() {
       sl := []int{1, 2, 3}
       newSl := append(sl, 4) // 必须将返回值赋给变量
       println(newSl)       // 输出 [1 2 3 4]
       println(sl)          // 输出 [1 2 3] (如果底层数组没有重新分配，可能会变，但最佳实践是使用返回值)
   }
   ```

3. **`make` 的参数：** `make` 函数用于创建切片、map 和 channel，参数的含义和数量因类型而异。例如，创建切片时可以指定长度和容量，但创建 map 或 channel 时只能指定可选的初始容量。

   **例子：**

   ```go
   package main

   func main() {
       // 创建长度为 5 的切片
       sl1 := make([]int, 5)
       println(len(sl1), cap(sl1)) // 输出 5 5

       // 创建长度为 5，容量为 10 的切片
       sl2 := make([]int, 5, 10)
       println(len(sl2), cap(sl2)) // 输出 5 10

       // 创建 map
       m := make(map[string]int)

       // 创建 channel
       ch := make(chan int)
       _ = ch
   }
   ```

总而言之，这段测试代码是 Go 编译器内部类型检查机制的重要组成部分，用于确保内置函数的行为符合语言规范，从而保证 Go 程序的正确性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/builtins_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2_test

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"testing"

	. "cmd/compile/internal/types2"
)

var builtinCalls = []struct {
	name, src, sig string
}{
	{"append", `var s []int; _ = append(s)`, `func([]int, ...int) []int`},
	{"append", `var s []int; _ = append(s, 0)`, `func([]int, ...int) []int`},
	{"append", `var s []int; _ = (append)(s, 0)`, `func([]int, ...int) []int`},
	{"append", `var s []byte; _ = ((append))(s, 0)`, `func([]byte, ...byte) []byte`},
	{"append", `var s []byte; _ = append(s, "foo"...)`, `func([]byte, string...) []byte`},
	{"append", `type T []byte; var s T; var str string; _ = append(s, str...)`, `func(p.T, string...) p.T`},
	{"append", `type T []byte; type U string; var s T; var str U; _ = append(s, str...)`, `func(p.T, p.U...) p.T`},

	{"cap", `var s [10]int; _ = cap(s)`, `invalid type`},  // constant
	{"cap", `var s [10]int; _ = cap(&s)`, `invalid type`}, // constant
	{"cap", `var s []int64; _ = cap(s)`, `func([]int64) int`},
	{"cap", `var c chan<-bool; _ = cap(c)`, `func(chan<- bool) int`},
	{"cap", `type S []byte; var s S; _ = cap(s)`, `func(p.S) int`},
	{"cap", `var s P; _ = cap(s)`, `func(P) int`},

	{"len", `_ = len("foo")`, `invalid type`}, // constant
	{"len", `var s string; _ = len(s)`, `func(string) int`},
	{"len", `var s [10]int; _ = len(s)`, `invalid type`},  // constant
	{"len", `var s [10]int; _ = len(&s)`, `invalid type`}, // constant
	{"len", `var s []int64; _ = len(s)`, `func([]int64) int`},
	{"len", `var c chan<-bool; _ = len(c)`, `func(chan<- bool) int`},
	{"len", `var m map[string]float32; _ = len(m)`, `func(map[string]float32) int`},
	{"len", `type S []byte; var s S; _ = len(s)`, `func(p.S) int`},
	{"len", `var s P; _ = len(s)`, `func(P) int`},

	{"clear", `var m map[float64]int; clear(m)`, `func(map[float64]int)`},
	{"clear", `var s []byte; clear(s)`, `func([]byte)`},

	{"close", `var c chan int; close(c)`, `func(chan int)`},
	{"close", `var c chan<- chan string; close(c)`, `func(chan<- chan string)`},

	{"complex", `_ = complex(1, 0)`, `invalid type`}, // constant
	{"complex", `var re float32; _ = complex(re, 1.0)`, `func(float32, float32) complex64`},
	{"complex", `var im float64; _ = complex(1, im)`, `func(float64, float64) complex128`},
	{"complex", `type F32 float32; var re, im F32; _ = complex(re, im)`, `func(p.F32, p.F32) complex64`},
	{"complex", `type F64 float64; var re, im F64; _ = complex(re, im)`, `func(p.F64, p.F64) complex128`},

	{"copy", `var src, dst []byte; copy(dst, src)`, `func([]byte, []byte) int`},
	{"copy", `type T [][]int; var src, dst T; _ = copy(dst, src)`, `func(p.T, p.T) int`},
	{"copy", `var src string; var dst []byte; copy(dst, src)`, `func([]byte, string) int`},
	{"copy", `type T string; type U []byte; var src T; var dst U; copy(dst, src)`, `func(p.U, p.T) int`},
	{"copy", `var dst []byte; copy(dst, "hello")`, `func([]byte, string) int`},

	{"delete", `var m map[string]bool; delete(m, "foo")`, `func(map[string]bool, string)`},
	{"delete", `type (K string; V int); var m map[K]V; delete(m, "foo")`, `func(map[p.K]p.V, p.K)`},

	{"imag", `_ = imag(1i)`, `invalid type`}, // constant
	{"imag", `var c complex64; _ = imag(c)`, `func(complex64) float32`},
	{"imag", `var c complex128; _ = imag(c)`, `func(complex128) float64`},
	{"imag", `type C64 complex64; var c C64; _ = imag(c)`, `func(p.C64) float32`},
	{"imag", `type C128 complex128; var c C128; _ = imag(c)`, `func(p.C128) float64`},

	{"real", `_ = real(1i)`, `invalid type`}, // constant
	{"real", `var c complex64; _ = real(c)`, `func(complex64) float32`},
	{"real", `var c complex128; _ = real(c)`, `func(complex128) float64`},
	{"real", `type C64 complex64; var c C64; _ = real(c)`, `func(p.C64) float32`},
	{"real", `type C128 complex128; var c C128; _ = real(c)`, `func(p.C128) float64`},

	{"make", `_ = make([]int, 10)`, `func([]int, int) []int`},
	{"make", `type T []byte; _ = make(T, 10, 20)`, `func(p.T, int, int) p.T`},

	// go.dev/issue/37349
	{"make", `              _ = make([]int, 0   )`, `func([]int, int) []int`},
	{"make", `var l    int; _ = make([]int, l   )`, `func([]int, int) []int`},
	{"make", `              _ = make([]int, 0, 0)`, `func([]int, int, int) []int`},
	{"make", `var l    int; _ = make([]int, l, 0)`, `func([]int, int, int) []int`},
	{"make", `var    c int; _ = make([]int, 0, c)`, `func([]int, int, int) []int`},
	{"make", `var l, c int; _ = make([]int, l, c)`, `func([]int, int, int) []int`},

	// go.dev/issue/37393
	{"make", `                _ = make([]int       , 0   )`, `func([]int, int) []int`},
	{"make", `var l    byte ; _ = make([]int8      , l   )`, `func([]int8, byte) []int8`},
	{"make", `                _ = make([]int16     , 0, 0)`, `func([]int16, int, int) []int16`},
	{"make", `var l    int16; _ = make([]string    , l, 0)`, `func([]string, int16, int) []string`},
	{"make", `var    c int32; _ = make([]float64   , 0, c)`, `func([]float64, int, int32) []float64`},
	{"make", `var l, c uint ; _ = make([]complex128, l, c)`, `func([]complex128, uint, uint) []complex128`},

	// go.dev/issue/45667
	{"make", `const l uint = 1; _ = make([]int, l)`, `func([]int, uint) []int`},

	{"max", `               _ = max(0        )`, `invalid type`}, // constant
	{"max", `var x int    ; _ = max(x        )`, `func(int) int`},
	{"max", `var x int    ; _ = max(0, x     )`, `func(int, int) int`},
	{"max", `var x string ; _ = max("a", x   )`, `func(string, string) string`},
	{"max", `var x float32; _ = max(0, 1.0, x)`, `func(float32, float32, float32) float32`},

	{"min", `               _ = min(0        )`, `invalid type`}, // constant
	{"min", `var x int    ; _ = min(x        )`, `func(int) int`},
	{"min", `var x int    ; _ = min(0, x     )`, `func(int, int) int`},
	{"min", `var x string ; _ = min("a", x   )`, `func(string, string) string`},
	{"min", `var x float32; _ = min(0, 1.0, x)`, `func(float32, float32, float32) float32`},

	{"new", `_ = new(int)`, `func(int) *int`},
	{"new", `type T struct{}; _ = new(T)`, `func(p.T) *p.T`},

	{"panic", `panic(0)`, `func(interface{})`},
	{"panic", `panic("foo")`, `func(interface{})`},

	{"print", `print()`, `func()`},
	{"print", `print(0)`, `func(int)`},
	{"print", `print(1, 2.0, "foo", true)`, `func(int, float64, string, bool)`},

	{"println", `println()`, `func()`},
	{"println", `println(0)`, `func(int)`},
	{"println", `println(1, 2.0, "foo", true)`, `func(int, float64, string, bool)`},

	{"recover", `recover()`, `func() interface{}`},
	{"recover", `_ = recover()`, `func() interface{}`},

	{"Add", `var p unsafe.Pointer; _ = unsafe.Add(p, -1.0)`, `func(unsafe.Pointer, int) unsafe.Pointer`},
	{"Add", `var p unsafe.Pointer; var n uintptr; _ = unsafe.Add(p, n)`, `func(unsafe.Pointer, uintptr) unsafe.Pointer`},
	{"Add", `_ = unsafe.Add(nil, 0)`, `func(unsafe.Pointer, int) unsafe.Pointer`},

	{"Alignof", `_ = unsafe.Alignof(0)`, `invalid type`},                 // constant
	{"Alignof", `var x struct{}; _ = unsafe.Alignof(x)`, `invalid type`}, // constant
	{"Alignof", `var x P; _ = unsafe.Alignof(x)`, `func(P) uintptr`},

	{"Offsetof", `var x struct{f bool}; _ = unsafe.Offsetof(x.f)`, `invalid type`},           // constant
	{"Offsetof", `var x struct{_ int; f bool}; _ = unsafe.Offsetof((&x).f)`, `invalid type`}, // constant
	{"Offsetof", `var x struct{_ int; f P}; _ = unsafe.Offsetof((&x).f)`, `func(P) uintptr`},

	{"Sizeof", `_ = unsafe.Sizeof(0)`, `invalid type`},                 // constant
	{"Sizeof", `var x struct{}; _ = unsafe.Sizeof(x)`, `invalid type`}, // constant
	{"Sizeof", `var x P; _ = unsafe.Sizeof(x)`, `func(P) uintptr`},

	{"Slice", `var p *int; _ = unsafe.Slice(p, 1)`, `func(*int, int) []int`},
	{"Slice", `var p *byte; var n uintptr; _ = unsafe.Slice(p, n)`, `func(*byte, uintptr) []byte`},
	{"Slice", `type B *byte; var b B; _ = unsafe.Slice(b, 0)`, `func(*byte, int) []byte`},

	{"SliceData", "var s []int; _ = unsafe.SliceData(s)", `func([]int) *int`},
	{"SliceData", "type S []int; var s S; _ = unsafe.SliceData(s)", `func([]int) *int`},

	{"String", `var p *byte; _ = unsafe.String(p, 1)`, `func(*byte, int) string`},
	{"String", `type B *byte; var b B; _ = unsafe.String(b, 0)`, `func(*byte, int) string`},

	{"StringData", `var s string; _ = unsafe.StringData(s)`, `func(string) *byte`},
	{"StringData", `_ = unsafe.StringData("foo")`, `func(string) *byte`},

	{"assert", `assert(true)`, `invalid type`},                                    // constant
	{"assert", `type B bool; const pred B = 1 < 2; assert(pred)`, `invalid type`}, // constant

	// no tests for trace since it produces output as a side-effect
}

func TestBuiltinSignatures(t *testing.T) {
	DefPredeclaredTestFuncs()

	seen := map[string]bool{"trace": true} // no test for trace built-in; add it manually
	for _, call := range builtinCalls {
		testBuiltinSignature(t, call.name, call.src, call.sig)
		seen[call.name] = true
	}

	// make sure we didn't miss one
	for _, name := range Universe.Names() {
		if _, ok := Universe.Lookup(name).(*Builtin); ok && !seen[name] {
			t.Errorf("missing test for %s", name)
		}
	}
	for _, name := range Unsafe.Scope().Names() {
		if _, ok := Unsafe.Scope().Lookup(name).(*Builtin); ok && !seen[name] {
			t.Errorf("missing test for unsafe.%s", name)
		}
	}
}

func testBuiltinSignature(t *testing.T, name, src0, want string) {
	src := fmt.Sprintf(`package p; import "unsafe"; type _ unsafe.Pointer /* use unsafe */; func _[P ~[]byte]() { %s }`, src0)

	uses := make(map[*syntax.Name]Object)
	types := make(map[syntax.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Uses: uses, Types: types})

	// find called function
	n := 0
	var fun syntax.Expr
	for x := range types {
		if call, _ := x.(*syntax.CallExpr); call != nil {
			fun = call.Fun
			n++
		}
	}
	if n != 1 {
		t.Errorf("%s: got %d CallExprs; want 1", src0, n)
		return
	}

	// check recorded types for fun and descendents (may be parenthesized)
	for {
		// the recorded type for the built-in must match the wanted signature
		typ := types[fun].Type
		if typ == nil {
			t.Errorf("%s: no type recorded for %s", src0, ExprString(fun))
			return
		}
		if got := typ.String(); got != want {
			t.Errorf("%s: got type %s; want %s", src0, got, want)
			return
		}

		// called function must be a (possibly parenthesized, qualified)
		// identifier denoting the expected built-in
		switch p := fun.(type) {
		case *syntax.Name:
			obj := uses[p]
			if obj == nil {
				t.Errorf("%s: no object found for %s", src0, p.Value)
				return
			}
			bin, _ := obj.(*Builtin)
			if bin == nil {
				t.Errorf("%s: %s does not denote a built-in", src0, p.Value)
				return
			}
			if bin.Name() != name {
				t.Errorf("%s: got built-in %s; want %s", src0, bin.Name(), name)
				return
			}
			return // we're done

		case *syntax.ParenExpr:
			fun = p.X // unpack

		case *syntax.SelectorExpr:
			// built-in from package unsafe - ignore details
			return // we're done

		default:
			t.Errorf("%s: invalid function call", src0)
			return
		}
	}
}
```