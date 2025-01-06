Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The fundamental goal is to analyze a Go source file and understand its purpose, illustrate its functionality, explain its logic, and identify potential pitfalls for users. The filename `slices.go` and the package `codegen` strongly suggest this is related to code generation and testing optimizations related to slices. The `// asmcheck` comment confirms that assembly-level checks are involved.

2. **Initial Scan for Key Areas:** Quickly read through the code, paying attention to:
    * **Comments:**  Comments like `// Issue #...` are crucial for understanding the context and the optimization being targeted. The `// amd64:` and `// ppc64x:` comments indicate platform-specific assembly checks.
    * **Function Names:**  Names like `SliceClear`, `SliceExtensionConst`, `SliceMakeCopyLen`, `SliceNilCheck`, etc., give strong hints about the functionality being tested.
    * **Core Go Features:** Identify the primary Go features being used: slices, `append`, `make`, `copy`, `unsafe.Slice`, and slice literals.

3. **Categorize Function Groups:** Notice the clear sections demarcated by comments like `// ------------------ //`. This structure helps organize the analysis. The categories are:
    * `Clear`:  Clearing slice elements.
    * `Extension`: Appending elements to a slice.
    * `Make+Copy`: Creating new slices and copying data.
    * `Nil check of &s[0]`: Checking for potential nil pointer dereferences.
    * `Init slice literal`:  Initializing slices with literal values.
    * `Test PPC64 SUBFCconst folding rules`:  PPC64-specific optimization.
    * `Code generation for unsafe.Slice`: Using `unsafe.Slice`.

4. **Analyze Each Function/Group Individually:**

    * **`Clear`:**
        * `SliceClear` and `SliceClearPointers`:  The assembly comments indicate a focus on the `memclrNoHeapPointers` and `memclrHasPointers` runtime functions for clearing slices of non-pointers and pointers, respectively.
        * **Example:** Create slices of `int` and `*int` and observe that the functions set the elements to their zero values.

    * **`Extension`:**
        * The focus is on the `append` operation combined with `make`. The assembly comments aim to verify that, in certain cases (especially with constant lengths), the runtime avoids unnecessary `makeslice` calls and potentially `memclr`.
        * **Example:** Show how `append` with `make` increases the slice's length.
        * **Logic/Assumptions:** Explain that the compiler might optimize `append(s, make([]T, N)...)` for constant `N`.

    * **`Make+Copy`:**
        * This section explores various ways to create a new slice and copy data from an existing one using `make` and `copy`. The assembly comments check for the presence or absence of `runtime.makeslicecopy`, `runtime.memmove`, etc., indicating optimization strategies.
        * **Example:** Demonstrate `SliceMakeCopyLen` creating a copy.
        * **Common Mistakes:** The functions with `NoOpt` in their names highlight scenarios where the compiler might *not* perform the `makeslicecopy` optimization. These provide excellent examples of potential user errors or non-optimal code patterns. List these out.

    * **`Nil check of &s[0]`:**
        * `SliceNilCheck`: Checks that the compiler avoids an explicit nil check when accessing the first element of a non-empty slice.
        * **Example:** Show that accessing `&s[0]` on a non-nil, non-empty slice is safe.

    * **`Init slice literal`:**
        * `InitSmallSliceLiteral` and `InitNotSmallSliceLiteral`:  Illustrate how the compiler might handle small vs. large slice literals differently (embedding small literals directly vs. allocating on the heap for larger ones).
        * **Example:** Show the creation of both types of literals.

    * **`Test PPC64 SUBFCconst folding rules`:**
        * `SliceWithConstCompare` and `SliceWithSubtractBound`:  Focus on specific instruction optimizations for the PPC64 architecture. While we can't directly "show" the assembly optimization in a Go example, we can illustrate the slice operations.

    * **`Code generation for unsafe.Slice`:**
        * `Slice1` and `Slice0`: Demonstrate the usage of `unsafe.Slice` and that the compiler might optimize away multiplication by the element size if the size is 0 or 1.
        * **Example:** Show how to create a slice from a pointer and length using `unsafe.Slice`.
        * **Caution:** Emphasize the dangers of `unsafe`.

5. **Synthesize and Organize the Findings:**

    * **Functionality:** Summarize the overall purpose of the code (testing slice optimizations).
    * **Go Language Feature:** Identify the primary feature being explored (slices).
    * **Code Examples:** Provide clear, concise Go code snippets to illustrate each function's behavior.
    * **Logic and Assumptions:** Explain the compiler optimizations being targeted and the assumptions behind them (e.g., constant lengths in `append`).
    * **Command-Line Arguments:** Note that this specific code doesn't directly process command-line arguments. The `// asmcheck` directive is handled by the Go test infrastructure.
    * **Common Mistakes:** Compile the list of potential errors identified in the `Make+Copy` section.

6. **Refine and Review:** Read through the generated analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the examples directly relate to the functions being described. Ensure the language is clear and avoids jargon where possible.

By following these steps, we can systematically analyze the provided Go code and generate a comprehensive and informative summary. The key is to break down the problem into smaller, manageable parts, understand the context provided by the comments and function names, and then synthesize the findings into a coherent explanation.
`go/test/codegen/slices.go` 这个 Go 语言文件是 Go 编译器代码生成测试的一部分，专门用于测试与切片（slices）类型相关的代码生成优化。它通过编写不同的操作切片的 Go 函数，并使用 `// asmcheck` 注释来断言生成的汇编代码是否符合预期，从而验证编译器的优化效果。

**功能归纳:**

该文件的主要功能是：

1. **测试切片的清空操作:**  验证编译器是否能将循环赋值零值或 `nil` 的操作优化为更高效的内存清零函数（例如 `memclrNoHeapPointers` 和 `memclrHasPointers`）。
2. **测试切片的扩展操作:** 验证 `append` 函数在扩展切片时的优化，特别是当追加的是通过 `make` 创建的新切片时，编译器是否能避免不必要的内存清零和 `makeslice` 调用。
3. **测试切片的创建和复制操作:** 验证 `make` 和 `copy` 函数结合使用时的优化，例如编译器是否能识别 `make` 后立即 `copy` 的模式，并使用更高效的 `makeslicecopy` 函数。
4. **测试访问切片元素时的 nil 检查:**  验证编译器是否能在确定切片非空时，省略对 `&s[0]` 的 nil 指针检查。
5. **测试切片字面量的初始化:** 验证编译器如何处理小切片和大切量字面量的初始化，可能采取不同的内存分配策略。
6. **测试特定架构的优化:**  例如，针对 PPC64 架构的常量折叠优化。
7. **测试 `unsafe.Slice` 的代码生成:** 验证 `unsafe.Slice` 在不同情况下的代码生成情况。

**它是什么 Go 语言功能的实现:**

该文件不是一个具体 Go 语言功能的实现，而是 Go 编译器自身优化的测试用例集合。它测试了编译器在处理切片时的各种优化策略。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	// 测试切片清空
	s1 := []int{1, 2, 3, 4, 5}
	fmt.Println("Before SliceClear:", s1)
	s1 = SliceClear(s1) // 假设 SliceClear 函数定义在 slices.go 中
	fmt.Println("After SliceClear:", s1)

	s2 := []*int{new(int), new(int)}
	fmt.Println("Before SliceClearPointers:", s2)
	s2 = SliceClearPointers(s2) // 假设 SliceClearPointers 函数定义在 slices.go 中
	fmt.Println("After SliceClearPointers:", s2)

	// 测试切片扩展
	s3 := []int{1, 2}
	fmt.Println("Before SliceExtensionConst:", s3)
	s3 = SliceExtensionConst(s3) // 假设 SliceExtensionConst 函数定义在 slices.go 中
	fmt.Println("After SliceExtensionConst:", s3)

	// 测试切片创建和复制
	s4 := []int{10, 20, 30}
	fmt.Println("Before SliceMakeCopyLen:", s4)
	s5 := SliceMakeCopyLen(s4) // 假设 SliceMakeCopyLen 函数定义在 slices.go 中
	fmt.Println("After SliceMakeCopyLen:", s5)
}

// 以下是 slices.go 文件中部分函数的简化版本，仅用于演示
func SliceClear(s []int) []int {
	for i := range s {
		s[i] = 0
	}
	return s
}

func SliceClearPointers(s []*int) []*int {
	for i := range s {
		s[i] = nil
	}
	return s
}

func SliceExtensionConst(s []int) []int {
	return append(s, make([]int, 1<<2)...)
}

func SliceMakeCopyLen(s []int) []int {
	a := make([]int, len(s))
	copy(a, s)
	return a
}
```

**代码逻辑介绍 (带假设的输入与输出):**

* **`SliceClear(s []int)`:**
    * **假设输入:** `s` 为 `[]int{1, 2, 3}`
    * **逻辑:** 遍历切片 `s` 的每个元素，将其赋值为 `0`。
    * **预期输出:** `[]int{0, 0, 0}`
* **`SliceClearPointers(s []*int)`:**
    * **假设输入:** `s` 为 `[]*int{0xc000010080, 0xc000010088}` (假设的指针地址)
    * **逻辑:** 遍历切片 `s` 的每个元素，将其赋值为 `nil`。
    * **预期输出:** `[]*int{<nil>, <nil>}`
* **`SliceExtensionConst(s []int)`:**
    * **假设输入:** `s` 为 `[]int{1, 2}`
    * **逻辑:** 创建一个新的 `[]int` 切片，长度为 `1 << 2` (即 4)，并将其追加到切片 `s` 的末尾。
    * **预期输出:** `[]int{1, 2, 0, 0, 0, 0}`
* **`SliceMakeCopyLen(s []int)`:**
    * **假设输入:** `s` 为 `[]int{10, 20, 30}`
    * **逻辑:** 创建一个新的 `[]int` 切片 `a`，长度与 `s` 相同。然后将 `s` 中的元素复制到 `a` 中。
    * **预期输出:** `[]int{10, 20, 30}`

**命令行参数的具体处理:**

该文件本身不处理命令行参数。它是作为 Go 编译器的测试用例被执行的。Go 的测试工具 (`go test`) 会解析以 `// asmcheck` 开头的注释，并根据目标架构执行相应的汇编代码检查。例如，`amd64:` 和 `ppc64x:` 后面的正则表达式用于匹配特定架构下生成的汇编指令。

**使用者易犯错的点:**

虽然该文件是编译器测试代码，但其中反映了一些在使用切片时容易犯错的地方，例如在 `SliceMakeCopyNoOpt...` 系列函数中体现的：

* **在 `make` 之后没有立即使用 `copy`:**  编译器可能无法优化这种模式，导致额外的内存清零操作。
* **`copy` 的目标切片未分配足够的空间:**  `copy` 函数只会复制到目标切片的长度范围内，如果目标切片长度小于源切片，则会丢失数据。
* **错误地使用切片进行赋值:** 例如 `s = make([]*int, 4)` 会改变 `s` 指向的切片，而不是操作原有的切片。
* **在没有 `make` 的情况下进行 `copy`:**  会导致 panic，因为目标切片为 `nil` 或未分配空间。

例如，`SliceMakeCopyNoOptBlank` 函数展示了一个潜在的错误：

```go
func SliceMakeCopyNoOptBlank(s []*int) []*int {
	var a []*int
	// amd64:-`.*runtime\.makeslicecopy`
	_ = make([]*int, 4) // 创建了一个新的切片但没有赋值给 a
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a, s) // 这里的 a 仍然是 nil，copy 会导致 panic
	return a
}
```

在这个例子中，`make([]*int, 4)` 创建了一个新的切片，但并没有将其赋值给 `a`。因此，在 `copy(a, s)` 时，`a` 仍然是 `nil`，这会导致运行时 panic。这是使用者容易犯的一个错误，即在进行 `copy` 操作之前，没有正确地初始化目标切片。

总而言之，`go/test/codegen/slices.go` 是一个深入了解 Go 编译器如何优化切片操作的宝贵资源。它通过汇编级别的断言，确保编译器在处理切片时能够生成高效的代码。虽然普通 Go 开发者不会直接使用或修改这个文件，但理解其背后的原理可以帮助我们编写更高效的 Go 代码，并避免一些常见的切片使用错误。

Prompt: 
```
这是路径为go/test/codegen/slices.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// asmcheck

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import "unsafe"

// This file contains code generation tests related to the handling of
// slice types.

// ------------------ //
//      Clear         //
// ------------------ //

// Issue #5373 optimize memset idiom
// Some of the clears get inlined, see #56997

func SliceClear(s []int) []int {
	// amd64:`.*memclrNoHeapPointers`
	// ppc64x:`.*memclrNoHeapPointers`
	for i := range s {
		s[i] = 0
	}
	return s
}

func SliceClearPointers(s []*int) []*int {
	// amd64:`.*memclrHasPointers`
	// ppc64x:`.*memclrHasPointers`
	for i := range s {
		s[i] = nil
	}
	return s
}

// ------------------ //
//      Extension     //
// ------------------ //

// Issue #21266 - avoid makeslice in append(x, make([]T, y)...)

func SliceExtensionConst(s []int) []int {
	// amd64:-`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:-`.*runtime\.panicmakeslicelen`
	// amd64:"MOVUPS\tX15"
	// loong64:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.makeslice`
	// ppc64x:-`.*runtime\.panicmakeslicelen`
	return append(s, make([]int, 1<<2)...)
}

func SliceExtensionConstInt64(s []int) []int {
	// amd64:-`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:-`.*runtime\.panicmakeslicelen`
	// amd64:"MOVUPS\tX15"
	// loong64:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.makeslice`
	// ppc64x:-`.*runtime\.panicmakeslicelen`
	return append(s, make([]int, int64(1<<2))...)
}

func SliceExtensionConstUint64(s []int) []int {
	// amd64:-`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:-`.*runtime\.panicmakeslicelen`
	// amd64:"MOVUPS\tX15"
	// loong64:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.makeslice`
	// ppc64x:-`.*runtime\.panicmakeslicelen`
	return append(s, make([]int, uint64(1<<2))...)
}

func SliceExtensionConstUint(s []int) []int {
	// amd64:-`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:-`.*runtime\.panicmakeslicelen`
	// amd64:"MOVUPS\tX15"
	// loong64:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.makeslice`
	// ppc64x:-`.*runtime\.panicmakeslicelen`
	return append(s, make([]int, uint(1<<2))...)
}

// On ppc64x and loong64 continue to use memclrNoHeapPointers
// for sizes >= 512.
func SliceExtensionConst512(s []int) []int {
	// amd64:-`.*runtime\.memclrNoHeapPointers`
	// loong64:`.*runtime\.memclrNoHeapPointers`
	// ppc64x:`.*runtime\.memclrNoHeapPointers`
	return append(s, make([]int, 1<<9)...)
}

func SliceExtensionPointer(s []*int, l int) []*int {
	// amd64:`.*runtime\.memclrHasPointers`
	// amd64:-`.*runtime\.makeslice`
	// ppc64x:`.*runtime\.memclrHasPointers`
	// ppc64x:-`.*runtime\.makeslice`
	return append(s, make([]*int, l)...)
}

func SliceExtensionVar(s []byte, l int) []byte {
	// amd64:`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// ppc64x:`.*runtime\.memclrNoHeapPointers`
	// ppc64x:-`.*runtime\.makeslice`
	return append(s, make([]byte, l)...)
}

func SliceExtensionVarInt64(s []byte, l int64) []byte {
	// amd64:`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:`.*runtime\.panicmakeslicelen`
	return append(s, make([]byte, l)...)
}

func SliceExtensionVarUint64(s []byte, l uint64) []byte {
	// amd64:`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:`.*runtime\.panicmakeslicelen`
	return append(s, make([]byte, l)...)
}

func SliceExtensionVarUint(s []byte, l uint) []byte {
	// amd64:`.*runtime\.memclrNoHeapPointers`
	// amd64:-`.*runtime\.makeslice`
	// amd64:`.*runtime\.panicmakeslicelen`
	return append(s, make([]byte, l)...)
}

func SliceExtensionInt64(s []int, l64 int64) []int {
	// 386:`.*runtime\.makeslice`
	// 386:-`.*runtime\.memclr`
	return append(s, make([]int, l64)...)
}

// ------------------ //
//      Make+Copy     //
// ------------------ //

// Issue #26252 - avoid memclr for make+copy

func SliceMakeCopyLen(s []int) []int {
	// amd64:`.*runtime\.mallocgc`
	// amd64:`.*runtime\.memmove`
	// amd64:-`.*runtime\.makeslice`
	// ppc64x:`.*runtime\.mallocgc`
	// ppc64x:`.*runtime\.memmove`
	// ppc64x:-`.*runtime\.makeslice`
	a := make([]int, len(s))
	copy(a, s)
	return a
}

func SliceMakeCopyLenPtr(s []*int) []*int {
	// amd64:`.*runtime\.makeslicecopy`
	// amd64:-`.*runtime\.makeslice\(`
	// amd64:-`.*runtime\.typedslicecopy
	// ppc64x:`.*runtime\.makeslicecopy`
	// ppc64x:-`.*runtime\.makeslice\(`
	// ppc64x:-`.*runtime\.typedslicecopy
	a := make([]*int, len(s))
	copy(a, s)
	return a
}

func SliceMakeCopyConst(s []int) []int {
	// amd64:`.*runtime\.makeslicecopy`
	// amd64:-`.*runtime\.makeslice\(`
	// amd64:-`.*runtime\.memmove`
	a := make([]int, 4)
	copy(a, s)
	return a
}

func SliceMakeCopyConstPtr(s []*int) []*int {
	// amd64:`.*runtime\.makeslicecopy`
	// amd64:-`.*runtime\.makeslice\(`
	// amd64:-`.*runtime\.typedslicecopy
	a := make([]*int, 4)
	copy(a, s)
	return a
}

func SliceMakeCopyNoOptNoDeref(s []*int) []*int {
	a := new([]*int)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	*a = make([]*int, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(*a, s)
	return *a
}

func SliceMakeCopyNoOptNoVar(s []*int) []*int {
	a := make([][]*int, 1)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a[0] = make([]*int, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a[0], s)
	return a[0]
}

func SliceMakeCopyNoOptBlank(s []*int) []*int {
	var a []*int
	// amd64:-`.*runtime\.makeslicecopy`
	_ = make([]*int, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a, s)
	return a
}

func SliceMakeCopyNoOptNoMake(s []*int) []*int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:-`.*runtime\.objectnew`
	a := *new([]*int)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a, s)
	return a
}

func SliceMakeCopyNoOptNoHeapAlloc(s []*int) int {
	// amd64:-`.*runtime\.makeslicecopy`
	a := make([]*int, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a, s)
	return cap(a)
}

func SliceMakeCopyNoOptNoCap(s []*int) []*int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 0, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.typedslicecopy`
	copy(a, s)
	return a
}

func SliceMakeCopyNoOptNoCopy(s []*int) []*int {
	copy := func(x, y []*int) {}
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 4)
	// amd64:-`.*runtime\.makeslicecopy`
	copy(a, s)
	return a
}

func SliceMakeCopyNoOptWrongOrder(s []*int) []*int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 4)
	// amd64:`.*runtime\.typedslicecopy`
	// amd64:-`.*runtime\.makeslicecopy`
	copy(s, a)
	return a
}

func SliceMakeCopyNoOptWrongAssign(s []*int) []*int {
	var a []*int
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	s = make([]*int, 4)
	// amd64:`.*runtime\.typedslicecopy`
	// amd64:-`.*runtime\.makeslicecopy`
	copy(a, s)
	return s
}

func SliceMakeCopyNoOptCopyLength(s []*int) (int, []*int) {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 4)
	// amd64:`.*runtime\.typedslicecopy`
	// amd64:-`.*runtime\.makeslicecopy`
	n := copy(a, s)
	return n, a
}

func SliceMakeCopyNoOptSelfCopy(s []*int) []*int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 4)
	// amd64:`.*runtime\.typedslicecopy`
	// amd64:-`.*runtime\.makeslicecopy`
	copy(a, a)
	return a
}

func SliceMakeCopyNoOptTargetReference(s []*int) []*int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]*int, 4)
	// amd64:`.*runtime\.typedslicecopy`
	// amd64:-`.*runtime\.makeslicecopy`
	copy(a, s[:len(a)])
	return a
}

func SliceMakeCopyNoOptCap(s []int) []int {
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.makeslice\(`
	a := make([]int, len(s), 9)
	// amd64:-`.*runtime\.makeslicecopy`
	// amd64:`.*runtime\.memmove`
	copy(a, s)
	return a
}

func SliceMakeCopyNoMemmoveDifferentLen(s []int) []int {
	// amd64:`.*runtime\.makeslicecopy`
	// amd64:-`.*runtime\.memmove`
	a := make([]int, len(s)-1)
	// amd64:-`.*runtime\.memmove`
	copy(a, s)
	return a
}

func SliceMakeEmptyPointerToZerobase() []int {
	// amd64:`LEAQ.+runtime\.zerobase`
	// amd64:-`.*runtime\.makeslice`
	return make([]int, 0)
}

// ---------------------- //
//   Nil check of &s[0]   //
// ---------------------- //
// See issue 30366
func SliceNilCheck(s []int) {
	p := &s[0]
	// amd64:-`TESTB`
	_ = *p
}

// ---------------------- //
//   Init slice literal   //
// ---------------------- //
// See issue 21561
func InitSmallSliceLiteral() []int {
	// amd64:`MOVQ\t[$]42`
	return []int{42}
}

func InitNotSmallSliceLiteral() []int {
	// amd64:`LEAQ\t.*stmp_`
	return []int{
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
		42,
	}
}

// --------------------------------------- //
//   Test PPC64 SUBFCconst folding rules   //
//   triggered by slice operations.        //
// --------------------------------------- //

func SliceWithConstCompare(a []int, b int) []int {
	var c []int = []int{1, 2, 3, 4, 5}
	if b+len(a) < len(c) {
		// ppc64x:-"NEG"
		return c[b:]
	}
	return a
}

func SliceWithSubtractBound(a []int, b int) []int {
	// ppc64x:"SUBC",-"NEG"
	return a[(3 - b):]
}

// --------------------------------------- //
//   Code generation for unsafe.Slice      //
// --------------------------------------- //

func Slice1(p *byte, i int) []byte {
	// amd64:-"MULQ"
	return unsafe.Slice(p, i)
}
func Slice0(p *struct{}, i int) []struct{} {
	// amd64:-"MULQ"
	return unsafe.Slice(p, i)
}

"""



```