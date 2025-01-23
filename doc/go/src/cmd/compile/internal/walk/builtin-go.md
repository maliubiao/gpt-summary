Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first line `// Copyright 2009 The Go Authors. All rights reserved.walk/bui` and the `package walk` declaration immediately tell us this code is part of the Go compiler, specifically in the `walk` phase. The `builtin.go` filename strongly suggests it deals with built-in functions.

2. **High-Level Scan for Function Names:** Quickly scan the code for function names starting with `walk`. This is a strong indicator of the core functionality. We see functions like `walkAppend`, `walkClear`, `walkClose`, `walkCopy`, etc. The pattern `walk<Builtin>` is a clear convention.

3. **Analyze Each `walk` Function:**  Go through each `walk` function individually and try to understand its purpose based on:
    * **Function Name:** `walkAppend` likely handles the `append` built-in. `walkClear` probably handles `clear`. `walkCopy` handles `copy`, and so on.
    * **Input Parameters:** The first parameter is usually a pointer to an IR node (`*ir.CallExpr` or `*ir.UnaryExpr`). This suggests the function is operating on the intermediate representation of the Go code. The `init *ir.Nodes` parameter is common, hinting at adding initialization statements.
    * **Return Type:** Usually `ir.Node`, indicating the function transforms or replaces an IR node.
    * **Function Body:** Look for key operations:
        * **`mkcall`:**  This function likely creates calls to runtime functions.
        * **`typecheck` package usage:**  Interactions with `typecheck` suggest type-related operations, conversions, and validation.
        * **`ir.New...` calls:** These create new IR nodes, showing how the code is being transformed.
        * **Logic (if statements, loops):** Understand the conditions and transformations being applied.

4. **Identify Key Built-in Functions:** Based on the `walk` function names, it becomes clear which built-in functions are handled: `append`, `clear`, `close`, `copy`, `delete`, `len`, `cap`, `make` (for slices, maps, and channels), `new`, `min`, `max`, `print`, `println`, `recover`, and functions in the `unsafe` package (`Slice`, `String`, `PointerData`, `StringData`).

5. **Infer Functionality:** Based on the analysis of each `walk` function, describe what it does. For example:
    * `walkAppend`:  Handles appending to slices, including checks for capacity and potentially calling `growslice`.
    * `walkCopy`:  Optimizes `copy` by potentially using `memmove` or runtime functions depending on pointer presence.
    * `walkMakeSlice`:  Handles the `make([]T, len, cap)` operation, potentially allocating on the stack for non-escaping slices.

6. **Look for Specific Optimizations and Edge Cases:**  Notice things like:
    * Special handling for `len([]rune(string))` using `runtime.countrunes`.
    * Optimizations for `make(map)` with small hints.
    * Different code paths for escaping and non-escaping values in `make` and `new`.
    * Handling for the race detector in `walkAppend`.
    * The use of `unsafe` package functions and related checks.

7. **Connect to Go Language Features:** Relate the analyzed `walk` functions to the corresponding Go language features. For instance, `walkAppend` directly implements the `append` functionality, `walkMakeMap` implements `make(map[K]V)`, and so on.

8. **Code Examples (Illustrative):**  Create simple Go code examples that demonstrate the behavior of the built-in functions being handled by the `walk` functions. Focus on common use cases.

9. **Code Reasoning (Hypothetical Inputs and Outputs):** For more complex functions like `walkAppend` or `walkCopy`, create scenarios with example inputs (e.g., a slice and elements to append) and describe the *intended* output after the `walk` phase. This helps illustrate the transformations. *Initially, I might think about showing the exact IR output, but that's too complex for a general explanation. Describing the higher-level transformation is sufficient.*

10. **Command-Line Parameters:**  Scan for any references to `base.Flag`. In this snippet, `base.Flag.Cfg.Instrumenting` and `base.Flag.CompilingRuntime` are checked in `walkAppend`. Explain how these flags likely influence the code generation, especially for features like the race detector or when compiling the runtime itself.

11. **Common Mistakes:** Think about common errors developers make when using these built-in functions. For example, misunderstanding slice capacity with `append`, incorrect usage of `unsafe.Slice`, or forgetting that `copy` truncates.

12. **Review and Refine:**  Read through the entire analysis to ensure accuracy, clarity, and completeness. Make sure the explanations are easy to understand and the code examples are relevant. *I might initially focus too much on compiler internals. I need to balance that with explanations that are useful to a Go developer.*

This systematic approach, starting with high-level understanding and progressively drilling down into the details of each function, allows for a comprehensive analysis of the code snippet and its connection to Go language features. The key is to identify the patterns and purpose of the `walk` functions and relate them back to the familiar built-in functions in Go.
这段代码是Go编译器 `cmd/compile/internal/walk` 包中 `builtin.go` 文件的一部分，主要负责**将Go语言的内置函数调用转换为更底层的、可以直接生成汇编代码的表示形式**。这个过程是编译过程中的一个重要阶段，被称为“walk”或者“Lowering”。

以下是这段代码中各个函数的功能以及它们实现的Go语言特性：

**1. `walkAppend(n *ir.CallExpr, init *ir.Nodes, dst ir.Node) ir.Node`**

* **功能:** 处理 `append` 内置函数。
* **Go语言特性:** 实现向切片追加元素的功能。
* **推理:** `append` 函数的核心在于处理切片的扩容。当切片的容量不足以容纳新元素时，需要分配更大的内存空间并将原有元素复制过去。这段代码的逻辑主要关注以下几点：
    * **副作用处理:** 确保 `append` 的参数（除了第一个切片参数）中的副作用在追加操作之前被执行。
    * **竞态检测:**  为竞态检测器扩展 `append` 操作，使其更加细致地跟踪内存访问。
    * **扩容逻辑:** 如果开启了竞态检测，会展开 `append` 操作，显式地进行容量检查和扩容（调用 `growslice`）。
* **代码示例 (竞态检测开启时):**

```go
package main

func main() {
	s := []int{1, 2, 3}
	a := 4
	b := 5
	s = append(s, a, b)
	println(s...)
}
```

* **假设输入:**  `s` 是 `[]int{1, 2, 3}`，要追加的元素是 `a = 4` 和 `b = 5`。
* **预期输出 (在walk阶段，竞态检测开启时):** 代码会被转换成类似下面的形式（这只是概念上的，实际的IR更复杂）：

```go
package main

func main() {
	s_orig := []int{1, 2, 3}
	a := 4
	b := 5

	// 初始化语句
	s := s_orig
	argc := 2 // 要追加的元素数量
	newLen := len(s) + argc
	var s_new []int
	if uint(newLen) <= uint(cap(s)) {
		s_new = s[:newLen]
	} else {
		s_new = growslice_runtime(s, newLen, cap(s), argc, element_type_int)
	}
	s_new[len(s)-argc] = a
	s_new[len(s)-argc+1] = b
	s = s_new // 将新切片赋值给原变量
	println(s...)
}

func growslice_runtime(oldSlice []int, newLen, oldCap, num int, elemType interface{}) []int {
	// 实际的扩容逻辑
	// ...
	return nil // 假设返回新的切片
}
```

**2. `walkGrowslice(slice *ir.Name, init *ir.Nodes, oldPtr, newLen, oldCap, num ir.Node) *ir.CallExpr`**

* **功能:** 生成调用运行时 `growslice` 函数的代码。
* **Go语言特性:**  实现切片的动态扩容。
* **推理:**  当 `append` 需要扩容时，会调用运行时系统提供的 `growslice` 函数来分配新的内存空间并复制数据。

**3. `walkClear(n *ir.UnaryExpr) ir.Node`**

* **功能:** 处理 `clear` 内置函数。
* **Go语言特性:** 清空切片或map中的所有元素。
* **推理:**  对于切片，`clear` 将切片的所有元素设置为零值。对于map，`clear` 删除map中的所有键值对。
* **代码示例:**

```go
package main

func main() {
	s := []int{1, 2, 3}
	clear(s)
	println(s...) // 输出：0 0 0

	m := map[string]int{"a": 1, "b": 2}
	clear(m)
	println(len(m)) // 输出：0
}
```

**4. `walkClose(n *ir.UnaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `close` 内置函数。
* **Go语言特性:** 关闭一个channel。
* **推理:** `close` 函数用于通知接收者channel中不再有新的数据发送。

**5. `walkCopy(n *ir.BinaryExpr, init *ir.Nodes, runtimecall bool) ir.Node`**

* **功能:** 处理 `copy` 内置函数。
* **Go语言特性:** 将元素从源切片复制到目标切片。
* **推理:**  `copy` 函数的实现会根据元素类型是否包含指针以及是否需要进行运行时调用来进行优化。如果元素不包含指针，并且可以安全地使用 `memmove`，则会生成 `memmove` 的调用。否则，会调用运行时提供的 `slicecopy` 函数。
* **代码示例:**

```go
package main

func main() {
	src := []int{1, 2, 3}
	dst := make([]int, 3)
	n := copy(dst, src)
	println(n, dst[0], dst[1], dst[2]) // 输出：3 1 2 3
}
```

**6. `walkDelete(init *ir.Nodes, n *ir.CallExpr) ir.Node`**

* **功能:** 处理 `delete` 内置函数。
* **Go语言特性:** 从map中删除指定的键值对。
* **推理:**  `delete` 函数会根据map的实现方式调用相应的运行时函数来删除元素。

**7. `walkLenCap(n *ir.UnaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `len` 和 `cap` 内置函数。
* **Go语言特性:** 获取切片、map、channel或数组的长度或容量。
* **推理:** 对于一些特殊情况，例如 `len([]rune(string))` 会被优化为调用 `runtime.countrunes`。对于数组，长度在编译时已知，可以直接替换为常量。对于channel，会调用 `chanlen` 或 `chancap` 运行时函数。
* **代码示例:**

```go
package main

func main() {
	s := []int{1, 2, 3}
	println(len(s), cap(s)) // 输出：3 (可能是3或更大的值)

	str := "你好"
	println(len([]rune(str))) // 输出：2
}
```

**8. `walkMakeChan(n *ir.MakeExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `make` 函数创建channel的情况。
* **Go语言特性:** 创建一个新的channel。
* **推理:**  会根据channel的缓冲区大小选择调用 `makechan` 或 `makechan64` 运行时函数。

**9. `walkMakeMap(n *ir.MakeExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `make` 函数创建map的情况。
* **Go语言特性:** 创建一个新的map。
* **推理:**  会根据是否启用新的 `swisstable` map 实现以及预估的大小选择不同的运行时函数，例如 `makemap`, `makemap64`, `makemap_small`。

**10. `walkMakeSlice(n *ir.MakeExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `make` 函数创建切片的情况。
* **Go语言特性:** 创建一个新的切片。
* **推理:**  会根据切片的长度和容量以及是否逃逸到堆上选择不同的实现方式。对于不逃逸的切片，可能会直接在栈上分配。对于逃逸的切片，会调用 `makeslice` 或 `makeslice64` 运行时函数。

**11. `walkMakeSliceCopy(n *ir.MakeExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `make` 函数创建切片并从另一个切片复制数据的情况 (对应的IR节点是 `OMAKESLICECOPY`)。
* **Go语言特性:**  一种优化的切片创建和复制操作。
* **推理:**  会根据元素类型是否包含指针选择调用 `makeslicecopy` 或组合使用 `mallocgc` 和 `memmove`。

**12. `walkNew(n *ir.UnaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `new` 内置函数。
* **Go语言特性:** 分配内存并返回指向该内存的指针。
* **推理:**  对于不逃逸到堆上的小对象，可能会在栈上分配。否则，会调用运行时分配内存的函数。

**13. `walkMinMax(n *ir.CallExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `min` 和 `max` 内置函数。
* **Go语言特性:** 返回一组参数中的最小值或最大值。

**14. `walkPrint(nn *ir.CallExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `print` 和 `println` 内置函数。
* **Go语言特性:** 输出信息到标准错误输出。
* **推理:**  会将参数转换为字符串并调用运行时提供的打印函数，例如 `printint`, `printstring` 等。

**15. `walkRecoverFP(nn *ir.CallExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `recover` 内置函数（通常通过 `runtime.GoRecover` 实现）。
* **Go语言特性:** 允许程序捕获 panic 异常。

**16. `walkUnsafeData(n *ir.UnaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `unsafe.SliceData` 和 `unsafe.StringData`。
* **Go语言特性:** 获取切片或字符串底层数组的指针。

**17. `walkUnsafeSlice(n *ir.BinaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `unsafe.Slice`。
* **Go语言特性:** 将指针和长度转换为切片。
* **推理:**  会进行一些安全检查，例如检查指针是否为空以及长度是否有效。

**18. `walkUnsafeString(n *ir.BinaryExpr, init *ir.Nodes) ir.Node`**

* **功能:** 处理 `unsafe.String`。
* **Go语言特性:** 将指针和长度转换为字符串。
* **推理:**  类似于 `unsafe.Slice`，会进行安全检查。

**命令行参数的处理:**

这段代码中涉及到以下命令行参数（通过 `base.Flag` 访问）：

* **`base.Flag.Cfg.Instrumenting`:**  指示是否正在进行代码插桩（例如，用于竞态检测或覆盖率分析）。在 `walkAppend` 中，如果启用了插桩，则会展开 `append` 操作以进行更细致的跟踪。
* **`base.Flag.CompilingRuntime`:** 指示是否正在编译Go运行时自身。在 `walkAppend` 中，如果正在编译运行时，则不会进行竞态检测相关的展开。
* **`base.Flag.N == 0`:**  在 `isRuneCount` 和 `isByteCount` 中使用，可能与编译器优化级别有关。当 `N` 为 0 时，会尝试将 `len([]rune(string))` 和 `len(string([]byte))` 优化为更高效的运行时函数调用。
* **`ir.ShouldCheckPtr(ir.CurFunc, 1)`:**  在 `walkUnsafeSlice` 和 `walkUnsafeString` 中使用，用于判断是否需要进行指针安全检查。这可能受到编译器参数的影响，例如 `-gcflags=-d=checkptr=1`。

**使用者易犯错的点 (与这些内置函数相关):**

虽然这段代码是编译器内部实现，但它反映了Go语言用户在使用这些内置函数时可能犯的错误：

* **`append`:**
    * **误解容量:**  不理解 `append` 在容量不足时的扩容机制，导致性能下降或不必要的内存分配。
    * **直接修改原切片:**  在某些情况下，`append` 可能会修改原切片的底层数组，这可能导致意想不到的结果，尤其是在多个切片共享底层数组时。
* **`copy`:**
    * **目标切片长度不足:** `copy` 只会复制较短切片的长度的元素，如果目标切片长度小于源切片，则会丢失部分数据。
* **`make`:**
    * **切片容量设置过小:** 导致频繁的扩容，影响性能。
    * **切片容量设置过大:** 浪费内存。
* **`unsafe.Slice` 和 `unsafe.String`:**
    * **指针和长度不匹配:** 导致程序崩溃或访问非法内存。
    * **生命周期管理不当:**  `unsafe` 包创建的切片或字符串的底层内存可能在预期之外被释放，导致悬 dangling 指针。

总而言之，`builtin.go` 中的代码是Go编译器实现其内置功能的核心部分，它将高级的Go语法转换为可以在运行时执行的低级操作。理解这段代码有助于深入了解Go语言的运行机制。

### 提示词
```
这是路径为go/src/cmd/compile/internal/walk/builtin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.walk/bui
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package walk

import (
	"fmt"
	"go/constant"
	"go/token"
	"internal/abi"
	"internal/buildcfg"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/escape"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
)

// Rewrite append(src, x, y, z) so that any side effects in
// x, y, z (including runtime panics) are evaluated in
// initialization statements before the append.
// For normal code generation, stop there and leave the
// rest to ssagen.
//
// For race detector, expand append(src, a [, b]* ) to
//
//	init {
//	  s := src
//	  const argc = len(args) - 1
//	  newLen := s.len + argc
//	  if uint(newLen) <= uint(s.cap) {
//	    s = s[:newLen]
//	  } else {
//	    s = growslice(s.ptr, newLen, s.cap, argc, elemType)
//	  }
//	  s[s.len - argc] = a
//	  s[s.len - argc + 1] = b
//	  ...
//	}
//	s
func walkAppend(n *ir.CallExpr, init *ir.Nodes, dst ir.Node) ir.Node {
	if !ir.SameSafeExpr(dst, n.Args[0]) {
		n.Args[0] = safeExpr(n.Args[0], init)
		n.Args[0] = walkExpr(n.Args[0], init)
	}
	walkExprListSafe(n.Args[1:], init)

	nsrc := n.Args[0]

	// walkExprListSafe will leave OINDEX (s[n]) alone if both s
	// and n are name or literal, but those may index the slice we're
	// modifying here. Fix explicitly.
	// Using cheapExpr also makes sure that the evaluation
	// of all arguments (and especially any panics) happen
	// before we begin to modify the slice in a visible way.
	ls := n.Args[1:]
	for i, n := range ls {
		n = cheapExpr(n, init)
		if !types.Identical(n.Type(), nsrc.Type().Elem()) {
			n = typecheck.AssignConv(n, nsrc.Type().Elem(), "append")
			n = walkExpr(n, init)
		}
		ls[i] = n
	}

	argc := len(n.Args) - 1
	if argc < 1 {
		return nsrc
	}

	// General case, with no function calls left as arguments.
	// Leave for ssagen, except that instrumentation requires the old form.
	if !base.Flag.Cfg.Instrumenting || base.Flag.CompilingRuntime {
		return n
	}

	var l []ir.Node

	// s = slice to append to
	s := typecheck.TempAt(base.Pos, ir.CurFunc, nsrc.Type())
	l = append(l, ir.NewAssignStmt(base.Pos, s, nsrc))

	// num = number of things to append
	num := ir.NewInt(base.Pos, int64(argc))

	// newLen := s.len + num
	newLen := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
	l = append(l, ir.NewAssignStmt(base.Pos, newLen, ir.NewBinaryExpr(base.Pos, ir.OADD, ir.NewUnaryExpr(base.Pos, ir.OLEN, s), num)))

	// if uint(newLen) <= uint(s.cap)
	nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
	nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OLE, typecheck.Conv(newLen, types.Types[types.TUINT]), typecheck.Conv(ir.NewUnaryExpr(base.Pos, ir.OCAP, s), types.Types[types.TUINT]))
	nif.Likely = true

	// then { s = s[:n] }
	slice := ir.NewSliceExpr(base.Pos, ir.OSLICE, s, nil, newLen, nil)
	slice.SetBounded(true)
	nif.Body = []ir.Node{
		ir.NewAssignStmt(base.Pos, s, slice),
	}

	// else { s = growslice(s.ptr, n, s.cap, a, T) }
	nif.Else = []ir.Node{
		ir.NewAssignStmt(base.Pos, s, walkGrowslice(s, nif.PtrInit(),
			ir.NewUnaryExpr(base.Pos, ir.OSPTR, s),
			newLen,
			ir.NewUnaryExpr(base.Pos, ir.OCAP, s),
			num)),
	}

	l = append(l, nif)

	ls = n.Args[1:]
	for i, n := range ls {
		// s[s.len-argc+i] = arg
		ix := ir.NewIndexExpr(base.Pos, s, ir.NewBinaryExpr(base.Pos, ir.OSUB, newLen, ir.NewInt(base.Pos, int64(argc-i))))
		ix.SetBounded(true)
		l = append(l, ir.NewAssignStmt(base.Pos, ix, n))
	}

	typecheck.Stmts(l)
	walkStmtList(l)
	init.Append(l...)
	return s
}

// growslice(ptr *T, newLen, oldCap, num int, <type>) (ret []T)
func walkGrowslice(slice *ir.Name, init *ir.Nodes, oldPtr, newLen, oldCap, num ir.Node) *ir.CallExpr {
	elemtype := slice.Type().Elem()
	fn := typecheck.LookupRuntime("growslice", elemtype, elemtype)
	elemtypeptr := reflectdata.TypePtrAt(base.Pos, elemtype)
	return mkcall1(fn, slice.Type(), init, oldPtr, newLen, oldCap, num, elemtypeptr)
}

// walkClear walks an OCLEAR node.
func walkClear(n *ir.UnaryExpr) ir.Node {
	typ := n.X.Type()
	switch {
	case typ.IsSlice():
		if n := arrayClear(n.X.Pos(), n.X, nil); n != nil {
			return n
		}
		// If n == nil, we are clearing an array which takes zero memory, do nothing.
		return ir.NewBlockStmt(n.Pos(), nil)
	case typ.IsMap():
		return mapClear(n.X, reflectdata.TypePtrAt(n.X.Pos(), n.X.Type()))
	}
	panic("unreachable")
}

// walkClose walks an OCLOSE node.
func walkClose(n *ir.UnaryExpr, init *ir.Nodes) ir.Node {
	return mkcall1(chanfn("closechan", 1, n.X.Type()), nil, init, n.X)
}

// Lower copy(a, b) to a memmove call or a runtime call.
//
//	init {
//	  n := len(a)
//	  if n > len(b) { n = len(b) }
//	  if a.ptr != b.ptr { memmove(a.ptr, b.ptr, n*sizeof(elem(a))) }
//	}
//	n;
//
// Also works if b is a string.
func walkCopy(n *ir.BinaryExpr, init *ir.Nodes, runtimecall bool) ir.Node {
	if n.X.Type().Elem().HasPointers() {
		ir.CurFunc.SetWBPos(n.Pos())
		fn := writebarrierfn("typedslicecopy", n.X.Type().Elem(), n.Y.Type().Elem())
		n.X = cheapExpr(n.X, init)
		ptrL, lenL := backingArrayPtrLen(n.X)
		n.Y = cheapExpr(n.Y, init)
		ptrR, lenR := backingArrayPtrLen(n.Y)
		return mkcall1(fn, n.Type(), init, reflectdata.CopyElemRType(base.Pos, n), ptrL, lenL, ptrR, lenR)
	}

	if runtimecall {
		// rely on runtime to instrument:
		//  copy(n.Left, n.Right)
		// n.Right can be a slice or string.

		n.X = cheapExpr(n.X, init)
		ptrL, lenL := backingArrayPtrLen(n.X)
		n.Y = cheapExpr(n.Y, init)
		ptrR, lenR := backingArrayPtrLen(n.Y)

		fn := typecheck.LookupRuntime("slicecopy", ptrL.Type().Elem(), ptrR.Type().Elem())

		return mkcall1(fn, n.Type(), init, ptrL, lenL, ptrR, lenR, ir.NewInt(base.Pos, n.X.Type().Elem().Size()))
	}

	n.X = walkExpr(n.X, init)
	n.Y = walkExpr(n.Y, init)
	nl := typecheck.TempAt(base.Pos, ir.CurFunc, n.X.Type())
	nr := typecheck.TempAt(base.Pos, ir.CurFunc, n.Y.Type())
	var l []ir.Node
	l = append(l, ir.NewAssignStmt(base.Pos, nl, n.X))
	l = append(l, ir.NewAssignStmt(base.Pos, nr, n.Y))

	nfrm := ir.NewUnaryExpr(base.Pos, ir.OSPTR, nr)
	nto := ir.NewUnaryExpr(base.Pos, ir.OSPTR, nl)

	nlen := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])

	// n = len(to)
	l = append(l, ir.NewAssignStmt(base.Pos, nlen, ir.NewUnaryExpr(base.Pos, ir.OLEN, nl)))

	// if n > len(frm) { n = len(frm) }
	nif := ir.NewIfStmt(base.Pos, nil, nil, nil)

	nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OGT, nlen, ir.NewUnaryExpr(base.Pos, ir.OLEN, nr))
	nif.Body.Append(ir.NewAssignStmt(base.Pos, nlen, ir.NewUnaryExpr(base.Pos, ir.OLEN, nr)))
	l = append(l, nif)

	// if to.ptr != frm.ptr { memmove( ... ) }
	ne := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.ONE, nto, nfrm), nil, nil)
	ne.Likely = true
	l = append(l, ne)

	fn := typecheck.LookupRuntime("memmove", nl.Type().Elem(), nl.Type().Elem())
	nwid := ir.Node(typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TUINTPTR]))
	setwid := ir.NewAssignStmt(base.Pos, nwid, typecheck.Conv(nlen, types.Types[types.TUINTPTR]))
	ne.Body.Append(setwid)
	nwid = ir.NewBinaryExpr(base.Pos, ir.OMUL, nwid, ir.NewInt(base.Pos, nl.Type().Elem().Size()))
	call := mkcall1(fn, nil, init, nto, nfrm, nwid)
	ne.Body.Append(call)

	typecheck.Stmts(l)
	walkStmtList(l)
	init.Append(l...)
	return nlen
}

// walkDelete walks an ODELETE node.
func walkDelete(init *ir.Nodes, n *ir.CallExpr) ir.Node {
	init.Append(ir.TakeInit(n)...)
	map_ := n.Args[0]
	key := n.Args[1]
	map_ = walkExpr(map_, init)
	key = walkExpr(key, init)

	t := map_.Type()
	fast := mapfast(t)
	key = mapKeyArg(fast, n, key, false)
	return mkcall1(mapfndel(mapdelete[fast], t), nil, init, reflectdata.DeleteMapRType(base.Pos, n), map_, key)
}

// walkLenCap walks an OLEN or OCAP node.
func walkLenCap(n *ir.UnaryExpr, init *ir.Nodes) ir.Node {
	if isRuneCount(n) {
		// Replace len([]rune(string)) with runtime.countrunes(string).
		return mkcall("countrunes", n.Type(), init, typecheck.Conv(n.X.(*ir.ConvExpr).X, types.Types[types.TSTRING]))
	}
	if isByteCount(n) {
		conv := n.X.(*ir.ConvExpr)
		walkStmtList(conv.Init())
		init.Append(ir.TakeInit(conv)...)
		_, len := backingArrayPtrLen(cheapExpr(conv.X, init))
		return len
	}
	if isChanLenCap(n) {
		name := "chanlen"
		if n.Op() == ir.OCAP {
			name = "chancap"
		}
		// cannot use chanfn - closechan takes any, not chan any,
		// because it accepts both send-only and recv-only channels.
		fn := typecheck.LookupRuntime(name, n.X.Type())
		return mkcall1(fn, n.Type(), init, n.X)
	}

	n.X = walkExpr(n.X, init)

	// replace len(*[10]int) with 10.
	// delayed until now to preserve side effects.
	t := n.X.Type()

	if t.IsPtr() {
		t = t.Elem()
	}
	if t.IsArray() {
		safeExpr(n.X, init)
		con := ir.NewConstExpr(constant.MakeInt64(t.NumElem()), n)
		con.SetTypecheck(1)
		return con
	}
	return n
}

// walkMakeChan walks an OMAKECHAN node.
func walkMakeChan(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	// When size fits into int, use makechan instead of
	// makechan64, which is faster and shorter on 32 bit platforms.
	size := n.Len
	fnname := "makechan64"
	argtype := types.Types[types.TINT64]

	// Type checking guarantees that TIDEAL size is positive and fits in an int.
	// The case of size overflow when converting TUINT or TUINTPTR to TINT
	// will be handled by the negative range checks in makechan during runtime.
	if size.Type().IsKind(types.TIDEAL) || size.Type().Size() <= types.Types[types.TUINT].Size() {
		fnname = "makechan"
		argtype = types.Types[types.TINT]
	}

	return mkcall1(chanfn(fnname, 1, n.Type()), n.Type(), init, reflectdata.MakeChanRType(base.Pos, n), typecheck.Conv(size, argtype))
}

// walkMakeMap walks an OMAKEMAP node.
func walkMakeMap(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	if buildcfg.Experiment.SwissMap {
		return walkMakeSwissMap(n, init)
	}
	return walkMakeOldMap(n, init)
}

func walkMakeSwissMap(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	t := n.Type()
	mapType := reflectdata.SwissMapType()
	hint := n.Len

	// var m *Map
	var m ir.Node
	if n.Esc() == ir.EscNone {
		// Allocate hmap on stack.

		// var mv Map
		// m = &mv
		m = stackTempAddr(init, mapType)

		// Allocate one group pointed to by m.dirPtr on stack if hint
		// is not larger than SwissMapGroupSlots. In case hint is
		// larger, runtime.makemap will allocate on the heap.
		// Maximum key and elem size is 128 bytes, larger objects
		// are stored with an indirection. So max bucket size is 2048+eps.
		if !ir.IsConst(hint, constant.Int) ||
			constant.Compare(hint.Val(), token.LEQ, constant.MakeInt64(abi.SwissMapGroupSlots)) {

			// In case hint is larger than SwissMapGroupSlots
			// runtime.makemap will allocate on the heap, see
			// #20184
			//
			// if hint <= abi.SwissMapGroupSlots {
			//     var gv group
			//     g = &gv
			//     g.ctrl = abi.SwissMapCtrlEmpty
			//     m.dirPtr = g
			// }

			nif := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OLE, hint, ir.NewInt(base.Pos, abi.SwissMapGroupSlots)), nil, nil)
			nif.Likely = true

			groupType := reflectdata.SwissMapGroupType(t)

			// var gv group
			// g = &gv
			g := stackTempAddr(&nif.Body, groupType)

			// Can't use ir.NewInt because bit 63 is set, which
			// makes conversion to uint64 upset.
			empty := ir.NewBasicLit(base.Pos, types.UntypedInt, constant.MakeUint64(abi.SwissMapCtrlEmpty))

			// g.ctrl = abi.SwissMapCtrlEmpty
			csym := groupType.Field(0).Sym // g.ctrl see reflectdata/map_swiss.go
			ca := ir.NewAssignStmt(base.Pos, ir.NewSelectorExpr(base.Pos, ir.ODOT, g, csym), empty)
			nif.Body.Append(ca)

			// m.dirPtr = g
			dsym := mapType.Field(2).Sym // m.dirPtr see reflectdata/map_swiss.go
			na := ir.NewAssignStmt(base.Pos, ir.NewSelectorExpr(base.Pos, ir.ODOT, m, dsym), typecheck.ConvNop(g, types.Types[types.TUNSAFEPTR]))
			nif.Body.Append(na)
			appendWalkStmt(init, nif)
		}
	}

	if ir.IsConst(hint, constant.Int) && constant.Compare(hint.Val(), token.LEQ, constant.MakeInt64(abi.SwissMapGroupSlots)) {
		// Handling make(map[any]any) and
		// make(map[any]any, hint) where hint <= abi.SwissMapGroupSlots
		// specially allows for faster map initialization and
		// improves binary size by using calls with fewer arguments.
		// For hint <= abi.SwissMapGroupSlots no groups will be
		// allocated by makemap. Therefore, no groups need to be
		// allocated in this code path.
		if n.Esc() == ir.EscNone {
			// Only need to initialize m.seed since
			// m map has been allocated on the stack already.
			// m.seed = uintptr(rand())
			rand := mkcall("rand", types.Types[types.TUINT64], init)
			seedSym := mapType.Field(1).Sym // m.seed see reflectdata/map_swiss.go
			appendWalkStmt(init, ir.NewAssignStmt(base.Pos, ir.NewSelectorExpr(base.Pos, ir.ODOT, m, seedSym), typecheck.Conv(rand, types.Types[types.TUINTPTR])))
			return typecheck.ConvNop(m, t)
		}
		// Call runtime.makemap_small to allocate a
		// map on the heap and initialize the map's seed field.
		fn := typecheck.LookupRuntime("makemap_small", t.Key(), t.Elem())
		return mkcall1(fn, n.Type(), init)
	}

	if n.Esc() != ir.EscNone {
		m = typecheck.NodNil()
	}

	// Map initialization with a variable or large hint is
	// more complicated. We therefore generate a call to
	// runtime.makemap to initialize hmap and allocate the
	// map buckets.

	// When hint fits into int, use makemap instead of
	// makemap64, which is faster and shorter on 32 bit platforms.
	fnname := "makemap64"
	argtype := types.Types[types.TINT64]

	// Type checking guarantees that TIDEAL hint is positive and fits in an int.
	// See checkmake call in TMAP case of OMAKE case in OpSwitch in typecheck1 function.
	// The case of hint overflow when converting TUINT or TUINTPTR to TINT
	// will be handled by the negative range checks in makemap during runtime.
	if hint.Type().IsKind(types.TIDEAL) || hint.Type().Size() <= types.Types[types.TUINT].Size() {
		fnname = "makemap"
		argtype = types.Types[types.TINT]
	}

	fn := typecheck.LookupRuntime(fnname, mapType, t.Key(), t.Elem())
	return mkcall1(fn, n.Type(), init, reflectdata.MakeMapRType(base.Pos, n), typecheck.Conv(hint, argtype), m)
}

func walkMakeOldMap(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	t := n.Type()
	hmapType := reflectdata.OldMapType()
	hint := n.Len

	// var h *hmap
	var h ir.Node
	if n.Esc() == ir.EscNone {
		// Allocate hmap on stack.

		// var hv hmap
		// h = &hv
		h = stackTempAddr(init, hmapType)

		// Allocate one bucket pointed to by hmap.buckets on stack if hint
		// is not larger than BUCKETSIZE. In case hint is larger than
		// BUCKETSIZE runtime.makemap will allocate the buckets on the heap.
		// Maximum key and elem size is 128 bytes, larger objects
		// are stored with an indirection. So max bucket size is 2048+eps.
		if !ir.IsConst(hint, constant.Int) ||
			constant.Compare(hint.Val(), token.LEQ, constant.MakeInt64(abi.OldMapBucketCount)) {

			// In case hint is larger than BUCKETSIZE runtime.makemap
			// will allocate the buckets on the heap, see #20184
			//
			// if hint <= BUCKETSIZE {
			//     var bv bmap
			//     b = &bv
			//     h.buckets = b
			// }

			nif := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OLE, hint, ir.NewInt(base.Pos, abi.OldMapBucketCount)), nil, nil)
			nif.Likely = true

			// var bv bmap
			// b = &bv
			b := stackTempAddr(&nif.Body, reflectdata.OldMapBucketType(t))

			// h.buckets = b
			bsym := hmapType.Field(5).Sym // hmap.buckets see reflect.go:hmap
			na := ir.NewAssignStmt(base.Pos, ir.NewSelectorExpr(base.Pos, ir.ODOT, h, bsym), typecheck.ConvNop(b, types.Types[types.TUNSAFEPTR]))
			nif.Body.Append(na)
			appendWalkStmt(init, nif)
		}
	}

	if ir.IsConst(hint, constant.Int) && constant.Compare(hint.Val(), token.LEQ, constant.MakeInt64(abi.OldMapBucketCount)) {
		// Handling make(map[any]any) and
		// make(map[any]any, hint) where hint <= BUCKETSIZE
		// special allows for faster map initialization and
		// improves binary size by using calls with fewer arguments.
		// For hint <= BUCKETSIZE overLoadFactor(hint, 0) is false
		// and no buckets will be allocated by makemap. Therefore,
		// no buckets need to be allocated in this code path.
		if n.Esc() == ir.EscNone {
			// Only need to initialize h.hash0 since
			// hmap h has been allocated on the stack already.
			// h.hash0 = rand32()
			rand := mkcall("rand32", types.Types[types.TUINT32], init)
			hashsym := hmapType.Field(4).Sym // hmap.hash0 see reflect.go:hmap
			appendWalkStmt(init, ir.NewAssignStmt(base.Pos, ir.NewSelectorExpr(base.Pos, ir.ODOT, h, hashsym), rand))
			return typecheck.ConvNop(h, t)
		}
		// Call runtime.makemap_small to allocate an
		// hmap on the heap and initialize hmap's hash0 field.
		fn := typecheck.LookupRuntime("makemap_small", t.Key(), t.Elem())
		return mkcall1(fn, n.Type(), init)
	}

	if n.Esc() != ir.EscNone {
		h = typecheck.NodNil()
	}
	// Map initialization with a variable or large hint is
	// more complicated. We therefore generate a call to
	// runtime.makemap to initialize hmap and allocate the
	// map buckets.

	// When hint fits into int, use makemap instead of
	// makemap64, which is faster and shorter on 32 bit platforms.
	fnname := "makemap64"
	argtype := types.Types[types.TINT64]

	// Type checking guarantees that TIDEAL hint is positive and fits in an int.
	// See checkmake call in TMAP case of OMAKE case in OpSwitch in typecheck1 function.
	// The case of hint overflow when converting TUINT or TUINTPTR to TINT
	// will be handled by the negative range checks in makemap during runtime.
	if hint.Type().IsKind(types.TIDEAL) || hint.Type().Size() <= types.Types[types.TUINT].Size() {
		fnname = "makemap"
		argtype = types.Types[types.TINT]
	}

	fn := typecheck.LookupRuntime(fnname, hmapType, t.Key(), t.Elem())
	return mkcall1(fn, n.Type(), init, reflectdata.MakeMapRType(base.Pos, n), typecheck.Conv(hint, argtype), h)
}

// walkMakeSlice walks an OMAKESLICE node.
func walkMakeSlice(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	l := n.Len
	r := n.Cap
	if r == nil {
		r = safeExpr(l, init)
		l = r
	}
	t := n.Type()
	if t.Elem().NotInHeap() {
		base.Errorf("%v can't be allocated in Go; it is incomplete (or unallocatable)", t.Elem())
	}
	if n.Esc() == ir.EscNone {
		if why := escape.HeapAllocReason(n); why != "" {
			base.Fatalf("%v has EscNone, but %v", n, why)
		}
		// var arr [r]T
		// n = arr[:l]
		i := typecheck.IndexConst(r)

		// cap is constrained to [0,2^31) or [0,2^63) depending on whether
		// we're in 32-bit or 64-bit systems. So it's safe to do:
		//
		// if uint64(len) > cap {
		//     if len < 0 { panicmakeslicelen() }
		//     panicmakeslicecap()
		// }
		nif := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OGT, typecheck.Conv(l, types.Types[types.TUINT64]), ir.NewInt(base.Pos, i)), nil, nil)
		niflen := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OLT, l, ir.NewInt(base.Pos, 0)), nil, nil)
		niflen.Body = []ir.Node{mkcall("panicmakeslicelen", nil, init)}
		nif.Body.Append(niflen, mkcall("panicmakeslicecap", nil, init))
		init.Append(typecheck.Stmt(nif))

		t = types.NewArray(t.Elem(), i) // [r]T
		var_ := typecheck.TempAt(base.Pos, ir.CurFunc, t)
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, var_, nil))  // zero temp
		r := ir.NewSliceExpr(base.Pos, ir.OSLICE, var_, nil, l, nil) // arr[:l]
		// The conv is necessary in case n.Type is named.
		return walkExpr(typecheck.Expr(typecheck.Conv(r, n.Type())), init)
	}

	// n escapes; set up a call to makeslice.
	// When len and cap can fit into int, use makeslice instead of
	// makeslice64, which is faster and shorter on 32 bit platforms.

	len, cap := l, r

	fnname := "makeslice64"
	argtype := types.Types[types.TINT64]

	// Type checking guarantees that TIDEAL len/cap are positive and fit in an int.
	// The case of len or cap overflow when converting TUINT or TUINTPTR to TINT
	// will be handled by the negative range checks in makeslice during runtime.
	if (len.Type().IsKind(types.TIDEAL) || len.Type().Size() <= types.Types[types.TUINT].Size()) &&
		(cap.Type().IsKind(types.TIDEAL) || cap.Type().Size() <= types.Types[types.TUINT].Size()) {
		fnname = "makeslice"
		argtype = types.Types[types.TINT]
	}
	fn := typecheck.LookupRuntime(fnname)
	ptr := mkcall1(fn, types.Types[types.TUNSAFEPTR], init, reflectdata.MakeSliceElemRType(base.Pos, n), typecheck.Conv(len, argtype), typecheck.Conv(cap, argtype))
	ptr.MarkNonNil()
	len = typecheck.Conv(len, types.Types[types.TINT])
	cap = typecheck.Conv(cap, types.Types[types.TINT])
	sh := ir.NewSliceHeaderExpr(base.Pos, t, ptr, len, cap)
	return walkExpr(typecheck.Expr(sh), init)
}

// walkMakeSliceCopy walks an OMAKESLICECOPY node.
func walkMakeSliceCopy(n *ir.MakeExpr, init *ir.Nodes) ir.Node {
	if n.Esc() == ir.EscNone {
		base.Fatalf("OMAKESLICECOPY with EscNone: %v", n)
	}

	t := n.Type()
	if t.Elem().NotInHeap() {
		base.Errorf("%v can't be allocated in Go; it is incomplete (or unallocatable)", t.Elem())
	}

	length := typecheck.Conv(n.Len, types.Types[types.TINT])
	copylen := ir.NewUnaryExpr(base.Pos, ir.OLEN, n.Cap)
	copyptr := ir.NewUnaryExpr(base.Pos, ir.OSPTR, n.Cap)

	if !t.Elem().HasPointers() && n.Bounded() {
		// When len(to)==len(from) and elements have no pointers:
		// replace make+copy with runtime.mallocgc+runtime.memmove.

		// We do not check for overflow of len(to)*elem.Width here
		// since len(from) is an existing checked slice capacity
		// with same elem.Width for the from slice.
		size := ir.NewBinaryExpr(base.Pos, ir.OMUL, typecheck.Conv(length, types.Types[types.TUINTPTR]), typecheck.Conv(ir.NewInt(base.Pos, t.Elem().Size()), types.Types[types.TUINTPTR]))

		// instantiate mallocgc(size uintptr, typ *byte, needszero bool) unsafe.Pointer
		fn := typecheck.LookupRuntime("mallocgc")
		ptr := mkcall1(fn, types.Types[types.TUNSAFEPTR], init, size, typecheck.NodNil(), ir.NewBool(base.Pos, false))
		ptr.MarkNonNil()
		sh := ir.NewSliceHeaderExpr(base.Pos, t, ptr, length, length)

		s := typecheck.TempAt(base.Pos, ir.CurFunc, t)
		r := typecheck.Stmt(ir.NewAssignStmt(base.Pos, s, sh))
		r = walkExpr(r, init)
		init.Append(r)

		// instantiate memmove(to *any, frm *any, size uintptr)
		fn = typecheck.LookupRuntime("memmove", t.Elem(), t.Elem())
		ncopy := mkcall1(fn, nil, init, ir.NewUnaryExpr(base.Pos, ir.OSPTR, s), copyptr, size)
		init.Append(walkExpr(typecheck.Stmt(ncopy), init))

		return s
	}
	// Replace make+copy with runtime.makeslicecopy.
	// instantiate makeslicecopy(typ *byte, tolen int, fromlen int, from unsafe.Pointer) unsafe.Pointer
	fn := typecheck.LookupRuntime("makeslicecopy")
	ptr := mkcall1(fn, types.Types[types.TUNSAFEPTR], init, reflectdata.MakeSliceElemRType(base.Pos, n), length, copylen, typecheck.Conv(copyptr, types.Types[types.TUNSAFEPTR]))
	ptr.MarkNonNil()
	sh := ir.NewSliceHeaderExpr(base.Pos, t, ptr, length, length)
	return walkExpr(typecheck.Expr(sh), init)
}

// walkNew walks an ONEW node.
func walkNew(n *ir.UnaryExpr, init *ir.Nodes) ir.Node {
	t := n.Type().Elem()
	if t.NotInHeap() {
		base.Errorf("%v can't be allocated in Go; it is incomplete (or unallocatable)", n.Type().Elem())
	}
	if n.Esc() == ir.EscNone {
		if t.Size() > ir.MaxImplicitStackVarSize {
			base.Fatalf("large ONEW with EscNone: %v", n)
		}
		return stackTempAddr(init, t)
	}
	types.CalcSize(t)
	n.MarkNonNil()
	return n
}

func walkMinMax(n *ir.CallExpr, init *ir.Nodes) ir.Node {
	init.Append(ir.TakeInit(n)...)
	walkExprList(n.Args, init)
	return n
}

// generate code for print.
func walkPrint(nn *ir.CallExpr, init *ir.Nodes) ir.Node {
	// Hoist all the argument evaluation up before the lock.
	walkExprListCheap(nn.Args, init)

	// For println, add " " between elements and "\n" at the end.
	if nn.Op() == ir.OPRINTLN {
		s := nn.Args
		t := make([]ir.Node, 0, len(s)*2)
		for i, n := range s {
			if i != 0 {
				t = append(t, ir.NewString(base.Pos, " "))
			}
			t = append(t, n)
		}
		t = append(t, ir.NewString(base.Pos, "\n"))
		nn.Args = t
	}

	// Collapse runs of constant strings.
	s := nn.Args
	t := make([]ir.Node, 0, len(s))
	for i := 0; i < len(s); {
		var strs []string
		for i < len(s) && ir.IsConst(s[i], constant.String) {
			strs = append(strs, ir.StringVal(s[i]))
			i++
		}
		if len(strs) > 0 {
			t = append(t, ir.NewString(base.Pos, strings.Join(strs, "")))
		}
		if i < len(s) {
			t = append(t, s[i])
			i++
		}
	}
	nn.Args = t

	calls := []ir.Node{mkcall("printlock", nil, init)}
	for i, n := range nn.Args {
		if n.Op() == ir.OLITERAL {
			if n.Type() == types.UntypedRune {
				n = typecheck.DefaultLit(n, types.RuneType)
			}

			switch n.Val().Kind() {
			case constant.Int:
				n = typecheck.DefaultLit(n, types.Types[types.TINT64])

			case constant.Float:
				n = typecheck.DefaultLit(n, types.Types[types.TFLOAT64])
			}
		}

		if n.Op() != ir.OLITERAL && n.Type() != nil && n.Type().Kind() == types.TIDEAL {
			n = typecheck.DefaultLit(n, types.Types[types.TINT64])
		}
		n = typecheck.DefaultLit(n, nil)
		nn.Args[i] = n
		if n.Type() == nil || n.Type().Kind() == types.TFORW {
			continue
		}

		var on *ir.Name
		switch n.Type().Kind() {
		case types.TINTER:
			if n.Type().IsEmptyInterface() {
				on = typecheck.LookupRuntime("printeface", n.Type())
			} else {
				on = typecheck.LookupRuntime("printiface", n.Type())
			}
		case types.TPTR:
			if n.Type().Elem().NotInHeap() {
				on = typecheck.LookupRuntime("printuintptr")
				n = ir.NewConvExpr(base.Pos, ir.OCONV, nil, n)
				n.SetType(types.Types[types.TUNSAFEPTR])
				n = ir.NewConvExpr(base.Pos, ir.OCONV, nil, n)
				n.SetType(types.Types[types.TUINTPTR])
				break
			}
			fallthrough
		case types.TCHAN, types.TMAP, types.TFUNC, types.TUNSAFEPTR:
			on = typecheck.LookupRuntime("printpointer", n.Type())
		case types.TSLICE:
			on = typecheck.LookupRuntime("printslice", n.Type())
		case types.TUINT, types.TUINT8, types.TUINT16, types.TUINT32, types.TUINT64, types.TUINTPTR:
			if types.RuntimeSymName(n.Type().Sym()) == "hex" {
				on = typecheck.LookupRuntime("printhex")
			} else {
				on = typecheck.LookupRuntime("printuint")
			}
		case types.TINT, types.TINT8, types.TINT16, types.TINT32, types.TINT64:
			on = typecheck.LookupRuntime("printint")
		case types.TFLOAT32, types.TFLOAT64:
			on = typecheck.LookupRuntime("printfloat")
		case types.TCOMPLEX64, types.TCOMPLEX128:
			on = typecheck.LookupRuntime("printcomplex")
		case types.TBOOL:
			on = typecheck.LookupRuntime("printbool")
		case types.TSTRING:
			cs := ""
			if ir.IsConst(n, constant.String) {
				cs = ir.StringVal(n)
			}
			switch cs {
			case " ":
				on = typecheck.LookupRuntime("printsp")
			case "\n":
				on = typecheck.LookupRuntime("printnl")
			default:
				on = typecheck.LookupRuntime("printstring")
			}
		default:
			badtype(ir.OPRINT, n.Type(), nil)
			continue
		}

		r := ir.NewCallExpr(base.Pos, ir.OCALL, on, nil)
		if params := on.Type().Params(); len(params) > 0 {
			t := params[0].Type
			n = typecheck.Conv(n, t)
			r.Args.Append(n)
		}
		calls = append(calls, r)
	}

	calls = append(calls, mkcall("printunlock", nil, init))

	typecheck.Stmts(calls)
	walkExprList(calls, init)

	r := ir.NewBlockStmt(base.Pos, nil)
	r.List = calls
	return walkStmt(typecheck.Stmt(r))
}

// walkRecoverFP walks an ORECOVERFP node.
func walkRecoverFP(nn *ir.CallExpr, init *ir.Nodes) ir.Node {
	return mkcall("gorecover", nn.Type(), init, walkExpr(nn.Args[0], init))
}

// walkUnsafeData walks an OUNSAFESLICEDATA or OUNSAFESTRINGDATA expression.
func walkUnsafeData(n *ir.UnaryExpr, init *ir.Nodes) ir.Node {
	slice := walkExpr(n.X, init)
	res := typecheck.Expr(ir.NewUnaryExpr(n.Pos(), ir.OSPTR, slice))
	res.SetType(n.Type())
	return walkExpr(res, init)
}

func walkUnsafeSlice(n *ir.BinaryExpr, init *ir.Nodes) ir.Node {
	ptr := safeExpr(n.X, init)
	len := safeExpr(n.Y, init)
	sliceType := n.Type()

	lenType := types.Types[types.TINT64]
	unsafePtr := typecheck.Conv(ptr, types.Types[types.TUNSAFEPTR])

	// If checkptr enabled, call runtime.unsafeslicecheckptr to check ptr and len.
	// for simplicity, unsafeslicecheckptr always uses int64.
	// Type checking guarantees that TIDEAL len/cap are positive and fit in an int.
	// The case of len or cap overflow when converting TUINT or TUINTPTR to TINT
	// will be handled by the negative range checks in unsafeslice during runtime.
	if ir.ShouldCheckPtr(ir.CurFunc, 1) {
		fnname := "unsafeslicecheckptr"
		fn := typecheck.LookupRuntime(fnname)
		init.Append(mkcall1(fn, nil, init, reflectdata.UnsafeSliceElemRType(base.Pos, n), unsafePtr, typecheck.Conv(len, lenType)))
	} else {
		// Otherwise, open code unsafe.Slice to prevent runtime call overhead.
		// Keep this code in sync with runtime.unsafeslice{,64}
		if len.Type().IsKind(types.TIDEAL) || len.Type().Size() <= types.Types[types.TUINT].Size() {
			lenType = types.Types[types.TINT]
		} else {
			// len64 := int64(len)
			// if int64(int(len64)) != len64 {
			//     panicunsafeslicelen()
			// }
			len64 := typecheck.Conv(len, lenType)
			nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
			nif.Cond = ir.NewBinaryExpr(base.Pos, ir.ONE, typecheck.Conv(typecheck.Conv(len64, types.Types[types.TINT]), lenType), len64)
			nif.Body.Append(mkcall("panicunsafeslicelen", nil, &nif.Body))
			appendWalkStmt(init, nif)
		}

		// if len < 0 { panicunsafeslicelen() }
		nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, typecheck.Conv(len, lenType), ir.NewInt(base.Pos, 0))
		nif.Body.Append(mkcall("panicunsafeslicelen", nil, &nif.Body))
		appendWalkStmt(init, nif)

		if sliceType.Elem().Size() == 0 {
			// if ptr == nil && len > 0  {
			//      panicunsafesliceptrnil()
			// }
			nifPtr := ir.NewIfStmt(base.Pos, nil, nil, nil)
			isNil := ir.NewBinaryExpr(base.Pos, ir.OEQ, unsafePtr, typecheck.NodNil())
			gtZero := ir.NewBinaryExpr(base.Pos, ir.OGT, typecheck.Conv(len, lenType), ir.NewInt(base.Pos, 0))
			nifPtr.Cond =
				ir.NewLogicalExpr(base.Pos, ir.OANDAND, isNil, gtZero)
			nifPtr.Body.Append(mkcall("panicunsafeslicenilptr", nil, &nifPtr.Body))
			appendWalkStmt(init, nifPtr)

			h := ir.NewSliceHeaderExpr(n.Pos(), sliceType,
				typecheck.Conv(ptr, types.Types[types.TUNSAFEPTR]),
				typecheck.Conv(len, types.Types[types.TINT]),
				typecheck.Conv(len, types.Types[types.TINT]))
			return walkExpr(typecheck.Expr(h), init)
		}

		// mem, overflow := math.mulUintptr(et.size, len)
		mem := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TUINTPTR])
		overflow := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TBOOL])

		decl := types.NewSignature(nil,
			[]*types.Field{
				types.NewField(base.Pos, nil, types.Types[types.TUINTPTR]),
				types.NewField(base.Pos, nil, types.Types[types.TUINTPTR]),
			},
			[]*types.Field{
				types.NewField(base.Pos, nil, types.Types[types.TUINTPTR]),
				types.NewField(base.Pos, nil, types.Types[types.TBOOL]),
			})

		fn := ir.NewFunc(n.Pos(), n.Pos(), math_MulUintptr, decl)

		call := mkcall1(fn.Nname, fn.Type().ResultsTuple(), init, ir.NewInt(base.Pos, sliceType.Elem().Size()), typecheck.Conv(typecheck.Conv(len, lenType), types.Types[types.TUINTPTR]))
		appendWalkStmt(init, ir.NewAssignListStmt(base.Pos, ir.OAS2, []ir.Node{mem, overflow}, []ir.Node{call}))

		// if overflow || mem > -uintptr(ptr) {
		//     if ptr == nil {
		//         panicunsafesliceptrnil()
		//     }
		//     panicunsafeslicelen()
		// }
		nif = ir.NewIfStmt(base.Pos, nil, nil, nil)
		memCond := ir.NewBinaryExpr(base.Pos, ir.OGT, mem, ir.NewUnaryExpr(base.Pos, ir.ONEG, typecheck.Conv(unsafePtr, types.Types[types.TUINTPTR])))
		nif.Cond = ir.NewLogicalExpr(base.Pos, ir.OOROR, overflow, memCond)
		nifPtr := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nifPtr.Cond = ir.NewBinaryExpr(base.Pos, ir.OEQ, unsafePtr, typecheck.NodNil())
		nifPtr.Body.Append(mkcall("panicunsafeslicenilptr", nil, &nifPtr.Body))
		nif.Body.Append(nifPtr, mkcall("panicunsafeslicelen", nil, &nif.Body))
		appendWalkStmt(init, nif)
	}

	h := ir.NewSliceHeaderExpr(n.Pos(), sliceType,
		typecheck.Conv(ptr, types.Types[types.TUNSAFEPTR]),
		typecheck.Conv(len, types.Types[types.TINT]),
		typecheck.Conv(len, types.Types[types.TINT]))
	return walkExpr(typecheck.Expr(h), init)
}

var math_MulUintptr = &types.Sym{Pkg: types.NewPkg("internal/runtime/math", "math"), Name: "MulUintptr"}

func walkUnsafeString(n *ir.BinaryExpr, init *ir.Nodes) ir.Node {
	ptr := safeExpr(n.X, init)
	len := safeExpr(n.Y, init)

	lenType := types.Types[types.TINT64]
	unsafePtr := typecheck.Conv(ptr, types.Types[types.TUNSAFEPTR])

	// If checkptr enabled, call runtime.unsafestringcheckptr to check ptr and len.
	// for simplicity, unsafestringcheckptr always uses int64.
	// Type checking guarantees that TIDEAL len are positive and fit in an int.
	if ir.ShouldCheckPtr(ir.CurFunc, 1) {
		fnname := "unsafestringcheckptr"
		fn := typecheck.LookupRuntime(fnname)
		init.Append(mkcall1(fn, nil, init, unsafePtr, typecheck.Conv(len, lenType)))
	} else {
		// Otherwise, open code unsafe.String to prevent runtime call overhead.
		// Keep this code in sync with runtime.unsafestring{,64}
		if len.Type().IsKind(types.TIDEAL) || len.Type().Size() <= types.Types[types.TUINT].Size() {
			lenType = types.Types[types.TINT]
		} else {
			// len64 := int64(len)
			// if int64(int(len64)) != len64 {
			//     panicunsafestringlen()
			// }
			len64 := typecheck.Conv(len, lenType)
			nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
			nif.Cond = ir.NewBinaryExpr(base.Pos, ir.ONE, typecheck.Conv(typecheck.Conv(len64, types.Types[types.TINT]), lenType), len64)
			nif.Body.Append(mkcall("panicunsafestringlen", nil, &nif.Body))
			appendWalkStmt(init, nif)
		}

		// if len < 0 { panicunsafestringlen() }
		nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, typecheck.Conv(len, lenType), ir.NewInt(base.Pos, 0))
		nif.Body.Append(mkcall("panicunsafestringlen", nil, &nif.Body))
		appendWalkStmt(init, nif)

		// if uintpr(len) > -uintptr(ptr) {
		//    if ptr == nil {
		//       panicunsafestringnilptr()
		//    }
		//    panicunsafeslicelen()
		// }
		nifLen := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nifLen.Cond = ir.NewBinaryExpr(base.Pos, ir.OGT, typecheck.Conv(len, types.Types[types.TUINTPTR]), ir.NewUnaryExpr(base.Pos, ir.ONEG, typecheck.Conv(unsafePtr, types.Types[types.TUINTPTR])))
		nifPtr := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nifPtr.Cond = ir.NewBinaryExpr(base.Pos, ir.OEQ, unsafePtr, typecheck.NodNil())
		nifPtr.Body.Append(mkcall("panicunsafestringnilptr", nil, &nifPtr.Body))
		nifLen.Body.Append(nifPtr, mkcall("panicunsafestringlen", nil, &nifLen.Body))
		appendWalkStmt(init, nifLen)
	}
	h := ir.NewStringHeaderExpr(n.Pos(),
		typecheck.Conv(ptr, types.Types[types.TUNSAFEPTR]),
		typecheck.Conv(len, types.Types[types.TINT]),
	)
	return walkExpr(typecheck.Expr(h), init)
}

func badtype(op ir.Op, tl, tr *types.Type) {
	var s string
	if tl != nil {
		s += fmt.Sprintf("\n\t%v", tl)
	}
	if tr != nil {
		s += fmt.Sprintf("\n\t%v", tr)
	}

	// common mistake: *struct and *interface.
	if tl != nil && tr != nil && tl.IsPtr() && tr.IsPtr() {
		if tl.Elem().IsStruct() && tr.Elem().IsInterface() {
			s += "\n\t(*struct vs *interface)"
		} else if tl.Elem().IsInterface() && tr.Elem().IsStruct() {
			s += "\n\t(*interface vs *struct)"
		}
	}

	base.Errorf("illegal types for operand: %v%s", op, s)
}

func writebarrierfn(name string, l *types.Type, r *types.Type) ir.Node {
	return typecheck.LookupRuntime(name, l, r)
}

// isRuneCount reports whether n is of the form len([]rune(string)).
// These are optimized into a call to runtime.countrunes.
func isRuneCount(n ir.Node) bool {
	return base.Flag.N == 0 && !base.Flag.Cfg.Instrumenting && n.Op() == ir.OLEN && n.(*ir.UnaryExpr).X.Op() == ir.OSTR2RUNES
}

// isByteCount reports whether n is of the form len(string([]byte)).
func isByteCount(n ir.Node) bool {
	return base.Flag.N == 0 && !base.Flag.Cfg.Instrumenting && n.Op() == ir.OLEN &&
		(n.(*ir.UnaryExpr).X.Op() == ir.OBYTES2STR || n.(*ir.UnaryExpr).X.Op() == ir.OBYTES2STRTMP)
}

// isChanLenCap reports whether n is of the form len(c) or cap(c) for a channel c.
// Note that this does not check for -n or instrumenting because this
// is a correctness rewrite, not an optimization.
func isChanLenCap(n ir.Node) bool {
	return (n.Op() == ir.OLEN || n.Op() == ir.OCAP) && n.(*ir.UnaryExpr).X.Type().IsChan()
}
```