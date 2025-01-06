Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of the `walkRange` function within the `go/src/cmd/compile/internal/walk/range.go` file. This immediately suggests the function is part of the Go compiler's intermediate representation (IR) processing, specifically dealing with `range` loops.

2. **High-Level Overview:** Read the initial comments. The comment for `walkRange` clearly states its purpose: transforming `ORANGE` (the IR representation of a `range` statement) into simpler forms. It also mentions assignment back to `n` and potential in-place modification. This sets the context.

3. **Identify Key Data Structures:**  Look for the function's input and how it's used. `walkRange` takes `*ir.RangeStmt` as input. This `RangeStmt` structure likely holds information about the `range` loop (the iterated variable, the key/value variables, the loop body, etc.).

4. **Decomposition by `range` Type:** The code uses a `switch` statement based on the *kind* of the iterated expression (`t.Kind()`). This is the most crucial observation. It means the `walkRange` function handles different types of `range` loops in specific ways. List out these cases:
    * Integer ranges (`types.IsInt[k]`)
    * Arrays, slices, and pointers to arrays (`k == types.TARRAY, k == types.TSLICE, k == types.TPTR`)
    * Maps (`k == types.TMAP`)
    * Channels (`k == types.TCHAN`)
    * Strings (`k == types.TSTRING`)

5. **Analyze Each Case Individually:** For each `case`, try to understand the transformation being applied. Look for:
    * **Temporary Variables:**  The code frequently creates temporary variables (using `typecheck.TempAt`). These are usually prefixed with `hv` (hidden value), `ha` (hidden aggregate), etc. This is a strong indicator of compiler optimizations and internal representation.
    * **Loop Structure Modification:** How is the `ir.ForStmt` being constructed?  What are the initializations (`init`), conditions (`Cond`), and post-statements (`Post`)?
    * **Body Construction:** How is the loop body being generated? Are there calls to runtime functions? Are there assignments to the key and value variables?
    * **Runtime Function Calls:** Identify calls to functions like `mapiterinit`, `mapiternext`, `decoderune`, `memclrNoHeapPointers`, `memclrHasPointers`. These provide clues about the underlying implementation.

6. **Focus on Examples and Reasoning:** After understanding the individual cases, try to connect the code to actual Go `range` loop syntax. For each case, construct a simple Go example that the code is likely designed to handle.

    * **Integer Range:** Easy case, standard `for i := 0; i < n; i++`.
    * **Array/Slice:**  Pay attention to the different ways key-value pairs are assigned (direct indexing vs. pointer manipulation for efficiency). The "unsafe pointer" logic is a detail that requires careful explanation.
    * **Map:** The use of `mapiterinit` and `mapiternext` clearly points to the internal map iteration mechanism.
    * **Channel:**  The `recv` operation (`<-`) and the boolean to check for channel closure are key.
    * **String:** The handling of UTF-8 encoding using `decoderune` is a crucial aspect.

7. **Identify Helper Functions:**  Note the presence of functions like `rangeAssign`, `rangeAssign2`, `rangeConvert`, `isMapClear`, `mapRangeClear`, `arrayRangeClear`, `arrayClear`. Understand their specific roles in the transformations. For example, `rangeAssign` handles the assignment to the key or value variable, potentially with type conversions.

8. **Address Specific Questions:** Go back to the original request and answer each point systematically:
    * **Functionality Listing:** Summarize the transformations performed for each `range` type.
    * **Go Language Feature:** Clearly state that it implements the `range` keyword.
    * **Go Code Examples:** Provide the concrete examples constructed earlier, showing the input and (conceptually) the output (simplified loop).
    * **Code Reasoning:** Explain the logic behind each transformation, focusing on the temporary variables and runtime calls.
    * **Command-Line Parameters:** Scan the code for usage of `base.Flag`. If found, explain the relevant flags. If not, state that no specific command-line parameters are handled in this snippet.
    * **Common Mistakes:** Look for potential pitfalls. The `isMapClear` function provides a good example – the specific pattern of a `range` loop with a `delete` call.

9. **Review and Refine:** Read through the entire explanation. Ensure clarity, accuracy, and completeness. Are the examples easy to understand? Is the reasoning clear?  Is the explanation structured logically?

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about iterating."  **Correction:** Realized the different cases in the `switch` statement imply different optimization strategies for each type.
* **Struggling with pointer logic for arrays/slices:** **Correction:** Focused on the comments explaining `hp` and `hu` to understand the intent of avoiding out-of-bounds pointers during GC.
* **Overlooking helper functions:** **Correction:**  Went back and analyzed the roles of `rangeAssign`, etc., to understand how the individual pieces fit together.
* **Not providing concrete examples:** **Correction:**  Recognized the need for illustrative Go code to make the explanations tangible.

By following this structured approach of decomposition, analysis, example construction, and refinement, a comprehensive understanding of the code's functionality can be achieved.
这段 `go/src/cmd/compile/internal/walk/range.go` 文件中的代码是 Go 编译器中 **`range` 循环** 的实现的一部分。它的主要功能是将各种形式的 `range` 语句转换为更底层的、更简单的 `for` 循环结构，以便后续的编译阶段可以更容易地处理。

下面我们分功能点详细列举一下：

**主要功能：转换 `range` 循环**

`walkRange` 函数是这个文件的核心，它的目标是将 `ir.RangeStmt` 类型的 `range` 语句节点转换成 `ir.ForStmt` 类型的 `for` 循环节点。

**针对不同类型的数据结构进行不同的转换**

`walkRange` 函数内部通过 `switch` 语句针对不同类型的数据结构（例如数组、切片、map、channel、字符串）实现了不同的转换逻辑：

1. **整数范围 (Integer Ranges):**  形如 `for i := range n { ... }`
   - 创建一个临时的索引变量 `hv1` 和一个临时的长度变量 `hn`。
   - 初始化 `hv1` 为 0，`hn` 为 `n` 的值。
   - 设置 `for` 循环的条件为 `hv1 < hn`。
   - 设置 `for` 循环的后置语句为 `hv1++`。
   - 如果 `range` 循环有索引变量 (`v1`)，则在循环体中添加赋值语句 `v1 = hv1`。

   ```go
   // 假设输入 nrange 代表 for i := range 10 {}
   // 输入: nrange.X 是一个表示常量 10 的 ir.Node

   // 输出 (伪代码):
   // hv1 := 0
   // hn := 10
   // for hv1 < hn {
   //   i = hv1
   //   hv1++
   // }
   ```

2. **数组、切片、指向数组的指针 (Arrays, Slices, Pointers to Arrays):** 形如 `for i, v := range arr/slice { ... }` 或 `for i := range arr/slice { ... }` 或 `for _ = range arr/slice { ... }`
   - 如果是特定的清空数组/切片的模式（后面会详细介绍 `arrayRangeClear`），则调用 `arrayRangeClear` 进行优化。
   - 创建临时的索引变量 `hv1` 和长度变量 `hn`。
   - 初始化 `hv1` 为 0，`hn` 为数组/切片的长度。
   - 设置 `for` 循环的条件为 `hv1 < hn`。
   - 设置 `for` 循环的后置语句为 `hv1++`。
   - 如果有索引变量 (`v1`)，则赋值 `v1 = hv1`。
   - 如果有值变量 (`v2`)，并且元素类型大小可以快速计算索引，则直接通过索引访问元素 `v2 = ha[hv1]`。
   - 否则，对于切片，直接使用切片 `ha` 进行迭代。对于数组指针，先获取数组的地址，然后创建一个新的切片进行迭代。
   - 为了优化，代码中使用了 `unsafe.Pointer` 来直接操作内存，避免额外的边界检查和提高效率。这部分比较复杂，涉及到 `hp`（指向当前元素的指针）和 `hu`（`uintptr` 版本的指针）的交替使用，以处理 GC 安全点的问题。

   ```go
   // 假设输入 nrange 代表 for i, v := range []int{1, 2, 3} {}
   // 输入: nrange.X 是一个表示 []int{1, 2, 3} 的 ir.Node

   // 输出 (简化后的伪代码):
   // ha := []int{1, 2, 3} // 可能会有拷贝
   // hv1 := 0
   // hn := len(ha)
   // for hv1 < hn {
   //   i = hv1
   //   v = ha[hv1]
   //   hv1++
   // }
   ```

3. **Map (Maps):** 形如 `for k, v := range m { ... }` 或 `for k := range m { ... }`
   - 调用运行时函数 `mapiterinit` 初始化 map 的迭代器。
   - `for` 循环的条件是检查迭代器是否还有下一个元素。
   - `for` 循环的后置语句是调用运行时函数 `mapiternext` 移动到下一个元素。
   - 从迭代器中获取键和值，并赋值给 `range` 循环的变量。

   ```go
   // 假设输入 nrange 代表 for k, v := range map[string]int{"a": 1, "b": 2} {}
   // 输入: nrange.X 是一个表示 map[string]int{"a": 1, "b": 2} 的 ir.Node

   // 输出 (伪代码):
   // ha := map[string]int{"a": 1, "b": 2} // 可能会有拷贝
   // hit := new(map_iteration_struct) // 预分配的迭代器
   // runtime.mapiterinit(typeOf(ha), ha, &hit)
   // for hit.key != nil { // 假设迭代器结构中有 key 字段
   //   k = *hit.key
   //   v = *hit.elem
   //   runtime.mapiternext(&hit)
   // }
   ```

4. **Channel (Channels):** 形如 `for v := range ch { ... }` 或 `for v, ok := range ch { ... }`
   - 创建一个临时的接收变量 `hv1` 和一个表示接收是否成功的布尔变量 `hb`。
   - `for` 循环的条件是通过接收操作 `hv1, hb = <-ha` 来判断 channel 是否关闭。
   - 如果有值变量 (`v1`)，则赋值 `v1 = hv1`。

   ```go
   // 假设输入 nrange 代表 for v := range ch {}，其中 ch 是一个 channel
   // 输入: nrange.X 是一个表示 channel ch 的 ir.Node

   // 输出 (伪代码):
   // ha := ch // 可能会有拷贝
   // hv1 := new(TypeOfChannelElement)
   // hb := new(bool)
   // for hv1, hb = <-ha; hb == true; {
   //   v = hv1
   // }
   ```

5. **字符串 (Strings):** 形如 `for i, r := range s { ... }` 或 `for i := range s { ... }`
   - 创建临时的索引变量 `hv1` 和 rune 变量 `hv2`。
   - 循环遍历字符串的字节。
   - 如果当前字节是 ASCII 字符，则索引递增 1。
   - 否则，调用运行时函数 `decoderune` 解码 UTF-8 字符，并更新索引。
   - 将当前的字节索引或 rune 赋值给 `range` 循环的变量。

   ```go
   // 假设输入 nrange 代表 for i, r := range "你好" {}
   // 输入: nrange.X 是一个表示字符串 "你好" 的 ir.Node

   // 输出 (伪代码):
   // ha := "你好" // 可能会有拷贝
   // hv1 := 0
   // for hv1 < len(ha) {
   //   hv1t := hv1
   //   hv2 := rune(ha[hv1])
   //   if hv2 < utf8.RuneSelf {
   //     hv1++
   //   } else {
   //     hv2, hv1 = decoderune(ha, hv1)
   //   }
   //   i = hv1t
   //   r = hv2
   // }
   ```

**辅助功能函数**

- **`cheapComputableIndex(width int64) bool`:**  判断根据索引直接访问数组/切片元素是否高效。这通常取决于目标架构和元素的大小。
- **`rangeAssign(n *ir.RangeStmt, key ir.Node) ir.Node`:**  生成将迭代的键赋值给 `range` 循环键变量的语句，并处理必要的类型转换。
- **`rangeAssign2(n *ir.RangeStmt, key, value ir.Node) ir.Node`:** 生成将迭代的键和值赋值给 `range` 循环键值变量的语句，并处理必要的类型转换。
- **`rangeConvert(nrange *ir.RangeStmt, dst *types.Type, src, typeWord, srcRType ir.Node) ir.Node`:**  处理 `range` 循环中赋值时的类型转换。
- **`isMapClear(n *ir.RangeStmt) bool`:**  识别一种特定的 map 清空模式：`for k := range m { delete(m, k) }`。
- **`mapRangeClear(nrange *ir.RangeStmt) ir.Node`:**  将 `isMapClear` 识别的模式转换为调用运行时函数 `mapclear`，这是一个更高效的清空 map 的方式。
- **`mapClear(m, rtyp ir.Node) ir.Node`:**  生成调用运行时函数 `mapclear` 的语句。
- **`arrayRangeClear(loop *ir.RangeStmt, v1, v2, a ir.Node) ir.Node`:**  识别一种特定的数组/切片清空模式：`for i := range a { a[i] = zero }`。
- **`arrayClear(wbPos src.XPos, a ir.Node, nrange *ir.RangeStmt) ir.Node`:**  将 `arrayRangeClear` 识别的模式转换为调用运行时函数 `memclrNoHeapPointers` 或 `memclrHasPointers`，这是一个更高效的清空数组/切片内存的方式。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `range` 循环语法的实现细节，负责将高级的 `range` 语法转换为底层的循环结构。

**代码推理示例**

假设我们有以下 Go 代码：

```go
package main

func main() {
	numbers := []int{10, 20, 30}
	for index, value := range numbers {
		println(index, value)
	}
}
```

`walkRange` 函数在编译这个 `range` 循环时，可能会进行如下转换（简化后的概念性表示）：

**假设的输入：**  `nrange` 是一个 `ir.RangeStmt` 节点，其 `nrange.X` 代表 `numbers`，`nrange.Key` 代表 `index`，`nrange.Value` 代表 `value`。

**推理过程：**

1. `walkRange` 函数接收到 `nrange`。
2. 判断 `nrange.X` 的类型是切片 (`types.TSLICE`)。
3. 创建临时变量 `hv1` (用于索引) 和 `hn` (用于长度)。
4. 生成初始化语句：`hv1 = 0`, `hn = len(numbers)`。
5. 生成 `for` 循环条件：`hv1 < hn`。
6. 生成 `for` 循环后置语句：`hv1++`。
7. 生成循环体内的赋值语句：`index = hv1`, `value = numbers[hv1]`。

**假设的输出 (转换为更底层的 `for` 循环结构):**

```go
// numbers := []int{10, 20, 30}  // 原始代码

// 经过 walkRange 转换后的概念性代码
{
	ha := numbers // 可能会有拷贝
	hv1 := 0
	hn := len(ha)
	for hv1 < hn {
		index = hv1
		value = ha[hv1]
		println(index, value) // 原始循环体
		hv1++
	}
}
```

**命令行参数的具体处理**

这段代码本身没有直接处理命令行参数。但是，它使用了 `internal/buildcfg` 和 `cmd/compile/internal/base` 包，这些包可能会受到编译器的命令行参数的影响。例如， `-N` 参数（禁用优化）和 `-gcflags` 等可能会影响到这里的代码生成和优化行为。  `base.Flag.N != 0` 就是一个判断是否禁用了优化的标志。

**使用者易犯错的点**

这段代码是编译器内部的实现，普通 Go 开发者不会直接接触到。因此，不存在使用者易犯错的点。  但是，理解这段代码有助于理解 `range` 循环的底层工作原理，这可以帮助开发者更好地理解 Go 的性能特性。

**总结**

`go/src/cmd/compile/internal/walk/range.go` 中的 `walkRange` 函数是 Go 编译器中 `range` 循环实现的关键部分，它负责将高级的 `range` 语法转换为更底层的 `for` 循环结构，并针对不同的数据类型进行了优化处理，例如 map 的迭代器、字符串的 UTF-8 解码以及数组/切片的快速清空。这使得编译器能够更好地理解和优化 `range` 循环，从而提高 Go 程序的性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/walk/range.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package walk

import (
	"internal/buildcfg"
	"unicode/utf8"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"cmd/internal/sys"
)

func cheapComputableIndex(width int64) bool {
	switch ssagen.Arch.LinkArch.Family {
	// MIPS does not have R+R addressing
	// Arm64 may lack ability to generate this code in our assembler,
	// but the architecture supports it.
	case sys.PPC64, sys.S390X:
		return width == 1
	case sys.AMD64, sys.I386, sys.ARM64, sys.ARM:
		switch width {
		case 1, 2, 4, 8:
			return true
		}
	}
	return false
}

// walkRange transforms various forms of ORANGE into
// simpler forms.  The result must be assigned back to n.
// Node n may also be modified in place, and may also be
// the returned node.
func walkRange(nrange *ir.RangeStmt) ir.Node {
	base.Assert(!nrange.DistinctVars) // Should all be rewritten before escape analysis
	if isMapClear(nrange) {
		return mapRangeClear(nrange)
	}

	nfor := ir.NewForStmt(nrange.Pos(), nil, nil, nil, nil, nrange.DistinctVars)
	nfor.SetInit(nrange.Init())
	nfor.Label = nrange.Label

	// variable name conventions:
	//	ohv1, hv1, hv2: hidden (old) val 1, 2
	//	ha, hit: hidden aggregate, iterator
	//	hn, hp: hidden len, pointer
	//	hb: hidden bool
	//	a, v1, v2: not hidden aggregate, val 1, 2

	a := nrange.X
	t := a.Type()
	lno := ir.SetPos(a)

	v1, v2 := nrange.Key, nrange.Value

	if ir.IsBlank(v2) {
		v2 = nil
	}

	if ir.IsBlank(v1) && v2 == nil {
		v1 = nil
	}

	if v1 == nil && v2 != nil {
		base.Fatalf("walkRange: v2 != nil while v1 == nil")
	}

	var body []ir.Node
	var init []ir.Node
	switch k := t.Kind(); {
	default:
		base.Fatalf("walkRange")

	case types.IsInt[k]:
		hv1 := typecheck.TempAt(base.Pos, ir.CurFunc, t)
		hn := typecheck.TempAt(base.Pos, ir.CurFunc, t)

		init = append(init, ir.NewAssignStmt(base.Pos, hv1, nil))
		init = append(init, ir.NewAssignStmt(base.Pos, hn, a))

		nfor.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, hv1, hn)
		nfor.Post = ir.NewAssignStmt(base.Pos, hv1, ir.NewBinaryExpr(base.Pos, ir.OADD, hv1, ir.NewInt(base.Pos, 1)))

		if v1 != nil {
			body = []ir.Node{rangeAssign(nrange, hv1)}
		}

	case k == types.TARRAY, k == types.TSLICE, k == types.TPTR: // TPTR is pointer-to-array
		if nn := arrayRangeClear(nrange, v1, v2, a); nn != nil {
			base.Pos = lno
			return nn
		}

		// Element type of the iteration
		var elem *types.Type
		switch t.Kind() {
		case types.TSLICE, types.TARRAY:
			elem = t.Elem()
		case types.TPTR:
			elem = t.Elem().Elem()
		}

		// order.stmt arranged for a copy of the array/slice variable if needed.
		ha := a

		hv1 := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
		hn := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])

		init = append(init, ir.NewAssignStmt(base.Pos, hv1, nil))
		init = append(init, ir.NewAssignStmt(base.Pos, hn, ir.NewUnaryExpr(base.Pos, ir.OLEN, ha)))

		nfor.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, hv1, hn)
		nfor.Post = ir.NewAssignStmt(base.Pos, hv1, ir.NewBinaryExpr(base.Pos, ir.OADD, hv1, ir.NewInt(base.Pos, 1)))

		// for range ha { body }
		if v1 == nil {
			break
		}

		// for v1 := range ha { body }
		if v2 == nil {
			body = []ir.Node{rangeAssign(nrange, hv1)}
			break
		}

		// for v1, v2 := range ha { body }
		if cheapComputableIndex(elem.Size()) {
			// v1, v2 = hv1, ha[hv1]
			tmp := ir.NewIndexExpr(base.Pos, ha, hv1)
			tmp.SetBounded(true)
			body = []ir.Node{rangeAssign2(nrange, hv1, tmp)}
			break
		}

		// Slice to iterate over
		var hs ir.Node
		if t.IsSlice() {
			hs = ha
		} else {
			var arr ir.Node
			if t.IsPtr() {
				arr = ha
			} else {
				arr = typecheck.NodAddr(ha)
				arr.SetType(t.PtrTo())
				arr.SetTypecheck(1)
			}
			hs = ir.NewSliceExpr(base.Pos, ir.OSLICEARR, arr, nil, nil, nil)
			// old typechecker doesn't know OSLICEARR, so we set types explicitly
			hs.SetType(types.NewSlice(elem))
			hs.SetTypecheck(1)
		}

		// We use a "pointer" to keep track of where we are in the backing array
		// of the slice hs. This pointer starts at hs.ptr and gets incremented
		// by the element size each time through the loop.
		//
		// It's tricky, though, as on the last iteration this pointer gets
		// incremented to point past the end of the backing array. We can't
		// let the garbage collector see that final out-of-bounds pointer.
		//
		// To avoid this, we keep the "pointer" alternately in 2 variables, one
		// pointer typed and one uintptr typed. Most of the time it lives in the
		// regular pointer variable, but when it might be out of bounds (after it
		// has been incremented, but before the loop condition has been checked)
		// it lives briefly in the uintptr variable.
		//
		// hp contains the pointer version (of type *T, where T is the element type).
		// It is guaranteed to always be in range, keeps the backing store alive,
		// and is updated on stack copies. If a GC occurs when this function is
		// suspended at any safepoint, this variable ensures correct operation.
		//
		// hu contains the equivalent uintptr version. It may point past the
		// end, but doesn't keep the backing store alive and doesn't get updated
		// on a stack copy. If a GC occurs while this function is on the top of
		// the stack, then the last frame is scanned conservatively and hu will
		// act as a reference to the backing array to ensure it is not collected.
		//
		// The "pointer" we're moving across the backing array lives in one
		// or the other of hp and hu as the loop proceeds.
		//
		// hp is live during most of the body of the loop. But it isn't live
		// at the very top of the loop, when we haven't checked i<n yet, and
		// it could point off the end of the backing store.
		// hu is live only at the very top and very bottom of the loop.
		// In particular, only when it cannot possibly be live across a call.
		//
		// So we do
		//   hu = uintptr(unsafe.Pointer(hs.ptr))
		//   for i := 0; i < hs.len; i++ {
		//     hp = (*T)(unsafe.Pointer(hu))
		//     v1, v2 = i, *hp
		//     ... body of loop ...
		//     hu = uintptr(unsafe.Pointer(hp)) + elemsize
		//   }
		//
		// Between the assignments to hu and the assignment back to hp, there
		// must not be any calls.

		// Pointer to current iteration position. Start on entry to the loop
		// with the pointer in hu.
		ptr := ir.NewUnaryExpr(base.Pos, ir.OSPTR, hs)
		ptr.SetBounded(true)
		huVal := ir.NewConvExpr(base.Pos, ir.OCONVNOP, types.Types[types.TUNSAFEPTR], ptr)
		huVal = ir.NewConvExpr(base.Pos, ir.OCONVNOP, types.Types[types.TUINTPTR], huVal)
		hu := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TUINTPTR])
		init = append(init, ir.NewAssignStmt(base.Pos, hu, huVal))

		// Convert hu to hp at the top of the loop (after the condition has been checked).
		hpVal := ir.NewConvExpr(base.Pos, ir.OCONVNOP, types.Types[types.TUNSAFEPTR], hu)
		hpVal.SetCheckPtr(true) // disable checkptr on this conversion
		hpVal = ir.NewConvExpr(base.Pos, ir.OCONVNOP, elem.PtrTo(), hpVal)
		hp := typecheck.TempAt(base.Pos, ir.CurFunc, elem.PtrTo())
		body = append(body, ir.NewAssignStmt(base.Pos, hp, hpVal))

		// Assign variables on the LHS of the range statement. Use *hp to get the element.
		e := ir.NewStarExpr(base.Pos, hp)
		e.SetBounded(true)
		a := rangeAssign2(nrange, hv1, e)
		body = append(body, a)

		// Advance pointer for next iteration of the loop.
		// This reads from hp and writes to hu.
		huVal = ir.NewConvExpr(base.Pos, ir.OCONVNOP, types.Types[types.TUNSAFEPTR], hp)
		huVal = ir.NewConvExpr(base.Pos, ir.OCONVNOP, types.Types[types.TUINTPTR], huVal)
		as := ir.NewAssignStmt(base.Pos, hu, ir.NewBinaryExpr(base.Pos, ir.OADD, huVal, ir.NewInt(base.Pos, elem.Size())))
		nfor.Post = ir.NewBlockStmt(base.Pos, []ir.Node{nfor.Post, as})

	case k == types.TMAP:
		// order.stmt allocated the iterator for us.
		// we only use a once, so no copy needed.
		ha := a

		hit := nrange.Prealloc
		th := hit.Type()
		// depends on layout of iterator struct.
		// See cmd/compile/internal/reflectdata/reflect.go:MapIterType
		var keysym, elemsym *types.Sym
		if buildcfg.Experiment.SwissMap {
			keysym = th.Field(0).Sym
			elemsym = th.Field(1).Sym // ditto
		} else {
			keysym = th.Field(0).Sym
			elemsym = th.Field(1).Sym // ditto
		}

		fn := typecheck.LookupRuntime("mapiterinit", t.Key(), t.Elem(), th)
		init = append(init, mkcallstmt1(fn, reflectdata.RangeMapRType(base.Pos, nrange), ha, typecheck.NodAddr(hit)))
		nfor.Cond = ir.NewBinaryExpr(base.Pos, ir.ONE, ir.NewSelectorExpr(base.Pos, ir.ODOT, hit, keysym), typecheck.NodNil())

		fn = typecheck.LookupRuntime("mapiternext", th)
		nfor.Post = mkcallstmt1(fn, typecheck.NodAddr(hit))

		key := ir.NewStarExpr(base.Pos, typecheck.ConvNop(ir.NewSelectorExpr(base.Pos, ir.ODOT, hit, keysym), types.NewPtr(t.Key())))
		if v1 == nil {
			body = nil
		} else if v2 == nil {
			body = []ir.Node{rangeAssign(nrange, key)}
		} else {
			elem := ir.NewStarExpr(base.Pos, typecheck.ConvNop(ir.NewSelectorExpr(base.Pos, ir.ODOT, hit, elemsym), types.NewPtr(t.Elem())))
			body = []ir.Node{rangeAssign2(nrange, key, elem)}
		}

	case k == types.TCHAN:
		// order.stmt arranged for a copy of the channel variable.
		ha := a

		hv1 := typecheck.TempAt(base.Pos, ir.CurFunc, t.Elem())
		hv1.SetTypecheck(1)
		if t.Elem().HasPointers() {
			init = append(init, ir.NewAssignStmt(base.Pos, hv1, nil))
		}
		hb := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TBOOL])

		nfor.Cond = ir.NewBinaryExpr(base.Pos, ir.ONE, hb, ir.NewBool(base.Pos, false))
		lhs := []ir.Node{hv1, hb}
		rhs := []ir.Node{ir.NewUnaryExpr(base.Pos, ir.ORECV, ha)}
		a := ir.NewAssignListStmt(base.Pos, ir.OAS2RECV, lhs, rhs)
		a.SetTypecheck(1)
		nfor.Cond = ir.InitExpr([]ir.Node{a}, nfor.Cond)
		if v1 == nil {
			body = nil
		} else {
			body = []ir.Node{rangeAssign(nrange, hv1)}
		}
		// Zero hv1. This prevents hv1 from being the sole, inaccessible
		// reference to an otherwise GC-able value during the next channel receive.
		// See issue 15281.
		body = append(body, ir.NewAssignStmt(base.Pos, hv1, nil))

	case k == types.TSTRING:
		// Transform string range statements like "for v1, v2 = range a" into
		//
		// ha := a
		// for hv1 := 0; hv1 < len(ha); {
		//   hv1t := hv1
		//   hv2 := rune(ha[hv1])
		//   if hv2 < utf8.RuneSelf {
		//      hv1++
		//   } else {
		//      hv2, hv1 = decoderune(ha, hv1)
		//   }
		//   v1, v2 = hv1t, hv2
		//   // original body
		// }

		// order.stmt arranged for a copy of the string variable.
		ha := a

		hv1 := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
		hv1t := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
		hv2 := typecheck.TempAt(base.Pos, ir.CurFunc, types.RuneType)

		// hv1 := 0
		init = append(init, ir.NewAssignStmt(base.Pos, hv1, nil))

		// hv1 < len(ha)
		nfor.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, hv1, ir.NewUnaryExpr(base.Pos, ir.OLEN, ha))

		if v1 != nil {
			// hv1t = hv1
			body = append(body, ir.NewAssignStmt(base.Pos, hv1t, hv1))
		}

		// hv2 := rune(ha[hv1])
		nind := ir.NewIndexExpr(base.Pos, ha, hv1)
		nind.SetBounded(true)
		body = append(body, ir.NewAssignStmt(base.Pos, hv2, typecheck.Conv(nind, types.RuneType)))

		// if hv2 < utf8.RuneSelf
		nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
		nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OLT, hv2, ir.NewInt(base.Pos, utf8.RuneSelf))

		// hv1++
		nif.Body = []ir.Node{ir.NewAssignStmt(base.Pos, hv1, ir.NewBinaryExpr(base.Pos, ir.OADD, hv1, ir.NewInt(base.Pos, 1)))}

		// } else {
		// hv2, hv1 = decoderune(ha, hv1)
		fn := typecheck.LookupRuntime("decoderune")
		call := mkcall1(fn, fn.Type().ResultsTuple(), &nif.Else, ha, hv1)
		a := ir.NewAssignListStmt(base.Pos, ir.OAS2, []ir.Node{hv2, hv1}, []ir.Node{call})
		nif.Else.Append(a)

		body = append(body, nif)

		if v1 != nil {
			if v2 != nil {
				// v1, v2 = hv1t, hv2
				body = append(body, rangeAssign2(nrange, hv1t, hv2))
			} else {
				// v1 = hv1t
				body = append(body, rangeAssign(nrange, hv1t))
			}
		}
	}

	typecheck.Stmts(init)

	nfor.PtrInit().Append(init...)

	typecheck.Stmts(nfor.Cond.Init())

	nfor.Cond = typecheck.Expr(nfor.Cond)
	nfor.Cond = typecheck.DefaultLit(nfor.Cond, nil)
	nfor.Post = typecheck.Stmt(nfor.Post)
	typecheck.Stmts(body)
	nfor.Body.Append(body...)
	nfor.Body.Append(nrange.Body...)

	var n ir.Node = nfor

	n = walkStmt(n)

	base.Pos = lno
	return n
}

// rangeAssign returns "n.Key = key".
func rangeAssign(n *ir.RangeStmt, key ir.Node) ir.Node {
	key = rangeConvert(n, n.Key.Type(), key, n.KeyTypeWord, n.KeySrcRType)
	return ir.NewAssignStmt(n.Pos(), n.Key, key)
}

// rangeAssign2 returns "n.Key, n.Value = key, value".
func rangeAssign2(n *ir.RangeStmt, key, value ir.Node) ir.Node {
	// Use OAS2 to correctly handle assignments
	// of the form "v1, a[v1] = range".
	key = rangeConvert(n, n.Key.Type(), key, n.KeyTypeWord, n.KeySrcRType)
	value = rangeConvert(n, n.Value.Type(), value, n.ValueTypeWord, n.ValueSrcRType)
	return ir.NewAssignListStmt(n.Pos(), ir.OAS2, []ir.Node{n.Key, n.Value}, []ir.Node{key, value})
}

// rangeConvert returns src, converted to dst if necessary. If a
// conversion is necessary, then typeWord and srcRType are copied to
// their respective ConvExpr fields.
func rangeConvert(nrange *ir.RangeStmt, dst *types.Type, src, typeWord, srcRType ir.Node) ir.Node {
	src = typecheck.Expr(src)
	if dst.Kind() == types.TBLANK || types.Identical(dst, src.Type()) {
		return src
	}

	n := ir.NewConvExpr(nrange.Pos(), ir.OCONV, dst, src)
	n.TypeWord = typeWord
	n.SrcRType = srcRType
	return typecheck.Expr(n)
}

// isMapClear checks if n is of the form:
//
//	for k := range m {
//		delete(m, k)
//	}
//
// where == for keys of map m is reflexive.
func isMapClear(n *ir.RangeStmt) bool {
	if base.Flag.N != 0 || base.Flag.Cfg.Instrumenting {
		return false
	}

	t := n.X.Type()
	if n.Op() != ir.ORANGE || t.Kind() != types.TMAP || n.Key == nil || n.Value != nil {
		return false
	}

	k := n.Key
	// Require k to be a new variable name.
	if !ir.DeclaredBy(k, n) {
		return false
	}

	if len(n.Body) != 1 {
		return false
	}

	stmt := n.Body[0] // only stmt in body
	if stmt == nil || stmt.Op() != ir.ODELETE {
		return false
	}

	m := n.X
	if delete := stmt.(*ir.CallExpr); !ir.SameSafeExpr(delete.Args[0], m) || !ir.SameSafeExpr(delete.Args[1], k) {
		return false
	}

	// Keys where equality is not reflexive can not be deleted from maps.
	if !types.IsReflexive(t.Key()) {
		return false
	}

	return true
}

// mapRangeClear constructs a call to runtime.mapclear for the map range idiom.
func mapRangeClear(nrange *ir.RangeStmt) ir.Node {
	m := nrange.X
	origPos := ir.SetPos(m)
	defer func() { base.Pos = origPos }()

	return mapClear(m, reflectdata.RangeMapRType(base.Pos, nrange))
}

// mapClear constructs a call to runtime.mapclear for the map m.
func mapClear(m, rtyp ir.Node) ir.Node {
	t := m.Type()

	// instantiate mapclear(typ *type, hmap map[any]any)
	fn := typecheck.LookupRuntime("mapclear", t.Key(), t.Elem())
	n := mkcallstmt1(fn, rtyp, m)
	return walkStmt(typecheck.Stmt(n))
}

// Lower n into runtime·memclr if possible, for
// fast zeroing of slices and arrays (issue 5373).
// Look for instances of
//
//	for i := range a {
//		a[i] = zero
//	}
//
// in which the evaluation of a is side-effect-free.
//
// Parameters are as in walkRange: "for v1, v2 = range a".
func arrayRangeClear(loop *ir.RangeStmt, v1, v2, a ir.Node) ir.Node {
	if base.Flag.N != 0 || base.Flag.Cfg.Instrumenting {
		return nil
	}

	if v1 == nil || v2 != nil {
		return nil
	}

	if len(loop.Body) != 1 || loop.Body[0] == nil {
		return nil
	}

	stmt1 := loop.Body[0] // only stmt in body
	if stmt1.Op() != ir.OAS {
		return nil
	}
	stmt := stmt1.(*ir.AssignStmt)
	if stmt.X.Op() != ir.OINDEX {
		return nil
	}
	lhs := stmt.X.(*ir.IndexExpr)
	x := lhs.X
	if a.Type().IsPtr() && a.Type().Elem().IsArray() {
		if s, ok := x.(*ir.StarExpr); ok && s.Op() == ir.ODEREF {
			x = s.X
		}
	}

	if !ir.SameSafeExpr(x, a) || !ir.SameSafeExpr(lhs.Index, v1) {
		return nil
	}

	if !ir.IsZero(stmt.Y) {
		return nil
	}

	return arrayClear(stmt.Pos(), a, loop)
}

// arrayClear constructs a call to runtime.memclr for fast zeroing of slices and arrays.
func arrayClear(wbPos src.XPos, a ir.Node, nrange *ir.RangeStmt) ir.Node {
	elemsize := typecheck.RangeExprType(a.Type()).Elem().Size()
	if elemsize <= 0 {
		return nil
	}

	// Convert to
	// if len(a) != 0 {
	// 	hp = &a[0]
	// 	hn = len(a)*sizeof(elem(a))
	// 	memclr{NoHeap,Has}Pointers(hp, hn)
	// 	i = len(a) - 1
	// }
	n := ir.NewIfStmt(base.Pos, nil, nil, nil)
	n.Cond = ir.NewBinaryExpr(base.Pos, ir.ONE, ir.NewUnaryExpr(base.Pos, ir.OLEN, a), ir.NewInt(base.Pos, 0))

	// hp = &a[0]
	hp := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TUNSAFEPTR])

	ix := ir.NewIndexExpr(base.Pos, a, ir.NewInt(base.Pos, 0))
	ix.SetBounded(true)
	addr := typecheck.ConvNop(typecheck.NodAddr(ix), types.Types[types.TUNSAFEPTR])
	n.Body.Append(ir.NewAssignStmt(base.Pos, hp, addr))

	// hn = len(a) * sizeof(elem(a))
	hn := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TUINTPTR])
	mul := typecheck.Conv(ir.NewBinaryExpr(base.Pos, ir.OMUL, ir.NewUnaryExpr(base.Pos, ir.OLEN, a), ir.NewInt(base.Pos, elemsize)), types.Types[types.TUINTPTR])
	n.Body.Append(ir.NewAssignStmt(base.Pos, hn, mul))

	var fn ir.Node
	if a.Type().Elem().HasPointers() {
		// memclrHasPointers(hp, hn)
		ir.CurFunc.SetWBPos(wbPos)
		fn = mkcallstmt("memclrHasPointers", hp, hn)
	} else {
		// memclrNoHeapPointers(hp, hn)
		fn = mkcallstmt("memclrNoHeapPointers", hp, hn)
	}

	n.Body.Append(fn)

	// For array range clear, also set "i = len(a) - 1"
	if nrange != nil {
		idx := ir.NewAssignStmt(base.Pos, nrange.Key, ir.NewBinaryExpr(base.Pos, ir.OSUB, ir.NewUnaryExpr(base.Pos, ir.OLEN, a), ir.NewInt(base.Pos, 1)))
		n.Body.Append(idx)
	}

	n.Cond = typecheck.Expr(n.Cond)
	n.Cond = typecheck.DefaultLit(n.Cond, nil)
	typecheck.Stmts(n.Body)
	return walkStmt(n)
}

"""



```