Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: What is this file?**

The first line `// Code generated from _gen/dec.rules using 'go generate'; DO NOT EDIT.` immediately tells us this is *generated code*. This is a crucial piece of information. It means we're not looking at manually crafted logic but rather the output of a code generation process. The `DO NOT EDIT` warning reinforces this. This suggests the underlying logic resides in `_gen/dec.rules`.

The package declaration `package ssa` tells us this code belongs to the `ssa` package. Knowing Go's standard library and compiler structure, `ssa` likely refers to Static Single Assignment, an intermediate representation used in the Go compiler.

**2. Examining the `rewriteValuedec` Function:**

This function is the entry point. It takes a `*Value` as input and returns a `bool`. The `switch v.Op` structure strongly suggests this function is dispatching based on the `Op` field of the `Value`. `Op` likely stands for "Operation". The cases list various `Op` constants like `OpArrayMake1`, `OpArraySelect`, etc. This indicates the file is concerned with transforming or simplifying different kinds of operations within the SSA representation.

**3. Analyzing Individual `rewriteValuedec_Op...` Functions:**

Each of these functions handles a specific `Op` type. The pattern is consistent:

* **Input:** A `*Value`.
* **Logic:**  Pattern matching on the structure of the `Value` (its arguments, auxiliary information, and types).
* **Output:** Either:
    * `v.copyOf(someOtherValue)`: Replaces the current `Value` with `someOtherValue`. This suggests a simplification or direct substitution.
    * `v.reset(newOp)` and `v.AddArg(...)`:  Changes the operation of the current `Value` and potentially its arguments. This indicates a transformation of the operation.
    * Returns `true` if a rewrite occurred, `false` otherwise.

**4. Inferring Functionality Based on `Op` Names:**

The `Op` names are quite descriptive:

* `OpArrayMake1`: Creating an array (likely with a single element initially).
* `OpArraySelect`: Accessing an element of an array.
* `OpComplexImag`/`OpComplexReal`:  Extracting the imaginary/real part of a complex number.
* `OpIData`/`OpITab`/`OpIMake`:  Related to interface types (data, type table, making an interface).
* `OpLoad`/`OpStore`:  Memory access (reading and writing).
* `OpSliceCap`/`OpSliceLen`/`OpSlicePtr`/`OpSlicePtrUnchecked`:  Operations on slices (capacity, length, pointer).
* `OpStringLen`/`OpStringPtr`: Operations on strings (length, pointer).
* `OpStructMake`/`OpStructSelect`: Operations on structs (creation, field access).

This list gives a good overview of the language features being handled.

**5. Connecting to Go Language Features:**

By associating the `Op` names with Go language features, we can start to understand what kind of optimizations or transformations are happening:

* **Arrays and Slices:**  Simplifying array/slice creation and access.
* **Complex Numbers:**  Optimizing access to real and imaginary parts, potentially how they are loaded/stored.
* **Interfaces:**  Manipulating the underlying data and type information of interfaces.
* **Memory Access:**  Optimizing how values are loaded from and stored to memory, particularly for complex types.
* **Strings:**  Accessing the underlying data and length of strings.
* **Structs:**  Simplifying struct creation and field access.

**6. Developing Example Code (Trial and Error/Hypothesis):**

Based on the inferred functionality, we can create Go code examples and hypothesize how these rewrite rules might apply. For instance, for `rewriteValuedec_OpArraySelect`:

* **Hypothesis:** Accessing the first element of an array might be simplified if the array's underlying representation is a pointer.
* **Go Code Example:** `arr := [1]int{42}; _ = arr[0]`
* **Expected Rewrite:**  The `ArraySelect` operation could be directly replaced by the underlying pointer to the first element.

Similarly, for `rewriteValuedec_OpLoad` when the type is complex:

* **Hypothesis:** Loading a complex number might be rewritten into separate loads for the real and imaginary parts.
* **Go Code Example:** `var c complex64; _ = c` (accessing the value of `c`).
* **Expected Rewrite:** The `Load` operation could be transformed into two `Load` operations, one for the real part and one for the imaginary part, combined into a `ComplexMake`.

**7. Considering Edge Cases and Potential Errors:**

Looking at the code, we can think about situations where these rewrites might not be immediately obvious or could lead to errors if not handled correctly. For example:

* **Zero-sized arrays/structs:** The `rewriteValuedec_OpStore` function has a special case for zero-sized types.
* **Pointer-shaped types:** Several rewrites have conditions like `x.Type.IsPtrShaped()`. Understanding what constitutes a "pointer-shaped" type is important.

**8. Reviewing and Refining:**

After drafting the explanation and examples, review them for clarity, accuracy, and completeness. Ensure the Go code examples accurately illustrate the hypothesized rewrites.

**Self-Correction Example During the Process:**

Initially, I might have thought that `OpArrayMake1` was about creating an array of size 1. However, looking at the rewrite rule:

```go
func rewriteValuedec_OpArrayMake1(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ArrayMake1 x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		x := v_0
		if !(x.Type.IsPtrShaped()) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
```

This suggests it's more about *coercing* or directly using an existing value `x` if its type is pointer-shaped. This correction leads to a better understanding of the rule's purpose.

By following this iterative process of examination, inference, example creation, and refinement, we can arrive at a comprehensive understanding of the code's functionality.
这个Go语言文件 `rewritedec.go` 是 Go 编译器中 SSA (Static Single Assignment) 中间表示的一个组成部分，它的主要功能是定义了一系列用于**简化和优化** SSA 图中特定操作的**重写规则 (rewrite rules)**。

更具体地说，`rewriteValuedec` 函数及其相关的 `rewriteValuedec_Op...` 函数针对不同的 SSA 操作符 (Opcode)，尝试应用预定义的模式匹配和替换，以达到以下目的：

**主要功能：**

1. **模式匹配和替换 (Pattern Matching and Substitution):**  识别 SSA 图中符合特定模式的节点 (Value) ，并将其替换为更简单或更高效的等价形式。
2. **针对特定操作符的优化:**  每个 `rewriteValuedec_Op...` 函数专门处理一个特定的操作符，例如 `OpArrayMake1`（创建数组）、`OpLoad`（加载内存）等，并应用与该操作符相关的优化。
3. **提高代码生成效率:** 通过在编译早期进行这些简化和优化，可以减少后续编译阶段的工作量，并最终生成更高效的目标代码。

**可以推理出的 Go 语言功能实现：**

通过分析 `rewriteValuedec` 函数中处理的各种 `Op`，我们可以推断出这个文件涉及到以下 Go 语言功能的底层实现和优化：

* **数组 (Arrays):**  `OpArrayMake1`, `OpArraySelect` 涉及到数组的创建和元素访问。
* **切片 (Slices):** `OpSliceCap`, `OpSliceLen`, `OpSlicePtr`, `OpSlicePtrUnchecked` 涉及到切片的容量、长度和指针操作。
* **复数 (Complex Numbers):** `OpComplexImag`, `OpComplexReal`, `OpComplexMake` 涉及到复数的实部、虚部提取和创建。
* **接口 (Interfaces):** `OpIData`, `OpIMake`, `OpITab` 涉及到接口的动态数据、类型信息和创建。
* **指针 (Pointers):** 许多操作都隐含地或显式地涉及指针操作。
* **字符串 (Strings):** `OpStringLen`, `OpStringPtr`, `OpStringMake` 涉及到字符串的长度、指针和创建。
* **结构体 (Structs):** `OpStructMake`, `OpStructSelect` 涉及到结构体的创建和字段访问。
* **内存加载和存储 (Memory Load and Store):** `OpLoad`, `OpStore` 涉及到从内存加载数据和将数据存储到内存。

**Go 代码举例说明：**

让我们以 `rewriteValuedec_OpArraySelect` 为例进行说明，它可以优化数组元素的访问。

```go
// 假设的输入 SSA Value 表示以下 Go 代码：
// arr := [1]int{10}
// x := arr[0]

// 对应的 SSA 图中，arr[0] 的操作可能是 OpArraySelect，其参数可能是指向数组的指针。
// v 是一个 *ssa.Value，其 Op 为 OpArraySelect，AuxInt 为 0 (表示访问索引 0)，Args[0] 是代表数组的 *ssa.Value。

func rewriteValuedec_OpArraySelect(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (ArraySelect [0] x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 { // 检查访问的索引是否为 0
			break
		}
		x := v_0 // 获取代表数组的 Value
		if !(x.Type.IsPtrShaped()) { // 检查数组的类型是否是指针形状的
			break
		}
		v.copyOf(x) // 如果满足条件，则直接用代表数组的 Value 替换当前的 ArraySelect 操作
		return true
	}
	// ... 其他匹配规则 ...
	return false
}
```

**假设的输入与输出：**

**输入 (假设的 SSA 图片段):**

```
b1:
    v1 = InitMem <mem>
    v2 = ArrayMake1 <*[1]int> (ConstNil <*int>)  // 创建一个数组，这里简化了
    v3 = ArraySelect <int> [0] v2             // 访问数组的第一个元素
    ...
```

**输出 (经过 `rewriteValuedec_OpArraySelect` 处理后的 SSA 图片段):**

```
b1:
    v1 = InitMem <mem>
    v2 = ArrayMake1 <*[1]int> (ConstNil <*int>)
    v3 = v2                                    // ArraySelect 操作被直接替换为代表数组的 v2
    ...
```

**推理：**

如果一个数组只有一个元素，并且我们要访问的是索引为 0 的元素，那么 `ArraySelect` 操作实际上可以直接返回指向该数组的指针（如果数组是“指针形状”的，例如数组本身是指针或者其元素是指针）。这样可以避免一次额外的元素访问操作。

**涉及代码推理，带上假设的输入与输出：**

上面已经通过 `rewriteValuedec_OpArraySelect` 的例子进行了说明。

**如果涉及命令行参数的具体处理，请详细介绍一下：**

这个 `rewritedec.go` 文件本身**不直接处理命令行参数**。 它的作用是在 Go 编译器的内部 SSA 优化阶段，通过预定义的规则对 SSA 图进行转换。 命令行参数可能会影响到编译器的其他阶段（例如，选择不同的优化级别），从而间接地影响到 SSA 图的构建和最终的优化结果，但 `rewritedec.go` 的逻辑是独立于命令行参数的。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明：**

由于 `rewritedec.go` 是 Go 编译器内部生成的代码，**最终用户（Go 程序员）不会直接与这个文件交互，也不会直接编写或修改这些重写规则。** 这些规则是由 Go 编译器开发人员定义和维护的。

因此，对于最终用户来说，不存在直接使用 `rewritedec.go` 而导致易犯错的点。 然而，理解 SSA 的概念和编译器的优化过程，可以帮助开发者编写出更高效的 Go 代码，从而更容易被编译器优化。

**总结：**

`rewritedec.go` 是 Go 编译器中 SSA 优化阶段的关键组成部分，它通过应用一系列预定义的重写规则，针对不同的 SSA 操作符进行简化和优化，从而提高最终生成代码的效率。 它处理了 Go 语言中多种核心数据结构和操作的底层表示和优化。 最终用户虽然不会直接使用这个文件，但编译器的优化工作对他们编写的 Go 代码的性能至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewritedec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Code generated from _gen/dec.rules using 'go generate'; DO NOT EDIT.

package ssa

import "cmd/compile/internal/types"

func rewriteValuedec(v *Value) bool {
	switch v.Op {
	case OpArrayMake1:
		return rewriteValuedec_OpArrayMake1(v)
	case OpArraySelect:
		return rewriteValuedec_OpArraySelect(v)
	case OpComplexImag:
		return rewriteValuedec_OpComplexImag(v)
	case OpComplexReal:
		return rewriteValuedec_OpComplexReal(v)
	case OpIData:
		return rewriteValuedec_OpIData(v)
	case OpIMake:
		return rewriteValuedec_OpIMake(v)
	case OpITab:
		return rewriteValuedec_OpITab(v)
	case OpLoad:
		return rewriteValuedec_OpLoad(v)
	case OpSliceCap:
		return rewriteValuedec_OpSliceCap(v)
	case OpSliceLen:
		return rewriteValuedec_OpSliceLen(v)
	case OpSlicePtr:
		return rewriteValuedec_OpSlicePtr(v)
	case OpSlicePtrUnchecked:
		return rewriteValuedec_OpSlicePtrUnchecked(v)
	case OpStore:
		return rewriteValuedec_OpStore(v)
	case OpStringLen:
		return rewriteValuedec_OpStringLen(v)
	case OpStringPtr:
		return rewriteValuedec_OpStringPtr(v)
	case OpStructMake:
		return rewriteValuedec_OpStructMake(v)
	case OpStructSelect:
		return rewriteValuedec_OpStructSelect(v)
	}
	return false
}
func rewriteValuedec_OpArrayMake1(v *Value) bool {
	v_0 := v.Args[0]
	// match: (ArrayMake1 x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		x := v_0
		if !(x.Type.IsPtrShaped()) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuedec_OpArraySelect(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (ArraySelect [0] x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		if !(x.Type.IsPtrShaped()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (ArraySelect (ArrayMake1 x))
	// result: x
	for {
		if v_0.Op != OpArrayMake1 {
			break
		}
		x := v_0.Args[0]
		v.copyOf(x)
		return true
	}
	// match: (ArraySelect [0] (IData x))
	// result: (IData x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpIData {
			break
		}
		x := v_0.Args[0]
		v.reset(OpIData)
		v.AddArg(x)
		return true
	}
	// match: (ArraySelect [i] x:(Load <t> ptr mem))
	// result: @x.Block (Load <v.Type> (OffPtr <v.Type.PtrTo()> [t.Elem().Size()*i] ptr) mem)
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, v.Type)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, v.Type.PtrTo())
		v1.AuxInt = int64ToAuxInt(t.Elem().Size() * i)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpComplexImag(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ComplexImag (ComplexMake _ imag ))
	// result: imag
	for {
		if v_0.Op != OpComplexMake {
			break
		}
		imag := v_0.Args[1]
		v.copyOf(imag)
		return true
	}
	// match: (ComplexImag x:(Load <t> ptr mem))
	// cond: t.IsComplex() && t.Size() == 8
	// result: @x.Block (Load <typ.Float32> (OffPtr <typ.Float32Ptr> [4] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsComplex() && t.Size() == 8) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float32)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.Float32Ptr)
		v1.AuxInt = int64ToAuxInt(4)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	// match: (ComplexImag x:(Load <t> ptr mem))
	// cond: t.IsComplex() && t.Size() == 16
	// result: @x.Block (Load <typ.Float64> (OffPtr <typ.Float64Ptr> [8] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsComplex() && t.Size() == 16) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float64)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.Float64Ptr)
		v1.AuxInt = int64ToAuxInt(8)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpComplexReal(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ComplexReal (ComplexMake real _ ))
	// result: real
	for {
		if v_0.Op != OpComplexMake {
			break
		}
		real := v_0.Args[0]
		v.copyOf(real)
		return true
	}
	// match: (ComplexReal x:(Load <t> ptr mem))
	// cond: t.IsComplex() && t.Size() == 8
	// result: @x.Block (Load <typ.Float32> ptr mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsComplex() && t.Size() == 8) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float32)
		v.copyOf(v0)
		v0.AddArg2(ptr, mem)
		return true
	}
	// match: (ComplexReal x:(Load <t> ptr mem))
	// cond: t.IsComplex() && t.Size() == 16
	// result: @x.Block (Load <typ.Float64> ptr mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsComplex() && t.Size() == 16) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float64)
		v.copyOf(v0)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpIData(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (IData (IMake _ data))
	// result: data
	for {
		if v_0.Op != OpIMake {
			break
		}
		data := v_0.Args[1]
		v.copyOf(data)
		return true
	}
	// match: (IData x:(Load <t> ptr mem))
	// cond: t.IsInterface()
	// result: @x.Block (Load <typ.BytePtr> (OffPtr <typ.BytePtrPtr> [config.PtrSize] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsInterface()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.BytePtr)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.BytePtrPtr)
		v1.AuxInt = int64ToAuxInt(config.PtrSize)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpIMake(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (IMake _typ (StructMake val))
	// result: (IMake _typ val)
	for {
		_typ := v_0
		if v_1.Op != OpStructMake || len(v_1.Args) != 1 {
			break
		}
		val := v_1.Args[0]
		v.reset(OpIMake)
		v.AddArg2(_typ, val)
		return true
	}
	return false
}
func rewriteValuedec_OpITab(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ITab (IMake itab _))
	// result: itab
	for {
		if v_0.Op != OpIMake {
			break
		}
		itab := v_0.Args[0]
		v.copyOf(itab)
		return true
	}
	// match: (ITab x:(Load <t> ptr mem))
	// cond: t.IsInterface()
	// result: @x.Block (Load <typ.Uintptr> ptr mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsInterface()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Uintptr)
		v.copyOf(v0)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpLoad(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Load <t> ptr mem)
	// cond: t.IsComplex() && t.Size() == 8
	// result: (ComplexMake (Load <typ.Float32> ptr mem) (Load <typ.Float32> (OffPtr <typ.Float32Ptr> [4] ptr) mem) )
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsComplex() && t.Size() == 8) {
			break
		}
		v.reset(OpComplexMake)
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float32)
		v0.AddArg2(ptr, mem)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Float32)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.Float32Ptr)
		v2.AuxInt = int64ToAuxInt(4)
		v2.AddArg(ptr)
		v1.AddArg2(v2, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsComplex() && t.Size() == 16
	// result: (ComplexMake (Load <typ.Float64> ptr mem) (Load <typ.Float64> (OffPtr <typ.Float64Ptr> [8] ptr) mem) )
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsComplex() && t.Size() == 16) {
			break
		}
		v.reset(OpComplexMake)
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Float64)
		v0.AddArg2(ptr, mem)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Float64)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.Float64Ptr)
		v2.AuxInt = int64ToAuxInt(8)
		v2.AddArg(ptr)
		v1.AddArg2(v2, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsString()
	// result: (StringMake (Load <typ.BytePtr> ptr mem) (Load <typ.Int> (OffPtr <typ.IntPtr> [config.PtrSize] ptr) mem))
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsString()) {
			break
		}
		v.reset(OpStringMake)
		v0 := b.NewValue0(v.Pos, OpLoad, typ.BytePtr)
		v0.AddArg2(ptr, mem)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v2.AuxInt = int64ToAuxInt(config.PtrSize)
		v2.AddArg(ptr)
		v1.AddArg2(v2, mem)
		v.AddArg2(v0, v1)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsSlice()
	// result: (SliceMake (Load <t.Elem().PtrTo()> ptr mem) (Load <typ.Int> (OffPtr <typ.IntPtr> [config.PtrSize] ptr) mem) (Load <typ.Int> (OffPtr <typ.IntPtr> [2*config.PtrSize] ptr) mem))
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsSlice()) {
			break
		}
		v.reset(OpSliceMake)
		v0 := b.NewValue0(v.Pos, OpLoad, t.Elem().PtrTo())
		v0.AddArg2(ptr, mem)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v2.AuxInt = int64ToAuxInt(config.PtrSize)
		v2.AddArg(ptr)
		v1.AddArg2(v2, mem)
		v3 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v4 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v4.AuxInt = int64ToAuxInt(2 * config.PtrSize)
		v4.AddArg(ptr)
		v3.AddArg2(v4, mem)
		v.AddArg3(v0, v1, v3)
		return true
	}
	// match: (Load <t> ptr mem)
	// cond: t.IsInterface()
	// result: (IMake (Load <typ.Uintptr> ptr mem) (Load <typ.BytePtr> (OffPtr <typ.BytePtrPtr> [config.PtrSize] ptr) mem))
	for {
		t := v.Type
		ptr := v_0
		mem := v_1
		if !(t.IsInterface()) {
			break
		}
		v.reset(OpIMake)
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Uintptr)
		v0.AddArg2(ptr, mem)
		v1 := b.NewValue0(v.Pos, OpLoad, typ.BytePtr)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.BytePtrPtr)
		v2.AuxInt = int64ToAuxInt(config.PtrSize)
		v2.AddArg(ptr)
		v1.AddArg2(v2, mem)
		v.AddArg2(v0, v1)
		return true
	}
	return false
}
func rewriteValuedec_OpSliceCap(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (SliceCap (SliceMake _ _ cap))
	// result: cap
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		cap := v_0.Args[2]
		v.copyOf(cap)
		return true
	}
	// match: (SliceCap x:(Load <t> ptr mem))
	// cond: t.IsSlice()
	// result: @x.Block (Load <typ.Int> (OffPtr <typ.IntPtr> [2*config.PtrSize] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsSlice()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v1.AuxInt = int64ToAuxInt(2 * config.PtrSize)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpSliceLen(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (SliceLen (SliceMake _ len _))
	// result: len
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		len := v_0.Args[1]
		v.copyOf(len)
		return true
	}
	// match: (SliceLen x:(Load <t> ptr mem))
	// cond: t.IsSlice()
	// result: @x.Block (Load <typ.Int> (OffPtr <typ.IntPtr> [config.PtrSize] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsSlice()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v1.AuxInt = int64ToAuxInt(config.PtrSize)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpSlicePtr(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (SlicePtr (SliceMake ptr _ _ ))
	// result: ptr
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		ptr := v_0.Args[0]
		v.copyOf(ptr)
		return true
	}
	// match: (SlicePtr x:(Load <t> ptr mem))
	// cond: t.IsSlice()
	// result: @x.Block (Load <t.Elem().PtrTo()> ptr mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsSlice()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, t.Elem().PtrTo())
		v.copyOf(v0)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpSlicePtrUnchecked(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SlicePtrUnchecked (SliceMake ptr _ _ ))
	// result: ptr
	for {
		if v_0.Op != OpSliceMake {
			break
		}
		ptr := v_0.Args[0]
		v.copyOf(ptr)
		return true
	}
	return false
}
func rewriteValuedec_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Store {t} _ _ mem)
	// cond: t.Size() == 0
	// result: mem
	for {
		t := auxToType(v.Aux)
		mem := v_2
		if !(t.Size() == 0) {
			break
		}
		v.copyOf(mem)
		return true
	}
	// match: (Store {t} dst (ComplexMake real imag) mem)
	// cond: t.Size() == 8
	// result: (Store {typ.Float32} (OffPtr <typ.Float32Ptr> [4] dst) imag (Store {typ.Float32} dst real mem))
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpComplexMake {
			break
		}
		imag := v_1.Args[1]
		real := v_1.Args[0]
		mem := v_2
		if !(t.Size() == 8) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(typ.Float32)
		v0 := b.NewValue0(v.Pos, OpOffPtr, typ.Float32Ptr)
		v0.AuxInt = int64ToAuxInt(4)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(typ.Float32)
		v1.AddArg3(dst, real, mem)
		v.AddArg3(v0, imag, v1)
		return true
	}
	// match: (Store {t} dst (ComplexMake real imag) mem)
	// cond: t.Size() == 16
	// result: (Store {typ.Float64} (OffPtr <typ.Float64Ptr> [8] dst) imag (Store {typ.Float64} dst real mem))
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpComplexMake {
			break
		}
		imag := v_1.Args[1]
		real := v_1.Args[0]
		mem := v_2
		if !(t.Size() == 16) {
			break
		}
		v.reset(OpStore)
		v.Aux = typeToAux(typ.Float64)
		v0 := b.NewValue0(v.Pos, OpOffPtr, typ.Float64Ptr)
		v0.AuxInt = int64ToAuxInt(8)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(typ.Float64)
		v1.AddArg3(dst, real, mem)
		v.AddArg3(v0, imag, v1)
		return true
	}
	// match: (Store dst (StringMake ptr len) mem)
	// result: (Store {typ.Int} (OffPtr <typ.IntPtr> [config.PtrSize] dst) len (Store {typ.BytePtr} dst ptr mem))
	for {
		dst := v_0
		if v_1.Op != OpStringMake {
			break
		}
		len := v_1.Args[1]
		ptr := v_1.Args[0]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(typ.Int)
		v0 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v0.AuxInt = int64ToAuxInt(config.PtrSize)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(typ.BytePtr)
		v1.AddArg3(dst, ptr, mem)
		v.AddArg3(v0, len, v1)
		return true
	}
	// match: (Store {t} dst (SliceMake ptr len cap) mem)
	// result: (Store {typ.Int} (OffPtr <typ.IntPtr> [2*config.PtrSize] dst) cap (Store {typ.Int} (OffPtr <typ.IntPtr> [config.PtrSize] dst) len (Store {t.Elem().PtrTo()} dst ptr mem)))
	for {
		t := auxToType(v.Aux)
		dst := v_0
		if v_1.Op != OpSliceMake {
			break
		}
		cap := v_1.Args[2]
		ptr := v_1.Args[0]
		len := v_1.Args[1]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(typ.Int)
		v0 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v0.AuxInt = int64ToAuxInt(2 * config.PtrSize)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(typ.Int)
		v2 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v2.AuxInt = int64ToAuxInt(config.PtrSize)
		v2.AddArg(dst)
		v3 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v3.Aux = typeToAux(t.Elem().PtrTo())
		v3.AddArg3(dst, ptr, mem)
		v1.AddArg3(v2, len, v3)
		v.AddArg3(v0, cap, v1)
		return true
	}
	// match: (Store dst (IMake itab data) mem)
	// result: (Store {typ.BytePtr} (OffPtr <typ.BytePtrPtr> [config.PtrSize] dst) data (Store {typ.Uintptr} dst itab mem))
	for {
		dst := v_0
		if v_1.Op != OpIMake {
			break
		}
		data := v_1.Args[1]
		itab := v_1.Args[0]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(typ.BytePtr)
		v0 := b.NewValue0(v.Pos, OpOffPtr, typ.BytePtrPtr)
		v0.AuxInt = int64ToAuxInt(config.PtrSize)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpStore, types.TypeMem)
		v1.Aux = typeToAux(typ.Uintptr)
		v1.AddArg3(dst, itab, mem)
		v.AddArg3(v0, data, v1)
		return true
	}
	// match: (Store _ (StructMake ___) _)
	// result: rewriteStructStore(v)
	for {
		if v_1.Op != OpStructMake {
			break
		}
		v.copyOf(rewriteStructStore(v))
		return true
	}
	// match: (Store dst (ArrayMake1 e) mem)
	// result: (Store {e.Type} dst e mem)
	for {
		dst := v_0
		if v_1.Op != OpArrayMake1 {
			break
		}
		e := v_1.Args[0]
		mem := v_2
		v.reset(OpStore)
		v.Aux = typeToAux(e.Type)
		v.AddArg3(dst, e, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpStringLen(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (StringLen (StringMake _ len))
	// result: len
	for {
		if v_0.Op != OpStringMake {
			break
		}
		len := v_0.Args[1]
		v.copyOf(len)
		return true
	}
	// match: (StringLen x:(Load <t> ptr mem))
	// cond: t.IsString()
	// result: @x.Block (Load <typ.Int> (OffPtr <typ.IntPtr> [config.PtrSize] ptr) mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsString()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.Int)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, typ.IntPtr)
		v1.AuxInt = int64ToAuxInt(config.PtrSize)
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpStringPtr(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (StringPtr (StringMake ptr _))
	// result: ptr
	for {
		if v_0.Op != OpStringMake {
			break
		}
		ptr := v_0.Args[0]
		v.copyOf(ptr)
		return true
	}
	// match: (StringPtr x:(Load <t> ptr mem))
	// cond: t.IsString()
	// result: @x.Block (Load <typ.BytePtr> ptr mem)
	for {
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		if !(t.IsString()) {
			break
		}
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, typ.BytePtr)
		v.copyOf(v0)
		v0.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValuedec_OpStructMake(v *Value) bool {
	// match: (StructMake x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		if len(v.Args) != 1 {
			break
		}
		x := v.Args[0]
		if !(x.Type.IsPtrShaped()) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuedec_OpStructSelect(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (StructSelect [0] (IData x))
	// result: (IData x)
	for {
		if auxIntToInt64(v.AuxInt) != 0 || v_0.Op != OpIData {
			break
		}
		x := v_0.Args[0]
		v.reset(OpIData)
		v.AddArg(x)
		return true
	}
	// match: (StructSelect [i] x:(StructMake ___))
	// result: x.Args[i]
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpStructMake {
			break
		}
		v.copyOf(x.Args[i])
		return true
	}
	// match: (StructSelect [0] x)
	// cond: x.Type.IsPtrShaped()
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		if !(x.Type.IsPtrShaped()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (StructSelect [i] x:(Load <t> ptr mem))
	// result: @x.Block (Load <v.Type> (OffPtr <v.Type.PtrTo()> [t.FieldOff(int(i))] ptr) mem)
	for {
		i := auxIntToInt64(v.AuxInt)
		x := v_0
		if x.Op != OpLoad {
			break
		}
		t := x.Type
		mem := x.Args[1]
		ptr := x.Args[0]
		b = x.Block
		v0 := b.NewValue0(v.Pos, OpLoad, v.Type)
		v.copyOf(v0)
		v1 := b.NewValue0(v.Pos, OpOffPtr, v.Type.PtrTo())
		v1.AuxInt = int64ToAuxInt(t.FieldOff(int(i)))
		v1.AddArg(ptr)
		v0.AddArg2(v1, mem)
		return true
	}
	return false
}
func rewriteBlockdec(b *Block) bool {
	return false
}

"""



```