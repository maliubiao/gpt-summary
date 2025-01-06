Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `convert.go` file within the Go compiler, specifically the `walk` package. It also requests examples, error-prone points, and handling of command-line arguments.

2. **Identify the Core Function:** The file name `convert.go` and the function names starting with `walkConv` strongly suggest this code deals with type conversions during the compilation process. The `walk` prefix hints at the AST traversal phase.

3. **Analyze Individual Functions:**  Go through each function (`walkConv`, `walkConvInterface`, `dataWord`, etc.) and understand its purpose.

    * **`walkConv`:**  Handles basic conversions. The check for `OCONVNOP` suggests optimization by removing redundant conversions. The call to `rtconvfn` hints at runtime function calls for conversions.

    * **`walkConvInterface`:**  Focuses on interface conversions (`OCONVIFACE`). It distinguishes between converting *to* an interface and converting *from* an interface. The `OMAKEFACE` operation is a key indicator of interface creation. The handling of empty interfaces is also noteworthy.

    * **`dataWord`:**  This function is crucial for interface construction. It determines how the underlying data of a non-interface value is represented when boxed into an interface. The various cases (small types, readonly globals, stack allocation, runtime calls) are important details.

    * **`walkBytesRunesToString`, `walkBytesToStringTemp`, `walkRuneToString`, `walkStringToBytes`, `walkStringToBytesTemp`, `walkStringToRunes`:** These functions deal with specific string conversions involving byte and rune slices. The `Temp` versions suggest optimizations or special handling for temporary conversions.

    * **`dataWordFuncName`:**  A helper function to determine the runtime function name for data word creation, based on the type.

    * **`rtconvfn`:**  Determines if a runtime conversion function is needed for specific numeric types based on the target architecture.

    * **`soleComponent`:**  Handles cases where a type effectively has a single meaningful component (e.g., structs with blank fields).

    * **`byteindex`:**  A utility for converting byte-sized values to integer indices.

    * **`walkCheckPtrArithmetic`:**  This function is particularly interesting. It seems to handle conversions between `uintptr` and `unsafe.Pointer` and checks for valid pointer arithmetic.

    * **`walkSliceToArray`:**  Deals with converting slices to arrays. The use of pointer casting (`*(*T)(x)`) is a significant detail.

4. **Identify Core Functionality:** Based on the individual function analysis, the primary functionality is the implementation of various type conversions required by the Go language. This involves:
    * Handling basic type conversions (numeric, etc.).
    * Boxing values into interfaces.
    * Unboxing values from interfaces.
    * Converting between strings and byte/rune slices.
    * Optimizing certain conversion scenarios.
    * Performing checks related to unsafe pointer arithmetic.

5. **Infer Go Language Features:** Connect the code to specific Go language features:
    * **Type Conversions:**  The `walkConv` functions directly relate to Go's type conversion syntax (e.g., `int(float64Var)`).
    * **Interfaces:**  `walkConvInterface` and `dataWord` are central to how Go implements interfaces.
    * **String Conversions:** The functions dealing with `OSTR2BYTES`, `OBYTES2STR`, etc., implement the standard conversions between strings and byte/rune slices.
    * **`unsafe.Pointer`:**  `walkCheckPtrArithmetic` directly addresses the usage of `unsafe.Pointer` and its potential for misuse.
    * **Slices and Arrays:**  `walkSliceToArray` and the string conversion functions demonstrate the interaction between slices and arrays.

6. **Construct Examples:**  Create concise Go code snippets that would trigger the different conversion scenarios handled in the code. Focus on illustrating the specific functionality of each `walkConv` function.

7. **Infer Assumptions and Inputs/Outputs (for Code Reasoning):** When explaining the logic of a function like `walkConvInterface`,  make explicit assumptions about the input `ir.ConvExpr` (e.g., the types of `n.X` and `n.Type()`). Describe the expected transformations the function performs on the input AST node.

8. **Consider Command-Line Arguments:**  While the provided snippet doesn't directly process command-line arguments, consider the context. This code is part of the Go compiler. Think about compiler flags that might affect conversion behavior (e.g., optimization levels, flags related to `unsafe`). *Self-correction:* The provided code doesn't explicitly handle command-line arguments. It's important not to invent things not present.

9. **Identify Error-Prone Areas:**  Think about common mistakes developers make related to the features implemented by this code:
    * **Incorrect interface conversions:**  Trying to convert to an interface that a type doesn't implement.
    * **Misusing `unsafe.Pointer`:**  Performing invalid pointer arithmetic.
    * **Assuming string immutability after `StringToBytesTemp` (if the backend didn't handle it as intended).**

10. **Structure the Answer:** Organize the information logically, starting with a general overview of the file's purpose, then detailing each function's functionality, followed by examples, assumptions, command-line considerations (if any are directly handled), and finally, common mistakes. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This code just does simple type conversions."  *Correction:* Realized the complexity, especially with interfaces and `unsafe.Pointer`.
* **Focusing too much on low-level details:**  *Correction:*  Shifted focus to the higher-level Go language features being implemented.
* **Overlooking the "walk" prefix:** *Correction:* Recognized the significance of `walk` indicating AST traversal.
* **Assuming knowledge of the entire compiler:** *Correction:* Focused only on the provided code snippet and made reasonable inferences about its role.
* **Including command-line arguments without evidence:** *Correction:* Removed that section since the code doesn't directly show command-line handling.

By following these steps and iteratively refining the analysis, a comprehensive and accurate explanation of the code snippet can be constructed.
这段代码是 Go 编译器 `cmd/compile/internal/walk` 包中 `convert.go` 文件的一部分，它主要负责处理 **类型转换** 相关的抽象语法树（AST）节点的遍历和转换。

**功能概览:**

这段代码定义了一系列 `walk` 函数，这些函数专门用于处理 `ir.ConvExpr` 类型的节点。 `ir.ConvExpr` 代表 Go 语言中的类型转换表达式。  这些 `walk` 函数的任务是：

1. **识别不同类型的类型转换:**  例如，将一个整数转换为浮点数，将一个切片转换为数组，将一个具体类型转换为接口类型等等。
2. **生成执行类型转换所需的代码:** 这可能涉及到调用运行时库的函数，进行内存分配，或者进行简单的类型转换操作。
3. **进行一些优化:**  例如，如果转换是不必要的（将一个类型转换为它自身），则直接返回原始表达式。
4. **处理 `unsafe.Pointer` 相关的转换:**  特别是从 `uintptr` 到 `unsafe.Pointer` 的转换，可能需要进行指针算术检查。
5. **处理字符串和字节/rune切片之间的转换。**
6. **处理接口类型的转换。**

**具体功能分解:**

* **`walkConv(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理 `OCONV` 和 `OCONVNOP` 操作码的转换节点（但不包括 `OCONVIFACE`，接口转换）。
    * 如果是 `OCONVNOP` 且源类型和目标类型相同，则直接返回原始表达式 `n.X`，这是一个优化。
    * 如果是将 `uintptr` 转换为 `unsafe.Pointer`，并且启用了指针检查 (`ir.ShouldCheckPtr`)，则调用 `walkCheckPtrArithmetic` 进行额外的检查。
    * 对于其他需要运行时转换的场景，它会根据源类型和目标类型调用 `rtconvfn` 获取运行时函数的参数和结果类型，然后构造对相应运行时函数的调用。例如，将 `int32` 转换为 `int64` 可能需要调用一个类似的运行时函数。

* **`walkConvInterface(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理 `OCONVIFACE` 操作码的转换节点，即转换为接口类型的转换。
    * 如果是将非接口类型转换为接口类型：
        * 它会调用 `reflectdata.MarkTypeUsedInInterface` 标记源类型在接口中的使用，以便进行反射相关的信息生成。
        * 它会使用 `ir.OMAKEFACE` 操作码创建一个新的接口值，其中包含类型信息 (`typeWord`) 和数据 (`dataWord`)。
    * 如果是将一个接口类型转换为另一个接口类型（更具体的接口到更抽象的接口），它会生成类型断言的代码，类似于 `x.(T)`。
    * 特殊处理了转换为 `interface{}` (空接口) 的情况。

* **`dataWord(conv *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 返回用于表示接口中数据的第二个字（data word）。
    * 对于指针类型，数据就是指针本身。
    * 对于其他类型，它尝试避免分配，例如：
        * 对于零大小的类型，使用 `zerobase`。
        * 对于 `bool` 或单字节整数，使用静态数组 `staticuint64s`。
        * 对于只读的全局变量，直接使用该变量。
        * 对于不逃逸且大小较小的类型，在栈上分配临时变量并赋值。
    * 如果以上方法都不可行，则会调用运行时函数进行内存分配和复制，例如 `convT16`, `convT32`, `convT64`, `convTstring`, `convTslice`, `convT`, `convTnoptr` 等。

* **`walkBytesRunesToString(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理将 `[]byte` 或 `[]rune` 转换为 `string` 的操作 (`OBYTES2STR`, `ORUNES2STR`)。
    * 如果转换结果不逃逸，会在栈上分配临时缓冲区。
    * 调用运行时函数 `slicerunetostring` 或 `slicebytetostring` 来执行转换。

* **`walkBytesToStringTemp(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理 `OBYTES2STRTMP` 操作码，这通常用于创建临时字符串，其底层数据直接指向字节切片。
    * 在开启了代码插桩的情况下，会调用 `slicebytetostringtmp` 运行时函数。否则，将此节点传递给后端处理。

* **`walkRuneToString(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理将 `rune` 转换为 `string` 的操作 (`ORUNESTR`)。
    * 类似地，如果结果不逃逸，会在栈上分配临时缓冲区。
    * 调用运行时函数 `intstring`。

* **`walkStringToBytes(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理将 `string` 转换为 `[]byte` 的操作 (`OSTR2BYTES`)。
    * 如果源字符串是常量，它会在编译时分配一个字节数组并复制字符串内容。
    * 否则，如果结果不逃逸，会在栈上分配临时缓冲区。
    * 调用运行时函数 `stringtoslicebyte`。

* **`walkStringToBytesTemp(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理 `OSTR2BYTESTMP` 操作码，这用于创建指向字符串底层数据的临时字节切片。
    * 此转换通常由后端处理，用于编译器内部优化。

* **`walkStringToRunes(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理将 `string` 转换为 `[]rune` 的操作 (`OSTR2RUNES`)。
    * 如果结果不逃逸，会在栈上分配临时缓冲区。
    * 调用运行时函数 `stringtoslicerune`。

* **`dataWordFuncName(from *types.Type) (fnname string, argType *types.Type, needsaddr bool)`**:
    * 根据源类型 `from` 返回用于创建接口数据字的运行时函数名称、参数类型以及是否需要传递地址。

* **`rtconvfn(src, dst *types.Type) (param, result types.Kind)`**:
    * 确定从 `src` 类型转换为 `dst` 类型是否需要运行时函数，并返回运行时函数的参数和结果类型。这通常用于处理不同大小或类型的数值转换，尤其是涉及到浮点数时，会考虑架构特性。

* **`soleComponent(init *ir.Nodes, n ir.Node) ir.Node`**:
    * 查找一个类型的唯一有效组成部分。例如，对于只有一个非空字段的结构体，或者数组的第一个元素。

* **`byteindex(n ir.Node) ir.Node`**:
    * 将字节大小的值 `n` 转换为用于数组索引的整数。它会确保类型是 `uint8` 并转换为 `int`。

* **`walkCheckPtrArithmetic(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理 `uintptr` 到 `unsafe.Pointer` 的转换。
    * 它会尝试找到参与指针算术运算的原始 `unsafe.Pointer` 操作数。
    * 调用运行时函数 `checkptrArithmetic` 来执行指针算术检查。

* **`walkSliceToArray(n *ir.ConvExpr, init *ir.Nodes) ir.Node`**:
    * 处理将切片转换为数组的操作 (`OSLICE2ARR`)。
    * 它会将 `T(x)` 转换为 `*(*T)(x)`，并标记解引用操作为 `Bounded(true)`，表示可以安全地进行，因为切片的长度已经检查过。

**推断的 Go 语言功能实现示例:**

```go
package main

import (
	"fmt"
	"unsafe"
)

func main() {
	// 1. 基本类型转换 (对应 walkConv)
	var i int32 = 10
	var f float64 = float64(i)
	fmt.Println(f) // Output: 10

	// 2. 转换为接口 (对应 walkConvInterface)
	var s string = "hello"
	var iface interface{} = s
	fmt.Println(iface) // Output: hello

	// 3. 字符串到字节切片 (对应 walkStringToBytes)
	var str string = "world"
	var bytes []byte = []byte(str)
	fmt.Println(bytes) // Output: [119 111 114 108 100]

	// 4. 字节切片到字符串 (对应 walkBytesRunesToString)
	var byteSlice []byte = []byte{'G', 'o'}
	var strFromBytes string = string(byteSlice)
	fmt.Println(strFromBytes) // Output: Go

	// 5. uintptr 到 unsafe.Pointer 的转换 (对应 walkCheckPtrArithmetic)
	var num int = 42
	ptr := unsafe.Pointer(&num)
	uintPtr := uintptr(ptr)
	ptrBack := unsafe.Pointer(uintPtr)
	fmt.Println(*(*int)(ptrBack)) // Output: 42

	// 6. 切片到数组的转换 (对应 walkSliceToArray)
	slice := []int{1, 2, 3}
	arrayPtr := (*[3]int)(unsafe.Pointer(&slice[0]))
	array := *arrayPtr
	fmt.Println(array) // Output: [1 2 3]
}
```

**代码推理的假设输入与输出:**

**示例 1: `walkConv` - `int32` 到 `int64` 的转换**

* **假设输入 `n`**: 一个 `ir.ConvExpr` 节点，其 `Op()` 为 `ir.OCONV`， `n.X.Type()` 是 `int32`， `n.Type()` 是 `int64`。
* **推断的输出**:  `walkConv` 可能会生成一个表示对运行时函数调用的 `ir.CallExpr` 节点，例如 `runtime.convT32toT64(n.X)`，其中 `convT32toT64` 是一个假设的运行时函数名。

**示例 2: `walkConvInterface` - `string` 到 `interface{}` 的转换**

* **假设输入 `n`**: 一个 `ir.ConvExpr` 节点，其 `Op()` 为 `ir.OCONVIFACE`， `n.X.Type()` 是 `string`， `n.Type()` 是 `interface{}`。
* **推断的输出**: `walkConvInterface` 可能会生成一个 `ir.BinaryExpr` 节点，其 `Op()` 为 `ir.OMAKEFACE`，左操作数是表示 `string` 类型信息的 `typeWord`，右操作数是通过 `dataWord` 函数获取的 `string` 的数据地址。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的解析通常发生在编译器的入口点，例如 `go/src/cmd/compile/internal/gc/main.go`。 然而，编译器的某些标志可能会影响到这里代码的行为，例如：

* **`-N` (禁用优化):**  可能会影响某些优化，例如 `OCONVNOP` 的处理。
* **`-gcflags "-G=3"` (启用泛型):**  泛型的引入可能会导致新的类型转换场景，虽然这段代码看起来是 Go 1.x 的实现，但这是一个可能的扩展方向。
* **与反射相关的标志:**  可能会影响 `reflectdata.MarkTypeUsedInInterface` 的行为。
* **与 `unsafe` 相关的警告或错误标志:** 可能会间接影响 `walkCheckPtrArithmetic` 的检查严格程度。
* **代码插桩标志 (`-coverage` 等):**  会影响 `walkBytesToStringTemp` 的处理，使其调用运行时函数。

**使用者易犯错的点 (与类型转换相关的常见错误，虽然不是直接由这段代码引起):**

1. **不安全的类型断言:**  在将接口类型转换为具体类型时，如果不使用类型断言的“comma ok”形式 (`value, ok := iface.(ConcreteType)`), 当类型不匹配时会发生 panic。

   ```go
   var iface interface{} = 10
   // potential panic if iface doesn't hold an int
   value := iface.(int)
   ```

2. **忽略数值类型转换的精度损失:**  将 `float64` 转换为 `int` 会截断小数部分。

   ```go
   var f float64 = 3.14
   var i int = int(f) // i will be 3
   ```

3. **字符串和字节/rune切片转换的误解:**  认为字符串可以像字节切片一样直接修改是错误的，因为字符串是不可变的。 任何修改都需要重新分配。

   ```go
   s := "abc"
   // 以下操作是非法的
   // s[0] = 'd'

   // 需要转换为 []byte 进行修改
   b := []byte(s)
   b[0] = 'd'
   s = string(b)
   ```

4. **`unsafe.Pointer` 的滥用:**  不理解 `unsafe.Pointer` 的含义和风险，进行不安全的指针操作可能导致程序崩溃或数据损坏。例如，在没有充分理解内存布局的情况下进行指针偏移。

这段代码是 Go 编译器类型检查和代码生成过程中的关键部分，它确保了类型转换在运行时能够正确高效地执行。理解其功能有助于深入了解 Go 语言的类型系统和编译原理。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/walk/convert.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"encoding/binary"
	"go/constant"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/sys"
)

// walkConv walks an OCONV or OCONVNOP (but not OCONVIFACE) node.
func walkConv(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	n.X = walkExpr(n.X, init)
	if n.Op() == ir.OCONVNOP && n.Type() == n.X.Type() {
		return n.X
	}
	if n.Op() == ir.OCONVNOP && ir.ShouldCheckPtr(ir.CurFunc, 1) {
		if n.Type().IsUnsafePtr() && n.X.Type().IsUintptr() { // uintptr to unsafe.Pointer
			return walkCheckPtrArithmetic(n, init)
		}
	}
	param, result := rtconvfn(n.X.Type(), n.Type())
	if param == types.Txxx {
		return n
	}
	fn := types.BasicTypeNames[param] + "to" + types.BasicTypeNames[result]
	return typecheck.Conv(mkcall(fn, types.Types[result], init, typecheck.Conv(n.X, types.Types[param])), n.Type())
}

// walkConvInterface walks an OCONVIFACE node.
func walkConvInterface(n *ir.ConvExpr, init *ir.Nodes) ir.Node {

	n.X = walkExpr(n.X, init)

	fromType := n.X.Type()
	toType := n.Type()
	if !fromType.IsInterface() && !ir.IsBlank(ir.CurFunc.Nname) {
		// skip unnamed functions (func _())
		if fromType.HasShape() {
			// Unified IR uses OCONVIFACE for converting all derived types
			// to interface type. Avoid assertion failure in
			// MarkTypeUsedInInterface, because we've marked used types
			// separately anyway.
		} else {
			reflectdata.MarkTypeUsedInInterface(fromType, ir.CurFunc.LSym)
		}
	}

	if !fromType.IsInterface() {
		typeWord := reflectdata.ConvIfaceTypeWord(base.Pos, n)
		l := ir.NewBinaryExpr(base.Pos, ir.OMAKEFACE, typeWord, dataWord(n, init))
		l.SetType(toType)
		l.SetTypecheck(n.Typecheck())
		return l
	}
	if fromType.IsEmptyInterface() {
		base.Fatalf("OCONVIFACE can't operate on an empty interface")
	}

	// Evaluate the input interface.
	c := typecheck.TempAt(base.Pos, ir.CurFunc, fromType)
	init.Append(ir.NewAssignStmt(base.Pos, c, n.X))

	if toType.IsEmptyInterface() {
		// Implement interface to empty interface conversion:
		//
		// var res *uint8
		// res = (*uint8)(unsafe.Pointer(itab))
		// if res != nil {
		//    res = res.type
		// }

		// Grab its parts.
		itab := ir.NewUnaryExpr(base.Pos, ir.OITAB, c)
		itab.SetType(types.Types[types.TUINTPTR].PtrTo())
		itab.SetTypecheck(1)
		data := ir.NewUnaryExpr(n.Pos(), ir.OIDATA, c)
		data.SetType(types.Types[types.TUINT8].PtrTo()) // Type is generic pointer - we're just passing it through.
		data.SetTypecheck(1)

		typeWord := typecheck.TempAt(base.Pos, ir.CurFunc, types.NewPtr(types.Types[types.TUINT8]))
		init.Append(ir.NewAssignStmt(base.Pos, typeWord, typecheck.Conv(typecheck.Conv(itab, types.Types[types.TUNSAFEPTR]), typeWord.Type())))
		nif := ir.NewIfStmt(base.Pos, typecheck.Expr(ir.NewBinaryExpr(base.Pos, ir.ONE, typeWord, typecheck.NodNil())), nil, nil)
		nif.Body = []ir.Node{ir.NewAssignStmt(base.Pos, typeWord, itabType(typeWord))}
		init.Append(nif)

		// Build the result.
		// e = iface{typeWord, data}
		e := ir.NewBinaryExpr(base.Pos, ir.OMAKEFACE, typeWord, data)
		e.SetType(toType) // assign type manually, typecheck doesn't understand OEFACE.
		e.SetTypecheck(1)
		return e
	}

	// Must be converting I2I (more specific to less specific interface).
	// Use the same code as e, _ = c.(T).
	var rhs ir.Node
	if n.TypeWord == nil || n.TypeWord.Op() == ir.OADDR && n.TypeWord.(*ir.AddrExpr).X.Op() == ir.OLINKSYMOFFSET {
		// Fixed (not loaded from a dictionary) type.
		ta := ir.NewTypeAssertExpr(base.Pos, c, toType)
		ta.SetOp(ir.ODOTTYPE2)
		// Allocate a descriptor for this conversion to pass to the runtime.
		ta.Descriptor = makeTypeAssertDescriptor(toType, true)
		rhs = ta
	} else {
		ta := ir.NewDynamicTypeAssertExpr(base.Pos, ir.ODYNAMICDOTTYPE2, c, n.TypeWord)
		rhs = ta
	}
	rhs.SetType(toType)
	rhs.SetTypecheck(1)

	res := typecheck.TempAt(base.Pos, ir.CurFunc, toType)
	as := ir.NewAssignListStmt(base.Pos, ir.OAS2DOTTYPE, []ir.Node{res, ir.BlankNode}, []ir.Node{rhs})
	init.Append(as)
	return res
}

// Returns the data word (the second word) used to represent conv.X in
// an interface.
func dataWord(conv *ir.ConvExpr, init *ir.Nodes) ir.Node {
	pos, n := conv.Pos(), conv.X
	fromType := n.Type()

	// If it's a pointer, it is its own representation.
	if types.IsDirectIface(fromType) {
		return n
	}

	isInteger := fromType.IsInteger()
	isBool := fromType.IsBoolean()
	if sc := fromType.SoleComponent(); sc != nil {
		isInteger = sc.IsInteger()
		isBool = sc.IsBoolean()
	}
	// Try a bunch of cases to avoid an allocation.
	var value ir.Node
	switch {
	case fromType.Size() == 0:
		// n is zero-sized. Use zerobase.
		cheapExpr(n, init) // Evaluate n for side-effects. See issue 19246.
		value = ir.NewLinksymExpr(base.Pos, ir.Syms.Zerobase, types.Types[types.TUINTPTR])
	case isBool || fromType.Size() == 1 && isInteger:
		// n is a bool/byte. Use staticuint64s[n * 8] on little-endian
		// and staticuint64s[n * 8 + 7] on big-endian.
		n = cheapExpr(n, init)
		n = soleComponent(init, n)
		// byteindex widens n so that the multiplication doesn't overflow.
		index := ir.NewBinaryExpr(base.Pos, ir.OLSH, byteindex(n), ir.NewInt(base.Pos, 3))
		if ssagen.Arch.LinkArch.ByteOrder == binary.BigEndian {
			index = ir.NewBinaryExpr(base.Pos, ir.OADD, index, ir.NewInt(base.Pos, 7))
		}
		// The actual type is [256]uint64, but we use [256*8]uint8 so we can address
		// individual bytes.
		staticuint64s := ir.NewLinksymExpr(base.Pos, ir.Syms.Staticuint64s, types.NewArray(types.Types[types.TUINT8], 256*8))
		xe := ir.NewIndexExpr(base.Pos, staticuint64s, index)
		xe.SetBounded(true)
		value = xe
	case n.Op() == ir.ONAME && n.(*ir.Name).Class == ir.PEXTERN && n.(*ir.Name).Readonly():
		// n is a readonly global; use it directly.
		value = n
	case conv.Esc() == ir.EscNone && fromType.Size() <= 1024:
		// n does not escape. Use a stack temporary initialized to n.
		value = typecheck.TempAt(base.Pos, ir.CurFunc, fromType)
		init.Append(typecheck.Stmt(ir.NewAssignStmt(base.Pos, value, n)))
	}
	if value != nil {
		// The interface data word is &value.
		return typecheck.Expr(typecheck.NodAddr(value))
	}

	// Time to do an allocation. We'll call into the runtime for that.
	fnname, argType, needsaddr := dataWordFuncName(fromType)
	var fn *ir.Name

	var args []ir.Node
	if needsaddr {
		// Types of large or unknown size are passed by reference.
		// Orderexpr arranged for n to be a temporary for all
		// the conversions it could see. Comparison of an interface
		// with a non-interface, especially in a switch on interface value
		// with non-interface cases, is not visible to order.stmt, so we
		// have to fall back on allocating a temp here.
		if !ir.IsAddressable(n) {
			n = copyExpr(n, fromType, init)
		}
		fn = typecheck.LookupRuntime(fnname, fromType)
		args = []ir.Node{reflectdata.ConvIfaceSrcRType(base.Pos, conv), typecheck.NodAddr(n)}
	} else {
		// Use a specialized conversion routine that takes the type being
		// converted by value, not by pointer.
		fn = typecheck.LookupRuntime(fnname)
		var arg ir.Node
		switch {
		case fromType == argType:
			// already in the right type, nothing to do
			arg = n
		case fromType.Kind() == argType.Kind(),
			fromType.IsPtrShaped() && argType.IsPtrShaped():
			// can directly convert (e.g. named type to underlying type, or one pointer to another)
			// TODO: never happens because pointers are directIface?
			arg = ir.NewConvExpr(pos, ir.OCONVNOP, argType, n)
		case fromType.IsInteger() && argType.IsInteger():
			// can directly convert (e.g. int32 to uint32)
			arg = ir.NewConvExpr(pos, ir.OCONV, argType, n)
		default:
			// unsafe cast through memory
			arg = copyExpr(n, fromType, init)
			var addr ir.Node = typecheck.NodAddr(arg)
			addr = ir.NewConvExpr(pos, ir.OCONVNOP, argType.PtrTo(), addr)
			arg = ir.NewStarExpr(pos, addr)
			arg.SetType(argType)
		}
		args = []ir.Node{arg}
	}
	call := ir.NewCallExpr(base.Pos, ir.OCALL, fn, nil)
	call.Args = args
	return safeExpr(walkExpr(typecheck.Expr(call), init), init)
}

// walkBytesRunesToString walks an OBYTES2STR or ORUNES2STR node.
func walkBytesRunesToString(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	a := typecheck.NodNil()
	if n.Esc() == ir.EscNone {
		// Create temporary buffer for string on stack.
		a = stackBufAddr(tmpstringbufsize, types.Types[types.TUINT8])
	}
	if n.Op() == ir.ORUNES2STR {
		// slicerunetostring(*[32]byte, []rune) string
		return mkcall("slicerunetostring", n.Type(), init, a, n.X)
	}
	// slicebytetostring(*[32]byte, ptr *byte, n int) string
	n.X = cheapExpr(n.X, init)
	ptr, len := backingArrayPtrLen(n.X)
	return mkcall("slicebytetostring", n.Type(), init, a, ptr, len)
}

// walkBytesToStringTemp walks an OBYTES2STRTMP node.
func walkBytesToStringTemp(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	n.X = walkExpr(n.X, init)
	if !base.Flag.Cfg.Instrumenting {
		// Let the backend handle OBYTES2STRTMP directly
		// to avoid a function call to slicebytetostringtmp.
		return n
	}
	// slicebytetostringtmp(ptr *byte, n int) string
	n.X = cheapExpr(n.X, init)
	ptr, len := backingArrayPtrLen(n.X)
	return mkcall("slicebytetostringtmp", n.Type(), init, ptr, len)
}

// walkRuneToString walks an ORUNESTR node.
func walkRuneToString(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	a := typecheck.NodNil()
	if n.Esc() == ir.EscNone {
		a = stackBufAddr(4, types.Types[types.TUINT8])
	}
	// intstring(*[4]byte, rune)
	return mkcall("intstring", n.Type(), init, a, typecheck.Conv(n.X, types.Types[types.TINT64]))
}

// walkStringToBytes walks an OSTR2BYTES node.
func walkStringToBytes(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	s := n.X

	if expr, ok := s.(*ir.AddStringExpr); ok {
		return walkAddString(n.Type(), expr, init)
	}

	if ir.IsConst(s, constant.String) {
		sc := ir.StringVal(s)

		// Allocate a [n]byte of the right size.
		t := types.NewArray(types.Types[types.TUINT8], int64(len(sc)))
		var a ir.Node
		if n.Esc() == ir.EscNone && len(sc) <= int(ir.MaxImplicitStackVarSize) {
			a = stackBufAddr(t.NumElem(), t.Elem())
		} else {
			types.CalcSize(t)
			a = ir.NewUnaryExpr(base.Pos, ir.ONEW, nil)
			a.SetType(types.NewPtr(t))
			a.SetTypecheck(1)
			a.MarkNonNil()
		}
		p := typecheck.TempAt(base.Pos, ir.CurFunc, t.PtrTo()) // *[n]byte
		init.Append(typecheck.Stmt(ir.NewAssignStmt(base.Pos, p, a)))

		// Copy from the static string data to the [n]byte.
		if len(sc) > 0 {
			sptr := ir.NewUnaryExpr(base.Pos, ir.OSPTR, s)
			sptr.SetBounded(true)
			as := ir.NewAssignStmt(base.Pos, ir.NewStarExpr(base.Pos, p), ir.NewStarExpr(base.Pos, typecheck.ConvNop(sptr, t.PtrTo())))
			appendWalkStmt(init, as)
		}

		// Slice the [n]byte to a []byte.
		slice := ir.NewSliceExpr(n.Pos(), ir.OSLICEARR, p, nil, nil, nil)
		slice.SetType(n.Type())
		slice.SetTypecheck(1)
		return walkExpr(slice, init)
	}

	a := typecheck.NodNil()
	if n.Esc() == ir.EscNone {
		// Create temporary buffer for slice on stack.
		a = stackBufAddr(tmpstringbufsize, types.Types[types.TUINT8])
	}
	// stringtoslicebyte(*32[byte], string) []byte
	return mkcall("stringtoslicebyte", n.Type(), init, a, typecheck.Conv(s, types.Types[types.TSTRING]))
}

// walkStringToBytesTemp walks an OSTR2BYTESTMP node.
func walkStringToBytesTemp(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	// []byte(string) conversion that creates a slice
	// referring to the actual string bytes.
	// This conversion is handled later by the backend and
	// is only for use by internal compiler optimizations
	// that know that the slice won't be mutated.
	// The only such case today is:
	// for i, c := range []byte(string)
	n.X = walkExpr(n.X, init)
	return n
}

// walkStringToRunes walks an OSTR2RUNES node.
func walkStringToRunes(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	a := typecheck.NodNil()
	if n.Esc() == ir.EscNone {
		// Create temporary buffer for slice on stack.
		a = stackBufAddr(tmpstringbufsize, types.Types[types.TINT32])
	}
	// stringtoslicerune(*[32]rune, string) []rune
	return mkcall("stringtoslicerune", n.Type(), init, a, typecheck.Conv(n.X, types.Types[types.TSTRING]))
}

// dataWordFuncName returns the name of the function used to convert a value of type "from"
// to the data word of an interface.
// argType is the type the argument needs to be coerced to.
// needsaddr reports whether the value should be passed (needaddr==false) or its address (needsaddr==true).
func dataWordFuncName(from *types.Type) (fnname string, argType *types.Type, needsaddr bool) {
	if from.IsInterface() {
		base.Fatalf("can only handle non-interfaces")
	}
	switch {
	case from.Size() == 2 && uint8(from.Alignment()) == 2:
		return "convT16", types.Types[types.TUINT16], false
	case from.Size() == 4 && uint8(from.Alignment()) == 4 && !from.HasPointers():
		return "convT32", types.Types[types.TUINT32], false
	case from.Size() == 8 && uint8(from.Alignment()) == uint8(types.Types[types.TUINT64].Alignment()) && !from.HasPointers():
		return "convT64", types.Types[types.TUINT64], false
	}
	if sc := from.SoleComponent(); sc != nil {
		switch {
		case sc.IsString():
			return "convTstring", types.Types[types.TSTRING], false
		case sc.IsSlice():
			return "convTslice", types.NewSlice(types.Types[types.TUINT8]), false // the element type doesn't matter
		}
	}

	if from.HasPointers() {
		return "convT", types.Types[types.TUNSAFEPTR], true
	}
	return "convTnoptr", types.Types[types.TUNSAFEPTR], true
}

// rtconvfn returns the parameter and result types that will be used by a
// runtime function to convert from type src to type dst. The runtime function
// name can be derived from the names of the returned types.
//
// If no such function is necessary, it returns (Txxx, Txxx).
func rtconvfn(src, dst *types.Type) (param, result types.Kind) {
	if ssagen.Arch.SoftFloat {
		return types.Txxx, types.Txxx
	}

	switch ssagen.Arch.LinkArch.Family {
	case sys.ARM, sys.MIPS:
		if src.IsFloat() {
			switch dst.Kind() {
			case types.TINT64, types.TUINT64:
				return types.TFLOAT64, dst.Kind()
			}
		}
		if dst.IsFloat() {
			switch src.Kind() {
			case types.TINT64, types.TUINT64:
				return src.Kind(), dst.Kind()
			}
		}

	case sys.I386:
		if src.IsFloat() {
			switch dst.Kind() {
			case types.TINT64, types.TUINT64:
				return types.TFLOAT64, dst.Kind()
			case types.TUINT32, types.TUINT, types.TUINTPTR:
				return types.TFLOAT64, types.TUINT32
			}
		}
		if dst.IsFloat() {
			switch src.Kind() {
			case types.TINT64, types.TUINT64:
				return src.Kind(), dst.Kind()
			case types.TUINT32, types.TUINT, types.TUINTPTR:
				return types.TUINT32, types.TFLOAT64
			}
		}
	}
	return types.Txxx, types.Txxx
}

func soleComponent(init *ir.Nodes, n ir.Node) ir.Node {
	if n.Type().SoleComponent() == nil {
		return n
	}
	// Keep in sync with cmd/compile/internal/types/type.go:Type.SoleComponent.
	for {
		switch {
		case n.Type().IsStruct():
			if n.Type().Field(0).Sym.IsBlank() {
				// Treat blank fields as the zero value as the Go language requires.
				n = typecheck.TempAt(base.Pos, ir.CurFunc, n.Type().Field(0).Type)
				appendWalkStmt(init, ir.NewAssignStmt(base.Pos, n, nil))
				continue
			}
			n = typecheck.DotField(n.Pos(), n, 0)
		case n.Type().IsArray():
			n = typecheck.Expr(ir.NewIndexExpr(n.Pos(), n, ir.NewInt(base.Pos, 0)))
		default:
			return n
		}
	}
}

// byteindex converts n, which is byte-sized, to an int used to index into an array.
// We cannot use conv, because we allow converting bool to int here,
// which is forbidden in user code.
func byteindex(n ir.Node) ir.Node {
	// We cannot convert from bool to int directly.
	// While converting from int8 to int is possible, it would yield
	// the wrong result for negative values.
	// Reinterpreting the value as an unsigned byte solves both cases.
	if !types.Identical(n.Type(), types.Types[types.TUINT8]) {
		n = ir.NewConvExpr(base.Pos, ir.OCONV, nil, n)
		n.SetType(types.Types[types.TUINT8])
		n.SetTypecheck(1)
	}
	n = ir.NewConvExpr(base.Pos, ir.OCONV, nil, n)
	n.SetType(types.Types[types.TINT])
	n.SetTypecheck(1)
	return n
}

func walkCheckPtrArithmetic(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	// Calling cheapExpr(n, init) below leads to a recursive call to
	// walkExpr, which leads us back here again. Use n.Checkptr to
	// prevent infinite loops.
	if n.CheckPtr() {
		return n
	}
	n.SetCheckPtr(true)
	defer n.SetCheckPtr(false)

	// TODO(mdempsky): Make stricter. We only need to exempt
	// reflect.Value.Pointer and reflect.Value.UnsafeAddr.
	switch n.X.Op() {
	case ir.OCALLMETH:
		base.FatalfAt(n.X.Pos(), "OCALLMETH missed by typecheck")
	case ir.OCALLFUNC, ir.OCALLINTER:
		return n
	}

	if n.X.Op() == ir.ODOTPTR && ir.IsReflectHeaderDataField(n.X) {
		return n
	}

	// Find original unsafe.Pointer operands involved in this
	// arithmetic expression.
	//
	// "It is valid both to add and to subtract offsets from a
	// pointer in this way. It is also valid to use &^ to round
	// pointers, usually for alignment."
	var originals []ir.Node
	var walk func(n ir.Node)
	walk = func(n ir.Node) {
		switch n.Op() {
		case ir.OADD:
			n := n.(*ir.BinaryExpr)
			walk(n.X)
			walk(n.Y)
		case ir.OSUB, ir.OANDNOT:
			n := n.(*ir.BinaryExpr)
			walk(n.X)
		case ir.OCONVNOP:
			n := n.(*ir.ConvExpr)
			if n.X.Type().IsUnsafePtr() {
				n.X = cheapExpr(n.X, init)
				originals = append(originals, typecheck.ConvNop(n.X, types.Types[types.TUNSAFEPTR]))
			}
		}
	}
	walk(n.X)

	cheap := cheapExpr(n, init)

	slice := typecheck.MakeDotArgs(base.Pos, types.NewSlice(types.Types[types.TUNSAFEPTR]), originals)
	slice.SetEsc(ir.EscNone)

	init.Append(mkcall("checkptrArithmetic", nil, init, typecheck.ConvNop(cheap, types.Types[types.TUNSAFEPTR]), slice))
	// TODO(khr): Mark backing store of slice as dead. This will allow us to reuse
	// the backing store for multiple calls to checkptrArithmetic.

	return cheap
}

// walkSliceToArray walks an OSLICE2ARR expression.
func walkSliceToArray(n *ir.ConvExpr, init *ir.Nodes) ir.Node {
	// Replace T(x) with *(*T)(x).
	conv := typecheck.Expr(ir.NewConvExpr(base.Pos, ir.OCONV, types.NewPtr(n.Type()), n.X)).(*ir.ConvExpr)
	deref := typecheck.Expr(ir.NewStarExpr(base.Pos, conv)).(*ir.StarExpr)

	// The OSLICE2ARRPTR conversion handles checking the slice length,
	// so the dereference can't fail.
	//
	// However, this is more than just an optimization: if T is a
	// zero-length array, then x (and thus (*T)(x)) can be nil, but T(x)
	// should *not* panic. So suppressing the nil check here is
	// necessary for correctness in that case.
	deref.SetBounded(true)

	return walkExpr(deref, init)
}

"""



```