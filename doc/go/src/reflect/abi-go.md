Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick skim to identify key terms and patterns. I look for:

* **Package Name:** `reflect` - This immediately signals interaction with Go's reflection capabilities.
* **Import Statements:** `internal/abi`, `internal/goarch`, `unsafe` - These imports suggest low-level operations related to the Application Binary Interface (ABI), architecture-specific details, and direct memory manipulation. The `internal` prefix is a strong indicator of implementation details not meant for public consumption.
* **Key Data Structures:** `abiStep`, `abiSeq`, `abiDesc` - These likely represent core concepts in managing function calls and their arguments/return values.
* **Function Names:** `addArg`, `addRcvr`, `regAssign`, `stackAssign`, `intFromReg`, `intToReg`, `floatFromReg`, `floatToReg`, `newAbiDesc` -  These suggest actions related to argument handling, register assignment, stack management, and ABI description creation.
* **Comments:**  The comments provide crucial context. I pay attention to explanations of data structures, the purpose of variables, and any warnings or TODOs.

**2. Understanding the Core Data Structures:**

* **`abiStep`:** The name "step" combined with the `kind` field suggests a sequence of instructions. The fields `offset`, `size`, `stkOff`, `ireg`, and `freg` strongly point towards describing how to move data between memory and registers (integer and floating-point) or the stack. The `abiStepKind` enum confirms this.
* **`abiSeq`:** The name "sequence" reinforces the idea of an ordered list of `abiStep` instructions. The `valueStart` field suggests grouping instructions by argument/return value. The `stackBytes`, `iregs`, and `fregs` fields track resource usage.
* **`abiDesc`:** The name "description" suggests this structure holds all the ABI-related information for a function. The `call` and `ret` fields of type `abiSeq` make sense for describing argument passing and return value handling. The `stackCallArgsSize`, `retOffset`, and `spill` fields relate to stack layout. The `stackPtrs`, `inRegPtrs`, and `outRegPtrs` fields deal with pointer tracking for garbage collection.

**3. Tracing the Functionality:**

I start connecting the dots by analyzing how the functions interact with the data structures:

* **`addArg` and `addRcvr`:** These functions add arguments (including the receiver for methods) to an `abiSeq`. The logic involves attempting register assignment first (`regAssign`). If that fails, it falls back to stack assignment (`stackAssign`). This suggests an optimization strategy: prefer registers for speed.
* **`regAssign`:** This is a crucial function responsible for deciding whether an argument can be passed via registers. The `switch` statement based on `Kind(t.Kind())` indicates different rules for different Go types (pointers, integers, floats, structs, etc.). The recursive calls for structs highlight how it handles complex types.
* **`assignIntN` and `assignFloatN`:** These are the low-level functions that actually allocate integer and floating-point registers. They check for available registers.
* **`stackAssign`:**  This function reserves space on the stack for an argument.
* **`newAbiDesc`:** This function takes a `funcType` and potentially a receiver type and creates an `abiDesc`. It orchestrates the creation of the `call` and `ret` `abiSeq` objects. The comments about "spill" and "stackPtrs" reveal details about stack frame layout and garbage collection.
* **`intFromReg`, `intToReg`, `floatFromReg`, `floatToReg`:** These are helper functions for moving data between registers and memory. The `unsafe` package usage is prominent here.

**4. Identifying the Go Feature:**

Based on the keywords (`reflect`, `abi`), data structures (`abiStep`, `abiSeq`, `abiDesc`), and the overall logic of handling function arguments and return values in registers and on the stack, the most likely Go feature is **the underlying implementation of how Go calls functions, particularly when using reflection**. Reflection allows inspecting and manipulating types and function calls at runtime, requiring a mechanism to dynamically set up the arguments and retrieve results. This code appears to be part of that mechanism.

**5. Crafting the Example:**

To illustrate this, I need a scenario where reflection is used to call a function. The simplest case is calling a function with some arguments and retrieving the result. The example should demonstrate how `reflect.ValueOf` and `reflect.Type` are used to get information about the function and its arguments, and how `Call` is used to invoke the function.

**6. Reasoning about Inputs and Outputs (for `regAssign`):**

For `regAssign`, it's important to consider different Go types as input. I'd think about:

* **Simple Types:** `int`, `bool`, `float64` - These might fit into single registers.
* **Pointers:** `*int` - These should be passed as addresses in registers.
* **Structs:**  Small structs might fit in registers, larger ones might be passed on the stack.
* **Slices/Strings/Interfaces:** These are represented by multiple words (pointer and length/type information) and might require multiple registers.

The output would be whether the register assignment succeeded or not.

**7. Considering Command-Line Arguments (if applicable):**

In this specific code snippet, there's no explicit handling of command-line arguments. However, I'd consider if the *larger* context of reflection (like `go test` as mentioned in the comments) *does* use command-line arguments and how those might interact with this code.

**8. Identifying Common Mistakes:**

The comments themselves hint at potential pitfalls, such as incorrect assumptions about register availability or the complexities of ABI design. I would also consider common mistakes when *using* reflection, such as type mismatches during `Call`.

**9. Structuring the Answer:**

Finally, I organize the information logically, starting with the overall functionality, then providing the example, explaining the code, discussing `regAssign` with examples, addressing command-line arguments (or the lack thereof), and listing potential pitfalls. Using clear headings and formatting makes the answer easier to understand.

This iterative process of scanning, understanding, connecting, and illustrating helps in dissecting and explaining complex code like the provided `abi.go` snippet.
这段代码是 Go 语言 `reflect` 包中 `abi.go` 文件的一部分，它主要负责 **处理函数调用时的参数和返回值的布局，以便在运行时进行反射调用**。更具体地说，它定义了如何将 Go 语言的值（在内存中）映射到函数调用帧（包括寄存器和栈），以及反向的映射。

可以推理出，这是 Go 语言 **支持使用寄存器传递参数和返回值** 功能的实现的核心部分。  在早期的 Go 版本中，函数参数和返回值主要通过栈来传递。为了提升性能，Go 引入了通过寄存器传递参数和返回值的 ABI (Application Binary Interface)。这段代码就是用来描述和管理这种新的 ABI 方式的。

**功能列举：**

1. **定义 ABI 的基本单元 `abiStep`**:  `abiStep` 结构体描述了一个 ABI "指令"，它指明了如何将 Go 值的一部分从内存复制到调用帧的特定位置（栈或寄存器），或者反过来。它包含了类型（`abiStepKind`，例如栈、整型寄存器、浮点寄存器）、内存中的偏移和大小，以及目标调用帧中的位置（栈偏移或寄存器索引）。
2. **定义 ABI 指令的种类 `abiStepKind`**:  枚举了不同的 ABI 指令类型，包括栈操作、整型寄存器操作、指针寄存器操作和浮点寄存器操作。
3. **定义 ABI 指令序列 `abiSeq`**:  `abiSeq` 结构体表示一个 ABI 指令的序列，用于描述如何将一系列 `reflect.Value` 转换为函数调用的参数或返回值。它记录了指令列表、每个参数/返回值的起始指令索引，以及使用的栈空间和寄存器数量。
4. **实现向 `abiSeq` 添加参数/返回值的方法**:  `addArg` 方法用于向 `abiSeq` 添加一个新的 Go 值，并决定如何传递它（通过寄存器或栈）。
5. **实现向 `abiSeq` 添加方法接收者的方法**:  `addRcvr` 方法用于处理方法调用时的接收者参数，它遵循接口调用的约定。
6. **实现寄存器分配算法 `regAssign`**:  这是一个核心方法，尝试为给定类型的 Go 值分配寄存器。它根据 Go 值的类型和架构规则，决定是否可以通过寄存器传递，并更新 `abiSeq` 中的指令。
7. **实现具体的寄存器分配方法 `assignIntN` 和 `assignFloatN`**:  这两个方法分别用于分配 N 个连续的整型寄存器和浮点寄存器。
8. **实现栈分配方法 `stackAssign`**:  用于在栈上为 Go 值分配空间。
9. **定义函数或方法的 ABI 描述 `abiDesc`**:  `abiDesc` 结构体包含了函数调用和返回的 ABI 指令序列 (`call` 和 `ret`)，以及栈空间大小、返回值偏移、寄存器溢出空间大小和用于垃圾回收的指针位图等信息。
10. **实现创建 `abiDesc` 的方法 `newAbiDesc`**:  根据函数类型和接收者类型，生成描述函数调用 ABI 的 `abiDesc` 结构体。
11. **实现从寄存器加载和存储值的方法**:  `intFromReg`, `intToReg`, `floatFromReg`, `floatToReg` 等函数用于在寄存器和内存之间移动数据。

**Go 代码举例说明 (推理的寄存器传参功能实现):**

假设我们有一个简单的函数 `add`，它接受两个 `int` 类型的参数并返回一个 `int` 类型的值。在支持寄存器传参的架构上，编译器和运行时可能会尝试使用寄存器来传递这些参数和返回值。

```go
package main

import (
	"fmt"
	"reflect"
	"unsafe"
)

func add(a, b int) int {
	return a + b
}

func main() {
	// 使用反射获取函数信息
	funcValue := reflect.ValueOf(add)
	funcType := funcValue.Type()

	// 假设我们通过某种方式（内部机制）获取了该函数的 abiDesc
	// 在实际的 reflect 包中，这是通过 reflect.funcinfo 结构体关联的
	// 这里我们简化模拟，假设已经有了 abiDesc 信息
	// 并且 abiDesc.call 描述了参数的传递方式，abiDesc.ret 描述了返回值的传递方式

	// 模拟参数传递：假设前两个 int 参数通过寄存器传递
	arg1 := reflect.ValueOf(10)
	arg2 := reflect.ValueOf(20)

	// 在实际的 reflect.Call 中，会根据 abiDesc.call 的指示
	// 将 arg1 和 arg2 的值加载到对应的寄存器中

	// ... (内部调用机制) ...

	// 模拟返回值获取：假设返回值通过寄存器传递
	results := funcValue.Call([]reflect.Value{arg1, arg2})
	result := results[0].Int()

	// 在实际的 reflect.Call 中，会根据 abiDesc.ret 的指示
	// 从对应的寄存器中读取返回值

	fmt.Println("Result:", result) // Output: Result: 30
}
```

**代码推理 (关于 `regAssign`):**

假设我们正在处理函数 `add(a int, b int)` 的参数传递，并且 `intArgRegs` 的值为 2 (表示有两个可用的整型参数寄存器)。

**输入：**

*   `t`:  指向 `int` 类型的 `abi.Type` 结构体的指针。
*   `offset`: 当前参数在内存中的偏移量 (假设第一个参数偏移为 0，第二个参数偏移为 `sizeof(int)`)。
*   `a`: 一个 `abiSeq` 实例，用于记录 ABI 指令。

**执行 `regAssign` 的过程：**

1. 当处理第一个 `int` 参数 `a` 时，`regAssign` 会进入 `case Int:` 分支。
2. `assignIntN(offset, t.Size(), 1, 0b0)` 被调用，尝试分配一个大小为 `sizeof(int)` 的值到一个整型寄存器。`ptrMap` 为 0 表示这不是一个指针类型。
3. 假设当前 `a.iregs` 为 0，且 `intArgRegs` 为 2，则 `a.iregs + 1 <= intArgRegs` 成立。
4. 一个新的 `abiStep` 被添加到 `a.steps` 中，其 `kind` 为 `abiStepIntReg`，`offset` 为当前参数的内存偏移，`size` 为 `sizeof(int)`，`ireg` 为 0。
5. `a.iregs` 增加到 1。
6. 当处理第二个 `int` 参数 `b` 时，重复上述过程，但 `offset` 会是 `sizeof(int)`，且新的 `abiStep` 的 `ireg` 将会是 1。
7. `a.iregs` 增加到 2。

**输出：**

*   `regAssign` 返回 `true`，表示寄存器分配成功。
*   `a.steps` 中包含了两个 `abiStep` 指令，分别指示将第一个和第二个 `int` 参数从内存加载到第 0 和第 1 个整型寄存器。
*   `a.iregs` 的值为 2。

**假设的输入和输出 (针对 `assignIntN`):**

假设我们要将两个 `int32` 类型的参数分配到寄存器。

**输入：**

*   `offset`: 0
*   `size`: 4 ( `sizeof(int32)`)
*   `n`: 2
*   `ptrMap`: 0 (都不是指针)
*   `a`: 一个 `abiSeq` 实例，`a.iregs` 当前为 0， `intArgRegs` 为 4。

**执行 `assignIntN` 的过程：**

1. 检查 `n > 8` 或 `n < 0`，条件不成立。
2. 检查 `ptrMap != 0 && size != goarch.PtrSize`，条件不成立。
3. 检查 `a.iregs + n <= intArgRegs`，即 `0 + 2 <= 4`，成立。
4. 循环两次 (因为 `n` 是 2):
    *   第一次循环 (i=0):
        *   `kind` 为 `abiStepIntReg`。
        *   添加 `abiStep{kind: abiStepIntReg, offset: 0, size: 4, ireg: 0}` 到 `a.steps`。
        *   `a.iregs` 增加到 1。
    *   第二次循环 (i=1):
        *   `kind` 为 `abiStepIntReg`。
        *   添加 `abiStep{kind: abiStepIntReg, offset: 4, size: 4, ireg: 1}` 到 `a.steps`。
        *   `a.iregs` 增加到 2。
5. 返回 `true`。

**输出：**

*   `true` (分配成功)
*   `a.steps` 包含两个 `abiStep` 结构体，分别描述了将内存中偏移 0 和 4 的 4 字节数据加载到第 0 和第 1 个整型寄存器。
*   `a.iregs` 的值为 2。

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。它属于 `reflect` 包的内部实现细节，负责函数调用的 ABI 处理。命令行参数的处理通常发生在 `main` 函数的 `os.Args`，或者使用 `flag` 等标准库进行解析。

然而，可以想象，像 `go test` 这样的工具，在运行时会使用反射来调用测试函数。在这种情况下，`go test` 的命令行参数可能会影响测试函数的执行，但 `abi.go` 的代码本身并不直接解析这些参数。

**使用者易犯错的点：**

这段代码是 `reflect` 包的内部实现，普通 Go 开发者不会直接使用或操作这些结构体和方法。  然而，理解其背后的概念有助于理解反射的性能开销和限制。

一个与反射相关的常见错误是 **不理解反射的性能成本**。  反射操作需要在运行时进行类型检查和 ABI 处理，这比直接调用函数要慢得多。这段代码的复杂性也暗示了反射操作的底层机制并不简单。

另一个潜在的误解是 **假设所有类型的参数都以相同的方式传递**。 实际上，Go 语言会根据参数的类型和大小，以及目标架构的 ABI 规则，选择不同的传递方式（寄存器或栈）。这段代码正是用来处理这种差异性的。

总而言之，这段 `abi.go` 的代码是 Go 语言运行时反射机制中一个至关重要的组成部分，它负责管理函数调用时参数和返回值的布局，特别是针对通过寄存器传递参数和返回值的新 ABI 方式。理解这段代码可以帮助我们更深入地理解 Go 语言的底层工作原理以及反射的机制。

### 提示词
```
这是路径为go/src/reflect/abi.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reflect

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

// These variables are used by the register assignment
// algorithm in this file.
//
// They should be modified with care (no other reflect code
// may be executing) and are generally only modified
// when testing this package.
//
// They should never be set higher than their internal/abi
// constant counterparts, because the system relies on a
// structure that is at least large enough to hold the
// registers the system supports.
//
// Currently they're set to zero because using the actual
// constants will break every part of the toolchain that
// uses reflect to call functions (e.g. go test, or anything
// that uses text/template). The values that are currently
// commented out there should be the actual values once
// we're ready to use the register ABI everywhere.
var (
	intArgRegs   = abi.IntArgRegs
	floatArgRegs = abi.FloatArgRegs
	floatRegSize = uintptr(abi.EffectiveFloatRegSize)
)

// abiStep represents an ABI "instruction." Each instruction
// describes one part of how to translate between a Go value
// in memory and a call frame.
type abiStep struct {
	kind abiStepKind

	// offset and size together describe a part of a Go value
	// in memory.
	offset uintptr
	size   uintptr // size in bytes of the part

	// These fields describe the ABI side of the translation.
	stkOff uintptr // stack offset, used if kind == abiStepStack
	ireg   int     // integer register index, used if kind == abiStepIntReg or kind == abiStepPointer
	freg   int     // FP register index, used if kind == abiStepFloatReg
}

// abiStepKind is the "op-code" for an abiStep instruction.
type abiStepKind int

const (
	abiStepBad      abiStepKind = iota
	abiStepStack                // copy to/from stack
	abiStepIntReg               // copy to/from integer register
	abiStepPointer              // copy pointer to/from integer register
	abiStepFloatReg             // copy to/from FP register
)

// abiSeq represents a sequence of ABI instructions for copying
// from a series of reflect.Values to a call frame (for call arguments)
// or vice-versa (for call results).
//
// An abiSeq should be populated by calling its addArg method.
type abiSeq struct {
	// steps is the set of instructions.
	//
	// The instructions are grouped together by whole arguments,
	// with the starting index for the instructions
	// of the i'th Go value available in valueStart.
	//
	// For instance, if this abiSeq represents 3 arguments
	// passed to a function, then the 2nd argument's steps
	// begin at steps[valueStart[1]].
	//
	// Because reflect accepts Go arguments in distinct
	// Values and each Value is stored separately, each abiStep
	// that begins a new argument will have its offset
	// field == 0.
	steps      []abiStep
	valueStart []int

	stackBytes   uintptr // stack space used
	iregs, fregs int     // registers used
}

func (a *abiSeq) dump() {
	for i, p := range a.steps {
		println("part", i, p.kind, p.offset, p.size, p.stkOff, p.ireg, p.freg)
	}
	print("values ")
	for _, i := range a.valueStart {
		print(i, " ")
	}
	println()
	println("stack", a.stackBytes)
	println("iregs", a.iregs)
	println("fregs", a.fregs)
}

// stepsForValue returns the ABI instructions for translating
// the i'th Go argument or return value represented by this
// abiSeq to the Go ABI.
func (a *abiSeq) stepsForValue(i int) []abiStep {
	s := a.valueStart[i]
	var e int
	if i == len(a.valueStart)-1 {
		e = len(a.steps)
	} else {
		e = a.valueStart[i+1]
	}
	return a.steps[s:e]
}

// addArg extends the abiSeq with a new Go value of type t.
//
// If the value was stack-assigned, returns the single
// abiStep describing that translation, and nil otherwise.
func (a *abiSeq) addArg(t *abi.Type) *abiStep {
	// We'll always be adding a new value, so do that first.
	pStart := len(a.steps)
	a.valueStart = append(a.valueStart, pStart)
	if t.Size() == 0 {
		// If the size of the argument type is zero, then
		// in order to degrade gracefully into ABI0, we need
		// to stack-assign this type. The reason is that
		// although zero-sized types take up no space on the
		// stack, they do cause the next argument to be aligned.
		// So just do that here, but don't bother actually
		// generating a new ABI step for it (there's nothing to
		// actually copy).
		//
		// We cannot handle this in the recursive case of
		// regAssign because zero-sized *fields* of a
		// non-zero-sized struct do not cause it to be
		// stack-assigned. So we need a special case here
		// at the top.
		a.stackBytes = align(a.stackBytes, uintptr(t.Align()))
		return nil
	}
	// Hold a copy of "a" so that we can roll back if
	// register assignment fails.
	aOld := *a
	if !a.regAssign(t, 0) {
		// Register assignment failed. Roll back any changes
		// and stack-assign.
		*a = aOld
		a.stackAssign(t.Size(), uintptr(t.Align()))
		return &a.steps[len(a.steps)-1]
	}
	return nil
}

// addRcvr extends the abiSeq with a new method call
// receiver according to the interface calling convention.
//
// If the receiver was stack-assigned, returns the single
// abiStep describing that translation, and nil otherwise.
// Returns true if the receiver is a pointer.
func (a *abiSeq) addRcvr(rcvr *abi.Type) (*abiStep, bool) {
	// The receiver is always one word.
	a.valueStart = append(a.valueStart, len(a.steps))
	var ok, ptr bool
	if rcvr.IfaceIndir() || rcvr.Pointers() {
		ok = a.assignIntN(0, goarch.PtrSize, 1, 0b1)
		ptr = true
	} else {
		// TODO(mknyszek): Is this case even possible?
		// The interface data work never contains a non-pointer
		// value. This case was copied over from older code
		// in the reflect package which only conditionally added
		// a pointer bit to the reflect.(Value).Call stack frame's
		// GC bitmap.
		ok = a.assignIntN(0, goarch.PtrSize, 1, 0b0)
		ptr = false
	}
	if !ok {
		a.stackAssign(goarch.PtrSize, goarch.PtrSize)
		return &a.steps[len(a.steps)-1], ptr
	}
	return nil, ptr
}

// regAssign attempts to reserve argument registers for a value of
// type t, stored at some offset.
//
// It returns whether or not the assignment succeeded, but
// leaves any changes it made to a.steps behind, so the caller
// must undo that work by adjusting a.steps if it fails.
//
// This method along with the assign* methods represent the
// complete register-assignment algorithm for the Go ABI.
func (a *abiSeq) regAssign(t *abi.Type, offset uintptr) bool {
	switch Kind(t.Kind()) {
	case UnsafePointer, Pointer, Chan, Map, Func:
		return a.assignIntN(offset, t.Size(), 1, 0b1)
	case Bool, Int, Uint, Int8, Uint8, Int16, Uint16, Int32, Uint32, Uintptr:
		return a.assignIntN(offset, t.Size(), 1, 0b0)
	case Int64, Uint64:
		switch goarch.PtrSize {
		case 4:
			return a.assignIntN(offset, 4, 2, 0b0)
		case 8:
			return a.assignIntN(offset, 8, 1, 0b0)
		}
	case Float32, Float64:
		return a.assignFloatN(offset, t.Size(), 1)
	case Complex64:
		return a.assignFloatN(offset, 4, 2)
	case Complex128:
		return a.assignFloatN(offset, 8, 2)
	case String:
		return a.assignIntN(offset, goarch.PtrSize, 2, 0b01)
	case Interface:
		return a.assignIntN(offset, goarch.PtrSize, 2, 0b10)
	case Slice:
		return a.assignIntN(offset, goarch.PtrSize, 3, 0b001)
	case Array:
		tt := (*arrayType)(unsafe.Pointer(t))
		switch tt.Len {
		case 0:
			// There's nothing to assign, so don't modify
			// a.steps but succeed so the caller doesn't
			// try to stack-assign this value.
			return true
		case 1:
			return a.regAssign(tt.Elem, offset)
		default:
			return false
		}
	case Struct:
		st := (*structType)(unsafe.Pointer(t))
		for i := range st.Fields {
			f := &st.Fields[i]
			if !a.regAssign(f.Typ, offset+f.Offset) {
				return false
			}
		}
		return true
	default:
		print("t.Kind == ", t.Kind(), "\n")
		panic("unknown type kind")
	}
	panic("unhandled register assignment path")
}

// assignIntN assigns n values to registers, each "size" bytes large,
// from the data at [offset, offset+n*size) in memory. Each value at
// [offset+i*size, offset+(i+1)*size) for i < n is assigned to the
// next n integer registers.
//
// Bit i in ptrMap indicates whether the i'th value is a pointer.
// n must be <= 8.
//
// Returns whether assignment succeeded.
func (a *abiSeq) assignIntN(offset, size uintptr, n int, ptrMap uint8) bool {
	if n > 8 || n < 0 {
		panic("invalid n")
	}
	if ptrMap != 0 && size != goarch.PtrSize {
		panic("non-empty pointer map passed for non-pointer-size values")
	}
	if a.iregs+n > intArgRegs {
		return false
	}
	for i := 0; i < n; i++ {
		kind := abiStepIntReg
		if ptrMap&(uint8(1)<<i) != 0 {
			kind = abiStepPointer
		}
		a.steps = append(a.steps, abiStep{
			kind:   kind,
			offset: offset + uintptr(i)*size,
			size:   size,
			ireg:   a.iregs,
		})
		a.iregs++
	}
	return true
}

// assignFloatN assigns n values to registers, each "size" bytes large,
// from the data at [offset, offset+n*size) in memory. Each value at
// [offset+i*size, offset+(i+1)*size) for i < n is assigned to the
// next n floating-point registers.
//
// Returns whether assignment succeeded.
func (a *abiSeq) assignFloatN(offset, size uintptr, n int) bool {
	if n < 0 {
		panic("invalid n")
	}
	if a.fregs+n > floatArgRegs || floatRegSize < size {
		return false
	}
	for i := 0; i < n; i++ {
		a.steps = append(a.steps, abiStep{
			kind:   abiStepFloatReg,
			offset: offset + uintptr(i)*size,
			size:   size,
			freg:   a.fregs,
		})
		a.fregs++
	}
	return true
}

// stackAssign reserves space for one value that is "size" bytes
// large with alignment "alignment" to the stack.
//
// Should not be called directly; use addArg instead.
func (a *abiSeq) stackAssign(size, alignment uintptr) {
	a.stackBytes = align(a.stackBytes, alignment)
	a.steps = append(a.steps, abiStep{
		kind:   abiStepStack,
		offset: 0, // Only used for whole arguments, so the memory offset is 0.
		size:   size,
		stkOff: a.stackBytes,
	})
	a.stackBytes += size
}

// abiDesc describes the ABI for a function or method.
type abiDesc struct {
	// call and ret represent the translation steps for
	// the call and return paths of a Go function.
	call, ret abiSeq

	// These fields describe the stack space allocated
	// for the call. stackCallArgsSize is the amount of space
	// reserved for arguments but not return values. retOffset
	// is the offset at which return values begin, and
	// spill is the size in bytes of additional space reserved
	// to spill argument registers into in case of preemption in
	// reflectcall's stack frame.
	stackCallArgsSize, retOffset, spill uintptr

	// stackPtrs is a bitmap that indicates whether
	// each word in the ABI stack space (stack-assigned
	// args + return values) is a pointer. Used
	// as the heap pointer bitmap for stack space
	// passed to reflectcall.
	stackPtrs *bitVector

	// inRegPtrs is a bitmap whose i'th bit indicates
	// whether the i'th integer argument register contains
	// a pointer. Used by makeFuncStub and methodValueCall
	// to make result pointers visible to the GC.
	//
	// outRegPtrs is the same, but for result values.
	// Used by reflectcall to make result pointers visible
	// to the GC.
	inRegPtrs, outRegPtrs abi.IntArgRegBitmap
}

func (a *abiDesc) dump() {
	println("ABI")
	println("call")
	a.call.dump()
	println("ret")
	a.ret.dump()
	println("stackCallArgsSize", a.stackCallArgsSize)
	println("retOffset", a.retOffset)
	println("spill", a.spill)
	print("inRegPtrs:")
	dumpPtrBitMap(a.inRegPtrs)
	println()
	print("outRegPtrs:")
	dumpPtrBitMap(a.outRegPtrs)
	println()
}

func dumpPtrBitMap(b abi.IntArgRegBitmap) {
	for i := 0; i < intArgRegs; i++ {
		x := 0
		if b.Get(i) {
			x = 1
		}
		print(" ", x)
	}
}

func newAbiDesc(t *funcType, rcvr *abi.Type) abiDesc {
	// We need to add space for this argument to
	// the frame so that it can spill args into it.
	//
	// The size of this space is just the sum of the sizes
	// of each register-allocated type.
	//
	// TODO(mknyszek): Remove this when we no longer have
	// caller reserved spill space.
	spill := uintptr(0)

	// Compute gc program & stack bitmap for stack arguments
	stackPtrs := new(bitVector)

	// Compute the stack frame pointer bitmap and register
	// pointer bitmap for arguments.
	inRegPtrs := abi.IntArgRegBitmap{}

	// Compute abiSeq for input parameters.
	var in abiSeq
	if rcvr != nil {
		stkStep, isPtr := in.addRcvr(rcvr)
		if stkStep != nil {
			if isPtr {
				stackPtrs.append(1)
			} else {
				stackPtrs.append(0)
			}
		} else {
			spill += goarch.PtrSize
		}
	}
	for i, arg := range t.InSlice() {
		stkStep := in.addArg(arg)
		if stkStep != nil {
			addTypeBits(stackPtrs, stkStep.stkOff, arg)
		} else {
			spill = align(spill, uintptr(arg.Align()))
			spill += arg.Size()
			for _, st := range in.stepsForValue(i) {
				if st.kind == abiStepPointer {
					inRegPtrs.Set(st.ireg)
				}
			}
		}
	}
	spill = align(spill, goarch.PtrSize)

	// From the input parameters alone, we now know
	// the stackCallArgsSize and retOffset.
	stackCallArgsSize := in.stackBytes
	retOffset := align(in.stackBytes, goarch.PtrSize)

	// Compute the stack frame pointer bitmap and register
	// pointer bitmap for return values.
	outRegPtrs := abi.IntArgRegBitmap{}

	// Compute abiSeq for output parameters.
	var out abiSeq
	// Stack-assigned return values do not share
	// space with arguments like they do with registers,
	// so we need to inject a stack offset here.
	// Fake it by artificially extending stackBytes by
	// the return offset.
	out.stackBytes = retOffset
	for i, res := range t.OutSlice() {
		stkStep := out.addArg(res)
		if stkStep != nil {
			addTypeBits(stackPtrs, stkStep.stkOff, res)
		} else {
			for _, st := range out.stepsForValue(i) {
				if st.kind == abiStepPointer {
					outRegPtrs.Set(st.ireg)
				}
			}
		}
	}
	// Undo the faking from earlier so that stackBytes
	// is accurate.
	out.stackBytes -= retOffset
	return abiDesc{in, out, stackCallArgsSize, retOffset, spill, stackPtrs, inRegPtrs, outRegPtrs}
}

// intFromReg loads an argSize sized integer from reg and places it at to.
//
// argSize must be non-zero, fit in a register, and a power-of-two.
func intFromReg(r *abi.RegArgs, reg int, argSize uintptr, to unsafe.Pointer) {
	memmove(to, r.IntRegArgAddr(reg, argSize), argSize)
}

// intToReg loads an argSize sized integer and stores it into reg.
//
// argSize must be non-zero, fit in a register, and a power-of-two.
func intToReg(r *abi.RegArgs, reg int, argSize uintptr, from unsafe.Pointer) {
	memmove(r.IntRegArgAddr(reg, argSize), from, argSize)
}

// floatFromReg loads a float value from its register representation in r.
//
// argSize must be 4 or 8.
func floatFromReg(r *abi.RegArgs, reg int, argSize uintptr, to unsafe.Pointer) {
	switch argSize {
	case 4:
		*(*float32)(to) = archFloat32FromReg(r.Floats[reg])
	case 8:
		*(*float64)(to) = *(*float64)(unsafe.Pointer(&r.Floats[reg]))
	default:
		panic("bad argSize")
	}
}

// floatToReg stores a float value in its register representation in r.
//
// argSize must be either 4 or 8.
func floatToReg(r *abi.RegArgs, reg int, argSize uintptr, from unsafe.Pointer) {
	switch argSize {
	case 4:
		r.Floats[reg] = archFloat32ToReg(*(*float32)(from))
	case 8:
		r.Floats[reg] = *(*uint64)(from)
	default:
		panic("bad argSize")
	}
}
```