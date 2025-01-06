Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Structure:** The first thing that jumps out is the `opcodeTable` variable. It's a slice of structs. Each struct seems to define an "operation" or "opcode". This immediately suggests that this code is about *defining a set of operations*.

2. **Examine the Struct Fields:**  Look at the fields within the struct: `name`, `argLen`, `auxType`, `call`, `generic`, etc. These fields provide clues about the *properties* of each operation.

    * `name`:  The human-readable name of the operation (e.g., "Load", "Store", "Add32").
    * `argLen`: The number of arguments the operation takes. `-1` likely means a variable number of arguments.
    * `auxType`:  An "auxiliary type."  This hints at additional information associated with the operation, potentially related to data types or symbols.
    * `call`: A boolean indicating if this operation represents a function call.
    * `generic`:  Likely indicates if the operation is generic or specific to a certain type.
    * Other fields like `zeroWidth`, `nilCheck`, `symEffect`, `hasSideEffects`, `unsafePoint`, `resultInArg0`, `commutative`, `scale`, `asm`, `tailCall`  provide more specific characteristics.

3. **Infer the Purpose:** Based on the structure and fields, it's highly likely this code defines the set of *intermediate representation operations* used by the Go compiler. Specifically, given the `ssa` package in the path, it's for the *Static Single Assignment* (SSA) form of the intermediate representation. SSA is a common way compilers represent code before generating machine code.

4. **Connect to Go Language Features:** Now, the request asks to connect these operations to Go language features. Think about the different kinds of things you do in Go code:

    * **Memory Access:**  `Load`, `Store`, `Move`, `Zero`, `Dereference` clearly relate to reading and writing memory. This is fundamental to any programming language.
    * **Arithmetic and Logic:**  While not explicitly shown in this snippet,  other parts of `opGen.go` likely define operations like `Add`, `Sub`, `Mul`, `Div`, `And`, `Or`, etc., corresponding to Go's arithmetic and logical operators.
    * **Function Calls:**  `ClosureCall`, `StaticCall`, `InterCall`, `TailCall` directly map to function invocation.
    * **Type Conversions:**  The numerous `Cvt...`, `SignExt...`, `ZeroExt...`, `Trunc...` operations handle Go's type conversion rules.
    * **Control Flow (Implicit):** While not directly listed as "If" or "Goto", the existence of these low-level ops allows for the *construction* of control flow within the SSA representation.
    * **Data Structures:** `SliceMake`, `StringMake`, `ComplexMake`, `IMake`, `StructMake`, `ArrayMake` relate to the creation of Go's built-in data structures.
    * **Pointers and Addresses:** `PtrIndex`, `OffPtr`, `SlicePtr`, `StringPtr` deal with pointer manipulation.
    * **Concurrency/Atomicity:** The `AtomicLoad...`, `AtomicStore...`, `AtomicCompareAndSwap...` operations are essential for implementing safe concurrent operations in Go.
    * **Panic/Error Handling:** `PanicBounds`, `PanicExtend` relate to runtime error conditions.
    * **Runtime Support:** `GetG`, `GetClosurePtr`, `GetCallerPC`, `GetCallerSP` provide access to Go's runtime information.

5. **Construct Example Code:** Choose a few representative operations and illustrate them with Go code. The `Load` and `Store` operations are good starting points because they are fundamental. Type conversions are another good area to demonstrate. Function calls are also important.

6. **Consider Command-line Arguments (If Applicable):**  The prompt specifically asks about command-line arguments. *For this specific snippet*, there's no direct handling of command-line arguments. This code is about defining data structures used *within* the compiler. However, recognize that the compiler itself (`go build`, `go run`) takes command-line arguments, and those arguments influence the *overall* compilation process, which would eventually *use* these opcodes.

7. **Identify Potential Pitfalls:** Think about how a *user* of the Go language might misunderstand or misuse the concepts represented by these operations. For instance, incorrect type conversions can lead to subtle bugs. Forgetting about the implications of atomic operations in concurrent code is another common mistake.

8. **Synthesize the Overall Function:**  Finally, step back and summarize the role of this code within the broader Go compilation process. It's about defining the vocabulary and grammar of the intermediate language that the compiler uses to reason about and transform Go code before generating machine code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this is about assembler instructions?  *Correction:* The `Asm()` method suggests a *connection* to assembly, but the higher-level names and the `ssa` package point towards an intermediate representation.
* **Realization:**  The sheer number of operations suggests a comprehensive representation of Go's semantics. It's not just a small set of basic instructions.
* **Understanding `generic`:**  This likely means the operation's behavior is similar across different data types, and the specific type is handled by other parts of the compiler.
* **Recognizing the "Part X of Y"**: The prompt mentions "part 18 of 18". This is crucial. It indicates this is the *final* piece of the `opGen.go` file. Therefore, the *summary* should reflect the *complete* functionality of opcode generation.

By following these steps, combining deduction with knowledge of compiler design and Go language features, you can arrive at a comprehensive and accurate explanation of the provided code snippet.
这个go语言文件的片段定义了一个名为 `opcodeTable` 的常量，它是一个 `op` 结构体类型的切片。每个 `op` 结构体定义了一个**操作码（opcode）**，用于表示在**静态单赋值（SSA）**中间表示形式中的一个操作。

**它的主要功能是：**

1. **定义了所有可能的 SSA 操作:**  `opcodeTable` 列举了 Go 编译器在将 Go 源代码转换为机器码的过程中使用的所有抽象操作。 这些操作涵盖了各种底层操作，例如：
    * **内存访问:** `Load`, `Store`, `Move`, `Zero`, `Dereference`
    * **算术和逻辑运算:** (虽然这里没展示，但其他部分会定义 `Add`, `Sub`, `Mul`, `Div`, `And`, `Or` 等)
    * **类型转换:** `SignExt`, `ZeroExt`, `Trunc`, `Cvt` 等
    * **函数调用:** `ClosureCall`, `StaticCall`, `InterCall`, `TailCall`
    * **控制流 (隐含):**  虽然没有直接的 `If` 或 `Goto`，但这些低级操作可以构建控制流结构。
    * **数据结构操作:** `SliceMake`, `StringMake`, `ComplexMake`, `IMake`, `StructMake`, `ArrayMake` 等
    * **指针操作:** `PtrIndex`, `OffPtr`
    * **原子操作:** `AtomicLoad`, `AtomicStore`, `AtomicCompareAndSwap` 等
    * **Panic 和错误处理:** `PanicBounds`, `PanicExtend`
    * **运行时支持:** `GetG`, `GetClosurePtr`, `GetCallerPC`, `GetCallerSP`
    * **垃圾回收相关的操作:** `WB` (Write Barrier) 相关操作

2. **为每个操作码提供元数据:**  每个 `op` 结构体包含了关于对应操作码的各种元数据，例如：
    * `name`: 操作码的名称（字符串形式）。
    * `argLen`:  操作码期望的参数数量。 `-1` 表示可变数量的参数。
    * `auxType`: 辅助值的类型，用于存储额外的信息，例如类型信息、偏移量、符号等。
    * `zeroWidth`:  是否是零宽度操作（不产生实际的机器代码，通常用于标记）。
    * `generic`: 是否是泛型操作。
    * `call`: 是否表示函数调用。
    * `tailCall`: 是否是尾调用。
    * `hasSideEffects`: 是否有副作用。
    * `unsafePoint`: 是否是 unsafe point（可能导致垃圾回收）。
    * `resultInArg0`: 结果是否存放在第一个参数中。
    * `symEffect`: 符号的影响 (SymNone, SymRead, 等)。
    * `commutative`: 是否满足交换律。

3. **提供了访问操作码属性的方法:**  后续定义的 `Asm()`, `Scale()`, `String()`, `SymEffect()`, `IsCall()`, `IsTailCall()`, `HasSideEffects()`, `UnsafePoint()`, `ResultInArg0()` 这些方法允许通过 `Op` 类型的值来访问 `opcodeTable` 中对应操作码的属性。

**可以推理出这是 Go 编译器中 SSA 中间表示的定义部分。**  SSA 是一种编译器内部使用的代码表示形式，它的特点是每个变量只被赋值一次。 `opGen.go` 文件通常用于生成与操作码相关的代码，包括操作码的定义、属性以及可能的代码生成逻辑。

**Go 代码举例说明:**

虽然不能直接写出使用这些 `Op` 常量的 Go 代码，因为这是编译器内部使用的，但可以模拟一下这些操作码在编译器内部是如何表示和使用的。

**假设的输入 (编译器内部的 SSA 表示):**

```
// 假设我们有如下的 Go 代码
// var x int
// y := x + 1

// 编译器内部可能会将 "x + 1" 表示为 SSA 指令
// v1 = Load [address of x]  // 使用 Load 操作码
// v2 = ConstInt 1           // 假设有 ConstInt 操作码表示常量
// v3 = Add v1 v2             // 假设有 Add 操作码表示加法
// Store v3 [address of y]   // 使用 Store 操作码
```

**对应的 `Op` 使用 (编译器内部逻辑):**

```go
package main

import "fmt"

// 模拟 Op 类型和 opcodeTable (简化)
type Op int

const (
	Load Op = iota
	Store
	Add
	ConstInt
)

type opData struct {
	name   string
	argLen int
}

var opcodeTable = []opData{
	{name: "Load", argLen: 1},
	{name: "Store", argLen: 2},
	{name: "Add", argLen: 2},
	{name: "ConstInt", argLen: 1},
}

func (o Op) String() string {
	return opcodeTable[o].name
}

func main() {
	// 模拟编译器内部的 SSA 指令
	instructions := []struct {
		op   Op
		args []string
	}{
		{op: Load, args: []string{"[address of x]"}},
		{op: ConstInt, args: []string{"1"}},
		{op: Add, args: []string{"v1", "v2"}},
		{op: Store, args: []string{"v3", "[address of y]"}},
	}

	for _, instruction := range instructions {
		fmt.Printf("%s", instruction.op)
		if len(instruction.args) > 0 {
			fmt.Printf(" %v", instruction.args)
		}
		fmt.Println()
	}
}
```

**假设的输出:**

```
Load [address of x]
ConstInt [1]
Add [v1 v2]
Store [v3 [address of y]]
```

**代码推理:**

代码片段中定义的操作码，例如 `Load` 和 `Store`，在编译器的 SSA 生成阶段会被用来表示对内存的读取和写入操作。其他操作码则对应不同的计算或控制流程。编译器会根据 Go 源代码的语义，生成一系列的 SSA 指令，这些指令由定义在 `opcodeTable` 中的操作码构成。

**命令行参数的具体处理:**

这个代码片段本身不涉及命令行参数的处理。命令行参数的处理通常发生在 Go 编译器的前端（例如词法分析、语法分析）以及主入口函数中。`opGen.go` 生成的数据是被编译器后端（SSA 优化和代码生成）使用的。

**使用者易犯错的点:**

作为编译器开发者，容易犯错的点包括：

* **操作码定义不完整或有歧义:** 确保所有必要的底层操作都有对应的操作码，并且每个操作码的语义清晰。
* **操作码元数据错误:** `argLen`, `auxType` 等信息的错误会导致编译器后端处理 SSA 指令时出现问题。
* **忽略某些操作码的副作用:**  `hasSideEffects` 标记的错误可能导致编译器在优化时做出错误的假设。

**归纳一下它的功能 (作为第 18 部分，共 18 部分):**

作为 `go/src/cmd/compile/internal/ssa/opGen.go` 文件的最后一部分，这个代码片段定义了 **SSA 中间表示的所有操作码以及它们的元数据**。  考虑到这是该文件的最后一部分，可以推断出 `opGen.go` 的整体功能是：

**`opGen.go` 的整体功能是生成与 SSA 操作码相关的 Go 代码。** 它可能包含以下几个部分（根据上下文推断）：

1. **操作码枚举定义:**  定义 `Op` 类型作为一个枚举，表示所有可能的 SSA 操作码。
2. **操作码结构体定义:** 定义 `op` 结构体，用于存储每个操作码的元数据。
3. **操作码表定义 (当前片段):**  定义 `opcodeTable` 常量，将每个操作码枚举值映射到其对应的元数据结构体。
4. **辅助类型定义:** 定义了 `auxType` 等辅助类型，用于存储操作码的额外信息。
5. **寄存器定义:**  定义了不同架构下的寄存器集合 (`registers386`, `registersAMD64` 等) 以及相关的寄存器掩码和参数寄存器信息。
6. **访问器方法:** 提供访问操作码属性的方法，例如 `Asm()`, `String()`, `IsCall()` 等。

**总结来说，`opGen.go` 是 Go 编译器中非常核心的文件，它定义了编译器进行代码转换和优化的基本词汇表，即 SSA 中间表示的操作码。 这个片段作为最后一部分，完成了操作码到其元数据的映射定义，是整个 `opGen.go` 功能的收尾工作。**

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第18部分，共18部分，请归纳一下它的功能

"""
  true,
	},
	{
		name:      "SB",
		argLen:    0,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "SPanchored",
		argLen:    2,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "Load",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Dereference",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Store",
		auxType: auxTyp,
		argLen:  3,
		generic: true,
	},
	{
		name:    "Move",
		auxType: auxTypSize,
		argLen:  3,
		generic: true,
	},
	{
		name:    "Zero",
		auxType: auxTypSize,
		argLen:  2,
		generic: true,
	},
	{
		name:    "StoreWB",
		auxType: auxTyp,
		argLen:  3,
		generic: true,
	},
	{
		name:    "MoveWB",
		auxType: auxTypSize,
		argLen:  3,
		generic: true,
	},
	{
		name:    "ZeroWB",
		auxType: auxTypSize,
		argLen:  2,
		generic: true,
	},
	{
		name:    "WBend",
		argLen:  1,
		generic: true,
	},
	{
		name:    "WB",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:      "HasCPUFeature",
		auxType:   auxSym,
		argLen:    0,
		symEffect: SymNone,
		generic:   true,
	},
	{
		name:    "PanicBounds",
		auxType: auxInt64,
		argLen:  3,
		call:    true,
		generic: true,
	},
	{
		name:    "PanicExtend",
		auxType: auxInt64,
		argLen:  4,
		call:    true,
		generic: true,
	},
	{
		name:    "ClosureCall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "StaticCall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "InterCall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "TailCall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "ClosureLECall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "StaticLECall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "InterLECall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "TailLECall",
		auxType: auxCallOff,
		argLen:  -1,
		call:    true,
		generic: true,
	},
	{
		name:    "SignExt8to16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SignExt8to32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SignExt8to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SignExt16to32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SignExt16to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SignExt32to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt8to16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt8to32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt8to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt16to32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt16to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ZeroExt32to64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc16to8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc32to8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc32to16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc64to8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc64to16",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Trunc64to32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32to32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32to64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64to32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64to64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Fto32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Fto64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Fto32",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Fto64",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Fto64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Fto32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "CvtBoolToUint8",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Round32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Round64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "IsNonNil",
		argLen:  1,
		generic: true,
	},
	{
		name:    "IsInBounds",
		argLen:  2,
		generic: true,
	},
	{
		name:    "IsSliceInBounds",
		argLen:  2,
		generic: true,
	},
	{
		name:     "NilCheck",
		argLen:   2,
		nilCheck: true,
		generic:  true,
	},
	{
		name:      "GetG",
		argLen:    1,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "GetClosurePtr",
		argLen:  0,
		generic: true,
	},
	{
		name:    "GetCallerPC",
		argLen:  0,
		generic: true,
	},
	{
		name:    "GetCallerSP",
		argLen:  1,
		generic: true,
	},
	{
		name:    "PtrIndex",
		argLen:  2,
		generic: true,
	},
	{
		name:    "OffPtr",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:    "SliceMake",
		argLen:  3,
		generic: true,
	},
	{
		name:    "SlicePtr",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SliceLen",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SliceCap",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SlicePtrUnchecked",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ComplexMake",
		argLen:  2,
		generic: true,
	},
	{
		name:    "ComplexReal",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ComplexImag",
		argLen:  1,
		generic: true,
	},
	{
		name:    "StringMake",
		argLen:  2,
		generic: true,
	},
	{
		name:    "StringPtr",
		argLen:  1,
		generic: true,
	},
	{
		name:    "StringLen",
		argLen:  1,
		generic: true,
	},
	{
		name:    "IMake",
		argLen:  2,
		generic: true,
	},
	{
		name:    "ITab",
		argLen:  1,
		generic: true,
	},
	{
		name:    "IData",
		argLen:  1,
		generic: true,
	},
	{
		name:    "StructMake",
		argLen:  -1,
		generic: true,
	},
	{
		name:    "StructSelect",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:    "ArrayMake0",
		argLen:  0,
		generic: true,
	},
	{
		name:    "ArrayMake1",
		argLen:  1,
		generic: true,
	},
	{
		name:    "ArraySelect",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:    "StoreReg",
		argLen:  1,
		generic: true,
	},
	{
		name:    "LoadReg",
		argLen:  1,
		generic: true,
	},
	{
		name:      "FwdRef",
		auxType:   auxSym,
		argLen:    0,
		symEffect: SymNone,
		generic:   true,
	},
	{
		name:    "Unknown",
		argLen:  0,
		generic: true,
	},
	{
		name:      "VarDef",
		auxType:   auxSym,
		argLen:    1,
		zeroWidth: true,
		symEffect: SymNone,
		generic:   true,
	},
	{
		name:      "VarLive",
		auxType:   auxSym,
		argLen:    1,
		zeroWidth: true,
		symEffect: SymRead,
		generic:   true,
	},
	{
		name:      "KeepAlive",
		argLen:    2,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "InlMark",
		auxType: auxInt32,
		argLen:  1,
		generic: true,
	},
	{
		name:    "Int64Make",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Int64Hi",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Int64Lo",
		argLen:  1,
		generic: true,
	},
	{
		name:        "Add32carry",
		argLen:      2,
		commutative: true,
		generic:     true,
	},
	{
		name:        "Add32withcarry",
		argLen:      3,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Sub32carry",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Sub32withcarry",
		argLen:  3,
		generic: true,
	},
	{
		name:        "Add64carry",
		argLen:      3,
		commutative: true,
		generic:     true,
	},
	{
		name:    "Sub64borrow",
		argLen:  3,
		generic: true,
	},
	{
		name:    "Signmask",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Zeromask",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Slicemask",
		argLen:  1,
		generic: true,
	},
	{
		name:    "SpectreIndex",
		argLen:  2,
		generic: true,
	},
	{
		name:    "SpectreSliceIndex",
		argLen:  2,
		generic: true,
	},
	{
		name:    "Cvt32Uto32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Uto64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Fto32U",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Fto32U",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Uto32F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Uto64F",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt32Fto64U",
		argLen:  1,
		generic: true,
	},
	{
		name:    "Cvt64Fto64U",
		argLen:  1,
		generic: true,
	},
	{
		name:      "Select0",
		argLen:    1,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:      "Select1",
		argLen:    1,
		zeroWidth: true,
		generic:   true,
	},
	{
		name:    "SelectN",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:    "SelectNAddr",
		auxType: auxInt64,
		argLen:  1,
		generic: true,
	},
	{
		name:    "MakeResult",
		argLen:  -1,
		generic: true,
	},
	{
		name:    "AtomicLoad8",
		argLen:  2,
		generic: true,
	},
	{
		name:    "AtomicLoad32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "AtomicLoad64",
		argLen:  2,
		generic: true,
	},
	{
		name:    "AtomicLoadPtr",
		argLen:  2,
		generic: true,
	},
	{
		name:    "AtomicLoadAcq32",
		argLen:  2,
		generic: true,
	},
	{
		name:    "AtomicLoadAcq64",
		argLen:  2,
		generic: true,
	},
	{
		name:           "AtomicStore8",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStore32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStore64",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStorePtrNoWB",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStoreRel32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStoreRel64",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange8",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange64",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAdd32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAdd64",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicCompareAndSwap32",
		argLen:         4,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicCompareAndSwap64",
		argLen:         4,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicCompareAndSwapRel32",
		argLen:         4,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd8",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr8",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr32",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd64value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd32value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd8value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr64value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr32value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr8value",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStore8Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStore32Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicStore64Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAdd32Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAdd64Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange8Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange32Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicExchange64Variant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicCompareAndSwap32Variant",
		argLen:         4,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicCompareAndSwap64Variant",
		argLen:         4,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd64valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr64valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd32valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr32valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicAnd8valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "AtomicOr8valueVariant",
		argLen:         3,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "PubBarrier",
		argLen:         1,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:      "Clobber",
		auxType:   auxSymOff,
		argLen:    0,
		symEffect: SymNone,
		generic:   true,
	},
	{
		name:    "ClobberReg",
		argLen:  0,
		generic: true,
	},
	{
		name:           "PrefetchCache",
		argLen:         2,
		hasSideEffects: true,
		generic:        true,
	},
	{
		name:           "PrefetchCacheStreamed",
		argLen:         2,
		hasSideEffects: true,
		generic:        true,
	},
}

func (o Op) Asm() obj.As          { return opcodeTable[o].asm }
func (o Op) Scale() int16         { return int16(opcodeTable[o].scale) }
func (o Op) String() string       { return opcodeTable[o].name }
func (o Op) SymEffect() SymEffect { return opcodeTable[o].symEffect }
func (o Op) IsCall() bool         { return opcodeTable[o].call }
func (o Op) IsTailCall() bool     { return opcodeTable[o].tailCall }
func (o Op) HasSideEffects() bool { return opcodeTable[o].hasSideEffects }
func (o Op) UnsafePoint() bool    { return opcodeTable[o].unsafePoint }
func (o Op) ResultInArg0() bool   { return opcodeTable[o].resultInArg0 }

var registers386 = [...]Register{
	{0, x86.REG_AX, 0, "AX"},
	{1, x86.REG_CX, 1, "CX"},
	{2, x86.REG_DX, 2, "DX"},
	{3, x86.REG_BX, 3, "BX"},
	{4, x86.REGSP, -1, "SP"},
	{5, x86.REG_BP, 4, "BP"},
	{6, x86.REG_SI, 5, "SI"},
	{7, x86.REG_DI, 6, "DI"},
	{8, x86.REG_X0, -1, "X0"},
	{9, x86.REG_X1, -1, "X1"},
	{10, x86.REG_X2, -1, "X2"},
	{11, x86.REG_X3, -1, "X3"},
	{12, x86.REG_X4, -1, "X4"},
	{13, x86.REG_X5, -1, "X5"},
	{14, x86.REG_X6, -1, "X6"},
	{15, x86.REG_X7, -1, "X7"},
	{16, 0, -1, "SB"},
}
var paramIntReg386 = []int8(nil)
var paramFloatReg386 = []int8(nil)
var gpRegMask386 = regMask(239)
var fpRegMask386 = regMask(65280)
var specialRegMask386 = regMask(0)
var framepointerReg386 = int8(5)
var linkReg386 = int8(-1)
var registersAMD64 = [...]Register{
	{0, x86.REG_AX, 0, "AX"},
	{1, x86.REG_CX, 1, "CX"},
	{2, x86.REG_DX, 2, "DX"},
	{3, x86.REG_BX, 3, "BX"},
	{4, x86.REGSP, -1, "SP"},
	{5, x86.REG_BP, 4, "BP"},
	{6, x86.REG_SI, 5, "SI"},
	{7, x86.REG_DI, 6, "DI"},
	{8, x86.REG_R8, 7, "R8"},
	{9, x86.REG_R9, 8, "R9"},
	{10, x86.REG_R10, 9, "R10"},
	{11, x86.REG_R11, 10, "R11"},
	{12, x86.REG_R12, 11, "R12"},
	{13, x86.REG_R13, 12, "R13"},
	{14, x86.REGG, -1, "g"},
	{15, x86.REG_R15, 13, "R15"},
	{16, x86.REG_X0, -1, "X0"},
	{17, x86.REG_X1, -1, "X1"},
	{18, x86.REG_X2, -1, "X2"},
	{19, x86.REG_X3, -1, "X3"},
	{20, x86.REG_X4, -1, "X4"},
	{21, x86.REG_X5, -1, "X5"},
	{22, x86.REG_X6, -1, "X6"},
	{23, x86.REG_X7, -1, "X7"},
	{24, x86.REG_X8, -1, "X8"},
	{25, x86.REG_X9, -1, "X9"},
	{26, x86.REG_X10, -1, "X10"},
	{27, x86.REG_X11, -1, "X11"},
	{28, x86.REG_X12, -1, "X12"},
	{29, x86.REG_X13, -1, "X13"},
	{30, x86.REG_X14, -1, "X14"},
	{31, x86.REG_X15, -1, "X15"},
	{32, 0, -1, "SB"},
}
var paramIntRegAMD64 = []int8{0, 3, 1, 7, 6, 8, 9, 10, 11}
var paramFloatRegAMD64 = []int8{16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
var gpRegMaskAMD64 = regMask(49135)
var fpRegMaskAMD64 = regMask(2147418112)
var specialRegMaskAMD64 = regMask(2147483648)
var framepointerRegAMD64 = int8(5)
var linkRegAMD64 = int8(-1)
var registersARM = [...]Register{
	{0, arm.REG_R0, 0, "R0"},
	{1, arm.REG_R1, 1, "R1"},
	{2, arm.REG_R2, 2, "R2"},
	{3, arm.REG_R3, 3, "R3"},
	{4, arm.REG_R4, 4, "R4"},
	{5, arm.REG_R5, 5, "R5"},
	{6, arm.REG_R6, 6, "R6"},
	{7, arm.REG_R7, 7, "R7"},
	{8, arm.REG_R8, 8, "R8"},
	{9, arm.REG_R9, 9, "R9"},
	{10, arm.REGG, -1, "g"},
	{11, arm.REG_R11, -1, "R11"},
	{12, arm.REG_R12, 10, "R12"},
	{13, arm.REGSP, -1, "SP"},
	{14, arm.REG_R14, 11, "R14"},
	{15, arm.REG_R15, -1, "R15"},
	{16, arm.REG_F0, -1, "F0"},
	{17, arm.REG_F1, -1, "F1"},
	{18, arm.REG_F2, -1, "F2"},
	{19, arm.REG_F3, -1, "F3"},
	{20, arm.REG_F4, -1, "F4"},
	{21, arm.REG_F5, -1, "F5"},
	{22, arm.REG_F6, -1, "F6"},
	{23, arm.REG_F7, -1, "F7"},
	{24, arm.REG_F8, -1, "F8"},
	{25, arm.REG_F9, -1, "F9"},
	{26, arm.REG_F10, -1, "F10"},
	{27, arm.REG_F11, -1, "F11"},
	{28, arm.REG_F12, -1, "F12"},
	{29, arm.REG_F13, -1, "F13"},
	{30, arm.REG_F14, -1, "F14"},
	{31, arm.REG_F15, -1, "F15"},
	{32, 0, -1, "SB"},
}
var paramIntRegARM = []int8(nil)
var paramFloatRegARM = []int8(nil)
var gpRegMaskARM = regMask(21503)
var fpRegMaskARM = regMask(4294901760)
var specialRegMaskARM = regMask(0)
var framepointerRegARM = int8(-1)
var linkRegARM = int8(14)
var registersARM64 = [...]Register{
	{0, arm64.REG_R0, 0, "R0"},
	{1, arm64.REG_R1, 1, "R1"},
	{2, arm64.REG_R2, 2, "R2"},
	{3, arm64.REG_R3, 3, "R3"},
	{4, arm64.REG_R4, 4, "R4"},
	{5, arm64.REG_R5, 5, "R5"},
	{6, arm64.REG_R6, 6, "R6"},
	{7, arm64.REG_R7, 7, "R7"},
	{8, arm64.REG_R8, 8, "R8"},
	{9, arm64.REG_R9, 9, "R9"},
	{10, arm64.REG_R10, 10, "R10"},
	{11, arm64.REG_R11, 11, "R11"},
	{12, arm64.REG_R12, 12, "R12"},
	{13, arm64.REG_R13, 13, "R13"},
	{14, arm64.REG_R14, 14, "R14"},
	{15, arm64.REG_R15, 15, "R15"},
	{16, arm64.REG_R16, 16, "R16"},
	{17, arm64.REG_R17, 17, "R17"},
	{18, arm64.REG_R18, -1, "R18"},
	{19, arm64.REG_R19, 18, "R19"},
	{20, arm64.REG_R20, 19, "R20"},
	{21, arm64.REG_R21, 20, "R21"},
	{22, arm64.REG_R22, 21, "R22"},
	{23, arm64.REG_R23, 22, "R23"},
	{24, arm64.REG_R24, 23, "R24"},
	{25, arm64.REG_R25, 24, "R25"},
	{26, arm64.REG_R26, 25, "R26"},
	{27, arm64.REGG, -1, "g"},
	{28, arm64.REG_R29, -1, "R29"},
	{29, arm64.REG_R30, 26, "R30"},
	{30, arm64.REGSP, -1, "SP"},
	{31, arm64.REG_F0, -1, "F0"},
	{32, arm64.REG_F1, -1, "F1"},
	{33, arm64.REG_F2, -1, "F2"},
	{34, arm64.REG_F3, -1, "F3"},
	{35, arm64.REG_F4, -1, "F4"},
	{36, arm64.REG_F5, -1, "F5"},
	{37, arm64.REG_F6, -1, "F6"},
	{38, arm64.REG_F7, -1, "F7"},
	{39, arm64.REG_F8, -1, "F8"},
	{40, arm64.REG_F9, -1, "F9"},
	{41, arm64.REG_F10, -1, "F10"},
	{42, arm64.REG_F11, -1, "F11"},
	{43, arm64.REG_F12, -1, "F12"},
	{44, arm64.REG_F13, -1, "F13"},
	{45, arm64.REG_F14, -1, "F14"},
	{46, arm64.REG_F15, -1, "F15"},
	{47, arm64.REG_F16, -1, "F16"},
	{48, arm64.REG_F17, -1, "F17"},
	{49, arm64.REG_F18, -1, "F18"},
	{50, arm64.REG_F19, -1, "F19"},
	{51, arm64.REG_F20, -1, "F20"},
	{52, arm64.REG_F21, -1, "F21"},
	{53, arm64.REG_F22, -1, "F22"},
	{54, arm64.REG_F23, -1, "F23"},
	{55, arm64.REG_F24, -1, "F24"},
	{56, arm64.REG_F25, -1, "F25"},
	{57, arm64.REG_F26, -1, "F26"},
	{58, arm64.REG_F27, -1, "F27"},
	{59, arm64.REG_F28, -1, "F28"},
	{60, arm64.REG_F29, -1, "F29"},
	{61, arm64.REG_F30, -1, "F30"},
	{62, arm64.REG_F31, -1, "F31"},
	{63, 0, -1, "SB"},
}
var paramIntRegARM64 = []int8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var paramFloatRegARM64 = []int8{31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46}
var gpRegMaskARM64 = regMask(670826495)
var fpRegMaskARM64 = regMask(9223372034707292160)
var specialRegMaskARM64 = regMask(0)
var framepointerRegARM64 = int8(-1)
var linkRegARM64 = int8(29)
var registersLOONG64 = [...]Register{
	{0, loong64.REG_R0, -1, "R0"},
	{1, loong64.REG_R1, -1, "R1"},
	{2, loong64.REGSP, -1, "SP"},
	{3, loong64.REG_R4, 0, "R4"},
	{4, loong64.REG_R5, 1, "R5"},
	{5, loong64.REG_R6, 2, "R6"},
	{6, loong64.REG_R7, 3, "R7"},
	{7, loong64.REG_R8, 4, "R8"},
	{8, loong64.REG_R9, 5, "R9"},
	{9, loong64.REG_R10, 6, "R10"},
	{10, loong64.REG_R11, 7, "R11"},
	{11, loong64.REG_R12, 8, "R12"},
	{12, loong64.REG_R13, 9, "R13"},
	{13, loong64.REG_R14, 10, "R14"},
	{14, loong64.REG_R15, 11, "R15"},
	{15, loong64.REG_R16, 12, "R16"},
	{16, loong64.REG_R17, 13, "R17"},
	{17, loong64.REG_R18, 14, "R18"},
	{18, loong64.REG_R19, 15, "R19"},
	{19, loong64.REG_R20, 16, "R20"},
	{20, loong64.REG_R21, 17, "R21"},
	{21, loong64.REGG, -1, "g"},
	{22, loong64.REG_R23, 18, "R23"},
	{23, loong64.REG_R24, 19, "R24"},
	{24, loong64.REG_R25, 20, "R25"},
	{25, loong64.REG_R26, 21, "R26"},
	{26, loong64.REG_R27, 22, "R27"},
	{27, loong64.REG_R28, 23, "R28"},
	{28, loong64.REG_R29, 24, "R29"},
	{29, loong64.REG_R31, 25, "R31"},
	{30, loong64.REG_F0, -1, "F0"},
	{31, loong64.REG_F1, -1, "F1"},
	{32, loong64.REG_F2, -1, "F2"},
	{33, loong64.REG_F3, -1, "F3"},
	{34, loong64.REG_F4, -1, "F4"},
	{35, loong64.REG_F5, -1, "F5"},
	{36, loong64.REG_F6, -1, "F6"},
	{37, loong64.REG_F7, -1, "F7"},
	{38, loong64.REG_F8, -1, "F8"},
	{39, loong64.REG_F9, -1, "F9"},
	{40, loong64.REG_F10, -1, "F10"},
	{41, loong64.REG_F11, -1, "F11"},
	{42, loong64.REG_F12, -1, "F12"},
	{43, loong64.REG_F13, -1, "F13"},
	{44, loong64.REG_F14, -1, "F14"},
	{45, loong64.REG_F15, -1, "F15"},
	{46, loong64.REG_F16, -1, "F16"},
	{47, loong64.REG_F17, -1, "F17"},
	{48, loong64.REG_F18, -1, "F18"},
	{49, loong64.REG_F19, -1, "F19"},
	{50, loong64.REG_F20, -1, "F20"},
	{51, loong64.REG_F21, -1, "F21"},
	{52, loong64.REG_F22, -1, "F22"},
	{53, loong64.REG_F23, -1, "F23"},
	{54, loong64.REG_F24, -1, "F24"},
	{55, loong64.REG_F25, -1, "F25"},
	{56, loong64.REG_F26, -1, "F26"},
	{57, loong64.REG_F27, -1, "F27"},
	{58, loong64.REG_F28, -1, "F28"},
	{59, loong64.REG_F29, -1, "F29"},
	{60, loong64.REG_F30, -1, "F30"},
	{61, loong64.REG_F31, -1, "F31"},
	{62, 0, -1, "SB"},
}
var paramIntRegLOONG64 = []int8{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}
var paramFloatRegLOONG64 = []int8{30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45}
var gpRegMaskLOONG64 = regMask(1071644664)
var fpRegMaskLOONG64 = regMask(4611686017353646080)
var specialRegMaskLOONG64 = regMask(0)
var framepointerRegLOONG64 = int8(-1)
var linkRegLOONG64 = int8(1)
var registersMIPS = [...]Register{
	{0, mips.REG_R0, -1, "R0"},
	{1, mips.REG_R1, 0, "R1"},
	{2, mips.REG_R2, 1, "R2"},
	{3, mips.REG_R3, 2, "R3"},
	{4, mips.REG_R4, 3, "R4"},
	{5, mips.REG_R5, 4, "R5"},
	{6, mips.REG_R6, 5, "R6"},
	{7, mips.REG_R7, 6, "R7"},
	{8, mips.REG_R8, 7, "R8"},
	{9, mips.REG_R9, 8, "R9"},
	{10, mips.REG_R10, 9, "R10"},
	{11, mips.REG_R11, 10, "R11"},
	{12, mips.REG_R12, 11, "R12"},
	{13, mips.REG_R13, 12, "R13"},
	{14, mips.REG_R14, 13, "R14"},
	{15, mips.REG_R15, 14, "R15"},
	{16, mips.REG_R16, 15, "R16"},
	{17, mips.REG_R17, 16, "R17"},
	{18, mips.REG_R18, 17, "R18"},
	{19, mips.REG_R19, 18, "R19"},
	{20, mips.REG_R20, 19, "R20"},
	{21, mips.REG_R21, 20, "R21"},
	{22, mips.REG_R22, 21, "R22"},
	{23, mips.REG_R24, 22, "R24"},
	{24, mips.REG_R25, 23, "R25"},
	{25, mips.REG_R28, 24, "R28"},
	{26, mips.REGSP, -1, "SP"},
	{27, mips.REGG, -1, "g"},
	{28, mips.REG_R31, 25, "R31"},
	{29, mips.REG_F0, -1, "F0"},
	{30, mips.REG_F2, -1, "F2"},
	{31, mips.REG_F4, -1, "F4"},
	{32, mips.REG_F6, -1, "F6"},
	{33, mips.REG_F8, -1, "F8"},
	{34, mips.REG_F10, -1, "F10"},
	{35, mips.REG_F12, -1, "F12"},
	{36, mips.REG_F14, -1, "F14"},
	{37, mips.REG_F16, -1, "F16"},
	{38, mips.REG_F18, -1, "F18"},
	{39, mips.REG_F20, -1, "F20"},
	{40, mips.REG_F22, -1, "F22"},
	{41, mips.REG_F24, -1, "F24"},
	{42, mips.REG_F26, -1, "F26"},
	{43, mips.REG_F28, -1, "F28"},
	{44, mips.REG_F30, -1, "F30"},
	{45, mips.REG_HI, -1, "HI"},
	{46, mips.REG_LO, -1, "LO"},
	{47, 0, -1, "SB"},
}
var paramIntRegMIPS = []int8(nil)
var paramFloatRegMIPS = []int8(nil)
var gpRegMaskMIPS = regMask(335544318)
var fpRegMaskMIPS = regMask(35183835217920)
var specialRegMaskMIPS = regMask(105553116266496)
var framepointerRegMIPS = int8(-1)
var linkRegMIPS = int8(28)
var registersMIPS64 = [...]Register{
	{0, mips.REG_R0, -1, "R0"},
	{1, mips.REG_R1, 0, "R1"},
	{2, mips.REG_R2, 1, "R2"},
	{3, mips.REG_R3, 2, "R3"},
	{4, mips.REG_R4, 3, "R4"},
	{5, mips.REG_R5, 4, "R5"},
	{6, mips.REG_R6, 5, "R6"},
	{7, mips.REG_R7, 6, "R7"},
	{8, mips.REG_R8, 7, "R8"},
	{9, mips.REG_R9, 8, "R9"},
	{10, mips.REG_R10, 9, "R10"},
	{11, mips.REG_R11, 10, "R11"},
	{12, mips.REG_R12, 11, "R12"},
	{13, mips.REG_R13, 12, "R13"},
	{14, mips.REG_R14, 13, "R14"},
	{15, mips.REG_R15, 14, "R15"},
	{16, mips.REG_R16, 15, "R16"},
	{17, mips.REG_R17, 16, "R17"},
	{18, mips.REG_R18, 17, "R18"},
	{19, mips.REG_R19, 18, "R19"},
	{20, mips.REG_R20, 19, "R20"},
	{21, mips.REG_R21, 20, "R21"},
	{22, mips.REG_R22, 21, "R22"},
	{23, mips.REG_R24, 22, "R24"},
	{24, mips.REG_R25, 23, "R25"},
	{25, mips.REGSP, -1, "SP"},
	{26, mips.REGG, -1, "g"},
	{27, mips.REG_R31, 24, "R31"},
	{28, mips.REG_F0, -1, "F0"},
	{29, mips.REG_F1, -1, "F1"},
	{30, mips.REG_F2, -1, "F2"},
	{31, mips.REG_F3, -1, "F3"},
	{32, mips.REG_F4, -1, "F4"},
	{33, mips.REG_F5, -1, "F5"},
	{34, mips.REG_F6, -1, "F6"},
	{35, mips.REG_F7, -1, "F7"},
	{36, mips.REG_F8, -1, "F8"},
	{37, mips.REG_F9, -1, "F9"},
	{38, mips.REG_F10, -1, "F10"},
	{39, mips.REG_F11, -1, "F11"},
	{40, mips.REG_F12, -1, "F12"},
	{41, mips.REG_F13, -1, "F13"},
	{42, mips.REG_F14, -1, "F14"},
	{43, mips.REG_F15, -1, "F15"},
	{44, mips.REG_F16, -1, "F16"},
	{45, mips.REG_F17, -1, "F17"},
	{46, mips.REG_F18, -1, "F18"},
	{47, mips.REG_F19, -1, "F19"},
	{48, mips.REG_F20, -1, "F20"},
	{49, mips.REG_F21, -1, "F21"},
	{50, mips.REG_F22, -1, "F22"},
	{51, mips.REG_F23, -1, "F23"},
	{52, mips.REG_F24, -1, "F24"},
	{53, mips.REG_F25, -1, "F25"},
	{54, mips.REG_F26, -1, "F26"},
	{55, mips.REG_F27, -1, "F27"},
	{56, mips.REG_F28, -1, "F28"},
	{57, mips.REG_F29, -1, "F29"},
	{58, mips.REG_F30, -1, "F30"},
	{59, mips.REG_F31, -1, "F31"},
	{60, mips.REG_HI, -1, "HI"},
	{61, mips.REG_LO, -1, "LO"},
	{62, 0, -1, "SB"},
}
var paramIntRegMIPS64 = []int8(nil)
var paramFloatRegMIPS64 = []int8(nil)
var gpRegMaskMIPS64 = regMask(167772158)
var fpRegMaskMIPS64 = regMask(1152921504338411520)
var specialRegMaskMIPS64 = regMask(3458764513820540928)
var framepointerRegMIPS64 = int8(-1)
var linkRegMIPS64 = int8(27)
var registersPPC64 = [...]Register{
	{0, ppc64.REG_R0, -1, "R0"},
	{1, ppc64.REGSP, -1, "SP"},
	{2, 0, -1, "SB"},
	{3, ppc64.REG_R3, 0, "R3"},
	{4, ppc64.REG_R4, 1, "R4"},
	{5, ppc64.REG_R5, 2, "R5"},
	{6, ppc64.REG_R6, 3, "R6"},
	{7, ppc64.REG_R7, 4, "R7"},
	{8, ppc64.REG_R8, 5, "R8"},
	{9, ppc64.REG_R9, 6, "R9"},
	{10, ppc64.REG_R10, 7, "R10"},
	{11, ppc64.REG_R11, 8, "R11"},
	{12, ppc64.REG_R12, 9, "R12"},
	{13, ppc64.REG_R13, -1, "R13"},
	{14, ppc64.REG_R14, 10, "R14"},
	{15, ppc64.REG_R15, 11, "R15"},
	{16, ppc64.REG_R16, 12, "R16"},
	{17, ppc64.REG_R17, 13, "R17"},
	{18, ppc64.REG_R18, 14, "R18"},
	{19, ppc64.REG_R19, 15, "R19"},
	{20, ppc64.REG_R20, 16, "R20"},
	{21, ppc64.REG_R21, 17, "R21"},
	{22, ppc64.REG_R22, 18, "R22"},
	{23, ppc64.REG_R23, 19, "R23"},
	{24, ppc64.REG_R24, 20, "R24"},
	{25, ppc64.REG_R25, 21, "R25"},
	{26, ppc64.REG_R26, 22, "R26"},
	{27, ppc64.REG_R27, 23, "R27"},
	{28, ppc64.REG_R28, 24, "R28"},
	{29, ppc64.REG_R29, 25, "R29"},
	{30, ppc64.REGG, -1, "g"},
	{31, ppc64.REG_R31, -1, "R31"},
	{32, ppc64.REG_F0, -1, "F0"},
	{33, ppc64.REG_F1, -1, "F1"},
	{34, ppc64.REG_F2, -1, "F2"},
	{35, ppc64.REG_F3, -1, "F3"},
	{36, ppc64.REG_F4, -1, "F4"},
	{37, ppc64.REG_F5, -1, "F5"},
	{38, ppc64.REG_F6, -1, "F6"},
	{39, ppc64.REG_F7, -1, "F7"},
	{40, ppc64.REG_F8, -1, "F8"},
	{41, ppc64.REG_F9, -1, "F9"},
	{42, ppc64.REG_F10, -1, "F10"},
	{43, ppc64.REG_F11, -1, "F11"},
	{44, ppc64.REG_F12, -1, "F12"},
	{45, ppc64.REG_F13, -1, "F13"},
	{46, ppc64.REG_F14, -1, "F14"},
	{47, ppc64.REG_F15, -1, "F15"},
	{48, ppc64.REG_F16, -1, "F16"},
	{49, ppc64.REG_F17, -1, "F17"},
	{50, ppc64.REG_F18, -1, "F18"},
	{51, ppc64.REG_F19, -1, "F19"},
	{52, ppc64.REG_F20, -1, "F20"},
	{53, ppc64.REG_F21, -1, "F21"},
	{54, ppc64.REG_F22, -1, "F22"},
	{55, ppc64.REG_F23, -1, "F23"},
	{56, ppc64.REG_F24, -1, "F24"},
	{57, ppc64.REG_F25, -1, "F25"},
	{58, ppc64.REG_F26, -1, "F26"},
	{59, ppc64.REG_F27, -1, "F27"},
	{60, ppc64.REG_F28, -1, "F28"},
	{61, ppc64.REG_F29, -1, "F29"},
	{62, ppc64.REG_F30, -1, "F30"},
	{63, ppc64.REG_XER, -1, "XER"},
}
var paramIntRegPPC64 = []int8{3, 4, 5, 6, 7, 8, 9, 10, 14, 15, 16, 17}
var paramFloatRegPPC64 = []int8{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44}
var gpRegMaskPPC64 = regMask(1073733624)
var fpRegMaskPPC64 = regMask(9223372032559808512)
var specialRegMaskPPC64 = regMask(9223372036854775808)
var framepointerRegPPC64 = int8(-1)
var linkRegPPC64 = int8(-1)
var registersRISCV64 = [...]Register{
	{0, riscv.REG_X0, -1, "X0"},
	{1, riscv.REGSP, -1, "SP"},
	{2, riscv.REG_X3, -1, "X3"},
	{3, riscv.REG_X4, -1, "X4"},
	{4, riscv.REG_X5, 0, "X5"},
	{5, riscv.REG_X6, 1, "X6"},
	{6, riscv.REG_X7, 2, "X7"},
	{7, riscv.REG_X8, 3, "X8"},
	{8, riscv.REG_X9, 4, "X9"},
	{9, riscv.REG_X10, 5, "X10"},
	{10, riscv.REG_X11, 6, "X11"},
	{11, riscv.REG_X12, 7, "X12"},
	{12, riscv.REG_X13, 8, "X13"},
	{13, riscv.REG_X14, 9, "X14"},
	{14, riscv.REG_X15, 10, "X15"},
	{15, riscv.REG_X16, 11, "X16"},
	{16, riscv.REG_X17, 12, "X17"},
	{17, riscv.REG_X18, 13, "X18"},
	{18, riscv.REG_X19, 14, "X19"},
	{19, riscv.REG_X20, 15, "X20"},
	{20, riscv.REG_X21, 16, "X21"},
	{21, riscv.REG_X22, 17, "X22"},
	{22, riscv.REG_X23, 18, "X23"},
	{23, riscv.REG_X24, 19, "X24"},
	{24, riscv.REG_X25, 20, "X25"},
	{25, riscv.REG_X26, 21, "X26"},
	{26, riscv.REGG, -1, "g"},
	{27, riscv.REG_X28, 22, "X28"},
	{28, riscv.REG_X29, 23, "X29"},
	{29, riscv.REG_X30, 24, "X30"},
	{30, riscv.REG_X31, -1, "X31"},
	{31, riscv.REG_F0, -1, "F0"},
	{32, riscv.REG_F1, -1, "F1"},
	{33, riscv.REG_F2, -1, "F2"},
	{34, riscv.REG_F3, -1, "F3"},
	{35, riscv.REG_F4, -1, "F4"},
	{36, riscv.REG_F5, -1, "F5"},
	{37, riscv.REG_F6, -1, "F6"},
	{38, riscv.REG_F7, -1, "F7"},
	{39, riscv.REG_F8, -1, "F8"},
	{40, riscv.REG_F9, -1, "F9"},
	{41, riscv.REG_F10, -1, "F10"},
	{42, riscv.REG_F11, -1, "F11"},
	{43, riscv.REG_F12, -1, "F12"},
	{44, riscv.REG_F13, -1, "F13"},
	{45, riscv.REG_F14, -1, "F14"},
	{46, riscv.REG_F15, -1, "F15"},
	{47, riscv.REG_F16, -1, "F16"},
	{48, riscv.REG_F17, -1, "F17"},
	{49, riscv.REG_F18, -1, "F18"},
	{50, riscv.REG_F19, -1, "F19"},
	{51, riscv.REG_F20, -1, "F20"},
	{52, riscv.REG_F21, -1, "F21"},
	{53, riscv.REG_F22, -1, "F22"},
	{54, riscv.REG_F23, -1, "F23"},
	{55, riscv.REG_F24, -1, "F24"},
	{56, riscv.REG_F25, -1, "F25"},
	{57, riscv.REG_F26, -1, "F26"},
	{58, riscv.REG_F27, -1, "F27"},
	{59, riscv.REG_F28, -1, "F28"},
	{60, riscv.REG_F29, -1, "F29"},
	{61, riscv.REG_F30, -1, "F30"},
	{62, riscv.REG_F31, -1, "F31"},
	{63, 0, -1, "SB"},
}
var paramIntRegRISCV64 = []int8{9, 10, 11, 12, 13, 14, 15, 16, 7, 8, 17, 18, 19, 20, 21, 22}
var paramFloatRegRISCV64 = []int8{41, 42, 43, 44, 45, 46, 47, 48, 39, 40, 49, 50, 51, 52, 53, 54}
var gpRegMaskRISCV64 = regMask(1006632944)
var fpRegMaskRISCV64 = regMask(9223372034707292160)
var specialRegMaskRISCV64 = regMask(0)
var framepointerRegRISCV64 = int8(-1)
var linkRegRISCV64 = int8(0)
var registersS390X = [...]Register{
	{0, s390x.REG_R0, 0, "R0"},
	{1, s390x.REG_R1, 1, "R1"},
	{2, s390x.REG_R2, 2, "R2"},
	{3, s390x.REG_R3, 3, "R3"},
	{4, s390x.REG_R4, 4, "R4"},
	{5, s390x.REG_R5, 5, "R5"},
	{6, s390x.REG_R6, 6, "R6"},
	{7, s390x.REG_R7, 7, "R7"},
	{8, s390x.REG_R8, 8, "R8"},
	{9, s390x.REG_R9, 9, "R9"},
	{10, s390x.REG_R10, -1, "R10"},
	{11, s390x.REG_R11, 10, "R11"},
	{12, s390x.REG_R12, 11, "R12"},
	{13, s390x.REGG, -1, "g"},
	{14, s390x.REG_R14, 12, "R14"},
	{15, s390x.REGSP, -1, "SP"},
	{16, s390x.REG_F0, -1, "F0"},
	{17, s390x.REG_F1, -1, "F1"},
	{18, s390x.REG_F2, -1, "F2"},
	{19, s390x.REG_F3, -1, "F3"},
	{20, s390x.REG_F4, -1, "F4"},
	{21, s390x.REG_F5, -1, "F5"},
	{22, s390x.REG_F6, -1, "F6"},
	{23, s390x.REG_F7, -1, "F7"},
	{24, s390x.REG_F8, -1, "F8"},
	{25, s390x.REG_F9, -1, "F9"},
	{26, s390x.REG_F10, -1, "F10"},
	{27, s390x.REG_F11, -1, "F11"},
	{28, s390x.REG_F12, -1, "F12"},
	{29, s390x.REG_F13, -1, "F13"},
	{30, s390x.REG_F14, -1, "F14"},
	{31, s390x.REG_F15, -1, "F15"},
	{32, 0, -1, "SB"},
}
var paramIntRegS390X = []int8(nil)
var paramFloatRegS390X = []int8(nil)
var gpRegMaskS390X = regMask(23551)
var fpRegMaskS390X = regMask(4294901760)
var specialRegMaskS390X = regMask(0)
var framepointerRegS390X = int8(-1)
var linkRegS390X = int8(14)
var registersWasm = [...]Register{
	{0, wasm.REG_R0, 0, "R0"},
	{1, wasm.REG_R1, 1, "R1"},
	{2, wasm.REG_R2, 2, "R2"},
	{3, wasm.REG_R3, 3, "R3"},
	{4, wasm.REG_R4, 4, "R4"},
	{5, wasm.REG_R5, 5, "R5"},
	{6, wasm.REG_R6, 6, "R6"},
	{7, wasm.REG_R7, 7, "R7"},
	{8, wasm.REG_R8, 8, "R8"},
	{9, wasm.REG_R9, 9, "R9"},
	{10, wasm.REG_R10, 10, "R10"},
	{11, wasm.REG_R11, 11, "R11"},
	{12, wasm.REG_R12, 12, "R12"},
	{13, wasm.REG_R13, 13, "R13"},
	{14, wasm.REG_R14, 14, "R14"},
	{15, wasm.REG_R15, 15, "R15"},
	{16, wasm.REG_F0, -1, "F0"},
	{17, wasm.REG_F1, -1, "F1"},
	{18, wasm.REG_F2, -1, "F2"},
	{19, wasm.REG_F3, -1, "F3"},
	{20, wasm.REG_F4, -1, "F4"},
	{21, wasm.REG_F5, -1, "F5"},
	{22, wasm.REG_F6, -1, "F6"},
	{23, wasm.REG_F7, -1, "F7"},
	{24, wasm.REG_F8, -1, "F8"},
	{25, wasm.REG_F9, -1, "F9"},
	{26, wasm.REG_F10, -1, "F10"},
	{27, wasm.REG_F11, -1, "F11"},
	{28, wasm.REG_F12, -1, "F12"},
	{29, wasm.REG_F13, -1, "F13"},
	{30, wasm.REG_F14, -1, "F14"},
	{31, wasm.REG_F15, -1, "F15"},
	{32, wasm.REG_F16, -1, "F16"},
	{33, wasm.REG_F17, -1, "F17"},
	{34, wasm.REG_F18, -1, "F18"},
	{35, wasm.REG_F19, -1, "F19"},
	{36, wasm.REG_F20, -1, "F20"},
	{37, wasm.REG_F21, -1, "F21"},
	{38, wasm.REG_F22, -1, "F22"},
	{39, wasm.REG_F23, -1, "F23"},
	{40, wasm.REG_F24, -1, "F24"},
	{41, wasm.REG_F25, -1, "F25"},
	{42, wasm.REG_F26, -1, "F26"},
	{43, wasm.REG_F27, -1, "F27"},
	{44, wasm.REG_F28, -1, "F28"},
	{45, wasm.REG_F29, -1, "F29"},
	{46, wasm.REG_F30, -1, "F30"},
	{47, wasm.REG_F31, -1, "F31"},
	{48, wasm.REGSP, -1, "SP"},
	{49, wasm.REGG, -1, "g"},
	{50, 0, -1, "SB"},
}
var paramIntRegWasm = []int8(nil)
var paramFloatRegWasm = []int8(nil)
var gpRegMaskWasm = regMask(65535)
var fpRegMaskWasm = regMask(281474976645120)
var fp32RegMaskWasm = regMask(4294901760)
var fp64RegMaskWasm = regMask(281470681743360)
var specialRegMaskWasm = regMask(0)
var framepointerRegWasm = int8(-1)
var linkRegWasm = int8(-1)

"""




```