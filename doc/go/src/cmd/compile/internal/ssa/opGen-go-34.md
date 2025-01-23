Response:
Let's break down the thought process to answer the request about the provided Go code snippet.

**1. Initial Understanding of the Request:**

The core request is to understand the *functionality* of the provided Go code. The code is clearly a definition of a table or array of structures. Each structure seems to describe an "operation" or "opcode". The request also asks to infer the broader Go feature being implemented, provide code examples, discuss command-line parameters (if applicable), and highlight potential errors. Crucially, it mentions this is part 35/36, suggesting a summarization is also needed.

**2. Analyzing the Structure of the Data:**

The code defines a slice of structs. Each struct has fields like `name`, `argLen`, `auxType`, `call`, `generic`, etc. This strongly suggests a description of different operations within a compiler or virtual machine. The `argLen` field likely indicates the number of arguments the operation takes. `auxType` hints at auxiliary data associated with the operation. `call` probably means the operation represents a function call. `generic` suggests the operation is not specific to a particular data type.

**3. Connecting to Go Compiler Concepts:**

Given the file path `go/src/cmd/compile/internal/ssa/opGen.go`, the context is clearly the Go compiler. The `ssa` package stands for Static Single Assignment, an intermediate representation used in compilers. Therefore, these structures are likely defining the *operations* supported in the SSA intermediate representation of the Go compiler.

**4. Inferring Functionality of Specific Operations:**

By examining the `name` field of some entries, we can deduce their purpose:

* `"Load"`, `"Store"`, `"Move"`: These are fundamental memory operations.
* `"Add32"`, `"Sub64"`: Arithmetic operations.
* `"ClosureCall"`, `"StaticCall"`, `"InterCall"`: Different types of function calls.
* `"SignExt8to16"`, `"ZeroExt32to64"`, `"Trunc64to32"`: Type conversion operations.
* `"SliceMake"`, `"StringLen"`: Operations related to built-in Go types like slices and strings.
* `"PanicBounds"`, `"NilCheck"`: Runtime checks.
* `"AtomicLoad8"`, `"AtomicStore64"`: Atomic operations for concurrency.

**5. Inferring the Overall Go Feature:**

Since this is part of the Go compiler's SSA generation, these operations are the building blocks for representing Go code in a low-level, architecture-independent way. This relates to how the compiler transforms Go source code into executable machine code.

**6. Creating Go Code Examples:**

To illustrate the usage, I need to connect these SSA operations back to concrete Go code. I'll choose a few diverse examples:

* **Load/Store:**  A simple variable assignment demonstrates this.
* **SliceMake/SliceLen:** Creating and getting the length of a slice.
* **StaticCall:** A regular function call.
* **PanicBounds:** Accessing an array out of bounds.

For each example, I'll describe the *expected* SSA operations that the compiler might generate (this is where the "假设" comes in). I won't be able to run the compiler and get the exact SSA output without more context, so the output is a plausible representation.

**7. Considering Command-Line Parameters:**

The provided code snippet itself doesn't directly process command-line arguments. However, the `go build` command, which utilizes this compiler code, has many flags. I'll discuss how flags like `-gcflags` could *indirectly* influence the SSA generation process, even though this specific file doesn't handle them.

**8. Identifying Potential Errors:**

Common errors when working with the concepts represented by these operations might include:

* **Incorrectly assuming the number of arguments:**  Referring to the `argLen` field is crucial.
* **Misunderstanding auxiliary data:**  Operations with `auxType` rely on that extra information.
* **Ignoring side effects:**  `hasSideEffects` is important for optimization and correctness.

I'll create examples of incorrect assumptions, like trying to use a `Load` operation with the wrong number of arguments.

**9. Summarizing the Functionality (Part 35/36):**

Since this is the penultimate part, the summary should emphasize that this file defines the *vocabulary* of the SSA intermediate representation. It provides the set of basic operations that the compiler uses to represent Go programs before generating machine code.

**10. Structuring the Answer:**

Finally, I'll organize the information into clear sections, addressing each part of the request:

* 功能 (Functionality)
* 实现的 Go 语言功能 (Implemented Go Feature)
* Go 代码举例 (Go Code Examples)
* 命令行参数 (Command-Line Parameters)
* 使用者易犯错的点 (Common Mistakes)
* 功能归纳 (Summary)

This methodical approach allows me to systematically analyze the code snippet and provide a comprehensive and accurate answer to the user's request. The key is to connect the low-level data definitions in the code to the higher-level concepts of the Go compiler and the Go language itself.
好的，让我们来分析一下 `go/src/cmd/compile/internal/ssa/opGen.go` 文件的这一部分代码的功能。

**功能列举:**

这段代码定义了一个名为 `opcodeTable` 的切片，其中包含了许多 `opData` 结构体。每个 `opData` 结构体描述了一个 SSA (Static Single Assignment) 操作码 (Opcode)。  这些结构体定义了以下关于每个操作码的信息：

* **`name`**: 操作码的名称，例如 "Load", "Store", "Add32", "Call"。
* **`argLen`**:  操作码接受的参数数量。`-1` 表示可变参数。
* **`auxType`**:  与操作码关联的辅助信息的类型。例如，对于 "Store" 操作，`auxType` 可能是被存储的值的类型。
* **`zeroWidth`**:  一个布尔值，指示该操作是否在逻辑上不消耗任何宽度（通常用于标记或元数据操作）。
* **`generic`**: 一个布尔值，指示该操作是否是通用的，不依赖于特定的数据类型。
* **`call`**: 一个布尔值，指示该操作是否代表一个函数调用。
* **`tailCall`**: 一个布尔值，指示该操作是否代表一个尾调用。
* **`hasSideEffects`**: 一个布尔值，指示该操作是否具有副作用（例如修改内存）。
* **`unsafePoint`**: 一个布尔值，指示该操作是否是一个不安全点（在垃圾回收期间可能需要特殊处理）。
* **`resultInArg0`**: 一个布尔值，指示操作的结果是否存储在其第一个参数的位置。
* **`symEffect`**:  一个 `SymEffect` 枚举值，描述了操作对符号的影响 (例如，读取、写入或无影响)。
* **`nilCheck`**: 一个布尔值，指示该操作是否执行空指针检查。
* **`commutative`**: 一个布尔值，指示该操作是否满足交换律 (例如加法)。

总而言之，这段代码是 Go 编译器中 SSA 中间表示层的一个核心组成部分，它定义了所有可用的操作以及它们的属性。

**推理出的 Go 语言功能实现:**

这段代码是 Go 编译器将 Go 源代码转换为机器码过程中的 **静态单赋值 (SSA) 中间表示** 的一部分。SSA 是一种编译器内部使用的中间语言，它具有以下关键特性：

* **静态单赋值**: 每个变量只被赋值一次。如果需要多次赋值，则会创建新的变量。
* **易于优化**: SSA 的特性使得编译器更容易进行各种优化，例如死代码消除、公共子表达式消除等。

这段代码定义了 SSA 中可以使用的各种操作，例如内存操作（Load, Store），算术运算（Add, Sub），类型转换（SignExt, Trunc），函数调用（Call），以及其他控制流和语言特有的操作。

**Go 代码举例说明:**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

**假设的输入与输出 (SSA 操作码):**

编译器在将上述代码转换为 SSA 形式时，可能会生成类似以下的 SSA 操作码序列（这只是一个简化的例子，实际的 SSA 可能更复杂）：

```
// main 函数
v1 = ConstInt 10           // 常量 10
v2 = VarDef {x} v1         // 定义变量 x 并赋值 v1
v3 = ConstInt 20           // 常量 20
v4 = VarDef {y} v3         // 定义变量 y 并赋值 v3
v5 = VarLive {x} v2        // 标记变量 x 仍然存活
v6 = VarLive {y} v4        // 标记变量 y 仍然存活
v7 = StaticCall {add} v5 v6 // 调用 add 函数，参数为 v5 和 v6
v8 = VarDef {z} v7         // 定义变量 z 并赋值 v7
v9 = VarLive {z} v8        // 标记变量 z 仍然存活
v10 = StaticCall {println} v9 // 调用 println 函数，参数为 v9
```

在这个简化的 SSA 例子中，我们可以看到：

* `ConstInt`:  对应于创建整数常量的操作。
* `VarDef`: 对应于定义新变量并赋值的操作。
* `VarLive`: 对应于标记变量在某个点仍然存活，这有助于后续的优化。
* `StaticCall`: 对应于对已知函数的静态调用。

**涉及的 SSA 操作码与 Go 代码的对应关系：**

* Go 代码中的 `x := 10` 会被翻译成 SSA 中的 `ConstInt` 和 `VarDef` 操作。
* Go 代码中的 `y := 20` 也会被翻译成 `ConstInt` 和 `VarDef` 操作。
* Go 代码中的 `add(x, y)` 会被翻译成 `StaticCall` 操作，其中 `{add}` 是指向 `add` 函数的符号引用。
* Go 代码中的 `println(z)` 也会被翻译成 `StaticCall` 操作。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的其他阶段。  然而，传递给 `go build` 等命令的某些标志可能会间接地影响 SSA 的生成和优化。

例如，使用 `-gcflags` 标志可以传递参数给 Go 编译器，其中一些参数可能会影响 SSA 的生成方式，例如：

* **`-N`**:  禁用优化。禁用优化可能会导致生成的 SSA 代码更加直观，但效率较低。
* **`-l`**:  禁用内联。禁用内联会影响函数调用的 SSA 表示。

**示例:**

```bash
go build -gcflags="-N -l" main.go
```

在这个例子中，`-gcflags="-N -l"` 将 `-N` 和 `-l` 传递给 Go 编译器，指示其禁用优化和内联。这将影响生成的 SSA 代码。

**使用者易犯错的点:**

作为编译器开发者，理解这些操作码的含义和正确使用方式至关重要。  常见的错误可能包括：

* **为操作码指定错误的参数数量 (`argLen`)**: 例如，尝试为一个需要两个参数的操作码只提供一个参数。
* **忽略 `auxType` 的要求**:  对于需要辅助信息的操作码，没有提供正确的辅助信息会导致错误。
* **对具有副作用 (`hasSideEffects: true`) 的操作码进行不正确的优化或消除**:  这可能导致程序行为的改变。
* **不理解不同调用操作码 (`ClosureCall`, `StaticCall`, `InterCall`) 的区别**:  错误地使用调用操作码会导致程序无法正确执行。

**功能归纳 (作为第 35 部分，共 36 部分):**

作为整个 `opGen.go` 文件的倒数第二部分，这段代码的核心功能是 **定义了 Go 编译器 SSA 中间表示的所有基本操作类型及其属性**。  这是构建 SSA 图的关键一步，后续的编译器阶段会基于这些操作进行代码转换、优化和最终的代码生成。  可以认为这部分代码是 SSA 层的“词汇表”，定义了编译器在中间表示阶段可以使用的所有“指令”。  接下来的部分很可能涉及如何实际生成和使用这些 SSA 操作码来表示 Go 代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/opGen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第35部分，共36部分，请归纳一下它的功能
```

### 源代码
```go
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
```