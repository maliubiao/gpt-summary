Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for the functionality of the given Go code, specifically the `genericOps` variable. It also asks for related concepts like example usage, reasoning behind certain designs, potential pitfalls, and how it relates to Go's functionality.

**2. Initial Scan and Keyword Recognition:**

The first thing I notice is the `genericOps` variable is a slice of `opData` structs. The comments mention "generic opcodes" and "SSA". This immediately suggests that this code is related to the *internal* workings of the Go compiler, specifically its Static Single Assignment (SSA) intermediate representation.

**3. Dissecting the `opData` Structure:**

I examine the fields of the `opData` struct: `name`, `argLength`, `commutative`, `typ`, `aux`, `auxint`, `symEffect`, `zeroWidth`, `resultInArg0`, `call`, `nilCheck`, and `hasSideEffects`. I start to map these to compiler concepts:

* `name`: The name of the operation (e.g., "Add32", "Load").
* `argLength`: The number of input arguments.
* `commutative`: Whether the order of inputs matters.
* `typ`: The Go type of the operation's result (or arguments in some cases).
* `aux`, `auxint`:  Auxiliary information, likely for constants, symbols, or flags.
* `symEffect`:  Indicates if the operation has side effects related to symbols (like accessing globals).
* `zeroWidth`:  Operations that don't produce a "real" value (like memory operations).
* `resultInArg0`: The result overwrites the first argument (optimization hint).
* `call`:  Represents a function call.
* `nilCheck`: Indicates a nil pointer check.
* `hasSideEffects`:  Indicates if the operation has side effects beyond just producing a value (like stores).

**4. Grouping and Categorization of Operations:**

As I go through the `genericOps` list, I start to mentally group them:

* **Arithmetic:** `Add`, `Sub`, `Mul`, `Div`, etc.
* **Bitwise:** `And`, `Or`, `Xor`, shifts, rotates.
* **Comparisons:** `Eq`, `Neq`, `Less`, `Leq`.
* **Boolean Logic:** `AndB`, `OrB`, `Not`.
* **Conversions:**  `SignExt`, `ZeroExt`, `Trunc`, type conversions.
* **Memory Operations:** `Load`, `Store`, `Move`, `Zero`.
* **Control Flow:** `Phi` (for merging values), function calls.
* **Constants:** `ConstBool`, `ConstInt`, `ConstFloat`.
* **Pointers and Addresses:** `Addr`, `LocalAddr`, `PtrIndex`.
* **Slices, Strings, Interfaces:** Operations specific to these Go types.
* **Atomic Operations:** `AtomicLoad`, `AtomicStore`, `AtomicAdd`, etc.

This categorization helps me understand the overall scope and purpose.

**5. Identifying Key Concepts and Relationships:**

* **SSA:** The "generic" nature and the concept of "operations" strongly point to SSA. I know SSA is an intermediate representation used by compilers.
* **Lowering:** The comments about "lowering" (e.g., for `Move`) and the existence of architecture-specific opcodes (mentioned in the `init` function) suggest that these generic ops are a higher-level representation that gets translated into machine-specific instructions.
* **Type System:** The explicit widths (8, 16, 32, 64) and the presence of signed/unsigned variants demonstrate how Go's type system is represented at this level.
* **Memory Management:** The memory operations (`Load`, `Store`, `Move`, write barriers) and concepts like `InitMem`, `Arg`, `LocalAddr` are clearly related to how Go manages memory, including the garbage collector.
* **Function Calls:** The various `Call` opcodes and the explanation of arguments and return values illustrate how function calls are represented in SSA.
* **Atomic Operations:** The dedicated set of `Atomic...` operations reflects Go's support for concurrency and synchronization.

**6. Formulating Examples and Explanations:**

With a good grasp of the categories and concepts, I can start generating examples and explanations. For instance:

* **Arithmetic:** Show a simple addition with `Add32`.
* **Memory:**  Illustrate a `Load` and `Store`.
* **Function Call:** Explain the role of `StaticCall`.
* **Constants:**  Demonstrate how `Const32` works.
* **Common Mistakes:**  Highlight the difference between signed and unsigned operations and potential confusion with shift amounts.

**7. Addressing Specific Questions:**

* **Functionality:**  Summarize the core purpose as defining a set of low-level operations for the Go compiler's intermediate representation.
* **Go Feature Implementation:** Connect specific opcodes to corresponding Go language constructs (e.g., `SliceMake` to slice creation).
* **Code Reasoning:** Explain *why* certain ops exist (e.g., `Convert` for GC safety).
* **Command-Line Arguments:** Realize that this code *doesn't* directly handle command-line arguments. It's part of the compiler's internal logic.
* **Common Mistakes:** Focus on type mismatches and signed/unsigned misunderstandings.

**8. Review and Refinement:**

Finally, I review my analysis, ensuring clarity, accuracy, and completeness. I check for any logical gaps or areas where further explanation might be needed. I organize the information in a structured way to make it easier to understand.

This iterative process of scanning, dissecting, categorizing, connecting, and formulating examples allows for a comprehensive understanding of the provided Go code snippet and its role within the Go compiler. The key is to recognize the context (compiler internals, SSA) and then map the individual elements to higher-level Go language features and concepts.
这段代码定义了Go编译器在中间代码表示（SSA，Static Single Assignment）阶段使用的一组**通用操作码（opcodes）**。 这些操作码不依赖于特定的计算机架构，是更抽象的表示，最终会被“lowering”到特定架构的操作码。

**主要功能：**

1. **定义了一系列基本的操作**：涵盖了算术运算、位运算、比较、逻辑运算、数据移动、类型转换、内存操作、函数调用、常量表示、控制流等各种基本计算和操作。
2. **作为 Go 语言编译器的中间表示**：这些操作码是 Go 源代码在编译过程中被转换成的中间形式，方便进行各种优化和分析。
3. **为后端代码生成提供基础**：最终，这些通用操作码会被翻译成目标架构的机器指令。

**更细致的功能分解：**

* **算术运算 (Arithmetic)：**  定义了各种位宽的加 (`Add8`, `Add16`, `Add32`, `Add64`, `AddPtr`, `Add32F`, `Add64F`)、减 (`Sub8` - `Sub64F`)、乘 (`Mul8` - `Mul64F`)、除 (`Div32F`, `Div64F`) 以及一些特殊的乘法运算（如高位乘法 `Hmul`，带溢出检查的乘法 `Mul*uover` 等）。
* **位运算 (Bitwise)：** 定义了按位与 (`And`)、或 (`Or`)、异或 (`Xor`)、左移 (`Lsh`)、右移（有符号 `Rsh` 和无符号 `RshU`）。
* **比较运算 (Comparisons)：** 定义了各种类型和位宽的相等 (`Eq`)、不等 (`Neq`)、小于 (`Less`)、小于等于 (`Leq`) 的比较操作。
* **逻辑运算 (Boolean Operations)：** 定义了布尔与 (`AndB`)、或 (`OrB`)、相等 (`EqB`)、不等 (`NeqB`) 和非 (`Not`)。
* **数据移动 (Data Movement)：**  定义了 `Copy`（复制值）和 `Phi`（用于在控制流汇聚点选择不同的值）。 `Convert` 用于指针和整数之间的转换，特别考虑了垃圾回收。
* **常量 (Constants)：** 定义了各种类型的常量表示，如布尔值 (`ConstBool`)、字符串 (`ConstString`)、整数 (`Const8` - `Const64`)、浮点数 (`Const32F`, `Const64F`)、nil 指针 (`ConstNil`) 等。
* **内存操作 (Memory Operations)：** 定义了从内存加载数据 (`Load`, `Dereference`)、存储数据到内存 (`Store`)、移动内存块 (`Move`)、将内存块置零 (`Zero`) 以及带有写屏障的内存操作 (`StoreWB`, `MoveWB`, `ZeroWB`)。
* **函数调用 (Function Calls)：** 定义了不同类型的函数调用，如直接调用 (`StaticCall`)、接口调用 (`InterCall`)、闭包调用 (`ClosureCall`) 和尾调用 (`TailCall`)。还有延迟展开的调用 (`LECall` 系列)。
* **类型转换 (Conversions)：** 定义了各种有符号扩展 (`SignExt`)、零扩展 (`ZeroExt`)、截断 (`Trunc`) 以及数值类型之间的转换 (`Cvt`)。
* **其他操作：** 包括取反 (`Neg`)、按位取反 (`Com`)、计算尾部零个数 (`Ctz`)、计算有效位数 (`BitLen`)、字节序交换 (`Bswap`)、位反转 (`BitRev`)、统计位数 (`PopCount`)、循环移位 (`RotateLeft`)、平方根 (`Sqrt`)、舍入 (`Floor`, `Ceil`, `Trunc`, `Round`)、绝对值 (`Abs`)、符号复制 (`Copysign`)、最小值/最大值 (`Min`, `Max`)、三元选择 (`CondSelect`)、获取 Goroutine (`GetG`) 等等。
* **安全检查 (Safety Checks)：**  定义了运行时插入的 nil 指针检查 (`NilCheck`)、越界检查 (`IsInBounds`, `IsSliceInBounds`)、非 nil 检查 (`IsNonNil`)。
* **原子操作 (Atomic Operations)：** 定义了一系列用于并发编程的原子操作，如原子加载 (`AtomicLoad`)、原子存储 (`AtomicStore`)、原子交换 (`AtomicExchange`)、原子加 (`AtomicAdd`)、原子比较并交换 (`AtomicCompareAndSwap`) 以及原子逻辑运算 (`AtomicAnd`, `AtomicOr`)。
* **与架构相关的伪操作：**  如 `Int64Make`, `Int64Hi`, `Int64Lo` 用于在 32 位架构上处理 64 位整数。
* **控制流相关的操作：**  `Phi` 用于表示控制流合并时的值选择。

**可以推理出的 Go 语言功能实现：**

这个文件定义的操作码直接对应着 Go 语言的各种基本操作和类型。例如：

* **算术运算符：** `+`, `-`, `*`, `/` 等运算符会被翻译成相应的 `Add`, `Sub`, `Mul`, `Div` 操作码。
* **位运算符：** `&`, `|`, `^`, `<<`, `>>` 等运算符会被翻译成 `And`, `Or`, `Xor`, `Lsh`, `Rsh`/`RshU` 操作码。
* **比较运算符：** `==`, `!=`, `<`, `<=`, `>`, `>=` 等运算符会被翻译成 `Eq`, `Neq`, `Less`, `Leq` 操作码。
* **类型转换：**  显式或隐式的类型转换会被翻译成 `SignExt`, `ZeroExt`, `Trunc`, `Cvt` 等操作码。
* **函数调用：**  Go 函数调用会被翻译成 `StaticCall`, `InterCall`, `ClosureCall` 等操作码。
* **内存访问：**  对变量的读写操作会被翻译成 `Load` 和 `Store` 操作码。
* **切片、字符串、接口操作：**  例如，创建切片会使用 `SliceMake`，获取切片长度会使用 `SliceLen`，等等。
* **原子操作：** `sync/atomic` 包中的函数会被翻译成相应的 `AtomicLoad`, `AtomicStore`, `AtomicAdd` 等操作码。

**Go 代码举例说明：**

```go
package main

import "fmt"

func main() {
	a := 10
	b := 20
	sum := a + b // 可能被编译成 Add32 操作

	fmt.Println(sum)

	var c uint8 = 5
	var d uint16 = uint16(c) // 可能被编译成 ZeroExt8to16 操作
	fmt.Println(d)

	arr := []int{1, 2, 3}
	length := len(arr) // 可能被编译成 SliceLen 操作
	fmt.Println(length)
}
```

**假设的输入与输出（SSA 形式，简化）：**

在编译 `a + b` 时，可能会生成如下的 SSA 指令：

```
v1 = Const32 <int> 10
v2 = Const32 <int> 20
v3 = Add32 <int> v1 v2
```

这里 `v1`, `v2`, `v3` 代表 SSA 中的值，`Const32` 表示 32 位整数常量，`Add32` 表示 32 位整数加法。

在编译 `uint16(c)` 时，可能会生成：

```
v4 = ... // 表示变量 c 的值
v5 = ZeroExt8to16 <uint16> v4
```

在编译 `len(arr)` 时，可能会生成：

```
v6 = ... // 表示切片 arr
v7 = SliceLen <int> v6
```

**命令行参数的具体处理：**

这个代码片段本身不涉及命令行参数的处理。命令行参数的处理发生在 Go 编译器的前端部分，负责解析命令行输入，并根据参数配置编译过程。这个 `genericOps.go` 文件定义的是编译过程中的中间表示，在命令行参数处理之后。

**使用者易犯错的点：**

作为 Go 开发者，一般不会直接接触到这些 `genericOps`。这些是编译器内部使用的。但是，理解这些操作码有助于理解 Go 编译器的优化和底层实现。

**容易混淆的点（对于编译器开发者）：**

* **有符号和无符号运算：** 区分有符号和无符号的操作码（例如 `Div32` vs `Div32u`，`Rsh` vs `RshU`）非常重要，错误的选择会导致逻辑错误。
* **位宽：**  必须使用正确的位宽操作码来匹配操作数类型，否则会导致类型不匹配或精度丢失。
* **内存操作的顺序和副作用：**  理解内存操作（`Load`, `Store`, `Move`）的副作用和正确的执行顺序对于保证程序的正确性至关重要，尤其是在并发场景下。
* **`AuxInt` 和 `Aux` 的使用：**  正确理解和使用 `AuxInt` 和 `Aux` 字段存储的额外信息（例如常量值、符号信息、类型信息）对于代码生成至关重要。例如，在除法操作中，`AuxInt` 可以用来表示除数是否已知非 -1，从而进行优化。
* **原子操作的语义：**  正确使用和理解原子操作的内存顺序和同步语义，避免出现数据竞争和死锁。例如，区分带 `Acq` (acquire) 和 `Rel` (release) 后缀的原子操作。

总而言之，`genericOps.go` 文件是 Go 编译器核心组件的一部分，它定义了编译器在进行静态单赋值 (SSA) 优化时所使用的一组与架构无关的通用操作，是理解 Go 编译器工作原理的重要入口。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/_gen/genericOps.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// Generic opcodes typically specify a width. The inputs and outputs
// of that op are the given number of bits wide. There is no notion of
// "sign", so Add32 can be used both for signed and unsigned 32-bit
// addition.

// Signed/unsigned is explicit with the extension ops
// (SignExt*/ZeroExt*) and implicit as the arg to some opcodes
// (e.g. the second argument to shifts is unsigned). If not mentioned,
// all args take signed inputs, or don't care whether their inputs
// are signed or unsigned.

var genericOps = []opData{
	// 2-input arithmetic
	// Types must be consistent with Go typing. Add, for example, must take two values
	// of the same type and produces that same type.
	{name: "Add8", argLength: 2, commutative: true}, // arg0 + arg1
	{name: "Add16", argLength: 2, commutative: true},
	{name: "Add32", argLength: 2, commutative: true},
	{name: "Add64", argLength: 2, commutative: true},
	{name: "AddPtr", argLength: 2}, // For address calculations.  arg0 is a pointer and arg1 is an int.
	{name: "Add32F", argLength: 2, commutative: true},
	{name: "Add64F", argLength: 2, commutative: true},

	{name: "Sub8", argLength: 2}, // arg0 - arg1
	{name: "Sub16", argLength: 2},
	{name: "Sub32", argLength: 2},
	{name: "Sub64", argLength: 2},
	{name: "SubPtr", argLength: 2},
	{name: "Sub32F", argLength: 2},
	{name: "Sub64F", argLength: 2},

	{name: "Mul8", argLength: 2, commutative: true}, // arg0 * arg1
	{name: "Mul16", argLength: 2, commutative: true},
	{name: "Mul32", argLength: 2, commutative: true},
	{name: "Mul64", argLength: 2, commutative: true},
	{name: "Mul32F", argLength: 2, commutative: true},
	{name: "Mul64F", argLength: 2, commutative: true},

	{name: "Div32F", argLength: 2}, // arg0 / arg1
	{name: "Div64F", argLength: 2},

	{name: "Hmul32", argLength: 2, commutative: true},
	{name: "Hmul32u", argLength: 2, commutative: true},
	{name: "Hmul64", argLength: 2, commutative: true},
	{name: "Hmul64u", argLength: 2, commutative: true},

	{name: "Mul32uhilo", argLength: 2, typ: "(UInt32,UInt32)", commutative: true}, // arg0 * arg1, returns (hi, lo)
	{name: "Mul64uhilo", argLength: 2, typ: "(UInt64,UInt64)", commutative: true}, // arg0 * arg1, returns (hi, lo)

	{name: "Mul32uover", argLength: 2, typ: "(UInt32,Bool)", commutative: true}, // Let x = arg0*arg1 (full 32x32-> 64 unsigned multiply), returns (uint32(x), (uint32(x) != x))
	{name: "Mul64uover", argLength: 2, typ: "(UInt64,Bool)", commutative: true}, // Let x = arg0*arg1 (full 64x64->128 unsigned multiply), returns (uint64(x), (uint64(x) != x))

	// Weird special instructions for use in the strength reduction of divides.
	// These ops compute unsigned (arg0 + arg1) / 2, correct to all
	// 32/64 bits, even when the intermediate result of the add has 33/65 bits.
	// These ops can assume arg0 >= arg1.
	// Note: these ops aren't commutative!
	{name: "Avg32u", argLength: 2, typ: "UInt32"}, // 32-bit platforms only
	{name: "Avg64u", argLength: 2, typ: "UInt64"}, // 64-bit platforms only

	// For Div16, Div32 and Div64, AuxInt non-zero means that the divisor has been proved to be not -1
	// or that the dividend is not the most negative value.
	{name: "Div8", argLength: 2},  // arg0 / arg1, signed
	{name: "Div8u", argLength: 2}, // arg0 / arg1, unsigned
	{name: "Div16", argLength: 2, aux: "Bool"},
	{name: "Div16u", argLength: 2},
	{name: "Div32", argLength: 2, aux: "Bool"},
	{name: "Div32u", argLength: 2},
	{name: "Div64", argLength: 2, aux: "Bool"},
	{name: "Div64u", argLength: 2},
	{name: "Div128u", argLength: 3}, // arg0:arg1 / arg2 (128-bit divided by 64-bit), returns (q, r)

	// For Mod16, Mod32 and Mod64, AuxInt non-zero means that the divisor has been proved to be not -1.
	{name: "Mod8", argLength: 2},  // arg0 % arg1, signed
	{name: "Mod8u", argLength: 2}, // arg0 % arg1, unsigned
	{name: "Mod16", argLength: 2, aux: "Bool"},
	{name: "Mod16u", argLength: 2},
	{name: "Mod32", argLength: 2, aux: "Bool"},
	{name: "Mod32u", argLength: 2},
	{name: "Mod64", argLength: 2, aux: "Bool"},
	{name: "Mod64u", argLength: 2},

	{name: "And8", argLength: 2, commutative: true}, // arg0 & arg1
	{name: "And16", argLength: 2, commutative: true},
	{name: "And32", argLength: 2, commutative: true},
	{name: "And64", argLength: 2, commutative: true},

	{name: "Or8", argLength: 2, commutative: true}, // arg0 | arg1
	{name: "Or16", argLength: 2, commutative: true},
	{name: "Or32", argLength: 2, commutative: true},
	{name: "Or64", argLength: 2, commutative: true},

	{name: "Xor8", argLength: 2, commutative: true}, // arg0 ^ arg1
	{name: "Xor16", argLength: 2, commutative: true},
	{name: "Xor32", argLength: 2, commutative: true},
	{name: "Xor64", argLength: 2, commutative: true},

	// For shifts, AxB means the shifted value has A bits and the shift amount has B bits.
	// Shift amounts are considered unsigned.
	// If arg1 is known to be nonnegative and less than the number of bits in arg0,
	// then auxInt may be set to 1.
	// This enables better code generation on some platforms.
	{name: "Lsh8x8", argLength: 2, aux: "Bool"}, // arg0 << arg1
	{name: "Lsh8x16", argLength: 2, aux: "Bool"},
	{name: "Lsh8x32", argLength: 2, aux: "Bool"},
	{name: "Lsh8x64", argLength: 2, aux: "Bool"},
	{name: "Lsh16x8", argLength: 2, aux: "Bool"},
	{name: "Lsh16x16", argLength: 2, aux: "Bool"},
	{name: "Lsh16x32", argLength: 2, aux: "Bool"},
	{name: "Lsh16x64", argLength: 2, aux: "Bool"},
	{name: "Lsh32x8", argLength: 2, aux: "Bool"},
	{name: "Lsh32x16", argLength: 2, aux: "Bool"},
	{name: "Lsh32x32", argLength: 2, aux: "Bool"},
	{name: "Lsh32x64", argLength: 2, aux: "Bool"},
	{name: "Lsh64x8", argLength: 2, aux: "Bool"},
	{name: "Lsh64x16", argLength: 2, aux: "Bool"},
	{name: "Lsh64x32", argLength: 2, aux: "Bool"},
	{name: "Lsh64x64", argLength: 2, aux: "Bool"},

	{name: "Rsh8x8", argLength: 2, aux: "Bool"}, // arg0 >> arg1, signed
	{name: "Rsh8x16", argLength: 2, aux: "Bool"},
	{name: "Rsh8x32", argLength: 2, aux: "Bool"},
	{name: "Rsh8x64", argLength: 2, aux: "Bool"},
	{name: "Rsh16x8", argLength: 2, aux: "Bool"},
	{name: "Rsh16x16", argLength: 2, aux: "Bool"},
	{name: "Rsh16x32", argLength: 2, aux: "Bool"},
	{name: "Rsh16x64", argLength: 2, aux: "Bool"},
	{name: "Rsh32x8", argLength: 2, aux: "Bool"},
	{name: "Rsh32x16", argLength: 2, aux: "Bool"},
	{name: "Rsh32x32", argLength: 2, aux: "Bool"},
	{name: "Rsh32x64", argLength: 2, aux: "Bool"},
	{name: "Rsh64x8", argLength: 2, aux: "Bool"},
	{name: "Rsh64x16", argLength: 2, aux: "Bool"},
	{name: "Rsh64x32", argLength: 2, aux: "Bool"},
	{name: "Rsh64x64", argLength: 2, aux: "Bool"},

	{name: "Rsh8Ux8", argLength: 2, aux: "Bool"}, // arg0 >> arg1, unsigned
	{name: "Rsh8Ux16", argLength: 2, aux: "Bool"},
	{name: "Rsh8Ux32", argLength: 2, aux: "Bool"},
	{name: "Rsh8Ux64", argLength: 2, aux: "Bool"},
	{name: "Rsh16Ux8", argLength: 2, aux: "Bool"},
	{name: "Rsh16Ux16", argLength: 2, aux: "Bool"},
	{name: "Rsh16Ux32", argLength: 2, aux: "Bool"},
	{name: "Rsh16Ux64", argLength: 2, aux: "Bool"},
	{name: "Rsh32Ux8", argLength: 2, aux: "Bool"},
	{name: "Rsh32Ux16", argLength: 2, aux: "Bool"},
	{name: "Rsh32Ux32", argLength: 2, aux: "Bool"},
	{name: "Rsh32Ux64", argLength: 2, aux: "Bool"},
	{name: "Rsh64Ux8", argLength: 2, aux: "Bool"},
	{name: "Rsh64Ux16", argLength: 2, aux: "Bool"},
	{name: "Rsh64Ux32", argLength: 2, aux: "Bool"},
	{name: "Rsh64Ux64", argLength: 2, aux: "Bool"},

	// 2-input comparisons
	{name: "Eq8", argLength: 2, commutative: true, typ: "Bool"}, // arg0 == arg1
	{name: "Eq16", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Eq32", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Eq64", argLength: 2, commutative: true, typ: "Bool"},
	{name: "EqPtr", argLength: 2, commutative: true, typ: "Bool"},
	{name: "EqInter", argLength: 2, typ: "Bool"}, // arg0 or arg1 is nil; other cases handled by frontend
	{name: "EqSlice", argLength: 2, typ: "Bool"}, // arg0 or arg1 is nil; other cases handled by frontend
	{name: "Eq32F", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Eq64F", argLength: 2, commutative: true, typ: "Bool"},

	{name: "Neq8", argLength: 2, commutative: true, typ: "Bool"}, // arg0 != arg1
	{name: "Neq16", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Neq32", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Neq64", argLength: 2, commutative: true, typ: "Bool"},
	{name: "NeqPtr", argLength: 2, commutative: true, typ: "Bool"},
	{name: "NeqInter", argLength: 2, typ: "Bool"}, // arg0 or arg1 is nil; other cases handled by frontend
	{name: "NeqSlice", argLength: 2, typ: "Bool"}, // arg0 or arg1 is nil; other cases handled by frontend
	{name: "Neq32F", argLength: 2, commutative: true, typ: "Bool"},
	{name: "Neq64F", argLength: 2, commutative: true, typ: "Bool"},

	{name: "Less8", argLength: 2, typ: "Bool"},  // arg0 < arg1, signed
	{name: "Less8U", argLength: 2, typ: "Bool"}, // arg0 < arg1, unsigned
	{name: "Less16", argLength: 2, typ: "Bool"},
	{name: "Less16U", argLength: 2, typ: "Bool"},
	{name: "Less32", argLength: 2, typ: "Bool"},
	{name: "Less32U", argLength: 2, typ: "Bool"},
	{name: "Less64", argLength: 2, typ: "Bool"},
	{name: "Less64U", argLength: 2, typ: "Bool"},
	{name: "Less32F", argLength: 2, typ: "Bool"},
	{name: "Less64F", argLength: 2, typ: "Bool"},

	{name: "Leq8", argLength: 2, typ: "Bool"},  // arg0 <= arg1, signed
	{name: "Leq8U", argLength: 2, typ: "Bool"}, // arg0 <= arg1, unsigned
	{name: "Leq16", argLength: 2, typ: "Bool"},
	{name: "Leq16U", argLength: 2, typ: "Bool"},
	{name: "Leq32", argLength: 2, typ: "Bool"},
	{name: "Leq32U", argLength: 2, typ: "Bool"},
	{name: "Leq64", argLength: 2, typ: "Bool"},
	{name: "Leq64U", argLength: 2, typ: "Bool"},
	{name: "Leq32F", argLength: 2, typ: "Bool"},
	{name: "Leq64F", argLength: 2, typ: "Bool"},

	// the type of a CondSelect is the same as the type of its first
	// two arguments, which should be register-width scalars; the third
	// argument should be a boolean
	{name: "CondSelect", argLength: 3}, // arg2 ? arg0 : arg1

	// boolean ops
	{name: "AndB", argLength: 2, commutative: true, typ: "Bool"}, // arg0 && arg1 (not shortcircuited)
	{name: "OrB", argLength: 2, commutative: true, typ: "Bool"},  // arg0 || arg1 (not shortcircuited)
	{name: "EqB", argLength: 2, commutative: true, typ: "Bool"},  // arg0 == arg1
	{name: "NeqB", argLength: 2, commutative: true, typ: "Bool"}, // arg0 != arg1
	{name: "Not", argLength: 1, typ: "Bool"},                     // !arg0, boolean

	// 1-input ops
	{name: "Neg8", argLength: 1}, // -arg0
	{name: "Neg16", argLength: 1},
	{name: "Neg32", argLength: 1},
	{name: "Neg64", argLength: 1},
	{name: "Neg32F", argLength: 1},
	{name: "Neg64F", argLength: 1},

	{name: "Com8", argLength: 1}, // ^arg0
	{name: "Com16", argLength: 1},
	{name: "Com32", argLength: 1},
	{name: "Com64", argLength: 1},

	{name: "Ctz8", argLength: 1},         // Count trailing (low order) zeroes (returns 0-8)
	{name: "Ctz16", argLength: 1},        // Count trailing (low order) zeroes (returns 0-16)
	{name: "Ctz32", argLength: 1},        // Count trailing (low order) zeroes (returns 0-32)
	{name: "Ctz64", argLength: 1},        // Count trailing (low order) zeroes (returns 0-64)
	{name: "Ctz64On32", argLength: 2},    // Count trailing (low order) zeroes (returns 0-64) in arg[1]<<32+arg[0]
	{name: "Ctz8NonZero", argLength: 1},  // same as above, but arg[0] known to be non-zero, returns 0-7
	{name: "Ctz16NonZero", argLength: 1}, // same as above, but arg[0] known to be non-zero, returns 0-15
	{name: "Ctz32NonZero", argLength: 1}, // same as above, but arg[0] known to be non-zero, returns 0-31
	{name: "Ctz64NonZero", argLength: 1}, // same as above, but arg[0] known to be non-zero, returns 0-63
	{name: "BitLen8", argLength: 1},      // Number of bits in arg[0] (returns 0-8)
	{name: "BitLen16", argLength: 1},     // Number of bits in arg[0] (returns 0-16)
	{name: "BitLen32", argLength: 1},     // Number of bits in arg[0] (returns 0-32)
	{name: "BitLen64", argLength: 1},     // Number of bits in arg[0] (returns 0-64)

	{name: "Bswap16", argLength: 1}, // Swap bytes
	{name: "Bswap32", argLength: 1}, // Swap bytes
	{name: "Bswap64", argLength: 1}, // Swap bytes

	{name: "BitRev8", argLength: 1},  // Reverse the bits in arg[0]
	{name: "BitRev16", argLength: 1}, // Reverse the bits in arg[0]
	{name: "BitRev32", argLength: 1}, // Reverse the bits in arg[0]
	{name: "BitRev64", argLength: 1}, // Reverse the bits in arg[0]

	{name: "PopCount8", argLength: 1},  // Count bits in arg[0]
	{name: "PopCount16", argLength: 1}, // Count bits in arg[0]
	{name: "PopCount32", argLength: 1}, // Count bits in arg[0]
	{name: "PopCount64", argLength: 1}, // Count bits in arg[0]

	// RotateLeftX instructions rotate the X bits of arg[0] to the left
	// by the low lg_2(X) bits of arg[1], interpreted as an unsigned value.
	// Note that this works out regardless of the bit width or signedness of
	// arg[1]. In particular, RotateLeft by x is the same as RotateRight by -x.
	{name: "RotateLeft64", argLength: 2},
	{name: "RotateLeft32", argLength: 2},
	{name: "RotateLeft16", argLength: 2},
	{name: "RotateLeft8", argLength: 2},

	// Square root.
	// Special cases:
	//   +∞  → +∞
	//   ±0  → ±0 (sign preserved)
	//   x<0 → NaN
	//   NaN → NaN
	{name: "Sqrt", argLength: 1},   // √arg0 (floating point, double precision)
	{name: "Sqrt32", argLength: 1}, // √arg0 (floating point, single precision)

	// Round to integer, float64 only.
	// Special cases:
	//   ±∞  → ±∞ (sign preserved)
	//   ±0  → ±0 (sign preserved)
	//   NaN → NaN
	{name: "Floor", argLength: 1},       // round arg0 toward -∞
	{name: "Ceil", argLength: 1},        // round arg0 toward +∞
	{name: "Trunc", argLength: 1},       // round arg0 toward 0
	{name: "Round", argLength: 1},       // round arg0 to nearest, ties away from 0
	{name: "RoundToEven", argLength: 1}, // round arg0 to nearest, ties to even

	// Modify the sign bit
	{name: "Abs", argLength: 1},      // absolute value arg0
	{name: "Copysign", argLength: 2}, // copy sign from arg0 to arg1

	// Integer min/max implementation, if hardware is available.
	{name: "Min64", argLength: 2},  // min(arg0,arg1), signed
	{name: "Max64", argLength: 2},  // max(arg0,arg1), signed
	{name: "Min64u", argLength: 2}, // min(arg0,arg1), unsigned
	{name: "Max64u", argLength: 2}, // max(arg0,arg1), unsigned

	// Float min/max implementation, if hardware is available.
	{name: "Min64F", argLength: 2}, // min(arg0,arg1)
	{name: "Min32F", argLength: 2}, // min(arg0,arg1)
	{name: "Max64F", argLength: 2}, // max(arg0,arg1)
	{name: "Max32F", argLength: 2}, // max(arg0,arg1)

	// 3-input opcode.
	// Fused-multiply-add, float64 only.
	// When a*b+c is exactly zero (before rounding), then the result is +0 or -0.
	// The 0's sign is determined according to the standard rules for the
	// addition (-0 if both a*b and c are -0, +0 otherwise).
	//
	// Otherwise, when a*b+c rounds to zero, then the resulting 0's sign is
	// determined by the sign of the exact result a*b+c.
	// See section 6.3 in ieee754.
	//
	// When the multiply is an infinity times a zero, the result is NaN.
	// See section 7.2 in ieee754.
	{name: "FMA", argLength: 3}, // compute (a*b)+c without intermediate rounding

	// Data movement. Max argument length for Phi is indefinite.
	{name: "Phi", argLength: -1, zeroWidth: true}, // select an argument based on which predecessor block we came from
	{name: "Copy", argLength: 1},                  // output = arg0
	// Convert converts between pointers and integers.
	// We have a special op for this so as to not confuse GC
	// (particularly stack maps).  It takes a memory arg so it
	// gets correctly ordered with respect to GC safepoints.
	// It gets compiled to nothing, so its result must in the same
	// register as its argument. regalloc knows it can use any
	// allocatable integer register for OpConvert.
	// arg0=ptr/int arg1=mem, output=int/ptr
	{name: "Convert", argLength: 2, zeroWidth: true, resultInArg0: true},

	// constants. Constant values are stored in the aux or
	// auxint fields.
	{name: "ConstBool", aux: "Bool"},     // auxint is 0 for false and 1 for true
	{name: "ConstString", aux: "String"}, // value is aux.(string)
	{name: "ConstNil", typ: "BytePtr"},   // nil pointer
	{name: "Const8", aux: "Int8"},        // auxint is sign-extended 8 bits
	{name: "Const16", aux: "Int16"},      // auxint is sign-extended 16 bits
	{name: "Const32", aux: "Int32"},      // auxint is sign-extended 32 bits
	// Note: ConstX are sign-extended even when the type of the value is unsigned.
	// For instance, uint8(0xaa) is stored as auxint=0xffffffffffffffaa.
	{name: "Const64", aux: "Int64"}, // value is auxint
	// Note: for both Const32F and Const64F, we disallow encoding NaNs.
	// Signaling NaNs are tricky because if you do anything with them, they become quiet.
	// Particularly, converting a 32 bit sNaN to 64 bit and back converts it to a qNaN.
	// See issue 36399 and 36400.
	// Encodings of +inf, -inf, and -0 are fine.
	{name: "Const32F", aux: "Float32"}, // value is math.Float64frombits(uint64(auxint)) and is exactly representable as float 32
	{name: "Const64F", aux: "Float64"}, // value is math.Float64frombits(uint64(auxint))
	{name: "ConstInterface"},           // nil interface
	{name: "ConstSlice"},               // nil slice

	// Constant-like things
	{name: "InitMem", zeroWidth: true},                               // memory input to the function.
	{name: "Arg", aux: "SymOff", symEffect: "Read", zeroWidth: true}, // argument to the function.  aux=GCNode of arg, off = offset in that arg.

	// Like Arg, these are generic ops that survive lowering. AuxInt is a register index, and the actual output register for each index is defined by the architecture.
	// AuxInt = integer argument index (not a register number). ABI-specified spill loc obtained from function
	{name: "ArgIntReg", aux: "NameOffsetInt8", zeroWidth: true},   // argument to the function in an int reg.
	{name: "ArgFloatReg", aux: "NameOffsetInt8", zeroWidth: true}, // argument to the function in a float reg.

	// The address of a variable.  arg0 is the base pointer.
	// If the variable is a global, the base pointer will be SB and
	// the Aux field will be a *obj.LSym.
	// If the variable is a local, the base pointer will be SP and
	// the Aux field will be a *gc.Node.
	{name: "Addr", argLength: 1, aux: "Sym", symEffect: "Addr"},      // Address of a variable.  Arg0=SB.  Aux identifies the variable.
	{name: "LocalAddr", argLength: 2, aux: "Sym", symEffect: "Addr"}, // Address of a variable.  Arg0=SP. Arg1=mem. Aux identifies the variable.

	{name: "SP", zeroWidth: true},                                       // stack pointer
	{name: "SB", typ: "Uintptr", zeroWidth: true},                       // static base pointer (a.k.a. globals pointer)
	{name: "Invalid"},                                                   // unused value
	{name: "SPanchored", typ: "Uintptr", argLength: 2, zeroWidth: true}, // arg0 = SP, arg1 = mem. Result is identical to arg0, but cannot be scheduled before memory state arg1.

	// Memory operations
	{name: "Load", argLength: 2},                          // Load from arg0.  arg1=memory
	{name: "Dereference", argLength: 2},                   // Load from arg0.  arg1=memory.  Helper op for arg/result passing, result is an otherwise not-SSA-able "value".
	{name: "Store", argLength: 3, typ: "Mem", aux: "Typ"}, // Store arg1 to arg0.  arg2=memory, aux=type.  Returns memory.
	// Normally we require that the source and destination of Move do not overlap.
	// There is an exception when we know all the loads will happen before all
	// the stores. In that case, overlap is ok. See
	// memmove inlining in generic.rules. When inlineablememmovesize (in ../rewrite.go)
	// returns true, we must do all loads before all stores, when lowering Move.
	// The type of Move is used for the write barrier pass to insert write barriers
	// and for alignment on some architectures.
	// For pointerless types, it is possible for the type to be inaccurate.
	// For type alignment and pointer information, use the type in Aux;
	// for type size, use the size in AuxInt.
	// The "inline runtime.memmove" rewrite rule generates Moves with inaccurate types,
	// such as type byte instead of the more accurate type [8]byte.
	{name: "Move", argLength: 3, typ: "Mem", aux: "TypSize"}, // arg0=destptr, arg1=srcptr, arg2=mem, auxint=size, aux=type.  Returns memory.
	{name: "Zero", argLength: 2, typ: "Mem", aux: "TypSize"}, // arg0=destptr, arg1=mem, auxint=size, aux=type. Returns memory.

	// Memory operations with write barriers.
	// Expand to runtime calls. Write barrier will be removed if write on stack.
	{name: "StoreWB", argLength: 3, typ: "Mem", aux: "Typ"},    // Store arg1 to arg0. arg2=memory, aux=type.  Returns memory.
	{name: "MoveWB", argLength: 3, typ: "Mem", aux: "TypSize"}, // arg0=destptr, arg1=srcptr, arg2=mem, auxint=size, aux=type.  Returns memory.
	{name: "ZeroWB", argLength: 2, typ: "Mem", aux: "TypSize"}, // arg0=destptr, arg1=mem, auxint=size, aux=type. Returns memory.
	{name: "WBend", argLength: 1, typ: "Mem"},                  // Write barrier code is done, interrupting is now allowed.

	// WB invokes runtime.gcWriteBarrier.  This is not a normal
	// call: it takes arguments in registers, doesn't clobber
	// general-purpose registers (the exact clobber set is
	// arch-dependent), and is not a safe-point.
	{name: "WB", argLength: 1, typ: "(BytePtr,Mem)", aux: "Int64"}, // arg0=mem, auxint=# of buffer entries needed. Returns buffer pointer and memory.

	{name: "HasCPUFeature", argLength: 0, typ: "bool", aux: "Sym", symEffect: "None"}, // aux=place that this feature flag can be loaded from

	// PanicBounds and PanicExtend generate a runtime panic.
	// Their arguments provide index values to use in panic messages.
	// Both PanicBounds and PanicExtend have an AuxInt value from the BoundsKind type (in ../op.go).
	// PanicBounds' index is int sized.
	// PanicExtend's index is int64 sized. (PanicExtend is only used on 32-bit archs.)
	{name: "PanicBounds", argLength: 3, aux: "Int64", typ: "Mem", call: true}, // arg0=idx, arg1=len, arg2=mem, returns memory.
	{name: "PanicExtend", argLength: 4, aux: "Int64", typ: "Mem", call: true}, // arg0=idxHi, arg1=idxLo, arg2=len, arg3=mem, returns memory.

	// Function calls. Arguments to the call have already been written to the stack.
	// Return values appear on the stack. The method receiver, if any, is treated
	// as a phantom first argument.
	// TODO(josharian): ClosureCall and InterCall should have Int32 aux
	// to match StaticCall's 32 bit arg size limit.
	// TODO(drchase,josharian): could the arg size limit be bundled into the rules for CallOff?

	// Before lowering, LECalls receive their fixed inputs (first), memory (last),
	// and a variable number of input values in the middle.
	// They produce a variable number of result values.
	// These values are not necessarily "SSA-able"; they can be too large,
	// but in that case inputs are loaded immediately before with OpDereference,
	// and outputs are stored immediately with OpStore.
	//
	// After call expansion, Calls have the same fixed-middle-memory arrangement of inputs,
	// with the difference that the "middle" is only the register-resident inputs,
	// and the non-register inputs are instead stored at ABI-defined offsets from SP
	// (and the stores thread through the memory that is ultimately an input to the call).
	// Outputs follow a similar pattern; register-resident outputs are the leading elements
	// of a Result-typed output, with memory last, and any memory-resident outputs have been
	// stored to ABI-defined locations.  Each non-memory input or output fits in a register.
	//
	// Subsequent architecture-specific lowering only changes the opcode.

	{name: "ClosureCall", argLength: -1, aux: "CallOff", call: true}, // arg0=code pointer, arg1=context ptr, arg2..argN-1 are register inputs, argN=memory.  auxint=arg size.  Returns Result of register results, plus memory.
	{name: "StaticCall", argLength: -1, aux: "CallOff", call: true},  // call function aux.(*obj.LSym), arg0..argN-1 are register inputs, argN=memory.  auxint=arg size.  Returns Result of register results, plus memory.
	{name: "InterCall", argLength: -1, aux: "CallOff", call: true},   // interface call.  arg0=code pointer, arg1..argN-1 are register inputs, argN=memory, auxint=arg size.  Returns Result of register results, plus memory.
	{name: "TailCall", argLength: -1, aux: "CallOff", call: true},    // tail call function aux.(*obj.LSym), arg0..argN-1 are register inputs, argN=memory.  auxint=arg size.  Returns Result of register results, plus memory.

	{name: "ClosureLECall", argLength: -1, aux: "CallOff", call: true}, // late-expanded closure call. arg0=code pointer, arg1=context ptr,  arg2..argN-1 are inputs, argN is mem. auxint = arg size. Result is tuple of result(s), plus mem.
	{name: "StaticLECall", argLength: -1, aux: "CallOff", call: true},  // late-expanded static call function aux.(*ssa.AuxCall.Fn). arg0..argN-1 are inputs, argN is mem. auxint = arg size. Result is tuple of result(s), plus mem.
	{name: "InterLECall", argLength: -1, aux: "CallOff", call: true},   // late-expanded interface call. arg0=code pointer, arg1..argN-1 are inputs, argN is mem. auxint = arg size. Result is tuple of result(s), plus mem.
	{name: "TailLECall", argLength: -1, aux: "CallOff", call: true},    // late-expanded static tail call function aux.(*ssa.AuxCall.Fn). arg0..argN-1 are inputs, argN is mem. auxint = arg size. Result is tuple of result(s), plus mem.

	// Conversions: signed extensions, zero (unsigned) extensions, truncations
	{name: "SignExt8to16", argLength: 1, typ: "Int16"},
	{name: "SignExt8to32", argLength: 1, typ: "Int32"},
	{name: "SignExt8to64", argLength: 1, typ: "Int64"},
	{name: "SignExt16to32", argLength: 1, typ: "Int32"},
	{name: "SignExt16to64", argLength: 1, typ: "Int64"},
	{name: "SignExt32to64", argLength: 1, typ: "Int64"},
	{name: "ZeroExt8to16", argLength: 1, typ: "UInt16"},
	{name: "ZeroExt8to32", argLength: 1, typ: "UInt32"},
	{name: "ZeroExt8to64", argLength: 1, typ: "UInt64"},
	{name: "ZeroExt16to32", argLength: 1, typ: "UInt32"},
	{name: "ZeroExt16to64", argLength: 1, typ: "UInt64"},
	{name: "ZeroExt32to64", argLength: 1, typ: "UInt64"},
	{name: "Trunc16to8", argLength: 1},
	{name: "Trunc32to8", argLength: 1},
	{name: "Trunc32to16", argLength: 1},
	{name: "Trunc64to8", argLength: 1},
	{name: "Trunc64to16", argLength: 1},
	{name: "Trunc64to32", argLength: 1},

	{name: "Cvt32to32F", argLength: 1},
	{name: "Cvt32to64F", argLength: 1},
	{name: "Cvt64to32F", argLength: 1},
	{name: "Cvt64to64F", argLength: 1},
	{name: "Cvt32Fto32", argLength: 1},
	{name: "Cvt32Fto64", argLength: 1},
	{name: "Cvt64Fto32", argLength: 1},
	{name: "Cvt64Fto64", argLength: 1},
	{name: "Cvt32Fto64F", argLength: 1},
	{name: "Cvt64Fto32F", argLength: 1},
	{name: "CvtBoolToUint8", argLength: 1},

	// Force rounding to precision of type.
	{name: "Round32F", argLength: 1},
	{name: "Round64F", argLength: 1},

	// Automatically inserted safety checks
	{name: "IsNonNil", argLength: 1, typ: "Bool"},        // arg0 != nil
	{name: "IsInBounds", argLength: 2, typ: "Bool"},      // 0 <= arg0 < arg1. arg1 is guaranteed >= 0.
	{name: "IsSliceInBounds", argLength: 2, typ: "Bool"}, // 0 <= arg0 <= arg1. arg1 is guaranteed >= 0.
	{name: "NilCheck", argLength: 2, nilCheck: true},     // arg0=ptr, arg1=mem. Panics if arg0 is nil. Returns the ptr unmodified.

	// Pseudo-ops
	{name: "GetG", argLength: 1, zeroWidth: true}, // runtime.getg() (read g pointer). arg0=mem
	{name: "GetClosurePtr"},                       // get closure pointer from dedicated register
	{name: "GetCallerPC"},                         // for GetCallerPC intrinsic
	{name: "GetCallerSP", argLength: 1},           // for GetCallerSP intrinsic. arg0=mem.

	// Indexing operations
	{name: "PtrIndex", argLength: 2},             // arg0=ptr, arg1=index. Computes ptr+sizeof(*v.type)*index, where index is extended to ptrwidth type
	{name: "OffPtr", argLength: 1, aux: "Int64"}, // arg0 + auxint (arg0 and result are pointers)

	// Slices
	{name: "SliceMake", argLength: 3},                // arg0=ptr, arg1=len, arg2=cap
	{name: "SlicePtr", argLength: 1, typ: "BytePtr"}, // ptr(arg0)
	{name: "SliceLen", argLength: 1},                 // len(arg0)
	{name: "SliceCap", argLength: 1},                 // cap(arg0)
	// SlicePtrUnchecked, like SlicePtr, extracts the pointer from a slice.
	// SlicePtr values are assumed non-nil, because they are guarded by bounds checks.
	// SlicePtrUnchecked values can be nil.
	{name: "SlicePtrUnchecked", argLength: 1},

	// Complex (part/whole)
	{name: "ComplexMake", argLength: 2}, // arg0=real, arg1=imag
	{name: "ComplexReal", argLength: 1}, // real(arg0)
	{name: "ComplexImag", argLength: 1}, // imag(arg0)

	// Strings
	{name: "StringMake", argLength: 2},                // arg0=ptr, arg1=len
	{name: "StringPtr", argLength: 1, typ: "BytePtr"}, // ptr(arg0)
	{name: "StringLen", argLength: 1, typ: "Int"},     // len(arg0)

	// Interfaces
	{name: "IMake", argLength: 2},                // arg0=itab, arg1=data
	{name: "ITab", argLength: 1, typ: "Uintptr"}, // arg0=interface, returns itable field
	{name: "IData", argLength: 1},                // arg0=interface, returns data field

	// Structs
	{name: "StructMake", argLength: -1},                // args...=field0..n-1. Returns struct with n fields.
	{name: "StructSelect", argLength: 1, aux: "Int64"}, // arg0=struct, auxint=field index.  Returns the auxint'th field.

	// Arrays
	{name: "ArrayMake0"},                              // Returns array with 0 elements
	{name: "ArrayMake1", argLength: 1},                // Returns array with 1 element
	{name: "ArraySelect", argLength: 1, aux: "Int64"}, // arg0=array, auxint=index. Returns a[i].

	// Spill&restore ops for the register allocator. These are
	// semantically identical to OpCopy; they do not take/return
	// stores like regular memory ops do. We can get away without memory
	// args because we know there is no aliasing of spill slots on the stack.
	{name: "StoreReg", argLength: 1},
	{name: "LoadReg", argLength: 1},

	// Used during ssa construction. Like Copy, but the arg has not been specified yet.
	{name: "FwdRef", aux: "Sym", symEffect: "None"},

	// Unknown value. Used for Values whose values don't matter because they are dead code.
	{name: "Unknown"},

	{name: "VarDef", argLength: 1, aux: "Sym", typ: "Mem", symEffect: "None", zeroWidth: true}, // aux is a *gc.Node of a variable that is about to be initialized.  arg0=mem, returns mem
	// TODO: what's the difference between VarLive and KeepAlive?
	{name: "VarLive", argLength: 1, aux: "Sym", symEffect: "Read", zeroWidth: true}, // aux is a *gc.Node of a variable that must be kept live.  arg0=mem, returns mem
	{name: "KeepAlive", argLength: 2, typ: "Mem", zeroWidth: true},                  // arg[0] is a value that must be kept alive until this mark.  arg[1]=mem, returns mem

	// InlMark marks the start of an inlined function body. Its AuxInt field
	// distinguishes which entry in the local inline tree it is marking.
	{name: "InlMark", argLength: 1, aux: "Int32", typ: "Void"}, // arg[0]=mem, returns void.

	// Ops for breaking 64-bit operations on 32-bit architectures
	{name: "Int64Make", argLength: 2, typ: "UInt64"}, // arg0=hi, arg1=lo
	{name: "Int64Hi", argLength: 1, typ: "UInt32"},   // high 32-bit of arg0
	{name: "Int64Lo", argLength: 1, typ: "UInt32"},   // low 32-bit of arg0

	{name: "Add32carry", argLength: 2, commutative: true, typ: "(UInt32,Flags)"}, // arg0 + arg1, returns (value, carry)
	{name: "Add32withcarry", argLength: 3, commutative: true},                    // arg0 + arg1 + arg2, arg2=carry (0 or 1)

	{name: "Sub32carry", argLength: 2, typ: "(UInt32,Flags)"}, // arg0 - arg1, returns (value, carry)
	{name: "Sub32withcarry", argLength: 3},                    // arg0 - arg1 - arg2, arg2=carry (0 or 1)

	{name: "Add64carry", argLength: 3, commutative: true, typ: "(UInt64,UInt64)"}, // arg0 + arg1 + arg2, arg2 must be 0 or 1. returns (value, value>>64)
	{name: "Sub64borrow", argLength: 3, typ: "(UInt64,UInt64)"},                   // arg0 - (arg1 + arg2), arg2 must be 0 or 1. returns (value, value>>64&1)

	{name: "Signmask", argLength: 1, typ: "Int32"},  // 0 if arg0 >= 0, -1 if arg0 < 0
	{name: "Zeromask", argLength: 1, typ: "UInt32"}, // 0 if arg0 == 0, 0xffffffff if arg0 != 0
	{name: "Slicemask", argLength: 1},               // 0 if arg0 == 0, -1 if arg0 > 0, undef if arg0<0. Type is native int size.

	{name: "SpectreIndex", argLength: 2},      // arg0 if 0 <= arg0 < arg1, 0 otherwise. Type is native int size.
	{name: "SpectreSliceIndex", argLength: 2}, // arg0 if 0 <= arg0 <= arg1, 0 otherwise. Type is native int size.

	{name: "Cvt32Uto32F", argLength: 1}, // uint32 -> float32, only used on 32-bit arch
	{name: "Cvt32Uto64F", argLength: 1}, // uint32 -> float64, only used on 32-bit arch
	{name: "Cvt32Fto32U", argLength: 1}, // float32 -> uint32, only used on 32-bit arch
	{name: "Cvt64Fto32U", argLength: 1}, // float64 -> uint32, only used on 32-bit arch
	{name: "Cvt64Uto32F", argLength: 1}, // uint64 -> float32, only used on archs that has the instruction
	{name: "Cvt64Uto64F", argLength: 1}, // uint64 -> float64, only used on archs that has the instruction
	{name: "Cvt32Fto64U", argLength: 1}, // float32 -> uint64, only used on archs that has the instruction
	{name: "Cvt64Fto64U", argLength: 1}, // float64 -> uint64, only used on archs that has the instruction

	// pseudo-ops for breaking Tuple
	{name: "Select0", argLength: 1, zeroWidth: true},  // the first component of a tuple
	{name: "Select1", argLength: 1, zeroWidth: true},  // the second component of a tuple
	{name: "SelectN", argLength: 1, aux: "Int64"},     // arg0=result, auxint=field index.  Returns the auxint'th member.
	{name: "SelectNAddr", argLength: 1, aux: "Int64"}, // arg0=result, auxint=field index.  Returns the address of auxint'th member. Used for un-SSA-able result types.
	{name: "MakeResult", argLength: -1},               // arg0 .. are components of a "Result" (like the result from a Call). The last arg should be memory (like the result from a call).

	// Atomic operations used for semantically inlining sync/atomic and
	// internal/runtime/atomic. Atomic loads return a new memory so that
	// the loads are properly ordered with respect to other loads and
	// stores.
	{name: "AtomicLoad8", argLength: 2, typ: "(UInt8,Mem)"},                                    // Load from arg0.  arg1=memory.  Returns loaded value and new memory.
	{name: "AtomicLoad32", argLength: 2, typ: "(UInt32,Mem)"},                                  // Load from arg0.  arg1=memory.  Returns loaded value and new memory.
	{name: "AtomicLoad64", argLength: 2, typ: "(UInt64,Mem)"},                                  // Load from arg0.  arg1=memory.  Returns loaded value and new memory.
	{name: "AtomicLoadPtr", argLength: 2, typ: "(BytePtr,Mem)"},                                // Load from arg0.  arg1=memory.  Returns loaded value and new memory.
	{name: "AtomicLoadAcq32", argLength: 2, typ: "(UInt32,Mem)"},                               // Load from arg0.  arg1=memory.  Lock acquisition, returns loaded value and new memory.
	{name: "AtomicLoadAcq64", argLength: 2, typ: "(UInt64,Mem)"},                               // Load from arg0.  arg1=memory.  Lock acquisition, returns loaded value and new memory.
	{name: "AtomicStore8", argLength: 3, typ: "Mem", hasSideEffects: true},                     // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStore32", argLength: 3, typ: "Mem", hasSideEffects: true},                    // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStore64", argLength: 3, typ: "Mem", hasSideEffects: true},                    // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStorePtrNoWB", argLength: 3, typ: "Mem", hasSideEffects: true},               // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStoreRel32", argLength: 3, typ: "Mem", hasSideEffects: true},                 // Store arg1 to *arg0.  arg2=memory.  Lock release, returns memory.
	{name: "AtomicStoreRel64", argLength: 3, typ: "Mem", hasSideEffects: true},                 // Store arg1 to *arg0.  arg2=memory.  Lock release, returns memory.
	{name: "AtomicExchange8", argLength: 3, typ: "(UInt8,Mem)", hasSideEffects: true},          // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicExchange32", argLength: 3, typ: "(UInt32,Mem)", hasSideEffects: true},        // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicExchange64", argLength: 3, typ: "(UInt64,Mem)", hasSideEffects: true},        // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicAdd32", argLength: 3, typ: "(UInt32,Mem)", hasSideEffects: true},             // Do *arg0 += arg1.  arg2=memory.  Returns sum and new memory.
	{name: "AtomicAdd64", argLength: 3, typ: "(UInt64,Mem)", hasSideEffects: true},             // Do *arg0 += arg1.  arg2=memory.  Returns sum and new memory.
	{name: "AtomicCompareAndSwap32", argLength: 4, typ: "(Bool,Mem)", hasSideEffects: true},    // if *arg0==arg1, then set *arg0=arg2.  Returns true if store happens and new memory.
	{name: "AtomicCompareAndSwap64", argLength: 4, typ: "(Bool,Mem)", hasSideEffects: true},    // if *arg0==arg1, then set *arg0=arg2.  Returns true if store happens and new memory.
	{name: "AtomicCompareAndSwapRel32", argLength: 4, typ: "(Bool,Mem)", hasSideEffects: true}, // if *arg0==arg1, then set *arg0=arg2.  Lock release, reports whether store happens and new memory.

	// Older atomic logical operations which don't return the old value.
	{name: "AtomicAnd8", argLength: 3, typ: "Mem", hasSideEffects: true},  // *arg0 &= arg1.  arg2=memory.  Returns memory.
	{name: "AtomicOr8", argLength: 3, typ: "Mem", hasSideEffects: true},   // *arg0 |= arg1.  arg2=memory.  Returns memory.
	{name: "AtomicAnd32", argLength: 3, typ: "Mem", hasSideEffects: true}, // *arg0 &= arg1.  arg2=memory.  Returns memory.
	{name: "AtomicOr32", argLength: 3, typ: "Mem", hasSideEffects: true},  // *arg0 |= arg1.  arg2=memory.  Returns memory.

	// Newer atomic logical operations which return the old value.
	{name: "AtomicAnd64value", argLength: 3, typ: "(Uint64, Mem)", hasSideEffects: true}, // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicAnd32value", argLength: 3, typ: "(Uint32, Mem)", hasSideEffects: true}, // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicAnd8value", argLength: 3, typ: "(Uint8, Mem)", hasSideEffects: true},   // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr64value", argLength: 3, typ: "(Uint64, Mem)", hasSideEffects: true},  // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr32value", argLength: 3, typ: "(Uint32, Mem)", hasSideEffects: true},  // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr8value", argLength: 3, typ: "(Uint8, Mem)", hasSideEffects: true},    // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.

	// Atomic operation variants
	// These variants have the same semantics as above atomic operations.
	// But they are used for generating more efficient code on certain modern machines, with run-time CPU feature detection.
	// On ARM64, these are used when the LSE hardware feature is available (either known at compile time or detected at runtime). If LSE is not available,
	// then the basic atomic operations are used instead.
	{name: "AtomicStore8Variant", argLength: 3, typ: "Mem", hasSideEffects: true},  // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStore32Variant", argLength: 3, typ: "Mem", hasSideEffects: true}, // Store arg1 to *arg0.  arg2=memory.  Returns memory.
	{name: "AtomicStore64Variant", argLength: 3, typ: "Mem", hasSideEffects: true}, // Store arg1 to *arg0.  arg2=memory.  Returns memory.

	{name: "AtomicAdd32Variant", argLength: 3, typ: "(UInt32,Mem)", hasSideEffects: true},          // Do *arg0 += arg1.  arg2=memory.  Returns sum and new memory.
	{name: "AtomicAdd64Variant", argLength: 3, typ: "(UInt64,Mem)", hasSideEffects: true},          // Do *arg0 += arg1.  arg2=memory.  Returns sum and new memory.
	{name: "AtomicExchange8Variant", argLength: 3, typ: "(UInt8,Mem)", hasSideEffects: true},       // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicExchange32Variant", argLength: 3, typ: "(UInt32,Mem)", hasSideEffects: true},     // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicExchange64Variant", argLength: 3, typ: "(UInt64,Mem)", hasSideEffects: true},     // Store arg1 to *arg0.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicCompareAndSwap32Variant", argLength: 4, typ: "(Bool,Mem)", hasSideEffects: true}, // if *arg0==arg1, then set *arg0=arg2.  Returns true if store happens and new memory.
	{name: "AtomicCompareAndSwap64Variant", argLength: 4, typ: "(Bool,Mem)", hasSideEffects: true}, // if *arg0==arg1, then set *arg0=arg2.  Returns true if store happens and new memory.
	{name: "AtomicAnd64valueVariant", argLength: 3, typ: "(Uint64, Mem)", hasSideEffects: true},    // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr64valueVariant", argLength: 3, typ: "(Uint64, Mem)", hasSideEffects: true},     // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicAnd32valueVariant", argLength: 3, typ: "(Uint32, Mem)", hasSideEffects: true},    // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr32valueVariant", argLength: 3, typ: "(Uint32, Mem)", hasSideEffects: true},     // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicAnd8valueVariant", argLength: 3, typ: "(Uint8, Mem)", hasSideEffects: true},      // *arg0 &= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.
	{name: "AtomicOr8valueVariant", argLength: 3, typ: "(Uint8, Mem)", hasSideEffects: true},       // *arg0 |= arg1.  arg2=memory.  Returns old contents of *arg0 and new memory.

	// Publication barrier
	{name: "PubBarrier", argLength: 1, hasSideEffects: true}, // Do data barrier. arg0=memory.

	// Clobber experiment op
	{name: "Clobber", argLength: 0, typ: "Void", aux: "SymOff", symEffect: "None"}, // write an invalid pointer value to the given pointer slot of a stack variable
	{name: "ClobberReg", argLength: 0, typ: "Void"},                                // clobber a register

	// Prefetch instruction
	{name: "PrefetchCache", argLength: 2, hasSideEffects: true},         // Do prefetch arg0 to cache. arg0=addr, arg1=memory.
	{name: "PrefetchCacheStreamed", argLength: 2, hasSideEffects: true}, // Do non-temporal or streamed prefetch arg0 to cache. arg0=addr, arg1=memory.
}

//     kind          controls        successors   implicit exit
//   ----------------------------------------------------------
//     Exit      [return mem]                []             yes
//      Ret      [return mem]                []             yes
//   RetJmp      [return mem]                []             yes
//    Plain                []            [next]
//       If   [boolean Value]      [then, else]
//    First                []   [always, never]
//    Defer             [mem]  [nopanic, panic]                  (control opcode should be OpStaticCall to runtime.deferproc)
// JumpTable   [integer Value]  [succ1,succ2,..]

var genericBlocks = []blockData{
	{name: "Plain"},                  // a single successor
	{name: "If", controls: 1},        // if Controls[0] goto Succs[0] else goto Succs[1]
	{name: "Defer", controls: 1},     // Succs[0]=defer queued, Succs[1]=defer recovered. Controls[0] is call op (of memory type)
	{name: "Ret", controls: 1},       // no successors, Controls[0] value is memory result
	{name: "RetJmp", controls: 1},    // no successors, Controls[0] value is a tail call
	{name: "Exit", controls: 1},      // no successors, Controls[0] value generates a panic
	{name: "JumpTable", controls: 1}, // multiple successors, the integer Controls[0] selects which one

	// transient block state used for dead code removal
	{name: "First"}, // 2 successors, always takes the first one (second is dead)
}

func init() {
	archs = append(archs, arch{
		name:    "generic",
		ops:     genericOps,
		blocks:  genericBlocks,
		generic: true,
	})
}

"""



```