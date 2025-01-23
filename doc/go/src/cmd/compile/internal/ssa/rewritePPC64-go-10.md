Response:
Let's break down the thought process to arrive at the summary of the provided Go code snippet.

1. **Understanding the Context:** The prompt states the code is part of `go/src/cmd/compile/internal/ssa/rewritePPC64.go` and is the 11th of 12 parts. This immediately tells us it's related to the Go compiler, specifically the SSA (Static Single Assignment) intermediate representation, and is responsible for rewriting or optimizing code for the PPC64 architecture. The fact that it's part 11 suggests it's likely handling a specific set of optimizations or transformations.

2. **Initial Scan for Keywords and Patterns:**  A quick scan reveals recurring patterns:
    * `rewriteValuePPC64_Op...`: This strongly suggests functions that handle rewriting specific Go operations (`Op`).
    * `v.reset(...)`: This indicates the replacement of an existing operation with a new one.
    * `v.AddArg(...)`: This signifies adding arguments to an operation.
    * `OpPPC64...`: This confirms the target architecture (PPC64) and lists specific PPC64 assembly instructions.
    * `b.NewValue0(...)`: This creates new SSA values.
    * `b.resetWithControl(...)`: This manipulates control flow blocks based on conditions.
    * `match: (...)`: These are code patterns that trigger specific rewrites.
    * `cond: (...)`: These are conditions that must be met for a rewrite to occur.
    * Block types like `BlockPPC64EQ`, `BlockPPC64GE`, `BlockIf`, etc. indicate handling of control flow based on comparisons.

3. **Analyzing `rewriteValuePPC64_Op...` functions:**  Focusing on these functions reveals the core logic. Each function seems to target a specific Go operation (e.g., `OpLsh8x64`, `OpSelect0`, `OpSelect1`, `OpSelectN`, `OpSlicemask`, `OpStore`, `OpTrunc...`, `OpZero`). The code within each function tries to find specific patterns of existing operations and replace them with more efficient or architecture-specific PPC64 instructions.

    * **Example Breakdown (`rewriteValuePPC64_OpLsh8x64`):**
        * It handles left shifts (`OpLsh8x64`).
        * It has two `match` cases.
        * The first case simplifies the shift if the shift amount is already masked (e.g., `ANDconst [63] y`).
        * The second case seems more complex, involving `ISEL`, `SRAD`, `MOVBreg`, `SRADconst`, `CMPconst`, and `ANDconst`. This likely implements a specific optimized way to handle 8-bit shifts on PPC64, possibly dealing with sign extension or edge cases.

    * **Example Breakdown (`rewriteValuePPC64_OpSelect0` and `rewriteValuePPC64_OpSelect1`):**
        * These handle selecting the 0th and 1st result of multi-value operations.
        * They optimize selections from operations like `Mul64uhilo`, `Mul64uover`, `Add64carry`, and `Sub64borrow` by directly using appropriate PPC64 instructions (`MULHDU`, `MULLD`, `ADDE`, `SUBE`).

    * **Example Breakdown (`rewriteValuePPC64_OpSelectN`):**
        * This deals with selecting the Nth result of a multi-value operation.
        * The examples focus on `CALLstatic` to `runtime.memmove` and rewrite it into a more direct `OpMove` if certain conditions (like inlinability and argument usage) are met. This is a common optimization for memory copy operations.

    * **Example Breakdown (`rewriteValuePPC64_OpZero`):**
        * This handles zeroing out memory.
        * It has multiple `match` cases for different sizes, using specific store-zero instructions (`MOVBstorezero`, `MOVHstorezero`, `MOVWstorezero`, `MOVDstorezero`).
        * It also includes cases for `LoweredZeroShort`, `LoweredZero`, `LoweredQuadZeroShort`, and `LoweredQuadZero`, which seem to be platform-specific implementations for larger zeroing operations, potentially taking into account the `buildcfg.GOPPC64` version.

4. **Analyzing `rewriteBlockPPC64`:** This function deals with rewriting control flow blocks. It examines the type of block (e.g., `BlockPPC64EQ`, `BlockPPC64GE`, `BlockIf`) and the controlling value, then potentially changes the block type or swaps successors to optimize the control flow based on PPC64 specific flags and comparisons. It also attempts to simplify conditions involving `AND`, `OR`, and `XOR` operations when they are used in comparisons.

5. **Inferring Go Functionality:** Based on the operations being rewritten, we can infer some of the Go language features being optimized:
    * **Arithmetic Operations:**  Integer and floating-point arithmetic (`Add64`, `Sub64`, `Mul64`, `Lsh`, `Rsh`).
    * **Multi-Value Returns:** Functions returning multiple values, as seen with `Select0`, `Select1`, and `SelectN`.
    * **Memory Operations:**  Storing and zeroing memory (`Store`, `Zero`, and the optimization of `memmove`).
    * **Type Conversions/Truncations:** Converting between different integer sizes (`Trunc16to8`, `Trunc32to16`, etc.).
    * **Control Flow:**  `if` statements and comparisons.

6. **Synthesizing the Summary:**  Combine the observations from the analysis to formulate a concise summary. Highlight the main purpose (SSA rewriting for PPC64), the types of operations handled (arithmetic, memory, control flow, etc.), and the techniques used (pattern matching, architecture-specific instructions, inlining). Emphasize that this part focuses on lowering high-level Go operations to low-level PPC64 instructions.

7. **Review and Refine:** Read the summary to ensure it's accurate, clear, and captures the key aspects of the code. Ensure the language is precise and avoids jargon where possible.

This structured approach, starting from understanding the context and progressively drilling down into the details of the code, allows for a comprehensive understanding and the creation of an informative summary. The key is to identify the patterns and the purpose behind the code transformations.
这段代码是 Go 语言编译器中针对 PPC64 架构的 SSA（Static Single Assignment）重写规则的一部分。它主要负责将 Go 语言的通用操作转换为更specific、更高效的 PPC64 汇编指令序列。这是编译器后端优化的一个关键步骤。

**功能归纳:**

这段代码定义了一系列针对 PPC64 架构的 SSA 值 (Value) 和块 (Block) 的重写规则。其核心功能是将 Go 语言的抽象操作（如位移、选择、存储、截断、清零以及条件分支等）映射到 PPC64 架构上更底层的指令。通过模式匹配和条件判断，它识别出可以被优化的 Go 语言操作，并将其替换为更高效的 PPC64 指令组合。

**具体功能列举:**

以下是代码片段中各个函数的主要功能：

* **`rewriteValuePPC64_OpLsh8x64(v *Value) bool`**:  处理 8 字节左移操作。它尝试匹配一些特定的左移模式，并将其转换为更高效的 PPC64 指令，例如使用 `ANDconst` 限制移位量，或使用 `ISEL` 指令进行选择。
* **`rewriteValuePPC64_OpSelect0(v *Value) bool`**: 处理从多返回值函数中选择第一个返回值的情况。它将某些特定的操作（如 `Mul64uhilo`, `Mul64uover`, `Add64carry`, `Sub64borrow`) 直接转换为对应的 PPC64 指令（如 `MULHDU`, `MULLD`, `ADDE`, `SUBE`）。
* **`rewriteValuePPC64_OpSelect1(v *Value) bool`**: 处理从多返回值函数中选择第二个返回值的情况。类似于 `OpSelect0`，它针对特定的操作进行优化，例如将 `Mul64uhilo` 转换为 `MULLD`，将 `Mul64uover` 转换为带条件设置的 `SETBCR` 指令，以及对带进位/借位的加减法进行优化。
* **`rewriteValuePPC64_OpSelectN(v *Value) bool`**: 处理从多返回值函数中选择任意索引的返回值。 这里主要针对 `runtime.memmove` 这个函数调用进行了优化，如果满足特定条件（例如大小已知，可以内联等），则将其转换为更底层的 `Move` 操作。
* **`rewriteValuePPC64_OpSlicemask(v *Value) bool`**: 处理计算切片掩码的操作，将其转换为 PPC64 的右移指令。
* **`rewriteValuePPC64_OpStore(v *Value) bool`**: 处理存储操作。它根据存储数据类型的大小和是否为浮点数，选择合适的 PPC64 存储指令 (例如 `FMOVDstore`, `FMOVSstore`, `MOVDstore`, `MOVWstore`, `MOVHstore`, `MOVBstore`)。
* **`rewriteValuePPC64_OpTrunc16to8(v *Value) bool`**, **`rewriteValuePPC64_OpTrunc32to16(v *Value) bool`**, ..., **`rewriteValuePPC64_OpTrunc64to8(v *Value) bool`**: 处理类型截断操作。根据目标类型是否有符号，选择合适的 PPC64 寄存器移动指令（例如 `MOVBreg`, `MOVBZreg`, `MOVHreg`, `MOVHZreg`, `MOVWreg`, `MOVWZreg`）。
* **`rewriteValuePPC64_OpZero(v *Value) bool`**: 处理将内存置零的操作。它针对不同大小的零操作，生成不同的 PPC64 置零指令序列 (例如 `MOVBstorezero`, `MOVHstorezero`, `MOVWstorezero`, `MOVDstorezero`)，并考虑了不同 Go 版本 (通过 `buildcfg.GOPPC64` 判断) 下的优化策略 (例如 `LoweredZeroShort`, `LoweredZero`, `LoweredQuadZeroShort`, `LoweredQuadZero`)。
* **`rewriteBlockPPC64(b *Block) bool`**:  处理控制流块的重写。它针对不同的 PPC64 条件分支块（如 `BlockPPC64EQ`, `BlockPPC64GE`, `BlockIf` 等），根据控制条件的值，进行优化，例如消除冗余的标志位检查，或者将高级的 `If` 语句转换为底层的比较和分支指令。

**Go 语言功能实现推断及代码示例:**

* **位移操作 (`OpLsh8x64`):** 这实现了 Go 语言中的左移运算符 `<<`。

```go
package main

import "fmt"

func main() {
	x := uint64(10)
	y := uint64(3)
	result := x << y
	fmt.Println(result) // Output: 80
}
```

* **多返回值选择 (`OpSelect0`, `OpSelect1`):** 这实现了 Go 语言中访问多返回值函数返回值的语法。

```go
package main

import "fmt"

func divide(a, b int) (int, int) {
	return a / b, a % b
}

func main() {
	quotient, remainder := divide(10, 3)
	fmt.Println("Quotient:", quotient)   // Output: Quotient: 3
	fmt.Println("Remainder:", remainder) // Output: Remainder: 1
}
```
  `OpSelect0` 对应获取 `quotient`，`OpSelect1` 对应获取 `remainder`。

* **内存拷贝 (`OpSelectN` 优化 `runtime.memmove`):** 这优化了 Go 语言中的内存拷贝操作，例如使用 `copy()` 函数。

```go
package main

import "fmt"

func main() {
	src := []int{1, 2, 3, 4, 5}
	dst := make([]int, len(src))
	n := copy(dst, src)
	fmt.Println("Copied:", n, "elements") // Output: Copied: 5 elements
	fmt.Println("Destination:", dst)       // Output: Destination: [1 2 3 4 5]
}
```

* **类型截断 (`OpTrunc...`):** 这实现了 Go 语言中的类型转换，将大类型转换为小类型。

```go
package main

import "fmt"

func main() {
	var big int32 = 1000
	small := int8(big)
	fmt.Println(small) // Output: -24 (因为发生了溢出和截断)
}
```

* **内存清零 (`OpZero`):** 这通常用于初始化变量或者清空数据结构。

```go
package main

import "fmt"

func main() {
	arr := make([]int, 5)
	fmt.Println("Initial array:", arr) // Output: Initial array: [0 0 0 0 0]
}
```
  当 `make([]int, 5)` 分配内存时，这块内存会被清零。

* **条件分支 (`rewriteBlockPPC64`):** 这对应 Go 语言中的 `if`, `else if`, `else` 等控制流语句。

```go
package main

import "fmt"

func main() {
	x := 10
	if x > 5 {
		fmt.Println("x is greater than 5")
	} else {
		fmt.Println("x is not greater than 5")
	}
}
```

**代码推理示例 (假设):**

**假设输入 (针对 `rewriteValuePPC64_OpLsh8x64`):**

一个 SSA 值 `v` 代表操作 `x << y`，其中 `y` 是一个常量 `6` (二进制 `00000110`)。

**匹配的模式:**

```
// match: (Lsh8x64 x (ANDconst <y.Type> [63] y))
// result: (SHLD x y)
```

虽然 `y` 本身是常量 6，但如果之前的某个步骤已经将 `y` 与 `63` 进行了 `ANDconst` 操作，那么就会匹配这个模式。

**假设 `y` 的 SSA 表示是 `(ANDconst [63] (MOVDconst [6]))`**

**输出:**

`v` 将被重写为 `(SHLD x y')`, 其中 `y'` 指向 `y` 的 SSA 值。

**实际的 `rewriteValuePPC64_OpLsh8x64` 中的第二个 `match` 示例：**

**假设输入:**

一个 SSA 值 `v` 代表 `Rsh8x8 <t> x y` (带符号的 8 字节右移)。

**输出:**

`v` 会被重写为使用 `ISEL` 指令的有条件选择结构，基于移位量 `y` 的高位进行不同的右移操作。这是一种针对小移位量优化的策略。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是在 Go 编译器的内部流程中被调用的。Go 编译器的命令行参数（例如 `-gcflags`, `-ldflags` 等）会影响编译过程的各个阶段，包括 SSA 的生成和优化，但 `rewritePPC64.go` 中的代码是在这些参数处理之后执行的，它专注于将 SSA 中间表示转换为目标架构的指令。

**使用者易犯错的点:**

由于这段代码是编译器内部实现，普通 Go 开发者不会直接接触到它。因此，不存在使用者易犯错的点。开发者只需编写符合 Go 语法规范的代码，编译器会自动进行优化。

**第 11 部分的功能归纳:**

作为 12 个部分中的第 11 部分，这段代码主要集中在 **将 Go 语言的各种操作降低到 PPC64 架构的指令级别**。它涵盖了算术运算、逻辑运算、内存操作、类型转换和控制流等多个方面。可以推断，之前的部分可能负责了更通用的 SSA 重写规则或者架构无关的优化，而这一部分则专门针对 PPC64 的特性进行优化，生成高效的目标代码。接下来的第 12 部分很可能处理最后阶段的指令选择、寄存器分配或者生成最终的汇编代码。

总而言之，`rewritePPC64.go` 的这一部分是 Go 编译器将 Go 代码高效地编译到 PPC64 架构的关键组成部分，通过模式匹配和指令替换，实现了针对该架构的性能优化。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewritePPC64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第11部分，共12部分，请归纳一下它的功能
```

### 源代码
```go
v.AddArg2(v0, y)
		return true
	}
	// match: (Rsh8x8 <t> x y)
	// result: (ISEL [2] (SRAD <t> (MOVBreg x) y) (SRADconst <t> (MOVBreg x) [7]) (CMPconst [0] (ANDconst [0x00F8] y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpPPC64ISEL)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64SRAD, t)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVBreg, typ.Int64)
		v1.AddArg(x)
		v0.AddArg2(v1, y)
		v2 := b.NewValue0(v.Pos, OpPPC64SRADconst, t)
		v2.AuxInt = int64ToAuxInt(7)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v3.AuxInt = int64ToAuxInt(0)
		v4 := b.NewValue0(v.Pos, OpPPC64ANDconst, typ.Int)
		v4.AuxInt = int64ToAuxInt(0x00F8)
		v4.AddArg(y)
		v3.AddArg(v4)
		v.AddArg3(v0, v2, v3)
		return true
	}
}
func rewriteValuePPC64_OpSelect0(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select0 (Mul64uhilo x y))
	// result: (MULHDU x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULHDU)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Mul64uover x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select0 (Add64carry x y c))
	// result: (Select0 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1]))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(-1)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select0 (Sub64borrow x y c))
	// result: (Select0 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpSelect0)
		v.Type = typ.UInt64
		v0 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v2.AuxInt = int64ToAuxInt(0)
		v2.AddArg(c)
		v1.AddArg(v2)
		v0.AddArg3(x, y, v1)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelect1(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Select1 (Mul64uhilo x y))
	// result: (MULLD x y)
	for {
		if v_0.Op != OpMul64uhilo {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64MULLD)
		v.AddArg2(x, y)
		return true
	}
	// match: (Select1 (Mul64uover x y))
	// result: (SETBCR [2] (CMPconst [0] (MULHDU <x.Type> x y)))
	for {
		if v_0.Op != OpMul64uover {
			break
		}
		y := v_0.Args[1]
		x := v_0.Args[0]
		v.reset(OpPPC64SETBCR)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpPPC64MULHDU, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (Add64carry x y c))
	// result: (ADDZEzero (Select1 <typ.UInt64> (ADDE x y (Select1 <typ.UInt64> (ADDCconst c [-1])))))
	for {
		if v_0.Op != OpAdd64carry {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64ADDZEzero)
		v0 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpPPC64ADDE, types.NewTuple(typ.UInt64, typ.UInt64))
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v3 := b.NewValue0(v.Pos, OpPPC64ADDCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v3.AuxInt = int64ToAuxInt(-1)
		v3.AddArg(c)
		v2.AddArg(v3)
		v1.AddArg3(x, y, v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (ADDCconst n:(ADDZEzero x) [-1]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64ADDCconst || auxIntToInt64(v_0.AuxInt) != -1 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64ADDZEzero {
			break
		}
		x := n.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (Select1 (Sub64borrow x y c))
	// result: (NEG (SUBZEzero (Select1 <typ.UInt64> (SUBE x y (Select1 <typ.UInt64> (SUBCconst c [0]))))))
	for {
		if v_0.Op != OpSub64borrow {
			break
		}
		c := v_0.Args[2]
		x := v_0.Args[0]
		y := v_0.Args[1]
		v.reset(OpPPC64NEG)
		v0 := b.NewValue0(v.Pos, OpPPC64SUBZEzero, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2 := b.NewValue0(v.Pos, OpPPC64SUBE, types.NewTuple(typ.UInt64, typ.UInt64))
		v3 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v4 := b.NewValue0(v.Pos, OpPPC64SUBCconst, types.NewTuple(typ.UInt64, typ.UInt64))
		v4.AuxInt = int64ToAuxInt(0)
		v4.AddArg(c)
		v3.AddArg(v4)
		v2.AddArg3(x, y, v3)
		v1.AddArg(v2)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (Select1 (SUBCconst n:(NEG (SUBZEzero x)) [0]))
	// cond: n.Uses <= 2
	// result: x
	for {
		if v_0.Op != OpPPC64SUBCconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		n := v_0.Args[0]
		if n.Op != OpPPC64NEG {
			break
		}
		n_0 := n.Args[0]
		if n_0.Op != OpPPC64SUBZEzero {
			break
		}
		x := n_0.Args[0]
		if !(n.Uses <= 2) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSelectN(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (SelectN [0] call:(CALLstatic {sym} s1:(MOVDstore _ (MOVDconst [sz]) s2:(MOVDstore _ src s3:(MOVDstore {t} _ dst mem)))))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 1 {
			break
		}
		sym := auxToCall(call.Aux)
		s1 := call.Args[0]
		if s1.Op != OpPPC64MOVDstore {
			break
		}
		_ = s1.Args[2]
		s1_1 := s1.Args[1]
		if s1_1.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(s1_1.AuxInt)
		s2 := s1.Args[2]
		if s2.Op != OpPPC64MOVDstore {
			break
		}
		_ = s2.Args[2]
		src := s2.Args[1]
		s3 := s2.Args[2]
		if s3.Op != OpPPC64MOVDstore {
			break
		}
		mem := s3.Args[2]
		dst := s3.Args[1]
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && s1.Uses == 1 && s2.Uses == 1 && s3.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(s1, s2, s3, call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (SelectN [0] call:(CALLstatic {sym} dst src (MOVDconst [sz]) mem))
	// cond: sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)
	// result: (Move [sz] dst src mem)
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		call := v_0
		if call.Op != OpPPC64CALLstatic || len(call.Args) != 4 {
			break
		}
		sym := auxToCall(call.Aux)
		mem := call.Args[3]
		dst := call.Args[0]
		src := call.Args[1]
		call_2 := call.Args[2]
		if call_2.Op != OpPPC64MOVDconst {
			break
		}
		sz := auxIntToInt64(call_2.AuxInt)
		if !(sz >= 0 && isSameCall(sym, "runtime.memmove") && call.Uses == 1 && isInlinableMemmove(dst, src, sz, config) && clobber(call)) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(sz)
		v.AddArg3(dst, src, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpSlicemask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Slicemask <t> x)
	// result: (SRADconst (NEG <t> x) [63])
	for {
		t := v.Type
		x := v_0
		v.reset(OpPPC64SRADconst)
		v.AuxInt = int64ToAuxInt(63)
		v0 := b.NewValue0(v.Pos, OpPPC64NEG, t)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
}
func rewriteValuePPC64_OpStore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && t.IsFloat()
	// result: (FMOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && t.IsFloat()) {
			break
		}
		v.reset(OpPPC64FMOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && t.IsFloat()
	// result: (FMOVSstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && t.IsFloat()) {
			break
		}
		v.reset(OpPPC64FMOVSstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 8 && !t.IsFloat()
	// result: (MOVDstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 8 && !t.IsFloat()) {
			break
		}
		v.reset(OpPPC64MOVDstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 4 && !t.IsFloat()
	// result: (MOVWstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 4 && !t.IsFloat()) {
			break
		}
		v.reset(OpPPC64MOVWstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 2
	// result: (MOVHstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 2) {
			break
		}
		v.reset(OpPPC64MOVHstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (Store {t} ptr val mem)
	// cond: t.Size() == 1
	// result: (MOVBstore ptr val mem)
	for {
		t := auxToType(v.Aux)
		ptr := v_0
		val := v_1
		mem := v_2
		if !(t.Size() == 1) {
			break
		}
		v.reset(OpPPC64MOVBstore)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValuePPC64_OpTrunc16to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc16to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc16to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc32to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to16 <t> x)
	// cond: t.IsSigned()
	// result: (MOVHreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to16 x)
	// result: (MOVHZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc32to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc32to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc32to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to16(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to16 <t> x)
	// cond: t.IsSigned()
	// result: (MOVHreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to16 x)
	// result: (MOVHZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVHZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to32(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to32 <t> x)
	// cond: t.IsSigned()
	// result: (MOVWreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to32 x)
	// result: (MOVWZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVWZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpTrunc64to8(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Trunc64to8 <t> x)
	// cond: t.IsSigned()
	// result: (MOVBreg x)
	for {
		t := v.Type
		x := v_0
		if !(t.IsSigned()) {
			break
		}
		v.reset(OpPPC64MOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (Trunc64to8 x)
	// result: (MOVBZreg x)
	for {
		x := v_0
		v.reset(OpPPC64MOVBZreg)
		v.AddArg(x)
		return true
	}
}
func rewriteValuePPC64_OpZero(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Zero [0] _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_1
		v.copyOf(mem)
		return true
	}
	// match: (Zero [1] destptr mem)
	// result: (MOVBstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [2] destptr mem)
	// result: (MOVHstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVHstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [3] destptr mem)
	// result: (MOVBstorezero [2] destptr (MOVHstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [4] destptr mem)
	// result: (MOVWstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVWstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [5] destptr mem)
	// result: (MOVBstorezero [4] destptr (MOVWstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [6] destptr mem)
	// result: (MOVHstorezero [4] destptr (MOVWstorezero destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVHstorezero)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [7] destptr mem)
	// result: (MOVBstorezero [6] destptr (MOVHstorezero [4] destptr (MOVWstorezero destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVBstorezero)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVHstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(4)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVWstorezero, types.TypeMem)
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [8] {t} destptr mem)
	// result: (MOVDstorezero destptr mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AddArg2(destptr, mem)
		return true
	}
	// match: (Zero [12] {t} destptr mem)
	// result: (MOVWstorezero [8] destptr (MOVDstorezero [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVWstorezero)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [16] {t} destptr mem)
	// result: (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(0)
		v0.AddArg2(destptr, mem)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [24] {t} destptr mem)
	// result: (MOVDstorezero [16] destptr (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(8)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg2(destptr, mem)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [32] {t} destptr mem)
	// result: (MOVDstorezero [24] destptr (MOVDstorezero [16] destptr (MOVDstorezero [8] destptr (MOVDstorezero [0] destptr mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		destptr := v_0
		mem := v_1
		v.reset(OpPPC64MOVDstorezero)
		v.AuxInt = int32ToAuxInt(24)
		v0 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v0.AuxInt = int32ToAuxInt(16)
		v1 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpPPC64MOVDstorezero, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg2(destptr, mem)
		v1.AddArg2(destptr, v2)
		v0.AddArg2(destptr, v1)
		v.AddArg2(destptr, v0)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 <= 8 && s < 64
	// result: (LoweredZeroShort [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 <= 8 && s < 64) {
			break
		}
		v.reset(OpPPC64LoweredZeroShort)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 <= 8
	// result: (LoweredZero [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 <= 8) {
			break
		}
		v.reset(OpPPC64LoweredZero)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: s < 128 && buildcfg.GOPPC64 >= 9
	// result: (LoweredQuadZeroShort [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(s < 128 && buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64LoweredQuadZeroShort)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (Zero [s] ptr mem)
	// cond: buildcfg.GOPPC64 >= 9
	// result: (LoweredQuadZero [s] ptr mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		ptr := v_0
		mem := v_1
		if !(buildcfg.GOPPC64 >= 9) {
			break
		}
		v.reset(OpPPC64LoweredQuadZero)
		v.AuxInt = int64ToAuxInt(s)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteBlockPPC64(b *Block) bool {
	typ := &b.Func.Config.Types
	switch b.Kind {
	case BlockPPC64EQ:
		// match: (EQ (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (FlagGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (EQ (InvertFlags cmp) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64EQ, cmp)
			return true
		}
		// match: (EQ (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
		// match: (EQ (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (EQ (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64EQ, v0)
				return true
			}
			break
		}
	case BlockPPC64GE:
		// match: (GE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GE (FlagGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GE (InvertFlags cmp) yes no)
		// result: (LE cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64LE, cmp)
			return true
		}
		// match: (GE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
		// match: (GE (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GE (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GE, v0)
				return true
			}
			break
		}
	case BlockPPC64GT:
		// match: (GT (FlagEQ) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagLT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (GT (FlagGT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (GT (InvertFlags cmp) yes no)
		// result: (LT cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64LT, cmp)
			return true
		}
		// match: (GT (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
		// match: (GT (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (GT (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64XOR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64XORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64GT, v0)
				return true
			}
			break
		}
	case BlockIf:
		// match: (If (Equal cc) yes no)
		// result: (EQ cc yes no)
		for b.Controls[0].Op == OpPPC64Equal {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64EQ, cc)
			return true
		}
		// match: (If (NotEqual cc) yes no)
		// result: (NE cc yes no)
		for b.Controls[0].Op == OpPPC64NotEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64NE, cc)
			return true
		}
		// match: (If (LessThan cc) yes no)
		// result: (LT cc yes no)
		for b.Controls[0].Op == OpPPC64LessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64LT, cc)
			return true
		}
		// match: (If (LessEqual cc) yes no)
		// result: (LE cc yes no)
		for b.Controls[0].Op == OpPPC64LessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64LE, cc)
			return true
		}
		// match: (If (GreaterThan cc) yes no)
		// result: (GT cc yes no)
		for b.Controls[0].Op == OpPPC64GreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64GT, cc)
			return true
		}
		// match: (If (GreaterEqual cc) yes no)
		// result: (GE cc yes no)
		for b.Controls[0].Op == OpPPC64GreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64GE, cc)
			return true
		}
		// match: (If (FLessThan cc) yes no)
		// result: (FLT cc yes no)
		for b.Controls[0].Op == OpPPC64FLessThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FLT, cc)
			return true
		}
		// match: (If (FLessEqual cc) yes no)
		// result: (FLE cc yes no)
		for b.Controls[0].Op == OpPPC64FLessEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FLE, cc)
			return true
		}
		// match: (If (FGreaterThan cc) yes no)
		// result: (FGT cc yes no)
		for b.Controls[0].Op == OpPPC64FGreaterThan {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FGT, cc)
			return true
		}
		// match: (If (FGreaterEqual cc) yes no)
		// result: (FGE cc yes no)
		for b.Controls[0].Op == OpPPC64FGreaterEqual {
			v_0 := b.Controls[0]
			cc := v_0.Args[0]
			b.resetWithControl(BlockPPC64FGE, cc)
			return true
		}
		// match: (If cond yes no)
		// result: (NE (CMPconst [0] (ANDconst [1] cond)) yes no)
		for {
			cond := b.Controls[0]
			v0 := b.NewValue0(cond.Pos, OpPPC64CMPconst, types.TypeFlags)
			v0.AuxInt = int64ToAuxInt(0)
			v1 := b.NewValue0(cond.Pos, OpPPC64ANDconst, typ.Int)
			v1.AuxInt = int64ToAuxInt(1)
			v1.AddArg(cond)
			v0.AddArg(v1)
			b.resetWithControl(BlockPPC64NE, v0)
			return true
		}
	case BlockPPC64LE:
		// match: (LE (FlagEQ) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagEQ {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagLT) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpPPC64FlagLT {
			b.Reset(BlockFirst)
			return true
		}
		// match: (LE (FlagGT) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpPPC64FlagGT {
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (LE (InvertFlags cmp) yes no)
		// result: (GE cmp yes no)
		for b.Controls[0].Op == OpPPC64InvertFlags {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockPPC64GE, cmp)
			return true
		}
		// match: (LE (CMPconst [0] z:(AND x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (ANDCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64AND {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ANDCC, types.NewTuple(typ.Int64, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] z:(OR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (ORCC x y)) yes no)
		for b.Controls[0].Op == OpPPC64CMPconst {
			v_0 := b.Controls[0]
			if auxIntToInt64(v_0.AuxInt) != 0 {
				break
			}
			z := v_0.Args[0]
			if z.Op != OpPPC64OR {
				break
			}
			_ = z.Args[1]
			z_0 := z.Args[0]
			z_1 := z.Args[1]
			for _i0 := 0; _i0 <= 1; _i0, z_0, z_1 = _i0+1, z_1, z_0 {
				x := z_0
				y := z_1
				if !(z.Uses == 1) {
					continue
				}
				v0 := b.NewValue0(v_0.Pos, OpSelect1, types.TypeFlags)
				v1 := b.NewValue0(v_0.Pos, OpPPC64ORCC, types.NewTuple(typ.Int, types.TypeFlags))
				v1.AddArg2(x, y)
				v0.AddArg(v1)
				b.resetWithControl(BlockPPC64LE, v0)
				return true
			}
			break
		}
		// match: (LE (CMPconst [0] z:(XOR x y)) yes no)
		// cond: z.Uses == 1
		// result: (LE (Select1 <types.TypeFlags> (XORCC x y)) yes no)
		for b.Controls[0].Op
```