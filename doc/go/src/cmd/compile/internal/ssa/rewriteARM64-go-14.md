Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the Go code's functionality, potentially inferring its purpose within the larger Go project, providing examples, and highlighting potential pitfalls. It also specifies this is part 15 of 20, suggesting a continuation of previous functionality.

2. **Scan the Code for Key Operations:** I'll read through the provided Go code, paying close attention to the `rewriteValueARM64_Op...` function names. These names clearly indicate the code's purpose: to rewrite Go operations (`Op...`) for the ARM64 architecture.

3. **Identify Operation Types:** I'll categorize the operations being rewritten. In this snippet, the predominant operations are related to:
    * **Left Shift Operations (`OpLsh...`):**  Various bitwise left shift operations with different operand sizes (e.g., `Lsh32x32`, `Lsh64x8`).
    * **Modulo Operations (`OpMod...`):** Integer modulo operations (`Mod16`, `Mod32`, `Mod64`).
    * **Memory Move Operation (`OpMove`):** Moving blocks of memory.
    * **Not Equal Comparisons (`OpNeq...`):**  Checking for inequality between different data types.
    * **Bitwise NOT (`OpNot`):**  Logical negation.
    * **Pointer Offset (`OpOffPtr`):** Calculating memory addresses with offsets.

4. **Analyze Rewrite Logic:** For each operation, I'll examine the different rewrite rules (the `match:` and `result:` blocks). I'll look for:
    * **Direct Mappings:** Cases where a Go operation is directly translated to a specific ARM64 instruction (e.g., `Lsh32x32` to `OpARM64SLL` when the shift is bounded).
    * **Conditional Rewrites:** Cases where the rewrite depends on certain conditions (e.g., `shiftIsBounded(v)`). This often involves generating conditional select instructions (`OpARM64CSEL`).
    * **Specialized Handling:**  The `OpMove` function is a prime example of specialized handling for different sizes of memory moves, often broken down into smaller load and store operations or using optimized instructions like `STP` and `LDP`. The Duff's device optimization is also evident.

5. **Infer Higher-Level Functionality (if possible):** Based on the operations, I can infer this code is part of the *backend* of the Go compiler. Specifically, it's involved in the *intermediate representation (SSA)* to *machine code* translation for the ARM64 architecture. It aims to optimize Go code by leveraging specific ARM64 instructions.

6. **Construct Examples:** For significant operations, I'll create Go code examples that would trigger the rewrite rules. I'll provide the *input* Go code and the *output* ARM64-like instructions (or a description of the generated instructions). For conditional rewrites, I'll create examples that satisfy both the `cond` and `!cond` scenarios.

7. **Identify Potential Pitfalls:** I'll look for areas where developers might make mistakes or misunderstand the underlying behavior. For instance, the `OpMove` function's complexity might lead to assumptions about its efficiency for small sizes. The handling of unbounded shifts is another potential area.

8. **Address Specific Instructions:**
    * **Command-line Arguments:**  I'll review the code for any direct handling of command-line arguments. In this snippet, there are no explicit command-line argument processing sections. This type of logic is more likely found in earlier stages of the compiler.
    * **Part 15 of 20:**  I'll acknowledge this context and note that the functionality builds upon previous parts, focusing on instruction selection and optimization for ARM64.

9. **Structure the Answer:** I'll organize the information clearly using headings and bullet points to address each part of the request. I'll use precise language and provide code examples where needed.

10. **Review and Refine:** I'll reread my answer and the original code to ensure accuracy, completeness, and clarity.

By following these steps, I can effectively analyze the provided Go code snippet and provide a comprehensive and informative answer to the user's request. The key is to understand the *purpose* of the code within the Go compiler's compilation process.
这是一个Go语言源文件 `go/src/cmd/compile/internal/ssa/rewriteARM64.go` 的一部分，主要负责**将Go语言的中间表示（SSA）中的操作符，针对ARM64架构进行重写和优化**。

**具体功能归纳：**

这部分代码主要定义了一系列的 `rewriteValueARM64_OpXXX` 函数，这些函数针对特定的Go语言操作符 `OpXXX`，定义了在ARM64架构下的重写规则。其核心功能是将高级的、通用的Go语言操作，转换为更底层的、更适合ARM64硬件执行的指令序列。

**具体功能列举:**

1. **处理左移操作 (`OpLsh`)：**
   - 针对不同大小的整数类型（8位、16位、32位、64位）以及不同大小的移位量类型（8位、16位、32位、64位）的左移操作 (`OpLshXXxYY`)，定义了重写规则。
   - **如果移位量在界限内 (`shiftIsBounded(v)`)**:  直接使用 ARM64 的左移指令 `SLL`。
   - **如果移位量可能超出界限**: 使用条件选择指令 `CSEL`，当移位量超出时，结果置为 0，否则执行左移。

2. **处理取模操作 (`OpMod`)：**
   - 针对不同大小的带符号和无符号整数类型（8位、16位、32位、64位）的取模操作 (`OpModXX` 和 `OpModXXu`)，将其转换为 ARM64 的取模指令 `MODW` (32位) 或 `MOD` (64位)。在处理较小类型时，会先进行符号扩展或零扩展。

3. **处理内存移动操作 (`OpMove`)：**
   - 针对将一块内存从一个位置复制到另一个位置的操作。
   - 针对不同大小的移动量，采用了不同的优化策略：
     - 小于等于16字节：使用一系列的单字节、双字节、四字节、八字节的加载和存储指令 (`MOVBstore`, `MOVHstore`, `MOVWstore`, `MOVDstore`) 组合实现。
     - 16字节：使用 `STP` (store pair) 和 `LDP` (load pair) 指令。
     - 更大的尺寸：使用 `STP` 和 `LDP` 组合，并针对特定尺寸（例如 32 字节、48 字节、64 字节）进行了优化展开。
     - 对于更大的尺寸，且满足特定条件（例如大小是 16 的倍数，且未禁用 Duff's Device 优化），可能会使用 `DUFFCOPY` 指令进行优化。
     - 如果尺寸非常大或者禁用了 Duff's Device，则会转换为 `LoweredMove` 操作。

4. **处理不等比较操作 (`OpNeq`)：**
   - 针对不同大小的整数类型和浮点数类型（8位、16位、32位、64位，以及浮点数 `float32` 和 `float64`）的不等比较操作 (`OpNeqXX` 和 `OpNeqXXF`)，将其转换为 ARM64 的比较指令 (`CMPW`, `CMP`, `FCMPS`, `FCMPD`) 并配合 `NotEqual` 操作符。

5. **处理按位取反操作 (`OpNot`)：**
   - 将按位取反操作转换为与常量 1 进行异或操作 (`XOR (MOVDconst [1]) x`)。

6. **处理指针偏移操作 (`OpOffPtr`)：**
   - 将计算指针偏移的操作，转换为 ARM64 的地址计算指令 `MOVDaddr`，前提是偏移量是 32 位有符号数。

**推断的 Go 语言功能实现（举例）：**

这部分代码主要负责对基本的算术、逻辑和内存操作进行优化。以下是一些可能触发这些重写规则的 Go 代码示例：

```go
package main

func main() {
	var a int32 = 10
	var b uint8 = 5
	c := a << b // 触发 OpLsh32x8

	var d int64 = 100
	var e int64 = 7
	f := d % e  // 触发 OpMod64

	var arr1 [10]int
	var arr2 [10]int
	// 触发 OpMove (假设编译器会识别出这是一个内存复制)
	for i := 0; i < len(arr1); i++ {
		arr1[i] = arr2[i]
	}

	var g float32 = 3.14
	var h float32 = 2.71
	neq := g != h // 触发 OpNeq32F

	var i int64 = 0xFFFFFFFFFFFFFFFF
	j := ^i       // 触发 OpNot
}
```

**代码推理（带假设的输入与输出）：**

**假设输入 (针对 `rewriteValueARM64_OpLsh32x8`)：**

一个 SSA 中的 `Value` 结构体 `v`，代表 `a << b` 这个操作，其中 `a` 的类型是 `int32`，`b` 的类型是 `uint8`，并且 `b` 的值是 `5`。

**输出 (如果 `shiftIsBounded(v)` 返回 `true`)：**

`v` 将被重写为代表 ARM64 的 `SLL` 指令的 `Value` 结构体，其参数为 `a` 和 `b`。  大致等价于 ARM64 汇编指令: `SLL W_a, W_a, #5` (假设 `W_a` 是寄存器表示 `a`)。

**输出 (如果 `shiftIsBounded(v)` 返回 `false`)：**

`v` 将被重写为代表条件选择的 `CSEL` 指令的 `Value` 结构体，包含一个 `SLL` 指令（当移位量小于 64 时）和一个常量 0（当移位量大于等于 64 时）。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。 命令行参数的处理通常发生在编译器的前端部分，用于控制编译过程的选项（例如优化级别、目标架构等）。这些参数会影响到后续的 SSA 生成和优化过程，从而间接地影响到 `rewriteARM64.go` 中的重写规则是否生效。

例如，如果使用了 `-gcflags="-N"` 禁用优化，那么某些优化性的重写规则可能就不会被应用。

**使用者易犯错的点（举例）：**

对于直接使用 `cmd/compile/internal/ssa` 包的开发者来说，一个易犯错的点可能是 **错误地假设了某些 Go 语言操作会直接对应到某个特定的 ARM64 指令**。 实际上，编译器会根据上下文和优化策略进行复杂的转换。

例如，开发者可能认为简单的整数加法会始终对应一个 `ADD` 指令，但实际上，编译器可能会使用 LEA (Load Effective Address) 指令在某些情况下实现加法，或者与其他操作合并。

**总结一下它的功能 (针对第15部分，共20部分):**

作为编译过程的一部分，`rewriteARM64.go` 的第15部分专注于 **针对 Go 语言中常见的算术、逻辑和内存操作，进行基于 ARM64 架构的指令选择和初步优化**。  它将通用的 SSA 操作符转换为更贴近硬件的 ARM64 指令序列，例如使用 `SLL` 进行左移，`MODW`/`MOD` 进行取模，以及使用一系列的加载/存储指令或者 `STP`/`LDP` 来优化内存移动。这部分工作是生成高效 ARM64 机器码的关键步骤。考虑到这是 20 个部分中的第 15 部分，可以推断出之前的部分可能负责更通用的 SSA 重写和架构无关的优化，而后续的部分可能会处理更复杂的指令选择、寄存器分配以及最终的代码生成。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第15部分，共20部分，请归纳一下它的功能

"""
hanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh32x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh32x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh32x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh32x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh32x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh32x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh64x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh64x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh64x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh64x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh64x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh64x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh64x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh8x16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x16 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x16 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh8x32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x32 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x32 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh8x64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Lsh8x64 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x64 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v2.AddArg(y)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpLsh8x8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Lsh8x8 <t> x y)
	// cond: shiftIsBounded(v)
	// result: (SLL <t> x y)
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64SLL)
		v.Type = t
		v.AddArg2(x, y)
		return true
	}
	// match: (Lsh8x8 <t> x y)
	// cond: !shiftIsBounded(v)
	// result: (CSEL [OpARM64LessThanU] (SLL <t> x y) (Const64 <t> [0]) (CMPconst [64] (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		if !(!shiftIsBounded(v)) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(OpARM64LessThanU)
		v0 := b.NewValue0(v.Pos, OpARM64SLL, t)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpConst64, t)
		v1.AuxInt = int64ToAuxInt(0)
		v2 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v3.AddArg(y)
		v2.AddArg(v3)
		v.AddArg3(v0, v1, v2)
		return true
	}
	return false
}
func rewriteValueARM64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (MODW (SignExt16to32 x) (SignExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v0 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt16to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (UMODW (ZeroExt16to32 x) (ZeroExt16to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UMODW)
		v0 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod32 x y)
	// result: (MODW x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueARM64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (Mod64 x y)
	// result: (MOD x y)
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MOD)
		v.AddArg2(x, y)
		return true
	}
}
func rewriteValueARM64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (MODW (SignExt8to32 x) (SignExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64MODW)
		v0 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpSignExt8to32, typ.Int32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (UMODW (ZeroExt8to32 x) (ZeroExt8to32 y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64UMODW)
		v0 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v0.AddArg(x)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(y)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueARM64_OpMove(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	typ := &b.Func.Config.Types
	// match: (Move [0] _ _ mem)
	// result: mem
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		mem := v_2
		v.copyOf(mem)
		return true
	}
	// match: (Move [1] dst src mem)
	// result: (MOVBstore dst (MOVBUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVHstore dst (MOVHUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBUload [2] src mem) (MOVHstore dst (MOVHUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVWstore dst (MOVWUload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [5] dst src mem)
	// result: (MOVBstore [4] dst (MOVBUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 5 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] dst src mem)
	// result: (MOVHstore [4] dst (MOVHUload [4] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [7] dst src mem)
	// result: (MOVWstore [3] dst (MOVWUload [3] src mem) (MOVWstore dst (MOVWUload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 7 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] dst src mem)
	// result: (MOVDstore dst (MOVDload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [9] dst src mem)
	// result: (MOVBstore [8] dst (MOVBUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 9 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVBstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVBUload, typ.UInt8)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [10] dst src mem)
	// result: (MOVHstore [8] dst (MOVHUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 10 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVHstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVHUload, typ.UInt16)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [11] dst src mem)
	// result: (MOVDstore [3] dst (MOVDload [3] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 11 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] dst src mem)
	// result: (MOVWstore [8] dst (MOVWUload [8] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpARM64MOVWUload, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [13] dst src mem)
	// result: (MOVDstore [5] dst (MOVDload [5] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 13 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(5)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(5)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [14] dst src mem)
	// result: (MOVDstore [6] dst (MOVDload [6] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 14 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [15] dst src mem)
	// result: (MOVDstore [7] dst (MOVDload [7] src mem) (MOVDstore dst (MOVDload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 15 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(7)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(7)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpARM64MOVDstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpARM64MOVDload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] dst src mem)
	// result: (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v.AddArg4(dst, v0, v2, mem)
		return true
	}
	// match: (Move [32] dst src mem)
	// result: (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 32 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(16)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v3.AddArg4(dst, v4, v6, mem)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [48] dst src mem)
	// result: (STP [32] dst (Select0 <typ.UInt64> (LDP [32] src mem)) (Select1 <typ.UInt64> (LDP [32] src mem)) (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 48 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(32)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(32)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(16)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AuxInt = int32ToAuxInt(16)
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v7 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v8 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v9 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v9.AddArg2(src, mem)
		v8.AddArg(v9)
		v10 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v10.AddArg(v9)
		v7.AddArg4(dst, v8, v10, mem)
		v3.AddArg4(dst, v4, v6, v7)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [64] dst src mem)
	// result: (STP [48] dst (Select0 <typ.UInt64> (LDP [48] src mem)) (Select1 <typ.UInt64> (LDP [48] src mem)) (STP [32] dst (Select0 <typ.UInt64> (LDP [32] src mem)) (Select1 <typ.UInt64> (LDP [32] src mem)) (STP [16] dst (Select0 <typ.UInt64> (LDP [16] src mem)) (Select1 <typ.UInt64> (LDP [16] src mem)) (STP dst (Select0 <typ.UInt64> (LDP src mem)) (Select1 <typ.UInt64> (LDP src mem)) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 64 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpARM64STP)
		v.AuxInt = int32ToAuxInt(48)
		v0 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v1.AuxInt = int32ToAuxInt(48)
		v1.AddArg2(src, mem)
		v0.AddArg(v1)
		v2 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v2.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(32)
		v4 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v5 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v5.AuxInt = int32ToAuxInt(32)
		v5.AddArg2(src, mem)
		v4.AddArg(v5)
		v6 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v6.AddArg(v5)
		v7 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v7.AuxInt = int32ToAuxInt(16)
		v8 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v9 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v9.AuxInt = int32ToAuxInt(16)
		v9.AddArg2(src, mem)
		v8.AddArg(v9)
		v10 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v10.AddArg(v9)
		v11 := b.NewValue0(v.Pos, OpARM64STP, types.TypeMem)
		v12 := b.NewValue0(v.Pos, OpSelect0, typ.UInt64)
		v13 := b.NewValue0(v.Pos, OpARM64LDP, types.NewTuple(typ.UInt64, typ.UInt64))
		v13.AddArg2(src, mem)
		v12.AddArg(v13)
		v14 := b.NewValue0(v.Pos, OpSelect1, typ.UInt64)
		v14.AddArg(v13)
		v11.AddArg4(dst, v12, v14, mem)
		v7.AddArg4(dst, v8, v10, v11)
		v3.AddArg4(dst, v4, v6, v7)
		v.AddArg4(dst, v0, v2, v3)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 != 0 && s%16 <= 8 && s > 16
	// result: (Move [8] (OffPtr <dst.Type> dst [s-8]) (OffPtr <src.Type> src [s-8]) (Move [s-s%16] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 != 0 && s%16 <= 8 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - 8)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - 8)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%16)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 != 0 && s%16 > 8 && s > 16
	// result: (Move [16] (OffPtr <dst.Type> dst [s-16]) (OffPtr <src.Type> src [s-16]) (Move [s-s%16] dst src mem))
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 != 0 && s%16 > 8 && s > 16) {
			break
		}
		v.reset(OpMove)
		v.AuxInt = int64ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpOffPtr, dst.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(dst)
		v1 := b.NewValue0(v.Pos, OpOffPtr, src.Type)
		v1.AuxInt = int64ToAuxInt(s - 16)
		v1.AddArg(src)
		v2 := b.NewValue0(v.Pos, OpMove, types.TypeMem)
		v2.AuxInt = int64ToAuxInt(s - s%16)
		v2.AddArg3(dst, src, mem)
		v.AddArg3(v0, v1, v2)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s > 64 && s <= 16*64 && s%16 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [8 * (64 - s/16)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 64 && s <= 16*64 && s%16 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARM64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(8 * (64 - s/16))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] dst src mem)
	// cond: s%16 == 0 && (s > 16*64 || config.noDuffDevice) && logLargeCopy(v, s)
	// result: (LoweredMove dst src (ADDconst <src.Type> src [s-16]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%16 == 0 && (s > 16*64 || config.noDuffDevice) && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpARM64LoweredMove)
		v0 := b.NewValue0(v.Pos, OpARM64ADDconst, src.Type)
		v0.AuxInt = int64ToAuxInt(s - 16)
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (NotEqual (CMPW (ZeroExt16to32 x) (ZeroExt16to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32 x y)
	// result: (NotEqual (CMPW x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (NotEqual (FCMPS x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64 x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (NotEqual (FCMPD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (NotEqual (CMPW (ZeroExt8to32 x) (ZeroExt8to32 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to32, typ.UInt32)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (NeqPtr x y)
	// result: (NotEqual (CMP x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpARM64NotEqual)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueARM64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Not x)
	// result: (XOR (MOVDconst [1]) x)
	for {
		x := v_0
		v.reset(OpARM64XOR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(1)
		v.AddArg2(v0, x)
		return true
	}
}
func rewriteValueARM64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// cond: is32Bit(off)
	// result: (MOVDaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP || !(is32Bit(off)) {
			br
"""




```