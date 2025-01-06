Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the Go code provided, specifically focusing on its function, potential Go feature implementation, code examples (with assumptions), command-line argument handling, common mistakes, and a final concise summary as part 5 of 7.

2. **Analyze the Code Structure:** The code consists of several Go functions named `rewriteValueMIPS64_Op...`. This naming convention strongly suggests that these functions are part of a larger system responsible for *rewriting* or *optimizing* some kind of intermediate representation (IR) for the MIPS64 architecture. The `Op` prefix further indicates that these functions handle specific operation types within that IR. The functions take a `*Value` as input and return a boolean, hinting at a rule-based transformation system.

3. **Infer the Purpose of `rewriteValueMIPS64_Op...`:**  The core function of these functions is to identify specific patterns in the IR (represented by `*Value`) and transform them into more efficient or canonical forms. The transformations are based on matching the `Op` field of the input `*Value` and potentially its arguments and auxiliary information (`AuxInt`, `Aux`).

4. **Identify Key Operations and Transformations:** I'll go through each function and note the kinds of transformations being performed:

    * **`rewriteValueMIPS64_OpMIPS64SUBV`:** Simplifies subtraction operations, especially when one operand is a constant or when subtracting a value from itself. It also handles the case of subtracting from zero (negation).
    * **`rewriteValueMIPS64_OpMIPS64SUBVconst`:**  Deals with subtraction where one operand is a constant. It simplifies cases like subtracting zero, subtracting a constant from another constant, and combining consecutive subtractions or additions with constants.
    * **`rewriteValueMIPS64_OpMIPS64XOR`:** Simplifies XOR operations, particularly when one operand is a constant or XORing a value with itself.
    * **`rewriteValueMIPS64_OpMIPS64XORconst`:** Handles XOR where one operand is a constant. It includes cases like XORing with zero, XORing with -1 (which is equivalent to NOR), XORing two constants, and combining consecutive XORs with constants.
    * **`rewriteValueMIPS64_OpMod...`:** These functions (`Mod16`, `Mod16u`, etc.) implement the modulo operator for different integer sizes. They achieve this by using division operations (`DIVV`, `DIVVU`) and selecting the remainder (`Select0`). They often involve sign or zero extension to ensure correct behavior.
    * **`rewriteValueMIPS64_OpMove`:**  Optimizes memory copy operations (`Move`). It handles small copies with individual byte/half-word/word stores, larger aligned copies with multi-word stores, and very large copies using a `DUFFCOPY` mechanism. It also includes a fallback to a `LoweredMove` for unaligned or very large copies.
    * **`rewriteValueMIPS64_OpMul...`:** Implements multiplication for various integer sizes using a `MULVU` operation and selecting the high bits (`Select1`), likely to handle potential overflows.
    * **`rewriteValueMIPS64_OpNeq...`:** Implements not-equal comparisons for different data types. It often uses XOR and a greater-than-unsigned comparison (`SGTU`) with zero. For floating-point numbers, it uses specific floating-point comparison instructions (`CMPEQF`, `CMPEQD`) and checks the flag.
    * **`rewriteValueMIPS64_OpNot`:** Implements the logical NOT operation using XOR with 1.
    * **`rewriteValueMIPS64_OpOffPtr`:**  Calculates the address of a memory location relative to a pointer. It optimizes the case of offsetting from the stack pointer (`SP`).
    * **`rewriteValueMIPS64_OpPanicBounds`:** Deals with runtime bounds checking and panic conditions. It uses different "lowered" panic operations based on the `boundsABI` setting.
    * **`rewriteValueMIPS64_OpRotateLeft...`:** Implements left bit rotation using a combination of left shift (`Lsh`) and right shift (`Rsh`) operations with appropriate masks.
    * **`rewriteValueMIPS64_OpRsh16Ux...`:** Implements unsigned right shift for 16-bit values with different shift amounts. It uses a combination of `AND`, `NEGV`, `SGTU`, and `SRLV` to handle shifts larger than the bit size.

5. **Infer the Go Feature:** Based on the file path (`go/src/cmd/compile/internal/ssa/`), the consistent naming conventions, and the nature of the transformations, it's highly likely that this code is part of the Go compiler's intermediate representation (SSA - Static Single Assignment) optimization phase for the MIPS64 architecture. Specifically, it looks like these functions are *rewrite rules* that the compiler applies to simplify and optimize the generated SSA code before final code generation.

6. **Construct Go Code Examples (with Assumptions):**  I'll create examples illustrating some of the transformations. I'll need to make assumptions about how the SSA values are represented and how the operators map to Go code.

7. **Address Command-Line Arguments:**  Since this is part of the compiler's internal workings, these specific rewrite rules are unlikely to be directly influenced by command-line arguments. However, the *overall* compilation process and optimization level are certainly affected by compiler flags (like `-O`). I'll explain this connection.

8. **Identify Common Mistakes:**  Users don't directly interact with this code. The potential mistakes would be in *writing* such rewrite rules incorrectly, which is a concern for compiler developers. I'll provide examples of what could go wrong in rule definitions.

9. **Write the Summary (Part 5):** I'll synthesize the information gathered into a concise summary, keeping in mind that this is part 5 of 7, implying a need to summarize the functionality covered in this specific code snippet.

10. **Review and Refine:** Finally, I'll review my answer for accuracy, clarity, and completeness, ensuring it addresses all parts of the request. I'll double-check the code examples and explanations.

By following these steps, I can systematically analyze the code and provide a comprehensive and accurate answer to the request. The key is to recognize the patterns and infer the context within the Go compiler.
这是对Go语言在MIPS64架构上的代码生成和优化的一个重要组成部分。具体来说，这个文件 `rewriteMIPS64.go` 包含了大量用于转换和优化抽象汇编表示（SSA - Static Single Assignment）的规则，目标是生成更高效的MIPS64机器码。

**功能归纳:**

这部分代码的主要功能是定义了一系列针对MIPS64架构的SSA重写规则，用于简化和优化算术运算、逻辑运算、内存操作以及其他基本操作。具体来说，它涵盖了以下操作的重写：

* **算术运算:**  加法 (`ADDVconst`)、减法 (`SUBV`, `SUBVconst`)、乘法 (`Mul16`, `Mul32`, `Mul64`, `Mul8`)、取模 (`Mod16`, `Mod16u`, `Mod32`, `Mod32u`, `Mod64`, `Mod64u`, `Mod8`, `Mod8u`)。
* **逻辑运算:** 异或 (`XOR`, `XORconst`)、非 (`Not`)。
* **位运算:**  左移 (`Lsh...`)、右移 (`Rsh...`)、循环左移 (`RotateLeft...`)。
* **比较运算:** 不等于 (`Neq16`, `Neq32`, `Neq32F`, `Neq64`, `Neq64F`, `Neq8`, `NeqPtr`)。
* **内存操作:** 移动内存块 (`Move`)、获取指针偏移 (`OffPtr`)。
* **其他操作:**  Panic边界检查 (`PanicBounds`)。

这些重写规则的目标是将SSA中的某些操作模式转换为更简单、更高效的MIPS64指令序列。

**Go语言功能的实现推理和代码示例:**

基于这些重写规则处理的操作类型，可以推断出这部分代码是Go语言编译器在编译过程中，将Go语言的各种操作转换为MIPS64汇编指令的关键步骤。

**示例 1: 减法优化**

`rewriteValueMIPS64_OpMIPS64SUBV` 中的一个规则将 `SUBV x (MOVVconst [c])` 转换为 `SUBVconst [c] x`，如果 `c` 是一个32位常量。这对应于Go语言中的整数减法，并且尝试将常量操作数放在更适合指令的位置。

```go
// 假设的 SSA 表示
// v1 = SUBV a (MOVVconst[5])

// 对应的 Go 代码
a := 10
result := a - 5

// 重写规则将其转换为：
// v1 = SUBVconst[5] a
```

**示例 2: 异或优化**

`rewriteValueMIPS64_OpMIPS64XOR` 中的一个规则将 `XOR x x` 转换为 `MOVVconst [0]`。这对应于任何值与自身进行异或运算的结果总是为零。

```go
// 假设的 SSA 表示
// v1 = XOR a a

// 对应的 Go 代码
a := 15
result := a ^ a // 结果为 0

// 重写规则将其转换为：
// v1 = MOVVconst[0]
```

**示例 3:  取模运算**

`rewriteValueMIPS64_OpMod16` 将 16 位整数的取模运算转换为先进行符号扩展，然后执行 64 位除法，并选择余数部分。

```go
// 假设的 SSA 表示
// v1 = Mod16 a b

// 对应的 Go 代码
a := int16(10)
b := int16(3)
result := a % b

// 重写规则将其转换为：
// v_select0 = Select0(DIVV(SignExt16to64(a), SignExt16to64(b)))
```

**假设的输入与输出 (针对 `rewriteValueMIPS64_OpMIPS64SUBV`):**

**输入 (SSA `Value`):**

```
Op: OpMIPS64SUBV
Args: [
  {Op: OpVar, Name: "a"},
  {Op: OpMIPS64MOVVconst, AuxInt: 5}
]
```

**输出 (boolean):** `true` (表示发生了重写)

**副作用:**  输入的 `Value` `v` 被修改为:

```
Op: OpMIPS64SUBVconst
AuxInt: 5
Args: [
  {Op: OpVar, Name: "a"}
]
```

**命令行参数的具体处理:**

这个代码片段本身不直接处理命令行参数。但是，`rewriteMIPS64.go` 文件是Go编译器的一部分。Go编译器的命令行参数（例如 `-gcflags` 中的优化级别 `-O`) 会影响编译器执行的优化程度，间接地影响这些重写规则的应用。例如，在较低的优化级别下，某些复杂的重写规则可能不会被应用。

**使用者易犯错的点:**

普通Go语言开发者不会直接编写或修改 `rewriteMIPS64.go` 文件。这是编译器开发者的工作。  然而，理解这些重写规则有助于理解Go语言编译器是如何优化代码的，从而在编写Go代码时可以更好地利用编译器的优化能力。

对于编译器开发者来说，编写错误的重写规则可能导致生成错误的代码或者性能下降。例如，条件判断不正确可能导致不应该发生的重写，或者重写后的代码引入了新的问题。

**第5部分功能归纳:**

总而言之，`rewriteMIPS64.go` 的这部分代码定义了MIPS64架构特定的SSA重写规则，用于优化各种基本操作，包括算术运算、逻辑运算、位运算、比较运算和内存操作。这些规则是Go编译器将高级Go代码转换为高效MIPS64机器码的关键步骤，旨在提高最终生成的可执行文件的性能。它通过模式匹配和转换，将抽象的SSA表示转换为更接近目标机器指令的形式。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能

"""
unc rewriteValueMIPS64_OpMIPS64SUBV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (SUBV x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (SUBVconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpMIPS64SUBVconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (SUBV x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (SUBV (MOVVconst [0]) x)
	// result: (NEGV x)
	for {
		if v_0.Op != OpMIPS64MOVVconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpMIPS64NEGV)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64SUBVconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (SUBVconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (SUBVconst [c] (MOVVconst [d]))
	// result: (MOVVconst [d-c])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(d - c)
		return true
	}
	// match: (SUBVconst [c] (SUBVconst [d] x))
	// cond: is32Bit(-c-d)
	// result: (ADDVconst [-c-d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64SUBVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c - d)) {
			break
		}
		v.reset(OpMIPS64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c - d)
		v.AddArg(x)
		return true
	}
	// match: (SUBVconst [c] (ADDVconst [d] x))
	// cond: is32Bit(-c+d)
	// result: (ADDVconst [-c+d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64ADDVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(-c + d)) {
			break
		}
		v.reset(OpMIPS64ADDVconst)
		v.AuxInt = int64ToAuxInt(-c + d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64XOR(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (XOR x (MOVVconst [c]))
	// cond: is32Bit(c)
	// result: (XORconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpMIPS64MOVVconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			if !(is32Bit(c)) {
				continue
			}
			v.reset(OpMIPS64XORconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (XOR x x)
	// result: (MOVVconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMIPS64XORconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (XORconst [0] x)
	// result: x
	for {
		if auxIntToInt64(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (XORconst [-1] x)
	// result: (NORconst [0] x)
	for {
		if auxIntToInt64(v.AuxInt) != -1 {
			break
		}
		x := v_0
		v.reset(OpMIPS64NORconst)
		v.AuxInt = int64ToAuxInt(0)
		v.AddArg(x)
		return true
	}
	// match: (XORconst [c] (MOVVconst [d]))
	// result: (MOVVconst [c^d])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64MOVVconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		v.reset(OpMIPS64MOVVconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		return true
	}
	// match: (XORconst [c] (XORconst [d] x))
	// cond: is32Bit(c^d)
	// result: (XORconst [c^d] x)
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpMIPS64XORconst {
			break
		}
		d := auxIntToInt64(v_0.AuxInt)
		x := v_0.Args[0]
		if !(is32Bit(c ^ d)) {
			break
		}
		v.reset(OpMIPS64XORconst)
		v.AuxInt = int64ToAuxInt(c ^ d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMod16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16 x y)
	// result: (Select0 (DIVV (SignExt16to64 x) (SignExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt16to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod16u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod16u x y)
	// result: (Select0 (DIVVU (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32 x y)
	// result: (Select0 (DIVV (SignExt32to64 x) (SignExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt32to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod32u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod32u x y)
	// result: (Select0 (DIVVU (ZeroExt32to64 x) (ZeroExt32to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod64 x y)
	// result: (Select0 (DIVV x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod64u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod64u x y)
	// result: (Select0 (DIVVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8 x y)
	// result: (Select0 (DIVV (SignExt8to64 x) (SignExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVV, types.NewTuple(typ.Int64, typ.Int64))
		v1 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpSignExt8to64, typ.Int64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMod8u(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mod8u x y)
	// result: (Select0 (DIVVU (ZeroExt8to64 x) (ZeroExt8to64 y)))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect0)
		v0 := b.NewValue0(v.Pos, OpMIPS64DIVVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMove(v *Value) bool {
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
	// result: (MOVBstore dst (MOVBload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 1 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore dst (MOVHload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [2] dst src mem)
	// result: (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 2 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(1)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore dst (MOVWload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [4] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [4] dst src mem)
	// result: (MOVBstore [3] dst (MOVBload [3] src mem) (MOVBstore [2] dst (MOVBload [2] src mem) (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(3)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(1)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v4.AuxInt = int32ToAuxInt(1)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore dst (MOVVload src mem) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v0.AddArg2(src, mem)
		v.AddArg3(dst, v0, mem)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [8] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [6] dst (MOVHload [6] src mem) (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(6)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(6)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(2)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v4.AuxInt = int32ToAuxInt(2)
		v4.AddArg2(src, mem)
		v5 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v6 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v6.AddArg2(src, mem)
		v5.AddArg3(dst, v6, mem)
		v3.AddArg3(dst, v4, v5)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [3] dst src mem)
	// result: (MOVBstore [2] dst (MOVBload [2] src mem) (MOVBstore [1] dst (MOVBload [1] src mem) (MOVBstore dst (MOVBload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		dst := v_0
		src := v_1
		mem := v_2
		v.reset(OpMIPS64MOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v0.AuxInt = int32ToAuxInt(2)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v2.AuxInt = int32ToAuxInt(1)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVBstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVBload, typ.Int8)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [6] {t} dst src mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] dst (MOVHload [4] src mem) (MOVHstore [2] dst (MOVHload [2] src mem) (MOVHstore dst (MOVHload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPS64MOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v0.AuxInt = int32ToAuxInt(4)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v2.AuxInt = int32ToAuxInt(2)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVHstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVHload, typ.Int16)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [12] {t} dst src mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] dst (MOVWload [8] src mem) (MOVWstore [4] dst (MOVWload [4] src mem) (MOVWstore dst (MOVWload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPS64MOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v2.AuxInt = int32ToAuxInt(4)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVWstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVWload, typ.Int32)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [16] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [8] dst (MOVVload [8] src mem) (MOVVstore dst (MOVVload src mem) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(8)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v2.AddArg2(src, mem)
		v1.AddArg3(dst, v2, mem)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [24] {t} dst src mem)
	// cond: t.Alignment()%8 == 0
	// result: (MOVVstore [16] dst (MOVVload [16] src mem) (MOVVstore [8] dst (MOVVload [8] src mem) (MOVVstore dst (MOVVload src mem) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 24 {
			break
		}
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(t.Alignment()%8 == 0) {
			break
		}
		v.reset(OpMIPS64MOVVstore)
		v.AuxInt = int32ToAuxInt(16)
		v0 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v0.AuxInt = int32ToAuxInt(16)
		v0.AddArg2(src, mem)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v2.AuxInt = int32ToAuxInt(8)
		v2.AddArg2(src, mem)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVstore, types.TypeMem)
		v4 := b.NewValue0(v.Pos, OpMIPS64MOVVload, typ.UInt64)
		v4.AddArg2(src, mem)
		v3.AddArg3(dst, v4, mem)
		v1.AddArg3(dst, v2, v3)
		v.AddArg3(dst, v0, v1)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: s%8 == 0 && s >= 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice && logLargeCopy(v, s)
	// result: (DUFFCOPY [16 * (128 - s/8)] dst src mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s%8 == 0 && s >= 24 && s <= 8*128 && t.Alignment()%8 == 0 && !config.noDuffDevice && logLargeCopy(v, s)) {
			break
		}
		v.reset(OpMIPS64DUFFCOPY)
		v.AuxInt = int64ToAuxInt(16 * (128 - s/8))
		v.AddArg3(dst, src, mem)
		return true
	}
	// match: (Move [s] {t} dst src mem)
	// cond: s > 24 && logLargeCopy(v, s) || t.Alignment()%8 != 0
	// result: (LoweredMove [t.Alignment()] dst src (ADDVconst <src.Type> src [s-moveSize(t.Alignment(), config)]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		dst := v_0
		src := v_1
		mem := v_2
		if !(s > 24 && logLargeCopy(v, s) || t.Alignment()%8 != 0) {
			break
		}
		v.reset(OpMIPS64LoweredMove)
		v.AuxInt = int64ToAuxInt(t.Alignment())
		v0 := b.NewValue0(v.Pos, OpMIPS64ADDVconst, src.Type)
		v0.AuxInt = int64ToAuxInt(s - moveSize(t.Alignment(), config))
		v0.AddArg(src)
		v.AddArg4(dst, src, v0, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpMul16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul16 x y)
	// result: (Select1 (MULVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMul32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul32 x y)
	// result: (Select1 (MULVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMul64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul64 x y)
	// result: (Select1 (MULVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpMul8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Mul8 x y)
	// result: (Select1 (MULVU x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpSelect1)
		v0 := b.NewValue0(v.Pos, OpMIPS64MULVU, types.NewTuple(typ.UInt64, typ.UInt64))
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpNeq16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq16 x y)
	// result: (SGTU (XOR (ZeroExt16to32 x) (ZeroExt16to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt16to32, typ.UInt32)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpNeq32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq32 x y)
	// result: (SGTU (XOR (ZeroExt32to64 x) (ZeroExt32to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpNeq32F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq32F x y)
	// result: (FPFlagFalse (CMPEQF x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPEQF, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpNeq64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq64 x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpNeq64F(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (Neq64F x y)
	// result: (FPFlagFalse (CMPEQD x y))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64FPFlagFalse)
		v0 := b.NewValue0(v.Pos, OpMIPS64CMPEQD, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
}
func rewriteValueMIPS64_OpNeq8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Neq8 x y)
	// result: (SGTU (XOR (ZeroExt8to64 x) (ZeroExt8to64 y)) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v1 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v1.AddArg(x)
		v2 := b.NewValue0(v.Pos, OpZeroExt8to64, typ.UInt64)
		v2.AddArg(y)
		v0.AddArg2(v1, v2)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpNeqPtr(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (NeqPtr x y)
	// result: (SGTU (XOR x y) (MOVVconst [0]))
	for {
		x := v_0
		y := v_1
		v.reset(OpMIPS64SGTU)
		v0 := b.NewValue0(v.Pos, OpMIPS64XOR, typ.UInt64)
		v0.AddArg2(x, y)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(0)
		v.AddArg2(v0, v1)
		return true
	}
}
func rewriteValueMIPS64_OpNot(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Not x)
	// result: (XORconst [1] x)
	for {
		x := v_0
		v.reset(OpMIPS64XORconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(x)
		return true
	}
}
func rewriteValueMIPS64_OpOffPtr(v *Value) bool {
	v_0 := v.Args[0]
	// match: (OffPtr [off] ptr:(SP))
	// cond: is32Bit(off)
	// result: (MOVVaddr [int32(off)] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		if ptr.Op != OpSP || !(is32Bit(off)) {
			break
		}
		v.reset(OpMIPS64MOVVaddr)
		v.AuxInt = int32ToAuxInt(int32(off))
		v.AddArg(ptr)
		return true
	}
	// match: (OffPtr [off] ptr)
	// result: (ADDVconst [off] ptr)
	for {
		off := auxIntToInt64(v.AuxInt)
		ptr := v_0
		v.reset(OpMIPS64ADDVconst)
		v.AuxInt = int64ToAuxInt(off)
		v.AddArg(ptr)
		return true
	}
}
func rewriteValueMIPS64_OpPanicBounds(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 0
	// result: (LoweredPanicBoundsA [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 0) {
			break
		}
		v.reset(OpMIPS64LoweredPanicBoundsA)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 1
	// result: (LoweredPanicBoundsB [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 1) {
			break
		}
		v.reset(OpMIPS64LoweredPanicBoundsB)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	// match: (PanicBounds [kind] x y mem)
	// cond: boundsABI(kind) == 2
	// result: (LoweredPanicBoundsC [kind] x y mem)
	for {
		kind := auxIntToInt64(v.AuxInt)
		x := v_0
		y := v_1
		mem := v_2
		if !(boundsABI(kind) == 2) {
			break
		}
		v.reset(OpMIPS64LoweredPanicBoundsC)
		v.AuxInt = int64ToAuxInt(kind)
		v.AddArg3(x, y, mem)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpRotateLeft16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft16 <t> x (MOVVconst [c]))
	// result: (Or16 (Lsh16x64 <t> x (MOVVconst [c&15])) (Rsh16Ux64 <t> x (MOVVconst [-c&15])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr16)
		v0 := b.NewValue0(v.Pos, OpLsh16x64, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 15)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh16Ux64, t)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 15)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpRotateLeft32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft32 <t> x (MOVVconst [c]))
	// result: (Or32 (Lsh32x64 <t> x (MOVVconst [c&31])) (Rsh32Ux64 <t> x (MOVVconst [-c&31])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr32)
		v0 := b.NewValue0(v.Pos, OpLsh32x64, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 31)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh32Ux64, t)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 31)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpRotateLeft64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft64 <t> x (MOVVconst [c]))
	// result: (Or64 (Lsh64x64 <t> x (MOVVconst [c&63])) (Rsh64Ux64 <t> x (MOVVconst [-c&63])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr64)
		v0 := b.NewValue0(v.Pos, OpLsh64x64, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 63)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh64Ux64, t)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 63)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpRotateLeft8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (RotateLeft8 <t> x (MOVVconst [c]))
	// result: (Or8 (Lsh8x64 <t> x (MOVVconst [c&7])) (Rsh8Ux64 <t> x (MOVVconst [-c&7])))
	for {
		t := v.Type
		x := v_0
		if v_1.Op != OpMIPS64MOVVconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpOr8)
		v0 := b.NewValue0(v.Pos, OpLsh8x64, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v1.AuxInt = int64ToAuxInt(c & 7)
		v0.AddArg2(x, v1)
		v2 := b.NewValue0(v.Pos, OpRsh8Ux64, t)
		v3 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v3.AuxInt = int64ToAuxInt(-c & 7)
		v2.AddArg2(x, v3)
		v.AddArg2(v0, v2)
		return true
	}
	return false
}
func rewriteValueMIPS64_OpRsh16Ux16(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux16 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt16to64 y))) (SRLV <t> (ZeroExt16to64 x) (ZeroExt16to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SRLV, t)
		v5 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v5.AddArg(x)
		v4.AddArg2(v5, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpRsh16Ux32(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux32 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt32to64 y))) (SRLV <t> (ZeroExt16to64 x) (ZeroExt32to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v3 := b.NewValue0(v.Pos, OpZeroExt32to64, typ.UInt64)
		v3.AddArg(y)
		v1.AddArg2(v2, v3)
		v0.AddArg(v1)
		v4 := b.NewValue0(v.Pos, OpMIPS64SRLV, t)
		v5 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v5.AddArg(x)
		v4.AddArg2(v5, v3)
		v.AddArg2(v0, v4)
		return true
	}
}
func rewriteValueMIPS64_OpRsh16Ux64(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux64 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) y)) (SRLV <t> (ZeroExt16to64 x) y))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = int64ToAuxInt(64)
		v1.AddArg2(v2, y)
		v0.AddArg(v1)
		v3 := b.NewValue0(v.Pos, OpMIPS64SRLV, t)
		v4 := b.NewValue0(v.Pos, OpZeroExt16to64, typ.UInt64)
		v4.AddArg(x)
		v3.AddArg2(v4, y)
		v.AddArg2(v0, v3)
		return true
	}
}
func rewriteValueMIPS64_OpRsh16Ux8(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Rsh16Ux8 <t> x y)
	// result: (AND (NEGV <t> (SGTU (MOVVconst <typ.UInt64> [64]) (ZeroExt8to64 y))) (SRLV <t> (ZeroExt16to64 x) (ZeroExt8to64 y)))
	for {
		t := v.Type
		x := v_0
		y := v_1
		v.reset(OpMIPS64AND)
		v0 := b.NewValue0(v.Pos, OpMIPS64NEGV, t)
		v1 := b.NewValue0(v.Pos, OpMIPS64SGTU, typ.Bool)
		v2 := b.NewValue0(v.Pos, OpMIPS64MOVVconst, typ.UInt64)
		v2.AuxInt = i
"""




```