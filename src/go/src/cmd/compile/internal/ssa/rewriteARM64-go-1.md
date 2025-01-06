Response: The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `rewriteARM64.go` file within the Go compiler, specifically dealing with SSA (Static Single Assignment) rewriting rules for the ARM64 architecture.

The code consists of several Go functions, each named `rewriteValueARM64_OpARM64_<Operation>`. These functions are responsible for transforming certain SSA operations into simpler or more efficient sequences of operations.

The primary function of these rewrite rules is to optimize the generated ARM64 assembly code by:

1. **Constant Folding:**  Performing arithmetic and logical operations on constants at compile time.
2. **Instruction Selection:** Choosing the most appropriate ARM64 instruction for a given operation, often by matching patterns of operations.
3. **Strength Reduction:** Replacing expensive operations with cheaper equivalents (e.g., using shift operations instead of multiplication/division by powers of 2).
4. **Canonicalization:**  Ensuring a consistent representation of equivalent operations, making further optimizations easier.
5. **Dead Code Elimination Hints:** Using `clobberIfDead` to indicate that the result of an operation is only needed if its output is used, potentially allowing for dead code elimination.

The operations being rewritten in this specific snippet are primarily related to:

- **Comparisons:** `CMN`, `CMNW`, `CMP`, `CMPW` (and their constant and shifted variants)
- **Conditional Selects:** `CSEL`, `CSEL0`, `CSETM`, `CSINC`, `CSINV`, `CSNEG`
- **Arithmetic Operations:** `DIV`, `DIVW`, `EON` (Exclusive OR NOT)
- **Floating-Point Operations:** `FADDD`, `FADDS`, `FCMPD`, `FCMPS`, `FMOVDfpgp`, `FMOVDgpfp`, `FMOVDload`, `FMOVDstore`, `FMOVSload`, `FMOVSstore`, `FMULD`

I need to iterate through each function and identify the transformations it performs. I should look for patterns in the `match` and `result` comments to understand the input and output of each rewrite rule.

Based on the patterns, I can infer the kind of Go language feature that might trigger these rewrites. For example, comparison operations often correspond to `if` statements or other conditional constructs. Load and store operations relate to accessing memory.

I will structure the summary by grouping the functions based on the type of operation they handle.
这段代码是Go语言编译器中针对ARM64架构的SSA（Static Single Assignment）形式的中间代码进行优化的一个部分。具体来说，它定义了一系列重写规则（rewrite rules），用于将一些特定的SSA操作模式转换为更高效的或者更符合目标架构指令集的操作。

**归纳其功能：**

这部分代码的主要功能是针对ARM64架构的比较和条件选择相关的SSA操作进行优化。它涵盖了以下几个方面：

1. **简化比较操作:**
   - 将 `CMN` (Compare Negative) 和 `CMP` (Compare) 操作与常量进行结合，生成 `CMNconst` 和 `CMPconst` 操作，或者使用带移位的比较指令（`CMNshiftLL`, `CMNshiftRL`, `CMNshiftRA`, `CMPshiftLL`, `CMPshiftRL`, `CMPshiftRA`）。
   - 将 `CMNW` 和 `CMPW` 操作与常量进行结合，生成 `CMNWconst` 和 `CMPWconst` 操作。
   - 对比较操作的参数进行规范化，例如 `canonLessThan` 确保比较操作的左操作数小于右操作数，不满足则通过 `InvertFlags` 反转比较结果。

2. **优化条件选择操作:**
   - 将 `CSEL` (Conditional Select) 操作与常量 0 和 -1 结合，简化为 `CSETM` (Conditional Set Mask)。
   - 将 `CSEL` 操作与常量 0 结合，简化为 `CSEL0`。
   - 将 `CSEL` 操作与简单的算术运算（如 `ADDconst [1]`, `MVN`, `NEG`) 结合，简化为 `CSINC`, `CSINV`, `CSNEG`。
   - 利用 `InvertFlags` 优化条件选择操作。
   - 在某些条件下，直接将条件选择操作替换为其中一个操作数。
   - 将基于 `CMPWconst [0]` 的条件选择转换为基于原始布尔值的条件选择。

3. **简化逻辑运算:**
   - 将 `EON` (Exclusive OR NOT) 操作与常量结合，生成 `XORconst` 操作。
   - 将 `EON` 操作与其自身进行运算，简化为常量 -1。
   - 将 `EON` 操作与带移位的操作结合，生成带移位的 `EON` 指令 (`EONshiftLL`, `EONshiftRL`, `EONshiftRA`, `EONshiftRO`)。

4. **优化相等判断:**
   - 将 `Equal` 操作与特定的比较操作模式结合，例如与 `AND`、`NEG`、`ADD`、`MADD`、`MSUB` 的比较结果结合，转换为更直接的比较操作 (`TST`, `CMN`)。
   - 将 `Equal` 操作与 `FlagConstant` 结合，直接计算布尔值。
   - 消除多余的 `InvertFlags`。

5. **浮点运算的优化:**
   - 将 `FADDD` 和 `FADDS` 操作与 `FMULD` 和 `FNMULD` 结合，尝试生成 `FMADDD` 和 `FMSUBD` (Fused Multiply-Add) 指令。
   - 将 `FCMPD` 和 `FCMPS` 操作与浮点数 0 进行比较，生成 `FCMPD0` 和 `FCMPS0` 操作。
   - 优化浮点数的加载和存储操作，例如将与常量偏移的加法合并到加载/存储指令的偏移中，或者转换为索引寻址模式 (`FMOVDloadidx`, `FMOVDstoreidx` 等)。

**代码示例：**

以下是一些基于代码推断的Go语言功能实现的示例，以及假设的输入和输出：

```go
// 假设我们有以下Go代码：
func example(a int64, b int64) bool {
	return a == -b
}

// 这段代码可能会被编译成类似以下的SSA形式 (简化)：
// v1 = Arg <int64> {a}
// v2 = Arg <int64> {b}
// v3 = NEG v2
// v4 = CMP v1 v3
// v5 = Equal v4
// Return v5

// rewriteValueARM64_OpARM64Equal 函数中的规则：
// match: (Equal (CMP x z:(NEG y)))
// cond: z.Uses == 1
// result: (Equal (CMN x y))

// 会将上述 SSA 中的
// v5 = Equal v4  (其中 v4 是 CMP v1 v3，v3 是 NEG v2)
// 转换为：
// v5 = Equal v6
// v6 = CMN v1 v2

// 输出的 SSA 形式会包含 CMN 操作，可能对应 ARM64 的 CMN 指令。
```

```go
// 假设我们有以下Go代码：
func example2(a int64, c int64) bool {
	return a == (10 + c)
}

// 可能会被编译成类似的 SSA 形式：
// v1 = Arg <int64> {a}
// v2 = Const <int64> [10]
// v3 = Arg <int64> {c}
// v4 = ADDconst v3 [10]  // 注意这里可能先有 ADD 再被优化成 ADDconst
// v5 = CMP v1 v4
// v6 = Equal v5
// Return v6

// rewriteValueARM64_OpARM64Equal 函数中的规则：
// match: (Equal (CMPconst [0] x:(ADDconst [c] y)))
// cond: x.Uses == 1
// result: (Equal (CMNconst [c] y))  // 这里匹配不太准确，Equal 更可能直接和 CMPconst 结合

// 更可能匹配的是 CMP 相关的规则，例如：
// rewriteValueARM64_OpARM64CMP 函数中的规则：
// match: (CMP x (MOVDconst [c]))
// result: (CMPconst [c] x)

// 如果编译器的实现细节是先生成 CMP，再优化，那么上述代码可能会先有 CMP。
// 最终 Equal 可能会与 CMPconst 结合，例如：
// rewriteValueARM64_OpARM64Equal 函数中的规则：
// match: (Equal (CMPconst [0] ...))

// 需要更深入的编译原理知识才能完全确定中间步骤。
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是在Go编译器的内部执行的，作为编译过程的一部分。命令行参数的处理发生在编译器的前端和中间表示生成阶段。这些重写规则作用于SSA中间表示，是对已经生成的代码进行优化的过程。

**使用者易犯错的点:**

普通Go语言开发者不会直接接触到这些底层的代码重写规则。这些是编译器开发者的工作。因此，普通使用者不会因为这些规则而犯错。

总而言之，这段代码是Go语言编译器中用于优化ARM64架构代码的关键部分，它通过模式匹配和规则替换，提高了生成代码的效率和性能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共10部分，请归纳一下它的功能

"""
0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64CMNconst)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (CMN x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMNshiftLL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SLLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64CMNshiftLL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (CMN x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMNshiftRL x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRLconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64CMNshiftRL)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	// match: (CMN x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMNshiftRA x0 y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x0 := v_0
			x1 := v_1
			if x1.Op != OpARM64SRAconst {
				continue
			}
			c := auxIntToInt64(x1.AuxInt)
			y := x1.Args[0]
			if !(clobberIfDead(x1)) {
				continue
			}
			v.reset(OpARM64CMNshiftRA)
			v.AuxInt = int64ToAuxInt(c)
			v.AddArg2(x0, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64CMNW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMNW x (MOVDconst [c]))
	// result: (CMNWconst [int32(c)] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARM64MOVDconst {
				continue
			}
			c := auxIntToInt64(v_1.AuxInt)
			v.reset(OpARM64CMNWconst)
			v.AuxInt = int32ToAuxInt(int32(c))
			v.AddArg(x)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64CMNWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMNWconst [c] y)
	// cond: c < 0 && c != -1<<31
	// result: (CMPWconst [-c] y)
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if !(c < 0 && c != -1<<31) {
			break
		}
		v.reset(OpARM64CMPWconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(y)
		return true
	}
	// match: (CMNWconst (MOVDconst [x]) [y])
	// result: (FlagConstant [addFlags32(int32(x),y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(addFlags32(int32(x), y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMNconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMNconst [c] y)
	// cond: c < 0 && c != -1<<63
	// result: (CMPconst [-c] y)
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if !(c < 0 && c != -1<<63) {
			break
		}
		v.reset(OpARM64CMPconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(y)
		return true
	}
	// match: (CMNconst (MOVDconst [x]) [y])
	// result: (FlagConstant [addFlags64(x,y)])
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(addFlags64(x, y))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMNshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftLL (MOVDconst [c]) x [d])
	// result: (CMNconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftLL x (MOVDconst [c]) [d])
	// result: (CMNconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMNshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRA (MOVDconst [c]) x [d])
	// result: (CMNconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRA x (MOVDconst [c]) [d])
	// result: (CMNconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMNshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRL (MOVDconst [c]) x [d])
	// result: (CMNconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v0.AuxInt = int64ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRL x (MOVDconst [c]) [d])
	// result: (CMNconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMP x (MOVDconst [c]))
	// result: (CMPconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMPconst)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMP (MOVDconst [c]) x)
	// result: (InvertFlags (CMPconst [c] x))
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMP y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMPshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64CMPshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (CMP x0:(SLLconst [c] y) x1)
	// cond: clobberIfDead(x0)
	// result: (InvertFlags (CMPshiftLL x1 y [c]))
	for {
		x0 := v_0
		if x0.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x0.AuxInt)
		y := x0.Args[0]
		x1 := v_1
		if !(clobberIfDead(x0)) {
			break
		}
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPshiftLL, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg2(x1, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMPshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64CMPshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (CMP x0:(SRLconst [c] y) x1)
	// cond: clobberIfDead(x0)
	// result: (InvertFlags (CMPshiftRL x1 y [c]))
	for {
		x0 := v_0
		if x0.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x0.AuxInt)
		y := x0.Args[0]
		x1 := v_1
		if !(clobberIfDead(x0)) {
			break
		}
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPshiftRL, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg2(x1, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (CMPshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64CMPshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (CMP x0:(SRAconst [c] y) x1)
	// cond: clobberIfDead(x0)
	// result: (InvertFlags (CMPshiftRA x1 y [c]))
	for {
		x0 := v_0
		if x0.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x0.AuxInt)
		y := x0.Args[0]
		x1 := v_1
		if !(clobberIfDead(x0)) {
			break
		}
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPshiftRA, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg2(x1, y)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPW x (MOVDconst [c]))
	// result: (CMPWconst [int32(c)] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMPWconst)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg(x)
		return true
	}
	// match: (CMPW (MOVDconst [c]) x)
	// result: (InvertFlags (CMPWconst [int32(c)] x))
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMPW x y)
	// cond: canonLessThan(x,y)
	// result: (InvertFlags (CMPW y x))
	for {
		x := v_0
		y := v_1
		if !(canonLessThan(x, y)) {
			break
		}
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPWconst [c] y)
	// cond: c < 0 && c != -1<<31
	// result: (CMNWconst [-c] y)
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if !(c < 0 && c != -1<<31) {
			break
		}
		v.reset(OpARM64CMNWconst)
		v.AuxInt = int32ToAuxInt(-c)
		v.AddArg(y)
		return true
	}
	// match: (CMPWconst (MOVDconst [x]) [y])
	// result: (FlagConstant [subFlags32(int32(x),y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(int32(x), y))
		return true
	}
	// match: (CMPWconst (MOVBUreg _) [c])
	// cond: 0xff < c
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	// match: (CMPWconst (MOVHUreg _) [c])
	// cond: 0xffff < c
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPconst [c] y)
	// cond: c < 0 && c != -1<<63
	// result: (CMNconst [-c] y)
	for {
		c := auxIntToInt64(v.AuxInt)
		y := v_0
		if !(c < 0 && c != -1<<63) {
			break
		}
		v.reset(OpARM64CMNconst)
		v.AuxInt = int64ToAuxInt(-c)
		v.AddArg(y)
		return true
	}
	// match: (CMPconst (MOVDconst [x]) [y])
	// result: (FlagConstant [subFlags64(x,y)])
	for {
		y := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		x := auxIntToInt64(v_0.AuxInt)
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(x, y))
		return true
	}
	// match: (CMPconst (MOVBUreg _) [c])
	// cond: 0xff < c
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	// match: (CMPconst (MOVHUreg _) [c])
	// cond: 0xffff < c
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	// match: (CMPconst (MOVWUreg _) [c])
	// cond: 0xffffffff < c
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVWUreg || !(0xffffffff < c) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	// match: (CMPconst (ANDconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		n := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64ANDconst {
			break
		}
		m := auxIntToInt64(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	// match: (CMPconst (SRLconst _ [c]) [n])
	// cond: 0 <= n && 0 < c && c <= 63 && (1<<uint64(64-c)) <= uint64(n)
	// result: (FlagConstant [subFlags64(0,1)])
	for {
		n := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if !(0 <= n && 0 < c && c <= 63 && (1<<uint64(64-c)) <= uint64(n)) {
			break
		}
		v.reset(OpARM64FlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags64(0, 1))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftLL (MOVDconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SLLconst <x.Type> x [d])))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARM64SLLconst, x.Type)
		v1.AuxInt = int64ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftLL x (MOVDconst [c]) [d])
	// result: (CMPconst x [int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMPconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRA (MOVDconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SRAconst <x.Type> x [d])))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARM64SRAconst, x.Type)
		v1.AuxInt = int64ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRA x (MOVDconst [c]) [d])
	// result: (CMPconst x [c>>uint64(d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMPconst)
		v.AuxInt = int64ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CMPshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRL (MOVDconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SRLconst <x.Type> x [d])))
	for {
		d := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64CMPconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARM64SRLconst, x.Type)
		v1.AuxInt = int64ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRL x (MOVDconst [c]) [d])
	// result: (CMPconst x [int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64CMPconst)
		v.AuxInt = int64ToAuxInt(int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSEL(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CSEL [cc] (MOVDconst [-1]) (MOVDconst [0]) flag)
	// result: (CSETM [cc] flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != -1 || v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		flag := v_2
		v.reset(OpARM64CSETM)
		v.AuxInt = opToAuxInt(cc)
		v.AddArg(flag)
		return true
	}
	// match: (CSEL [cc] (MOVDconst [0]) (MOVDconst [-1]) flag)
	// result: (CSETM [arm64Negate(cc)] flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0 || v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != -1 {
			break
		}
		flag := v_2
		v.reset(OpARM64CSETM)
		v.AuxInt = opToAuxInt(arm64Negate(cc))
		v.AddArg(flag)
		return true
	}
	// match: (CSEL [cc] x (MOVDconst [0]) flag)
	// result: (CSEL0 [cc] x flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst || auxIntToInt64(v_1.AuxInt) != 0 {
			break
		}
		flag := v_2
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(cc)
		v.AddArg2(x, flag)
		return true
	}
	// match: (CSEL [cc] (MOVDconst [0]) y flag)
	// result: (CSEL0 [arm64Negate(cc)] y flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64MOVDconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		y := v_1
		flag := v_2
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(arm64Negate(cc))
		v.AddArg2(y, flag)
		return true
	}
	// match: (CSEL [cc] x (ADDconst [1] a) flag)
	// result: (CSINC [cc] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64ADDconst || auxIntToInt64(v_1.AuxInt) != 1 {
			break
		}
		a := v_1.Args[0]
		flag := v_2
		v.reset(OpARM64CSINC)
		v.AuxInt = opToAuxInt(cc)
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] (ADDconst [1] a) x flag)
	// result: (CSINC [arm64Negate(cc)] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64ADDconst || auxIntToInt64(v_0.AuxInt) != 1 {
			break
		}
		a := v_0.Args[0]
		x := v_1
		flag := v_2
		v.reset(OpARM64CSINC)
		v.AuxInt = opToAuxInt(arm64Negate(cc))
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] x (MVN a) flag)
	// result: (CSINV [cc] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MVN {
			break
		}
		a := v_1.Args[0]
		flag := v_2
		v.reset(OpARM64CSINV)
		v.AuxInt = opToAuxInt(cc)
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] (MVN a) x flag)
	// result: (CSINV [arm64Negate(cc)] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64MVN {
			break
		}
		a := v_0.Args[0]
		x := v_1
		flag := v_2
		v.reset(OpARM64CSINV)
		v.AuxInt = opToAuxInt(arm64Negate(cc))
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] x (NEG a) flag)
	// result: (CSNEG [cc] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64NEG {
			break
		}
		a := v_1.Args[0]
		flag := v_2
		v.reset(OpARM64CSNEG)
		v.AuxInt = opToAuxInt(cc)
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] (NEG a) x flag)
	// result: (CSNEG [arm64Negate(cc)] x a flag)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64NEG {
			break
		}
		a := v_0.Args[0]
		x := v_1
		flag := v_2
		v.reset(OpARM64CSNEG)
		v.AuxInt = opToAuxInt(arm64Negate(cc))
		v.AddArg3(x, a, flag)
		return true
	}
	// match: (CSEL [cc] x y (InvertFlags cmp))
	// result: (CSEL [arm64Invert(cc)] x y cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_2.Args[0]
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CSEL [cc] x _ flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: x
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		flag := v_2
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CSEL [cc] _ y flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: y
	for {
		cc := auxIntToOp(v.AuxInt)
		y := v_1
		flag := v_2
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.copyOf(y)
		return true
	}
	// match: (CSEL [cc] x y (CMPWconst [0] boolval))
	// cond: cc == OpARM64NotEqual && flagArg(boolval) != nil
	// result: (CSEL [boolval.Op] x y flagArg(boolval))
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64CMPWconst || auxIntToInt32(v_2.AuxInt) != 0 {
			break
		}
		boolval := v_2.Args[0]
		if !(cc == OpARM64NotEqual && flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(boolval.Op)
		v.AddArg3(x, y, flagArg(boolval))
		return true
	}
	// match: (CSEL [cc] x y (CMPWconst [0] boolval))
	// cond: cc == OpARM64Equal && flagArg(boolval) != nil
	// result: (CSEL [arm64Negate(boolval.Op)] x y flagArg(boolval))
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64CMPWconst || auxIntToInt32(v_2.AuxInt) != 0 {
			break
		}
		boolval := v_2.Args[0]
		if !(cc == OpARM64Equal && flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL)
		v.AuxInt = opToAuxInt(arm64Negate(boolval.Op))
		v.AddArg3(x, y, flagArg(boolval))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSEL0(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CSEL0 [cc] x (InvertFlags cmp))
	// result: (CSEL0 [arm64Invert(cc)] x cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_1.Args[0]
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg2(x, cmp)
		return true
	}
	// match: (CSEL0 [cc] x flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: x
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		flag := v_1
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CSEL0 [cc] _ flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: (MOVDconst [0])
	for {
		cc := auxIntToOp(v.AuxInt)
		flag := v_1
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	// match: (CSEL0 [cc] x (CMPWconst [0] boolval))
	// cond: cc == OpARM64NotEqual && flagArg(boolval) != nil
	// result: (CSEL0 [boolval.Op] x flagArg(boolval))
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64CMPWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		boolval := v_1.Args[0]
		if !(cc == OpARM64NotEqual && flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(boolval.Op)
		v.AddArg2(x, flagArg(boolval))
		return true
	}
	// match: (CSEL0 [cc] x (CMPWconst [0] boolval))
	// cond: cc == OpARM64Equal && flagArg(boolval) != nil
	// result: (CSEL0 [arm64Negate(boolval.Op)] x flagArg(boolval))
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64CMPWconst || auxIntToInt32(v_1.AuxInt) != 0 {
			break
		}
		boolval := v_1.Args[0]
		if !(cc == OpARM64Equal && flagArg(boolval) != nil) {
			break
		}
		v.reset(OpARM64CSEL0)
		v.AuxInt = opToAuxInt(arm64Negate(boolval.Op))
		v.AddArg2(x, flagArg(boolval))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSETM(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CSETM [cc] (InvertFlags cmp))
	// result: (CSETM [arm64Invert(cc)] cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_0.Args[0]
		v.reset(OpARM64CSETM)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg(cmp)
		return true
	}
	// match: (CSETM [cc] flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: (MOVDconst [-1])
	for {
		cc := auxIntToOp(v.AuxInt)
		flag := v_0
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (CSETM [cc] flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: (MOVDconst [0])
	for {
		cc := auxIntToOp(v.AuxInt)
		flag := v_0
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSINC(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CSINC [cc] x y (InvertFlags cmp))
	// result: (CSINC [arm64Invert(cc)] x y cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_2.Args[0]
		v.reset(OpARM64CSINC)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CSINC [cc] x _ flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: x
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		flag := v_2
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CSINC [cc] _ y flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: (ADDconst [1] y)
	for {
		cc := auxIntToOp(v.AuxInt)
		y := v_1
		flag := v_2
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.reset(OpARM64ADDconst)
		v.AuxInt = int64ToAuxInt(1)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSINV(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CSINV [cc] x y (InvertFlags cmp))
	// result: (CSINV [arm64Invert(cc)] x y cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_2.Args[0]
		v.reset(OpARM64CSINV)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CSINV [cc] x _ flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: x
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		flag := v_2
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CSINV [cc] _ y flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: (Not y)
	for {
		cc := auxIntToOp(v.AuxInt)
		y := v_1
		flag := v_2
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.reset(OpNot)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64CSNEG(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CSNEG [cc] x y (InvertFlags cmp))
	// result: (CSNEG [arm64Invert(cc)] x y cmp)
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		y := v_1
		if v_2.Op != OpARM64InvertFlags {
			break
		}
		cmp := v_2.Args[0]
		v.reset(OpARM64CSNEG)
		v.AuxInt = opToAuxInt(arm64Invert(cc))
		v.AddArg3(x, y, cmp)
		return true
	}
	// match: (CSNEG [cc] x _ flag)
	// cond: ccARM64Eval(cc, flag) > 0
	// result: x
	for {
		cc := auxIntToOp(v.AuxInt)
		x := v_0
		flag := v_2
		if !(ccARM64Eval(cc, flag) > 0) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CSNEG [cc] _ y flag)
	// cond: ccARM64Eval(cc, flag) < 0
	// result: (NEG y)
	for {
		cc := auxIntToOp(v.AuxInt)
		y := v_1
		flag := v_2
		if !(ccARM64Eval(cc, flag) < 0) {
			break
		}
		v.reset(OpARM64NEG)
		v.AddArg(y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64DIV(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIV (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [c/d])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(c / d)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64DIVW(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (DIVW (MOVDconst [c]) (MOVDconst [d]))
	// cond: d != 0
	// result: (MOVDconst [int64(uint32(int32(c)/int32(d)))])
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		d := auxIntToInt64(v_1.AuxInt)
		if !(d != 0) {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(int64(uint32(int32(c) / int32(d))))
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64EON(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EON x (MOVDconst [c]))
	// result: (XORconst [^c] x)
	for {
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(^c)
		v.AddArg(x)
		return true
	}
	// match: (EON x x)
	// result: (MOVDconst [-1])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	// match: (EON x0 x1:(SLLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (EONshiftLL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SLLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64EONshiftLL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (EON x0 x1:(SRLconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (EONshiftRL x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRLconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64EONshiftRL)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (EON x0 x1:(SRAconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (EONshiftRA x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64SRAconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64EONshiftRA)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	// match: (EON x0 x1:(RORconst [c] y))
	// cond: clobberIfDead(x1)
	// result: (EONshiftRO x0 y [c])
	for {
		x0 := v_0
		x1 := v_1
		if x1.Op != OpARM64RORconst {
			break
		}
		c := auxIntToInt64(x1.AuxInt)
		y := x1.Args[0]
		if !(clobberIfDead(x1)) {
			break
		}
		v.reset(OpARM64EONshiftRO)
		v.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x0, y)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64EONshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EONshiftLL x (MOVDconst [c]) [d])
	// result: (XORconst x [^int64(uint64(c)<<uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) << uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (EONshiftLL (SLLconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64EONshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EONshiftRA x (MOVDconst [c]) [d])
	// result: (XORconst x [^(c>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(^(c >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (EONshiftRA (SRAconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRAconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64EONshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EONshiftRL x (MOVDconst [c]) [d])
	// result: (XORconst x [^int64(uint64(c)>>uint64(d))])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(^int64(uint64(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (EONshiftRL (SRLconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64SRLconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64EONshiftRO(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (EONshiftRO x (MOVDconst [c]) [d])
	// result: (XORconst x [^rotateRight64(c, d)])
	for {
		d := auxIntToInt64(v.AuxInt)
		x := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		v.reset(OpARM64XORconst)
		v.AuxInt = int64ToAuxInt(^rotateRight64(c, d))
		v.AddArg(x)
		return true
	}
	// match: (EONshiftRO (RORconst x [c]) x [c])
	// result: (MOVDconst [-1])
	for {
		c := auxIntToInt64(v.AuxInt)
		if v_0.Op != OpARM64RORconst || auxIntToInt64(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(-1)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64Equal(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (Equal (CMPconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (Equal (TST x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64TST, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (Equal (TSTWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64TSTWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] z:(AND x y)))
	// cond: z.Uses == 1
	// result: (Equal (TSTW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64AND {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64TSTW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPconst [0] x:(ANDconst [c] y)))
	// cond: x.Uses == 1
	// result: (Equal (TSTconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ANDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64TSTconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMP x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (Equal (CMN x y))
	for {
		if v_0.Op != OpARM64CMP {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		z := v_0.Args[1]
		if z.Op != OpARM64NEG {
			break
		}
		y := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPW x z:(NEG y)))
	// cond: z.Uses == 1
	// result: (Equal (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPW {
			break
		}
		_ = v_0.Args[1]
		x := v_0.Args[0]
		z := v_0.Args[1]
		if z.Op != OpARM64NEG {
			break
		}
		y := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (Equal (CMNconst [c] y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMNconst, types.TypeFlags)
		v0.AuxInt = int64ToAuxInt(c)
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] x:(ADDconst [c] y)))
	// cond: x.Uses == 1
	// result: (Equal (CMNWconst [int32(c)] y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		x := v_0.Args[0]
		if x.Op != OpARM64ADDconst {
			break
		}
		c := auxIntToInt64(x.AuxInt)
		y := x.Args[0]
		if !(x.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMNWconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(int32(c))
		v0.AddArg(y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMN x y))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] z:(ADD x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMNW x y))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64ADD {
			break
		}
		y := z.Args[1]
		x := z.Args[0]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPconst [0] z:(MADD a x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMN a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADD {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMN, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPconst [0] z:(MSUB a x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMP a (MUL <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPconst || auxIntToInt64(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUB {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMP, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MUL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] z:(MADDW a x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMNW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MADDW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMNW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (CMPWconst [0] z:(MSUBW a x y)))
	// cond: z.Uses == 1
	// result: (Equal (CMPW a (MULW <x.Type> x y)))
	for {
		if v_0.Op != OpARM64CMPWconst || auxIntToInt32(v_0.AuxInt) != 0 {
			break
		}
		z := v_0.Args[0]
		if z.Op != OpARM64MSUBW {
			break
		}
		y := z.Args[2]
		a := z.Args[0]
		x := z.Args[1]
		if !(z.Uses == 1) {
			break
		}
		v.reset(OpARM64Equal)
		v0 := b.NewValue0(v.Pos, OpARM64CMPW, types.TypeFlags)
		v1 := b.NewValue0(v.Pos, OpARM64MULW, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg2(a, v1)
		v.AddArg(v0)
		return true
	}
	// match: (Equal (FlagConstant [fc]))
	// result: (MOVDconst [b2i(fc.eq())])
	for {
		if v_0.Op != OpARM64FlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARM64MOVDconst)
		v.AuxInt = int64ToAuxInt(b2i(fc.eq()))
		return true
	}
	// match: (Equal (InvertFlags x))
	// result: (Equal x)
	for {
		if v_0.Op != OpARM64InvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARM64Equal)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FADDD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADDD a (FMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDD a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARM64FMULD {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpARM64FMADDD)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	// match: (FADDD a (FNMULD x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBD a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARM64FNMULD {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpARM64FMSUBD)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FADDS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FADDS a (FMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMADDS a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARM64FMULS {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpARM64FMADDS)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	// match: (FADDS a (FNMULS x y))
	// cond: a.Block.Func.useFMA(v)
	// result: (FMSUBS a x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			a := v_0
			if v_1.Op != OpARM64FNMULS {
				continue
			}
			y := v_1.Args[1]
			x := v_1.Args[0]
			if !(a.Block.Func.useFMA(v)) {
				continue
			}
			v.reset(OpARM64FMSUBS)
			v.AddArg3(a, x, y)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM64_OpARM64FCMPD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (FCMPD x (FMOVDconst [0]))
	// result: (FCMPD0 x)
	for {
		x := v_0
		if v_1.Op != OpARM64FMOVDconst || auxIntToFloat64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpARM64FCMPD0)
		v.AddArg(x)
		return true
	}
	// match: (FCMPD (FMOVDconst [0]) x)
	// result: (InvertFlags (FCMPD0 x))
	for {
		if v_0.Op != OpARM64FMOVDconst || auxIntToFloat64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPD0, types.TypeFlags)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FCMPS(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (FCMPS x (FMOVSconst [0]))
	// result: (FCMPS0 x)
	for {
		x := v_0
		if v_1.Op != OpARM64FMOVSconst || auxIntToFloat64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpARM64FCMPS0)
		v.AddArg(x)
		return true
	}
	// match: (FCMPS (FMOVSconst [0]) x)
	// result: (InvertFlags (FCMPS0 x))
	for {
		if v_0.Op != OpARM64FMOVSconst || auxIntToFloat64(v_0.AuxInt) != 0 {
			break
		}
		x := v_1
		v.reset(OpARM64InvertFlags)
		v0 := b.NewValue0(v.Pos, OpARM64FCMPS0, types.TypeFlags)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDfpgp(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (FMOVDfpgp <t> (Arg [off] {sym}))
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDgpfp(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	// match: (FMOVDgpfp <t> (Arg [off] {sym}))
	// result: @b.Func.Entry (Arg <t> [off] {sym})
	for {
		t := v.Type
		if v_0.Op != OpArg {
			break
		}
		off := auxIntToInt32(v_0.AuxInt)
		sym := auxToSym(v_0.Aux)
		b = b.Func.Entry
		v0 := b.NewValue0(v.Pos, OpArg, t)
		v.copyOf(v0)
		v0.AuxInt = int32ToAuxInt(off)
		v0.Aux = symToAux(sym)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (FMOVDload [off] {sym} ptr (MOVDstore [off] {sym} ptr val _))
	// result: (FMOVDgpfp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVDstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpARM64FMOVDgpfp)
		v.AddArg(val)
		return true
	}
	// match: (FMOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVDload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVDload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVDloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVDloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVDload [off] {sym} (ADDshiftLL [3] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVDloadidx8 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVDload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVDload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (FMOVDload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVDloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (FMOVDload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVDloadidx ptr (SLLconst [3] idx) mem)
	// result: (FMOVDloadidx8 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 3 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64FMOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVDloadidx (SLLconst [3] idx) ptr mem)
	// result: (FMOVDloadidx8 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64FMOVDloadidx8)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDloadidx8(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDloadidx8 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<3)
	// result: (FMOVDload ptr [int32(c)<<3] mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 3)) {
			break
		}
		v.reset(OpARM64FMOVDload)
		v.AuxInt = int32ToAuxInt(int32(c) << 3)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (FMOVDstore [off] {sym} ptr (FMOVDgpfp val) mem)
	// result: (MOVDstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVDgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVDstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVDstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVDstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVDstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVDstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVDstore [off] {sym} (ADDshiftLL [3] ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVDstoreidx8 ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVDstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVDstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (FMOVDstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVDstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (FMOVDstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (FMOVDstoreidx ptr (SLLconst [3] idx) val mem)
	// result: (FMOVDstoreidx8 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 3 {
			break
		}
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARM64FMOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVDstoreidx (SLLconst [3] idx) ptr val mem)
	// result: (FMOVDstoreidx8 ptr idx val mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 3 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64FMOVDstoreidx8)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVDstoreidx8(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVDstoreidx8 ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c<<3)
	// result: (FMOVDstore [int32(c)<<3] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c << 3)) {
			break
		}
		v.reset(OpARM64FMOVDstore)
		v.AuxInt = int32ToAuxInt(int32(c) << 3)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (FMOVSload [off] {sym} ptr (MOVWstore [off] {sym} ptr val _))
	// result: (FMOVSgpfp val)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64MOVWstore || auxIntToInt32(v_1.AuxInt) != off || auxToSym(v_1.Aux) != sym {
			break
		}
		val := v_1.Args[1]
		if ptr != v_1.Args[0] {
			break
		}
		v.reset(OpARM64FMOVSgpfp)
		v.AddArg(val)
		return true
	}
	// match: (FMOVSload [off1] {sym} (ADDconst [off2] ptr) mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVSload [off1+int32(off2)] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVSload [off] {sym} (ADD ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVSloadidx ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVSloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVSload [off] {sym} (ADDshiftLL [2] ptr idx) mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVSloadidx4 ptr idx mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVSloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVSload [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVSload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSloadidx ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c)
	// result: (FMOVSload [int32(c)] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVSloadidx (MOVDconst [c]) ptr mem)
	// cond: is32Bit(c)
	// result: (FMOVSload [int32(c)] ptr mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (FMOVSloadidx ptr (SLLconst [2] idx) mem)
	// result: (FMOVSloadidx4 ptr idx mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64FMOVSloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (FMOVSloadidx (SLLconst [2] idx) ptr mem)
	// result: (FMOVSloadidx4 ptr idx mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		mem := v_2
		v.reset(OpARM64FMOVSloadidx4)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSloadidx4(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSloadidx4 ptr (MOVDconst [c]) mem)
	// cond: is32Bit(c<<2)
	// result: (FMOVSload ptr [int32(c)<<2] mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		mem := v_2
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64FMOVSload)
		v.AuxInt = int32ToAuxInt(int32(c) << 2)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (FMOVSstore [off] {sym} ptr (FMOVSgpfp val) mem)
	// result: (MOVWstore [off] {sym} ptr val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARM64FMOVSgpfp {
			break
		}
		val := v_1.Args[0]
		mem := v_2
		v.reset(OpARM64MOVWstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVSstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// cond: is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVSstore [off1+int32(off2)] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDconst {
			break
		}
		off2 := auxIntToInt64(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(is32Bit(int64(off1)+off2) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + int32(off2))
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVSstore [off] {sym} (ADD ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVSstoreidx ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVSstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVSstore [off] {sym} (ADDshiftLL [2] ptr idx) val mem)
	// cond: off == 0 && sym == nil
	// result: (FMOVSstoreidx4 ptr idx val mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARM64ADDshiftLL || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(off == 0 && sym == nil) {
			break
		}
		v.reset(OpARM64FMOVSstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVSstore [off1] {sym1} (MOVDaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)
	// result: (FMOVSstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARM64MOVDaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2) && is32Bit(int64(off1)+int64(off2)) && (ptr.Op != OpSB || !config.ctxt.Flag_dynlink)) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSstoreidx ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c)
	// result: (FMOVSstore [int32(c)] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (FMOVSstoreidx (MOVDconst [c]) idx val mem)
	// cond: is32Bit(c)
	// result: (FMOVSstore [int32(c)] idx val mem)
	for {
		if v_0.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_0.AuxInt)
		idx := v_1
		val := v_2
		mem := v_3
		if !(is32Bit(c)) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(int32(c))
		v.AddArg3(idx, val, mem)
		return true
	}
	// match: (FMOVSstoreidx ptr (SLLconst [2] idx) val mem)
	// result: (FMOVSstoreidx4 ptr idx val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64SLLconst || auxIntToInt64(v_1.AuxInt) != 2 {
			break
		}
		idx := v_1.Args[0]
		val := v_2
		mem := v_3
		v.reset(OpARM64FMOVSstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	// match: (FMOVSstoreidx (SLLconst [2] idx) ptr val mem)
	// result: (FMOVSstoreidx4 ptr idx val mem)
	for {
		if v_0.Op != OpARM64SLLconst || auxIntToInt64(v_0.AuxInt) != 2 {
			break
		}
		idx := v_0.Args[0]
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARM64FMOVSstoreidx4)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMOVSstoreidx4(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMOVSstoreidx4 ptr (MOVDconst [c]) val mem)
	// cond: is32Bit(c<<2)
	// result: (FMOVSstore [int32(c)<<2] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARM64MOVDconst {
			break
		}
		c := auxIntToInt64(v_1.AuxInt)
		val := v_2
		mem := v_3
		if !(is32Bit(c << 2)) {
			break
		}
		v.reset(OpARM64FMOVSstore)
		v.AuxInt = int32ToAuxInt(int32(c) << 2)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM64_OpARM64FMULD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (FMULD (FNEGD x) y)
	// result: (FNMULD x y)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			if v_0.Op != OpARM64FNEGD {
				continue
			}
			x := 
"""




```