Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the provided Go code snippet, specifically its functionality within the Go compiler. It also asks for a Go code example illustrating the functionality, clarification on command-line arguments (if any), and potential pitfalls for users.

2. **Initial Code Analysis:** I see a Go file located in the `go/src/cmd/compile/internal/ssa` directory, named `rewriteARM64latelower.go`. The file starts with a `// Code generated` comment, strongly suggesting it's automatically generated, likely from a set of rules. The `package ssa` declaration tells me it's part of the SSA (Static Single Assignment) intermediate representation used in the Go compiler.

3. **Function `rewriteValueARM64latelower`:** This function is a switch statement on `v.Op`, where `v` is a `*Value`. This immediately tells me it's about rewriting or transforming SSA values based on their operation (`Op`). The "latelower" part of the filename and function name suggests this happens relatively late in the compilation pipeline, likely just before or during the lowering of the SSA representation to machine code. The function returns a boolean, indicating whether a rewrite occurred.

4. **Individual `rewriteValueARM64latelower_Op*` Functions:**  Each `case` in the switch corresponds to a specific ARM64 instruction (e.g., `OpARM64ADDSconstflags`, `OpARM64ADDconst`). The corresponding functions (e.g., `rewriteValueARM64latelower_OpARM64ADDSconstflags`) implement the rewrite logic for that specific instruction.

5. **Rewrite Logic Pattern:** I observe a recurring pattern in these individual functions:
    * They take a `*Value` as input.
    * They often extract arguments from the `Value` (e.g., `v_0 := v.Args[0]`, `c := auxIntToInt64(v.AuxInt)`).
    * They have a `// match:` comment describing the pattern they're looking for in the SSA.
    * They have a `// cond:` comment specifying a condition that must be true for the rewrite to happen. These conditions often involve functions like `isARM64addcon` or `isARM64bitcon`, which likely check if a constant value can be directly encoded within the instruction.
    * They have a `// result:` comment showing how the SSA value is rewritten. This often involves creating new `Value`s with different opcodes (e.g., replacing `ADDSconstflags [c] x` with `ADDSflags x (MOVDconst [c])`).

6. **Inference of Functionality:** Based on the patterns, I deduce that this code performs *constant materialization* and *instruction selection* optimizations specific to the ARM64 architecture. When an arithmetic or logical operation is performed with a constant that cannot be directly encoded as an immediate operand in the instruction, the rewrite rule transforms it into an operation with a register loaded with that constant. The `MOVDconst` operation creates a "move doubleword constant" instruction to load the constant into a register.

7. **Go Code Example:** To illustrate this, I pick a simple case like `OpARM64ADDconst`. I create a Go function that performs an addition with a constant. Then, I imagine what the SSA might look like *before* the rewrite (using `ADDconst`) and *after* the rewrite (using `ADD` and `MOVDconst`). This leads to the example provided in the answer.

8. **Command-Line Arguments:** Since this code operates within the Go compiler's internal SSA representation, it doesn't directly interact with command-line arguments. The compiler itself takes command-line arguments, but this specific file is part of the compilation process.

9. **Potential Pitfalls:**  As this is generated code and part of the compiler's internals, end-users don't directly interact with it. The main potential pitfall for *developers working on the Go compiler* would be to manually edit this generated file, which is explicitly discouraged by the `// DO NOT EDIT` comment. Incorrectly defining the `isARM64addcon` or `isARM64bitcon` functions, or introducing errors in the rewrite rules themselves, could lead to incorrect code generation.

10. **Refine and Structure:** Finally, I organize the information into a clear and structured answer, addressing each part of the request. I start with a summary of the functionality, then provide the Go code example with explanations of the "before" and "after" SSA, clarify the lack of command-line arguments, and discuss the potential pitfalls for compiler developers. I make sure to explain the core concept of constant materialization in this context.
这段代码是 Go 语言编译器的一部分，位于 `go/src/cmd/compile/internal/ssa/rewriteARM64latelower.go` 文件中。它的主要功能是在编译过程的后期阶段，对 ARM64 架构的 SSA（Static Single Assignment）中间表示进行重写和优化。

**具体功能分解：**

1. **`rewriteValueARM64latelower(v *Value) bool` 函数:**
   - 这是一个核心的调度函数。它接收一个 `ssa.Value` 类型的指针 `v` 作为输入，该指针代表 SSA 图中的一个操作。
   - 它通过 `switch v.Op` 判断当前操作 `v` 的具体类型（例如 `OpARM64ADDconst`，`OpARM64MOVBUreg` 等）。
   - 针对每一种 `Op` 类型，它会调用相应的 `rewriteValueARM64latelower_Op*` 函数进行更细致的重写处理。
   - 函数返回一个布尔值，指示是否对 `v` 进行了重写。

2. **`rewriteValueARM64latelower_Op*(v *Value) bool` 函数 (例如 `rewriteValueARM64latelower_OpARM64ADDSconstflags`)**:
   - 这些函数针对特定的 ARM64 指令操作进行优化。
   - 它们通常会检查操作数的某些特性（例如，是否是常量，常量的值是否在特定范围内）。
   - 如果满足特定的条件（通过 `// cond:` 注释描述），它们会将当前的操作 `v` 重写为更高效或更符合目标架构指令特性的操作。
   - 重写的过程通常涉及到修改 `v` 的操作码 (`v.reset()`)，并修改或添加其操作数 (`v.AddArg()`, `v.AddArg2()`).

**推理其实现的 Go 语言功能：**

这段代码主要在进行 **指令选择** 和 **常量优化**，特别是针对 ARM64 架构的特性。  它试图将一些通用的操作或带有常量的操作，转换为更底层的、更适合 ARM64 硬件执行的指令序列。

**Go 代码举例说明：**

假设有以下 Go 代码：

```go
package main

func addConst(a int64) int64 {
	return a + 1000
}
```

在编译这个函数时，`a + 1000` 这个操作会被转换成 SSA 的一个节点，其操作码可能是 `OpARM64ADDconst`，操作数是 `a` 和常量 `1000`。

`rewriteValueARM64latelower_OpARM64ADDconst` 函数的代码如下：

```go
func rewriteValueARM64latelower_OpARM64ADDconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDconst [c] x)
	// cond: !isARM64addcon(c)
	// result: (ADD x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
```

**假设输入 SSA：**

一个 `ssa.Value` `v` 代表 `a + 1000`，其属性可能如下：

- `v.Op`: `OpARM64ADDconst`
- `v.AuxInt`: 表示常量 `1000` 的某种内部表示
- `v.Args[0]`: 代表变量 `a` 的 `ssa.Value`

**推理过程：**

- `auxIntToInt64(v.AuxInt)` 会将 `v.AuxInt` 转换为 `int64` 类型的常量值 `c`，这里 `c` 就是 `1000`。
- `isARM64addcon(c)` 是一个辅助函数，用于判断常量 `c` 是否可以直接作为 ARM64 `ADD` 指令的立即数。
- 如果 `!isARM64addcon(c)` 为真（即 `1000` 不能直接作为立即数），则执行重写。
- `v.reset(OpARM64ADD)` 将 `v` 的操作码改为 `OpARM64ADD`。
- `b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)` 创建一个新的 `ssa.Value` `v0`，其操作码是 `OpARM64MOVDconst`，用于将常量 `c` 加载到寄存器中。
- `v0.AuxInt = int64ToAuxInt(c)` 设置 `v0` 的常量值为 `1000`。
- `v.AddArg2(x, v0)` 将 `v` 的操作数改为 `x`（代表 `a`）和 `v0`（代表加载了常量 `1000` 的寄存器）。

**假设输出 SSA：**

重写后的 `v` 的属性可能如下：

- `v.Op`: `OpARM64ADD`
- `v.Args[0]`: 代表变量 `a` 的 `ssa.Value`
- `v.Args[1]`: 一个新的 `ssa.Value`，其 `Op` 是 `OpARM64MOVDconst`，`AuxInt` 代表常量 `1000`。

**对应的汇编代码（可能）：**

```assembly
// 假设 R0 寄存器存储了变量 a 的值
MOV  R1, #1000  // 将常量 1000 加载到 R1 寄存器
ADD  R0, R0, R1  // 将 R0 和 R1 的值相加，结果存回 R0
```

**涉及的代码推理：**

- **`isARM64addcon(c)`:**  这是一个关键的假设。它代表一个函数，用于判断一个常量是否可以作为 ARM64 `ADD` 指令的立即数。ARM64 的立即数有特定的编码规则，不是任意 64 位整数都能直接作为立即数。
- **`isARM64bitcon(uint64(c))`:** 类似地，这个函数判断一个常量是否可以作为位运算指令（如 `AND`, `OR`, `XOR`）的立即数。
- **`zeroUpper32Bits(x, 3)`:** 这个函数可能用于检查一个值的上 32 位是否为零，这在处理 32 位无符号数扩展到 64 位时可能用到。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它属于 Go 语言编译器的内部实现，在编译过程中被调用。Go 编译器的命令行参数（如 `-gcflags`，`-ldflags` 等）会影响整个编译流程，但不会直接传递到这个特定的重写阶段。

**使用者易犯错的点：**

由于这段代码是编译器内部生成的，并且是编译过程的一部分，**Go 语言开发者通常不会直接与这段代码交互，因此不存在使用者易犯错的点**。

然而，对于 **Go 编译器开发者** 来说，理解这些重写规则非常重要，因为：

- **错误的条件判断 (`// cond:`)** 可能导致不正确的代码生成。
- **错误的重写逻辑 (`// result:`)** 可能引入 bug。
- **不了解 ARM64 指令集的特性** 可能会导致低效的优化。

例如，如果 `isARM64addcon` 的实现有误，可能会导致本来可以作为立即数的常量被错误地加载到寄存器，增加指令数量。

总而言之，`rewriteARM64latelower.go` 是 Go 编译器针对 ARM64 架构进行底层优化的重要组成部分，它通过模式匹配和条件判断，将 SSA 中间表示转换为更贴合目标硬件的指令序列，从而提高生成代码的效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM64latelower.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Code generated from _gen/ARM64latelower.rules using 'go generate'; DO NOT EDIT.

package ssa

func rewriteValueARM64latelower(v *Value) bool {
	switch v.Op {
	case OpARM64ADDSconstflags:
		return rewriteValueARM64latelower_OpARM64ADDSconstflags(v)
	case OpARM64ADDconst:
		return rewriteValueARM64latelower_OpARM64ADDconst(v)
	case OpARM64ANDconst:
		return rewriteValueARM64latelower_OpARM64ANDconst(v)
	case OpARM64CMNWconst:
		return rewriteValueARM64latelower_OpARM64CMNWconst(v)
	case OpARM64CMNconst:
		return rewriteValueARM64latelower_OpARM64CMNconst(v)
	case OpARM64CMPWconst:
		return rewriteValueARM64latelower_OpARM64CMPWconst(v)
	case OpARM64CMPconst:
		return rewriteValueARM64latelower_OpARM64CMPconst(v)
	case OpARM64MOVBUreg:
		return rewriteValueARM64latelower_OpARM64MOVBUreg(v)
	case OpARM64MOVBreg:
		return rewriteValueARM64latelower_OpARM64MOVBreg(v)
	case OpARM64MOVHUreg:
		return rewriteValueARM64latelower_OpARM64MOVHUreg(v)
	case OpARM64MOVHreg:
		return rewriteValueARM64latelower_OpARM64MOVHreg(v)
	case OpARM64MOVWUreg:
		return rewriteValueARM64latelower_OpARM64MOVWUreg(v)
	case OpARM64MOVWreg:
		return rewriteValueARM64latelower_OpARM64MOVWreg(v)
	case OpARM64ORconst:
		return rewriteValueARM64latelower_OpARM64ORconst(v)
	case OpARM64SUBconst:
		return rewriteValueARM64latelower_OpARM64SUBconst(v)
	case OpARM64TSTWconst:
		return rewriteValueARM64latelower_OpARM64TSTWconst(v)
	case OpARM64TSTconst:
		return rewriteValueARM64latelower_OpARM64TSTconst(v)
	case OpARM64XORconst:
		return rewriteValueARM64latelower_OpARM64XORconst(v)
	}
	return false
}
func rewriteValueARM64latelower_OpARM64ADDSconstflags(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDSconstflags [c] x)
	// cond: !isARM64addcon(c)
	// result: (ADDSflags x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64ADDSflags)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64ADDconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ADDconst [c] x)
	// cond: !isARM64addcon(c)
	// result: (ADD x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64ADD)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64ANDconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ANDconst [c] x)
	// cond: !isARM64bitcon(uint64(c))
	// result: (AND x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64bitcon(uint64(c))) {
			break
		}
		v.reset(OpARM64AND)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64CMNWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMNWconst [c] x)
	// cond: !isARM64addcon(int64(c))
	// result: (CMNW x (MOVDconst [int64(c)]))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(int64(c))) {
			break
		}
		v.reset(OpARM64CMNW)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(c))
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64CMNconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMNconst [c] x)
	// cond: !isARM64addcon(c)
	// result: (CMN x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64CMN)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64CMPWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPWconst [c] x)
	// cond: !isARM64addcon(int64(c))
	// result: (CMPW x (MOVDconst [int64(c)]))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(int64(c))) {
			break
		}
		v.reset(OpARM64CMPW)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(c))
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64CMPconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (CMPconst [c] x)
	// cond: !isARM64addcon(c)
	// result: (CMP x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64CMP)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg x:(Equal _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64Equal {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(NotEqual _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64NotEqual {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessThan _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessThan {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessThanU _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessThanU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessThanF _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessThanF {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessEqual _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessEqual {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessEqualU _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessEqualU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(LessEqualF _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64LessEqualF {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterThan _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterThan {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterThanU _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterThanU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterThanF _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterThanF {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterEqual _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterEqual {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterEqualU _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterEqualU {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(GreaterEqualF _))
	// result: x
	for {
		x := v_0
		if x.Op != OpARM64GreaterEqualF {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUloadidx2 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx2 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVHreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHloadidx2 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHloadidx2 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHreg x:(MOVHreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVWUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWUreg x)
	// cond: zeroUpper32Bits(x, 3)
	// result: x
	for {
		x := v_0
		if !(zeroUpper32Bits(x, 3)) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUloadidx2 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx2 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUloadidx4 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWUloadidx4 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVHUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWUreg x:(MOVWUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64MOVWreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVWreg x:(MOVBload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWload _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWload {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWloadidx _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWloadidx {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHloadidx2 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHloadidx2 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHUloadidx2 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHUloadidx2 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWloadidx4 _ _ _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWloadidx4 {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVBUreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVBUreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVHreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVHreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVWreg x:(MOVWreg _))
	// result: (MOVDreg x)
	for {
		x := v_0
		if x.Op != OpARM64MOVWreg {
			break
		}
		v.reset(OpARM64MOVDreg)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64ORconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (ORconst [c] x)
	// cond: !isARM64bitcon(uint64(c))
	// result: (OR x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64bitcon(uint64(c))) {
			break
		}
		v.reset(OpARM64OR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64SUBconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (SUBconst [c] x)
	// cond: !isARM64addcon(c)
	// result: (SUB x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64addcon(c)) {
			break
		}
		v.reset(OpARM64SUB)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64TSTWconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (TSTWconst [c] x)
	// cond: !isARM64bitcon(uint64(c)|uint64(c)<<32)
	// result: (TSTW x (MOVDconst [int64(c)]))
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARM64bitcon(uint64(c) | uint64(c)<<32)) {
			break
		}
		v.reset(OpARM64TSTW)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(int64(c))
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64TSTconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (TSTconst [c] x)
	// cond: !isARM64bitcon(uint64(c))
	// result: (TST x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64bitcon(uint64(c))) {
			break
		}
		v.reset(OpARM64TST)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteValueARM64latelower_OpARM64XORconst(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (XORconst [c] x)
	// cond: !isARM64bitcon(uint64(c))
	// result: (XOR x (MOVDconst [c]))
	for {
		c := auxIntToInt64(v.AuxInt)
		x := v_0
		if !(!isARM64bitcon(uint64(c))) {
			break
		}
		v.reset(OpARM64XOR)
		v0 := b.NewValue0(v.Pos, OpARM64MOVDconst, typ.UInt64)
		v0.AuxInt = int64ToAuxInt(c)
		v.AddArg2(x, v0)
		return true
	}
	return false
}
func rewriteBlockARM64latelower(b *Block) bool {
	return false
}
```