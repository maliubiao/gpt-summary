Response:
这是对Go语言编译器中用于MIPS架构的SSA（Static Single Assignment）形式进行重写的代码。这个代码文件的主要功能是定义了一系列的重写规则，用于优化MIPS架构下的特定操作。

**功能概览**

这个代码片段主要包含两个函数：`rewriteValueMIPS` 和 `rewriteBlockMIPS`。

*   **`rewriteValueMIPS(v *Value)`**:  这个函数接收一个SSA Value类型的指针作为输入，并尝试应用各种重写规则来优化这个Value代表的操作。这些规则通常将一个操作替换为更高效的等价操作序列。
*   **`rewriteBlockMIPS(b *Block)`**: 这个函数接收一个SSA Block类型的指针作为输入，并尝试应用重写规则来优化控制流块。这些规则通常涉及将一个条件分支操作替换为更底层的、特定于MIPS架构的分支指令。

**更具体的功能（基于提供的代码片段）**

这个代码片段着重于优化 `OpZero` 和控制流相关的操作。

1. **`OpZero` 优化**:  `OpZero` 操作用于将一块内存区域设置为零。代码中包含多个针对不同大小的 `OpZero` 操作的优化规则。这些规则尝试利用MIPS架构提供的存储指令（如 `MOVWstore`、`MOVHstore`、`MOVBstore`）来更高效地完成清零操作。优化会考虑内存对齐情况，选择最合适的指令序列。对于较大的 `OpZero` 操作，如果大小超过一定阈值或者不对齐，会将其转换为 `OpMIPSLoweredZero`，这可能表示调用一个底层的清零函数或者使用循环来实现。

2. **`OpZeromask` 优化**: `OpZeromask` 操作根据输入值生成一个掩码。如果输入非零，则结果为全零；如果输入为零，则结果为全一。这里将其转换为一个比较指令 (`SGTU`) 和一个取反指令 (`NEG`) 的组合。

3. **控制流块重写**: `rewriteBlockMIPS` 函数针对不同的控制流块类型（如 `BlockMIPSEQ`、`BlockMIPSNE`、`BlockMIPSGEZ` 等）定义了重写规则。这些规则通常基于控制流块的条件判断操作，将其转换为更底层的MIPS分支指令。例如，将比较一个值是否等于零的 `EQ` 块转换为 `First` 块，或者根据比较结果交换分支目标。

**Go语言功能推断与代码示例**

基于 `OpZero` 的优化，可以推断这部分代码与Go语言中的**内存清零**操作相关，例如使用 `unsafe.ZeroMem` 或创建并初始化一个切片/数组。

**示例 (假设输入与输出)**

假设我们有以下Go代码，它尝试将一个长度为4的数组清零：

```go
package main

func main() {
	arr := [4]int{1, 2, 3, 4}
	for i := range arr {
		arr[i] = 0
	}
	// 或者使用更底层的 unsafe.ZeroMem
	// p := unsafe.Pointer(&arr)
	// unsafe.ZeroMem(p, unsafe.Sizeof(arr))
}
```

当Go编译器将这段代码转换为SSA形式时，可能会生成一个 `OpZero` 操作。

**假设的SSA输入 (针对 `OpZero [4]` 的情况):**

```
v1 = InitMem <mem>
v2 = SP <uintptr>
v3 = OffsetAddr <*int> {0} v2
v4 = Zero [4] {*[4]int} v3 v1
```

这里 `v4` 就是一个 `OpZero` 操作，表示将地址 `v3` 开始的 4 个字节清零。

**可能的SSA输出 (应用优化规则后):**

根据代码中的规则，如果类型对齐，可能会被转换为：

```
v1 = InitMem <mem>
v2 = SP <uintptr>
v3 = OffsetAddr <*int> {0} v2
v5 = MOVWconst <uint32> [0]
v6 = MOVWstore v3 v5 v1
```

这里 `OpZero` 被替换为 `MOVWstore` 指令，直接存储一个32位（4字节）的零值。

**命令行参数**

这段代码本身不直接处理命令行参数。它是Go编译器内部的一部分，当使用 `go build` 或 `go run` 等命令编译Go代码时，编译器会在内部调用这些重写规则来优化生成的机器码。用户无法直接控制这些规则的应用。

**归纳 `rewriteMIPS.go` 的功能 (第 6 部分)**

作为第 6 部分，并且结合之前的分析，可以归纳出 `rewriteMIPS.go` 文件的主要功能是：

*   **定义了一系列针对MIPS架构的SSA重写规则。**
*   **专注于优化特定的SSA操作，如 `OpZero` 和 `OpZeromask`。**
*   **通过模式匹配和条件判断，将这些操作替换为更高效的MIPS指令序列。**
*   **优化控制流块，将通用的控制流操作转换为MIPS架构特定的分支指令，以提高执行效率。**

总而言之，`rewriteMIPS.go` 是Go编译器中MIPS后端优化的重要组成部分，它通过细致的指令级优化来提升在MIPS架构上运行的Go程序的性能。

好的，我们来归纳一下提供的Go语言代码片段（`go/src/cmd/compile/internal/ssa/rewriteMIPS.go` 的一部分）的功能。

**功能归纳**

这段代码是Go语言编译器中，针对MIPS架构的SSA（Static Single Assignment）形式进行优化的一个环节。具体来说，它定义了一系列重写规则，用于替换某些SSA操作，以期生成更高效的MIPS汇编代码。

**具体功能点:**

1. **`OpZero` 操作优化:**  代码的核心在于优化 `OpZero` 操作，该操作用于将一块内存区域设置为零。针对 `OpZero` 操作，代码定义了多条匹配规则，根据需要清零的内存大小和对齐方式，将其转换为一系列MIPS的存储指令 (`MOVWstore`, `MOVHstore`, `MOVBstore`)。
    *   对于小块且对齐的内存（例如 4 字节），直接使用 `MOVWstore` 指令存储一个常量 0。
    *   对于稍大或不对齐的内存，可能会分解为多个较小的存储操作，例如将 4 字节清零分解为两个 `MOVHstore` 或四个 `MOVBstore`。
    *   对于更大的或对齐不佳的内存，会将其转换为 `OpMIPSLoweredZero` 操作，这可能表示使用一个运行时库函数或者一个循环来实现清零。

2. **`OpZeromask` 操作优化:** 将 `OpZeromask` 操作（生成一个根据输入是否为零而全零或全一的掩码）转换为一个比较指令 (`SGTU`) 和一个取反指令 (`NEG`) 的组合。

3. **控制流块的重写:** `rewriteBlockMIPS` 函数负责对SSA图中的控制流块进行优化。它会根据块的类型（例如 `BlockMIPSEQ` 表示相等分支）和控制条件，将其转换为更底层的MIPS条件分支指令。
    *   例如，将比较结果为真的 `EQ` 块，如果其条件是一个表示“真”的浮点标志，则转换为 `FPF` 块。
    *   对一些特定的比较操作（如 `SGTUconst [1]`）进行简化，直接使用被比较的值作为新的控制条件。
    *   对常数比较进行优化，例如如果 `EQ` 块的条件是 `MOVWconst [0]`，则直接跳转到 `yes` 分支。

**作为第6部分的归纳：**

作为整个重写过程的第 6 部分，这段代码主要关注以下方面的最终优化和转换：

*   **内存清零的精细化处理:**  在之前的阶段可能已经识别出了需要清零的内存区域，这一部分则根据MIPS架构的特性，选择最优的指令序列进行实现，充分考虑了内存大小和对齐的影响。
*   **控制流的最终调整:** 进一步将高级的控制流结构转换为MIPS架构的原生条件分支指令，为最终的代码生成做好准备。通过对比较操作和常数的分析，尽可能地简化和优化分支条件。

总而言之，这段代码是MIPS架构代码生成过程中的关键优化步骤，它将中间表示的 `OpZero` 和控制流结构转换为高效的MIPS机器指令序列。通过这些重写规则，编译器能够生成更紧凑、执行效率更高的MIPS汇编代码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteMIPS.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共6部分，请归纳一下它的功能

"""
.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore ptr (MOVWconst [0]) mem)
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	// match: (Zero [4] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [2] ptr (MOVWconst [0]) (MOVHstore [0] ptr (MOVWconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [4] ptr mem)
	// result: (MOVBstore [3] ptr (MOVWconst [0]) (MOVBstore [2] ptr (MOVWconst [0]) (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 4 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(3)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(1)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [3] ptr mem)
	// result: (MOVBstore [2] ptr (MOVWconst [0]) (MOVBstore [1] ptr (MOVWconst [0]) (MOVBstore [0] ptr (MOVWconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 3 {
			break
		}
		ptr := v_0
		mem := v_1
		v.reset(OpMIPSMOVBstore)
		v.AuxInt = int32ToAuxInt(2)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(1)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVBstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [6] {t} ptr mem)
	// cond: t.Alignment()%2 == 0
	// result: (MOVHstore [4] ptr (MOVWconst [0]) (MOVHstore [2] ptr (MOVWconst [0]) (MOVHstore [0] ptr (MOVWconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 6 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%2 == 0) {
			break
		}
		v.reset(OpMIPSMOVHstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(2)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVHstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [8] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [4] ptr (MOVWconst [0]) (MOVWstore [0] ptr (MOVWconst [0]) mem))
	for {
		if auxIntToInt64(v.AuxInt) != 8 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(4)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(0)
		v1.AddArg3(ptr, v0, mem)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [12] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [8] ptr (MOVWconst [0]) (MOVWstore [4] ptr (MOVWconst [0]) (MOVWstore [0] ptr (MOVWconst [0]) mem)))
	for {
		if auxIntToInt64(v.AuxInt) != 12 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(8)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(4)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(0)
		v2.AddArg3(ptr, v0, mem)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [16] {t} ptr mem)
	// cond: t.Alignment()%4 == 0
	// result: (MOVWstore [12] ptr (MOVWconst [0]) (MOVWstore [8] ptr (MOVWconst [0]) (MOVWstore [4] ptr (MOVWconst [0]) (MOVWstore [0] ptr (MOVWconst [0]) mem))))
	for {
		if auxIntToInt64(v.AuxInt) != 16 {
			break
		}
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(t.Alignment()%4 == 0) {
			break
		}
		v.reset(OpMIPSMOVWstore)
		v.AuxInt = int32ToAuxInt(12)
		v0 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v0.AuxInt = int32ToAuxInt(0)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v1.AuxInt = int32ToAuxInt(8)
		v2 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v2.AuxInt = int32ToAuxInt(4)
		v3 := b.NewValue0(v.Pos, OpMIPSMOVWstore, types.TypeMem)
		v3.AuxInt = int32ToAuxInt(0)
		v3.AddArg3(ptr, v0, mem)
		v2.AddArg3(ptr, v0, v3)
		v1.AddArg3(ptr, v0, v2)
		v.AddArg3(ptr, v0, v1)
		return true
	}
	// match: (Zero [s] {t} ptr mem)
	// cond: (s > 16 || t.Alignment()%4 != 0)
	// result: (LoweredZero [int32(t.Alignment())] ptr (ADDconst <ptr.Type> ptr [int32(s-moveSize(t.Alignment(), config))]) mem)
	for {
		s := auxIntToInt64(v.AuxInt)
		t := auxToType(v.Aux)
		ptr := v_0
		mem := v_1
		if !(s > 16 || t.Alignment()%4 != 0) {
			break
		}
		v.reset(OpMIPSLoweredZero)
		v.AuxInt = int32ToAuxInt(int32(t.Alignment()))
		v0 := b.NewValue0(v.Pos, OpMIPSADDconst, ptr.Type)
		v0.AuxInt = int32ToAuxInt(int32(s - moveSize(t.Alignment(), config)))
		v0.AddArg(ptr)
		v.AddArg3(ptr, v0, mem)
		return true
	}
	return false
}
func rewriteValueMIPS_OpZeromask(v *Value) bool {
	v_0 := v.Args[0]
	b := v.Block
	typ := &b.Func.Config.Types
	// match: (Zeromask x)
	// result: (NEG (SGTU x (MOVWconst [0])))
	for {
		x := v_0
		v.reset(OpMIPSNEG)
		v0 := b.NewValue0(v.Pos, OpMIPSSGTU, typ.Bool)
		v1 := b.NewValue0(v.Pos, OpMIPSMOVWconst, typ.UInt32)
		v1.AuxInt = int32ToAuxInt(0)
		v0.AddArg2(x, v1)
		v.AddArg(v0)
		return true
	}
}
func rewriteBlockMIPS(b *Block) bool {
	switch b.Kind {
	case BlockMIPSEQ:
		// match: (EQ (FPFlagTrue cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPSFPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPSFPF, cmp)
			return true
		}
		// match: (EQ (FPFlagFalse cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPSFPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPSFPT, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGT {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTU {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTconst {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTUconst {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTzero _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTzero {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (XORconst [1] cmp:(SGTUzero _)) yes no)
		// result: (NE cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTUzero {
				break
			}
			b.resetWithControl(BlockMIPSNE, cmp)
			return true
		}
		// match: (EQ (SGTUconst [1] x) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPSSGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSNE, x)
			return true
		}
		// match: (EQ (SGTUzero x) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPSSGTUzero {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSEQ, x)
			return true
		}
		// match: (EQ (SGTconst [0] x) yes no)
		// result: (GEZ x yes no)
		for b.Controls[0].Op == OpMIPSSGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSGEZ, x)
			return true
		}
		// match: (EQ (SGTzero x) yes no)
		// result: (LEZ x yes no)
		for b.Controls[0].Op == OpMIPSSGTzero {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSLEZ, x)
			return true
		}
		// match: (EQ (MOVWconst [0]) yes no)
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (EQ (MOVWconst [c]) yes no)
		// cond: c != 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPSGEZ:
		// match: (GEZ (MOVWconst [c]) yes no)
		// cond: c >= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GEZ (MOVWconst [c]) yes no)
		// cond: c < 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPSGTZ:
		// match: (GTZ (MOVWconst [c]) yes no)
		// cond: c > 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (GTZ (MOVWconst [c]) yes no)
		// cond: c <= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockIf:
		// match: (If cond yes no)
		// result: (NE cond yes no)
		for {
			cond := b.Controls[0]
			b.resetWithControl(BlockMIPSNE, cond)
			return true
		}
	case BlockMIPSLEZ:
		// match: (LEZ (MOVWconst [c]) yes no)
		// cond: c <= 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c <= 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LEZ (MOVWconst [c]) yes no)
		// cond: c > 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c > 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPSLTZ:
		// match: (LTZ (MOVWconst [c]) yes no)
		// cond: c < 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c < 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
		// match: (LTZ (MOVWconst [c]) yes no)
		// cond: c >= 0
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c >= 0) {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
	case BlockMIPSNE:
		// match: (NE (FPFlagTrue cmp) yes no)
		// result: (FPT cmp yes no)
		for b.Controls[0].Op == OpMIPSFPFlagTrue {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPSFPT, cmp)
			return true
		}
		// match: (NE (FPFlagFalse cmp) yes no)
		// result: (FPF cmp yes no)
		for b.Controls[0].Op == OpMIPSFPFlagFalse {
			v_0 := b.Controls[0]
			cmp := v_0.Args[0]
			b.resetWithControl(BlockMIPSFPF, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGT _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGT {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTU _ _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTU {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTconst {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTUconst _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTUconst {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTzero _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTzero {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (XORconst [1] cmp:(SGTUzero _)) yes no)
		// result: (EQ cmp yes no)
		for b.Controls[0].Op == OpMIPSXORconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			cmp := v_0.Args[0]
			if cmp.Op != OpMIPSSGTUzero {
				break
			}
			b.resetWithControl(BlockMIPSEQ, cmp)
			return true
		}
		// match: (NE (SGTUconst [1] x) yes no)
		// result: (EQ x yes no)
		for b.Controls[0].Op == OpMIPSSGTUconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 1 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSEQ, x)
			return true
		}
		// match: (NE (SGTUzero x) yes no)
		// result: (NE x yes no)
		for b.Controls[0].Op == OpMIPSSGTUzero {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSNE, x)
			return true
		}
		// match: (NE (SGTconst [0] x) yes no)
		// result: (LTZ x yes no)
		for b.Controls[0].Op == OpMIPSSGTconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSLTZ, x)
			return true
		}
		// match: (NE (SGTzero x) yes no)
		// result: (GTZ x yes no)
		for b.Controls[0].Op == OpMIPSSGTzero {
			v_0 := b.Controls[0]
			x := v_0.Args[0]
			b.resetWithControl(BlockMIPSGTZ, x)
			return true
		}
		// match: (NE (MOVWconst [0]) yes no)
		// result: (First no yes)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			if auxIntToInt32(v_0.AuxInt) != 0 {
				break
			}
			b.Reset(BlockFirst)
			b.swapSuccessors()
			return true
		}
		// match: (NE (MOVWconst [c]) yes no)
		// cond: c != 0
		// result: (First yes no)
		for b.Controls[0].Op == OpMIPSMOVWconst {
			v_0 := b.Controls[0]
			c := auxIntToInt32(v_0.AuxInt)
			if !(c != 0) {
				break
			}
			b.Reset(BlockFirst)
			return true
		}
	}
	return false
}

"""




```