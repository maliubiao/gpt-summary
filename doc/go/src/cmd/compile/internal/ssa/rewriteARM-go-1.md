Response: The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `rewriteARM.go` file, which suggests it's involved in optimizing or rewriting Go code for the ARM architecture within the SSA (Static Single Assignment) intermediate representation.

The code consists of several Go functions named `rewriteValueARM_Op...`, each taking a `*Value` as input and returning a boolean. These functions appear to be pattern-matching and replacement rules for specific ARM operations (`OpARM...`).

Therefore, the core function of this code is to apply architecture-specific rewrite rules to SSA values representing ARM instructions. These rules aim to simplify or optimize the instruction sequences.

Let's break down the structure of the functions:

- Each function handles a specific ARM operation (e.g., `OpARMAND`, `OpARMANDconst`, `OpARMANDshiftRL`).
- Inside each function, there are "match" blocks that attempt to identify specific patterns of operands and their operations.
- If a match is found, a "result" block defines how the matched value should be rewritten, often by creating new `Value`s with different operations or operands.
- The functions often involve checks on `AuxInt` (an integer constant associated with the operation) and the types of the arguments.

Based on the patterns, the rewrites seem to focus on:

- **Constant propagation:** Replacing operations with constant results when the inputs are constants.
- **Strength reduction:** Replacing more expensive operations with cheaper equivalents (e.g., shifts instead of multiplication).
- **Identity elimination:** Removing redundant operations (e.g., `AND x, x` becomes `MOVWconst 0`).
- **Reordering operations:** Changing the order of operands for potential further optimization.
- **Combining operations:** Merging sequences of operations into a single, more efficient one.

To summarize, this part of `rewriteARM.go` defines a set of peephole optimizations for ARM assembly instructions represented in the Go SSA form.
这段代码是Go语言编译器中用于ARM架构代码优化的一个组成部分。它定义了一系列重写规则，用于在静态单赋值(SSA)形式的中间表示上对ARM指令进行优化和简化。

**主要功能归纳:**

这段代码的主要功能是定义了一系列的函数，这些函数用于识别特定的ARM指令模式，并将其替换为更简单或更高效的指令序列。这些重写规则的目标是：

1. **常量折叠和传播:**  当操作数是常量时，直接计算结果并用常量替换表达式。
2. **强度削减:** 将耗时的操作替换为更快的等效操作。例如，用移位操作代替乘法或除法。
3. **消除冗余操作:** 移除不必要的操作，例如 `BIC x x` 可以直接替换为 `MOVWconst [0]`。
4. **指令合并:** 将多个指令合并成一个更高效的指令。
5. **利用特定的ARM指令特性:**  例如，利用带移位的AND操作。
6. **简化控制流:** 虽然这段代码不直接涉及控制流，但通过简化表达式，可能会间接地影响控制流的优化。

**具体功能和Go代码示例 (带假设的输入与输出):**

以下列举一些函数的具体功能，并用Go代码示例说明其优化的场景：

**1. `rewriteValueARM_OpARMAND` 函数:**

* **功能:** 优化 `AND` (按位与) 操作。
* **示例:**
   ```go
   // 假设输入 SSA Value v 代表  "AND R1, R2, R2 LSL #3"  (ARM汇编)
   // 其对应的 Go SSA 结构可能为:
   // v.Op = OpARMANDshiftLLreg
   // v.Args[0] = R1
   // v.Args[1] = R2
   // v.Args[2] = 常量 3

   // 匹配: (ANDshiftLLreg x y y)  =>  (SLL <x.Type> x [c])

   // 输出 SSA Value v 会被重写为代表 "LSL R1, R2, #3"
   // v.Op = OpARMSLL
   // v.Args[0] = R1
   // v.Args[1] = R2
   // v.AuxInt = 3
   ```
   **解释:** 如果 `AND` 操作的两个源操作数相同，并且是经过左移的，可以直接用左移指令代替 `AND`。

**2. `rewriteValueARM_OpARMANDconst` 函数:**

* **功能:** 优化 `ANDconst` (按位与常量) 操作。
* **示例:**
   ```go
   // 假设输入 SSA Value v 代表 "AND R1, #0xFF"
   // 其对应的 Go SSA 结构可能为:
   // v.Op = OpARMANDconst
   // v.Args[0] = R1
   // v.AuxInt = 0xFF

   // 匹配: (ANDconst [c] (MOVWconst [d])) => (MOVWconst [c & d])

   // 假设 R1 的值在编译时已知为常量 0x123
   // 则输入的 SSA 结构可能更具体为:
   // v.Op = OpARMANDconst
   // v.Args[0].Op = OpARMMOVWconst
   // v.Args[0].AuxInt = 0x123
   // v.AuxInt = 0xFF

   // 输出 SSA Value v 会被重写为代表常量 0x23
   // v.Op = OpARMMOVWconst
   // v.AuxInt = 0x23
   ```
   **解释:** 如果 `ANDconst` 的源操作数也是常量，可以直接计算结果并用常量替换。

**3. `rewriteValueARM_OpARMANDshiftRL` 函数:**

* **功能:** 优化带右移的 `AND` 操作。
* **示例:**
   ```go
   // 假设输入 SSA Value v 代表 "AND R1, R2 LSR #5, R2"
   // 其对应的 Go SSA 结构可能为:
   // v.Op = OpARMANDshiftRL
   // v.Args[0] = R1
   // v.Args[1] = R2
   // v.AuxInt = 5

   // 匹配: (ANDshiftRL y:(SRLconst x [c]) x [c]) => y

   // 输出 SSA Value v 会被重写为代表  "LSR R1, R2, #5"
   // 也就是直接复用 SRLconst 的结果
   // v 会直接指向原本的 y Value
   ```
   **解释:** 如果 `AND` 操作的两个源操作数分别是某个值右移的结果和原始值，并且右移的位数相同，那么 `AND` 的结果就是右移后的值。

**命令行参数处理:**

这段代码本身不直接处理命令行参数。它是在Go编译器的内部工作流程中被调用的。编译器的命令行参数（例如 `-gcflags` 用于传递编译器标志）可能会影响到代码生成和优化阶段，从而间接地影响到这些重写规则的应用。

**使用者易犯错的点:**

作为编译器开发者，容易犯错的点在于：

* **重写规则的正确性:**  确保重写后的指令序列在所有情况下都与原始指令序列的功能完全一致，尤其要考虑到标志位的影响。
* **模式匹配的完备性:**  确保覆盖所有需要优化的常见模式，避免遗漏。
* **性能影响的评估:**  确保重写规则确实能带来性能提升，而不是引入性能下降。
* **与目标架构的适配性:**  重写规则必须符合ARM架构的指令集和特性。

**总结这段代码的功能:**

这段 `rewriteARM.go` 代码定义了一系列基于模式匹配的重写规则，用于优化ARM架构下的按位与 (`AND`)、带移位的按位与等操作。这些规则旨在通过常量折叠、强度削减、消除冗余操作和利用ARM指令特性来生成更高效的ARM汇编代码。它是Go编译器针对ARM架构进行性能优化的关键组成部分。
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/rewriteARM.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
MANDconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (ANDshiftRL y:(SRLconst x [c]) x [c])
	// result: y
	for {
		c := auxIntToInt32(v.AuxInt)
		y := v_0
		if y.Op != OpARMSRLconst || auxIntToInt32(y.AuxInt) != c {
			break
		}
		x := y.Args[0]
		if x != v_1 {
			break
		}
		v.copyOf(y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMANDshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (ANDshiftRLreg (MOVWconst [c]) x y)
	// result: (ANDconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (ANDshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (ANDshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMANDshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBFX(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BFX [c] (MOVWconst [d]))
	// result: (MOVWconst [d<<(32-uint32(c&0xff)-uint32(c>>8))>>(32-uint32(c>>8))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(d << (32 - uint32(c&0xff) - uint32(c>>8)) >> (32 - uint32(c>>8)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMBFXU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BFXU [c] (MOVWconst [d]))
	// result: (MOVWconst [int32(uint32(d)<<(32-uint32(c&0xff)-uint32(c>>8))>>(32-uint32(c>>8)))])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(d) << (32 - uint32(c&0xff) - uint32(c>>8)) >> (32 - uint32(c>>8))))
		return true
	}
	return false
}
func rewriteValueARM_OpARMBIC(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BIC x (MOVWconst [c]))
	// result: (BICconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (BIC x (SLLconst [c] y))
	// result: (BICshiftLL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMBICshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (BIC x (SRLconst [c] y))
	// result: (BICshiftRL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMBICshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (BIC x (SRAconst [c] y))
	// result: (BICshiftRA x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMBICshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (BIC x (SLL y z))
	// result: (BICshiftLLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMBICshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (BIC x (SRL y z))
	// result: (BICshiftRLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMBICshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (BIC x (SRA y z))
	// result: (BICshiftRAreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMBICshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (BIC x x)
	// result: (MOVWconst [0])
	for {
		x := v_0
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (BICconst [0] x)
	// result: x
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		x := v_0
		v.copyOf(x)
		return true
	}
	// match: (BICconst [c] _)
	// cond: int32(c)==-1
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if !(int32(c) == -1) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	// match: (BICconst [c] x)
	// cond: !isARMImmRot(uint32(c)) && isARMImmRot(^uint32(c))
	// result: (ANDconst [int32(^uint32(c))] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(!isARMImmRot(uint32(c)) && isARMImmRot(^uint32(c))) {
			break
		}
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(int32(^uint32(c)))
		v.AddArg(x)
		return true
	}
	// match: (BICconst [c] x)
	// cond: buildcfg.GOARM.Version==7 && !isARMImmRot(uint32(c)) && uint32(c)>0xffff && ^uint32(c)<=0xffff
	// result: (ANDconst [int32(^uint32(c))] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if !(buildcfg.GOARM.Version == 7 && !isARMImmRot(uint32(c)) && uint32(c) > 0xffff && ^uint32(c) <= 0xffff) {
			break
		}
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(int32(^uint32(c)))
		v.AddArg(x)
		return true
	}
	// match: (BICconst [c] (MOVWconst [d]))
	// result: (MOVWconst [d&^c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(d &^ c)
		return true
	}
	// match: (BICconst [c] (BICconst [d] x))
	// result: (BICconst [c|d] x)
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMBICconst {
			break
		}
		d := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(c | d)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftLL x (MOVWconst [c]) [d])
	// result: (BICconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (BICshiftLL (SLLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSLLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (BICshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMBICshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftRA x (MOVWconst [c]) [d])
	// result: (BICconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	// match: (BICshiftRA (SRAconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRAconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (BICshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMBICshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftRL x (MOVWconst [c]) [d])
	// result: (BICconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMBICconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	// match: (BICshiftRL (SRLconst x [c]) x [c])
	// result: (MOVWconst [0])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRLconst || auxIntToInt32(v_0.AuxInt) != c {
			break
		}
		x := v_0.Args[0]
		if x != v_1 {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMBICshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (BICshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (BICshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMBICshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMN(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMN x (MOVWconst [c]))
	// result: (CMNconst [c] x)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMMOVWconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			v.reset(OpARMCMNconst)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg(x)
			return true
		}
		break
	}
	// match: (CMN x (SLLconst [c] y))
	// result: (CMNshiftLL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftLL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (CMN x (SRLconst [c] y))
	// result: (CMNshiftRL x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRLconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftRL)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (CMN x (SRAconst [c] y))
	// result: (CMNshiftRA x y [c])
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRAconst {
				continue
			}
			c := auxIntToInt32(v_1.AuxInt)
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftRA)
			v.AuxInt = int32ToAuxInt(c)
			v.AddArg2(x, y)
			return true
		}
		break
	}
	// match: (CMN x (SLL y z))
	// result: (CMNshiftLLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSLL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftLLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (CMN x (SRL y z))
	// result: (CMNshiftRLreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRL {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftRLreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	// match: (CMN x (SRA y z))
	// result: (CMNshiftRAreg x y z)
	for {
		for _i0 := 0; _i0 <= 1; _i0, v_0, v_1 = _i0+1, v_1, v_0 {
			x := v_0
			if v_1.Op != OpARMSRA {
				continue
			}
			z := v_1.Args[1]
			y := v_1.Args[0]
			v.reset(OpARMCMNshiftRAreg)
			v.AddArg3(x, y, z)
			return true
		}
		break
	}
	return false
}
func rewriteValueARM_OpARMCMNconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMNconst (MOVWconst [x]) [y])
	// result: (FlagConstant [addFlags32(x,y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(addFlags32(x, y))
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftLL (MOVWconst [c]) x [d])
	// result: (CMNconst [c] (SLLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftLL x (MOVWconst [c]) [d])
	// result: (CMNconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftLLreg (MOVWconst [c]) x y)
	// result: (CMNconst [c] (SLL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMNshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMNshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRA (MOVWconst [c]) x [d])
	// result: (CMNconst [c] (SRAconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRA x (MOVWconst [c]) [d])
	// result: (CMNconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRAreg (MOVWconst [c]) x y)
	// result: (CMNconst [c] (SRA <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMNshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMNshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRL (MOVWconst [c]) x [d])
	// result: (CMNconst [c] (SRLconst <x.Type> x [d]))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v0.AuxInt = int32ToAuxInt(d)
		v0.AddArg(x)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRL x (MOVWconst [c]) [d])
	// result: (CMNconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMNshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMNshiftRLreg (MOVWconst [c]) x y)
	// result: (CMNconst [c] (SRL <x.Type> x y))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMCMNconst)
		v.AuxInt = int32ToAuxInt(c)
		v0 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMNshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMNshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMNshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMOVWHSconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWHSconst _ (FlagConstant [fc]) [c])
	// cond: fc.uge()
	// result: (MOVWconst [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_1.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_1.AuxInt)
		if !(fc.uge()) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (CMOVWHSconst x (FlagConstant [fc]) [c])
	// cond: fc.ult()
	// result: x
	for {
		x := v_0
		if v_1.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_1.AuxInt)
		if !(fc.ult()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWHSconst x (InvertFlags flags) [c])
	// result: (CMOVWLSconst x flags [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMInvertFlags {
			break
		}
		flags := v_1.Args[0]
		v.reset(OpARMCMOVWLSconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMOVWLSconst(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMOVWLSconst _ (FlagConstant [fc]) [c])
	// cond: fc.ule()
	// result: (MOVWconst [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_1.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_1.AuxInt)
		if !(fc.ule()) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(c)
		return true
	}
	// match: (CMOVWLSconst x (FlagConstant [fc]) [c])
	// cond: fc.ugt()
	// result: x
	for {
		x := v_0
		if v_1.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_1.AuxInt)
		if !(fc.ugt()) {
			break
		}
		v.copyOf(x)
		return true
	}
	// match: (CMOVWLSconst x (InvertFlags flags) [c])
	// result: (CMOVWHSconst x flags [c])
	for {
		c := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMInvertFlags {
			break
		}
		flags := v_1.Args[0]
		v.reset(OpARMCMOVWHSconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, flags)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMP(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMP x (MOVWconst [c]))
	// result: (CMPconst [c] x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMPconst)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg(x)
		return true
	}
	// match: (CMP (MOVWconst [c]) x)
	// result: (InvertFlags (CMPconst [c] x))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
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
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMP, types.TypeFlags)
		v0.AddArg2(y, x)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SLLconst [c] y))
	// result: (CMPshiftLL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMP (SLLconst [c] y) x)
	// result: (InvertFlags (CMPshiftLL x y [c]))
	for {
		if v_0.Op != OpARMSLLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftLL, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SRLconst [c] y))
	// result: (CMPshiftRL x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMP (SRLconst [c] y) x)
	// result: (InvertFlags (CMPshiftRL x y [c]))
	for {
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftRL, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SRAconst [c] y))
	// result: (CMPshiftRA x y [c])
	for {
		x := v_0
		if v_1.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	// match: (CMP (SRAconst [c] y) x)
	// result: (InvertFlags (CMPshiftRA x y [c]))
	for {
		if v_0.Op != OpARMSRAconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftRA, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v0.AddArg2(x, y)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SLL y z))
	// result: (CMPshiftLLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSLL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftLLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (CMP (SLL y z) x)
	// result: (InvertFlags (CMPshiftLLreg x y z))
	for {
		if v_0.Op != OpARMSLL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftLLreg, types.TypeFlags)
		v0.AddArg3(x, y, z)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SRL y z))
	// result: (CMPshiftRLreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRL {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftRLreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (CMP (SRL y z) x)
	// result: (InvertFlags (CMPshiftRLreg x y z))
	for {
		if v_0.Op != OpARMSRL {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftRLreg, types.TypeFlags)
		v0.AddArg3(x, y, z)
		v.AddArg(v0)
		return true
	}
	// match: (CMP x (SRA y z))
	// result: (CMPshiftRAreg x y z)
	for {
		x := v_0
		if v_1.Op != OpARMSRA {
			break
		}
		z := v_1.Args[1]
		y := v_1.Args[0]
		v.reset(OpARMCMPshiftRAreg)
		v.AddArg3(x, y, z)
		return true
	}
	// match: (CMP (SRA y z) x)
	// result: (InvertFlags (CMPshiftRAreg x y z))
	for {
		if v_0.Op != OpARMSRA {
			break
		}
		z := v_0.Args[1]
		y := v_0.Args[0]
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPshiftRAreg, types.TypeFlags)
		v0.AddArg3(x, y, z)
		v.AddArg(v0)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPD(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPD x (MOVDconst [0]))
	// result: (CMPD0 x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVDconst || auxIntToFloat64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpARMCMPD0)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPF(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (CMPF x (MOVFconst [0]))
	// result: (CMPF0 x)
	for {
		x := v_0
		if v_1.Op != OpARMMOVFconst || auxIntToFloat64(v_1.AuxInt) != 0 {
			break
		}
		v.reset(OpARMCMPF0)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPconst(v *Value) bool {
	v_0 := v.Args[0]
	// match: (CMPconst (MOVWconst [x]) [y])
	// result: (FlagConstant [subFlags32(x,y)])
	for {
		y := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		x := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(x, y))
		return true
	}
	// match: (CMPconst (MOVBUreg _) [c])
	// cond: 0xff < c
	// result: (FlagConstant [subFlags32(0, 1)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVBUreg || !(0xff < c) {
			break
		}
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(0, 1))
		return true
	}
	// match: (CMPconst (MOVHUreg _) [c])
	// cond: 0xffff < c
	// result: (FlagConstant [subFlags32(0, 1)])
	for {
		c := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVHUreg || !(0xffff < c) {
			break
		}
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(0, 1))
		return true
	}
	// match: (CMPconst (ANDconst _ [m]) [n])
	// cond: 0 <= m && m < n
	// result: (FlagConstant [subFlags32(0, 1)])
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMANDconst {
			break
		}
		m := auxIntToInt32(v_0.AuxInt)
		if !(0 <= m && m < n) {
			break
		}
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(0, 1))
		return true
	}
	// match: (CMPconst (SRLconst _ [c]) [n])
	// cond: 0 <= n && 0 < c && c <= 32 && (1<<uint32(32-c)) <= uint32(n)
	// result: (FlagConstant [subFlags32(0, 1)])
	for {
		n := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMSRLconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		if !(0 <= n && 0 < c && c <= 32 && (1<<uint32(32-c)) <= uint32(n)) {
			break
		}
		v.reset(OpARMFlagConstant)
		v.AuxInt = flagConstantToAuxInt(subFlags32(0, 1))
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftLL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftLL (MOVWconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SLLconst <x.Type> x [d])))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSLLconst, x.Type)
		v1.AuxInt = int32ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftLL x (MOVWconst [c]) [d])
	// result: (CMPconst x [c<<uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMPconst)
		v.AuxInt = int32ToAuxInt(c << uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftLLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftLLreg (MOVWconst [c]) x y)
	// result: (InvertFlags (CMPconst [c] (SLL <x.Type> x y)))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSLL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftLLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMPshiftLL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMPshiftLL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftRA(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRA (MOVWconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SRAconst <x.Type> x [d])))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSRAconst, x.Type)
		v1.AuxInt = int32ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRA x (MOVWconst [c]) [d])
	// result: (CMPconst x [c>>uint64(d)])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMPconst)
		v.AuxInt = int32ToAuxInt(c >> uint64(d))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftRAreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRAreg (MOVWconst [c]) x y)
	// result: (InvertFlags (CMPconst [c] (SRA <x.Type> x y)))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSRA, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRAreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMPshiftRA x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMPshiftRA)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftRL(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRL (MOVWconst [c]) x [d])
	// result: (InvertFlags (CMPconst [c] (SRLconst <x.Type> x [d])))
	for {
		d := auxIntToInt32(v.AuxInt)
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSRLconst, x.Type)
		v1.AuxInt = int32ToAuxInt(d)
		v1.AddArg(x)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRL x (MOVWconst [c]) [d])
	// result: (CMPconst x [int32(uint32(c)>>uint64(d))])
	for {
		d := auxIntToInt32(v.AuxInt)
		x := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		v.reset(OpARMCMPconst)
		v.AuxInt = int32ToAuxInt(int32(uint32(c) >> uint64(d)))
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMCMPshiftRLreg(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	// match: (CMPshiftRLreg (MOVWconst [c]) x y)
	// result: (InvertFlags (CMPconst [c] (SRL <x.Type> x y)))
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_1
		y := v_2
		v.reset(OpARMInvertFlags)
		v0 := b.NewValue0(v.Pos, OpARMCMPconst, types.TypeFlags)
		v0.AuxInt = int32ToAuxInt(c)
		v1 := b.NewValue0(v.Pos, OpARMSRL, x.Type)
		v1.AddArg2(x, y)
		v0.AddArg(v1)
		v.AddArg(v0)
		return true
	}
	// match: (CMPshiftRLreg x y (MOVWconst [c]))
	// cond: 0 <= c && c < 32
	// result: (CMPshiftRL x y [c])
	for {
		x := v_0
		y := v_1
		if v_2.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_2.AuxInt)
		if !(0 <= c && c < 32) {
			break
		}
		v.reset(OpARMCMPshiftRL)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(x, y)
		return true
	}
	return false
}
func rewriteValueARM_OpARMEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (Equal (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.eq())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.eq()))
		return true
	}
	// match: (Equal (InvertFlags x))
	// result: (Equal x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMGreaterEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterEqual (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.ge())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.ge()))
		return true
	}
	// match: (GreaterEqual (InvertFlags x))
	// result: (LessEqual x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMLessEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMGreaterEqualU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterEqualU (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.uge())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.uge()))
		return true
	}
	// match: (GreaterEqualU (InvertFlags x))
	// result: (LessEqualU x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMLessEqualU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMGreaterThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterThan (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.gt())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.gt()))
		return true
	}
	// match: (GreaterThan (InvertFlags x))
	// result: (LessThan x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMLessThan)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMGreaterThanU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (GreaterThanU (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.ugt())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.ugt()))
		return true
	}
	// match: (GreaterThanU (InvertFlags x))
	// result: (LessThanU x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMLessThanU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMLessEqual(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessEqual (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.le())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.le()))
		return true
	}
	// match: (LessEqual (InvertFlags x))
	// result: (GreaterEqual x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMGreaterEqual)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMLessEqualU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessEqualU (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.ule())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.ule()))
		return true
	}
	// match: (LessEqualU (InvertFlags x))
	// result: (GreaterEqualU x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMGreaterEqualU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMLessThan(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessThan (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.lt())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.lt()))
		return true
	}
	// match: (LessThan (InvertFlags x))
	// result: (GreaterThan x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMGreaterThan)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMLessThanU(v *Value) bool {
	v_0 := v.Args[0]
	// match: (LessThanU (FlagConstant [fc]))
	// result: (MOVWconst [b2i32(fc.ult())])
	for {
		if v_0.Op != OpARMFlagConstant {
			break
		}
		fc := auxIntToFlagConstant(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(b2i32(fc.ult()))
		return true
	}
	// match: (LessThanU (InvertFlags x))
	// result: (GreaterThanU x)
	for {
		if v_0.Op != OpARMInvertFlags {
			break
		}
		x := v_0.Args[0]
		v.reset(OpARMGreaterThanU)
		v.AddArg(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVBUload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVBUload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVBUload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVBUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBUreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVBUreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUload [0] {sym} (ADD ptr idx) mem)
	// cond: sym == nil
	// result: (MOVBUloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVBUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVBUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVWconst [int32(read8(sym, int64(off)))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(read8(sym, int64(off))))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBUloadidx ptr idx (MOVBstoreidx ptr2 idx x _))
	// cond: isSamePtr(ptr, ptr2)
	// result: (MOVBUreg x)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVBstoreidx {
			break
		}
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVBUreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUloadidx ptr (MOVWconst [c]) mem)
	// result: (MOVBUload [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVBUload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBUloadidx (MOVWconst [c]) ptr mem)
	// result: (MOVBUload [c] ptr mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVBUload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBUreg x:(MOVBUload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (ANDconst [c] x))
	// result: (ANDconst [c&0xff] x)
	for {
		if v_0.Op != OpARMANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c & 0xff)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg x:(MOVBUreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBUreg (MOVWconst [c]))
	// result: (MOVWconst [int32(uint8(c))])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint8(c)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVBload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVBload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVBload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVBload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBload [off] {sym} ptr (MOVBstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVBreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVBstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBload [0] {sym} (ADD ptr idx) mem)
	// cond: sym == nil
	// result: (MOVBloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVBloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBloadidx ptr idx (MOVBstoreidx ptr2 idx x _))
	// cond: isSamePtr(ptr, ptr2)
	// result: (MOVBreg x)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVBstoreidx {
			break
		}
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVBreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBloadidx ptr (MOVWconst [c]) mem)
	// result: (MOVBload [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVBload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVBloadidx (MOVWconst [c]) ptr mem)
	// result: (MOVBload [c] ptr mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVBload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVBreg x:(MOVBload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (ANDconst [c] x))
	// cond: c & 0x80 == 0
	// result: (ANDconst [c&0x7f] x)
	for {
		if v_0.Op != OpARMANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		if !(c&0x80 == 0) {
			break
		}
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c & 0x7f)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg x:(MOVBreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVBreg (MOVWconst [c]))
	// result: (MOVWconst [int32(int8(c))])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(int8(c)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// result: (MOVBstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym} (SUBconst [off2] ptr) val mem)
	// result: (MOVBstore [off1-off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVBstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVBreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVBUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVBUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [off] {sym} ptr (MOVHUreg x) mem)
	// result: (MOVBstore [off] {sym} ptr x mem)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHUreg {
			break
		}
		x := v_1.Args[0]
		mem := v_2
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(off)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, x, mem)
		return true
	}
	// match: (MOVBstore [0] {sym} (ADD ptr idx) val mem)
	// cond: sym == nil
	// result: (MOVBstoreidx ptr idx val mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVBstoreidx)
		v.AddArg4(ptr, idx, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVBstoreidx(v *Value) bool {
	v_3 := v.Args[3]
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVBstoreidx ptr (MOVWconst [c]) val mem)
	// result: (MOVBstore [c] ptr val mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		val := v_2
		mem := v_3
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVBstoreidx (MOVWconst [c]) ptr val mem)
	// result: (MOVBstore [c] ptr val mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		val := v_2
		mem := v_3
		v.reset(OpARMMOVBstore)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVDload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVDload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVDload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVDload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVDload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVDload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVDload [off] {sym} ptr (MOVDstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVDstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVDstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVDstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// result: (MOVDstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym} (SUBconst [off2] ptr) val mem)
	// result: (MOVDstore [off1-off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVDstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVDstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVDstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVFload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVFload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVFload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVFload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVFload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVFload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVFload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVFload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVFload [off] {sym} ptr (MOVFstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: x
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVFstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.copyOf(x)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVFstore(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVFstore [off1] {sym} (ADDconst [off2] ptr) val mem)
	// result: (MOVFstore [off1+off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym} (SUBconst [off2] ptr) val mem)
	// result: (MOVFstore [off1-off2] {sym} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		v.reset(OpARMMOVFstore)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg3(ptr, val, mem)
		return true
	}
	// match: (MOVFstore [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) val mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVFstore [off1+off2] {mergeSym(sym1,sym2)} ptr val mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		val := v_1
		mem := v_2
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVFstore)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg3(ptr, val, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHUload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	b := v.Block
	config := b.Func.Config
	// match: (MOVHUload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVHUload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVHUload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVHUload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVHUload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVHUload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} ptr (MOVHstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVHUreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVHUreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUload [0] {sym} (ADD ptr idx) mem)
	// cond: sym == nil
	// result: (MOVHUloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
		}
		v.reset(OpARMMOVHUloadidx)
		v.AddArg3(ptr, idx, mem)
		return true
	}
	// match: (MOVHUload [off] {sym} (SB) _)
	// cond: symIsRO(sym)
	// result: (MOVWconst [int32(read16(sym, int64(off), config.ctxt.Arch.ByteOrder))])
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpSB || !(symIsRO(sym)) {
			break
		}
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(read16(sym, int64(off), config.ctxt.Arch.ByteOrder)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHUloadidx(v *Value) bool {
	v_2 := v.Args[2]
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHUloadidx ptr idx (MOVHstoreidx ptr2 idx x _))
	// cond: isSamePtr(ptr, ptr2)
	// result: (MOVHUreg x)
	for {
		ptr := v_0
		idx := v_1
		if v_2.Op != OpARMMOVHstoreidx {
			break
		}
		x := v_2.Args[2]
		ptr2 := v_2.Args[0]
		if idx != v_2.Args[1] || !(isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVHUreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUloadidx ptr (MOVWconst [c]) mem)
	// result: (MOVHUload [c] ptr mem)
	for {
		ptr := v_0
		if v_1.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_1.AuxInt)
		mem := v_2
		v.reset(OpARMMOVHUload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHUloadidx (MOVWconst [c]) ptr mem)
	// result: (MOVHUload [c] ptr mem)
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		ptr := v_1
		mem := v_2
		v.reset(OpARMMOVHUload)
		v.AuxInt = int32ToAuxInt(c)
		v.AddArg2(ptr, mem)
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHUreg(v *Value) bool {
	v_0 := v.Args[0]
	// match: (MOVHUreg x:(MOVBUload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUload _ _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVHUload {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (ANDconst [c] x))
	// result: (ANDconst [c&0xffff] x)
	for {
		if v_0.Op != OpARMANDconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		x := v_0.Args[0]
		v.reset(OpARMANDconst)
		v.AuxInt = int32ToAuxInt(c & 0xffff)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVBUreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVBUreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg x:(MOVHUreg _))
	// result: (MOVWreg x)
	for {
		x := v_0
		if x.Op != OpARMMOVHUreg {
			break
		}
		v.reset(OpARMMOVWreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHUreg (MOVWconst [c]))
	// result: (MOVWconst [int32(uint16(c))])
	for {
		if v_0.Op != OpARMMOVWconst {
			break
		}
		c := auxIntToInt32(v_0.AuxInt)
		v.reset(OpARMMOVWconst)
		v.AuxInt = int32ToAuxInt(int32(uint16(c)))
		return true
	}
	return false
}
func rewriteValueARM_OpARMMOVHload(v *Value) bool {
	v_1 := v.Args[1]
	v_0 := v.Args[0]
	// match: (MOVHload [off1] {sym} (ADDconst [off2] ptr) mem)
	// result: (MOVHload [off1+off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADDconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym} (SUBconst [off2] ptr) mem)
	// result: (MOVHload [off1-off2] {sym} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMSUBconst {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		ptr := v_0.Args[0]
		mem := v_1
		v.reset(OpARMMOVHload)
		v.AuxInt = int32ToAuxInt(off1 - off2)
		v.Aux = symToAux(sym)
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off1] {sym1} (MOVWaddr [off2] {sym2} ptr) mem)
	// cond: canMergeSym(sym1,sym2)
	// result: (MOVHload [off1+off2] {mergeSym(sym1,sym2)} ptr mem)
	for {
		off1 := auxIntToInt32(v.AuxInt)
		sym1 := auxToSym(v.Aux)
		if v_0.Op != OpARMMOVWaddr {
			break
		}
		off2 := auxIntToInt32(v_0.AuxInt)
		sym2 := auxToSym(v_0.Aux)
		ptr := v_0.Args[0]
		mem := v_1
		if !(canMergeSym(sym1, sym2)) {
			break
		}
		v.reset(OpARMMOVHload)
		v.AuxInt = int32ToAuxInt(off1 + off2)
		v.Aux = symToAux(mergeSym(sym1, sym2))
		v.AddArg2(ptr, mem)
		return true
	}
	// match: (MOVHload [off] {sym} ptr (MOVHstore [off2] {sym2} ptr2 x _))
	// cond: sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)
	// result: (MOVHreg x)
	for {
		off := auxIntToInt32(v.AuxInt)
		sym := auxToSym(v.Aux)
		ptr := v_0
		if v_1.Op != OpARMMOVHstore {
			break
		}
		off2 := auxIntToInt32(v_1.AuxInt)
		sym2 := auxToSym(v_1.Aux)
		x := v_1.Args[1]
		ptr2 := v_1.Args[0]
		if !(sym == sym2 && off == off2 && isSamePtr(ptr, ptr2)) {
			break
		}
		v.reset(OpARMMOVHreg)
		v.AddArg(x)
		return true
	}
	// match: (MOVHload [0] {sym} (ADD ptr idx) mem)
	// cond: sym == nil
	// result: (MOVHloadidx ptr idx mem)
	for {
		if auxIntToInt32(v.AuxInt) != 0 {
			break
		}
		sym := auxToSym(v.Aux)
		if v_0.Op != OpARMADD {
			break
		}
		idx := v_0.Args[1]
		ptr := v_0.Args[0]
		mem := v_1
		if !(sym == nil) {
			break
```