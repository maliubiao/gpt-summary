Response:
Let's break down the thought process to analyze the given Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its purpose within the larger Go ecosystem, illustrative examples, handling of command-line arguments (if any), and potential pitfalls for users.

2. **Identify the Core Package:** The code starts with `package arm64`. This immediately tells us it's related to the ARM64 architecture. The import path `cmd/compile/internal/arm64` confirms this is part of the Go compiler specifically targeting ARM64.

3. **Scan for Key Data Structures and Functions:** Quickly look for prominent elements:
    * **Functions:** `loadByType`, `storeByType`, `loadByType2`, `storeByType2`, `makeshift`, `genshift`, `genIndexedOperand`, `ssaGenValue`, `ssaGenBlock`, `loadRegResult`, `spillArgReg`.
    * **Data Structures:**  The imports reveal interaction with `ssa.Value`, `ssa.Block`, `types.Type`, `obj.As`, `obj.Addr`, `obj.Prog`, etc. These are core compiler data structures.
    * **Constants/Maps:** `condBits`, `blockJump`, `leJumps`, `gtJumps`. These suggest mappings related to conditional operations and branching.

4. **Analyze Individual Functions:**  Go through each function and determine its role:
    * `loadByType`, `storeByType`, `loadByType2`, `storeByType2`: These functions clearly select appropriate ARM64 assembly instructions (`obj.As`) for loading and storing data based on the Go type's size and whether it's a float or integer. The "2" versions suggest handling pairs of values.
    * `makeshift`: The name and the bitwise operations suggest encoding register and shift information into a single `int64`. This is likely used for optimized addressing modes in ARM64.
    * `genshift`: This function generates an assembly instruction for shift operations, utilizing the output of `makeshift`.
    * `genIndexedOperand`: This function constructs memory operands for indexed addressing, incorporating shift operations based on the `ssa.Op`.
    * `ssaGenValue`: This is the most complex function. The `switch v.Op` strongly indicates it's responsible for generating assembly instructions for various SSA (Static Single Assignment) operations. Each `case` handles a specific SSA operation, translating it into corresponding ARM64 assembly. This is the heart of the code generation process.
    * `ssaGenBlock`: This function handles the generation of assembly code for different types of control flow blocks (e.g., conditional branches, jumps, returns). It uses the `blockJump`, `leJumps`, and `gtJumps` maps.
    * `loadRegResult`, `spillArgReg`:  These deal with loading function return values from the stack and spilling argument registers to the stack, respectively.

5. **Infer the Overall Functionality:** Based on the analysis of individual functions, it becomes clear that this code is a crucial part of the **Go compiler's backend for the ARM64 architecture**. Its primary function is to translate the architecture-independent intermediate representation (SSA) of Go code into concrete ARM64 assembly instructions.

6. **Construct Illustrative Examples:**  Choose a few representative functions and demonstrate their behavior with hypothetical inputs and outputs:
    * `loadByType`: Show how different Go types map to different ARM64 load instructions.
    * `storeByType`: Similar to `loadByType`, but for stores.
    * `ssaGenValue`: Select a few simple SSA ops (like `OpCopy`, `OpAddconst`, `OpLoadReg`) and demonstrate the generated assembly. *Initially, I might try a more complex example, but it's better to start simple for clarity.*
    * `ssaGenBlock`: Illustrate how different block kinds translate to different branching instructions.

7. **Address Command-Line Arguments:**  Carefully review the code for any direct handling of command-line flags. In this snippet, there are none. However, acknowledge that the *compiler as a whole* uses command-line flags and that these flags can indirectly influence the code generation process (e.g., optimization level).

8. **Identify Potential Pitfalls:**  Think about common errors developers might make or misunderstandings they could have when interacting with the *output* of this code (the generated assembly) or the *compilation process* in general:
    * **Incorrect assumptions about register usage:**  Emphasize that register allocation is handled by the compiler.
    * **Manual assembly optimization:**  Discourage manual tweaking of the generated assembly unless there's a deep understanding.
    * **Debugging generated assembly:** Highlight that debugging can be complex and requires specialized tools.

9. **Structure the Output:**  Organize the findings logically, starting with a high-level summary, then detailing the functionality of each part, providing examples, discussing command-line arguments, and finally addressing potential pitfalls. Use clear headings and formatting for readability. Use code blocks for examples.

10. **Refine and Review:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For instance, I initially might have focused too much on the individual assembly instructions and not enough on the overall purpose within the compiler. Reviewing helps correct this. Also, ensure the examples are correct and easy to understand. Double-check the assumptions made during code inference.

This step-by-step approach helps to systematically analyze the code, understand its purpose, and provide a comprehensive and informative answer to the request.
这段代码是Go语言编译器 `cmd/compile` 中用于将中间表示 (SSA, Static Single Assignment) 转换为 ARM64 汇编代码的关键部分。它定义了 ARM64 架构特定的 SSA 代码生成逻辑。

**功能列表:**

1. **类型相关的加载和存储指令选择 (`loadByType`, `storeByType`, `loadByType2`, `storeByType2`):**
   - 根据 Go 语言变量的类型（大小、是否浮点、是否有符号）选择合适的 ARM64 加载和存储指令。
   - `loadByType` 和 `storeByType` 处理单个值的加载和存储。
   - `loadByType2` 和 `storeByType2` 处理一次加载或存储两个连续内存位置的值到/从两个寄存器。这通常用于优化结构体或数组的访问。

2. **偏移量编码 (`makeshift`):**
   - 将寄存器、偏移类型和移位量编码到一个 64 位整数中，用于 `obj.Prog` 结构体的 `Offset` 字段，表示内存操作的偏移量。

3. **移位操作代码生成 (`genshift`):**
   - 生成执行带移位操作的 ARM64 汇编指令。例如，`r = r0 op (r1 << n)`。

4. **索引寻址模式代码生成 (`genIndexedOperand`):**
   - 为使用索引寄存器的加载和存储指令生成内存操作数。根据操作类型，索引寄存器可能会进行移位。

5. **SSA 值代码生成 (`ssaGenValue`):**
   - 这是核心功能。它遍历 SSA 图中的每个值 ( `ssa.Value` )，并根据其操作类型 (`v.Op`) 生成相应的 ARM64 汇编指令。
   - 处理各种操作，包括：
     - 数据移动 (`OpCopy`, `OpARM64MOVDreg`, `OpLoadReg`, `OpStoreReg`)
     - 算术和逻辑运算 (`OpARM64ADD`, `OpARM64SUB`, `OpARM64AND`, `OpARM64OR`, 等)
     - 常量加载 (`OpARM64MOVDconst`, `OpARM64FMOVSconst`, `OpARM64FMOVDconst`)
     - 比较操作 (`OpARM64CMP`, `OpARM64CMPconst`, 等)
     - 地址计算 (`OpARM64MOVDaddr`)
     - 内存加载和存储 (`OpARM64MOVBload`, `OpARM64MOVHstore`, `OpARM64LDP`, `OpARM64STP`, 等)
     - 原子操作 (`OpARM64LoweredAtomicExchange64`, `OpARM64LoweredAtomicAdd64`, `OpARM64LoweredAtomicCas64`, 等)
     - 类型转换
     - 函数调用 (`OpARM64CALLstatic`, `OpARM64CALLclosure`, `OpARM64CALLinter`, `OpARM64CALLtail`)
     - 运行时支持 (例如，零初始化 `OpARM64LoweredZero`, 内存拷贝 `OpARM64LoweredMove`, 边界检查 `OpARM64LoweredPanicBoundsA`, 空指针检查 `OpARM64LoweredNilCheck`)
     - 条件选择 (`OpARM64CSEL`, `OpARM64CSINC`, 等)
     - 特殊指令 (`OpARM64DMB`, `OpARM64PRFM`)

6. **SSA 代码块代码生成 (`ssaGenBlock`):**
   - 遍历 SSA 图中的每个代码块 (`ssa.Block`)，并根据其类型 (`b.Kind`) 生成相应的控制流指令（例如，跳转指令）。
   - 处理各种块类型，包括：
     - 无条件跳转 (`ssa.BlockPlain`)
     - defer 机制 (`ssa.BlockDefer`)
     - 函数返回 (`ssa.BlockRet`)
     - 条件跳转 (`ssa.BlockARM64EQ`, `ssa.BlockARM64NE`, 等)
     - 基于寄存器值的跳转 (`ssa.BlockARM64Z`, `ssa.BlockARM64NZ`, 等)
     - 位测试跳转 (`ssa.BlockARM64TBZ`, `ssa.BlockARM64TBNZ`)
     - 跳转表 (`ssa.BlockARM64JUMPTABLE`)

7. **加载寄存器结果 (`loadRegResult`):**
   - 从栈帧中加载函数调用的返回值到寄存器。

8. **溢出参数寄存器 (`spillArgReg`):**
   - 将参数寄存器的值保存到栈帧中。

**推断的 Go 语言功能实现:**

这段代码是 Go 语言编译器中 **SSA 后端代码生成** 的一部分，专门针对 ARM64 架构。它负责将 Go 语言的高级抽象操作转换为底层的 ARM64 汇编指令，使得程序能够在 ARM64 处理器上执行。

**Go 代码示例:**

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(5, 3)
	fmt.Println(result)
}
```

**代码推理 (假设):**

当编译上述 `main.go` 文件时，编译器会经历多个阶段，其中之一就是 SSA 代码生成。对于 `add` 函数的加法操作 `a + b`，在 `ssaGenValue` 函数中，可能会遇到 `ssa.OpARM64ADD` 操作。

**假设输入 (对于 `add` 函数的 `a + b` 操作):**

- `v.Op`: `ssa.OpARM64ADD`
- `v.Args[0].Reg()`: 代表变量 `a` 的寄存器 (例如，R1)
- `v.Args[1].Reg()`: 代表变量 `b` 的寄存器 (例如，R2)
- `v.Reg()`:  用于存储结果的寄存器 (例如，R0)

**假设输出 (生成的 ARM64 汇编指令):**

```assembly
ADD R1, R2, R0  // 将 R1 和 R2 的值相加，结果存储到 R0
```

**命令行参数:**

这段代码本身不直接处理命令行参数。但是，`cmd/compile` 编译器作为一个整体会接收各种命令行参数来控制编译过程，例如：

- `-o <outfile>`:  指定输出文件名。
- `-gcflags <flags>`:  传递参数给垃圾回收器。
- `-l`: 禁用内联优化。
- `-N`: 禁用优化。
- `-S`:  打印生成的汇编代码。

这些命令行参数会影响编译器的行为，包括 SSA 的生成和随后的 ARM64 代码生成，但这段代码本身是编译过程的一个内部环节。

**使用者易犯错的点 (通常是编译器开发者或需要深入理解编译器行为的人):**

1. **错误地理解类型和指令的对应关系:**  `loadByType` 和 `storeByType` 等函数确保了类型安全的内存访问。如果手动修改或生成 SSA，可能会错误地选择指令，导致类型不匹配的访问，造成程序崩溃或数据损坏。例如，使用 `AMOVB` 加载一个 `int32` 类型的值。

2. **不正确的偏移量计算:** `makeshift` 函数用于编码偏移量。手动计算或修改偏移量时，可能会出现错误，导致访问错误的内存地址。

3. **对原子操作的误解:** 原子操作的实现需要特定的指令序列 (`LDAXR`, `STLXR` 等) 来保证操作的原子性。如果手动修改原子操作相关的 SSA 或汇编代码，可能会破坏原子性，导致并发问题。

4. **不了解条件码和跳转指令的对应关系:** `condBits` 和 `blockJump` 定义了条件码和跳转指令的映射。错误地使用条件码或跳转指令会导致程序逻辑错误。例如，在比较两个无符号数后，错误地使用了有符号比较的跳转指令。

5. **忽略了调用约定和栈帧布局:**  函数调用和返回涉及到特定的寄存器使用和栈帧布局。如果手动修改函数调用相关的代码，可能会破坏调用约定，导致程序崩溃或传递错误的参数。

**总结:**

这段 `ssa.go` 代码是 Go 语言编译器针对 ARM64 架构进行代码生成的核心部分。它负责将高级的 SSA 中间表示转换为可以在 ARM64 处理器上执行的低级汇编指令。理解这段代码需要对 Go 语言的编译过程、SSA 的概念以及 ARM64 汇编语言有深入的了解。普通 Go 语言开发者通常不需要直接接触这部分代码，但理解其功能有助于更好地理解 Go 语言的运行机制和性能特性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/arm64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm64

import (
	"math"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/arm64"
)

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm64.AFMOVS
		case 8:
			return arm64.AFMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			if t.IsSigned() {
				return arm64.AMOVB
			} else {
				return arm64.AMOVBU
			}
		case 2:
			if t.IsSigned() {
				return arm64.AMOVH
			} else {
				return arm64.AMOVHU
			}
		case 4:
			if t.IsSigned() {
				return arm64.AMOVW
			} else {
				return arm64.AMOVWU
			}
		case 8:
			return arm64.AMOVD
		}
	}
	panic("bad load type")
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm64.AFMOVS
		case 8:
			return arm64.AFMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			return arm64.AMOVB
		case 2:
			return arm64.AMOVH
		case 4:
			return arm64.AMOVW
		case 8:
			return arm64.AMOVD
		}
	}
	panic("bad store type")
}

// loadByType2 returns an opcode that can load consecutive memory locations into 2 registers with type t.
// returns obj.AXXX if no such opcode exists.
func loadByType2(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm64.AFLDPS
		case 8:
			return arm64.AFLDPD
		}
	} else {
		switch t.Size() {
		case 4:
			return arm64.ALDPW
		case 8:
			return arm64.ALDP
		}
	}
	return obj.AXXX
}

// storeByType2 returns an opcode that can store registers with type t into 2 consecutive memory locations.
// returns obj.AXXX if no such opcode exists.
func storeByType2(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm64.AFSTPS
		case 8:
			return arm64.AFSTPD
		}
	} else {
		switch t.Size() {
		case 4:
			return arm64.ASTPW
		case 8:
			return arm64.ASTP
		}
	}
	return obj.AXXX
}

// makeshift encodes a register shifted by a constant, used as an Offset in Prog.
func makeshift(v *ssa.Value, reg int16, typ int64, s int64) int64 {
	if s < 0 || s >= 64 {
		v.Fatalf("shift out of range: %d", s)
	}
	return int64(reg&31)<<16 | typ | (s&63)<<10
}

// genshift generates a Prog for r = r0 op (r1 shifted by n).
func genshift(s *ssagen.State, v *ssa.Value, as obj.As, r0, r1, r int16, typ int64, n int64) *obj.Prog {
	p := s.Prog(as)
	p.From.Type = obj.TYPE_SHIFT
	p.From.Offset = makeshift(v, r1, typ, n)
	p.Reg = r0
	if r != 0 {
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	}
	return p
}

// generate the memory operand for the indexed load/store instructions.
// base and idx are registers.
func genIndexedOperand(op ssa.Op, base, idx int16) obj.Addr {
	// Reg: base register, Index: (shifted) index register
	mop := obj.Addr{Type: obj.TYPE_MEM, Reg: base}
	switch op {
	case ssa.OpARM64MOVDloadidx8, ssa.OpARM64MOVDstoreidx8, ssa.OpARM64MOVDstorezeroidx8,
		ssa.OpARM64FMOVDloadidx8, ssa.OpARM64FMOVDstoreidx8:
		mop.Index = arm64.REG_LSL | 3<<5 | idx&31
	case ssa.OpARM64MOVWloadidx4, ssa.OpARM64MOVWUloadidx4, ssa.OpARM64MOVWstoreidx4, ssa.OpARM64MOVWstorezeroidx4,
		ssa.OpARM64FMOVSloadidx4, ssa.OpARM64FMOVSstoreidx4:
		mop.Index = arm64.REG_LSL | 2<<5 | idx&31
	case ssa.OpARM64MOVHloadidx2, ssa.OpARM64MOVHUloadidx2, ssa.OpARM64MOVHstoreidx2, ssa.OpARM64MOVHstorezeroidx2:
		mop.Index = arm64.REG_LSL | 1<<5 | idx&31
	default: // not shifted
		mop.Index = idx
	}
	return mop
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy, ssa.OpARM64MOVDreg:
		if v.Type.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x == y {
			return
		}
		as := arm64.AMOVD
		if v.Type.IsFloat() {
			switch v.Type.Size() {
			case 4:
				as = arm64.AFMOVS
			case 8:
				as = arm64.AFMOVD
			default:
				panic("bad float size")
			}
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x
		p.To.Type = obj.TYPE_REG
		p.To.Reg = y
	case ssa.OpARM64MOVDnop:
		// nothing to do
	case ssa.OpLoadReg:
		if v.Type.IsFlags() {
			v.Fatalf("load flags not implemented: %v", v.LongString())
			return
		}
		p := s.Prog(loadByType(v.Type))
		ssagen.AddrAuto(&p.From, v.Args[0])
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpStoreReg:
		if v.Type.IsFlags() {
			v.Fatalf("store flags not implemented: %v", v.LongString())
			return
		}
		p := s.Prog(storeByType(v.Type))
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddrAuto(&p.To, v)
	case ssa.OpArgIntReg, ssa.OpArgFloatReg:
		ssagen.CheckArgReg(v)
		// The assembler needs to wrap the entry safepoint/stack growth code with spill/unspill
		// The loop only runs once.
		args := v.Block.Func.RegArgs
		if len(args) == 0 {
			break
		}
		v.Block.Func.RegArgs = nil // prevent from running again

		for i := 0; i < len(args); i++ {
			a := args[i]
			// Offset by size of the saved LR slot.
			addr := ssagen.SpillSlotAddr(a, arm64.REGSP, base.Ctxt.Arch.FixedFrameSize)
			// Look for double-register operations if we can.
			if i < len(args)-1 {
				b := args[i+1]
				if a.Type.Size() == b.Type.Size() &&
					a.Type.IsFloat() == b.Type.IsFloat() &&
					b.Offset == a.Offset+a.Type.Size() {
					ld := loadByType2(a.Type)
					st := storeByType2(a.Type)
					if ld != obj.AXXX && st != obj.AXXX {
						s.FuncInfo().AddSpill(obj.RegSpill{Reg: a.Reg, Reg2: b.Reg, Addr: addr, Unspill: ld, Spill: st})
						i++ // b is done also, skip it.
						continue
					}
				}
			}
			// Pass the spill/unspill information along to the assembler.
			s.FuncInfo().AddSpill(obj.RegSpill{Reg: a.Reg, Addr: addr, Unspill: loadByType(a.Type), Spill: storeByType(a.Type)})
		}

	case ssa.OpARM64ADD,
		ssa.OpARM64SUB,
		ssa.OpARM64AND,
		ssa.OpARM64OR,
		ssa.OpARM64XOR,
		ssa.OpARM64BIC,
		ssa.OpARM64EON,
		ssa.OpARM64ORN,
		ssa.OpARM64MUL,
		ssa.OpARM64MULW,
		ssa.OpARM64MNEG,
		ssa.OpARM64MNEGW,
		ssa.OpARM64MULH,
		ssa.OpARM64UMULH,
		ssa.OpARM64MULL,
		ssa.OpARM64UMULL,
		ssa.OpARM64DIV,
		ssa.OpARM64UDIV,
		ssa.OpARM64DIVW,
		ssa.OpARM64UDIVW,
		ssa.OpARM64MOD,
		ssa.OpARM64UMOD,
		ssa.OpARM64MODW,
		ssa.OpARM64UMODW,
		ssa.OpARM64SLL,
		ssa.OpARM64SRL,
		ssa.OpARM64SRA,
		ssa.OpARM64FADDS,
		ssa.OpARM64FADDD,
		ssa.OpARM64FSUBS,
		ssa.OpARM64FSUBD,
		ssa.OpARM64FMULS,
		ssa.OpARM64FMULD,
		ssa.OpARM64FNMULS,
		ssa.OpARM64FNMULD,
		ssa.OpARM64FDIVS,
		ssa.OpARM64FDIVD,
		ssa.OpARM64FMINS,
		ssa.OpARM64FMIND,
		ssa.OpARM64FMAXS,
		ssa.OpARM64FMAXD,
		ssa.OpARM64ROR,
		ssa.OpARM64RORW:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARM64FMADDS,
		ssa.OpARM64FMADDD,
		ssa.OpARM64FNMADDS,
		ssa.OpARM64FNMADDD,
		ssa.OpARM64FMSUBS,
		ssa.OpARM64FMSUBD,
		ssa.OpARM64FNMSUBS,
		ssa.OpARM64FNMSUBD,
		ssa.OpARM64MADD,
		ssa.OpARM64MADDW,
		ssa.OpARM64MSUB,
		ssa.OpARM64MSUBW:
		rt := v.Reg()
		ra := v.Args[0].Reg()
		rm := v.Args[1].Reg()
		rn := v.Args[2].Reg()
		p := s.Prog(v.Op.Asm())
		p.Reg = ra
		p.From.Type = obj.TYPE_REG
		p.From.Reg = rm
		p.AddRestSourceReg(rn)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = rt
	case ssa.OpARM64ADDconst,
		ssa.OpARM64SUBconst,
		ssa.OpARM64ANDconst,
		ssa.OpARM64ORconst,
		ssa.OpARM64XORconst,
		ssa.OpARM64SLLconst,
		ssa.OpARM64SRLconst,
		ssa.OpARM64SRAconst,
		ssa.OpARM64RORconst,
		ssa.OpARM64RORWconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64ADDSconstflags:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpARM64ADCzerocarry:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGZERO
		p.Reg = arm64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64ADCSflags,
		ssa.OpARM64ADDSflags,
		ssa.OpARM64SBCSflags,
		ssa.OpARM64SUBSflags:
		r := v.Reg0()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARM64NEGSflags:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpARM64NGCzerocarry:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64EXTRconst,
		ssa.OpARM64EXTRWconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.AddRestSourceReg(v.Args[0].Reg())
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64MVNshiftLL, ssa.OpARM64NEGshiftLL:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm64.SHIFT_LL, v.AuxInt)
	case ssa.OpARM64MVNshiftRL, ssa.OpARM64NEGshiftRL:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm64.SHIFT_LR, v.AuxInt)
	case ssa.OpARM64MVNshiftRA, ssa.OpARM64NEGshiftRA:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm64.SHIFT_AR, v.AuxInt)
	case ssa.OpARM64MVNshiftRO:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm64.SHIFT_ROR, v.AuxInt)
	case ssa.OpARM64ADDshiftLL,
		ssa.OpARM64SUBshiftLL,
		ssa.OpARM64ANDshiftLL,
		ssa.OpARM64ORshiftLL,
		ssa.OpARM64XORshiftLL,
		ssa.OpARM64EONshiftLL,
		ssa.OpARM64ORNshiftLL,
		ssa.OpARM64BICshiftLL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm64.SHIFT_LL, v.AuxInt)
	case ssa.OpARM64ADDshiftRL,
		ssa.OpARM64SUBshiftRL,
		ssa.OpARM64ANDshiftRL,
		ssa.OpARM64ORshiftRL,
		ssa.OpARM64XORshiftRL,
		ssa.OpARM64EONshiftRL,
		ssa.OpARM64ORNshiftRL,
		ssa.OpARM64BICshiftRL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm64.SHIFT_LR, v.AuxInt)
	case ssa.OpARM64ADDshiftRA,
		ssa.OpARM64SUBshiftRA,
		ssa.OpARM64ANDshiftRA,
		ssa.OpARM64ORshiftRA,
		ssa.OpARM64XORshiftRA,
		ssa.OpARM64EONshiftRA,
		ssa.OpARM64ORNshiftRA,
		ssa.OpARM64BICshiftRA:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm64.SHIFT_AR, v.AuxInt)
	case ssa.OpARM64ANDshiftRO,
		ssa.OpARM64ORshiftRO,
		ssa.OpARM64XORshiftRO,
		ssa.OpARM64EONshiftRO,
		ssa.OpARM64ORNshiftRO,
		ssa.OpARM64BICshiftRO:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm64.SHIFT_ROR, v.AuxInt)
	case ssa.OpARM64MOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64FMOVSconst,
		ssa.OpARM64FMOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64FCMPS0,
		ssa.OpARM64FCMPD0:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(0)
		p.Reg = v.Args[0].Reg()
	case ssa.OpARM64CMP,
		ssa.OpARM64CMPW,
		ssa.OpARM64CMN,
		ssa.OpARM64CMNW,
		ssa.OpARM64TST,
		ssa.OpARM64TSTW,
		ssa.OpARM64FCMPS,
		ssa.OpARM64FCMPD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
	case ssa.OpARM64CMPconst,
		ssa.OpARM64CMPWconst,
		ssa.OpARM64CMNconst,
		ssa.OpARM64CMNWconst,
		ssa.OpARM64TSTconst,
		ssa.OpARM64TSTWconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
	case ssa.OpARM64CMPshiftLL, ssa.OpARM64CMNshiftLL, ssa.OpARM64TSTshiftLL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm64.SHIFT_LL, v.AuxInt)
	case ssa.OpARM64CMPshiftRL, ssa.OpARM64CMNshiftRL, ssa.OpARM64TSTshiftRL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm64.SHIFT_LR, v.AuxInt)
	case ssa.OpARM64CMPshiftRA, ssa.OpARM64CMNshiftRA, ssa.OpARM64TSTshiftRA:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm64.SHIFT_AR, v.AuxInt)
	case ssa.OpARM64TSTshiftRO:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm64.SHIFT_ROR, v.AuxInt)
	case ssa.OpARM64MOVDaddr:
		p := s.Prog(arm64.AMOVD)
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

		var wantreg string
		// MOVD $sym+off(base), R
		// the assembler expands it as the following:
		// - base is SP: add constant offset to SP (R13)
		//               when constant is large, tmp register (R11) may be used
		// - base is SB: load external address from constant pool (use relocation)
		switch v.Aux.(type) {
		default:
			v.Fatalf("aux is of unknown type %T", v.Aux)
		case *obj.LSym:
			wantreg = "SB"
			ssagen.AddAux(&p.From, v)
		case *ir.Name:
			wantreg = "SP"
			ssagen.AddAux(&p.From, v)
		case nil:
			// No sym, just MOVD $off(SP), R
			wantreg = "SP"
			p.From.Offset = v.AuxInt
		}
		if reg := v.Args[0].RegName(); reg != wantreg {
			v.Fatalf("bad reg %s for symbol type %T, want %s", reg, v.Aux, wantreg)
		}
	case ssa.OpARM64MOVBload,
		ssa.OpARM64MOVBUload,
		ssa.OpARM64MOVHload,
		ssa.OpARM64MOVHUload,
		ssa.OpARM64MOVWload,
		ssa.OpARM64MOVWUload,
		ssa.OpARM64MOVDload,
		ssa.OpARM64FMOVSload,
		ssa.OpARM64FMOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LDP:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REGREG
		p.To.Reg = v.Reg0()
		p.To.Offset = int64(v.Reg1())
	case ssa.OpARM64MOVBloadidx,
		ssa.OpARM64MOVBUloadidx,
		ssa.OpARM64MOVHloadidx,
		ssa.OpARM64MOVHUloadidx,
		ssa.OpARM64MOVWloadidx,
		ssa.OpARM64MOVWUloadidx,
		ssa.OpARM64MOVDloadidx,
		ssa.OpARM64FMOVSloadidx,
		ssa.OpARM64FMOVDloadidx,
		ssa.OpARM64MOVHloadidx2,
		ssa.OpARM64MOVHUloadidx2,
		ssa.OpARM64MOVWloadidx4,
		ssa.OpARM64MOVWUloadidx4,
		ssa.OpARM64MOVDloadidx8,
		ssa.OpARM64FMOVDloadidx8,
		ssa.OpARM64FMOVSloadidx4:
		p := s.Prog(v.Op.Asm())
		p.From = genIndexedOperand(v.Op, v.Args[0].Reg(), v.Args[1].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LDAR,
		ssa.OpARM64LDARB,
		ssa.OpARM64LDARW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpARM64MOVBstore,
		ssa.OpARM64MOVHstore,
		ssa.OpARM64MOVWstore,
		ssa.OpARM64MOVDstore,
		ssa.OpARM64FMOVSstore,
		ssa.OpARM64FMOVDstore,
		ssa.OpARM64STLRB,
		ssa.OpARM64STLR,
		ssa.OpARM64STLRW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpARM64MOVBstoreidx,
		ssa.OpARM64MOVHstoreidx,
		ssa.OpARM64MOVWstoreidx,
		ssa.OpARM64MOVDstoreidx,
		ssa.OpARM64FMOVSstoreidx,
		ssa.OpARM64FMOVDstoreidx,
		ssa.OpARM64MOVHstoreidx2,
		ssa.OpARM64MOVWstoreidx4,
		ssa.OpARM64FMOVSstoreidx4,
		ssa.OpARM64MOVDstoreidx8,
		ssa.OpARM64FMOVDstoreidx8:
		p := s.Prog(v.Op.Asm())
		p.To = genIndexedOperand(v.Op, v.Args[0].Reg(), v.Args[1].Reg())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
	case ssa.OpARM64STP:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REGREG
		p.From.Reg = v.Args[1].Reg()
		p.From.Offset = int64(v.Args[2].Reg())
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpARM64MOVBstorezero,
		ssa.OpARM64MOVHstorezero,
		ssa.OpARM64MOVWstorezero,
		ssa.OpARM64MOVDstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpARM64MOVBstorezeroidx,
		ssa.OpARM64MOVHstorezeroidx,
		ssa.OpARM64MOVWstorezeroidx,
		ssa.OpARM64MOVDstorezeroidx,
		ssa.OpARM64MOVHstorezeroidx2,
		ssa.OpARM64MOVWstorezeroidx4,
		ssa.OpARM64MOVDstorezeroidx8:
		p := s.Prog(v.Op.Asm())
		p.To = genIndexedOperand(v.Op, v.Args[0].Reg(), v.Args[1].Reg())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGZERO
	case ssa.OpARM64MOVQstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REGREG
		p.From.Reg = arm64.REGZERO
		p.From.Offset = int64(arm64.REGZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpARM64BFI,
		ssa.OpARM64BFXIL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt >> 8
		p.AddRestSourceConst(v.AuxInt & 0xff)
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64SBFIZ,
		ssa.OpARM64SBFX,
		ssa.OpARM64UBFIZ,
		ssa.OpARM64UBFX:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt >> 8
		p.AddRestSourceConst(v.AuxInt & 0xff)
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LoweredAtomicExchange64,
		ssa.OpARM64LoweredAtomicExchange32,
		ssa.OpARM64LoweredAtomicExchange8:
		// LDAXR	(Rarg0), Rout
		// STLXR	Rarg1, (Rarg0), Rtmp
		// CBNZ		Rtmp, -2(PC)
		var ld, st obj.As
		switch v.Op {
		case ssa.OpARM64LoweredAtomicExchange8:
			ld = arm64.ALDAXRB
			st = arm64.ASTLXRB
		case ssa.OpARM64LoweredAtomicExchange32:
			ld = arm64.ALDAXRW
			st = arm64.ASTLXRW
		case ssa.OpARM64LoweredAtomicExchange64:
			ld = arm64.ALDAXR
			st = arm64.ASTLXR
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		p1 := s.Prog(st)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Type = obj.TYPE_MEM
		p1.To.Reg = r0
		p1.RegTo2 = arm64.REGTMP
		p2 := s.Prog(arm64.ACBNZ)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = arm64.REGTMP
		p2.To.Type = obj.TYPE_BRANCH
		p2.To.SetTarget(p)
	case ssa.OpARM64LoweredAtomicExchange64Variant,
		ssa.OpARM64LoweredAtomicExchange32Variant,
		ssa.OpARM64LoweredAtomicExchange8Variant:
		var swap obj.As
		switch v.Op {
		case ssa.OpARM64LoweredAtomicExchange8Variant:
			swap = arm64.ASWPALB
		case ssa.OpARM64LoweredAtomicExchange32Variant:
			swap = arm64.ASWPALW
		case ssa.OpARM64LoweredAtomicExchange64Variant:
			swap = arm64.ASWPALD
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()

		// SWPALD	Rarg1, (Rarg0), Rout
		p := s.Prog(swap)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = r0
		p.RegTo2 = out

	case ssa.OpARM64LoweredAtomicAdd64,
		ssa.OpARM64LoweredAtomicAdd32:
		// LDAXR	(Rarg0), Rout
		// ADD		Rarg1, Rout
		// STLXR	Rout, (Rarg0), Rtmp
		// CBNZ		Rtmp, -3(PC)
		ld := arm64.ALDAXR
		st := arm64.ASTLXR
		if v.Op == ssa.OpARM64LoweredAtomicAdd32 {
			ld = arm64.ALDAXRW
			st = arm64.ASTLXRW
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		p1 := s.Prog(arm64.AADD)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out
		p2 := s.Prog(st)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = out
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = r0
		p2.RegTo2 = arm64.REGTMP
		p3 := s.Prog(arm64.ACBNZ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = arm64.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
	case ssa.OpARM64LoweredAtomicAdd64Variant,
		ssa.OpARM64LoweredAtomicAdd32Variant:
		// LDADDAL	Rarg1, (Rarg0), Rout
		// ADD		Rarg1, Rout
		op := arm64.ALDADDALD
		if v.Op == ssa.OpARM64LoweredAtomicAdd32Variant {
			op = arm64.ALDADDALW
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		p := s.Prog(op)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = r0
		p.RegTo2 = out
		p1 := s.Prog(arm64.AADD)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out
	case ssa.OpARM64LoweredAtomicCas64,
		ssa.OpARM64LoweredAtomicCas32:
		// LDAXR	(Rarg0), Rtmp
		// CMP		Rarg1, Rtmp
		// BNE		3(PC)
		// STLXR	Rarg2, (Rarg0), Rtmp
		// CBNZ		Rtmp, -4(PC)
		// CSET		EQ, Rout
		ld := arm64.ALDAXR
		st := arm64.ASTLXR
		cmp := arm64.ACMP
		if v.Op == ssa.OpARM64LoweredAtomicCas32 {
			ld = arm64.ALDAXRW
			st = arm64.ASTLXRW
			cmp = arm64.ACMPW
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		r2 := v.Args[2].Reg()
		out := v.Reg0()
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		p1 := s.Prog(cmp)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.Reg = arm64.REGTMP
		p2 := s.Prog(arm64.ABNE)
		p2.To.Type = obj.TYPE_BRANCH
		p3 := s.Prog(st)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = r2
		p3.To.Type = obj.TYPE_MEM
		p3.To.Reg = r0
		p3.RegTo2 = arm64.REGTMP
		p4 := s.Prog(arm64.ACBNZ)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = arm64.REGTMP
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p)
		p5 := s.Prog(arm64.ACSET)
		p5.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		p5.From.Offset = int64(arm64.SPOP_EQ)
		p5.To.Type = obj.TYPE_REG
		p5.To.Reg = out
		p2.To.SetTarget(p5)
	case ssa.OpARM64LoweredAtomicCas64Variant,
		ssa.OpARM64LoweredAtomicCas32Variant:
		// Rarg0: ptr
		// Rarg1: old
		// Rarg2: new
		// MOV  	Rarg1, Rtmp
		// CASAL	Rtmp, (Rarg0), Rarg2
		// CMP  	Rarg1, Rtmp
		// CSET 	EQ, Rout
		cas := arm64.ACASALD
		cmp := arm64.ACMP
		mov := arm64.AMOVD
		if v.Op == ssa.OpARM64LoweredAtomicCas32Variant {
			cas = arm64.ACASALW
			cmp = arm64.ACMPW
			mov = arm64.AMOVW
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		r2 := v.Args[2].Reg()
		out := v.Reg0()

		// MOV  	Rarg1, Rtmp
		p := s.Prog(mov)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP

		// CASAL	Rtmp, (Rarg0), Rarg2
		p1 := s.Prog(cas)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = arm64.REGTMP
		p1.To.Type = obj.TYPE_MEM
		p1.To.Reg = r0
		p1.RegTo2 = r2

		// CMP  	Rarg1, Rtmp
		p2 := s.Prog(cmp)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = r1
		p2.Reg = arm64.REGTMP

		// CSET 	EQ, Rout
		p3 := s.Prog(arm64.ACSET)
		p3.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		p3.From.Offset = int64(arm64.SPOP_EQ)
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = out

	case ssa.OpARM64LoweredAtomicAnd64,
		ssa.OpARM64LoweredAtomicOr64,
		ssa.OpARM64LoweredAtomicAnd32,
		ssa.OpARM64LoweredAtomicOr32,
		ssa.OpARM64LoweredAtomicAnd8,
		ssa.OpARM64LoweredAtomicOr8:
		// LDAXR[BW] (Rarg0), Rout
		// AND/OR	Rarg1, Rout, tmp1
		// STLXR[BW] tmp1, (Rarg0), Rtmp
		// CBNZ		Rtmp, -3(PC)
		ld := arm64.ALDAXR
		st := arm64.ASTLXR
		if v.Op == ssa.OpARM64LoweredAtomicAnd32 || v.Op == ssa.OpARM64LoweredAtomicOr32 {
			ld = arm64.ALDAXRW
			st = arm64.ASTLXRW
		}
		if v.Op == ssa.OpARM64LoweredAtomicAnd8 || v.Op == ssa.OpARM64LoweredAtomicOr8 {
			ld = arm64.ALDAXRB
			st = arm64.ASTLXRB
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		tmp := v.RegTmp()
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		p1 := s.Prog(v.Op.Asm())
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.Reg = out
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = tmp
		p2 := s.Prog(st)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = tmp
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = r0
		p2.RegTo2 = arm64.REGTMP
		p3 := s.Prog(arm64.ACBNZ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = arm64.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)

	case ssa.OpARM64LoweredAtomicAnd8Variant,
		ssa.OpARM64LoweredAtomicAnd32Variant,
		ssa.OpARM64LoweredAtomicAnd64Variant:
		atomic_clear := arm64.ALDCLRALD
		if v.Op == ssa.OpARM64LoweredAtomicAnd32Variant {
			atomic_clear = arm64.ALDCLRALW
		}
		if v.Op == ssa.OpARM64LoweredAtomicAnd8Variant {
			atomic_clear = arm64.ALDCLRALB
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()

		// MNV       Rarg1 Rtemp
		p := s.Prog(arm64.AMVN)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP

		// LDCLRAL[BDW]  Rtemp, (Rarg0), Rout
		p1 := s.Prog(atomic_clear)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = arm64.REGTMP
		p1.To.Type = obj.TYPE_MEM
		p1.To.Reg = r0
		p1.RegTo2 = out

	case ssa.OpARM64LoweredAtomicOr8Variant,
		ssa.OpARM64LoweredAtomicOr32Variant,
		ssa.OpARM64LoweredAtomicOr64Variant:
		atomic_or := arm64.ALDORALD
		if v.Op == ssa.OpARM64LoweredAtomicOr32Variant {
			atomic_or = arm64.ALDORALW
		}
		if v.Op == ssa.OpARM64LoweredAtomicOr8Variant {
			atomic_or = arm64.ALDORALB
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()

		// LDORAL[BDW]  Rarg1, (Rarg0), Rout
		p := s.Prog(atomic_or)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = r0
		p.RegTo2 = out

	case ssa.OpARM64MOVBreg,
		ssa.OpARM64MOVBUreg,
		ssa.OpARM64MOVHreg,
		ssa.OpARM64MOVHUreg,
		ssa.OpARM64MOVWreg,
		ssa.OpARM64MOVWUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpARM64MOVDreg {
			a = a.Args[0]
		}
		if a.Op == ssa.OpLoadReg {
			t := a.Type
			switch {
			case v.Op == ssa.OpARM64MOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpARM64MOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpARM64MOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpARM64MOVHUreg && t.Size() == 2 && !t.IsSigned(),
				v.Op == ssa.OpARM64MOVWreg && t.Size() == 4 && t.IsSigned(),
				v.Op == ssa.OpARM64MOVWUreg && t.Size() == 4 && !t.IsSigned():
				// arg is a proper-typed load, already zero/sign-extended, don't extend again
				if v.Reg() == v.Args[0].Reg() {
					return
				}
				p := s.Prog(arm64.AMOVD)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = v.Args[0].Reg()
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				return
			default:
			}
		}
		fallthrough
	case ssa.OpARM64MVN,
		ssa.OpARM64NEG,
		ssa.OpARM64FABSD,
		ssa.OpARM64FMOVDfpgp,
		ssa.OpARM64FMOVDgpfp,
		ssa.OpARM64FMOVSfpgp,
		ssa.OpARM64FMOVSgpfp,
		ssa.OpARM64FNEGS,
		ssa.OpARM64FNEGD,
		ssa.OpARM64FSQRTS,
		ssa.OpARM64FSQRTD,
		ssa.OpARM64FCVTZSSW,
		ssa.OpARM64FCVTZSDW,
		ssa.OpARM64FCVTZUSW,
		ssa.OpARM64FCVTZUDW,
		ssa.OpARM64FCVTZSS,
		ssa.OpARM64FCVTZSD,
		ssa.OpARM64FCVTZUS,
		ssa.OpARM64FCVTZUD,
		ssa.OpARM64SCVTFWS,
		ssa.OpARM64SCVTFWD,
		ssa.OpARM64SCVTFS,
		ssa.OpARM64SCVTFD,
		ssa.OpARM64UCVTFWS,
		ssa.OpARM64UCVTFWD,
		ssa.OpARM64UCVTFS,
		ssa.OpARM64UCVTFD,
		ssa.OpARM64FCVTSD,
		ssa.OpARM64FCVTDS,
		ssa.OpARM64REV,
		ssa.OpARM64REVW,
		ssa.OpARM64REV16,
		ssa.OpARM64REV16W,
		ssa.OpARM64RBIT,
		ssa.OpARM64RBITW,
		ssa.OpARM64CLZ,
		ssa.OpARM64CLZW,
		ssa.OpARM64FRINTAD,
		ssa.OpARM64FRINTMD,
		ssa.OpARM64FRINTND,
		ssa.OpARM64FRINTPD,
		ssa.OpARM64FRINTZD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LoweredRound32F, ssa.OpARM64LoweredRound64F:
		// input is already rounded
	case ssa.OpARM64VCNT:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = (v.Args[0].Reg()-arm64.REG_F0)&31 + arm64.REG_ARNG + ((arm64.ARNG_8B & 15) << 5)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = (v.Reg()-arm64.REG_F0)&31 + arm64.REG_ARNG + ((arm64.ARNG_8B & 15) << 5)
	case ssa.OpARM64VUADDLV:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = (v.Args[0].Reg()-arm64.REG_F0)&31 + arm64.REG_ARNG + ((arm64.ARNG_8B & 15) << 5)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg() - arm64.REG_F0 + arm64.REG_V0
	case ssa.OpARM64CSEL, ssa.OpARM64CSEL0:
		r1 := int16(arm64.REGZERO)
		if v.Op != ssa.OpARM64CSEL0 {
			r1 = v.Args[1].Reg()
		}
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		condCode := condBits[ssa.Op(v.AuxInt)]
		p.From.Offset = int64(condCode)
		p.Reg = v.Args[0].Reg()
		p.AddRestSourceReg(r1)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64CSINC, ssa.OpARM64CSINV, ssa.OpARM64CSNEG:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		condCode := condBits[ssa.Op(v.AuxInt)]
		p.From.Offset = int64(condCode)
		p.Reg = v.Args[0].Reg()
		p.AddRestSourceReg(v.Args[1].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64CSETM:
		p := s.Prog(arm64.ACSETM)
		p.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		condCode := condBits[ssa.Op(v.AuxInt)]
		p.From.Offset = int64(condCode)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64DUFFZERO:
		// runtime.duffzero expects start address in R20
		p := s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = v.AuxInt
	case ssa.OpARM64LoweredZero:
		// STP.P	(ZR,ZR), 16(R16)
		// CMP	Rarg1, R16
		// BLE	-2(PC)
		// arg1 is the address of the last 16-byte unit to zero
		p := s.Prog(arm64.ASTP)
		p.Scond = arm64.C_XPOST
		p.From.Type = obj.TYPE_REGREG
		p.From.Reg = arm64.REGZERO
		p.From.Offset = int64(arm64.REGZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REG_R16
		p.To.Offset = 16
		p2 := s.Prog(arm64.ACMP)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Args[1].Reg()
		p2.Reg = arm64.REG_R16
		p3 := s.Prog(arm64.ABLE)
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
	case ssa.OpARM64DUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffcopy
		p.To.Offset = v.AuxInt
	case ssa.OpARM64LoweredMove:
		// LDP.P	16(R16), (R25, Rtmp)
		// STP.P	(R25, Rtmp), 16(R17)
		// CMP	Rarg2, R16
		// BLE	-3(PC)
		// arg2 is the address of the last element of src
		p := s.Prog(arm64.ALDP)
		p.Scond = arm64.C_XPOST
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = arm64.REG_R16
		p.From.Offset = 16
		p.To.Type = obj.TYPE_REGREG
		p.To.Reg = arm64.REG_R25
		p.To.Offset = int64(arm64.REGTMP)
		p2 := s.Prog(arm64.ASTP)
		p2.Scond = arm64.C_XPOST
		p2.From.Type = obj.TYPE_REGREG
		p2.From.Reg = arm64.REG_R25
		p2.From.Offset = int64(arm64.REGTMP)
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = arm64.REG_R17
		p2.To.Offset = 16
		p3 := s.Prog(arm64.ACMP)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[2].Reg()
		p3.Reg = arm64.REG_R16
		p4 := s.Prog(arm64.ABLE)
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p)
	case ssa.OpARM64CALLstatic, ssa.OpARM64CALLclosure, ssa.OpARM64CALLinter:
		s.Call(v)
	case ssa.OpARM64CALLtail:
		s.TailCall(v)
	case ssa.OpARM64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]

	case ssa.OpARM64LoweredPanicBoundsA, ssa.OpARM64LoweredPanicBoundsB, ssa.OpARM64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(16) // space used in callee args area by assembly stubs
	case ssa.OpARM64LoweredNilCheck:
		// Issue a load which will fault if arg is nil.
		p := s.Prog(arm64.AMOVB)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Line==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}
	case ssa.OpARM64Equal,
		ssa.OpARM64NotEqual,
		ssa.OpARM64LessThan,
		ssa.OpARM64LessEqual,
		ssa.OpARM64GreaterThan,
		ssa.OpARM64GreaterEqual,
		ssa.OpARM64LessThanU,
		ssa.OpARM64LessEqualU,
		ssa.OpARM64GreaterThanU,
		ssa.OpARM64GreaterEqualU,
		ssa.OpARM64LessThanF,
		ssa.OpARM64LessEqualF,
		ssa.OpARM64GreaterThanF,
		ssa.OpARM64GreaterEqualF,
		ssa.OpARM64NotLessThanF,
		ssa.OpARM64NotLessEqualF,
		ssa.OpARM64NotGreaterThanF,
		ssa.OpARM64NotGreaterEqualF,
		ssa.OpARM64LessThanNoov,
		ssa.OpARM64GreaterEqualNoov:
		// generate boolean values using CSET
		p := s.Prog(arm64.ACSET)
		p.From.Type = obj.TYPE_SPECIAL // assembler encodes conditional bits in Offset
		condCode := condBits[v.Op]
		p.From.Offset = int64(condCode)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64PRFM:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = v.AuxInt
	case ssa.OpARM64LoweredGetClosurePtr:
		// Closure pointer is R26 (arm64.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpARM64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(arm64.AMOVD)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64DMB:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
	case ssa.OpARM64FlagConstant:
		v.Fatalf("FlagConstant op should never make it to codegen %v", v.LongString())
	case ssa.OpARM64InvertFlags:
		v.Fatalf("InvertFlags should never make it to codegen %v", v.LongString())
	case ssa.OpClobber:
		// MOVW	$0xdeaddead, REGTMP
		// MOVW	REGTMP, (slot)
		// MOVW	REGTMP, 4(slot)
		p := s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0xdeaddead
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		p = s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGTMP
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGSP
		ssagen.AddAux(&p.To, v)
		p = s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGTMP
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGSP
		ssagen.AddAux2(&p.To, v, v.AuxInt+4)
	case ssa.OpClobberReg:
		x := uint64(0xdeaddeaddeaddead)
		p := s.Prog(arm64.AMOVD)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(x)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var condBits = map[ssa.Op]arm64.SpecialOperand{
	ssa.OpARM64Equal:         arm64.SPOP_EQ,
	ssa.OpARM64NotEqual:      arm64.SPOP_NE,
	ssa.OpARM64LessThan:      arm64.SPOP_LT,
	ssa.OpARM64LessThanU:     arm64.SPOP_LO,
	ssa.OpARM64LessEqual:     arm64.SPOP_LE,
	ssa.OpARM64LessEqualU:    arm64.SPOP_LS,
	ssa.OpARM64GreaterThan:   arm64.SPOP_GT,
	ssa.OpARM64GreaterThanU:  arm64.SPOP_HI,
	ssa.OpARM64GreaterEqual:  arm64.SPOP_GE,
	ssa.OpARM64GreaterEqualU: arm64.SPOP_HS,
	ssa.OpARM64LessThanF:     arm64.SPOP_MI, // Less than
	ssa.OpARM64LessEqualF:    arm64.SPOP_LS, // Less than or equal to
	ssa.OpARM64GreaterThanF:  arm64.SPOP_GT, // Greater than
	ssa.OpARM64GreaterEqualF: arm64.SPOP_GE, // Greater than or equal to

	// The following condition codes have unordered to handle comparisons related to NaN.
	ssa.OpARM64NotLessThanF:     arm64.SPOP_PL, // Greater than, equal to, or unordered
	ssa.OpARM64NotLessEqualF:    arm64.SPOP_HI, // Greater than or unordered
	ssa.OpARM64NotGreaterThanF:  arm64.SPOP_LE, // Less than, equal to or unordered
	ssa.OpARM64NotGreaterEqualF: arm64.SPOP_LT, // Less than or unordered

	ssa.OpARM64LessThanNoov:     arm64.SPOP_MI, // Less than but without honoring overflow
	ssa.OpARM64GreaterEqualNoov: arm64.SPOP_PL, // Greater than or equal to but without honoring overflow
}

var blockJump = map[ssa.BlockKind]struct {
	asm, invasm obj.As
}{
	ssa.BlockARM64EQ:     {arm64.ABEQ, arm64.ABNE},
	ssa.BlockARM64NE:     {arm64.ABNE, arm64.ABEQ},
	ssa.BlockARM64LT:     {arm64.ABLT, arm64.ABGE},
	ssa.BlockARM64GE:     {arm64.ABGE, arm64.ABLT},
	ssa.BlockARM64LE:     {arm64.ABLE, arm64.ABGT},
	ssa.BlockARM64GT:     {arm64.ABGT, arm64.ABLE},
	ssa.BlockARM64ULT:    {arm64.ABLO, arm64.ABHS},
	ssa.BlockARM64UGE:    {arm64.ABHS, arm64.ABLO},
	ssa.BlockARM64UGT:    {arm64.ABHI, arm64.ABLS},
	ssa.BlockARM64ULE:    {arm64.ABLS, arm64.ABHI},
	ssa.BlockARM64Z:      {arm64.ACBZ, arm64.ACBNZ},
	ssa.BlockARM64NZ:     {arm64.ACBNZ, arm64.ACBZ},
	ssa.BlockARM64ZW:     {arm64.ACBZW, arm64.ACBNZW},
	ssa.BlockARM64NZW:    {arm64.ACBNZW, arm64.ACBZW},
	ssa.BlockARM64TBZ:    {arm64.ATBZ, arm64.ATBNZ},
	ssa.BlockARM64TBNZ:   {arm64.ATBNZ, arm64.ATBZ},
	ssa.BlockARM64FLT:    {arm64.ABMI, arm64.ABPL},
	ssa.BlockARM64FGE:    {arm64.ABGE, arm64.ABLT},
	ssa.BlockARM64FLE:    {arm64.ABLS, arm64.ABHI},
	ssa.BlockARM64FGT:    {arm64.ABGT, arm64.ABLE},
	ssa.BlockARM64LTnoov: {arm64.ABMI, arm64.ABPL},
	ssa.BlockARM64GEnoov: {arm64.ABPL, arm64.ABMI},
}

// To model a 'LEnoov' ('<=' without overflow checking) branching.
var leJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm64.ABEQ, Index: 0}, {Jump: arm64.ABPL, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm64.ABMI, Index: 0}, {Jump: arm64.ABEQ, Index: 0}}, // next == b.Succs[1]
}

// To model a 'GTnoov' ('>' without overflow checking) branching.
var gtJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm64.ABMI, Index: 1}, {Jump: arm64.ABEQ, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm64.ABEQ, Index: 1}, {Jump: arm64.ABPL, Index: 0}}, // next == b.Succs[1]
}

func ssaGenBlock(s *ssagen.State, b, next *ssa.Block) {
	switch b.Kind {
	case ssa.BlockPlain:
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}

	case ssa.BlockDefer:
		// defer returns in R0:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(arm64.ACMP)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0
		p.Reg = arm64.REG_R0
		p = s.Prog(arm64.ABNE)
		p.To.Type = obj.TYPE_BRANCH
		s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[1].Block()})
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}

	case ssa.BlockExit, ssa.BlockRetJmp:

	case ssa.BlockRet:
		s.Prog(obj.ARET)

	case ssa.BlockARM64EQ, ssa.BlockARM64NE,
		ssa.BlockARM64LT, ssa.BlockARM64GE,
		ssa.BlockARM64LE, ssa.BlockARM64GT,
		ssa.BlockARM64ULT, ssa.BlockARM64UGT,
		ssa.BlockARM64ULE, ssa.BlockARM64UGE,
		ssa.BlockARM64Z, ssa.BlockARM64NZ,
		ssa.BlockARM64ZW, ssa.BlockARM64NZW,
		ssa.BlockARM64FLT, ssa.BlockARM64FGE,
		ssa.BlockARM64FLE, ssa.BlockARM64FGT,
		ssa.BlockARM64LTnoov, ssa.BlockARM64GEnoov:
		jmp := blockJump[b.Kind]
		var p *obj.Prog
		switch next {
		case b.Succs[0].Block():
			p = s.Br(jmp.invasm, b.Succs[1].Block())
		case b.Succs[1].Block():
			p = s.Br(jmp.asm, b.Succs[0].Block())
		default:
			if b.Likely != ssa.BranchUnlikely {
				p = s.Br(jmp.asm, b.Succs[0].Block())
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				p = s.Br(jmp.invasm, b.Succs[1].Block())
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}
		if !b.Controls[0].Type.IsFlags() {
			p.From.Type = obj.TYPE_REG
			p.From.Reg = b.Controls[0].Reg()
		}
	case ssa.BlockARM64TBZ, ssa.BlockARM64TBNZ:
		jmp := blockJump[b.Kind]
		var p *obj.Prog
		switch next {
		case b.Succs[0].Block():
			p = s.Br(jmp.invasm, b.Succs[1].Block())
		case b.Succs[1].Block():
			p = s.Br(jmp.asm, b.Succs[0].Block())
		default:
			if b.Likely != ssa.BranchUnlikely {
				p = s.Br(jmp.asm, b.Succs[0].Block())
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				p = s.Br(jmp.invasm, b.Succs[1].Block())
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}
		p.From.Offset = b.AuxInt
		p.From.Type = obj.TYPE_CONST
		p.Reg = b.Controls[0].Reg()

	case ssa.BlockARM64LEnoov:
		s.CombJump(b, next, &leJumps)
	case ssa.BlockARM64GTnoov:
		s.CombJump(b, next, &gtJumps)

	case ssa.BlockARM64JUMPTABLE:
		// MOVD	(TABLE)(IDX<<3), Rtmp
		// JMP	(Rtmp)
		p := s.Prog(arm64.AMOVD)
		p.From = genIndexedOperand(ssa.OpARM64MOVDloadidx8, b.Controls[1].Reg(), b.Controls[0].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		p = s.Prog(obj.AJMP)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGTMP
		// Save jump tables for later resolution of the target blocks.
		s.JumpTables = append(s.JumpTables, b)

	default:
		b.Fatalf("branch not implemented: %s", b.LongString())
	}
}

func loadRegResult(s *ssagen.State, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p := s.Prog(loadByType(t))
	p.From.Type = obj.TYPE_MEM
	p.From.Name = obj.NAME_AUTO
	p.From.Sym = n.Linksym()
	p.From.Offset = n.FrameOffset() + off
	p.To.Type = obj.TYPE_REG
	p.To.Reg = reg
	return p
}

func spillArgReg(pp *objw.Progs, p *obj.Prog, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p = pp.Append(p, storeByType(t), obj.TYPE_REG, reg, 0, obj.TYPE_MEM, 0, n.FrameOffset()+off)
	p.To.Name = obj.NAME_PARAM
	p.To.Sym = n.Linksym()
	p.Pos = p.Pos.WithNotStmt()
	return p
}
```