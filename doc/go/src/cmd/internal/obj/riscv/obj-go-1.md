Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of a specific Go file related to RISC-V assembly within the Go compiler. The key is to understand what this code *does* within the larger context of compiling Go code for the RISC-V architecture.

2. **Initial Scan for Keywords and Patterns:**  Quickly scan the code for important keywords and recognizable patterns. This helps to form initial hypotheses. Some things that stand out:
    * `package obj`:  Indicates this is part of the `cmd/internal/obj` package, dealing with object file manipulation and architecture-specific logic.
    * `riscv`:  Confirms the target architecture.
    * `instruction`:  Suggests this code is involved in creating or manipulating RISC-V instructions.
    * `obj.Prog`:  A central data structure in the Go assembler representing an assembly program instruction.
    * `instructionsFor...`:  Functions with this naming pattern strongly suggest the conversion of high-level assembly instructions into lower-level machine instructions.
    * `MOV`, `ADD`, `LUI`, `SLLI`, etc.: These are recognizable RISC-V assembly mnemonics.
    * `assemble`: This function name hints at the final stage of code generation where instructions are turned into binary data.
    * `objabi.R_RISCV_*`:  Relocation types specific to RISC-V, indicating how addresses are resolved during linking.
    * Conditional logic based on `buildcfg.GORISCV64`:  Indicates handling of differences between the RV32 and RV64 architectures.
    * Error handling (`p.Ctxt.Diag`):  The code performs validation and reports errors.

3. **Focus on Key Functions:**  The `instructionsForProg` function appears to be the core logic for translating Go assembly instructions (`obj.Prog`) into sequences of machine instructions (`[]*instruction`). This is a natural starting point for deeper analysis.

4. **Analyze `instructionsForProg`:**
    * **Input:** Takes an `obj.Prog` (Go assembly instruction).
    * **Output:** Returns a slice of `*instruction` (RISC-V machine instructions).
    * **Logic:**  It uses a `switch` statement based on the `ins.as` field (the RISC-V assembly opcode). Each `case` handles a different instruction type.
    * **`instructionsForMOV`:**  This function is called for `AMOV` variants, indicating specific handling for move instructions.
    * **`instructionsForLoad/Store`:**  These functions handle memory access operations.
    * **`instructionsForOpImmediate`:**  Handles instructions with immediate operands.
    * **`instructionsForRotate`:**  Deals with bitwise rotation instructions, with special handling for architectures without native rotation support.
    * **Other Cases:**  Handles various other RISC-V instructions, often with code to synthesize them from simpler instructions or to set specific instruction fields.

5. **Analyze `instructionsForMOV`:** This function seems complex, suggesting that `MOV` instructions have various forms and need careful translation.
    * **Constants:**  Handles loading constants into registers, including splitting large constants into `LUI` (load upper immediate) and `ADDI` (add immediate) instructions.
    * **Register-to-Register Moves:**  Translates `MOV` into equivalent RISC-V instructions like `ADDI $0, Ra, Rb`.
    * **Memory Access:**  Calls `instructionsForLoad` and `instructionsForStore`.
    * **Address Loading:** Handles loading the addresses of symbols.

6. **Analyze `assemble`:** This function is responsible for the final code generation.
    * **Relocations:**  It iterates through the instructions and adds relocation entries to the object file. Relocations are necessary when the final address of a symbol is not known until linking time. The code checks `p.Mark` to see if a relocation is needed.
    * **Instruction Encoding:** It calls `ins.encode()` to convert the `instruction` struct into its binary representation.
    * **Padding:**  Handles `obj.APCALIGN` to insert NOP instructions for alignment.

7. **Infer Higher-Level Functionality:** Based on the detailed analysis, we can infer the broader purpose of the code:
    * **RISC-V Code Generation:** The code is responsible for translating Go's intermediate representation of assembly code into actual RISC-V machine instructions.
    * **Instruction Selection and Synthesis:** It selects the appropriate RISC-V instructions for a given Go assembly operation and sometimes synthesizes complex instructions from simpler ones (e.g., rotations, negations on architectures without those instructions).
    * **Constant Handling:**  It efficiently handles the loading of constants, even those that don't fit into a single immediate field.
    * **Memory Access:** It manages load and store operations, considering different addressing modes.
    * **Relocation Information:** It generates relocation information needed by the linker.
    * **Architecture-Specific Optimizations/Workarounds:**  The conditional logic based on `buildcfg.GORISCV64` shows that the code adapts to different RISC-V sub-architectures.

8. **Construct Examples (Mental or Actual):**  Think about simple Go code snippets and how they might be translated by this code. For instance:
    * `var x int = 10`:  This might lead to `MOV $10, Rx`.
    * `a := b`:  This could become `MOV Rb, Ra`.
    * `c := &someGlobal`:  This would involve address loading using `AUIPC` and `ADDI`.

9. **Identify Potential Pitfalls:**  Think about situations where a user might make a mistake when writing assembly code that this code processes. The error messages in the code provide clues. For example, trying to load a constant into a memory location directly is flagged as an error.

10. **Synthesize the Summary:**  Combine the findings from the analysis into a concise summary that highlights the key functionalities and its role in the Go compilation process for RISC-V.

This detailed breakdown demonstrates how to approach understanding a piece of compiler code. It involves a combination of scanning, detailed analysis of key functions, inferring higher-level purpose, and thinking about concrete examples and potential issues.
这是 `go/src/cmd/internal/obj/riscv/obj.go` 文件的第二部分代码，它延续了第一部分的功能，主要负责将 Go 语言的汇编指令转换为 RISC-V 机器码。

**功能归纳：**

这部分代码的核心功能是 **将 Go 语言的 RISC-V 汇编指令 `obj.Prog` 结构体转换为一个或多个 RISC-V 机器指令 `instruction` 结构体，并最终生成可执行的机器码。** 它涵盖了多种指令的处理，包括：

* **MOV 指令的各种形式:**  常量加载、寄存器到寄存器移动、内存加载和存储、地址加载等。
* **旋转指令:**  ROL (循环左移), ROR (循环右移) 及其立即数版本。
* **其他算术、逻辑和控制流指令:**  例如 JAL, BEQ, ADDI, ANDI 等。
* **浮点指令:**  包括浮点数的移动、比较、运算、类型转换等。
* **原子指令:**  例如 LR.W, SC.W, AMO 操作等。
* **CSR (控制和状态寄存器) 操作指令:** 例如 ECALL, EBREAK, RDCYCLE 等。
* **内存屏障指令:** FENCE。

**更详细的功能分解：**

1. **`instructionsForMOV(p *obj.Prog)`:**  处理 `MOV` 指令的不同变体。
    * **常量加载:** 将常量加载到寄存器。对于大于 12 位的常量，会使用 `LUI` 和 `ADDI` 指令组合。
    * **寄存器到寄存器移动:**  根据不同的数据类型（整数、浮点数，有符号/无符号扩展），转换为相应的 RISC-V 指令，例如 `ADDI $0, Ra, Rb`，或者使用符号扩展/零扩展指令。
    * **内存加载 (TYPE_MEM -> TYPE_REG):**  调用 `instructionsForLoad` 函数生成加载指令。对于外部符号和静态符号，会使用 `AUIPC` 和加载指令的组合来实现 PC 相对寻址。
    * **内存存储 (TYPE_REG -> TYPE_MEM):** 调用 `instructionsForStore` 函数生成存储指令。对于外部符号和静态符号，也会使用 `AUIPC` 和存储指令的组合。
    * **地址加载 (TYPE_ADDR -> TYPE_REG):**  将地址加载到寄存器。对于外部符号和静态符号，使用 `AUIPC` 和 `ADDI` 的组合。

2. **`instructionsForRotate(p *obj.Prog, ins *instruction)`:** 处理位旋转指令（ROL, ROR）。
    * 如果 RISC-V 架构支持原生旋转指令（buildcfg.GORISCV64 >= 22），则直接返回该指令。
    * 否则，使用移位和或运算来模拟旋转操作。

3. **`instructionsForProg(p *obj.Prog)`:**  这是核心函数，根据 `obj.Prog` 指令的类型 (`ins.as`)，调用相应的辅助函数来生成 RISC-V 机器指令。
    * 它处理了各种 RISC-V 指令的编码，包括 JAL/JALR 的跳转目标、条件分支指令的条件和目标地址、MOV 指令的各种情况、加载/存储指令、原子指令、浮点指令等等。
    * 对于一些伪指令或复杂的指令，它可能会生成多个 RISC-V 机器指令来完成操作（例如，用移位和或模拟旋转，用 `LUI` 和 `ADDI` 加载大常量）。
    * 对于一些指令，它会进行指令的转换或参数的调整，例如将 `BEQZ` 转换为 `BEQ REG_ZERO, Rx`。
    * 对于某些浮点指令，它会处理舍入模式的设置。
    * 它还会处理一些特殊的指令，例如 `ANEG` (取负数) 和 `ANOT` (按位取反)，将其转换为 RISC-V 的基本算术和逻辑指令。

4. **`assemble(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc)`:**  在汇编过程的最后阶段被调用，负责将生成的 `instruction` 结构体编码成实际的机器码，并写入到符号表 (`cursym`) 中。
    * **处理重定位:**  对于需要在链接时才能确定地址的指令（例如，跳转到外部函数，访问全局变量），会添加重定位信息 (`obj.Reloc`)，告知链接器如何修改这些指令。
    * **编码指令:**  调用 `ins.encode()` 方法将 `instruction` 结构体转换为二进制机器码。
    * **处理 PC 对齐:**  对于 `obj.APCALIGN` 指令，会插入 NOP 指令以保证代码按照指定的字节数对齐。

5. **`isUnsafePoint(p *obj.Prog)`:**  判断某个指令是否是不安全点，这可能与栈扫描和垃圾回收有关。

6. **`ParseSuffix(prog *obj.Prog, cond string)`:**  解析浮点指令的后缀，例如舍入模式。

**Go 代码示例 (基于推理)：**

假设有以下 Go 代码：

```go
package main

func main() {
	var a int = 100000 // 一个需要 LUI 和 ADDI 的常量
	var b int = 5
	c := a + b
	println(c)
}
```

编译到 RISC-V 汇编后，可能会有类似以下的 `obj.Prog` 结构体（简化表示）：

```
// ... 一些初始化代码 ...
MOV $100000, R10  // 将常量 100000 加载到寄存器 R10
MOV $5, R11      // 将常量 5 加载到寄存器 R11
ADD R10, R11, R12 // 将 R10 和 R11 的值相加，结果存到 R12
// ... 调用 println ...
```

`instructionsForMOV` 函数在处理 `MOV $100000, R10` 时，由于 100000 (0x186A0) 大于 12 位，会将其拆分成 `LUI` 和 `ADDI` 指令：

```
假设输入 p 指向代表 "MOV $100000, R10" 的 obj.Prog
假设 p.To.Reg 为 10 (代表 R10)
假设 p.From.Type 为 obj.TYPE_CONST，p.From.Offset 为 100000

输出的 inss 为:
&instruction{as: ALUI, rd: 10, imm: 0x1} // LUI R10, 0x1
&instruction{as: AADDIW, rd: 10, rs1: 10, imm: 0x86a0} // ADDIW R10, R10, 0x86a0
```

在处理 `ADD R10, R11, R12` 时，`instructionsForProg` 会生成相应的 `AADD` 指令。

**命令行参数处理：**

这部分代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `go tool compile` 的更上层。但是，`buildcfg.GORISCV64` 这样的配置信息可能由命令行参数间接影响，例如通过 `-target` 或 `-GOARCH` 等标志。

**使用者易犯错的点（基于代码推断）：**

* **尝试将常量加载到内存地址：**  代码中有 `case p.From.Type == obj.TYPE_CONST && p.To.Type != obj.TYPE_REG:` 的错误处理，说明直接将常量加载到内存地址是不允许的，必须先加载到寄存器。
  ```go
  // 错误示例 (假设的汇编语法)
  // MOV $10, (0x1000)  // 尝试将常量 10 存储到内存地址 0x1000，这是不允许的
  ```

* **`MOV` 指令目标不是寄存器 (当源是常量或地址时):**  代码中检查了 `p.From.Type == obj.TYPE_CONST && p.To.Type != obj.TYPE_REG` 和 `p.From.Type == obj.TYPE_ADDR && p.To.Type != obj.TYPE_REG` 的情况，如果目标不是寄存器，则会报错。

* **不正确的立即数范围:**  对于移位指令 (`ASLLI`, `ASRLI`, `ASRAI` 等)，立即数的范围有限制 (0-63 或 0-31)。如果使用了超出范围的立即数，`instructionsForProg` 会报错。

总而言之，这部分代码是 Go 语言 RISC-V 后端的关键组成部分，负责将抽象的汇编指令转换为底层的机器码，并处理了各种 RISC-V 特有的指令和寻址模式。它在 Go 语言编译到 RISC-V 架构的过程中扮演着至关重要的角色。

### 提示词
```
这是路径为go/src/cmd/internal/obj/riscv/obj.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
mes
		// 	MOV $1, X10
		// 	SLLI $63, X10, X10
		var insSLLI *instruction
		if err := immIFits(ins.imm, 32); err != nil {
			ctz := bits.TrailingZeros64(uint64(ins.imm))
			if err := immIFits(ins.imm>>ctz, 32); err == nil {
				ins.imm = ins.imm >> ctz
				insSLLI = &instruction{as: ASLLI, rd: ins.rd, rs1: ins.rd, imm: int64(ctz)}
			}
		}

		low, high, err := Split32BitImmediate(ins.imm)
		if err != nil {
			p.Ctxt.Diag("%v: constant %d too large: %v", p, ins.imm, err)
			return nil
		}

		// MOV $c, R -> ADD $c, ZERO, R
		ins.as, ins.rs1, ins.rs2, ins.imm = AADDI, REG_ZERO, obj.REG_NONE, low

		// LUI is only necessary if the constant does not fit in 12 bits.
		if high != 0 {
			// LUI top20bits(c), R
			// ADD bottom12bits(c), R, R
			insLUI := &instruction{as: ALUI, rd: ins.rd, imm: high}
			inss = []*instruction{insLUI}
			if low != 0 {
				ins.as, ins.rs1 = AADDIW, ins.rd
				inss = append(inss, ins)
			}
		}
		if insSLLI != nil {
			inss = append(inss, insSLLI)
		}

	case p.From.Type == obj.TYPE_CONST && p.To.Type != obj.TYPE_REG:
		p.Ctxt.Diag("%v: constant load must target register", p)
		return nil

	case p.From.Type == obj.TYPE_REG && p.To.Type == obj.TYPE_REG:
		// Handle register to register moves.
		switch p.As {
		case AMOV: // MOV Ra, Rb -> ADDI $0, Ra, Rb
			ins.as, ins.rs1, ins.rs2, ins.imm = AADDI, uint32(p.From.Reg), obj.REG_NONE, 0
		case AMOVW: // MOVW Ra, Rb -> ADDIW $0, Ra, Rb
			ins.as, ins.rs1, ins.rs2, ins.imm = AADDIW, uint32(p.From.Reg), obj.REG_NONE, 0
		case AMOVBU: // MOVBU Ra, Rb -> ANDI $255, Ra, Rb
			ins.as, ins.rs1, ins.rs2, ins.imm = AANDI, uint32(p.From.Reg), obj.REG_NONE, 255
		case AMOVF: // MOVF Ra, Rb -> FSGNJS Ra, Ra, Rb
			ins.as, ins.rs1 = AFSGNJS, uint32(p.From.Reg)
		case AMOVD: // MOVD Ra, Rb -> FSGNJD Ra, Ra, Rb
			ins.as, ins.rs1 = AFSGNJD, uint32(p.From.Reg)
		case AMOVB, AMOVH:
			if buildcfg.GORISCV64 >= 22 {
				// Use SEXTB or SEXTH to extend.
				ins.as, ins.rs1, ins.rs2 = ASEXTB, uint32(p.From.Reg), obj.REG_NONE
				if p.As == AMOVH {
					ins.as = ASEXTH
				}
			} else {
				// Use SLLI/SRAI sequence to extend.
				ins.as, ins.rs1, ins.rs2 = ASLLI, uint32(p.From.Reg), obj.REG_NONE
				if p.As == AMOVB {
					ins.imm = 56
				} else if p.As == AMOVH {
					ins.imm = 48
				}
				ins2 := &instruction{as: ASRAI, rd: ins.rd, rs1: ins.rd, imm: ins.imm}
				inss = append(inss, ins2)
			}
		case AMOVHU, AMOVWU:
			if buildcfg.GORISCV64 >= 22 {
				// Use ZEXTH or ADDUW to extend.
				ins.as, ins.rs1, ins.rs2, ins.imm = AZEXTH, uint32(p.From.Reg), obj.REG_NONE, 0
				if p.As == AMOVWU {
					ins.as, ins.rs2 = AADDUW, REG_ZERO
				}
			} else {
				// Use SLLI/SRLI sequence to extend.
				ins.as, ins.rs1, ins.rs2 = ASLLI, uint32(p.From.Reg), obj.REG_NONE
				if p.As == AMOVHU {
					ins.imm = 48
				} else if p.As == AMOVWU {
					ins.imm = 32
				}
				ins2 := &instruction{as: ASRLI, rd: ins.rd, rs1: ins.rd, imm: ins.imm}
				inss = append(inss, ins2)
			}
		}

	case p.From.Type == obj.TYPE_MEM && p.To.Type == obj.TYPE_REG:
		// Memory to register loads.
		switch p.From.Name {
		case obj.NAME_AUTO, obj.NAME_PARAM, obj.NAME_NONE:
			// MOV c(Rs), Rd -> L $c, Rs, Rd
			inss = instructionsForLoad(p, movToLoad(p.As), addrToReg(p.From))

		case obj.NAME_EXTERN, obj.NAME_STATIC:
			if p.From.Sym.Type == objabi.STLSBSS {
				return instructionsForTLSLoad(p)
			}

			// Note that the values for $off_hi and $off_lo are currently
			// zero and will be assigned during relocation.
			//
			// AUIPC $off_hi, Rd
			// L $off_lo, Rd, Rd
			insAUIPC := &instruction{as: AAUIPC, rd: ins.rd}
			ins.as, ins.rs1, ins.rs2, ins.imm = movToLoad(p.As), ins.rd, obj.REG_NONE, 0
			inss = []*instruction{insAUIPC, ins}

		default:
			p.Ctxt.Diag("unsupported name %d for %v", p.From.Name, p)
			return nil
		}

	case p.From.Type == obj.TYPE_REG && p.To.Type == obj.TYPE_MEM:
		// Register to memory stores.
		switch p.As {
		case AMOVBU, AMOVHU, AMOVWU:
			p.Ctxt.Diag("%v: unsupported unsigned store", p)
			return nil
		}
		switch p.To.Name {
		case obj.NAME_AUTO, obj.NAME_PARAM, obj.NAME_NONE:
			// MOV Rs, c(Rd) -> S $c, Rs, Rd
			inss = instructionsForStore(p, movToStore(p.As), addrToReg(p.To))

		case obj.NAME_EXTERN, obj.NAME_STATIC:
			if p.To.Sym.Type == objabi.STLSBSS {
				return instructionsForTLSStore(p)
			}

			// Note that the values for $off_hi and $off_lo are currently
			// zero and will be assigned during relocation.
			//
			// AUIPC $off_hi, Rtmp
			// S $off_lo, Rtmp, Rd
			insAUIPC := &instruction{as: AAUIPC, rd: REG_TMP}
			ins.as, ins.rd, ins.rs1, ins.rs2, ins.imm = movToStore(p.As), REG_TMP, uint32(p.From.Reg), obj.REG_NONE, 0
			inss = []*instruction{insAUIPC, ins}

		default:
			p.Ctxt.Diag("unsupported name %d for %v", p.From.Name, p)
			return nil
		}

	case p.From.Type == obj.TYPE_ADDR && p.To.Type == obj.TYPE_REG:
		// MOV $sym+off(SP/SB), R
		if p.As != AMOV {
			p.Ctxt.Diag("%v: unsupported address load", p)
			return nil
		}
		switch p.From.Name {
		case obj.NAME_AUTO, obj.NAME_PARAM, obj.NAME_NONE:
			inss = instructionsForOpImmediate(p, AADDI, addrToReg(p.From))

		case obj.NAME_EXTERN, obj.NAME_STATIC:
			// Note that the values for $off_hi and $off_lo are currently
			// zero and will be assigned during relocation.
			//
			// AUIPC $off_hi, R
			// ADDI $off_lo, R
			insAUIPC := &instruction{as: AAUIPC, rd: ins.rd}
			ins.as, ins.rs1, ins.rs2, ins.imm = AADDI, ins.rd, obj.REG_NONE, 0
			inss = []*instruction{insAUIPC, ins}

		default:
			p.Ctxt.Diag("unsupported name %d for %v", p.From.Name, p)
			return nil
		}

	case p.From.Type == obj.TYPE_ADDR && p.To.Type != obj.TYPE_REG:
		p.Ctxt.Diag("%v: address load must target register", p)
		return nil

	default:
		p.Ctxt.Diag("%v: unsupported MOV", p)
		return nil
	}

	return inss
}

// instructionsForRotate returns the machine instructions for a bitwise rotation.
func instructionsForRotate(p *obj.Prog, ins *instruction) []*instruction {
	if buildcfg.GORISCV64 >= 22 {
		// Rotation instructions are supported natively.
		return []*instruction{ins}
	}

	switch ins.as {
	case AROL, AROLW, AROR, ARORW:
		// ROL -> OR (SLL x y) (SRL x (NEG y))
		// ROR -> OR (SRL x y) (SLL x (NEG y))
		sllOp, srlOp := ASLL, ASRL
		if ins.as == AROLW || ins.as == ARORW {
			sllOp, srlOp = ASLLW, ASRLW
		}
		shift1, shift2 := sllOp, srlOp
		if ins.as == AROR || ins.as == ARORW {
			shift1, shift2 = shift2, shift1
		}
		return []*instruction{
			&instruction{as: ASUB, rs1: REG_ZERO, rs2: ins.rs2, rd: REG_TMP},
			&instruction{as: shift2, rs1: ins.rs1, rs2: REG_TMP, rd: REG_TMP},
			&instruction{as: shift1, rs1: ins.rs1, rs2: ins.rs2, rd: ins.rd},
			&instruction{as: AOR, rs1: REG_TMP, rs2: ins.rd, rd: ins.rd},
		}

	case ARORI, ARORIW:
		// ROR -> OR (SLLI -x y) (SRLI x y)
		sllOp, srlOp := ASLLI, ASRLI
		sllImm := int64(int8(-ins.imm) & 63)
		if ins.as == ARORIW {
			sllOp, srlOp = ASLLIW, ASRLIW
			sllImm = int64(int8(-ins.imm) & 31)
		}
		return []*instruction{
			&instruction{as: srlOp, rs1: ins.rs1, rd: REG_TMP, imm: ins.imm},
			&instruction{as: sllOp, rs1: ins.rs1, rd: ins.rd, imm: sllImm},
			&instruction{as: AOR, rs1: REG_TMP, rs2: ins.rd, rd: ins.rd},
		}

	default:
		p.Ctxt.Diag("%v: unknown rotation", p)
		return nil
	}
}

// instructionsForProg returns the machine instructions for an *obj.Prog.
func instructionsForProg(p *obj.Prog) []*instruction {
	ins := instructionForProg(p)
	inss := []*instruction{ins}

	if len(p.RestArgs) > 1 {
		p.Ctxt.Diag("too many source registers")
		return nil
	}

	switch ins.as {
	case AJAL, AJALR:
		ins.rd, ins.rs1, ins.rs2 = uint32(p.From.Reg), uint32(p.To.Reg), obj.REG_NONE
		ins.imm = p.To.Offset

	case ABEQ, ABEQZ, ABGE, ABGEU, ABGEZ, ABGT, ABGTU, ABGTZ, ABLE, ABLEU, ABLEZ, ABLT, ABLTU, ABLTZ, ABNE, ABNEZ:
		switch ins.as {
		case ABEQZ:
			ins.as, ins.rs1, ins.rs2 = ABEQ, REG_ZERO, uint32(p.From.Reg)
		case ABGEZ:
			ins.as, ins.rs1, ins.rs2 = ABGE, REG_ZERO, uint32(p.From.Reg)
		case ABGT:
			ins.as, ins.rs1, ins.rs2 = ABLT, uint32(p.From.Reg), uint32(p.Reg)
		case ABGTU:
			ins.as, ins.rs1, ins.rs2 = ABLTU, uint32(p.From.Reg), uint32(p.Reg)
		case ABGTZ:
			ins.as, ins.rs1, ins.rs2 = ABLT, uint32(p.From.Reg), REG_ZERO
		case ABLE:
			ins.as, ins.rs1, ins.rs2 = ABGE, uint32(p.From.Reg), uint32(p.Reg)
		case ABLEU:
			ins.as, ins.rs1, ins.rs2 = ABGEU, uint32(p.From.Reg), uint32(p.Reg)
		case ABLEZ:
			ins.as, ins.rs1, ins.rs2 = ABGE, uint32(p.From.Reg), REG_ZERO
		case ABLTZ:
			ins.as, ins.rs1, ins.rs2 = ABLT, REG_ZERO, uint32(p.From.Reg)
		case ABNEZ:
			ins.as, ins.rs1, ins.rs2 = ABNE, REG_ZERO, uint32(p.From.Reg)
		}
		ins.imm = p.To.Offset

	case AMOV, AMOVB, AMOVH, AMOVW, AMOVBU, AMOVHU, AMOVWU, AMOVF, AMOVD:
		inss = instructionsForMOV(p)

	case ALW, ALWU, ALH, ALHU, ALB, ALBU, ALD, AFLW, AFLD:
		inss = instructionsForLoad(p, ins.as, p.From.Reg)

	case ASW, ASH, ASB, ASD, AFSW, AFSD:
		inss = instructionsForStore(p, ins.as, p.To.Reg)

	case ALRW, ALRD:
		// Set aq to use acquire access ordering
		ins.funct7 = 2
		ins.rs1, ins.rs2 = uint32(p.From.Reg), REG_ZERO

	case AADDI, AANDI, AORI, AXORI:
		inss = instructionsForOpImmediate(p, ins.as, p.Reg)

	case ASCW, ASCD:
		// Set release access ordering
		ins.funct7 = 1
		ins.rd, ins.rs1, ins.rs2 = uint32(p.RegTo2), uint32(p.To.Reg), uint32(p.From.Reg)

	case AAMOSWAPW, AAMOSWAPD, AAMOADDW, AAMOADDD, AAMOANDW, AAMOANDD, AAMOORW, AAMOORD,
		AAMOXORW, AAMOXORD, AAMOMINW, AAMOMIND, AAMOMINUW, AAMOMINUD, AAMOMAXW, AAMOMAXD, AAMOMAXUW, AAMOMAXUD:
		// Set aqrl to use acquire & release access ordering
		ins.funct7 = 3
		ins.rd, ins.rs1, ins.rs2 = uint32(p.RegTo2), uint32(p.To.Reg), uint32(p.From.Reg)

	case AECALL, AEBREAK:
		insEnc := encode(p.As)
		if p.To.Type == obj.TYPE_NONE {
			ins.rd = REG_ZERO
		}
		ins.rs1 = REG_ZERO
		ins.imm = insEnc.csr

	case ARDCYCLE, ARDTIME, ARDINSTRET:
		ins.as = ACSRRS
		if p.To.Type == obj.TYPE_NONE {
			ins.rd = REG_ZERO
		}
		ins.rs1 = REG_ZERO
		switch p.As {
		case ARDCYCLE:
			ins.imm = -1024
		case ARDTIME:
			ins.imm = -1023
		case ARDINSTRET:
			ins.imm = -1022
		}

	case AFENCE:
		ins.rd, ins.rs1, ins.rs2 = REG_ZERO, REG_ZERO, obj.REG_NONE
		ins.imm = 0x0ff

	case AFCVTWS, AFCVTLS, AFCVTWUS, AFCVTLUS, AFCVTWD, AFCVTLD, AFCVTWUD, AFCVTLUD:
		// Set the default rounding mode in funct3 to round to zero.
		if p.Scond&rmSuffixBit == 0 {
			ins.funct3 = uint32(RM_RTZ)
		} else {
			ins.funct3 = uint32(p.Scond &^ rmSuffixBit)
		}

	case AFNES, AFNED:
		// Replace FNE[SD] with FEQ[SD] and NOT.
		if p.To.Type != obj.TYPE_REG {
			p.Ctxt.Diag("%v needs an integer register output", p)
			return nil
		}
		if ins.as == AFNES {
			ins.as = AFEQS
		} else {
			ins.as = AFEQD
		}
		ins2 := &instruction{
			as:  AXORI, // [bit] xor 1 = not [bit]
			rd:  ins.rd,
			rs1: ins.rd,
			imm: 1,
		}
		inss = append(inss, ins2)

	case AFSQRTS, AFSQRTD:
		// These instructions expect a zero (i.e. float register 0)
		// to be the second input operand.
		ins.rs1 = uint32(p.From.Reg)
		ins.rs2 = REG_F0

	case AFMADDS, AFMSUBS, AFNMADDS, AFNMSUBS,
		AFMADDD, AFMSUBD, AFNMADDD, AFNMSUBD:
		// Swap the first two operands so that the operands are in the same
		// order as they are in the specification: RS1, RS2, RS3, RD.
		ins.rs1, ins.rs2 = ins.rs2, ins.rs1

	case ANEG, ANEGW:
		// NEG rs, rd -> SUB rs, X0, rd
		ins.as = ASUB
		if p.As == ANEGW {
			ins.as = ASUBW
		}
		ins.rs1 = REG_ZERO
		if ins.rd == obj.REG_NONE {
			ins.rd = ins.rs2
		}

	case ANOT:
		// NOT rs, rd -> XORI $-1, rs, rd
		ins.as = AXORI
		ins.rs1, ins.rs2 = uint32(p.From.Reg), obj.REG_NONE
		if ins.rd == obj.REG_NONE {
			ins.rd = ins.rs1
		}
		ins.imm = -1

	case ASEQZ:
		// SEQZ rs, rd -> SLTIU $1, rs, rd
		ins.as = ASLTIU
		ins.rs1, ins.rs2 = uint32(p.From.Reg), obj.REG_NONE
		ins.imm = 1

	case ASNEZ:
		// SNEZ rs, rd -> SLTU rs, x0, rd
		ins.as = ASLTU
		ins.rs1 = REG_ZERO

	case AFABSS:
		// FABSS rs, rd -> FSGNJXS rs, rs, rd
		ins.as = AFSGNJXS
		ins.rs1 = uint32(p.From.Reg)

	case AFABSD:
		// FABSD rs, rd -> FSGNJXD rs, rs, rd
		ins.as = AFSGNJXD
		ins.rs1 = uint32(p.From.Reg)

	case AFNEGS:
		// FNEGS rs, rd -> FSGNJNS rs, rs, rd
		ins.as = AFSGNJNS
		ins.rs1 = uint32(p.From.Reg)

	case AFNEGD:
		// FNEGD rs, rd -> FSGNJND rs, rs, rd
		ins.as = AFSGNJND
		ins.rs1 = uint32(p.From.Reg)

	case AROL, AROLW, AROR, ARORW:
		inss = instructionsForRotate(p, ins)

	case ARORI:
		if ins.imm < 0 || ins.imm > 63 {
			p.Ctxt.Diag("%v: immediate out of range 0 to 63", p)
		}
		inss = instructionsForRotate(p, ins)

	case ARORIW:
		if ins.imm < 0 || ins.imm > 31 {
			p.Ctxt.Diag("%v: immediate out of range 0 to 31", p)
		}
		inss = instructionsForRotate(p, ins)

	case ASLLI, ASRLI, ASRAI:
		if ins.imm < 0 || ins.imm > 63 {
			p.Ctxt.Diag("%v: immediate out of range 0 to 63", p)
		}

	case ASLLIW, ASRLIW, ASRAIW:
		if ins.imm < 0 || ins.imm > 31 {
			p.Ctxt.Diag("%v: immediate out of range 0 to 31", p)
		}

	case ACLZ, ACLZW, ACTZ, ACTZW, ACPOP, ACPOPW, ASEXTB, ASEXTH, AZEXTH:
		ins.rs1, ins.rs2 = uint32(p.From.Reg), obj.REG_NONE

	case AORCB, AREV8:
		ins.rd, ins.rs1, ins.rs2 = uint32(p.To.Reg), uint32(p.From.Reg), obj.REG_NONE

	case AANDN, AORN:
		if buildcfg.GORISCV64 >= 22 {
			// ANDN and ORN instructions are supported natively.
			break
		}
		// ANDN -> (AND (NOT x) y)
		// ORN  -> (OR  (NOT x) y)
		bitwiseOp, notReg := AAND, ins.rd
		if ins.as == AORN {
			bitwiseOp = AOR
		}
		if ins.rs1 == notReg {
			notReg = REG_TMP
		}
		inss = []*instruction{
			&instruction{as: AXORI, rs1: ins.rs2, rs2: obj.REG_NONE, rd: notReg, imm: -1},
			&instruction{as: bitwiseOp, rs1: ins.rs1, rs2: notReg, rd: ins.rd},
		}

	case AXNOR:
		if buildcfg.GORISCV64 >= 22 {
			// XNOR instruction is supported natively.
			break
		}
		// XNOR -> (NOT (XOR x y))
		ins.as = AXOR
		inss = append(inss, &instruction{as: AXORI, rs1: ins.rd, rs2: obj.REG_NONE, rd: ins.rd, imm: -1})
	}

	for _, ins := range inss {
		ins.p = p
	}

	return inss
}

// assemble emits machine code.
// It is called at the very end of the assembly process.
func assemble(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	if ctxt.Retpoline {
		ctxt.Diag("-spectre=ret not supported on riscv")
		ctxt.Retpoline = false // don't keep printing
	}

	// If errors were encountered during preprocess/validation, proceeding
	// and attempting to encode said instructions will only lead to panics.
	if ctxt.Errors > 0 {
		return
	}

	for p := cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case AJAL:
			if p.Mark&NEED_JAL_RELOC == NEED_JAL_RELOC {
				cursym.AddRel(ctxt, obj.Reloc{
					Type: objabi.R_RISCV_JAL,
					Off:  int32(p.Pc),
					Siz:  4,
					Sym:  p.To.Sym,
					Add:  p.To.Offset,
				})
			}
		case AJALR:
			if p.To.Sym != nil {
				ctxt.Diag("%v: unexpected AJALR with to symbol", p)
			}

		case AAUIPC, AMOV, AMOVB, AMOVH, AMOVW, AMOVBU, AMOVHU, AMOVWU, AMOVF, AMOVD:
			var addr *obj.Addr
			var rt objabi.RelocType
			if p.Mark&NEED_CALL_RELOC == NEED_CALL_RELOC {
				rt = objabi.R_RISCV_CALL
				addr = &p.From
			} else if p.Mark&NEED_PCREL_ITYPE_RELOC == NEED_PCREL_ITYPE_RELOC {
				rt = objabi.R_RISCV_PCREL_ITYPE
				addr = &p.From
			} else if p.Mark&NEED_PCREL_STYPE_RELOC == NEED_PCREL_STYPE_RELOC {
				rt = objabi.R_RISCV_PCREL_STYPE
				addr = &p.To
			} else {
				break
			}
			if p.As == AAUIPC {
				if p.Link == nil {
					ctxt.Diag("AUIPC needing PC-relative reloc missing following instruction")
					break
				}
				addr = &p.RestArgs[0].Addr
			}
			if addr.Sym == nil {
				ctxt.Diag("PC-relative relocation missing symbol")
				break
			}
			if addr.Sym.Type == objabi.STLSBSS {
				if ctxt.Flag_shared {
					rt = objabi.R_RISCV_TLS_IE
				} else {
					rt = objabi.R_RISCV_TLS_LE
				}
			}

			cursym.AddRel(ctxt, obj.Reloc{
				Type: rt,
				Off:  int32(p.Pc),
				Siz:  8,
				Sym:  addr.Sym,
				Add:  addr.Offset,
			})

		case obj.APCALIGN:
			alignedValue := p.From.Offset
			v := pcAlignPadLength(p.Pc, alignedValue)
			offset := p.Pc
			for ; v >= 4; v -= 4 {
				// NOP
				cursym.WriteBytes(ctxt, offset, []byte{0x13, 0, 0, 0})
				offset += 4
			}
			continue
		}

		offset := p.Pc
		for _, ins := range instructionsForProg(p) {
			if ic, err := ins.encode(); err == nil {
				cursym.WriteInt(ctxt, offset, ins.length(), int64(ic))
				offset += int64(ins.length())
			}
			if ins.usesRegTmp() {
				p.Mark |= USES_REG_TMP
			}
		}
	}

	obj.MarkUnsafePoints(ctxt, cursym.Func().Text, newprog, isUnsafePoint, nil)
}

func isUnsafePoint(p *obj.Prog) bool {
	return p.Mark&USES_REG_TMP == USES_REG_TMP || p.From.Reg == REG_TMP || p.To.Reg == REG_TMP || p.Reg == REG_TMP
}

func ParseSuffix(prog *obj.Prog, cond string) (err error) {
	switch prog.As {
	case AFCVTWS, AFCVTLS, AFCVTWUS, AFCVTLUS, AFCVTWD, AFCVTLD, AFCVTWUD, AFCVTLUD:
		prog.Scond, err = rmSuffixEncode(strings.TrimPrefix(cond, "."))
	}
	return
}

var LinkRISCV64 = obj.LinkArch{
	Arch:           sys.ArchRISCV64,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       assemble,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: RISCV64DWARFRegisters,
}
```