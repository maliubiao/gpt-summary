Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the RISC-V assembler within the Go compiler.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code is in `go/src/cmd/internal/obj/riscv/obj.go`. The `obj` package deals with object code manipulation. The `riscv` directory indicates it's specific to the RISC-V architecture. Therefore, the primary function is handling RISC-V assembly instructions.

2. **Analyze key functions:**  Look for prominent function names and their roles:
    * `instructionsForMOV`: Handles `MOV` instructions, which are fundamental for data movement.
    * `instructionsForRotate`: Deals with bitwise rotation operations.
    * `instructionsForProg`:  The central function to process a single assembly program instruction (`obj.Prog`).
    * `assemble`:  The final stage where machine code is generated.
    * Helper functions like `instructionForProg`, `instructionsForLoad`, `instructionsForStore`, `instructionsForOpImmediate`.

3. **Categorize functionalities:** Group related actions together:
    * **Instruction Translation:** The core task is converting high-level assembly instructions into low-level machine instructions. This involves handling different operand types (registers, constants, memory addresses).
    * **Special Instruction Handling:** Specific instructions like `MOV`, rotations, jumps, branches, and floating-point operations have custom logic.
    * **Address Handling:**  The code deals with different address modes (register direct, immediate offsets, PC-relative addressing).
    * **Relocation:** The `assemble` function handles relocations, necessary for linking code.
    * **Optimization/Transformation:**  The code performs some instruction transformations (e.g., implementing rotations using shifts and OR).
    * **Error Handling:**  The code includes checks for invalid operands and out-of-range immediates.
    * **Architecture-Specific Logic:** The code considers differences between RISC-V 32-bit and 64-bit architectures (e.g., native rotation instructions).

4. **Infer Go language feature implementation:** Based on the code's role in handling assembly, it's a core part of the Go compiler's **assembler**. The `obj` package is used internally by the compiler to represent and manipulate assembly code.

5. **Illustrate with Go code examples:** Choose a simple, common assembly instruction and show how it might be translated. `MOV` is a good choice. Demonstrate different `MOV` scenarios (register-to-register, constant-to-register).

6. **Describe command-line parameters:** Since this is part of the compiler's internal workings, there aren't direct command-line parameters exposed *by this specific file*. However, the broader Go toolchain (`go build`, `go assemble`) uses command-line flags. Mention the `-spectre` flag as an example based on the code's check.

7. **Identify potential errors:** Look for common pitfalls:
    * Incorrect operand types for instructions.
    * Out-of-range immediate values.
    * Trying to load constants into memory directly.

8. **Summarize the entire functionality (as requested in part 3):** Combine the categorized functionalities into a concise summary.

9. **Review and refine:** Ensure the language is clear, accurate, and addresses all aspects of the prompt. Use appropriate terminology (e.g., "machine code," "relocation"). Organize the answer logically.

**(Self-Correction during thought process):**

* Initially, I might focus too much on the individual instruction handling functions. It's important to step back and identify the overarching purpose – it's about the RISC-V assembler.
* I need to be careful not to overstate the impact of command-line flags *within this specific file*. It's more about how the Go compiler uses these functions.
* The examples should be simple and illustrate the core concepts without getting bogged down in complex scenarios.
这段Go语言代码是Go编译器中用于将RISC-V汇编指令转换为机器码的关键部分。它属于`go/src/cmd/internal/obj/riscv`包，专门处理RISC-V架构的汇编。

**功能归纳 (第3部分):**

总的来说，这段代码的主要功能是**将RISC-V架构的Go汇编语言指令翻译成最终的机器码指令**。它涵盖了多种RISC-V指令的处理，包括数据移动、算术运算、逻辑运算、跳转、分支以及浮点运算等。

**详细功能列举:**

1. **指令识别和分解:** `instructionsForProg` 函数是核心，它接收一个 `obj.Prog` 类型的汇编指令，并根据指令的操作码 (`p.As`) 分配到不同的处理逻辑。
2. **数据移动指令 (MOV):** `instructionsForMOV` 函数处理各种 `MOV` 指令，包括：
   - 常数加载到寄存器：将立即数加载到寄存器，如果立即数过大，会分解成 `LUI` (Load Upper Immediate) 和 `ADDI` 指令。
   - 寄存器到寄存器移动：通过 `ADDI $0, Ra, Rb` 等指令实现。
   - 内存加载到寄存器：使用 `instructionsForLoad` 函数，根据不同的寻址模式生成相应的加载指令 (`LW`, `LH`, `LB` 等)。
   - 寄存器存储到内存：使用 `instructionsForStore` 函数，生成相应的存储指令 (`SW`, `SH`, `SB` 等)。
   - 地址加载到寄存器：将内存地址加载到寄存器，涉及到 `AUIPC` (Add Upper Immediate to PC) 和 `ADDI` 指令。
3. **旋转指令:** `instructionsForRotate` 函数处理位旋转指令 (`ROL`, `ROR` 等)，如果目标架构支持硬件旋转指令，则直接使用，否则会使用移位和或运算的组合来模拟。
4. **其他指令处理:** `instructionsForProg` 函数中还包含了对其他各种 RISC-V 指令的处理，例如：
   - 跳转和链接指令 (`JAL`, `JALR`)
   - 分支指令 (`BEQ`, `BNE`, `BLT` 等)
   - 算术和逻辑运算指令 (`ADDI`, `ANDI`, `ORI`, `XORI` 等)
   - 原子操作指令 (`AMOSWAPW`, `AAMOADDW` 等)
   - 系统调用和断点指令 (`ECALL`, `EBREAK`)
   - 读 CSR 寄存器指令 (`RDCYCLE`, `RDTIME`, `RDINSTRET`)
   - 浮点运算指令 (`FCVTWS`, `AFNES`, `FSQRTS` 等)
   - 伪指令的转换，例如 `NEG` 转换成 `SUB X0, rd`，`NOT` 转换成 `XORI $-1, rs, rd` 等。
5. **指令编码:** `assemble` 函数遍历所有的汇编指令，并调用 `instructionsForProg` 获取其对应的机器码指令序列，然后调用 `ins.encode()` 将指令编码为二进制机器码。
6. **重定位处理:** `assemble` 函数中还处理了重定位，用于处理需要链接时才能确定的地址，例如函数调用、全局变量访问等。对于不同的重定位类型 (`R_RISCV_JAL`, `R_RISCV_CALL`, `R_RISCV_PCREL_ITYPE` 等)，会添加相应的重定位条目。
7. **PC 对齐:**  处理 `obj.APCALIGN` 指令，在代码中插入 `NOP` 指令以实现代码地址的对齐。

**Go语言功能实现推断及代码示例:**

这段代码是 Go 编译器中 **RISC-V 后端汇编器** 的一部分实现。它负责将 Go 汇编代码（通常由编译器生成，也可以由开发者手动编写）转换成机器码。

**示例：MOV 指令的翻译**

假设有以下 Go 汇编代码片段：

```assembly
MOV $1234, R10 // 将立即数 1234 加载到寄存器 R10
MOV R10, R11   // 将寄存器 R10 的值移动到寄存器 R11
```

以下是 `instructionsForMOV` 函数可能如何处理这些指令（假设输入 `p` 对应相应的 `obj.Prog` 结构）：

**场景 1: `MOV $1234, R10`**

**假设输入:**
```go
p := &obj.Prog{
    As: obj.AMOV,
    From: obj.Addr{Type: obj.TYPE_CONST, Offset: 1234},
    To:   obj.Addr{Type: obj.TYPE_REG, Reg: 10},
}
ins := &instruction{rd: 10} // 初始化 instruction
```

**代码片段 (obj.go):**

```go
case p.From.Type == obj.TYPE_CONST && p.To.Type == obj.TYPE_REG:
    low, high, err := Split32BitImmediate(ins.imm) // ins.imm 应该为 1234
    // ... (省略了错误处理)
    ins.as, ins.rs1, ins.rs2, ins.imm = AADDI, REG_ZERO, obj.REG_NONE, low // AADDI 是 ADDI 指令的助记符

    if high != 0 {
        // 对于更大的立即数，会生成 LUI 指令
        insLUI := &instruction{as: ALUI, rd: ins.rd, imm: high}
        inss = []*instruction{insLUI}
        if low != 0 {
            ins.as, ins.rs1 = AADDIW, ins.rd
            inss = append(inss, ins)
        }
    }
```

**可能的输出 (如果 1234 能放入 12 位立即数):**
```go
inss = []*instruction{&instruction{as: AADDI, rd: 10, rs1: 0, imm: 1234}}
```
这将被编码成 RISC-V 的 `addi x10, x0, 1234` 指令。

**场景 2: `MOV R10, R11`**

**假设输入:**
```go
p := &obj.Prog{
    As: obj.AMOV,
    From: obj.Addr{Type: obj.TYPE_REG, Reg: 10},
    To:   obj.Addr{Type: obj.TYPE_REG, Reg: 11},
}
ins := &instruction{rd: 11} // 初始化 instruction
```

**代码片段 (obj.go):**

```go
case p.From.Type == obj.TYPE_REG && p.To.Type == obj.TYPE_REG:
    switch p.As {
    case AMOV: // MOV Ra, Rb -> ADDI $0, Ra, Rb
        ins.as, ins.rs1, ins.rs2, ins.imm = AADDI, uint32(p.From.Reg), obj.REG_NONE, 0
    // ...
    }
```

**可能的输出:**
```go
inss = []*instruction{&instruction{as: AADDI, rd: 11, rs1: 10, imm: 0}}
```
这将被编码成 RISC-V 的 `addi x11, x10, 0` 指令。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。但是，作为 Go 编译工具链的一部分，它会受到编译选项的影响。例如：

- **`-spectre=...`**:  `assemble` 函数中检查了 `ctxt.Retpoline`，这与 `-spectre` 编译选项有关，用于缓解 Spectre 漏洞。如果设置了 `-spectre=ret`，代码会报错，因为 RISC-V 架构尚不支持该缓解措施。

**使用者易犯错的点:**

虽然开发者通常不直接编写 `obj.Prog` 结构，但在编写 Go 汇编代码时，一些常见的错误会被这段代码捕获并报错：

- **常量加载目标不是寄存器:**
  ```assembly
  MOV $10, 0(R10) // 错误：不能将常量直接加载到内存
  ```
  这段代码会触发 `p.Ctxt.Diag("%v: constant load must target register", p)` 错误。

- **不支持的无符号存储:**
  ```assembly
  MOVWU R10, 0(R11) // 错误：不支持无符号存储指令
  ```
  这段代码会触发 `p.Ctxt.Diag("%v: unsupported unsigned store", p)` 错误。

- **地址加载目标不是寄存器:**
  ```assembly
  MOV sym(SB), 0(R10) // 错误：地址加载必须目标寄存器
  ```
  这段代码会触发 `p.Ctxt.Diag("%v: address load must target register", p)` 错误。

- **立即数超出范围:** 例如旋转指令的立即数必须在 0-63 或 0-31 之间。

这段代码是 Go 编译器 RISC-V 后端的核心组成部分，负责将抽象的汇编指令转化为具体的机器码，为 Go 程序在 RISC-V 架构上的运行奠定了基础。

### 提示词
```
这是路径为go/src/cmd/internal/obj/riscv/obj.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
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