Response:
Let's break down the thought process for summarizing the functionality of the provided Go code snippet.

1. **Initial Scan and Keyword Identification:**  The first step is to quickly scan the code, looking for keywords and patterns. I see `case` statements, arithmetic operations (`|=`, `&`), bit shifting (`<<`), and function calls like `c.opbfm`, `c.opbit`, `c.opirr`, etc. This immediately tells me this code is likely part of an instruction encoder or assembler, translating high-level instructions into machine code. The `case` numbers suggest a dispatch table based on instruction types.

2. **Focusing on the `case` Structure:** The core structure is a `switch` statement based on a number (likely representing an opcode or instruction type index). Each `case` handles a different instruction format or family. This is the most important structural element to understand.

3. **Analyzing Individual `case` Blocks:**  I start examining individual `case` blocks. I notice patterns:
    * **Fetching Operands:**  Extracting register numbers (`p.From.Reg`, `p.To.Reg`, `p.Reg`, `p.RegTo2`), immediate values (`p.From.Offset`), and potentially other operand information.
    * **Bit Manipulation:** Performing bitwise OR operations (`|=`) to assemble the instruction word (`o1`, `o2`, `o3`). Bit shifting is used to place the operand values in the correct bit positions.
    * **Helper Functions:** Calls to functions like `c.opbfm`, `c.opirr`, `c.opload`, `c.opstore`, `c.brdist`, etc. These functions likely handle common instruction encoding patterns or specific instruction types.
    * **Error Handling:**  Calls to `c.ctxt.Diag` indicate error checking for invalid operands, arrangements, or other issues.
    * **Relocation Handling:** `c.cursym.AddRel` suggests the code deals with relocations, which are necessary when generating code that needs to be loaded at different memory addresses.
    * **Vector Instructions (SIMD):** The presence of `V` registers (`Vm`, `Vn`, `Vd`) and terms like "arrangement" strongly suggest support for ARM's Advanced SIMD (NEON) instructions.
    * **Atomic Instructions:**  `atomicLDADD`, `atomicSWP` point to the handling of atomic memory operations.

4. **Identifying Recurring Themes:**  As I analyze more `case` blocks, I identify common themes:
    * **Register Manipulation:**  Moving data between registers, performing arithmetic and logical operations.
    * **Memory Access:** Loading and storing data from memory (with various addressing modes).
    * **Control Flow:** Branch instructions (although not explicitly shown in this snippet, they are likely handled elsewhere or implied by the branching logic within some cases).
    * **Special Instructions:**  Instructions like `cls`, `sys`, `dmb`, `hint`.
    * **Floating-Point Operations:**  Instructions starting with `A` and involving `float64`.

5. **Inferring the Purpose of Helper Functions:** Based on the patterns of usage, I can infer the purpose of some helper functions:
    * `c.opirr`: Likely encodes instructions with register and immediate operands.
    * `c.oprrr`: Likely encodes instructions with three register operands.
    * `c.opload`/`c.opstore`: Encode load and store instructions.
    * `c.brdist`: Calculates branch distances.
    * `c.oaddi`: Encodes addition with immediate values.
    * `c.omovconst`: Encodes moving constant values into registers.
    * `c.olsr12u`:  Potentially encodes load/store with register offset.

6. **Connecting to Go Language Features:**  While the code itself is low-level assembly manipulation, I can connect it to higher-level Go concepts:
    * **Compiler Backend:** This code is part of the Go compiler's backend for the ARM64 architecture. It's responsible for translating Go's intermediate representation into machine code.
    * **`cmd/internal/obj`:** This package is part of Go's internal tooling for object file manipulation, further solidifying its role in the compilation process.

7. **Synthesizing the Summary:** Based on the analysis, I start constructing the summary, focusing on the key functions:
    * Instruction encoding for various ARM64 instructions.
    * Handling different operand types (registers, immediates, memory addresses).
    * Support for SIMD instructions.
    * Relocation processing.
    * Error detection.

8. **Refining the Summary:** I review the initial summary and refine it for clarity and conciseness. I emphasize the core purpose of instruction encoding and the breadth of supported instruction types. I also mention the connection to the Go compiler.

This iterative process of scanning, analyzing, identifying patterns, inferring purpose, and synthesizing allows for a comprehensive understanding and summary of the code's functionality, even without deep knowledge of every specific instruction encoding.
这段代码是Go语言编译器的一部分，负责将中间表示形式的ARM64指令编码成实际的机器码。它是`asm7.go`文件的第五部分，主要处理了大量的ARM64指令的编码逻辑。

**核心功能归纳：**

这段代码的主要功能是根据输入的指令结构体 `p` (类型为 `obj.Prog`)，以及指令的操作码 `p.As`，将指令的各个部分（如源寄存器、目标寄存器、立即数等）编码到机器指令的二进制表示 `o1`, `o2`, `o3` 中。

**更具体的功能点包括：**

* **处理多种ARM64指令:**  代码中大量的 `case` 语句对应着不同的ARM64指令，例如：
    * 数据处理指令 (例如 `ADD`, `SUB`, `AND`, `ORR`, `EOR`)
    * 内存访问指令 (例如 `LDR`, `STR`, `LDP`, `STP`)
    * 分支指令 (例如 `B`, `BL`, 间接跳转)
    * 位域操作指令 (例如 `SXTW`, `UXTB`)
    * 原子操作指令 (例如 `SWP`, `LDADD`)
    * 系统指令 (例如 `SYS`, `SYSL`, `DMB`, `HINT`)
    * 浮点运算指令 (例如 `FADDD`, `FMULS`, `FCMPD`)
    * SIMD (NEON) 指令 (例如 `VADD`, `VSUB`, `VMOV`, `VLD`, `VST`)
    * 地址加载指令 (例如 `ADRP`, `ADR`)
* **处理不同的寻址模式:**  代码中针对不同的操作数类型和组合，采用了不同的编码方式，例如：
    * 寄存器寻址
    * 立即数寻址
    * 寄存器偏移寻址 (带或不带扩展和移位)
    * PC相对寻址 (用于分支和加载地址)
* **处理立即数编码:**  对于立即数，代码会根据其大小和指令的要求进行编码，例如 `bitconEncode` 函数用于编码特定的位掩码。
* **处理SIMD指令的排列方式 (Arrangement):** 代码中多次出现对 `ARNG_` 常量的检查，这是为了确保SIMD指令的操作数具有正确的向量元素类型和大小。
* **处理链接和重定位:**  对于涉及到符号地址的指令，代码会生成重定位信息，以便链接器在最终生成可执行文件时填充正确的地址。 例如 `c.cursym.AddRel`。
* **错误检测:**  代码中包含了大量的错误检查，例如检查寄存器是否非法，立即数是否超出范围，SIMD指令的操作数排列是否匹配等等，并通过 `c.ctxt.Diag` 输出错误信息。
* **处理常量池:**  对于无法直接编码的大立即数或地址，代码会使用常量池，并在指令中加载常量池中的值。

**它是什么go语言功能的实现：**

这段代码是 **Go语言编译器后端针对ARM64架构的代码生成器** 的一部分。它负责将Go语言的中间表示形式（SSA或其他形式）转换为目标机器的汇编指令，并最终编码成机器码。

**Go代码举例说明（假设）：**

假设有以下Go代码：

```go
package main

func main() {
    a := 10
    b := 20
    c := a + b
    println(c)
}
```

Go编译器在编译这段代码时，会生成类似以下的ARM64汇编指令（这是一个简化的例子，实际可能更复杂）：

```assembly
// ... 前面的代码 ...
MOV (R0), #10     // 将立即数 10 加载到寄存器 R0 (对应变量 a)
MOV (R1), #20     // 将立即数 20 加载到寄存器 R1 (对应变量 b)
ADD (R2), R0, R1  // 将 R0 和 R1 的值相加，结果存入 R2 (对应变量 c)
// ... 调用 println 函数的代码 ...
```

`asm7.go` 中的这段代码就负责将类似 `ADD (R2), R0, R1` 这样的汇编指令编码成二进制机器码。例如，当 `p.As` 是 `AADD` (ARM64的ADD指令)，并且源寄存器是 `R0` 和 `R1`，目标寄存器是 `R2` 时，代码会计算出对应的二进制编码并赋值给 `o1`。

**代码推理（带上假设的输入与输出）：**

假设输入的 `p` 指令结构体表示 `ADD X1, X2, X3` (将寄存器 X2 和 X3 的值相加，结果存入 X1)：

* **假设输入:**
    * `p.As = AADD` (ARM64的ADD指令)
    * `p.To.Type = obj.TYPE_REG`, `p.To.Reg = REG_R1` (目标寄存器 X1)
    * `p.From.Type = obj.TYPE_REG`, `p.From.Reg = REG_R2` (第一个源寄存器 X2)
    * `p.Reg = REG_R3` (第二个源寄存器 X3)

* **代码执行过程（简化）：**
    * 进入 `switch o.type_ { ... case 1: ... case 2: ... case 3: ... }` 的某个分支 (假设 `o.type_` 对应 `AADD` 指令的类型)
    * 进入 `switch p.As { ... case AADD: ... }` 分支
    * `o1 = c.oprrr(p, p.As)`  (调用 `oprrr` 函数，根据指令类型设置 `o1` 的一些通用位)
    * `o1 |= uint32(p.From.Reg&31) << 16`  (将源寄存器 X2 的编号编码到 `o1` 的相应位)
    * `o1 |= uint32(p.Reg&31) << 5`   (将源寄存器 X3 的编号编码到 `o1` 的相应位)
    * `o1 |= uint32(p.To.Reg & 31)`  (将目标寄存器 X1 的编号编码到 `o1` 的相应位)

* **假设输出:**
    * `o1` 的值会是一个32位的整数，其二进制表示就是 `ADD X1, X2, X3` 指令的机器码 (例如，可能为 `0b10001011000000100001000000000001`)。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的前端部分（例如 `go/src/cmd/compile/internal/gc`）。 `asm7.go` 接收的是已经解析过的中间表示指令。

**使用者易犯错的点：**

这段代码是编译器内部实现，开发者通常不会直接接触。但是，理解其功能有助于理解Go编译器的工作原理以及ARM64架构的指令编码。

**总结这段代码的功能：**

总而言之，`go/src/cmd/internal/obj/arm64/asm7.go` 的这一部分是 **Go语言编译器中将ARM64汇编指令翻译成机器码的核心模块**。它通过一系列的 `case` 语句和位操作，针对不同的ARM64指令格式和操作数类型，生成正确的二进制指令编码。这是Go语言能够运行在ARM64架构上的关键组成部分。

### 提示词
```
这是路径为go/src/cmd/internal/obj/arm64/asm7.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
rf, rt)

		case ASXTHW:
			o1 = c.opbfm(p, ASBFMW, 0, 15, rf, rt)

		case AUXTBW:
			o1 = c.opbfm(p, AUBFMW, 0, 7, rf, rt)

		case AUXTHW:
			o1 = c.opbfm(p, AUBFMW, 0, 15, rf, rt)

		default:
			c.ctxt.Diag("bad sxt %v", as)
			break
		}

	case 46: /* cls */
		o1 = c.opbit(p, p.As)

		o1 |= uint32(p.From.Reg&31) << 5
		o1 |= uint32(p.To.Reg & 31)

	case 47: // SWPx/LDADDx/LDCLRx/LDEORx/LDORx/CASx Rs, (Rb), Rt
		rs := p.From.Reg
		rt := p.RegTo2
		rb := p.To.Reg

		// rt can't be sp.
		if rt == REG_RSP {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}

		o1 = atomicLDADD[p.As] | atomicSWP[p.As]
		o1 |= uint32(rs&31)<<16 | uint32(rb&31)<<5 | uint32(rt&31)

	case 48: /* ADD $C_ADDCON2, Rm, Rd */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		op := c.opirr(p, p.As)
		if op&Sbit != 0 {
			c.ctxt.Diag("can not break addition/subtraction when S bit is set", p)
		}
		rt, r := p.To.Reg, p.Reg
		if r == obj.REG_NONE {
			r = rt
		}
		o1 = c.oaddi(p, p.As, c.regoff(&p.From)&0x000fff, rt, r)
		o2 = c.oaddi(p, p.As, c.regoff(&p.From)&0xfff000, rt, rt)

	case 49: /* op Vm.<T>, Vn, Vd */
		o1 = c.oprrr(p, p.As)
		cf := c.aclass(&p.From)
		af := (p.From.Reg >> 5) & 15
		sz := ARNG_4S
		if p.As == ASHA512H || p.As == ASHA512H2 {
			sz = ARNG_2D
		}
		if cf == C_ARNG && af != int16(sz) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= uint32(p.From.Reg&31)<<16 | uint32(p.Reg&31)<<5 | uint32(p.To.Reg&31)

	case 50: /* sys/sysl */
		o1 = c.opirr(p, p.As)

		if (p.From.Offset &^ int64(SYSARG4(0x7, 0xF, 0xF, 0x7))) != 0 {
			c.ctxt.Diag("illegal SYS argument\n%v", p)
		}
		o1 |= uint32(p.From.Offset)
		if p.To.Type == obj.TYPE_REG {
			o1 |= uint32(p.To.Reg & 31)
		} else {
			o1 |= 0x1F
		}

	case 51: /* dmb */
		o1 = c.opirr(p, p.As)

		if p.From.Type == obj.TYPE_CONST {
			o1 |= uint32((p.From.Offset & 0xF) << 8)
		}

	case 52: /* hint */
		o1 = c.opirr(p, p.As)

		o1 |= uint32((p.From.Offset & 0x7F) << 5)

	case 53: /* and/or/eor/bic/tst/... $bitcon, Rn, Rd */
		a := p.As
		rt := int(p.To.Reg)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		if r == REG_RSP {
			c.ctxt.Diag("illegal source register: %v", p)
			break
		}
		mode := 64
		v := uint64(p.From.Offset)
		switch p.As {
		case AANDW, AORRW, AEORW, AANDSW, ATSTW:
			mode = 32
		case ABIC, AORN, AEON, ABICS:
			v = ^v
		case ABICW, AORNW, AEONW, ABICSW:
			v = ^v
			mode = 32
		}
		o1 = c.opirr(p, a)
		o1 |= bitconEncode(v, mode) | uint32(r&31)<<5 | uint32(rt&31)

	case 54: /* floating point arith */
		o1 = c.oprrr(p, p.As)
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if (o1&(0x1F<<24)) == (0x1E<<24) && (o1&(1<<11)) == 0 { /* monadic */
			r = rf
			rf = 0
		} else if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 55: /* floating-point constant */
		var rf int
		o1 = 0xf<<25 | 1<<21 | 1<<12
		rf = c.chipfloat7(p.From.Val.(float64))
		if rf < 0 {
			c.ctxt.Diag("invalid floating-point immediate\n%v", p)
		}
		if p.As == AFMOVD {
			o1 |= 1 << 22
		}
		o1 |= (uint32(rf&0xff) << 13) | uint32(p.To.Reg&31)

	case 56: /* floating point compare */
		o1 = c.oprrr(p, p.As)

		var rf int
		if p.From.Type == obj.TYPE_FCONST {
			o1 |= 8 /* zero */
			rf = 0
		} else {
			rf = int(p.From.Reg)
		}
		rt := int(p.Reg)
		o1 |= uint32(rf&31)<<16 | uint32(rt&31)<<5

	case 57: /* floating point conditional compare */
		o1 = c.oprrr(p, p.As)

		cond := SpecialOperand(p.From.Offset)
		if cond < SPOP_EQ || cond > SPOP_NV {
			c.ctxt.Diag("invalid condition\n%v", p)
		} else {
			cond -= SPOP_EQ
		}

		nzcv := int(p.To.Offset)
		if nzcv&^0xF != 0 {
			c.ctxt.Diag("implausible condition\n%v", p)
		}
		rf := int(p.Reg)
		if p.GetFrom3() == nil || p.GetFrom3().Reg < REG_F0 || p.GetFrom3().Reg > REG_F31 {
			c.ctxt.Diag("illegal FCCMP\n%v", p)
			break
		}
		rt := int(p.GetFrom3().Reg)
		o1 |= uint32(rf&31)<<16 | uint32(cond&15)<<12 | uint32(rt&31)<<5 | uint32(nzcv)

	case 58: /* ldar/ldarb/ldarh/ldaxp/ldxp/ldaxr/ldxr */
		o1 = c.opload(p, p.As)

		o1 |= 0x1F << 16
		o1 |= uint32(p.From.Reg&31) << 5
		if p.As == ALDXP || p.As == ALDXPW || p.As == ALDAXP || p.As == ALDAXPW {
			if int(p.To.Reg) == int(p.To.Offset) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
			o1 |= uint32(p.To.Offset&31) << 10
		} else {
			o1 |= 0x1F << 10
		}
		o1 |= uint32(p.To.Reg & 31)

	case 59: /* stxr/stlxr/stxp/stlxp */
		s := p.RegTo2
		n := p.To.Reg
		t := p.From.Reg
		if isSTLXRop(p.As) {
			if s == t || (s == n && n != REGSP) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
		} else if isSTXPop(p.As) {
			t2 := int16(p.From.Offset)
			if (s == t || s == t2) || (s == n && n != REGSP) {
				c.ctxt.Diag("constrained unpredictable behavior: %v", p)
			}
		}
		if s == REG_RSP {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		o1 = c.opstore(p, p.As)

		if p.RegTo2 != obj.REG_NONE {
			o1 |= uint32(p.RegTo2&31) << 16
		} else {
			o1 |= 0x1F << 16
		}
		if isSTXPop(p.As) {
			o1 |= uint32(p.From.Offset&31) << 10
		}
		o1 |= uint32(p.To.Reg&31)<<5 | uint32(p.From.Reg&31)

	case 60: /* adrp label,r */
		d := c.brdist(p, 12, 21, 0)

		o1 = ADR(1, uint32(d), uint32(p.To.Reg))

	case 61: /* adr label, r */
		d := c.brdist(p, 0, 21, 0)

		o1 = ADR(0, uint32(d), uint32(p.To.Reg))

	case 62: /* op $movcon, [R], R -> mov $movcon, REGTMP + op REGTMP, [R], R */
		if p.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		if p.To.Reg == REG_RSP && isADDSop(p.As) {
			c.ctxt.Diag("illegal destination register: %v\n", p)
		}
		lsl0 := LSL0_64
		if isADDWop(p.As) || isANDWop(p.As) {
			o1 = c.omovconst(AMOVW, p, &p.From, REGTMP)
			lsl0 = LSL0_32
		} else {
			o1 = c.omovconst(AMOVD, p, &p.From, REGTMP)
		}

		rt, r, rf := p.To.Reg, p.Reg, int16(REGTMP)
		if p.To.Type == obj.TYPE_NONE {
			rt = REGZERO
		}
		if r == obj.REG_NONE {
			r = rt
		}
		if rt == REGSP || r == REGSP {
			o2 = c.opxrrr(p, p.As, rt, r, rf, false)
			o2 |= uint32(lsl0)
		} else {
			o2 = c.oprrr(p, p.As)
			o2 |= uint32(rf&31) << 16 /* shift is 0 */
			o2 |= uint32(r&31) << 5
			o2 |= uint32(rt & 31)
		}

	case 63: /* op Vm.<t>, Vn.<T>, Vd.<T> */
		o1 |= c.oprrr(p, p.As)
		af := (p.From.Reg >> 5) & 15
		at := (p.To.Reg >> 5) & 15
		ar := (p.Reg >> 5) & 15
		sz := ARNG_4S
		if p.As == ASHA512SU1 {
			sz = ARNG_2D
		}
		if af != at || af != ar || af != int16(sz) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= uint32(p.From.Reg&31)<<16 | uint32(p.Reg&31)<<5 | uint32(p.To.Reg&31)

	/* reloc ops */
	case 64: /* movT R,addr -> adrp + movT R, (REGTMP) */
		if p.From.Reg == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v\n", p)
		}
		o1 = ADR(1, 0, REGTMP)
		var typ objabi.RelocType
		// For unaligned access, fall back to adrp + add + movT R, (REGTMP).
		if o.size(c.ctxt, p) != 8 {
			o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
			o3 = c.olsr12u(p, c.opstr(p, p.As), 0, REGTMP, p.From.Reg)
			typ = objabi.R_ADDRARM64
		} else {
			o2 = c.olsr12u(p, c.opstr(p, p.As), 0, REGTMP, p.From.Reg)
			typ = c.addrRelocType(p)
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 65: /* movT addr,R -> adrp + movT (REGTMP), R */
		o1 = ADR(1, 0, REGTMP)
		var typ objabi.RelocType
		// For unaligned access, fall back to adrp + add + movT (REGTMP), R.
		if o.size(c.ctxt, p) != 8 {
			o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
			o3 = c.olsr12u(p, c.opldr(p, p.As), 0, REGTMP, p.To.Reg)
			typ = objabi.R_ADDRARM64
		} else {
			o2 = c.olsr12u(p, c.opldr(p, p.As), 0, REGTMP, p.To.Reg)
			typ = c.addrRelocType(p)
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 66: /* ldp O(R)!, (r1, r2); ldp (R)O!, (r1, r2) */
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v\n", p)
		}
		v := c.regoff(&p.From)
		o1 = c.opldpstp(p, o, v, rf, rt1, rt2, 1)

	case 67: /* stp (r1, r2), O(R)!; stp (r1, r2), (R)O! */
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v\n", p)
		}
		v := c.regoff(&p.To)
		o1 = c.opldpstp(p, o, v, rt, rf1, rf2, 0)

	case 68: /* movT $vconaddr(SB), reg -> adrp + add + reloc */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		if p.As == AMOVW {
			c.ctxt.Diag("invalid load of 32-bit address: %v", p)
		}
		o1 = ADR(1, 0, uint32(p.To.Reg))
		o2 = c.opirr(p, AADD) | uint32(p.To.Reg&31)<<5 | uint32(p.To.Reg&31)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 69: /* LE model movd $tlsvar, reg -> movz reg, 0 + reloc */
		o1 = c.opirr(p, AMOVZ)
		o1 |= uint32(p.To.Reg & 31)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_TLS_LE,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
		})
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset on MOVW $tlsvar")
		}

	case 70: /* IE model movd $tlsvar, reg -> adrp REGTMP, 0; ldr reg, [REGTMP, #0] + relocs */
		o1 = ADR(1, 0, REGTMP)
		o2 = c.olsr12u(p, c.opldr(p, AMOVD), 0, REGTMP, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_TLS_IE,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})
		if p.From.Offset != 0 {
			c.ctxt.Diag("invalid offset on MOVW $tlsvar")
		}

	case 71: /* movd sym@GOT, reg -> adrp REGTMP, #0; ldr reg, [REGTMP, #0] + relocs */
		o1 = ADR(1, 0, REGTMP)
		o2 = c.olsr12u(p, c.opldr(p, AMOVD), 0, REGTMP, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ARM64_GOTPCREL,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
		})

	case 72: /* vaddp/vand/vcmeq/vorr/vadd/veor/vfmla/vfmls/vbit/vbsl/vcmtst/vsub/vbif/vuzip1/vuzip2/vrax1 Vm.<T>, Vn.<T>, Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		af3 := int((p.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != af3 || af != at {
			c.ctxt.Diag("operand mismatch: %v", p)
			break
		}
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)

		Q := 0
		size := 0
		switch af {
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_2D:
			Q = 1
			size = 3
		case ARNG_2S:
			Q = 0
			size = 2
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_4S:
			Q = 1
			size = 2
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_8H:
			Q = 1
			size = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		switch p.As {
		case AVORR, AVAND, AVEOR, AVBIT, AVBSL, AVBIF:
			if af != ARNG_16B && af != ARNG_8B {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		case AVFMLA, AVFMLS:
			if af != ARNG_2D && af != ARNG_2S && af != ARNG_4S {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		case AVUMAX, AVUMIN:
			if af == ARNG_2D {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		}
		switch p.As {
		case AVAND, AVEOR:
			size = 0
		case AVBSL:
			size = 1
		case AVORR, AVBIT, AVBIF:
			size = 2
		case AVFMLA, AVFMLS:
			if af == ARNG_2D {
				size = 1
			} else {
				size = 0
			}
		case AVRAX1:
			if af != ARNG_2D {
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
			size = 0
			Q = 0
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(size&3) << 22) | (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 73: /* vmov V.<T>[index], R */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		o1 = 7<<25 | 0xf<<10
		index := int(p.From.Index)
		switch (p.From.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index, 15)
			imm5 |= 1
			imm5 |= index << 1
		case ARNG_H:
			c.checkindex(p, index, 7)
			imm5 |= 2
			imm5 |= index << 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			imm5 |= 4
			imm5 |= index << 3
		case ARNG_D:
			c.checkindex(p, index, 1)
			imm5 |= 8
			imm5 |= index << 4
			o1 |= 1 << 30
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 74:
		//	add $O, R, Rtmp or sub $O, R, Rtmp
		//	ldp (Rtmp), (R1, R2)
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v", p)
		}
		v := c.regoff(&p.From)
		o1 = c.oaddi12(p, v, REGTMP, rf)
		o2 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 75:
		// If offset L fits in a 24 bit unsigned immediate:
		//	add $lo, R, Rtmp
		//	add $hi, Rtmp, Rtmp
		//	ldr (Rtmp), R
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	add Rtmp, R, Rtmp
		//	ldp (Rtmp), (R1, R2)
		rf, rt1, rt2 := p.From.Reg, p.To.Reg, int16(p.To.Offset)
		if rf == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset load: %v", p)
		}
		if rf == obj.REG_NONE {
			rf = o.param
		}
		if rf == obj.REG_NONE {
			c.ctxt.Diag("invalid ldp source: %v", p)
		}

		v := c.regoff(&p.From)
		if v >= -4095 && v <= 4095 {
			c.ctxt.Diag("%v: bad type for offset %d (should be add/sub+ldp)", p, v)
		}

		hi, lo, err := splitImm24uScaled(v, 0)
		if err != nil {
			goto loadpairusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, lo, REGTMP, int16(rf))
		o2 = c.oaddi(p, AADD, hi, REGTMP, REGTMP)
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)
		break

	loadpairusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if rf == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset load: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.From, REGTMP)
		o2 = c.opxrrr(p, AADD, REGTMP, rf, REGTMP, false)
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 76:
		//	add $O, R, Rtmp or sub $O, R, Rtmp
		//	stp (R1, R2), (Rtmp)
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v", p)
		}
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v", p)
		}
		v := c.regoff(&p.To)
		o1 = c.oaddi12(p, v, REGTMP, rt)
		o2 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 77:
		// If offset L fits in a 24 bit unsigned immediate:
		//	add $lo, R, Rtmp
		//	add $hi, Rtmp, Rtmp
		//	stp (R1, R2), (Rtmp)
		// Otherwise, use constant pool:
		//	mov $L, Rtmp (from constant pool)
		//	add Rtmp, R, Rtmp
		//	stp (R1, R2), (Rtmp)
		rt, rf1, rf2 := p.To.Reg, p.From.Reg, int16(p.From.Offset)
		if rt == REGTMP || rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset store: %v", p)
		}
		if rt == obj.REG_NONE {
			rt = o.param
		}
		if rt == obj.REG_NONE {
			c.ctxt.Diag("invalid stp destination: %v", p)
		}

		v := c.regoff(&p.To)
		if v >= -4095 && v <= 4095 {
			c.ctxt.Diag("%v: bad type for offset %d (should be add/sub+stp)", p, v)
		}

		hi, lo, err := splitImm24uScaled(v, 0)
		if err != nil {
			goto storepairusepool
		}
		if p.Pool != nil {
			c.ctxt.Diag("%v: unused constant in pool (%v)\n", p, v)
		}
		o1 = c.oaddi(p, AADD, lo, REGTMP, int16(rt))
		o2 = c.oaddi(p, AADD, hi, REGTMP, REGTMP)
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)
		break

	storepairusepool:
		if p.Pool == nil {
			c.ctxt.Diag("%v: constant is not in pool", p)
		}
		if rt == REGTMP || p.From.Reg == REGTMP {
			c.ctxt.Diag("REGTMP used in large offset store: %v", p)
		}
		o1 = c.omovlit(AMOVD, p, &p.To, REGTMP)
		o2 = c.opxrrr(p, AADD, REGTMP, rt, REGTMP, false)
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 78: /* vmov R, V.<T>[index] */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		o1 = 1<<30 | 7<<25 | 7<<10
		index := int(p.To.Index)
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index, 15)
			imm5 |= 1
			imm5 |= index << 1
		case ARNG_H:
			c.checkindex(p, index, 7)
			imm5 |= 2
			imm5 |= index << 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			imm5 |= 4
			imm5 |= index << 3
		case ARNG_D:
			c.checkindex(p, index, 1)
			imm5 |= 8
			imm5 |= index << 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 79: /* vdup Vn.<T>[index], Vd.<T> */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		o1 = 7<<25 | 1<<10
		var imm5, Q int
		index := int(p.From.Index)
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_16B:
			c.checkindex(p, index, 15)
			Q = 1
			imm5 = 1
			imm5 |= index << 1
		case ARNG_2D:
			c.checkindex(p, index, 1)
			Q = 1
			imm5 = 8
			imm5 |= index << 4
		case ARNG_2S:
			c.checkindex(p, index, 3)
			Q = 0
			imm5 = 4
			imm5 |= index << 3
		case ARNG_4H:
			c.checkindex(p, index, 7)
			Q = 0
			imm5 = 2
			imm5 |= index << 2
		case ARNG_4S:
			c.checkindex(p, index, 3)
			Q = 1
			imm5 = 4
			imm5 |= index << 3
		case ARNG_8B:
			c.checkindex(p, index, 15)
			Q = 0
			imm5 = 1
			imm5 |= index << 1
		case ARNG_8H:
			c.checkindex(p, index, 7)
			Q = 1
			imm5 = 2
			imm5 |= index << 2
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(Q&1) << 30) | (uint32(imm5&0x1f) << 16)
		o1 |= (uint32(rf&31) << 5) | uint32(rt&31)

	case 80: /* vmov/vdup V.<T>[index], Vn */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm5 := 0
		index := int(p.From.Index)
		switch p.As {
		case AVMOV, AVDUP:
			o1 = 1<<30 | 15<<25 | 1<<10
			switch (p.From.Reg >> 5) & 15 {
			case ARNG_B:
				c.checkindex(p, index, 15)
				imm5 |= 1
				imm5 |= index << 1
			case ARNG_H:
				c.checkindex(p, index, 7)
				imm5 |= 2
				imm5 |= index << 2
			case ARNG_S:
				c.checkindex(p, index, 3)
				imm5 |= 4
				imm5 |= index << 3
			case ARNG_D:
				c.checkindex(p, index, 1)
				imm5 |= 8
				imm5 |= index << 4
			default:
				c.ctxt.Diag("invalid arrangement: %v", p)
			}
		default:
			c.ctxt.Diag("unsupported op %v", p.As)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 81: /* vld[1-4]|vld[1-4]r (Rn), [Vt1.<T>, Vt2.<T>, ...] */
		c.checkoffset(p, p.As)
		r := int(p.From.Reg)
		o1 = c.oprrr(p, p.As)
		if o.scond == C_XPOST {
			o1 |= 1 << 23
			if p.From.Index == 0 {
				// immediate offset variant
				o1 |= 0x1f << 16
			} else {
				// register offset variant
				if isRegShiftOrExt(&p.From) {
					c.ctxt.Diag("invalid extended register op: %v\n", p)
				}
				o1 |= uint32(p.From.Index&0x1f) << 16
			}
		}
		o1 |= uint32(p.To.Offset)
		// cmd/asm/internal/arch/arm64.go:ARM64RegisterListOffset
		// add opcode(bit 12-15) for vld1, mask it off if it's not vld1
		o1 = c.maskOpvldvst(p, o1)
		o1 |= uint32(r&31) << 5

	case 82: /* vmov/vdup Rn, Vd.<T> */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		o1 = 7<<25 | 3<<10
		var imm5, Q uint32
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_16B:
			Q = 1
			imm5 = 1
		case ARNG_2D:
			Q = 1
			imm5 = 8
		case ARNG_2S:
			Q = 0
			imm5 = 4
		case ARNG_4H:
			Q = 0
			imm5 = 2
		case ARNG_4S:
			Q = 1
			imm5 = 4
		case ARNG_8B:
			Q = 0
			imm5 = 1
		case ARNG_8H:
			Q = 1
			imm5 = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 |= (Q & 1 << 30) | (imm5 & 0x1f << 16)
		o1 |= (uint32(rf&31) << 5) | uint32(rt&31)

	case 83: /* vmov Vn.<T>, Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != at {
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)

		var Q, size uint32
		switch af {
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_8H:
			Q = 1
			size = 1
		case ARNG_2S:
			Q = 0
			size = 2
		case ARNG_4S:
			Q = 1
			size = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}

		if (p.As == AVMOV || p.As == AVRBIT || p.As == AVCNT) && (af != ARNG_16B && af != ARNG_8B) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVREV32 && (af == ARNG_2S || af == ARNG_4S) {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVREV16 && af != ARNG_8B && af != ARNG_16B {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if p.As == AVMOV {
			o1 |= uint32(rf&31) << 16
		}

		if p.As == AVRBIT {
			size = 1
		}

		o1 |= (Q&1)<<30 | (size&3)<<22 | uint32(rf&31)<<5 | uint32(rt&31)

	case 84: /* vst[1-4] [Vt1.<T>, Vt2.<T>, ...], (Rn) */
		c.checkoffset(p, p.As)
		r := int(p.To.Reg)
		o1 = 3 << 26
		if o.scond == C_XPOST {
			o1 |= 1 << 23
			if p.To.Index == 0 {
				// immediate offset variant
				o1 |= 0x1f << 16
			} else {
				// register offset variant
				if isRegShiftOrExt(&p.To) {
					c.ctxt.Diag("invalid extended register: %v\n", p)
				}
				o1 |= uint32(p.To.Index&31) << 16
			}
		}
		o1 |= uint32(p.From.Offset)
		// cmd/asm/internal/arch/arm64.go:ARM64RegisterListOffset
		// add opcode(bit 12-15) for vst1, mask it off if it's not vst1
		o1 = c.maskOpvldvst(p, o1)
		o1 |= uint32(r&31) << 5

	case 85: /* vaddv/vuaddlv Vn.<T>, Vd*/
		af := int((p.From.Reg >> 5) & 15)
		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		Q := 0
		size := 0
		switch af {
		case ARNG_8B:
			Q = 0
			size = 0
		case ARNG_16B:
			Q = 1
			size = 0
		case ARNG_4H:
			Q = 0
			size = 1
		case ARNG_8H:
			Q = 1
			size = 1
		case ARNG_4S:
			Q = 1
			size = 2
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 |= (uint32(Q&1) << 30) | (uint32(size&3) << 22) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 86: /* vmovi $imm8, Vd.<T>*/
		at := int((p.To.Reg >> 5) & 15)
		r := int(p.From.Offset)
		if r > 255 || r < 0 {
			c.ctxt.Diag("immediate constant out of range: %v\n", p)
		}
		rt := int((p.To.Reg) & 31)
		Q := 0
		switch at {
		case ARNG_8B:
			Q = 0
		case ARNG_16B:
			Q = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		o1 = 0xf<<24 | 0xe<<12 | 1<<10
		o1 |= (uint32(Q&1) << 30) | (uint32((r>>5)&7) << 16) | (uint32(r&0x1f) << 5) | uint32(rt&31)

	case 87: /* stp (r,r), addr(SB) -> adrp + add + stp */
		rf1, rf2 := p.From.Reg, int16(p.From.Offset)
		if rf1 == REGTMP || rf2 == REGTMP {
			c.ctxt.Diag("cannot use REGTMP as source: %v", p)
		}
		o1 = ADR(1, 0, REGTMP)
		o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})
		o3 = c.opldpstp(p, o, 0, REGTMP, rf1, rf2, 0)

	case 88: /* ldp addr(SB), (r,r) -> adrp + add + ldp */
		rt1, rt2 := p.To.Reg, int16(p.To.Offset)
		o1 = ADR(1, 0, REGTMP)
		o2 = c.opirr(p, AADD) | REGTMP&31<<5 | REGTMP&31
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRARM64,
			Off:  int32(c.pc),
			Siz:  8,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})
		o3 = c.opldpstp(p, o, 0, REGTMP, rt1, rt2, 1)

	case 89: /* vadd/vsub Vm, Vn, Vd */
		switch p.As {
		case AVADD:
			o1 = 5<<28 | 7<<25 | 7<<21 | 1<<15 | 1<<10

		case AVSUB:
			o1 = 7<<28 | 7<<25 | 7<<21 | 1<<15 | 1<<10

		default:
			c.ctxt.Diag("bad opcode: %v\n", p)
			break
		}

		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		r := int(p.Reg)
		if r == obj.REG_NONE {
			r = rt
		}
		o1 |= (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	// This is supposed to be something that stops execution.
	// It's not supposed to be reached, ever, but if it is, we'd
	// like to be able to tell how we got there. Assemble as
	// UDF which is guaranteed to raise the undefined instruction
	// exception.
	case 90:
		o1 = 0x0

	case 91: /* prfm imm(Rn), <prfop | $imm5> */
		imm := uint32(p.From.Offset)
		r := p.From.Reg
		var v uint32
		var ok bool
		if p.To.Type == obj.TYPE_CONST {
			v = uint32(p.To.Offset)
			ok = v <= 31
		} else {
			v, ok = prfopfield[SpecialOperand(p.To.Offset)]
		}
		if !ok {
			c.ctxt.Diag("illegal prefetch operation:\n%v", p)
		}

		o1 = c.opirr(p, p.As)
		o1 |= (uint32(r&31) << 5) | (uint32((imm>>3)&0xfff) << 10) | (uint32(v & 31))

	case 92: /* vmov Vn.<T>[index], Vd.<T>[index] */
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		imm4 := 0
		imm5 := 0
		o1 = 3<<29 | 7<<25 | 1<<10
		index1 := int(p.To.Index)
		index2 := int(p.From.Index)
		if ((p.To.Reg >> 5) & 15) != ((p.From.Reg >> 5) & 15) {
			c.ctxt.Diag("operand mismatch: %v", p)
		}
		switch (p.To.Reg >> 5) & 15 {
		case ARNG_B:
			c.checkindex(p, index1, 15)
			c.checkindex(p, index2, 15)
			imm5 |= 1
			imm5 |= index1 << 1
			imm4 |= index2
		case ARNG_H:
			c.checkindex(p, index1, 7)
			c.checkindex(p, index2, 7)
			imm5 |= 2
			imm5 |= index1 << 2
			imm4 |= index2 << 1
		case ARNG_S:
			c.checkindex(p, index1, 3)
			c.checkindex(p, index2, 3)
			imm5 |= 4
			imm5 |= index1 << 3
			imm4 |= index2 << 2
		case ARNG_D:
			c.checkindex(p, index1, 1)
			c.checkindex(p, index2, 1)
			imm5 |= 8
			imm5 |= index1 << 4
			imm4 |= index2 << 3
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		o1 |= (uint32(imm5&0x1f) << 16) | (uint32(imm4&0xf) << 11) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 93: /* vpmull{2} Vm.<Tb>, Vn.<Tb>, Vd.<Ta> */
		af := uint8((p.From.Reg >> 5) & 15)
		at := uint8((p.To.Reg >> 5) & 15)
		a := uint8((p.Reg >> 5) & 15)
		if af != a {
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		var Q, size uint32
		if p.As == AVPMULL2 {
			Q = 1
		}
		switch pack(Q, at, af) {
		case pack(0, ARNG_8H, ARNG_8B), pack(1, ARNG_8H, ARNG_16B):
			size = 0
		case pack(0, ARNG_1Q, ARNG_1D), pack(1, ARNG_1Q, ARNG_2D):
			size = 3
		default:
			c.ctxt.Diag("operand mismatch: %v\n", p)
		}

		o1 = c.oprrr(p, p.As)
		rf := int((p.From.Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)
		o1 |= ((Q & 1) << 30) | ((size & 3) << 22) | (uint32(rf&31) << 16) | (uint32(r&31) << 5) | uint32(rt&31)

	case 94: /* vext $imm4, Vm.<T>, Vn.<T>, Vd.<T> */
		af := int(((p.GetFrom3().Reg) >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		a := int((p.Reg >> 5) & 15)
		index := int(p.From.Offset)

		if af != a || af != at {
			c.ctxt.Diag("invalid arrangement: %v", p)
			break
		}

		var Q uint32
		var b int
		if af == ARNG_8B {
			Q = 0
			b = 7
		} else if af == ARNG_16B {
			Q = 1
			b = 15
		} else {
			c.ctxt.Diag("invalid arrangement, should be B8 or B16: %v", p)
			break
		}

		if index < 0 || index > b {
			c.ctxt.Diag("illegal offset: %v", p)
		}

		o1 = c.opirr(p, p.As)
		rf := int((p.GetFrom3().Reg) & 31)
		rt := int((p.To.Reg) & 31)
		r := int((p.Reg) & 31)

		o1 |= ((Q & 1) << 30) | (uint32(r&31) << 16) | (uint32(index&15) << 11) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 95: /* vushr/vshl/vsri/vsli/vusra $shift, Vn.<T>, Vd.<T> */
		at := int((p.To.Reg >> 5) & 15)
		af := int((p.Reg >> 5) & 15)
		shift := int(p.From.Offset)

		if af != at {
			c.ctxt.Diag("invalid arrangement on op Vn.<T>, Vd.<T>: %v", p)
		}

		var Q uint32
		var imax, esize int

		switch af {
		case ARNG_8B, ARNG_4H, ARNG_2S:
			Q = 0
		case ARNG_16B, ARNG_8H, ARNG_4S, ARNG_2D:
			Q = 1
		default:
			c.ctxt.Diag("invalid arrangement on op Vn.<T>, Vd.<T>: %v", p)
		}

		switch af {
		case ARNG_8B, ARNG_16B:
			imax = 15
			esize = 8
		case ARNG_4H, ARNG_8H:
			imax = 31
			esize = 16
		case ARNG_2S, ARNG_4S:
			imax = 63
			esize = 32
		case ARNG_2D:
			imax = 127
			esize = 64
		}

		imm := 0
		switch p.As {
		case AVUSHR, AVSRI, AVUSRA:
			imm = esize*2 - shift
			if imm < esize || imm > imax {
				c.ctxt.Diag("shift out of range: %v", p)
			}
		case AVSHL, AVSLI:
			imm = esize + shift
			if imm > imax {
				c.ctxt.Diag("shift out of range: %v", p)
			}
		default:
			c.ctxt.Diag("invalid instruction %v\n", p)
		}

		o1 = c.opirr(p, p.As)
		rt := int((p.To.Reg) & 31)
		rf := int((p.Reg) & 31)

		o1 |= ((Q & 1) << 30) | (uint32(imm&0x7f) << 16) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 96: /* vst1 Vt1.<T>[index], offset(Rn) */
		af := int((p.From.Reg >> 5) & 15)
		rt := int((p.From.Reg) & 31)
		rf := int((p.To.Reg) & 31)
		r := int(p.To.Index & 31)
		index := int(p.From.Index)
		offset := c.regoff(&p.To)

		if o.scond == C_XPOST {
			if (p.To.Index != 0) && (offset != 0) {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			if p.To.Index == 0 && offset == 0 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
		}

		if offset != 0 {
			r = 31
		}

		var Q, S, size int
		var opcode uint32
		switch af {
		case ARNG_B:
			c.checkindex(p, index, 15)
			if o.scond == C_XPOST && offset != 0 && offset != 1 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 3
			S = (index >> 2) & 1
			size = index & 3
			opcode = 0
		case ARNG_H:
			c.checkindex(p, index, 7)
			if o.scond == C_XPOST && offset != 0 && offset != 2 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 2
			S = (index >> 1) & 1
			size = (index & 1) << 1
			opcode = 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			if o.scond == C_XPOST && offset != 0 && offset != 4 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 1
			S = index & 1
			size = 0
			opcode = 4
		case ARNG_D:
			c.checkindex(p, index, 1)
			if o.scond == C_XPOST && offset != 0 && offset != 8 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index
			S = 0
			size = 1
			opcode = 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if o.scond == C_XPOST {
			o1 |= 27 << 23
		} else {
			o1 |= 26 << 23
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(r&31) << 16) | ((opcode & 7) << 13) | (uint32(S&1) << 12) | (uint32(size&3) << 10) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 97: /* vld1 offset(Rn), vt.<T>[index] */
		at := int((p.To.Reg >> 5) & 15)
		rt := int((p.To.Reg) & 31)
		rf := int((p.From.Reg) & 31)
		r := int(p.From.Index & 31)
		index := int(p.To.Index)
		offset := c.regoff(&p.From)

		if o.scond == C_XPOST {
			if (p.From.Index != 0) && (offset != 0) {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			if p.From.Index == 0 && offset == 0 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
		}

		if offset != 0 {
			r = 31
		}

		Q := 0
		S := 0
		size := 0
		var opcode uint32
		switch at {
		case ARNG_B:
			c.checkindex(p, index, 15)
			if o.scond == C_XPOST && offset != 0 && offset != 1 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 3
			S = (index >> 2) & 1
			size = index & 3
			opcode = 0
		case ARNG_H:
			c.checkindex(p, index, 7)
			if o.scond == C_XPOST && offset != 0 && offset != 2 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 2
			S = (index >> 1) & 1
			size = (index & 1) << 1
			opcode = 2
		case ARNG_S:
			c.checkindex(p, index, 3)
			if o.scond == C_XPOST && offset != 0 && offset != 4 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index >> 1
			S = index & 1
			size = 0
			opcode = 4
		case ARNG_D:
			c.checkindex(p, index, 1)
			if o.scond == C_XPOST && offset != 0 && offset != 8 {
				c.ctxt.Diag("invalid offset: %v", p)
			}
			Q = index
			S = 0
			size = 1
			opcode = 4
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}

		if o.scond == C_XPOST {
			o1 |= 110 << 21
		} else {
			o1 |= 106 << 21
		}

		o1 |= (uint32(Q&1) << 30) | (uint32(r&31) << 16) | ((opcode & 7) << 13) | (uint32(S&1) << 12) | (uint32(size&3) << 10) | (uint32(rf&31) << 5) | uint32(rt&31)

	case 98: /* MOVD (Rn)(Rm.SXTW[<<amount]),Rd */
		if isRegShiftOrExt(&p.From) {
			// extended or shifted offset register.
			c.checkShiftAmount(p, &p.From)

			o1 = c.opldrr(p, p.As, true)
			o1 |= c.encRegShiftOrExt(p, &p.From, p.From.Index) /* includes reg, op, etc */
		} else {
			// (Rn)(Rm), no extension or shift.
			o1 = c.opldrr(p, p.As, false)
			o1 |= uint32(p.From.Index&31) << 16
		}
		o1 |= uint32(p.From.Reg&31) << 5
		rt := int(p.To.Reg)
		o1 |= uint32(rt & 31)

	case 99: /* MOVD Rt, (Rn)(Rm.SXTW[<<amount]) */
		if isRegShiftOrExt(&p.To) {
			// extended or shifted offset register.
			c.checkShiftAmount(p, &p.To)

			o1 = c.opstrr(p, p.As, true)
			o1 |= c.encRegShiftOrExt(p, &p.To, p.To.Index) /* includes reg, op, etc */
		} else {
			// (Rn)(Rm), no extension or shift.
			o1 = c.opstrr(p, p.As, false)
			o1 |= uint32(p.To.Index&31) << 16
		}
		o1 |= uint32(p.To.Reg&31) << 5
		rf := int(p.From.Reg)
		o1 |= uint32(rf & 31)

	case 100: /* VTBL/VTBX Vn.<T>, [Vt1.<T>, Vt2.<T>, ...], Vd.<T> */
		af := int((p.From.Reg >> 5) & 15)
		at := int((p.To.Reg >> 5) & 15)
		if af != at {
			c.ctxt.Diag("invalid arrangement: %v\n", p)
		}
		var q, len uint32
		switch af {
		case ARNG_8B:
			q = 0
		case ARNG_16B:
			q = 1
		default:
			c.ctxt.Diag("invalid arrangement: %v", p)
		}
		rf := int(p.From.Reg)
		rt := int(p.To.Reg)
		offset := int(p.GetFrom3().Offset)
		opcode := (offset >> 12) & 15
		switch opcode {
		case 0x7:
			len = 0 // one register
		case 0xa:
			le
```