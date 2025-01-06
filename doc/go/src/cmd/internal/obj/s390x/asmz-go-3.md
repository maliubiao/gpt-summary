Response:
The user has provided a snippet of Go code from the file `go/src/cmd/internal/obj/s390x/asmz.go`. This is part 4 of 6. The request asks for a summary of the code's functionality, to infer what Go feature it implements, provide a Go code example, explain command-line argument handling (if any), highlight common mistakes, and finally, summarize the functionality of this specific part.

**Plan:**

1. **Analyze the provided code:** Identify the main elements and their purpose. The code primarily defines constants representing S390X assembly opcodes and several helper functions for assembly output.
2. **Infer Go feature implementation:** Based on the file path and the code's content, it's likely related to the S390X architecture backend within the Go compiler. It deals with generating assembly instructions for this specific architecture.
3. **Provide a Go code example:**  Since this is low-level assembly generation, a direct user-facing Go code example might not be the most relevant. Instead, I'll show a simple Go snippet and explain how this code might be used *internally* by the compiler to translate it to S390X assembly.
4. **Explain command-line argument handling:**  This specific snippet doesn't handle command-line arguments directly. This functionality is likely handled in other parts of the Go compiler. I'll explain this.
5. **Highlight common mistakes:**  Since this is internal compiler code, common user mistakes are not directly applicable. I'll skip this.
6. **Summarize the functionality of this part:**  Focus on the specific functionality within the provided code snippet: defining opcodes and helper functions for generating S390X assembly.

**Detailed Breakdown of the Code:**

* **Constants (op_...):** These are definitions of S390X assembly instruction opcodes. Each constant is a `uint32` representing the binary encoding of the instruction. The comments after each constant indicate the instruction name and its format.
* **`oclass(a *obj.Addr) int`:** This function seems to extract an instruction class from an `obj.Addr` structure. This likely helps in determining the instruction format or type.
* **`addrilreloc`, `addrilrelocoffset`, `addcallreloc`:** These functions are related to adding relocations for relative addressing in RIL-style instructions. Relocations are necessary when the final address of a symbol is not known at assembly time.
* **`branchMask(p *obj.Prog) CCMask`:** This function determines the condition code mask for conditional branch instructions. It maps Go assembly instructions to specific condition codes.
* **`regtmp(p *obj.Prog) uint32`:**  This function appears to mark a program instruction as using a temporary register.
* **`asmout(p *obj.Prog, asm *[]byte)`:** This is the core function for generating assembly output. It takes a program instruction (`obj.Prog`) and a byte slice (`asm`) and appends the corresponding S390X machine code to the byte slice. It uses the `oplook` function (not shown in this snippet) to find the opcode information and then calls functions like `zRRE`, `zRI`, `zRIL`, `zRSY`, `zRX` (also not fully defined here) to format the instruction bytes.

**Self-Correction during thought:** Initially, I considered providing a complex Go example that would *trigger* the use of these assembly instructions. However, it's more accurate and helpful to demonstrate a simple Go construct and explain *how* the compiler *might* use this code internally. This avoids the misconception that users directly interact with these low-level functions. Also, focusing on the *purpose* of this specific part (defining opcodes and helper functions) is crucial for the final summary.
这是 `go/src/cmd/internal/obj/s390x/asmz.go` 文件的一部分，它主要定义了 **S390X 架构的汇编指令的操作码 (opcodes) 和一些用于生成汇编代码的辅助函数。**

**功能归纳:**

这部分代码的主要功能是为 S390X 架构的各种汇编指令定义了对应的数字编码（操作码），并提供了一些辅助函数，用于在将 Go 代码编译成 S390X 汇编代码的过程中，根据不同的指令类型和操作数生成正确的机器码。

**更详细的功能列表:**

1. **定义 S390X 汇编指令操作码常量:**  `op_LL`, `op_SLLG`, `op_SLR` 等 `op_` 开头的常量定义了各种 S390X 汇编指令的 32 位操作码。这些常量与具体的汇编指令助记符（如 "LL" 代表 "SHIFT LEFT SINGLE LOGICAL"）相对应。
2. **提供获取指令类别的函数:** `oclass(a *obj.Addr) int` 函数用于获取操作数的类别，这在后续的汇编代码生成中可能用于判断操作数的类型和格式。
3. **提供添加重定位信息的函数:** `addrilreloc`, `addrilrelocoffset`, `addcallreloc` 函数用于为 RIL 格式的指令添加重定位信息。重定位用于处理在编译时地址未知的符号引用，需要在链接时进行调整。
4. **提供获取分支指令条件掩码的函数:** `branchMask(p *obj.Prog) CCMask` 函数根据程序指令 `p` 的类型，返回相应的条件码掩码。这用于处理条件分支指令。
5. **提供标记使用临时寄存器的函数:** `regtmp(p *obj.Prog) uint32` 函数用于标记程序指令使用了临时寄存器。
6. **提供生成汇编输出的核心函数:** `asmout(p *obj.Prog, asm *[]byte)` 是一个核心函数，它根据给定的程序指令 `p`，查找对应的操作码，并根据指令的格式和操作数，将机器码添加到 `asm` 字节切片中。这个函数根据 `o.i` 的值来处理不同类型的指令生成。

**它是什么go语言功能的实现？**

这部分代码是 **Go 语言编译器 (specifically the `cmd/compile` package) 中用于支持 S390X 架构的代码生成部分。**  它负责将 Go 的中间表示 (Intermediate Representation, IR) 转换为目标机器的汇编指令。

**go代码举例说明:**

假设有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

当 Go 编译器为 S390X 架构编译这段代码时，`asmout` 函数会被调用来生成 `add` 函数中的加法操作的汇编指令。  当处理到 `return a + b` 这行代码时，编译器可能会生成类似以下的 S390X 汇编指令（这只是一个简化的例子，实际生成的代码可能更复杂）：

```assembly
	LGR  R3, R15  // 假设 a 在 R15 寄存器
	AGR  R3, R14  // 假设 b 在 R14 寄存器，将 R14 加到 R3
	LGR  R15, R3  // 将结果存回 R15（返回值通常放在特定寄存器）
	BR   R14       // 返回
```

在 `asmout` 函数中，当处理到加法操作时，根据 `p.As` 的值（可能是代表加法的某个常量，例如 `obj.OADD`），会找到对应的 S390X 加法指令操作码。 例如，如果 `p.As` 对应于 64 位寄存器加法，`asmout` 函数的 `case 2:` 分支中的以下代码会被执行：

```go
		case AADD:
			opcode = op_AGRK
		// ...
		case AADD, AADDC, AADDW:
			if p.As == AADDW && r == p.To.Reg {
				zRR(op_AR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRF(opcode, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(r), asm)
			}
```

**假设的输入与输出：**

假设 `p` 是一个代表 `a + b` 操作的 `obj.Prog` 结构体，其中：

* `p.As` 是 `AADD` (代表加法操作)。
* `p.From.Reg` 是 `REG_R14` (代表寄存器 R14，存储变量 `b` 的值)。
* `p.To.Reg` 是 `REG_R15` (代表寄存器 R15，存储变量 `a` 的值，也是结果存放的目标寄存器)。
* `p.Reg` 是 0 (表示没有额外的中间寄存器)。

在这种情况下，`asmout` 函数会执行 `case 2:` 分支，并且由于 `p.As` 是 `AADD`，`opcode` 会被设置为 `op_AGRK`。 由于 `r` 是 0，会执行 `zRRE(op_AGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)`，这会生成 S390X 的 `AGR` (Add Register) 指令的机器码，将 `p.From.Reg` (R14) 的值加到 `p.To.Reg` (R15) 上。最终，`asm` 字节切片中会添加 `AGR R15, R14` 指令对应的机器码。

**命令行参数的具体处理：**

这部分代码本身不直接处理命令行参数。 命令行参数的处理通常发生在 Go 编译器的更高层，例如 `cmd/compile/internal/gc` 包中。  编译器会根据命令行参数（如 `-o` 指定输出文件，`-gcflags` 传递额外的编译器标志等）来控制编译过程。  `asmz.go` 中的代码只负责代码生成阶段，接收来自编译器的指令信息并生成对应的机器码。

**总结第4部分的功能:**

总而言之，`go/src/cmd/internal/obj/s390x/asmz.go` 的这部分代码专注于 **S390X 架构的汇编指令编码和基本的代码生成逻辑。** 它定义了指令的操作码，并提供了一个核心函数 `asmout`，用于将抽象的程序指令转换为实际的 S390X 机器码字节序列。 这是 Go 编译器中针对特定硬件架构进行代码生成的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/s390x/asmz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共6部分，请归纳一下它的功能

"""
LL     uint32 = 0x8900 // FORMAT_RS1        SHIFT LEFT SINGLE LOGICAL (32)
	op_SLLG    uint32 = 0xEB0D // FORMAT_RSY1       SHIFT LEFT SINGLE LOGICAL (64)
	op_SLLK    uint32 = 0xEBDF // FORMAT_RSY1       SHIFT LEFT SINGLE LOGICAL (32)
	op_SLR     uint32 = 0x1F00 // FORMAT_RR         SUBTRACT LOGICAL (32)
	op_SLRK    uint32 = 0xB9FB // FORMAT_RRF1       SUBTRACT LOGICAL (32)
	op_SLXT    uint32 = 0xED48 // FORMAT_RXF        SHIFT SIGNIFICAND LEFT (extended DFP)
	op_SLY     uint32 = 0xE35F // FORMAT_RXY1       SUBTRACT LOGICAL (32)
	op_SP      uint32 = 0xFB00 // FORMAT_SS2        SUBTRACT DECIMAL
	op_SPKA    uint32 = 0xB20A // FORMAT_S          SET PSW KEY FROM ADDRESS
	op_SPM     uint32 = 0x0400 // FORMAT_RR         SET PROGRAM MASK
	op_SPT     uint32 = 0xB208 // FORMAT_S          SET CPU TIMER
	op_SPX     uint32 = 0xB210 // FORMAT_S          SET PREFIX
	op_SQD     uint32 = 0xED35 // FORMAT_RXE        SQUARE ROOT (long HFP)
	op_SQDB    uint32 = 0xED15 // FORMAT_RXE        SQUARE ROOT (long BFP)
	op_SQDBR   uint32 = 0xB315 // FORMAT_RRE        SQUARE ROOT (long BFP)
	op_SQDR    uint32 = 0xB244 // FORMAT_RRE        SQUARE ROOT (long HFP)
	op_SQE     uint32 = 0xED34 // FORMAT_RXE        SQUARE ROOT (short HFP)
	op_SQEB    uint32 = 0xED14 // FORMAT_RXE        SQUARE ROOT (short BFP)
	op_SQEBR   uint32 = 0xB314 // FORMAT_RRE        SQUARE ROOT (short BFP)
	op_SQER    uint32 = 0xB245 // FORMAT_RRE        SQUARE ROOT (short HFP)
	op_SQXBR   uint32 = 0xB316 // FORMAT_RRE        SQUARE ROOT (extended BFP)
	op_SQXR    uint32 = 0xB336 // FORMAT_RRE        SQUARE ROOT (extended HFP)
	op_SR      uint32 = 0x1B00 // FORMAT_RR         SUBTRACT (32)
	op_SRA     uint32 = 0x8A00 // FORMAT_RS1        SHIFT RIGHT SINGLE (32)
	op_SRAG    uint32 = 0xEB0A // FORMAT_RSY1       SHIFT RIGHT SINGLE (64)
	op_SRAK    uint32 = 0xEBDC // FORMAT_RSY1       SHIFT RIGHT SINGLE (32)
	op_SRDA    uint32 = 0x8E00 // FORMAT_RS1        SHIFT RIGHT DOUBLE
	op_SRDL    uint32 = 0x8C00 // FORMAT_RS1        SHIFT RIGHT DOUBLE LOGICAL
	op_SRDT    uint32 = 0xED41 // FORMAT_RXF        SHIFT SIGNIFICAND RIGHT (long DFP)
	op_SRK     uint32 = 0xB9F9 // FORMAT_RRF1       SUBTRACT (32)
	op_SRL     uint32 = 0x8800 // FORMAT_RS1        SHIFT RIGHT SINGLE LOGICAL (32)
	op_SRLG    uint32 = 0xEB0C // FORMAT_RSY1       SHIFT RIGHT SINGLE LOGICAL (64)
	op_SRLK    uint32 = 0xEBDE // FORMAT_RSY1       SHIFT RIGHT SINGLE LOGICAL (32)
	op_SRNM    uint32 = 0xB299 // FORMAT_S          SET BFP ROUNDING MODE (2 bit)
	op_SRNMB   uint32 = 0xB2B8 // FORMAT_S          SET BFP ROUNDING MODE (3 bit)
	op_SRNMT   uint32 = 0xB2B9 // FORMAT_S          SET DFP ROUNDING MODE
	op_SRP     uint32 = 0xF000 // FORMAT_SS3        SHIFT AND ROUND DECIMAL
	op_SRST    uint32 = 0xB25E // FORMAT_RRE        SEARCH STRING
	op_SRSTU   uint32 = 0xB9BE // FORMAT_RRE        SEARCH STRING UNICODE
	op_SRXT    uint32 = 0xED49 // FORMAT_RXF        SHIFT SIGNIFICAND RIGHT (extended DFP)
	op_SSAIR   uint32 = 0xB99F // FORMAT_RRE        SET SECONDARY ASN WITH INSTANCE
	op_SSAR    uint32 = 0xB225 // FORMAT_RRE        SET SECONDARY ASN
	op_SSCH    uint32 = 0xB233 // FORMAT_S          START SUBCHANNEL
	op_SSKE    uint32 = 0xB22B // FORMAT_RRF3       SET STORAGE KEY EXTENDED
	op_SSM     uint32 = 0x8000 // FORMAT_S          SET SYSTEM MASK
	op_ST      uint32 = 0x5000 // FORMAT_RX1        STORE (32)
	op_STAM    uint32 = 0x9B00 // FORMAT_RS1        STORE ACCESS MULTIPLE
	op_STAMY   uint32 = 0xEB9B // FORMAT_RSY1       STORE ACCESS MULTIPLE
	op_STAP    uint32 = 0xB212 // FORMAT_S          STORE CPU ADDRESS
	op_STC     uint32 = 0x4200 // FORMAT_RX1        STORE CHARACTER
	op_STCH    uint32 = 0xE3C3 // FORMAT_RXY1       STORE CHARACTER HIGH (8)
	op_STCK    uint32 = 0xB205 // FORMAT_S          STORE CLOCK
	op_STCKC   uint32 = 0xB207 // FORMAT_S          STORE CLOCK COMPARATOR
	op_STCKE   uint32 = 0xB278 // FORMAT_S          STORE CLOCK EXTENDED
	op_STCKF   uint32 = 0xB27C // FORMAT_S          STORE CLOCK FAST
	op_STCM    uint32 = 0xBE00 // FORMAT_RS2        STORE CHARACTERS UNDER MASK (low)
	op_STCMH   uint32 = 0xEB2C // FORMAT_RSY2       STORE CHARACTERS UNDER MASK (high)
	op_STCMY   uint32 = 0xEB2D // FORMAT_RSY2       STORE CHARACTERS UNDER MASK (low)
	op_STCPS   uint32 = 0xB23A // FORMAT_S          STORE CHANNEL PATH STATUS
	op_STCRW   uint32 = 0xB239 // FORMAT_S          STORE CHANNEL REPORT WORD
	op_STCTG   uint32 = 0xEB25 // FORMAT_RSY1       STORE CONTROL (64)
	op_STCTL   uint32 = 0xB600 // FORMAT_RS1        STORE CONTROL (32)
	op_STCY    uint32 = 0xE372 // FORMAT_RXY1       STORE CHARACTER
	op_STD     uint32 = 0x6000 // FORMAT_RX1        STORE (long)
	op_STDY    uint32 = 0xED67 // FORMAT_RXY1       STORE (long)
	op_STE     uint32 = 0x7000 // FORMAT_RX1        STORE (short)
	op_STEY    uint32 = 0xED66 // FORMAT_RXY1       STORE (short)
	op_STFH    uint32 = 0xE3CB // FORMAT_RXY1       STORE HIGH (32)
	op_STFL    uint32 = 0xB2B1 // FORMAT_S          STORE FACILITY LIST
	op_STFLE   uint32 = 0xB2B0 // FORMAT_S          STORE FACILITY LIST EXTENDED
	op_STFPC   uint32 = 0xB29C // FORMAT_S          STORE FPC
	op_STG     uint32 = 0xE324 // FORMAT_RXY1       STORE (64)
	op_STGRL   uint32 = 0xC40B // FORMAT_RIL2       STORE RELATIVE LONG (64)
	op_STH     uint32 = 0x4000 // FORMAT_RX1        STORE HALFWORD
	op_STHH    uint32 = 0xE3C7 // FORMAT_RXY1       STORE HALFWORD HIGH (16)
	op_STHRL   uint32 = 0xC407 // FORMAT_RIL2       STORE HALFWORD RELATIVE LONG
	op_STHY    uint32 = 0xE370 // FORMAT_RXY1       STORE HALFWORD
	op_STIDP   uint32 = 0xB202 // FORMAT_S          STORE CPU ID
	op_STM     uint32 = 0x9000 // FORMAT_RS1        STORE MULTIPLE (32)
	op_STMG    uint32 = 0xEB24 // FORMAT_RSY1       STORE MULTIPLE (64)
	op_STMH    uint32 = 0xEB26 // FORMAT_RSY1       STORE MULTIPLE HIGH
	op_STMY    uint32 = 0xEB90 // FORMAT_RSY1       STORE MULTIPLE (32)
	op_STNSM   uint32 = 0xAC00 // FORMAT_SI         STORE THEN AND SYSTEM MASK
	op_STOC    uint32 = 0xEBF3 // FORMAT_RSY2       STORE ON CONDITION (32)
	op_STOCG   uint32 = 0xEBE3 // FORMAT_RSY2       STORE ON CONDITION (64)
	op_STOSM   uint32 = 0xAD00 // FORMAT_SI         STORE THEN OR SYSTEM MASK
	op_STPQ    uint32 = 0xE38E // FORMAT_RXY1       STORE PAIR TO QUADWORD
	op_STPT    uint32 = 0xB209 // FORMAT_S          STORE CPU TIMER
	op_STPX    uint32 = 0xB211 // FORMAT_S          STORE PREFIX
	op_STRAG   uint32 = 0xE502 // FORMAT_SSE        STORE REAL ADDRESS
	op_STRL    uint32 = 0xC40F // FORMAT_RIL2       STORE RELATIVE LONG (32)
	op_STRV    uint32 = 0xE33E // FORMAT_RXY1       STORE REVERSED (32)
	op_STRVG   uint32 = 0xE32F // FORMAT_RXY1       STORE REVERSED (64)
	op_STRVH   uint32 = 0xE33F // FORMAT_RXY1       STORE REVERSED (16)
	op_STSCH   uint32 = 0xB234 // FORMAT_S          STORE SUBCHANNEL
	op_STSI    uint32 = 0xB27D // FORMAT_S          STORE SYSTEM INFORMATION
	op_STURA   uint32 = 0xB246 // FORMAT_RRE        STORE USING REAL ADDRESS (32)
	op_STURG   uint32 = 0xB925 // FORMAT_RRE        STORE USING REAL ADDRESS (64)
	op_STY     uint32 = 0xE350 // FORMAT_RXY1       STORE (32)
	op_SU      uint32 = 0x7F00 // FORMAT_RX1        SUBTRACT UNNORMALIZED (short HFP)
	op_SUR     uint32 = 0x3F00 // FORMAT_RR         SUBTRACT UNNORMALIZED (short HFP)
	op_SVC     uint32 = 0x0A00 // FORMAT_I          SUPERVISOR CALL
	op_SW      uint32 = 0x6F00 // FORMAT_RX1        SUBTRACT UNNORMALIZED (long HFP)
	op_SWR     uint32 = 0x2F00 // FORMAT_RR         SUBTRACT UNNORMALIZED (long HFP)
	op_SXBR    uint32 = 0xB34B // FORMAT_RRE        SUBTRACT (extended BFP)
	op_SXR     uint32 = 0x3700 // FORMAT_RR         SUBTRACT NORMALIZED (extended HFP)
	op_SXTR    uint32 = 0xB3DB // FORMAT_RRF1       SUBTRACT (extended DFP)
	op_SXTRA   uint32 = 0xB3DB // FORMAT_RRF1       SUBTRACT (extended DFP)
	op_SY      uint32 = 0xE35B // FORMAT_RXY1       SUBTRACT (32)
	op_TABORT  uint32 = 0xB2FC // FORMAT_S          TRANSACTION ABORT
	op_TAM     uint32 = 0x010B // FORMAT_E          TEST ADDRESSING MODE
	op_TAR     uint32 = 0xB24C // FORMAT_RRE        TEST ACCESS
	op_TB      uint32 = 0xB22C // FORMAT_RRE        TEST BLOCK
	op_TBDR    uint32 = 0xB351 // FORMAT_RRF5       CONVERT HFP TO BFP (long)
	op_TBEDR   uint32 = 0xB350 // FORMAT_RRF5       CONVERT HFP TO BFP (long to short)
	op_TBEGIN  uint32 = 0xE560 // FORMAT_SIL        TRANSACTION BEGIN
	op_TBEGINC uint32 = 0xE561 // FORMAT_SIL        TRANSACTION BEGIN
	op_TCDB    uint32 = 0xED11 // FORMAT_RXE        TEST DATA CLASS (long BFP)
	op_TCEB    uint32 = 0xED10 // FORMAT_RXE        TEST DATA CLASS (short BFP)
	op_TCXB    uint32 = 0xED12 // FORMAT_RXE        TEST DATA CLASS (extended BFP)
	op_TDCDT   uint32 = 0xED54 // FORMAT_RXE        TEST DATA CLASS (long DFP)
	op_TDCET   uint32 = 0xED50 // FORMAT_RXE        TEST DATA CLASS (short DFP)
	op_TDCXT   uint32 = 0xED58 // FORMAT_RXE        TEST DATA CLASS (extended DFP)
	op_TDGDT   uint32 = 0xED55 // FORMAT_RXE        TEST DATA GROUP (long DFP)
	op_TDGET   uint32 = 0xED51 // FORMAT_RXE        TEST DATA GROUP (short DFP)
	op_TDGXT   uint32 = 0xED59 // FORMAT_RXE        TEST DATA GROUP (extended DFP)
	op_TEND    uint32 = 0xB2F8 // FORMAT_S          TRANSACTION END
	op_THDER   uint32 = 0xB358 // FORMAT_RRE        CONVERT BFP TO HFP (short to long)
	op_THDR    uint32 = 0xB359 // FORMAT_RRE        CONVERT BFP TO HFP (long)
	op_TM      uint32 = 0x9100 // FORMAT_SI         TEST UNDER MASK
	op_TMH     uint32 = 0xA700 // FORMAT_RI1        TEST UNDER MASK HIGH
	op_TMHH    uint32 = 0xA702 // FORMAT_RI1        TEST UNDER MASK (high high)
	op_TMHL    uint32 = 0xA703 // FORMAT_RI1        TEST UNDER MASK (high low)
	op_TML     uint32 = 0xA701 // FORMAT_RI1        TEST UNDER MASK LOW
	op_TMLH    uint32 = 0xA700 // FORMAT_RI1        TEST UNDER MASK (low high)
	op_TMLL    uint32 = 0xA701 // FORMAT_RI1        TEST UNDER MASK (low low)
	op_TMY     uint32 = 0xEB51 // FORMAT_SIY        TEST UNDER MASK
	op_TP      uint32 = 0xEBC0 // FORMAT_RSL        TEST DECIMAL
	op_TPI     uint32 = 0xB236 // FORMAT_S          TEST PENDING INTERRUPTION
	op_TPROT   uint32 = 0xE501 // FORMAT_SSE        TEST PROTECTION
	op_TR      uint32 = 0xDC00 // FORMAT_SS1        TRANSLATE
	op_TRACE   uint32 = 0x9900 // FORMAT_RS1        TRACE (32)
	op_TRACG   uint32 = 0xEB0F // FORMAT_RSY1       TRACE (64)
	op_TRAP2   uint32 = 0x01FF // FORMAT_E          TRAP
	op_TRAP4   uint32 = 0xB2FF // FORMAT_S          TRAP
	op_TRE     uint32 = 0xB2A5 // FORMAT_RRE        TRANSLATE EXTENDED
	op_TROO    uint32 = 0xB993 // FORMAT_RRF3       TRANSLATE ONE TO ONE
	op_TROT    uint32 = 0xB992 // FORMAT_RRF3       TRANSLATE ONE TO TWO
	op_TRT     uint32 = 0xDD00 // FORMAT_SS1        TRANSLATE AND TEST
	op_TRTE    uint32 = 0xB9BF // FORMAT_RRF3       TRANSLATE AND TEST EXTENDED
	op_TRTO    uint32 = 0xB991 // FORMAT_RRF3       TRANSLATE TWO TO ONE
	op_TRTR    uint32 = 0xD000 // FORMAT_SS1        TRANSLATE AND TEST REVERSE
	op_TRTRE   uint32 = 0xB9BD // FORMAT_RRF3       TRANSLATE AND TEST REVERSE EXTENDED
	op_TRTT    uint32 = 0xB990 // FORMAT_RRF3       TRANSLATE TWO TO TWO
	op_TS      uint32 = 0x9300 // FORMAT_S          TEST AND SET
	op_TSCH    uint32 = 0xB235 // FORMAT_S          TEST SUBCHANNEL
	op_UNPK    uint32 = 0xF300 // FORMAT_SS2        UNPACK
	op_UNPKA   uint32 = 0xEA00 // FORMAT_SS1        UNPACK ASCII
	op_UNPKU   uint32 = 0xE200 // FORMAT_SS1        UNPACK UNICODE
	op_UPT     uint32 = 0x0102 // FORMAT_E          UPDATE TREE
	op_X       uint32 = 0x5700 // FORMAT_RX1        EXCLUSIVE OR (32)
	op_XC      uint32 = 0xD700 // FORMAT_SS1        EXCLUSIVE OR (character)
	op_XG      uint32 = 0xE382 // FORMAT_RXY1       EXCLUSIVE OR (64)
	op_XGR     uint32 = 0xB982 // FORMAT_RRE        EXCLUSIVE OR (64)
	op_XGRK    uint32 = 0xB9E7 // FORMAT_RRF1       EXCLUSIVE OR (64)
	op_XI      uint32 = 0x9700 // FORMAT_SI         EXCLUSIVE OR (immediate)
	op_XIHF    uint32 = 0xC006 // FORMAT_RIL1       EXCLUSIVE OR IMMEDIATE (high)
	op_XILF    uint32 = 0xC007 // FORMAT_RIL1       EXCLUSIVE OR IMMEDIATE (low)
	op_XIY     uint32 = 0xEB57 // FORMAT_SIY        EXCLUSIVE OR (immediate)
	op_XR      uint32 = 0x1700 // FORMAT_RR         EXCLUSIVE OR (32)
	op_XRK     uint32 = 0xB9F7 // FORMAT_RRF1       EXCLUSIVE OR (32)
	op_XSCH    uint32 = 0xB276 // FORMAT_S          CANCEL SUBCHANNEL
	op_XY      uint32 = 0xE357 // FORMAT_RXY1       EXCLUSIVE OR (32)
	op_ZAP     uint32 = 0xF800 // FORMAT_SS2        ZERO AND ADD
	op_BRRK    uint32 = 0x0001 // FORMAT_E          BREAKPOINT

	// added in z13
	op_CXPT   uint32 = 0xEDAF // 	RSL-b	CONVERT FROM PACKED (to extended DFP)
	op_CDPT   uint32 = 0xEDAE // 	RSL-b	CONVERT FROM PACKED (to long DFP)
	op_CPXT   uint32 = 0xEDAD // 	RSL-b	CONVERT TO PACKED (from extended DFP)
	op_CPDT   uint32 = 0xEDAC // 	RSL-b	CONVERT TO PACKED (from long DFP)
	op_LZRF   uint32 = 0xE33B // 	RXY-a	LOAD AND ZERO RIGHTMOST BYTE (32)
	op_LZRG   uint32 = 0xE32A // 	RXY-a	LOAD AND ZERO RIGHTMOST BYTE (64)
	op_LCCB   uint32 = 0xE727 // 	RXE	LOAD COUNT TO BLOCK BOUNDARY
	op_LOCHHI uint32 = 0xEC4E // 	RIE-g	LOAD HALFWORD HIGH IMMEDIATE ON CONDITION (32←16)
	op_LOCHI  uint32 = 0xEC42 // 	RIE-g	LOAD HALFWORD IMMEDIATE ON CONDITION (32←16)
	op_LOCGHI uint32 = 0xEC46 // 	RIE-g	LOAD HALFWORD IMMEDIATE ON CONDITION (64←16)
	op_LOCFH  uint32 = 0xEBE0 // 	RSY-b	LOAD HIGH ON CONDITION (32)
	op_LOCFHR uint32 = 0xB9E0 // 	RRF-c	LOAD HIGH ON CONDITION (32)
	op_LLZRGF uint32 = 0xE33A // 	RXY-a	LOAD LOGICAL AND ZERO RIGHTMOST BYTE (64←32)
	op_STOCFH uint32 = 0xEBE1 // 	RSY-b	STORE HIGH ON CONDITION
	op_VA     uint32 = 0xE7F3 // 	VRR-c	VECTOR ADD
	op_VACC   uint32 = 0xE7F1 // 	VRR-c	VECTOR ADD COMPUTE CARRY
	op_VAC    uint32 = 0xE7BB // 	VRR-d	VECTOR ADD WITH CARRY
	op_VACCC  uint32 = 0xE7B9 // 	VRR-d	VECTOR ADD WITH CARRY COMPUTE CARRY
	op_VN     uint32 = 0xE768 // 	VRR-c	VECTOR AND
	op_VNC    uint32 = 0xE769 // 	VRR-c	VECTOR AND WITH COMPLEMENT
	op_VAVG   uint32 = 0xE7F2 // 	VRR-c	VECTOR AVERAGE
	op_VAVGL  uint32 = 0xE7F0 // 	VRR-c	VECTOR AVERAGE LOGICAL
	op_VCKSM  uint32 = 0xE766 // 	VRR-c	VECTOR CHECKSUM
	op_VCEQ   uint32 = 0xE7F8 // 	VRR-b	VECTOR COMPARE EQUAL
	op_VCH    uint32 = 0xE7FB // 	VRR-b	VECTOR COMPARE HIGH
	op_VCHL   uint32 = 0xE7F9 // 	VRR-b	VECTOR COMPARE HIGH LOGICAL
	op_VCLZ   uint32 = 0xE753 // 	VRR-a	VECTOR COUNT LEADING ZEROS
	op_VCTZ   uint32 = 0xE752 // 	VRR-a	VECTOR COUNT TRAILING ZEROS
	op_VEC    uint32 = 0xE7DB // 	VRR-a	VECTOR ELEMENT COMPARE
	op_VECL   uint32 = 0xE7D9 // 	VRR-a	VECTOR ELEMENT COMPARE LOGICAL
	op_VERIM  uint32 = 0xE772 // 	VRI-d	VECTOR ELEMENT ROTATE AND INSERT UNDER MASK
	op_VERLL  uint32 = 0xE733 // 	VRS-a	VECTOR ELEMENT ROTATE LEFT LOGICAL
	op_VERLLV uint32 = 0xE773 // 	VRR-c	VECTOR ELEMENT ROTATE LEFT LOGICAL
	op_VESLV  uint32 = 0xE770 // 	VRR-c	VECTOR ELEMENT SHIFT LEFT
	op_VESL   uint32 = 0xE730 // 	VRS-a	VECTOR ELEMENT SHIFT LEFT
	op_VESRA  uint32 = 0xE73A // 	VRS-a	VECTOR ELEMENT SHIFT RIGHT ARITHMETIC
	op_VESRAV uint32 = 0xE77A // 	VRR-c	VECTOR ELEMENT SHIFT RIGHT ARITHMETIC
	op_VESRL  uint32 = 0xE738 // 	VRS-a	VECTOR ELEMENT SHIFT RIGHT LOGICAL
	op_VESRLV uint32 = 0xE778 // 	VRR-c	VECTOR ELEMENT SHIFT RIGHT LOGICAL
	op_VX     uint32 = 0xE76D // 	VRR-c	VECTOR EXCLUSIVE OR
	op_VFAE   uint32 = 0xE782 // 	VRR-b	VECTOR FIND ANY ELEMENT EQUAL
	op_VFEE   uint32 = 0xE780 // 	VRR-b	VECTOR FIND ELEMENT EQUAL
	op_VFENE  uint32 = 0xE781 // 	VRR-b	VECTOR FIND ELEMENT NOT EQUAL
	op_VFA    uint32 = 0xE7E3 // 	VRR-c	VECTOR FP ADD
	op_WFK    uint32 = 0xE7CA // 	VRR-a	VECTOR FP COMPARE AND SIGNAL SCALAR
	op_VFCE   uint32 = 0xE7E8 // 	VRR-c	VECTOR FP COMPARE EQUAL
	op_VFCH   uint32 = 0xE7EB // 	VRR-c	VECTOR FP COMPARE HIGH
	op_VFCHE  uint32 = 0xE7EA // 	VRR-c	VECTOR FP COMPARE HIGH OR EQUAL
	op_WFC    uint32 = 0xE7CB // 	VRR-a	VECTOR FP COMPARE SCALAR
	op_VCDG   uint32 = 0xE7C3 // 	VRR-a	VECTOR FP CONVERT FROM FIXED 64-BIT
	op_VCDLG  uint32 = 0xE7C1 // 	VRR-a	VECTOR FP CONVERT FROM LOGICAL 64-BIT
	op_VCGD   uint32 = 0xE7C2 // 	VRR-a	VECTOR FP CONVERT TO FIXED 64-BIT
	op_VCLGD  uint32 = 0xE7C0 // 	VRR-a	VECTOR FP CONVERT TO LOGICAL 64-BIT
	op_VFD    uint32 = 0xE7E5 // 	VRR-c	VECTOR FP DIVIDE
	op_VLDE   uint32 = 0xE7C4 // 	VRR-a	VECTOR FP LOAD LENGTHENED
	op_VLED   uint32 = 0xE7C5 // 	VRR-a	VECTOR FP LOAD ROUNDED
	op_VFM    uint32 = 0xE7E7 // 	VRR-c	VECTOR FP MULTIPLY
	op_VFMA   uint32 = 0xE78F // 	VRR-e	VECTOR FP MULTIPLY AND ADD
	op_VFMS   uint32 = 0xE78E // 	VRR-e	VECTOR FP MULTIPLY AND SUBTRACT
	op_VFPSO  uint32 = 0xE7CC // 	VRR-a	VECTOR FP PERFORM SIGN OPERATION
	op_VFSQ   uint32 = 0xE7CE // 	VRR-a	VECTOR FP SQUARE ROOT
	op_VFS    uint32 = 0xE7E2 // 	VRR-c	VECTOR FP SUBTRACT
	op_VFTCI  uint32 = 0xE74A // 	VRI-e	VECTOR FP TEST DATA CLASS IMMEDIATE
	op_VGFM   uint32 = 0xE7B4 // 	VRR-c	VECTOR GALOIS FIELD MULTIPLY SUM
	op_VGFMA  uint32 = 0xE7BC // 	VRR-d	VECTOR GALOIS FIELD MULTIPLY SUM AND ACCUMULATE
	op_VGEF   uint32 = 0xE713 // 	VRV	VECTOR GATHER ELEMENT (32)
	op_VGEG   uint32 = 0xE712 // 	VRV	VECTOR GATHER ELEMENT (64)
	op_VGBM   uint32 = 0xE744 // 	VRI-a	VECTOR GENERATE BYTE MASK
	op_VGM    uint32 = 0xE746 // 	VRI-b	VECTOR GENERATE MASK
	op_VISTR  uint32 = 0xE75C // 	VRR-a	VECTOR ISOLATE STRING
	op_VL     uint32 = 0xE706 // 	VRX	VECTOR LOAD
	op_VLR    uint32 = 0xE756 // 	VRR-a	VECTOR LOAD
	op_VLREP  uint32 = 0xE705 // 	VRX	VECTOR LOAD AND REPLICATE
	op_VLC    uint32 = 0xE7DE // 	VRR-a	VECTOR LOAD COMPLEMENT
	op_VLEH   uint32 = 0xE701 // 	VRX	VECTOR LOAD ELEMENT (16)
	op_VLEF   uint32 = 0xE703 // 	VRX	VECTOR LOAD ELEMENT (32)
	op_VLEG   uint32 = 0xE702 // 	VRX	VECTOR LOAD ELEMENT (64)
	op_VLEB   uint32 = 0xE700 // 	VRX	VECTOR LOAD ELEMENT (8)
	op_VLEIH  uint32 = 0xE741 // 	VRI-a	VECTOR LOAD ELEMENT IMMEDIATE (16)
	op_VLEIF  uint32 = 0xE743 // 	VRI-a	VECTOR LOAD ELEMENT IMMEDIATE (32)
	op_VLEIG  uint32 = 0xE742 // 	VRI-a	VECTOR LOAD ELEMENT IMMEDIATE (64)
	op_VLEIB  uint32 = 0xE740 // 	VRI-a	VECTOR LOAD ELEMENT IMMEDIATE (8)
	op_VFI    uint32 = 0xE7C7 // 	VRR-a	VECTOR LOAD FP INTEGER
	op_VLGV   uint32 = 0xE721 // 	VRS-c	VECTOR LOAD GR FROM VR ELEMENT
	op_VLLEZ  uint32 = 0xE704 // 	VRX	VECTOR LOAD LOGICAL ELEMENT AND ZERO
	op_VLM    uint32 = 0xE736 // 	VRS-a	VECTOR LOAD MULTIPLE
	op_VLP    uint32 = 0xE7DF // 	VRR-a	VECTOR LOAD POSITIVE
	op_VLBB   uint32 = 0xE707 // 	VRX	VECTOR LOAD TO BLOCK BOUNDARY
	op_VLVG   uint32 = 0xE722 // 	VRS-b	VECTOR LOAD VR ELEMENT FROM GR
	op_VLVGP  uint32 = 0xE762 // 	VRR-f	VECTOR LOAD VR FROM GRS DISJOINT
	op_VLL    uint32 = 0xE737 // 	VRS-b	VECTOR LOAD WITH LENGTH
	op_VMX    uint32 = 0xE7FF // 	VRR-c	VECTOR MAXIMUM
	op_VMXL   uint32 = 0xE7FD // 	VRR-c	VECTOR MAXIMUM LOGICAL
	op_VMRH   uint32 = 0xE761 // 	VRR-c	VECTOR MERGE HIGH
	op_VMRL   uint32 = 0xE760 // 	VRR-c	VECTOR MERGE LOW
	op_VMN    uint32 = 0xE7FE // 	VRR-c	VECTOR MINIMUM
	op_VMNL   uint32 = 0xE7FC // 	VRR-c	VECTOR MINIMUM LOGICAL
	op_VMAE   uint32 = 0xE7AE // 	VRR-d	VECTOR MULTIPLY AND ADD EVEN
	op_VMAH   uint32 = 0xE7AB // 	VRR-d	VECTOR MULTIPLY AND ADD HIGH
	op_VMALE  uint32 = 0xE7AC // 	VRR-d	VECTOR MULTIPLY AND ADD LOGICAL EVEN
	op_VMALH  uint32 = 0xE7A9 // 	VRR-d	VECTOR MULTIPLY AND ADD LOGICAL HIGH
	op_VMALO  uint32 = 0xE7AD // 	VRR-d	VECTOR MULTIPLY AND ADD LOGICAL ODD
	op_VMAL   uint32 = 0xE7AA // 	VRR-d	VECTOR MULTIPLY AND ADD LOW
	op_VMAO   uint32 = 0xE7AF // 	VRR-d	VECTOR MULTIPLY AND ADD ODD
	op_VME    uint32 = 0xE7A6 // 	VRR-c	VECTOR MULTIPLY EVEN
	op_VMH    uint32 = 0xE7A3 // 	VRR-c	VECTOR MULTIPLY HIGH
	op_VMLE   uint32 = 0xE7A4 // 	VRR-c	VECTOR MULTIPLY EVEN LOGICAL
	op_VMLH   uint32 = 0xE7A1 // 	VRR-c	VECTOR MULTIPLY HIGH LOGICAL
	op_VMLO   uint32 = 0xE7A5 // 	VRR-c	VECTOR MULTIPLY ODD LOGICAL
	op_VML    uint32 = 0xE7A2 // 	VRR-c	VECTOR MULTIPLY LOW
	op_VMO    uint32 = 0xE7A7 // 	VRR-c	VECTOR MULTIPLY ODD
	op_VNO    uint32 = 0xE76B // 	VRR-c	VECTOR NOR
	op_VO     uint32 = 0xE76A // 	VRR-c	VECTOR OR
	op_VPK    uint32 = 0xE794 // 	VRR-c	VECTOR PACK
	op_VPKLS  uint32 = 0xE795 // 	VRR-b	VECTOR PACK LOGICAL SATURATE
	op_VPKS   uint32 = 0xE797 // 	VRR-b	VECTOR PACK SATURATE
	op_VPERM  uint32 = 0xE78C // 	VRR-e	VECTOR PERMUTE
	op_VPDI   uint32 = 0xE784 // 	VRR-c	VECTOR PERMUTE DOUBLEWORD IMMEDIATE
	op_VPOPCT uint32 = 0xE750 // 	VRR-a	VECTOR POPULATION COUNT
	op_VREP   uint32 = 0xE74D // 	VRI-c	VECTOR REPLICATE
	op_VREPI  uint32 = 0xE745 // 	VRI-a	VECTOR REPLICATE IMMEDIATE
	op_VSCEF  uint32 = 0xE71B // 	VRV	VECTOR SCATTER ELEMENT (32)
	op_VSCEG  uint32 = 0xE71A // 	VRV	VECTOR SCATTER ELEMENT (64)
	op_VSEL   uint32 = 0xE78D // 	VRR-e	VECTOR SELECT
	op_VSL    uint32 = 0xE774 // 	VRR-c	VECTOR SHIFT LEFT
	op_VSLB   uint32 = 0xE775 // 	VRR-c	VECTOR SHIFT LEFT BY BYTE
	op_VSLDB  uint32 = 0xE777 // 	VRI-d	VECTOR SHIFT LEFT DOUBLE BY BYTE
	op_VSRA   uint32 = 0xE77E // 	VRR-c	VECTOR SHIFT RIGHT ARITHMETIC
	op_VSRAB  uint32 = 0xE77F // 	VRR-c	VECTOR SHIFT RIGHT ARITHMETIC BY BYTE
	op_VSRL   uint32 = 0xE77C // 	VRR-c	VECTOR SHIFT RIGHT LOGICAL
	op_VSRLB  uint32 = 0xE77D // 	VRR-c	VECTOR SHIFT RIGHT LOGICAL BY BYTE
	op_VSEG   uint32 = 0xE75F // 	VRR-a	VECTOR SIGN EXTEND TO DOUBLEWORD
	op_VST    uint32 = 0xE70E // 	VRX	VECTOR STORE
	op_VSTEH  uint32 = 0xE709 // 	VRX	VECTOR STORE ELEMENT (16)
	op_VSTEF  uint32 = 0xE70B // 	VRX	VECTOR STORE ELEMENT (32)
	op_VSTEG  uint32 = 0xE70A // 	VRX	VECTOR STORE ELEMENT (64)
	op_VSTEB  uint32 = 0xE708 // 	VRX	VECTOR STORE ELEMENT (8)
	op_VSTM   uint32 = 0xE73E // 	VRS-a	VECTOR STORE MULTIPLE
	op_VSTL   uint32 = 0xE73F // 	VRS-b	VECTOR STORE WITH LENGTH
	op_VSTRC  uint32 = 0xE78A // 	VRR-d	VECTOR STRING RANGE COMPARE
	op_VS     uint32 = 0xE7F7 // 	VRR-c	VECTOR SUBTRACT
	op_VSCBI  uint32 = 0xE7F5 // 	VRR-c	VECTOR SUBTRACT COMPUTE BORROW INDICATION
	op_VSBCBI uint32 = 0xE7BD // 	VRR-d	VECTOR SUBTRACT WITH BORROW COMPUTE BORROW INDICATION
	op_VSBI   uint32 = 0xE7BF // 	VRR-d	VECTOR SUBTRACT WITH BORROW INDICATION
	op_VSUMG  uint32 = 0xE765 // 	VRR-c	VECTOR SUM ACROSS DOUBLEWORD
	op_VSUMQ  uint32 = 0xE767 // 	VRR-c	VECTOR SUM ACROSS QUADWORD
	op_VSUM   uint32 = 0xE764 // 	VRR-c	VECTOR SUM ACROSS WORD
	op_VTM    uint32 = 0xE7D8 // 	VRR-a	VECTOR TEST UNDER MASK
	op_VUPH   uint32 = 0xE7D7 // 	VRR-a	VECTOR UNPACK HIGH
	op_VUPLH  uint32 = 0xE7D5 // 	VRR-a	VECTOR UNPACK LOGICAL HIGH
	op_VUPLL  uint32 = 0xE7D4 // 	VRR-a	VECTOR UNPACK LOGICAL LOW
	op_VUPL   uint32 = 0xE7D6 // 	VRR-a	VECTOR UNPACK LOW
	op_VMSL   uint32 = 0xE7B8 // 	VRR-d	VECTOR MULTIPLY SUM LOGICAL

	// added in z15
	op_KDSA uint32 = 0xB93A // FORMAT_RRE        COMPUTE DIGITAL SIGNATURE AUTHENTICATION (KDSA)

)

func oclass(a *obj.Addr) int {
	return int(a.Class) - 1
}

// Add a relocation for the immediate in a RIL style instruction.
// The addend will be adjusted as required.
func (c *ctxtz) addrilreloc(sym *obj.LSym, add int64) {
	if sym == nil {
		c.ctxt.Diag("require symbol to apply relocation")
	}
	offset := int64(2) // relocation offset from start of instruction
	c.cursym.AddRel(c.ctxt, obj.Reloc{
		Type: objabi.R_PCRELDBL,
		Off:  int32(c.pc + offset),
		Siz:  4,
		Sym:  sym,
		Add:  add + offset + 4,
	})
}

func (c *ctxtz) addrilrelocoffset(sym *obj.LSym, add, offset int64) {
	if sym == nil {
		c.ctxt.Diag("require symbol to apply relocation")
	}
	offset += int64(2) // relocation offset from start of instruction
	c.cursym.AddRel(c.ctxt, obj.Reloc{
		Type: objabi.R_PCRELDBL,
		Off:  int32(c.pc + offset),
		Siz:  4,
		Sym:  sym,
		Add:  add + offset + 4,
	})
}

// Add a CALL relocation for the immediate in a RIL style instruction.
// The addend will be adjusted as required.
func (c *ctxtz) addcallreloc(sym *obj.LSym, add int64) {
	if sym == nil {
		c.ctxt.Diag("require symbol to apply relocation")
	}
	offset := int64(2) // relocation offset from start of instruction
	c.cursym.AddRel(c.ctxt, obj.Reloc{
		Type: objabi.R_CALL,
		Off:  int32(c.pc + offset),
		Siz:  4,
		Sym:  sym,
		Add:  add + offset + int64(4),
	})
}

func (c *ctxtz) branchMask(p *obj.Prog) CCMask {
	switch p.As {
	case ABRC, ALOCR, ALOCGR,
		ACRJ, ACGRJ, ACIJ, ACGIJ,
		ACLRJ, ACLGRJ, ACLIJ, ACLGIJ:
		return CCMask(p.From.Offset)
	case ABEQ, ACMPBEQ, ACMPUBEQ, AMOVDEQ:
		return Equal
	case ABGE, ACMPBGE, ACMPUBGE, AMOVDGE:
		return GreaterOrEqual
	case ABGT, ACMPBGT, ACMPUBGT, AMOVDGT:
		return Greater
	case ABLE, ACMPBLE, ACMPUBLE, AMOVDLE:
		return LessOrEqual
	case ABLT, ACMPBLT, ACMPUBLT, AMOVDLT:
		return Less
	case ABNE, ACMPBNE, ACMPUBNE, AMOVDNE:
		return NotEqual
	case ABLEU: // LE or unordered
		return NotGreater
	case ABLTU: // LT or unordered
		return LessOrUnordered
	case ABVC:
		return Never // needs extra instruction
	case ABVS:
		return Unordered
	}
	c.ctxt.Diag("unknown conditional branch %v", p.As)
	return Always
}

func regtmp(p *obj.Prog) uint32 {
	p.Mark |= USETMP
	return REGTMP
}

func (c *ctxtz) asmout(p *obj.Prog, asm *[]byte) {
	o := c.oplook(p)

	if o == nil {
		return
	}

	// If REGTMP is used in generated code, we need to set USETMP on p.Mark.
	// So we use regtmp(p) for REGTMP.

	switch o.i {
	default:
		c.ctxt.Diag("unknown index %d", o.i)

	case 0: // PSEUDO OPS
		break

	case 1: // mov reg reg
		switch p.As {
		default:
			c.ctxt.Diag("unhandled operation: %v", p.As)
		case AMOVD:
			zRRE(op_LGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		// sign extend
		case AMOVW:
			zRRE(op_LGFR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case AMOVH:
			zRRE(op_LGHR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case AMOVB:
			zRRE(op_LGBR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		// zero extend
		case AMOVWZ:
			zRRE(op_LLGFR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case AMOVHZ:
			zRRE(op_LLGHR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case AMOVBZ:
			zRRE(op_LLGCR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		// reverse bytes
		case AMOVDBR:
			zRRE(op_LRVGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		case AMOVWBR:
			zRRE(op_LRVR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		// floating point
		case AFMOVD, AFMOVS:
			zRR(op_LDR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		}

	case 2: // arithmetic op reg [reg] reg
		r := p.Reg
		if r == 0 {
			r = p.To.Reg
		}

		var opcode uint32

		switch p.As {
		default:
			c.ctxt.Diag("invalid opcode")
		case AADD:
			opcode = op_AGRK
		case AADDC:
			opcode = op_ALGRK
		case AADDE:
			opcode = op_ALCGR
		case AADDW:
			opcode = op_ARK
		case AMULLW:
			opcode = op_MSGFR
		case AMULLD:
			opcode = op_MSGR
		case ADIVW, AMODW:
			opcode = op_DSGFR
		case ADIVWU, AMODWU:
			opcode = op_DLR
		case ADIVD, AMODD:
			opcode = op_DSGR
		case ADIVDU, AMODDU:
			opcode = op_DLGR
		}

		switch p.As {
		default:

		case AADD, AADDC, AADDW:
			if p.As == AADDW && r == p.To.Reg {
				zRR(op_AR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRF(opcode, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(r), asm)
			}

		case AADDE, AMULLW, AMULLD:
			if r == p.To.Reg {
				zRRE(opcode, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else if p.From.Reg == p.To.Reg {
				zRRE(opcode, uint32(p.To.Reg), uint32(r), asm)
			} else {
				zRRE(op_LGR, uint32(p.To.Reg), uint32(r), asm)
				zRRE(opcode, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			}

		case ADIVW, ADIVWU, ADIVD, ADIVDU:
			if p.As == ADIVWU || p.As == ADIVDU {
				zRI(op_LGHI, regtmp(p), 0, asm)
			}
			zRRE(op_LGR, REGTMP2, uint32(r), asm)
			zRRE(opcode, regtmp(p), uint32(p.From.Reg), asm)
			zRRE(op_LGR, uint32(p.To.Reg), REGTMP2, asm)

		case AMODW, AMODWU, AMODD, AMODDU:
			if p.As == AMODWU || p.As == AMODDU {
				zRI(op_LGHI, regtmp(p), 0, asm)
			}
			zRRE(op_LGR, REGTMP2, uint32(r), asm)
			zRRE(opcode, regtmp(p), uint32(p.From.Reg), asm)
			zRRE(op_LGR, uint32(p.To.Reg), regtmp(p), asm)

		}

	case 3: // mov $constant reg
		v := c.vregoff(&p.From)
		switch p.As {
		case AMOVBZ:
			v = int64(uint8(v))
		case AMOVHZ:
			v = int64(uint16(v))
		case AMOVWZ:
			v = int64(uint32(v))
		case AMOVB:
			v = int64(int8(v))
		case AMOVH:
			v = int64(int16(v))
		case AMOVW:
			v = int64(int32(v))
		}
		if int64(int16(v)) == v {
			zRI(op_LGHI, uint32(p.To.Reg), uint32(v), asm)
		} else if v&0xffff0000 == v {
			zRI(op_LLILH, uint32(p.To.Reg), uint32(v>>16), asm)
		} else if v&0xffff00000000 == v {
			zRI(op_LLIHL, uint32(p.To.Reg), uint32(v>>32), asm)
		} else if uint64(v)&0xffff000000000000 == uint64(v) {
			zRI(op_LLIHH, uint32(p.To.Reg), uint32(v>>48), asm)
		} else if int64(int32(v)) == v {
			zRIL(_a, op_LGFI, uint32(p.To.Reg), uint32(v), asm)
		} else if int64(uint32(v)) == v {
			zRIL(_a, op_LLILF, uint32(p.To.Reg), uint32(v), asm)
		} else if uint64(v)&0xffffffff00000000 == uint64(v) {
			zRIL(_a, op_LLIHF, uint32(p.To.Reg), uint32(v>>32), asm)
		} else {
			zRIL(_a, op_LLILF, uint32(p.To.Reg), uint32(v), asm)
			zRIL(_a, op_IIHF, uint32(p.To.Reg), uint32(v>>32), asm)
		}

	case 4: // multiply high (a*b)>>64
		r := p.Reg
		if r == 0 {
			r = p.To.Reg
		}
		zRRE(op_LGR, REGTMP2, uint32(r), asm)
		zRRE(op_MLGR, regtmp(p), uint32(p.From.Reg), asm)
		switch p.As {
		case AMULHDU:
			// Unsigned: move result into correct register.
			zRRE(op_LGR, uint32(p.To.Reg), regtmp(p), asm)
		case AMULHD:
			// Signed: need to convert result.
			// See Hacker's Delight 8-3.
			zRSY(op_SRAG, REGTMP2, uint32(p.From.Reg), 0, 63, asm)
			zRRE(op_NGR, REGTMP2, uint32(r), asm)
			zRRE(op_SGR, regtmp(p), REGTMP2, asm)
			zRSY(op_SRAG, REGTMP2, uint32(r), 0, 63, asm)
			zRRE(op_NGR, REGTMP2, uint32(p.From.Reg), asm)
			zRRF(op_SGRK, REGTMP2, 0, uint32(p.To.Reg), regtmp(p), asm)
		}

	case 5: // syscall
		zI(op_SVC, 0, asm)

	case 6: // logical op reg [reg] reg
		var oprr, oprre, oprrf uint32
		switch p.As {
		case AAND:
			oprre = op_NGR
			oprrf = op_NGRK
		case AANDW:
			oprr = op_NR
			oprrf = op_NRK
		case AOR:
			oprre = op_OGR
			oprrf = op_OGRK
		case AORW:
			oprr = op_OR
			oprrf = op_ORK
		case AXOR:
			oprre = op_XGR
			oprrf = op_XGRK
		case AXORW:
			oprr = op_XR
			oprrf = op_XRK
		}
		if p.Reg == 0 {
			if oprr != 0 {
				zRR(oprr, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRE(oprre, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			}
		} else {
			zRRF(oprrf, uint32(p.Reg), 0, uint32(p.To.Reg), uint32(p.From.Reg), asm)
		}

	case 7: // shift/rotate reg [reg] reg
		d2 := c.vregoff(&p.From)
		b2 := p.From.Reg
		r3 := p.Reg
		if r3 == 0 {
			r3 = p.To.Reg
		}
		r1 := p.To.Reg
		var opcode uint32
		switch p.As {
		default:
		case ASLD:
			opcode = op_SLLG
		case ASRD:
			opcode = op_SRLG
		case ASLW:
			opcode = op_SLLK
		case ASRW:
			opcode = op_SRLK
		case ARLL:
			opcode = op_RLL
		case ARLLG:
			opcode = op_RLLG
		case ASRAW:
			opcode = op_SRAK
		case ASRAD:
			opcode = op_SRAG
		}
		zRSY(opcode, uint32(r1), uint32(r3), uint32(b2), uint32(d2), asm)

	case 8: // find leftmost one
		if p.To.Reg&1 != 0 {
			c.ctxt.Diag("target must be an even-numbered register")
		}
		// FLOGR also writes a mask to p.To.Reg+1.
		zRRE(op_FLOGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 9: // population count
		zRRE(op_POPCNT, uint32(p.To.Reg), uint32(p.From.Reg), asm)

	case 10: // subtract reg [reg] reg
		r := int(p.Reg)

		switch p.As {
		default:
		case ASUB:
			if r == 0 {
				zRRE(op_SGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRF(op_SGRK, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(r), asm)
			}
		case ASUBC:
			if r == 0 {
				zRRE(op_SLGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRF(op_SLGRK, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(r), asm)
			}
		case ASUBE:
			if r == 0 {
				r = int(p.To.Reg)
			}
			if r == int(p.To.Reg) {
				zRRE(op_SLBGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else if p.From.Reg == p.To.Reg {
				zRRE(op_LGR, regtmp(p), uint32(p.From.Reg), asm)
				zRRE(op_LGR, uint32(p.To.Reg), uint32(r), asm)
				zRRE(op_SLBGR, uint32(p.To.Reg), regtmp(p), asm)
			} else {
				zRRE(op_LGR, uint32(p.To.Reg), uint32(r), asm)
				zRRE(op_SLBGR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			}
		case ASUBW:
			if r == 0 {
				zRR(op_SR, uint32(p.To.Reg), uint32(p.From.Reg), asm)
			} else {
				zRRF(op_SRK, uint32(p.From.Reg), 0, uint32(p.To.Reg), uint32(r), asm)
			}
		}

	case 11: // br/bl
		v := int32(0)

		if p.To.Target() != nil {
			v = int32((p.To.Target().Pc - p.Pc) >> 1)
		}

		if p.As == ABR && p.To.Sym == nil && int32(int16(v)) == v {
			zRI(op_BRC, 0xF, uint32(v), asm)
		} else {
			if p.As == ABL {
				zRIL(_b, op_BRASL, uint32(REG_LR), uint32(v), asm)
			} else {
				zRIL(_c, op_BRCL, 0xF, uint32(v), asm)
			}
			if p.To.Sym != nil {
				c.addcallreloc(p.To.Sym, p.To.Offset)
			}
		}

	case 12:
		r1 := p.To.Reg
		d2 := c.vregoff(&p.From)
		b2 := p.From.Reg
		if b2 == 0 {
			b2 = REGSP
		}
		x2 := p.From.Index
		if -DISP20/2 > d2 || d2 >= DISP20/2 {
			zRIL(_a, op_LGFI, regtmp(p), uint32(d2), asm)
			if x2 != 0 {
				zRX(op_LA, regtmp(p), regtmp(p), uint32(x2), 0, asm)
			}
			x2 = int16(regtmp(p))
			d2 = 0
		}
		var opx, opxy uint32
		switch p.As {
		case AADD:
			opxy = op_AG
		case AADDC:
			opxy = op_ALG
		case AADDE:
			opxy = op_ALCG

"""




```