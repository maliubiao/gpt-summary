Response: The user wants a summary of the functionality of the provided Go code snippet. This code defines a large number of constants representing S/390x assembly instructions and some helper functions for assembly output.

Therefore, the main function of this code is to define the S/390x instruction set for the Go assembler. It provides a mapping between Go assembler mnemonics and their corresponding opcode values.

Let's break down the components:

1. **Instruction Constants (op_\*)**:  These are `uint32` constants. Each constant represents a specific S/390x assembly instruction. The name of the constant (`op_IC`, `op_ICM`, `op_L`, etc.) often corresponds to the assembly mnemonic. The value of the constant is the machine code (opcode) for that instruction. The comments next to each constant provide the assembly mnemonic and the instruction format.

2. **`oclass` function**: This function takes an `obj.Addr` (representing an operand in the Go assembler) and returns its class. This is likely used to determine the type of operand (register, memory address, immediate value, etc.).

3. **`addrilreloc`, `addrilrelocoffset`, `addcallreloc` functions**: These functions add relocations to the current symbol being assembled. Relocations are necessary when the final address of a symbol is not known at assembly time (e.g., for function calls or access to global variables). The different functions likely handle different types of relocations and instruction formats (RIL style instructions).

4. **`branchMask` function**: This function takes a branch instruction (`obj.Prog`) and returns a `CCMask`. This likely extracts or determines the condition code mask for conditional branch instructions.

5. **`regtmp` function**: This function marks a program instruction as using a temporary register and returns a constant `REGTMP`.

6. **`asmout` function**: This is the core of the assembly output logic. It takes a program instruction (`obj.Prog`) and a byte slice (`*[]byte`) representing the assembled output. It looks up the opcode for the instruction using `c.oplook(p)` (which is not shown in the provided snippet but is assumed to exist) and then generates the corresponding machine code bytes. The `switch` statement inside this function handles different instruction formats and operands.

Based on this analysis, the primary goal of this code is to enable the Go assembler to generate machine code for the S/390x architecture.
这是路径为`go/src/cmd/internal/obj/s390x/asmz.go`的go语言实现的一部分，它定义了S/390x架构的汇编指令集和相关的辅助功能，用于将Go语言编译成该架构的机器码。

**功能归纳:**

这段代码的主要功能是定义了一系列常量，这些常量代表了S/390x架构的各种机器指令的十六进制编码（操作码）。这些指令涵盖了数据处理、内存操作、控制流、浮点运算以及一些特殊的系统控制指令。

**详细功能列举:**

1. **定义 S/390x 汇编指令的操作码:**  代码中大量的 `op_XXX` 形式的常量，例如 `op_IC`, `op_L`, `op_ADD`,  分别对应着 S/390x 架构中的一条具体的汇编指令。常量的值是该指令的机器码。例如，`op_L` (LOAD) 的值为 `0x5800`。

2. **指令分类:**  代码通过注释将指令大致分类，例如 "SS SPACE CONTROL"。这有助于理解指令的功能分组。

3. **指令格式信息:**  每个指令常量的注释中还包含了指令的格式，例如 `FORMAT_RX1`, `FORMAT_RS2` 等。这表示指令的操作数布局和寻址方式。

4. **提供操作数类型判断的辅助函数:** `oclass(a *obj.Addr) int` 函数用于获取操作数的类别。这在生成机器码时，需要根据操作数的类型进行不同的编码处理。

5. **实现重定位功能:** `addrilreloc`, `addrilrelocoffset`, `addcallreloc` 这几个函数用于添加重定位信息。在编译过程中，有些符号（例如函数地址、全局变量地址）在汇编时可能无法确定，需要等到链接时才能确定。重定位信息指示了需要在链接阶段修改哪些指令部分。`addrilreloc` 和 `addrilrelocoffset` 可能是为 RIL 格式的指令处理立即数的重定位，而 `addcallreloc` 专门用于函数调用的重定位。

6. **处理条件分支:** `branchMask(p *obj.Prog) CCMask` 函数根据条件分支指令 (`obj.Prog`) 返回一个条件码掩码 (`CCMask`)。这用于确定在什么条件下执行分支。

7. **标记使用临时寄存器:** `regtmp(p *obj.Prog) uint32` 函数用于标记某个指令使用了临时寄存器。

8. **实现汇编输出的核心逻辑:** `asmout(p *obj.Prog, asm *[]byte)` 函数负责将 Go 汇编指令 (`obj.Prog`) 转换成机器码字节并添加到 `asm` 切片中。这个函数通过 `c.oplook(p)` 查找指令对应的操作信息，然后根据不同的指令类型和格式，调用相应的函数生成机器码。

**Go 语言功能实现推断和代码示例:**

这段代码是 Go 语言编译器内部组件的一部分，负责将中间表示的汇编代码转换成目标机器码。它不直接对应于用户可见的 Go 语言功能。但是，我们可以通过代码中定义的指令，推断出一些底层的 Go 语言特性是如何实现的。

例如，`op_L` (LOAD) 和 `op_ST` (STORE) 等指令是所有程序进行数据读写的基石。Go 语言中的变量访问，无论是局部变量还是全局变量，最终都会通过这些底层的 LOAD 和 STORE 指令来实现。

**假设的输入与输出（针对 `asmout` 函数）：**

假设我们有一个简单的 Go 语言赋值语句 `a = b`，其中 `a` 和 `b` 是两个 64 位整数类型的变量，并且 `b` 的值已经加载到寄存器 `R3` 中，我们要将 `R3` 的值存储到变量 `a` 对应的内存地址。在 Go 汇编中，这可能表示为类似 `MOVD R3, a` 的指令。

**假设输入 (`p` 指向的 `obj.Prog` 结构体):**

```go
// 假设的 obj.Prog 结构体
prog := &obj.Prog{
    As:   asm.AMOVQ, //  假设使用 AMOVQ 代表 64 位 move
    From: obj.Addr{Type: obj.TYPE_REG, Reg: s390x.REG_R3},
    To:   obj.Addr{Type: obj.TYPE_MEM, Sym: symA, Offset: 0}, // symA 指向变量 a 的符号
    Pc:   100, // 假设当前指令的 PC 值
}
```

**期望输出 (`asm` 指向的 `[]byte` 切片):**

输出的字节序列将是 `op_STG` 指令的机器码，加上用于寻址变量 `a` 的必要信息（例如，基于寄存器的偏移寻址）。具体的字节序列取决于 `oplook` 函数的实现和 `symA` 的地址。 假设 `op_STG` 的机器码是 `0xE324`，并且变量 `a` 可以通过基址寄存器 `R1` 加上偏移量 `0x100` 来访问，那么输出可能类似于（这是一个简化的例子，实际情况更复杂）：

```
[0xE3, 0x24,  // op_STG 的部分编码
 0x10, 0x00, //  可能表示偏移量 0x100 的编码
 0x03, 0x01, // 可能表示源寄存器 R3 和基址寄存器 R1 的编码
 ...]
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 Go 编译器的更高层，例如 `go tool compile` 命令的参数解析。这些参数会影响编译过程，例如目标架构、优化级别等，最终会影响到这里生成的机器码。

**易犯错的点:**

这段代码是机器码生成的底层实现，用户通常不会直接接触。开发者在使用 Go 汇编（例如通过 `//go:nosplit` 或 `import "unsafe"`) 时，需要理解这些指令的行为。

一个可能的易错点是**对指令操作数格式的理解错误**。例如，某些指令对寄存器的奇偶性有要求，如果使用了错误的寄存器，会导致程序崩溃或行为异常。

**示例：**

假设某个指令要求目标寄存器是偶数寄存器，而开发者错误地使用了奇数寄存器：

```go
// 假设的错误汇编代码
// MOVD R1, R3  // 假设该指令的机器码生成逻辑中，To 寄存器必须是偶数
```

如果 `asmout` 函数中处理这条指令时，没有进行足够的校验，就可能生成错误的机器码，导致程序运行时出现未定义的行为。

**总结:**

这段 `asmz.go` 代码是 Go 语言 s390x 架构后端的核心组成部分，它定义了该架构的指令集，并负责将 Go 汇编代码转换为实际的机器码。它不直接对应用户可见的 Go 语言功能，但它是 Go 语言程序在 s390x 架构上运行的基础。

### 提示词
```
这是路径为go/src/cmd/internal/obj/s390x/asmz.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
SS SPACE CONTROL
	op_IC      uint32 = 0x4300 // FORMAT_RX1        INSERT CHARACTER
	op_ICM     uint32 = 0xBF00 // FORMAT_RS2        INSERT CHARACTERS UNDER MASK (low)
	op_ICMH    uint32 = 0xEB80 // FORMAT_RSY2       INSERT CHARACTERS UNDER MASK (high)
	op_ICMY    uint32 = 0xEB81 // FORMAT_RSY2       INSERT CHARACTERS UNDER MASK (low)
	op_ICY     uint32 = 0xE373 // FORMAT_RXY1       INSERT CHARACTER
	op_IDTE    uint32 = 0xB98E // FORMAT_RRF2       INVALIDATE DAT TABLE ENTRY
	op_IEDTR   uint32 = 0xB3F6 // FORMAT_RRF2       INSERT BIASED EXPONENT (64 to long DFP)
	op_IEXTR   uint32 = 0xB3FE // FORMAT_RRF2       INSERT BIASED EXPONENT (64 to extended DFP)
	op_IIHF    uint32 = 0xC008 // FORMAT_RIL1       INSERT IMMEDIATE (high)
	op_IIHH    uint32 = 0xA500 // FORMAT_RI1        INSERT IMMEDIATE (high high)
	op_IIHL    uint32 = 0xA501 // FORMAT_RI1        INSERT IMMEDIATE (high low)
	op_IILF    uint32 = 0xC009 // FORMAT_RIL1       INSERT IMMEDIATE (low)
	op_IILH    uint32 = 0xA502 // FORMAT_RI1        INSERT IMMEDIATE (low high)
	op_IILL    uint32 = 0xA503 // FORMAT_RI1        INSERT IMMEDIATE (low low)
	op_IPK     uint32 = 0xB20B // FORMAT_S          INSERT PSW KEY
	op_IPM     uint32 = 0xB222 // FORMAT_RRE        INSERT PROGRAM MASK
	op_IPTE    uint32 = 0xB221 // FORMAT_RRF1       INVALIDATE PAGE TABLE ENTRY
	op_ISKE    uint32 = 0xB229 // FORMAT_RRE        INSERT STORAGE KEY EXTENDED
	op_IVSK    uint32 = 0xB223 // FORMAT_RRE        INSERT VIRTUAL STORAGE KEY
	op_KDB     uint32 = 0xED18 // FORMAT_RXE        COMPARE AND SIGNAL (long BFP)
	op_KDBR    uint32 = 0xB318 // FORMAT_RRE        COMPARE AND SIGNAL (long BFP)
	op_KDTR    uint32 = 0xB3E0 // FORMAT_RRE        COMPARE AND SIGNAL (long DFP)
	op_KEB     uint32 = 0xED08 // FORMAT_RXE        COMPARE AND SIGNAL (short BFP)
	op_KEBR    uint32 = 0xB308 // FORMAT_RRE        COMPARE AND SIGNAL (short BFP)
	op_KIMD    uint32 = 0xB93E // FORMAT_RRE        COMPUTE INTERMEDIATE MESSAGE DIGEST
	op_KLMD    uint32 = 0xB93F // FORMAT_RRE        COMPUTE LAST MESSAGE DIGEST
	op_KM      uint32 = 0xB92E // FORMAT_RRE        CIPHER MESSAGE
	op_KMAC    uint32 = 0xB91E // FORMAT_RRE        COMPUTE MESSAGE AUTHENTICATION CODE
	op_KMC     uint32 = 0xB92F // FORMAT_RRE        CIPHER MESSAGE WITH CHAINING
	op_KMA     uint32 = 0xB929 // FORMAT_RRF2       CIPHER MESSAGE WITH AUTHENTICATION
	op_KMCTR   uint32 = 0xB92D // FORMAT_RRF2       CIPHER MESSAGE WITH COUNTER
	op_KMF     uint32 = 0xB92A // FORMAT_RRE        CIPHER MESSAGE WITH CFB
	op_KMO     uint32 = 0xB92B // FORMAT_RRE        CIPHER MESSAGE WITH OFB
	op_KXBR    uint32 = 0xB348 // FORMAT_RRE        COMPARE AND SIGNAL (extended BFP)
	op_KXTR    uint32 = 0xB3E8 // FORMAT_RRE        COMPARE AND SIGNAL (extended DFP)
	op_L       uint32 = 0x5800 // FORMAT_RX1        LOAD (32)
	op_LA      uint32 = 0x4100 // FORMAT_RX1        LOAD ADDRESS
	op_LAA     uint32 = 0xEBF8 // FORMAT_RSY1       LOAD AND ADD (32)
	op_LAAG    uint32 = 0xEBE8 // FORMAT_RSY1       LOAD AND ADD (64)
	op_LAAL    uint32 = 0xEBFA // FORMAT_RSY1       LOAD AND ADD LOGICAL (32)
	op_LAALG   uint32 = 0xEBEA // FORMAT_RSY1       LOAD AND ADD LOGICAL (64)
	op_LAE     uint32 = 0x5100 // FORMAT_RX1        LOAD ADDRESS EXTENDED
	op_LAEY    uint32 = 0xE375 // FORMAT_RXY1       LOAD ADDRESS EXTENDED
	op_LAM     uint32 = 0x9A00 // FORMAT_RS1        LOAD ACCESS MULTIPLE
	op_LAMY    uint32 = 0xEB9A // FORMAT_RSY1       LOAD ACCESS MULTIPLE
	op_LAN     uint32 = 0xEBF4 // FORMAT_RSY1       LOAD AND AND (32)
	op_LANG    uint32 = 0xEBE4 // FORMAT_RSY1       LOAD AND AND (64)
	op_LAO     uint32 = 0xEBF6 // FORMAT_RSY1       LOAD AND OR (32)
	op_LAOG    uint32 = 0xEBE6 // FORMAT_RSY1       LOAD AND OR (64)
	op_LARL    uint32 = 0xC000 // FORMAT_RIL2       LOAD ADDRESS RELATIVE LONG
	op_LASP    uint32 = 0xE500 // FORMAT_SSE        LOAD ADDRESS SPACE PARAMETERS
	op_LAT     uint32 = 0xE39F // FORMAT_RXY1       LOAD AND TRAP (32L<-32)
	op_LAX     uint32 = 0xEBF7 // FORMAT_RSY1       LOAD AND EXCLUSIVE OR (32)
	op_LAXG    uint32 = 0xEBE7 // FORMAT_RSY1       LOAD AND EXCLUSIVE OR (64)
	op_LAY     uint32 = 0xE371 // FORMAT_RXY1       LOAD ADDRESS
	op_LB      uint32 = 0xE376 // FORMAT_RXY1       LOAD BYTE (32)
	op_LBH     uint32 = 0xE3C0 // FORMAT_RXY1       LOAD BYTE HIGH (32<-8)
	op_LBR     uint32 = 0xB926 // FORMAT_RRE        LOAD BYTE (32)
	op_LCDBR   uint32 = 0xB313 // FORMAT_RRE        LOAD COMPLEMENT (long BFP)
	op_LCDFR   uint32 = 0xB373 // FORMAT_RRE        LOAD COMPLEMENT (long)
	op_LCDR    uint32 = 0x2300 // FORMAT_RR         LOAD COMPLEMENT (long HFP)
	op_LCEBR   uint32 = 0xB303 // FORMAT_RRE        LOAD COMPLEMENT (short BFP)
	op_LCER    uint32 = 0x3300 // FORMAT_RR         LOAD COMPLEMENT (short HFP)
	op_LCGFR   uint32 = 0xB913 // FORMAT_RRE        LOAD COMPLEMENT (64<-32)
	op_LCGR    uint32 = 0xB903 // FORMAT_RRE        LOAD COMPLEMENT (64)
	op_LCR     uint32 = 0x1300 // FORMAT_RR         LOAD COMPLEMENT (32)
	op_LCTL    uint32 = 0xB700 // FORMAT_RS1        LOAD CONTROL (32)
	op_LCTLG   uint32 = 0xEB2F // FORMAT_RSY1       LOAD CONTROL (64)
	op_LCXBR   uint32 = 0xB343 // FORMAT_RRE        LOAD COMPLEMENT (extended BFP)
	op_LCXR    uint32 = 0xB363 // FORMAT_RRE        LOAD COMPLEMENT (extended HFP)
	op_LD      uint32 = 0x6800 // FORMAT_RX1        LOAD (long)
	op_LDE     uint32 = 0xED24 // FORMAT_RXE        LOAD LENGTHENED (short to long HFP)
	op_LDEB    uint32 = 0xED04 // FORMAT_RXE        LOAD LENGTHENED (short to long BFP)
	op_LDEBR   uint32 = 0xB304 // FORMAT_RRE        LOAD LENGTHENED (short to long BFP)
	op_LDER    uint32 = 0xB324 // FORMAT_RRE        LOAD LENGTHENED (short to long HFP)
	op_LDETR   uint32 = 0xB3D4 // FORMAT_RRF4       LOAD LENGTHENED (short to long DFP)
	op_LDGR    uint32 = 0xB3C1 // FORMAT_RRE        LOAD FPR FROM GR (64 to long)
	op_LDR     uint32 = 0x2800 // FORMAT_RR         LOAD (long)
	op_LDXBR   uint32 = 0xB345 // FORMAT_RRE        LOAD ROUNDED (extended to long BFP)
	op_LDXBRA  uint32 = 0xB345 // FORMAT_RRF5       LOAD ROUNDED (extended to long BFP)
	op_LDXR    uint32 = 0x2500 // FORMAT_RR         LOAD ROUNDED (extended to long HFP)
	op_LDXTR   uint32 = 0xB3DD // FORMAT_RRF5       LOAD ROUNDED (extended to long DFP)
	op_LDY     uint32 = 0xED65 // FORMAT_RXY1       LOAD (long)
	op_LE      uint32 = 0x7800 // FORMAT_RX1        LOAD (short)
	op_LEDBR   uint32 = 0xB344 // FORMAT_RRE        LOAD ROUNDED (long to short BFP)
	op_LEDBRA  uint32 = 0xB344 // FORMAT_RRF5       LOAD ROUNDED (long to short BFP)
	op_LEDR    uint32 = 0x3500 // FORMAT_RR         LOAD ROUNDED (long to short HFP)
	op_LEDTR   uint32 = 0xB3D5 // FORMAT_RRF5       LOAD ROUNDED (long to short DFP)
	op_LER     uint32 = 0x3800 // FORMAT_RR         LOAD (short)
	op_LEXBR   uint32 = 0xB346 // FORMAT_RRE        LOAD ROUNDED (extended to short BFP)
	op_LEXBRA  uint32 = 0xB346 // FORMAT_RRF5       LOAD ROUNDED (extended to short BFP)
	op_LEXR    uint32 = 0xB366 // FORMAT_RRE        LOAD ROUNDED (extended to short HFP)
	op_LEY     uint32 = 0xED64 // FORMAT_RXY1       LOAD (short)
	op_LFAS    uint32 = 0xB2BD // FORMAT_S          LOAD FPC AND SIGNAL
	op_LFH     uint32 = 0xE3CA // FORMAT_RXY1       LOAD HIGH (32)
	op_LFHAT   uint32 = 0xE3C8 // FORMAT_RXY1       LOAD HIGH AND TRAP (32H<-32)
	op_LFPC    uint32 = 0xB29D // FORMAT_S          LOAD FPC
	op_LG      uint32 = 0xE304 // FORMAT_RXY1       LOAD (64)
	op_LGAT    uint32 = 0xE385 // FORMAT_RXY1       LOAD AND TRAP (64)
	op_LGB     uint32 = 0xE377 // FORMAT_RXY1       LOAD BYTE (64)
	op_LGBR    uint32 = 0xB906 // FORMAT_RRE        LOAD BYTE (64)
	op_LGDR    uint32 = 0xB3CD // FORMAT_RRE        LOAD GR FROM FPR (long to 64)
	op_LGF     uint32 = 0xE314 // FORMAT_RXY1       LOAD (64<-32)
	op_LGFI    uint32 = 0xC001 // FORMAT_RIL1       LOAD IMMEDIATE (64<-32)
	op_LGFR    uint32 = 0xB914 // FORMAT_RRE        LOAD (64<-32)
	op_LGFRL   uint32 = 0xC40C // FORMAT_RIL2       LOAD RELATIVE LONG (64<-32)
	op_LGH     uint32 = 0xE315 // FORMAT_RXY1       LOAD HALFWORD (64)
	op_LGHI    uint32 = 0xA709 // FORMAT_RI1        LOAD HALFWORD IMMEDIATE (64)
	op_LGHR    uint32 = 0xB907 // FORMAT_RRE        LOAD HALFWORD (64)
	op_LGHRL   uint32 = 0xC404 // FORMAT_RIL2       LOAD HALFWORD RELATIVE LONG (64<-16)
	op_LGR     uint32 = 0xB904 // FORMAT_RRE        LOAD (64)
	op_LGRL    uint32 = 0xC408 // FORMAT_RIL2       LOAD RELATIVE LONG (64)
	op_LH      uint32 = 0x4800 // FORMAT_RX1        LOAD HALFWORD (32)
	op_LHH     uint32 = 0xE3C4 // FORMAT_RXY1       LOAD HALFWORD HIGH (32<-16)
	op_LHI     uint32 = 0xA708 // FORMAT_RI1        LOAD HALFWORD IMMEDIATE (32)
	op_LHR     uint32 = 0xB927 // FORMAT_RRE        LOAD HALFWORD (32)
	op_LHRL    uint32 = 0xC405 // FORMAT_RIL2       LOAD HALFWORD RELATIVE LONG (32<-16)
	op_LHY     uint32 = 0xE378 // FORMAT_RXY1       LOAD HALFWORD (32)
	op_LLC     uint32 = 0xE394 // FORMAT_RXY1       LOAD LOGICAL CHARACTER (32)
	op_LLCH    uint32 = 0xE3C2 // FORMAT_RXY1       LOAD LOGICAL CHARACTER HIGH (32<-8)
	op_LLCR    uint32 = 0xB994 // FORMAT_RRE        LOAD LOGICAL CHARACTER (32)
	op_LLGC    uint32 = 0xE390 // FORMAT_RXY1       LOAD LOGICAL CHARACTER (64)
	op_LLGCR   uint32 = 0xB984 // FORMAT_RRE        LOAD LOGICAL CHARACTER (64)
	op_LLGF    uint32 = 0xE316 // FORMAT_RXY1       LOAD LOGICAL (64<-32)
	op_LLGFAT  uint32 = 0xE39D // FORMAT_RXY1       LOAD LOGICAL AND TRAP (64<-32)
	op_LLGFR   uint32 = 0xB916 // FORMAT_RRE        LOAD LOGICAL (64<-32)
	op_LLGFRL  uint32 = 0xC40E // FORMAT_RIL2       LOAD LOGICAL RELATIVE LONG (64<-32)
	op_LLGH    uint32 = 0xE391 // FORMAT_RXY1       LOAD LOGICAL HALFWORD (64)
	op_LLGHR   uint32 = 0xB985 // FORMAT_RRE        LOAD LOGICAL HALFWORD (64)
	op_LLGHRL  uint32 = 0xC406 // FORMAT_RIL2       LOAD LOGICAL HALFWORD RELATIVE LONG (64<-16)
	op_LLGT    uint32 = 0xE317 // FORMAT_RXY1       LOAD LOGICAL THIRTY ONE BITS
	op_LLGTAT  uint32 = 0xE39C // FORMAT_RXY1       LOAD LOGICAL THIRTY ONE BITS AND TRAP (64<-31)
	op_LLGTR   uint32 = 0xB917 // FORMAT_RRE        LOAD LOGICAL THIRTY ONE BITS
	op_LLH     uint32 = 0xE395 // FORMAT_RXY1       LOAD LOGICAL HALFWORD (32)
	op_LLHH    uint32 = 0xE3C6 // FORMAT_RXY1       LOAD LOGICAL HALFWORD HIGH (32<-16)
	op_LLHR    uint32 = 0xB995 // FORMAT_RRE        LOAD LOGICAL HALFWORD (32)
	op_LLHRL   uint32 = 0xC402 // FORMAT_RIL2       LOAD LOGICAL HALFWORD RELATIVE LONG (32<-16)
	op_LLIHF   uint32 = 0xC00E // FORMAT_RIL1       LOAD LOGICAL IMMEDIATE (high)
	op_LLIHH   uint32 = 0xA50C // FORMAT_RI1        LOAD LOGICAL IMMEDIATE (high high)
	op_LLIHL   uint32 = 0xA50D // FORMAT_RI1        LOAD LOGICAL IMMEDIATE (high low)
	op_LLILF   uint32 = 0xC00F // FORMAT_RIL1       LOAD LOGICAL IMMEDIATE (low)
	op_LLILH   uint32 = 0xA50E // FORMAT_RI1        LOAD LOGICAL IMMEDIATE (low high)
	op_LLILL   uint32 = 0xA50F // FORMAT_RI1        LOAD LOGICAL IMMEDIATE (low low)
	op_LM      uint32 = 0x9800 // FORMAT_RS1        LOAD MULTIPLE (32)
	op_LMD     uint32 = 0xEF00 // FORMAT_SS5        LOAD MULTIPLE DISJOINT
	op_LMG     uint32 = 0xEB04 // FORMAT_RSY1       LOAD MULTIPLE (64)
	op_LMH     uint32 = 0xEB96 // FORMAT_RSY1       LOAD MULTIPLE HIGH
	op_LMY     uint32 = 0xEB98 // FORMAT_RSY1       LOAD MULTIPLE (32)
	op_LNDBR   uint32 = 0xB311 // FORMAT_RRE        LOAD NEGATIVE (long BFP)
	op_LNDFR   uint32 = 0xB371 // FORMAT_RRE        LOAD NEGATIVE (long)
	op_LNDR    uint32 = 0x2100 // FORMAT_RR         LOAD NEGATIVE (long HFP)
	op_LNEBR   uint32 = 0xB301 // FORMAT_RRE        LOAD NEGATIVE (short BFP)
	op_LNER    uint32 = 0x3100 // FORMAT_RR         LOAD NEGATIVE (short HFP)
	op_LNGFR   uint32 = 0xB911 // FORMAT_RRE        LOAD NEGATIVE (64<-32)
	op_LNGR    uint32 = 0xB901 // FORMAT_RRE        LOAD NEGATIVE (64)
	op_LNR     uint32 = 0x1100 // FORMAT_RR         LOAD NEGATIVE (32)
	op_LNXBR   uint32 = 0xB341 // FORMAT_RRE        LOAD NEGATIVE (extended BFP)
	op_LNXR    uint32 = 0xB361 // FORMAT_RRE        LOAD NEGATIVE (extended HFP)
	op_LOC     uint32 = 0xEBF2 // FORMAT_RSY2       LOAD ON CONDITION (32)
	op_LOCG    uint32 = 0xEBE2 // FORMAT_RSY2       LOAD ON CONDITION (64)
	op_LOCGR   uint32 = 0xB9E2 // FORMAT_RRF3       LOAD ON CONDITION (64)
	op_LOCR    uint32 = 0xB9F2 // FORMAT_RRF3       LOAD ON CONDITION (32)
	op_LPD     uint32 = 0xC804 // FORMAT_SSF        LOAD PAIR DISJOINT (32)
	op_LPDBR   uint32 = 0xB310 // FORMAT_RRE        LOAD POSITIVE (long BFP)
	op_LPDFR   uint32 = 0xB370 // FORMAT_RRE        LOAD POSITIVE (long)
	op_LPDG    uint32 = 0xC805 // FORMAT_SSF        LOAD PAIR DISJOINT (64)
	op_LPDR    uint32 = 0x2000 // FORMAT_RR         LOAD POSITIVE (long HFP)
	op_LPEBR   uint32 = 0xB300 // FORMAT_RRE        LOAD POSITIVE (short BFP)
	op_LPER    uint32 = 0x3000 // FORMAT_RR         LOAD POSITIVE (short HFP)
	op_LPGFR   uint32 = 0xB910 // FORMAT_RRE        LOAD POSITIVE (64<-32)
	op_LPGR    uint32 = 0xB900 // FORMAT_RRE        LOAD POSITIVE (64)
	op_LPQ     uint32 = 0xE38F // FORMAT_RXY1       LOAD PAIR FROM QUADWORD
	op_LPR     uint32 = 0x1000 // FORMAT_RR         LOAD POSITIVE (32)
	op_LPSW    uint32 = 0x8200 // FORMAT_S          LOAD PSW
	op_LPSWE   uint32 = 0xB2B2 // FORMAT_S          LOAD PSW EXTENDED
	op_LPTEA   uint32 = 0xB9AA // FORMAT_RRF2       LOAD PAGE TABLE ENTRY ADDRESS
	op_LPXBR   uint32 = 0xB340 // FORMAT_RRE        LOAD POSITIVE (extended BFP)
	op_LPXR    uint32 = 0xB360 // FORMAT_RRE        LOAD POSITIVE (extended HFP)
	op_LR      uint32 = 0x1800 // FORMAT_RR         LOAD (32)
	op_LRA     uint32 = 0xB100 // FORMAT_RX1        LOAD REAL ADDRESS (32)
	op_LRAG    uint32 = 0xE303 // FORMAT_RXY1       LOAD REAL ADDRESS (64)
	op_LRAY    uint32 = 0xE313 // FORMAT_RXY1       LOAD REAL ADDRESS (32)
	op_LRDR    uint32 = 0x2500 // FORMAT_RR         LOAD ROUNDED (extended to long HFP)
	op_LRER    uint32 = 0x3500 // FORMAT_RR         LOAD ROUNDED (long to short HFP)
	op_LRL     uint32 = 0xC40D // FORMAT_RIL2       LOAD RELATIVE LONG (32)
	op_LRV     uint32 = 0xE31E // FORMAT_RXY1       LOAD REVERSED (32)
	op_LRVG    uint32 = 0xE30F // FORMAT_RXY1       LOAD REVERSED (64)
	op_LRVGR   uint32 = 0xB90F // FORMAT_RRE        LOAD REVERSED (64)
	op_LRVH    uint32 = 0xE31F // FORMAT_RXY1       LOAD REVERSED (16)
	op_LRVR    uint32 = 0xB91F // FORMAT_RRE        LOAD REVERSED (32)
	op_LT      uint32 = 0xE312 // FORMAT_RXY1       LOAD AND TEST (32)
	op_LTDBR   uint32 = 0xB312 // FORMAT_RRE        LOAD AND TEST (long BFP)
	op_LTDR    uint32 = 0x2200 // FORMAT_RR         LOAD AND TEST (long HFP)
	op_LTDTR   uint32 = 0xB3D6 // FORMAT_RRE        LOAD AND TEST (long DFP)
	op_LTEBR   uint32 = 0xB302 // FORMAT_RRE        LOAD AND TEST (short BFP)
	op_LTER    uint32 = 0x3200 // FORMAT_RR         LOAD AND TEST (short HFP)
	op_LTG     uint32 = 0xE302 // FORMAT_RXY1       LOAD AND TEST (64)
	op_LTGF    uint32 = 0xE332 // FORMAT_RXY1       LOAD AND TEST (64<-32)
	op_LTGFR   uint32 = 0xB912 // FORMAT_RRE        LOAD AND TEST (64<-32)
	op_LTGR    uint32 = 0xB902 // FORMAT_RRE        LOAD AND TEST (64)
	op_LTR     uint32 = 0x1200 // FORMAT_RR         LOAD AND TEST (32)
	op_LTXBR   uint32 = 0xB342 // FORMAT_RRE        LOAD AND TEST (extended BFP)
	op_LTXR    uint32 = 0xB362 // FORMAT_RRE        LOAD AND TEST (extended HFP)
	op_LTXTR   uint32 = 0xB3DE // FORMAT_RRE        LOAD AND TEST (extended DFP)
	op_LURA    uint32 = 0xB24B // FORMAT_RRE        LOAD USING REAL ADDRESS (32)
	op_LURAG   uint32 = 0xB905 // FORMAT_RRE        LOAD USING REAL ADDRESS (64)
	op_LXD     uint32 = 0xED25 // FORMAT_RXE        LOAD LENGTHENED (long to extended HFP)
	op_LXDB    uint32 = 0xED05 // FORMAT_RXE        LOAD LENGTHENED (long to extended BFP)
	op_LXDBR   uint32 = 0xB305 // FORMAT_RRE        LOAD LENGTHENED (long to extended BFP)
	op_LXDR    uint32 = 0xB325 // FORMAT_RRE        LOAD LENGTHENED (long to extended HFP)
	op_LXDTR   uint32 = 0xB3DC // FORMAT_RRF4       LOAD LENGTHENED (long to extended DFP)
	op_LXE     uint32 = 0xED26 // FORMAT_RXE        LOAD LENGTHENED (short to extended HFP)
	op_LXEB    uint32 = 0xED06 // FORMAT_RXE        LOAD LENGTHENED (short to extended BFP)
	op_LXEBR   uint32 = 0xB306 // FORMAT_RRE        LOAD LENGTHENED (short to extended BFP)
	op_LXER    uint32 = 0xB326 // FORMAT_RRE        LOAD LENGTHENED (short to extended HFP)
	op_LXR     uint32 = 0xB365 // FORMAT_RRE        LOAD (extended)
	op_LY      uint32 = 0xE358 // FORMAT_RXY1       LOAD (32)
	op_LZDR    uint32 = 0xB375 // FORMAT_RRE        LOAD ZERO (long)
	op_LZER    uint32 = 0xB374 // FORMAT_RRE        LOAD ZERO (short)
	op_LZXR    uint32 = 0xB376 // FORMAT_RRE        LOAD ZERO (extended)
	op_M       uint32 = 0x5C00 // FORMAT_RX1        MULTIPLY (64<-32)
	op_MAD     uint32 = 0xED3E // FORMAT_RXF        MULTIPLY AND ADD (long HFP)
	op_MADB    uint32 = 0xED1E // FORMAT_RXF        MULTIPLY AND ADD (long BFP)
	op_MADBR   uint32 = 0xB31E // FORMAT_RRD        MULTIPLY AND ADD (long BFP)
	op_MADR    uint32 = 0xB33E // FORMAT_RRD        MULTIPLY AND ADD (long HFP)
	op_MAE     uint32 = 0xED2E // FORMAT_RXF        MULTIPLY AND ADD (short HFP)
	op_MAEB    uint32 = 0xED0E // FORMAT_RXF        MULTIPLY AND ADD (short BFP)
	op_MAEBR   uint32 = 0xB30E // FORMAT_RRD        MULTIPLY AND ADD (short BFP)
	op_MAER    uint32 = 0xB32E // FORMAT_RRD        MULTIPLY AND ADD (short HFP)
	op_MAY     uint32 = 0xED3A // FORMAT_RXF        MULTIPLY & ADD UNNORMALIZED (long to ext. HFP)
	op_MAYH    uint32 = 0xED3C // FORMAT_RXF        MULTIPLY AND ADD UNNRM. (long to ext. high HFP)
	op_MAYHR   uint32 = 0xB33C // FORMAT_RRD        MULTIPLY AND ADD UNNRM. (long to ext. high HFP)
	op_MAYL    uint32 = 0xED38 // FORMAT_RXF        MULTIPLY AND ADD UNNRM. (long to ext. low HFP)
	op_MAYLR   uint32 = 0xB338 // FORMAT_RRD        MULTIPLY AND ADD UNNRM. (long to ext. low HFP)
	op_MAYR    uint32 = 0xB33A // FORMAT_RRD        MULTIPLY & ADD UNNORMALIZED (long to ext. HFP)
	op_MC      uint32 = 0xAF00 // FORMAT_SI         MONITOR CALL
	op_MD      uint32 = 0x6C00 // FORMAT_RX1        MULTIPLY (long HFP)
	op_MDB     uint32 = 0xED1C // FORMAT_RXE        MULTIPLY (long BFP)
	op_MDBR    uint32 = 0xB31C // FORMAT_RRE        MULTIPLY (long BFP)
	op_MDE     uint32 = 0x7C00 // FORMAT_RX1        MULTIPLY (short to long HFP)
	op_MDEB    uint32 = 0xED0C // FORMAT_RXE        MULTIPLY (short to long BFP)
	op_MDEBR   uint32 = 0xB30C // FORMAT_RRE        MULTIPLY (short to long BFP)
	op_MDER    uint32 = 0x3C00 // FORMAT_RR         MULTIPLY (short to long HFP)
	op_MDR     uint32 = 0x2C00 // FORMAT_RR         MULTIPLY (long HFP)
	op_MDTR    uint32 = 0xB3D0 // FORMAT_RRF1       MULTIPLY (long DFP)
	op_MDTRA   uint32 = 0xB3D0 // FORMAT_RRF1       MULTIPLY (long DFP)
	op_ME      uint32 = 0x7C00 // FORMAT_RX1        MULTIPLY (short to long HFP)
	op_MEE     uint32 = 0xED37 // FORMAT_RXE        MULTIPLY (short HFP)
	op_MEEB    uint32 = 0xED17 // FORMAT_RXE        MULTIPLY (short BFP)
	op_MEEBR   uint32 = 0xB317 // FORMAT_RRE        MULTIPLY (short BFP)
	op_MEER    uint32 = 0xB337 // FORMAT_RRE        MULTIPLY (short HFP)
	op_MER     uint32 = 0x3C00 // FORMAT_RR         MULTIPLY (short to long HFP)
	op_MFY     uint32 = 0xE35C // FORMAT_RXY1       MULTIPLY (64<-32)
	op_MGHI    uint32 = 0xA70D // FORMAT_RI1        MULTIPLY HALFWORD IMMEDIATE (64)
	op_MH      uint32 = 0x4C00 // FORMAT_RX1        MULTIPLY HALFWORD (32)
	op_MHI     uint32 = 0xA70C // FORMAT_RI1        MULTIPLY HALFWORD IMMEDIATE (32)
	op_MHY     uint32 = 0xE37C // FORMAT_RXY1       MULTIPLY HALFWORD (32)
	op_ML      uint32 = 0xE396 // FORMAT_RXY1       MULTIPLY LOGICAL (64<-32)
	op_MLG     uint32 = 0xE386 // FORMAT_RXY1       MULTIPLY LOGICAL (128<-64)
	op_MLGR    uint32 = 0xB986 // FORMAT_RRE        MULTIPLY LOGICAL (128<-64)
	op_MLR     uint32 = 0xB996 // FORMAT_RRE        MULTIPLY LOGICAL (64<-32)
	op_MP      uint32 = 0xFC00 // FORMAT_SS2        MULTIPLY DECIMAL
	op_MR      uint32 = 0x1C00 // FORMAT_RR         MULTIPLY (64<-32)
	op_MS      uint32 = 0x7100 // FORMAT_RX1        MULTIPLY SINGLE (32)
	op_MSCH    uint32 = 0xB232 // FORMAT_S          MODIFY SUBCHANNEL
	op_MSD     uint32 = 0xED3F // FORMAT_RXF        MULTIPLY AND SUBTRACT (long HFP)
	op_MSDB    uint32 = 0xED1F // FORMAT_RXF        MULTIPLY AND SUBTRACT (long BFP)
	op_MSDBR   uint32 = 0xB31F // FORMAT_RRD        MULTIPLY AND SUBTRACT (long BFP)
	op_MSDR    uint32 = 0xB33F // FORMAT_RRD        MULTIPLY AND SUBTRACT (long HFP)
	op_MSE     uint32 = 0xED2F // FORMAT_RXF        MULTIPLY AND SUBTRACT (short HFP)
	op_MSEB    uint32 = 0xED0F // FORMAT_RXF        MULTIPLY AND SUBTRACT (short BFP)
	op_MSEBR   uint32 = 0xB30F // FORMAT_RRD        MULTIPLY AND SUBTRACT (short BFP)
	op_MSER    uint32 = 0xB32F // FORMAT_RRD        MULTIPLY AND SUBTRACT (short HFP)
	op_MSFI    uint32 = 0xC201 // FORMAT_RIL1       MULTIPLY SINGLE IMMEDIATE (32)
	op_MSG     uint32 = 0xE30C // FORMAT_RXY1       MULTIPLY SINGLE (64)
	op_MSGF    uint32 = 0xE31C // FORMAT_RXY1       MULTIPLY SINGLE (64<-32)
	op_MSGFI   uint32 = 0xC200 // FORMAT_RIL1       MULTIPLY SINGLE IMMEDIATE (64<-32)
	op_MSGFR   uint32 = 0xB91C // FORMAT_RRE        MULTIPLY SINGLE (64<-32)
	op_MSGR    uint32 = 0xB90C // FORMAT_RRE        MULTIPLY SINGLE (64)
	op_MSR     uint32 = 0xB252 // FORMAT_RRE        MULTIPLY SINGLE (32)
	op_MSTA    uint32 = 0xB247 // FORMAT_RRE        MODIFY STACKED STATE
	op_MSY     uint32 = 0xE351 // FORMAT_RXY1       MULTIPLY SINGLE (32)
	op_MVC     uint32 = 0xD200 // FORMAT_SS1        MOVE (character)
	op_MVCDK   uint32 = 0xE50F // FORMAT_SSE        MOVE WITH DESTINATION KEY
	op_MVCIN   uint32 = 0xE800 // FORMAT_SS1        MOVE INVERSE
	op_MVCK    uint32 = 0xD900 // FORMAT_SS4        MOVE WITH KEY
	op_MVCL    uint32 = 0x0E00 // FORMAT_RR         MOVE LONG
	op_MVCLE   uint32 = 0xA800 // FORMAT_RS1        MOVE LONG EXTENDED
	op_MVCLU   uint32 = 0xEB8E // FORMAT_RSY1       MOVE LONG UNICODE
	op_MVCOS   uint32 = 0xC800 // FORMAT_SSF        MOVE WITH OPTIONAL SPECIFICATIONS
	op_MVCP    uint32 = 0xDA00 // FORMAT_SS4        MOVE TO PRIMARY
	op_MVCS    uint32 = 0xDB00 // FORMAT_SS4        MOVE TO SECONDARY
	op_MVCSK   uint32 = 0xE50E // FORMAT_SSE        MOVE WITH SOURCE KEY
	op_MVGHI   uint32 = 0xE548 // FORMAT_SIL        MOVE (64<-16)
	op_MVHHI   uint32 = 0xE544 // FORMAT_SIL        MOVE (16<-16)
	op_MVHI    uint32 = 0xE54C // FORMAT_SIL        MOVE (32<-16)
	op_MVI     uint32 = 0x9200 // FORMAT_SI         MOVE (immediate)
	op_MVIY    uint32 = 0xEB52 // FORMAT_SIY        MOVE (immediate)
	op_MVN     uint32 = 0xD100 // FORMAT_SS1        MOVE NUMERICS
	op_MVO     uint32 = 0xF100 // FORMAT_SS2        MOVE WITH OFFSET
	op_MVPG    uint32 = 0xB254 // FORMAT_RRE        MOVE PAGE
	op_MVST    uint32 = 0xB255 // FORMAT_RRE        MOVE STRING
	op_MVZ     uint32 = 0xD300 // FORMAT_SS1        MOVE ZONES
	op_MXBR    uint32 = 0xB34C // FORMAT_RRE        MULTIPLY (extended BFP)
	op_MXD     uint32 = 0x6700 // FORMAT_RX1        MULTIPLY (long to extended HFP)
	op_MXDB    uint32 = 0xED07 // FORMAT_RXE        MULTIPLY (long to extended BFP)
	op_MXDBR   uint32 = 0xB307 // FORMAT_RRE        MULTIPLY (long to extended BFP)
	op_MXDR    uint32 = 0x2700 // FORMAT_RR         MULTIPLY (long to extended HFP)
	op_MXR     uint32 = 0x2600 // FORMAT_RR         MULTIPLY (extended HFP)
	op_MXTR    uint32 = 0xB3D8 // FORMAT_RRF1       MULTIPLY (extended DFP)
	op_MXTRA   uint32 = 0xB3D8 // FORMAT_RRF1       MULTIPLY (extended DFP)
	op_MY      uint32 = 0xED3B // FORMAT_RXF        MULTIPLY UNNORMALIZED (long to ext. HFP)
	op_MYH     uint32 = 0xED3D // FORMAT_RXF        MULTIPLY UNNORM. (long to ext. high HFP)
	op_MYHR    uint32 = 0xB33D // FORMAT_RRD        MULTIPLY UNNORM. (long to ext. high HFP)
	op_MYL     uint32 = 0xED39 // FORMAT_RXF        MULTIPLY UNNORM. (long to ext. low HFP)
	op_MYLR    uint32 = 0xB339 // FORMAT_RRD        MULTIPLY UNNORM. (long to ext. low HFP)
	op_MYR     uint32 = 0xB33B // FORMAT_RRD        MULTIPLY UNNORMALIZED (long to ext. HFP)
	op_N       uint32 = 0x5400 // FORMAT_RX1        AND (32)
	op_NC      uint32 = 0xD400 // FORMAT_SS1        AND (character)
	op_NG      uint32 = 0xE380 // FORMAT_RXY1       AND (64)
	op_NGR     uint32 = 0xB980 // FORMAT_RRE        AND (64)
	op_NGRK    uint32 = 0xB9E4 // FORMAT_RRF1       AND (64)
	op_NI      uint32 = 0x9400 // FORMAT_SI         AND (immediate)
	op_NIAI    uint32 = 0xB2FA // FORMAT_IE         NEXT INSTRUCTION ACCESS INTENT
	op_NIHF    uint32 = 0xC00A // FORMAT_RIL1       AND IMMEDIATE (high)
	op_NIHH    uint32 = 0xA504 // FORMAT_RI1        AND IMMEDIATE (high high)
	op_NIHL    uint32 = 0xA505 // FORMAT_RI1        AND IMMEDIATE (high low)
	op_NILF    uint32 = 0xC00B // FORMAT_RIL1       AND IMMEDIATE (low)
	op_NILH    uint32 = 0xA506 // FORMAT_RI1        AND IMMEDIATE (low high)
	op_NILL    uint32 = 0xA507 // FORMAT_RI1        AND IMMEDIATE (low low)
	op_NIY     uint32 = 0xEB54 // FORMAT_SIY        AND (immediate)
	op_NR      uint32 = 0x1400 // FORMAT_RR         AND (32)
	op_NRK     uint32 = 0xB9F4 // FORMAT_RRF1       AND (32)
	op_NTSTG   uint32 = 0xE325 // FORMAT_RXY1       NONTRANSACTIONAL STORE
	op_NY      uint32 = 0xE354 // FORMAT_RXY1       AND (32)
	op_O       uint32 = 0x5600 // FORMAT_RX1        OR (32)
	op_OC      uint32 = 0xD600 // FORMAT_SS1        OR (character)
	op_OG      uint32 = 0xE381 // FORMAT_RXY1       OR (64)
	op_OGR     uint32 = 0xB981 // FORMAT_RRE        OR (64)
	op_OGRK    uint32 = 0xB9E6 // FORMAT_RRF1       OR (64)
	op_OI      uint32 = 0x9600 // FORMAT_SI         OR (immediate)
	op_OIHF    uint32 = 0xC00C // FORMAT_RIL1       OR IMMEDIATE (high)
	op_OIHH    uint32 = 0xA508 // FORMAT_RI1        OR IMMEDIATE (high high)
	op_OIHL    uint32 = 0xA509 // FORMAT_RI1        OR IMMEDIATE (high low)
	op_OILF    uint32 = 0xC00D // FORMAT_RIL1       OR IMMEDIATE (low)
	op_OILH    uint32 = 0xA50A // FORMAT_RI1        OR IMMEDIATE (low high)
	op_OILL    uint32 = 0xA50B // FORMAT_RI1        OR IMMEDIATE (low low)
	op_OIY     uint32 = 0xEB56 // FORMAT_SIY        OR (immediate)
	op_OR      uint32 = 0x1600 // FORMAT_RR         OR (32)
	op_ORK     uint32 = 0xB9F6 // FORMAT_RRF1       OR (32)
	op_OY      uint32 = 0xE356 // FORMAT_RXY1       OR (32)
	op_PACK    uint32 = 0xF200 // FORMAT_SS2        PACK
	op_PALB    uint32 = 0xB248 // FORMAT_RRE        PURGE ALB
	op_PC      uint32 = 0xB218 // FORMAT_S          PROGRAM CALL
	op_PCC     uint32 = 0xB92C // FORMAT_RRE        PERFORM CRYPTOGRAPHIC COMPUTATION
	op_PCKMO   uint32 = 0xB928 // FORMAT_RRE        PERFORM CRYPTOGRAPHIC KEY MGMT. OPERATIONS
	op_PFD     uint32 = 0xE336 // FORMAT_RXY2       PREFETCH DATA
	op_PFDRL   uint32 = 0xC602 // FORMAT_RIL3       PREFETCH DATA RELATIVE LONG
	op_PFMF    uint32 = 0xB9AF // FORMAT_RRE        PERFORM FRAME MANAGEMENT FUNCTION
	op_PFPO    uint32 = 0x010A // FORMAT_E          PERFORM FLOATING-POINT OPERATION
	op_PGIN    uint32 = 0xB22E // FORMAT_RRE        PAGE IN
	op_PGOUT   uint32 = 0xB22F // FORMAT_RRE        PAGE OUT
	op_PKA     uint32 = 0xE900 // FORMAT_SS6        PACK ASCII
	op_PKU     uint32 = 0xE100 // FORMAT_SS6        PACK UNICODE
	op_PLO     uint32 = 0xEE00 // FORMAT_SS5        PERFORM LOCKED OPERATION
	op_POPCNT  uint32 = 0xB9E1 // FORMAT_RRE        POPULATION COUNT
	op_PPA     uint32 = 0xB2E8 // FORMAT_RRF3       PERFORM PROCESSOR ASSIST
	op_PR      uint32 = 0x0101 // FORMAT_E          PROGRAM RETURN
	op_PT      uint32 = 0xB228 // FORMAT_RRE        PROGRAM TRANSFER
	op_PTF     uint32 = 0xB9A2 // FORMAT_RRE        PERFORM TOPOLOGY FUNCTION
	op_PTFF    uint32 = 0x0104 // FORMAT_E          PERFORM TIMING FACILITY FUNCTION
	op_PTI     uint32 = 0xB99E // FORMAT_RRE        PROGRAM TRANSFER WITH INSTANCE
	op_PTLB    uint32 = 0xB20D // FORMAT_S          PURGE TLB
	op_QADTR   uint32 = 0xB3F5 // FORMAT_RRF2       QUANTIZE (long DFP)
	op_QAXTR   uint32 = 0xB3FD // FORMAT_RRF2       QUANTIZE (extended DFP)
	op_RCHP    uint32 = 0xB23B // FORMAT_S          RESET CHANNEL PATH
	op_RISBG   uint32 = 0xEC55 // FORMAT_RIE6       ROTATE THEN INSERT SELECTED BITS
	op_RISBGN  uint32 = 0xEC59 // FORMAT_RIE6       ROTATE THEN INSERT SELECTED BITS
	op_RISBHG  uint32 = 0xEC5D // FORMAT_RIE6       ROTATE THEN INSERT SELECTED BITS HIGH
	op_RISBLG  uint32 = 0xEC51 // FORMAT_RIE6       ROTATE THEN INSERT SELECTED BITS LOW
	op_RLL     uint32 = 0xEB1D // FORMAT_RSY1       ROTATE LEFT SINGLE LOGICAL (32)
	op_RLLG    uint32 = 0xEB1C // FORMAT_RSY1       ROTATE LEFT SINGLE LOGICAL (64)
	op_RNSBG   uint32 = 0xEC54 // FORMAT_RIE6       ROTATE THEN AND SELECTED BITS
	op_ROSBG   uint32 = 0xEC56 // FORMAT_RIE6       ROTATE THEN OR SELECTED BITS
	op_RP      uint32 = 0xB277 // FORMAT_S          RESUME PROGRAM
	op_RRBE    uint32 = 0xB22A // FORMAT_RRE        RESET REFERENCE BIT EXTENDED
	op_RRBM    uint32 = 0xB9AE // FORMAT_RRE        RESET REFERENCE BITS MULTIPLE
	op_RRDTR   uint32 = 0xB3F7 // FORMAT_RRF2       REROUND (long DFP)
	op_RRXTR   uint32 = 0xB3FF // FORMAT_RRF2       REROUND (extended DFP)
	op_RSCH    uint32 = 0xB238 // FORMAT_S          RESUME SUBCHANNEL
	op_RXSBG   uint32 = 0xEC57 // FORMAT_RIE6       ROTATE THEN EXCLUSIVE OR SELECTED BITS
	op_S       uint32 = 0x5B00 // FORMAT_RX1        SUBTRACT (32)
	op_SAC     uint32 = 0xB219 // FORMAT_S          SET ADDRESS SPACE CONTROL
	op_SACF    uint32 = 0xB279 // FORMAT_S          SET ADDRESS SPACE CONTROL FAST
	op_SAL     uint32 = 0xB237 // FORMAT_S          SET ADDRESS LIMIT
	op_SAM24   uint32 = 0x010C // FORMAT_E          SET ADDRESSING MODE (24)
	op_SAM31   uint32 = 0x010D // FORMAT_E          SET ADDRESSING MODE (31)
	op_SAM64   uint32 = 0x010E // FORMAT_E          SET ADDRESSING MODE (64)
	op_SAR     uint32 = 0xB24E // FORMAT_RRE        SET ACCESS
	op_SCHM    uint32 = 0xB23C // FORMAT_S          SET CHANNEL MONITOR
	op_SCK     uint32 = 0xB204 // FORMAT_S          SET CLOCK
	op_SCKC    uint32 = 0xB206 // FORMAT_S          SET CLOCK COMPARATOR
	op_SCKPF   uint32 = 0x0107 // FORMAT_E          SET CLOCK PROGRAMMABLE FIELD
	op_SD      uint32 = 0x6B00 // FORMAT_RX1        SUBTRACT NORMALIZED (long HFP)
	op_SDB     uint32 = 0xED1B // FORMAT_RXE        SUBTRACT (long BFP)
	op_SDBR    uint32 = 0xB31B // FORMAT_RRE        SUBTRACT (long BFP)
	op_SDR     uint32 = 0x2B00 // FORMAT_RR         SUBTRACT NORMALIZED (long HFP)
	op_SDTR    uint32 = 0xB3D3 // FORMAT_RRF1       SUBTRACT (long DFP)
	op_SDTRA   uint32 = 0xB3D3 // FORMAT_RRF1       SUBTRACT (long DFP)
	op_SE      uint32 = 0x7B00 // FORMAT_RX1        SUBTRACT NORMALIZED (short HFP)
	op_SEB     uint32 = 0xED0B // FORMAT_RXE        SUBTRACT (short BFP)
	op_SEBR    uint32 = 0xB30B // FORMAT_RRE        SUBTRACT (short BFP)
	op_SER     uint32 = 0x3B00 // FORMAT_RR         SUBTRACT NORMALIZED (short HFP)
	op_SFASR   uint32 = 0xB385 // FORMAT_RRE        SET FPC AND SIGNAL
	op_SFPC    uint32 = 0xB384 // FORMAT_RRE        SET FPC
	op_SG      uint32 = 0xE309 // FORMAT_RXY1       SUBTRACT (64)
	op_SGF     uint32 = 0xE319 // FORMAT_RXY1       SUBTRACT (64<-32)
	op_SGFR    uint32 = 0xB919 // FORMAT_RRE        SUBTRACT (64<-32)
	op_SGR     uint32 = 0xB909 // FORMAT_RRE        SUBTRACT (64)
	op_SGRK    uint32 = 0xB9E9 // FORMAT_RRF1       SUBTRACT (64)
	op_SH      uint32 = 0x4B00 // FORMAT_RX1        SUBTRACT HALFWORD
	op_SHHHR   uint32 = 0xB9C9 // FORMAT_RRF1       SUBTRACT HIGH (32)
	op_SHHLR   uint32 = 0xB9D9 // FORMAT_RRF1       SUBTRACT HIGH (32)
	op_SHY     uint32 = 0xE37B // FORMAT_RXY1       SUBTRACT HALFWORD
	op_SIGP    uint32 = 0xAE00 // FORMAT_RS1        SIGNAL PROCESSOR
	op_SL      uint32 = 0x5F00 // FORMAT_RX1        SUBTRACT LOGICAL (32)
	op_SLA     uint32 = 0x8B00 // FORMAT_RS1        SHIFT LEFT SINGLE (32)
	op_SLAG    uint32 = 0xEB0B // FORMAT_RSY1       SHIFT LEFT SINGLE (64)
	op_SLAK    uint32 = 0xEBDD // FORMAT_RSY1       SHIFT LEFT SINGLE (32)
	op_SLB     uint32 = 0xE399 // FORMAT_RXY1       SUBTRACT LOGICAL WITH BORROW (32)
	op_SLBG    uint32 = 0xE389 // FORMAT_RXY1       SUBTRACT LOGICAL WITH BORROW (64)
	op_SLBGR   uint32 = 0xB989 // FORMAT_RRE        SUBTRACT LOGICAL WITH BORROW (64)
	op_SLBR    uint32 = 0xB999 // FORMAT_RRE        SUBTRACT LOGICAL WITH BORROW (32)
	op_SLDA    uint32 = 0x8F00 // FORMAT_RS1        SHIFT LEFT DOUBLE
	op_SLDL    uint32 = 0x8D00 // FORMAT_RS1        SHIFT LEFT DOUBLE LOGICAL
	op_SLDT    uint32 = 0xED40 // FORMAT_RXF        SHIFT SIGNIFICAND LEFT (long DFP)
	op_SLFI    uint32 = 0xC205 // FORMAT_RIL1       SUBTRACT LOGICAL IMMEDIATE (32)
	op_SLG     uint32 = 0xE30B // FORMAT_RXY1       SUBTRACT LOGICAL (64)
	op_SLGF    uint32 = 0xE31B // FORMAT_RXY1       SUBTRACT LOGICAL (64<-32)
	op_SLGFI   uint32 = 0xC204 // FORMAT_RIL1       SUBTRACT LOGICAL IMMEDIATE (64<-32)
	op_SLGFR   uint32 = 0xB91B // FORMAT_RRE        SUBTRACT LOGICAL (64<-32)
	op_SLGR    uint32 = 0xB90B // FORMAT_RRE        SUBTRACT LOGICAL (64)
	op_SLGRK   uint32 = 0xB9EB // FORMAT_RRF1       SUBTRACT LOGICAL (64)
	op_SLHHHR  uint32 = 0xB9CB // FORMAT_RRF1       SUBTRACT LOGICAL HIGH (32)
	op_SLHHLR  uint32 = 0xB9DB // FORMAT_RRF1       SUBTRACT LOGICAL HIGH (32)
	op_SLL     uint32 = 0x8900 // FORMAT_RS1        SHIFT LEFT SINGLE LOGICAL (32)
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
```