Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is part of the `asm9_gtables.go` file in the `go/src/cmd/internal/obj/ppc64` package. This file seems to be related to the assembler for the PowerPC 64-bit architecture.

The code consists of several functions named `type_...`, each taking a `ctxt9`, an `obj.Prog`, an `Optab`, and a pointer to a `[5]uint32` array as input. These functions seem to be responsible for generating machine code (represented by the `uint32` array) for different PowerPC instructions.

The function names like `type_xsaddqp`, `type_xscvuqqp`, etc., likely correspond to different PowerPC instruction mnemonics. The code within each function manipulates bits of the output `uint32` array based on the fields of the input `obj.Prog`, which probably represents a parsed assembly instruction.

The `opsetGen` function appears to be related to instruction set extensions or variants. It takes an `obj.As` (likely representing an assembly opcode) and uses a `switch` statement to map certain instructions to other related instructions using the `opset` function.

**Plan:**

1. **Identify the core functionality:** The core functionality is generating machine code for PowerPC64 instructions.
2. **Summarize the `type_...` functions:**  These functions encode different instruction formats into the `uint32` array. They extract information from the `obj.Prog` structure (registers, immediate values, etc.) and place it in the correct bit positions according to the PowerPC instruction encoding.
3. **Summarize the `opsetGen` function:** This function handles variations or extensions of instructions. It seems to map a given instruction to a set of related instructions.
4. **Connect the functions:** The `type_...` functions are likely called based on the instruction type being processed during the assembly process.
5. **Infer the purpose:** The file is part of the assembler and helps translate assembly instructions into machine code.
这是 Go 语言 PowerPC 64 位架构汇编器的代码生成部分。具体来说，它定义了一系列函数（以 `type_` 开头）来处理不同的 PowerPC 指令，并将这些指令编码成机器码（`uint32` 数组）。

**归纳一下它的功能：**

这段代码片段的主要功能是定义了将各种特定的 PowerPC 64 位汇编指令编码成机器码的规则。每个以 `type_` 开头的函数对应一类或一种特定的指令格式，并负责将该指令的操作数（寄存器、立即数等）按照 PowerPC 指令的编码规范填充到 `uint32` 数组中。

更具体地说：

1. **指令类型处理:** 每个 `type_` 函数都对应一种特定的指令格式，例如 `xsaddqp`，`xscvuqqp` 等。这些名称很可能直接对应于 PowerPC 指令的助记符。
2. **操作数提取:**  这些函数从 `obj.Prog` 结构体中提取指令的操作数信息，例如源寄存器 (`p.From.Reg`)、目标寄存器 (`p.To.Reg`)、辅助寄存器 (`p.Reg`)、立即数 (`p.RestArgs[0].Addr.Offset`) 等。
3. **位域编码:**  关键操作是将提取出的操作数值按照指令格式的要求，移动到 `uint32` 数组中对应的位域。例如，`o0 |= uint32(p.To.Reg&0x1f) << 21` 表示将目标寄存器的低 5 位移动到 `o0` 的第 21 位开始的位置。
4. **前缀处理:**  对于一些需要前缀指令的复杂指令（例如 `xxblendvw`, `xxeval`, `xxpermx`, `xxsplti32dx`, `xxspltiw`），代码会先处理前缀操作码 (`GenPfxOpcodes`)，然后再处理主操作码 (`GenOpcodes`)。
5. **`opsetGen` 函数:**  这个函数用于处理指令的变体或别名。它检查给定的指令 (`from`)，并根据指令类型调用 `opset` 函数，将该指令映射到其他相关的指令。这可能是为了处理指令的不同形式（例如，针对不同数据大小的操作）。

**总而言之，这段代码是 PowerPC 64 位汇编器将汇编指令转换为机器码的核心部分，它针对不同的指令定义了具体的编码规则。**

**代码推理示例：**

假设我们有以下 PowerPC 汇编指令：

```assembly
# XT, XA, XB
xxblendvw V1, V2, V3, V4
```

根据 `type_xxblendvw` 函数的定义，我们可以推断出其编码过程：

**假设输入：**

* `p.As`:  `AXXBLENDVW` (表示 `xxblendvw` 指令)
* `p.To.Reg`:  寄存器编号，假设 `V1` 对应编号 1
* `p.From.Reg`: 寄存器编号，假设 `V2` 对应编号 2
* `p.Reg`: 寄存器编号，假设 `V3` 对应编号 3
* `p.RestArgs[0].Addr.Reg`: 寄存器编号，假设 `V4` 对应编号 4

**处理过程：**

1. **前缀操作码 (`o0`)**:  `o0` 从 `GenPfxOpcodes[p.As-AXXSPLTIW]` 获取。这里假设 `AXXSPLTIW` 是一个相关的枚举值，用于索引前缀操作码表。
2. **主操作码 (`o1`)**: `o1` 从 `GenOpcodes[p.As-AXXSETACCZ]` 获取。同样，`AXXSETACCZ` 是一个相关的枚举值。
3. **寄存器编码**:
   * `o1 |= uint32((p.To.Reg>>5)&0x1) << 0`:  提取目标寄存器 `V1` 的高位（bit 5），并放到 `o1` 的 bit 0。
   * `o1 |= uint32(p.To.Reg&0x1f) << 21`: 提取目标寄存器 `V1` 的低 5 位，并放到 `o1` 的 bit 21-25。
   * 类似地，编码源寄存器 `V2`、辅助寄存器 `V3` 和控制寄存器 `V4`。

**可能的输出：**

`out` 数组的前两个元素可能包含以下值（具体数值取决于 `GenPfxOpcodes` 和 `GenOpcodes` 的定义）：

* `out[0]`:  包含前缀操作码的 `uint32` 值。
* `out[1]`:  包含主操作码以及编码后的寄存器信息的 `uint32` 值。

**`opsetGen` 函数的功能举例：**

假设 PowerPC 架构中 `ABRW` 指令是一个泛化的加载指令，而 `ABRH`、`ABRD` 是其针对半字 (Half-word) 和双字 (Double-word) 的具体形式。 当汇编器遇到 `ABRW` 指令时，`opsetGen` 函数会进行如下处理：

**假设输入：**

* `from`: `ABRW`

**处理过程：**

`opsetGen` 函数的 `switch` 语句会匹配到 `case ABRW:`，然后执行以下操作：

```go
case ABRW:
    opset(ABRH, r0)
    opset(ABRD, r0)
```

这意味着，对于 `ABRW` 指令，汇编器可能会将其视为 `ABRH` 和 `ABRD` 这两种具体形式，并分别处理它们的编码。

**使用者易犯错的点：**

这段代码是汇编器内部的实现细节，普通 Go 开发者通常不会直接与它交互。 但是，对于需要深入理解汇编过程或进行底层开发的工程师来说，以下是一些可能犯错的点：

1. **误解指令格式:**  如果对 PowerPC 指令的编码格式不熟悉，可能会错误地理解代码中位域操作的含义，导致无法正确生成机器码。
2. **寄存器编号错误:**  在手动模拟编码过程时，可能会弄错寄存器的编号，导致编码错误。
3. **立即数范围错误:**  某些指令的立即数有取值范围限制，如果超出范围，编码会出错。这段代码中 `&0x1f`, `&0x7`, `&0xff` 等掩码操作暗示了这些限制。
4. **指令变体理解不足:**  `opsetGen` 函数的存在表明某些指令有多种变体。如果不了解这些变体，可能会在汇编时产生困惑。

总而言之，这段代码是 Go 语言 PowerPC 64 位汇编器实现的关键部分，它负责将汇编指令翻译成机器可以执行的二进制代码。理解这段代码需要对 PowerPC 架构的指令集和编码规范有深入的了解。

### 提示词
```
这是路径为go/src/cmd/internal/obj/ppc64/asm9_gtables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
*[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x1f) << 21                // VRT
	o0 |= uint32(p.From.Reg&0x1f) << 16              // VRA
	o0 |= uint32(p.Reg&0x1f) << 11                   // VRB
	o0 |= uint32(p.RestArgs[0].Addr.Offset&0x7) << 6 // SH
	out[0] = o0
}

// xscvuqqp VRT,VRB
func type_xscvuqqp(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x1f) << 21   // VRT
	o0 |= uint32(p.From.Reg&0x1f) << 11 // VRB
	out[0] = o0
}

// xsmincqp VRT,VRA,VRB
func type_xsmincqp(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x1f) << 21   // VRT
	o0 |= uint32(p.From.Reg&0x1f) << 16 // VRA
	o0 |= uint32(p.Reg&0x1f) << 11      // VRB
	out[0] = o0
}

// xvcvspbf16 XT,XB
func type_xvcvspbf16(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32((p.To.Reg>>5)&0x1) << 0   // TX
	o0 |= uint32(p.To.Reg&0x1f) << 21      // T
	o0 |= uint32((p.From.Reg>>5)&0x1) << 1 // BX
	o0 |= uint32(p.From.Reg&0x1f) << 11    // B
	out[0] = o0
}

// xvi8ger4spp AT,XA,XB
func type_xvi8ger4spp(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x7) << 23       // AT
	o0 |= uint32((p.From.Reg>>5)&0x1) << 2 // AX
	o0 |= uint32(p.From.Reg&0x1f) << 16    // A
	o0 |= uint32((p.Reg>>5)&0x1) << 1      // BX
	o0 |= uint32(p.Reg&0x1f) << 11         // B
	out[0] = o0
}

// xvtlsbb BF,XB
func type_xvtlsbb(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x7) << 23       // BF
	o0 |= uint32((p.From.Reg>>5)&0x1) << 1 // BX
	o0 |= uint32(p.From.Reg&0x1f) << 11    // B
	out[0] = o0
}

// xxblendvw XT,XA,XB,XC
func type_xxblendvw(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenPfxOpcodes[p.As-AXXSPLTIW]
	o1 := GenOpcodes[p.As-AXXSETACCZ]
	o1 |= uint32((p.To.Reg>>5)&0x1) << 0               // TX
	o1 |= uint32(p.To.Reg&0x1f) << 21                  // T
	o1 |= uint32((p.From.Reg>>5)&0x1) << 2             // AX
	o1 |= uint32(p.From.Reg&0x1f) << 16                // A
	o1 |= uint32((p.Reg>>5)&0x1) << 1                  // BX
	o1 |= uint32(p.Reg&0x1f) << 11                     // B
	o1 |= uint32((p.RestArgs[0].Addr.Reg>>5)&0x1) << 3 // CX
	o1 |= uint32(p.RestArgs[0].Addr.Reg&0x1f) << 6     // C
	out[1] = o1
	out[0] = o0
}

// xxeval XT,XA,XB,XC,IMM
func type_xxeval(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenPfxOpcodes[p.As-AXXSPLTIW]
	o1 := GenOpcodes[p.As-AXXSETACCZ]
	o1 |= uint32((p.To.Reg>>5)&0x1) << 0               // TX
	o1 |= uint32(p.To.Reg&0x1f) << 21                  // T
	o1 |= uint32((p.From.Reg>>5)&0x1) << 2             // AX
	o1 |= uint32(p.From.Reg&0x1f) << 16                // A
	o1 |= uint32((p.Reg>>5)&0x1) << 1                  // BX
	o1 |= uint32(p.Reg&0x1f) << 11                     // B
	o1 |= uint32((p.RestArgs[0].Addr.Reg>>5)&0x1) << 3 // CX
	o1 |= uint32(p.RestArgs[0].Addr.Reg&0x1f) << 6     // C
	o0 |= uint32(p.RestArgs[1].Addr.Offset&0xff) << 0  // IMM
	out[1] = o1
	out[0] = o0
}

// xxgenpcvwm XT,VRB,IMM
func type_xxgenpcvwm(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32((p.To.Reg>>5)&0x1) << 0               // TX
	o0 |= uint32(p.To.Reg&0x1f) << 21                  // T
	o0 |= uint32(p.From.Reg&0x1f) << 11                // VRB
	o0 |= uint32(p.RestArgs[0].Addr.Offset&0x1f) << 16 // IMM
	out[0] = o0
}

// xxpermx XT,XA,XB,XC,UIM
func type_xxpermx(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenPfxOpcodes[p.As-AXXSPLTIW]
	o1 := GenOpcodes[p.As-AXXSETACCZ]
	o1 |= uint32((p.To.Reg>>5)&0x1) << 0               // TX
	o1 |= uint32(p.To.Reg&0x1f) << 21                  // T
	o1 |= uint32((p.From.Reg>>5)&0x1) << 2             // AX
	o1 |= uint32(p.From.Reg&0x1f) << 16                // A
	o1 |= uint32((p.Reg>>5)&0x1) << 1                  // BX
	o1 |= uint32(p.Reg&0x1f) << 11                     // B
	o1 |= uint32((p.RestArgs[0].Addr.Reg>>5)&0x1) << 3 // CX
	o1 |= uint32(p.RestArgs[0].Addr.Reg&0x1f) << 6     // C
	o0 |= uint32(p.RestArgs[1].Addr.Offset&0x7) << 0   // UIM
	out[1] = o1
	out[0] = o0
}

// xxsetaccz AT
func type_xxsetaccz(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenOpcodes[p.As-AXXSETACCZ]
	o0 |= uint32(p.To.Reg&0x7) << 23 // AT
	out[0] = o0
}

// xxsplti32dx XT,IX,IMM32
func type_xxsplti32dx(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenPfxOpcodes[p.As-AXXSPLTIW]
	o1 := GenOpcodes[p.As-AXXSETACCZ]
	o1 |= uint32((p.To.Reg>>5)&0x1) << 16                     // TX
	o1 |= uint32(p.To.Reg&0x1f) << 21                         // T
	o1 |= uint32(p.From.Offset&0x1) << 17                     // IX
	o0 |= uint32((p.RestArgs[0].Addr.Offset>>16)&0xffff) << 0 // imm0
	o1 |= uint32(p.RestArgs[0].Addr.Offset&0xffff) << 0       // imm1
	out[1] = o1
	out[0] = o0
}

// xxspltiw XT,IMM32
func type_xxspltiw(c *ctxt9, p *obj.Prog, t *Optab, out *[5]uint32) {
	o0 := GenPfxOpcodes[p.As-AXXSPLTIW]
	o1 := GenOpcodes[p.As-AXXSETACCZ]
	o1 |= uint32((p.To.Reg>>5)&0x1) << 16         // TX
	o1 |= uint32(p.To.Reg&0x1f) << 21             // T
	o0 |= uint32((p.From.Offset>>16)&0xffff) << 0 // imm0
	o1 |= uint32(p.From.Offset&0xffff) << 0       // imm1
	out[1] = o1
	out[0] = o0
}

func opsetGen(from obj.As) bool {
	r0 := from & obj.AMask
	switch from {
	case ABRW:
		opset(ABRH, r0)
		opset(ABRD, r0)
	case ADCFFIXQQ:
	case ADCTFIXQQ:
	case AHASHCHKP:
		opset(AHASHCHK, r0)
	case AHASHSTP:
		opset(AHASHST, r0)
	case ALXVKQ:
	case ALXVP:
	case ALXVPX:
	case ALXVRWX:
		opset(ALXVRHX, r0)
		opset(ALXVRDX, r0)
		opset(ALXVRBX, r0)
	case AMTVSRBMI:
	case AMTVSRWM:
		opset(AMTVSRQM, r0)
		opset(AMTVSRHM, r0)
		opset(AMTVSRDM, r0)
		opset(AMTVSRBM, r0)
	case APADDI:
	case APEXTD:
		opset(APDEPD, r0)
		opset(ACNTTZDM, r0)
		opset(ACNTLZDM, r0)
		opset(ACFUGED, r0)
	case APLFS:
		opset(APLFD, r0)
	case APLQ:
	case APLWZ:
		opset(APLWA, r0)
		opset(APLHZ, r0)
		opset(APLHA, r0)
		opset(APLD, r0)
		opset(APLBZ, r0)
	case APLXSSP:
		opset(APLXSD, r0)
	case APLXV:
	case APLXVP:
	case APMXVF32GERPP:
		opset(APMXVF32GERPN, r0)
		opset(APMXVF32GERNP, r0)
		opset(APMXVF32GERNN, r0)
		opset(APMXVF32GER, r0)
	case APMXVF64GERPP:
		opset(APMXVF64GERPN, r0)
		opset(APMXVF64GERNP, r0)
		opset(APMXVF64GERNN, r0)
		opset(APMXVF64GER, r0)
	case APMXVI16GER2SPP:
		opset(APMXVI16GER2S, r0)
		opset(APMXVI16GER2PP, r0)
		opset(APMXVI16GER2, r0)
		opset(APMXVF16GER2PP, r0)
		opset(APMXVF16GER2PN, r0)
		opset(APMXVF16GER2NP, r0)
		opset(APMXVF16GER2NN, r0)
		opset(APMXVF16GER2, r0)
		opset(APMXVBF16GER2PP, r0)
		opset(APMXVBF16GER2PN, r0)
		opset(APMXVBF16GER2NP, r0)
		opset(APMXVBF16GER2NN, r0)
		opset(APMXVBF16GER2, r0)
	case APMXVI4GER8PP:
		opset(APMXVI4GER8, r0)
	case APMXVI8GER4SPP:
		opset(APMXVI8GER4PP, r0)
		opset(APMXVI8GER4, r0)
	case APNOP:
	case APSTFS:
		opset(APSTFD, r0)
	case APSTQ:
	case APSTW:
		opset(APSTH, r0)
		opset(APSTD, r0)
		opset(APSTB, r0)
	case APSTXSSP:
		opset(APSTXSD, r0)
	case APSTXV:
	case APSTXVP:
	case ASETNBCR:
		opset(ASETNBC, r0)
		opset(ASETBCR, r0)
		opset(ASETBC, r0)
	case ASTXVP:
	case ASTXVPX:
	case ASTXVRWX:
		opset(ASTXVRHX, r0)
		opset(ASTXVRDX, r0)
		opset(ASTXVRBX, r0)
	case AVCLRRB:
		opset(AVCLRLB, r0)
	case AVCMPUQ:
		opset(AVCMPSQ, r0)
	case AVCNTMBW:
		opset(AVCNTMBH, r0)
		opset(AVCNTMBD, r0)
		opset(AVCNTMBB, r0)
	case AVEXTDUWVRX:
		opset(AVEXTDUWVLX, r0)
		opset(AVEXTDUHVRX, r0)
		opset(AVEXTDUHVLX, r0)
		opset(AVEXTDUBVRX, r0)
		opset(AVEXTDUBVLX, r0)
		opset(AVEXTDDVRX, r0)
		opset(AVEXTDDVLX, r0)
	case AVEXTRACTWM:
		opset(AVEXTRACTQM, r0)
		opset(AVEXTRACTHM, r0)
		opset(AVEXTRACTDM, r0)
		opset(AVEXTRACTBM, r0)
	case AVGNB:
	case AVINSW:
		opset(AVINSD, r0)
	case AVINSWRX:
		opset(AVINSWLX, r0)
		opset(AVINSHRX, r0)
		opset(AVINSHLX, r0)
		opset(AVINSDRX, r0)
		opset(AVINSDLX, r0)
		opset(AVINSBRX, r0)
		opset(AVINSBLX, r0)
	case AVINSWVRX:
		opset(AVINSWVLX, r0)
		opset(AVINSHVRX, r0)
		opset(AVINSHVLX, r0)
		opset(AVINSBVRX, r0)
		opset(AVINSBVLX, r0)
	case AVMSUMCUD:
	case AVSRDBI:
		opset(AVSLDBI, r0)
	case AXSCVUQQP:
		opset(AXSCVSQQP, r0)
		opset(AXSCVQPUQZ, r0)
		opset(AXSCVQPSQZ, r0)
		opset(AVSTRIHRCC, r0)
		opset(AVSTRIHR, r0)
		opset(AVSTRIHLCC, r0)
		opset(AVSTRIHL, r0)
		opset(AVSTRIBRCC, r0)
		opset(AVSTRIBR, r0)
		opset(AVSTRIBLCC, r0)
		opset(AVSTRIBL, r0)
		opset(AVEXTSD2Q, r0)
		opset(AVEXPANDWM, r0)
		opset(AVEXPANDQM, r0)
		opset(AVEXPANDHM, r0)
		opset(AVEXPANDDM, r0)
		opset(AVEXPANDBM, r0)
	case AXSMINCQP:
		opset(AXSMAXCQP, r0)
		opset(AXSCMPGTQP, r0)
		opset(AXSCMPGEQP, r0)
		opset(AXSCMPEQQP, r0)
		opset(AVSRQ, r0)
		opset(AVSRAQ, r0)
		opset(AVSLQ, r0)
		opset(AVRLQNM, r0)
		opset(AVRLQMI, r0)
		opset(AVRLQ, r0)
		opset(AVPEXTD, r0)
		opset(AVPDEPD, r0)
		opset(AVMULOUD, r0)
		opset(AVMULOSD, r0)
		opset(AVMULLD, r0)
		opset(AVMULHUW, r0)
		opset(AVMULHUD, r0)
		opset(AVMULHSW, r0)
		opset(AVMULHSD, r0)
		opset(AVMULEUD, r0)
		opset(AVMULESD, r0)
		opset(AVMODUW, r0)
		opset(AVMODUQ, r0)
		opset(AVMODUD, r0)
		opset(AVMODSW, r0)
		opset(AVMODSQ, r0)
		opset(AVMODSD, r0)
		opset(AVDIVUW, r0)
		opset(AVDIVUQ, r0)
		opset(AVDIVUD, r0)
		opset(AVDIVSW, r0)
		opset(AVDIVSQ, r0)
		opset(AVDIVSD, r0)
		opset(AVDIVEUW, r0)
		opset(AVDIVEUQ, r0)
		opset(AVDIVEUD, r0)
		opset(AVDIVESW, r0)
		opset(AVDIVESQ, r0)
		opset(AVDIVESD, r0)
		opset(AVCTZDM, r0)
		opset(AVCMPGTUQCC, r0)
		opset(AVCMPGTUQ, r0)
		opset(AVCMPGTSQCC, r0)
		opset(AVCMPGTSQ, r0)
		opset(AVCMPEQUQCC, r0)
		opset(AVCMPEQUQ, r0)
		opset(AVCLZDM, r0)
		opset(AVCFUGED, r0)
	case AXVCVSPBF16:
		opset(AXVCVBF16SPN, r0)
	case AXVI8GER4SPP:
		opset(AXVI8GER4PP, r0)
		opset(AXVI8GER4, r0)
		opset(AXVI4GER8PP, r0)
		opset(AXVI4GER8, r0)
		opset(AXVI16GER2SPP, r0)
		opset(AXVI16GER2S, r0)
		opset(AXVI16GER2PP, r0)
		opset(AXVI16GER2, r0)
		opset(AXVF64GERPP, r0)
		opset(AXVF64GERPN, r0)
		opset(AXVF64GERNP, r0)
		opset(AXVF64GERNN, r0)
		opset(AXVF64GER, r0)
		opset(AXVF32GERPP, r0)
		opset(AXVF32GERPN, r0)
		opset(AXVF32GERNP, r0)
		opset(AXVF32GERNN, r0)
		opset(AXVF32GER, r0)
		opset(AXVF16GER2PP, r0)
		opset(AXVF16GER2PN, r0)
		opset(AXVF16GER2NP, r0)
		opset(AXVF16GER2NN, r0)
		opset(AXVF16GER2, r0)
		opset(AXVBF16GER2PP, r0)
		opset(AXVBF16GER2PN, r0)
		opset(AXVBF16GER2NP, r0)
		opset(AXVBF16GER2NN, r0)
		opset(AXVBF16GER2, r0)
	case AXVTLSBB:
	case AXXBLENDVW:
		opset(AXXBLENDVH, r0)
		opset(AXXBLENDVD, r0)
		opset(AXXBLENDVB, r0)
	case AXXEVAL:
	case AXXGENPCVWM:
		opset(AXXGENPCVHM, r0)
		opset(AXXGENPCVDM, r0)
		opset(AXXGENPCVBM, r0)
	case AXXPERMX:
	case AXXSETACCZ:
		opset(AXXMTACC, r0)
		opset(AXXMFACC, r0)
	case AXXSPLTI32DX:
	case AXXSPLTIW:
		opset(AXXSPLTIDP, r0)
	default:
		return false
	}
	return true
}
```