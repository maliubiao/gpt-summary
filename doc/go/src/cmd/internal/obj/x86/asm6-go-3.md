Response:
The user wants a summary of the functionality of the provided Go code snippet from `go/src/cmd/internal/obj/x86/asm6.go`. This file seems to be responsible for assembling x86 instructions.

Here's a plan to generate the response:

1. **Identify key functions and data structures:** Look for function definitions and prominent data structures used in the code.
2. **Analyze the logic:** Understand the purpose of the identified functions and how they manipulate data.
3. **Infer the overall goal:** Based on the analysis, determine the main objective of this code snippet.
4. **Relate to Go features:** If possible, connect the code to specific Go language features or functionalities.
5. **Construct a concise summary:**  Write a summary highlighting the core functionalities.
这段代码是Go语言编译器中x86架构的汇编器 (`asm6.go`) 的一部分，主要负责将中间表示的指令 (`obj.Prog`) 编码成实际的机器码。它处理指令的操作数，并根据不同的操作数类型和指令特性生成相应的字节码。

**功能归纳:**

这段代码的主要功能是处理指令的操作数，并将其编码成机器码的一部分。具体来说，它涵盖了以下几个方面：

1. **处理地址操作数 (`asmandsz`, `asmand`, `asmando`)**:
   - 根据操作数的类型 (寄存器、内存地址、立即数等) 和属性 (静态、自动、参数等) 计算出相应的内存偏移或寄存器编码。
   - 处理不同的寻址模式，例如直接寻址、寄存器寻址、基址加偏移寻址、比例变址寻址等。
   - 考虑了32位和64位架构的差异，以及共享库的情况下的特殊处理。
   - 将计算出的偏移或立即数编码到输出的字节流中。

2. **处理特殊寄存器和段寄存器 (`bytereg`, `unbytereg`)**:
   - 针对字节操作，调整寄存器的编码。例如，将 `AX` 转换为 `AL` 等。
   - 处理段寄存器的操作，如 `PUSH` 和 `POP` 段寄存器。

3. **处理 `MOV` 指令的特殊情况 (`ymovtab`)**:
   - 定义了一个查找表 `ymovtab`，用于处理 `MOV` 指令的不同变体，尤其是涉及段寄存器、控制寄存器、调试寄存器等的移动操作。
   - 这个表记录了不同操作数类型的 `MOV` 指令对应的操作码和编码方式。

4. **处理媒体指令前缀 (`mediaop`)**:
   - 处理像 `0F`, `66`, `F3` 等媒体指令前缀，这些前缀用于指示特定的指令集扩展（如SSE, AVX）。

5. **处理 VEX 和 EVEX 前缀指令 (`asmevex`, `asmvex`)**:
   - 负责编码 AVX 和 AVX-512 指令的 VEX 和 EVEX 前缀。
   - 这涉及到复杂的位域设置，包括 REX 位、操作码扩展位、向量长度、掩码寄存器等。

6. **处理 AVX2 和 AVX512 的 gather 指令验证 (`avx2gatherValid`, `avx512gatherValid`)**:
   - 针对 AVX2 和 AVX512 的 gather 指令，进行操作数寄存器的有效性检查，以避免触发非法指令异常。

7. **主要的汇编逻辑 (`doasm`)**:
   - 查找指令对应的操作码表 (`opindex`)。
   - 处理指令前缀。
   - 根据操作数类型和指令特性，选择合适的编码方式。
   - 调用相应的函数来编码操作数。
   - 将最终的机器码写入到输出缓冲区 (`AsmBuf`)。

**Go 语言功能的实现推断:**

这段代码是Go编译器将Go语言代码编译成机器码的关键部分。它负责将Go语言的汇编指令（通常在低级代码或汇编文件中使用）转换成CPU可以直接执行的二进制代码。

**Go 代码举例 (假设的输入与输出):**

假设我们有以下 Go 汇编代码：

```go
//go:noescape
func Add(a, b int) int

// TEXT ·Add(SB), NOSPLIT, $0-24
//  MOVQ a+0(FP), AX
//  ADDQ b+8(FP), AX
//  MOVQ AX, ret+16(FP)
//  RET
```

当编译器处理 `ADDQ b+8(FP), AX` 这条指令时，`doasm` 函数会被调用，`p` 参数会包含这条指令的信息，包括操作码 `ADDQ`，源操作数 `b+8(FP)` 和目标操作数 `AX`。

**假设的输入 `p` (简化表示):**

```
p.As = AADDQ // ADDQ 指令
p.From.Type = TYPE_MEM // 源操作数为内存地址
p.From.Reg = REG_FP   // 基址寄存器为 FP (帧指针)
p.From.Offset = 8    // 偏移量为 8
p.To.Type = TYPE_REG  // 目标操作数为寄存器
p.To.Reg = REG_AX    // 目标寄存器为 AX
```

**可能的输出字节码 (简化表示):**

假设经过 `asmandsz` 或相关函数的处理，会生成类似以下的字节码：

```
48 01 45 08  //  ADDQ 0x8(%rbp), %rax  (实际字节码可能略有不同)
```

**代码推理:**

- `doasm` 函数会根据 `p.As` 找到 `AADDQ` 对应的操作码信息。
- 由于源操作数是内存地址，目标操作数是寄存器，会调用类似 `asmand` 的函数来处理。
- `asmand` 会根据 `p.From` 的信息，计算出基于 `FP` 寄存器偏移 8 字节的内存地址。
- 它会根据目标操作数 `p.To.Reg` (即 `AX`) 生成相应的寄存器编码。
- 最终将操作码和操作数编码组合成机器码。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在更上层的编译流程中，例如 `compile` 函数或更早的阶段。编译器会根据命令行参数（如目标架构、是否生成共享库等）来设置 `ctxt` 中的标志，这些标志会影响汇编代码的生成。例如，`ctxt.Flag_shared` 标志会影响静态符号的寻址方式。

**使用者易犯错的点 (开发者编写汇编代码时):**

虽然 `asm6.go` 是编译器内部的代码，但开发者在编写 Go 汇编代码时可能会遇到以下易错点，这些错误可能导致 `asm6.go` 生成错误的机器码或报错：

1. **错误的寄存器名称或类型:** 使用了不存在的寄存器或者在指令中使用了错误的寄存器大小（例如，在需要 64 位寄存器的地方使用了 32 位寄存器）。
2. **错误的内存寻址方式:**  偏移量计算错误，或者使用了不支持的寻址模式组合。例如，在某些情况下，立即数不能直接作为内存地址。
3. **指令操作数类型不匹配:**  指令要求的操作数类型与实际提供的操作数类型不符。例如，`MOV` 指令的源操作数和目标操作数的大小必须匹配。
4. **忽略了架构差异:**  在不同的 CPU 架构（例如 32 位和 64 位）下，某些指令的编码方式或可用寄存器可能不同。
5. **在共享库中错误使用绝对地址:**  在生成共享库时，需要避免使用绝对地址，而是使用与位置无关的代码 (PIC)。`asm6.go` 中的 `useAbs` 函数和对 `ctxt.Flag_shared` 的检查就与此相关。

**总结:**

这段 `asm6.go` 代码是 Go 语言 x86 架构汇编器的核心部分，负责将中间表示的指令转换为实际的机器码。它处理各种操作数类型和寻址模式，并针对不同的指令和架构特性进行编码。虽然开发者不直接操作这段代码，但了解其功能有助于理解 Go 语言的编译过程和编写正确的 Go 汇编代码。

### 提示词
```
这是路径为go/src/cmd/internal/obj/x86/asm6.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```go
F,
			obj.NAME_STATIC:
			if !useAbs(ctxt, a.Sym) && ctxt.Arch.Family == sys.AMD64 {
				goto bad
			}
			if ctxt.Arch.Family == sys.I386 && ctxt.Flag_shared {
				// The base register has already been set. It holds the PC
				// of this instruction returned by a PC-reading thunk.
				// See obj6.go:rewriteToPcrel.
			} else {
				base = REG_NONE
			}
			v = int32(vaddr(ctxt, p, a, &rel))

		case obj.NAME_AUTO,
			obj.NAME_PARAM:
			base = REG_SP
		}

		ab.rexflag |= regrex[int(a.Index)]&Rxx | regrex[base]&Rxb | rex
		if base == REG_NONE {
			ab.Put1(byte(0<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			goto putrelv
		}

		if v == 0 && rel.Siz == 0 && base != REG_BP && base != REG_R13 {
			ab.Put1(byte(0<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok && rel.Siz == 0 {
			ab.Put1(byte(1<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			ab.Put1(disp8)
			return
		}

		ab.Put1(byte(2<<6 | 4<<0 | r<<3))
		ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
		goto putrelv
	}

	base = int(a.Reg)
	switch a.Name {
	case obj.NAME_STATIC,
		obj.NAME_GOTREF,
		obj.NAME_EXTERN:
		if a.Sym == nil {
			ctxt.Diag("bad addr: %v", p)
		}
		if ctxt.Arch.Family == sys.I386 && ctxt.Flag_shared {
			// The base register has already been set. It holds the PC
			// of this instruction returned by a PC-reading thunk.
			// See obj6.go:rewriteToPcrel.
		} else {
			base = REG_NONE
		}
		v = int32(vaddr(ctxt, p, a, &rel))

	case obj.NAME_AUTO,
		obj.NAME_PARAM:
		base = REG_SP
	}

	if base == REG_TLS {
		v = int32(vaddr(ctxt, p, a, &rel))
	}

	ab.rexflag |= regrex[base]&Rxb | rex
	if base == REG_NONE || (REG_CS <= base && base <= REG_GS) || base == REG_TLS {
		if (a.Sym == nil || !useAbs(ctxt, a.Sym)) && base == REG_NONE && (a.Name == obj.NAME_STATIC || a.Name == obj.NAME_EXTERN || a.Name == obj.NAME_GOTREF) || ctxt.Arch.Family != sys.AMD64 {
			if a.Name == obj.NAME_GOTREF && (a.Offset != 0 || a.Index != 0 || a.Scale != 0) {
				ctxt.Diag("%v has offset against gotref", p)
			}
			ab.Put1(byte(0<<6 | 5<<0 | r<<3))
			goto putrelv
		}

		// temporary
		ab.Put2(
			byte(0<<6|4<<0|r<<3), // sib present
			0<<6|4<<3|5<<0,       // DS:d32
		)
		goto putrelv
	}

	if base == REG_SP || base == REG_R12 {
		if v == 0 {
			ab.Put1(byte(0<<6 | reg[base]<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok {
			ab.Put1(byte(1<<6 | reg[base]<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
			ab.Put1(disp8)
			return
		}

		ab.Put1(byte(2<<6 | reg[base]<<0 | r<<3))
		ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
		goto putrelv
	}

	if REG_AX <= base && base <= REG_R15 {
		if a.Index == REG_TLS && !ctxt.Flag_shared && !isAndroid &&
			ctxt.Headtype != objabi.Hwindows {
			rel = obj.Reloc{}
			rel.Type = objabi.R_TLS_LE
			rel.Siz = 4
			rel.Sym = nil
			rel.Add = int64(v)
			v = 0
		}

		if v == 0 && rel.Siz == 0 && base != REG_BP && base != REG_R13 {
			ab.Put1(byte(0<<6 | reg[base]<<0 | r<<3))
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok && rel.Siz == 0 {
			ab.Put2(byte(1<<6|reg[base]<<0|r<<3), disp8)
			return
		}

		ab.Put1(byte(2<<6 | reg[base]<<0 | r<<3))
		goto putrelv
	}

	goto bad

putrelv:
	if rel.Siz != 0 {
		if rel.Siz != 4 {
			ctxt.Diag("bad rel")
			goto bad
		}

		rel.Off = int32(p.Pc + int64(ab.Len()))
		cursym.AddRel(ctxt, rel)
	}

	ab.PutInt32(v)
	return

bad:
	ctxt.Diag("asmand: bad address %v", obj.Dconv(p, a))
}

func (ab *AsmBuf) asmand(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr, ra *obj.Addr) {
	ab.asmandsz(ctxt, cursym, p, a, reg[ra.Reg], regrex[ra.Reg], 0)
}

func (ab *AsmBuf) asmando(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr, o int) {
	ab.asmandsz(ctxt, cursym, p, a, o, 0, 0)
}

func bytereg(a *obj.Addr, t *uint8) {
	if a.Type == obj.TYPE_REG && a.Index == REG_NONE && (REG_AX <= a.Reg && a.Reg <= REG_R15) {
		a.Reg += REG_AL - REG_AX
		*t = 0
	}
}

func unbytereg(a *obj.Addr, t *uint8) {
	if a.Type == obj.TYPE_REG && a.Index == REG_NONE && (REG_AL <= a.Reg && a.Reg <= REG_R15B) {
		a.Reg += REG_AX - REG_AL
		*t = 0
	}
}

const (
	movLit uint8 = iota // Like Zlit
	movRegMem
	movMemReg
	movRegMem2op
	movMemReg2op
	movFullPtr // Load full pointer, trash heap (unsupported)
	movDoubleShift
	movTLSReg
)

var ymovtab = []movtab{
	// push
	{APUSHL, Ycs, Ynone, Ynone, movLit, [4]uint8{0x0e, 0}},
	{APUSHL, Yss, Ynone, Ynone, movLit, [4]uint8{0x16, 0}},
	{APUSHL, Yds, Ynone, Ynone, movLit, [4]uint8{0x1e, 0}},
	{APUSHL, Yes, Ynone, Ynone, movLit, [4]uint8{0x06, 0}},
	{APUSHL, Yfs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa0, 0}},
	{APUSHL, Ygs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa8, 0}},
	{APUSHQ, Yfs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa0, 0}},
	{APUSHQ, Ygs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa8, 0}},
	{APUSHW, Ycs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0e, 0}},
	{APUSHW, Yss, Ynone, Ynone, movLit, [4]uint8{Pe, 0x16, 0}},
	{APUSHW, Yds, Ynone, Ynone, movLit, [4]uint8{Pe, 0x1e, 0}},
	{APUSHW, Yes, Ynone, Ynone, movLit, [4]uint8{Pe, 0x06, 0}},
	{APUSHW, Yfs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0f, 0xa0, 0}},
	{APUSHW, Ygs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0f, 0xa8, 0}},

	// pop
	{APOPL, Ynone, Ynone, Yds, movLit, [4]uint8{0x1f, 0}},
	{APOPL, Ynone, Ynone, Yes, movLit, [4]uint8{0x07, 0}},
	{APOPL, Ynone, Ynone, Yss, movLit, [4]uint8{0x17, 0}},
	{APOPL, Ynone, Ynone, Yfs, movLit, [4]uint8{0x0f, 0xa1, 0}},
	{APOPL, Ynone, Ynone, Ygs, movLit, [4]uint8{0x0f, 0xa9, 0}},
	{APOPQ, Ynone, Ynone, Yfs, movLit, [4]uint8{0x0f, 0xa1, 0}},
	{APOPQ, Ynone, Ynone, Ygs, movLit, [4]uint8{0x0f, 0xa9, 0}},
	{APOPW, Ynone, Ynone, Yds, movLit, [4]uint8{Pe, 0x1f, 0}},
	{APOPW, Ynone, Ynone, Yes, movLit, [4]uint8{Pe, 0x07, 0}},
	{APOPW, Ynone, Ynone, Yss, movLit, [4]uint8{Pe, 0x17, 0}},
	{APOPW, Ynone, Ynone, Yfs, movLit, [4]uint8{Pe, 0x0f, 0xa1, 0}},
	{APOPW, Ynone, Ynone, Ygs, movLit, [4]uint8{Pe, 0x0f, 0xa9, 0}},

	// mov seg
	{AMOVW, Yes, Ynone, Yml, movRegMem, [4]uint8{0x8c, 0, 0, 0}},
	{AMOVW, Ycs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 1, 0, 0}},
	{AMOVW, Yss, Ynone, Yml, movRegMem, [4]uint8{0x8c, 2, 0, 0}},
	{AMOVW, Yds, Ynone, Yml, movRegMem, [4]uint8{0x8c, 3, 0, 0}},
	{AMOVW, Yfs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 4, 0, 0}},
	{AMOVW, Ygs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 5, 0, 0}},
	{AMOVW, Yml, Ynone, Yes, movMemReg, [4]uint8{0x8e, 0, 0, 0}},
	{AMOVW, Yml, Ynone, Ycs, movMemReg, [4]uint8{0x8e, 1, 0, 0}},
	{AMOVW, Yml, Ynone, Yss, movMemReg, [4]uint8{0x8e, 2, 0, 0}},
	{AMOVW, Yml, Ynone, Yds, movMemReg, [4]uint8{0x8e, 3, 0, 0}},
	{AMOVW, Yml, Ynone, Yfs, movMemReg, [4]uint8{0x8e, 4, 0, 0}},
	{AMOVW, Yml, Ynone, Ygs, movMemReg, [4]uint8{0x8e, 5, 0, 0}},

	// mov cr
	{AMOVL, Ycr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 0, 0}},
	{AMOVL, Ycr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 2, 0}},
	{AMOVL, Ycr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 3, 0}},
	{AMOVL, Ycr4, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 4, 0}},
	{AMOVL, Ycr8, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 8, 0}},
	{AMOVQ, Ycr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 0, 0}},
	{AMOVQ, Ycr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 2, 0}},
	{AMOVQ, Ycr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 3, 0}},
	{AMOVQ, Ycr4, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 4, 0}},
	{AMOVQ, Ycr8, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 8, 0}},
	{AMOVL, Yrl, Ynone, Ycr0, movMemReg2op, [4]uint8{0x0f, 0x22, 0, 0}},
	{AMOVL, Yrl, Ynone, Ycr2, movMemReg2op, [4]uint8{0x0f, 0x22, 2, 0}},
	{AMOVL, Yrl, Ynone, Ycr3, movMemReg2op, [4]uint8{0x0f, 0x22, 3, 0}},
	{AMOVL, Yrl, Ynone, Ycr4, movMemReg2op, [4]uint8{0x0f, 0x22, 4, 0}},
	{AMOVL, Yrl, Ynone, Ycr8, movMemReg2op, [4]uint8{0x0f, 0x22, 8, 0}},
	{AMOVQ, Yrl, Ynone, Ycr0, movMemReg2op, [4]uint8{0x0f, 0x22, 0, 0}},
	{AMOVQ, Yrl, Ynone, Ycr2, movMemReg2op, [4]uint8{0x0f, 0x22, 2, 0}},
	{AMOVQ, Yrl, Ynone, Ycr3, movMemReg2op, [4]uint8{0x0f, 0x22, 3, 0}},
	{AMOVQ, Yrl, Ynone, Ycr4, movMemReg2op, [4]uint8{0x0f, 0x22, 4, 0}},
	{AMOVQ, Yrl, Ynone, Ycr8, movMemReg2op, [4]uint8{0x0f, 0x22, 8, 0}},

	// mov dr
	{AMOVL, Ydr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 0, 0}},
	{AMOVL, Ydr6, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 6, 0}},
	{AMOVL, Ydr7, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 7, 0}},
	{AMOVQ, Ydr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 0, 0}},
	{AMOVQ, Ydr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 2, 0}},
	{AMOVQ, Ydr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 3, 0}},
	{AMOVQ, Ydr6, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 6, 0}},
	{AMOVQ, Ydr7, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 7, 0}},
	{AMOVL, Yrl, Ynone, Ydr0, movMemReg2op, [4]uint8{0x0f, 0x23, 0, 0}},
	{AMOVL, Yrl, Ynone, Ydr6, movMemReg2op, [4]uint8{0x0f, 0x23, 6, 0}},
	{AMOVL, Yrl, Ynone, Ydr7, movMemReg2op, [4]uint8{0x0f, 0x23, 7, 0}},
	{AMOVQ, Yrl, Ynone, Ydr0, movMemReg2op, [4]uint8{0x0f, 0x23, 0, 0}},
	{AMOVQ, Yrl, Ynone, Ydr2, movMemReg2op, [4]uint8{0x0f, 0x23, 2, 0}},
	{AMOVQ, Yrl, Ynone, Ydr3, movMemReg2op, [4]uint8{0x0f, 0x23, 3, 0}},
	{AMOVQ, Yrl, Ynone, Ydr6, movMemReg2op, [4]uint8{0x0f, 0x23, 6, 0}},
	{AMOVQ, Yrl, Ynone, Ydr7, movMemReg2op, [4]uint8{0x0f, 0x23, 7, 0}},

	// mov tr
	{AMOVL, Ytr6, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x24, 6, 0}},
	{AMOVL, Ytr7, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x24, 7, 0}},
	{AMOVL, Yml, Ynone, Ytr6, movMemReg2op, [4]uint8{0x0f, 0x26, 6, 0xff}},
	{AMOVL, Yml, Ynone, Ytr7, movMemReg2op, [4]uint8{0x0f, 0x26, 7, 0xff}},

	// lgdt, sgdt, lidt, sidt
	{AMOVL, Ym, Ynone, Ygdtr, movMemReg2op, [4]uint8{0x0f, 0x01, 2, 0}},
	{AMOVL, Ygdtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 0, 0}},
	{AMOVL, Ym, Ynone, Yidtr, movMemReg2op, [4]uint8{0x0f, 0x01, 3, 0}},
	{AMOVL, Yidtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 1, 0}},
	{AMOVQ, Ym, Ynone, Ygdtr, movMemReg2op, [4]uint8{0x0f, 0x01, 2, 0}},
	{AMOVQ, Ygdtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 0, 0}},
	{AMOVQ, Ym, Ynone, Yidtr, movMemReg2op, [4]uint8{0x0f, 0x01, 3, 0}},
	{AMOVQ, Yidtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 1, 0}},

	// lldt, sldt
	{AMOVW, Yml, Ynone, Yldtr, movMemReg2op, [4]uint8{0x0f, 0x00, 2, 0}},
	{AMOVW, Yldtr, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x00, 0, 0}},

	// lmsw, smsw
	{AMOVW, Yml, Ynone, Ymsw, movMemReg2op, [4]uint8{0x0f, 0x01, 6, 0}},
	{AMOVW, Ymsw, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x01, 4, 0}},

	// ltr, str
	{AMOVW, Yml, Ynone, Ytask, movMemReg2op, [4]uint8{0x0f, 0x00, 3, 0}},
	{AMOVW, Ytask, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x00, 1, 0}},

	/* load full pointer - unsupported
	{AMOVL, Yml, Ycol, movFullPtr, [4]uint8{0, 0, 0, 0}},
	{AMOVW, Yml, Ycol, movFullPtr, [4]uint8{Pe, 0, 0, 0}},
	*/

	// double shift
	{ASHLL, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHLL, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHLL, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHRL, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHRL, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHRL, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHLQ, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHLQ, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHLQ, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHRQ, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHRQ, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHRQ, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHLW, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHLW, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHLW, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHRW, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},
	{ASHRW, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},
	{ASHRW, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},

	// load TLS base
	{AMOVL, Ytls, Ynone, Yrl, movTLSReg, [4]uint8{0, 0, 0, 0}},
	{AMOVQ, Ytls, Ynone, Yrl, movTLSReg, [4]uint8{0, 0, 0, 0}},
	{0, 0, 0, 0, 0, [4]uint8{}},
}

func isax(a *obj.Addr) bool {
	switch a.Reg {
	case REG_AX, REG_AL, REG_AH:
		return true
	}

	return a.Index == REG_AX
}

func subreg(p *obj.Prog, from int, to int) {
	if false { /* debug['Q'] */
		fmt.Printf("\n%v\ts/%v/%v/\n", p, rconv(from), rconv(to))
	}

	if int(p.From.Reg) == from {
		p.From.Reg = int16(to)
		p.Ft = 0
	}

	if int(p.To.Reg) == from {
		p.To.Reg = int16(to)
		p.Tt = 0
	}

	if int(p.From.Index) == from {
		p.From.Index = int16(to)
		p.Ft = 0
	}

	if int(p.To.Index) == from {
		p.To.Index = int16(to)
		p.Tt = 0
	}

	if false { /* debug['Q'] */
		fmt.Printf("%v\n", p)
	}
}

func (ab *AsmBuf) mediaop(ctxt *obj.Link, o *Optab, op int, osize int, z int) int {
	switch op {
	case Pm, Pe, Pf2, Pf3:
		if osize != 1 {
			if op != Pm {
				ab.Put1(byte(op))
			}
			ab.Put1(Pm)
			z++
			op = int(o.op[z])
			break
		}
		fallthrough

	default:
		if ab.Len() == 0 || ab.Last() != Pm {
			ab.Put1(Pm)
		}
	}

	ab.Put1(byte(op))
	return z
}

var bpduff1 = []byte{
	0x48, 0x89, 0x6c, 0x24, 0xf0, // MOVQ BP, -16(SP)
	0x48, 0x8d, 0x6c, 0x24, 0xf0, // LEAQ -16(SP), BP
}

var bpduff2 = []byte{
	0x48, 0x8b, 0x6d, 0x00, // MOVQ 0(BP), BP
}

// asmevex emits EVEX pregis and opcode byte.
// In addition to asmvex r/m, vvvv and reg fields also requires optional
// K-masking register.
//
// Expects asmbuf.evex to be properly initialized.
func (ab *AsmBuf) asmevex(ctxt *obj.Link, p *obj.Prog, rm, v, r, k *obj.Addr) {
	ab.evexflag = true
	evex := ab.evex

	rexR := byte(1)
	evexR := byte(1)
	rexX := byte(1)
	rexB := byte(1)
	if r != nil {
		if regrex[r.Reg]&Rxr != 0 {
			rexR = 0 // "ModR/M.reg" selector 4th bit.
		}
		if regrex[r.Reg]&RxrEvex != 0 {
			evexR = 0 // "ModR/M.reg" selector 5th bit.
		}
	}
	if rm != nil {
		if rm.Index == REG_NONE && regrex[rm.Reg]&RxrEvex != 0 {
			rexX = 0
		} else if regrex[rm.Index]&Rxx != 0 {
			rexX = 0
		}
		if regrex[rm.Reg]&Rxb != 0 {
			rexB = 0
		}
	}
	// P0 = [R][X][B][R'][00][mm]
	p0 := (rexR << 7) |
		(rexX << 6) |
		(rexB << 5) |
		(evexR << 4) |
		(0 << 2) |
		(evex.M() << 0)

	vexV := byte(0)
	if v != nil {
		// 4bit-wide reg index.
		vexV = byte(reg[v.Reg]|(regrex[v.Reg]&Rxr)<<1) & 0xF
	}
	vexV ^= 0x0F
	// P1 = [W][vvvv][1][pp]
	p1 := (evex.W() << 7) |
		(vexV << 3) |
		(1 << 2) |
		(evex.P() << 0)

	suffix := evexSuffixMap[p.Scond]
	evexZ := byte(0)
	evexLL := evex.L()
	evexB := byte(0)
	evexV := byte(1)
	evexA := byte(0)
	if suffix.zeroing {
		if !evex.ZeroingEnabled() {
			ctxt.Diag("unsupported zeroing: %v", p)
		}
		if k == nil {
			// When you request zeroing you must specify a mask register.
			// See issue 57952.
			ctxt.Diag("mask register must be specified for .Z instructions: %v", p)
		} else if k.Reg == REG_K0 {
			// The mask register must not be K0. That restriction is already
			// handled by the Yknot0 restriction in the opcode tables, so we
			// won't ever reach here. But put something sensible here just in case.
			ctxt.Diag("mask register must not be K0 for .Z instructions: %v", p)
		}
		evexZ = 1
	}
	switch {
	case suffix.rounding != rcUnset:
		if rm != nil && rm.Type == obj.TYPE_MEM {
			ctxt.Diag("illegal rounding with memory argument: %v", p)
		} else if !evex.RoundingEnabled() {
			ctxt.Diag("unsupported rounding: %v", p)
		}
		evexB = 1
		evexLL = suffix.rounding
	case suffix.broadcast:
		if rm == nil || rm.Type != obj.TYPE_MEM {
			ctxt.Diag("illegal broadcast without memory argument: %v", p)
		} else if !evex.BroadcastEnabled() {
			ctxt.Diag("unsupported broadcast: %v", p)
		}
		evexB = 1
	case suffix.sae:
		if rm != nil && rm.Type == obj.TYPE_MEM {
			ctxt.Diag("illegal SAE with memory argument: %v", p)
		} else if !evex.SaeEnabled() {
			ctxt.Diag("unsupported SAE: %v", p)
		}
		evexB = 1
	}
	if rm != nil && regrex[rm.Index]&RxrEvex != 0 {
		evexV = 0
	} else if v != nil && regrex[v.Reg]&RxrEvex != 0 {
		evexV = 0 // VSR selector 5th bit.
	}
	if k != nil {
		evexA = byte(reg[k.Reg])
	}
	// P2 = [z][L'L][b][V'][aaa]
	p2 := (evexZ << 7) |
		(evexLL << 5) |
		(evexB << 4) |
		(evexV << 3) |
		(evexA << 0)

	const evexEscapeByte = 0x62
	ab.Put4(evexEscapeByte, p0, p1, p2)
	ab.Put1(evex.opcode)
}

// Emit VEX prefix and opcode byte.
// The three addresses are the r/m, vvvv, and reg fields.
// The reg and rm arguments appear in the same order as the
// arguments to asmand, which typically follows the call to asmvex.
// The final two arguments are the VEX prefix (see encoding above)
// and the opcode byte.
// For details about vex prefix see:
// https://en.wikipedia.org/wiki/VEX_prefix#Technical_description
func (ab *AsmBuf) asmvex(ctxt *obj.Link, rm, v, r *obj.Addr, vex, opcode uint8) {
	ab.vexflag = true
	rexR := 0
	if r != nil {
		rexR = regrex[r.Reg] & Rxr
	}
	rexB := 0
	rexX := 0
	if rm != nil {
		rexB = regrex[rm.Reg] & Rxb
		rexX = regrex[rm.Index] & Rxx
	}
	vexM := (vex >> 3) & 0x7
	vexWLP := vex & 0x87
	vexV := byte(0)
	if v != nil {
		vexV = byte(reg[v.Reg]|(regrex[v.Reg]&Rxr)<<1) & 0xF
	}
	vexV ^= 0xF
	if vexM == 1 && (rexX|rexB) == 0 && vex&vexW1 == 0 {
		// Can use 2-byte encoding.
		ab.Put2(0xc5, byte(rexR<<5)^0x80|vexV<<3|vexWLP)
	} else {
		// Must use 3-byte encoding.
		ab.Put3(0xc4,
			(byte(rexR|rexX|rexB)<<5)^0xE0|vexM,
			vexV<<3|vexWLP,
		)
	}
	ab.Put1(opcode)
}

// regIndex returns register index that fits in 5 bits.
//
//	R         : 3 bit | legacy instructions     | N/A
//	[R/V]EX.R : 1 bit | REX / VEX extension bit | Rxr
//	EVEX.R    : 1 bit | EVEX extension bit      | RxrEvex
//
// Examples:
//
//	REG_Z30 => 30
//	REG_X15 => 15
//	REG_R9  => 9
//	REG_AX  => 0
func regIndex(r int16) int {
	lower3bits := reg[r]
	high4bit := regrex[r] & Rxr << 1
	high5bit := regrex[r] & RxrEvex << 0
	return lower3bits | high4bit | high5bit
}

// avx2gatherValid reports whether p satisfies AVX2 gather constraints.
// Reports errors via ctxt.
func avx2gatherValid(ctxt *obj.Link, p *obj.Prog) bool {
	// If any pair of the index, mask, or destination registers
	// are the same, illegal instruction trap (#UD) is triggered.
	index := regIndex(p.GetFrom3().Index)
	mask := regIndex(p.From.Reg)
	dest := regIndex(p.To.Reg)
	if dest == mask || dest == index || mask == index {
		ctxt.Diag("mask, index, and destination registers should be distinct: %v", p)
		return false
	}

	return true
}

// avx512gatherValid reports whether p satisfies AVX512 gather constraints.
// Reports errors via ctxt.
func avx512gatherValid(ctxt *obj.Link, p *obj.Prog) bool {
	// Illegal instruction trap (#UD) is triggered if the destination vector
	// register is the same as index vector in VSIB.
	index := regIndex(p.From.Index)
	dest := regIndex(p.To.Reg)
	if dest == index {
		ctxt.Diag("index and destination registers should be distinct: %v", p)
		return false
	}

	return true
}

func (ab *AsmBuf) doasm(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog) {
	o := opindex[p.As&obj.AMask]

	if o == nil {
		ctxt.Diag("asmins: missing op %v", p)
		return
	}

	if pre := prefixof(ctxt, &p.From); pre != 0 {
		ab.Put1(byte(pre))
	}
	if pre := prefixof(ctxt, &p.To); pre != 0 {
		ab.Put1(byte(pre))
	}

	// Checks to warn about instruction/arguments combinations that
	// will unconditionally trigger illegal instruction trap (#UD).
	switch p.As {
	case AVGATHERDPD,
		AVGATHERQPD,
		AVGATHERDPS,
		AVGATHERQPS,
		AVPGATHERDD,
		AVPGATHERQD,
		AVPGATHERDQ,
		AVPGATHERQQ:
		if p.GetFrom3() == nil {
			// gathers need a 3rd arg. See issue 58822.
			ctxt.Diag("need a third arg for gather instruction: %v", p)
			return
		}
		// AVX512 gather requires explicit K mask.
		if p.GetFrom3().Reg >= REG_K0 && p.GetFrom3().Reg <= REG_K7 {
			if !avx512gatherValid(ctxt, p) {
				return
			}
		} else {
			if !avx2gatherValid(ctxt, p) {
				return
			}
		}
	}

	if p.Ft == 0 {
		p.Ft = uint8(oclass(ctxt, p, &p.From))
	}
	if p.Tt == 0 {
		p.Tt = uint8(oclass(ctxt, p, &p.To))
	}

	ft := int(p.Ft) * Ymax
	tt := int(p.Tt) * Ymax

	xo := obj.Bool2int(o.op[0] == 0x0f)
	z := 0

	args := make([]int, 0, argListMax)
	if ft != Ynone*Ymax {
		args = append(args, ft)
	}
	for i := range p.RestArgs {
		args = append(args, oclass(ctxt, p, &p.RestArgs[i].Addr)*Ymax)
	}
	if tt != Ynone*Ymax {
		args = append(args, tt)
	}

	var f3t int
	for _, yt := range o.ytab {
		// ytab matching is purely args-based,
		// but AVX512 suffixes like "Z" or "RU_SAE" will
		// add EVEX-only filter that will reject non-EVEX matches.
		//
		// Consider "VADDPD.BCST 2032(DX), X0, X0".
		// Without this rule, operands will lead to VEX-encoded form
		// and produce "c5b15813" encoding.
		if !yt.match(args) {
			// "xo" is always zero for VEX/EVEX encoded insts.
			z += int(yt.zoffset) + xo
		} else {
			if p.Scond != 0 && !evexZcase(yt.zcase) {
				// Do not signal error and continue to search
				// for matching EVEX-encoded form.
				z += int(yt.zoffset)
				continue
			}

			switch o.prefix {
			case Px1: // first option valid only in 32-bit mode
				if ctxt.Arch.Family == sys.AMD64 && z == 0 {
					z += int(yt.zoffset) + xo
					continue
				}
			case Pq: // 16 bit escape and opcode escape
				ab.Put2(Pe, Pm)

			case Pq3: // 16 bit escape and opcode escape + REX.W
				ab.rexflag |= Pw
				ab.Put2(Pe, Pm)

			case Pq4: // 66 0F 38
				ab.Put3(0x66, 0x0F, 0x38)

			case Pq4w: // 66 0F 38 + REX.W
				ab.rexflag |= Pw
				ab.Put3(0x66, 0x0F, 0x38)

			case Pq5: // F3 0F 38
				ab.Put3(0xF3, 0x0F, 0x38)

			case Pq5w: //  F3 0F 38 + REX.W
				ab.rexflag |= Pw
				ab.Put3(0xF3, 0x0F, 0x38)

			case Pf2, // xmm opcode escape
				Pf3:
				ab.Put2(o.prefix, Pm)

			case Pef3:
				ab.Put3(Pe, Pf3, Pm)

			case Pfw: // xmm opcode escape + REX.W
				ab.rexflag |= Pw
				ab.Put2(Pf3, Pm)

			case Pm: // opcode escape
				ab.Put1(Pm)

			case Pe: // 16 bit escape
				ab.Put1(Pe)

			case Pw: // 64-bit escape
				if ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal 64: %v", p)
				}
				ab.rexflag |= Pw

			case Pw8: // 64-bit escape if z >= 8
				if z >= 8 {
					if ctxt.Arch.Family != sys.AMD64 {
						ctxt.Diag("asmins: illegal 64: %v", p)
					}
					ab.rexflag |= Pw
				}

			case Pb: // botch
				if ctxt.Arch.Family != sys.AMD64 && (isbadbyte(&p.From) || isbadbyte(&p.To)) {
					goto bad
				}
				// NOTE(rsc): This is probably safe to do always,
				// but when enabled it chooses different encodings
				// than the old cmd/internal/obj/i386 code did,
				// which breaks our "same bits out" checks.
				// In particular, CMPB AX, $0 encodes as 80 f8 00
				// in the original obj/i386, and it would encode
				// (using a valid, shorter form) as 3c 00 if we enabled
				// the call to bytereg here.
				if ctxt.Arch.Family == sys.AMD64 {
					bytereg(&p.From, &p.Ft)
					bytereg(&p.To, &p.Tt)
				}

			case P32: // 32 bit but illegal if 64-bit mode
				if ctxt.Arch.Family == sys.AMD64 {
					ctxt.Diag("asmins: illegal in 64-bit mode: %v", p)
				}

			case Py: // 64-bit only, no prefix
				if ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}

			case Py1: // 64-bit only if z < 1, no prefix
				if z < 1 && ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}

			case Py3: // 64-bit only if z < 3, no prefix
				if z < 3 && ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}
			}

			if z >= len(o.op) {
				log.Fatalf("asmins bad table %v", p)
			}
			op := int(o.op[z])
			if op == 0x0f {
				ab.Put1(byte(op))
				z++
				op = int(o.op[z])
			}

			switch yt.zcase {
			default:
				ctxt.Diag("asmins: unknown z %d %v", yt.zcase, p)
				return

			case Zpseudo:
				break

			case Zlit:
				ab.PutOpBytesLit(z, &o.op)

			case Zlitr_m:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zlitm_r:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zlit_m_r:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zmb_r:
				bytereg(&p.From, &p.Ft)
				fallthrough

			case Zm_r:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Z_m_r:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zm2_r:
				ab.Put2(byte(op), o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_xm_nr:
				ab.rexflag = 0
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_i_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, p.GetFrom3())
				ab.Put1(byte(p.To.Offset))

			case Zibm_r, Zibr_m:
				ab.PutOpBytesLit(z, &o.op)
				if yt.zcase == Zibr_m {
					ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				} else {
					ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				}
				switch {
				default:
					ab.Put1(byte(p.From.Offset))
				case yt.args[0] == Yi32 && o.prefix == Pe:
					ab.PutInt16(int16(p.From.Offset))
				case yt.args[0] == Yi32:
					ab.PutInt32(int32(p.From.Offset))
				}

			case Zaut_r:
				ab.Put1(0x8d) // leal
				if p.From.Type != obj.TYPE_ADDR {
					ctxt.Diag("asmins: Zaut sb type ADDR")
				}
				p.From.Type = obj.TYPE_MEM
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)
				p.From.Type = obj.TYPE_ADDR

			case Zm_o:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+1]))

			case Zr_m:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zvex:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])

			case Zvex_rm_v_r:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zvex_rm_v_ro:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+2]))

			case Zvex_i_rm_vo:
				ab.asmvex(ctxt, p.GetFrom3(), &p.To, nil, o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, p.GetFrom3(), int(o.op[z+2]))
				ab.Put1(byte(p.From.Offset))

			case Zvex_i_r_v:
				ab.asmvex(ctxt, p.GetFrom3(), &p.To, nil, o.op[z], o.op[z+1])
				regnum := byte(0x7)
				if p.GetFrom3().Reg >= REG_X0 && p.GetFrom3().Reg <= REG_X15 {
					regnum &= byte(p.GetFrom3().Reg - REG_X0)
				} else {
					regnum &= byte(p.GetFrom3().Reg - REG_Y0)
				}
				ab.Put1(o.op[z+2] | regnum)
				ab.Put1(byte(p.From.Offset))

			case Zvex_i_rm_v_r:
				imm, from, from3, to := unpackOps4(p)
				ab.asmvex(ctxt, from, from3, to, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zvex_i_rm_r:
				ab.asmvex(ctxt, p.GetFrom3(), nil, &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				ab.Put1(byte(p.From.Offset))

			case Zvex_v_rm_r:
				ab.asmvex(ctxt, p.GetFrom3(), &p.From, &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zvex_r_v_rm:
				ab.asmvex(ctxt, &p.To, p.GetFrom3(), &p.From, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zvex_rm_r_vo:
				ab.asmvex(ctxt, &p.From, &p.To, p.GetFrom3(), o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+2]))

			case Zvex_i_r_rm:
				ab.asmvex(ctxt, &p.To, nil, p.GetFrom3(), o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				ab.Put1(byte(p.From.Offset))

			case Zvex_hr_rm_v_r:
				hr, from, from3, to := unpackOps4(p)
				ab.asmvex(ctxt, from, from3, to, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(regIndex(hr.Reg) << 4))

			case Zevex_k_rmo:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, nil, &p.From)
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+3]))

			case Zevex_i_rm_vo:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, p.GetFrom3(), &p.To, nil, nil)
				ab.asmando(ctxt, cursym, p, p.GetFrom3(), int(o.op[z+3]))
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_rm_k_vo:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, to, nil, kmask)
				ab.asmando(ctxt, cursym, p, from, int(o.op[z+3]))
				ab.Put1(byte(imm.Offset))

			case Zevex_i_r_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, p.GetFrom3(), nil)
				ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_r_k_rm:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, to, nil, from, kmask)
				ab.asmand(ctxt, cursym, p, to, from)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, p.GetFrom3(), nil, &p.To, nil)
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_rm_k_r:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, nil, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_v_r:
				imm, from, from3, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, nil)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_v_k_r:
				imm, from, from3, kmask, to := unpackOps5(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_r_v_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, p.GetFrom3(), &p.From, nil)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zevex_rm_v_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.From, p.GetFrom3(), &p.To, nil)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zevex_rm_k_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.From, nil, &p.To, p.GetFrom3())
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zevex_r_k_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, &p.From, p.GetFrom3())
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zevex_rm_v_k_r:
				from, from3, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)

			case Zevex_r_v_k_rm:
				from, from3, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, to, from3, from, kmask)
				ab.asmand(ctxt, cursym, p, to, from)

			case Zr_m_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zr_m_xm_nr:
				ab.rexflag = 0
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zo_m:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))

			case Zcallindreg:
				cursym.AddRel(ctxt, obj.Reloc{
					Type: objabi.R_CALLIND,
					Off:  int32(p.Pc),
				})
				fallthrough

			case Zo_m64:
				ab.Put1(byte(op))
				ab.asmandsz(ctxt, cursym, p, &p.To, int(o.op[z+1]), 0, 1)

			case Zm_ibo:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.To, nil)))

			case Zibo_m:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.From, nil)))

			case Zibo_m_xm:
				z = ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.From, nil)))

			case Z_ib, Zib_:
				var a *obj.Addr
				if yt.zcase == Zib_ {
					a = &p.From
				} else {
					a = &p.To
				}
				ab.Put1(byte(op))
				if p.As == AXABORT {
					ab.Put1(o.op[z+1])
				}
				ab.Put1(byte(vaddr(ctxt, p, a, nil)))

			case Zib_rp:
				ab.rexflag |= regrex[p.To.Reg] & (Rxb | 0x40)
				ab.Put2(byte(op+reg[p.To.Reg]), byte(vaddr(ctxt, p, &p.From, nil)))

			case Zil_rp:
				ab.rexflag |= regrex[p.To.Reg] & Rxb
				ab.Put1(byte(op + reg[p.To.Reg]))
				if o.prefix == Pe {
					v := vaddr(ctxt, p, &p.From, nil)
					ab.PutInt16(int16(v))
				} else {
					ab.relput4(ctxt, cursym, p, &p.From)
				}

			case Zo_iw:
				ab.Put1(byte(op))
				if p.From.Type != obj.TYPE_NONE {
					v := vaddr(ctxt, p, &p.From, nil)
					ab.PutInt16(int16(v))
				}

			case Ziq_rp:
				var rel obj.Reloc
				v := vaddr(ctxt, p, &p.Fr
```