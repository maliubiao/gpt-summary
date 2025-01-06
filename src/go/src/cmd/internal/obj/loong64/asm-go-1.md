Response: The user has provided a snippet of Go code from `go/src/cmd/internal/obj/loong64/asm.go` and is asking for its functionality. This is the second part of the code. The first part was analyzed previously.

Based on the code structure, it seems like this file is responsible for generating machine code for the LoongArch 64-bit architecture. The functions `opirr`, `opi`, `opir`, `opirr`, `opirir`, `specialFpMovInst`, and `specialLsxMovInst` appear to map Go assembly instructions to their corresponding LoongArch machine code representations.

Specifically:
- `oprr` handles register-register operations.
- `opi` handles immediate operations.
- `opir` handles operations with an immediate value.
- `opirr` handles register-register operations with potential immediate or branch offsets.
- `opirir` handles specific bit manipulation instructions.
- `specialFpMovInst` handles specific floating-point move instructions with different register classes.
- `specialLsxMovInst` seems to handle vector load/store and move instructions with specific indexing and element sizes.

The `vshift` function checks if an instruction is a vector shift operation.

The goal is to:
1. Summarize the functionalities of this second part of the code.
2. Infer the high-level Go feature this code contributes to.
3. Provide Go code examples demonstrating the inferred feature, including input and output assumptions.
4. Detail the handling of any command-line parameters (if present).
5. Identify common mistakes users might make (if applicable).
这是 `go/src/cmd/internal/obj/loong64/asm.go` 文件的第二部分，它主要负责将 Go 汇编指令转换为 LoongArch 64 位架构的机器码。具体来说，这部分代码定义了多个函数，每个函数负责处理特定类型的汇编指令，并返回对应的机器码。

**功能列举:**

1. **`oprr(a obj.As) uint32`:**  将某些特定类型的寄存器-寄存器操作的 Go 汇编指令 `a` 映射到其对应的 32 位机器码。这些指令通常是浮点运算和数据移动指令，例如 `ATRUNCFW`, `AMOVFV`, `AABSF` 等。
2. **`opi(a obj.As) uint32`:** 将某些特定类型的立即数操作的 Go 汇编指令 `a` 映射到其对应的 32 位机器码。这些指令通常是系统调用和断点指令，例如 `ASYSCALL`, `ABREAK`, `ADBAR`。
3. **`opir(a obj.As) uint32`:** 将带有立即数的 Go 汇编指令 `a` 映射到其对应的 32 位机器码。例如，`ALU12IW`, `ALU32ID`, `APCALAU12I`, `APCADDU12I`。
4. **`opirr(a obj.As) uint32`:** 将寄存器-寄存器操作或者带有立即数/分支偏移的 Go 汇编指令 `a` 映射到其对应的 32 位机器码。这包括算术运算（`AADD`, `ASGT`），逻辑运算（`AAND`, `AOR`），移位操作（`ASLL`, `ASRL`），跳转指令（`AJMP`, `AJAL`），分支指令（`ABLTU`, `ABEQ`）以及内存访问指令（`AMOVB`, `AMOVF`, `AVMOVQ`）。
5. **`opirir(a obj.As) uint32`:** 将特定类型的带有两个寄存器操作数的 Go 汇编指令 `a` 映射到其对应的 32 位机器码。目前只处理位字段操作指令，如 `ABSTRINSW`, `ABSTRINSV`, `ABSTRPICKW`, `ABSTRPICKV`。
6. **`specialFpMovInst(a obj.As, fclass int, tclass int) uint32`:** 处理特殊的浮点数移动指令 `AMOVV` 和 `AMOVW`，根据源操作数和目标操作数的寄存器类型（`fclass` 和 `tclass`）来生成不同的机器码。这允许在通用寄存器、浮点寄存器、浮点控制寄存器之间进行数据移动。
7. **`specialLsxMovInst(a obj.As, fReg int16, tReg int16) (op_code, index_mask uint32)`:** 处理特殊的向量加载/存储和移动指令 `AVMOVQ` 和 `AXVMOVQ`，涉及到向量寄存器和通用寄存器之间元素的移动。它根据源和目标寄存器的类型和元素大小，生成操作码和索引掩码。
8. **`vshift(a obj.As) bool`:** 判断给定的 Go 汇编指令 `a` 是否是向量移位操作。

**推理 Go 语言功能实现:**

这部分代码是 Go 语言编译器中，将特定架构（LoongArch 64）的汇编代码转换为机器码的关键部分。它是构建 Go 语言运行时环境和编译用户代码的基础。更具体地说，它属于 **汇编器（Assembler）** 的一部分。汇编器负责将汇编语言源代码翻译成机器可以直接执行的二进制代码。

**Go 代码举例说明:**

由于这部分代码是编译器内部的实现细节，用户通常不会直接调用这些函数。但是，我们可以通过编写包含特定汇编指令的 Go 代码，然后观察编译器如何处理来理解其作用。

假设我们有以下 Go 代码，其中使用了内联汇编：

```go
package main

import "fmt"

func main() {
	var x float64 = 3.14
	var y float64

	// 使用内联汇编将 x 的值移动到 y
	//go:noinline
	func() {
		// 这里使用了 AMD64 的汇编指令作为示例，
		// 实际的 LoongArch64 指令会对应 asm.go 中的映射关系
		// 我们假设 LoongArch64 中存在类似的 MOV 指令
		asm volatile (
			"movsd %1, %0" : "=x"(y) : "x"(x)
		)
	}()

	fmt.Println(y)
}
```

**假设的输入与输出 (针对 `specialFpMovInst` 中的 `AMOVV` 和 `specialLsxMovInst` 中的 `AVMOVQ`)**

由于我们无法直接控制汇编器的工作方式，这里我们只能假设一些输入，并推测 `asm.go` 中的函数会如何处理。

**示例 1: `specialFpMovInst` 和 `AMOVV`**

假设汇编器遇到以下 LoongArch64 汇编指令 (这是 Go 编译器生成的中间表示，最终会被 `asm.go` 处理)：

```assembly
// 假设的 LoongArch64 汇编指令，将浮点寄存器 f0 的双精度浮点数移动到通用寄存器 r1
MOVVD F0, R1
```

在这种情况下，`specialFpMovInst` 函数可能会被调用，参数如下（这些是假设的常量值）：

* `a`:  表示 `AMOVV` (代表 MOV 指令)
* `fclass`: 代表 `F0` (浮点寄存器), 假设其值为 `C_FREG`
* `tclass`: 代表 `R1` (通用寄存器), 假设其值为 `C_REG`

根据 `specialFpMovInst` 中的 `case AMOVV` 和对应的 `fclass` 和 `tclass` 分支，它会返回 `0x452e << 10`，这对应着 `movfr2gr.d` 指令的机器码。

**示例 2: `specialLsxMovInst` 和 `AVMOVQ`**

假设汇编器遇到以下 LoongArch64 汇编指令：

```assembly
// 假设的 LoongArch64 汇编指令，将通用寄存器 R2 的值移动到向量寄存器 V3 的第一个双字元素
VMOVQ R2, V3.V[0]
```

在这种情况下，`specialLsxMovInst` 函数可能会被调用，参数如下：

* `a`: 表示 `AVMOVQ`
* `fReg`: 代表 `R2`，假设其值为某个表示通用寄存器的常量
* `tReg`: 代表 `V3.V[0]`，假设其值为某个表示向量寄存器 V3 的双字类型元素的常量，并且包含了索引信息。

根据 `specialLsxMovInst` 中的 `case C_REG | (C_ELEM << 16)` 和对应的 `tarng` 分支，它会返回相应的操作码和索引掩码，例如 `(0x0E5D7E << 11)` 和 `0x1`，对应 `vinsgr2vr.d` 指令。

**命令行参数处理:**

这部分代码主要负责指令到机器码的转换，通常不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的其他阶段，例如词法分析、语法分析和代码生成。

**使用者易犯错的点:**

作为编译器内部的实现，普通 Go 开发者不会直接与这部分代码交互。错误通常发生在编写内联汇编时，如果内联汇编的指令与目标架构的指令不匹配，或者操作数类型不正确，那么在编译阶段会出错。

**归纳功能:**

总而言之，这段 `go/src/cmd/internal/obj/loong64/asm.go` 代码的主要功能是 **将 Go 语言的汇编指令（特别是针对 LoongArch 64 位架构）翻译成机器码**。它通过一系列函数，针对不同类型的指令进行编码，是 Go 编译器中目标代码生成阶段的关键组成部分。这部分代码确保了 Go 程序能够被 LoongArch 64 位处理器正确执行。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/loong64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
a1 << 10
	case ATRUNCDW:
		return 0x46a2 << 10
	case AMOVFV:
		return 0x46c9 << 10
	case AMOVDV:
		return 0x46ca << 10
	case AMOVVF:
		return 0x4746 << 10
	case AMOVVD:
		return 0x474a << 10
	case AMOVFW:
		return 0x46c1 << 10
	case AMOVDW:
		return 0x46c2 << 10
	case AMOVWF:
		return 0x4744 << 10
	case AMOVDF:
		return 0x4646 << 10
	case AMOVWD:
		return 0x4748 << 10
	case AMOVFD:
		return 0x4649 << 10
	case AABSF:
		return 0x4501 << 10
	case AABSD:
		return 0x4502 << 10
	case AMOVF:
		return 0x4525 << 10
	case AMOVD:
		return 0x4526 << 10
	case ANEGF:
		return 0x4505 << 10
	case ANEGD:
		return 0x4506 << 10
	case ASQRTF:
		return 0x4511 << 10
	case ASQRTD:
		return 0x4512 << 10
	case AFLOGBF:
		return 0x4509 << 10 // flogb.s
	case AFLOGBD:
		return 0x450a << 10 // flogb.d
	case AFCLASSF:
		return 0x450d << 10 // fclass.s
	case AFCLASSD:
		return 0x450e << 10 // fclass.d
	case AFFINTFW:
		return 0x4744 << 10 // ffint.s.w
	case AFFINTFV:
		return 0x4746 << 10 // ffint.s.l
	case AFFINTDW:
		return 0x4748 << 10 // ffint.d.w
	case AFFINTDV:
		return 0x474a << 10 // ffint.d.l
	case AFTINTWF:
		return 0x46c1 << 10 // ftint.w.s
	case AFTINTWD:
		return 0x46c2 << 10 // ftint.w.d
	case AFTINTVF:
		return 0x46c9 << 10 // ftint.l.s
	case AFTINTVD:
		return 0x46ca << 10 // ftint.l.d
	case AFTINTRMWF:
		return 0x4681 << 10 // ftintrm.w.s
	case AFTINTRMWD:
		return 0x4682 << 10 // ftintrm.w.d
	case AFTINTRMVF:
		return 0x4689 << 10 // ftintrm.l.s
	case AFTINTRMVD:
		return 0x468a << 10 // ftintrm.l.d
	case AFTINTRPWF:
		return 0x4691 << 10 // ftintrp.w.s
	case AFTINTRPWD:
		return 0x4692 << 10 // ftintrp.w.d
	case AFTINTRPVF:
		return 0x4699 << 10 // ftintrp.l.s
	case AFTINTRPVD:
		return 0x469a << 10 // ftintrp.l.d
	case AFTINTRZWF:
		return 0x46a1 << 10 // ftintrz.w.s
	case AFTINTRZWD:
		return 0x46a2 << 10 // ftintrz.w.d
	case AFTINTRZVF:
		return 0x46a9 << 10 // ftintrz.l.s
	case AFTINTRZVD:
		return 0x46aa << 10 // ftintrz.l.d
	case AFTINTRNEWF:
		return 0x46b1 << 10 // ftintrne.w.s
	case AFTINTRNEWD:
		return 0x46b2 << 10 // ftintrne.w.d
	case AFTINTRNEVF:
		return 0x46b9 << 10 // ftintrne.l.s
	case AFTINTRNEVD:
		return 0x46ba << 10 // ftintrne.l.d
	case AVPCNTB:
		return 0x1ca708 << 10 // vpcnt.b
	case AVPCNTH:
		return 0x1ca709 << 10 // vpcnt.h
	case AVPCNTW:
		return 0x1ca70a << 10 // vpcnt.w
	case AVPCNTV:
		return 0x1ca70b << 10 // vpcnt.v
	case AXVPCNTB:
		return 0x1da708 << 10 // xvpcnt.b
	case AXVPCNTH:
		return 0x1da709 << 10 // xvpcnt.h
	case AXVPCNTW:
		return 0x1da70a << 10 // xvpcnt.w
	case AXVPCNTV:
		return 0x1da70b << 10 // xvpcnt.v
	}

	c.ctxt.Diag("bad rr opcode %v", a)
	return 0
}

func (c *ctxt0) opi(a obj.As) uint32 {
	switch a {
	case ASYSCALL:
		return 0x56 << 15
	case ABREAK:
		return 0x54 << 15
	case ADBAR:
		return 0x70e4 << 15
	}

	c.ctxt.Diag("bad ic opcode %v", a)

	return 0
}

func (c *ctxt0) opir(a obj.As) uint32 {
	switch a {
	case ALU12IW:
		return 0x0a << 25
	case ALU32ID:
		return 0x0b << 25
	case APCALAU12I:
		return 0x0d << 25
	case APCADDU12I:
		return 0x0e << 25
	}
	return 0
}

func (c *ctxt0) opirr(a obj.As) uint32 {
	switch a {
	case AADD, AADDU:
		return 0x00a << 22
	case ASGT:
		return 0x008 << 22
	case ASGTU:
		return 0x009 << 22
	case AAND:
		return 0x00d << 22
	case AOR:
		return 0x00e << 22
	case ALU52ID:
		return 0x00c << 22
	case AXOR:
		return 0x00f << 22
	case ASLL:
		return 0x00081 << 15
	case ASRL:
		return 0x00089 << 15
	case ASRA:
		return 0x00091 << 15
	case AROTR:
		return 0x00099 << 15
	case AADDV:
		return 0x00b << 22
	case AADDVU:
		return 0x00b << 22

	case AJMP:
		return 0x14 << 26
	case AJAL,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		return 0x15 << 26

	case AJIRL:
		return 0x13 << 26
	case ABLTU:
		return 0x1a << 26
	case ABLT, ABLTZ, ABGTZ:
		return 0x18 << 26
	case ABGEU:
		return 0x1b << 26
	case ABGE, ABGEZ, ABLEZ:
		return 0x19 << 26
	case -ABEQ: // beqz
		return 0x10 << 26
	case -ABNE: // bnez
		return 0x11 << 26
	case ABEQ:
		return 0x16 << 26
	case ABNE:
		return 0x17 << 26
	case ABFPT:
		return 0x12<<26 | 0x1<<8
	case ABFPF:
		return 0x12<<26 | 0x0<<8

	case AMOVB,
		AMOVBU:
		return 0x0a4 << 22
	case AMOVH,
		AMOVHU:
		return 0x0a5 << 22
	case AMOVW,
		AMOVWU:
		return 0x0a6 << 22
	case AMOVV:
		return 0x0a7 << 22
	case AMOVF:
		return 0x0ad << 22
	case AMOVD:
		return 0x0af << 22
	case -AMOVB:
		return 0x0a0 << 22
	case -AMOVBU:
		return 0x0a8 << 22
	case -AMOVH:
		return 0x0a1 << 22
	case -AMOVHU:
		return 0x0a9 << 22
	case -AMOVW:
		return 0x0a2 << 22
	case -AMOVWU:
		return 0x0aa << 22
	case -AMOVV:
		return 0x0a3 << 22
	case -AMOVF:
		return 0x0ac << 22
	case -AMOVD:
		return 0x0ae << 22
	case -AVMOVQ:
		return 0x0b0 << 22 // vld
	case -AXVMOVQ:
		return 0x0b2 << 22 // xvld
	case AVMOVQ:
		return 0x0b1 << 22 // vst
	case AXVMOVQ:
		return 0x0b3 << 22 // xvst
	case ASLLV:
		return 0x0041 << 16
	case ASRLV:
		return 0x0045 << 16
	case ASRAV:
		return 0x0049 << 16
	case AROTRV:
		return 0x004d << 16
	case -ALL:
		return 0x020 << 24
	case -ALLV:
		return 0x022 << 24
	case ASC:
		return 0x021 << 24
	case ASCV:
		return 0x023 << 24
	}

	if a < 0 {
		c.ctxt.Diag("bad irr opcode -%v", -a)
	} else {
		c.ctxt.Diag("bad irr opcode %v", a)
	}
	return 0
}

func (c *ctxt0) opirir(a obj.As) uint32 {
	switch a {
	case ABSTRINSW:
		return 0x3<<21 | 0x0<<15 // bstrins.w
	case ABSTRINSV:
		return 0x2 << 22 // bstrins.d
	case ABSTRPICKW:
		return 0x3<<21 | 0x1<<15 // bstrpick.w
	case ABSTRPICKV:
		return 0x3 << 22 // bstrpick.d
	}

	return 0
}

func (c *ctxt0) specialFpMovInst(a obj.As, fclass int, tclass int) uint32 {
	switch a {
	case AMOVV:
		switch fclass {
		case C_REG:
			switch tclass {
			case C_FREG:
				return 0x452a << 10 // movgr2fr.d
			case C_FCCREG:
				return 0x4536 << 10 // movgr2cf
			case C_FCSRREG:
				return 0x4530 << 10 // movgr2fcsr
			}
		case C_FREG:
			switch tclass {
			case C_REG:
				return 0x452e << 10 // movfr2gr.d
			case C_FCCREG:
				return 0x4534 << 10 // movfr2cf
			}
		case C_FCCREG:
			switch tclass {
			case C_REG:
				return 0x4537 << 10 // movcf2gr
			case C_FREG:
				return 0x4535 << 10 // movcf2fr
			}
		case C_FCSRREG:
			switch tclass {
			case C_REG:
				return 0x4532 << 10 // movfcsr2gr
			}
		}

	case AMOVW:
		switch fclass {
		case C_REG:
			switch tclass {
			case C_FREG:
				return 0x4529 << 10 // movgr2fr.w
			}
		case C_FREG:
			switch tclass {
			case C_REG:
				return 0x452d << 10 // movfr2gr.s
			}
		}
	}

	c.ctxt.Diag("bad class combination: %s %s,%s\n", a, fclass, tclass)

	return 0
}

func (c *ctxt0) specialLsxMovInst(a obj.As, fReg, tReg int16) (op_code, index_mask uint32) {
	farng := (fReg >> EXT_TYPE_SHIFT) & EXT_TYPE_MASK
	tarng := (tReg >> EXT_TYPE_SHIFT) & EXT_TYPE_MASK
	fclass := c.rclass(fReg)
	tclass := c.rclass(tReg)

	switch fclass | (tclass << 16) {
	case C_REG | (C_ELEM << 16):
		// vmov Rn, Vd.<T>[index]
		switch a {
		case AVMOVQ:
			switch tarng {
			case ARNG_B:
				return (0x01CBAE << 14), 0xf // vinsgr2vr.b
			case ARNG_H:
				return (0x03975E << 13), 0x7 // vinsgr2vr.h
			case ARNG_W:
				return (0x072EBE << 12), 0x3 // vinsgr2vr.w
			case ARNG_V:
				return (0x0E5D7E << 11), 0x1 // vinsgr2vr.d
			}
		case AXVMOVQ:
			switch tarng {
			case ARNG_W:
				return (0x03B75E << 13), 0x7 // xvinsgr2vr.w
			case ARNG_V:
				return (0x076EBE << 12), 0x3 // xvinsgr2vr.d
			}
		}

	case C_ELEM | (C_REG << 16):
		// vmov Vd.<T>[index], Rn
		switch a {
		case AVMOVQ:
			switch farng {
			case ARNG_B:
				return (0x01CBBE << 14), 0xf // vpickve2gr.b
			case ARNG_H:
				return (0x03977E << 13), 0x7 // vpickve2gr.h
			case ARNG_W:
				return (0x072EFE << 12), 0x3 // vpickve2gr.w
			case ARNG_V:
				return (0x0E5DFE << 11), 0x1 // vpickve2gr.d
			case ARNG_BU:
				return (0x01CBCE << 14), 0xf // vpickve2gr.bu
			case ARNG_HU:
				return (0x03979E << 13), 0x7 // vpickve2gr.hu
			case ARNG_WU:
				return (0x072F3E << 12), 0x3 // vpickve2gr.wu
			case ARNG_VU:
				return (0x0E5E7E << 11), 0x1 // vpickve2gr.du
			}
		case AXVMOVQ:
			switch farng {
			case ARNG_W:
				return (0x03B77E << 13), 0x7 // xvpickve2gr.w
			case ARNG_V:
				return (0x076EFE << 12), 0x3 // xvpickve2gr.d
			case ARNG_WU:
				return (0x03B79E << 13), 0x7 // xvpickve2gr.wu
			case ARNG_VU:
				return (0x076F3E << 12), 0x3 // xvpickve2gr.du
			}
		}

	case C_REG | (C_ARNG << 16):
		// vmov Rn, Vd.<T>
		switch a {
		case AVMOVQ:
			switch tarng {
			case ARNG_16B:
				return (0x1CA7C0 << 10), 0x0 // vreplgr2vr.b
			case ARNG_8H:
				return (0x1CA7C1 << 10), 0x0 // vreplgr2vr.h
			case ARNG_4W:
				return (0x1CA7C2 << 10), 0x0 // vreplgr2vr.w
			case ARNG_2V:
				return (0x1CA7C3 << 10), 0x0 // vreplgr2vr.d
			}
		case AXVMOVQ:
			switch tarng {
			case ARNG_32B:
				return (0x1DA7C0 << 10), 0x0 // xvreplgr2vr.b
			case ARNG_16H:
				return (0x1DA7C1 << 10), 0x0 // xvreplgr2vr.h
			case ARNG_8W:
				return (0x1DA7C2 << 10), 0x0 // xvreplgr2vr.w
			case ARNG_4V:
				return (0x1DA7C3 << 10), 0x0 // xvreplgr2vr.d
			}
		}

	case C_XREG | (C_ARNG << 16):
		// vmov  xj, xd.<T>
		switch a {
		case AVMOVQ:
			return 0, 0 // unsupported op
		case AXVMOVQ:
			switch tarng {
			case ARNG_32B:
				return (0x1DC1C0 << 10), 0x0 // xvreplve0.b
			case ARNG_16H:
				return (0x1DC1E0 << 10), 0x0 // xvreplve0.h
			case ARNG_8W:
				return (0x1DC1F0 << 10), 0x0 // xvreplve0.w
			case ARNG_4V:
				return (0x1DC1F8 << 10), 0x0 // xvreplve0.d
			case ARNG_2Q:
				return (0x1DC1FC << 10), 0x0 // xvreplve0.q
			}
		}

	case C_XREG | (C_ELEM << 16):
		// vmov  xj, xd.<T>[index]
		switch a {
		case AVMOVQ:
			return 0, 0 // unsupported op
		case AXVMOVQ:
			switch tarng {
			case ARNG_W:
				return (0x03B7FE << 13), 0x7 // xvinsve0.w
			case ARNG_V:
				return (0x076FFE << 12), 0x3 // xvinsve0.d
			}
		}

	case C_ELEM | (C_XREG << 16):
		// vmov  xj.<T>[index], xd
		switch a {
		case AVMOVQ:
			return 0, 0 // unsupported op
		case AXVMOVQ:
			switch farng {
			case ARNG_W:
				return (0x03B81E << 13), 0x7 // xvpickve.w
			case ARNG_V:
				return (0x07703E << 12), 0x3 // xvpickve.d
			}
		}

	case C_ELEM | (C_ARNG << 16):
		// vmov  vj.<T>[index], vd.<T>
		switch a {
		case AVMOVQ:
			switch int32(farng) | (int32(tarng) << 16) {
			case int32(ARNG_B) | (int32(ARNG_16B) << 16):
				return (0x01CBDE << 14), 0xf // vreplvei.b
			case int32(ARNG_H) | (int32(ARNG_8H) << 16):
				return (0x0397BE << 13), 0x7 // vreplvei.h
			case int32(ARNG_W) | (int32(ARNG_4W) << 16):
				return (0x072F7E << 12), 0x3 // vreplvei.w
			case int32(ARNG_V) | (int32(ARNG_2V) << 16):
				return (0x0E5EFE << 11), 0x1 // vreplvei.d
			}
		case AXVMOVQ:
			return 0, 0 // unsupported op
		}
	}

	return 0, 0
}

func vshift(a obj.As) bool {
	switch a {
	case ASLLV,
		ASRLV,
		ASRAV,
		AROTRV:
		return true
	}
	return false
}

"""




```