Response:
从提供的代码片段来看，这部分代码是 Go 语言实现的 PowerPC 64 位架构（PPC64）的汇编指令表的一部分。它定义了 PPC64 架构中的一些指令及其操作码、操作数等信息。具体来说，这部分代码的功能可以归纳为以下几点：

### 1. **指令定义**
   - 代码中定义了大量的 PPC64 指令，例如 `LXVKQ`、`LXVP`、`LXVPX`、`MTVSRBM` 等。每个指令都包含了操作码（opcode）、操作数类型（argField）等信息。
   - 这些指令通常用于处理向量寄存器（Vector Registers）、浮点寄存器（FP Registers）、通用寄存器（General Purpose Registers）等。

### 2. **操作数类型**
   - 每个指令的操作数类型通过 `argField` 来定义。例如，`ap_VecReg_6_10` 表示从第 6 位到第 10 位的向量寄存器，`ap_FPReg_16_20` 表示从第 16 位到第 20 位的浮点寄存器。
   - 操作数类型还包括立即数（Immediate Values）、偏移量（Offsets）等。

### 3. **指令格式**
   - 指令的格式通过操作码和操作数类型来定义。例如，`LXVKQ` 指令的格式是 `X-form`，表示它是一个 X 型指令，操作数包括一个向量寄存器和一个无符号立即数。

### 4. **功能分类**
   - 这些指令涵盖了多种功能，包括：
     - **加载/存储指令**：如 `LXVP`（加载 VSX 向量对）、`LXVPX`（加载 VSX 向量对索引）等。
     - **向量操作指令**：如 `MTVSRBM`（将字节掩码移动到向量寄存器）、`VCFUGED`（向量离心双字）等。
     - **浮点操作指令**：如 `PMXVF16GER2`（预取掩码 VSX 向量 16 位浮点 GER 操作）等。
     - **算术运算指令**：如 `PADDI`（预取加法立即数）、`PDEPD`（并行位提取双字）等。

### 5. **指令编码**
   - 每个指令的操作码和操作数类型通过位掩码（bitmask）来定义。例如，`LXVKQ` 的操作码是 `0xfc1f07fe00000000`，表示该指令的二进制编码。

### 6. **指令的实现**
   - 这些指令的实现通常是通过 Go 语言的位操作和结构体来完成的。每个指令的结构体包含了操作码、操作数类型等信息，用于在汇编器或反汇编器中解析和执行这些指令。

### 7. **易错点**
   - **操作数类型错误**：由于操作数类型是通过位掩码来定义的，因此在编写或解析指令时，容易混淆操作数的位范围。例如，`ap_VecReg_6_10` 和 `ap_VecReg_16_20` 分别表示不同的寄存器范围，如果混淆可能会导致指令解析错误。
   - **指令格式错误**：不同的指令有不同的格式（如 X-form、D-form 等），如果格式不匹配，可能会导致指令无法正确执行。

### 示例代码
假设我们要解析 `LXVKQ` 指令，它的操作码是 `0xfc1f07fe00000000`，操作数包括一个向量寄存器和一个无符号立即数。我们可以通过以下 Go 代码来解析该指令：

```go
package main

import (
	"fmt"
)

type argField struct {
	start, end int
}

var (
	ap_VecSReg_31_31_6_10 = argField{6, 10}
	ap_ImmUnsigned_16_20  = argField{16, 20}
)

type instruction struct {
	name    string
	opcode  uint64
	mask    uint64
	argList [6]*argField
}

var lxvkq = instruction{
	name:   "LXVKQ",
	opcode: 0xf01f02d000000000,
	mask:   0xfc1f07fe00000000,
	argList: [6]*argField{
		&ap_VecSReg_31_31_6_10,
		&ap_ImmUnsigned_16_20,
	},
}

func main() {
	fmt.Printf("Instruction: %s\n", lxvkq.name)
	fmt.Printf("Opcode: %x\n", lxvkq.opcode)
	fmt.Printf("Mask: %x\n", lxvkq.mask)
	for i, arg := range lxvkq.argList {
		if arg != nil {
			fmt.Printf("Arg %d: start=%d, end=%d\n", i, arg.start, arg.end)
		}
	}
}
```

### 输出
```
Instruction: LXVKQ
Opcode: f01f02d000000000
Mask: fc1f07fe00000000
Arg 0: start=6, end=10
Arg 1: start=16, end=20
```

### 总结
这部分代码的主要功能是定义和解析 PPC64 架构中的汇编指令。它通过操作码、操作数类型和指令格式来描述每个指令的行为，并提供了在 Go 语言中解析和执行这些指令的基础。
### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
o Fixed Quadword Quad X-form (dctfixqq VRT,FRBp)
		[6]*argField{ap_VecReg_6_10, ap_FPReg_16_20}},
	{LXVKQ, 0xfc1f07fe00000000, 0xf01f02d000000000, 0x0, // Load VSX Vector Special Value Quadword X-form (lxvkq XT,UIM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_ImmUnsigned_16_20}},
	{LXVP, 0xfc00000f00000000, 0x1800000000000000, 0x0, // Load VSX Vector Paired DQ-form (lxvp XTp,DQ(RA))
		[6]*argField{ap_VecSpReg_10_10_6_9, ap_Offset_16_27_shift4, ap_Reg_11_15}},
	{LXVPX, 0xfc0007fe00000000, 0x7c00029a00000000, 0x100000000, // Load VSX Vector Paired Indexed X-form (lxvpx XTp,RA,RB)
		[6]*argField{ap_VecSpReg_10_10_6_9, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVRBX, 0xfc0007fe00000000, 0x7c00001a00000000, 0x0, // Load VSX Vector Rightmost Byte Indexed X-form (lxvrbx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVRDX, 0xfc0007fe00000000, 0x7c0000da00000000, 0x0, // Load VSX Vector Rightmost Doubleword Indexed X-form (lxvrdx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVRHX, 0xfc0007fe00000000, 0x7c00005a00000000, 0x0, // Load VSX Vector Rightmost Halfword Indexed X-form (lxvrhx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVRWX, 0xfc0007fe00000000, 0x7c00009a00000000, 0x0, // Load VSX Vector Rightmost Word Indexed X-form (lxvrwx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MTVSRBM, 0xfc1f07ff00000000, 0x1010064200000000, 0x0, // Move to VSR Byte Mask VX-form (mtvsrbm VRT,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20}},
	{MTVSRBMI, 0xfc00003e00000000, 0x1000001400000000, 0x0, // Move To VSR Byte Mask Immediate DX-form (mtvsrbmi VRT,bm)
		[6]*argField{ap_VecReg_6_10, ap_ImmUnsigned_16_25_11_15_31_31}},
	{MTVSRDM, 0xfc1f07ff00000000, 0x1013064200000000, 0x0, // Move to VSR Doubleword Mask VX-form (mtvsrdm VRT,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20}},
	{MTVSRHM, 0xfc1f07ff00000000, 0x1011064200000000, 0x0, // Move to VSR Halfword Mask VX-form (mtvsrhm VRT,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20}},
	{MTVSRQM, 0xfc1f07ff00000000, 0x1014064200000000, 0x0, // Move to VSR Quadword Mask VX-form (mtvsrqm VRT,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20}},
	{MTVSRWM, 0xfc1f07ff00000000, 0x1012064200000000, 0x0, // Move to VSR Word Mask VX-form (mtvsrwm VRT,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20}},
	{PADDI, 0xff800000fc000000, 0x600000038000000, 0x6c000000000000, // Prefixed Add Immediate MLS:D-form (paddi RT,RA,SI,R)
		[6]*argField{ap_Reg_38_42, ap_Reg_43_47, ap_ImmSigned_14_31_48_63, ap_ImmUnsigned_11_11}},
	{PDEPD, 0xfc0007fe00000000, 0x7c00013800000000, 0x100000000, // Parallel Bits Deposit Doubleword X-form (pdepd RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{PEXTD, 0xfc0007fe00000000, 0x7c00017800000000, 0x100000000, // Parallel Bits Extract Doubleword X-form (pextd RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{PLBZ, 0xff800000fc000000, 0x600000088000000, 0x6c000000000000, // Prefixed Load Byte and Zero MLS:D-form (plbz RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLD, 0xff800000fc000000, 0x4000000e4000000, 0x6c000000000000, // Prefixed Load Doubleword 8LS:D-form (pld RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLFD, 0xff800000fc000000, 0x6000000c8000000, 0x6c000000000000, // Prefixed Load Floating-Point Double MLS:D-form (plfd FRT,D(RA),R)
		[6]*argField{ap_FPReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLFS, 0xff800000fc000000, 0x6000000c0000000, 0x6c000000000000, // Prefixed Load Floating-Point Single MLS:D-form (plfs FRT,D(RA),R)
		[6]*argField{ap_FPReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLHA, 0xff800000fc000000, 0x6000000a8000000, 0x6c000000000000, // Prefixed Load Halfword Algebraic MLS:D-form (plha RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLHZ, 0xff800000fc000000, 0x6000000a0000000, 0x6c000000000000, // Prefixed Load Halfword and Zero MLS:D-form (plhz RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLQ, 0xff800000fc000000, 0x4000000e0000000, 0x6c000000000000, // Prefixed Load Quadword 8LS:D-form (plq RTp,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLWA, 0xff800000fc000000, 0x4000000a4000000, 0x6c000000000000, // Prefixed Load Word Algebraic 8LS:D-form (plwa RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLWZ, 0xff800000fc000000, 0x600000080000000, 0x6c000000000000, // Prefixed Load Word and Zero MLS:D-form (plwz RT,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLXSD, 0xff800000fc000000, 0x4000000a8000000, 0x6c000000000000, // Prefixed Load VSX Scalar Doubleword 8LS:D-form (plxsd VRT,D(RA),R)
		[6]*argField{ap_VecReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLXSSP, 0xff800000fc000000, 0x4000000ac000000, 0x6c000000000000, // Prefixed Load VSX Scalar Single-Precision 8LS:D-form (plxssp VRT,D(RA),R)
		[6]*argField{ap_VecReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLXV, 0xff800000f8000000, 0x4000000c8000000, 0x6c000000000000, // Prefixed Load VSX Vector 8LS:D-form (plxv XT,D(RA),R)
		[6]*argField{ap_VecSReg_37_37_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PLXVP, 0xff800000fc000000, 0x4000000e8000000, 0x6c000000000000, // Prefixed Load VSX Vector Paired 8LS:D-form (plxvp XTp,D(RA),R)
		[6]*argField{ap_VecSpReg_42_42_38_41, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PMXVBF16GER2, 0xfff00000fc0007f8, 0x7900000ec000198, 0xf3f0000000000, // Prefixed Masked VSX Vector bfloat16 GER (Rank-2 Update) MMIRR:XX3-form (pmxvbf16ger2 AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVBF16GER2NN, 0xfff00000fc0007f8, 0x7900000ec000790, 0xf3f0000000000, // Prefixed Masked VSX Vector bfloat16 GER (Rank-2 Update) Negative multiply, Negative accumulate MMIRR:XX3-form (pmxvbf16ger2nn AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVBF16GER2NP, 0xfff00000fc0007f8, 0x7900000ec000390, 0xf3f0000000000, // Prefixed Masked VSX Vector bfloat16 GER (Rank-2 Update) Negative multiply, Positive accumulate MMIRR:XX3-form (pmxvbf16ger2np AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVBF16GER2PN, 0xfff00000fc0007f8, 0x7900000ec000590, 0xf3f0000000000, // Prefixed Masked VSX Vector bfloat16 GER (Rank-2 Update) Positive multiply, Negative accumulate MMIRR:XX3-form (pmxvbf16ger2pn AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVBF16GER2PP, 0xfff00000fc0007f8, 0x7900000ec000190, 0xf3f0000000000, // Prefixed Masked VSX Vector bfloat16 GER (Rank-2 Update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvbf16ger2pp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF16GER2, 0xfff00000fc0007f8, 0x7900000ec000098, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Floating-Point GER (rank-2 update) MMIRR:XX3-form (pmxvf16ger2 AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF16GER2NN, 0xfff00000fc0007f8, 0x7900000ec000690, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Floating-Point GER (rank-2 update) Negative multiply, Negative accumulate MMIRR:XX3-form (pmxvf16ger2nn AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF16GER2NP, 0xfff00000fc0007f8, 0x7900000ec000290, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Floating-Point GER (rank-2 update) Negative multiply, Positive accumulate MMIRR:XX3-form (pmxvf16ger2np AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF16GER2PN, 0xfff00000fc0007f8, 0x7900000ec000490, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Floating-Point GER (rank-2 update) Positive multiply, Negative accumulate MMIRR:XX3-form (pmxvf16ger2pn AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF16GER2PP, 0xfff00000fc0007f8, 0x7900000ec000090, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Floating-Point GER (rank-2 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvf16ger2pp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVF32GER, 0xfff00000fc0007f8, 0x7900000ec0000d8, 0xfff0000000000, // Prefixed Masked VSX Vector 32-bit Floating-Point GER (rank-1 update) MMIRR:XX3-form (pmxvf32ger AT,XA,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31}},
	{PMXVF32GERNN, 0xfff00000fc0007f8, 0x7900000ec0006d0, 0xfff0000000000, // Prefixed Masked VSX Vector 32-bit Floating-Point GER (rank-1 update) Negative multiply, Negative accumulate MMIRR:XX3-form (pmxvf32gernn AT,XA,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31}},
	{PMXVF32GERNP, 0xfff00000fc0007f8, 0x7900000ec0002d0, 0xfff0000000000, // Prefixed Masked VSX Vector 32-bit Floating-Point GER (rank-1 update) Negative multiply, Positive accumulate MMIRR:XX3-form (pmxvf32gernp AT,XA,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31}},
	{PMXVF32GERPN, 0xfff00000fc0007f8, 0x7900000ec0004d0, 0xfff0000000000, // Prefixed Masked VSX Vector 32-bit Floating-Point GER (rank-1 update) Positive multiply, Negative accumulate MMIRR:XX3-form (pmxvf32gerpn AT,XA,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31}},
	{PMXVF32GERPP, 0xfff00000fc0007f8, 0x7900000ec0000d0, 0xfff0000000000, // Prefixed Masked VSX Vector 32-bit Floating-Point GER (rank-1 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvf32gerpp AT,XA,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31}},
	{PMXVF64GER, 0xfff00000fc0007f8, 0x7900000ec0001d8, 0xfff0300000000, // Prefixed Masked VSX Vector 64-bit Floating-Point GER (rank-1 update) MMIRR:XX3-form (pmxvf64ger AT,XAp,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_29}},
	{PMXVF64GERNN, 0xfff00000fc0007f8, 0x7900000ec0007d0, 0xfff0300000000, // Prefixed Masked VSX Vector 64-bit Floating-Point GER (rank-1 update) Negative multiply, Negative accumulate MMIRR:XX3-form (pmxvf64gernn AT,XAp,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_29}},
	{PMXVF64GERNP, 0xfff00000fc0007f8, 0x7900000ec0003d0, 0xfff0300000000, // Prefixed Masked VSX Vector 64-bit Floating-Point GER (rank-1 update) Negative multiply, Positive accumulate MMIRR:XX3-form (pmxvf64gernp AT,XAp,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_29}},
	{PMXVF64GERPN, 0xfff00000fc0007f8, 0x7900000ec0005d0, 0xfff0300000000, // Prefixed Masked VSX Vector 64-bit Floating-Point GER (rank-1 update) Positive multiply, Negative accumulate MMIRR:XX3-form (pmxvf64gerpn AT,XAp,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_29}},
	{PMXVF64GERPP, 0xfff00000fc0007f8, 0x7900000ec0001d0, 0xfff0300000000, // Prefixed Masked VSX Vector 64-bit Floating-Point GER (rank-1 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvf64gerpp AT,XAp,XB,XMSK,YMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_29}},
	{PMXVI16GER2, 0xfff00000fc0007f8, 0x7900000ec000258, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Signed Integer GER (rank-2 update) MMIRR:XX3-form (pmxvi16ger2 AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVI16GER2PP, 0xfff00000fc0007f8, 0x7900000ec000358, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Signed Integer GER (rank-2 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvi16ger2pp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVI16GER2S, 0xfff00000fc0007f8, 0x7900000ec000158, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Signed Integer GER (rank-2 update) with Saturation MMIRR:XX3-form (pmxvi16ger2s AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVI16GER2SPP, 0xfff00000fc0007f8, 0x7900000ec000150, 0xf3f0000000000, // Prefixed Masked VSX Vector 16-bit Signed Integer GER (rank-2 update) with Saturation Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvi16ger2spp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_17}},
	{PMXVI4GER8, 0xfff00000fc0007f8, 0x7900000ec000118, 0xf000000000000, // Prefixed Masked VSX Vector 4-bit Signed Integer GER (rank-8 update) MMIRR:XX3-form (pmxvi4ger8 AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_23}},
	{PMXVI4GER8PP, 0xfff00000fc0007f8, 0x7900000ec000110, 0xf000000000000, // Prefixed Masked VSX Vector 4-bit Signed Integer GER (rank-8 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvi4ger8pp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_23}},
	{PMXVI8GER4, 0xfff00000fc0007f8, 0x7900000ec000018, 0xf0f0000000000, // Prefixed Masked VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) MMIRR:XX3-form (pmxvi8ger4 AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_19}},
	{PMXVI8GER4PP, 0xfff00000fc0007f8, 0x7900000ec000010, 0xf0f0000000000, // Prefixed Masked VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvi8ger4pp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_19}},
	{PMXVI8GER4SPP, 0xfff00000fc0007f8, 0x7900000ec000318, 0xf0f0000000000, // Prefixed Masked VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) with Saturate Positive multiply, Positive accumulate MMIRR:XX3-form (pmxvi8ger4spp AT,XA,XB,XMSK,YMSK,PMSK)
		[6]*argField{ap_MMAReg_38_40, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_ImmUnsigned_24_27, ap_ImmUnsigned_28_31, ap_ImmUnsigned_16_19}},
	{PNOP, 0xfff3fffe00000000, 0x700000000000000, 0xc000100000000, // Prefixed Nop MRR:*-form (pnop)
		[6]*argField{}},
	{PSTB, 0xff800000fc000000, 0x600000098000000, 0x6c000000000000, // Prefixed Store Byte MLS:D-form (pstb RS,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTD, 0xff800000fc000000, 0x4000000f4000000, 0x6c000000000000, // Prefixed Store Doubleword 8LS:D-form (pstd RS,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTFD, 0xff800000fc000000, 0x6000000d8000000, 0x6c000000000000, // Prefixed Store Floating-Point Double MLS:D-form (pstfd FRS,D(RA),R)
		[6]*argField{ap_FPReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTFS, 0xff800000fc000000, 0x6000000d0000000, 0x6c000000000000, // Prefixed Store Floating-Point Single MLS:D-form (pstfs FRS,D(RA),R)
		[6]*argField{ap_FPReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTH, 0xff800000fc000000, 0x6000000b0000000, 0x6c000000000000, // Prefixed Store Halfword MLS:D-form (psth RS,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTQ, 0xff800000fc000000, 0x4000000f0000000, 0x6c000000000000, // Prefixed Store Quadword 8LS:D-form (pstq RSp,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTW, 0xff800000fc000000, 0x600000090000000, 0x6c000000000000, // Prefixed Store Word MLS:D-form (pstw RS,D(RA),R)
		[6]*argField{ap_Reg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTXSD, 0xff800000fc000000, 0x4000000b8000000, 0x6c000000000000, // Prefixed Store VSX Scalar Doubleword 8LS:D-form (pstxsd VRS,D(RA),R)
		[6]*argField{ap_VecReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTXSSP, 0xff800000fc000000, 0x4000000bc000000, 0x6c000000000000, // Prefixed Store VSX Scalar Single-Precision 8LS:D-form (pstxssp VRS,D(RA),R)
		[6]*argField{ap_VecReg_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTXV, 0xff800000f8000000, 0x4000000d8000000, 0x6c000000000000, // Prefixed Store VSX Vector 8LS:D-form (pstxv XS,D(RA),R)
		[6]*argField{ap_VecSReg_37_37_38_42, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{PSTXVP, 0xff800000fc000000, 0x4000000f8000000, 0x6c000000000000, // Prefixed Store VSX Vector Paired 8LS:D-form (pstxvp XSp,D(RA),R)
		[6]*argField{ap_VecSpReg_42_42_38_41, ap_Offset_14_31_48_63, ap_Reg_43_47, ap_ImmUnsigned_11_11}},
	{SETBC, 0xfc0007fe00000000, 0x7c00030000000000, 0xf80100000000, // Set Boolean Condition X-form (setbc RT,BI)
		[6]*argField{ap_Reg_6_10, ap_CondRegBit_11_15}},
	{SETBCR, 0xfc0007fe00000000, 0x7c00034000000000, 0xf80100000000, // Set Boolean Condition Reverse X-form (setbcr RT,BI)
		[6]*argField{ap_Reg_6_10, ap_CondRegBit_11_15}},
	{SETNBC, 0xfc0007fe00000000, 0x7c00038000000000, 0xf80100000000, // Set Negative Boolean Condition X-form (setnbc RT,BI)
		[6]*argField{ap_Reg_6_10, ap_CondRegBit_11_15}},
	{SETNBCR, 0xfc0007fe00000000, 0x7c0003c000000000, 0xf80100000000, // Set Negative Boolean Condition Reverse X-form (setnbcr RT,BI)
		[6]*argField{ap_Reg_6_10, ap_CondRegBit_11_15}},
	{STXVP, 0xfc00000f00000000, 0x1800000100000000, 0x0, // Store VSX Vector Paired DQ-form (stxvp XSp,DQ(RA))
		[6]*argField{ap_VecSpReg_10_10_6_9, ap_Offset_16_27_shift4, ap_Reg_11_15}},
	{STXVPX, 0xfc0007fe00000000, 0x7c00039a00000000, 0x100000000, // Store VSX Vector Paired Indexed X-form (stxvpx XSp,RA,RB)
		[6]*argField{ap_VecSpReg_10_10_6_9, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVRBX, 0xfc0007fe00000000, 0x7c00011a00000000, 0x0, // Store VSX Vector Rightmost Byte Indexed X-form (stxvrbx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVRDX, 0xfc0007fe00000000, 0x7c0001da00000000, 0x0, // Store VSX Vector Rightmost Doubleword Indexed X-form (stxvrdx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVRHX, 0xfc0007fe00000000, 0x7c00015a00000000, 0x0, // Store VSX Vector Rightmost Halfword Indexed X-form (stxvrhx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVRWX, 0xfc0007fe00000000, 0x7c00019a00000000, 0x0, // Store VSX Vector Rightmost Word Indexed X-form (stxvrwx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VCFUGED, 0xfc0007ff00000000, 0x1000054d00000000, 0x0, // Vector Centrifuge Doubleword VX-form (vcfuged VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCLRLB, 0xfc0007ff00000000, 0x1000018d00000000, 0x0, // Vector Clear Leftmost Bytes VX-form (vclrlb VRT,VRA,RB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_Reg_16_20}},
	{VCLRRB, 0xfc0007ff00000000, 0x100001cd00000000, 0x0, // Vector Clear Rightmost Bytes VX-form (vclrrb VRT,VRA,RB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_Reg_16_20}},
	{VCLZDM, 0xfc0007ff00000000, 0x1000078400000000, 0x0, // Vector Count Leading Zeros Doubleword under bit Mask VX-form (vclzdm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUQ, 0xfc0007ff00000000, 0x100001c700000000, 0x0, // Vector Compare Equal Quadword VC-form (vcmpequq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUQCC, 0xfc0007ff00000000, 0x100005c700000000, 0x0, // Vector Compare Equal Quadword VC-form (vcmpequq. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSQ, 0xfc0007ff00000000, 0x1000038700000000, 0x0, // Vector Compare Greater Than Signed Quadword VC-form (vcmpgtsq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSQCC, 0xfc0007ff00000000, 0x1000078700000000, 0x0, // Vector Compare Greater Than Signed Quadword VC-form (vcmpgtsq. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUQ, 0xfc0007ff00000000, 0x1000028700000000, 0x0, // Vector Compare Greater Than Unsigned Quadword VC-form (vcmpgtuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUQCC, 0xfc0007ff00000000, 0x1000068700000000, 0x0, // Vector Compare Greater Than Unsigned Quadword VC-form (vcmpgtuq. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPSQ, 0xfc0007ff00000000, 0x1000014100000000, 0x60000000000000, // Vector Compare Signed Quadword VX-form (vcmpsq BF,VRA,VRB)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPUQ, 0xfc0007ff00000000, 0x1000010100000000, 0x60000000000000, // Vector Compare Unsigned Quadword VX-form (vcmpuq BF,VRA,VRB)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCNTMBB, 0xfc1e07ff00000000, 0x1018064200000000, 0x0, // Vector Count Mask Bits Byte VX-form (vcntmbb RT,VRB,MP)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_15_15}},
	{VCNTMBD, 0xfc1e07ff00000000, 0x101e064200000000, 0x0, // Vector Count Mask Bits Doubleword VX-form (vcntmbd RT,VRB,MP)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_15_15}},
	{VCNTMBH, 0xfc1e07ff00000000, 0x101a064200000000, 0x0, // Vector Count Mask Bits Halfword VX-form (vcntmbh RT,VRB,MP)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_15_15}},
	{VCNTMBW, 0xfc1e07ff00000000, 0x101c064200000000, 0x0, // Vector Count Mask Bits Word VX-form (vcntmbw RT,VRB,MP)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_15_15}},
	{VCTZDM, 0xfc0007ff00000000, 0x100007c400000000, 0x0, // Vector Count Trailing Zeros Doubleword under bit Mask VX-form (vctzdm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVESD, 0xfc0007ff00000000, 0x100003cb00000000, 0x0, // Vector Divide Extended Signed Doubleword VX-form (vdivesd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVESQ, 0xfc0007ff00000000, 0x1000030b00000000, 0x0, // Vector Divide Extended Signed Quadword VX-form (vdivesq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVESW, 0xfc0007ff00000000, 0x1000038b00000000, 0x0, // Vector Divide Extended Signed Word VX-form (vdivesw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVEUD, 0xfc0007ff00000000, 0x100002cb00000000, 0x0, // Vector Divide Extended Unsigned Doubleword VX-form (vdiveud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVEUQ, 0xfc0007ff00000000, 0x1000020b00000000, 0x0, // Vector Divide Extended Unsigned Quadword VX-form (vdiveuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVEUW, 0xfc0007ff00000000, 0x1000028b00000000, 0x0, // Vector Divide Extended Unsigned Word VX-form (vdiveuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVSD, 0xfc0007ff00000000, 0x100001cb00000000, 0x0, // Vector Divide Signed Doubleword VX-form (vdivsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVSQ, 0xfc0007ff00000000, 0x1000010b00000000, 0x0, // Vector Divide Signed Quadword VX-form (vdivsq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVSW, 0xfc0007ff00000000, 0x1000018b00000000, 0x0, // Vector Divide Signed Word VX-form (vdivsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVUD, 0xfc0007ff00000000, 0x100000cb00000000, 0x0, // Vector Divide Unsigned Doubleword VX-form (vdivud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVUQ, 0xfc0007ff00000000, 0x1000000b00000000, 0x0, // Vector Divide Unsigned Quadword VX-form (vdivuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VDIVUW, 0xfc0007ff00000000, 0x1000008b00000000, 0x0, // Vector Divide Unsigned Word VX-form (vdivuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VEXPANDBM, 0xfc1f07ff00000000, 0x1000064200000000, 0x0, // Vector Expand Byte Mask VX-form (vexpandbm VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXPANDDM, 0xfc1f07ff00000000, 0x1003064200000000, 0x0, // Vector Expand Doubleword Mask VX-form (vexpanddm VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXPANDHM, 0xfc1f07ff00000000, 0x1001064200000000, 0x0, // Vector Expand Halfword Mask VX-form (vexpandhm VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXPANDQM, 0xfc1f07ff00000000, 0x1004064200000000, 0x0, // Vector Expand Quadword Mask VX-form (vexpandqm VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXPANDWM, 0xfc1f07ff00000000, 0x1002064200000000, 0x0, // Vector Expand Word Mask VX-form (vexpandwm VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTDDVLX, 0xfc00003f00000000, 0x1000001e00000000, 0x0, // Vector Extract Double Doubleword to VSR using GPR-specified Left-Index VA-form (vextddvlx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDDVRX, 0xfc00003f00000000, 0x1000001f00000000, 0x0, // Vector Extract Double Doubleword to VSR using GPR-specified Right-Index VA-form (vextddvrx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUBVLX, 0xfc00003f00000000, 0x1000001800000000, 0x0, // Vector Extract Double Unsigned Byte to VSR using GPR-specified Left-Index VA-form (vextdubvlx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUBVRX, 0xfc00003f00000000, 0x1000001900000000, 0x0, // Vector Extract Double Unsigned Byte to VSR using GPR-specified Right-Index VA-form (vextdubvrx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUHVLX, 0xfc00003f00000000, 0x1000001a00000000, 0x0, // Vector Extract Double Unsigned Halfword to VSR using GPR-specified Left-Index VA-form (vextduhvlx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUHVRX, 0xfc00003f00000000, 0x1000001b00000000, 0x0, // Vector Extract Double Unsigned Halfword to VSR using GPR-specified Right-Index VA-form (vextduhvrx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUWVLX, 0xfc00003f00000000, 0x1000001c00000000, 0x0, // Vector Extract Double Unsigned Word to VSR using GPR-specified Left-Index VA-form (vextduwvlx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTDUWVRX, 0xfc00003f00000000, 0x1000001d00000000, 0x0, // Vector Extract Double Unsigned Word to VSR using GPR-specified Right-Index VA-form (vextduwvrx VRT,VRA,VRB,RC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_Reg_21_25}},
	{VEXTRACTBM, 0xfc1f07ff00000000, 0x1008064200000000, 0x0, // Vector Extract Byte Mask VX-form (vextractbm RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VEXTRACTDM, 0xfc1f07ff00000000, 0x100b064200000000, 0x0, // Vector Extract Doubleword Mask VX-form (vextractdm RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VEXTRACTHM, 0xfc1f07ff00000000, 0x1009064200000000, 0x0, // Vector Extract Halfword Mask VX-form (vextracthm RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VEXTRACTQM, 0xfc1f07ff00000000, 0x100c064200000000, 0x0, // Vector Extract Quadword Mask VX-form (vextractqm RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VEXTRACTWM, 0xfc1f07ff00000000, 0x100a064200000000, 0x0, // Vector Extract Word Mask VX-form (vextractwm RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VEXTSD2Q, 0xfc1f07ff00000000, 0x101b060200000000, 0x0, // Vector Extend Sign Doubleword to Quadword VX-form (vextsd2q VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VGNB, 0xfc0007ff00000000, 0x100004cc00000000, 0x18000000000000, // Vector Gather every Nth Bit VX-form (vgnb RT,VRB,N)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_13_15}},
	{VINSBLX, 0xfc0007ff00000000, 0x1000020f00000000, 0x0, // Vector Insert Byte from GPR using GPR-specified Left-Index VX-form (vinsblx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSBRX, 0xfc0007ff00000000, 0x1000030f00000000, 0x0, // Vector Insert Byte from GPR using GPR-specified Right-Index VX-form (vinsbrx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSBVLX, 0xfc0007ff00000000, 0x1000000f00000000, 0x0, // Vector Insert Byte from VSR using GPR-specified Left-Index VX-form (vinsbvlx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSBVRX, 0xfc0007ff00000000, 0x1000010f00000000, 0x0, // Vector Insert Byte from VSR using GPR-specified Right-Index VX-form (vinsbvrx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSD, 0xfc0007ff00000000, 0x100001cf00000000, 0x10000000000000, // Vector Insert Doubleword from GPR using immediate-specified index VX-form (vinsd VRT,RB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20, ap_ImmUnsigned_12_15}},
	{VINSDLX, 0xfc0007ff00000000, 0x100002cf00000000, 0x0, // Vector Insert Doubleword from GPR using GPR-specified Left-Index VX-form (vinsdlx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSDRX, 0xfc0007ff00000000, 0x100003cf00000000, 0x0, // Vector Insert Doubleword from GPR using GPR-specified Right-Index VX-form (vinsdrx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSHLX, 0xfc0007ff00000000, 0x1000024f00000000, 0x0, // Vector Insert Halfword from GPR using GPR-specified Left-Index VX-form (vinshlx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSHRX, 0xfc0007ff00000000, 0x1000034f00000000, 0x0, // Vector Insert Halfword from GPR using GPR-specified Right-Index VX-form (vinshrx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSHVLX, 0xfc0007ff00000000, 0x1000004f00000000, 0x0, // Vector Insert Halfword from VSR using GPR-specified Left-Index VX-form (vinshvlx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSHVRX, 0xfc0007ff00000000, 0x1000014f00000000, 0x0, // Vector Insert Halfword from VSR using GPR-specified Right-Index VX-form (vinshvrx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSW, 0xfc0007ff00000000, 0x100000cf00000000, 0x10000000000000, // Vector Insert Word from GPR using immediate-specified index VX-form (vinsw VRT,RB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_Reg_16_20, ap_ImmUnsigned_12_15}},
	{VINSWLX, 0xfc0007ff00000000, 0x1000028f00000000, 0x0, // Vector Insert Word from GPR using GPR-specified Left-Index VX-form (vinswlx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSWRX, 0xfc0007ff00000000, 0x1000038f00000000, 0x0, // Vector Insert Word from GPR using GPR-specified Right-Index VX-form (vinswrx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VINSWVLX, 0xfc0007ff00000000, 0x1000008f00000000, 0x0, // Vector Insert Word from VSR using GPR-specified Left-Index VX-form (vinswvlx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSWVRX, 0xfc0007ff00000000, 0x1000018f00000000, 0x0, // Vector Insert Word from VSR using GPR-specified Left-Index VX-form (vinswvrx VRT,RA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VMODSD, 0xfc0007ff00000000, 0x100007cb00000000, 0x0, // Vector Modulo Signed Doubleword VX-form (vmodsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMODSQ, 0xfc0007ff00000000, 0x1000070b00000000, 0x0, // Vector Modulo Signed Quadword VX-form (vmodsq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMODSW, 0xfc0007ff00000000, 0x1000078b00000000, 0x0, // Vector Modulo Signed Word VX-form (vmodsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMODUD, 0xfc0007ff00000000, 0x100006cb00000000, 0x0, // Vector Modulo Unsigned Doubleword VX-form (vmodud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMODUQ, 0xfc0007ff00000000, 0x1000060b00000000, 0x0, // Vector Modulo Unsigned Quadword VX-form (vmoduq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMODUW, 0xfc0007ff00000000, 0x1000068b00000000, 0x0, // Vector Modulo Unsigned Word VX-form (vmoduw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMSUMCUD, 0xfc00003f00000000, 0x1000001700000000, 0x0, // Vector Multiply-Sum & write Carry-out Unsigned Doubleword VA-form (vmsumcud VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMULESD, 0xfc0007ff00000000, 0x100003c800000000, 0x0, // Vector Multiply Even Signed Doubleword VX-form (vmulesd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULEUD, 0xfc0007ff00000000, 0x100002c800000000, 0x0, // Vector Multiply Even Unsigned Doubleword VX-form (vmuleud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULHSD, 0xfc0007ff00000000, 0x100003c900000000, 0x0, // Vector Multiply High Signed Doubleword VX-form (vmulhsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULHSW, 0xfc0007ff00000000, 0x1000038900000000, 0x0, // Vector Multiply High Signed Word VX-form (vmulhsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULHUD, 0xfc0007ff00000000, 0x100002c900000000, 0x0, // Vector Multiply High Unsigned Doubleword VX-form (vmulhud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULHUW, 0xfc0007ff00000000, 0x1000028900000000, 0x0, // Vector Multiply High Unsigned Word VX-form (vmulhuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULLD, 0xfc0007ff00000000, 0x100001c900000000, 0x0, // Vector Multiply Low Doubleword VX-form (vmulld VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOSD, 0xfc0007ff00000000, 0x100001c800000000, 0x0, // Vector Multiply Odd Signed Doubleword VX-form (vmulosd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOUD, 0xfc0007ff00000000, 0x100000c800000000, 0x0, // Vector Multiply Odd Unsigned Doubleword VX-form (vmuloud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPDEPD, 0xfc0007ff00000000, 0x100005cd00000000, 0x0, // Vector Parallel Bits Deposit Doubleword VX-form (vpdepd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPEXTD, 0xfc0007ff00000000, 0x1000058d00000000, 0x0, // Vector Parallel Bits Extract Doubleword VX-form (vpextd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLQ, 0xfc0007ff00000000, 0x1000000500000000, 0x0, // Vector Rotate Left Quadword VX-form (vrlq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLQMI, 0xfc0007ff00000000, 0x1000004500000000, 0x0, // Vector Rotate Left Quadword then Mask Insert VX-form (vrlqmi VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLQNM, 0xfc0007ff00000000, 0x1000014500000000, 0x0, // Vector Rotate Left Quadword then AND with Mask VX-form (vrlqnm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLDBI, 0xfc00063f00000000, 0x1000001600000000, 0x0, // Vector Shift Left Double by Bit Immediate VN-form (vsldbi VRT,VRA,VRB,SH)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_23_25}},
	{VSLQ, 0xfc0007ff00000000, 0x1000010500000000, 0x0, // Vector Shift Left Quadword VX-form (vslq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRAQ, 0xfc0007ff00000000, 0x1000030500000000, 0x0, // Vector Shift Right Algebraic Quadword VX-form (vsraq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRDBI, 0xfc00063f00000000, 0x1000021600000000, 0x0, // Vector Shift Right Double by Bit Immediate VN-form (vsrdbi VRT,VRA,VRB,SH)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_23_25}},
	{VSRQ, 0xfc0007ff00000000, 0x1000020500000000, 0x0, // Vector Shift Right Quadword VX-form (vsrq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSTRIBL, 0xfc1f07ff00000000, 0x1000000d00000000, 0x0, // Vector String Isolate Byte Left-justified VX-form (vstribl VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIBLCC, 0xfc1f07ff00000000, 0x1000040d00000000, 0x0, // Vector String Isolate Byte Left-justified VX-form (vstribl. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIBR, 0xfc1f07ff00000000, 0x1001000d00000000, 0x0, // Vector String Isolate Byte Right-justified VX-form (vstribr VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIBRCC, 0xfc1f07ff00000000, 0x1001040d00000000, 0x0, // Vector String Isolate Byte Right-justified VX-form (vstribr. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIHL, 0xfc1f07ff00000000, 0x1002000d00000000, 0x0, // Vector String Isolate Halfword Left-justified VX-form (vstrihl VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIHLCC, 0xfc1f07ff00000000, 0x1002040d00000000, 0x0, // Vector String Isolate Halfword Left-justified VX-form (vstrihl. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIHR, 0xfc1f07ff00000000, 0x1003000d00000000, 0x0, // Vector String Isolate Halfword Right-justified VX-form (vstrihr VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSTRIHRCC, 0xfc1f07ff00000000, 0x1003040d00000000, 0x0, // Vector String Isolate Halfword Right-justified VX-form (vstrihr. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCMPEQQP, 0xfc0007fe00000000, 0xfc00008800000000, 0x100000000, // VSX Scalar Compare Equal Quad-Precision X-form (xscmpeqqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCMPGEQP, 0xfc0007fe00000000, 0xfc00018800000000, 0x100000000, // VSX Scalar Compare Greater Than or Equal Quad-Precision X-form (xscmpgeqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCMPGTQP, 0xfc0007fe00000000, 0xfc0001c800000000, 0x100000000, // VSX Scalar Compare Greater Than Quad-Precision X-form (xscmpgtqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCVQPSQZ, 0xfc1f07fe00000000, 0xfc08068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Signed Quadword X-form (xscvqpsqz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPUQZ, 0xfc1f07fe00000000, 0xfc00068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Unsigned Quadword X-form (xscvqpuqz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVSQQP, 0xfc1f07fe00000000, 0xfc0b068800000000, 0x100000000, // VSX Scalar Convert with round Signed Quadword to Quad-Precision X-form (xscvsqqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVUQQP, 0xfc1f07fe00000000, 0xfc03068800000000, 0x100000000, // VSX Scalar Convert with round Unsigned Quadword to Quad-Precision X-form (xscvuqqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSMAXCQP, 0xfc0007fe00000000, 0xfc00054800000000, 0x100000000, // VSX Scalar Maximum Type-C Quad-Precision X-form (xsmaxcqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMINCQP, 0xfc0007fe00000000, 0xfc0005c800000000, 0x100000000, // VSX Scalar Minimum Type-C Quad-Precision X-form (xsmincqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XVBF16GER2, 0xfc0007f800000000, 0xec00019800000000, 0x60000100000000, // VSX Vector bfloat16 GER (Rank-2 Update) XX3-form (xvbf16ger2 AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVBF16GER2NN, 0xfc0007f800000000, 0xec00079000000000, 0x60000100000000, // VSX Vector bfloat16 GER (Rank-2 Update) Negative multiply, Negative accumulate XX3-form (xvbf16ger2nn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVBF16GER2NP, 0xfc0007f800000000, 0xec00039000000000, 0x60000100000000, // VSX Vector bfloat16 GER (Rank-2 Update) Negative multiply, Positive accumulate XX3-form (xvbf16ger2np AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVBF16GER2PN, 0xfc0007f800000000, 0xec00059000000000, 0x60000100000000, // VSX Vector bfloat16 GER (Rank-2 Update) Positive multiply, Negative accumulate XX3-form (xvbf16ger2pn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVBF16GER2PP, 0xfc0007f800000000, 0xec00019000000000, 0x60000100000000, // VSX Vector bfloat16 GER (Rank-2 Update) Positive multiply, Positive accumulate XX3-form (xvbf16ger2pp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCVBF16SPN, 0xfc1f07fc00000000, 0xf010076c00000000, 0x0, // VSX Vector Convert bfloat16 to Single-Precision format Non-signaling XX2-form (xvcvbf16spn XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPBF16, 0xfc1f07fc00000000, 0xf011076c00000000, 0x0, // VSX Vector Convert with round Single-Precision to bfloat16 format XX2-form (xvcvspbf16 XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVF16GER2, 0xfc0007f800000000, 0xec00009800000000, 0x60000100000000, // VSX Vector 16-bit Floating-Point GER (rank-2 update) XX3-form (xvf16ger2 AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF16GER2NN, 0xfc0007f800000000, 0xec00069000000000, 0x60000100000000, // VSX Vector 16-bit Floating-Point GER (rank-2 update) Negative multiply, Negative accumulate XX3-form (xvf16ger2nn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF16GER2NP, 0xfc0007f800000000, 0xec00029000000000, 0x60000100000000, // VSX Vector 16-bit Floating-Point GER (rank-2 update) Negative multiply, Positive accumulate XX3-form (xvf16ger2np AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF16GER2PN, 0xfc0007f800000000, 0xec00049000000000, 0x60000100000000, // VSX Vector 16-bit Floating-Point GER (rank-2 update) Positive multiply, Negative accumulate XX3-form (xvf16ger2pn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF16GER2PP, 0xfc0007f800000000, 0xec00009000000000, 0x60000100000000, // VSX Vector 16-bit Floating-Point GER (rank-2 update) Positive multiply, Positive accumulate XX3-form (xvf16ger2pp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF32GER, 0xfc0007f800000000, 0xec0000d800000000, 0x60000100000000, // VSX Vector 32-bit Floating-Point GER (rank-1 update) XX3-form (xvf32ger AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF32GERNN, 0xfc0007f800000000, 0xec0006d000000000, 0x60000100000000, // VSX Vector 32-bit Floating-Point GER (rank-1 update) Negative multiply, Negative accumulate XX3-form (xvf32gernn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF32GERNP, 0xfc0007f800000000, 0xec0002d000000000, 0x60000100000000, // VSX Vector 32-bit Floating-Point GER (rank-1 update) Negative multiply, Positive accumulate XX3-form (xvf32gernp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF32GERPN, 0xfc0007f800000000, 0xec0004d000000000, 0x60000100000000, // VSX Vector 32-bit Floating-Point GER (rank-1 update) Positive multiply, Negative accumulate XX3-form (xvf32gerpn AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF32GERPP, 0xfc0007f800000000, 0xec0000d000000000, 0x60000100000000, // VSX Vector 32-bit Floating-Point GER (rank-1 update) Positive multiply, Positive accumulate XX3-form (xvf32gerpp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF64GER, 0xfc0007f800000000, 0xec0001d800000000, 0x60000100000000, // VSX Vector 64-bit Floating-Point GER (rank-1 update) XX3-form (xvf64ger AT,XAp,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF64GERNN, 0xfc0007f800000000, 0xec0007d000000000, 0x60000100000000, // VSX Vector 64-bit Floating-Point GER (rank-1 update) Negative multiply, Negative accumulate XX3-form (xvf64gernn AT,XAp,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF64GERNP, 0xfc0007f800000000, 0xec0003d000000000, 0x60000100000000, // VSX Vector 64-bit Floating-Point GER (rank-1 update) Negative multiply, Positive accumulate XX3-form (xvf64gernp AT,XAp,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF64GERPN, 0xfc0007f800000000, 0xec0005d000000000, 0x60000100000000, // VSX Vector 64-bit Floating-Point GER (rank-1 update) Positive multiply, Negative accumulate XX3-form (xvf64gerpn AT,XAp,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVF64GERPP, 0xfc0007f800000000, 0xec0001d000000000, 0x60000100000000, // VSX Vector 64-bit Floating-Point GER (rank-1 update) Positive multiply, Positive accumulate XX3-form (xvf64gerpp AT,XAp,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI16GER2, 0xfc0007f800000000, 0xec00025800000000, 0x60000100000000, // VSX Vector 16-bit Signed Integer GER (rank-2 update) XX3-form (xvi16ger2 AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI16GER2PP, 0xfc0007f800000000, 0xec00035800000000, 0x60000100000000, // VSX Vector 16-bit Signed Integer GER (rank-2 update) Positive multiply, Positive accumulate XX3-form (xvi16ger2pp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI16GER2S, 0xfc0007f800000000, 0xec00015800000000, 0x60000100000000, // VSX Vector 16-bit Signed Integer GER (rank-2 update) with Saturation XX3-form (xvi16ger2s AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI16GER2SPP, 0xfc0007f800000000, 0xec00015000000000, 0x60000100000000, // VSX Vector 16-bit Signed Integer GER (rank-2 update) with Saturation Positive multiply, Positive accumulate XX3-form (xvi16ger2spp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI4GER8, 0xfc0007f800000000, 0xec00011800000000, 0x60000100000000, // VSX Vector 4-bit Signed Integer GER (rank-8 update) XX3-form (xvi4ger8 AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI4GER8PP, 0xfc0007f800000000, 0xec00011000000000, 0x60000100000000, // VSX Vector 4-bit Signed Integer GER (rank-8 update) Positive multiply, Positive accumulate XX3-form (xvi4ger8pp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI8GER4, 0xfc0007f800000000, 0xec00001800000000, 0x60000100000000, // VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) XX3-form (xvi8ger4 AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI8GER4PP, 0xfc0007f800000000, 0xec00001000000000, 0x60000100000000, // VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) Positive multiply, Positive accumulate XX3-form (xvi8ger4pp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVI8GER4SPP, 0xfc0007f800000000, 0xec00031800000000, 0x60000100000000, // VSX Vector 8-bit Signed/Unsigned Integer GER (rank-4 update) with Saturate Positive multiply, Positive accumulate XX3-form (xvi8ger4spp AT,XA,XB)
		[6]*argField{ap_MMAReg_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVTLSBB, 0xfc1f07fc00000000, 0xf002076c00000000, 0x60000100000000, // VSX Vector Test Least-Significant Bit by Byte XX2-form (xvtlsbb BF,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20}},
	{XXBLENDVB, 0xfff00000fc000030, 0x500000084000000, 0xfffff00000000, // VSX Vector Blend Variable Byte 8RR:XX4-form (xxblendvb XT,XA,XB,XC)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57}},
	{XXBLENDVD, 0xfff00000fc000030, 0x500000084000030, 0xfffff00000000, // VSX Vector Blend Variable Doubleword 8RR:XX4-form (xxblendvd XT,XA,XB,XC)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57}},
	{XXBLENDVH, 0xfff00000fc000030, 0x500000084000010, 0xfffff00000000, // VSX Vector Blend Variable Halfword 8RR:XX4-form (xxblendvh XT,XA,XB,XC)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57}},
	{XXBLENDVW, 0xfff00000fc000030, 0x500000084000020, 0xfffff00000000, // VSX Vector Blend Variable Word 8RR:XX4-form (xxblendvw XT,XA,XB,XC)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57}},
	{XXEVAL, 0xfff00000fc000030, 0x500000088000010, 0xfff0000000000, // VSX Vector Evaluate 8RR-XX4-form (xxeval XT,XA,XB,XC,IMM)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57, ap_ImmUnsigned_24_31}},
	{XXGENPCVBM, 0xfc0007fe00000000, 0xf000072800000000, 0x0, // VSX Vector Generate PCV from Byte Mask X-form (xxgenpcvbm XT,VRB,IMM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{XXGENPCVDM, 0xfc0007fe00000000, 0xf000076a00000000, 0x0, // VSX Vector Generate PCV from Doubleword Mask X-form (xxgenpcvdm XT,VRB,IMM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{XXGENPCVHM, 0xfc0007fe00000000, 0xf000072a00000000, 0x0, // VSX Vector Generate PCV from Halfword Mask X-form (xxgenpcvhm XT,VRB,IMM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{XXGENPCVWM, 0xfc0007fe00000000, 0xf000076800000000, 0x0, // VSX Vector Generate PCV from Word Mask X-form (xxgenpcvwm XT,VRB,IMM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{XXMFACC, 0xfc1f07fe00000000, 0x7c00016200000000, 0x60f80100000000, // VSX Move From Accumulator X-form (xxmfacc AS)
		[6]*argField{ap_MMAReg_6_8}},
	{XXMTACC, 0xfc1f07fe00000000, 0x7c01016200000000, 0x60f80100000000, // VSX Move To Accumulator X-form (xxmtacc AT)
		[6]*argField{ap_MMAReg_6_8}},
	{XXPERMX, 0xfff00000fc000030, 0x500000088000000, 0xffff800000000, // VSX Vector Permute Extended 8RR:XX4-form (xxpermx XT,XA,XB,XC,UIM)
		[6]*argField{ap_VecSReg_63_63_38_42, ap_VecSReg_61_61_43_47, ap_VecSReg_62_62_48_52, ap_VecSReg_60_60_53_57, ap_ImmUnsigned_29_31}},
	{XXSETACCZ, 0xfc1f07fe00000000, 0x7c03016200000000, 0x60f80100000000, // VSX Set Accumulator to Zero X-form (xxsetaccz AT)
		[6]*argField{ap_MMAReg_6_8}},
	{XXSPLTI32DX, 0xfff00000fc1c0000, 0x500000080000000, 0xf000000000000, // VSX Vector Splat Immediate32 Doubleword Indexed 8RR:D-form (xxsplti32dx XT,IX,IMM32)
		[6]*argField{ap_VecSReg_47_47_38_42, ap_ImmUnsigned_46_46, ap_ImmUnsigned_16_31_48_63}},
	{XXSPLTIDP, 0xfff00000fc1e0000, 0x500000080040000, 0xf000000000000, // VSX Vector Splat Immediate Double-Precision 8RR:D-form (xxspltidp XT,IMM32)
		[6]*argField{ap_VecSReg_47_47_38_42, ap_ImmUnsigned_16_31_48_63}},
	{XXSPLTIW, 0xfff00000fc1e0000, 0x500000080060000, 0xf000000000000, // VSX Vector Splat Immediate Word 8RR:D-form (xxspltiw XT,IMM32)
		[6]*argField{ap_VecSReg_47_47_38_42, ap_ImmUnsigned_16_31_48_63}},
	{MSGCLRU, 0xfc0007fe00000000, 0x7c0000dc00000000, 0x3ff000100000000, // Ultravisor Message Clear X-form (msgclru RB)
		[6]*argField{ap_Reg_16_20}},
	{MSGSNDU, 0xfc0007fe00000000, 0x7c00009c00000000, 0x3ff000100000000, // Ultravisor Message SendX-form (msgsndu RB)
		[6]*argField{ap_Reg_16_20}},
	{URFID, 0xfc0007fe00000000, 0x4c00026400000000, 0x3fff80100000000, // Ultravisor Return From Interrupt Doubleword XL-form (urfid)
		[6]*argField{}},
	{ADDEX, 0xfc0001fe00000000, 0x7c00015400000000, 0x100000000, // Add Extended using alternate carry bit Z23-form (addex RT,RA,RB,CY)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_21_22}},
	{MFFSCDRN, 0xfc1f07fe00000000, 0xfc14048e00000000, 0x100000000, // Move From FPSCR Control & Set DRN X-form (mffscdrn FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{MFFSCDRNI, 0xfc1f07fe00000000, 0xfc15048e00000000, 0xc00100000000, // Move From FPSCR Control & Set DRN Immediate X-form (mffscdrni FRT,DRM)
		[6]*argField{ap_FPReg_6_10, ap_ImmUnsigned_18_20}},
	{MFFSCE, 0xfc1f07fe00000000, 0xfc01048e00000000, 0xf80100000000, // Move From FPSCR & Clear Enables X-form (mffsce FRT)
		[6]*argField{ap_FPReg_6_10}},
	{MFFSCRN, 0xfc1f07fe00000000, 0xfc16048e00000000, 0x100000000, // Move From FPSCR Control & Set RN X-form (mffscrn FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{MFFSCRNI, 0xfc1f07fe00000000, 0xfc17048e00000000, 0xe00100000000, // Move From FPSCR Control & Set RN Immediate X-form (mffscrni FRT,RM)
		[6]*argField{ap_FPReg_6_10, ap_ImmUnsigned_19_20}},
	{MFFSL, 0xfc1f07fe00000000, 0xfc18048e00000000, 0xf80100000000, // Move From FPSCR Lightweight X-form (mffsl FRT)
		[6]*argField{ap_FPReg_6_10}},
	{SLBIAG, 0xfc0007fe00000000, 0x7c0006a400000000, 0x1ef80100000000, // SLB Invalidate All Global X-form (slbiag RS, L)
		[6]*argField{ap_Reg_6_10, ap_ImmUnsigned_15_15}},
	{VMSUMUDM, 0xfc00003f00000000, 0x1000002300000000, 0x0, // Vector Multiply-Sum Unsigned Doubleword Modulo VA-form (vmsumudm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{ADDPCIS, 0xfc00003e00000000, 0x4c00000400000000, 0x0, // Add PC Immediate Shifted DX-form (addpcis RT,D)
		[6]*argField{ap_Reg_6_10, ap_ImmSigned_16_25_11_15_31_31}},
	{BCDCFNCC, 0xfc1f05ff00000000, 0x1007058100000000, 0x0, // Decimal Convert From National VX-form (bcdcfn. VRT,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDCFSQCC, 0xfc1f05ff00000000, 0x1002058100000000, 0x0, // Decimal Convert From Signed Quadword VX-form (bcdcfsq. VRT,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDCFZCC, 0xfc1f05ff00000000, 0x1006058100000000, 0x0, // Decimal Convert From Zoned VX-form (bcdcfz. VRT,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDCPSGNCC, 0xfc0007ff00000000, 0x1000034100000000, 0x0, // Decimal Copy Sign VX-form (bcdcpsgn. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{BCDCTNCC, 0xfc1f05ff00000000, 0x1005058100000000, 0x20000000000, // Decimal Convert To National VX-form (bcdctn. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{BCDCTSQCC, 0xfc1f05ff00000000, 0x1000058100000000, 0x20000000000, // Decimal Convert To Signed Quadword VX-form (bcdctsq. VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{BCDCTZCC, 0xfc1f05ff00000000, 0x1004058100000000, 0x0, // Decimal Convert To Zoned VX-form (bcdctz. VRT,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDSCC, 0xfc0005ff00000000, 0x100004c100000000, 0x0, // Decimal Shift VX-form (bcds. VRT,VRA,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDSETSGNCC, 0xfc1f05ff00000000, 0x101f058100000000, 0x0, // Decimal Set Sign VX-form (bcdsetsgn. VRT,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDSRCC, 0xfc0005ff00000000, 0x100005c100000000, 0x0, // Decimal Shift and Round VX-form (bcdsr. VRT,VRA,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDTRUNCCC, 0xfc0005ff00000000, 0x1000050100000000, 0x0, // Decimal Truncate VX-form (bcdtrunc. VRT,VRA,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDUSCC, 0xfc0005ff00000000, 0x1000048100000000, 0x20000000000, // Decimal Unsigned Shift VX-form (bcdus. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{BCDUTRUNCCC, 0xfc0005ff00000000, 0x1000054100000000, 0x20000000000, // Decimal Unsigned Truncate VX-form (bcdutrunc. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{CMPEQB, 0xfc0007fe00000000, 0x7c0001c000000000, 0x60000100000000, // Compare Equal Byte X-form (cmpeqb BF,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPRB, 0xfc0007fe00000000, 0x7c00018000000000, 0x40000100000000, // Compare Ranged Byte X-form (cmprb BF,L,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_10, ap_Reg_11_15, ap_Reg_16_20}},
	{CNTTZD, 0xfc0007ff00000000, 0x7c00047400000000, 0xf80000000000, // Count Trailing Zeros Doubleword X-form (cnttzd RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CNTTZDCC, 0xfc0007ff00000000, 0x7c00047500000000, 0xf80000000000, // Count Trailing Zeros Doubleword X-form (cnttzd. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CNTTZW, 0xfc0007ff00000000, 0x7c00043400000000, 0xf80000000000, // Count Trailing Zeros Word X-form (cnttzw RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CNTTZWCC, 0xfc0007ff00000000, 0x7c00043500000000, 0xf80000000000, // Count Trailing Zeros Word X-form (cnttzw. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{COPY, 0xfc2007fe00000000, 0x7c20060c00000000, 0x3c0000100000000, // Copy X-form (copy RA,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20}},
	{CPABORT, 0xfc0007fe00000000, 0x7c00068c00000000, 0x3fff80100000000, // Copy-Paste Abort X-form (cpabort)
		[6]*argField{}},
	{DARN, 0xfc0007fe00000000, 0x7c0005e600000000, 0x1cf80100000000, // Deliver A Random Number X-form (darn RT,L)
		[6]*argField{ap_Reg_6_10, ap_ImmUnsigned_14_15}},
	{DTSTSFI, 0xfc0007fe00000000, 0xec00054600000000, 0x40000100000000, // DFP Test Significance Immediate X-form (dtstsfi BF,UIM,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_15, ap_FPReg_16_20}},
	{DTSTSFIQ, 0xfc0007fe00000000, 0xfc00054600000000, 0x40000100000000, // DFP Test Significance Immediate Quad X-form (dtstsfiq BF,UIM,FRBp)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_15, ap_FPReg_16_20}},
	{EXTSWSLI, 0xfc0007fd00000000, 0x7c0006f400000000, 0x0, // Extend Sign Word and Shift Left Immediate XS-form (extswsli RA,RS,SH)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20}},
	{EXTSWSLICC, 0xfc0007fd00000000, 0x7c0006f500000000, 0x0, // Extend Sign Word and Shift Left Immediate XS-form (extswsli. RA,RS,SH)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20}},
	{LDAT, 0xfc0007fe00000000, 0x7c0004cc00000000, 0x100000000, // Load Doubleword ATomic X-form (ldat RT,RA,FC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmUnsigned_16_20}},
	{LWAT, 0xfc0007fe00000000, 0x7c00048c00000000, 0x100000000, // Load Word ATomic X-form (lwat RT,RA,FC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmUnsigned_16_20}},
	{LXSD, 0xfc00000300000000, 0xe400000200000000, 0x0, // Load VSX Scalar Doubleword DS-form (lxsd VRT,DS(RA))
		[6]*argField{ap_VecReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LXSIBZX, 0xfc0007fe00000000, 0x7c00061a00000000, 0x0, // Load VSX Scalar as Integer Byte & Zero Indexed X-form (lxsibzx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXSIHZX, 0xfc0007fe00000000, 0x7c00065a00000000, 0x0, // Load VSX Scalar as Integer Halfword & Zero Indexed X-form (lxsihzx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXSSP, 0xfc00000300000000, 0xe400000300000000, 0x0, // Load VSX Scalar Single-Precision DS-form (lxssp VRT,DS(RA))
		[6]*argField{ap_VecReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LXV, 0xfc00000700000000, 0xf400000100000000, 0x0, // Load VSX Vector DQ-form (lxv XT,DQ(RA))
		[6]*argField{ap_VecSReg_28_28_6_10, ap_Offset_16_27_shift4, ap_Reg_11_15}},
	{LXVB16X, 0xfc0007fe00000000, 0x7c0006d800000000, 0x0, // Load VSX Vector Byte*16 Indexed X-form (lxvb16x XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVH8X, 0xfc0007fe00000000, 0x7c00065800000000, 0x0, // Load VSX Vector Halfword*8 Indexed X-form (lxvh8x XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVL, 0xfc0007fe00000000, 0x7c00021a00000000, 0x0, // Load VSX Vector with Length X-form (lxvl XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVLL, 0xfc0007fe00000000, 0x7c00025a00000000, 0x0, // Load VSX Vector with Length Left-justified X-form (lxvll XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVWSX, 0xfc0007fe00000000, 0x7c0002d800000000, 0x0, // Load VSX Vector Word & Splat Indexed X-form (lxvwsx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVX, 0xfc0007be00000000, 0x7c00021800000000, 0x4000000000, // Load VSX Vector Indexed X-form (lxvx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MADDHD, 0xfc00003f00000000, 0x1000003000000000, 0x0, // Multiply-Add High Doubleword VA-form (maddhd RT,RA,RB,RC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_Reg_21_25}},
	{MADDHDU, 0xfc00003f00000000, 0x1000003100000000, 0x0, // Multiply-Add High Doubleword Unsigned VA-form (maddhdu RT,RA,RB,RC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_Reg_21_25}},
	{MADDLD, 0xfc00003f00000000, 0x1000003300000000, 0x0, // Multiply-Add Low Doubleword VA-form (maddld RT,RA,RB,RC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_Reg_21_25}},
	{MCRXRX, 0xfc0007fe00000000, 0x7c00048000000000, 0x7ff80100000000, // Move to CR from XER Extended X-form (mcrxrx BF)
		[6]*argField{ap_CondRegField_6_8}},
	{MFVSRLD, 0xfc0007fe00000000, 0x7c00026600000000, 0xf80000000000, // Move From VSR Lower Doubleword X-form (mfvsrld RA,XS)
		[6]*argField{ap_Reg_11_15, ap_VecSReg_31_31_6_10}},
	{MODSD, 0xfc0007fe00000000, 0x7c00061200000000, 0x100000000, // Modulo Signed Doubleword X-form (modsd RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MODSW, 0xfc0007fe00000000, 0x7c00061600000000, 0x100000000, // Modulo Signed Word X-form (modsw RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MODUD, 0xfc0007fe00000000, 0x7c00021200000000, 0x100000000, // Modulo Unsigned Doubleword X-form (modud RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MODUW, 0xfc0007fe00000000, 0x7c00021600000000, 0x100000000, // Modulo Unsigned Word X-form (moduw RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MSGSYNC, 0xfc0007fe00000000, 0x7c0006ec00000000, 0x3fff80100000000, // Message Synchronize X-form (msgsync)
		[6]*argField{}},
	{MTVSRDD, 0xfc0007fe00000000, 0x7c00036600000000, 0x0, // Move To VSR Double Doubleword X-form (mtvsrdd XT,RA,RB)
		[6]*ar
```