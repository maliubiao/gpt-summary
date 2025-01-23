Response:
这段代码是 Go 语言实现的一部分，主要用于 **PowerPC 64 位架构（ppc64）的指令集解码**。具体来说，它定义了一系列 PowerPC 指令的操作码、操作数字段以及相关的指令格式。以下是对其功能的详细归纳：

---

### 功能归纳

1. **指令定义与解码**  
   代码中定义了大量的 PowerPC 指令，每条指令包括以下信息：
   - **指令名称**：如 `MTVSRWS`、`PASTECC`、`SETB` 等。
   - **操作码（Opcode）**：用于唯一标识指令的二进制编码。
   - **操作数字段（argField）**：描述指令的操作数，如寄存器、立即数等。
   - **指令格式**：如 X-form、VX-form、XX3-form 等，表示指令的编码格式。

2. **指令分类**  
   代码中涉及的指令涵盖了多种类型，包括：
   - **向量操作指令**：如 `VABSDUB`（向量绝对值差）、`VBPERMD`（向量位排列）等。
   - **浮点操作指令**：如 `XSADDDP`（VSX 标量双精度加法）、`XSCVDPSP`（VSX 标量双精度转单精度）等。
   - **存储与加载指令**：如 `STXSDX`（存储 VSX 标量双字）、`LXVD2X`（加载 VSX 向量双字）等。
   - **分支与跳转指令**：如 `BCTAR`（条件分支到目标地址寄存器）、`RFEBB`（从事件分支返回）等。
   - **逻辑与算术指令**：如 `ADDG6S`（生成六位加法）、`DIVDE`（双字扩展除法）等。

3. **指令格式**  
   代码中涉及的指令格式包括：
   - **X-form**：标准指令格式，通常用于算术和逻辑操作。
   - **VX-form**：向量指令格式，用于向量操作。
   - **XX3-form**：VSX 指令格式，用于 VSX（Vector-Scalar eXtension）操作。
   - **VA-form**：向量算术指令格式，用于复杂的向量操作。

4. **操作数字段**  
   每条指令的操作数字段通过 `argField` 描述，常见的操作数类型包括：
   - **寄存器**：如 `ap_Reg_6_10` 表示 6 到 10 位的寄存器字段。
   - **立即数**：如 `ap_ImmUnsigned_12_15` 表示 12 到 15 位的无符号立即数。
   - **向量寄存器**：如 `ap_VecReg_6_10` 表示 6 到 10 位的向量寄存器字段。
   - **条件寄存器**：如 `ap_CondRegField_6_8` 表示 6 到 8 位的条件寄存器字段。

5. **指令功能示例**  
   - **MTVSRWS**：将通用寄存器的值移动到向量标量寄存器，并进行字扩展。
   - **PASTECC**：将两个寄存器的值粘贴到目标寄存器，并根据条件码设置标志位。
   - **SETB**：根据条件寄存器字段设置布尔值。
   - **VABSDUB**：计算两个向量寄存器中无符号字节的绝对值差。

---

### 代码推理与示例

假设我们有一条 PowerPC 指令 `VABSDUB VRT, VRA, VRB`，其功能是计算两个向量寄存器中无符号字节的绝对值差。以下是一个可能的 Go 代码实现：

```go
func vabsdub(vrt, vra, vrb uint32) {
    for i := 0; i < 16; i++ { // 假设向量寄存器包含 16 个字节
        diff := abs(int(vra[i]) - int(vrb[i]))
        vrt[i] = uint8(diff)
    }
}

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}
```

**输入**：  
- `vra = [10, 20, 30, 40, ...]`  
- `vrb = [5, 25, 35, 45, ...]`  

**输出**：  
- `vrt = [5, 5, 5, 5, ...]`  

---

### 易错点

1. **操作数字段的位范围**  
   在解析指令时，操作数字段的位范围必须准确匹配，否则会导致错误的寄存器或立即数值。例如，`ap_Reg_6_10` 表示 6 到 10 位的寄存器字段，如果误用为 `ap_Reg_6_11`，则会导致错误。

2. **指令格式的混淆**  
   不同的指令格式（如 X-form、VX-form、XX3-form）有不同的编码规则，混淆格式会导致解码错误。例如，X-form 和 VX-form 的操作数字段布局不同，不能混用。

3. **向量寄存器的字节顺序**  
   在实现向量操作时，需要注意 PowerPC 的字节顺序（大端序）。如果忽略这一点，可能会导致计算结果错误。

---

### 总结

这段代码是 PowerPC 64 位架构指令集解码的核心部分，定义了大量的指令及其操作数字段。它的主要功能是支持指令的解码和执行，涵盖了向量操作、浮点操作、存储加载、分支跳转等多种类型的指令。在实际使用中，需要特别注意操作数字段的位范围和指令格式的正确性。
### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```go
gField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MTVSRWS, 0xfc0007fe00000000, 0x7c00032600000000, 0xf80000000000, // Move To VSR Word & Splat X-form (mtvsrws XT,RA)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15}},
	{PASTECC, 0xfc0007ff00000000, 0x7c00070d00000000, 0x3c0000000000000, // Paste X-form (paste. RA,RB,L)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_10_10}},
	{SETB, 0xfc0007fe00000000, 0x7c00010000000000, 0x3f80100000000, // Set Boolean X-form (setb RT,BFA)
		[6]*argField{ap_Reg_6_10, ap_CondRegField_11_13}},
	{SLBIEG, 0xfc0007fe00000000, 0x7c0003a400000000, 0x1f000100000000, // SLB Invalidate Entry Global X-form (slbieg RS,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_16_20}},
	{SLBSYNC, 0xfc0007fe00000000, 0x7c0002a400000000, 0x3fff80100000000, // SLB Synchronize X-form (slbsync)
		[6]*argField{}},
	{STDAT, 0xfc0007fe00000000, 0x7c0005cc00000000, 0x100000000, // Store Doubleword ATomic X-form (stdat RS,RA,FC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmUnsigned_16_20}},
	{STOP, 0xfc0007fe00000000, 0x4c0002e400000000, 0x3fff80100000000, // Stop XL-form (stop)
		[6]*argField{}},
	{STWAT, 0xfc0007fe00000000, 0x7c00058c00000000, 0x100000000, // Store Word ATomic X-form (stwat RS,RA,FC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmUnsigned_16_20}},
	{STXSD, 0xfc00000300000000, 0xf400000200000000, 0x0, // Store VSX Scalar Doubleword DS-form (stxsd VRS,DS(RA))
		[6]*argField{ap_VecReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{STXSIBX, 0xfc0007fe00000000, 0x7c00071a00000000, 0x0, // Store VSX Scalar as Integer Byte Indexed X-form (stxsibx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXSIHX, 0xfc0007fe00000000, 0x7c00075a00000000, 0x0, // Store VSX Scalar as Integer Halfword Indexed X-form (stxsihx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXSSP, 0xfc00000300000000, 0xf400000300000000, 0x0, // Store VSX Scalar Single DS-form (stxssp VRS,DS(RA))
		[6]*argField{ap_VecReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{STXV, 0xfc00000700000000, 0xf400000500000000, 0x0, // Store VSX Vector DQ-form (stxv XS,DQ(RA))
		[6]*argField{ap_VecSReg_28_28_6_10, ap_Offset_16_27_shift4, ap_Reg_11_15}},
	{STXVB16X, 0xfc0007fe00000000, 0x7c0007d800000000, 0x0, // Store VSX Vector Byte*16 Indexed X-form (stxvb16x XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVH8X, 0xfc0007fe00000000, 0x7c00075800000000, 0x0, // Store VSX Vector Halfword*8 Indexed X-form (stxvh8x XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVL, 0xfc0007fe00000000, 0x7c00031a00000000, 0x0, // Store VSX Vector with Length X-form (stxvl XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVLL, 0xfc0007fe00000000, 0x7c00035a00000000, 0x0, // Store VSX Vector with Length Left-justified X-form (stxvll XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVX, 0xfc0007fe00000000, 0x7c00031800000000, 0x0, // Store VSX Vector Indexed X-form (stxvx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VABSDUB, 0xfc0007ff00000000, 0x1000040300000000, 0x0, // Vector Absolute Difference Unsigned Byte VX-form (vabsdub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VABSDUH, 0xfc0007ff00000000, 0x1000044300000000, 0x0, // Vector Absolute Difference Unsigned Halfword VX-form (vabsduh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VABSDUW, 0xfc0007ff00000000, 0x1000048300000000, 0x0, // Vector Absolute Difference Unsigned Word VX-form (vabsduw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VBPERMD, 0xfc0007ff00000000, 0x100005cc00000000, 0x0, // Vector Bit Permute Doubleword VX-form (vbpermd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCLZLSBB, 0xfc1f07ff00000000, 0x1000060200000000, 0x0, // Vector Count Leading Zero Least-Significant Bits Byte VX-form (vclzlsbb RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VCMPNEB, 0xfc0007ff00000000, 0x1000000700000000, 0x0, // Vector Compare Not Equal Byte VC-form (vcmpneb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEBCC, 0xfc0007ff00000000, 0x1000040700000000, 0x0, // Vector Compare Not Equal Byte VC-form (vcmpneb. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEH, 0xfc0007ff00000000, 0x1000004700000000, 0x0, // Vector Compare Not Equal Halfword VC-form (vcmpneh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEHCC, 0xfc0007ff00000000, 0x1000044700000000, 0x0, // Vector Compare Not Equal Halfword VC-form (vcmpneh. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEW, 0xfc0007ff00000000, 0x1000008700000000, 0x0, // Vector Compare Not Equal Word VC-form (vcmpnew VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEWCC, 0xfc0007ff00000000, 0x1000048700000000, 0x0, // Vector Compare Not Equal Word VC-form (vcmpnew. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZB, 0xfc0007ff00000000, 0x1000010700000000, 0x0, // Vector Compare Not Equal or Zero Byte VC-form (vcmpnezb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZBCC, 0xfc0007ff00000000, 0x1000050700000000, 0x0, // Vector Compare Not Equal or Zero Byte VC-form (vcmpnezb. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZH, 0xfc0007ff00000000, 0x1000014700000000, 0x0, // Vector Compare Not Equal or Zero Halfword VC-form (vcmpnezh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZHCC, 0xfc0007ff00000000, 0x1000054700000000, 0x0, // Vector Compare Not Equal or Zero Halfword VC-form (vcmpnezh. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZW, 0xfc0007ff00000000, 0x1000018700000000, 0x0, // Vector Compare Not Equal or Zero Word VC-form (vcmpnezw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPNEZWCC, 0xfc0007ff00000000, 0x1000058700000000, 0x0, // Vector Compare Not Equal or Zero Word VC-form (vcmpnezw. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCTZB, 0xfc1f07ff00000000, 0x101c060200000000, 0x0, // Vector Count Trailing Zeros Byte VX-form (vctzb VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCTZD, 0xfc1f07ff00000000, 0x101f060200000000, 0x0, // Vector Count Trailing Zeros Doubleword VX-form (vctzd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCTZH, 0xfc1f07ff00000000, 0x101d060200000000, 0x0, // Vector Count Trailing Zeros Halfword VX-form (vctzh VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCTZLSBB, 0xfc1f07ff00000000, 0x1001060200000000, 0x0, // Vector Count Trailing Zero Least-Significant Bits Byte VX-form (vctzlsbb RT,VRB)
		[6]*argField{ap_Reg_6_10, ap_VecReg_16_20}},
	{VCTZW, 0xfc1f07ff00000000, 0x101e060200000000, 0x0, // Vector Count Trailing Zeros Word VX-form (vctzw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTRACTD, 0xfc0007ff00000000, 0x100002cd00000000, 0x10000000000000, // Vector Extract Doubleword to VSR using immediate-specified index VX-form (vextractd VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VEXTRACTUB, 0xfc0007ff00000000, 0x1000020d00000000, 0x10000000000000, // Vector Extract Unsigned Byte to VSR using immediate-specified index VX-form (vextractub VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VEXTRACTUH, 0xfc0007ff00000000, 0x1000024d00000000, 0x10000000000000, // Vector Extract Unsigned Halfword to VSR using immediate-specified index VX-form (vextractuh VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VEXTRACTUW, 0xfc0007ff00000000, 0x1000028d00000000, 0x10000000000000, // Vector Extract Unsigned Word to VSR using immediate-specified index VX-form (vextractuw VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VEXTSB2D, 0xfc1f07ff00000000, 0x1018060200000000, 0x0, // Vector Extend Sign Byte To Doubleword VX-form (vextsb2d VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTSB2W, 0xfc1f07ff00000000, 0x1010060200000000, 0x0, // Vector Extend Sign Byte To Word VX-form (vextsb2w VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTSH2D, 0xfc1f07ff00000000, 0x1019060200000000, 0x0, // Vector Extend Sign Halfword To Doubleword VX-form (vextsh2d VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTSH2W, 0xfc1f07ff00000000, 0x1011060200000000, 0x0, // Vector Extend Sign Halfword To Word VX-form (vextsh2w VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTSW2D, 0xfc1f07ff00000000, 0x101a060200000000, 0x0, // Vector Extend Sign Word To Doubleword VX-form (vextsw2d VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VEXTUBLX, 0xfc0007ff00000000, 0x1000060d00000000, 0x0, // Vector Extract Unsigned Byte to GPR using GPR-specified Left-Index VX-form (vextublx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VEXTUBRX, 0xfc0007ff00000000, 0x1000070d00000000, 0x0, // Vector Extract Unsigned Byte to GPR using GPR-specified Right-Index VX-form (vextubrx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VEXTUHLX, 0xfc0007ff00000000, 0x1000064d00000000, 0x0, // Vector Extract Unsigned Halfword to GPR using GPR-specified Left-Index VX-form (vextuhlx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VEXTUHRX, 0xfc0007ff00000000, 0x1000074d00000000, 0x0, // Vector Extract Unsigned Halfword to GPR using GPR-specified Right-Index VX-form (vextuhrx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VEXTUWLX, 0xfc0007ff00000000, 0x1000068d00000000, 0x0, // Vector Extract Unsigned Word to GPR using GPR-specified Left-Index VX-form (vextuwlx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VEXTUWRX, 0xfc0007ff00000000, 0x1000078d00000000, 0x0, // Vector Extract Unsigned Word to GPR using GPR-specified Right-Index VX-form (vextuwrx RT,RA,VRB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_VecReg_16_20}},
	{VINSERTB, 0xfc0007ff00000000, 0x1000030d00000000, 0x10000000000000, // Vector Insert Byte from VSR using immediate-specified index VX-form (vinsertb VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VINSERTD, 0xfc0007ff00000000, 0x100003cd00000000, 0x10000000000000, // Vector Insert Doubleword from VSR using immediate-specified index VX-form (vinsertd VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VINSERTH, 0xfc0007ff00000000, 0x1000034d00000000, 0x10000000000000, // Vector Insert Halfword from VSR using immediate-specified index VX-form (vinserth VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VINSERTW, 0xfc0007ff00000000, 0x1000038d00000000, 0x10000000000000, // Vector Insert Word from VSR using immediate-specified index VX-form (vinsertw VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VMUL10CUQ, 0xfc0007ff00000000, 0x1000000100000000, 0xf80000000000, // Vector Multiply-by-10 & write Carry-out Unsigned Quadword VX-form (vmul10cuq VRT,VRA)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15}},
	{VMUL10ECUQ, 0xfc0007ff00000000, 0x1000004100000000, 0x0, // Vector Multiply-by-10 Extended & write Carry-out Unsigned Quadword VX-form (vmul10ecuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMUL10EUQ, 0xfc0007ff00000000, 0x1000024100000000, 0x0, // Vector Multiply-by-10 Extended Unsigned Quadword VX-form (vmul10euq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMUL10UQ, 0xfc0007ff00000000, 0x1000020100000000, 0xf80000000000, // Vector Multiply-by-10 Unsigned Quadword VX-form (vmul10uq VRT,VRA)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15}},
	{VNEGD, 0xfc1f07ff00000000, 0x1007060200000000, 0x0, // Vector Negate Doubleword VX-form (vnegd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VNEGW, 0xfc1f07ff00000000, 0x1006060200000000, 0x0, // Vector Negate Word VX-form (vnegw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPERMR, 0xfc00003f00000000, 0x1000003b00000000, 0x0, // Vector Permute Right-indexed VA-form (vpermr VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VPRTYBD, 0xfc1f07ff00000000, 0x1009060200000000, 0x0, // Vector Parity Byte Doubleword VX-form (vprtybd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPRTYBQ, 0xfc1f07ff00000000, 0x100a060200000000, 0x0, // Vector Parity Byte Quadword VX-form (vprtybq VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPRTYBW, 0xfc1f07ff00000000, 0x1008060200000000, 0x0, // Vector Parity Byte Word VX-form (vprtybw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRLDMI, 0xfc0007ff00000000, 0x100000c500000000, 0x0, // Vector Rotate Left Doubleword then Mask Insert VX-form (vrldmi VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLDNM, 0xfc0007ff00000000, 0x100001c500000000, 0x0, // Vector Rotate Left Doubleword then AND with Mask VX-form (vrldnm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLWMI, 0xfc0007ff00000000, 0x1000008500000000, 0x0, // Vector Rotate Left Word then Mask Insert VX-form (vrlwmi VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLWNM, 0xfc0007ff00000000, 0x1000018500000000, 0x0, // Vector Rotate Left Word then AND with Mask VX-form (vrlwnm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLV, 0xfc0007ff00000000, 0x1000074400000000, 0x0, // Vector Shift Left Variable VX-form (vslv VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRV, 0xfc0007ff00000000, 0x1000070400000000, 0x0, // Vector Shift Right Variable VX-form (vsrv VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{WAIT, 0xfc0007fe00000000, 0x7c00003c00000000, 0x9cf80100000000, // Wait X-form (wait WC,PL)
		[6]*argField{ap_ImmUnsigned_9_10, ap_ImmUnsigned_14_15}},
	{XSABSQP, 0xfc1f07fe00000000, 0xfc00064800000000, 0x100000000, // VSX Scalar Absolute Quad-Precision X-form (xsabsqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSADDQP, 0xfc0007ff00000000, 0xfc00000800000000, 0x0, // VSX Scalar Add Quad-Precision [using round to Odd] X-form (xsaddqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSADDQPO, 0xfc0007ff00000000, 0xfc00000900000000, 0x0, // VSX Scalar Add Quad-Precision [using round to Odd] X-form (xsaddqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCMPEQDP, 0xfc0007f800000000, 0xf000001800000000, 0x0, // VSX Scalar Compare Equal Double-Precision XX3-form (xscmpeqdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPEXPDP, 0xfc0007f800000000, 0xf00001d800000000, 0x60000100000000, // VSX Scalar Compare Exponents Double-Precision XX3-form (xscmpexpdp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPEXPQP, 0xfc0007fe00000000, 0xfc00014800000000, 0x60000100000000, // VSX Scalar Compare Exponents Quad-Precision X-form (xscmpexpqp BF,VRA,VRB)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCMPGEDP, 0xfc0007f800000000, 0xf000009800000000, 0x0, // VSX Scalar Compare Greater Than or Equal Double-Precision XX3-form (xscmpgedp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPGTDP, 0xfc0007f800000000, 0xf000005800000000, 0x0, // VSX Scalar Compare Greater Than Double-Precision XX3-form (xscmpgtdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPOQP, 0xfc0007fe00000000, 0xfc00010800000000, 0x60000100000000, // VSX Scalar Compare Ordered Quad-Precision X-form (xscmpoqp BF,VRA,VRB)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCMPUQP, 0xfc0007fe00000000, 0xfc00050800000000, 0x60000100000000, // VSX Scalar Compare Unordered Quad-Precision X-form (xscmpuqp BF,VRA,VRB)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCPSGNQP, 0xfc0007fe00000000, 0xfc0000c800000000, 0x100000000, // VSX Scalar Copy Sign Quad-Precision X-form (xscpsgnqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSCVDPHP, 0xfc1f07fc00000000, 0xf011056c00000000, 0x0, // VSX Scalar Convert with round Double-Precision to Half-Precision format XX2-form (xscvdphp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVDPQP, 0xfc1f07fe00000000, 0xfc16068800000000, 0x100000000, // VSX Scalar Convert Double-Precision to Quad-Precision format X-form (xscvdpqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVHPDP, 0xfc1f07fc00000000, 0xf010056c00000000, 0x0, // VSX Scalar Convert Half-Precision to Double-Precision format XX2-form (xscvhpdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVQPDP, 0xfc1f07ff00000000, 0xfc14068800000000, 0x0, // VSX Scalar Convert with round Quad-Precision to Double-Precision format [using round to Odd] X-form (xscvqpdp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPDPO, 0xfc1f07ff00000000, 0xfc14068900000000, 0x0, // VSX Scalar Convert with round Quad-Precision to Double-Precision format [using round to Odd] X-form (xscvqpdpo VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPSDZ, 0xfc1f07fe00000000, 0xfc19068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Signed Doubleword format X-form (xscvqpsdz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPSWZ, 0xfc1f07fe00000000, 0xfc09068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Signed Word format X-form (xscvqpswz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPUDZ, 0xfc1f07fe00000000, 0xfc11068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Unsigned Doubleword format X-form (xscvqpudz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVQPUWZ, 0xfc1f07fe00000000, 0xfc01068800000000, 0x100000000, // VSX Scalar Convert with round to zero Quad-Precision to Unsigned Word format X-form (xscvqpuwz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVSDQP, 0xfc1f07fe00000000, 0xfc0a068800000000, 0x100000000, // VSX Scalar Convert Signed Doubleword to Quad-Precision format X-form (xscvsdqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSCVUDQP, 0xfc1f07fe00000000, 0xfc02068800000000, 0x100000000, // VSX Scalar Convert Unsigned Doubleword to Quad-Precision format X-form (xscvudqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSDIVQP, 0xfc0007ff00000000, 0xfc00044800000000, 0x0, // VSX Scalar Divide Quad-Precision [using round to Odd] X-form (xsdivqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSDIVQPO, 0xfc0007ff00000000, 0xfc00044900000000, 0x0, // VSX Scalar Divide Quad-Precision [using round to Odd] X-form (xsdivqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSIEXPDP, 0xfc0007fe00000000, 0xf000072c00000000, 0x0, // VSX Scalar Insert Exponent Double-Precision X-form (xsiexpdp XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{XSIEXPQP, 0xfc0007fe00000000, 0xfc0006c800000000, 0x100000000, // VSX Scalar Insert Exponent Quad-Precision X-form (xsiexpqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMADDQP, 0xfc0007ff00000000, 0xfc00030800000000, 0x0, // VSX Scalar Multiply-Add Quad-Precision [using round to Odd] X-form (xsmaddqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMADDQPO, 0xfc0007ff00000000, 0xfc00030900000000, 0x0, // VSX Scalar Multiply-Add Quad-Precision [using round to Odd] X-form (xsmaddqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMAXCDP, 0xfc0007f800000000, 0xf000040000000000, 0x0, // VSX Scalar Maximum Type-C Double-Precision XX3-form (xsmaxcdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMAXJDP, 0xfc0007f800000000, 0xf000048000000000, 0x0, // VSX Scalar Maximum Type-J Double-Precision XX3-form (xsmaxjdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMINCDP, 0xfc0007f800000000, 0xf000044000000000, 0x0, // VSX Scalar Minimum Type-C Double-Precision XX3-form (xsmincdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMINJDP, 0xfc0007f800000000, 0xf00004c000000000, 0x0, // VSX Scalar Minimum Type-J Double-Precision XX3-form (xsminjdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMSUBQP, 0xfc0007ff00000000, 0xfc00034800000000, 0x0, // VSX Scalar Multiply-Subtract Quad-Precision [using round to Odd] X-form (xsmsubqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMSUBQPO, 0xfc0007ff00000000, 0xfc00034900000000, 0x0, // VSX Scalar Multiply-Subtract Quad-Precision [using round to Odd] X-form (xsmsubqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMULQP, 0xfc0007ff00000000, 0xfc00004800000000, 0x0, // VSX Scalar Multiply Quad-Precision [using round to Odd] X-form (xsmulqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSMULQPO, 0xfc0007ff00000000, 0xfc00004900000000, 0x0, // VSX Scalar Multiply Quad-Precision [using round to Odd] X-form (xsmulqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSNABSQP, 0xfc1f07fe00000000, 0xfc08064800000000, 0x0, // VSX Scalar Negative Absolute Quad-Precision X-form (xsnabsqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSNEGQP, 0xfc1f07fe00000000, 0xfc10064800000000, 0x100000000, // VSX Scalar Negate Quad-Precision X-form (xsnegqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSNMADDQP, 0xfc0007ff00000000, 0xfc00038800000000, 0x0, // VSX Scalar Negative Multiply-Add Quad-Precision [using round to Odd] X-form (xsnmaddqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSNMADDQPO, 0xfc0007ff00000000, 0xfc00038900000000, 0x0, // VSX Scalar Negative Multiply-Add Quad-Precision [using round to Odd] X-form (xsnmaddqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSNMSUBQP, 0xfc0007ff00000000, 0xfc0003c800000000, 0x0, // VSX Scalar Negative Multiply-Subtract Quad-Precision [using round to Odd] X-form (xsnmsubqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSNMSUBQPO, 0xfc0007ff00000000, 0xfc0003c900000000, 0x0, // VSX Scalar Negative Multiply-Subtract Quad-Precision [using round to Odd] X-form (xsnmsubqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSRQPI, 0xfc0001ff00000000, 0xfc00000a00000000, 0x1e000000000000, // VSX Scalar Round to Quad-Precision Integer [with Inexact] Z23-form (xsrqpi R,VRT,VRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_21_22}},
	{XSRQPIX, 0xfc0001ff00000000, 0xfc00000b00000000, 0x1e000000000000, // VSX Scalar Round to Quad-Precision Integer [with Inexact] Z23-form (xsrqpix R,VRT,VRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_21_22}},
	{XSRQPXP, 0xfc0001fe00000000, 0xfc00004a00000000, 0x1e000100000000, // VSX Scalar Round Quad-Precision to Double-Extended Precision Z23-form (xsrqpxp R,VRT,VRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_21_22}},
	{XSSQRTQP, 0xfc1f07ff00000000, 0xfc1b064800000000, 0x0, // VSX Scalar Square Root Quad-Precision [using round to Odd] X-form (xssqrtqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSSQRTQPO, 0xfc1f07ff00000000, 0xfc1b064900000000, 0x0, // VSX Scalar Square Root Quad-Precision [using round to Odd] X-form (xssqrtqpo VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSSUBQP, 0xfc0007ff00000000, 0xfc00040800000000, 0x0, // VSX Scalar Subtract Quad-Precision [using round to Odd] X-form (xssubqp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSSUBQPO, 0xfc0007ff00000000, 0xfc00040900000000, 0x0, // VSX Scalar Subtract Quad-Precision [using round to Odd] X-form (xssubqpo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{XSTSTDCDP, 0xfc0007fc00000000, 0xf00005a800000000, 0x100000000, // VSX Scalar Test Data Class Double-Precision XX2-form (xststdcdp BF,XB,DCMX)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_9_15}},
	{XSTSTDCQP, 0xfc0007fe00000000, 0xfc00058800000000, 0x100000000, // VSX Scalar Test Data Class Quad-Precision X-form (xststdcqp BF,VRB,DCMX)
		[6]*argField{ap_CondRegField_6_8, ap_VecReg_16_20, ap_ImmUnsigned_9_15}},
	{XSTSTDCSP, 0xfc0007fc00000000, 0xf00004a800000000, 0x100000000, // VSX Scalar Test Data Class Single-Precision XX2-form (xststdcsp BF,XB,DCMX)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_9_15}},
	{XSXEXPDP, 0xfc1f07fc00000000, 0xf000056c00000000, 0x100000000, // VSX Scalar Extract Exponent Double-Precision XX2-form (xsxexpdp RT,XB)
		[6]*argField{ap_Reg_6_10, ap_VecSReg_30_30_16_20}},
	{XSXEXPQP, 0xfc1f07fe00000000, 0xfc02064800000000, 0x100000000, // VSX Scalar Extract Exponent Quad-Precision X-form (xsxexpqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSXSIGDP, 0xfc1f07fc00000000, 0xf001056c00000000, 0x100000000, // VSX Scalar Extract Significand Double-Precision XX2-form (xsxsigdp RT,XB)
		[6]*argField{ap_Reg_6_10, ap_VecSReg_30_30_16_20}},
	{XSXSIGQP, 0xfc1f07fe00000000, 0xfc12064800000000, 0x100000000, // VSX Scalar Extract Significand Quad-Precision X-form (xsxsigqp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XVCVHPSP, 0xfc1f07fc00000000, 0xf018076c00000000, 0x0, // VSX Vector Convert Half-Precision to Single-Precision format XX2-form (xvcvhpsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPHP, 0xfc1f07fc00000000, 0xf019076c00000000, 0x0, // VSX Vector Convert with round Single-Precision to Half-Precision format XX2-form (xvcvsphp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVIEXPDP, 0xfc0007f800000000, 0xf00007c000000000, 0x0, // VSX Vector Insert Exponent Double-Precision XX3-form (xviexpdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVIEXPSP, 0xfc0007f800000000, 0xf00006c000000000, 0x0, // VSX Vector Insert Exponent Single-Precision XX3-form (xviexpsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVTSTDCDP, 0xfc0007b800000000, 0xf00007a800000000, 0x0, // VSX Vector Test Data Class Double-Precision XX2-form (xvtstdcdp XT,XB,DCMX)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_25_25_29_29_11_15}},
	{XVTSTDCSP, 0xfc0007b800000000, 0xf00006a800000000, 0x0, // VSX Vector Test Data Class Single-Precision XX2-form (xvtstdcsp XT,XB,DCMX)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_25_25_29_29_11_15}},
	{XVXEXPDP, 0xfc1f07fc00000000, 0xf000076c00000000, 0x0, // VSX Vector Extract Exponent Double-Precision XX2-form (xvxexpdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVXEXPSP, 0xfc1f07fc00000000, 0xf008076c00000000, 0x0, // VSX Vector Extract Exponent Single-Precision XX2-form (xvxexpsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVXSIGDP, 0xfc1f07fc00000000, 0xf001076c00000000, 0x0, // VSX Vector Extract Significand Double-Precision XX2-form (xvxsigdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVXSIGSP, 0xfc1f07fc00000000, 0xf009076c00000000, 0x0, // VSX Vector Extract Significand Single-Precision XX2-form (xvxsigsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XXBRD, 0xfc1f07fc00000000, 0xf017076c00000000, 0x0, // VSX Vector Byte-Reverse Doubleword XX2-form (xxbrd XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XXBRH, 0xfc1f07fc00000000, 0xf007076c00000000, 0x0, // VSX Vector Byte-Reverse Halfword XX2-form (xxbrh XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XXBRQ, 0xfc1f07fc00000000, 0xf01f076c00000000, 0x0, // VSX Vector Byte-Reverse Quadword XX2-form (xxbrq XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XXBRW, 0xfc1f07fc00000000, 0xf00f076c00000000, 0x0, // VSX Vector Byte-Reverse Word XX2-form (xxbrw XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XXEXTRACTUW, 0xfc0007fc00000000, 0xf000029400000000, 0x10000000000000, // VSX Vector Extract Unsigned Word XX2-form (xxextractuw XT,XB,UIM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_12_15}},
	{XXINSERTW, 0xfc0007fc00000000, 0xf00002d400000000, 0x10000000000000, // VSX Vector Insert Word XX2-form (xxinsertw XT,XB,UIM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_12_15}},
	{XXPERM, 0xfc0007f800000000, 0xf00000d000000000, 0x0, // VSX Vector Permute XX3-form (xxperm XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXPERMR, 0xfc0007f800000000, 0xf00001d000000000, 0x0, // VSX Vector Permute Right-indexed XX3-form (xxpermr XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXSPLTIB, 0xfc1807fe00000000, 0xf00002d000000000, 0x0, // VSX Vector Splat Immediate Byte X-form (xxspltib XT,IMM8)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_ImmUnsigned_13_20}},
	{BCDADDCC, 0xfc0005ff00000000, 0x1000040100000000, 0x0, // Decimal Add Modulo VX-form (bcdadd. VRT,VRA,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCDSUBCC, 0xfc0005ff00000000, 0x1000044100000000, 0x0, // Decimal Subtract Modulo VX-form (bcdsub. VRT,VRA,VRB,PS)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_22}},
	{BCTAR, 0xfc0007ff00000000, 0x4c00046000000000, 0xe00000000000, // Branch Conditional to Branch Target Address Register XL-form (bctar BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{BCTARL, 0xfc0007ff00000000, 0x4c00046100000000, 0xe00000000000, // Branch Conditional to Branch Target Address Register XL-form (bctarl BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{CLRBHRB, 0xfc0007fe00000000, 0x7c00035c00000000, 0x3fff80100000000, // Clear BHRB X-form (clrbhrb)
		[6]*argField{}},
	{FMRGEW, 0xfc0007fe00000000, 0xfc00078c00000000, 0x100000000, // Floating Merge Even Word X-form (fmrgew FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FMRGOW, 0xfc0007fe00000000, 0xfc00068c00000000, 0x100000000, // Floating Merge Odd Word X-form (fmrgow FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{ICBT, 0xfc0007fe00000000, 0x7c00002c00000000, 0x200000100000000, // Instruction Cache Block Touch X-form (icbt CT, RA, RB)
		[6]*argField{ap_ImmUnsigned_7_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LQARX, 0xfc0007fe00000000, 0x7c00022800000000, 0x0, // Load Quadword And Reserve Indexed X-form (lqarx RTp,RA,RB,EH)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_31_31}},
	{LXSIWAX, 0xfc0007fe00000000, 0x7c00009800000000, 0x0, // Load VSX Scalar as Integer Word Algebraic Indexed X-form (lxsiwax XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXSIWZX, 0xfc0007fe00000000, 0x7c00001800000000, 0x0, // Load VSX Scalar as Integer Word & Zero Indexed X-form (lxsiwzx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXSSPX, 0xfc0007fe00000000, 0x7c00041800000000, 0x0, // Load VSX Scalar Single-Precision Indexed X-form (lxsspx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MFBHRBE, 0xfc0007fe00000000, 0x7c00025c00000000, 0x100000000, // Move From BHRB XFX-form (mfbhrbe RT,BHRBE)
		[6]*argField{ap_Reg_6_10, ap_ImmUnsigned_11_20}},
	{MFVSRD, 0xfc0007fe00000000, 0x7c00006600000000, 0xf80000000000, // Move From VSR Doubleword X-form (mfvsrd RA,XS)
		[6]*argField{ap_Reg_11_15, ap_VecSReg_31_31_6_10}},
	{MFVSRWZ, 0xfc0007fe00000000, 0x7c0000e600000000, 0xf80000000000, // Move From VSR Word and Zero X-form (mfvsrwz RA,XS)
		[6]*argField{ap_Reg_11_15, ap_VecSReg_31_31_6_10}},
	{MSGCLR, 0xfc0007fe00000000, 0x7c0001dc00000000, 0x3ff000100000000, // Message Clear X-form (msgclr RB)
		[6]*argField{ap_Reg_16_20}},
	{MSGCLRP, 0xfc0007fe00000000, 0x7c00015c00000000, 0x3ff000100000000, // Message Clear Privileged X-form (msgclrp RB)
		[6]*argField{ap_Reg_16_20}},
	{MSGSND, 0xfc0007fe00000000, 0x7c00019c00000000, 0x3ff000100000000, // Message Send X-form (msgsnd RB)
		[6]*argField{ap_Reg_16_20}},
	{MSGSNDP, 0xfc0007fe00000000, 0x7c00011c00000000, 0x3ff000100000000, // Message Send Privileged X-form (msgsndp RB)
		[6]*argField{ap_Reg_16_20}},
	{MTVSRD, 0xfc0007fe00000000, 0x7c00016600000000, 0xf80000000000, // Move To VSR Doubleword X-form (mtvsrd XT,RA)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15}},
	{MTVSRWA, 0xfc0007fe00000000, 0x7c0001a600000000, 0xf80000000000, // Move To VSR Word Algebraic X-form (mtvsrwa XT,RA)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15}},
	{MTVSRWZ, 0xfc0007fe00000000, 0x7c0001e600000000, 0xf80000000000, // Move To VSR Word and Zero X-form (mtvsrwz XT,RA)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15}},
	{RFEBB, 0xfc0007fe00000000, 0x4c00012400000000, 0x3fff00100000000, // Return from Event Based Branch XL-form (rfebb S)
		[6]*argField{ap_ImmUnsigned_20_20}},
	{STQCXCC, 0xfc0007ff00000000, 0x7c00016d00000000, 0x0, // Store Quadword Conditional Indexed X-form (stqcx. RSp,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXSIWX, 0xfc0007fe00000000, 0x7c00011800000000, 0x0, // Store VSX Scalar as Integer Word Indexed X-form (stxsiwx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXSSPX, 0xfc0007fe00000000, 0x7c00051800000000, 0x0, // Store VSX Scalar Single-Precision Indexed X-form (stxsspx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{VADDCUQ, 0xfc0007ff00000000, 0x1000014000000000, 0x0, // Vector Add & write Carry Unsigned Quadword VX-form (vaddcuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDECUQ, 0xfc00003f00000000, 0x1000003d00000000, 0x0, // Vector Add Extended & write Carry Unsigned Quadword VA-form (vaddecuq VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VADDEUQM, 0xfc00003f00000000, 0x1000003c00000000, 0x0, // Vector Add Extended Unsigned Quadword Modulo VA-form (vaddeuqm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VADDUDM, 0xfc0007ff00000000, 0x100000c000000000, 0x0, // Vector Add Unsigned Doubleword Modulo VX-form (vaddudm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUQM, 0xfc0007ff00000000, 0x1000010000000000, 0x0, // Vector Add Unsigned Quadword Modulo VX-form (vadduqm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VBPERMQ, 0xfc0007ff00000000, 0x1000054c00000000, 0x0, // Vector Bit Permute Quadword VX-form (vbpermq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCIPHER, 0xfc0007ff00000000, 0x1000050800000000, 0x0, // Vector AES Cipher VX-form (vcipher VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCIPHERLAST, 0xfc0007ff00000000, 0x1000050900000000, 0x0, // Vector AES Cipher Last VX-form (vcipherlast VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCLZB, 0xfc0007ff00000000, 0x1000070200000000, 0x1f000000000000, // Vector Count Leading Zeros Byte VX-form (vclzb VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCLZD, 0xfc0007ff00000000, 0x100007c200000000, 0x1f000000000000, // Vector Count Leading Zeros Doubleword VX-form (vclzd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCLZH, 0xfc0007ff00000000, 0x1000074200000000, 0x1f000000000000, // Vector Count Leading Zeros Halfword VX-form (vclzh VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCLZW, 0xfc0007ff00000000, 0x1000078200000000, 0x1f000000000000, // Vector Count Leading Zeros Word VX-form (vclzw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VCMPEQUD, 0xfc0007ff00000000, 0x100000c700000000, 0x0, // Vector Compare Equal Unsigned Doubleword VC-form (vcmpequd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUDCC, 0xfc0007ff00000000, 0x100004c700000000, 0x0, // Vector Compare Equal Unsigned Doubleword VC-form (vcmpequd. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSD, 0xfc0007ff00000000, 0x100003c700000000, 0x0, // Vector Compare Greater Than Signed Doubleword VC-form (vcmpgtsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSDCC, 0xfc0007ff00000000, 0x100007c700000000, 0x0, // Vector Compare Greater Than Signed Doubleword VC-form (vcmpgtsd. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUD, 0xfc0007ff00000000, 0x100002c700000000, 0x0, // Vector Compare Greater Than Unsigned Doubleword VC-form (vcmpgtud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUDCC, 0xfc0007ff00000000, 0x100006c700000000, 0x0, // Vector Compare Greater Than Unsigned Doubleword VC-form (vcmpgtud. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VEQV, 0xfc0007ff00000000, 0x1000068400000000, 0x0, // Vector Logical Equivalence VX-form (veqv VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VGBBD, 0xfc0007ff00000000, 0x1000050c00000000, 0x1f000000000000, // Vector Gather Bits by Bytes by Doubleword VX-form (vgbbd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VMAXSD, 0xfc0007ff00000000, 0x100001c200000000, 0x0, // Vector Maximum Signed Doubleword VX-form (vmaxsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXUD, 0xfc0007ff00000000, 0x100000c200000000, 0x0, // Vector Maximum Unsigned Doubleword VX-form (vmaxud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINSD, 0xfc0007ff00000000, 0x100003c200000000, 0x0, // Vector Minimum Signed Doubleword VX-form (vminsd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINUD, 0xfc0007ff00000000, 0x100002c200000000, 0x0, // Vector Minimum Unsigned Doubleword VX-form (vminud VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGEW, 0xfc0007ff00000000, 0x1000078c00000000, 0x0, // Vector Merge Even Word VX-form (vmrgew VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGOW, 0xfc0007ff00000000, 0x1000068c00000000, 0x0, // Vector Merge Odd Word VX-form (vmrgow VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULESW, 0xfc0007ff00000000, 0x1000038800000000, 0x0, // Vector Multiply Even Signed Word VX-form (vmulesw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULEUW, 0xfc0007ff00000000, 0x1000028800000000, 0x0, // Vector Multiply Even Unsigned Word VX-form (vmuleuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOSW, 0xfc0007ff00000000, 0x1000018800000000, 0x0, // Vector Multiply Odd Signed Word VX-form (vmulosw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOUW, 0xfc0007ff00000000, 0x1000008800000000, 0x0, // Vector Multiply Odd Unsigned Word VX-form (vmulouw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULUWM, 0xfc0007ff00000000, 0x1000008900000000, 0x0, // Vector Multiply Unsigned Word Modulo VX-form (vmuluwm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VNAND, 0xfc0007ff00000000, 0x1000058400000000, 0x0, // Vector Logical NAND VX-form (vnand VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VNCIPHER, 0xfc0007ff00000000, 0x1000054800000000, 0x0, // Vector AES Inverse Cipher VX-form (vncipher VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VNCIPHERLAST, 0xfc0007ff00000000, 0x1000054900000000, 0x0, // Vector AES Inverse Cipher Last VX-form (vncipherlast VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VORC, 0xfc0007ff00000000, 0x1000054400000000, 0x0, // Vector Logical OR with Complement VX-form (vorc VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPERMXOR, 0xfc00003f00000000, 0x1000002d00000000, 0x0, // Vector Permute & Exclusive-OR VA-form (vpermxor VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VPKSDSS, 0xfc0007ff00000000, 0x100005ce00000000, 0x0, // Vector Pack Signed Doubleword Signed Saturate VX-form (vpksdss VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKSDUS, 0xfc0007ff00000000, 0x1000054e00000000, 0x0, // Vector Pack Signed Doubleword Unsigned Saturate VX-form (vpksdus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUDUM, 0xfc0007ff00000000, 0x1000044e00000000, 0x0, // Vector Pack Unsigned Doubleword Unsigned Modulo VX-form (vpkudum VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUDUS, 0xfc0007ff00000000, 0x100004ce00000000, 0x0, // Vector Pack Unsigned Doubleword Unsigned Saturate VX-form (vpkudus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPMSUMB, 0xfc0007ff00000000, 0x1000040800000000, 0x0, // Vector Polynomial Multiply-Sum Byte VX-form (vpmsumb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPMSUMD, 0xfc0007ff00000000, 0x100004c800000000, 0x0, // Vector Polynomial Multiply-Sum Doubleword VX-form (vpmsumd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPMSUMH, 0xfc0007ff00000000, 0x1000044800000000, 0x0, // Vector Polynomial Multiply-Sum Halfword VX-form (vpmsumh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPMSUMW, 0xfc0007ff00000000, 0x1000048800000000, 0x0, // Vector Polynomial Multiply-Sum Word VX-form (vpmsumw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPOPCNTB, 0xfc0007ff00000000, 0x1000070300000000, 0x1f000000000000, // Vector Population Count Byte VX-form (vpopcntb VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPOPCNTD, 0xfc0007ff00000000, 0x100007c300000000, 0x1f000000000000, // Vector Population Count Doubleword VX-form (vpopcntd VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPOPCNTH, 0xfc0007ff00000000, 0x1000074300000000, 0x1f000000000000, // Vector Population Count Halfword VX-form (vpopcnth VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VPOPCNTW, 0xfc0007ff00000000, 0x1000078300000000, 0x1f000000000000, // Vector Population Count Word VX-form (vpopcntw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRLD, 0xfc0007ff00000000, 0x100000c400000000, 0x0, // Vector Rotate Left Doubleword VX-form (vrld VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSBOX, 0xfc0007ff00000000, 0x100005c800000000, 0xf80000000000, // Vector AES SubBytes VX-form (vsbox VRT,VRA)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15}},
	{VSHASIGMAD, 0xfc0007ff00000000, 0x100006c200000000, 0x0, // Vector SHA-512 Sigma Doubleword VX-form (vshasigmad VRT,VRA,ST,SIX)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_ImmUnsigned_16_16, ap_ImmUnsigned_17_20}},
	{VSHASIGMAW, 0xfc0007ff00000000, 0x1000068200000000, 0x0, // Vector SHA-256 Sigma Word VX-form (vshasigmaw VRT,VRA,ST,SIX)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_ImmUnsigned_16_16, ap_ImmUnsigned_17_20}},
	{VSLD, 0xfc0007ff00000000, 0x100005c400000000, 0x0, // Vector Shift Left Doubleword VX-form (vsld VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRAD, 0xfc0007ff00000000, 0x100003c400000000, 0x0, // Vector Shift Right Algebraic Doubleword VX-form (vsrad VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRD, 0xfc0007ff00000000, 0x100006c400000000, 0x0, // Vector Shift Right Doubleword VX-form (vsrd VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBCUQ, 0xfc0007ff00000000, 0x1000054000000000, 0x0, // Vector Subtract & write Carry-out Unsigned Quadword VX-form (vsubcuq VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBECUQ, 0xfc00003f00000000, 0x1000003f00000000, 0x0, // Vector Subtract Extended & write Carry-out Unsigned Quadword VA-form (vsubecuq VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VSUBEUQM, 0xfc00003f00000000, 0x1000003e00000000, 0x0, // Vector Subtract Extended Unsigned Quadword Modulo VA-form (vsubeuqm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VSUBUDM, 0xfc0007ff00000000, 0x100004c000000000, 0x0, // Vector Subtract Unsigned Doubleword Modulo VX-form (vsubudm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUQM, 0xfc0007ff00000000, 0x1000050000000000, 0x0, // Vector Subtract Unsigned Quadword Modulo VX-form (vsubuqm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VUPKHSW, 0xfc0007ff00000000, 0x1000064e00000000, 0x1f000000000000, // Vector Unpack High Signed Word VX-form (vupkhsw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKLSW, 0xfc0007ff00000000, 0x100006ce00000000, 0x1f000000000000, // Vector Unpack Low Signed Word VX-form (vupklsw VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{XSADDSP, 0xfc0007f800000000, 0xf000000000000000, 0x0, // VSX Scalar Add Single-Precision XX3-form (xsaddsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCVDPSPN, 0xfc0007fc00000000, 0xf000042c00000000, 0x1f000000000000, // VSX Scalar Convert Scalar Single-Precision to Vector Single-Precision format Non-signalling XX2-form (xscvdpspn XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVSPDPN, 0xfc0007fc00000000, 0xf000052c00000000, 0x1f000000000000, // VSX Scalar Convert Single-Precision to Double-Precision format Non-signalling XX2-form (xscvspdpn XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVSXDSP, 0xfc0007fc00000000, 0xf00004e000000000, 0x1f000000000000, // VSX Scalar Convert with round Signed Doubleword to Single-Precision format XX2-form (xscvsxdsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVUXDSP, 0xfc0007fc00000000, 0xf00004a000000000, 0x1f000000000000, // VSX Scalar Convert with round Unsigned Doubleword to Single-Precision XX2-form (xscvuxdsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSDIVSP, 0xfc0007f800000000, 0xf00000c000000000, 0x0, // VSX Scalar Divide Single-Precision XX3-form (xsdivsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMADDASP, 0xfc0007f800000000, 0xf000000800000000, 0x0, // VSX Scalar Multiply-Add Type-A Single-Precision XX3-form (xsmaddasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMADDMSP, 0xfc0007f800000000, 0xf000004800000000, 0x0, // VSX Scalar Multiply-Add Type-M Single-Precision XX3-form (xsmaddmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMSUBASP, 0xfc0007f800000000, 0xf000008800000000, 0x0, // VSX Scalar Multiply-Subtract Type-A Single-Precision XX3-form (xsmsubasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMSUBMSP, 0xfc0007f800000000, 0xf00000c800000000, 0x0, // VSX Scalar Multiply-Subtract Type-M Single-Precision XX3-form (xsmsubmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMULSP, 0xfc0007f800000000, 0xf000008000000000, 0x0, // VSX Scalar Multiply Single-Precision XX3-form (xsmulsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMADDASP, 0xfc0007f800000000, 0xf000040800000000, 0x0, // VSX Scalar Negative Multiply-Add Type-A Single-Precision XX3-form (xsnmaddasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMADDMSP, 0xfc0007f800000000, 0xf000044800000000, 0x0, // VSX Scalar Negative Multiply-Add Type-M Single-Precision XX3-form (xsnmaddmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMSUBASP, 0xfc0007f800000000, 0xf000048800000000, 0x0, // VSX Scalar Negative Multiply-Subtract Type-A Single-Precision XX3-form (xsnmsubasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMSUBMSP, 0xfc0007f800000000, 0xf00004c800000000, 0x0, // VSX Scalar Negative Multiply-Subtract Type-M Single-Precision XX3-form (xsnmsubmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSRESP, 0xfc0007fc00000000, 0xf000006800000000, 0x1f000000000000, // VSX Scalar Reciprocal Estimate Single-Precision XX2-form (xsresp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRSP, 0xfc0007fc00000000, 0xf000046400000000, 0x1f000000000000, // VSX Scalar Round to Single-Precision XX2-form (xsrsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRSQRTESP, 0xfc0007fc00000000, 0xf000002800000000, 0x1f000000000000, // VSX Scalar Reciprocal Square Root Estimate Single-Precision XX2-form (xsrsqrtesp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSSQRTSP, 0xfc0007fc00000000, 0xf000002c00000000, 0x1f000000000000, // VSX Scalar Square Root Single-Precision XX2-form (xssqrtsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSSUBSP, 0xfc0007f800000000, 0xf000004000000000, 0x0, // VSX Scalar Subtract Single-Precision XX3-form (xssubsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLEQV, 0xfc0007f800000000, 0xf00005d000000000, 0x0, // VSX Vector Logical Equivalence XX3-form (xxleqv XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLNAND, 0xfc0007f800000000, 0xf000059000000000, 0x0, // VSX Vector Logical NAND XX3-form (xxlnand XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLORC, 0xfc0007f800000000, 0xf000055000000000, 0x0, // VSX Vector Logical OR with Complement XX3-form (xxlorc XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{ADDG6S, 0xfc0003fe00000000, 0x7c00009400000000, 0x40100000000, // Add and Generate Sixes XO-form (addg6s RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{BPERMD, 0xfc0007fe00000000, 0x7c0001f800000000, 0x100000000, // Bit Permute Doubleword X-form (bpermd RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{CBCDTD, 0xfc0007fe00000000, 0x7c00027400000000, 0xf80100000000, // Convert Binary Coded Decimal To Declets X-form (cbcdtd RA, RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CDTBCD, 0xfc0007fe00000000, 0x7c00023400000000, 0xf80100000000, // Convert Declets To Binary Coded Decimal X-form (cdtbcd RA, RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{DCFFIX, 0xfc0007ff00000000, 0xec00064400000000, 0x1f000000000000, // DFP Convert From Fixed X-form (dcffix FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCFFIXCC, 0xfc0007ff00000000, 0xec00064500000000, 0x1f000000000000, // DFP Convert From Fixed X-form (dcffix. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DIVDE, 0xfc0007ff00000000, 0x7c00035200000000, 0x0, // Divide Doubleword Extended XO-form (divde RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDECC, 0xfc0007ff00000000, 0x7c00035300000000, 0x0, // Divide Doubleword Extended XO-form (divde. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEO, 0xfc0007ff00000000, 0x7c00075200000000, 0x0, // Divide Doubleword Extended XO-form (divdeo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEOCC, 0xfc0007ff00000000, 0x7c00075300000000, 0x0, // Divide Doubleword Extended XO-form (divdeo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEU, 0xfc0007ff00000000, 0x7c00031200000000, 0x0, // Divide Doubleword Extended Unsigned XO-form (divdeu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEUCC, 0xfc0007ff00000000, 0x7c00031300000000, 0x0, // Divide Doubleword Extended Unsigned XO-form (divdeu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEUO, 0xfc0007ff00000000, 0x7c00071200000000, 0x0, // Divide Doubleword Extended Unsigned XO-form (divdeuo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDEUOCC, 0xfc0007ff00000000, 0x7c00071300000000, 0x0, // Divide Doubleword Extended Unsigned XO-form (divdeuo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWE, 0xfc0007ff00000000, 0x7c00035600000000, 0x0, // Divide Word Extended XO-form (divwe RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWECC, 0xfc0007ff00000000, 0x7c00035700000000, 0x0, // Divide Word Extended XO-form (divwe. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEO, 0xfc0007ff00000000, 0x7c00075600000000, 0x0, // Divide Word Extended XO-form (divweo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEOCC, 0xfc0007ff00000000, 0x7c00075700000000, 0x0, // Divide Word Extended XO-form (divweo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEU, 0xfc0007ff00000000, 0x7c00031600000000, 0x0, // Divide Word Extended Unsigned XO-form (divweu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEUCC, 0xfc0007ff00000000, 0x7c00031700000000, 0x0, // Divide Word Extended Unsigned XO-form (divweu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEUO, 0xfc0007ff00000000, 0x7c00071600000000, 0x0, // Divide Word Extended Unsigned XO-form (divweuo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWEUOCC, 0xfc0007ff00000000, 0x7c00071700000000, 0x0, // Divide Word Extended Unsigned XO-form (divweuo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{FCFIDS, 0xfc0007ff00000000, 0xec00069c00000000, 0x1f000000000000, // Floating Convert with round Signed Doubleword to Single-Precision format X-form (fcfids FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDSCC, 0xfc0007ff00000000, 0xec00069d00000000, 0x1f000000000000, // Floating Convert with round Signed Doubleword to Single-Precision format X-form (fcfids. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDU, 0xfc0007ff00000000, 0xfc00079c00000000, 0x1f000000000000, // Floating Convert with round Unsigned Doubleword to Double-Precision format X-form (fcfidu FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDUCC, 0xfc0007ff00000000, 0xfc00079d00000000, 0x1f000000000000, // Floating Convert with round Unsigned Doubleword to Double-Precision format X-form (fcfidu. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDUS, 0xfc0007ff00000000, 0xec00079c00000000, 0x1f000000000000, // Floating Convert with round Unsigned Doubleword to Single-Precision format X-form (fcfidus FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDUSCC, 0xfc0007ff00000000, 0xec00079d00000000, 0x1f000000000000, // Floating Convert with round Unsigned Doubleword to Single-Precision format X-form (fcfidus. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDU, 0xfc0007ff00000000, 0xfc00075c00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Unsigned Doubleword format X-form (fctidu FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDUCC, 0xfc0007ff00000000, 0xfc00075d00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Unsigned Doubleword format X-form (fctidu. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDUZ, 0xfc0007ff00000000, 0xfc00075e00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Unsigned Doubleword format X-form (fctiduz FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDUZCC, 0xfc0007ff00000000, 0xfc00075f00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Unsigned Doubleword format X-form (fctiduz. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWU, 0xfc0007ff00000000, 0xfc00011c00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Unsigned Word format X-form (fctiwu FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWUCC, 0xfc0007ff00000000, 0xfc00011d00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Unsigned Word format X-form (fctiwu. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWUZ, 0xfc0007ff00000000, 0xfc00011e00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Unsigned Word format X-form (fctiwuz FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWUZCC, 0xfc0007ff00000000, 0xfc00011f00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Unsigned Word format X-form (fctiwuz. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FTDIV, 0xfc0007fe00000000, 0xfc00010000000000, 0x60000100000000, // Floating Test for software Divide X-form (ftdiv BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FTSQRT, 0xfc0007fe00000000, 0xfc00014000000000, 0x7f000100000000, // Floating Test for software Square Root X-form (ftsqrt BF,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_16_20}},
	{LBARX, 0xfc0007fe00000000, 0x7c00006800000000, 0x0, // Load Byte And Reserve Indexed X-form (lbarx RT,RA,RB,EH)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_31_31}},
	{LDBRX, 0xfc0007fe00000000, 0x7c00042800000000, 0x100000000, // Load Doubleword Byte-Reverse Indexed X-form (ldbrx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFIWZX, 0xfc0007fe00000000, 0x7c0006ee00000000, 0x100000000, // Load Floating-Point as Integer Word & Zero Indexed X-form (lfiwzx FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHARX, 0xfc0007fe00000000, 0x7c0000e800000000, 0x0, // Load Halfword And Reserve Indexed Xform (lharx RT,RA,RB,EH)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_31_31}},
	{LXSDX, 0xfc0007fe00000000, 0x7c00049800000000, 0x0, // Load VSX Scalar Doubleword Indexed X-form (lxsdx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVD2X, 0xfc0007fe00000000, 0x7c00069800000000, 0x0, // Load VSX Vector Doubleword*2 Indexed X-form (lxvd2x XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVDSX, 0xfc0007fe00000000, 0x7c00029800000000, 0x0, // Load VSX Vector Doubleword & Splat Indexed X-form (lxvdsx XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LXVW4X, 0xfc0007fe00000000, 0x7c00061800000000, 0x0, // Load VSX Vector Word*4 Indexed X-form (lxvw4x XT,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{POPCNTD, 0xfc0007fe00000000, 0x7c0003f400000000, 0xf80100000000, // Population Count Doubleword X-form (popcntd RA, RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{POPCNTW, 0xfc0007fe00000000, 0x7c0002f400000000, 0xf80100000000, // Population Count Words X-form (popcntw RA, RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{STBCXCC, 0xfc0007ff00000000, 0x7c00056d00000000, 0x0, // Store Byte Conditional Indexed X-form (stbcx. RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STDBRX, 0xfc0007fe00000000, 0x7c00052800000000, 0x100000000, // Store Doubleword Byte-Reverse Indexed X-form (stdbrx RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STHCXCC, 0xfc0007ff00000000, 0x7c0005ad00000000, 0x0, // Store Halfword Conditional Indexed X-form (sthcx. RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXSDX, 0xfc0007fe00000000, 0x7c00059800000000, 0x0, // Store VSX Scalar Doubleword Indexed X-form (stxsdx XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVD2X, 0xfc0007fe00000000, 0x7c00079800000000, 0x0, // Store VSX Vector Doubleword*2 Indexed X-form (stxvd2x XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STXVW4X, 0xfc0007fe00000000, 0x7c00071800000000, 0x0, // Store VSX Vector Word*4 Indexed X-form (stxvw4x XS,RA,RB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{XSABSDP, 0xfc0007fc00000000, 0xf000056400000000, 0x1f000000000000, // VSX Scalar Absolute Double-Precision XX2-form (xsabsdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSADDDP, 0xfc0007f800000000, 0xf000010000000000, 0x0, // VSX Scalar Add Double-Precision XX3-form (xsadddp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPODP, 0xfc0007f800000000, 0xf000015800000000, 0x60000100000000, // VSX Scalar Compare Ordered Double-Precision XX3-form (xscmpodp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCMPUDP, 0xfc0007f800000000, 0xf000011800000000, 0x60000100000000, // VSX Scalar Compare Unordered Double-Precision XX3-form (xscmpudp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCPSGNDP, 0xfc0007f800000000, 0xf000058000000000, 0x0, // VSX Scalar Copy Sign Double-Precision XX3-form (xscpsgndp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSCVDPSP, 0xfc0007fc00000000, 0xf000042400000000, 0x1f000000000000, // VSX Scalar Convert with round Double-Precision to Single-Precision format XX2-form (xscvdpsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVDPSXDS, 0xfc0007fc00000000, 0xf000056000000000, 0x1f000000000000, // VSX Scalar Convert with round to zero Double-Precision to Signed Doubleword format XX2-form (xscvdpsxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVDPSXWS, 0xfc0007fc00000000, 0xf000016000000000, 0x1f000000000000, // VSX Scalar Convert with round to zero Double-Precision to Signed Word format XX2-form (xscvdpsxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVDPUXDS, 0xfc0007fc00000000, 0xf000052000000000, 0x1f000000000000, // VSX Scalar Convert with round to zero Double-Precision to Unsigned Doubleword format XX2-form (xscvdpuxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVDPUXWS, 0xfc0007fc00000000, 0xf000012000000000, 0x1f000000000000, // VSX Scalar Convert with round to zero Double-Precision to Unsigned Word format XX2-form (xscvdpuxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVSPDP, 0xfc0007fc00000000, 0xf000052400000000, 0x1f000000000000, // VSX Scalar Convert Single-Precision to Double-Precision format XX2-form (xscvspdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVSXDDP, 0xfc0007fc00000000, 0xf00005e000000000, 0x1f000000000000, // VSX Scalar Convert with round Signed Doubleword to Double-Precision format XX2-form (xscvsxddp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSCVUXDDP, 0xfc0007fc00000000, 0xf00005a000000000, 0x1f000000000000, // VSX Scalar Convert with round Unsigned Doubleword to Double-Precision format XX2-form (xscvuxddp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSDIVD
```