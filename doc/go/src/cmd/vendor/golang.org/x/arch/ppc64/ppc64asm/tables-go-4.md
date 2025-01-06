Response:
这段代码是 Go 语言实现的 PowerPC 64 位架构（ppc64）的指令集解析器的一部分，具体来说，它是用于解析和生成 PowerPC 汇编指令的表格。这个表格定义了 PowerPC 指令的编码、操作码、操作数类型等信息。以下是对其功能的详细分析：

### 1. **指令集定义**
   - 该文件定义了一系列 PowerPC 指令，包括它们的操作码、操作数类型、指令格式等。每个指令都通过一个结构体来表示，结构体中包含了指令的名称、操作码、操作数字段等信息。
   - 例如，`VMSUMUHM` 指令的定义如下：
     ```go
     {VMSUMUHM, 0xfc00003f00000000, 0x1000002600000000, 0x0, // Vector Multiply-Sum Unsigned Halfword Modulo VA-form (vmsumuhm VRT,VRA,VRB,VRC)
         [6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
     ```
     这里 `VMSUMUHM` 是指令的名称，`0xfc00003f00000000` 是操作码的掩码，`0x1000002600000000` 是操作码的值，`0x0` 是额外的标志位，`[6]*argField` 是指令的操作数字段。

### 2. **指令格式**
   - 每个指令都有一个特定的格式，例如 `VA-form`、`VX-form` 等。这些格式决定了指令的编码方式和操作数的排列方式。
   - 例如，`VMSUMUHM` 指令是 `VA-form`，表示它是一个向量算术指令，操作数包括向量寄存器 `VRT`、`VRA`、`VRB` 和 `VRC`。

### 3. **操作数类型**
   - 操作数类型通过 `argField` 结构体来表示，例如 `ap_VecReg_6_10` 表示一个向量寄存器，其字段位于指令的第 6 到第 10 位。
   - 其他常见的操作数类型包括立即数（`ap_ImmUnsigned`）、通用寄存器（`ap_Reg`）、浮点寄存器（`ap_FPReg`）等。

### 4. **指令功能**
   - 该文件定义的指令涵盖了 PowerPC 的多种功能，包括向量运算、浮点运算、整数运算、逻辑运算、分支跳转等。
   - 例如，`VMSUMUHM` 指令用于无符号半字（halfword）的向量乘加运算，`VADDUBM` 指令用于无符号字节（byte）的向量加法运算。

### 5. **指令编码**
   - 每个指令的操作码和操作数字段都通过位掩码和位偏移来定义。例如，`VMSUMUHM` 指令的操作码掩码是 `0xfc00003f00000000`，操作码值是 `0x1000002600000000`，表示该指令的操作码位于指令的高 32 位。

### 6. **指令解析**
   - 该表格用于指令解析器，解析器可以根据指令的编码和操作数字段来解析二进制指令，并将其转换为可读的汇编指令。
   - 例如，给定一个二进制指令，解析器可以通过查找该表格来确定该指令的名称、操作数类型等信息。

### 7. **指令生成**
   - 该表格也可以用于指令生成器，生成器可以根据汇编指令的操作码和操作数来生成对应的二进制指令。
   - 例如，给定一个汇编指令 `VMSUMUHM V1, V2, V3, V4`，生成器可以通过查找该表格来确定该指令的二进制编码。

### 8. **易错点**
   - **操作数字段的位偏移**：在定义指令时，操作数字段的位偏移必须准确，否则会导致指令解析或生成错误。例如，`ap_VecReg_6_10` 表示向量寄存器字段位于指令的第 6 到第 10 位，如果位偏移定义错误，可能会导致解析错误。
   - **指令格式的混淆**：不同的指令格式（如 `VA-form`、`VX-form` 等）有不同的编码方式，混淆指令格式会导致指令解析或生成错误。

### 9. **示例代码**
   假设我们有一个二进制指令 `0x1000002600000000`，我们可以通过查找该表格来解析该指令：
   ```go
   for _, inst := range instructions {
       if (binaryInstruction & inst.mask) == inst.opcode {
           fmt.Printf("Instruction: %s\n", inst.name)
           for _, arg := range inst.args {
               fmt.Printf("Operand: %s\n", arg)
           }
           break
       }
   }
   ```
   输出结果可能是：
   ```
   Instruction: VMSUMUHM
   Operand: VRT
   Operand: VRA
   Operand: VRB
   Operand: VRC
   ```

### 总结
该文件是 PowerPC 64 位架构指令集解析器的一部分，定义了指令的编码、操作数类型、指令格式等信息。它用于解析和生成 PowerPC 汇编指令，涵盖了向量运算、浮点运算、整数运算等多种功能。在使用时需要注意操作数字段的位偏移和指令格式的准确性。
Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共6部分，请归纳一下它的功能

"""
eld{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMSUMUHM, 0xfc00003f00000000, 0x1000002600000000, 0x0, // Vector Multiply-Sum Unsigned Halfword Modulo VA-form (vmsumuhm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMSUMUHS, 0xfc00003f00000000, 0x1000002700000000, 0x0, // Vector Multiply-Sum Unsigned Halfword Saturate VA-form (vmsumuhs VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMULESB, 0xfc0007ff00000000, 0x1000030800000000, 0x0, // Vector Multiply Even Signed Byte VX-form (vmulesb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULESH, 0xfc0007ff00000000, 0x1000034800000000, 0x0, // Vector Multiply Even Signed Halfword VX-form (vmulesh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULEUB, 0xfc0007ff00000000, 0x1000020800000000, 0x0, // Vector Multiply Even Unsigned Byte VX-form (vmuleub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULEUH, 0xfc0007ff00000000, 0x1000024800000000, 0x0, // Vector Multiply Even Unsigned Halfword VX-form (vmuleuh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOSB, 0xfc0007ff00000000, 0x1000010800000000, 0x0, // Vector Multiply Odd Signed Byte VX-form (vmulosb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOSH, 0xfc0007ff00000000, 0x1000014800000000, 0x0, // Vector Multiply Odd Signed Halfword VX-form (vmulosh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOUB, 0xfc0007ff00000000, 0x1000000800000000, 0x0, // Vector Multiply Odd Unsigned Byte VX-form (vmuloub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMULOUH, 0xfc0007ff00000000, 0x1000004800000000, 0x0, // Vector Multiply Odd Unsigned Halfword VX-form (vmulouh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VNMSUBFP, 0xfc00003f00000000, 0x1000002f00000000, 0x0, // Vector Negative Multiply-Subtract Floating-Point VA-form (vnmsubfp VRT,VRA,VRC,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_21_25, ap_VecReg_16_20}},
	{VNOR, 0xfc0007ff00000000, 0x1000050400000000, 0x0, // Vector Logical NOR VX-form (vnor VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VOR, 0xfc0007ff00000000, 0x1000048400000000, 0x0, // Vector Logical OR VX-form (vor VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPERM, 0xfc00003f00000000, 0x1000002b00000000, 0x0, // Vector Permute VA-form (vperm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VPKPX, 0xfc0007ff00000000, 0x1000030e00000000, 0x0, // Vector Pack Pixel VX-form (vpkpx VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKSHSS, 0xfc0007ff00000000, 0x1000018e00000000, 0x0, // Vector Pack Signed Halfword Signed Saturate VX-form (vpkshss VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKSHUS, 0xfc0007ff00000000, 0x1000010e00000000, 0x0, // Vector Pack Signed Halfword Unsigned Saturate VX-form (vpkshus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKSWSS, 0xfc0007ff00000000, 0x100001ce00000000, 0x0, // Vector Pack Signed Word Signed Saturate VX-form (vpkswss VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKSWUS, 0xfc0007ff00000000, 0x1000014e00000000, 0x0, // Vector Pack Signed Word Unsigned Saturate VX-form (vpkswus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUHUM, 0xfc0007ff00000000, 0x1000000e00000000, 0x0, // Vector Pack Unsigned Halfword Unsigned Modulo VX-form (vpkuhum VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUHUS, 0xfc0007ff00000000, 0x1000008e00000000, 0x0, // Vector Pack Unsigned Halfword Unsigned Saturate VX-form (vpkuhus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUWUM, 0xfc0007ff00000000, 0x1000004e00000000, 0x0, // Vector Pack Unsigned Word Unsigned Modulo VX-form (vpkuwum VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VPKUWUS, 0xfc0007ff00000000, 0x100000ce00000000, 0x0, // Vector Pack Unsigned Word Unsigned Saturate VX-form (vpkuwus VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VREFP, 0xfc0007ff00000000, 0x1000010a00000000, 0x1f000000000000, // Vector Reciprocal Estimate Floating-Point VX-form (vrefp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRFIM, 0xfc0007ff00000000, 0x100002ca00000000, 0x1f000000000000, // Vector Round to Floating-Point Integer toward -Infinity VX-form (vrfim VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRFIN, 0xfc0007ff00000000, 0x1000020a00000000, 0x1f000000000000, // Vector Round to Floating-Point Integer Nearest VX-form (vrfin VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRFIP, 0xfc0007ff00000000, 0x1000028a00000000, 0x1f000000000000, // Vector Round to Floating-Point Integer toward +Infinity VX-form (vrfip VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRFIZ, 0xfc0007ff00000000, 0x1000024a00000000, 0x1f000000000000, // Vector Round to Floating-Point Integer toward Zero VX-form (vrfiz VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VRLB, 0xfc0007ff00000000, 0x1000000400000000, 0x0, // Vector Rotate Left Byte VX-form (vrlb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLH, 0xfc0007ff00000000, 0x1000004400000000, 0x0, // Vector Rotate Left Halfword VX-form (vrlh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRLW, 0xfc0007ff00000000, 0x1000008400000000, 0x0, // Vector Rotate Left Word VX-form (vrlw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VRSQRTEFP, 0xfc0007ff00000000, 0x1000014a00000000, 0x1f000000000000, // Vector Reciprocal Square Root Estimate Floating-Point VX-form (vrsqrtefp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VSEL, 0xfc00003f00000000, 0x1000002a00000000, 0x0, // Vector Select VA-form (vsel VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VSL, 0xfc0007ff00000000, 0x100001c400000000, 0x0, // Vector Shift Left VX-form (vsl VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLB, 0xfc0007ff00000000, 0x1000010400000000, 0x0, // Vector Shift Left Byte VX-form (vslb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLDOI, 0xfc00003f00000000, 0x1000002c00000000, 0x40000000000, // Vector Shift Left Double by Octet Immediate VA-form (vsldoi VRT,VRA,VRB,SHB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_ImmUnsigned_22_25}},
	{VSLH, 0xfc0007ff00000000, 0x1000014400000000, 0x0, // Vector Shift Left Halfword VX-form (vslh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLO, 0xfc0007ff00000000, 0x1000040c00000000, 0x0, // Vector Shift Left by Octet VX-form (vslo VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSLW, 0xfc0007ff00000000, 0x1000018400000000, 0x0, // Vector Shift Left Word VX-form (vslw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSPLTB, 0xfc0007ff00000000, 0x1000020c00000000, 0x10000000000000, // Vector Splat Byte VX-form (vspltb VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_12_15}},
	{VSPLTH, 0xfc0007ff00000000, 0x1000024c00000000, 0x18000000000000, // Vector Splat Halfword VX-form (vsplth VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_13_15}},
	{VSPLTISB, 0xfc0007ff00000000, 0x1000030c00000000, 0xf80000000000, // Vector Splat Immediate Signed Byte VX-form (vspltisb VRT,SIM)
		[6]*argField{ap_VecReg_6_10, ap_ImmSigned_11_15}},
	{VSPLTISH, 0xfc0007ff00000000, 0x1000034c00000000, 0xf80000000000, // Vector Splat Immediate Signed Halfword VX-form (vspltish VRT,SIM)
		[6]*argField{ap_VecReg_6_10, ap_ImmSigned_11_15}},
	{VSPLTISW, 0xfc0007ff00000000, 0x1000038c00000000, 0xf80000000000, // Vector Splat Immediate Signed Word VX-form (vspltisw VRT,SIM)
		[6]*argField{ap_VecReg_6_10, ap_ImmSigned_11_15}},
	{VSPLTW, 0xfc0007ff00000000, 0x1000028c00000000, 0x1c000000000000, // Vector Splat Word VX-form (vspltw VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_14_15}},
	{VSR, 0xfc0007ff00000000, 0x100002c400000000, 0x0, // Vector Shift Right VX-form (vsr VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRAB, 0xfc0007ff00000000, 0x1000030400000000, 0x0, // Vector Shift Right Algebraic Byte VX-form (vsrab VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRAH, 0xfc0007ff00000000, 0x1000034400000000, 0x0, // Vector Shift Right Algebraic Halfword VX-form (vsrah VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRAW, 0xfc0007ff00000000, 0x1000038400000000, 0x0, // Vector Shift Right Algebraic Word VX-form (vsraw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRB, 0xfc0007ff00000000, 0x1000020400000000, 0x0, // Vector Shift Right Byte VX-form (vsrb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRH, 0xfc0007ff00000000, 0x1000024400000000, 0x0, // Vector Shift Right Halfword VX-form (vsrh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRO, 0xfc0007ff00000000, 0x1000044c00000000, 0x0, // Vector Shift Right by Octet VX-form (vsro VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSRW, 0xfc0007ff00000000, 0x1000028400000000, 0x0, // Vector Shift Right Word VX-form (vsrw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBCUW, 0xfc0007ff00000000, 0x1000058000000000, 0x0, // Vector Subtract & Write Carry-out Unsigned Word VX-form (vsubcuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBFP, 0xfc0007ff00000000, 0x1000004a00000000, 0x0, // Vector Subtract Floating-Point VX-form (vsubfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBSBS, 0xfc0007ff00000000, 0x1000070000000000, 0x0, // Vector Subtract Signed Byte Saturate VX-form (vsubsbs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBSHS, 0xfc0007ff00000000, 0x1000074000000000, 0x0, // Vector Subtract Signed Halfword Saturate VX-form (vsubshs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBSWS, 0xfc0007ff00000000, 0x1000078000000000, 0x0, // Vector Subtract Signed Word Saturate VX-form (vsubsws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUBM, 0xfc0007ff00000000, 0x1000040000000000, 0x0, // Vector Subtract Unsigned Byte Modulo VX-form (vsububm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUBS, 0xfc0007ff00000000, 0x1000060000000000, 0x0, // Vector Subtract Unsigned Byte Saturate VX-form (vsububs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUHM, 0xfc0007ff00000000, 0x1000044000000000, 0x0, // Vector Subtract Unsigned Halfword Modulo VX-form (vsubuhm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUHS, 0xfc0007ff00000000, 0x1000064000000000, 0x0, // Vector Subtract Unsigned Halfword Saturate VX-form (vsubuhs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUWM, 0xfc0007ff00000000, 0x1000048000000000, 0x0, // Vector Subtract Unsigned Word Modulo VX-form (vsubuwm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUBUWS, 0xfc0007ff00000000, 0x1000068000000000, 0x0, // Vector Subtract Unsigned Word Saturate VX-form (vsubuws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUM2SWS, 0xfc0007ff00000000, 0x1000068800000000, 0x0, // Vector Sum across Half Signed Word Saturate VX-form (vsum2sws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUM4SBS, 0xfc0007ff00000000, 0x1000070800000000, 0x0, // Vector Sum across Quarter Signed Byte Saturate VX-form (vsum4sbs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUM4SHS, 0xfc0007ff00000000, 0x1000064800000000, 0x0, // Vector Sum across Quarter Signed Halfword Saturate VX-form (vsum4shs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUM4UBS, 0xfc0007ff00000000, 0x1000060800000000, 0x0, // Vector Sum across Quarter Unsigned Byte Saturate VX-form (vsum4ubs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VSUMSWS, 0xfc0007ff00000000, 0x1000078800000000, 0x0, // Vector Sum across Signed Word Saturate VX-form (vsumsws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VUPKHPX, 0xfc0007ff00000000, 0x1000034e00000000, 0x1f000000000000, // Vector Unpack High Pixel VX-form (vupkhpx VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKHSB, 0xfc0007ff00000000, 0x1000020e00000000, 0x1f000000000000, // Vector Unpack High Signed Byte VX-form (vupkhsb VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKHSH, 0xfc0007ff00000000, 0x1000024e00000000, 0x1f000000000000, // Vector Unpack High Signed Halfword VX-form (vupkhsh VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKLPX, 0xfc0007ff00000000, 0x100003ce00000000, 0x1f000000000000, // Vector Unpack Low Pixel VX-form (vupklpx VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKLSB, 0xfc0007ff00000000, 0x1000028e00000000, 0x1f000000000000, // Vector Unpack Low Signed Byte VX-form (vupklsb VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VUPKLSH, 0xfc0007ff00000000, 0x100002ce00000000, 0x1f000000000000, // Vector Unpack Low Signed Halfword VX-form (vupklsh VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VXOR, 0xfc0007ff00000000, 0x100004c400000000, 0x0, // Vector Logical XOR VX-form (vxor VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{FRE, 0xfc00003f00000000, 0xfc00003000000000, 0x1f07c000000000, // Floating Reciprocal Estimate A-form (fre FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRECC, 0xfc00003f00000000, 0xfc00003100000000, 0x1f07c000000000, // Floating Reciprocal Estimate A-form (fre. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIM, 0xfc0007ff00000000, 0xfc0003d000000000, 0x1f000000000000, // Floating Round to Integer Minus X-form (frim FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIMCC, 0xfc0007ff00000000, 0xfc0003d100000000, 0x1f000000000000, // Floating Round to Integer Minus X-form (frim. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIN, 0xfc0007ff00000000, 0xfc00031000000000, 0x1f000000000000, // Floating Round to Integer Nearest X-form (frin FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRINCC, 0xfc0007ff00000000, 0xfc00031100000000, 0x1f000000000000, // Floating Round to Integer Nearest X-form (frin. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIP, 0xfc0007ff00000000, 0xfc00039000000000, 0x1f000000000000, // Floating Round to Integer Plus X-form (frip FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIPCC, 0xfc0007ff00000000, 0xfc00039100000000, 0x1f000000000000, // Floating Round to Integer Plus X-form (frip. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIZ, 0xfc0007ff00000000, 0xfc00035000000000, 0x1f000000000000, // Floating Round to Integer Toward Zero X-form (friz FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRIZCC, 0xfc0007ff00000000, 0xfc00035100000000, 0x1f000000000000, // Floating Round to Integer Toward Zero X-form (friz. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRSQRTES, 0xfc00003f00000000, 0xec00003400000000, 0x1f07c000000000, // Floating Reciprocal Square Root Estimate Single A-form (frsqrtes FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRSQRTESCC, 0xfc00003f00000000, 0xec00003500000000, 0x1f07c000000000, // Floating Reciprocal Square Root Estimate Single A-form (frsqrtes. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{HRFID, 0xfc0007fe00000000, 0x4c00022400000000, 0x3fff80100000000, // Return From Interrupt Doubleword Hypervisor XL-form (hrfid)
		[6]*argField{}},
	{POPCNTB, 0xfc0007fe00000000, 0x7c0000f400000000, 0xf80100000000, // Population Count Bytes X-form (popcntb RA, RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{MFOCRF, 0xfc1007fe00000000, 0x7c10002600000000, 0x80100000000, // Move From One Condition Register Field XFX-form (mfocrf RT,FXM)
		[6]*argField{ap_Reg_6_10, ap_ImmUnsigned_12_19}},
	{MTOCRF, 0xfc1007fe00000000, 0x7c10012000000000, 0x80100000000, // Move To One Condition Register Field XFX-form (mtocrf FXM,RS)
		[6]*argField{ap_ImmUnsigned_12_19, ap_Reg_6_10}},
	{SLBMFEE, 0xfc0007fe00000000, 0x7c00072600000000, 0x1e000100000000, // SLB Move From Entry ESID X-form (slbmfee RT,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_16_20}},
	{SLBMFEV, 0xfc0007fe00000000, 0x7c0006a600000000, 0x1e000100000000, // SLB Move From Entry VSID X-form (slbmfev RT,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_16_20}},
	{SLBMTE, 0xfc0007fe00000000, 0x7c00032400000000, 0x1f000100000000, // SLB Move To Entry X-form (slbmte RS,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_16_20}},
	{RFSCV, 0xfc0007fe00000000, 0x4c0000a400000000, 0x3fff80100000000, // Return From System Call Vectored XL-form (rfscv)
		[6]*argField{}},
	{SCV, 0xfc00000300000000, 0x4400000100000000, 0x3fff01c00000000, // System Call Vectored SC-form (scv LEV)
		[6]*argField{ap_ImmUnsigned_20_26}},
	{LQ, 0xfc00000000000000, 0xe000000000000000, 0xf00000000, // Load Quadword DQ-form (lq RTp,DQ(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_27_shift4, ap_Reg_11_15}},
	{STQ, 0xfc00000300000000, 0xf800000200000000, 0x0, // Store Quadword DS-form (stq RSp,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{CNTLZD, 0xfc0007ff00000000, 0x7c00007400000000, 0xf80000000000, // Count Leading Zeros Doubleword X-form (cntlzd RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CNTLZDCC, 0xfc0007ff00000000, 0x7c00007500000000, 0xf80000000000, // Count Leading Zeros Doubleword X-form (cntlzd. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{DCBF, 0xfc0007fe00000000, 0x7c0000ac00000000, 0x300000100000000, // Data Cache Block Flush X-form (dcbf RA,RB,L)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_8_10}},
	{DCBST, 0xfc0007fe00000000, 0x7c00006c00000000, 0x3e0000100000000, // Data Cache Block Store X-form (dcbst RA,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20}},
	{DCBT, 0xfc0007fe00000000, 0x7c00022c00000000, 0x100000000, // Data Cache Block Touch X-form (dcbt RA,RB,TH)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_6_10}},
	{DCBTST, 0xfc0007fe00000000, 0x7c0001ec00000000, 0x100000000, // Data Cache Block Touch for Store X-form (dcbtst RA,RB,TH)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_6_10}},
	{DIVD, 0xfc0007ff00000000, 0x7c0003d200000000, 0x0, // Divide Doubleword XO-form (divd RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDCC, 0xfc0007ff00000000, 0x7c0003d300000000, 0x0, // Divide Doubleword XO-form (divd. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDO, 0xfc0007ff00000000, 0x7c0007d200000000, 0x0, // Divide Doubleword XO-form (divdo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDOCC, 0xfc0007ff00000000, 0x7c0007d300000000, 0x0, // Divide Doubleword XO-form (divdo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDU, 0xfc0007ff00000000, 0x7c00039200000000, 0x0, // Divide Doubleword Unsigned XO-form (divdu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDUCC, 0xfc0007ff00000000, 0x7c00039300000000, 0x0, // Divide Doubleword Unsigned XO-form (divdu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDUO, 0xfc0007ff00000000, 0x7c00079200000000, 0x0, // Divide Doubleword Unsigned XO-form (divduo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVDUOCC, 0xfc0007ff00000000, 0x7c00079300000000, 0x0, // Divide Doubleword Unsigned XO-form (divduo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVW, 0xfc0007ff00000000, 0x7c0003d600000000, 0x0, // Divide Word XO-form (divw RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWCC, 0xfc0007ff00000000, 0x7c0003d700000000, 0x0, // Divide Word XO-form (divw. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWO, 0xfc0007ff00000000, 0x7c0007d600000000, 0x0, // Divide Word XO-form (divwo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWOCC, 0xfc0007ff00000000, 0x7c0007d700000000, 0x0, // Divide Word XO-form (divwo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWU, 0xfc0007ff00000000, 0x7c00039600000000, 0x0, // Divide Word Unsigned XO-form (divwu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWUCC, 0xfc0007ff00000000, 0x7c00039700000000, 0x0, // Divide Word Unsigned XO-form (divwu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWUO, 0xfc0007ff00000000, 0x7c00079600000000, 0x0, // Divide Word Unsigned XO-form (divwuo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{DIVWUOCC, 0xfc0007ff00000000, 0x7c00079700000000, 0x0, // Divide Word Unsigned XO-form (divwuo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{EIEIO, 0xfc0007fe00000000, 0x7c0006ac00000000, 0x3fff80100000000, // Enforce In-order Execution of I/O X-form (eieio)
		[6]*argField{}},
	{EXTSB, 0xfc0007ff00000000, 0x7c00077400000000, 0xf80000000000, // Extend Sign Byte X-form (extsb RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{EXTSBCC, 0xfc0007ff00000000, 0x7c00077500000000, 0xf80000000000, // Extend Sign Byte X-form (extsb. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{EXTSW, 0xfc0007ff00000000, 0x7c0007b400000000, 0xf80000000000, // Extend Sign Word X-form (extsw RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{EXTSWCC, 0xfc0007ff00000000, 0x7c0007b500000000, 0xf80000000000, // Extend Sign Word X-form (extsw. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{FADDS, 0xfc00003f00000000, 0xec00002a00000000, 0x7c000000000, // Floating Add Single A-form (fadds FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FADDSCC, 0xfc00003f00000000, 0xec00002b00000000, 0x7c000000000, // Floating Add Single A-form (fadds. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FCFID, 0xfc0007ff00000000, 0xfc00069c00000000, 0x1f000000000000, // Floating Convert with round Signed Doubleword to Double-Precision format X-form (fcfid FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCFIDCC, 0xfc0007ff00000000, 0xfc00069d00000000, 0x1f000000000000, // Floating Convert with round Signed Doubleword to Double-Precision format X-form (fcfid. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTID, 0xfc0007ff00000000, 0xfc00065c00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Signed Doubleword format X-form (fctid FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDCC, 0xfc0007ff00000000, 0xfc00065d00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Signed Doubleword format X-form (fctid. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDZ, 0xfc0007ff00000000, 0xfc00065e00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Signed Doubleword format X-form (fctidz FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIDZCC, 0xfc0007ff00000000, 0xfc00065f00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Signed Doubleword format X-form (fctidz. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FDIVS, 0xfc00003f00000000, 0xec00002400000000, 0x7c000000000, // Floating Divide Single A-form (fdivs FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FDIVSCC, 0xfc00003f00000000, 0xec00002500000000, 0x7c000000000, // Floating Divide Single A-form (fdivs. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FMADDS, 0xfc00003f00000000, 0xec00003a00000000, 0x0, // Floating Multiply-Add Single A-form (fmadds FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMADDSCC, 0xfc00003f00000000, 0xec00003b00000000, 0x0, // Floating Multiply-Add Single A-form (fmadds. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMSUBS, 0xfc00003f00000000, 0xec00003800000000, 0x0, // Floating Multiply-Subtract Single A-form (fmsubs FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMSUBSCC, 0xfc00003f00000000, 0xec00003900000000, 0x0, // Floating Multiply-Subtract Single A-form (fmsubs. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMULS, 0xfc00003f00000000, 0xec00003200000000, 0xf80000000000, // Floating Multiply Single A-form (fmuls FRT,FRA,FRC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25}},
	{FMULSCC, 0xfc00003f00000000, 0xec00003300000000, 0xf80000000000, // Floating Multiply Single A-form (fmuls. FRT,FRA,FRC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25}},
	{FNMADDS, 0xfc00003f00000000, 0xec00003e00000000, 0x0, // Floating Negative Multiply-Add Single A-form (fnmadds FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMADDSCC, 0xfc00003f00000000, 0xec00003f00000000, 0x0, // Floating Negative Multiply-Add Single A-form (fnmadds. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMSUBS, 0xfc00003f00000000, 0xec00003c00000000, 0x0, // Floating Negative Multiply-Subtract Single A-form (fnmsubs FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMSUBSCC, 0xfc00003f00000000, 0xec00003d00000000, 0x0, // Floating Negative Multiply-Subtract Single A-form (fnmsubs. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FRES, 0xfc00003f00000000, 0xec00003000000000, 0x1f07c000000000, // Floating Reciprocal Estimate Single A-form (fres FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRESCC, 0xfc00003f00000000, 0xec00003100000000, 0x1f07c000000000, // Floating Reciprocal Estimate Single A-form (fres. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRSQRTE, 0xfc00003f00000000, 0xfc00003400000000, 0x1f07c000000000, // Floating Reciprocal Square Root Estimate A-form (frsqrte FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRSQRTECC, 0xfc00003f00000000, 0xfc00003500000000, 0x1f07c000000000, // Floating Reciprocal Square Root Estimate A-form (frsqrte. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSEL, 0xfc00003f00000000, 0xfc00002e00000000, 0x0, // Floating Select A-form (fsel FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FSELCC, 0xfc00003f00000000, 0xfc00002f00000000, 0x0, // Floating Select A-form (fsel. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FSQRTS, 0xfc00003f00000000, 0xec00002c00000000, 0x1f07c000000000, // Floating Square Root Single A-form (fsqrts FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSQRTSCC, 0xfc00003f00000000, 0xec00002d00000000, 0x1f07c000000000, // Floating Square Root Single A-form (fsqrts. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSUBS, 0xfc00003f00000000, 0xec00002800000000, 0x7c000000000, // Floating Subtract Single A-form (fsubs FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FSUBSCC, 0xfc00003f00000000, 0xec00002900000000, 0x7c000000000, // Floating Subtract Single A-form (fsubs. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{ICBI, 0xfc0007fe00000000, 0x7c0007ac00000000, 0x3e0000100000000, // Instruction Cache Block Invalidate X-form (icbi RA,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20}},
	{LD, 0xfc00000300000000, 0xe800000000000000, 0x0, // Load Doubleword DS-form (ld RT,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LDARX, 0xfc0007fe00000000, 0x7c0000a800000000, 0x0, // Load Doubleword And Reserve Indexed X-form (ldarx RT,RA,RB,EH)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_31_31}},
	{LDU, 0xfc00000300000000, 0xe800000100000000, 0x0, // Load Doubleword with Update DS-form (ldu RT,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LDUX, 0xfc0007fe00000000, 0x7c00006a00000000, 0x100000000, // Load Doubleword with Update Indexed X-form (ldux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LDX, 0xfc0007fe00000000, 0x7c00002a00000000, 0x100000000, // Load Doubleword Indexed X-form (ldx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWA, 0xfc00000300000000, 0xe800000200000000, 0x0, // Load Word Algebraic DS-form (lwa RT,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LWARX, 0xfc0007fe00000000, 0x7c00002800000000, 0x0, // Load Word & Reserve Indexed X-form (lwarx RT,RA,RB,EH)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_ImmUnsigned_31_31}},
	{LWAUX, 0xfc0007fe00000000, 0x7c0002ea00000000, 0x100000000, // Load Word Algebraic with Update Indexed X-form (lwaux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWAX, 0xfc0007fe00000000, 0x7c0002aa00000000, 0x100000000, // Load Word Algebraic Indexed X-form (lwax RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MFTB, 0xfc0007fe00000000, 0x7c0002e600000000, 0x100000000, // Move From Time Base XFX-form (mftb RT,TBR)
		[6]*argField{ap_Reg_6_10, ap_SpReg_16_20_11_15}},
	{MTMSRD, 0xfc0007fe00000000, 0x7c00016400000000, 0x1ef80100000000, // Move To MSR Doubleword X-form (mtmsrd RS,L)
		[6]*argField{ap_Reg_6_10, ap_ImmUnsigned_15_15}},
	{MULHD, 0xfc0003ff00000000, 0x7c00009200000000, 0x40000000000, // Multiply High Doubleword XO-form (mulhd RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHDCC, 0xfc0003ff00000000, 0x7c00009300000000, 0x40000000000, // Multiply High Doubleword XO-form (mulhd. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHDU, 0xfc0003ff00000000, 0x7c00001200000000, 0x40000000000, // Multiply High Doubleword Unsigned XO-form (mulhdu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHDUCC, 0xfc0003ff00000000, 0x7c00001300000000, 0x40000000000, // Multiply High Doubleword Unsigned XO-form (mulhdu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHW, 0xfc0003ff00000000, 0x7c00009600000000, 0x40000000000, // Multiply High Word XO-form (mulhw RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHWCC, 0xfc0003ff00000000, 0x7c00009700000000, 0x40000000000, // Multiply High Word XO-form (mulhw. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHWU, 0xfc0003ff00000000, 0x7c00001600000000, 0x40000000000, // Multiply High Word Unsigned XO-form (mulhwu RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULHWUCC, 0xfc0003ff00000000, 0x7c00001700000000, 0x40000000000, // Multiply High Word Unsigned XO-form (mulhwu. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULLD, 0xfc0007ff00000000, 0x7c0001d200000000, 0x0, // Multiply Low Doubleword XO-form (mulld RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULLDCC, 0xfc0007ff00000000, 0x7c0001d300000000, 0x0, // Multiply Low Doubleword XO-form (mulld. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULLDO, 0xfc0007ff00000000, 0x7c0005d200000000, 0x0, // Multiply Low Doubleword XO-form (mulldo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MULLDOCC, 0xfc0007ff00000000, 0x7c0005d300000000, 0x0, // Multiply Low Doubleword XO-form (mulldo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{RFID, 0xfc0007fe00000000, 0x4c00002400000000, 0x3fff80100000000, // Return from Interrupt Doubleword XL-form (rfid)
		[6]*argField{}},
	{RLDCL, 0xfc00001f00000000, 0x7800001000000000, 0x0, // Rotate Left Doubleword then Clear Left MDS-form (rldcl RA,RS,RB,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDCLCC, 0xfc00001f00000000, 0x7800001100000000, 0x0, // Rotate Left Doubleword then Clear Left MDS-form (rldcl. RA,RS,RB,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDCR, 0xfc00001f00000000, 0x7800001200000000, 0x0, // Rotate Left Doubleword then Clear Right MDS-form (rldcr RA,RS,RB,ME)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDCRCC, 0xfc00001f00000000, 0x7800001300000000, 0x0, // Rotate Left Doubleword then Clear Right MDS-form (rldcr. RA,RS,RB,ME)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDIC, 0xfc00001d00000000, 0x7800000800000000, 0x0, // Rotate Left Doubleword Immediate then Clear MD-form (rldic RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDICCC, 0xfc00001d00000000, 0x7800000900000000, 0x0, // Rotate Left Doubleword Immediate then Clear MD-form (rldic. RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDICL, 0xfc00001d00000000, 0x7800000000000000, 0x0, // Rotate Left Doubleword Immediate then Clear Left MD-form (rldicl RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDICLCC, 0xfc00001d00000000, 0x7800000100000000, 0x0, // Rotate Left Doubleword Immediate then Clear Left MD-form (rldicl. RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDICR, 0xfc00001d00000000, 0x7800000400000000, 0x0, // Rotate Left Doubleword Immediate then Clear Right MD-form (rldicr RA,RS,SH,ME)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDICRCC, 0xfc00001d00000000, 0x7800000500000000, 0x0, // Rotate Left Doubleword Immediate then Clear Right MD-form (rldicr. RA,RS,SH,ME)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDIMI, 0xfc00001d00000000, 0x7800000c00000000, 0x0, // Rotate Left Doubleword Immediate then Mask Insert MD-form (rldimi RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{RLDIMICC, 0xfc00001d00000000, 0x7800000d00000000, 0x0, // Rotate Left Doubleword Immediate then Mask Insert MD-form (rldimi. RA,RS,SH,MB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20, ap_ImmUnsigned_26_26_21_25}},
	{SC, 0xfc00000200000000, 0x4400000200000000, 0x3fff01d00000000, // System Call SC-form (sc LEV)
		[6]*argField{ap_ImmUnsigned_20_26}},
	{SLBIA, 0xfc0007fe00000000, 0x7c0003e400000000, 0x31ff80100000000, // SLB Invalidate All X-form (slbia IH)
		[6]*argField{ap_ImmUnsigned_8_10}},
	{SLBIE, 0xfc0007fe00000000, 0x7c00036400000000, 0x3ff000100000000, // SLB Invalidate Entry X-form (slbie RB)
		[6]*argField{ap_Reg_16_20}},
	{SLD, 0xfc0007ff00000000, 0x7c00003600000000, 0x0, // Shift Left Doubleword X-form (sld RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{SLDCC, 0xfc0007ff00000000, 0x7c00003700000000, 0x0, // Shift Left Doubleword X-form (sld. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{SRAD, 0xfc0007ff00000000, 0x7c00063400000000, 0x0, // Shift Right Algebraic Doubleword X-form (srad RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{SRADCC, 0xfc0007ff00000000, 0x7c00063500000000, 0x0, // Shift Right Algebraic Doubleword X-form (srad. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{SRADI, 0xfc0007fd00000000, 0x7c00067400000000, 0x0, // Shift Right Algebraic Doubleword Immediate XS-form (sradi RA,RS,SH)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20}},
	{SRADICC, 0xfc0007fd00000000, 0x7c00067500000000, 0x0, // Shift Right Algebraic Doubleword Immediate XS-form (sradi. RA,RS,SH)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_30_30_16_20}},
	{SRD, 0xfc0007ff00000000, 0x7c00043600000000, 0x0, // Shift Right Doubleword X-form (srd RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{SRDCC, 0xfc0007ff00000000, 0x7c00043700000000, 0x0, // Shift Right Doubleword X-form (srd. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{STD, 0xfc00000300000000, 0xf800000000000000, 0x0, // Store Doubleword DS-form (std RS,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{STDCXCC, 0xfc0007ff00000000, 0x7c0001ad00000000, 0x0, // Store Doubleword Conditional Indexed X-form (stdcx. RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STDU, 0xfc00000300000000, 0xf800000100000000, 0x0, // Store Doubleword with Update DS-form (stdu RS,DS(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{STDUX, 0xfc0007fe00000000, 0x7c00016a00000000, 0x100000000, // Store Doubleword with Update Indexed X-form (stdux RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STDX, 0xfc0007fe00000000, 0x7c00012a00000000, 0x100000000, // Store Doubleword Indexed X-form (stdx RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STFIWX, 0xfc0007fe00000000, 0x7c0007ae00000000, 0x100000000, // Store Floating-Point as Integer Word Indexed X-form (stfiwx FRS,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STWCXCC, 0xfc0007ff00000000, 0x7c00012d00000000, 0x0, // Store Word Conditional Indexed X-form (stwcx. RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{SUBF, 0xfc0007ff00000000, 0x7c00005000000000, 0x0, // Subtract From XO-form (subf RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{SUBFCC, 0xfc0007ff00000000, 0x7c00005100000000, 0x0, // Subtract From XO-form (subf. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{SUBFO, 0xfc0007ff00000000, 0x7c00045000000000, 0x0, // Subtract From XO-form (subfo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{SUBFOCC, 0xfc0007ff00000000, 0x7c00045100000000, 0x0, // Subtract From XO-form (subfo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{TD, 0xfc0007fe00000000, 0x7c00008800000000, 0x100000000, // Trap Doubleword X-form (td TO,RA,RB)
		[6]*argField{ap_ImmUnsigned_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{TDI, 0xfc00000000000000, 0x800000000000000, 0x0, // Trap Doubleword Immediate D-form (tdi TO,RA,SI)
		[6]*argField{ap_ImmUnsigned_6_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{TLBSYNC, 0xfc0007fe00000000, 0x7c00046c00000000, 0x3fff80100000000, // TLB Synchronize X-form (tlbsync)
		[6]*argField{}},
	{FCTIW, 0xfc0007ff00000000, 0xfc00001c00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Signed Word format X-form (fctiw FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWCC, 0xfc0007ff00000000, 0xfc00001d00000000, 0x1f000000000000, // Floating Convert with round Double-Precision To Signed Word format X-form (fctiw. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWZ, 0xfc0007ff00000000, 0xfc00001e00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Signed Word fomat X-form (fctiwz FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCTIWZCC, 0xfc0007ff00000000, 0xfc00001f00000000, 0x1f000000000000, // Floating Convert with truncate Double-Precision To Signed Word fomat X-form (fctiwz. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSQRT, 0xfc00003f00000000, 0xfc00002c00000000, 0x1f07c000000000, // Floating Square Root A-form (fsqrt FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSQRTCC, 0xfc00003f00000000, 0xfc00002d00000000, 0x1f07c000000000, // Floating Square Root A-form (fsqrt. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{ADD, 0xfc0007ff00000000, 0x7c00021400000000, 0x0, // Add XO-form (add RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDCC, 0xfc0007ff00000000, 0x7c00021500000000, 0x0, // Add XO-form (add. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDO, 0xfc0007ff00000000, 0x7c00061400000000, 0x0, // Add XO-form (addo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDOCC, 0xfc0007ff00000000, 0x7c00061500000000, 0x0, // Add XO-form (addo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDC, 0xfc0007ff00000000, 0x7c00001400000000, 0x0, // Add Carrying XO-form (addc RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDCCC, 0xfc0007ff00000000, 0x7c00001500000000, 0x0, // Add Carrying XO-form (addc. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDCO, 0xfc0007ff00000000, 0x7c00041400000000, 0x0, // Add Carrying XO-form (addco RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDCOCC, 0xfc0007ff00000000, 0x7c00041500000000, 0x0, // Add Carrying XO-form (addco. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDE, 0xfc0007ff00000000, 0x7c00011400000000, 0x0, // Add Extended XO-form (adde RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDECC, 0xfc0007ff00000000, 0x7c00011500000000, 0x0, // Add Extended XO-form (adde. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDEO, 0xfc0007ff00000000, 0x7c00051400000000, 0x0, // Add Extended XO-form (addeo RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ADDEOCC, 0xfc0007ff00000000, 0x7c00051500000000, 0x0, // Add Extended XO-form (addeo. RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LI, 0xfc1f000000000000, 0x3800000000000000, 0x0, // Add Immediate D-form (li RT,SI)
		[6]*argField{ap_Reg_6_10, ap_ImmSigned_16_31}},
	{ADDI, 0xfc00000000000000, 0x3800000000000000, 0x0, // Add Immediate D-form (addi RT,RA,SI)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{ADDIC, 0xfc00000000000000, 0x3000000000000000, 0x0, // Add Immediate Carrying D-form (addic RT,RA,SI)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{ADDICCC, 0xfc00000000000000, 0x3400000000000000, 0x0, // Add Immediate Carrying and Record D-form (addic. RT,RA,SI)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{LIS, 0xfc1f000000000000, 0x3c00000000000000, 0x0, // Add Immediate Shifted D-form (lis RT,SI)
		[6]*argField{ap_Reg_6_10, ap_ImmSigned_16_31}},
	{ADDIS, 0xfc00000000000000, 0x3c00000000000000, 0x0, // Add Immediate Shifted D-form (addis RT,RA,SI)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{ADDME, 0xfc0007ff00000000, 0x7c0001d400000000, 0xf80000000000, // Add to Minus One Extended XO-form (addme RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDMECC, 0xfc0007ff00000000, 0x7c0001d500000000, 0xf80000000000, // Add to Minus One Extended XO-form (addme. RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDMEO, 0xfc0007ff00000000, 0x7c0005d400000000, 0xf80000000000, // Add to Minus One Extended XO-form (addmeo RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDMEOCC, 0xfc0007ff00000000, 0x7c0005d500000000, 0xf80000000000, // Add to Minus One Extended XO-form (addmeo. RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDZE, 0xfc0007ff00000000, 0x7c00019400000000, 0xf80000000000, // Add to Zero Extended XO-form (addze RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDZECC, 0xfc0007ff00000000, 0x7c00019500000000, 0xf80000000000, // Add to Zero Extended XO-form (addze. RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDZEO, 0xfc0007ff00000000, 0x7c00059400000000, 0xf80000000000, // Add to Zero Extended XO-form (addzeo RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{ADDZEOCC, 0xfc0007ff00000000, 0x7c00059500000000, 0xf80000000000, // Add to Zero Extended XO-form (addzeo. RT,RA)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15}},
	{AND, 0xfc0007ff00000000, 0x7c00003800000000, 0x0, // AND X-form (and RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{ANDCC, 0xfc0007ff00000000, 0x7c00003900000000, 0x0, // AND X-form (and. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{ANDC, 0xfc0007ff00000000, 0x7c00007800000000, 0x0, // AND with Complement X-form (andc RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{ANDCCC, 0xfc0007ff00000000, 0x7c00007900000000, 0x0, // AND with Complement X-form (andc. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{ANDICC, 0xfc00000000000000, 0x7000000000000000, 0x0, // AND Immediate D-form (andi. RA,RS,UI)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_16_31}},
	{ANDISCC, 0xfc00000000000000, 0x7400000000000000, 0x0, // AND Immediate Shifted D-form (andis. RA,RS,UI)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_ImmUnsigned_16_31}},
	{B, 0xfc00000300000000, 0x4800000000000000, 0x0, // Branch I-form (b target_addr)
		[6]*argField{ap_PCRel_6_29_shift2}},
	{BA, 0xfc00000300000000, 0x4800000200000000, 0x0, // Branch I-form (ba target_addr)
		[6]*argField{ap_Label_6_29_shift2}},
	{BL, 0xfc00000300000000, 0x4800000100000000, 0x0, // Branch I-form (bl target_addr)
		[6]*argField{ap_PCRel_6_29_shift2}},
	{BLA, 0xfc00000300000000, 0x4800000300000000, 0x0, // Branch I-form (bla target_addr)
		[6]*argField{ap_Label_6_29_shift2}},
	{BC, 0xfc00000300000000, 0x4000000000000000, 0x0, // Branch Conditional B-form (bc BO,BI,target_addr)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_PCRel_16_29_shift2}},
	{BCA, 0xfc00000300000000, 0x4000000200000000, 0x0, // Branch Conditional B-form (bca BO,BI,target_addr)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_Label_16_29_shift2}},
	{BCL, 0xfc00000300000000, 0x4000000100000000, 0x0, // Branch Conditional B-form (bcl BO,BI,target_addr)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_PCRel_16_29_shift2}},
	{BCLA, 0xfc00000300000000, 0x4000000300000000, 0x0, // Branch Conditional B-form (bcla BO,BI,target_addr)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_Label_16_29_shift2}},
	{BCCTR, 0xfc0007ff00000000, 0x4c00042000000000, 0xe00000000000, // Branch Conditional to Count Register XL-form (bcctr BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{BCCTRL, 0xfc0007ff00000000, 0x4c00042100000000, 0xe00000000000, // Branch Conditional to Count Register XL-form (bcctrl BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{BCLR, 0xfc0007ff00000000, 0x4c00002000000000, 0xe00000000000, // Branch Conditional to Link Register XL-form (bclr BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{BCLRL, 0xfc0007ff00000000, 0x4c00002100000000, 0xe00000000000, // Branch Conditional to Link Register XL-form (bclrl BO,BI,BH)
		[6]*argField{ap_ImmUnsigned_6_10, ap_CondRegBit_11_15, ap_ImmUnsigned_19_20}},
	{CMPW, 0xfc2007fe00000000, 0x7c00000000000000, 0x40000100000000, // Compare X-form (cmpw BF,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPD, 0xfc2007fe00000000, 0x7c20000000000000, 0x40000100000000, // Compare X-form (cmpd BF,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_Reg_16_20}},
	{CMP, 0xfc0007fe00000000, 0x7c00000000000000, 0x40000100000000, // Compare X-form (cmp BF,L,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_10, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPWI, 0xfc20000000000000, 0x2c00000000000000, 0x40000000000000, // Compare Immediate D-form (cmpwi BF,RA,SI)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{CMPDI, 0xfc20000000000000, 0x2c20000000000000, 0x40000000000000, // Compare Immediate D-form (cmpdi BF,RA,SI)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{CMPI, 0xfc00000000000000, 0x2c00000000000000, 0x40000000000000, // Compare Immediate D-form (cmpi BF,L,RA,SI)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_10, ap_Reg_11_15, ap_ImmSigned_16_31}},
	{CMPLW, 0xfc2007fe00000000, 0x7c00004000000000, 0x40000100000000, // Compare Logical X-form (cmplw BF,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPLD, 0xfc2007fe00000000, 0x7c20004000000000, 0x40000100000000, // Compare Logical X-form (cmpld BF,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPL, 0xfc0007fe00000000, 0x7c00004000000000, 0x40000100000000, // Compare Logical X-form (cmpl BF,L,RA,RB)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_10, ap_Reg_11_15, ap_Reg_16_20}},
	{CMPLWI, 0xfc20000000000000, 0x2800000000000000, 0x40000000000000, // Compare Logical Immediate D-form (cmplwi BF,RA,UI)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_ImmUnsigned_16_31}},
	{CMPLDI, 0xfc20000000000000, 0x2820000000000000, 0x40000000000000, // Compare Logical Immediate D-form (cmpldi BF,RA,UI)
		[6]*argField{ap_CondRegField_6_8, ap_Reg_11_15, ap_ImmUnsigned_16_31}},
	{CMPLI, 0xfc00000000000000, 0x2800000000000000, 0x40000000000000, // Compare Logical Immediate D-form (cmpli BF,L,RA,UI)
		[6]*argField{ap_CondRegField_6_8, ap_ImmUnsigned_10_10, ap_Reg_11_15, ap_ImmUnsigned_16_31}},
	{CNTLZW, 0xfc0007ff00000000, 0x7c00003400000000, 0xf80000000000, // Count Leading Zeros Word X-form (cntlzw RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CNTLZWCC, 0xfc0007ff00000000, 0x7c00003500000000, 0xf80000000000, // Count Leading Zeros Word X-form (cntlzw. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{CRAND, 0xfc0007fe00000000, 0x4c00020200000000, 0x100000000, // Condition Register AND XL-form (crand BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CRANDC, 0xfc0007fe00000000, 0x4c00010200000000, 0x100000000, // Condition Register AND with Complement XL-form (crandc BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CREQV, 0xfc0007fe00000000, 0x4c00024200000000, 0x100000000, // Condition Register Equivalent XL-form (creqv BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CRNAND, 0xfc0007fe00000000, 0x4c0001c200000000, 0x100000000, // Condition Register NAND XL-form (crnand BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CRNOR, 0xfc0007fe00000000, 0x4c00004200000000, 0x100000000, // Condition Register NOR XL-form (crnor BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CROR, 0xfc0007fe00000000, 0x4c00038200000000, 0x100000000, // Condition Register OR XL-form (cror BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CRORC, 0xfc0007fe00000000, 0x4c00034200000000, 0x100000000, // Condition Register OR with Complement XL-form (crorc BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{CRXOR, 0xfc0007fe00000000, 0x4c00018200000000, 0x100000000, // Condition Register XOR XL-form (crxor BT,BA,BB)
		[6]*argField{ap_CondRegBit_6_10, ap_CondRegBit_11_15, ap_CondRegBit_16_20}},
	{DCBZ, 0xfc0007fe00000000, 0x7c0007ec00000000, 0x3e0000100000000, // Data Cache Block set to Zero X-form (dcbz RA,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_16_20}},
	{EQV, 0xfc0007ff00000000, 0x7c00023800000000, 0x0, // Equivalent X-form (eqv RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{EQVCC, 0xfc0007ff00000000, 0x7c00023900000000, 0x0, // Equivalent X-form (eqv. RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{EXTSH, 0xfc0007ff00000000, 0x7c00073400000000, 0xf80000000000, // Extend Sign Halfword X-form (extsh RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{EXTSHCC, 0xfc0007ff00000000, 0x7c00073500000000, 0xf80000000000, // Extend Sign Halfword X-form (extsh. RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{FABS, 0xfc0007ff00000000, 0xfc00021000000000, 0x1f000000000000, // Floating Absolute Value X-form (fabs FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FABSCC, 0xfc0007ff00000000, 0xfc00021100000000, 0x1f000000000000, // Floating Absolute Value X-form (fabs. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FADD, 0xfc00003f00000000, 0xfc00002a00000000, 0x7c000000000, // Floating Add A-form (fadd FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FADDCC, 0xfc00003f00000000, 0xfc00002b00000000, 0x7c000000000, // Floating Add A-form (fadd. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FCMPO, 0xfc0007fe00000000, 0xfc00004000000000, 0x60000100000000, // Floating Compare Ordered X-form (fcmpo BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FCMPU, 0xfc0007fe00000000, 0xfc00000000000000, 0x60000100000000, // Floating Compare Unordered X-form (fcmpu BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FDIV, 0xfc00003f00000000, 0xfc00002400000000, 0x7c000000000, // Floating Divide A-form (fdiv FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FDIVCC, 0xfc00003f00000000, 0xfc00002500000000, 0x7c000000000, // Floating Divide A-form (fdiv. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FMADD, 0xfc00003f00000000, 0xfc00003a00000000, 0x0, // Floating Multiply-Add A-form (fmadd FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMADDCC, 0xfc00003f00000000, 0xfc00003b00000000, 0x0, // Floating Multiply-Add A-form (fmadd. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMR, 0xfc0007ff00000000, 0xfc00009000000000, 0x1f000000000000, // Floating Move Register X-form (fmr FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FMRCC, 0xfc0007ff00000000, 0xfc00009100000000, 0x1f000000000000, // Floating Move Register X-form (fmr. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FMSUB, 0xfc00003f00000000, 0xfc00003800000000, 0x0, // Floating Multiply-Subtract A-form (fmsub FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMSUBCC, 0xfc00003f00000000, 0xfc00003900000000, 0x0, // Floating Multiply-Subtract A-form (fmsub. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FMUL, 0xfc00003f00000000, 0xfc00003200000000, 0xf80000000000, // Floating Multiply A-form (fmul FRT,FRA,FRC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25}},
	{FMULCC, 0xfc00003f00000000, 0xfc00003300000000, 0xf80000000000, // Floating Multiply A-form (fmul. FRT,FRA,FRC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25}},
	{FNABS, 0xfc0007ff00000000, 0xfc00011000000000, 0x1f000000000000, // Floating Negative Absolute Value X-form (fnabs FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FNABSCC, 0xfc0007ff00000000, 0xfc00011100000000, 0x1f000000000000, // Floating Negative Absolute Value X-form (fnabs. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FNEG, 0xfc0007ff00000000, 0xfc00005000000000, 0x1f000000000000, // Floating Negate X-form (fneg FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FNEGCC, 0xfc0007ff00000000, 0xfc00005100000000, 0x1f000000000000, // Floating Negate X-form (fneg. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FNMADD, 0xfc00003f00000000, 0xfc00003e00000000, 0x0, // Floating Negative Multiply-Add A-form (fnmadd FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMADDCC, 0xfc00003f00000000, 0xfc00003f00000000, 0x0, // Floating Negative Multiply-Add A-form (fnmadd. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMSUB, 0xfc00003f00000000, 0xfc00003c00000000, 0x0, // Floating Negative Multiply-Subtract A-form (fnmsub FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FNMSUBCC, 0xfc00003f00000000, 0xfc00003d00000000, 0x0, // Floating Negative Multiply-Subtract A-form (fnmsub. FRT,FRA,FRC,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_21_25, ap_FPReg_16_20}},
	{FRSP, 0xfc0007ff00000000, 0xfc00001800000000, 0x1f000000000000, // Floating Round to Single-Precision X-form (frsp FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FRSPCC, 0xfc0007ff00000000, 0xfc00001900000000, 0x1f000000000000, // Floating Round to Single-Precision X-form (frsp. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FSUB, 0xfc00003f00000000, 0xfc00002800000000, 0x7c000000000, // Floating Subtract A-form (fsub FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FSUBCC, 0xfc00003f00000000, 0xfc00002900000000, 0x7c000000000, // Floating Subtract A-form (fsub. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{ISYNC, 0xfc0007fe00000000, 0x4c00012c00000000, 0x3fff80100000000, // Instruction Synchronize XL-form (isync)
		[6]*argField{}},
	{LBZ, 0xfc00000000000000, 0x8800000000000000, 0x0, // Load Byte and Zero D-form (lbz RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LBZU, 0xfc00000000000000, 0x8c00000000000000, 0x0, // Load Byte and Zero with Update D-form (lbzu RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LBZUX, 0xfc0007fe00000000, 0x7c0000ee00000000, 0x100000000, // Load Byte and Zero with Update Indexed X-form (lbzux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LBZX, 0xfc0007fe00000000, 0x7c0000ae00000000, 0x100000000, // Load Byte and Zero Indexed X-form (lbzx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFD, 0xfc00000000000000, 0xc800000000000000, 0x0, // Load Floating-Point Double D-form (lfd FRT,D(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LFDU, 0xfc00000000000000, 0xcc00000000000000, 0x0, // Load Floating-Point Double with Update D-form (lfdu FRT,D(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LFDUX, 0xfc0007fe00000000, 0x7c0004ee00000000, 0x100000000, // Load Floating-Point Double with Update Indexed X-form (lfdux FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFDX, 0xfc0007fe00000000, 0x7c0004ae00000000, 0x100000000, // Load Floating-Point Double Indexed X-form (lfdx FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFS, 0xfc00000000000000, 0xc000000000000000, 0x0, // Load Floating-Point Single D-form (lfs FRT,D(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LFSU, 0xfc00000000000000, 0xc400000000000000, 0x0, // Load Floating-Point Single with Update D-form (lfsu FRT,D(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LFSUX, 0xfc0007fe00000000, 0x7c00046e00000000, 0x100000000, // Load Floating-Point Single with Update Indexed X-form (lfsux FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFSX, 0xfc0007fe00000000, 0x7c00042e00000000, 0x100000000, // Load Floating-Point Single Indexed X-form (lfsx FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHA, 0xfc00000000000000, 0xa800000000000000, 0x0, // Load Halfword Algebraic D-form (lha RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LHAU, 0xfc00000000000000, 0xac00000000000000, 0x0, // Load Halfword Algebraic with Update D-form (lhau RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LHAUX, 0xfc0007fe00000000, 0x7c0002ee00000000, 0x100000000, // Load Halfword Algebraic with Update Indexed X-form (lhaux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHAX, 0xfc0007fe00000000, 0x7c0002ae00000000, 0x100000000, // Load Halfword Algebraic Indexed X-form (lhax RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHBRX, 0xfc0007fe00000000, 0x7c00062c00000000, 0x100000000, // Load Halfword Byte-Reverse Indexed X-form (lhbrx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHZ, 0xfc00000000000000, 0xa000000000000000, 0x0, // Load Halfword and Zero D-form (lhz RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LHZU, 0xfc00000000000000, 0xa400000000000000, 0x0, // Load Halfword and Zero with Update D-form (lhzu RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LHZUX, 0xfc0007fe00000000, 0x7c00026e00000000, 0x100000000, // Load Halfword and Zero with Update Indexed X-form (lhzux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHZX, 0xfc0007fe00000000, 0x7c00022e00000000, 0x100000000, // Load Halfword and Zero Indexed X-form (lhzx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LMW, 0xfc00000000000000, 0xb800000000000000, 0x0, // Load Multiple Word D-form (lmw RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LSWI, 0xfc0007fe00000000, 0x7c0004aa00000000, 0x100000000, // Load String Word Immediate X-form (lswi RT,RA,NB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_ImmUnsigned_16_20}},
	{LSWX, 0xfc0007fe00000000, 0x7c00042a00000000, 0x100000000, // Load String Word Indexed X-form (lswx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWBRX, 0xfc0007fe00000000, 0x7c00042c00000000, 0x100000000, // Load Word Byte-Reverse Indexed X-form (lwbrx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWZ, 0xfc00000000000000, 0x8000000000000000, 0x0, // Load Word and Zero D-form (lwz RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LWZU, 0xfc00000000000000, 0x8400000000000000, 0x0, // Load Word and Zero with Update D-form (lwzu RT,D(RA))
		[6]*argField{ap_Reg_6_10, ap_Offset_16_31, ap_Reg_11_15}},
	{LWZUX, 0xfc0007fe00000000, 0x7c00006e00000000, 0x100000000, // Load Word and Zero with Update Indexed X-form (lwzux RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWZX, 0xfc0007fe00000000, 0x7c00002e00000000, 0x100000000, // Load Word and Zero Indexed X-form (lwzx RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MCRF, 0xfc0007fe00000000, 0x4c00000000000000, 0x63f80100000000, // Move Condition Register Field XL-form (mcrf BF,BFA)
		[6]*argField{ap_CondRegField_6_8, ap_CondRegField_11_13}},
	{MCRFS, 0xfc0007fe00000000, 0xfc00008000000000, 0x63f80100000000, // Move to Condition Register from FPSCR X-form (mcrfs BF,BFA)
		[6]*argField{ap_CondRegField_6_8, ap_CondRegField_11_13}},
	{MFCR, 0xfc1007fe00000000, 0x7c00002600000000, 0xff80100000000, // Move From Condition Register XFX-form (mfcr RT)
		[6]*argField{ap_Reg_6_10}},
	{MFFS, 0xfc1f07ff00000000, 0xfc00048e00000000, 0xf80000000000, // Move From FPSCR X-form (mffs FRT)
		[6]*argField{ap_FPReg_6_10}},
	{MFFSCC, 0xfc1f07ff00000000, 0xfc00048f00000000, 0xf80000000000, // Move From FPSCR X-form (mffs. FRT)
		[6]*argField{ap_FPReg_6_10}},
	{MFMSR, 0xfc0007fe00000000, 0x7c0000a600000000, 0x1ff80100000000, // Move From MSR X-form (mfmsr RT)
		[6]*argField{ap_Reg_6_10}},
	{MFSPR, 0xfc0007fe00000000, 0x7c0002a600000000, 0x100000000, // Move From Special Purpose Register XFX-form (mfspr RT,SPR)
		[6]*argField{ap_Reg_6_10, ap_SpReg_16_20_11_15}},
	{MTCRF, 0xfc1007fe00000000, 0x7c00012000000000, 0x80100000000, // Move To Condition Register Fields XFX-form (mtcrf FXM,RS)
		[6]*argField{ap_ImmUnsigned_12_19, ap_Reg_6_10}},
	{MTFSB0, 0xfc0007ff00000000, 0xfc00008c00000000, 0x1ff80000000000, // Move To FPSCR Bit 0 X-form (mtfsb0 BT)
		[6]*argField{ap_ImmUnsigned_6_10}},
	{MTFSB0CC, 0xfc0007ff00000000, 0xfc00008d00000000, 0x1ff80000000000, // Move To FPSCR Bit 0 X-form (mtfsb0. BT)
		[6]*argField{ap_ImmUnsigned_6_10}},
	{MTFSB1, 0xfc0007ff00000000, 0xfc00004c00000000, 0x1ff80000000000, // Move To FPSCR Bit 1 X-form (mtfsb1 BT)
		[6]*argField{ap_ImmUnsigned_6_10}},
	{MTFSB1CC, 0xfc0007ff00000000, 0xfc00004d00000000, 0x1ff80000000000, // Move To FPSCR Bit 1 X-form (mtfsb1. BT)
		[6]*argField{ap_ImmUnsigned_6_10}},
	{MTFSF, 0xfc0007ff00000000, 0xfc00058e00000000, 0x0, // Move To FPSCR Fields XFL-form (mtfsf FLM,FRB,L,W)
		[6]*argField{ap_ImmUnsigned_7_14, ap_FPReg_16_20, ap_ImmUnsigned_6_6, ap_ImmUnsigned_15_15}},
	{MTFSFCC, 0xfc0007ff00000000, 0xfc00058f00000000, 0x0, // Move To FPSCR Fields XFL-form (mtfsf. FLM,FRB,L,W)
		[6]*argField{ap_ImmUnsigned_7_14, ap_FPReg_16_20, ap_Im
"""




```