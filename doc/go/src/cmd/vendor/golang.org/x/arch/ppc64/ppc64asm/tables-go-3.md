Response:
这段代码是 Go 语言实现的一部分，位于 `go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/tables.go` 文件中。它主要用于定义和描述 PowerPC 64 位架构（PPC64）的指令集，特别是与 **VSX**（Vector Scalar eXtension）和 **DFP**（Decimal Floating Point）相关的指令。

### 功能归纳

1. **指令定义**：
   - 代码中定义了大量的 PPC64 指令，特别是 VSX 和 DFP 相关的指令。每条指令都包含了操作码（opcode）、掩码（mask）、值（value）以及操作数字段（argField）。
   - 例如，`XSDIVDP` 是 VSX 标量双精度除法指令，`XSMADDADP` 是 VSX 标量双精度乘法-加法指令等。

2. **操作数字段**：
   - 每条指令的操作数字段通过 `argField` 结构体定义，描述了指令的操作数类型和位置。例如，`ap_VecSReg_31_31_6_10` 表示从指令的第 6 到 10 位提取向量标量寄存器的值。

3. **指令格式**：
   - 代码中使用了不同的指令格式，如 `XX3-form`、`XX2-form` 等，这些格式描述了指令的操作数布局和编码方式。

4. **指令功能**：
   - 代码中定义的指令涵盖了多种功能，包括：
     - 算术运算（如加法、减法、乘法、除法）
     - 逻辑运算（如与、或、非、异或）
     - 比较运算（如等于、大于、小于）
     - 类型转换（如浮点数到整数、整数到浮点数）
     - 向量操作（如向量合并、向量移位）

### 代码推理

假设我们有以下指令：

```go
{XSDIVDP, 0xfc0007f800000000, 0xf00001c000000000, 0x0, // VSX Scalar Divide Double-Precision XX3-form (xsdivdp XT,XA,XB)
    [6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
```

- **指令名称**：`XSDIVDP`
- **操作码**：`0xfc0007f800000000`
- **掩码**：`0xf00001c000000000`
- **值**：`0x0`
- **操作数**：`ap_VecSReg_31_31_6_10`, `ap_VecSReg_29_29_11_15`, `ap_VecSReg_30_30_16_20`

这条指令的功能是执行 VSX 标量双精度除法，操作数为三个向量标量寄存器 `XT`, `XA`, `XB`。

### 假设的输入与输出

假设我们有以下输入：

- `XT` = `VS0`
- `XA` = `VS1`
- `XB` = `VS2`

执行 `XSDIVDP VS0, VS1, VS2` 后，`VS0` 将包含 `VS1` 除以 `VS2` 的结果。

### 命令行参数处理

这段代码本身并不直接处理命令行参数，而是定义了 PPC64 指令集的解析规则。命令行参数的处理通常由调用该代码的上层程序（如汇编器或反汇编器）负责。

### 使用者易犯错的点

1. **操作数顺序**：
   - 在编写汇编代码时，操作数的顺序非常重要。例如，`XSDIVDP XT, XA, XB` 表示 `XT = XA / XB`，如果顺序写错，可能会导致错误的结果。

2. **寄存器类型**：
   - VSX 指令操作的是向量标量寄存器（`VS0` 到 `VS63`），而不是普通的通用寄存器（`R0` 到 `R31`）。混淆寄存器类型会导致汇编错误。

3. **指令格式**：
   - 不同的指令有不同的格式（如 `XX3-form`、`XX2-form`），使用错误的格式会导致指令无法正确解析。

### 总结

这段代码的主要功能是定义和描述 PPC64 架构中的 VSX 和 DFP 指令集，包括指令的操作码、掩码、值以及操作数字段。它为汇编器和反汇编器提供了必要的信息，以便正确解析和生成 PPC64 指令。
Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/ppc64/ppc64asm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共6部分，请归纳一下它的功能

"""
P, 0xfc0007f800000000, 0xf00001c000000000, 0x0, // VSX Scalar Divide Double-Precision XX3-form (xsdivdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMADDADP, 0xfc0007f800000000, 0xf000010800000000, 0x0, // VSX Scalar Multiply-Add Type-A Double-Precision XX3-form (xsmaddadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMADDMDP, 0xfc0007f800000000, 0xf000014800000000, 0x0, // VSX Scalar Multiply-Add Type-M Double-Precision XX3-form (xsmaddmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMAXDP, 0xfc0007f800000000, 0xf000050000000000, 0x0, // VSX Scalar Maximum Double-Precision XX3-form (xsmaxdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMINDP, 0xfc0007f800000000, 0xf000054000000000, 0x0, // VSX Scalar Minimum Double-Precision XX3-form (xsmindp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMSUBADP, 0xfc0007f800000000, 0xf000018800000000, 0x0, // VSX Scalar Multiply-Subtract Type-A Double-Precision XX3-form (xsmsubadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMSUBMDP, 0xfc0007f800000000, 0xf00001c800000000, 0x0, // VSX Scalar Multiply-Subtract Type-M Double-Precision XX3-form (xsmsubmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSMULDP, 0xfc0007f800000000, 0xf000018000000000, 0x0, // VSX Scalar Multiply Double-Precision XX3-form (xsmuldp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNABSDP, 0xfc0007fc00000000, 0xf00005a400000000, 0x1f000000000000, // VSX Scalar Negative Absolute Double-Precision XX2-form (xsnabsdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSNEGDP, 0xfc0007fc00000000, 0xf00005e400000000, 0x1f000000000000, // VSX Scalar Negate Double-Precision XX2-form (xsnegdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSNMADDADP, 0xfc0007f800000000, 0xf000050800000000, 0x0, // VSX Scalar Negative Multiply-Add Type-A Double-Precision XX3-form (xsnmaddadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMADDMDP, 0xfc0007f800000000, 0xf000054800000000, 0x0, // VSX Scalar Negative Multiply-Add Type-M Double-Precision XX3-form (xsnmaddmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMSUBADP, 0xfc0007f800000000, 0xf000058800000000, 0x0, // VSX Scalar Negative Multiply-Subtract Type-A Double-Precision XX3-form (xsnmsubadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSNMSUBMDP, 0xfc0007f800000000, 0xf00005c800000000, 0x0, // VSX Scalar Negative Multiply-Subtract Type-M Double-Precision XX3-form (xsnmsubmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSRDPI, 0xfc0007fc00000000, 0xf000012400000000, 0x1f000000000000, // VSX Scalar Round to Double-Precision Integer using round to Nearest Away XX2-form (xsrdpi XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRDPIC, 0xfc0007fc00000000, 0xf00001ac00000000, 0x1f000000000000, // VSX Scalar Round to Double-Precision Integer exact using Current rounding mode XX2-form (xsrdpic XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRDPIM, 0xfc0007fc00000000, 0xf00001e400000000, 0x1f000000000000, // VSX Scalar Round to Double-Precision Integer using round toward -Infinity XX2-form (xsrdpim XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRDPIP, 0xfc0007fc00000000, 0xf00001a400000000, 0x1f000000000000, // VSX Scalar Round to Double-Precision Integer using round toward +Infinity XX2-form (xsrdpip XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRDPIZ, 0xfc0007fc00000000, 0xf000016400000000, 0x1f000000000000, // VSX Scalar Round to Double-Precision Integer using round toward Zero XX2-form (xsrdpiz XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSREDP, 0xfc0007fc00000000, 0xf000016800000000, 0x1f000000000000, // VSX Scalar Reciprocal Estimate Double-Precision XX2-form (xsredp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSRSQRTEDP, 0xfc0007fc00000000, 0xf000012800000000, 0x1f000000000000, // VSX Scalar Reciprocal Square Root Estimate Double-Precision XX2-form (xsrsqrtedp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSSQRTDP, 0xfc0007fc00000000, 0xf000012c00000000, 0x1f000000000000, // VSX Scalar Square Root Double-Precision XX2-form (xssqrtdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XSSUBDP, 0xfc0007f800000000, 0xf000014000000000, 0x0, // VSX Scalar Subtract Double-Precision XX3-form (xssubdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSTDIVDP, 0xfc0007f800000000, 0xf00001e800000000, 0x60000100000000, // VSX Scalar Test for software Divide Double-Precision XX3-form (xstdivdp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XSTSQRTDP, 0xfc0007fc00000000, 0xf00001a800000000, 0x7f000100000000, // VSX Scalar Test for software Square Root Double-Precision XX2-form (xstsqrtdp BF,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20}},
	{XVABSDP, 0xfc0007fc00000000, 0xf000076400000000, 0x1f000000000000, // VSX Vector Absolute Value Double-Precision XX2-form (xvabsdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVABSSP, 0xfc0007fc00000000, 0xf000066400000000, 0x1f000000000000, // VSX Vector Absolute Value Single-Precision XX2-form (xvabssp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVADDDP, 0xfc0007f800000000, 0xf000030000000000, 0x0, // VSX Vector Add Double-Precision XX3-form (xvadddp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVADDSP, 0xfc0007f800000000, 0xf000020000000000, 0x0, // VSX Vector Add Single-Precision XX3-form (xvaddsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPEQDP, 0xfc0007f800000000, 0xf000031800000000, 0x0, // VSX Vector Compare Equal To Double-Precision XX3-form (xvcmpeqdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPEQDPCC, 0xfc0007f800000000, 0xf000071800000000, 0x0, // VSX Vector Compare Equal To Double-Precision XX3-form (xvcmpeqdp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPEQSP, 0xfc0007f800000000, 0xf000021800000000, 0x0, // VSX Vector Compare Equal To Single-Precision XX3-form (xvcmpeqsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPEQSPCC, 0xfc0007f800000000, 0xf000061800000000, 0x0, // VSX Vector Compare Equal To Single-Precision XX3-form (xvcmpeqsp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGEDP, 0xfc0007f800000000, 0xf000039800000000, 0x0, // VSX Vector Compare Greater Than or Equal To Double-Precision XX3-form (xvcmpgedp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGEDPCC, 0xfc0007f800000000, 0xf000079800000000, 0x0, // VSX Vector Compare Greater Than or Equal To Double-Precision XX3-form (xvcmpgedp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGESP, 0xfc0007f800000000, 0xf000029800000000, 0x0, // VSX Vector Compare Greater Than or Equal To Single-Precision XX3-form (xvcmpgesp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGESPCC, 0xfc0007f800000000, 0xf000069800000000, 0x0, // VSX Vector Compare Greater Than or Equal To Single-Precision XX3-form (xvcmpgesp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGTDP, 0xfc0007f800000000, 0xf000035800000000, 0x0, // VSX Vector Compare Greater Than Double-Precision XX3-form (xvcmpgtdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGTDPCC, 0xfc0007f800000000, 0xf000075800000000, 0x0, // VSX Vector Compare Greater Than Double-Precision XX3-form (xvcmpgtdp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGTSP, 0xfc0007f800000000, 0xf000025800000000, 0x0, // VSX Vector Compare Greater Than Single-Precision XX3-form (xvcmpgtsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCMPGTSPCC, 0xfc0007f800000000, 0xf000065800000000, 0x0, // VSX Vector Compare Greater Than Single-Precision XX3-form (xvcmpgtsp. XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCPSGNDP, 0xfc0007f800000000, 0xf000078000000000, 0x0, // VSX Vector Copy Sign Double-Precision XX3-form (xvcpsgndp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCPSGNSP, 0xfc0007f800000000, 0xf000068000000000, 0x0, // VSX Vector Copy Sign Single-Precision XX3-form (xvcpsgnsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVCVDPSP, 0xfc0007fc00000000, 0xf000062400000000, 0x1f000000000000, // VSX Vector Convert with round Double-Precision to Single-Precision format XX2-form (xvcvdpsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVDPSXDS, 0xfc0007fc00000000, 0xf000076000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Double-Precision to Signed Doubleword format XX2-form (xvcvdpsxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVDPSXWS, 0xfc0007fc00000000, 0xf000036000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Double-Precision to Signed Word format XX2-form (xvcvdpsxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVDPUXDS, 0xfc0007fc00000000, 0xf000072000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Double-Precision to Unsigned Doubleword format XX2-form (xvcvdpuxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVDPUXWS, 0xfc0007fc00000000, 0xf000032000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Double-Precision to Unsigned Word format XX2-form (xvcvdpuxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPDP, 0xfc0007fc00000000, 0xf000072400000000, 0x1f000000000000, // VSX Vector Convert Single-Precision to Double-Precision format XX2-form (xvcvspdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPSXDS, 0xfc0007fc00000000, 0xf000066000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Single-Precision to Signed Doubleword format XX2-form (xvcvspsxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPSXWS, 0xfc0007fc00000000, 0xf000026000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Single-Precision to Signed Word format XX2-form (xvcvspsxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPUXDS, 0xfc0007fc00000000, 0xf000062000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Single-Precision to Unsigned Doubleword format XX2-form (xvcvspuxds XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSPUXWS, 0xfc0007fc00000000, 0xf000022000000000, 0x1f000000000000, // VSX Vector Convert with round to zero Single-Precision to Unsigned Word format XX2-form (xvcvspuxws XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSXDDP, 0xfc0007fc00000000, 0xf00007e000000000, 0x1f000000000000, // VSX Vector Convert with round Signed Doubleword to Double-Precision format XX2-form (xvcvsxddp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSXDSP, 0xfc0007fc00000000, 0xf00006e000000000, 0x1f000000000000, // VSX Vector Convert with round Signed Doubleword to Single-Precision format XX2-form (xvcvsxdsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSXWDP, 0xfc0007fc00000000, 0xf00003e000000000, 0x1f000000000000, // VSX Vector Convert Signed Word to Double-Precision format XX2-form (xvcvsxwdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVSXWSP, 0xfc0007fc00000000, 0xf00002e000000000, 0x1f000000000000, // VSX Vector Convert with round Signed Word to Single-Precision format XX2-form (xvcvsxwsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVUXDDP, 0xfc0007fc00000000, 0xf00007a000000000, 0x1f000000000000, // VSX Vector Convert with round Unsigned Doubleword to Double-Precision format XX2-form (xvcvuxddp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVUXDSP, 0xfc0007fc00000000, 0xf00006a000000000, 0x1f000000000000, // VSX Vector Convert with round Unsigned Doubleword to Single-Precision format XX2-form (xvcvuxdsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVUXWDP, 0xfc0007fc00000000, 0xf00003a000000000, 0x1f000000000000, // VSX Vector Convert Unsigned Word to Double-Precision format XX2-form (xvcvuxwdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVCVUXWSP, 0xfc0007fc00000000, 0xf00002a000000000, 0x1f000000000000, // VSX Vector Convert with round Unsigned Word to Single-Precision format XX2-form (xvcvuxwsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVDIVDP, 0xfc0007f800000000, 0xf00003c000000000, 0x0, // VSX Vector Divide Double-Precision XX3-form (xvdivdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVDIVSP, 0xfc0007f800000000, 0xf00002c000000000, 0x0, // VSX Vector Divide Single-Precision XX3-form (xvdivsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMADDADP, 0xfc0007f800000000, 0xf000030800000000, 0x0, // VSX Vector Multiply-Add Type-A Double-Precision XX3-form (xvmaddadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMADDASP, 0xfc0007f800000000, 0xf000020800000000, 0x0, // VSX Vector Multiply-Add Type-A Single-Precision XX3-form (xvmaddasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMADDMDP, 0xfc0007f800000000, 0xf000034800000000, 0x0, // VSX Vector Multiply-Add Type-M Double-Precision XX3-form (xvmaddmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMADDMSP, 0xfc0007f800000000, 0xf000024800000000, 0x0, // VSX Vector Multiply-Add Type-M Single-Precision XX3-form (xvmaddmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMAXDP, 0xfc0007f800000000, 0xf000070000000000, 0x0, // VSX Vector Maximum Double-Precision XX3-form (xvmaxdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMAXSP, 0xfc0007f800000000, 0xf000060000000000, 0x0, // VSX Vector Maximum Single-Precision XX3-form (xvmaxsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMINDP, 0xfc0007f800000000, 0xf000074000000000, 0x0, // VSX Vector Minimum Double-Precision XX3-form (xvmindp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMINSP, 0xfc0007f800000000, 0xf000064000000000, 0x0, // VSX Vector Minimum Single-Precision XX3-form (xvminsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMSUBADP, 0xfc0007f800000000, 0xf000038800000000, 0x0, // VSX Vector Multiply-Subtract Type-A Double-Precision XX3-form (xvmsubadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMSUBASP, 0xfc0007f800000000, 0xf000028800000000, 0x0, // VSX Vector Multiply-Subtract Type-A Single-Precision XX3-form (xvmsubasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMSUBMDP, 0xfc0007f800000000, 0xf00003c800000000, 0x0, // VSX Vector Multiply-Subtract Type-M Double-Precision XX3-form (xvmsubmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMSUBMSP, 0xfc0007f800000000, 0xf00002c800000000, 0x0, // VSX Vector Multiply-Subtract Type-M Single-Precision XX3-form (xvmsubmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMULDP, 0xfc0007f800000000, 0xf000038000000000, 0x0, // VSX Vector Multiply Double-Precision XX3-form (xvmuldp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVMULSP, 0xfc0007f800000000, 0xf000028000000000, 0x0, // VSX Vector Multiply Single-Precision XX3-form (xvmulsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNABSDP, 0xfc0007fc00000000, 0xf00007a400000000, 0x1f000000000000, // VSX Vector Negative Absolute Double-Precision XX2-form (xvnabsdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVNABSSP, 0xfc0007fc00000000, 0xf00006a400000000, 0x1f000000000000, // VSX Vector Negative Absolute Single-Precision XX2-form (xvnabssp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVNEGDP, 0xfc0007fc00000000, 0xf00007e400000000, 0x1f000000000000, // VSX Vector Negate Double-Precision XX2-form (xvnegdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVNEGSP, 0xfc0007fc00000000, 0xf00006e400000000, 0x1f000000000000, // VSX Vector Negate Single-Precision XX2-form (xvnegsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVNMADDADP, 0xfc0007f800000000, 0xf000070800000000, 0x0, // VSX Vector Negative Multiply-Add Type-A Double-Precision XX3-form (xvnmaddadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMADDASP, 0xfc0007f800000000, 0xf000060800000000, 0x0, // VSX Vector Negative Multiply-Add Type-A Single-Precision XX3-form (xvnmaddasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMADDMDP, 0xfc0007f800000000, 0xf000074800000000, 0x0, // VSX Vector Negative Multiply-Add Type-M Double-Precision XX3-form (xvnmaddmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMADDMSP, 0xfc0007f800000000, 0xf000064800000000, 0x0, // VSX Vector Negative Multiply-Add Type-M Single-Precision XX3-form (xvnmaddmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMSUBADP, 0xfc0007f800000000, 0xf000078800000000, 0x0, // VSX Vector Negative Multiply-Subtract Type-A Double-Precision XX3-form (xvnmsubadp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMSUBASP, 0xfc0007f800000000, 0xf000068800000000, 0x0, // VSX Vector Negative Multiply-Subtract Type-A Single-Precision XX3-form (xvnmsubasp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMSUBMDP, 0xfc0007f800000000, 0xf00007c800000000, 0x0, // VSX Vector Negative Multiply-Subtract Type-M Double-Precision XX3-form (xvnmsubmdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVNMSUBMSP, 0xfc0007f800000000, 0xf00006c800000000, 0x0, // VSX Vector Negative Multiply-Subtract Type-M Single-Precision XX3-form (xvnmsubmsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVRDPI, 0xfc0007fc00000000, 0xf000032400000000, 0x1f000000000000, // VSX Vector Round to Double-Precision Integer using round to Nearest Away XX2-form (xvrdpi XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRDPIC, 0xfc0007fc00000000, 0xf00003ac00000000, 0x1f000000000000, // VSX Vector Round to Double-Precision Integer Exact using Current rounding mode XX2-form (xvrdpic XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRDPIM, 0xfc0007fc00000000, 0xf00003e400000000, 0x1f000000000000, // VSX Vector Round to Double-Precision Integer using round toward -Infinity XX2-form (xvrdpim XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRDPIP, 0xfc0007fc00000000, 0xf00003a400000000, 0x1f000000000000, // VSX Vector Round to Double-Precision Integer using round toward +Infinity XX2-form (xvrdpip XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRDPIZ, 0xfc0007fc00000000, 0xf000036400000000, 0x1f000000000000, // VSX Vector Round to Double-Precision Integer using round toward Zero XX2-form (xvrdpiz XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVREDP, 0xfc0007fc00000000, 0xf000036800000000, 0x1f000000000000, // VSX Vector Reciprocal Estimate Double-Precision XX2-form (xvredp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRESP, 0xfc0007fc00000000, 0xf000026800000000, 0x1f000000000000, // VSX Vector Reciprocal Estimate Single-Precision XX2-form (xvresp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSPI, 0xfc0007fc00000000, 0xf000022400000000, 0x1f000000000000, // VSX Vector Round to Single-Precision Integer using round to Nearest Away XX2-form (xvrspi XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSPIC, 0xfc0007fc00000000, 0xf00002ac00000000, 0x1f000000000000, // VSX Vector Round to Single-Precision Integer Exact using Current rounding mode XX2-form (xvrspic XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSPIM, 0xfc0007fc00000000, 0xf00002e400000000, 0x1f000000000000, // VSX Vector Round to Single-Precision Integer using round toward -Infinity XX2-form (xvrspim XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSPIP, 0xfc0007fc00000000, 0xf00002a400000000, 0x1f000000000000, // VSX Vector Round to Single-Precision Integer using round toward +Infinity XX2-form (xvrspip XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSPIZ, 0xfc0007fc00000000, 0xf000026400000000, 0x1f000000000000, // VSX Vector Round to Single-Precision Integer using round toward Zero XX2-form (xvrspiz XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSQRTEDP, 0xfc0007fc00000000, 0xf000032800000000, 0x1f000000000000, // VSX Vector Reciprocal Square Root Estimate Double-Precision XX2-form (xvrsqrtedp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVRSQRTESP, 0xfc0007fc00000000, 0xf000022800000000, 0x1f000000000000, // VSX Vector Reciprocal Square Root Estimate Single-Precision XX2-form (xvrsqrtesp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVSQRTDP, 0xfc0007fc00000000, 0xf000032c00000000, 0x1f000000000000, // VSX Vector Square Root Double-Precision XX2-form (xvsqrtdp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVSQRTSP, 0xfc0007fc00000000, 0xf000022c00000000, 0x1f000000000000, // VSX Vector Square Root Single-Precision XX2-form (xvsqrtsp XT,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20}},
	{XVSUBDP, 0xfc0007f800000000, 0xf000034000000000, 0x0, // VSX Vector Subtract Double-Precision XX3-form (xvsubdp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVSUBSP, 0xfc0007f800000000, 0xf000024000000000, 0x0, // VSX Vector Subtract Single-Precision XX3-form (xvsubsp XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVTDIVDP, 0xfc0007f800000000, 0xf00003e800000000, 0x60000100000000, // VSX Vector Test for software Divide Double-Precision XX3-form (xvtdivdp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVTDIVSP, 0xfc0007f800000000, 0xf00002e800000000, 0x60000100000000, // VSX Vector Test for software Divide Single-Precision XX3-form (xvtdivsp BF,XA,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XVTSQRTDP, 0xfc0007fc00000000, 0xf00003a800000000, 0x7f000100000000, // VSX Vector Test for software Square Root Double-Precision XX2-form (xvtsqrtdp BF,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20}},
	{XVTSQRTSP, 0xfc0007fc00000000, 0xf00002a800000000, 0x7f000100000000, // VSX Vector Test for software Square Root Single-Precision XX2-form (xvtsqrtsp BF,XB)
		[6]*argField{ap_CondRegField_6_8, ap_VecSReg_30_30_16_20}},
	{XXLAND, 0xfc0007f800000000, 0xf000041000000000, 0x0, // VSX Vector Logical AND XX3-form (xxland XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLANDC, 0xfc0007f800000000, 0xf000045000000000, 0x0, // VSX Vector Logical AND with Complement XX3-form (xxlandc XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLNOR, 0xfc0007f800000000, 0xf000051000000000, 0x0, // VSX Vector Logical NOR XX3-form (xxlnor XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLOR, 0xfc0007f800000000, 0xf000049000000000, 0x0, // VSX Vector Logical OR XX3-form (xxlor XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXLXOR, 0xfc0007f800000000, 0xf00004d000000000, 0x0, // VSX Vector Logical XOR XX3-form (xxlxor XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXMRGHW, 0xfc0007f800000000, 0xf000009000000000, 0x0, // VSX Vector Merge High Word XX3-form (xxmrghw XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXMRGLW, 0xfc0007f800000000, 0xf000019000000000, 0x0, // VSX Vector Merge Low Word XX3-form (xxmrglw XT,XA,XB)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20}},
	{XXPERMDI, 0xfc0004f800000000, 0xf000005000000000, 0x0, // VSX Vector Permute Doubleword Immediate XX3-form (xxpermdi XT,XA,XB,DM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_22_23}},
	{XXSEL, 0xfc00003000000000, 0xf000003000000000, 0x0, // VSX Vector Select XX4-form (xxsel XT,XA,XB,XC)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20, ap_VecSReg_28_28_21_25}},
	{XXSLDWI, 0xfc0004f800000000, 0xf000001000000000, 0x0, // VSX Vector Shift Left Double by Word Immediate XX3-form (xxsldwi XT,XA,XB,SHW)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_29_29_11_15, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_22_23}},
	{XXSPLTW, 0xfc0007fc00000000, 0xf000029000000000, 0x1c000000000000, // VSX Vector Splat Word XX2-form (xxspltw XT,XB,UIM)
		[6]*argField{ap_VecSReg_31_31_6_10, ap_VecSReg_30_30_16_20, ap_ImmUnsigned_14_15}},
	{CMPB, 0xfc0007fe00000000, 0x7c0003f800000000, 0x100000000, // Compare Bytes X-form (cmpb RA,RS,RB)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10, ap_Reg_16_20}},
	{DADD, 0xfc0007ff00000000, 0xec00000400000000, 0x0, // DFP Add X-form (dadd FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DADDCC, 0xfc0007ff00000000, 0xec00000500000000, 0x0, // DFP Add X-form (dadd. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DADDQ, 0xfc0007ff00000000, 0xfc00000400000000, 0x0, // DFP Add Quad X-form (daddq FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DADDQCC, 0xfc0007ff00000000, 0xfc00000500000000, 0x0, // DFP Add Quad X-form (daddq. FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DCFFIXQ, 0xfc0007ff00000000, 0xfc00064400000000, 0x1f000000000000, // DFP Convert From Fixed Quad X-form (dcffixq FRTp,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCFFIXQCC, 0xfc0007ff00000000, 0xfc00064500000000, 0x1f000000000000, // DFP Convert From Fixed Quad X-form (dcffixq. FRTp,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCMPO, 0xfc0007fe00000000, 0xec00010400000000, 0x60000100000000, // DFP Compare Ordered X-form (dcmpo BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DCMPOQ, 0xfc0007fe00000000, 0xfc00010400000000, 0x60000100000000, // DFP Compare Ordered Quad X-form (dcmpoq BF,FRAp,FRBp)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DCMPU, 0xfc0007fe00000000, 0xec00050400000000, 0x60000100000000, // DFP Compare Unordered X-form (dcmpu BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DCMPUQ, 0xfc0007fe00000000, 0xfc00050400000000, 0x60000100000000, // DFP Compare Unordered Quad X-form (dcmpuq BF,FRAp,FRBp)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DCTDP, 0xfc0007ff00000000, 0xec00020400000000, 0x1f000000000000, // DFP Convert To DFP Long X-form (dctdp FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTDPCC, 0xfc0007ff00000000, 0xec00020500000000, 0x1f000000000000, // DFP Convert To DFP Long X-form (dctdp. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTFIX, 0xfc0007ff00000000, 0xec00024400000000, 0x1f000000000000, // DFP Convert To Fixed X-form (dctfix FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTFIXCC, 0xfc0007ff00000000, 0xec00024500000000, 0x1f000000000000, // DFP Convert To Fixed X-form (dctfix. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTFIXQ, 0xfc0007ff00000000, 0xfc00024400000000, 0x1f000000000000, // DFP Convert To Fixed Quad X-form (dctfixq FRT,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTFIXQCC, 0xfc0007ff00000000, 0xfc00024500000000, 0x1f000000000000, // DFP Convert To Fixed Quad X-form (dctfixq. FRT,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTQPQ, 0xfc0007ff00000000, 0xfc00020400000000, 0x1f000000000000, // DFP Convert To DFP Extended X-form (dctqpq FRTp,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DCTQPQCC, 0xfc0007ff00000000, 0xfc00020500000000, 0x1f000000000000, // DFP Convert To DFP Extended X-form (dctqpq. FRTp,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DDEDPD, 0xfc0007ff00000000, 0xec00028400000000, 0x7000000000000, // DFP Decode DPD To BCD X-form (ddedpd SP,FRT,FRB)
		[6]*argField{ap_ImmUnsigned_11_12, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DDEDPDCC, 0xfc0007ff00000000, 0xec00028500000000, 0x7000000000000, // DFP Decode DPD To BCD X-form (ddedpd. SP,FRT,FRB)
		[6]*argField{ap_ImmUnsigned_11_12, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DDEDPDQ, 0xfc0007ff00000000, 0xfc00028400000000, 0x7000000000000, // DFP Decode DPD To BCD Quad X-form (ddedpdq SP,FRTp,FRBp)
		[6]*argField{ap_ImmUnsigned_11_12, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DDEDPDQCC, 0xfc0007ff00000000, 0xfc00028500000000, 0x7000000000000, // DFP Decode DPD To BCD Quad X-form (ddedpdq. SP,FRTp,FRBp)
		[6]*argField{ap_ImmUnsigned_11_12, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DDIV, 0xfc0007ff00000000, 0xec00044400000000, 0x0, // DFP Divide X-form (ddiv FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DDIVCC, 0xfc0007ff00000000, 0xec00044500000000, 0x0, // DFP Divide X-form (ddiv. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DDIVQ, 0xfc0007ff00000000, 0xfc00044400000000, 0x0, // DFP Divide Quad X-form (ddivq FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DDIVQCC, 0xfc0007ff00000000, 0xfc00044500000000, 0x0, // DFP Divide Quad X-form (ddivq. FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DENBCD, 0xfc0007ff00000000, 0xec00068400000000, 0xf000000000000, // DFP Encode BCD To DPD X-form (denbcd S,FRT,FRB)
		[6]*argField{ap_ImmUnsigned_11_11, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DENBCDCC, 0xfc0007ff00000000, 0xec00068500000000, 0xf000000000000, // DFP Encode BCD To DPD X-form (denbcd. S,FRT,FRB)
		[6]*argField{ap_ImmUnsigned_11_11, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DENBCDQ, 0xfc0007ff00000000, 0xfc00068400000000, 0xf000000000000, // DFP Encode BCD To DPD Quad X-form (denbcdq S,FRTp,FRBp)
		[6]*argField{ap_ImmUnsigned_11_11, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DENBCDQCC, 0xfc0007ff00000000, 0xfc00068500000000, 0xf000000000000, // DFP Encode BCD To DPD Quad X-form (denbcdq. S,FRTp,FRBp)
		[6]*argField{ap_ImmUnsigned_11_11, ap_FPReg_6_10, ap_FPReg_16_20}},
	{DIEX, 0xfc0007ff00000000, 0xec0006c400000000, 0x0, // DFP Insert Biased Exponent X-form (diex FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DIEXCC, 0xfc0007ff00000000, 0xec0006c500000000, 0x0, // DFP Insert Biased Exponent X-form (diex. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DIEXQCC, 0xfc0007ff00000000, 0xfc0006c500000000, 0x0, // DFP Insert Biased Exponent Quad X-form (diexq. FRTp,FRA,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DIEXQ, 0xfc0007fe00000000, 0xfc0006c400000000, 0x0, // DFP Insert Biased Exponent Quad X-form (diexq FRTp,FRA,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DMUL, 0xfc0007ff00000000, 0xec00004400000000, 0x0, // DFP Multiply X-form (dmul FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DMULCC, 0xfc0007ff00000000, 0xec00004500000000, 0x0, // DFP Multiply X-form (dmul. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DMULQ, 0xfc0007ff00000000, 0xfc00004400000000, 0x0, // DFP Multiply Quad X-form (dmulq FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DMULQCC, 0xfc0007ff00000000, 0xfc00004500000000, 0x0, // DFP Multiply Quad X-form (dmulq. FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DQUA, 0xfc0001ff00000000, 0xec00000600000000, 0x0, // DFP Quantize Z23-form (dqua FRT,FRA,FRB,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUACC, 0xfc0001ff00000000, 0xec00000700000000, 0x0, // DFP Quantize Z23-form (dqua. FRT,FRA,FRB,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAI, 0xfc0001ff00000000, 0xec00008600000000, 0x0, // DFP Quantize Immediate Z23-form (dquai TE,FRT,FRB,RMC)
		[6]*argField{ap_ImmSigned_11_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAICC, 0xfc0001ff00000000, 0xec00008700000000, 0x0, // DFP Quantize Immediate Z23-form (dquai. TE,FRT,FRB,RMC)
		[6]*argField{ap_ImmSigned_11_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAIQ, 0xfc0001ff00000000, 0xfc00008600000000, 0x0, // DFP Quantize Immediate Quad Z23-form (dquaiq TE,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmSigned_11_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAIQCC, 0xfc0001ff00000000, 0xfc00008700000000, 0x0, // DFP Quantize Immediate Quad Z23-form (dquaiq. TE,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmSigned_11_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAQ, 0xfc0001ff00000000, 0xfc00000600000000, 0x0, // DFP Quantize Quad Z23-form (dquaq FRTp,FRAp,FRBp,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DQUAQCC, 0xfc0001ff00000000, 0xfc00000700000000, 0x0, // DFP Quantize Quad Z23-form (dquaq. FRTp,FRAp,FRBp,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRDPQ, 0xfc0007ff00000000, 0xfc00060400000000, 0x1f000000000000, // DFP Round To DFP Long X-form (drdpq FRTp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DRDPQCC, 0xfc0007ff00000000, 0xfc00060500000000, 0x1f000000000000, // DFP Round To DFP Long X-form (drdpq. FRTp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DRINTN, 0xfc0001ff00000000, 0xec0001c600000000, 0x1e000000000000, // DFP Round To FP Integer Without Inexact Z23-form (drintn R,FRT,FRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTNCC, 0xfc0001ff00000000, 0xec0001c700000000, 0x1e000000000000, // DFP Round To FP Integer Without Inexact Z23-form (drintn. R,FRT,FRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTNQ, 0xfc0001ff00000000, 0xfc0001c600000000, 0x1e000000000000, // DFP Round To FP Integer Without Inexact Quad Z23-form (drintnq R,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTNQCC, 0xfc0001ff00000000, 0xfc0001c700000000, 0x1e000000000000, // DFP Round To FP Integer Without Inexact Quad Z23-form (drintnq. R,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTX, 0xfc0001ff00000000, 0xec0000c600000000, 0x1e000000000000, // DFP Round To FP Integer With Inexact Z23-form (drintx R,FRT,FRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTXCC, 0xfc0001ff00000000, 0xec0000c700000000, 0x1e000000000000, // DFP Round To FP Integer With Inexact Z23-form (drintx. R,FRT,FRB,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTXQ, 0xfc0001ff00000000, 0xfc0000c600000000, 0x1e000000000000, // DFP Round To FP Integer With Inexact Quad Z23-form (drintxq R,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRINTXQCC, 0xfc0001ff00000000, 0xfc0000c700000000, 0x1e000000000000, // DFP Round To FP Integer With Inexact Quad Z23-form (drintxq. R,FRTp,FRBp,RMC)
		[6]*argField{ap_ImmUnsigned_15_15, ap_FPReg_6_10, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRRND, 0xfc0001ff00000000, 0xec00004600000000, 0x0, // DFP Reround Z23-form (drrnd FRT,FRA,FRB,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRRNDCC, 0xfc0001ff00000000, 0xec00004700000000, 0x0, // DFP Reround Z23-form (drrnd. FRT,FRA,FRB,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRRNDQ, 0xfc0001ff00000000, 0xfc00004600000000, 0x0, // DFP Reround Quad Z23-form (drrndq FRTp,FRA,FRBp,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRRNDQCC, 0xfc0001ff00000000, 0xfc00004700000000, 0x0, // DFP Reround Quad Z23-form (drrndq. FRTp,FRA,FRBp,RMC)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20, ap_ImmUnsigned_21_22}},
	{DRSP, 0xfc0007ff00000000, 0xec00060400000000, 0x1f000000000000, // DFP Round To DFP Short X-form (drsp FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DRSPCC, 0xfc0007ff00000000, 0xec00060500000000, 0x1f000000000000, // DFP Round To DFP Short X-form (drsp. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DSCLI, 0xfc0003ff00000000, 0xec00008400000000, 0x0, // DFP Shift Significand Left Immediate Z22-form (dscli FRT,FRA,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCLICC, 0xfc0003ff00000000, 0xec00008500000000, 0x0, // DFP Shift Significand Left Immediate Z22-form (dscli. FRT,FRA,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCLIQ, 0xfc0003ff00000000, 0xfc00008400000000, 0x0, // DFP Shift Significand Left Immediate Quad Z22-form (dscliq FRTp,FRAp,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCLIQCC, 0xfc0003ff00000000, 0xfc00008500000000, 0x0, // DFP Shift Significand Left Immediate Quad Z22-form (dscliq. FRTp,FRAp,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCRI, 0xfc0003ff00000000, 0xec0000c400000000, 0x0, // DFP Shift Significand Right Immediate Z22-form (dscri FRT,FRA,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCRICC, 0xfc0003ff00000000, 0xec0000c500000000, 0x0, // DFP Shift Significand Right Immediate Z22-form (dscri. FRT,FRA,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCRIQ, 0xfc0003ff00000000, 0xfc0000c400000000, 0x0, // DFP Shift Significand Right Immediate Quad Z22-form (dscriq FRTp,FRAp,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSCRIQCC, 0xfc0003ff00000000, 0xfc0000c500000000, 0x0, // DFP Shift Significand Right Immediate Quad Z22-form (dscriq. FRTp,FRAp,SH)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DSUB, 0xfc0007ff00000000, 0xec00040400000000, 0x0, // DFP Subtract X-form (dsub FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DSUBCC, 0xfc0007ff00000000, 0xec00040500000000, 0x0, // DFP Subtract X-form (dsub. FRT,FRA,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DSUBQ, 0xfc0007ff00000000, 0xfc00040400000000, 0x0, // DFP Subtract Quad X-form (dsubq FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DSUBQCC, 0xfc0007ff00000000, 0xfc00040500000000, 0x0, // DFP Subtract Quad X-form (dsubq. FRTp,FRAp,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DTSTDC, 0xfc0003fe00000000, 0xec00018400000000, 0x60000100000000, // DFP Test Data Class Z22-form (dtstdc BF,FRA,DCM)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DTSTDCQ, 0xfc0003fe00000000, 0xfc00018400000000, 0x60000100000000, // DFP Test Data Class Quad Z22-form (dtstdcq BF,FRAp,DCM)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DTSTDG, 0xfc0003fe00000000, 0xec0001c400000000, 0x60000100000000, // DFP Test Data Group Z22-form (dtstdg BF,FRA,DGM)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DTSTDGQ, 0xfc0003fe00000000, 0xfc0001c400000000, 0x60000100000000, // DFP Test Data Group Quad Z22-form (dtstdgq BF,FRAp,DGM)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_ImmUnsigned_16_21}},
	{DTSTEX, 0xfc0007fe00000000, 0xec00014400000000, 0x60000100000000, // DFP Test Exponent X-form (dtstex BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DTSTEXQ, 0xfc0007fe00000000, 0xfc00014400000000, 0x60000100000000, // DFP Test Exponent Quad X-form (dtstexq BF,FRAp,FRBp)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DTSTSF, 0xfc0007fe00000000, 0xec00054400000000, 0x60000100000000, // DFP Test Significance X-form (dtstsf BF,FRA,FRB)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DTSTSFQ, 0xfc0007fe00000000, 0xfc00054400000000, 0x60000100000000, // DFP Test Significance Quad X-form (dtstsfq BF,FRA,FRBp)
		[6]*argField{ap_CondRegField_6_8, ap_FPReg_11_15, ap_FPReg_16_20}},
	{DXEX, 0xfc0007ff00000000, 0xec0002c400000000, 0x1f000000000000, // DFP Extract Biased Exponent X-form (dxex FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DXEXCC, 0xfc0007ff00000000, 0xec0002c500000000, 0x1f000000000000, // DFP Extract Biased Exponent X-form (dxex. FRT,FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DXEXQ, 0xfc0007ff00000000, 0xfc0002c400000000, 0x1f000000000000, // DFP Extract Biased Exponent Quad X-form (dxexq FRT,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{DXEXQCC, 0xfc0007ff00000000, 0xfc0002c500000000, 0x1f000000000000, // DFP Extract Biased Exponent Quad X-form (dxexq. FRT,FRBp)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_16_20}},
	{FCPSGN, 0xfc0007ff00000000, 0xfc00001000000000, 0x0, // Floating Copy Sign X-form (fcpsgn FRT, FRA, FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{FCPSGNCC, 0xfc0007ff00000000, 0xfc00001100000000, 0x0, // Floating Copy Sign X-form (fcpsgn. FRT, FRA, FRB)
		[6]*argField{ap_FPReg_6_10, ap_FPReg_11_15, ap_FPReg_16_20}},
	{LBZCIX, 0xfc0007fe00000000, 0x7c0006aa00000000, 0x100000000, // Load Byte & Zero Caching Inhibited Indexed X-form (lbzcix RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LDCIX, 0xfc0007fe00000000, 0x7c0006ea00000000, 0x100000000, // Load Doubleword Caching Inhibited Indexed X-form (ldcix RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFDP, 0xfc00000300000000, 0xe400000000000000, 0x0, // Load Floating-Point Double Pair DS-form (lfdp FRTp,DS(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{LFDPX, 0xfc0007fe00000000, 0x7c00062e00000000, 0x100000000, // Load Floating-Point Double Pair Indexed X-form (lfdpx FRTp,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LFIWAX, 0xfc0007fe00000000, 0x7c0006ae00000000, 0x100000000, // Load Floating-Point as Integer Word Algebraic Indexed X-form (lfiwax FRT,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LHZCIX, 0xfc0007fe00000000, 0x7c00066a00000000, 0x100000000, // Load Halfword & Zero Caching Inhibited Indexed X-form (lhzcix RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LWZCIX, 0xfc0007fe00000000, 0x7c00062a00000000, 0x100000000, // Load Word & Zero Caching Inhibited Indexed X-form (lwzcix RT,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{PRTYD, 0xfc0007fe00000000, 0x7c00017400000000, 0xf80100000000, // Parity Doubleword X-form (prtyd RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{PRTYW, 0xfc0007fe00000000, 0x7c00013400000000, 0xf80100000000, // Parity Word X-form (prtyw RA,RS)
		[6]*argField{ap_Reg_11_15, ap_Reg_6_10}},
	{SLBFEECC, 0xfc0007ff00000000, 0x7c0007a700000000, 0x1f000000000000, // SLB Find Entry ESID X-form (slbfee. RT,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_16_20}},
	{STBCIX, 0xfc0007fe00000000, 0x7c0007aa00000000, 0x100000000, // Store Byte Caching Inhibited Indexed X-form (stbcix RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STDCIX, 0xfc0007fe00000000, 0x7c0007ea00000000, 0x100000000, // Store Doubleword Caching Inhibited Indexed X-form (stdcix RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STFDP, 0xfc00000300000000, 0xf400000000000000, 0x0, // Store Floating-Point Double Pair DS-form (stfdp FRSp,DS(RA))
		[6]*argField{ap_FPReg_6_10, ap_Offset_16_29_shift2, ap_Reg_11_15}},
	{STFDPX, 0xfc0007fe00000000, 0x7c00072e00000000, 0x100000000, // Store Floating-Point Double Pair Indexed X-form (stfdpx FRSp,RA,RB)
		[6]*argField{ap_FPReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STHCIX, 0xfc0007fe00000000, 0x7c00076a00000000, 0x100000000, // Store Halfword Caching Inhibited Indexed X-form (sthcix RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STWCIX, 0xfc0007fe00000000, 0x7c00072a00000000, 0x100000000, // Store Word Caching Inhibited Indexed X-form (stwcix RS,RA,RB)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{ISEL, 0xfc00003e00000000, 0x7c00001e00000000, 0x100000000, // Integer Select A-form (isel RT,RA,RB,BC)
		[6]*argField{ap_Reg_6_10, ap_Reg_11_15, ap_Reg_16_20, ap_CondRegBit_21_25}},
	{LVEBX, 0xfc0007fe00000000, 0x7c00000e00000000, 0x100000000, // Load Vector Element Byte Indexed X-form (lvebx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVEHX, 0xfc0007fe00000000, 0x7c00004e00000000, 0x100000000, // Load Vector Element Halfword Indexed X-form (lvehx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVEWX, 0xfc0007fe00000000, 0x7c00008e00000000, 0x100000000, // Load Vector Element Word Indexed X-form (lvewx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVSL, 0xfc0007fe00000000, 0x7c00000c00000000, 0x100000000, // Load Vector for Shift Left Indexed X-form (lvsl VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVSR, 0xfc0007fe00000000, 0x7c00004c00000000, 0x100000000, // Load Vector for Shift Right Indexed X-form (lvsr VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVX, 0xfc0007fe00000000, 0x7c0000ce00000000, 0x100000000, // Load Vector Indexed X-form (lvx VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{LVXL, 0xfc0007fe00000000, 0x7c0002ce00000000, 0x100000000, // Load Vector Indexed Last X-form (lvxl VRT,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{MFVSCR, 0xfc0007ff00000000, 0x1000060400000000, 0x1ff80000000000, // Move From Vector Status and Control Register VX-form (mfvscr VRT)
		[6]*argField{ap_VecReg_6_10}},
	{MTVSCR, 0xfc0007ff00000000, 0x1000064400000000, 0x3ff000000000000, // Move To Vector Status and Control Register VX-form (mtvscr VRB)
		[6]*argField{ap_VecReg_16_20}},
	{STVEBX, 0xfc0007fe00000000, 0x7c00010e00000000, 0x100000000, // Store Vector Element Byte Indexed X-form (stvebx VRS,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STVEHX, 0xfc0007fe00000000, 0x7c00014e00000000, 0x100000000, // Store Vector Element Halfword Indexed X-form (stvehx VRS,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STVEWX, 0xfc0007fe00000000, 0x7c00018e00000000, 0x100000000, // Store Vector Element Word Indexed X-form (stvewx VRS,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STVX, 0xfc0007fe00000000, 0x7c0001ce00000000, 0x100000000, // Store Vector Indexed X-form (stvx VRS,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{STVXL, 0xfc0007fe00000000, 0x7c0003ce00000000, 0x100000000, // Store Vector Indexed Last X-form (stvxl VRS,RA,RB)
		[6]*argField{ap_VecReg_6_10, ap_Reg_11_15, ap_Reg_16_20}},
	{TLBIEL, 0xfc0007fe00000000, 0x7c00022400000000, 0x10000100000000, // TLB Invalidate Entry Local X-form (tlbiel RB,RS,RIC,PRS,R)
		[6]*argField{ap_Reg_16_20, ap_Reg_6_10, ap_ImmUnsigned_12_13, ap_ImmUnsigned_14_14, ap_ImmUnsigned_15_15}},
	{VADDCUW, 0xfc0007ff00000000, 0x1000018000000000, 0x0, // Vector Add & write Carry Unsigned Word VX-form (vaddcuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDFP, 0xfc0007ff00000000, 0x1000000a00000000, 0x0, // Vector Add Floating-Point VX-form (vaddfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDSBS, 0xfc0007ff00000000, 0x1000030000000000, 0x0, // Vector Add Signed Byte Saturate VX-form (vaddsbs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDSHS, 0xfc0007ff00000000, 0x1000034000000000, 0x0, // Vector Add Signed Halfword Saturate VX-form (vaddshs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDSWS, 0xfc0007ff00000000, 0x1000038000000000, 0x0, // Vector Add Signed Word Saturate VX-form (vaddsws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUBM, 0xfc0007ff00000000, 0x1000000000000000, 0x0, // Vector Add Unsigned Byte Modulo VX-form (vaddubm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUBS, 0xfc0007ff00000000, 0x1000020000000000, 0x0, // Vector Add Unsigned Byte Saturate VX-form (vaddubs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUHM, 0xfc0007ff00000000, 0x1000004000000000, 0x0, // Vector Add Unsigned Halfword Modulo VX-form (vadduhm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUHS, 0xfc0007ff00000000, 0x1000024000000000, 0x0, // Vector Add Unsigned Halfword Saturate VX-form (vadduhs VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUWM, 0xfc0007ff00000000, 0x1000008000000000, 0x0, // Vector Add Unsigned Word Modulo VX-form (vadduwm VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VADDUWS, 0xfc0007ff00000000, 0x1000028000000000, 0x0, // Vector Add Unsigned Word Saturate VX-form (vadduws VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAND, 0xfc0007ff00000000, 0x1000040400000000, 0x0, // Vector Logical AND VX-form (vand VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VANDC, 0xfc0007ff00000000, 0x1000044400000000, 0x0, // Vector Logical AND with Complement VX-form (vandc VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGSB, 0xfc0007ff00000000, 0x1000050200000000, 0x0, // Vector Average Signed Byte VX-form (vavgsb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGSH, 0xfc0007ff00000000, 0x1000054200000000, 0x0, // Vector Average Signed Halfword VX-form (vavgsh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGSW, 0xfc0007ff00000000, 0x1000058200000000, 0x0, // Vector Average Signed Word VX-form (vavgsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGUB, 0xfc0007ff00000000, 0x1000040200000000, 0x0, // Vector Average Unsigned Byte VX-form (vavgub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGUH, 0xfc0007ff00000000, 0x1000044200000000, 0x0, // Vector Average Unsigned Halfword VX-form (vavguh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VAVGUW, 0xfc0007ff00000000, 0x1000048200000000, 0x0, // Vector Average Unsigned Word VX-form (vavguw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCFSX, 0xfc0007ff00000000, 0x1000034a00000000, 0x0, // Vector Convert with round to nearest From Signed Word to floating-point format VX-form (vcfsx VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{VCFUX, 0xfc0007ff00000000, 0x1000030a00000000, 0x0, // Vector Convert with round to nearest From Unsigned Word to floating-point format VX-form (vcfux VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{VCMPBFP, 0xfc0007ff00000000, 0x100003c600000000, 0x0, // Vector Compare Bounds Floating-Point VC-form (vcmpbfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPBFPCC, 0xfc0007ff00000000, 0x100007c600000000, 0x0, // Vector Compare Bounds Floating-Point VC-form (vcmpbfp. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQFP, 0xfc0007ff00000000, 0x100000c600000000, 0x0, // Vector Compare Equal Floating-Point VC-form (vcmpeqfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQFPCC, 0xfc0007ff00000000, 0x100004c600000000, 0x0, // Vector Compare Equal Floating-Point VC-form (vcmpeqfp. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUB, 0xfc0007ff00000000, 0x1000000600000000, 0x0, // Vector Compare Equal Unsigned Byte VC-form (vcmpequb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUBCC, 0xfc0007ff00000000, 0x1000040600000000, 0x0, // Vector Compare Equal Unsigned Byte VC-form (vcmpequb. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUH, 0xfc0007ff00000000, 0x1000004600000000, 0x0, // Vector Compare Equal Unsigned Halfword VC-form (vcmpequh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUHCC, 0xfc0007ff00000000, 0x1000044600000000, 0x0, // Vector Compare Equal Unsigned Halfword VC-form (vcmpequh. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUW, 0xfc0007ff00000000, 0x1000008600000000, 0x0, // Vector Compare Equal Unsigned Word VC-form (vcmpequw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPEQUWCC, 0xfc0007ff00000000, 0x1000048600000000, 0x0, // Vector Compare Equal Unsigned Word VC-form (vcmpequw. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGEFP, 0xfc0007ff00000000, 0x100001c600000000, 0x0, // Vector Compare Greater Than or Equal Floating-Point VC-form (vcmpgefp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGEFPCC, 0xfc0007ff00000000, 0x100005c600000000, 0x0, // Vector Compare Greater Than or Equal Floating-Point VC-form (vcmpgefp. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTFP, 0xfc0007ff00000000, 0x100002c600000000, 0x0, // Vector Compare Greater Than Floating-Point VC-form (vcmpgtfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTFPCC, 0xfc0007ff00000000, 0x100006c600000000, 0x0, // Vector Compare Greater Than Floating-Point VC-form (vcmpgtfp. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSB, 0xfc0007ff00000000, 0x1000030600000000, 0x0, // Vector Compare Greater Than Signed Byte VC-form (vcmpgtsb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSBCC, 0xfc0007ff00000000, 0x1000070600000000, 0x0, // Vector Compare Greater Than Signed Byte VC-form (vcmpgtsb. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSH, 0xfc0007ff00000000, 0x1000034600000000, 0x0, // Vector Compare Greater Than Signed Halfword VC-form (vcmpgtsh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSHCC, 0xfc0007ff00000000, 0x1000074600000000, 0x0, // Vector Compare Greater Than Signed Halfword VC-form (vcmpgtsh. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSW, 0xfc0007ff00000000, 0x1000038600000000, 0x0, // Vector Compare Greater Than Signed Word VC-form (vcmpgtsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTSWCC, 0xfc0007ff00000000, 0x1000078600000000, 0x0, // Vector Compare Greater Than Signed Word VC-form (vcmpgtsw. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUB, 0xfc0007ff00000000, 0x1000020600000000, 0x0, // Vector Compare Greater Than Unsigned Byte VC-form (vcmpgtub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUBCC, 0xfc0007ff00000000, 0x1000060600000000, 0x0, // Vector Compare Greater Than Unsigned Byte VC-form (vcmpgtub. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUH, 0xfc0007ff00000000, 0x1000024600000000, 0x0, // Vector Compare Greater Than Unsigned Halfword VC-form (vcmpgtuh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUHCC, 0xfc0007ff00000000, 0x1000064600000000, 0x0, // Vector Compare Greater Than Unsigned Halfword VC-form (vcmpgtuh. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUW, 0xfc0007ff00000000, 0x1000028600000000, 0x0, // Vector Compare Greater Than Unsigned Word VC-form (vcmpgtuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCMPGTUWCC, 0xfc0007ff00000000, 0x1000068600000000, 0x0, // Vector Compare Greater Than Unsigned Word VC-form (vcmpgtuw. VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VCTSXS, 0xfc0007ff00000000, 0x100003ca00000000, 0x0, // Vector Convert with round to zero from floating-point To Signed Word format Saturate VX-form (vctsxs VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{VCTUXS, 0xfc0007ff00000000, 0x1000038a00000000, 0x0, // Vector Convert with round to zero from floating-point To Unsigned Word format Saturate VX-form (vctuxs VRT,VRB,UIM)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20, ap_ImmUnsigned_11_15}},
	{VEXPTEFP, 0xfc0007ff00000000, 0x1000018a00000000, 0x1f000000000000, // Vector 2 Raised to the Exponent Estimate Floating-Point VX-form (vexptefp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VLOGEFP, 0xfc0007ff00000000, 0x100001ca00000000, 0x1f000000000000, // Vector Log Base 2 Estimate Floating-Point VX-form (vlogefp VRT,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_16_20}},
	{VMADDFP, 0xfc00003f00000000, 0x1000002e00000000, 0x0, // Vector Multiply-Add Floating-Point VA-form (vmaddfp VRT,VRA,VRC,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_21_25, ap_VecReg_16_20}},
	{VMAXFP, 0xfc0007ff00000000, 0x1000040a00000000, 0x0, // Vector Maximum Floating-Point VX-form (vmaxfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXSB, 0xfc0007ff00000000, 0x1000010200000000, 0x0, // Vector Maximum Signed Byte VX-form (vmaxsb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXSH, 0xfc0007ff00000000, 0x1000014200000000, 0x0, // Vector Maximum Signed Halfword VX-form (vmaxsh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXSW, 0xfc0007ff00000000, 0x1000018200000000, 0x0, // Vector Maximum Signed Word VX-form (vmaxsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXUB, 0xfc0007ff00000000, 0x1000000200000000, 0x0, // Vector Maximum Unsigned Byte VX-form (vmaxub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXUH, 0xfc0007ff00000000, 0x1000004200000000, 0x0, // Vector Maximum Unsigned Halfword VX-form (vmaxuh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMAXUW, 0xfc0007ff00000000, 0x1000008200000000, 0x0, // Vector Maximum Unsigned Word VX-form (vmaxuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMHADDSHS, 0xfc00003f00000000, 0x1000002000000000, 0x0, // Vector Multiply-High-Add Signed Halfword Saturate VA-form (vmhaddshs VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMHRADDSHS, 0xfc00003f00000000, 0x1000002100000000, 0x0, // Vector Multiply-High-Round-Add Signed Halfword Saturate VA-form (vmhraddshs VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMINFP, 0xfc0007ff00000000, 0x1000044a00000000, 0x0, // Vector Minimum Floating-Point VX-form (vminfp VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINSB, 0xfc0007ff00000000, 0x1000030200000000, 0x0, // Vector Minimum Signed Byte VX-form (vminsb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINSH, 0xfc0007ff00000000, 0x1000034200000000, 0x0, // Vector Minimum Signed Halfword VX-form (vminsh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINSW, 0xfc0007ff00000000, 0x1000038200000000, 0x0, // Vector Minimum Signed Word VX-form (vminsw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINUB, 0xfc0007ff00000000, 0x1000020200000000, 0x0, // Vector Minimum Unsigned Byte VX-form (vminub VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINUH, 0xfc0007ff00000000, 0x1000024200000000, 0x0, // Vector Minimum Unsigned Halfword VX-form (vminuh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMINUW, 0xfc0007ff00000000, 0x1000028200000000, 0x0, // Vector Minimum Unsigned Word VX-form (vminuw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMLADDUHM, 0xfc00003f00000000, 0x1000002200000000, 0x0, // Vector Multiply-Low-Add Unsigned Halfword Modulo VA-form (vmladduhm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMRGHB, 0xfc0007ff00000000, 0x1000000c00000000, 0x0, // Vector Merge High Byte VX-form (vmrghb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGHH, 0xfc0007ff00000000, 0x1000004c00000000, 0x0, // Vector Merge High Halfword VX-form (vmrghh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGHW, 0xfc0007ff00000000, 0x1000008c00000000, 0x0, // Vector Merge High Word VX-form (vmrghw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGLB, 0xfc0007ff00000000, 0x1000010c00000000, 0x0, // Vector Merge Low Byte VX-form (vmrglb VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGLH, 0xfc0007ff00000000, 0x1000014c00000000, 0x0, // Vector Merge Low Halfword VX-form (vmrglh VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMRGLW, 0xfc0007ff00000000, 0x1000018c00000000, 0x0, // Vector Merge Low Word VX-form (vmrglw VRT,VRA,VRB)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20}},
	{VMSUMMBM, 0xfc00003f00000000, 0x1000002500000000, 0x0, // Vector Multiply-Sum Mixed Byte Modulo VA-form (vmsummbm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMSUMSHM, 0xfc00003f00000000, 0x1000002800000000, 0x0, // Vector Multiply-Sum Signed Halfword Modulo VA-form (vmsumshm VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMSUMSHS, 0xfc00003f00000000, 0x1000002900000000, 0x0, // Vector Multiply-Sum Signed Halfword Saturate VA-form (vmsumshs VRT,VRA,VRB,VRC)
		[6]*argField{ap_VecReg_6_10, ap_VecReg_11_15, ap_VecReg_16_20, ap_VecReg_21_25}},
	{VMSUMUBM, 0xfc00003f00000000, 0x1000002400000000, 0x0, // Vector Multiply-Sum Unsigned Byte Modulo VA-form (vmsumubm VRT,VRA,VRB,VRC)
		[6]*argFi
"""




```