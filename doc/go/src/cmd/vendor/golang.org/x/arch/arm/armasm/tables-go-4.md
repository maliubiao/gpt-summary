Response:
The user is asking for a description of the functionality of a Go code snippet. This snippet appears to define a table of ARM assembly instructions. Each entry in the table seems to represent an instruction with its binary encoding, a mask, the number of operands, the instruction name, a condition code, and a structure describing the arguments.

Here's a breakdown of the thought process:

1. **Identify the Core Data Structure:** The code defines a slice of structs. Each struct likely represents a single ARM assembly instruction.

2. **Analyze the Struct Fields:**  Examine the fields within each struct:
    * `0x0ff000f0`: This looks like a hexadecimal number and could be a mask for instruction matching.
    * `0x06600f70`: Another hexadecimal number, potentially the binary encoding of the instruction.
    * `3`: An integer, probably the number of operands the instruction takes.
    * `UQSUB16_EQ`: A string, likely the name of the assembly instruction. The `_EQ` suffix suggests a conditional execution based on the "equal" flag.
    * `0x1c04`: Another hexadecimal number, potentially a condition code or additional flags.
    * `instArgs{arg_R_12, arg_R_16, arg_R_0}}`: This looks like a structure (`instArgs`) holding the arguments for the instruction. The names like `arg_R_12` suggest register operands.

3. **Infer the Purpose:** Based on the structure, the code likely implements a mechanism for:
    * **Decoding ARM assembly instructions:** The masks and encodings are crucial for identifying the instruction from its binary representation.
    * **Representing instruction properties:** The number of operands, instruction name, and arguments provide information about the instruction's syntax and usage.
    * **Conditional execution:** The `_EQ` suffix and the `cond:4|...` annotations suggest that these instructions can be executed conditionally based on processor flags.

4. **Hypothesize the Go Feature:** This kind of table-driven approach is common for implementing assemblers, disassemblers, or instruction set simulators. In Go, this could be part of a package that works with ARM assembly code.

5. **Construct a Go Example:**  Imagine a function that takes a binary instruction as input and uses this table to decode it. The example should illustrate how the table is used for pattern matching and extracting information. A simple function that tries to find a matching entry in the table would be a good demonstration.

6. **Address Command-Line Parameters:** Since this snippet is part of `cmd/vendor`, it's likely related to a command-line tool. Think about how such a tool might use this table. An assembler might take assembly source code as input, or a disassembler might take raw binary. The tool would then process these inputs, potentially using this table to perform its core function. However, *this specific snippet doesn't directly handle command-line arguments*. It's just a data table. So, the explanation should focus on *how a larger tool* might use this table in the context of command-line processing.

7. **Identify Potential Mistakes:**  Consider common errors when working with such tables:
    * **Incorrect mask or encoding:** A mismatch here would lead to incorrect instruction decoding.
    * **Incorrect number of arguments:** Providing the wrong number of operands during assembly would be an error.
    * **Incorrect argument types:** Using a register when an immediate value is expected, for example.

8. **Summarize the Functionality:**  Consolidate the findings into a concise summary, emphasizing the role of the table in representing and decoding ARM assembly instructions.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Could this be for assembly? Yes, the instruction names and argument types strongly suggest that.
* **Alternative:** Could it be for something else?  Perhaps a simulator or emulator. The core functionality is similar – interpreting instructions.
* **Refinement on command-line parameters:** While the snippet itself doesn't handle them, it's crucial to explain how a tool *using* this table would interact with command-line arguments.
* **Focus on the table:** Emphasize that the snippet's primary function is defining this data structure. The *use* of this data structure is what enables the broader functionality.
这是 `go/src/cmd/vendor/golang.org/x/arch/arm/armasm/tables.go` 文件的一部分，它定义了一个用于表示 ARM 汇编指令的表格。

**功能列举:**

1. **存储 ARM 汇编指令的元数据:**  这个表格存储了 ARM 汇编指令的二进制编码模式、掩码、操作数数量、指令名称、条件码以及操作数类型等信息。
2. **用于指令匹配和解码:**  这些数据可以被 ARM 汇编器或反汇编器使用，通过给定的二进制指令码，根据掩码进行匹配，从而确定具体的汇编指令及其操作数。
3. **定义指令的语法结构:** `instArgs` 结构体定义了指令的操作数类型和顺序，这有助于理解指令的语法结构。
4. **支持条件执行:**  `cond:4` 以及指令名称中的 `_EQ` 等后缀表明表格中包含支持条件执行的指令。

**它是什么 Go 语言功能的实现？**

这个表格很可能是 ARM 汇编器或反汇编器实现的核心组成部分。它通过结构化的数据来描述 ARM 指令集，使得程序能够理解和处理 ARM 汇编代码。

**Go 代码举例说明:**

假设我们有一个函数 `decodeInstruction`，它接收一个 32 位的 ARM 指令码，并尝试在这个表格中查找匹配的指令信息。

```go
package main

import "fmt"

// 假设这是从 tables.go 文件中提取出的部分数据结构
type instArgs struct {
	args []string
}

type instruction struct {
	mask   uint32
	value  uint32
	nargs  int
	name   string
	cond   uint32
	args   instArgs
}

var instructions = []instruction{
	{0x0ff000f0, 0x06600f70, 3, "UQSUB16_EQ", 0x1c04, instArgs{[]string{"arg_R_12", "arg_R_16", "arg_R_0"}}},
	{0x0ff00ff0, 0x06600ff0, 4, "UQSUB8_EQ", 0x1c04, instArgs{[]string{"arg_R_12", "arg_R_16", "arg_R_0"}}},
	// ... 更多指令
}

func decodeInstruction(instructionCode uint32) *instruction {
	for _, inst := range instructions {
		if (instructionCode & inst.mask) == inst.value {
			return &inst
		}
	}
	return nil
}

func main() {
	// 假设我们有以下 ARM 指令码 (对应 UQSUB16 EQ R1, R2, R3)
	instructionCode := uint32(0b01100110000010100001001111110111) // 实际指令码可能需要根据 ARM 规范精确计算

	decodedInst := decodeInstruction(instructionCode)

	if decodedInst != nil {
		fmt.Printf("指令名称: %s\n", decodedInst.name)
		fmt.Printf("操作数数量: %d\n", decodedInst.nargs)
		fmt.Printf("操作数类型: %v\n", decodedInst.args.args)
	} else {
		fmt.Println("未找到匹配的指令")
	}
}
```

**假设的输入与输出:**

**输入:** `instructionCode = 0b01100110000010100001001111110111` (这只是一个示例，实际的指令码需要根据 ARM 规范生成)

**输出:**
```
指令名称: UQSUB16_EQ
操作数数量: 3
操作数类型: [arg_R_12 arg_R_16 arg_R_0]
```

**涉及命令行参数的具体处理:**

这个代码片段本身不直接处理命令行参数。它只是一个数据表。但是，使用这个表格的 ARM 汇编器或反汇编器工具可能会通过命令行参数接收以下信息：

* **汇编源文件路径:**  对于汇编器，指定要编译的 `.s` 或 `.asm` 文件。
* **目标文件路径:**  对于汇编器，指定生成的目标文件的路径。
* **二进制文件路径:** 对于反汇编器，指定要反汇编的二进制可执行文件。
* **输出格式:**  控制反汇编输出的格式 (例如，文本、汇编代码)。
* **架构选项:**  指定目标 ARM 架构 (尽管在这个特定的 `tables.go` 文件中已经限定为 ARM)。

例如，一个假设的 ARM 汇编器命令可能是：

```bash
armasm -o output.o input.s
```

其中 `input.s` 是汇编源文件，`output.o` 是生成的目标文件。汇编器会读取 `input.s` 的内容，然后使用 `tables.go` 中定义的指令表格来将汇编指令转换为机器码。

反汇编器的命令可能是：

```bash
armdis output.o
```

反汇编器会读取 `output.o` 的二进制内容，然后使用 `tables.go` 中的表格来将机器码转换回汇编指令。

**使用者易犯错的点:**

在直接使用或理解这种指令表时，使用者可能会犯以下错误：

* **误解掩码的作用:** 掩码 (`mask`) 用于提取指令码中的关键位，以进行匹配。不理解掩码可能导致无法正确匹配指令。
* **二进制编码的细节错误:** ARM 指令的编码非常精细，即使是细微的二进制位差异也可能导致指令被错误识别或解码。
* **忽略条件码的影响:**  带有条件码的指令只有在满足特定条件时才会执行。理解条件码对于分析代码执行流程至关重要。
* **操作数类型的混淆:**  每个指令对操作数的类型有严格的要求 (例如，寄存器、立即数、内存地址)。混淆操作数类型会导致汇编错误或运行时异常。

**总结 `tables.go` 的功能 (第 5 部分):**

作为系列的一部分，这个 `tables.go` 文件（的这个片段）定义了一个关键的数据结构，用于存储 ARM 汇编指令的详细信息。这个表格是 ARM 汇编器和反汇编器的核心组件，用于将汇编语言转换为机器码，或将机器码转换回汇编语言。它通过结构化的方式描述了 ARM 指令集的语法、编码和操作数，为处理 ARM 汇编代码提供了必要的基础数据。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm/armasm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```go
1)|(1)|(1)|0|1|1|1|Rm:4
	{0x0ff000f0, 0x06600f70, 3, UQSUB16_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                        // UQSUB16<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|1|0|Rn:4|Rd:4|(1)|(1)|(1)|(1)|0|1|1|1|Rm:4
	{0x0ff00ff0, 0x06600ff0, 4, UQSUB8_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                         // UQSUB8<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|1|0|Rn:4|Rd:4|(1)|(1)|(1)|(1)|1|1|1|1|Rm:4
	{0x0ff000f0, 0x06600ff0, 3, UQSUB8_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                         // UQSUB8<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|1|0|Rn:4|Rd:4|(1)|(1)|(1)|(1)|1|1|1|1|Rm:4
	{0x0ff0f0f0, 0x0780f010, 4, USAD8_EQ, 0x1c04, instArgs{arg_R_16, arg_R_0, arg_R_8}},                           // USAD8<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|1|1|0|0|0|Rd:4|1|1|1|1|Rm:4|0|0|0|1|Rn:4
	{0x0ff000f0, 0x07800010, 2, USADA8_EQ, 0x1c04, instArgs{arg_R_16, arg_R_0, arg_R_8, arg_R_12}},                // USADA8<c> <Rd>,<Rn>,<Rm>,<Ra> cond:4|0|1|1|1|1|0|0|0|Rd:4|Ra:4|Rm:4|0|0|0|1|Rn:4
	{0x0ff00ff0, 0x06e00f30, 4, USAT16_EQ, 0x1c04, instArgs{arg_R_12, arg_satimm4, arg_R_0}},                      // USAT16<c> <Rd>,#<sat_imm4>,<Rn> cond:4|0|1|1|0|1|1|1|0|sat_imm:4|Rd:4|(1)|(1)|(1)|(1)|0|0|1|1|Rn:4
	{0x0ff000f0, 0x06e00f30, 3, USAT16_EQ, 0x1c04, instArgs{arg_R_12, arg_satimm4, arg_R_0}},                      // USAT16<c> <Rd>,#<sat_imm4>,<Rn> cond:4|0|1|1|0|1|1|1|0|sat_imm:4|Rd:4|(1)|(1)|(1)|(1)|0|0|1|1|Rn:4
	{0x0fe00030, 0x06e00010, 4, USAT_EQ, 0x1c04, instArgs{arg_R_12, arg_satimm5, arg_R_shift_imm}},                // USAT<c> <Rd>,#<sat_imm5>,<Rn>{,<shift>} cond:4|0|1|1|0|1|1|1|sat_imm:5|Rd:4|imm5:5|sh|0|1|Rn:4
	{0x0ff00ff0, 0x06500f50, 4, USAX_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                           // USAX<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|0|1|0|1|Rm:4
	{0x0ff000f0, 0x06500f50, 3, USAX_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                           // USAX<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|0|1|0|1|Rm:4
	{0x0ff00ff0, 0x06500f70, 4, USUB16_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                         // USUB16<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|0|1|1|1|Rm:4
	{0x0ff000f0, 0x06500f70, 3, USUB16_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                         // USUB16<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|0|1|1|1|Rm:4
	{0x0ff00ff0, 0x06500ff0, 4, USUB8_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                          // USUB8<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|1|1|1|1|Rm:4
	{0x0ff000f0, 0x06500ff0, 3, USUB8_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_0}},                          // USUB8<c> <Rd>,<Rn>,<Rm> cond:4|0|1|1|0|0|1|0|1|Rn:4|Rd:4|(1)|(1)|(1)|(1)|1|1|1|1|Rm:4
	{0x0ff003f0, 0x06c00070, 2, UXTAB16_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_rotate}},                   // UXTAB16<c> <Rd>,<Rn>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|0|0|Rn:4|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0ff003f0, 0x06e00070, 2, UXTAB_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_rotate}},                     // UXTAB<c> <Rd>,<Rn>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|1|0|Rn:4|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0ff003f0, 0x06f00070, 2, UXTAH_EQ, 0x1c04, instArgs{arg_R_12, arg_R_16, arg_R_rotate}},                     // UXTAH<c> <Rd>,<Rn>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|1|1|Rn:4|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0fff03f0, 0x06cf0070, 4, UXTB16_EQ, 0x1c04, instArgs{arg_R_12, arg_R_rotate}},                              // UXTB16<c> <Rd>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|0|0|1|1|1|1|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0fff03f0, 0x06ef0070, 4, UXTB_EQ, 0x1c04, instArgs{arg_R_12, arg_R_rotate}},                                // UXTB<c> <Rd>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|1|0|1|1|1|1|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0fff03f0, 0x06ff0070, 4, UXTH_EQ, 0x1c04, instArgs{arg_R_12, arg_R_rotate}},                                // UXTH<c> <Rd>,<Rm>{,<rotation>} cond:4|0|1|1|0|1|1|1|1|1|1|1|1|Rd:4|rotate:2|0|0|0|1|1|1|Rm:4
	{0x0fb00e10, 0x0e000a00, 4, VMLA_EQ_F32, 0x60108011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},            // V<MLA,MLS><c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|0|0|Vn:4|Vd:4|1|0|1|sz|N|op|M|0|Vm:4
	{0x0fbf0ed0, 0x0eb00ac0, 4, VABS_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sm_Dm}},                           // VABS<c>.F<32,64> <Sd,Dd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|0|0|0|Vd:4|1|0|1|sz|1|1|M|0|Vm:4
	{0x0fb00e50, 0x0e300a00, 4, VADD_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},                // VADD<c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|1|1|Vn:4|Vd:4|1|0|1|sz|N|0|M|0|Vm:4
	{0x0fbf0e7f, 0x0eb50a40, 4, VCMP_EQ_F32, 0x70108011c04, instArgs{arg_Sd_Dd, arg_fp_0}},                        // VCMP{E}<c>.F<32,64> <Sd,Dd>, #0.0 cond:4|1|1|1|0|1|D|1|1|0|1|0|1|Vd:4|1|0|1|sz|E|1|0|0|(0)|(0)|(0)|(0)
	{0x0fbf0e70, 0x0eb50a40, 3, VCMP_EQ_F32, 0x70108011c04, instArgs{arg_Sd_Dd, arg_fp_0}},                        // VCMP{E}<c>.F<32,64> <Sd,Dd>, #0.0 cond:4|1|1|1|0|1|D|1|1|0|1|0|1|Vd:4|1|0|1|sz|E|1|0|0|(0)|(0)|(0)|(0)
	{0x0fbf0e50, 0x0eb40a40, 4, VCMP_EQ_F32, 0x70108011c04, instArgs{arg_Sd_Dd, arg_Sm_Dm}},                       // VCMP{E}<c>.F<32,64> <Sd,Dd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|1|0|0|Vd:4|1|0|1|sz|E|1|M|0|Vm:4
	{0x0fbe0e50, 0x0eba0a40, 4, VCVT_EQ_F32_FXS16, 0x801100107011c04, instArgs{arg_Sd_Dd, arg_Sd_Dd, arg_fbits}},  // VCVT<c>.F<32,64>.FX<S,U><16,32> <Sd,Dd>, <Sd,Dd>, #<fbits> cond:4|1|1|1|0|1|D|1|1|1|0|1|U|Vd:4|1|0|1|sz|sx|1|i|0|imm4:4
	{0x0fbe0e50, 0x0ebe0a40, 4, VCVT_EQ_FXS16_F32, 0x1001070108011c04, instArgs{arg_Sd_Dd, arg_Sd_Dd, arg_fbits}}, // VCVT<c>.FX<S,U><16,32>.F<32,64> <Sd,Dd>, <Sd,Dd>, #<fbits> cond:4|1|1|1|0|1|D|1|1|1|1|1|U|Vd:4|1|0|1|sz|sx|1|i|0|imm4:4
	{0x0fbf0ed0, 0x0eb70ac0, 4, VCVT_EQ_F64_F32, 0x8011c04, instArgs{arg_Dd_Sd, arg_Sm_Dm}},                       // VCVT<c>.<F64.F32,F32.F64> <Dd,Sd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|1|1|1|Vd:4|1|0|1|sz|1|1|M|0|Vm:4
	{0x0fbe0f50, 0x0eb20a40, 4, VCVTB_EQ_F32_F16, 0x70110011c04, instArgs{arg_Sd, arg_Sm}},                        // VCVT<B,T><c>.<F32.F16,F16.F32> <Sd>, <Sm> cond:4|1|1|1|0|1|D|1|1|0|0|1|op|Vd:4|1|0|1|0|T|1|M|0|Vm:4
	{0x0fbf0e50, 0x0eb80a40, 4, VCVT_EQ_F32_U32, 0x80107011c04, instArgs{arg_Sd_Dd, arg_Sm}},                      // VCVT<c>.F<32,64>.<U,S>32 <Sd,Dd>, <Sm> cond:4|1|1|1|0|1|D|1|1|1|0|0|0|Vd:4|1|0|1|sz|op|1|M|0|Vm:4
	{0x0fbe0e50, 0x0ebc0a40, 4, VCVTR_EQ_U32_F32, 0x701100108011c04, instArgs{arg_Sd, arg_Sm_Dm}},                 // VCVT<R,><c>.<U,S>32.F<32,64> <Sd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|1|1|0|signed|Vd:4|1|0|1|sz|op|1|M|0|Vm:4
	{0x0fb00e50, 0x0e800a00, 4, VDIV_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},                // VDIV<c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|1|D|0|0|Vn:4|Vd:4|1|0|1|sz|N|0|M|0|Vm:4
	{0x0f300e00, 0x0d100a00, 4, VLDR_EQ, 0x1c04, instArgs{arg_Sd_Dd, arg_mem_R_pm_imm8at0_offset}},                // VLDR<c> <Sd,Dd>, [<Rn>{,#+/-<imm8>}] cond:4|1|1|0|1|U|D|0|1|Rn:4|Vd:4|1|0|1|sz|imm8:8
	{0x0ff00f7f, 0x0e000a10, 4, VMOV_EQ, 0x1c04, instArgs{arg_Sn, arg_R_12}},                                      // VMOV<c> <Sn>, <Rt> cond:4|1|1|1|0|0|0|0|0|Vn:4|Rt:4|1|0|1|0|N|0|0|1|0|0|0|0
	{0x0ff00f7f, 0x0e100a10, 4, VMOV_EQ, 0x1c04, instArgs{arg_R_12, arg_Sn}},                                      // VMOV<c> <Rt>, <Sn> cond:4|1|1|1|0|0|0|0|1|Vn:4|Rt:4|1|0|1|0|N|0|0|1|0|0|0|0
	{0x0fd00f7f, 0x0e100b10, 4, VMOV_EQ_32, 0x1c04, instArgs{arg_R_12, arg_Dn_half}},                              // VMOV<c>.32 <Rt>, <Dn[x]> cond:4|1|1|1|0|0|0|opc1|1|Vn:4|Rt:4|1|0|1|1|N|0|0|1|0|0|0|0
	{0x0fd00f7f, 0x0e000b10, 4, VMOV_EQ_32, 0x1c04, instArgs{arg_Dn_half, arg_R_12}},                              // VMOV<c>.32 <Dd[x]>, <Rt> cond:4|1|1|1|0|0|0|opc1|0|Vd:4|Rt:4|1|0|1|1|D|0|0|1|0|0|0|0
	{0x0fb00ef0, 0x0eb00a00, 4, VMOV_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_imm_vfp}},                         // VMOV<c>.F<32,64> <Sd,Dd>, #<imm_vfp> cond:4|1|1|1|0|1|D|1|1|imm4H:4|Vd:4|1|0|1|sz|0|0|0|0|imm4L:4
	{0x0fbf0ed0, 0x0eb00a40, 4, VMOV_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sm_Dm}},                           // VMOV<c>.F<32,64> <Sd,Dd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|0|0|0|Vd:4|1|0|1|sz|0|1|M|0|Vm:4
	{0x0fff0fff, 0x0ef10a10, 4, VMRS_EQ, 0x1c04, instArgs{arg_R_12_nzcv, arg_FPSCR}},                              // VMRS<c> <Rt_nzcv>, FPSCR cond:4|1|1|1|0|1|1|1|1|0|0|0|1|Rt:4|1|0|1|0|0|0|0|1|0|0|0|0
	{0x0fff0fff, 0x0ee10a10, 4, VMSR_EQ, 0x1c04, instArgs{arg_FPSCR, arg_R_12}},                                   // VMSR<c> FPSCR, <Rt> cond:4|1|1|1|0|1|1|1|0|0|0|0|1|Rt:4|1|0|1|0|0|0|0|1|0|0|0|0
	{0x0fb00e50, 0x0e200a00, 4, VMUL_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},                // VMUL<c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|1|0|Vn:4|Vd:4|1|0|1|sz|N|0|M|0|Vm:4
	{0x0fbf0ed0, 0x0eb10a40, 4, VNEG_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sm_Dm}},                           // VNEG<c>.F<32,64> <Sd,Dd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|0|0|1|Vd:4|1|0|1|sz|0|1|M|0|Vm:4
	{0x0fb00e10, 0x0e100a00, 4, VNMLS_EQ_F32, 0x60108011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},           // VN<MLS,MLA><c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|0|1|Vn:4|Vd:4|1|0|1|sz|N|op|M|0|Vm:4
	{0x0fb00e50, 0x0e200a40, 4, VNMUL_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},               // VNMUL<c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|1|0|Vn:4|Vd:4|1|0|1|sz|N|1|M|0|Vm:4
	{0x0fbf0ed0, 0x0eb10ac0, 4, VSQRT_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sm_Dm}},                          // VSQRT<c>.F<32,64> <Sd,Dd>, <Sm,Dm> cond:4|1|1|1|0|1|D|1|1|0|0|0|1|Vd:4|1|0|1|sz|1|1|M|0|Vm:4
	{0x0f300e00, 0x0d000a00, 4, VSTR_EQ, 0x1c04, instArgs{arg_Sd_Dd, arg_mem_R_pm_imm8at0_offset}},                // VSTR<c> <Sd,Dd>, [<Rn>{,#+/-<imm8>}] cond:4|1|1|0|1|U|D|0|0|Rn:4|Vd:4|1|0|1|sz|imm8:8
	{0x0fb00e50, 0x0e300a40, 4, VSUB_EQ_F32, 0x8011c04, instArgs{arg_Sd_Dd, arg_Sn_Dn, arg_Sm_Dm}},                // VSUB<c>.F<32,64> <Sd,Dd>, <Sn,Dn>, <Sm,Dm> cond:4|1|1|1|0|0|D|1|1|Vn:4|Vd:4|1|0|1|sz|N|1|M|0|Vm:4
	{0x0fffffff, 0x0320f002, 4, WFE_EQ, 0x1c04, instArgs{}},                                                       // WFE<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|1|0
	{0x0fff00ff, 0x0320f002, 3, WFE_EQ, 0x1c04, instArgs{}},                                                       // WFE<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|1|0
	{0x0fffffff, 0x0320f003, 4, WFI_EQ, 0x1c04, instArgs{}},                                                       // WFI<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|1|1
	{0x0fff00ff, 0x0320f003, 3, WFI_EQ, 0x1c04, instArgs{}},                                                       // WFI<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|1|1
	{0x0fffffff, 0x0320f001, 4, YIELD_EQ, 0x1c04, instArgs{}},                                                     // YIELD<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|0|1
	{0x0fff00ff, 0x0320f001, 3, YIELD_EQ, 0x1c04, instArgs{}},                                                     // YIELD<c> cond:4|0|0|1|1|0|0|1|0|0|0|0|0|(1)|(1)|(1)|(1)|(0)|(0)|(0)|(0)|0|0|0|0|0|0|0|1
	{0xffffffff, 0xf7fabcfd, 4, UNDEF, 0x0, instArgs{}},                                                           // UNDEF 1|1|1|1|0|1|1|1|1|1|1|1|1|0|1|0|1|0|1|1|1|1|0|0|1|1|1|1|1|1|0|1
}
```