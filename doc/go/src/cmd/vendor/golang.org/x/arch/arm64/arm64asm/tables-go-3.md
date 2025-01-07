Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first step is to recognize the structural pattern. The code defines a Go `struct` type (anonymous in this case, which is common for initializing data) containing a slice of other `struct`s. Each inner `struct` seems to represent something related to instructions, given the fields like bitmasks, opcodes, instruction names (like `UCVTF`, `UHADD`), and argument specifications. The path `go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/tables.go` strongly suggests this is related to ARM64 assembly.

2. **Deconstruct the Inner Struct:** Analyze the fields within the inner `struct`.
    * `{0xbf80fc00, 0x2f00e400, UCVTF, ...}` - The first two values look like bit patterns or masks. The third value, `UCVTF`, is very likely an instruction mnemonic.
    * `instArgs{...}` - This suggests a structure to hold the arguments or operands of the instruction. The fields within `instArgs` have names that are highly descriptive of argument types (e.g., `arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81`). These detailed names encode information about the register (`Vd`, `Vn`, `Vm`), data arrangement/size (`arrangement`), and immediate values.
    * `ucvtf_asimdshf_c_cond` - This looks like a function or variable name that likely handles specific decoding or processing logic for this instruction type, possibly related to "Advanced SIMD" and conditional execution.

3. **Formulate Initial Hypotheses:** Based on the deconstruction, the primary function of this code is to define a table that maps bit patterns to ARM64 assembly instructions and their argument structures. This table is likely used by an assembler or disassembler.

4. **Connect to Go Functionality (Instruction Decoding/Encoding):** Consider how such a table would be used in a larger Go program. The most probable use case is in the assembly process (encoding assembly into machine code) or the reverse (disassembling machine code into assembly). The presence of bitmasks and opcodes strongly supports this.

5. **Illustrative Go Code (Encoding):**  To demonstrate encoding, think about the input and output. The input would be an assembly instruction (e.g., `UCVTF D0, D1, #16`). The output would be the corresponding machine code (the hexadecimal values from the table). The Go code would need to:
    * Parse the assembly instruction to extract the opcode and operands.
    * Look up the opcode in the table.
    * Parse the operands and map them to the `instArgs` structure.
    * Potentially use the bitmasks to combine the opcode and operand information into the final machine code.

6. **Illustrative Go Code (Decoding):** For decoding, the input is machine code (e.g., `0x2f00e400`). The output is the corresponding assembly instruction. The Go code would:
    * Iterate through the table.
    * Use the bitmasks to check if the input machine code matches an entry.
    * If a match is found, identify the instruction and extract the operands based on the `instArgs` structure.
    * Format the output as an assembly instruction.

7. **Command Line Parameters (Assembler/Disassembler):** If this table is part of an assembler/disassembler, command-line parameters would be used to specify input files (assembly or machine code) and output files. Flags could control aspects like output format or verbosity.

8. **Common Mistakes (Assembler/Disassembler Usage):**  Think about what could go wrong when using such a tool. Incorrect syntax in assembly code, providing the wrong input file format, or not understanding the instruction set are common errors.

9. **Synthesize and Refine:**  Combine the findings into a coherent summary. Emphasize the table's role in instruction representation, the potential use in assembly/disassembly, and illustrate with example Go code. Ensure the explanations are clear and logically structured. Pay attention to the specific terminology used in the code (e.g., "arrangement," "immediate").

10. **Address Part 4:** The final step is to specifically address the request for a summary in the context of it being "part 4 of 4." This reinforces the idea that the code defines data structures used by other parts of a larger system (the assembler/disassembler).

This detailed thought process allows for a comprehensive understanding of the code snippet's function and its potential role within the larger Go project.
这是对一个Go语言实现的ARM64汇编器或反汇编器中指令定义表格的一部分。

**功能归纳:**

这段代码定义了一个Go语言的结构体切片，用于存储ARM64汇编指令的定义信息。每个结构体条目代表一条不同的ARM64汇编指令，包含了以下关键信息：

* **指令匹配的掩码和值:**  `{0xbf80fc00, 0x2f00e400, ...}` 这两个十六进制数用于匹配机器码。第一个数是掩码，用于指定哪些位需要进行比较；第二个数是值，用于指定需要匹配的位的值。
* **指令助记符:** `UCVTF`, `UHADD`, `UMAX` 等，表示该指令的名称。
* **指令参数定义:** `instArgs{...}` 定义了指令的操作数类型和排列方式。这些 `arg_...` 的字段名详细描述了操作数的类型（例如，寄存器 `Vd`, `Vn`, `Vm`），数据排列方式（例如，`arrangement_size_Q`），以及立即数限制等。
* **可选的特定处理函数/变量:** 例如 `ucvtf_asimdshf_c_cond`，这可能是一个在匹配到该指令后需要执行的特定处理函数或变量，用于进一步处理指令的细节，例如处理不同的条件码或特殊情况。

**推断的Go语言功能实现 (指令解码/反汇编):**

这段代码很可能是ARM64汇编器的反汇编器部分的核心数据结构。反汇编器的主要任务是将机器码转换为可读的汇编代码。这个表格用于根据机器码的模式匹配到对应的汇编指令，并解析出其操作数。

**Go代码举例 (指令解码):**

假设我们有一个函数 `decodeInstruction`，它接收一个32位的机器码作为输入，并尝试将其解码为ARM64汇编指令。

```go
package main

import "fmt"

// 假设这是从 tables.go 文件中提取出来的结构体定义
type instDef struct {
	Mask   uint32
	Value  uint32
	Name   string
	Args   instArgs
	 الخاص interface{} //  为了简化，假设存在一个空接口
}

type instArgs struct {
	// ... (省略 tables.go 中定义的 instArgs 的字段)
	Arg0 string
	Arg1 string
	Arg2 string
	Imm  string // 假设有立即数字段
}

// 假设这是从 tables.go 文件中提取出来的指令定义表格
var instructionTable = []instDef{
	{0xbf80fc00, 0x2f00e400, "UCVTF", instArgs{Arg0: "Vd", Arg1: "Vn", Imm: "#fbits"}, nil},
	{0xffbffc00, 0x7e21d800, "UCVTF", instArgs{Arg0: "Vd", Arg1: "Vn"}, nil},
	// ... 其他指令定义
}

func decodeInstruction(code uint32) (string, error) {
	for _, def := range instructionTable {
		if (code & def.Mask) == def.Value {
			// 指令匹配成功，开始解析操作数 (这里只是简单示例)
			var operands string
			if def.Args.Arg0 != "" {
				operands += def.Args.Arg0
			}
			if def.Args.Arg1 != "" {
				if operands != "" {
					operands += ", "
				}
				operands += def.Args.Arg1
			}
			if def.Args.Imm != "" {
				if operands != "" {
					operands += ", "
				}
				// 这里需要根据指令定义解析出实际的立即数
				operands += "#<立即数>"
			}
			return fmt.Sprintf("%s %s", def.Name, operands), nil
		}
	}
	return "", fmt.Errorf("未知的指令: 0x%X", code)
}

func main() {
	// 假设的输入机器码
	machineCode1 := uint32(0x2f00e400)
	decodedInstruction1, err := decodeInstruction(machineCode1)
	if err != nil {
		fmt.Println("解码错误:", err)
	} else {
		fmt.Println("解码结果:", decodedInstruction1) // 输出: 解码结果: UCVTF Vd, Vn, #<立即数>
	}

	machineCode2 := uint32(0x7e21d800)
	decodedInstruction2, err := decodeInstruction(machineCode2)
	if err != nil {
		fmt.Println("解码错误:", err)
	} else {
		fmt.Println("解码结果:", decodedInstruction2) // 输出: 解码结果: UCVTF Vd, Vn
	}

	unknownCode := uint32(0x12345678)
	_, err = decodeInstruction(unknownCode)
	if err != nil {
		fmt.Println("解码错误:", err) // 输出: 解码错误: 未知的指令: 0x12345678
	}
}
```

**假设的输入与输出:**

* **输入 (机器码):** `0x2f00e400`
* **输出 (汇编指令):** `UCVTF Vd, Vn, #<立即数>` (注意，实际的立即数需要根据机器码的特定位来解析，这里用 `<立即数>` 占位)

* **输入 (机器码):** `0x7e21d800`
* **输出 (汇编指令):** `UCVTF Vd, Vn`

* **输入 (机器码):** `0x12345678` (一个在表格中不存在的机器码)
* **输出 (错误):** `未知的指令: 0x12345678`

**命令行参数的具体处理:**

由于这段代码只是指令定义的表格，它本身不直接处理命令行参数。但是，使用这个表格的汇编器或反汇编器工具会通过命令行参数来指定输入文件、输出文件、目标架构等。

例如，一个使用该表格的反汇编器工具可能有如下命令行参数：

```bash
go tool objdump -arch arm64 input.o  # 反汇编 input.o 文件，指定架构为 arm64
```

或者一个汇编器工具：

```bash
go tool asm -o output.o input.s  # 汇编 input.s 文件，生成 output.o 目标文件
```

在这些工具的内部实现中，会读取命令行参数，根据参数加载或生成相应的机器码，然后使用 `tables.go` 中定义的表格进行指令的匹配、编码或解码。

**使用者易犯错的点:**

* **误解掩码和值的含义:**  初学者可能会不理解掩码的作用，认为 `Value` 就是完整的机器码。实际上，掩码用于提取机器码中需要进行比较的特定位。
* **忽略指令参数的详细定义:**  `instArgs` 中的字段名包含了大量的细节信息，例如操作数的大小、排列方式等。如果忽略这些细节，可能会导致解析错误或生成错误的机器码。例如，`arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81`  指明了 `Vd` 寄存器的一种特定排列方式和立即数限制。
* **不理解可选处理函数/变量的作用:**  像 `ucvtf_asimdshf_c_cond` 这样的字段，暗示了某些指令可能需要特殊的处理逻辑，不能简单地通过表格匹配就完成。

**第4部分功能归纳:**

作为第4部分，这个 `tables.go` 文件很可能是整个ARM64汇编/反汇编实现中定义指令集架构细节的最后一部分，它提供了核心的指令定义数据，供其他模块（例如，词法分析器、语法分析器、编码器、解码器）使用。它将具体的指令编码模式、操作数类型和格式以结构化的方式组织起来，是实现指令处理逻辑的关键数据来源。

总而言之，`tables.go` 文件定义了一个关键的查找表，用于在ARM64汇编指令的机器码表示和汇编助记符表示之间进行转换，是实现ARM64汇编器或反汇编器等工具的基础数据。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共4部分，请归纳一下它的功能

"""
.<t>, #<fbits>
	{0xbf80fc00, 0x2f00e400, UCVTF, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81, arg_immediate_fbits_min_1_max_0_sub_0_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__64UIntimmhimmb_4__128UIntimmhimmb_8}, ucvtf_asimdshf_c_cond},
	// UCVTF <V><d>, <V><n>
	{0xffbffc00, 0x7e21d800, UCVTF, instArgs{arg_Vd_22_1__S_0__D_1, arg_Vn_22_1__S_0__D_1}, nil},
	// UCVTF <Vd>.<t>, <Vn>.<t>
	{0xbfbffc00, 0x2e21d800, UCVTF, instArgs{arg_Vd_arrangement_sz_Q___2S_00__4S_01__2D_11, arg_Vn_arrangement_sz_Q___2S_00__4S_01__2D_11}, nil},
	// UHADD <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e200400, UHADD, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UHSUB <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e202400, UHSUB, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMAX <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e206400, UMAX, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMAXP <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e20a400, UMAXP, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMAXV <V><d>, <Vn>.<t>
	{0xbf3ffc00, 0x2e30a800, UMAXV, instArgs{arg_Vd_22_2__B_0__H_1__S_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__4S_21}, nil},
	// UMIN <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e206c00, UMIN, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMINP <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e20ac00, UMINP, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMINV <V><d>, <Vn>.<t>
	{0xbf3ffc00, 0x2e31a800, UMINV, instArgs{arg_Vd_22_2__B_0__H_1__S_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__4S_21}, nil},
	// UMLAL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x2f002000, UMLAL, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMLAL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x6f002000, UMLAL2, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMLAL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x2e208000, UMLAL, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMLAL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x6e208000, UMLAL2, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMLSL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x2f006000, UMLSL, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMLSL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x6f006000, UMLSL2, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMLSL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x2e20a000, UMLSL, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMLSL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x6e20a000, UMLSL2, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMULL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x2f00a000, UMULL, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMULL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<ts>[<index>]
	{0xff00f400, 0x6f00a000, UMULL2, instArgs{arg_Vd_arrangement_size___4S_1__2D_2, arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1}, nil},
	// UMULL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x2e20c000, UMULL, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UMULL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x6e20c000, UMULL2, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UQADD <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e200c00, UQADD, instArgs{arg_Vd_22_2__B_0__H_1__S_2__D_3, arg_Vn_22_2__B_0__H_1__S_2__D_3, arg_Vm_22_2__B_0__H_1__S_2__D_3}, nil},
	// UQADD <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e200c00, UQADD, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UQRSHL <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e205c00, UQRSHL, instArgs{arg_Vd_22_2__B_0__H_1__S_2__D_3, arg_Vn_22_2__B_0__H_1__S_2__D_3, arg_Vm_22_2__B_0__H_1__S_2__D_3}, nil},
	// UQRSHL <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e205c00, UQRSHL, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UQRSHRN <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f009c00, UQRSHRN, instArgs{arg_Vd_19_4__B_1__H_2__S_4, arg_Vn_19_4__H_1__S_2__D_4, arg_immediate_1_width_immh_immb__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqrshrn_asisdshf_n_cond},
	// UQRSHRN <Vd>.<tb>, <Vn>.<ta>, #<shift>
	{0xff80fc00, 0x2f009c00, UQRSHRN, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_Vn_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqrshrn_asimdshf_n_cond},
	// UQRSHRN2 <Vd>.<tb>, <Vn>.<ta>, #<shift>
	{0xff80fc00, 0x6f009c00, UQRSHRN2, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_Vn_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqrshrn_asimdshf_n_cond},
	// UQSHL <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f007400, UQSHL, instArgs{arg_Vd_19_4__B_1__H_2__S_4__D_8, arg_Vn_19_4__B_1__H_2__S_4__D_8, arg_immediate_0_width_m1_immh_immb__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4__UIntimmhimmb64_8}, uqshl_asisdshf_r_cond},
	// UQSHL <Vd>.<t>, <Vn>.<t>, #<shift>
	{0xbf80fc00, 0x2f007400, UQSHL, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_immediate_0_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4__UIntimmhimmb64_8}, uqshl_asimdshf_r_cond},
	// UQSHL <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e204c00, UQSHL, instArgs{arg_Vd_22_2__B_0__H_1__S_2__D_3, arg_Vn_22_2__B_0__H_1__S_2__D_3, arg_Vm_22_2__B_0__H_1__S_2__D_3}, nil},
	// UQSHL <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e204c00, UQSHL, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UQSHRN <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f009400, UQSHRN, instArgs{arg_Vd_19_4__B_1__H_2__S_4, arg_Vn_19_4__H_1__S_2__D_4, arg_immediate_1_width_immh_immb__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqshrn_asisdshf_n_cond},
	// UQSHRN <Vd>.<tb>, <Vn>.<ta>, #<shift>
	{0xff80fc00, 0x2f009400, UQSHRN, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_Vn_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqshrn_asimdshf_n_cond},
	// UQSHRN2 <Vd>.<tb>, <Vn>.<ta>, #<shift>
	{0xff80fc00, 0x6f009400, UQSHRN2, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_Vn_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4}, uqshrn_asimdshf_n_cond},
	// UQSUB <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e202c00, UQSUB, instArgs{arg_Vd_22_2__B_0__H_1__S_2__D_3, arg_Vn_22_2__B_0__H_1__S_2__D_3, arg_Vm_22_2__B_0__H_1__S_2__D_3}, nil},
	// UQSUB <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e202c00, UQSUB, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UQXTN <V><d>, <V><n>
	{0xff3ffc00, 0x7e214800, UQXTN, instArgs{arg_Vd_22_2__B_0__H_1__S_2, arg_Vn_22_2__H_0__S_1__D_2}, nil},
	// UQXTN <Vd>.<tb>, <Vn>.<ta>
	{0xff3ffc00, 0x2e214800, UQXTN, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size___8H_0__4S_1__2D_2}, nil},
	// UQXTN2 <Vd>.<tb>, <Vn>.<ta>
	{0xff3ffc00, 0x6e214800, UQXTN2, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size___8H_0__4S_1__2D_2}, nil},
	// URECPE <Vd>.<t>, <Vn>.<t>
	{0xbfbffc00, 0x0ea1c800, URECPE, instArgs{arg_Vd_arrangement_sz_Q___2S_00__4S_01, arg_Vn_arrangement_sz_Q___2S_00__4S_01}, nil},
	// URHADD <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e201400, URHADD, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// URSHL <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e205400, URSHL, instArgs{arg_Vd_22_2__D_3, arg_Vn_22_2__D_3, arg_Vm_22_2__D_3}, nil},
	// URSHL <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e205400, URSHL, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// URSHR <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f002400, URSHR, instArgs{arg_Vd_19_4__D_8, arg_Vn_19_4__D_8, arg_immediate_1_64_immh_immb__128UIntimmhimmb_8}, urshr_asisdshf_r_cond},
	// URSHR <Vd>.<t>, <Vn>.<t>, #<shift>
	{0xbf80fc00, 0x2f002400, URSHR, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4__128UIntimmhimmb_8}, urshr_asimdshf_r_cond},
	// URSQRTE <Vd>.<t>, <Vn>.<t>
	{0xbfbffc00, 0x2ea1c800, URSQRTE, instArgs{arg_Vd_arrangement_sz_Q___2S_00__4S_01, arg_Vn_arrangement_sz_Q___2S_00__4S_01}, nil},
	// URSRA <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f003400, URSRA, instArgs{arg_Vd_19_4__D_8, arg_Vn_19_4__D_8, arg_immediate_1_64_immh_immb__128UIntimmhimmb_8}, ursra_asisdshf_r_cond},
	// URSRA <Vd>.<t>, <Vn>.<t>, #<shift>
	{0xbf80fc00, 0x2f003400, URSRA, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4__128UIntimmhimmb_8}, ursra_asimdshf_r_cond},
	// USHL <V><d>, <V><n>, <V><m>
	{0xff20fc00, 0x7e204400, USHL, instArgs{arg_Vd_22_2__D_3, arg_Vn_22_2__D_3, arg_Vm_22_2__D_3}, nil},
	// USHL <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x2e204400, USHL, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UXTL <Vd>.<ta>, <Vn>.<tb>
	{0xff87fc00, 0x2f00a400, UXTL, instArgs{arg_Vd_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41}, uxtl_ushll_asimdshf_l_cond},
	// UXTL2 <Vd>.<ta>, <Vn>.<tb>
	{0xff87fc00, 0x6f00a400, UXTL2, instArgs{arg_Vd_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41}, uxtl_ushll_asimdshf_l_cond},
	// USHLL <Vd>.<ta>, <Vn>.<tb>, #<shift>
	{0xff80fc00, 0x2f00a400, USHLL, instArgs{arg_Vd_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_immediate_0_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4}, ushll_asimdshf_l_cond},
	// USHLL2 <Vd>.<ta>, <Vn>.<tb>, #<shift>
	{0xff80fc00, 0x6f00a400, USHLL2, instArgs{arg_Vd_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41, arg_immediate_0_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4}, ushll_asimdshf_l_cond},
	// USHR <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f000400, USHR, instArgs{arg_Vd_19_4__D_8, arg_Vn_19_4__D_8, arg_immediate_1_64_immh_immb__128UIntimmhimmb_8}, ushr_asisdshf_r_cond},
	// USHR <Vd>.<t>, <Vn>.<t>, #<shift>
	{0xbf80fc00, 0x2f000400, USHR, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4__128UIntimmhimmb_8}, ushr_asimdshf_r_cond},
	// USQADD <V><d>, <V><n>
	{0xff3ffc00, 0x7e203800, USQADD, instArgs{arg_Vd_22_2__B_0__H_1__S_2__D_3, arg_Vn_22_2__B_0__H_1__S_2__D_3}, nil},
	// USQADD <Vd>.<t>, <Vn>.<t>
	{0xbf3ffc00, 0x2e203800, USQADD, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// USRA <V><d>, <V><n>, #<shift>
	{0xff80fc00, 0x7f001400, USRA, instArgs{arg_Vd_19_4__D_8, arg_Vn_19_4__D_8, arg_immediate_1_64_immh_immb__128UIntimmhimmb_8}, usra_asisdshf_r_cond},
	// USRA <Vd>.<t>, <Vn>.<t>, #<shift>
	{0xbf80fc00, 0x2f001400, USRA, instArgs{arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81, arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4__128UIntimmhimmb_8}, usra_asimdshf_r_cond},
	// USUBL <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x2e202000, USUBL, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// USUBL2 <Vd>.<ta>, <Vn>.<tb>, <Vm>.<tb>
	{0xff20fc00, 0x6e202000, USUBL2, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// USUBW <Vd>.<ta>, <Vn>.<ta>, <Vm>.<tb>
	{0xff20fc00, 0x2e203000, USUBW, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size___8H_0__4S_1__2D_2, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// USUBW2 <Vd>.<ta>, <Vn>.<ta>, <Vm>.<tb>
	{0xff20fc00, 0x6e203000, USUBW2, instArgs{arg_Vd_arrangement_size___8H_0__4S_1__2D_2, arg_Vn_arrangement_size___8H_0__4S_1__2D_2, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21}, nil},
	// UZP1 <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x0e001800, UZP1, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// UZP2 <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x0e005800, UZP2, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// XTN <Vd>.<tb>, <Vn>.<ta>
	{0xff3ffc00, 0x0e212800, XTN, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size___8H_0__4S_1__2D_2}, nil},
	// XTN2 <Vd>.<tb>, <Vn>.<ta>
	{0xff3ffc00, 0x4e212800, XTN2, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21, arg_Vn_arrangement_size___8H_0__4S_1__2D_2}, nil},
	// ZIP1 <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x0e003800, ZIP1, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
	// ZIP2 <Vd>.<t>, <Vn>.<t>, <Vm>.<t>
	{0xbf20fc00, 0x0e007800, ZIP2, instArgs{arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31, arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31}, nil},
}

"""




```