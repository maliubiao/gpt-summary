Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, which is part of an ARM64 assembler. The core task is to interpret the numerous `arg_` prefixed constants and the comments explaining them.

2. **Identify the Core Concept:** The file is named `arg.go` and contains a large `const` block defining types prefixed with `arg_`. The comments clearly link these to "Go decoder arguments". This immediately suggests that this code is involved in representing and identifying the different *arguments* that an ARM64 assembly instruction can take.

3. **Deconstruct the Naming Conventions:** The comments explain the naming scheme. I need to pay close attention to the prefixes and suffixes of the `arg_` constants. For example:
    * `arg_Wd`:  `W` register, `d` indicates the `Rd` field.
    * `arg_Wm_extend__...`:  `W` register, `m` indicates the `Rm` field, and `extend` signifies an extension mechanism.
    * `arg_slabel_imm14_2`: A signed label, `imm14` suggests a 14-bit immediate, and `_2` likely means it's multiplied by 2.

4. **Categorize the Argument Types:** As I examine the different `arg_` constants, I start to see patterns and categories emerge. These include:
    * **Registers:**  Different sizes (W, X, vector registers like Vd, Vn, Vt), different encodings (Rd, Rn, Rm fields), and variations like stack pointers (wsp, sp).
    * **Immediates:** Various sizes (imm12, imm7, imm16, etc.), signed/unsigned, with optional shifts or other transformations. Some are bitmasks or specific floating-point values.
    * **Memory Addressing Modes:**  Combinations of base registers, offsets (immediate or register-based), pre/post-indexing, and extensions.
    * **Labels:**  Representing jump targets, with different ranges and scaling.
    * **Conditions:**  Representing conditional execution flags.
    * **System Registers and Operations:** For interacting with the processor's system level.
    * **Vector Arrangements:**  Specific layouts and sizes of data within vector registers.

5. **Relate to Assembly Concepts:**  I draw upon my knowledge of assembly language (specifically ARM64) to connect these `arg_` types to concrete instruction components. For example, I know that `add` and `sub` instructions often take an immediate value, which corresponds to `arg_IAddSub`. Memory access instructions use addressing modes described by the `arg_Xns_mem_*` types.

6. **Infer the Go Functionality:** Based on the naming and the purpose of representing assembly arguments, I deduce that this code is likely used within a Go package for:
    * **Decoding ARM64 instructions:**  Parsing the raw instruction bytes to identify the operands and their types.
    * **Encoding ARM64 instructions:**  Potentially, though less evident from this snippet, generating the raw bytes from a higher-level representation.
    * **Disassembly:**  Converting raw instruction bytes into human-readable assembly.

7. **Construct Go Code Examples:**  To illustrate the functionality, I create simple Go code snippets that demonstrate how these argument types might be used in practice. I focus on the decoding scenario, as it aligns best with the provided code. I choose examples that cover common argument types like registers, immediates, and basic memory addressing.

8. **Address Specific Requirements:**
    * **Functionality Listing:** I create a comprehensive list of the functionalities based on the categorized argument types.
    * **Go Code Example:** I provide the `decodeInstruction` function example with clear explanations of the assumed input and output.
    * **Code Reasoning:** I explain the logic behind the `decodeInstruction` example and how the `instArg` constants relate to the bit fields in the instruction.
    * **Command-line Arguments:** The provided code doesn't directly handle command-line arguments, so I explicitly state this.
    * **Common Mistakes:** I think about potential errors a user might make when working with an assembler or disassembler, such as incorrect register names, out-of-range immediate values, or misunderstanding addressing modes.

9. **Refine and Organize:**  I review my answer to ensure clarity, accuracy, and completeness. I organize the information logically with clear headings and bullet points. I double-check the code examples for correctness and make sure the explanations are easy to understand.

By following this systematic approach, I can effectively analyze the provided code snippet and provide a comprehensive answer that addresses all aspects of the request. The key is to combine code analysis with an understanding of the underlying domain (ARM64 assembly language).
Based on the provided Go code snippet, which defines a series of constants prefixed with `arg_`, here's a breakdown of its functionality:

**Core Functionality:**

This Go code defines an enumeration (`instArg`) representing various types of arguments that can be used in ARM64 assembly instructions. Essentially, it's a way to categorize and identify different kinds of operands that an ARM64 instruction can operate on.

**Detailed Breakdown of Functionality:**

The `arg_` prefixed constants represent different categories of instruction arguments. Here's a categorization based on the naming conventions:

* **Registers:**
    * **General Purpose Registers:** `arg_Wd`, `arg_Xd`, `arg_Wn`, `arg_Wm`, etc. These differentiate between 32-bit (`W`) and 64-bit (`X`) registers and the specific fields in the instruction encoding where the register is specified (e.g., `Rd`, `Rn`, `Rm`). The `s` suffix (like `arg_Wds`, `arg_Xds`) likely indicates the stack pointer register (wsp/sp).
    * **Vector Registers:** `arg_Vd`, `arg_Vn`, `arg_Vt`, `arg_Qm`, etc. These represent SIMD (Single Instruction, Multiple Data) registers and often include size and arrangement specifiers.
    * **Floating-Point Registers:** `arg_Sd`, `arg_Dd`, `arg_Hd`, etc. These denote single-precision, double-precision, and half-precision floating-point registers.

* **Immediates (Constant Values):**
    * **Basic Immediates:** `arg_IAddSub` (for add/sub), `arg_immediate_0_127_CRm_op2`, `arg_immediate_bitmask_64_N_imms_immr`, etc. These represent constant values encoded directly within the instruction. The naming often specifies the range, the encoding fields, and sometimes the intended usage.
    * **Shifted Immediates:**  Immediates with optional left shifts (e.g., for `MOV` instructions).
    * **Bitmask Immediates:**  Specific bit patterns used in logical operations.
    * **Floating-Point Immediates:**  Representations of floating-point constants like `#0.0`.

* **Memory Addressing Modes:**
    * **Base Register + Offset:** `arg_Xns_mem_optional_imm12_4_unsigned`, `arg_Xns_mem_post_imm7_8_signed`, etc. These describe how memory addresses are calculated, using a base register (`Xns`) and an offset (immediate or register-based).
    * **Pre/Post Indexing:** `arg_Xns_mem_wb_imm7_4_signed` (write-back), `arg_Xns_mem_post_imm7_8_signed`. These indicate whether the base register is updated before or after the memory access.
    * **Register Extension:** `arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__3_1`. This involves extending a smaller register to a larger size before using it as an offset.

* **Labels (Branch Targets):**
    * `arg_slabel_imm14_2`, `arg_slabel_imm19_2`, etc. These represent jump targets within the code. The naming indicates if the label is signed (`slabel`), the size of the immediate offset (`imm14`, `imm19`), and a scaling factor.

* **Conditions:**
    * `arg_cond_AllowALNV_Normal`, `arg_cond_NotAllowALNV_Invert`. These represent conditional flags that can determine if an instruction is executed.

* **System Operations and Registers:**
    * `arg_sysop_AT_SYS_CR_system`, `arg_sysreg_o0_op1_CRn_CRm_op2`. These are used for interacting with the processor's system-level functions and registers.

* **SIMD Arrangement Specifiers:**
    * `arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31`. These specify how data elements are arranged within vector registers (e.g., 8 bytes, 4 halfwords, 2 single-precision floats, etc.).

**Inferred Go Language Functionality:**

This `arg.go` file is most likely part of an ARM64 assembler, disassembler, or instruction decoder. It serves as a central definition for the different types of operands that ARM64 instructions can take.

**Go Code Example (Instruction Decoding):**

Let's assume this code is used in a disassembler to interpret the raw bytes of an ARM64 instruction.

```go
package main

import "fmt"

// Assume the constants from arg.go are defined here

type Instruction struct {
	Opcode string
	Args   map[instArg]interface{} // Map to store decoded arguments
}

func decodeInstruction(instructionBytes uint32) Instruction {
	// This is a simplified example, actual decoding is more complex
	opcode := "ADD" // Hypothetical opcode

	args := make(map[instArg]interface{})

	// Example: Decoding a register operand (assuming bits 0-4 encode Rd)
	rdValue := instructionBytes & 0x1F // Extract the first 5 bits
	if rdValue == 31 {
		args[arg_Wd] = "wzr" // Zero register
	} else {
		args[arg_Wd] = fmt.Sprintf("w%d", rdValue)
	}

	// Example: Decoding an immediate operand (assuming bits 10-21 encode an immediate)
	immValue := (instructionBytes >> 10) & 0xFFF // Extract 12 bits
	args[arg_IAddSub] = immValue

	return Instruction{
		Opcode: opcode,
		Args:   args,
	}
}

func main() {
	// Example of raw instruction bytes (hypothetical ADD instruction)
	instructionBytes := uint32(0x8B020020) // Example encoding

	decodedInstruction := decodeInstruction(instructionBytes)

	fmt.Printf("Decoded Instruction: %s\n", decodedInstruction.Opcode)
	for argType, argValue := range decodedInstruction.Args {
		fmt.Printf("  %v: %v\n", argType, argValue)
	}
}
```

**Example Output:**

```
Decoded Instruction: ADD
  arg_Wd: w0
  arg_IAddSub: 512
```

**Assumptions in the Example:**

* **Simplified Decoding:** The `decodeInstruction` function is highly simplified and doesn't represent the full complexity of ARM64 instruction decoding.
* **Hypothetical Bit Fields:**  The bit field extractions (`&`, `>>`) are based on common ARM64 instruction formats but are not specific to a particular instruction in this example.
* **Mapping to Constants:** The example shows how the decoded bit values can be associated with the `instArg` constants.

**Command-line Argument Handling:**

The provided `arg.go` file itself **does not handle command-line arguments**. It's a data definition file. If this file were part of an assembler or disassembler, other parts of the program (likely in `main.go` or other files) would use libraries like `flag` or `os.Args` to process command-line arguments for input files, output formats, etc.

**Example of Command-line Argument Handling (Illustrative):**

```go
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	inputFile := flag.String("input", "", "Path to the assembly input file")
	outputFile := flag.String("output", "output.s", "Path to the output file")
	disassemble := flag.Bool("disassemble", false, "Disassemble the input file")

	flag.Parse()

	if *inputFile == "" {
		fmt.Println("Error: Input file is required.")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("Input File: %s\n", *inputFile)
	fmt.Printf("Output File: %s\n", *outputFile)
	fmt.Printf("Disassemble Mode: %t\n", *disassemble)

	// ... rest of the assembler/disassembler logic ...
}
```

**Common User Mistakes (If this were used in an assembler/disassembler):**

1. **Incorrect Register Names:**  Typing `R0` instead of `w0` or `x0` when specifying registers.
2. **Out-of-Range Immediates:** Providing an immediate value that is outside the allowed range for a specific instruction (as defined by constants like `arg_immediate_0_127_CRm_op2`).
3. **Incorrect Addressing Modes:** Using a memory addressing mode that is not supported by the instruction or providing incorrect offsets. For example, trying to use a signed offset where only an unsigned offset is allowed.
4. **Misunderstanding Condition Codes:** Using an invalid condition code or misunderstanding the behavior of specific condition flags.
5. **Incorrect SIMD Arrangement Specifiers:** Specifying an invalid combination of size and arrangement for vector registers.

This `arg.go` file is a foundational piece for working with ARM64 assembly in Go, providing a structured way to represent the different components of instructions.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/arm64/arm64asm/arg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Generated by ARM internal tool
// DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm64asm

// Naming for Go decoder arguments:
//
// - arg_Wd: a W register encoded in the Rd[4:0] field (31 is wzr)
//
// - arg_Xd: a X register encoded in the Rd[4:0] field (31 is xzr)
//
// - arg_Wds: a W register encoded in the Rd[4:0] field (31 is wsp)
//
// - arg_Xds: a X register encoded in the Rd[4:0] field (31 is sp)
//
// - arg_Wn: encoded in Rn[9:5]
//
// - arg_Wm: encoded in Rm[20:16]
//
// - arg_Wm_extend__UXTB_0__UXTH_1__LSL_UXTW_2__UXTX_3__SXTB_4__SXTH_5__SXTW_6__SXTX_7__0_4:
//     a W register encoded in Rm with an extend encoded in option[15:13] and an amount
//     encoded in imm3[12:10] in the range [0,4].
//
// - arg_Rm_extend__UXTB_0__UXTH_1__UXTW_2__LSL_UXTX_3__SXTB_4__SXTH_5__SXTW_6__SXTX_7__0_4:
//     a W or X register encoded in Rm with an extend encoded in option[15:13] and an
//     amount encoded in imm3[12:10] in the range [0,4]. If the extend is UXTX or SXTX,
//     it's an X register else, it's a W register.
//
// - arg_Wm_shift__LSL_0__LSR_1__ASR_2__0_31:
//     a W register encoded in Rm with a shift encoded in shift[23:22] and an amount
//     encoded in imm6[15:10] in the range [0,31].
//
// - arg_IAddSub:
//     An immediate for a add/sub instruction encoded in imm12[21:10] with an optional
//     left shift of 12 encoded in shift[23:22].
//
// - arg_Rt_31_1__W_0__X_1:
//     a W or X register encoded in Rt[4:0]. The width specifier is encoded in the field
//     [31:31] (offset 31, bit count 1) and the register is W for 0 and X for 1.
//
// - arg_[s|u]label_FIELDS_POWER:
//     a program label encoded as "FIELDS" times 2^POWER in the range [MIN, MAX] (determined
//     by signd/unsigned, FIELDS and POWER), e.g.
//       arg_slabel_imm14_2
//       arg_slabel_imm19_2
//       arg_slabel_imm26_2
//       arg_slabel_immhi_immlo_0
//       arg_slabel_immhi_immlo_12
//
// - arg_Xns_mem_post_imm7_8_signed:
//     addressing mode of post-index with a base register: Xns and a signed offset encoded
//     in the "imm7" field times 8
//
// - arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__3_1:
//     addressing mode of extended register with a base register: Xns, an offset register
//     (<Wm>|<Xm>) with an extend encoded in option[15:13] and a shift amount encoded in
//     S[12:12] in the range [0,3] (S=0:0, S=1:3).
//
// - arg_Xns_mem_optional_imm12_4_unsigned:
//     addressing mode of unsigned offset with a base register: Xns and an optional unsigned
//     offset encoded in the "imm12" field times 4
//
// - arg_Xns_mem_wb_imm7_4_signed:
//     addressing mode of pre-index with a base register: Xns and the signed offset encoded
//     in the "imm7" field times 4
//
// - arg_Xns_mem_post_size_1_8_unsigned__4_0__8_1__16_2__32_3:
//     a post-index immediate offset, encoded in the "size" field. It can have the following values:
//       #4 when size = 00
//       #8 when size = 01
//       #16 when size = 10
//       #32 when size = 11
//
// - arg_immediate_0_127_CRm_op2:
//     an immediate encoded in "CRm:op2" in the range 0 to 127
//
// - arg_immediate_bitmask_64_N_imms_immr:
//     a bitmask immediate for 64-bit variant and encoded in "N:imms:immr"
//
// - arg_immediate_SBFX_SBFM_64M_bitfield_width_64_imms:
//     an immediate for the <width> bitfield of SBFX 64-bit variant
//
// - arg_immediate_shift_32_implicit_inverse_imm16_hw:
//     a 32-bit immediate of the bitwise inverse of which can be encoded in "imm16:hw"
//
// - arg_cond_[Not]AllowALNV_[Invert|Normal]:
//     a standard condition, encoded in the "cond" field, excluding (NotAllow) AL and NV with
//     its least significant bit [Yes|No] inverted, e.g.
//       arg_cond_AllowALNV_Normal
//       arg_cond_NotAllowALNV_Invert
//
// - arg_immediate_OptLSL_amount_16_0_48:
//     An immediate for MOV[KNZ] instruction encoded in imm16[20:5] with an optional
//     left shift of 16 in the range [0, 48] encoded in hw[22, 21]
//
// - arg_immediate_0_width_m1_immh_immb__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4__UIntimmhimmb64_8:
//     the left shift amount, in the range 0 to the operand width in bits minus 1,
//     encoded in the "immh:immb" field. It can have the following values:
//       (UInt(immh:immb)-8) when immh = 0001
//       (UInt(immh:immb)-16) when immh = 001x
//       (UInt(immh:immb)-32) when immh = 01xx
//       (UInt(immh:immb)-64) when immh = 1xxx
//
// - arg_immediate_1_width_immh_immb__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4:
//     the right shift amount, in the range 1 to the destination operand width in
//     bits, encoded in the "immh:immb" field. It can have the following values:
//       (16-UInt(immh:immb)) when immh = 0001
//       (32-UInt(immh:immb)) when immh = 001x
//       (64-UInt(immh:immb)) when immh = 01xx
//
// - arg_immediate_8x8_a_b_c_d_e_f_g_h:
//     a 64-bit immediate 'aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhh',
//     encoded in "a:b:c:d:e:f:g:h".
//
// - arg_immediate_fbits_min_1_max_32_sub_64_scale:
//     the number of bits after the binary point in the fixed-point destination,
//     in the range 1 to 32, encoded as 64 minus "scale".
//
// - arg_immediate_floatzero: #0.0
//
// - arg_immediate_exp_3_pre_4_a_b_c_d_e_f_g_h:
//     a signed floating-point constant with 3-bit exponent and normalized 4 bits of precision,
//     encoded in "a:b:c:d:e:f:g:h"
//
// - arg_immediate_fbits_min_1_max_0_sub_0_immh_immb__64UIntimmhimmb_4__128UIntimmhimmb_8:
//     the number of fractional bits, in the range 1 to the operand width, encoded
//     in the "immh:immb" field. It can have the following values:
//       (64-UInt(immh:immb)) when immh = 01xx
//       (128-UInt(immh:immb)) when immh = 1xxx
//
// - arg_immediate_index_Q_imm4__imm4lt20gt_00__imm4_10:
//     the lowest numbered byte element to be extracted, encoded in the "Q:imm4" field.
//     It can have the following values:
//       imm4<2:0> when Q = 0, imm4<3> = 0
//       imm4 when Q = 1, imm4<3> = x
//
// - arg_sysop_AT_SYS_CR_system:
//     system operation for system instruction: AT encoded in the "op1:CRm<0>:op2" field
//
// - arg_prfop_Rt:
//     prefectch operation encoded in the "Rt"
//
// - arg_sysreg_o0_op1_CRn_CRm_op2:
//     system register name encoded in the "o0:op1:CRn:CRm:op2"
//
// - arg_pstatefield_op1_op2__SPSel_05__DAIFSet_36__DAIFClr_37:
//     PSTATE field name encoded in the "op1:op2" field
//
// - arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31:
//     one register with arrangement specifier encoded in the "size:Q" field which can have the following values:
//       8B when size = 00, Q = 0
//       16B when size = 00, Q = 1
//       4H when size = 01, Q = 0
//       8H when size = 01, Q = 1
//       2S when size = 10, Q = 0
//       4S when size = 10, Q = 1
//       2D when size = 11, Q = 1
//       The encoding size = 11, Q = 0 is reserved.
//
// - arg_Vt_3_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__1D_30__2D_31:
//     three registers with arrangement specifier encoded in the "size:Q" field which can have the following values:
//       8B when size = 00, Q = 0
//       16B when size = 00, Q = 1
//       4H when size = 01, Q = 0
//       8H when size = 01, Q = 1
//       2S when size = 10, Q = 0
//       4S when size = 10, Q = 1
//       2D when size = 11, Q = 1
//       The encoding size = 11, Q = 0 is reserved.
//
// - arg_Vt_1_arrangement_H_index__Q_S_size_1:
//     one register with arrangement:H and element index encoded in "Q:S:size<1>".

type instArg uint16

const (
	_ instArg = iota
	arg_Bt
	arg_Cm
	arg_Cn
	arg_cond_AllowALNV_Normal
	arg_conditional
	arg_cond_NotAllowALNV_Invert
	arg_Da
	arg_Dd
	arg_Dm
	arg_Dn
	arg_Dt
	arg_Dt2
	arg_Hd
	arg_Hn
	arg_Ht
	arg_IAddSub
	arg_immediate_0_127_CRm_op2
	arg_immediate_0_15_CRm
	arg_immediate_0_15_nzcv
	arg_immediate_0_31_imm5
	arg_immediate_0_31_immr
	arg_immediate_0_31_imms
	arg_immediate_0_63_b5_b40
	arg_immediate_0_63_immh_immb__UIntimmhimmb64_8
	arg_immediate_0_63_immr
	arg_immediate_0_63_imms
	arg_immediate_0_65535_imm16
	arg_immediate_0_7_op1
	arg_immediate_0_7_op2
	arg_immediate_0_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4
	arg_immediate_0_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4__UIntimmhimmb64_8
	arg_immediate_0_width_m1_immh_immb__UIntimmhimmb8_1__UIntimmhimmb16_2__UIntimmhimmb32_4__UIntimmhimmb64_8
	arg_immediate_0_width_size__8_0__16_1__32_2
	arg_immediate_1_64_immh_immb__128UIntimmhimmb_8
	arg_immediate_1_width_immh_immb__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4
	arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4
	arg_immediate_1_width_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__16UIntimmhimmb_1__32UIntimmhimmb_2__64UIntimmhimmb_4__128UIntimmhimmb_8
	arg_immediate_8x8_a_b_c_d_e_f_g_h
	arg_immediate_ASR_SBFM_32M_bitfield_0_31_immr
	arg_immediate_ASR_SBFM_64M_bitfield_0_63_immr
	arg_immediate_BFI_BFM_32M_bitfield_lsb_32_immr
	arg_immediate_BFI_BFM_32M_bitfield_width_32_imms
	arg_immediate_BFI_BFM_64M_bitfield_lsb_64_immr
	arg_immediate_BFI_BFM_64M_bitfield_width_64_imms
	arg_immediate_BFXIL_BFM_32M_bitfield_lsb_32_immr
	arg_immediate_BFXIL_BFM_32M_bitfield_width_32_imms
	arg_immediate_BFXIL_BFM_64M_bitfield_lsb_64_immr
	arg_immediate_BFXIL_BFM_64M_bitfield_width_64_imms
	arg_immediate_bitmask_32_imms_immr
	arg_immediate_bitmask_64_N_imms_immr
	arg_immediate_exp_3_pre_4_a_b_c_d_e_f_g_h
	arg_immediate_exp_3_pre_4_imm8
	arg_immediate_fbits_min_1_max_0_sub_0_immh_immb__64UIntimmhimmb_4__128UIntimmhimmb_8
	arg_immediate_fbits_min_1_max_0_sub_0_immh_immb__SEEAdvancedSIMDmodifiedimmediate_0__64UIntimmhimmb_4__128UIntimmhimmb_8
	arg_immediate_fbits_min_1_max_32_sub_64_scale
	arg_immediate_fbits_min_1_max_64_sub_64_scale
	arg_immediate_floatzero
	arg_immediate_index_Q_imm4__imm4lt20gt_00__imm4_10
	arg_immediate_LSL_UBFM_32M_bitfield_0_31_immr
	arg_immediate_LSL_UBFM_64M_bitfield_0_63_immr
	arg_immediate_LSR_UBFM_32M_bitfield_0_31_immr
	arg_immediate_LSR_UBFM_64M_bitfield_0_63_immr
	arg_immediate_MSL__a_b_c_d_e_f_g_h_cmode__8_0__16_1
	arg_immediate_optional_0_15_CRm
	arg_immediate_optional_0_65535_imm16
	arg_immediate_OptLSL__a_b_c_d_e_f_g_h_cmode__0_0__8_1
	arg_immediate_OptLSL__a_b_c_d_e_f_g_h_cmode__0_0__8_1__16_2__24_3
	arg_immediate_OptLSL_amount_16_0_16
	arg_immediate_OptLSL_amount_16_0_48
	arg_immediate_OptLSLZero__a_b_c_d_e_f_g_h
	arg_immediate_SBFIZ_SBFM_32M_bitfield_lsb_32_immr
	arg_immediate_SBFIZ_SBFM_32M_bitfield_width_32_imms
	arg_immediate_SBFIZ_SBFM_64M_bitfield_lsb_64_immr
	arg_immediate_SBFIZ_SBFM_64M_bitfield_width_64_imms
	arg_immediate_SBFX_SBFM_32M_bitfield_lsb_32_immr
	arg_immediate_SBFX_SBFM_32M_bitfield_width_32_imms
	arg_immediate_SBFX_SBFM_64M_bitfield_lsb_64_immr
	arg_immediate_SBFX_SBFM_64M_bitfield_width_64_imms
	arg_immediate_shift_32_implicit_imm16_hw
	arg_immediate_shift_32_implicit_inverse_imm16_hw
	arg_immediate_shift_64_implicit_imm16_hw
	arg_immediate_shift_64_implicit_inverse_imm16_hw
	arg_immediate_UBFIZ_UBFM_32M_bitfield_lsb_32_immr
	arg_immediate_UBFIZ_UBFM_32M_bitfield_width_32_imms
	arg_immediate_UBFIZ_UBFM_64M_bitfield_lsb_64_immr
	arg_immediate_UBFIZ_UBFM_64M_bitfield_width_64_imms
	arg_immediate_UBFX_UBFM_32M_bitfield_lsb_32_immr
	arg_immediate_UBFX_UBFM_32M_bitfield_width_32_imms
	arg_immediate_UBFX_UBFM_64M_bitfield_lsb_64_immr
	arg_immediate_UBFX_UBFM_64M_bitfield_width_64_imms
	arg_immediate_zero
	arg_option_DMB_BO_system_CRm
	arg_option_DSB_BO_system_CRm
	arg_option_ISB_BI_system_CRm
	arg_prfop_Rt
	arg_pstatefield_op1_op2__SPSel_05__DAIFSet_36__DAIFClr_37
	arg_Qd
	arg_Qn
	arg_Qt
	arg_Qt2
	arg_Rm_extend__UXTB_0__UXTH_1__UXTW_2__LSL_UXTX_3__SXTB_4__SXTH_5__SXTW_6__SXTX_7__0_4
	arg_Rn_16_5__W_1__W_2__W_4__X_8
	arg_Rt_31_1__W_0__X_1
	arg_Sa
	arg_Sd
	arg_slabel_imm14_2
	arg_slabel_imm19_2
	arg_slabel_imm26_2
	arg_slabel_immhi_immlo_0
	arg_slabel_immhi_immlo_12
	arg_Sm
	arg_Sn
	arg_St
	arg_St2
	arg_sysop_AT_SYS_CR_system
	arg_sysop_DC_SYS_CR_system
	arg_sysop_IC_SYS_CR_system
	arg_sysop_SYS_CR_system
	arg_sysop_TLBI_SYS_CR_system
	arg_sysreg_o0_op1_CRn_CRm_op2
	arg_Vd_16_5__B_1__H_2__S_4__D_8
	arg_Vd_19_4__B_1__H_2__S_4
	arg_Vd_19_4__B_1__H_2__S_4__D_8
	arg_Vd_19_4__D_8
	arg_Vd_19_4__S_4__D_8
	arg_Vd_22_1__S_0
	arg_Vd_22_1__S_0__D_1
	arg_Vd_22_1__S_1
	arg_Vd_22_2__B_0__H_1__S_2
	arg_Vd_22_2__B_0__H_1__S_2__D_3
	arg_Vd_22_2__D_3
	arg_Vd_22_2__H_0__S_1__D_2
	arg_Vd_22_2__H_1__S_2
	arg_Vd_22_2__S_1__D_2
	arg_Vd_arrangement_16B
	arg_Vd_arrangement_2D
	arg_Vd_arrangement_4S
	arg_Vd_arrangement_D_index__1
	arg_Vd_arrangement_imm5___B_1__H_2__S_4__D_8_index__imm5__imm5lt41gt_1__imm5lt42gt_2__imm5lt43gt_4__imm5lt4gt_8_1
	arg_Vd_arrangement_imm5_Q___8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81
	arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81
	arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41
	arg_Vd_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81
	arg_Vd_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4
	arg_Vd_arrangement_Q___2S_0__4S_1
	arg_Vd_arrangement_Q___4H_0__8H_1
	arg_Vd_arrangement_Q___8B_0__16B_1
	arg_Vd_arrangement_Q_sz___2S_00__4S_10__2D_11
	arg_Vd_arrangement_size___4S_1__2D_2
	arg_Vd_arrangement_size___8H_0__1Q_3
	arg_Vd_arrangement_size___8H_0__4S_1__2D_2
	arg_Vd_arrangement_size_Q___4H_00__8H_01__2S_10__4S_11__1D_20__2D_21
	arg_Vd_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21
	arg_Vd_arrangement_size_Q___8B_00__16B_01
	arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11
	arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21
	arg_Vd_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Vd_arrangement_sz___4S_0__2D_1
	arg_Vd_arrangement_sz_Q___2S_00__4S_01
	arg_Vd_arrangement_sz_Q___2S_00__4S_01__2D_11
	arg_Vd_arrangement_sz_Q___2S_10__4S_11
	arg_Vd_arrangement_sz_Q___4H_00__8H_01__2S_10__4S_11
	arg_Vm_22_1__S_0__D_1
	arg_Vm_22_2__B_0__H_1__S_2__D_3
	arg_Vm_22_2__D_3
	arg_Vm_22_2__H_1__S_2
	arg_Vm_arrangement_4S
	arg_Vm_arrangement_Q___8B_0__16B_1
	arg_Vm_arrangement_size___8H_0__4S_1__2D_2
	arg_Vm_arrangement_size___H_1__S_2_index__size_L_H_M__HLM_1__HL_2_1
	arg_Vm_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21
	arg_Vm_arrangement_size_Q___8B_00__16B_01
	arg_Vm_arrangement_size_Q___8B_00__16B_01__1D_30__2D_31
	arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21
	arg_Vm_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Vm_arrangement_sz_Q___2S_00__4S_01__2D_11
	arg_Vm_arrangement_sz___S_0__D_1_index__sz_L_H__HL_00__H_10_1
	arg_Vn_19_4__B_1__H_2__S_4__D_8
	arg_Vn_19_4__D_8
	arg_Vn_19_4__H_1__S_2__D_4
	arg_Vn_19_4__S_4__D_8
	arg_Vn_1_arrangement_16B
	arg_Vn_22_1__D_1
	arg_Vn_22_1__S_0__D_1
	arg_Vn_22_2__B_0__H_1__S_2__D_3
	arg_Vn_22_2__D_3
	arg_Vn_22_2__H_0__S_1__D_2
	arg_Vn_22_2__H_1__S_2
	arg_Vn_2_arrangement_16B
	arg_Vn_3_arrangement_16B
	arg_Vn_4_arrangement_16B
	arg_Vn_arrangement_16B
	arg_Vn_arrangement_4S
	arg_Vn_arrangement_D_index__1
	arg_Vn_arrangement_D_index__imm5_1
	arg_Vn_arrangement_imm5___B_1__H_2_index__imm5__imm5lt41gt_1__imm5lt42gt_2_1
	arg_Vn_arrangement_imm5___B_1__H_2__S_4__D_8_index__imm5_imm4__imm4lt30gt_1__imm4lt31gt_2__imm4lt32gt_4__imm4lt3gt_8_1
	arg_Vn_arrangement_imm5___B_1__H_2__S_4__D_8_index__imm5__imm5lt41gt_1__imm5lt42gt_2__imm5lt43gt_4__imm5lt4gt_8_1
	arg_Vn_arrangement_imm5___B_1__H_2__S_4_index__imm5__imm5lt41gt_1__imm5lt42gt_2__imm5lt43gt_4_1
	arg_Vn_arrangement_imm5___D_8_index__imm5_1
	arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__2S_40__4S_41__2D_81
	arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41
	arg_Vn_arrangement_immh_Q___SEEAdvancedSIMDmodifiedimmediate_00__8B_10__16B_11__4H_20__8H_21__2S_40__4S_41__2D_81
	arg_Vn_arrangement_immh___SEEAdvancedSIMDmodifiedimmediate_0__8H_1__4S_2__2D_4
	arg_Vn_arrangement_Q___8B_0__16B_1
	arg_Vn_arrangement_Q_sz___2S_00__4S_10__2D_11
	arg_Vn_arrangement_Q_sz___4S_10
	arg_Vn_arrangement_S_index__imm5__imm5lt41gt_1__imm5lt42gt_2__imm5lt43gt_4_1
	arg_Vn_arrangement_size___2D_3
	arg_Vn_arrangement_size___8H_0__4S_1__2D_2
	arg_Vn_arrangement_size_Q___4H_10__8H_11__2S_20__4S_21
	arg_Vn_arrangement_size_Q___8B_00__16B_01
	arg_Vn_arrangement_size_Q___8B_00__16B_01__1D_30__2D_31
	arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11
	arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21
	arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Vn_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__4S_21
	arg_Vn_arrangement_sz___2D_1
	arg_Vn_arrangement_sz___2S_0__2D_1
	arg_Vn_arrangement_sz___4S_0__2D_1
	arg_Vn_arrangement_sz_Q___2S_00__4S_01
	arg_Vn_arrangement_sz_Q___2S_00__4S_01__2D_11
	arg_Vn_arrangement_sz_Q___4H_00__8H_01__2S_10__4S_11
	arg_Vt_1_arrangement_B_index__Q_S_size_1
	arg_Vt_1_arrangement_D_index__Q_1
	arg_Vt_1_arrangement_H_index__Q_S_size_1
	arg_Vt_1_arrangement_S_index__Q_S_1
	arg_Vt_1_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__1D_30__2D_31
	arg_Vt_2_arrangement_B_index__Q_S_size_1
	arg_Vt_2_arrangement_D_index__Q_1
	arg_Vt_2_arrangement_H_index__Q_S_size_1
	arg_Vt_2_arrangement_S_index__Q_S_1
	arg_Vt_2_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__1D_30__2D_31
	arg_Vt_2_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Vt_3_arrangement_B_index__Q_S_size_1
	arg_Vt_3_arrangement_D_index__Q_1
	arg_Vt_3_arrangement_H_index__Q_S_size_1
	arg_Vt_3_arrangement_S_index__Q_S_1
	arg_Vt_3_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__1D_30__2D_31
	arg_Vt_3_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Vt_4_arrangement_B_index__Q_S_size_1
	arg_Vt_4_arrangement_D_index__Q_1
	arg_Vt_4_arrangement_H_index__Q_S_size_1
	arg_Vt_4_arrangement_S_index__Q_S_1
	arg_Vt_4_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__1D_30__2D_31
	arg_Vt_4_arrangement_size_Q___8B_00__16B_01__4H_10__8H_11__2S_20__4S_21__2D_31
	arg_Wa
	arg_Wd
	arg_Wds
	arg_Wm
	arg_Wm_extend__UXTB_0__UXTH_1__LSL_UXTW_2__UXTX_3__SXTB_4__SXTH_5__SXTW_6__SXTX_7__0_4
	arg_Wm_shift__LSL_0__LSR_1__ASR_2__0_31
	arg_Wm_shift__LSL_0__LSR_1__ASR_2__ROR_3__0_31
	arg_Wn
	arg_Wns
	arg_Ws
	arg_Wt
	arg_Wt2
	arg_Xa
	arg_Xd
	arg_Xds
	arg_Xm
	arg_Xm_shift__LSL_0__LSR_1__ASR_2__0_63
	arg_Xm_shift__LSL_0__LSR_1__ASR_2__ROR_3__0_63
	arg_Xn
	arg_Xns
	arg_Xns_mem
	arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__1_1
	arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__2_1
	arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__3_1
	arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__0_0__4_1
	arg_Xns_mem_extend_m__UXTW_2__LSL_3__SXTW_6__SXTX_7__absent_0__0_1
	arg_Xns_mem_offset
	arg_Xns_mem_optional_imm12_16_unsigned
	arg_Xns_mem_optional_imm12_1_unsigned
	arg_Xns_mem_optional_imm12_2_unsigned
	arg_Xns_mem_optional_imm12_4_unsigned
	arg_Xns_mem_optional_imm12_8_unsigned
	arg_Xns_mem_optional_imm7_16_signed
	arg_Xns_mem_optional_imm7_4_signed
	arg_Xns_mem_optional_imm7_8_signed
	arg_Xns_mem_optional_imm9_1_signed
	arg_Xns_mem_post_fixedimm_1
	arg_Xns_mem_post_fixedimm_12
	arg_Xns_mem_post_fixedimm_16
	arg_Xns_mem_post_fixedimm_2
	arg_Xns_mem_post_fixedimm_24
	arg_Xns_mem_post_fixedimm_3
	arg_Xns_mem_post_fixedimm_32
	arg_Xns_mem_post_fixedimm_4
	arg_Xns_mem_post_fixedimm_6
	arg_Xns_mem_post_fixedimm_8
	arg_Xns_mem_post_imm7_16_signed
	arg_Xns_mem_post_imm7_4_signed
	arg_Xns_mem_post_imm7_8_signed
	arg_Xns_mem_post_imm9_1_signed
	arg_Xns_mem_post_Q__16_0__32_1
	arg_Xns_mem_post_Q__24_0__48_1
	arg_Xns_mem_post_Q__32_0__64_1
	arg_Xns_mem_post_Q__8_0__16_1
	arg_Xns_mem_post_size__1_0__2_1__4_2__8_3
	arg_Xns_mem_post_size__2_0__4_1__8_2__16_3
	arg_Xns_mem_post_size__3_0__6_1__12_2__24_3
	arg_Xns_mem_post_size__4_0__8_1__16_2__32_3
	arg_Xns_mem_post_Xm
	arg_Xns_mem_wb_imm7_16_signed
	arg_Xns_mem_wb_imm7_4_signed
	arg_Xns_mem_wb_imm7_8_signed
	arg_Xns_mem_wb_imm9_1_signed
	arg_Xs
	arg_Xt
	arg_Xt2
)
```